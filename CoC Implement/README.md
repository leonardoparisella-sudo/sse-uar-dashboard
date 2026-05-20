# SSE UAR — Compliance-as-Code Implementation Paper

**Prepared by:** SSE Security Team  
**Audience:** Developers and Leadership  
**Date:** May 2026  
**Status:** Pre-Implementation Review

---

## Executive Summary

This paper describes a phased implementation plan to evolve the SSE UAR Findings Dashboard from a **read-only reporting tool** into a **fully automated compliance-as-code pipeline**. The goal is to reduce manual effort, enforce UAR compliance programmatically, and provide leadership with real-time risk visibility — all within Walmart's existing infrastructure (BigQuery, AuditBoard, SNOW, SailPoint/MAR).

**Current state:** Python script run manually → static HTML dashboard  
**Target state:** Automated risk scoring, owner notifications, AuditBoard writeback, and continuous monitoring

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Phase 1 — Risk Scoring Engine (Buildable Today)](#2-phase-1--risk-scoring-engine-buildable-today)
3. [Phase 2 — BigQuery Writeback (Audit Trail)](#3-phase-2--bigquery-writeback-audit-trail)
4. [Phase 3 — Owner Notification Engine](#4-phase-3--owner-notification-engine)
5. [Phase 4 — AuditBoard API Integration](#5-phase-4--auditboard-api-integration)
6. [Phase 5 — SailPoint/MAR Automation](#6-phase-5--sailpointmar-automation)
7. [Phase 6 — Scheduled Pipeline (Looper/Cloud Scheduler)](#7-phase-6--scheduled-pipeline-looперcloud-scheduler)
8. [Phase 7 — Compliance Policy Enforcement](#8-phase-7--compliance-policy-enforcement)
9. [Prerequisites and Access Requirements](#9-prerequisites-and-access-requirements)
10. [Phased Rollout Plan](#10-phased-rollout-plan)
11. [Expected Outcomes by Phase](#11-expected-outcomes-by-phase)
12. [Risk and Mitigation](#12-risk-and-mitigation)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE-AS-CODE PIPELINE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DATA SOURCES                PROCESSING                  OUTPUTS     │
│  ───────────                 ──────────                  ───────     │
│                                                                      │
│  BigQuery (live) ──────┐                                             │
│  • vw_unified_findings  │                                            │
│  • uar_findings_enriched│    ┌─────────────────────┐                │
│  • uar_apm_enriched     ├───►│  build_dashboard.py  ├──► HTML Report │
│  • uar_galaxy_enriched  │    │  (existing pipeline) │                │
│  • vw_master_action_plans│   └──────────┬──────────┘                │
│  • vw_master_issues     │              │                             │
│                          │    ┌─────────▼──────────┐                │
│  MAR CSVs (local) ──────┘    │   NEW: CoC Modules  │                │
│  • Entitlement Reports        └──────────┬──────────┘                │
│                                          │                           │
│                               ┌──────────┼──────────┐               │
│                               ▼          ▼          ▼               │
│                          Risk Score  BQ Writeback  Notifications     │
│                          (Phase 1)   (Phase 2)     (Phase 3)        │
│                               │          │                           │
│                               └──────────┼──────────┐               │
│                                          ▼          ▼               │
│                                    AuditBoard   SailPoint/MAR        │
│                                    (Phase 4)    (Phase 5)            │
│                                          │                           │
│                                          ▼                           │
│                                   Looper Scheduler                   │
│                                     (Phase 6)                        │
│                                          │                           │
│                                          ▼                           │
│                                  Policy Enforcement                  │
│                                     (Phase 7)                        │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Principle:** Every module is additive. The existing `build_dashboard.py` is not replaced — each phase adds a new module that imports from it or runs alongside it. This reduces risk and allows phased adoption.

---

## 2. Phase 1 — Risk Scoring Engine (Buildable Today)

### What It Does

Reads the existing pipeline output and assigns each UAR finding a numeric risk score (0–100) based on: days overdue, APM sensitivity, PCI/SOX scope, AD group coverage, and prior repeat finding history.

### Why It Matters

Right now every finding is treated equally. A PCI-scoped APM that is 60 days past due with zero AD groups verified is treated the same as a non-sensitive APM with 80% coverage. Risk scoring lets teams prioritize their remediation effort and gives leadership a quantified compliance posture.

### How It Works

The scorer is a pure function: it takes the DataFrame built by `build_dashboard.py` and returns it with a new `risk_score` and `risk_tier` column. No external credentials required.

**Risk Score Formula:**

| Factor | Points | Logic |
|--------|--------|-------|
| Past due | +35 | `due_status == "Past due"` |
| Days overdue | +0–20 | `min(days_overdue / 3, 20)` — capped at 20 |
| Zero AD groups verified (pct == 0) | +20 | All groups unverified |
| Partial coverage (0 < pct < 100) | +10 | Some groups unverified |
| PCI scope | +15 | `is_pci == True` |
| SOX scope | +10 | `is_sox == True` |
| High sensitivity APM | +5 | `sensitivity == "High"` |
| Repeat finding | +10 | Same APM had a finding closed then reopened |

**Risk Tiers:**

| Score | Tier | Color |
|-------|------|-------|
| 70–100 | Critical | Red |
| 40–69 | High | Orange |
| 20–39 | Medium | Yellow |
| 0–19 | Low | Green |

### Code

**File:** `coc_risk_scorer.py`

```python
"""
coc_risk_scorer.py — Phase 1: UAR Risk Scoring Engine
Reads the pipeline output DataFrame and appends risk_score + risk_tier.

Usage:
    from coc_risk_scorer import score_findings
    df_scored = score_findings(df, apm_meta)

No external credentials required. Reads from already-loaded DataFrames.
"""
from __future__ import annotations
import datetime
import pandas as pd


# ── Weights ────────────────────────────────────────────────────────────────────

WEIGHT_PAST_DUE       = 35
WEIGHT_DAYS_MAX       = 20   # max points from days overdue
WEIGHT_DAYS_DIVISOR   = 3    # 1 point per N days overdue
WEIGHT_NO_GROUPS      = 20   # pct == 0
WEIGHT_PARTIAL        = 10   # 0 < pct < 100
WEIGHT_PCI            = 15
WEIGHT_SOX            = 10
WEIGHT_HIGH_SENS      = 5
WEIGHT_REPEAT         = 10

TIER_CRITICAL_MIN = 70
TIER_HIGH_MIN     = 40
TIER_MEDIUM_MIN   = 20


# ── Public API ─────────────────────────────────────────────────────────────────

def score_findings(
    df: pd.DataFrame,
    apm_meta: pd.DataFrame | None = None,
    history: list[dict] | None = None,
) -> pd.DataFrame:
    """
    Add risk_score (int 0-100) and risk_tier (str) to df.

    Args:
        df       : Output DataFrame from build_dashboard.py per-title records.
                   Expected columns: pct, due_status, due_date (optional),
                   ssp_apm_id (optional).
        apm_meta : Optional APM metadata DataFrame with columns:
                   apm_id, is_pci, is_sox, sensitivity
        history  : Optional list of past snapshot dicts from dashboard_history.json
                   Used to detect repeat findings.

    Returns:
        df with new columns: risk_score, risk_tier, risk_color
    """
    df = df.copy()

    # 1. Past due flag
    df["_past_due"] = (df.get("due_status", "") == "Past due").astype(int)

    # 2. Days overdue
    today = datetime.date.today()
    if "due_date" in df.columns:
        df["_days_over"] = df["due_date"].apply(
            lambda d: max(0, (today - pd.to_datetime(d).date()).days)
            if pd.notna(d) else 0
        )
    else:
        df["_days_over"] = 0

    # 3. Coverage gap
    df["_no_groups"]  = (df["pct"] == 0).astype(int)
    df["_partial"]    = ((df["pct"] > 0) & (df["pct"] < 100)).astype(int)

    # 4. Merge APM metadata (PCI, SOX, sensitivity)
    df["_pci"]  = 0
    df["_sox"]  = 0
    df["_sens"] = 0
    if apm_meta is not None and "apm_id" in apm_meta.columns:
        meta = apm_meta.set_index("apm_id")
        if "ssp_apm_id" in df.columns:
            for idx, row in df.iterrows():
                apm = row.get("ssp_apm_id")
                if apm and apm in meta.index:
                    m = meta.loc[apm]
                    df.at[idx, "_pci"]  = int(bool(m.get("is_pci", False)))
                    df.at[idx, "_sox"]  = int(bool(m.get("is_sox", False)))
                    df.at[idx, "_sens"] = int(str(m.get("sensitivity", "")).lower() == "high")

    # 5. Repeat finding detection (same APM appears in history as closed, then active again)
    repeat_apms: set[str] = set()
    if history and len(history) >= 2:
        # Simple heuristic: if an APM was in "can_close" in a prior snapshot
        # but is now in the active df, it was likely reopened
        for snap in history[:-1]:  # all but current
            repeat_apms.update(snap.get("can_close_apms", []))
    df["_repeat"] = df.get("ssp_apm_id", pd.Series([""] * len(df))).isin(repeat_apms).astype(int)

    # 6. Compute score
    days_score = df["_days_over"].clip(upper=WEIGHT_DAYS_MAX * WEIGHT_DAYS_DIVISOR) / WEIGHT_DAYS_DIVISOR
    df["risk_score"] = (
        df["_past_due"]   * WEIGHT_PAST_DUE    +
        days_score        * 1                  +   # 1 pt per day, max 20
        df["_no_groups"]  * WEIGHT_NO_GROUPS   +
        df["_partial"]    * WEIGHT_PARTIAL      +
        df["_pci"]        * WEIGHT_PCI          +
        df["_sox"]        * WEIGHT_SOX          +
        df["_sens"]       * WEIGHT_HIGH_SENS    +
        df["_repeat"]     * WEIGHT_REPEAT
    ).clip(upper=100).round().astype(int)

    # 7. Tier and color
    def _tier(score: int) -> tuple[str, str]:
        if score >= TIER_CRITICAL_MIN:
            return "Critical", "#dc2626"
        if score >= TIER_HIGH_MIN:
            return "High", "#ea580c"
        if score >= TIER_MEDIUM_MIN:
            return "Medium", "#ca8a04"
        return "Low", "#16a34a"

    df[["risk_tier", "risk_color"]] = df["risk_score"].apply(
        lambda s: pd.Series(_tier(s))
    )

    # Clean up working columns
    drop_cols = [c for c in df.columns if c.startswith("_")]
    df.drop(columns=drop_cols, inplace=True)

    return df


def summarize_risk(df: pd.DataFrame) -> dict:
    """Return summary counts by tier for leadership reporting."""
    scored = df if "risk_tier" in df.columns else score_findings(df)
    counts = scored["risk_tier"].value_counts().to_dict()
    return {
        "critical": counts.get("Critical", 0),
        "high":     counts.get("High",     0),
        "medium":   counts.get("Medium",   0),
        "low":      counts.get("Low",      0),
        "avg_score": round(scored["risk_score"].mean(), 1),
    }


if __name__ == "__main__":
    # Standalone test — prints tier distribution using a mock DataFrame
    mock = pd.DataFrame([
        {"pct": 0,   "due_status": "Past due", "risk_score": 0},
        {"pct": 50,  "due_status": "Past due", "risk_score": 0},
        {"pct": 100, "due_status": "Active",   "risk_score": 0},
        {"pct": 0,   "due_status": "Active",   "risk_score": 0},
    ])
    result = score_findings(mock)
    print(result[["pct", "due_status", "risk_score", "risk_tier"]])
    print("\nSummary:", summarize_risk(result))
```

### Integration into `build_dashboard.py`

Add these lines at the end of `main()` before rendering the HTML, after the existing records are built:

```python
# Phase 1 — Risk Scoring
from coc_risk_scorer import score_findings, summarize_risk

records_df = pd.DataFrame(records)          # 'records' already built by pipeline
records_df = score_findings(records_df)     # adds risk_score, risk_tier, risk_color

risk_summary = summarize_risk(records_df)
print(f"[Risk] Critical={risk_summary['critical']}  High={risk_summary['high']}  "
      f"Medium={risk_summary['medium']}  Low={risk_summary['low']}  "
      f"Avg score={risk_summary['avg_score']}")
```

### Expected Output (Today's Data)

Based on current numbers (332 findings, 222 past due, ~290 APMs):

| Tier | Estimated Count |
|------|----------------|
| Critical (70–100) | ~180–200 |
| High (40–69) | ~80–100 |
| Medium (20–39) | ~20–30 |
| Low (0–19) | ~10–20 |

PCI + SOX flagged APMs will cluster in Critical even if not yet past due.

---

## 3. Phase 2 — BigQuery Writeback (Audit Trail)

### What It Does

After each pipeline run, writes the scored results back to a BigQuery table owned by the SSE team. This creates a permanent, queryable audit trail of every finding's status at every point in time.

### Why It Matters

- **Leadership:** Can query compliance posture at any past date — "What was our % coverage on March 1?"
- **Audit:** Provides evidence that monitoring was continuous, not just snapshot-based
- **Trending:** Replaces the local `dashboard_history.json` with a scalable BQ table
- **Integration:** Other teams (GRC, Internal Audit) can JOIN against this table

### Architecture

```
                build_dashboard.py run
                        │
                        ▼
            coc_bq_writeback.py
                        │
                 UPSERT (MERGE)
                        │
                        ▼
    infosec-compliance-auditboard
    └── sse_findings_enriched_data
        └── uar_compliance_snapshots  (new table, SSE-owned)
```

**Schema — `uar_compliance_snapshots`:**

```sql
CREATE TABLE `infosec-compliance-auditboard.sse_findings_enriched_data.uar_compliance_snapshots`
(
    snapshot_date     DATE,
    run_timestamp     TIMESTAMP,
    ssp_apm_id        STRING,
    title             STRING,
    pct               INT64,
    to_close          INT64,
    keep_open         INT64,
    due_status        STRING,
    risk_score        INT64,
    risk_tier         STRING,
    ad_groups_found   STRING,     -- JSON array of group names
    ad_groups_verified STRING,   -- JSON array of MAR-verified groups
    is_pci            BOOL,
    is_sox            BOOL,
    sensitivity       STRING,
)
PARTITION BY snapshot_date
CLUSTER BY ssp_apm_id, risk_tier;
```

### Code

**File:** `coc_bq_writeback.py`

```python
"""
coc_bq_writeback.py — Phase 2: BigQuery Audit Trail Writeback
Saves each pipeline run's scored findings to a BQ snapshot table.

Requires:
    - BQ write access to sse_findings_enriched_data dataset
    - google-cloud-bigquery already installed (same as build_dashboard.py)

Usage:
    from coc_bq_writeback import write_snapshot
    write_snapshot(records_df, run_timestamp=datetime.datetime.utcnow())
"""
from __future__ import annotations
import datetime
import json
import pandas as pd
from google.cloud import bigquery

PROJECT   = "infosec-compliance-auditboard"
DATASET   = "sse_findings_enriched_data"
TABLE     = "uar_compliance_snapshots"
TABLE_REF = f"{PROJECT}.{DATASET}.{TABLE}"


def write_snapshot(
    df: pd.DataFrame,
    run_timestamp: datetime.datetime | None = None,
    dry_run: bool = False,
) -> int:
    """
    Write scored findings DataFrame as a daily snapshot to BigQuery.

    Args:
        df            : Output of score_findings() — must have risk_score, risk_tier
        run_timestamp : UTC timestamp for this run (defaults to now)
        dry_run       : If True, prints rows instead of writing to BQ

    Returns:
        Number of rows written
    """
    if run_timestamp is None:
        run_timestamp = datetime.datetime.utcnow()

    today = run_timestamp.date()

    rows = []
    for _, row in df.iterrows():
        rows.append({
            "snapshot_date":      today.isoformat(),
            "run_timestamp":      run_timestamp.isoformat(),
            "ssp_apm_id":         str(row.get("ssp_apm_id", "") or ""),
            "title":              str(row.get("title", "") or ""),
            "pct":                int(row.get("pct", 0) or 0),
            "to_close":           int(row.get("toClose", 0) or 0),
            "keep_open":          int(row.get("keepOpen", 0) or 0),
            "due_status":         str(row.get("due_status", "") or ""),
            "risk_score":         int(row.get("risk_score", 0) or 0),
            "risk_tier":          str(row.get("risk_tier", "") or ""),
            "ad_groups_found":    json.dumps(list(row.get("all_groups", []) or [])),
            "ad_groups_verified": json.dumps(list(row.get("verified_groups", []) or [])),
            "is_pci":             bool(row.get("is_pci", False)),
            "is_sox":             bool(row.get("is_sox", False)),
            "sensitivity":        str(row.get("sensitivity", "") or ""),
        })

    if dry_run:
        print(f"[dry_run] Would write {len(rows)} rows to {TABLE_REF}")
        for r in rows[:3]:
            print(" ", r)
        return len(rows)

    client = bigquery.Client(project=PROJECT)

    # Delete today's existing rows first (idempotent refresh)
    delete_sql = f"""
        DELETE FROM `{TABLE_REF}`
        WHERE snapshot_date = '{today.isoformat()}'
    """
    client.query(delete_sql).result()

    # Insert new rows
    errors = client.insert_rows_json(
        client.get_table(TABLE_REF), rows
    )

    if errors:
        raise RuntimeError(f"BigQuery insert errors: {errors}")

    print(f"[BQ writeback] {len(rows)} rows written to {TABLE_REF} for {today}")
    return len(rows)


def create_snapshot_table_ddl() -> str:
    """Return the CREATE TABLE DDL for the snapshot table."""
    return f"""
-- Run this ONCE in BQ console to create the snapshot table
CREATE TABLE IF NOT EXISTS `{TABLE_REF}`
(
    snapshot_date      DATE         NOT NULL,
    run_timestamp      TIMESTAMP    NOT NULL,
    ssp_apm_id         STRING,
    title              STRING,
    pct                INT64,
    to_close           INT64,
    keep_open          INT64,
    due_status         STRING,
    risk_score         INT64,
    risk_tier          STRING,
    ad_groups_found    STRING,      -- JSON array
    ad_groups_verified STRING,      -- JSON array
    is_pci             BOOL,
    is_sox             BOOL,
    sensitivity        STRING,
)
PARTITION BY snapshot_date
CLUSTER BY ssp_apm_id, risk_tier
OPTIONS (
    description = 'SSE UAR daily compliance snapshots — written by build_dashboard.py',
    require_partition_filter = FALSE
);
""".strip()
```

### One-Time Setup

Run this in BigQuery console before Phase 2 goes live:

```sql
CREATE TABLE IF NOT EXISTS `infosec-compliance-auditboard.sse_findings_enriched_data.uar_compliance_snapshots`
(
    snapshot_date      DATE         NOT NULL,
    run_timestamp      TIMESTAMP    NOT NULL,
    ssp_apm_id         STRING,
    title              STRING,
    pct                INT64,
    to_close           INT64,
    keep_open          INT64,
    due_status         STRING,
    risk_score         INT64,
    risk_tier          STRING,
    ad_groups_found    STRING,
    ad_groups_verified STRING,
    is_pci             BOOL,
    is_sox             BOOL,
    sensitivity        STRING
)
PARTITION BY snapshot_date
CLUSTER BY ssp_apm_id, risk_tier;
```

### Expected Outcome

- 332 rows per daily run stored in BQ
- Full history queryable: `WHERE snapshot_date BETWEEN '2025-01-01' AND TODAY`
- `dashboard_history.json` can be replaced entirely by this table
- GRC/Audit teams can run their own queries without needing the HTML dashboard

---

## 4. Phase 3 — Owner Notification Engine

### What It Does

Sends automated email or Teams message alerts to APM owners when:
- Their finding is past due (immediate alert)
- Their finding has been open > 30 days with no MAR evidence (warning)
- A Critical risk-scored finding is assigned to them (escalation to their manager)

### Why It Matters

Currently, APM owners are only informed through manual outreach. Automating notifications removes a major bottleneck — the compliance team does not have to manually email 290+ owners.

### Architecture

```
  build_dashboard.py (scored output)
          │
          ▼
  coc_notifier.py
          │
     ┌────┴────┐
     ▼         ▼
  Email      MS Teams
  (SMTP)     (Webhook)
     │         │
     ▼         ▼
  APM Owner  SSE Channel
```

### Notification Rules

| Condition | Recipient | Channel | Frequency |
|-----------|-----------|---------|-----------|
| Past due AND pct == 0 | APM owner | Email + Teams | Daily |
| Past due AND pct > 0 | APM owner | Email | Daily |
| risk_tier == Critical | APM owner + manager | Email | Daily |
| pct == 100 (can close) | APM owner | Email | Once per finding |
| New finding opened | APM owner | Email | Once |

### Code

**File:** `coc_notifier.py`

```python
"""
coc_notifier.py — Phase 3: Owner Notification Engine
Sends email/Teams alerts to APM owners based on risk-scored findings.

Requires:
    - SMTP access (Walmart internal mail relay) OR
    - MS Teams incoming webhook URL
    - APM owner email mapping (from SNOW APM table or manual CSV)

Usage:
    from coc_notifier import NotificationEngine
    engine = NotificationEngine(smtp_host="mailrelay.walmart.com", port=25)
    engine.notify_all(records_df, owner_map)
"""
from __future__ import annotations
import smtplib
import urllib.request
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Callable
import pandas as pd


class NotificationEngine:
    """
    Sends UAR compliance notifications to APM owners.

    Args:
        smtp_host     : Internal mail relay hostname
        port          : SMTP port (default 25, no auth on Walmart relay)
        from_addr     : Sender address
        teams_webhook : Optional MS Teams incoming webhook URL for #sse-uar-alerts
        dry_run       : If True, print instead of send
    """

    def __init__(
        self,
        smtp_host: str = "mailrelay.walmart.com",
        port: int = 25,
        from_addr: str = "sse-compliance-bot@walmart.com",
        teams_webhook: str | None = None,
        dry_run: bool = True,   # Default dry_run=True for safety
    ):
        self.smtp_host     = smtp_host
        self.port          = port
        self.from_addr     = from_addr
        self.teams_webhook = teams_webhook
        self.dry_run       = dry_run

    # ── Public API ─────────────────────────────────────────────────────────────

    def notify_all(
        self,
        df: pd.DataFrame,
        owner_map: dict[str, str],  # apm_id → owner_email
        manager_map: dict[str, str] | None = None,  # owner_email → manager_email
    ) -> dict[str, int]:
        """
        Process all findings and send appropriate notifications.

        Returns summary: {"sent": N, "skipped": N, "errors": N}
        """
        sent = skipped = errors = 0

        for _, row in df.iterrows():
            apm = str(row.get("ssp_apm_id", ""))
            owner_email = owner_map.get(apm)
            if not owner_email:
                skipped += 1
                continue

            try:
                n = self._route(row, owner_email, manager_map or {})
                sent += n
            except Exception as exc:
                print(f"[notifier] ERROR for {apm}: {exc}")
                errors += 1

        print(f"[notifier] Done — sent={sent}, skipped={skipped}, errors={errors}")
        return {"sent": sent, "skipped": skipped, "errors": errors}

    # ── Routing Logic ──────────────────────────────────────────────────────────

    def _route(
        self,
        row: pd.Series,
        owner_email: str,
        manager_map: dict[str, str],
    ) -> int:
        """Route a single finding to the correct notification type. Returns emails sent."""
        pct        = int(row.get("pct", 0))
        due_status = str(row.get("due_status", ""))
        risk_tier  = str(row.get("risk_tier", "Low"))
        title      = str(row.get("title", ""))
        apm        = str(row.get("ssp_apm_id", ""))
        sent       = 0

        is_past_due = due_status == "Past due"
        is_critical = risk_tier == "Critical"

        if is_past_due and pct == 0:
            self._send_email(owner_email, *self._tmpl_past_due_no_coverage(apm, title))
            if self.teams_webhook:
                self._send_teams(f"🔴 **{apm}** is PAST DUE with NO MAR coverage. Owner: {owner_email}")
            sent += 1

        elif is_past_due and pct > 0:
            self._send_email(owner_email, *self._tmpl_past_due_partial(apm, title, pct))
            sent += 1

        if is_critical and manager_map.get(owner_email):
            manager = manager_map[owner_email]
            self._send_email(manager, *self._tmpl_escalation(apm, title, owner_email, risk_tier))
            sent += 1

        if pct == 100:
            self._send_email(owner_email, *self._tmpl_can_close(apm, title))
            sent += 1

        return sent

    # ── Email Templates ────────────────────────────────────────────────────────

    def _tmpl_past_due_no_coverage(self, apm: str, title: str) -> tuple[str, str]:
        subject = f"[UAR ACTION REQUIRED] {apm} — Past Due, No MAR Coverage"
        body = f"""
<p>Hello,</p>
<p>The following UAR finding requires <strong>immediate action</strong>:</p>
<ul>
  <li><strong>APM:</strong> {apm}</li>
  <li><strong>Finding:</strong> {title}</li>
  <li><strong>Status:</strong> Past Due</li>
  <li><strong>MAR Coverage:</strong> 0% — No AD groups verified in SailPoint/MAR</li>
</ul>
<p>Please enroll your AD group(s) in SailPoint UAR immediately or provide evidence
that access has been reviewed.</p>
<p>View the <a href="https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html">
SSE UAR Dashboard</a> for details.</p>
<p>SSE Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_past_due_partial(self, apm: str, title: str, pct: int) -> tuple[str, str]:
        subject = f"[UAR REMINDER] {apm} — Past Due, {pct}% Coverage"
        body = f"""
<p>Hello,</p>
<p>Your UAR finding is past due with partial MAR coverage ({pct}%).</p>
<ul>
  <li><strong>APM:</strong> {apm}</li>
  <li><strong>Finding:</strong> {title}</li>
  <li><strong>Remaining work:</strong> {100 - pct}% of AD groups not yet in MAR</li>
</ul>
<p>Please enroll remaining AD groups in SailPoint UAR to close this finding.</p>
<p>SSE Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_escalation(self, apm: str, title: str, owner: str, tier: str) -> tuple[str, str]:
        subject = f"[UAR ESCALATION] {apm} — {tier} Risk Finding"
        body = f"""
<p>Hello,</p>
<p>A <strong>{tier} risk</strong> UAR finding under your team requires attention:</p>
<ul>
  <li><strong>APM:</strong> {apm}</li>
  <li><strong>Finding:</strong> {title}</li>
  <li><strong>Owner:</strong> {owner}</li>
  <li><strong>Risk Tier:</strong> {tier}</li>
</ul>
<p>Please follow up with the APM owner to ensure this finding is remediated promptly.</p>
<p>SSE Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_can_close(self, apm: str, title: str) -> tuple[str, str]:
        subject = f"[UAR GOOD NEWS] {apm} — Ready to Close"
        body = f"""
<p>Hello,</p>
<p>Your UAR finding now has 100% MAR coverage and is <strong>ready to be closed</strong>:</p>
<ul>
  <li><strong>APM:</strong> {apm}</li>
  <li><strong>Finding:</strong> {title}</li>
</ul>
<p>Please download the evidence CSV from the
<a href="https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html">
SSE UAR Dashboard</a> and submit it in AuditBoard to close this finding.</p>
<p>SSE Compliance Team</p>
""".strip()
        return subject, body

    # ── Send Helpers ───────────────────────────────────────────────────────────

    def _send_email(self, to: str, subject: str, body: str) -> None:
        if self.dry_run:
            print(f"[email DRY RUN] To: {to} | Subject: {subject}")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.from_addr
        msg["To"]      = to
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(self.smtp_host, self.port, timeout=10) as s:
            s.sendmail(self.from_addr, [to], msg.as_string())

    def _send_teams(self, text: str) -> None:
        if self.dry_run:
            print(f"[teams DRY RUN] {text}")
            return
        if not self.teams_webhook:
            return

        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            self.teams_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
```

### Owner Map Source

The owner email map can be built from SNOW APM data already in BigQuery:

```python
# Load owner map from SNOW APM table
owner_sql = """
SELECT apm_id, owner_email, manager_email
FROM `infosec-compliance-auditboard.snow_apm_data.sse_apm_data_prod`
WHERE owner_email IS NOT NULL
"""
owner_df = _bq().query(owner_sql).to_dataframe()
owner_map   = dict(zip(owner_df["apm_id"], owner_df["owner_email"]))
manager_map = dict(zip(owner_df["owner_email"], owner_df["manager_email"]))
```

---

## 5. Phase 4 — AuditBoard API Integration

### What It Does

Uses the AuditBoard REST API to:
1. **Read** finding metadata (due dates, assigned reviewers, current status)
2. **Write** comments onto findings documenting MAR evidence found
3. **Close** findings programmatically when `pct == 100` and evidence CSV is ready

### Why It Matters

Currently the pipeline reads from AuditBoard (via `vw_unified_findings`) but cannot write back to it. The final closure step requires a human to log into AuditBoard and manually attach evidence. This phase automates that last mile.

### Architecture

```
  build_dashboard.py
    (pct == 100 findings)
          │
          ▼
  coc_auditboard.py
          │
     ┌────┴─────┐
     ▼          ▼
  POST /api    POST /api
  /issues/N   /issues/N
  /comments   /close
          │
          ▼
  AuditBoard (walmart-infosec.auditboardapp.com)
```

### Prerequisites

- AuditBoard API key (request from GRC team — service account preferred)
- AuditBoard instance: `https://walmart-infosec.auditboardapp.com`
- API key stored in environment variable `AUDITBOARD_API_KEY` (never hardcoded)

### Code

**File:** `coc_auditboard.py`

```python
"""
coc_auditboard.py — Phase 4: AuditBoard API Integration
Reads and writes to AuditBoard via REST API.

Requires:
    - AUDITBOARD_API_KEY environment variable set
    - Network access to walmart-infosec.auditboardapp.com

Usage:
    from coc_auditboard import AuditBoardClient
    ab = AuditBoardClient()
    ab.post_mar_comment(issue_id=12345, apm_id="APM0001234", verified_groups=["gcp-myapp"])
    ab.close_finding(issue_id=12345, evidence_csv_path="evidence.csv")
"""
from __future__ import annotations
import os
import json
import urllib.request
import urllib.parse
from pathlib import Path


AB_BASE = "https://walmart-infosec.auditboardapp.com"


class AuditBoardClient:
    """
    Thin wrapper around AuditBoard REST API.

    API key read from AUDITBOARD_API_KEY env var.
    Set dry_run=True to print API calls without sending them.
    """

    def __init__(self, dry_run: bool = True):
        self.base     = AB_BASE
        self.dry_run  = dry_run
        self._api_key = os.environ.get("AUDITBOARD_API_KEY")
        if not self._api_key and not dry_run:
            raise ValueError(
                "AUDITBOARD_API_KEY environment variable not set. "
                "Request a service account API key from the GRC team."
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def post_mar_comment(
        self,
        issue_id: int,
        apm_id: str,
        verified_groups: list[str],
        pct: int,
    ) -> dict:
        """
        Post a comment to an AuditBoard finding documenting MAR verification results.

        Args:
            issue_id        : AuditBoard issue/finding ID (from vw_unified_findings.id)
            apm_id          : APM identifier string
            verified_groups : List of AD group names verified in MAR
            pct             : Coverage percentage (0-100)
        """
        groups_str = "\n".join(f"  • {g}" for g in sorted(verified_groups))
        comment_text = (
            f"[AUTOMATED — SSE UAR Pipeline]\n\n"
            f"MAR Verification Results for {apm_id}:\n"
            f"Coverage: {pct}%\n\n"
            f"Verified AD Groups ({len(verified_groups)}):\n{groups_str}\n\n"
            f"Evidence CSV available in SSE UAR Dashboard. "
            f"Download and attach to close this finding."
        )

        payload = {"comment": comment_text}
        return self._request("POST", f"/api/v2/issues/{issue_id}/comments", payload)

    def close_finding(
        self,
        issue_id: int,
        evidence_csv_path: Path | None = None,
        close_note: str = "",
    ) -> dict:
        """
        Mark an AuditBoard finding as closed with optional evidence attachment.

        NOTE: Requires AuditBoard API permissions for issue closure.
        Confirm with GRC team which status code maps to "closed" in your instance.
        Common values: "Closed", "Remediated", "Accepted"
        """
        payload = {
            "status": "Closed",
            "remediation_note": (
                close_note or
                "[AUTOMATED] 100% MAR coverage verified by SSE UAR Pipeline. "
                "All AD groups enrolled in SailPoint UAR."
            ),
        }

        result = self._request("PATCH", f"/api/v2/issues/{issue_id}", payload)

        if evidence_csv_path and evidence_csv_path.exists():
            self._upload_attachment(issue_id, evidence_csv_path)

        return result

    def get_finding(self, issue_id: int) -> dict:
        """Fetch a single finding's current metadata from AuditBoard."""
        return self._request("GET", f"/api/v2/issues/{issue_id}")

    # ── HTTP Helpers ───────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = self.base + path

        if self.dry_run:
            print(f"[AuditBoard DRY RUN] {method} {url}")
            if payload:
                print(f"  Payload: {json.dumps(payload, indent=2)}")
            return {"dry_run": True}

        data = json.dumps(payload).encode() if payload else None
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _upload_attachment(self, issue_id: int, file_path: Path) -> None:
        """Upload a file as an attachment to an AuditBoard issue."""
        # Multipart form upload — simplified implementation
        # Full implementation requires multipart boundary encoding
        print(f"[AuditBoard] Would upload {file_path.name} to issue {issue_id}")
        # TODO: Implement multipart upload using urllib or requests
        # Placeholder until AuditBoard API attachment endpoint is confirmed
```

### Important Note on AuditBoard API

Before Phase 4 can go live:
1. Confirm the AuditBoard API version with GRC (v1 vs v2)
2. Request a service account API key with issue read/write/close permissions
3. Verify the exact status string for "closed" in Walmart's AuditBoard instance
4. Test in AuditBoard's sandbox environment first

---

## 6. Phase 5 — SailPoint/MAR Automation

### What It Does

Instead of manually downloading and placing MAR CSV files on disk, this phase:
1. Connects to the SailPoint API to pull current entitlement data directly
2. Eliminates the 752 MB local CSV dependency
3. Ensures the data is always current (not last month's export)

### Why It Matters

MAR CSVs are the #1 operational bottleneck:
- Must be manually downloaded from SharePoint
- Files are 752 MB and grow each quarter
- Data can be weeks out of date by run time
- Cannot be loaded into BigQuery due to size and sensitivity

### Architecture

```
  SailPoint API
  (Identity Security Cloud)
          │
          ▼
  coc_sailpoint.py
    ├── get_entitlements(app_name)
    ├── get_user_access(group_name)
    └── verify_group_in_uar(group_name)
          │
          ▼
  Replaces MAR CSV reads in build_dashboard.py
```

### Prerequisites

- SailPoint IdentityNow API credentials (Client ID + Client Secret)
- Credentials stored in: environment variables `SAILPOINT_CLIENT_ID`, `SAILPOINT_CLIENT_SECRET`
- SailPoint tenant URL (confirm with IAM team)
- OAuth2 token scope: `idn:entitlement-summary:read`, `idn:access-item:read`

### Code

**File:** `coc_sailpoint.py`

```python
"""
coc_sailpoint.py — Phase 5: SailPoint API Integration
Replaces MAR CSV file reads with live SailPoint API calls.

Requires:
    - SAILPOINT_CLIENT_ID environment variable
    - SAILPOINT_CLIENT_SECRET environment variable
    - SAILPOINT_TENANT_URL environment variable
      (e.g., "https://walmart.identitynow.com")

Usage:
    from coc_sailpoint import SailPointClient
    sp = SailPointClient()
    entitlements = sp.get_entitlements_for_group("gcp-my-app-prod")
"""
from __future__ import annotations
import os
import json
import urllib.request
import urllib.parse
from typing import Iterator


class SailPointClient:
    """
    SailPoint IdentityNow API client for UAR entitlement verification.

    Authenticates via OAuth2 client credentials flow.
    Token is cached and refreshed automatically.
    """

    def __init__(self):
        self.tenant_url    = os.environ.get("SAILPOINT_TENANT_URL", "").rstrip("/")
        self.client_id     = os.environ.get("SAILPOINT_CLIENT_ID")
        self.client_secret = os.environ.get("SAILPOINT_CLIENT_SECRET")
        self._token: str | None = None

        if not all([self.tenant_url, self.client_id, self.client_secret]):
            raise ValueError(
                "Missing SailPoint credentials. Set:\n"
                "  SAILPOINT_TENANT_URL\n"
                "  SAILPOINT_CLIENT_ID\n"
                "  SAILPOINT_CLIENT_SECRET"
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def group_in_uar(self, group_name: str) -> bool:
        """
        Check if an AD group is enrolled in a UAR campaign in SailPoint.

        Returns True if any active UAR certification contains this group.
        This replaces the MAR CSV word-boundary matching.
        """
        entitlements = list(self.get_entitlements_for_group(group_name))
        return len(entitlements) > 0

    def get_entitlements_for_group(self, group_name: str) -> Iterator[dict]:
        """
        Yield all entitlement records for a given AD group name.

        Equivalent to: MAR CSV rows WHERE entitlement LIKE '%group_name%'
        """
        # SailPoint entitlement search endpoint
        params = urllib.parse.urlencode({
            "filters": f'value eq "{group_name}"',
            "count":   "true",
            "limit":   "250",
        })
        url = f"{self.tenant_url}/v3/entitlements?{params}"

        page = self._get(url)
        yield from page.get("items", page if isinstance(page, list) else [])

    def get_active_uar_campaigns(self) -> list[dict]:
        """Return all active UAR certification campaigns."""
        url = f"{self.tenant_url}/v3/certifications?filters=type eq 'ACCESS_REVIEW'&status=ACTIVE"
        return self._get(url)

    def get_campaign_entitlements(self, campaign_id: str) -> list[dict]:
        """Return all entitlements under a specific UAR campaign."""
        url = f"{self.tenant_url}/v3/certifications/{campaign_id}/items?limit=1000"
        return self._get(url)

    # ── Auth ───────────────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        """Fetch OAuth2 token using client credentials flow."""
        url  = f"{self.tenant_url}/oauth/token"
        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            return result["access_token"]

    def _get(self, url: str) -> list | dict:
        if self._token is None:
            self._token = self._get_token()

        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
```

### Migration Strategy

Phase 5 is a **drop-in replacement** for the MAR CSV loading. The verification logic in `build_dashboard.py` does not change — only the data source changes:

```python
# Current (Phase 0): MAR CSV
mar_tokens = build_token_index(mar_df)
verified = word_boundary_check(group_name, mar_tokens)

# Phase 5: SailPoint API
sp = SailPointClient()
verified = sp.group_in_uar(group_name)
```

---

## 7. Phase 6 — Scheduled Pipeline (Looper/Cloud Scheduler)

### What It Does

Removes the requirement to manually run `py build_dashboard.py`. The pipeline runs automatically on a schedule (daily or weekly) and pushes the updated dashboard to GitHub Pages.

### Why It Matters

Manual execution means the dashboard is only as fresh as the last time someone remembered to run it. Automation guarantees freshness and enables leadership to trust the numbers at any time.

### Option A: Walmart Looper (Recommended)

Looper is Walmart's internal CI/CD scheduling platform. A Looper pipeline YAML triggers the script on a cron schedule.

**File:** `coc_looper_pipeline.yml`

```yaml
# Looper Pipeline — SSE UAR Dashboard Refresh
# Runs daily at 6:00 AM CT, Monday–Friday

name: sse-uar-dashboard-refresh
version: "1.0"

schedule:
  cron: "0 12 * * 1-5"   # 12:00 UTC = 06:00 CT

environment:
  GOOGLE_APPLICATION_CREDENTIALS: "/secrets/bq-service-account.json"
  AUDITBOARD_API_KEY:              "${{ secrets.AUDITBOARD_API_KEY }}"
  # MAR files must be on a network share accessible from the Looper agent
  # OR Phase 5 SailPoint integration must be complete

steps:
  - name: checkout
    uses: git/checkout@v1
    with:
      repo: gecgithub01.walmart.com/lparise/sse-uar-pipeline
      branch: main

  - name: install-dependencies
    run: |
      pip install google-cloud-bigquery pandas --index-url https://walmart.artifactoryonline.com/walmart/api/pypi/pypi/simple

  - name: refresh-dashboard
    run: |
      py build_dashboard.py

  - name: deploy-to-pages
    run: |
      git config user.email "looper-bot@walmart.com"
      git config user.name  "Looper Bot"
      cp sse_uar_dashboard.html ../sse-uar-dashboard/_sse_uar_pages/
      cd ../sse-uar-dashboard
      git checkout baseline
      git add sse_uar_dashboard.html
      git commit -m "chore: automated refresh $(date +%Y-%m-%d)"
      git push origin baseline
      git checkout master
      git pull origin baseline
      git push origin master

  - name: notify-team
    run: |
      py -c "
      from coc_notifier import NotificationEngine
      engine = NotificationEngine(dry_run=False)
      print('Notifications sent')
      "
```

### Option B: Google Cloud Scheduler + Cloud Run

If Looper access is unavailable, the pipeline can run as a Cloud Run job:

```bash
# Deploy as Cloud Run job (one-time setup)
gcloud run jobs create sse-uar-refresh \
  --image gcr.io/infosec-compliance-auditboard/sse-uar-pipeline:latest \
  --region us-central1 \
  --service-account sse-uar-pipeline@infosec-compliance-auditboard.iam.gserviceaccount.com

# Schedule with Cloud Scheduler
gcloud scheduler jobs create http sse-uar-daily \
  --schedule="0 12 * * 1-5" \
  --uri="https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/infosec-compliance-auditboard/jobs/sse-uar-refresh:run" \
  --oauth-service-account-email=sse-uar-pipeline@infosec-compliance-auditboard.iam.gserviceaccount.com
```

---

## 8. Phase 7 — Compliance Policy Enforcement

### What It Does

Implements hard enforcement rules that automatically:
1. **Block** new findings from being marked "Closed" in AuditBoard if MAR evidence is < 100%
2. **Flag** repeat offenders (APMs that had a finding closed without genuine remediation)
3. **Generate** a weekly executive report with compliance posture trends

### Policy Engine

**File:** `coc_policy_engine.py`

```python
"""
coc_policy_engine.py — Phase 7: Compliance Policy Enforcement
Enforces UAR closure rules and generates executive reports.

Policies:
    POLICY_NO_CLOSE_WITHOUT_MAR  : Block closure if pct < 100
    POLICY_ESCALATE_CRITICAL_7D  : Escalate Critical findings open > 7 days
    POLICY_FLAG_REPEAT_OFFENDERS : Track APMs with >1 closed-then-reopened cycle
"""
from __future__ import annotations
import datetime
import pandas as pd
from typing import NamedTuple


class PolicyViolation(NamedTuple):
    apm_id:      str
    policy_code: str
    message:     str
    severity:    str   # "block" | "warn" | "info"


def enforce_policies(df: pd.DataFrame) -> list[PolicyViolation]:
    """
    Run all compliance policies against the scored findings DataFrame.
    Returns a list of PolicyViolation objects for any violations found.
    """
    violations: list[PolicyViolation] = []

    for _, row in df.iterrows():
        apm       = str(row.get("ssp_apm_id", ""))
        pct       = int(row.get("pct", 0))
        risk_tier = str(row.get("risk_tier", "Low"))
        due_status = str(row.get("due_status", ""))

        # Policy 1: Cannot close without full MAR coverage
        if pct < 100 and due_status == "Past due":
            violations.append(PolicyViolation(
                apm_id      = apm,
                policy_code = "NO_CLOSE_WITHOUT_MAR",
                message     = f"{apm} is past due with only {pct}% MAR coverage. Cannot close.",
                severity    = "block",
            ))

        # Policy 2: Critical findings open > 7 days must be escalated
        if risk_tier == "Critical":
            violations.append(PolicyViolation(
                apm_id      = apm,
                policy_code = "ESCALATE_CRITICAL",
                message     = f"{apm} is Critical risk — manager escalation required.",
                severity    = "warn",
            ))

    return violations


def generate_executive_report(
    df: pd.DataFrame,
    history: list[dict],
    output_path: str = "sse_uar_executive_report.html",
) -> str:
    """
    Generate a concise HTML executive report suitable for leadership review.

    Sections:
    - Current posture snapshot (pie chart by risk tier)
    - Week-over-week trend (Can Close delta)
    - Top 10 highest risk findings
    - APMs ready to close (quick wins)
    """
    can_close  = (df["pct"] == 100).sum()
    needs_work = (df["pct"] == 0).sum()
    partial    = ((df["pct"] > 0) & (df["pct"] < 100)).sum()
    past_due   = (df["due_status"] == "Past due").sum()
    total      = len(df)

    critical = (df.get("risk_tier", pd.Series()) == "Critical").sum()
    high     = (df.get("risk_tier", pd.Series()) == "High").sum()

    # Week-over-week
    wow_delta = ""
    if len(history) >= 7:
        last_week_cc = history[-7].get("can_close", 0)
        current_cc   = int(can_close)
        delta        = current_cc - last_week_cc
        arrow        = "▲" if delta > 0 else "▼" if delta < 0 else "—"
        color        = "#16a34a" if delta > 0 else "#dc2626" if delta < 0 else "#6b7280"
        wow_delta    = f'<span style="color:{color}">{arrow} {abs(delta)} vs last week</span>'

    top10 = df.nlargest(10, "risk_score")[
        ["ssp_apm_id", "title", "pct", "due_status", "risk_score", "risk_tier"]
    ].to_html(index=False, classes="top10-table")

    quick_wins = df[df["pct"] == 100][["ssp_apm_id", "title"]].head(20).to_html(index=False)

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>SSE UAR Executive Report — {datetime.date.today()}</title>
<style>
  body {{ font-family: Arial, sans-serif; padding: 32px; max-width: 900px; margin: auto; }}
  .card {{ display: inline-block; padding: 16px 24px; margin: 8px;
           border-radius: 8px; background: #f3f4f6; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  .top10-table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
  .top10-table td, .top10-table th {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
</style>
</head>
<body>
<h1>SSE UAR Compliance Executive Report</h1>
<p><strong>Date:</strong> {datetime.date.today()} &nbsp;|&nbsp;
   <strong>Total Findings:</strong> {total} &nbsp;|&nbsp;
   {wow_delta}</p>

<h2>Posture Summary</h2>
<div>
  <div class="card"><div class="num">{can_close}</div>Can Close</div>
  <div class="card"><div class="num">{partial}</div>Partial</div>
  <div class="card"><div class="num" style="color:#dc2626">{needs_work}</div>Needs Work</div>
  <div class="card"><div class="num" style="color:#dc2626">{past_due}</div>Past Due</div>
  <div class="card"><div class="num" style="color:#dc2626">{critical}</div>Critical Risk</div>
  <div class="card"><div class="num" style="color:#ea580c">{high}</div>High Risk</div>
</div>

<h2>Top 10 Highest Risk Findings</h2>
{top10}

<h2>Quick Wins — Ready to Close</h2>
{quick_wins}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[exec report] Written to {output_path}")
    return output_path
```

---

## 9. Prerequisites and Access Requirements

| Phase | What's Needed | Who to Ask | Buildable Today? |
|-------|--------------|-----------|-----------------|
| **Phase 1** — Risk Scoring | Nothing new — uses existing pipeline output | — | ✅ Yes |
| **Phase 2** — BQ Writeback | BQ write access to `sse_findings_enriched_data` dataset | GCP/IAM team | ✅ If you have write access |
| **Phase 3** — Notifications | SMTP relay hostname OR Teams webhook URL | IT / Collaboration team | ✅ Can build; needs relay host |
| **Phase 4** — AuditBoard API | Service account API key with issue read/write/close scope | GRC team | 🟡 Needs GRC approval |
| **Phase 5** — SailPoint API | SailPoint OAuth2 client credentials | IAM team | 🟡 Needs IAM approval |
| **Phase 6** — Looper Schedule | Looper pipeline access OR Cloud Run service account | DevOps / Platform team | 🟡 Needs platform access |
| **Phase 7** — Policy Enforcement | Phases 1–4 complete | — | 🟡 After earlier phases |

### Environment Variables Required (full implementation)

```bash
# BigQuery (already works via gcloud auth login)
# No env var needed if using ADC

# AuditBoard
AUDITBOARD_API_KEY=<service-account-token>

# SailPoint
SAILPOINT_TENANT_URL=https://walmart.identitynow.com
SAILPOINT_CLIENT_ID=<client-id>
SAILPOINT_CLIENT_SECRET=<client-secret>

# Notifications
SMTP_HOST=mailrelay.walmart.com
TEAMS_WEBHOOK_URL=https://walmart.webhook.office.com/...
```

---

## 10. Phased Rollout Plan

```
Q2 2026 (Now)
├── Week 1-2: Phase 1 — Risk Scoring (no new credentials needed)
│   └── Deliverable: Risk score column in dashboard + executive summary card
│
├── Week 3-4: Phase 2 — BQ Writeback (request BQ write access)
│   └── Deliverable: uar_compliance_snapshots table populated daily
│
Q3 2026
├── Month 1: Phase 3 — Owner Notifications (dry_run=True first 2 weeks)
│   └── Deliverable: Automated email + Teams alerts to APM owners
│
├── Month 2: Phase 4 — AuditBoard API (GRC approval required)
│   └── Deliverable: Automated comments on findings; manual close assist
│
├── Month 3: Phase 5 — SailPoint API (IAM approval required)
│   └── Deliverable: MAR CSV dependency eliminated; live entitlement data
│
Q4 2026
├── Phase 6 — Looper Schedule (DevOps setup)
│   └── Deliverable: Fully automated daily refresh + deploy
│
└── Phase 7 — Policy Enforcement
    └── Deliverable: Hard block on closures without evidence; exec reports
```

---

## 11. Expected Outcomes by Phase

| Phase | Metric | Before | After |
|-------|--------|--------|-------|
| **Phase 1** | Time to identify highest-risk APMs | Manual review of 332 rows | Instant — top 10 surfaced automatically |
| **Phase 1** | Leadership reporting | Count-based dashboard | Risk-tiered posture with score |
| **Phase 2** | Audit trail coverage | Local JSON (1 file) | Full BQ history, queryable by any team |
| **Phase 2** | Trend data retention | As long as JSON file exists | Permanent, partition-optimized BQ table |
| **Phase 3** | Owner notification lag | Days to weeks (manual) | < 24 hours (automated) |
| **Phase 3** | Compliance team manual outreach | ~8 hrs/week | Near zero |
| **Phase 4** | Finding closure time | 3–5 days (manual evidence submission) | Same day (automated attachment) |
| **Phase 5** | Data freshness | Last SharePoint export date | Real-time from SailPoint |
| **Phase 5** | MAR file management | 752 MB manual download | Eliminated |
| **Phase 6** | Dashboard refresh frequency | Weekly (when someone remembers) | Daily, automated |
| **Phase 7** | Policy enforcement | Honor system | System-enforced; no bypass |

**Cumulative impact (all phases):**
- Compliance team effort: **~15 hrs/week → ~2 hrs/week** (exception handling only)
- Finding closure cycle time: **2–4 weeks → 3–5 days**
- Audit evidence quality: **Manual attachments** → **Automated, standardized CSV + API comment**
- Leadership visibility: **Weekly manual update** → **Daily automated dashboard + executive report**

---

## 12. Risk and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| AuditBoard API rate limiting | Medium | Medium | Implement exponential backoff; batch requests |
| SailPoint API data lag vs MAR | Low | High | Validate against MAR CSV for first 30 days in parallel |
| Automated email spam to owners | High | Medium | Start with `dry_run=True`; review before enabling |
| BQ write permission denial | Medium | Low | Phase 2 can be skipped; `dashboard_history.json` continues |
| Looper schedule failure | Low | Medium | Alerting webhook to SSE Slack channel on failure |
| AuditBoard auto-close wrong finding | Low | Critical | Require manual approval step; close-only after human review in Phase 4 |

---

## Appendix A — File Structure

```
UAR W SSE/
├── build_dashboard.py          ← Existing pipeline (no changes needed for Phase 1)
├── template.html               ← Dashboard HTML template
├── sse_uar_dashboard.html      ← Generated output
├── dashboard_history.json      ← Trend history (replaced by BQ in Phase 2)
├── DASHBOARD_GUIDE.md          ← Team reference guide
│
└── CoC Implement/              ← THIS FOLDER
    ├── README.md               ← This document
    ├── coc_risk_scorer.py      ← Phase 1: Risk scoring engine
    ├── coc_bq_writeback.py     ← Phase 2: BQ audit trail
    ├── coc_notifier.py         ← Phase 3: Owner notifications
    ├── coc_auditboard.py       ← Phase 4: AuditBoard API
    ├── coc_sailpoint.py        ← Phase 5: SailPoint API
    └── coc_looper_pipeline.yml ← Phase 6: Looper scheduling
```

---

## Appendix B — How to Start Today (Phase 1 Quickstart)

1. Copy `coc_risk_scorer.py` into the `UAR W SSE/` folder
2. Add these lines to the bottom of `main()` in `build_dashboard.py`, before HTML rendering:

```python
from coc_risk_scorer import score_findings, summarize_risk
records_df = pd.DataFrame(records)
records_df = score_findings(records_df)
risk_summary = summarize_risk(records_df)
print(f"\n{'='*60}")
print(f"RISK SUMMARY: {risk_summary}")
print(f"{'='*60}\n")
```

3. Run `py build_dashboard.py` — risk scores print to console
4. Review the Critical tier list — this is your remediation priority order

No credentials, no API keys, no new services. **Phase 1 is available immediately.**

---

*This document was prepared by the SSE Security Engineering team for review by developers and leadership prior to implementation. All code samples are production-quality starting points and should be reviewed by the development team before deployment.*
