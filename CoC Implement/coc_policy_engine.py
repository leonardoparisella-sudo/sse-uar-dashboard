"""
coc_policy_engine.py — Phase 7: Compliance Policy Enforcement
Enforces UAR closure rules and generates executive-ready reports.

This module provides:
    1. Policy enforcement (PolicyEngine): validates findings against rules
    2. Executive report generation: HTML report for leadership review
    3. Repeat offender detection: tracks APMs with recurring findings

Usage:
    from coc_policy_engine import PolicyEngine, generate_executive_report
    from coc_risk_scorer   import score_findings

    engine    = PolicyEngine()
    scored_df = score_findings(records_df)
    violations = engine.enforce(scored_df)
    for v in violations:
        print(v)

    generate_executive_report(scored_df, history, output_path="exec_report.html")
"""
from __future__ import annotations
import datetime
from pathlib import Path
from typing import NamedTuple
import pandas as pd


DASHBOARD_URL = "https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html"


# ── Policy Violation ──────────────────────────────────────────────────────────

class PolicyViolation(NamedTuple):
    apm_id:      str
    policy_code: str
    message:     str
    severity:    str   # "block" | "warn" | "info"

    def __str__(self) -> str:
        icon = {"block": "🚫", "warn": "⚠", "info": "ℹ"}.get(self.severity, "•")
        return f"[{self.severity.upper()}] {icon} {self.apm_id} — {self.policy_code}: {self.message}"


# ── Policy Engine ─────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Runs defined compliance policies against the scored findings DataFrame.

    Active Policies:
        NO_CLOSE_WITHOUT_MAR : Cannot close a finding with <100% MAR coverage
        ESCALATE_CRITICAL    : Critical findings must be escalated to manager
        FLAG_REPEAT_OFFENDER : APM had a finding closed then reopened
        STALE_PARTIAL        : Partial coverage (>0%) unchanged for >30 days
    """

    def enforce(
        self,
        df: pd.DataFrame,
        history: list[dict] | None = None,
    ) -> list[PolicyViolation]:
        """
        Run all active policies against the findings DataFrame.

        Args:
            df      : Risk-scored findings DataFrame (output of score_findings)
            history : Historical snapshots list for stale/repeat detection

        Returns:
            List of PolicyViolation named tuples
        """
        violations: list[PolicyViolation] = []

        # Build repeat offender set from history
        repeat_apms: set[str] = set()
        if history and len(history) >= 2:
            for snap in history[:-1]:
                repeat_apms.update(snap.get("can_close_apms", []))

        # Build stale partial map: apm_id → days_since_pct_changed
        stale_map = self._detect_stale_partials(df, history or [])

        for _, row in df.iterrows():
            apm        = str(row.get("ssp_apm_id", "") or "")
            pct        = int(row.get("pct", 0) or 0)
            due_status = str(row.get("due_status", "") or "")
            risk_tier  = str(row.get("risk_tier", "Low") or "Low")

            # Policy 1: NO_CLOSE_WITHOUT_MAR
            if pct < 100 and due_status == "Past due":
                violations.append(PolicyViolation(
                    apm_id      = apm,
                    policy_code = "NO_CLOSE_WITHOUT_MAR",
                    message     = f"Cannot close — only {pct}% MAR coverage. Minimum 100% required.",
                    severity    = "block",
                ))

            # Policy 2: ESCALATE_CRITICAL
            if risk_tier == "Critical":
                violations.append(PolicyViolation(
                    apm_id      = apm,
                    policy_code = "ESCALATE_CRITICAL",
                    message     = f"Critical risk tier — manager escalation required per SSE policy.",
                    severity    = "warn",
                ))

            # Policy 3: FLAG_REPEAT_OFFENDER
            if apm in repeat_apms and due_status == "Past due":
                violations.append(PolicyViolation(
                    apm_id      = apm,
                    policy_code = "FLAG_REPEAT_OFFENDER",
                    message     = f"APM {apm} was previously closed but is now past due again. Repeat offender.",
                    severity    = "warn",
                ))

            # Policy 4: STALE_PARTIAL
            if apm in stale_map and 0 < pct < 100:
                days_stale = stale_map[apm]
                if days_stale >= 30:
                    violations.append(PolicyViolation(
                        apm_id      = apm,
                        policy_code = "STALE_PARTIAL",
                        message     = f"Partial coverage ({pct}%) unchanged for {days_stale} days.",
                        severity    = "warn",
                    ))

        # Summary
        blocks = sum(1 for v in violations if v.severity == "block")
        warns  = sum(1 for v in violations if v.severity == "warn")
        print(f"[PolicyEngine] {len(violations)} violations — {blocks} blocks, {warns} warnings")

        return violations

    def violations_to_dataframe(self, violations: list[PolicyViolation]) -> pd.DataFrame:
        """Convert violations list to a DataFrame for reporting."""
        if not violations:
            return pd.DataFrame(columns=["apm_id", "policy_code", "message", "severity"])
        return pd.DataFrame([v._asdict() for v in violations])

    def _detect_stale_partials(
        self,
        df: pd.DataFrame,
        history: list[dict],
    ) -> dict[str, int]:
        """
        Detect APMs where partial coverage has not changed in N+ days.

        Returns dict of {apm_id: days_since_change}
        """
        if not history:
            return {}

        current_pct: dict[str, int] = {}
        if "ssp_apm_id" in df.columns and "pct" in df.columns:
            current_pct = dict(zip(df["ssp_apm_id"].astype(str), df["pct"].fillna(0).astype(int)))

        stale: dict[str, int] = {}
        today = datetime.date.today()

        for snap in reversed(history):  # most recent first
            snap_date_str = snap.get("date", "")
            snap_pcts     = snap.get("apm_pct_map", {})   # optional fine-grained history

            if not snap_date_str or not snap_pcts:
                continue

            try:
                snap_date = datetime.date.fromisoformat(snap_date_str)
            except ValueError:
                continue

            days_ago = (today - snap_date).days

            for apm, cur_pct in current_pct.items():
                prior_pct = snap_pcts.get(apm)
                if prior_pct is not None and prior_pct == cur_pct and 0 < cur_pct < 100:
                    stale[apm] = max(stale.get(apm, 0), days_ago)

        return stale


# ── Executive Report Generator ────────────────────────────────────────────────

def generate_executive_report(
    df: pd.DataFrame,
    history: list[dict] | None = None,
    violations: list[PolicyViolation] | None = None,
    output_path: str | Path = "sse_uar_executive_report.html",
) -> Path:
    """
    Generate a concise HTML executive report for leadership review.

    Sections:
    - Posture snapshot (counts by status and risk tier)
    - Week-over-week trend
    - Top 10 highest risk findings
    - Quick wins (APMs at 100% ready to close)
    - Policy violations summary

    Args:
        df           : Risk-scored findings DataFrame
        history      : List of historical snapshot dicts
        violations   : List of PolicyViolation from PolicyEngine.enforce()
        output_path  : Where to write the HTML file

    Returns:
        Path to the generated report file
    """
    history    = history    or []
    violations = violations or []

    today      = datetime.date.today()
    total      = len(df)
    can_close  = int((df["pct"] == 100).sum())
    partial    = int(((df["pct"] > 0) & (df["pct"] < 100)).sum())
    needs_work = int((df["pct"] == 0).sum())
    past_due   = int((df.get("due_status", "") == "Past due").sum())

    critical = int((df.get("risk_tier", pd.Series()) == "Critical").sum()) if "risk_tier" in df.columns else 0
    high     = int((df.get("risk_tier", pd.Series()) == "High").sum())     if "risk_tier" in df.columns else 0
    avg_score = round(float(df["risk_score"].mean()), 1) if "risk_score" in df.columns else 0.0

    # Week-over-week delta
    wow_html = ""
    if len(history) >= 7:
        try:
            last_week_cc = int(history[-7].get("can_close", 0))
            delta        = can_close - last_week_cc
            arrow        = "▲" if delta > 0 else "▼" if delta < 0 else "—"
            color        = "#16a34a" if delta > 0 else "#dc2626" if delta < 0 else "#6b7280"
            wow_html     = f'<span style="color:{color};font-size:1.1rem">{arrow} {abs(delta)} Can Close vs 7 days ago</span>'
        except Exception:
            pass

    # Top 10 highest risk
    top_cols = [c for c in ["ssp_apm_id", "title", "pct", "due_status", "risk_score", "risk_tier"] if c in df.columns]
    if "risk_score" in df.columns:
        top10_html = (
            df.nlargest(10, "risk_score")[top_cols]
            .to_html(index=False, border=0, classes="data-table")
        )
    else:
        top10_html = "<p>Risk scoring not available — add coc_risk_scorer.py integration.</p>"

    # Quick wins
    qw_cols   = [c for c in ["ssp_apm_id", "title"] if c in df.columns]
    qw_df     = df[df["pct"] == 100][qw_cols].head(20)
    quick_html = qw_df.to_html(index=False, border=0, classes="data-table")

    # Policy violations
    v_rows = "".join(
        f"<tr><td>{v.apm_id}</td><td>{v.policy_code}</td>"
        f"<td style='color:{'#dc2626' if v.severity=='block' else '#ea580c'}'>{v.severity.upper()}</td>"
        f"<td>{v.message}</td></tr>"
        for v in violations[:50]
    )
    v_table = (
        f"<table class='data-table'><thead><tr>"
        f"<th>APM</th><th>Policy</th><th>Severity</th><th>Message</th>"
        f"</tr></thead><tbody>{v_rows}</tbody></table>"
        if violations else "<p>No policy violations found.</p>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSE UAR Executive Report — {today}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    background: #f8fafc; color: #1e293b; padding: 32px;
  }}
  .page {{ max-width: 1000px; margin: auto; }}
  h1 {{ font-size: 1.75rem; font-weight: 700; margin-bottom: 4px; }}
  h2 {{ font-size: 1.2rem; font-weight: 600; margin: 32px 0 12px; color: #334155; }}
  .meta {{ color: #64748b; margin-bottom: 24px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }}
  .card {{
    background: white; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 16px 20px; min-width: 120px; text-align: center;
  }}
  .card .num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .card .lbl {{ font-size: 0.8rem; color: #64748b; margin-top: 4px; }}
  .red {{ color: #dc2626; }}
  .orange {{ color: #ea580c; }}
  .green {{ color: #16a34a; }}
  .data-table {{
    width: 100%; border-collapse: collapse; font-size: 0.875rem;
    background: white; border-radius: 8px; overflow: hidden;
  }}
  .data-table th {{
    background: #f1f5f9; padding: 10px 12px; text-align: left;
    font-weight: 600; border-bottom: 1px solid #e2e8f0;
  }}
  .data-table td {{
    padding: 8px 12px; border-bottom: 1px solid #f1f5f9;
  }}
  .footer {{
    margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0;
    color: #94a3b8; font-size: 0.8rem;
  }}
</style>
</head>
<body>
<div class="page">
  <h1>SSE UAR Compliance Executive Report</h1>
  <p class="meta">
    Generated: {today} &nbsp;|&nbsp;
    Total Findings: <strong>{total}</strong> &nbsp;|&nbsp;
    Avg Risk Score: <strong>{avg_score}</strong>
    {f' &nbsp;|&nbsp; {wow_html}' if wow_html else ''}
  </p>

  <h2>Compliance Posture</h2>
  <div class="cards">
    <div class="card"><div class="num green">{can_close}</div><div class="lbl">Can Close</div></div>
    <div class="card"><div class="num orange">{partial}</div><div class="lbl">Partial</div></div>
    <div class="card"><div class="num red">{needs_work}</div><div class="lbl">Needs Work</div></div>
    <div class="card"><div class="num red">{past_due}</div><div class="lbl">Past Due</div></div>
    <div class="card"><div class="num red">{critical}</div><div class="lbl">Critical Risk</div></div>
    <div class="card"><div class="num orange">{high}</div><div class="lbl">High Risk</div></div>
  </div>

  <h2>Top 10 Highest Risk Findings</h2>
  {top10_html}

  <h2>Quick Wins — Ready to Close Now ({can_close} total)</h2>
  <p style="color:#64748b;margin-bottom:8px">These APMs have 100% MAR coverage.
  Download evidence from the
  <a href="{DASHBOARD_URL}" style="color:#2563eb">SSE UAR Dashboard</a> and close in AuditBoard.</p>
  {quick_html}

  <h2>Policy Violations ({len(violations)})</h2>
  {v_table}

  <div class="footer">
    <p>SSE UAR Compliance Pipeline &nbsp;|&nbsp; Auto-generated &nbsp;|&nbsp;
    <a href="{DASHBOARD_URL}">Live Dashboard</a></p>
  </div>
</div>
</body>
</html>"""

    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    print(f"[exec report] Written to {out}")
    return out


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    print("Running coc_policy_engine standalone test...\n")

    mock_df = pd.DataFrame([
        {"ssp_apm_id": "APM0001000", "title": "APM0001000 UAR", "pct": 0,   "due_status": "Past due",  "risk_tier": "Critical", "risk_score": 90},
        {"ssp_apm_id": "APM0001001", "title": "APM0001001 UAR", "pct": 60,  "due_status": "Past due",  "risk_tier": "High",     "risk_score": 55},
        {"ssp_apm_id": "APM0001002", "title": "APM0001002 UAR", "pct": 100, "due_status": "Active",    "risk_tier": "Low",      "risk_score": 5},
        {"ssp_apm_id": "APM0001003", "title": "APM0001003 UAR", "pct": 0,   "due_status": "Active",    "risk_tier": "Medium",   "risk_score": 20},
    ])

    engine     = PolicyEngine()
    violations = engine.enforce(mock_df)

    print("\nViolations:")
    for v in violations:
        print(f"  {v}")

    out = generate_executive_report(
        mock_df,
        history    = [],
        violations = violations,
        output_path= Path(__file__).parent / "test_exec_report.html",
    )
    print(f"\nReport written to: {out}")
    print("Open in a browser to preview the executive report layout.")
