# SSE UAR Findings Dashboard — Team Guide

## Overview

The SSE UAR Findings Dashboard tracks User Access Review (UAR) findings across all active APMs in scope. It shows which APMs have AD groups enrolled in UAR (via SailPoint/MAR), which can be closed, and which still need work.

**Live Report:** https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html

---

## How to Refresh the Dashboard

1. Connect to **Walmart VPN**
2. Ensure `gcloud auth login` has been completed (one-time setup)
3. Open a terminal and navigate to the pipeline folder:
   ```
   C:\Users\lparise\OneDrive - Walmart Inc\Desktop\SSE Tean\SSE 2025 Projects\Goals\UAR W SSE
   ```
4. Run:
   ```
   py build_dashboard.py
   ```
5. Output file: `sse_uar_dashboard.html` (~12 MB, self-contained)

> **Note:** Use `py` (system Python), not `uv run python`. Only `py` has the `google.cloud.bigquery` package installed.

---

## Data Sources

### Live from BigQuery (`infosec-compliance-auditboard`) — queried fresh every run

| Table | Purpose |
|-------|---------|
| `sse_data_lake.vw_unified_findings` | Driving table — one row per active UAR finding |
| `sse_findings_enriched_data.uar_findings_enriched` | LLM fields + AD group columns (LEFT JOIN) |
| `snow_apm_data.sse_apm_data_prod` | APM sensitivity, PCI/SOX flags |
| `sse_findings_enriched_data.uar_apm_enriched` | APM Universe (all ~7,952 APMs) |
| `sse_findings_enriched_data.uar_galaxy_enriched` | Azure subscription signal |
| `sse_data_lake.vw_master_action_plans` | Stage 1e: AD groups in remediation text |
| `sse_data_lake.vw_master_issues` | Stage 1f: AD groups in issue descriptions |

**Findings filter:**
```sql
WHERE norm_status = 'Active'
  AND ssp_apm_id IS NOT NULL
  AND UPPER(title) LIKE '%UAR%'
```

### Local MAR Files (SharePoint) — read from disk

Location:
```
C:\Users\lparise\Walmart Inc\SSE - Global Compliance Program - Documents
\PowerBI\Manual Reports Data\MAR Information\
```

| File | Purpose |
|------|---------|
| `CONSOLIDATEDEntitlementReport (5).csv` | Primary evidence — MAR user/entitlement data |
| `CONSOLIDATEDEntitlementReport.csv` + 4 others | Quarter mapping only |

> MAR files are ~752 MB total and cannot be loaded into BigQuery, so they remain local.

---

## How the Pipeline Works (Step by Step)

### Step 1 — Load MAR Data
Reads all MAR CSVs to build:
- `entitlement → quarter` mapping (34,695 entries)
- Evidence DataFrame for MAR verification and CSV downloads
- Token index for fast AD group matching

### Step 2 — Load Findings from BQ
Queries `vw_unified_findings` LEFT JOIN `uar_findings_enriched`.
Returns 332 rows across 290 unique APMs (grouped into 332 unique titles).

### Step 3 — AD Group Extraction (4 stages)

| Stage | Source | What it does |
|-------|--------|-------------|
| 1 (primary) | `uar_findings_enriched` columns | Reads `kitt_ad_group`, `signal_ad_groups`, `gcp_owner_groups`, `gcp_prod_owner_groups`, `rl_access_groups`, `kitt_sibling_ad_groups`, `desc_named_groups` |
| 1e | `vw_master_action_plans.remediation_action` | Parses free-text for explicit "AD Group:" references and known prefixes (`gcp-`, `hw-`, `sams-`, etc.) |
| 1f | `vw_master_issues.description` + `issue_notes` | Same parsing approach on issue description and notes fields |

All extracted groups are merged per APM before MAR verification.

### Step 4 — Strict AD → MAR Verification
Each AD group is matched against MAR entitlements using a **word-boundary rule**:
- Minimum 4-character group name
- Must match on word boundary (dash, underscore, space, start, or end)
- OR entitlement ends with the group name
- OR core name (prefix-stripped: `gcp-`, `hw-`, etc.) appears in entitlement

A token index pre-filters candidates for speed (~20k checks instead of 28M).

### Step 5 — Build Per-Title Records
Records are grouped by **unique title** (not APM ID). For each title:
- `toClose` = number of AD groups verified in MAR
- `keepOpen` = number of AD groups NOT verified in MAR
- `pct` = `round(toClose / (toClose + keepOpen) * 100)`
- `due_status` = worst-case across all rows for that title

### Step 6 — APM Universe
Loads all 7,952 APMs from `uar_apm_enriched`, enriches with Stage 1e/1f groups, and runs the same MAR verification to categorize each APM.

### Step 7 — Daily Snapshot + History
Saves today's metrics to `dashboard_history.json` for the Trends chart. One entry per day; same-day refreshes overwrite.

### Step 8 — Render HTML
Injects all data into `template.html` and writes `sse_uar_dashboard.html`.

---

## Dashboard Cards Explained

| Card | Calculation |
|------|------------|
| **Total** | Count of unique titles from `vw_unified_findings` |
| **Can Close** | Titles where `pct == 100` (all AD groups verified in MAR) |
| **Partial** | Titles where `0 < pct < 100` (some groups verified) |
| **Needs Work** | Titles where `pct == 0` (no groups verified in MAR) |
| **Past Due** | Titles where `due_status == "Past due"` (from `vw_unified_findings`) |

---

## APM Universe Tab

Shows all ~7,952 APMs from `uar_apm_enriched` regardless of whether they have an active finding.

| Status | Meaning |
|--------|---------|
| **Can Close** | All AD groups are verified in MAR — ready for UAR |
| **Needs Finding** | Has AD groups but none verified in MAR yet |
| **No AD Groups** | No AD groups found in any source |

The **"Already has finding"** flag is set when the APM ID appears in `vw_unified_findings` as an active UAR finding (IDs normalised: `8623` → `APM0008623`).

---

## Evidence CSV Download

For every **Can Close** APM, a pre-built MAR evidence CSV is embedded in the dashboard. Click **Download Evidence** on any Can Close row to get a CSV with:
- `userId`, `DisplayName`, `status`, `Certifier`
- `application`, `entitlement`, `entitlementDesc`, `CertifiedDate`, `quarter`

The CSV contains only entitlements that strictly match the APM's verified AD groups (same word-boundary rule as verification).

---

## Deploying to GitHub Pages

After refreshing:
```bash
# Copy to pages repo
cp sse_uar_dashboard.html <path_to_sse-uar-dashboard_repo>/_sse_uar_pages/

# Push to baseline and master
cd <path_to_sse-uar-dashboard_repo>
git checkout baseline && git add sse_uar_dashboard.html && git commit -m "chore: refresh dashboard" && git push origin baseline
git checkout master && git pull origin baseline && git push origin master
```

GitHub Pages serves from the `baseline` branch.
Live URL: https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html
