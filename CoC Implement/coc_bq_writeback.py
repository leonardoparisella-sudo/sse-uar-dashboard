"""
coc_bq_writeback.py — Phase 2: BigQuery Audit Trail Writeback
Saves each pipeline run's scored findings to a persistent BQ snapshot table.

Prerequisites:
    - BQ write access to: infosec-compliance-auditboard.sse_findings_enriched_data
    - google-cloud-bigquery already installed (same requirement as build_dashboard.py)
    - Run create_snapshot_table_ddl() once in BQ Console to create the table

Usage:
    from coc_bq_writeback import write_snapshot, create_snapshot_table_ddl
    # One-time table setup:
    print(create_snapshot_table_ddl())   # copy SQL into BQ console
    # Per-run writeback:
    write_snapshot(records_df)
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


# ── Public API ─────────────────────────────────────────────────────────────────

def write_snapshot(
    df: pd.DataFrame,
    run_timestamp: datetime.datetime | None = None,
    dry_run: bool = False,
) -> int:
    """
    Write scored findings DataFrame as a daily snapshot to BigQuery.

    This is idempotent: if today's snapshot already exists it is deleted and
    replaced, so re-running the pipeline on the same day is safe.

    Args:
        df            : Output of score_findings(). Must contain pct, due_status.
                        Optionally: risk_score, risk_tier, ssp_apm_id, title,
                        toClose, keepOpen, all_groups, verified_groups,
                        is_pci, is_sox, sensitivity.
        run_timestamp : UTC datetime for this run. Defaults to utcnow().
        dry_run       : If True, prints rows instead of writing to BQ.

    Returns:
        Number of rows written (or that would be written in dry_run mode).
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
            "ad_groups_found":    json.dumps(sorted(row.get("all_groups", []) or [])),
            "ad_groups_verified": json.dumps(sorted(row.get("verified_groups", []) or [])),
            "is_pci":             bool(row.get("is_pci", False)),
            "is_sox":             bool(row.get("is_sox", False)),
            "sensitivity":        str(row.get("sensitivity", "") or ""),
        })

    if not rows:
        print("[BQ writeback] No rows to write — DataFrame is empty.")
        return 0

    if dry_run:
        print(f"[BQ writeback DRY RUN] Would write {len(rows)} rows to {TABLE_REF} for {today}")
        for r in rows[:3]:
            print("  Sample row:", r)
        return len(rows)

    client = bigquery.Client(project=PROJECT)

    # Idempotent: delete today's rows before inserting fresh ones
    delete_sql = f"DELETE FROM `{TABLE_REF}` WHERE snapshot_date = '{today.isoformat()}'"
    client.query(delete_sql).result()
    print(f"[BQ writeback] Cleared existing rows for {today}")

    # Insert new rows
    errors = client.insert_rows_json(client.get_table(TABLE_REF), rows)
    if errors:
        raise RuntimeError(f"BigQuery streaming insert errors: {errors}")

    print(f"[BQ writeback] ✓ {len(rows)} rows written to {TABLE_REF} for {today}")
    return len(rows)


def read_history_from_bq(days: int = 90) -> list[dict]:
    """
    Read daily summary history from BQ for use in trend charts.
    Replaces dashboard_history.json once Phase 2 is live.

    Returns list of dicts matching the dashboard_history.json schema:
        [{"date": "2026-05-01", "total": 332, "can_close": 45, ...}, ...]
    """
    client = bigquery.Client(project=PROJECT)
    sql = f"""
        SELECT
            snapshot_date                                    AS date,
            COUNT(*)                                         AS total,
            COUNTIF(pct = 100)                               AS can_close,
            COUNTIF(pct > 0 AND pct < 100)                   AS partial,
            COUNTIF(pct = 0)                                 AS needs_work,
            COUNTIF(due_status = 'Past due')                 AS past_due,
            COUNTIF(risk_tier = 'Critical')                  AS critical,
            ROUND(AVG(risk_score), 1)                        AS avg_risk_score
        FROM `{TABLE_REF}`
        WHERE snapshot_date >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY)
        GROUP BY snapshot_date
        ORDER BY snapshot_date ASC
    """
    rows = client.query(sql).to_dataframe()
    return rows.to_dict(orient="records")


def create_snapshot_table_ddl() -> str:
    """
    Return the CREATE TABLE DDL string for the snapshot table.
    Run this ONCE in BigQuery Console before Phase 2 goes live.
    """
    return f"""-- ============================================================
-- SSE UAR Compliance Snapshot Table — run ONCE in BQ Console
-- ============================================================
CREATE TABLE IF NOT EXISTS `{TABLE_REF}`
(
    snapshot_date      DATE         NOT NULL
        OPTIONS(description = 'Date of this pipeline run (partitioning key)'),
    run_timestamp      TIMESTAMP    NOT NULL
        OPTIONS(description = 'UTC timestamp of the build_dashboard.py run'),
    ssp_apm_id         STRING
        OPTIONS(description = 'Normalized APM ID, e.g. APM0001234'),
    title              STRING
        OPTIONS(description = 'Finding title from vw_unified_findings'),
    pct                INT64
        OPTIONS(description = 'MAR coverage: round(to_close / (to_close + keep_open) * 100)'),
    to_close           INT64
        OPTIONS(description = 'Number of AD groups verified in MAR'),
    keep_open          INT64
        OPTIONS(description = 'Number of AD groups NOT verified in MAR'),
    due_status         STRING
        OPTIONS(description = 'Active | Past due | etc from vw_unified_findings'),
    risk_score         INT64
        OPTIONS(description = 'Composite risk score 0-100 from coc_risk_scorer.py'),
    risk_tier          STRING
        OPTIONS(description = 'Critical | High | Medium | Low'),
    ad_groups_found    STRING
        OPTIONS(description = 'JSON array of all AD groups found for this APM'),
    ad_groups_verified STRING
        OPTIONS(description = 'JSON array of AD groups verified in MAR'),
    is_pci             BOOL
        OPTIONS(description = 'APM is in PCI scope'),
    is_sox             BOOL
        OPTIONS(description = 'APM is in SOX scope'),
    sensitivity        STRING
        OPTIONS(description = 'APM sensitivity level from SNOW')
)
PARTITION BY snapshot_date
CLUSTER BY ssp_apm_id, risk_tier
OPTIONS (
    description = 'SSE UAR daily compliance snapshots — written by build_dashboard.py + coc_bq_writeback.py',
    require_partition_filter = FALSE
);"""


# ── Useful BQ Queries ──────────────────────────────────────────────────────────

SAMPLE_QUERIES = """
-- Q1: Week-over-week Can Close delta
SELECT
    snapshot_date,
    COUNTIF(pct = 100) AS can_close,
    COUNTIF(pct = 100) - LAG(COUNTIF(pct = 100)) OVER (ORDER BY snapshot_date) AS delta
FROM `{table}`
GROUP BY snapshot_date
ORDER BY snapshot_date DESC
LIMIT 30;

-- Q2: APMs consistently in Critical tier (last 30 days)
SELECT ssp_apm_id, title, COUNT(*) AS days_critical, MAX(risk_score) AS max_score
FROM `{table}`
WHERE risk_tier = 'Critical'
  AND snapshot_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
GROUP BY ssp_apm_id, title
HAVING days_critical >= 20
ORDER BY max_score DESC;

-- Q3: APMs that improved (pct increased vs 7 days ago)
SELECT
    t.ssp_apm_id,
    t.title,
    p.pct AS pct_7_days_ago,
    t.pct AS pct_today,
    t.pct - p.pct AS improvement
FROM `{table}` t
JOIN `{table}` p
  ON t.ssp_apm_id = p.ssp_apm_id
  AND p.snapshot_date = DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
WHERE t.snapshot_date = CURRENT_DATE()
  AND t.pct > p.pct
ORDER BY improvement DESC;
""".format(table=TABLE_REF)


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 2: BQ Writeback — Setup Instructions")
    print("=" * 60)
    print()
    print("Step 1: Run this DDL in BigQuery Console to create the table:")
    print()
    print(create_snapshot_table_ddl())
    print()
    print("Step 2: Add to build_dashboard.py (before HTML render):")
    print("""
    from coc_bq_writeback import write_snapshot
    import datetime
    write_snapshot(pd.DataFrame(records), run_timestamp=datetime.datetime.utcnow())
    """)
    print()
    print("Step 3: Verify the table exists:")
    print(f"    SELECT COUNT(*) FROM `{TABLE_REF}`")
