"""
coc_risk_scorer.py — Phase 1: UAR Risk Scoring Engine
Reads the pipeline output DataFrame and appends risk_score + risk_tier.

Usage:
    from coc_risk_scorer import score_findings, summarize_risk
    df_scored = score_findings(df)
    summary   = summarize_risk(df_scored)

No external credentials required. Works on DataFrames already built by build_dashboard.py.

Integration into build_dashboard.py (add before HTML render):
    from coc_risk_scorer import score_findings, summarize_risk
    records_df = pd.DataFrame(records)
    records_df = score_findings(records_df)
    risk_summary = summarize_risk(records_df)
    print(f"[Risk] {risk_summary}")
"""
from __future__ import annotations
import datetime
import pandas as pd


# ── Scoring Weights ────────────────────────────────────────────────────────────

WEIGHT_PAST_DUE     = 35   # Is the finding currently past due?
WEIGHT_DAYS_MAX     = 20   # Maximum points from days overdue
WEIGHT_DAYS_DIVISOR = 3    # 1 point per N days overdue (capped at WEIGHT_DAYS_MAX)
WEIGHT_NO_GROUPS    = 20   # pct == 0: no AD groups verified in MAR at all
WEIGHT_PARTIAL      = 10   # 0 < pct < 100: some groups verified, some not
WEIGHT_PCI          = 15   # APM is in PCI scope
WEIGHT_SOX          = 10   # APM is in SOX scope
WEIGHT_HIGH_SENS    = 5    # APM has High sensitivity classification
WEIGHT_REPEAT       = 10   # Finding was closed then reopened (repeat offender)

# Risk tier thresholds (inclusive lower bound)
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
    Add risk_score (int 0-100), risk_tier (str), and risk_color (hex str) to df.

    Args:
        df       : Per-title records DataFrame from build_dashboard.py.
                   Expected columns: pct, due_status.
                   Optional columns: due_date, ssp_apm_id.
        apm_meta : Optional APM metadata with columns: apm_id, is_pci, is_sox, sensitivity.
                   When provided, PCI/SOX/sensitivity weights are applied.
        history  : Optional dashboard_history.json entries as list of dicts.
                   Used to detect APMs that were previously closed but reopened.

    Returns:
        Copy of df with added columns: risk_score, risk_tier, risk_color
    """
    df = df.copy()

    # ── Factor 1: Past due flag ─────────────────────────────────────────────
    df["_past_due"] = (df.get("due_status", pd.Series([""] * len(df))) == "Past due").astype(int)

    # ── Factor 2: Days overdue ──────────────────────────────────────────────
    today = datetime.date.today()
    if "due_date" in df.columns:
        def _days_over(d) -> int:
            if pd.isna(d):
                return 0
            try:
                return max(0, (today - pd.to_datetime(d).date()).days)
            except Exception:
                return 0
        df["_days_over"] = df["due_date"].apply(_days_over)
    else:
        df["_days_over"] = 0

    # ── Factor 3: MAR coverage gap ──────────────────────────────────────────
    pct_col = df.get("pct", pd.Series([0] * len(df))).fillna(0).astype(int)
    df["_no_groups"] = (pct_col == 0).astype(int)
    df["_partial"]   = ((pct_col > 0) & (pct_col < 100)).astype(int)

    # ── Factor 4: APM metadata (PCI, SOX, sensitivity) ─────────────────────
    df["_pci"]  = 0
    df["_sox"]  = 0
    df["_sens"] = 0
    if apm_meta is not None and not apm_meta.empty and "apm_id" in apm_meta.columns:
        meta = apm_meta.set_index("apm_id")
        if "ssp_apm_id" in df.columns:
            for idx, row in df.iterrows():
                apm = row.get("ssp_apm_id")
                if apm and apm in meta.index:
                    m = meta.loc[apm]
                    df.at[idx, "_pci"]  = int(bool(m.get("is_pci", False)))
                    df.at[idx, "_sox"]  = int(bool(m.get("is_sox", False)))
                    df.at[idx, "_sens"] = int(
                        str(m.get("sensitivity", "")).strip().lower() == "high"
                    )

    # ── Factor 5: Repeat finding detection ─────────────────────────────────
    # An APM is a repeat if it appeared in a prior snapshot's can_close list
    # but is now active again (was closed, then reopened).
    repeat_apms: set[str] = set()
    if history and len(history) >= 2:
        for snap in history[:-1]:  # all snapshots except the most recent
            repeat_apms.update(snap.get("can_close_apms", []))
    apm_series = df.get("ssp_apm_id", pd.Series([""] * len(df))).fillna("")
    df["_repeat"] = apm_series.isin(repeat_apms).astype(int)

    # ── Compute total score ─────────────────────────────────────────────────
    days_pts = (
        df["_days_over"]
        .clip(upper=WEIGHT_DAYS_MAX * WEIGHT_DAYS_DIVISOR)
        .div(WEIGHT_DAYS_DIVISOR)
    )

    df["risk_score"] = (
        df["_past_due"]  * WEIGHT_PAST_DUE  +
        days_pts         * 1                +   # 1 pt per day, capped at WEIGHT_DAYS_MAX
        df["_no_groups"] * WEIGHT_NO_GROUPS +
        df["_partial"]   * WEIGHT_PARTIAL   +
        df["_pci"]       * WEIGHT_PCI       +
        df["_sox"]       * WEIGHT_SOX       +
        df["_sens"]      * WEIGHT_HIGH_SENS +
        df["_repeat"]    * WEIGHT_REPEAT
    ).clip(upper=100).round().astype(int)

    # ── Assign tier and color ───────────────────────────────────────────────
    def _tier_color(score: int) -> tuple[str, str]:
        if score >= TIER_CRITICAL_MIN:
            return "Critical", "#dc2626"   # red
        if score >= TIER_HIGH_MIN:
            return "High",     "#ea580c"   # orange
        if score >= TIER_MEDIUM_MIN:
            return "Medium",   "#ca8a04"   # amber
        return "Low",      "#16a34a"       # green

    tiers_colors = df["risk_score"].apply(lambda s: pd.Series(_tier_color(s), index=["risk_tier", "risk_color"]))
    df[["risk_tier", "risk_color"]] = tiers_colors

    # ── Clean working columns ───────────────────────────────────────────────
    df.drop(columns=[c for c in df.columns if c.startswith("_")], inplace=True)

    return df


def summarize_risk(df: pd.DataFrame) -> dict:
    """
    Return tier distribution and average score for leadership summary.

    Args:
        df : DataFrame with risk_score and risk_tier columns (output of score_findings)

    Returns:
        dict with keys: critical, high, medium, low, avg_score, total
    """
    if "risk_tier" not in df.columns:
        df = score_findings(df)

    counts = df["risk_tier"].value_counts().to_dict()
    return {
        "total":     len(df),
        "critical":  counts.get("Critical", 0),
        "high":      counts.get("High",     0),
        "medium":    counts.get("Medium",   0),
        "low":       counts.get("Low",      0),
        "avg_score": round(float(df["risk_score"].mean()), 1),
    }


def top_risks(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return the N highest-risk findings, sorted by risk_score descending."""
    if "risk_score" not in df.columns:
        df = score_findings(df)
    cols = [c for c in ["ssp_apm_id", "title", "pct", "due_status", "risk_score", "risk_tier"] if c in df.columns]
    return df.nlargest(n, "risk_score")[cols].reset_index(drop=True)


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running coc_risk_scorer standalone test...\n")

    mock_data = pd.DataFrame([
        # Past due, zero coverage — Critical
        {"ssp_apm_id": "APM0001000", "title": "APM0001000 UAR", "pct": 0,   "due_status": "Past due"},
        # Past due, partial coverage — High
        {"ssp_apm_id": "APM0001001", "title": "APM0001001 UAR", "pct": 50,  "due_status": "Past due"},
        # Active, full coverage — Low
        {"ssp_apm_id": "APM0001002", "title": "APM0001002 UAR", "pct": 100, "due_status": "Active"},
        # Active, zero coverage — Medium
        {"ssp_apm_id": "APM0001003", "title": "APM0001003 UAR", "pct": 0,   "due_status": "Active"},
        # Active, partial — Low
        {"ssp_apm_id": "APM0001004", "title": "APM0001004 UAR", "pct": 75,  "due_status": "Active"},
    ])

    scored = score_findings(mock_data)
    print(scored[["ssp_apm_id", "pct", "due_status", "risk_score", "risk_tier"]])
    print()
    print("Summary:", summarize_risk(scored))
    print()
    print("Top risks:")
    print(top_risks(scored, n=3))
