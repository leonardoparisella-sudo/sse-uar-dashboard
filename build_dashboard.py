"""
build_dashboard.py — SSE UAR Evidence Collection Dashboard
Self-contained single script: BigQuery loaders, inline strict AD→MAR matching,
APM record builder, and HTML generation. No dependency on the puppy workspace.

Usage:
    py -3.13 build_dashboard.py

Output:
    sse_uar_dashboard.html  (self-contained, ~4 MB)

Data sources:
    BigQuery (infosec-compliance-auditboard):
        sse_findings_enriched_data.uar_findings_enriched
        sse_data_lake.vw_unified_findings        (join: u.id = v.issue_id)
        snow_apm_data.sse_apm_data_prod
    Local CSVs (MAR files only — ~752 MB, too large for BQ):
        C:\\Users\\lparise\\Walmart Inc\\SSE - Global Compliance Program - Documents
        \\PowerBI\\Manual Reports Data\\MAR Information\\
"""
from __future__ import annotations

import base64
import datetime
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd
from google.cloud import bigquery


# ── Constants ──────────────────────────────────────────────────────────────────

PROJECT = "infosec-compliance-auditboard"
BQ_FINDINGS = f"`{PROJECT}.sse_findings_enriched_data.uar_findings_enriched`"
BQ_UNIFIED  = f"`{PROJECT}.sse_data_lake.vw_unified_findings`"
BQ_APM      = f"`{PROJECT}.snow_apm_data.sse_apm_data_prod`"

MAR_DIR = Path(
    r"C:\Users\lparise\Walmart Inc\SSE - Global Compliance Program - Documents"
    r"\PowerBI\Manual Reports Data\MAR Information"
)
MAR_FILES = [
    "CONSOLIDATEDEntitlementReport.csv",
    "CONSOLIDATEDEntitlementReport (2).csv",
    "CONSOLIDATEDEntitlementReport (4).csv",
    "CONSOLIDATEDEntitlementReport (5).csv",
    "SailPointEntitlementReport.csv",
    "All Entitlement Report (3).csv",
]
MAR_EVIDENCE_FILE = "CONSOLIDATEDEntitlementReport (5).csv"

AD_GROUP_COLS = [
    "kitt_ad_group", "signal_ad_groups",
    "gcp_owner_groups", "gcp_prod_owner_groups",
    "rl_access_groups", "kitt_sibling_ad_groups", "desc_named_groups",
]

# Columns for the APM Universe tab (uar_apm_enriched)
BQ_APM_ENRICHED = f"`{PROJECT}.sse_findings_enriched_data.uar_apm_enriched`"
BQ_GALAXY       = f"`{PROJECT}.sse_findings_enriched_data.uar_galaxy_enriched`"
APM_ENRICHED_AD_COLS = ["Kitt_AD_Group", "GCP_Owner_Groups", "GCP_Prod_Owner_Groups", "AZ_AD_Groups"]

HERE = Path(__file__).parent
OUTPUT = HERE / "sse_uar_dashboard.html"
TEMPLATE_FILE = HERE / "template.html"
HISTORY_FILE  = HERE / "dashboard_history.json"
AB_BASE = "https://walmart-infosec.auditboardapp.com"


# ── BQ client ──────────────────────────────────────────────────────────────────

_bq_client: bigquery.Client | None = None


def _bq() -> bigquery.Client:
    global _bq_client
    if _bq_client is None:
        _bq_client = bigquery.Client(project=PROJECT)
    return _bq_client


def _query(sql: str) -> pd.DataFrame:
    """Execute SQL and return DataFrame. Avoids db-dtypes dependency."""
    job = _bq().query(sql)
    rows = list(job.result())
    if not rows:
        cols = [field.name for field in job.result().schema]
        return pd.DataFrame(columns=cols)
    return pd.DataFrame([dict(r) for r in rows])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_str(val, default: str = "") -> str:
    if val is None:
        return default
    if isinstance(val, float):
        import math
        if math.isnan(val):
            return default
    return str(val)


def parse_owner_email(raw: str) -> str:
    """Extract Walmart email from a ServiceNow owner dict string."""
    if not raw:
        return ""
    s = str(raw).strip()
    for pat in (
        r"'display_value'\s*:\s*'([^']+)'",
        r'"display_value"\s*:\s*"([^"]+)"',
    ):
        m = re.search(pat, s)
        if m:
            uid = re.search(r'\(([^)]+)\)\s*$', m.group(1).strip())
            if uid:
                return f"{uid.group(1)}@walmart.com"
    return ""


def parse_owner(raw: str) -> str:
    """Extract human-readable name from a ServiceNow display_value dict."""
    if not raw:
        return "Unknown"
    s = str(raw).strip()
    m = re.search(r"'display_value'\s*:\s*'([^']+)'", s)
    if m:
        return re.sub(r'\s*\([^)]+\)\s*$', '', m.group(1)).strip()[:30]
    m = re.search(r'"display_value"\s*:\s*"([^"]+)"', s)
    if m:
        return m.group(1)[:30]
    return s[:30]


def clean_ad_group(g: str) -> str:
    """Normalize AD group name — strip brackets, quotes, @walmart.com."""
    if not g:
        return ""
    g = re.sub(r"[\[\]\"']", "", str(g).strip())
    return re.sub(r"@walmart\.com$", "", g, flags=re.IGNORECASE).strip()


def extract_groups_from_value(val) -> set[str]:
    """Parse an AD group field that may be JSON list, CSV, or plain string."""
    groups: set[str] = set()
    if val is None:
        return groups
    val = str(val).strip()
    if val in ("", "null", "None", "[]", "nan"):
        return groups
    # Try JSON list
    try:
        parsed = json.loads(val.replace("'", '"'))
        if isinstance(parsed, list):
            return {clean_ad_group(g) for g in parsed if len(clean_ad_group(g)) >= 3}
    except (json.JSONDecodeError, ValueError):
        pass
    # Comma-separated or plain string
    parts = val.split(",") if "," in val else [val]
    for part in parts:
        cleaned = clean_ad_group(part)
        if cleaned and len(cleaned) >= 3:
            groups.add(cleaned)
    return groups


def get_quarter_for_group(group: str, entitlement_quarters: dict, default: str) -> str:
    if not group:
        return default
    return entitlement_quarters.get(group.strip().lower(), default)


def _sens_level(dc: str) -> str:
    dc = (dc or "").lower().strip()
    if "highly_sensitive" in dc or "restricted_highly_sensitive" in dc:
        return "highly_sensitive"
    if dc == "sensitive":
        return "sensitive"
    if "non" in dc and "sensitive" in dc:
        return "non_sensitive"
    return ""


# ── Strict AD→MAR matching (inlined from verify_strict_matches.py) ─────────────

def is_meaningful_match(ad_group: str, entitlement: str) -> bool:
    """Return True if ad_group meaningfully appears in entitlement.

    Rules (all require >= 4-char ad_group after cleaning):
      1. Word-boundary regex match (dash/underscore/space/start/end)
      2. Entitlement ends with the ad_group
      3. Core name (prefix-stripped) appears in entitlement
    """
    ad_clean = clean_ad_group(ad_group).lower()
    ent_lower = entitlement.lower()
    if len(ad_clean) < 4:
        return False
    pattern = r'(^|[\s\-_])' + re.escape(ad_clean) + r'($|[\s\-_@])'
    if re.search(pattern, ent_lower):
        return True
    if ent_lower.endswith(ad_clean):
        return True
    ad_core = re.sub(r'^(gcp-|hw-|sams-|intl-|ad\s*-\s*)', '', ad_clean, flags=re.IGNORECASE)
    if len(ad_core) >= 4 and ad_core in ent_lower:
        return True
    return False


def build_strict_verification(
    apm_all_groups: dict[str, set[str]],
    mar_ent_counts: dict[str, dict],
    mar_df: pd.DataFrame | None = None,
) -> dict[str, dict]:
    """Cross-reference all APM AD groups against MAR entitlements.

    Args:
        apm_all_groups: apm_id → set of AD group names (from BQ)
        mar_ent_counts: entitlement_lower → {'original': str, 'count': int}
                        (built from MAR evidence CSV)
        mar_df: Full MAR evidence DataFrame for unique userId counting.
                If None, falls back to summing per-entitlement counts (may double-count).

    Returns:
        apm_verified: apm_id → {'ad_groups': [...], 'mar_entitlements': [...], 'user_count': int}
    """
    print("Performing strict AD→MAR verification (inline)...")
    apm_verified: dict[str, dict] = {}

    for apm, groups in apm_all_groups.items():
        if not groups:
            continue
        matched_groups: list[str] = []
        matched_ents: list[str] = []
        matched_ent_lowers: list[str] = []

        for ad_group in groups:
            best_ent: str | None = None
            best_ent_lower: str | None = None
            best_count = 0
            for ent_lower, info in mar_ent_counts.items():
                if is_meaningful_match(ad_group, ent_lower):
                    if best_ent is None or info["count"] > best_count:
                        best_ent = info["original"]
                        best_ent_lower = ent_lower
                        best_count = info["count"]
            if best_ent:
                matched_groups.append(ad_group)
                if best_ent not in matched_ents:
                    matched_ents.append(best_ent)
                    matched_ent_lowers.append(best_ent_lower)

        if matched_groups:
            # Fix #3: count unique userIds across all matched entitlements,
            # not sum of per-entitlement counts (which double-counts users).
            if mar_df is not None and matched_ent_lowers:
                mask = mar_df["entitlement_lower"].isin(matched_ent_lowers)
                unique_users = mar_df.loc[mask, "userId"].dropna().nunique()
            else:
                # Fallback: sum per-entitlement counts (conservative, may double-count)
                unique_users = sum(
                    mar_ent_counts[el]["count"]
                    for el in matched_ent_lowers
                    if el in mar_ent_counts
                )

            apm_verified[apm] = {
                "ad_groups": matched_groups,
                "mar_entitlements": matched_ents,
                "user_count": unique_users,
            }

    print(f"   {len(apm_verified)} APMs have verified UAR evidence")
    return apm_verified


# ── Data loaders ───────────────────────────────────────────────────────────────

def load_mar_quarters() -> tuple[dict, set, list[pd.DataFrame]]:
    """Load MAR CSV files. Returns (entitlement_quarters, all_quarters, [evidence_df])."""
    entitlement_quarters: dict = {}
    all_quarters: set = set()

    print("Loading quarter info from MAR files...")
    for name in MAR_FILES:
        fp = MAR_DIR / name
        if not fp.exists():
            continue
        try:
            chunk = pd.read_csv(
                fp,
                usecols=lambda c: c.lower() in {"entitlement", "quarter"},
                low_memory=False,
            )
            chunk.columns = chunk.columns.str.lower()
            if {"entitlement", "quarter"}.issubset(chunk.columns):
                chunk = chunk.dropna(subset=["entitlement", "quarter"])
                chunk["entitlement"] = chunk["entitlement"].str.strip().str.lower()
                chunk["quarter"] = chunk["quarter"].str.strip()
                entitlement_quarters.update(zip(chunk["entitlement"], chunk["quarter"]))
                all_quarters.update(chunk["quarter"].unique())
                print(f"   OK {name}: {len(chunk):,} rows")
        except Exception as exc:
            print(f"   WARN {name}: {exc}")

    print(f"Found {len(entitlement_quarters):,} entitlement->quarter mappings")
    print(f"Quarters: {sorted(all_quarters, reverse=True)[:5]}")

    mar_dataframes: list[pd.DataFrame] = []
    evidence_path = MAR_DIR / MAR_EVIDENCE_FILE
    if evidence_path.exists():
        try:
            ev = pd.read_csv(evidence_path, low_memory=False)
            ev["entitlement_lower"] = (
                ev["entitlement"].fillna("").astype(str).str.strip().str.lower()
            )
            mar_dataframes.append(ev)
            print(f"Evidence file loaded: {len(ev):,} rows")
        except Exception as exc:
            print(f"WARN evidence file: {exc}")

    return entitlement_quarters, all_quarters, mar_dataframes


def load_findings() -> pd.DataFrame:
    """Load active UAR findings from unified_findings (authoritative source),
    LEFT JOIN uar_findings_enriched for LLM/AD group enrichment fields.

    Driving table: unified_findings (364 active UAR rows / 320 APMs)
    Enrichment:    uar_findings_enriched via issue_id (260/364 matched)
    """
    print("Loading UAR findings from BigQuery...")

    BQ_UF = f"`{PROJECT}.sse_data_lake.unified_findings`"

    sql = f"""
    SELECT
      v.issue_id                        AS issue_id,
      v.ssp_apm_id                      AS apm_id,
      u.uid,
      v.issue_status,
      v.vbu,
      v.apm_App_Name                    AS ssp_application_name,
      u.llm_sla,
      u.llm_sentiment_analysis,
      u.llm_summarized_comments,
      u.llm_last_reach_out,
      u.llm_ownership_change_requested,
      u.llm_customer_question_requested,
      COALESCE(v.task_reviewer, u.llm_sse_reviewer) AS llm_sse_reviewer,
      u.llm_auditboard_link,
      u.snow_data_classification,
      u.apm_sox_flag,
      u.hsd_scope,
      u.kitt_ad_group,
      u.signal_ad_groups,
      u.gcp_owner_groups,
      u.gcp_prod_owner_groups,
      u.rl_access_groups,
      u.kitt_sibling_ad_groups,
      u.desc_named_groups,
      v.title,
      v.issue_sub_type,
      v.norm_status,
      v.due_date,
      v.due_status,
      v.remediation_owner,
      v.remediation_owner_email
    FROM {BQ_UF} v
    LEFT JOIN {BQ_FINDINGS} u
      ON v.issue_id = u.id
    WHERE v.ssp_apm_id IS NOT NULL
      AND v.norm_status = 'Active'
      AND (
        UPPER(COALESCE(v.issue_sub_type, '')) LIKE '%UAR%'
        OR UPPER(COALESCE(v.title, ''))       LIKE '%UAR%'
      )
    """

    df = _query(sql)
    df["issue_id"] = df["issue_id"].fillna(0).astype(int)
    df["apm_id"] = df["apm_id"].fillna("").astype(str).str.strip()
    df["apm_sox_flag"] = df["apm_sox_flag"].fillna(False).astype(bool)
    df["hsd_scope"] = df["hsd_scope"].fillna(False).astype(bool)

    # Fallback: derive email from owner dict for remaining blanks
    blank = df["remediation_owner_email"].fillna("").astype(str).str.strip().isin(["", "nan", "None"])
    if blank.any():
        df.loc[blank, "remediation_owner_email"] = (
            df.loc[blank, "remediation_owner"].apply(
                lambda x: parse_owner_email(str(x)) if pd.notna(x) else ""
            )
        )

    filled = (df["remediation_owner_email"].fillna("").astype(str).str.strip() != "").sum()
    print(f"Loaded {len(df):,} rows, {df['apm_id'].nunique()} unique APMs")
    print(f"Owner emails resolved: {filled}/{len(df)}")
    return df


def load_sensitivity() -> dict[str, dict]:
    """Load APM sensitivity classification from sse_apm_data_prod."""
    print("Loading APM sensitivity from BigQuery...")

    sql = f"""
    SELECT
      APMid,
      App_Name,
      Data_Classification,
      Flagged_PCI,
      Flagged_SOX
    FROM {BQ_APM}
    WHERE APMid IS NOT NULL
    QUALIFY ROW_NUMBER() OVER (PARTITION BY APMid ORDER BY APMid) = 1
    """

    df = _query(sql)
    df["sens_level"] = df["Data_Classification"].fillna("").apply(_sens_level)
    df["pci"] = df["Flagged_PCI"].astype(str).str.lower() == "true"
    df["sox"] = df["Flagged_SOX"].astype(str).str.lower() == "true"

    result: dict[str, dict] = {}
    for _, row in df.iterrows():
        apm = _safe_str(row.get("APMid"))
        if not apm:
            continue
        result[apm] = {
            "data_class": _safe_str(row.get("Data_Classification")),
            "sens_level": row["sens_level"],
            "pci": bool(row["pci"]),
            "sox": bool(row["sox"]),
            "app_name": _safe_str(row.get("App_Name"))[:40],
        }

    print(f"Loaded {len(result)} APM sensitivity records")
    return result


def load_ad_groups_from_bq(df: pd.DataFrame) -> dict[str, set[str]]:
    """Extract all AD groups per APM from the already-loaded findings DataFrame."""
    print("Extracting AD groups from findings data...")
    apm_all_groups: dict[str, set[str]] = {}
    for _, row in df.iterrows():
        apm = _safe_str(row.get("apm_id"))
        if not apm:
            continue
        groups: set[str] = set()
        for col in AD_GROUP_COLS:
            val = row.get(col)
            if val is not None and str(val).strip() not in ("", "nan", "None"):
                groups.update(extract_groups_from_value(val))
        apm_all_groups.setdefault(apm, set()).update(groups)

    has_groups = sum(1 for v in apm_all_groups.values() if v)
    print(f"   {has_groups} APMs have AD groups, {len(apm_all_groups) - has_groups} have none")
    return apm_all_groups


def load_ab_links(df: pd.DataFrame) -> tuple[dict, dict]:
    """Build AuditBoard link maps from findings DataFrame."""
    print("Building AuditBoard links...")
    links: dict = {}
    link_types: dict = {}

    for apm, group in df.groupby("apm_id"):
        apm = str(apm)
        row = group.iloc[0]
        llm_link = _safe_str(row.get("llm_auditboard_link", ""))
        if llm_link.startswith("http"):
            links[apm] = llm_link
            link_types[apm] = "direct"
        elif pd.notna(row.get("issue_id")) and row.get("issue_id", 0):
            links[apm] = f"{AB_BASE}/issues/{int(row['issue_id'])}"
            link_types[apm] = "fallback"

    direct = sum(1 for t in link_types.values() if t == "direct")
    fallback = sum(1 for t in link_types.values() if t == "fallback")
    print(f"AuditBoard links: {direct} direct + {fallback} fallback = {len(links)} total")
    return links, link_types


# ── APM record builder ─────────────────────────────────────────────────────────

_EMPTY_SENS = {"data_class": "", "sens_level": "", "pci": False, "sox": False, "app_name": ""}

_CSV_COLS = [
    "userId", "DisplayName", "status", "Certifier",
    "application", "entitlement", "entitlementDesc", "CertifiedDate", "quarter",
]
_CSV_HEADER = ",".join(_CSV_COLS)


def _csv_row(row: pd.Series) -> str:
    vals = [str(row.get(c, "") or "").replace('"', '""') for c in _CSV_COLS]
    return ",".join(f'"{v}"' for v in vals)


def build_evidence_csv(in_uar: set[str], mar_df: pd.DataFrame | None, apm: str, quarter: str) -> str:
    """Build base64-encoded MAR evidence CSV for in-browser download.

    Uses the same strict is_meaningful_match() rule as verification so the
    downloaded CSV contains exactly the same entitlements that caused the APM
    to be marked Can Close — no loose substring surprises.

    User deduplication: if a userId appears in multiple matched entitlements
    they are included once per entitlement (each row is a certification event),
    but the MAR user count reported in the dashboard is unique users.
    """
    lines = [_CSV_HEADER]
    seen_row_keys: set[tuple] = set()

    if in_uar and mar_df is not None:
        for ent_lower, row_info in (
            (el, ri) for el, ri in
            [(e.lower(), e) for e in mar_df["entitlement"].dropna().unique()]
        ):
            # Only include entitlements that strictly match at least one verified AD group
            if not any(is_meaningful_match(g, ent_lower) for g in in_uar):
                continue
            matches = mar_df[mar_df["entitlement_lower"] == ent_lower]
            for _, r in matches.iterrows():
                key = (str(r.get("userId", "")), str(r.get("entitlement", "")))
                if key in seen_row_keys:
                    continue
                seen_row_keys.add(key)
                lines.append(_csv_row(r))

    if len(lines) == 1:  # only header
        in_uar_str = "|".join(in_uar)
        lines.append(
            f'"N/A","No MAR data found","","","{apm}","{in_uar_str}",'
            f'"AD groups in UAR but no MAR rows","","{quarter}"'
        )

    return base64.b64encode("\n".join(lines).encode()).decode()


def build_apm_list(
    df: pd.DataFrame,
    apm_all_groups: dict[str, set[str]],
    apm_verified: dict[str, dict],
    apm_sensitivity: dict[str, dict],
    ab_links: dict,
    ab_types: dict,
    entitlement_quarters: dict,
    current_quarter: str,
    mar_dataframes: list[pd.DataFrame],
) -> list[dict[str, Any]]:
    """Build the final serialisable APM list with embedded evidence CSVs."""
    print("Building APM records...")
    mar_df = mar_dataframes[0] if mar_dataframes else None

    # Fix #1: Aggregate all rows per APM first, then build one record per APM.
    # This ensures multi-finding APMs use worst-case due_status, first non-null
    # owner/email, and all LLM fields from the most data-rich row.
    DUE_STATUS_RANK = {"Past due": 0, "Due soon": 1, "On track": 2, "": 3}

    apm_rows: dict[str, list] = {}
    for _, row in df.iterrows():
        apm = str(row["apm_id"])
        apm_rows.setdefault(apm, []).append(row)

    records: dict[str, dict] = {}

    for apm, rows in apm_rows.items():
        all_groups = apm_all_groups.get(apm, set())
        verified_info = apm_verified.get(apm)

        if verified_info:
            verified = set(verified_info["ad_groups"])
            mar_ents = verified_info["mar_entitlements"]
            mar_user_count = verified_info.get("user_count", 0)
            in_uar = verified
            not_in_uar = all_groups - verified
            status = "ALL_DOING_UAR" if not not_in_uar else "PARTIAL_UAR"
        else:
            mar_ents = []
            mar_user_count = 0
            in_uar = set()
            not_in_uar = all_groups
            status = "NOT_DOING_UAR" if all_groups else "NO_AD_GROUPS"

        # Fix #4: Deterministic quarter — use max() over all matched group quarters.
        # Sets are unordered; iterating until first hit produced different results each run.
        matched_quarters = [
            get_quarter_for_group(g, entitlement_quarters, "")
            for g in in_uar
        ]
        matched_quarters = [q for q in matched_quarters if q]
        quarter = max(matched_quarters) if matched_quarters else current_quarter

        sens = apm_sensitivity.get(apm, _EMPTY_SENS)

        # Fix #1: Select the best row for scalar fields.
        # due_status: worst-case (Past due > Due soon > On track)
        # owner/email/issue_status: first non-null/non-empty value across all rows
        best_due_status = min(
            (_safe_str(r.get("due_status", "")) for r in rows),
            key=lambda s: DUE_STATUS_RANK.get(s, 3),
        )

        def _first_non_empty(field: str) -> str:
            for r in rows:
                v = _safe_str(r.get(field, ""))
                if v and v not in ("nan", "None"):
                    return v
            return ""

        # LLM fields — pick the row with the longest summary (most complete LLM run)
        best_llm_row = max(
            rows,
            key=lambda r: len(_safe_str(r.get("llm_summarized_comments", ""))),
        )

        llm = {
            "sla":               _safe_str(best_llm_row.get("llm_sla")),
            "sentiment":         _safe_str(best_llm_row.get("llm_sentiment_analysis")),
            "summary":           _safe_str(best_llm_row.get("llm_summarized_comments")),
            "last_reach_out":    _safe_str(best_llm_row.get("llm_last_reach_out")),
            "ownership_change":  _safe_str(best_llm_row.get("llm_ownership_change_requested")),
            "customer_question": _safe_str(best_llm_row.get("llm_customer_question_requested")),
            "sse_reviewer":      _safe_str(best_llm_row.get("llm_sse_reviewer")),
        }

        # Title/VBU: use first row (consistent since all rows share the same APM)
        first_row = rows[0]

        # is_enriched: True if any row for this APM matched uar_findings_enriched (uid populated)
        is_enriched = any(_safe_str(r.get("uid", "")) not in ("", "nan", "None") for r in rows)

        records[apm] = {
            "is_enriched": is_enriched,
            "apm": apm,
            "title": _first_non_empty("title")[:50],
            "owner": parse_owner(_first_non_empty("remediation_owner")),
            "email": _first_non_empty("remediation_owner_email"),
            "due_date": _first_non_empty("due_date"),
            "due_status": best_due_status,
            "issue_status": _first_non_empty("issue_status") or "Pending Remediation",
            "vbu": _first_non_empty("vbu"),
            "app_name": sens["app_name"] or _safe_str(first_row.get("ssp_application_name", ""))[:40],
            "quarter": quarter,
            # Sensitivity
            "data_class": sens["data_class"],
            "sens_level": sens["sens_level"],
            "pci": sens["pci"],
            "sox": sens["sox"],
            # AuditBoard
            "auditboard_link": ab_links.get(apm, ""),
            "ab_link_type": ab_types.get(apm, ""),
            # LLM
            "llm_sla": llm["sla"],
            "llm_sentiment": llm["sentiment"],
            "llm_summary": llm["summary"],
            "llm_last_reach_out": llm["last_reach_out"],
            "llm_ownership_change": llm["ownership_change"],
            "llm_customer_question": llm["customer_question"],
            "llm_sse_reviewer": llm["sse_reviewer"],
            # AD groups
            "in_uar": in_uar,
            "not_in_uar": not_in_uar,
            "all_ad_groups": all_groups,
            "toClose": len(in_uar),
            "keepOpen": len(not_in_uar),
            "mar_ents_list": mar_ents,
            "mar_user_count": mar_user_count,
            "uar_status": status,
            "findings": [
                {
                    "id": _safe_str(r.get("issue_id", "")),
                    "due_date": _safe_str(r.get("due_date", "")),
                }
                for r in rows
            ],
        }

    # Serialise to list
    print("Generating evidence CSVs (can-close only)...")
    result: list[dict[str, Any]] = []
    for apm, data in records.items():
        total_ad = data["toClose"] + data["keepOpen"]
        pct = round(data["toClose"] / total_ad * 100) if total_ad else 0
        # Only embed CSV for APMs that can fully close (pct == 100) — saves ~2.5 MB
        csv_b64 = build_evidence_csv(data["in_uar"], mar_df, apm, data["quarter"]) if pct == 100 else ""
        mar_ents_str = ", ".join(data["mar_ents_list"]) if data["mar_ents_list"] else ""
        in_uar_str = "|".join(data["in_uar"])
        result.append({
            "apm": apm,
            "title": data["title"],
            "owner": data["owner"],
            "email": data["email"],
            "due_date": data["due_date"],
            "due_status": data["due_status"],
            "issue_status": data["issue_status"],
            "vbu": data["vbu"],
            "app_name": data["app_name"],
            "quarter": data["quarter"],
            "sens_level": data["sens_level"],
            "data_class": data["data_class"],
            "pci": data["pci"],
            "sox": data["sox"],
            "auditboard_link": data["auditboard_link"],
            "ab_link_type": data["ab_link_type"],
            "llm_sla": data["llm_sla"],
            "llm_sentiment": data["llm_sentiment"],
            "llm_summary": data["llm_summary"],
            "llm_last_reach_out": data["llm_last_reach_out"],
            "llm_ownership_change": data["llm_ownership_change"],
            "llm_customer_question": data["llm_customer_question"],
            "llm_sse_reviewer": data["llm_sse_reviewer"],
            "toClose": data["toClose"],
            "keepOpen": data["keepOpen"],
            "pct": pct,
            "all_ad_groups": "|".join(data["all_ad_groups"]),
            "in_uar": in_uar_str,
            "not_in_uar": "|".join(data["not_in_uar"]),
            "mar_matched_groups": in_uar_str.replace("|", ", "),
            "mar_entitlements": mar_ents_str,
            "mar_user_count": data["mar_user_count"],
            "findings": data["findings"],
            "csv_b64": csv_b64,
            "is_enriched": data["is_enriched"],
        })

    return result


# ── Token-indexed MAR matcher (fast pre-filter for large APM sets) ─────────────

def build_mar_token_index(mar_ent_counts: dict[str, dict]) -> dict[str, list[str]]:
    """Build a token → [ent_lowers] index for fast candidate lookup.

    Tokenizes each entitlement on word boundaries (dash, underscore, space).
    For an AD group query we look up each token of the group name and get a
    small candidate set before running the full is_meaningful_match() regex.
    This cuts 7948×3500 = 28M calls down to ~1000×(small candidate set).
    """
    index: dict[str, list[str]] = {}
    for ent_lower in mar_ent_counts:
        tokens = re.split(r'[\s\-_@]+', ent_lower)
        for tok in tokens:
            if len(tok) >= 4:
                index.setdefault(tok, []).append(ent_lower)
    return index


def get_mar_candidates(ad_group: str, token_index: dict[str, list[str]]) -> set[str]:
    """Return candidate entitlement_lowers that share at least one token with ad_group."""
    ad_clean = clean_ad_group(ad_group).lower()
    if len(ad_clean) < 4:
        return set()
    tokens = re.split(r'[\s\-_@]+', ad_clean)
    candidates: set[str] = set()
    for tok in tokens:
        if len(tok) >= 4:
            candidates.update(token_index.get(tok, []))
    # Also try full string and core name (strip common prefixes)
    ad_core = re.sub(r'^(gcp-|hw-|sams-|intl-|ad\s*-\s*)', '', ad_clean, flags=re.IGNORECASE)
    if len(ad_core) >= 4:
        for tok in re.split(r'[\s\-_@]+', ad_core):
            if len(tok) >= 4:
                candidates.update(token_index.get(tok, []))
    return candidates


def build_strict_verification_fast(
    apm_all_groups: dict[str, set[str]],
    mar_ent_counts: dict[str, dict],
    token_index: dict[str, list[str]],
    mar_df: pd.DataFrame | None = None,
) -> dict[str, dict]:
    """Token-indexed version of build_strict_verification — same output, much faster.

    For 1800 APMs with AD groups × 3500 MAR entitlements:
    - Without index: ~6.3M is_meaningful_match calls
    - With index:    ~20k calls (only candidate entitlements per AD group)
    """
    apm_verified: dict[str, dict] = {}

    for apm, groups in apm_all_groups.items():
        if not groups:
            continue
        matched_groups: list[str] = []
        matched_ents: list[str] = []
        matched_ent_lowers: list[str] = []

        for ad_group in groups:
            candidates = get_mar_candidates(ad_group, token_index)
            if not candidates:
                continue
            best_ent: str | None = None
            best_ent_lower: str | None = None
            best_count = 0
            for ent_lower in candidates:
                info = mar_ent_counts.get(ent_lower)
                if not info:
                    continue
                if is_meaningful_match(ad_group, ent_lower):
                    if best_ent is None or info["count"] > best_count:
                        best_ent = info["original"]
                        best_ent_lower = ent_lower
                        best_count = info["count"]
            if best_ent:
                matched_groups.append(ad_group)
                if best_ent not in matched_ents:
                    matched_ents.append(best_ent)
                    matched_ent_lowers.append(best_ent_lower)

        if matched_groups:
            if mar_df is not None and matched_ent_lowers:
                mask = mar_df["entitlement_lower"].isin(matched_ent_lowers)
                unique_users = mar_df.loc[mask, "userId"].dropna().nunique()
            else:
                unique_users = sum(
                    mar_ent_counts[el]["count"]
                    for el in matched_ent_lowers
                    if el in mar_ent_counts
                )
            apm_verified[apm] = {
                "ad_groups": matched_groups,
                "mar_entitlements": matched_ents,
                "user_count": unique_users,
            }

    return apm_verified


# ── APM Universe loader (uar_apm_enriched) ─────────────────────────────────────

def load_apm_universe(
    mar_ent_counts: dict[str, dict],
    token_index: dict[str, list[str]],
    mar_df: pd.DataFrame | None,
    existing_apm_ids: set[str],
) -> list[dict]:
    """Load all 7948 APMs from uar_apm_enriched, run strict MAR matching,
    and categorize them for the APM Universe tab.

    Returns a list of dicts with keys:
        apm, app_name, business_unit, data_class, sens_level, pci, sox,
        it_owner_email, biz_owner_email, owner_email (best available),
        ad_groups (pipe-joined), matched_groups (pipe-joined),
        mar_entitlements (text), mar_user_count,
        status: 'can_close' | 'needs_finding' | 'no_groups',
        has_existing_finding (bool — already in current UAR findings)
    """
    print("Loading APM Universe from BigQuery (uar_apm_enriched)...")
    sql = f"""
    SELECT
      a.APMid,
      a.App_Name,
      a.Business_Unit,
      a.Data_Classification,
      a.Flagged_PCI,
      a.Flagged_SOX,
      a.IT_App_Owner_Email,
      a.Business_Owner_Email,
      a.IT_App_Owner,
      a.Business_Owner,
      a.Kitt_AD_Group,
      a.GCP_Owner_Groups,
      a.GCP_Prod_Owner_Groups,
      a.AZ_AD_Groups,
      a.APM_Status,
      -- Azure pending enrichment signal from Galaxy
      CASE WHEN g.Galaxy_AZ_Sub_Names IS NOT NULL AND g.Galaxy_AZ_Sub_Names != ''
           THEN TRUE ELSE FALSE END AS azure_pending
    FROM {BQ_APM_ENRICHED} a
    LEFT JOIN {BQ_GALAXY} g ON a.APMid = g.APMid
    WHERE a.APMid IS NOT NULL
    """
    df = _query(sql)
    print(f"   Loaded {len(df):,} APMs from uar_apm_enriched")

    # Normalize
    df["APMid"] = df["APMid"].fillna("").astype(str).str.strip()
    df = df[df["APMid"] != ""]

    # Build AD groups per APM (Kitt, GCP Owner, GCP Prod, Azure)
    print("Extracting AD groups from uar_apm_enriched...")
    apm_groups: dict[str, set[str]] = {}
    for _, row in df.iterrows():
        apm = str(row["APMid"])
        groups: set[str] = set()
        for col in APM_ENRICHED_AD_COLS:
            val = row.get(col)
            if val is not None and str(val).strip() not in ("", "nan", "None", "[]", "null"):
                groups.update(extract_groups_from_value(val))
        apm_groups[apm] = groups

    has_any = sum(1 for v in apm_groups.values() if v)
    print(f"   {has_any:,} APMs have AD groups, {len(apm_groups)-has_any:,} have none")

    # Run fast token-indexed strict matching
    print("Running strict AD→MAR matching for APM Universe (token-indexed)...")
    apm_verified = build_strict_verification_fast(
        apm_groups, mar_ent_counts, token_index, mar_df
    )
    print(f"   {len(apm_verified):,} APMs have verified MAR evidence")

    # Build output records
    universe: list[dict] = []
    for _, row in df.iterrows():
        apm = str(row["APMid"])
        groups = apm_groups.get(apm, set())
        verified = apm_verified.get(apm)

        # Categorize
        if not groups:
            status = "no_groups"
            matched_groups: set[str] = set()
            unmatched_groups = set()
            mar_ents: list[str] = []
            mar_users = 0
        elif verified:
            matched_groups = set(verified["ad_groups"])
            unmatched_groups = groups - matched_groups
            mar_ents = verified["mar_entitlements"]
            mar_users = verified.get("user_count", 0)
            status = "can_close" if not unmatched_groups else "needs_finding"
        else:
            matched_groups = set()
            unmatched_groups = groups
            mar_ents = []
            mar_users = 0
            status = "needs_finding"

        # Best owner email
        it_email = _safe_str(row.get("IT_App_Owner_Email", "")).strip()
        biz_email = _safe_str(row.get("Business_Owner_Email", "")).strip()
        owner_email = it_email if it_email and "@" in it_email else biz_email
        owner_name = _safe_str(row.get("IT_App_Owner", row.get("Business_Owner", "Unknown")))[:30]

        # Per-source AD group fields (pipe-joined, lowercased) for JS filter
        def _pipe_groups(col: str) -> str:
            val = row.get(col)
            if val is None or str(val).strip() in ("", "nan", "None", "[]", "null"):
                return ""
            return "|".join(sorted(g.lower() for g in extract_groups_from_value(val) if g))

        universe.append({
            "apm": apm,
            "app_name": _safe_str(row.get("App_Name", ""))[:50],
            "business_unit": _safe_str(row.get("Business_Unit", "")),
            # data_class omitted — sens_level (derived) is used by JS, raw classification is not
            "sens_level": _sens_level(_safe_str(row.get("Data_Classification", ""))),
            "pci": str(row.get("Flagged_PCI", "")).lower() == "true",
            "sox": str(row.get("Flagged_SOX", "")).lower() == "true",
            # it_owner_email / biz_owner_email omitted — JS only uses owner_email
            "owner_email": owner_email,
            "owner_name": owner_name,
            "all_ad_groups": "|".join(sorted(groups)),
            "matched_groups": "|".join(sorted(matched_groups)),
            "unmatched_groups": "|".join(sorted(unmatched_groups)),
            "mar_entitlements": ", ".join(mar_ents[:5]) + ("…" if len(mar_ents) > 5 else ""),
            "mar_user_count": mar_users,
            "status": status,
            "has_existing_finding": apm in existing_apm_ids,
            # apm_status omitted — not referenced in template
            # Per-source AD group fields for JS AD source filter
            "kitt_group": _pipe_groups("Kitt_AD_Group"),
            "gcp_group":  _pipe_groups("GCP_Owner_Groups"),
            "gcpp_group": _pipe_groups("GCP_Prod_Owner_Groups"),
            "az_group":   _pipe_groups("AZ_AD_Groups"),
            "azure_pending": bool(row.get("azure_pending", False)),
        })

    # Stats
    can_close  = sum(1 for u in universe if u["status"] == "can_close")
    needs      = sum(1 for u in universe if u["status"] == "needs_finding")
    no_groups  = sum(1 for u in universe if u["status"] == "no_groups")
    with_finding = sum(1 for u in universe if u["has_existing_finding"])
    print(f"APM Universe: {len(universe):,} total")
    print(f"   Can Close (in MAR):    {can_close:,}")
    print(f"   Needs Finding (not in MAR): {needs:,}")
    print(f"   No AD Groups:          {no_groups:,}")
    print(f"   Already have finding:  {with_finding:,}")

    return universe


# ── Main orchestrator ──────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 62)
    print("SSE UAR Dashboard — Building...")
    print("=" * 62)

    # 1. MAR data (CSV) — quarters + evidence df
    entitlement_quarters, all_quarters, mar_dataframes = load_mar_quarters()
    current_quarter = sorted(all_quarters, reverse=True)[0] if all_quarters else "FY27_Q1"

    # 2. Build MAR entitlement counts for strict matching (reuse evidence df)
    mar_ent_counts: dict[str, dict] = {}
    token_index: dict[str, list[str]] = {}
    if mar_dataframes:
        ev = mar_dataframes[0]
        ent_grp = ev.groupby("entitlement").agg({"userId": "count"}).reset_index()
        ent_grp.columns = ["entitlement", "user_count"]
        for _, r in ent_grp.iterrows():
            ent = str(r["entitlement"]).strip()
            if ent:
                mar_ent_counts[ent.lower()] = {"original": ent, "count": int(r["user_count"])}
        print(f"MAR entitlement index: {len(mar_ent_counts):,} unique entitlements")
        token_index = build_mar_token_index(mar_ent_counts)
        print(f"Token index: {len(token_index):,} tokens")

    # 3. Findings from BQ (includes all LLM fields + AD groups inline)
    df = load_findings()

    # 4. Extract AD groups from findings df (no extra BQ query needed)
    apm_all_groups = load_ad_groups_from_bq(df)

    # 5. Strict AD→MAR verification — use fast token-indexed version if index built
    mar_df_for_verification = mar_dataframes[0] if mar_dataframes else None
    if token_index:
        print("Strict AD→MAR verification (token-indexed)...")
        apm_verified = build_strict_verification_fast(
            apm_all_groups, mar_ent_counts, token_index, mar_df=mar_df_for_verification
        )
        print(f"   {len(apm_verified)} APMs have verified UAR evidence")
    else:
        apm_verified = build_strict_verification(apm_all_groups, mar_ent_counts, mar_df=mar_df_for_verification)

    # 6. Sensitivity from BQ
    apm_sensitivity = load_sensitivity()

    # 7. AuditBoard links from findings df
    ab_links, ab_types = load_ab_links(df)

    # 8. APM Universe (uar_apm_enriched) — run against MAR to find new findings
    existing_apm_ids = {str(a["apm_id"]) for _, a in df.iterrows()} if not df.empty else set()
    apm_universe = load_apm_universe(
        mar_ent_counts=mar_ent_counts,
        token_index=token_index,
        mar_df=mar_dataframes[0] if mar_dataframes else None,
        existing_apm_ids=existing_apm_ids,
    )

    # 9. Build final APM list
    apm_list = build_apm_list(
        df,
        apm_all_groups=apm_all_groups,
        apm_verified=apm_verified,
        apm_sensitivity=apm_sensitivity,
        ab_links=ab_links,
        ab_types=ab_types,
        entitlement_quarters=entitlement_quarters,
        current_quarter=current_quarter,
        mar_dataframes=mar_dataframes,
    )

    # Stats
    can_close  = sum(1 for a in apm_list if a["pct"] == 100)
    partial    = sum(1 for a in apm_list if 0 < a["pct"] < 100)
    needs_work = sum(1 for a in apm_list if a["pct"] == 0)
    past_due   = sum(1 for a in apm_list if a["due_status"] == "Past due")

    print()
    print(f"Total APMs:          {len(apm_list)}")
    print(f"  Can Close (100%):  {can_close}")
    print(f"  Partial:           {partial}")
    print(f"  Needs Work (0%):   {needs_work}")
    print(f"  Past Due:          {past_due}")
    print(f"  Quarter:           {current_quarter}")

    # 10. Update daily history snapshot
    today_str = datetime.date.today().isoformat()
    today_snapshot = {
        "date":       today_str,
        "total":      len(apm_list),
        "can_close":  can_close,
        "partial":    partial,
        "needs_work": needs_work,
        "past_due":   past_due,
    }

    try:
        history: list[dict] = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        if not isinstance(history, list):
            history = []
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        history = []

    # Overwrite same-day entry; append new entry otherwise
    existing_idx = next((i for i, e in enumerate(history) if e.get("date") == today_str), None)
    if existing_idx is not None:
        history[existing_idx] = today_snapshot
    else:
        history.append(today_snapshot)

    HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    print(f"History snapshot saved ({len(history)} entries) → {HISTORY_FILE.name}")

    # 11. Render HTML
    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    html = template.replace("__APM_DATA__", json.dumps(apm_list, default=str))
    html = html.replace("__APM_UNIVERSE_DATA__", json.dumps(apm_universe, default=str))
    html = html.replace("__CURRENT_QUARTER__", current_quarter)
    html = html.replace("__HISTORY_DATA__", json.dumps(history, default=str))

    OUTPUT.write_text(html, encoding="utf-8")
    size_mb = OUTPUT.stat().st_size / 1_048_576
    print(f"\nDashboard written: {OUTPUT}")
    print(f"  Size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
