# 🔐 SSE — APM-to-AD Group Intelligence Pipeline

**Team:** SSE Global Compliance | **Quarter:** FY27 Q1

## 🚀 Open the Dashboard

**→ [Open Dashboard (GHE Raw)](https://gecgithub01.walmart.com/lparise/sse-uar-dashboard/raw/master/sse_uar_dashboard.html)**

> Download the file and open in any browser. No installation needed — fully self-contained HTML.

---

## What It Does

Real-time view of every application (APM) under User Access Review (UAR).  
Answers one question per app: *"Do we have MAR evidence to close this UAR finding?"*

| Tab | Who it's for | Action |
|-----|-------------|--------|
| ✅ **Can Close** | APMs with AD groups verified in MAR | Download CSV → upload to AuditBoard → check Done |
| ❌ **Issue / Needs Work** | APMs with no MAR match | Follow up with owner or issue UAR finding |
| 🌐 **APM Universe** | All 7,952 APMs — find which need new findings | Generate Finding sub-tab: select APMs → Bulk Email owners |
| 📈 **Trends** | Daily count snapshots per rebuild | Track Total, Can Close, Partial, Needs Work, Past Due over time |

### AD Group Source Filter (APM Universe tab)

Filter the "Generate Finding" sub-tab by AD group source:

| Button | Source |
|--------|--------|
| **All** | All APMs needing a finding |
| **Kitt** | Kitt AD group only |
| **GCP Groups** | GCP Owner Groups **or** GCP Prod Owner Groups (merged — shows union count) |

> Previously split into "GCP Owner" and "GCP Prod" buttons whose counts overlapped. Now unified as **GCP Groups** showing the correct unique count.

---

## Data Sources

| Source | Type | What It Provides |
|--------|------|-----------------|
| `sse_findings_enriched_data.uar_findings_enriched` | BigQuery | UAR findings + AD groups + LLM fields |
| `sse_data_lake.vw_unified_findings` | BigQuery | Title, due date, owner, email |
| `snow_apm_data.sse_apm_data_prod` | BigQuery | APM sensitivity, PCI/SOX flags |
| `sse_findings_enriched_data.uar_apm_enriched` | BigQuery | Full 7,952 APM universe |
| MAR CSV files | Local SharePoint sync | Quarterly entitlement evidence (~752 MB) |

**BigQuery Project:** `infosec-compliance-auditboard`  
**Auth:** Google Application Default Credentials (ADC)

---

## Refresh the Dashboard

```powershell
cd "C:\Users\lparise\OneDrive - Walmart Inc\Desktop\SSE Tean\SSE 2025 Projects\Goals\UAR W SSE"
.\deploy.ps1
```

Builds fresh from BigQuery (~2-3 min), commits, and pushes to both repos automatically.

```powershell
# Tag a versioned release:
.\deploy.ps1 -version "v1.2"
```

---

## Performance

| Version | File Size | Notes |
|---------|-----------|-------|
| v1.0 | ~4 MB | Initial release |
| v1.1 | 8.6 MB | Added APM Universe (7,952 records) + LLM fields |
| v1.2 | **6.6 MB** | Optimized — see below |

### v1.2 Optimizations (May 2026)

- **−2 MB** — CSV evidence blobs (`csv_b64`) only generated for Can Close APMs (81 of 383); non-closeable records no longer carry unused data
- **−0.3 MB** — Dropped 4 unused fields from 7,952-record universe payload (`it_owner_email`, `biz_owner_email`, `data_class`, `apm_status`)
- **Faster UI** — Universe table renders deferred via `requestAnimationFrame`, eliminating jank when switching tabs or AD group filters

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `master` | 🌐 Live — what the dashboard link serves |
| `baseline` | 🔒 Frozen FY27 Q1 snapshot (locked, never modified) |
| `dev` | 🛠 Active development — merge to master to deploy |

---

## Links

| | URL |
|--|--|
| **Dashboard (download & open)** | https://gecgithub01.walmart.com/lparise/sse-uar-dashboard/raw/master/sse_uar_dashboard.html |
| **Enterprise repo (primary)** | https://gecgithub01.walmart.com/lparise/sse-uar-dashboard |

*SSE Global Compliance · `build_dashboard.py` · BigQuery `infosec-compliance-auditboard`*
