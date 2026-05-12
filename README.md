# 🔐 SSE UAR Evidence Collection Dashboard

**Team:** SSE Global Compliance | **Quarter:** FY27 Q1

## 🚀 Open the Dashboard

**→ [Open Dashboard (Walmart login required)](https://gecgithub01.walmart.com/lparise/sse-uar-dashboard/raw/master/index.html)**

> Works in any browser. No installation needed — just click and open.

---

## What It Does

Real-time view of every application (APM) under User Access Review (UAR).  
Answers one question per app: *"Do we have MAR evidence to close this UAR finding?"*

| Tab | Who it's for | Action |
|-----|-------------|--------|
| ✅ **Can Close** | APMs with AD groups verified in MAR | Download CSV → upload to AuditBoard → check Done |
| ❌ **Issue / Needs Work** | APMs with no MAR match | Follow up with owner or issue UAR finding |

---

## Data Sources

| Source | Type | What It Provides |
|--------|------|-----------------|
| `sse_findings_enriched_data.uar_findings_enriched` | BigQuery | UAR findings + AD groups + LLM fields |
| `sse_data_lake.vw_unified_findings` | BigQuery | Title, due date, owner, email |
| `snow_apm_data.sse_apm_data_prod` | BigQuery | APM sensitivity, PCI/SOX flags |
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
.\deploy.ps1 -version "v1.1"
```

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
| **Enterprise repo (primary)** | https://gecgithub01.walmart.com/lparise/sse-uar-dashboard |
| **GitHub mirror + Pages** | https://leonardoparisella-sudo.github.io/sse-uar-dashboard/ |

*SSE Global Compliance · `build_dashboard.py` · BigQuery `infosec-compliance-auditboard`*
