# UAR Risk Scoring — Methodology, Rationale, and Expansion Framework

**Prepared by:** SSE Security Team  
**Audience:** Developers, Security Leadership, GRC  
**Date:** May 2026  
**Related file:** `coc_risk_scorer.py`

---

## Table of Contents

1. [Why Risk Scoring Matters](#1-why-risk-scoring-matters)
2. [The Problem with Count-Based Compliance](#2-the-problem-with-count-based-compliance)
3. [How the Score Is Calculated](#3-how-the-score-is-calculated)
4. [Factor-by-Factor Breakdown](#4-factor-by-factor-breakdown)
5. [Risk Tiers and What They Mean](#5-risk-tiers-and-what-they-mean)
6. [Score Examples — Real Scenarios](#6-score-examples--real-scenarios)
7. [How to Tune the Weights](#7-how-to-tune-the-weights)
8. [Expanding to Other Finding Types](#8-expanding-to-other-finding-types)
9. [Limitations and Known Gaps](#9-limitations-and-known-gaps)
10. [Glossary](#10-glossary)

---

## 1. Why Risk Scoring Matters

The SSE UAR dashboard currently shows 332 active findings. Every finding is displayed the same way — a row in a table. A PCI-scoped application that is 90 days past due with zero access review evidence sits next to a non-sensitive internal tool that is 2 days past due with 80% coverage. They look identical.

**Count-based compliance asks: "How many findings are open?"**  
**Risk-based compliance asks: "Which open findings actually threaten the business?"**

These are different questions with different answers and different remediation actions.

Risk scoring solves three concrete problems:

### Problem 1: Remediation Priority
With 332 findings and limited team bandwidth, where do you start? Without scores, the instinct is to close easy ones first (high coverage, simple APMs). But the right answer is to close the most dangerous ones first — those are not always the easiest.

A risk score makes the prioritization explicit, defensible, and consistent. Every team member — and every auditor — can see exactly why APM X was treated as higher priority than APM Y.

### Problem 2: Leadership Communication
Telling leadership "we have 222 past due findings" is alarming but not actionable. Telling leadership "we have 47 Critical-tier findings, 12 of which are PCI-scoped and more than 30 days overdue, and here are the top 10 by score" gives them:
- A sense of magnitude
- A sense of which business units are exposed
- A basis for resource allocation decisions
- A metric that will move over time as remediation happens

### Problem 3: Audit Evidence
Regulators and internal audit increasingly expect evidence that risk-based prioritization drove remediation decisions — not just that findings were eventually closed. A timestamped risk score, stored in BigQuery (Phase 2), shows that on any given date, the team knew which findings were highest risk and acted accordingly.

---

## 2. The Problem with Count-Based Compliance

Consider two hypothetical teams:

**Team A** closes 50 findings in a quarter — all low-sensitivity, non-PCI, with partial MAR coverage already in place. Their "Can Close" count jumps by 50.

**Team B** closes 8 findings in a quarter — all Critical-tier, PCI-scoped, past due, zero prior MAR coverage. Their count jumps by 8.

Under a count-based model, Team A looks 6x more productive. Under a risk-based model, Team B eliminated significantly more compliance exposure.

This is why count alone is not a compliance posture metric. It is a workload metric. Risk score is the posture metric.

---

## 3. How the Score Is Calculated

The risk score is a **weighted additive model** — each risk factor contributes a fixed number of points, the contributions are summed, and the result is clipped to a 0–100 scale.

### Formula

```
risk_score = min(100,
    past_due_flag      × 35  +
    days_overdue_pts   × 1   +   (capped at 20)
    no_mar_coverage    × 20  +
    partial_coverage   × 10  +
    pci_scope          × 15  +
    sox_scope          × 10  +
    high_sensitivity   × 5   +
    repeat_finding     × 10
)
```

Where:
- `past_due_flag` = 1 if `due_status == "Past due"`, else 0
- `days_overdue_pts` = min(days since due date / 3, 20)
- `no_mar_coverage` = 1 if `pct == 0`, else 0
- `partial_coverage` = 1 if `0 < pct < 100`, else 0
- `pci_scope` = 1 if APM is in PCI scope, else 0
- `sox_scope` = 1 if APM is in SOX scope, else 0
- `high_sensitivity` = 1 if APM sensitivity == "High", else 0
- `repeat_finding` = 1 if APM was previously in Can Close but is now active again

### Why Additive?

An additive model was chosen deliberately over multiplicative or machine-learning approaches for three reasons:

1. **Transparency:** Every point can be traced to a specific factor. "This APM scored 80 because it is past due (+35), has zero MAR coverage (+20), is PCI-scoped (+15), and has been open for 30 days (+10)" is a complete explanation. A model that says "the algorithm assigned 80" is not.

2. **Auditability:** When an auditor asks "why was this finding prioritized over that one?", the score formula is the answer. It is written down, version-controlled, and applied consistently to every finding.

3. **Tunability:** Changing the weights requires editing four constants and re-running the script. No model retraining, no data science expertise required.

The tradeoff is that additive models do not capture interaction effects (e.g., "PCI + past due is worse than PCI alone + past due alone"). In practice, the additive model handles this acceptably because the worst-case combinations still score highest — they accumulate points from all contributing factors.

---

## 4. Factor-by-Factor Breakdown

### Factor 1: Past Due Status (+35 points)

**Source:** `due_status` field from `vw_unified_findings`  
**Values:** `"Past due"` → +35, anything else → +0

**Why 35?**  
Past due is the single largest compliance signal. A finding that has breached its contractual or regulatory deadline has already failed — the question is now about severity of failure, not risk of failure. It is weighted at 35 (the heaviest single factor) to ensure that no combination of non-due-date factors can outrank a past-due finding unless the past-due finding has significantly better coverage.

A finding with PCI + SOX + high sensitivity but NOT past due scores 30 max. A finding that IS past due with no other risk factors scores 35. This ordering reflects that deadline breach is a compliance failure regardless of other attributes.

**Leadership interpretation:** Every Critical-tier finding is past due. If past-due findings drop, Critical count drops proportionally.

---

### Factor 2: Days Overdue (+0 to +20 points)

**Source:** Difference between today and `due_date` from `vw_unified_findings`  
**Formula:** `min(days_overdue / 3, 20)` → 1 point per 3 days, capped at 20

**Why 1 point per 3 days, capped at 20?**  
The goal is to distinguish "1 day late" from "60 days late" — these are not the same compliance situation even though both trigger the past-due flag. However, we do not want days-overdue to dominate over structural factors (PCI scope, repeat finding). The cap at 20 ensures that even a finding 200 days overdue cannot outweigh a PCI-scoped finding on days alone.

The divisor of 3 means:
- 3 days overdue → +1 point (barely past due)
- 15 days overdue → +5 points (approaching serious)
- 30 days overdue → +10 points (a full month overdue)
- 60+ days overdue → +20 points (capped, maximum urgency)

**Tuning note:** If your team's SLA is 90-day cycles, you may want to change the divisor to 4 or 5 so that early overdue findings score lower. If 30 days is a critical threshold, you might add a step function (+5 extra at 30 days).

---

### Factor 3: Zero MAR Coverage (+20 points)

**Source:** `pct` field (0 = no AD groups verified in SailPoint/MAR)  
**Values:** `pct == 0` → +20, `pct > 0` → +0

**Why 20?**  
Zero coverage means the finding has no evidence that any access has been reviewed. This is the worst possible coverage state. It is weighted at 20 (tied with the days-overdue cap) because "no evidence at all" represents a complete compliance gap, not just an incomplete one.

This factor and the partial-coverage factor are mutually exclusive — only one of them can apply to a given finding at any time. Together they define a three-tier evidence gradient:
- `pct == 100`: No coverage penalty (ready to close)
- `0 < pct < 100`: Partial penalty (+10)
- `pct == 0`: Full penalty (+20)

---

### Factor 4: Partial MAR Coverage (+10 points)

**Source:** `pct` field  
**Values:** `0 < pct < 100` → +10, else +0

**Why 10 (half of zero-coverage)?**  
Partial coverage is better than no coverage — the team has done some work, some groups are enrolled. But incomplete is still non-compliant. The half-weight relative to zero-coverage reflects that partial = progress, just not complete.

Practical consequence: a finding that goes from `pct == 0` to `pct == 50%` drops 10 risk points. This makes the score responsive to remediation progress even before the finding is fully closeable.

---

### Factor 5: PCI Scope (+15 points)

**Source:** `is_pci` field from `snow_apm_data.sse_apm_data_prod`  
**Values:** `is_pci == True` → +15

**Why 15?**  
PCI DSS (Payment Card Industry Data Security Standard) is an external regulatory requirement with direct financial penalties for non-compliance. UAR findings on PCI-scoped applications represent potential violations of PCI Requirement 7 (restrict access to system components) and Requirement 8 (identify users and authenticate access). External QSA audits will specifically examine UAR evidence for PCI systems.

PCI is weighted higher than SOX in the current model because:
- PCI violations can trigger direct fines from card brands
- PCI audit evidence requirements are stricter and more prescriptive
- PCI scope is narrower (fewer APMs), so the weight has less total impact on the score distribution

---

### Factor 6: SOX Scope (+10 points)

**Source:** `is_sox` field from `snow_apm_data.sse_apm_data_prod`  
**Values:** `is_sox == True` → +10

**Why 10?**  
SOX (Sarbanes-Oxley) requires controls over financial reporting systems. User access reviews are a key SOX IT General Control (ITGC). However, SOX findings generally carry less immediate external penalty than PCI — the consequence is audit findings and management letter comments rather than direct regulatory fines. SOX is weighted 5 points below PCI to reflect this difference in external exposure.

**Note:** An APM can be both PCI and SOX scoped, in which case both weights apply (+25 total from regulatory scope alone).

---

### Factor 7: High Sensitivity (+5 points)

**Source:** `sensitivity` field from `snow_apm_data.sse_apm_data_prod`  
**Values:** `sensitivity == "High"` → +5

**Why only 5?**  
Sensitivity is a softer signal than formal regulatory scope. Many high-sensitivity APMs are already captured by PCI or SOX flags. The +5 is a small bump to catch high-sensitivity systems that fall outside formal regulatory scope — internal data platforms, executive systems, security tooling — without double-counting the risk of formally regulated systems.

---

### Factor 8: Repeat Finding (+10 points)

**Source:** Comparison against historical `dashboard_history.json` snapshots  
**Logic:** If an APM appeared in a prior snapshot's Can Close list but is now active again, it is a repeat

**Why 10?**  
A repeat finding indicates process failure — the APM was previously closed (or nearly closed) but the access review lapsed and the finding was reopened. This suggests the APM owner either:
- Did not genuinely remediate (closed without full evidence)
- Did not sustain the UAR process after initial compliance
- Has a systemic access management gap

Either way, repeat offenders require a different response than first-time findings — typically involving manager escalation and process review, not just re-enrollment. The +10 weight is meaningful but not dominant, reflecting that repeats are serious without overriding the structural risk of new PCI/past-due findings.

---

## 5. Risk Tiers and What They Mean

| Tier | Score Range | Color | Meaning |
|------|------------|-------|---------|
| **Critical** | 70–100 | 🔴 Red | Past due AND significant coverage gap AND/OR regulatory scope. Immediate action required. Escalate to manager. |
| **High** | 40–69 | 🟠 Orange | Past due OR no coverage OR PCI/SOX scope. Action required within this week. |
| **Medium** | 20–39 | 🟡 Amber | Partial coverage gap or regulatory scope but not yet past due. Monitor and remediate this sprint. |
| **Low** | 0–19 | 🟢 Green | Minimal or no risk factors. May be approaching due date or have minor gaps. Track in normal workflow. |

### Tier Boundaries — Why These Numbers?

The tier boundaries were set to produce a useful distribution given the current dataset (332 findings, 222 past due):

- **Critical ≥ 70:** A finding reaches 70 by being past due (+35) + zero coverage (+20) + PCI (+15), or past due (+35) + zero coverage (+20) + 45+ days overdue (+15). This combination represents genuine regulatory exposure with no evidence and breach of deadline.

- **High ≥ 40:** Reached by being past due (+35) with any one additional factor, or by having PCI+SOX+zero coverage without being past due (+45). Either scenario requires action within a week.

- **Medium ≥ 20:** Reached by partial coverage + regulatory scope, or zero coverage on a non-regulated APM. These need attention but are not emergencies.

- **Low < 20:** Active findings with good partial coverage and no regulatory scope. Normal workflow management.

---

## 6. Score Examples — Real Scenarios

### Example A — Maximum Risk (Score: 100)
```
APM:         APM0001234
Status:      Past due (91 days overdue)
MAR:         pct == 0 (no groups verified)
Scope:       PCI + SOX + High sensitivity
History:     Previously closed, now reopened

Score:   35 (past due)
       + 20 (91 days / 3 = 30.3 → capped at 20)
       + 20 (pct == 0)
       + 15 (PCI)
       + 10 (SOX)
       +  5 (High sensitivity)
       + 10 (Repeat finding)
       ─────
       115 → clipped to 100

Tier: Critical 🔴
Action: Immediate escalation to APM owner + manager.
        Block any closure attempt until pct == 100.
```

### Example B — Past Due, Some Progress (Score: 55)
```
APM:         APM0005678
Status:      Past due (15 days overdue)
MAR:         pct == 60 (partial coverage)
Scope:       No PCI, no SOX, medium sensitivity
History:     First occurrence

Score:   35 (past due)
       +  5 (15 days / 3 = 5)
       + 10 (partial coverage)
       +  0 (no regulatory scope)
       +  0 (not a repeat)
       ─────
        50

Tier: High 🟠
Action: Owner reminder email. Enroll remaining 40% of AD groups.
        This finding can move to Can Close once pct reaches 100.
```

### Example C — Not Yet Due, Regulatory Scope (Score: 30)
```
APM:         APM0009999
Status:      Active (not past due)
MAR:         pct == 0 (no groups verified yet)
Scope:       SOX-scoped
History:     First occurrence

Score:    0 (not past due)
       +  0 (not overdue)
       + 20 (pct == 0)
       +  0 (no PCI)
       + 10 (SOX)
       +  0 (not high sensitivity)
       ─────
        30

Tier: Medium 🟡
Action: Enroll AD groups now — if due date passes without coverage,
        score jumps to 65 (High → Critical threshold).
```

### Example D — Healthy, Ready to Close (Score: 0)
```
APM:         APM0002222
Status:      Active (not past due)
MAR:         pct == 100 (all groups verified)
Scope:       No regulatory flags
History:     First occurrence

Score:    0 (all factors zero)

Tier: Low 🟢
Action: Download evidence CSV from dashboard.
        Submit in AuditBoard to close.
```

### Example E — Score Jump Demonstration
This illustrates how a finding's score changes as its situation changes:

| Date | Situation | Score | Tier |
|------|-----------|-------|------|
| Day 0 | Opening, not due, pct=0, SOX | 30 | Medium |
| Day 30 | Still not due, pct=40, SOX | 10 | Low |
| Day 45 | Due date passes, pct=40, SOX | 55 | High |
| Day 60 | 15 days past due, pct=40, SOX | 60 | High |
| Day 90 | 45 days past due, pct=0 (regression), SOX | 80 | Critical |

This time series shows two important behaviors:
1. Improving coverage (pct 0→40) dropped the score even before the due date — scores are **responsive to remediation progress**
2. A regression (pct 40→0, if groups are unenrolled) causes a score spike — the model **detects backsliding**

---

## 7. How to Tune the Weights

All weights are defined as module-level constants in `coc_risk_scorer.py`:

```python
WEIGHT_PAST_DUE     = 35
WEIGHT_DAYS_MAX     = 20
WEIGHT_DAYS_DIVISOR = 3
WEIGHT_NO_GROUPS    = 20
WEIGHT_PARTIAL      = 10
WEIGHT_PCI          = 15
WEIGHT_SOX          = 10
WEIGHT_HIGH_SENS    = 5
WEIGHT_REPEAT       = 10

TIER_CRITICAL_MIN = 70
TIER_HIGH_MIN     = 40
TIER_MEDIUM_MIN   = 20
```

### When to Retune

Retune the weights when:
- **Audit findings:** External auditors disagree with the risk ordering — "APM X should have been prioritized over APM Y"
- **Business changes:** A new regulatory framework is adopted that increases or decreases the weight of a scope flag
- **Distribution feedback:** The tier distribution is too top-heavy or too bottom-heavy for actionable prioritization
- **New data available:** Additional risk signals become available (e.g., number of privileged users, data classification)

### How to Retune Safely

1. Export the current scored DataFrame to CSV before changing weights
2. Change the constant(s)
3. Re-run `score_findings()` on the same DataFrame
4. Compare before/after score distributions
5. Check that the rank order of your known-worst APMs is still correct
6. If the BQ writeback (Phase 2) is live, the new scores will be recorded with the next run — historical scores under old weights are preserved

### Common Tuning Scenarios

**"SOX findings are being deprioritized relative to PCI but we have equal exposure"**  
→ Set `WEIGHT_SOX = 15`. Rerun and check that dual-scope (PCI+SOX) APMs don't cap out too early.

**"Our findings are mostly Critical which makes the tier useless for prioritization"**  
→ Lower `TIER_CRITICAL_MIN` to 60 or raise `WEIGHT_PAST_DUE` threshold. Or reduce `WEIGHT_PAST_DUE` to 25 to spread scores lower.

**"The days-overdue factor doesn't matter because all our SLAs are 90 days"**  
→ Set `WEIGHT_DAYS_DIVISOR = 9` (1 point per 9 days) and `WEIGHT_DAYS_MAX = 10`. This makes days-overdue a minor factor rather than a significant one.

---

## 8. Expanding to Other Finding Types

The risk scoring model was built for UAR findings but the framework applies to any AuditBoard finding type. The pattern is:

```
risk_score = Σ (factor_value × factor_weight), clipped to [0, 100]
```

The factors change by finding type. The framework does not.

### 8.1 Vulnerability Management Findings

For patch/vulnerability findings, the relevant risk factors are different:

| Factor | Points | Data Source |
|--------|--------|-------------|
| CVSS score ≥ 9.0 (Critical) | +40 | Vulnerability scanner (Tenable, Qualys) |
| CVSS score 7.0–8.9 (High) | +25 | Same |
| Past due | +30 | vw_unified_findings |
| Internet-facing asset | +20 | SNOW APM / CMDB |
| PCI scope | +15 | snow_apm_data |
| SOX scope | +10 | snow_apm_data |
| Active exploit known (CISA KEV) | +20 | CISA KEV list (public API) |
| No patch available | +5 | Vendor advisory |

```python
# coc_risk_scorer_vuln.py (future module)
WEIGHT_CVSS_CRITICAL  = 40
WEIGHT_CVSS_HIGH      = 25
WEIGHT_PAST_DUE       = 30
WEIGHT_INTERNET_FACING = 20
WEIGHT_ACTIVE_EXPLOIT  = 20
WEIGHT_PCI            = 15
WEIGHT_SOX            = 10
WEIGHT_NO_PATCH       = 5
```

### 8.2 Access Certification Findings (Non-UAR)

For privileged access or service account certification findings:

| Factor | Points | Rationale |
|--------|--------|-----------|
| Past due | +35 | Same as UAR |
| Privileged account (admin/root) | +25 | Privileged access = higher blast radius |
| No certification on record | +20 | No evidence |
| Service account (non-human) | +15 | Harder to audit, often forgotten |
| PCI/SOX scope | +15/+10 | Same as UAR |
| Orphaned account | +20 | Account with no known owner = uncontrolled access |

### 8.3 Policy Exception Findings

For security policy exceptions (firewall rules, encryption waivers):

| Factor | Points | Rationale |
|--------|--------|-----------|
| Past due | +35 | Standard |
| Exception age > 1 year | +20 | Stale exceptions are often forgotten permanently |
| No compensating control documented | +20 | No mitigation evidence |
| Production environment | +15 | Higher impact than dev/test |
| PCI scope | +15 | Regulatory |
| Broad scope (CIDR /16 or larger) | +15 | Wide blast radius |

### 8.4 Data Classification Findings

For data handling and classification compliance:

| Factor | Points | Rationale |
|--------|--------|-----------|
| Past due | +35 | Standard |
| Unclassified PII data | +30 | Highest data risk |
| Unclassified financial data | +20 | SOX-relevant |
| No data owner assigned | +20 | Unowned data = unmanaged risk |
| Public-facing storage | +20 | Exposure risk |
| Retention policy missing | +10 | Legal/regulatory gap |

### 8.5 The Universal Expansion Pattern

Any finding type can be scored by following this pattern:

**Step 1 — Identify the risk factors for this finding type**
Ask: "What makes this finding worse than average? What signals indicate the business is actually at risk?"

**Step 2 — Rank the factors by business impact**
The highest-impact factor should get the highest weight. Past due is almost always in the top 2 for any finding type.

**Step 3 — Assign weights that sum to ~100 in the worst case**
Design the weights so that a finding with every bad factor scores near 100. This keeps the scale consistent across finding types.

**Step 4 — Define tier boundaries for the new finding type**
You can use the same 70/40/20 thresholds or adjust them based on how the scores distribute in your dataset.

**Step 5 — Create a new scorer module**
```python
# coc_risk_scorer_{finding_type}.py
# Follow the same pattern as coc_risk_scorer.py:
# - Constants at the top for all weights and thresholds
# - score_findings(df) as the main function
# - summarize_risk(df) for leadership reporting
# - top_risks(df, n) for prioritized lists
```

**Step 6 — Store in the same BQ table**
Add a `finding_type` column to `uar_compliance_snapshots` and the same writeback code works for all types. Leadership can query across finding types: "Show me all Critical-tier findings regardless of type."

### 8.6 Cross-Finding-Type Risk Aggregation

Once multiple finding types are scored, you can compute an **APM-level composite risk score**:

```sql
-- APM composite risk: worst score across all finding types
SELECT
    ssp_apm_id,
    MAX(risk_score) AS max_risk_score,
    STRING_AGG(DISTINCT finding_type) AS finding_types,
    COUNT(*) AS total_findings,
    COUNTIF(risk_tier = 'Critical') AS critical_count
FROM `infosec-compliance-auditboard.sse_findings_enriched_data.uar_compliance_snapshots`
WHERE snapshot_date = CURRENT_DATE()
GROUP BY ssp_apm_id
ORDER BY max_risk_score DESC
LIMIT 50;
```

This gives leadership a single view: "These 20 APMs have the highest combined risk exposure across UAR, vulnerability, and policy exception findings." That is the foundation of a true risk-based compliance program.

---

## 9. Limitations and Known Gaps

### Gap 1: Factors Are Treated as Independent
The additive model assumes that past-due and PCI-scope add their risks independently. In reality, a past-due PCI finding may carry disproportionately more risk than the sum of its parts (regulatory deadlines compound). Future iterations could introduce multiplicative terms for specific high-risk combinations.

### Gap 2: No Velocity Signal
The model scores a finding's current state but does not capture trajectory. An APM that went from pct=80 to pct=20 (backsliding) scores the same as one that has always been at pct=20. Adding a `pct_delta_7d` factor would penalize regressions and reward progress.

**Proposed addition:**
```python
# pct regression in last 7 days
if pct_today < pct_7_days_ago:
    score += 10   # penalize backsliding
elif pct_today > pct_7_days_ago:
    score -= 5    # small reward for progress (floored at 0)
```

### Gap 3: No User Count Signal
An AD group with 5,000 members is riskier than one with 5 members — but both score identically. SailPoint API (Phase 5) would provide member counts, enabling a `large_group_factor` weight.

### Gap 4: Repeat Finding Detection Is Approximate
The current repeat-finding logic checks if an APM appeared in any prior Can Close list, which is a proxy for "was previously compliant." It does not distinguish between a finding that was genuinely closed and reopened versus one that fluctuated in and out of pct=100 due to data refreshes.

Phase 2 (BQ writeback) + Phase 5 (SailPoint) together enable exact repeat detection by tracking finding lifecycle through AuditBoard status changes.

### Gap 5: Weights Are Not Statistically Derived
The weights are based on security best practice judgment, not on historical correlation with actual adverse outcomes (breaches, audit findings, regulatory actions). If historical outcome data becomes available — e.g., "APMs with score > 70 were 3x more likely to receive an audit comment" — the weights can be recalibrated against that data.

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **Risk Score** | A numeric value 0–100 representing the compliance exposure of a single finding at a point in time |
| **Risk Tier** | A categorical label (Critical/High/Medium/Low) derived from the risk score |
| **UAR** | User Access Review — the process of periodically certifying that user access to systems is appropriate and necessary |
| **MAR** | Monthly Access Review — Walmart's SailPoint-based entitlement certification process |
| **MAR Coverage (pct)** | Percentage of a finding's AD groups that have been verified in SailPoint/MAR |
| **AD Group** | Active Directory security group used to manage access to systems and resources |
| **PCI DSS** | Payment Card Industry Data Security Standard — external regulatory framework for cardholder data protection |
| **SOX** | Sarbanes-Oxley Act — US financial reporting law requiring controls over IT systems used in financial reporting |
| **APM** | Application Portfolio Management — Walmart's application catalog; each APM ID identifies a discrete application |
| **Past Due** | A finding whose remediation deadline has passed without closure |
| **Repeat Finding** | An APM that was previously compliant (Can Close) but has been re-identified as non-compliant in a later period |
| **Additive Model** | A scoring approach where each risk factor contributes a fixed number of points to the total score |
| **Weighted Factor** | A risk signal multiplied by a constant to reflect its relative importance to the total score |
| **CVSS** | Common Vulnerability Scoring System — standardized vulnerability severity scoring (used in vuln management expansion) |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog — public list of CVEs with confirmed active exploitation |

---

*This document describes the risk scoring methodology implemented in `coc_risk_scorer.py`. Weights and thresholds are version-controlled alongside the code and should be reviewed quarterly or after any significant change in regulatory scope, business priorities, or finding volume.*
