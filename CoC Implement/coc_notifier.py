"""
coc_notifier.py — Phase 3: Owner Notification Engine
Sends automated email/Teams alerts to APM owners based on risk-scored findings.

Prerequisites:
    - SMTP relay hostname (Walmart internal mail relay)
    - OR MS Teams incoming webhook URL for the #sse-uar-alerts channel
    - APM owner email map (from SNOW APM table or manual CSV)

Usage:
    from coc_notifier import NotificationEngine, load_owner_map_from_bq
    owner_map   = load_owner_map_from_bq()
    manager_map = load_manager_map_from_bq()
    engine = NotificationEngine(dry_run=True)  # dry_run=True first!
    results = engine.notify_all(records_df, owner_map, manager_map)
    print(results)

IMPORTANT: Always run with dry_run=True for at least 2 weeks before enabling
live notifications. Review the output to confirm correct owner mapping.
"""
from __future__ import annotations
import smtplib
import urllib.request
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd

DASHBOARD_URL = "https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html"
FROM_ADDRESS  = "sse-compliance-noreply@walmart.com"
SMTP_HOST     = "mailrelay.walmart.com"
SMTP_PORT     = 25


# ── BQ Owner Map Helpers ───────────────────────────────────────────────────────

def load_owner_map_from_bq() -> dict[str, str]:
    """
    Load APM ID → owner email mapping from SNOW APM table in BigQuery.

    Returns:
        dict mapping apm_id (str) → owner_email (str)
    """
    from google.cloud import bigquery
    client = bigquery.Client(project="infosec-compliance-auditboard")
    sql = """
        SELECT
            CONCAT('APM', LPAD(CAST(apm_id AS STRING), 7, '0')) AS apm_id_norm,
            owner_email
        FROM `infosec-compliance-auditboard.snow_apm_data.sse_apm_data_prod`
        WHERE owner_email IS NOT NULL
          AND owner_email != ''
    """
    df = client.query(sql).to_dataframe()
    return dict(zip(df["apm_id_norm"], df["owner_email"]))


def load_manager_map_from_bq() -> dict[str, str]:
    """
    Load owner email → manager email mapping from SNOW APM table.

    Returns:
        dict mapping owner_email (str) → manager_email (str)
    """
    from google.cloud import bigquery
    client = bigquery.Client(project="infosec-compliance-auditboard")
    sql = """
        SELECT DISTINCT
            owner_email,
            manager_email
        FROM `infosec-compliance-auditboard.snow_apm_data.sse_apm_data_prod`
        WHERE owner_email IS NOT NULL
          AND manager_email IS NOT NULL
    """
    df = client.query(sql).to_dataframe()
    return dict(zip(df["owner_email"], df["manager_email"]))


# ── Notification Engine ────────────────────────────────────────────────────────

class NotificationEngine:
    """
    Routes UAR compliance notifications to APM owners via email and/or Teams.

    Args:
        smtp_host     : Walmart internal SMTP relay (default: mailrelay.walmart.com)
        port          : SMTP port (default: 25, no auth on Walmart relay)
        from_addr     : Sender address shown to recipients
        teams_webhook : Optional MS Teams incoming webhook URL
        dry_run       : If True, prints what would be sent without actually sending.
                        ALWAYS start with dry_run=True.
    """

    def __init__(
        self,
        smtp_host: str     = SMTP_HOST,
        port: int          = SMTP_PORT,
        from_addr: str     = FROM_ADDRESS,
        teams_webhook: str | None = None,
        dry_run: bool      = True,
    ):
        self.smtp_host     = smtp_host
        self.port          = port
        self.from_addr     = from_addr
        self.teams_webhook = teams_webhook
        self.dry_run       = dry_run

        if dry_run:
            print("[notifier] ⚠ DRY RUN MODE — no emails or Teams messages will be sent")

    # ── Public API ─────────────────────────────────────────────────────────────

    def notify_all(
        self,
        df: pd.DataFrame,
        owner_map: dict[str, str],
        manager_map: dict[str, str] | None = None,
    ) -> dict[str, int]:
        """
        Process all findings and send appropriate notifications.

        Notification rules:
          - Past due AND pct == 0  → Owner: urgent email + Teams alert
          - Past due AND pct > 0   → Owner: reminder email
          - risk_tier == Critical   → Manager: escalation email
          - pct == 100             → Owner: good news + close instructions

        Args:
            df          : risk-scored records DataFrame
            owner_map   : {apm_id → owner_email}
            manager_map : {owner_email → manager_email} (optional, for escalations)

        Returns:
            Summary dict: {"sent": N, "skipped": N, "errors": N}
        """
        sent = skipped = errors = 0
        manager_map = manager_map or {}

        for _, row in df.iterrows():
            apm = str(row.get("ssp_apm_id", ""))
            owner_email = owner_map.get(apm)
            if not owner_email:
                skipped += 1
                continue

            try:
                n = self._route(row, owner_email, manager_map)
                sent += n
            except Exception as exc:
                print(f"[notifier] ERROR for {apm}: {exc}")
                errors += 1

        summary = {"sent": sent, "skipped": skipped, "errors": errors}
        print(f"[notifier] Complete — {summary}")
        return summary

    # ── Internal Routing ───────────────────────────────────────────────────────

    def _route(
        self,
        row: pd.Series,
        owner_email: str,
        manager_map: dict[str, str],
    ) -> int:
        """Route a single finding to the correct notification(s). Returns count sent."""
        pct        = int(row.get("pct", 0) or 0)
        due_status = str(row.get("due_status", "") or "")
        risk_tier  = str(row.get("risk_tier", "Low") or "Low")
        title      = str(row.get("title", "") or "")
        apm        = str(row.get("ssp_apm_id", "") or "")
        sent       = 0

        is_past_due = due_status == "Past due"
        is_critical = risk_tier == "Critical"

        # Urgent: past due with zero coverage
        if is_past_due and pct == 0:
            self._send_email(owner_email, *self._tmpl_past_due_no_coverage(apm, title))
            if self.teams_webhook:
                self._send_teams(
                    f"🔴 **URGENT — UAR Past Due** | {apm} | No MAR coverage | Owner: {owner_email}"
                )
            sent += 1

        # Reminder: past due with partial coverage
        elif is_past_due and 0 < pct < 100:
            self._send_email(owner_email, *self._tmpl_past_due_partial(apm, title, pct))
            sent += 1

        # Escalation: critical risk tier → notify manager
        if is_critical:
            manager = manager_map.get(owner_email)
            if manager:
                self._send_email(manager, *self._tmpl_escalation(apm, title, owner_email, risk_tier))
                sent += 1

        # Good news: 100% coverage → ready to close
        if pct == 100:
            self._send_email(owner_email, *self._tmpl_can_close(apm, title))
            sent += 1

        return sent

    # ── Email Templates ────────────────────────────────────────────────────────

    def _tmpl_past_due_no_coverage(self, apm: str, title: str) -> tuple[str, str]:
        subject = f"[UAR ACTION REQUIRED] {apm} — Past Due with No MAR Coverage"
        body = f"""
<p>Hello,</p>

<p>The following UAR finding requires <strong>immediate action</strong>:</p>

<table style="border-collapse:collapse;margin:16px 0">
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">APM:</td><td>{apm}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Finding:</td><td>{title}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Status:</td>
      <td style="color:#dc2626;font-weight:bold">Past Due</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">MAR Coverage:</td>
      <td style="color:#dc2626">0% — No AD groups verified in SailPoint/MAR</td></tr>
</table>

<p><strong>Required action:</strong> Enroll your AD group(s) in SailPoint UAR immediately,
or provide evidence that user access has been reviewed for this quarter.</p>

<p><a href="{DASHBOARD_URL}" style="color:#2563eb">View SSE UAR Dashboard</a>
for details and to download evidence once enrolled.</p>

<p>If you believe this finding is in error or have questions, reply to this email
and the SSE Compliance team will assist.</p>

<p>— SSE Security & Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_past_due_partial(self, apm: str, title: str, pct: int) -> tuple[str, str]:
        remaining = 100 - pct
        subject = f"[UAR REMINDER] {apm} — Past Due, {pct}% MAR Coverage"
        body = f"""
<p>Hello,</p>

<p>Your UAR finding is past due with partial MAR coverage ({pct}%).</p>

<table style="border-collapse:collapse;margin:16px 0">
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">APM:</td><td>{apm}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Finding:</td><td>{title}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Coverage:</td>
      <td>{pct}% verified ({remaining}% remaining)</td></tr>
</table>

<p>Good progress — you're partway there! Please enroll the remaining AD groups
in SailPoint UAR to reach 100% coverage and close this finding.</p>

<p><a href="{DASHBOARD_URL}" style="color:#2563eb">View SSE UAR Dashboard</a>
to see which groups still need MAR enrollment.</p>

<p>— SSE Security & Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_escalation(
        self, apm: str, title: str, owner: str, tier: str
    ) -> tuple[str, str]:
        subject = f"[UAR ESCALATION] {apm} — {tier} Risk Finding Requires Attention"
        body = f"""
<p>Hello,</p>

<p>A <strong style="color:#dc2626">{tier} Risk</strong> UAR finding under your team
requires urgent attention:</p>

<table style="border-collapse:collapse;margin:16px 0">
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">APM:</td><td>{apm}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Finding:</td><td>{title}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">APM Owner:</td><td>{owner}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Risk Tier:</td>
      <td style="color:#dc2626;font-weight:bold">{tier}</td></tr>
</table>

<p>Please follow up with {owner} to ensure this finding is remediated promptly.
{tier} risk findings are escalated automatically by the SSE UAR compliance pipeline.</p>

<p><a href="{DASHBOARD_URL}" style="color:#2563eb">View SSE UAR Dashboard</a></p>

<p>— SSE Security & Compliance Team</p>
""".strip()
        return subject, body

    def _tmpl_can_close(self, apm: str, title: str) -> tuple[str, str]:
        subject = f"[UAR READY TO CLOSE] {apm} — 100% MAR Coverage Achieved"
        body = f"""
<p>Hello,</p>

<p>Great news — your UAR finding now has <strong>100% MAR coverage</strong> and is
ready to be closed in AuditBoard!</p>

<table style="border-collapse:collapse;margin:16px 0">
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">APM:</td><td>{apm}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">Finding:</td><td>{title}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;font-weight:bold">MAR Coverage:</td>
      <td style="color:#16a34a;font-weight:bold">100% ✓</td></tr>
</table>

<p><strong>Next steps to close this finding:</strong></p>
<ol>
  <li>Go to the <a href="{DASHBOARD_URL}" style="color:#2563eb">SSE UAR Dashboard</a></li>
  <li>Find your APM in the <strong>Can Close</strong> tab</li>
  <li>Click <strong>Download Evidence</strong> to get the MAR evidence CSV</li>
  <li>Attach the CSV in AuditBoard and mark the finding as closed</li>
</ol>

<p>— SSE Security & Compliance Team</p>
""".strip()
        return subject, body

    # ── Send Helpers ───────────────────────────────────────────────────────────

    def _send_email(self, to: str, subject: str, body: str) -> None:
        if self.dry_run:
            print(f"  [email DRY RUN] To: {to}")
            print(f"    Subject: {subject}")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.from_addr
        msg["To"]      = to
        msg.attach(MIMEText(body, "html", "utf-8"))

        with smtplib.SMTP(self.smtp_host, self.port, timeout=10) as s:
            s.sendmail(self.from_addr, [to], msg.as_string())

    def _send_teams(self, text: str) -> None:
        if self.dry_run:
            print(f"  [teams DRY RUN] {text}")
            return
        if not self.teams_webhook:
            return

        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            self.teams_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10):
            pass


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running coc_notifier dry-run test...\n")

    mock_df = pd.DataFrame([
        {"ssp_apm_id": "APM0001000", "title": "APM0001000 UAR", "pct": 0,   "due_status": "Past due",  "risk_tier": "Critical"},
        {"ssp_apm_id": "APM0001001", "title": "APM0001001 UAR", "pct": 60,  "due_status": "Past due",  "risk_tier": "High"},
        {"ssp_apm_id": "APM0001002", "title": "APM0001002 UAR", "pct": 100, "due_status": "Active",    "risk_tier": "Low"},
    ])

    mock_owner_map   = {"APM0001000": "alice@walmart.com",
                        "APM0001001": "bob@walmart.com",
                        "APM0001002": "carol@walmart.com"}
    mock_manager_map = {"alice@walmart.com": "manager@walmart.com"}

    engine = NotificationEngine(dry_run=True)
    results = engine.notify_all(mock_df, mock_owner_map, mock_manager_map)
    print(f"\nResults: {results}")
