"""
coc_auditboard.py — Phase 4: AuditBoard API Integration
Reads and writes to AuditBoard findings via REST API.

Prerequisites:
    - AUDITBOARD_API_KEY environment variable set (service account token from GRC team)
    - Network access to walmart-infosec.auditboardapp.com
    - API permissions: issue:read, issue:write, issue:close (confirm with GRC)

Usage:
    import os
    os.environ["AUDITBOARD_API_KEY"] = "your-token-here"  # or set in shell

    from coc_auditboard import AuditBoardClient
    ab = AuditBoardClient(dry_run=True)  # always dry_run first

    # Post MAR verification comment
    ab.post_mar_comment(
        issue_id=12345,
        apm_id="APM0001234",
        verified_groups=["gcp-myapp-prod", "hw-myteam"],
        pct=100,
    )

    # Close a finding
    ab.close_finding(issue_id=12345)

IMPORTANT: Test all operations with dry_run=True before enabling live writes.
Confirm the correct "closed" status string with GRC before calling close_finding().
"""
from __future__ import annotations
import os
import json
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path


AB_BASE       = "https://walmart-infosec.auditboardapp.com"
DASHBOARD_URL = "https://gecgithub01.walmart.com/pages/lparise/sse-uar-dashboard/sse_uar_dashboard.html"

# !! Confirm this status string with GRC before using close_finding() !!
# Common values: "Closed", "Remediated", "Accepted", "Risk Accepted"
AUDITBOARD_CLOSED_STATUS = "Closed"


class AuditBoardClient:
    """
    REST API client for AuditBoard (walmart-infosec.auditboardapp.com).

    Always initialize with dry_run=True until the API key and permissions
    are confirmed with the GRC team.

    Args:
        base_url : AuditBoard instance URL (default: walmart-infosec)
        dry_run  : If True, prints API calls instead of executing them
    """

    def __init__(
        self,
        base_url: str = AB_BASE,
        dry_run: bool = True,
    ):
        self.base     = base_url.rstrip("/")
        self.dry_run  = dry_run
        self._api_key = os.environ.get("AUDITBOARD_API_KEY")

        if not self._api_key and not dry_run:
            raise ValueError(
                "AUDITBOARD_API_KEY environment variable not set.\n"
                "Request a service account API key from the GRC team with:\n"
                "  - issue:read\n"
                "  - issue:write (comments)\n"
                "  - issue:close\n"
                "permissions."
            )

        if dry_run:
            print("[AuditBoard] ⚠ DRY RUN MODE — no API calls will be made")

    # ── Public API ─────────────────────────────────────────────────────────────

    def post_mar_comment(
        self,
        issue_id: int,
        apm_id: str,
        verified_groups: list[str],
        pct: int,
        keep_open_groups: list[str] | None = None,
    ) -> dict:
        """
        Post a structured MAR verification comment to an AuditBoard finding.

        This creates a permanent audit record on the finding documenting:
        - Which AD groups were verified in SailPoint/MAR
        - The coverage percentage at time of run
        - Instructions for the next step

        Args:
            issue_id         : AuditBoard issue/finding integer ID
            apm_id           : APM ID string (e.g. "APM0001234")
            verified_groups  : AD groups verified in MAR (will be posted to finding)
            pct              : MAR coverage percentage 0-100
            keep_open_groups : AD groups NOT yet in MAR (optional, for partial coverage)

        Returns:
            API response dict (or dry_run placeholder)
        """
        verified_list  = "\n".join(f"  • {g}" for g in sorted(verified_groups)) or "  (none)"
        unverified_str = ""
        if keep_open_groups:
            unverified_list = "\n".join(f"  • {g}" for g in sorted(keep_open_groups))
            unverified_str  = f"\n\nAD Groups NOT yet in MAR ({len(keep_open_groups)}):\n{unverified_list}"

        status_line = (
            "✅ READY TO CLOSE — 100% MAR coverage achieved."
            if pct == 100
            else f"⚠ PARTIAL — {pct}% coverage. {100 - pct}% of AD groups still need MAR enrollment."
        )

        comment_text = (
            f"[AUTOMATED — SSE UAR Pipeline]\n\n"
            f"APM: {apm_id}\n"
            f"MAR Coverage: {pct}%\n"
            f"Status: {status_line}\n\n"
            f"Verified AD Groups ({len(verified_groups)}):\n{verified_list}"
            f"{unverified_str}\n\n"
            f"Evidence CSV available at: {DASHBOARD_URL}\n"
            f"Download the CSV from the 'Can Close' tab and attach here to close."
        )

        return self._request("POST", f"/api/v2/issues/{issue_id}/comments", {"comment": comment_text})

    def close_finding(
        self,
        issue_id: int,
        close_note: str = "",
        evidence_path: Path | None = None,
    ) -> dict:
        """
        Mark an AuditBoard finding as closed.

        ⚠ CONFIRM WITH GRC BEFORE CALLING THIS:
        - What is the correct "closed" status string in Walmart's AuditBoard?
        - Does the API support programmatic closure or only status update?
        - Is a second approval step required?

        Args:
            issue_id     : AuditBoard issue integer ID
            close_note   : Closure justification text
            evidence_path: Optional path to evidence CSV to attach

        Returns:
            API response dict
        """
        payload = {
            "status": AUDITBOARD_CLOSED_STATUS,
            "remediation_note": (
                close_note or
                "[AUTOMATED] 100% MAR/SailPoint coverage verified by SSE UAR Pipeline. "
                f"All AD groups enrolled in UAR. Evidence at {DASHBOARD_URL}"
            ),
        }
        result = self._request("PATCH", f"/api/v2/issues/{issue_id}", payload)

        if evidence_path and evidence_path.exists():
            self._upload_evidence(issue_id, evidence_path)

        return result

    def get_finding(self, issue_id: int) -> dict:
        """
        Fetch a single finding's full metadata from AuditBoard.

        Useful for verifying current status before posting a comment or closing.
        """
        return self._request("GET", f"/api/v2/issues/{issue_id}")

    def list_findings(
        self,
        status: str = "Active",
        title_contains: str = "UAR",
        limit: int = 500,
    ) -> list[dict]:
        """
        List AuditBoard findings filtered by status and title keyword.

        Useful for cross-referencing against the pipeline's finding list
        to ensure IDs are consistent.
        """
        params = urllib.parse.urlencode({
            "filter[status]":  status,
            "filter[title]":   title_contains,
            "page[size]":      str(limit),
        })
        result = self._request("GET", f"/api/v2/issues?{params}")
        return result if isinstance(result, list) else result.get("data", [])

    def process_can_close_batch(
        self,
        df,  # pd.DataFrame with issue_id, ssp_apm_id, pct, title columns
        post_comments: bool = True,
        auto_close: bool = False,   # False by default — requires GRC approval
    ) -> dict[str, int]:
        """
        Process all 'Can Close' findings in batch.

        For each finding where pct == 100:
        1. Post a MAR verification comment (if post_comments=True)
        2. Close the finding (if auto_close=True — requires GRC approval first)

        Args:
            df            : Records DataFrame with pct, issue_id, ssp_apm_id columns
            post_comments : Post verification comment to each finding
            auto_close    : Close the finding (ONLY enable after GRC confirmation)

        Returns:
            {"commented": N, "closed": N, "errors": N}
        """
        commented = closed = errors = 0

        can_close_df = df[df.get("pct", 0) == 100] if hasattr(df, "__len__") else []

        for _, row in (can_close_df.iterrows() if hasattr(can_close_df, "iterrows") else []):
            issue_id = row.get("issue_id")
            apm_id   = str(row.get("ssp_apm_id", ""))
            pct      = int(row.get("pct", 0))
            verified = list(row.get("verified_groups", []) or [])

            if not issue_id:
                print(f"[AuditBoard] Skipping {apm_id} — no issue_id")
                continue

            try:
                if post_comments:
                    self.post_mar_comment(int(issue_id), apm_id, verified, pct)
                    commented += 1

                if auto_close:
                    self.close_finding(int(issue_id))
                    closed += 1

            except Exception as exc:
                print(f"[AuditBoard] ERROR for issue {issue_id} ({apm_id}): {exc}")
                errors += 1

        result = {"commented": commented, "closed": closed, "errors": errors}
        print(f"[AuditBoard] Batch complete — {result}")
        return result

    # ── HTTP Helpers ───────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | list:
        url = self.base + path

        if self.dry_run:
            print(f"  [AuditBoard DRY RUN] {method} {path}")
            if payload:
                preview = json.dumps(payload)[:200]
                print(f"    Payload preview: {preview}{'...' if len(json.dumps(payload)) > 200 else ''}")
            return {"dry_run": True, "method": method, "path": path}

        data    = json.dumps(payload).encode("utf-8") if payload else None
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"AuditBoard API HTTP {e.code}: {body}") from e

    def _upload_evidence(self, issue_id: int, file_path: Path) -> None:
        """
        Attach a file to an AuditBoard finding.

        NOTE: Multipart upload implementation depends on AuditBoard API version.
        Confirm the attachment endpoint with GRC before implementing.
        Placeholder implementation — prints intent in dry_run mode.
        """
        if self.dry_run:
            print(f"  [AuditBoard DRY RUN] Would upload {file_path.name} to issue {issue_id}")
            return
        # TODO: Implement multipart/form-data upload
        # Example endpoint (verify with GRC): POST /api/v2/issues/{id}/attachments
        print(f"[AuditBoard] ⚠ Evidence upload not yet implemented. "
              f"Please manually attach {file_path} to issue {issue_id} in AuditBoard.")


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running coc_auditboard dry-run test...\n")

    ab = AuditBoardClient(dry_run=True)

    print("Test 1: post_mar_comment")
    ab.post_mar_comment(
        issue_id        = 99999,
        apm_id          = "APM0001234",
        verified_groups = ["gcp-myapp-prod", "hw-myteam-access", "sams-member"],
        pct             = 100,
    )

    print("\nTest 2: post_mar_comment (partial)")
    ab.post_mar_comment(
        issue_id         = 99998,
        apm_id           = "APM0005678",
        verified_groups  = ["gcp-myapp-prod"],
        pct              = 50,
        keep_open_groups = ["hw-myteam-access"],
    )

    print("\nTest 3: close_finding")
    ab.close_finding(issue_id=99999)

    print("\nTest 4: get_finding")
    ab.get_finding(issue_id=99999)

    print("\nAll dry-run tests passed.")
    print("\nTo enable live mode:")
    print("  1. Set AUDITBOARD_API_KEY environment variable")
    print("  2. Confirm AUDITBOARD_CLOSED_STATUS string with GRC team")
    print("  3. Change dry_run=False in AuditBoardClient()")
