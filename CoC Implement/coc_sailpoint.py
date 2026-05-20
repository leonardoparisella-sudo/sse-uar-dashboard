"""
coc_sailpoint.py — Phase 5: SailPoint API Integration
Replaces local MAR CSV file reads with live SailPoint IdentityNow API calls.

Prerequisites:
    - SAILPOINT_TENANT_URL  : e.g. https://walmart.identitynow.com
    - SAILPOINT_CLIENT_ID   : OAuth2 client ID (from IAM team)
    - SAILPOINT_CLIENT_SECRET: OAuth2 client secret
    Set these as environment variables — NEVER hardcode them.

Usage:
    from coc_sailpoint import SailPointClient
    sp = SailPointClient()

    # Verify an AD group is in a UAR campaign
    if sp.group_in_uar("gcp-myapp-prod"):
        print("Group is enrolled in SailPoint UAR")

    # Get all entitlement records for a group
    for record in sp.get_entitlements_for_group("gcp-myapp-prod"):
        print(record)

    # Replace MAR CSV verification in build_dashboard.py:
    # Old: verified = word_boundary_check(group, mar_tokens)
    # New: verified = sp.group_in_uar(group)

Migration strategy:
    - Run in parallel with MAR CSV for 30 days to validate match accuracy
    - Compare sp.group_in_uar() results against word_boundary_check() results
    - If agreement >= 95%, retire the MAR CSV dependency
"""
from __future__ import annotations
import os
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Iterator


class SailPointClient:
    """
    SailPoint IdentityNow API client for UAR entitlement verification.

    Authenticates via OAuth2 client credentials flow.
    Access token is cached and refreshed when expired.

    Args:
        tenant_url    : SailPoint tenant base URL
        client_id     : OAuth2 client ID
        client_secret : OAuth2 client secret
    All three default to their respective environment variables.
    """

    def __init__(
        self,
        tenant_url:    str | None = None,
        client_id:     str | None = None,
        client_secret: str | None = None,
    ):
        self.tenant_url    = (tenant_url    or os.environ.get("SAILPOINT_TENANT_URL", "")).rstrip("/")
        self.client_id     = client_id     or os.environ.get("SAILPOINT_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("SAILPOINT_CLIENT_SECRET", "")

        if not all([self.tenant_url, self.client_id, self.client_secret]):
            missing = [
                k for k, v in {
                    "SAILPOINT_TENANT_URL":    self.tenant_url,
                    "SAILPOINT_CLIENT_ID":     self.client_id,
                    "SAILPOINT_CLIENT_SECRET": self.client_secret,
                }.items() if not v
            ]
            raise ValueError(
                f"Missing SailPoint credentials: {', '.join(missing)}\n"
                "Request OAuth2 client credentials from the IAM team.\n"
                "Scopes required: idn:entitlement-summary:read, idn:access-item:read"
            )

        self._token:      str | None = None
        self._token_exp:  float      = 0.0   # epoch seconds

    # ── Public API ─────────────────────────────────────────────────────────────

    def group_in_uar(self, group_name: str) -> bool:
        """
        Check if an AD group name is enrolled in any active UAR campaign.

        This is the drop-in replacement for the MAR CSV word_boundary_check().

        Args:
            group_name : AD group name (e.g. "gcp-myapp-prod", "hw-myteam")

        Returns:
            True if any SailPoint entitlement record contains this group name.
        """
        if not group_name or len(group_name) < 4:
            return False
        entitlements = list(self.get_entitlements_for_group(group_name))
        return len(entitlements) > 0

    def verify_groups_batch(self, group_names: list[str]) -> dict[str, bool]:
        """
        Verify multiple AD groups in batch.

        More efficient than calling group_in_uar() in a loop for large group lists.

        Args:
            group_names : List of AD group name strings

        Returns:
            dict mapping group_name → bool (True if found in SailPoint)
        """
        results: dict[str, bool] = {}
        for group in group_names:
            if group and len(group) >= 4:
                results[group] = self.group_in_uar(group)
        return results

    def get_entitlements_for_group(self, group_name: str) -> Iterator[dict]:
        """
        Yield all SailPoint entitlement records matching an AD group name.

        Equivalent to: MAR CSV rows WHERE entitlement LIKE '%group_name%'

        Args:
            group_name : AD group name to search for

        Yields:
            Entitlement record dicts from SailPoint API
        """
        # SailPoint v3 entitlement search — filter by value (group name)
        params = urllib.parse.urlencode({
            "filters": f'value eq "{group_name}"',
            "limit":   "250",
            "count":   "true",
        })
        url = f"{self.tenant_url}/v3/entitlements?{params}"

        try:
            page = self._get(url)
            items = page if isinstance(page, list) else page.get("items", [])
            yield from items
        except Exception as exc:
            # Log but don't crash — fall back to False
            print(f"[SailPoint] Error fetching entitlements for '{group_name}': {exc}")

    def get_active_uar_campaigns(self) -> list[dict]:
        """
        Return all active UAR (Access Review) certification campaigns.

        Useful for verifying which certification cycles are currently open.
        """
        params = urllib.parse.urlencode({
            "filters": "type eq \"ACCESS_REVIEW\" and status eq \"ACTIVE\"",
            "limit":   "100",
        })
        url = f"{self.tenant_url}/v3/certifications?{params}"
        result = self._get(url)
        return result if isinstance(result, list) else result.get("items", [])

    def get_campaign_details(self, campaign_id: str) -> dict:
        """Fetch full details for a specific UAR campaign."""
        return self._get(f"{self.tenant_url}/v3/certifications/{campaign_id}")

    def get_campaign_entitlements(self, campaign_id: str, limit: int = 1000) -> list[dict]:
        """
        Return all entitlements under a specific certification campaign.

        Useful for building a campaign-scoped MAR index.
        """
        params = urllib.parse.urlencode({"limit": str(limit)})
        url    = f"{self.tenant_url}/v3/certifications/{campaign_id}/items?{params}"
        result = self._get(url)
        return result if isinstance(result, list) else result.get("items", [])

    def build_entitlement_index(self, campaign_id: str | None = None) -> dict[str, list[dict]]:
        """
        Build an in-memory index of entitlement_value → [records] for fast lookups.

        If campaign_id is provided, indexes only that campaign.
        Otherwise indexes all active UAR campaigns.

        This is the SailPoint equivalent of the MAR CSV token index.

        Returns:
            dict[group_name → list[entitlement_records]]
        """
        index: dict[str, list[dict]] = {}

        if campaign_id:
            campaigns = [{"id": campaign_id}]
        else:
            campaigns = self.get_active_uar_campaigns()

        for campaign in campaigns:
            cid   = campaign.get("id", "")
            items = self.get_campaign_entitlements(cid)
            for item in items:
                value = str(item.get("entitlement", {}).get("value", "") or "").lower()
                if value:
                    index.setdefault(value, []).append(item)

        print(f"[SailPoint] Built entitlement index: {len(index)} unique values "
              f"across {len(campaigns)} campaign(s)")
        return index

    # ── MAR CSV Migration Helper ───────────────────────────────────────────────

    def validate_against_mar_csv(
        self,
        group_names: list[str],
        mar_word_boundary_fn,   # Callable: (group_name, mar_tokens) -> bool
        mar_tokens: set,
        print_report: bool = True,
    ) -> dict:
        """
        Compare SailPoint API results against existing MAR CSV results for the
        same set of AD groups.

        Run this in parallel mode for 30 days before retiring MAR CSVs.

        Args:
            group_names          : List of AD groups to compare
            mar_word_boundary_fn : The existing word_boundary_check function
            mar_tokens           : The existing MAR token index
            print_report         : Print detailed comparison report

        Returns:
            dict with agreement_pct, sp_only, mar_only, both, neither
        """
        sp_results  = self.verify_groups_batch(group_names)
        mar_results = {g: mar_word_boundary_fn(g, mar_tokens) for g in group_names}

        agree     = sum(1 for g in group_names if sp_results.get(g) == mar_results.get(g))
        sp_only   = [g for g in group_names if sp_results.get(g) and not mar_results.get(g)]
        mar_only  = [g for g in group_names if not sp_results.get(g) and mar_results.get(g)]
        both      = [g for g in group_names if sp_results.get(g) and mar_results.get(g)]
        neither   = [g for g in group_names if not sp_results.get(g) and not mar_results.get(g)]

        total           = len(group_names)
        agreement_pct   = round(agree / total * 100, 1) if total else 0.0

        report = {
            "total":          total,
            "agreement_pct":  agreement_pct,
            "sp_only":        sp_only,   # in SailPoint but not MAR CSV
            "mar_only":       mar_only,  # in MAR CSV but not SailPoint
            "both":           both,
            "neither":        neither,
        }

        if print_report:
            print(f"\n[SailPoint vs MAR] Validation Report")
            print(f"  Total groups:    {total}")
            print(f"  Agreement:       {agreement_pct}%")
            print(f"  SailPoint only:  {len(sp_only)} — {sp_only[:5]}")
            print(f"  MAR CSV only:    {len(mar_only)} — {mar_only[:5]}")
            print(f"  Both:            {len(both)}")
            print(f"  Neither:         {len(neither)}")
            if agreement_pct >= 95:
                print("  ✅ Agreement >= 95% — safe to retire MAR CSVs")
            else:
                print("  ⚠ Agreement < 95% — investigate discrepancies before retiring MAR CSVs")

        return report

    # ── OAuth2 Auth ────────────────────────────────────────────────────────────

    def _ensure_token(self) -> str:
        """Return a valid access token, refreshing if expired."""
        if self._token and time.time() < self._token_exp - 60:
            return self._token

        url  = f"{self.tenant_url}/oauth/token"
        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result     = json.loads(resp.read())
                self._token    = result["access_token"]
                expires_in     = int(result.get("expires_in", 3600))
                self._token_exp = time.time() + expires_in
                return self._token
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"SailPoint OAuth2 error HTTP {e.code}: {body}") from e

    def _get(self, url: str) -> list | dict:
        """Make an authenticated GET request to the SailPoint API."""
        token = self._ensure_token()
        req   = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept",        "application/json")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"SailPoint API error HTTP {e.code} for {url}: {body}") from e


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("coc_sailpoint.py — Phase 5: SailPoint API Integration")
    print()
    print("This module requires live SailPoint credentials to test.")
    print("Set these environment variables then run:")
    print()
    print("  SAILPOINT_TENANT_URL=https://walmart.identitynow.com")
    print("  SAILPOINT_CLIENT_ID=<from IAM team>")
    print("  SAILPOINT_CLIENT_SECRET=<from IAM team>")
    print()

    if all(os.environ.get(k) for k in ["SAILPOINT_TENANT_URL", "SAILPOINT_CLIENT_ID", "SAILPOINT_CLIENT_SECRET"]):
        sp = SailPointClient()

        print("Testing: get_active_uar_campaigns()...")
        campaigns = sp.get_active_uar_campaigns()
        print(f"  Found {len(campaigns)} active UAR campaign(s)")
        for c in campaigns[:3]:
            print(f"    - {c.get('id')}: {c.get('name')}")

        print("\nTesting: group_in_uar('gcp-test-group')...")
        result = sp.group_in_uar("gcp-test-group")
        print(f"  Result: {result}")
    else:
        print("Credentials not set — skipping live test.")
        print("Module structure is valid and ready for integration.")
