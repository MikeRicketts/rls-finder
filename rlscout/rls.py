"""The core check: a read-only anon SELECT per table, capturing counts only.

For each discovered table, against the anon key only, issue a single
``GET /rest/v1/<table>?select=*`` with a tight row limit and a count header.

Interpretation:
- rows returned     -> FINDING: table readable by an unauthenticated client.
- empty/default-deny -> reported as protected.
- 401/403           -> protected (RLS blocked the read).

Per CLAUDE.md §6 the tool records only metadata: table name, the access that
succeeded, HTTP status, and a row count. It never stores sample rows.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enumerate import _supabase_headers
from .http import ScopedClient
from .recon import FoundKey

# Severity labels used in reports.
SEV_HIGH = "high"
SEV_INFO = "info"

STATUS_VULNERABLE = "vulnerable"
STATUS_PROTECTED = "protected"
STATUS_UNKNOWN = "unknown"


@dataclass
class TableResult:
    """The outcome of one read-only anon SELECT against one table."""

    table: str
    status: str  # STATUS_*
    http_status: int
    row_count: int | None  # rows visible to anon (None = unknown)
    access: str  # human description of what was proven
    request: str  # the request that proved it
    severity: str = SEV_INFO

    @property
    def is_vulnerable(self) -> bool:
        return self.status == STATUS_VULNERABLE


def _parse_count(resp) -> int | None:
    """Read the row count from PostgREST's Content-Range header (e.g. ``0-0/42``)."""
    cr = resp.headers.get("content-range") or resp.headers.get("Content-Range")
    if not cr or "/" not in cr:
        return None
    total = cr.rsplit("/", 1)[-1].strip()
    if total in ("", "*"):
        return None
    try:
        return int(total)
    except ValueError:
        return None


def check_table(
    client: ScopedClient,
    api_base: str,
    key: FoundKey,
    table: str,
    *,
    verbose: bool = False,
) -> TableResult:
    """Run a single read-only anon SELECT and classify the result (counts only)."""
    url = f"{api_base.rstrip('/')}/rest/v1/{table}"
    # limit=1 keeps the read tiny; count=exact + Range:0-0 learns "are there rows"
    # without pulling any record contents back.
    headers = {**_supabase_headers(key), "Prefer": "count=exact", "Range": "0-0"}
    params = {"select": "*", "limit": "1"}
    req_desc = (
        f"GET {url}?select=*&limit=1  "
        f"(anon apikey, Prefer: count=exact, Range: 0-0)"
    )

    resp = client.get(url, headers=headers, params=params)
    if resp is None:
        return TableResult(
            table, STATUS_UNKNOWN, 0, None, "network error", req_desc, SEV_INFO
        )

    code = resp.status_code
    if code in (401, 403):
        return TableResult(
            table, STATUS_PROTECTED, code,
            0, "anon read blocked by RLS (auth required)", req_desc, SEV_INFO,
        )

    if code in (404, 406):
        # 404 = table doesn't exist / not exposed; 406 = bad Accept negotiation.
        return TableResult(
            table, STATUS_UNKNOWN, code, None,
            "table not exposed or not present", req_desc, SEV_INFO,
        )

    if 200 <= code < 300:
        count = _parse_count(resp)
        # A 2xx that returns rows is the proof. PostgREST returns a JSON array;
        # we only inspect length, never contents.
        returned_rows = 0
        try:
            body = resp.json()
            if isinstance(body, list):
                returned_rows = len(body)
        except ValueError:
            returned_rows = 0

        has_rows = (count is not None and count > 0) or returned_rows > 0
        if has_rows:
            shown = count if count is not None else returned_rows
            return TableResult(
                table, STATUS_VULNERABLE, code, shown,
                "anon SELECT returned rows", req_desc, SEV_HIGH,
            )
        return TableResult(
            table, STATUS_PROTECTED, code, 0,
            "anon SELECT returned no rows (default-deny / empty)", req_desc, SEV_INFO,
        )

    return TableResult(
        table, STATUS_UNKNOWN, code, None,
        f"unexpected status {code}", req_desc, SEV_INFO,
    )


def scan_tables(
    client: ScopedClient,
    api_base: str,
    key: FoundKey,
    tables: list[str],
    *,
    verbose: bool = False,
) -> list[TableResult]:
    """Run the read-only check across all tables. No write, no cross-user testing."""
    results: list[TableResult] = []
    for table in tables:
        res = check_table(client, api_base, key, table, verbose=verbose)
        results.append(res)
        if verbose:
            marker = "VULN" if res.is_vulnerable else res.status
            count = "" if res.row_count is None else f" rows>={res.row_count}"
            print(f"  [{marker:>9}] {table} ({res.http_status}){count}")
    return results
