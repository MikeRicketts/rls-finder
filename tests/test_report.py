"""The single most important behaviour to pin down: reports never carry
record contents. CLAUDE.md §6 promises counts and metadata only; this test
exists so any future change that adds sample-row capture has to go through a
red test first.
"""

import json
import re

from rlscout.report import ScanReport, to_json, to_markdown
from rlscout.rls import SEV_HIGH, STATUS_PROTECTED, STATUS_VULNERABLE, TableResult


def _vuln(table, count):
    return TableResult(
        table, STATUS_VULNERABLE, 200, count,
        "anon SELECT returned rows",
        f"GET https://api.example.com/rest/v1/{table}?select=*&limit=1  "
        f"(anon apikey, Prefer: count=exact, Range: 0-0)",
        SEV_HIGH,
    )


def _protected(table):
    return TableResult(
        table, STATUS_PROTECTED, 200, 0,
        "anon SELECT returned no rows (default-deny / empty)",
        f"GET .../rest/v1/{table}?select=*&limit=1", "info",
    )


def _report_with_data():
    return ScanReport(
        target="https://app.example.com/",
        api_base="https://api.example.com",
        scope_notes="bounty target X, scope confirmed",
        started_at="t0", finished_at="t1", request_count=10,
        anon_key_found=True,
        table_results=[
            _vuln("public_notes", 17),
            _vuln("leaky_profiles", 2),
            _protected("private_secrets"),
        ],
        fetched_urls=["https://app.example.com/", "https://app.example.com/main.js"],
    )


def test_markdown_report_carries_counts_not_rows():
    report = _report_with_data()
    md = to_markdown(report)
    assert "public_notes" in md and "17" in md
    # The "evidence" line is the request, not a payload.
    assert "Range: 0-0" in md  # the new evidence string (S4)
    # Anti-tests: no record-content shapes can appear in a Markdown report.
    forbidden = (
        "note-1", "note-2",          # any seeded row contents
        '"id":', '"email":',         # JSON object shapes (would hint at row data)
        "@example.com",              # any sample email
        "row_data", "sample_rows", "sample",
    )
    for needle in forbidden:
        assert needle not in md, f"forbidden token {needle!r} found in markdown report"


def test_json_report_has_counts_but_no_record_payload():
    report = _report_with_data()
    js = json.loads(to_json(report))
    findings = {f["table"]: f for f in js["findings"]}
    assert findings["public_notes"]["row_count"] == 17
    assert findings["public_notes"]["status"] == "vulnerable"
    # Anti-tests on the JSON shape: nothing that hints at row contents.
    for f in js["findings"]:
        assert set(f.keys()) <= {
            "table", "status", "severity", "access_proven",
            "request", "http_status", "row_count",
        }
    assert "rows" not in js
    assert "samples" not in js
    assert "row_data" not in js
    # Belt-and-suspenders: the *serialised* json must not contain any
    # word that screams "I have row contents."
    raw = json.dumps(js)
    for token in ("\"sample_row\"", "\"sample_rows\"", "\"row_data\""):
        assert token not in raw


def test_service_role_critical_block_does_not_carry_the_key():
    """A critical-exposure report describes the leak; it must not echo the JWT
    itself, since that would still be a sensitive payload sitting in the
    report (and bounty platforms reject reports that exfiltrate live secrets).
    """
    report = ScanReport(
        target="https://app.example.com/",
        api_base=None, scope_notes="",
        started_at="t0", finished_at="t1", request_count=1,
        service_role_exposed=True,
        # The detail intentionally uses .short (first 12 chars + last 6) — not
        # the full JWT — so the report points at the leak without re-exporting it.
        service_role_detail=(
            "service_role JWT found in client-shipped content at "
            "https://app.example.com/main.js (key eyJhbGciOi...ABCDEF). "
            "This is a full RLS bypass. RLScout halted WITHOUT using the key."
        ),
        halted_reason="service_role key exposed client-side",
    )
    md = to_markdown(report)
    assert "CRITICAL" in md and "service_role" in md
    # The fingerprint is fine; a full JWT (header.payload.signature with three
    # base64url segments) must not appear anywhere.
    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")
    assert not jwt_pattern.search(md), "report appears to contain a full JWT"
