"""Report emission — Markdown (submission-ready) and JSON (machine-readable).

Per CLAUDE.md §6 and §8: each finding carries the table, the access proven, the
request that proved it, HTTP status, row count, and severity. **No record
samples** are ever included — there is nothing sensitive captured to redact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .rls import STATUS_PROTECTED, TableResult


@dataclass
class ScanReport:
    """The complete result of one run, ready to serialize."""

    target: str
    api_base: str | None
    scope_notes: str
    started_at: str
    finished_at: str
    request_count: int
    service_role_exposed: bool = False
    service_role_detail: str = ""
    anon_key_found: bool = False
    table_results: list[TableResult] = field(default_factory=list)
    fetched_urls: list[str] = field(default_factory=list)
    halted_reason: str = ""
    # Optional bounded-LLM layer (--ai); advisory only.
    ai_notes: list[str] = field(default_factory=list)
    ai_triage_markdown: str = ""
    ai_judgments: list[dict] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[TableResult]:
        return [r for r in self.table_results if r.is_vulnerable]

    @property
    def protected(self) -> list[TableResult]:
        return [r for r in self.table_results if r.status == STATUS_PROTECTED]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_json(report: ScanReport) -> str:
    payload = {
        "tool": "RLScout",
        "version": "1.0.0",
        "target": report.target,
        "api_base": report.api_base,
        "scope_notes": report.scope_notes,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "request_count": report.request_count,
        "service_role_exposed": report.service_role_exposed,
        "service_role_detail": report.service_role_detail,
        "anon_key_found": report.anon_key_found,
        "halted_reason": report.halted_reason,
        "fetched_urls": report.fetched_urls,
        "ai_notes": report.ai_notes,
        "ai_triage": report.ai_judgments,
        "summary": {
            "tables_checked": len(report.table_results),
            "vulnerable": len(report.vulnerable),
            "protected": len(report.protected),
        },
        "findings": [
            {
                "table": r.table,
                "status": r.status,
                "severity": r.severity,
                "access_proven": r.access,
                "request": r.request,
                "http_status": r.http_status,
                "row_count": r.row_count,
            }
            for r in report.table_results
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("# RLScout report")
    lines.append("")
    lines.append(f"- **Target:** `{report.target}`")
    lines.append(f"- **API base:** `{report.api_base or 'n/a'}`")
    lines.append(f"- **Scope:** {report.scope_notes or 'n/a'}")
    lines.append(f"- **Run:** {report.started_at} → {report.finished_at}")
    lines.append(f"- **Requests made:** {report.request_count}")
    lines.append("")
    lines.append(
        "> RLScout is a read-only, in-scope detector for unauthenticated read "
        "exposure. It records counts/metadata only — never record contents."
    )
    lines.append("")

    if report.service_role_exposed:
        lines.append("## 🔴 CRITICAL: service_role key exposed client-side")
        lines.append("")
        lines.append(report.service_role_detail or
                     "A service_role key was found in client-shipped content. "
                     "This is a full RLS bypass. Scan halted without using the key.")
        lines.append("")

    vuln = report.vulnerable
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Tables checked: **{len(report.table_results)}**")
    lines.append(f"- Vulnerable (anon-readable): **{len(vuln)}**")
    lines.append(f"- Protected: **{len(report.protected)}**")
    if report.halted_reason:
        lines.append(f"- Halted: {report.halted_reason}")
    lines.append("")

    if vuln:
        lines.append("## Findings — unauthenticated read exposure")
        lines.append("")
        lines.append("| Table | Severity | HTTP | Row count | Access proven |")
        lines.append("|---|---|---|---|---|")
        for r in vuln:
            rc = "?" if r.row_count is None else str(r.row_count)
            lines.append(
                f"| `{r.table}` | {r.severity} | {r.http_status} | {rc} | {r.access} |"
            )
        lines.append("")
        lines.append("### Evidence (request that proved each finding)")
        lines.append("")
        for r in vuln:
            lines.append(f"- **`{r.table}`** — `{r.request}` → HTTP {r.http_status}, "
                         f"row count {'?' if r.row_count is None else r.row_count}")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No unauthenticated read exposure detected. ✅")
        lines.append("")

    if report.ai_judgments or report.ai_triage_markdown:
        lines.append("## AI triage (advisory — verify manually)")
        lines.append("")
        if report.ai_judgments:
            lines.append("| Table | Assessment | Rationale |")
            lines.append("|---|---|---|")
            for j in report.ai_judgments:
                lines.append(f"| `{j.get('table','')}` | {j.get('likelihood','')} | "
                             f"{j.get('rationale','')} |")
            lines.append("")
        if report.ai_triage_markdown:
            lines.append(report.ai_triage_markdown)
            lines.append("")

    if report.ai_notes:
        lines.append("## AI notes")
        lines.append("")
        for n in report.ai_notes:
            lines.append(f"- {n}")
        lines.append("")

    protected = report.protected
    if protected:
        lines.append("## Reported as protected")
        lines.append("")
        for r in protected:
            lines.append(f"- `{r.table}` — {r.access} (HTTP {r.http_status})")
        lines.append("")

    lines.append("## Out of scope by design (needs a human)")
    lines.append("")
    lines.append("- Cross-user / IDOR-style broken RLS (authenticated multi-user).")
    lines.append("- Write-side policy gaps (INSERT/UPDATE/DELETE).")
    lines.append("")
    lines.append("_v1 is a high-confidence detector for unauthenticated read "
                 "exposure, and a pointer for the deeper classes that need a human._")
    lines.append("")
    return "\n".join(lines)


def write_reports(report: ScanReport, out_prefix: str | Path) -> tuple[Path, Path]:
    """Write ``<prefix>.md`` and ``<prefix>.json``; return both paths."""
    prefix = Path(out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    md_path = prefix.with_suffix(".md")
    json_path = prefix.with_suffix(".json")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    json_path.write_text(to_json(report), encoding="utf-8")
    return md_path, json_path
