"""RLScout CLI — wiring and flags.

One way to run: ``rlscout app.example.com`` (or ``https://app.example.com``).
The website you type is the implicit allowlist. If recon discovers a Supabase
API host on a *different* host (it usually is), the CLI pauses ONCE with
``Also scan api-xyz.supabase.co? [y/N]`` — ``--yes`` auto-accepts.

The structural invariants are unchanged: every request goes through
``ScopedClient`` → ``scope.enforce()``, ``ALLOWED_METHODS = {"GET"}``, off-scope
redirects hard-abort, service_role keys are reported and never used.

Flow:
    build scope (target name → Scope.from_target)
      └▶ recon: fetch page + same-origin JS/config, extract JWTs, decode role
           ├─ service_role found ─▶ CRITICAL finding, STOP
           ├─ discovered Supabase API host not in scope ─▶ inline confirm,
           │   ``scope.allow(host)``, continue
           └─ anon ─▶ enumerate tables (OpenAPI ∪ wordlist)
                        └▶ read-only anon SELECT per table (rate-limited)
                             └▶ report (md + json), counts only, no samples
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, agent
from .enumerate import discover_tables
from .envfile import load_dotenv
from .http import DEFAULT_UA, ScopedClient
from .ratelimit import RateLimiter, RateLimitError
from .recon import (
    ApiBaseDecision,
    FoundKey,
    decode_jwt_payload,
    infer_api_base,
    run_recon,
)
from .report import (
    ScanReport,
    now_iso,
    to_markdown,
    write_reports,
)
from .rls import scan_tables
from .scope import Scope, ScopeError, normalize_target


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rlscout",
        description="Read-only, in-scope detector for missing/broken Supabase RLS.",
    )
    p.add_argument(
        "target", nargs="?", default=None,
        help="the website to scan — a bare name (app.example.com) or a full "
             "http(s):// URL. Its host is the implicit allowlist; a Supabase API "
             "host discovered in the bundle prompts for inline approval (or "
             "--yes to auto-accept).",
    )
    p.add_argument(
        "--wordlist", default=None,
        help="extra table-name wordlist file (extends the built-in default)",
    )
    p.add_argument(
        "--crawl-depth", type=int, default=1,
        help="recon crawl depth (default: 1 = target page + same-origin assets)",
    )
    p.add_argument(
        "--rate", type=float, default=3.0,
        help="max requests/second (default: 3; <=0 disables throttle)",
    )
    p.add_argument(
        "--max-requests", type=int, default=500,
        help="global per-run request cap (default: 500; <=0 disables)",
    )
    p.add_argument(
        "--api-base", default=None,
        help="override the PostgREST base URL (still scope-checked)",
    )
    p.add_argument(
        "--user-agent", default=None,
        help="override the HTTP User-Agent (default: a browser-like UA)",
    )
    p.add_argument(
        "-o", "--out", default=None,
        help="output prefix; writes <prefix>.md and <prefix>.json",
    )
    p.add_argument(
        "--ai", action="store_true",
        help="enable the bounded LLM layer: triage findings + draft writeup, and "
             "a recon fallback. Needs the 'ai' extra and ANTHROPIC_API_KEY.",
    )
    p.add_argument(
        "--ai-model", default=None,
        help="Anthropic model id for --ai (default: claude-opus-4-8)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="verbose progress")
    p.add_argument(
        "--yes", "-y", action="store_true",
        help="non-interactive: auto-accept any inline 'also scan discovered "
             "Supabase API host X?' prompt. Required for piped/CI use.",
    )
    p.add_argument("--version", action="version", version=f"RLScout {__version__}")
    return p


def _print_scope_banner(scope: Scope) -> None:
    """Print the scope the run will operate under. No prompt — the website name
    on the command line IS the operator's affirmation."""
    print("[scope] (Quick Mode): " + ", ".join(scope.authorized_hosts))
    if scope.notes:
        print(f"[scope] notes: {scope.notes}")
    sys.stdout.flush()


def _confirm_allow(host: str, *, assume_yes: bool) -> bool:
    """Inline y/N prompt to extend scope at runtime (e.g. discovered API host).

    Returns True if the operator (or ``--yes``) approved. Non-interactive
    sessions without ``--yes`` return False, refusing to extend scope silently.
    """
    if assume_yes:
        print(f"  [scope] auto-accepting newly-discovered host {host} (--yes).")
        return True
    if not sys.stdin.isatty():
        print(f"  [scope] {host} not in scope and stdin is not a TTY; "
              f"refusing to add silently. Re-run with --yes.", file=sys.stderr)
        return False
    try:
        ans = input(f"  Also scan discovered Supabase host {host}? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes")


def _ai_recon_fallback(recon, scope, args, report):
    """B+: let the LLM read already-fetched in-scope text and PROPOSE a key/base.

    Returns ``(FoundKey|None, api_base|None)``. The proposed key is re-validated
    (must decode to an anon JWT, never service_role) and the proposed base is
    scope-enforced here, before either is used. The LLM never fetches anything.
    """
    if not agent.ai_available():
        report.ai_notes.append(f"AI recon fallback skipped: {agent.ai_import_hint()}")
        print(f"[ai] {agent.ai_import_hint()}", file=sys.stderr)
        return None, None
    if args.verbose:
        print("[ai] deterministic recon found no key; trying LLM fallback ...")
    res = agent.recon_fallback(recon.fetched_texts,
                               model=args.ai_model or agent.DEFAULT_AI_MODEL)
    if not res.ok:
        report.ai_notes.append(f"AI recon fallback error: {res.error}")
        print(f"[ai] recon fallback failed: {res.error}", file=sys.stderr)
        return None, None

    proposal = res.value
    key = None
    token = (proposal.anon_key or "").strip()
    if token:
        payload = decode_jwt_payload(token)
        if payload is None:
            report.ai_notes.append("AI proposed a key that is not a valid JWT — ignored.")
        elif payload.get("role") == "service_role":
            report.ai_notes.append("AI proposed a service_role key — refused to use it.")
        elif payload.get("role") == "anon":
            key = FoundKey(token=token, role="anon", payload=payload,
                           source_url="ai-recon-fallback")
            report.ai_notes.append("AI recon fallback recovered an anon key from the bundle.")
        else:
            report.ai_notes.append(
                f"AI proposed a key with role={payload.get('role')!r} — not anon, ignored.")

    api_base = None
    cand = (proposal.api_base or "").strip().rstrip("/")
    if cand:
        try:
            authorized = scope.is_authorized(cand)
        except ScopeError as exc:
            # The proposal wasn't even a parseable URL; record it so the
            # operator sees why the LLM fallback didn't yield a base.
            report.ai_notes.append(
                f"AI proposed an unparseable API base ({cand!r}): {exc}"
            )
        else:
            if authorized:
                api_base = cand
                report.ai_notes.append(f"AI recon fallback proposed API base {cand}.")
            else:
                report.ai_notes.append(
                    f"AI proposed off-scope API base {cand} — refused "
                    f"(approve it at the inline prompt instead).")
    return key, api_base


def _ai_triage(report, target, api_base, args):
    """B: classify anon-readable tables + draft a writeup (metadata only)."""
    if not agent.ai_available():
        report.ai_notes.append(f"AI triage skipped: {agent.ai_import_hint()}")
        print(f"[ai] {agent.ai_import_hint()}", file=sys.stderr)
        return
    findings = [(r.table, r.row_count) for r in report.vulnerable]
    if args.verbose:
        print(f"[ai] triaging {len(findings)} finding(s) ...")
    res = agent.triage(findings, target=target, api_base=api_base,
                       model=args.ai_model or agent.DEFAULT_AI_MODEL)
    if not res.ok:
        report.ai_notes.append(f"AI triage error: {res.error}")
        print(f"[ai] triage failed: {res.error}", file=sys.stderr)
        return
    result = res.value
    report.ai_triage_markdown = result.writeup_markdown
    report.ai_judgments = [
        {"table": j.table, "likelihood": j.likelihood, "rationale": j.rationale}
        for j in result.judgments
    ]


def _scan_target(
    client: ScopedClient,
    scope: Scope,
    target: str,
    args: argparse.Namespace,
    limiter: RateLimiter,
) -> ScanReport:
    """Run the full read-only pipeline against the target; return the report.

    A mid-scan ``ScopeError`` (e.g. off-scope redirect) is caught and recorded as
    a halt — loudly. ``RateLimitError`` (global cap) is left to propagate.
    """
    before = limiter.count
    started = now_iso()
    report = ScanReport(
        target=target, api_base=None, scope_notes=scope.notes,
        started_at=started, finished_at=started, request_count=0,
    )

    def finalize() -> ScanReport:
        report.request_count = limiter.count - before
        report.finished_at = now_iso()
        return report

    try:
        if args.verbose:
            print(f"[*] Recon: {target}")
        recon = run_recon(
            client, target, crawl_depth=args.crawl_depth, verbose=args.verbose
        )
        report.fetched_urls = recon.fetched_urls

        # service_role branch: STOP, do not use the key. The leak is the finding.
        if recon.service_role_keys:
            k = recon.service_role_keys[0]
            report.service_role_exposed = True
            report.service_role_detail = (
                f"service_role JWT found in client-shipped content at "
                f"{k.source_url} (key {k.short}). This is a full RLS bypass. "
                f"RLScout halted WITHOUT using the key — the leak itself is the "
                f"critical finding."
            )
            report.halted_reason = "service_role key exposed client-side"
            print(f"[!] CRITICAL: service_role key exposed at {target}. Halting.")
            return finalize()

        # Need an anon key to test.
        anon = recon.anon_keys
        key = anon[0] if anon else None
        ai_api_base: str | None = None
        if key is None and args.ai:
            key, ai_api_base = _ai_recon_fallback(recon, scope, args, report)
        if key is None:
            report.halted_reason = "no anon key found in client-shipped content"
            print(f"[!] {target}: no anon Supabase key found; nothing to test.")
            return finalize()
        report.anon_key_found = True

        # Resolve the API base (override > key-paired/discovered in-scope > origin).
        if args.api_base:
            try:
                scope.enforce(args.api_base)
            except ScopeError as exc:
                print(f"[scope] {target}: --api-base off-scope: {exc}", file=sys.stderr)
                report.halted_reason = "supplied API base was off-scope"
                return finalize()
            api_base = args.api_base
        else:
            decision = infer_api_base(recon, target, scope, key=key)
            # If everything Supabase-shaped is off-scope, offer to extend the
            # scope inline. The structural enforcement at ScopedClient does not
            # change — we ask, then call scope.allow(), then re-run the chooser.
            if decision.base is None and decision.off_scope_candidates:
                approved_any = False
                for host in decision.off_scope_candidates:
                    if _confirm_allow(host, assume_yes=args.yes):
                        scope.allow(host)
                        approved_any = True
                        report.ai_notes.append(
                            f"scope extended at runtime: {host} (operator-approved)"
                        )
                if approved_any:
                    decision = infer_api_base(recon, target, scope, key=key)
            if decision.base is None and ai_api_base:
                # AI fallback proposed an API base (already scope-validated).
                decision = ApiBaseDecision(base=ai_api_base)
            if decision.base is None:
                if decision.off_scope_candidates:
                    hosts = ", ".join(decision.off_scope_candidates)
                    print(f"[!] {target}: declined to add Supabase API host(s) "
                          f"[{hosts}] to scope; nothing to test.", file=sys.stderr)
                    report.halted_reason = (
                        f"API host(s) not approved for scanning: {hosts}"
                    )
                else:
                    report.halted_reason = "could not resolve a PostgREST API base"
                    print(f"[!] {target}: could not resolve an API base to test.")
                return finalize()
            api_base = decision.base
            if decision.fell_back_to_origin and args.verbose:
                print(f"  note: no Supabase URL found in bundle; testing target "
                      f"origin {api_base} as the API base.")
        report.api_base = api_base

        if args.verbose:
            print(f"[*] Enumerating tables against {api_base} ...")
        tables = discover_tables(
            client, api_base, key,
            extra_wordlist=args.wordlist, verbose=args.verbose,
        )

        if args.verbose:
            print(f"[*] Testing {len(tables)} table(s) (read-only)...")
        report.table_results = scan_tables(
            client, api_base, key, tables, verbose=args.verbose
        )

        # Optional bounded-LLM triage of the findings (metadata only, no network).
        if args.ai and report.vulnerable:
            _ai_triage(report, target, api_base, args)
    except ScopeError as exc:
        # Hard abort (e.g. off-scope redirect): fail closed, loudly.
        report.halted_reason = f"scope abort: {exc}"
        print(f"[scope] HARD ABORT on {target}: {exc}", file=sys.stderr)

    return finalize()


def _build_scope(args: argparse.Namespace) -> tuple[Scope, str] | None:
    """Build the Quick-Mode scope from the typed target.

    Returns ``(scope, normalized_target_url)``, or ``None`` on a usage error
    (caller maps that to exit code 2).
    """
    if not args.target:
        print("[!] Usage: rlscout <website>   (e.g. rlscout app.example.com)",
              file=sys.stderr)
        return None
    try:
        target = normalize_target(args.target)
        return Scope.from_target(target), target
    except ScopeError as exc:
        print(f"[scope] {exc}", file=sys.stderr)
        return None


def run(args: argparse.Namespace) -> int:
    built = _build_scope(args)
    if built is None:
        return 2
    scope, target = built

    _print_scope_banner(scope)

    limiter = RateLimiter(rate=args.rate, cap=args.max_requests)
    client = ScopedClient(
        scope=scope, limiter=limiter,
        verbose=args.verbose,
        user_agent=args.user_agent or DEFAULT_UA,
    )
    capped = False
    with client:
        try:
            report = _scan_target(client, scope, target, args, limiter)
        except RateLimitError as exc:
            # Global per-run cap: stop, keep what we have.
            print(f"[!] {exc}", file=sys.stderr)
            capped = True
            report = None

    if report is not None:
        _emit(report, args)
        if capped:
            print("[!] Run stopped early on the global request cap.", file=sys.stderr)
        return _exit_code(report)

    print("[!] Run stopped before producing a report.", file=sys.stderr)
    return 2


def _exit_code(report: ScanReport) -> int:
    if report.service_role_exposed:
        return 10  # critical
    if report.vulnerable:
        return 1  # findings present
    if report.halted_reason.startswith("scope abort"):
        return 2  # aborted on scope
    return 0


def _emit(report: ScanReport, args: argparse.Namespace) -> None:
    if args.out:
        md, js = write_reports(report, args.out)
        print(f"[+] Wrote {md}")
        print(f"[+] Wrote {js}")
    else:
        print()
        print(to_markdown(report))


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so the Markdown report (→, —, ✅, 🔴) prints on
    Windows' legacy cp1252 console without crashing. Report files are already
    written UTF-8 regardless."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    load_dotenv()  # pick up ANTHROPIC_API_KEY (and friends) from .env if present
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
