"""Run RLScout against a local Supabase stack and assert known RLS verdicts.

Prereqs:
    1. Install the Supabase CLI and Docker.
    2. From the repo root:  supabase init   (keeps the existing migration)
    3.                      supabase start   (boots the stack, applies migrations)

Then:
    uv run python scripts/check_local_supabase.py

The script discovers the local API URL + anon key from `supabase status` (or the
RLSCOUT_TEST_URL / RLSCOUT_TEST_ANON_KEY env vars), drives RLScout's real
enumeration + read-only checks against the live Supabase PostgREST, and asserts
each table's verdict matches the ground truth in
supabase/migrations/0001_rls_states.sql.

Exit code 0 = all verdicts matched; 1 = a mismatch or setup failure.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from urllib.parse import urlsplit

from rlscout.enumerate import discover_tables
from rlscout.http import ScopedClient
from rlscout.ratelimit import RateLimiter
from rlscout.recon import FoundKey, decode_jwt_payload
from rlscout.rls import scan_tables
from rlscout.scope import Scope

# Ground truth — keep in sync with supabase/migrations/0001_rls_states.sql.
EXPECTED = {
    "public_notes": "vulnerable",
    "leaky_profiles": "vulnerable",
    "private_secrets": "protected",
    "owner_only": "protected",
}


def _from_supabase_status() -> tuple[str, str] | None:
    """Parse `supabase status -o env` for the API URL and anon key."""
    try:
        out = subprocess.run(
            ["supabase", "status", "-o", "env"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    url = key = None
    for line in out.splitlines():
        k, _, v = line.partition("=")
        v = v.strip().strip('"')
        if k.strip() == "API_URL":
            url = v
        elif k.strip() == "ANON_KEY":
            key = v
    if url and key:
        return url, key
    return None


def resolve_target() -> tuple[str, str]:
    url = os.environ.get("RLSCOUT_TEST_URL")
    key = os.environ.get("RLSCOUT_TEST_ANON_KEY")
    if url and key:
        return url, key
    found = _from_supabase_status()
    if found:
        return found
    raise SystemExit(
        "Could not find the local Supabase URL/anon key.\n"
        "Start it with `supabase start`, or set RLSCOUT_TEST_URL and "
        "RLSCOUT_TEST_ANON_KEY."
    )


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Drive RLScout against a local Supabase stack and assert "
                    "verdicts against the ground truth in migrations.",
    )
    parser.parse_args(argv)  # no flags yet; argparse handles --help/-h

    api_base, anon_key = resolve_target()
    host = urlsplit(api_base).hostname or "127.0.0.1"

    # Same philosophy as the main CLI: running the script with a deliberately
    # local target is the operator's affirmation. The structural scope gate at
    # ScopedClient still enforces it.
    print(f"[supabase-itest] target {api_base} (host {host})")

    payload = decode_jwt_payload(anon_key)
    if payload is None or payload.get("role") != "anon":
        raise SystemExit("resolved key is not a valid anon JWT")
    key = FoundKey(token=anon_key, role="anon", payload=payload, source_url=api_base)

    # Scope authorizes only the local Supabase host.
    scope = Scope(authorized_hosts=[host], notes="local supabase integration test")
    limiter = RateLimiter(rate=0, cap=2000)  # local; no throttle, generous cap

    with ScopedClient(scope=scope, limiter=limiter) as client:
        tables = discover_tables(client, api_base, key)
        # Make sure our four ground-truth tables were actually discovered.
        for t in EXPECTED:
            if t not in tables:
                tables.append(t)
        results = scan_tables(client, api_base, key, tables)

    verdicts = {r.table: r.status for r in results}
    print("\n[supabase-itest] verdict vs. ground truth:")
    ok = True
    for table, expected in EXPECTED.items():
        actual = verdicts.get(table, "<<missing>>")
        match = actual == expected
        ok = ok and match
        mark = "PASS" if match else "FAIL"
        print(f"  [{mark}] {table:<16} expected={expected:<10} actual={actual}")

    if ok:
        print("\n[supabase-itest] ✅ ALL VERDICTS MATCH — works against real Supabase.")
        return 0
    print("\n[supabase-itest] ❌ MISMATCH — see above.")
    return 1


if __name__ == "__main__":
    # UTF-8 stdout so the ✅/❌ summary prints on Windows' cp1252 console.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    raise SystemExit(run())
