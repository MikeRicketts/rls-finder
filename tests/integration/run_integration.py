"""End-to-end integration test for RLScout against REAL PostgREST.

Stands up Postgres + PostgREST + an nginx gateway (docker-compose.yml), seeded
with tables in known RLS states (seed.sql), then runs the actual `rlscout` CLI
against it and asserts the verdict for each table matches ground truth.

This is the test that answers "does it work against the real software?" — it
exercises the real OpenAPI spec, real Content-Range counts, and real RLS
behaviour (default-deny empty vs. leak), all on localhost (in scope, authorized).

Run it (Docker Desktop must be running):

    uv run python tests/integration/run_integration.py

Exit code 0 = all verdicts matched; 1 = a mismatch or setup failure.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx
import yaml

from rlscout.cli import main as rlscout_main

HERE = Path(__file__).parent
COMPOSE_FILE = HERE / "docker-compose.yml"
COMPOSE = ["docker", "compose", "-f", str(COMPOSE_FILE)]
GATEWAY = "http://localhost:8088"


def jwt_secret_from_compose() -> str:
    """Read PGRST_JWT_SECRET straight from the compose file (single source of
    truth — the minted anon JWT must be signed with exactly this secret)."""
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    return data["services"]["postgrest"]["environment"]["PGRST_JWT_SECRET"]

# Ground truth — keep in sync with seed.sql.
EXPECTED = {
    "public_notes": "vulnerable",     # RLS disabled
    "leaky_profiles": "vulnerable",   # RLS on, USING(true)
    "private_secrets": "protected",   # RLS on, no policy (default-deny)
    "owner_only": "protected",        # RLS on, owner-only policy
}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint_anon_jwt(secret: str) -> str:
    """Mint an HS256 anon JWT PostgREST will accept (role=anon claim)."""
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64u(json.dumps(
        {"role": "anon", "iss": "rlscout-itest", "exp": 9999999999},
        separators=(",", ":"),
    ).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64u(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def write_landing_page(anon_jwt: str) -> None:
    """Write the page the gateway serves at /, shipping the anon key like a SPA."""
    (HERE / "www").mkdir(exist_ok=True)
    html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>itest app</title>"
        f"<script>window.__SUPABASE__={{anonKey:'{anon_jwt}'}};</script>"
        "</head><body>RLScout integration target</body></html>"
    )
    (HERE / "www" / "index.html").write_text(html, encoding="utf-8")


def wait_for_backend(timeout: float = 120.0) -> None:
    """Poll the gateway until PostgREST's OpenAPI spec is served (200)."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{GATEWAY}/rest/v1/", timeout=3.0)
            if r.status_code == 200:
                return
            last = f"status {r.status_code}"
        except httpx.HTTPError as exc:
            last = str(exc)
        time.sleep(2.0)
    raise SystemExit(f"backend never became ready ({last})")


def run() -> int:
    anon_jwt = mint_anon_jwt(jwt_secret_from_compose())
    write_landing_page(anon_jwt)

    out_prefix = HERE / "_itest_report"

    print("[itest] bringing up Postgres + PostgREST + gateway ...")
    subprocess.run(COMPOSE + ["up", "-d"], check=True)
    try:
        wait_for_backend()
        print("[itest] backend ready; running rlscout ...")
        # Quick Mode: the target's host (localhost) is the implicit allowlist, and
        # the --api-base host is the same, so no scope file is needed. --yes keeps
        # it non-interactive in case recon surfaces another host.
        code = rlscout_main([
            f"{GATEWAY}/",
            "--api-base", GATEWAY,
            "--yes",
            "-o", str(out_prefix),
        ])
        print(f"[itest] rlscout exit code: {code}")

        report = json.loads((out_prefix.with_suffix(".json")).read_text(encoding="utf-8"))
        verdicts = {f["table"]: f["status"] for f in report["findings"]}

        print("\n[itest] verdict vs. ground truth:")
        ok = True
        for table, expected in EXPECTED.items():
            actual = verdicts.get(table, "<<missing>>")
            match = actual == expected
            ok = ok and match
            mark = "PASS" if match else "FAIL"
            print(f"  [{mark}] {table:<16} expected={expected:<10} actual={actual}")

        if ok:
            print("\n[itest] ✅ ALL VERDICTS MATCH — RLScout works against real PostgREST.")
            return 0
        print("\n[itest] ❌ MISMATCH — see above.")
        return 1
    finally:
        print("[itest] tearing down ...")
        subprocess.run(COMPOSE + ["down", "-v"], check=False)
        for p in (out_prefix.with_suffix(".md"), out_prefix.with_suffix(".json")):
            p.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(run())
