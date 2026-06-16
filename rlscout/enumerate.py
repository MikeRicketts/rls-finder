"""Table discovery: PostgREST OpenAPI spec UNION a built-in/operator wordlist.

Primary source is the OpenAPI spec at ``/rest/v1/`` (authoritative when exposed).
The built-in wordlist is always merged in; ``--wordlist`` extends (never replaces)
the default.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from .http import ScopedClient
from .recon import FoundKey


def _supabase_headers(key: FoundKey, *, accept: str = "application/json") -> dict[str, str]:
    """The anon apikey/Authorization headers PostgREST expects."""
    return {
        "apikey": key.token,
        "Authorization": f"Bearer {key.token}",
        "Accept": accept,
    }


def load_default_wordlist() -> list[str]:
    """Load the packaged default table-name wordlist."""
    try:
        text = resources.files("rlscout.wordlists").joinpath("default.txt").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, ModuleNotFoundError):
        return []
    return _parse_wordlist(text)


def load_wordlist_file(path: str | Path) -> list[str]:
    """Load an operator-supplied wordlist file (extends the default)."""
    return _parse_wordlist(Path(path).read_text(encoding="utf-8"))


def _parse_wordlist(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def tables_from_openapi(
    client: ScopedClient, api_base: str, key: FoundKey, *, verbose: bool = False
) -> list[str]:
    """Fetch the PostgREST OpenAPI spec and return the table names it declares."""
    url = api_base.rstrip("/") + "/rest/v1/"
    # PostgREST advertises the spec as application/openapi+json; ask for that
    # explicitly and fall back to application/json so older proxies still answer.
    headers = _supabase_headers(
        key, accept="application/openapi+json, application/json"
    )
    resp = client.get(url, headers=headers)
    if resp is None or resp.status_code >= 400:
        if verbose:
            code = resp.status_code if resp else "ERR"
            print(f"  enumerate: OpenAPI spec not available ({code})")
        return []
    try:
        spec = resp.json()
    except ValueError:
        return []

    names: set[str] = set()
    # PostgREST (Swagger 2.0) lists tables under "definitions" and as "/table" paths.
    for name in (spec.get("definitions") or {}):
        names.add(name)
    for path in (spec.get("paths") or {}):
        p = path.strip("/")
        # Top-level table endpoint: no nested segments, and not the PostgREST
        # RPC namespace endpoint itself (which is exactly "/rpc" -> "rpc").
        # Real tables named "rpc_jobs", "rpcs", etc. must NOT be dropped here.
        if p and "/" not in p and p != "rpc":
            names.add(p)
    if verbose:
        print(f"  enumerate: OpenAPI spec yielded {len(names)} table(s)")
    return sorted(names)


def discover_tables(
    client: ScopedClient,
    api_base: str,
    key: FoundKey,
    *,
    extra_wordlist: str | Path | None = None,
    verbose: bool = False,
) -> list[str]:
    """Merge OpenAPI-declared tables with the default (+ optional extra) wordlist."""
    names: set[str] = set()
    names.update(tables_from_openapi(client, api_base, key, verbose=verbose))
    names.update(load_default_wordlist())
    if extra_wordlist:
        names.update(load_wordlist_file(extra_wordlist))
    return sorted(names)
