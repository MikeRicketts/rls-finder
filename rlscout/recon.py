"""Recon: fetch the target, find client-shipped Supabase keys, decode the role.

Looks at the target page plus its same-origin linked ``.js`` bundles and inline
config blobs — wherever a client-shipped key would plausibly live. Every fetch is
still scope-gated by `ScopedClient`. Crawl depth defaults to 1 (target page + its
same-origin assets); intentionally shallow.

Role branching (handled by the caller):
- ``anon``         -> proceed with read-only testing.
- ``service_role`` -> STOP. Using the key would be exploitation. The leak itself
  is the headline critical finding.
"""

from __future__ import annotations

import base64
import json
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .http import ScopedClient
from .scope import ScopeError

# A JWT: three base64url segments. Supabase anon/service keys are JWTs whose
# payload (2nd segment) also starts with the "eyJ" of a base64url-encoded "{".
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Supabase REST base URLs commonly shipped to the client (hosted *.supabase.*).
_SUPABASE_URL_RE = re.compile(r"https://[A-Za-z0-9-]+\.supabase\.(?:co|in|net)")

# Strongest signal: createClient("<url>", "<anon-key>") — pairs the API base with
# its key, and works for CUSTOM domains (not just *.supabase.co).
_CREATE_CLIENT_RE = re.compile(
    r"""createClient\(\s*["'](https?://[^"']+?)["']\s*,\s*"""
    r"""["'](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']""",
    re.IGNORECASE,
)
# Inlined env-var / config assignments: supabaseUrl, VITE_/NEXT_PUBLIC_/REACT_APP_.
_URL_ASSIGN_RE = re.compile(
    r"""(?:supabase[_-]?url|VITE_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|"""
    r"""REACT_APP_SUPABASE_URL)["']?\s*[:=]\s*["'](https?://[^"']+?)["']""",
    re.IGNORECASE,
)

# Same-origin script/asset references to crawl at depth >= 1.
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
# Restrict the JS-href regex to URL-shaped strings (http(s)://, /, ./, ../).
# A bare ".js" inside a docstring or bundler module-id can otherwise balloon
# the asset queue with false positives like `import("./helpers.js")` that
# aren't useful crawl targets. Also forbid whitespace and `${…}` interpolation.
_HREF_JS_RE = re.compile(
    r"""["']((?:https?://|/|\./|\.\./)[^\s"'`${}]+?\.js(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)

# Cap how much fetched text we retain for the optional LLM recon fallback, to
# bound memory and token cost. (Per-document and total byte caps.)
_MAX_TEXT_PER_DOC = 60_000
_MAX_TEXT_DOCS = 6

# A hard ceiling on how many same-origin assets recon will enqueue per target.
# Belt-and-suspenders alongside the global --max-requests cap: an adversarial
# bundle with thousands of `.js` references cannot drain the whole budget
# before the actual API scan even runs.
_MAX_RECON_ASSETS = 50


@dataclass
class FoundKey:
    """A JWT discovered in client-shipped content, with its decoded role."""

    token: str
    role: str
    payload: dict
    source_url: str

    @property
    def is_service_role(self) -> bool:
        return self.role == "service_role"

    @property
    def short(self) -> str:
        return f"{self.token[:12]}...{self.token[-6:]}"


@dataclass
class ReconResult:
    keys: list[FoundKey] = field(default_factory=list)
    api_bases: list[str] = field(default_factory=list)  # confidence-ordered
    fetched_urls: list[str] = field(default_factory=list)
    # token -> API base discovered paired with that key (createClient signal).
    key_url_pairs: dict[str, str] = field(default_factory=dict)
    # (url, text) snippets retained for the optional LLM recon fallback only.
    fetched_texts: list[tuple[str, str]] = field(default_factory=list)

    @property
    def anon_keys(self) -> list[FoundKey]:
        return [k for k in self.keys if k.role == "anon"]

    @property
    def service_role_keys(self) -> list[FoundKey]:
        return [k for k in self.keys if k.is_service_role]


@dataclass
class ApiBaseDecision:
    """The resolved PostgREST base, plus context for clear operator messaging."""

    base: str | None
    off_scope_candidates: list[str] = field(default_factory=list)
    fell_back_to_origin: bool = False


def _b64url_decode(segment: str) -> bytes:
    # Supabase JWT segments arrive without "=" padding; restore it to the
    # nearest multiple of 4 before handing to the base64 decoder.
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt_payload(token: str) -> dict | None:
    """Decode a JWT's payload segment to a dict, or ``None`` if it isn't valid."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlsplit(base), urlsplit(urljoin(base, candidate))
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


def _extract_keys(text: str, source_url: str) -> list[FoundKey]:
    found: list[FoundKey] = []
    seen: set[str] = set()
    for token in _JWT_RE.findall(text):
        if token in seen:
            continue
        seen.add(token)
        payload = decode_jwt_payload(token)
        if payload is None:
            continue
        role = str(payload.get("role", "")) or "unknown"
        found.append(FoundKey(token=token, role=role, payload=payload, source_url=source_url))
    return found


def _strip_base(url: str) -> str:
    """Trailing-slash-normalize a discovered API base URL."""
    return url.strip().rstrip("/")


def _ordered_insert(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def run_recon(
    client: ScopedClient,
    target_url: str,
    *,
    crawl_depth: int = 1,
    verbose: bool = False,
) -> ReconResult:
    """Fetch the target (and, at depth>=1, its same-origin JS) and harvest keys."""
    result = ReconResult()
    queue: deque[tuple[str, int]] = deque([(target_url, 0)])
    visited: set[str] = set()
    enqueued_assets = 0

    while queue:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        # Scope is enforced inside client.get; an off-scope asset aborts the run.
        resp = client.get(url)
        if resp is None or resp.status_code >= 400:
            continue
        text = resp.text
        result.fetched_urls.append(url)
        if len(result.fetched_texts) < _MAX_TEXT_DOCS:
            result.fetched_texts.append((url, text[:_MAX_TEXT_PER_DOC]))

        result.keys.extend(_extract_keys(text, url))

        # API base discovery, ordered by confidence:
        #   1) createClient(url, key) pairs  2) env-var assignments  3) *.supabase.*
        for base, key in _CREATE_CLIENT_RE.findall(text):
            b = _strip_base(base)
            _ordered_insert(result.api_bases, b)
            result.key_url_pairs.setdefault(key, b)
        for base in _URL_ASSIGN_RE.findall(text):
            _ordered_insert(result.api_bases, _strip_base(base))
        for base in _SUPABASE_URL_RE.findall(text):
            _ordered_insert(result.api_bases, _strip_base(base))

        if depth < crawl_depth:
            assets = set(_SCRIPT_SRC_RE.findall(text)) | set(_HREF_JS_RE.findall(text))
            for asset in assets:
                if enqueued_assets >= _MAX_RECON_ASSETS:
                    if verbose:
                        print(f"  recon: asset queue capped at "
                              f"{_MAX_RECON_ASSETS}; remaining hrefs ignored")
                    break
                absolute = urljoin(url, asset)
                if not _same_origin(url, absolute):
                    continue  # depth-1 stays same-origin by design
                queue.append((absolute, depth + 1))
                enqueued_assets += 1

    # De-duplicate keys across all sources, keeping first sighting.
    deduped: dict[str, FoundKey] = {}
    for k in result.keys:
        deduped.setdefault(k.token, k)
    result.keys = list(deduped.values())

    if verbose:
        print(
            f"  recon: fetched {len(result.fetched_urls)} url(s), "
            f"found {len(result.keys)} key(s), "
            f"{len(result.api_bases)} api base(s)"
        )
    return result


def infer_api_base(
    result: ReconResult,
    target_url: str,
    scope,
    *,
    key: FoundKey | None = None,
) -> ApiBaseDecision:
    """Resolve the PostgREST base URL to test against.

    Preference order:
      1. The base discovered *paired with the chosen key* (createClient signal) —
         handles custom domains, not just ``*.supabase.co``.
      2. The first in-scope discovered base (confidence-ordered).
      3. The target's own origin (it may itself be a self-hosted PostgREST).

    Discovered bases that are OUT of scope are reported separately in
    ``off_scope_candidates`` so the caller can prompt the operator inline
    (``scope.allow(host)`` + re-call this function) — never a silent fallback
    that 404s.
    """
    off_scope: list[str] = []

    # 1. Key-paired base first.
    ordered: list[str] = []
    if key is not None and key.token in result.key_url_pairs:
        _ordered_insert(ordered, result.key_url_pairs[key.token])
    for b in result.api_bases:
        _ordered_insert(ordered, b)

    for base in ordered:
        try:
            authorized = scope.is_authorized(base)
        except ScopeError:
            authorized = False
        if authorized:
            return ApiBaseDecision(base=_strip_base(base), off_scope_candidates=off_scope)
        _ordered_insert(off_scope, _host_only(base))

    # We discovered a Supabase API host but it's out of scope: report it (so the
    # operator can authorize it) rather than silently testing the app origin,
    # which we know is NOT the API and would just 404.
    if off_scope:
        return ApiBaseDecision(base=None, off_scope_candidates=off_scope)

    # 3. Nothing discovered — fall back to the target origin if it's in scope
    #    (it may itself be a self-hosted PostgREST).
    parts = urlsplit(target_url)
    if parts.scheme and parts.netloc:
        origin = f"{parts.scheme}://{parts.netloc}"
        if scope.is_authorized(origin):
            return ApiBaseDecision(base=origin, fell_back_to_origin=True)
    return ApiBaseDecision(base=None)


def _host_only(url: str) -> str:
    parts = urlsplit(url if "//" in url else "//" + url)
    host = parts.hostname or url
    return f"{host}:{parts.port}" if parts.port else host
