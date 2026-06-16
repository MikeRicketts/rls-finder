"""The one network primitive every other module uses.

`ScopedClient` is the chokepoint where the two hard invariants are enforced:

1. **In scope only.** Every request's target host is checked against the loaded
   `Scope` *before the request leaves the process*. A non-match is a hard abort.
2. **Read-only.** The client only exposes ``get``; ``ALLOWED_METHODS = {"GET"}``.
   There is no code path here that issues HEAD/POST/PATCH/PUT/DELETE against a
   target. If/when Phase 2 (CLAUDE.md §7b — OPTIONS-style write-side detection)
   lands, it will widen this set deliberately and add tests around the new
   method; until then the surface stays as small as possible.

Redirects are followed manually so each hop's `Location` can be re-checked against
scope — an off-scope 30x is not followed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

try:
    import httpx
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "httpx is required. Install dependencies with: pip install -e ."
    ) from exc

from .ratelimit import RateLimiter
from .scope import Scope, ScopeError

# A browser-like User-Agent by default: many WAFs/CDNs challenge or block
# non-browser agents, which would otherwise show up as false "protected" results.
# Override with --user-agent (e.g. an identifiable bug-bounty UA) when a program
# asks for attributable traffic.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
MAX_REDIRECTS = 5
MAX_429_RETRIES = 3  # honor Retry-After up to this many times per request

# Methods the tool is permitted to send. Deliberately read-only AND deliberately
# minimal: v1 only ever needs GET, so widening this set must be an obvious,
# reviewable edit (Phase 2 / CLAUDE.md §7b).
ALLOWED_METHODS = frozenset({"GET"})


def _retry_after_seconds(resp: "httpx.Response", *, default: float) -> float:
    """Parse a numeric Retry-After header; fall back to ``default`` (capped)."""
    raw = resp.headers.get("retry-after")
    if raw:
        try:
            return min(float(raw), 60.0)
        except ValueError:
            pass  # HTTP-date form: ignore, use default backoff
    return default


@dataclass
class LoggedExchange:
    """One request/response pair, captured as metadata only (never body content)."""

    method: str
    url: str
    status: int
    reason: str = ""
    note: str = ""


@dataclass
class ScopedClient:
    """Scope-enforcing, rate-limited, read-only HTTP client."""

    scope: Scope
    limiter: RateLimiter
    timeout: float = 15.0
    user_agent: str = DEFAULT_UA
    verbose: bool = False
    log: list[LoggedExchange] = field(default_factory=list)
    _client: "httpx.Client | None" = None

    def __enter__(self) -> "ScopedClient":
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,  # we follow manually to re-check scope
            headers={"User-Agent": self.user_agent, **DEFAULT_HEADERS},
        )
        return self

    def __exit__(self, *exc: object) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> "httpx.Response | None":
        """Scope-checked, rate-limited GET that follows redirects safely.

        Returns the final response, or ``None`` on a network error. Raises
        ``ScopeError`` (fatal) if the target — or any redirect hop — is off-scope.
        """
        return self._request("GET", url, headers=headers, params=params)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        params: dict[str, str] | None,
    ) -> "httpx.Response | None":
        if method not in ALLOWED_METHODS:
            # Defense in depth: this client is read-only by construction.
            raise ScopeError(f"refusing non-read-only method: {method}")
        assert self._client is not None, "ScopedClient must be used as a context manager"

        current = url
        redirects = 0
        throttled = 0
        # Two independent budgets: a redirect cap (how many hops we'll follow)
        # and a 429-retry cap (per request, not per redirect chain). Conflating
        # them — as a single `range(MAX_REDIRECTS + MAX_429_RETRIES + 2)` did —
        # made the "too many redirects" path trip early on a request that
        # legitimately back-offs once on a 429.
        while True:
            # Invariant #1: enforced BEFORE the request is built.
            self.scope.enforce(current)
            self.limiter.acquire()
            try:
                resp = self._client.request(
                    method, current, headers=headers, params=params
                )
            except httpx.HTTPError as exc:
                self.log.append(
                    LoggedExchange(method, current, 0, note=f"network error: {exc}")
                )
                if self.verbose:
                    print(f"  [!] {method} {current} -> network error: {exc}")
                return None

            self.log.append(
                LoggedExchange(method, current, resp.status_code, resp.reason_phrase)
            )
            if self.verbose:
                print(f"  [>] {method} {current} -> {resp.status_code}")

            # 429: back off (honoring Retry-After) and retry, so a transient rate
            # limit isn't misread as "protected". Capped per request.
            if resp.status_code == 429 and throttled < MAX_429_RETRIES:
                throttled += 1
                wait = _retry_after_seconds(resp, default=min(2 ** throttled, 30))
                if self.verbose:
                    print(f"  [~] 429 from {current}; backing off {wait:.1f}s "
                          f"(retry {throttled}/{MAX_429_RETRIES})")
                time.sleep(wait)
                continue

            if resp.is_redirect and "location" in resp.headers:
                if redirects >= MAX_REDIRECTS:
                    raise ScopeError(f"too many redirects following {url}")
                redirects += 1
                nxt = urljoin(current, resp.headers["location"])
                # Re-check scope on the redirect target; off-scope = not followed.
                self.scope.enforce(nxt)
                current = nxt
                params = None  # redirect target carries its own query
                continue
            return resp
