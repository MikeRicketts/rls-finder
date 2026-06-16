"""ScopedClient redirect handling: an off-scope 30x is NOT followed (fail closed).

Also pins the split redirect / 429-retry counters and the --user-agent override.
"""

import httpx
import pytest

from rlscout.http import ScopedClient
from rlscout.ratelimit import RateLimiter
from rlscout.scope import Scope, ScopeError


def make_client(scope, handler, **kw):
    """Build a ScopedClient whose underlying httpx.Client uses a mock transport.

    Note: we set ``_client`` directly rather than entering the context manager,
    since ``__enter__`` would replace it with a real (non-mock) client.
    """
    client = ScopedClient(scope=scope, limiter=RateLimiter(rate=0, cap=100), **kw)
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    return client


def test_in_scope_redirect_is_followed():
    scope = Scope(authorized_hosts=["a.example.com", "b.example.com"])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "a.example.com":
            return httpx.Response(302, headers={"location": "https://b.example.com/x"})
        return httpx.Response(200, text="landed")

    client = make_client(scope, handler)
    try:
        resp = client.get("https://a.example.com/start")
        assert resp is not None and resp.status_code == 200
        assert resp.text == "landed"
    finally:
        client._client.close()


def test_off_scope_redirect_is_a_hard_abort():
    scope = Scope(authorized_hosts=["a.example.com"])  # attacker.com NOT in scope

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://attacker.com/evil"})

    client = make_client(scope, handler)
    try:
        with pytest.raises(ScopeError):
            client.get("https://a.example.com/start")
    finally:
        client._client.close()


def test_initial_off_scope_target_aborts_before_request():
    scope = Scope(authorized_hosts=["a.example.com"])
    hit = {"called": False}

    def handler(request: httpx.Request) -> httpx.Response:
        hit["called"] = True
        return httpx.Response(200)

    client = make_client(scope, handler)
    try:
        with pytest.raises(ScopeError):
            client.get("https://attacker.com/")
        assert hit["called"] is False  # never reached the transport
    finally:
        client._client.close()


# --- redirect / 429 counters are independent (B2) ---------------------------

def test_redirect_then_429_does_not_misclassify():
    """One 429 hop followed by a small redirect chain must succeed.

    Before B2 the two budgets shared one loop counter; depending on the
    ordering this either ate into the redirect budget or vice versa.
    """
    scope = Scope(authorized_hosts=["a.example.com"])
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        n = len(seen)
        seen.append(request.url.path)
        if n == 0:
            # First hop: 429 with a tiny Retry-After so the test is fast.
            return httpx.Response(429, headers={"retry-after": "0"})
        if n < 4:
            return httpx.Response(302, headers={"location": f"/hop{n}"})
        return httpx.Response(200, text="ok")

    client = make_client(scope, handler)
    try:
        resp = client.get("https://a.example.com/start")
        assert resp is not None and resp.status_code == 200
        assert resp.text == "ok"
    finally:
        client._client.close()


def test_max_redirects_raises():
    """A redirect chain longer than MAX_REDIRECTS must hard-abort, not loop forever."""
    scope = Scope(authorized_hosts=["a.example.com"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/again"})

    client = make_client(scope, handler)
    try:
        with pytest.raises(ScopeError, match="too many redirects"):
            client.get("https://a.example.com/")
    finally:
        client._client.close()


# --- --user-agent plumbing (S2) ---------------------------------------------

def test_user_agent_override():
    """The CLI --user-agent flag must actually change the outgoing UA header."""
    scope = Scope(authorized_hosts=["a.example.com"])
    seen_uas: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_uas.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, text="ok")

    # The override has to be applied when the underlying httpx.Client is built,
    # so use the real context manager (with a transport swapped in) to mirror
    # what cli.py actually does.
    client = ScopedClient(
        scope=scope,
        limiter=RateLimiter(rate=0, cap=10),
        user_agent="rlscout-test/9.9",
    )
    with client:
        # Reach in just to replace the transport on the freshly-built httpx
        # client, while keeping the User-Agent header it was configured with.
        client._client._transport = httpx.MockTransport(handler)
        resp = client.get("https://a.example.com/x")
    assert resp is not None and resp.status_code == 200
    assert seen_uas == ["rlscout-test/9.9"]


def test_default_user_agent_is_browser_like():
    """Default UA must look like a real browser (WAFs/CDNs otherwise return
    canned 'protected' responses and corrupt the RLS verdict)."""
    scope = Scope(authorized_hosts=["a.example.com"])
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, text="ok")

    client = ScopedClient(scope=scope, limiter=RateLimiter(rate=0, cap=10))
    with client:
        client._client._transport = httpx.MockTransport(handler)
        client.get("https://a.example.com/")
    assert seen and "Mozilla/" in seen[0]
