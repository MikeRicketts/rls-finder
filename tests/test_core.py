"""Core invariants: read-only methods, rate cap, JWT role decode, count parsing."""

import base64
import json

import pytest

from rlscout.http import ALLOWED_METHODS, ScopedClient
from rlscout.ratelimit import RateLimiter, RateLimitError
from rlscout.recon import decode_jwt_payload, _extract_keys
from rlscout.rls import _parse_count, STATUS_VULNERABLE, STATUS_PROTECTED
from rlscout.scope import Scope, ScopeError


def make_scope(hosts):
    return Scope(authorized_hosts=hosts)


def make_jwt(role: str) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'role': role})}.sig"


# --- read-only enforcement ---------------------------------------------------

def test_only_read_methods_allowed():
    # v1 only needs GET. Widening this is a deliberate Phase-2 change.
    assert ALLOWED_METHODS == frozenset({"GET"})


def test_client_rejects_write_methods():
    s = make_scope(["x.com"])
    client = ScopedClient(scope=s, limiter=RateLimiter())
    client._client = object()  # not used; rejection happens before any send
    # HEAD is included to pin that v1 narrowed the surface to GET only.
    for method in ("HEAD", "POST", "PATCH", "PUT", "DELETE"):
        with pytest.raises(ScopeError):
            client._request(method, "https://x.com", headers=None, params=None)


# --- rate limiter cap --------------------------------------------------------

def test_rate_limiter_cap_enforced():
    rl = RateLimiter(rate=0, cap=3)  # no throttle, hard cap of 3
    rl.acquire()
    rl.acquire()
    rl.acquire()
    with pytest.raises(RateLimitError):
        rl.acquire()
    assert rl.count == 3


def test_rate_limiter_default_is_capped():
    rl = RateLimiter()
    assert rl.cap > 0  # global cap on by default


# --- JWT role decode ---------------------------------------------------------

def test_decode_anon_jwt():
    payload = decode_jwt_payload(make_jwt("anon"))
    assert payload is not None and payload["role"] == "anon"


def test_decode_service_role_jwt():
    payload = decode_jwt_payload(make_jwt("service_role"))
    assert payload["role"] == "service_role"


def test_extract_keys_branches_on_role():
    text = f"const k='{make_jwt('anon')}'; const s='{make_jwt('service_role')}';"
    keys = _extract_keys(text, "https://x.com/app.js")
    roles = {k.role for k in keys}
    assert roles == {"anon", "service_role"}
    assert any(k.is_service_role for k in keys)


def test_decode_rejects_non_jwt():
    assert decode_jwt_payload("not.a.jwt") is None
    assert decode_jwt_payload("eyJ.eyJ") is None  # only 2 segments


# --- count parsing -----------------------------------------------------------

class FakeResp:
    def __init__(self, headers):
        self.headers = headers


def test_parse_count_from_content_range():
    assert _parse_count(FakeResp({"content-range": "0-0/42"})) == 42
    assert _parse_count(FakeResp({"Content-Range": "0-24/100"})) == 100


def test_parse_count_unknown():
    assert _parse_count(FakeResp({})) is None
    assert _parse_count(FakeResp({"content-range": "*/*"})) is None
    assert _parse_count(FakeResp({"content-range": "0-0/*"})) is None
