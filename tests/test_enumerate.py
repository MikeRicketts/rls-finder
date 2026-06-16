"""Table enumeration: OpenAPI spec parsing must not over-reject real tables.

The historical bug this test pins down: ``not p.startswith("rpc")`` dropped
any table whose name happened to begin with the three letters ``rpc`` —
including real schemas like ``rpc_jobs``, ``rpcs``, ``rpc_log``. The
``/rpc/<fn>`` namespace endpoint is what we actually want to skip; that's
already excluded by the no-nested-slash check.
"""

import json

from rlscout.enumerate import tables_from_openapi
from rlscout.recon import FoundKey


class FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def json(self):
        return json.loads(self.text)


class FakeClient:
    def __init__(self, spec_dict):
        self._text = json.dumps(spec_dict)
        self.calls = []

    def get(self, url, *, headers=None, params=None):
        self.calls.append((url, headers))
        return FakeResp(self._text)


KEY = FoundKey(token="eyJa.eyJb.c", role="anon", payload={"role": "anon"},
               source_url="https://x.com")


def test_real_table_named_rpc_jobs_kept():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/users": {},
            "/rpc_jobs": {},   # real table, not the rpc namespace
            "/rpcs": {},
            "/rpc/whoami": {}, # this IS the PostgREST rpc namespace
        },
        "definitions": {},
    }
    tables = tables_from_openapi(FakeClient(spec), "https://api.example.com", KEY)
    assert "rpc_jobs" in tables, "real table 'rpc_jobs' must not be dropped"
    assert "rpcs" in tables
    assert "users" in tables


def test_rpc_namespace_endpoint_dropped():
    # Plain ``/rpc`` (the namespace itself) and any nested ``/rpc/<fn>`` paths
    # are not tables and must not be enumerated as such.
    spec = {
        "swagger": "2.0",
        "paths": {"/rpc": {}, "/rpc/echo": {}, "/users": {}},
        "definitions": {},
    }
    tables = tables_from_openapi(FakeClient(spec), "https://api.example.com", KEY)
    assert "rpc" not in tables
    assert "rpc/echo" not in tables
    assert tables == ["users"]


def test_openapi_accept_header_is_advertised():
    spec = {"swagger": "2.0", "paths": {}, "definitions": {}}
    client = FakeClient(spec)
    tables_from_openapi(client, "https://api.example.com", KEY)
    url, headers = client.calls[0]
    # PostgREST serves the spec as application/openapi+json. We must ask for
    # it explicitly (with JSON as the documented fallback).
    assert "openapi+json" in headers["Accept"]


def test_definitions_are_also_extracted():
    spec = {
        "swagger": "2.0",
        "paths": {},
        "definitions": {"profiles": {}, "rpc_audit": {}},
    }
    tables = tables_from_openapi(FakeClient(spec), "https://api.example.com", KEY)
    assert tables == ["profiles", "rpc_audit"]
