"""RLS classification: rows -> vulnerable, 401/403 -> protected, empty -> protected."""

from rlscout.recon import FoundKey
from rlscout.rls import check_table, STATUS_PROTECTED, STATUS_VULNERABLE, STATUS_UNKNOWN


class FakeResp:
    def __init__(self, status, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeClient:
    """Stand-in for ScopedClient that returns a queued response."""

    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def get(self, url, *, headers=None, params=None):
        self.calls.append((url, headers, params))
        return self._resp


KEY = FoundKey(token="eyJx.eyJy.z", role="anon", payload={"role": "anon"},
               source_url="https://x.com")
BASE = "https://proj.supabase.co"


def test_rows_returned_is_vulnerable():
    client = FakeClient(FakeResp(200, {"content-range": "0-0/17"}, body=[{"id": 1}]))
    res = check_table(client, BASE, KEY, "users")
    assert res.status == STATUS_VULNERABLE
    assert res.row_count == 17
    assert res.is_vulnerable


def test_count_zero_but_array_rows_still_vulnerable():
    # No count header, but a non-empty array came back -> still a read.
    client = FakeClient(FakeResp(200, {}, body=[{"id": 1}, {"id": 2}]))
    res = check_table(client, BASE, KEY, "profiles")
    assert res.status == STATUS_VULNERABLE
    assert res.row_count == 2


def test_empty_result_is_protected():
    client = FakeClient(FakeResp(200, {"content-range": "*/0"}, body=[]))
    res = check_table(client, BASE, KEY, "secrets")
    assert res.status == STATUS_PROTECTED
    assert res.row_count == 0


def test_401_is_protected():
    client = FakeClient(FakeResp(401, {}))
    res = check_table(client, BASE, KEY, "users")
    assert res.status == STATUS_PROTECTED


def test_403_is_protected():
    client = FakeClient(FakeResp(403, {}))
    res = check_table(client, BASE, KEY, "users")
    assert res.status == STATUS_PROTECTED


def test_404_is_unknown_not_finding():
    client = FakeClient(FakeResp(404, {}))
    res = check_table(client, BASE, KEY, "nonexistent")
    assert res.status == STATUS_UNKNOWN


def test_request_uses_read_only_get_with_limit():
    client = FakeClient(FakeResp(200, {"content-range": "0-0/5"}, body=[{"id": 1}]))
    check_table(client, BASE, KEY, "orders")
    url, headers, params = client.calls[0]
    assert url == f"{BASE}/rest/v1/orders"
    assert params["limit"] == "1"
    assert headers["apikey"] == KEY.token
