"""Phase A recon hardening: richer key/URL extraction + API-base resolution."""

import base64
import json

from rlscout.recon import (
    ApiBaseDecision,
    FoundKey,
    ReconResult,
    infer_api_base,
    run_recon,
)
from rlscout.scope import Scope


def make_jwt(role: str) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'role': role})}.sig"


ANON = make_jwt("anon")


class FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class FakeClient:
    """Returns a single page for any GET (depth-0 extraction tests)."""

    def __init__(self, text):
        self._text = text

    def get(self, url, *, headers=None, params=None):
        return FakeResp(self._text)


# --- extraction --------------------------------------------------------------

def test_create_client_pairs_url_and_key_custom_domain():
    page = f"const c = createClient('https://api.myapp.com', '{ANON}');"
    result = run_recon(FakeClient(page), "https://app.myapp.com/", crawl_depth=0)
    assert "https://api.myapp.com" in result.api_bases
    assert result.key_url_pairs[ANON] == "https://api.myapp.com"
    assert any(k.token == ANON and k.role == "anon" for k in result.keys)


def test_env_var_url_assignment_extracted():
    page = (
        f"window.__ENV={{NEXT_PUBLIC_SUPABASE_URL:'https://proj.supabase.co',"
        f"key:'{ANON}'}}"
    )
    result = run_recon(FakeClient(page), "https://app.example.com/", crawl_depth=0)
    assert "https://proj.supabase.co" in result.api_bases


def test_supabase_co_still_extracted():
    page = f"fetch('https://xyz.supabase.co/rest/v1/'); k='{ANON}'"
    result = run_recon(FakeClient(page), "https://app.example.com/", crawl_depth=0)
    assert "https://xyz.supabase.co" in result.api_bases


def test_fetched_texts_retained_for_fallback():
    page = "no key here"
    result = run_recon(FakeClient(page), "https://app.example.com/", crawl_depth=0)
    assert result.fetched_texts and result.fetched_texts[0][1] == page


# --- API-base resolution -----------------------------------------------------

def _anon_key():
    return FoundKey(token=ANON, role="anon", payload={"role": "anon"}, source_url="x")


def test_infer_prefers_key_paired_custom_domain():
    scope = Scope(authorized_hosts=["app.myapp.com", "api.myapp.com"])
    result = ReconResult(api_bases=["https://other.supabase.co", "https://api.myapp.com"],
                         key_url_pairs={ANON: "https://api.myapp.com"})
    decision = infer_api_base(result, "https://app.myapp.com/", scope, key=_anon_key())
    assert decision.base == "https://api.myapp.com"


def test_infer_reports_off_scope_host():
    # Discovered the API host, but it's not authorized — actionable, not silent.
    scope = Scope(authorized_hosts=["app.example.com"])
    result = ReconResult(api_bases=["https://proj.supabase.co"])
    decision = infer_api_base(result, "https://app.example.com/", scope)
    assert decision.base is None
    assert "proj.supabase.co" in decision.off_scope_candidates


def test_infer_falls_back_to_in_scope_origin():
    scope = Scope(authorized_hosts=["self.example.com"])
    result = ReconResult()  # nothing discovered
    decision = infer_api_base(result, "https://self.example.com/app", scope)
    assert decision.base == "https://self.example.com"
    assert decision.fell_back_to_origin is True


def test_infer_skips_off_scope_base_for_in_scope_one():
    scope = Scope(authorized_hosts=["api.myapp.com"])
    result = ReconResult(api_bases=["https://evil.supabase.co", "https://api.myapp.com"])
    decision = infer_api_base(result, "https://app.myapp.com/", scope)
    assert decision.base == "https://api.myapp.com"
    assert "evil.supabase.co" in decision.off_scope_candidates


# --- asset queue cap + tighter href regex (H2) ------------------------------

class _CountingClient:
    """Records every fetched URL so we can assert the recon queue is bounded."""

    def __init__(self, text_for):
        self._text_for = text_for
        self.fetched: list[str] = []

    def get(self, url, *, headers=None, params=None):
        self.fetched.append(url)
        return FakeResp(self._text_for(url))


def test_href_js_regex_does_not_swamp_on_adversarial_bundle():
    """A bundle that references thousands of `.js` strings must not blow past
    the per-target asset cap. Belt-and-suspenders alongside --max-requests."""
    from rlscout.recon import _MAX_RECON_ASSETS

    # 5000 module-id-shaped strings, plus one real script tag.
    bundle_refs = "".join(
        f'import("/chunk-{i}.js");' for i in range(5000)
    )
    landing = (
        '<script src="/main.js"></script>'
        f'<script>{bundle_refs}</script>'
    )

    def text_for(url):
        if url.endswith("/main.js"):
            return ""  # empty bundle, nothing more to find
        if url.startswith("https://app.example.com/chunk-"):
            return ""
        return landing

    client = _CountingClient(text_for)
    run_recon(client, "https://app.example.com/", crawl_depth=1)

    # 1 (target) + up to _MAX_RECON_ASSETS chunks + main.js. The cap must hold.
    assert len(client.fetched) <= _MAX_RECON_ASSETS + 2


def test_href_js_regex_ignores_bare_module_ids_in_template_strings():
    """Strings with whitespace or ${...} interpolation must NOT be queued."""
    page = (
        '<html><body><script>'
        'const x = "some text .js";'              # whitespace -> skip
        'const y = `prefix-${id}.js`;'            # template literal -> skip
        '<a href="./real-asset.js">go</a>'        # real -> keep
        '</script></body></html>'
    )
    fetched = []

    def text_for(url):
        fetched.append(url)
        return page if url.endswith("/") else ""

    run_recon(_CountingClient(text_for), "https://app.example.com/", crawl_depth=1)
    # Should have fetched the target page plus exactly the one real asset.
    assert "https://app.example.com/real-asset.js" in fetched
    assert not any("some text" in u for u in fetched)
    assert not any("${" in u for u in fetched)
