"""Scope matcher must fail closed against tricky near-matches (AGENTS.md §10)."""

import pytest

from rlscout.scope import Scope, ScopeError, normalize_target


def make_scope(hosts, notes="test"):
    return Scope(authorized_hosts=[h.lower() for h in hosts], notes=notes)


# --- exact matches -----------------------------------------------------------

def test_exact_host_matches():
    s = make_scope(["app.example-ctf.com"])
    assert s.is_authorized("https://app.example-ctf.com/path")
    assert s.is_authorized("app.example-ctf.com")
    assert s.is_authorized("http://app.example-ctf.com:443/x")


def test_exact_host_rejects_near_misses():
    s = make_scope(["example.com"])
    # The classic substring traps must all fail closed.
    assert not s.is_authorized("https://evil-example.com")
    assert not s.is_authorized("https://example.com.evil.com")
    assert not s.is_authorized("https://notexample.com")
    assert not s.is_authorized("https://example.co")
    assert not s.is_authorized("https://sub.example.com")  # exact != subdomain


# --- wildcard matches --------------------------------------------------------

def test_wildcard_matches_subdomains():
    s = make_scope(["*.staging.example-bounty.com"])
    assert s.is_authorized("https://foo.staging.example-bounty.com")
    assert s.is_authorized("https://a.b.staging.example-bounty.com")


def test_wildcard_does_not_match_apex():
    s = make_scope(["*.domain.com"])
    assert not s.is_authorized("https://domain.com")


def test_wildcard_does_not_match_sibling_suffix():
    s = make_scope(["*.domain.com"])
    # evildomain.com ends with "domain.com" but NOT ".domain.com" -> reject.
    assert not s.is_authorized("https://evildomain.com")
    assert not s.is_authorized("https://xdomain.com")
    assert not s.is_authorized("https://domain.com.attacker.net")


def test_wildcard_is_not_loose_substring():
    s = make_scope(["*.example.com"])
    assert not s.is_authorized("https://example.com.evil.org")
    assert not s.is_authorized("https://fooexample.com")


# --- enforce fails closed and loudly ----------------------------------------

def test_enforce_raises_off_scope():
    s = make_scope(["app.example-ctf.com"])
    with pytest.raises(ScopeError):
        s.enforce("https://attacker.com")


def test_enforce_passes_in_scope():
    s = make_scope(["app.example-ctf.com"])
    s.enforce("https://app.example-ctf.com/rest/v1/")  # no raise


# --- normalize_target: "just type the website name" --------------------------

def test_normalize_bare_host_gets_https():
    assert normalize_target("app.example.com") == "https://app.example.com"


def test_normalize_bare_host_with_path():
    assert normalize_target("app.example.com/admin") == "https://app.example.com/admin"


def test_normalize_full_url_passes_through():
    assert normalize_target("http://app.example.com/") == "http://app.example.com/"
    assert normalize_target("https://app.example.com") == "https://app.example.com"


def test_normalize_strips_whitespace():
    assert normalize_target("  app.example.com  ") == "https://app.example.com"


def test_normalize_rejects_empty():
    with pytest.raises(ScopeError):
        normalize_target("   ")


def test_normalize_rejects_nonsense():
    with pytest.raises(ScopeError):
        normalize_target("::: not a url :::")


def test_normalize_rejects_non_web_scheme():
    with pytest.raises(ScopeError):
        normalize_target("ftp://files.example.com")


# --- Quick Mode: scope from a name, allow() for inline extension -------------

def test_from_target_authorizes_only_the_host():
    s = Scope.from_target("https://app.example.com/")
    assert s.authorized_hosts == ["app.example.com"]
    assert s.is_authorized("https://app.example.com/anything")
    # The api host most apps actually use is a DIFFERENT host — Quick Mode must
    # NOT silently authorize it. The CLI's job is to ask the operator first.
    assert not s.is_authorized("https://api-xyz.supabase.co/rest/v1/")


def test_from_target_accepts_bare_name():
    # The headline UX: a bare website name, no scheme.
    s = Scope.from_target("app.example.com")
    assert s.authorized_hosts == ["app.example.com"]
    assert s.is_authorized("https://app.example.com/x")


def test_from_target_rejects_unparseable():
    with pytest.raises(ScopeError):
        Scope.from_target("::: nonsense :::")


def test_allow_extends_scope_at_runtime():
    s = Scope.from_target("https://app.example.com/")
    assert not s.is_authorized("https://api-xyz.supabase.co")
    s.allow("api-xyz.supabase.co")
    assert s.is_authorized("https://api-xyz.supabase.co/rest/v1/")
    # Idempotent — calling twice does not duplicate the entry.
    s.allow("api-xyz.supabase.co")
    assert s.authorized_hosts.count("api-xyz.supabase.co") == 1


def test_allow_refuses_empty():
    s = Scope.from_target("https://app.example.com/")
    with pytest.raises(ScopeError):
        s.allow("   ")


def test_allow_does_not_loosen_match_rules():
    # Adding "api.x.com" must NOT authorize evil-api.x.com or api.x.com.evil.
    s = Scope.from_target("https://app.example.com/")
    s.allow("api.x.com")
    assert s.is_authorized("https://api.x.com")
    assert not s.is_authorized("https://evil-api.x.com")
    assert not s.is_authorized("https://api.x.com.attacker.net")
