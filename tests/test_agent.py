"""Bounded-LLM layer: graceful degradation + the safety re-validation of proposals.

These never call the real API — the agent functions are monkeypatched. The point
is to prove the deterministic core re-validates whatever the LLM proposes:
service_role refused, non-anon/invalid keys ignored, off-scope API bases refused.
"""

import argparse
import base64
import json
import types

from rlscout import agent
from rlscout.cli import _ai_recon_fallback, _ai_triage
from rlscout.recon import ReconResult
from rlscout.report import ScanReport
from rlscout.rls import TableResult, STATUS_VULNERABLE, SEV_HIGH
from rlscout.scope import Scope


def make_jwt(role: str) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'role': role})}.sig"


ANON = make_jwt("anon")
SERVICE = make_jwt("service_role")


def _args():
    return argparse.Namespace(ai=True, ai_model=None, verbose=False)


def _report():
    return ScanReport(target="https://app.myapp.com/", api_base=None, scope_notes="",
                      started_at="t", finished_at="t", request_count=0)


def _proposal(anon_key=None, api_base=None):
    return agent.AIResult(ok=True, value=types.SimpleNamespace(
        anon_key=anon_key, api_base=api_base, confidence="high", notes=""))


SCOPE = Scope(authorized_hosts=["app.myapp.com", "api.myapp.com"])
RECON = ReconResult(fetched_texts=[("https://app.myapp.com/app.js", "bundle text")])


# --- graceful degradation ----------------------------------------------------

def test_ai_unavailable_returns_error(monkeypatch):
    monkeypatch.setattr(agent, "anthropic", None)
    assert agent.ai_available() is False
    res = agent.triage([("users", 5)], target="t", api_base=None)
    assert not res.ok  # _client() raises, wrapped into an error result


def test_fallback_notes_when_ai_unavailable(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: False)
    report = _report()
    key, base = _ai_recon_fallback(RECON, SCOPE, _args(), report)
    assert key is None and base is None
    assert any("install" in n for n in report.ai_notes)


# --- proposal re-validation (the safety boundary) ----------------------------

def test_fallback_accepts_anon_and_in_scope_base(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: True)
    monkeypatch.setattr(agent, "recon_fallback",
                        lambda *a, **k: _proposal(ANON, "https://api.myapp.com"))
    report = _report()
    key, base = _ai_recon_fallback(RECON, SCOPE, _args(), report)
    assert key is not None and key.role == "anon"
    assert base == "https://api.myapp.com"


def test_fallback_refuses_service_role(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: True)
    monkeypatch.setattr(agent, "recon_fallback", lambda *a, **k: _proposal(SERVICE, None))
    report = _report()
    key, base = _ai_recon_fallback(RECON, SCOPE, _args(), report)
    assert key is None
    assert any("service_role" in n for n in report.ai_notes)


def test_fallback_ignores_invalid_jwt(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: True)
    monkeypatch.setattr(agent, "recon_fallback",
                        lambda *a, **k: _proposal("not-a-jwt", None))
    report = _report()
    key, _ = _ai_recon_fallback(RECON, SCOPE, _args(), report)
    assert key is None


def test_fallback_refuses_off_scope_base(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: True)
    monkeypatch.setattr(agent, "recon_fallback",
                        lambda *a, **k: _proposal(ANON, "https://evil.supabase.co"))
    report = _report()
    key, base = _ai_recon_fallback(RECON, SCOPE, _args(), report)
    assert key is not None  # key is fine
    assert base is None      # but the off-scope base is refused
    assert any("off-scope" in n for n in report.ai_notes)


def test_fallback_unparseable_url_records_note(monkeypatch):
    """B4: a malformed URL proposal must not be silently swallowed — the
    operator should see why the LLM fallback yielded no API base."""
    from rlscout.scope import Scope, ScopeError

    monkeypatch.setattr(agent, "ai_available", lambda: True)
    monkeypatch.setattr(agent, "recon_fallback",
                        lambda *a, **k: _proposal(ANON, "not a url at all"))

    # Force is_authorized to raise on this malformed candidate — same shape
    # of failure that an unparseable URL hits in real code.
    class _BrokenScope(Scope):
        def is_authorized(self, url_or_host):
            if "not a url" in url_or_host:
                raise ScopeError("could not determine host")
            return super().is_authorized(url_or_host)

    broken = _BrokenScope(authorized_hosts=["app.myapp.com", "api.myapp.com"])
    report = _report()
    key, base = _ai_recon_fallback(RECON, broken, _args(), report)
    assert key is not None       # the anon key was still accepted
    assert base is None          # but the unparseable URL was refused
    assert any("unparseable" in n.lower() for n in report.ai_notes), report.ai_notes


# --- triage ------------------------------------------------------------------

def test_triage_populates_report(monkeypatch):
    monkeypatch.setattr(agent, "ai_available", lambda: True)
    judgment = types.SimpleNamespace(
        table="users", likelihood="likely_sensitive", rationale="user PII")
    monkeypatch.setattr(agent, "triage", lambda *a, **k: agent.AIResult(
        ok=True, value=types.SimpleNamespace(
            writeup_markdown="## Writeup\nLooks bad.", judgments=[judgment])))
    report = _report()
    report.table_results = [TableResult(
        "users", STATUS_VULNERABLE, 200, 42, "anon SELECT returned rows", "GET ...",
        SEV_HIGH)]
    _ai_triage(report, "https://app.myapp.com/", "https://api.myapp.com", _args())
    assert report.ai_triage_markdown.startswith("## Writeup")
    assert report.ai_judgments[0]["likelihood"] == "likely_sensitive"
