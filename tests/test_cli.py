"""CLI-level tests for Quick Mode and the inline 'also scan host X?' confirm.

These exercise the bootstrap (`_build_scope`) and the runtime scope-extension
prompt (`_confirm_allow`). The structural invariants do not change — every
request still passes through `scope.enforce()` at the `ScopedClient`
chokepoint — so this file focuses on the UX seams.
"""

from __future__ import annotations

import argparse
import sys

from rlscout.cli import _build_scope, _confirm_allow


def _ns(**kw):
    base = {"target": None, "yes": False}
    base.update(kw)
    return argparse.Namespace(**base)


# --- _build_scope: Quick Mode ------------------------------------------------

def test_quick_mode_builds_scope_from_url():
    """`rlscout https://app.example.com` and nothing else."""
    built = _build_scope(_ns(target="https://app.example.com/"))
    assert built is not None
    scope, target = built
    assert scope.authorized_hosts == ["app.example.com"]
    assert target == "https://app.example.com/"


def test_quick_mode_builds_scope_from_bare_name():
    """The headline UX: just the website name, no scheme."""
    built = _build_scope(_ns(target="app.example.com"))
    assert built is not None
    scope, target = built
    assert scope.authorized_hosts == ["app.example.com"]
    assert target == "https://app.example.com"


def test_quick_mode_target_url_is_authorized_for_enforce():
    scope, _ = _build_scope(_ns(target="https://app.example.com/admin"))
    scope.enforce("https://app.example.com/admin")  # must not raise


def test_quick_mode_rejects_unparseable_target(capsys):
    built = _build_scope(_ns(target="::: nonsense :::"))
    assert built is None
    err = capsys.readouterr().err
    assert "[scope]" in err


def test_no_target_is_usage_error(capsys):
    assert _build_scope(_ns()) is None
    assert "Usage:" in capsys.readouterr().err


# --- _confirm_allow: the inline y/N prompt -----------------------------------

class _StubStdin:
    """Mimic sys.stdin.isatty() + input() without touching the real terminal."""

    def __init__(self, tty: bool, answer: str = ""):
        self._tty = tty
        self._answer = answer

    def isatty(self) -> bool:
        return self._tty


def test_yes_flag_auto_accepts_without_prompting(monkeypatch, capsys):
    # The --yes path must not require stdin at all (CI / piped use case).
    monkeypatch.setattr(sys, "stdin", _StubStdin(tty=False))
    assert _confirm_allow("api-xyz.supabase.co", assume_yes=True) is True
    out = capsys.readouterr().out
    assert "auto-accepting" in out
    assert "api-xyz.supabase.co" in out


def test_non_tty_without_yes_refuses_to_extend_silently(monkeypatch, capsys):
    """Fail closed on piped/CI runs that didn't pre-affirm with --yes."""
    monkeypatch.setattr(sys, "stdin", _StubStdin(tty=False))
    assert _confirm_allow("api-xyz.supabase.co", assume_yes=False) is False
    err = capsys.readouterr().err
    assert "not in scope" in err
    assert "--yes" in err  # actionable next step in message


def test_interactive_yes_extends_scope(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _StubStdin(tty=True))
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    assert _confirm_allow("api-xyz.supabase.co", assume_yes=False) is True


def test_interactive_no_or_empty_refuses(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _StubStdin(tty=True))
    for answer in ("", "n", "no", "nope", "maybe"):
        monkeypatch.setattr("builtins.input", lambda _p="", _a=answer: _a)
        assert _confirm_allow("api.x.com", assume_yes=False) is False, answer


def test_interactive_eof_refuses(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _StubStdin(tty=True))

    def _eof(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", _eof)
    assert _confirm_allow("api.x.com", assume_yes=False) is False


# --- end-to-end: Quick Mode + allow() round-trip mirrors the CLI flow --------

def test_quick_mode_plus_allow_authorizes_api_host():
    """The CLI prompts, then calls scope.allow(host). After that, the scope
    must accept that host."""
    scope, _ = _build_scope(_ns(target="https://app.example.com/"))
    assert not scope.is_authorized("https://api-xyz.supabase.co/rest/v1/")
    scope.allow("api-xyz.supabase.co")
    scope.enforce("https://api-xyz.supabase.co/rest/v1/")  # no raise
