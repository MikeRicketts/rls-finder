"""Scope building and fail-closed enforcement.

Invariant #1 from AGENTS.md: the tool refuses to send a single request to any
host not in its in-memory allowlist. Scope is enforced *in code, before any
network call* — never left to the operator's memory.

There is exactly one way to build a scope (Quick Mode):

1. ``Scope.from_target(name)``  — the website you typed *is* the allowlist. A
   bare host (``app.example.com``) or a full URL (``https://app.example.com``)
   both work; the bare form is normalized to ``https://`` for you. The CLI then
   optionally extends the scope (``scope.allow(host)``) after the operator
   confirms a newly-discovered Supabase API host inline.
2. ``Scope(authorized_hosts=...)`` — for tests/library users.

Matching rules (identical for both):

- Exact host matches are required for non-wildcard entries (``example.com`` only
  matches ``example.com`` — never ``evil-example.com`` or ``example.com.evil``).
- Wildcard entries (``*.domain.com``) match any host that is a strict subdomain
  of ``domain.com`` (one or more leading labels). They do NOT match the bare apex
  ``domain.com`` and they do NOT match ``evildomain.com``.
- Matching is case-insensitive and ignores any port.

A non-match is a HARD ABORT (``ScopeError``), not a logged-and-skipped event —
fail closed, loudly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when an out-of-scope target is encountered. This is fatal by design."""


def normalize_target(raw: str) -> str:
    """Turn what the operator typed into a full ``http(s)://`` URL.

    The headline UX is "just type the name of the website", so a bare host like
    ``app.example.com`` (or ``app.example.com/path``) is accepted and gets an
    ``https://`` scheme prepended. A URL that already carries an ``http``/``https``
    scheme is passed through untouched. Anything that still doesn't parse to a
    real host — or carries a non-web scheme like ``ftp://`` — is rejected, so we
    never silently authorize a nonsense host.
    """
    candidate = raw.strip()
    if not candidate:
        raise ScopeError("no target given")

    parts = urlsplit(candidate)
    if not parts.scheme and "//" not in candidate:
        # Bare host (possibly host:port/path) — assume https.
        candidate = "https://" + candidate
        parts = urlsplit(candidate)

    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ScopeError(
            f"target must be a website name or http(s):// URL (got: {raw!r})"
        )
    # Make sure a real host falls out (urlsplit is otherwise permissive enough
    # to treat garbage as a netloc).
    if not parts.hostname:
        raise ScopeError(f"could not determine host from target: {raw!r}")
    return candidate


def _host_of(url_or_host: str) -> str:
    """Extract the bare lowercase hostname from a URL or host string (no port)."""
    candidate = url_or_host.strip()
    if "//" not in candidate:
        # Bare host (possibly host:port). Give urlsplit a scheme to parse it.
        candidate = "//" + candidate
    host = urlsplit(candidate).hostname
    if not host:
        raise ScopeError(f"Could not determine host from: {url_or_host!r}")
    return host.lower().rstrip(".")


def _matches_pattern(host: str, pattern: str) -> bool:
    """True if ``host`` matches a single authorized-host ``pattern``.

    Wildcards are only honored as a leading ``*.`` label; everything else is an
    exact, full-host comparison. This deliberately avoids loose substring checks.
    """
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        return False

    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".domain.com"
        # Strict subdomain: host must end with ".domain.com" AND have a non-empty
        # label before it. "domain.com" itself and "evildomain.com" both fail
        # because neither leaves a non-empty prefix once ".domain.com" is removed.
        if not host.endswith(suffix):
            return False
        prefix = host[: -len(suffix)]
        return len(prefix) > 0

    # No wildcard anywhere else — exact host match only.
    return host == pattern


@dataclass
class Scope:
    """A built, validated authorization scope.

    ``authorized_hosts`` is the *allowlist* — what the tool is permitted to
    contact. In Quick Mode it starts as the single host the operator typed, and
    can be extended at runtime via :meth:`allow` once the operator confirms a
    newly-discovered Supabase API host.
    """

    authorized_hosts: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_target(cls, target: str, *, notes: str = "") -> "Scope":
        """Build a one-host scope from the website the operator typed.

        ``target`` may be a bare host (``app.example.com``) or a full
        ``http(s)://`` URL; it is normalized the same way as the CLI target. The
        URL's host *is* the implicit allowlist — nothing else is authorized until
        the operator approves it inline (:meth:`allow`).
        """
        url = normalize_target(target)
        host = _host_of(url)
        return cls(
            authorized_hosts=[host],
            notes=notes or f"Quick Mode (target {url})",
        )

    def allow(self, host_or_pattern: str) -> None:
        """Extend the scope at runtime (e.g. operator-confirmed API host).

        Idempotent. The host is normalized the same way as the initial entry.
        After this call, ``is_authorized(host)`` returns True for the added host
        and ``enforce()`` no longer raises for it.
        """
        cleaned = host_or_pattern.strip().lower().rstrip(".")
        if not cleaned:
            raise ScopeError("refusing to allow empty host")
        if cleaned not in self.authorized_hosts:
            self.authorized_hosts.append(cleaned)

    def is_authorized(self, url_or_host: str) -> bool:
        """Return True iff the target's host matches an authorized pattern."""
        host = _host_of(url_or_host)
        return any(_matches_pattern(host, pat) for pat in self.authorized_hosts)

    def enforce(self, url_or_host: str) -> None:
        """Raise ``ScopeError`` (hard abort) if the target is out of scope."""
        if not self.is_authorized(url_or_host):
            host = _host_of(url_or_host)
            raise ScopeError(
                f"OUT OF SCOPE: refusing to contact host {host!r} "
                f"(not in the active scope: {', '.join(self.authorized_hosts)})"
            )
