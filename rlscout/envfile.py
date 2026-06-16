"""Minimal, dependency-free ``.env`` loader.

Loads ``KEY=VALUE`` pairs from a ``.env`` file into ``os.environ`` so secrets like
``ANTHROPIC_API_KEY`` (used by the optional ``--ai`` layer) don't have to be set in
the shell. Real environment variables always win — the file never overrides an
already-set value. This is intentionally tiny; for anything fancier, use
python-dotenv.
"""

from __future__ import annotations

import os
from pathlib import Path


def _candidate_paths(explicit: str | None) -> list[Path]:
    if explicit:
        return [Path(explicit)]
    # Current working dir first, then the project root (parent of this package),
    # so it works whether you run from the repo root or a subdirectory.
    here = Path(__file__).resolve().parent.parent
    return [Path.cwd() / ".env", here / ".env"]


def load_dotenv(path: str | None = None) -> Path | None:
    """Load the first ``.env`` found into ``os.environ``; return the path used."""
    for p in _candidate_paths(path):
        if not p.is_file():
            continue
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        return p
    return None
