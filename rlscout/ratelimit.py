"""Request throttling and a global per-run request cap.

Don't hammer a live database: a sensible default rate plus a hard ceiling on the
total number of requests a single run may make. Both are easily adjustable.
"""

from __future__ import annotations

import threading
import time


class RateLimitError(Exception):
    """Raised when the global per-run request cap is exhausted."""


class RateLimiter:
    """Simple thread-safe throttle + global request counter.

    ``rate`` is requests/second (<= 0 disables throttling). ``cap`` is the maximum
    number of requests permitted for the whole run (<= 0 disables the cap).
    """

    def __init__(self, rate: float = 3.0, cap: int = 500) -> None:
        self.rate = rate
        self.cap = cap
        self._min_interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._last = 0.0
        self._count = 0
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        """Number of requests acquired so far this run."""
        return self._count

    def acquire(self) -> None:
        """Block until the next request is allowed; raise if the cap is hit."""
        with self._lock:
            if self.cap and self.cap > 0 and self._count >= self.cap:
                raise RateLimitError(
                    f"global request cap reached ({self.cap}); aborting run"
                )
            if self._min_interval:
                now = time.monotonic()
                wait = self._last + self._min_interval - now
                if wait > 0:
                    time.sleep(wait)
                self._last = time.monotonic()
            self._count += 1
