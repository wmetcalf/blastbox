"""Dynamic concurrency gate — the sizer's live control over how many jobs a dispatcher runs.

The node autosizer allocates each engine a slot ceiling under the node RAM/vCPU budget. But a
warm pool only bounds WARM slots; the cold-fallback path (and egress jobs, which must go cold)
runs OUTSIDE the pool, so bounding warm slots alone doesn't bound node RAM. Each in-flight
detonation — warm OR cold — is one slot's worth of RAM, so the honest bound is on CONCURRENT
JOB PROCESSING, whatever tier it lands on.

This gate provides exactly that: dispatch workers acquire a permit before processing a job and
release it after, and the sizer calls :meth:`set_limit` on every resize to track the pool's
current ceiling. With the pool ceiling capped at the dispatcher's worker count, we get
``active ≤ ceiling ≤ budget`` at all times — a hard node cap that also covers cold fallback.
"""

from __future__ import annotations

import threading
import time


class DynamicConcurrencyGate:
    """Bounds concurrent job processing to a limit the node autosizer adjusts on the fly."""

    def __init__(self, limit: int) -> None:
        self._cond = threading.Condition()
        self._limit = max(1, int(limit))
        self._in_flight = 0

    @property
    def limit(self) -> int:
        with self._cond:
            return self._limit

    @property
    def in_flight(self) -> int:
        with self._cond:
            return self._in_flight

    def set_limit(self, limit: int) -> None:
        """Adjust the concurrency ceiling (the sizer calls this each resize). A GROWN limit
        may let blocked workers through, so wake them; a SHRUNK limit just means new acquires
        block until in-flight drains below it — in-flight jobs are never interrupted."""
        with self._cond:
            self._limit = max(1, int(limit))
            self._cond.notify_all()

    def acquire(self, timeout: float) -> bool:
        """Reserve one in-flight permit, waiting up to ``timeout`` seconds. Returns False if it
        timed out (the caller then re-checks its stop flag and retries) — never blocks forever,
        so shutdown stays responsive."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while self._in_flight >= self._limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(timeout=remaining)
            self._in_flight += 1
            return True

    def release(self) -> None:
        with self._cond:
            if self._in_flight > 0:
                self._in_flight -= 1
            self._cond.notify()
