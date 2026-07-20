"""Dynamic concurrency gate — the sizer's live cap on COLD-path admission.

The node autosizer allocates each engine a slot ceiling under the node RAM/vCPU budget. The
warm pool already bounds warm slots at that ceiling. But the cold-fallback path (and egress
jobs, which must go cold) spawns workers OUTSIDE the pool, so those add footprint ON TOP of
warm residency — bounding warm slots alone doesn't bound the node.

This gate bounds cold admission to the budget's COLD HEADROOM. Only the cold path acquires a
permit (warm dispatch reuses an already-resident slot and adds nothing, so it is never gated);
the sizer calls :meth:`set_limit` on every resize with ``ceiling − warm reservation``, so warm
residency + cold workers stay within the ceiling instead of each independently reaching it. The
limit floors at 1 so cold never fully starves when warm claims the whole budget.

This is BEST-EFFORT, not a hard guarantee: the warm pool can burst above its reservation within
a sizing interval before the gate limit catches up, a bounded overshoot that self-corrects on
the next tick (plus idle-slot reaping) — see the eventual-consistency note in dispatcher_sizer.
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
