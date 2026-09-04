"""Concurrent slot spawning (BLASTBOX_POOL_SPAWN_CONCURRENCY).

The maintenance thread issues runtime.spawn() one at a time, so a tier whose spawn is
latency-bound caps the whole pool. Measured on toolz2 with the FC snapshot tier: spawn gap
p50 0.57s -> ~1.7 slots/s, and because every job burns a disposable slot that was also the
job-throughput ceiling (1.4/s) while the node sat at load 8 of 32 cores with 94G free.

These cover the properties that make overlapping spawns safe, not just faster:
the ceiling must hold while spawns are IN FLIGHT, and a spawn that cannot be published
must be reaped rather than leaked.
"""

from __future__ import annotations

import threading
import time

import pytest

from blastbox.host.pool import WarmPool
from blastbox.host.pool_config import PoolConfig

from tests.host.test_pool import _FakeRuntime


class _SlowSpawnRuntime(_FakeRuntime):
    """Spawn blocks for *delay*, recording max observed concurrency."""

    def __init__(self, delay: float = 0.2) -> None:
        super().__init__()
        self._delay = delay
        self._in_flight = 0
        self.max_in_flight = 0
        self._cl = threading.Lock()

    def spawn(self):
        with self._cl:
            self._in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self._in_flight)
        try:
            time.sleep(self._delay)
            return super().spawn()
        finally:
            with self._cl:
                self._in_flight -= 1


def _fill(pool: WarmPool, deadline_s: float = 10.0) -> None:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        pool.tick()
        if len(pool._slots) >= pool._warm_size:
            return
        time.sleep(0.02)


def test_default_is_serial_so_behaviour_is_unchanged():
    """Default 1 must keep the previous one-at-a-time behaviour."""
    rt = _SlowSpawnRuntime(delay=0.05)
    pool = WarmPool(
        runtime=rt, warm_size=4, concurrent_ceiling=8, spawn_rate_limit=1000.0
    )
    _fill(pool)
    assert rt.max_in_flight == 1, "default must not overlap spawns"


def test_concurrency_overlaps_spawns():
    rt = _SlowSpawnRuntime(delay=0.2)
    pool = WarmPool(
        runtime=rt,
        warm_size=6,
        concurrent_ceiling=12,
        spawn_rate_limit=1000.0,
        spawn_concurrency=4,
    )
    _fill(pool)
    assert rt.max_in_flight > 1, "spawns should overlap when concurrency > 1"
    assert rt.max_in_flight <= 4, (
        f"must not exceed the configured cap, saw {rt.max_in_flight}"
    )


@pytest.mark.skip(
    reason="VACUOUS: WarmPool.__init__ clamps warm_size to concurrent_ceiling "
    "(pool.py:404), so warm_size=10/ceiling=4 becomes target=4 and the "
    "overshoot this claims to test is unreachable. Verified: deleting BOTH "
    "the headroom clamp and the in-flight ceiling check still passes. "
    "Rewrite against a real overshoot before trusting it."
)
def test_ceiling_is_never_breached_under_concurrent_spawning():
    """VACUOUS -- see skip reason. Kept visible rather than deleted so the gap stays on the record."""
    rt = _SlowSpawnRuntime(delay=0.15)
    pool = WarmPool(
        runtime=rt,
        warm_size=10,
        concurrent_ceiling=4,
        spawn_rate_limit=1000.0,
        spawn_concurrency=8,
    )
    _fill(pool, deadline_s=6.0)
    assert len(pool._slots) <= 4, f"ceiling breached: {len(pool._slots)} slots"
    assert rt.max_in_flight <= 4, (
        f"more spawns in flight than the ceiling allows: {rt.max_in_flight}"
    )


def test_failed_spawns_do_not_wedge_the_batch():
    class _HalfFail(_SlowSpawnRuntime):
        def __init__(self):
            super().__init__(delay=0.05)
            self.calls = 0

        def spawn(self):
            with self._cl:
                self.calls += 1
                fail = self.calls % 2 == 0
            if fail:
                raise RuntimeError("synthetic spawn failure")
            return super().spawn()

    rt = _HalfFail()
    pool = WarmPool(
        runtime=rt,
        warm_size=4,
        concurrent_ceiling=8,
        spawn_rate_limit=1000.0,
        spawn_concurrency=4,
    )
    for _ in range(40):
        pool.tick()
        time.sleep(0.02)
        if len(pool._slots) >= 4:
            break
    assert len(pool._slots) >= 1, "a partially failing batch must still make progress"


def test_in_flight_counter_returns_to_zero():
    """A leaked reservation would permanently shrink the effective ceiling."""
    rt = _SlowSpawnRuntime(delay=0.05)
    pool = WarmPool(
        runtime=rt,
        warm_size=4,
        concurrent_ceiling=8,
        spawn_rate_limit=1000.0,
        spawn_concurrency=4,
    )
    _fill(pool)
    assert pool._spawns_in_flight == 0


def test_config_reads_env(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_SPAWN_CONCURRENCY", "6")
    assert PoolConfig.from_env().spawn_concurrency == 6
    monkeypatch.setenv("BLASTBOX_POOL_SPAWN_CONCURRENCY", "0")
    assert PoolConfig.from_env().spawn_concurrency == 1, "must clamp to at least serial"


def test_config_default_is_serial(monkeypatch):
    monkeypatch.delenv("BLASTBOX_POOL_SPAWN_CONCURRENCY", raising=False)
    assert PoolConfig.from_env().spawn_concurrency == 1
