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
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    _fill(pool)
    assert rt.max_in_flight == 1, "default must not overlap spawns"


def test_concurrency_overlaps_spawns():
    rt = _SlowSpawnRuntime(delay=0.2)
    pool = WarmPool(runtime=rt, warm_size=6, concurrent_ceiling=12,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
    _fill(pool)
    assert rt.max_in_flight > 1, "spawns should overlap when concurrency > 1"
    assert rt.max_in_flight <= 4, f"must not exceed the configured cap, saw {rt.max_in_flight}"


def test_ceiling_holds_when_batches_overlap():
    """The reservation counter, against the caller it exists to defend against.

    The previous version of this test asked for warm_size=10 with ceiling=4 and
    asserted the pool stayed at 4. `WarmPool.__init__` clamps warm_size DOWN to
    the ceiling, so the target was 4 all along and no overshoot was ever
    attempted: deleting both the headroom clamp and the in-flight check left it
    passing. It was skipped as vacuous rather than deleted, with a note to
    rewrite it against a real overshoot. This is that rewrite.

    `_spawn_batch_concurrent` documents `_spawns_in_flight` as defensive -- the
    maintenance thread waits for each batch, so today's batches cannot overlap
    and the counter is unreachable through `tick()`. It exists for "a future
    caller which issues batches without waiting", so the test IS that caller:
    two batches are issued concurrently, each asking for the whole ceiling.

    Without the reservation counter, both batches see an empty pool, both
    reserve the full ceiling, and the node ends up with twice the workers it is
    allowed -- which on a real tier is twice the RAM.
    """
    rt = _SlowSpawnRuntime(delay=0.15)
    ceiling = 4
    pool = WarmPool(runtime=rt, warm_size=ceiling, concurrent_ceiling=ceiling,
                    spawn_rate_limit=1000.0, spawn_concurrency=ceiling)

    # Watch the RESERVATIONS too, not just the slots that get published. Each
    # one is an intent to create a worker, and the pre-spawn gate declining them
    # later still means the pool briefly promised the node twice its ceiling.
    peak_reserved = 0
    real_spawn = rt.spawn

    def watched_spawn():
        nonlocal peak_reserved
        peak_reserved = max(peak_reserved, pool._spawns_in_flight)
        return real_spawn()

    rt.spawn = watched_spawn

    barrier = threading.Barrier(2, timeout=5)

    def issue_batch():
        barrier.wait()          # both callers start inside the same window
        pool._spawn_batch_concurrent(ceiling, None)

    threads = [threading.Thread(target=issue_batch) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    # EXACTLY the ceiling: not fewer either. Two batches asking for 4 each must
    # fill the pool to 4, not deadlock it. Bounding reservations by published
    # slots alone (dropping `_spawns_in_flight` from the reservation check)
    # makes both batches reserve the full ceiling, and then the pre-spawn gate
    # declines every one of them -- the pool creates NOTHING and the ceiling
    # "holds" vacuously, which is how the previous version of this test passed.
    assert len(pool._slots) == ceiling, (
        f"expected the pool to fill to {ceiling}, got {len(pool._slots)} slots"
    )
    assert rt.max_in_flight <= ceiling, (
        f"more spawns in flight than the ceiling allows: {rt.max_in_flight}"
    )
    assert pool._spawns_in_flight == 0, "every reservation must be released"
    assert peak_reserved <= ceiling, (
        f"reservations overshot the ceiling: {peak_reserved} > {ceiling}. The "
        "pre-spawn gate would still decline them, but the pool must not promise "
        "the node more workers than it is allowed in the first place."
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
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
    for _ in range(40):
        pool.tick()
        time.sleep(0.02)
        if len(pool._slots) >= 4:
            break
    assert len(pool._slots) >= 1, "a partially failing batch must still make progress"


def test_in_flight_counter_returns_to_zero():
    """A leaked reservation would permanently shrink the effective ceiling."""
    rt = _SlowSpawnRuntime(delay=0.05)
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
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
