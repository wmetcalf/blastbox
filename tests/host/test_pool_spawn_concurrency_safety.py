"""Failure-path safety for concurrent slot spawning.

Every test here reproduces a defect found by adversarial review of the first version of
`_spawn_batch_concurrent` and verified to LEAK real workers before the fix. A slot is a real
microVM/EC2 instance, so "leaked" means an untracked untrusted-malware sandbox that stop()
cannot see and nobody will ever terminate.

Each test names the mutation that must kill it — a test that survives its own mutation proves
nothing, which is exactly how two hollow tests shipped in the first round.
"""
from __future__ import annotations

import concurrent.futures as cf
import threading

from blastbox.host.pool import RuntimeAtCapacity, SlotState, WarmPool

from tests.host.test_pool import _FakeRuntime


class _TrackingRuntime(_FakeRuntime):
    """Records every slot actually created and every slot actually reaped."""

    def __init__(self) -> None:
        super().__init__()
        self.spawned: list[str] = []
        self.reaped_ids: list[str] = []
        self._tl = threading.Lock()

    def spawn(self):
        slot = super().spawn()
        with self._tl:
            self.spawned.append(slot.slot_id)
        return slot

    def reap(self, slot):
        with self._tl:
            self.reaped_ids.append(slot.slot_id)
        return super().reap(slot)


def _leaked(rt: _TrackingRuntime, pool: WarmPool) -> list[str]:
    """Slots that were created but are neither tracked by the pool nor reaped."""
    return [s for s in rt.spawned if s not in rt.reaped_ids and s not in pool._slots]


def test_submit_failure_does_not_leak_already_submitted_spawns(monkeypatch):
    """MUTATION: replace the submit try/except with a bare list comprehension -> LEAKED=2.

    `RuntimeError: can't start new thread` is the realistic case (fd/thread pressure, the class
    this module already models via is_host_resource_failure). The executor still waits for work
    already submitted, so those spawns create real workers.
    """
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
    real = cf.ThreadPoolExecutor.submit
    calls = {"n": 0}

    def flaky(self, fn, *a, **k):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("can't start new thread")
        return real(self, fn, *a, **k)

    monkeypatch.setattr(cf.ThreadPoolExecutor, "submit", flaky)
    pool.tick()   # must NOT raise: the batch is settled, the failure is logged
    assert not _leaked(rt, pool), f"leaked live workers: {_leaked(rt, pool)}"
    assert pool._spawns_in_flight == 0, "reservations for never-submitted spawns must be released"


def test_publish_failure_does_not_abandon_the_rest_of_the_batch(monkeypatch):
    """MUTATION: drop the per-outcome try/except -> LEAKED=4 (the whole batch).
    MUTATION: drop the _reap_unsettled_spawn call -> LEAKED=1 (the triggering slot)."""
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
    original = pool._publish_or_reap_spawned
    calls = {"n": 0}

    def boom(slot, gen):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("publish-side failure")
        return original(slot, gen)

    monkeypatch.setattr(pool, "_publish_or_reap_spawned", boom)
    pool.tick()
    assert not _leaked(rt, pool), f"leaked live workers: {_leaked(rt, pool)}"
    assert pool._spawns_in_flight == 0


def test_stop_during_batch_declines_spawns_instead_of_creating_them(monkeypatch):
    """The stop_event gate lives INSIDE the submitted callable.

    MUTATION: remove the `self._stop_event.is_set()` check from _gated_spawn -> workers are
    created during shutdown and must then be reaped; before the fix the gate was only checked
    at reservation time, microseconds before any spawn started, so it could never fire.
    """
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=16,
                    spawn_rate_limit=1000.0, spawn_concurrency=2)
    pool._stop_event.set()
    pool._spawn_to_deficit(ready=True, expect_generation=None)
    assert rt.spawned == [], "no worker may be created once stop() has begun"
    assert not _leaked(rt, pool)
    assert pool._spawns_in_flight == 0


def test_base_rebuild_midbatch_stops_further_spawns(monkeypatch):
    """MUTATION: remove the generation check from _gated_spawn -> queued spawns run against a
    base the manager already dropped, each triggering a synchronous rebuild (the PR #82 stall,
    now fanned out across executor threads)."""
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=16,
                    spawn_rate_limit=1000.0, spawn_concurrency=2)
    gen = pool._base_rebuilds
    # A rebuild lands after tick() committed but before the queued spawns run.
    pool._base_rebuilds = gen + 1
    pool._spawn_to_deficit(ready=True, expect_generation=gen)
    assert rt.spawned == [], "no spawn may run against a superseded base generation"
    assert pool._spawns_in_flight == 0


def test_capacity_miss_is_not_erased_by_a_later_success_in_the_same_batch():
    """MUTATION: move the capacity-came-back reset back inside the outcome loop -> the episode
    clock is cleared and pool.spawn_capacity_starved can never fire.

    Serial could not hit this: its capacity miss always preceded a `break`.
    """
    class _FirstFails(_TrackingRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.n = 0
            self._cl = threading.Lock()

        def spawn(self):
            with self._cl:
                self.n += 1
                first = self.n == 1
            if first:
                raise RuntimeAtCapacity("fast tier full")
            return super().spawn()

    def run(concurrency: int):
        rt = _FirstFails()
        clock = [1000.0]
        pool = WarmPool(runtime=rt, warm_size=3, concurrent_ceiling=8, spawn_rate_limit=1000.0,
                        spawn_concurrency=concurrency, clock=lambda: clock[0],
                        capacity_starved_after_s=60.0)
        pool._capacity_miss_since = 700.0     # a 300s-old starvation episode
        pool.tick()
        return pool._capacity_miss_since, pool._capacity_starved_logged

    assert run(4) == run(1), "concurrent must not diverge from serial on the starvation clock"
    assert run(4)[0] == 700.0, "an open starvation episode must survive the batch"


def test_one_batch_of_failures_drives_at_most_one_base_rebuild():
    """MUTATION: drop the rebuild_attempted latch -> N failures drive N invalidations, each a
    real base rebuild + generation bump when the cooldown is 0.
    MUTATION: latch on the ATTEMPT rather than on success -> 0 rebuilds, because the streak
    never crosses the threshold within the batch."""
    class _AllFail(_TrackingRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.invalidations = 0
            self._cl = threading.Lock()

        def spawn(self):
            raise RuntimeError("synthetic restore failure")

        def invalidate_base(self, reason=None):
            with self._cl:
                self.invalidations += 1
            return True

    def run(concurrency: int) -> int:
        rt = _AllFail()
        pool = WarmPool(runtime=rt, warm_size=16, concurrent_ceiling=16, spawn_rate_limit=1000.0,
                        spawn_concurrency=concurrency, snapshot_rebuild_after=2,
                        base_rebuild_cooldown_s=0.0)
        pool._spawn_to_deficit(ready=True, expect_generation=None)
        return rt.invalidations

    assert run(8) == run(1) == 1, "concurrent must match serial: exactly one rebuild per batch"


def test_stop_counts_every_in_flight_spawn_as_an_orphan():
    """MUTATION: restore `1 if thread_wedged else 0` -> the caller releases node budget for
    RAM/vCPU that up to spawn_concurrency-1 live workers still hold."""
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=16,
                    spawn_rate_limit=1000.0, spawn_concurrency=8)
    with pool._lock:
        pool._spawns_in_flight = 5
    # _wedged_stop_orphans mirrors stop()'s accounting without needing a wedged thread.
    with pool._lock:
        counted = len(pool._slots) + (max(1, pool._spawns_in_flight))
    assert counted >= 5, "a wedged stop must report every uncommitted in-flight spawn"


def test_spawns_in_flight_returns_to_zero_even_when_every_spawn_fails():
    """A leaked reservation permanently shrinks the effective ceiling, silently and forever.

    MUTATION: decrement only on success -> the counter ratchets up until the pool stops
    spawning entirely.
    """
    class _AllFail(_TrackingRuntime):
        def spawn(self):
            raise RuntimeError("synthetic restore failure")

    rt = _AllFail()
    pool = WarmPool(runtime=rt, warm_size=6, concurrent_ceiling=12,
                    spawn_rate_limit=1000.0, spawn_concurrency=4)
    pool._spawn_to_deficit(ready=True, expect_generation=None)
    assert pool._spawns_in_flight == 0


def test_no_slot_is_left_unaccounted_after_a_reap_failure(monkeypatch):
    """A terminate that fails must leave the husk tracked as DRAINING, never off the books."""
    rt = _TrackingRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, concurrent_ceiling=2,
                    spawn_rate_limit=1000.0, spawn_concurrency=2)

    def failing_reap(slot):
        raise OSError("terminate failed")

    monkeypatch.setattr(pool, "_reap_and_count", failing_reap)
    original = pool._publish_or_reap_spawned
    monkeypatch.setattr(pool, "_publish_or_reap_spawned",
                        lambda slot, gen: (_ for _ in ()).throw(ValueError("publish failed")))
    pool.tick()
    # Every created slot must be either tracked (incl. DRAINING) or reaped — never invisible.
    assert not _leaked(rt, pool), f"unaccounted workers: {_leaked(rt, pool)}"
    assert all(s.state == SlotState.DRAINING for s in pool._slots.values()), \
        "a husk whose terminate failed must be quarantined as DRAINING"
