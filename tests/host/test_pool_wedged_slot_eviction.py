"""Regression tests: a warm slot whose in-guest agent has wedged must leave the pool.

NB the releases below pass ``fault="worker"``: these scenarios are an in-guest agent wedge, which
is evidence about the SLOT. A dirty release with no fault (or fault="job") means the engine failed
on that INPUT and must never advance a slot toward eviction -- on a malware corpus a run of samples
that crash the engine is the workload, not a broken worker.

Motivation (observed in production, twice, on two independent hosts): a Firecracker warm
pool failed 100% of jobs for days. Nothing detected it, and the pool could not recover on
its own -- only restarting the dispatcher helped.

The reason all three of the pool's existing safeguards missed it:

  1. ``is_alive()`` for a snapshot runtime only checks that the host-side sandbox PROCESS is
     running. A wedged in-guest agent inside a perfectly healthy microVM answers True.
  2. ``release(dirty=True)`` recycles the slot -- for a snapshot runtime that is a revert to
     the SHARED persisted base -- and then republishes it to IDLE because ``is_alive()`` said
     True. So the very next job is handed to the same wedged worker, forever.
  3. The persisted base is preserved across ``reap()`` by design, so even respawning every
     slot restores the same wedged guest state if the base itself captured one.

These tests pin the two behaviours that break that loop, using only the pool's public
surface (``release(dirty=True)``) and a runtime that reproduces the invisible-wedge shape:
recycle "succeeds", is_alive() keeps saying True, but the worker never does useful work.
"""
from __future__ import annotations

import threading
from pathlib import Path
from uuid import uuid4

from blastbox.host.pool import Slot, SlotState, WarmPool


class _WedgeableRuntime:
    """Runtime whose slots can wedge INVISIBLY: alive + recyclable, but never healthy.

    This is the production shape. ``recycle()`` returns without error (a snapshot revert that
    "worked") and ``is_alive()`` returns True (the sandbox process is up), so nothing the pool
    inspects can tell the worker is dead to jobs.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reaped: list[str] = []
        self.recycled: list[str] = []
        self.base_invalidations = 0
        self.spawned: list[str] = []

    def spawn(self) -> Slot:
        slot_id = str(uuid4())
        with self._lock:
            self.spawned.append(slot_id)
        return Slot(
            slot_id=slot_id,
            control_dir=Path(f"/fake/ctrl/{slot_id}"),
            input_dir=Path(f"/fake/in/{slot_id}"),
            output_dir=Path(f"/fake/out/{slot_id}"),
            state=SlotState.WARMING,
            spawned_at=0.0,
        )

    def is_ready(self, slot: Slot) -> bool:
        return True

    def is_alive(self, slot: Slot) -> bool:
        # The wedge is invisible: the process is always up.
        return True

    def recycle(self, slot: Slot) -> None:
        with self._lock:
            self.recycled.append(slot.slot_id)

    def reap(self, slot: Slot) -> None:
        with self._lock:
            self.reaped.append(slot.slot_id)

    def invalidate_base(self) -> None:
        with self._lock:
            self.base_invalidations += 1


def _pool(runtime: _WedgeableRuntime, **kw) -> WarmPool:
    return WarmPool(runtime=runtime, warm_size=1, concurrent_ceiling=4, **kw)


def _claim_one(pool: WarmPool) -> Slot:
    pool.tick()  # spawn
    pool.tick()  # promote WARMING -> IDLE
    slot = pool.claim(timeout_s=0)
    assert slot is not None, "expected an IDLE slot to claim"
    return slot


def test_repeatedly_failing_slot_is_reaped_not_returned_to_the_pool() -> None:
    """After max_consecutive_failures dirty releases, the slot must be REAPED.

    Pre-fix this test fails: every dirty release recycled the slot and republished it to
    IDLE (because is_alive() is True), so `reaped` stayed empty and the same wedged slot
    served job after job.
    """
    rt = _WedgeableRuntime()
    pool = _pool(rt, max_consecutive_failures=2)

    first = _claim_one(pool)
    pool.release(first, dirty=True, fault="worker")          # failure 1 -> recycle, back to IDLE
    assert first.slot_id not in rt.reaped, "one failure should not condemn a slot"

    again = pool.claim(timeout_s=0)
    assert again is not None and again.slot_id == first.slot_id, (
        "after a single failure the recycled slot is expected to be reused"
    )
    pool.release(again, dirty=True, fault="worker")          # failure 2 -> limit reached

    assert first.slot_id in rt.reaped, (
        "a slot that failed max_consecutive_failures times in a row must be reaped, not "
        "recycled and handed out again (this is the production wedge loop)"
    )
    assert pool.claim(timeout_s=0) is None, "the reaped slot must no longer be claimable"


def test_a_success_resets_the_failure_streak() -> None:
    """Only CONSECUTIVE failures condemn a slot -- an intermittent failure must not."""
    rt = _WedgeableRuntime()
    pool = _pool(rt, max_consecutive_failures=2)

    slot = _claim_one(pool)
    pool.release(slot, dirty=True, fault="worker")           # 1 failure
    s2 = pool.claim(timeout_s=0)
    assert s2 is not None
    pool.release(s2, dirty=False)            # success -> streak resets
    s3 = pool.claim(timeout_s=0)
    assert s3 is not None
    pool.release(s3, dirty=True, fault="worker")             # 1 failure again, not 2

    assert s3.slot_id not in rt.reaped, (
        "a failure -> success -> failure sequence must not reap the slot"
    )
    # last-success is pool-owned (keyed by slot_id) because runtimes supply their own slot
    # types that do not inherit Slot's dataclass fields.
    assert pool._slot_last_success.get(s3.slot_id, 0) > 0, (
        "a clean release must record the slot's last success"
    )


def test_sustained_pool_wide_failure_invalidates_the_warm_base() -> None:
    """Reaping cannot fix a poisoned BASE -- the pool must ask the runtime to rebuild it.

    Pre-fix there was no such call at all: the base is preserved across reap() by design, so
    a base that captured a wedged guest kept producing wedged slots until the process
    restarted.
    """
    rt = _WedgeableRuntime()
    pool = _pool(rt, max_consecutive_failures=2, snapshot_rebuild_after=4)

    for _ in range(6):
        pool.tick()
        pool.tick()
        slot = pool.claim(timeout_s=0)
        if slot is None:
            continue
        pool.release(slot, dirty=True, fault="worker")

    assert rt.base_invalidations >= 1, (
        "sustained pool-wide dirty releases must invalidate the persisted warm base so the "
        "next spawn rebuilds it"
    )


def test_base_is_not_invalidated_while_jobs_are_succeeding() -> None:
    """A healthy pool must never drop its base (rebuilds are expensive: a full boot)."""
    rt = _WedgeableRuntime()
    pool = _pool(rt, max_consecutive_failures=2, snapshot_rebuild_after=4)

    for _ in range(8):
        pool.tick()
        pool.tick()
        slot = pool.claim(timeout_s=0)
        if slot is None:
            continue
        pool.release(slot, dirty=False)

    assert rt.base_invalidations == 0, "successful jobs must not trigger a base rebuild"
    assert rt.reaped == [] or all(s in rt.recycled for s in rt.reaped), (
        "healthy slots should be recycled/reused, not reaped for failure"
    )


# ---------------------------------------------------------------------------
# Churn safety: the eviction path must not become a boot storm
# ---------------------------------------------------------------------------


def test_sustained_unrelated_failure_does_not_cause_a_base_rebuild_storm() -> None:
    """Eviction must not turn a systemic failure into repeated full base boots.

    A base rebuild is a full sandbox boot, unlike a slot respawn (a cheap snapshot restore
    already bounded by the spawn token bucket). If jobs fail for a reason that has nothing to
    do with the base -- a bad input class, a full disk, a sick dependency -- the pool would
    otherwise rebuild every ``snapshot_rebuild_after`` failures indefinitely, which is more
    damaging than the wedge this eviction exists to fix. One rebuild per cooldown window is
    enough: if the base were at fault, the first rebuild would have fixed it.
    """
    rt = _WedgeableRuntime()
    now = [1000.0]
    pool = WarmPool(
        runtime=rt, warm_size=1, concurrent_ceiling=4,
        clock=lambda: now[0],
        max_consecutive_failures=2,
        snapshot_rebuild_after=2,
        base_rebuild_cooldown_s=300.0,
    )

    # 40 consecutive failures inside one cooldown window (clock barely advances).
    for _ in range(40):
        pool.tick()
        pool.tick()
        slot = pool.claim(timeout_s=0)
        if slot is None:
            now[0] += 0.1
            continue
        pool.release(slot, dirty=True, fault="worker")
        now[0] += 0.1

    assert rt.base_invalidations == 1, (
        "sustained failure inside one cooldown window must rebuild the base at most ONCE, "
        f"got {rt.base_invalidations} rebuilds (each is a full boot)"
    )

    # Past the cooldown, a genuinely new episode may rebuild again.
    now[0] += 301.0
    for _ in range(4):
        pool.tick()
        pool.tick()
        slot = pool.claim(timeout_s=0)
        if slot is None:
            continue
        pool.release(slot, dirty=True, fault="worker")

    assert rt.base_invalidations == 2, (
        "after the cooldown elapses a fresh failure episode should be allowed one more rebuild"
    )


# ---------------- fault attribution + bounded blast radius ------------------------------------

def _healthy_pool(**kw):
    """A pool whose worker is demonstrably fine: is_alive() always True, reap recorded."""
    from blastbox.host.pool import Slot, SlotState, WarmPool

    reaped: list[str] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            return Slot(slot_id=f"new{len(reaped)}", control_dir="/c", input_dir="/i",
                        output_dir="/o", state=SlotState.IDLE)

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            reaped.append(slot.slot_id)

        def recycle(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=1, max_consecutive_failures=2, **kw)
    pool._slots["s0"] = Slot(slot_id="s0", control_dir="/c", input_dir="/i", output_dir="/o",
                             state=SlotState.IDLE)
    return pool, reaped


def test_bad_inputs_do_not_evict_a_healthy_worker():
    """The workload is malware: samples that crash the engine are routine, not a broken worker. A
    slot with a hundred clean jobs behind it was destroyed by two bad samples in a row, because the
    counter could not tell whose failure it was."""
    pool, reaped = _healthy_pool()
    for _ in range(100):                       # a proven track record
        pool.release(pool.claim(timeout_s=0.2), dirty=False)
    for _ in range(5):                         # then a run of engine-killing samples
        got = pool.claim(timeout_s=0.2)
        assert got is not None, "the healthy slot was taken away by bad inputs"
        pool.release(got, dirty=True, fault="job")
    assert reaped == [], f"bad INPUTS evicted a healthy worker: {reaped}"


def test_an_unattributed_failure_never_evicts():
    """A caller that has not been taught to attribute must not be able to reap warm capacity by
    accident -- the default has to be conservative, or every un-migrated call site is a hazard."""
    pool, reaped = _healthy_pool()
    for _ in range(5):
        got = pool.claim(timeout_s=0.2)
        assert got is not None
        pool.release(got, dirty=True)          # no fault given
    assert reaped == [], f"an unattributed failure evicted a slot: {reaped}"


def test_worker_faults_still_evict():
    """The guard must not disarm the feature it protects: a genuine wedge is still reaped."""
    pool, reaped = _healthy_pool()
    for _ in range(2):
        got = pool.claim(timeout_s=0.2)
        if got is None:
            break
        pool.release(got, dirty=True, fault="worker")
    assert reaped == ["s0"], f"a wedged worker was not evicted: {reaped}"


def test_evictions_are_capped_per_window():
    """Whatever the predicate decides, it must not be able to empty the tier. The cap turns a wrong
    signal into churn instead of an outage -- this module has produced three fleet-wide evictions
    from predicates that read correctly in review."""
    from blastbox.host.pool import Slot, SlotState

    pool, reaped = _healthy_pool(max_evictions_per_window=1, eviction_window_s=10_000.0)
    for i in range(6):
        if f"s{i}" not in pool._slots:
            pool._slots[f"s{i}"] = Slot(slot_id=f"s{i}", control_dir="/c", input_dir="/i",
                                        output_dir="/o", state=SlotState.IDLE)
        got = pool.claim(timeout_s=0.2)
        if got is None:
            continue
        for _ in range(2):                     # two worker faults = over the wedge threshold
            pool.release(got, dirty=True, fault="worker")
            got = pool.claim(timeout_s=0.2)
            if got is None:
                break
    assert len(reaped) <= 1, f"the eviction cap did not hold: {reaped}"
