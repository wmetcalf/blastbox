"""Regression tests: a warm slot whose in-guest agent has wedged must leave the pool.

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
    pool.release(first, dirty=True)          # failure 1 -> recycle, back to IDLE
    assert first.slot_id not in rt.reaped, "one failure should not condemn a slot"

    again = pool.claim(timeout_s=0)
    assert again is not None and again.slot_id == first.slot_id, (
        "after a single failure the recycled slot is expected to be reused"
    )
    pool.release(again, dirty=True)          # failure 2 -> limit reached

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
    pool.release(slot, dirty=True)           # 1 failure
    s2 = pool.claim(timeout_s=0)
    assert s2 is not None
    pool.release(s2, dirty=False)            # success -> streak resets
    s3 = pool.claim(timeout_s=0)
    assert s3 is not None
    pool.release(s3, dirty=True)             # 1 failure again, not 2

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
        pool.release(slot, dirty=True)

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
