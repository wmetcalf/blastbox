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

import contextlib
from types import SimpleNamespace

import pytest
import logging


from blastbox.host.runtime.cascade import CascadeExhausted, CascadingRuntime, Tier
from blastbox.host.runtime.static_pool import StaticPoolExhausted
from blastbox.host.pool import RuntimeAtCapacity, Slot, SlotState, WarmPool


class _FakeClock:
    """Local copy -- cross-test-module imports don't resolve under this layout."""
    def __init__(self, t: float = 0.0) -> None:
        self._t = t

    def __call__(self) -> float:
        return self._t

    def advance(self, delta: float) -> None:
        self._t += delta




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


def test_repeated_restore_failures_invalidate_the_base() -> None:
    """A base too broken to RESTORE must still get rebuilt.

    Job-failure counting cannot see this case: if spawn() raises, no slot ever reaches IDLE, so
    no job is dispatched and no dirty release happens. The tier sits at zero capacity, logging
    pool.spawn_failed forever, while the counter that would trigger a rebuild stays at zero --
    even though "cannot restore the base" is stronger evidence the base is bad than "jobs
    restored from it fail". Discovered while fault-injecting a corrupted snapshot on a real host.
    """
    class _BrokenRestore(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawn_attempts = 0

        def spawn(self) -> Slot:
            self.spawn_attempts += 1
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    rt = _BrokenRestore()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        max_consecutive_failures=2, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0,   # isolate the trigger from the cooldown
    )

    for _ in range(12):
        pool.tick()

    assert rt.spawn_attempts >= 3, "expected the pool to keep retrying spawns"
    assert rt.base_invalidations >= 1, (
        "repeated restore failures must invalidate the base -- otherwise a corrupt base leaves "
        "the tier at zero capacity indefinitely and only a process restart recovers it"
    )


def test_a_successful_spawn_resets_the_restore_failure_streak() -> None:
    """Transient restore failures must not accumulate into a needless rebuild."""
    class _FlakyRestore(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def spawn(self) -> Slot:
            self.calls += 1
            if self.calls % 2 == 1:      # fail, succeed, fail, succeed, ...
                raise RuntimeError("transient restore failure")
            return super().spawn()

    rt = _FlakyRestore()
    pool = WarmPool(
        runtime=rt, warm_size=1, concurrent_ceiling=4,
        max_consecutive_failures=2, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0,
    )

    for _ in range(12):
        pool.tick()

    assert rt.base_invalidations == 0, (
        "alternating failure/success never reaches the consecutive threshold, so the base must "
        f"not be rebuilt (got {rt.base_invalidations})"
    )


def test_a_release_seam_degrades_against_a_pool_without_fault_attribution(tmp_path, monkeypatch):
    """The seam always forwarded fault=, so against a pool predating attribution EVERY rung of
    remote_http's fallback ladder raised TypeError again -- and the slot was never released at all.
    Degrade at the seam instead of making the caller retry (upstream, PR #82)."""
    import blastbox.host.runtime.remote_http as rh
    import blastbox.host.runtime.vm_dispatch as vd
    from blastbox.host.jobs.memory import InMemoryJobStore
    from tests.host.test_vm_dispatch import _FAKE_LIMITS

    captured: dict = {}

    def _fake(claim, release, **kw):  # noqa: ANN001
        captured["release"] = release
        return lambda *a, **k: None

    monkeypatch.setattr(rh, "make_remote_validate", _fake)

    seen: list = []

    class _OldPool:                        # no `fault` parameter at all
        runtime = type("R", (), {"ssl_context": None})()

        def claim(self, *, timeout_s):  # noqa: ANN001
            return None

        def release(self, slot, *, dirty=False):  # noqa: ANN001
            seen.append(dirty)

    vd.build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _OldPool(),
                                  tier="static", engine="clippyshot", limits=_FAKE_LIMITS)
    captured["release"](object(), True, "worker")
    assert seen == [True], f"the slot was never released against an old pool: {seen}"


def test_a_late_release_for_an_untracked_slot_books_nothing():
    """stop()/eviction can remove a slot while a job is still finishing. Recording health state
    then leaks an entry keyed on a dead slot_id and moves the POOL-wide counter on evidence from a
    slot that is no longer in the pool -- which can tip a base rebuild (upstream, PR #82)."""
    from blastbox.host.pool import Slot, SlotState, WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=1, max_consecutive_failures=2)
    orphan = Slot(slot_id="gone", control_dir="/c", input_dir="/i", output_dir="/o",
                  state=SlotState.ASSIGNED)          # never in _slots: already removed
    pool.release(orphan, dirty=True, fault="worker")
    assert "gone" not in pool._slot_failures, "leaked bookkeeping for an untracked slot"
    assert pool._pool_consecutive_failures == 0, (
        "a slot no longer in the pool moved the pool-wide failure counter")


def test_snapshot_rebuild_after_zero_actually_disables():
    """The comment said 0 disables while the code treated <=0 as 'derive a default', so rebuilds
    were on by default and could not be turned off at all (upstream, PR #82)."""
    from blastbox.host.pool import WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    assert WarmPool(runtime=_Rt(), warm_size=4, snapshot_rebuild_after=0)._snapshot_rebuild_after == 0
    assert WarmPool(runtime=_Rt(), warm_size=4, snapshot_rebuild_after=7)._snapshot_rebuild_after == 7
    assert WarmPool(runtime=_Rt(), warm_size=4)._snapshot_rebuild_after > 0      # None -> derived


def test_the_eviction_cap_holds_under_concurrent_burnouts():
    """The cap CHECKED the count and RECORDED it later, so two threads could both observe "under the
    limit" before either wrote. With max_evictions_per_window=1 a concurrent burnout reaped two
    slots. A cap that is not a cap is worse than none, because it is trusted (upstream, PR #82)."""
    import threading

    from blastbox.host.pool import Slot, SlotState, WarmPool

    reaped: list[str] = []
    lock = threading.Lock()

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            with lock:
                reaped.append(slot.slot_id)

        def recycle(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0, max_consecutive_failures=1,
                    max_evictions_per_window=1, eviction_window_s=10_000.0)
    slots = []
    for i in range(8):
        s = Slot(slot_id=f"s{i}", control_dir="/c", input_dir="/i", output_dir="/o",
                 state=SlotState.ASSIGNED)
        pool._slots[s.slot_id] = s
        slots.append(s)

    barrier = threading.Barrier(len(slots))

    def burn(s):
        barrier.wait()                      # all threads hit the cap check together
        pool.release(s, dirty=True, fault="worker")

    threads = [threading.Thread(target=burn, args=(s,)) for s in slots]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert len(reaped) <= 1, f"the cap was exceeded under concurrency: {reaped}"


def test_a_claim_lost_is_not_a_worker_wedge():
    """ClaimLost means a PEER already reclaimed or finished the job -- our claim outlived itself.
    Attributing it as a wedge let two stale attempts burn out a healthy slot (upstream, PR #82)."""
    import inspect

    import blastbox.host.runtime.remote_http as rh

    src = inspect.getsource(rh.make_remote_validate)
    claim_idx = src.index("except ClaimLost")
    # rindex, not index: an EARLIER try block handles local validation failures before any slot is
    # claimed, and matching that one compares against an unrelated handler.
    broad_idx = src.rindex("except Exception as exc")
    assert claim_idx < broad_idx, "ClaimLost must be handled BEFORE the broad worker attribution"
    tail = src[claim_idx:broad_idx]
    assert 'fault = "unknown"' in tail, "a lost claim was still attributed to the worker"


def test_file_ipc_warm_failures_are_attributed_to_the_worker():
    """The file-IPC warm dispatcher released without a fault, which defaults to "unknown" and never
    advances a slot toward eviction -- so FC/gVisor snapshot workers that time out or return
    unusable output were invisible to wedge detection entirely, and a poisoned base was never
    invalidated. Only the REMOTE path had been attributed (upstream, PR #82)."""
    import inspect

    from blastbox.host.dispatch import Dispatcher

    # Scan the whole class, not a character window around the first match: an explanatory comment
    # sits between the match and the call, so a narrow window missed a fix that was present.
    src = inspect.getsource(Dispatcher)
    assert "dirty=not warm_clean" in src, "the warm file-IPC release path moved; retarget this test"
    assert "fault=None if warm_clean else warm_fault" in src, (
        "the warm file-IPC release path does not attribute its failures, so wedge detection and "
        "base invalidation are dead for the snapshot runtimes")
    # ...and the attribution must DISCRIMINATE: a validated engine_error is the engine reporting on
    # the INPUT, so a run of malformed samples must not invalidate a healthy snapshot.
    assert 'warm_fault = "job"' in src, (
        "every non-DONE outcome is attributed to the worker, so bad samples advance the pool "
        "streak and can invalidate a healthy base")


def test_the_failure_streak_is_read_under_the_lock():
    """The release path must read the pool-wide streak LIVE and under the lock, not carry a value
    captured earlier: another slot can release cleanly and reset it in between, and the stale
    reading still invalidates the shared base, dropping a healthy warm snapshot after the pool has
    already recovered (upstream, PR #82).

    NB the remaining difference between a live read and a stale one is the lock itself, which only
    has an effect under real concurrency -- so this asserts the lock is genuinely taken rather than
    trying to stage the instruction-level race, which no deterministic test can reach."""
    import threading

    from blastbox.host.pool import WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=1)
    pool._pool_consecutive_failures = 7
    assert pool._current_failure_streak() == 7        # reads the CURRENT value

    entered = threading.Event()
    done = threading.Event()

    def reader():
        entered.set()
        pool._current_failure_streak()
        done.set()

    with pool._lock:                                   # hold it, so a locked read must block
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        assert entered.wait(2), "reader thread never started"
        assert not done.wait(0.3), (
            "the streak was read WITHOUT taking the lock, so it can tear against a concurrent "
            "release that is mid-update")
    assert done.wait(2), "the read never completed after the lock was released"
    t.join(timeout=2)


def _snapshot_pool(**kw):
    """A pool whose runtime exposes invalidate_base, so rebuild decisions are observable."""
    from blastbox.host.pool import WarmPool

    dropped: list[int] = []

    class _Rt:
        kind = "test"
        spawns = 0

        def spawn(self):
            from blastbox.host.pool import Slot, SlotState
            _Rt.spawns += 1
            raise RuntimeError("restore failed")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

        def invalidate_base(self):
            dropped.append(1)

    return WarmPool(runtime=_Rt(), **kw), dropped, _Rt


def test_gvisor_invalidate_base_reaches_the_snapshot_manager():
    """Only the direct FC runtime implemented invalidate_base, so for gVisor the pool's lookup
    always failed and sustained failures merely logged base_rebuild_unavailable while every
    replacement restored the poisoned snapshot until restart (upstream, PR #82)."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    dropped: list[int] = []

    class _Mgr:
        def invalidate(self):
            dropped.append(1)

        def ensure_build_started(self):
            pass

    rt = GvisorSnapshotSlotRuntime(_Mgr())
    assert hasattr(rt, "invalidate_base"), "gVisor has no invalidation seam at all"
    rt.invalidate_base()
    assert dropped == [1], "invalidate_base did not reach the snapshot manager"


def test_cascade_invalidate_base_reaches_every_wrapped_tier():
    """In production the pool holds the CASCADE, not the snapshot runtime, so without delegation
    the lookup fails and a poisoned base is never rebuilt (upstream, PR #82)."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime

    dropped: list[str] = []

    class _Tier:
        def __init__(self, name):
            self.name = name

        def invalidate_base(self):
            dropped.append(self.name)

    from blastbox.host.runtime.cascade import Tier

    # Construct it for real rather than object.__new__: invalidate_base now consults per-tier
    # failure evidence, and a half-built instance would only prove that a bypassed __init__
    # raises AttributeError.
    rt = CascadingRuntime(tiers=[
        Tier(name="fc", runtime=_Tier("fc"), capacity=1),
        Tier(name="gvisor", runtime=_Tier("gvisor"), capacity=1),
        Tier(name="seamless", runtime=object(), capacity=1),   # no seam -> skipped
    ])
    rt.invalidate_base()
    # No tier has recorded a failure, so there is nothing to attribute and every tier is repaired.
    assert dropped == ["fc", "gvisor"], f"delegation missed a tier: {dropped}"


def test_the_eviction_cap_follows_resize():
    """The derived budget was computed once from the constructor's warm_size, but the autosizer
    calls resize() in production -- a pool started at 16 and downsized to 1 still permitted 16
    evictions per window, when the cap is meant to bound damage to roughly one warm set."""
    from blastbox.host.pool import WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=16)
    assert pool._max_evictions_per_window == 16
    pool.resize(warm_size=1)
    assert pool._max_evictions_per_window == 2, (
        "the cap kept the pool's ORIGINAL size after a downsize")

    explicit = WarmPool(runtime=_Rt(), warm_size=16, max_evictions_per_window=3)
    explicit.resize(warm_size=1)
    assert explicit._max_evictions_per_window == 3, "an EXPLICIT cap must not be overwritten"


def test_the_spawn_batch_halts_after_invalidating_the_base():
    """With the artifact dropped, the very next runtime.spawn() runs SnapshotManager.build()
    SYNCHRONOUSLY and blocks the maintenance thread for a full base boot -- promotion, health
    checks and deferred reaping all stall behind it (upstream, PR #82)."""
    pool, dropped, rt = _snapshot_pool(warm_size=8, snapshot_rebuild_after=2,
                                       base_rebuild_cooldown_s=0.0)
    rt.spawns = 0
    pool._spawn_to_deficit(ready=True)
    assert dropped, "the base was never invalidated despite repeated spawn failures"
    assert rt.spawns <= 3, (
        f"the batch kept spawning after the rebuild ({rt.spawns} attempts) — the next one runs a "
        f"synchronous base build on the maintenance thread")


def test_a_capacity_miss_is_not_a_restore_failure() -> None:
    """A FULL pool must never be mistaken for a BROKEN one.

    CascadingRuntime.prepare() reports ready when ANY tier is ready, so spawn() legitimately
    raises CascadeExhausted while the ready tiers are saturated and a snapshot tier is still
    building. Counting that routine capacity miss toward the restore-failure streak invalidates
    a perfectly good base -- and does it precisely under sustained load, when a rebuild is the
    most expensive thing the pool could possibly do. Upstream, PR #82.
    """
    class _AlwaysFull(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawn_attempts = 0

        def spawn(self) -> Slot:
            self.spawn_attempts += 1
            raise CascadeExhausted("cascade: every tier is at capacity")

    rt = _AlwaysFull()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        max_consecutive_failures=2, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0,
        # The default token bucket allows only ~4 spawns before the loop runs dry, leaving the
        # assertion a margin of 4-vs-3 over the rebuild threshold -- it would measure the rate
        # limiter, not the fix, the moment either number moved.
        spawn_rate_limit=1000.0,
    )

    for _ in range(12):
        pool.tick()

    assert rt.spawn_attempts >= 12, "the pool must keep retrying -- capacity comes back"
    assert rt.base_invalidations == 0, (
        "a capacity miss must not invalidate the base; a busy pool would destroy and rebuild "
        f"its own base under load (got {rt.base_invalidations} invalidations)"
    )


def test_a_real_spawn_failure_still_invalidates_after_a_capacity_miss() -> None:
    """The capacity carve-out must not become a blanket amnesty.

    Guards the obvious over-correction: swallowing CascadeExhausted so broadly (or resetting the
    streak on it) that a genuinely corrupt base stops being repaired. Capacity misses are
    ignored; the real failures around them must still accumulate.
    """
    class _FullThenBroken(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawn_attempts = 0

        def spawn(self) -> Slot:
            self.spawn_attempts += 1
            # alternate: capacity miss, then a real restore failure
            if self.spawn_attempts % 2 == 1:
                raise CascadeExhausted("cascade: every tier is at capacity")
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    rt = _FullThenBroken()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        # NOT 2: a capacity miss BREAKS the batch, so only one real failure lands per tick and
        # the spawn circuit-breaker would trip before the rebuild threshold is ever reachable --
        # the test would then pass for the wrong reason (no spawns at all, not "no rebuild").
        max_consecutive_failures=50, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0,
        # Alternating means 6 attempts to reach a streak of 3, and the default token bucket only
        # holds ~4 -- the loop runs in microseconds so nothing refills. Without this the pool
        # simply stops spawning and the assertion measures the rate limiter, not the fix.
        spawn_rate_limit=1000.0,
    )

    for _ in range(24):
        pool.tick()

    assert rt.base_invalidations >= 1, (
        "interleaved capacity misses must not stop a genuinely corrupt base from being repaired"
    )


def test_resize_re_derives_every_threshold_computed_from_warm_size() -> None:
    """Both derived thresholds must follow the live target, not the constructor's.

    The node autosizer moves warm_size at runtime. A pool created at 16 and shrunk to 1 kept a
    rebuild threshold of 32 -- so a poisoned base on a now-tiny pool needed 32 consecutive
    failures instead of 4, i.e. effectively never. The eviction cap already re-derived; this is
    the sibling that did not. Upstream, PR #82.
    """
    pool = WarmPool(runtime=_WedgeableRuntime(), warm_size=16, concurrent_ceiling=32)
    assert pool._snapshot_rebuild_after == 32
    assert pool._max_evictions_per_window == 16

    pool.resize(warm_size=1)
    assert pool._snapshot_rebuild_after == 4, (
        "shrinking must lower the rebuild threshold -- otherwise a poisoned base on a 1-slot "
        f"pool is never repaired (got {pool._snapshot_rebuild_after})"
    )
    assert pool._max_evictions_per_window == 2

    pool.resize(warm_size=16)
    assert pool._snapshot_rebuild_after == 32, "growing must raise it back"


def test_an_explicit_rebuild_threshold_survives_resize() -> None:
    """Re-deriving must only touch values the pool derived ITSELF.

    An operator who pinned the threshold means it; silently recomputing over their value on the
    next autosizer tick is worse than the bug being fixed.
    """
    pool = WarmPool(
        runtime=_WedgeableRuntime(), warm_size=16, concurrent_ceiling=32,
        snapshot_rebuild_after=7, max_evictions_per_window=3,
    )
    pool.resize(warm_size=1)
    assert pool._snapshot_rebuild_after == 7, "an explicitly configured threshold must be kept"
    assert pool._max_evictions_per_window == 3


def test_a_static_pool_at_capacity_is_not_a_restore_failure() -> None:
    """The capacity contract must cover EVERY runtime that can legitimately be full.

    StaticPoolExhausted is the sibling of CascadeExhausted: all static workers busy is routine
    backpressure, not a broken base. Caught by mutation testing -- retyping it was a one-word
    change that nothing verified.
    """
    class _AllBusy(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawn_attempts = 0

        def spawn(self) -> Slot:
            self.spawn_attempts += 1
            raise StaticPoolExhausted("no free static worker is currently healthy")

    rt = _AllBusy()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        max_consecutive_failures=2, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(12):
        pool.tick()

    assert rt.spawn_attempts >= 3
    assert rt.base_invalidations == 0, (
        "a static pool with every worker busy must not invalidate the base "
        f"(got {rt.base_invalidations} invalidations)"
    )


def test_a_corrupt_base_behind_a_REAL_cascade_is_still_repaired() -> None:
    """The production topology, not a hand-rolled fake.

    Every other capacity test hands the pool a fake that raises CascadeExhausted directly, so
    none of them can see this: CascadingRuntime.spawn() swallows each tier's exception and
    re-raises CascadeExhausted for BOTH "all tiers full" and "every tier threw". Once the pool
    began treating capacity as a non-fault, that conflation silently disabled base repair for
    every cascaded deployment -- an unrestorable base sat at zero capacity until someone
    restarted the process, which is the outage the rebuild streak exists to prevent.

    Drives a real CascadingRuntime so the regression cannot come back through the fake.
    """
    class _CorruptBase(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawn_attempts = 0

        def prepare(self) -> bool:
            return True

        def spawn(self) -> Slot:
            self.spawn_attempts += 1
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    inner = _CorruptBase()
    pool = WarmPool(
        runtime=CascadingRuntime(tiers=[Tier(name="fc", runtime=inner, capacity=4)]),
        warm_size=2, concurrent_ceiling=4,
        max_consecutive_failures=50, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(24):
        pool.tick()

    assert inner.spawn_attempts >= 3
    assert inner.base_invalidations >= 1, (
        "a corrupt base behind a cascade must still be repaired -- otherwise the tier sits at "
        "zero capacity until the process is restarted"
    )


def test_a_genuinely_full_cascade_is_still_not_a_failure() -> None:
    """The other half of the split: a cascade whose tiers are FULL (nothing attempted, nothing
    threw) must remain a routine capacity miss."""
    class _Fine(_WedgeableRuntime):
        def prepare(self) -> bool:
            return True

    inner = _Fine()
    casc = CascadingRuntime(tiers=[Tier(name="fc", runtime=inner, capacity=1)])
    pool = WarmPool(
        runtime=casc, warm_size=8, concurrent_ceiling=8,
        max_consecutive_failures=50, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(24):
        pool.tick()

    assert inner.base_invalidations == 0, (
        "a cascade that is merely FULL must never invalidate the base "
        f"(got {inner.base_invalidations})"
    )


def test_sustained_capacity_starvation_escalates_above_debug(caplog) -> None:
    """"Not a fault" must not mean "unbounded and silent".

    Treating capacity as a non-fault removed the only operator-visible signal a starved pool ever
    produced (spawn_failed at ERROR). Without a floor, a permanently full or misconfigured cascade
    sits at zero warm capacity forever emitting nothing above DEBUG, and the only symptom is a
    sagging warm-hit rate. Mirrors how unknown_grace_s bounds the analogous UNKNOWN state.
    """
    clock = _FakeClock()

    class _AlwaysFull(_WedgeableRuntime):
        def spawn(self) -> Slot:
            raise CascadeExhausted("cascade: every tier is at capacity")

    pool = WarmPool(
        runtime=_AlwaysFull(), warm_size=2, concurrent_ceiling=4,
        clock=clock, capacity_starved_after_s=300.0,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )

    with caplog.at_level(logging.WARNING, logger="blastbox.host.pool"):
        pool.tick()
        assert not caplog.records, "brief backpressure must stay quiet"

        clock.advance(301.0)
        pool.tick()
        starved = [r for r in caplog.records if "spawn_capacity_starved" in r.getMessage()]
        assert len(starved) == 1, (
            f"sustained starvation must escalate above DEBUG (got {[r.getMessage() for r in caplog.records]})"
        )
        assert starved[0].levelno >= logging.ERROR

        # ...and must NOT repeat every tick, or it becomes noise an operator learns to ignore.
        clock.advance(600.0)
        pool.tick()
        pool.tick()
        assert len([r for r in caplog.records if "spawn_capacity_starved" in r.getMessage()]) == 1


def test_a_ceiling_only_resize_also_re_derives_the_thresholds() -> None:
    """The autosizer lowers the CEILING, not just warm_size.

    Deriving inside the `warm_size is not None` branch, and from the ARGUMENT rather than the
    clamped live value, left both holes open: a ceiling-only resize silently lowers the live warm
    target while the thresholds keep their old (much larger) values, and a warm_size above the
    ceiling derives for a size the pool never runs at. Either way a 1-slot pool waits 32
    consecutive failures to repair a poisoned base -- verbatim the defect this was meant to fix.
    """
    pool = WarmPool(runtime=_WedgeableRuntime(), warm_size=16, concurrent_ceiling=32)
    assert pool._snapshot_rebuild_after == 32

    # ceiling only -- warm_size is not passed at all
    pool.resize(concurrent_ceiling=1)
    assert pool._warm_size == 1, "the ceiling clamps the live warm target"
    assert pool._snapshot_rebuild_after == 4, (
        "a ceiling-only resize must re-derive too -- the live target moved "
        f"(got {pool._snapshot_rebuild_after})"
    )
    assert pool._max_evictions_per_window == 2

    # warm_size ABOVE the ceiling: derive from what the pool will actually run at, not the ask
    pool.resize(warm_size=64, concurrent_ceiling=8)
    assert pool._warm_size == 8
    assert pool._snapshot_rebuild_after == 16, (
        f"must derive from the clamped target (8), not the requested 64 "
        f"(got {pool._snapshot_rebuild_after})"
    )


def test_a_broken_primary_tier_is_repaired_even_when_fallback_succeeds() -> None:
    """Fallback is exactly what HIDES tier-level breakage.

    A snapshot primary whose base is poisoned raises on every spawn; a healthy overflow tier then
    satisfies the request, so CascadingRuntime.spawn() RETURNS a slot and the pool records a
    success — resetting the very streak that would have repaired the primary. The deployment then
    runs permanently on the lower-priority tier, at its cost and performance, with nothing above a
    per-attempt warning to say so. Only per-tier evidence can see this.
    """
    class _PoisonedPrimary(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        def prepare(self) -> bool:
            return True

        def spawn(self) -> Slot:
            self.attempts += 1
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    class _HealthyOverflow(_WedgeableRuntime):
        def prepare(self) -> bool:
            return True

    primary, overflow = _PoisonedPrimary(), _HealthyOverflow()
    casc = CascadingRuntime(
        tiers=[Tier(name="fc", runtime=primary, capacity=8),
               Tier(name="overflow", runtime=overflow, capacity=8)],
        tier_rebuild_after=4,
    )
    pool = WarmPool(
        runtime=casc, warm_size=4, concurrent_ceiling=8,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(6):
        pool.tick()

    assert primary.attempts >= 4, "the primary must keep being tried"
    assert primary.base_invalidations >= 1, (
        "a primary that fails every spawn must be repaired even though the overflow tier kept "
        "serving — otherwise the fallback silently becomes permanent"
    )
    assert overflow.base_invalidations == 0, "the HEALTHY tier's base must never be touched"


def test_a_healthy_tier_that_merely_loses_the_race_is_not_repaired() -> None:
    """The over-correction guard: per-tier repair must key on that tier's OWN failures."""
    class _Fine(_WedgeableRuntime):
        def prepare(self) -> bool:
            return True

    a, b = _Fine(), _Fine()
    casc = CascadingRuntime(
        tiers=[Tier(name="fc", runtime=a, capacity=1), Tier(name="overflow", runtime=b, capacity=8)],
        tier_rebuild_after=2,
    )
    pool = WarmPool(
        runtime=casc, warm_size=6, concurrent_ceiling=8,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(6):
        pool.tick()

    assert a.base_invalidations == 0 and b.base_invalidations == 0, (
        "a tier that is merely FULL has produced no failure evidence at all"
    )


def test_intermittent_tier_failures_do_not_accumulate_into_a_rebuild() -> None:
    """A tier's own successes must clear its own streak.

    Per-tier repair is only safe if the counter measures a SUSTAINED fault. Without the reset, a
    tier that fails occasionally — a transient restore hiccup, a brief resource pinch — slowly
    accumulates unrelated failures and eventually gets its perfectly good base destroyed, which
    is a strictly worse outage than the one per-tier repair exists to fix.
    """
    class _Flaky(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.n = 0

        def prepare(self) -> bool:
            return True

        def spawn(self) -> Slot:
            self.n += 1
            if self.n % 2 == 1:          # fail, succeed, fail, succeed …
                raise RuntimeError("transient restore hiccup")
            return super().spawn()

    flaky = _Flaky()
    casc = CascadingRuntime(tiers=[Tier(name="fc", runtime=flaky, capacity=8)],
                            tier_rebuild_after=3)
    pool = WarmPool(
        runtime=casc, warm_size=4, concurrent_ceiling=8,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(10):
        pool.tick()

    assert flaky.n >= 6, "the tier must actually have been exercised"
    assert flaky.base_invalidations == 0, (
        "intermittent failures interleaved with successes must never reach the rebuild "
        f"threshold (got {flaky.base_invalidations} invalidations)"
    )


@contextlib.contextmanager
def caplog_at_error():
    """Collect ERROR+ records from the pool logger (caplog is awkward across resize/tick)."""
    records: list[logging.LogRecord] = []

    class _Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    lg = logging.getLogger("blastbox.host.pool")
    h = _Grab(level=logging.ERROR)
    lg.addHandler(h)
    try:
        yield records
    finally:
        lg.removeHandler(h)


def test_an_idle_pool_does_not_bank_starvation_time() -> None:
    """The alert must measure CONTINUOUS starvation, not two unrelated autosizer epochs.

    The episode clock was cleared only by a successful spawn, so a pool whose target the
    autosizer shrank to zero kept a stale timestamp for however long it idled — and the first
    capacity miss after a later scale-up fired immediately, citing that entire idle interval as
    if the pool had been starving through it.
    """
    clock = _FakeClock()

    class _AlwaysFull(_WedgeableRuntime):
        def spawn(self) -> Slot:
            raise CascadeExhausted("cascade: every tier is at capacity")

    pool = WarmPool(
        runtime=_AlwaysFull(), warm_size=2, concurrent_ceiling=4,
        clock=clock, capacity_starved_after_s=300.0,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )

    with caplog_at_error() as records:
        pool.tick()                 # a brief miss opens an episode
        pool.resize(warm_size=0)    # autosizer removes the deficit: nothing is being asked for
        clock.advance(4000.0)       # ...and the pool idles for over an hour
        pool.tick()
        pool.resize(warm_size=2)    # scale back up
        pool.tick()                 # first miss of a NEW episode

        assert not [r for r in records if "spawn_capacity_starved" in r.getMessage()], (
            "an idle interval was banked as starvation — the alert fired on its first miss"
        )

        clock.advance(301.0)        # now genuinely starving, continuously
        pool.tick()
        assert [r for r in records if "spawn_capacity_starved" in r.getMessage()], (
            "real continuous starvation must still alert"
        )


def test_concurrent_failures_cannot_each_rebuild_off_one_streak() -> None:
    """The decision must be CONSUMED under the same lock that reads it.

    Reading the streak under the lock and deciding outside it leaves a window where two dispatch
    threads both see the same above-threshold value and each destroys the base — and a clean
    release landing in that window is ignored entirely, so a base a job just succeeded against
    is rebuilt anyway. Sequentially the two versions look identical (the rebuild path resets the
    counter afterwards either way), so only a concurrent test can tell them apart.

    The barrier is what forces the interleaving: with the fix the lock serialises the two
    threads, so the second never reaches the barrier and it times out; without it, both reach it
    holding the same stale value.
    """
    import threading

    rt = _WedgeableRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        snapshot_rebuild_after=2, base_rebuild_cooldown_s=0.0,
        spawn_rate_limit=1000.0,
    )
    with pool._lock:
        pool._pool_consecutive_failures = 2

    barrier = threading.Barrier(2, timeout=1.0)
    real_lock = pool._lock

    class _BarrieredLock:
        """Rendezvous on the way OUT of the streak read — reachable by both threads only if the
        decision is made outside the lock."""

        def __enter__(self):
            return real_lock.__enter__()

        def __exit__(self, *a):
            r = real_lock.__exit__(*a)
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait()
            return r

    pool._lock = _BarrieredLock()  # type: ignore[assignment]

    def _decide():
        with contextlib.suppress(Exception):
            pool._maybe_rebuild_base(reason="job")

    ts = [threading.Thread(target=_decide, daemon=True) for _ in range(2)]
    for th in ts:
        th.start()
    for th in ts:
        th.join(10.0)

    assert rt.base_invalidations == 1, (
        f"one failure episode must destroy the base at most once, got "
        f"{rt.base_invalidations} rebuilds off the same streak"
    )


def test_a_tier_at_capacity_does_not_become_a_cascade_spawn_failure() -> None:
    """A tier reporting CAPACITY must stay capacity all the way out of the cascade.

    The tier loop's broad handler caught RuntimeAtCapacity (a static fleet inside
    dirty_cooldown_s, a nested cascade that is full) and turned it into a tier failure —
    advancing the per-tier rebuild streak and, once every tier was exhausted, promoting the whole
    spawn to CascadeSpawnFailed. Routine backpressure would then invalidate healthy bases.
    """
    class _Full(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        def prepare(self) -> bool:
            return True

        def spawn(self) -> Slot:
            self.attempts += 1
            raise StaticPoolExhausted("all workers are within dirty_cooldown_s")

    tier_rt = _Full()
    casc = CascadingRuntime(tiers=[Tier(name="static", runtime=tier_rt, capacity=4)],
                            tier_rebuild_after=2)

    with pytest.raises(RuntimeAtCapacity):
        casc.spawn()          # must NOT be promoted to CascadeSpawnFailed

    pool = WarmPool(
        runtime=casc, warm_size=2, concurrent_ceiling=4,
        snapshot_rebuild_after=2, base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    for _ in range(12):
        pool.tick()

    assert tier_rt.attempts >= 3, "the pool must keep retrying — capacity comes back"
    assert tier_rt.base_invalidations == 0, (
        f"a cooling tier must not destroy any base (got {tier_rt.base_invalidations})"
    )


def test_construction_derives_thresholds_from_the_feasible_target() -> None:
    """warm_size above the ceiling is a target the pool can never reach.

    PoolConfig permits it, and the pool then runs at the ceiling — so warm_size=16 with
    ceiling=1 waited 32 consecutive failures before repairing a poisoned base and allowed 16
    evictions per window on a ONE-slot pool. resize() clamped and re-derived; construction did
    neither, so the two disagreed until some later resize happened to correct it.
    """
    pool = WarmPool(runtime=_WedgeableRuntime(), warm_size=16, concurrent_ceiling=1)
    assert pool._warm_size == 1
    assert pool._snapshot_rebuild_after == 4, (
        f"must derive from the feasible target (1), not the requested 16 "
        f"(got {pool._snapshot_rebuild_after})"
    )
    assert pool._max_evictions_per_window == 2

    # and construction must agree with resize for the same effective target
    other = WarmPool(runtime=_WedgeableRuntime(), warm_size=16, concurrent_ceiling=32)
    other.resize(warm_size=16, concurrent_ceiling=1)
    assert (other._snapshot_rebuild_after, other._max_evictions_per_window) == (
        pool._snapshot_rebuild_after, pool._max_evictions_per_window
    ), "construction and resize must derive identically for the same effective target"


def test_no_headroom_with_a_real_deficit_still_counts_as_starvation() -> None:
    """Zero usable capacity is exactly what the alert is for.

    to_spawn is zero in two very different situations: there is no deficit (fine), and there IS a
    deficit but no headroom — which is what happens when failed reaps leave DRAINING slots
    occupying concurrent_ceiling. Keying the episode reset on to_spawn cleared the clock on every
    tick in the second case, so a pool with no usable capacity could never report it.
    """
    clock = _FakeClock()

    class _UnreapableRuntime(_WedgeableRuntime):
        def reap(self, slot: Slot) -> None:
            raise RuntimeError("reap failed; the slot stays DRAINING")

    rt = _UnreapableRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=2, clock=clock,
        capacity_starved_after_s=300.0, base_rebuild_cooldown_s=0.0,
        spawn_rate_limit=1000.0,
    )
    pool.tick()
    # wedge every slot into DRAINING: they still occupy the ceiling but do not count as active
    for s in list(pool._slots.values()):
        s.state = SlotState.DRAINING

    with caplog_at_error() as records:
        pool.tick()
        clock.advance(301.0)
        pool.tick()
        starved = [r for r in records if "spawn_capacity_starved" in r.getMessage()]
        assert starved, (
            "a pool whose ceiling is full of DRAINING slots has zero usable capacity and must "
            "report it, not silently reset its own clock every tick"
        )


def test_a_healthy_but_full_tier_keeps_its_base_when_a_sibling_fails() -> None:
    """Repair must follow the evidence, not the blast radius.

    When one snapshot tier throws repeatedly while a later healthy tier is merely FULL, the spawn
    still ends as CascadeSpawnFailed, so the pool's global streak asks the cascade to invalidate —
    and invalidating every wrapped base destroys the healthy tier's snapshot during ordinary
    saturation, despite it producing no failure evidence at all. The failing tier is already
    tracked and repaired per-tier.
    """
    class _Broken:
        def __init__(self) -> None:
            self.invalidated = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

        def invalidate_base(self) -> None:
            self.invalidated += 1

    class _HealthyButFull:
        def __init__(self) -> None:
            self.invalidated = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            raise StaticPoolExhausted("every worker is claimed")

        def invalidate_base(self) -> None:
            self.invalidated += 1

    broken, full = _Broken(), _HealthyButFull()
    casc = CascadingRuntime(
        tiers=[Tier(name="fc", runtime=broken, capacity=4),
               Tier(name="static", runtime=full, capacity=4)],
        tier_rebuild_after=1000,   # isolate from per-tier repair; test the cascade-level call
    )
    with contextlib.suppress(Exception):
        casc.spawn()               # records failure evidence against 'fc' only

    with contextlib.suppress(Exception):
        casc.invalidate_base(reason="spawn")   # spawn-driven: the trigger IS attributable

    assert broken.invalidated >= 1, "the tier that actually failed must be repaired"
    assert full.invalidated == 0, (
        "a tier that was merely FULL produced no failure evidence and must keep its base"
    )


def test_a_stalled_snapshot_build_still_reports_starvation() -> None:
    """"Not ready" is not a reason to stop watching.

    A stuck or repeatedly-failing snapshot build keeps prepare() False forever, and the spawn
    path bailed out before any starvation bookkeeping — so a pool with a positive target and zero
    slots never touched the capacity meter or the clock, even though "a snapshot tier stuck
    building" is one of the causes the alert message itself names.
    """
    clock = _FakeClock()
    rt = _WedgeableRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4, clock=clock,
        capacity_starved_after_s=300.0, base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )

    with caplog_at_error() as records:
        pool._spawn_to_deficit(ready=False)          # build not ready
        assert not [r for r in records if "spawn_capacity_starved" in r.getMessage()]

        clock.advance(301.0)
        pool._spawn_to_deficit(ready=False)
        assert [r for r in records if "spawn_capacity_starved" in r.getMessage()], (
            "a pool at zero capacity behind a stalled build must report it"
        )


def test_slots_that_never_become_ready_count_toward_base_repair() -> None:
    """A spawn that returns a slot which then dies produced no usable worker.

    The successful spawn reset the failure streak, and _health_check reaped the timed-out WARMING
    slot without incrementing anything — so a base poisoned just enough to restore-and-then-die
    cycled restore, warmup timeout and replace forever, and invalidate_base() was never reached.
    """
    clock = _FakeClock()

    class _RestoresButNeverReady(_WedgeableRuntime):
        def is_ready(self, slot: Slot) -> bool:
            return False          # restores fine, never becomes usable

    rt = _RestoresButNeverReady()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4, clock=clock,
        warming_timeout_s=10.0, snapshot_rebuild_after=2,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )

    for _ in range(6):
        pool.tick()
        clock.advance(11.0)       # every warmup times out

    assert rt.base_invalidations >= 1, (
        "a base that restores but never yields a ready worker must still be repaired "
        f"(got {rt.base_invalidations} invalidations)"
    )


def test_a_validated_engine_error_clears_the_worker_streaks() -> None:
    """"Consecutive" has to mean consecutive.

    A structurally valid engine_error is POSITIVE evidence: the worker ran, and the base it
    restored from is responsive. Leaving the streaks untouched meant a timeout, then any number of
    valid engine errors, then another timeout read as two CONSECUTIVE worker failures — evicting a
    healthy slot or invalidating a good base on two unrelated events an hour apart. The slot is
    still force-recycled; only the health streaks reset.
    """
    rt = _WedgeableRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=3, concurrent_ceiling=6,
        max_consecutive_failures=2, snapshot_rebuild_after=2,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    pool.tick()
    slots = list(pool._slots.values())
    assert len(slots) >= 3

    pool.release(slots[0], dirty=True, fault="worker")     # one genuine worker failure
    pool.release(slots[1], dirty=True, fault="job")        # the worker demonstrably RAN
    pool.tick()
    fresh = [s for s in pool._slots.values() if s.slot_id not in
             {slots[0].slot_id, slots[1].slot_id}]
    pool.release(fresh[0], dirty=True, fault="worker")     # a later, unrelated failure

    assert rt.base_invalidations == 0, (
        "two worker failures separated by proof the worker was healthy are not consecutive "
        f"(got {rt.base_invalidations} rebuilds)"
    )


def test_a_warmup_triggered_rebuild_defers_spawning_to_the_next_tick() -> None:
    """A synchronous build() on the maintenance thread stalls everything behind it.

    tick() captures `ready` BEFORE _health_check runs, so a rebuild triggered by timed-out
    warmups would walk straight into spawn() -> SnapshotManager.build(), blocking the pool's only
    maintenance thread for a full base boot plus readiness timeout — promotion, health checks and
    deferred reaping all stall. The spawn-failure path already halts its batch for this reason.
    """
    clock = _FakeClock()

    class _RestoresButNeverReady(_WedgeableRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.spawns_after_invalidate = 0

        def is_ready(self, slot: Slot) -> bool:
            return False

        def spawn(self) -> Slot:
            if self.base_invalidations:
                self.spawns_after_invalidate += 1
            return super().spawn()

    rt = _RestoresButNeverReady()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4, clock=clock,
        warming_timeout_s=10.0, snapshot_rebuild_after=2,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    pool.tick()
    clock.advance(11.0)
    pool.tick()                     # warmups time out -> streak -> invalidate

    assert rt.base_invalidations >= 1, "sanity: the rebuild must have been triggered"
    assert rt.spawns_after_invalidate == 0, (
        "the pool spawned in the same tick it invalidated the base — that call runs build() "
        "synchronously and stalls the maintenance thread"
    )


def test_a_repaired_tier_stays_attributable_for_the_pools_own_repair() -> None:
    """Per-tier repair must not erase the evidence the pool is about to consult.

    _maybe_repair_tier resets that tier's streak to give the rebuild a window. The pool reaches
    its own threshold a moment later and calls invalidate_base(), which filters on the guilty
    set — so clearing the only marker first left that set empty, the global repair fell back to
    every tier, and healthy merely-saturated siblings lost their bases. Exactly what the
    guilty-set filter was added to prevent.
    """
    class _Broken:
        def __init__(self) -> None:
            self.invalidated = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            raise RuntimeError("snapshot restore failed: corrupt warm.mem")

        def invalidate_base(self) -> None:
            self.invalidated += 1

    class _HealthyButFull:
        def __init__(self) -> None:
            self.invalidated = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            raise StaticPoolExhausted("every worker is claimed")

        def invalidate_base(self) -> None:
            self.invalidated += 1

    broken, full = _Broken(), _HealthyButFull()
    casc = CascadingRuntime(
        tiers=[Tier(name="fc", runtime=broken, capacity=4),
               Tier(name="static", runtime=full, capacity=4)],
        tier_rebuild_after=1,      # repair (and reset the streak) on the FIRST failure
    )
    with contextlib.suppress(Exception):
        casc.spawn()
    assert broken.invalidated == 1, "sanity: per-tier repair fired and cleared the streak"

    # The pool now makes its own global decision, with the tier streak already reset to 0.
    with contextlib.suppress(Exception):
        casc.invalidate_base(reason="spawn")   # spawn-driven: the trigger IS attributable

    assert full.invalidated == 0, (
        "a healthy, merely-saturated tier lost its base because the guilty marker was cleared "
        "by the per-tier repair before the pool's own repair consulted it"
    )


def test_a_success_during_the_decision_abandons_the_rebuild() -> None:
    """A base that just produced a valid result must not be destroyed.

    Consuming the streak closed the read/decide gap, but drop() still runs outside the lock. A
    clean release landing in THAT window is proof the base works, so rebuilding it is an
    unnecessary outage during recovery. The gate is an episode token captured with the decision.

    The barrier forces the interleaving deterministically: the decision thread waits inside the
    window for a clean release to complete.
    """
    import threading

    rt = _WedgeableRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        snapshot_rebuild_after=2, base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    pool.tick()
    good = list(pool._slots.values())[0]
    with pool._lock:
        pool._pool_consecutive_failures = 2      # at the threshold

    released = threading.Event()
    real_lock = pool._lock

    class _GatedLock:
        """After the decision's locked section exits, let a clean release land before drop()."""

        def __init__(self) -> None:
            self._armed = True

        def __enter__(self):
            return real_lock.__enter__()

        def __exit__(self, *a):
            r = real_lock.__exit__(*a)
            if self._armed:
                self._armed = False
                threading.Thread(
                    target=lambda: (pool.release(good, dirty=False), released.set()),
                    daemon=True,
                ).start()
                released.wait(5.0)
            return r

    pool._lock = _GatedLock()  # type: ignore[assignment]
    rebuilt = pool._maybe_rebuild_base(reason="job")

    assert released.is_set(), "the racing clean release never ran — the test proved nothing"
    assert rebuilt is False and rt.base_invalidations == 0, (
        "the base produced a valid result while the failure was being judged, and was rebuilt "
        f"anyway (invalidations={rt.base_invalidations})"
    )


def test_a_job_driven_repair_is_not_narrowed_by_stale_spawn_guilt() -> None:
    """Only a SPAWN-triggered repair carries tier attribution.

    A job-triggered one does not: the failures came from whichever tier served those jobs, which
    the cascade cannot know. Filtering it through a spawn marker meant tier A's stale guilt
    selected A while the actual offender B kept its poisoned base — and the pool recorded a
    rebuild and started its cooldown regardless, delaying the next attempt.
    """
    class _Tier:
        def __init__(self) -> None:
            self.invalidated = 0
            self.n = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            # B must SUCCEED, or it gets marked guilty by the same spawn and the assertion below
            # becomes meaningless.
            self.n += 1
            return SimpleNamespace(slot_id=f"b{self.n}")

        def invalidate_base(self) -> None:
            self.invalidated += 1

    class _BrokenSpawn(_Tier):
        def spawn(self):
            raise RuntimeError("snapshot restore failed")

    a, b = _BrokenSpawn(), _Tier()
    casc = CascadingRuntime(
        tiers=[Tier(name="a", runtime=a, capacity=4), Tier(name="b", runtime=b, capacity=4)],
        tier_rebuild_after=1,
    )
    casc.spawn()                           # A fails and is marked guilty; B serves the request
    assert a.invalidated == 1, "sanity: per-tier repair marked A"
    assert b.invalidated == 0, "sanity: B succeeded and is not guilty"

    # Now a JOB-driven repair: the failing jobs ran on B, which the cascade cannot know.
    casc.invalidate_base(reason="job")

    assert b.invalidated == 1, (
        "a job-driven repair has no tier attribution and must not be narrowed to a tier whose "
        "guilt came from an unrelated SPAWN failure — B's poisoned base was left untouched"
    )


def test_sequential_warmup_failures_still_reach_the_rebuild_threshold() -> None:
    """The one-slot pool is where the previous fix silently did nothing.

    Counting timed-out warmups only helps if the count SURVIVES. A spawn that merely returns was
    clearing the streak, so with warm_size=1 each failure bumped it to 1 and the replacement's
    spawn immediately reset it: a base that consistently restores but never yields a ready worker
    cycled at a streak of one forever and never reached snapshot_rebuild_after. Only reaching
    IDLE is proof the base works.
    """
    clock = _FakeClock()

    class _RestoresButNeverReady(_WedgeableRuntime):
        def is_ready(self, slot: Slot) -> bool:
            return False

    rt = _RestoresButNeverReady()
    pool = WarmPool(
        runtime=rt, warm_size=1, concurrent_ceiling=2, clock=clock,
        warming_timeout_s=10.0, snapshot_rebuild_after=3,
        base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )

    for _ in range(8):
        pool.tick()
        clock.advance(11.0)     # one slot, one timeout, one replacement, each tick

    assert rt.base_invalidations >= 1, (
        "sequential warmup failures on a one-slot pool never accumulated — the replacement "
        f"spawn kept clearing the streak (got {rt.base_invalidations} invalidations)"
    )


def test_the_pool_forwards_the_repair_trigger_to_the_runtime() -> None:
    """The cascade can only attribute a repair if the pool tells it what triggered one.

    Testing the cascade directly proves the filter works; it does not prove the pool passes the
    trigger at all. Without that, every repair looks unattributed and the guilty-set filter is
    dead code.
    """
    seen: list[object] = []

    class _RecordingRuntime(_WedgeableRuntime):
        def invalidate_base(self, *, reason=None) -> None:  # type: ignore[override]
            seen.append(reason)
            super().invalidate_base()

    rt = _RecordingRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        snapshot_rebuild_after=1, base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    pool.tick()
    slot = list(pool._slots.values())[0]
    pool.release(slot, dirty=True, fault="worker")     # a JOB-path failure

    assert seen == ["job"], f"the pool must forward the trigger it acted on (got {seen})"


def test_a_failed_invalidation_keeps_its_episode() -> None:
    """The streak is consumed to make the decision, so a failed repair must give it back.

    Otherwise a transient backend/cleanup error makes the poisoned base wait for another full
    snapshot_rebuild_after worker failures before retrying — every one of which is a failed job.
    """
    class _InvalidateFails(_WedgeableRuntime):
        def invalidate_base(self, *, reason=None) -> None:  # type: ignore[override]
            raise RuntimeError("snapshot cleanup failed")

    rt = _InvalidateFails()
    pool = WarmPool(
        runtime=rt, warm_size=2, concurrent_ceiling=4,
        snapshot_rebuild_after=2, base_rebuild_cooldown_s=0.0, spawn_rate_limit=1000.0,
    )
    with pool._lock:
        pool._pool_consecutive_failures = 2

    assert pool._maybe_rebuild_base(reason="job") is False
    with pool._lock:
        streak = pool._pool_consecutive_failures
    assert streak >= 2, (
        f"a repair that did not happen consumed its episode anyway — the base now waits for a "
        f"whole new streak (got {streak})"
    )


def test_a_failed_tier_repair_keeps_its_streak() -> None:
    """The streak is cleared to give a successful rebuild a window — so a FAILED one must give it back.

    Behind a working fallback tier the broken tier may be attempted rarely, so demanding another
    full threshold after a transient invalidation error can mean never retrying at all. The pool's
    own repair already restores its episode; this is the sibling that did not.
    """
    class _BrokenAndUnrepairable:
        def __init__(self) -> None:
            self.attempts = 0
            self.invalidate_attempts = 0

        def prepare(self) -> bool:
            return True

        def spawn(self):
            self.attempts += 1
            raise RuntimeError("snapshot restore failed")

        def invalidate_base(self) -> None:
            self.invalidate_attempts += 1
            raise RuntimeError("snapshot cleanup failed")

    rt = _BrokenAndUnrepairable()
    casc = CascadingRuntime(tiers=[Tier(name="fc", runtime=rt, capacity=4)],
                            tier_rebuild_after=2)

    for _ in range(4):
        with contextlib.suppress(Exception):
            casc.spawn()

    # With the streak restored, EVERY subsequent failure re-attempts the repair. Without it, the
    # tier would need two more failures before trying again.
    assert rt.invalidate_attempts >= 3, (
        f"a failed repair discarded its streak, so the broken tier waits a whole new threshold "
        f"before retrying (repair attempts: {rt.invalidate_attempts} over {rt.attempts} spawns)"
    )


def test_a_slot_claimed_during_escalation_is_not_disposed() -> None:
    """The load-bearing guard is the DRAIN re-check, and it was untested.

    Sweeping for "decide under the lock, act outside it" turned up the unknown-escalation path:
    it read the stamp under the lock and escalated after releasing it, so a claim() could take the
    slot in that window and the pass would still add it to `dead`. That shape is now tightened —
    but it was never observable, because the drain step re-checks state under the lock and only
    transitions slots still IDLE/WARMING. This test pins THAT guard, which is what actually keeps
    a job-serving slot alive, and which nothing covered.
    """
    import threading

    clock = _FakeClock()

    class _UnknownRuntime(_WedgeableRuntime):
        def is_alive(self, slot: Slot):
            return None            # the BACKGROUND probe cannot tell — UNKNOWN, never a verdict

        def is_alive_for_claim(self, slot: Slot, budget_s=None):
            # ...but the claim path's own fresh probe says the worker is fine. That asymmetry is
            # the realistic case: a control-plane brownout makes the sweep unknown while the box
            # itself answers.
            return True

    rt = _UnknownRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=1, concurrent_ceiling=2, clock=clock,
        unknown_grace_s=10.0, spawn_rate_limit=1000.0,
    )
    pool.tick()
    for s in pool._slots.values():
        s.state = SlotState.IDLE

    pool._health_check()          # opens the unknown episode
    clock.advance(11.0)           # past the grace: this pass escalates

    claimed: list[object] = []
    real_lock = pool._lock

    class _GatedLock:
        """Let a claim land in the escalation window. Armed by the setdefault below rather than
        on the first exit: _health_check takes this lock several times, and arming on the first
        fires long before the window."""

        def __init__(self) -> None:
            self.armed = False

        def __enter__(self):
            return real_lock.__enter__()

        def __exit__(self, *a):
            r = real_lock.__exit__(*a)
            if self.armed:
                self.armed = False
                th = threading.Thread(
                    target=lambda: claimed.append(pool.claim(timeout_s=1.0)), daemon=True
                )
                th.start()
                th.join(5.0)
            return r

    gate = _GatedLock()

    class _ArmingStamps(dict):
        def setdefault(self, *a, **kw):
            gate.armed = True
            return super().setdefault(*a, **kw)

    pool._unknown_since = _ArmingStamps(pool._unknown_since)  # type: ignore[assignment]
    pool._lock = gate  # type: ignore[assignment]
    pool._health_check()
    pool._lock = real_lock

    assert claimed and claimed[0] is not None, (
        "the racing claim never took the slot — the test proved nothing"
    )
    got = claimed[0]
    assert got.state == SlotState.ASSIGNED, (
        f"a slot handed to a job was drained mid-flight (state={got.state})"
    )
    assert got.slot_id in pool._slots, "the claimed slot was disposed while serving a job"
