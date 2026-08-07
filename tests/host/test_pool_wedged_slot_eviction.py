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

import logging


class _FakeClock:
    """Local copy -- cross-test-module imports don't resolve under this layout."""
    def __init__(self, t: float = 0.0) -> None:
        self._t = t

    def __call__(self) -> float:
        return self._t

    def advance(self, delta: float) -> None:
        self._t += delta


from blastbox.host.runtime.cascade import CascadeExhausted, CascadingRuntime, Tier
from blastbox.host.runtime.static_pool import StaticPoolExhausted
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

    rt = object.__new__(CascadingRuntime)
    rt.tiers = [SimpleNamespace(runtime=_Tier("fc")), SimpleNamespace(runtime=_Tier("gvisor")),
                SimpleNamespace(runtime=object())]      # a tier with no seam must be skipped
    CascadingRuntime.invalidate_base(rt)
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
