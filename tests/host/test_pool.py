"""TDD tests for blastbox.host.pool — WarmPool core.

All 9 tests from the slice plan.  A _FakeRuntime drives spawn/ready/alive/reap
deterministically; a fake clock drives rate-limit/timeout logic.  The background
thread is exercised only in test_9_stop_thread, keeping all other tests
synchronous via tick().
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from uuid import uuid4

from blastbox.host.pool import SlotState, Slot, WarmPool


# ---------------------------------------------------------------------------
# Fake runtime
# ---------------------------------------------------------------------------


class _FakeRuntime:
    """Deterministic SlotRuntime for testing.

    Per-slot knobs:
        ready_after_ticks[slot_id]   -- slot becomes ready after N is_ready calls
        alive[slot_id]               -- liveness toggle (default True after spawn)
        reaped                       -- set of reaped slot_ids
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ready_after: dict[str, int] = {}  # slot_id -> ticks remaining
        self._alive: dict[str, bool] = {}
        self.reaped: list[str] = []
        self._default_ready_after: int = 0  # 0 = ready immediately

    def set_default_ready_after(self, ticks: int) -> None:
        with self._lock:
            self._default_ready_after = ticks

    def set_alive(self, slot_id: str, alive: bool) -> None:
        with self._lock:
            self._alive[slot_id] = alive

    def spawn(self) -> Slot:
        slot_id = str(uuid4())
        with self._lock:
            self._ready_after[slot_id] = self._default_ready_after
            self._alive[slot_id] = True
        return Slot(
            slot_id=slot_id,
            control_dir=Path(f"/fake/ctrl/{slot_id}"),
            input_dir=Path(f"/fake/in/{slot_id}"),
            output_dir=Path(f"/fake/out/{slot_id}"),
            state=SlotState.WARMING,
            spawned_at=0.0,
        )

    def is_ready(self, slot: Slot) -> bool:
        with self._lock:
            remaining = self._ready_after.get(slot.slot_id, 0)
            if remaining <= 0:
                return True
            self._ready_after[slot.slot_id] = remaining - 1
            return False

    def is_alive(self, slot: Slot) -> bool:
        with self._lock:
            return self._alive.get(slot.slot_id, False)

    def reap(self, slot: Slot) -> None:
        with self._lock:
            self._alive[slot.slot_id] = False
            self.reaped.append(slot.slot_id)


class _ReapFailRuntime(_FakeRuntime):
    """Models a runtime whose reap() RAISES because it couldn't dispose the worker (e.g. a libvirt VM
    whose `virsh destroy` failed and may still be running)."""

    def reap(self, slot: Slot) -> None:
        raise RuntimeError("destroy failed; worker may still be running")


def test_spawn_completing_after_stop_is_reaped_not_leaked() -> None:
    # a slow spawn (AWS run-instances/run-microvm, up to 120s) can finish AFTER stop() snapshotted
    # _slots. Publishing it then would leak a live cloud instance -> reap it instead.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._stop_event.set()                 # shutdown already in progress
    pool._spawn_to_deficit(ready=True)     # a spawn completes while stopping
    assert len(rt.reaped) == 1             # the just-created slot was reaped...
    assert not pool._slots                 # ...and never published (no leak)


def test_claim_prefers_fresh_liveness_when_runtime_provides_it() -> None:
    # H2: at hand-out the pool must prefer is_alive_for_claim (a FRESH check) over the possibly-cached
    # is_alive, so a slot the cached is_alive still reports alive -- but which AWS terminated since -- is
    # dropped+replaced instead of assigned to a user job.
    class _FreshRuntime(_FakeRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.claim_checks = 0

        def is_alive(self, slot: Slot) -> bool:
            return True                       # background/tick view: still (cached) alive

        def is_alive_for_claim(self, slot: Slot) -> bool:
            self.claim_checks += 1
            return False                      # fresh view: terminated since the last tick

    rt = _FreshRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    next(iter(pool._slots.values())).state = SlotState.IDLE   # make it claimable
    assert pool._try_claim_one() is None      # dead-at-claim slot dropped, nothing handed out
    assert rt.claim_checks == 1               # used the FRESH hand-out check, not is_alive


def test_stop_budget_covers_spawn_plus_reap() -> None:
    # #2: the default shutdown budget must cover an in-flight spawn (cli_timeout_s) PLUS its terminate
    # (another cli_timeout_s) + margin -- else a slow AWS spawn racing stop() leaves too little for the
    # terminate and the process exits mid-reap, leaking the worker.
    class _CfgRt(_FakeRuntime):
        cfg = type("C", (), {"cli_timeout_s": 120.0})()

    assert WarmPool(runtime=_CfgRt(), warm_size=1)._default_stop_budget() == 270.0   # 2*120 + 30
    assert WarmPool(runtime=_FakeRuntime(), warm_size=1)._default_stop_budget() == 150.0   # floor (no cli)


def test_stop_waits_for_inflight_spawn_then_reaps() -> None:
    # G1: a spawn racing stop() (not yet in _slots) must be disposed by the daemon's post-spawn reap
    # BEFORE stop() returns -- else the CLII's sys.exit() right after stop() kills the daemon and leaks the
    # live cloud instance. So stop() blocks (bounded) on the in-flight tick.
    entered, release = threading.Event(), threading.Event()

    class _SlowSpawn(_FakeRuntime):
        def spawn(self) -> Slot:
            entered.set()
            release.wait(timeout=5)
            return super().spawn()

    rt = _SlowSpawn()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.start()
    assert entered.wait(timeout=5)                 # daemon is inside spawn() (in-flight, not yet published)
    st = threading.Thread(target=lambda: pool.stop(stop_timeout_s=10.0))
    st.start()
    time.sleep(0.3)
    assert st.is_alive()                           # stop() is WAITING for the in-flight spawn, not returning
    release.set()                                  # let spawn finish -> daemon's post-spawn reap runs
    st.join(timeout=5)
    assert not st.is_alive()
    assert len(rt.reaped) == 1                      # the raced slot was reaped, not leaked
    assert not pool._slots


def test_stop_fast_path_returns_promptly() -> None:
    # G1: a clean shutdown (no spawn in flight) must NOT wait the stop_timeout_s ceiling.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.start()
    time.sleep(0.3)
    t0 = time.monotonic()
    pool.stop(stop_timeout_s=100.0)
    assert time.monotonic() - t0 < 5.0             # returned fast, didn't burn the 100s ceiling


def test_stop_is_bounded_when_spawn_wedged() -> None:
    # G1: a spawn that never returns must not hang shutdown -- stop() gives up after ~stop_timeout_s.
    entered, never = threading.Event(), threading.Event()

    class _WedgedSpawn(_FakeRuntime):
        def spawn(self) -> Slot:
            entered.set()
            never.wait(timeout=10)                 # not released by the test; daemon exits after 10s
            return super().spawn()

    rt = _WedgedSpawn()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.start()
    assert entered.wait(timeout=5)
    t0 = time.monotonic()
    orphans = pool.stop(stop_timeout_s=1.0)
    dt = time.monotonic() - t0
    assert 0.8 < dt < 5.0                           # gave up ~1s (the ceiling), did NOT hang for 10s
    # ...and the in-flight spawn is REPORTED as an orphan. It isn't in _slots yet, so len(_slots)
    # can't see it — the +1 for a wedged thread is the only thing that keeps the caller's node-budget
    # reservation alive for a worker that may still come up. (Previously untested: dropping the +1
    # left the suite green while stop() under-reported and peers reallocated its RAM.)
    assert orphans >= 1, f"wedged spawn must be counted as an orphan, got {orphans}"


def test_after_stop_spawn_tracks_slot_when_reap_fails() -> None:
    # G4: a slow spawn (AWS run-instances/run-microvm) can finish AFTER stop() flipped _stop_event; the
    # slot is reaped while still untracked. If that terminate RAISES (the cloud resource may persist), the
    # husk must be TRACKED as DRAINING for accounting/manual cleanup -- not silently leaked off the books,
    # matching every other reap-failure path (release/health/stop).
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._stop_event.set()                 # shutdown already in progress
    pool._spawn_to_deficit(ready=True)     # a spawn completes while stopping; its reap raises
    assert len(pool._slots) == 1           # tracked, not leaked
    assert next(iter(pool._slots.values())).state == SlotState.DRAINING   # quarantined husk


def test_release_quarantines_slot_when_reap_fails() -> None:
    # a reap that RAISES (worker not disposed) must NOT pop the slot — keep it tracked/quarantined so
    # it counts against the ceiling and surfaces, instead of orphaning a live worker off the books.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    pool.release(slot)
    assert slot.slot_id in pool._slots                       # NOT popped — quarantined
    assert pool._slots[slot.slot_id].state == SlotState.DRAINING


def test_reap_and_count_skips_concurrent_double_dispose() -> None:
    # stop()'s bounded thread-join can expire while the background tick is still mid-reap of a slow AWS
    # terminate; both paths must NOT run a SECOND concurrent terminate on the same live cloud resource.
    # The _reaping guard makes EXACTLY ONE path dispose a slot that is already being reaped.
    entered, release = threading.Event(), threading.Event()

    class _BlockingReapRuntime(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            entered.set()
            release.wait(timeout=5)
            super().reap(slot)

    rt = _BlockingReapRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    slot = rt.spawn()
    owner_ret: list[bool] = []
    t = threading.Thread(target=lambda: owner_ret.append(pool._reap_and_count(slot)), daemon=True)
    t.start()
    assert entered.wait(timeout=5)     # first reap in-flight -> slot in _reaping
    # concurrent second dispose must be a no-op that reports it did NOT dispose (False) -- so the caller
    # leaves the slot tracked instead of popping a slot whose real terminate might still fail.
    assert pool._reap_and_count(slot) is False
    assert rt.reaped == []             # second call did NOT invoke a real reap (first still blocked)
    release.set()
    t.join(timeout=5)
    assert rt.reaped == [slot.slot_id]  # exactly ONE real disposal
    assert owner_ret == [True]          # the owning call reports it DID dispose


def test_caller_keeps_slot_tracked_when_reap_skipped() -> None:
    # when _reap_and_count reports it SKIPPED (False -- another thread owns the reap), a caller must NOT
    # pop the slot: the owning thread disposes it (or quarantines on failure). Popping here could untrack
    # a slot whose real terminate later fails, orphaning a live worker off the books.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    pool._reap_and_count = lambda s, **kw: False   # type: ignore[assignment]  # simulate a concurrent skip
    pool.retire(slot)
    assert slot.slot_id in pool._slots   # left tracked for the owning thread, not popped


class _FinalizeFailRuntime(_FakeRuntime):
    """Models a runtime (e.g. libvirt) whose finalize fails closed: it reaps the VM INSIDE is_ready()
    — flipping the slot to DRAINING — and returns False."""

    def is_ready(self, slot: Slot) -> bool:
        slot.state = SlotState.DRAINING
        self.reap(slot)
        return False


def test_promote_warming_evicts_slot_reaped_during_finalize() -> None:
    # a slot the runtime reaped internally (DRAINING, is_ready False) must be EVICTED from the pool,
    # not left as a husk that eats concurrent_ceiling headroom and eventually stops new spawns.
    rt = _FinalizeFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, concurrent_ceiling=4)
    pool._spawn_to_deficit(ready=True)
    ids = set(pool._slots.keys())
    assert len(ids) == 2
    pool._promote_warming()
    assert pool.slot_count == 0          # both dead husks removed (not stuck DRAINING)
    assert set(rt.reaped) == ids         # and they were reaped


class _ExternallyDrainedReapFails(_FakeRuntime):
    """is_ready() finds the slot DRAINING (set EXTERNALLY, e.g. a racing stop()) and returns False
    WITHOUT reaping — and reap() then RAISES (the VM may still be running)."""

    def is_ready(self, slot: Slot) -> bool:
        slot.state = SlotState.DRAINING   # external drain — NOT a runtime-internal reap
        return False

    def reap(self, slot: Slot) -> None:
        raise RuntimeError("destroy failed; VM may still be running")


def test_promote_warming_quarantines_externally_drained_slot_when_reap_fails() -> None:
    # a slot marked DRAINING externally while finalize is still in flight must NOT be blindly popped
    # on is_ready=False — the pool must reap it, and if that reap FAILS (VM possibly still running)
    # keep it tracked/quarantined rather than orphaning a live worker off the books.
    rt = _ExternallyDrainedReapFails()
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=2)
    pool._spawn_to_deficit(ready=True)
    sid = next(iter(pool._slots.keys()))
    pool._promote_warming()
    assert sid in pool._slots            # reap raised → NOT popped, quarantined (still tracked)


def test_health_check_quarantines_slot_when_reap_fails() -> None:
    # a dead IDLE slot whose reap RAISES (destroy failed → VM may still run) must stay quarantined in
    # _slots (not popped), so the health sweep can't orphan a live worker off pool accounting.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=4)
    pool._spawn_to_deficit(ready=True)
    sid = next(iter(pool._slots))
    pool._slots[sid].state = SlotState.IDLE
    rt.set_alive(sid, False)            # mark it dead so _health_check tries to evict it
    pool._health_check()
    assert sid in pool._slots           # NOT popped — quarantined
    assert pool._slots[sid].state == SlotState.DRAINING


class _FinalizeReapRaisesRuntime(_FakeRuntime):
    """is_ready() RAISES (e.g. finalize's reap couldn't `virsh destroy` the VM — it may still run)."""

    def is_ready(self, slot: Slot) -> bool:
        slot.state = SlotState.DRAINING
        raise RuntimeError("destroy failed during finalize; VM may still be running")


def test_promote_warming_quarantines_slot_when_is_ready_raises() -> None:
    # if is_ready RAISES (reap couldn't dispose the VM), the slot must NOT be popped — leave it
    # quarantined/tracked, not evicted like a cleanly-reaped husk (which would orphan a live VM).
    rt = _FinalizeReapRaisesRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=4)
    pool._spawn_to_deficit(ready=True)
    sid = next(iter(pool._slots))
    pool._promote_warming()
    assert sid in pool._slots                                # NOT evicted — quarantined
    assert pool._slots[sid].state == SlotState.DRAINING


# ---------------------------------------------------------------------------
# Fake clock (injectable)
# ---------------------------------------------------------------------------


class _FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self._t = t

    def __call__(self) -> float:
        return self._t

    def advance(self, delta: float) -> None:
        self._t += delta


# ---------------------------------------------------------------------------
# Test 1: start+tick fills warm_size; idle_count == warm_size once ready
# ---------------------------------------------------------------------------


def test_1_spawn_to_warm_size() -> None:
    """tick() spawns up to warm_size; once fake marks them ready, idle_count == warm_size."""
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=3)

    # tick once: should spawn 3 slots (all WARMING initially)
    pool.tick()
    assert pool.slot_count == 3

    # all ready immediately (default_ready_after=0)
    pool.tick()
    assert pool.idle_count == 3


# ---------------------------------------------------------------------------
# Test 2: claim returns IDLE slot (ASSIGNED); claim with no idle + tiny timeout → None
# ---------------------------------------------------------------------------


def test_2_claim_returns_assigned_or_none() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2)
    pool.tick()  # spawn 2
    pool.tick()  # promote to IDLE

    slot = pool.claim(timeout_s=0.0)
    assert slot is not None
    assert slot.state == SlotState.ASSIGNED

    # Drain all IDLE slots
    while pool.claim(timeout_s=0.0) is not None:
        pass  # exhaust

    result = pool.claim(timeout_s=0.0)
    assert result is None


# ---------------------------------------------------------------------------
# Test 3: release reaps + tick spawns replacement → idle_count recovers
# ---------------------------------------------------------------------------


def test_3_release_reaps_and_replacement_spawns() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2)
    pool.tick()  # spawn 2
    pool.tick()  # promote to IDLE

    slot = pool.claim(timeout_s=0.0)
    assert slot is not None
    slot_id = slot.slot_id

    # idle_count dropped by 1
    assert pool.idle_count == 1

    pool.release(slot)

    # slot should have been reaped
    assert slot_id in rt.reaped

    # replacement spawns on next tick
    pool.tick()  # spawn replacement
    pool.tick()  # promote to IDLE

    assert pool.idle_count == 2


# ---------------------------------------------------------------------------
# Test 4: never-reused — released slot_id never reappears as IDLE;
#          second claim returns a DIFFERENT slot_id
# ---------------------------------------------------------------------------


def test_4_never_reused() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2)
    pool.tick()
    pool.tick()

    slot_a = pool.claim(timeout_s=0.0)
    assert slot_a is not None
    id_a = slot_a.slot_id

    pool.release(slot_a)
    pool.tick()  # spawn replacement
    pool.tick()  # promote

    # The released slot_id must NOT be IDLE again
    with pool._lock:
        for s in pool._slots.values():
            if s.slot_id == id_a:
                assert s.state != SlotState.IDLE, (
                    f"Slot {id_a} was recycled back to IDLE — violates never-reuse!"
                )

    # New claim returns a different slot
    slot_b = pool.claim(timeout_s=0.0)
    assert slot_b is not None
    assert slot_b.slot_id != id_a, "claim returned the same slot_id after release!"


# ---------------------------------------------------------------------------
# Test 5: liveness race — slot that dies after IDLE but before claim is skipped
# ---------------------------------------------------------------------------


def test_5_liveness_race() -> None:
    rt = _FakeRuntime()
    rt.set_default_ready_after(0)

    pool = WarmPool(runtime=rt, warm_size=2)
    pool.tick()  # spawn 2
    pool.tick()  # promote to IDLE

    # Identify the two idle slot_ids and kill the first one
    with pool._lock:
        idle_ids = [s.slot_id for s in pool._slots.values() if s.state == SlotState.IDLE]
    assert len(idle_ids) == 2

    dead_id = idle_ids[0]
    live_id = idle_ids[1]
    rt.set_alive(dead_id, False)

    # claim should skip the dead slot and return the live one
    slot = pool.claim(timeout_s=0.0)
    assert slot is not None
    assert slot.slot_id == live_id, (
        f"claim handed out dead slot {dead_id} instead of live {live_id}"
    )

    # Dead slot must be unclaimable immediately, but its disposal is DEFERRED to the tick
    # (issue #75: claim() never reaps inline — a wedged reap would block the claim path and, with
    # the warm-only gate, hold a slot reservation that locks peers out of healthy slots).
    with pool._lock:
        assert pool._slots[dead_id].state == SlotState.DRAINING   # can't be handed out again
        assert dead_id in pool._deferred_reap
    assert dead_id not in rt.reaped        # not reaped on the claim path...
    pool.tick()
    _join_reaper(pool)                     # disposal runs on the dedicated reaper thread
    assert dead_id in rt.reaped            # ...disposed off the tick + claim paths instead
    assert dead_id not in pool._slots      # and untracked once disposed


# ---------------------------------------------------------------------------
# Test 6: no double-claim under concurrency — N idle slots, M threads each
#          claim once → no slot_id claimed twice; surplus get None
# ---------------------------------------------------------------------------


def test_6_no_double_claim() -> None:
    N = 4   # idle slots available
    M = 8   # threads racing to claim

    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=N, concurrent_ceiling=N)
    pool.tick()
    pool.tick()
    assert pool.idle_count == N

    results: list[Slot | None] = [None] * M
    barrier = threading.Barrier(M)

    def _worker(i: int) -> None:
        barrier.wait()  # all start together
        results[i] = pool.claim(timeout_s=0.0)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(M)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    claimed_ids = [r.slot_id for r in results if r is not None]
    nones = [r for r in results if r is None]

    assert len(claimed_ids) == N, f"Expected {N} claims, got {len(claimed_ids)}"
    assert len(set(claimed_ids)) == N, f"Duplicate slot_ids claimed! {claimed_ids}"
    assert len(nones) == M - N, f"Expected {M - N} None results, got {len(nones)}"


# ---------------------------------------------------------------------------
# Test 7: concurrent_ceiling — slot_count never exceeds ceiling
# ---------------------------------------------------------------------------


def test_7_concurrent_ceiling() -> None:
    rt = _FakeRuntime()
    ceiling = 3
    pool = WarmPool(runtime=rt, warm_size=5, concurrent_ceiling=ceiling)

    # Multiple ticks — pool should never exceed ceiling
    for _ in range(5):
        pool.tick()
        assert pool.slot_count <= ceiling, (
            f"slot_count {pool.slot_count} exceeded ceiling {ceiling}"
        )


# ---------------------------------------------------------------------------
# Test 8: spawn rate-limit — with spawn_rate_limit=2 and fake clock,
#         no more than 2 spawns/sec
# ---------------------------------------------------------------------------


def test_8_spawn_rate_limit() -> None:
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)

    pool = WarmPool(
        runtime=rt,
        warm_size=6,
        concurrent_ceiling=20,
        spawn_rate_limit=2.0,
        clock=clock,
    )

    # At t=0: can spawn up to 2
    pool.tick()
    count_after_first = pool.slot_count
    assert count_after_first <= 2, (
        f"At t=0 should have spawned at most 2, got {count_after_first}"
    )

    # Immediately tick again without advancing clock — no more spawns
    pool.tick()
    assert pool.slot_count == count_after_first, (
        "Should not spawn more without advancing clock"
    )

    # Advance 1 second → 2 more tokens available
    clock.advance(1.0)
    pool.tick()
    count_after_advance = pool.slot_count
    assert count_after_advance <= count_after_first + 2, (
        f"After 1s should spawn at most 2 more, got {count_after_advance - count_after_first}"
    )


# ---------------------------------------------------------------------------
# Test 9: stop reaps every slot (no orphaned containers)
# ---------------------------------------------------------------------------


def test_9_stop_reaps_all() -> None:
    """start()+stop() with real background thread; all slots get reaped."""
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=3, spawn_rate_limit=100.0)

    pool.start()

    # Wait for the pool to fill (background thread running tick)
    deadline = time.monotonic() + 5.0
    while pool.idle_count < 3 and time.monotonic() < deadline:
        time.sleep(0.05)

    assert pool.idle_count == 3, f"Pool did not warm up in time; idle={pool.idle_count}"

    # Capture slot_ids before stop
    with pool._lock:
        all_ids = {s.slot_id for s in pool._slots.values()}

    pool.stop()

    assert pool.slot_count == 0, f"slot_count after stop = {pool.slot_count}"
    assert all_ids.issubset(set(rt.reaped)), (
        f"Not all slots were reaped.\n"
        f"  Expected: {sorted(all_ids)}\n"
        f"  Reaped:   {sorted(rt.reaped)}"
    )


def test_stop_retains_slot_whose_reap_fails() -> None:
    # stop() must NOT drop a slot whose reap RAISES (e.g. virsh destroy failed → the VM may still be
    # running): popping it would orphan a live worker off the books. Keep it tracked/quarantined so it
    # surfaces for manual cleanup instead of leaking silently. AND mark it DRAINING so a pool
    # restart/reuse (or a claim() racing stop()) can never hand the still-undisposed husk back out.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    sid = next(iter(pool._slots.keys()))
    pool._slots[sid].state = SlotState.IDLE       # an IDLE slot at stop time...
    pool.stop()
    assert sid in pool._slots                      # NOT popped — quarantined for manual cleanup
    assert pool._slots[sid].state == SlotState.DRAINING  # ...is now unclaimable (claim() picks IDLE)


def test_stop_marks_slots_draining_before_reaping() -> None:
    # stop() must flip every slot to DRAINING UNDER THE LOCK before reaping, so a dispatcher racing
    # claim() in the window between snapshotting to_reap and the reap can never be handed a slot stop()
    # is about to dispose. Observe the slot's state AT reap time.
    class _RecordStateAtReap(_FakeRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.state_at_reap: dict[str, SlotState] = {}

        def reap(self, slot: Slot) -> None:
            self.state_at_reap[slot.slot_id] = slot.state
            super().reap(slot)

    rt = _RecordStateAtReap()
    pool = WarmPool(runtime=rt, warm_size=2)
    pool._spawn_to_deficit(ready=True)
    for s in pool._slots.values():
        s.state = SlotState.IDLE                   # claimable before stop
    ids = set(pool._slots.keys())
    pool.stop()
    assert set(rt.state_at_reap.keys()) == ids
    assert all(st == SlotState.DRAINING for st in rt.state_at_reap.values())  # never IDLE at reap


# ---------------------------------------------------------------------------
# Test 10: burst scaling — effective_target rises to warm_size + burst_size
#          after sustained misses for burst_trigger_s; drains after burst_drain_s
# ---------------------------------------------------------------------------


def test_10_burst_scaling_effective_target_rises_and_drains() -> None:
    """effective_target lifts to warm_size+burst_size after sustained misses,
    then drops back to warm_size after burst_drain_s with no misses."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)

    warm_size = 2
    burst_size = 3
    burst_trigger_s = 3.0
    burst_drain_s = 60.0

    pool = WarmPool(
        runtime=rt,
        warm_size=warm_size,
        concurrent_ceiling=20,
        spawn_rate_limit=100.0,
        clock=clock,
        burst_size=burst_size,
        burst_trigger_s=burst_trigger_s,
        burst_drain_s=burst_drain_s,
    )

    # Before any demand: effective_target == warm_size, burst_active == False
    assert pool.effective_target == warm_size
    assert pool.burst_active is False

    # Record a demand miss at t=0 (simulates claim() finding no idle slot)
    pool._record_demand_miss()
    pool.tick()

    # Only 0 seconds elapsed since first miss → not triggered yet
    assert pool.burst_active is False
    assert pool.effective_target == warm_size

    # Advance time past burst_trigger_s, record another miss, tick
    clock.advance(burst_trigger_s + 0.1)
    pool._record_demand_miss()
    pool.tick()

    # Burst should now be active
    assert pool.burst_active is True
    assert pool.effective_target == warm_size + burst_size

    # Advance past burst_drain_s with NO new misses → burst drains
    clock.advance(burst_drain_s + 0.1)
    pool.tick()

    assert pool.burst_active is False
    assert pool.effective_target == warm_size


def test_11_burst_never_exceeds_concurrent_ceiling() -> None:
    """effective_target is clamped to concurrent_ceiling even during burst."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)

    warm_size = 3
    burst_size = 5
    ceiling = 4   # warm_size + burst_size would be 8 > ceiling

    pool = WarmPool(
        runtime=rt,
        warm_size=warm_size,
        concurrent_ceiling=ceiling,
        spawn_rate_limit=100.0,
        clock=clock,
        burst_size=burst_size,
        burst_trigger_s=1.0,
        burst_drain_s=60.0,
    )

    # Trigger burst
    pool._record_demand_miss()
    clock.advance(2.0)
    pool._record_demand_miss()
    pool.tick()

    assert pool.burst_active is True
    # effective_target must not exceed ceiling
    assert pool.effective_target <= ceiling


def test_12_burst_spawn_to_deficit_uses_effective_target() -> None:
    """_spawn_to_deficit fills to effective_target (not just warm_size) during burst."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)

    warm_size = 2
    burst_size = 2
    ceiling = 10

    pool = WarmPool(
        runtime=rt,
        warm_size=warm_size,
        concurrent_ceiling=ceiling,
        spawn_rate_limit=100.0,
        clock=clock,
        burst_size=burst_size,
        burst_trigger_s=1.0,
        burst_drain_s=60.0,
    )

    # Fill to warm_size first
    pool.tick()
    pool.tick()
    assert pool.idle_count == warm_size

    # Trigger burst: miss at t=0, advance, miss again, tick
    pool._record_demand_miss()
    clock.advance(2.0)
    pool._record_demand_miss()
    pool.tick()   # burst triggers + spawns to effective_target
    pool.tick()   # promote warming → idle

    assert pool.burst_active is True
    assert pool.idle_count == warm_size + burst_size


# ---------------------------------------------------------------------------
# Test 13: health check — dead IDLE slots are evicted by tick() and replaced
# ---------------------------------------------------------------------------


def test_13_health_check_evicts_dead_idle_slots() -> None:
    """tick() calls _health_check(); a dead IDLE slot is reaped and replaced."""
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)

    pool.tick()  # spawn 2
    pool.tick()  # promote to IDLE

    assert pool.idle_count == 2

    # Kill one slot without going through claim/release
    with pool._lock:
        idle_ids = [s.slot_id for s in pool._slots.values() if s.state == SlotState.IDLE]
    dead_id = idle_ids[0]
    rt.set_alive(dead_id, False)

    # tick() should detect the dead slot, reap it, remove it
    pool.tick()

    # The dead slot must have been reaped
    assert dead_id in rt.reaped

    # After another tick the pool should have spawned a replacement
    pool.tick()   # spawn replacement
    pool.tick()   # promote to IDLE

    # We should be back to warm_size idle slots
    assert pool.idle_count == 2


# ---------------------------------------------------------------------------
# Test 14: is_healthy — True with idle slots; False when empty + past warmup
# ---------------------------------------------------------------------------


def test_14_is_healthy_true_with_idle_slots() -> None:
    """is_healthy() returns True when there is at least one IDLE slot."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)
    pool = WarmPool(runtime=rt, warm_size=2, clock=clock, spawn_rate_limit=100.0)

    pool.tick()
    pool.tick()
    assert pool.idle_count == 2

    assert pool.is_healthy() is True


def test_15_is_healthy_true_during_warmup_grace() -> None:
    """is_healthy() returns True within the warmup grace period even with no idle slots."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=0.0)
    rt.set_default_ready_after(99)  # slots never become ready during this test

    pool = WarmPool(
        runtime=rt,
        warm_size=2,
        clock=clock,
        spawn_rate_limit=100.0,
        warmup_grace_s=10.0,
    )

    pool.start()  # records _started_at
    pool.tick()   # spawns but not ready

    # At t=0, within warmup grace → healthy
    assert pool.is_healthy() is True

    # Advance past grace → no longer healthy (still no idle slots)
    clock.advance(11.0)
    assert pool.is_healthy() is False

    pool.stop()


def test_16_is_healthy_true_if_idle_recently() -> None:
    """is_healthy() returns True if a slot was idle within the last 30 s."""
    rt = _FakeRuntime()
    clock = _FakeClock(t=100.0)
    pool = WarmPool(
        runtime=rt,
        warm_size=1,
        clock=clock,
        spawn_rate_limit=100.0,
        warmup_grace_s=5.0,
    )

    pool.tick()
    pool.tick()
    assert pool.idle_count == 1

    # Claim the only slot so idle_count drops to 0
    slot = pool.claim(timeout_s=0.0)
    assert slot is not None
    assert pool.idle_count == 0

    # Within 30 s of last idle → still healthy
    clock.advance(10.0)
    assert pool.is_healthy() is True

    # Beyond 30 s without idle and past warmup grace → not healthy
    clock.advance(30.0)
    assert pool.is_healthy() is False


def test_stuck_warming_slot_evicted_after_timeout() -> None:
    """A WARMING slot that never becomes ready (dead restore) must be evicted after
    warming_timeout_s and replaced — otherwise it counts toward capacity forever."""
    clock = _FakeClock()
    rt = _FakeRuntime()
    rt.set_default_ready_after(10**9)  # never becomes ready
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0, warming_timeout_s=60.0
    )
    pool.tick()  # spawn one WARMING slot (spawned_at = clock = 0)
    warming = [s for s in pool._slots.values() if s.state == SlotState.WARMING]
    assert len(warming) == 1
    stuck_id = warming[0].slot_id

    # Before the timeout: still WARMING, not evicted, no replacement.
    clock.advance(30.0)
    pool.tick()
    assert stuck_id in pool._slots

    # After the timeout: the stuck slot is reaped + removed and a fresh slot spawned.
    clock.advance(40.0)  # now 70s > 60s
    pool.tick()
    assert stuck_id in rt.reaped
    assert stuck_id not in pool._slots
    new_warming = [s for s in pool._slots.values() if s.state == SlotState.WARMING]
    assert len(new_warming) == 1 and new_warming[0].slot_id != stuck_id


# ---------------------------------------------------------------------------
# Spawn gating: warm-snapshot runtimes build asynchronously; the pool must not
# spawn (and must not block the tick) until runtime.prepare() reports ready.
# ---------------------------------------------------------------------------


class _GatedRuntime(_FakeRuntime):
    """A snapshot-style runtime whose prepare() gates spawning on an async build."""

    def __init__(self) -> None:
        super().__init__()
        self.ready = False
        self.prepare_calls = 0

    def prepare(self) -> bool:
        self.prepare_calls += 1
        return self.ready

    def spawn(self) -> Slot:
        assert self.ready, "spawn() must NOT be called before prepare() reports ready"
        return super().spawn()


def test_pool_does_not_spawn_until_runtime_prepared() -> None:
    rt = _GatedRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)

    pool.tick()  # build not ready -> spawn nothing this tick (and don't block on it)
    assert pool.slot_count == 0
    assert rt.prepare_calls >= 1

    rt.ready = True
    pool.tick()  # ready -> fills warm_size
    assert pool.slot_count == 2


def test_pool_still_promotes_while_spawn_gated() -> None:
    """tick() runs promote/health BEFORE the gated spawn, so a transient 'not ready' (e.g. a
    rebuild) never stalls promotion of already-WARMING slots."""
    rt = _GatedRuntime()
    rt.ready = True
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)
    pool.tick()  # spawn 2 (WARMING)
    assert pool.slot_count == 2

    rt.ready = False  # warm tier goes "rebuilding" — spawning is gated off
    pool.tick()  # promote must still run despite the spawn gate
    assert pool.idle_count == 2


def test_burst_suppressed_while_warm_tier_building() -> None:
    """Demand misses accumulated while the snapshot is still building (prepare() False) must NOT
    arm burst the instant the tier becomes ready — otherwise the pool over-provisions to the
    burst ceiling right after its first build."""
    rt = _GatedRuntime()  # ready=False (build in flight)
    clock = _FakeClock(t=0.0)
    pool = WarmPool(
        runtime=rt,
        warm_size=1,
        burst_size=4,
        burst_trigger_s=3.0,
        burst_drain_s=60.0,
        concurrent_ceiling=20,
        spawn_rate_limit=100.0,
        clock=clock,
    )

    # Sustained misses across a long build window — far exceeding burst_trigger_s.
    for _ in range(4):
        pool._record_demand_miss()
        clock.advance(2.0)  # cumulative 8s >> burst_trigger_s=3.0
        pool.tick()
        assert pool.burst_active is False  # can't spawn while building -> never bursts

    # Build finishes; the stale build-window misses must NOT have armed burst.
    rt.ready = True
    pool.tick()
    assert pool.burst_active is False
    assert pool.effective_target == 1  # warm_size only, NOT warm_size + burst_size
    assert pool.slot_count == 1


# ---------------------------------------------------------------------------
# Reuse mode (jobs_per_recycle / max_jobs_per_slot) — opt-in for recycle-capable runtimes
# ---------------------------------------------------------------------------


class _RecycleRuntime(_FakeRuntime):
    """A SlotRuntime that supports in-place reset (e.g. a VM snapshot-revert)."""

    def __init__(self, recycle_raises: bool = False) -> None:
        super().__init__()
        self.recycled: list[str] = []
        self._recycle_raises = recycle_raises

    def recycle(self, slot: Slot) -> None:
        if self._recycle_raises:
            raise RuntimeError("snapshot-revert failed")
        self.recycled.append(slot.slot_id)


def _warm_one(pool: WarmPool) -> None:
    pool.tick()  # spawn
    pool.tick()  # promote to IDLE


def test_release_does_not_republish_slot_drained_during_recycle() -> None:
    # If a concurrent stop() flips the slot to DRAINING WHILE the (seconds-long) recycle runs,
    # release() must NOT republish it to IDLE — that would hand a caller a slot stop() is reaping.
    # It must leave DRAINING alone and fall through to reap (fail-safe).
    class _DrainDuringRecycle(_RecycleRuntime):
        def recycle(self, slot: Slot) -> None:
            super().recycle(slot)
            slot.state = SlotState.DRAINING   # simulate stop() winning the race mid-recycle

    rt = _DrainDuringRecycle()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=1)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    assert s1 is not None
    pool.release(s1)                          # recycle drains it → must reap, NOT return to IDLE
    assert rt.reaped == [s1.slot_id]          # fell through to the reap fail-safe
    assert pool.claim(timeout_s=0.2) is None  # never republished as claimable


def test_reuse_returns_slot_to_idle_and_recycles_on_cadence() -> None:
    rt = _RecycleRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=2)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    assert s1 is not None
    pool.release(s1)  # job 1: 1 % 2 != 0 → reuse without reset
    assert rt.reaped == [] and rt.recycled == []
    s2 = pool.claim(timeout_s=1.0)
    assert s2 is not None and s2.slot_id == s1.slot_id  # SAME slot reused
    pool.release(s2)  # job 2: 2 % 2 == 0 → recycle (reset) then back to IDLE
    assert rt.recycled == [s1.slot_id] and rt.reaped == []
    pool.stop()


def test_reuse_reaps_at_max_jobs_per_slot() -> None:
    rt = _RecycleRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0,
                    jobs_per_recycle=1, max_jobs_per_slot=2)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    pool.release(s1)  # job 1: reset (1%1==0), reused
    assert rt.recycled == [s1.slot_id] and rt.reaped == []
    s2 = pool.claim(timeout_s=1.0)
    assert s2.slot_id == s1.slot_id
    pool.release(s2)  # job 2: jobs == max_jobs_per_slot → reap+respawn (no reuse)
    assert rt.reaped == [s1.slot_id]
    pool.stop()


def test_no_recycle_method_always_reaps_even_with_jobs_per_recycle() -> None:
    rt = _FakeRuntime()  # no recycle() → never reused, regardless of config
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=5)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    pool.release(s1)
    assert rt.reaped == [s1.slot_id]  # disposable-per-job, byte-identical to before
    pool.stop()


def test_recycle_failure_falls_back_to_reap() -> None:
    rt = _RecycleRuntime(recycle_raises=True)
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=1)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    pool.release(s1)  # recycle raises → must reap, never return a broken slot to IDLE
    assert rt.reaped == [s1.slot_id]
    pool.stop()


def test_dirty_release_force_recycles_off_cadence() -> None:
    # A failed run (dirty=True) must reset the slot BEFORE reuse even on a non-boundary job, so the
    # next job never inherits a wedged/contaminated warm worker.
    rt = _RecycleRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=10)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    assert s1 is not None
    pool.release(s1, dirty=True)  # job 1: 1 % 10 != 0 but DIRTY → force recycle, then back to IDLE
    assert rt.recycled == [s1.slot_id] and rt.reaped == []
    s2 = pool.claim(timeout_s=1.0)
    assert s2 is not None and s2.slot_id == s1.slot_id  # reset-in-place, same slot reused
    pool.stop()


def test_dirty_release_reaps_when_no_recycle_method() -> None:
    # Non-reuse runtime: a dirty release is reaped (a full reset) exactly like a clean one.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, jobs_per_recycle=5)
    _warm_one(pool)
    s1 = pool.claim(timeout_s=1.0)
    pool.release(s1, dirty=True)
    assert rt.reaped == [s1.slot_id]
    pool.stop()


def test_resize_down_reaps_surplus_idle_slots() -> None:
    # regression (marla finding 3): lowering the target must proactively reap surplus IDLE
    # slots so a node-autosizer downsize actually frees resources — not just lazily.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool.tick()                          # spawn + promote WARMING→IDLE up to warm_size=4
    assert pool.idle_count == 4 and pool.slot_count == 4
    pool.resize(warm_size=1, concurrent_ceiling=1)
    pool.tick()                              # should reap the 3 surplus IDLE slots
    assert pool.slot_count == 1
    assert len(rt.reaped) == 3


def test_spawn_stops_when_resize_lowers_ceiling_mid_batch() -> None:
    # regression (PR #60 review): a resize() lowering the ceiling WHILE _spawn_to_deficit is
    # mid-batch must not over-commit. `to_spawn` is computed once for the old ceiling; the
    # per-spawn ceiling recheck must pick up the concurrent downsize and stop early, so the
    # pool never exceeds the new ceiling (a transient RAM overshoot on a tight node).
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    orig_spawn = rt.spawn
    calls = {"n": 0}

    def racing_spawn() -> Slot:
        calls["n"] += 1
        if calls["n"] == 1:                       # a concurrent autosizer downsize mid-batch
            pool.resize(warm_size=2, concurrent_ceiling=2)
        return orig_spawn()

    rt.spawn = racing_spawn                        # type: ignore[method-assign]
    pool._spawn_to_deficit(ready=True)            # would spawn 8 for the old ceiling
    assert pool.slot_count <= 2                    # but stopped at the lowered ceiling
    pool.stop()


def test_spawn_reaps_slot_when_ceiling_drops_during_slow_spawn() -> None:
    # regression (PR #60 review): the pre-spawn ceiling check can't catch a resize() that
    # fires WHILE runtime.spawn() is blocked — the check already passed against the old
    # ceiling. The PUBLISH step must re-check and reap the completed slot rather than admit
    # it one past the new cap (RAM overshoot on a tight node).
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, concurrent_ceiling=2, spawn_rate_limit=1000.0)
    orig_spawn = rt.spawn
    calls = {"n": 0}

    def slow_spawn() -> Slot:
        calls["n"] += 1
        if calls["n"] == 2:                       # ceiling drops DURING the 2nd in-flight spawn
            pool.resize(warm_size=1, concurrent_ceiling=1)
        return orig_spawn()

    rt.spawn = slow_spawn                          # type: ignore[method-assign]
    pool._spawn_to_deficit(ready=True)
    assert pool.slot_count == 1                    # 1st published; 2nd reaped at publish (over cap)
    assert len(rt.reaped) >= 1
    pool.stop()


def test_reap_surplus_noop_until_autosized() -> None:
    # regression (round-7 holistic): _reap_surplus must be a NO-OP on a pool that never
    # opted into the autosizer, so a default deployment keeps its exact prior behavior —
    # post-burst surplus drains lazily (a lingering warm cushion for the next spike)
    # instead of being reaped the instant the effective target drops. Only a pool an
    # external controller has resize()d reaps surplus eagerly.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool.tick()
    assert pool.idle_count == 4
    # simulate the post-burst-drain state: the effective target drops below the live slot
    # count, WITHOUT a resize() — i.e. this pool never opted into the autosizer.
    pool._warm_size = 1
    pool._reap_surplus()
    assert pool.slot_count == 4 and rt.reaped == []       # cushion preserved, nothing reaped
    # once an external controller resize()s it, eager surplus reaping turns on
    pool.resize(warm_size=1, concurrent_ceiling=1)
    pool._reap_surplus()
    assert pool.slot_count == 1 and len(rt.reaped) == 3
    pool.stop()


def test_stop_returns_orphan_count_for_unreaped_slots() -> None:
    # regression (PR #60 codex P1): stop() must report slots it could NOT reap (VM may still be
    # running) so the caller keeps its node-budget reservation for the still-consumed RAM instead
    # of removing the snapshot and letting peers reallocate it. Clean stop → 0; failed reap → >0.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=3, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool.tick()
    assert pool.slot_count == 3
    orphans = pool.stop()
    assert orphans == 3                       # every reap raised → all 3 left tracked as orphans

    rt2 = _FakeRuntime()
    pool2 = WarmPool(runtime=rt2, warm_size=2, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool2.tick()
    assert pool2.stop() == 0                   # clean shutdown → no orphans


def test_resize_mark_autosized_false_keeps_legacy_behavior() -> None:
    # regression (PR #60 codex P2): resize() normally sets _autosized=True permanently, which
    # turns on eager surplus reaping. The CLI's PROVISIONAL moves — the pre-start shrink and the
    # restore when the sizer is SKIPPED (incomplete inventory / unwritable share_dir) — must NOT
    # change the pool's behavior: a failed opt-in has to drain lazily exactly like an un-managed
    # pool. resize(mark_autosized=False) makes those moves a true no-op for reaping.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool.tick()
    assert pool.idle_count == 4
    # the CLI pre-shrink then restore-on-skip, both provisional:
    pool.resize(warm_size=0, concurrent_ceiling=1, mark_autosized=False)
    pool.resize(warm_size=4, concurrent_ceiling=8, mark_autosized=False)
    assert pool._autosized is False                       # never flipped into managed mode
    pool._warm_size = 1                                    # target drops (as post-burst drain)
    pool._reap_surplus()
    assert pool.slot_count == 4 and rt.reaped == []        # lazy drain preserved — nothing reaped
    pool.stop()


def test_reap_surplus_leaves_assigned_slots_untouched() -> None:
    # regression (round-2): surplus reaping must only take IDLE slots; a slot serving a
    # job (ASSIGNED) must never be reaped, even when it counts toward the surplus.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=3, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    for _ in range(6):
        pool.tick()
    assert pool.idle_count == 3
    claimed = pool.claim(timeout_s=1.0)               # one slot IDLE -> ASSIGNED
    assert claimed is not None and pool.assigned_count == 1
    pool.resize(warm_size=0, concurrent_ceiling=1)
    pool.tick()                                       # reap surplus IDLE, NOT the assigned one
    assert claimed.slot_id in pool._slots             # the in-flight slot survives
    assert claimed.slot_id not in rt.reaped


def test_claim_not_blocked_by_a_hung_dead_slot_reap() -> None:
    # issue #75: claim(timeout_s=) bounded only the wait-for-idle, NOT the dead-slot reap inside
    # _try_claim_one — a wedged reap (hung runsc/virsh destroy) made claim() block far past its
    # timeout. With the #72 warm-only gate that also holds a slot reservation, so peers are gated
    # off HEALTHY slots. claim() must never block on a reap: defer it to the background tick.
    release = threading.Event()

    class _HungReapRuntime(_FakeRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.reap_entered = threading.Event()

        def reap(self, slot: Slot) -> None:
            self.reap_entered.set()
            release.wait(30)          # wedged disposal
            super().reap(slot)

    rt = _HungReapRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slots = list(pool._slots.values())
    for s in slots:
        s.state = SlotState.IDLE
    rt.set_alive(slots[0].slot_id, False)      # first candidate is dead -> triggers the reap path

    got: list = []
    t = threading.Thread(target=lambda: got.append(pool.claim(timeout_s=0.5)), daemon=True)
    t.start()
    t.join(10)
    try:
        assert not t.is_alive(), "claim() blocked on the hung dead-slot reap (issue #75)"
        # and it still hands out the OTHER, healthy slot rather than failing the caller
        assert got and got[0] is not None and got[0].slot_id == slots[1].slot_id
    finally:
        release.set()
        t.join(5)


def test_deferred_husk_is_disposed_and_replaced_without_blocking_the_tick() -> None:
    # issue #75: disposal is ASYNCHRONOUS (dedicated reaper thread), so tick() only KICKS it and
    # returns immediately — that is the whole point (a wedged reap must not stall maintenance).
    # Consequence, asserted here so it can't silently change: the husk still counts against
    # concurrent_ceiling until the reaper actually disposes it, so on a pool sitting exactly at its
    # ceiling the replacement spawns on a LATER tick. Deliberate — an unconfirmed disposal may still
    # be a live worker holding node RAM, and this pool counts it rather than over-commit the node.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, concurrent_ceiling=2, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slots = list(pool._slots.values())
    for s in slots:
        s.state = SlotState.IDLE
    rt.set_alive(slots[0].slot_id, False)
    assert pool._try_claim_one() is not None          # hands out the healthy one, defers the dead
    assert slots[0].slot_id in pool._deferred_reap

    pool.tick()                                        # kicks the reaper; does NOT block on it
    _join_reaper(pool)
    assert slots[0].slot_id in rt.reaped               # husk disposed off the tick + claim paths
    assert slots[0].slot_id not in pool._slots         # ...and untracked

    pool.tick()                                        # headroom now really free -> replacement
    assert len(pool._slots) == 2, {s.slot_id: s.state for s in pool._slots.values()}


def test_stop_disposes_a_deferred_husk() -> None:
    # a husk awaiting its deferred reap must NOT survive shutdown (that would leak a live VM).
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slots = list(pool._slots.values())
    for s in slots:
        s.state = SlotState.IDLE
    rt.set_alive(slots[0].slot_id, False)
    pool._try_claim_one()
    assert slots[0].slot_id in pool._deferred_reap
    pool.stop()
    assert slots[0].slot_id in rt.reaped


def _join_reaper(pool, timeout: float = 5.0) -> None:
    """Wait for the dedicated deferred-reap thread (issue #75 disposal is asynchronous)."""
    for entry in list(getattr(pool, "_reaper_threads", [])):
        entry[0].join(timeout)   # entry = [thread, last_progress_at, retired]


class _CachedLivenessRuntime(_FakeRuntime):
    """The cloud shape: a CACHED background is_alive() vs a FRESH is_alive_for_claim().

    This is why the deferred disposal must NOT run on the tick thread: for a slot the provider
    terminated inside the cache window, claim() — not _health_check — is the DISCOVERER, so putting
    the (possibly wedged) reap on the tick loop would trade one stalled claim for a whole-tier stall.
    """

    def __init__(self, hang: threading.Event | None = None, probe_delay: float = 0.0) -> None:
        super().__init__()
        self.fresh_dead: set[str] = set()
        self._hang = hang
        self._probe_delay = probe_delay
        # wedge the reap of exactly ONE slot (None = every fresh-dead slot), so a test can pin
        # which disposal stalls instead of accidentally wedging stop()'s own reaps too.
        self.hang_slot: str | None = None
        self._reap_delay = 0.0

    def set_reap_delay(self, seconds: float) -> None:
        self._reap_delay = seconds

    def is_alive(self, slot: Slot) -> bool:          # background/tick view: still cached-alive
        return True

    def is_alive_for_claim(self, slot: Slot) -> bool:
        if self._probe_delay:
            time.sleep(self._probe_delay)
        return slot.slot_id not in self.fresh_dead

    def reap(self, slot: Slot) -> None:
        wedge = (slot.slot_id == self.hang_slot) if self.hang_slot else (slot.slot_id in self.fresh_dead)
        if self._hang is not None and wedge:
            self._hang.wait(20)                       # wedged disposal
        if self._reap_delay:
            time.sleep(self._reap_delay)              # slow-but-working disposal
        super().reap(slot)


def test_pool_keeps_serving_while_a_deferred_reap_is_wedged() -> None:
    # issue #75 (review finding): the disposal must run on its OWN thread, not the tick loop.
    # Otherwise a wedged reap stalls promotion/spawn/health-check and the whole warm tier goes
    # down — strictly worse than the single stalled claim thread the fix set out to remove.
    hang = threading.Event()
    rt = _CachedLivenessRuntime(hang=hang)
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0, poll_interval=0.02)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slots = list(pool._slots.values())
    rt.fresh_dead.add(slots[0].slot_id)               # dead only to the FRESH hand-out check
    pool.start()
    try:
        assert pool.claim(timeout_s=1.0) is not None  # defers the husk, hands out the healthy slot
        time.sleep(0.4)                               # ticks run while the reaper is wedged
        # the tier is STILL serving: maintenance ran and a replacement is available
        assert pool.claim(timeout_s=1.0) is not None, "pool stopped serving while a reap was wedged"
    finally:
        hang.set()
        pool.stop()


def test_claim_scan_is_bounded_when_every_probe_stalls() -> None:
    # issue #75 (review finding): the hand-out probe (is_alive_for_claim) is itself a remote call —
    # up to cli_timeout_s on the cloud tiers. N dead slots must not hold the caller (and its
    # warm-gate reservation, #72) for N x probe. The rescan is deadline-bounded with a grace floor.
    rt = _CachedLivenessRuntime(probe_delay=0.4)
    pool = WarmPool(runtime=rt, warm_size=10, concurrent_ceiling=10, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    for s in pool._slots.values():
        rt.fresh_dead.add(s.slot_id)                  # every slot dead at hand-out
    t0 = time.monotonic()
    assert pool.claim(timeout_s=0.05) is None
    elapsed = time.monotonic() - t0
    # Discriminating bound: unbounded scanning would probe all 10 slots = 4.0s. The deadline+grace
    # must cut it to ~grace (1.0s) + one in-flight probe. (Verified by mutation: disabling the
    # scan_deadline check makes this FAIL, which the earlier 4-slot version did not.)
    assert elapsed < pool._SCAN_GRACE_S + 1.0, f"claim scan ran away: {elapsed:.2f}s"
    pool.stop()


def test_stop_racing_the_reaper_does_not_double_terminate() -> None:
    # issue #75 (review finding): the reaper must re-check membership UNDER THE LOCK before each
    # disposal. Reaping from a stale snapshot let stop() pop a slot the reaper then terminated a
    # SECOND time (a double control-plane terminate against a possibly-recycled id).
    hang = threading.Event()
    rt = _CachedLivenessRuntime(hang=hang)
    pool = WarmPool(runtime=rt, warm_size=3, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slots = list(pool._slots.values())
    for s in slots[:2]:
        rt.fresh_dead.add(s.slot_id)                  # two husks; the reaper wedges on the first
    rt.hang_slot = slots[0].slot_id                   # ONLY the first wedges (stop() must stay free)
    pool._try_claim_one()
    pool._reap_deferred()
    time.sleep(0.2)
    pool.stop(stop_timeout_s=1.0)                     # bounded: don't burn the 150s default budget
    hang.set()
    _join_reaper(pool)
    assert len(rt.reaped) == len(set(rt.reaped)), f"double-terminated: {rt.reaped}"


def test_stop_waits_for_a_reaper_mid_terminate() -> None:
    # issue #75 (review finding): the deferred reaper is a DAEMON thread, so if stop() returned
    # while it was mid-terminate the process exit would kill it and leak a live worker. stop()'s own
    # reap loop cannot cover that slot either — _reap_and_count's ownership guard makes it skip
    # whatever the reaper already owns — so stop() must JOIN the reaper within its budget.
    release = threading.Event()
    rt = _CachedLivenessRuntime(hang=release)
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slots = list(pool._slots.values())
    rt.fresh_dead.add(slots[0].slot_id)
    rt.hang_slot = slots[0].slot_id
    pool._try_claim_one()
    pool._reap_deferred()
    time.sleep(0.15)                               # reaper is now inside the wedged terminate
    threading.Timer(0.4, release.set).start()      # it completes shortly after stop() begins
    orphans = pool.stop(stop_timeout_s=5)
    assert slots[0].slot_id in rt.reaped, "stop() left a worker the reaper was mid-terminate on"
    assert orphans == 0


def test_concurrent_ticks_never_exceed_the_reaper_bound() -> None:
    # issue #75 (review): the check-and-set must start reapers INSIDE the lock — a
    # created-but-not-yet-started thread reports is_alive()==False, so releasing the lock first lets
    # concurrent ticks over-spawn past _MAX_REAPERS (thread fan-out on a busy pool).
    # DETERMINISTIC by construction: the reapers block on a gate until every kick has returned, so
    # the racing window is held open instead of being won by luck (the earlier version of this test
    # only caught the regression ~10% of runs).
    import blastbox.host.pool as pool_mod

    gate = threading.Event()
    created: list[int] = []
    real_thread = threading.Thread

    class _CountingThread(real_thread):     # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            if k.get("name") == "blastbox-pool-reaper":
                created.append(1)

    class _GatedRuntime(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            gate.wait(10)                    # hold every reaper alive for the whole race
            super().reap(slot)

    rt = _GatedRuntime()
    pool = WarmPool(runtime=rt, warm_size=12, concurrent_ceiling=12, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    for slot in pool._slots.values():        # a queue deep enough to want many reapers
        slot.state = SlotState.DRAINING
        with pool._lock:
            pool._deferred_reap.add(slot.slot_id)

    pool_mod.threading.Thread = _CountingThread
    try:
        kicks = [real_thread(target=pool._reap_deferred) for _ in range(24)]
        for t in kicks:
            t.start()
        for t in kicks:
            t.join(5)
        assert len(created) <= pool._MAX_REAPERS, (
            f"spawned {len(created)} reapers, bound is {pool._MAX_REAPERS}")
    finally:
        pool_mod.threading.Thread = real_thread
        gate.set()
        _join_reaper(pool)


def test_require_tracked_refuses_to_reap_an_untracked_slot() -> None:
    # issue #75 (review): the deferred reaper resolves its work list before disposing, so a slot
    # stop() already disposed+popped in between must NOT be terminated a second time. The guard has
    # to be evaluated in the SAME critical section that takes reap ownership — tested directly here,
    # because stop()'s reaper-join now serializes away the interleaving that used to reach it.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))

    with pool._lock:                          # simulate: another path already disposed + popped it
        pool._slots.pop(slot.slot_id, None)

    assert pool._reap_and_count(slot, require_tracked=True) is False
    assert slot.slot_id not in rt.reaped, "re-terminated a slot that was already disposed"
    # ...while the default (untracked-tolerant) call still disposes, as every other path relies on
    assert pool._reap_and_count(slot) is True
    assert slot.slot_id in rt.reaped


def test_wedged_reaper_does_not_inflate_the_orphan_count() -> None:
    # issue #75 (review): stop()'s orphan return drives the caller's node-budget reservation. The
    # +1 for a wedged thread exists for the wedged-SPAWN case, whose slot is NOT in _slots. A wedged
    # REAPER's slot IS tracked (it only pops after a successful reap), so counting it twice would
    # make the caller hold a reservation for capacity that doesn't exist.
    hang = threading.Event()
    rt = _CachedLivenessRuntime(hang=hang)
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slot = next(iter(pool._slots.values()))
    rt.fresh_dead.add(slot.slot_id)
    rt.hang_slot = slot.slot_id
    pool._try_claim_one()
    pool._reap_deferred()
    time.sleep(0.2)
    try:
        orphans = pool.stop(stop_timeout_s=0.5)       # reaper still wedged -> join expires
        # ABSOLUTE, not `orphans == len(_slots)` — that is a tautology (both sides read the same
        # dict), so any mutation dropping the slot satisfies it while under-reporting the orphan.
        assert orphans == 1, f"expected exactly 1 orphan (the wedged live worker), got {orphans}"
        assert slot.slot_id in pool._slots, "the wedged reaper's slot must remain tracked"
    finally:
        hang.set()
        _join_reaper(pool)


def test_mass_slot_death_drains_in_parallel() -> None:
    # issue #75 (review): a mass death (spot reclamation / AZ event inside is_alive()'s cache
    # window) is exactly what this path exists for. Draining serially would stall a ceiling-bound
    # tier for N x reap latency; pre-#75 each claim thread reaped concurrently, so the bounded
    # reaper pool must keep recovery parallel.
    rt = _CachedLivenessRuntime()
    n = 8
    pool = WarmPool(runtime=rt, warm_size=n, concurrent_ceiling=n, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    for s in pool._slots.values():
        rt.fresh_dead.add(s.slot_id)
    slow = 0.3
    rt.set_reap_delay(slow)
    pool._try_claim_one()                              # discovers + defers all of them
    t0 = time.monotonic()
    pool.tick()
    _join_reaper(pool, timeout=60)
    elapsed = time.monotonic() - t0
    assert len(rt.reaped) == n, rt.reaped
    # parallel across _MAX_REAPERS -> well under the serial n*slow
    assert elapsed < n * slow * 0.75, f"drain looks serial: {elapsed:.2f}s for {n} x {slow}s"


def test_stop_clears_the_deferred_queue_so_a_restart_cannot_re_terminate() -> None:
    # issue #75 (review): a slot whose reap RAISES stays tracked as a QUARANTINED husk. If stop()
    # left its id queued, a restarted pool's first tick would re-terminate a resource whose
    # disposal already failed — which _drain_deferred_reaps' own contract forbids.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.DRAINING
    with pool._lock:
        pool._deferred_reap.add(slot.slot_id)
    pool.stop(stop_timeout_s=1.0)
    assert slot.slot_id not in pool._deferred_reap


def test_stop_budget_is_shared_between_tick_thread_and_reaper() -> None:
    # issue #75 (review): the reaper join must draw on the SAME shutdown budget as the tick-thread
    # join — otherwise a hung spawn followed by a hung reap costs 2x the caller's timeout.
    # The pool MUST be started with a WEDGED SPAWN, else stop() skips the tick-join branch entirely
    # and a per-join budget is indistinguishable from a shared one (mutation-proven).
    spawn_gate = threading.Event()
    reap_gate = threading.Event()

    class _BothWedged(_CachedLivenessRuntime):
        def spawn(self) -> Slot:
            slot = super().spawn()
            if self.fresh_dead:              # wedge only AFTER the first slot exists
                spawn_gate.wait(20)
            return slot

    rt = _BothWedged(hang=reap_gate)
    pool = WarmPool(runtime=rt, warm_size=2, spawn_rate_limit=100.0, poll_interval=0.01)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slot = next(iter(pool._slots.values()))
    rt.fresh_dead.add(slot.slot_id)          # from here spawns wedge too
    rt.hang_slot = slot.slot_id
    pool._try_claim_one()                    # defer the husk
    pool._reap_deferred()                    # reaper wedges in reap
    pool.start()                             # tick thread wedges in spawn
    time.sleep(0.3)
    try:
        t0 = time.monotonic()
        pool.stop(stop_timeout_s=0.5)        # BOTH wedged: must stay within ONE budget
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, f"shutdown took {elapsed:.2f}s on a 0.5s budget (double-charged?)"
    finally:
        spawn_gate.set()
        reap_gate.set()
        _join_reaper(pool)



def test_successful_reap_pops_under_the_ownership_lock() -> None:
    # issue #75 (review): _reap_and_count released reap ownership (_reaping) and only THEN did the
    # caller pop _slots. In that window the slot is tracked but unowned, so a concurrent stop()
    # would terminate it a SECOND time. pop_on_success closes it by untracking in the same critical
    # section that releases ownership.
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))

    assert pool._reap_and_count(slot, pop_on_success=True) is True
    with pool._lock:
        assert slot.slot_id not in pool._slots      # untracked atomically with the ownership release
        assert slot.slot_id not in pool._reaping


def test_pop_on_success_keeps_a_failed_reap_quarantined() -> None:
    # issue #75 (review, HIGH): pop_on_success lives in a FINALLY, so without gating it on the reap
    # actually RETURNING it would untrack a slot whose disposal RAISED — orphaning a worker that may
    # still be running, which is precisely what the quarantine policy prevents.
    rt = _ReapFailRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))

    try:
        pool._reap_and_count(slot, pop_on_success=True)
        raise AssertionError("expected the failing reap to propagate")
    except RuntimeError:
        pass
    with pool._lock:
        assert slot.slot_id in pool._slots, "a FAILED reap must stay tracked (quarantined)"
        assert slot.slot_id not in pool._reaping, "ownership must still be released"


def test_dead_reapers_are_pruned_so_the_queue_keeps_draining() -> None:
    # issue #75 (review): the `_reaper_threads = [t for t in ... if t.is_alive()]` prune is
    # LOAD-BEARING for liveness. Without it, once _MAX_REAPERS threads have EVER been created the
    # slot budget is permanently exhausted, _reap_deferred returns early forever, and husks pile up
    # in _deferred_reap holding ceiling headroom — the tier quietly stops replacing slots.
    # More rounds than _MAX_REAPERS, so an unpruned list would stall partway through.
    rt = _CachedLivenessRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=4, spawn_rate_limit=1000.0)
    rounds = 6
    assert rounds > pool._MAX_REAPERS
    for _ in range(rounds):
        pool._spawn_to_deficit(ready=True)
        pool._promote_warming()
        idle = [s for s in pool._slots.values() if s.state == SlotState.IDLE]
        assert idle, "expected a fresh IDLE slot each round"
        rt.fresh_dead.add(idle[0].slot_id)
        pool._try_claim_one()                    # defers it
        pool._reap_deferred()
        _join_reaper(pool)
    assert len(rt.reaped) == rounds, f"only {len(rt.reaped)}/{rounds} husks disposed"
    with pool._lock:
        assert not pool._deferred_reap, f"queue stalled with {len(pool._deferred_reap)} husks"


def test_drain_passes_both_guards_to_the_reap_primitive() -> None:
    # issue #75 (review): the guards were pinned only at the PRIMITIVE — dropping the kwargs at the
    # drain CALL SITE left the suite green while silently reintroducing the double-terminate.
    # Pin the call site's contract directly.
    rt = _CachedLivenessRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slot = next(iter(pool._slots.values()))
    rt.fresh_dead.add(slot.slot_id)
    pool._try_claim_one()

    seen: list[dict] = []
    real = pool._reap_and_count

    def _spy(s, **kw):
        seen.append(kw)
        return real(s, **kw)

    pool._reap_and_count = _spy            # type: ignore[method-assign]
    pool._drain_deferred_reaps()
    assert seen, "the drain never reached the reap primitive"
    assert seen[0].get("require_tracked") is True, seen[0]
    assert seen[0].get("pop_on_success") is True, seen[0]


def _spy_reap_kwargs(pool):
    """Record the kwargs every disposal path passes to _reap_and_count."""
    seen: list[dict] = []
    real = pool._reap_and_count

    def _spy(slot, **kw):
        seen.append(kw)
        return real(slot, **kw)

    pool._reap_and_count = _spy            # type: ignore[method-assign]
    return seen


def _assert_guarded(seen, path: str) -> None:
    assert seen, f"{path} never reached the reap primitive"
    for kw in seen:
        assert kw.get("require_tracked") is True, f"{path} lost require_tracked: {kw}"
        assert kw.get("pop_on_success") is True, f"{path} lost pop_on_success: {kw}"


# --- every two-phase disposal path must take BOTH guards (issue #75 review) -----------------
# Without them the "still tracked?" check runs in a DIFFERENT critical section from the one that
# takes reap ownership, and the pop happens in a SEPARATE lock acquisition after ownership is
# released — two windows in which a concurrent stop() terminates the same worker a second time.
# These pin each CALL SITE (mutation-proven: stripping the kwargs from any one of them used to
# leave the whole suite green).

def test_release_passes_both_reap_guards() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    seen = _spy_reap_kwargs(pool)
    pool.release(slot)
    _assert_guarded(seen, "release()")


def test_retire_passes_both_reap_guards() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    seen = _spy_reap_kwargs(pool)
    pool.retire(slot)
    _assert_guarded(seen, "retire()")


def test_reap_surplus_passes_both_reap_guards() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, concurrent_ceiling=4, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    pool.resize(warm_size=1, concurrent_ceiling=1)      # marks the pool autosized -> surplus reaping
    seen = _spy_reap_kwargs(pool)
    pool._reap_surplus()
    _assert_guarded(seen, "_reap_surplus()")


def test_health_check_passes_both_reap_guards() -> None:
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slot = next(iter(pool._slots.values()))
    rt.set_alive(slot.slot_id, False)                   # dead IDLE slot -> health eviction
    seen = _spy_reap_kwargs(pool)
    pool._health_check()
    _assert_guarded(seen, "_health_check()")


def test_promote_warming_passes_both_reap_guards() -> None:
    # The DRAINING-while-WARMING branch: is_ready() returns False on a slot an external stop()
    # already flipped to DRAINING, so the pool disposes it itself. Same two-phase shape, same guards.
    # The branch is reached only when the slot was WARMING at snapshot time and became DRAINING
    # DURING the loop — exactly what a concurrent stop() does — so flip it inside is_ready().
    class _NotReadyFlipsToDraining(_FakeRuntime):
        def is_ready(self, slot: Slot) -> bool:
            slot.state = SlotState.DRAINING    # a concurrent stop() flips it mid-promote
            return False

    rt = _NotReadyFlipsToDraining()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    assert slot.state == SlotState.WARMING
    seen = _spy_reap_kwargs(pool)
    pool._promote_warming()
    _assert_guarded(seen, "_promote_warming()")
def test_wedged_reapers_stop_counting_so_the_queue_keeps_draining() -> None:
    # issue #77: a wedged runtime.reap can't be killed, but it must not hold a slot in the reaper
    # pool forever — _MAX_REAPERS stuck disposals would otherwise stop the queue draining for the
    # life of the pool. A reaper older than _REAPER_WEDGED_AFTER_S stops counting against the cap.
    # ORDERING MATTERS: the wedged ids are queued and picked up FIRST, so every reaper is blocked
    # before the healthy ids arrive. Draining them then REQUIRES the watchdog to free pool slots
    # (otherwise an initial reaper could have drained them incidentally and the test would pass
    # even with the watchdog removed).
    hang = threading.Event()
    rt = _CachedLivenessRuntime(hang=hang)
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    pool._REAPER_WEDGED_AFTER_S = 0.2                 # shrink the watchdog for the test
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slots = list(pool._slots.values())
    wedged = slots[:pool._MAX_REAPERS]
    healthy = slots[pool._MAX_REAPERS:]
    assert healthy, "need slots beyond the reaper cap"
    rt.fresh_dead = {s.slot_id for s in wedged}       # ONLY these block inside reap()

    try:
        for s in wedged:                              # queue the wedging ones FIRST
            with pool._lock:
                s.state = SlotState.DRAINING
                pool._deferred_reap.add(s.slot_id)
        pool._reap_deferred()
        time.sleep(0.35)                              # all reapers now blocked, past the watchdog

        for s in healthy:                             # now the ones that must still get disposed
            with pool._lock:
                s.state = SlotState.DRAINING
                pool._deferred_reap.add(s.slot_id)

        want = {s.slot_id for s in healthy}
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not want.issubset(set(rt.reaped)):
            pool._reap_deferred()                     # must be ALLOWED to start more reapers
            time.sleep(0.05)
        assert want.issubset(set(rt.reaped)), (
            f"queue stalled behind {len(wedged)} wedged reapers: "
            f"{len(set(rt.reaped) & want)}/{len(want)} disposed")
    finally:
        hang.set()
        _join_reaper(pool)


def test_hand_out_probe_is_always_inline_never_threaded() -> None:
    # issue #77: the claim probe must never be wrapped in a watchdog thread — for ANY runtime,
    # seam or not. A thread cannot cancel a blocking call, only abandon it, and one abandoned
    # thread (plus its aws CLI subprocess) per probe under a control-plane brownout is a resource
    # storm during exactly the incident the bound exists to survive. The bound belongs in the
    # runtime (see AwsWorkerConfig.claim_probe_timeout_s), which can actually cancel its own call.
    import blastbox.host.pool as pool_mod

    made: list[str] = []
    real_thread = threading.Thread

    class _CountingThread(real_thread):     # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            made.append(k.get("name") or "")

    for rt in (_FakeRuntime(), _CachedLivenessRuntime()):   # without AND with the remote seam
        pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
        pool._spawn_to_deficit(ready=True)
        pool._promote_warming()
        made.clear()
        pool_mod.threading.Thread = _CountingThread
        try:
            assert pool._try_claim_one() is not None
        finally:
            pool_mod.threading.Thread = real_thread
        # Assert on the PROPERTY (no thread at all), not on a name — a watchdog reintroduced
        # under any other thread name would otherwise slip past this regression test.
        assert made == [], f"_try_claim_one created thread(s) for {type(rt).__name__}: {made}"


def test_total_reaper_threads_are_hard_capped_even_when_all_are_wedged() -> None:
    # issue #77 (review): the wedged-reaper watchdog frees pool slots so a stuck disposal can't halt
    # the queue — but on its own it removed the ONLY bound, because a wedged reaper never exits and
    # is never pruned, so every tick could start _MAX_REAPERS more (measured: 64 live threads
    # against a cap of 4). _MAX_REAPER_THREADS is the hard ceiling, wedged ones included.
    hang = threading.Event()

    class _NeverReaps(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            hang.wait(300)

    rt = _NeverReaps()
    n = 80
    pool = WarmPool(runtime=rt, warm_size=n, concurrent_ceiling=n, spawn_rate_limit=10000.0)
    pool._REAPER_WEDGED_AFTER_S = 0.02        # every reaper counts as wedged almost immediately
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    with pool._lock:
        for sid, slot in pool._slots.items():
            slot.state = SlotState.DRAINING
            pool._deferred_reap.add(sid)
    try:
        for _ in range(60):                    # hammer the kick; watchdog keeps freeing slots
            pool._reap_deferred()
            time.sleep(0.02)
        alive = sum(1 for t in threading.enumerate() if t.name == "blastbox-pool-reaper")
        assert alive <= pool._MAX_REAPER_THREADS, (
            f"{alive} live reapers exceeds the hard cap of {pool._MAX_REAPER_THREADS}")
    finally:
        hang.set()
        _join_reaper(pool, timeout=10)


def test_a_reaper_making_progress_is_not_treated_as_wedged() -> None:
    # issue #77 (review): "wedged" must mean NO PROGRESS, not merely old. A reaper steadily draining
    # a long queue (slow-but-working terminates) would otherwise be reclassified as wedged the
    # moment it aged past the watchdog, spawning redundant reapers against the same queue.
    # The reap must be SLOW so the queue is still non-empty at the second kick — with instant reaps
    # the queue drains first and the test passes even with progress-tracking removed.
    class _SlowButWorking(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            time.sleep(0.05)                    # working, just not instant
            super().reap(slot)

    rt = _SlowButWorking()
    n = 40
    pool = WarmPool(runtime=rt, warm_size=n, concurrent_ceiling=n, spawn_rate_limit=10000.0)
    pool._MAX_REAPERS = 1                       # exactly ONE reaper may make progress
    # Watchdog LONGER than one reap (0.05s) but far shorter than the whole drain (40 x 0.05 = 2s):
    # a progressing reaper stamps every ~0.05s so it never looks stalled, while age-based detection
    # would flag it after 0.3s. (A watchdog shorter than one reap would flag even a working reaper
    # mid-disposal — progress is only observable BETWEEN disposals.)
    pool._REAPER_WEDGED_AFTER_S = 0.3
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    with pool._lock:
        for sid, slot in pool._slots.items():
            slot.state = SlotState.DRAINING
            pool._deferred_reap.add(sid)

    try:
        pool._reap_deferred()                   # start the single reaper
        for _ in range(12):                     # keep kicking well past the watchdog window
            time.sleep(0.1)
            pool._reap_deferred()
            with pool._lock:
                assert len(pool._reaper_threads) <= 1, (
                    f"a progressing reaper was misread as wedged: "
                    f"{len(pool._reaper_threads)} reapers for _MAX_REAPERS=1")
    finally:
        _join_reaper(pool, timeout=15)


class _UnknownProbeRuntime(_FakeRuntime):
    """A cloud-shaped runtime whose hand-out probe reports UNKNOWN (None) — the tri-state the
    redesign turns on. Nothing else in the suite ever returns None, so the pool's whole UNKNOWN
    branch was dead code under test (mutations that deleted or inverted it all survived)."""

    def __init__(self) -> None:            # noqa: D107
        super().__init__()
        self.unknown: set[str] = set()
        self.probe_delay = 0.0

    def is_alive_for_claim(self, slot: Slot) -> "bool | None":
        if slot.slot_id in self.unknown:
            if self.probe_delay:
                time.sleep(self.probe_delay)   # a REAL brownout probe is slow, not instant
            return None
        return True


def test_unknown_probe_never_destroys_and_serves_a_healthy_slot_behind_it() -> None:
    # issue #77: UNKNOWN must be skipped NON-DESTRUCTIVELY — left IDLE, never deferred for reap —
    # and a healthy slot behind it must still be served.
    rt = _UnknownProbeRuntime()
    pool = WarmPool(runtime=rt, warm_size=3, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    slots = list(pool._slots.values())
    rt.unknown = {slots[0].slot_id, slots[1].slot_id}       # first two can't be probed

    got = pool.claim(timeout_s=2.0)
    assert got is not None and got.slot_id == slots[2].slot_id, "healthy slot behind UNKNOWN not served"
    with pool._lock:
        for s in slots[:2]:
            assert s.state == SlotState.IDLE, f"UNKNOWN slot left in {s.state}, must stay IDLE"
            assert s.slot_id not in pool._deferred_reap, "UNKNOWN slot queued for disposal"
    assert not rt.reaped, f"UNKNOWN destroyed a worker: {rt.reaped}"


def test_all_unknown_claim_terminates_promptly_without_destroying_anything() -> None:
    # issue #77: with EVERY slot UNKNOWN the scan must not spin — it returns None within the
    # caller's budget and leaves the whole (possibly healthy) pool intact.
    rt = _UnknownProbeRuntime()
    pool = WarmPool(runtime=rt, warm_size=8, concurrent_ceiling=8, spawn_rate_limit=1000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    with pool._lock:
        rt.unknown = set(pool._slots)
    rt.probe_delay = 0.3                  # 8 slots x 0.3s = 2.4s if the scan ignores its deadline

    t0 = time.monotonic()
    assert pool.claim(timeout_s=0.1) is None
    elapsed = time.monotonic() - t0
    # bounded by the grace floor + one in-flight probe, NOT by probing every slot
    assert elapsed < pool._SCAN_GRACE_S + 0.9, f"all-UNKNOWN scan ran away: {elapsed:.2f}s"
    with pool._lock:
        assert all(s.state == SlotState.IDLE for s in pool._slots.values())
        assert not pool._deferred_reap
    assert not rt.reaped


def test_each_reaper_stamps_its_OWN_progress_entry() -> None:
    # issue #77 (agy/codex, HIGH): the thread target was a lambda closing over `entry_box`, which
    # captures the VARIABLE — so with more than one reaper every thread resolved it to the LAST
    # iteration's list. All reapers stamped one entry while the others were never stamped, looked
    # wedged, and triggered over-spawning. functools.partial binds the value.
    gate = threading.Event()

    class _Slow(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            gate.wait(5)
            super().reap(slot)

    rt = _Slow()
    pool = WarmPool(runtime=rt, warm_size=6, concurrent_ceiling=6, spawn_rate_limit=10000.0)
    pool._spawn_to_deficit(ready=True)
    pool._promote_warming()
    with pool._lock:
        for sid, slot in pool._slots.items():
            slot.state = SlotState.DRAINING
            pool._deferred_reap.add(sid)
    try:
        pool._reap_deferred()                      # starts _MAX_REAPERS threads
        time.sleep(0.2)
        with pool._lock:
            entries = list(pool._reaper_threads)
        assert len(entries) >= 2, "need multiple reapers to expose the capture bug"
        # every entry must belong to a DISTINCT thread — a shared box would leave duplicates
        threads = [e[0] for e in entries]
        assert len(set(id(t) for t in threads)) == len(threads)
        # and each entry object must be distinct (not all reapers pointing at one list slot)
        assert len(set(id(e) for e in entries)) == len(entries)
    finally:
        gate.set()
        _join_reaper(pool, timeout=10)


# ------------------------------------------------ issue #77 round 2: escalated-review regressions

def _slot(slot_id: str, state):  # noqa: ANN001
    from blastbox.host.pool import Slot
    return Slot(slot_id=slot_id, control_dir="/tmp/c", input_dir="/tmp/i", output_dir="/tmp/o",
                state=state)


def test_f5_claim_passes_its_remaining_budget_to_the_runtimes_claim_probe():
    """The runtime bounds its own claim probe (claim_probe_timeout_s), but nothing told it how long
    the CALLER actually had. claim(timeout_s=0.5) against a 5s probe bound blocked ~5s -- a 10x
    violation of the claim contract that also pinned the dispatcher's warm-gate reservation."""
    from blastbox.host.pool import SlotState, WarmPool

    seen: list[float | None] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            seen.append(budget_s)
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    slot = _slot("s1", SlotState.IDLE)
    pool._slots["s1"] = slot
    got = pool.claim(timeout_s=0.5)
    assert got is slot
    assert seen and seen[0] is not None, "the runtime was given no claim budget at all"
    # Bounded by the pool's SCAN deadline (caller deadline, floored at _SCAN_GRACE_S) -- that grace
    # is deliberate and is what keeps a non-blocking claim(timeout_s=0) able to take a ready slot
    # (issue #77 round 4). The point of the finding stands: the probe must be bounded by the POOL's
    # deadline, never left to the runtime's own much larger claim_probe_timeout_s.
    assert seen[0] <= pool._SCAN_GRACE_S + 1e-6, (
        f"probe was handed {seen[0]}s, beyond the scan deadline")


def test_f20_a_nonblocking_claim_can_still_take_a_ready_slot():
    """The round-2 budget plumbing passed the caller's RAW deadline, so claim(timeout_s=0) handed
    the runtime a 0s probe budget; it correctly reported an exhausted probe, the pool read UNKNOWN,
    and every AWS slot was skipped. A non-blocking claim could never succeed again."""
    from blastbox.host.pool import SlotState, WarmPool

    budgets: list = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            budgets.append(budget_s)
            return None if (budget_s is not None and budget_s <= 0) else True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    slot = _slot("s1", SlotState.IDLE)
    pool._slots["s1"] = slot
    assert pool.claim(timeout_s=0) is slot, f"non-blocking claim failed; budgets={budgets}"


def test_f5_a_runtime_without_the_budget_kwarg_still_works():
    """Back-compat: an external runtime whose is_alive_for_claim predates the kwarg must not break."""
    from blastbox.host.pool import SlotState, WarmPool

    class _OldRt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot):  # noqa: ANN001 -- no budget_s
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_OldRt(), warm_size=0)
    slot = _slot("s1", SlotState.IDLE)
    pool._slots["s1"] = slot
    assert pool.claim(timeout_s=0.5) is slot


# ------------------------- issue #77 round 3: the escalated review of the round-2 fixes ----------

def test_f10_a_reaper_retired_while_wedged_does_not_rejoin_the_drain():
    """Dropping a wedged reaper from the progress count is what lets replacements spawn -- but
    nothing STOPPED the original. If its terminate ever returned it resumed draining alongside its
    replacements, so the _MAX_REAPERS=4 concurrency bound silently became _MAX_REAPER_THREADS=32.
    It can't be interrupted, but it can be told to stop after its current disposal."""
    from blastbox.host.pool import SlotState, WarmPool

    reaped: list[str] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            reaped.append(slot.slot_id)

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    for i in range(3):
        s = _slot(f"s{i}", SlotState.DRAINING)
        pool._slots[s.slot_id] = s
        pool._deferred_reap.add(s.slot_id)

    retired_box = [[None, 0.0, True]]      # this reaper was declared wedged and retired
    pool._drain_deferred_reaps(retired_box)
    assert reaped == [], f"a retired reaper kept draining the queue: {reaped}"

    live_box = [[None, 0.0, False]]        # a healthy one still drains it
    pool._drain_deferred_reaps(live_box)
    assert len(reaped) == 3, f"a live reaper must drain the queue, got {reaped}"


def test_f10_the_spawner_retires_a_reaper_that_has_stopped_making_progress():
    """The other half of F10: something must SET the retired flag. A reaper whose last progress is
    older than _REAPER_WEDGED_AFTER_S stops counting toward _MAX_REAPERS so replacements can spawn;
    that same decision must mark it retired, or it rejoins the drain if its terminate ever returns."""
    import threading

    from blastbox.host.pool import SlotState, WarmPool

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

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    release = threading.Event()
    t = threading.Thread(target=release.wait, daemon=True)   # a real, still-alive thread
    t.start()
    try:
        stale = [t, pool._clock() - (pool._REAPER_WEDGED_AFTER_S + 1.0), False]
        pool._reaper_threads.append(stale)
        s = _slot("s0", SlotState.DRAINING)          # give it a reason to look at the queue
        pool._slots["s0"] = s
        pool._deferred_reap.add("s0")
        pool._reap_deferred()
        assert stale[2] is True, "a wedged reaper was abandoned but never told to stop"
    finally:
        release.set()
        t.join(timeout=5)


def test_f26_an_unknown_slot_is_probed_once_per_claim_not_once_per_scan():
    """The unprobeable set was rebuilt every scan, so a runtime that answers UNKNOWN *fast* (a
    throttle returns in milliseconds) was re-probed on every rescan of the same claim -- multiplying
    aws CLI subprocesses per dispatcher thread during exactly the brownout the budget exists for."""
    from blastbox.host.pool import SlotState, WarmPool

    probes: list[str] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            probes.append(slot.slot_id)
            return None            # fast UNKNOWN, exactly like a throttled describe

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    for i in range(3):
        s = _slot(f"s{i}", SlotState.IDLE)
        pool._slots[s.slot_id] = s
    assert pool.claim(timeout_s=0.3) is None       # every slot unknown -> no claim
    assert len(probes) == 3, f"expected one probe per slot for the whole claim, got {probes}"


# ---------------- marla loop (run-41): UNKNOWN must be survivable, not permanent -----------------

def _unknown_rt(reaped: list):
    """A runtime whose probes never give a definitive answer (a persistent host/control-plane fault)."""
    class _Rt:
        kind = "test"

        def spawn(self):
            from blastbox.host.pool import SlotState
            return _slot(f"new{len(reaped)}", SlotState.IDLE)

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            raise OSError("[Errno 24] Too many open files: 'aws'")

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            return None

        def reap(self, slot):  # noqa: ANN001
            reaped.append(slot.slot_id)
    return _Rt()


def test_a_transient_unknown_does_not_cost_the_slot():
    """The whole point of #77: a correlated control-plane brownout must NOT destroy warm workers."""
    from blastbox.host.pool import SlotState, WarmPool

    reaped: list[str] = []
    clock = [1000.0]
    pool = WarmPool(runtime=_unknown_rt(reaped), warm_size=1, clock=lambda: clock[0])
    slot = _slot("s1", SlotState.IDLE)
    pool._slots["s1"] = slot
    for _ in range(20):
        clock[0] += 1.0          # 20 seconds of solid UNKNOWN
        pool._health_check()
    assert reaped == [], f"a transient brownout destroyed a healthy warm worker: {reaped}"
    assert pool._slots.get("s1") is slot


def test_a_PERSISTENT_unknown_eventually_escalates_to_dead():
    """The half of the inversion that was missing. Before this, UNKNOWN was permanent: the slot was
    never claimable, never reaped and never replaced, _spawn_to_deficit counted it as active, and
    is_healthy() still returned True -- a tier silently wedged at zero capacity. On main a probe
    error set alive=False, so this case SELF-HEALED; keeping the slot forever is strictly worse than
    the bug #77 fixes. UNKNOWN is a reason to WAIT, never a reason to wait indefinitely."""
    from blastbox.host.pool import SlotState, WarmPool

    reaped: list[str] = []
    clock = [1000.0]
    pool = WarmPool(runtime=_unknown_rt(reaped), warm_size=1, clock=lambda: clock[0])
    slot = _slot("s1", SlotState.IDLE)
    pool._slots["s1"] = slot
    for _ in range(400):
        clock[0] += 5.0          # well past any sane grace
        pool._health_check()
    # Disposal is ASYNCHRONOUS: an escalated slot is handed to the bounded deferred reapers rather
    # than terminated inline, so a tier's worth of 120s AWS terminates cannot stall the tick thread.
    pool._drain_deferred_reaps()
    assert reaped == ["s1"], (
        f"a PERMANENTLY unknown slot was never escalated: reaped={reaped} "
        f"(tier wedged at zero capacity -- the pre-#77 self-heal that was removed)")


def test_a_definitive_answer_resets_the_unknown_clock():
    """A slot that flickers unknown/alive must never accumulate its way to a reap."""
    from blastbox.host.pool import SlotState, WarmPool

    reaped: list[str] = []
    answers = iter([None, True] * 500)

    class _Flaky:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            if next(answers) is None:
                raise OSError("transient")
            return True

        def reap(self, slot):  # noqa: ANN001
            reaped.append(slot.slot_id)

    clock = [1000.0]
    pool = WarmPool(runtime=_Flaky(), warm_size=1, clock=lambda: clock[0])
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    for _ in range(400):
        clock[0] += 5.0
        pool._health_check()
    assert reaped == [], f"a recovering slot was escalated to dead: {reaped}"


def test_an_unknown_slot_is_re_probed_later_in_the_same_claim():
    """Suppressing an UNKNOWN slot for the WHOLE claim was the opposite error to re-probing it every
    scan: a throttle answers in milliseconds, so every slot was suppressed within the first second
    of a 60s window and never asked again -- claim() then span on demand misses and tripped burst
    spawning mid-brownout. It must be a cooldown, so a slot recovering mid-window is still usable."""
    from blastbox.host.pool import SlotState, WarmPool

    probes: list[float] = []
    clock = [1000.0]
    recovered = {"v": False}

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            probes.append(clock[0])
            return True if recovered["v"] else None

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0])
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    unprobeable: dict[str, float] = {}
    assert pool._try_claim_one(clock[0] + 1, clock[0] + 1, unprobeable) is None   # unknown -> skip
    assert len(probes) == 1
    clock[0] += pool._UNPROBEABLE_COOLDOWN_S + 0.1                                # cooldown elapses
    recovered["v"] = True                                                          # control plane back
    got = pool._try_claim_one(clock[0] + 1, clock[0] + 1, unprobeable)
    assert got is not None, f"a recovered slot was never re-probed within the claim: probes={probes}"
    assert len(probes) == 2


def test_escalation_that_cannot_dispose_returns_the_slot_instead_of_quarantining_it():
    """The escalation reaps through the SAME control plane that made the slot unknown, so during a
    long brownout terminate fails too -- and the slot was quarantined DRAINING, which nothing ever
    retries and which still counts against concurrent_ceiling. That is strictly WORSE than the
    UNKNOWN wedge it replaced: the wedge recovered when the brownout ended, the quarantine never
    does. An escalated slot is only SUSPECTED dead; if we cannot dispose of it we know nothing, so
    it goes back to IDLE and the normal cycle resumes."""
    from blastbox.host.pool import SlotState, WarmPool

    brownout = {"v": True}
    reap_calls: list[str] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return None if brownout["v"] else True

        def reap(self, slot):  # noqa: ANN001
            reap_calls.append(slot.slot_id)
            if brownout["v"]:
                raise RuntimeError("terminate failed: throttled")

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=1, clock=lambda: clock[0], unknown_grace_s=60.0)
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    for _ in range(40):                       # ride out a brownout longer than the grace
        clock[0] += 5.0
        pool._health_check()
        pool._drain_deferred_reaps()      # disposal is asynchronous now (bounded reapers)
    assert reap_calls, "escalation never even attempted a disposal"

    brownout["v"] = False                     # control plane recovers
    clock[0] += 5.0
    pool._health_check()
    pool._drain_deferred_reaps()
    s = pool._slots.get("s1")
    assert s is not None, "the slot vanished despite never being disposed of"
    assert s.state == SlotState.IDLE, (
        f"slot stuck in {s.state} after the brownout ended — permanently zero capacity")


def test_unknown_since_leak_is_pruned_when_slots_leave():
    """One bookkeeping entry per reaped slot is a slow leak on a tier that churns a slot per job
    (measured: 50 entries against 0 live slots)."""
    from blastbox.host.pool import SlotState, WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return None            # always UNKNOWN -> stamps _unknown_since

        def reap(self, slot):  # noqa: ANN001
            pass

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0])
    for i in range(5):
        pool._slots[f"s{i}"] = _slot(f"s{i}", SlotState.IDLE)
        clock[0] += 1.0
        pool._health_check()                 # stamps an entry for each
        pool._slots.pop(f"s{i}")             # ...and the slot then leaves the pool
    clock[0] += 1.0
    pool._health_check()
    assert pool._unknown_since == {}, f"bookkeeping leaked for departed slots: {pool._unknown_since}"


def test_escalated_disposals_do_not_block_the_tick_thread():
    """The escalation routed suspected-dead slots into the SYNCHRONOUS reap path, so a whole tier's
    terminates ran serially on the sole tick thread with no budget -- during the very outage that
    made them unknown, each AWS terminate can burn its full CLI timeout. That is exactly the wedge
    issue #77 exists to fix, reintroduced on the health path (upstream P1). They must go through the
    bounded deferred reapers instead."""
    from blastbox.host.pool import SlotState, WarmPool

    reaping = {"n": 0}

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return None                     # permanently UNKNOWN -> escalation fires

        def reap(self, slot):  # noqa: ANN001
            reaping["n"] += 1
            raise AssertionError("reap must NOT run inline on the tick thread")

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0], unknown_grace_s=10.0)
    for i in range(3):
        pool._slots[f"s{i}"] = _slot(f"s{i}", SlotState.IDLE)
    for _ in range(6):
        clock[0] += 5.0
        pool._health_check()                # must not raise: nothing reaped inline
    assert reaping["n"] == 0, "an escalated disposal ran synchronously on the tick thread"
    assert pool._deferred_reap, "escalated slots were not handed to the bounded deferred reapers"


def test_a_brownout_is_not_recorded_as_demand():
    """When every slot is skipped because its runtime could not ANSWER, the shortage is a brownout,
    not load. Recording it as a demand miss trips burst-spawning during the outage -- adding
    control-plane calls to a control plane that is already failing (upstream P2)."""
    from blastbox.host.pool import SlotState, WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            return None                     # fast UNKNOWN, like a throttled describe

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    misses: list[int] = []
    pool._record_demand_miss = lambda: misses.append(1)   # type: ignore[method-assign]
    assert pool.claim(timeout_s=0.2) is None
    assert misses == [], f"a control-plane brownout was billed as demand pressure: {len(misses)}"


def test_a_successful_claim_probe_resets_the_unknown_grace():
    """The unknown clock was reset only by the HEALTH tick. A slot answering fine at CLAIM time --
    i.e. being handed out and used -- could still age out and be escalated to dead (upstream P2)."""
    from blastbox.host.pool import SlotState, WarmPool

    answers = {"v": None}

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return answers["v"]

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            return answers["v"]

        def reap(self, slot):  # noqa: ANN001
            pass

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0], unknown_grace_s=50.0)
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)

    clock[0] += 10.0
    pool._health_check()                       # UNKNOWN -> clock starts
    assert "s1" in pool._unknown_since

    answers["v"] = True                        # control plane recovers, and a CLAIM succeeds
    got = pool.claim(timeout_s=0.2)
    assert got is not None
    assert "s1" not in pool._unknown_since, (
        "a slot that answered at claim time still carried its unknown clock toward escalation")


def test_a_definitive_probe_lifts_the_demand_suppression():
    """A slot that answered UNKNOWN once stayed in `unprobeable` for the whole claim, so the
    demand-miss suppression stayed on even after the control plane recovered -- and a lone queued
    job could never trip burst capacity again inside that window (upstream P2)."""
    from blastbox.host.pool import SlotState, WarmPool

    answers = {"v": None}

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def is_alive_for_claim(self, slot, *, budget_s=None):  # noqa: ANN001
            return answers["v"]

        def reap(self, slot):  # noqa: ANN001
            pass

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0])
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    unprobeable: dict[str, float] = {}
    assert pool._try_claim_one(None, None, unprobeable) is None      # UNKNOWN -> suppressed
    assert "s1" in unprobeable

    answers["v"] = True                                             # control plane recovers
    clock[0] += pool._UNPROBEABLE_COOLDOWN_S + 0.1                   # ...and the cooldown elapses
    got = pool._try_claim_one(None, None, unprobeable)
    assert got is not None
    assert "s1" not in unprobeable, (
        "a definitively-answered slot stayed suppressed, muting demand for the rest of the claim")


def test_the_unknown_clock_is_not_backdated_across_a_slow_health_pass():
    """_health_check samples `now` ONCE and then probes every idle slot serially. Stamping each
    slot's first UNKNOWN with that stale value charges later slots for the time spent probing
    earlier ones -- so on a big tier with slow probes a slot can be born already most of the way
    through its grace and escalate on its very first unknown (escalated codex, loop 5)."""
    from blastbox.host.pool import SlotState, WarmPool

    clock = [1000.0]
    reaped: list[str] = []

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            clock[0] += 40.0        # each probe is SLOW, as during a real brownout
            return None

        def reap(self, slot):  # noqa: ANN001
            reaped.append(slot.slot_id)

    # One pass costs 4 x 40s = 160s, so every slot is legitimately re-probed 160s apart. The grace
    # sits ABOVE that but BELOW 160 + the backdating error (up to a full pass), so only a backdated
    # clock can push a slot over it.
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0], unknown_grace_s=200.0)
    for i in range(4):
        pool._slots[f"s{i}"] = _slot(f"s{i}", SlotState.IDLE)

    # Pass 1 stamps each slot. The LAST slot is not actually probed until ~160s in, but a single
    # `now` sampled at the top stamps it as though it went unknown at t=0.
    pool._health_check()
    pool._drain_deferred_reaps()
    assert reaped == [], f"escalated on the FIRST unknown: {reaped}"
    stamps = dict(pool._unknown_since)
    assert len(stamps) == 4
    assert max(stamps.values()) > min(stamps.values()), (
        f"all four slots share one timestamp, so the later ones are backdated: {stamps}")

    # Pass 2: the last slot has genuinely been unknown for only one pass, far inside the 100s grace.
    pool._health_check()
    pool._drain_deferred_reaps()
    assert reaped == [], (
        f"escalated on backdated time: every slot has been unknown for one 160s pass, inside the "
        f"200s grace, yet these were reaped: {reaped}")


def test_a_stale_health_result_is_dropped_when_a_claim_took_the_slot():
    """Taking the lock only SERIALISES the writes, it does not ORDER them: a probe that began while
    the slot was IDLE could still stamp _unknown_since after a concurrent claim cleared it. That
    stale stamp then ages untouched for the whole job, so the first UNKNOWN after release exceeds
    the grace at once and evicts a worker that has been serving the entire time (upstream P2)."""
    from blastbox.host.pool import SlotState, WarmPool

    class _Rt:
        kind = "test"

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            # simulate the claim landing WHILE this probe is in flight
            slot.state = SlotState.ASSIGNED
            return None

        def reap(self, slot):  # noqa: ANN001
            pass

    clock = [1000.0]
    pool = WarmPool(runtime=_Rt(), warm_size=0, clock=lambda: clock[0])
    pool._slots["s1"] = _slot("s1", SlotState.IDLE)
    pool._health_check()
    assert "s1" not in pool._unknown_since, (
        "a health result that lost the race to a claim was written anyway, and will age while the "
        "slot is ASSIGNED")


def test_the_wedged_after_threshold_exceeds_one_reap_call():
    """A disposal is a remote call bounded by the runtime's cli_timeout_s (120s by default). A flat
    60s threshold declares a perfectly healthy slow reap wedged and spawns a replacement beside it,
    so _MAX_REAPERS stops bounding concurrency during exactly the control-plane slowdown where
    extra CLI calls amplify the outage (upstream P2)."""
    from types import SimpleNamespace

    from blastbox.host.pool import WarmPool

    class _Rt:
        kind = "test"
        cfg = SimpleNamespace(cli_timeout_s=120.0)

        def spawn(self):
            raise AssertionError("no spawning in this test")

        def is_ready(self, slot):  # noqa: ANN001
            return True

        def is_alive(self, slot):  # noqa: ANN001
            return True

        def reap(self, slot):  # noqa: ANN001
            pass

    pool = WarmPool(runtime=_Rt(), warm_size=0)
    assert pool._reaper_wedged_after_s() > 120.0, (
        "a legitimate 120s disposal would be declared wedged and replaced mid-flight")

    class _NoCfg(_Rt):
        cfg = None

    assert WarmPool(runtime=_NoCfg(), warm_size=0)._reaper_wedged_after_s() == \
        WarmPool._REAPER_WEDGED_AFTER_S      # runtimes without a cfg keep the floor


def test_the_wedge_threshold_sees_through_a_cascade():
    """PRODUCTION wraps tiers in a CascadingRuntime, which has no cfg of its own -- so reading
    self._runtime.cfg silently fell back to the 60s floor and the derived threshold never applied
    where it was actually needed. Any wrapped tier could own the slot being reaped (upstream P2)."""
    from types import SimpleNamespace

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

    slow = _Rt()
    slow.cfg = SimpleNamespace(cli_timeout_s=120.0)      # type: ignore[attr-defined]
    fast = _Rt()
    fast.cfg = SimpleNamespace(cli_timeout_s=30.0)       # type: ignore[attr-defined]

    class _Cascade(_Rt):
        tiers = [SimpleNamespace(runtime=fast), SimpleNamespace(runtime=slow)]

    pool = WarmPool(runtime=_Cascade(), warm_size=1)
    assert pool._reaper_wedged_after_s() > 120.0, (
        "behind a cascade the threshold fell back to the floor, so a legitimate 120s disposal is "
        "declared wedged and replaced mid-flight")


class _UnknownReadyRuntime(_FakeRuntime):
    """A runtime whose is_ready() reports UNKNOWN -- the control plane won't answer.

    The cloud tiers' shape during an AWS brownout: the instance may be booting perfectly well,
    we simply cannot describe it.
    """

    def __init__(self) -> None:
        super().__init__()
        self.unknown = True

    def is_ready(self, slot: Slot) -> "bool | None":
        if self.unknown:
            return None
        return super().is_ready(slot)


def test_a_brownout_does_not_evict_the_tiers_warming_slots() -> None:
    """issue #79: is_ready UNKNOWN must not be spent as the warming timeout's evidence.

    A brownout outlasting warming_timeout_s used to terminate every WARMING instance in the tier
    at once -- instances booting fine whose only fault was that AWS wouldn't describe them. Spawns
    are throttled during the same event, so the tier then held at zero.
    """
    clock = _FakeClock()
    rt = _UnknownReadyRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
        warming_timeout_s=60.0, unknown_grace_s=300.0,
    )
    pool.tick()
    warming = [s for s in pool._slots.values() if s.state == SlotState.WARMING]
    assert len(warming) == 1
    slot_id = warming[0].slot_id

    # Well past warming_timeout_s, still inside the unknown grace: the slot SURVIVES.
    clock.advance(120.0)
    pool.tick()
    assert slot_id in pool._slots, "a slot we could not ask about was evicted by the warming timeout"
    assert slot_id not in rt.reaped

    # The control plane comes back and says "ready": it promotes, having never been destroyed.
    rt.unknown = False
    clock.advance(1.0)
    pool.tick()
    assert pool._slots[slot_id].state == SlotState.IDLE


def _drain_reapers(pool, timeout: float = 5.0) -> None:
    """Wait for the dedicated reaper thread(s) to finish.

    An expired WARMING unknown is a SUSPICION, so since 2026-08-21 it is disposed of on the
    deferred reaper thread rather than synchronously on the tick thread -- that is the whole point
    (a terminate burning its full CLI timeout must not stall promotion, health checks and spawning
    for the entire pool). The eviction is therefore still guaranteed but no longer complete by the
    time tick() returns, so a test asserting `slot_id in rt.reaped` has to join the reaper instead
    of racing it. Without this it passes alone and fails under load, which is worse than failing.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        threads = [t for t, *_ in list(getattr(pool, "_reaper_threads", []))]
        alive = [t for t in threads if t.is_alive()]
        for t in alive:
            t.join(timeout=0.1)
        if not alive and not pool._deferred_reap:
            return
        pool.tick()


def test_an_unknown_that_outlasts_the_grace_still_evicts() -> None:
    """The exemption must be BOUNDED. An unbounded one is strictly worse than the bug it fixes:
    the tier wedges at zero capacity forever while is_healthy() still reports True.
    """
    clock = _FakeClock()
    rt = _UnknownReadyRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
        warming_timeout_s=60.0, unknown_grace_s=100.0,
    )
    pool.tick()
    slot_id = [s for s in pool._slots.values() if s.state == SlotState.WARMING][0].slot_id

    clock.advance(90.0)   # past warming timeout, and the episode is first OBSERVED here
    pool.tick()
    assert slot_id in pool._slots
    # The grace runs from when the UNKNOWN was first SEEN, not from spawn -- we cannot start a
    # clock on an episode we had not yet observed.
    since = pool._warming_unknown_since[slot_id]

    clock.advance(101.0)  # unbroken UNKNOWN for longer than the 100s grace
    pool.tick()
    _drain_reapers(pool)
    assert clock() - since > 100.0, "sanity: the episode really did outlast the grace"
    assert slot_id in rt.reaped, "an outage that outlasts the grace must still let the slot age out"
    assert slot_id not in pool._slots


def test_a_definitive_not_ready_still_ages_the_slot_out() -> None:
    """Only the ABSENCE of an answer is exempt. A tier that keeps answering "not ready yet" is
    telling us about the worker, so the warming timeout must still apply -- otherwise the exemption
    would silently disable the timeout for every runtime.
    """
    clock = _FakeClock()
    rt = _FakeRuntime()
    rt.set_default_ready_after(10**9)  # answers, definitively, "not ready"
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
        warming_timeout_s=60.0, unknown_grace_s=300.0,
    )
    pool.tick()
    slot_id = [s for s in pool._slots.values() if s.state == SlotState.WARMING][0].slot_id

    clock.advance(70.0)
    pool.tick()
    assert slot_id in rt.reaped, "a definitively not-ready slot must still age out"


def test_a_recovered_control_plane_resumes_aging_the_slot() -> None:
    """A brownout that ENDS must not leave the slot permanently exempt: the episode is cleared by
    a definitive answer, so the timeout applies again from then on.
    """
    clock = _FakeClock()
    rt = _UnknownReadyRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
        warming_timeout_s=60.0, unknown_grace_s=300.0,
    )
    pool.tick()
    slot_id = [s for s in pool._slots.values() if s.state == SlotState.WARMING][0].slot_id

    clock.advance(120.0)
    pool.tick()
    assert slot_id in pool._slots

    # Control plane answers again -- definitively "not ready". The episode ends.
    rt.unknown = False
    rt.set_default_ready_after(10**9)
    rt._ready_after[slot_id] = 10**9
    clock.advance(1.0)
    pool.tick()
    assert pool._warming_unknown_since.get(slot_id) is None, "the episode must be cleared"
    assert slot_id in rt.reaped, "with the brownout over, the long-overdue slot ages out"


def test_a_zero_grace_disables_the_warming_exemption_entirely() -> None:
    """unknown_grace_s=0 is the operator saying "do not ride out brownouts". The exemption must
    honour that, exactly as the IDLE path's escalation does -- otherwise setting it to 0 silently
    turns the warming timeout OFF for any tier that reports UNKNOWN, the opposite of the intent.
    """
    clock = _FakeClock()
    rt = _UnknownReadyRuntime()
    pool = WarmPool(
        runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
        warming_timeout_s=60.0, unknown_grace_s=0.0,
    )
    pool.tick()
    slot_id = [s for s in pool._slots.values() if s.state == SlotState.WARMING][0].slot_id

    clock.advance(70.0)
    pool.tick()
    _drain_reapers(pool)
    assert slot_id in rt.reaped, "grace=0 must disable the exemption, not enable it forever"


class _DrainingOnProbeRuntime(_FakeRuntime):
    """is_ready() finds the slot has been flipped to DRAINING by a concurrent stop(), and cannot
    reach the control plane to say anything about it."""

    def __init__(self, pool_ref: dict) -> None:
        super().__init__()
        self.pool_ref = pool_ref

    def is_ready(self, slot: Slot) -> "bool | None":
        live = self.pool_ref["pool"]._slots.get(slot.slot_id)
        if live is not None:
            live.state = SlotState.DRAINING
        return None


def test_an_unknown_probe_does_not_reap_a_draining_slot() -> None:
    """The DRAINING branch reaps on a CONFIRMED not-ready. UNKNOWN is falsy too, so a plain
    truthiness test there would reap a slot precisely BECAUSE we could not ask about it -- the bug
    the tri-state exists to prevent, re-entering through the back door (issue #79).
    """
    ref: dict = {}
    clock = _FakeClock()
    rt = _DrainingOnProbeRuntime(ref)
    pool = WarmPool(runtime=rt, warm_size=1, clock=clock, spawn_rate_limit=100.0,
                    warming_timeout_s=600.0, unknown_grace_s=300.0)
    ref["pool"] = pool
    pool.tick()
    slot_id = next(iter(pool._slots))

    clock.advance(1.0)
    pool.tick()   # is_ready flips it to DRAINING and returns UNKNOWN
    assert pool._slots[slot_id].state == SlotState.DRAINING, "sanity: the branch is reachable"
    assert slot_id not in rt.reaped, "a slot we could not ask about was reaped as not-ready"


def test_an_unqueryable_liveness_probe_does_not_reap_a_recycled_slot() -> None:
    """issue #79: the reuse path shared one `except` between recycle and the liveness probe.

    A recycle failure IS a reason to reap -- the slot was never reset. An exception from is_alive
    is not: it means we could not TELL, and the slot had just been reset successfully and served
    its job fine. This path runs once PER JOB, so the mistake was charged at job rate.
    """
    class _RecycleOkProbeRaises(_FakeRuntime):
        def recycle(self, slot: Slot) -> None:
            pass

        def is_alive(self, slot: Slot) -> bool:
            raise RuntimeError("libvirtd connection reset")

    rt = _RecycleOkProbeRaises()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    pool.release(slot, dirty=True)      # dirty forces the recycle branch

    assert slot.slot_id not in rt.reaped, "a slot we could not probe was reaped after a good recycle"
    assert pool._slots[slot.slot_id].state == SlotState.IDLE


def test_a_failed_recycle_still_reaps() -> None:
    """The other half: an unreset slot must never go back to IDLE, or the next job inherits a
    contaminated worker. Splitting the handler must not weaken this."""
    class _RecycleRaises(_FakeRuntime):
        def recycle(self, slot: Slot) -> None:
            raise RuntimeError("snapshot revert failed")

    rt = _RecycleRaises()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    pool.release(slot, dirty=True)

    assert slot.slot_id in rt.reaped, "an unreset slot must be reaped, not republished"


def test_a_confirmed_dead_slot_after_recycle_is_still_reaped() -> None:
    """And the third case: a CONFIRMED False must keep reaping. Widening the probe handler to
    treat everything as unknown would republish genuinely dead workers."""
    class _RecycleOkButDead(_FakeRuntime):
        def recycle(self, slot: Slot) -> None:
            pass

        def is_alive(self, slot: Slot) -> bool:
            return False

    rt = _RecycleOkButDead()
    pool = WarmPool(runtime=rt, warm_size=1)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.ASSIGNED
    pool.release(slot, dirty=True)

    assert slot.slot_id in rt.reaped, "a confirmed-dead slot must still be reaped"


def test_maintenance_holds_an_exclusive_window_so_claim_cannot_take_the_slot() -> None:
    """issue #80: state-changing maintenance must run under a window the POOL grants.

    The first attempt ran it from is_alive() on an IDLE slot with nothing excluding a concurrent
    claim, so it could hibernate an instance out from under a job. Ownership has to come from the
    only thing that can make a slot unclaimable.
    """
    seen_states: list = []

    class _MaintainingRuntime(_FakeRuntime):
        def __init__(self, pool_ref: dict) -> None:
            super().__init__()
            self.pool_ref = pool_ref

        def maintain_idle(self, slot: Slot) -> bool:
            pool = self.pool_ref["pool"]
            live = pool._slots[slot.slot_id]
            seen_states.append(live.state)
            # A claimant running right now must NOT be able to take it.
            assert pool.claim(timeout_s=0.0) is None, "claim took a slot under maintenance"
            return True

    ref: dict = {}
    rt = _MaintainingRuntime(ref)
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    ref["pool"] = pool
    pool.tick()
    pool.tick()

    assert seen_states, "the maintenance hook never ran"
    assert seen_states[0] == SlotState.ASSIGNED, "the slot was not reserved before the hook ran"
    # ...and it is handed back afterwards.
    slot_id = next(iter(pool._slots))
    assert pool._slots[slot_id].state == SlotState.IDLE


def test_a_raising_maintenance_hook_still_hands_the_slot_back() -> None:
    """A slot stranded in ASSIGNED is capacity lost forever: _spawn_to_deficit counts it as active,
    so nothing replaces it and nothing can claim it."""
    class _RaisingRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            raise RuntimeError("describe blew up")

    rt = _RaisingRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.tick()
    pool.tick()

    slot_id = next(iter(pool._slots))
    assert pool._slots[slot_id].state == SlotState.IDLE, "the slot was stranded in ASSIGNED"
    assert slot_id not in rt.reaped, "an exception is not a verdict about the slot"


def test_a_maintenance_retirement_whose_terminate_fails_is_retried_not_stranded() -> None:
    """`retire()` does NOT raise on a failed reap -- it logs pool.retire_reap_error and returns
    normally, leaving the slot tracked and DRAINING.

    So the `except Exception` around the retire call was dead code for the case that actually
    happens. A tracked DRAINING husk keeps counting against concurrent_ceiling, and nothing retries
    it: during a correlated termination brownout every retired slot is stranded and its replacement
    never spawns, until the process restarts. The deferred reaper is exactly the machinery for
    "disposal failed, retry off the tick thread".

    MUTATION: drop the _deferred_reap enqueue -> the husk sits DRAINING with nothing retrying it.
    """
    class _UnusableUnreapable(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            return False                          # terminal: retire it

        def reap(self, slot: Slot) -> None:
            raise OSError("terminate-instances: throttled")

    pool = WarmPool(runtime=_UnusableUnreapable(), warm_size=1, spawn_rate_limit=100.0,
                    maintain_interval_s=0.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.IDLE

    pool._maintain_idle()

    cur = pool._slots.get(slot.slot_id)
    assert cur is not None and cur.state == SlotState.DRAINING, (
        "sanity: a failed terminate should leave the husk tracked and DRAINING")
    assert slot.slot_id in pool._deferred_reap, (
        "the husk was left DRAINING with nothing retrying its disposal; it counts against "
        "concurrent_ceiling forever and its replacement never spawns"
    )


def test_a_proven_slot_is_restored_to_idle_not_warming() -> None:
    """The undo path asks "has this slot ever been ready?" and briefly borrowed
    _warming_unknown_credit to answer it.

    That dict is a timeout LEDGER with a different lifetime -- it survived promotion -- so it
    silently became a permanent "was once warming-unknown" flag. A PROVEN, promoted, IDLE slot was
    then restored to WARMING carrying its original spawned_at, which had already exceeded
    warming_timeout_s; it was evicted on the next tick and charged as a CONFIRMED restore failure,
    which feeds _maybe_rebuild_base and can discard a healthy snapshot base. Two questions, two
    fields: _never_ready answers this one and is cleared on promotion.

    Driven straight at _drain_deferred_reaps rather than through tick(). Two earlier attempts went
    through the tick loop and were VACUOUS: the restore is immediately followed by a re-promotion,
    so the state sampled afterwards is IDLE whatever the undo chose, and a mutation of BOTH halves
    of the fix survived. The decision under test is one branch; test that branch.

    MUTATION: key the restore on _warming_unknown_credit and stop clearing it at promotion ->
    the proven slot comes back WARMING.
    """
    class _Unreapable(_FakeRuntime):
        def reap(self, slot: Slot) -> None:
            raise OSError("terminate-instances: throttled")

    pool = WarmPool(runtime=_Unreapable(), warm_size=1, spawn_rate_limit=100.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    assert slot.slot_id in pool._never_ready, "a freshly spawned slot has never been ready"

    # Promote it FOR REAL, so the clearing is exercised rather than simulated. The banked credit
    # must go with it: it is WARMING-scoped, and leaving it behind is precisely what turned a
    # timeout ledger into a permanent state-history flag.
    pool._warming_unknown_credit[slot.slot_id] = 3.0
    slot.state = SlotState.WARMING
    pool._promote_warming()
    assert slot.state == SlotState.IDLE, "sanity: the slot must have been promoted"
    assert slot.slot_id not in pool._never_ready, (
        "promotion did not clear the never-ready marker, so a proven slot still looks unproven")
    assert slot.slot_id not in pool._warming_unknown_credit, (
        "the WARMING-scoped credit outlived promotion; that is the lifetime bug that made it a "
        "permanent 'was once warming-unknown' flag")
    pool._warming_unknown_credit[slot.slot_id] = 3.0   # the stale entry the old code keyed on

    # ...now escalated on suspicion and queued for disposal, which will fail.
    slot.state = SlotState.DRAINING
    pool._suspected_unknown.add(slot.slot_id)
    pool._deferred_reap.add(slot.slot_id)

    pool._drain_deferred_reaps()

    cur = pool._slots.get(slot.slot_id)
    assert cur is not None, "the failed disposal must leave the slot tracked"
    assert cur.state == SlotState.IDLE, (
        f"a slot that HAS been ready was restored to {cur.state} with a stale spawned_at; it trips "
        f"the warming timeout on the next tick and is charged as a confirmed restore failure"
    )


def test_an_undone_disposal_does_not_publish_a_never_ready_slot_as_claimable() -> None:
    """The undo path restores a suspected slot to IDLE. Since expired warming-unknowns became
    `suspected`, that path can now apply to a slot which has NEVER passed is_ready().

    IDLE is claimable. A disposable EC2/Lambda resource that merely describes as `running` would
    be handed to a job before its agent or auth token is up, so user jobs fail during exactly the
    recovery this restore exists to help. A restored warming slot has to go back to WARMING and
    earn IDLE through promotion.

    MUTATION: restore `cur.state = SlotState.IDLE` unconditionally -> the slot is claimable while
    never having been ready, and this fails.
    """
    now = [1000.0]

    class _BrownoutRuntime(_FakeRuntime):
        def is_ready(self, slot: Slot):
            return None                       # control plane will not answer

        def reap(self, slot: Slot) -> None:
            raise OSError("terminate-instances: throttled")   # the same outage

    pool = WarmPool(runtime=_BrownoutRuntime(), warm_size=1, spawn_rate_limit=100.0,
                    clock=lambda: now[0], warming_timeout_s=10.0, unknown_grace_s=5.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.WARMING

    for _ in range(4):                        # age past the grace and the warming timeout
        pool.tick()
        now[0] += 6.0
    _drain_reapers(pool)

    cur = pool._slots.get(slot.slot_id)
    assert cur is not None, "the failed disposal should have left the slot tracked"
    assert cur.state != SlotState.IDLE, (
        "a slot that never passed is_ready() was republished as IDLE (claimable) after its "
        "disposal failed; a job would run on a worker whose agent may not be up"
    )


def test_a_warming_slot_whose_unknown_episode_expires_is_suspected_not_convicted() -> None:
    """The IDLE path escalates an expired UNKNOWN "on suspicion, not on a verdict". The WARMING
    path did not, and the asymmetry costs a tier its capacity during the outage this PR exists to
    survive.

    A WARMING slot past its timeout with no definitive observation lands in `stuck_warming`, which
    becomes `dead` with no `suspected` membership. Three consequences, all during one brownout:
    it is charged to the restore-failure streak (which can discard a healthy snapshot on zero
    confirmed deaths), it is reaped SYNCHRONOUSLY on the sole tick thread, and when that reap
    fails -- same unresponsive control plane -- it is left DRAINING forever with its eviction
    token spent, counting against the ceiling until the process restarts.

    MUTATION: drop the warming-unknown ids from `suspected` -> the slot is convicted, reaped
    synchronously and stranded, and this fails.
    """
    ready_answer: list = [None]        # UNKNOWN: the control plane will not say

    reap_threads: list = []

    class _BrownoutRuntime(_FakeRuntime):
        def is_ready(self, slot: Slot):
            return ready_answer[0]

        def reap(self, slot: Slot) -> None:
            reap_threads.append(threading.get_ident())
            super().reap(slot)

        # NOTE: in the real outage the terminate is throttled too, and that reap failure is what
        # strands the slot DRAINING forever. Not simulated here -- it raises out of tick() and
        # masks the assertion below. This test pins the CLASSIFICATION; the stranding is its
        # consequence.

    now = [1000.0]
    rt = _BrownoutRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, clock=lambda: now[0],
                    warming_timeout_s=10.0, unknown_grace_s=5.0)
    pool._spawn_to_deficit(ready=True)
    slot = next(iter(pool._slots.values()))
    slot.state = SlotState.WARMING

    for _ in range(4):                 # age it past both the grace and the warming timeout
        pool.tick()
        now[0] += 6.0

    # The directly observable half of the conviction: the restore-failure streak drives
    # _maybe_rebuild_base, which DISCARDS A HEALTHY SNAPSHOT. Silence is not evidence about the
    # worker, so it must not be spent as any. (The other half -- deferred vs synchronous reap, and
    # the DRAINING stranding when that reap also fails -- needs a failing terminate to observe,
    # which raises out of tick() and would mask this assertion.)
    assert pool._spawn_consecutive_failures == 0, (
        f"a WARMING slot that timed out on SILENCE was charged to the restore-failure streak "
        f"({pool._spawn_consecutive_failures}); one brownout can now invalidate a healthy base "
        f"on zero confirmed deaths"
    )

    # And the disposal must leave the tick thread. A suspected slot goes to the dedicated reaper
    # (issue #75/#77); a CONVICTED one is terminated inline, so during a brownout each terminate
    # burns its full CLI timeout on the pool's only maintenance thread -- no promotion, no health
    # check, no spawning, for the duration.
    _drain_reapers(pool)
    assert reap_threads, "the slot was never disposed of at all"
    assert threading.get_ident() not in reap_threads, (
        "the slot was reaped INLINE on the tick thread: a suspected-unknown disposal must be "
        "deferred, or one throttled terminate stalls the whole pool"
    )


def test_a_slow_maintenance_hook_does_not_become_eligible_again_immediately() -> None:
    """The cooldown must measure from when the hook RETURNS, not when it started.

    The hook's control-plane calls are bounded by health_probe_timeout_s (default 30s) against a
    cooldown that defaults to 5s. Stamping on entry means a stalled describe leaves the stamp six
    times older than the cooldown before the hook even returns, so the next 0.1s tick starts
    another one -- the rate limit throttles nothing during exactly the brownout it exists for.
    Same defect as _last_admit_attempt in cascade.py, made twice.

    MUTATION: remove the completion re-stamp -> 5 back-to-back ticks give 5 slow calls.
    """
    now = [1000.0]
    calls: list = []

    class _SlowRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            calls.append(now[0])
            now[0] += 30.0          # a stalled describe at the health-probe bound
            return True

    pool = WarmPool(runtime=_SlowRuntime(), warm_size=1, spawn_rate_limit=100.0,
                    clock=lambda: now[0], maintain_interval_s=5.0)
    pool._spawn_to_deficit(ready=True)
    for sl in pool._slots.values():
        sl.state = SlotState.IDLE

    for _ in range(5):
        pool._maintain_idle()
        now[0] += 0.1

    assert len(calls) == 1, (
        f"{len(calls)} slow maintenance passes across 5 ticks ({len(calls)*30}s of tick-thread "
        f"blockage): a hook that outruns its own cooldown is eligible the moment it returns"
    )


def test_the_maintenance_cooldown_map_does_not_grow_without_bound() -> None:
    """`_maintain_last` is keyed by per-spawn slot id, so it leaks one entry per disposed slot.

    ec2-hibernate slots are disposable after a single job and every promoted slot normally passes
    through maintenance before being claimed, so a long-running dispatcher accumulates a permanent
    dictionary entry per COMPLETED JOB while the slots themselves are long gone. Same unbounded
    growth `_forget_slot_health` exists to prevent for every other per-slot map.

    MUTATION: remove the _maintain_last.pop from _forget_slot_health -> the map keeps every id.
    """
    class _MaintainedRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            return True

    rt = _MaintainedRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0, maintain_interval_s=0.0)
    seen: set = set()
    for _ in range(6):
        pool._spawn_to_deficit(ready=True)
        for sl in list(pool._slots.values()):
            sl.state = SlotState.IDLE
        pool._maintain_idle()
        for sl in list(pool._slots.values()):
            seen.add(sl.slot_id)
            pool.retire(sl)

    assert len(seen) >= 3, "sanity: several distinct slots really did pass through maintenance"
    leaked = set(pool._maintain_last) - set(pool._slots)
    assert not leaked, (
        f"{len(leaked)} cooldown entries survive slots that have left the pool; on a disposable "
        f"tier that is one permanent entry per completed job"
    )


def test_maintenance_is_rate_limited_per_slot_not_run_on_every_tick() -> None:
    """The hook is allowed to make UNCACHED control-plane calls, and tick() runs at ~10Hz.

    ec2-hibernate's maintain_idle opens with an uncached describe-instances, so with no per-slot
    interval an idle pool issued one AWS round trip every 0.1s forever -- the reconciliation hook
    manufacturing the DescribeInstances throttling the rest of this PR exists to survive. Every
    other AWS probe path in that runtime is throttled behind the 5s liveness cache for exactly
    this reason; this one was not.

    MUTATION: remove the _maintain_last cooldown check -> 20 calls instead of 1 and this fails.
    """
    calls: list = []
    now = [1000.0]

    class _CountingRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            calls.append(slot.slot_id)
            return True

    rt = _CountingRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0,
                    clock=lambda: now[0], maintain_interval_s=5.0)
    pool._spawn_to_deficit(ready=True)
    for sl in pool._slots.values():
        sl.state = SlotState.IDLE

    for _ in range(20):                 # 2 seconds of ticks at 0.1s
        pool._maintain_idle()
        now[0] += 0.1

    assert len(calls) == 1, (
        f"maintain_idle ran {len(calls)}x in 2s on one slot; at 10Hz that is an unthrottled "
        f"control-plane call per tick"
    )

    now[0] += 5.0                       # past the cooldown
    pool._maintain_idle()
    assert len(calls) == 2, "the cooldown never expires — the slot would stop being reconciled"


def test_an_unusable_slot_is_never_claimable_between_maintenance_and_retirement() -> None:
    """issue #80 follow-up: the exclusive window must not end one instruction before the
    destructive act.

    The first version republished the slot to IDLE and called ``_idle_event.set()`` -- actively
    WAKING a blocked claimant -- and only then called ``retire()``. ``retire`` is not a CAS: it
    overwrites whatever state it finds, ASSIGNED included. So a claimant could take the slot,
    pass ``is_alive_for_claim``, start a job, and have the instance terminated under it.

    Asserted as an INVARIANT on the slot's state rather than by racing a real claimant: `claim`
    is only able to take a slot that is IDLE, so "never IDLE between the verdict and retirement"
    is the property, and checking it directly is deterministic instead of timing-dependent.

    MUTATION: restore the unconditional `cur.state = SlotState.IDLE` in the finally block -> the
    observed state below is IDLE and this fails.
    """
    seen: list = []

    class _UnusableRuntime(_FakeRuntime):
        def __init__(self, pool_ref: dict) -> None:
            super().__init__()
            self.pool_ref = pool_ref
            self.verdict_given = False

        def maintain_idle(self, slot: Slot) -> bool:
            self.verdict_given = True
            return False        # terminal: hibernation stuck past its timeout

        def base_identity(self, slot: Slot) -> str:
            # Called by retire(fault="worker") during failure attribution, i.e. BEFORE the lock
            # that flips the slot to DRAINING. This is the exact window the bug opened.
            # base_identity is also called on the spawn path, so only record AFTER the verdict --
            # an unscoped recorder passes for the wrong reason (it reads a WARMING slot).
            if self.verdict_given:
                pool = self.pool_ref["pool"]
                live = pool._slots.get(slot.slot_id)
                seen.append(live.state if live else None)
            return "base"

    ref: dict = {}
    rt = _UnusableRuntime(ref)
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    ref["pool"] = pool
    pool.tick()
    pool.tick()

    assert seen, "retire() never ran, so the window was never exercised"
    assert seen[0] != SlotState.IDLE, (
        f"slot was {seen[0]} -- claimable -- between the unusable verdict and retirement; a "
        f"claimant taking it here has its instance terminated mid-job"
    )


def test_maintenance_rotates_so_every_idle_slot_is_eventually_reconciled() -> None:
    """issue #80: 'ONE slot per tick' has to mean a DIFFERENT slot per tick.

    ``next(s for s in self._slots.values() if s.state is IDLE)`` over an insertion-ordered dict
    returns the same slot forever, because the hook restores it to IDLE without changing the
    order. Slot #2 -- the one whose resume half-succeeded and is billing -- is then never looked
    at, which is precisely the leak this hook exists to close.

    MUTATION: drop the rotation cursor -> only the first slot is ever maintained and this fails.
    """
    maintained: list = []

    class _RecordingRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            maintained.append(slot.slot_id)
            return True

    rt = _RecordingRuntime()
    # interval 0 ISOLATES the cursor. With the default 5s cooldown this property also holds
    # without any cursor at all (a recently-maintained slot is skipped, so the scan falls through
    # to the next one) -- and a mutation that broke the cursor survived the first version of this
    # test for exactly that reason. Turning the cooldown off leaves the cursor as the only thing
    # that can rotate.
    pool = WarmPool(runtime=rt, warm_size=3, spawn_rate_limit=100.0, maintain_interval_s=0.0)
    pool._spawn_to_deficit(ready=True)
    for s in pool._slots.values():
        s.state = SlotState.IDLE
    ids = [s.slot_id for s in pool._slots.values()]
    assert len(ids) == 3

    for _ in range(9):
        pool._maintain_idle()

    assert set(maintained) == set(ids), (
        f"only {len(set(maintained))} of 3 idle slots were ever reconciled: "
        f"{ {i: maintained.count(i) for i in ids} }"
    )


def test_a_slot_reported_unusable_is_retired() -> None:
    """The terminal give-up has to RETURN capacity. Parking a permanently unclaimable slot is the
    failure mode issue #80 calls out: it blocks its own replacement."""
    class _UnusableRuntime(_FakeRuntime):
        def maintain_idle(self, slot: Slot) -> bool:
            return False

    rt = _UnusableRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.tick()
    slot_id = next(iter(pool._slots))
    pool.tick()

    assert slot_id in rt.reaped or slot_id not in pool._slots, (
        "an unusable slot must be retired so a replacement can spawn"
    )


def test_a_runtime_without_the_hook_is_untouched() -> None:
    """The seam is optional -- every local tier lacks it and must be unaffected."""
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=1, spawn_rate_limit=100.0)
    pool.tick()
    pool.tick()
    slot_id = next(iter(pool._slots))
    assert pool._slots[slot_id].state == SlotState.IDLE
    assert rt.reaped == []
