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
    pool.stop(stop_timeout_s=1.0)
    dt = time.monotonic() - t0
    assert 0.8 < dt < 5.0                           # gave up ~1s (the ceiling), did NOT hang for 10s


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

    # Dead slot should have been reaped (or dropped)
    assert dead_id in rt.reaped


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
