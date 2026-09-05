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
from concurrent.futures import ThreadPoolExecutor


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


def test_a_reservation_counts_spawns_already_in_flight():
    """The predicate itself, with no scheduler in the way.

    The concurrent test below can only BIAS the interleaving; whether the
    over-reserved spawns end up published depends on how the pre-spawn gate's
    declines interleave with the remaining gated calls. This one removes the
    race entirely: a batch has already reserved the whole ceiling, and the next
    caller must reserve NOTHING.

    The bucket token is the tell. `_spawn_batch_concurrent` consumes one per
    reservation ATTEMPT and then checks the ceiling, so a caller that stops at
    the first check has consumed exactly one. Counting in_flight-blind, it
    consumes one per slot of headroom it wrongly believes it has.
    """
    rt = _SlowSpawnRuntime(delay=0.01)
    ceiling = 4
    pool = WarmPool(runtime=rt, warm_size=ceiling, concurrent_ceiling=ceiling,
                    spawn_rate_limit=1000.0, spawn_concurrency=ceiling)

    tokens = 0
    real_consume = pool._bucket.consume

    def counted_consume():
        nonlocal tokens
        tokens += 1
        return real_consume()

    pool._bucket.consume = counted_consume

    # A batch already in flight has promised the node the whole ceiling; none of
    # it is published yet, which is exactly the window the counter exists for.
    with pool._lock:
        pool._spawns_in_flight = ceiling

    pool._spawn_batch_concurrent(ceiling, None)

    assert tokens == 1, (
        f"the caller must stop at its FIRST ceiling check, taking one token; "
        f"took {tokens}. More than one means the reservation predicate is "
        f"ignoring the {ceiling} spawns already in flight."
    )
    assert not pool._slots, f"nothing may be created: {len(pool._slots)} slots"
    assert rt.max_in_flight == 0, "no spawn may even be attempted"
    assert pool._spawns_in_flight == ceiling, "the in-flight count must be untouched"


def test_ceiling_holds_when_batches_overlap():
    """The reservation counter, against the caller it exists to defend against.

    The previous version asked for warm_size=10 with ceiling=4 and asserted the
    pool stayed at 4. `WarmPool.__init__` clamps warm_size DOWN to the ceiling,
    so the target was 4 all along and no overshoot was ever attempted: deleting
    both guards left it passing. It was skipped as vacuous with a note to
    rewrite it against a real overshoot. This is that rewrite.

    `_spawn_batch_concurrent` documents `_spawns_in_flight` as defensive -- the
    maintenance thread waits for each batch, so batches cannot overlap through
    `tick()` and the counter is unreachable that way. It exists for "a future
    caller which issues batches without waiting", so the test IS that caller:
    two batches issued concurrently, each asking for the whole ceiling.

    Without the counter both batches see an empty pool, both reserve the full
    ceiling, and the pool promises the node twice the workers it is allowed.

    What this test is FOR: that two overlapping callers leave the pool at
    exactly its ceiling and neither deadlocks it. It biases the interleaving but
    cannot guarantee it -- the gates below hold both callers in their loops and
    stop either publishing before the other has taken a token, and that is as
    far as scheduler-dependent synchronisation goes. The reservation PREDICATE
    is pinned race-free by
    `test_a_reservation_counts_spawns_already_in_flight`; do not rely on this
    one to catch that regression on any single run.
    """
    rt = _SlowSpawnRuntime(delay=0.15)
    ceiling = 4
    pool = WarmPool(runtime=rt, warm_size=ceiling, concurrent_ceiling=ceiling,
                    spawn_rate_limit=1000.0, spawn_concurrency=ceiling)

    # Two synchronisation points, because entering the function together proves
    # nothing about the reservation loops:
    #
    #   both_reserving  -- neither caller passes its FIRST token until the other
    #                      is in its loop too. The bucket is consumed once per
    #                      reservation attempt, so this puts them there together.
    #   both_consumed   -- no slot is PUBLISHED until both callers have taken a
    #                      token. A caller's ceiling check follows its token
    #                      immediately, so this stops one caller reserving,
    #                      spawning and publishing a full pool before the other
    #                      checks anything -- which lets the unguarded predicate
    #                      yield four slots and the regression survive. Measured
    #                      before this gate: the mutant escaped 4 runs in 10.
    #
    # Blocking each caller's SECOND consume instead -- proving a reservation
    # completed rather than merely started -- is worse: when the ceiling
    # legitimately stops the other caller at its first check it never reaches
    # consume #2, the barrier times out, and the mutant escapes more often
    # (measured 3/5).
    peak_reserved = 0

    def _sample_reserved() -> None:
        nonlocal peak_reserved
        peak_reserved = max(peak_reserved, pool._spawns_in_flight)

    both_reserving = threading.Barrier(2, timeout=5)
    both_consumed = threading.Event()
    consumes: dict[int, int] = {}
    seen_lock = threading.Lock()
    real_consume = pool._bucket.consume

    def interleaved_consume():
        caller = threading.get_ident()
        with seen_lock:
            consumes[caller] = consumes.get(caller, 0) + 1
            first_token = consumes[caller] == 1
            everyone_in = len(consumes) == 2
        if everyone_in:
            both_consumed.set()
        if first_token:
            try:
                both_reserving.wait()
            except threading.BrokenBarrierError:
                pass
        # Sampled HERE, inside the reservation loop, not only at spawn time.
        # Whether the over-reserved spawns end up published is a race -- the
        # gate declines them and releases reservations while later gated calls
        # are still deciding -- so the published count detects the regression
        # only most of the time (measured 8 runs in 10). The RESERVATION count
        # does not race: with the counter dropped from the predicate, both
        # callers reserve the whole ceiling before anything is published,
        # because publication waits on `both_consumed` and spawns are slow.
        _sample_reserved()
        return real_consume()

    pool._bucket.consume = interleaved_consume

    # Watch the RESERVATIONS too, not only the slots that get published: each is
    # an intent to create a worker, and the pre-spawn gate declining it later
    # still means the pool briefly promised the node more than its ceiling.
    real_spawn = rt.spawn

    def watched_spawn():
        both_consumed.wait(timeout=5)
        _sample_reserved()
        return real_spawn()

    rt.spawn = watched_spawn

    # Futures, not raw threads: a raw thread's exception never reaches the test,
    # so one caller could fail outright while the other filled the pool and
    # every assertion below would still pass.
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [
            ex.submit(pool._spawn_batch_concurrent, ceiling, None) for _ in range(2)
        ]
        for future in futures:
            future.result(timeout=15)   # re-raises whatever that caller raised

    # EXACTLY the ceiling, not merely at most: two batches asking for 4 each
    # must FILL the pool to 4, not deadlock it. Bounding reservations by
    # published slots alone makes both batches reserve the full ceiling and the
    # pre-spawn gate then declines every one of them -- the pool creates
    # NOTHING and the ceiling "holds" vacuously, exactly as it did before.
    assert len(pool._slots) == ceiling, (
        f"expected the pool to fill to {ceiling}, got {len(pool._slots)} slots"
    )
    assert rt.max_in_flight <= ceiling, (
        f"more spawns in flight than the ceiling allows: {rt.max_in_flight}"
    )
    assert pool._spawns_in_flight == 0, "every reservation must be released"
    assert peak_reserved <= ceiling, (
        f"reservations overshot the ceiling: {peak_reserved} > {ceiling}"
    )
    # The schedule this test needs actually happened. Without this a run where
    # one caller never reached its loop would pass silently, and the regression
    # would go undetected on exactly that run.
    assert len(consumes) == 2, (
        f"both callers must reach the reservation loop; only {len(consumes)} did"
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
