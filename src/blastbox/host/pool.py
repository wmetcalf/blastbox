"""Warm-pool manager for blastbox — engine-agnostic pre-spawned worker slots.

State machine
-------------
    spawn() → WARMING → IDLE → ASSIGNED → DRAINING → (gone)
                   |                                     ^
                   +→ (reap on spawn failure) ───────────+

Invariants enforced:
- One job per slot (warm ≠ reuse): release() ALWAYS reaps; there is no
  ASSIGNED→IDLE path. A reaped slot_id never reappears as IDLE.
- Liveness race: claim() re-checks is_alive() inside the lock; a slot that
  died between IDLE and claim is dropped+replaced, never handed out.
- No double-claim: the slot dict is mutated under a single threading.Lock so
  two concurrent claim() calls cannot pick the same slot.
- concurrent_ceiling: tick() clamps new spawns so slot_count stays ≤ ceiling.
- spawn_rate_limit: token-bucket on the injected clock; max N spawns/sec.
- stop() reaps every slot regardless of state.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from blastbox.observability.metrics import (
    record_pool_state,
    record_slot_reaped,
    record_slot_spawned,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class SlotState(str, Enum):
    SPAWNING = "spawning"
    WARMING = "warming"
    IDLE = "idle"
    ASSIGNED = "assigned"
    DRAINING = "draining"


@dataclass
class Slot:
    slot_id: str
    control_dir: Path        # FileWarmControl handshake dir (ready/go.json/done)
    input_dir: Path
    output_dir: Path
    state: SlotState
    container_id: str | None = None
    spawned_at: float = 0.0


@runtime_checkable
class SlotRuntime(Protocol):
    """Engine-agnostic protocol for managing one warm worker slot."""

    def spawn(self) -> Slot:
        """Launch a warm worker; returns a SPAWNING/WARMING slot."""
        ...

    def is_ready(self, slot: Slot) -> bool:
        """True once the worker has signalled ready (control_dir/ready)."""
        ...

    def is_alive(self, slot: Slot) -> bool:
        """True if the underlying process/container is still running."""
        ...

    def reap(self, slot: Slot) -> None:
        """Kill+rm the container/process and clean up slot dirs."""
        ...


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (injected clock for determinism)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Leaky-bucket / token-bucket for spawn-rate limiting.

    Initialised with a full bucket (up to ``rate`` tokens so we don't block
    the very first spawns).  Tokens refill at ``rate`` per second.
    """

    def __init__(self, rate: float, clock: Callable[[], float]) -> None:
        self._rate = rate           # tokens per second
        self._tokens = rate         # start full
        self._last_ts = clock()
        self._clock = clock

    def consume(self, n: int = 1) -> bool:
        """Try to consume n tokens.  Returns True if successful."""
        now = self._clock()
        elapsed = now - self._last_ts
        self._last_ts = now
        self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False


# ---------------------------------------------------------------------------
# WarmPool
# ---------------------------------------------------------------------------


class WarmPool:
    """Manages a warm pool of pre-spawned worker slots.

    Args:
        runtime:            Engine-agnostic SlotRuntime (spawn/is_ready/is_alive/reap).
        warm_size:          Target number of IDLE+WARMING slots to maintain.
        concurrent_ceiling: Hard upper bound on total slot_count (WARMING+IDLE+ASSIGNED+DRAINING).
        spawn_rate_limit:   Maximum new spawns per second (token-bucket).
        clock:              Injectable monotonic clock (default: time.monotonic).
        poll_interval:      Background-thread sleep between ticks (seconds).
        burst_size:         Extra slots to spawn during burst (demand-driven lift).
        burst_trigger_s:    Seconds of sustained demand misses before burst activates.
        burst_drain_s:      Seconds of no misses before burst target drains back.
        warmup_grace_s:     Seconds after start() during which is_healthy() is True
                            even if no idle slots exist yet.
    """

    def __init__(
        self,
        *,
        runtime: SlotRuntime,
        warm_size: int = 4,
        concurrent_ceiling: int = 16,
        spawn_rate_limit: float = 4.0,
        clock: Callable[[], float] = time.monotonic,
        poll_interval: float = 0.1,
        burst_size: int = 4,
        burst_trigger_s: float = 3.0,
        burst_drain_s: float = 60.0,
        warmup_grace_s: float = 30.0,
        warming_timeout_s: float = 120.0,
    ) -> None:
        self._runtime = runtime
        self._warm_size = warm_size
        self._concurrent_ceiling = concurrent_ceiling
        self._poll_interval = poll_interval
        self._clock = clock
        self._burst_size = burst_size
        self._burst_trigger_s = burst_trigger_s
        self._burst_drain_s = burst_drain_s
        self._warmup_grace_s = warmup_grace_s
        self._warming_timeout_s = warming_timeout_s

        # slot_id → Slot; all mutations under _lock
        self._slots: dict[str, Slot] = {}
        self._lock = threading.Lock()

        # Signalled whenever a slot becomes IDLE — unblocks claim() pollers
        self._idle_event = threading.Event()

        # Token bucket for spawn rate limiting
        self._bucket = _TokenBucket(rate=spawn_rate_limit, clock=clock)

        # Background thread
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Burst demand tracking — all access under _lock
        self._first_miss_at: float | None = None   # time of first unserviced claim miss
        self._last_miss_at: float | None = None    # time of most recent unserviced claim miss
        self._burst_active: bool = False            # True when effective target is lifted

        # Health tracking — all access under _lock
        self._last_idle_at: float | None = None    # clock() when a slot last became IDLE
        self._started_at: float | None = None      # clock() when start() was called

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin the background spawn/promote loop."""
        if self._thread is not None:
            return
        self._stop_event.clear()
        with self._lock:
            self._started_at = self._clock()
        self._thread = threading.Thread(
            target=self._background_loop,
            daemon=True,
            name="warmpool-tick",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background loop and reap ALL slots (no orphans)."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)
            self._thread = None

        # Reap every slot regardless of state
        with self._lock:
            to_reap = list(self._slots.values())
            self._slots.clear()

        for slot in to_reap:
            try:
                self._reap_and_count(slot)
            except Exception:
                logger.exception("pool.reap_error_on_stop slot_id=%s", slot.slot_id)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def claim(self, *, timeout_s: float) -> Slot | None:
        """Return an IDLE+alive slot (now ASSIGNED), or None on timeout.

        Liveness race guard: re-checks is_alive() while holding the lock.
        If the candidate died, it is dropped+replaced and the scan continues.
        Thread-safe: the IDLE→ASSIGNED flip is done inside the lock so two
        concurrent callers cannot pick the same slot.
        """
        deadline = self._clock() + timeout_s

        while True:
            slot = self._try_claim_one()
            if slot is not None:
                return slot

            # No IDLE slot — record demand miss, wait for idle_event or timeout
            self._record_demand_miss()
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None

            self._idle_event.wait(timeout=min(remaining, 0.05))
            self._idle_event.clear()

            if self._clock() >= deadline:
                return None

    def release(self, slot: Slot) -> None:
        """ASSIGNED → DRAINING → reap.  Spawns a replacement on the next tick.

        There is NO path back to IDLE. This is the structural guarantee of
        warm ≠ reuse.
        """
        with self._lock:
            slot.state = SlotState.DRAINING

        # Reap in-place (synchronous) so the caller is certain cleanup happened.
        # The replacement will be spawned by the next tick() call.
        try:
            self._reap_and_count(slot)
        except Exception:
            logger.exception("pool.reap_error slot_id=%s", slot.slot_id)
        finally:
            with self._lock:
                self._slots.pop(slot.slot_id, None)

    def tick(self) -> None:
        """One maintenance step: promote WARMING→IDLE, health-check, burst, spawn to deficit.

        Must be called periodically (the background thread does this).
        Safe to call manually in tests.
        """
        # Warm-snapshot runtimes build their base lazily + asynchronously; resolve readiness
        # ONCE per tick (this also kicks the async build) and gate both burst + spawn on it, so
        # the (up to ready_timeout_s) build never blocks this loop and demand misses during the
        # build window don't spuriously trip burst the instant the tier becomes ready.
        ready = self._runtime_ready()
        self._promote_warming()
        self._health_check()
        self._update_burst(ready)
        self._spawn_to_deficit(ready)
        self._sample_metrics()

    def _runtime_ready(self) -> bool:
        """Kick the warm runtime's async prepare (if any) and report whether it can spawn this
        tick. Runtimes without prepare() (cold/docker, test fakes) are always ready."""
        prepare = getattr(self._runtime, "prepare", None)
        if callable(prepare):
            return bool(prepare())
        return True

    def _reap_and_count(self, slot: "Slot") -> None:
        """Reap a slot via the runtime and count the disposal (metrics)."""
        try:
            self._runtime.reap(slot)
        finally:
            record_slot_reaped()

    def _sample_metrics(self) -> None:
        """Publish a snapshot of slot-state counts + target to Prometheus gauges."""
        with self._lock:
            counts = {st: 0 for st in SlotState}
            for s in self._slots.values():
                counts[s.state] = counts.get(s.state, 0) + 1
            target = self._effective_target_unlocked()
            burst = self._burst_active
        record_pool_state(
            spawning=counts[SlotState.SPAWNING],
            warming=counts[SlotState.WARMING],
            idle=counts[SlotState.IDLE],
            assigned=counts[SlotState.ASSIGNED],
            draining=counts[SlotState.DRAINING],
            warm_target=target,
            burst_active=burst,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def runtime(self) -> SlotRuntime:
        """The slot runtime backing this pool (exposes the warm-path seam the
        dispatcher uses to vary input/output handling per runtime)."""
        return self._runtime

    @property
    def idle_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._slots.values() if s.state == SlotState.IDLE)

    @property
    def slot_count(self) -> int:
        with self._lock:
            return len(self._slots)

    @property
    def effective_target(self) -> int:
        """Current warm target: warm_size + burst_size (clamped to ceiling) when burst active."""
        with self._lock:
            return self._effective_target_unlocked()

    @property
    def burst_active(self) -> bool:
        """True when demand misses have triggered a burst lift of the target."""
        with self._lock:
            return self._burst_active

    def is_healthy(self) -> bool:
        """True if ≥1 IDLE slot exists, or a slot was idle recently, or within warmup grace."""
        with self._lock:
            # 1. Any idle slot right now
            if any(s.state == SlotState.IDLE for s in self._slots.values()):
                return True
            now = self._clock()
            # 2. A slot was idle within the last 30 s
            if self._last_idle_at is not None and (now - self._last_idle_at) < 30.0:
                return True
            # 3. Within the warmup grace period since start()
            if self._started_at is not None and (now - self._started_at) < self._warmup_grace_s:
                return True
        return False

    def _record_demand_miss(self) -> None:
        """Record that claim() found no idle slot (a demand miss).

        Called by claim() when it exhausts the timeout with no idle slot, OR
        when _try_claim_one returns None.  May also be called directly in tests
        to drive burst-trigger logic.
        Thread-safe (acquires _lock).
        """
        now = self._clock()
        with self._lock:
            if self._first_miss_at is None:
                self._first_miss_at = now
            self._last_miss_at = now

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_claim_one(self) -> Slot | None:
        """Scan for an IDLE slot, flip to ASSIGNED inside the lock.

        If the chosen slot is dead: demote to DRAINING, reap+remove outside
        the lock (a new slot will be spawned by next tick), and retry.
        Returns the ASSIGNED slot, or None if no live IDLE slot exists.
        """
        while True:
            # Find a candidate inside the lock
            with self._lock:
                candidate: Slot | None = None
                for s in self._slots.values():
                    if s.state == SlotState.IDLE:
                        candidate = s
                        break
                if candidate is None:
                    return None
                # Flip to ASSIGNED immediately to block concurrent claimers
                candidate.state = SlotState.ASSIGNED

            # Check liveness OUTSIDE the lock (may be slow)
            alive = False
            try:
                alive = self._runtime.is_alive(candidate)
            except Exception:
                logger.exception("pool.is_alive_error slot_id=%s", candidate.slot_id)

            if alive:
                return candidate

            # Slot was dead — demote it and spawn a replacement
            logger.warning("pool.claim_found_dead_slot slot_id=%s", candidate.slot_id)
            with self._lock:
                candidate.state = SlotState.DRAINING

            # Reap + remove (best-effort; don't crash claim on failure)
            try:
                self._reap_and_count(candidate)
            except Exception:
                logger.exception("pool.reap_dead_slot_error slot_id=%s", candidate.slot_id)
            finally:
                with self._lock:
                    self._slots.pop(candidate.slot_id, None)

            # Loop: try to find another IDLE slot

    def _promote_warming(self) -> None:
        """Promote WARMING slots to IDLE when is_ready() returns True."""
        with self._lock:
            warming = [s for s in self._slots.values() if s.state == SlotState.WARMING]

        newly_idle: list[str] = []
        for slot in warming:
            try:
                ready = self._runtime.is_ready(slot)
            except Exception:
                logger.exception("pool.is_ready_error slot_id=%s", slot.slot_id)
                ready = False
            if ready:
                with self._lock:
                    # Only promote if still WARMING (concurrent stop could clear it)
                    if slot.slot_id in self._slots and slot.state == SlotState.WARMING:
                        slot.state = SlotState.IDLE
                        newly_idle.append(slot.slot_id)

        if newly_idle:
            with self._lock:
                self._last_idle_at = self._clock()
            self._idle_event.set()

    def _spawn_to_deficit(self, ready: bool = True) -> None:
        """Spawn new slots to fill the deficit, respecting ceiling + rate limit.

        ``ready`` is the warm runtime's per-tick readiness (resolved once in tick()). When False
        the warm snapshot is still building, so we spawn nothing this tick — _promote_warming and
        _health_check already ran, and dispatch falls back to cold until the snapshot is ready.
        """
        if not ready:
            return
        with self._lock:
            # Deficit = effective_target minus everything not DRAINING
            active = sum(
                1 for s in self._slots.values() if s.state != SlotState.DRAINING
            )
            target = self._effective_target_unlocked()
            deficit = max(0, target - active)
            # Never exceed concurrent_ceiling
            headroom = self._concurrent_ceiling - len(self._slots)
            to_spawn = max(0, min(deficit, headroom))

        for _ in range(to_spawn):
            # Rate-limit: consume one token per spawn
            if not self._bucket.consume():
                break

            try:
                slot = self._runtime.spawn()
                slot.state = SlotState.WARMING
                slot.spawned_at = self._clock()
                record_slot_spawned()
            except Exception:
                logger.exception("pool.spawn_failed")
                continue

            with self._lock:
                self._slots[slot.slot_id] = slot

    def _effective_target_unlocked(self) -> int:
        """Compute current target (must be called under _lock or read-only context).

        Returns warm_size + burst_size when burst is active, clamped to ceiling.
        """
        if self._burst_active:
            return min(self._warm_size + self._burst_size, self._concurrent_ceiling)
        return self._warm_size

    def _update_burst(self, ready: bool = True) -> None:
        """Check demand history and activate/deactivate burst.

        Called from tick().  Thread-safe (acquires _lock).  When ``ready`` is False the warm
        tier can't spawn yet (snapshot still building), so misses now aren't burst-actionable:
        drop the miss window so a long build doesn't activate burst the instant it goes ready
        (which would over-provision to the ceiling at startup).
        """
        now = self._clock()
        with self._lock:
            if not ready:
                self._first_miss_at = None
                self._last_miss_at = None
                return
            if not self._burst_active:
                # Activate if sustained demand for >= burst_trigger_s
                if (
                    self._first_miss_at is not None
                    and self._last_miss_at is not None
                    and (now - self._first_miss_at) >= self._burst_trigger_s
                ):
                    self._burst_active = True
                    logger.info("pool.burst_activated warm_size=%d burst_size=%d", self._warm_size, self._burst_size)
            else:
                # Deactivate if no misses for >= burst_drain_s
                if (
                    self._last_miss_at is None
                    or (now - self._last_miss_at) >= self._burst_drain_s
                ):
                    self._burst_active = False
                    self._first_miss_at = None
                    self._last_miss_at = None
                    logger.info("pool.burst_drained")

    def _health_check(self) -> None:
        """Evict dead IDLE slots AND stuck WARMING slots so the spawn loop replaces them.

        For each IDLE slot, calls runtime.is_alive(); on False → DRAINING → reap → remove.
        Additionally, a WARMING slot that never reached IDLE within ``warming_timeout_s`` (a
        dead/never-ready restore) is evicted too — otherwise it counts toward capacity in
        _spawn_to_deficit and permanently blocks its replacement. All slot-dict mutations happen
        under _lock; the (possibly slow) is_alive() call is made outside the lock.
        """
        now = self._clock()
        with self._lock:
            idle_slots = [s for s in self._slots.values() if s.state == SlotState.IDLE]
            stuck_warming = [
                s for s in self._slots.values()
                if s.state == SlotState.WARMING
                and self._warming_timeout_s > 0
                and now - s.spawned_at > self._warming_timeout_s
            ]

        dead: list[Slot] = list(stuck_warming)
        for slot in stuck_warming:
            logger.warning(
                "pool.warming_timeout_evict slot_id=%s age=%.1fs", slot.slot_id, now - slot.spawned_at
            )
        for slot in idle_slots:
            try:
                alive = self._runtime.is_alive(slot)
            except Exception:
                logger.exception("pool.health_is_alive_error slot_id=%s", slot.slot_id)
                alive = False
            if not alive:
                dead.append(slot)

        if not dead:
            return

        # Demote dead slots under the lock, then reap+remove outside
        with self._lock:
            for slot in dead:
                cur = self._slots.get(slot.slot_id)
                if cur is not None and cur.state in (SlotState.IDLE, SlotState.WARMING):
                    cur.state = SlotState.DRAINING

        for slot in dead:
            logger.warning("pool.health_evicted_dead_slot slot_id=%s", slot.slot_id)
            try:
                self._reap_and_count(slot)
            except Exception:
                logger.exception("pool.health_reap_error slot_id=%s", slot.slot_id)
            finally:
                with self._lock:
                    self._slots.pop(slot.slot_id, None)

    def _background_loop(self) -> None:
        """Run tick() repeatedly until stop() is called."""
        while not self._stop_event.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("pool.tick_error")
            self._stop_event.wait(timeout=self._poll_interval)
