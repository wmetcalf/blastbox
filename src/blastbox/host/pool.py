"""Warm-pool manager for blastbox — engine-agnostic pre-spawned worker slots.

State machine
-------------
    spawn() → WARMING → IDLE → ASSIGNED → DRAINING → (gone)
                   |                                     ^
                   +→ (reap on spawn failure) ───────────+

Invariants enforced:
- One job per slot by default (warm ≠ reuse): release() reaps; a reaped slot_id never
  reappears as IDLE. This is the right posture for cheap-reset tiers (container/FC/gVisor) —
  a fresh disposable sandbox per job, zero cross-job contamination.
- OPT-IN reuse (expensive-reset tiers, e.g. a full-VM snapshot-revert is ~seconds, too slow
  per job): a runtime that implements ``recycle(slot)`` enables an ASSIGNED→IDLE reuse path.
  The slot serves up to ``jobs_per_recycle`` jobs, then ``recycle()`` resets it in place and it
  returns to IDLE; after ``max_jobs_per_slot`` total jobs it is reaped+respawned for a fresh one.
  Runtimes WITHOUT ``recycle`` are never reused — behaviour is byte-identical to before.
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
    jobs: int = 0            # cumulative jobs served (reuse mode: drives recycle/reprovision)


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

    # Optional (hasattr-guarded by WarmPool — NOT part of the structural Protocol, so existing
    # runtimes that omit it still satisfy isinstance(.., SlotRuntime)):
    #
    #   def recycle(self, slot: Slot) -> None:
    #       """Reset a reused slot IN PLACE (e.g. VM snapshot-revert) and leave it serving.
    #       Implementing this opts the runtime into WarmPool's reuse path."""


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
        jobs_per_recycle:   REUSE knob (only if the runtime implements recycle()). Reset the slot in
                            place every N jobs. THIS IS AN ENGINE-THREAT DECISION, not a generic
                            tuning knob: the value should come from the engine's risk profile. Default
                            1 = reset every job. A parse-only engine (e.g. signature validation, which
                            never executes the sample) may safely raise it for throughput; an engine
                            that RENDERS or EXECUTES untrusted input (LibreOffice, a headless browser,
                            any detonation engine) MUST keep it at 1 — and on a cheap-reset tier the
                            point is moot (no recycle() → disposable per job regardless).
        max_jobs_per_slot:  Reap+respawn a fully fresh slot after this many jobs (0 = unlimited reuse
                            with periodic resets). Bounds drift in the reused overlay/snapshot.
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
        jobs_per_recycle: int = 1,
        max_jobs_per_slot: int = 0,
    ) -> None:
        self._runtime = runtime
        # Some runtimes (static pool) reuse a long-lived box on reap and care whether the just-finished
        # job was DIRTY (timeout/trust-fail) so they can quarantine it instead of re-offering it while a
        # stale request may still be running. Pass `dirty` to reap() only if it accepts the kwarg
        # (backward-compatible: disposable runtimes reap the whole worker regardless).
        try:
            import inspect
            self._reap_takes_dirty = "dirty" in inspect.signature(runtime.reap).parameters
        except (TypeError, ValueError):
            self._reap_takes_dirty = False
        # Reuse mode (only active when the runtime implements recycle()): serve N jobs, reset every
        # ``jobs_per_recycle`` via runtime.recycle(), reap+respawn after ``max_jobs_per_slot`` (0 =
        # unlimited reuse with periodic resets). Cheap-reset runtimes have no recycle() → disposable.
        self._recycle = getattr(runtime, "recycle", None)
        self._jobs_per_recycle = max(1, jobs_per_recycle)
        self._max_jobs_per_slot = max_jobs_per_slot
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
        self._reaping: set[str] = set()   # slot_ids currently being disposed (dedupe concurrent reaps)
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

    def _default_stop_budget(self) -> float:
        """Shutdown budget covering an in-flight spawn (up to the runtime's per-call CLI timeout) PLUS its
        post-spawn terminate (another CLI timeout), + margin -- else a slow AWS spawn racing stop() eats the
        budget and the process exits mid-terminate, leaking the just-created worker. Floors at 150s; a
        runtime with no cli_timeout_s (file/libvirt) uses the floor."""
        cli = (getattr(getattr(self._runtime, "cfg", None), "cli_timeout_s", None)
               or getattr(self._runtime, "cli_timeout_s", None) or 0.0)
        return max(150.0, 2.0 * float(cli) + 30.0)

    def stop(self, stop_timeout_s: float | None = None) -> None:
        """Stop the background loop and reap ALL slots (no orphans).

        Waits (BOUNDED) for the daemon to finish an in-flight tick so its OWN post-spawn reap disposes a
        slot spawned during shutdown: a slow AWS ``run-instances``/``run-microvm`` racing stop() isn't yet
        in ``_slots``, so stop()'s reap loop can't see it -- and if the process exits right after stop()
        returns (the CLI does), the daemon is killed before its terminate call runs, leaking a live cloud
        worker. The budget must cover the in-flight spawn (up to a runtime's per-call CLI timeout) PLUS its
        post-spawn terminate (another CLI timeout), so the default is derived from the runtime's
        ``cli_timeout_s`` (2× + margin) when unset -- else a slow spawn eats the budget and the process
        exits mid-terminate. A wedged spawn can't hang shutdown forever; past the budget we log and proceed
        (the slot's self-terminate TTL, where enabled, is the last backstop). A clean shutdown with no
        in-flight spawn returns within one poll."""
        if stop_timeout_s is None:
            stop_timeout_s = self._default_stop_budget()
        self._stop_event.set()
        if self._thread is not None:
            # Fast path returns immediately when the daemon has already exited (no spawn in flight).
            self._thread.join(timeout=min(10.0, stop_timeout_s))
            waited = min(10.0, stop_timeout_s)
            while self._thread.is_alive() and waited < stop_timeout_s:
                step = min(1.0, stop_timeout_s - waited)
                self._thread.join(timeout=step)   # let the in-flight tick finish + run its post-spawn reap
                waited += step
            if self._thread.is_alive():
                logger.warning("pool.stop: background thread still running after %.0fs (wedged spawn?) — "
                               "proceeding; an in-flight cloud slot may leak until its TTL", stop_timeout_s)
            self._thread = None

        # Reap every slot regardless of state. Pop each ONLY after a successful reap: if reap RAISES
        # (e.g. a libvirt VM whose `virsh destroy` failed during a rolling restart), KEEP it tracked —
        # else the still-running domain (with its overlay + egress rules) is forgotten outside pool
        # accounting and never retried. Quarantined entries stay in _slots for surfacing/manual cleanup.
        # Flip EVERY slot to DRAINING under the lock BEFORE releasing it to reap: claim()/promotion
        # only hand out IDLE/WARMING slots, so a dispatcher that races claim() in the window between
        # snapshotting to_reap and reaping must not be handed a slot stop() is about to dispose. After
        # this, reap failures simply leave the (already-DRAINING) husk tracked for manual cleanup.
        with self._lock:
            to_reap = list(self._slots.values())
            for slot in to_reap:
                slot.state = SlotState.DRAINING

        for slot in to_reap:
            try:
                disposed = self._reap_and_count(slot)
            except Exception:
                logger.exception("pool.reap_error_on_stop slot_id=%s — quarantining (still DRAINING, "
                                 "never claimable)", slot.slot_id)
            else:
                if disposed:   # skip-because-another-thread-owns-it (False) -> leave it for that thread
                    with self._lock:
                        self._slots.pop(slot.slot_id, None)

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

    def release(self, slot: Slot, *, dirty: bool = False) -> None:
        """Finish a job on ``slot``.

        Default (no ``recycle`` on the runtime): ASSIGNED → DRAINING → reap (warm ≠ reuse); the
        replacement is spawned on the next tick. REUSE mode (runtime implements ``recycle``): the
        slot is reset every ``jobs_per_recycle`` jobs and returned to IDLE, until it reaches
        ``max_jobs_per_slot`` (then reaped+respawned). On any recycle failure or a dead slot it
        falls back to reap, so a broken slot is never returned to IDLE.

        ``dirty=True`` marks the just-finished run as a failure (timeout/trust-fail/engine error/
        crash). A dirty slot is force-reset BEFORE reuse: it recycles unconditionally (not just on
        the ``jobs_per_recycle`` boundary) in REUSE mode, so the next job never inherits a wedged or
        contaminated warm worker. In non-reuse mode the slot is reaped anyway, which is already a
        full reset.
        """
        with self._lock:
            slot.jobs += 1
            jobs = slot.jobs
            tracked = slot.slot_id in self._slots

        if callable(self._recycle) and tracked and not (
            self._max_jobs_per_slot and jobs >= self._max_jobs_per_slot
        ):
            try:
                if dirty or jobs % self._jobs_per_recycle == 0:
                    # Reset in place while the slot stays ASSIGNED. ASSIGNED is counted as active
                    # (state != DRAINING) so _spawn_to_deficit won't spawn a spurious replacement,
                    # AND it is neither claimable (claim() picks IDLE) nor promotable
                    # (_promote_warming only touches WARMING) — so the background tick cannot hand
                    # this slot out mid-reset. Flip to IDLE only once the reset completes.
                    self._recycle(slot)  # e.g. VM snapshot-revert (seconds-long)
                if self._runtime.is_alive(slot):
                    with self._lock:
                        # Only publish to IDLE if the slot is STILL the ASSIGNED one we're recycling.
                        # A concurrent stop() flips slots to DRAINING under the lock before reaping; if
                        # it won the race, republishing to IDLE here would hand a caller a slot stop()
                        # is about to dispose. Leave DRAINING alone and fall through to reap (fail-safe).
                        if slot.slot_id in self._slots and slot.state == SlotState.ASSIGNED:
                            slot.state = SlotState.IDLE
                            self._last_idle_at = self._clock()
                            self._idle_event.set()
                            return
            except Exception:
                logger.exception("pool.recycle_error slot_id=%s", slot.slot_id)
            # recycle failed / slot died / max-jobs reached → fall through to reap (fail-safe)

        with self._lock:
            if slot.slot_id not in self._slots:
                return  # already removed+reaped concurrently (e.g. stop()/eviction) — don't double-reap
            slot.state = SlotState.DRAINING
        # Reap in-place (synchronous) so the caller is certain cleanup happened.
        # The replacement will be spawned by the next tick() call.
        reaped = False
        try:
            # forward dirty so a reusing runtime can quarantine; False = another thread owns the reap
            reaped = self._reap_and_count(slot, dirty=dirty)
        except Exception:
            # reap() raises when it could NOT dispose the worker (e.g. a libvirt VM whose `virsh
            # destroy` failed and may still be running). Do NOT pop the slot: keep it tracked
            # (DRAINING) so it still counts against the ceiling and surfaces, instead of silently
            # orphaning a live worker outside pool accounting while a replacement spawns.
            logger.exception("pool.reap_error slot_id=%s — quarantining slot (worker may persist)",
                             slot.slot_id)
        finally:
            with self._lock:
                if reaped:
                    self._slots.pop(slot.slot_id, None)

    def retire(self, slot: Slot) -> None:
        """Permanently dispose ``slot`` WITHOUT recycling it — for a worker that may STILL be in use
        by an abandoned/hung thread (e.g. a validate that timed out). Unlike ``release(dirty=True)``,
        which on a recycle-capable runtime snapshot-reverts and returns the SAME endpoint to IDLE
        (letting the hung thread keep talking to it and corrupt a later job), retire REAPS (destroys)
        the worker — severing the hung interaction — and removes the slot. On a reap failure the slot
        is quarantined (kept tracked/DRAINING, never reused). The replacement spawns on the next tick.
        """
        with self._lock:
            if slot.slot_id not in self._slots:
                return  # already removed/reaped concurrently — don't double-reap
            slot.state = SlotState.DRAINING  # unclaimable from here, even if the reap is slow
        reaped = False
        try:
            reaped = self._reap_and_count(slot)   # False = another thread owns the reap -> don't pop
        except Exception:
            logger.exception("pool.retire_reap_error slot_id=%s — quarantining (worker may persist)",
                             slot.slot_id)
        with self._lock:
            if reaped:
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
        self._reap_surplus()
        self._sample_metrics()

    def _reap_surplus(self) -> None:
        """Reap IDLE slots above the (possibly just-lowered) effective target, so a
        downsize — e.g. the node autosizer lowering warm_size/ceiling — actually shrinks
        the pool and frees node resources now, instead of only converging lazily as
        one-job-per-slot consumption drains it. Only IDLE slots are taken; ASSIGNED /
        WARMING / DRAINING are left alone."""
        with self._lock:
            target = self._effective_target_unlocked()
            non_draining = sum(1 for s in self._slots.values() if s.state != SlotState.DRAINING)
            surplus = non_draining - target
            if surplus <= 0:
                return
            victims = [s for s in self._slots.values() if s.state == SlotState.IDLE][:surplus]
            # Flip to DRAINING HERE, still under the selection lock, so a concurrent
            # claim() (which only takes IDLE) cannot grab a victim between selection and
            # reap — otherwise we'd destroy a slot mid-job. (stop() takes the same care.)
            for slot in victims:
                slot.state = SlotState.DRAINING
        for slot in victims:
            reaped = False
            try:
                reaped = self._reap_and_count(slot)   # False = another thread owns the reap
            except Exception:
                logger.exception("pool.reap_surplus_error slot_id=%s — quarantining", slot.slot_id)
            if reaped:
                with self._lock:
                    self._slots.pop(slot.slot_id, None)

    def _runtime_ready(self) -> bool:
        """Kick the warm runtime's async prepare (if any) and report whether it can spawn this
        tick. Runtimes without prepare() (cold/docker, test fakes) are always ready."""
        prepare = getattr(self._runtime, "prepare", None)
        if callable(prepare):
            return bool(prepare())
        return True

    def _reap_and_count(self, slot: "Slot", *, dirty: bool = False) -> bool:
        """Reap a slot via the runtime and count the disposal (metrics). ``dirty`` (from a failed
        release) is forwarded to a reap() that accepts it, so a reusing runtime can quarantine.

        Guarded so EXACTLY ONE path disposes a given slot even under concurrency: stop() (whose 10s
        thread-join can expire while the background tick is still mid-reap of a slow AWS terminate,
        up to cli_timeout_s) must not run a SECOND concurrent terminate on the same real cloud resource
        (double control-plane call + double metric/count).

        Returns ``True`` iff THIS call actually disposed the slot. Returns ``False`` when it SKIPPED
        because another thread already owns the reap -- the caller MUST NOT then treat the slot as gone
        (don't pop it from ``_slots``): leave it tracked so the owning thread pops it on success or
        keeps it quarantined if its reap raises. A silent early-return that read as success could let a
        second path untrack a slot whose real terminate later fails, orphaning a live cloud resource."""
        with self._lock:
            if slot.slot_id in self._reaping:
                return False
            self._reaping.add(slot.slot_id)
        try:
            if self._reap_takes_dirty:
                self._runtime.reap(slot, dirty=dirty)  # type: ignore[call-arg]
            else:
                self._runtime.reap(slot)
        finally:
            record_slot_reaped()
            with self._lock:
                self._reaping.discard(slot.slot_id)
        return True

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
    def assigned_count(self) -> int:
        """Slots currently serving a job (the pool's live concurrent load)."""
        with self._lock:
            return sum(1 for s in self._slots.values() if s.state == SlotState.ASSIGNED)

    @property
    def warm_size(self) -> int:
        with self._lock:
            return self._warm_size

    @property
    def concurrent_ceiling(self) -> int:
        with self._lock:
            return self._concurrent_ceiling

    def resize(self, *, warm_size: int | None = None, concurrent_ceiling: int | None = None) -> None:
        """Retune the warm target / hard ceiling on a live pool. Used by an external
        controller (the node autosizer) to re-allocate a node's capacity across engines.
        The background tick() converges to the new target on its own schedule; this only
        moves the setpoints. warm_size is clamped to the (possibly new) ceiling."""
        with self._lock:
            if concurrent_ceiling is not None:
                if concurrent_ceiling < 1:
                    raise ValueError("concurrent_ceiling must be >= 1")
                self._concurrent_ceiling = concurrent_ceiling
            if warm_size is not None:
                if warm_size < 0:
                    raise ValueError("warm_size must be >= 0")
                self._warm_size = warm_size
            # keep warm within the ceiling
            if self._warm_size > self._concurrent_ceiling:
                self._warm_size = self._concurrent_ceiling

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

            # Check liveness OUTSIDE the lock (may be slow). Prefer a FRESH hand-out check
            # (is_alive_for_claim) when the runtime provides one: the per-tick is_alive() may be cached
            # (AWS throttles the control-plane describe), so a slot terminated since the last tick could
            # otherwise be handed out and fail the user's job. Falls back to is_alive() for file/libvirt
            # tiers whose is_alive() is already a fresh check.
            claim_check = getattr(self._runtime, "is_alive_for_claim", None)
            if not callable(claim_check):
                claim_check = self._runtime.is_alive
            alive = False
            try:
                alive = claim_check(candidate)
            except Exception:
                logger.exception("pool.is_alive_error slot_id=%s", candidate.slot_id)

            if alive:
                return candidate

            # Slot was dead — demote it and spawn a replacement
            logger.warning("pool.claim_found_dead_slot slot_id=%s", candidate.slot_id)
            with self._lock:
                candidate.state = SlotState.DRAINING

            # Reap + remove (best-effort; don't crash claim on failure). If reap RAISES (could not
            # dispose the worker — e.g. a libvirt VM whose `virsh destroy` failed and may still run),
            # do NOT pop: keep it quarantined/tracked, like release(), so a live worker isn't orphaned
            # off the books while a replacement spawns.
            reaped = False
            try:
                reaped = self._reap_and_count(candidate)   # False = another thread owns it -> don't pop
            except Exception:
                logger.exception("pool.reap_dead_slot_error slot_id=%s — quarantining", candidate.slot_id)
            finally:
                if reaped:
                    with self._lock:
                        self._slots.pop(candidate.slot_id, None)

            # Loop: try to find another IDLE slot

    def _promote_warming(self) -> None:
        """Promote WARMING slots to IDLE when is_ready() returns True."""
        with self._lock:
            warming = [s for s in self._slots.values() if s.state == SlotState.WARMING]

        newly_idle: list[str] = []
        for slot in warming:
            raised = False
            try:
                ready = self._runtime.is_ready(slot)
            except Exception:
                logger.exception("pool.is_ready_error slot_id=%s", slot.slot_id)
                ready = False
                raised = True
            if ready:
                with self._lock:
                    # Only promote if still WARMING (concurrent stop could clear it)
                    if slot.slot_id in self._slots and slot.state == SlotState.WARMING:
                        slot.state = SlotState.IDLE
                        newly_idle.append(slot.slot_id)
            elif slot.state == SlotState.DRAINING and not raised:
                # is_ready returned False AND the slot is DRAINING. Usually the runtime's finalize
                # failed closed and reaped the VM ITSELF; but DRAINING can ALSO be set EXTERNALLY (a
                # concurrent stop() flips every slot to DRAINING before reaping) while a slow finalize
                # is still in flight. We can't tell which, so DON'T blindly pop on the assumption the
                # VM is gone: reap() it ourselves (idempotent — a second destroy is a benign "not
                # found") and pop ONLY on a successful reap; on a reap failure the VM may still be
                # running, so keep it tracked/quarantined instead of orphaning it off the books.
                # (If is_ready RAISED, we never enter here — same quarantine intent.)
                reaped = False
                try:
                    reaped = self._reap_and_count(slot)   # False = another thread owns it -> don't pop
                except Exception:
                    logger.exception("pool.promote_reap_error slot_id=%s — quarantining", slot.slot_id)
                with self._lock:
                    if reaped:
                        self._slots.pop(slot.slot_id, None)

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

            # Publish under the lock, BUT only if shutdown hasn't begun. A slow spawn (e.g. AWS
            # run-instances / run-microvm blocks up to cli_timeout_s=120s, far past stop()'s 10s
            # thread-join) can complete AFTER stop() snapshotted _slots -- publishing then would leak a
            # live EC2 instance / MicroVM (never reaped until its TTL). Checking _stop_event under the
            # same lock stop() flips slots to DRAINING under closes the race either way.
            with self._lock:
                stopping = self._stop_event.is_set()
                if not stopping:
                    self._slots[slot.slot_id] = slot
            if stopping:
                reaped = False
                try:
                    reaped = self._reap_and_count(slot)   # reap the just-created (untracked) slot ourselves
                except Exception:
                    logger.exception("pool.reap_after_stop_failed slot_id=%s — quarantining (worker may "
                                     "persist)", slot.slot_id)
                if not reaped:
                    # the terminate raised (the EC2/MicroVM may still be running): TRACK the husk as
                    # DRAINING so it's accounted/surfaced for manual cleanup instead of silently leaked
                    # off the books -- matching every other reap-failure path (release/health/stop).
                    slot.state = SlotState.DRAINING
                    with self._lock:
                        self._slots[slot.slot_id] = slot
                break

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

        # Demote dead slots under the lock, capturing ONLY the ones we actually
        # transitioned to DRAINING. A slot a dispatcher claimed (IDLE->ASSIGNED) between
        # the outside-lock is_alive() check and now is NOT demoted by the guard above —
        # and must NOT be reaped out from under the live detonation. Reaping `dead`
        # unconditionally would kill the just-claimed worker (job spuriously FAILED +
        # double-reap on release). Reap only what we demoted, so the claim wins the race.
        to_reap: list[Slot] = []
        with self._lock:
            for slot in dead:
                cur = self._slots.get(slot.slot_id)
                if cur is not None and cur.state in (SlotState.IDLE, SlotState.WARMING):
                    cur.state = SlotState.DRAINING
                    to_reap.append(slot)

        for slot in to_reap:
            logger.warning("pool.health_evicted_dead_slot slot_id=%s", slot.slot_id)
            reaped = False
            try:
                reaped = self._reap_and_count(slot)   # False = another thread owns it -> don't pop
            except Exception:
                # reap raised (worker not disposed — may still run): quarantine, don't pop (like
                # release()), so a live worker isn't orphaned off pool accounting.
                logger.exception("pool.health_reap_error slot_id=%s — quarantining", slot.slot_id)
            finally:
                if reaped:
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
