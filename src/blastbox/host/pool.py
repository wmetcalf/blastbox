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

import functools
import inspect
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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

    def is_alive(self, slot: Slot) -> "bool | None":
        """Tri-state liveness: True = alive, False = CONFIRMED dead, None = UNKNOWN.

        UNKNOWN is not death (issue #77). A runtime that cannot reach its control plane must say
        None rather than guess: the pool keeps such a slot and asks again, and bounds how long that
        may last via ``unknown_grace_s`` -- a runtime masking UNKNOWN as True made that impossible
        and wedged tiers at zero capacity. Local tiers whose check is a process poll always know,
        and may keep returning a plain bool."""
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
        unknown_grace_s: float = 300.0,
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
        # How long a slot may stay CONTINUOUSLY unknown before the health check gives up on it and
        # lets it be replaced. Must comfortably outlast a real control-plane brownout (minutes) --
        # too short and it becomes the destroy-healthy-workers bug #77 fixes; 0 disables escalation
        # entirely (a slot can then be unknown forever, which wedges the tier -- see _health_check).
        self._unknown_grace_s = unknown_grace_s

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
        # slot_ids claim() found DEAD and demoted to DRAINING but deliberately did NOT reap inline
        # (issue #75): a wedged reap must never block the claim path (it would also hold a warm-only
        # gate reservation and lock peers out of HEALTHY slots). Disposed by a DEDICATED reaper
        # thread — never the tick loop: claim() is the *discoverer* of a slot the cloud terminated
        # inside is_alive()'s cache window (it uses the fresh is_alive_for_claim, _health_check the
        # cached is_alive), so putting the disposal on the tick thread would trade a one-thread
        # stall for a whole-tier outage (no promote/spawn/health-check while a reap hangs).
        self._deferred_reap: set[str] = set()
        self._budget_kwarg_cache: dict[str, bool] = {}
        # slot_id -> when it FIRST went UNKNOWN and stayed that way (cleared by any definitive
        # answer). Bounds how long "we can't tell" may keep a slot alive; see _health_check.
        self._unknown_since: dict[str, float] = {}
        # Slots escalated on SUSPICION (a long UNKNOWN) rather than a confirmed verdict. Disposal is
        # asynchronous now, so this must outlive the tick that queued it -- the reaper needs to know
        # not to strand a slot it merely could not dispose of.
        self._suspected_unknown: set[str] = set()
        # Bounded pool of disposal threads. Parallel because a MASS slot death (spot reclamation /
        # AZ event terminating the fleet inside is_alive()'s cache window) is exactly what this path
        # exists for: draining N husks serially would stall a ceiling-bound tier for N x reap
        # latency, whereas pre-#75 each claim thread reaped its own dead slot concurrently. Bounded
        # so a mass death can't spawn an unbounded thread fan-out.
        # [thread, last_progress_at] — MUTABLE so a draining reaper can stamp progress. "Wedged"
        # means NO PROGRESS for _REAPER_WEDGED_AFTER_S, not merely old: a reaper steadily disposing
        # a long queue (40s per terminate x N) is working, and counting it as wedged would spawn
        # redundant reapers against the same queue (issue #77).
        self._reaper_threads: list[list] = []
        # Wall-clock bound for the hand-out liveness probe. Short ON PURPOSE: it sits on
        # job-dispatch latency and holds the caller's warm-gate reservation (#72), so a slot that
        # can't be described in a few seconds is better skipped than waited on (issue #77).
        self._thread: threading.Thread | None = None

        # Burst demand tracking — all access under _lock
        self._first_miss_at: float | None = None   # time of first unserviced claim miss
        self._last_miss_at: float | None = None    # time of most recent unserviced claim miss
        self._burst_active: bool = False            # True when effective target is lifted
        self._autosized: bool = False               # True once an external controller (the node
                                                    # autosizer) has resize()d this pool; gates
                                                    # eager surplus reaping so a pool that never
                                                    # opts in keeps its exact prior burst-drain
                                                    # (lazy) behavior — "off by default = as today"

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

    def stop(self, stop_timeout_s: float | None = None) -> int:
        """Stop the background loop and reap ALL slots. Returns the number of slots that could
        NOT be reaped (orphans left tracked as DRAINING because their VM may still be running) —
        the caller uses this to decide whether to release its node-budget reservation: an orphan
        still consumes RAM/vCPU, so the reservation must NOT be dropped while orphans remain, or
        peers would reallocate still-in-use capacity (node oversubscription). 0 = clean shutdown.

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
        thread_wedged = False        # a spawn still in flight past the timeout — an untracked orphan
        # ONE budget for the whole shutdown, shared by the tick-thread join AND the reaper join
        # below — otherwise a hung spawn followed by a hung reap costs 2 x stop_timeout_s, and the
        # caller's timeout stops meaning what it says.
        stop_deadline = self._clock() + stop_timeout_s
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
                thread_wedged = True
            self._thread = None

        # Join the DEFERRED REAPER within the same budget (issue #75 review): it is a daemon, so if
        # the process exits while it is mid-terminate the worker is leaked. stop()'s own reap loop
        # below CANNOT cover that slot — _reap_and_count's ownership guard makes it skip whatever the
        # reaper already owns — so waiting here is the only thing that disposes it. Past the budget we
        # log and proceed, exactly like the wedged-spawn case above.
        with self._lock:
            _entries = list(self._reaper_threads)   # snapshot under the lock: the tick thread
        for entry in _entries:                      # rebinds/appends to this list concurrently
            reaper = entry[0]                    # [thread, last_progress_at, retired]
            if not reaper.is_alive():
                continue
            reaper.join(timeout=max(0.0, stop_deadline - self._clock()))
            if reaper.is_alive():
                # NOTE: do NOT set thread_wedged here. That flag adds +1 to the orphan count for the
                # wedged-SPAWN case, whose slot is NOT yet in _slots and so is invisible to the
                # len(_slots) tally below. A wedged REAPER's slot is the opposite: it is still
                # tracked (the reaper only pops after a successful reap, and stop()'s own loop skips
                # it because _reaping ownership makes _reap_and_count return False), so it is already
                # counted. Adding +1 would report a phantom orphan and make the caller hold a
                # node-budget reservation for capacity that does not exist.
                logger.warning("pool.stop: deferred reaper still running after %.0fs (wedged reap?) — "
                               "proceeding; that worker may leak until its TTL", stop_timeout_s)

        # Reap every slot regardless of state. Pop each ONLY after a successful reap: if reap RAISES
        # (e.g. a libvirt VM whose `virsh destroy` failed during a rolling restart), KEEP it tracked —
        # else the still-running domain (with its overlay + egress rules) is forgotten outside pool
        # accounting and never retried. Quarantined entries stay in _slots for surfacing/manual cleanup.
        # Flip EVERY slot to DRAINING under the lock BEFORE releasing it to reap: claim()/promotion
        # only hand out IDLE/WARMING slots, so a dispatcher that races claim() in the window between
        # snapshotting to_reap and reaping must not be handed a slot stop() is about to dispose. After
        # this, reap failures simply leave the (already-DRAINING) husk tracked for manual cleanup.
        with self._lock:
            # Drop the deferred queue: stop() disposes every tracked slot itself below, and a slot
            # whose reap RAISES stays tracked as a QUARANTINED husk. Leaving its id queued would let
            # a restarted pool's first tick re-terminate a resource whose disposal already failed —
            # exactly what _drain_deferred_reaps' contract forbids.
            self._deferred_reap.clear()
            to_reap = list(self._slots.values())
            for slot in to_reap:
                slot.state = SlotState.DRAINING

        for slot in to_reap:
            try:
                # require_tracked: after a reaper-join TIMEOUT this list is a snapshot — a reaper
                # may have disposed+popped a slot since. Verifying membership in the same critical
                # section that takes ownership stops a SECOND terminate on that worker. A False
                # return leaves nothing to pop and the slot is already out of _slots, so it is
                # correctly NOT counted as an orphan below.
                disposed = self._reap_and_count(slot, require_tracked=True)
            except Exception:
                logger.exception("pool.reap_error_on_stop slot_id=%s — quarantining (still DRAINING, "
                                 "never claimable)", slot.slot_id)
            else:
                if disposed:   # skip-because-another-thread-owns-it (False) -> leave it for that thread
                    with self._lock:
                        self._slots.pop(slot.slot_id, None)

        # Whatever remains in _slots failed to reap (or is owned by another thread mid-dispose) —
        # a still-live VM the caller must keep reserving for. A wedged background thread means an
        # in-flight spawn that isn't in _slots yet but may still complete into a live worker, so
        # count it as one more orphan too — the caller must hold the reservation for it.
        with self._lock:
            return len(self._slots) + (1 if thread_wedged else 0)

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
        # Arm the scan grace ONCE for the whole claim (issue #77 review): re-arming it per rescan
        # gave a scan starting near the deadline a fresh floor, so claim() overran timeout_s while
        # holding the caller's warm-gate reservation.
        scan_deadline = max(deadline, self._clock() + self._SCAN_GRACE_S)

        # slot_id -> when it last answered UNKNOWN. A short COOLDOWN, not a blacklist: rebuilding
        # this per scan re-probed every slot on every 50ms rescan (~5x the aws subprocesses per
        # claim, per thread, during the brownout the budget exists to ride out), but suppressing for
        # the WHOLE window was the opposite error -- during a throttle that answers in milliseconds
        # every slot was suppressed within the first second of a 60s claim and never re-probed, so
        # claim() span on demand misses and tripped burst-spawning mid-brownout (issue #77
        # marla-loop). Re-ask, but no faster than the cooldown.
        unprobeable: dict[str, float] = {}

        while True:
            slot = self._try_claim_one(deadline, scan_deadline, unprobeable)
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
                # `is not False`: an UNKNOWN post-job liveness answer must not destroy the slot
                # either. Republish it -- the claim-time fresh probe still gates hand-out, and the
                # unknown-escalation clock bounds how long it can stay that way.
                if self._runtime.is_alive(slot) is not False:
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
            reaped = self._reap_and_count(slot, dirty=dirty, require_tracked=True, pop_on_success=True)
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

    def unclaim(self, slot: Slot) -> None:
        """Hand an ASSIGNED slot back UNUSED, without disposing it (issue #77).

        ``release()`` reaps on every non-recycle runtime, so a caller that claimed a slot and then
        could not tell whether it was usable — a resume whose describes were merely throttled — had
        no way to give it back except by destroying it. That is how a control-plane brownout
        terminated healthy PARKED warm slots, the most expensive kind. This returns it to IDLE so
        the next claim (or the next tick's health check) can decide with better information."""
        with self._lock:
            cur = self._slots.get(slot.slot_id)
            if cur is None or cur.state != SlotState.ASSIGNED:
                return                      # already disposed/reclaimed by another path
            cur.state = SlotState.IDLE
            self._last_idle_at = self._clock()
        self._idle_event.set()

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
            reaped = self._reap_and_count(slot, require_tracked=True, pop_on_success=True)   # False = another thread owns it, or it is already gone
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
        # Kick the deferred reaper EARLY so its (asynchronous) disposal overlaps the rest of the
        # tick. NOTE: it does NOT free `concurrent_ceiling` headroom for this tick's
        # _spawn_to_deficit — the husk stays tracked until the reaper thread actually disposes it,
        # so on a pool sitting exactly at its ceiling the replacement spawns on a LATER tick. That
        # is deliberate: a husk whose disposal has not been confirmed may still be a live worker
        # holding node RAM, and this file's policy is to keep counting it (see _spawn_to_deficit's
        # headroom + the quarantine comments) rather than risk over-committing the node.
        self._reap_deferred()
        self._update_burst(ready)
        self._spawn_to_deficit(ready)
        self._reap_surplus()
        self._sample_metrics()

    _MAX_REAPERS = 4          # concurrent disposal threads (bounds a mass-death fan-out)
    # A reaper still running after this long is treated as WEDGED and stops counting against
    # _MAX_REAPERS, so four stuck disposals can't permanently stop the queue draining (issue #77).
    # The thread is abandoned, not killed — Python cannot interrupt a blocking call — but its slot
    # in the pool is freed so healthy husks keep getting disposed.
    _REAPER_WEDGED_AFTER_S = 60.0
    # HARD ceiling on live reaper threads, wedged ones INCLUDED. Without it the watchdog above
    # removes the only bound: a wedged reaper stops counting toward _MAX_REAPERS but never exits and
    # is never removed, so every tick could start 4 more — measured 64 live threads against a cap of
    # 4 on a permanently-hung terminate. Past this we stop starting reapers; the queue waits rather
    # than melting the host, and stop() still disposes everything it can.
    _MAX_REAPER_THREADS = 32

    def _reap_deferred(self) -> None:
        """Kick the DEDICATED reaper thread for slots claim() found dead and deferred (issue #75).

        Never disposes inline. claim() must not reap (a wedged reap would block the claim path and
        hold a warm-only gate reservation, #72) — and neither must the tick loop: for the cloud
        tiers, claim() is the *discoverer* of a slot terminated inside is_alive()'s cache window
        (claim uses the fresh ``is_alive_for_claim``, ``_health_check`` the cached ``is_alive``), so
        disposing here would turn a single stalled claim thread into a whole-tier outage — no
        promotion, no spawn-to-deficit, no health eviction, no metrics — for as long as the reap
        hangs. So the (possibly wedged) disposal runs on its own thread.

        At most ONE reaper is in flight: if a previous batch is still wedged, the ids simply stay
        queued and are drained when it finishes. stop() reaps every tracked slot regardless, so a
        wedged reaper can never leak a live worker past shutdown."""
        with self._lock:
            now = self._clock()
            self._reaper_threads = [e for e in self._reaper_threads if e[0].is_alive()]
            # Count only reapers that are still making progress. One wedged in a hung terminate is
            # abandoned (Python can't interrupt it) but must not hold a slot in the pool forever,
            # or four stuck disposals stop the queue draining for the life of the pool (issue #77).
            live = 0
            for entry in self._reaper_threads:
                if now - entry[1] < self._REAPER_WEDGED_AFTER_S:
                    live += 1
                else:
                    # RETIRE it. Dropping a wedged reaper from the progress count lets replacements
                    # spawn, but nothing stopped the original: if its terminate finally returns it
                    # resumes draining alongside them, so the "4 concurrent" bound silently became
                    # _MAX_REAPER_THREADS (issue #77 round 3). It cannot be interrupted, but it can
                    # be told to stop after its current disposal.
                    entry[2] = True
            # Two bounds: _MAX_REAPERS caps CONCURRENT PROGRESS (wedged ones don't count, so a stuck
            # disposal can't halt the queue), and _MAX_REAPER_THREADS caps TOTAL live threads
            # (wedged ones DO count, so a permanently-hung runtime can't spawn threads forever).
            headroom = min(self._MAX_REAPERS - live,
                           self._MAX_REAPER_THREADS - len(self._reaper_threads))
            want = min(len(self._deferred_reap), headroom)
            if want <= 0:
                return                      # queue empty, or every reaper slot is busy/wedged
            for _ in range(want):
                entry_box: list = []
                # functools.partial, NOT a closure: a lambda captures the VARIABLE, so with
                # want > 1 every thread would resolve entry_box to the LAST iteration's list —
                # all reapers stamping one entry while the others looked wedged and over-spawned.
                t = threading.Thread(target=functools.partial(self._drain_deferred_reaps, entry_box),
                                     name="blastbox-pool-reaper", daemon=True)
                entry = [t, now, False]   # [thread, last_progress_at, retired]
                entry_box.append(entry)          # let the thread stamp its own progress
                self._reaper_threads.append(entry)
                # START INSIDE the lock: a created-but-not-yet-started thread reports
                # is_alive()==False, so releasing first would let a concurrent tick see fewer live
                # reapers and over-spawn past _MAX_REAPERS. start() does not take _lock — the new
                # thread just blocks on its first acquisition until we release here.
                t.start()

    def _drain_deferred_reaps(self, entry_box: "list | None" = None) -> None:
        """Dispose every queued husk, one at a time, off the tick + claim paths.

        Scoped to ids claim() deferred, so DRAINING slots owned by release()/stop()/_reap_surplus —
        or quarantined after a reap that RAISED — are untouched. A reap that raises keeps the slot
        tracked (quarantined) and drops it from the queue, matching every other reap path: never
        re-terminate a resource whose disposal already failed."""
        while True:
            with self._lock:
                if entry_box and entry_box[0][2]:
                    return          # retired while wedged: a replacement owns the queue now
                if not self._deferred_reap:
                    return
                slot_id = next(iter(self._deferred_reap))
                self._deferred_reap.discard(slot_id)
                slot = self._slots.get(slot_id)
                if slot is None:
                    continue                # already disposed+popped by stop()/another path
            try:
                # require_tracked closes the stop()-race (never re-terminate a popped slot) and
                # pop_on_success untracks it in the same critical section that releases ownership,
                # so there is nothing for this caller to do with the result.
                self._reap_and_count(slot, require_tracked=True, pop_on_success=True)
                with self._lock:
                    self._suspected_unknown.discard(slot.slot_id)
            except Exception:
                logger.exception("pool.reap_deferred_error slot_id=%s — quarantining", slot.slot_id)
                with self._lock:
                    if slot.slot_id in self._suspected_unknown:
                        # Only SUSPECTED, and we could not dispose of it either -- so we know
                        # nothing. Quarantining it as DRAINING is retried by nothing and keeps
                        # counting against the ceiling, which is worse than the wedge escalation
                        # exists to fix (that one healed when the brownout ended). Put it back.
                        cur = self._slots.get(slot.slot_id)
                        if cur is not None and cur.state == SlotState.DRAINING:
                            cur.state = SlotState.IDLE
                            logger.warning("pool.deferred_escalation_undone slot_id=%s — could not "
                                           "dispose a suspected slot; returning it to IDLE",
                                           slot.slot_id)
                    self._suspected_unknown.discard(slot.slot_id)
            # Stamp PROGRESS: this reaper just finished a disposal, so it is working, not wedged.
            if entry_box:
                with self._lock:
                    entry_box[0][1] = self._clock()

    def _reap_surplus(self) -> None:
        """Reap IDLE slots above the (possibly just-lowered) effective target, so a
        downsize — e.g. the node autosizer lowering warm_size/ceiling — actually shrinks
        the pool and frees node resources now, instead of only converging lazily as
        one-job-per-slot consumption drains it. Only IDLE slots are taken; ASSIGNED /
        WARMING / DRAINING are left alone.

        No-op until the pool has been resize()d by an external controller: a pool that
        never opts into the autosizer keeps its exact prior behavior, where post-burst
        surplus drains lazily (a lingering warm cushion for the next spike) rather than
        being reaped the instant burst deactivates. This preserves the feature's promise
        that a node behaves exactly as today unless an operator turns the autosizer on."""
        if not self._autosized:
            return
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
                reaped = self._reap_and_count(slot, require_tracked=True, pop_on_success=True)
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

    def _reap_and_count(self, slot: "Slot", *, dirty: bool = False,
                        require_tracked: bool = False, pop_on_success: bool = False) -> bool:
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
            # require_tracked: verify the slot is STILL tracked in the same critical section that
            # takes ownership. The deferred reaper resolves its work list before reaping, so without
            # this a stop() that disposed+popped the slot in between would be followed by a SECOND
            # terminate on the same (possibly recycled) resource + a double reap metric (issue #75).
            if require_tracked and slot.slot_id not in self._slots:
                return False
            self._reaping.add(slot.slot_id)
        disposed = False
        try:
            if self._reap_takes_dirty:
                self._runtime.reap(slot, dirty=dirty)  # type: ignore[call-arg]
            else:
                self._runtime.reap(slot)
            disposed = True                 # ONLY a reap that RETURNED disposed the worker
        finally:
            if disposed:
                record_slot_reaped()   # count DISPOSALS, not attempts: a raising reap quarantines
            with self._lock:
                # pop_on_success: untrack the slot in the SAME critical section that releases
                # ownership. Otherwise there is a window where the slot is still tracked but no
                # longer owned, and a concurrent stop() would terminate it a SECOND time (duplicate
                # control-plane call + double reap accounting). Callers that must keep a husk
                # tracked on failure (the quarantine policy) leave this False and pop themselves.
                # `disposed` gate is essential: this is a FINALLY, so it also runs when reap()
                # RAISED. Popping then would untrack a worker whose disposal FAILED and may still be
                # running — exactly the orphan the quarantine policy exists to prevent.
                if pop_on_success and disposed:
                    self._slots.pop(slot.slot_id, None)
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

    def resize(self, *, warm_size: int | None = None, concurrent_ceiling: int | None = None,
               mark_autosized: bool = True) -> None:
        """Retune the warm target / hard ceiling on a live pool. Used by an external
        controller (the node autosizer) to re-allocate a node's capacity across engines.
        The background tick() converges to the new target on its own schedule; this only
        moves the setpoints. warm_size is clamped to the (possibly new) ceiling.

        mark_autosized (default True) records that an external controller now owns this
        pool, enabling eager surplus reaping. Pass False for a PROVISIONAL move that must
        NOT change the pool's legacy behavior — e.g. the CLI's pre-start shrink and its
        restore-on-skip: if the sizer never actually takes over, the pool must drain
        lazily exactly as an un-managed pool would, so a failed opt-in is a true no-op."""
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
            # This pool is now under external (autosizer) control → eager surplus reaping
            # is enabled so a downsize frees node RAM promptly instead of draining lazily.
            # Skipped for provisional moves (mark_autosized=False) so an opt-in that never
            # starts leaves the pool in exactly its pre-autosizer state.
            if mark_autosized:
                self._autosized = True

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

    # Grace floor for the claim rescan (issue #75): even at claim(timeout_s=0) the scan gets this
    # long to step past dead slots and find a healthy one behind them. Small enough that a stalled
    # remote probe can't hold the caller (or its warm-gate reservation) for long.
    _SCAN_GRACE_S = 1.0
    # How long a slot that answered UNKNOWN is passed over before this claim asks it again. Long
    # enough that a fast-failing control plane can't be re-probed per 50ms rescan; short enough
    # that a slot recovering mid-window is still reachable inside the claim.
    _UNPROBEABLE_COOLDOWN_S = 2.0

    def _accepts_budget(self, fn: "Callable[..., Any]") -> bool:
        """Whether a runtime's is_alive_for_claim takes the budget_s kwarg (cached per callable)."""
        key = getattr(fn, "__qualname__", repr(fn))
        cached = self._budget_kwarg_cache.get(key)
        if cached is None:
            try:
                cached = "budget_s" in inspect.signature(fn).parameters
            except (TypeError, ValueError):   # builtins / C callables have no introspectable sig
                cached = False
            self._budget_kwarg_cache[key] = cached
        return cached

    def _probe_alive(self, slot: "Slot", budget_s: float | None = None) -> "bool | None":
        """Hand-out liveness probe (issue #77).

        Called INLINE — deliberately no watchdog thread. The bound belongs in the runtime, not
        here: a thread can't cancel a blocking call, only abandon it, and abandoning one per probe
        under a control-plane brownout produced unbounded threads (and, on the cloud tiers, one
        live ``aws`` CLI subprocess each) during exactly the incident the bound exists to ride out.
        A wrapper also can't see through ``cascade``, whose ``is_alive_for_claim`` delegates to the
        owning tier, so it threaded LOCAL claims too.

        So the cloud runtimes bound their own claim-time describe (``claim_probe_timeout_s`` on the
        AWS config) and on timeout report **None = UNKNOWN — never False**: a slow control plane is
        not evidence of death, and the caller must skip such a slot rather than destroy it. The
        local tiers were never the problem — their ``is_alive`` is a process poll. A probe that
        RAISES is treated as not-alive, as before.
        """
        fresh_check = getattr(self._runtime, "is_alive_for_claim", None)
        try:
            if callable(fresh_check):
                # Tell the runtime how long the CALLER actually has left, so its own probe bound is
                # a CEILING rather than an entitlement (issue #77 round 2): claim(timeout_s=0.5)
                # against a 5s claim_probe_timeout_s otherwise blocked ~5s while holding the
                # dispatcher's warm-gate reservation. Only when it accepts the kwarg, so an external
                # runtime predating it keeps working.
                if budget_s is not None and self._accepts_budget(fresh_check):
                    alive = fresh_check(slot, budget_s=budget_s)
                else:
                    alive = fresh_check(slot)
            else:
                # No fresh hook: fall back to the background contract, which takes no budget.
                alive = self._runtime.is_alive(slot)
        except Exception:
            # UNKNOWN, not dead (issue #77). A runtime's exception enumeration is never complete —
            # an http.client.HTTPException from the static tier, a TypeError from a slot-shape
            # mismatch — and none of those are evidence the worker is gone. Skip the slot instead
            # of terminating it; a genuinely dead one still fails at detonate and is reaped there.
            logger.exception("pool.is_alive_error slot_id=%s — treating as unknown", slot.slot_id)
            return None
        # None = the runtime bounded its own probe and the control plane didn't answer. UNKNOWN,
        # NOT dead — a brownout must not get healthy workers destroyed (issue #77).
        return None if alive is None else bool(alive)

    def _try_claim_one(self, deadline: float | None = None,
                       scan_deadline: float | None = None,
                       unprobeable: "dict[str, float] | None" = None) -> Slot | None:
        """Scan for an IDLE slot, flip to ASSIGNED inside the lock.

        If the chosen slot is dead: demote to DRAINING and DEFER its disposal to the background
        tick (``_reap_deferred``), then retry the scan. Returns the ASSIGNED slot, or None if no
        live IDLE slot exists.

        Issue #75 — the claim path never reaps: a wedged ``runtime.reap`` (hung ``runsc delete`` /
        ``virsh destroy``) used to run INLINE here, so ``claim(timeout_s=)`` — which only bounded
        the wait-for-idle between scans — could block far past its timeout. With the warm-only gate
        (issue #72) that call also holds a slot reservation, locking peers out of HEALTHY slots.
        Deferring keeps claim bounded; the slot is already DRAINING so it is unclaimable meanwhile,
        and ``_spawn_to_deficit`` (which ignores DRAINING) still spawns its replacement.
        """
        if scan_deadline is None and deadline is not None:
            # Fallback for direct callers/tests. claim() passes an ALREADY-ARMED deadline so the
            # grace floor is applied ONCE per claim, not re-armed on every rescan (which let a scan
            # starting just before the deadline get a fresh 1s and overrun the caller's timeout).
            scan_deadline = max(deadline, self._clock() + self._SCAN_GRACE_S)
        # Slots whose runtime couldn't answer within its budget, mapped to when they said so.
        # Owned by claim() across rescans when it passes one in; a direct caller gets a fresh map.
        if unprobeable is None:
            unprobeable = {}
        while True:
            # Shutdown in progress: hand out NOTHING. stop() reaps every slot after its joins, so a
            # slot claimed during that window would be destroyed mid-job; and a dead slot deferred
            # here would repopulate the queue stop() just cleared, making a restarted pool
            # re-terminate a husk whose disposal already failed. The caller requeues instead.
            if self._stop_event.is_set():
                return None
            # Find a candidate inside the lock
            with self._lock:
                candidate: Slot | None = None
                for s in self._slots.values():
                    if s.state == SlotState.IDLE and (
                            self._clock() - unprobeable.get(s.slot_id, -1e18)
                            >= self._UNPROBEABLE_COOLDOWN_S):
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
            # Bound the probe by the SCAN deadline, not the caller's raw deadline: claim() grants a
            # scan grace precisely so a non-blocking claim(timeout_s=0) can still take an
            # immediately-available slot. Passing the (already expired) raw deadline handed the
            # runtime a 0s budget, which it correctly reported as an exhausted probe -> UNKNOWN ->
            # every AWS slot skipped, so claim(timeout_s=0) could never succeed (issue #77 round 4,
            # a regression from the round-2 budget plumbing).
            probe_budget = (None if scan_deadline is None
                            else max(0.0, scan_deadline - self._clock()))
            alive = self._probe_alive(candidate, probe_budget)

            if alive is None:
                # UNKNOWN (the runtime's own probe budget expired). Leave the slot IDLE and skip it
                # for THIS scan — never defer it for disposal: a slow control plane is not evidence
                # of death, and destroying healthy workers during a brownout is far worse than a
                # missed claim. It stays claimable on the next scan.
                with self._lock:
                    if candidate.state == SlotState.ASSIGNED:
                        candidate.state = SlotState.IDLE
                unprobeable[candidate.slot_id] = self._clock()
                if scan_deadline is not None and self._clock() >= scan_deadline:
                    return None
                continue

            if alive:
                return candidate

            # Slot was dead — demote it (unclaimable from here) and hand the disposal to the
            # background tick. NO inline reap: see the docstring (issue #75). DRAINING is excluded
            # from _spawn_to_deficit's count, so the replacement still spawns on the next tick even
            # while this husk is awaiting its (possibly slow) reap.
            logger.warning("pool.claim_found_dead_slot slot_id=%s (reap deferred to tick)",
                           candidate.slot_id)
            with self._lock:
                candidate.state = SlotState.DRAINING
                if self._stop_event.is_set():
                    # stop() already drained the queue; re-adding here (the probe above takes
                    # seconds, so stop() can land mid-probe) resurrects a husk stop() quarantined
                    # after a failed reap, and the next drain terminates it a SECOND time -- the
                    # contract _drain_deferred_reaps documents as forbidden (issue #77 marla-loop).
                    logger.debug("pool.defer_reap_skipped_after_stop slot_id=%s", candidate.slot_id)
                else:
                    self._deferred_reap.add(candidate.slot_id)

            # Loop: try to find another IDLE slot. Every iteration returns, or moves one slot out
            # of IDLE (→DRAINING), so the rescan is bounded by the IDLE-slot count — but NOT in
            # wall-clock: the per-candidate hand-out probe (is_alive_for_claim) is itself a remote
            # call, up to cli_timeout_s (120s) on the cloud tiers. N dead slots would then hold the
            # caller — and its warm-gate reservation (#72) — for N×120s regardless of timeout_s.
            # So bound the RESCAN by the caller's deadline, with a small grace floor: the grace
            # guarantees at least one rescan when probes are fast, so a HEALTHY slot sitting behind
            # a dead one is still found even at claim(timeout_s=0), while a brownout where every
            # probe stalls yields promptly instead of running away.
            if scan_deadline is not None and self._clock() >= scan_deadline:
                logger.warning("pool.claim_scan_deadline_exceeded — yielding with dead slots pending")
                return None

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
                    reaped = self._reap_and_count(slot, require_tracked=True, pop_on_success=True)
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

            # Re-check the ceiling before each (expensive) spawn: `to_spawn` was computed
            # once up front, but a concurrent resize() — the node autosizer lowering THIS
            # pool's ceiling — can shrink the budget mid-batch. Without this recheck a
            # downsize racing a spawn burst over-commits past the new ceiling for a tick
            # (a transient RAM overshoot that matters on a tight node). Stop early instead;
            # _reap_surplus converges any already-published surplus next. (Stop/shutdown is
            # deliberately NOT checked here — the publish block below reaps a spawn that
            # completes during stop, so an in-flight cloud worker is never leaked.)
            with self._lock:
                if len(self._slots) >= self._concurrent_ceiling:
                    break

            try:
                slot = self._runtime.spawn()
                slot.state = SlotState.WARMING
                slot.spawned_at = self._clock()
                record_slot_spawned()
            except Exception:
                logger.exception("pool.spawn_failed")
                continue

            # Publish under the lock, BUT only if shutdown hasn't begun AND we're still under
            # the ceiling. Two races to close, both possible because runtime.spawn() ran
            # OUTSIDE the lock and can be slow (AWS run-instances / run-microvm up to
            # cli_timeout_s=120s):
            #   * stop() may have snapshotted _slots meanwhile — publishing then leaks a live
            #     EC2 instance / MicroVM (never reaped until its TTL);
            #   * a concurrent resize() (the autosizer) may have LOWERED the ceiling meanwhile
            #     — the pre-spawn check passed against the OLD ceiling, so without re-checking
            #     here this in-flight slot would land one past the new cap (RAM overshoot on a
            #     tight node) until a later tick reaps it.
            # Either way: don't publish, reap the just-created slot instead.
            with self._lock:
                drop = self._stop_event.is_set() or len(self._slots) >= self._concurrent_ceiling
                if not drop:
                    self._slots[slot.slot_id] = slot
            if drop:
                reaped = False
                try:
                    reaped = self._reap_and_count(slot)   # reap the just-created (untracked) slot ourselves
                except Exception:
                    logger.exception("pool.reap_unpublished_failed slot_id=%s — quarantining (worker may "
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
            # Drop bookkeeping for slots that have left the pool. One entry per reaped slot is a
            # slow leak on a tier that churns a slot per job (measured: 50 entries, 0 slots).
            if self._unknown_since:
                for gone in [k for k in self._unknown_since if k not in self._slots]:
                    self._unknown_since.pop(gone, None)
            stuck_warming = [
                s for s in self._slots.values()
                if s.state == SlotState.WARMING
                and self._warming_timeout_s > 0
                and now - s.spawned_at > self._warming_timeout_s
            ]

        dead: list[Slot] = list(stuck_warming)
        # Slots we escalated because we could not TELL, as opposed to ones AWS/libvirt confirmed
        # dead. If disposing of a merely-suspected slot also fails, we have learned nothing and must
        # not strand it (see the reap loop below).
        suspected: set[str] = set()
        for slot in stuck_warming:
            logger.warning(
                "pool.warming_timeout_evict slot_id=%s age=%.1fs", slot.slot_id, now - slot.spawned_at
            )
        for slot in idle_slots:
            # TRI-STATE, same contract as the claim probe (_probe_alive): True = alive,
            # False = CONFIRMED dead, None = UNKNOWN. Only a CONFIRMED negative may evict — the
            # background path was the structural hole that let every runtime-level fix be undone
            # one tick later (issue #77): it read a falsy None as dead, so a runtime had no way to
            # say "the control plane didn't answer" here, and an unenumerated exception was a death
            # sentence. An UNKNOWN slot is simply left alone; the next tick asks again, and the
            # claim-time fresh probe is still the gate before any job is handed to it.
            try:
                alive = self._runtime.is_alive(slot)
            except Exception:
                # An exception is NOT evidence of death — it is evidence we could not tell. Killing
                # a healthy worker over an unanticipated error is the worse failure.
                logger.exception("pool.health_is_alive_error slot_id=%s — treating as unknown",
                                 slot.slot_id)
                alive = None
            if alive is None:
                # UNKNOWN is a reason to WAIT — never a reason to wait FOREVER. Left unbounded this
                # is strictly worse than the bug #77 fixes: on main a probe error set alive=False,
                # so a persistent fault self-healed (reap -> respawn). Keeping the slot instead
                # means it is never claimable (the claim probe skips UNKNOWN), never reaped, and
                # never replaced (_spawn_to_deficit counts it as active) — the tier silently wedges
                # at ZERO capacity while is_healthy() still reports True. So: ride out a brownout,
                # but escalate a fault that outlasts any plausible one.
                since = self._unknown_since.setdefault(slot.slot_id, now)
                stuck_for = now - since
                if self._unknown_grace_s > 0 and stuck_for > self._unknown_grace_s:
                    logger.warning("pool.health_unknown_escalated slot_id=%s unknown_for=%.0fs "
                                   "(> %.0fs) — treating as dead so the slot is replaced",
                                   slot.slot_id, stuck_for, self._unknown_grace_s)
                    self._unknown_since.pop(slot.slot_id, None)
                    suspected.add(slot.slot_id)   # escalated on suspicion, not on a verdict
                    dead.append(slot)
                else:
                    logger.debug("pool.health_unknown slot_id=%s unknown_for=%.0fs — keeping slot",
                                 slot.slot_id, stuck_for)
                continue
            # A DEFINITIVE answer (either way) means the control plane is talking to us again.
            self._unknown_since.pop(slot.slot_id, None)
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
                    if slot.slot_id in suspected:
                        self._suspected_unknown.add(slot.slot_id)
                        # SUSPECTED (escalated after a long UNKNOWN), not confirmed. Its disposal
                        # runs through the SAME control plane that is not answering, so each
                        # terminate can burn its full CLI timeout -- and doing a tier's worth of
                        # them serially here would stall promotion, spawning and reaping on the sole
                        # tick thread for minutes. That is the wedge #77 exists to fix, and #76
                        # already built the bounded reapers for exactly this. Hand it to them.
                        self._deferred_reap.add(slot.slot_id)
                    else:
                        to_reap.append(slot)

        for slot in to_reap:
            logger.warning("pool.health_evicted_dead_slot slot_id=%s", slot.slot_id)
            reaped = False
            try:
                reaped = self._reap_and_count(slot, require_tracked=True, pop_on_success=True)
            except Exception:
                # reap raised (worker not disposed — may still run): quarantine, don't pop (like
                # release()), so a live worker isn't orphaned off pool accounting.
                logger.exception("pool.health_reap_error slot_id=%s — quarantining", slot.slot_id)
                if slot.slot_id in suspected:
                    # ...unless this slot was only SUSPECTED (escalated after a long UNKNOWN). The
                    # disposal runs through the SAME control plane that made it unknown, so during
                    # a brownout it fails too — and a quarantined DRAINING slot is retried by
                    # nothing, keeps counting against concurrent_ceiling, and never recovers. That
                    # is strictly worse than the wedge escalation exists to fix: the wedge healed
                    # when the brownout ended, this does not. We could not confirm it dead and could
                    # not dispose of it, so we know nothing: put it back and let the cycle resume
                    # (issue #77 marla-loop 2).
                    with self._lock:
                        cur = self._slots.get(slot.slot_id)
                        if cur is not None and cur.state == SlotState.DRAINING:
                            cur.state = SlotState.IDLE
                    logger.warning("pool.health_escalation_undone slot_id=%s — could not dispose a "
                                   "merely-suspected slot; returning it to IDLE", slot.slot_id)
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
