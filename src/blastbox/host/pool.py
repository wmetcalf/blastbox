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

from blastbox.errors import is_host_resource_failure
from blastbox.observability.metrics import (
    record_pool_state,
    record_slot_reaped,
    record_slot_spawned,
    record_spawn_capacity_miss,
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


def _accepts_kwarg(fn: Any, name: str) -> bool:
    """Whether ``fn`` declares ``name`` (or absorbs it via **kwargs). Introspection only."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if name in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def release_kwargs(fn: Any, *, dirty: bool, fault: str | None = None,
                   fault_stage: str | None = None) -> dict[str, Any]:
    """The subset of ``dirty``/``fault`` that this ``release`` callable actually accepts.

    Introspection ONLY, deliberately separate from the call. Every seam here used to degrade with
    a ladder of ``except TypeError`` wrapped around ``release(...)`` itself, which cannot tell
    "this pool predates the kwarg" from "release() raised TypeError for a real reason". One
    genuine bug inside release was therefore retried as a compatibility fallback: the same slot
    was released two or three times, and the longest ladder's final rung dropped ``dirty``
    entirely -- returning a worker that had just failed a detonation to IDLE with no forced
    recycle, to be handed the next untrusted sample. Same reasoning as ``_takes_budget`` in
    cascade.py.

    A ``**kwargs`` release counts as accepting everything: the ladders passed those through, and
    reporting otherwise would silently drop the attribution -- no exception, no log, and the
    conflated worker/job signal quietly returns.
    """
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {}
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return {"dirty": dirty, "fault": fault, "fault_stage": fault_stage}
    out: dict[str, Any] = {}
    if "dirty" in params:
        out["dirty"] = dirty
    # Never invent an attribution a caller cannot carry: an unattributed dirty release still
    # force-resets the slot, it just does not advance it toward eviction.
    if "fault" in params:
        out["fault"] = fault
    # Same rule one step further: a pool that predates the stage attribution simply does not get
    # it, and behaves exactly as before. Passing it blind would raise TypeError, which the ladder
    # this function replaced used to swallow as a "compatibility fallback" -- releasing the same
    # slot twice.
    if "fault_stage" in params:
        out["fault_stage"] = fault_stage
    return out


class RuntimeAtCapacity(RuntimeError):
    """``spawn()`` has no room right now — a NORMAL condition, not a fault.

    Part of the :class:`SlotRuntime` contract. A runtime that can be legitimately full
    (a cascade whose ready tiers are saturated while a snapshot tier still builds; a static
    pool with every worker busy) raises this instead of a generic error, so the pool can tell
    "no capacity this instant" apart from "spawning is broken". The distinction matters: the
    latter feeds the consecutive-failure streak that eventually invalidates the snapshot base,
    so counting a routine capacity miss there slowly destroys a perfectly good base under load
    — exactly when the pool is busiest and can least afford a rebuild.
    """


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
        spawn_concurrency: int = 1,
        clock: Callable[[], float] = time.monotonic,
        poll_interval: float = 0.1,
        burst_size: int = 4,
        burst_trigger_s: float = 3.0,
        burst_drain_s: float = 60.0,
        warmup_grace_s: float = 30.0,
        warming_timeout_s: float = 120.0,
        unknown_grace_s: float = 300.0,
        capacity_starved_after_s: float = 300.0,
        jobs_per_recycle: int = 1,
        max_jobs_per_slot: int = 0,
        max_consecutive_failures: int = 2,
        max_evictions_per_window: int | None = None,
        eviction_window_s: float = 600.0,
        snapshot_rebuild_after: int | None = None,
        pre_guest_rebuild_after: int = 3,
        base_rebuild_cooldown_s: float = 300.0,
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
        # A wedged warm worker is INVISIBLE to is_alive(): the sandbox process is healthy, only the
        # in-guest agent has stopped answering. release(dirty=True) therefore recycled it (a
        # snapshot-revert, which restores the SAME persisted base) and republished it to IDLE, so it
        # took the next job and failed again -- observed as a pool failing 100% of jobs for days,
        # curable only by restarting the dispatcher (which rebuilds the base). Counting consecutive
        # dirty releases gives the pool a way to notice without a liveness probe it does not have:
        # after N in a row, stop trusting the slot and reap it so a genuinely fresh one replaces it.
        self._max_consecutive_failures = max(0, max_consecutive_failures)
        # (3) Blast radius. Wedge detection is a HEURISTIC over a signal the pool cannot fully
        # verify, and this file's history is of predicates that looked right in review and then
        # took whole tiers. Whatever the predicate decides, never let it evict more than this many
        # slots per window: a wrong signal then costs some churn instead of the warm pool.
        # Default scales with the tier: you may churn through the warm set ONCE inside a window,
        # but not over and over. An absolute constant is wrong at both ends -- 2 starves a large
        # pool's legitimate replacement, and is far too permissive for a warm_size of 1.
        # None => DERIVED, and re-derived whenever resize() moves the warm target. Computing it
        # once from the constructor's warm_size meant a pool started at 16 and downsized to 1 by
        # the autosizer still permitted 16 evictions per window -- the cap is meant to bound damage
        # to roughly one warm set, so it has to track the live set (upstream, PR #82).
        self._eviction_cap_explicit = max_evictions_per_window is not None
        self._max_evictions_per_window = (
            max(2, int(warm_size)) if max_evictions_per_window is None
            else max(0, int(max_evictions_per_window)))
        self._eviction_window_s = max(0.0, eviction_window_s)
        # (timestamp, owner) -- the owner is the slot the token was reserved FOR. Refunding by
        # popping the newest entry gave back whichever thread reserved LAST, so a concurrent
        # reservation was cancelled while the failed attempt stayed charged: the cap could then be
        # exceeded (upstream, PR #82).
        self._evictions: list[tuple[float, str]] = []
        # Reaping cannot help when the persisted warm BASE is what is poisoned -- every replacement
        # restores the same bad state. After this many dirty releases pool-wide with no intervening
        # success, ask the runtime to discard its base so the next spawn rebuilds it.
        #   None -> derive from warm_size, so it scales with the pool
        #   0    -> DISABLED
        #   >0   -> exactly that many
        # The previous form said "0 disables" in the comment while treating <=0 as "use the derived
        # default", so rebuilds were on by default and there was no way to turn them off at all
        # (upstream, PR #82). Same sentinel convention as max_evictions_per_window above.
        # How many DISTINCT slots must fail before their guest ever executes before the base is
        # judged poisoned. Deliberately tiny next to snapshot_rebuild_after (2 x warm_size, so 48
        # at warm_size=24): that threshold is sized for failures that might be the DOCUMENTS, and
        # has to be, since a run of malformed samples must not cost a healthy base. A slot that
        # never reached its guest carries no such ambiguity -- three different slots restored from
        # one base, none of which could execute anything, is the base. Waiting for 48 of those
        # means 48 real jobs burning the full worker timeout apiece before the tier self-heals,
        # which is how a warm tier silently degrades to cold-only for hours.
        # 0 disables the fast path entirely (the default; see PoolConfig). Anything enabled is
        # floored at 2 -- a threshold of 1 would rebuild the base on a single hung document.
        _pg = int(pre_guest_rebuild_after)
        self._pre_guest_rebuild_after = 0 if _pg <= 0 else max(2, _pg)
        self._rebuild_after_explicit = snapshot_rebuild_after is not None
        self._snapshot_rebuild_after = (
            max(4, 2 * max(1, warm_size)) if snapshot_rebuild_after is None
            else max(0, int(snapshot_rebuild_after))
        )
        # PER BASE IDENTITY ("" for a single-base runtime). A cascade has one base per tier, and
        # one shared counter meant a healthy tier-A job reset the episode a poisoned tier B was
        # accumulating -- so alternating A successes and B failures kept B below the threshold
        # forever, and since blame_tier_for_slot no longer repairs on its own, nothing else would
        # ever fix it (upstream, PR #82).
        self._pool_consecutive_failures: dict[str, int] = {}
        # base identity -> the DISTINCT slots that failed before their guest ever executed.
        # Kept apart from the general failure streak because it is far stronger evidence: a slot
        # whose guest never ran did not fail ON a document, it failed to become able to run one.
        # Distinct slots, because one wedged worker is not a wedged base.
        self._pool_pre_guest_failures: dict[str, set[str]] = {}
        self._base_rebuilds = 0
        # Rebuilding the base is a full sandbox BOOT (seconds), unlike a slot respawn which is a
        # cheap snapshot restore. Slot respawn churn is already bounded by the spawn token bucket;
        # rebuilds are not, so a systemic failure unrelated to the base (bad input class, full disk,
        # a sick dependency) would otherwise trigger a boot every snapshot_rebuild_after failures
        # forever. Cool down between rebuilds so a wrong guess costs one boot per window, not a
        # boot storm. 0 disables the cooldown.
        self._base_rebuild_cooldown_s = max(0.0, base_rebuild_cooldown_s)
        self._last_base_rebuild_at: float | None = None
        # Consecutive runtime.spawn() failures. A base broken badly enough that RESTORES fail never
        # produces a slot, so no job is ever dispatched and no dirty release happens -- the
        # job-failure counter stays at zero while the tier sits at zero capacity forever. Spawn
        # failures must feed base invalidation too: "cannot restore the base" is even stronger
        # evidence the base is bad than "jobs restored from it fail".
        self._spawn_consecutive_failures = 0
        # Keyed by slot_id, NOT stored on the slot: runtimes supply their own slot types (e.g.
        # AwsWorkerSlot) that duck-type the Slot protocol without inheriting its dataclass fields,
        # so attributes added to Slot are not universally present.
        self._slot_failures: dict[str, int] = {}
        self._slot_last_success: dict[str, float] = {}
        # slot_id -> the key its failure history is filed under. Usually the slot_id itself; a
        # runtime that REUSES a physical worker across slots reports a stable identity instead.
        self._health_key_by_slot: dict[str, str] = {}
        # slot_id -> the value of _base_rebuilds when this slot was spawned, i.e. WHICH warm base
        # produced it. A slot restored from generation A can still be mid-job long after A was
        # invalidated and B built in its place.
        # slot_id -> (base identity, generation) it was restored from. The IDENTITY matters:
        # a cascade has one base PER TIER, and a job-driven repair may touch only tier A while
        # tier B's artifact stays current. A single pool-wide counter retired B's live slots too,
        # discarding their failures as coming from a base that was in fact never replaced.
        self._slot_base: dict[str, tuple[str, int]] = {}
        # COMMITTED base generation, advanced only when an invalidation actually succeeded.
        # Deliberately not _base_rebuilds, which is bumped BEFORE drop() so an in-flight spawn
        # batch can be fenced: a drop() that RAISED still advanced it, so slots whose tier was
        # never repaired were stamped with a "retired" generation and their later failures were
        # discarded -- leaving the un-repaired tier unable to reach the rebuild threshold at all.
        # base identity -> committed generation. "" is the whole-runtime base (anything that is
        # not a cascade). Advanced only when an invalidation actually succeeded, and only for the
        # bases it actually repaired.
        self._base_generation: dict[str, int] = {}
        # ONE invalidation at a time, whatever base triggered it. Two identities reaching the
        # threshold concurrently -- worker failures from two cascade tiers -- each consumed their
        # own episode, saw the same pre-cooldown state and both called invalidate_base(). Both
        # calls can target the same guilty tiers, so the second discards the first's replacement
        # or bumps its build epoch and the replacement build is REJECTED, while the pool advances
        # that generation twice. Not _lock: drop() is slow and must never run under it (PR #82).
        self._invalidation_lock = threading.Lock()
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
        # How long the pool may be CONTINUOUSLY unable to spawn for capacity reasons before that
        # stops being backpressure and becomes an outage. Capacity misses are deliberately not
        # faults -- they must not invalidate the base -- but "not a fault" must not mean
        # "unbounded and silent": with no floor here, a permanently full or misconfigured cascade
        # (ceiling above the fleet, a snapshot tier whose build never finishes) sits at zero warm
        # capacity forever emitting nothing above DEBUG, and the only symptom is a sagging warm-hit
        # rate. Same reasoning as _unknown_grace_s above; 0 disables the escalation.
        self._capacity_starved_after_s = capacity_starved_after_s
        self._capacity_miss_since: float | None = None
        self._capacity_starved_logged = False
        # Monotonic count of CLEAN releases. Read as an episode token so a rebuild decision can
        # be abandoned if a slot succeeded while it was being made.
        self._clean_release_count = 0
        # Slots promoted to IDLE that have not yet completed a job. Their promotion cleared the
        # restore-failure streak provisionally; a confirmed death before first use revokes that.
        self._promoted_unproven: set[str] = set()
        # Set by _health_check when it invalidates the base, read and cleared by tick(): the next
        # spawn would run a synchronous rebuild on this thread.
        self._rebuilt_this_tick = False
        # Derive from the FEASIBLE target, not the requested one. PoolConfig permits
        # warm_size > concurrent_ceiling, and the pool can then only ever run at the ceiling --
        # so warm_size=16 with ceiling=1 waited 32 consecutive failures before repairing a
        # poisoned base and allowed 16 evictions per window on a ONE-slot pool. resize() already
        # clamps and then re-derives; construction did neither, so the two disagreed until some
        # later resize happened to correct it (upstream, PR #82).
        if self._warm_size > self._concurrent_ceiling:
            self._warm_size = self._concurrent_ceiling
        self._rederive_warm_size_thresholds()

        # slot_id → Slot; all mutations under _lock
        self._slots: dict[str, Slot] = {}
        self._lock = threading.Lock()

        # Signalled whenever a slot becomes IDLE — unblocks claim() pollers
        self._idle_event = threading.Event()

        # Token bucket for spawn rate limiting
        self._bucket = _TokenBucket(rate=spawn_rate_limit, clock=clock)
        # >1 lets several runtime.spawn() calls overlap. Slots reserved but not yet
        # published must still count against concurrent_ceiling, or a batch would
        # overshoot the cap by however many spawns are in flight.
        self._spawn_concurrency = max(1, int(spawn_concurrency))
        self._spawns_in_flight = 0

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
                        self._forget_slot_health(slot.slot_id)

        # Whatever remains in _slots failed to reap (or is owned by another thread mid-dispose) —
        # a still-live VM the caller must keep reserving for. A wedged background thread means
        # in-flight spawns that aren't in _slots yet but may still complete into live workers, so
        # count them as orphans too — the caller must hold the reservation for them.
        #
        # Count them from _spawns_in_flight rather than assuming ONE. That assumption was true
        # while spawns were strictly serial; with spawn_concurrency>1 a wedged thread can be
        # holding up to that many uncommitted spawns, and undercounting makes the caller release
        # node budget for RAM/vCPU that live workers still hold (peer oversubscription — the
        # exact harm this return value exists to prevent). max(1, ...) keeps the old floor: a
        # wedged thread means at least one in-flight spawn even if the counter says zero.
        with self._lock:
            in_flight = max(1, self._spawns_in_flight) if thread_wedged else 0
            return len(self._slots) + in_flight

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

            # No IDLE slot. Only count that as DEMAND if we actually had nothing to give: when
            # slots were skipped because their runtime could not answer, the shortage is a
            # brownout, not load, and recording it trips burst-spawning DURING the outage --
            # adding control-plane calls to a control plane already failing (upstream P2).
            if not unprobeable:
                self._record_demand_miss()
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None

            self._idle_event.wait(timeout=min(remaining, 0.05))
            self._idle_event.clear()

            if self._clock() >= deadline:
                return None

    def _refund_eviction_unlocked(self, owner: str) -> None:
        """Give back the token reserved FOR ``owner``. CALLER MUST HOLD ``self._lock``.

        Reservations are taken at the DECISION and the eviction can still be undone afterwards; a
        token that bought nothing must not count against the window. It must be the RIGHT token:
        popping the newest entry refunded whichever thread reserved last, leaving the failed
        attempt charged and a real eviction uncounted, so later releases could exceed the cap
        (upstream, PR #82).
        """
        for i in range(len(self._evictions) - 1, -1, -1):
            if self._evictions[i][1] == owner:
                del self._evictions[i]
                return

    def _reserve_eviction_unlocked(self, now: float, owner: str = "") -> bool:
        """Check-and-reserve one eviction token. CALLER MUST HOLD ``self._lock``.

        Split out because the demotion step -- the only place that truly evicts -- already holds
        the lock, and the locking variant would deadlock there.
        """
        if self._max_evictions_per_window <= 0:
            return False        # 0 = evict NOTHING; see _eviction_allowed
        if self._eviction_window_s <= 0:
            return True         # no window to rate-limit over
        self._evictions = [e for e in self._evictions
                           if now - e[0] < self._eviction_window_s]
        if len(self._evictions) >= self._max_evictions_per_window:
            return False
        self._evictions.append((now, owner))
        return True

    def _eviction_allowed(self, owner: str = "") -> bool:
        """True if the wedge heuristic may still evict a slot inside the current window.

        Wedge detection is a heuristic over a signal the pool cannot verify. This module's history
        is of predicates that read correctly in review and then took whole tiers, so the corrective
        action is bounded independently of how confident the predicate is."""
        if self._max_evictions_per_window <= 0:
            # A ZERO CAP BLOCKS EVICTION. This read "cap disabled" and permitted UNLIMITED
            # evictions -- the exact opposite of what the number says, and reachable precisely
            # when an operator sets BLASTBOX_POOL_MAX_EVICTIONS_PER_WINDOW=0 during an incident
            # to stop the heuristic taking more slots. The mitigation removed the blast-radius
            # guard entirely. Nothing in PoolConfig or docs/CONFIGURATION.md documents zero as an
            # unlimited sentinel, so there is no reading to preserve; a negative is nonsense and
            # fails the same way, toward LESS corrective action (upstream, PR #82).
            return False
        if self._eviction_window_s <= 0:
            # A different knob: with no window there is nothing to rate-limit over, so the cap
            # cannot be applied. Kept separate so it can never re-absorb the zero-cap case above.
            return True
        now = self._clock()
        with self._lock:
            self._evictions = [e for e in self._evictions
                               if now - e[0] < self._eviction_window_s]
            if len(self._evictions) >= self._max_evictions_per_window:
                return False
            # RESERVE inside the same critical section. Checking here and appending in a separate
            # _record_eviction() let two threads both observe "under the cap" before either wrote,
            # so with max_evictions_per_window=1 a concurrent burnout could reap two slots -- a cap
            # that is not a cap is worse than none, because it is trusted (upstream, PR #82).
            self._evictions.append((now, owner))
            return True

    def release(self, slot: Slot, *, dirty: bool = False,
                fault: "str | None" = None,
                fault_stage: "str | None" = None) -> None:
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

        ``fault`` says WHOSE failure it was, and only ``"worker"`` counts toward wedge eviction:

          "worker"  the WORKER is suspect -- a hung validate (dead in-guest agent), a transport
                    error, a busy-lock held by a stale detonation. Evidence about this slot.
          "job"     the ENGINE ran and reported a failure on this INPUT. Says nothing about the
                    worker: on a malware corpus, samples that crash the engine are the workload.
          "unknown" we cannot attribute it. Treated like "job" -- never destroy a warm worker on a
                    failure we could not attribute (the invariant this whole module is built on).

        Omitting ``fault`` on a dirty release therefore force-resets the slot exactly as before but
        does NOT advance it toward eviction. That default is deliberate: a caller that has not been
        taught to attribute must not be able to reap warm capacity by accident.
        """
        fault = (fault or "unknown") if dirty else None
        # Resolved OUTSIDE the lock: the optional worker_identity() hook belongs to the runtime
        # and must not run under the pool lock.
        hkey = self._health_key(slot)
        _bident = self._base_identity(slot)
        # Set under the lock by either recovery branch; the runtime hook runs outside it.
        episode_recovered = False
        with self._lock:
            slot.jobs += 1
            jobs = slot.jobs
            tracked = slot.slot_id in self._slots
            if not tracked:
                # A late release for a slot stop()/eviction already removed. Recording anything
                # here leaks an entry keyed on a dead slot_id AND moves the POOL-wide counter on
                # evidence from a slot that is no longer in the pool -- which can tip a base
                # rebuild (upstream, PR #82).
                #
                # ...including the identity caches _health_key/_base_identity just populated.
                # retire() or an eviction can remove a slot while its timed-out validation is
                # still running, and that validation reaches release() afterwards --
                # _forget_slot_health has already run, so nothing else would ever drop the fresh
                # entries and every such late completion grew both dicts forever.
                self._health_key_by_slot.pop(slot.slot_id, None)
                self._slot_base.pop(slot.slot_id, None)
                slot_failures = 0
                last_success = 0.0
            elif dirty and fault == "job":
                # POSITIVE evidence: the worker RAN and returned a structurally valid
                # engine_error, so it is demonstrably responsive and so is the base it restored
                # from. "Consecutive" has to mean consecutive -- leaving the streaks untouched
                # meant a timeout, then any number of valid engine errors, then another timeout
                # read as two CONSECUTIVE worker failures, evicting a healthy slot or invalidating
                # a good base on two unrelated events an hour apart. The slot is still
                # force-recycled (dirty); only the HEALTH streaks reset (upstream, PR #82).
                # hkey, not slot_id. With a reusing runtime the record is filed under the
                # physical worker while slot_id is minted fresh for every assignment, so popping
                # the slot id left the box's prior failure intact -- and the lookup below,
                # correctly keyed, read it straight back. A failure / valid engine_error /
                # failure sequence was then treated as CONSECUTIVE and could burn out a healthy
                # box or spend eviction budget on it. The clean-release branch already had this
                # right (upstream, PR #82).
                self._slot_failures.pop(hkey, None)
                episode_recovered = True
                self._pool_consecutive_failures.pop(_bident, None)
                # One served job proves the base can execute, which is exactly what the
                # pre-guest evidence claims it cannot -- but only for the base that SERVED it.
                # The failure side is generation-guarded and this side was not: a long-running
                # job from generation A, completing after A was invalidated, wiped evidence that
                # replacement generation B had accumulated under the same identity, delaying the
                # repair of a base which produced none of that success. Same guard, both sides.
                _ok_stamp = self._slot_base.get(slot.slot_id)
                if _ok_stamp is None or _ok_stamp[1] == self._base_generation.get(_ok_stamp[0], 0):
                    self._pool_pre_guest_failures.pop(_bident, None)
                slot_failures = 0
                # ...and it proves the RESTORED BASE is responsive too, so it must clear the
                # restore-side evidence as well. Leaving these meant restore deaths separated by
                # a successfully validated engine run still counted as consecutive (PR #82).
                self._spawn_consecutive_failures = 0
                self._promoted_unproven.discard(slot.slot_id)
                self._clean_release_count += 1
            elif dirty and fault == "worker":
                # ONLY worker-attributed failures are evidence about the slot. Counting job faults
                # here is what let two bad samples in a row destroy a warm worker with a hundred
                # clean jobs behind it -- and on this workload two bad samples in a row is routine,
                # not exceptional.
                self._slot_failures[hkey] = self._slot_failures.get(hkey, 0) + 1
                # The SLOT counter always moves -- this worker really did fail. The POOL-wide
                # counter judges the BASE, and it is the only evidence _maybe_rebuild_base
                # consults, so a slot restored from a generation that has since been RETIRED must
                # not feed it. Generation A is invalidated while A-backed slots are still
                # assigned; those jobs run for minutes, and their later failures kept accumulating
                # here. With the cooldown elapsed (or configured to zero) and no intervening clean
                # release from B, enough long-running A failures invalidated the freshly built B
                # artifact -- which produced none of them -- and the tier rebuilt cold over and
                # over. slot_ids carries cascade-TIER attribution; it says nothing about which
                # snapshot generation restored the slot (upstream, PR #82).
                _stamp = self._slot_base.get(slot.slot_id)
                if _stamp is None or _stamp[1] == self._base_generation.get(_stamp[0], 0):
                    self._pool_consecutive_failures[_bident] = (
                        self._pool_consecutive_failures.get(_bident, 0) + 1)
                    # A worker fault whose guest NEVER EXECUTED is evidence about the base, not
                    # about the sample: the slot did not fail on a document, it failed to become
                    # able to run one. Same generation guard as above -- a slot restored from a
                    # retired base must not convict the one now installed.
                    if fault_stage == "pre_guest":
                        self._pool_pre_guest_failures.setdefault(_bident, set()).add(
                            slot.slot_id)
                else:
                    logger.info(
                        "pool.failure_from_retired_generation slot_id=%s spawned_generation=%d "
                        "current_generation=%d -- not counted against the base now installed",
                        slot.slot_id, _stamp[1], self._base_generation.get(_stamp[0], 0),
                    )
            elif dirty:
                # A job/unknown fault still forces a recycle (the slot may be contaminated) but must
                # not advance it toward eviction, and must not reset its success record either.
                pass
            else:
                self._slot_failures.pop(hkey, None)
                self._slot_last_success[hkey] = self._clock()
                self._pool_consecutive_failures.pop(_bident, None)
                # One served job proves the base can execute, which is exactly what the
                # pre-guest evidence claims it cannot -- but only for the base that SERVED it.
                # The failure side is generation-guarded and this side was not: a long-running
                # job from generation A, completing after A was invalidated, wiped evidence that
                # replacement generation B had accumulated under the same identity, delaying the
                # repair of a base which produced none of that success. Same guard, both sides.
                _ok_stamp = self._slot_base.get(slot.slot_id)
                if _ok_stamp is None or _ok_stamp[1] == self._base_generation.get(_ok_stamp[0], 0):
                    self._pool_pre_guest_failures.pop(_bident, None)
                episode_recovered = True
                # Episode token: a rebuild decision taken before this point is abandoned, because
                # the base demonstrably just produced a valid result.
                self._clean_release_count += 1
                # A served job is the only conclusive proof that the base yields a usable worker,
                # so it — not promotion — is what clears the restore-failure streak.
                self._spawn_consecutive_failures = 0
                self._promoted_unproven.discard(slot.slot_id)
            if tracked:
                slot_failures = self._slot_failures.get(hkey, 0)
                last_success = self._slot_last_success.get(hkey, 0.0)

        # A wedged in-guest agent is invisible to is_alive(), so consecutive dirty releases are the
        # only signal the pool gets. Once a slot hits the limit, do NOT recycle-and-republish it:
        # fall through to the reap path so the slot is destroyed and genuinely respawned.
        burned_out = (
            self._max_consecutive_failures > 0
            and slot_failures >= self._max_consecutive_failures
        )
        if episode_recovered:
            # The pool-wide episode is over, so the per-tier attribution it accumulated is over
            # too. A cascade otherwise consumes _job_guilty only on a successful invalidation, so
            # a tier blamed in an episode that then RECOVERED stayed guilty -- and the next,
            # independent episode on a different tier invalidated both, discarding a healthy
            # snapshot and its fallback capacity for a failure it had nothing to do with
            # (upstream, PR #82).
            self._clear_runtime_job_guilt()

        # POOL-wide, and deliberately NOT gated on this slot burning out. Disposable snapshot
        # runtimes (FC/gVisor) have no recycle(), so every dirty release reaps the restored VM and
        # _forget_slot_health() clears its counter -- no individual slot ever reaches the
        # consecutive-failure limit, so hanging the rebuild off `burned_out` meant a poisoned base
        # could restore into fresh slot after fresh slot forever without ever being invalidated
        # (upstream, PR #82). It is also ordered before the eviction cap: refusing to destroy more
        # slots must not suppress the one action that fixes the base.
        if dirty and fault == "worker":
            # ATTRIBUTE FIRST. A job-triggered repair carried no tier evidence, so a cascade fell
            # back to invalidating EVERY tier -- discarding healthy siblings and removing usable
            # fallback capacity because one tier's workers were failing jobs. The cascade still
            # knows which tier served this slot (it is in _owner until the slot is reaped), and
            # this is the one place that knows the failure was worker-attributed (upstream,
            # PR #82).
            self._blame_tiers([slot.slot_id])
            # The generation check lives on the STREAK (see the counter above), which is the
            # single thing this call consults -- a second guard here would be unreachable, and an
            # unreachable guard is one nobody can prove still works.
            self._maybe_rebuild_base()
        if burned_out and not self._eviction_allowed(slot.slot_id):
            # (3) The heuristic wants this slot gone, but the window's budget is spent. Refuse, and
            # say so loudly: if the wedge is real the slot keeps failing and the next window takes
            # it, while a WRONG signal costs some churn instead of the warm tier. No predicate over
            # a signal the pool cannot verify should be able to empty the pool.
            logger.error(
                "pool.eviction_capped slot_id=%s consecutive_worker_failures=%d limit=%d -- "
                "%d evictions already in the last %.0fs; recycling instead of reaping. If this "
                "repeats the wedge is real; if it repeats across MANY slots at once, suspect a "
                "shared cause (inputs, disk, base image) rather than the workers.",
                slot.slot_id, slot_failures, self._max_consecutive_failures,
                self._max_evictions_per_window, self._eviction_window_s,
            )
            burned_out = False
        if burned_out:
            # TELL THE RUNTIME. On a disposable tier reaping IS the eviction, but a REUSING one
            # (a static pool) just returns the same physical box to its free list, so the
            # threshold was reached, logged and charged against the eviction budget while the
            # wedged endpoint kept receiving and failing jobs forever. Optional seam,
            # hasattr-guarded (upstream, PR #82).
            _burn = getattr(self._runtime, "burn_out", None)
            if callable(_burn):
                try:
                    _burn(slot)
                except Exception as exc:  # noqa: BLE001 -- must never break the release path
                    logger.warning("pool.burn_out_failed slot_id=%s: %s", slot.slot_id, exc)
            logger.warning(
                "pool.slot_burned_out slot_id=%s fault=worker consecutive_failures=%d limit=%d "
                "jobs=%d last_success_age=%s -- reaping instead of recycling",
                slot.slot_id, slot_failures, self._max_consecutive_failures, jobs,
                ("never" if not last_success else "%.1fs" % (self._clock() - last_success)),
            )

        if callable(self._recycle) and tracked and not burned_out and not (
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
                    self._forget_slot_health(slot.slot_id)

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

    def retire(self, slot: Slot, *, fault: "str | None" = None) -> None:
        """Permanently dispose ``slot`` WITHOUT recycling it — for a worker that may STILL be in use
        by an abandoned/hung thread (e.g. a validate that timed out). Unlike ``release(dirty=True)``,
        which on a recycle-capable runtime snapshot-reverts and returns the SAME endpoint to IDLE
        (letting the hung thread keep talking to it and corrupt a later job), retire REAPS (destroys)
        the worker — severing the hung interaction — and removes the slot. On a reap failure the slot
        is quarantined (kept tracked/DRAINING, never reused). The replacement spawns on the next tick.
        """
        if fault == "worker":
            # A hard retire still has to leave EVIDENCE. The compose seam retires a slot whose
            # agent hung, which is the most direct worker fault there is -- but retiring recorded
            # nothing, so if every VM restored from a poisoned snapshot hangs, each is destroyed
            # and replaced from that same snapshot forever and the base-rebuild protection is
            # unreachable. Attribute first, then retire as before (upstream, PR #82).
            hkey = self._health_key(slot)
            bident = self._base_identity(slot)
            with self._lock:
                self._slot_failures[hkey] = self._slot_failures.get(hkey, 0) + 1
                stamp = self._slot_base.get(slot.slot_id)
                if stamp is None or stamp[1] == self._base_generation.get(stamp[0], 0):
                    self._pool_consecutive_failures[bident] = (
                        self._pool_consecutive_failures.get(bident, 0) + 1)
            self._blame_tiers([slot.slot_id])
            self._maybe_rebuild_base()
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
                self._forget_slot_health(slot.slot_id)

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
        self._drain_runtime_repairs()
        self._reap_deferred()
        self._update_burst(ready)
        # CONSUME the flag and commit to the decision in one locked step. Checking it here and
        # spawning afterwards left a window in which a job thread's _maybe_rebuild_base() could
        # invalidate the base: `ready` then still described the discarded artifact, and the
        # snapshot runtime's spawn() ran SnapshotManager.build() synchronously on this thread --
        # the sole maintenance thread -- for a full boot plus readiness timeout. That is exactly
        # the stall this flag exists to prevent, reintroduced by reading it non-atomically
        # (PR #82).
        with self._lock:
            rebuilt = self._rebuilt_this_tick
            self._rebuilt_this_tick = False
            spawn_generation = self._base_rebuilds
        if rebuilt:
            # _health_check or a racing release invalidated the base during THIS tick. `ready` was
            # captured before that, so spawning now would build synchronously. The next tick
            # re-reads readiness and spawns against the fresh base.
            logger.info("pool.tick_spawn_deferred reason=base_invalidated_this_tick")
        else:
            self._spawn_to_deficit(ready, expect_generation=spawn_generation)
        self._reap_surplus()
        self._sample_metrics()

    _MAX_REAPERS = 4          # concurrent disposal threads (bounds a mass-death fan-out)
    # A reaper still running after this long is treated as WEDGED and stops counting against
    # _MAX_REAPERS, so four stuck disposals can't permanently stop the queue draining (issue #77).
    # The thread is abandoned, not killed — Python cannot interrupt a blocking call — but its slot
    # in the pool is freed so healthy husks keep getting disposed.
    # Must exceed ONE legitimate disposal, or a merely-slow reap is declared wedged and replaced --
    # so _MAX_REAPERS stops bounding concurrency during exactly the control-plane slowdown where
    # extra CLI calls and threads amplify the outage (upstream P2). Derived from the runtime's own
    # call timeout where it exposes one, with this as the floor.
    _REAPER_WEDGED_AFTER_S = 60.0
    # HARD ceiling on live reaper threads, wedged ones INCLUDED. Without it the watchdog above
    # removes the only bound: a wedged reaper stops counting toward _MAX_REAPERS but never exits and
    # is never removed, so every tick could start 4 more — measured 64 live threads against a cap of
    # 4 on a permanently-hung terminate. Past this we stop starting reapers; the queue waits rather
    # than melting the host, and stop() still disposes everything it can.
    _MAX_REAPER_THREADS = 32

    def _drain_runtime_repairs(self) -> None:
        """Advance generations for bases a runtime repaired on its OWN (the spawn path).

        A cascade repairs a tier whose spawns keep failing behind a healthy fallback -- which the
        pool never sees, because the fallback makes every spawn succeed. Unreported, the retired
        artifact's slots and the replacement's slots share a generation stamp, so a late failure
        from an old slot is charged to the new base and can invalidate it at once. Optional seam,
        hasattr-guarded (upstream, PR #82).
        """
        take = getattr(self._runtime, "take_repaired_tiers", None)
        if not callable(take):
            return
        try:
            names = take()
        except Exception as exc:  # noqa: BLE001 -- bookkeeping must never break the tick
            logger.warning("pool.take_repaired_tiers_failed: %s", exc)
            return
        if not names:
            return
        with self._lock:
            for name in names:
                self._base_generation[str(name)] = self._base_generation.get(str(name), 0) + 1
        logger.info("pool.runtime_repaired_bases tiers=%s -- their slots are now retired",
                    ",".join(str(n) for n in names))

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
            wedged_after = self._reaper_wedged_after_s()
            live = 0
            for entry in self._reaper_threads:
                if now - entry[1] < wedged_after:
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

    def _reaper_wedged_after_s(self) -> float:
        """How long a reaper may make no progress before it is presumed wedged.

        A disposal is a remote call: the AWS tiers bound theirs at cli_timeout_s (120s by default),
        so a flat 60s threshold declares a perfectly healthy slow reap wedged and spawns a
        replacement beside it. Give one call room to finish, twice over."""
        per_call = self._runtime_call_timeout_s()
        if per_call is None:
            return self._REAPER_WEDGED_AFTER_S
        return max(self._REAPER_WEDGED_AFTER_S, 2.0 * float(per_call))

    def _runtime_call_timeout_s(self) -> "float | None":
        """The longest single remote call the runtime can make, or None if it does not say.

        A CascadingRuntime -- the PRODUCTION shape -- has no cfg of its own, so reading
        ``self._runtime.cfg`` silently fell back to the floor and the derived threshold never
        applied where it was needed. Any wrapped tier could own the slot being reaped, so take the
        maximum across them (upstream P2)."""
        cfg = getattr(self._runtime, "cfg", None)
        direct = getattr(cfg, "cli_timeout_s", None) if cfg is not None else None
        if direct is not None:
            return float(direct)
        vals: list[float] = []
        for tier in getattr(self._runtime, "tiers", None) or ():
            tcfg = getattr(getattr(tier, "runtime", None), "cfg", None)
            v = getattr(tcfg, "cli_timeout_s", None) if tcfg is not None else None
            if v is not None:
                vals.append(float(v))
        return max(vals) if vals else None

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
                            # REFUND: the demotion spent a token to evict this slot and we have
                            # just put it back, so the budget bought nothing. This is the path the
                            # deferred reaper takes, and it is the COMMON one during a brownout --
                            # every disposal goes through the same unresponsive control plane, so
                            # the window's whole allowance can be consumed without evicting
                            # anything (upstream, PR #82).
                            self._refund_eviction_unlocked(slot.slot_id)
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
                    self._forget_slot_health(slot.slot_id)

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
                    self._forget_slot_health(slot.slot_id)
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
            # Wedged-slot visibility: a slot whose in-guest agent has stopped answering looks
            # identical to a healthy IDLE one in every other gauge, which is why a 100%-failing
            # pool went unnoticed for days. Surface the failure state directly.
            # Resolve each live slot to the key its health is FILED under. With a reusing
            # runtime (a static pool, or a static tier inside a cascade) the record is keyed
            # "static:0" / "tier:static:0" while `live` holds per-assignment slot ids, so these
            # membership tests reported slots_failing=0 and worst_consecutive=0 while a box was
            # walking toward burnout -- defeating this log for the one runtime that needed
            # stable identities in the first place (upstream, PR #82).
            live = {self._health_key_by_slot.get(sid, sid) for sid in self._slots}
            failing = sum(1 for k, n in self._slot_failures.items() if k in live and n > 0)
            worst = max((n for k, n in self._slot_failures.items() if k in live), default=0)
            never_ok = sum(
                1 for sid, s in self._slots.items()
                if s.jobs > 0
                and not self._slot_last_success.get(self._health_key_by_slot.get(sid, sid))
            )
            pool_failures = max(self._pool_consecutive_failures.values(), default=0)
            pre_guest = max((len(v) for v in self._pool_pre_guest_failures.values()), default=0)
            rebuilds = self._base_rebuilds
        if failing or pool_failures:
            logger.info(
                "pool.health slots_failing=%d worst_consecutive=%d never_succeeded=%d "
                "pool_consecutive_failures=%d pre_guest_failures=%d base_rebuilds=%d",
                failing, worst, never_ok, pool_failures, pre_guest, rebuilds,
            )
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

    def _note_capacity_miss(self, reason: str) -> None:
        """Record that the pool wanted capacity and could not get any, and escalate a SUSTAINED
        episode exactly once. Shared by the two ways this happens: a tier reporting itself full,
        and a deficit with no headroom to even try."""
        record_spawn_capacity_miss()
        now = self._clock()
        with self._lock:
            if self._capacity_miss_since is None:
                self._capacity_miss_since = now
            starved_for = now - self._capacity_miss_since
            # Latched so a sustained outage logs once, not once per tick.
            escalate = (
                self._capacity_starved_after_s > 0
                and starved_for > self._capacity_starved_after_s
                and not self._capacity_starved_logged
            )
            if escalate:
                self._capacity_starved_logged = True
        if escalate:
            logger.error(
                "pool.spawn_capacity_starved: no capacity for %.0fs (>%.0fs) — this is no longer "
                "backpressure. Check ceiling vs fleet size, a snapshot tier stuck building, or "
                "leaked capacity reservations. reason=%s",
                starved_for, self._capacity_starved_after_s, reason,
            )

    def _retune_runtime_thresholds(self, rebuild_after: int) -> None:
        """Push a re-derived rebuild threshold into a runtime that keeps its own copy.

        Optional seam (hasattr-guarded): only CascadingRuntime has a per-tier threshold today,
        and a runtime without one is unaffected.
        """
        runtime = getattr(self, "_runtime", None)
        if runtime is None or not hasattr(runtime, "tier_rebuild_after"):
            return
        if getattr(runtime, "tier_rebuild_after_explicit", False):
            return          # the caller pinned it; a derived policy must not stomp that
        try:
            runtime.tier_rebuild_after = max(0, int(rebuild_after))
        except Exception as exc:  # noqa: BLE001 -- retuning must never break a resize
            logger.warning("pool.retune_runtime_threshold_failed: %s", exc)

    def _rederive_warm_size_thresholds(self) -> None:
        """Recompute every threshold derived from the LIVE warm target, preserving explicit
        operator values. Called from __init__ and resize() so the two can never disagree."""
        if not self._eviction_cap_explicit:
            # Bounds damage to roughly ONE warm set, so it follows the live target.
            self._max_evictions_per_window = max(2, int(self._warm_size))
        if not self._rebuild_after_explicit:
            self._snapshot_rebuild_after = max(4, 2 * max(1, self._warm_size))
            # ...and tell a cascade, which keeps its OWN per-tier copy. The autosizer moves the
            # target in production, so after a 4->16 resize per-tier repair still fired at 8
            # while the pool-wide policy had moved to 32 (and downsizing gave the reverse
            # delay). One policy, both consumers -- at construction AND at resize (PR #82).
            self._retune_runtime_thresholds(self._snapshot_rebuild_after)

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
            # EVERY value derived from warm_size has to follow resize, not just the one that was
            # reported. The autosizer moves the target in production: a pool created at 16 and
            # shrunk to 1 otherwise waits 32 consecutive failures instead of 4 before repairing a
            # poisoned base, and one grown 1 -> 16 invalidates far too eagerly (upstream, PR #82).
            #
            # Derived AFTER the clamp and from self._warm_size, NOT from the warm_size argument,
            # and OUTSIDE the `warm_size is not None` branch. Both matter: a ceiling-only resize
            # silently lowers the live target (so it must re-derive too), and a warm_size above
            # the ceiling would otherwise derive thresholds for a size the pool never runs at --
            # reintroducing the very "waits 32 failures instead of 4" defect this fixes.
            self._rederive_warm_size_thresholds()
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
            if alive is not None:
                # The control plane ANSWERED about this slot. That resets the unknown clock exactly
                # as a health-tick answer does -- otherwise a slot being claimed and used
                # successfully could still age out and be escalated to dead (upstream P2).
                with self._lock:
                    self._unknown_since.pop(candidate.slot_id, None)
                # ...and it is no longer "unprobeable" for this claim. Leaving it there kept the
                # demand-miss suppression on for the rest of the window, so once the control plane
                # recovered a lone queued job still could not trip burst capacity (upstream P2).
                unprobeable.pop(candidate.slot_id, None)

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
            claim_unproven_death = False
            with self._lock:
                candidate.state = SlotState.DRAINING
                # CONFIRMED dead, and it never served a job: its promotion was the only evidence
                # the base yields a usable worker, and that is now refuted. Demand can reach a
                # newly promoted slot before the health tick does, and this path neither advanced
                # the restore-failure streak nor consumed the marker -- _forget_slot_health then
                # discarded it silently, so a poisoned base whose restores briefly pass is_ready()
                # was never repaired when claims got there first (PR #82).
                if candidate.slot_id in self._promoted_unproven:
                    self._promoted_unproven.discard(candidate.slot_id)
                    self._spawn_consecutive_failures += 1
                    claim_unproven_death = True
                    warm_failures = self._spawn_consecutive_failures
                if self._stop_event.is_set():
                    # stop() already drained the queue; re-adding here (the probe above takes
                    # seconds, so stop() can land mid-probe) resurrects a husk stop() quarantined
                    # after a failed reap, and the next drain terminates it a SECOND time -- the
                    # contract _drain_deferred_reaps documents as forbidden (issue #77 marla-loop).
                    logger.debug("pool.defer_reap_skipped_after_stop slot_id=%s", candidate.slot_id)
                else:
                    self._deferred_reap.add(candidate.slot_id)

            if claim_unproven_death:
                # ATTRIBUTE FIRST, while the cascade still owns this slot's mapping -- the reap is
                # deferred, so the ownership is still there right now. spawn() returned and the
                # slot even reached IDLE, so the cascade's per-tier streak is empty, and a repair
                # with no guilty tier falls back to invalidating EVERY snapshot-capable tier:
                # healthy sibling bases discarded for deaths confined to one. The warming-timeout
                # and background-health paths already blame here; this third one, the claim-time
                # probe, did not (upstream, PR #82).
                self._blame_tiers([candidate.slot_id])
                # Outside the lock: _maybe_rebuild_base takes it itself.
                self._maybe_rebuild_base(warm_failures, reason="spawn")

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
                        # Promotion is EVIDENCE, not proof, so it does NOT clear the
                        # restore-failure streak. A poisoned snapshot can restore a process that
                        # survives long enough to pass is_ready() and then dies while IDLE:
                        # clearing here let it promote, die and be replaced forever, with each new
                        # promotion wiping the evidence the previous death had just produced, so
                        # the streak oscillated and invalidate_base() was never reached. A SERVED
                        # JOB is the proof, and that is where the reset lives (upstream, PR #82).
                        self._promoted_unproven.add(slot.slot_id)
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
                        self._forget_slot_health(slot.slot_id)

        if newly_idle:
            with self._lock:
                self._last_idle_at = self._clock()
            self._idle_event.set()

    def _spawn_batch_concurrent(self, to_spawn: int, expect_generation: int | None) -> None:
        """Issue up to *to_spawn* spawns with at most ``spawn_concurrency`` in flight.

        Why this exists: the maintenance thread issues runtime.spawn() one at a time, so a tier
        whose spawn is LATENCY-bound (an FC snapshot restore: measured gap p50 0.57s) caps the
        whole pool at ~1.7 slots/s. With a disposable slot per job that is the job-throughput
        ceiling too -- observed 1.4/s on a 32-core node sitting at load 8 with 94G free. Spawns
        wait on I/O, not CPU, so overlapping them is nearly free.

        Same gates as the serial path (token bucket, ceiling, base generation).

        ``_spawns_in_flight`` counts spawns reserved but not yet published. It is DEFENSIVE, not
        load-bearing today: the executor context manager blocks until the batch finishes, so two
        batches cannot overlap on the single maintenance thread, and ``to_spawn`` is already
        clamped to the ceiling headroom. It exists so that a future caller which issues batches
        without waiting cannot overshoot the cap. Mutation-checked: removing it does not fail any
        test, precisely because the overlap it guards against is currently unreachable.

        History, because the shape of this function is a direct response to it: a 2026-08-16
        adversarial review REPRODUCED four defects in the first version -- two worker-leak classes
        (a raising submit() abandoned already-submitted spawns; an unprotected outcome loop
        abandoned the rest of the batch), a capacity-starvation clock a later success could erase,
        and gates evaluated only at reservation time so no mid-batch stop()/resize()/rebuild could
        truncate the batch. All four are fixed here and each is mutation-checked by
        tests/host/test_pool_spawn_concurrency_safety.py -- reverting any one of them fails a test.
        Do not "simplify" the gated callable, the per-outcome try/finally, or the deferred
        capacity reset back into a plain comprehension; that is precisely the code that leaked.
        """
        from concurrent.futures import ThreadPoolExecutor

        reservations = 0
        for _ in range(to_spawn):
            if not self._bucket.consume():
                break
            with self._lock:
                if len(self._slots) + self._spawns_in_flight >= self._concurrent_ceiling:
                    break
                if expect_generation is not None and self._base_rebuilds != expect_generation:
                    logger.info("pool.spawn_batch_abandoned reason=base_rebuilt_mid_batch")
                    break
                self._spawns_in_flight += 1
                reservations += 1
        if not reservations:
            return

        def _gated_spawn() -> tuple[Any, dict] | tuple[None, None]:
            """Re-check every gate immediately before the slow spawn, then spawn.

            This is the fix for the reservation-time-only gating: reservations are taken in a
            microsecond loop, so a stop(), a resize() lowering the ceiling, or a base rebuild
            landing DURING the spawns could not truncate the batch. Running the checks here --
            on the worker thread, microseconds before runtime.spawn() -- restores the serial
            path's per-spawn semantics: a declined spawn creates nothing at all, rather than
            creating a worker that the publish step then has to reap.

            The generation ledger is snapshotted HERE, not at reservation time, so a queued
            spawn is stamped with the ledger as its own restore starts (the serial path's
            invariant); stamping a stale generation would make the slot born pre-retired and
            its later failures silently discarded.
            """
            with self._lock:
                if self._stop_event.is_set():
                    return (None, None)
                if len(self._slots) + self._spawns_in_flight > self._concurrent_ceiling:
                    return (None, None)
                if expect_generation is not None and self._base_rebuilds != expect_generation:
                    return (None, None)
                gen_at_spawn = dict(self._base_generation)
            return (self._runtime.spawn(), gen_at_spawn)

        workers = min(self._spawn_concurrency, reservations)
        futures: list[Any] = []
        submit_exc: BaseException | None = None
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bb-spawn")
        try:
            for _ in range(reservations):
                try:
                    futures.append(executor.submit(_gated_spawn))
                except Exception as exc:  # noqa: BLE001 - RuntimeError: can't start new thread
                    # Stop submitting, but DO NOT abandon what is already submitted: shutdown
                    # below waits for it, and the settle loop reaps every worker it created.
                    submit_exc = exc
                    break
            never_submitted = reservations - len(futures)
            if never_submitted:
                with self._lock:
                    self._spawns_in_flight = max(0, self._spawns_in_flight - never_submitted)
        finally:
            # wait=True: every submitted spawn has finished, so no worker can be created after
            # this returns. Not the `with` form -- an exception from submit() must not skip the
            # settle loop below, which is the only thing that reaps what was already created.
            executor.shutdown(wait=True)

        capacity_miss = False
        rebuild_attempted = False
        spawned = 0
        for fut in futures:
            slot = None
            try:
                # `err`, not `exc`: an `except ... as exc` earlier in this method binds that
                # name, and Python deletes it at the end of the clause -- so reusing it here is
                # legal but reads as a live rebind, and mypy rejects it outright ("Assignment to
                # variable exc outside except: block"). CI runs `mypy src`, so this was a red
                # build on the branch while origin/main was clean.
                err = fut.exception()
                if err is not None:
                    kind, rebuild_attempted = self._handle_concurrent_spawn_error(
                        err, rebuild_attempted)
                    capacity_miss = capacity_miss or kind == "capacity"
                    continue
                slot, gen_at_spawn = fut.result()
                if slot is None:
                    continue        # a gate declined it; nothing was created
                slot.state = SlotState.WARMING
                slot.spawned_at = self._clock()
                record_slot_spawned()
                spawned += 1
                self._publish_or_reap_spawned(slot, gen_at_spawn)
                slot = None         # settled: the helper either published or reaped it
            except Exception:  # noqa: BLE001
                # One bad outcome must never abandon the rest of the batch -- those are already
                # COMPLETED spawns holding live workers, and this loop is the only thing that
                # will ever publish or reap them.
                logger.exception("pool.spawn_outcome_failed")
                if slot is not None:
                    self._reap_unsettled_spawn(slot)
            finally:
                with self._lock:
                    self._spawns_in_flight = max(0, self._spawns_in_flight - 1)

        if spawned and not capacity_miss:
            # Capacity came back. Deferred to here so a success later in the batch cannot erase
            # the starvation episode an earlier capacity miss opened -- that reset is what made
            # pool.spawn_capacity_starved unfireable.
            with self._lock:
                self._capacity_miss_since = None
                self._capacity_starved_logged = False
        if submit_exc is not None:
            # Reported, not raised: the batch is fully settled by here, and raising would only
            # surface as pool.tick_error while telling the operator nothing about the cause.
            logger.error("pool.spawn_submit_failed after %d/%d submitted: %s",
                         len(futures), reservations, submit_exc)

    def _handle_concurrent_spawn_error(
        self, exc: BaseException, rebuild_attempted: bool
    ) -> tuple[str, bool]:
        """Classify a failed spawn as the serial loop does. Returns (kind, rebuild_attempted).

        The serial loop ``break``s on each of these; a batch is already in flight here, so
        instead the caller carries the state the break used to imply: *capacity* suppresses the
        end-of-batch "capacity came back" reset, and *rebuild_attempted* makes the base rebuild
        at-most-once per batch (N failing spawns must not drive N invalidations, which with a
        zero cooldown is N real base rebuilds and N generation bumps).
        """
        if isinstance(exc, RuntimeAtCapacity):
            logger.debug("pool.spawn_capacity_miss reason=%s", exc)
            self._note_capacity_miss(str(exc))
            return ("capacity", rebuild_attempted)
        if is_host_resource_failure(exc):
            logger.warning("pool.spawn_host_resource_failure (not counted against the base): %s", exc)
            self._note_capacity_miss(f"host resources exhausted: {exc}")
            return ("capacity", rebuild_attempted)
        logger.error("pool.spawn_failed", exc_info=exc)
        with self._lock:
            self._spawn_consecutive_failures += 1
            spawn_failures = self._spawn_consecutive_failures
        if rebuild_attempted:
            # A rebuild already landed in this batch. Serial would have broken out entirely;
            # the remaining outcomes still need settling, but must not drive a SECOND
            # invalidation (with a zero cooldown that is a second real base rebuild, and with
            # the default cooldown it is a spurious ERROR that also resets the streak).
            return ("failed", rebuild_attempted)
        # Latch only on a rebuild that actually HAPPENED, not on the attempt: the threshold is
        # reached mid-batch (streak 1 is below it, streak 2 crosses it), so latching on the
        # attempt would stop the streak from ever crossing and no rebuild would occur at all.
        if self._maybe_rebuild_base(spawn_failures, reason="spawn"):
            logger.info("pool.spawn_batch_halted_for_rebuild reason=base_invalidated")
            return ("failed", True)
        return ("failed", False)

    def _reap_unsettled_spawn(self, slot: Any) -> None:
        """Last-resort disposal for a spawned worker that publish raised on.

        Without this the slot that TRIGGERED the exception is the one leaked: it exists as a real
        microVM/instance but is in neither _slots nor reaped, so stop() cannot see it. If publish
        got far enough to insert it, leave it -- it is tracked, and the health check owns it now.
        """
        with self._lock:
            if slot.slot_id in self._slots:
                return
        try:
            if self._reap_and_count(slot):
                return
        except Exception:
            logger.exception("pool.reap_unsettled_failed slot_id=%s", slot.slot_id)
        # Terminate failed or raised: track the husk as DRAINING so it is accounted for and
        # surfaced for manual cleanup rather than silently leaked off the books.
        slot.state = SlotState.DRAINING
        with self._lock:
            self._slots[slot.slot_id] = slot

    def _publish_or_reap_spawned(self, slot: Any, gen_at_spawn: dict) -> None:
        """Publish a freshly spawned slot, or reap it if shutdown/ceiling says we must not.

        Mirrors the serial path's publish block: stop() may have snapshotted _slots while the
        spawn was in flight (publishing then leaks a live microVM/instance), and a concurrent
        resize() may have lowered the ceiling underneath us.
        """
        with self._lock:
            drop = self._stop_event.is_set() or len(self._slots) >= self._concurrent_ceiling
            if not drop:
                self._slots[slot.slot_id] = slot
                _ident = self._base_identity(slot)
                self._slot_base[slot.slot_id] = (_ident, gen_at_spawn.get(_ident, 0))
        if not drop:
            return
        reaped = False
        try:
            reaped = self._reap_and_count(slot)
        except Exception:
            logger.exception("pool.reap_unpublished_failed slot_id=%s — quarantining (worker may "
                             "persist)", slot.slot_id)
        if not reaped:
            # Track the husk as DRAINING so it is accounted for instead of silently leaked.
            slot.state = SlotState.DRAINING
            with self._lock:
                self._slots[slot.slot_id] = slot

    def _spawn_to_deficit(self, ready: bool = True, *,
                          expect_generation: int | None = None) -> None:
        """Spawn new slots to fill the deficit, respecting ceiling + rate limit.

        ``ready`` is the warm runtime's per-tick readiness (resolved once in tick()). When False
        the warm snapshot is still building, so we spawn nothing this tick — _promote_warming and
        _health_check already ran, and dispatch falls back to cold until the snapshot is ready.
        """
        if not ready:
            # A stuck or repeatedly-failing snapshot build keeps prepare() False forever. Bailing
            # out here meant the pool could sit at a positive target with ZERO slots and never
            # touch the capacity meter or the starvation clock -- even though "a snapshot tier
            # stuck building" is one of the causes the alert message itself names (upstream,
            # PR #82).
            with self._lock:
                active = sum(
                    1 for s in self._slots.values() if s.state != SlotState.DRAINING
                )
                deficit = max(0, self._effective_target_unlocked() - active)
            if deficit > 0:
                self._note_capacity_miss("the warm snapshot is not ready (build stuck or failing)")
            else:
                with self._lock:
                    self._capacity_miss_since = None
                    self._capacity_starved_logged = False
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
            starved_without_headroom = deficit > 0 and to_spawn == 0
            if deficit == 0:
                # NOT starving -- we are not asking for anything. Keyed on DEFICIT, not on
                # to_spawn: to_spawn is also zero when there IS a deficit but no headroom, which
                # happens when failed reaps leave DRAINING slots occupying concurrent_ceiling.
                # That is a pool with zero usable capacity -- precisely what the alert exists to
                # report -- and clearing the episode there meant it could never fire.
                #
                # The episode clock is cleared
                # only by a successful spawn otherwise, so a pool whose target the autosizer
                # shrank to zero keeps a stale timestamp for however long it idles; the first
                # capacity miss after a later scale-up then fires pool.spawn_capacity_starved
                # citing that whole unrelated idle interval. The alert must measure CONTINUOUS
                # starvation, not the gap between two autosizer epochs (upstream, PR #82).
                self._capacity_miss_since = None
                self._capacity_starved_logged = False

        if starved_without_headroom:
            # A deficit we cannot even ATTEMPT to fill. The spawn loop below never runs, so the
            # capacity handler inside it — the only thing that used to open a starvation episode —
            # is unreachable here. That is how a pool whose ceiling is entirely occupied by
            # DRAINING slots (failed reaps, leaked reservations) sat at zero usable capacity
            # without ever reporting it: not merely clearing the clock, but never starting it.
            self._note_capacity_miss(
                "a deficit exists but no headroom: the ceiling is full of slots that are not "
                "usable (DRAINING/leaked reservations)"
            )

        if self._spawn_concurrency > 1 and to_spawn > 1:
            # Overlap the slow runtime.spawn() calls. Everything else -- gates, accounting,
            # publication -- is unchanged; see _spawn_batch_concurrent.
            self._spawn_batch_concurrent(to_spawn, expect_generation)
            return

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

            if expect_generation is not None:
                with self._lock:
                    if self._base_rebuilds != expect_generation:
                        # A rebuild landed after tick() committed. Abandon the batch rather than
                        # call spawn() -- it would build the new base synchronously here.
                        logger.info(
                            "pool.spawn_batch_abandoned reason=base_rebuilt_mid_batch"
                        )
                        break
            # SNAPSHOT the generation ledger BEFORE the restore starts. spawn() can take a long
            # time, and a job thread can invalidate while it runs: the manager keeps the retired
            # artifact pinned long enough for the restore to finish, so the slot really is from
            # the OLD generation -- but publication below read the already-advanced counter and
            # stamped it as CURRENT. A later worker failure from that slot then passed the
            # retired-generation guard and could invalidate the replacement base (PR #82).
            with self._lock:
                _gen_at_spawn = dict(self._base_generation)
            try:
                slot = self._runtime.spawn()
                with self._lock:
                    # NOT the failure streak. A spawn that merely RETURNS says nothing about
                    # whether the base can produce a usable worker: with warm_size=1 each
                    # timed-out WARMING slot bumped the streak to 1 and its replacement's spawn
                    # immediately cleared it, so a base that consistently restores but never
                    # becomes ready cycled at a streak of one and never reached the rebuild
                    # threshold. Only reaching IDLE is proof (upstream, PR #82).
                    #
                    # Capacity came back: reset the starvation clock AND the latch, so a later
                    # outage escalates again rather than being permanently silenced by the first.
                    self._capacity_miss_since = None
                    self._capacity_starved_logged = False
                slot.state = SlotState.WARMING
                slot.spawned_at = self._clock()
                record_slot_spawned()
            except RuntimeAtCapacity as exc:
                # NOT a restore failure, so it must NOT touch the streak. prepare() reports ready
                # when ANY tier is, so spawn() legitimately raises this while the ready tiers are
                # full and a snapshot tier is still building. Break rather than continue: capacity
                # will not appear later in the SAME batch, and each further attempt is a wasted
                # spawn. The next tick retries (upstream, PR #82).
                logger.debug("pool.spawn_capacity_miss reason=%s", exc)
                self._note_capacity_miss(str(exc))
                break
            except Exception as exc:
                if is_host_resource_failure(exc):
                    # THIS HOST is out of space/fds/inodes. Spawning creates a slot workdir and
                    # copies a per-slot disk, so it says nothing about the base -- and the cascade
                    # deliberately leaves its per-tier guilt EMPTY for these, so counting it here
                    # produced a spawn-driven repair with no guilty tier, whose empty-guilt
                    # fallback invalidates every healthy tier. An all-local cascade sharing one
                    # full filesystem hits exactly that (upstream, PR #82).
                    logger.warning("pool.spawn_host_resource_failure (not counted against the "
                                   "base): %s", exc)
                    self._note_capacity_miss(f"host resources exhausted: {exc}")
                    break
                logger.exception("pool.spawn_failed")
                with self._lock:
                    self._spawn_consecutive_failures += 1
                    spawn_failures = self._spawn_consecutive_failures
                rebuilt = self._maybe_rebuild_base(spawn_failures, reason="spawn")
                if rebuilt:
                    # STOP the batch. The artifact is gone, so the very next runtime.spawn() would
                    # run SnapshotManager.build() synchronously and block this maintenance thread
                    # for a full base boot + readiness timeout -- promotion, health checks and
                    # deferred reaping all stall behind it. The next tick spawns against the fresh
                    # base instead (upstream, PR #82).
                    logger.info("pool.spawn_batch_halted_for_rebuild reason=base_invalidated")
                    break
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
                    # STAMP the generation this slot came from, under the same lock that
                    # publishes it, so a later failure can be told apart from one produced by
                    # the base currently installed.
                    _ident = self._base_identity(slot)
                    # ...from the ledger as it was when this restore STARTED, not as it is now.
                    self._slot_base[slot.slot_id] = (
                        _ident, _gen_at_spawn.get(_ident, 0)
                    )
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

    def _base_identity(self, slot: "Slot") -> str:
        """Which BASE produced this slot: a cascade tier name, or "" for a single-base runtime.

        Optional seam, hasattr-guarded, exactly like worker_identity.
        """
        fn = getattr(self._runtime, "base_identity", None)
        if callable(fn):
            try:
                got = fn(slot)
            except Exception as exc:  # noqa: BLE001 -- attribution must never break a release
                logger.warning("pool.base_identity_failed slot_id=%s: %s", slot.slot_id, exc)
            else:
                if got:
                    return str(got)
        return ""

    def _clear_runtime_job_guilt(self) -> None:
        """Tell a runtime that keeps per-tier job attribution that the episode recovered.

        Optional seam, hasattr-guarded: only a cascade tracks this. MUST NOT be called under
        _lock -- it takes the runtime's own lock.
        """
        fn = getattr(self._runtime, "clear_job_guilt", None)
        if not callable(fn):
            return
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- attribution must never break a release
            logger.warning("pool.clear_job_guilt_failed: %s", exc)

    def _health_key(self, slot: "Slot") -> str:
        """The identity this slot's failure history belongs to.

        A disposable runtime mints a fresh slot per worker, so the slot_id IS the worker and the
        default is right. A STATIC pool does the opposite: every spawn() hands a new slot_id to
        the same long-lived box and reap() just returns that box to the free list. Keyed by
        slot_id, its counter reached one, the non-recycle release path removed the slot,
        _forget_slot_health() erased the history, and the next request to the SAME endpoint
        started from zero -- so the default threshold of two could never burn out a static box,
        even for correctly attributed transport failures. And a static tier has no snapshot base
        to invalidate, so burnout is the only protection it has (upstream, PR #82).

        Optional seam, hasattr-guarded: a runtime that does not reuse workers is unaffected.
        """
        # No lock: dict get/set are atomic, the value for a given slot is deterministic, and a
        # concurrent double-fill therefore stores the same key twice. Taking _lock here would put
        # a runtime callout inside it and invite the lock-ordering hazard this module has already
        # produced once.
        cached = self._health_key_by_slot.get(slot.slot_id)
        if cached is not None:
            return cached
        key = slot.slot_id
        identity = getattr(self._runtime, "worker_identity", None)
        if callable(identity):
            try:
                got = identity(slot)
            except Exception as exc:  # noqa: BLE001 -- attribution must never break a release
                logger.warning("pool.worker_identity_failed slot_id=%s: %s", slot.slot_id, exc)
            else:
                if got:
                    key = str(got)
        self._health_key_by_slot[slot.slot_id] = key
        return key

    def _forget_slot_health(self, slot_id: str) -> None:
        """Drop per-slot failure bookkeeping for a slot that has left the pool.

        Called wherever a slot is popped from ``_slots`` so the tracking dicts cannot grow without
        bound over a long-lived dispatcher (slot ids are per-spawn UUIDs).
        """
        # ...but only when the history belongs to THIS SLOT. On a static pool the key is the
        # physical box, which outlives every slot handed to it -- dropping its record on reap is
        # exactly how its failures could never accumulate. Bounded either way: a reused identity
        # is one entry per registered worker.
        self._slot_base.pop(slot_id, None)
        key = self._health_key_by_slot.pop(slot_id, slot_id)
        if key == slot_id:
            self._slot_failures.pop(slot_id, None)
            self._slot_last_success.pop(slot_id, None)
        # ...and the promotion ledger. Disposable runtimes mint a new slot_id per replacement, so a
        # workload with recurring failures or resizes grows this set without bound, and none of its
        # entries can ever be consulted again (PR #82).
        self._promoted_unproven.discard(slot_id)

    def _current_failure_streak(self) -> int:
        """The pool-wide consecutive-failure streak, read NOW under the lock.

        Carrying a value captured earlier in release() meant another slot could release cleanly and
        reset the streak before this ran, and the stale reading still invalidated the shared base --
        dropping a healthy warm snapshot after the pool had already recovered (upstream, PR #82)."""
        with self._lock:
            return max(self._pool_consecutive_failures.values(), default=0)

    def _maybe_rebuild_base(self, streak: "int | None" = None, *, reason: str = "job") -> bool:
        """Discard the runtime's persisted warm base after sustained pool-wide failure.

        Reaping a burned-out slot only helps if a FRESH slot would be healthy. When the persisted
        base itself captured a bad guest state, every replacement restores the same wedge and the
        tier stays dead until an operator restarts the dispatcher. If the runtime exposes a way to
        drop that base (``invalidate_base``/``invalidate_snapshot``), call it once the pool has
        failed ``snapshot_rebuild_after`` times in a row with no intervening success.
        """
        # streak=None means "read the JOB streak live, under the lock, right now". The release
        # path must use that: it computed a value earlier in release(), and another slot could
        # release cleanly -- resetting the streak -- before the call ran, so a stale reading still
        # invalidated the base and dropped a healthy warm snapshot after the pool had recovered
        # (upstream, PR #82). The SPAWN path passes its own counter explicitly, because consecutive
        # restore failures are a different signal from consecutive job failures.
        _consumed_pre_guest: frozenset = frozenset()
        if self._snapshot_rebuild_after <= 0:
            # --- D: the escape hatch must not leak. _maybe_rebuild_base returns here, so nothing
            # ever consumes the evidence set; a continuously wedged tier producing no successes
            # then added one slot id per failed job, for the life of the process. The previous
            # integer counter could not grow. Drop it rather than accumulate a ledger nobody will
            # ever read.
            with self._lock:
                self._pool_pre_guest_failures.clear()
            return False
        success_token: int | None = None
        # "" is the whole-runtime base: the SPAWN path passes its own counter and does not consume
        # a per-identity episode, so it has no identity of its own to restore on failure.
        episode_ident = ""
        if streak is None:
            # CHECK-AND-CONSUME in one locked step. Reading the streak under the lock and then
            # deciding outside it still leaves a window: a clean release from another dispatch
            # thread resets the counter to zero in between, and this stale failing release goes
            # on to destroy a base that a job has just succeeded against. Consuming the episode
            # here also stops several concurrent failures from each triggering their own rebuild
            # off the same streak. (The spawn path passes its own counter and is single-threaded
            # in the maintenance tick, so it opts out.)
            with self._lock:
                _worst = max(self._pool_consecutive_failures.items(),
                             key=lambda kv: kv[1], default=("", 0))
                # TWO thresholds, because there are two qualities of evidence. The ordinary
                # streak counts worker faults that MIGHT be the documents, so it is sized to
                # tolerate a run of bad samples (2 x warm_size). Slots that never reached their
                # guest carry no such ambiguity, and demanding the same count of them means the
                # tier eats ~48 real jobs -- each burning the full worker timeout -- before it
                # repairs itself, which is exactly how a warm tier rots into a cold-only one.
                _pre = max(self._pool_pre_guest_failures.items(),
                           key=lambda kv: len(kv[1]), default=("", set()))
                _pre_crossed = (self._pre_guest_rebuild_after > 0
                                and len(_pre[1]) >= self._pre_guest_rebuild_after)
                if _worst[1] < self._snapshot_rebuild_after and not _pre_crossed:
                    return False
                if _pre_crossed and _worst[1] < self._snapshot_rebuild_after:
                    logger.error(
                        "pool.base_rebuild_pre_guest base=%s slots=%d threshold=%d -- %d DISTINCT "
                        "slots restored from this base failed before their guest ever executed; "
                        "that is the base, not the samples",
                        _pre[0] or "<default>", len(_pre[1]), self._pre_guest_rebuild_after,
                        len(_pre[1]),
                    )
                    _worst = (_pre[0], len(_pre[1]))
                # Consume ONLY the episode that crossed. Zeroing every base's counter let one
                # tier's repair discard the evidence another tier was still accumulating.
                episode_ident, pool_failures = _worst
                self._pool_consecutive_failures.pop(episode_ident, None)
                # Kept so a FAILED repair can hand it back; see _invalidate_now.
                _consumed_pre_guest = frozenset(
                    self._pool_pre_guest_failures.pop(episode_ident, set()))
                # Token captured WITH the decision. Consuming the streak closed the read/decide
                # gap, but drop() still runs outside the lock: a clean release landing in that
                # window is proof the base just produced a valid result, and rebuilding it then
                # is an unnecessary outage during recovery (upstream, PR #82).
                success_token = self._clean_release_count
        else:
            pool_failures = streak
            if pool_failures < self._snapshot_rebuild_after:
                return False
            # Take the episode token even on the explicit-streak path. The caller captured its
            # count earlier, so a concurrent clean release can land between then and here -- and
            # skipping the token meant that path invalidated a base which had just produced a
            # valid result, the very case the token was added to prevent (PR #82).
            with self._lock:
                success_token = self._clean_release_count
        now = self._clock()
        with self._lock:
            last = self._last_base_rebuild_at
            cooling = (
                self._base_rebuild_cooldown_s > 0
                and last is not None
                and (now - last) < self._base_rebuild_cooldown_s
            )
        if cooling:
            # Keep failing loudly, but do not boot again yet: if the base were the problem, the
            # previous rebuild would have fixed it, so continued failure points elsewhere.
            logger.error(
                "pool.base_rebuild_suppressed pool_consecutive_failures=%d since_last_rebuild=%.1fs "
                "cooldown=%.1fs -- sustained failure that a base rebuild did NOT fix; the cause is "
                "likely NOT the warm base (check inputs/disk/dependencies)",
                pool_failures, now - float(last or now), self._base_rebuild_cooldown_s,
            )
            with self._lock:
                if reason == "spawn":
                    self._spawn_consecutive_failures = 0
                else:
                    self._pool_consecutive_failures.pop(episode_ident, None)
                    self._pool_pre_guest_failures.pop(episode_ident, None)
            return False
        if reason == "spawn":
            with self._lock:
                # ASSIGNED counts too. A slot only reaches ASSIGNED by being CLAIMED, which is
                # stronger proof the base produces usable workers than sitting IDLE -- yet the
                # guard recognised IDLE alone, so an ordinary claim erased its own evidence: with
                # one healthy worker the streak was retained, the worker was handed a job, and
                # the next failed restore saw zero usable slots and invalidated the base out from
                # under a demonstrably-live worker mid-job. The protection was lost to nothing
                # more than normal traffic (upstream, PR #82).
                usable = sum(1 for s in self._slots.values()
                             if s.state in (SlotState.IDLE, SlotState.ASSIGNED))
            if usable:
                # A base with LIVE, IDLE workers is not poisoned. Counting restore failures alone
                # made fail/succeed/fail/succeed/fail reach the threshold with healthy workers
                # sitting right there, while resetting on every promotion went the other way and
                # let promote/die/promote/die never accumulate at all. "Is it currently producing
                # usable workers?" separates the two directly, which a consecutive count of one
                # side of the story cannot (PR #82).
                logger.info(
                    "pool.base_rebuild_skipped reason=usable_workers_present usable=%d "
                    "restore_failures=%d", usable, pool_failures,
                )
                return False

        drop = (getattr(self._runtime, "invalidate_base", None)
                or getattr(self._runtime, "invalidate_snapshot", None))
        if not callable(drop):
            logger.error(
                "pool.base_rebuild_unavailable pool_consecutive_failures=%d -- runtime %s exposes no "
                "invalidate_base(); the warm base may be poisoned and only a dispatcher restart can "
                "rebuild it", pool_failures, type(self._runtime).__name__,
            )
            return False
        with self._lock:
            stale = success_token is not None and success_token != self._clean_release_count
        if stale:
            logger.info(
                "pool.base_rebuild_skipped reason=slot_succeeded_during_decision — the base "
                "produced a valid result while this failure was being judged"
            )
            return False
        # Bump the generation BEFORE drop() runs. It was incremented only after drop() returned,
        # so throughout the call -- which is where the artifact is actually cleared -- the spawn
        # batch's re-check still saw the old value and spawned against a base the manager had
        # already discarded, rebuilding it synchronously on the maintenance thread. The generation
        # must mark "an invalidation is IN PROGRESS", not "one finished" (PR #82).
        with self._lock:
            self._base_rebuilds += 1
            self._rebuilt_this_tick = True
        # SERIALISE. Held across the whole drop() so a second repair cannot land mid-rebuild; the
        # cooldown check above is re-read inside so the loser of the race sees the winner's result
        # instead of repeating it.
        with self._invalidation_lock:
            with self._lock:
                _last = self._last_base_rebuild_at
            if (self._base_rebuild_cooldown_s > 0 and _last
                    and (now - float(_last)) < self._base_rebuild_cooldown_s):
                logger.info(
                    "pool.base_rebuild_skipped reason=another_repair_just_completed "
                    "reason_kind=%s", reason,
                )
                return False
            return self._invalidate_now(drop, reason, pool_failures, success_token, now,
                                        episode_ident, _consumed_pre_guest)

    def _invalidate_now(self, drop, reason, pool_failures, success_token, now,
                        episode_ident, pre_guest_slots=frozenset()):  # noqa: ANN001, ANN201
        """Perform the invalidation. CALLER MUST HOLD ``self._invalidation_lock``."""
        try:
            # Pass the trigger through when the runtime accepts it: a cascade can only attribute a
            # SPAWN-driven repair to a tier. Introspection, not except-TypeError -- a TypeError
            # from inside drop() must never be mistaken for an older signature.
            if _accepts_kwarg(drop, "reason"):
                repaired = drop(reason=reason)
            else:
                repaired = drop()
        except Exception as exc:
            # A PARTIAL repair still replaced some artifacts. Retire their slots even though the
            # call failed overall, or those tiers' old slots keep reporting failures against a
            # base that is already gone -- which re-blames the tier and invalidates its fresh
            # replacement (upstream, PR #82).
            _repaired = getattr(exc, "repaired", None)
            if isinstance(_repaired, (list, tuple, set, frozenset)) and _repaired:
                with self._lock:
                    for _name in {str(n) for n in _repaired}:
                        self._base_generation[_name] = self._base_generation.get(_name, 0) + 1
            logger.exception("pool.base_rebuild_error pool_consecutive_failures=%d", pool_failures)
            # RESTORE the consumed episode. The streak was consumed to make the decision, but the
            # repair did not happen -- so making the poisoned base wait for another full
            # snapshot_rebuild_after failures before retrying just fails that many more jobs. Only
            # restore what we took, and never below what has accumulated since.
            if success_token is not None and reason != "spawn":
                # Only a JOB episode is consumed from _pool_consecutive_failures, so only that one
                # is restored here. A spawn episode lives in _spawn_consecutive_failures and is
                # already retained by its own caller -- copying its count into the job counter
                # meant one later worker fault could trigger an immediate job-driven rebuild, and
                # in a cascade that repair carries no tier attribution and hits every tier (PR #82).
                with self._lock:
                    self._pool_consecutive_failures[episode_ident] = max(
                        self._pool_consecutive_failures.get(episode_ident, 0), pool_failures
                    )
                    # ...and the PRE-GUEST evidence with it. Restoring only the integer streak
                    # made the fast path a one-shot: its crossing count (3) is far below the
                    # ordinary threshold (48), so a failed repair meant the same unrepaired base
                    # had to accumulate three fresh distinct slots all over again before it would
                    # even retry -- three more jobs lost per failed attempt, which is precisely
                    # what this path exists to stop.
                    if pre_guest_slots:
                        self._pool_pre_guest_failures.setdefault(episode_ident, set()).update(
                            pre_guest_slots)
            return False
        with self._lock:
            if reason == "spawn":
                self._spawn_consecutive_failures = 0
            else:
                self._pool_consecutive_failures.pop(episode_ident, None)
            # NB _base_rebuilds was already bumped before drop() (it is the in-flight fence).
            # The COMMITTED generation advances only here, on the success path: a drop() that
            # raised leaves the tier's artifact in place, and stamping its live slots as retired
            # would discard the very failures that must repair it.
            # Advance ONLY the bases actually repaired. A cascade reports the tier names it
            # invalidated; anything else repaired its single base. Bumping one pool-wide counter
            # retired the live slots of tiers this repair never touched, so their failures --
            # about a base that is still current -- were discarded, and for reusable slots that
            # suppressed the evidence until the slot was eventually replaced (upstream, PR #82).
            if isinstance(repaired, (list, tuple, set, frozenset)):
                names = {str(n) for n in repaired}
            else:
                names = {ident for ident, _ in self._slot_base.values()} | {""}
            for _name in names:
                self._base_generation[_name] = self._base_generation.get(_name, 0) + 1
            self._last_base_rebuild_at = now
            # Defer this tick's spawning wherever the rebuild came from. tick() captured `ready`
            # before release() could run, and a JOB-triggered rebuild races it: both snapshot
            # runtimes call SnapshotManager.build() synchronously from spawn(), so spawning on a
            # stale ready=True blocks the sole maintenance thread for a full boot + readiness
            # timeout. Setting the flag only in _health_check covered one of the two triggers
            # (PR #82).
            self._rebuilt_this_tick = True
            rebuilds = self._base_rebuilds
        logger.warning(
            "pool.base_invalidated reason=%s consecutive_failures=%d rebuilds=%d -- next spawn "
            "rebuilds the warm base", reason, pool_failures, rebuilds,
        )
        return True

    def _blame_tiers(self, slot_ids: "list[str]") -> None:
        """Attribute post-spawn failures to the tiers that produced those slots.

        A spawn that RETURNED leaves the cascade's per-tier streak empty, so a repair driven by
        these failures finds no guilty tier and the empty-guilt fallback invalidates EVERY tier --
        discarding healthy sibling snapshots over a fault confined to one. Must run BEFORE the
        slots are reaped: the cascade drops its slot->tier mapping on reap, and an unattributable
        slot is exactly the empty guilt this exists to avoid.

        Shared by both post-spawn failure paths. It lived inline in the health check, so the
        warming-timeout path -- added later, feeding the same streak and the same
        _maybe_rebuild_base(reason="spawn") -- never attributed anything (upstream, PR #82).
        """
        if not slot_ids:
            return
        blame = getattr(self._runtime, "blame_tier_for_slot", None)
        if not callable(blame):
            return
        for slot_id in slot_ids:
            try:
                blame(slot_id)
            except Exception as exc:  # noqa: BLE001 -- attribution must never break the tick
                logger.warning("pool.tier_blame_failed slot_id=%s: %s", slot_id, exc)

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
        # Deaths of slots that were promoted but never served a job are restore failures too:
        # see _promote_warming. Collected here so the streak reflects them before the rebuild
        # decision below.
        unproven_deaths = 0
        # Slot ids whose post-promotion death should be attributed to their owning tier: the
        # spawn SUCCEEDED, so the cascade has no guilt recorded and would otherwise fall back to
        # invalidating every tier (PR #82).
        blamed: list[str] = []
        # Slots we escalated because we could not TELL, as opposed to ones AWS/libvirt confirmed
        # dead. If disposing of a merely-suspected slot also fails, we have learned nothing and must
        # not strand it (see the reap loop below).
        suspected: set[str] = set()
        # Slots that already hold an eviction token (reserved when their timeout was detected),
        # so the demotion loop must not charge them again.
        budgeted: set[str] = set()
        for slot in stuck_warming:
            logger.warning(
                "pool.warming_timeout_evict slot_id=%s age=%.1fs", slot.slot_id, now - slot.spawned_at
            )
        if stuck_warming:
            # A spawn that RETURNED a slot reset the spawn-failure streak, but a slot that never
            # reached IDLE produced no usable worker at all. Without counting these, a base
            # poisoned just enough to restore-and-then-die cycles restore -> warmup timeout ->
            # replace forever, and invalidate_base() is never reached: the tier stays at zero
            # capacity until the process restarts, which is exactly the outage the restore-failure
            # streak exists to end (upstream, PR #82).
            # Attribute BEFORE the repair decision and before these slots are reaped. Each
            # spawn() returned successfully, so the cascade's per-tier streak is empty and a
            # repair would fall back to invalidating every tier -- destroying healthy siblings
            # because one tier hands back slots that never reach IDLE (upstream, PR #82).
            # RESERVE FIRST, then count only what is actually being evicted. The streak was
            # advanced for every timed-out slot before the budget decision, so a slot the cap
            # REFUSED to evict stayed WARMING and was counted again by every later tick: one
            # healthy-but-slow capped slot reached the rebuild threshold within a few poll cycles
            # and invalidated a healthy snapshot on no additional restore failure at all. With
            # max_evictions_per_window=0 -- the operator's "stop evicting" -- it counted forever
            # (upstream, PR #82). The tokens taken here are carried in `budgeted` so the demotion
            # loop does not charge these slots a second time.
            with self._lock:
                for s in stuck_warming:
                    if self._reserve_eviction_unlocked(self._clock(), s.slot_id):
                        budgeted.add(s.slot_id)
            capped = [s for s in stuck_warming if s.slot_id not in budgeted]
            if capped:
                logger.warning(
                    "pool.warming_timeout_capped count=%d -- the eviction budget is spent; these "
                    "slots stay WARMING and are NOT counted as restore failures", len(capped),
                )
            evicting = [s for s in stuck_warming if s.slot_id in budgeted]
            self._blame_tiers([s.slot_id for s in evicting])
            with self._lock:
                self._spawn_consecutive_failures += len(evicting)
                warm_failures = self._spawn_consecutive_failures
            if self._maybe_rebuild_base(warm_failures, reason="spawn"):
                # HALT THE TICK. The artifact is gone, so the very next runtime.spawn() runs
                # SnapshotManager.build() synchronously and blocks this thread -- the pool's only
                # maintenance thread -- for a full base boot plus readiness timeout, stalling
                # promotion, health checks and deferred reaping behind it. tick() captured
                # ready=True before _health_check ran, so without this it walks straight into
                # exactly that. The spawn-failure path already halts its batch for this reason;
                # this newer trigger did not inherit it (upstream, PR #82).
                self._rebuilt_this_tick = True
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
                # Under the lock: the claim path pops this entry, and an in-flight health probe
                # that started BEFORE that pop would otherwise write a stale timestamp after it.
                # On a reusable slot the stale stamp keeps ageing while the slot is ASSIGNED, so the
                # first UNKNOWN after release can exceed the grace at once and evict a worker that
                # has been serving jobs the whole time (upstream P2).
                # Read the clock HERE, not the `now` sampled before the pass began. Probes run
                # serially, so a tier's worth of slow ones means the last slot is reached minutes
                # after `now` -- and stamping it with that stale value charges it for time spent
                # probing the slots ahead of it. On the next pass it is already most of the way
                # through its grace and escalates on what is really its FIRST unknown (escalated
                # codex, loop 5).
                probed_at = self._clock()
                with self._lock:
                    # DROP the result if a claim took this slot while we were probing. Taking the
                    # lock only serialises the writes; it does not ORDER them, so a probe that
                    # started when the slot was IDLE could still stamp it after a concurrent claim
                    # cleared the entry -- and that stale stamp then ages untouched for the whole
                    # job, so the first UNKNOWN after release exceeds the grace at once and evicts a
                    # worker that has been serving the entire time (upstream P2).
                    cur = self._slots.get(slot.slot_id)
                    if cur is not slot or cur.state != SlotState.IDLE:
                        continue
                    since = self._unknown_since.setdefault(slot.slot_id, probed_at)
                    # DECIDE under the same lock that verified the state. Computing stuck_for and
                    # escalating after releasing it left a window in which a concurrent claim()
                    # could take this slot -- and we would still mark it dead and dispose of it
                    # WHILE IT WAS SERVING A JOB. Locking the check but not the decision is the
                    # same mistake as reading the failure streak under the lock and deciding
                    # outside it, and as comparing the build epoch before publishing (PR #82).
                    stuck_for = probed_at - since
                    escalate = (
                        self._unknown_grace_s > 0 and stuck_for > self._unknown_grace_s
                    )
                    if escalate:
                        self._unknown_since.pop(slot.slot_id, None)
                # NB the eviction cap is NOT consulted here. It is enforced at the demotion
                # below -- the step that actually evicts -- because a claimant can take this slot
                # in between and the budget must not be spent on an eviction that never happens.
                # A peek here as well was pure duplication: removing it changed no behaviour,
                # which is exactly what a surviving mutant told me (PR #82).
                if escalate:
                    logger.warning("pool.health_unknown_escalated slot_id=%s unknown_for=%.0fs "
                                   "(> %.0fs) — treating as dead so the slot is replaced",
                                   slot.slot_id, stuck_for, self._unknown_grace_s)
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
                # Bookkeeping is deferred to the DEMOTION below, which is the step that
                # actually wins the race against a concurrent claim. Recording it here let a
                # stale death verdict advance the restore-failure streak for a slot a claimant
                # had just taken -- and whose own fresher probe had accepted the worker -- so a
                # perfectly good shared base could be invalidated on it (PR #82).

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
                    # RESERVE here: this is the step that actually evicts. A slot a claimant took
                    # between the escalation decision and now is skipped by the guard above, and
                    # must not have consumed budget on the way past.
                    # Reserve INLINE: we already hold self._lock, and _eviction_allowed takes
                    # it -- calling it here deadlocks on a non-reentrant Lock (it hung the whole
                    # suite before this was caught).
                    # A FRESH clock read: `now` was sampled before any probe ran, and a pass
                    # over a large static/cloud tier probes serially. Reserving with that stale
                    # value backdates the token by the whole pass, so on a short window the next
                    # pass expires every token immediately and evicts another full capped batch --
                    # defeating max_evictions_per_window exactly when it matters (PR #82).
                    # A warming timeout is a HEURISTIC too: "healthy but slower than the
                    # configured budget" looks identical to "never coming up", and a low timeout
                    # on a cloud tier churns the entire warm set. Only a runtime-CONFIRMED death
                    # may bypass the cap; a timed-out WARMING slot was never confirmed by anyone,
                    # so it spends budget exactly like an escalated-unknown one. It bypassed the
                    # cap purely because it was never added to `suspected` (upstream, PR #82).
                    heuristic = (slot.slot_id in suspected
                                 or cur.state == SlotState.WARMING)
                    if (heuristic and slot.slot_id not in budgeted
                            and not self._reserve_eviction_unlocked(self._clock(), slot.slot_id)):
                        logger.warning(
                            "pool.health_unknown_escalation_capped slot_id=%s — budget exhausted "
                            "at demotion; leaving the slot in place", slot.slot_id,
                        )
                        self._unknown_since.setdefault(slot.slot_id, now)
                        continue
                    cur.state = SlotState.DRAINING
                    # We won the race, so this death is real evidence. A slot that never served a
                    # job had only its promotion vouching for the base, and that is now refuted.
                    # ONLY a confirmed death is restore evidence. A slot escalated from
                    # UNKNOWN entered `dead` on suspicion, and during a prolonged control-plane
                    # brownout every slot does -- counting those would invalidate a healthy base
                    # on no verdict at all, and the count would stand even when the disposal then
                    # failed and the slot was restored to IDLE (PR #82).
                    if (cur.slot_id in self._promoted_unproven
                            and cur.slot_id not in suspected):
                        self._promoted_unproven.discard(cur.slot_id)
                        unproven_deaths += 1
                        blamed.append(cur.slot_id)
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


        # Counted AFTER the demotion loop, which is the step that wins the race against a
        # concurrent claim -- so only deaths we actually acted on feed the restore-failure streak.
        self._blame_tiers(blamed)

        if unproven_deaths:
            with self._lock:
                self._spawn_consecutive_failures += unproven_deaths
                warm_failures = self._spawn_consecutive_failures
            if self._maybe_rebuild_base(warm_failures, reason="spawn"):
                self._rebuilt_this_tick = True
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
                            # REFUND the token. The demotion spent one to evict this slot, and we
                            # have just put it back -- so the budget paid for nothing. During a
                            # brownout every disposal goes through the same unresponsive control
                            # plane and fails, so the window's whole allowance could be consumed
                            # without a single eviction, blocking the replacement of a slot that
                            # IS confirmed dead for the rest of the window (upstream, PR #82).
                            self._refund_eviction_unlocked(slot.slot_id)
                    logger.warning("pool.health_escalation_undone slot_id=%s — could not dispose a "
                                   "merely-suspected slot; returning it to IDLE", slot.slot_id)
            finally:
                if reaped:
                    with self._lock:
                        self._slots.pop(slot.slot_id, None)
                        self._forget_slot_health(slot.slot_id)

    def _background_loop(self) -> None:
        """Run tick() repeatedly until stop() is called."""
        while not self._stop_event.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("pool.tick_error")
            self._stop_event.wait(timeout=self._poll_interval)
