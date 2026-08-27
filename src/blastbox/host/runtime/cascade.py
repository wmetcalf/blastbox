"""Cascading (tiered) SlotRuntime: fill a primary tier, then overflow to the next.

Answers "run **X workers locally, then burst up to Y on other hardware / AWS**" as a single warm pool.
It composes any of the existing backends (gvisor / firecracker locally, ``static`` for other boxes,
``aws-ec2`` / ``aws-lambda-microvm`` for cloud) into a **priority-ordered** list of tiers, each with a
capacity. ``spawn`` fills tier 1 up to its capacity, then tier 2, and so on; ``reap`` frees the slot on
whichever tier owns it. The WarmPool above it is unchanged -- it just sees one SlotRuntime.

Wiring (env):
  BLASTBOX_POOL_RUNTIME=cascade
  BLASTBOX_POOL_TIERS=static:4,aws-ec2:16     # 4 warm local + up to 16 overflow on AWS
  BLASTBOX_POOL_WARM_SIZE=4                    # keep the 4 local slots warm
  BLASTBOX_POOL_BURST_SIZE=16                  # so the pool can burst 4 -> 20 into the overflow tier
  BLASTBOX_POOL_CEILING=20                     # 4 local + 16 overflow
  BLASTBOX_DISPATCH_CONCURRENCY=20

Each tier reads its own backend config (BLASTBOX_STATIC_WORKERS, BLASTBOX_EC2_*, BLASTBOX_FC_*, ...).
The **primary** tier must be available at startup (fail-closed); an **overflow** tier that isn't
available is logged and skipped, so local capacity still comes up if the cloud tier is misconfigured.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import time

from blastbox.errors import is_host_resource_failure
from blastbox.host.pool import _accepts_kwarg
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from blastbox.host.pool import RuntimeAtCapacity

_log = logging.getLogger("blastbox.host.runtime.cascade")


class CascadeMisconfigured(RuntimeError):
    """No usable tier (empty ``BLASTBOX_POOL_TIERS`` or the primary tier is unavailable)."""


class CascadeExhausted(RuntimeAtCapacity):
    """Every tier is FULL or still building -- routine backpressure, nothing is broken.

    Raised only when no tier was even attempted (all skipped on capacity/not-ready).
    ``RuntimeAtCapacity`` (a ``RuntimeError``, so existing handlers are unaffected) tells the
    pool to retry next tick without counting a failure.

    NB the split below is load-bearing. This class used to cover BOTH "everything is full" and
    "every tier tried and threw", which is fine while both are merely logged -- but the moment
    the pool started treating capacity as a non-fault, that conflation silently disabled base
    repair for every cascaded deployment: an unrestorable base raised from here, the streak
    never advanced, and the tier sat at zero capacity until someone restarted the process.
    Do not re-merge these two.
    """


class CascadeInvalidateFailed(RuntimeError):
    """At least one tier's base invalidation failed. Raised AFTER every tier was attempted, so
    the pool cannot record a repair that did not happen and start a cooldown on it."""


class CascadeSpawnFailed(RuntimeError):
    """Every tier that was ATTEMPTED raised -- a real fault, deliberately NOT RuntimeAtCapacity.

    Chained from the last tier exception so the cause survives. The pool counts this toward the
    restore-failure streak, which is what eventually invalidates and rebuilds a poisoned base."""


class CascadeSlotUnknown(RuntimeError):
    """A slot was handed to the cascade that no tier owns -- a ROUTING BUG, not capacity.

    Deliberately NOT a ``RuntimeAtCapacity``: it used to reuse ``CascadeExhausted``, which
    would now quietly read as "the pool is full" and get swallowed by the capacity handler."""


@dataclass
class Tier:
    name: str
    runtime: Any          # a SlotRuntime (concrete slot type varies per backend)
    capacity: int


@dataclass
class DeferredTier:
    """A tier we could not decide about at startup, kept for re-probing (issue #79).

    NOT the same as an unavailable tier. This is "the control plane would not tell us", and the
    difference is the whole point: a confirmed-unusable tier is dropped, an undecided one is
    retried until it answers.
    """
    name: str
    capacity: int
    reason: str
    build: "Callable[[], Any]"    # () -> SlotRuntime; re-runs the availability probe
    # DECLARED budgets, captured at startup from a probe-free construction of the runtime. Every
    # budget in the system (the pool's WARMING eviction, the dispatcher's thaw and cleanup, the
    # watchdog allowance) is sized ONCE from the cascade's aggregate properties below, so a tier
    # that joins later is invisible to all of them unless it is counted from the beginning. Its
    # AVAILABILITY was undecided; its declared budgets never were.
    # The entry's DECLARED position in BLASTBOX_POOL_TIERS. Names are NOT unique -- the codebase
    # already knows this (`_tier_identity` is f"{name}#{idx}", "a UNIQUE identity per tier position,
    # not per backend name") -- so "aws-ec2:4,aws-ec2:16" has two legitimate entries. Deduping the
    # deferred list by NAME silently discarded the second one the moment its sibling was admitted.
    pos: int = -1
    readiness_timeout_s: float = 0.0
    resume_timeout_s: "float | None" = None
    #: The tier's DECLARED transport facts. Same reasoning as the timeouts above: we could not
    #: learn whether the tier is UP, but what transport it speaks is a config fact we already
    #: have. Without them the cascade's two hard uniformity invariants are computed over the
    #: ADMITTED tiers alone, so a startup throttle silently converts a configuration the docs
    #: promise to reject into one that boots -- and then loses the tier ~60s later when
    #: _transport_conflict refuses it at the late door instead.
    #: None means UNKNOWN, not "file". _declared_budgets is best-effort: a tier whose config is
    #: broken enough that even a probe-free build fails contributes nothing. Defaulting to "file"
    #: there would INVENT a mismatch against a network cascade and refuse a valid configuration at
    #: startup -- turning a transient build failure into an outage, which is worse than the gap it
    #: closes. Unknown transports are simply not counted.
    dispatch_style: "str | None" = None
    ssl_context: "Any | None" = None
    cli_timeout_s: "float | None" = None



def _declared_budgets(name: str, *, warm_snapshot: bool) -> dict:
    """Read a tier's DECLARED timeouts without probing whether it is reachable.

    ``require_available=False`` constructs the runtime from configuration alone -- no control-plane
    call -- which is exactly the distinction that matters for a deferred tier: we could not learn
    whether it is *up*, but what it *needs* is a config fact we already have. Without this, a
    deferred tier contributes 0.0 to every cascade budget and is silently sized out of the pool's
    warming timeout, the dispatcher's thaw and cleanup budgets and the watchdog allowance.

    Best-effort by construction: a tier whose config is broken enough that even a probe-free build
    fails simply contributes nothing, exactly as before. This runs during startup and must never be
    the thing that prevents a cascade from coming up.
    """
    # Imported here, not in the try below: the module-level name does not exist (the builder
    # imports it lazily inside build_cascade_runtime), and the first version of this helper
    # NameError'd into its own best-effort handler and silently returned nothing -- a broad
    # except that swallows a bug in the code it guards is worse than no guard.
    from blastbox.host.pool_config import select_runtime_by_name

    out: dict = {}
    try:
        rt = select_runtime_by_name(name, warm_snapshot=warm_snapshot, require_available=False)
    except Exception as exc:  # noqa: BLE001 -- unreachable tier config, never fatal at startup
        _log.debug("cascade: could not read declared budgets for deferred tier %r: %s", name, exc)
        return out
    out["dispatch_style"] = getattr(rt, "dispatch_style", "file")
    out["ssl_context"] = getattr(rt, "ssl_context", None)
    cfg = getattr(rt, "cfg", None)
    ready = getattr(rt, "readiness_timeout_s", None)
    if ready is not None:
        out["readiness_timeout_s"] = float(ready)
    for field in ("resume_timeout_s", "cli_timeout_s"):
        val = getattr(cfg, field, None) or getattr(rt, field, None)
        if val is not None:
            out[field] = float(val)
    return out


def _is_undecided_availability(exc: BaseException) -> bool:
    """True when a tier's availability probe failed to REACH a verdict, rather than returning one.

    Matched by type name and walked through the cause chain, the same shape ``_is_unknown_not_dead``
    uses in vm_dispatch: the AWS runtime raises AwsThrottled/AwsProbeTimeout at the point of
    failure, and the factory wraps errors on the way out. Name-based so this module keeps no import
    dependency on the cloud runtime (which is optional and may not be installed).
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if any(c.__name__ in ("AwsNoVerdict", "AwsThrottled", "AwsProbeTimeout")
               for c in type(cur).__mro__):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _takes_budget(fn: Any) -> bool:
    """Whether ``fn`` accepts the optional budget_s kwarg. Introspection only — deliberately
    separate from the call site so a failure INSIDE the call can never be mistaken for one here."""
    try:
        return "budget_s" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


class CascadingRuntime:
    """SlotRuntime that routes each spawn to the first non-full tier, in declared order.

    Slot ownership is tracked by ``slot_id`` (every backend's slot has one) rather than by mutating
    the heterogeneous slot objects, so ``is_ready`` / ``is_alive`` / ``reap`` delegate to the right
    tier. No ``recycle`` -> WarmPool treats each slot as one-job-then-reap."""

    kind = "cascade"

    @property
    def dispatch_style(self) -> str:
        """The common dispatch style of the tiers. A job can't use two transports, so a cascade that
        mixes network-endpoint (aws/static) and file-handshake (fc/gvisor) tiers is a misconfig."""
        # DEFERRED TIERS COUNT. They are declared in BLASTBOX_POOL_TIERS and will be admitted the
        # moment the control plane answers, so a mismatch is a misconfiguration NOW -- the whole
        # point of this fail-fast. Computing over the admitted tiers alone meant a merely THROTTLED
        # tier let the dispatcher boot on a config that is documented to be refused.
        styles = {getattr(t.runtime, "dispatch_style", "file") for t in self.tiers}
        styles |= {d.dispatch_style for d in self._deferred if d.dispatch_style is not None}
        if len(styles) > 1:
            raise CascadeMisconfigured(
                f"cascade tiers mix dispatch styles {sorted(styles)} -- all must be the same "
                "(all network-endpoint aws/static, or all file-handshake fc/gvisor)"
            )
        return next(iter(styles), "file")

    @property
    def ssl_context(self) -> Any:
        """The client (m)TLS context for the network tiers. Worker-mTLS tiers (static/ec2) carry a
        private-CA context; Lambda uses AWS PUBLIC TLS (no context). Those can't share one transport
        context, so a cascade mixing them is a misconfig (fail-fast, like dispatch_style)."""
        ctxs = [getattr(t.runtime, "ssl_context", None) for t in self.tiers
                if getattr(t.runtime, "dispatch_style", "file") == "network"]
        # ...including the tiers we have not admitted yet; see dispatch_style.
        ctxs += [d.ssl_context for d in self._deferred if d.dispatch_style == "network"]
        # (a deferred tier whose transport we could not read is absent from both lists above)
        has_ctx = [c is not None for c in ctxs]
        if any(has_ctx) and not all(has_ctx):
            raise CascadeMisconfigured(
                "cascade mixes worker-mTLS tiers (static/ec2, private CA) with public-TLS tiers "
                "(aws-lambda-microvm) -- one transport context can't verify both; use separate pools"
            )
        return next((c for c in ctxs if c is not None), None)

    @property
    def readiness_timeout_s(self) -> float:
        """The MAX readiness budget across tiers, so the warm pool's warming timeout covers the slowest
        tier (e.g. an aws-ec2 overflow tier that boots slower than a local one)."""
        vals = [float(getattr(t.runtime, "readiness_timeout_s", 0.0)) for t in self.tiers]
        vals += [d.readiness_timeout_s for d in self._deferred]      # see DeferredTier
        return max(vals, default=0.0)

    @property
    def resume_timeout_s(self) -> float | None:
        """The MAX in-claim resume budget across wrapped tiers (a snapstart/hibernate seam carries one on
        its cfg), or None if no tier resumes on claim. A cascade has no single cfg, so the dispatcher
        factory reads this to still warn when a tier's resume budget outlasts the per-job budget."""
        vals = [
            float(rt) for t in self.tiers
            if (rt := getattr(getattr(t.runtime, "cfg", None), "resume_timeout_s", None)
                or getattr(t.runtime, "resume_timeout_s", None)) is not None
        ]
        vals += [d.resume_timeout_s for d in self._deferred if d.resume_timeout_s is not None]
        return max(vals) if vals else None

    @property
    def cli_timeout_s(self) -> float | None:
        """The MAX per-CLI-call timeout across wrapped tiers (an AWS tier's synchronous terminate on
        release runs up to this), or None if no tier carries one. A cascade has no single cfg, so the
        dispatcher factory reads this to budget the post-job cleanup terminate in the watchdog -- exactly
        as it reads resume_timeout_s -- else a cascaded AWS job that used most of its budget is watchdog-
        killed during the post-success terminate."""
        vals = [
            float(ct) for t in self.tiers
            if (ct := getattr(getattr(t.runtime, "cfg", None), "cli_timeout_s", None)
                or getattr(t.runtime, "cli_timeout_s", None)) is not None
        ]
        vals += [d.cli_timeout_s for d in self._deferred if d.cli_timeout_s is not None]
        return max(vals) if vals else None

    def __init__(self, tiers: list[Tier], *, tier_rebuild_after: int | None = None,
                 deferred: "list[DeferredTier] | None" = None,
                 admit_retry_s: float = 60.0,
                 clock: "Callable[[], float]" = time.monotonic) -> None:
        if not tiers:
            raise CascadeMisconfigured("cascade needs at least one tier")
        self.tiers = tiers
        # Tiers whose availability could not be DETERMINED at startup (a throttled STS), as opposed
        # to ones we confirmed unusable. Availability was a construction-time question with no
        # re-probe, so a brownout lasting seconds removed a tier until the process restarted --
        # pool reporting green the whole time (issue #79). These are retried instead.
        self._deferred: list[DeferredTier] = list(deferred or [])
        # Declared positions already admitted, so a concurrent pass cannot admit one twice. Keyed
        # by position rather than name because names repeat legitimately (see DeferredTier.pos).
        self._admitted_deferred: set[int] = set()
        self._admit_retry_s = float(admit_retry_s)
        self._clock = clock
        self._last_admit_attempt: float | None = None
        #: True while an admission probe is running. The time gate alone cannot exclude a
        #: concurrent caller, because the probe can outrun its own window (see _admit_deferred).
        self._admit_inflight = False
        #: The admission probe runs on its OWN thread. It is `d.build()` -- an STS round trip
        #: plus a service probe, each able to burn cli_timeout_s -- and spawn() reaches it from
        #: the pool's SINGLE tick thread, the one that also drives promotion, health checks,
        #: reaping and replacement spawning. Probing there froze all of them for as long as a
        #: browning-out control plane took to answer, repeatedly, during exactly the overflow
        #: brownout the deferral machine exists to survive.
        #:
        #: Shutdown discipline is deliberate and copies the pool's reapers, because that same
        #: class of bug arrived there seven times: never START one once closing, and JOIN it.
        self._admit_thread: "threading.Thread | None" = None
        self._admit_closing = False
        #: Tiers admitted whose post-admission orphan sweep was SKIPPED because shutdown
        #: landed mid-publish. Without this the skip was permanent: the tier stays
        #: appended and leaves _deferred, so reopen() has neither an entry to retry nor
        #: any record that the sweep is still owed -- and the CLI's one-shot startup
        #: sweep already ran before the tier existed. With BLASTBOX_EC2_ORPHAN_MAX_AGE_S
        #: on, a predecessor's parked instances would accrue cost indefinitely across the
        #: stop/start lifecycle this runtime now supports.
        self._sweep_owed: list = []
        # Consecutive per-tier spawn failures before that tier's base is invalidated. 0 disables
        # per-tier repair (the tier then stays broken until something else notices, which behind
        # a working fallback is "never").
        # An EXPLICIT value is the operator's (or the caller's) decision and is never retuned by
        # the pool's derived policy -- the same rule the pool applies to its own explicit
        # snapshot_rebuild_after. Only a derived default follows the live warm target.
        self.tier_rebuild_after_explicit = tier_rebuild_after is not None
        self.tier_rebuild_after = 4 if tier_rebuild_after is None else max(0, int(tier_rebuild_after))
        self._counts = [0] * len(tiers)          # live slots per tier
        self._owner: dict[str, int] = {}          # slot_id -> tier index
        # Tiers blamed for a JOB failure since the last repair. Separate from _recently_guilty,
        # which carries SPAWN guilt: mixing them let a stale spawn failure narrow a job repair to
        # the wrong tier. Recorded at blame time because _owner is gone by repair time -- a dirty
        # release reaps the slot, so an episode spanning four slots has three of them already
        # unmapped when the fourth crosses the threshold (upstream, PR #82).
        self._job_guilty: set[int] = set()
        # Tier names repaired on the SPAWN path (invisible to the pool, because a healthy fallback
        # absorbs the spawn) and not yet reported to it, so it can retire those slots.
        self._repaired_unreported: set[str] = set()
        # Tiers repaired LOCALLY since the last pool-driven repair. Distinguishes "no guilty tier
        # because this episode was already handled" from "no guilty tier because we have no
        # evidence" -- the first must repair NOTHING, the second must fall back to every tier.
        # Collapsing them re-invalidated a just-repaired tier, or destroyed healthy siblings.
        self._repaired_this_episode: set[int] = set()
        self._lock = threading.Lock()
        # Consecutive spawn failures PER TIER. The pool's own streak cannot see these: a tier
        # whose base is poisoned raises here, the cascade falls through to a healthy overflow
        # tier, and spawn() RETURNS a slot -- so the pool records a success and resets its
        # streak. The broken tier is then never repaired and the deployment silently runs
        # permanently on the lower-priority tier, at its cost/performance, with nothing above
        # a per-attempt warning to say so (upstream, PR #82).
        self._tier_failures = [0] * len(tiers)
        # Tiers whose streak was reset BY A REPAIR, not by a success. They stay attributable for
        # the pool's own (slightly later) global repair decision; a successful spawn clears them.
        self._recently_guilty: set[int] = set()

    def _admit_deferred(self) -> int:
        """Re-probe tiers whose availability was UNDECIDED at startup and admit the ones that answer.

        APPEND-ONLY, deliberately. ``_tier_identity`` is ``f"{name}#{idx}"``, so inserting a tier at
        its declared position would renumber every tier after it -- and live slots carry those
        identities in the pool's base-generation map. A recovering tier joining at the end of the
        order is a small priority loss; renumbering under running slots is a correctness bug.

        Rate-limited: the probe is an STS round trip, and spawn() is on the pool's tick thread.
        """
        with self._lock:
            if not self._deferred:
                return 0
            if self._admit_inflight:
                # An IN-FLIGHT probe excludes a second one; the stamp cannot. A time gate bounds
                # when a probe may START, and this probe is two aws-cli calls that can each burn
                # the full cli_timeout_s -- the completion re-stamp below exists precisely because
                # they outrun _admit_retry_s. Once they do, the window reopens while the first
                # caller is still inside d.build(), and the next tick probes the same tier again:
                # duplicate round trips on the pool's sole maintenance thread, and the loser's
                # freshly built runtime is dropped on the floor by the _admitted_deferred re-check
                # with nothing to close it. The old comment here claimed this exclusion; only the
                # flag actually provides it.
                return 0
            now = self._clock()
            if self._last_admit_attempt is not None and \
                    (now - self._last_admit_attempt) < self._admit_retry_s:
                return 0
            self._last_admit_attempt = now
            self._admit_inflight = True
            pending = list(self._deferred)

        try:
            return self._admit_probe(pending)
        finally:
            with self._lock:
                self._admit_inflight = False

    def _admit_deferred_async(self) -> None:
        """Start the admission probe OFF the caller's thread and return immediately.

        spawn() reaches admission from the pool's tick thread, so probing there stalls the entire
        pool for as long as the control plane takes to answer. Nothing is admitted by the time this
        returns, so the caller's spawn still fails -- but the pool retries on its next tick (~0.1s)
        and picks the tier up then, which is a far cheaper way to wait than holding the thread.

        _admit_deferred() remains the SYNCHRONOUS primitive for callers that want to block.
        """
        with self._lock:
            if self._admit_closing or self._admit_inflight:
                return
            if not self._deferred and not self._sweep_owed:
                return
            if self._admit_thread is not None and self._admit_thread.is_alive():
                return
            now = self._clock()
            if self._last_admit_attempt is not None and \
                    (now - self._last_admit_attempt) < self._admit_retry_s:
                return
            self._last_admit_attempt = now
            self._admit_inflight = True
            pending = list(self._deferred)
            t = threading.Thread(target=self._admit_probe_bg, args=(pending,),
                                 name="blastbox-cascade-admit", daemon=True)
            self._admit_thread = t
        try:
            t.start()
        except Exception:
            # The host could not give us a thread (RuntimeError: can't start new thread -- a
            # temporary process/thread-allowance exhaustion). Roll the flags BACK: they are only
            # cleared in _admit_probe_bg's finally, which never runs if the worker never started,
            # so every later call would return at the in-flight guard and the overflow tier could
            # never recover even once host resources came back. Setting state before the operation
            # that can fail it needs an undo on the failing path -- the same obligation the close
            # latch needed a reopen() for.
            with self._lock:
                self._admit_inflight = False
                self._admit_thread = None
            _log.warning("cascade: could not start the admission probe thread", exc_info=True)

    def poll(self) -> None:
        """The pool's periodic beat. Optional hook, called from WarmPool.tick().

        spawn() was the ONLY caller of the admission probe, and _spawn_to_deficit does not call
        spawn() at all while the primary already satisfies the warm target -- so on an idle-but-
        healthy deployment the probe never ran: the advertised ~60s re-probe cadence was inert and
        a deferred tier's post-admission orphan sweep never happened. A cadence needs a clock, not
        a demand signal.

        Also settles any sweep skipped because shutdown landed mid-publish, which is otherwise
        owed to nobody: the tier is already appended and gone from _deferred, so reopen() has
        nothing to retry it from.
        """
        self._admit_deferred_async()

    def _run_owed_sweeps(self) -> None:
        """Settle sweeps skipped because shutdown landed mid-publish. BACKGROUND ONLY.

        An EC2 sweep is an uncached describe plus potentially several serial terminates, each able
        to burn the full CLI timeout. Running them from poll() -- which the pool calls on its sole
        tick thread -- blocked promotion, health checks, reaping and replacement spawning for the
        duration, under a comment claiming it never blocks the tick. It was the same mistake the
        admission probe itself was moved off that thread to fix, made in the fix for it.
        """
        with self._lock:
            if self._admit_closing:
                return
            owed, self._sweep_owed = self._sweep_owed, []
        for i, rt in enumerate(owed):
            # Recheck the latch between entries, not just once before the drain. A sweep is an
            # uncached describe plus serial terminates, so a full drain can outlive the close()
            # that arrives mid-loop -- and because the drain already emptied the ledger, every
            # entry not yet reached would be silently forgotten rather than settled on reopen().
            # Hand the untouched remainder back so it stays owed, exactly like _admit_probe's
            # `still` list does for unprocessed tiers.
            with self._lock:
                if self._admit_closing:
                    self._sweep_owed.extend(owed[i:])
                    return
            fn = getattr(rt, "sweep_orphans", None)
            if not callable(fn):
                continue
            try:
                fn()
            except Exception:  # noqa: BLE001 -- best-effort
                # Requeue: a retry that fails is still owed. Dropping it here would make the
                # ledger a one-shot too, which is the problem it exists to solve.
                with self._lock:
                    self._sweep_owed.append(rt)
                _log.warning("cascade: deferred orphan sweep failed -- still owed", exc_info=True)

    def _admit_probe_bg(self, pending: "list[DeferredTier]") -> None:
        try:
            self._run_owed_sweeps()
            # RECHECK between the phases. The sweeps above are control-plane calls that can outlast
            # close()'s join deadline, so this thread can resume here after stop() has returned --
            # and _admit_probe's first action is d.build(), an unchecked STS + service probe. Its
            # own closing check happens only AFTER that build completes, so shutdown landing during
            # the sweep phase still bought fresh control-plane calls during teardown.
            with self._lock:
                if self._admit_closing:
                    return
            self._admit_probe(pending)
        except Exception:  # noqa: BLE001 -- must not die silently on a background thread
            _log.warning("cascade: deferred admission probe failed", exc_info=True)
        finally:
            with self._lock:
                self._admit_inflight = False

    def reopen(self) -> None:
        """Undo close(). The pool calls this from start(), symmetric with close() from stop().

        close() latches _admit_closing so no new probe begins during shutdown. Without a way back,
        the latch was PERMANENT: a WarmPool that is stopped and started again -- which start() fully
        supports, it only clears its own stop event -- could never admit its configured overflow
        tiers again until the whole runtime object was reconstructed.
        """
        with self._lock:
            self._admit_closing = False

    def close(self, *, timeout_s: "float | None" = None) -> None:
        """Stop starting admission probes and join one already in flight.

        Optional lifecycle hook, resolved by getattr like every other optional seam on this
        runtime. Without a join the probe is a daemon making control-plane calls while the process
        tears down -- precisely the shape that made the pool's reaper threads a recurring bug.
        """
        with self._lock:
            self._admit_closing = True
            t = self._admit_thread
        if t is not None and t.is_alive():
            # The POOL's remaining shutdown allowance when it gives us one. stop() promises a single
            # budget for the whole shutdown, and a join with its own default (60s) broke that.
            _budget = self._admit_retry_s or 5.0 if timeout_s is None else max(0.0, timeout_s)
            t.join(timeout=_budget)
            if t.is_alive():
                _log.warning("cascade: admission probe still running at close -- proceeding")

    def _admit_probe(self, pending: "list[DeferredTier]") -> int:
        """The probe half of _admit_deferred, which owns the in-flight flag and the gate."""
        admitted_count = 0
        still: list[DeferredTier] = []
        for _i, d in enumerate(pending):
            with self._lock:
                if self._admit_closing:
                    # Checked BEFORE the build, not after it. The post-build check cannot stop a
                    # probe that is already in flight, and each entry is a fresh STS + service
                    # round trip -- so a multi-entry pass kept buying control-plane calls during
                    # teardown, one per remaining tier.
                    still.extend(pending[_i:])
                    break
            try:
                rt = d.build()
            except Exception as exc:  # noqa: BLE001 -- classified immediately below
                # The narrow startup rule has to survive deferral. Re-queueing on ANY failure
                # meant a tier throttled at startup (undecided, rightly deferred) whose creds were
                # later revoked (definitive) got re-probed every admit interval forever -- two
                # aws-cli round trips a time, on the pool's tick thread. That contradicts the
                # startup path, where "missing credentials is a VERDICT" and the tier is dropped.
                if _is_undecided_availability(exc):
                    _log.debug("cascade: deferred tier %r still undecided: %s", d.name, exc)
                    still.append(d)
                else:
                    _log.warning("cascade: deferred tier %r is confirmed unusable, dropping: %s",
                                 d.name, exc)
                continue
            with self._lock:
                # Re-check: a concurrent _admit_deferred may have admitted it already. Keyed by the
                # DECLARED POSITION, not the name: a repeated backend ("aws-ec2:4,aws-ec2:16") has
                # two legitimate entries, and matching on name dropped the second as soon as the
                # first was admitted -- silently losing capacity the operator asked for.
                if d.pos in self._admitted_deferred:
                    continue
                # REVALIDATE THE TRANSPORT. The startup path refuses a cascade that mixes dispatch
                # styles or TLS postures; this is the only other door in, so it must refuse too.
                # Not by RAISING: this runs inside spawn() on the pool's sole maintenance thread,
                # where an exception aborts that spawn and every tick behind it -- an unusable tier
                # must not take down a healthy pool. Drop it loudly. Fail-closed for the policy gate
                # too: reachable_tiers already counted this name at startup, so removing it only
                # ever SHRINKS what the dispatcher can reach.
                conflict = self._transport_conflict(rt)
                if conflict is not None:
                    _log.error("cascade: deferred tier %r became available but cannot be admitted: "
                               "%s -- dropping it. Run it in a separate pool.", d.name, conflict)
                    continue
                if self._admit_closing:
                    # stop() exhausted its deadline while d.build() was still blocked, so close()
                    # latched and RETURNED without us. Publishing now mutates a cascade the pool
                    # has finished with, and the orphan sweep below would issue describe/terminate
                    # calls during teardown. Discard the runtime we just built instead -- closing
                    # it if it knows how -- rather than handing it to a pool that has stopped.
                    #
                    # KEEP IT DEFERRED, and stop the pass. `continue` dropped d from `still`, and
                    # the assignment at the end of this method rebuilds _deferred from `still`
                    # alone -- so the tier was permanently DELETED, and reopen() cannot recover an
                    # entry that no longer exists: a restarted pool silently lost its configured
                    # overflow capacity. Breaking also stops us starting the remaining builds,
                    # which are control-plane calls we already know we will discard.
                    _log.info("cascade: discarding tier %r built during shutdown", d.name)
                    _c = getattr(rt, "close", None)
                    if callable(_c):
                        with contextlib.suppress(Exception):
                            _c()
                    still.append(d)
                    still.extend(pending[_i + 1:])
                    break
                self.tiers.append(Tier(name=d.name, runtime=rt, capacity=d.capacity))
                self._admitted_deferred.add(d.pos)
                admitted_count += 1
                self._counts.append(0)
                self._tier_failures.append(0)
            _log.info("cascade: deferred tier %r became available -- admitted at position %d "
                      "(was undecided at startup: %s)", d.name, len(self.tiers) - 1, d.reason)
            # ...and sweep it ONCE, here. The CLI's sweep is one-shot at dispatcher start and runs
            # before this tier exists in self.tiers, so forwarding to the ADMITTED tiers reclaims
            # nothing for a tier that was deferred through a brownout and admitted afterwards -- it
            # would stay unreclaimed for the life of the process, which is precisely the recovered
            # -brownout path this deferral machine exists to serve. Admission is the first moment
            # the tier exists, so it is the startup sweep's real equivalent for it.
            #
            # OUTSIDE the lock and best-effort: this is a describe + terminate round trip, and it
            # must neither hold the cascade nor fail an admission that has already succeeded.
            # sweep_orphans is itself opt-in (a no-op unless orphan_max_age_s > 0), so this costs
            # nothing at all when the knob is off. Once per tier, because admission happens once.
            # ...and recheck the latch HERE too. The check above happens under the lock before
            # the append; this sweep runs after it and OUTSIDE the lock, so shutdown landing in
            # that window still let a probe issue describe/terminate calls after stop() had
            # exhausted its deadline and proceeded. A latch has to be read at the point of use,
            # not only at the point of decision.
            with self._lock:
                _closing = self._admit_closing
            if _closing:
                _log.info("cascade: deferring the post-admission sweep for %r -- shutting down",
                          d.name)
                with self._lock:
                    self._sweep_owed.append(rt)
                continue
            _sweep = getattr(rt, "sweep_orphans", None)
            if callable(_sweep):
                try:
                    _sweep()
                except Exception:  # noqa: BLE001 -- a sweep hiccup must not unwind an admission
                    # ...but it must not DISCARD the sweep either. The tier has already left
                    # _deferred by now, so nothing else remembers this is owed -- and both sweep
                    # callers are one-shot, so logging alone forfeits reclamation until the next
                    # process restart. The blank-inventory AwsNoVerdict added a fresh way to reach
                    # this handler, which is what made the gap reachable rather than theoretical.
                    with self._lock:
                        self._sweep_owed.append(rt)
                    _log.warning("cascade: orphan sweep failed on newly admitted tier %r -- kept "
                                 "owed for a later beat", d.name, exc_info=True)
        with self._lock:
            # Re-stamp from COMPLETION, not from the start. The probe is two aws-cli calls that can
            # each burn the full cli_timeout_s during the very outage that caused the deferral, so
            # stamping at the start meant a probe longer than _admit_retry_s was already eligible
            # by the time it returned: the next tick launched another one immediately and the
            # pool's sole maintenance thread never got back to promotion, health checks or local
            # spawning. Rate-limiting a call by when it STARTED throttles nothing once the call
            # outruns its own window.
            self._last_admit_attempt = self._clock()
            # Keep only entries still undecided AND not admitted by a racing caller.
            self._deferred = [x for x in still if x.pos not in self._admitted_deferred]
        return admitted_count

    def sweep_orphans(self, **kw: Any) -> list:
        """Forward the one-shot startup reclamation to every tier that provides one.

        The CLI resolves this with ``getattr(pool.runtime, "sweep_orphans", None)``, and whenever
        BLASTBOX_POOL_TIERS is set -- the configuration the guide's own examples use -- that runtime
        is THIS cascade, which had neither the attribute nor a __getattr__. So an operator who
        enabled BLASTBOX_EC2_ORPHAN_MAX_AGE_S got the documented "the dispatcher runs
        sweep_orphans()" only on a single-runtime deployment; in a cascade the getattr returned None
        and the sweep silently never ran, leaving a crashed predecessor's parked instances accruing
        encrypted-root-EBS cost indefinitely with the setting apparently on.

        Best-effort, matching the CLI's own guard: one tier failing must not stop the others, and a
        sweep hiccup must never block dispatch.
        """
        killed: list = []
        for tier in self.tiers:
            fn = getattr(tier.runtime, "sweep_orphans", None)
            if not callable(fn):
                continue
            try:
                got = fn(**kw)
            except Exception:  # noqa: BLE001 -- a sweep hiccup must not block startup
                _log.warning("cascade: orphan sweep failed on tier %r", tier.name, exc_info=True)
                continue
            if got:
                killed.extend(got)
        return killed

    # -- SlotRuntime protocol ----------------------------------------------
    def spawn(self) -> Any:
        """Spawn on the first tier that can take it, admitting a recovered tier only if none can.

        _admit_deferred used to run FIRST, on every spawn. It is rate-limited, but the probe itself
        is a synchronous availability check that can burn full cloud CLI timeouts -- and spawn()
        runs on the pool's sole maintenance thread. So a deferred AWS tier that stays unreachable
        delayed every spawn from perfectly healthy local tiers, for the duration of the outage.
        The deferred tier is the OVERFLOW; paying for it before trying the primary inverts the
        cascade's whole ordering. Now it is only probed once the admitted tiers cannot serve, which
        is exactly when a new one would help.
        """
        # Probe FIRST, on every spawn, and do not wait for the primary to be exhausted. The
        # laziness this replaces was justified by the probe being a SYNCHRONOUS cloud call that
        # "must never delay a spawn a healthy PRIMARY can serve" -- and it is not synchronous any
        # more. Keeping the trigger behind exhaustion meant a pool whose primary keeps satisfying
        # its warm target never probed at all: the deferred tier stayed deferred for the life of
        # the process, its documented ~60s re-probe cadence never ran, and the post-admission
        # orphan sweep never happened, so a predecessor's parked instances accrued cost forever.
        # It is rate-limited and off-thread; calling it here costs nothing.
        self._admit_deferred_async()
        return self._spawn_from_admitted()

    def _spawn_from_admitted(self, start: int = 0) -> Any:
        last_exc: Exception | None = None
        for i, tier in enumerate(self.tiers):
            if i < start:
                continue
            with self._lock:
                if self._counts[i] >= tier.capacity:
                    continue
            # SKIP a tier still building its base snapshot (prepare() False) -- don't reserve/spawn on it
            # (would block the tick thread in spawn().build()); a ready tier later in the order can still
            # be filled. Its build was already kicked by prepare() and it becomes spawnable once ready.
            p = getattr(tier.runtime, "prepare", None)
            if callable(p) and not p():
                continue
            with self._lock:
                if self._counts[i] >= tier.capacity:   # re-check under the lock (raced a concurrent spawn)
                    continue
                self._counts[i] += 1          # reserve before the (slow) spawn
            try:
                slot = tier.runtime.spawn()
            except RuntimeAtCapacity as exc:
                # This tier is FULL, not broken (a static fleet inside dirty_cooldown_s, a nested
                # cascade at capacity). Counting it as a tier failure would both advance the
                # per-tier rebuild streak and, once every tier is exhausted, promote the whole
                # spawn to CascadeSpawnFailed -- so routine backpressure would invalidate healthy
                # bases. Try the next tier and leave last_exc alone so the final raise stays a
                # capacity type (upstream, PR #82).
                with self._lock:
                    self._counts[i] -= 1
                _log.debug("cascade: tier %r at capacity, trying next: %s", tier.name, exc)
                continue
            except Exception as exc:  # noqa: BLE001 -- try the next tier, don't fail the whole spawn
                if is_host_resource_failure(exc):
                    # THIS HOST is out of space/fds/inodes, or its filesystem went read-only:
                    # a snapshot spawn creates the slot workdir and copies a per-slot disk, so
                    # ENOSPC/EROFS/EMFILE/EIO here says nothing whatever about the tier's
                    # artifact. Counting it invalidated a perfectly good snapshot during a host
                    # storage incident -- and because a healthy fallback tier absorbs the spawn,
                    # the pool sees only successes and the misattribution stays invisible until
                    # the primary tier has destroyed its usable base. Try the next tier without
                    # marking this one (upstream, PR #82).
                    with self._lock:
                        self._counts[i] -= 1
                    last_exc = exc
                    _log.warning("cascade: tier %r spawn hit a HOST resource failure (not "
                                 "counted against the tier), trying next: %s", tier.name, exc)
                    continue
                with self._lock:
                    self._counts[i] -= 1
                    self._tier_failures[i] += 1
                    streak = self._tier_failures[i]
                last_exc = exc
                _log.warning("cascade: tier %r spawn failed (streak=%d), trying next: %s",
                             tier.name, streak, exc)
                self._maybe_repair_tier(i, tier, streak)
                continue
            with self._lock:
                self._owner[slot.slot_id] = i
                # Only THIS tier's streak clears: a success here says nothing about the tiers
                # above it that were skipped or that just failed.
                self._tier_failures[i] = 0
                self._recently_guilty.discard(i)   # a real success clears the mark
            _log.info("cascade: spawned on tier %r (%d/%d) slot=%s",
                      tier.name, self._counts[i], tier.capacity, slot.slot_id)
            return slot
        if last_exc is not None:
            # At least one tier actually ATTEMPTED a spawn and threw: that is evidence something
            # is broken (a corrupt base restores nowhere), not that we are busy. Must not be a
            # capacity type or the pool will never repair the base.
            raise CascadeSpawnFailed(
                f"all attempted cascade tiers failed to spawn; last error: {last_exc}"
            ) from last_exc
        raise CascadeExhausted(
            f"all {len(self.tiers)} cascade tiers full/unavailable "
            f"(capacities {[t.capacity for t in self.tiers]})"
        ) from last_exc

    def _transport_conflict(self, rt: Any) -> "str | None":
        """Why ``rt`` cannot join the admitted tiers, or None if it can. Call with ``_lock`` held.

        ``dispatch_style`` and ``ssl_context`` are the cascade's two uniformity invariants, and both
        are consumed exactly ONCE, at startup: the CLI picks the file vs network dispatcher from the
        style, and the VM dispatcher captures the context when it is built. A tier admitted later
        can therefore neither change that choice nor be raised about -- it is simply handed jobs
        over a transport it does not speak. So the check the startup path makes fatal has to be made
        here too, at the only other door into the cascade.
        """
        style = getattr(rt, "dispatch_style", "file")
        admitted = {getattr(t.runtime, "dispatch_style", "file") for t in self.tiers}
        if admitted and style not in admitted:
            return (f"dispatch style {style!r} does not match the admitted tiers {sorted(admitted)}"
                    " -- one job cannot use two transports")
        if style == "network":
            ctxs = [getattr(t.runtime, "ssl_context", None) for t in self.tiers
                    if getattr(t.runtime, "dispatch_style", "file") == "network"]
            if ctxs and (getattr(rt, "ssl_context", None) is not None) != any(
                    c is not None for c in ctxs):
                return ("its worker-TLS posture differs from the admitted network tiers "
                        "(private-CA mTLS vs AWS public TLS) -- the dispatcher holds ONE client "
                        "context and it cannot verify both")
        return None

    def _tier_of(self, slot: Any) -> Tier | None:
        with self._lock:
            i = self._owner.get(slot.slot_id)
        return self.tiers[i] if i is not None else None

    def is_ready(self, slot: Any) -> "bool | None":
        # Delegate the owning tier's TRI-STATE verdict through unchanged, including None. The old
        # `tier is not None and ...` form happened to propagate None correctly, but it was typed
        # bool and read as a boolean guard -- one tidy-up away from collapsing a brownout into
        # "not ready" for every cloud slot behind the cascade (issue #79).
        tier = self._tier_of(slot)
        if tier is None:
            return False
        return tier.runtime.is_ready(slot)

    def is_alive(self, slot: Any) -> "bool | None":
        tier = self._tier_of(slot)
        if tier is None:
            return False
        return tier.runtime.is_alive(slot)   # may be None = UNKNOWN; the pool owns that policy

    def is_alive_for_claim(self, slot: Any, *, budget_s: float | None = None) -> "bool | None":
        """Claim-time FRESH liveness, delegated to the owning tier's cache-bypassing hook when it has one
        (AWS tiers) -- else the tier's is_alive (file/libvirt, already fresh). Without this the pool's
        getattr(runtime, "is_alive_for_claim") finds nothing on the cascade and falls back to the cascade's
        CACHED is_alive, so a cascade-wrapped AWS slot terminated between tick and claim would be handed out."""
        tier = self._tier_of(slot)
        if tier is None:
            return False
        fresh = getattr(tier.runtime, "is_alive_for_claim", None)
        if not callable(fresh):
            return tier.runtime.is_alive(slot)
        # Forward the caller's remaining claim budget to the owning tier when it takes one. Without
        # this a cascade-wrapped AWS tier -- the common production shape -- never sees the pool's
        # deadline and probes at its own full bound (issue #77 round 2).
        # Same defect as resume(): wrapping the call made a probe error re-probe unbudgeted.
        if budget_s is not None and _takes_budget(fresh):
            return fresh(slot, budget_s=budget_s)
        return fresh(slot)

    def _maybe_repair_tier(self, index: int, tier: "Tier", streak: int) -> None:
        """Invalidate ONE tier's base after it fails to spawn repeatedly, independent of whether
        a later tier went on to satisfy the request.

        Without this, tier-level breakage is invisible to the pool by construction: fallback is
        exactly what hides it. Never raises -- a failed repair must not break the spawn path.
        """
        if self.tier_rebuild_after <= 0 or streak < self.tier_rebuild_after:
            return
        invalidate = getattr(tier.runtime, "invalidate_base", None)
        if not callable(invalidate):
            return
        with self._lock:
            self._tier_failures[index] = 0   # give the rebuild a full window before trying again
            # No _recently_guilty marker here any more, and deliberately so. It was added because
            # clearing the streak first left the pool's repair with an empty guilty set, which
            # fell back to every tier and destroyed healthy siblings. Both outcomes are now
            # decided explicitly: a SUCCESSFUL repair records _repaired_this_episode, so the pool
            # repairs nothing further; a FAILED one restores _tier_failures below, which puts the
            # tier back in the guilty set on its own. The marker had become a third copy of the
            # same fact -- and a mutation run proved nothing could tell whether it was still
            # there (upstream, PR #82).
        _log.error(
            "cascade: tier %r failed %d consecutive spawns — invalidating its base so it can be "
            "rebuilt. Fallback tiers have been absorbing this, so the pool saw only successes.",
            tier.name, streak,
        )
        try:
            invalidate()
        except Exception as exc:  # noqa: BLE001
            # RESTORE the streak. It was cleared to give a successful rebuild a full window, but
            # no rebuild happened -- and behind a working fallback tier this tier may be attempted
            # rarely or not at all, so demanding another full threshold can mean never retrying.
            # Same rule the pool's own repair now follows for its episode; this sibling did not
            # inherit it (upstream, PR #82).
            with self._lock:
                self._tier_failures[index] = max(self._tier_failures[index], streak)
            _log.warning("cascade: tier %r base invalidation failed: %s", tier.name, exc)
        else:
            # PUBLISH it. This repair happens on the SPAWN path, which the pool never sees -- a
            # healthy fallback absorbs the spawn, so the pool records only successes. Without
            # telling it, slots from the retired artifact and slots restored from its replacement
            # carry the SAME generation stamp, so a late failure from an old slot is charged to
            # the new base and can invalidate the replacement immediately (upstream, PR #82).
            with self._lock:
                self._repaired_unreported.add(self._tier_identity(index))
                # _repaired_this_episode is what stops the pool repairing this tier AGAIN: the
                # CascadeSpawnFailed that follows drives WarmPool to the same threshold, and
                # invalidating a just-repaired snapshot tier bumps its build epoch and REJECTS
                # the replacement already being built. No _recently_guilty bookkeeping is needed
                # for that -- nothing adds the marker on this path any more (upstream, PR #82).
                self._repaired_this_episode.add(index)

    def take_repaired_tiers(self) -> "list[str]":
        """Drain the tiers repaired since the last call -- the pool advances their generations.

        Drained, not read: each repair must retire its slots exactly once.
        """
        with self._lock:
            out = sorted(self._repaired_unreported)
            self._repaired_unreported.clear()
        return out

    def clear_job_guilt(self) -> None:
        """Forget which tiers a job-failure EPISODE implicated, because it recovered.

        The set is otherwise consumed only by a successful invalidation, so a tier blamed in an
        episode that then ended in a validated clean release stayed guilty indefinitely -- and the
        next independent episode, on a different tier, invalidated BOTH: discarding a healthy
        snapshot and the fallback capacity it provides for a failure it had nothing to do with.
        The pool calls this wherever it resets the pool-wide streak on demonstrated worker
        success, which is exactly what "this episode is over" means (upstream, PR #82).
        """
        with self._lock:
            self._job_guilty.clear()

    def _tier_identity(self, idx: int) -> str:
        """A UNIQUE identity per tier position, not per backend name.

        BLASTBOX_POOL_TIERS accepts a repeated backend (``firecracker:2,firecracker:2``) and
        _parse_tiers builds two runtimes with SEPARATE snapshot bases -- but the name is the same
        for both. Keyed on the name alone, repairing either advanced the one shared generation
        entry, so live slots of the untouched sibling looked retired and their failure evidence
        was thrown away; locally reported repairs collapsed the same way (upstream, PR #82).
        """
        return f"{self.tiers[idx].name}#{idx}"

    def base_identity(self, slot: object) -> str | None:
        """Which TIER's base produced this slot -- a cascade has one per tier, not one overall."""
        with self._lock:
            idx = self._owner.get(str(getattr(slot, "slot_id", "") or ""))
        return None if idx is None else self._tier_identity(idx)

    def worker_identity(self, slot: object) -> str | None:
        """Delegate to the tier that produced this slot, TIER-QUALIFIED.

        The identity hook exists so a runtime that REUSES a physical worker across slots keeps
        its failure history. A static tier under a cascade -- the supported configuration -- lost
        that entirely: the pool asked the outer cascade, which had no hook, so each reusable box
        was keyed by its fresh per-spawn slot_id again and the burnout threshold stayed
        unreachable. Qualified by tier index because two tiers can each report "static:0" and
        they are different boxes (upstream, PR #82).
        """
        slot_id = str(getattr(slot, "slot_id", "") or "")
        with self._lock:
            idx = self._owner.get(slot_id)
        if idx is None:
            return None
        inner = getattr(self.tiers[idx].runtime, "worker_identity", None)
        if not callable(inner):
            return None                       # a disposable tier: the slot IS the worker
        try:
            got = inner(slot)
        except Exception as exc:  # noqa: BLE001 -- attribution must never break a release
            _log.warning("cascade: worker_identity failed for tier %r: %s",
                         self.tiers[idx].name, exc)
            return None
        return None if not got else f"{self._tier_identity(idx)}:{got}"

    def blame_tier_for_slot(self, slot_id: str) -> bool:
        """Attribute a post-spawn failure to the tier that produced ``slot_id``.

        A slot that spawned fine, reached IDLE and then died before its first job leaves
        _tier_failures empty -- the spawn SUCCEEDED -- so the pool's repair found no guilty tier
        and the empty-guilt fallback invalidated EVERY tier, destroying healthy siblings for
        deaths confined to one of them. The owning tier is already tracked per slot; this is the
        one caller that knows the failure happened after the spawn (PR #82).

        Returns True when the slot was attributable.
        """
        with self._lock:
            idx = self._owner.get(str(slot_id))
            if idx is None:
                return False
            self._tier_failures[idx] += 1
            self._recently_guilty.add(idx)
            self._job_guilty.add(idx)
        # NO immediate repair here. This is the JOB path, and repairing from it invalidated the
        # tier the moment its own streak hit the threshold -- before WarmPool._maybe_rebuild_base
        # could apply base_rebuild_cooldown_s, and then again through the pool-wide repair on the
        # same release. Continued job failures could therefore rebuild a tier every
        # threshold-sized batch inside the advertised cooldown. Recording the guilt is this
        # method's whole job; the pool decides WHEN, and invalidate_base() then targets exactly
        # the tiers named here. _maybe_repair_tier stays on the spawn path, which the pool cannot
        # see (upstream, PR #82).
        return True

    def spawn_guilty_identities(self) -> "list[str]":
        """Identities of the tiers a SPAWN-triggered repair would target RIGHT NOW.

        invalidate_base(reason="spawn") narrows to exactly this set, but the pool decides
        *whether* to call it at all -- and its own spawn streak is a single pool-wide integer
        with no tier attribution, so it was comparing "has ANY tier released cleanly?" against a
        repair aimed at ONE tier. A healthy sibling absorbing the load then cancelled the guilty
        tier's repair. The pool needs the same set this method selects to ask its question about
        the right base.

        An empty list means "no per-tier evidence": the caller must fall back to its pool-wide
        view rather than read an empty scope as "nothing has succeeded".
        """
        with self._lock:
            guilty = ({i for i, n in enumerate(self._tier_failures) if n > 0}
                      | self._recently_guilty)
        # _tier_identity reads only the immutable tier list, so it is safe outside the lock.
        return sorted(self._tier_identity(i) for i in guilty)

    def invalidate_base(self, *, reason: str | None = None,
                        only: "str | Iterable[str] | None" = None) -> "list[str]":
        """Forward base invalidation to every wrapped tier that supports it.

        Every tier is attempted even if an earlier one fails -- one poisoned tier must not stop
        the others being repaired -- but a failure is then PROPAGATED. Swallowing it made the
        pool record a successful rebuild and start its cooldown while the poisoned tier was
        untouched, so the next repair attempt was delayed for the whole cooldown and the tier
        kept failing (upstream, PR #82).
        """

        # Prefer the tiers that actually FAILED. The pool's global streak cannot attribute:
        # when one snapshot tier throws repeatedly while a later healthy tier is merely FULL, the
        # spawn still ends as CascadeSpawnFailed, and invalidating every wrapped base then
        # destroys the healthy tier's snapshot during ordinary saturation despite it producing no
        # failure evidence at all. With no per-tier evidence (a job-failure-driven rebuild, which
        # carries no tier attribution) fall back to every tier (upstream, PR #82).
        # Only a SPAWN-triggered repair carries tier attribution. A job-triggered one does not:
        # the failures came from whichever tier served those jobs, which the cascade cannot know.
        # Filtering it through a spawn marker meant tier A's stale guilt selected A while the
        # actual offender B kept its poisoned base -- and the pool recorded a rebuild and started
        # its cooldown regardless (upstream, PR #82).
        # NAMED SLOTS BEAT INFERENCE. A job-driven repair used to hit every tier because the
        # cascade could not know which one served the failing jobs -- and it must not be narrowed
        # by _tier_failures, whose spawn guilt is DURABLE and therefore stale here: that selected
        # tier A on an old spawn failure while the actual offender B kept its poisoned base.
        # But the caller does know. WarmPool.release() has the slot in hand, and this cascade
        # still holds its tier in _owner, so an episode that names its slots is attributed
        # exactly -- no inference, no stale state. Invalidating every tier over failures confined
        # to one discards healthy sibling snapshots and removes usable fallback capacity
        # (upstream, PR #82).
        named: set[int] = set()
        if reason != "spawn":
            # The tiers blamed during THIS episode, recorded by blame_tier_for_slot as each
            # failure happened. Resolving slot ids at repair time instead was too late: a dirty
            # release reaps its slot, so by the time the fourth failure of an A,A,B,B episode
            # crossed the threshold only that last slot was still in _owner and the repair hit B
            # alone -- leaving A's failing base active while the pool reset the episode and
            # started its cooldown (upstream, PR #82).
            with self._lock:
                named = set(self._job_guilty)
        if only:
            # NAMED TARGET WINS. The pre-guest fast path convicts exactly ONE tier -- it counted
            # distinct slots restored from that specific base -- but arrived with no way to say
            # which, so it fell back to the episode-wide guilt set. An unrelated worker fault on
            # healthy tier A followed by three pre-guest failures on B then rebuilt BOTH,
            # removing the fallback capacity that is the entire point of a cascade.
            # A SET, because a spawn repair now arrives with its targets frozen. Recomputing
            # them here from the live guilty set meant a tier that became guilty AFTER the
            # decision -- and then produced a clean release -- was invalidated by a decision that
            # never examined it, and whose staleness check therefore could not see its success.
            _wanted = {only} if isinstance(only, str) else {str(x) for x in only}
            _named = {i for i in range(len(self.tiers)) if self._tier_identity(i) in _wanted}
            if _named:
                named = _named
            else:
                _log.warning("cascade.invalidate_base target %r matches no tier; "
                             "falling back to the episode's guilt set", only)
        if named:
            targets = [t for i, t in enumerate(self.tiers) if i in named]
        elif reason == "spawn":
            with self._lock:
                guilty = ({i for i, n in enumerate(self._tier_failures) if n > 0}
                          | self._recently_guilty)
                already = set(self._repaired_this_episode)
            if guilty:
                targets = [t for i, t in enumerate(self.tiers) if i in guilty]
            elif already:
                # This episode was ALREADY discharged by the per-tier repair. Falling back to
                # every tier here destroyed healthy siblings; keeping the guilt instead
                # re-invalidated the repaired tier, which on a snapshot tier bumps the build epoch
                # and REJECTS the replacement already being built. Neither: there is nothing left
                # to do (upstream, PR #82).
                _log.info("cascade: spawn repair already satisfied by per-tier repair of %s",
                          ",".join(sorted(self._tier_identity(i) for i in already)))
                with self._lock:
                    self._repaired_this_episode.clear()
                return sorted(self._tier_identity(i) for i in already)
            else:
                targets = list(self.tiers)
        else:
            # No names and no spawn attribution: every tier is the only safe target.
            targets = list(self.tiers)

        with self._lock:
            self._recently_guilty.clear()   # consumed by this repair
            self._repaired_this_episode.clear()
            # _job_guilty is NOT cleared here. Discarding it before the outcomes are known lost
            # the naming for tiers whose invalidation then FAILED: the pool restores the consumed
            # episode after CascadeInvalidateFailed, but its retry had no guilty tiers left and
            # fell back to invalidating EVERY tier -- including the siblings this attempt had
            # just repaired successfully. Each tier's guilt is discarded below, individually,
            # when its own invalidation succeeds (upstream, PR #82).

        failures: list[str] = []
        repaired: list[str] = []
        attempted = 0
        for tier in targets:
            fn = getattr(tier.runtime, "invalidate_base", None)
            if not callable(fn):
                continue
            attempted += 1
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 -- try every tier, report at the end
                failures.append(f"{tier.name}: {exc}")
                _log.warning("cascade: tier %r base invalidation failed: %s", tier.name, exc)
            else:
                # This tier IS repaired. Clear its guilt so a retry of the partially-failed
                # repair does not invalidate it a second time: its replacement build may be in
                # flight, and each redundant invalidate bumps the build epoch and rejects it, so
                # one persistently failing tier could keep healthy siblings permanently rebuilding
                # (PR #82).
                repaired.append(self._tier_identity(self.tiers.index(tier)))
                with self._lock:
                    idx = self.tiers.index(tier)
                    self._tier_failures[idx] = 0
                    self._recently_guilty.discard(idx)
                    self._job_guilty.discard(idx)
        if failures:
            # CARRY what succeeded. Discarding `repaired` here meant the pool never advanced the
            # generation of a tier whose artifact really was replaced, so its old assigned slots
            # still looked current -- their later failures re-added that tier to _job_guilty and
            # immediately invalidated its REPLACEMENT while the retry was still chasing the
            # failed sibling (upstream, PR #82).
            partial = CascadeInvalidateFailed(
                "cascade: base invalidation failed for " + "; ".join(failures)
            )
            partial.repaired = repaired  # type: ignore[attr-defined]
            raise partial
        if attempted == 0:
            # NOTHING was repaired. When a spawn-driven repair attributes the failures to a
            # static/AWS tier that has no base to invalidate, every target is skipped and a silent
            # success made the pool reset its streak, count a rebuild and start the cooldown --
            # so the tier stayed broken AND further diagnosis was delayed by the full cooldown
            # (upstream, PR #82).
            raise CascadeInvalidateFailed(
                "cascade: no selected tier supports base invalidation "
                f"({[t.name for t in targets]}) — nothing was repaired"
            )
        # Name what was ACTUALLY repaired. The pool retires only the slots of these bases: a
        # sibling tier whose artifact this repair never touched must keep producing usable
        # failure evidence (upstream, PR #82).
        return repaired


    def reap(self, slot: Any, dirty: bool = False) -> None:
        with self._lock:
            i = self._owner.get(slot.slot_id)
        if i is None:
            return
        # reap FIRST; only drop ownership + decrement on success, so a failing inner reap keeps the
        # slot->tier mapping (a later stop()/retry can terminate it) and doesn't undercount capacity
        # while the worker is still live. Forward `dirty` to a tier reap that accepts it (static
        # quarantine); tiers whose reap ignores it (disposable) just dispose the whole worker.
        # INTROSPECTION, not except-TypeError. The bare except was meant to detect an OLD SIGNATURE
        # that does not accept `dirty`, but it cannot tell that apart from a TypeError raised by the
        # BODY of a reap that accepted the kwarg and had already issued its terminate -- so the
        # disposal ran a SECOND time against the same cloud resource, which is the one thing every
        # reap path in this file promises not to do. pool.py resolves the same question with
        # inspect.signature (_reap_takes_dirty) and _invalidate_now says why in as many words: "a
        # TypeError from inside drop() must never be mistaken for an older signature". This was the
        # one dispose path still doing it the unsafe way.
        _reap = self.tiers[i].runtime.reap
        if _accepts_kwarg(_reap, "dirty"):
            _reap(slot, dirty=dirty)
        else:
            _reap(slot)
        with self._lock:
            self._owner.pop(slot.slot_id, None)
            self._counts[i] = max(0, self._counts[i] - 1)

    def prepare(self) -> bool:
        """Delegate the async-build/readiness gate to the tiers. A snapshot tier (gvisor/fc with
        BLASTBOX_POOL_WARM_SNAPSHOT) relies on prepare() so WarmPool kicks its slow base-snapshot build
        OFF the tick thread. Kick EVERY tier's prepare (so all builds start) but report ready if ANY tier
        is ready -- so a slow overflow snapshot build doesn't starve an already-ready primary tier
        (spawn() itself skips the still-building tiers). A tier without prepare() is always ready."""
        any_ready = False
        for t in self.tiers:
            p = getattr(t.runtime, "prepare", None)
            if p is None:
                any_ready = True
            elif p():        # kicks the async build + reports readiness
                any_ready = True
        return any_ready

    def available(self) -> bool:
        return bool(self.tiers)   # built only with tiers that came up

    # -- file-handshake warm-path hooks ------------------------------------
    # An ALL-FILE cascade (e.g. gvisor:4,firecracker:4) is driven by the file Dispatcher, which reads
    # these hooks off the pool runtime (getattr) to decide how input/output move for a slot. The cascade
    # must delegate them to the slot's OWNING tier -- otherwise gVisor jobs get host paths in go.json
    # instead of /in//out and FC jobs miss the vsock path. (Network cascades never reach this path; they
    # run through VmJobDispatcher, so exposing these here is inert for them.)
    def _delegate(self, slot: Any, name: str) -> Any:
        tier = self._tier_of(slot)
        if tier is None:
            raise CascadeSlotUnknown(f"cascade: no owning tier for slot {getattr(slot, 'slot_id', slot)!r}")
        fn = getattr(tier.runtime, name, None)
        if fn is None:
            raise CascadeMisconfigured(
                f"cascade tier {tier.name!r} does not implement the warm hook {name!r} -- a file "
                "cascade needs file-handshake warm tiers (gvisor/firecracker) on every tier"
            )
        return fn

    def host_warm_control(self, slot: Any) -> Any:
        return self._delegate(slot, "host_warm_control")(slot)

    def stage_warm_input(self, slot: Any, staged_input_path: Any) -> Any:
        return self._delegate(slot, "stage_warm_input")(slot, staged_input_path)

    def materialize_warm_output(self, slot: Any) -> None:
        self._delegate(slot, "materialize_warm_output")(slot)

    def maintain_idle(self, slot: Any, *, budget_s: "float | None" = None) -> bool:
        """Delegate the OPTIONAL idle-reconciliation seam (issue #80) to the slot's OWNING tier.

        The pool resolves this hook with ``getattr(self._runtime, "maintain_idle", None)``, and in
        every documented deployment the pool holds the CASCADE, not the tier -- the same reason
        ``resume`` and ``is_alive_for_claim`` need explicit passthroughs. Without it the entire
        reconciliation was inert behind a cascade: a resume that half-succeeded left the instance
        RUNNING and billing while the pool counted a parked warm slot.

        Returns True (usable) for a tier that has no such upkeep, so a mixed or all-non-hibernate
        cascade is unaffected. An unknown slot is likewise reported usable rather than raising:
        this runs on the maintenance tick, and a False here RETIRES the slot.
        """
        tier = self._tier_of(slot)
        if tier is None:
            _log.debug("cascade: maintain_idle for unknown slot %r — treating as usable",
                       getattr(slot, "slot_id", slot))
            return True
        fn = getattr(tier.runtime, "maintain_idle", None)
        if not callable(fn):
            return True
        # Forward the pool's tick-thread budget when the tier accepts one. Introspection rather
        # than try/TypeError, for the reason reap() now states: a TypeError from INSIDE a tier's
        # maintain_idle must never be mistaken for an older signature and retried.
        if budget_s is not None and _accepts_kwarg(fn, "budget_s"):
            return fn(slot, budget_s=budget_s) is not False
        return fn(slot) is not False

    def resume(self, slot: Any, *, budget_s: float | None = None) -> None:
        """Delegate the OPTIONAL per-claim resume seam (aws-ec2-hibernate / aws-lambda-snapstart) to the
        slot's OWNING tier. Unlike the file-handshake warm hooks above, resume is optional -- a tier
        without it (file/disposable) is a NO-OP, so a mixed or all-non-resume cascade is unaffected.
        Without this delegate `_resume_on_claim` only sees CascadingRuntime (no resume) and would POST to
        a still-parked (stopped/suspended) endpoint. A resume failure propagates so the claim retires the
        slot dirty."""
        tier = self._tier_of(slot)
        if tier is None:
            raise CascadeSlotUnknown(f"cascade: no owning tier for slot {getattr(slot, 'slot_id', slot)!r}")
        fn = getattr(tier.runtime, "resume", None)
        if not callable(fn):
            return
        # Forward the dispatcher's remaining claim window when the tier accepts one. In production
        # the pool holds the CASCADE, so without this passthrough the budget stops here and a slow
        # resume can still consume the whole claim window (issue #77 round 4).
        # The try guards ONLY inspect.signature. It used to wrap the CALL too, so a TypeError or
        # ValueError raised INSIDE resume() was mistaken for an introspection failure and resume --
        # which issues resume-microvm / start-instances and clears auth_token -- was invoked a
        # SECOND time, unbudgeted (issue #77 round 6; observed [('resume', 0.5), ('resume', None)]).
        if budget_s is not None and _takes_budget(fn):
            fn(slot, budget_s=budget_s)
            return
        fn(slot)


# ---------------------------------------------------------------------------
# Build from env
# ---------------------------------------------------------------------------

def _parse_tiers(spec: str) -> list[tuple[str, int]]:
    """Parse ``static:4,aws-ec2:16`` -> [('static', 4), ('aws-ec2', 16)]."""
    out: list[tuple[str, int]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, cap = item.partition(":")
        name = name.strip()
        if not name or not cap.strip():
            raise CascadeMisconfigured(f"tier spec {item!r} must be 'backend:capacity'")
        try:
            capacity = int(cap)
        except ValueError as exc:
            raise CascadeMisconfigured(f"tier {name!r} capacity {cap!r} is not an int") from exc
        if capacity < 1:
            raise CascadeMisconfigured(f"tier {name!r} capacity must be >= 1")
        out.append((name, capacity))
    return out


def build_cascade_runtime(
    get: Callable[[str], str | None] | None = None,
    *,
    warm_snapshot: bool = False,
    tier_rebuild_after: int | None = None,
    tier_rebuild_after_explicit: bool | None = None,
) -> CascadingRuntime:
    """Build a CascadingRuntime from ``BLASTBOX_POOL_TIERS``. The primary (first) tier must be
    available -- otherwise ``CascadeMisconfigured``; overflow tiers that aren't available are skipped
    with a warning so local capacity still comes up."""
    import os

    from blastbox.host.pool_config import select_runtime_by_name

    get = get or os.environ.get
    # The advertised incident escape hatch (BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER=0 disables
    # automatic base invalidation) must disable EVERY path that can invalidate a base, not just
    # the pool's. Per-tier repair is a second, independently-triggered invalidation route, so an
    # operator who turned rebuilds off during an incident would still have had tier bases
    # destroyed under them (upstream, PR #82).
    # An explicitly RESOLVED value from the caller wins; only fall back to reading the
    # environment when nobody resolved one (direct callers, tests).
    if tier_rebuild_after is None:
        raw_rebuild = (get("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER") or "").strip()
        tier_rebuild_after = 4
        if raw_rebuild:
            try:
                tier_rebuild_after = max(0, int(raw_rebuild))
            except ValueError:
                _log.warning("cascade: invalid BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER=%r; using %d",
                             raw_rebuild, tier_rebuild_after)
    tier_rebuild_after = max(0, int(tier_rebuild_after))
    spec = get("BLASTBOX_POOL_TIERS") or ""
    parsed = _parse_tiers(spec)
    if not parsed:
        raise CascadeMisconfigured("BLASTBOX_POOL_TIERS is empty (need e.g. 'static:4,aws-ec2:16')")

    tiers: list[Tier] = []
    deferred: list[DeferredTier] = []
    for pos, (name, capacity) in enumerate(parsed):
        try:
            rt = select_runtime_by_name(name, warm_snapshot=warm_snapshot, require_available=True)
        except Exception as exc:  # noqa: BLE001
            # UNDECIDED vs UNUSABLE. A throttled sts get-caller-identity used to be indistinguishable
            # from absent credentials, so seconds of throttling at startup dropped the tier for the
            # whole process lifetime -- or, for the primary, refused to start at all (issue #79).
            undecided = _is_undecided_availability(exc)
            if pos == 0:
                if undecided:
                    # Fail closed, but say WHY: this is retryable, so a supervisor restart fixes it.
                    # Admitting a primary tier we could not verify would be the worse trade -- every
                    # spawn would route to a tier that may not exist.
                    raise CascadeMisconfigured(
                        f"primary cascade tier {name!r}: could not determine availability "
                        f"({exc}). This is a transient control-plane failure, not a "
                        "misconfiguration -- retry."
                    ) from exc
                raise CascadeMisconfigured(f"primary cascade tier {name!r} is unavailable: {exc}") from exc
            if undecided:
                _log.warning("cascade: overflow tier %r availability UNDECIDED at startup -- will "
                             "retry rather than drop it: %s", name, exc)
                declared = _declared_budgets(name, warm_snapshot=warm_snapshot)
                deferred.append(DeferredTier(
                    name=name, capacity=capacity, reason=str(exc), pos=pos,
                    build=functools.partial(select_runtime_by_name, name,
                                            warm_snapshot=warm_snapshot, require_available=True),
                    **declared,
                ))
                continue
            _log.warning("cascade: overflow tier %r unavailable at startup -- skipping: %s", name, exc)
            continue
        tiers.append(Tier(name=name, runtime=rt, capacity=capacity))

    if not tiers:
        if deferred:
            raise CascadeMisconfigured(
                "no cascade tier could be verified available; "
                f"{len(deferred)} tier(s) undecided (transient control-plane failure) -- retry"
            )
        raise CascadeMisconfigured("no cascade tier is available")
    _log.info("cascade: %s", ", ".join(f"{t.name}:{t.capacity}" for t in tiers))
    casc = CascadingRuntime(tiers, tier_rebuild_after=tier_rebuild_after, deferred=deferred)
    if tier_rebuild_after_explicit is not None:
        # The caller knows whether its number came from an operator or from a derived default;
        # only the former should be immune to retuning.
        casc.tier_rebuild_after_explicit = tier_rebuild_after_explicit
    return casc
