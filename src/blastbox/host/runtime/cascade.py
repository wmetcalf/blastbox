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

import inspect
import logging

from blastbox.errors import is_host_resource_failure
import threading
from collections.abc import Callable
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
        styles = {getattr(t.runtime, "dispatch_style", "file") for t in self.tiers}
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
        return max((float(getattr(t.runtime, "readiness_timeout_s", 0.0)) for t in self.tiers),
                   default=0.0)

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
        return max(vals) if vals else None

    def __init__(self, tiers: list[Tier], *, tier_rebuild_after: int | None = None) -> None:
        if not tiers:
            raise CascadeMisconfigured("cascade needs at least one tier")
        self.tiers = tiers
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

    # -- SlotRuntime protocol ----------------------------------------------
    def spawn(self) -> Any:
        last_exc: Exception | None = None
        for i, tier in enumerate(self.tiers):
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

    def _tier_of(self, slot: Any) -> Tier | None:
        with self._lock:
            i = self._owner.get(slot.slot_id)
        return self.tiers[i] if i is not None else None

    def is_ready(self, slot: Any) -> bool:
        tier = self._tier_of(slot)
        return tier is not None and tier.runtime.is_ready(slot)

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

    def invalidate_base(self, *, reason: str | None = None) -> "list[str]":
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
        try:
            self.tiers[i].runtime.reap(slot, dirty=dirty)
        except TypeError:
            self.tiers[i].runtime.reap(slot)
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
    for pos, (name, capacity) in enumerate(parsed):
        try:
            rt = select_runtime_by_name(name, warm_snapshot=warm_snapshot, require_available=True)
        except Exception as exc:  # noqa: BLE001
            if pos == 0:
                raise CascadeMisconfigured(f"primary cascade tier {name!r} is unavailable: {exc}") from exc
            _log.warning("cascade: overflow tier %r unavailable at startup -- skipping: %s", name, exc)
            continue
        tiers.append(Tier(name=name, runtime=rt, capacity=capacity))

    if not tiers:
        raise CascadeMisconfigured("no cascade tier is available")
    _log.info("cascade: %s", ", ".join(f"{t.name}:{t.capacity}" for t in tiers))
    casc = CascadingRuntime(tiers, tier_rebuild_after=tier_rebuild_after)
    if tier_rebuild_after_explicit is not None:
        # The caller knows whether its number came from an operator or from a derived default;
        # only the former should be immune to retuning.
        casc.tier_rebuild_after_explicit = tier_rebuild_after_explicit
    return casc
