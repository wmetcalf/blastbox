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
import inspect
import logging
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

    def __init__(self, tiers: list[Tier], *, tier_rebuild_after: int = 4) -> None:
        if not tiers:
            raise CascadeMisconfigured("cascade needs at least one tier")
        self.tiers = tiers
        # Consecutive per-tier spawn failures before that tier's base is invalidated. 0 disables
        # per-tier repair (the tier then stays broken until something else notices, which behind
        # a working fallback is "never").
        self.tier_rebuild_after = max(0, int(tier_rebuild_after))
        self._counts = [0] * len(tiers)          # live slots per tier
        self._owner: dict[str, int] = {}          # slot_id -> tier index
        self._lock = threading.Lock()
        # Consecutive spawn failures PER TIER. The pool's own streak cannot see these: a tier
        # whose base is poisoned raises here, the cascade falls through to a healthy overflow
        # tier, and spawn() RETURNS a slot -- so the pool records a success and resets its
        # streak. The broken tier is then never repaired and the deployment silently runs
        # permanently on the lower-priority tier, at its cost/performance, with nothing above
        # a per-attempt warning to say so (upstream, PR #82).
        self._tier_failures = [0] * len(tiers)

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
        _log.error(
            "cascade: tier %r failed %d consecutive spawns — invalidating its base so it can be "
            "rebuilt. Fallback tiers have been absorbing this, so the pool saw only successes.",
            tier.name, streak,
        )
        try:
            invalidate()
        except Exception as exc:  # noqa: BLE001
            _log.warning("cascade: tier %r base invalidation failed: %s", tier.name, exc)

    def invalidate_base(self) -> None:
        """Forward base invalidation to every wrapped tier that supports it.

        In production the pool holds THIS object, not the snapshot runtime, so without this the
        pool's getattr lookup fails and a poisoned base is never rebuilt (upstream, PR #82). Which
        tier owns the bad base is not knowable here -- invalidating a healthy one costs a rebuild,
        leaving a poisoned one costs the tier, so ask all of them."""
        for tier in getattr(self, "tiers", None) or ():
            drop = getattr(getattr(tier, "runtime", None), "invalidate_base", None)
            if callable(drop):
                with contextlib.suppress(Exception):
                    drop()

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
) -> CascadingRuntime:
    """Build a CascadingRuntime from ``BLASTBOX_POOL_TIERS``. The primary (first) tier must be
    available -- otherwise ``CascadeMisconfigured``; overflow tiers that aren't available are skipped
    with a warning so local capacity still comes up."""
    import os

    from blastbox.host.pool_config import select_runtime_by_name

    get = get or os.environ.get
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
    return CascadingRuntime(tiers)
