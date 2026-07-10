"""Cascading (tiered) SlotRuntime: fill a primary tier, then overflow to the next.

Answers "run **X workers locally, then burst up to Y on other hardware / AWS**" as a single warm pool.
It composes any of the existing backends (gvisor / firecracker locally, ``static`` for other boxes,
``aws-ec2`` / ``aws-lambda-microvm`` for cloud) into a **priority-ordered** list of tiers, each with a
capacity. ``spawn`` fills tier 1 up to its capacity, then tier 2, and so on; ``reap`` frees the slot on
whichever tier owns it. The WarmPool above it is unchanged -- it just sees one SlotRuntime.

Wiring (env):
  BLASTBOX_POOL_RUNTIME=cascade
  BLASTBOX_POOL_TIERS=gvisor:4,aws-ec2:16     # 4 warm local + up to 16 overflow on AWS
  BLASTBOX_POOL_WARM_SIZE=4                    # keep the 4 local slots warm
  BLASTBOX_POOL_CEILING=20                     # 4 local + 16 overflow
  BLASTBOX_DISPATCH_CONCURRENCY=20

Each tier reads its own backend config (BLASTBOX_STATIC_WORKERS, BLASTBOX_EC2_*, BLASTBOX_FC_*, ...).
The **primary** tier must be available at startup (fail-closed); an **overflow** tier that isn't
available is logged and skipped, so local capacity still comes up if the cloud tier is misconfigured.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_log = logging.getLogger("blastbox.host.runtime.cascade")


class CascadeMisconfigured(RuntimeError):
    """No usable tier (empty ``BLASTBOX_POOL_TIERS`` or the primary tier is unavailable)."""


class CascadeExhausted(RuntimeError):
    """Every tier is at capacity (or failed to spawn) -- the whole cascade is full."""


@dataclass
class Tier:
    name: str
    runtime: Any          # a SlotRuntime (concrete slot type varies per backend)
    capacity: int


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

    def __init__(self, tiers: list[Tier]) -> None:
        if not tiers:
            raise CascadeMisconfigured("cascade needs at least one tier")
        self.tiers = tiers
        self._counts = [0] * len(tiers)          # live slots per tier
        self._owner: dict[str, int] = {}          # slot_id -> tier index
        self._lock = threading.Lock()

    # -- SlotRuntime protocol ----------------------------------------------
    def spawn(self) -> Any:
        last_exc: Exception | None = None
        for i, tier in enumerate(self.tiers):
            with self._lock:
                if self._counts[i] >= tier.capacity:
                    continue
                self._counts[i] += 1          # reserve before the (slow) spawn
            try:
                slot = tier.runtime.spawn()
            except Exception as exc:  # noqa: BLE001 -- try the next tier, don't fail the whole spawn
                with self._lock:
                    self._counts[i] -= 1
                last_exc = exc
                _log.warning("cascade: tier %r spawn failed, trying next: %s", tier.name, exc)
                continue
            with self._lock:
                self._owner[slot.slot_id] = i
            _log.info("cascade: spawned on tier %r (%d/%d) slot=%s",
                      tier.name, self._counts[i], tier.capacity, slot.slot_id)
            return slot
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

    def is_alive(self, slot: Any) -> bool:
        tier = self._tier_of(slot)
        return tier is not None and tier.runtime.is_alive(slot)

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
            raise CascadeExhausted(f"cascade: no owning tier for slot {getattr(slot, 'slot_id', slot)!r}")
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


# ---------------------------------------------------------------------------
# Build from env
# ---------------------------------------------------------------------------

def _parse_tiers(spec: str) -> list[tuple[str, int]]:
    """Parse ``gvisor:4,aws-ec2:16`` -> [('gvisor', 4), ('aws-ec2', 16)]."""
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
        raise CascadeMisconfigured("BLASTBOX_POOL_TIERS is empty (need e.g. 'gvisor:4,aws-ec2:16')")

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
