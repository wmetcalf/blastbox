"""Node inventory + opt-in toggles for the pool coordinator.

Everything here is OFF by default — a node runs exactly as it does today unless an
operator turns features on. Three independent switches, layered:

  1. run it at all                      (the sizer runs inside `blastbox dispatch` only
                                         when a switch below is on; otherwise it never starts)
  2. resource_management: bool          (enforce the node RAM/vCPU budget — cap total slots
                                         so engines can't oversubscribe the node)
  3. balancing: bool                    (dynamically rebalance the budget across engines by
                                         live queue backlog; implies resource_management)

The node also carries an inventory of the engines running on it — add/remove an engine
(a hardware node's set of engines) by editing this list (env or the API). With balancing
OFF but resource_management ON, each engine gets a static, weight-proportional share of
the budget; with both OFF the coordinator is a no-op and each pool self-manages via its
own burst logic exactly as before.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, replace

# The bounds the READER (node_share._valid) enforces on a published snapshot. from_env is
# the WRITER of a dispatcher's own snapshot, so it MUST clamp to these same caps — a value
# from_env accepts but _valid rejects makes the engine's self-snapshot silently dropped
# from its own and every peer's node view (→ it never sizes, and peers water-fill as if its
# slots don't exist → oversubscription). Import them so writer and reader can't drift.
from .node_share import _MAX_CEILING_SANE, _MAX_WEIGHT

# An engine name becomes part of the on-disk snapshot FILENAME (node_share keys the file by
# the identity), so it must be a plain slug — a '/', '\\' or '..' would let the publish path
# escape the share dir and clobber an unrelated file. Validate at config load (fail fast +
# visible), backed up by a hard guard in FileNodeShare.publish.
_SAFE_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Upper bound on the sizing interval (seconds). A finite-but-huge value passes float()
# but OverflowError-s in stop.wait()/time.sleep() and kills the sizing thread; one day is
# absurdly long for a heartbeat yet safely within platform time_t.
_MAX_INTERVAL_S = 86_400.0


def _is_safe_slug(s: str) -> bool:
    return bool(_SAFE_SLUG.match(s)) and ".." not in s


@dataclass(frozen=True)
class EngineNode:
    """One engine on this hardware node — an entry in the node inventory."""

    name: str
    url: str                              # engine ingress base url (status/resize live here)
    slot_ram_mib: float = 2048.0          # per-slot RAM footprint (a warm microVM)
    slot_vcpus: float = 1.0
    min_warm: int = 0                     # floor: slots kept hot even at zero backlog
    max_ceiling: int = 64                # hard per-engine cap
    weight: float = 1.0                   # static share when balancing is OFF


@dataclass(frozen=True)
class NodeConfig:
    """A hardware node: its engine inventory + the opt-in coordination toggles."""

    engines: tuple[EngineNode, ...] = ()
    resource_management: bool = False
    balancing: bool = False
    ram_headroom_frac: float = 0.8
    vcpu_oversubscription: float = 2.0
    adaptive: bool = False                # opt-in: adapt the budget from observed free RAM
    min_free_mib: float = 2048.0          # adaptive: keep at least this much node RAM free
    interval_s: float = 5.0
    # shared-store (dispatcher self-sizing) transport: the node dir every engine's
    # dispatcher publishes its demand to + reads peers from. Snapshots older than
    # stale_after_s are ignored (a dead engine drops out of the node view).
    share_dir: str = "/var/lib/blastbox/node"
    stale_after_s: float = 20.0

    @property
    def active(self) -> bool:
        """True if the coordinator should touch pools at all. With both switches off it
        is a pure no-op (pools self-manage) — the safest default."""
        return bool(self.engines) and (self.resource_management or self.balancing)

    def add_engine(self, engine: EngineNode) -> "NodeConfig":
        """Return a copy with `engine` added (or replaced by name) — add a HW node's
        engine to the managed inventory."""
        others = tuple(e for e in self.engines if e.name != engine.name)
        return replace(self, engines=others + (engine,))

    def remove_engine(self, name: str) -> "NodeConfig":
        """Return a copy with the named engine removed from management."""
        return replace(self, engines=tuple(e for e in self.engines if e.name != name))

    @classmethod
    def from_env(cls) -> "NodeConfig":
        """Read the node config from BLASTBOX_NODE_* env.

        BLASTBOX_NODE_ENGINES = 'clippyshot=http://127.0.0.1:8001,redtusk=http://127.0.0.1:8003'
        BLASTBOX_NODE_ENGINE_<NAME>_RAM_MIB / _VCPUS / _MIN_WARM / _MAX_CEILING / _WEIGHT
        BLASTBOX_NODE_RESOURCE_MANAGEMENT / _BALANCING / _ADAPTIVE = 1|0  (default 0)
        BLASTBOX_NODE_RAM_HEADROOM / _VCPU_OVERSUBSCRIPTION / _INTERVAL_S
        """
        def _bool(key: str, default: bool) -> bool:
            raw = os.environ.get(key, "").strip().lower()
            if not raw:
                return default
            if raw in ("1", "true", "yes", "on"):
                return True
            if raw in ("0", "false", "no", "off"):
                return False
            # Reject an unrecognised spelling (e.g. 'flase') rather than treating any nonempty
            # value as True — a typo must NOT silently enable hard-cap management, forced
            # warm_only, and startup pre-shrinking.
            raise ValueError(
                f"{key}={raw!r} is not a valid boolean (use 1/0/true/false/yes/no/on/off)")

        def _float(key: str, default: float) -> float:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                v = float(raw)
            except ValueError:
                return default
            # Reject inf/nan: they slip past float() and max()/min() don't tame them — an
            # infinite interval makes time.sleep(inf) raise OverflowError and kill the sizer
            # thread, and a non-finite stale window never ages a snapshot out (or rejects
            # every one). Fall back to the default, like an unparseable value.
            return v if math.isfinite(v) else default

        def _int(key: str, default: int) -> int:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError:                       # 'inf'/'nan'/garbage → default, never crash
                return default

        def _clamp(val: float, lo: float, hi: float) -> float:
            return max(lo, min(hi, val))

        engines: list[EngineNode] = []
        seen: set[str] = set()
        seen_up: set[str] = set()
        raw = os.environ.get("BLASTBOX_NODE_ENGINES", "").strip()
        for item in (p for p in raw.split(",") if p.strip()):
            # `name` or `name=url`; url is optional + unused by the shipped sizer (a
            # leftover from the removed HTTP-push design) — don't make it mandatory.
            name, _, url = item.partition("=")
            name, url = name.strip(), url.strip()
            if not name:
                raise ValueError(f"BLASTBOX_NODE_ENGINES entry must name an engine, got {item!r}")
            if not _is_safe_slug(name):
                raise ValueError(
                    f"BLASTBOX_NODE_ENGINES engine name {name!r} is not a safe slug "
                    "(letters/digits/._- only, no path separators or '..')")
            if name in seen:
                # a repeat would be counted twice (doubled weight in static mode, double the
                # footprint in the node view) — reject rather than silently double-count.
                raise ValueError(f"BLASTBOX_NODE_ENGINES lists engine {name!r} more than once")
            seen.add(name)
            up = name.upper().replace("-", "_")
            if up in seen_up:
                # two distinct names that normalise to the same env prefix (foo-bar vs foo_bar,
                # or Clip vs clip) would read the IDENTICAL BLASTBOX_NODE_ENGINE_<UP>_* vars, so
                # you couldn't give them distinct footprints/ceilings — reject the ambiguity.
                raise ValueError(
                    f"BLASTBOX_NODE_ENGINES: engine name {name!r} collides with another on the "
                    f"env-var prefix {up!r} (names differing only in case or -/_ are ambiguous)")
            seen_up.add(up)
            engines.append(EngineNode(
                name=name, url=url,
                # footprints/caps clamped to sane positives so a typo can't produce a
                # 0-RAM slot (water-fill footgun) or a runaway ceiling.
                slot_ram_mib=_clamp(_float(f"BLASTBOX_NODE_ENGINE_{up}_RAM_MIB", 2048.0), 1.0, 1 << 20),
                slot_vcpus=_clamp(_float(f"BLASTBOX_NODE_ENGINE_{up}_VCPUS", 1.0), 0.01, 1024.0),
                # min_warm/weight clamped to the READER's _valid caps (not just >= 0), or
                # the engine's own snapshot fails validation → silent self-eviction.
                min_warm=int(_clamp(_int(f"BLASTBOX_NODE_ENGINE_{up}_MIN_WARM", 0), 0, _MAX_CEILING_SANE)),
                max_ceiling=int(_clamp(_int(f"BLASTBOX_NODE_ENGINE_{up}_MAX_CEILING", 64), 1, _MAX_CEILING_SANE)),
                weight=_clamp(_float(f"BLASTBOX_NODE_ENGINE_{up}_WEIGHT", 1.0), 0.0, _MAX_WEIGHT)))
        balancing = _bool("BLASTBOX_NODE_BALANCING", False)
        # Clamp the budget knobs — these are footguns: headroom is a FRACTION (0,1], so a
        # bare "80" meaning 80% would give an 80× budget → OOM; a non-positive interval is
        # a busy-loop; a staleness window shorter than the publish interval ages peers out
        # every tick → each engine sees only itself → N-way oversubscription.
        # Upper-bound too: a huge but finite interval (e.g. 1e10) passes _float() but then
        # OverflowError-s in stop.wait()/time.sleep() ("timestamp out of range for platform
        # time_t"), OUTSIDE the tick handler — the sizing thread dies while its pool keeps its
        # last allocation and peers eventually expire its snapshot and reallocate. A day is
        # already absurd for a heartbeat and safely within time_t.
        interval_s = _clamp(_float("BLASTBOX_NODE_INTERVAL_S", 5.0), 0.5, _MAX_INTERVAL_S)
        # stale_after_s only feeds mtime staleness comparison (never wait()/sleep()), so it needs
        # no time_t cap — but it MUST stay >= 2*interval or peers age out every tick.
        stale_after_s = max(_float("BLASTBOX_NODE_STALE_AFTER_S", 20.0), interval_s * 2.0)
        return cls(
            engines=tuple(engines),
            # balancing implies resource_management (you can't rebalance a budget you
            # don't enforce), so enabling balancing turns budget enforcement on too.
            resource_management=_bool("BLASTBOX_NODE_RESOURCE_MANAGEMENT", False) or balancing,
            balancing=balancing,
            ram_headroom_frac=_clamp(_float("BLASTBOX_NODE_RAM_HEADROOM", 0.8), 0.05, 1.0),
            vcpu_oversubscription=_clamp(_float("BLASTBOX_NODE_VCPU_OVERSUBSCRIPTION", 2.0), 0.5, 64.0),
            adaptive=_bool("BLASTBOX_NODE_ADAPTIVE", False),
            min_free_mib=max(0.0, _float("BLASTBOX_NODE_MIN_FREE_MIB", 2048.0)),
            interval_s=interval_s,
            share_dir=os.environ.get("BLASTBOX_NODE_SHARE_DIR", "/var/lib/blastbox/node").strip()
            or "/var/lib/blastbox/node",
            stale_after_s=stale_after_s,
        )
