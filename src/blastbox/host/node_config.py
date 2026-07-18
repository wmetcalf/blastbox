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

import os
from dataclasses import dataclass, replace


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
            return default if not raw else raw not in ("0", "false", "no", "off")

        def _float(key: str, default: float) -> float:
            raw = os.environ.get(key, "").strip()
            return float(raw) if raw else default

        def _int(key: str, default: int) -> int:
            raw = os.environ.get(key, "").strip()
            return int(raw) if raw else default

        engines: list[EngineNode] = []
        raw = os.environ.get("BLASTBOX_NODE_ENGINES", "").strip()
        for item in (p for p in raw.split(",") if p.strip()):
            name, _, url = item.partition("=")
            name, url = name.strip(), url.strip()
            if not name or not url:
                raise ValueError(f"BLASTBOX_NODE_ENGINES entry must be 'name=url', got {item!r}")
            up = name.upper().replace("-", "_")
            engines.append(EngineNode(
                name=name, url=url,
                slot_ram_mib=_float(f"BLASTBOX_NODE_ENGINE_{up}_RAM_MIB", 2048.0),
                slot_vcpus=_float(f"BLASTBOX_NODE_ENGINE_{up}_VCPUS", 1.0),
                min_warm=_int(f"BLASTBOX_NODE_ENGINE_{up}_MIN_WARM", 0),
                max_ceiling=_int(f"BLASTBOX_NODE_ENGINE_{up}_MAX_CEILING", 64),
                weight=_float(f"BLASTBOX_NODE_ENGINE_{up}_WEIGHT", 1.0)))
        balancing = _bool("BLASTBOX_NODE_BALANCING", False)
        return cls(
            engines=tuple(engines),
            # balancing implies resource_management (you can't rebalance a budget you
            # don't enforce), so enabling balancing turns budget enforcement on too.
            resource_management=_bool("BLASTBOX_NODE_RESOURCE_MANAGEMENT", False) or balancing,
            balancing=balancing,
            ram_headroom_frac=_float("BLASTBOX_NODE_RAM_HEADROOM", 0.8),
            vcpu_oversubscription=_float("BLASTBOX_NODE_VCPU_OVERSUBSCRIPTION", 2.0),
            adaptive=_bool("BLASTBOX_NODE_ADAPTIVE", False),
            min_free_mib=_float("BLASTBOX_NODE_MIN_FREE_MIB", 2048.0),
            interval_s=_float("BLASTBOX_NODE_INTERVAL_S", 5.0),
            share_dir=os.environ.get("BLASTBOX_NODE_SHARE_DIR", "/var/lib/blastbox/node").strip()
            or "/var/lib/blastbox/node",
            stale_after_s=_float("BLASTBOX_NODE_STALE_AFTER_S", 20.0),
        )
