"""Node coordinator — the opt-in cross-process driver for the pool autosizer.

Each engine on a node runs as its own `serve` process (its own warm pool + `/v1/pool`
endpoints). This coordinator is a small daemon (one per node) that scrapes every engine's
status, decides a per-engine warm/ceiling under the node budget, and pushes the result
back. It is OFF unless configured (see NodeConfig) and honours the two toggles:

  - both off              → tick() is a no-op; pools self-manage via their own burst logic.
  - resource_management   → enforce the node budget; static weight-proportional shares.
  - balancing             → shares follow live queue backlog (rebalance the node toward
                            whichever engine has work); implies resource_management.

It reuses the tested NodeAutoSizer by wrapping each remote engine in a RemotePoolProxy
that presents the WarmPool-structural surface (runtime / assigned_count / burst_active /
resize) over HTTP. Transports are injectable so the decision logic is unit-testable
without a network.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Callable, Optional

from .node_config import EngineNode, NodeConfig
from .node_sizer import ManagedPool, NodeAutoSizer, PoolSpec

# fetch_status(url) -> {"runtime", "assigned", "burst_active", "backlog", ...}
FetchStatus = Callable[[str], dict]
# push_resize(url, warm_size, concurrent_ceiling) -> None
PushResize = Callable[[str, int, int], None]


class RemotePoolProxy:
    """A WarmPool-shaped view of a remote engine's pool. NodeAutoSizer reads
    runtime/assigned_count/burst_active and calls resize(); we serve those from the last
    scraped status and turn resize() into a push."""

    def __init__(self, engine: EngineNode, push: PushResize) -> None:
        self._engine = engine
        self._push = push
        self.runtime = ""                 # filled from status; blank → skipped by manages()
        self.assigned_count = 0
        self.burst_active = False
        self.backlog = 0

    def update(self, status: dict) -> None:
        self.runtime = str(status.get("runtime", "") or "")
        self.assigned_count = int(status.get("assigned", 0) or 0)
        self.burst_active = bool(status.get("burst_active", False))
        self.backlog = int(status.get("backlog", 0) or 0)

    def resize(self, *, warm_size: int, concurrent_ceiling: int) -> None:
        self._push(self._engine.url, warm_size, concurrent_ceiling)


class NodeCoordinator:
    def __init__(
        self,
        config: NodeConfig,
        *,
        fetch_status: FetchStatus,
        push_resize: PushResize,
    ) -> None:
        self._config = config
        self._fetch = fetch_status
        self._proxies: dict[str, RemotePoolProxy] = {
            e.name: RemotePoolProxy(e, push_resize) for e in config.engines
        }

    def _refresh(self) -> None:
        for e in self._config.engines:
            try:
                self._proxies[e.name].update(self._fetch(e.url))
            except Exception:
                # an unreachable engine is left with its last-known (or zero) state; it
                # simply won't pull node share until it answers again.
                pass

    def tick(self) -> dict:
        """One coordination pass. Returns the applied plan (empty if inactive)."""
        cfg = self._config
        if not cfg.active:
            return {}                      # feature off → don't touch any pool
        self._refresh()

        # Demand source depends on the mode:
        #   balancing ON  → live queue backlog (dynamic rebalance across engines)
        #   balancing OFF → each engine's static weight (fixed proportional share)
        if cfg.balancing:
            def backlog_fn(name: str) -> int:
                p = self._proxies.get(name)
                return p.backlog if p else 0
        else:
            weights = {e.name: e.weight for e in cfg.engines}

            def backlog_fn(name: str) -> int:
                return int(round(weights.get(name, 1.0)))

        managed = [
            ManagedPool(
                PoolSpec(name=e.name, slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
                         min_warm=e.min_warm, max_ceiling=e.max_ceiling),
                self._proxies[e.name],
            )
            for e in cfg.engines
        ]
        sizer = NodeAutoSizer(
            managed,
            ram_headroom_frac=cfg.ram_headroom_frac,
            vcpu_oversubscription=cfg.vcpu_oversubscription,
            adaptive=cfg.adaptive,
            backlog_fn=backlog_fn,
        )
        plan = sizer.tick()
        return {name: {"warm_size": s.warm_size, "concurrent_ceiling": s.concurrent_ceiling}
                for name, s in plan.items()}

    def run(self, *, stop: Optional[threading.Event] = None, max_ticks: Optional[int] = None,
            sleep: Callable[[float], None] = time.sleep) -> None:
        n = 0
        while not (stop is not None and stop.is_set()):
            self.tick()
            n += 1
            if max_ticks is not None and n >= max_ticks:
                return
            sleep(self._config.interval_s)


# --- HTTP transports (thin; the decision logic above is transport-agnostic) --------

def http_fetch_status(timeout: float = 4.0) -> FetchStatus:
    def _fetch(url: str) -> dict:
        req = urllib.request.Request(url.rstrip("/") + "/v1/pool/status")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operator-configured url
            return json.loads(r.read())
    return _fetch


def http_push_resize(admin_token: str, timeout: float = 4.0) -> PushResize:
    def _push(url: str, warm_size: int, concurrent_ceiling: int) -> None:
        body = json.dumps({"warm_size": warm_size, "concurrent_ceiling": concurrent_ceiling}).encode()
        req = urllib.request.Request(
            url.rstrip("/") + "/v1/pool/resize", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {admin_token}"})
        with urllib.request.urlopen(req, timeout=timeout):  # noqa: S310 - operator-configured url
            return None
    return _push
