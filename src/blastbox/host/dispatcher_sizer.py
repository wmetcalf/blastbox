"""Dispatcher-side self-sizer — the transport that fits blastbox's serve/dispatch split.

Runs inside the `dispatch` process (which owns the warm pool). Each tick it publishes its
own demand to the shared node view and reads every peer's, then runs the SAME
deterministic allocation (node_sizer.plan_sizes) over the whole node and resizes ITS OWN
pool. Because every engine's dispatcher runs the identical allocation over the identical
shared view, the node partitions consistently — no central daemon, no HTTP push, no admin
endpoint. Off unless NodeConfig enables resource_management or balancing.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .node_config import EngineNode, NodeConfig
from .node_share import DemandSnapshot, NodeShare
from .node_sizer import PoolSpec, PoolSize, manages, node_capacity, plan_sizes


class DispatcherSizer:
    def __init__(
        self,
        engine: EngineNode,
        pool: object,                         # the local WarmPool (assigned_count/runtime/resize)
        share: NodeShare,
        config: NodeConfig,
        *,
        backlog_fn: Callable[[], int],        # this engine's own QUEUED count
        capacity_fn: Callable[[float, float], object] = node_capacity,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._engine = engine
        self._pool = pool
        self._share = share
        self._config = config
        self._backlog_fn = backlog_fn
        self._capacity_fn = capacity_fn
        self._clock = clock

    def _active(self) -> bool:
        cfg = self._config
        return (cfg.resource_management or cfg.balancing) and manages(getattr(self._pool, "runtime", ""))

    def tick(self) -> Optional[PoolSize]:
        """Publish own demand, read the node view, size the local pool. Returns this
        engine's decided size (None when the feature is off or the view is empty)."""
        if not self._active():
            return None
        now = self._clock()
        e = self._engine
        self._share.publish(DemandSnapshot(
            engine=e.name,
            backlog=max(0, int(self._backlog_fn())),
            assigned=int(getattr(self._pool, "assigned_count", 0)),
            slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
            min_warm=e.min_warm, max_ceiling=e.max_ceiling, weight=e.weight, ts=now,
        ))
        snaps = self._share.read_all(max_age_s=self._config.stale_after_s, now=now)
        if not snaps:
            return None

        balancing = self._config.balancing
        specs = [
            PoolSpec(
                name=s.engine, slot_ram_mib=s.slot_ram_mib, slot_vcpus=s.slot_vcpus,
                # balancing → live backlog + in-flight; else the configured static weight
                demand=float(s.backlog + s.assigned) if balancing else float(s.weight),
                min_warm=s.min_warm, max_ceiling=s.max_ceiling,
            )
            for s in snaps
        ]
        budget = self._capacity_fn(self._config.ram_headroom_frac, self._config.vcpu_oversubscription)
        plan = plan_sizes(specs, budget)  # type: ignore[arg-type]
        mine = plan.get(e.name)
        if mine is not None and hasattr(self._pool, "resize"):
            self._pool.resize(  # type: ignore[attr-defined]
                warm_size=mine.warm_size, concurrent_ceiling=mine.concurrent_ceiling)
        return mine

    def run(self, *, stop: Optional[threading.Event] = None, max_ticks: Optional[int] = None,
            sleep: Callable[[float], None] = time.sleep) -> None:
        n = 0
        while not (stop is not None and stop.is_set()):
            try:
                self.tick()
            except Exception:  # a sizing hiccup must never take down the dispatcher
                pass
            n += 1
            if max_ticks is not None and n >= max_ticks:
                return
            sleep(self._config.interval_s)

    def start_thread(self, stop: threading.Event) -> threading.Thread:
        """Start the loop in a daemon thread (for use alongside the dispatcher loop)."""
        t = threading.Thread(target=self.run, kwargs={"stop": stop},
                             name=f"node-sizer:{self._engine.name}", daemon=True)
        t.start()
        return t
