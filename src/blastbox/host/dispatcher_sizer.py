"""Dispatcher-side self-sizer — the transport that fits blastbox's serve/dispatch split.

Runs inside the `dispatch` process (which owns the warm pool). Each tick it publishes its
own demand to the shared node view and reads every peer's, then runs the SAME
deterministic allocation (node_sizer.plan_sizes) over the whole node and resizes ITS OWN
pool. Because every engine's dispatcher runs the identical allocation over the identical
shared view, the node partitions consistently — no central daemon, no HTTP push, no admin
endpoint. Off unless NodeConfig enables resource_management or balancing.

Consistency is EVENTUAL, not instantaneous: dispatchers publish/read on their own clocks
(and adaptive scale is per-process), so two engines can act on slightly divergent views
for one interval and transiently sum above budget. That window is bounded — the staleness
horizon is short, each engine's real RAM use is capped by IDLE-slot reaping + the warm
target tracking demand, and the views reconverge next tick — so it self-corrects rather
than drifting; it is not a hard oversubscription guarantee.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Optional

from .node_config import EngineNode, NodeConfig
from .node_share import DemandSnapshot, NodeShare
from .node_sizer import (
    NodeBudget,
    PoolSize,
    PoolSpec,
    _mem_available_mib,
    manages,
    node_capacity,
    plan_sizes,
)


def _pool_key(engine: str, tier: str) -> str:
    """Identity of a warm pool within a node view = (engine, tier). The same engine on two
    node-managed tiers on one host is two distinct pools; keying by engine alone would merge
    them in the allocation. Deterministic + identical across every dispatcher, so all agree
    on the plan. (node is not in the key — the view is already node-filtered.)"""
    return f"{engine}@{tier}" if tier else engine


class DispatcherSizer:
    def __init__(
        self,
        engine: EngineNode,
        pool: object,                         # the local WarmPool (assigned_count/resize)
        share: NodeShare,
        config: NodeConfig,
        *,
        runtime: str,                         # the pool's runtime NAME (BLASTBOX_POOL_RUNTIME /
                                              # dispatcher tier) — WarmPool.runtime is the
                                              # SlotRuntime OBJECT, not a name, so gating must
                                              # use this string.
        backlog_fn: Callable[[], int],        # this engine's own QUEUED count
        node: Optional[str] = None,           # physical-node id; default from BLASTBOX_NODE_ID
        capacity_fn: Callable[[float, float], NodeBudget] = node_capacity,
        avail_fn: Callable[[], Optional[float]] = _mem_available_mib,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._engine = engine
        self._pool = pool
        self._share = share
        self._config = config
        self._runtime = (runtime or "").strip().lower()
        self._backlog_fn = backlog_fn
        # The node id must identify the PHYSICAL HOST, shared by every engine container on
        # it — NOT socket.gethostname(), which inside a container is the container's own
        # name (so each engine would see only itself → no coordination, the common toolz2
        # layout). Default "" means "the share_dir IS the node boundary" (correct when all
        # of a host's engines bind-mount one dir); set BLASTBOX_NODE_ID per physical host
        # only to defend a share_dir accidentally shared ACROSS hosts.
        self._node = node if node is not None else os.environ.get("BLASTBOX_NODE_ID", "").strip()
        self._capacity_fn = capacity_fn
        self._avail_fn = avail_fn
        self._clock = clock
        self._budget_scale = 1.0              # adaptive correction, persisted across ticks
        self._last_tick_dur = 0.0             # measured, to widen the staleness window

    def _active(self) -> bool:
        cfg = self._config
        return (cfg.resource_management or cfg.balancing) and manages(self._runtime)

    def _adapt(self, budget: "NodeBudget") -> "NodeBudget":
        """Nudge the RAM budget from observed free memory when BLASTBOX_NODE_ADAPTIVE is
        on. Persisted across ticks. The UP-scale is capped so the adapted budget never
        exceeds physical RAM: with headroom_frac h the baseline budget is total·h, so the
        scale is capped at 1/h (times the safety 1.25) — otherwise a high headroom (e.g.
        1.0) × 1.25 would target 125% of node RAM → OOM."""
        if not self._config.adaptive:
            return budget
        free = self._avail_fn()
        if free is None:
            return budget
        hi = min(1.25, 1.0 / max(self._config.ram_headroom_frac, 0.05))
        floor = self._config.min_free_mib
        if free < floor:
            self._budget_scale = max(0.5, self._budget_scale - 0.1)
        elif free > floor * 2:
            self._budget_scale = min(hi, self._budget_scale + 0.05)
        self._budget_scale = min(self._budget_scale, hi)   # clamp if headroom changed
        return NodeBudget(ram_mib=budget.ram_mib * self._budget_scale, vcpus=budget.vcpus)

    def tick(self) -> Optional[PoolSize]:
        """Publish own demand, read the node view, size the local pool. Returns this
        engine's decided size (None when the feature is off or the view is empty)."""
        if not self._active():
            return None
        started = self._clock()
        e = self._engine
        # Do the (possibly slow) backlog count FIRST, then stamp ts — otherwise the
        # snapshot is written already-aged by the count latency (on a large shared store
        # the count scans every key), which can push peers past the staleness window.
        backlog = max(0, int(self._backlog_fn()))
        assigned = int(getattr(self._pool, "assigned_count", 0))
        now = self._clock()
        self._share.publish(DemandSnapshot(
            engine=e.name, backlog=backlog, assigned=assigned,
            slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
            min_warm=e.min_warm, max_ceiling=e.max_ceiling, weight=e.weight, ts=now,
            node=self._node, tier=self._runtime,
        ))
        # Effective staleness widens by the measured tick cost: the real publish period is
        # interval + tick_time, so a slow count (huge shared store) must not age peers out
        # and collapse every engine to "sees only itself" → node oversubscription.
        max_age = max(self._config.stale_after_s,
                      (self._config.interval_s + self._last_tick_dur) * 2.0)
        # Node filter, SYMMETRIC so a partial config (some engines set BLASTBOX_NODE_ID,
        # some not, on one host) still coordinates instead of each thinking it's alone
        # (→ oversubscription): include a peer if either side is untagged, or the tags
        # match. A set-vs-different-set pair (real cross-host isolation) is excluded.
        snaps = [s for s in self._share.read_all(max_age_s=max_age, now=now)
                 if s.node == "" or self._node == "" or s.node == self._node]
        self._last_tick_dur = max(0.0, self._clock() - started)
        if not snaps:
            return None

        balancing = self._config.balancing
        specs = [
            PoolSpec(
                # key each pool by (engine, tier): the same engine on two node-managed tiers
                # (firecracker + gvisor) on one host is TWO pools competing for the budget —
                # keying by engine alone would collapse them and each would size to the whole
                # budget. `_pool_key` matches what THIS dispatcher looks up for itself below.
                name=_pool_key(s.engine, s.tier),
                slot_ram_mib=s.slot_ram_mib, slot_vcpus=s.slot_vcpus,
                # ceiling water-fill: by live backlog (balancing) or the static weight share.
                demand=float(s.backlog + s.assigned) if balancing else float(s.weight),
                min_warm=s.min_warm, max_ceiling=s.max_ceiling,
            )
            for s in snaps
        ]
        budget = self._adapt(self._capacity_fn(self._config.ram_headroom_frac,
                                               self._config.vcpu_oversubscription))
        plan = plan_sizes(specs, budget)  # type: ignore[arg-type]
        mine = plan.get(_pool_key(e.name, self._runtime))
        if mine is not None and hasattr(self._pool, "resize"):
            # WARM tracks THIS engine's REAL demand (not the weight, which is only a
            # ceiling-share ratio) so static mode doesn't hold idle engines hot: a big
            # weight buys a big ceiling to burst into, but few hot slots when idle.
            warm = min(mine.concurrent_ceiling, max(e.min_warm, backlog + assigned))
            mine = PoolSize(warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
            self._pool.resize(  # type: ignore[attr-defined]
                warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
        return mine

    def run(self, *, stop: Optional[threading.Event] = None, max_ticks: Optional[int] = None,
            sleep: Callable[[float], None] = time.sleep) -> None:
        n = 0
        while not (stop is not None and stop.is_set()):
            try:
                self.tick()
            except Exception:  # a sizing hiccup must never take down the dispatcher
                logging.getLogger("blastbox.node_sizer").warning(
                    "node self-sizer tick failed for %s (continuing)", self._engine.name,
                    exc_info=True)
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
