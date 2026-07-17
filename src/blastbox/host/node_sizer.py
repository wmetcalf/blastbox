"""Node-level pool autosizer — right-sizes every node-managed warm pool on a host
from live demand + a resource budget, instead of hand-tuning ``BLASTBOX_POOL_CEILING``
per engine.

A node runs several engine pools (clippyshot / redtusk / titanarum …), each a warm
pool of local microVMs that share the node's RAM/CPU. The per-engine ``WarmPool``
already reacts to its OWN queue pressure (demand-driven burst), but nothing keeps the
SUM across engines under the node's capacity, and the ceilings are static config blind
to per-slot footprint. This module adds the missing node-level coordinator:

  budget (node RAM/CPU × headroom)  +  live demand per engine  +  per-slot footprint
      → a ceiling/warm allocation per engine, water-filled by demand under the budget,
        with the invariant  Σ ceiling_i · footprint_i ≤ budget  (all engines can max
        out at once and still fit — no oversubscription).

Only **node-managed** runtimes are sized here (firecracker / gvisor — they consume this
node's resources). Serverless / remote tiers are skipped: on AWS Lambda the platform
manages concurrency (no node pool to size), and EC2/cloud capacity is the control
plane's job (Loadout's queue-depth autoscaler), not this node's. Sizing them here would
be meaningless, so ``manages()`` returns False and they're left untouched.

The allocation math (``plan_sizes``) is pure + testable; ``NodeAutoSizer`` is the thin
controller that reads live pool state, (optionally) adapts the budget from observed
node headroom, and applies the plan via ``WarmPool.resize()``.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Callable, Optional

from .pool_config import RUNTIME_FIRECRACKER, RUNTIME_GVISOR

# Runtimes whose concurrency is bounded by THIS node's resources → we size their pools.
# Everything else (aws-lambda-*, aws-ec2*, static, none, cascade) is skipped: the
# platform or the control plane owns their concurrency.
NODE_MANAGED_RUNTIMES: frozenset[str] = frozenset({RUNTIME_FIRECRACKER, RUNTIME_GVISOR})


def manages(runtime: str) -> bool:
    """True if a pool on this runtime should be sized by the node autosizer."""
    return (runtime or "").strip().lower() in NODE_MANAGED_RUNTIMES


@dataclass(frozen=True)
class NodeBudget:
    """The resource envelope the sizer may allocate on this node."""

    ram_mib: float                       # usable RAM for pools (node RAM × headroom_frac)
    vcpus: float                         # usable vCPU (cpu_count × vcpu_oversubscription)


@dataclass(frozen=True)
class PoolSpec:
    """One engine pool's inputs to the allocator."""

    name: str
    slot_ram_mib: float                  # RAM footprint of a single slot (microVM)
    slot_vcpus: float = 1.0              # vCPU footprint of a single slot
    demand: float = 0.0                  # current wantedness (busy slots + pressure)
    min_warm: int = 0                    # guaranteed warm floor (latency baseline)
    max_ceiling: int = 64               # per-engine hard cap (never exceed regardless of budget)


@dataclass(frozen=True)
class PoolSize:
    """The allocator's decision for one pool."""

    warm_size: int
    concurrent_ceiling: int


def plan_sizes(specs: list[PoolSpec], budget: NodeBudget) -> dict[str, PoolSize]:
    """Allocate the node budget across pools. Pure + deterministic.

    Ceilings are water-filled by demand so that Σ ceiling·footprint ≤ budget on BOTH
    RAM and vCPU — i.e. even if every engine simultaneously bursts to its ceiling, the
    node still fits (no oversubscription). Warm target then tracks each engine's demand
    (don't hold the whole node hot when idle). Floors (min_warm) are honoured first;
    per-engine max_ceiling caps growth.
    """
    if not specs:
        return {}

    # Hard baseline: every managed pool must be able to run at least one job, so ceiling
    # starts at 1 (WarmPool requires ceiling >= 1). This is counted against the budget;
    # if even the 1-per-engine baseline exceeds the budget the node is simply undersized
    # and we don't shed below 1 (a pool that can't run is useless). `min_warm` is a soft
    # WARM floor, honoured later only up to the ceiling the budget affords.
    alloc: dict[str, int] = {s.name: 1 for s in specs}
    used_ram = sum(s.slot_ram_mib for s in specs)
    used_vcpu = sum(s.slot_vcpus for s in specs)

    # Water-fill the remaining budget one slot at a time to the most-starved engine
    # (highest demand relative to what it already has), respecting caps + footprint.
    def fits(s: PoolSpec) -> bool:
        return (alloc[s.name] < s.max_ceiling
                and used_ram + s.slot_ram_mib <= budget.ram_mib
                and used_vcpu + s.slot_vcpus <= budget.vcpus)

    while True:
        cands = [s for s in specs if fits(s)]
        if not cands:
            break
        # diminishing returns: (demand + epsilon) / (already-allocated + 1). A tie or a
        # zero-demand engine still fills a beefy node after busy ones are satisfied, but
        # only up to its cap — busy engines are served first.
        pick = max(cands, key=lambda s: (s.demand + 1e-3) / (alloc[s.name] + 1))
        alloc[pick.name] += 1
        used_ram += pick.slot_ram_mib
        used_vcpu += pick.slot_vcpus

    out: dict[str, PoolSize] = {}
    for s in specs:
        ceiling = alloc[s.name]                      # >= 1 by construction
        # keep warm what demand needs (honouring the soft floor), never above ceiling
        warm = min(ceiling, max(s.min_warm, math.ceil(s.demand)))
        out[s.name] = PoolSize(warm_size=warm, concurrent_ceiling=ceiling)
    return out


def node_capacity(ram_headroom_frac: float = 0.8,
                  vcpu_oversubscription: float = 2.0) -> NodeBudget:
    """Static node budget from /proc/meminfo + os.cpu_count() (dependency-free).

    Uses MemTotal × headroom (not MemAvailable — the pools' own RSS is part of the
    node's live usage; we budget against total and let the adaptive loop correct)."""
    total_kib = 0.0
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total_kib = float(line.split()[1])
                    break
    except OSError:
        total_kib = 0.0
    ram_mib = (total_kib / 1024.0) * ram_headroom_frac
    vcpus = float(os.cpu_count() or 1) * vcpu_oversubscription
    return NodeBudget(ram_mib=ram_mib, vcpus=vcpus)


def _mem_available_mib() -> Optional[float]:
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return float(line.split()[1]) / 1024.0
    except OSError:
        return None
    return None


@dataclass
class ManagedPool:
    """Binds a live WarmPool to its sizing inputs. `pool` is any object exposing
    `runtime`, `assigned_count`, `burst_active`, `slot_count`, and `resize(...)`
    (WarmPool does)."""

    spec: PoolSpec
    pool: object                          # WarmPool (kept structural for testability)


class NodeAutoSizer:
    """Node-level controller. Each tick(): read live demand per managed pool, (optionally)
    adapt the budget from observed node headroom, compute a plan, and apply it. Pools on
    non-node-managed runtimes are ignored."""

    def __init__(
        self,
        pools: list[ManagedPool],
        *,
        ram_headroom_frac: float = 0.8,
        vcpu_oversubscription: float = 2.0,
        adaptive: bool = False,
        min_free_mib: float = 2048.0,     # adaptive: keep at least this much node RAM free
        clock: Callable[[], float] = None,  # type: ignore[assignment]
        capacity_fn: Callable[[float, float], NodeBudget] = node_capacity,
        avail_fn: Callable[[], Optional[float]] = _mem_available_mib,
    ) -> None:
        # only manage pools on node-managed runtimes (skip lambda/ec2/static/none)
        self._pools = [mp for mp in pools if manages(getattr(mp.pool, "runtime", ""))]
        self._ram_headroom = ram_headroom_frac
        self._vcpu_over = vcpu_oversubscription
        self._adaptive = adaptive
        self._min_free_mib = min_free_mib
        self._capacity_fn = capacity_fn
        self._avail_fn = avail_fn
        self._budget_scale = 1.0          # adaptive correction on the RAM budget (EWMA-driven)

    @property
    def managed_names(self) -> list[str]:
        return [mp.spec.name for mp in self._pools]

    def _live_demand(self, mp: ManagedPool) -> float:
        """Current wantedness of a pool: slots busy right now, lifted while bursting so a
        pool under sustained pressure pulls extra node share."""
        pool = mp.pool
        busy = float(getattr(pool, "assigned_count", 0))
        if getattr(pool, "burst_active", False):
            busy += 1.0                    # +1 slot of intent while under sustained pressure
        return busy

    def _adapt_budget(self, budget: NodeBudget) -> NodeBudget:
        """Nudge the RAM budget from observed free memory: if the node is running hotter
        than the model expects (free RAM below the safety floor) shrink; if there's lots
        of slack, relax back toward 1.0. Bounded to [0.5, 1.25]. No-op when not adaptive
        or when free memory can't be read."""
        if not self._adaptive:
            return budget
        free = self._avail_fn()
        if free is None:
            return budget
        if free < self._min_free_mib:
            self._budget_scale = max(0.5, self._budget_scale - 0.1)
        elif free > self._min_free_mib * 2:
            self._budget_scale = min(1.25, self._budget_scale + 0.05)
        return NodeBudget(ram_mib=budget.ram_mib * self._budget_scale, vcpus=budget.vcpus)

    def plan(self) -> dict[str, PoolSize]:
        """Compute (but don't apply) the current sizing plan."""
        if not self._pools:
            return {}
        budget = self._adapt_budget(self._capacity_fn(self._ram_headroom, self._vcpu_over))
        specs = [
            PoolSpec(
                name=mp.spec.name,
                slot_ram_mib=mp.spec.slot_ram_mib,
                slot_vcpus=mp.spec.slot_vcpus,
                demand=self._live_demand(mp),
                min_warm=mp.spec.min_warm,
                max_ceiling=mp.spec.max_ceiling,
            )
            for mp in self._pools
        ]
        return plan_sizes(specs, budget)

    def tick(self) -> dict[str, PoolSize]:
        """Compute the plan and apply it to every managed pool. Returns the plan."""
        plan = self.plan()
        for mp in self._pools:
            size = plan.get(mp.spec.name)
            if size is None:
                continue
            mp.pool.resize(  # type: ignore[attr-defined]
                warm_size=size.warm_size,
                concurrent_ceiling=size.concurrent_ceiling,
            )
        return plan
