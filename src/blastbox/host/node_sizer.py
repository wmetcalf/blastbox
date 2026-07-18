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

The allocation math (``plan_sizes``) is pure + testable; ``dispatcher_sizer.DispatcherSizer``
is the thin controller that reads live pool state, (optionally) adapts the budget from
observed node headroom, and applies the plan via ``WarmPool.resize()``.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .pool_config import RUNTIME_FIRECRACKER, RUNTIME_GVISOR

# Runtimes whose concurrency is bounded by THIS node's resources → we size their pools.
# Everything else (aws-lambda-*, aws-ec2*, static, none, cascade) is skipped: the
# platform or the control plane owns their concurrency.
NODE_MANAGED_RUNTIMES: frozenset[str] = frozenset({RUNTIME_FIRECRACKER, RUNTIME_GVISOR})


def manages(runtime: str) -> bool:
    """True if a pool on this runtime should be sized by the node autosizer. Takes the
    runtime NAME string (not a SlotRuntime object); a non-string is defensively False."""
    if not isinstance(runtime, str):
        return False
    return runtime.strip().lower() in NODE_MANAGED_RUNTIMES


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

    Ceilings are water-filled by demand so that, ABOVE the mandatory 1-slot-per-engine
    baseline, Σ ceiling·footprint ≤ budget on BOTH RAM and vCPU — i.e. once every engine
    can seat its one guaranteed slot, no further growth oversubscribes the node. The
    baseline itself is unconditional (a WarmPool needs ceiling ≥ 1 to run at all): a node
    too small to seat even one slot per engine is undersized and gets 1 each anyway —
    that's the ONLY case Σ can exceed budget, and it's viability-over-budget by design.
    Warm target then tracks each engine's demand (don't hold the whole node hot when
    idle). min_warm is honoured up to the afforded ceiling; per-engine max_ceiling caps
    growth. A non-positive footprint is clamped to a tiny positive so the water-fill
    always terminates (a 0-RAM slot would otherwise "fit" forever).
    """
    if not specs:
        return {}
    # clamp footprints > 0 so fit() can't loop forever on a mis-declared 0-RAM/0-vCPU slot
    specs = [
        s if (s.slot_ram_mib > 0 and s.slot_vcpus > 0)
        else PoolSpec(name=s.name, slot_ram_mib=max(s.slot_ram_mib, 1.0),
                      slot_vcpus=max(s.slot_vcpus, 0.01), demand=s.demand,
                      min_warm=s.min_warm, max_ceiling=s.max_ceiling)
        for s in specs
    ]

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
        # keep warm what demand needs (honouring the soft floor), never above ceiling.
        # Floor at 0: min_warm/demand are non-negative by contract (and _valid enforces it
        # upstream), but a negative from an out-of-contract caller must never reach
        # WarmPool.resize() as a negative warm target — clamp defensively.
        warm = max(0, min(ceiling, max(s.min_warm, math.ceil(s.demand))))
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
    except (OSError, ValueError, IndexError):
        # malformed/empty/mocked /proc/meminfo (missing column, non-numeric) → 0 budget,
        # a safe degradation (every engine gets the viable baseline), not a crashed tick.
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
    except (OSError, ValueError, IndexError):
        return None                     # malformed/mocked /proc/meminfo → adaptive no-ops safely
    return None


def local_backlog_fn(job_store: object,
                     engine: "str | Iterable[str] | None" = None) -> Callable[[str], int]:
    """QUEUED backlog from the dispatcher's store, scoped to the engine(s) this dispatcher
    serves. Scoping matters on a SHARED multi-engine store (blastbox supports one store
    across engines): without it every dispatcher reports the node-wide queue and balancing
    splits evenly instead of by real demand. A dispatcher serving SEVERAL engines on one
    pool sums their queues (the pool's total demand). None → whole store."""
    from .jobs.base import JobStatus

    engines: Optional[list[str]] = None
    if engine is not None:
        engines = [engine] if isinstance(engine, str) else [e for e in engine if e]

    def _fn(_engine: str = "") -> int:
        try:
            if engines is None:
                return int(job_store.count(JobStatus.QUEUED))  # type: ignore[attr-defined]
            return sum(int(job_store.count(JobStatus.QUEUED, engine=e))  # type: ignore[attr-defined,misc]
                       for e in engines)
        except Exception:
            return 0
    return _fn
