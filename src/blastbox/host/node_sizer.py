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


def cascade_all_local(runtime: object) -> bool:
    """True if ``runtime`` is a cascade whose EVERY member tier runs on a node-managed LOCAL
    backend (firecracker/gvisor).

    A ``cascade`` runtime (``runtime.host.cascade.CascadingRuntime``) composes an ordered list of
    member tiers — ``runtime.tiers``, each a ``Tier(name, runtime, capacity)`` — and its pool
    ceiling (``BLASTBOX_POOL_CEILING``) is the SUM of the members' capacities. ``manages()`` is
    False for the bare name ``"cascade"``, so such a pool is NOT node-sized by default even though
    its slots consume real node RAM — an all-local cascade would then run OUTSIDE the water-fill
    and oversubscribe the node against sibling fc/gvisor pools.

    Only an ALL-LOCAL cascade is safe to enroll: then its whole ceiling is THIS node's RAM, so the
    autosizer can budget it exactly like any warm pool (max member footprint · ceiling ≤ budget).
    A cascade with ANY off-node member (aws-*, static, remote) has cloud/other-host slots inside
    that same ceiling — folding the whole ceiling into the LOCAL budget would over-reserve local
    RAM and mis-shed under memory pressure — so it stays UNMANAGED (fail-closed), exactly as before.

    Member identity is the parsed ``BLASTBOX_POOL_TIERS`` backend NAME (``Tier.name``, e.g.
    ``firecracker``/``gvisor``/``aws-ec2``), which ``select_runtime_by_name`` matches EXACTLY (no
    aliases) — the same names ``manages()`` checks. A non-cascade runtime, an empty/malformed
    cascade, or a member whose backend isn't a recognized local runtime → False (fail-closed)."""
    if getattr(runtime, "kind", None) != "cascade":
        return False
    members = getattr(runtime, "tiers", None)
    try:
        members = list(members)  # type: ignore[arg-type]
    except TypeError:
        return False
    if not members:
        return False
    return all(manages(getattr(t, "name", "")) for t in members)


def cascade_capacity(runtime: object) -> "int | None":
    """The number of slots an all-local cascade can ACTUALLY spawn — the sum of its SURVIVING
    members' ``Tier.capacity`` — or ``None`` if ``runtime`` isn't a cascade (so callers can leave
    non-cascade pools unchanged).

    ``build_cascade_runtime`` SKIPS an overflow tier that is unavailable at boot (e.g. gVisor/runsc
    missing), so ``runtime.tiers`` can carry FEWER slots than ``BLASTBOX_POOL_CEILING`` was
    configured for. The autosizer must cap the cascade's warm target at THIS number, not the
    configured ceiling: otherwise it reserves warm slots the runtime can never spawn
    (``CascadeExhausted``) and — because the cold-admission gate is ``ceiling − warm reservation`` —
    it starves the cold path of the freed budget (only 1 cold worker despite idle capacity), which
    with ``BLASTBOX_MAX_QUEUED_AGE_S`` can even age out + delete jobs while the node sits underused.

    Fail-closed on a malformed cascade (non-iterable ``tiers``, a member missing or non-int
    ``capacity``) → ``0`` for that member, so the cap is conservative (never inflates capacity)."""
    if getattr(runtime, "kind", None) != "cascade":
        return None
    members = getattr(runtime, "tiers", None)
    try:
        members = list(members)  # type: ignore[arg-type]
    except TypeError:
        return 0
    total = 0
    for t in members:
        try:
            total += max(0, int(getattr(t, "capacity", 0)))
        except (TypeError, ValueError):
            continue          # a garbled capacity contributes 0 (conservative)
    return total


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
    reserved: int = 0                    # slots this pool is ALREADY consuming (resident warm +
                                         # cold in flight). A HARD ceiling floor: the allocator
                                         # must not hand this pool fewer slots than it's physically
                                         # running, or a peer would grow into capacity that's still
                                         # in use (resize() shrinks setpoints; VMs drain later).


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
    idle). min_warm is RESERVED before demand-filling — a real latency floor a busy
    neighbour can't starve — bounded by the budget and, when the floors can't all fit,
    seated by demand priority. per-engine max_ceiling caps growth. A non-positive footprint
    is clamped to a tiny positive so the water-fill always terminates (a 0-RAM slot would
    otherwise "fit" forever).
    """
    if not specs:
        return {}
    # clamp footprints > 0 so fit() can't loop forever on a mis-declared 0-RAM/0-vCPU slot
    specs = [
        s if (s.slot_ram_mib > 0 and s.slot_vcpus > 0)
        else PoolSpec(name=s.name, slot_ram_mib=max(s.slot_ram_mib, 1.0),
                      slot_vcpus=max(s.slot_vcpus, 0.01), demand=s.demand,
                      min_warm=s.min_warm, max_ceiling=s.max_ceiling, reserved=s.reserved)
        for s in specs
    ]

    # Hard baseline: every managed pool must be able to run at least one job, so ceiling
    # starts at 1 (WarmPool requires ceiling >= 1). This is counted against the budget;
    # if even the 1-per-engine baseline exceeds the budget the node is simply undersized
    # and we don't shed below 1 (a pool that can't run is useless).
    alloc: dict[str, int] = {s.name: 1 for s in specs}
    used_ram = sum(s.slot_ram_mib for s in specs)
    used_vcpu = sum(s.slot_vcpus for s in specs)

    def budget_has_room(s: PoolSpec) -> bool:
        return (used_ram + s.slot_ram_mib <= budget.ram_mib
                and used_vcpu + s.slot_vcpus <= budget.vcpus)

    # RESERVED (in-use) FLOOR — seated FIRST, before any other allocation. A pool that is
    # physically running `reserved` slots (resident warm VMs + cold workers in flight) must not be
    # allocated fewer than that: resize() only lowers setpoints, so those VMs drain over later pool
    # ticks, and if we advertised a smaller ceiling a peer would grow into capacity that's STILL in
    # use → node oversubscription. This is the ceiling analogue of min_warm, but it takes priority
    # (it's real current consumption, not a latency target). Bounded by max_ceiling and the budget;
    # if reservations can't all fit the node is already transiently over-committed and we seat by
    # demand priority (busy pools' in-use slots first) — the plan can't un-spend RAM already spent.
    while True:
        below = [s for s in specs
                 if alloc[s.name] < min(s.reserved, s.max_ceiling) and budget_has_room(s)]
        if not below:
            break
        pick = max(below, key=lambda s: s.demand)
        alloc[pick.name] += 1
        used_ram += pick.slot_ram_mib
        used_vcpu += pick.slot_vcpus

    # min_warm RESERVATION: seat each pool's warm floor BEFORE demand-filling, so a latency
    # floor is a real reservation — an idle pool with min_warm=N keeps N hot even when a busy
    # neighbour wants the budget (a soft floor a neighbour could starve isn't a floor). Bounded
    # by the budget (never over-commits above the baseline); when Σ min_warm can't all fit, the
    # floors are seated by demand priority, so a busy pool's floor beats an idle pool's.
    while True:
        below = [s for s in specs
                 if alloc[s.name] < min(s.min_warm, s.max_ceiling) and budget_has_room(s)]
        if not below:
            break
        pick = max(below, key=lambda s: s.demand)      # busy floors first under contention
        alloc[pick.name] += 1
        used_ram += pick.slot_ram_mib
        used_vcpu += pick.slot_vcpus

    # Water-fill the remaining budget one slot at a time to the most-starved engine
    # (highest demand relative to what it already has), respecting caps + footprint.
    def fits(s: PoolSpec) -> bool:
        return alloc[s.name] < s.max_ceiling and budget_has_room(s)

    # Per-slot cost as a fraction of the node budget, taking the BINDING resource (whichever
    # of RAM/vCPU is tighter for THIS pool). Dividing the water-fill score by this makes
    # `demand`/`weight` buy a share of the node's actual bottleneck resource, not just RAM:
    # two equal-weight pools that differ only in slot_vcpus get equal CPU share on a
    # vCPU-bound node (and equal RAM on a RAM-bound one). Budget dims are >0 (headroom/
    # oversub clamps + cpu_count>=1); guard anyway.
    def slot_cost(s: PoolSpec) -> float:
        ram_frac = s.slot_ram_mib / budget.ram_mib if budget.ram_mib > 0 else 0.0
        vcpu_frac = s.slot_vcpus / budget.vcpus if budget.vcpus > 0 else 0.0
        return max(ram_frac, vcpu_frac, 1e-12)

    while True:
        cands = [s for s in specs if fits(s)]
        if not cands:
            break
        # Diminishing returns, normalised by the BINDING-resource cost: (demand + epsilon) /
        # (share of the bottleneck resource the pool would then hold). So demand/weight buys a
        # share of the node's tight resource, not a raw slot count — with heterogeneous
        # footprints two equal-weight pools get equal RESOURCE (a 4 GiB / 4 vCPU pool gets
        # ~1/4 the slots of a 1 GiB / 1 vCPU one), not equal slots. Same-footprint pools are
        # unaffected. A tie or zero-demand engine still fills a beefy node after busy ones are
        # satisfied, up to its cap.
        pick = max(cands, key=lambda s: (s.demand + 1e-3) / ((alloc[s.name] + 1) * slot_cost(s)))
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


def unseatable_floors(
    specs: list[PoolSpec], budget: NodeBudget
) -> dict[str, tuple[int, int]]:
    """Engines whose ``min_warm`` floor ``plan_sizes`` could NOT fully seat within the
    budget, mapped to ``(granted_warm, wanted_floor)``. Empty when every floor fits.

    ``plan_sizes`` reserves ``min_warm`` by demand priority and, when the floors can't
    all fit the node budget, silently clamps the loser's ceiling to the 1-slot baseline —
    so its warm target lands BELOW ``min_warm`` with no signal in the returned plan. On a
    ``BLASTBOX_DISPATCH_WARM_ONLY`` dispatcher that starved pool then wedges (every job
    requeues, no cold fallback) with no diagnostic. This pure companion re-derives the
    plan and reports which floors were starved so the controller can WARN — turning a
    silent, fleet-wide over-subscription into a visible, actionable one. See issue #68.

    A ``min_warm`` above the pool's own ``max_ceiling`` is a config choice (the cap wins),
    NOT starvation, so the comparison is against ``min(min_warm, max_ceiling)``.
    """
    plan = plan_sizes(specs, budget)
    starved: dict[str, tuple[int, int]] = {}
    for s in specs:
        wanted = min(s.min_warm, s.max_ceiling)
        got = plan[s.name].warm_size
        if wanted > 0 and got < wanted:
            starved[s.name] = (got, wanted)
    return starved


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
                     engine: "str | Iterable[str] | None" = None,
                     claimant_tier: "str | None" = None,
                     untargeted_only: bool = False) -> Callable[[str], int]:
    """QUEUED backlog from the dispatcher's store, scoped to the engine(s) this dispatcher
    serves. Scoping matters on a SHARED multi-engine store (blastbox supports one store
    across engines): without it every dispatcher reports the node-wide queue and balancing
    splits evenly instead of by real demand. A dispatcher serving SEVERAL engines on one
    pool sums their queues (the pool's total demand). None → whole store.

    ``claimant_tier`` scopes the count to jobs THIS dispatcher can actually claim (same
    ``target_tier`` routing as ``claim_next``): a warm/gvisor sizer must not grow its pool
    for jobs pinned to another tier (e.g. ``cold``) that it can never drain and that would
    steal node budget from peers with claimable work. None → count all tiers."""
    from .jobs.base import JobStatus

    engines: Optional[list[str]] = None
    if engine is not None:
        engines = [engine] if isinstance(engine, str) else [e for e in engine if e]

    def _fn(_engine: str = "") -> int:
        # ONE store call for the whole served set (count() takes a collection), so a
        # multi-engine dispatcher's backlog is a single scan/query, not one per engine.
        # Do NOT swallow a store error into 0 — a transient Redis/SQL failure would then look
        # like an EMPTY queue and shrink the warm target to its floor (handing capacity to peers)
        # even though the queue is unchanged. Let it propagate so the sizer's count wrapper falls
        # back to the LAST-KNOWN backlog instead of a false zero.
        return int(job_store.count(JobStatus.QUEUED,  # type: ignore[attr-defined]
                                   engine=engines, claimant_tier=claimant_tier,
                                   untargeted_only=untargeted_only))
    return _fn
