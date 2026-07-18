"""Node pool autosizer: pure allocation math, node-managed-runtime gating (skip
lambda/ec2), live-demand sizing, adaptive budget, and applying via WarmPool.resize()."""

from __future__ import annotations

from blastbox.host.node_sizer import (
    NodeBudget,
    PoolSpec,
    manages,
    node_capacity,
    plan_sizes,
)
from blastbox.host.pool_config import (
    RUNTIME_AWS_EC2,
    RUNTIME_AWS_LAMBDA_MICROVM,
    RUNTIME_FIRECRACKER,
    RUNTIME_GVISOR,
    RUNTIME_STATIC,
)


# --- runtime gating (Will's "skip obvious doesn't-fit like lambda") ---------

def test_manages_only_node_runtimes():
    assert manages(RUNTIME_FIRECRACKER) and manages(RUNTIME_GVISOR)
    assert manages("GVISOR")                       # case-insensitive
    for r in (RUNTIME_AWS_LAMBDA_MICROVM, RUNTIME_AWS_EC2, RUNTIME_STATIC, "none", ""):
        assert not manages(r)


# --- pure allocation --------------------------------------------------------

def test_no_oversubscription_invariant():
    # two engines, 4 GiB budget, 1 GiB slots → at most 4 slots total across both
    specs = [PoolSpec("a", slot_ram_mib=1024, demand=10),
             PoolSpec("b", slot_ram_mib=1024, demand=10)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=4096, vcpus=99))
    total = sum(p.concurrent_ceiling for p in plan.values())
    assert total == 4                              # Σ ceiling·footprint ≤ budget
    # balanced demand → even split
    assert plan["a"].concurrent_ceiling == 2 and plan["b"].concurrent_ceiling == 2


def test_allocates_by_demand():
    # busy engine gets the lion's share of a beefy node; idle keeps its viable baseline (1)
    specs = [PoolSpec("busy", slot_ram_mib=1024, demand=20, max_ceiling=64),
             PoolSpec("idle", slot_ram_mib=1024, demand=0, max_ceiling=64)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=10 * 1024, vcpus=99))
    assert plan["busy"].concurrent_ceiling > plan["idle"].concurrent_ceiling
    assert plan["idle"].concurrent_ceiling == 1    # viable baseline, no more (0 demand)
    assert plan["busy"].concurrent_ceiling + plan["idle"].concurrent_ceiling == 10


def test_respects_per_engine_cap_and_vcpu_budget():
    specs = [PoolSpec("a", slot_ram_mib=512, slot_vcpus=1, demand=99, max_ceiling=3)]
    # RAM allows way more, but max_ceiling caps at 3
    plan = plan_sizes(specs, NodeBudget(ram_mib=100 * 1024, vcpus=99))
    assert plan["a"].concurrent_ceiling == 3
    # vCPU is the binding constraint
    specs2 = [PoolSpec("a", slot_ram_mib=1, slot_vcpus=2, demand=99, max_ceiling=64)]
    plan2 = plan_sizes(specs2, NodeBudget(ram_mib=10 ** 9, vcpus=8))
    assert plan2["a"].concurrent_ceiling == 4      # 8 vCPU / 2 per slot


def test_warm_tracks_demand_not_whole_node():
    # a low-demand engine on a huge node gets a big CEILING (can burst) but a small WARM
    specs = [PoolSpec("a", slot_ram_mib=1024, demand=2, min_warm=1, max_ceiling=64)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=32 * 1024, vcpus=99))
    assert plan["a"].concurrent_ceiling >= 8       # can grow into the node
    assert plan["a"].warm_size == 2                # but only 2 kept hot (demand)


def test_warm_floor_shed_under_tight_budget():
    # both want min_warm=2 (4 warm slots) but the node only affords 3 slots total; the
    # busy engine keeps its floor, the idle engine's floor is shed to its ceiling.
    specs = [PoolSpec("a", slot_ram_mib=1024, demand=0, min_warm=2, max_ceiling=64),
             PoolSpec("b", slot_ram_mib=1024, demand=1, min_warm=2, max_ceiling=64)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=3 * 1024, vcpus=99))
    assert plan["a"].concurrent_ceiling + plan["b"].concurrent_ceiling == 3
    assert plan["b"].warm_size == 2                 # busy engine keeps its warm floor
    assert plan["a"].warm_size == plan["a"].concurrent_ceiling  # idle's floor shed to ceiling
    assert plan["a"].warm_size < 2


def test_empty_specs():
    assert plan_sizes([], NodeBudget(ram_mib=1024, vcpus=8)) == {}


def test_node_capacity_reads_real_node():
    # reads /proc/meminfo + cpu_count on this host; headroom + oversubscription applied
    b = node_capacity(ram_headroom_frac=0.5, vcpu_oversubscription=1.0)
    assert b.ram_mib > 0 and b.vcpus >= 1


# --- round-4: config clamping + optional url ---

def test_from_env_clamps_footgun_config(monkeypatch):
    from blastbox.host.node_config import NodeConfig
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,red")   # url optional (bare names)
    monkeypatch.setenv("BLASTBOX_NODE_BALANCING", "1")
    monkeypatch.setenv("BLASTBOX_NODE_RAM_HEADROOM", "80")    # meant 80% → clamp to 1.0
    monkeypatch.setenv("BLASTBOX_NODE_INTERVAL_S", "0")       # busy-loop → floor
    monkeypatch.setenv("BLASTBOX_NODE_STALE_AFTER_S", "1")    # < interval → raise to 2×
    monkeypatch.setenv("BLASTBOX_NODE_VCPU_OVERSUBSCRIPTION", "999")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "0")  # 0-RAM footgun → clamp
    c = NodeConfig.from_env()
    assert {e.name for e in c.engines} == {"clip", "red"}     # bare names parsed (url optional)
    assert c.ram_headroom_frac == 1.0
    assert c.interval_s >= 0.5
    assert c.stale_after_s >= c.interval_s * 2
    assert c.vcpu_oversubscription <= 64.0
    assert next(e for e in c.engines if e.name == "clip").slot_ram_mib >= 1.0


def test_local_backlog_sums_across_served_engines():
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_sizer import local_backlog_fn
    s = InMemoryJobStore()
    for e in ("clip", "clip", "red"):
        s.create(Job.new(engine=e, filename="x"))
    assert local_backlog_fn(s, ["clip", "red"])() == 3       # multi-engine dispatcher: total
    assert local_backlog_fn(s, "clip")() == 2
