"""Node pool autosizer: pure allocation math, node-managed-runtime gating (skip
lambda/ec2), live-demand sizing, adaptive budget, and applying via WarmPool.resize()."""

from __future__ import annotations

from blastbox.host.node_sizer import (
    ManagedPool,
    NodeAutoSizer,
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


# --- controller with a fake pool -------------------------------------------

class _FakePool:
    def __init__(self, runtime, assigned=0, burst=False):
        self.runtime = runtime
        self.assigned_count = assigned
        self.burst_active = burst
        self.slot_count = assigned
        self.warm_size = 0
        self.concurrent_ceiling = 0
        self.resized: tuple[int, int] | None = None

    def resize(self, *, warm_size, concurrent_ceiling):
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling
        self.resized = (warm_size, concurrent_ceiling)


def _budget(ram, vcpus):
    return lambda h, o: NodeBudget(ram_mib=ram, vcpus=vcpus)


def test_controller_skips_non_node_pools_and_applies():
    fc = _FakePool(RUNTIME_FIRECRACKER, assigned=4)
    lam = _FakePool(RUNTIME_AWS_LAMBDA_MICROVM, assigned=99)
    sizer = NodeAutoSizer(
        [ManagedPool(PoolSpec("clip", slot_ram_mib=1024, max_ceiling=64), fc),
         ManagedPool(PoolSpec("lam", slot_ram_mib=1024, max_ceiling=64), lam)],
        capacity_fn=_budget(8 * 1024, 99))
    plan = sizer.tick()
    assert sizer.managed_names == ["clip"]         # lambda pool dropped
    assert "lam" not in plan
    assert fc.resized is not None                  # firecracker pool got resized
    assert lam.resized is None                     # lambda pool untouched
    assert fc.concurrent_ceiling == 8              # whole node (8 GiB / 1 GiB slots)


def test_controller_demand_from_live_state():
    hot = _FakePool(RUNTIME_FIRECRACKER, assigned=6, burst=True)
    cold = _FakePool(RUNTIME_GVISOR, assigned=0)
    sizer = NodeAutoSizer(
        [ManagedPool(PoolSpec("hot", slot_ram_mib=1024, max_ceiling=64), hot),
         ManagedPool(PoolSpec("cold", slot_ram_mib=1024, max_ceiling=64), cold)],
        capacity_fn=_budget(16 * 1024, 99))
    plan = sizer.tick()
    assert plan["hot"].concurrent_ceiling > plan["cold"].concurrent_ceiling


def test_backlog_drives_scale_up_and_down_to_min():
    # one engine on a big node; demand is driven purely by its QUEUED backlog. min_warm
    # is the floor it returns to once the backlog drains.
    fc = _FakePool(RUNTIME_FIRECRACKER, assigned=0)
    mp = ManagedPool(PoolSpec("clip", slot_ram_mib=1024, min_warm=1, max_ceiling=64), fc)
    backlog = {"n": 0}
    sizer = NodeAutoSizer([mp], backlog_fn=lambda _e: backlog["n"],
                          capacity_fn=_budget(64 * 1024, 999))
    # idle → warm at the floor
    p0 = sizer.plan()["clip"]
    assert p0.warm_size == 1
    # backlog spikes → scale UP (warm tracks backlog)
    backlog["n"] = 12
    p1 = sizer.plan()["clip"]
    assert p1.warm_size == 12 and p1.concurrent_ceiling >= 12
    # backlog drains → scale back DOWN to the min floor
    backlog["n"] = 0
    p2 = sizer.plan()["clip"]
    assert p2.warm_size == 1


def test_backlog_splits_node_between_engines_by_queue():
    a = _FakePool(RUNTIME_FIRECRACKER, assigned=0)
    b = _FakePool(RUNTIME_FIRECRACKER, assigned=0)
    depth = {"a": 30, "b": 3}
    sizer = NodeAutoSizer(
        [ManagedPool(PoolSpec("a", slot_ram_mib=1024, max_ceiling=64), a),
         ManagedPool(PoolSpec("b", slot_ram_mib=1024, max_ceiling=64), b)],
        backlog_fn=lambda e: depth[e], capacity_fn=_budget(10 * 1024, 999))
    plan = sizer.tick()
    assert plan["a"].concurrent_ceiling > plan["b"].concurrent_ceiling
    assert plan["a"].concurrent_ceiling + plan["b"].concurrent_ceiling == 10


def test_run_loop_ticks_and_stops():
    fc = _FakePool(RUNTIME_FIRECRACKER, assigned=2)
    sizer = NodeAutoSizer([ManagedPool(PoolSpec("a", slot_ram_mib=1024), fc)],
                          capacity_fn=_budget(8 * 1024, 99))
    ticks = {"n": 0}
    sizer.run(interval_s=0, max_ticks=3, sleep=lambda _s: ticks.__setitem__("n", ticks["n"] + 1))
    assert fc.resized is not None                  # applied at least once


def test_local_backlog_fn_reads_queued_count():
    from blastbox.host.jobs.base import JobStatus
    from blastbox.host.node_sizer import local_backlog_fn

    class _Store:
        def count(self, status=None, *, q=None):
            return 7 if status == JobStatus.QUEUED else 99
    fn = local_backlog_fn(_Store())
    assert fn("clip") == 7                          # only QUEUED counted


def test_adaptive_shrinks_when_node_hot():
    fc = _FakePool(RUNTIME_FIRECRACKER, assigned=2)
    mp = ManagedPool(PoolSpec("a", slot_ram_mib=1024, max_ceiling=64), fc)
    # static budget = 16 slots; adaptive with free RAM under the floor should shrink it
    static = NodeAutoSizer([mp], adaptive=False, capacity_fn=_budget(16 * 1024, 99))
    adapt = NodeAutoSizer([mp], adaptive=True, min_free_mib=4096,
                          capacity_fn=_budget(16 * 1024, 99),
                          avail_fn=lambda: 1024.0)   # node nearly full
    s0 = static.plan()["a"].concurrent_ceiling
    # one tick nudges the scale down; several drive it lower
    for _ in range(5):
        a = adapt.plan()["a"].concurrent_ceiling
    assert a < s0
