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


def test_resource_share_normalizes_by_binding_vcpu():
    # PR #60 r13: when vCPU (not RAM) is the binding budget, equal-weight/equal-RAM pools with
    # different slot_vcpus get an equal CPU share, not equal slots.
    specs = [PoolSpec("a", slot_ram_mib=1024, slot_vcpus=1, demand=5, max_ceiling=99),
             PoolSpec("b", slot_ram_mib=1024, slot_vcpus=4, demand=5, max_ceiling=99)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=100 * 1024, vcpus=20))     # RAM huge, vCPU tight
    a_cpu = plan["a"].concurrent_ceiling * 1
    b_cpu = plan["b"].concurrent_ceiling * 4
    assert plan["a"].concurrent_ceiling > plan["b"].concurrent_ceiling     # a gets more slots
    assert abs(a_cpu - b_cpu) <= 4                                         # ~equal vCPU share
    assert a_cpu + b_cpu <= 20                                             # within vCPU budget


def test_weight_allocates_resource_share_not_slot_count():
    # PR #60 r12: equal-weight/equal-demand pools with DIFFERENT footprints get an equal RAM
    # SHARE, not equal slot counts — a 4 GiB pool gets ~1/4 the slots of a 1 GiB one, so both
    # use ~the same RAM (not the 4x a slot-count split would hand the big pool).
    specs = [PoolSpec("small", slot_ram_mib=1024, demand=5, max_ceiling=64),
             PoolSpec("big", slot_ram_mib=4096, demand=5, max_ceiling=64)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=20 * 1024, vcpus=9999))    # 20 GiB
    small_ram = plan["small"].concurrent_ceiling * 1024
    big_ram = plan["big"].concurrent_ceiling * 4096
    assert plan["small"].concurrent_ceiling > plan["big"].concurrent_ceiling   # more small slots
    assert abs(small_ram - big_ram) <= 4096                                    # ~equal RAM share
    assert small_ram + big_ram <= 20 * 1024                                    # within budget


def test_min_warm_reserved_before_busy_demand():
    # PR #60 r12: min_warm is now a RESERVED floor, not soft — an IDLE latency-critical pool
    # keeps its min_warm hot even when a busy neighbour wants the whole budget.
    specs = [PoolSpec("idle", slot_ram_mib=1024, demand=0, min_warm=4, max_ceiling=64),
             PoolSpec("busy", slot_ram_mib=1024, demand=50, min_warm=0, max_ceiling=64)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=5 * 1024, vcpus=99))        # 5 slots
    assert plan["idle"].warm_size == 4                                      # floor honoured...
    assert plan["idle"].concurrent_ceiling >= 4
    assert plan["busy"].concurrent_ceiling == 1                            # ...even over demand
    # never over budget
    assert sum(p.concurrent_ceiling for p in plan.values()) == 5


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


def test_warm_never_negative_on_out_of_contract_input():
    # defense-in-depth (round-9): min_warm/demand are non-negative by contract (and _valid
    # enforces it upstream), but plan_sizes must never emit a negative warm target — it
    # would crash WarmPool.resize(warm_size<0). A negative min_warm/demand clamps to 0.
    plan = plan_sizes([PoolSpec("a", slot_ram_mib=10, demand=-5.0, min_warm=-3, max_ceiling=4)],
                      NodeBudget(ram_mib=1000, vcpus=100))
    assert plan["a"].warm_size == 0
    assert plan["a"].concurrent_ceiling >= 1


def test_empty_specs():
    assert plan_sizes([], NodeBudget(ram_mib=1024, vcpus=8)) == {}


def test_node_capacity_reads_real_node():
    # reads /proc/meminfo + cpu_count on this host; headroom + oversubscription applied
    b = node_capacity(ram_headroom_frac=0.5, vcpu_oversubscription=1.0)
    assert b.ram_mib > 0 and b.vcpus >= 1


def test_node_capacity_survives_malformed_meminfo(monkeypatch, tmp_path):
    # regression (PR #60 review): a malformed/empty /proc/meminfo (missing column,
    # non-numeric) must degrade to a 0 RAM budget, not crash the sizer tick.
    import builtins
    bad = tmp_path / "meminfo"
    bad.write_text("MemTotal:\nGarbage line without colon\nMemAvailable: notanumber kB\n")
    real_open = builtins.open

    def fake_open(path, *a, **k):
        return real_open(bad if path == "/proc/meminfo" else path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    b = node_capacity(ram_headroom_frac=0.8, vcpu_oversubscription=2.0)
    assert b.ram_mib == 0.0 and b.vcpus >= 1          # safe degradation, no exception
    from blastbox.host.node_sizer import _mem_available_mib
    assert _mem_available_mib() is None               # malformed MemAvailable → None


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


def test_from_env_rejects_unsafe_engine_name(monkeypatch):
    # regression (PR #60 P2): an engine name becomes part of the snapshot filename, so a
    # path separator / '..' must be rejected at config load (backed by publish's hard guard).
    import pytest

    from blastbox.host.node_config import NodeConfig
    for bad in ("ev/il", "../escape", "a\\b", ".."):
        monkeypatch.setenv("BLASTBOX_NODE_ENGINES", bad)
        with pytest.raises(ValueError):
            NodeConfig.from_env()


def test_from_env_rejects_non_finite_intervals(monkeypatch):
    # regression (PR #60 review): inf/nan durations slip past float() and max()/min() don't
    # tame them — an infinite interval makes time.sleep(inf) raise OverflowError and kill the
    # sizer thread. Non-finite env values must fall back to finite defaults.
    from blastbox.host.node_config import NodeConfig
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_INTERVAL_S", "inf")
    monkeypatch.setenv("BLASTBOX_NODE_STALE_AFTER_S", "nan")
    monkeypatch.setenv("BLASTBOX_NODE_RAM_HEADROOM", "inf")
    monkeypatch.setenv("BLASTBOX_NODE_MIN_FREE_MIB", "nan")
    c = NodeConfig.from_env()
    import math as _m
    assert _m.isfinite(c.interval_s) and c.interval_s >= 0.5
    assert _m.isfinite(c.stale_after_s) and c.stale_after_s >= c.interval_s * 2
    assert _m.isfinite(c.ram_headroom_frac) and 0.0 < c.ram_headroom_frac <= 1.0
    assert _m.isfinite(c.min_free_mib)


def test_from_env_clamps_huge_finite_interval_to_time_t_safe(monkeypatch):
    # regression (PR #60 codex P2): a finite-but-huge interval (e.g. 1e10) PASSES the non-finite
    # guard, then OverflowError-s in stop.wait()/time.sleep() ("timestamp out of range for
    # platform time_t") — OUTSIDE the tick handler — killing the sizing thread while its pool
    # keeps its last allocation (peers later expire it and reallocate). Clamp to a safe upper
    # bound, and prove the clamped value survives the exact call the sizer makes.
    import threading

    from blastbox.host.node_config import NodeConfig, _MAX_INTERVAL_S
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_INTERVAL_S", "10000000000")   # 1e10 s
    c = NodeConfig.from_env()
    assert c.interval_s <= _MAX_INTERVAL_S
    assert c.stale_after_s >= c.interval_s * 2
    # The sizer's run() blocks on stop.wait(interval_s), which converts the timeout to a
    # time_t deadline. Exercise that exact C conversion WITHOUT blocking: acquiring a free lock
    # with a timeout converts the deadline eagerly, then returns immediately. The clamped value
    # must convert cleanly; the raw 1e10 would OverflowError on the same call.
    import pytest
    assert threading.Lock().acquire(timeout=c.interval_s) is True   # clamped: no overflow
    with pytest.raises(OverflowError):
        threading.Lock().acquire(timeout=1e10)                      # raw: crashes the sizer thread


def test_from_env_output_always_passes_reader_validation(monkeypatch):
    # regression (round-8): from_env is the WRITER of a dispatcher's own snapshot; every
    # EngineNode it produces must round-trip through node_share._valid, or the engine's
    # self-snapshot is silently dropped from its own + peers' node view → it never sizes
    # and peers oversubscribe. Absurd min_warm/weight must be clamped to the reader's caps.
    from blastbox.host.node_config import NodeConfig
    from blastbox.host.node_share import DemandSnapshot, _valid
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_BALANCING", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MIN_WARM", "5000")      # > _MAX_CEILING_SANE
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_WEIGHT", "2000000")     # > _MAX_WEIGHT
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "999999")  # > _MAX_CEILING_SANE
    e = NodeConfig.from_env().engines[0]
    snap = DemandSnapshot(e.name, 0, 0, e.slot_ram_mib, e.slot_vcpus,
                          e.min_warm, e.max_ceiling, e.weight, ts=1.0, node="")
    assert _valid(snap)                  # writer's output survives the reader → no self-eviction


def test_from_env_rejects_bad_boolean(monkeypatch):
    # PR #60 r13: a misspelled bool (flase) must NOT be treated as True and silently enable
    # hard-cap management + forced warm_only + startup pre-shrinking.
    import pytest

    from blastbox.host.node_config import NodeConfig
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_BALANCING", "flase")
    with pytest.raises(ValueError):
        NodeConfig.from_env()


def test_from_env_rejects_env_prefix_collision(monkeypatch):
    # PR #60 r14: two names normalising to the same env prefix (foo-bar vs foo_bar) would read
    # identical BLASTBOX_NODE_ENGINE_<NAME>_* vars — reject the ambiguity.
    import pytest

    from blastbox.host.node_config import NodeConfig
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "foo-bar,foo_bar")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    with pytest.raises(ValueError):
        NodeConfig.from_env()


def test_from_env_rejects_duplicate_engines(monkeypatch):
    # PR #60 r13: a repeated engine would double-count (doubled weight in static mode) — reject.
    import pytest

    from blastbox.host.node_config import NodeConfig
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,clip,red")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    with pytest.raises(ValueError):
        NodeConfig.from_env()


def test_count_accepts_engine_collection():
    # PR #60 r13: count() takes a COLLECTION so a multi-engine backlog is ONE store scan, not
    # one per engine (a full Redis SCAN each).
    from blastbox.host.jobs.base import Job, JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    s = InMemoryJobStore()
    for e in ("clip", "clip", "red", "titan"):
        s.create(Job.new(engine=e, filename="x"))
    assert s.count(JobStatus.QUEUED, engine=["clip", "red"]) == 3      # one pass, both engines
    assert s.count(JobStatus.QUEUED, engine=["clip"]) == 2
    assert s.count(JobStatus.QUEUED, engine="titan") == 1             # single name still works


def test_local_backlog_sums_across_served_engines():
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_sizer import local_backlog_fn
    s = InMemoryJobStore()
    for e in ("clip", "clip", "red"):
        s.create(Job.new(engine=e, filename="x"))
    assert local_backlog_fn(s, ["clip", "red"])() == 3       # multi-engine dispatcher: total
    assert local_backlog_fn(s, "clip")() == 2


def test_local_backlog_scopes_to_claimable_tier():
    # regression (PR #60 review): a tiered dispatcher must count only jobs it can CLAIM —
    # target_tier routing means a job pinned to another tier is undrainable here, so sizing
    # the pool for it would steal node budget. Mirrors claim_next(claimant_tier=).
    from blastbox.host.jobs.base import Job, JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_sizer import local_backlog_fn
    s = InMemoryJobStore()

    def _job(fn, tier=None):
        j = Job.new(engine="clip", filename=fn)
        j.target_tier = tier
        return j

    s.create(_job("a"))                        # untargeted
    s.create(_job("b", "firecracker"))
    s.create(_job("c", "cold"))                # not claimable by a firecracker dispatcher
    # a firecracker sizer counts the untargeted + fc-pinned (2), NOT the cold-pinned one
    assert local_backlog_fn(s, "clip", claimant_tier="firecracker")() == 2
    assert local_backlog_fn(s, "clip", claimant_tier="cold")() == 2       # untargeted + cold
    assert local_backlog_fn(s, "clip")() == 3                            # no tier filter = all
    # count() mirrors claim_next's predicate directly
    assert s.count(JobStatus.QUEUED, engine="clip", claimant_tier="firecracker") == 2
