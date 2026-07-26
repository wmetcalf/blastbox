"""Node pool autosizer: pure allocation math, node-managed-runtime gating (skip
lambda/ec2), live-demand sizing, adaptive budget, and applying via WarmPool.resize()."""

from __future__ import annotations

from blastbox.host.node_sizer import (
    NodeBudget,
    PoolSpec,
    manages,
    node_capacity,
    plan_sizes,
    unseatable_floors,
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


# --- all-local cascade enrollment (feature: budget a cascade whose members are all fc/gvisor) --

class _FakeTier:
    def __init__(self, name):
        self.name = name


class _FakeCascade:
    kind = "cascade"

    def __init__(self, *member_names):
        self.tiers = [_FakeTier(n) for n in member_names]


class _FakeGvisorRuntime:
    kind = "gvisor"


def test_cascade_all_local_true_for_fc_gvisor_members():
    from blastbox.host.node_sizer import cascade_all_local

    assert cascade_all_local(_FakeCascade("firecracker", "gvisor"))
    assert cascade_all_local(_FakeCascade("gvisor"))            # single local member
    assert cascade_all_local(_FakeCascade("firecracker", "firecracker"))


def test_cascade_all_local_false_with_any_offnode_member():
    from blastbox.host.node_sizer import cascade_all_local

    # ANY off-node member (cloud/static/remote) disqualifies the WHOLE cascade — its ceiling then
    # contains slots that don't live on this node, so it must not enter the local water-fill.
    assert not cascade_all_local(_FakeCascade("firecracker", "aws-ec2"))
    assert not cascade_all_local(_FakeCascade("gvisor", "static"))
    assert not cascade_all_local(_FakeCascade("aws-lambda-microvm"))
    assert not cascade_all_local(_FakeCascade("firecracker", "libvirt-vm"))  # file but not managed


def test_cascade_all_local_false_for_non_cascade_or_malformed():
    from blastbox.host.node_sizer import cascade_all_local

    assert not cascade_all_local(_FakeGvisorRuntime())         # a plain fc/gvisor runtime, not a cascade
    assert not cascade_all_local(None)                          # pool with no runtime
    assert not cascade_all_local(_FakeCascade())                # empty cascade (no members)
    assert not cascade_all_local(object())                      # no .kind / .tiers

    class _BadTiers:
        kind = "cascade"
        tiers = 5                                               # not iterable

    assert not cascade_all_local(_BadTiers())

    # A non-string Tier.name must fail CLOSED (not crash): manages() rejects non-strings, so an
    # adversarial/garbled member is treated as off-node → the whole cascade stays unmanaged.
    assert not cascade_all_local(_FakeCascade(None))            # name is None
    assert not cascade_all_local(_FakeCascade(5))               # name is an int
    assert not cascade_all_local(_FakeCascade("firecracker", None))  # one good, one garbled
    assert not cascade_all_local(type("_C", (), {"kind": "cascade", "tiers": [object()]})())  # no .name


class _FakeCapTier:
    def __init__(self, name, capacity):
        self.name = name
        self.capacity = capacity


class _FakeCapCascade:
    kind = "cascade"

    def __init__(self, *pairs):
        self.tiers = [_FakeCapTier(n, c) for n, c in pairs]


def test_cascade_capacity_sums_surviving_tier_capacities():
    from blastbox.host.node_sizer import cascade_capacity

    assert cascade_capacity(_FakeCapCascade(("firecracker", 4), ("gvisor", 8))) == 12
    assert cascade_capacity(_FakeCapCascade(("firecracker", 4))) == 4   # overflow tier skipped at boot
    assert cascade_capacity(_FakeCapCascade()) == 0                      # empty → 0, not None


def test_cascade_capacity_none_for_non_cascade_and_conservative_on_garbled():
    from blastbox.host.node_sizer import cascade_capacity

    assert cascade_capacity(None) is None                               # not a cascade → leave uncapped
    assert cascade_capacity(object()) is None
    assert cascade_capacity(type("_C", (), {"kind": "cascade", "tiers": 5})()) == 0   # non-iterable
    # a garbled/missing capacity contributes 0 (never inflates the cap)
    assert cascade_capacity(_FakeCapCascade(("firecracker", "oops"), ("gvisor", 8))) == 8
    assert cascade_capacity(type("_C", (), {"kind": "cascade", "tiers": [object()]})()) == 0  # no .capacity


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


def test_reserved_is_a_hard_ceiling_floor():
    # PR #60 codex P1: a pool physically running `reserved` slots (resident warm + cold in flight)
    # must not be allocated FEWER — resize() only lowers setpoints, VMs drain later, and a smaller
    # advertised ceiling would let a peer grow into still-in-use capacity → oversubscription.
    # A: 8 reserved but LOW demand; B: no reserved but huge backlog. A keeps its 8 floor.
    specs = [PoolSpec("a", slot_ram_mib=1024, demand=1, max_ceiling=64, reserved=8),
             PoolSpec("b", slot_ram_mib=1024, demand=100, max_ceiling=64, reserved=0)]
    plan = plan_sizes(specs, NodeBudget(ram_mib=10 * 1024, vcpus=999))
    assert plan["a"].concurrent_ceiling >= 8      # in-use slots preserved as a floor, despite low demand
    assert plan["a"].concurrent_ceiling + plan["b"].concurrent_ceiling <= 10   # no oversubscription


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


def test_from_env_clamps_published_stale_after_to_reader_bound(monkeypatch):
    # PR #60 codex P2: stale_after_s is now PUBLISHED, so a huge finite value (1e100) that _float
    # accepts would be REJECTED by node_share._valid (> _MAX_TS) → snapshot dropped → pool stays
    # throttled. Clamp to the reader's honored lifetime cap (300s) so the snapshot always validates.
    from blastbox.host.node_config import NodeConfig, _MAX_STALE_AFTER_S
    from blastbox.host.node_share import DemandSnapshot, _valid
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_STALE_AFTER_S", "1e100")
    c = NodeConfig.from_env()
    assert c.stale_after_s <= _MAX_STALE_AFTER_S == 300.0
    # a snapshot carrying this stale_after must PASS the reader's validation (not be dropped)
    snap = DemandSnapshot("clip", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                          tier="firecracker", instance="i", stale_after_s=c.stale_after_s)
    assert _valid(snap)


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
    assert _MAX_INTERVAL_S <= 150.0            # ≤ GC floor / 2, so a beat can't expire between ticks
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


# --- min_warm floor feasibility: surface silent over-subscription (issue #68) ---

def _sz(name, ram, demand, min_warm, cap=64):
    return PoolSpec(name=name, slot_ram_mib=ram, slot_vcpus=1.0,
                    demand=demand, min_warm=min_warm, max_ceiling=cap)


def test_unseatable_floors_flags_starved_engine():
    # The production wedge: a 62 GiB node (budget ~53 GiB) can't seat BOTH
    # clippyshot's 12x4096 MiB (~48 GiB) warm floor AND redtusk's 8x2048 MiB (~16 GiB).
    # Under simultaneous demand the higher-demand engine seats its floor; the other is
    # silently clamped to ceiling=1 (warm below its min_warm). unseatable_floors must
    # NAME the starved engine so the controller can warn instead of wedging silently.
    budget = NodeBudget(ram_mib=53_000, vcpus=100)   # RAM is the binding resource here
    clippy = _sz("clippyshot", ram=4096, demand=12, min_warm=12)
    redtusk = _sz("redtusk", ram=2048, demand=8, min_warm=8)

    starved = unseatable_floors([clippy, redtusk], budget)

    assert "redtusk" in starved, starved
    got, want = starved["redtusk"]
    assert want == 8 and got < 8            # floor requested 8, seated fewer
    # sanity: the plan itself confirms the silent violation this helper detects
    assert plan_sizes([clippy, redtusk], budget)["redtusk"].warm_size == got


def test_unseatable_floors_empty_when_all_floors_fit():
    # Same node, but clippyshot capped to a 6-slot warm floor (~24 GiB): 24 + 16 = 40 < 53,
    # so both floors fit and nothing is starved.
    budget = NodeBudget(ram_mib=53_000, vcpus=100)
    clippy = _sz("clippyshot", ram=4096, demand=12, min_warm=6)
    redtusk = _sz("redtusk", ram=2048, demand=8, min_warm=8)

    assert unseatable_floors([clippy, redtusk], budget) == {}
    # and both floors are actually honored in the plan
    plan = plan_sizes([clippy, redtusk], budget)
    assert plan["clippyshot"].warm_size >= 6 and plan["redtusk"].warm_size >= 8


def test_unseatable_floors_ignores_floor_above_its_own_cap():
    # min_warm > max_ceiling is a config choice (the cap wins), NOT starvation: the
    # helper compares against min(min_warm, max_ceiling), so it must stay quiet here.
    budget = NodeBudget(ram_mib=53_000, vcpus=100)
    solo = _sz("redtusk", ram=2048, demand=4, min_warm=10, cap=4)   # cap 4 < floor 10
    assert unseatable_floors([solo], budget) == {}


def test_min_warm_shrinks_proportionally_not_clamped_to_one():
    # issue #68 fix: on an over-subscribed node (12x4096 + 8x2048 = 64 GiB > 53 GiB budget) the
    # floors SHRINK PROPORTIONALLY — neither engine is clamped to the 1-slot baseline (which would
    # requeue-wedge a warm-only dispatcher). Both keep a functional warm pool; cold is never used.
    budget = NodeBudget(ram_mib=53_000, vcpus=999)
    clippy = _sz("clippyshot", ram=4096, demand=40, min_warm=12)   # higher demand
    redtusk = _sz("redtusk", ram=2048, demand=8, min_warm=8)       # lower demand — must NOT be starved to 1
    plan = plan_sizes([clippy, redtusk], budget)

    assert plan["redtusk"].warm_size >= 4, plan        # was 1 under the old demand-priority clamp
    assert plan["clippyshot"].warm_size >= 8, plan
    # proportional: similar FRACTION of each declared floor (not winner-take-all)
    r_frac = plan["redtusk"].warm_size / 8
    c_frac = plan["clippyshot"].warm_size / 12
    assert abs(r_frac - c_frac) <= 0.25, (r_frac, c_frac)
    # never oversubscribed
    assert (plan["redtusk"].warm_size * 2048
            + plan["clippyshot"].warm_size * 4096) <= budget.ram_mib
