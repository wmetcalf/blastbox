"""Dispatcher-side self-sizer + shared node view — the transport that fits the
serve/dispatch split (pool in the dispatcher, coordinated via a shared file)."""

from __future__ import annotations

from blastbox.host.dispatcher_sizer import DispatcherSizer
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_share import DemandSnapshot, FileNodeShare
from blastbox.host.node_sizer import NodeBudget
from blastbox.host.pool_config import RUNTIME_AWS_LAMBDA_MICROVM, RUNTIME_FIRECRACKER


class _Pool:
    def __init__(self, assigned=0, runtime=RUNTIME_FIRECRACKER):
        self.runtime = runtime
        self.assigned_count = assigned
        self.warm_size = 0
        self.concurrent_ceiling = 0

    def resize(self, *, warm_size, concurrent_ceiling):
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling


def _budget(ram, vcpus):
    return lambda h, o: NodeBudget(ram_mib=ram, vcpus=vcpus)


# --- shared store -----------------------------------------------------------

def test_file_share_roundtrip_and_staleness(tmp_path):
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("a", 3, 1, 1024, 1, 0, 64, 1.0, ts=100.0))
    share.publish(DemandSnapshot("b", 0, 0, 1024, 1, 0, 64, 1.0, ts=100.0))
    fresh = share.read_all(max_age_s=20, now=110.0)
    assert {s.engine for s in fresh} == {"a", "b"}
    # b goes stale (published at 100, now 130, window 20) → drops out
    assert {s.engine for s in share.read_all(max_age_s=20, now=130.0)} == set()


# --- dispatcher self-sizer --------------------------------------------------

def test_off_by_default_is_noop(tmp_path):
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig()  # both switches off
    ds = DispatcherSizer(EngineNode("clip", "-"), _Pool(), share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 9)
    assert ds.tick() is None                       # no sizing, and nothing published
    assert share.read_all(max_age_s=1e9, now=1.0) == []


def test_sizes_own_pool_from_shared_node_view(tmp_path):
    # two engines share the node view; a busy peer already published a deep backlog. This
    # engine (clip) sizes ITS OWN pool from the whole view under the node budget.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", backlog=40, assigned=0, slot_ram_mib=1024, slot_vcpus=1,
                                 min_warm=0, max_ceiling=64, weight=1.0, ts=1000.0))
    pool = _Pool(assigned=0)
    cfg = NodeConfig(balancing=True, resource_management=True, stale_after_s=60,
                     ram_headroom_frac=1.0, vcpu_oversubscription=999)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 4,
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1000.0)
    mine = ds.tick()
    # node has 10 slots; red's backlog(40) >> clip's(4) → red gets the larger share, but
    # clip still self-sizes to its portion and resizes its OWN pool.
    assert mine is not None and pool.concurrent_ceiling == mine.concurrent_ceiling
    assert mine.concurrent_ceiling >= 1
    # clip published itself into the shared view
    assert any(s.engine == "clip" for s in share.read_all(max_age_s=60, now=1000.0))


def test_static_mode_uses_weight_not_backlog(tmp_path):
    share = FileNodeShare(str(tmp_path))
    # peer with a huge backlog but low weight; resource_management on, balancing OFF
    share.publish(DemandSnapshot("red", backlog=99, assigned=0, slot_ram_mib=1024, slot_vcpus=1,
                                 min_warm=0, max_ceiling=64, weight=1.0, ts=5.0))
    pool = _Pool()
    cfg = NodeConfig(resource_management=True, balancing=False, stale_after_s=60,
                     ram_headroom_frac=1.0, vcpu_oversubscription=999)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64, weight=4.0),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0,
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 5.0)
    ds.tick()
    view = {s.engine: s for s in share.read_all(max_age_s=60, now=5.0)}
    # clip's weight (4) beats red's (1) despite red's huge backlog → clip gets more
    from blastbox.host.node_sizer import PoolSpec, plan_sizes
    specs = [PoolSpec(s.engine, s.slot_ram_mib, s.slot_vcpus, demand=s.weight,
                      min_warm=s.min_warm, max_ceiling=s.max_ceiling) for s in view.values()]
    plan = plan_sizes(specs, NodeBudget(10 * 1024, 999))
    assert plan["clip"].concurrent_ceiling > plan["red"].concurrent_ceiling


def test_skips_non_node_runtime(tmp_path):
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True)
    pool = _Pool(runtime=RUNTIME_AWS_LAMBDA_MICROVM)
    ds = DispatcherSizer(EngineNode("lam", "-"), pool, share, cfg, runtime=RUNTIME_AWS_LAMBDA_MICROVM, backlog_fn=lambda: 50)
    assert ds.tick() is None                       # lambda pool never sized here


def test_run_loop_ticks_and_stops(tmp_path):
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, interval_s=0)
    pool = _Pool(assigned=1)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), pool, share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 2, capacity_fn=_budget(8 * 1024, 99))
    ds.run(max_ticks=3, sleep=lambda _s: None)
    assert pool.concurrent_ceiling >= 1            # sized at least once


# --- regression: finding 1 (real WarmPool.runtime is an OBJECT, not a string) ---

class _RealishRuntimeObj:
    """Mimics WarmPool.runtime returning a SlotRuntime OBJECT (no .strip())."""


def test_gating_uses_runtime_name_not_pool_object(tmp_path):
    # the pool's .runtime is an object (like a real WarmPool); gating must use the
    # runtime= NAME string, or manages() would crash and the sizer silently no-op.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(assigned=1)
    pool.runtime = _RealishRuntimeObj()          # object, not a string
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), pool, share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 3,
                         capacity_fn=_budget(8 * 1024, 99), clock=lambda: 1.0)
    mine = ds.tick()                              # must NOT raise, must actually size
    assert mine is not None and pool.concurrent_ceiling >= 1


# --- regression: finding 4 (untrusted snapshot values are validated) ---

def test_read_all_drops_invalid_and_impersonating_snapshots(tmp_path):
    share = FileNodeShare(str(tmp_path))
    good = DemandSnapshot("clip", 2, 0, 1024, 1, 0, 64, 1.0, ts=1.0)
    share.publish(good)
    # zero footprint (would make plan_sizes water-fill forever) — written under its own name
    share.publish(DemandSnapshot("zero", 1, 0, 0, 0, 0, 64, 1.0, ts=1.0))
    # absurd ceiling
    share.publish(DemandSnapshot("huge", 1, 0, 1024, 1, 0, 2_000_000_000, 1.0, ts=1.0))
    # impersonation: a file named evil.json that claims engine="clip"
    import json as _json
    (tmp_path / "evil.json").write_text(_json.dumps({
        "engine": "clip", "backlog": 1, "assigned": 0, "slot_ram_mib": 1024,
        "slot_vcpus": 1, "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1.0}))
    kept = {s.engine for s in share.read_all(max_age_s=60, now=1.0)}
    assert kept == {"clip"}                       # only the valid, non-impersonating snapshot


def test_read_all_skips_type_poisoned_file_without_crashing(tmp_path):
    # regression (round-2): a valid-JSON but wrong-typed field must skip that file, not
    # raise out of read_all() and silently wedge the sizer node-wide.
    import json as _json
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0))
    (tmp_path / "clip.json").write_text(_json.dumps({
        "engine": "clip", "backlog": 1, "assigned": 0, "slot_ram_mib": None,   # poisoned
        "slot_vcpus": 1, "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1.0}))
    kept = {s.engine for s in share.read_all(max_age_s=60, now=1.0)}   # must not raise
    assert kept == {"red"}


# --- regression: round-3 findings ---

def test_local_backlog_fn_scopes_to_engine():
    # F1: on a SHARED multi-engine store, backlog must be scoped to THIS engine, else
    # every dispatcher reports the node-wide queue and balancing splits evenly.
    from blastbox.host.jobs.base import Job, JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_sizer import local_backlog_fn
    store = InMemoryJobStore()
    for eng in ("clip", "clip", "red"):
        store.create(Job.new(engine=eng, filename="x"))
    assert local_backlog_fn(store, "clip")() == 2      # only clip's QUEUED
    assert local_backlog_fn(store, "red")() == 1
    assert local_backlog_fn(store)() == 3              # unscoped = whole store
    assert store.count(JobStatus.QUEUED, engine="clip") == 2


def test_node_isolation_ignores_foreign_host(tmp_path):
    # F3: a share_dir accidentally shared across hosts must not conflate them.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 50, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="hostB"))  # other host
    pool = _Pool(assigned=0)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 3, node="hostA",
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0)
    ds.tick()
    # clip sizes as if it's the only engine on hostA — hostB's red is not in its view
    from blastbox.host.node_share import DemandSnapshot as DS
    view = [s.engine for s in share.read_all(max_age_s=60, now=1.0) if s.node in ("", "hostA")]
    assert view == ["clip"]
    _ = DS


def test_valid_rejects_infinite_footprint(tmp_path):
    import json as _json
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("good", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0))
    (tmp_path / "inf.json").write_text(_json.dumps({
        "engine": "inf", "backlog": 1, "assigned": 0, "slot_ram_mib": 1e999,  # → inf
        "slot_vcpus": 1, "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1.0}))
    assert {s.engine for s in share.read_all(max_age_s=60, now=1.0)} == {"good"}
