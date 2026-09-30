"""Dispatcher-side self-sizer + shared node view — the transport that fits the
serve/dispatch split (pool in the dispatcher, coordinated via a shared file)."""

from __future__ import annotations

import time

from blastbox.host.dispatcher_sizer import DispatcherSizer
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_share import DemandSnapshot, FileNodeShare
from blastbox.host.node_sizer import NodeBudget
from blastbox.host.pool_config import RUNTIME_AWS_LAMBDA_MICROVM, RUNTIME_FIRECRACKER


class _Pool:
    def __init__(self, assigned=0, runtime=RUNTIME_FIRECRACKER, slot_count=0):
        self.runtime = runtime
        self.assigned_count = assigned
        self.warm_size = 0
        self.concurrent_ceiling = 0
        # resident slot count (IDLE+WARMING+ASSIGNED). resize() only moves setpoints; real
        # residency lags, so tests set this explicitly to simulate an async resize/reap.
        self.slot_count = slot_count

    def resize(self, *, warm_size, concurrent_ceiling, mark_autosized=True):
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


def test_auto_created_share_dir_is_group_writable_not_world(tmp_path):
    # regression (PR #60 codex P1): an auto-created share must let a peer under a DIFFERENT UID (but
    # the same dispatcher GROUP) publish its own <identity>.json — but must NOT be world-writable,
    # since snapshots are unauthenticated and any local UID could otherwise publish a poisoned one.
    import os
    import stat
    d = tmp_path / "share-auto"
    assert not d.exists()
    FileNodeShare(str(d))
    mode = stat.S_IMODE(os.stat(d).st_mode)
    assert mode & 0o070 == 0o070, f"auto-created share dir not group-writable: {oct(mode)}"
    assert not (mode & 0o007), f"auto-created share dir must NOT be world-accessible: {oct(mode)}"


def test_preprovisioned_share_dir_perms_left_untouched(tmp_path):
    # the flip side: if an operator PRE-PROVISIONED the dir (the trust-sensitive path — tight
    # per-owner perms on a mounted dir), FileNodeShare must NOT loosen it.
    import os
    import stat
    d = tmp_path / "share-tight"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)               # ensure exact perms regardless of umask
    FileNodeShare(str(d))
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_cold_only_gate_floored_on_fail_closed(tmp_path):
    # PR #60 marla P1: _size_to_floor is the fail-closed net (mixed node ids / lost visibility). For
    # a pool-less cold-only dispatcher there's no pool to resize, but its GATE must STILL be floored
    # to 1 — else it keeps admitting the full budgeted ceiling of cold workers exactly when peers
    # have reclaimed its share (oversubscription in the case this net exists to prevent).
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    # an UNTAGGED peer makes THIS tagged ("n") cold dispatcher's view mixed → fail closed.
    share.publish(DemandSnapshot("clip", 5, 0, 4096, 1, 0, 8, 1.0, ts=1.0, node="", tier="cold"))
    gate = DynamicConcurrencyGate(8)
    gate.set_limit(8)                                      # currently admitting the full budget
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=4096, max_ceiling=8), None, share,
                         cfg, runtime="cold", backlog_fn=lambda: 5, node="n", instance="i",
                         capacity_fn=_budget(8 * 4096, 999), clock=lambda: 1.0,
                         concurrency_gate=gate, cold_slot_ram_mib=4096)
    ds.tick()                                             # mixed view → _size_to_floor
    assert gate.limit == 1                                # cold gate floored, NOT left at 8


def test_mixed_node_ids_fail_closed_to_floor(tmp_path):
    # PR #60 codex P1: a tagged dispatcher + an untagged peer give each process a DIFFERENT
    # planner view (the symmetric node filter), so their independent slices sum past the budget.
    # No local plan can fix a globally-inconsistent view → fail closed: size to the warm floor
    # (never grow), so every affected dispatcher floors identically and none over-allocates.
    share = FileNodeShare(str(tmp_path))
    # an UNTAGGED peer with a deep backlog sits in the shared dir
    share.publish(DemandSnapshot("red", 40, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node=""))
    pool = _Pool()
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    # THIS dispatcher is TAGGED "n" → its view is {n(self), ""(peer)} = mixed identities. A LARGE
    # min_warm (8) must NOT be honored as the floor: with an inconsistent view the dispatcher can't
    # know how many peers exist, so N pools each flooring to 8 would oversubscribe the very node
    # this branch protects. The safe floor is ONE slot (the plan_sizes baseline).
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64, min_warm=8),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 30,
                         node="n", instance="c", capacity_fn=_budget(10 * 1024, 999),
                         clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.warm_size == 1 and mine.concurrent_ceiling == 1   # ceiling 1, NOT min_warm=8
    assert pool.concurrent_ceiling == 1


def test_budget_consensus_uses_min_across_view(tmp_path):
    # PR #60 codex P1: dispatchers with different headroom/vcpu config or per-process adaptive
    # scale each compute their own budget and pick incompatible slices that sum past the true
    # budget. Reconcile to the elementwise MIN so every reader plans against the same (tightest)
    # budget → Σ ≤ min ≤ everyone's actual.
    share = FileNodeShare(str(tmp_path))
    # a same-node peer publishes a SMALL budget (4 slots) — the tightest view.
    share.publish(DemandSnapshot("red", 2, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                                 budget_ram_mib=4 * 1024, budget_vcpus=4))
    pool = _Pool()
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    # THIS dispatcher's OWN budget is 16 slots, but it must reconcile down to the peer's 4.
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 40, node="n",
                         instance="c", capacity_fn=_budget(16 * 1024, 16), clock=lambda: 1.0)
    mine = ds.tick()
    # clip + red share the CONSENSUS 4-slot budget → clip's ceiling is bounded by 4, not 16.
    assert mine.concurrent_ceiling <= 4


def test_mixed_balancing_modes_on_a_node_do_not_oversubscribe(tmp_path):
    # regression (PR #60 codex P1): two dispatchers on ONE node with DIFFERENT
    # BLASTBOX_NODE_BALANCING values used to each apply its own mode to the shared snapshots,
    # compute a different plan, and take self-slices that summed PAST the node budget. With the
    # published-mode consensus (balancing only if unanimous, else static), every reader derives
    # the SAME basis, so the slices sum to the budget. Construct the worst case: the balancing
    # engine holds ALL the backlog while the static engine holds ALL the weight — under the old
    # per-dispatcher mode each would claim the lion's share and Σ would blow past the budget.
    share = FileNodeShare(str(tmp_path))
    budget_slots = 10
    cap = _budget(budget_slots * 1024, 999)   # 10 slots @ 1024 MiB
    clip_pool, red_pool = _Pool(), _Pool()
    # clip: BALANCING, all the backlog, tiny weight.
    clip = DispatcherSizer(
        EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64, min_warm=0, weight=1.0),
        clip_pool, share,
        NodeConfig(balancing=True, resource_management=True, stale_after_s=1e9,
                   ram_headroom_frac=1.0, vcpu_oversubscription=999),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 40, node="n", instance="c",
        capacity_fn=cap, clock=lambda: 1000.0)
    # red: STATIC, no backlog, big weight.
    red = DispatcherSizer(
        EngineNode("red", "-", slot_ram_mib=1024, max_ceiling=64, min_warm=0, weight=9.0),
        red_pool, share,
        NodeConfig(balancing=False, resource_management=True, stale_after_s=1e9,
                   ram_headroom_frac=1.0, vcpu_oversubscription=999),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n", instance="r",
        capacity_fn=cap, clock=lambda: 1000.0)
    for _ in range(3):        # a few rounds so both see each other and converge
        clip.tick()
        red.tick()
    # THE invariant: the two independently-computed self-slices never exceed the node budget.
    assert clip_pool.concurrent_ceiling + red_pool.concurrent_ceiling <= budget_slots
    # And consensus fell to STATIC (weight basis): red's big weight wins the ceiling, not clip's
    # backlog — proving the balancer didn't silently impose its own basis.
    assert red_pool.concurrent_ceiling > clip_pool.concurrent_ceiling


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


def test_same_engine_across_two_physical_nodes_sizes_independently(tmp_path):
    # The real multi-node model (Will): one engine (clip) runs on TWO physical nodes
    # sharing a QUEUE for load-balancing/failover. The sizer is PER-NODE — each host sizes
    # its OWN clip pool against its OWN hardware budget from its OWN node view. Even on a
    # shared share_dir (NFS/PV), the two nodes must not collide on the file nor contaminate
    # each other's view: node-namespaced filenames + the node filter keep them independent.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool2, pool3 = _Pool(assigned=0), _Pool(assigned=0)
    common = dict(runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 5, instance="p1",
                  capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    ds2 = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                          pool2, share, cfg, node="toolz2", **common)
    ds3 = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                          pool3, share, cfg, node="toolz3", **common)
    mine2, mine3 = ds2.tick(), ds3.tick()
    # no filename collision on the shared dir — one file per (engine, tier, node, instance)
    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "clip@firecracker@toolz2@p1.json", "clip@firecracker@toolz3@p1.json"]
    # each node sized ITS OWN clip pool to ITS OWN full 8-slot budget — not halved or
    # doubled by the peer node's identically-named engine (independent LB/failover pools)
    assert mine2.concurrent_ceiling == 8 and pool2.concurrent_ceiling == 8
    assert mine3.concurrent_ceiling == 8 and pool3.concurrent_ceiling == 8


def test_same_engine_two_tiers_on_one_node_are_distinct_pools(tmp_path):
    # regression (PR #60 review, Will-confirmed): one host can run the SAME engine on TWO
    # node-managed tiers (firecracker + gvisor) — two separate WarmPools. Keyed by engine
    # ALONE they'd collide on <engine>.json and each size to the whole budget (2x
    # oversubscription). Keyed by (engine, tier) they're distinct pools that SHARE the node
    # budget. 8-slot node, both busy → they split it, Σ ceiling == 8 (no oversubscription).
    from blastbox.host.pool_config import RUNTIME_GVISOR
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool_fc, pool_gv = _Pool(assigned=0), _Pool(assigned=0)
    common = dict(backlog_fn=lambda: 10, node="toolz2", instance="p1",
                  capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    ds_fc = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                            pool_fc, share, cfg, runtime=RUNTIME_FIRECRACKER, **common)
    ds_gv = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                            pool_gv, share, cfg, runtime=RUNTIME_GVISOR, **common)
    ds_fc.tick()
    ds_gv.tick()
    # distinct files — no collision between the two tiers of the same engine on one host
    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "clip@firecracker@toolz2@p1.json", "clip@gvisor@toolz2@p1.json"]
    # both are in each other's view now; re-tick so each sees the full 2-pool node
    m_fc, m_gv = ds_fc.tick(), ds_gv.tick()
    assert m_fc.concurrent_ceiling + m_gv.concurrent_ceiling == 8    # SHARE budget, no 2x
    assert m_fc.concurrent_ceiling >= 1 and m_gv.concurrent_ceiling >= 1


def test_sizer_drives_concurrency_gate_to_cold_headroom(tmp_path):
    # PR #60: the sizer drives the dispatcher's COLD-admission gate to the budget's cold
    # HEADROOM (ceiling − warm reservation), NOT the whole ceiling — the warm pool already
    # bounds warm slots, and cold workers spawn outside it, so headroom is what keeps warm
    # residency + cold within the budget instead of each reaching the ceiling (→ ~2× the node).
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    # low backlog → warm target well below the ceiling, so there's real cold headroom to check.
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=6), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 2, node="n",
                         instance="i", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0,
                         concurrency_gate=gate)
    mine = ds.tick()
    assert mine.warm_size < mine.concurrent_ceiling                        # genuine headroom
    assert gate.limit == max(1, mine.concurrent_ceiling - mine.warm_size)  # gate == cold headroom
    # and warm residency (≤ ceiling in the pool) + cold (≤ gate) never exceeds the ceiling except
    # for the floor-of-1 liveness margin:
    assert mine.warm_size + gate.limit <= mine.concurrent_ceiling + 1


def test_cold_gate_reserves_resident_slots_not_just_target(tmp_path):
    # PR #60 codex P1: resize() only moves setpoints — surplus IDLE/WARMING slots aren't reaped
    # until a later pool tick. When a tick LOWERS warm (8 resident → target 1), basing cold
    # headroom on the target alone would open ceiling−1 permits while 8 VMs are still resident
    # (≈2× budget). Reserve max(target, resident) so the cold limit stays down until the surplus
    # actually drains.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(slot_count=8)                 # 8 VMs still resident from a prior larger warm
    # low backlog + min_warm=1 → new warm target is 1, well below the 8 still resident.
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=1),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0,
                         node="n", instance="i", capacity_fn=_budget(8 * 1024, 999),
                         clock=lambda: 1.0, concurrency_gate=gate)
    mine = ds.tick()
    assert mine.warm_size == 1                  # target dropped to the floor
    # headroom = ceiling − max(target=1, resident=8) = 8 − 8 = 0 → floored to 1, NOT ceiling−1=7.
    assert gate.limit == 1


def test_cold_gate_priced_by_cold_worker_footprint(tmp_path):
    # PR #60 codex P1: a cold worker (BLASTBOX_WORKER_MEMORY, default 4g) can be bigger than a
    # warm slot (RAM_MIB, default 2048). Converting warm-slot headroom to cold permits 1:1 would
    # let a pool priced for 2g slots admit 4g cold workers = ~2x its RAM. Price permits by the
    # cold footprint: permits = headroom_slots * warm_slot_ram / cold_ram.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048, max_ceiling=8, min_warm=0),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 2,
                         node="n", instance="i", capacity_fn=_budget(8 * 2048, 999),
                         clock=lambda: 1.0, concurrency_gate=gate,
                         cold_slot_ram_mib=4096)          # cold worker is 2x the warm slot
    mine = ds.tick()
    headroom = mine.concurrent_ceiling - mine.warm_size
    assert headroom >= 2
    assert gate.limit == headroom * 2048 // 4096          # priced down by the 2x footprint


def test_sizer_fails_closed_when_publish_keeps_failing(tmp_path):
    # PR #60 codex P1: if publish() keeps failing (permission change / broken bind mount), peers
    # expire our snapshot and reclaim our share — but our pool is still live and consuming RAM.
    # After the staleness window with no successful publish, shrink to the floor to stop
    # oversubscribing (recovers when publish works again).
    class _FailingShare:
        def publish(self, snap):
            raise OSError("permission denied")

        def read_all(self, *, max_age_s, now):
            return []

        def remove(self, snap):
            pass

    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=1.0)
    pool = _Pool()
    pool.resize(warm_size=6, concurrent_ceiling=6)        # pretend it grew earlier
    ticks = {"n": 0}

    def clock():                                          # advances 10s per call → past the 1s window
        ticks["n"] += 1
        return ticks["n"] * 10.0

    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=1),
                         pool, _FailingShare(), cfg, runtime=RUNTIME_FIRECRACKER,
                         backlog_fn=lambda: 5, node="n", instance="i",
                         capacity_fn=_budget(8 * 1024, 999), clock=clock)
    ds.run(max_ticks=2, sleep=lambda _s: None)
    assert pool.concurrent_ceiling == 1                   # floored (min_warm=1), not left at 6


def test_sizer_floors_cold_gate_at_one_when_warm_saturates(tmp_path):
    # when warm demand claims the whole ceiling, cold headroom is 0 — but the gate floors at 1 so
    # egress / warm-miss jobs never fully starve (a bounded, self-correcting overshoot).
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=6), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 50, node="n",
                         instance="i", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0,
                         concurrency_gate=gate)
    mine = ds.tick()
    assert mine.warm_size == mine.concurrent_ceiling      # warm saturated the ceiling
    assert gate.limit == 1                                # floored, not 0


def test_overlapping_replicas_split_budget_not_double(tmp_path):
    # regression (PR #60 review): two replicas of the SAME engine/tier/node — a rolling
    # deploy's brief overlap — must be two distinct pools that SHARE the budget, not collide
    # on one file and each take the full ceiling (2x oversubscription). Keyed by instance.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    common = dict(runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 20, node="toolz2",
                  capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    old = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                          _Pool(), share, cfg, instance="old", **common)
    new = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                          _Pool(), share, cfg, instance="new", **common)
    old.tick()
    new.tick()
    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "clip@firecracker@toolz2@new.json", "clip@firecracker@toolz2@old.json"]
    m_old, m_new = old.tick(), new.tick()             # each now sees both replicas
    # 8-slot node; the two replicas SPLIT it (Σ == 8), neither takes the full budget
    assert m_old.concurrent_ceiling + m_new.concurrent_ceiling == 8
    assert m_old.concurrent_ceiling < 8 and m_new.concurrent_ceiling < 8


def test_start_node_sizer_no_thread_leak_if_status_print_fails(tmp_path, monkeypatch):
    # regression (PR #60 r11): the status print() must happen BEFORE start_thread(), or a
    # broken-pipe/closed-stderr OSError from print leaves the just-started daemon thread
    # running while _start_node_sizer returns None (caller can never stop/join it).
    import builtins
    import sys
    import threading as _th

    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    real_print = builtins.print

    def boom(*a, **k):
        if k.get("file") is sys.stderr:               # ONLY the status line (not logging's IO)
            raise OSError("broken pipe")
        return real_print(*a, **k)

    monkeypatch.setattr(builtins, "print", boom)
    before = _th.active_count()
    res = _start_node_sizer(_Pool(), ["clip"], InMemoryJobStore(), "firecracker")
    assert res is None                                 # setup failed → no sizer handle
    assert _th.active_count() == before                # and NO leaked thread


def test_default_instance_is_unique_per_process_not_pid(tmp_path):
    # regression (PR #60 r10, codex HIGH): the instance token must be RANDOM, not os.getpid()
    # — each dispatcher runs in its own container where pid is almost always 1, so two
    # replicas would collide on `@1` and each size to the full budget. With a random token
    # they publish DISTINCT files even sharing a pid namespace.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    common = dict(runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 5, node="toolz2",
                  capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    a = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg, **common)
    b = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg, **common)
    a.tick()
    b.tick()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 2                             # two distinct files, no collision


def test_slow_publisher_refresh_hint_prevents_aging(tmp_path):
    # PR #60 r13: a publisher whose count is consistently slow declares its refresh period
    # (refresh_s), and a fast reader ages it out by the LARGER of its own window and that —
    # so it isn't expired mid-count and its share reallocated. Bounded by the GC floor.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 5, 0, 1024, 1, 0, 64, 1.0, ts=0.0, node="n",
                                 tier="firecracker", instance="i", refresh_s=35.0))
    # a 20s reader window would normally expire a 30s-old snapshot...
    assert [s.engine for s in share.read_all(max_age_s=20.0, now=30.0)] == ["red"]  # kept (eff 70s)
    # ...but a truly-dead one past the cap is still dropped
    assert share.read_all(max_age_s=20.0, now=10_000.0) == []


def test_multi_engine_weight_clamped_to_valid_cap(tmp_path, monkeypatch):
    # PR #60 r13: summing multi-engine weights can exceed _MAX_WEIGHT; the reader rejects a
    # snapshot above it, so the sum must be clamped or the pool self-evicts from every view.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_share import _MAX_WEIGHT
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "aa,bb")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_AA_WEIGHT", "600000")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_BB_WEIGHT", "600000")   # sum 1.2M > _MAX_WEIGHT
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["aa", "bb"], InMemoryJobStore(), "firecracker")
    assert res is not None
    stop, thread, sizer = res
    try:
        assert sizer._engine.weight <= _MAX_WEIGHT                    # clamped, so _valid passes
        # its own snapshot round-trips through the reader (not self-evicted)
        from blastbox.host.node_share import _valid
        assert _valid(sizer._identity())
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_multi_engine_pool_ceiling_sums_caps_bounded_by_concurrency(tmp_path, monkeypatch):
    # PR #60 codex P2: a shared pool serving multiple engines must SUM their usable ceilings
    # (bounded by dispatch concurrency), not take the min (a low-cap engine throttles the pool) nor
    # the max (undercounts SIMULTANEOUS multi-engine work). Two engines capped 8 each, concurrency
    # 16 → 16 usable, so both can run at once; the node budget still bounds the actual allocation.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,red")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "8")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_RED_MAX_CEILING", "8")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["clip", "red"], InMemoryJobStore(), "firecracker", 16)
    assert res is not None
    stop, thread, sizer = res
    try:
        assert sizer._engine.max_ceiling == 16     # sum(8,8)=16, bounded by concurrency 16
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_read_all_rejects_poisoned_consensus_field(tmp_path):
    # PR #60 codex P2: a malformed consensus field (budget_ram_mib="oops") must be DROPPED by
    # read_all — else it survives to tick() where `s.budget_ram_mib > 0` raises; the heartbeat
    # already published, so the run loop retries forever, freezing pools at stale allocations.
    import json
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 2, 0, 1024, 1, 0, 64, 1.0, ts=1.0))
    # hand-write a poisoned file (bypassing publish's typed API); filename must match the slug.
    (tmp_path / "red.json").write_text(json.dumps({
        "engine": "red", "backlog": 1, "assigned": 0, "slot_ram_mib": 1024, "slot_vcpus": 1,
        "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1.0, "budget_ram_mib": "oops"}))
    engines = {s.engine for s in share.read_all(max_age_s=60, now=1.0)}
    assert engines == {"clip"}     # poisoned red dropped; good clip survives


def test_reservation_sums_resident_warm_and_cold_in_flight(tmp_path):
    # PR #60 audit P1: cold workers spawn OUTSIDE the warm pool, so they COEXIST with resident
    # warm VMs — the reservation must be (warm residency) + (cold in flight), not the MAX. A pool
    # with 6 idle warm + 2 cold in flight physically runs 8; publishing max(6,2)=6 would let a peer
    # reallocate the 2 cold slots' RAM while both are live.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    for _ in range(2):
        gate.acquire(0.0)                       # 2 cold workers in flight
    assert gate.in_flight == 2
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(assigned=0, slot_count=6)      # 6 warm resident, all idle
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n",
                         instance="i", capacity_fn=_budget(64 * 1024, 999), clock=lambda: 1.0,
                         concurrency_gate=gate)
    ds.tick()
    mine = next(s for s in share.read_all(max_age_s=60, now=1.0) if s.engine == "clip")
    assert mine.assigned == 8                   # 6 warm + 2 cold, NOT max(6, 2)=6


def test_reservation_prices_cold_in_warm_slot_equivalents(tmp_path):
    # PR #60 codex P1: the planner values `assigned` at slot_ram_mib, so a cold worker bigger than
    # a warm slot (BLASTBOX_WORKER_MEMORY 4g vs a 2g slot) must reserve MULTIPLE warm-slot units,
    # not 1 — else a peer allocates the missing RAM. 2 cold workers @ 2x footprint = 4 units.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(64)
    for _ in range(2):
        gate.acquire(0.0)                        # 2 cold workers in flight
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(assigned=0, slot_count=0)       # no warm residency — isolate the cold pricing
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n",
                         instance="i", capacity_fn=_budget(64 * 2048, 999), clock=lambda: 1.0,
                         concurrency_gate=gate, cold_slot_ram_mib=4096)   # cold = 2x warm slot
    ds.tick()
    mine = next(s for s in share.read_all(max_age_s=60, now=1.0) if s.engine == "clip")
    assert mine.assigned == 4                     # 2 cold workers × (4096/2048) = 4 warm-slot units


def test_long_identity_hashed_into_filesystem_safe_key(tmp_path):
    # PR #60 codex P2: a long-but-valid engine/node identity can exceed the FS per-component limit
    # (mkstemp's temp decoration hits it sooner) → publish raises → unmanaged fallback → budget
    # unenforced. Long keys are hashed to a bounded name; publish + read_all still agree on it.
    share = FileNodeShare(str(tmp_path))
    long_node = "n" * 250                         # valid slug, but way over the FS limit
    snap = DemandSnapshot("clip", 3, 0, 1024, 1, 0, 64, 1.0, ts=1.0,
                          node=long_node, tier="firecracker", instance="i1")
    share.publish(snap)                           # must NOT raise ENAMETOOLONG
    names = [p.name for p in tmp_path.glob("*.json")]
    assert len(names) == 1 and len(names[0]) < 120        # bounded, hashed
    round_tripped = share.read_all(max_age_s=60, now=1.0)  # anti-impersonation check still passes
    assert len(round_tripped) == 1 and round_tripped[0].node == long_node


def test_start_node_sizer_removes_snapshot_when_setup_aborts_after_publish(tmp_path, monkeypatch):
    # PR #60 audit P1: the synchronous first tick publishes a heartbeat; if a LATER setup step
    # (here start_thread) raises, _start_node_sizer returns None — but the published phantom
    # snapshot must NOT be left behind (it advertises ~0 demand, ages out permanently, and peers
    # reclaim this node's share while the pool runs unmanaged = persistent oversubscription).
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.dispatcher_sizer import DispatcherSizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))

    def _boom(self, stop):                       # start_thread fails AFTER tick() published
        raise RuntimeError("thread exhaustion")
    monkeypatch.setattr(DispatcherSizer, "start_thread", _boom)

    res = _start_node_sizer(_Pool(), ["clip"], InMemoryJobStore(), "firecracker")
    assert res is None                                              # setup aborted
    assert list(tmp_path.glob("*.json")) == []                     # phantom snapshot cleaned up


def test_published_reservation_holds_resident_slots(tmp_path):
    # PR #60 codex P1: resize() only moves setpoints — surplus IDLE/WARMING VMs aren't reaped
    # until a later pool tick. If demand drops and we advertised the LOWER share immediately, a
    # peer would spawn into the "freed" budget while our old VMs still consume it. The published
    # reservation must hold at current residency until it actually reaps.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(assigned=0, slot_count=8)      # 8 VMs still resident, but no active work / backlog
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n",
                         instance="i", capacity_fn=_budget(16 * 1024, 999), clock=lambda: 1.0)
    ds.tick()
    mine = next(s for s in share.read_all(max_age_s=60, now=1.0) if s.engine == "clip")
    assert mine.assigned >= 8      # reservation reflects the 8 still-resident slots, not 0


def test_adaptive_only_direct_config_is_active(tmp_path):
    # PR #60 codex P2: a DIRECTLY-constructed NodeConfig(adaptive=True) reports active=True, so
    # the sizer's own _active() gate must agree — else tick() returns None and adaptive never
    # runs. (from_env folds adaptive into resource_management; the construction API path doesn't,
    # so _active must include adaptive too.)
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(engines=(EngineNode("clip", "-"),), adaptive=True,
                     resource_management=False, balancing=False, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    assert cfg.active is True
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 3, node="n",
                         instance="i", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert mine is not None                 # sized, NOT no-op'd by the _active() gate
    assert pool.concurrent_ceiling >= 1


def test_combined_ceiling_clamped_to_reader_bound(tmp_path, monkeypatch):
    # PR #60 codex P2: the summed multi-engine ceiling must be clamped to _MAX_CEILING_SANE — else
    # the dispatcher's own snapshot is rejected by the reader's _valid() and the pool stalls at
    # warm-0/ceiling-1.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_share import _MAX_CEILING_SANE, _valid
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,red")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "3000")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_RED_MAX_CEILING", "3000")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["clip", "red"], InMemoryJobStore(), "firecracker", 6000)
    assert res is not None
    stop, thread, sizer = res
    try:
        assert sizer._engine.max_ceiling <= _MAX_CEILING_SANE   # clamped (sum 6000 > 4096)
        assert _valid(sizer._identity())                        # own snapshot round-trips
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_node_manages_tier_gating(monkeypatch):
    # PR #60 r13: _node_manages_tier drives the hard-cap startup wiring (force warm_only,
    # start unspawned). True only when RM is on AND the tier is node-managed (fc/gvisor).
    from blastbox.host.cli import _node_manages_tier
    monkeypatch.delenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", raising=False)
    monkeypatch.delenv("BLASTBOX_NODE_BALANCING", raising=False)
    assert not _node_manages_tier("firecracker")          # RM off → not managed
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    assert _node_manages_tier("firecracker") and _node_manages_tier("gvisor")
    assert _node_manages_tier("cold")                     # cold is now managed pool-lessly (gate + reservation)
    assert not _node_manages_tier("aws-ec2")              # cloud tiers stay unmanaged (platform owns concurrency)

    # An all-local cascade (fc/gvisor members only) IS managed via pool member inspection — a bare
    # tier=="cascade" is not node-managed by name, so without the pool it stays unmanaged.
    class _T:
        def __init__(self, name): self.name = name

    class _Casc:
        kind = "cascade"
        def __init__(self, *names): self.tiers = [_T(n) for n in names]

    class _Pool:
        def __init__(self, rt): self.runtime = rt

    assert not _node_manages_tier("cascade")                             # no pool → can't inspect → unmanaged
    assert _node_manages_tier("cascade", _Pool(_Casc("firecracker", "gvisor")))   # all-local → managed
    assert not _node_manages_tier("cascade", _Pool(_Casc("firecracker", "aws-ec2")))  # off-node member → not
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "0")
    monkeypatch.delenv("BLASTBOX_NODE_BALANCING", raising=False)
    assert not _node_manages_tier("cascade", _Pool(_Casc("firecracker", "gvisor")))  # RM off → unmanaged even all-local


def test_cold_only_dispatcher_gets_budgeted_gate_and_publishes(tmp_path, monkeypatch):
    # PR #60 codex P1 (feature): a cold-ONLY dispatcher (tier="cold", no warm pool) is now managed
    # pool-lessly — _start_node_sizer builds a sizer that publishes a COLD-footprint reservation
    # into the node view AND drives the concurrency gate to a budgeted cold ceiling, so warm peers
    # account for its docker workers instead of over-allocating the whole budget to warm slots.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "4096")     # cold worker footprint
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "8")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    gate = DynamicConcurrencyGate(8)
    res = _start_node_sizer(None, ["clip"], InMemoryJobStore(), "cold", 8, gate, 4096)  # pool=None!
    assert res is not None                          # cold-only sizer started despite no warm pool
    stop, thread, sizer = res
    try:
        # published a cold-tier snapshot with the COLD worker footprint (not a warm-slot RAM)
        snaps = FileNodeShare(str(tmp_path)).read_all(max_age_s=1e9, now=time.time())
        mine = [s for s in snaps if s.engine == "clip" and s.tier == "cold"]
        assert len(mine) == 1
        assert mine[0].slot_ram_mib == 4096         # priced as a cold worker
        assert mine[0].min_warm == 0                # no warm floor for a pool-less cold dispatcher
        # gate driven to a budgeted ceiling (>=1, and never above its cold concurrency cap)
        assert 1 <= gate.limit <= 8
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_all_local_cascade_is_sized_and_published(tmp_path, monkeypatch):
    # Feature: an ALL-LOCAL cascade (fc/gvisor members) is enrolled in node management — its whole
    # ceiling is this node's RAM, so _start_node_sizer sizes its warm pool and publishes a snapshot
    # under tier="cascade", exactly like an fc/gvisor pool. (A cascade with an off-node member is
    # gated OUT at the caller via _node_manages_tier; covered in test_node_manages_tier_gating.)
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore

    class _CascTier:
        def __init__(self, name): self.name = name

    class _CascRuntime:
        kind = "cascade"
        def __init__(self, *names): self.tiers = [_CascTier(n) for n in names]

    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "2048")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "8")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    pool = _Pool(runtime=_CascRuntime("firecracker", "gvisor"))
    res = _start_node_sizer(pool, ["clip"], InMemoryJobStore(), "cascade", 8, None, 0.0)
    assert res is not None                              # the cascade pool got a sizer
    stop, thread, sizer = res
    try:
        snaps = FileNodeShare(str(tmp_path)).read_all(max_age_s=1e9, now=time.time())
        mine = [s for s in snaps if s.engine == "clip" and s.tier == "cascade"]
        assert len(mine) == 1                           # published under the cascade tier identity
        assert mine[0].slot_ram_mib == 2048             # sized by the engine's declared local footprint
        assert pool.concurrent_ceiling >= 1             # the warm pool was actually resized (managed)
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_cascade_warm_capped_at_surviving_capacity_frees_cold_headroom(tmp_path, monkeypatch):
    # Regression (codex escalate, run-16 MEDIUM): an all-local cascade whose overflow tier was
    # unavailable at boot has FEWER real slots than the configured ceiling. The sizer must cap the
    # warm target at the cascade's surviving capacity — else it reserves warm slots the runtime
    # can never spawn, and the cold gate (ceiling − warm) zeroes out → cold starves to its floor of
    # 1 and the node runs at ~5/8 while queued jobs could age out (MAX_QUEUED_AGE_S) and be deleted.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.memory import InMemoryJobStore

    class _CTier:
        def __init__(self, name, cap):
            self.name = name
            self.capacity = cap

    class _CRuntime:  # gvisor overflow tier was unavailable at boot → only firecracker:4 survives
        kind = "cascade"
        def __init__(self): self.tiers = [_CTier("firecracker", 4)]

    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "512")   # small → budget easily fits 8
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "8")  # configured for 8, runtime holds 4
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    store = InMemoryJobStore()
    for i in range(8):                                               # backlog 8 > surviving capacity 4
        store.create(Job.new(engine="clip", filename=f"f{i}.docx"))
    gate = DynamicConcurrencyGate(8)
    pool = _Pool(runtime=_CRuntime())
    res = _start_node_sizer(pool, ["clip"], store, "cascade", 8, gate, 0.0)  # cold priced 1:1 (0.0)
    assert res is not None
    stop, thread, sizer = res
    try:
        assert pool.warm_size <= 4                  # capped at surviving capacity, not the ceiling of 8
        # the 4 slots the cascade can't warm are freed to the cold path, not lost off the budget
        assert gate.limit >= 2, f"cold gate starved to {gate.limit} (should get the freed headroom)"
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_start_node_sizer_skips_on_incomplete_inventory(tmp_path, monkeypatch):
    # PR #60 r13 (SF7Lh): a dispatcher serving engines not all in BLASTBOX_NODE_ENGINES must
    # NOT size — the pool footprint would be derived from a partial inventory → under-count.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")   # only clip declared
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["clip", "red"], InMemoryJobStore(), "firecracker")
    assert res is None                                    # red undeclared → fail closed


def test_start_node_sizer_caps_ceiling_at_concurrency(tmp_path, monkeypatch):
    # PR #60 r14: the pool ceiling is capped at BLASTBOX_DISPATCH_CONCURRENCY — the sizer must
    # not warm more slots than the dispatcher can actually run (each in-flight job = one slot
    # of RAM). This is how the node budget stays bounded by real in-flight RAM (warm+cold).
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "64")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    store = InMemoryJobStore()
    for _ in range(50):
        store.create(Job.new(engine="clip", filename="x"))     # huge backlog → wants many slots
    pool = _Pool()
    res = _start_node_sizer(pool, ["clip"], store, "firecracker", 3)   # concurrency=3
    assert res is not None
    stop, thread, sizer = res
    try:
        assert pool.concurrent_ceiling <= 3                    # capped despite the big backlog
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_start_node_sizer_returns_none_if_publish_fails(tmp_path, monkeypatch):
    # PR #60 r14: if the synchronous first tick can't publish (e.g. read-only share_dir), the
    # sizer can never work AND the pool is still unspawned — return None so the caller restores
    # the pool instead of leaving a non-working sizer + a dead pool.
    from blastbox.host import node_share
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore

    def boom(self, snap):
        raise OSError("read-only share")

    monkeypatch.setattr(node_share.FileNodeShare, "publish", boom)
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    assert _start_node_sizer(_Pool(), ["clip"], InMemoryJobStore(), "firecracker", 4) is None


def test_start_node_sizer_sizes_pool_synchronously(tmp_path, monkeypatch):
    # PR #60 r13 (SDoR-): the sizer does one synchronous tick before the background thread, so
    # a pool started unspawned is sized from the node budget before dispatch serves.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    pool = _Pool()
    res = _start_node_sizer(pool, ["clip"], InMemoryJobStore(), "firecracker")
    assert res is not None
    stop, thread, sizer = res
    try:
        assert pool.concurrent_ceiling >= 1              # sized by the synchronous first tick
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_multi_engine_pool_uses_max_footprint(tmp_path, monkeypatch):
    # PR #60 r12: a dispatcher serving several engines with DIFFERENT slot footprints sizes
    # one shared pool — it must use the CONSERVATIVE (max) footprint across them, or the
    # ceiling under-counts RAM and oversubscribes the node.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,red")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "512")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_RED_RAM_MIB", "2048")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["clip", "red"], InMemoryJobStore(), "firecracker")
    assert res is not None
    stop, thread, sizer = res
    try:
        assert sizer._engine.slot_ram_mib == 2048.0        # max of clip(512) + red(2048)
    finally:
        stop.set()
        thread.join(2.0)
        sizer.remove_own_snapshot()


def test_node_id_with_path_separator_is_rejected(tmp_path):
    # regression (PR #60 r10): a BLASTBOX_NODE_ID with a path separator would make every
    # publish raise (traversal guard) and the sizer loop forever without publishing → peers
    # oversubscribe. Reject it at construction, like engine names.
    import pytest
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True)
    with pytest.raises(ValueError):
        DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg,
                        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 1, node="site/rack1")


def test_update_publish_is_fenced_when_stopped_mid_count(tmp_path):
    # regression (PR #60 r12): tick() publishes a heartbeat at start, then the UPDATED
    # snapshot after the (slow) count — but the update is fenced on the stop event. So a
    # shutdown that removes our file while we're blocked in the count isn't followed by a
    # republish that would leave a phantom pool. Simulate the CLI removing mid-count.
    import threading
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    stop = threading.Event()
    holder = {}

    def slow_count() -> int:                          # the CLI stops + removes us mid-count
        stop.set()
        holder["ds"].remove_own_snapshot()
        return 3

    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=slow_count, node="n",
                         instance="i", capacity_fn=_budget(8 * 1024, 99), clock=lambda: 1.0)
    holder["ds"] = ds
    ds._stop_event = stop
    ds.tick()
    assert list(tmp_path.glob("*.json")) == []        # heartbeat removed, update fenced → gone


def test_remove_own_snapshot_clears_the_pool_reservation(tmp_path):
    # regression (PR #60 r13): removal is the CALLER's job (the CLI calls it AFTER pool.stop()
    # reaps the slots, so the reservation isn't released while our RAM is still in use). run()
    # itself no longer removes on exit; remove_own_snapshot() clears exactly this unit's file.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, interval_s=0.5)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(assigned=1),
                         share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 2,
                         node="toolz2", instance="p9", capacity_fn=_budget(8 * 1024, 99))
    ds.run(max_ticks=2, sleep=lambda _s: None)
    assert list(tmp_path.glob("*.json"))              # snapshot still there after run() (not
    #                                                   removed early — reservation retained)
    ds.remove_own_snapshot()                          # the caller releases it (post-reap)
    assert list(tmp_path.glob("*.json")) == []


def test_read_all_gcs_long_abandoned_file(tmp_path):
    # regression (PR #60 review): a crashed process's snapshot (never gracefully removed) is
    # swept by read_all once its FILE MTIME is far past the staleness window, so the dir
    # self-cleans across restarts instead of accumulating dead per-instance files. GC is by
    # filesystem mtime (robust to a malformed payload; spares a just-republished file).
    import os
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("dead", 1, 0, 1024, 1, 0, 64, 1.0, ts=0.0,
                                 node="n", tier="firecracker", instance="ghost"))
    f = tmp_path / "dead@firecracker@n@ghost.json"
    assert f.exists()
    old = time.time() - 100_000                        # make the file's mtime ancient
    os.utime(f, (old, old))
    kept = share.read_all(max_age_s=20, now=time.time())
    assert [s.engine for s in kept] == []              # stale → out of the view
    assert not f.exists()                              # AND physically GC'd (by mtime)


def test_read_all_gcs_leaked_tmp_file(tmp_path):
    # regression (PR #60 r10): a `.tmp` left by a publish killed mid-write (SIGKILL/OOM) is
    # invisible to the `*.json` view, so it must be swept by the mtime GC or it accumulates.
    import os
    share = FileNodeShare(str(tmp_path))
    leaked = tmp_path / ".engine@firecracker@n@x.json.abc123.tmp"   # mkstemp-style dotfile
    leaked.write_text("{}")
    old = time.time() - 100_000
    os.utime(leaked, (old, old))
    share.read_all(max_age_s=20, now=time.time())
    assert not leaked.exists()                         # leaked temp GC'd by mtime


def test_read_all_survives_huge_int_ts(tmp_path):
    # regression (PR #60 r10): a huge-int ts out of json makes bare math.isfinite OVERFLOW;
    # read_all must skip such a file (via _finite_in bound), not raise out and wedge sizing.
    import json as _json
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("ok", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0,
                                 node="n", tier="firecracker", instance="g"))
    (tmp_path / "big@firecracker@n@h.json").write_text(_json.dumps({
        "engine": "big", "backlog": 1, "assigned": 0, "slot_ram_mib": 1024, "slot_vcpus": 1,
        "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 10 ** 400,
        "node": "n", "tier": "firecracker", "instance": "h"}))
    kept = {s.engine for s in share.read_all(max_age_s=20, now=1.0)}   # must not raise
    assert kept == {"ok"}


def test_publish_does_not_follow_planted_tmp_symlink(tmp_path):
    # regression (PR #60 P1): a peer pre-creating a predictable `<pool>.json.tmp` as a
    # symlink to a victim file must not cause publish() to follow it and truncate the victim.
    # mkstemp writes to an unpredictable, exclusively-created temp, so the planted link is
    # simply ignored.
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    sdir = tmp_path / "share"
    share = FileNodeShare(str(sdir))
    name = share._filename("clip", "firecracker", "n", "p1")
    # the old code's predictable temp name (<name>.json -> <name>.json.tmp), as a symlink
    (sdir / (name + ".tmp")).symlink_to(victim)
    share.publish(DemandSnapshot("clip", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0,
                                 node="n", tier="firecracker", instance="p1"))
    assert victim.read_text() == "precious"           # untouched — link not followed
    assert (sdir / name).exists()                     # snapshot still written correctly


def test_publish_rejects_path_traversal_identity(tmp_path):
    # regression (PR #60 P2): an identity component with a path separator must not let the
    # write escape the share dir.
    import pytest
    share = FileNodeShare(str(tmp_path))
    with pytest.raises(ValueError):
        share.publish(DemandSnapshot("../evil", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0,
                                     node="n", tier="firecracker", instance="p1"))


def test_slow_current_count_widens_staleness_and_keeps_peer(tmp_path):
    # regression (PR #60 P2): a suddenly-slow count THIS tick must widen the staleness window
    # now (from now-started), not rely on the previous tick's fast duration — otherwise a
    # live peer is aged out and this dispatcher sizes to the full node budget.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 40, 0, 1024, 1, 0, 64, 1.0, ts=0.0,
                                 node="toolz2", tier="firecracker", instance="r1"))
    pool = _Pool()
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, interval_s=5.0, stale_after_s=20.0)
    times = iter([0.0, 25.0, 25.0, 25.0, 25.0])       # started=0, now=25 → a 25s count
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 4, node="toolz2",
                         instance="c1", capacity_fn=_budget(8 * 1024, 999),
                         clock=lambda: next(times))
    mine = ds.tick()
    # red is 25s old > the 20s base window, but now-started=25 widens it to ~60s → red stays
    # in view → clip SHARES the 8-slot node instead of grabbing all 8.
    assert mine.concurrent_ceiling < 8


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


# --- round-5 regressions ---

def test_default_node_lets_containers_coordinate(tmp_path, monkeypatch):
    # regression: node id must NOT default to the container hostname (each engine container
    # has a different one → they'd never see each other). Default "" = share_dir boundary.
    monkeypatch.delenv("BLASTBOX_NODE_ID", raising=False)
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 40, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node=""))
    pool = _Pool(assigned=0)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 4,
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.concurrent_ceiling < 10       # shares the node with red — NOT isolated to itself


def test_node_namespaced_files_dont_collide_across_hosts(tmp_path):
    # regression (PR #60 review): with BLASTBOX_NODE_ID set to isolate an accidentally
    # shared dir, two hosts running the SAME engine must not collide on <engine>.json —
    # the file is namespaced <engine>@<node>.json so each host keeps its own snapshot.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 3, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="hostA"))
    share.publish(DemandSnapshot("clip", 9, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="hostB"))
    names = sorted(p.name for p in tmp_path.glob("*.json"))
    assert names == ["clip@hostA.json", "clip@hostB.json"]     # no collision
    seen = {(s.node, s.backlog) for s in share.read_all(max_age_s=60, now=1.0)}
    assert seen == {("hostA", 3), ("hostB", 9)}                # both survive


def test_split_cap_never_clips_incumbent_reservation(tmp_path):
    # PR #60 codex P1: splitting max_ceiling when a replica joins must NOT clip the INCUMBENT's
    # hard `reserved` floor — plan_sizes seats min(reserved, max_ceiling), so a cap split below the
    # incumbent's residency would let a newcomer grow into slots the incumbent's VMs still occupy.
    # cap = max(split, reserved), so the incumbent holds its 8 resident until it drains.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 0, 0, 1024, 1, 0, 8, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="b"))     # newly joined replica
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool(slot_count=8)                                          # incumbent: 8 resident VMs
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="a",
                         instance="a", capacity_fn=_budget(12 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.concurrent_ceiling >= 8            # reservation preserved, NOT clipped to split-cap 4


def test_local_warm_floor_split_across_replicas(tmp_path):
    # PR #60 codex P2: the LOCAL warm target must use the split min_warm too — else two replicas of
    # a min_warm=2 engine each warm 2 (aggregate 4) for the configured floor of 2.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 0, 0, 1024, 1, 2, 8, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="b"))     # replica peer, min_warm=2
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=2),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0,
                         node="n", instance="a", capacity_fn=_budget(16 * 1024, 999),
                         clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.warm_size == 1                      # split floor 2/2=1, not the full 2


def test_per_engine_cap_and_floor_split_across_replicas(tmp_path):
    # PR #60 codex P2: min_warm and max_ceiling are per-ENGINE — splitting only backlog/weight let
    # two replicas of a cap-8 engine each get 8 (aggregate 16) and a floor of 4 become 8. The cap
    # and floor are now split across replicas too.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 100, 0, 1024, 1, 2, 8, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="b"))   # min_warm=2, max_ceiling=8
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=2),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 100,
                         node="n", instance="a", capacity_fn=_budget(64 * 1024, 999),
                         clock=lambda: 1.0)                            # huge budget + backlog
    mine = ds.tick()
    assert mine.concurrent_ceiling <= 4        # split cap 8/2=4, NOT the full 8 despite the budget


def test_late_finishing_count_is_consumed_not_discarded(tmp_path):
    # PR #60 codex P1: a count that exceeds its deadline but finishes before the next tick must be
    # CONSUMED (into _last_backlog), not discarded when the replacement is launched — else a
    # consistently-just-over-deadline query never advances the backlog.
    import threading
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=0.3, interval_s=0.3)
    block = threading.Event()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), _Pool(), share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: block.wait(5.0) or 1,
                         node="n", instance="i", capacity_fn=_budget(8 * 1024, 999))

    class _DoneThread:                          # a prior count that already finished
        def is_alive(self):
            return False
    ds._count_thread = _DoneThread()
    ds._count_result = {"v": 9}                 # its (late) result, not yet consumed
    ds._last_backlog = 0
    ds.tick()                                   # new count blocks past the deadline → falls back
    block.set()
    assert ds._last_backlog == 9                # consumed the prior result, didn't reset to 0


def test_backlog_remainder_distributed_not_floored_to_zero(tmp_path):
    # PR #60 codex P1: when the shared backlog is SMALLER than the replica count, flooring the
    # divisor gave EVERY replica a warm target of 0, stranding the job (warm-only mode won't burst
    # without a demand miss). The remainder is now handed to the lowest-sorted instances so the
    # replicas' warm targets still SUM to the backlog.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 1, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="b"))     # replica peer, sorts after "a"
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=0),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 1,
                         node="n", instance="a", capacity_fn=_budget(8 * 1024, 999),
                         clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.warm_size == 1        # "a" (lowest-ranked) gets the +1, not floor(1/2)=0 for all


def test_untargeted_backlog_deduped_across_engine_tiers(tmp_path):
    # PR #60: fc + gvisor of ONE engine drain the SAME untargeted queue, so its demand is counted
    # ONCE across the engine's tier-pools, not once per tier. A fc pool sharing the untargeted queue
    # with a gvisor peer of the same engine gets a SMALLER ceiling than the same fc pool alone.
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)

    def _ceiling(with_gvisor_peer):
        share = FileNodeShare(str(tmp_path / ("b" if with_gvisor_peer else "a")))
        if with_gvisor_peer:
            # a gvisor peer of the SAME engine, draining the same 10 untargeted jobs
            share.publish(DemandSnapshot("clip", 10, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                                         tier="gvisor", instance="g", untargeted_backlog=10))
        pool = _Pool()
        ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                             cfg, runtime="firecracker", backlog_fn=lambda: 10,
                             untargeted_backlog_fn=lambda: 10, node="n", instance="f",
                             capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
        return ds.tick().concurrent_ceiling

    alone = _ceiling(with_gvisor_peer=False)          # fc alone: untargeted demand 10
    shared = _ceiling(with_gvisor_peer=True)          # fc + gvisor: untargeted demand split → 5 each
    assert shared < alone                             # the shared untargeted queue isn't double-counted


def test_shared_backlog_split_across_replicas(tmp_path):
    # PR #60 codex P2: two replicas of the same engine+tier drain the SAME queue, so each reporting
    # the full backlog doubles that engine's demand. Split it: clip (2 replicas, backlog 10 each)
    # and red (1 pool, backlog 10) should get EQUAL total shares, not clip 2×.
    share = FileNodeShare(str(tmp_path))
    # a clip replica peer + a red peer, all backlog 10, on the same node.
    share.publish(DemandSnapshot("clip", 10, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="c2"))
    share.publish(DemandSnapshot("red", 10, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="n",
                                 tier="firecracker", instance="r1"))
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 10, node="n",
                         instance="c1", capacity_fn=_budget(12 * 1024, 999), clock=lambda: 1.0)
    ds.tick()
    # THIS clip replica gets ~a quarter of the budget (clip's half, split over 2 replicas), i.e.
    # roughly half of red's share — NOT an equal-to-red share that would double clip's engine total.
    assert pool.concurrent_ceiling <= 5           # not the ~8 it'd take if the backlog weren't split


def test_fail_closed_when_view_cannot_be_read(tmp_path):
    # PR #60 codex P1: if PUBLISH works but the READ/list of the share fails, the dispatcher never
    # sees peers reclaiming its share and would hold a stale ceiling. Fail closed on lost visibility
    # (we can't read our own snapshot back), not just on publish failure.
    class _WriteOnlyShare:
        def publish(self, snap):
            pass                                   # writes "succeed"...

        def read_all(self, *, max_age_s, now):
            raise OSError("cannot list share")     # ...but the view can't be read

        def remove(self, snap):
            pass

    cfg = NodeConfig(balancing=True, resource_management=True, stale_after_s=1.0,
                     ram_headroom_frac=1.0, vcpu_oversubscription=999)
    pool = _Pool()
    pool.resize(warm_size=6, concurrent_ceiling=6)         # grew earlier
    ticks = {"n": 0}

    def clock():
        ticks["n"] += 1
        return ticks["n"] * 10.0                           # advances past the 1s window

    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=1),
                         pool, _WriteOnlyShare(), cfg, runtime=RUNTIME_FIRECRACKER,
                         backlog_fn=lambda: 5, node="n", instance="i",
                         capacity_fn=_budget(8 * 1024, 999), clock=clock)
    ds.run(max_ticks=2, sleep=lambda _s: None)
    assert pool.concurrent_ceiling == 1                    # floored — lost visibility, not held at 6


def test_slow_backlog_count_does_not_trigger_fail_closed(tmp_path):
    # PR #60 codex P2 (regression in the fail-closed fix): a backlog count slower than stale_after_s
    # must NOT make run() shrink the pool to its floor after an otherwise-successful tick. The
    # post-count update publish advances _last_publish_ok past the count, so the fail-closed timer
    # doesn't fire on a healthy-but-slow tick.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, stale_after_s=1.0,
                     ram_headroom_frac=1.0, vcpu_oversubscription=999)
    t = {"v": 0.0}

    def clock():
        return t["v"]

    def slow_count():
        t["v"] += 100.0                          # the count takes 100s, >> stale_after_s=1
        return 5

    pool = _Pool()
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8, min_warm=1),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=slow_count,
                         node="n", instance="i", capacity_fn=_budget(8 * 1024, 999), clock=clock)
    ds.run(max_ticks=1, sleep=lambda _s: None)
    assert pool.concurrent_ceiling > 1           # sized from the successful publish, NOT floored


def test_publish_orphan_lease_prices_cold_workers(tmp_path):
    # PR #60 codex P1: the orphan lease must price hung COLD workers in warm-slot equivalents too.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, stale_after_s=20.0)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048, max_ceiling=8), _Pool(), share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n",
                         instance="i", clock=lambda: 1000.0, cold_slot_ram_mib=4096)
    ds.publish_orphan_lease(1, 2)                 # 1 warm orphan + 2 cold @ 2x footprint
    mine = next(s for s in share.read_all(max_age_s=20.0, now=1100.0) if s.engine == "clip")
    assert mine.assigned == 1 + 2 * 2            # warm 1 + cold 2×(4096/2048) = 5
    # PR #60 codex P2: the lease caps max_ceiling AT the reservation, so plan_sizes can't
    # demand-fill spare budget into the dead pool (it reserves what's held, never grows).
    assert mine.max_ceiling == mine.assigned


def test_parse_mem_mib_bare_value_is_bytes():
    # PR #60 codex P2: a bare docker --memory value is BYTES (matches what docker enforces), not
    # MiB — mispricing it as MiB would balloon the cold footprint and throttle the node.
    from blastbox.host.cli import _parse_mem_mib
    assert _parse_mem_mib("4g") == 4096
    assert _parse_mem_mib("512m") == 512
    assert _parse_mem_mib("4294967296") == 4096      # 4 GiB in bytes → 4096 MiB
    assert _parse_mem_mib("") == 0.0


def test_locked_final_skips_when_publish_in_progress(tmp_path):
    # PR #60 codex P1: if a publish is still in progress (lock can't be acquired), the final
    # remove/lease must SKIP rather than run anyway — else the in-flight publish's os.replace()
    # would clobber it (recreate a removed snapshot / overwrite the orphan lease) afterward.
    calls = []

    class _Share:
        def publish(self, snap):
            pass

        def read_all(self, *, max_age_s, now):
            return []

        def remove(self, snap):
            calls.append("remove")

    class _HeldLock:                     # a publish is in flight → acquire fails
        def acquire(self, timeout=None):
            return False

        def release(self):
            pass

    cfg = NodeConfig(balancing=True, resource_management=True)
    ds = DispatcherSizer(EngineNode("clip", "-"), _Pool(), _Share(), cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n", instance="i")
    ds._publish_lock = _HeldLock()
    ds.remove_own_snapshot()
    assert calls == []                   # skipped — did NOT race the in-flight publish


def test_count_skipped_while_previous_thread_alive(tmp_path):
    # PR #60 codex P2: at most ONE outstanding count — a still-running prior count thread (wedged
    # backlog_fn) must not spawn another every tick (thread/connection accumulation). Skip and use
    # the last-known backlog.
    share = FileNodeShare(str(tmp_path))
    calls = {"n": 0}

    def backlog_fn():
        calls["n"] += 1
        return 3

    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), _Pool(), share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=backlog_fn, node="n",
                         instance="i", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0)
    ds._last_backlog = 7

    class _AliveThread:                  # pretend a prior count is still running
        def is_alive(self):
            return True
    ds._count_thread = _AliveThread()
    ds.tick()
    assert calls["n"] == 0               # backlog_fn NOT invoked — reused last_backlog


def test_publish_orphan_lease_extends_reservation_lifetime(tmp_path):
    # PR #60 codex P1: on shutdown with unreaped VMs (a Firecracker guest has NO idle TTL), the
    # reservation must outlive the normal ~20s window. publish_orphan_lease re-publishes what's
    # still running with an extended lifetime (up to the reader's GC floor), so peers keep it.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, stale_after_s=20.0)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), _Pool(), share,
                         cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0, node="n",
                         instance="i", clock=lambda: 1000.0)
    ds.publish_orphan_lease(3)                    # 3 slots still consuming
    # far past the normal 20s window, but within the extended lease → still visible, reserving 3.
    live = [s for s in share.read_all(max_age_s=20.0, now=1000.0 + 200) if s.engine == "clip"]
    assert len(live) == 1 and live[0].assigned == 3
    # past the reader's GC floor (~300s) → finally aged out.
    assert [s for s in share.read_all(max_age_s=20.0, now=1000.0 + 400) if s.engine == "clip"] == []


def test_staleness_uses_publisher_declared_window_not_reader(tmp_path):
    # PR #60 audit P1: a peer's liveness is decided by ITS OWN published window (refresh_s /
    # stale_after_s), so two readers with different LOCAL windows agree on the same snapshot set —
    # otherwise a slow-but-live peer aged out by fast readers and kept by slow ones splits the node
    # into divergent plans → oversubscription. A peer declaring stale_after_s=50 stays visible to a
    # reader whose own max_age is only 20, and ages out at the SAME point (50) for everyone.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 5, 0, 1024, 1, 0, 64, 1.0, ts=100.0, node="n",
                                 stale_after_s=50.0))
    # reader passes a SMALL window (20), but the publisher declared 50 → still fresh at age 40.
    assert {s.engine for s in share.read_all(max_age_s=20.0, now=140.0)} == {"red"}
    # a reader with a LARGER window (90) agrees it's still fresh — same publisher window governs.
    assert {s.engine for s in share.read_all(max_age_s=90.0, now=140.0)} == {"red"}
    # past the publisher's own 50s window → aged out (age 60 > 50), consistently for any reader.
    assert {s.engine for s in share.read_all(max_age_s=20.0, now=160.0)} == set()
    assert {s.engine for s in share.read_all(max_age_s=90.0, now=160.0)} == set()


def test_default_node_keeps_plain_filename(tmp_path):
    # backcompat: node="" (the common single-host case) still writes <engine>.json.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 2, 0, 1024, 1, 0, 64, 1.0, ts=1.0))
    assert [p.name for p in tmp_path.glob("*.json")] == ["clip.json"]
    assert [s.engine for s in share.read_all(max_age_s=60, now=1.0)] == ["clip"]


def test_read_all_rejects_far_future_snapshot(tmp_path):
    # regression (PR #60 review): a snapshot dated far in the future (bad clock / stale
    # file) must not read as fresh forever — its negative age would keep a stopped engine
    # consuming node budget. Bound the age one staleness window on BOTH sides.
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 5, 0, 1024, 1, 0, 64, 1.0, ts=10_000.0))  # 9000s ahead
    assert share.read_all(max_age_s=60, now=1000.0) == []          # rejected as future
    # a modest skew within the window is still tolerated
    share.publish(DemandSnapshot("red", 5, 0, 1024, 1, 0, 64, 1.0, ts=1030.0))    # 30s ahead
    assert [s.engine for s in share.read_all(max_age_s=60, now=1000.0)] == ["red"]


def test_node_filename_mismatch_is_rejected(tmp_path):
    # anti-impersonation: a file named clip@hostA.json whose snapshot claims node=hostB
    # must be dropped (the filename node and the self-declared node must agree).
    import json as _json
    share = FileNodeShare(str(tmp_path))
    (tmp_path / "clip@hostA.json").write_text(_json.dumps({
        "engine": "clip", "backlog": 1, "assigned": 0, "slot_ram_mib": 1024,
        "slot_vcpus": 1, "min_warm": 0, "max_ceiling": 64, "weight": 1.0,
        "ts": 1.0, "node": "hostB"}))       # filename says hostA, payload says hostB
    assert share.read_all(max_age_s=60, now=1.0) == []


def test_read_all_tolerates_unknown_future_fields(tmp_path):
    # regression (PR #60 review): a NEWER peer that adds a DemandSnapshot field must not
    # make an OLDER reader drop its snapshot (TypeError → silent eviction → oversubscription
    # during a rolling upgrade). Unknown keys are filtered before construction.
    import json as _json
    share = FileNodeShare(str(tmp_path))
    good = DemandSnapshot("red", 2, 0, 1024, 1, 0, 64, 1.0, ts=1.0)
    payload = {**good.__dict__, "some_future_field": {"nested": [1, 2, 3]}, "another": 42}
    (tmp_path / "red.json").write_text(_json.dumps(payload))
    kept = share.read_all(max_age_s=60, now=1.0)
    assert [s.engine for s in kept] == ["red"]        # accepted despite the extra fields
    assert kept[0].backlog == 2 and kept[0].max_ceiling == 64


def test_valid_bounds_reject_overflow_and_infinite_ts(tmp_path):
    import json as _json
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("good", 5, 0, 1024, 1, 0, 64, 1.0, ts=1.0))
    (tmp_path / "big.json").write_text(_json.dumps({   # 400-digit backlog → float() overflow
        "engine": "big", "backlog": int("9" * 400), "assigned": 0, "slot_ram_mib": 1024,
        "slot_vcpus": 1, "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1.0}))
    (tmp_path / "inf.json").write_text(_json.dumps({   # non-finite ts never ages out
        "engine": "inf", "backlog": 1, "assigned": 0, "slot_ram_mib": 1024, "slot_vcpus": 1,
        "min_warm": 0, "max_ceiling": 64, "weight": 1.0, "ts": 1e999}))
    assert {s.engine for s in share.read_all(max_age_s=60, now=1.0)} == {"good"}   # no crash


# --- round-6 regressions ---

def test_partial_node_config_still_coordinates(tmp_path):
    # regression: on ONE host, if some engines set BLASTBOX_NODE_ID and some don't, the
    # UNTAGGED engine must still see a TAGGED peer (symmetric filter) — the old asymmetric
    # `s.node in ("", self._node)` hid the tagged peer from an untagged reader → it thought
    # it was alone → oversubscribed. clip(untagged) shares a 10-slot node with red(tagged).
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("red", 40, 0, 1024, 1, 0, 64, 1.0, ts=1.0, node="hostA"))
    pool = _Pool(assigned=0)
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64), pool, share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 4, node="",  # untagged
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.concurrent_ceiling < 10       # sees red → shares, not isolated to the whole node


def test_static_mode_warm_tracks_real_demand_not_weight(tmp_path):
    # regression: static mode used weight as WARM demand → a big weight held ceil(weight)
    # slots hot at zero backlog. Weight is a CEILING share, not a warm target: clip has
    # weight=8 (→ big ceiling to burst into) but backlog 0 → 0 warm slots.
    share = FileNodeShare(str(tmp_path))
    pool = _Pool(assigned=0)
    cfg = NodeConfig(resource_management=True, balancing=False, ram_headroom_frac=1.0,
                     vcpu_oversubscription=999, stale_after_s=60)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64, weight=8.0,
                                    min_warm=0),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 0,
                         capacity_fn=_budget(32 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert mine.concurrent_ceiling > 1        # weight bought a big ceiling to burst into
    assert mine.warm_size == 0                # but nothing held hot at zero backlog
    assert pool.warm_size == 0


def test_adaptive_sheds_below_half_under_sustained_pressure(tmp_path):
    # PR #60 r12: under sustained memory pressure the adaptive scale sheds to the 0.25 floor
    # (was 0.5, which could still authorize ~half the RAM under pressure → OOM risk). The
    # 1-per-engine baseline still keeps pools viable regardless.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, adaptive=True,
                     ram_headroom_frac=0.8, min_free_mib=2048.0)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 1,
                         avail_fn=lambda: 100.0)          # far below min_free → real pressure
    base = NodeBudget(ram_mib=1000.0, vcpus=10.0)
    for _ in range(30):
        out = ds._adapt(base)
    assert 0.24 <= out.ram_mib / base.ram_mib <= 0.26     # shed to the 0.25 floor


def test_adaptive_never_exceeds_physical_ram(tmp_path):
    # regression (codex HIGH): the adaptive UP-scale (cap 1.25) times a high headroom can
    # target >100% of node RAM → OOM. With headroom 1.0 the baseline budget already IS the
    # whole node, so the scale must cap at 1.0 (1/headroom) — never inflate past total.
    share = FileNodeShare(str(tmp_path))
    cfg = NodeConfig(balancing=True, resource_management=True, adaptive=True,
                     ram_headroom_frac=1.0, min_free_mib=100.0)
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg,
                         runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 1,
                         avail_fn=lambda: 1_000_000.0)   # tons of free RAM → wants to ramp up
    base = NodeBudget(ram_mib=1000.0, vcpus=10.0)
    for _ in range(50):
        out = ds._adapt(base)
    assert out.ram_mib <= base.ram_mib + 1e-6   # headroom 1.0 → never grows past total

    # contrast: with headroom 0.8 the baseline is 80% of node, so ramping to 1.25× is safe
    # (0.8 × 1.25 = 1.0 = the whole node, still not over).
    cfg2 = NodeConfig(balancing=True, resource_management=True, adaptive=True,
                      ram_headroom_frac=0.8, min_free_mib=100.0)
    ds2 = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024), _Pool(), share, cfg2,
                          runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 1,
                          avail_fn=lambda: 1_000_000.0)
    for _ in range(50):
        out2 = ds2._adapt(base)
    assert 1.24 <= out2.ram_mib / base.ram_mib <= 1.25   # allowed up to 1.25×, no further


def test_demand_snapshot_field_order_is_append_only():
    """Regression: new fields are APPENDED (`untargeted_backlog`, `overflow_only`, `lease`), so adding
    one never reinterprets an existing POSITIONAL constructor arg. A caller that passed the
    consensus fields positionally (…, balancing, stale_after_s, budget_ram_mib, budget_vcpus)
    must keep binding them to those fields — not silently absorb one into a newer field."""
    import dataclasses

    fields = [f.name for f in dataclasses.fields(DemandSnapshot)]
    assert fields[-6:] == ["untargeted_backlog", "overflow_only", "lease", "running",
                           "engines", "serving"], (
        f"new fields must be appended in order (append-only); order is {fields}")

    # Positional construction through `balancing` still lands each value on its field.
    snap = DemandSnapshot(
        "eng", 10, 2, 1024.0, 1.0, 0, 64, 1.0, 100.0,   # engine..ts (9 positional)
        "node-x", "firecracker", 5.0, "inst-1", True,   # node, tier, refresh_s, instance, balancing
    )
    assert snap.engine == "eng" and snap.backlog == 10 and snap.ts == 100.0
    assert (snap.node == "node-x" and snap.tier == "firecracker"
            and snap.refresh_s == 5.0 and snap.instance == "inst-1" and snap.balancing is True)
    # The consensus/budget/untargeted fields keep their defaults — none was shifted by the append.
    assert snap.untargeted_backlog == 0 and snap.overflow_only is None and snap.lease is None
    assert snap.budget_ram_mib == 0.0 and snap.budget_vcpus == 0.0 and snap.stale_after_s == 0.0


def test_sizer_warns_when_min_warm_floor_starved(tmp_path, caplog):
    # Reproduce the production wedge (issue #68): a node whose RAM budget can't seat BOTH
    # clippyshot's 12x4096 MiB warm floor (~48 GiB) AND redtusk's 8x2048 MiB floor (~16 GiB).
    # The higher-demand engine (clip) seats its floor; redtusk is clamped BELOW its min_warm.
    # The sizer must WARN so the over-subscription is visible instead of a silent warm-only wedge.
    import logging

    share = FileNodeShare(str(tmp_path))
    cap = _budget(53_000, 999)                 # RAM is the binding resource
    common = dict(balancing=True, resource_management=True, stale_after_s=1e9,
                  ram_headroom_frac=1.0, vcpu_oversubscription=999)
    clip = DispatcherSizer(
        EngineNode("clip", "-", slot_ram_mib=4096, max_ceiling=64, min_warm=12),
        _Pool(), share, NodeConfig(**common),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 40, node="n", instance="c",
        capacity_fn=cap, clock=lambda: 1000.0)
    red = DispatcherSizer(
        EngineNode("red", "-", slot_ram_mib=2048, max_ceiling=64, min_warm=8),
        _Pool(), share, NodeConfig(**common),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 8, node="n", instance="r",
        capacity_fn=cap, clock=lambda: 1000.0)

    with caplog.at_level(logging.WARNING, logger="blastbox.node_sizer"):
        for _ in range(3):                     # converge the shared view
            clip.tick()
            red.tick()

    starved_warns = [r.getMessage() for r in caplog.records if "blastbox#68" in r.getMessage()]
    # Under proportional shrink BOTH engines land below their declared floors on an
    # over-subscribed node — the warning must fire for the pool that asked for a floor it
    # isn't getting (redtusk here; clip too, since neither is fully seated).
    assert any("engine=red" in m and "configured min_warm=8" in m for m in starved_warns), starved_warns


def test_sizer_no_floor_warning_when_floors_fit(tmp_path, caplog):
    # Same node, clippyshot floor capped to 6 (~24 GiB): 24 + 16 = 40 < 53 → both fit, no warning.
    import logging

    share = FileNodeShare(str(tmp_path))
    cap = _budget(53_000, 999)
    common = dict(balancing=True, resource_management=True, stale_after_s=1e9,
                  ram_headroom_frac=1.0, vcpu_oversubscription=999)
    clip = DispatcherSizer(
        EngineNode("clip", "-", slot_ram_mib=4096, max_ceiling=64, min_warm=6),
        _Pool(), share, NodeConfig(**common),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 40, node="n", instance="c",
        capacity_fn=cap, clock=lambda: 1000.0)
    red = DispatcherSizer(
        EngineNode("red", "-", slot_ram_mib=2048, max_ceiling=64, min_warm=8),
        _Pool(), share, NodeConfig(**common),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 8, node="n", instance="r",
        capacity_fn=cap, clock=lambda: 1000.0)

    with caplog.at_level(logging.WARNING, logger="blastbox.node_sizer"):
        for _ in range(3):
            clip.tick()
            red.tick()

    assert not [r for r in caplog.records if "blastbox#68" in r.getMessage()]


def test_no_floor_warning_for_cold_only_dispatcher(tmp_path, caplog):
    # issue #68 (escalation review): a cold-only dispatcher (pool=None, runtime=cold) applies warm=0
    # regardless of a misconfigured min_warm>0 — so even when unseatable_floors flags its cold
    # ceiling below that floor, it must NOT emit the warm-shrink warning (wrong semantics for cold).
    import logging

    share = FileNodeShare(str(tmp_path))
    cap = _budget(7000, 999)                    # tight: can't seat the cold floor
    common = dict(balancing=True, resource_management=True, stale_after_s=1e9,
                  ram_headroom_frac=1.0, vcpu_oversubscription=999)
    cold = DispatcherSizer(
        EngineNode("cold", "-", slot_ram_mib=4096, max_ceiling=64, min_warm=5),
        None, share, NodeConfig(**common),      # pool=None → cold-only
        runtime="cold", backlog_fn=lambda: 0, node="n", instance="c",
        capacity_fn=cap, clock=lambda: 1000.0)
    fc = DispatcherSizer(
        EngineNode("fc", "-", slot_ram_mib=2048, max_ceiling=64, min_warm=2),
        _Pool(), share, NodeConfig(**common),
        runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 50, node="n", instance="f",
        capacity_fn=cap, clock=lambda: 1000.0)

    with caplog.at_level(logging.WARNING, logger="blastbox.node_sizer"):
        for _ in range(3):
            fc.tick()
            cold.tick()

    cold_warns = [r.getMessage() for r in caplog.records
                  if "blastbox#68" in r.getMessage() and "engine=cold" in r.getMessage()]
    assert not cold_warns, cold_warns


class TestABacklogThatCannotBeReadSaysSo:
    """The whole of this file's #178 change is these two log lines, and nothing asserted them:
    the call site could be replaced with `pass` and the suite stayed green.

    Why they matter: falling back to `_last_backlog` is right for a transient store error and it
    is also how a PERMANENT one hides -- `_last_backlog` starts at 0 and never advances without a
    successful read, so "the store cannot answer" and "the queue is empty" size identically.
    A credential-less node whose backlog route is refused is exactly that case."""

    def _sizer(self, tmp_path, backlog_fn):
        share = FileNodeShare(str(tmp_path))
        cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                         vcpu_oversubscription=999, stale_after_s=60)
        return DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8), None,
                               share, cfg, runtime="cold", backlog_fn=backlog_fn, node="n",
                               instance="i", capacity_fn=_budget(8 * 1024, 999),
                               clock=lambda: 1.0, cold_slot_ram_mib=1024)

    def test_the_first_failure_is_reported(self, tmp_path, caplog):
        def refuses():
            raise RuntimeError("a node may not enumerate the queue")

        ds = self._sizer(tmp_path, refuses)
        with caplog.at_level("WARNING", logger="blastbox.node_sizer"):
            ds.tick()
        assert any("backlog could not be read" in r.message for r in caplog.records), (
            "a permanently unreadable backlog pinned sizing to its floors with nothing in "
            "the log -- indistinguishable from an empty queue")

    def test_it_warns_once_and_then_keeps_a_running_count(self, tmp_path, caplog):
        def refuses():
            raise RuntimeError("a node may not enumerate the queue")

        ds = self._sizer(tmp_path, refuses)
        with caplog.at_level("WARNING", logger="blastbox.node_sizer"):
            for _ in range(60):
                ds.tick()
        first = [r for r in caplog.records if "backlog could not be read" in r.message]
        running = [r for r in caplog.records if "times in a row" in r.message]
        assert len(first) == 1, f"the opening warning repeated {len(first)} times"
        assert running, (
            "no running count: an operator who joined the log tail after the outage started "
            "sees nothing at all")

    def test_a_backlog_that_answers_says_nothing(self, tmp_path, caplog):
        ds = self._sizer(tmp_path, lambda: 5)
        with caplog.at_level("WARNING", logger="blastbox.node_sizer"):
            ds.tick()
        assert not [r for r in caplog.records if "backlog" in r.message]


# --- overflow-only pools (BLASTBOX_CLAIM_UNTARGETED_AFTER_S) -------------------------------------
# A dispatcher with a claim delay declines UNTARGETED work until it has aged, so a co-resident
# warm dispatcher claims it first. The planner must therefore not hand that pool a share of the
# engine's untargeted backlog: the warm pools are sized for all of it, the overflow pool keeps
# only what is targeted at its own tier.

_OVF_CFG = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=1.0,
                      vcpu_oversubscription=999, stale_after_s=60)


_PLAN: dict = {}     # the last node plan a tick computed (every pool's PoolSize), set by the spy


def _capture_specs(monkeypatch):
    """Record the PoolSpecs every tick hands plan_sizes (keyed by pool name), and the plan it
    returned in _PLAN."""
    from blastbox.host import dispatcher_sizer as mod
    seen: dict = {}
    real = mod.plan_sizes

    def _spy(specs, budget):
        seen.clear()
        seen.update({s.name: s for s in specs})
        plan = real(specs, budget)
        _PLAN.clear()
        _PLAN.update(plan)
        return plan
    monkeypatch.setattr(mod, "plan_sizes", _spy)
    return seen


def _peer(tier, instance, backlog, untargeted, *, overflow_only=None, max_ceiling=64,
          engine="clip", ram=1024):
    kw = ({} if overflow_only is None
          else {"overflow_only": overflow_only, "lease": False, "running": 0,
                "engines": 1, "serving": True})
    return DemandSnapshot(engine, backlog, 0, ram, 1, 0, max_ceiling, 1.0, ts=1.0, node="n",
                          tier=tier, instance=instance, untargeted_backlog=untargeted,
                          balancing=True, **kw)


def _fc_sizer(share, *, backlog, untargeted, overflow_only=False, ram_budget=64 * 1024,
              max_ceiling=64, instance="f", tier="firecracker"):
    return DispatcherSizer(
        EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=max_ceiling),
        None if tier == "cold" else _Pool(), share,   # a cold-only dispatcher has no warm pool
        _OVF_CFG, runtime=tier, backlog_fn=lambda: backlog,
        untargeted_backlog_fn=lambda: untargeted, node="n", instance=instance,
        capacity_fn=_budget(ram_budget, 999), clock=lambda: 1.0, overflow_only=overflow_only)


def test_overflow_only_cold_takes_no_untargeted_share(tmp_path, monkeypatch):
    # warm fc + cold (overflow-only) of one engine, 16 untargeted queued: fc is sized for all 16,
    # cold for none of them — not 8/8, which left the burst past the warm share landing cold, late.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    mine = _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert mine.warm_size == 16
    assert specs["clip@firecracker@f"].queued == 16
    assert specs["clip@cold@c"].queued == 0
    assert specs["clip@cold@c"].demand == 0          # no budget priority for work it declines


def test_overflow_only_cold_still_sizes_for_jobs_targeted_at_it(tmp_path, monkeypatch):
    # cold's backlog is 20 of which 16 untargeted → 4 targeted at the cold tier. The exclusion only
    # drops the untargeted share; the tier-targeted demand is untouched.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("cold", "c", 20, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 4
    assert specs["clip@firecracker@f"].queued == 16


def test_engine_with_only_overflow_pools_gets_whole_untargeted_share(tmp_path, monkeypatch):
    # Fallback: no pool of the engine claims untargeted work promptly, so the overflow pools still
    # split it (today's behaviour) — work is never left unsized.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    mine = _fc_sizer(share, backlog=16, untargeted=16, overflow_only=True).tick()
    assert mine.warm_size == 16
    assert specs["clip@firecracker@f"].queued == 16
    # two overflow-only pools, no prompt one: they split it like any two pools
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    mine = _fc_sizer(share, backlog=16, untargeted=16, overflow_only=True).tick()
    assert specs["clip@firecracker@f"].queued == 8 and specs["clip@cold@c"].queued == 8
    assert mine.warm_size == 8


def test_overflow_only_is_per_engine(tmp_path, monkeypatch):
    # Another engine's prompt pool doesn't make this engine's overflow pool drop its share: the
    # fallback is decided per engine.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("firecracker", "r", 10, 10, engine="red", overflow_only=False))
    mine = _fc_sizer(share, backlog=16, untargeted=16, overflow_only=True).tick()
    assert mine.warm_size == 16
    assert specs["clip@firecracker@f"].queued == 16
    assert specs["red@firecracker@r"].queued == 10


def test_snapshot_without_overflow_field_is_not_overflow_only(tmp_path, monkeypatch):
    # Mixed-version: an older cold dispatcher's snapshot has no `overflow_only` key. It is treated
    # as prompt (today's even split), never as overflow.
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    old = asdict(_peer("cold", "c", 16, 16))
    old.pop("overflow_only", None)
    old.pop("lease", None)
    old.pop("running", None)
    old.pop("engines", None)
    old.pop("serving", None)
    (tmp_path / FileNodeShare._filename("clip", "cold", "n", "c")).write_text(json.dumps(old))
    mine = _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert "clip@cold@c" in specs                     # the old snapshot was accepted
    assert specs["clip@cold@c"].queued == 8
    assert specs["clip@firecracker@f"].queued == 8
    assert mine.warm_size == 8


def test_poisoned_overflow_flag_is_rejected(tmp_path):
    # Like `balancing`, the flag steers every reader's plan, so a non-bool is dropped, not coerced.
    import json
    from dataclasses import asdict
    share = FileNodeShare(str(tmp_path))
    bad = asdict(_peer("cold", "c", 16, 16, overflow_only=True))
    bad["overflow_only"] = "yes"
    (tmp_path / FileNodeShare._filename("clip", "cold", "n", "c")).write_text(json.dumps(bad))
    assert share.read_all(max_age_s=60, now=1.0) == []


def test_untargeted_shares_sum_to_the_count_with_overflow_pools(tmp_path, monkeypatch):
    # Invariant: however the engine's pools are flagged, the untargeted shares (float demand AND the
    # integer warm split) sum to the untargeted count — nothing double-counted, nothing dropped.
    import itertools
    specs = _capture_specs(monkeypatch)
    pools = [("firecracker", "a"), ("firecracker", "b"), ("gvisor", "g")]
    for flags in itertools.product([False, True], repeat=len(pools)):
        for u in (0, 1, 2, 3, 7, 16):
            d = tmp_path / f"{''.join('1' if f else '0' for f in flags)}-{u}"
            share = FileNodeShare(str(d))
            for (tier, inst), f in zip(pools, flags):
                share.publish(_peer(tier, inst, u, u, overflow_only=f))
            warm_total = 0
            for (tier, inst), f in zip(pools, flags):
                mine = _fc_sizer(share, backlog=u, untargeted=u, overflow_only=f,
                                 instance=inst, tier=tier).tick()
                warm_total += mine.warm_size
                assert abs(sum(s.queued for s in specs.values()) - u) < 1e-9, (flags, u)
                if any(not x for x in flags):
                    # overflow pools take nothing while a prompt pool exists
                    for (t2, i2), f2 in zip(pools, flags):
                        if f2:
                            assert specs[f"clip@{t2}@{i2}"].queued == 0, (flags, u)
            assert warm_total == u, (flags, u)


def test_budget_no_longer_reserved_for_colds_declined_untargeted_share(tmp_path, monkeypatch):
    # Tight budget (8 slots): fc wants 16 untargeted, cold is overflow-only with only untargeted
    # queued. Before the fix cold's equal demand split the budget 4/4; now fc outranks it and takes
    # everything above cold's 1-slot baseline. Σ ceiling·footprint still ≤ budget.
    _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    mine = _fc_sizer(share, backlog=16, untargeted=16, ram_budget=8 * 1024).tick()
    assert mine.concurrent_ceiling == 7
    plan = dict(_PLAN)
    assert plan["clip@cold@c"].concurrent_ceiling == 1
    assert sum(p.concurrent_ceiling * 1024 for p in plan.values()) <= 8 * 1024


def test_overflow_pool_keeps_its_reservation_and_floor(tmp_path, monkeypatch):
    # Dropping the untargeted share must not drop what cold is RUNNING (its reservation stays a
    # hard ceiling floor) — only its priority for work it declines.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(DemandSnapshot("clip", 16, 3, 1024, 1, 0, 64, 1.0, ts=1.0, node="n", tier="cold",
                                 instance="c", untargeted_backlog=16, overflow_only=True,
                                 balancing=True, lease=False, running=3, engines=1, serving=True))
    _fc_sizer(share, backlog=16, untargeted=16, ram_budget=8 * 1024).tick()
    cold = specs["clip@cold@c"]
    assert cold.reserved == 3 and cold.demand == 3 and cold.queued == 0
    plan = dict(_PLAN)
    assert plan["clip@cold@c"].concurrent_ceiling >= 3


def test_sizer_publishes_overflow_flag(tmp_path):
    share = FileNodeShare(str(tmp_path))
    _fc_sizer(share, backlog=0, untargeted=0, overflow_only=True).tick()
    (snap,) = share.read_all(max_age_s=60, now=1.0)
    assert snap.overflow_only is True
    share2 = FileNodeShare(str(tmp_path / "b"))
    _fc_sizer(share2, backlog=0, untargeted=0).tick()
    (snap2,) = share2.read_all(max_age_s=60, now=1.0)
    assert snap2.overflow_only is False


def test_start_node_sizer_threads_claim_delay_into_overflow_flag(tmp_path, monkeypatch):
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    for delay, want in ((3.0, True), (0.0, False)):
        res = _start_node_sizer(_Pool(), ["clip"], InMemoryJobStore(), "firecracker",
                                claim_untargeted_after_s=delay)
        assert res is not None
        stop, thread, sizer = res
        try:
            snaps = FileNodeShare(str(tmp_path)).read_all(max_age_s=60, now=time.time())
            assert [s.overflow_only for s in snaps] == [want]
        finally:
            stop.set()
            thread.join(2.0)
            sizer.remove_own_snapshot()


# --- version gate: the exclusion applies only when EVERY pool of the engine carries the field ----
# Pools plan independently from the shared view; the node stays within budget only because they
# all compute the SAME plan. A dispatcher from before `overflow_only` splits untargeted evenly, so
# while one of an engine's pools is on that version every planner must split that engine evenly
# too, or the old pool's slice and the new pools' slices come from different plans and can sum
# past the budget.

def _write_old(tmp_path_dir, tier, instance, backlog, untargeted, *, assigned=0, engine="clip"):
    """A pre-`overflow_only` peer: the key is absent from the file, not False."""
    import json
    from dataclasses import asdict
    raw = asdict(_peer(tier, instance, backlog, untargeted, engine=engine))
    raw.pop("overflow_only", None)
    raw.pop("lease", None)
    raw.pop("running", None)
    raw.pop("engines", None)
    raw.pop("serving", None)
    raw["assigned"] = assigned
    (tmp_path_dir / FileNodeShare._filename(engine, tier, "n", instance)).write_text(
        json.dumps(raw))


def _own_plan(monkeypatch, share, sizer):
    """What `sizer`'s planner computes for the node: {pool: ceiling}, plus the specs."""
    specs = _capture_specs(monkeypatch)
    sizer.tick()
    return {k: p.concurrent_ceiling for k, p in _PLAN.items()}, dict(specs)


def test_mixed_version_engine_keeps_the_even_split(tmp_path, monkeypatch):
    # (a) fc is new and prompt, cold is new and overflow-only, gvisor is OLD (no key). The new
    # planners must compute exactly what the old gvisor planner does — the even three-way split —
    # so each pool's own slice, taken from its own planner, stays within the budget jointly.
    mixed = tmp_path / "mixed"
    share = FileNodeShare(str(mixed))
    _write_old(mixed, "gvisor", "g", 16, 16)
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    new_fc, fc_specs = _own_plan(monkeypatch, share, _fc_sizer(
        share, backlog=16, untargeted=16, ram_budget=8 * 1024))
    cold_sizer = _fc_sizer(
        share, backlog=16, untargeted=16, ram_budget=8 * 1024, overflow_only=True,
        tier="cold", instance="c")
    assert cold_sizer._active()                         # it really plans (pool-less cold-only)
    new_cold, cold_specs = _own_plan(monkeypatch, share, cold_sizer)

    # what the OLD gvisor planner computes: the even split, i.e. no pool treated as overflow
    even = tmp_path / "even"
    eshare = FileNodeShare(str(even))
    eshare.publish(_peer("gvisor", "g", 16, 16, overflow_only=False))
    eshare.publish(_peer("cold", "c", 16, 16, overflow_only=False))
    old, old_specs = _own_plan(monkeypatch, eshare, _fc_sizer(
        eshare, backlog=16, untargeted=16, ram_budget=8 * 1024))

    for got in (fc_specs, cold_specs):
        assert {k: (s.queued, s.demand) for k, s in got.items()} == \
            {k: (s.queued, s.demand) for k, s in old_specs.items()}
        assert got["clip@cold@c"].queued == 16 / 3          # not excluded while gvisor is old
    assert new_fc == new_cold == old
    joint = (new_fc["clip@firecracker@f"] + new_cold["clip@cold@c"] + old["clip@gvisor@g"])
    assert joint * 1024 <= 8 * 1024


def test_exclusion_applies_once_every_pool_carries_the_field(tmp_path, monkeypatch):
    # (b) the same three pools, all upgraded: cold (overflow-only) is excluded.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("gvisor", "g", 16, 16, overflow_only=False))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 0
    assert specs["clip@firecracker@f"].queued == 8 and specs["clip@gvisor@g"].queued == 8


def test_old_pool_forces_even_split_even_without_an_overflow_pool(tmp_path, monkeypatch):
    # (c) a new prompt pool carrying the field + an old pool without it → the old split.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _write_old(tmp_path, "cold", "c", 16, 16)
    mine = _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8
    assert mine.warm_size == 8


def test_mixed_version_overflow_pool_keeps_its_warm_share(tmp_path, monkeypatch):
    # The warm-target split is gated too: a new overflow-only fc beside an OLD fc replica warms its
    # even share (the old replica warms only its own half), so the burst is still fully warmed.
    share = FileNodeShare(str(tmp_path))
    _write_old(tmp_path, "gvisor", "g", 16, 16)
    mine = _fc_sizer(share, backlog=16, untargeted=16, overflow_only=True).tick()
    assert mine.warm_size == 8


def test_gate_is_node_wide(tmp_path, monkeypatch):
    # The budget is NODE-wide: every planner plans every engine's pools and takes its own slice. An
    # old pool of ANOTHER engine (red) plans clip with the even split, so clip's exclusion must be
    # off too while red is old — else red's slice and clip's slices come from different plans.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _write_old(tmp_path, "firecracker", "r", 10, 10, engine="red")
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8


def test_legacy_pool_of_another_engine_cannot_oversubscribe(tmp_path, monkeypatch):
    # codex repro: 8 GiB node, 1 GiB slots. New clip prompt fc + new overflow-only clip cold each
    # report 16 untargeted; a LEGACY red pool reports 4. Before the node-wide gate the new planners
    # gave clip 6 + 1 while the legacy planner (even clip split) gave red 2 → 9 slots on an 8-slot
    # node. Each pool takes its slice from its OWN planner; the joint must fit.
    mixed = tmp_path / "mixed"
    share = FileNodeShare(str(mixed))
    _write_old(mixed, "firecracker", "r", 4, 4, engine="red")
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    new_fc, _ = _own_plan(monkeypatch, share, _fc_sizer(
        share, backlog=16, untargeted=16, ram_budget=8 * 1024))
    new_cold, _ = _own_plan(monkeypatch, share, _fc_sizer(
        share, backlog=16, untargeted=16, ram_budget=8 * 1024, overflow_only=True,
        tier="cold", instance="c"))
    # the legacy red planner: the even split, i.e. what a view where nobody is overflow computes
    even = tmp_path / "even"
    eshare = FileNodeShare(str(even))
    eshare.publish(_peer("firecracker", "r", 4, 4, engine="red", overflow_only=False))
    eshare.publish(_peer("cold", "c", 16, 16, overflow_only=False))
    legacy, _ = _own_plan(monkeypatch, eshare, _fc_sizer(
        eshare, backlog=16, untargeted=16, ram_budget=8 * 1024))
    assert new_fc == new_cold == legacy
    joint = new_fc["clip@firecracker@f"] + new_cold["clip@cold@c"] + legacy["red@firecracker@r"]
    assert joint * 1024 <= 8 * 1024


def test_exclusion_on_once_every_engine_is_current(tmp_path, monkeypatch):
    # the same node with red upgraded: the exclusion applies
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("firecracker", "r", 4, 4, engine="red", overflow_only=False))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16, ram_budget=8 * 1024).tick()
    assert specs["clip@cold@c"].queued == 0 and specs["clip@firecracker@f"].queued == 16


def test_current_lease_does_not_switch_the_node_gate_off(tmp_path, monkeypatch):
    # a lease of another engine published by current code carries the field
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, engine="red", instance="y")
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 0


def test_legacy_lease_switches_the_node_gate_off(tmp_path, monkeypatch):
    # a lease from a pre-field dispatcher looks like an old pool (no key): stay on the even split,
    # the conservative reading — an old planner may still be live on the node.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _write_old(tmp_path, "firecracker", "y", 0, 0, assigned=2, engine="red")
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8


def test_multi_engine_dispatcher_never_publishes_overflow_only(tmp_path, monkeypatch):
    # A dispatcher serving several engines publishes its COMBINED backlog under its first engine's
    # name; a prompt peer of that engine can't run the others, so excluding it could leave their
    # untargeted jobs unsized. Only a single-engine dispatcher publishes overflow_only=True.
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "aa,bb")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    for served, want in ((["aa", "bb"], False), (["aa"], True)):
        res = _start_node_sizer(_Pool(), served, InMemoryJobStore(), "firecracker",
                                claim_untargeted_after_s=3.0)
        assert res is not None
        stop, thread, sizer = res
        try:
            snaps = FileNodeShare(str(tmp_path)).read_all(max_age_s=60, now=time.time())
            assert [s.overflow_only for s in snaps] == [want], served
        finally:
            stop.set()
            thread.join(2.0)
            sizer.remove_own_snapshot()


# --- orphan leases never drain the queue -------------------------------------------------------
# A crashed/stopping dispatcher's orphan lease holds its still-running slots' reservation, but no
# process behind it claims anything. It must never be counted as an untargeted drainer: not as the
# prompt pool that turns an engine's overflow exclusion on, and not as a recipient of a share.

def _lease(share, *, tier="firecracker", instance="w", warm_orphans=2, overflow_only=False,
           engine="clip"):
    """Publish the lease a real DispatcherSizer leaves behind (the exact production snapshot)."""
    ds = DispatcherSizer(EngineNode(engine, "-", slot_ram_mib=1024, max_ceiling=64),
                         None if tier == "cold" else _Pool(), share, _OVF_CFG, runtime=tier,
                         backlog_fn=lambda: 0, node="n", instance=instance,
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0,
                         overflow_only=overflow_only)
    ds.publish_orphan_lease(warm_orphans)


def test_orphan_lease_is_marked(tmp_path):
    share = FileNodeShare(str(tmp_path))
    _lease(share)
    (snap,) = share.read_all(max_age_s=60, now=1.0)
    assert snap.lease is True and snap.overflow_only is False
    share2 = FileNodeShare(str(tmp_path / "live"))
    _fc_sizer(share2, backlog=0, untargeted=0).tick()
    (live,) = share2.read_all(max_age_s=60, now=1.0)
    assert live.lease is False


def test_overflow_cold_takes_untargeted_while_warm_is_only_a_lease(tmp_path, monkeypatch):
    # Reviewer's repro: budget 10, warm fc W of clip crashed leaving a lease (2 slots); cold C of
    # clip is overflow-only with 20 untargeted queued; engine red has 20 queued. The lease can't
    # claim, so C is the engine's only drainer and must be sized for all 20 — not demand 0.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, instance="w", warm_orphans=2)
    share.publish(_peer("firecracker", "y", 20, 20, engine="red", overflow_only=False))
    mine = _fc_sizer(share, backlog=20, untargeted=20, overflow_only=True, tier="cold",
                     instance="c", ram_budget=10 * 1024).tick()
    assert specs["clip@cold@c"].queued == 20 and specs["clip@cold@c"].demand == 20
    assert specs["clip@firecracker@w"].queued == 0                 # the lease: reservation only
    assert specs["clip@firecracker@w"].reserved == 2
    assert mine.concurrent_ceiling >= 3                            # not starved to the baseline
    plan = dict(_PLAN)
    assert plan["clip@firecracker@w"].concurrent_ceiling == 2
    assert sum(p.concurrent_ceiling * 1024 for p in plan.values()) <= 10 * 1024


def test_lease_beside_live_prompt_pool_gets_no_untargeted_share(tmp_path, monkeypatch):
    # live prompt fc F + a lease of a crashed fc replica + overflow-only cold C: the exclusion stays
    # on (F is a live prompt pool), F takes the whole untargeted count, lease and C take none.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, instance="w", warm_orphans=2)
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    mine = _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@firecracker@f"].queued == 16
    assert specs["clip@firecracker@w"].queued == 0
    assert specs["clip@cold@c"].queued == 0
    assert mine.warm_size == 16


def test_overflow_lease_does_not_count_as_a_live_drainer(tmp_path, monkeypatch):
    # a lease left by an OVERFLOW-only pool beside a live overflow-only pool: the live one takes it
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, tier="cold", instance="old", warm_orphans=1, overflow_only=True)
    mine = _fc_sizer(share, backlog=16, untargeted=16, overflow_only=True).tick()
    assert specs["clip@firecracker@f"].queued == 16
    assert specs["clip@cold@old"].queued == 0
    assert mine.warm_size == 16


def test_lease_only_engine_keeps_only_its_reservation(tmp_path, monkeypatch):
    # an engine whose only pool is a lease: nobody can drain its queue, so nothing is sized for it;
    # the lease holds exactly its reservation and the budget goes to the live engine.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, engine="red", instance="y", warm_orphans=2)
    _fc_sizer(share, backlog=4, untargeted=4, ram_budget=10 * 1024).tick()
    lease = specs["red@firecracker@y"]
    assert lease.queued == 0 and lease.reserved == 2 and lease.max_ceiling == 2
    plan = dict(_PLAN)
    assert plan["red@firecracker@y"].concurrent_ceiling == 2
    assert plan["clip@firecracker@f"].concurrent_ceiling == 8


def test_lease_cannot_switch_the_version_gate_off(tmp_path, monkeypatch):
    # a current lease carries overflow_only, so it never looks like a pre-field peer: live prompt fc
    # + overflow-only cold + a lease → the exclusion applies.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _lease(share, instance="w")
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 0


def test_lease_in_a_mixed_version_engine_keeps_the_old_split(tmp_path, monkeypatch):
    # An OLD reader drops the unknown `lease` key and divides the untargeted count by EVERY pool,
    # the lease included (the lease itself reports 0 queued, so its own share is 0 and each live
    # pool gets count/3). While any pool of the engine is old, new planners must compute that same
    # split, so a lease can't switch the gate ON either: old gvisor + lease + overflow cold.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    _write_old(tmp_path, "gvisor", "g", 15, 15)
    _lease(share, instance="w")
    mine = _fc_sizer(share, backlog=15, untargeted=15, overflow_only=True, tier="cold",
                     instance="c").tick()
    assert mine is not None
    assert {k: s.queued for k, s in specs.items()} == {
        "clip@gvisor@g": 5, "clip@firecracker@w": 0, "clip@cold@c": 5}


def test_untargeted_shares_sum_over_live_pools_with_leases(tmp_path, monkeypatch):
    # Invariant with leases in the view: a SPILLING engine (a live overflow pool) sums its shares
    # to the count with every lease at 0 (at least the count: a capped prompt pool keeps its legacy
    # share); without an overflow pool it is the legacy split, which on a current node leaves the
    # leases out of the denominator. Each lease's ceiling is its reservation; budget holds.
    import itertools
    specs = _capture_specs(monkeypatch)
    for flags in itertools.product([False, True], repeat=2):
        for n_leases in (1, 2):
            for u in (0, 1, 5, 16):
                d = tmp_path / f"{flags}-{n_leases}-{u}"
                share = FileNodeShare(str(d))
                for i in range(n_leases):
                    _lease(share, instance=f"l{i}", warm_orphans=1 + i, overflow_only=flags[i % 2])
                share.publish(_peer("gvisor", "g", u, u, overflow_only=flags[1]))
                mine = _fc_sizer(share, backlog=u, untargeted=u, overflow_only=flags[0],
                                 ram_budget=10 * 1024).tick()
                assert mine is not None
                if flags[0] or flags[1]:
                    assert sum(s.queued for s in specs.values()) >= u - 1e-9, (flags, n_leases, u)
                else:          # legacy split, leases out of the denominator on a current node
                    assert abs(sum(s.queued for s in specs.values()) - u) < 1e-9
                plan = dict(_PLAN)
                for i in range(n_leases):
                    assert specs[f"clip@firecracker@l{i}"].queued == 0
                    assert plan[f"clip@firecracker@l{i}"].concurrent_ceiling == 1 + i
                assert sum(p.concurrent_ceiling * 1024 for p in plan.values()) <= 10 * 1024


# --- spill-over: what the prompt pools can't take goes to the overflow pools ---------------------
# The prompt pools absorb the untargeted count only up to their CAPACITY — max_ceiling (the
# planner's per-replica cap) minus what is already running there (assigned) and what is queued
# targeted at that tier. The rest spills to the live overflow-only pools, so a capped warm pool
# beside an overflow cold doesn't strand the burst (cold was pinned at ceiling 1 forever).

def _cpeer(tier, instance, backlog, untargeted, *, overflow_only, max_ceiling=64, assigned=0,
           engine="clip", running=None):
    # `assigned` is the published RESERVATION (resident slots + cold in flight); `running` the jobs
    # actually running (defaults to all of the reservation being busy)
    return DemandSnapshot(engine, backlog, assigned, 1024, 1, 0, max_ceiling, 1.0, ts=1.0,
                          node="n", tier=tier, instance=instance, untargeted_backlog=untargeted,
                          balancing=True, overflow_only=overflow_only, lease=False,
                          running=assigned if running is None else running, engines=1, serving=True)


def test_capped_prompt_pool_spills_untargeted_to_overflow(tmp_path, monkeypatch):
    # reviewer's cap.py: budget 10; clip warm W capped at 2 and running 2; clip cold C overflow-only
    # with 20 untargeted; red Y 20 queued. W can take no more, so C is sized for the burst.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("firecracker", "w", 20, 20, overflow_only=False, max_ceiling=2,
                         assigned=2))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    DispatcherSizer(EngineNode("red", "-", slot_ram_mib=1024, max_ceiling=64), _Pool(), share,
                    _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 20,
                    untargeted_backlog_fn=lambda: 20, node="n", instance="y",
                    capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0,
                    overflow_only=False).tick()
    # W is at its cap (2 − 2 running = 0 capacity): it keeps its legacy share as DEMAND (20/2; it
    # can't seat it — max_ceiling 2 caps it) and ALL 20 spill to cold, since the residue counts
    # only what the prompt pools can take: 20 − min(10, 0).
    assert specs["clip@firecracker@w"].queued == 10
    assert specs["clip@cold@c"].queued == 20
    plan = dict(_PLAN)
    assert plan["clip@cold@c"].concurrent_ceiling >= 3   # not the self-locking 1
    assert plan["clip@firecracker@w"].concurrent_ceiling == 2
    assert sum(p.concurrent_ceiling * 1024 for p in plan.values()) <= 10 * 1024


def test_partly_capped_prompt_pool_keeps_its_capacity_and_spills_the_rest(tmp_path, monkeypatch):
    # prompt fc capped at 6 (nothing running, nothing targeted): it is sized and warmed for 6, the
    # overflow cold for the other 14.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    mine = _fc_sizer(share, backlog=20, untargeted=20, max_ceiling=6).tick()
    assert specs["clip@firecracker@f"].queued == 10        # max(capacity 6, old share 20/2)
    assert specs["clip@cold@c"].queued == 14               # 20 − min(10, 6)
    assert mine.warm_size == 6


def test_targeted_work_uses_up_prompt_capacity(tmp_path, monkeypatch):
    # prompt fc capped at 6 with 2 jobs targeted at it (backlog 22, 20 untargeted): 4 untargeted
    # fit, 16 spill.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    mine = _fc_sizer(share, backlog=22, untargeted=20, max_ceiling=6).tick()
    # 2 targeted + max(4 that fit, legacy share 20/2); cold gets 20 − min(10, 4)
    assert specs["clip@firecracker@f"].queued == 12
    assert specs["clip@cold@c"].queued == 16
    assert mine.warm_size == 6


def test_uncapped_prompt_pools_still_leave_overflow_nothing(tmp_path, monkeypatch):
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    _fc_sizer(share, backlog=20, untargeted=20, max_ceiling=20).tick()
    assert specs["clip@firecracker@f"].queued == 20 and specs["clip@cold@c"].queued == 0


def test_spill_shares_sum_to_the_count_over_a_grid(tmp_path, monkeypatch):
    # Σ untargeted shares == count for every mix of prompt caps × overflow pools × counts, in both
    # the float demand and the integer warm split; no prompt pool is handed more than its capacity
    # while an overflow pool exists.
    import itertools
    specs = _capture_specs(monkeypatch)
    n = 0
    for cap_a, cap_b, n_ovf, u in itertools.product((1, 3, 8, 64), (None, 2, 64), (0, 1, 2),
                                                     (0, 1, 5, 13, 40)):
        n += 1
        share = FileNodeShare(str(tmp_path / str(n)))
        prompt = [("firecracker", "a", cap_a)] + ([("gvisor", "b", cap_b)] if cap_b else [])
        ovf = [("cold", f"c{i}") for i in range(n_ovf)]
        for tier, inst, cap in prompt:
            share.publish(_cpeer(tier, inst, u, u, overflow_only=False, max_ceiling=cap))
        for tier, inst in ovf:
            share.publish(_cpeer(tier, inst, u, u, overflow_only=True))
        warm_total = 0
        for tier, inst, cap in prompt:
            mine = _fc_sizer(share, backlog=u, untargeted=u, max_ceiling=cap, instance=inst,
                             tier=tier).tick()
            q = specs[f"clip@{tier}@{inst}"].queued
            n_all = len(prompt) + len(ovf)
            if ovf:                    # ≥ the legacy share, and ≥ what fits (≤ cap) of the count
                assert q >= u / n_all - 1e-9, (cap_a, cap_b, n_ovf, u)
                assert sum(s.queued for s in specs.values()) >= u - 1e-9
            else:
                assert abs(sum(s.queued for s in specs.values()) - u * len(prompt) / n_all
                           ) < 1e-9, (cap_a, cap_b, n_ovf, u)
            warm_total += mine.warm_size
        prompt_cap = sum(c for _, _, c in prompt)
        if ovf:
            # the prompt pools warm at least what they can absorb (their legacy share too), never
            # past their caps; the overflow pools' share is exactly what the prompt pools can't take
            assert min(u, prompt_cap) <= warm_total <= prompt_cap, (cap_a, cap_b, n_ovf, u)
            for tier, inst in ovf:
                share_u = specs[f"clip@{tier}@{inst}"].queued
                assert abs(share_u - (u - min(u, prompt_cap)) / n_ovf) < 1e-9
        else:
            assert warm_total <= u


def test_gate_requires_lease_field_too(tmp_path, monkeypatch):
    # The gate keys on BOTH fields: a snapshot with `overflow_only` but no `lease` key comes from a
    # binary that would read a current lease as a prompt pool and plan differently, so the node
    # stays on the even split while one is in view.
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    raw = asdict(_peer("cold", "c", 16, 16, overflow_only=True))
    raw.pop("lease", None)
    (tmp_path / FileNodeShare._filename("clip", "cold", "n", "c")).write_text(json.dumps(raw))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert "clip@cold@c" in specs
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8


def test_spilled_share_warms_an_overflow_pool(tmp_path, monkeypatch):
    # the INTEGER (warm-target) split spills too: prompt fc capped at 6 with 2 targeted at it can
    # take 4 untargeted, so an overflow-only gvisor pool warms the other 16.
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("firecracker", "f", 22, 20, overflow_only=False, max_ceiling=6))
    mine = _fc_sizer(share, backlog=20, untargeted=20, overflow_only=True, tier="gvisor",
                     instance="g").tick()
    assert mine.warm_size == 16


def test_gate_requires_running_field_too(tmp_path, monkeypatch):
    # `running` came in the same change and the spill capacity reads it, so it is part of the gate
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    raw = asdict(_peer("cold", "c", 16, 16, overflow_only=True))
    raw.pop("running", None)
    (tmp_path / FileNodeShare._filename("clip", "cold", "n", "c")).write_text(json.dumps(raw))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8


# --- starve scenarios: prompt-first in the untargeted demand split, never below the old share ---
# Every real pool is planned by plain plan_sizes at its true footprint. The prompt pools' priority
# lives only in how the untargeted count is divided before planning: a prompt pool's untargeted
# demand is the LARGER of its capacity fill and its OLD even share (what the legacy / a929bc9 split
# gives it), and the overflow pools get the residue the prompt pools can't take. So a warm pool is
# never planned below what it had before; the engine may weigh a little more than its queue.

def _starve_view(tmp_path, *, w_cap, w_assigned=0, w_running=None, red_backlog=None):
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("firecracker", "w", 20, 20, overflow_only=False, max_ceiling=w_cap,
                         assigned=w_assigned, running=w_running))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    if red_backlog is not None:
        share.publish(_cpeer("firecracker", "y", red_backlog, red_backlog, overflow_only=False,
                             engine="red"))
    return share


def _plan_from(share, engine, tier, instance, backlog, untargeted, budget=10):
    ds = DispatcherSizer(EngineNode(engine, "-", slot_ram_mib=1024, max_ceiling=64),
                         None if tier == "cold" else _Pool(), share, _OVF_CFG, runtime=tier,
                         backlog_fn=lambda: backlog, untargeted_backlog_fn=lambda: untargeted,
                         node="n", instance=instance, capacity_fn=_budget(budget * 1024, 999),
                         clock=lambda: 1.0, overflow_only=(tier == "cold"))
    ds.tick()
    return {k: p.concurrent_ceiling for k, p in _PLAN.items()}


def _starve_pools(w_cap, red=None, w_res=0):
    pools = {"W": ("clip", "firecracker", "w", 1024, 20, 20, w_cap, w_res, w_res, False),
             "C": ("clip", "cold", "c", 1024, 20, 20, 64, 0, 0, True)}
    if red is not None:
        pools["Y"] = ("red", "firecracker", "y", 1024, red, red, 64, 0, 0, False)
    return pools


def test_starve_scenarios(tmp_path, monkeypatch):
    # starve.py. W4: W (cap 4, idle) gets its capacity and cold the rest: W4 C6 (was W2 C8). In every
    # case W is planned no lower than the legacy (a929bc9) path plans it on the same view; the other
    # engine pays at most the pinned delta.
    specs = _capture_specs(monkeypatch)
    cases = [("W4", _starve_pools(4), 10, 16,
              {"clip@firecracker@w": 4, "clip@cold@c": 6}),
             ("W4Y", _starve_pools(4, red=40), 10, 16, None),
             ("W0", _starve_pools(2, red=20), 10, 18, None)]
    for name, pools, w_q, c_q, want in cases:
        cur = _het_plan(tmp_path / name, pools, 10 * 1024)
        assert specs["clip@firecracker@w"].queued == w_q, name   # max(capacity, old share 20/2)
        assert specs["clip@cold@c"].queued == c_q, name          # 20 − min(10, capacity)
        leg = _legacy_plan(tmp_path / (name + "-legacy"), pools, 10 * 1024)
        assert cur["clip@firecracker@w"] >= leg["clip@firecracker@w"], (name, cur, leg)
        assert sum(cur.values()) <= 10
        if want is not None:
            assert cur == want, (name, cur)
    # W4Y / W0: exactly the legacy plan; red pays nothing (7 and 5, as before)
    assert _het_plan(tmp_path / "W4Y2", _starve_pools(4, red=40), 10 * 1024) == {
        "clip@firecracker@w": 1, "clip@cold@c": 2, "red@firecracker@y": 7}
    assert _het_plan(tmp_path / "W02", _starve_pools(2, red=20), 10 * 1024) == {
        "clip@firecracker@w": 2, "clip@cold@c": 3, "red@firecracker@y": 5}


def test_full_prompt_pool_still_spills_to_cold_against_another_engine(tmp_path, monkeypatch):
    # W capped at 2 with 2 running jobs: the spill competes with red, cold is not pinned at 1
    _capture_specs(monkeypatch)
    plan = _plan_from(_starve_view(tmp_path, w_cap=2, w_assigned=2, red_backlog=20), "red",
                      "firecracker", "y", 20, 20)
    assert plan["clip@firecracker@w"] == 2
    assert plan["clip@cold@c"] >= 3
    assert sum(plan.values()) <= 10


def test_every_planner_computes_the_same_node_plan(tmp_path, monkeypatch):
    # cross-planner determinism: W, C and Y each plan the node from their own perspective and must
    # all get the identical plan (they each apply only their own slice of it).
    _capture_specs(monkeypatch)
    for i, (w_cap, w_assigned, red) in enumerate(
            [(4, 0, None), (4, 0, 40), (2, 0, 20), (2, 2, 20), (6, 6, 5), (64, 0, 20)]):
        share = _starve_view(tmp_path / str(i), w_cap=w_cap, w_assigned=w_assigned,
                             red_backlog=red)
        plans = [_plan_from(share, "clip", "cold", "c", 20, 20)]
        w = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=w_cap),
                            _Pool(assigned=w_assigned, slot_count=w_assigned), share, _OVF_CFG,
                            runtime="firecracker", backlog_fn=lambda: 20,
                            untargeted_backlog_fn=lambda: 20, node="n", instance="w",
                            capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0)
        w.tick()
        plans.append({k: p.concurrent_ceiling for k, p in _PLAN.items()})
        if red is not None:
            plans.append(_plan_from(share, "red", "firecracker", "y", red, red))
        assert all(p == plans[0] for p in plans), (i, plans)
        assert sum(plans[0].values()) <= 10


def test_idle_warm_slots_count_as_capacity_not_as_running(tmp_path, monkeypatch):
    # codex: prompt fc capped at 6 with 6 IDLE ready slots (reservation 6, running 0) beside an
    # overflow cold with 20 queued. The fc can absorb 6 — it must keep its 6 warm slots, not spill
    # everything to cold and reap them.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    pool = _Pool(assigned=0, slot_count=6)                     # 6 resident, none busy
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=6), pool, share,
                         _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 20,
                         untargeted_backlog_fn=lambda: 20, node="n", instance="w",
                         capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0)
    mine = ds.tick()
    assert specs["clip@firecracker@w"].queued == 10        # max(6 idle-slot capacity, 20/2)
    assert specs["clip@cold@c"].queued == 14               # 20 − min(10, 6)
    assert mine.warm_size == 6 and pool.warm_size == 6


def test_prompt_pool_running_at_cap_spills_everything(tmp_path, monkeypatch):
    # the same fc with its 6 slots all RUNNING jobs can take no more: all 20 spill to cold
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("cold", "c", 20, 20, overflow_only=True))
    pool = _Pool(assigned=6, slot_count=6)
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=6), pool, share,
                    _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 20,
                    untargeted_backlog_fn=lambda: 20, node="n", instance="w",
                    capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0).tick()
    # all 6 busy → capacity 0: W keeps its legacy share as demand (capped by max_ceiling 6), and
    # the whole count spills to cold: 20 − min(10, 0)
    assert specs["clip@firecracker@w"].queued == 10
    assert specs["clip@cold@c"].queued == 20


def test_sizer_publishes_running_separately_from_the_reservation(tmp_path):
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    share = FileNodeShare(str(tmp_path))
    gate = DynamicConcurrencyGate(4)
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                    _Pool(assigned=2, slot_count=5), share, _OVF_CFG, runtime="firecracker",
                    backlog_fn=lambda: 0, node="n", instance="f",
                    capacity_fn=_budget(10 * 1024, 999), clock=lambda: 1.0,
                    concurrency_gate=gate).tick()
    (snap,) = share.read_all(max_age_s=60, now=1.0)
    assert snap.assigned == 5 and snap.running == 2          # 5 resident, 2 busy


def test_one_stale_high_count_does_not_inflate_the_engine(tmp_path, monkeypatch):
    # counts are averaged over the engine's live pools, as before: a stale 40 beside a fresh 0 is
    # an engine demand of 20, not 40.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_cpeer("gvisor", "g", 40, 40, overflow_only=False))
    mine = _fc_sizer(share, backlog=0, untargeted=0).tick()
    # no overflow pool → the legacy split, each pool's OWN count over the pools: 0 and 40/2
    assert abs(sum(s.queued for s in specs.values()) - 20) < 1e-9
    assert mine.warm_size == 0
    share2 = FileNodeShare(str(tmp_path / "ovf"))
    share2.publish(_cpeer("cold", "c", 40, 40, overflow_only=True))
    _fc_sizer(share2, backlog=0, untargeted=0, max_ceiling=4).tick()
    assert abs(sum(s.queued for s in specs.values()) - 20) < 1e-9


def test_spill_plans_agree_and_fit_the_budget_randomized(tmp_path, monkeypatch):
    # Randomised views (prompt caps, running, targeted work, an overflow cold with a BIGGER
    # footprint, a competing engine): every pool's planner computes the identical plan, and
    # Σ ceiling·footprint ≤ budget whenever the budget can seat every pool's baseline.
    import random
    rng = random.Random(193)
    _capture_specs(monkeypatch)
    checked = spilled = 0
    for case in range(150):
        d = tmp_path / str(case)
        share = FileNodeShare(str(d))
        budget = rng.choice([6, 10, 16, 32])
        u = rng.choice([0, 3, 20, 60])
        pools = []                                   # (engine, tier, inst, ram, backlog, unt, cap, asg, run, ovf)
        for inst in rng.sample(["a", "b"], rng.choice([1, 2])):
            cap = rng.choice([1, 2, 4, 64])
            asg = rng.randint(0, cap)
            tgt = rng.choice([0, 0, 3])
            pools.append(("clip", "firecracker", inst, rng.choice([512, 1024, 4096]), u + tgt,
                          u, cap, asg, rng.randint(0, asg), False))
        c_asg = rng.choice([0, 1, 3])
        pools.append(("clip", "cold", "c", rng.choice([1024, 2048]), u, u, 64, c_asg, c_asg,
                      True))
        if rng.random() < 0.6:
            r = rng.choice([5, 20, 40])
            pools.append(("red", "gvisor", "y", 1024, r, r, 64, 0, 0, False))
        for eng, tier, inst, ram, b, un, cap, asg, run, ovf in pools:
            share.publish(DemandSnapshot(eng, b, asg, ram, 1, 0, cap, 1.0, ts=1.0, node="n",
                                         tier=tier, instance=inst, untargeted_backlog=un,
                                         balancing=True, overflow_only=ovf, lease=False,
                                         running=run, engines=1, serving=True))
        plans = []
        class _Gate:                                 # cold in flight = its reservation/running
            def __init__(self, n):
                self.in_flight = n

            def set_limit(self, n):
                pass

        for eng, tier, inst, ram, b, un, cap, asg, run, ovf in pools:
            cold = tier == "cold"
            ds = DispatcherSizer(
                EngineNode(eng, "-", slot_ram_mib=ram, max_ceiling=cap),
                None if cold else _Pool(assigned=run, slot_count=asg), share,
                _OVF_CFG, runtime=tier, backlog_fn=lambda b=b: b,
                untargeted_backlog_fn=lambda un=un: un, node="n", instance=inst,
                capacity_fn=_budget(budget * 1024, 999), clock=lambda: 1.0, overflow_only=ovf,
                concurrency_gate=_Gate(asg) if cold else None)
            ds.tick()
            plans.append({k: p.concurrent_ceiling for k, p in _PLAN.items()})
        assert all(p == plans[0] for p in plans), (case, pools, plans)
        rams = {f"{e}@{t}@{i}": r for e, t, i, r, *_ in pools}
        if sum(rams.values()) <= budget * 1024:
            used = sum(plans[0][k] * rams[k] for k in rams)
            # reservations are seated even past the budget (they are already spent); only a plan
            # that had room for every reservation must fit
            if sum(max(1, min(p[7], p[6])) * p[3] for p in pools) <= budget * 1024:
                assert used <= budget * 1024, (case, pools, plans[0])
                checked += 1
        spilled += plans[0]["clip@cold@c"] > 1
    assert checked >= 80 and spilled >= 20, (checked, spilled)     # the net actually bit


# --- mixed footprints inside a spilling engine --------------------------------------------------
# The engine's pools can have different slot sizes (one engine on two tiers). Every member's
# reservation must be seated at its TRUE footprint (as plan_sizes does), and the engine's extra
# capacity charged per member at its true footprint — never priced as the largest member.

class _ServingPool(_Pool):
    """A warm pool whose WarmPool.is_serving() answer is fixed."""

    def __init__(self, *a, serving=True, **kw):
        super().__init__(*a, **kw)
        self.serving = serving

    def is_serving(self):
        return self.serving


class _FixedGate:
    """A cold dispatcher's concurrency gate with a fixed number of workers in flight."""

    def __init__(self, n):
        self.in_flight = n

    def set_limit(self, n):
        pass


def _het_sizer(share, pool, budget_mib, budget_vcpus):
    """The DispatcherSizer for one pool tuple (engine, tier, inst, ram, backlog, untargeted, cap,
    reserved, running, ovf[, vcpus]). A cold pool is pool-less with `reserved` workers in flight."""
    eng, tier, inst, ram, b, u, cap, res, run, ovf, *rest = pool
    cold = tier == "cold"
    return DispatcherSizer(
        EngineNode(eng, "-", slot_ram_mib=ram, slot_vcpus=rest[0] if rest else 1,
                   max_ceiling=cap),
        None if cold else _ServingPool(assigned=run, slot_count=res,
                                       serving=rest[2] if len(rest) > 2 else True),
        share, _OVF_CFG, runtime=tier,
        backlog_fn=lambda: b, untargeted_backlog_fn=lambda: u, node="n", instance=inst,
        capacity_fn=_budget(budget_mib, budget_vcpus), clock=lambda: 1.0, overflow_only=ovf,
        concurrency_gate=_FixedGate(res) if cold else None,
        served_engines=rest[1] if len(rest) > 1 else 1,
        warm_only=True)                     # warm-only: a broken warm path can't fall back to cold


def _het_snapshot(pool):
    eng, tier, inst, ram, b, u, cap, res, run, ovf, *rest = pool
    return DemandSnapshot(eng, b, res, ram, rest[0] if rest else 1, 0, cap, 1.0, ts=1.0,
                          node="n", tier=tier, instance=inst, untargeted_backlog=u,
                          balancing=True, overflow_only=ovf, lease=False,
                          running=res if tier == "cold" else run,
                          engines=rest[1] if len(rest) > 1 else 1,
                          serving=rest[2] if len(rest) > 2 else True)


def _het_plan(tmp_path, pools, budget_mib, budget_vcpus=999):
    """pools: name → (engine, tier, inst, ram, backlog, untargeted, cap, reserved, running, ovf
    [, vcpus]). Every pool ticks its own planner on the shared view; returns the (identical) plan."""
    share = FileNodeShare(str(tmp_path))
    for pool in pools.values():
        share.publish(_het_snapshot(pool))
    plans = []
    for pool in pools.values():
        _PLAN.clear()
        assert _het_sizer(share, pool, budget_mib, budget_vcpus).tick() is not None
        plans.append({k: p.concurrent_ceiling for k, p in _PLAN.items()})
    assert all(p == plans[0] for p in plans), plans
    return plans[0]


def test_small_member_reservation_is_seated_at_its_true_footprint(tmp_path, monkeypatch):
    # het.py: 12 GiB. engine a: prompt W (1 GiB, cap 8, 6 RESIDENT and running, 6 untargeted),
    # overflow C (4 GiB, cap 4, 1 resident); engine b: Y (1 GiB, 4 queued). W's six resident VMs
    # must keep their slots: W6 C1 Y2 = 12 GiB. Pricing W's reservation at C's 4 GiB unseated it
    # (W2 C1 Y3 → 13 GiB physically in use on a 12 GiB node).
    _capture_specs(monkeypatch)
    plan = _het_plan(tmp_path, {
        "W": ("a", "firecracker", "w", 1024, 6, 6, 8, 6, 6, False),
        "C": ("a", "gvisor", "c", 4096, 6, 6, 4, 1, 1, True),
        "Y": ("b", "firecracker", "y", 1024, 4, 4, 64, 0, 0, False)}, 12 * 1024)
    assert plan == {"a@firecracker@w": 6, "a@gvisor@c": 1, "b@firecracker@y": 2}


def test_mixed_footprints_do_not_strand_budget(tmp_path, monkeypatch):
    # vcap.py: 32 GiB. W (1 GiB, cap 8, 8 untargeted) + overflow C (4 GiB, cap 1); Y (1 GiB, cap 8,
    # 8 queued). Everything fits: W8 C1 Y8 — W must not stop at 5 with 15 GiB idle.
    _capture_specs(monkeypatch)
    plan = _het_plan(tmp_path, {
        "W": ("a", "firecracker", "w", 1024, 8, 8, 8, 0, 0, False),
        "C": ("a", "gvisor", "c", 4096, 8, 8, 1, 0, 0, True),
        "Y": ("b", "firecracker", "y", 1024, 8, 8, 8, 0, 0, False)}, 32 * 1024)
    assert plan == {"a@firecracker@w": 8, "a@gvisor@c": 1, "b@firecracker@y": 8}




# --- codex regressions on the (removed) virtual spill pool ---------------------------------------

def test_targeted_only_load_is_plain_plan_sizes(tmp_path, monkeypatch):
    # prompt warm + overflow cold each with 20 jobs TARGETED at their own tier, 0 untargeted, equal
    # 1 GiB, 10 GiB: nothing spills, so the plan is exactly the plain one (5/5), identical to what
    # the same view plans on the legacy (pre-field) path.
    _capture_specs(monkeypatch)
    pools = {"W": ("clip", "firecracker", "w", 1024, 20, 0, 64, 0, 0, False),
             "C": ("clip", "gvisor", "c", 1024, 20, 0, 64, 0, 0, True)}
    plan = _het_plan(tmp_path / "cur", pools, 10 * 1024)
    assert plan == {"clip@firecracker@w": 5, "clip@gvisor@c": 5}
    assert plan == _legacy_plan(tmp_path / "old", pools, 10 * 1024)


def test_member_floors_are_not_double_counted(tmp_path, monkeypatch):
    # two clip pools (prompt + overflow) with min_warm 1 each and queued work, red min_warm 2, all
    # 1 GiB, 4 GiB: every floor is feasible (1 + 1 + 2) and is seated; unseatable_floors agrees.
    from blastbox.host.node_sizer import NodeBudget, unseatable_floors
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    for eng, tier, inst, mw, ovf in (("clip", "firecracker", "w", 1, False),
                                     ("clip", "gvisor", "c", 1, True),
                                     ("red", "firecracker", "y", 2, False)):
        share.publish(DemandSnapshot(eng, 5, 0, 1024, 1, mw, 64, 1.0, ts=1.0, node="n",
                                     tier=tier, instance=inst, untargeted_backlog=5,
                                     balancing=True, overflow_only=ovf, lease=False, running=0, engines=1, serving=True))
    DispatcherSizer(EngineNode("red", "-", slot_ram_mib=1024, max_ceiling=64, min_warm=2),
                    _Pool(), share, _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 5,
                    untargeted_backlog_fn=lambda: 5, node="n", instance="y",
                    capacity_fn=_budget(4 * 1024, 999), clock=lambda: 1.0).tick()
    assert {k: p.concurrent_ceiling for k, p in _PLAN.items()} == {
        "clip@firecracker@w": 1, "clip@gvisor@c": 1, "red@firecracker@y": 2}
    assert unseatable_floors(list(specs.values()), NodeBudget(4 * 1024, 999)) == {}


def test_smaller_prompt_footprint_is_not_stranded(tmp_path, monkeypatch):
    # prompt 2 GiB/slot, overflow 4 GiB/slot, 8 GiB node: a second prompt slot fits and is used
    # (no 2 GiB left idle).
    _capture_specs(monkeypatch)
    plan = _het_plan(tmp_path, {
        "W": ("clip", "firecracker", "w", 2048, 10, 10, 4, 0, 0, False),
        "C": ("clip", "gvisor", "c", 4096, 10, 10, 4, 0, 0, True)}, 8 * 1024)
    assert plan == {"clip@firecracker@w": 2, "clip@gvisor@c": 1}


def _legacy_plan(tmp_path, pools, budget_mib, budget_vcpus=999):
    """What the pre-field (a929bc9-equivalent) path plans for the same pools: every OTHER pool's
    snapshot lacks the new fields, so the node is legacy for the planner."""
    import json
    from dataclasses import asdict
    tmp_path.mkdir(parents=True, exist_ok=True)
    share = FileNodeShare(str(tmp_path))
    for pool in pools.values():
        raw = asdict(_het_snapshot(pool))
        for k in ("overflow_only", "lease", "running", "engines", "serving"):
            raw.pop(k, None)
        (tmp_path / FileNodeShare._filename(pool[0], pool[1], "n", pool[2])).write_text(
            json.dumps(raw))
    _PLAN.clear()
    assert _het_sizer(share, next(iter(pools.values())), budget_mib,
                      budget_vcpus).tick() is not None
    return {k: p.concurrent_ceiling for k, p in _PLAN.items()}


def test_heterogeneous_footprint_property_fuzz(tmp_path, monkeypatch):
    # Random heterogeneous nodes (1–3 engines, prompt/overflow pools on fc/gvisor/cold, 512 MiB–4 GiB
    # and 0.5–4 vCPU slots, caps, resident reservations, running jobs, targeted work):
    # (a) whenever the legacy (a929bc9-equivalent) plan seats every reservation, the current does;
    # (b) Σ ceiling·footprint ≤ budget per dimension whenever the reservations fit;
    # (c) every pool's planner computes the identical plan.
    import random
    rng = random.Random(0x193)
    _capture_specs(monkeypatch)
    seated = fitted = 0
    for case in range(300):
        pools = {}
        for e in range(rng.randint(1, 3)):
            n_p, n_o = rng.randint(1, 2), rng.choice([0, 1, 1, 2])
            u = rng.choice([0, 4, 20])
            for i in range(n_p + n_o):
                ovf = i >= n_p
                cap = rng.choice([1, 2, 4, 8, 64])
                res = rng.randint(0, min(cap, 5))
                tier = ("firecracker", "gvisor", "cold")[i % 3]
                pools[f"{e}{i}"] = (f"e{e}", tier, f"i{i}", rng.choice([512, 1024, 2048, 4096]),
                                    u + rng.choice([0, 0, 3]), u, cap, res,
                                    res if tier == "cold" else rng.randint(0, res), ovf,
                                    rng.choice([0.5, 1, 2, 4]))
        budget = rng.choice([4, 8, 12, 24, 64]) * 1024
        vcpus = rng.choice([4, 8, 16, 999])
        cur = _het_plan(tmp_path / f"c{case}", pools, budget, vcpus)     # asserts (c)
        leg = _legacy_plan(tmp_path / f"l{case}", pools, budget, vcpus)
        name = {k: f"{p[0]}@{p[1]}@{p[2]}" for k, p in pools.items()}
        if all(leg[name[k]] >= min(p[7], p[6]) for k, p in pools.items()):
            seated += 1
            for k, p in pools.items():
                assert cur[name[k]] >= min(p[7], p[6]), (case, pools, cur, leg)
        floors = {k: max(1, min(p[7], p[6])) for k, p in pools.items()}
        if (sum(floors[k] * p[3] for k, p in pools.items()) <= budget
                and sum(floors[k] * p[10] for k, p in pools.items()) <= vcpus):
            fitted += 1
            assert sum(cur[name[k]] * p[3] for k, p in pools.items()) <= budget, (case, pools, cur)
            assert sum(cur[name[k]] * p[10] for k, p in pools.items()) <= vcpus, (case, pools, cur)
    assert seated >= 80 and fitted >= 70, (seated, fitted)       # the net actually bit


def _own_sizes(tmp_path, pools, budget_mib, budget_vcpus, legacy):
    """Each pool's OWN PoolSize from its own tick, on the current view or on a legacy one (every
    other pool's snapshot stripped of the new fields — the a929bc9-equivalent path)."""
    import json
    from dataclasses import asdict
    out = {}
    for key, pool in pools.items():
        d = tmp_path / key
        d.mkdir(parents=True, exist_ok=True)
        share = FileNodeShare(str(d))
        for other in pools.values():
            raw = asdict(_het_snapshot(other))
            if legacy:
                for k in ("overflow_only", "lease", "running", "engines", "serving"):
                    raw.pop(k, None)
            (d / FileNodeShare._filename(other[0], other[1], "n", other[2])).write_text(
                json.dumps(raw))
        out[f"{pool[0]}@{pool[1]}@{pool[2]}"] = _het_sizer(share, pool, budget_mib,
                                                            budget_vcpus).tick()
    return out


def test_prompt_pool_never_below_legacy_fuzz(tmp_path, monkeypatch):
    # On random heterogeneous views, every PROMPT pool's own planned ceiling AND warm target are
    # never below what the legacy (a929bc9-equivalent) path gives it on the same view.
    import random
    rng = random.Random(0xA929)
    _capture_specs(monkeypatch)
    compared = exact = 0
    for case in range(250):
        pools = {}
        for e in range(rng.randint(1, 3)):
            n_p, n_o = rng.randint(1, 2), rng.choice([0, 1, 1, 2])
            u = rng.choice([0, 4, 20, 50])
            for i in range(n_p + n_o):
                cap = rng.choice([1, 2, 4, 8, 64])
                res = rng.randint(0, min(cap, 5))
                tier = ("firecracker", "gvisor", "cold")[i % 3]
                pools[f"{e}{i}"] = (f"e{e}", tier, f"i{i}", rng.choice([512, 1024, 2048, 4096]),
                                    u + rng.choice([0, 0, 3]), u, cap, res,
                                    res if tier == "cold" else rng.randint(0, res), i >= n_p,
                                    rng.choice([0.5, 1, 2, 4]), 1,
                                    rng.random() > 0.15)     # ~15% not serving
        budget, vcpus = rng.choice([4, 8, 12, 24, 64]) * 1024, rng.choice([4, 8, 16, 999])
        cur = _own_sizes(tmp_path / f"c{case}", pools, budget, vcpus, legacy=False)
        leg = _own_sizes(tmp_path / f"l{case}", pools, budget, vcpus, legacy=True)
        spilling = {p[0] for p in pools.values() if p[9]}
        names = {k: f"{p[0]}@{p[1]}@{p[2]}" for k, p in pools.items()}
        if not spilling:
            # no overflow pool anywhere: EXACTLY the legacy (a929bc9-equivalent) plan and warm
            assert {n: (cur[n].concurrent_ceiling, cur[n].warm_size) for n in cur} == {
                n: (leg[n].concurrent_ceiling, leg[n].warm_size) for n in leg}, (case, pools)
            exact += 1
        if not all(leg[names[k]].concurrent_ceiling >= min(p[7], p[6]) for k, p in pools.items()):
            continue      # over-committed node: reservations are seated by demand priority, which
                          # legitimately moves with the split — no per-pool guarantee there
        for k, p in pools.items():
            if p[9] or p[0] not in spilling or not p[12]:   # a broken prompt pool: no guarantee
                continue          # the guarantee is for the PROMPT pools of an engine with overflow
            name = f"{p[0]}@{p[1]}@{p[2]}"
            compared += 1
            assert cur[name].concurrent_ceiling >= leg[name].concurrent_ceiling, (
                case, name, pools, cur, leg)
            assert cur[name].warm_size >= leg[name].warm_size, (case, name, pools, cur, leg)
    assert compared >= 80 and exact >= 10, (compared, exact)


def test_multi_engine_pool_without_overflow_plans_as_legacy(tmp_path, monkeypatch):
    # codex: a warm pool serving aa+bb reports 8 untargeted (bb) jobs under aa; a second warm pool
    # serves only aa and reports 0; 4 slots. No overflow pool → exactly the legacy plan and warm
    # targets (the shared pool warms for its own count; the aa-only pool is not sized for bb jobs).
    _capture_specs(monkeypatch)
    pools = {"A": ("aa", "firecracker", "a", 1024, 8, 8, 64, 0, 0, False, 1, 2),
             "B": ("aa", "gvisor", "b", 1024, 0, 0, 64, 0, 0, False, 1, 1)}
    cur = _own_sizes(tmp_path / "cur", pools, 4 * 1024, 999, legacy=False)
    leg = _own_sizes(tmp_path / "leg", pools, 4 * 1024, 999, legacy=True)
    assert cur == leg
    assert cur["aa@gvisor@b"].warm_size == 0


def test_engine_with_a_multi_engine_pool_never_spills(tmp_path, monkeypatch):
    # a spilling layout (prompt + overflow cold), but the prompt pool serves two engines: its count
    # is combined, so the engine keeps the legacy split rather than redistributing it
    specs = _capture_specs(monkeypatch)
    pools = {"A": ("aa", "firecracker", "a", 1024, 16, 16, 64, 0, 0, False, 1, 2),
             "C": ("aa", "cold", "c", 1024, 16, 16, 64, 0, 0, True, 1, 1)}
    cur = _own_sizes(tmp_path / "cur", pools, 8 * 1024, 999, legacy=False)
    leg = _own_sizes(tmp_path / "leg", pools, 8 * 1024, 999, legacy=True)
    assert cur == leg
    assert specs["aa@cold@c"].queued == 8                    # the even split, not the residue


def test_gate_requires_engines_field_too(tmp_path, monkeypatch):
    # a pool of ANOTHER engine without `engines` switches the node gate off: clip keeps the legacy
    # split although its own pools carry every field
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    raw = asdict(_peer("firecracker", "y", 4, 4, overflow_only=False, engine="red"))
    raw.pop("engines", None)
    (tmp_path / FileNodeShare._filename("red", "firecracker", "n", "y")).write_text(
        json.dumps(raw))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8


def test_legacy_floor_not_applied_on_an_over_committed_node(tmp_path, monkeypatch):
    # reservations that don't all fit (4 slots, 6 resident): the legacy plan grows no pool past
    # its reservation there, so the floors raise nothing — reservations keep plain plan_sizes'
    # demand-priority seating and an overflow pool's resident workers aren't displaced by a floor
    specs = _capture_specs(monkeypatch)
    pools = {"W": ("clip", "firecracker", "w", 1024, 20, 20, 64, 1, 1, False),
             "C": ("clip", "cold", "c", 1024, 20, 20, 64, 3, 3, True),
             "Y": ("red", "firecracker", "y", 1024, 20, 20, 64, 2, 2, False)}
    _het_plan(tmp_path, pools, 4 * 1024)
    assert {k: sp.reserved for k, sp in specs.items()} == {
        "clip@firecracker@w": 1, "clip@cold@c": 3, "red@firecracker@y": 2}


def test_legacy_floor_is_a_reservation_floor(tmp_path, monkeypatch):
    # on a node that fits, a non-overflow pool's reservation is raised to its legacy ceiling
    # (starve W4: W's legacy ceiling is 4); the overflow pool's is left alone
    specs = _capture_specs(monkeypatch)
    _het_plan(tmp_path, _starve_pools(4), 10 * 1024)
    assert specs["clip@firecracker@w"].reserved == 4
    assert specs["clip@cold@c"].reserved == 0


def test_sizer_publishes_served_engine_count(tmp_path, monkeypatch):
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "aa,bb")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    for served in (["aa", "bb"], ["aa"]):
        stop, thread, sizer = _start_node_sizer(_Pool(), served, InMemoryJobStore(),
                                                "firecracker")
        try:
            (snap,) = FileNodeShare(str(tmp_path)).read_all(max_age_s=60, now=time.time())
            assert snap.engines == len(served)
        finally:
            stop.set()
            thread.join(2.0)
            sizer.remove_own_snapshot()


# --- a prompt pool that can't serve gives its untargeted capacity to the overflow pools -----------

def _broken_warm(serving, *, cap=8):
    return {"W": ("clip", "firecracker", "w", 1024, 20, 20, cap, 0, 0, False, 1, 1, serving),
            "C": ("clip", "cold", "c", 1024, 20, 20, 64, 0, 0, True, 1, 1, True)}


def test_unserving_warm_pool_hands_the_spill_to_cold(tmp_path, monkeypatch):
    # codex: 8 slots; the warm fc pool's spawns keep failing (nothing ready) — it can't claim. Its
    # delayed cold peer gets the untargeted work: at least its legacy share (4) and the spill,
    # not 1 (HEAD: warm 7, cold 1). The broken pool keeps a warm target so it keeps retrying.
    specs = _capture_specs(monkeypatch)
    plan = _het_plan(tmp_path / "broken", _broken_warm(False), 8 * 1024)
    assert specs["clip@cold@c"].queued == 20                  # the whole count spills
    assert specs["clip@firecracker@w"].reserved == 0          # no legacy floor for a broken pool
    legacy = _legacy_plan(tmp_path / "legacy", _broken_warm(False), 8 * 1024)
    assert legacy == {"clip@firecracker@w": 4, "clip@cold@c": 4}
    assert plan["clip@cold@c"] >= 4
    assert plan == {"clip@firecracker@w": 1, "clip@cold@c": 7}
    w = _own_sizes(tmp_path / "own", _broken_warm(False), 8 * 1024, 999, legacy=False)
    assert w["clip@firecracker@w"].warm_size == 1              # still retries a slot


def test_healthy_warming_pool_still_counts(tmp_path, monkeypatch):
    # the same pool while serving (warming healthily / ready): it takes what it can, as before
    specs = _capture_specs(monkeypatch)
    plan = _het_plan(tmp_path, _broken_warm(True, cap=4), 8 * 1024)
    assert specs["clip@cold@c"].queued == 16                   # 20 − min(10, 4)
    assert plan["clip@firecracker@w"] == 4


def test_flapping_serving_flag_plans_deterministically(tmp_path, monkeypatch):
    # serving toggles tick to tick: every planner reads the same published flag, so each tick all
    # pools compute the same plan, and the plan follows the flag
    _capture_specs(monkeypatch)
    plans = [_het_plan(tmp_path / f"t{i}", _broken_warm(i % 2 == 0), 8 * 1024) for i in range(4)]
    assert plans[0] == plans[2] and plans[1] == plans[3] and plans[0] != plans[1]


def test_gate_requires_serving_field_too(tmp_path, monkeypatch):
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_peer("cold", "c", 16, 16, overflow_only=True))
    raw = asdict(_peer("firecracker", "y", 4, 4, overflow_only=False, engine="red"))
    raw.pop("serving", None)
    (tmp_path / FileNodeShare._filename("red", "firecracker", "n", "y")).write_text(
        json.dumps(raw))
    _fc_sizer(share, backlog=16, untargeted=16).tick()
    assert specs["clip@cold@c"].queued == 8 and specs["clip@firecracker@f"].queued == 8


def test_sizer_publishes_pool_serving_state(tmp_path):
    # not serving only when the dispatcher is WARM-ONLY and its pool can't serve: a dispatcher that
    # falls back to cold on a warm miss (the node-managed default) still runs untargeted work
    for warm_only, pool_serving, want in ((True, True, True), (True, False, False),
                                          (False, False, True), (False, True, True)):
        share = FileNodeShare(str(tmp_path / f"{warm_only}-{pool_serving}"))
        DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64),
                        _ServingPool(serving=pool_serving), share, _OVF_CFG,
                        runtime="firecracker", backlog_fn=lambda: 0, node="n", instance="f",
                        capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0,
                        warm_only=warm_only).tick()
        (snap,) = share.read_all(max_age_s=60, now=1.0)
        assert snap.serving is want, (warm_only, pool_serving)


def test_broken_warm_base_with_cold_fallback_keeps_its_share(tmp_path, monkeypatch):
    # probe sc.py: warm_only=False — the broken warm path falls back to cold, so the dispatcher is
    # serving and keeps its capacity + floors (no spill away from it)
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, 20, 20, 64, 0, 0, True)))
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=4),
                    _ServingPool(serving=False), share, _OVF_CFG, runtime="firecracker",
                    backlog_fn=lambda: 20, untargeted_backlog_fn=lambda: 20, node="n",
                    instance="w", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0,
                    warm_only=False).tick()
    assert specs["clip@cold@c"].queued == 16                   # 20 − min(10, 4): normal spill


def test_start_node_sizer_threads_warm_only(tmp_path, monkeypatch):
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    for warm_only, want in ((True, False), (False, True)):
        stop, thread, sizer = _start_node_sizer(_ServingPool(serving=False), ["clip"],
                                                InMemoryJobStore(), "firecracker",
                                                warm_only=warm_only)
        try:
            (snap,) = FileNodeShare(str(tmp_path)).read_all(max_age_s=60, now=time.time())
            assert snap.serving is want
        finally:
            stop.set()
            thread.join(2.0)
            sizer.remove_own_snapshot()


def test_worker_fault_burst_does_not_churn_the_plan(tmp_path, monkeypatch):
    # probe_flap end to end: a REAL WarmPool whose 4 slots were all recycled by worker faults (all
    # WARMING, respawning) stays serving, so its plan is the serving plan — no floor drop, no reap
    from blastbox.host.pool import WarmPool
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
    from test_pool import _FakeRuntime
    rt = _FakeRuntime()
    pool = WarmPool(runtime=rt, warm_size=4, spawn_rate_limit=100.0)
    pool.resize(warm_size=4, concurrent_ceiling=7)
    for _ in range(4):
        pool.tick()
    rt.set_default_ready_after(2)
    for sl in [pool.claim(timeout_s=0.1) for _ in range(4)]:
        pool.release(sl, dirty=True, fault="worker")
    pool.tick()
    assert pool.idle_count == 0 and pool.is_serving() is True
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, 20, 20, 64, 0, 0, True)))
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=7), pool, share,
                    _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 20,
                    untargeted_backlog_fn=lambda: 20, node="n", instance="w",
                    capacity_fn=_budget(12 * 1024, 999), clock=lambda: 1.0,
                    warm_only=True).tick()
    (snap,) = [x for x in share.read_all(max_age_s=60, now=1.0) if x.instance == "w"]
    assert snap.serving is True
    assert specs["clip@firecracker@w"].queued == 10            # max(capacity 7, legacy 10)


def test_lease_takes_no_untargeted_share_on_a_current_node(tmp_path, monkeypatch):
    # codex: the delayed cold peer stopped with 1 job in flight, leaving an overflow-only LEASE; the
    # engine then has no live overflow pool (no spill) and falls to the even split — whose
    # denominator counted the lease, so the live warm pool warmed for only half of the 16 queued.
    # On a current (gate-on) node a lease takes no share and isn't in the denominator.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path / "cur"))
    _lease(share, tier="cold", instance="c", warm_orphans=1, overflow_only=True)
    mine = _fc_sizer(share, backlog=16, untargeted=16, max_ceiling=16,
                     ram_budget=17 * 1024).tick()
    assert specs["clip@firecracker@f"].queued == 16
    assert mine.warm_size == 16 and mine.concurrent_ceiling == 16


def test_lease_denominator_unchanged_on_the_legacy_path(tmp_path, monkeypatch):
    # the same view with a pre-field peer on the node (gate off): exactly the a929bc9 split, lease
    # counted, 8 each — every planner on a mixed node must agree
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    d = tmp_path / "old"
    share = FileNodeShare(str(d))
    _lease(share, tier="cold", instance="c", warm_orphans=1, overflow_only=True)
    raw = asdict(_peer("firecracker", "y", 0, 0, engine="red"))
    for k in ("overflow_only", "lease", "running", "engines", "serving"):
        raw.pop(k, None)
    (d / FileNodeShare._filename("red", "firecracker", "n", "y")).write_text(json.dumps(raw))
    mine = _fc_sizer(share, backlog=16, untargeted=16, max_ceiling=16,
                     ram_budget=17 * 1024).tick()
    assert specs["clip@firecracker@f"].queued == 8
    assert mine.warm_size == 8


def test_lease_does_not_dilute_targeted_work_in_prompt_capacity(tmp_path, monkeypatch):
    # codex: an orphan lease of the SAME engine+tier sits beside the live prompt fc. The 8 jobs
    # targeted at fc can only go to the live pool, so its untargeted capacity is its cap (10, as
    # planned) − 8, and cold gets the other 6 of the 8 untargeted — not 2.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, 8, 8, 64, 0, 0, True)))
    _lease(share, instance="old", warm_orphans=1)
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=20), _Pool(), share,
                    _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 16,
                    untargeted_backlog_fn=lambda: 8, node="n", instance="w",
                    capacity_fn=_budget(12 * 1024, 999), clock=lambda: 1.0).tick()
    assert specs["clip@firecracker@w"].max_ceiling == 10
    assert specs["clip@cold@c"].queued == 6


def test_lease_does_not_dilute_targeted_work_in_the_warm_target(tmp_path, monkeypatch):
    # probe_int: a same-tier orphan lease beside the live prompt fc; 8 jobs targeted at fc, 4
    # untargeted. All 8 targeted jobs are the live pool's (a lease claims nothing), plus the 2
    # untargeted its capacity (10 − 8) takes: warm 8 at ceiling 8, not 6 (the targeted term split
    # 4/4 with the lease). Fails if either the capacity or the warm-target half counts the lease.
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, 4, 4, 64, 0, 0, True)))
    _lease(share, instance="old", warm_orphans=1)
    mine = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=20), _Pool(),
                           share, _OVF_CFG, runtime="firecracker", backlog_fn=lambda: 12,
                           untargeted_backlog_fn=lambda: 4, node="n", instance="w",
                           capacity_fn=_budget(12 * 1024, 999), clock=lambda: 1.0).tick()
    assert specs["clip@cold@c"].queued == 2                    # 4 − the 2 that fit
    assert (mine.warm_size, mine.concurrent_ceiling) == (8, 8)


# --- recovery probe: a not-serving prompt pool keeps one warm slot targeted ----------------------
# A warm-only prompt pool that isn't serving gets no untargeted capacity; without more, a small
# queue (its legacy integer share 0) left it at warm 0 — it never spawned, never proved itself,
# never came back. The shared plan gives it a 1-slot warm reservation (min_warm floor, seated under
# the budget like any floor); a healed base promotes that slot, the pool serves again.

def test_not_serving_prompt_pool_gets_a_one_slot_recovery_probe(tmp_path, monkeypatch):
    specs = _capture_specs(monkeypatch)
    pools = {"W": ("clip", "firecracker", "w", 1024, 1, 1, 8, 0, 0, False, 1, 1, False),
             "C": ("clip", "cold", "c", 1024, 1, 1, 64, 0, 0, True, 1, 1, True)}
    plan = _het_plan(tmp_path / "p", pools, 8 * 1024)            # every planner agrees
    assert specs["clip@firecracker@w"].min_warm == 1
    assert specs["clip@firecracker@w"].queued == 0                # still no untargeted capacity
    own = _own_sizes(tmp_path / "own", pools, 8 * 1024, 999, legacy=False)
    assert own["clip@firecracker@w"].warm_size == 1
    assert plan["clip@firecracker@w"] >= 1


def test_serving_prompt_pool_gets_no_probe_floor(tmp_path, monkeypatch):
    specs = _capture_specs(monkeypatch)
    pools = {"W": ("clip", "firecracker", "w", 1024, 1, 1, 8, 0, 0, False, 1, 1, True),
             "C": ("clip", "cold", "c", 1024, 1, 1, 64, 0, 0, True, 1, 1, True)}
    _het_plan(tmp_path, pools, 8 * 1024)
    assert specs["clip@firecracker@w"].min_warm == 0


def test_recovery_probe_respects_a_tiny_budget(tmp_path, monkeypatch):
    # 3 slots of budget, three pools with baselines: the probe floor can't push past it
    _capture_specs(monkeypatch)
    pools = {"W": ("clip", "firecracker", "w", 1024, 1, 1, 8, 0, 0, False, 1, 1, False),
             "C": ("clip", "cold", "c", 1024, 1, 1, 64, 1, 1, True, 1, 1, True),
             "Y": ("red", "firecracker", "y", 1024, 5, 5, 64, 1, 1, False, 1, 1, True)}
    plan = _het_plan(tmp_path, pools, 3 * 1024)
    assert sum(plan.values()) <= 3


def test_mixed_version_node_gets_no_probe_floor(tmp_path, monkeypatch):
    # a pre-field peer on the node: legacy path, a929-exact — no probe floor
    import json
    from dataclasses import asdict
    specs = _capture_specs(monkeypatch)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, 1, 1, 64, 0, 0, True)))
    raw = asdict(_peer("firecracker", "y", 0, 0, engine="red"))
    for k in ("overflow_only", "lease", "running", "engines", "serving"):
        raw.pop(k, None)
    (tmp_path / FileNodeShare._filename("red", "firecracker", "n", "y")).write_text(
        json.dumps(raw))
    DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8),
                    _ServingPool(serving=False), share, _OVF_CFG, runtime="firecracker",
                    backlog_fn=lambda: 1, untargeted_backlog_fn=lambda: 1, node="n",
                    instance="w", capacity_fn=_budget(8 * 1024, 999), clock=lambda: 1.0,
                    warm_only=True).tick()
    assert specs["clip@firecracker@w"].min_warm == 0


# --- closed loop: a REAL warm-only WarmPool driven by its own sizer ------------------------------

def _closed_loop(tmp_path, *, u, schedule, extra_prompt=False, min_warm=0, budget=8,
                 stale_streak_at=None):
    """Run a warm-only fc prompt pool (real WarmPool + DispatcherSizer) beside a delayed cold peer
    (and optionally a second, healthy prompt peer). `schedule[t]` = restores fail at tick t. Each
    tick: sizer tick (resizes the pool), pool tick, then one untargeted job is served on a ready
    slot if any. Returns per-tick (broken, serving, streak, served_so_far)."""
    import logging
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
    from test_pool import _FakeRuntime
    from blastbox.host.pool import SlotState, WarmPool
    logging.disable(logging.CRITICAL)

    class _RT(_FakeRuntime):
        broken = False

        def spawn(self):
            if self.broken:
                raise RuntimeError("restore fails")
            return super().spawn()
    rt = _RT()
    pool = WarmPool(runtime=rt, warm_size=0, spawn_rate_limit=1000.0,
                    snapshot_rebuild_after=10**6)
    share = FileNodeShare(str(tmp_path))
    share.publish(_het_snapshot(("clip", "cold", "c", 1024, u, u, 64, 0, 0, True)))
    if extra_prompt:
        share.publish(_het_snapshot(("clip", "gvisor", "g", 1024, u, u, 8, 0, 0, False)))
    sizer = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=8,
                                       min_warm=min_warm), pool, share, _OVF_CFG,
                            runtime="firecracker", backlog_fn=lambda: u,
                            untargeted_backlog_fn=lambda: u, node="n", instance="w",
                            capacity_fn=_budget(budget * 1024, 999), clock=lambda: 1.0,
                            warm_only=True)
    out, served = [], 0
    try:
        for t, broken in enumerate(schedule):
            rt.broken = broken
            if stale_streak_at == t:
                pool._restore_failure_streak = WarmPool.SERVING_RESTORE_FAILURES
            sizer.tick()
            pool.tick()
            if u > 0 and any(s.state == SlotState.IDLE for s in pool._slots.values()):
                slot = pool.claim(timeout_s=0.05)
                if slot is not None:
                    pool.release(slot)
                    served += 1
            out.append((broken, pool.is_serving(), pool._restore_failure_streak, served))
    finally:
        logging.disable(logging.NOTSET)
    return out


def test_closed_loop_u1_recovers_after_heal_and_stays_down_while_broken(tmp_path, monkeypatch):
    # probe_liveness u=1: 3 transient failures then heal. Before the probe the fc pool's legacy
    # integer share was 0 (cold sorts first): warm 0, never spawned, not serving forever.
    _capture_specs(monkeypatch)
    sched = [True] * 6 + [False] * 10
    h = _closed_loop(tmp_path, u=1, schedule=sched)
    assert all(not serving for broken, serving, _s, _n in h[3:6])      # down while broken
    healed = [serving for broken, serving, _s, _n in h[6:]]
    assert any(healed[:4])                                            # back within a few ticks
    assert h[-1][1] is True and h[-1][3] >= 1 and h[-1][2] == 0        # served → streak reset


def test_closed_loop_stays_not_serving_while_every_restore_fails(tmp_path, monkeypatch):
    _capture_specs(monkeypatch)
    h = _closed_loop(tmp_path, u=4, schedule=[True] * 30)
    assert all(not serving for _b, serving, _s, _n in h[WarmPool_K():])
    assert h[-1][3] == 0


def test_stale_failures_after_a_served_job_recover_via_the_probe(tmp_path, monkeypatch):
    # codex: failures are not generation-guarded, so old-generation WARMING timeouts landing after
    # a new-generation served job can push the streak back to K (simulated here at tick 6 on a
    # healthy base). Accepted, bounded: the probe slot restores on the healthy base, promotes, and
    # the pool is serving again within one restore.
    _capture_specs(monkeypatch)
    h = _closed_loop(tmp_path, u=1, schedule=[False] * 12, stale_streak_at=6)
    assert h[5][1] is True
    assert any(serving for _b, serving, _s, _n in h[6:9])
    assert h[-1][1] is True


def WarmPool_K():
    from blastbox.host.pool import WarmPool
    return WarmPool.SERVING_RESTORE_FAILURES


def test_closed_loop_liveness_fuzz(tmp_path, monkeypatch):
    # over (u, a second prompt peer, min_warm, budget, fail/heal schedules): once restores heal the
    # pool is serving again within a bounded number of ticks and serves a job (streak 0); while
    # every restore fails (after K of them) it is never serving
    import itertools
    import random
    _capture_specs(monkeypatch)
    rng = random.Random(1313)
    n = 0
    for u, extra, mw, budget in itertools.product((1, 2, 5), (False, True), (0, 1), (3, 8)):
        for lead in (0, rng.randint(1, 4)):
            broken_len = rng.randint(4, 8)
            sched = [False] * lead + [True] * broken_len + [False] * 10
            n += 1
            h = _closed_loop(tmp_path / str(n), u=u, schedule=sched, extra_prompt=extra,
                             min_warm=mw, budget=budget)
            end = lead + broken_len
            if lead == 0:
                # broken from the start (no slot ever ready): after K failures, never serving
                assert not any(serving for _b, serving, streak, _nn in h[:end]
                               if streak >= WarmPool_K()), (u, extra, mw, budget, sched, h)
                assert not h[end - 1][1], (u, extra, mw, budget, sched, h)
            after = [serving for _b, serving, _s, _nn in h[end:]]
            assert any(after[:5]), (u, extra, mw, budget, sched, h)
            assert h[-1][1] and h[-1][2] == 0, (u, extra, mw, budget, sched, h)
