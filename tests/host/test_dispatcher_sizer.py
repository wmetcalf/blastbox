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


def test_auto_created_share_dir_is_writable_by_cross_uid_peers(tmp_path):
    # regression (PR #60 codex P2): when FileNodeShare AUTO-creates the dir and dispatchers run
    # under different UIDs, a default-umask dir (0755) lets peers READ but not create their own
    # <identity>.json → their publish fails, they fall back to static sizing, and the first
    # dispatcher sees only itself and allocates the WHOLE node budget. An auto-created dir must
    # be sticky world-writable (0o1777, /tmp semantics) so any peer UID can publish.
    import os
    import stat
    d = tmp_path / "share-auto"
    assert not d.exists()
    FileNodeShare(str(d))
    mode = stat.S_IMODE(os.stat(d).st_mode)
    assert mode & 0o002, f"auto-created share dir not world-writable: {oct(mode)}"
    assert mode & stat.S_ISVTX, f"auto-created share dir missing sticky bit: {oct(mode)}"


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
    # THIS dispatcher is TAGGED "n" → its view is {n(self), ""(peer)} = mixed identities.
    ds = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=1024, max_ceiling=64, min_warm=1),
                         pool, share, cfg, runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 30,
                         node="n", instance="c", capacity_fn=_budget(10 * 1024, 999),
                         clock=lambda: 1.0)
    mine = ds.tick()
    # floored to min_warm — NOT grown to a big share despite the deep backlog + 10-slot budget.
    assert mine.warm_size == 1 and mine.concurrent_ceiling == 1
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


def test_multi_engine_pool_ceiling_is_largest_not_smallest(tmp_path, monkeypatch):
    # PR #60 codex P2: a shared pool serving engines with different MAX_CEILING must take the
    # LARGEST (bounded by concurrency), not the smallest — else a low-cap engine throttles the
    # whole pool (clip cap 1 + red cap 32 → capped at 1 even when all work is red).
    from blastbox.host.cli import _start_node_sizer
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip,red")
    monkeypatch.setenv("BLASTBOX_NODE_RESOURCE_MANAGEMENT", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_MAX_CEILING", "1")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_RED_MAX_CEILING", "32")
    monkeypatch.setenv("BLASTBOX_NODE_SHARE_DIR", str(tmp_path))
    res = _start_node_sizer(_Pool(), ["clip", "red"], InMemoryJobStore(), "firecracker", 32)
    assert res is not None
    stop, thread, sizer = res
    try:
        assert sizer._engine.max_ceiling == 32     # largest engine's cap, not min(1, 32)=1
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
    assert not _node_manages_tier("cold")                 # RM on but cold isn't node-managed
    assert not _node_manages_tier("aws-ec2")


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
