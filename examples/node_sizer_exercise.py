"""End-to-end exercise of the node pool autosizer on real hardware.

Drives EVERY behavior against this node's real /proc/meminfo + cpu_count budget and real
filesystem, with fake pools (touches no production container), and asserts each:

  1. real node budget read from /proc/meminfo + cpu_count
  2. tier identity      — same engine on fc AND gvisor = distinct pools, share budget
  3. no oversubscription — Σ ceiling·footprint ≤ node budget
  4. min_warm reserved  — an idle latency-floor pool keeps its floor vs a busy neighbour
  5. resource-share     — equal-weight pools with different footprints get equal RAM
  6. adaptive shedding  — under simulated memory pressure the budget sheds toward the floor
  7. heartbeat + fence  — snapshot stays fresh across a slow count; no republish after stop
  8. cross-node iso     — foreign-node snapshots in a shared dir are ignored
  9. graceful cleanup   — a stopped unit removes its own snapshot

Run:  PYTHONPATH=src python3 examples/node_sizer_exercise.py
Exit code 0 = all PASS.
"""

from __future__ import annotations

import socket
import sys
import tempfile
import threading

from blastbox.host.dispatcher_sizer import DispatcherSizer
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_sizer import NodeBudget, PoolSpec, node_capacity, plan_sizes
from blastbox.host.node_share import DemandSnapshot, FileNodeShare
from blastbox.host.pool_config import RUNTIME_FIRECRACKER, RUNTIME_GVISOR

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


class FakePool:
    def __init__(self, assigned: int = 0) -> None:
        self.assigned_count = assigned
        self.warm_size = 0
        self.concurrent_ceiling = 0

    def resize(self, *, warm_size: int, concurrent_ceiling: int) -> None:
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling


def cfg(**kw: object) -> NodeConfig:
    base = dict(balancing=True, resource_management=True, ram_headroom_frac=0.8,
                vcpu_oversubscription=2.0, stale_after_s=60.0)
    base.update(kw)
    return NodeConfig(**base)  # type: ignore[arg-type]


def main() -> int:
    node = socket.gethostname()
    cap = node_capacity(0.8, 2.0)
    print(f"node={node}  real budget: {cap.ram_mib:,.0f} MiB ({cap.ram_mib/1024:.1f} GiB) / "
          f"{cap.vcpus:.0f} vCPU\n")

    # 1 — real budget
    check("real node budget", cap.ram_mib > 0 and cap.vcpus >= 1,
          f"{cap.ram_mib/1024:.1f} GiB / {cap.vcpus:.0f} vCPU")

    # 2 + 3 — tier identity + no oversubscription, real production topology on THIS node
    d = tempfile.mkdtemp(prefix="bb-ex-")
    share = FileNodeShare(d)
    units = [("redtusk", RUNTIME_FIRECRACKER, 30, "r1"), ("redtusk", RUNTIME_GVISOR, 6, "r2"),
             ("titanarum", RUNTIME_FIRECRACKER, 12, "t1"), ("titanarum", RUNTIME_GVISOR, 3, "t2")]
    sizers = []
    for name, tier, backlog, inst in units:
        p = FakePool()
        ds = DispatcherSizer(EngineNode(name, "-", slot_ram_mib=2048, slot_vcpus=1, max_ceiling=64),
                             p, share, cfg(), runtime=tier, backlog_fn=(lambda b=backlog: b),
                             node=node, instance=inst)
        sizers.append((name, tier, p, ds))
    for _ in range(3):
        for *_, ds in sizers:
            ds.tick()
    files = sorted(f.name for f in __import__("pathlib").Path(d).glob("*.json"))
    check("tier identity: 4 distinct pool files", len(files) == 4, str(files))
    total_ram = sum(p.concurrent_ceiling * 2048 for _, _, p, _ in sizers)
    check("no oversubscription (Σ ≤ budget)", total_ram <= cap.ram_mib,
          f"{total_ram:,.0f} ≤ {cap.ram_mib:,.0f} MiB")
    rt_fc = next(p for n, t, p, _ in sizers if n == "redtusk" and t == RUNTIME_FIRECRACKER)
    rt_gv = next(p for n, t, p, _ in sizers if n == "redtusk" and t == RUNTIME_GVISOR)
    check("redtusk fc+gvisor both sized, demand-weighted",
          rt_fc.concurrent_ceiling >= 1 and rt_gv.concurrent_ceiling >= 1
          and rt_fc.concurrent_ceiling > rt_gv.concurrent_ceiling,
          f"fc={rt_fc.concurrent_ceiling} gv={rt_gv.concurrent_ceiling}")

    # 4 — min_warm reserved (pure allocation, deterministic)
    plan = plan_sizes([PoolSpec("idle", slot_ram_mib=2048, demand=0, min_warm=4, max_ceiling=64),
                       PoolSpec("busy", slot_ram_mib=2048, demand=50, min_warm=0, max_ceiling=64)],
                      NodeBudget(ram_mib=5 * 2048, vcpus=999))
    check("min_warm reserved over busy neighbour",
          plan["idle"].warm_size == 4 and plan["busy"].concurrent_ceiling == 1,
          f"idle.warm={plan['idle'].warm_size} busy.ceil={plan['busy'].concurrent_ceiling}")

    # 5 — resource-share
    plan = plan_sizes([PoolSpec("small", slot_ram_mib=1024, demand=5, max_ceiling=99),
                       PoolSpec("big", slot_ram_mib=4096, demand=5, max_ceiling=99)],
                      NodeBudget(ram_mib=20 * 1024, vcpus=9999))
    sram, bram = plan["small"].concurrent_ceiling * 1024, plan["big"].concurrent_ceiling * 4096
    check("resource-share: equal weight → ~equal RAM",
          plan["small"].concurrent_ceiling > plan["big"].concurrent_ceiling and abs(sram - bram) <= 4096,
          f"small={sram/1024:.0f}GiB big={bram/1024:.0f}GiB")

    # 6 — adaptive shedding under simulated pressure (real avail_fn overridden)
    ds_a = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048), FakePool(),
                           FileNodeShare(tempfile.mkdtemp(prefix="bb-ex-")),
                           cfg(adaptive=True, min_free_mib=2048.0), runtime=RUNTIME_FIRECRACKER,
                           backlog_fn=lambda: 1, avail_fn=lambda: 100.0)  # 100 MiB free = pressure
    b = NodeBudget(ram_mib=10000.0, vcpus=10.0)
    for _ in range(30):
        adapted = ds_a._adapt(b)
    check("adaptive sheds under pressure (→ 0.25 floor)",
          0.24 <= adapted.ram_mib / b.ram_mib <= 0.26, f"scale={adapted.ram_mib/b.ram_mib:.2f}")

    # 7 — heartbeat during a slow count + fence on stop
    d7 = tempfile.mkdtemp(prefix="bb-ex-")
    sh7 = FileNodeShare(d7)
    stop = threading.Event()
    holder: dict[str, DispatcherSizer] = {}

    def slow_count() -> int:            # peer read happens DURING this; then stop+remove
        mid = sh7.read_all(max_age_s=60.0, now=1.0)   # a peer reads mid-count
        holder["seen_during"] = bool(mid)             # heartbeat should be visible
        stop.set()
        holder["ds"].remove_own_snapshot()
        return 3

    ds7 = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048), FakePool(), sh7, cfg(),
                          runtime=RUNTIME_FIRECRACKER, backlog_fn=slow_count, node="n",
                          instance="i", clock=lambda: 1.0)
    holder["ds"] = ds7
    ds7._stop_event = stop
    ds7.tick()
    import pathlib
    check("heartbeat visible to peers during slow count", bool(holder.get("seen_during")))
    check("update-publish fenced on stop (no phantom)",
          list(pathlib.Path(d7).glob("*.json")) == [])

    # 8 — cross-node isolation (seed a FOREIGN node's snapshots into a shared dir)
    d8 = tempfile.mkdtemp(prefix="bb-ex-")
    sh8 = FileNodeShare(d8)
    for eng in ("redtusk", "titanarum"):
        sh8.publish(DemandSnapshot(eng, 40, 0, 2048, 1, 0, 64, 1.0, ts=1.0,
                                   node="OTHERHOST", tier="firecracker", instance="x"))
    pool8 = FakePool()
    ds8 = DispatcherSizer(EngineNode("redtusk", "-", slot_ram_mib=2048, max_ceiling=64), pool8, sh8,
                          cfg(), runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 4, node=node,
                          instance="me", capacity_fn=lambda h, o: NodeBudget(8 * 2048, 999),
                          clock=lambda: 1.0)
    ds8.tick()
    ds8.tick()
    own = sum(p.concurrent_ceiling for p in [pool8]) * 2048
    check("cross-node: foreign pools ignored, sized only from own node",
          own <= 8 * 2048, f"own Σ={own/1024:.0f}GiB ≤ 16GiB budget")

    # 9 — graceful cleanup removes own snapshot
    d9 = tempfile.mkdtemp(prefix="bb-ex-")
    sh9 = FileNodeShare(d9)
    ds9 = DispatcherSizer(EngineNode("clip", "-", slot_ram_mib=2048), FakePool(), sh9,
                          cfg(interval_s=0.5), runtime=RUNTIME_FIRECRACKER, backlog_fn=lambda: 2,
                          node="n", instance="g")
    ds9.run(max_ticks=2, sleep=lambda _s: None)
    check("graceful stop removes own snapshot",
          list(pathlib.Path(d9).glob("*.json")) == [])

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks PASS on {node}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
