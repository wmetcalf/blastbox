"""Live real-hardware demo of the blastbox node pool autosizer.

Simulates the exact production topology on this node — engines redtusk + titanarum, each
on BOTH firecracker and gvisor tiers (4 pools on one physical host) — coordinating via a
shared node dir under this node's REAL /proc/meminfo + cpu_count budget. Uses fake pools,
so it touches NO production container. Proves end-to-end on real hardware:

  * node_capacity() reads this box's real RAM/vCPU;
  * the (engine, tier, node) identity keeps all 4 pools distinct — no file collision, and
    redtusk@firecracker vs redtusk@gvisor are NOT collapsed;
  * every dispatcher sizes its own pool from the shared view, and
    Σ ceiling·footprint stays within the node budget (no oversubscription).

Run:  PYTHONPATH=src python3 examples/node_sizer_live_demo.py
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile

from blastbox.host.dispatcher_sizer import DispatcherSizer
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_sizer import node_capacity
from blastbox.host.node_share import FileNodeShare
from blastbox.host.pool_config import RUNTIME_FIRECRACKER, RUNTIME_GVISOR

SLOT_RAM_MIB = 2048.0          # a warm microVM footprint
HEADROOM = 0.8
OVERSUB = 2.0


class FakePool:
    """WarmPool-shaped stand-in: records the size the sizer applies, spawns nothing."""

    def __init__(self, assigned: int = 0) -> None:
        self.assigned_count = assigned
        self.warm_size = 0
        self.concurrent_ceiling = 0

    def resize(self, *, warm_size: int, concurrent_ceiling: int) -> None:
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling


def main() -> int:
    node = socket.gethostname()
    cap = node_capacity(ram_headroom_frac=HEADROOM, vcpu_oversubscription=OVERSUB)
    print(f"node               : {node}")
    print(f"real budget        : RAM={cap.ram_mib:,.0f} MiB ({cap.ram_mib/1024:.1f} GiB) "
          f"| vCPU={cap.vcpus:.0f}  (headroom {HEADROOM}, oversub {OVERSUB})")
    print(f"per-slot footprint : {SLOT_RAM_MIB:,.0f} MiB")

    share_dir = tempfile.mkdtemp(prefix="bb-node-demo-")
    share = FileNodeShare(share_dir)
    cfg = NodeConfig(balancing=True, resource_management=True,
                     ram_headroom_frac=HEADROOM, vcpu_oversubscription=OVERSUB,
                     stale_after_s=120.0)

    # the real toolz2 topology: 2 engines x 2 node-managed tiers = 4 pools, one host.
    units = [
        ("redtusk",   RUNTIME_FIRECRACKER, 30),
        ("redtusk",   RUNTIME_GVISOR,       6),
        ("titanarum", RUNTIME_FIRECRACKER, 12),
        ("titanarum", RUNTIME_GVISOR,       3),
    ]
    sizers = []
    for name, tier, backlog in units:
        pool = FakePool()
        ds = DispatcherSizer(
            EngineNode(name, "-", slot_ram_mib=SLOT_RAM_MIB, slot_vcpus=1.0, max_ceiling=64),
            pool, share, cfg, runtime=tier,
            backlog_fn=(lambda b=backlog: b), node=node,
        )
        sizers.append((name, tier, backlog, pool, ds))

    # two rounds so every dispatcher's view includes all four published snapshots
    for _ in range(2):
        for *_, ds in sizers:
            ds.tick()

    files = sorted(os.listdir(share_dir))
    print(f"\npublished files    : {files}")

    print("\n  pool                         backlog  warm  ceiling")
    total_ram = 0.0
    total_slots = 0
    for name, tier, backlog, pool, _ in sizers:
        print(f"  {name+'@'+tier:<28} {backlog:>7}  {pool.warm_size:>4}  {pool.concurrent_ceiling:>7}")
        total_ram += pool.concurrent_ceiling * SLOT_RAM_MIB
        total_slots += pool.concurrent_ceiling

    print(f"\nΣ ceiling·footprint: {total_ram:,.0f} MiB   (budget {cap.ram_mib:,.0f} MiB)")
    print(f"Σ ceilings         : {total_slots} slots     (vCPU budget {cap.vcpus:.0f})")

    ok = True
    if len(files) != 4:
        print("FAIL: expected 4 distinct pool files (collision!)")
        ok = False
    if total_ram > cap.ram_mib + 1e-6:
        print("FAIL: Σ ceiling·footprint exceeds the RAM budget (oversubscription!)")
        ok = False
    if total_slots > cap.vcpus + 1e-6:
        print("FAIL: Σ ceilings exceeds the vCPU budget")
        ok = False
    # redtusk's two tiers must be distinct pools, both alive
    rt_fc = next(p for n, t, _, p, _ in sizers if n == "redtusk" and t == RUNTIME_FIRECRACKER)
    rt_gv = next(p for n, t, _, p, _ in sizers if n == "redtusk" and t == RUNTIME_GVISOR)
    if rt_fc.concurrent_ceiling < 1 or rt_gv.concurrent_ceiling < 1:
        print("FAIL: a redtusk tier got no capacity (pools collapsed?)")
        ok = False
    if rt_fc.concurrent_ceiling <= rt_gv.concurrent_ceiling:
        print("WARN: busier redtusk@firecracker (backlog 30) did not outsize redtusk@gvisor (6)")

    print("\nRESULT:", "PASS — real-HW budget honored, 4 distinct pools, demand-weighted" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
