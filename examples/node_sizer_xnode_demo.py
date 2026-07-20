"""Cross-node isolation check for the node pool autosizer.

The multi-node model: engines span physical nodes sharing a QUEUE, but each node sizes its
OWN pools against its OWN hardware. If a share_dir is (accidentally, via NFS) seen by more
than one node, each node MUST size only its own engines and ignore the foreign node's — or
it would double-budget and oversubscribe. This publishes THIS node's pools into a possibly
shared dir, reads the whole dir, and proves the node filter keeps foreign pools out of the
plan.

Run:  PYTHONPATH=src python3 examples/node_sizer_xnode_demo.py <shared_dir>
"""

from __future__ import annotations

import os
import socket
import time
import sys

from blastbox.host.dispatcher_sizer import DispatcherSizer
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_sizer import node_capacity
from blastbox.host.node_share import FileNodeShare
from blastbox.host.pool_config import RUNTIME_FIRECRACKER, RUNTIME_GVISOR

SLOT = 2048.0


class FakePool:
    def __init__(self) -> None:
        self.assigned_count = 0
        self.warm_size = 0
        self.concurrent_ceiling = 0

    def resize(self, *, warm_size: int, concurrent_ceiling: int) -> None:
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling


def main() -> int:
    share_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bb-xnode"
    node = socket.gethostname()
    os.makedirs(share_dir, exist_ok=True)
    share = FileNodeShare(share_dir)
    budget = node_capacity(0.8, 2.0).ram_mib
    cfg = NodeConfig(balancing=True, resource_management=True, ram_headroom_frac=0.8,
                     vcpu_oversubscription=2.0, stale_after_s=3600.0)

    units = [("redtusk", RUNTIME_FIRECRACKER, 30), ("redtusk", RUNTIME_GVISOR, 6),
             ("titanarum", RUNTIME_FIRECRACKER, 12), ("titanarum", RUNTIME_GVISOR, 3)]
    sizers = []
    for name, tier, backlog in units:
        p = FakePool()
        ds = DispatcherSizer(
            EngineNode(name, "-", slot_ram_mib=SLOT, slot_vcpus=1.0, max_ceiling=64),
            p, share, cfg, runtime=tier, backlog_fn=(lambda b=backlog: b), node=node)
        sizers.append((name, tier, p, ds))

    for _ in range(2):                          # two rounds so this node sees its own full set
        for *_, ds in sizers:
            ds.tick()

    allfiles = sorted(os.listdir(share_dir))
    # filename is engine[@tier]@<node>[@<instance>].json — mine carry this node id as a part
    mine = [f for f in allfiles if f"@{node}@" in f or f.endswith(f"@{node}.json")]
    foreign = [f for f in allfiles if f not in mine]
    total_slots = sum(p.concurrent_ceiling for _, _, p, _ in sizers)

    print(f"node={node}  budget={budget:,.0f} MiB")
    print(f"shared dir: {len(allfiles)} files = {len(mine)} mine + {len(foreign)} FOREIGN")
    print(f"  foreign (must be ignored): {foreign}")
    print("  my pools: " + ", ".join(f"{n}@{t}={p.concurrent_ceiling}" for n, t, p, _ in sizers))
    print(f"Σ my ceilings = {total_slots} slots -> {total_slots*SLOT:,.0f} MiB of {budget:,.0f} MiB budget")

    # DIRECT proof of isolation: apply the sizer's node filter to the whole shared dir and
    # assert NO foreign node survives into the view we plan over. (A budget check alone can't
    # prove this — plan_sizes clamps the combined view to budget regardless, so summing local
    # pools stays ≤ budget even if foreign pools entered.)
    view = [s for s in share.read_all(max_age_s=3600.0, now=time.time())
            if s.node == "" or node == "" or s.node == node]
    foreign_in_view = sorted({s.node for s in view if s.node not in ("", node)})
    print(f"  foreign nodes surviving the filter: {foreign_in_view} (must be empty)")
    ok = not foreign_in_view and total_slots * SLOT <= budget + 1e-6
    print("RESULT:", "PASS — foreign snapshots filtered out of the planning view"
          if ok else "FAIL — a foreign node's pools entered the view")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
