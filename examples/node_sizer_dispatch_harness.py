"""Dispatch-startup integration exercise for the node autosizer, on real hardware.

Drives the ACTUAL cli dispatch-startup wiring (`_node_manages_tier`, `_start_node_sizer`,
the hard-cap forcing, unspawned start, synchronous first sizing, restore-on-skip,
reservation-until-reaped) against a REAL SQLite job store (exercising idx_jobs_status_engine_tier
and the count-collection path) and a REAL filesystem share dir, with a WarmPool-shaped fake pool
so no microVM runtime is needed. Non-disruptive — touches no production container.

Run:  PYTHONPATH=src python3 examples/node_sizer_dispatch_harness.py
Exit 0 = all PASS.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile

from blastbox.host.cli import _node_manages_tier, _start_node_sizer
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.sql_store import SqlJobStore

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


class FakePool:
    """WarmPool-shaped: resize/start/stop + the props the sizer reads."""

    def __init__(self, warm_size: int = 8, concurrent_ceiling: int = 8) -> None:
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling
        self.assigned_count = 0
        self.started = False
        self.stopped = False

    def resize(self, *, warm_size: int, concurrent_ceiling: int) -> None:
        self.warm_size = warm_size
        self.concurrent_ceiling = concurrent_ceiling

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


def main() -> int:
    node = socket.gethostname()
    print(f"node={node}\n")
    tmp = tempfile.mkdtemp(prefix="bb-disp-")
    db = os.path.join(tmp, "jobs.db")
    share_dir = os.path.join(tmp, "nodeshare")

    # Real SQLite store — creating it runs the schema DDL incl. idx_jobs_status_engine_tier.
    store = SqlJobStore(f"sqlite:///{db}")
    for e, n in (("clip", 30), ("clip", 0), ("red", 5)):   # seed a backlog for clip + red
        for _ in range(n if n else 1):
            j = Job.new(engine=e, filename="x")
            if n == 0:
                break
            store.create(j)
    check("SQLite backlog index exists (idx_jobs_status_engine_tier)",
          _sqlite_has_index(db, "idx_jobs_status_engine_tier"))
    check("tier-scoped backlog count over SQLite",
          store.count(JobStatus.QUEUED, engine=["clip", "red"], claimant_tier="firecracker") == 35,
          "clip(30)+red(5)=35")

    # Node config for the managed case.
    for k, v in {"BLASTBOX_NODE_ENGINES": "clip,red",
                 "BLASTBOX_NODE_RESOURCE_MANAGEMENT": "1",
                 "BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB": "2048",
                 "BLASTBOX_NODE_ENGINE_RED_RAM_MIB": "2048",
                 "BLASTBOX_NODE_SHARE_DIR": share_dir}.items():
        os.environ[k] = v

    tier = "firecracker"
    node_managed = _node_manages_tier(tier)
    check("node manages fc tier (RM on) → cold-gate wiring active", node_managed)
    check("cold tier NOT node-managed", not _node_manages_tier("cold"))

    # ---- managed startup sequence (as _dispatch_cmd does) ----
    concurrency = 6                                         # BLASTBOX_DISPATCH_CONCURRENCY
    pool = FakePool(warm_size=8, concurrent_ceiling=8)
    pool.resize(warm_size=0, concurrent_ceiling=1)         # start unspawned
    pool.start()
    check("pool starts unspawned (warm=0) before first sizing", pool.warm_size == 0)

    # A live COLD-admission gate (as _dispatch_cmd builds when node-managed) — seeded with the
    # operator's dispatch concurrency, then driven by the sizer to the budget's cold HEADROOM.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    gate = DynamicConcurrencyGate(concurrency)
    sizer = _start_node_sizer(pool, ["clip", "red"], store, tier, concurrency, gate)
    check("sizer started for a complete inventory", sizer is not None)
    check("synchronous first tick sized the pool from the node budget", pool.concurrent_ceiling >= 1,
          f"ceiling={pool.concurrent_ceiling}")
    check("pool ceiling capped at dispatch concurrency (not warmed beyond usable)",
          pool.concurrent_ceiling <= concurrency, f"{pool.concurrent_ceiling} <= {concurrency}")
    # The gate is the COLD headroom = max(1, ceiling − warm reservation): warm dispatch reuses a
    # resident slot (never gated); cold spawns outside the pool, so headroom is what keeps
    # warm residency + cold within the budget instead of each independently reaching the ceiling.
    expect_headroom = max(1, pool.concurrent_ceiling - pool.warm_size)
    check("sizer drove the cold gate to (ceiling − warm) headroom",
          gate.limit == expect_headroom,
          f"gate={gate.limit} expected={expect_headroom} (ceiling={pool.concurrent_ceiling} warm={pool.warm_size})")
    # warm residency + cold admission stays within the ceiling (+1 liveness floor):
    check("warm reservation + cold headroom ≤ ceiling (+1 floor)",
          pool.warm_size + gate.limit <= pool.concurrent_ceiling + 1,
          f"warm={pool.warm_size} + cold={gate.limit} vs ceiling={pool.concurrent_ceiling}")
    # And the gate actually bounds: acquire the headroom's worth of permits, the next one blocks.
    got = [gate.acquire(0.05) for _ in range(gate.limit)]
    over = gate.acquire(0.05)
    for _ in range(sum(got)):
        gate.release()
    check("cold gate admits exactly the headroom and blocks the over-limit job",
          all(got) and not over, f"admitted={sum(got)}/{expect_headroom} over_limit_blocked={not over}")
    files = os.listdir(share_dir)
    check("published a node-view snapshot", any(f.endswith(".json") for f in files), str(files))

    # ---- graceful shutdown: reap THEN release the reservation ----
    if sizer is not None:
        stop, thread, obj = sizer
        stop.set()
        thread.join(timeout=5.0)
        pool.stop()                                        # reap slots first...
        obj.remove_own_snapshot()                          # ...then release reservation
    check("graceful stop reaped pool then removed snapshot",
          pool.stopped and not [f for f in os.listdir(share_dir) if f.endswith(".json")])

    # ---- restore-on-skip: incomplete inventory must NOT leave the pool dead at 0 ----
    pool2 = FakePool(warm_size=6, concurrent_ceiling=6)
    orig2 = (pool2.warm_size, pool2.concurrent_ceiling)
    pool2.resize(warm_size=0, concurrent_ceiling=1)
    pool2.start()
    # dispatcher serves clip+red+titan but titan isn't declared → sizer skips
    sizer2 = _start_node_sizer(pool2, ["clip", "red", "titan"], store, tier)
    if sizer2 is None:
        pool2.resize(warm_size=orig2[0], concurrent_ceiling=orig2[1])   # restore (as cli does)
    check("incomplete inventory → sizer skipped, pool restored (not stuck at 0)",
          sizer2 is None and pool2.warm_size == 6 and pool2.concurrent_ceiling == 6)

    for k in ("BLASTBOX_NODE_ENGINES", "BLASTBOX_NODE_RESOURCE_MANAGEMENT",
              "BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "BLASTBOX_NODE_ENGINE_RED_RAM_MIB",
              "BLASTBOX_NODE_SHARE_DIR"):
        os.environ.pop(k, None)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks PASS on {node}")
    return 0 if passed == len(RESULTS) else 1


def _sqlite_has_index(db_path: str, name: str) -> bool:
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        return any(r[0] == name for r in rows)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
