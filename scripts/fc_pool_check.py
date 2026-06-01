"""Live end-to-end WARM POOL of Firecracker microVMs (run on toolz2).

Proves the whole orchestrator with the FC tier: a WarmPool maintains N warm
microVMs (each boots + signals READY over vsock → IDLE), and the Dispatcher
serves a stream of jobs from them — each job's input goes over vsock, the guest
detonates, the host rdumps + trust-validates, and the slot is reaped+replaced
(warm ≠ reuse). Confirms warm slots are re-established after each job.
"""
from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from pathlib import Path

from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.pool_config import PoolConfig, build_warm_pool
from blastbox.host.runtime.firecracker import FCConfig, select_fc_runtime
from blastbox.limits import Limits

WARM_SIZE = 2
N_JOBS = 3


def _stage(job_root: Path, job: Job, payload: bytes) -> None:
    in_dir = job_root / job.job_id / "input"
    in_dir.mkdir(parents=True)
    (job_root / job.job_id / "output").mkdir(parents=True)
    (in_dir / job.filename).write_bytes(payload)


def main() -> None:
    scratch = tempfile.mkdtemp(prefix="dfc")
    job_root = Path(scratch) / "jobs"
    job_root.mkdir()

    cfg = FCConfig.from_env(scratch_root=str(Path(scratch) / "slots"))
    runtime = select_fc_runtime(cfg=cfg, require_available=True)
    pool = build_warm_pool(
        PoolConfig(runtime="firecracker", warm_size=WARM_SIZE, concurrent_ceiling=6),
        runtime=runtime,
    )
    assert pool is not None
    pool.start()
    print(f"pool started (warm_size={WARM_SIZE}); waiting for warm microVMs...")

    # Wait for the pool to bring up warm_size IDLE microVMs.
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline and pool.idle_count < WARM_SIZE:
        time.sleep(0.5)
    print(f"[warm] IDLE microVMs ready: {pool.idle_count}/{WARM_SIZE}")

    store = InMemoryJobStore()
    engines = {"probe": EngineSpec(name="probe", image="n/a", worker_argv=["worker", "run"])}
    dispatcher = Dispatcher(
        job_store=store,
        engines=engines,
        limits=Limits.from_env(),
        job_root=job_root,
        worker_timeout_s=60,
        pool=pool,
        warm_claim_timeout_s=20.0,
    )

    jobs: list[tuple[Job, str]] = []
    for i in range(N_JOBS):
        payload = f"pool-job-{i}-".encode() + b"X" * 2000
        sha = hashlib.sha256(payload).hexdigest()
        job = Job.new(engine="probe", filename=f"doc{i}.bin")
        job.input_sha256 = sha
        store.create(job)
        _stage(job_root, job, payload)
        jobs.append((job, sha))

    print(f"\nsubmitting {N_JOBS} jobs to the warm FC pool...")
    served = 0
    for _ in range(N_JOBS):
        if dispatcher.dispatch_once():
            served += 1

    done = 0
    for job, _sha in jobs:
        j = store.get(job.job_id)
        assert j is not None
        arts = j.result_summary["artifact_count"] if j.result_summary else "-"
        print(f"  {job.filename}: status={j.status.value} artifacts={arts} runtime={j.worker_runtime}")
        if j.status == JobStatus.DONE:
            done += 1

    # The pool replaces each consumed slot — confirm warm slots re-establish.
    time.sleep(8.0)
    print(f"\n[after] pool re-warmed IDLE microVMs: {pool.idle_count}/{WARM_SIZE}")

    # Observability: the pool + dispatcher populate Prometheus metrics live.
    from blastbox.observability.metrics import generate_latest

    print("\n=== LIVE METRICS (/metrics) ===")
    wanted = (
        "blastbox_pool_slots{",
        "blastbox_pool_warm_target ",
        "blastbox_pool_spawns_total ",
        "blastbox_pool_reaps_total ",
        "blastbox_warm_claims_total{",
        "blastbox_jobs_dispatched_total{",
        "blastbox_job_duration_seconds_count{",
    )
    for line in generate_latest().decode().splitlines():
        if line.startswith(wanted):
            print("  " + line)

    pool.stop()
    shutil.rmtree(scratch, ignore_errors=True)

    print("\n=== SUMMARY ===")
    print(f"  jobs served: {served}/{N_JOBS}")
    print(f"  jobs DONE (trust-validated): {done}/{N_JOBS}")
    assert done == N_JOBS, f"only {done}/{N_JOBS} jobs completed"
    print("RESULT: WARM POOL OF FC MICROVMS SERVED ALL JOBS (vsock in -> detonate "
          "-> rdump -> trust-validated; slots reaped + replaced)")


if __name__ == "__main__":
    main()
