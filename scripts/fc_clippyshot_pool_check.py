"""Live: a WARM POOL of ClippyShot LibreOffice microVMs serving .docx jobs.

The full deployment shape: a WarmPool maintains warm clippyshot microVMs (each
boots + signals READY), the Dispatcher serves a stream of real .docx jobs from
them — each input over vsock, detonated by ClippyShot's Converter (soffice ->
pdftoppm) as non-root, output rdumped + trust-validated, slot reaped+replaced.
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

DOCX = Path("/home/coz/fixture.docx")
WARM_SIZE = 2
CEILING = 4
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
        PoolConfig(runtime="firecracker", warm_size=WARM_SIZE, concurrent_ceiling=CEILING),
        runtime=runtime,
    )
    assert pool is not None
    pool.start()
    print(f"pool started (warm_size={WARM_SIZE}); booting clippyshot microVMs...")

    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and pool.idle_count < WARM_SIZE:
        time.sleep(0.5)
    print(f"[warm] IDLE clippyshot microVMs: {pool.idle_count}/{WARM_SIZE}")

    docx = DOCX.read_bytes()
    sha = hashlib.sha256(docx).hexdigest()

    store = InMemoryJobStore()
    engines = {"clippyshot": EngineSpec(name="clippyshot", image="n/a", worker_argv=["worker"])}
    dispatcher = Dispatcher(
        job_store=store, engines=engines, limits=Limits.from_env(),
        job_root=job_root, worker_timeout_s=120, pool=pool, warm_claim_timeout_s=60.0,
    )

    jobs = []
    for i in range(N_JOBS):
        job = Job.new(engine="clippyshot", filename=f"doc{i}.docx")
        job.input_sha256 = sha
        store.create(job)
        _stage(job_root, job, docx)
        jobs.append(job)

    print(f"\nsubmitting {N_JOBS} .docx jobs to the warm clippyshot pool...")
    served = 0
    for _ in range(N_JOBS):
        if dispatcher.dispatch_once():
            served += 1

    done = 0
    for job in jobs:
        j = store.get(job.job_id)
        assert j is not None
        arts = j.result_summary["artifact_count"] if j.result_summary else "-"
        print(f"  {job.filename}: status={j.status.value} artifacts={arts} runtime={j.worker_runtime}")
        if j.status == JobStatus.DONE:
            done += 1

    time.sleep(8.0)
    print(f"\n[after] pool re-warmed IDLE microVMs: {pool.idle_count}/{WARM_SIZE}")

    from blastbox.observability.metrics import generate_latest

    print("\n=== LIVE METRICS ===")
    for line in generate_latest().decode().splitlines():
        if line.startswith((
            "blastbox_pool_slots{state=\"idle\"}",
            "blastbox_pool_spawns_total ",
            "blastbox_jobs_dispatched_total{",
            "blastbox_warm_claims_total{",
        )):
            print("  " + line)

    pool.stop()
    shutil.rmtree(scratch, ignore_errors=True)

    print(f"\n=== SUMMARY ===  served={served}/{N_JOBS}  DONE(trust-validated)={done}/{N_JOBS}")
    assert done == N_JOBS, f"only {done}/{N_JOBS} completed"
    print("RESULT: WARM POOL OF CLIPPYSHOT LIBREOFFICE MICROVMS SERVED ALL .docx JOBS")


if __name__ == "__main__":
    main()
