"""Libvirt pool job dispatcher — the VM-worker analogue of ``blastbox dispatch``.

``blastbox dispatch`` claims queued jobs and ``docker run``s a fresh worker container per job. A
VM-backed engine can't do that (its worker is a long-lived libvirt VM, not a container), so this is
the parallel: it claims queued jobs from the shared JobStore + their spooled inputs from ``job_root``
and runs each through an engine-supplied ``validate`` callable (which talks the engine's warm VM
worker over its own transport), then writes the verdict back as the Job's ``result_summary``.

It owns ONLY the generic plumbing — the JobStore claim loop (a thread per warm worker), the
CAS-fenced terminal write, and input cleanup. The engine owns the WarmPool + the worker transport
(``validate``). This is the privileged host tier in an ingress/dispatcher split: it is never
client-facing — its inputs are the queue + the spooled files.

    validate(input_path) -> (result_summary: dict | None, ok: bool)
        ok True  -> the job is marked DONE with result_summary
        ok False -> FAILED  (an engine-detected error: dead worker, engine_error envelope, …)
        raising  -> FAILED  (the exception type, sanitized, as the error)
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from blastbox.host.jobs.base import Job, JobStatus, JobStore
from blastbox.host.jobs.retention import JobRetentionSweeper

logger = logging.getLogger(__name__)


class VmJobDispatcher:
    """Drive queued jobs through an engine's warm VM pool. ``validate`` is the engine seam.

    ``engine`` scopes claims in a SHARED multi-engine JobStore: this dispatcher has a single
    engine-specific ``validate``, so a job for another engine that it happens to claim is requeued
    (not run through the wrong validator). Leave ``None`` for a single-engine store (claim anything).
    ``worker_tier`` is the warm-backend label surfaced to UIs (``worker_runtime`` is always the
    sweep-recognized ``"warm"`` so a peer's crash-recovery treats an in-flight VM job as warm — TIME-
    based fail, never a cold re-detonation). ``job_retention_s`` sets ``expires_at`` on terminal jobs
    so the retention sweeper reclaims their dirs (None = keep indefinitely)."""

    def __init__(self, store: JobStore, job_root: str,
                 validate: Callable[[Path], tuple[dict | None, bool]], *,
                 engine: str | None = None, worker_tier: str = "libvirt-vm",
                 job_retention_s: int = 0, concurrency: int = 1, poll_s: float = 0.5,
                 heartbeat_s: float = 30.0, maintenance_interval_s: float = 60.0,
                 orphan_timeout_s: float = 600.0, sole_owner: bool = False) -> None:
        self._store = store
        self._job_root = Path(job_root)
        self._validate = validate
        self._engine = engine
        self._worker_tier = worker_tier
        self._retention_s = max(0, int(job_retention_s))
        self._concurrency = max(1, concurrency)
        self._poll_s = poll_s
        self._heartbeat_s = max(1.0, float(heartbeat_s))
        # Maintenance (retention + orphan recovery): a VM-only deployment has no container Dispatcher
        # to run it. interval<=0 disables. orphan_timeout: a RUNNING job not heartbeat-refreshed in
        # this long has a dead owner → FAIL it (keep it comfortably above heartbeat_s).
        self._maintenance_interval_s = float(maintenance_interval_s)
        self._orphan_timeout_s = max(self._heartbeat_s * 4, float(orphan_timeout_s))
        # sole_owner: this is the ONLY dispatcher on the store (VM-only deployment, no cold/container
        # dispatcher). Then orphan recovery can also reclaim a stale RUNNING job that was claimed but
        # crashed BEFORE _process stamped worker_runtime="warm" — there's no cold job to mistake it
        # for. Default False keeps recovery scoped to our own warm-stamped claims (shared-store safe).
        self._sole_owner = bool(sole_owner)
        self._retention = JobRetentionSweeper(self._job_root)
        self._stop = threading.Event()

    def _job_dir(self, job: Job) -> Path:
        # The ingress canonical layout is <job_root>/<id>/{input,output}/ (job.result_dir points at
        # the OUTPUT subdir, NOT this parent — don't derive paths from it). Everything hangs off here.
        return self._job_root / job.job_id

    def _input_path(self, job: Job) -> Path:
        # ingress spools the sample to <job_root>/<id>/input/<filename>. Path(...).name strips any
        # directory components a non-ingress producer left in `filename`, so the join (and the
        # finally-block unlink) can never escape the job's own input/ dir.
        return self._job_dir(job) / "input" / Path(job.filename).name

    def _expiry(self, finished_at: float) -> float | None:
        return finished_at + self._retention_s if self._retention_s > 0 else None

    def _ensure_metadata(self, job: Job, summary: dict | None) -> bool:
        """Write ``<output>/metadata.json`` from the validate() summary. Called BEFORE the terminal
        CAS so DONE is never observable without it (the ingress ``/metadata``/``/artifacts``/
        ``/result`` routes gate on DONE then require the file). ATOMIC (tmp + replace) and OVERWRITES,
        so a reclaim race resolves to the LAST validation's metadata — the DONE-winner wrote its own
        before winning, and a stale loser's file is replaced by the next owner. Returns whether it
        wrote (False on an I/O hiccup — the authoritative result is the stored ``result_summary``).

        SECURITY: force ``artifacts: []``. The ingress treats metadata.json's artifact list as
        dispatcher-VALIDATED (re-hashed by the host trust gate), and drives ``/artifacts``/``/result``
        file serving off it. A VM ``validate()`` summary is NOT that — it never went through the trust
        gate — so an ``artifacts`` list in it (guest-influenced) must never make unsealed output files
        downloadable. We surface the summary as the metadata body but neuter its artifact manifest."""
        out = self._job_dir(job) / "output"
        try:
            out.mkdir(parents=True, exist_ok=True)
            tmp = out / "metadata.json.tmp"
            tmp.write_text(json.dumps({**(summary or {}), "artifacts": []}))
            tmp.replace(out / "metadata.json")   # atomic publish
            return True
        except OSError:
            logger.warning("vm_dispatch: could not write metadata.json for %s (result routes may "
                           "404)", job.job_id, exc_info=True)
            return False

    def _validate_with_heartbeat(self, job: Job, in_path: Path) -> tuple[dict | None, bool]:
        """Run ``validate()`` while a daemon thread refreshes the job's ``started_at`` every
        ``heartbeat_s``. A VM validation can legitimately outrun a peer's warm-recovery cutoff
        (``worker_timeout_s + grace``); without the heartbeat that sweep would FAIL the still-running
        job as abandoned and delete its input before our terminal CAS. The refresh is CAS-fenced on
        our claim, so it no-ops harmlessly if the job was reclaimed."""
        beat = threading.Event()

        def _pump() -> None:
            while not beat.wait(self._heartbeat_s):
                self._store.update_if_status(job.job_id, JobStatus.RUNNING,
                                             expect_claim_id=job.claim_id, started_at=time.time())

        hb = threading.Thread(target=_pump, name=f"vmhb-{job.job_id[:8]}", daemon=True)
        hb.start()
        try:
            return self._validate(in_path)
        finally:
            beat.set()
            hb.join(timeout=2)

    def _claim_is_ours(self, job: Job) -> bool:
        """True if we should run this claimed job. ``claim_next(engine=)`` already filters at the
        store, so this is a DEFENSIVE fallback: if a store ignored the filter and handed us another
        engine's job, requeue it (CAS back to QUEUED, claim cleared) and return ``False`` so the
        right dispatcher picks it up. ``engine=None`` = any engine (no scoping)."""
        if self._engine is None or job.engine == self._engine:
            return True
        self._store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                                     status=JobStatus.QUEUED, claim_id=None, started_at=None)
        return False

    def _process(self, job: Job) -> None:
        # Mark the in-flight job as a warm worker BEFORE the (possibly long) validate, so a peer's
        # requeue_orphaned_jobs sweep — which treats a RUNNING job with worker_runtime != "warm" as a
        # dead COLD Docker job and requeues it — doesn't re-detonate it under us. The CAS is also our
        # OWNERSHIP fence: if it returns False the job was reclaimed since we claimed it, so STOP here
        # (don't validate someone else's job / write output another owner now controls).
        if not self._store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                                            worker_runtime="warm", worker_tier=self._worker_tier):
            logger.info("vm_dispatch: job %s reclaimed before validate; skipping", job.job_id)
            return
        in_path = self._input_path(job)
        owned = False
        try:
            if not in_path.exists():
                raise FileNotFoundError(f"spooled input missing: {in_path}")
            summary, ok = self._validate_with_heartbeat(job, in_path)
            # Materialize metadata.json BEFORE the DONE CAS: the ingress result routes gate on DONE and
            # then require the file, so DONE must never be observable (by a poller, or after a crash in
            # this window) without it. The write is atomic + overwriting, so a reclaim race resolves to
            # the last validation's metadata (the DONE-winner wrote its own just before winning).
            if ok:
                self._ensure_metadata(job, summary)
            finished = time.time()
            # CAS on (status, claim_id) so a stale owner can't clobber a job that was reclaimed
            # (RUNNING->QUEUED->RUNNING under another dispatcher). The return value is OUR ownership.
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.DONE if ok else JobStatus.FAILED,
                finished_at=finished, result_summary=summary, expires_at=self._expiry(finished))
        except Exception as exc:  # noqa: BLE001 — one bad job must not sink the dispatcher
            logger.warning("vm_dispatch: job %s failed: %s", job.job_id, exc, exc_info=True)
            finished = time.time()
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.FAILED, finished_at=finished, error=type(exc).__name__,
                expires_at=self._expiry(finished))
        finally:
            # Drop the spooled input ONLY if WE still own the job (terminal write applied). If it was
            # reclaimed, the CAS returned False and the input now belongs to the new owner — leave it.
            if owned:
                try:  # the sample is consumed; drop the spooled input (keep any sealed output)
                    in_path.unlink()
                except OSError:
                    pass

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                # Engine-scoped + tier-scoped claim: the store filters to our engine (so we never
                # claim+requeue another engine's head job and HOL-block our own work) AND honours
                # target_tier — a job tagged target_tier=<worker_tier> (e.g. "libvirt-vm") is claimed
                # here, not by the cold dispatcher, while untargeted jobs are still claimable by anyone.
                job = self._store.claim_next(claimant_tier=self._worker_tier, engine=self._engine)
            except Exception:  # noqa: BLE001 — a transient store error must not kill the loop
                logger.warning("vm_dispatch: claim_next failed", exc_info=True)
                job = None
            if job is None:
                self._stop.wait(self._poll_s)
                continue
            if not self._claim_is_ours(job):
                # Defensive: a store that ignores the engine= filter could still hand us a foreign
                # job — requeue it for the right dispatcher and back off (shouldn't normally happen).
                self._stop.wait(self._poll_s)
                continue
            try:
                self._process(job)
            except Exception:  # noqa: BLE001 — a crash in _process must not kill the claim thread
                logger.warning("vm_dispatch: _process crashed for %s", job.job_id, exc_info=True)

    def _run_maintenance(self) -> None:
        """Periodic upkeep a VM-only deployment otherwise lacks (the container Dispatcher does its own):
        reclaim terminal job dirs past ``expires_at`` (retention), and FAIL orphaned RUNNING jobs whose
        heartbeat went stale because the dispatcher that claimed them crashed (so they don't sit
        RUNNING forever with their input on disk). Orphan recovery is CAS-fenced on the observed claim
        (won't clobber a reclaimed job) and scoped to our engine; we FAIL (never requeue) — a requeue
        would let a second worker re-detonate the same untrusted input."""
        try:
            self._retention.expire_due(self._store)
        except Exception:  # noqa: BLE001 — a sweep failure must not kill maintenance
            logger.warning("vm_dispatch: retention sweep failed", exc_info=True)
        try:
            cutoff = time.time() - self._orphan_timeout_s
            for job in self._store.list(status=JobStatus.RUNNING):
                if self._engine is not None and job.engine != self._engine:
                    continue
                # Recover jobs a VM dispatcher of OUR tier owns (worker_runtime="warm" + matching
                # worker_tier, both set by _process). In a SHARED store a long COLD/container job for
                # the same engine has worker_runtime=None/"runc" — its Docker worker may still be
                # running, so failing it would be a cross-tier clobber. EXCEPT when sole_owner: then
                # there's no cold dispatcher, so also reclaim an unmarked claim that crashed before the
                # warm stamp (it would otherwise be stuck RUNNING forever).
                if not self._sole_owner and (
                        job.worker_runtime != "warm" or job.worker_tier != self._worker_tier):
                    continue
                if job.started_at is None or job.started_at >= cutoff:
                    continue  # fresh (heartbeat-refreshed) → still alive
                now = time.time()
                if self._store.update_if_status(
                        job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                        status=JobStatus.FAILED, finished_at=now, error="orphaned",
                        expires_at=self._expiry(now)):
                    logger.warning("vm_dispatch: recovered orphaned job %s (no heartbeat >%.0fs)",
                                   job.job_id, self._orphan_timeout_s)
                    try:  # the owner is gone + the job is terminal; drop its leaked input
                        self._input_path(job).unlink()
                    except OSError:
                        pass
        except Exception:  # noqa: BLE001
            logger.warning("vm_dispatch: orphan recovery failed", exc_info=True)

    def _maintenance_loop(self) -> None:
        while not self._stop.wait(self._maintenance_interval_s):
            self._run_maintenance()

    def run(self) -> None:
        """Block, claiming + processing jobs on ``concurrency`` threads until :meth:`stop`. Also runs
        periodic maintenance (retention + orphan recovery) so a VM-only deployment doesn't accumulate
        terminal output dirs / leave crashed claims RUNNING forever."""
        logger.info("vm_dispatch: claiming from %s (%d workers)", type(self._store).__name__,
                    self._concurrency)
        with ThreadPoolExecutor(max_workers=self._concurrency + 1, thread_name_prefix="vmclaim") as ex:
            for _ in range(self._concurrency):
                ex.submit(self._worker_loop)
            if self._maintenance_interval_s > 0:
                ex.submit(self._maintenance_loop)
            self._stop.wait()

    def stop(self, *_: object) -> None:
        self._stop.set()
