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
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from blastbox.contract.envelope import atomic_write_confined
from blastbox.host.jobs.base import Job, JobStatus, JobStore
from blastbox.host.jobs.retention import JobRetentionSweeper

# Cap a VM validate() summary before it's stored as result_summary / written to metadata.json — a
# compromised/buggy VM agent could otherwise return a huge nested blob that balloons the DB/Redis
# value and every status/list response for the job.
_MAX_SUMMARY_BYTES = 256 * 1024

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
                 orphan_timeout_s: float = 600.0, sole_owner: bool = False,
                 validate_timeout_s: float = 1800.0,
                 max_summary_bytes: int = _MAX_SUMMARY_BYTES) -> None:
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
        # Bound a hung validate() so a dead VM agent can't occupy a claim thread forever (heartbeat
        # would keep the job looking fresh, so the orphan sweep never recovers it).
        self._validate_timeout_s = max(self._heartbeat_s, float(validate_timeout_s))
        self._max_summary_bytes = max(1024, int(max_summary_bytes))
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

    def _bounded_summary(self, summary: dict | None) -> dict | None:
        """Cap an untrusted VM summary so it can't balloon the store / every status response. Returns
        a small marker if it's unserializable or exceeds ``max_summary_bytes``."""
        if summary is None:
            return None
        try:
            n = len(json.dumps(summary))
        except (TypeError, ValueError):
            return {"error": "unserializable_summary"}
        if n > self._max_summary_bytes:
            return {"error": "summary_too_large", "summary_bytes": n}
        return summary

    def _stage_metadata(self, job: Job, summary: dict | None) -> str | None:
        """Write metadata to a confined, claim-specific STAGING file (not yet published). Confined +
        symlink-safe (atomic_write_confined: random O_EXCL|O_NOFOLLOW temp under a dir fd), so a
        prior untrusted attempt's planted symlink in output/ can't redirect the host write. Returns
        the staged file's name, or None on failure.

        SECURITY: force ``artifacts: []`` — the ingress treats metadata.json's artifact list as
        host-trust-gate-validated and serves files off it; a VM summary's (guest-influenced) artifact
        list never went through the gate, so it must never make unsealed output downloadable."""
        out = self._job_dir(job) / "output"
        name = f".metadata.{job.claim_id or 'x'}.staged"
        try:
            out.mkdir(parents=True, exist_ok=True)
            data = json.dumps({**(summary or {}), "artifacts": []}).encode()
            atomic_write_confined(out, name, data, mode=0o644)
            return name
        except OSError:
            logger.warning("vm_dispatch: could not stage metadata.json for %s", job.job_id,
                           exc_info=True)
            return None

    def _publish_or_discard_metadata(self, job: Job, staged: str, *, publish: bool) -> None:
        """Atomically rename the staged metadata into ``metadata.json`` (ONLY when our terminal CAS
        won — so a stale loser never overwrites the DONE-winner's file), else discard it. The rename
        is confined (renameat under the output dir fd) and clobbers any planted ``metadata.json``
        symlink at the destination."""
        out = self._job_dir(job) / "output"
        try:
            dir_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            if publish:
                os.replace(staged, "metadata.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            else:
                try:
                    os.unlink(staged, dir_fd=dir_fd)
                except OSError:
                    pass
        except OSError:
            logger.warning("vm_dispatch: could not %s metadata for %s",
                           "publish" if publish else "discard", job.job_id, exc_info=True)
        finally:
            os.close(dir_fd)

    def _validate_with_heartbeat(self, job: Job, in_path: Path) -> tuple[dict | None, bool]:
        """Run ``validate()`` while a daemon thread refreshes the job's ``started_at`` every
        ``heartbeat_s``. A VM validation can legitimately outrun a peer's warm-recovery cutoff
        (``worker_timeout_s + grace``); without the heartbeat that sweep would FAIL the still-running
        job as abandoned and delete its input before our terminal CAS. The refresh is CAS-fenced on
        our claim, so it no-ops harmlessly if the job was reclaimed.

        Bounded by ``validate_timeout_s``: validate() runs in a daemon thread; if it hangs (dead agent
        / stuck network read) past the deadline we raise TimeoutError (→ the job FAILs) and stop
        beating, freeing this claim thread. The hung daemon thread is abandoned (Python can't kill a
        thread) — the engine's validate() should also use its own socket timeouts."""
        beat = threading.Event()

        def _pump() -> None:
            while not beat.wait(self._heartbeat_s):
                self._store.update_if_status(job.job_id, JobStatus.RUNNING,
                                             expect_claim_id=job.claim_id, started_at=time.time())

        result: dict[str, object] = {}

        def _run() -> None:
            try:
                result["v"] = self._validate(in_path)
            except BaseException as exc:  # noqa: BLE001 — surfaced to the caller below
                result["e"] = exc

        hb = threading.Thread(target=_pump, name=f"vmhb-{job.job_id[:8]}", daemon=True)
        vt = threading.Thread(target=_run, name=f"vmval-{job.job_id[:8]}", daemon=True)
        hb.start()
        vt.start()
        try:
            vt.join(timeout=self._validate_timeout_s)
            if vt.is_alive():
                raise TimeoutError(f"validate() exceeded {self._validate_timeout_s:.0f}s "
                                   "(hung VM agent?)")
            if "e" in result:
                raise result["e"]  # type: ignore[misc]
            return result["v"]  # type: ignore[return-value]
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
            summary = self._bounded_summary(summary)   # cap untrusted summary before store/metadata
            # STAGE metadata.json (confined) before the CAS so its bytes are ready, then PUBLISH it
            # only if WE win the terminal CAS — satisfies both "DONE must imply metadata exists" (the
            # publish is a single renameat right after the winning CAS) and "only the winning claim's
            # metadata is served" (a stale loser discards its staged file, never overwriting the
            # winner's). A loser's CAS fails below and we discard.
            staged = self._stage_metadata(job, summary) if ok else None
            finished = time.time()
            # CAS on (status, claim_id) so a stale owner can't clobber a job that was reclaimed
            # (RUNNING->QUEUED->RUNNING under another dispatcher). The return value is OUR ownership.
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.DONE if ok else JobStatus.FAILED,
                finished_at=finished, result_summary=summary, expires_at=self._expiry(finished))
            if staged is not None:
                self._publish_or_discard_metadata(job, staged, publish=owned)
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
