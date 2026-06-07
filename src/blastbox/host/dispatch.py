"""Host orchestrator dispatcher — claim a queued job, run a disposable worker
container, validate output through the trust gate, record the result, and delete
the malicious input.

Security properties (review will check):
1. The worker image is ALWAYS derived from ``engines[job.engine].image`` —
   never from any job field (engine name, filename, params).  A malicious job
   cannot select an arbitrary image.
2. Output is validated through ``trust.validate_worker_output`` BEFORE the job
   is marked DONE.  A worker that writes a traversal/tampered/oversized
   metadata.json produces FAILED, not DONE.
3. Input is deleted on EVERY terminal path (success, failure, timeout, launch
   error, unknown engine, insecure runtime) via a ``finally`` block.
4. ``job.params`` → ``extra_env`` only for keys matching ``^[A-Z][A-Z0-9_]*$``
   with length-capped values; never raw.
5. All error strings stored on the job pass through ``sanitize_public_error``.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping

from blastbox.contract.envelope import (
    atomic_write_confined,
    confined_atomic_writer,
    open_confined_regular_fd,
)
from blastbox.errors import OutputTrustError, WarmTimeout, sanitize_public_error
from blastbox.host.jobs.base import Job, JobStatus, JobStore
from blastbox.host.runtime.docker import (
    RuntimeSelection,
    build_worker_docker_run_argv,
    select_worker_runtime,
)
from blastbox.host.trust import validate_worker_output
from blastbox.limits import Limits
from blastbox.observability.metrics import (
    observe_job_duration,
    record_job_dispatched,
    record_warm_claim,
)
from blastbox.worker.warm import HostWarmControl, WarmJobSpec

if TYPE_CHECKING:
    from blastbox.host.pool import Slot, WarmPool


_log = logging.getLogger("blastbox.host.dispatch")

# Maximum length for a validated env-var value derived from job.params.
_MAX_ENV_VALUE_LEN = 4096

# Pattern for valid extra_env keys derived from job.params.
# Must start with an uppercase letter, contain only uppercase letters, digits,
# and underscores.  This prevents any lowercase/symbol injection.
_VALID_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

# Max number of entries (files + dirs) allowed in a worker output dir — bounds inode + walk-time
# exhaustion from undeclared files even under the byte cap.
_MAX_OUTPUT_ENTRIES = 65536


@dataclass(frozen=True)
class EngineSpec:
    """Operator-configured description of one detonation engine.

    ``image`` is the worker container image.  **It must never be derived from
    job data** — only an operator can configure this.
    ``worker_argv`` is the command run inside the container.
    """

    name: str
    image: str
    worker_argv: list[str]


class Dispatcher:
    """Claim queued jobs and execute each in a disposable worker container.

    ``runtime_selector`` and ``subprocess_runner`` are injectable for testing
    — no Docker daemon is required in the test suite.
    """

    def __init__(
        self,
        *,
        job_store: JobStore,
        engines: Mapping[str, EngineSpec],
        limits: Limits,
        job_root: Path,
        runtime_selector: Callable[[], RuntimeSelection] = select_worker_runtime,
        subprocess_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        worker_timeout_s: int = 300,
        job_retention_seconds: int = 0,
        pool: "WarmPool | None" = None,
        warm_claim_timeout_s: float = 2.0,
        requeue_grace_s: float = 60.0,
    ) -> None:
        self._job_store = job_store
        # engines is kept as an immutable mapping snapshot so callers cannot
        # mutate it after construction.
        self._engines: dict[str, EngineSpec] = dict(engines)
        self._limits = limits
        self._job_root = Path(job_root)
        self._runtime_selector = runtime_selector
        self._subprocess_runner = subprocess_runner
        self._worker_timeout_s = max(1, int(worker_timeout_s))
        self._job_retention_seconds = max(0, int(job_retention_seconds))
        self._pool = pool
        self._warm_claim_timeout_s = float(warm_claim_timeout_s)
        self._requeue_grace_s = max(0.0, float(requeue_grace_s))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch_once(self) -> bool:
        """Claim and dispatch the next queued job.

        Returns True if a job was claimed, False if the queue was empty.
        """
        job = self._job_store.claim_next()
        if job is None:
            return False
        self._dispatch_claimed_job(job)
        return True

    def run_forever(
        self,
        *,
        poll_interval_s: float = 1.0,
        stop: Callable[[], bool] | None = None,
        maintenance_interval_s: float = 60.0,
    ) -> None:
        """Continuously claim and dispatch jobs until ``stop()`` returns True.

        Every ``maintenance_interval_s`` it also runs _run_maintenance: requeue orphaned RUNNING
        jobs (crash recovery) and expire retention-due artifacts (so untrusted output doesn't
        accumulate forever). Set ``maintenance_interval_s<=0`` to disable.
        """
        last_maint = time.monotonic()
        while True:
            if stop is not None and stop():
                break
            try:
                progressed = self.dispatch_once()
            except Exception:  # noqa: BLE001
                # A transient store/dispatch error must not crash the loop. Any
                # job claimed before the error is left RUNNING with its input
                # already deleted by the dispatch finally; requeue_orphaned_jobs
                # returns it to the queue. Log and keep serving.
                _log.exception("dispatch_once failed; continuing")
                progressed = False
            if maintenance_interval_s > 0 and time.monotonic() - last_maint >= maintenance_interval_s:
                last_maint = time.monotonic()
                self._run_maintenance()
            if not progressed:
                time.sleep(poll_interval_s)

    def requeue_orphaned_jobs(self, *, exclude: frozenset[str] | None = None) -> int:
        """Re-queue RUNNING jobs whose worker container is no longer alive.

        Uses ``docker ps --filter label=blastbox.role=worker`` to determine
        which worker containers are still running.  On any ``docker ps`` failure
        the method returns 0 without modifying any jobs (fail-safe: never
        accidentally requeue a job that is still live).

        WARM-tier jobs (worker_runtime == "warm") are NEVER requeued here: a warm
        slot is a runsc/Firecracker sandbox with no docker label, so ``docker ps``
        can't attest its liveness at any age — requeuing one off this cold-only
        signal would double-detonate a LIVE warm job under a multi-dispatcher
        topology. They are bounded by worker_timeout_s + the owning dispatcher's
        pool; a crashed warm dispatcher's jobs are recovered by timeout/retention,
        not this docker-ps sweep.

        ``exclude`` is an optional set of job_ids to skip (claimed in-process
        this tick).
        """
        active_job_ids = self._list_active_worker_job_ids()
        if active_job_ids is None:
            # docker ps failed — don't touch anything
            return 0

        excluded = exclude or frozenset()
        grace_cutoff = time.time() - self._requeue_grace_s
        recovered = 0
        for job in self._job_store.list(status=JobStatus.RUNNING):
            if job.job_id in excluded or job.job_id in active_job_ids:
                continue
            # Warm slots carry no docker label, so docker ps can never confirm their liveness;
            # never requeue them off this cold-only signal (would double-detonate a live one).
            if job.worker_runtime == "warm":
                continue
            # Grace window: a just-claimed job's worker container may not appear in `docker ps`
            # yet, so requeuing it now would double-detonate the same (malicious) input in two
            # workers. Only requeue jobs whose started_at is older than the grace window.
            if job.started_at is not None and job.started_at > grace_cutoff:
                continue
            self._job_store.update(
                job.job_id,
                status=JobStatus.QUEUED,
                started_at=None,
                worker_runtime=None,
                security_warnings=[
                    *job.security_warnings,
                    "requeued: worker container disappeared",
                ],
                error=None,
            )
            recovered += 1
        return recovered

    # ------------------------------------------------------------------
    # Internal dispatch flow
    # ------------------------------------------------------------------

    def _dispatch_claimed_job(self, job: Job) -> None:
        """Execute one claimed job (status is already RUNNING on entry).

        Security: input is ALWAYS deleted via a finally block — every branch
        ultimately falls into the ``finally`` at the bottom of this method.

        If a warm pool is configured, attempt to claim a slot.  On success, the
        WARM path runs.  If no slot is available (pool.claim returns None), the
        COLD path runs as a fallback.  When no pool is configured, COLD always.
        """
        root = self._job_root / job.job_id
        input_dir = root / "input"
        output_dir = root / "output"
        input_path = input_dir / Path(job.filename).name

        # Try the warm path if a pool is configured
        if self._pool is not None:
            slot = self._pool.claim(timeout_s=self._warm_claim_timeout_s)
            record_warm_claim(hit=slot is not None)
            if slot is not None:
                # WARM PATH — the slot, not input_path/output_dir, owns I/O dirs.
                # Staged input is still deleted in the finally block.
                t0 = time.monotonic()
                try:
                    self._dispatch_warm(
                        job, staged_input_path=input_path, slot=slot, output_dir=output_dir
                    )
                finally:
                    # Security: delete staged input on EVERY terminal path.
                    self._delete_input(input_path)
                    self._record_outcome(job, path="warm", started=t0)
                return
            else:
                _log.info("warm_pool_miss job_id=%s; falling back to cold path", job.job_id)

        # COLD PATH (default / fallback)
        t0 = time.monotonic()
        try:
            self._dispatch_inner(job, input_path, output_dir)
        finally:
            # Security guarantee: delete the malicious input on every path,
            # regardless of success, failure, exception, or unknown engine.
            # We never touch output/ here.
            self._delete_input(input_path)
            self._record_outcome(job, path="cold", started=t0)

    def _record_outcome(self, job: Job, *, path: str, started: float) -> None:
        """Record the dispatched-job outcome + duration (warm|cold). Read the
        final status from the store so a crash mid-dispatch counts as 'failed'."""
        final = self._job_store.get(job.job_id)
        outcome = "done" if final is not None and final.status == JobStatus.DONE else "failed"
        record_job_dispatched(path=path, outcome=outcome)
        observe_job_duration(path=path, seconds=time.monotonic() - started)

    def _dispatch_warm(
        self,
        job: Job,
        *,
        staged_input_path: Path,
        slot: "Slot",
        output_dir: Path,
    ) -> None:
        """Execute one claimed job via a pre-warmed slot.

        Security properties (same as cold path):
        1. Image/runtime are the pool's (engine-configured), NEVER job-derived.
        2. Output validated via validate_worker_output BEFORE marking DONE.
        3. Staged input + slot input copy deleted on EVERY terminal path.
        4. job.params allowlisted through _sanitize_params before forwarding.
        5. Error strings scrubbed via sanitize_public_error.
        6. slot is released exactly once in the finally block.
        """
        # The runtime's warm-path seam selects how input/output are handled: FC
        # (and other vsock runtimes) carry input over the wire and materialize
        # output via rdump; file-based runtimes copy into slot.input_dir and read
        # slot.output_dir directly. Absent the seam, the file-based path is used.
        runtime = self._pool.runtime  # type: ignore[union-attr]  # pool non-None here
        stage_fn = getattr(runtime, "stage_warm_input", None)
        control_fn = getattr(runtime, "host_warm_control", None)
        materialize_fn = getattr(runtime, "materialize_warm_output", None)

        slot_input_copy: Path | None = None
        try:
            # ------------------------------------------------------------------
            # Step 1: Engine lookup (security: engine spec is operator-configured)
            # ------------------------------------------------------------------
            engine = self._engines.get(job.engine)
            if engine is None:
                self._fail_job(job, "unknown engine")
                return

            # ------------------------------------------------------------------
            # Step 2: Stage input — over the wire (vsock) or into slot.input_dir
            # ------------------------------------------------------------------
            if callable(stage_fn):
                input_path = stage_fn(slot, staged_input_path)
            else:
                slot_input_copy = slot.input_dir / staged_input_path.name
                try:
                    shutil.copy2(staged_input_path, slot_input_copy)
                except OSError as exc:
                    self._fail_job(job, f"failed to stage input to warm slot: {exc}")
                    return
                input_path = slot_input_copy

            # ------------------------------------------------------------------
            # Step 3: Mark RUNNING with warm worker_runtime
            # ------------------------------------------------------------------
            self._job_store.update(
                job.job_id,
                worker_runtime="warm",
            )

            # ------------------------------------------------------------------
            # Step 4: Signal go to warm worker (atomic write of go.json)
            # Security: params pass through the allowlist; no job field selects
            # the slot or the slot's image.
            # ------------------------------------------------------------------
            control = (
                control_fn(slot)
                if callable(control_fn)
                else HostWarmControl(slot.control_dir)
            )
            spec = WarmJobSpec(
                input_path=input_path,
                output_dir=slot.output_dir,
                params=self._sanitize_params(job.params),
            )
            try:
                control.signal_go(spec)
            except Exception as exc:  # noqa: BLE001
                self._fail_job(job, f"failed to signal go to warm worker: {exc}")
                return

            # ------------------------------------------------------------------
            # Step 5: Wait for done signal
            # ------------------------------------------------------------------
            try:
                control.wait_for_done(timeout_s=self._worker_timeout_s)
            except WarmTimeout:
                self._fail_job(
                    job,
                    f"warm worker timed out after {self._worker_timeout_s}s",
                )
                return

            # ------------------------------------------------------------------
            # Step 5b: Materialize output into slot.output_dir (FC: rdump the ext4
            # disk; file runtimes: no seam → output is already in slot.output_dir).
            # ------------------------------------------------------------------
            if callable(materialize_fn):
                try:
                    materialize_fn(slot)
                except Exception as exc:  # noqa: BLE001
                    self._fail_job(job, f"failed to read warm worker output: {exc}")
                    return

            # Bound TOTAL on-disk output (declared + UNDECLARED) before trusting it. The gVisor
            # warm /out is a live 0o777 host bind mount with NO kernel size/inode quota, so a
            # compromised worker can fill job_root with undeclared files just like the cold path
            # — this closes the cold/warm asymmetry. (FC's output is already bounded by its
            # fixed-size ext4 disk, so this is a cheap no-op there.)
            #
            # KNOWN RESIDUAL (post-run gate, not a runtime quota): this rejects + reclaims
            # oversized output AFTER the worker exits, so oversized output is never trusted or
            # served. It does NOT stop a compromised worker from TRANSIENTLY filling host disk
            # DURING execution on the docker-cold + gVisor-warm tiers (bounded by worker_timeout_s,
            # then SIGKILL + reclaim; partially capped by the worker's per-file RLIMIT_FSIZE). A
            # true in-execution kernel quota isn't portable here (gVisor reads /out via this very
            # host bind — a sentry-internal tmpfs would be unreadable; docker bind sizing needs a
            # storage-driver quota). Mitigate operationally: put job_root on a project-quota'd /
            # size-capped filesystem. FC is immune (fixed ext4 disk).
            try:
                self._enforce_output_size_cap(slot.output_dir)
            except OutputTrustError as exc:
                self._fail_job(job, f"warm output too large: {exc}")
                return

            # ------------------------------------------------------------------
            # Step 6: Validate output through trust gate
            # Security: validate BEFORE marking DONE.
            # ------------------------------------------------------------------
            try:
                envelope = validate_worker_output(
                    output_dir=slot.output_dir,
                    input_sha256=job.input_sha256 or "",
                    engine=job.engine,
                    limits=self._limits,
                )
            except OutputTrustError as exc:
                self._fail_job(job, f"output trust validation failed: {exc}")
                return
            except Exception as exc:  # noqa: BLE001
                self._fail_job(job, f"unexpected trust validation error: {exc}")
                return

            # ------------------------------------------------------------------
            # Step 6b: Materialize the SEALED, validated output from the (possibly still-live)
            # slot dir into the host-only job_root output dir, re-verifying each artifact's sha.
            # This makes warm results fetchable from the API (they were validated in the slot dir,
            # which is reaped) AND makes the served bytes == the sealed shas (#5/#6 + the live-dir
            # validation residual).
            # ------------------------------------------------------------------
            try:
                self._materialize_sealed_warm_output(envelope, slot.output_dir, output_dir)
            except OutputTrustError as exc:
                self._fail_job(job, f"failed to materialize warm output: {exc}")
                return

            # ------------------------------------------------------------------
            # Step 7: Mark DONE
            # ------------------------------------------------------------------
            finished_at = time.time()
            expires_at = (
                finished_at + self._job_retention_seconds
                if self._job_retention_seconds > 0
                else None
            )
            result_summary = {
                "status": envelope.status,
                "artifact_count": len(envelope.artifacts),
                "warning_count": len(envelope.warnings),
            }
            self._job_store.update(
                job.job_id,
                status=JobStatus.DONE,
                finished_at=finished_at,
                expires_at=expires_at,
                result_summary=result_summary,
                error=None,
            )

        finally:
            # Security: release the slot on EVERY terminal path (success, trust-fail,
            # timeout, unexpected error). release() reaps+replaces — warm ≠ reuse.
            # Delete the slot's copy of the input (only the file path makes one; the
            # staged input itself is deleted by the caller on every terminal path).
            if slot_input_copy is not None:
                try:
                    slot_input_copy.unlink(missing_ok=True)
                except OSError:
                    pass
            self._pool.release(slot)  # type: ignore[union-attr]  # pool is non-None here

    def _dispatch_inner(
        self, job: Job, input_path: Path, output_dir: Path
    ) -> None:
        """Core dispatch logic.  Called from within the try/finally."""

        # ------------------------------------------------------------------
        # Step 2: Engine lookup
        # Security: image comes from engine.image, NEVER from any job field.
        # ------------------------------------------------------------------
        engine = self._engines.get(job.engine)
        if engine is None:
            self._fail_job(job, "unknown engine")
            return

        # ------------------------------------------------------------------
        # Step 3: Runtime selection
        # ------------------------------------------------------------------
        try:
            runtime = self._runtime_selector()
        except Exception as exc:  # noqa: BLE001  (incl. InsecureRuntimeRefused)
            self._fail_job(job, f"runtime selection failed: {exc}")
            return

        # Update job to RUNNING state with runtime info.
        # (claim_next already set status=RUNNING; we enrich with runtime data.)
        self._job_store.update(
            job.job_id,
            worker_runtime=runtime.runtime,
            security_warnings=list(job.security_warnings) + list(runtime.warnings),
        )

        # ------------------------------------------------------------------
        # Step 4: Build argv and launch worker container
        # Security: image is engine.image (operator-configured), never job data.
        # extra_env is filtered through _sanitize_params.
        # ------------------------------------------------------------------
        container_name = f"blastbox-worker-{job.job_id[:12]}"
        argv = build_worker_docker_run_argv(
            image=engine.image,          # NEVER job.engine / job.filename / job.params
            input_path=input_path,
            input_mount_path=f"/input/{input_path.name}",
            output_dir=output_dir,
            output_mount_path="/output",
            worker_argv=list(engine.worker_argv),
            runtime=runtime,
            container_name=container_name,
            labels={
                "blastbox.role": "worker",
                "blastbox.job_id": job.job_id,
            },
            extra_env={
                **self._sanitize_params(job.params),
                # Tell the harness where the dispatcher mounted I/O (it mounts the input file at
                # /input/<name> and output at /output; the harness defaults are /in,/out, so
                # without this the cold path is broken-as-wired). Dispatcher-set keys are merged
                # LAST so a hostile job.param can't override them.
                "BLASTBOX_INPUT_DIR": "/input",
                "BLASTBOX_OUTPUT_DIR": "/output",
            },
        )

        try:
            # Run to completion (or timeout). The worker's exit code is not the
            # authority — the trust gate below decides DONE/FAILED from the
            # re-sealed output. capture_output keeps worker stdio off our streams.
            self._subprocess_runner(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._worker_timeout_s,
            )
        except subprocess.TimeoutExpired:
            # Best-effort kill of the stuck container.
            self._kill_container(container_name)
            self._fail_job(job, f"worker timed out after {self._worker_timeout_s}s")
            return
        except Exception as exc:  # noqa: BLE001
            self._fail_job(job, f"docker launch failed: {exc}")
            return

        # Bound TOTAL on-disk output (declared + UNDECLARED) before trusting it, so a worker
        # that wrote a huge undeclared file can't exhaust job_root (#3 disk-exhaustion DoS).
        try:
            self._enforce_output_size_cap(output_dir)
        except OutputTrustError as exc:
            self._fail_job(job, f"output too large: {exc}")
            return

        # ------------------------------------------------------------------
        # Step 5: Validate output through trust gate
        # Security: validate BEFORE marking DONE.  A compromised worker cannot
        # cause a DONE status by writing a bad metadata.json.
        # ------------------------------------------------------------------
        # For non-zero exit with no valid output, fail the job.
        # We attempt validation regardless of exit code — a zero-exit with bad
        # output also fails.  A non-zero exit that somehow produced valid output
        # still results in DONE (the trust gate is the arbiter).
        try:
            envelope = validate_worker_output(
                output_dir=output_dir,
                input_sha256=job.input_sha256 or "",
                engine=job.engine,
                limits=self._limits,
            )
        except OutputTrustError as exc:
            # Scrub the message before storing it.
            self._fail_job(job, f"output trust validation failed: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            self._fail_job(job, f"unexpected trust validation error: {exc}")
            return

        # Persist the host-SEALED metadata over the worker's raw file so the API serves trusted
        # hashes/sizes/payload, not worker-fabricated ones (#5).
        self._write_sealed_metadata(envelope, output_dir)

        # Note: a non-zero worker exit with *no* valid output is already FAILED
        # via the OutputTrustError branch above (missing/invalid metadata.json
        # raises). A non-zero exit WITH valid, trust-passing output is treated as
        # DONE — the re-sealed output is what we trust, not the exit code.
        # ------------------------------------------------------------------
        # Step 6: Mark DONE
        # result_summary is a small derivative of the envelope — NOT the whole
        # tree.  This keeps the job record small and avoids leaking engine
        # internals into the generic job layer.
        # ------------------------------------------------------------------
        finished_at = time.time()
        expires_at = (
            finished_at + self._job_retention_seconds
            if self._job_retention_seconds > 0
            else None
        )
        result_summary = {
            "status": envelope.status,
            "artifact_count": len(envelope.artifacts),
            "warning_count": len(envelope.warnings),
        }
        self._job_store.update(
            job.job_id,
            status=JobStatus.DONE,
            finished_at=finished_at,
            expires_at=expires_at,
            result_summary=result_summary,
            error=None,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fail_job(self, job: Job, reason: str) -> None:
        """Mark a job FAILED, scrubbing the error string before storage."""
        error = sanitize_public_error(reason)
        finished_at = time.time()
        expires_at = (
            finished_at + self._job_retention_seconds
            if self._job_retention_seconds > 0
            else None
        )
        self._job_store.update(
            job.job_id,
            status=JobStatus.FAILED,
            finished_at=finished_at,
            expires_at=expires_at,
            error=error,
        )

    def _delete_input(self, input_path: Path) -> None:
        """Delete the malicious input file and its containing input/ directory.

        Best-effort: swallows OSError so a missing file doesn't abort cleanup
        of the parent dir.
        """
        try:
            input_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            # Remove the (now-empty) input/ directory.
            input_path.parent.rmdir()
        except OSError:
            pass

    def _enforce_output_size_cap(self, output_dir: Path) -> None:
        """Reject if the TOTAL on-disk output exceeds the total-artifact cap.

        The trust gate only sums DECLARED artifacts, so a worker can write a huge UNDECLARED
        file (e.g. /output/pad.bin) that passes validation yet fills job_root. This counts every
        regular file (declared or not) and fails the job before DONE if the sum exceeds the cap.
        The cold worker is already exited (--rm) so the dir is static (no TOCTOU)."""
        cap = self._limits.max_total_artifact_bytes
        total = 0
        count = 0
        for p in output_dir.rglob("*"):
            count += 1
            # Bound entry count too: many tiny/empty files exhaust inodes + traversal time even
            # under the byte cap. Checked first so the walk itself can't run unbounded.
            if count > _MAX_OUTPUT_ENTRIES:
                raise OutputTrustError(
                    f"output entry count exceeds {_MAX_OUTPUT_ENTRIES} (inode/traversal DoS)"
                )
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                total += p.stat().st_size
            except OSError:
                continue
            if total > cap:
                raise OutputTrustError(
                    f"total output {total} bytes exceeds cap {cap} (undeclared files counted)"
                )

    def _write_sealed_metadata(self, envelope, output_dir: Path) -> None:
        """Overwrite metadata.json with the host-SEALED envelope (recomputed sha256/bytes/payload)
        atomically AND symlink-safely, so the API serves host-trusted metadata — not the raw
        worker file. atomic_write_confined uses a random O_EXCL|O_NOFOLLOW temp + renameat, so a
        worker that pre-planted .metadata.json.tmp (or metadata.json) as a symlink can't redirect
        the host write to clobber an outside file."""
        data = envelope.model_dump_json(by_alias=True).encode("utf-8")
        # 0o644: in compose mode the API serves this from a separate process/uid than the
        # dispatcher that writes it; 0o600 would make /metadata + /result unreadable. Not secret.
        atomic_write_confined(output_dir, "metadata.json", data, mode=0o644)

    def _materialize_sealed_warm_output(self, envelope, src_dir: Path, dst_dir: Path) -> None:
        """Copy the validated declared artifacts from the warm slot dir (``src_dir``, possibly a
        still-live bind mount) into the host-only job_root output dir (``dst_dir``) using
        TOCTOU-safe reads, RE-VERIFYING each artifact's sha against the sealed envelope (so a
        mid-flight content swap is detected and fails the job), then writing the sealed
        metadata.json. After this the API serves a stable, host-trusted copy — closing both the
        'warm results unreachable' gap and the live-dir validation residual.

        ``dst_dir`` is job_root/<id>/output — the SAME dir a prior COLD attempt of this job
        bind-mounts writable into the untrusted worker (a requeue after a cold crash reuses it),
        so it can contain worker-planted symlinks. We therefore (1) wipe+recreate it (rmtree
        unlinks symlinks, never follows them) and (2) write each artifact via confined_atomic_writer
        (per-segment O_NOFOLLOW walk + O_EXCL temp + renameat) — exactly the symlink defence the
        sibling metadata write already uses — so a planted symlink can never redirect a
        host-trusted write to clobber a file outside dst_dir."""
        shutil.rmtree(dst_dir, ignore_errors=True)
        dst_dir.mkdir(parents=True, exist_ok=True)
        for a in envelope.artifacts:
            fd = open_confined_regular_fd(src_dir, a.path)
            digest = hashlib.sha256()
            n = 0
            try:
                with confined_atomic_writer(dst_dir, a.path, mode=0o644) as out_fd:
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        n += len(chunk)
                        # Cap the copy at the sealed size — a still-live worker growing the file
                        # past its declared bytes can't force unbounded host I/O (#4).
                        if n > a.bytes:
                            raise OutputTrustError(
                                f"artifact {a.id} grew past {a.bytes} bytes during materialization"
                            )
                        digest.update(chunk)
                        mv = memoryview(chunk)
                        while mv:
                            mv = mv[os.write(out_fd, mv):]
                    # Re-verify INSIDE the writer ctx: a mismatch raises -> the temp is unlinked
                    # and nothing is published (no partial/forged artifact ever lands in dst_dir).
                    if digest.hexdigest() != a.sha256 or n != a.bytes:
                        raise OutputTrustError(
                            f"artifact {a.id} changed during materialization (live-dir swap)"
                        )
            finally:
                os.close(fd)
        self._write_sealed_metadata(envelope, dst_dir)

    def _run_maintenance(self) -> None:
        """Periodic upkeep from run_forever: requeue jobs whose worker vanished (so a crash
        mid-dispatch doesn't strand a RUNNING zombie forever) and expire retention-due artifacts
        (so output of untrusted documents doesn't accumulate on disk forever)."""
        try:
            self.requeue_orphaned_jobs()
        except Exception:  # noqa: BLE001
            _log.exception("requeue_orphaned_jobs failed")
        if self._job_retention_seconds > 0:
            try:
                from blastbox.host.jobs.retention import JobRetentionSweeper

                expired = JobRetentionSweeper(self._job_root).expire_due(self._job_store)
                if expired:
                    _log.info("retention_sweep_expired count=%d", len(expired))
            except Exception:  # noqa: BLE001
                _log.exception("retention sweep failed")

    def _kill_container(self, container_name: str) -> None:
        """Best-effort ``docker kill`` on a timed-out worker."""
        try:
            self._subprocess_runner(
                ["docker", "kill", container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:  # noqa: BLE001
            pass

    def _list_active_worker_job_ids(self) -> set[str] | None:
        """Query docker ps for worker containers and return their job IDs.

        Returns None on any failure (caller treats None as "don't requeue").
        """
        try:
            proc = self._subprocess_runner(
                [
                    "docker",
                    "ps",
                    "--filter",
                    "label=blastbox.role=worker",
                    "--format",
                    '{{.Label "blastbox.job_id"}}',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:  # noqa: BLE001
            return None
        if proc.returncode != 0:
            return None
        # Parse lines of the form "blastbox.job_id=<uuid>" or just "<uuid>"
        # depending on the docker version / format string.
        job_ids: set[str] = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Handle "blastbox.job_id=<uuid>" format (from some docker versions)
            if "=" in line:
                line = line.split("=", 1)[1].strip()
            job_ids.add(line)
        return job_ids

    @staticmethod
    def _sanitize_params(params: dict[str, str]) -> dict[str, str]:
        """Filter job.params to a safe subset suitable for extra_env.

        Security:
        - Keys must match ``^[A-Z][A-Z0-9_]*$`` (uppercase start, no symbols).
          A key like ``"x; --privileged"`` is silently dropped.
        - Values are capped at _MAX_ENV_VALUE_LEN characters.
        - Everything is coerced to str before inclusion.

        Returns a new dict; never modifies params in place.
        """
        out: dict[str, str] = {}
        for key, value in (params or {}).items():
            if not isinstance(key, str):
                continue
            if not _VALID_ENV_KEY_RE.match(key):
                _log.debug("dropping invalid extra_env key: %r", key)
                continue
            str_val = str(value) if value is not None else ""
            if len(str_val) > _MAX_ENV_VALUE_LEN:
                _log.debug(
                    "truncating extra_env value for key %r to %d chars",
                    key,
                    _MAX_ENV_VALUE_LEN,
                )
                str_val = str_val[:_MAX_ENV_VALUE_LEN]
            out[key] = str_val
        return out
