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
import contextlib
import inspect
import logging
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from blastbox.host.pool import release_kwargs
from blastbox.contract.envelope import atomic_write_confined
from blastbox.host.blobs.base import BlobFetchError, BlobStore, upload_output_with_retry
from blastbox.host.jobs.base import Job, JobStatus, JobStore
from blastbox.host.jobs.retention import (
    JobRetentionSweeper,
    purge_job_dir,
    reap_stale_scratch,
)
from blastbox.host.runtime.remote_http import WorkerBusy   # 409 from a busy worker -> requeue, not fail
from blastbox.observability.metrics import (
    observe_job_duration,
    record_job_dispatched,
    record_warm_claim,
)

# Cap a VM validate() summary before it's stored as result_summary / written to metadata.json — a
# compromised/buggy VM agent could otherwise return a huge nested blob that balloons the DB/Redis
# value and every status/list response for the job.
_MAX_SUMMARY_BYTES = 256 * 1024

# Bound the release-on-BlobFetchError loop (Task 4/5): a TRANSIENT fetch failure (this worker's
# connectivity) should release the claim and let another node try. But a PERMANENTLY missing
# sample (deleted/never-written blob) would otherwise release -> reclaim -> release forever with
# no terminal state. Once a job's materialise_attempts reaches this ceiling, the dispatcher marks
# it FAILED instead of releasing again.
MAX_MATERIALISE_ATTEMPTS = 3

# Bound the inline put_output retry (Finding D1). The detonation already ran and its
# result is sitting on disk right now, while this worker still holds the claim -- a
# transient upload failure (a momentary object-store blip) deserves a real, bounded,
# IN-LINE chance to succeed. There is deliberately no "leave it RUNNING for later"
# fallback: nothing ever re-runs a RUNNING job, so once every attempt is exhausted the
# job FAILs and its dir is purged like every other terminal path -- see _process.
PUT_OUTPUT_MAX_ATTEMPTS = 3
PUT_OUTPUT_RETRY_BACKOFF_S = 1.0




logger = logging.getLogger(__name__)


class NoWarmSlot(RuntimeError):
    """No warm slot was available to run a claimed job. The dispatcher REQUEUES the job (it never ran)
    instead of FAILing it, so it waits for a slot / another dispatcher rather than burning a job on
    transient capacity pressure."""


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
                 fixed_net_policy: str | None = None,
                 engine_net_policy: str | None = None,
                 trust_output_metadata: bool = False,
                 sanitize_params: Callable[[dict[str, str]], dict[str, str]] | None = None,
                 output_validator: Callable[[Job, Path], None] | None = None,
                 max_queued_age_s: float = 0.0,
                 max_summary_bytes: int = _MAX_SUMMARY_BYTES,
                 blob_store: BlobStore | None = None,
                 blob_retry_backoff_s: float = 30.0,
                 put_output_max_attempts: int = PUT_OUTPUT_MAX_ATTEMPTS,
                 put_output_retry_backoff_s: float = PUT_OUTPUT_RETRY_BACKOFF_S) -> None:
        self._store = store
        self._job_root = Path(job_root)
        self._validate = validate
        # When the transport itself sealed + wrote output/metadata.json (the remote_http path: the
        # http_agent runs run_detonation which re-hashes artifacts from disk, and the HOST extracts the
        # tar traversal-safe), that file is a trustworthy sealed envelope -- preserve it (with its
        # artifact list) instead of clobbering it to artifacts:[]. False = the libvirt-VM path, where the
        # summary is guest-influenced and artifacts MUST be forced empty.
        self._trust_output_metadata = trust_output_metadata
        # Optional per-job param gate (built from the engine's allowlist by the caller): the sanitized
        # subset is passed to a validate() that accepts a `params` kwarg (the remote_http seam), so a
        # network-endpoint job honors per-job toggles (OCR/QR) just like the local worker.
        self._sanitize = sanitize_params
        # Host trust gate for output already on disk (remote_http path): re-seal + verify engine, input
        # SHA, artifact hashes, caps before DONE. Raises to fail the job. None = no gate (libvirt-vm
        # returns an in-memory summary, not on-disk artifacts, so the summary-neuter is the control).
        self._output_validator = output_validator
        try:
            import inspect
            _params = inspect.signature(validate).parameters
            self._validate_takes_params = "params" in _params
            # the remote transport's trust gate compares against the AUTHORITATIVE ingress-recorded
            # input SHA (not a recompute of the staged file) -> pass job.input_sha256 when accepted.
            self._validate_takes_input_sha = "input_sha256" in _params
            # ownership predicate so the transport can fence its metadata write by our still-held claim.
            self._validate_takes_owns = "owns" in _params
        except (TypeError, ValueError):
            self._validate_takes_params = False
            self._validate_takes_input_sha = False
            self._validate_takes_owns = False
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
        # Opt-in ceiling (0 = off) on how long a job may sit QUEUED before this dispatcher's maintenance
        # FAILs it + deletes its input. In a remote-only (static/AWS) deployment there is NO cold
        # Dispatcher to run this sweep, so a job pinned to a target_tier nobody serves (or for an engine
        # this single-engine dispatcher can't claim) would otherwise keep its untrusted input forever.
        self._max_queued_age_s = max(0.0, float(max_queued_age_s))
        # Same bound on job_root the container Dispatcher applies, and the SAME
        # implementation (jobs/retention.reap_stale_scratch). The terminal purge in _process's
        # finally covers every path this dispatcher can reach, but a SIGKILL/OOM/redeploy
        # mid-detonation reaches none of them and strands the sample plus its output forever --
        # that is exactly the #84 accumulation class, and on a remote-only (static/AWS) node
        # there is no container Dispatcher to sweep it up. BLASTBOX_SCRATCH_MAX_AGE_S was
        # documented as a global knob while only one dispatcher honoured it (#85 review).
        self._scratch_max_age_s = max(0.0, float(
            os.environ.get("BLASTBOX_SCRATCH_MAX_AGE_S", "21600") or "21600"))
        # Bound a hung validate() so a dead VM agent can't occupy a claim thread forever (heartbeat
        # would keep the job looking fresh, so the orphan sweep never recovers it).
        self._validate_timeout_s = max(self._heartbeat_s, float(validate_timeout_s))
        # The net_policy (egress personality) this pool's VMs are PROVISIONED with, or None. A warm VM
        # has a FIXED egress applied at spawn; it can't re-steer per job like the cold container path.
        # A job requesting a different policy is rejected fail-closed in _process (see there).
        self._fixed_net_policy = fixed_net_policy
        # Explicit per-dispatcher engine-default override. When None (the usual case), the engine
        # default is derived PER JOB from BLASTBOX_ENGINE_<job.engine>_NETPOLICY in _engine_default_policy
        # — so an UNSCOPED dispatcher (engine=None, the documented single-engine default) still resolves
        # each job's engine default instead of silently skipping the check.
        self._engine_net_policy = engine_net_policy
        self._max_summary_bytes = max(1024, int(max_summary_bytes))
        # Backing blob store for on-demand sample materialisation (Task 4). None (the default, and
        # every existing call site) lazily resolves BLASTBOX_BLOB_URL -- unset means LocalBlobStore, a
        # REAL filesystem-backed store rooted outside job_root (Task 9), so get_sample() can
        # re-materialise a sample this worker purged, exactly like the S3 backend. Imported here, not
        # at module scope, to mirror ingress/app.py's lazy factory import.
        if blob_store is not None:
            self._blobs = blob_store
        else:
            from blastbox.host.blobs.factory import build_blob_store_from_env

            # Task 9: LocalBlobStore derives its default blob_root FROM job_root (a sibling
            # `blobs` dir), so the factory must see the job_root THIS dispatcher actually
            # uses, not just the raw env var -- else a caller that passes an explicit
            # `job_root=` (differing from BLASTBOX_JOB_ROOT) would get a local store rooted
            # at the wrong directory, and get_sample() would raise "not present" for a
            # sample this same process's ingress just put_sample'd. Mirrors ingress/app.py's
            # build_app fix for the identical mismatch.
            self._blobs = build_blob_store_from_env(
                {**os.environ, "BLASTBOX_JOB_ROOT": str(self._job_root)}
            )
        # How long a job that just failed to fetch is deferred (claimable_after) before it's eligible
        # again -- long enough that THIS worker doesn't immediately re-claim and spin on a sample its
        # own connectivity can't reach (see the release branch in _process).
        self._blob_retry_backoff_s = max(0.0, float(blob_retry_backoff_s))
        # Bounded inline retry policy for a result upload (Finding D1) -- see the
        # module-level constants for why this is bounded and has no "retry later"
        # fallback: put_output_max_attempts tries, put_output_retry_backoff_s apart.
        self._put_output_max_attempts = max(1, int(put_output_max_attempts))
        self._put_output_retry_backoff_s = max(0.0, float(put_output_retry_backoff_s))
        # Reap result blobs alongside the on-disk dir; delete_job is scoped to
        # results/<job_id> only, so shared samples/<sha256> blobs are never touched.
        self._retention = JobRetentionSweeper(self._job_root, blob_store=self._blobs)
        self._stop = threading.Event()

    def _engine_default_policy(self, engine: str | None) -> str:
        """The engine's DEFAULT net_policy name, mirroring the cold path's ``engine.net_policy``. An
        explicit ``engine_net_policy`` ctor value wins; otherwise it's derived PER JOB from
        ``BLASTBOX_ENGINE_<engine>_NETPOLICY`` (so an unscoped dispatcher resolves each job's engine),
        defaulting to ``"none"`` (the fail-closed no-egress default) — never silently skipped."""
        if self._engine_net_policy is not None:
            return self._engine_net_policy
        name = (engine or "").upper().replace("-", "_")
        if not name:
            return "none"
        raw = os.environ.get(f"BLASTBOX_ENGINE_{name}_NETPOLICY")
        return raw.strip().lower() if raw and raw.strip() else "none"

    def _claim_is_still_ours(self, job: Job) -> bool:
        """Whether we still own the claim: the stored job is RUNNING with OUR claim_id. A best-effort
        TOCTOU narrowing for the metadata write (the store CAS fences the status update; this fences
        the unfenceable filesystem write so a reclaimed job's new owner isn't clobbered). A store read
        error is treated as "not ours" — fail closed, don't write."""
        try:
            cur = self._store.get(job.job_id)
        except Exception:  # noqa: BLE001 — a transient store error → don't risk a clobbering write
            return False
        return cur is not None and cur.status == JobStatus.RUNNING and cur.claim_id == job.claim_id

    def _job_dir(self, job: Job) -> Path:
        # The ingress canonical layout is <job_root>/<id>/{input,output}/ (job.result_dir points at
        # the OUTPUT subdir, NOT this parent — don't derive paths from it). Everything hangs off here.
        return self._job_root / job.job_id

    def _input_path(self, job: Job) -> Path:
        # ingress spools the sample to <job_root>/<id>/input/<filename>. Path(...).name strips any
        # directory components a non-ingress producer left in `filename`, so the join (and the
        # finally-block unlink) can never escape the job's own input/ dir.
        return self._job_dir(job) / "input" / Path(job.filename).name

    def _purge_job_dir(self, job: Job) -> None:
        """Remove this job's entire dir (input AND output) from THIS worker's disk.

        SECURITY INVARIANT, not housekeeping: a worker is a malware-analysis node,
        frequently spare hardware that is not a hardened sample repository. Nothing
        may survive a terminal state (or a release of this worker's claim on the
        job), and there is deliberately no setting that disables this. Best-effort
        by design — a purge failure must never mask the job's real outcome — but it
        IS logged loudly, never silently swallowed, so an operator can see a worker
        that is failing to clean up after itself.

        Containment mirrors JobRetentionSweeper._safe_rmtree (jobs/retention.py):
        resolve first, then refuse anything that doesn't land strictly under
        ``job_root`` (guards a job_id/path with traversal components).
        """
        # Delegates to the shared implementation so this invariant cannot drift between the
        # two dispatchers -- it already had, and the file-handshake path leaked forever (#84).
        purge_job_dir(self._job_root, job.job_id, logger)

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

    def _ensure_metadata(self, job: Job, summary: dict | None) -> bool:
        """Write+publish ``<output>/metadata.json`` from the summary, atomically and CONFINED
        (atomic_write_confined: a random O_EXCL|O_NOFOLLOW temp under the output dir fd, then renameat
        — a prior untrusted attempt's planted symlink in output/ can't redirect the host write, and a
        planted metadata.json symlink at the destination is clobbered, not followed). Returns whether
        it succeeded; the caller writes metadata BEFORE the DONE CAS and FAILs the job if this returns
        False, so DONE is never observable without the file. (A VM job is never requeued mid-validate
        — orphan recovery FAILs it and the cold requeue skips worker_runtime="warm" — so there's no
        concurrent owner whose metadata could race/overwrite this one.)

        SECURITY: force ``artifacts: []`` — the ingress treats metadata.json's artifact list as
        host-trust-gate-validated and serves files off it; a VM summary's (guest-influenced) artifact
        list never went through the gate, so it must never make unsealed output downloadable."""
        out = self._job_dir(job) / "output"
        try:
            out.mkdir(parents=True, exist_ok=True)
            # Remote path: the transport already sealed + wrote a trustworthy metadata.json (with the
            # real artifact list) into output/. Preserve it rather than overwriting with artifacts:[].
            if self._trust_output_metadata and (out / "metadata.json").is_file():
                return True
            data = json.dumps({**(summary or {}), "artifacts": []}).encode()
            atomic_write_confined(out, "metadata.json", data, mode=0o644)
            return True
        except OSError:
            logger.warning("vm_dispatch: could not write metadata.json for %s", job.job_id,
                           exc_info=True)
            return False

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
                try:
                    self._store.update_if_status(job.job_id, JobStatus.RUNNING,
                                                 expect_claim_id=job.claim_id, started_at=time.time())
                except Exception:  # noqa: BLE001 — a transient store error must NOT kill the heartbeat:
                    # if started_at stops refreshing, the orphan sweep would fail this still-running
                    # job and delete its input. Log and keep beating; the next tick retries.
                    logger.warning("vm_dispatch: heartbeat store update failed for %s (will retry)",
                                   job.job_id, exc_info=True)

        result: dict[str, object] = {}
        # run the sanitizer whenever it exists (even with empty job.params) so operator default_params
        # still reach the worker, matching the cold/file-warm paths.
        params = self._sanitize(dict(job.params)) if self._sanitize else None

        def _run() -> None:
            try:
                kw: dict[str, object] = {}
                if self._validate_takes_params:
                    kw["params"] = params
                if self._validate_takes_input_sha:
                    kw["input_sha256"] = job.input_sha256   # authoritative ingress SHA for the trust gate
                if self._validate_takes_owns:
                    kw["owns"] = lambda: self._claim_is_still_ours(job)   # fence the metadata write
                result["v"] = self._validate(in_path, **kw)  # type: ignore[call-arg]
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
                exc = result["e"]
                # _run captures BaseException so a validate() that raises SystemExit/GeneratorExit
                # (e.g. a sample-triggered sys.exit in the engine) can't silently kill the daemon
                # thread. But _process/_worker_loop only catch Exception, so re-raising a bare
                # BaseException would skip the FAILED write and leave the job RUNNING until orphan
                # recovery. Normalize a non-Exception BaseException into a RuntimeError so the
                # documented raising→FAILED path runs. (KeyboardInterrupt isn't delivered to this
                # daemon thread by the signal machinery, so there's no interactive shutdown to lose.)
                if isinstance(exc, Exception):
                    raise exc
                raise RuntimeError(f"validate() raised {type(exc).__name__}: {exc}")  # type: ignore[union-attr]
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
        # Fail closed on an EFFECTIVE net_policy this warm tier can't honor — BEFORE detonation. A
        # warm VM's egress is FIXED at spawn and can't be re-steered per job like the cold container
        # path. Enforcement is OPT-IN via fixed_net_policy (the egress this pool is PROVISIONED with):
        # we must NOT assume an undeclared pool is "none"/no-network, because a libvirt VM with
        # egress_policy=None is left on the (unrestricted) libvirt network, NOT --network=none — so
        # defaulting to "none" would falsely pass no-egress jobs onto a networked VM. When declared,
        # the effective policy (override → engine default → "none", mirroring resolve_net_policy) must
        # EQUAL it; "none"/"drop" (=--network=none) are enforced like any other, no skipping.
        if self._fixed_net_policy is not None:
            effective_policy = (job.net_policy or self._engine_default_policy(job.engine)
                                or "none").strip().lower()
            fixed_policy = self._fixed_net_policy.strip().lower()
        else:
            effective_policy = fixed_policy = ""  # enforcement opt-out: operator owns routing
        if effective_policy != fixed_policy:
            kind = "override" if job.net_policy else "engine-default"
            finished = time.time()
            self._store.update_if_status(
                    job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                    status=JobStatus.FAILED, finished_at=finished,
                    error=f"net_policy {effective_policy!r} ({kind}) not honored by {self._worker_tier} "
                          f"tier (fixed egress {fixed_policy!r})",
                    expires_at=self._expiry(finished))
            # Purge unconditionally, regardless of whether the FAILED CAS above won: this worker's
            # involvement with the job ends here either way. If the CAS won, this is a terminal
            # write and the purge invariant applies unconditionally (not just a bare input unlink) --
            # nothing may survive on this worker's disk, even if _process is ever reordered so this
            # check runs after materialisation/validation and output/ has content too. If the CAS
            # LOST, a peer reclaimed the job between our claim_next() and this check, so leaving the
            # spooled input here would just be orphaned malware bytes on spare hardware that no peer
            # (on another host) could ever read -- the blob store always re-materialises the sample
            # for whoever owns the job now. Mirrors the reclaim-before-validate purge just below.
            self._purge_job_dir(job)
            logger.warning("vm_dispatch: rejecting job %s — net_policy %r (%s) != fixed egress %r on %s",
                           job.job_id, effective_policy, kind, fixed_policy, self._worker_tier)
            return
        # Mark the in-flight job as a warm worker BEFORE the (possibly long) validate, so a peer's
        # requeue_orphaned_jobs sweep — which treats a RUNNING job with worker_runtime != "warm" as a
        # dead COLD Docker job and requeues it — doesn't re-detonate it under us. The CAS is also our
        # OWNERSHIP fence: if it returns False the job was reclaimed since we claimed it, so STOP here
        # (don't validate someone else's job / write output another owner now controls).
        if not self._store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                                            worker_runtime="warm", worker_tier=self._worker_tier):
            logger.info("vm_dispatch: job %s reclaimed before validate; skipping", job.job_id)
            # Purge unconditionally (Task 9): this worker's involvement with the job ends here, and
            # the blob store (real in every mode, not just S3) can always re-materialise the sample
            # for whichever node now owns it. We no longer leave the input "for the new owner" — in a
            # real fleet the new owner is on ANOTHER host, so leftovers here are just orphaned malware
            # bytes on spare hardware, not something a peer could ever read.
            self._purge_job_dir(job)
            return
        in_path = self._input_path(job)
        owned = False
        terminal_status: JobStatus | None = None   # the terminal state THIS attempt CAS-won (for metrics)
        # The `finally` purge is UNCONDITIONAL for every terminal state and every lost/released claim
        # (the security invariant: this worker is spare hardware that must not accumulate malware, and
        # the blob store always re-materialises the sample for whoever owns the job now). There is no
        # exception for a put_output failure: Finding D1 removed the earlier "leave it RUNNING for the
        # sweeper" branch (preserve_result_for_retry) because nothing ever consumes a job left that
        # way -- see the upload block below, which retries inline (bounded) and, on exhaustion, FAILs
        # the job so this purge runs like every other terminal path.
        t0 = time.monotonic()   # for the job-duration metric (parity with the cold dispatcher)
        try:
            if not in_path.exists():
                # Materialise on demand. In local mode this re-raises (there is no
                # second copy); in S3 mode it fetches and hash-verifies.
                #
                # A fetch failure RELEASES the claim instead of failing the job: the
                # object store being unreachable says something about this worker's
                # connectivity, not about the sample. Failing here would permanently
                # discard work because one node's link was down.
                if job.input_sha256 is None:
                    # No content key to fetch by -- there's nothing a blob store could
                    # materialise. Same terminal shape as before this feature existed.
                    raise FileNotFoundError(f"spooled input missing: {in_path}")
                try:
                    self._blobs.get_sample(job.input_sha256, in_path)
                except BlobFetchError:
                    attempts = job.materialise_attempts + 1
                    if attempts >= MAX_MATERIALISE_ATTEMPTS:
                        # Bounded out: this isn't a transient connectivity blip anymore --
                        # `attempts` failed materialisations in a row means the sample itself
                        # is gone (deleted / never written), and no amount of releasing will
                        # ever fetch it. FAIL terminally instead of releasing again, so the
                        # job stops looping release -> reclaim -> release forever.
                        logger.warning(
                            "vm_dispatch: job %s could not materialise its sample after "
                            "%d attempts; failing", job.job_id, attempts,
                        )
                        finished = time.time()
                        owned = self._store.update_if_status(
                            job.job_id,
                            JobStatus.RUNNING,
                            expect_claim_id=job.claim_id,
                            status=JobStatus.FAILED,
                            finished_at=finished,
                            error=f"sample could not be materialised after {attempts} attempts",
                            materialise_attempts=attempts,
                            expires_at=self._expiry(finished),
                        )
                        terminal_status = JobStatus.FAILED
                        return
                    logger.warning(
                        "vm_dispatch: job %s could not materialise its sample; "
                        "releasing the claim for another node", job.job_id,
                    )
                    # RUNNING -> QUEUED, CAS'd on (status, claim_id) so a stale owner
                    # can't clobber a job that was already RECLAIMED. claim_id is
                    # cleared so the next claim_next() stamps a fresh token.
                    #
                    # claimable_after backs the job off briefly: without it THIS worker
                    # is free to instantly re-claim the job it just failed to fetch and
                    # spin on it. created_at is deliberately untouched, so public
                    # ordering and max_queued_age still see the real submission time.
                    #
                    # materialise_attempts is persisted incremented so the counter survives
                    # the release -- it's a durable Job field (not an in-memory counter)
                    # precisely so a DIFFERENT node reclaiming this job on the next attempt
                    # still sees how many times materialisation has already failed.
                    self._store.update_if_status(
                        job.job_id,
                        JobStatus.RUNNING,
                        expect_claim_id=job.claim_id,
                        status=JobStatus.QUEUED,
                        claim_id=None,
                        claimable_after=time.time() + self._blob_retry_backoff_s,
                        materialise_attempts=attempts,
                    )
                    # Releasing the claim relinquishes THIS worker's involvement with the job; the
                    # unconditional `finally` purge (below) destroys whatever it holds (nothing should
                    # have materialised on a failed fetch, but the invariant never assumes).
                    return
                else:
                    # Finding E3: a successful fetch means this attempt's failure streak is
                    # over -- reset the counter so only CONSECUTIVE fetch failures accumulate
                    # toward MAX_MATERIALISE_ATTEMPTS, matching its "permanently missing"
                    # intent. Persisted (not just the in-memory `job`) so a LATER release/
                    # reclaim cycle (e.g. after a NoWarmSlot/WorkerBusy requeue purges this
                    # job dir and it must re-fetch) doesn't inherit an earlier, unrelated
                    # failure streak.
                    if job.materialise_attempts:
                        self._store.update_if_status(
                            job.job_id,
                            JobStatus.RUNNING,
                            expect_claim_id=job.claim_id,
                            materialise_attempts=0,
                        )
            summary, ok = self._validate_with_heartbeat(job, in_path)
            summary = self._bounded_summary(summary)   # cap untrusted summary before store/metadata
            err: str | None = None
            sealed_env: Any = None
            if ok and self._trust_output_metadata:
                # Remote path: the transport returns the FULL sealed metadata dict. Persist a COMPACT
                # result_summary (like the cold dispatcher) so list/status responses don't carry the
                # whole payload/artifacts (up to 256 KiB/job) -- the full envelope stays in metadata.json
                # for /metadata. Parse the envelope ONCE here and reuse it for page-hash indexing.
                sealed_env = self._sealed_envelope(job)
                if sealed_env is not None:
                    from blastbox.host.dispatch import _build_result_summary
                    summary = _build_result_summary(sealed_env)
            if not ok and isinstance(summary, dict):
                # a failing validate carries a coarse sanitized reason (remote transport/trust/engine)
                # so the FAILED job has an actionable error instead of a bare None.
                _e = summary.get("error")
                if isinstance(_e, str):
                    err = _e
            # Host trust gate on the extracted output BEFORE DONE: verify engine + input SHA, re-seal
            # artifact hashes from disk, enforce caps. A compromised/stale remote agent can't get a
            # wrong-input or unsealed result marked DONE.
            if ok and self._output_validator is not None:
                try:
                    self._output_validator(job, self._job_dir(job) / "output")
                except Exception as exc:  # noqa: BLE001 -- trust failure => FAIL, don't mark DONE
                    ok, err = False, f"output trust validation failed: {exc}"
                    logger.warning("vm_dispatch: job %s failed trust gate: %s", job.job_id, exc)
            # Publish metadata.json BEFORE the DONE CAS so DONE never implies a 404 on /metadata,
            # /artifacts, /result. If the write fails, FAIL the job (recoverable) rather than mark it
            # DONE-without-metadata. But re-check OWNERSHIP first: if a long validation outlived its
            # claim and a peer reclaimed+completed the job, the terminal CAS below would no-op — yet
            # the metadata WRITE is a filesystem op the CAS can't fence, so a stale owner could clobber
            # the new owner's metadata.json (served for the now-DONE job). If we no longer own the
            # claim, bail before writing — don't touch a job another dispatcher controls.
            if ok and not self._claim_is_still_ours(job):
                logger.info("vm_dispatch: job %s reclaimed during validate; not publishing metadata "
                            "or CAS (peer owns it now)", job.job_id)
                # The unconditional `finally` purge (below) destroys this worker's dir: the blob
                # store can always re-materialise this job's sample for its new owner, so there's no
                # reason to leave bytes behind on this worker's disk.
                return
            if ok and not self._ensure_metadata(job, summary):
                ok, err = False, "metadata_write_failed"
            # Upload the sealed output BEFORE the terminal CAS below -- and long before the
            # `finally` purge, which is about to delete it. Unlike a get_sample fetch failure
            # (which releases the claim because the WORK hasn't happened yet), a put_output
            # failure is the mirror image: the expensive detonation already ran and its result
            # is sitting right here. Retry is out of scope, so don't record a FAILED outcome and
            # don't let the purge erase it -- skip the terminal CAS entirely and return. The
            # store's status field is untouched (still RUNNING from the warm-stamp CAS earlier in
            # this method), `owned` stays False, so `finally` does not purge, and the reclaim
            # sweeper (or a peer) picks the job up for another attempt instead of the result being
            # silently discarded.
            #
            # But put_output writes to a deterministic per-job key (results/<job_id>/...) as a
            # per-file overwrite/union -- it is NOT a claim-fenced atomic swap the way the store's
            # CAS is. If our claim was reclaimed since the `_claim_is_still_ours` check above (e.g.
            # during `_ensure_metadata`'s filesystem I/O), and a peer has since re-detonated,
            # uploaded its OWN result, and CAS-committed DONE, this worker's write would land
            # stale/divergent bytes over the peer's already-correct, already-DONE result --
            # detonation is not guaranteed deterministic run-to-run, so this is a real corruption,
            # not a harmless redundant rewrite. Re-checking ownership IMMEDIATELY before the call
            # narrows that window to the same width the rest of this file already accepts for its
            # store operations (the same TOCTOU `_claim_is_still_ours` above narrows for the
            # metadata write) -- it does NOT fully close it: there is no store-level compare-and-
            # swap on the uploaded object itself (S3 offers no such primitive), so a reclaim landing
            # AFTER this check but DURING the upload call is still possible and is not fenced here.
            # Accepted residual with a documented closure path: design doc "Known limitations"
            # (Finding C2) — a claim-scoped result key or object-level conditional write.
            if ok and not self._claim_is_still_ours(job):
                logger.info("vm_dispatch: job %s reclaimed before upload; skipping put_output "
                            "(peer owns it now)", job.job_id)
                # Same reasoning as the other lost-claim returns in this method: our local copy
                # is a stale attempt now, the peer's own upload is the correct result, and the
                # blob store can always re-materialise the sample if this job needs to run again
                # -- nothing may survive on this worker's disk once we're no longer the owner. The
                # unconditional `finally` purge (below) handles it.
                return
            if ok:
                upload_exc = upload_output_with_retry(
                    self._blobs, job.job_id, self._job_dir(job) / "output",
                    attempts=self._put_output_max_attempts,
                    backoff_s=self._put_output_retry_backoff_s,
                )
                if upload_exc is not None:
                    # Finding D1: every inline attempt failed. There is no consumer for a job left
                    # RUNNING "for the sweeper" (nothing re-runs a RUNNING job), so treat this the
                    # same as any other post-detonation failure -- FAIL the job (the terminal write
                    # below) and let the unconditional `finally` purge run. The completed result is
                    # discarded (it was never durably stored), but the job dir + claim don't leak.
                    logger.error(
                        "vm_dispatch: result upload failed for %s after %d attempt(s) (%s); "
                        "discarding the result and failing the job (no leftover output dir)",
                        job.job_id, self._put_output_max_attempts, upload_exc,
                    )
                    ok = False
                    err = (f"result upload failed after {self._put_output_max_attempts} attempts; "
                           "result discarded")
                    # Finding S1: a partial result may already be sitting under
                    # results/<job_id> (some of put_output's per-file writes may have landed
                    # before a later one failed). This attempt marks the job FAILED (never
                    # DONE), so it will never be served (open_output is DONE-gated) -- and
                    # with the default job_retention_s=0, expires_at is None, so the
                    # retention sweeper skips it forever (retention.py: `if job.expires_at
                    # is None ... continue`). Without reaping here, that partial blob is
                    # orphaned permanently, recoverable only by an explicit DELETE.
                    # delete_job is results-scoped + idempotent. Best-effort: a reap
                    # failure must not mask the real upload failure / FAILED outcome this
                    # method is already reporting.
                    #
                    # Claim-fenced (ultrareview bug_001): the `_claim_is_still_ours`
                    # check above ran BEFORE the retry loop -- if a peer requeued +
                    # re-ran + CAS-committed DONE during the backoff window, its upload
                    # landed at this same results/<job_id> prefix, and an unconditional
                    # delete would wipe the peer's authoritative result while the job
                    # store says DONE (every result route then 404s, unrepairably). On
                    # a lost claim the prefix isn't ours to reap -- skip; the bounded
                    # partial-blob leak in the no-peer-upload case is the smaller cost.
                    if self._claim_is_still_ours(job):
                        try:
                            self._blobs.delete_job(job.job_id)
                        except Exception as reap_exc:  # noqa: BLE001
                            logger.warning(
                                "vm_dispatch: failed to reap partial result blob for job %s "
                                "after upload exhaustion: %s", job.job_id, reap_exc,
                            )
                    else:
                        logger.info(
                            "vm_dispatch: job %s: skipping partial-blob reap on upload "
                            "exhaustion; claim lost -- results/<job_id> belongs to a peer now",
                            job.job_id,
                        )
            finished = time.time()
            # CAS on (status, claim_id) so a stale owner can't clobber a job that was reclaimed
            # (RUNNING->QUEUED->RUNNING under another dispatcher). The return value is OUR ownership.
            terminal_status = JobStatus.DONE if ok else JobStatus.FAILED
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=terminal_status,
                finished_at=finished, result_summary=summary, error=err,
                expires_at=self._expiry(finished))
            if ok and owned:
                # index per-page perceptual hashes for /v1/similar, same as the cold/file-warm paths --
                # else a network-endpoint (static/AWS) page-hash job is DONE but invisible to search.
                self._index_page_hashes(job, sealed_env)
        except (NoWarmSlot, WorkerBusy):
            # capacity pressure, not a job failure -- the job NEVER ran (no slot, or the claimed worker's
            # single-flight lock was held by a stale detonation -> 409). REQUEUE it (CAS back to QUEUED,
            # clear our claim + warm stamp) so it waits for a slot / another dispatcher instead of FAILing.
            record_warm_claim(hit=False)   # warm-pool miss (parity with the cold dispatcher's metric)
            logger.info("vm_dispatch: no usable warm slot for %s; requeuing (not failing)", job.job_id)
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.QUEUED, claim_id=None, started_at=None,
                worker_runtime=None, worker_tier=None)
            owned = False   # requeued, not terminal -> don't delete the input in the finally
        except Exception as exc:  # noqa: BLE001 — one bad job must not sink the dispatcher
            logger.warning("vm_dispatch: job %s failed: %s", job.job_id, exc, exc_info=True)
            finished = time.time()
            terminal_status = JobStatus.FAILED
            owned = self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.FAILED, finished_at=finished, error=type(exc).__name__,
                expires_at=self._expiry(finished))
        finally:
            # SECURITY INVARIANT (not housekeeping): nothing survives on this worker's disk once its
            # attempt ends. The purge is UNCONDITIONAL across every terminal state (DONE/FAILED) AND
            # every lost/released claim -- crucially including when a peer reclaimed the job mid-flight
            # so our terminal CAS lost (owned=False), AND a put_output failure that exhausted its
            # retry budget (Finding D1 removed the "leave it RUNNING for the sweeper" exception: no
            # consumer ever picks a RUNNING job like that back up, so that branch could only ever
            # leak a job dir forever). Bytes left behind would be orphaned malware that no peer on
            # another host could ever read (this design rejects a shared filesystem), while the blob
            # store (real in every mode) always re-materialises the sample for the new owner. It
            # deliberately purges output/ too, and there is no setting that disables it.
            self._purge_job_dir(job)
            # Metric parity with the cold dispatcher: count the terminal outcome + wall time -- but ONLY
            # for THIS attempt's own winning CAS (owned + the status we wrote). Requeued (NoWarmSlot)
            # attempts set owned=False, and a reclaimed attempt loses the CAS -> both are skipped. Gating
            # on a store re-read instead would double-count: after a requeue, a PEER dispatcher can claim
            # and finish the same job before this finally runs, so we'd record a hit + terminal outcome
            # for a tier that only recorded a miss and never ran the job.
            if owned and terminal_status is not None:
                record_warm_claim(hit=True)   # a slot was claimed to produce this terminal outcome
                record_job_dispatched(
                    path=self._worker_tier,
                    outcome="done" if terminal_status is JobStatus.DONE else "failed",
                )
                observe_job_duration(path=self._worker_tier, seconds=time.monotonic() - t0)

    def _sealed_envelope(self, job: Job) -> Any:
        """Parse the HOST-SEALED metadata.json (the Envelope the trust gate wrote) for the remote path,
        or None if absent/unparseable. Used to build a COMPACT result_summary + index page hashes."""
        meta = self._job_dir(job) / "output" / "metadata.json"
        if not meta.exists():
            return None
        try:
            from blastbox.contract.envelope import Envelope
            return Envelope.model_validate_json(meta.read_text())
        except Exception:  # noqa: BLE001
            logger.warning("vm_dispatch: could not parse sealed metadata for %s", job.job_id, exc_info=True)
            return None

    def _index_page_hashes(self, job: Job, envelope: Any) -> None:
        """Best-effort: index the job's per-page perceptual hashes (phash/colorhash/sha256) for
        ``/v1/similar``, same as the cold/file-warm paths -- else a network-endpoint page-hash job is
        DONE with sealed artifacts but invisible to search. Postgres+pg_bktree only, so gate on
        ``supports_hash_search()``. An indexing failure NEVER fails an otherwise-DONE job."""
        supports = getattr(self._store, "supports_hash_search", None)
        indexer = getattr(self._store, "index_page_hashes", None)
        if supports is None or indexer is None or not supports() or envelope is None:
            return
        try:
            indexer(job.job_id, envelope)
        except Exception:  # noqa: BLE001 -- indexing is best-effort; never fail a DONE job on it
            logger.exception("vm_dispatch: page-hash indexing failed for %s; continuing", job.job_id)

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
            reap_stale_scratch(
                self._job_root, self._scratch_max_age_s, self._store, logger,
                blob_store=self._blobs,
            )
        except Exception:  # noqa: BLE001 — a sweep failure must not kill maintenance
            logger.warning("vm_dispatch: scratch reclaim failed", exc_info=True)
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
        self._fail_stale_queued_jobs()

    def _fail_stale_queued_jobs(self) -> None:
        """FAIL jobs stuck QUEUED past ``max_queued_age_s`` and delete their untrusted input (opt-in;
        0 = off). The network-endpoint path bypasses the cold ``Dispatcher`` (the only other place this
        runs), so without this a job pinned to a target_tier nobody serves — or for an engine this
        single-engine dispatcher can't claim — would sit QUEUED with its input on disk forever. CAS on
        QUEUED so a job claimed since the list() snapshot (→ RUNNING) is left to its claimer."""
        if self._max_queued_age_s <= 0:
            return
        cutoff = time.time() - self._max_queued_age_s
        try:
            for job in self._store.list(status=JobStatus.QUEUED):
                # Normally scope the sweep to OUR engine (a peer dispatcher owns the others). But when
                # sole_owner (no other dispatcher on this store), also fail jobs for engines NOBODY
                # serves -- a typo'd/mismatched engine would otherwise keep its untrusted input forever
                # despite the TTL. Only sole_owner may safely reach across engines.
                if not self._sole_owner and self._engine is not None and job.engine != self._engine:
                    continue
                if job.created_at > cutoff:
                    continue
                now = time.time()
                if self._store.update_if_status(
                        job.job_id, JobStatus.QUEUED,
                        status=JobStatus.FAILED, finished_at=now,
                        error=f"job exceeded the max queued age ({self._max_queued_age_s:.0f}s) without "
                              f"being claimed (no dispatcher for target_tier={job.target_tier!r}?)",
                        expires_at=self._expiry(now)):
                    logger.info("vm_dispatch: failed stale-queued job %s", job.job_id)
                    try:
                        self._input_path(job).unlink()
                    except OSError:
                        pass
        except Exception:  # noqa: BLE001 — a sweep failure must not kill maintenance
            logger.warning("vm_dispatch: stale-queued sweep failed", exc_info=True)

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
            try:
                self._stop.wait()
            finally:
                # Release the worker/maintenance loops BEFORE the ThreadPoolExecutor's __exit__ joins them.
                # A KeyboardInterrupt out of _stop.wait() would otherwise deadlock: __exit__ waits for the
                # loops, but the loops only exit once _stop is set -- which the caller's `except` can't do
                # until run() returns. Setting it here (idempotent on a normal stop()) breaks that cycle,
                # so the interrupt propagates to the CLI where vm.stop()/pool.stop() reap live cloud slots.
                self._stop.set()

    def stop(self, *_: object) -> None:
        self._stop.set()


def _accepts_budget_kwarg(fn: "Callable[..., Any]") -> bool:
    """Whether a runtime's resume() takes the optional budget_s kwarg (external runtimes may not)."""
    try:
        return "budget_s" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _is_unknown_not_dead(exc: BaseException) -> bool:
    """True if this failure means "the control plane didn't tell us", not "the worker is gone".

    issue #77: resume() destroying a PARKED warm slot — already booted and engine-warmed, the most
    expensive kind — because a describe was throttled for a minute is the worst trade in the system.
    Only a CONFIRMED dead state should cost the slot.

    The TYPE is now authoritative and no string matching is left here. The AWS runtime classifies at
    the point of failure against an allowlist of confirmed-dead answers and raises AwsUnknownState
    for everything else, so anything that reaches us as a plain AwsWorkerError has already been
    judged a real verdict (a definitive "no such resource", or a local failure like an agent that
    never came up). Re-deciding that here from the message text is what let four review rounds each
    find another retryable error read as death (issue #77 round 4). The cause chain is walked
    because resume() re-raises its own summary error over the last one it saw."""
    names = {c.__name__ for c in type(exc).__mro__}
    if "AwsUnknownState" in names or "AwsProbeTimeout" in names:
        return True
    if "AwsWorkerError" in names:
        # OUR type, chosen deliberately at the raise site: a definitive verdict. Do NOT walk the
        # cause chain here -- resume() chains the last error it saw for debuggability, and that is
        # often a trailing budget expiry. Letting the chain win would flip a verdict we established
        # by observation ("the control plane confirmed it running and its agent stayed silent for a
        # fair window") back into UNKNOWN, leaking the husk forever (issue #77 marla-loop 3).
        return False
    # A FOREIGN exception: it carries no verdict of its own, so look for one it may be wrapping.
    seen: set[int] = set()
    cur: BaseException | None = exc.__cause__ or exc.__context__
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if any(c.__name__ in ("AwsUnknownState", "AwsProbeTimeout") for c in type(cur).__mro__):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _resume_on_claim(pool: Any, slot: Any, *, budget_s: float | None = None) -> None:
    """Optional per-claim resume seam (aws-lambda-snapstart): wake a parked/suspended warm slot and
    block until its agent answers BEFORE the transport POSTs (which has no retry). The runtime
    repopulates slot.url/auth_token in place; slot_base_url + the POST read them dynamically after claim,
    so no transport change is needed. On resume failure release the slot DIRTY (retire the un-resumable
    worker) rather than leak it, then re-raise so the job fails. A runtime without resume() is a no-op."""
    resume = getattr(getattr(pool, "runtime", None), "resume", None)
    if not callable(resume):
        return
    try:
        # Hand the runtime the claim window's REMAINING time when it accepts one, so a single
        # unreachable slot cannot burn the whole window (its own resume_timeout_s may be far
        # larger) and starve the healthy slots behind it (issue #77 round 4).
        if budget_s is not None and _accepts_budget_kwarg(resume):
            resume(slot, budget_s=budget_s)
        else:
            resume(slot)
    except Exception as exc:
        # UNKNOWN (the control plane never answered) is NOT "un-resumable": handing the slot back
        # unused keeps a healthy PARKED worker alive through a brownout, where release(dirty=True)
        # would terminate it — and concurrent dispatch threads would then walk the whole tier
        # doing the same (issue #77). The job still requeues via the re-raise.
        # UNKNOWN covers BOTH shapes: an explicit AwsProbeTimeout, and a plain runtime error whose
        # message is a transient control-plane answer (a throttle/5xx exits non-zero, so it is not a
        # timeout — resume() has no probe budget of its own, so it surfaces as AwsWorkerError).
        if _is_unknown_not_dead(exc):
            unclaim = getattr(pool, "unclaim", None)
            if callable(unclaim):
                with contextlib.suppress(Exception):
                    unclaim(slot)
                raise
        try:
            # A CONFIRMED-dead resume verdict (AWS says the resource is gone / the state is
            # terminal) is evidence about the WORKER, so it counts toward wedge eviction.
            pool.release(slot, **release_kwargs(pool.release, dirty=True, fault="worker"))
        except Exception:   # noqa: BLE001 -- release failure must not mask the resume error
            logger.warning("vm_dispatch: releasing un-resumable slot failed", exc_info=True)
        raise


_RETRY_SLOT_COOLDOWN_S = 3.0   # how long a slot that just failed to resume is passed over


def _claim_resumable_slot(pool: Any, timeout_s: float, *,
                          clock: "Callable[[], float]" = time.monotonic) -> Any:
    """Claim a warm slot and resume it, trying OTHER slots when one can't be woken.

    Returns the claimed+resumed slot, or None if the window closed without one.

    issue #77 round 2: this loop used to rely on a failed resume having REMOVED the slot from the
    pool (``release(dirty=True)``), so "try the next one" happened for free. Making the UNKNOWN
    case non-destructive (``unclaim`` -> IDLE) broke that premise: ``pool.claim`` is
    insertion-ordered, so the slot we just handed back is the very next one handed out, and a
    single throttled slot spun until the deadline while a healthy slot sat idle behind it — the
    job then requeued with NoWarmSlot despite live capacity. Track what we've tried and HOLD those
    slots ASSIGNED so the scan advances; hand them all back when the window ends.
    """
    deadline = clock() + timeout_s
    last_exc: Exception | None = None
    tried: dict[str, float] = {}     # slot_id -> when its resume last failed
    held: dict[str, Any] = {}        # slot_id -> slot, withheld (ASSIGNED) during its cooldown

    def _release(sid: str) -> None:
        slot_ = held.pop(sid, None)
        if slot_ is None:
            return
        unclaim_ = getattr(pool, "unclaim", None)
        if callable(unclaim_):
            with contextlib.suppress(Exception):
                unclaim_(slot_)

    try:
        while True:
            # Release anything whose cooldown has expired FIRST, so it is claimable again this pass.
            # Holding to the end of the window was the bug the cooldown was meant to fix but didn't:
            # the cooldown gated only the retry DECISION, while `held` stayed ASSIGNED until the
            # finally -- so one transient failure made a warm_size=1 tier unclaimable for the whole
            # window, and _spawn_to_deficit counts ASSIGNED as active so nothing replaced it either.
            for sid_h in [s for s, _ in list(held.items())
                          if clock() - tried.get(s, -1e18) >= _RETRY_SLOT_COOLDOWN_S]:
                _release(sid_h)

            remaining = deadline - clock()
            if remaining <= 0:
                break
            # Cap the wait at the next cooldown expiry. WarmPool.claim BLOCKS until its deadline and
            # never returns early, so waiting the whole remaining window meant the release loop above
            # never regained control and a held slot stayed ASSIGNED for the entire claim -- the very
            # bug the cooldown exists to prevent (issue #77 marla-loop 3). Only a fake pool that
            # returns None instantly ever exercised the release path.
            wait = remaining
            if held:
                next_free = min(tried.get(s, -1e18) + _RETRY_SLOT_COOLDOWN_S for s in held)
                wait = min(wait, max(0.0, next_free - clock()))
            slot = pool.claim(timeout_s=wait)
            if slot is None:
                # Nothing claimable right now. If we are withholding slots, their cooldown is the
                # only thing that will change that, so keep looping until one frees up.
                if held and deadline - clock() > 0:
                    continue
                break
            sid = getattr(slot, "slot_id", None)
            if sid is not None and (clock() - tried.get(sid, -1e18)) < _RETRY_SLOT_COOLDOWN_S:
                # Failed recently: withhold it so the scan reaches the slots behind it, and release
                # it again as soon as its cooldown expires (above).
                held[sid] = slot
                continue
            if sid is not None:
                tried[sid] = clock()
            remaining_for_resume = deadline - clock()
            if remaining_for_resume <= 0:
                # The window closed while we were probing. Hand the slot back untouched rather than
                # starting a resume we cannot afford -- attempting one with no budget is how a
                # never-probed healthy slot got destroyed (issue #77 round 5).
                unclaim = getattr(pool, "unclaim", None)
                if callable(unclaim):
                    with contextlib.suppress(Exception):
                        unclaim(slot)
                break
            try:
                _resume_on_claim(pool, slot, budget_s=remaining_for_resume)
                return slot
            except Exception as exc:  # noqa: BLE001 -- dead slots are already retired dirty by
                last_exc = exc        # _resume_on_claim; UNKNOWN ones were handed back. Try another.
                if sid is not None:
                    tried[sid] = clock()
    finally:
        for sid_h in list(held):
            _release(sid_h)

    if last_exc is not None:
        raise NoWarmSlot("no resumable warm slot within claim timeout") from last_exc
    return None


def build_remote_vm_dispatcher(
    store: JobStore,
    job_root: str | Path,
    pool: Any,
    *,
    tier: str,
    engine: str | None = None,
    engine_spec: Any = None,
    limits: Any = None,
    worker_timeout_s: float = 300.0,
    warm_claim_timeout_s: float = 60.0,
    concurrency: int = 1,
    job_retention_s: int = 0,
) -> "VmJobDispatcher":
    """Assemble a VmJobDispatcher that drives a NETWORK-ENDPOINT warm pool (aws/static/cascade) over the
    remote_http transport: claim a warm slot -> POST the job to its http_agent -> HOST-TRUST-GATE the
    extracted output (re-seal + verify engine/input-SHA/caps) -> DONE. The runtime's client (m)TLS
    context flows through; per-job params are gated through the engine's allowlist and forwarded; the
    engine's egress personality is enforced fail-closed. Selection is capability-based
    (``runtime.dispatch_style``), not tier-name matching -- this is the single typed CLI seam."""
    from blastbox.host.runtime.remote_http import make_remote_validate

    # FAIL CLOSED on an unsafe trust configuration. This path sets trust_output_metadata=True (it PRESERVES
    # the worker-supplied metadata.json + artifact list), which is only safe when the host trust gate re-
    # seals/hashes/caps that output first. The gate needs BOTH: `limits` (without it output_trust is never
    # installed -> a compromised worker's untrusted artifacts get marked DONE unvalidated) and `engine`
    # (validate_worker_output requires an exact engine match -> engine=None validates against "" and every
    # real envelope deterministically fails). The CLI always supplies both; a direct caller must too.
    if limits is None:
        raise ValueError("build_remote_vm_dispatcher requires limits: the trust-gated remote path preserves "
                         "worker metadata and MUST re-validate it (caps/hashes). Pass Limits.")
    if not engine:
        raise ValueError("build_remote_vm_dispatcher requires engine: the host trust gate validates each "
                         "worker envelope against an exact engine. Pass the tier's engine name.")

    # Fail-closed per-engine tier gate, applied here so the network-endpoint/cascade path — and any
    # embedder calling this factory directly — can't route the engine onto a tier its allowed_runtimes
    # excludes. Network tiers requeue rather than cold-fall-back, so reachable_tiers folds in only the
    # concrete cascade members here (no "cold"). Runs before the CLI's pool.start().
    if engine_spec is not None:
        from blastbox.host.dispatch import enforce_allowed_runtimes, reachable_tiers

        enforce_allowed_runtimes({engine: engine_spec}, reachable_tiers(pool, tier, warm_only=True))

    ssl_context = getattr(pool.runtime, "ssl_context", None)
    max_output_bytes = getattr(limits, "max_total_artifact_bytes", None)
    # A resume seam (snapstart) runs INSIDE the claim, before the transport's timeout guard -- if its
    # budget outlasts the per-job budget a slow wake can abandon the claim thread with a live billing
    # slot. Warn (don't fail) if the operator sized them backwards.
    # A tier's cfg carries it directly; a CascadingRuntime aggregates it across its wrapped tiers and
    # exposes the max as a plain attribute (it has no single cfg), so honor both.
    _resume_to = getattr(getattr(pool.runtime, "cfg", None), "resume_timeout_s", None)
    if _resume_to is None:
        _resume_to = getattr(pool.runtime, "resume_timeout_s", None)
    if _resume_to is not None and float(_resume_to) >= worker_timeout_s:
        logger.warning("vm_dispatch: resume_timeout_s=%.0f >= worker_timeout_s=%.0f -- lower "
                       "BLASTBOX_LAMBDA_SNAPSTART_RESUME_TIMEOUT_S below BLASTBOX_WORKER_TIMEOUT_S so a "
                       "slow resume can't outlast the job budget and leak a live slot", float(_resume_to),
                       worker_timeout_s)
    # Disposable AWS tiers have no recycle(), so make_remote_validate's finally release() runs a
    # SYNCHRONOUS terminate-instances/terminate-microvm (bounded by the aws-cli timeout) BEFORE validate()
    # returns -- i.e. INSIDE the heartbeat watchdog. Budget that cleanup too, else a job that used most of
    # worker_timeout_s gets watchdog-killed (marked FAILED) while terminating, after its output was already
    # received + trusted.
    # honor a tier's cfg directly; a CascadingRuntime has no single cfg but aggregates the max across its
    # wrapped tiers as a plain attribute (mirrors the resume_timeout_s fallback above).
    _cleanup_to = getattr(getattr(pool.runtime, "cfg", None), "cli_timeout_s", None)
    if _cleanup_to is None:
        _cleanup_to = getattr(pool.runtime, "cli_timeout_s", None)
    _cleanup_budget = float(_cleanup_to) if _cleanup_to is not None else 0.0
    # Post-read HOST sealing runs INSIDE the watchdog AFTER detonate_remote's network read may have
    # consumed the whole worker_timeout_s: _safe_extract_tar (write up to max_total_artifact_bytes) +
    # output_trust re-SHA-256 of every artifact + validate_envelope. It's CPU/disk-bound and scales with
    # the artifact cap; it must NOT borrow from _cleanup_budget (sized for the terminate; 0 on recycle-only
    # VM/static tiers), else a slow-but-VALID job is watchdog-FAILED during sealing. Base covers parse +
    # small-file overhead; ~50MB/s floor covers the extract-write + hash-read passes. Cap may be None
    # (unbounded) -> base only. This is purely additive; the transport still bounds the network read.
    _seal_slack = 30.0 + (max_output_bytes or 0) / (50 * 1024 * 1024)
    # DoS backstops for the untrusted worker tar, BEFORE the host trust gate parses/validates it:
    # a member (inode) cap ~ the artifact ceiling (+slack for metadata.json/control files), and a
    # metadata.json size cap so a huge JSON isn't parsed before max_metadata_bytes is enforced.
    _max_artifacts = getattr(limits, "max_artifacts", None)
    max_members = (_max_artifacts + 16) if _max_artifacts is not None else None
    max_metadata_bytes = getattr(limits, "max_metadata_bytes", None)

    def _claim() -> Any:
        # Claim + (optionally) resume within a BOUNDED claim budget -- NOT the whole worker_timeout_s.
        # The claim wait and the detonation must not share one budget: if the wait could burn all of
        # worker_timeout_s, a slot appearing near the deadline would start detonating just as the parent
        # heartbeat watchdog (validate_timeout_s) fired, marking the job failed + deleting its input while
        # the daemon keeps a LIVE claimed slot. Capping the wait at warm_claim_timeout_s reserves the full
        # worker_timeout_s for the detonation (validate_timeout_s = claim + detonate).
        #
        # Exhausting the window on un-resumable slots is the SAME "no usable warm slot; the job never
        # ran" condition as a plain capacity miss -- resume only wakes the SLOT, it never touched the
        # job's input/content. So REQUEUE (NoWarmSlot), don't FAIL+delete-input: AWS auto-terminates
        # parked slots in correlated batches, so a whole claim window can be stale at once and that
        # must not fail jobs.
        slot = _claim_resumable_slot(pool, warm_claim_timeout_s)
        if slot is None:
            raise NoWarmSlot("no warm slot available within claim timeout")   # capacity -> REQUEUE
        return slot

    def _release(slot: Any, dirty: bool = False, fault: str | None = None) -> None:
        # Forward the transport's attribution through to the pool -- dropping it here would put the
        # conflated signal straight back (job failures counting as worker evidence). But degrade
        # HERE rather than making the caller retry: this seam always passed fault= through, so
        # against a pool predating fault attribution EVERY retry in remote_http's fallback ladder
        # raised TypeError again and the slot was never released at all (upstream, PR #82).
        pool.release(slot, **release_kwargs(pool.release, dirty=dirty, fault=fault))

    sanitize: Callable[[dict[str, str]], dict[str, str]] | None = None
    # the RESOLVED policy the worker's egress is actually provisioned to (None = enforcement opt-out, i.e.
    # engine declared no policy). Set from _personality below so a malformed/missing BLASTBOX_NETPOLICY_*
    # -- which resolve_net_policy fails-closed to 'none' -- is what _process compares against, not the raw
    # spec name (else a job matching the raw name runs on a sealed worker instead of being rejected).
    _resolved_net_policy: str | None = None
    if engine_spec is not None:
        from blastbox.host.dispatch import Dispatcher   # lazy: dispatch<->vm_dispatch are independent
        from blastbox.host.netpolicy import parse_personalities, resolve_net_policy

        # The remote tier's egress is FIXED at the engine's provisioned personality (the dispatcher
        # already FAILs jobs whose effective policy != this). Tell the remote worker's inner sandbox
        # whether that personality grants egress by injecting BLASTBOX_NET_EGRESS -- the SAME dispatcher-
        # owned env the cold path sets. Without it a bwrap/nsjail/nono inner sandbox on the remote box
        # keeps the image default (sealed) and fails closed even on an egress-provisioned tier.
        _registry = parse_personalities(os.environ)
        _personality = resolve_net_policy(
            job_net_policy=None, engine_default=(getattr(engine_spec, "net_policy", None) or "none"),
            registry=_registry, allow_override=False,
        )
        # resolved name to enforce against -- but ONLY when the engine actually declared a policy, so an
        # UNdeclared engine (net_policy None) stays enforcement-opt-out exactly as before.
        _resolved_net_policy = _personality.name if getattr(engine_spec, "net_policy", None) else None
        _net_env = {"BLASTBOX_NET_EGRESS": "1" if _personality.exit_driver not in ("none", "drop") else "0"}
        # For an httpproxy personality, inject the SAME validated HTTP_PROXY/HTTPS_PROXY the cold dispatcher
        # sets (Dispatcher._httpproxy_env) into the worker env -- else the inner sandbox is opened for egress
        # but proxy-aware clients get no proxy and go direct / fail, silently differing from the cold tier.
        # (Returns {} for non-httpproxy personalities, so it's a no-op for none/direct/inetsim.)
        _net_env.update(Dispatcher._httpproxy_env(_personality))
        # Forward the HOST-owned output caps to the worker. http_agent builds Limits.from_env() PER JOB and
        # rejects a result over ITS OWN metadata/artifact-bytes/file caps (HTTP 500) BEFORE returning the
        # tar -- so a cap the operator raised only on the DISPATCHER (for the host trust gate + extractor)
        # would still 500 at the agent unless it's also raised in the worker image. Forwarding closes that
        # drift: these are dispatcher-owned (merged LAST, a job param can't flip them).
        for _env_key, _cap in (("BLASTBOX_MAX_METADATA", max_metadata_bytes),
                               ("BLASTBOX_MAX_TOTAL_ARTIFACTS", max_output_bytes),
                               ("BLASTBOX_MAX_ARTIFACTS", getattr(limits, "max_artifacts", None)),
                               # per-artifact cap too: engines (detonate/urlgrab) read max_artifact_bytes
                               # during detonation, so an unforwarded raise silently TRUNCATES on the worker.
                               ("BLASTBOX_MAX_ARTIFACT", getattr(limits, "max_artifact_bytes", None))):
            if _cap is not None:
                _net_env[_env_key] = str(_cap)

        def sanitize(p: dict[str, str]) -> dict[str, str]:
            out = Dispatcher._sanitize_params(
                p, engine_spec.allowed_param_keys, engine_spec.reserved_param_keys,
                getattr(engine_spec, "default_params", None),
            )
            return {**out, **_net_env}   # dispatcher-owned, merged LAST so a job param can't flip it

    # host trust gate: re-seal the extracted output + verify engine/input-SHA/caps, then overwrite
    # metadata.json with the host-sealed envelope (recomputed hashes). Same gate the cold path runs.
    # It runs INSIDE the transport (make_remote_validate) BEFORE the slot is released clean, so a worker
    # that fails trust keeps its slot dirty and is retired instead of re-offered. The transport hands it
    # (input_path, out_dir); recompute the input SHA from the bytes actually POSTed (== job.input_sha256).
    # limits + engine are guaranteed non-None (fail-closed guard at the top), so the trust gate is ALWAYS
    # installed on this path -- trust_output_metadata=True is never set without it.
    def output_trust(input_path: Path, out_dir: Path, expected_sha: str | None,
                     owns: Callable[[], bool] | None = None) -> None:
        from blastbox.errors import EngineErrorEnvelope
        from blastbox.host.runtime.remote_http import ClaimLost
        from blastbox.host.trust import validate_worker_output
        # Compare the worker's sealed envelope against the AUTHORITATIVE ingress-recorded input SHA
        # (job.input_sha256), matching the cold/file-warm paths -- so a staged input that was
        # corrupted/replaced after submission is caught (the worker hashed different bytes). Fall
        # back to hashing the POSTed file only if the dispatcher didn't supply one.
        if not expected_sha:
            import hashlib
            h = hashlib.sha256()
            with open(input_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            expected_sha = h.hexdigest()
        env = validate_worker_output(output_dir=out_dir, input_sha256=expected_sha,
                                     engine=engine, limits=limits)
        if env.status == "engine_error":
            # the envelope VALIDATED (structure/hashes/input-sha) -> a healthy worker, a failed SAMPLE.
            # Distinct exception so the transport can release the slot clean (a malformed/unvalidatable
            # envelope raised a plain OutputTrustError above and stays dirty).
            detail = env.warnings[0].message if env.warnings else "engine_error"
            raise EngineErrorEnvelope(f"engine_error: {detail}")
        # Fence the metadata WRITE by claim ownership: if this (possibly long) remote attempt
        # outlived its claim and a peer recovered the job, DON'T overwrite the new owner's
        # metadata.json in the shared output dir. Raise -> job fails for this stale attempt, slot
        # retired dirty. Checked immediately before the write to shrink the TOCTOU to ~nothing.
        if owns is not None and not owns():
            # ClaimLost, NOT OutputTrustError: a peer owning the job says nothing about this
            # worker's output, which validated fine. Raising a trust error routed it into the
            # generic handler and convicted a healthy slot on every reclaim race (upstream, PR #82).
            # validated=True: the trust gate has ALREADY accepted this worker's output above, so
            # the run is positive evidence about the worker -- not merely "nothing was proven".
            raise ClaimLost("claim lost before host metadata write (peer recovered the job)",
                            validated=True)
        atomic_write_confined(out_dir, "metadata.json",
                              env.model_dump_json(by_alias=True).encode("utf-8"), mode=0o644)

    # A tier that declares it needs longer to resume than the claim window can ever grant is a
    # CONFIGURATION contradiction, not something the verdict logic can resolve: the hibernate tier
    # defaults to resume_timeout_s=180 against warm_claim_timeout_s=60, so a 90s thaw accumulates
    # full-duration failed probes for 60s and is convicted -- even though the tier budgeted 180 and
    # the watchdog reserves it. Three attempts to express this as a rule inside resume() each
    # produced the mirror of the previous bug (always-true, then almost-always-false, then
    # unreachable), because the rule was standing in for a config that cannot be satisfied. Say so
    # here instead, where it can actually be fixed. See issue #81.
    _tier_resume = getattr(getattr(pool.runtime, "cfg", None), "resume_timeout_s", None)
    if _tier_resume is None:
        _tier_resume = getattr(pool.runtime, "resume_timeout_s", None)
    if _tier_resume is not None and float(_tier_resume) > float(warm_claim_timeout_s):
        logger.warning(
            "vm_dispatch: warm_claim_timeout_s=%.0fs cannot honour the %s tier's declared "
            "resume_timeout_s=%.0fs -- a slot that legitimately takes longer than the claim window "
            "is judged on a window it was never given. NOTE the resume budget is "
            "min(resume_timeout_s, remaining claim window), so RAISING warm_claim_timeout_s alone "
            "does not close the gap: the tier's own resume_timeout_s must come down to at or below "
            "the claim window, or the claim path must stop truncating it. Tracking in issue #81.",
            float(warm_claim_timeout_s), tier, float(_tier_resume),
        )

    validate = make_remote_validate(
        _claim, _release,
        output_dir_for=lambda in_path: in_path.parent.parent / "output",
        ssl_context=ssl_context,
        max_output_bytes=max_output_bytes,
        max_members=max_members,
        max_metadata_bytes=max_metadata_bytes,
        output_trust=output_trust,   # trust gate runs pre-release so a failed slot stays dirty
        timeout=worker_timeout_s,   # bound the transport by the operator's worker timeout, not the 600s default
    )
    return VmJobDispatcher(
        store, str(job_root), validate,
        engine=engine, worker_tier=tier,
        trust_output_metadata=True,   # preserve the host-sealed metadata.json the validator wrote
        sanitize_params=sanitize,
        fixed_net_policy=_resolved_net_policy,   # enforce against the RESOLVED (fail-closed) egress, not raw
        # the job's DEFAULT policy must ALSO be the RESOLVED name, matching fixed_net_policy + the worker's
        # actual egress: a malformed/undeclared BLASTBOX_NETPOLICY_* fails closed to "none" (worker sealed),
        # so an untargeted job should run SEALED (effective "none" == fixed "none"), as resolve_net_policy
        # intends -- NOT be rejected (raw "inspect" != "none"). In the normal case resolved == raw.
        engine_net_policy=_resolved_net_policy,
        # the parent heartbeat watchdog must cover the bounded claim WAIT + the in-claim RESUME (snapstart/
        # hibernate wake, up to the tier's resume_timeout_s) + the full detonation budget + the synchronous
        # post-job cleanup terminate (disposable AWS tiers, up to cli_timeout_s), so a slot claimed late,
        # slow to wake, or slow to terminate still gets its whole worker_timeout_s to run without a
        # post-success watchdog kill.
        validate_timeout_s=(warm_claim_timeout_s
                            + (float(_resume_to) if _resume_to is not None else 0.0)
                            + worker_timeout_s
                            + _seal_slack
                            + _cleanup_budget),
        # sole_owner recovers a claim that crashed in the tiny window BETWEEN claim and the
        # worker_runtime="warm" stamp -- but it makes maintenance FAIL any stale RUNNING job for this
        # engine, which would clobber a COLD dispatcher's live jobs if one shares the store. Default OFF
        # (shared-store safe); opt in with BLASTBOX_DISPATCH_SOLE_OWNER=1 ONLY for a network-ONLY store.
        sole_owner=(os.environ.get("BLASTBOX_DISPATCH_SOLE_OWNER") or "").strip().lower()
                   in ("1", "true", "yes", "on"),
        # same stale-queued TTL the cold Dispatcher honors -- bounds a job pinned to a tier no remote
        # dispatcher serves (else its untrusted input lingers forever in a remote-only deployment).
        max_queued_age_s=float(os.environ.get("BLASTBOX_MAX_QUEUED_AGE_S") or "0"),
        concurrency=concurrency,
        job_retention_s=job_retention_s,
    )
