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
3. Input is deleted whenever a dispatcher reaches a terminal path FOR A JOB IT STILL
   OWNS (success, failure, timeout, launch error, unknown engine, insecure runtime) via a
   ``finally`` block; on a lost-claim abort the input is left for the dispatcher that
   reclaimed it, and a time-recovered (owner-gone) job's input is deleted by the recovery
   sweep — so untrusted input never persists permanently, but never races a live new owner.
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
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping

from blastbox.contract.envelope import (
    Artifact,
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
_VALID_ENV_KEY_RE = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")  # \Z (not $) — $ also matches a trailing \n

# Engine-AGNOSTIC reserved env keys/prefixes that a client's job.params may NEVER set,
# even when they match the key shape and even if an engine's allowlist is misconfigured
# (belt-and-suspenders / fail-safe). These cover framework + loader/interpreter control
# that applies to EVERY engine — re-selecting the engine (BLASTBOX_*), hijacking the
# dynamic loader (LD_*) or Python (PYTHON*), or redirecting executable resolution
# (PATH/IFS). ENGINE-SPECIFIC dangerous keys (a clippyshot inner-sandbox selector, a
# redtusk JVM binary/jar/opts path, …) are NOT named here — blastbox stays engine-
# agnostic; each engine declares its own reserved keys via the per-engine
# ``EngineSpec.reserved_param_keys`` (BLASTBOX_ENGINE_<NAME>_RESERVED_KEYS), unioned in
# below. The per-engine default-deny allowlist is the primary control; this floor +
# the engine's declared reserved set are the unconditional belt-and-suspenders.
_RESERVED_ENV_PREFIXES = ("BLASTBOX_", "LD_", "PYTHON")
_RESERVED_ENV_KEYS = frozenset({
    # Executable/command resolution — a client setting PATH (or IFS) could redirect the
    # worker's `java`/`soffice`/`python` lookup to an attacker-planted binary under a
    # writable mount (e.g. /tmp), i.e. arbitrary code as the worker uid. LD_* is already
    # prefix-reserved; PATH/IFS close the rest of the loader/shell-resolution surface.
    "PATH",
    "IFS",
})


def _is_reserved_env_key(key: str, engine_reserved: frozenset[str] = frozenset()) -> bool:
    return (
        key in _RESERVED_ENV_KEYS
        or key in engine_reserved
        or key.startswith(_RESERVED_ENV_PREFIXES)
    )


def _build_result_summary(envelope) -> dict:
    """Small derivative of the envelope persisted on the Job for list views — kept
    minimal so the generic job layer stays small. Carries the generic detection
    label + a bounded set of the engine's SCALAR payload fields (page counts,
    labels, …) so a list view can show them without fetching /metadata. Large
    strings (the embedded ``*_metadata`` JSON) and nested structures are excluded.
    """
    det = getattr(envelope, "detected", None)
    summary: dict = {
        "status": envelope.status,
        "artifact_count": len(envelope.artifacts),
        "warning_count": len(envelope.warnings),
        "detected": getattr(det, "label", None),
    }
    try:
        pm = envelope.payload.metadata
        if pm and pm.fields:
            meta = {
                k: v
                for k, v in pm.fields.items()
                if isinstance(v, (bool, int, float))
                or (isinstance(v, str) and len(v) <= 64)
            }
            if meta:
                summary["meta"] = meta
    except Exception:  # noqa: BLE001 — best-effort enrichment, never fail the job
        pass
    return summary


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
    # Operator-configured allowlist of job.param keys forwardable to the worker as env.
    # None (default) = no allowlist configured (legacy shape+denylist behaviour); a
    # frozenset = ONLY those keys forward (default-deny, per engine) — and an EXPLICITLY
    # EMPTY frozenset blocks ALL client params (it does not collapse to legacy). This keeps
    # the privilege of opening the worker's env namespace with the operator who configures
    # the engine — not any client who can guess a key the worker reads.
    allowed_param_keys: frozenset[str] | None = None
    # Engine-OWNED reserved keys: client params this engine's worker reads that flip its
    # security posture or are code-exec vectors (a clippyshot inner-sandbox selector, a
    # redtusk JVM binary/jar/opts/library path, a CRaC checkpoint dir, …). Dropped from
    # job.params UNCONDITIONALLY — even if allowed_param_keys is unset/misconfigured — so
    # an engine declares its own dangerous keys without blastbox core naming them. The
    # engine-agnostic floor (PATH/IFS/BLASTBOX_*/LD_*/PYTHON*) is separate (module-level).
    reserved_param_keys: frozenset[str] = frozenset()
    # Operator-configured DEFAULT params (BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS): applied for
    # any key a job does NOT set, so the job-level value ALWAYS wins. This makes an enablement
    # default (e.g. a scanner toggle) a *runtime* decision in the dispatcher env instead of a
    # value hardcoded in the engine — flip it + restart the dispatcher, no image/snapshot
    # rebuild, and it reaches cold AND warm tiers (warm.py injects forwarded params into the
    # guest env before detonate). Merged UNDER job.params then passed through the SAME
    # _sanitize_params gate (shape + engine-agnostic floor + reserved + allowlist): a defaulted
    # key must itself be forwardable (allowlisted, if an allowlist is set) and non-reserved —
    # one gate, fail-closed, no broader trust path for operator policy than for client params.
    default_params: dict[str, str] = field(default_factory=dict)
    # Per-engine DEFAULT network personality (BLASTBOX_ENGINE_<NAME>_NETPOLICY). Ships "none"
    # (no egress). Resolved per job against the operator's personality registry, fail-closed
    # (see netpolicy.resolve_net_policy). Runtime-configurable like default_params: flip the
    # env + restart the dispatcher, no rebuild. This task only carries it; applying it is later.
    net_policy: str = "none"


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
        max_queued_age_s: float = 0.0,
        pool: "WarmPool | None" = None,
        tier: str = "cold",
        warm_claim_timeout_s: float = 2.0,
        requeue_grace_s: float = 60.0,
        warm_only: bool = False,
        warm_requeue_backoff_s: float = 1.0,
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
        # Opt-in ceiling (0 = off) on how long a job may sit QUEUED before the maintenance sweep
        # FAILs it + deletes its input. Bounds the target_tier footgun: a job pinned to a tier
        # with no running dispatcher is claimable by nobody and would otherwise persist forever.
        self._max_queued_age_s = max(0.0, float(max_queued_age_s))
        self._pool = pool
        self._warm_claim_timeout_s = float(warm_claim_timeout_s)
        self._requeue_grace_s = max(0.0, float(requeue_grace_s))
        # Warm-ONLY dispatcher (a socket-less warm-pool SIDECAR, e.g. the gVisor C/R or
        # Firecracker tier): on a warm-pool miss, RE-QUEUE the job instead of cold-falling-back.
        # Such a sidecar holds NO docker socket, so _dispatch_inner (cold) would fail closed
        # ("runtime 'runc' is insecure: runsc unavailable") and FAIL the job rather than let the
        # cold dispatcher take it. Only meaningful WITH a pool (guarded at the call site); a
        # warm-only dispatcher with no pool would requeue every job forever, so it stays inert
        # there and the cold path runs. Requires a separate cold dispatcher to drain overflow.
        self._warm_only = bool(warm_only)
        # Backoff after a warm-only requeue. dispatch_once() returns True (a job WAS claimed),
        # so run_forever does NOT sleep its poll interval and would immediately re-claim — and the
        # job we just released to QUEUED is the oldest, so THIS dispatcher would keep re-grabbing
        # it, starving the cold dispatcher and churning the job store. (Not a tight CPU loop:
        # pool.claim already blocks up to warm_claim_timeout_s each iteration.) Sleeping briefly
        # before returning yields the requeued job to a peer dispatcher / lets a warm slot free.
        self._warm_requeue_backoff_s = max(0.0, float(warm_requeue_backoff_s))
        # Safety floor for warm recovery: the warm staleness cutoff anchors on started_at (set at
        # CLAIM time), but a warm job's bounding deadline is only established later — after
        # pool.claim (<= warm_claim_timeout_s) + input staging. requeue_grace_s is the slack that
        # must cover that pre-deadline overhead, so a concurrent dispatcher never judges a live
        # warm job stale. Floor it at the claim window when a pool is configured.
        if self._pool is not None:
            self._requeue_grace_s = max(self._requeue_grace_s, self._warm_claim_timeout_s)
        # Warm-pool SIDECAR mode: claim a job ONLY when a warm slot is free (claim-gate) and
        # NEVER cold-fall-back — overflow stays queued for the cold dispatcher / other warm
        # sidecars. This lets a single-purpose, socket-less warm dispatcher run beside the
        # hardened cold one, with each warm backend's privilege (FC: /dev/kvm; gVisor: scoped
        # caps) confined to it. The main dispatcher keeps the docker socket + full hardening.
        # (self._warm_only is set above, grouped with the warm-pool/backoff init.)
        if self._warm_only and self._pool is None:
            raise ValueError(
                "warm_only dispatcher requires a warm pool (set BLASTBOX_POOL_RUNTIME)"
            )

        # This dispatcher's tier identity ("cold"/"firecracker"/"gvisor"), for optional per-job
        # routing (target_tier) and the warm-backend result label (worker_tier). Passed to
        # claim_next so a job targeting a specific tier is only claimed here when it matches; an
        # untargeted job (the default) is claimable by every tier. The CALLER derives this
        # (the CLI from BLASTBOX_POOL_RUNTIME, validated against the built pool — see
        # _dispatch_cmd) so the Dispatcher stays env-agnostic and a misconfig fails fast there,
        # not by silently mislabeling warm jobs as cold here. Inert until an operator enables
        # routing at the API (BLASTBOX_ALLOW_TIER_ROUTING) — existing jobs have no target.
        self._tier = tier

        # Personality registry built ONCE from the operator env (does not change per job).
        from blastbox.host.netpolicy import parse_personalities
        self._net_policies = parse_personalities(os.environ)
        self._allow_net_override = os.environ.get(
            "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", ""
        ).strip().lower() in ("1", "true", "yes", "on")
        # Per-job packet capture (opt-in). When on, egress workers are LABELLED for blastbox-netd
        # (the privileged host capture helper) and the resulting host-only pcap is sealed into the
        # envelope as a trusted artifact. Default OFF — capture has storage/privacy implications and
        # needs netd running; the dispatcher itself stays cap-drop=ALL and never captures.
        self._net_capture = os.environ.get(
            "BLASTBOX_NET_CAPTURE", ""
        ).strip().lower() in ("1", "true", "yes", "on")
        # Optional TLS decrypt of the capture (P5): when on AND a keylog sits in the job's capture
        # dir, run GoGoRoboCap to seal decrypted+mixed pcaps alongside the raw capture. Default off
        # (needs the binary + key material); a hostile/absent keylog is a silent no-op.
        self._net_decrypt = os.environ.get(
            "BLASTBOX_NET_DECRYPT", ""
        ).strip().lower() in ("1", "true", "yes", "on")
        self._gogorobocap_bin = (
            os.environ.get("BLASTBOX_GOGOROBOCAP_BIN") or "gogorobocap"
        ).strip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch_once(self) -> bool:
        """Claim and dispatch the next queued job.

        Returns True if a job was claimed, False if the queue was empty.
        """
        # Warm-sidecar claim-gate: don't pull a job unless a warm slot is free right NOW.
        # Overflow stays queued for the cold dispatcher / another warm sidecar — a warm-only
        # dispatcher has no cold path, so it must not claim work it can't immediately serve.
        if self._warm_only and (self._pool is None or self._pool.idle_count <= 0):
            return False
        job = self._job_store.claim_next(claimant_tier=self._tier)
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
        concurrency: int = 1,
    ) -> None:
        """Continuously claim and dispatch jobs until ``stop()`` returns True.

        Every ``maintenance_interval_s`` it also runs _run_maintenance: requeue orphaned RUNNING
        jobs (crash recovery) and expire retention-due artifacts (so untrusted output doesn't
        accumulate forever). Set ``maintenance_interval_s<=0`` to disable.

        ``concurrency`` > 1 runs that many dispatch-loop threads (each claims+dispatches
        independently; correctness comes from the claim fence + the thread-safe stores). Each
        concurrent worker is one more in-flight detonation, so size
        ``BLASTBOX_WORKER_MEMORY * concurrency`` to the host's RAM.
        """
        if max(1, int(concurrency)) > 1:
            self._run_forever_concurrent(
                poll_interval_s=poll_interval_s,
                stop=stop,
                maintenance_interval_s=maintenance_interval_s,
                concurrency=int(concurrency),
            )
            return
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

    def _run_forever_concurrent(
        self,
        *,
        poll_interval_s: float,
        stop: "Callable[[], bool] | None",
        maintenance_interval_s: float,
        concurrency: int,
    ) -> None:
        """N dispatch-loop threads claim+dispatch independently; maintenance runs from
        this coordinator thread (a global sweep — must NOT run N times concurrently)."""
        stop_evt = threading.Event()

        def _should_stop() -> bool:
            return stop_evt.is_set() or (stop is not None and stop())

        def _worker() -> None:
            while not _should_stop():
                try:
                    progressed = self.dispatch_once()
                except Exception:  # noqa: BLE001
                    _log.exception("dispatch_once failed; continuing")
                    progressed = False
                if not progressed:
                    time.sleep(poll_interval_s)

        threads = [
            threading.Thread(target=_worker, name=f"bb-dispatch-{i}", daemon=True)
            for i in range(concurrency)
        ]
        for t in threads:
            t.start()
        last_maint = time.monotonic()
        try:
            while not _should_stop():
                if (
                    maintenance_interval_s > 0
                    and time.monotonic() - last_maint >= maintenance_interval_s
                ):
                    last_maint = time.monotonic()
                    self._run_maintenance()
                time.sleep(min(poll_interval_s, 1.0))
        finally:
            stop_evt.set()
            # Collective deadline: bound TOTAL shutdown to ~(worker_timeout+5), not
            # concurrency*(worker_timeout) — sequential joins each with the full timeout
            # would accumulate if several threads are mid-detonation.
            join_deadline = time.monotonic() + self._worker_timeout_s + 5
            for t in threads:
                t.join(timeout=max(0.0, join_deadline - time.monotonic()))

    def requeue_orphaned_jobs(self, *, exclude: frozenset[str] | None = None) -> int:
        """Recover RUNNING jobs whose owning dispatcher is gone, in two independent passes.

        WARM pass (first; needs NO docker): warm slots have no docker label, so liveness is
        TIME-based — a warm job still RUNNING past ``worker_timeout_s + requeue_grace_s`` (from a
        started_at that ``_dispatch_warm`` refreshes before its sealing phase) has a gone owner.
        It is FAILED (terminal), NOT requeued — a requeue would let a second worker re-detonate
        the same untrusted input, and orphaned sandboxes don't die with a crashed dispatcher.
        Running this pass first means a ``docker ps`` failure can't strand warm jobs.

        COLD pass (needs docker): uses ``docker ps --filter label=blastbox.role=worker`` to find
        live worker containers; a cold job absent from it (and past the grace window) is requeued.
        On a ``docker ps`` failure the COLD pass is skipped (fail-safe — never requeue a job that
        may still be live), but the WARM pass already ran.

        All recovery + terminal writes are CAS-fenced on (status, claim_id), so a stale owner can
        never clobber a job that was reclaimed (RUNNING->QUEUED->RUNNING), and recovery never
        clobbers a terminal status the owner wrote.

        ``exclude`` is an optional set of job_ids to skip (claimed in-process this tick).
        """
        excluded = exclude or frozenset()
        now = time.time()
        grace_cutoff = now - self._requeue_grace_s
        warm_stale_cutoff = now - (self._worker_timeout_s + self._requeue_grace_s)
        running = self._job_store.list(status=JobStatus.RUNNING)
        recovered = 0

        # --- WARM recovery (time-based; needs NO docker) -------------------------------------
        # A warm slot carries no docker label, so docker ps can't attest its liveness — recovery
        # is purely TIME-based, so it runs FIRST and is NOT blocked by a docker-ps failure. A warm
        # job still RUNNING past worker_timeout_s + grace (started_at refreshed before the bounded
        # sealing phase) has a GONE owner; we FAIL it (terminal), NOT requeue — a requeue would let
        # a second worker re-detonate the same untrusted input, and orphaned sandboxes don't die
        # with a crashed dispatcher. CAS-fenced on (RUNNING, the observed claim_id): never clobbers
        # a terminal status the owner wrote, and never fails a job that was reclaimed (ABA-safe).
        for job in running:
            if job.job_id in excluded or job.worker_runtime != "warm":
                continue
            if job.started_at is None or job.started_at >= warm_stale_cutoff:
                continue
            if self._fail_if_running(
                job,
                "warm worker abandoned: owning dispatcher gone "
                f"(no progress for >{self._worker_timeout_s + self._requeue_grace_s:.0f}s)",
                warning="recovered: warm worker owner gone",
            ):
                recovered += 1
                # The owner is gone and the job is now terminal (FAILED is not claim_next-able),
                # so nothing else will clean up its staged input. Delete it here so a recovered
                # job's untrusted input doesn't leak on disk even when retention is disabled.
                self._delete_input(
                    self._job_root / job.job_id / "input" / Path(job.filename).name
                )

        # --- COLD requeue (needs docker liveness) -------------------------------------------
        active_job_ids = self._list_active_worker_job_ids()
        if active_job_ids is None:
            # docker ps failed — skip cold requeue (warm recovery above already ran).
            return recovered
        for job in running:
            if (
                job.job_id in excluded
                or job.job_id in active_job_ids
                or job.worker_runtime == "warm"  # handled above
            ):
                continue
            # Grace window: a just-claimed cold job's worker container may not appear in
            # `docker ps` yet, so requeuing it now would double-detonate the same (malicious)
            # input in two workers. Only requeue jobs whose started_at is older than the window.
            if job.started_at is not None and job.started_at > grace_cutoff:
                continue
            # Claim-fenced (RUNNING, observed claim_id) so we never requeue a job that was
            # reclaimed since the list() snapshot, and clear claim_id so the next claim is fresh.
            if self._job_store.update_if_status(
                job.job_id,
                JobStatus.RUNNING,
                expect_claim_id=job.claim_id,
                status=JobStatus.QUEUED,
                started_at=None,
                worker_runtime=None,
                # Clear the warm-backend label too, so a re-dispatch by a different tier never
                # inherits a stale one (defensive: this cold path skips warm jobs today, so the
                # field is None here — but keep worker_runtime/worker_tier reset in lockstep).
                worker_tier=None,
                claim_id=None,
                security_warnings=[
                    *job.security_warnings,
                    "requeued: worker container disappeared",
                ],
                error=None,
            ):
                recovered += 1
        return recovered

    def _fail_if_running(self, job: Job, reason: str, *, warning: str | None = None) -> bool:
        """CAS terminal-fail: mark ``job`` FAILED only while it is STILL RUNNING (so a concurrent
        terminal write by its owner is never clobbered). Mirrors ``_fail_job``'s fields + error
        scrubbing + retention expiry. Returns whether the transition applied."""
        finished_at = time.time()
        expires_at = (
            finished_at + self._job_retention_seconds
            if self._job_retention_seconds > 0
            else None
        )
        fields: dict = dict(
            status=JobStatus.FAILED,
            finished_at=finished_at,
            expires_at=expires_at,
            error=sanitize_public_error(reason),
        )
        if warning is not None:
            fields["security_warnings"] = [*job.security_warnings, warning]
        # Fence on the claim_id observed in the list() snapshot: if the job was reclaimed
        # (RUNNING->QUEUED->RUNNING with a new claim) since we read it, do NOT fail the fresh
        # claim — closes the status-only ABA hole.
        return self._job_store.update_if_status(
            job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id, **fields
        )

    # ------------------------------------------------------------------
    # Internal dispatch flow
    # ------------------------------------------------------------------

    def _dispatch_claimed_job(self, job: Job) -> None:
        """Execute one claimed job (status is already RUNNING on entry).

        Security: input is deleted via a finally block on every branch — but only when we
        still own the claim (``_delete_input_if_owned``); a job a peer reclaimed keeps its
        input for the new owner (the recovery sweep deletes a time-recovered job's input).

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
                # Staged input is deleted in the finally block (only if we still own the claim;
                # a reclaimed job's input is left for the new owner — see _delete_input_if_owned).
                t0 = time.monotonic()
                try:
                    self._dispatch_warm(
                        job, staged_input_path=input_path, slot=slot, output_dir=output_dir
                    )
                finally:
                    # Delete the staged input on every terminal path WE own.
                    self._delete_input_if_owned(job, input_path)
                    self._record_outcome(job, path="warm", started=t0)
                return
            elif self._warm_only:
                # Warm-only sidecar: do NOT cold-fall-back (no docker socket here — the cold
                # path would fail closed and FAIL the job). Release the claim back to QUEUED so
                # the cold dispatcher (or another warm tier) claims it. CAS-fenced on OUR
                # claim_id and clears it, so a job reclaimed since we claimed is left untouched;
                # started_at/worker_runtime are reset so it looks fresh. The staged input is NOT
                # deleted — the next owner needs it (we only delete input on paths WE terminate).
                requeued = self._job_store.update_if_status(
                    job.job_id,
                    JobStatus.RUNNING,
                    expect_claim_id=job.claim_id,
                    status=JobStatus.QUEUED,
                    started_at=None,
                    worker_runtime=None,
                    worker_tier=None,  # reset in lockstep with worker_runtime (see cold requeue)
                    claim_id=None,
                    error=None,
                )
                _log.info(
                    "warm_pool_miss job_id=%s; warm_only requeue=%s (no cold fallback)",
                    job.job_id,
                    requeued,
                )
                # Yield before returning: dispatch_once() reports progress (a job was claimed),
                # so run_forever loops without its poll sleep — without this, THIS dispatcher
                # re-claims the just-requeued job in a ~warm_claim_timeout_s-paced churn loop and
                # the cold dispatcher never gets a turn at it. The backoff hands it off.
                if self._warm_requeue_backoff_s:
                    time.sleep(self._warm_requeue_backoff_s)
                return
            else:
                _log.info("warm_pool_miss job_id=%s; falling back to cold path", job.job_id)

        # COLD PATH (default / fallback)
        t0 = time.monotonic()
        try:
            self._dispatch_inner(job, input_path, output_dir)
        finally:
            # Delete the malicious input on every terminal path WE own, regardless of success,
            # failure, exception, or unknown engine. We never touch output/ here.
            self._delete_input_if_owned(job, input_path)
            self._record_outcome(job, path="cold", started=t0)

    def _delete_input_if_owned(self, job: Job, input_path: Path) -> None:
        """Delete the shared staged input ONLY if we still hold the claim (or the job
        terminalized under it). The input at job_root/<id>/input is spooled ONCE at submission
        and shared across reclaims; if a peer dispatcher requeued+reclaimed this job (claim_id
        changed/cleared — e.g. we ABORTED a lost claim), the NEW owner still needs it on disk, so
        we must NOT delete it. On the normal owned terminal path claim_id still matches and the
        untrusted input is deleted exactly as before; a leak only occurs if the reclaiming owner
        also dies before its own cleanup, bounded by the retention sweep of job_root/<id>."""
        final = self._job_store.get(job.job_id)
        if final is None or final.claim_id == job.claim_id:
            self._delete_input(input_path)
        else:
            _log.info(
                "job %s reclaimed by another dispatcher (claim changed); leaving its staged "
                "input for the new owner", job.job_id,
            )

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
            # Step 2: Mark warm BEFORE staging (claim-fenced).
            # A slow staging copy (e.g. the gVisor input copy) would otherwise leave the job
            # looking COLD (worker_runtime=None) to a PEER dispatcher's maintenance sweep, which
            # would docker-ps-requeue it (a warm job has no container) and double-detonate. Mark
            # warm first so the sweep routes it to time-based warm recovery. CAS on our claim so
            # if a peer already requeued/reclaimed it we abort BEFORE staging+detonating.
            # ------------------------------------------------------------------
            if not self._job_store.update_if_status(
                job.job_id,
                JobStatus.RUNNING,
                expect_claim_id=job.claim_id,
                worker_runtime="warm",
                # Disambiguate the two warm backends in the result (both else report just
                # "warm"): self._tier is "firecracker"/"gvisor" on a warm dispatcher.
                worker_tier=self._tier,
            ):
                _log.warning(
                    "warm job %s lost its claim before staging (requeued/recovered by another "
                    "dispatcher); aborting", job.job_id,
                )
                return
            job.worker_runtime = "warm"
            job.worker_tier = self._tier

            # ------------------------------------------------------------------
            # Step 3: Stage input — over the wire (vsock) or into slot.input_dir
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
                params=self._sanitize_params(
                    job.params, engine.allowed_param_keys, engine.reserved_param_keys,
                    engine.default_params,
                ),
            )
            # One absolute deadline bounds the input send + wait (the only steps a slow guest
            # can stall) to worker_timeout_s, so the upload (which runs BEFORE the wait) can't
            # pin dispatch. NOTE: the post-wait sealing phase (Step 5b+) is NOT under this
            # deadline; its staleness is covered separately by refreshing started_at below.
            warm_deadline = time.monotonic() + self._worker_timeout_s
            try:
                control.signal_go(spec, deadline=warm_deadline)
            except Exception as exc:  # noqa: BLE001
                self._fail_job(job, f"failed to signal go to warm worker: {exc}")
                return

            # ------------------------------------------------------------------
            # Step 5: Wait for done signal (same deadline; remaining budget after the send)
            # ------------------------------------------------------------------
            remaining = warm_deadline - time.monotonic()
            if remaining <= 0:
                self._fail_job(
                    job, f"warm worker timed out after {self._worker_timeout_s}s"
                )
                return
            try:
                control.wait_for_done(timeout_s=remaining)
            except WarmTimeout:
                self._fail_job(
                    job,
                    f"warm worker timed out after {self._worker_timeout_s}s",
                )
                return

            # The guest is done; the sealing phase below (rdump materialize, output-cap, validate,
            # re-seal of up to max_total_artifact_bytes) is real wall-clock work NOT bounded by
            # warm_deadline. Refresh started_at so requeue_orphaned_jobs (which fails a warm job
            # RUNNING past worker_timeout_s + grace) measures the sealing phase from a fresh clock
            # — otherwise a legitimately slow/large seal could be judged "owner gone" and FAILed
            # out from under a live owner. Claim-fenced (like every other owner write): if a peer
            # already recovered/reclaimed us, abort before the pointless seal.
            if not self._job_store.update_if_status(
                job.job_id,
                JobStatus.RUNNING,
                expect_claim_id=job.claim_id,
                started_at=time.time(),
            ):
                _log.warning(
                    "warm job %s lost its claim before sealing (recovered/reclaimed by another "
                    "dispatcher); aborting", job.job_id,
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

            # The trust gate validates output STRUCTURE, not the engine's verdict: an engine that
            # honestly reports a FAILED conversion (status="engine_error", typically 0 artifacts)
            # still produces a structurally valid envelope. Gate on it here — else a failed convert
            # is silently marked DONE (a false green that lets a broken warm tier pass a corpus).
            # "rejected" (unsupported/encrypted input) is a legitimate engine verdict, not an error,
            # so it stays DONE.
            if envelope.status == "engine_error":
                detail = envelope.warnings[0].message if envelope.warnings else "engine_error"
                self._fail_job(job, f"engine_error: {detail}")
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
            result_summary = _build_result_summary(envelope)
            # CAS-fence the terminal DONE on RUNNING (symmetric with the recovery FAIL): under a
            # multi-dispatcher topology a peer may have already FAILED this warm job as stale (its
            # output possibly retention-deleted). A blind DONE would resurrect that terminal state
            # to DONE with no artifacts on disk + a self-contradictory "owner gone" warning. "First
            # writer wins": if the job is no longer RUNNING, leave the recovery's terminal state.
            applied = self._job_store.update_if_status(
                job.job_id,
                JobStatus.RUNNING,
                expect_claim_id=job.claim_id,
                status=JobStatus.DONE,
                finished_at=finished_at,
                expires_at=expires_at,
                result_summary=result_summary,
                error=None,
            )
            if not applied:
                _log.warning(
                    "warm job %s no longer our RUNNING claim at DONE write (recovered/reclaimed "
                    "by another dispatcher); leaving its terminal state untouched",
                    job.job_id,
                )
            else:
                # DONE applied + still ours: index per-page perceptual hashes for /similar.
                self._index_page_hashes(job.job_id, envelope)

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

        # Build the worker argv BEFORE the claim-fenced RUNNING write below, so the persisted
        # security_warnings are complete: build_worker_docker_run_argv() appends the
        # nono-skipped-under-runsc / missing-AppArmor / missing-seccomp warnings onto
        # runtime.warnings. argv assembly is pure (no filesystem or container side effects), so
        # doing it here cannot lose the claim or launch anything early.

        # Resolve the effective network personality FAIL-CLOSED. Uses the registry built once at
        # __init__ (from the operator env), the per-engine default (engine.net_policy), and the
        # per-job override (only honoured when BLASTBOX_ALLOW_NETPOLICY_OVERRIDE is set). Any
        # unknown driver falls back to --network=none in docker_network_args.
        from blastbox.host.netpolicy import resolve_net_policy
        from blastbox.host.netapply import docker_network_args, worker_resolv_conf
        personality = resolve_net_policy(
            job_net_policy=job.net_policy,
            engine_default=engine.net_policy,
            registry=self._net_policies,
            allow_override=self._allow_net_override,
        )
        _log.info(
            "net_policy_resolved job=%s personality=%s driver=%s",
            job.job_id, personality.name, personality.exit_driver,
        )
        network_args = docker_network_args(personality)

        # Optional resolv.conf injection for an egress personality (per-personality ``dns=``).
        # On a docker user-defined bridge the worker's only nameserver is docker's embedded
        # 127.0.0.11 — unreachable from a gVisor (runsc) worker — so without this an egress
        # worker on the default cold runtime gets L3 connectivity but cannot resolve names.
        # Compute the path now so it lands in the argv; the file is written below, once the job
        # dir exists (it's a sibling of output/, never inside the /output mount).
        resolv_conf_content = worker_resolv_conf(personality)
        resolv_conf_src: str | None = (
            str(output_dir.parent / "resolv.conf") if resolv_conf_content else None
        )

        # Per-job capture: label the worker for blastbox-netd ONLY when capture is enabled AND
        # the personality actually has egress (none/drop have no traffic to capture). netd reads
        # this label off `docker events`; the dispatcher never touches a raw socket.
        capture_on = self._net_capture and personality.exit_driver not in ("none", "drop")
        worker_labels = {
            "blastbox.role": "worker",
            "blastbox.job_id": job.job_id,
        }
        if capture_on:
            worker_labels["blastbox.net.capture"] = "1"
        # SOCKS / VPN personalities run the worker on an INTERNAL bridge (no direct egress); netd
        # wires the only route out in the worker netns. The label requests that wiring by mode;
        # until netd wires it the worker simply has no egress (fail-closed).
        #   socks (tor/BrightData)         → tun2socks in the netns   (bb-socks)
        #   openvpn / wireguard (all-IP)   → default route via gateway (bb-vpn)
        if personality.exit_driver == "socks":
            worker_labels["blastbox.net.wire"] = "socks"
        elif personality.exit_driver in ("openvpn", "wireguard"):
            worker_labels["blastbox.net.wire"] = "vpn"

        container_name = f"blastbox-worker-{job.job_id[:12]}"
        argv = build_worker_docker_run_argv(
            image=engine.image,          # NEVER job.engine / job.filename / job.params
            input_path=input_path,
            input_mount_path=f"/input/{input_path.name}",
            output_dir=output_dir,
            output_mount_path="/output",
            worker_argv=list(engine.worker_argv),
            runtime=runtime,
            network_args=network_args,
            resolv_conf_src=resolv_conf_src,
            container_name=container_name,
            labels=worker_labels,
            extra_env={
                **self._sanitize_params(
                    job.params, engine.allowed_param_keys, engine.reserved_param_keys,
                    engine.default_params,
                ),
                # Tell the harness where the dispatcher mounted I/O (it mounts the input file at
                # /input/<name> and output at /output; the harness defaults are /in,/out, so
                # without this the cold path is broken-as-wired). Dispatcher-set keys are merged
                # LAST so a hostile job.param can't override them.
                "BLASTBOX_INPUT_DIR": "/input",
                "BLASTBOX_OUTPUT_DIR": "/output",
                # Tell an engine that nests an inner namespace sandbox (bwrap/nsjail) whether to
                # NET-SHARE the worker's (rooter-routed) netns or ISOLATE it. Only personalities
                # with an actual exit grant egress; none/drop stay sealed. Set EXPLICITLY (merged
                # last, after job.params) so a hostile job.param can't flip a sealed worker open.
                "BLASTBOX_NET_EGRESS": (
                    "1" if personality.exit_driver not in ("none", "drop") else "0"
                ),
            },
        )

        # Enrich the RUNNING job with runtime info — claim-fenced (the cold twin of the warm
        # mark-warm fence). _runtime_selector() can block on `docker info` (no timeout); a peer's
        # docker-ps requeue can fire during that stall and reclaim the row under a new claim. A
        # BLIND write here would overwrite worker_runtime on the reclaimed job — mis-routing the
        # peer's warm-vs-cold recovery (a relabeled warm job gets cold-requeued -> re-detonation).
        # If we lost the claim, abort BEFORE launching our own (stale) worker.
        if not self._job_store.update_if_status(
            job.job_id,
            JobStatus.RUNNING,
            expect_claim_id=job.claim_id,
            worker_runtime=runtime.runtime,
            security_warnings=list(job.security_warnings) + list(runtime.warnings),
        ):
            _log.warning(
                "cold job %s lost its claim before launch (requeued/reclaimed by another "
                "dispatcher); aborting before detonation", job.job_id,
            )
            return

        # ------------------------------------------------------------------
        # Step 4: Launch worker container (argv already built above, before the
        # claim-fenced RUNNING write, so security_warnings persisted complete).
        # ------------------------------------------------------------------
        # The worker runs unprivileged (--user 10001:10001); make the output bind
        # dir writable by it (cold-path parity with the warm /out 0o777). The host
        # re-seals + size-caps the result regardless, so 0o777 here widens no trust
        # boundary — the worker's output is untrusted on every path.
        # Wipe-then-recreate for a clean slate (mirrors the warm path): a requeued
        # job must NOT inherit files a prior crashed/compromised worker left behind —
        # stale undeclared files would otherwise count against the output size cap
        # (a spurious-failure DoS) and, pre the serve-route manifest check, be
        # servable. The host owns this dir between attempts, so the wipe is safe.
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(output_dir, 0o777)

        # Materialize the egress resolv.conf (its path is already wired into argv) now that the
        # per-job dir exists. Written to the job root, a sibling of output/, so it is never
        # visible in the worker's /output artifacts; only the single file is bind-mounted.
        if resolv_conf_src and resolv_conf_content:
            Path(resolv_conf_src).write_text(resolv_conf_content, encoding="ascii")

        try:
            # Run to completion (or timeout). The worker's exit code is not the
            # authority — the trust gate below decides DONE/FAILED from the
            # re-sealed output. capture_output keeps worker stdio off our streams.
            proc = self._subprocess_runner(
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

        # The worker's exit code is NOT the authority (the trust gate below is), but a non-zero
        # `docker run` (e.g. a malformed flag → RC 125 "invalid argument for --memory", or an
        # OOM-killed worker) produces NO output, so the trust gate then fails with an opaque
        # "metadata.json not found". Log the launcher's exit + stderr tail so that whole class of
        # launch failure is diagnosable instead of being silently mislabeled as missing output.
        launch_rc = getattr(proc, "returncode", None)
        if launch_rc:
            stderr_tail = (getattr(proc, "stderr", "") or "")[-500:].strip()
            _log.warning(
                "worker launcher for job %s exited rc=%s (output is trust-gated regardless); "
                "docker/worker stderr tail: %s",
                job.job_id,
                launch_rc,
                stderr_tail,
            )

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

        # The trust gate validates output STRUCTURE, not the engine's verdict: a structurally valid
        # envelope can still report a FAILED conversion (status="engine_error"). Gate on it here —
        # else a failed convert is silently marked DONE (a false green). "rejected" (unsupported/
        # encrypted input) is a legitimate engine verdict, not an error, so it stays DONE.
        if envelope.status == "engine_error":
            detail = envelope.warnings[0].message if envelope.warnings else "engine_error"
            self._fail_job(job, f"engine_error: {detail}")
            return

        # Fold a per-job network capture (if blastbox-netd produced one) into the sealed envelope
        # as a TRUSTED host artifact. The pcap lives off the worker /output mount, so the worker
        # never had write access to it; the host hashes it here. Best-effort — a missing/empty
        # capture (netd not running, or a none/drop personality) is a silent no-op.
        if capture_on:
            envelope = self._seal_network_capture(envelope, output_dir)
            if self._net_decrypt:
                envelope = self._seal_decrypted_capture(envelope, output_dir)

        # Persist the host-SEALED metadata over the worker's raw file so the API serves trusted
        # hashes/sizes/payload, not worker-fabricated ones (#5).
        self._write_sealed_metadata(envelope, output_dir)

        # The output dir was 0o777 so the unprivileged worker (uid 10001) could write it. The
        # worker is done and the host has re-sealed, so re-tighten to close the post-seal tamper
        # window before the ingress serves these bytes (served files are NOT re-hashed per request).
        # Best-effort: a chmod failure must not fail an otherwise-valid, sealed job.
        try:
            os.chmod(output_dir, 0o755)
        except OSError:
            pass

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
        result_summary = _build_result_summary(envelope)
        # Claim-fenced (RUNNING, our claim_id): a peer's docker-ps sweep on another host can't
        # see this container, so it may have requeued the job; don't resurrect a reclaimed job to
        # DONE with this (stale) detonation's result.
        if not self._job_store.update_if_status(
            job.job_id,
            JobStatus.RUNNING,
            expect_claim_id=job.claim_id,
            status=JobStatus.DONE,
            finished_at=finished_at,
            expires_at=expires_at,
            result_summary=result_summary,
            error=None,
        ):
            _log.warning(
                "cold job %s no longer our RUNNING claim at DONE write (recovered/reclaimed by "
                "another dispatcher); leaving its terminal state untouched",
                job.job_id,
            )
            return
        # DONE applied + still ours: index per-page perceptual hashes for /similar search.
        self._index_page_hashes(job.job_id, envelope)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _index_page_hashes(self, job_id: str, envelope: object) -> None:
        """Best-effort: index the job's per-page perceptual hashes (phash/colorhash/
        sha256) for similarity search. Only the Postgres + pg_bktree store can serve
        search, so gate on ``supports_hash_search()`` — a SQL store on SQLite / plain
        Postgres *has* the method but it raises; memory/redis lack it entirely. An
        indexing failure NEVER fails an otherwise-DONE job."""
        supports = getattr(self._job_store, "supports_hash_search", None)
        indexer = getattr(self._job_store, "index_page_hashes", None)
        if supports is None or indexer is None or not supports():
            return
        try:
            indexer(job_id, envelope)
        except Exception:  # noqa: BLE001
            _log.exception("page-hash indexing failed for job %s; continuing", job_id)

    def _fail_stale_queued_jobs(self) -> int:
        """FAIL jobs stuck QUEUED past ``max_queued_age_s`` and delete their (untrusted) input.

        Opt-in (0 = disabled → no-op, the default). Bounds the ``target_tier`` footgun: a job
        pinned to a tier with no running dispatcher is claimable by nobody and the retention
        sweep only touches TERMINAL jobs, so it would otherwise sit QUEUED with its input on disk
        forever. CAS on QUEUED so a job claimed since the ``list()`` snapshot (→ RUNNING) is left
        to its claimer untouched. Returns the count failed."""
        if self._max_queued_age_s <= 0:
            return 0
        cutoff = time.time() - self._max_queued_age_s
        failed = 0
        for job in self._job_store.list(status=JobStatus.QUEUED):
            if job.created_at > cutoff:
                continue
            finished_at = time.time()
            expires_at = (
                finished_at + self._job_retention_seconds
                if self._job_retention_seconds > 0
                else None
            )
            if self._job_store.update_if_status(
                job.job_id,
                JobStatus.QUEUED,
                status=JobStatus.FAILED,
                finished_at=finished_at,
                expires_at=expires_at,
                error=sanitize_public_error(
                    f"job exceeded the max queued age ({self._max_queued_age_s:.0f}s) without "
                    f"being claimed (no dispatcher for target_tier={job.target_tier!r}?)"
                ),
            ):
                failed += 1
                self._delete_input(
                    self._job_root / job.job_id / "input" / Path(job.filename).name
                )
        if failed:
            _log.info("stale_queued_failed count=%d", failed)
        return failed

    def _fail_job(self, job: Job, reason: str) -> None:
        """Mark a job FAILED, scrubbing the error string before storage.

        Claim-fenced on (RUNNING, our claim_id): if a peer dispatcher already requeued/recovered
        this job, the owner's FAILED is a no-op (don't clobber the new owner's state). In the
        normal path the job is RUNNING under our claim, so it applies as before."""
        error = sanitize_public_error(reason)
        finished_at = time.time()
        expires_at = (
            finished_at + self._job_retention_seconds
            if self._job_retention_seconds > 0
            else None
        )
        self._job_store.update_if_status(
            job.job_id,
            JobStatus.RUNNING,
            expect_claim_id=job.claim_id,
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

    def _seal_network_capture(self, envelope, output_dir: Path):
        """Fold blastbox-netd's per-job pcap into the sealed envelope as a TRUSTED host artifact.

        netd writes the capture to ``<job_root>/<id>/capture/dump.pcap`` — a sibling of
        ``output/``, OFF the worker ``/output`` mount, so the untrusted worker never had write
        access to it. We move it INTO ``output_dir/capture/`` (so the ingress serve route, which
        confines artifacts to the output dir, can serve it), host-hash it, and append an
        :class:`Artifact`. Best-effort: any miss (no pcap, empty, oversized, copy/hash error)
        leaves the envelope unchanged so a capture hiccup never fails an otherwise-valid job.
        """
        src = output_dir.parent / "capture" / "dump.pcap"
        try:
            if not src.is_file() or src.stat().st_size == 0:
                return envelope
            size = src.stat().st_size
            if size > self._limits.max_artifact_bytes:
                _log.warning(
                    "netd capture for output %s is %d bytes (> max_artifact_bytes %d); not sealed",
                    output_dir, size, self._limits.max_artifact_bytes,
                )
                return envelope
            dst_dir = output_dir / "capture"
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / "dump.pcap"
            shutil.copy2(src, dst)
            h = hashlib.sha256()
            with open(dst, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            artifact = Artifact(
                id="network.capture.pcap",
                path="capture/dump.pcap",
                kind="network_capture",
                sha256=h.hexdigest(),
                bytes=dst.stat().st_size,
            )
        except Exception as exc:  # noqa: BLE001 — capture is best-effort, never fail the job
            _log.warning("sealing netd capture for output %s failed: %s", output_dir, exc)
            return envelope
        _log.info("sealed network capture artifact (%d bytes) for output %s", size, output_dir)
        return envelope.model_copy(update={"artifacts": [*envelope.artifacts, artifact]})

    def _seal_decrypted_capture(self, envelope, output_dir: Path):
        """If a TLS keylog sits in the job's capture dir, run GoGoRoboCap over the sealed capture
        pcap to produce decrypted+mixed pcaps and seal them as TRUSTED host artifacts. Best-effort:
        no keylog / no binary / no TLS flows / any error → envelope unchanged. The keylog is a
        host-side input (an sslproxy/MITM sidecar or an instrumented runtime writes it to the
        host-only capture dir); the worker never had write access to the capture dir."""
        from blastbox.host.decrypt import decrypt_capture

        cap_dir = output_dir / "capture"           # the sealed (host-owned) capture dir
        pcap = cap_dir / "dump.pcap"
        keylog = output_dir.parent / "capture" / "sslkeys.log"  # host-only key drop
        if not pcap.is_file() or not keylog.is_file() or keylog.stat().st_size == 0:
            return envelope
        try:
            result = decrypt_capture(
                binary=self._gogorobocap_bin,
                pcap_path=str(pcap),
                keylog_path=str(keylog),
                out_dir=str(cap_dir),
                run_fn=lambda argv: self._subprocess_runner(
                    argv, capture_output=True, text=True, check=False, timeout=300
                ).returncode,
            )
        except Exception as exc:  # noqa: BLE001 — decrypt is best-effort enrichment
            _log.warning("decrypt seal for output %s failed: %s", output_dir, exc)
            return envelope
        if result is None:
            return envelope
        new_artifacts = list(envelope.artifacts)
        for art_id, kind, path in (
            ("network.capture.decrypted.pcap", "network_capture_decrypted", result.decrypted_path),
            ("network.capture.mixed.pcap", "network_capture_mixed", result.mixed_path),
        ):
            if not path:
                continue
            try:
                p = Path(path)
                if not p.is_file() or p.stat().st_size > self._limits.max_artifact_bytes:
                    continue
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                new_artifacts.append(Artifact(
                    id=art_id, path=f"capture/{p.name}", kind=kind,
                    sha256=h.hexdigest(), bytes=p.stat().st_size,
                ))
            except Exception as exc:  # noqa: BLE001
                _log.warning("sealing decrypt artifact %s failed: %s", art_id, exc)
        if len(new_artifacts) == len(envelope.artifacts):
            return envelope
        _log.info("sealed %d decrypted capture artifact(s) for output %s",
                  len(new_artifacts) - len(envelope.artifacts), output_dir)
        return envelope.model_copy(update={"artifacts": new_artifacts})

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
                with confined_atomic_writer(
                    dst_dir, a.path, mode=0o644, dir_mode=0o755
                ) as out_fd:
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
        try:
            self._fail_stale_queued_jobs()
        except Exception:  # noqa: BLE001
            _log.exception("stale-queued sweep failed")
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
    def _sanitize_params(
        params: dict[str, str], allowed_keys: frozenset[str] | None = None,
        reserved_keys: frozenset[str] = frozenset(),
        default_params: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Filter job.params to a safe subset suitable for extra_env.

        ``default_params`` (operator-configured per engine) are applied UNDER ``params``:
        the union ``{**default_params, **params}`` is filtered, so a job-level value always
        overrides the default and a defaulted key still has to clear the SAME gate below
        (shape + reserved + allowlist). This lets an operator make an enablement default a
        runtime decision without widening the trust model — the default reaches the worker
        only if a client param with that key would have, too.

        Security:
        - Keys must match ``^[A-Z][A-Z0-9_]*$`` (uppercase start, no symbols).
          A key like ``"x; --privileged"`` is silently dropped.
        - Reserved keys/prefixes are dropped even though they match the shape
          (BLASTBOX_*, LD_*, PYTHON*, PATH/IFS, and specific security/breadcrumb keys):
          a client must not be able to re-select the engine (BLASTBOX_ENGINE), re-wire
          I/O, flip the security posture (sandbox selection / insecure fallback /
          internals disclosure), or hijack the loader/interpreter resolution.
        - ``allowed_keys`` per-engine ALLOWLIST, with a deliberate None-vs-empty split:
          * ``None`` (UNSET) = no allowlist configured → legacy shape+denylist behaviour.
          * a frozenset (incl. the EMPTY one) = explicit allowlist → ONLY those keys
            forward (default-deny). An explicitly-empty allowlist therefore blocks ALL
            client params — which is what an operator configuring an empty set means,
            and must NOT silently collapse to legacy.
        - Values are capped at _MAX_ENV_VALUE_LEN characters.
        - Everything is coerced to str before inclusion.

        Returns a new dict; never modifies params in place.
        """
        # Operator defaults first, job params second → job wins on key collisions. The merged
        # union is filtered as one, so defaults get no privileged path past the gate.
        merged = {**(default_params or {}), **(params or {})}
        out: dict[str, str] = {}
        for key, value in merged.items():
            if not isinstance(key, str):
                continue
            if not _VALID_ENV_KEY_RE.match(key):
                _log.debug("dropping invalid extra_env key: %r", key)
                continue
            if _is_reserved_env_key(key, reserved_keys):
                _log.warning("dropping reserved extra_env key from job.params/defaults: %r", key)
                continue
            if allowed_keys is not None and key not in allowed_keys:
                _log.warning(
                    "dropping non-allowlisted extra_env key %r from job.params/defaults "
                    "(per-engine allowlist in effect)", key,
                )
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
