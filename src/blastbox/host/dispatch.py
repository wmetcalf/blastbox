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
import contextlib
import logging
import os
import re
import shutil

from blastbox.host.jobs.retention import (
    RESULT_RETAINED_MARKER,
    clear_retained_orphan,
    clear_pending_upload,
    mark_pending_upload,
    mark_retained_orphan,
    purge_job_dir,
    _blob_local_roots,
    reap_stale_scratch,
    retry_pending_uploads,
)
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Collection, Mapping

from blastbox.host.pool import release_kwargs
from blastbox.contract.envelope import (
    Artifact,
    atomic_write_confined,
    confined_atomic_writer,
    open_confined_regular_fd,
)
from blastbox.errors import HOST_RESOURCE_ERRNOS, OutputTrustError, OutputTrustUnknown, WarmTimeout, sanitize_public_error
from blastbox.host.blobs.base import BlobFetchError, BlobStore, upload_output_with_retry
from blastbox.host.canary import (
    CanaryFailure,
    blob_roundtrip,
    check_store_coherence,
    describe_blob_store,
)
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
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    from blastbox.host.pool import Slot, WarmPool





# Errors that mean the GUEST or its seam failed, as opposed to our own filesystem. FCError covers
# rdump/vsock faults; both are OSError subclasses in places, so the distinction must be explicit.
def _guest_seam_errors() -> tuple[type[BaseException], ...]:
    try:
        from blastbox.host.runtime.firecracker import FCError
    except Exception:  # noqa: BLE001 -- FC not installed; nothing guest-specific to distinguish
        return ()
    return (FCError,)


_GUEST_SEAM_ERRORS: tuple[type[BaseException], ...] = _guest_seam_errors()


_JOB_ID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

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

# Bound the inline put_output retry (Finding D1, shared with VmJobDispatcher): the detonation
# already ran and the sealed result is sitting in job_root/<id>/output right now, while this
# dispatcher still owns the claim -- a transient upload failure deserves a real, bounded, IN-LINE
# chance to succeed. There is deliberately no "retry later" path: exhausting every attempt takes
# the normal failure path (_fail_job) instead of marking DONE, so the job never claims a result
# that was never durably stored.
_PUT_OUTPUT_MAX_ATTEMPTS = 3
_PUT_OUTPUT_RETRY_BACKOFF_S = 1.0

# Bound the release-on-BlobFetchError loop (Finding E1, mirrors VmJobDispatcher's identical
# policy in runtime/vm_dispatch.py -- see that module for the full rationale): a TRANSIENT
# fetch failure (this worker's connectivity) releases the claim back to QUEUED so another
# node can retry; a job that fails MAX_MATERIALISE_ATTEMPTS times IN A ROW is FAILED instead
# of released again, so a PERMANENTLY missing sample reaches a terminal state rather than
# looping release -> reclaim -> release forever.
MAX_MATERIALISE_ATTEMPTS = 3
_BLOB_RETRY_BACKOFF_S = 30.0


def warm_fault_stage(warm_clean: bool, warm_fault: "str | None",
                     phases: "_PhaseTimer", control: "Any | None" = None) -> "str | None":
    """WHERE a warm run failed, when that changes what the failure is evidence ABOUT.

    ``pre_guest`` means the slot never executed anything: it did not fail on this document, it
    failed to become able to run one. That convicts the warm base far sooner than ordinary worker
    faults can, which need 2 x warm_size (48 at warm_size=24) precisely because they might be the
    samples -- so a wedged base otherwise costs 48 jobs at the full worker timeout before the tier
    repairs itself.

    It requires PROOF, not inference. "The `guest` phase was never marked" is not proof: that mark
    lands only after the work COMPLETES, so a guest that started and hung on a pathological
    document looks identical to one that never woke up. Convicting a base on that would destroy a
    healthy artifact over three bad documents -- worse than the bug.

    So the guest says so itself. It sends a START frame the moment it has the job and before it
    begins work, and the host records ``control.guest_started``:

        True  -> it ran; whatever went wrong afterwards may well be the document.  NOT pre_guest.
        None  -> UNKNOWN. No ack seen, which is what an older worker image does, and absence of
                 evidence is not evidence of absence.                              NOT pre_guest.

    Only a control that is ack-capable AND reported no start yields ``pre_guest``. A free function
    so the decision is testable without standing up a dispatch.
    """
    if warm_clean or warm_fault != "worker":
        return None
    started = getattr(control, "guest_started", None)
    if started is not False:
        # True = it ran. None = the guest never told us (older image, or a seam with no ack), and
        # guessing there is exactly the mistake this parameter exists to prevent.
        return None
    # PROOF, and it outranks the completed-work mark -- which is why `phases` is no longer
    # consulted here. `phases.reached("guest")` means only that wait_for_done RETURNED, i.e. that
    # some `done` file appeared; the dispatcher discards the status string it carries. A worker
    # whose wait_for_go() expired writes done="idle_timeout" WITHOUT ever writing `started`, so
    # the guest phase is marked for a job the guest never took, and that inference was overriding
    # the definitive signal. Three restored slots that all fail before accepting their jobs then
    # waited for the much larger ordinary threshold -- defeating the fast repair for precisely the
    # failure mode it was built for. A worker-controlled completion status is not proof that
    # detonation executed; an ack-capable image declining to say it started is.
    #
    # Safe in the other direction too: both seams REFUSE the job when they cannot promise the
    # host they started (fc_warm raises if the ACK send fails, serve_warm if the `started` write
    # fails), so "ack-capable and no start" cannot describe a guest that actually ran.
    return "pre_guest"


class _PhaseTimer:
    """Host-side wall-clock per phase for ONE warm dispatch, keyed by job_id.

    Throughput on a disposable-slot tier is `slots / slot_cycle_time`, not `1 / engine_time`:
    24 slots sustaining ~2.6 jobs/s means a ~9s slot cycle, while a single job against an idle
    tier finishes in well under a second. So most of the cycle is something OTHER than
    extraction -- and until this existed, nothing could say which part, which makes every
    engine-side optimisation a guess.

    Why the HOST and not the guest: the guest's log lines carry no correlation id, so under
    concurrency pairing the k-th "job received" with the k-th "returned" pairs DIFFERENT JOBS.
    That method reported 0.67s and 5.48s for the same tier minutes apart, which is how you can
    tell it measures nothing (see RedTusk scripts/slot_cycle_profile.sh, which refuses to print
    such numbers). `_dispatch_claimed_job` owns one job start to finish on ONE thread, so its
    phases are already sequential and already ours -- no correlation id needed, and no guest
    change, so this deploys with a container rebuild instead of a rootfs rebuild.

    Instrumentation only: it never raises and never touches control flow. A phase that was
    never reached is simply ABSENT from the line, which is itself the diagnostic -- the last
    phase present is where the dispatch exited.
    """

    __slots__ = ("job_id", "outcome", "_start", "_last", "_phases")

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.outcome = "unknown"
        now = time.monotonic()
        self._start = now
        self._last = now
        self._phases: list[tuple[str, float]] = []

    def reached(self, name: str) -> bool:
        """Did this phase ever run? Used to tell a slot that failed ON a document from one that
        never became able to run one -- evidence of very different strength about the warm base."""
        return any(n == name for n, _ in self._phases)

    def mark(self, name: str) -> None:
        """Close the phase that ended at this line and open the next one."""
        now = time.monotonic()
        self._phases.append((name, now - self._last))
        self._last = now

    def emit(self, log: logging.Logger = _log) -> None:
        """One line per job. Guarded: a broken logging backend must not fail a job that has
        already done its work -- this runs from the outer `finally`, past every terminal path."""
        try:
            total = time.monotonic() - self._start
            log.info(
                "warm_phases job_id=%s outcome=%s total=%.3f %s",
                self.job_id,
                self.outcome,
                total,
                " ".join(f"{name}={secs:.3f}" for name, secs in self._phases),
            )
        except Exception:  # noqa: BLE001 -- instrumentation is never worth a failed job
            pass


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
    # Operator allowlist of dispatcher TIERS this engine may run on (BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES),
    # matched against the canonical tier vocabulary (jobs.base.VALID_TIERS: "cold" + the warm tiers
    # firecracker/gvisor/libvirt-vm/aws-*/static/cascade). None (default) ⇒ no restriction (any tier).
    # A frozenset ⇒ ONLY those tiers; a dispatcher whose tier is not in the set REFUSES TO START for
    # this engine (checked before the pool spawns, so no cloud slot leaks) — so an operator can pin a
    # locally-vetted engine to secure local tiers and a BLASTBOX_POOL_RUNTIME drift can't silently route
    # it onto a public-AWS/remote worker with a different egress posture. Fail-closed like the param
    # allowlist: the set must list EVERY tier the engine is intended to run on.
    allowed_runtimes: frozenset[str] | None = None


def reachable_tiers(pool: Any, tier: str, warm_only: bool) -> frozenset[str]:
    """The full set of tiers a dispatcher can actually EXECUTE a job on — not just its advertised
    ``tier``. A file-handshake warm dispatcher **cold-falls-back** to the local Docker path on a pool
    miss or an egress job (unless ``warm_only``), so ``"cold"`` is reachable; a **cascade** routes each
    spawn to any of its concrete member tiers. ``allowed_runtimes`` is enforced against ALL of these so
    the gate can't be escaped via cold-fall-back, an egress job, or a cascade overflow."""
    if pool is None:
        return frozenset({"cold"})
    rt = getattr(pool, "runtime", None)
    members = getattr(rt, "tiers", None)
    if getattr(rt, "kind", None) == "cascade" and members:
        tiers = {t.name for t in members}   # the concrete BLASTBOX_POOL_TIERS entries spawn routes to
        # DEFERRED tiers count too. A tier whose startup availability probe was undecided (issue
        # #79) is not in `tiers` yet, but `_admit_deferred` appends it on a later spawn -- so
        # leaving it out let a tier the operator's allowed_runtimes EXCLUDES join a dispatcher
        # that had already passed the fail-closed check, minutes after start. Its identity was
        # never in doubt, only its availability, so it belongs in the gate's input from the
        # beginning: had it been reachable at startup the dispatcher would have refused to boot,
        # and being briefly unreachable must not buy a weaker verdict.
        tiers |= {d.name for d in (getattr(rt, "_deferred", None) or ())}
    else:
        tiers = {tier}
    # Only the file-handshake Dispatcher cold-falls-back; network-endpoint tiers requeue (no cold path).
    if not warm_only and getattr(rt, "dispatch_style", "file") == "file":
        tiers.add("cold")
    return frozenset(tiers)


def enforce_allowed_runtimes(engines: Mapping[str, "EngineSpec"], reachable: Collection[str]) -> None:
    """Fail-closed guard: refuse a dispatcher that can execute an engine on a tier its operator-
    configured ``allowed_runtimes`` excludes. ``reachable`` is EVERY tier this dispatcher can run a job
    on (see :func:`reachable_tiers`) — including the ``"cold"`` fallback and each ``cascade`` member — so
    the gate isn't bypassable via cold-fall-back, an egress job, or a cascade overflow. Enforced in the
    dispatcher constructors/factory (so embedders are covered, not just the CLI) and again in the CLI
    before the pool spawns any (cloud) slot. Engines with ``allowed_runtimes is None`` impose no
    restriction, so this is a no-op for the default config."""
    reachable = frozenset(reachable)
    for name, spec in engines.items():
        # getattr default: a real EngineSpec always has the field; a duck-typed spec (embedder/tests)
        # without it just imposes no restriction (same as None).
        allowed = getattr(spec, "allowed_runtimes", None)
        if allowed is None:
            continue
        disallowed = reachable - allowed
        if disallowed:
            # env-var form normalizes name like _parse_engine_specs (upper + hyphen→underscore)
            env_name = name.upper().replace("-", "_")
            raise ValueError(
                f"engine {name!r} is not permitted on tier(s) {sorted(disallowed)} that this "
                f"dispatcher can execute jobs on (reachable={sorted(reachable)}, "
                f"allowed_runtimes={sorted(allowed)}); refusing to start — add them to "
                f"BLASTBOX_ENGINE_{env_name}_ALLOWED_RUNTIMES, or reconfigure the pool "
                f"(BLASTBOX_POOL_RUNTIME / BLASTBOX_POOL_TIERS / BLASTBOX_DISPATCH_WARM_ONLY) "
                f"so it can't reach them"
            )


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
        concurrency_gate: "DynamicConcurrencyGate | None" = None,
        blob_store: BlobStore | None = None,
        require_shared_blob_store: bool = False,
        put_output_max_attempts: int = _PUT_OUTPUT_MAX_ATTEMPTS,
        put_output_retry_backoff_s: float = _PUT_OUTPUT_RETRY_BACKOFF_S,
        blob_retry_backoff_s: float = _BLOB_RETRY_BACKOFF_S,
    ) -> None:
        # Optional live cold-admission cap driven by the node autosizer. ONLY the cold path
        # acquires a permit (see _dispatch_claimed_job): a cold worker spawns footprint OUTSIDE
        # the warm pool, so the sizer sets the gate limit to the budget's cold headroom
        # (ceiling − warm reservation) → warm residency + cold workers stay within the node
        # budget. Warm dispatch is never gated (it reuses a resident slot). Best-effort, not a
        # hard guarantee — see the eventual-consistency note in dispatcher_sizer.
        self._concurrency_gate = concurrency_gate
        # Cold workers whose timeout-kill was NOT confirmed: we RETAIN their gate permit (so no
        # worker stacks on a possible orphan) and reconcile in maintenance — once `docker ps` shows
        # the container is gone, we release the permit. Without this the permit leaks permanently
        # and cold capacity bleeds to zero after enough failed kills. name → nothing (a set).
        # container name -> (job_id, claim_id we held). The claim_id is what lets the
        # reconcile below apply the SAME ownership gate as the terminal purge: by the time
        # the container is confirmed gone a peer may have reclaimed the job, and comparing
        # the store row against itself would pass trivially and delete the peer's tree.
        self._retained_cold_orphans: dict[str, tuple[str, str | None]] = {}
        # Jobs whose result upload EXHAUSTED its retries: the durable copy never landed, so the
        # local tree is the ONLY copy and the terminal purge must spare it. Everything else in
        # this file assumes the blob store is the durable copy -- on this one branch that is
        # false BY CONSTRUCTION, and the tree holds host-sealed, trust-gate-passed output plus
        # one-shot evidence (the netd C2 pcap is MOVED, not copied, into it). Reviewed on #85.
        self._upload_failed_job_ids: set[str] = set()
        # Age-based reclaim of per-job SCRATCH, deliberately independent of
        # job_retention_seconds. That knob governs RESULT lifecycle -- its sweeper also calls
        # blob_store.delete_job(), so it must stay 0 in any deployment that wants to keep
        # results, which left NOTHING in-process reclaiming job_root. Every "leave it for the
        # sweep" decision in terminal cleanup (an unconfirmed-dead container's tree, a result
        # whose upload exhausted) was therefore an unbounded leak (#85 review). This is the
        # bound, and it never touches the blob store. 0 disables.
        # Separate from BLASTBOX_SCRATCH_MAX_AGE_S on purpose: that knob governs DELETION,
        # this one governs RECOVERY (re-uploading a retained result and repairing its row
        # FAILED->DONE). An operator staging an upgrade conservatively needs to be able to
        # turn the write-side off without also disabling the only thing bounding the disk,
        # and vice versa -- and before this there was no off-switch for the write side at
        # all short of disabling maintenance entirely, which also kills crash recovery.
        self._pending_upload_retry = os.environ.get(
            "BLASTBOX_PENDING_UPLOAD_RETRY", "1").strip().lower() not in ("0", "false", "no", "off")
        self._scratch_max_age_s = max(0.0, float(
            os.environ.get("BLASTBOX_SCRATCH_MAX_AGE_S", "21600") or "21600"))
        self._retained_lock = threading.Lock()
        # Set once shutdown begins: a dispatch worker abandoned past the join deadline (e.g. blocked
        # in a slow claim_next) must NOT acquire a cold permit and spawn a container after the CLI
        # has removed the node reservation. The cold path checks this before acquiring the gate.
        self._shutting_down = threading.Event()
        self._job_store = job_store
        self._require_shared_blob_store = bool(require_shared_blob_store)
        # engines is kept as an immutable mapping snapshot so callers cannot
        # mutate it after construction.
        self._engines: dict[str, EngineSpec] = dict(engines)
        self._limits = limits
        self._job_root = Path(job_root)
        self._runtime_selector = runtime_selector
        self._subprocess_runner = subprocess_runner
        # Backing blob store for the retention sweeper (see _run_maintenance): in a mixed-tier
        # fleet sharing one JobStore, a job dispatched over the network (VmJobDispatcher,
        # blob-backed) can be reaped by THIS (file-handshake) dispatcher's maintenance sweep —
        # without a blob store, expire_due deletes only the (harmlessly-absent, wrong-host) local
        # dir and clears expires_at, orphaning the result blob forever. None (the default, and
        # every existing call site) lazily resolves BLASTBOX_BLOB_URL, mirroring
        # VmJobDispatcher.__init__ — unset means LocalBlobStore, whose delete_job is a no-op/miss
        # for a job this node never stored, so single-node/unset deployments are unaffected.
        # Imported here, not at module scope, to mirror ingress/app.py's lazy factory import.
        if blob_store is not None:
            self._blobs = blob_store
        else:
            from blastbox.host.blobs.factory import build_blob_store_from_env

            # Mirrors VmJobDispatcher: the factory must see the job_root THIS dispatcher
            # actually uses, not just the raw env var, or a caller passing an explicit
            # job_root= (differing from BLASTBOX_JOB_ROOT) gets a LocalBlobStore rooted at
            # the wrong directory.
            self._blobs = build_blob_store_from_env(
                {**os.environ, "BLASTBOX_JOB_ROOT": str(self._job_root)}
            )
        # Bounded inline retry policy for a result upload (Finding P1/D1): the ONLY place
        # this dispatcher's finished output is durably persisted for the API's
        # BlobStore-only result routes (ingress/app.py) is put_output, called from the cold
        # and warm success paths BEFORE their DONE write -- see _dispatch_inner /
        # _dispatch_warm. See the module-level constants for why this is bounded and has
        # no "leave it running" fallback.
        self._put_output_max_attempts = max(1, int(put_output_max_attempts))
        self._put_output_retry_backoff_s = max(0.0, float(put_output_retry_backoff_s))
        # How long a job that just failed to fetch its sample is deferred (claimable_after)
        # before it's eligible again -- long enough that THIS dispatcher doesn't immediately
        # re-claim and spin on a sample its own connectivity can't reach. Mirrors
        # VmJobDispatcher's identical backoff (Finding E1).
        self._blob_retry_backoff_s = max(0.0, float(blob_retry_backoff_s))
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

        # Warm-only concurrency cap (issue #72): a warm sidecar with N idle slots must admit at
        # most N concurrent claims. The old gate checked ``idle_count > 0`` but that is RACY —
        # under DISPATCH_CONCURRENCY threads, all pass when idle>0, all claim a job, and the excess
        # requeue-churn (especially once the node sizer has shrunk the pool below the static
        # concurrency). This atomic reservation caps the number of threads that reach pool.claim()
        # to the LIVE idle count, so overflow stays QUEUED (backpressure) instead of requeuing.
        # Reserved at the gate (dispatch_once); released the moment the slot is resolved
        # (acquired or not) in _dispatch_claimed_job. Only warm-only sidecars gate this way — a
        # warm+cold dispatcher can still claim freely and cold-fall-back.
        self._warm_gate_lock = threading.Lock()
        self._warm_slot_reservations = 0

        # This dispatcher's tier identity ("cold"/"firecracker"/"gvisor"), for optional per-job
        # routing (target_tier) and the warm-backend result label (worker_tier). Passed to
        # claim_next so a job targeting a specific tier is only claimed here when it matches; an
        # untargeted job (the default) is claimable by every tier. The CALLER derives this
        # (the CLI from BLASTBOX_POOL_RUNTIME, validated against the built pool — see
        # _dispatch_cmd) so the Dispatcher stays env-agnostic and a misconfig fails fast there,
        # not by silently mislabeling warm jobs as cold here. Inert until an operator enables
        # routing at the API (BLASTBOX_ALLOW_TIER_ROUTING) — existing jobs have no target.
        self._tier = tier
        # Fail-closed per-engine tier gate, in the CONSTRUCTOR (not just the CLI) so embedders are
        # covered: refuse if THIS dispatcher can execute an engine on a tier its allowed_runtimes
        # excludes — reachable_tiers folds in the cold-fallback + egress-bypass ("cold") and cascade
        # overflow paths, so the gate isn't escapable at dispatch time.
        enforce_allowed_runtimes(
            self._engines, reachable_tiers(self._pool, self._tier, self._warm_only)
        )
        # OPT-IN engine scoping for SHARED multi-dispatcher stores: when set, claim only jobs for
        # engines this dispatcher handles, so it can't grab (and fail "unknown engine") a job that a
        # co-resident VM/other-engine dispatcher owns. Default OFF preserves the single-dispatcher
        # contract — claim anything + FAIL a genuinely-unknown engine fast (an open-allowlist typo
        # would otherwise sit QUEUED forever). Enable this only when peers handle the other engines.
        self._engine_scoped = os.environ.get(
            "BLASTBOX_DISPATCHER_ENGINE_SCOPED", "").strip().lower() in ("1", "true", "yes", "on")

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
        # netd drops the per-job TLS keylog (sslkeys.log) on the worker's DIE event, which races
        # this dispatcher's post-worker seal. Briefly poll for it so an inspect job's decrypt isn't
        # silently skipped just because the snapshot landed a beat after we started sealing. Clamped
        # to [0, 60]s: this poll blocks a dispatch thread, so a fat-fingered env can't wedge one.
        self._decrypt_keylog_wait_s = max(0.0, min(
            float(os.environ.get("BLASTBOX_NET_DECRYPT_KEYLOG_WAIT_S") or "8"), 60.0
        ))
        # netd finalizes the pcap (terminates tcpdump) on the worker's DIE event, asynchronously to
        # this dispatcher's post-worker seal. Wait (bounded) for netd's <pcap>.done sentinel before
        # copying so the capture isn't sealed mid-write (truncated tail). Clamped like the keylog wait.
        self._net_capture_wait_s = max(0.0, min(
            float(os.environ.get("BLASTBOX_NET_CAPTURE_WAIT_S") or "5"), 60.0
        ))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _reserve_warm_slot(self) -> bool:
        """Atomically reserve gate capacity against a currently-idle warm slot (issue #72).

        Returns True if a reservation was taken — the caller MUST then release it exactly once
        (via _release_warm_reservation, done in _dispatch_claimed_job once the slot resolves, or
        here if no job is claimed). False when there is no idle capacity left to reserve, i.e.
        every idle slot is already spoken for by a concurrent claimer. This caps the number of
        threads that reach pool.claim() to the LIVE idle count, so a warm-only sidecar never
        over-claims and requeue-churns.
        """
        pool = self._pool
        if pool is None:
            return False
        with self._warm_gate_lock:
            # Lock order is _warm_gate_lock → pool._lock (idle_count takes the pool's own lock).
            # Safe: the pool holds no reference to this gate and never calls back into it, so the
            # order is acyclic — no inversion is possible. INVARIANT: never acquire _warm_gate_lock
            # while holding pool._lock (e.g. from a future slot-state callback), or that would
            # create the reverse edge and a deadlock.
            idle = int(getattr(pool, "idle_count", 0) or 0)
            if idle - self._warm_slot_reservations <= 0:
                return False
            self._warm_slot_reservations += 1
            return True

    def _release_warm_reservation(self) -> None:
        with self._warm_gate_lock:
            if self._warm_slot_reservations > 0:
                self._warm_slot_reservations -= 1

    def dispatch_once(self) -> bool:
        """Claim and dispatch the next queued job.

        Returns True if a job was claimed, False if the queue was empty.
        """
        # Warm-sidecar claim-gate (issue #72): a warm-only dispatcher has no cold path, so it must
        # not claim work it can't immediately serve. Reserve one idle warm slot ATOMICALLY before
        # claiming — capping concurrent claims to the live idle count, so overflow stays QUEUED
        # (backpressure) for another sidecar instead of being claimed-then-requeued under
        # concurrency (the old `idle_count > 0` check was racy: N threads all passed on the same
        # few idle slots). The reservation is freed the instant the slot is resolved
        # (in _dispatch_claimed_job) or here when no job is claimed.
        reserved = False
        if self._warm_only:
            if not self._reserve_warm_slot():
                return False
            reserved = True
        # Engine scoping is OPT-IN (shared multi-dispatcher stores): scoped → leave another
        # dispatcher's engine's jobs for it; unscoped (default) → claim anything, and the
        # _dispatch_claimed_job path FAILs a genuinely-unknown engine fast. Only pass engine= when
        # scoping is on, so the default path keeps the original claim_next(*, claimant_tier=) shape an
        # injected/legacy JobStore double may implement (no new keyword forced on it).
        try:
            if self._engine_scoped:
                job = self._job_store.claim_next(claimant_tier=self._tier,
                                                 engine=frozenset(self._engines))
            else:
                job = self._job_store.claim_next(claimant_tier=self._tier)
        except BaseException:
            if reserved:
                self._release_warm_reservation()
            raise
        if job is None:
            if reserved:
                self._release_warm_reservation()
            return False
        # From here _dispatch_claimed_job owns releasing the reservation (freed once the slot is
        # resolved there); do NOT release it again in this method.
        self._dispatch_claimed_job(job, warm_reserved=reserved)
        return True

    def self_test(self, *, gate: bool) -> bool:
        """Prove this dispatcher can actually store and serve a result, before it claims a job.

        ``gate=True`` (startup) RAISES on failure. A dispatcher whose store is misconfigured cannot
        do its job, and the useful failure is a loud one at boot: the alternative -- which is what
        happened -- is a stack that looks healthy, claims thousands of jobs and marks them DONE
        with results nobody can fetch. A crash-loop with the remedy in the log is strictly better
        than that, and it is the same class of error as a bad database URL, which already fails
        closed.

        ``gate=False`` (periodic) only logs. Once the process is serving, a store that goes away is
        a BROWNOUT, not a config error, and taking the dispatcher down over it would destroy warm
        capacity for something that heals on its own -- exactly what issue #79 exists to prevent.
        The periodic pass is there to make a store that broke *since* boot visible in the log
        rather than at the next collection.
        """
        try:
            # BEFORE the round-trip. A LocalBlobStore round-trips perfectly -- it reads back its
            # own directory -- so the write/read test cannot see the single worst deployment bug
            # this fleet has had. Only the COMBINATION (shared queue, private store) reveals it.
            check_store_coherence(self._job_store, self._blobs, self._job_root,
                                  require_shared=self._require_shared_blob_store)
            # Host+tier alone still collides for two engine-scoped dispatchers on one box, and a
            # collision costs a retry (see canary_job_id). Fold in the engines and the job_root:
            # cheap, stable across restarts, and distinct for every dispatcher that could co-exist.
            key = "|".join((
                str(getattr(self, "_tier", "") or ""),
                ",".join(sorted(getattr(self, "_engines", {}) or {})),
                str(self._job_root),
            ))
            _log.info("canary.ok %s", blob_roundtrip(
                self._blobs, key_hint=key, scratch_dir=self._job_root))
            return True
        except CanaryFailure as exc:
            if gate:
                _log.error("canary.FAILED refusing to serve — %s", exc)
                raise
            _log.error("canary.FAILED (already serving; not gating) — %s", exc)
            return False

    def run_forever(
        self,
        *,
        poll_interval_s: float = 1.0,
        stop: Callable[[], bool] | None = None,
        maintenance_interval_s: float = 60.0,
        concurrency: int = 1,
        canary: bool = True,
        canary_interval_s: float = 900.0,
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
        # BEFORE the first claim, and before the concurrent fan-out -- a self-test that runs after
        # work has been claimed is not a gate, it is a report.
        # OUTSIDE the toggle. This is the only line naming the backend, bucket, prefix and
        # endpoint for a file dispatcher, and the point of logging it is the side-by-side
        # comparison with the ingress -- which logs its read target regardless. Hiding it behind
        # BLASTBOX_CANARY=0 broke that comparison in exactly the deployments that opted out,
        # including the documented one where the store is deliberately absent at boot.
        _log.info("canary.blob_store %s", describe_blob_store(self._blobs))
        # TOPOLOGY ENFORCEMENT IS NOT THE PROBE, and must not share its off switch. BLASTBOX_CANARY
        # disables the write/read round-trip; BLASTBOX_REQUIRE_SHARED_BLOB_STORE is an explicit hard
        # requirement, documented as failing closed at startup. Coupling them meant CANARY=0 silently
        # dropped the requirement too, so a Postgres/Redis dispatcher on a private LocalBlobStore
        # started happily and produced DONE jobs whose results no other machine can read -- the single
        # worst deployment bug this fleet has had, re-enabled by an unrelated opt-out. Second thing
        # found behind this toggle that did not belong to it; the blob-store log was the first.
        check_store_coherence(self._job_store, self._blobs, self._job_root,
                              require_shared=self._require_shared_blob_store)
        if canary:
            self.self_test(gate=True)
        if max(1, int(concurrency)) > 1:
            self._run_forever_concurrent(
                poll_interval_s=poll_interval_s,
                stop=stop,
                maintenance_interval_s=maintenance_interval_s,
                concurrency=int(concurrency),
                canary=canary,
                canary_interval_s=canary_interval_s,
            )
            return
        last_maint = time.monotonic()
        # OFF THE CLAIM PATH. Checked inline, the probe only ran between jobs: dispatch_once() is
        # synchronous here, so a single detonation up to the worker timeout (300s by default)
        # delayed a 60s interval for the whole job, and a continuously busy dispatcher delayed it
        # again every job. A configured cadence that only holds while idle is not the configured
        # cadence. The concurrent path already has a coordinator thread for exactly this.
        canary_stop = threading.Event()
        canary_thread = None
        if canary and canary_interval_s > 0:
            def _canary_tick() -> None:
                while not canary_stop.wait(canary_interval_s):
                    try:
                        self.self_test(gate=False)
                    except Exception:  # noqa: BLE001 - advisory once serving
                        _log.exception("canary raised; continuing to serve")
            canary_thread = threading.Thread(target=_canary_tick, name="blastbox-canary",
                                             daemon=True)
            canary_thread.start()
        try:
            self._run_forever_serial(poll_interval_s, stop, maintenance_interval_s, last_maint)
        finally:
            canary_stop.set()
            if canary_thread is not None:
                canary_thread.join(timeout=5.0)

    def _run_forever_serial(self, poll_interval_s: float, stop: "Callable[[], bool] | None",
                            maintenance_interval_s: float, last_maint: float) -> None:
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
        canary: bool = True,
        canary_interval_s: float = 900.0,
    ) -> None:
        """N dispatch-loop threads claim+dispatch independently; maintenance runs from
        this coordinator thread (a global sweep — must NOT run N times concurrently).

        The periodic canary runs here too, for the same reason maintenance does: one coordinator,
        not N. Without it BLASTBOX_CANARY_INTERVAL_S was silently ignored for every concurrent
        dispatcher -- they probed once at boot and never noticed a store that broke afterwards,
        which is precisely the shape (multi-worker, shared queue) most likely to have one."""
        stop_evt = threading.Event()

        def _should_stop() -> bool:
            return stop_evt.is_set() or (stop is not None and stop())

        def _worker() -> None:
            while not _should_stop():
                # The concurrency gate is NOT held here: warm dispatch runs in an already-resident
                # slot (adds no footprint) and must never be blocked. Only the COLD path — which
                # spawns a NEW worker outside the warm pool — acquires a gate permit, inside
                # _dispatch_claimed_job, so the node budget's cold headroom bounds it.
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
        last_canary = time.monotonic()
        try:
            while not _should_stop():
                # CANARY FIRST. Both run on this one coordinator thread, so a maintenance sweep
                # starting at or before the canary deadline blocks it -- and _run_maintenance can
                # retry thousands of pending uploads through the very store that is down, so an
                # object-store outage could postpone by many minutes the check whose whole job is
                # reporting that outage. Maintenance must not be able to hide it.
                if canary and canary_interval_s > 0 \
                        and time.monotonic() - last_canary >= canary_interval_s:
                    try:
                        self.self_test(gate=False)
                    except Exception:  # noqa: BLE001
                        _log.exception("canary raised; continuing to serve")
                    # Re-stamped from COMPLETION -- the round-trip can block for the store's own
                    # timeout, so stamping first would re-probe every pass exactly when the store
                    # is least able to answer.
                    last_canary = time.monotonic()
                if (
                    maintenance_interval_s > 0
                    and time.monotonic() - last_maint >= maintenance_interval_s
                ):
                    last_maint = time.monotonic()
                    self._run_maintenance()
                time.sleep(min(poll_interval_s, 1.0))
        finally:
            stop_evt.set()
            # Fence NEW cold admissions: a worker abandoned past the join (below), e.g. blocked in a
            # slow claim_next, must not acquire a gate permit and spawn a container after the CLI
            # removes the reservation. The cold path re-checks this after its claim.
            self._shutting_down.set()
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
                # Delete the staged input only -- NOT the whole tree.
                #
                # An earlier revision purged everything here, reasoning "our CAS won, so no peer
                # owns the tree". That is FALSE and this file says so 560 lines down: the CAS is
                # on (RUNNING, claim_id), and a live owner mid-SEAL still holds exactly that
                # state, because it writes its terminal status only after the seal completes. The
                # seal (rdump materialize, size-cap walk, re-hash, upload) is explicitly NOT
                # bounded by warm_deadline, which is why _dispatch_warm refreshes started_at
                # before it -- see the comment there: "a legitimately slow/large seal could be
                # judged 'owner gone' and FAILed out from under a live owner". Refreshing narrows
                # that window; it does not close it. So this sweep CAN fire against a live owner,
                # and rmtree'ing output/ while that owner is writing into it destroys a result
                # that actually succeeded.
                #
                # Deleting the input is safe in that same race (the owner no longer needs it by
                # seal time, and the sample is content-addressed in the blob store), which is why
                # this path has always done exactly that. output/ is left for the age-based
                # scratch sweep: a leaked dir is recoverable, a live job's destroyed output is
                # not. Reviewed on #85.
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

    @staticmethod
    def _httpproxy_env(personality) -> dict[str, str]:
        """The HTTP(S)_PROXY env to inject for an httpproxy personality, or {} if the driver isn't
        httpproxy or the proxy= URL is malformed (fail closed — no env, no egress). Validates scheme
        + host:port so an operator typo can't silently produce a broken/leaky proxy env."""
        if personality.exit_driver != "httpproxy":
            return {}
        proxy = (personality.config.get("proxy") or "").strip()
        if not proxy:
            return {}
        parsed = urllib.parse.urlparse(proxy)
        ok = (
            parsed.scheme in ("http", "https", "socks5", "socks5h")
            and bool(parsed.hostname)
            and " " not in proxy and "\n" not in proxy
        )
        if not ok:
            _log.warning("httpproxy proxy= %r is malformed; not injecting proxy env (fail closed)",
                         proxy[:80])
            return {}
        try:  # urlparse only validates the port lazily on access
            _ = parsed.port
        except ValueError:
            _log.warning("httpproxy proxy= %r has a bad port; not injecting proxy env", proxy[:80])
            return {}
        # Strip any inline user:pass@ — the upstream provider's credentials must NOT cross into the
        # untrusted worker env (the documented design is a creds-holding chaining sidecar that the
        # worker reaches credential-free). A creds-bearing proxy= is an operator misconfiguration;
        # drop the userinfo (and warn) so it can't leak to a sample via HTTP_PROXY.
        if parsed.username or parsed.password:
            _log.warning("httpproxy proxy= carries inline credentials; stripping userinfo before "
                         "injecting into the worker env (use a creds-holding sidecar instead)")
            host = parsed.hostname or ""
            if ":" in host:        # IPv6 literal: parsed.hostname drops the brackets — restore them,
                host = f"[{host}]"  # else "2001:db8::1:8080" is an invalid host/port to URL parsers.
            netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
            proxy = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
        return {k: proxy for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}

    def _resolve_personality(self, job: Job):
        """Resolve a job's effective network personality (fail-closed to ``none``). Used both to
        decide warm-vs-cold routing here and inside the cold path; same inputs → same result."""
        from blastbox.host.netpolicy import resolve_net_policy
        engine = self._engines.get(job.engine)
        return resolve_net_policy(
            job_net_policy=job.net_policy,
            engine_default=engine.net_policy if engine else "none",
            registry=self._net_policies,
            allow_override=self._allow_net_override,
        )

    def _dispatch_claimed_job(self, job: Job, *, warm_reserved: bool = False) -> None:
        """Execute one claimed job (status is already RUNNING on entry).

        ``warm_reserved`` (issue #72): the caller took a warm-slot gate reservation before
        claiming this job. This method releases it exactly once, the instant the slot is resolved
        (acquired or missed) — never held across the long warm detonation.

        Security: input is deleted via a finally block on every branch — but only when we
        still own the claim (``_delete_input_if_owned``); a job a peer reclaimed keeps its
        input for the new owner (the recovery sweep deletes a time-recovered job's input).

        If a warm pool is configured, attempt to claim a slot.  On success, the
        WARM path runs.  If no slot is available (pool.claim returns None), the
        COLD path runs as a fallback.  When no pool is configured, COLD always.
        """
        # issue #72: dispatch_once() handed off SOLE ownership of releasing the warm-slot gate
        # reservation to this method (freed in the finally around the slot claim below). That
        # finally does NOT cover this pre-claim setup, so an exception here (e.g. Path() on a job
        # whose filename is None — filename is treated as possibly-falsy elsewhere) would leak the
        # reservation, permanently shrinking the gate until the sidecar re-wedges. Release + re-raise
        # so a pre-claim failure can never strand a reservation. (Only fires on the error path; the
        # normal path's release is the finally at the claim below — no double-release.)
        try:
            root = self._job_root / job.job_id
            input_dir = root / "input"
            output_dir = root / "output"
            input_path = input_dir / Path(job.filename).name
        except BaseException:
            if warm_reserved:
                self._release_warm_reservation()
            raise

        # Try the warm path if a pool is configured. EXCEPTION: an egress personality needs the cold
        # path's netd netns-wiring + dispatcher network args/labels, which the warm tier can't apply
        # (warm-tier networking is a future phase) — so an egress job on a warm slot would silently
        # fail closed. Don't claim a warm slot for it: a warm-only sidecar then requeues it for a
        # cold dispatcher (existing branch below); a warm+cold dispatcher cold-falls-through. Either
        # way the job runs WITH egress instead of failing.
        if self._pool is not None:
            try:
                egress = self._resolve_personality(job).exit_driver not in ("none", "drop")
                if egress:
                    _log.info("net_policy egress job_id=%s → bypassing warm slot (cold wires egress)",
                              job.job_id)
                phases = _PhaseTimer(job.job_id)
                slot = None if egress else self._pool.claim(timeout_s=self._warm_claim_timeout_s)
                # BEFORE the reservation release below, so a slow claim is billed to the claim
                # and not to whatever runs next.
                phases.mark("slot_claim")
            finally:
                # The reservation covered gate→slot-resolution only. Free it now: the slot is
                # ASSIGNED (out of idle_count) or was missed, so keeping the reservation would
                # double-count against idle_count and needlessly gate peers during the detonation.
                if warm_reserved:
                    self._release_warm_reservation()
            if not egress:
                record_warm_claim(hit=slot is not None)
            if slot is not None:
                # WARM PATH — the slot, not input_path/output_dir, owns I/O dirs.
                # Staged input is deleted in the finally block (only if we still own the claim;
                # a reclaimed job's input is left for the new owner — see _delete_input_if_owned).
                t0 = time.monotonic()
                try:
                    self._dispatch_warm(
                        job, staged_input_path=input_path, slot=slot, output_dir=output_dir,
                        phases=phases,
                    )
                finally:
                    # Delete the staged input on every terminal path WE own, then purge the
                    # whole dir -- output/ included (issue #84).
                    self._delete_input_if_owned(job, input_path)
                    self._purge_job_dir_if_owned(job)
                    self._record_outcome(job, path="warm", started=t0)
                    # Emitted HERE, not inside _dispatch_warm, so the line covers the whole
                    # slot cycle this thread is responsible for -- the purge is real per-job
                    # wall-clock on a tier that keeps 82.7k result trees around, and billing it
                    # to nobody is how it stayed invisible.
                    phases.mark("purge")
                    phases.emit()
                return
            elif self._warm_only:
                # Warm-only sidecar: do NOT cold-fall-back (no docker socket here — the cold
                # path would fail closed and FAIL the job). Release the claim back to QUEUED so
                # the cold dispatcher (or another warm tier) claims it.
                self._requeue_claimed(job, reason="warm_only requeue (no cold fallback)")
                return
            else:
                _log.info("warm_pool_miss job_id=%s; falling back to cold path", job.job_id)

        # COLD PATH (default / fallback). A cold worker spawns NEW footprint OUTSIDE the warm
        # pool, so it must fit the node budget's COLD HEADROOM: the sizer caps concurrent cold
        # workers at (ceiling − warm reservation) via the gate. If there's no headroom right now
        # (warm is using the budget), REQUEUE rather than block a dispatch thread or oversubscribe
        # — a worker reclaims it once the sizer frees headroom (idle-warm reaping). Best-effort,
        # per the eventual-consistency model in dispatcher_sizer: a warm burst mid-interval can
        # transiently overshoot, corrected next tick.
        gate = self._concurrency_gate
        if gate is not None and self._shutting_down.is_set():
            # Shutdown began while we were between claim and cold admission (e.g. a slow
            # claim_next). Do NOT spawn a container after the reservation is being torn down —
            # requeue the job for a fresh dispatcher/restart to pick up.
            self._requeue_claimed(job, reason="shutdown before cold admission")
            return
        if gate is not None and not gate.acquire(timeout=0.0):
            # DEFER (set claimable_after) so this capacity-blocked cold job is temporarily
            # INELIGIBLE: claim_next() skips it for a short window, so warm-eligible work reaches
            # idle warm slots instead of dispatch threads reclaiming+requeuing this same job in a
            # loop. created_at (submission time / max_queued_age) is preserved.
            self._requeue_claimed(job, reason="no cold budget headroom", defer=True)
            return
        t0 = time.monotonic()
        orphaned: list[str] = []           # container name(s) whose timeout kill FAILED
        try:
            self._dispatch_inner(job, input_path, output_dir, orphan_out=orphaned)
        finally:
            # RELEASE the cold permit only when the worker is CONFIRMED gone. If a timed-out
            # container's `docker kill` failed, it may still be running and holding node RAM;
            # releasing the permit would let another cold worker be admitted on top of the orphan,
            # accumulating past the budget across repeated failures. RETAIN the permit and record
            # the container so maintenance can reclaim it once `docker ps` confirms the container
            # is gone (else the permit would leak permanently and cold capacity bleed to zero).
            if orphaned:
                # Register the TREE unconditionally. This used to live under the permit's branch
                # (`elif gate is not None`), while the purge skip below ran regardless -- so with
                # the node autosizer off (gate is None, the default) the orphan was never
                # recorded, _reconcile_cold_orphans returned at its own `gate is None` check, and
                # NOTHING ever purged it. Retention is about the sample bytes; the permit is a
                # separate concern that simply has nothing to release here (#85 review).
                with self._retained_lock:
                    self._retained_cold_orphans.update(
                        {n: (job.job_id, job.claim_id) for n in orphaned})
                # ...and on DISK too, so the other dispatcher sharing this job_root -- and this
                # one after a restart -- also knows not to reclaim it.
                mark_retained_orphan(self._job_root, job.job_id, _log)
                _log.warning("cold worker cleanup unconfirmed for job_id=%s (docker kill failed) — "
                             "deferring the job-dir purge%s until a sweep confirms the container "
                             "is gone", job.job_id,
                             " and retaining the concurrency permit" if gate is not None else "")
            elif gate is not None:
                gate.release()
            # Delete the malicious input on every terminal path WE own, regardless of success,
            # failure, exception, or unknown engine -- then purge the whole job dir. output/ used
            # to survive here forever, which is the leak in issue #84.
            self._delete_input_if_owned(job, input_path)
            if orphaned:
                # `docker kill` was NOT confirmed, which is exactly why the permit above is
                # retained -- the container may still be running with job_root/<id>/output
                # bind-mounted 0o777. rmtree'ing a tree a live writer is using races it into a
                # half-deleted state and a spurious "PURGE FAILED ... sample bytes may remain",
                # and its open fds pin the disk anyway, so nothing is reclaimed. Leave it for the
                # maintenance sweep that already reconciles these orphans (#85 review).
                _log.warning("job %s: worker container not confirmed gone; retaining %s until a "
                             "sweep reclaims it", job.job_id, self._job_root / job.job_id)
            else:
                self._purge_job_dir_if_owned(job)
            self._record_outcome(job, path="cold", started=t0)

    def _requeue_claimed(self, job: Job, *, reason: str, defer: bool = False) -> None:
        """Release OUR claim back to QUEUED so another worker/dispatcher takes the job. CAS-fenced
        on our claim_id and clears it, so a job reclaimed since we claimed is left untouched;
        started_at/worker_runtime/worker_tier are reset so it looks fresh. The staged input is
        NOT deleted — the next owner needs it (we only delete input on paths WE terminate).

        ``defer`` (capacity requeue): set claimable_after to a short window in the future so the job
        becomes temporarily INELIGIBLE — claim_next() skips it, so warm-eligible work reaches idle
        warm slots instead of dispatch threads reclaiming+requeuing this same capacity-blocked cold
        job in a loop. This does NOT touch created_at (the submission time used for public ordering
        and max_queued_age expiry). Warm-miss requeues do not defer (the cold dispatcher should take
        the job promptly).

        Then yields (backoff): dispatch_once() reports progress (a job WAS claimed), so run_forever
        loops without its poll sleep — without a pause THIS dispatcher re-claims the just-requeued
        job in a tight churn loop and no peer gets a turn. The backoff hands it off."""
        fields: dict[str, object] = dict(
            started_at=None,
            worker_runtime=None,
            worker_tier=None,
            claim_id=None,
            error=None,
        )
        if defer:
            # ineligible for a short window; retried once warm may have freed cold headroom.
            fields["claimable_after"] = time.time() + max(2.0, self._warm_requeue_backoff_s)
        requeued = self._job_store.update_if_status(
            job.job_id,
            JobStatus.RUNNING,
            expect_claim_id=job.claim_id,
            status=JobStatus.QUEUED,
            **fields,
        )
        _log.info("job_id=%s requeued=%s defer=%s (%s)", job.job_id, requeued, defer, reason)
        if self._warm_requeue_backoff_s:
            time.sleep(self._warm_requeue_backoff_s)

    def _purge_job_dir_if_owned(self, job: Job) -> None:
        """Terminal purge of this job's whole dir -- parity with VmJobDispatcher (issue #84).

        Deleting only the input left output/ (metadata.json, rmeta -- text and embedded objects
        extracted from the sample) on the worker forever. The blob store holds the durable copy,
        so nothing is lost by removing it.

        OWNERSHIP-GATED, and that is not optional here. Two dispatcher containers on one node
        share a single job_root bind mount, so a peer that reclaimed this job still needs the
        staged bytes; purging unconditionally would delete them out from under the new owner
        mid-flight. That peer's own terminal purge cleans up instead. This mirrors exactly the
        condition _delete_input_if_owned already applies, so the two cannot disagree about who
        owns the tree.
        """
        self._purge_job_dir_if_claim_matches(job.job_id, job.claim_id)

    def _purge_job_dir_if_claim_matches(self, job_id: str, claim_id: str | None) -> None:
        """The ownership gate itself, callable with an id + the claim we held.

        Split out so the deferred cold-orphan purge (_reconcile_cold_orphans) applies exactly
        the same rule as the inline terminal purge -- the two must never drift, since between
        them they decide whether a peer's staged input survives.
        """
        if job_id in self._upload_failed_job_ids:
            # The result upload exhausted its retries, so results/<job_id> does not exist and
            # this tree is the ONLY copy of a host-sealed, trust-gate-passed result -- including
            # evidence that cannot be reproduced by re-running (the C2 pcap is moved into it, and
            # detonation is explicitly not deterministic run-to-run). Purging here would turn a
            # transient object-store outage into fleet-wide, irreversible result loss. The scratch
            # sweep still bounds it on age. Reviewed on #85.
            self._upload_failed_job_ids.discard(job_id)
            _log.warning("job %s: retaining %s — the result upload failed, so this is the only "
                         "copy", job_id, self._job_root / job_id)
            return

        # This runs from a terminal `finally`, so it must not raise: an escaping store error
        # would mask the DONE/FAILED the job actually produced. And it fails SAFE -- if we
        # cannot PROVE we still own the tree we leave it alone, because the alternative is
        # deleting a peer's staged input mid-flight. A leaked dir is recoverable; a job whose
        # input vanished under it is not (upstream review of #85).
        try:
            final = self._job_store.get(job_id)
        except Exception:  # noqa: BLE001
            _log.warning("job %s: could not confirm ownership for the terminal purge (store "
                         "error); leaving %s in place", job_id, self._job_root / job_id,
                         exc_info=True)
            return
        if final is None or final.claim_id == claim_id:
            purge_job_dir(self._job_root, job_id, _log)

    def _delete_input_if_owned(self, job: Job, input_path: Path) -> None:
        """Delete the shared staged input ONLY if we still hold the claim (or the job
        terminalized under it). The input at job_root/<id>/input is spooled ONCE at submission
        and shared across reclaims; if a peer dispatcher requeued+reclaimed this job (claim_id
        changed/cleared — e.g. we ABORTED a lost claim), the NEW owner still needs it on disk, so
        we must NOT delete it. On the normal owned terminal path claim_id still matches and the
        untrusted input is deleted exactly as before; a leak only occurs if the reclaiming owner
        also dies before its own cleanup, bounded by the retention sweep of job_root/<id>."""
        # Same terminal-`finally` contract as _purge_job_dir_if_owned: never raise (that would
        # mask the job's real outcome) and fail SAFE -- an unprovable owner means leave the
        # bytes for whoever does own them.
        try:
            final = self._job_store.get(job.job_id)
        except Exception:  # noqa: BLE001
            _log.warning("job %s: could not confirm ownership for input deletion (store error); "
                         "leaving the staged input in place", job.job_id, exc_info=True)
            return
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
        # Metrics must never mask the job's real outcome: this runs from the same terminal
        # `finally` as the input delete and the purge, so a store error here would surface
        # instead of the DONE/FAILED the job actually produced (#85 review).
        try:
            return self._record_outcome_inner(job, path=path, started=started)
        except Exception:  # noqa: BLE001
            _log.warning("job %s: failed to record outcome metrics", job.job_id,
                         exc_info=True)
            return

    def _record_outcome_inner(self, job: Job, *, path: str, started: float) -> None:
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
        phases: "_PhaseTimer | None" = None,
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
        # Default rather than required: the marks below then need no `if phases is not None`
        # guard, and the dozens of existing callers/tests that predate the instrumentation keep
        # working. A timer with nobody to emit to costs a list append per phase.
        if phases is None:
            phases = _PhaseTimer(job.job_id)
        runtime = self._pool.runtime  # type: ignore[union-attr]  # pool non-None here
        # BOUND BEFORE THE TRY. The release in the finally consults it for the guest-start
        # signal, and a failure early enough (a blob fetch, a lost claim, a staging error) leaves
        # the later assignment unreached -- an UnboundLocalError raised out of the cleanup path,
        # replacing a real failure with a confusing one. None simply means "no signal", which is
        # exactly right for a job that never got as far as a guest.
        control: "Any | None" = None
        stage_fn = getattr(runtime, "stage_warm_input", None)
        control_fn = getattr(runtime, "host_warm_control", None)
        materialize_fn = getattr(runtime, "materialize_warm_output", None)

        slot_input_copy: Path | None = None
        warm_clean = False  # set True ONLY on the clean DONE path; every _fail_job/timeout/error path
        #                     leaves it False so the slot is released DIRTY (force-recycled, never
        #                     returned to IDLE with a wedged/contaminated worker for the next job).
        # ...and WHOSE failure it was. Dirty means "reset before reuse" either way; the fault only
        # decides whether it counts as evidence AGAINST THE WORKER. A validated engine_error is the
        # engine successfully running and reporting an input-specific failure, so a run of
        # malformed samples must not advance the pool streak and invalidate a healthy snapshot
        # (upstream, PR #82). Attributing everything non-DONE to the worker was my over-correction
        # for the opposite bug one round earlier.
        # UNATTRIBUTED until this worker is positively observed to be at fault. This used to
        # default to "worker" and be walked back exit by exit; six review rounds found six
        # different exits that needed acquitting (four claim races, blob fetch, result upload),
        # because an enumerate-the-innocents design fails OPEN -- every exit anyone forgets
        # silently burns healthy slots and can invalidate a good base. Positive-evidence
        # conviction is the posture the pool already takes on liveness (issue #77): a slow or
        # erroring control plane must never be read as "this worker is dead".
        #
        # Set to "worker" ONLY where the worker itself demonstrably misbehaved: its IO seam
        # failed, it never answered, or it produced output we cannot trust. Host-side failures
        # (blob store, local disk) and lost claims stay unattributed by construction.
        warm_fault = "unknown"
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
                # RECLAIM RACE, not a bad worker: a peer owns the job now, so this worker either
                # never ran or already finished cleanly. Attributing it burns out healthy slots and
                # can invalidate a good base (upstream, PR #82). Same reasoning as ClaimLost on the
                # remote path -- which I fixed while leaving this one.
                warm_fault = "unknown"
                _log.warning(
                    "warm job %s lost its claim before staging (requeued/recovered by another "
                    "dispatcher); aborting", job.job_id,
                )
                return
            job.worker_runtime = "warm"
            job.worker_tier = self._tier

            # ------------------------------------------------------------------
            # Step 2b: Materialise the sample on demand (Finding E1) if this node never
            # spooled it locally -- see the identical comment in _dispatch_inner (cold
            # path). Must run BEFORE staging: the vsock seam reads bytes FROM
            # staged_input_path on the host, and the file-based seam shutil.copy2's it.
            # ------------------------------------------------------------------
            if not self._materialise_sample(job, staged_input_path):
                # THIS HOST could not fetch the sample (blob store unreachable / integrity
                # failure) and the claim has been released back to QUEUED. Nothing was ever
                # handed to the slot, so blaming it means a MinIO/S3 outage marches every node
                # to a base rebuild while evicting healthy slots -- a far more common trigger
                # than any of the claim races.
                warm_fault = "unknown"
                return
            # SPLIT from `stage` on purpose. _materialise_sample pulls the sample from the blob
            # store over the NETWORK; staging below is a vsock write or a local copy. Lumping
            # them reported ~10% of all job-seconds as "staging" when nearly all of it was blob
            # I/O -- and blob I/O is a MinIO/S3 problem, not a dispatcher one. Different fix,
            # different phase.
            phases.mark("fetch")

            # ------------------------------------------------------------------
            # Step 3: Stage input — over the wire (vsock) or into slot.input_dir
            # ------------------------------------------------------------------
            if callable(stage_fn):
                try:
                    input_path = stage_fn(slot, staged_input_path)
                except Exception:
                    # Convict ONLY if this runtime's staging really does talk to the worker.
                    # "There is a stage_warm_input hook" does not mean "this is a transport" --
                    # today NO runtime's does: FC returns the host path unchanged (the bytes go
                    # over vsock later, at signal_go) and gVisor does a host-side shutil.copyfile
                    # into a bind mount, where an ENOSPC/EROFS on the DISPATCHER disk would
                    # otherwise burn out the entire healthy gVisor pool. An earlier version
                    # convicted this branch outright on the mistaken premise that the hook meant
                    # vsock. Runtimes opt IN, so a new one is safe by default, not dangerous.
                    if getattr(runtime, "warm_staging_is_transport", False):
                        warm_fault = "worker"
                    raise
            else:
                slot_input_copy = slot.input_dir / staged_input_path.name
                try:
                    shutil.copy2(staged_input_path, slot_input_copy)
                except OSError as exc:
                    # UNATTRIBUTED. This is a local shutil.copy2 on the dispatcher host; ENOSPC,
                    # EROFS or a failing disk here says nothing about the worker, which has not
                    # been contacted at all yet. A host-wide filesystem outage hits every job at
                    # once, so convicting here burns the whole warm set and invalidates a healthy
                    # base during an incident the workers had no part in. The vsock staging seam
                    # above IS a transport to the worker and stays convicted (upstream, PR #82).
                    self._fail_job(job, f"failed to stage input to warm slot: {exc}")
                    return
                input_path = slot_input_copy
            phases.mark("stage")

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
                # Only if signalling really does reach the worker. FC's control writes over
                # vsock (worker evidence); the FILE handshake used by gVisor is a host-side
                # atomic_write_confined() into the bind-mounted ctrl dir, where ENOSPC/EROFS is a
                # dispatcher-disk failure that would burn out the whole healthy pool. Same
                # opt-in shape as staging, and asked of the CONTROL object because that is what
                # differs -- the runtime may offer both (upstream, PR #82).
                if (getattr(control, "signal_is_transport", False)
                        and not getattr(exc, "host_io", False)):
                    warm_fault = "worker"
                elif isinstance(exc, OSError) and exc.errno not in HOST_RESOURCE_ERRNOS:
                    # ...and the FILE handshake has its own worker evidence. ctrl/ is
                    # WORKER-WRITABLE (the gVisor tier bind-mounts it 0o777), so a poisoned
                    # worker can put a directory or a symlink where go.json belongs and
                    # atomic_write_confined()'s os.replace() raises EISDIR/ENOTEMPTY/ENOTDIR.
                    # That is a concrete violation, not our disk failing -- and leaving it
                    # unknown meant repeated restores from a poisoned checkpoint never advanced
                    # burnout or base-rebuild detection. Only a host-resource errno is ours; the
                    # same split ctrl/done already carries on the worker side (upstream, PR #82).
                    warm_fault = "worker"
                self._fail_job(job, f"failed to signal go to warm worker: {exc}")
                return
            # On the FC seam signal_go is where the sample crosses vsock into the guest, so this
            # is the input-transfer cost and it scales with the document, unlike its neighbours.
            phases.mark("go")

            # ------------------------------------------------------------------
            # Step 5: Wait for done signal (same deadline; remaining budget after the send)
            # ------------------------------------------------------------------
            remaining = warm_deadline - time.monotonic()
            if remaining <= 0:
                warm_fault = "worker"   # it never answered within its deadline
                self._fail_job(
                    job, f"warm worker timed out after {self._worker_timeout_s}s"
                )
                return
            try:
                control.wait_for_done(timeout_s=remaining)
            except WarmTimeout as exc:
                # ...unless the timeout came from OUR filesystem. The FILE handshake turns an
                # EMFILE/EIO/ENOMEM reading ctrl/done into a WarmTimeout, which would otherwise
                # convict a worker that may have completed perfectly -- and a host outage hits
                # every job at once (upstream, PR #82).
                if not getattr(exc, "host_io", False):
                    warm_fault = "worker"   # it never answered within its deadline
                self._fail_job(
                    job,
                    f"warm worker timed out after {self._worker_timeout_s}s",
                )
                return
            # THE one phase that is actual extraction. Everything else on this line is the cost
            # of running it in a disposable sandbox; if the rest outweighs this, tuning the
            # engine is the wrong lever.
            phases.mark("guest")

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
                # RECLAIM RACE, not a bad worker: a peer owns the job now, so this worker either
                # never ran or already finished cleanly. Attributing it burns out healthy slots and
                # can invalidate a good base (upstream, PR #82). Same reasoning as ClaimLost on the
                # remote path -- which I fixed while leaving this one.
                warm_fault = "unknown"
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
                    # materialize_warm_output ends in a host-side rdump_ext4() extraction into
                    # slot.output_dir, so an ENOSPC/EROFS here is a DISPATCHER-disk outage -- which
                    # hits every job at once -- and the guest's output disk may be perfectly valid.
                    # Only a guest/seam failure (FCError: rdump/vsock) is worker evidence.
                    # rdump_ext4 converts a host OSError into ValueError, so the type alone is
                    # not enough -- check the flag it carries as well (PR #82).
                    host_io = getattr(exc, "host_io", False) or (
                        isinstance(exc, OSError) and not isinstance(exc, _GUEST_SEAM_ERRORS)
                    )
                    if not host_io:
                        warm_fault = "worker"   # the guest/seam failed to hand its output back
                    self._fail_job(job, f"failed to read warm worker output: {exc}")
                    return
            phases.mark("rdump")

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
                # Same guard as its siblings. The size cap raises a verdict today, but this
                # handler catches the PARENT type, so a future non-verdict subtype arriving here
                # must not silently become a conviction.
                if not isinstance(exc, OutputTrustUnknown):
                    warm_fault = "worker"   # it emitted more than the declared bound
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
                # ...only when validation reached a VERDICT. OutputTrustUnknown means the host
                # could not complete the check (EMFILE/EIO/ENOMEM reading or hashing), which is
                # evidence about this dispatcher, not the worker -- and a host I/O outage hits
                # every job at once (upstream, PR #82).
                if not isinstance(exc, OutputTrustUnknown):
                    warm_fault = "worker"   # it produced output that failed trust validation
                self._fail_job(job, f"output trust validation failed: {exc}")
                return
            except Exception as exc:  # noqa: BLE001
                self._fail_job(job, f"unexpected trust validation error: {exc}")
                return
            # Covers the output-size cap AND the trust gate: both walk + hash the same output
            # tree, so splitting them would report one traversal as two phases.
            phases.mark("validate")

            # The trust gate validates output STRUCTURE, not the engine's verdict: an engine that
            # honestly reports a FAILED conversion (status="engine_error", typically 0 artifacts)
            # still produces a structurally valid envelope. Gate on it here — else a failed convert
            # is silently marked DONE (a false green that lets a broken warm tier pass a corpus).
            # "rejected" (unsupported/encrypted input) is a legitimate engine verdict, not an error,
            # so it stays DONE.
            if envelope.status == "engine_error":
                detail = envelope.warnings[0].message if envelope.warnings else "engine_error"
                warm_fault = "job"      # the engine RAN and reported on this input
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
                # OutputTrustUnknown is a SUBCLASS by design, so catching the parent here and
                # convicting unconditionally undoes the distinction at the point that consumes
                # it: a host EMFILE/ENOMEM/EIO opening the declared artifact would advance slot
                # burnout and the rebuild streak with no worker verdict at all. Guarded at the
                # trust-gate handler above and not here -- the same sibling omission this series
                # keeps producing (upstream, PR #82).
                if not isinstance(exc, OutputTrustUnknown):
                    warm_fault = "worker"   # its output could not be materialized
                self._fail_job(job, f"failed to materialize warm output: {exc}")
                return
            phases.mark("seal")

            # ------------------------------------------------------------------
            # Step 6c: Upload the sealed HOST output dir to the blob store BEFORE marking
            # DONE (Finding P1) — same policy as the cold path (Finding D1: bounded inline
            # retry, then fail instead of DONE). warm_clean stays False on failure, so the
            # `finally` below releases the slot DIRTY, same as every other warm failure.
            #
            # But put_output writes to a deterministic per-job key as a per-file overwrite,
            # NOT a claim-fenced atomic swap the way the store's CAS is. If our claim was
            # reclaimed since this attempt last checked (peer orphan/requeue sweep → a
            # second worker re-ran + uploaded ITS result + CAS-committed DONE), our write
            # here would land stale/divergent bytes over the peer's already-correct result
            # (Round-2 finding R2-1). Re-checking ownership IMMEDIATELY before the call
            # narrows that window (mirrors VmJobDispatcher._process's identical recheck,
            # and the cold path's above) — it does NOT fully close it: a reclaim landing
            # AFTER this check but DURING the upload call is still possible and unfenced.
            # warm_clean stays False (the finally releases the slot dirty, same as any
            # other lost-claim/failure path) and we do NOT call _fail_job — the job is no
            # longer ours to terminalize; the peer's own state is left untouched.
            # ------------------------------------------------------------------
            if not self._claim_is_still_ours(job):
                # Third of the four claim-loss exits (file order: pre-staging, pre-seal, here,
                # terminal DONE CAS). Like the other three, a peer
                # owning the job says nothing about this worker -- which here has already produced
                # and sealed valid output (upstream, PR #82).
                # "job", not "unknown". This worker has already RUN, produced output and had it
                # pass the host trust gate -- positive proof it and the base it restored from are
                # healthy. Leaving it unknown preserved both streaks, so worker-failure /
                # valid-output-then-claim-loss / worker-failure counted as CONSECUTIVE and could
                # evict the slot or invalidate its base on two unrelated events. The peer owning
                # the job says nothing about this worker; the demonstrated success does
                # (upstream, PR #82).
                warm_fault = "job"
                _log.info(
                    "warm job %s reclaimed before upload; skipping put_output (peer owns "
                    "it now)", job.job_id,
                )
                return
            if not self._upload_output(job, output_dir):
                # The worker RAN and its output passed the trust gate; the upload is OUR side
                # failing. Attribute the demonstrated success so the streaks reset -- the default
                # would convict the worker for this dispatcher's storage problem, and an upload
                # outage hits every job at once (upstream, PR #82).
                warm_fault = "job"
                # Same as the cold branch: no durable copy landed, so the terminal purge must
                # spare this tree rather than destroy the only copy.
                self._upload_failed_job_ids.add(job.job_id)
                # Same ordering and same fence as the cold path above.
                self._retain_for_upload_retry(
                    job,
                    f"result upload failed after {self._put_output_max_attempts} attempts; "
                    f"{RESULT_RETAINED_MARKER}",
                )
                return
            phases.mark("upload")

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
                # This worker RAN AND PRODUCED VALID OUTPUT -- it merely lost the terminal race.
                # Leaving the default "worker" attribution here is the worst of the four
                # claim-loss sites: reclaim races cluster exactly when the queue is deep, so a
                # busy fleet would steadily burn out its healthiest, fastest slots and eventually
                # invalidate a perfectly good base (upstream, PR #82).
                # "job", not "unknown", for the same reason as the pre-upload exit: unknown
                # PRESERVES both streaks, so a failure on either side of this success still
                # counted as consecutive. The run itself is proof the worker and its base are
                # healthy, and reclaim races cluster exactly when the queue is deep.
                warm_fault = "job"
                _log.warning(
                    "warm job %s no longer our RUNNING claim at DONE write (recovered/reclaimed "
                    "by another dispatcher); leaving its terminal state untouched",
                    job.job_id,
                )
            else:
                # DONE applied + still ours: index per-page perceptual hashes for /similar.
                self._index_page_hashes(job.job_id, envelope)
                warm_clean = True   # clean run → the warm slot is safe to reuse without a forced reset
            phases.mark("commit")

        finally:
            phases.outcome = "done" if warm_clean else "failed"
            # Security: release the slot on EVERY terminal path (success, trust-fail,
            # timeout, unexpected error). release() reaps+replaces — warm ≠ reuse.
            # Delete the slot's copy of the input (only the file path makes one; the
            # staged input itself is deleted by the caller on every terminal path).
            if slot_input_copy is not None:
                try:
                    slot_input_copy.unlink(missing_ok=True)
                except OSError:
                    pass
            # dirty=not warm_clean → a failed run force-recycles the slot before reuse.
            # ATTRIBUTED: without a fault this defaults to "unknown", which never advances a slot
            # toward eviction -- so FC/gVisor snapshot workers that time out or return unusable
            # output were invisible to wedge detection entirely, and a poisoned base was never
            # invalidated (upstream, PR #82). A warm run that failed AGAINST this worker is worker
            # evidence; the engine reporting a bad sample is not, and is already excluded because
            # warm_clean covers only the clean DONE path.
            # WHERE it failed, not just that it did. A worker fault whose `guest` phase never
            # ran means the slot never executed anything -- it did not fail on this document, it
            # failed to become able to run one. Three distinct slots doing that convict the base
            # outright, where ordinary worker faults need 2 x warm_size (48 at warm_size=24) to
            # allow for a run of bad samples. Without this distinction a wedged base costs those
            # 48 jobs, each burning the full worker timeout, before the tier repairs itself.
            _stage = warm_fault_stage(warm_clean, warm_fault, phases, control)
            self._pool.release(slot, **release_kwargs(          # type: ignore[union-attr]
                self._pool.release,                                # type: ignore[union-attr]
                dirty=not warm_clean,
                fault=None if warm_clean else warm_fault,
                fault_stage=_stage,
            ))
            # release() reaps AND replaces the microVM (warm != reuse), so this is the respawn
            # cost -- the phase most likely to dominate a cycle whose extraction is milliseconds.
            phases.mark("release")

    def _dispatch_inner(
        self, job: Job, input_path: Path, output_dir: Path,
        orphan_out: list[str] | None = None,
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
        # Step 2b: Materialise the sample on demand (Finding E1) if this node never
        # spooled it locally -- the shared-queue / blob-store deployment, where a
        # worker claims a job whose input was uploaded via another node's ingress.
        # A no-op when the input is already on disk (today's single-node default).
        # Must run BEFORE the bind-mount below: docker silently creates an empty
        # directory for a nonexistent bind source instead of failing.
        # ------------------------------------------------------------------
        if not self._materialise_sample(job, input_path):
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
        from blastbox.host.netapply import (
            docker_network_args,
            inspect_routes_via_gateway,
            worker_resolv_conf,
        )
        from blastbox.host.netwire import (
            BLOCK_INTERNAL_LABEL,
            EGRESS_PORTS_LABEL,
            parse_egress_ports,
        )
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
        # netd wires these tiers by entering the worker's network namespace (nsenter by host pid),
        # which only a runc worker exposes — a runsc (gVisor) worker's network lives in the Sentry's
        # userspace netstack, not a host-visible netns, so wiring is impossible and the worker would
        # just wait for a route that never comes and fail closed. Refuse early with a clear, fixable
        # diagnostic instead. (direct/inetsim ride a plain bridge and httpproxy is env-based — those
        # need no netns wiring and run under runsc fine; only the route/tunnel tiers are gated.)
        needs_netns_wiring = (
            personality.exit_driver in ("tor", "socks", "openvpn", "wireguard")
            or inspect_routes_via_gateway(personality)
        )
        if needs_netns_wiring and runtime.runtime != "runc":
            self._fail_job(
                job,
                f"netpolicy {personality.name!r} (exit={personality.exit_driver}) needs netd to wire "
                f"the worker's network namespace, which the {runtime.runtime!r} runtime does not "
                f"expose (host-visible netns is runc-only today). Run this tier under runc "
                f"(BLASTBOX_ALLOW_RUNC=1 + BLASTBOX_WORKER_RUNTIME=runc), or use a non-wired exit "
                f"(direct / inetsim / httpproxy).",
            )
            return
        # Gateway-routed tiers (tor/openvpn/wireguard/inspect) have netd install the default route
        # AFTER the container starts; the worker waits for that route via BLASTBOX_NET_WAIT_GATEWAY,
        # which is derived from the personality's gateway=. Without it the barrier is empty and a fast
        # engine races netd (flapping / fail-closed). Require gateway= rather than launch a racey job.
        # (socks waits for the TUN device, not a gateway, so it is exempt.)
        routed_via_gateway = (
            personality.exit_driver in ("tor", "openvpn", "wireguard")
            or inspect_routes_via_gateway(personality)
        )
        if routed_via_gateway and not personality.config.get("gateway"):
            self._fail_job(
                job,
                f"netpolicy {personality.name!r} (exit={personality.exit_driver}) is a gateway-routed "
                f"tier but declares no gateway=; the worker can't be told which route to wait for, so "
                f"egress would race netd. Add gateway=<netd gateway IP> to the personality.",
            )
            return
        # Egress-hardening knobs (egress_ports / block_internal) are only enforceable on the
        # gateway-routed, netd-gated tiers (tor/openvpn/wireguard): there the worker's OWN netns OUTPUT
        # carries the real destination IP:port (so a port/destination filter is meaningful) AND egress
        # is fail-closed until netd installs the leak guard (the knobs ride it as a precondition). On a
        # SOCKS/httpproxy proxy hop the OUTPUT is the proxy connection (the filter would drop the
        # tunnel); on a plain bridge (direct/inetsim) it fails OPEN under runsc / before netd wires.
        raw_egress_ports = personality.config.get("egress_ports")
        wants_egress_filter = bool(raw_egress_ports and raw_egress_ports.strip()) or (
            personality.config.get("block_internal", "").strip().lower() in ("1", "true", "yes", "on")
        )
        if wants_egress_filter and personality.exit_driver not in ("tor", "openvpn", "wireguard"):
            self._fail_job(
                job,
                f"netpolicy {personality.name!r} (exit={personality.exit_driver}) declares "
                f"egress_ports or block_internal, which are only enforceable on the netd-gated tiers "
                f"tor, openvpn, or wireguard (the worker's OUTPUT carries the real destination there "
                f"and egress is fail-closed until the leak guard installs). A proxy hop (socks or "
                f"httpproxy) would drop its own tunnel; a plain bridge (direct or inetsim) fails open. "
                f"Use tor, openvpn, or wireguard, or drop the knob.",
            )
            return
        if (raw_egress_ports and raw_egress_ports.strip()
                and parse_egress_ports(raw_egress_ports) is None):
            self._fail_job(
                job,
                f"netpolicy {personality.name!r}: egress_ports={raw_egress_ports!r} has no valid port "
                f"(1-65535) — refusing rather than widen egress.",
            )
            return
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
        # tor / SOCKS / VPN / inspect personalities run the worker on an INTERNAL bridge (no direct
        # egress); netd wires the only route out. The label requests that wiring by mode; until netd
        # wires it the worker simply has no egress (fail-closed).
        #   inspect (any egress exit)      → default route via sslproxy/MITM gw (bb-inspect)
        #   tor (CAPE transparent)         → default route → host gw + host REDIRECT to tor (bb-socks)
        #   socks (BrightData/SOCKS5)      → tun2socks in the netns   (bb-socks)
        #   openvpn / wireguard (all-IP)   → default route via gateway (bb-vpn)
        # Inspect WINS: an inspected worker faces the MITM gateway (which chains onward to the real
        # exit), so it is routed to the gateway regardless of the underlying exit driver — but ONLY
        # for a route-inspectable driver. inspect+httpproxy is unsupported: docker_network_args
        # fails it closed to --network=none, so we must NOT label it wire=inspect (which would send
        # netd chasing a gateway route that doesn't apply). Same predicate, single source of truth.
        if inspect_routes_via_gateway(personality):
            worker_labels["blastbox.net.wire"] = "inspect"
        elif personality.exit_driver == "tor":
            worker_labels["blastbox.net.wire"] = "transproxy"
        elif personality.exit_driver == "socks":
            worker_labels["blastbox.net.wire"] = "socks"
            # Per-personality SOCKS endpoint (e.g. a specific country's tor SocksPort) overrides
            # netd's global --socks-proxy, so one netd fronts a whole fleet of socks backends.
            if personality.config.get("proxy"):
                worker_labels["blastbox.net.socks-proxy"] = personality.config["proxy"]
        elif personality.exit_driver in ("openvpn", "wireguard"):
            worker_labels["blastbox.net.wire"] = "vpn"

        # Non-TCP leak guard for the TCP-only proxy tiers (tor/socks/httpproxy): netd installs an
        # in-netns OUTPUT firewall that DROPs all non-TCP egress (UDP/ICMP/raw) — these tiers carry
        # only TCP, so a sample must not be able to leak non-TCP past the worker. The VPN tier is the
        # all-IP path and gets NO guard. tor needs UDP:53 out (the host DNSPort REDIRECT) → "dns".
        # A socks personality that opted OUT of use-vc (dns_tcp=0) resolves over UDP:53 to a directly
        # reachable resolver, so it ALSO needs the "dns" guard or its DNS would be dropped (its
        # resolv.conf has no use-vc — see worker_resolv_conf — so strict would break resolution).
        socks_udp_dns = (
            personality.exit_driver == "socks"
            and personality.config.get("dns_tcp", "1").strip().lower() in ("0", "false", "no")
        )
        if personality.exit_driver == "tor" or socks_udp_dns:
            worker_labels["blastbox.net.leakguard"] = "dns"
        elif personality.exit_driver in ("socks", "httpproxy"):
            worker_labels["blastbox.net.leakguard"] = "strict"

        # Egress-filter labels for the gateway-routed tiers (already gated to tor/openvpn/wireguard +
        # validated above). netd folds these into the in-netns leak guard, which is a PRECONDITION for
        # wiring → fail-closed. tor already carries 'dns' (TCP+DNS only) from the block above; the
        # all-IP vpn tiers get 'allip' so block_internal keeps non-internal UDP/ICMP.
        if wants_egress_filter:
            egress_ports = parse_egress_ports(personality.config.get("egress_ports"))
            if egress_ports is not None:
                worker_labels[EGRESS_PORTS_LABEL] = ",".join(str(p) for p in egress_ports)
            if personality.config.get("block_internal", "").strip().lower() in (
                    "1", "true", "yes", "on"):
                worker_labels[BLOCK_INTERNAL_LABEL] = "1"
            worker_labels.setdefault("blastbox.net.leakguard", "allip")

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
                # Egress-readiness barrier for netd-wired tiers: netd installs the worker's only
                # route out AFTER the container starts, so tell the harness what to wait for before
                # detonating — otherwise a fast one-shot engine reaches the network first and fails
                # closed. inspect/vpn wait for the gateway route (personality `gateway=`, must match
                # netd's --inspect-gateway/--vpn-gateway); socks waits for the tun2socks TUN device.
                # Empty = no wait. Merged last so a hostile job.param can't suppress it.
                "BLASTBOX_NET_WAIT_GATEWAY": (
                    personality.config.get("gateway", "")
                    if (inspect_routes_via_gateway(personality) or personality.exit_driver
                        in ("tor", "openvpn", "wireguard"))
                    else ""
                ),
                "BLASTBOX_NET_WAIT_TUN": (
                    "tun0" if (personality.exit_driver == "socks"
                               and not personality.inspect) else ""
                ),
                # httpproxy tier: the worker's only egress is an HTTP(S) proxy. Inject it as the
                # standard proxy env (both case-variants for client coverage) from the personality's
                # `proxy=` — a creds-holding chaining sidecar, so the upstream provider creds never
                # enter the untrusted worker env. Merged last so a hostile job.param can't override.
                # The URL is validated (parity with the socks tier): a malformed proxy= injects no
                # env → the worker fails closed (internal bridge, no egress) rather than racing some
                # client's direct-fallback behaviour.
                **self._httpproxy_env(personality),
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
            # Kill the stuck container. If the kill is NOT confirmed, flag a possible orphan so the
            # caller keeps its cold-permit reservation (the container may still hold node RAM).
            if not self._kill_container(container_name) and orphan_out is not None:
                orphan_out.append(container_name)
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
        # Step 5c: Upload the sealed output to the blob store BEFORE marking DONE
        # (Finding P1) — the API's result routes read ONLY through BlobStore.open_output,
        # so a job marked DONE without a stored result would 404 on every result route in
        # the default local deployment. A failure here (after bounded inline retries, see
        # Finding D1) takes the normal failure path instead of DONE.
        #
        # But put_output writes to a deterministic per-job key (results/<job_id>/...) as a
        # per-file overwrite, NOT a claim-fenced atomic swap the way the store's CAS is. If
        # our claim was reclaimed since this attempt last checked (e.g. a peer's orphan/
        # requeue sweep decided this job's owner was gone, requeued it, and a second worker
        # re-ran + uploaded ITS result + CAS-committed DONE), our write here would land
        # stale/divergent bytes over the peer's already-correct, already-DONE result —
        # detonation is not guaranteed deterministic run-to-run, so this is a real
        # corruption, not a harmless redundant rewrite (Round-2 finding R2-1). Re-checking
        # ownership IMMEDIATELY before the call narrows that window (mirrors
        # VmJobDispatcher._process's identical recheck) — it does NOT fully close it: there
        # is no store-level compare-and-swap on the uploaded object itself, so a reclaim
        # landing AFTER this check but DURING the upload call is still possible and is not
        # fenced here.
        # ------------------------------------------------------------------
        if not self._claim_is_still_ours(job):
            _log.info(
                "cold job %s reclaimed before upload; skipping put_output (peer owns it "
                "now)", job.job_id,
            )
            return
        if not self._upload_output(job, output_dir):
            # The durable copy never landed, so do NOT purge this tree -- it is the only copy.
            self._upload_failed_job_ids.add(job.job_id)
            # BEFORE the terminal write, not after: a crash in between would otherwise lose the
            # marker, and without it the tree is ordinary scratch that the reclaim deletes -- the
            # only copy of a sealed result. The marker records OUR claim, and the sweep refuses to
            # act on one whose claim no longer matches the row, so writing it early cannot let a
            # superseded attempt publish over a peer. If we then lose the CAS we clear it anyway,
            # so the common case leaves nothing behind (#85 review).
            self._retain_for_upload_retry(
                job,
                f"result upload failed after {self._put_output_max_attempts} attempts; "
                f"{RESULT_RETAINED_MARKER}",
            )
            return

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

    def _claim_is_still_ours(self, job: Job) -> bool:
        """Whether we still own the claim: the stored job is RUNNING with OUR claim_id.

        Mirrors ``VmJobDispatcher._claim_is_still_ours`` — a best-effort TOCTOU narrowing
        for ``_upload_output``, which the store's CAS can't fence (``put_output`` writes to
        a deterministic per-job key as a per-file overwrite, not a claim-fenced atomic
        swap). A store read error is treated as "not ours" — fail closed, don't upload."""
        try:
            cur = self._job_store.get(job.job_id)
        except Exception:  # noqa: BLE001 — a transient store error → don't risk a stale upload
            return False
        return cur is not None and cur.status == JobStatus.RUNNING and cur.claim_id == job.claim_id

    def _materialise_sample(self, job: Job, input_path: Path) -> bool:
        """Ensure *input_path* exists on THIS node's disk before it's consumed (the cold
        bind-mount / the warm stage-into-slot copy), fetching it from the blob store on
        demand if not (Finding E1). Mirrors ``VmJobDispatcher._process``'s identical
        on-demand materialise + bounded-release policy -- see that module for the full
        rationale.

        Returns True to tell the caller to proceed (the input is present, whether it was
        already there or was just fetched). Returns False to tell the caller to stop
        immediately (``return``): this method has already terminalized the claim itself --
        either RELEASED it back to QUEUED (bounded retry) or FAILED it once
        ``MAX_MATERIALISE_ATTEMPTS`` is reached -- so the caller must not run the worker or
        write any further job state.

        Single-node behaviour is UNCHANGED: when ``input_path`` already exists (the
        default -- this node's own ingress spooled it), this is a pure no-op with no
        ``get_sample`` call and no store write.
        """
        if input_path.exists():
            return True
        if job.input_sha256 is None:
            # No content key to fetch by -- there's nothing a blob store could
            # materialise. Same terminal shape as before this feature existed.
            self._fail_job(job, f"spooled input missing: {input_path}")
            return False
        try:
            self._blobs.get_sample(job.input_sha256, input_path)
        except BlobFetchError:
            # A fetch failure is a property of THIS worker's connectivity, not of the
            # sample -- release the claim (bounded) rather than failing the job outright,
            # so another node can retry. See MAX_MATERIALISE_ATTEMPTS above.
            attempts = job.materialise_attempts + 1
            finished = time.time()
            expires_at = (
                finished + self._job_retention_seconds
                if self._job_retention_seconds > 0
                else None
            )
            if attempts >= MAX_MATERIALISE_ATTEMPTS:
                _log.warning(
                    "job %s could not materialise its sample after %d attempts; failing",
                    job.job_id, attempts,
                )
                self._job_store.update_if_status(
                    job.job_id,
                    JobStatus.RUNNING,
                    expect_claim_id=job.claim_id,
                    status=JobStatus.FAILED,
                    finished_at=finished,
                    error=sanitize_public_error(
                        f"sample could not be materialised after {attempts} attempts"
                    ),
                    materialise_attempts=attempts,
                    expires_at=expires_at,
                )
            else:
                _log.warning(
                    "job %s could not materialise its sample; releasing the claim for "
                    "another node", job.job_id,
                )
                # RUNNING -> QUEUED, CAS'd on (status, claim_id) so a stale owner can't
                # clobber a job that was already RECLAIMED. claim_id is cleared so the
                # next claim_next() stamps a fresh token; worker_runtime/worker_tier are
                # reset (mirrors _requeue_claimed) so a re-claim looks fresh regardless of
                # which path (warm/cold) picks it up next. claimable_after backs the job
                # off briefly so THIS dispatcher doesn't instantly re-claim + spin on a
                # sample its own connectivity can't reach; created_at is left untouched
                # (public ordering + max_queued_age must still see the real submission time).
                self._job_store.update_if_status(
                    job.job_id,
                    JobStatus.RUNNING,
                    expect_claim_id=job.claim_id,
                    status=JobStatus.QUEUED,
                    claim_id=None,
                    worker_runtime=None,
                    worker_tier=None,
                    claimable_after=time.time() + self._blob_retry_backoff_s,
                    materialise_attempts=attempts,
                )
            # This attempt never materialised anything -- clean up whatever this worker's
            # job dir accumulated (e.g. an empty input/ dir a failed get_sample's atomic-copy
            # helper may have created via its parent mkdir) so nothing lingers on this node.
            self._delete_input(input_path)
            return False
        else:
            # Finding E3: a successful fetch means this attempt's failure streak is over --
            # reset the counter so only CONSECUTIVE fetch failures accumulate toward
            # MAX_MATERIALISE_ATTEMPTS, matching its "permanently missing" intent. Persisted
            # (not just the in-memory `job`) so a later reclaim that must re-fetch (the
            # sample vanished from THIS node again, e.g. a different node next time) starts
            # counting from zero instead of inheriting an earlier, unrelated failure streak.
            if job.materialise_attempts:
                self._job_store.update_if_status(
                    job.job_id,
                    JobStatus.RUNNING,
                    expect_claim_id=job.claim_id,
                    materialise_attempts=0,
                )
            return True

    def _upload_output(self, job: Job, output_dir: Path) -> bool:
        """Upload *output_dir* (already sealed) to the blob store, with a bounded inline
        retry (Finding P1/D1). Called from BOTH the cold and warm success paths, BEFORE
        their DONE write — the API's result routes read ONLY through
        ``BlobStore.open_output`` (ingress/app.py), so a job marked DONE without a
        successful upload would 404 on every result route.

        Returns True on success. On exhaustion, logs the last error and returns False;
        the caller must NOT mark the job DONE — it takes its normal failure path
        (``_fail_job``) instead, exactly like every other post-detonation failure (trust
        validation, output-too-large, …). There is no "leave it running for later" branch:
        mirrors the identical policy in ``VmJobDispatcher._process`` (Finding D1) — nothing
        ever re-runs a RUNNING job, so preserving one for a retry that never comes would
        only leak the job dir forever.
        """
        exc = upload_output_with_retry(
            self._blobs, job.job_id, output_dir,
            attempts=self._put_output_max_attempts,
            backoff_s=self._put_output_retry_backoff_s,
        )
        if exc is None:
            return True
        _log.error(
            "result upload failed for job %s after %d attempt(s) (%s); failing the job "
            "(result discarded, not stored)",
            job.job_id, self._put_output_max_attempts, exc,
        )
        # Finding S1: a partial result may already be sitting under results/<job_id> (e.g.
        # some of put_output's per-file put_object calls landed before a later one failed).
        # The caller below marks the job FAILED via _fail_job, never DONE, so this job will
        # never be served (open_output is DONE-gated) -- and with the default
        # job_retention_seconds=0, expires_at is None, so the retention sweeper skips it
        # forever (retention.py: `if job.expires_at is None ... continue`). Without reaping
        # here, that partial blob is orphaned permanently, recoverable only by an explicit
        # DELETE. delete_job is results-scoped + idempotent. Best-effort: a reap failure
        # must not mask the real upload failure / FAILED outcome this method is already
        # reporting.
        #
        # Claim-fenced (ultrareview bug_001): the pre-upload `_claim_is_still_ours` check
        # ran BEFORE the retry loop -- the whole backoff window sits between it and here.
        # If a peer requeued + re-ran + CAS-committed DONE during that window, its upload
        # landed at this same results/<job_id> prefix and an unconditional delete_job
        # would wipe the peer's authoritative result out from under the DONE it wrote
        # (job store says DONE, every result route 404s, and nothing ever repairs it --
        # our _fail_job CAS correctly no-ops on the stale claim, but only AFTER this
        # delete would have run). On a lost claim the prefix isn't ours to reap; the
        # bounded partial-blob leak in the rare lost-claim-but-no-peer-upload case is the
        # strictly smaller cost (recoverable via DELETE), so skip.
        if self._claim_is_still_ours(job):
            try:
                self._blobs.delete_job(job.job_id)
            except Exception as reap_exc:  # noqa: BLE001
                _log.warning(
                    "failed to reap partial result blob for job %s after upload exhaustion: %s",
                    job.job_id, reap_exc,
                )
        else:
            _log.info(
                "job %s: skipping partial-blob reap on upload exhaustion; claim lost -- "
                "results/<job_id> belongs to a peer now", job.job_id,
            )
        return False

    def _index_repaired_result(self, job_id: str, out_dir: Path, seal_text: str) -> None:
        """Post-repair hook for the pending-upload sweep: do what this job's own DONE path never
        got to do. Only page-hash indexing today -- a recovered job is otherwise DONE, servable
        and permanently invisible to /similar, because nothing re-walks DONE jobs."""
        try:
            from blastbox.contract.envelope import Envelope

            # From the bytes the sweep read while the tree was still held, not from the
            # tree itself -- which a peer may already have reclaimed once the row went DONE.
            envelope = Envelope.model_validate_json(seal_text)
        except Exception:  # noqa: BLE001 -- the repair stands; only the index is best-effort
            _log.warning("could not parse sealed metadata for repaired job %s", job_id,
                         exc_info=True)
            return
        self._index_page_hashes(job_id, envelope)
        # ...and the summary the DONE path would have written. Without it a recovered job is DONE
        # with result_summary=None forever -- /v1/jobs and the status route report null
        # artifact/warning counts, and anything that tallies off them (the fleet corpus runners
        # do) silently under-reports every recovered job. Nothing re-walks DONE jobs to fix it.
        try:
            summary = _build_result_summary(envelope)
        except Exception:  # noqa: BLE001 -- the repair stands; the summary is cosmetic
            return
        with contextlib.suppress(Exception):
            self._job_store.update(job_id, result_summary=summary)

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

    def _retain_for_upload_retry(self, job: Job, reason: str) -> None:
        """Terminalize a job whose result upload exhausted, keeping its tree as the last copy.

        The ORDER here is the whole point, and both call sites need exactly this order, which is
        why it is one method rather than two copies:

        1. Mark FIRST. The marker is what tells every later sweep -- in this process, in the peer
           dispatcher, and after a restart -- that this tree holds the only copy of a host-sealed
           result. Written after the terminal store write instead, a crash in the gap (SIGKILL,
           OOM, redeploy: the class this mechanism exists for) loses it, and the tree becomes
           ordinary scratch that the reclaim deletes.
        2. Then the terminal CAS.
        3. If the CAS LOST, drop the marker again: a peer reclaimed the job during our retry
           window, so our tree is a stale attempt. The marker also records our claim, so even a
           marker stranded by a crash at step 2 cannot license publishing those stale bytes -- the
           sweep refuses one whose claim no longer matches the row.
        """
        mark_pending_upload(self._job_root, job.job_id, _log, job.claim_id)
        if not self._fail_job(job, reason):
            clear_pending_upload(self._job_root, job.job_id, job.claim_id)

    def _fail_job(self, job: Job, reason: str) -> bool:
        """Mark a job FAILED, scrubbing the error string before storage. Returns whether OUR
        attempt won the CAS.

        Claim-fenced on (RUNNING, our claim_id): if a peer dispatcher already requeued/recovered
        this job, the owner's FAILED is a no-op (don't clobber the new owner's state). In the
        normal path the job is RUNNING under our claim, so it applies as before.

        The return value matters to callers that leave state behind on the strength of the
        failure -- specifically the pending-upload sentinel, which must never be written onto a
        tree a peer now owns."""
        error = sanitize_public_error(reason)
        finished_at = time.time()
        expires_at = (
            finished_at + self._job_retention_seconds
            if self._job_retention_seconds > 0
            else None
        )
        return bool(self._job_store.update_if_status(
            job.job_id,
            JobStatus.RUNNING,
            expect_claim_id=job.claim_id,
            status=JobStatus.FAILED,
            finished_at=finished_at,
            expires_at=expires_at,
            error=error,
        ))

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

    def _confined_capture_dir(self, output_dir: Path) -> Path | None:
        """``output_dir/capture`` as a real directory confined under ``output_dir`` (created if
        absent), or ``None`` if the untrusted worker planted a SYMLINK there. The capture/decrypt
        artifacts are written HOST-side after worker-output validation, so a worker-planted symlink
        at ``output/capture`` would otherwise let the host pcap copy / GoGoRoboCap output follow it
        OUTSIDE the job tree (a containment escape). The worker has already exited by seal time, so
        the symlink is static — a check-then-write here has no live TOCTOU."""
        cap = output_dir / "capture"
        try:
            if cap.is_symlink():
                _log.warning("refusing capture seal: %s is a symlink (worker tampering)", cap)
                return None
            cap.mkdir(parents=True, exist_ok=True)
            real_out, real_cap = os.path.realpath(output_dir), os.path.realpath(cap)
            if os.path.commonpath([real_out, real_cap]) != real_out:
                _log.warning("refusing capture seal: %s escapes %s", cap, output_dir)
                return None
        except (OSError, ValueError) as exc:
            _log.warning("capture dir guard failed for %s: %s", output_dir, exc)
            return None
        return cap

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
        done = output_dir.parent / "capture" / "dump.pcap.done"
        try:
            # If a capture exists but netd's die-handler hasn't finalized it yet, wait (bounded) for
            # the .done sentinel so we copy a COMPLETE pcap, not one tcpdump is still appending to.
            # Gated on the pcap existing → no wait when capture is off (no netd, sentinel never lands).
            if src.is_file() and not done.is_file():
                deadline = time.monotonic() + self._net_capture_wait_s
                while not done.is_file() and time.monotonic() < deadline:
                    time.sleep(0.05)
            if not src.is_file() or src.stat().st_size == 0:
                return envelope
            size = src.stat().st_size
            if size > self._limits.max_artifact_bytes:
                _log.warning(
                    "netd capture for output %s is %d bytes (> max_artifact_bytes %d); not sealed",
                    output_dir, size, self._limits.max_artifact_bytes,
                )
                return envelope
            # Don't overwrite a path the worker already declared as its own artifact — the served
            # bytes would then mismatch that artifact's sealed sha. Leave the worker's artifact be.
            if any(a.path == "capture/dump.pcap" for a in envelope.artifacts):
                _log.warning("capture/dump.pcap already declared by the worker; not sealing netd "
                             "capture for %s", output_dir)
                return envelope
            # This host artifact is appended AFTER worker-output validation/cap enforcement, so honor
            # the same ceilings here rather than silently exceeding them in the final metadata.
            if len(envelope.artifacts) >= self._limits.max_artifacts:
                _log.warning("artifact count cap reached; not sealing netd capture for %s", output_dir)
                return envelope
            if (sum(a.bytes for a in envelope.artifacts) + size) > \
                    self._limits.max_total_artifact_bytes:
                _log.warning("total artifact-bytes cap reached; not sealing netd capture for %s",
                             output_dir)
                return envelope
            dst_dir = self._confined_capture_dir(output_dir)
            if dst_dir is None:
                return envelope
            dst = dst_dir / "dump.pcap"
            if dst.is_symlink():
                _log.warning("refusing capture seal: %s is a symlink (worker tampering)", dst)
                return envelope
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

        # Decrypt the HOST-ONLY original pcap and write GoGoRoboCap's output into the host-only
        # capture dir (a sibling of output/, OFF the worker /output mount). The worker never had
        # write access there, so it can't pre-plant a symlink for ggrc's -o write to follow outside
        # the job tree. We then confined-COPY each output into output/capture/ with the SAME
        # symlink/collision/cap guards as the raw pcap (parity with _seal_network_capture).
        host_cap = output_dir.parent / "capture"
        pcap = host_cap / "dump.pcap"
        keylog = host_cap / "sslkeys.log"  # host-only key drop
        if not pcap.is_file() or pcap.is_symlink():
            return envelope
        # The keylog is dropped by netd on the worker's die event, which races this seal. If we have
        # a capture but the keylog hasn't landed yet, wait briefly for it rather than skip decrypt.
        deadline = time.monotonic() + self._decrypt_keylog_wait_s
        while (not keylog.is_file() or keylog.stat().st_size == 0) and time.monotonic() < deadline:
            time.sleep(0.1)
        if not keylog.is_file() or keylog.stat().st_size == 0:
            return envelope
        try:
            result = decrypt_capture(
                binary=self._gogorobocap_bin,
                pcap_path=str(pcap),
                keylog_path=str(keylog),
                out_dir=str(host_cap),  # host-only scratch — worker can't plant a symlink here
                run_fn=lambda argv: self._subprocess_runner(
                    argv, capture_output=True, text=True, check=False, timeout=300
                ).returncode,
            )
        except Exception as exc:  # noqa: BLE001 — decrypt is best-effort enrichment
            _log.warning("decrypt seal for output %s failed: %s", output_dir, exc)
            return envelope
        if result is None:
            return envelope
        dst_dir = self._confined_capture_dir(output_dir)  # output/capture, refuse a symlinked dir
        if dst_dir is None:
            return envelope
        new_artifacts = list(envelope.artifacts)
        total = sum(a.bytes for a in new_artifacts)
        for art_id, kind, path in (
            ("network.capture.decrypted.pcap", "network_capture_decrypted", result.decrypted_path),
            ("network.capture.mixed.pcap", "network_capture_mixed", result.mixed_path),
        ):
            if not path:
                continue
            try:
                src = Path(path)
                if not src.is_file() or src.is_symlink():
                    continue
                size = src.stat().st_size
                if size > self._limits.max_artifact_bytes:
                    continue
                rel = f"capture/{src.name}"
                if any(a.path == rel for a in new_artifacts):  # path already declared by the worker
                    continue
                if len(new_artifacts) >= self._limits.max_artifacts:
                    break
                if total + size > self._limits.max_total_artifact_bytes:
                    break
                dst = dst_dir / src.name
                if dst.is_symlink():
                    continue
                shutil.copy2(src, dst)
                h = hashlib.sha256()
                with open(dst, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                new_artifacts.append(Artifact(
                    id=art_id, path=rel, kind=kind,
                    sha256=h.hexdigest(), bytes=dst.stat().st_size,
                ))
                total += dst.stat().st_size
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
            try:
                fd = open_confined_regular_fd(src_dir, a.path)
            except (FileNotFoundError, ValueError) as exc:
                # The worker DELETED or SWAPPED a declared artifact between validation and this
                # copy -- on the gVisor tier /out is a live 0o777 bind mount, so it can. Those
                # come out of the confinement check as FileNotFoundError/ValueError rather than
                # OutputTrustError, so they bypassed the trust handler upstream and left the
                # failure unattributed: repeated untrusted-output races never advanced burnout or
                # rebuild detection even though the worker caused every one (upstream, PR #82).
                raise OutputTrustError(
                    f"declared artifact {a.id} vanished or changed type during materialization"
                ) from exc
            except OSError as exc:
                # ELOOP/ENOTDIR come from the CONFINEMENT check: the worker swapped the artifact
                # for a symlink, or put a symlink/non-directory in the path. That is a violation,
                # and calling it unknown meant repeated malicious swaps never advanced burnout.
                # Only a host-resource errno is ours (PR #82) -- the same split just applied to
                # the validation path, missing from this one.
                if exc.errno not in HOST_RESOURCE_ERRNOS:
                    raise OutputTrustError(
                        f"declared artifact {a.id} failed the confinement check ({exc})"
                    ) from exc
                raise OutputTrustUnknown(
                    f"could not open declared artifact {a.id} ({exc})"
                ) from exc
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
        # BEFORE the scratch reclaim, for two reasons. (1) It is cheap -- one `docker ps` and a
        # purge per confirmed-gone orphan -- while the reclaim walks every tree under job_root and
        # does a store lookup per candidate; running the reclaim first head-of-line blocks the
        # cold permits behind it on exactly the fleet state this PR targets (97,681 dirs). (2) It
        # purges the orphans it confirms and drops them from _retained_cold_orphans, so the
        # reclaim's skip set is accurate for THIS tick instead of one tick stale (#85 review).
        try:
            self._reconcile_cold_orphans()
        except Exception:  # noqa: BLE001
            _log.exception("cold-orphan reconcile failed")
        # BEFORE the reclaim: a retained tree is a PENDING UPLOAD, and draining it is what makes
        # the reclaim's last-copy rule a temporary hold rather than a permanent one.
        try:
            if self._pending_upload_retry:
                retry_pending_uploads(self._job_root, self._blobs, self._job_store, _log,
                                      on_repaired=self._index_repaired_result,
                                      retention_seconds=self._job_retention_seconds)
        except Exception:  # noqa: BLE001
            _log.exception("pending-upload sweep failed")
        try:
            self._reap_stale_scratch()
        except Exception:  # noqa: BLE001
            _log.exception("scratch reclaim failed")
        if self._job_retention_seconds > 0:
            try:
                from blastbox.host.jobs.retention import JobRetentionSweeper

                expired = JobRetentionSweeper(
                    self._job_root, blob_store=self._blobs
                ).expire_due(self._job_store)
                if expired:
                    _log.info("retention_sweep_expired count=%d", len(expired))
            except Exception:  # noqa: BLE001
                _log.exception("retention sweep failed")

    def _dispatch_saturated(self) -> bool:
        """True when every dispatch slot is in use, i.e. work is queueing behind us.

        Read from the concurrency gate when there is one (it counts in-flight cold workers);
        otherwise assume NOT saturated, so a deployment without the autosizer still reclaims.
        """
        gate = self._concurrency_gate
        if gate is None:
            return False
        try:
            return gate.in_flight >= gate.limit
        except Exception:  # noqa: BLE001
            return False

    def _reap_stale_scratch(self) -> int:
        """Reclaim this dispatcher's stale scratch. The implementation is SHARED with
        VmJobDispatcher (jobs/retention.reap_stale_scratch) for the same reason purge_job_dir
        is: two copies of a destructive age rule drift, and #84 is what that costs.

        The one thing only this dispatcher can supply is skip_job_ids -- trees whose worker
        container this process still believes is alive. VmJobDispatcher has no cold-orphan
        retention, so it passes none.
        """
        with self._retained_lock:
            retained = {jid for jid, _claim in self._retained_cold_orphans.values()}
        return reap_stale_scratch(
            self._job_root, self._scratch_max_age_s, self._job_store, _log,
            skip_job_ids=retained, blob_store=self._blobs,
            recovery_enabled=self._pending_upload_retry,
            protect_paths=_blob_local_roots(),
            live_job_ids=self._list_active_worker_job_ids,
            # Skip the sweep entirely while every dispatch slot is busy: the machine has better
            # things to do with its disk and its object store than housekeeping.
            yield_to_work=self._dispatch_saturated,
        )

    def _reconcile_cold_orphans(self) -> None:
        """Release cold permits we RETAINED for a failed-kill container ONCE `docker ps` confirms
        the container is gone (it exited on its own, or a later kill/host reaper got it). Until
        then the permit stays held so no worker stacks on a possible orphan; here we reclaim it so
        the retention isn't permanent. If docker ps can't be read we keep retaining (can't confirm
        absence)."""
        # NOT gated on `gate is not None`: the deferred PURGE has to run whether or not this
        # dispatcher has a concurrency gate. Only the release below is the gate's business.
        gate = self._concurrency_gate
        with self._retained_lock:
            if not self._retained_cold_orphans:
                return
        # Snapshot WHICH orphans this verdict is about BEFORE querying docker. `docker ps` is a
        # subprocess round-trip, and dispatch threads register new orphans throughout it; judging
        # the post-query map against the pre-query snapshot would classify an orphan registered
        # in that window as "confirmed gone" -- its container was never in the listing because it
        # did not exist yet when the listing was taken. That used to leak a permit; now it also
        # rmtree's a live container's tree (#85 review).
        with self._retained_lock:
            candidates = set(self._retained_cold_orphans)
        live_ids = self._list_active_worker_job_ids()
        if live_ids is None:
            return                        # can't confirm absence → keep retaining
        live_names = {f"blastbox-worker-{jid[:12]}" for jid in live_ids}
        with self._retained_lock:
            gone = [n for n in candidates
                    if n not in live_names and n in self._retained_cold_orphans]
            reclaimed = [self._retained_cold_orphans.pop(n) for n in gone]
        if gate is not None:
            for _ in gone:
                gate.release()            # container confirmed gone → reclaim its permit
        if gone and gate is not None:
            _log.info("reclaimed %d cold permit(s) from confirmed-gone orphan container(s)", len(gone))
        # ...and NOW purge the trees we deliberately left behind. The inline terminal purge skips
        # a failed-kill orphan because rmtree'ing under a live writer half-deletes the tree, races
        # into a spurious "PURGE FAILED", and reclaims nothing (its fds pin the disk anyway). This
        # is the moment that reservation expires: docker ps has CONFIRMED the container is gone,
        # so the tree is inert and the security invariant applies again. Without this the sample
        # bytes sat until the age reclaim -- hours -- and the deferral comment upstream promised a
        # sweep that only ever reclaimed the permit (#85 review / upstream codex comment).
        for job_id, claim_id in reclaimed:
            try:
                clear_retained_orphan(self._job_root, job_id)   # confirmed gone: the hold ends
                self._purge_job_dir_if_claim_matches(job_id, claim_id)
            except Exception:  # noqa: BLE001 -- one bad tree must not strand the rest
                _log.exception("cold-orphan purge failed for job %s", job_id)

    def _kill_container(self, container_name: str) -> bool:
        """``docker kill`` a timed-out worker. Returns True only if the container is CONFIRMED
        stopped (kill returned 0), False if the kill failed / errored / timed out — in which case
        the container may still be running and holding node RAM, so the caller must keep its
        reservation (not free the cold permit) until a later sweep confirms cleanup."""
        try:
            proc = self._subprocess_runner(
                ["docker", "kill", container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:  # noqa: BLE001
            return False
        return getattr(proc, "returncode", 1) == 0

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
