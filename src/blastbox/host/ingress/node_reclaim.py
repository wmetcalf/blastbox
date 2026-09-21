"""Reclaim jobs whose node-side owner is gone (#178).

WHY THIS HAS TO EXIST HERE. The node-claim design leans on "reclaim on timeout" as the bound
on every lost-claim case -- a node restarting mid-job, a claim response lost in flight, a kill
between claiming and recording. That path is `Dispatcher.requeue_orphaned_jobs`, whose first
statement is ``list(status=RUNNING)``, and a credential-less node's store REFUSES to enumerate
the queue. So on the one topology where the claim routes are prevention rather than advice, the
backstop the design cited did not exist at all: three separate safety arguments rested on a
sweep that could never run, and the only symptom was a swallowed traceback per maintenance tick.

Three independent reviewers found that, which is what it deserved.

The queue belongs to the control plane, so the sweep belongs here too. This is the TIME-BASED
half of the dispatcher's own recovery, which is the half that needs no local docker: a job still
RUNNING long past any plausible progress has a gone owner.

IT FAILS, IT DOES NOT REQUEUE, and that is not a detail. `requeue_orphaned_jobs` records the
reason: a requeue "would let a second worker re-detonate the same untrusted input, and orphaned
sandboxes don't die with a crashed dispatcher". Terminal is the safe end for an abandoned
detonation.

THE QUEUED HALF IS HERE TOO (:func:`fail_stale_queued`). Work pinned with ``target_tier`` is
unclaimable on an all-federated fleet -- the node path passes no tier, so `claim_next` skips
pinned rows by design -- and the dispatcher's counterpart is list()-driven, so it stayed behind
with the database. Such a job otherwise sits QUEUED forever with its untrusted sample spooled
under the ingress's own job_root, which the scratch reaper will not touch while the row is
non-terminal. Same policy variable as the dispatcher's (``BLASTBOX_MAX_QUEUED_AGE_S``), so a
fleet that already set it gets the same behaviour wherever the queue lives.

ONE SWEEPER PER HOST (see :func:`sweeper_lock`). ``workers>1`` forks, and each worker ran its
own maintenance loop: N full scans per interval, each holding the store's process lock, measured
at ~150 ms of added worst-case API latency per sweep on a 50k-row table. Every write is
CAS-fenced so it was waste rather than corruption, but it was waste in the request-serving
process. A non-blocking ``flock`` on a sidecar file elects one sweeper per host per tick -- the
same idiom `egress_apply` already uses, and it needs no new store method. RESIDUAL, stated: two
ingress HOSTS still sweep independently. That is bounded by host count rather than worker count,
and every write remains CAS-fenced.

OPT-IN, because a cutoff this side cannot derive. The dispatcher knows its own
``worker_timeout_s``; the control plane does not, and failing a job a healthy node is still
working on is worse than leaving it. So an operator sets the age explicitly, and a fleet whose
nodes still hold database credentials keeps using the dispatcher's own sweep unchanged.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:                       # pragma: no cover - typing only
    from blastbox.host.jobs.base import JobStore

_log = logging.getLogger("blastbox.ingress.node_reclaim")

#: Age past which a RUNNING job is treated as abandoned. Unset/0 = the sweep does not run.
RECLAIM_AFTER_ENV = "BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S"

#: Never sweep more aggressively than this, whatever the operator sets. A cutoff shorter than a
#: long detonation would fail healthy jobs, which is the one outcome worse than leaving an
#: orphan -- a rounding error in a unit file should not terminate live work.
MIN_RECLAIM_AFTER_S = 900.0     # above the dispatcher's own warm cutoff (300 + 60 grace)


def reclaim_after_s(env: "dict[str, str] | None" = None) -> float:
    """The configured cutoff, floored, or 0.0 when the sweep is off."""
    e = os.environ if env is None else env
    raw = (e.get(RECLAIM_AFTER_ENV, "") or "").strip()
    if not raw:
        return 0.0
    try:
        value = float(raw)
    except ValueError:
        _log.warning("%s=%r is not a number; the stale-claim sweep stays OFF. A "
                     "credential-less fleet has no other reclaim path.", RECLAIM_AFTER_ENV, raw)
        return 0.0
    if value <= 0:
        return 0.0
    if value < MIN_RECLAIM_AFTER_S:
        _log.warning("%s=%.0fs is below the %.0fs floor and would risk failing jobs that are "
                     "still running; using the floor.", RECLAIM_AFTER_ENV, value,
                     MIN_RECLAIM_AFTER_S)
        return MIN_RECLAIM_AFTER_S
    return value


def sweeper_lock(job_root: "Path | str"):
    """Elect ONE sweeper per host for this tick, or yield False.

    ``workers>1`` forks the app, so without this every worker ran the full maintenance sweep
    every interval -- N scans, each serialising on the store's lock inside a process that is
    meant to be answering requests. A non-blocking flock on a sidecar file is the cheapest
    correct election and is already this codebase's idiom for exactly this (`egress_apply`
    locks a sidecar rather than the file it rewrites).

    PER TICK, not for the process lifetime: if the holder is slow or wedged, the next tick is
    simply taken by whoever gets the lock, rather than the fleet losing its sweep entirely
    because one worker is stuck. Failure to lock at all (a read-only mount, an exotic
    filesystem) yields True -- N sweeps is wasteful, zero sweeps loses the only reclaim path a
    credential-less fleet has.
    """
    import contextlib
    import fcntl
    import os as _os

    @contextlib.contextmanager
    def _held():
        path = Path(job_root) / ".blastbox-maintenance.lock"
        fd = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = _os.open(path, _os.O_CREAT | _os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False             # another worker on this host has it this tick
                return
            yield True
        except Exception:               # noqa: BLE001 - see below; never lose the sweep
            # BROADER THAN OSError DELIBERATELY. A pathological job_root raises ValueError
            # ("embedded null byte") rather than OSError, which escaped and would have killed
            # the maintenance tick -- found by this module's own test. The contract of this
            # helper is "never cost the fleet its sweep", so anything at all that goes wrong
            # here errs towards sweeping: N sweeps is waste, zero sweeps is the only reclaim
            # path a credential-less fleet has.
            _log.debug("node_reclaim: cannot take the maintenance lock; sweeping anyway",
                       exc_info=True)
            yield True
        finally:
            if fd is not None:
                with contextlib.suppress(OSError):
                    _os.close(fd)

    return _held()


def max_queued_age_s(env: "dict[str, str] | None" = None) -> float:
    """The dispatcher's own policy variable, read here too. 0 = the QUEUED sweep is off."""
    e = os.environ if env is None else env
    try:
        return max(0.0, float((e.get("BLASTBOX_MAX_QUEUED_AGE_S") or "0").strip() or 0))
    except ValueError:
        _log.warning("BLASTBOX_MAX_QUEUED_AGE_S is not a number; the stale-QUEUED sweep is OFF")
        return 0.0


def fail_stale_queued(job_store: "JobStore", *, max_age_s: float,
                      job_root: "Path | str | None" = None,
                      retention_s: float = 0.0,
                      now: float | None = None) -> int:
    """FAIL jobs stuck QUEUED past *max_age_s*, and delete their untrusted input.

    WHY IT HAS TO RUN HERE. A job pinned with ``target_tier`` is claimable by nobody on an
    all-federated fleet, `reclaim_stale_claims` only looks at RUNNING, and retention only at
    terminal states -- so it sits QUEUED forever with its sample on disk. The dispatcher's
    version of this is list()-driven and cannot run on a node.

    CAS ON QUEUED, so a job claimed since the snapshot (now RUNNING) is left entirely alone.

    A DELIBERATELY DEFERRED JOB IS NOT ABANDONED. Anything with ``claimable_after`` in the
    future was put there on purpose -- by a dispatcher's capacity backoff, or by this control
    plane releasing a job a node may not run -- and judging it on ``created_at`` alone let a
    restricted node weaponise this sweep: poll until a governed job it cannot run is deferred
    again and again, and once it aged past the policy THIS function marked it FAILED and deleted
    another tenant's sample. Reviewed and reproduced. Deferred jobs are skipped.

    AND IT WRITES ``expires_at``, which the dispatcher's counterpart computes on exactly this
    transition. Without it `expire_due` skips the row forever (it requires a non-null
    ``expires_at``), so this sweep would trade "a sample sitting QUEUED forever" for "a FAILED
    row and its tree sitting forever" -- with the growth adversary-driven, per the above.
    """
    import time

    from blastbox.host.jobs.base import JobStatus

    if max_age_s <= 0:
        return 0
    stamp = time.time() if now is None else now
    cutoff = stamp - max_age_s
    try:
        queued = job_store.list(status=JobStatus.QUEUED)
    except Exception:                   # noqa: BLE001 - a sweep failure must not kill serving
        _log.warning("node_reclaim: could not list QUEUED jobs", exc_info=True)
        return 0

    failed = 0
    for job in queued:
        if job.created_at > cutoff:
            continue
        if job.claimable_after is not None and job.claimable_after > stamp:
            continue                    # deferred on purpose; see the docstring
        try:
            applied = job_store.update_if_status(
                job.job_id, JobStatus.QUEUED, status=JobStatus.FAILED, finished_at=stamp,
                expires_at=(stamp + retention_s) if retention_s > 0 else None,
                error=(f"stuck QUEUED for more than {max_age_s:.0f}s: no dispatcher claimed "
                       "it (a target_tier with no matching dispatcher, or an engine nobody "
                       "serves)"))
        except Exception:               # noqa: BLE001 - one bad row is not a sweep outage
            _log.warning("node_reclaim: could not fail stale job=%s", job.job_id,
                         exc_info=True)
            continue
        if not applied:
            continue
        failed += 1
        _log.warning("node_reclaim: failed job=%s stuck QUEUED >%.0fs (target_tier=%r)",
                     job.job_id, max_age_s, job.target_tier)
        if job_root is not None and job.filename:
            # The untrusted sample was spooled here at submission and nothing else will remove
            # it now the row is terminal-but-never-run: the scratch reaper needs the tree aged,
            # and retention needs an expires_at this job never got. Best-effort and narrow --
            # the input FILE and its input/ directory, never the job tree, which may hold a
            # partial result. Mirrors `Dispatcher._delete_input`.
            _delete_input(Path(job_root) / job.job_id / "input" / Path(job.filename).name)
    return failed


def _delete_input(input_path: "Path") -> None:
    """Delete an untrusted input file and its input/ directory. Swallows OSError, so a missing
    file does not abort the rest of the sweep."""
    import contextlib

    with contextlib.suppress(OSError):
        input_path.unlink()
    with contextlib.suppress(OSError):
        input_path.parent.rmdir()


def reclaim_stale_claims(job_store: "JobStore", *, after_s: float,
                         retention_s: float = 0.0,
                         now: float | None = None) -> int:
    """Fail every RUNNING job whose owner has plainly gone. Returns how many.

    IT STAMPS ``expires_at``, like both dispatcher siblings do on their own terminal writes.
    Without it `expire_due` skips the row forever (it requires a non-null ``expires_at``), and on
    a credential-less fleet THIS is the normal terminal state for every lost claim -- so the rows
    and, worse, the durable blob objects of jobs that actually ran would outlive the operator's
    retention policy permanently. `blob_store.delete_job` only ever runs from `_expire_job`.

    CAS-FENCED on (RUNNING, the claim_id observed in this pass), so it can never clobber a
    terminal status the owner wrote, and never touches a job that was reclaimed between the read
    and the write. That is the same fence the dispatcher's recovery uses, and it is what makes it
    safe for both to run against one queue.
    """
    import time

    from blastbox.host.jobs.base import JobStatus

    if after_s <= 0:
        return 0
    stamp = time.time() if now is None else now
    cutoff = stamp - after_s
    try:
        running = job_store.list(status=JobStatus.RUNNING)
    except Exception:                   # noqa: BLE001 - a sweep failure must not kill serving
        _log.warning("node_reclaim: could not list RUNNING jobs", exc_info=True)
        return 0

    from blastbox.host.ingress.node_claim import NODE_CLAIM_PREFIX

    failed = 0
    for job in running:
        if not (job.claim_id or "").startswith(NODE_CLAIM_PREFIX):
            # NOT OURS TO JUDGE. Only jobs the control plane handed to a node carry the prefix.
            # A DB-backed dispatcher's claim is recovered by that dispatcher's own sweep, which
            # knows its worker_timeout and, for cold jobs, has no time bound at all by design.
            # Failing those from here terminated healthy runs on a mixed fleet and discarded
            # their results when the owner's DONE write lost its CAS. Reproduced.
            continue
        # started_at, not created_at: a job that waited an hour in the queue has not been
        # running an hour, and failing on queue age would terminate work that just started.
        started = job.started_at
        if started is None or started >= cutoff:
            continue
        try:
            applied = job_store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.FAILED, finished_at=stamp,
                expires_at=(stamp + retention_s) if retention_s > 0 else None,
                error=("abandoned: no progress for more than "
                       f"{after_s:.0f}s, so the claiming node is gone"))
        except Exception:               # noqa: BLE001 - one bad row is not a sweep outage
            _log.warning("node_reclaim: could not fail job=%s", job.job_id, exc_info=True)
            continue
        if applied:
            failed += 1
            _log.warning("node_reclaim: failed abandoned job=%s (claimed, no progress for "
                         ">%.0fs). FAILED rather than requeued: re-queuing would let a second "
                         "worker re-detonate the same untrusted input.", job.job_id, after_s)
    return failed
