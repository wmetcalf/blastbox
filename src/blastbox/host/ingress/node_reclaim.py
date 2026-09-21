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

OPT-IN, because a cutoff this side cannot derive. The dispatcher knows its own
``worker_timeout_s``; the control plane does not, and failing a job a healthy node is still
working on is worse than leaving it. So an operator sets the age explicitly, and a fleet whose
nodes still hold database credentials keeps using the dispatcher's own sweep unchanged.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:                       # pragma: no cover - typing only
    from blastbox.host.jobs.base import JobStore

_log = logging.getLogger("blastbox.ingress.node_reclaim")

#: Age past which a RUNNING job is treated as abandoned. Unset/0 = the sweep does not run.
RECLAIM_AFTER_ENV = "BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S"

#: Never sweep more aggressively than this, whatever the operator sets. A cutoff shorter than a
#: long detonation would fail healthy jobs, which is the one outcome worse than leaving an
#: orphan -- a rounding error in a unit file should not terminate live work.
MIN_RECLAIM_AFTER_S = 300.0


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


def reclaim_stale_claims(job_store: "JobStore", *, after_s: float,
                         now: float | None = None) -> int:
    """Fail every RUNNING job whose owner has plainly gone. Returns how many.

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

    failed = 0
    for job in running:
        # started_at, not created_at: a job that waited an hour in the queue has not been
        # running an hour, and failing on queue age would terminate work that just started.
        started = job.started_at
        if started is None or started >= cutoff:
            continue
        try:
            applied = job_store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.FAILED, finished_at=stamp,
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
