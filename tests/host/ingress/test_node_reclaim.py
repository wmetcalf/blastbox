"""The reclaim backstop must actually exist on a credential-less fleet (#178).

Three independent reviewers found the same thing: the design cited "reclaim on timeout" as the
bound on every lost-claim case, that path is `Dispatcher.requeue_orphaned_jobs`, its first
statement enumerates the queue, and a node's store refuses to enumerate. So on the one topology
where the claim routes are prevention rather than advice, the backstop did not exist — and the
only symptom was a swallowed traceback per maintenance tick.
"""
from __future__ import annotations

import time

import pytest

from blastbox.host.ingress.node_reclaim import (
    MIN_RECLAIM_AFTER_S,
    RECLAIM_AFTER_ENV,
    reclaim_after_s,
    reclaim_stale_claims,
)
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


@pytest.fixture
def store():
    return InMemoryJobStore()


def running(store, job_id, *, started_at, claim_id="c1"):
    store.create(Job(job_id=job_id, engine="clamav", filename="s.bin",
                     status=JobStatus.RUNNING, created_at=started_at,
                     started_at=started_at, claim_id=claim_id))
    return job_id


def test_an_abandoned_job_is_failed(store):
    running(store, "gone", started_at=time.time() - 10_000)
    assert reclaim_stale_claims(store, after_s=600.0) == 1
    job = store.get("gone")
    assert job.status is JobStatus.FAILED
    assert "abandoned" in (job.error or "")


def test_it_fails_rather_than_requeues(store):
    """Not a detail. The dispatcher's own recovery records why: a requeue "would let a second
    worker re-detonate the same untrusted input, and orphaned sandboxes don't die with a crashed
    dispatcher." Terminal is the safe end for an abandoned detonation."""
    running(store, "gone", started_at=time.time() - 10_000)
    reclaim_stale_claims(store, after_s=600.0)
    assert store.get("gone").status is not JobStatus.QUEUED


def test_a_live_job_is_left_alone(store):
    running(store, "live", started_at=time.time() - 5)
    assert reclaim_stale_claims(store, after_s=600.0) == 0
    assert store.get("live").status is JobStatus.RUNNING


def test_queue_age_is_not_run_age(store):
    """started_at, not created_at: a job that waited an hour in the queue has not been RUNNING
    an hour, and failing on queue age would terminate work that had just begun."""
    now = time.time()
    store.create(Job(job_id="waited", engine="clamav", filename="s.bin",
                     status=JobStatus.RUNNING, created_at=now - 10_000,
                     started_at=now - 5, claim_id="c1"))
    assert reclaim_stale_claims(store, after_s=600.0) == 0
    assert store.get("waited").status is JobStatus.RUNNING


def test_a_job_that_terminalised_under_us_is_not_clobbered(store):
    """CAS-fenced on (RUNNING, claim_id). The owner may write DONE between our read and our
    write, and a sweep that overwrote it would turn a finished job into a failed one."""
    running(store, "raced", started_at=time.time() - 10_000)
    store.update("raced", status=JobStatus.DONE)
    assert reclaim_stale_claims(store, after_s=600.0) == 0
    assert store.get("raced").status is JobStatus.DONE


def test_a_job_reclaimed_BETWEEN_the_read_and_the_write_is_not_clobbered(store):
    """The real ABA race, and it needs the interleaving forced.

    My first version of this test set claim_id without refreshing started_at and then ran the
    sweep -- a state `claim_next` never produces (it stamps started_at on every claim), so the
    sweep read the NEW claim id, fenced on it, and correctly failed a job the test had built
    wrong. The genuine hazard is a peer re-claiming between this sweep's `list` and its write, so
    that is what is simulated: the listed snapshot carries the old claim, the row carries the new
    one, and the CAS must refuse."""
    now = time.time()
    running(store, "aba", started_at=now - 10_000, claim_id="old")
    stale_snapshot = store.list(status=JobStatus.RUNNING)

    class ReclaimedUnderUs(InMemoryJobStore):
        def list(self, *a, **k):
            # Hand back the pre-reclaim snapshot, as a real sweep would already be holding.
            return stale_snapshot

    racing = ReclaimedUnderUs()
    racing.create(Job(job_id="aba", engine="clamav", filename="s.bin",
                      status=JobStatus.RUNNING, created_at=now - 10_000,
                      started_at=now - 1, claim_id="new-owner"))
    assert reclaim_stale_claims(racing, after_s=600.0) == 0, (
        "the sweep failed a job a peer had already re-claimed")
    fresh = racing.get("aba")
    assert fresh.status is JobStatus.RUNNING and fresh.claim_id == "new-owner"


def test_a_re_claimed_job_gets_a_fresh_run_clock(store):
    """Why the case above is rare in practice: `claim_next` stamps started_at, so a job taken
    over by a peer is no longer stale and the sweep skips it on age alone."""
    now = time.time()
    running(store, "taken", started_at=now - 10_000, claim_id="old")
    store.update("taken", status=JobStatus.QUEUED, claim_id=None, started_at=None)
    again = store.claim_next()
    assert again is not None and again.job_id == "taken"
    assert again.started_at is not None and again.started_at > now - 600
    assert reclaim_stale_claims(store, after_s=600.0) == 0


def test_the_sweep_is_off_unless_configured(store, monkeypatch):
    monkeypatch.delenv(RECLAIM_AFTER_ENV, raising=False)
    assert reclaim_after_s() == 0.0
    running(store, "gone", started_at=time.time() - 10_000)
    assert reclaim_stale_claims(store, after_s=reclaim_after_s()) == 0
    assert store.get("gone").status is JobStatus.RUNNING


def test_a_dangerously_short_cutoff_is_floored(monkeypatch):
    """A cutoff shorter than a long detonation would fail healthy jobs, which is worse than
    leaving an orphan. A rounding error in a unit file must not terminate live work."""
    monkeypatch.setenv(RECLAIM_AFTER_ENV, "5")
    assert reclaim_after_s() == MIN_RECLAIM_AFTER_S


def test_a_nonsense_cutoff_leaves_the_sweep_off_loudly(monkeypatch, caplog):
    monkeypatch.setenv(RECLAIM_AFTER_ENV, "soon")
    with caplog.at_level("WARNING"):
        assert reclaim_after_s() == 0.0
    assert any("not a number" in r.message for r in caplog.records), caplog.text


def test_a_store_that_cannot_enumerate_does_not_kill_the_sweep(store):
    """The control plane holds a real store, but be certain a raise is contained: this runs on
    the serving process's maintenance thread."""
    class Refuses(InMemoryJobStore):
        def list(self, *a, **k):
            raise NotImplementedError("nope")

    assert reclaim_stale_claims(Refuses(), after_s=600.0) == 0


def test_it_is_wired_into_the_ingress_maintenance_thread():
    """A sweep nothing calls is the defect this replaces. `fix-79` recorded the same shape."""
    import inspect

    from blastbox.host.ingress import app

    src = inspect.getsource(app)
    assert "reclaim_stale_claims" in src, "the sweep is not called from the ingress app"
    assert "reclaim_after_s" in src, "the sweep's gate is not read from the ingress app"
