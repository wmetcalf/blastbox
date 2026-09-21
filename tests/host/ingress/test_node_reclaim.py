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


def running(store, job_id, *, started_at, claim_id="node:c1"):
    # node: prefix -- the sweep only reclaims jobs the control plane handed to a node, never a
    # DB-backed dispatcher's own claims (which its own sweep, aware of its worker_timeout, owns).
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
    running(store, "taken", started_at=now - 10_000, claim_id="node:old")
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


def test_job_retention_also_runs_on_the_control_plane():
    """`expire_due` finds its candidates by ENUMERATING, which a credential-less node's store
    refuses by design — so BLASTBOX_JOB_RETENTION_SECONDS was quietly a no-op on such a fleet and
    detonation output accumulated under a policy nobody enforced. It belongs where the queue is,
    for the same reason the stale-claim sweep does."""
    import inspect

    from blastbox.host.ingress import app

    src = inspect.getsource(app)
    assert "expire_due" in src, "the control plane runs no job retention"
    assert "JobRetentionSweeper" in src


def test_a_dispatchers_own_claim_is_never_touched(store):
    """The mixed-fleet safety property. A claim WITHOUT the node: prefix belongs to a DB-backed
    dispatcher, whose own sweep knows its worker_timeout -- and whose cold jobs have no time
    bound at all by design. Failing those from here terminated healthy runs and discarded their
    results when the owner's DONE write lost its CAS. Reproduced by review."""
    store.create(Job(job_id="dispatcher-job", engine="clamav", filename="s.bin",
                     status=JobStatus.RUNNING, created_at=time.time() - 10_000,
                     started_at=time.time() - 10_000, claim_id="plain-dispatcher-claim"))
    assert reclaim_stale_claims(store, after_s=900.0) == 0
    assert store.get("dispatcher-job").status is JobStatus.RUNNING


class TestTheQueuedHalf:
    """Work nobody can claim. On an all-federated fleet a target_tier-pinned job is claimable by
    no node (the node path passes no tier, so `claim_next` skips pinned rows by design),
    `reclaim_stale_claims` only looks at RUNNING, and retention only at terminal states — so it
    sat QUEUED forever with its untrusted sample on the ingress's own disk."""

    def test_a_job_nobody_can_claim_is_eventually_failed(self, store):
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        store.create(Job(job_id="pinned", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000,
                         target_tier="firecracker"))
        assert fail_stale_queued(store, max_age_s=3600.0) == 1
        job = store.get("pinned")
        assert job.status is JobStatus.FAILED
        assert "QUEUED" in (job.error or "")

    def test_a_fresh_job_is_left_alone(self, store):
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        store.create(Job(job_id="new", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time()))
        assert fail_stale_queued(store, max_age_s=3600.0) == 0
        assert store.get("new").status is JobStatus.QUEUED

    def test_a_job_claimed_since_the_snapshot_is_not_failed(self, store):
        """CAS on QUEUED. A job that went RUNNING between the list() and the write belongs to
        whoever claimed it."""
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        now = time.time()
        store.create(Job(job_id="taken", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=now - 10_000))
        snapshot = store.list(status=JobStatus.QUEUED)

        class Stale(InMemoryJobStore):
            def list(self, *a, **k):
                return snapshot

        racing = Stale()
        racing.create(Job(job_id="taken", engine="clamav", filename="s.bin",
                          status=JobStatus.RUNNING, created_at=now - 10_000,
                          started_at=now, claim_id="node:someone"))
        assert fail_stale_queued(racing, max_age_s=3600.0) == 0
        assert racing.get("taken").status is JobStatus.RUNNING

    def test_the_untrusted_input_is_deleted(self, store, tmp_path):
        """Nothing else will: the scratch reaper needs the tree aged, and retention needs an
        expires_at this job never got."""
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        root = tmp_path / "jobs"
        sample = root / "pinned" / "input" / "s.bin"
        sample.parent.mkdir(parents=True)
        sample.write_text("untrusted")
        store.create(Job(job_id="pinned", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000))
        assert fail_stale_queued(store, max_age_s=3600.0, job_root=root) == 1
        assert not sample.exists()
        assert root.exists(), "the sweep removed more than the input"

    def test_it_is_off_unless_the_policy_is_set(self, store, monkeypatch):
        from blastbox.host.ingress.node_reclaim import fail_stale_queued, max_queued_age_s

        monkeypatch.delenv("BLASTBOX_MAX_QUEUED_AGE_S", raising=False)
        assert max_queued_age_s() == 0.0
        store.create(Job(job_id="old", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000))
        assert fail_stale_queued(store, max_age_s=max_queued_age_s()) == 0
        assert store.get("old").status is JobStatus.QUEUED


class TestOneSweeperPerHost:
    """workers>1 forks, and every worker ran the whole sweep: N full scans per interval, each
    holding the store's lock inside a process meant to be answering requests."""

    def test_only_one_holder_at_a_time(self, tmp_path):
        from blastbox.host.ingress.node_reclaim import sweeper_lock

        with sweeper_lock(tmp_path) as first:
            assert first is True
            with sweeper_lock(tmp_path) as second:
                assert second is False, "two workers swept the same tick"

    def test_the_lock_is_released_for_the_next_tick(self, tmp_path):
        from blastbox.host.ingress.node_reclaim import sweeper_lock

        with sweeper_lock(tmp_path) as a:
            assert a is True
        with sweeper_lock(tmp_path) as b:
            assert b is True, "a wedged holder would cost the fleet its sweep entirely"

    def test_an_unlockable_root_still_sweeps(self, tmp_path):
        """N sweeps is waste; ZERO sweeps loses the only reclaim path a credential-less fleet
        has. So a filesystem that cannot lock errs towards sweeping."""
        from blastbox.host.ingress.node_reclaim import sweeper_lock

        with sweeper_lock(tmp_path / "nonexistent" / "\0bad") as ok:
            assert ok is True
