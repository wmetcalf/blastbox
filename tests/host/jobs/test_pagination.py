"""Store-level pagination pushdown + count(), uniform across all JobStore backends.

The listing endpoint pages with ``list(..., limit=, offset=, newest_first=True)`` and
reports ``total`` via ``count()`` — so a large jobs table never fully materializes.  These
tests pin that contract for the in-memory, Redis (fakeredis), and SQLite backends together,
including the SQLite ``LIMIT -1 OFFSET n`` sentinel path (bare offset, no limit).
"""

from __future__ import annotations

import fakeredis
import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.redis_store import RedisJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


@pytest.fixture(params=["memory", "redis", "sql"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryJobStore()
    if request.param == "redis":
        return RedisJobStore(fakeredis.FakeRedis(), ttl_seconds=3600)
    return SqlJobStore(f"sqlite:///{tmp_path / 'jobs.db'}")


def _seed(store, n: int) -> list[Job]:
    """Create n QUEUED jobs with strictly increasing created_at; return them oldest-first."""
    jobs = []
    for i in range(n):
        j = Job.new(engine="e", filename=f"f{i}.docx")
        j.created_at = 1000.0 + i  # deterministic ordering, independent of wall clock
        store.create(j)
        jobs.append(j)
    return jobs


def test_update_rejects_unknown_field_all_backends(store):
    # Cross-backend parity: memory/redis/sql must ALL fail closed (ValueError) on an unknown
    # field name, and accept a valid one. Asserts the type only (messages differ by backend),
    # so the three allowlists can't silently drift apart.
    jobs = _seed(store, 1)
    with pytest.raises(ValueError):
        store.update(jobs[0].job_id, not_a_real_field="x")
    updated = store.update(jobs[0].job_id, status=JobStatus.RUNNING)
    assert updated.status == JobStatus.RUNNING


def test_update_if_status_cas_all_backends(store):
    """update_if_status applies ONLY while status matches (a CAS, like claim_next) — across
    memory/redis/sql. Used to fence orphan-recovery against a concurrent terminal write."""
    jobs = _seed(store, 1)
    jid = jobs[0].job_id
    store.update(jid, status=JobStatus.RUNNING)

    # Mismatched expectation -> no write, returns False.
    assert (
        store.update_if_status(jid, JobStatus.QUEUED, status=JobStatus.FAILED) is False
    )
    assert store.get(jid).status == JobStatus.RUNNING  # unchanged

    # Matching expectation -> applies, returns True.
    assert (
        store.update_if_status(
            jid, JobStatus.RUNNING, status=JobStatus.FAILED, error="boom"
        )
        is True
    )
    got = store.get(jid)
    assert got.status == JobStatus.FAILED and got.error == "boom"

    # Now RUNNING no longer matches -> a second CAS can't clobber the terminal state.
    assert (
        store.update_if_status(jid, JobStatus.RUNNING, status=JobStatus.DONE) is False
    )
    assert store.get(jid).status == JobStatus.FAILED

    # Missing job -> False.
    assert (
        store.update_if_status("nope", JobStatus.RUNNING, status=JobStatus.FAILED)
        is False
    )


def test_claim_next_stamps_unique_claim_id(store):
    _seed(store, 2)
    j1 = store.claim_next()
    j2 = store.claim_next()
    assert j1 is not None and j2 is not None
    assert j1.claim_id and j2.claim_id and j1.claim_id != j2.claim_id
    assert store.get(j1.job_id).claim_id == j1.claim_id  # persisted on the row


def test_update_if_status_claim_id_fences_aba(store):
    """The claim_id guard closes the status-only ABA hole: after RUNNING->QUEUED->RUNNING (a new
    claim), a STALE owner keyed on the OLD claim_id can no longer write — only the new owner can."""
    _seed(store, 1)
    claimed = store.claim_next()
    c1 = claimed.claim_id
    assert c1

    # The owner's write keyed on (RUNNING, c1) applies now (still our claim).
    assert (
        store.update_if_status(
            claimed.job_id, JobStatus.RUNNING, expect_claim_id=c1, worker_runtime="warm"
        )
        is True
    )

    # ABA: requeue (clear claim) then reclaim -> a fresh claim c2.
    assert (
        store.update_if_status(
            claimed.job_id,
            JobStatus.RUNNING,
            expect_claim_id=c1,
            status=JobStatus.QUEUED,
            claim_id=None,
        )
        is True
    )
    reclaimed = store.claim_next()
    c2 = reclaimed.claim_id
    assert c2 and c2 != c1

    # The OLD owner (c1) must NOT be able to terminal-write the reclaimed job (ABA closed).
    assert (
        store.update_if_status(
            claimed.job_id, JobStatus.RUNNING, expect_claim_id=c1, status=JobStatus.DONE
        )
        is False
    )
    assert (
        store.get(claimed.job_id).status == JobStatus.RUNNING
    )  # still the new claim's job

    # The CURRENT owner (c2) can.
    assert (
        store.update_if_status(
            claimed.job_id, JobStatus.RUNNING, expect_claim_id=c2, status=JobStatus.DONE
        )
        is True
    )
    assert store.get(claimed.job_id).status == JobStatus.DONE


def test_update_if_status_rejects_unknown_field(store):
    jobs = _seed(store, 1)  # QUEUED
    # Fail-fast on a bad field name UNIFORMLY across backends — regardless of status match,
    # mismatch, or a missing job (an unknown field is a programming error, caught everywhere).
    with pytest.raises(ValueError):  # status MATCH
        store.update_if_status(jobs[0].job_id, JobStatus.QUEUED, not_a_field="x")
    with pytest.raises(ValueError):  # status MISMATCH
        store.update_if_status(jobs[0].job_id, JobStatus.RUNNING, not_a_field="x")
    with pytest.raises(ValueError):  # missing job
        store.update_if_status("nope", JobStatus.RUNNING, not_a_field="x")


def test_count_total_and_by_status(store):
    jobs = _seed(store, 5)
    store.update(jobs[0].job_id, status=JobStatus.DONE)
    store.update(jobs[1].job_id, status=JobStatus.DONE)
    assert store.count() == 5
    assert store.count(status=JobStatus.DONE) == 2
    assert store.count(status=JobStatus.QUEUED) == 3


def test_count_empty(store):
    assert store.count() == 0
    assert store.count(status=JobStatus.QUEUED) == 0


def test_list_newest_first(store):
    jobs = _seed(store, 4)  # created_at 1000..1003
    got = store.list(newest_first=True)
    assert [j.job_id for j in got] == [j.job_id for j in reversed(jobs)]


def test_list_limit_offset_window(store):
    jobs = _seed(store, 5)  # newest-first: 4,3,2,1,0
    page = store.list(newest_first=True, limit=2, offset=1)
    assert [j.job_id for j in page] == [jobs[3].job_id, jobs[2].job_id]


def test_list_offset_without_limit(store):
    # Exercises the SQLite ``LIMIT -1 OFFSET n`` sentinel; plain slice for memory/redis.
    jobs = _seed(store, 4)  # newest-first: 3,2,1,0
    got = store.list(newest_first=True, offset=2)
    assert [j.job_id for j in got] == [jobs[1].job_id, jobs[0].job_id]


def test_list_offset_beyond_end_is_empty(store):
    _seed(store, 3)
    assert store.list(newest_first=True, limit=10, offset=100) == []


def test_list_limit_none_returns_all_unordered(store):
    _seed(store, 7)
    assert (
        len(store.list()) == 7
    )  # callers that iterate everything (dispatch/retention)


def test_list_status_filter_with_window(store):
    jobs = _seed(store, 6)
    for j in jobs[:4]:
        store.update(j.job_id, status=JobStatus.DONE)
    done = store.list(status=JobStatus.DONE, newest_first=True, limit=2, offset=0)
    assert len(done) == 2
    assert all(j.status == JobStatus.DONE for j in done)
    assert store.count(status=JobStatus.DONE) == 4
