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
    assert len(store.list()) == 7  # callers that iterate everything (dispatch/retention)


def test_list_status_filter_with_window(store):
    jobs = _seed(store, 6)
    for j in jobs[:4]:
        store.update(j.job_id, status=JobStatus.DONE)
    done = store.list(status=JobStatus.DONE, newest_first=True, limit=2, offset=0)
    assert len(done) == 2
    assert all(j.status == JobStatus.DONE for j in done)
    assert store.count(status=JobStatus.DONE) == 4
