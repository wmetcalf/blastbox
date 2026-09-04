"""Tests for InMemoryJobStore."""

from __future__ import annotations

import threading
import time

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


def _make_job(engine: str = "test", filename: str = "file.docx") -> Job:
    return Job.new(engine=engine, filename=filename)


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------


def test_create_and_get():
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    fetched = store.get(job.job_id)
    assert fetched is not None
    assert fetched.job_id == job.job_id


def test_get_missing_returns_none():
    store = InMemoryJobStore()
    assert store.get("nonexistent") is None


def test_update_field():
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    store.update(job.job_id, status=JobStatus.RUNNING)
    updated = store.get(job.job_id)
    assert updated is not None
    assert updated.status == JobStatus.RUNNING


def test_update_missing_raises():
    store = InMemoryJobStore()
    with pytest.raises(KeyError):
        store.update("bad-id", status=JobStatus.RUNNING)


def test_delete_removes_job():
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    store.delete(job.job_id)
    assert store.get(job.job_id) is None


def test_delete_missing_is_noop():
    store = InMemoryJobStore()
    store.delete("nonexistent")  # no error


def test_list_all():
    store = InMemoryJobStore()
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    store.create(j1)
    store.create(j2)
    all_jobs = store.list()
    ids = {j.job_id for j in all_jobs}
    assert j1.job_id in ids
    assert j2.job_id in ids


def test_update_rejects_unknown_field():
    # Parity with SQL (_COLUMNS) and Redis (_JOB_FIELDS): an unknown/typo'd field name must
    # fail closed, not silently setattr a junk attribute that prod stores would reject.
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    with pytest.raises(ValueError):
        store.update(job.job_id, malicious_col="bad")
    with pytest.raises(ValueError):
        store.update(job.job_id, **{"status; DROP TABLE jobs": "x"})
    # A valid field still succeeds.
    updated = store.update(job.job_id, status=JobStatus.RUNNING)
    assert updated.status == JobStatus.RUNNING


def test_list_by_status():
    store = InMemoryJobStore()
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    store.create(j1)
    store.create(j2)
    store.update(j2.job_id, status=JobStatus.DONE)
    queued = store.list(status=JobStatus.QUEUED)
    assert len(queued) == 1
    assert queued[0].job_id == j1.job_id


# ---------------------------------------------------------------------------
# claim_next — oldest QUEUED flips to RUNNING
# ---------------------------------------------------------------------------


def test_claim_next_returns_oldest_queued():
    store = InMemoryJobStore()
    j1 = Job.new(engine="e", filename="first.docx")
    time.sleep(0.01)
    j2 = Job.new(engine="e", filename="second.docx")
    store.create(j2)
    store.create(j1)
    claimed = store.claim_next()
    assert claimed is not None
    assert claimed.job_id == j1.job_id
    assert claimed.status == JobStatus.RUNNING
    assert claimed.started_at is not None


def test_claim_next_empty_returns_none():
    store = InMemoryJobStore()
    assert store.claim_next() is None


def test_claim_next_no_queued_returns_none():
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    store.update(job.job_id, status=JobStatus.DONE)
    assert store.claim_next() is None


def test_claim_next_flips_status_in_store():
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    claimed = store.claim_next()
    assert claimed is not None
    assert store.get(job.job_id).status == JobStatus.RUNNING


# ---------------------------------------------------------------------------
# Concurrent claim_next — no double-claim
# ---------------------------------------------------------------------------


def test_concurrent_claims_no_double_claim():
    """Two threads racing claim_next on a single queued job must not both claim it."""
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)

    results = []
    barrier = threading.Barrier(2)

    def claim():
        barrier.wait()
        results.append(store.claim_next())

    t1 = threading.Thread(target=claim)
    t2 = threading.Thread(target=claim)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    non_none = [r for r in results if r is not None]
    assert len(non_none) == 1, "exactly one thread should claim the job"


def test_concurrent_claims_many_jobs():
    """N threads racing on N jobs — each job claimed exactly once."""
    n = 10
    store = InMemoryJobStore()
    jobs = [_make_job() for _ in range(n)]
    for j in jobs:
        store.create(j)

    claimed_ids: list[str] = []
    lock = threading.Lock()

    def claim():
        job = store.claim_next()
        if job is not None:
            with lock:
                claimed_ids.append(job.job_id)

    threads = [threading.Thread(target=claim) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(claimed_ids) == len(set(claimed_ids)), "no duplicate claims"
    assert len(claimed_ids) == n, "all jobs claimed"
