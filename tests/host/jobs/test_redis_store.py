"""Tests for RedisJobStore via fakeredis."""

from __future__ import annotations

import json
import threading
import time

import fakeredis

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.redis_store import RedisJobStore, _PREFIX


def _make_store(ttl: int = 3600) -> RedisJobStore:
    r = fakeredis.FakeRedis()
    return RedisJobStore(r, ttl_seconds=ttl)


def _make_job(engine: str = "test", filename: str = "file.docx") -> Job:
    return Job.new(engine=engine, filename=filename)


# ---------------------------------------------------------------------------
# Basic CRUD via JSON
# ---------------------------------------------------------------------------


def test_create_and_get():
    store = _make_store()
    job = _make_job()
    store.create(job)
    fetched = store.get(job.job_id)
    assert fetched is not None
    assert fetched.job_id == job.job_id
    assert fetched.engine == job.engine
    assert fetched.filename == job.filename


def test_get_missing_returns_none():
    store = _make_store()
    assert store.get("missing") is None


def test_delete():
    store = _make_store()
    job = _make_job()
    store.create(job)
    store.delete(job.job_id)
    assert store.get(job.job_id) is None


def test_update_field():
    store = _make_store()
    job = _make_job()
    store.create(job)
    store.update(job.job_id, status=JobStatus.RUNNING)
    updated = store.get(job.job_id)
    assert updated.status == JobStatus.RUNNING


def test_list_all():
    store = _make_store()
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    store.create(j1)
    store.create(j2)
    all_jobs = store.list()
    ids = {j.job_id for j in all_jobs}
    assert j1.job_id in ids and j2.job_id in ids


def test_list_by_status():
    store = _make_store()
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    store.create(j1)
    store.create(j2)
    store.update(j2.job_id, status=JobStatus.DONE)
    queued = store.list(status=JobStatus.QUEUED)
    assert len(queued) == 1
    assert queued[0].job_id == j1.job_id


# ---------------------------------------------------------------------------
# JSON serialization (not pickle)
# ---------------------------------------------------------------------------


def test_stored_as_json():
    """Data must be stored as JSON text, not pickle."""
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=3600)
    job = _make_job()
    store.create(job)
    raw = r.get(_PREFIX + job.job_id)
    assert raw is not None
    # Must be valid JSON
    parsed = json.loads(raw)
    assert parsed["job_id"] == job.job_id
    # Must NOT be pickle (pickle starts with specific magic bytes 0x80...)
    assert not raw.startswith(b"\x80")


def test_params_stored_in_json():
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=3600)
    job = _make_job()
    job.params = {"mode": "fast", "lang": "en"}
    store.create(job)
    raw = r.get(_PREFIX + job.job_id)
    parsed = json.loads(raw)
    assert parsed["params"] == {"mode": "fast", "lang": "en"}


# ---------------------------------------------------------------------------
# TTL set on every set
# ---------------------------------------------------------------------------


def test_ttl_set_on_create():
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=300)
    job = _make_job()
    store.create(job)
    ttl = r.ttl(_PREFIX + job.job_id)
    assert 0 < ttl <= 300


def test_ttl_set_on_update():
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=300)
    job = _make_job()
    store.create(job)
    store.update(job.job_id, status=JobStatus.RUNNING)
    ttl = r.ttl(_PREFIX + job.job_id)
    assert 0 < ttl <= 300


def test_no_ttl_when_zero():
    """ttl_seconds=0 means no expiry."""
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=0)
    job = _make_job()
    store.create(job)
    ttl = r.ttl(_PREFIX + job.job_id)
    # -1 means no expiry in Redis
    assert ttl == -1


# ---------------------------------------------------------------------------
# list uses scan_iter (not KEYS) — behaviorally verified via prefix match
# ---------------------------------------------------------------------------


def test_list_uses_prefix_scan():
    """list() must only return jobs from this store's prefix."""
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=3600)
    job = _make_job()
    store.create(job)
    # Insert a key with a different prefix directly
    r.set("other:prefix:xyz", json.dumps({"job_id": "xyz", "status": "queued"}))
    # list() should only see the store's job
    all_jobs = store.list()
    assert len(all_jobs) == 1
    assert all_jobs[0].job_id == job.job_id


# ---------------------------------------------------------------------------
# claim_next atomic under concurrent claimers
# ---------------------------------------------------------------------------


def test_claim_next_returns_oldest_queued():
    store = _make_store()
    j1 = Job.new(engine="e", filename="first.docx")
    time.sleep(0.01)
    j2 = Job.new(engine="e", filename="second.docx")
    store.create(j1)
    store.create(j2)
    claimed = store.claim_next()
    assert claimed is not None
    assert claimed.job_id == j1.job_id
    assert claimed.status == JobStatus.RUNNING


def test_claim_next_empty_returns_none():
    store = _make_store()
    assert store.claim_next() is None


def test_claim_next_no_queued_returns_none():
    store = _make_store()
    job = _make_job()
    store.create(job)
    store.update(job.job_id, status=JobStatus.DONE)
    assert store.claim_next() is None


def test_concurrent_claim_no_double_claim():
    """Two threads racing claim_next on a single job must not both claim it."""
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=3600)
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


def test_concurrent_claim_many_jobs():
    """N threads racing on N jobs — each job claimed exactly once."""
    n = 8
    r = fakeredis.FakeRedis()
    store = RedisJobStore(r, ttl_seconds=3600)
    jobs = [_make_job(filename=f"f{i}.docx") for i in range(n)]
    for j in jobs:
        store.create(j)

    claimed_ids: list[str] = []
    lock = threading.Lock()

    def claim():
        j = store.claim_next()
        if j is not None:
            with lock:
                claimed_ids.append(j.job_id)

    threads = [threading.Thread(target=claim) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(claimed_ids) == len(set(claimed_ids)), "no duplicate claims"
    assert len(claimed_ids) == n, "all jobs claimed"


def test_claim_filters_by_engine():
    # claim_next(engine=...) must never return a foreign-engine job (initial-scan predicate).
    store = _make_store()
    store.create(_make_job(engine="other", filename="foreign.docx"))
    assert store.claim_next(engine="mine") is None
    mine = _make_job(engine="mine", filename="ours.docx")
    store.create(mine)
    claimed = store.claim_next(engine="mine")
    assert claimed is not None and claimed.job_id == mine.job_id


def test_claim_rechecks_engine_inside_watch(monkeypatch):
    # If a candidate's engine is reassigned AFTER the scan selects it but BEFORE the watched re-read,
    # the watched section must re-validate the engine predicate and NOT claim the now-foreign job.
    import blastbox.host.jobs.redis_store as rs

    store = _make_store()
    job = _make_job(engine="mine", filename="ours.docx")
    store.create(job)

    real_decode = rs._decode_job
    calls = {"n": 0}

    def flaky_decode(raw):
        j = real_decode(raw)
        calls["n"] += 1
        if (
            j is not None and calls["n"] >= 2
        ):  # first decode (scan) matches; later (watch re-read) drifts
            j.engine = "other"
        return j

    monkeypatch.setattr(rs, "_decode_job", flaky_decode)
    # scan selects it (engine "mine"), watched re-read sees "other" → skip; rescan now also sees
    # "other" → no candidate → None. Without the watched engine re-check this would claim a foreign job.
    assert store.claim_next(engine="mine") is None
    assert store.get(job.job_id).status is JobStatus.QUEUED  # never claimed
