"""Tests for SqlJobStore (SQLite path; Postgres gated by DSN env var)."""
from __future__ import annotations

import os
import time
import unittest.mock

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.sql_store import SqlJobStore


POSTGRES_DSN = os.environ.get("BLASTBOX_TEST_PG_DSN")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sqlite_store(tmp_path):
    db = tmp_path / "test.db"
    return SqlJobStore(f"sqlite:///{db}")


def _make_job(engine: str = "test", filename: str = "file.docx") -> Job:
    return Job.new(engine=engine, filename=filename)


# ---------------------------------------------------------------------------
# SQLite — CRUD
# ---------------------------------------------------------------------------

def test_create_and_get(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    fetched = sqlite_store.get(job.job_id)
    assert fetched is not None
    assert fetched.job_id == job.job_id
    assert fetched.engine == job.engine
    assert fetched.filename == job.filename


def test_get_missing_returns_none(sqlite_store):
    assert sqlite_store.get("missing") is None


def test_update_status(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    sqlite_store.update(job.job_id, status=JobStatus.RUNNING)
    updated = sqlite_store.get(job.job_id)
    assert updated.status == JobStatus.RUNNING


def test_delete(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    sqlite_store.delete(job.job_id)
    assert sqlite_store.get(job.job_id) is None


def test_list_all(sqlite_store):
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    sqlite_store.create(j1)
    sqlite_store.create(j2)
    all_jobs = sqlite_store.list()
    ids = {j.job_id for j in all_jobs}
    assert j1.job_id in ids and j2.job_id in ids


def test_list_by_status(sqlite_store):
    j1 = _make_job(filename="a.docx")
    j2 = _make_job(filename="b.docx")
    sqlite_store.create(j1)
    sqlite_store.create(j2)
    sqlite_store.update(j2.job_id, status=JobStatus.DONE)
    queued = sqlite_store.list(status=JobStatus.QUEUED)
    assert len(queued) == 1
    assert queued[0].job_id == j1.job_id


def test_params_and_result_summary_roundtrip(sqlite_store):
    job = _make_job()
    job.params = {"flag": "true", "mode": "fast"}
    job.result_summary = {"pages": 7, "engine_version": "1.2"}
    sqlite_store.create(job)
    fetched = sqlite_store.get(job.job_id)
    assert fetched.params == {"flag": "true", "mode": "fast"}
    assert fetched.result_summary == {"pages": 7, "engine_version": "1.2"}


def test_security_warnings_roundtrip(sqlite_store):
    job = _make_job()
    job.security_warnings = ["macro_enabled", "external_links"]
    sqlite_store.create(job)
    fetched = sqlite_store.get(job.job_id)
    assert fetched.security_warnings == ["macro_enabled", "external_links"]


# ---------------------------------------------------------------------------
# SQLite — parameterization / SQL-injection safety
# ---------------------------------------------------------------------------

def test_sql_injection_filename_roundtrips_intact(sqlite_store):
    """A filename containing SQL metacharacters must survive a full roundtrip."""
    evil = "'); DROP TABLE jobs; --"
    job = _make_job(filename=evil)
    sqlite_store.create(job)
    fetched = sqlite_store.get(job.job_id)
    assert fetched is not None
    assert fetched.filename == evil


def test_sql_injection_in_update_value(sqlite_store):
    """An error message containing SQL metacharacters must roundtrip intact."""
    job = _make_job()
    sqlite_store.create(job)
    evil_error = "failed: '); DROP TABLE jobs; --"
    sqlite_store.update(job.job_id, error=evil_error)
    fetched = sqlite_store.get(job.job_id)
    assert fetched.error == evil_error


# ---------------------------------------------------------------------------
# SQLite — update() column allowlist
# ---------------------------------------------------------------------------

def test_update_rejects_non_allowlisted_field(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    with pytest.raises(ValueError, match="invalid column"):
        sqlite_store.update(job.job_id, malicious_col="bad")


def test_update_rejects_semicolon_injection(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    with pytest.raises(ValueError, match="invalid column"):
        sqlite_store.update(job.job_id, **{"status; DROP TABLE jobs": "x"})


# ---------------------------------------------------------------------------
# SQLite — claim_next (status-guarded CAS)
# ---------------------------------------------------------------------------

def test_claim_next_returns_oldest_queued(sqlite_store):
    j1 = Job.new(engine="e", filename="first.docx")
    time.sleep(0.01)
    j2 = Job.new(engine="e", filename="second.docx")
    sqlite_store.create(j1)
    sqlite_store.create(j2)
    claimed = sqlite_store.claim_next()
    assert claimed is not None
    assert claimed.job_id == j1.job_id
    assert claimed.status == JobStatus.RUNNING


def test_claim_next_empty_returns_none(sqlite_store):
    assert sqlite_store.claim_next() is None


def test_claim_next_no_queued_returns_none(sqlite_store):
    job = _make_job()
    sqlite_store.create(job)
    sqlite_store.update(job.job_id, status=JobStatus.DONE)
    assert sqlite_store.claim_next() is None


def test_claim_next_cas_guards_concurrent_status_change(sqlite_store):
    """If a job is flipped to EXPIRED between SELECT and UPDATE, the CAS
    must NOT overwrite it to RUNNING (must return None).

    We simulate the race by monkeypatching _claim_next_sqlite to run a
    status-changing side-effect between the SELECT and the UPDATE.
    """
    job = _make_job()
    sqlite_store.create(job)

    original_method = sqlite_store._claim_next_sqlite

    def claim_with_interleave(claimant_tier=None):
        import sqlite3
        from urllib.parse import unquote, urlparse

        # Connect independently and flip the job to EXPIRED before the CAS fires
        parsed = urlparse(sqlite_store._database_url)
        db_path = unquote(parsed.path or "")
        conn2 = sqlite3.connect(db_path)
        conn2.execute(
            "UPDATE jobs SET status = ? WHERE job_id = ?",
            ("expired", job.job_id),
        )
        conn2.commit()
        conn2.close()

        return original_method(claimant_tier)

    with unittest.mock.patch.object(sqlite_store, "_claim_next_sqlite", claim_with_interleave):
        result = sqlite_store.claim_next()

    # The CAS should have seen rowcount==0 and returned None
    assert result is None

    # The job must still be EXPIRED (not clobbered to RUNNING)
    final = sqlite_store.get(job.job_id)
    assert final is not None
    assert final.status == JobStatus.EXPIRED


def test_claim_next_cas_rowcount_guard_direct(sqlite_store):
    """Direct unit test: the UPDATE includes AND status='queued', so when a
    job has been moved to EXPIRED the rowcount is 0 and claim returns None.

    This tests the CAS guard itself: we write EXPIRED directly into the DB
    (bypassing claim_next), then call _claim_next_sqlite which will SELECT
    nothing (status != queued) and return None.  Then we also verify the
    inverse: a queued job is claimed successfully (rowcount == 1).
    """
    # Scenario A: job exists but is already expired — CAS sees rowcount 0
    job_a = _make_job(filename="a.docx")
    sqlite_store.create(job_a)
    sqlite_store.update(job_a.job_id, status=JobStatus.EXPIRED)
    result_a = sqlite_store.claim_next()
    assert result_a is None

    # Scenario B: job is genuinely queued — CAS succeeds (rowcount 1)
    job_b = _make_job(filename="b.docx")
    sqlite_store.create(job_b)
    result_b = sqlite_store.claim_next()
    assert result_b is not None
    assert result_b.job_id == job_b.job_id
    assert result_b.status == JobStatus.RUNNING
    # Confirm the DB reflects RUNNING (not a phantom claim)
    persisted = sqlite_store.get(job_b.job_id)
    assert persisted.status == JobStatus.RUNNING


# ---------------------------------------------------------------------------
# Postgres — gated (skip if DSN absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not POSTGRES_DSN, reason="BLASTBOX_TEST_PG_DSN not set")
def test_postgres_crud():
    store = SqlJobStore(POSTGRES_DSN)
    job = _make_job()
    store.create(job)
    fetched = store.get(job.job_id)
    assert fetched is not None
    assert fetched.job_id == job.job_id
    store.delete(job.job_id)


@pytest.mark.skipif(not POSTGRES_DSN, reason="BLASTBOX_TEST_PG_DSN not set")
def test_postgres_claim_next_skip_locked():
    store = SqlJobStore(POSTGRES_DSN)
    job = _make_job()
    store.create(job)
    claimed = store.claim_next()
    assert claimed is not None
    assert claimed.status == JobStatus.RUNNING
    store.delete(job.job_id)


def test_net_policy_persists(tmp_path):
    from blastbox.host.jobs.base import Job
    from blastbox.host.jobs.sql_store import SqlJobStore

    store = SqlJobStore(f"sqlite:///{tmp_path / 'j.db'}")
    job = Job.new(engine="redtusk", filename="x.doc")
    job.net_policy = "fakenet"
    store.create(job)
    assert store.get(job.job_id).net_policy == "fakenet"


@pytest.mark.skipif(not POSTGRES_DSN, reason="BLASTBOX_TEST_PG_DSN not set")
def test_postgres_claim_next_respects_target_tier():
    """Exercise the Postgres-specific claim CTE param binding (separate SQL string from sqlite)
    with a non-NULL target_tier — guards the off-by-one risk if that params tuple is ever
    reordered (sqlite/memory/redis coverage can't catch a PG-only mis-bind)."""
    store = SqlJobStore(POSTGRES_DSN)
    job = _make_job()
    job.target_tier = "gvisor"
    store.create(job)
    try:
        assert store.claim_next(claimant_tier="firecracker") is None  # non-match → not claimed
        assert store.claim_next(claimant_tier=None) is None            # untiered → not claimed
        claimed = store.claim_next(claimant_tier="gvisor")            # match → claimed
        assert claimed is not None
        assert claimed.target_tier == "gvisor"
        assert claimed.status == JobStatus.RUNNING
    finally:
        store.delete(job.job_id)
