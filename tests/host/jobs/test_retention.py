"""Tests for retention sweeper."""
from __future__ import annotations

import time


from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import JobRetentionSweeper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_job(
    status: JobStatus = JobStatus.DONE,
    expires_at: float | None = None,
    result_dir: str | None = None,
    engine: str = "test",
    filename: str = "file.docx",
) -> Job:
    job = Job.new(engine=engine, filename=filename)
    job.status = status
    job.expires_at = expires_at
    job.result_dir = result_dir
    return job


def _past(delta: float = 10.0) -> float:
    return time.time() - delta


def _future(delta: float = 3600.0) -> float:
    return time.time() + delta


# ---------------------------------------------------------------------------
# Basic expiry of terminal-status jobs
# ---------------------------------------------------------------------------

def test_expires_done_job_past_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired
    # result_dir's parent (job1/) should be deleted
    assert not (tmp_path / "job1").exists()
    # Job should be marked EXPIRED in store
    final = store.get(job.job_id)
    assert final is not None
    assert final.status == JobStatus.EXPIRED


def test_expires_failed_job_past_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job2" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.FAILED,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired


def test_does_not_expire_future_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job3" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_future(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "job3").exists()


def test_does_not_expire_no_expires_at(tmp_path):
    store = InMemoryJobStore()
    job = _make_job(status=JobStatus.DONE, expires_at=None)
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired


# ---------------------------------------------------------------------------
# Non-terminal jobs must NOT be expired
# ---------------------------------------------------------------------------

def test_does_not_expire_queued_job(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "q1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.QUEUED,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "q1").exists()


def test_does_not_expire_running_job(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "r1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.RUNNING,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "r1").exists()


# ---------------------------------------------------------------------------
# rmtree confinement — result_dir outside job_root must be refused
# ---------------------------------------------------------------------------

def test_rmtree_refused_outside_job_root(tmp_path):
    """A result_dir pointing outside job_root must not be deleted."""
    store = InMemoryJobStore()
    # Create a directory *outside* tmp_path that we want to protect
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("do not delete")

    # result_dir points to a path outside tmp_path
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(outside),
    )
    store.create(job)

    # Use a sub-directory as the job_root
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    sweeper = JobRetentionSweeper(job_root=job_root)
    sweeper.expire_due(store)

    # The sweep either skips this job or marks it expired without deletion
    # The outside directory must still exist
    assert outside.exists(), "directory outside job_root must not be deleted"
    assert sentinel.exists(), "files outside job_root must not be deleted"


def test_rmtree_confined_to_job_root(tmp_path):
    """A result_dir inside job_root is safe to delete."""
    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    result_dir = job_root / "job1" / "result"
    result_dir.mkdir(parents=True)
    (result_dir / "output.png").write_bytes(b"data")

    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=job_root)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired
    # The job subdirectory (or at least result_dir) should be gone
    assert not result_dir.exists()


# ---------------------------------------------------------------------------
# Symlink escape — a symlink inside result_dir pointing outside must not be
# followed during deletion
# ---------------------------------------------------------------------------

def test_symlink_escape_not_followed(tmp_path):
    """A symlink inside the result dir pointing outside the base is not followed."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    # Victim directory outside job_root
    victim = tmp_path / "victim"
    victim.mkdir()
    victim_file = victim / "important.txt"
    victim_file.write_text("do not delete")

    # Set up result_dir inside job_root with a symlink pointing outside
    result_dir = job_root / "job1" / "result"
    result_dir.mkdir(parents=True)
    symlink = result_dir / "escape"
    symlink.symlink_to(victim)

    store = InMemoryJobStore()
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=job_root)
    sweeper.expire_due(store)

    # The victim directory must still exist — the symlink target must not
    # have been recursively deleted.
    assert victim.exists(), "victim dir outside job_root must survive"
    assert victim_file.exists(), "victim file must not be deleted via symlink"


# ---------------------------------------------------------------------------
# Failure logging (not crashing the sweeper)
# ---------------------------------------------------------------------------

def test_failure_on_one_job_does_not_block_others(tmp_path, caplog):
    """A failure expiring one job must not prevent others from being expired."""
    import logging

    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    # job1: result_dir points to a non-existent path (simulates partial cleanup)
    job1 = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(job_root / "missing" / "result"),
    )
    store.create(job1)

    # job2: has a real result_dir that should be deleted
    result2 = job_root / "job2" / "result"
    result2.mkdir(parents=True)
    job2 = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result2),
    )
    store.create(job2)

    sweeper = JobRetentionSweeper(job_root=job_root)
    with caplog.at_level(logging.WARNING):
        expired = sweeper.expire_due(store)

    # job2 must be expired even if job1 had issues
    assert job2.job_id in expired
    assert not result2.exists()
