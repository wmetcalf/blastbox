"""Expiring one job must not delete a sample another job still references.

This is the highest-risk failure in the design: sample blobs are content-addressed
and SHARED, so a sweeper that deletes them breaks unrelated jobs silently — including
future re-runs of the same corpus.
"""
from __future__ import annotations

from pathlib import Path

from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import JobRetentionSweeper


class Blobs:
    def __init__(self):
        self.deleted: list[str] = []
        self.samples = {"a" * 64}

    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id):
        self.deleted.append(job_id)


def test_expiring_a_job_calls_delete_job(tmp_path: Path, expired_job_factory):
    """expired_job_factory: see tests/host/jobs/conftest.py."""
    store = InMemoryJobStore()
    job = expired_job_factory(store, sha256="a" * 64)
    blobs = Blobs()

    JobRetentionSweeper(job_root=tmp_path, blob_store=blobs).expire_due(store)

    assert blobs.deleted == [job.job_id]


def test_expiring_a_job_never_deletes_shared_samples(tmp_path: Path, expired_job_factory):
    store = InMemoryJobStore()
    expired_job_factory(store, sha256="a" * 64)
    blobs = Blobs()

    JobRetentionSweeper(job_root=tmp_path, blob_store=blobs).expire_due(store)

    assert blobs.samples == {"a" * 64}, "sample blob must survive job expiry"


def test_delete_job_failure_does_not_block_other_jobs(tmp_path: Path, expired_job_factory):
    """A blob-store hiccup reaping one job's results must not abort the sweep for others."""
    store = InMemoryJobStore()
    job1 = expired_job_factory(store, sha256="a" * 64)
    job2 = expired_job_factory(store, sha256="b" * 64)

    class FlakyBlobs(Blobs):
        def delete_job(self, job_id):
            if job_id == job1.job_id:
                raise RuntimeError("simulated blob-store outage")
            super().delete_job(job_id)

    blobs = FlakyBlobs()

    expired = JobRetentionSweeper(job_root=tmp_path, blob_store=blobs).expire_due(store)

    assert job1.job_id in expired
    assert job2.job_id in expired
    assert blobs.deleted == [job2.job_id]


def test_failed_delete_leaves_job_sweepable_then_a_later_sweep_expires_it(tmp_path: Path, expired_job_factory):
    """A transient delete_job failure must NOT advance the job to EXPIRED / clear expires_at -- else
    the result blob is orphaned forever (an EXPIRED job with null expires_at is never re-selected).
    The job stays in its terminal state with expires_at intact, and a later sweep whose delete
    succeeds finishes the expiry."""
    store = InMemoryJobStore()
    job = expired_job_factory(store, sha256="a" * 64)

    class OnceFailingBlobs(Blobs):
        def __init__(self):
            super().__init__()
            self.fail_next = True

        def delete_job(self, job_id):
            if self.fail_next:
                self.fail_next = False
                raise RuntimeError("transient object-store outage")
            super().delete_job(job_id)

    blobs = OnceFailingBlobs()
    sweeper = JobRetentionSweeper(job_root=tmp_path, blob_store=blobs)

    # Sweep 1: delete_job raises -> job NOT marked EXPIRED, expires_at intact -> still sweepable.
    sweeper.expire_due(store)
    after = store.get(job.job_id)
    assert after.status is JobStatus.DONE, "a failed blob delete must not mark the job EXPIRED"
    assert after.expires_at is not None, "expires_at must be preserved so the next sweep retries"
    assert blobs.deleted == []

    # Sweep 2: delete_job now succeeds -> job advances to EXPIRED and the blob is reaped.
    sweeper.expire_due(store)
    final = store.get(job.job_id)
    assert final.status is JobStatus.EXPIRED
    assert final.expires_at is None
    assert blobs.deleted == [job.job_id]


def test_no_blob_store_is_a_pure_regression_noop(tmp_path: Path, expired_job_factory):
    """blob_store defaults to None: mode-1 (no object storage) behaviour is unchanged."""
    store = InMemoryJobStore()
    job = expired_job_factory(store, sha256="a" * 64)

    expired = JobRetentionSweeper(job_root=tmp_path).expire_due(store)

    assert job.job_id in expired
