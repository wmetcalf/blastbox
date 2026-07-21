"""A worker that cannot fetch a sample must RELEASE the claim, not fail the job.

An unreachable object store is a property of THIS worker's connectivity, not of the
sample. Failing would permanently discard work because one node's link blipped.
"""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class UnreachableBlobStore:
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        raise BlobFetchError("object store unreachable")
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FetchingBlobStore:
    def __init__(self, data=b"materialised"): self.data = data; self.calls = 0
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        self.calls += 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.data)
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_fetch_failure_returns_the_job_to_queued(vm_dispatcher_factory):
    """vm_dispatcher_factory: see tests/host/runtime/conftest.py."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "d" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp._process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED, "must be reclaimable"


def test_missing_input_is_fetched_then_processed(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "e" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp._process(claimed)

    assert blobs.calls == 1
    assert store.get(job.job_id).status is JobStatus.DONE


def test_present_input_is_not_refetched(vm_dispatcher_factory, tmp_path):
    """Local mode must not pay a fetch for a file that is already there."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "f" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    p = disp._input_path(claimed)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"already here")

    disp._process(claimed)
    assert blobs.calls == 0


def test_release_clears_claim_id_and_backs_the_job_off(vm_dispatcher_factory):
    """Guards the flapping-worker livelock: without claimable_after, the worker that
    just failed to fetch immediately re-claims the same job and spins on it."""
    import time

    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "g" * 64
    store.create(job)
    claimed = store.claim_next()
    assert claimed.claim_id is not None

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp._process(claimed)

    released = store.get(job.job_id)
    assert released.status is JobStatus.QUEUED
    assert released.claim_id is None, "a released job must not keep its claim token"
    assert released.claimable_after > time.time(), "must back off, not be instantly re-claimable"
    assert released.created_at == job.created_at, "submission time must not be rewritten"
