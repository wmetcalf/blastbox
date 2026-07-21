"""Security invariant: a worker leaves no sample bytes behind — on ANY path.

Workers are frequently spare hardware (a laptop, an old desktop), not hardened
sample repositories. The failure paths matter most: they are where a purge is
easiest to omit, and ~1.6% of a real corpus hits the timeout path.
"""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

SECRET = b"MALWARE-BYTES-MUST-NOT-PERSIST"


class Blobs:
    def __init__(self, fail_fetch=False): self.fail_fetch = fail_fetch
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        if self.fail_fetch:
            raise BlobFetchError("down")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(SECRET)
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def _residue(root):
    return [p for p in root.rglob("*") if p.is_file() and SECRET in p.read_bytes()]


@pytest.mark.parametrize("validate_ok", [True, False], ids=["success", "engine-failure"])
def test_no_sample_residue_after_terminal_state(vm_dispatcher_factory, tmp_path, validate_ok):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "a" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=validate_ok)
    disp._process(claimed)

    assert _residue(tmp_path) == [], "sample bytes survived a terminal state"
    # The stub validate() writes no SECRET into output/, so the residue check alone can't catch a
    # dir-level leak (e.g. output/metadata.json, or an empty-but-present input/ dir) — assert the
    # whole per-job directory is gone, which is the actual invariant ("nothing survives").
    assert not (tmp_path / job.job_id).exists(), "job dir must not survive a terminal state"


def test_no_sample_residue_after_validator_raises(vm_dispatcher_factory, tmp_path):
    """The timeout/crash path — the one most likely to skip cleanup."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    def _boom(in_path):
        raise TimeoutError("engine timed out after 120.0s")

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=True)
    disp._validate = _boom
    disp._process(claimed)

    assert _residue(tmp_path) == []
    assert not (tmp_path / job.job_id).exists(), "job dir must not survive a crashed validate()"


def test_no_residue_after_release_back_to_queued(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "c" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(fail_fetch=True))
    disp._process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED
    assert _residue(tmp_path) == []
