"""Security invariant: a worker leaves no sample bytes behind — on ANY path.

Workers are frequently spare hardware (a laptop, an old desktop), not hardened
sample repositories. The failure paths matter most: they are where a purge is
easiest to omit, and ~1.6% of a real corpus hits the timeout path.
"""
import logging
import shutil

import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

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


def test_purge_refuses_path_outside_job_root(tmp_path, caplog):
    """The containment refusal: _purge_job_dir must never rmtree anything that doesn't
    resolve strictly under job_root -- it must refuse and log an error instead."""
    job_root = tmp_path / "job_root"
    job_root.mkdir()
    outside = tmp_path / "outside-target"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(SECRET)

    disp = VmJobDispatcher(store=InMemoryJobStore(), job_root=str(job_root),
                           validate=lambda p: ({}, True))
    job = Job.new(engine="redtusk", filename="a.doc")
    job.job_id = "../outside-target"   # job_root / job_id resolves OUTSIDE job_root

    with caplog.at_level(logging.ERROR, logger="blastbox.host.runtime.vm_dispatch"):
        disp._purge_job_dir(job)

    assert outside.exists() and (outside / "secret.bin").exists(), "refused purge must leave the dir intact"
    assert any("refus" in r.message.lower() for r in caplog.records), "containment refusal must be logged"


def test_purge_logs_error_and_does_not_raise_on_rmtree_failure(tmp_path, monkeypatch, caplog):
    """The OSError branch: an rmtree failure must be logged loudly at ERROR and must NOT
    raise -- it must never mask the job's real (already-written) terminal outcome."""
    job_root = tmp_path / "job_root"
    job = Job.new(engine="redtusk", filename="a.doc")
    job_dir = job_root / job.job_id
    (job_dir / "input").mkdir(parents=True)
    (job_dir / "input" / "a.doc").write_bytes(SECRET)

    disp = VmJobDispatcher(store=InMemoryJobStore(), job_root=str(job_root),
                           validate=lambda p: ({}, True))

    def _boom(path):
        raise OSError("device or resource busy")

    monkeypatch.setattr(shutil, "rmtree", _boom)

    with caplog.at_level(logging.ERROR, logger="blastbox.host.runtime.vm_dispatch"):
        disp._purge_job_dir(job)   # must not raise

    assert any("PURGE FAILED" in r.message for r in caplog.records), "rmtree failure must be logged at ERROR"


def test_no_residue_after_net_policy_rejection(tmp_path):
    """The net_policy-rejection path is a terminal (FAILED) write and must go through the
    same unconditional purge invariant as every other terminal path -- not a bare input
    unlink that leaves the (now-empty) job dir behind."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.net_policy = "tor"
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / "a.doc").write_bytes(SECRET)
    job.result_dir = str(root)
    store.create(job)
    claimed = store.claim_next()

    def _validate(in_path):
        raise AssertionError("validate() must not run -- job is rejected before detonation")

    disp = VmJobDispatcher(store=store, job_root=str(tmp_path), validate=_validate,
                           fixed_net_policy="none")   # pool declared no-network; job wants "tor"
    disp._process(claimed)

    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert _residue(tmp_path) == [], "sample bytes survived a net_policy-rejected terminal state"
    assert not (tmp_path / job.job_id).exists(), "job dir must not survive a net_policy-rejected job"
