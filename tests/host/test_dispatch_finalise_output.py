"""Dispatcher.finalise_output: the shared seal-and-ship step, callable on a populated tree."""
from __future__ import annotations

import json
import os

import pytest

from blastbox.host import attest
from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.test_dispatch import (
    _ENGINE_IMAGE,
    _ENGINE_NAME,
    _INPUT_SHA,
    _fake_runtime,
    _limits,
    _make_job,
    _make_valid_output_dir,
    _setup_job_dirs,
)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_") or k in (
                "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BLASTBOX_HOST_ID", "finaliser-host")


def _setup(tmp_path, *, key=None):
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job, input_content=b"malware")
    claimed = store.claim_next()
    assert claimed is not None and claimed.job_id == job.job_id
    d = Dispatcher(
        job_store=store,
        engines={_ENGINE_NAME: EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE,
                                          worker_argv=["worker", "run"])},
        limits=_limits(), job_root=tmp_path / "jobs", runtime_selector=_fake_runtime,
        blob_store=LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs"),
        put_output_max_attempts=1, put_output_retry_backoff_s=0.0, attest_key=key,
    )
    return d, store, claimed, tmp_path / "jobs" / job.job_id / "output"


def _obs(job):
    now = attest.now_ms()
    return attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256=_INPUT_SHA,
        worker_runtime="runc", worker_tier=None, started_at_ms=now, finished_at_ms=now)


def test_finalise_output_done(tmp_path):
    key = attest.load_or_create_key(tmp_path / "keys" / "attest.key")
    d, store, job, out = _setup(tmp_path, key=key)
    _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
    assert d.finalise_output(job, out, _obs(job)) == "done"
    assert store.get(job.job_id).status == JobStatus.DONE
    receipt = tmp_path / "blobs" / "results" / job.job_id / attest.RECEIPT_NAME
    assert json.loads(receipt.read_bytes())["attestation"]["job_id"] == job.job_id


def test_finalise_output_engine_error_fails(tmp_path):
    d, store, job, out = _setup(tmp_path)
    _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["status"] = "engine_error"
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    result = d.finalise_output(job, out, None)
    assert result.startswith("failed: engine_error")
    row = store.get(job.job_id)
    assert row.status == JobStatus.FAILED and "engine_error" in (row.error or "")


def test_finalise_output_lost_claim_does_not_upload(tmp_path):
    d, store, job, out = _setup(tmp_path)
    _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
    assert store.update_if_status(job.job_id, JobStatus.RUNNING, status=JobStatus.QUEUED,
                                  claim_id=None)
    assert d.finalise_output(job, out, None) == "lost"
    assert store.get(job.job_id).status == JobStatus.QUEUED
    assert not (tmp_path / "blobs" / "results" / job.job_id).exists()


def test_finalise_output_untrusted_tree_fails(tmp_path):
    d, store, job, out = _setup(tmp_path)
    out.mkdir(parents=True, exist_ok=True)  # no metadata.json
    result = d.finalise_output(job, out, None)
    assert result.startswith("failed: output trust validation failed")
    assert store.get(job.job_id).status == JobStatus.FAILED
