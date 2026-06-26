"""Unit tests for the libvirt pool job dispatcher (in-memory store; validate stubbed)."""
from __future__ import annotations

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.vm_dispatch import VmJobDispatcher


def _queue_job(store, tmp_path, filename="evil.dll", body=b"MZ"):
    job = Job.new(engine="authenticode", filename=filename)
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / filename).write_bytes(body)
    job.result_dir = str(root)
    store.create(job)
    return job


def test_dispatch_marks_done_with_summary_and_unlinks_input(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    seen = {}

    def validate(path):
        seen["path"] = path
        return ({"verdict": {"status": "Revoked"}}, True)

    d = VmJobDispatcher(store, str(tmp_path), validate)
    d._process(store.claim_next())                       # claim_next -> RUNNING + claim_id
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary["verdict"]["status"] == "Revoked"
    assert seen["path"].name == "evil.dll"
    assert not (tmp_path / job.job_id / "input" / "evil.dll").exists()   # input consumed


def test_dispatch_marks_failed_when_engine_reports_not_ok(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"envelope_status": "engine_error"}, False))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.FAILED


def test_dispatch_marks_failed_on_raise(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def boom(p):
        raise RuntimeError("worker died")

    d = VmJobDispatcher(store, str(tmp_path), boom)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert got.error == "RuntimeError"


def test_dispatch_missing_input_is_failed(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    (tmp_path / job.job_id / "input" / "evil.dll").unlink()   # spooled input vanished
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.FAILED
