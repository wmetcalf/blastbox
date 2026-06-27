"""Unit tests for the libvirt pool job dispatcher (in-memory store; validate stubbed)."""
from __future__ import annotations

import pytest

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

    d = VmJobDispatcher(store, str(tmp_path), validate, worker_tier="libvirt-vm")
    d._process(store.claim_next())                       # claim_next -> RUNNING + claim_id
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary["verdict"]["status"] == "Revoked"
    assert seen["path"].name == "evil.dll"
    assert not (tmp_path / job.job_id / "input" / "evil.dll").exists()   # input consumed
    # marked as a warm worker so a peer's crash-recovery sweep won't treat it as a dead cold job.
    assert got.worker_runtime == "warm"
    assert got.worker_tier == "libvirt-vm"


def test_dispatch_writes_metadata_json_on_done(tmp_path):
    # ingress /metadata, /artifacts, /result require <output>/metadata.json once a job is DONE; the
    # dispatcher materializes it from the summary so those routes don't 404 on a VM job.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"verdict": {"status": "Valid"}}, True))
    d._process(store.claim_next())
    meta = tmp_path / job.job_id / "output" / "metadata.json"
    assert meta.is_file()
    import json
    assert json.loads(meta.read_text())["verdict"]["status"] == "Valid"


def test_dispatch_does_not_write_metadata_on_failure(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"err": 1}, False))
    d._process(store.claim_next())
    assert not (tmp_path / job.job_id / "output" / "metadata.json").exists()   # only on success


def test_heartbeat_refreshes_started_at_during_validate(tmp_path):
    # a long validate() must not look abandoned to a peer recovery sweep: the heartbeat refreshes
    # started_at while it runs.
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    claimed = store.claim_next()
    t0 = store.get(job.job_id).started_at

    def slow_validate(p):
        deadline = _t.time() + 3.0
        while _t.time() < deadline:           # wait until the heartbeat bumps started_at
            if (store.get(job.job_id).started_at or 0) > t0:
                return ({}, True)
            _t.sleep(0.02)
        return ({}, False)                    # heartbeat never fired → fail the assertion below

    d = VmJobDispatcher(store, str(tmp_path), slow_validate, heartbeat_s=0.05)
    d._process(claimed)
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE       # heartbeat fired (validate returned ok=True)
    assert got.started_at > t0                # started_at was refreshed past claim time


def test_dispatch_sets_retention_expiry(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), job_retention_s=100)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.finished_at is not None and got.expires_at is not None
    assert got.expires_at == pytest.approx(got.finished_at + 100)   # retention sweeper can reclaim it


def test_dispatch_keeps_input_when_job_was_reclaimed(tmp_path):
    # if validation outran a recovery requeue and another dispatcher reclaimed the job, our terminal
    # CAS fails (stale claim_id) and we must NOT unlink the shared input out from under the new owner.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    stale = store.claim_next()                                       # claim A
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=stale.claim_id,
                           status=JobStatus.QUEUED, claim_id=None, started_at=None)  # requeue
    store.claim_next()                                              # reclaim B (now RUNNING under B)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"v": 1}, True))
    d._process(stale)                                              # process with the STALE claim A
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists()  # preserved for the new owner
    assert store.get(job.job_id).status is JobStatus.RUNNING        # stale owner couldn't terminate it


def test_claim_is_ours_requeues_foreign_engine(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)                  # engine="authenticode"
    ran = []
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (ran.append(p), ({}, True))[1], engine="other")
    assert d._claim_is_ours(store.claim_next()) is False
    got = store.get(job.job_id)
    assert got.status is JobStatus.QUEUED and got.claim_id is None  # requeued for the right dispatcher
    assert ran == []                                               # foreign job never validated


def test_claim_is_ours_accepts_matching_and_unscoped(tmp_path):
    store = InMemoryJobStore()
    _queue_job(store, tmp_path)
    claimed = store.claim_next()
    assert VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))._claim_is_ours(claimed) is True
    assert VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                           engine="authenticode")._claim_is_ours(claimed) is True


def test_claim_next_engine_set_keeps_vm_jobs_off_cold_dispatcher():
    # a cold dispatcher claiming with the SET of engines it handles must leave a VM-only engine's job
    # for the VM dispatcher, not grab it first and fail it "unknown engine".
    store = InMemoryJobStore()
    for eng in ("clippyshot", "authenticode", "redtusk"):
        store.create(Job.new(engine=eng, filename="f"))
    cold_engines = {"clippyshot", "redtusk"}
    seen = set()
    while (j := store.claim_next(engine=cold_engines)) is not None:
        seen.add(j.engine)
    assert seen == cold_engines                                   # never claimed authenticode
    vm = store.claim_next(engine="authenticode")                  # left for the VM dispatcher
    assert vm is not None and vm.engine == "authenticode"


def test_libvirt_vm_is_a_routable_tier():
    # operators must be able to target_tier=libvirt-vm so VM-only jobs aren't claimed+failed by the
    # cold dispatcher in a shared store (ingress validates target_tier against VALID_TIERS).
    from blastbox.host.jobs.base import VALID_TIERS
    assert "libvirt-vm" in VALID_TIERS


def test_engine_scoped_claim_skips_older_foreign_head(tmp_path):
    # the store-side fix: an engine-scoped claim must reach OUR job even when an older foreign job is
    # at the queue head (no head-of-line block, no claim+requeue churn).
    store = InMemoryJobStore()
    other = Job.new(engine="other-engine", filename="b.dll")
    store.create(other)                       # older, head of queue
    mine = Job.new(engine="authenticode", filename="a.dll")
    store.create(mine)
    claimed = store.claim_next(engine="authenticode")
    assert claimed is not None and claimed.job_id == mine.job_id   # skipped the foreign head
    assert store.get(other.job_id).status is JobStatus.QUEUED      # foreign job left untouched


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
