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


def test_dispatch_metadata_overwrites_stale_and_neuters_artifacts(tmp_path):
    # metadata.json is overwritten (not skip-if-exists) so a reclaim race resolves to OUR validation,
    # and the guest-supplied artifacts list is neutered to [] (never served as trusted output).
    import json
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text('{"stale": true, "artifacts": [{"id": "x", "path": "../etc"}]}')
    d = VmJobDispatcher(store, str(tmp_path),
                        lambda p: ({"verdict": "ok", "artifacts": [{"id": "y", "path": "z"}]}, True))
    d._process(store.claim_next())
    meta = json.loads((out / "metadata.json").read_text())
    assert meta.get("verdict") == "ok" and "stale" not in meta   # overwritten with our result
    assert meta["artifacts"] == []                               # guest artifacts neutered (security)


def test_dispatch_bounds_oversized_summary(tmp_path):
    # a compromised VM agent's huge summary must not be stored verbatim (balloons DB + every response)
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    big = {"blob": "A" * (300 * 1024)}
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (big, True), max_summary_bytes=256 * 1024)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary["error"] == "summary_too_large"


def test_dispatch_times_out_a_hung_validate(tmp_path):
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: _t.sleep(5),
                        validate_timeout_s=0.3, heartbeat_s=0.1)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "TimeoutError"   # claim thread freed


def test_dispatch_fails_job_when_metadata_unwritable(tmp_path):
    # metadata is a precondition for DONE: if it can't be written, the job FAILs (never DONE with a
    # 404'ing /metadata).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"v": 1}, True))
    d._ensure_metadata = lambda *a, **k: False   # simulate a write failure  # type: ignore[method-assign]
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "metadata_write_failed"


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


def test_heartbeat_survives_transient_store_error(tmp_path):
    # a transient store error in the heartbeat must NOT kill the heartbeat thread: if started_at
    # stopped refreshing, the orphan sweep would FAIL this still-running job and delete its input.
    # The pump swallows+logs the error and keeps beating; the job still completes.
    import time as _t

    class _FlakyHeartbeatStore(InMemoryJobStore):
        heartbeat_raises = 0

        def update_if_status(self, job_id, expect_status, *, expect_claim_id=None, **fields):
            # The heartbeat is the ONLY caller that refreshes started_at with no status change; the
            # terminal CAS sets status= and the warm-mark sets worker_runtime/worker_tier.
            if "started_at" in fields and "status" not in fields and self.heartbeat_raises > 0:
                self.heartbeat_raises -= 1
                raise RuntimeError("transient store blip")
            return super().update_if_status(job_id, expect_status,
                                            expect_claim_id=expect_claim_id, **fields)

    store = _FlakyHeartbeatStore()
    store.heartbeat_raises = 2          # first two heartbeats blow up, then recover
    job = _queue_job(store, tmp_path)
    claimed = store.claim_next()
    t0 = store.get(job.job_id).started_at

    def slow_validate(p):
        # the heartbeat interval floors at 1s; 2 injected failures push the first SURVIVING beat to
        # ~3s, so give it generous headroom (this asserts recovery, not latency).
        deadline = _t.time() + 8.0
        while _t.time() < deadline:     # wait until a heartbeat survives the blips and bumps started_at
            if (store.get(job.job_id).started_at or 0) > t0:
                return ({}, True)
            _t.sleep(0.02)
        return ({}, False)

    d = VmJobDispatcher(store, str(tmp_path), slow_validate, heartbeat_s=0.05)
    d._process(claimed)
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE        # heartbeat recovered + job completed despite the blips
    assert got.started_at > t0                 # started_at was still refreshed (sweep won't orphan it)
    assert store.heartbeat_raises == 0         # both injected errors were actually exercised


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


def _claim_as_vm(store, job, *, started_at, worker_runtime="warm", worker_tier="libvirt-vm"):
    claimed = store.claim_next()
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=claimed.claim_id,
                           started_at=started_at, worker_runtime=worker_runtime, worker_tier=worker_tier)


def test_maintenance_recovers_orphaned_running_job(tmp_path):
    # a VM-owned RUNNING job whose heartbeat went stale (claiming dispatcher crashed) is FAILED by
    # maintenance and its input dropped — not left RUNNING forever.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0)             # ancient started_at, marked warm/our-tier
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0)
    d._run_maintenance()
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "orphaned"
    assert not (tmp_path / job.job_id / "input" / "evil.dll").exists()


def test_maintenance_leaves_fresh_running_job_alone(tmp_path):
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=_t.time())        # freshly heartbeated
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=600.0)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.RUNNING   # still alive, untouched


def test_maintenance_sole_owner_recovers_unmarked_claim(tmp_path):
    # a claim that crashed BEFORE the warm stamp (worker_runtime unset) is stuck forever in a VM-only
    # deployment; sole_owner=True lets maintenance reclaim it (no cold dispatcher to mistake it for).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0, worker_runtime=None, worker_tier=None)  # unmarked, stale
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0,
                        sole_owner=True)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.FAILED       # reclaimed
    # without sole_owner an unmarked claim is left alone (could be a cold job)
    store2 = InMemoryJobStore()
    job2 = _queue_job(store2, tmp_path / "b")
    _claim_as_vm(store2, job2, started_at=1.0, worker_runtime=None, worker_tier=None)
    VmJobDispatcher(store2, str(tmp_path / "b"), lambda p: ({}, True),
                    orphan_timeout_s=10.0)._run_maintenance()
    assert store2.get(job2.job_id).status is JobStatus.RUNNING


def test_maintenance_does_not_recover_a_cold_job(tmp_path):
    # a stale-but-not-ours job (a cold/container job, worker_runtime != "warm") must NOT be failed —
    # its Docker worker may still be running; failing + deleting input would be a cross-tier clobber.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0, worker_runtime="runc", worker_tier=None)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.RUNNING        # left for the cold dispatcher
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists()  # input NOT deleted


def test_maintenance_expires_terminal_job_dir(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.result_dir = str(tmp_path / job.job_id / "output")
    (tmp_path / job.job_id / "output").mkdir(parents=True)
    store.update(job.job_id, status=JobStatus.DONE, result_dir=job.result_dir, expires_at=1.0)  # past
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._run_maintenance()
    assert not (tmp_path / job.job_id).exists()           # retention reclaimed the whole job dir
    assert store.get(job.job_id).status is JobStatus.EXPIRED


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


def test_dispatch_marks_failed_when_validate_raises_baseexception(tmp_path):
    # a validate() that raises a non-Exception BaseException (e.g. a sample-triggered sys.exit) must
    # still FAIL the job, not slip past _process's `except Exception` and leave it RUNNING forever.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def sys_exit(p):
        raise SystemExit(2)

    d = VmJobDispatcher(store, str(tmp_path), sys_exit)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED              # normalized to a failure, not a stuck RUNNING
    assert got.error == "RuntimeError"                 # wrapped (SystemExit → RuntimeError)


def test_dispatch_missing_input_is_failed(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    (tmp_path / job.job_id / "input" / "evil.dll").unlink()   # spooled input vanished
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.FAILED
