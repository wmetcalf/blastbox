"""TDD tests for the dispatcher warm path + HostWarmControl.

7 tests per the plan at docs/plans/2026-05-31-dispatch-warm.md.

Fixtures:
- FakeWarmPool: returns a pre-built Slot; records release() calls.
- _fake_worker_thread: when it sees go.json appear in the slot's control_dir,
  writes valid output + done file (mirrors the cold-path test style).
- All tests use tmp_path so nothing touches the real filesystem.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from blastbox.contract.envelope import DeclaredArtifact, seal_envelope
from blastbox.contract.leaf import Detection
from blastbox.contract.nodes import ExtractedText
from dataclasses import replace

from blastbox.errors import OutputTrustError
from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.pool import Slot, SlotState
from blastbox.host.runtime.docker import RuntimeSelection
from blastbox.limits import Limits
from blastbox.worker.warm import FileWarmControl, HostWarmControl, WarmJobSpec, WarmTimeout


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_ENGINE_NAME = "test-engine"
_ENGINE_IMAGE = "registry.example.com/test-worker:latest"
_INPUT_SHA = "b" * 64


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _limits() -> Limits:
    return Limits()


def _engine_spec(name: str = _ENGINE_NAME, image: str = _ENGINE_IMAGE) -> EngineSpec:
    return EngineSpec(name=name, image=image, worker_argv=["worker", "run"])


def _fake_runtime() -> RuntimeSelection:
    return RuntimeSelection(runtime="runc", secure=False, warnings=["no runsc"])


def _make_job(
    *,
    engine: str = _ENGINE_NAME,
    filename: str = "malware.docx",
    params: dict | None = None,
) -> Job:
    job = Job.new(engine=engine, filename=filename)
    if params:
        job.params = params
    return job


def _make_valid_output_dir(
    output_dir: Path,
    *,
    engine: str = _ENGINE_NAME,
    input_sha256: str = _INPUT_SHA,
    artifact_content: bytes = b"PNG_DATA_WARM",
) -> None:
    """Write a valid output directory that passes validate_worker_output."""
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "page-001.png"
    artifact_path.write_bytes(artifact_content)
    real_sha = hashlib.sha256(artifact_content).hexdigest()

    envelope = {
        "engine": engine,
        "status": "ok",
        "input_sha256": input_sha256,
        "detected": {
            "label": "docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "confidence": 0.99,
            "source": "magika",
        },
        "artifacts": [
            {
                "id": "page-001",
                "path": "page-001.png",
                "kind": "image",
                "sha256": real_sha,
                "bytes": len(artifact_content),
            }
        ],
        "warnings": [],
        "payload": {
            "_type": "extracted_text",
            "text": "hello world",
            "char_count": 11,
        },
    }
    (output_dir / "metadata.json").write_bytes(json.dumps(envelope).encode())


def _make_slot(tmp_path: Path, slot_id: str | None = None) -> Slot:
    """Create a Slot backed by real temp directories."""
    slot_id = slot_id or str(uuid4())
    base = tmp_path / "slots" / slot_id
    control_dir = base / "control"
    input_dir = base / "input"
    output_dir = base / "output"
    for d in (control_dir, input_dir, output_dir):
        d.mkdir(parents=True)
    return Slot(
        slot_id=slot_id,
        control_dir=control_dir,
        input_dir=input_dir,
        output_dir=output_dir,
        state=SlotState.IDLE,
    )


def _setup_job_dirs(job_root: Path, job: Job, *, input_content: bytes = b"malware") -> Path:
    """Create the job directory structure (same logic as cold-path test)."""
    job_dir = job_root / job.job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    input_path = input_dir / Path(job.filename).name
    input_path.write_bytes(input_content)
    return input_path


# ---------------------------------------------------------------------------
# FakeWarmPool
# ---------------------------------------------------------------------------


class FakeWarmPool:
    """Minimal WarmPool double: claim() returns _slot (or None if _return_none=True).
    Records all release() calls.
    """

    def __init__(self, slot: Slot | None, runtime: object | None = None) -> None:
        self._slot = slot
        self.release_calls: list[Slot] = []
        self.release_dirty: list[bool] = []
        self.release_fault: list[str | None] = []  # parallel to release_calls: the dirty flag per release
        # Default: a file-based warm runtime that deliberately lacks the vsock
        # warm-path seam (stage_warm_input / host_warm_control /
        # materialize_warm_output), so the dispatcher falls back to the
        # go.json/done + slot-dir path these tests simulate with _start_fake_worker.
        self._runtime = runtime if runtime is not None else object()

    @property
    def runtime(self) -> object:
        return self._runtime

    @property
    def idle_count(self) -> int:
        # Report one idle slot so a warm_only dispatcher's claim-gate passes and proceeds
        # to claim(); claim() is the real hit/miss arbiter (None → requeue path). This also
        # models the gate-saw-idle-then-slot-died race the requeue exists to handle.
        return 1

    def claim(self, *, timeout_s: float) -> Slot | None:
        return self._slot

    def release(self, slot: Slot, *, dirty: bool = False, fault: str | None = None) -> None:
        self.release_calls.append(slot)
        self.release_dirty.append(dirty)
        # Recording the ATTRIBUTION, not just the dirty bit: dirty says "recycle this slot",
        # fault says "hold this slot responsible". Only the latter advances wedge eviction and
        # can invalidate the snapshot base, so it is the field worth asserting on.
        self.release_fault.append(fault)


# ---------------------------------------------------------------------------
# fake-worker thread helper
# ---------------------------------------------------------------------------


def _start_fake_worker(
    slot: Slot,
    *,
    output_fn: Any = None,
    done_status: str = "ok",
    poll_interval: float = 0.01,
    delay_before_done: float = 0.0,
) -> threading.Thread:
    """Launch a background thread that watches for go.json in slot.control_dir.

    When go.json appears, it:
    1. Calls output_fn(slot.output_dir) if provided (else writes valid output).
    2. Optionally sleeps delay_before_done.
    3. Writes control_dir/done atomically with done_status.
    """

    def _worker_body() -> None:
        go_path = slot.control_dir / "go.json"
        # Poll until go.json appears (or for up to 10 s to avoid hangs in CI)
        deadline = time.monotonic() + 10.0
        while not go_path.exists():
            if time.monotonic() > deadline:
                return
            time.sleep(poll_interval)

        # Optionally write output
        if output_fn is not None:
            output_fn(slot.output_dir)

        if delay_before_done:
            time.sleep(delay_before_done)

        # Atomic write of done file
        done_path = slot.control_dir / "done"
        tmp = slot.control_dir / ".done.tmp"
        tmp.write_text(done_status, encoding="utf-8")
        os.replace(tmp, done_path)

    t = threading.Thread(target=_worker_body, daemon=True)
    t.start()
    return t


def _make_dispatcher_with_pool(
    store: InMemoryJobStore,
    *,
    job_root: Path,
    pool: FakeWarmPool | None = None,
    engines: dict | None = None,
    subprocess_runner: Any = None,
    worker_timeout_s: int = 30,
    warm_claim_timeout_s: float = 0.5,
    warm_only: bool = False,
    tier: str = "cold",
    blob_store: Any = None,
    put_output_max_attempts: int = 3,
    put_output_retry_backoff_s: float = 0.0,
) -> Dispatcher:
    if engines is None:
        engines = {_ENGINE_NAME: _engine_spec()}
    if subprocess_runner is None:
        subprocess_runner = lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", "")  # noqa: E731

    return Dispatcher(
        job_store=store,
        engines=engines,
        limits=_limits(),
        job_root=job_root,
        runtime_selector=_fake_runtime,
        subprocess_runner=subprocess_runner,
        worker_timeout_s=worker_timeout_s,
        pool=pool,
        tier=tier,
        warm_claim_timeout_s=warm_claim_timeout_s,
        warm_only=warm_only,
        warm_requeue_backoff_s=0.0,  # tests must not sleep the real 1.0s requeue backoff
        blob_store=blob_store,
        put_output_max_attempts=put_output_max_attempts,
        put_output_retry_backoff_s=put_output_retry_backoff_s,
    )


# ===========================================================================
# Test: FC vsock warm-path seam (input over the wire, output materialized)
# ===========================================================================


class _RecordingVsockControl:
    """A vsock HostWarmControl double: records the spec; reports done='ok'."""

    def __init__(self, slot: Slot) -> None:
        self.slot = slot
        self.spec: Any = None

    def signal_go(self, spec: Any, *, deadline: float | None = None) -> None:
        self.spec = spec
        self.deadline = deadline

    def wait_for_done(self, *, timeout_s: float) -> str:
        return "ok"


class _FakeVsockRuntime:
    """A vsock-style warm runtime: input over the wire (no slot-dir copy), output
    materialized via rdump. Records the seam calls so the test can assert them."""

    def __init__(self) -> None:
        self.staged_input: Path | None = None
        self.materialized_for: Slot | None = None
        self.control: _RecordingVsockControl | None = None

    def stage_warm_input(self, slot: Slot, staged_input_path: Path) -> Path:
        self.staged_input = staged_input_path
        return staged_input_path  # vsock carries it; no copy into slot.input_dir

    def host_warm_control(self, slot: Slot) -> _RecordingVsockControl:
        self.control = _RecordingVsockControl(slot)
        return self.control

    def materialize_warm_output(self, slot: Slot) -> None:
        self.materialized_for = slot
        _make_valid_output_dir(slot.output_dir, input_sha256=_INPUT_SHA)


def test_warm_fc_vsock_seam(tmp_path):
    """When the runtime exposes the vsock seam, the dispatcher delivers input over
    the wire (no slot-dir copy), materializes output via rdump BEFORE the trust
    gate, marks DONE, and releases the slot — preserving every warm guarantee."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    staged = _setup_job_dirs(tmp_path / "jobs", job)  # the host-staged input path

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()
    pool = FakeWarmPool(slot, runtime=runtime)

    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    assert dispatcher.dispatch_once() is True

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE
    assert final_job.result_summary is not None
    assert final_job.result_summary["artifact_count"] == 1

    # The seam was exercised:
    assert runtime.staged_input is not None
    assert runtime.control is not None and runtime.control.spec is not None
    # input_path forwarded to the control is the staged input, NOT a slot copy
    assert runtime.control.spec.input_path == runtime.staged_input
    # output was materialized (rdump) before validation
    assert runtime.materialized_for is slot
    # no copy was made into the slot's input dir (vsock carries the input)
    assert list(slot.input_dir.iterdir()) == []
    # slot released exactly once
    assert len(pool.release_calls) == 1
    # staged input deleted on the seam path too (caller's finally)
    assert not staged.exists()


def test_warm_fc_vsock_seam_materialize_failure_releases_slot(tmp_path):
    """If output materialization (rdump) raises, the job FAILS, the slot is still
    released exactly once, and DONE is never reached — same guarantees as the
    file path's failure modes, but exercised through the vsock seam."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    def _boom(s):
        raise RuntimeError("rdump exploded")

    runtime.materialize_warm_output = _boom  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)

    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    assert dispatcher.dispatch_once() is True

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert len(pool.release_calls) == 1


# ===========================================================================
# Test 7: HostWarmControl round-trip with FileWarmControl (no Dispatcher)
# ===========================================================================


def test_7_hostwarmcontrol_roundtrip(tmp_path):
    """HostWarmControl.signal_go → FileWarmControl.wait_for_go returns spec;
    FileWarmControl.signal_done("ok") → HostWarmControl.wait_for_done returns "ok";
    HostWarmControl.wait_for_done with no done + tiny timeout → WarmTimeout.
    """
    control_dir = tmp_path / "control"
    control_dir.mkdir()
    # Make a dummy input_path and output_dir so FileWarmControl validates them
    input_file = tmp_path / "input.docx"
    input_file.write_bytes(b"data")
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    host_ctrl = HostWarmControl(control_dir)
    worker_ctrl = FileWarmControl(control_dir)

    spec = WarmJobSpec(
        input_path=input_file,
        output_dir=output_dir,
        params={"KEY": "val"},
    )

    # host signals go; worker should receive it
    host_ctrl.signal_go(spec)

    received = worker_ctrl.wait_for_go(timeout_s=2.0)
    assert received.input_path == spec.input_path
    assert received.output_dir == spec.output_dir
    assert received.params == {"KEY": "val"}

    # worker signals done; host should receive it
    worker_ctrl.signal_done(status="ok")
    status = host_ctrl.wait_for_done(timeout_s=2.0)
    assert status == "ok"

    # WarmTimeout when done doesn't appear
    control_dir2 = tmp_path / "control2"
    control_dir2.mkdir()
    host_ctrl2 = HostWarmControl(control_dir2)
    with pytest.raises(WarmTimeout):
        host_ctrl2.wait_for_done(timeout_s=0.05)


# ===========================================================================
# Test 1: Warm happy path
# ===========================================================================


def test_1_warm_happy_path(tmp_path):
    """Pool returns a slot; fake worker writes valid output + done → DONE,
    result_summary set, pool.release(slot) called once, input gone (staged + slot copy).
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    # Start fake worker thread: writes valid output then signals done
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    result = dispatcher.dispatch_once()

    assert result is True
    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE
    assert final_job.result_summary is not None
    assert final_job.result_summary["artifact_count"] == 1
    assert final_job.worker_runtime == "warm"

    # pool.release must have been called exactly once with our slot, CLEAN (the run succeeded)
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot
    assert pool.release_dirty == [False]  # clean DONE → slot safe to reuse without a forced reset

    # staged input must be gone (job_root/job_id/input/<filename>)
    staged_input = tmp_path / "jobs" / job.job_id / "input" / Path(job.filename).name
    assert not staged_input.exists()

    # slot input dir copy must be gone too
    slot_input = slot.input_dir / Path(job.filename).name
    assert not slot_input.exists()


class _RecordingBlobs:
    """Minimal BlobStore double for the warm-path P1/D1 tests (mirrors the cold-path
    double in test_dispatch.py)."""

    def __init__(self, fail_times: int = 0):
        self.fail_times = fail_times
        self.calls = 0
        self.uploaded: list[str] = []
        self.saw_metadata = False
        self.deleted: list[str] = []

    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise OSError(f"object store down (attempt {self.calls})")
        self.saw_metadata = (Path(out_dir) / "metadata.json").is_file()
        self.uploaded.append(job_id)
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id):
        self.deleted.append(job_id)


def test_warm_dispatch_uploads_result_to_blob_store_before_done(tmp_path):
    """P1 (warm completion path): the warm path must also call put_output, with the
    HOST job_root output dir (not the slot dir) already sealed, BEFORE marking DONE."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    blobs = _RecordingBlobs()
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10, blob_store=blobs,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.uploaded == [job.job_id]
    assert blobs.saw_metadata, "the host-materialized output dir must be sealed before upload"
    final_job = store.get(job.job_id)
    assert final_job.status == JobStatus.DONE


def test_warm_upload_failure_fails_job_and_releases_slot_dirty(tmp_path):
    """Finding D1 (warm completion path): an upload that exhausts every bounded
    inline attempt must FAIL the job (never DONE) and release the slot DIRTY —
    the same shape as every other warm-path failure (see test_2_warm_trust_failure)."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    blobs = _RecordingBlobs(fail_times=999)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10, blob_store=blobs,
        put_output_max_attempts=3,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.calls == 3
    assert blobs.uploaded == []
    final_job = store.get(job.job_id)
    assert final_job.status == JobStatus.FAILED
    assert final_job.error is not None
    assert "upload" in final_job.error.lower()

    # Slot released exactly once, DIRTY — a failed run force-recycles it before reuse.
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot
    assert pool.release_dirty == [True]

    # Finding S1: the exhaustion path must reap any partial result blob -- else, with the
    # default job_retention_seconds=0 (expires_at=None), the retention sweeper skips this
    # FAILED job forever and the partial results/<job_id> blob leaks unbounded.
    assert blobs.deleted == [job.job_id]


def test_warm_reclaimed_claim_skips_upload_instead_of_clobbering_peer_result(tmp_path):
    """Round-2 finding R2-1 (warm completion path): put_output writes to a deterministic
    per-job key that is a per-file overwrite/union, not a claim-fenced atomic swap. If a
    peer reclaims this job in the narrow window between the last local ownership check
    and the upload -- here simulated by flipping claim_id right after
    _materialize_sealed_warm_output runs, mirroring VmJobDispatcher's own
    test_reclaimed_claim_skips_upload_instead_of_clobbering_peer_result -- this worker must
    NOT then upload its (possibly stale) bytes over the peer's already-correct result."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    blobs = _RecordingBlobs()
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10, blob_store=blobs,
    )

    # Simulate a peer reclaiming the job right after the host materializes + seals the
    # output but before the dispatcher re-checks ownership for the upload.
    real_materialize = dispatcher._materialize_sealed_warm_output

    def _materialize_then_peer_reclaims(envelope, src_dir, dst_dir):
        real_materialize(envelope, src_dir, dst_dir)
        store.update(job.job_id, claim_id="peer-claim-id-not-ours")

    dispatcher._materialize_sealed_warm_output = _materialize_then_peer_reclaims  # type: ignore[method-assign]

    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.uploaded == [], "put_output must never be called once ownership is lost"
    stored = store.get(job.job_id)
    assert stored.status == JobStatus.RUNNING, "must not clobber the peer's ownership of this job"
    assert stored.claim_id == "peer-claim-id-not-ours"

    # The slot must still be released exactly once (dirty -- this attempt did not cleanly finish).
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot
    assert pool.release_dirty == [True]
    # ...and NOT blamed on the worker. It produced valid output and merely lost a race; a peer
    # owns the job now. Blaming it means a busy queue (where reclaim races are common) steadily
    # burns out healthy slots and can invalidate a good base. Upstream, PR #82.
    assert pool.release_dirty == [True], (
        "a claim-loss abort must still release the slot DIRTY -- fault=None is reachable only "
        f"via warm_clean=True, which returns a possibly-contaminated slot to IDLE unreset "
        f"(got dirty={pool.release_dirty})"
    )
    assert pool.release_fault == ["unknown"], (
        f"a reclaim race is not worker evidence (got {pool.release_fault})"
    )


def test_warm_claim_lost_before_staging_is_not_blamed_on_the_worker(tmp_path):
    """The SIBLING claim-loss exit: the pre-staging CAS.

    Same defect as the DONE-CAS path above, one branch earlier -- and the one that survived when
    the equivalent fix landed on the remote path. Here the worker has not even been handed the
    job yet, so attributing the abort to it is not merely unfair, it is evidence-free.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    # The peer must reclaim AFTER this dispatcher takes its own claim -- flipping it up front
    # only makes dispatch_once() re-claim and the CAS then SUCCEEDS, so the job runs normally and
    # times out, and the test would be asserting on a timeout rather than on claim loss.
    # pool.claim() is the seam that sits between the claim and the pre-staging CAS.
    real_claim = pool.claim

    def _claim_then_peer_reclaims(*a, **kw):
        got = real_claim(*a, **kw)
        store.update(job.job_id, claim_id="peer-claim-id-not-ours")
        return got

    pool.claim = _claim_then_peer_reclaims  # type: ignore[method-assign]

    dispatcher.dispatch_once()

    stored = store.get(job.job_id)
    assert stored.claim_id == "peer-claim-id-not-ours", "the peer must still own the job"

    assert pool.release_calls == [slot], "the slot must still be released exactly once"
    assert pool.release_dirty == [True], (
        "a claim-loss abort must still release the slot DIRTY -- fault=None is reachable only "
        f"via warm_clean=True, which returns a possibly-contaminated slot to IDLE unreset "
        f"(got dirty={pool.release_dirty})"
    )
    assert pool.release_fault == ["unknown"], (
        f"a claim lost BEFORE staging cannot be the worker's fault (got {pool.release_fault})"
    )


def test_a_genuine_warm_failure_is_still_blamed_on_the_worker(tmp_path):
    """The carve-out must stay narrow.

    Guards the over-correction: de-attributing claim loss so broadly that real warm failures stop
    advancing wedge eviction -- which is the bug the attribution was added to fix.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    # No fake worker started -> the run times out against this slot: real worker evidence.
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=0.5,
    )

    dispatcher.dispatch_once()

    assert pool.release_dirty == [True]
    assert pool.release_fault == ["worker"], (
        f"a warm run that failed against this slot IS worker evidence (got {pool.release_fault})"
    )


def test_warm_claim_lost_before_sealing_is_not_blamed_on_the_worker(tmp_path):
    """Third claim-loss exit: the pre-SEAL CAS.

    The worker has already run and written its output here; the abort only skips the seal. Found
    by mutation testing -- the other three exits were guarded and this one silently was not.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    # Flip the claim as the worker writes its output: that lands after staging (so the
    # pre-staging CAS passes) and before the dispatcher's pre-seal CAS.
    def _output_then_peer_reclaims(out_dir):
        _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA)
        store.update(job.job_id, claim_id="peer-claim-id-not-ours")

    _start_fake_worker(slot, output_fn=_output_then_peer_reclaims)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    dispatcher.dispatch_once()

    assert pool.release_calls == [slot]
    assert pool.release_dirty == [True], (
        "a claim-loss abort must still release the slot DIRTY -- fault=None is reachable only "
        f"via warm_clean=True, which returns a possibly-contaminated slot to IDLE unreset "
        f"(got dirty={pool.release_dirty})"
    )
    assert pool.release_fault == ["unknown"], (
        f"a claim lost before sealing is not worker evidence (got {pool.release_fault})"
    )


def test_warm_claim_lost_at_the_done_write_is_not_blamed_on_the_worker(tmp_path):
    """Fourth claim-loss exit: the terminal DONE CAS.

    The most costly one to misattribute -- this worker did everything right, produced valid
    output, uploaded it, and lost only the final race. Also found by mutation testing.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    # Let the pre-upload ownership check SUCCEED (it reads the store before the flip), then flip
    # so the terminal DONE CAS is the exit taken. Without this ordering the test would land on
    # the pre-upload exit instead and silently prove nothing about the DONE write.
    real_check = dispatcher._claim_is_still_ours

    def _check_then_peer_reclaims(j):
        ours = real_check(j)
        store.update(job.job_id, claim_id="peer-claim-id-not-ours")
        return ours

    dispatcher._claim_is_still_ours = _check_then_peer_reclaims  # type: ignore[method-assign]

    dispatcher.dispatch_once()

    stored = store.get(job.job_id)
    assert stored.status == JobStatus.RUNNING, "the peer's state must be left untouched"
    assert pool.release_calls == [slot]
    assert pool.release_dirty == [True], (
        "a claim-loss abort must still release the slot DIRTY -- fault=None is reachable only "
        f"via warm_clean=True, which returns a possibly-contaminated slot to IDLE unreset "
        f"(got dirty={pool.release_dirty})"
    )
    assert pool.release_fault == ["unknown"], (
        f"losing only the DONE race is not worker evidence (got {pool.release_fault})"
    )


def test_a_broken_release_is_not_retried_as_a_compatibility_fallback(tmp_path):
    """A TypeError from INSIDE release() must not be mistaken for an old release() signature.

    The fault kwarg was introduced with a `try: release(fault=...) except TypeError: release(...)`
    shim. That shim cannot tell "this pool predates fault=" from "release() itself raised
    TypeError", so a genuine bug inside release made the dispatcher release the SAME slot twice --
    a double reap, caused by a compatibility shim. Signature introspection cannot confuse the two.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)

    class _BrokenRelease(FakeWarmPool):
        def release(self, slot: Slot, *, dirty: bool = False, fault: str | None = None) -> None:
            super().release(slot, dirty=dirty, fault=fault)
            raise TypeError("bug inside release(), NOT an old signature")

    pool = _BrokenRelease(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    with contextlib.suppress(TypeError):
        dispatcher.dispatch_once()

    assert len(pool.release_calls) == 1, (
        f"the slot must be released exactly once, not re-released as a fallback "
        f"(got {len(pool.release_calls)} releases)"
    )


def test_warm_dispatch_stamps_worker_tier(tmp_path):
    """Feature #1: a warm dispatch records WHICH backend ran the job (worker_tier), alongside the
    generic worker_runtime="warm" — so FC-warm and gVisor-warm are distinguishable in the result.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10, tier="gvisor",
    )
    assert dispatcher.dispatch_once() is True
    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE
    assert final_job.worker_runtime == "warm"   # generic tier marker (unchanged)
    assert final_job.worker_tier == "gvisor"     # specific backend (new)


def test_warm_done_cas_fenced_against_concurrent_recovery(tmp_path):
    """If a peer dispatcher FAILs the warm job as stale WHILE this owner is processing, the
    owner's terminal DONE write must NOT resurrect it (first-writer-wins) — otherwise a recovered/
    retention-expired job flips back to DONE with a self-contradictory 'owner gone' record."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    # Fake worker writes valid output AND simulates a concurrent peer recovery: CAS-fail the
    # still-RUNNING job before signaling done, so the owner's later DONE must be fenced out.
    def _output_then_peer_recovers(out_dir):
        _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA)
        assert store.update_if_status(
            job.job_id, JobStatus.RUNNING, status=JobStatus.FAILED, error="peer recovered (stale)"
        )

    _start_fake_worker(slot, output_fn=_output_then_peer_recovers)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    dispatcher.dispatch_once()

    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED  # DONE did NOT resurrect the peer-recovered job
    assert final.error == "peer recovered (stale)"
    assert final.result_summary is None  # the DONE write (with result_summary) never applied


# ===========================================================================
# Test 2: Warm output fails trust → FAILED, slot released, input gone
# ===========================================================================


def test_2_warm_trust_failure(tmp_path):
    """Worker writes a traversal artifact → trust validation fails → FAILED,
    slot released, input gone.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    def _bad_output(output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Traversal artifact — trust gate must reject this
        escape = tmp_path / "escape.bin"
        escape.write_bytes(b"secret")
        envelope = {
            "engine": _ENGINE_NAME,
            "status": "ok",
            "input_sha256": _INPUT_SHA,
            "detected": {
                "label": "docx",
                "mime": "text/plain",
                "confidence": 1.0,
                "source": "magika",
            },
            "artifacts": [
                {
                    "id": "evil",
                    "path": "../escape.bin",  # TRAVERSAL
                    "kind": "image",
                    "sha256": "a" * 64,
                    "bytes": 6,
                }
            ],
            "warnings": [],
            "payload": {"_type": "extracted_text", "text": "x", "char_count": 1},
        }
        (output_dir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    _start_fake_worker(slot, output_fn=_bad_output)

    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert final_job.error is not None

    # Slot released exactly once, DIRTY (trust failure → force-reset before reuse)
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot
    assert pool.release_dirty == [True]

    # Input gone
    staged_input = tmp_path / "jobs" / job.job_id / "input" / Path(job.filename).name
    assert not staged_input.exists()
    slot_input = slot.input_dir / Path(job.filename).name
    assert not slot_input.exists()


# ===========================================================================
# Test 3: Warm worker never signals done → WarmTimeout → FAILED, slot released, input gone
# ===========================================================================


def test_3_warm_timeout(tmp_path):
    """Fake worker never writes done → WarmTimeout → FAILED("timed out"),
    slot released, input gone.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    # No fake worker thread started — done file never appears

    dispatcher = _make_dispatcher_with_pool(
        store,
        job_root=tmp_path / "jobs",
        pool=pool,
        worker_timeout_s=1,  # very short timeout
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert final_job.error is not None
    assert "timed out" in final_job.error.lower() or "timeout" in final_job.error.lower()

    # Slot released exactly once, DIRTY (timeout → force-reset before reuse)
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot
    assert pool.release_dirty == [True]

    # Input gone
    staged_input = tmp_path / "jobs" / job.job_id / "input" / Path(job.filename).name
    assert not staged_input.exists()
    slot_input = slot.input_dir / Path(job.filename).name
    assert not slot_input.exists()


# ===========================================================================
# Test 4: pool.claim returns None → cold fallback, NOT failed
# ===========================================================================


def test_4_cold_fallback_when_no_slot(tmp_path):
    """pool.claim returns None → cold path runs (subprocess_runner called),
    job is processed, NOT failed (with valid cold output → DONE).
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    # Pool returns None → cold fallback
    pool = FakeWarmPool(None)

    cold_launched: list[list[str]] = []
    output_dir = tmp_path / "jobs" / job.job_id / "output"

    def cold_runner(argv, **kw):
        cold_launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher_with_pool(
        store,
        job_root=tmp_path / "jobs",
        pool=pool,
        subprocess_runner=cold_runner,
        worker_timeout_s=10,
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE

    # Cold subprocess was called
    assert any(a[:2] == ["docker", "run"] for a in cold_launched), (
        f"expected docker run in cold fallback; calls: {cold_launched}"
    )

    # Pool.release was NOT called (no slot was claimed)
    assert len(pool.release_calls) == 0


def test_warm_only_requeues_on_miss_instead_of_cold(tmp_path):
    """warm_only=True + pool.claim returns None → the job is REQUEUED (back to QUEUED,
    claim_id cleared, started_at reset), the cold path is NOT run, and the staged input
    is NOT deleted (the next owner needs it). This is the socket-less warm-only sidecar
    behavior: a warm-pool miss must hand the job to the cold dispatcher, never fail closed.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)
    input_path = tmp_path / "jobs" / job.job_id / "input" / job.filename
    assert input_path.exists()

    pool = FakeWarmPool(None)  # always misses

    cold_launched: list[list[str]] = []

    def cold_runner(argv, **kw):
        cold_launched.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher_with_pool(
        store,
        job_root=tmp_path / "jobs",
        pool=pool,
        subprocess_runner=cold_runner,
        worker_timeout_s=10,
        warm_only=True,
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    # Requeued, not failed, not done — claim released for the cold dispatcher.
    assert final_job.status == JobStatus.QUEUED
    assert final_job.claim_id is None
    assert final_job.started_at is None
    # The cold path (docker run) was NEVER invoked on this socket-less sidecar.
    assert not any(a[:2] == ["docker", "run"] for a in cold_launched), (
        f"warm_only must NOT cold-fall-back; calls: {cold_launched}"
    )
    # Input preserved for the next owner.
    assert input_path.exists()
    assert len(pool.release_calls) == 0


def test_warm_only_requeue_backs_off_before_returning(tmp_path, monkeypatch):
    """A warm-only requeue sleeps warm_requeue_backoff_s before returning, so this dispatcher
    doesn't immediately re-claim the just-requeued job (dispatch_once reports progress, so
    run_forever skips its poll sleep). Without it, the cold dispatcher gets starved."""
    import blastbox.host.dispatch as dispatch_mod

    slept: list[float] = []
    monkeypatch.setattr(dispatch_mod.time, "sleep", lambda s: slept.append(s))

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    d = Dispatcher(
        job_store=store,
        engines={_ENGINE_NAME: _engine_spec()},
        limits=_limits(),
        job_root=tmp_path / "jobs",
        runtime_selector=_fake_runtime,
        pool=FakeWarmPool(None),  # always misses
        warm_only=True,
        warm_requeue_backoff_s=0.75,
    )
    d.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.QUEUED
    assert 0.75 in slept, f"expected a 0.75s requeue backoff; slept={slept}"


# ===========================================================================
# Test 5: Slot released on EVERY path (happy, trust-fail, timeout)
# ===========================================================================


def test_5_slot_released_on_every_path(tmp_path):
    """Slot is released exactly once on: happy path, trust failure, warm timeout."""

    # --- happy path ---
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs_happy", job)
    slot_happy = _make_slot(tmp_path / "slot_happy")
    pool_happy = FakeWarmPool(slot_happy)
    _start_fake_worker(
        slot_happy,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )
    d = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs_happy", pool=pool_happy, worker_timeout_s=10)
    d.dispatch_once()
    assert len(pool_happy.release_calls) == 1, "happy: release must be called exactly once"

    # --- trust failure ---
    store2 = InMemoryJobStore()
    job2 = _make_job()
    job2.input_sha256 = _INPUT_SHA
    store2.create(job2)
    _setup_job_dirs(tmp_path / "jobs_trust", job2)
    slot_trust = _make_slot(tmp_path / "slot_trust")
    pool_trust = FakeWarmPool(slot_trust)

    def _bad(output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "metadata.json").write_bytes(b'{"bad": true}')

    _start_fake_worker(slot_trust, output_fn=_bad)
    d2 = _make_dispatcher_with_pool(store2, job_root=tmp_path / "jobs_trust", pool=pool_trust, worker_timeout_s=10)
    d2.dispatch_once()
    assert len(pool_trust.release_calls) == 1, "trust-fail: release must be called exactly once"

    # --- warm timeout ---
    store3 = InMemoryJobStore()
    job3 = _make_job()
    job3.input_sha256 = _INPUT_SHA
    store3.create(job3)
    _setup_job_dirs(tmp_path / "jobs_timeout", job3)
    slot_timeout = _make_slot(tmp_path / "slot_timeout")
    pool_timeout = FakeWarmPool(slot_timeout)
    d3 = _make_dispatcher_with_pool(store3, job_root=tmp_path / "jobs_timeout", pool=pool_timeout, worker_timeout_s=1)
    d3.dispatch_once()
    assert len(pool_timeout.release_calls) == 1, "timeout: release must be called exactly once"


# ===========================================================================
# Test 6: Image/runtime never job-derived in warm mode
# ===========================================================================


def test_6_image_never_job_derived_in_warm_mode(tmp_path):
    """In warm mode the pool owns the slot (pre-spawned with engine image).
    A malicious job.engine or job.filename cannot change which slot/engine runs.
    The dispatcher must NOT pass job.engine/filename/params to the slot selection.
    """
    store = InMemoryJobStore()
    # Malicious job: engine field doesn't exist, filename looks like an image
    malicious_filename = "evil.io/pwned:latest"
    job = _make_job(engine=_ENGINE_NAME, filename=malicious_filename)
    job.input_sha256 = _INPUT_SHA
    job.params = {"IMAGE": "evil.io/injected:latest"}
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    cold_called: list[list[str]] = []

    def cold_runner(argv, **kw):
        cold_called.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher_with_pool(
        store,
        job_root=tmp_path / "jobs",
        pool=pool,
        subprocess_runner=cold_runner,
        worker_timeout_s=10,
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE

    # The warm path must have been taken (subprocess not called for docker run)
    docker_runs = [a for a in cold_called if len(a) >= 2 and a[:2] == ["docker", "run"]]
    assert docker_runs == [], (
        "warm path taken → no cold docker run should be launched; "
        f"got: {docker_runs}"
    )

    # Pool release was called (confirming warm path was used)
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot


# ===========================================================================
# Warm-output materialize trust gate (symlink overwrite + live-dir swap/grow)
# ===========================================================================


def _det() -> Detection:
    return Detection(label="docx", mime="x", confidence=1.0, source="magika")


def _seal_over(src_dir: Path, *, content: bytes, path: str = "page-001.png"):
    """Seal an envelope over a freshly-written src artifact (sha/bytes from its current content)."""
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / path).write_bytes(content)
    return seal_envelope(
        engine=_ENGINE_NAME,
        outdir=src_dir,
        input_sha256=_INPUT_SHA,
        detected=_det(),
        declared=[DeclaredArtifact(id="page-001", path=path, kind="image")],
        warnings=[],
        payload=ExtractedText(text="x", char_count=1),
    )


def test_materialize_defeats_destination_symlink(tmp_path):
    """The trust-boundary MED: a cold attempt of this job can plant a symlink in the REUSED
    job_root/<id>/output dir; a requeue→warm materialize must NOT follow it to overwrite a host
    file. The sealed artifact lands as a real confined file; the outside target is untouched."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs")
    src = tmp_path / "slot_out"
    env = _seal_over(src, content=b"REAL-PNG-BYTES")

    dst = tmp_path / "job_out"
    dst.mkdir()
    outside = tmp_path / "victim"
    outside.write_bytes(b"ORIGINAL")
    (dst / "page-001.png").symlink_to(outside)  # cold-worker-planted symlink in the reused dir

    disp._materialize_sealed_warm_output(env, src, dst)

    assert outside.read_bytes() == b"ORIGINAL"  # host file NOT overwritten
    assert not (dst / "page-001.png").is_symlink()
    assert (dst / "page-001.png").read_bytes() == b"REAL-PNG-BYTES"
    assert (dst / "metadata.json").exists()


def test_materialize_detects_content_swap(tmp_path):
    """A still-live worker swapping the artifact's content (same length) after sealing must fail
    the re-hash and publish nothing."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs")
    src = tmp_path / "slot_out"
    env = _seal_over(src, content=b"ORIGINAL-X")  # 10 bytes
    (src / "page-001.png").write_bytes(b"SWAPPED-YZ")  # 10 bytes, different content -> sha mismatch

    dst = tmp_path / "job_out"
    with pytest.raises(OutputTrustError):
        disp._materialize_sealed_warm_output(env, src, dst)
    assert not (dst / "page-001.png").exists()  # nothing published on a swap


def test_materialize_rejects_oversize_growth(tmp_path):
    """A worker growing the artifact past its sealed size during the copy is capped + fails."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs")
    src = tmp_path / "slot_out"
    env = _seal_over(src, content=b"SMALL")  # sealed bytes = 5
    (src / "page-001.png").write_bytes(b"SMALL" + b"X" * 4096)  # grew past

    dst = tmp_path / "job_out"
    with pytest.raises(OutputTrustError):
        disp._materialize_sealed_warm_output(env, src, dst)
    assert not (dst / "page-001.png").exists()


def test_requeue_recovers_only_stale_warm_jobs(tmp_path, monkeypatch):
    """Warm jobs have no docker label, so they're recovered on TIME and FAILED (terminal) — NOT
    requeued (a second worker would re-detonate the same untrusted input). A warm job still
    RUNNING past worker_timeout_s + grace (owner gone) is failed; a younger one (possibly live)
    is left alone. Cold jobs requeue via the docker-ps + grace path."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs", worker_timeout_s=30)
    monkeypatch.setattr(disp, "_list_active_worker_job_ids", lambda: set())  # docker ps: none active
    now = time.time()

    # Young warm job (within worker_timeout_s=30 + grace): could be live -> left alone.
    live_warm = Job.new(engine=_ENGINE_NAME, filename="live.docx")
    live_warm.status = JobStatus.RUNNING
    live_warm.worker_runtime = "warm"
    live_warm.started_at = now - 5
    store.create(live_warm)

    # Stale warm job (past worker_timeout_s + grace, ~90s): owner gone -> FAILED (not requeued).
    stale_warm = Job.new(engine=_ENGINE_NAME, filename="stale.docx")
    stale_warm.status = JobStatus.RUNNING
    stale_warm.worker_runtime = "warm"
    stale_warm.started_at = now - 600
    store.create(stale_warm)

    # Cold orphan -> requeued via the docker-ps path.
    cold = Job.new(engine=_ENGINE_NAME, filename="cold.docx")
    cold.status = JobStatus.RUNNING
    cold.worker_runtime = "runsc"
    cold.started_at = now - 600
    store.create(cold)

    recovered = disp.requeue_orphaned_jobs()

    assert recovered == 2  # stale warm (failed) + cold (requeued)
    assert store.get(live_warm.job_id).status == JobStatus.RUNNING  # live warm protected
    failed = store.get(stale_warm.job_id)
    assert failed.status == JobStatus.FAILED  # crashed-owner warm -> terminal, never re-detonated
    assert "recovered: warm worker owner gone" in failed.security_warnings
    assert store.get(cold.job_id).status == JobStatus.QUEUED


def test_requeue_warm_recovery_runs_when_docker_probe_fails(tmp_path, monkeypatch):
    """Warm recovery is TIME-based and must NOT be gated by the docker probe — a docker ps
    failure (returns None) still recovers a stale warm job, while cold requeue is skipped."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs", worker_timeout_s=30)
    monkeypatch.setattr(disp, "_list_active_worker_job_ids", lambda: None)  # docker ps FAILED
    now = time.time()

    stale_warm = Job.new(engine=_ENGINE_NAME, filename="warm.docx")
    stale_warm.status = JobStatus.RUNNING
    stale_warm.worker_runtime = "warm"
    stale_warm.started_at = now - 600
    store.create(stale_warm)

    cold = Job.new(engine=_ENGINE_NAME, filename="cold.docx")
    cold.status = JobStatus.RUNNING
    cold.worker_runtime = "runsc"
    cold.started_at = now - 600
    store.create(cold)

    recovered = disp.requeue_orphaned_jobs()
    assert recovered == 1  # warm recovered despite the docker-probe failure
    assert store.get(stale_warm.job_id).status == JobStatus.FAILED
    assert store.get(cold.job_id).status == JobStatus.RUNNING  # cold requeue skipped (docker down)


def test_warm_recovery_deletes_stale_input(tmp_path, monkeypatch):
    """A recovered (owner-gone) warm job's staged input is deleted by the sweep — the gone owner
    won't clean up, so without this the untrusted input would leak when retention is disabled."""
    store = InMemoryJobStore()
    disp = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs", worker_timeout_s=30)
    monkeypatch.setattr(disp, "_list_active_worker_job_ids", lambda: set())

    job = Job.new(engine=_ENGINE_NAME, filename="stale.docx")
    job.status = JobStatus.RUNNING
    job.worker_runtime = "warm"
    job.started_at = time.time() - 600
    store.create(job)
    input_path = _setup_job_dirs(tmp_path / "jobs", job)
    assert input_path.exists()

    assert disp.requeue_orphaned_jobs() == 1
    assert store.get(job.job_id).status == JobStatus.FAILED
    assert not input_path.exists()  # recovered job's input cleaned up by the sweep


# ---------------------------------------------------------------------------
# Warm-pool SIDECAR mode (warm_only): claim-gate + requeue-on-miss + no cold
# ---------------------------------------------------------------------------


class _CapPool:
    """Minimal WarmPool double exposing idle_count + claim() for sidecar tests."""

    def __init__(self, *, idle: int, slot: Slot | None = None) -> None:
        self._idle = idle
        self._slot = slot

    @property
    def idle_count(self) -> int:  # MUST mirror WarmPool.idle_count (a @property, not a method)
        return self._idle

    def claim(self, *, timeout_s: float) -> Slot | None:  # noqa: ARG002
        return self._slot


def test_warm_only_requires_pool(tmp_path):
    with pytest.raises(ValueError):
        Dispatcher(
            job_store=InMemoryJobStore(), engines={}, limits=_limits(),
            job_root=tmp_path, pool=None, warm_only=True,
        )


def test_warm_only_claim_gate_leaves_job_queued_when_no_idle(tmp_path):
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    d = Dispatcher(
        job_store=store, engines={}, limits=_limits(), job_root=tmp_path,
        pool=_CapPool(idle=0), warm_only=True,
    )
    assert d.dispatch_once() is False  # gated: no free warm slot, nothing claimed
    assert store.get(job.job_id).status == JobStatus.QUEUED


def test_warm_only_requeues_on_slot_miss(tmp_path):
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    # Gate passes (idle=1) but the slot dies -> claim() returns None -> requeue, never cold.
    d = Dispatcher(
        job_store=store, engines={}, limits=_limits(), job_root=tmp_path,
        pool=_CapPool(idle=1, slot=None), warm_only=True,
    )
    assert d.dispatch_once() is True  # a job was claimed
    final = store.get(job.job_id)
    assert final.status == JobStatus.QUEUED  # requeued for the cold dispatcher / another sidecar
    assert final.claim_id is None


def test_warm_slot_reservation_counter_caps_at_idle(tmp_path):
    # issue #72: the atomic gate reservation admits at most idle_count concurrent claims.
    d = Dispatcher(job_store=InMemoryJobStore(), engines={}, limits=_limits(),
                   job_root=tmp_path, pool=_CapPool(idle=2), warm_only=True)
    assert d._reserve_warm_slot() is True     # 1 of 2 idle
    assert d._reserve_warm_slot() is True     # 2 of 2 idle
    assert d._reserve_warm_slot() is False    # idle exhausted by reservations → GATED
    d._release_warm_reservation()
    assert d._reserve_warm_slot() is True      # freed → capacity available again


def test_warm_only_gate_blocks_second_claim_while_slot_in_flight(tmp_path):
    # issue #72 (the race): with ONE idle slot, a second concurrent dispatch_once() must be
    # GATED while the first is still resolving its slot — never claim-then-requeue-churn.
    import threading as _t

    store = InMemoryJobStore()
    store.create(_make_job())
    store.create(_make_job())

    in_claim = _t.Event()
    release = _t.Event()

    class _BlockingPool(_CapPool):
        def claim(self, *, timeout_s):        # noqa: ARG002
            in_claim.set()                     # thread A is now INSIDE claim(), holding its reservation
            release.wait(5)
            return self._slot                  # slot=None → A requeues its job (irrelevant to the gate)

    d = Dispatcher(job_store=store, engines={}, limits=_limits(), job_root=tmp_path,
                   pool=_BlockingPool(idle=1, slot=None), warm_only=True)

    a = _t.Thread(target=d.dispatch_once, daemon=True)
    a.start()
    assert in_claim.wait(5)                    # A reserved the 1 idle slot and is in claim()

    # The single idle slot is reserved by A → a second dispatch must NOT claim (was over-claim pre-#72)
    assert d.dispatch_once() is False          # GATED: returns immediately, nothing claimed

    release.set()
    a.join(5)
    # No job was lost or double-claimed: A's slot came back None so its job requeued, and the
    # second job was never claimed — both are back QUEUED, ready for a freed slot.
    assert len(store.list(status=JobStatus.QUEUED)) == 2


def test_warm_reservation_released_if_predispatch_raises(tmp_path):
    # issue #72 regression (found by adversarial review): dispatch_once() hands off sole ownership
    # of releasing the gate reservation to _dispatch_claimed_job, whose release lives in the
    # try/finally around the slot claim. But the pre-claim path construction (Path(job.filename))
    # runs BEFORE that try — an exception there must NOT leak the reservation, else the warm gate
    # under-admits forever and the sidecar re-wedges.
    d = Dispatcher(job_store=InMemoryJobStore(), engines={}, limits=_limits(),
                   job_root=tmp_path, pool=_CapPool(idle=1, slot=object()), warm_only=True)
    d._warm_slot_reservations = 1            # simulate: dispatch_once reserved before claiming
    bad = _make_job()
    bad.filename = None                      # Path(None) raises TypeError in the pre-claim window
    with pytest.raises(TypeError):
        d._dispatch_claimed_job(bad, warm_reserved=True)
    assert d._warm_slot_reservations == 0    # released despite the exception (RED before the fix)


def test_a_blob_fetch_failure_is_not_blamed_on_the_warm_slot(tmp_path):
    """A blob-store outage must not march every node into a base rebuild.

    _materialise_sample returning False means THIS HOST could not fetch the sample and the claim
    went back to QUEUED -- nothing was ever handed to the slot. Blaming it is worse than any of
    the claim races: an outage hits every job at once, so each slot is evicted after
    max_consecutive_failures jobs and the pool-wide streak invalidates a perfectly healthy base
    during an incident that had nothing to do with the workers.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )
    # The host cannot materialise the sample (blob store unreachable).
    dispatcher._materialise_sample = lambda job, path: False  # type: ignore[method-assign]

    dispatcher.dispatch_once()

    assert pool.release_calls == [slot]
    assert pool.release_fault == ["unknown"], (
        f"a blob-store failure is host connectivity, not worker evidence (got {pool.release_fault})"
    )


def test_an_upload_failure_is_not_blamed_on_the_worker(tmp_path):
    """The exit NOBODY enumerated — which is the point of the inverted default.

    This worker ran, produced valid output, and passed trust validation; the result upload then
    failed against the host's blob store. There is no explicit acquittal at this exit: it is
    protected only by warm_fault defaulting to "unknown". That is exactly the property worth
    pinning — six review rounds each found another exit that had been left blaming the worker,
    because enumerating the innocents fails open. If the default is ever flipped back, this test
    is what notices.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )
    # The blob store rejects the upload; the worker did nothing wrong.
    dispatcher._upload_output = lambda job, output_dir: False  # type: ignore[method-assign]

    dispatcher.dispatch_once()

    assert pool.release_calls == [slot]
    assert pool.release_fault == ["unknown"], (
        f"a host-side upload failure is not worker evidence (got {pool.release_fault})"
    )


# ---------------------------------------------------------------------------
# Convictions. The inverted default (unattributed unless proven) is only safe if the
# positive-evidence sites still FIRE — otherwise wedge detection silently dies, which is the
# bug the attribution was built for. One test per conviction site; each was found unguarded by
# mutation testing after the inversion.
# ---------------------------------------------------------------------------


def _warm_case(tmp_path, store=None, **kw):
    """Shared setup: a job, a slot, a recording pool and a dispatcher over them."""
    store = store or InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)
    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, **kw
    )
    return store, job, slot, pool, dispatcher


def test_a_staging_failure_is_unattributed_unless_the_runtime_opts_in(tmp_path):
    """Staging is NOT worker evidence by default, and today never is.

    No runtime's stage_warm_input actually talks to the worker: FC returns the host path
    unchanged (bytes move later, at signal_go) and gVisor does a host-side shutil.copyfile into a
    bind mount. An earlier version convicted this branch outright on the premise that the hook
    meant vsock, so a full dispatcher disk would have burned out the entire healthy gVisor pool.
    A runtime must opt in via warm_staging_is_transport.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    def _boom(s, src):
        raise RuntimeError("cannot stage into the slot")

    runtime.stage_warm_input = _boom  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    with contextlib.suppress(RuntimeError):
        dispatcher.dispatch_once()

    assert pool.release_calls == [slot], "the slot must still be released on this path"
    assert pool.release_fault == ["unknown"], (
        f"host-side staging is not worker evidence by default (got {pool.release_fault})"
    )

    # ...and a runtime that genuinely transports at staging CAN opt in.
    runtime.warm_staging_is_transport = True  # type: ignore[attr-defined]
    store2 = InMemoryJobStore()
    job2 = _make_job()
    job2.input_sha256 = _INPUT_SHA
    store2.create(job2)
    _setup_job_dirs(tmp_path / "jobs2", job2)
    slot2 = _make_slot(tmp_path / "s2")
    pool2 = FakeWarmPool(slot2, runtime=runtime)
    d2 = _make_dispatcher_with_pool(
        store2, job_root=tmp_path / "jobs2", pool=pool2, worker_timeout_s=10,
    )
    with contextlib.suppress(RuntimeError):
        d2.dispatch_once()
    assert pool2.release_fault == ["worker"], (
        f"an opted-in transport failure IS worker evidence (got {pool2.release_fault})"
    )


def test_a_timeout_convicts_the_worker(tmp_path):
    """It never answered within its deadline."""
    _, _, slot, pool, dispatcher = _warm_case(tmp_path, worker_timeout_s=0.5)
    # no fake worker started -> the done signal never arrives
    dispatcher.dispatch_once()

    assert pool.release_dirty == [True]
    assert pool.release_fault == ["worker"], (
        f"a worker that never answered IS worker evidence (got {pool.release_fault})"
    )


def test_unreadable_output_convicts_the_worker(tmp_path):
    """Its output could not be read back (rdump failed) -- the guest/seam is bad."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    def _boom(s):
        raise RuntimeError("rdump failed: cannot read the slot's output disk")

    runtime.materialize_warm_output = _boom  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED, "the materialize failure must be reached"
    assert pool.release_fault == ["worker"], (
        f"output that cannot be read back IS worker evidence (got {pool.release_fault})"
    )


def test_trust_validation_failure_convicts_the_worker(tmp_path):
    """It produced output that failed trust validation."""
    _, _, slot, pool, dispatcher = _warm_case(tmp_path, worker_timeout_s=10)

    def _bad_output(output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "..evil").write_text("traversal artifact")
        (output_dir / "done").write_text("1")

    _start_fake_worker(slot, output_fn=_bad_output)
    dispatcher.dispatch_once()

    assert pool.release_dirty == [True]
    assert pool.release_fault == ["worker"], (
        f"untrustworthy output IS worker evidence (got {pool.release_fault})"
    )


def test_a_signal_failure_is_unattributed_unless_signalling_is_a_transport(tmp_path):
    """Signalling is not automatically worker evidence.

    FC's control writes over vsock, so a failure there IS about the worker. The FILE handshake
    used by gVisor is a host-side atomic_write_confined() into the bind-mounted ctrl dir, where
    ENOSPC/EROFS is a dispatcher-disk failure that would burn out the whole healthy pool. The
    control object declares which it is.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    class _DeafControl(_RecordingVsockControl):
        def signal_go(self, spec, *, deadline=None):
            raise RuntimeError("vsock write failed: worker not listening")

    runtime.host_warm_control = lambda s: _DeafControl(s)  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED, "the signal failure must be reached"
    assert pool.release_fault == ["unknown"], (
        f"a host-side control write is not worker evidence (got {pool.release_fault})"
    )

    # ...and a control that genuinely transports DOES convict.
    class _DeafTransport(_DeafControl):
        signal_is_transport = True

    runtime.host_warm_control = lambda s: _DeafTransport(s)  # type: ignore[assignment]
    store2 = InMemoryJobStore()
    job2 = _make_job()
    job2.input_sha256 = _INPUT_SHA
    store2.create(job2)
    _setup_job_dirs(tmp_path / "jobs2", job2)
    slot2 = _make_slot(tmp_path / "s2")
    pool2 = FakeWarmPool(slot2, runtime=runtime)
    d2 = _make_dispatcher_with_pool(
        store2, job_root=tmp_path / "jobs2", pool=pool2, worker_timeout_s=10,
    )
    d2.dispatch_once()
    assert pool2.release_fault == ["worker"], (
        f"a failed vsock signal IS worker evidence (got {pool2.release_fault})"
    )


def test_a_file_ipc_staging_failure_is_NOT_blamed_on_the_worker(tmp_path, monkeypatch):
    """The two staging branches are NOT symmetric, and that is the point.

    The vsock branch writes THROUGH the worker's transport, so a failure there is evidence about
    the worker. This branch is a local shutil.copy2 on the dispatcher host: ENOSPC, EROFS or a
    dying disk says nothing about a worker that has not been contacted yet — and a host-wide
    filesystem outage hits every job at once, so convicting here burns the entire warm set and
    invalidates a healthy base during an incident the workers had no part in.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)          # no runtime seam -> the copy2 file path
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    def _boom(src, dst, **kw):
        raise OSError("ENOSPC writing into the slot")

    monkeypatch.setattr("blastbox.host.dispatch.shutil.copy2", _boom)

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED
    assert pool.release_fault == ["unknown"], (
        f"a host-side copy failure is not worker evidence (got {pool.release_fault})"
    )


def test_oversize_output_convicts_the_worker(tmp_path):
    """It emitted more than the declared bound — undeclared bytes are the worker's doing."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)

    def _fat_output(output_dir: Path) -> None:
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        (output_dir / "undeclared.bin").write_bytes(b"x" * 8192)

    _start_fake_worker(slot, output_fn=_fat_output)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )
    # The cap lives on Limits, not on the dispatcher; shrink it so a small fake output trips it.
    dispatcher._limits = replace(dispatcher._limits, max_total_artifact_bytes=1024)

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED, "the size cap must be reached"
    assert pool.release_fault == ["worker"], (
        f"output beyond the declared bound IS worker evidence (got {pool.release_fault})"
    )


def test_a_deadline_consumed_before_waiting_convicts_the_worker(tmp_path):
    """The OTHER timeout branch: the budget is gone before we ever wait.

    Two timeout sites share one message — `remaining <= 0` (signalling consumed the whole
    deadline) and the real wait timeout. A mutant removing the first survived while the second
    stayed covered, so a slot that burned its entire budget in signal_go went unattributed.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    class _SlowControl(_RecordingVsockControl):
        def signal_go(self, spec, *, deadline=None):
            # Must exceed the WHOLE deadline. worker_timeout_s is coerced to int, so 1s is the
            # smallest budget available -- a sub-second sleep silently leaves time on the clock
            # and the job completes, testing nothing.
            time.sleep(1.25)

    runtime.host_warm_control = lambda s: _SlowControl(s)  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=1,
    )

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED
    assert pool.release_fault == ["worker"], (
        f"a slot that consumed its whole deadline IS worker evidence (got {pool.release_fault})"
    )


def test_a_trust_check_the_host_could_not_complete_is_not_worker_evidence(tmp_path):
    """OutputTrustError means two different things and only one is a verdict.

    validate_worker_output() wraps a host-side OSError (EMFILE, EIO, ENOMEM opening or hashing
    metadata.json) in the same exception as a genuine trust violation. Convicting on both means a
    host I/O outage — which hits every job at once — burns out the whole warm set and rebuilds
    healthy snapshot bases, even though no worker produced anything proven invalid.
    """
    from blastbox.errors import OutputTrustUnknown

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    def _cannot_check(*a, **kw):
        raise OutputTrustUnknown("EMFILE opening metadata.json")

    # Patch the symbol the dispatcher actually calls. A previous version patched a method that
    # does not exist, so the job simply succeeded and the assertion measured nothing.
    monkey = pytest.MonkeyPatch()
    monkey.setattr("blastbox.host.dispatch.validate_worker_output", _cannot_check)
    try:
        dispatcher.dispatch_once()
    finally:
        monkey.undo()

    assert store.get(job.job_id).status == JobStatus.FAILED, "the trust path must be reached"
    assert pool.release_fault == ["unknown"], (
        f"a check the HOST could not complete is not worker evidence (got {pool.release_fault})"
    )


def test_a_host_disk_failure_reading_output_is_not_worker_evidence(tmp_path):
    """materialize_warm_output ends in a host-side rdump extraction into slot.output_dir.

    An ENOSPC/EROFS there is a DISPATCHER-disk outage — which hits every job at once — and the
    guest's output disk may be perfectly valid. Only a guest/seam failure is worker evidence, and
    the sibling test above covers that direction.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)

    slot = _make_slot(tmp_path)
    runtime = _FakeVsockRuntime()

    def _enospc(s):
        raise OSError(28, "No space left on device")

    runtime.materialize_warm_output = _enospc  # type: ignore[assignment]
    pool = FakeWarmPool(slot, runtime=runtime)
    dispatcher = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10,
    )

    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED
    assert pool.release_fault == ["unknown"], (
        f"a full dispatcher disk is not worker evidence (got {pool.release_fault})"
    )
