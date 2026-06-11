"""TDD tests for the dispatcher warm path + HostWarmControl.

7 tests per the plan at docs/plans/2026-05-31-dispatch-warm.md.

Fixtures:
- FakeWarmPool: returns a pre-built Slot; records release() calls.
- _fake_worker_thread: when it sees go.json appear in the slot's control_dir,
  writes valid output + done file (mirrors the cold-path test style).
- All tests use tmp_path so nothing touches the real filesystem.
"""
from __future__ import annotations

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
        # Default: a file-based warm runtime that deliberately lacks the vsock
        # warm-path seam (stage_warm_input / host_warm_control /
        # materialize_warm_output), so the dispatcher falls back to the
        # go.json/done + slot-dir path these tests simulate with _start_fake_worker.
        self._runtime = runtime if runtime is not None else object()

    @property
    def runtime(self) -> object:
        return self._runtime

    def claim(self, *, timeout_s: float) -> Slot | None:
        return self._slot

    def release(self, slot: Slot) -> None:
        self.release_calls.append(slot)


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
        warm_claim_timeout_s=warm_claim_timeout_s,
        warm_only=warm_only,
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

    # pool.release must have been called exactly once with our slot
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot

    # staged input must be gone (job_root/job_id/input/<filename>)
    staged_input = tmp_path / "jobs" / job.job_id / "input" / Path(job.filename).name
    assert not staged_input.exists()

    # slot input dir copy must be gone too
    slot_input = slot.input_dir / Path(job.filename).name
    assert not slot_input.exists()


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

    # Slot released exactly once
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot

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

    # Slot released exactly once
    assert len(pool.release_calls) == 1
    assert pool.release_calls[0] is slot

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
