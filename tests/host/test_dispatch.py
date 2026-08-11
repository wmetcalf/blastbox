"""TDD tests for blastbox.host.dispatch.Dispatcher.

11 test cases per the plan at docs/plans/2026-05-31-host-dispatch.md.
"""
from __future__ import annotations

import shutil
import logging
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.docker import InsecureRuntimeRefused, RuntimeSelection
from blastbox.limits import Limits


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_ENGINE_NAME = "test-engine"
_ENGINE_IMAGE = "registry.example.com/test-worker:latest"
_INPUT_SHA = "a" * 64


def _limits() -> Limits:
    return Limits()


def _engine_spec(
    name: str = _ENGINE_NAME,
    image: str = _ENGINE_IMAGE,
    reserved_param_keys: frozenset[str] = frozenset(),
) -> EngineSpec:
    return EngineSpec(
        name=name,
        image=image,
        worker_argv=["worker", "run"],
        reserved_param_keys=reserved_param_keys,
    )


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
    artifact_content: bytes = b"PNG_DATA",
) -> None:
    """Write a valid output directory with one artifact + valid metadata.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    # Write artifact file
    artifact_path = output_dir / "page-001.png"
    artifact_path.write_bytes(artifact_content)
    real_sha = hashlib.sha256(artifact_content).hexdigest()

    # Build a valid envelope using the contract
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


def _make_dispatcher(
    store: InMemoryJobStore,
    *,
    job_root: Path,
    engines: dict | None = None,
    runtime_selector=None,
    subprocess_runner=None,
    worker_timeout_s: int = 30,
    job_retention_seconds: int = 0,
    tier: str = "cold",
    max_queued_age_s: float = 0.0,
    pool=None,
    blob_store=None,
    put_output_max_attempts: int = 3,
    put_output_retry_backoff_s: float = 0.0,
) -> Dispatcher:
    if engines is None:
        engines = {_ENGINE_NAME: _engine_spec()}
    if runtime_selector is None:
        runtime_selector = _fake_runtime
    return Dispatcher(
        job_store=store,
        engines=engines,
        limits=_limits(),
        job_root=job_root,
        runtime_selector=runtime_selector,
        subprocess_runner=subprocess_runner or (lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", "")),
        worker_timeout_s=worker_timeout_s,
        job_retention_seconds=job_retention_seconds,
        pool=pool,
        tier=tier,
        max_queued_age_s=max_queued_age_s,
        blob_store=blob_store,
        put_output_max_attempts=put_output_max_attempts,
        put_output_retry_backoff_s=put_output_retry_backoff_s,
    )


def _setup_job_dirs(job_root: Path, job: Job, *, input_content: bytes = b"malware") -> Path:
    """Create the job directory structure ingress would create; return input_path.

    Uses only the basename of job.filename (same logic the dispatcher uses)
    so malicious filenames containing slashes don't cause mkdir failures.
    """
    job_dir = job_root / job.job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    # Dispatcher uses Path(job.filename).name — use the same here.
    input_path = input_dir / Path(job.filename).name
    input_path.write_bytes(input_content)
    return input_path


# ---------------------------------------------------------------------------
# Test 1: dispatch_once with empty store → returns False
# ---------------------------------------------------------------------------


def test_dispatch_once_empty_store(tmp_path):
    """dispatch_once returns False when no jobs are queued."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher.dispatch_once() is False


# ---------------------------------------------------------------------------
# Test 2: Happy path — valid output dir + exit 0 → DONE, result_summary, input gone
# ---------------------------------------------------------------------------


def test_happy_path_done_result_summary_input_gone(tmp_path):
    """Happy path: queued job + valid output + exit 0 → DONE, result_summary, input deleted."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    invocations: list[list[str]] = []

    def fake_runner(argv, **kw):
        invocations.append(argv)
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    result = dispatcher.dispatch_once()

    assert result is True
    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.DONE
    assert final_job.result_summary is not None
    assert final_job.result_summary["artifact_count"] == 1
    assert "warning_count" in final_job.result_summary
    assert final_job.finished_at is not None
    # Input file and directory must be gone
    assert not input_path.exists()
    assert not input_path.parent.exists()


# ---------------------------------------------------------------------------
# Finding P1: the classic (cold) Dispatcher must upload results to the blob
# store, exactly like VmJobDispatcher — otherwise the API's result routes
# (which read ONLY through BlobStore.open_output) 404 on every completed job
# in the default local deployment.
# ---------------------------------------------------------------------------


def _sealed_metadata(job_root: Path, job) -> dict:
    """Read a job's sealed metadata from the DURABLE copy, not the purged job dir.

    The dispatcher destroys job_root/<id> on every terminal path (issue #84). LocalBlobStore
    deliberately roots durable bytes OUTSIDE job_root (a sibling `blobs/results/<job_id>`)
    precisely so the purge cannot touch them -- see blobs/local.py's header. Reading there is
    also more faithful: it is the copy the API actually serves.
    """
    return json.loads((_blob_root(job_root) / "results" / job.job_id / "metadata.json").read_text())


def _blob_root(job_root: Path) -> Path:
    """Where LocalBlobStore actually put the durable copy.

    Derived from the SAME env the factory reads, not hardcoded: with BLASTBOX_BLOB_LOCAL_ROOT
    set in an operator's environment the store writes elsewhere, and a hardcoded sibling path
    made these tests fail on correct production behaviour (#85 review).
    """
    configured = os.environ.get("BLASTBOX_BLOB_LOCAL_ROOT", "").strip()
    return Path(configured) if configured else job_root.parent / "blobs"


def _durable_artifact(job_root: Path, job, rel: str) -> Path:
    """Path to a sealed artifact in the durable blob copy (see _sealed_metadata)."""
    return _blob_root(job_root) / "results" / job.job_id / rel


class _RecordingBlobs:
    """Minimal BlobStore double that records put_output calls + a snapshot of
    whether metadata.json existed in out_dir at call time (it must -- upload
    happens BEFORE the DONE write, not after)."""

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

class _SnapshotBlobs(_RecordingBlobs):
    """Recording blob store that also COPIES out_dir aside at put_output time.

    Needed because the dispatcher now purges the whole job dir on every terminal path
    (issue #84) -- the durable copy is the blob store, so a test that inspects
    job_root/<id>/output after dispatch is reading a directory production deliberately
    deletes. Upload happens while output/ is still intact, so snapshotting there asserts
    exactly what the blob store received, which is what the API actually serves.
    """

    def __init__(self, snapshot_root: Path, fail_times: int = 0):
        super().__init__(fail_times=fail_times)
        self.snapshot_root = Path(snapshot_root)
        self.snapshot: Path | None = None

    def put_output(self, job_id, out_dir):
        super().put_output(job_id, out_dir)
        dest = self.snapshot_root / f"snap-{job_id}"
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(out_dir, dest)
        self.snapshot = dest


def test_cold_dispatch_uploads_result_to_blob_store_before_done(tmp_path):
    """P1: the cold path's success write must call put_output BEFORE marking DONE,
    with the sealed metadata.json already on disk in the uploaded directory."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    blobs = _RecordingBlobs()
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.uploaded == [job.job_id]
    assert blobs.saw_metadata, "metadata.json must already be sealed when put_output runs"
    final_job = store.get(job.job_id)
    assert final_job.status == JobStatus.DONE
    assert not input_path.exists()


def test_cold_dispatch_upload_failure_fails_job_not_done(tmp_path):
    """Finding D1 applied to the classic Dispatcher: an upload that fails every
    bounded inline attempt must NOT be marked DONE. It takes the normal failure
    path (FAILED, scrubbed error) and the normal input cleanup runs -- exactly
    like every other post-detonation failure in this dispatcher (trust failure,
    output-too-large, etc). There is no "leave it RUNNING" branch here either."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    blobs = _RecordingBlobs(fail_times=999)  # every attempt fails
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs,
        put_output_max_attempts=3,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.calls == 3, "must exhaust the bounded retry budget, not give up early"
    assert blobs.uploaded == []
    final_job = store.get(job.job_id)
    assert final_job.status == JobStatus.FAILED, "must not be marked DONE with an unstored result"
    assert final_job.error is not None
    assert "upload" in final_job.error.lower()
    # Normal cleanup for this dispatcher: the untrusted input is deleted on every
    # terminal path it owns, exactly as on every other failure branch.
    assert not input_path.exists()
    assert not input_path.parent.exists()
    # Finding S1: the exhaustion path must reap any partial result blob -- else, with the
    # default job_retention_seconds=0 (expires_at=None), the retention sweeper skips this
    # FAILED job forever and the partial results/<job_id> blob leaks unbounded.
    assert blobs.deleted == [job.job_id]


def test_cold_dispatch_upload_exhaustion_with_lost_claim_does_not_reap_peer_result(tmp_path):
    """Ultrareview bug_001: the exhaustion reap (Finding S1) must be claim-fenced. The
    pre-upload `_claim_is_still_ours` check runs ONCE, before the retry loop -- the whole
    backoff window sits between it and the reap. If a peer requeues + re-runs + CAS-commits
    DONE during that window (its upload landed at the same results/<job_id> prefix), our
    unconditional `delete_job` would wipe the peer's authoritative result out from under
    the DONE status it wrote: job store says DONE, every result route 404s, forever (the
    retention sweeper never touches it). On a lost claim the blob prefix belongs to the
    peer -- the exhaustion path must NOT reap it."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    class _PeerWinsDuringRetryBlobs(_RecordingBlobs):
        """Every put_output attempt fails; the first failure simulates the peer's full
        requeue -> re-run -> upload -> DONE-CAS landing during our retry/backoff window."""
        def put_output(self, job_id, out_dir):
            first = self.calls == 0
            try:
                super().put_output(job_id, out_dir)
            finally:
                if first:
                    store.update(job_id, status=JobStatus.DONE, claim_id="peer-claim-id-not-ours")

    blobs = _PeerWinsDuringRetryBlobs(fail_times=999)  # every attempt fails
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs,
        put_output_max_attempts=3,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.calls == 3
    assert blobs.deleted == [], "must not reap the peer's authoritative result blob"
    stored = store.get(job.job_id)
    assert stored.status == JobStatus.DONE, "the peer's terminal DONE must survive untouched"
    assert stored.claim_id == "peer-claim-id-not-ours"


def test_cold_dispatch_reclaimed_claim_skips_upload_instead_of_clobbering_peer_result(tmp_path):
    """Round-2 finding R2-1: put_output writes to a deterministic per-job key that is a
    per-file overwrite/union, not a claim-fenced atomic swap. If a peer reclaims this job
    (e.g. an orphan/requeue sweep) in the narrow window between the last local ownership
    check and the upload -- here simulated by flipping claim_id right after
    _write_sealed_metadata runs, mirroring VmJobDispatcher's own
    test_reclaimed_claim_skips_upload_instead_of_clobbering_peer_result -- this worker must
    NOT then upload its (possibly stale) bytes over the peer's already-correct result.
    put_output must never be invoked once ownership is lost, and the job must not be
    marked DONE by this (no-longer-owning) worker."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    blobs = _RecordingBlobs()
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs,
    )

    # Simulate a peer reclaiming the job right after the host seals metadata.json but
    # before the dispatcher re-checks ownership for the upload.
    real_write_sealed_metadata = dispatcher._write_sealed_metadata

    def _write_sealed_metadata_then_peer_reclaims(envelope, out_dir):
        real_write_sealed_metadata(envelope, out_dir)
        store.update(job.job_id, claim_id="peer-claim-id-not-ours")

    dispatcher._write_sealed_metadata = _write_sealed_metadata_then_peer_reclaims  # type: ignore[method-assign]

    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.uploaded == [], "put_output must never be called once ownership is lost"
    stored = store.get(job.job_id)
    assert stored.status == JobStatus.RUNNING, "must not clobber the peer's ownership of this job"
    assert stored.claim_id == "peer-claim-id-not-ours"
    # Input is the new (peer) owner's responsibility now -- not deleted by the reclaimed worker.
    assert input_path.exists()


def test_cold_dispatch_still_owned_uploads_and_marks_done(tmp_path):
    """Sanity companion to the reclaim test above: when ownership is intact throughout,
    the normal upload + DONE path is unaffected by the new recheck."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    blobs = _RecordingBlobs()
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs,
    )
    result = dispatcher.dispatch_once()

    assert result is True
    assert blobs.uploaded == [job.job_id]
    assert store.get(job.job_id).status == JobStatus.DONE


def test_cold_dispatch_serves_host_sealed_metadata(tmp_path):
    """#5: a worker that fabricates artifact sha256/bytes in metadata.json must NOT have those
    served — after DONE the on-disk metadata.json carries the host-recomputed (real) values."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    content = b"REAL-ARTIFACT-BYTES"
    real_sha = hashlib.sha256(content).hexdigest()

    def fake_runner(argv, **kw):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "page-001.png").write_bytes(content)
        env = {
            "engine": _ENGINE_NAME, "status": "ok", "input_sha256": _INPUT_SHA,
            "detected": {"label": "docx", "mime": "x", "confidence": 1.0, "source": "magika"},
            "artifacts": [{"id": "page-001", "path": "page-001.png", "kind": "image",
                           "sha256": "f" * 64, "bytes": 999999}],  # FABRICATED by the worker
            "warnings": [], "payload": {"_type": "extracted_text", "text": "x", "char_count": 1},
        }
        (output_dir / "metadata.json").write_bytes(json.dumps(env).encode())
        return subprocess.CompletedProcess(argv, 0, "", "")

    d = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    served = _sealed_metadata(tmp_path, job)
    assert served["artifacts"][0]["sha256"] == real_sha
    assert served["artifacts"][0]["bytes"] == len(content)


def test_cold_dispatch_injects_mount_dir_env(tmp_path):
    """#8: the worker argv carries BLASTBOX_INPUT_DIR=/input + BLASTBOX_OUTPUT_DIR=/output so the
    harness (defaults /in,/out) reads the dirs the dispatcher actually mounted."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    seen: list[list[str]] = []

    def fake_runner(argv, **kw):
        seen.append(argv)
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner).dispatch_once()
    flat = seen[0]
    assert "BLASTBOX_INPUT_DIR=/input" in flat
    assert "BLASTBOX_OUTPUT_DIR=/output" in flat


def test_cold_output_size_cap_fails_undeclared_bloat(tmp_path):
    """#3: a huge UNDECLARED file (the trust gate never sizes it) must fail the job, not DONE."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)  # one tiny declared artifact
        (output_dir / "pad.bin").write_bytes(b"x" * 200_000)  # huge undeclared file
        return subprocess.CompletedProcess(argv, 0, "", "")

    d = Dispatcher(
        job_store=store, engines={_ENGINE_NAME: _engine_spec()},
        limits=Limits(max_total_artifact_bytes=50_000), job_root=tmp_path,
        runtime_selector=_fake_runtime, subprocess_runner=fake_runner, worker_timeout_s=30,
    )
    assert d.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED
    assert "too large" in (final.error or "")


def test_run_maintenance_expires_and_requeues(tmp_path):
    """#4: _run_maintenance expires retention-due artifacts AND requeues orphaned RUNNING jobs."""
    store = InMemoryJobStore()
    # an expired DONE job with on-disk artifacts
    done = Job.new(engine=_ENGINE_NAME, filename="d.docx")
    done.status = JobStatus.DONE
    done.finished_at = time.time() - 100
    done.expires_at = time.time() - 50
    out = tmp_path / done.job_id / "output"
    out.mkdir(parents=True)
    (out / "art.png").write_bytes(b"data")
    done.result_dir = str(out)
    store.create(done)
    # a RUNNING job whose worker container is gone (mock docker ps returns no active ids)
    running = Job.new(engine=_ENGINE_NAME, filename="r.docx")
    running.status = JobStatus.RUNNING
    store.create(running)

    d = _make_dispatcher(store, job_root=tmp_path, job_retention_seconds=60)
    d._run_maintenance()

    assert store.get(done.job_id).status == JobStatus.EXPIRED
    assert not out.exists()  # artifacts swept
    assert store.get(running.job_id).status == JobStatus.QUEUED  # orphan requeued


class _StubBlobs:
    """Minimal BlobStore double — only delete_job's call is asserted."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...

    def delete_job(self, job_id):
        self.deleted.append(job_id)


def test_run_maintenance_reaps_result_blob_when_blob_store_configured(tmp_path):
    """The dispatch.py retention sweeper must reap the result blob too.

    In a mixed-tier fleet sharing one JobStore (FC-warm nodes driven by this
    file-handshake Dispatcher + AWS Lambda burst driven by the always blob-backed
    VmJobDispatcher/network dispatch_style), a burst job's results are put_output'd to
    S3/blob storage. expire_due lists expired jobs with no node/tier scoping, so THIS
    Dispatcher's maintenance can claim and expire that job. Without blob_store wired
    through to JobRetentionSweeper, expire_due only clears the (harmlessly-absent,
    wrong-host) local dir and clears expires_at — no sweeper ever revisits it and the
    result blob leaks permanently. This proves Dispatcher._run_maintenance now builds
    the sweeper WITH the configured blob store and that delete_job is actually called.
    """
    store = InMemoryJobStore()
    done = Job.new(engine=_ENGINE_NAME, filename="d.docx")
    done.status = JobStatus.DONE
    done.finished_at = time.time() - 100
    done.expires_at = time.time() - 50
    store.create(done)

    blobs = _StubBlobs()
    d = Dispatcher(
        job_store=store,
        engines={_ENGINE_NAME: _engine_spec()},
        limits=_limits(),
        job_root=tmp_path,
        runtime_selector=_fake_runtime,
        job_retention_seconds=60,
        blob_store=blobs,
    )
    d._run_maintenance()

    assert store.get(done.job_id).status == JobStatus.EXPIRED
    assert blobs.deleted == [done.job_id]


# ---------------------------------------------------------------------------
# Test 3: Worker non-zero exit (no valid output) → FAILED, input gone
# ---------------------------------------------------------------------------


def test_nonzero_exit_fails_job_input_gone(tmp_path):
    """Worker exits with non-zero and writes no valid output → job FAILED, input gone."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)

    def fake_runner(argv, **kw):
        # No output written, non-zero exit
        return subprocess.CompletedProcess(argv, 1, "", "worker crashed")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert final_job.error is not None
    assert not input_path.exists()
    assert not input_path.parent.exists()


# ---------------------------------------------------------------------------
# Test 4: TimeoutExpired → docker kill invoked, FAILED("timed out"), input gone
# ---------------------------------------------------------------------------


def test_timeout_kills_container_fails_job_input_gone(tmp_path):
    """TimeoutExpired → docker kill is called, job FAILED with timed-out message, input gone."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    kill_calls: list[list[str]] = []

    def fake_runner(argv, **kw):
        if argv[0] == "docker" and len(argv) > 1 and argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, kw.get("timeout", 30))
        # docker kill call
        kill_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert final_job.error is not None
    assert "timed out" in final_job.error.lower() or "timeout" in final_job.error.lower()
    # docker kill should have been called
    assert any(
        "kill" in argv for argv in kill_calls
    ), f"docker kill not invoked; calls: {kill_calls}"
    assert not input_path.exists()
    assert not input_path.parent.exists()


# ---------------------------------------------------------------------------
# Test 5: Trust fails (traversal artifact) → FAILED, input gone
# ---------------------------------------------------------------------------


def test_trust_failure_fails_job_input_gone(tmp_path):
    """Output with traversal artifact path fails trust validation → FAILED, input gone."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        # Write a metadata.json with a traversal path — trust gate should reject
        output_dir.mkdir(parents=True, exist_ok=True)
        # Write an escape target outside the output dir
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
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert not input_path.exists()
    assert not input_path.parent.exists()


# ---------------------------------------------------------------------------
# Test 6: Unknown engine → FAILED, input gone, no subprocess launched
# ---------------------------------------------------------------------------


def test_unknown_engine_fails_job_no_subprocess_input_gone(tmp_path):
    """DEFAULT (engine scoping OFF): a job with an unknown engine → FAILED fast, no subprocess, input
    gone. The single-dispatcher contract — so an open-allowlist typo can't sit QUEUED forever."""
    store = InMemoryJobStore()
    job = _make_job(engine="no-such-engine")
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    subprocess_calls: list = []

    def fake_runner(argv, **kw):
        subprocess_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert "engine" in (final_job.error or "").lower()
    assert subprocess_calls == [], "subprocess must NOT be launched for unknown engine"
    assert not input_path.exists()
    assert not input_path.parent.exists()


def test_default_claim_keeps_legacy_store_signature(tmp_path):
    # default (scoping OFF): claim_next must be called WITHOUT engine= so a store implementing only
    # the original claim_next(*, claimant_tier=) shape doesn't raise TypeError.
    store = InMemoryJobStore()
    orig = store.claim_next

    def legacy(*, claimant_tier=None):    # NO engine kwarg (pre-engine-scoping protocol)
        return orig(claimant_tier=claimant_tier)

    store.claim_next = legacy  # type: ignore[method-assign]
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher.dispatch_once() is False    # no TypeError; just an empty queue


def test_engine_scoped_dispatcher_leaves_foreign_engine_jobs(tmp_path, monkeypatch):
    """OPT-IN (BLASTBOX_DISPATCHER_ENGINE_SCOPED=1): a job for an engine this dispatcher doesn't
    handle is LEFT UNCLAIMED for its real (e.g. VM) dispatcher — not stolen + failed."""
    monkeypatch.setenv("BLASTBOX_DISPATCHER_ENGINE_SCOPED", "1")
    store = InMemoryJobStore()
    job = _make_job(engine="no-such-engine")          # not in this dispatcher's {test-engine}
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    input_path = _setup_job_dirs(tmp_path, job)

    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher.dispatch_once() is False         # nothing claimable for our engine
    final_job = store.get(job.job_id)
    assert final_job is not None and final_job.status == JobStatus.QUEUED  # left, not failed
    assert input_path.exists()                          # input preserved


# ---------------------------------------------------------------------------
# Test 7: runtime_selector raises InsecureRuntimeRefused → FAILED, input gone
# ---------------------------------------------------------------------------


def test_insecure_runtime_refused_fails_job_input_gone(tmp_path):
    """InsecureRuntimeRefused from runtime_selector → job FAILED, input gone."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)

    def bad_runtime_selector():
        raise InsecureRuntimeRefused("no secure runtime available")

    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, runtime_selector=bad_runtime_selector
    )
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    assert not input_path.exists()
    assert not input_path.parent.exists()


# ---------------------------------------------------------------------------
# Test 8: Image used in argv == engine.image, NEVER any job field
# ---------------------------------------------------------------------------


def test_image_in_argv_is_engine_image_not_job_field(tmp_path):
    """The image in the docker run argv must be engine.image, never derived from job data."""
    store = InMemoryJobStore()
    # Set filename to something that looks like a Docker image name
    malicious_filename = "evil.io/pwned:latest"
    job = _make_job(filename=malicious_filename)
    job.input_sha256 = _INPUT_SHA
    # Also set params to something that looks like an image override
    job.params = {"IMAGE": "evil.io/injected:latest"}
    store.create(job)

    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    # Find the docker run invocation
    docker_run_argv = next(
        (a for a in launched_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None, "docker run not called"

    # The image must be _ENGINE_IMAGE (the last non-worker-argv positional)
    # The image appears just before the worker_argv elements.
    # It must be exactly engine.image — no job field.
    assert _ENGINE_IMAGE in docker_run_argv, f"engine image not in argv: {docker_run_argv}"
    assert malicious_filename not in docker_run_argv, (
        f"job filename appeared as image in argv: {docker_run_argv}"
    )
    assert "evil.io/injected:latest" not in docker_run_argv, (
        f"job params IMAGE appeared in argv position: {docker_run_argv}"
    )


# ---------------------------------------------------------------------------
# Test 9: requeue_orphaned_jobs
# ---------------------------------------------------------------------------


def test_requeue_orphaned_jobs(tmp_path):
    """RUNNING job not in active set → back to QUEUED + warning; active job untouched;
    docker ps failure → no requeue."""
    store = InMemoryJobStore()

    # Create two RUNNING jobs. The orphan's started_at is past the requeue grace window so it
    # is eligible (a fresh start_at would be skipped — see test_requeue_grace_window).
    orphan_job = Job.new(engine=_ENGINE_NAME, filename="a.docx")
    orphan_job.status = JobStatus.RUNNING
    orphan_job.started_at = time.time() - 120
    store.create(orphan_job)

    active_job = Job.new(engine=_ENGINE_NAME, filename="b.docx")
    active_job.status = JobStatus.RUNNING
    active_job.started_at = time.time()
    store.create(active_job)

    ps_calls: list[list[str]] = []

    def fake_runner(argv, **kw):
        ps_calls.append(list(argv))
        # docker ps returns only the active_job's container
        if "ps" in argv:
            return subprocess.CompletedProcess(
                argv, 0, f"blastbox.job_id={active_job.job_id}\n", ""
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)

    count = dispatcher.requeue_orphaned_jobs()
    assert count == 1

    orphan_after = store.get(orphan_job.job_id)
    assert orphan_after is not None
    assert orphan_after.status == JobStatus.QUEUED

    active_after = store.get(active_job.job_id)
    assert active_after is not None
    assert active_after.status == JobStatus.RUNNING  # untouched

    # Now test docker ps failure → no requeue
    store2 = InMemoryJobStore()
    stranded = Job.new(engine=_ENGINE_NAME, filename="c.docx")
    stranded.status = JobStatus.RUNNING
    store2.create(stranded)

    def failing_runner(argv, **kw):
        if "ps" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "error")
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher2 = _make_dispatcher(store2, job_root=tmp_path, subprocess_runner=failing_runner)
    count2 = dispatcher2.requeue_orphaned_jobs()
    assert count2 == 0

    stranded_after = store2.get(stranded.job_id)
    assert stranded_after is not None
    assert stranded_after.status == JobStatus.RUNNING  # NOT requeued


# ---------------------------------------------------------------------------
# Test 10: job.params key filtering — bad key dropped, good key passes
# ---------------------------------------------------------------------------


def test_params_key_filtering_bad_dropped_good_passes(tmp_path):
    """Bad params keys are dropped from extra_env; valid keys pass through."""
    store = InMemoryJobStore()
    job = _make_job(
        params={
            "VALID_KEY": "good_value",
            "x; --privileged": "evil",   # bad key: spaces/semicolons
            "also-bad": "val",            # bad key: hyphens
            "123STARTS_WITH_DIGIT": "val",  # bad key: starts with digit
            "ANOTHER_VALID": "value2",
        }
    )
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    captured_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        captured_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    docker_run_argv = next(
        (a for a in captured_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None

    # Flatten to find -e KEY=VAL tokens
    env_tokens = []
    for i, tok in enumerate(docker_run_argv):
        if tok == "-e" and i + 1 < len(docker_run_argv):
            env_tokens.append(docker_run_argv[i + 1])

    env_keys = [t.split("=", 1)[0] for t in env_tokens]

    # Valid keys must be present
    assert "VALID_KEY" in env_keys
    assert "ANOTHER_VALID" in env_keys

    # Bad keys must NOT appear anywhere in argv — not as separate tokens
    full_argv_str = " ".join(docker_run_argv)
    assert "x; --privileged" not in full_argv_str
    assert "--privileged" not in docker_run_argv, (
        "bad key injection: --privileged appeared as standalone argv element"
    )
    # The bad key itself should not have produced an -e entry
    assert not any("x;" in k for k in env_keys)
    assert not any("also-bad" in k for k in env_keys)
    assert not any("123STARTS" in k for k in env_keys)


def test_params_reserved_keys_dropped(tmp_path):
    """M2: a client must not set reserved env keys via job.params even though they match the key
    SHAPE. The engine-AGNOSTIC floor — BLASTBOX_ENGINE (engine re-selection → arbitrary module
    import), LD_PRELOAD, PYTHONPATH, BLASTBOX_OUTPUT_DIR (I/O rewire) — is dropped unconditionally.
    An ENGINE-declared reserved key (here CLIPPYSHOT_WARM_DIAG_FILE, via EngineSpec.reserved_param_keys)
    is also dropped, without blastbox core naming it; ordinary tunables (CLIPPYSHOT_DPI) pass."""
    store = InMemoryJobStore()
    job = _make_job(
        params={
            "CLIPPYSHOT_DPI": "200",  # legitimate per-job tunable -> passes
            "BLASTBOX_ENGINE": "evil.module:Backdoor",  # reserved: engine re-selection
            "LD_PRELOAD": "/tmp/evil.so",  # reserved: loader hijack
            "PYTHONPATH": "/tmp",  # reserved: interpreter hijack
            "BLASTBOX_OUTPUT_DIR": "/etc",  # reserved: I/O rewire
            "CLIPPYSHOT_WARM_DIAG_FILE": "/tmp/x",  # reserved: breadcrumb path (L5)
        }
    )
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    captured_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        captured_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner,
        engines={_ENGINE_NAME: _engine_spec(
            reserved_param_keys=frozenset({"CLIPPYSHOT_WARM_DIAG_FILE"}),
        )},
    )
    dispatcher.dispatch_once()

    docker_run_argv = next(
        (a for a in captured_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None
    env_keys = {
        docker_run_argv[i + 1].split("=", 1)[0]
        for i, tok in enumerate(docker_run_argv)
        if tok == "-e" and i + 1 < len(docker_run_argv)
    }
    assert "CLIPPYSHOT_DPI" in env_keys  # ordinary tunable survives
    for reserved in ("BLASTBOX_ENGINE", "LD_PRELOAD", "PYTHONPATH", "CLIPPYSHOT_WARM_DIAG_FILE"):
        assert reserved not in env_keys, f"reserved key {reserved} leaked from job.params"
    # The dispatcher still sets BLASTBOX_OUTPUT_DIR itself (merged last) — to /output, never /etc.
    out_dir_vals = [
        docker_run_argv[i + 1].split("=", 1)[1]
        for i, tok in enumerate(docker_run_argv)
        if tok == "-e" and i + 1 < len(docker_run_argv)
        and docker_run_argv[i + 1].startswith("BLASTBOX_OUTPUT_DIR=")
    ]
    assert out_dir_vals == ["/output"], f"client overrode BLASTBOX_OUTPUT_DIR: {out_dir_vals}"


# ---------------------------------------------------------------------------
# Test 11: Error strings on FAILED jobs are scrubbed of filesystem paths
# ---------------------------------------------------------------------------


def test_error_strings_scrubbed_of_filesystem_paths(tmp_path):
    """Error messages stored on FAILED jobs must not contain internal filesystem paths."""
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    _setup_job_dirs(tmp_path, job)

    def fake_runner(argv, **kw):
        # Inject an error that contains an internal path
        return subprocess.CompletedProcess(
            argv, 1, "", f"fatal error at /var/lib/blastbox/jobs/{job.job_id}/input/malware.docx"
        )

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    final_job = store.get(job.job_id)
    assert final_job is not None
    assert final_job.status == JobStatus.FAILED
    error = final_job.error or ""
    # The raw path must not appear in the stored error
    assert "/var/lib/blastbox" not in error, f"Internal path leaked in error: {error!r}"
    assert job.job_id not in error or "/jobs/" not in error, (
        f"Internal path with job_id leaked in error: {error!r}"
    )


def test_run_forever_survives_dispatch_error(tmp_path):
    """A transient error from dispatch_once must not crash the run_forever loop."""
    store = InMemoryJobStore()
    d = _make_dispatcher(store, job_root=tmp_path)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient store error")
        return False  # no work available

    d.dispatch_once = flaky  # type: ignore[method-assign]
    # stop() is checked at the top of each iteration; break once we've gotten
    # past the raising call (proving the loop continued instead of crashing).
    d.run_forever(poll_interval_s=0, stop=lambda: calls["n"] >= 2)
    assert calls["n"] >= 2


def test_requeue_grace_window(tmp_path):
    """A just-claimed RUNNING job (fresh started_at) is NOT requeued — its container may not be
    in docker ps yet; requeuing would double-detonate the same input."""
    store = InMemoryJobStore()
    fresh = Job.new(engine=_ENGINE_NAME, filename="x.docx")
    fresh.status = JobStatus.RUNNING
    fresh.started_at = time.time()  # within the grace window
    store.create(fresh)
    d = _make_dispatcher(
        store, job_root=tmp_path,
        subprocess_runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
    )
    assert d.requeue_orphaned_jobs() == 0
    assert store.get(fresh.job_id).status == JobStatus.RUNNING


def test_cold_enrichment_claim_fenced_aborts_on_reclaim(tmp_path):
    """If a peer requeues+reclaims a cold job while _runtime_selector blocks (e.g. on `docker
    info`), the claim-fenced enrichment write aborts THIS stale owner before it launches a worker,
    does NOT overwrite the new owner's worker_runtime (which would mis-route recovery and cause a
    double-detonation), and leaves the shared input on disk for the new owner."""
    # SqlJobStore (not in-memory) so the dispatcher's claimed Job is a frozen SNAPSHOT — modelling
    # a real multi-dispatcher store. (In-memory is single-process and returns live references, so
    # it can't model a peer reclaim.)
    from blastbox.host.jobs.sql_store import SqlJobStore
    store = SqlJobStore(f"sqlite:///{tmp_path / 'jobs.db'}")
    job = _make_job()
    store.create(job)
    input_path = _setup_job_dirs(tmp_path, job)

    launched: list = []

    def _runner(argv, **kw):
        launched.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def _selector_that_reclaims() -> RuntimeSelection:
        # Simulate a peer dispatcher mid-`docker info`: requeue (clear claim), reclaim under a
        # fresh claim, and mark it warm — exactly the multi-dispatcher reclaim the fence detects.
        cur = store.get(job.job_id)
        store.update_if_status(
            job.job_id, JobStatus.RUNNING, expect_claim_id=cur.claim_id,
            status=JobStatus.QUEUED, claim_id=None,
        )
        new_owner = store.claim_next()
        store.update_if_status(
            job.job_id, JobStatus.RUNNING,
            expect_claim_id=new_owner.claim_id, worker_runtime="warm",
        )
        return RuntimeSelection(runtime="runc", secure=False, warnings=["stale"])

    disp = _make_dispatcher(
        store, job_root=tmp_path,
        runtime_selector=_selector_that_reclaims, subprocess_runner=_runner,
    )
    disp.dispatch_once()

    final = store.get(job.job_id)
    assert launched == []  # the stale owner aborted — no worker launched
    assert final.worker_runtime == "warm"  # the new owner's label is NOT clobbered to "runc"
    assert final.status == JobStatus.RUNNING  # still the new owner's live claim
    assert input_path.exists()  # shared input preserved for the new owner (not deleted on abort)


# ---------------------------------------------------------------------------
# Param-key SHAPE: a purely-lowercase key (valid letters, no symbols) is still
# dropped — keys must be UPPERCASE env-shaped. Regression for the redtusk thumbnail
# trap: `enable_thumbnails` silently never reached the worker; `REDTUSK_ENABLE_*` did.
# (The existing key-filtering test covers symbols/hyphens/digits, not lowercase.)
# ---------------------------------------------------------------------------
def test_sanitize_params_lowercase_dropped_uppercase_forwarded():
    allow = frozenset(
        {"REDTUSK_ENABLE_THUMBNAILS", "REDTUSK_ENABLE_QR", "enable_thumbnails"}
    )
    out = Dispatcher._sanitize_params(
        {
            "enable_thumbnails": "true",          # lowercase → dropped by the shape floor
            "REDTUSK_ENABLE_THUMBNAILS": "true",  # uppercase + allowlisted → forwarded
            "REDTUSK_ENABLE_QR": "false",
            "Redtusk_Mixed": "x",                 # not uppercase-only → dropped
        },
        allow,
    )
    assert out == {"REDTUSK_ENABLE_THUMBNAILS": "true", "REDTUSK_ENABLE_QR": "false"}
    assert "enable_thumbnails" not in out  # the bug: lowercase never forwards


def test_sanitize_params_allowlist_default_deny():
    """A non-empty allowlist is default-deny: an uppercase key NOT in it is dropped."""
    out = Dispatcher._sanitize_params(
        {"REDTUSK_ENABLE_THUMBNAILS": "true", "REDTUSK_SECRET_KNOB": "1"},
        frozenset({"REDTUSK_ENABLE_THUMBNAILS"}),
    )
    assert out == {"REDTUSK_ENABLE_THUMBNAILS": "true"}


def test_dispatcher_passes_its_tier_to_claim_next(tmp_path):
    """The dispatcher claims with its tier identity so per-job target_tier routing works.
    A plain dispatcher (no warm pool) identifies as 'cold'; the CLI passes a warm sidecar's
    backend explicitly (derived + validated next to the pool — kept out of the Dispatcher)."""
    store = InMemoryJobStore()
    seen = {}
    orig = store.claim_next

    def spy(*, claimant_tier=None, engine=None):
        seen["tier"] = claimant_tier
        return orig(claimant_tier=claimant_tier, engine=engine)

    store.claim_next = spy  # type: ignore[method-assign]
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher._tier == "cold"
    dispatcher.dispatch_once()
    assert seen["tier"] == "cold"

    # An explicit tier (as the CLI passes for a warm sidecar) is honored + claimed with.
    seen.clear()
    warm = _make_dispatcher(store, job_root=tmp_path, tier="gvisor")
    assert warm._tier == "gvisor"
    warm.dispatch_once()
    assert seen["tier"] == "gvisor"


def test_stale_queued_jobs_failed_after_max_age(tmp_path):
    """A job stuck QUEUED past max_queued_age_s (e.g. target_tier pinned to a tier with no
    running dispatcher) is FAILed + its input deleted by the maintenance sweep. The default
    (0 = off) is a no-op, and a recent job is left alone."""
    store = InMemoryJobStore()
    old = _make_job(filename="old.docx")
    old.created_at = time.time() - 100  # stale
    store.create(old)
    _setup_job_dirs(tmp_path, old)
    fresh = _make_job(filename="fresh.docx")
    store.create(fresh)
    _setup_job_dirs(tmp_path, fresh)

    # Disabled by default → no-op even for the stale job.
    _make_dispatcher(store, job_root=tmp_path, max_queued_age_s=0)._fail_stale_queued_jobs()
    assert store.get(old.job_id).status == JobStatus.QUEUED

    # Enabled → stale job FAILed (input gone), fresh one untouched.
    d = _make_dispatcher(store, job_root=tmp_path, max_queued_age_s=60)
    assert d._fail_stale_queued_jobs() == 1
    assert store.get(old.job_id).status == JobStatus.FAILED
    assert store.get(fresh.job_id).status == JobStatus.QUEUED
    assert not (tmp_path / old.job_id / "input" / "old.docx").exists()


def test_argv_build_warnings_reach_security_warnings(tmp_path, monkeypatch):
    """Hardening warnings appended while BUILDING the docker argv (e.g. skipped nono under
    runsc, missing AppArmor/seccomp) must land in job.security_warnings. Regression: the
    claim-fenced RUNNING write used to persist warnings BEFORE argv was built, silently
    dropping them so a job looked clean even though a MAC layer was absent."""
    import blastbox.host.dispatch as dispatch_mod

    def _spy_argv(*args, **kwargs):
        # Simulate build_worker_docker_run_argv appending a hardening warning to runtime.
        kwargs["runtime"].warnings.append("argv-time: seccomp profile missing")
        return ["docker", "run", "--rm", kwargs["image"]]

    monkeypatch.setattr(dispatch_mod, "build_worker_docker_run_argv", _spy_argv)

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True

    final_job = store.get(job.job_id)
    # The argv-build-time warning AND the runtime-selection warning are both persisted.
    assert "argv-time: seccomp profile missing" in final_job.security_warnings
    assert "no runsc" in final_job.security_warnings


# ---------------------------------------------------------------------------
# Network personality → argv integration tests (Plan 2)
# ---------------------------------------------------------------------------


def test_netpolicy_direct_engine_puts_bb_net0_in_argv(tmp_path, monkeypatch):
    """An engine with net_policy='direct' (registry declaring it) → argv contains 'bb-net0'."""
    # Declare the 'direct' personality in the env BEFORE constructing the Dispatcher
    # so __init__ picks it up via parse_personalities(os.environ).
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    launched_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    # Build an engine with net_policy="direct" — use EngineSpec directly since _engine_spec
    # doesn't expose that field.
    direct_engine = EngineSpec(
        name=_ENGINE_NAME,
        image=_ENGINE_IMAGE,
        worker_argv=["worker", "run"],
        net_policy="direct",
    )
    dispatcher = _make_dispatcher(
        store,
        job_root=tmp_path,
        engines={_ENGINE_NAME: direct_engine},
        subprocess_runner=fake_runner,
    )
    assert dispatcher.dispatch_once() is True

    docker_run_argv = next(
        (a for a in launched_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None, "docker run not called"
    assert "bb-net0" in docker_run_argv, f"bb-net0 not in argv: {docker_run_argv}"
    assert "--network=none" not in docker_run_argv, (
        f"--network=none should not appear for direct: {docker_run_argv}"
    )


def test_netpolicy_default_none_engine_has_network_none_in_argv(tmp_path, monkeypatch):
    """A default engine (net_policy='none') → argv contains '--network=none', not 'bb-net0'."""
    import os
    # Scrub any BLASTBOX_NETPOLICY_* vars from the ambient env that could bleed in.
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_"):
            monkeypatch.delenv(k, raising=False)

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    launched_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    # Default engine spec has net_policy="none" (the EngineSpec default).
    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True

    docker_run_argv = next(
        (a for a in launched_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None, "docker run not called"
    assert "--network=none" in docker_run_argv, (
        f"--network=none not in argv: {docker_run_argv}"
    )
    assert "bb-net0" not in docker_run_argv, (
        f"bb-net0 should not appear for none: {docker_run_argv}"
    )


def test_netpolicy_direct_with_dns_injects_resolv_conf(tmp_path, monkeypatch):
    """An egress personality declaring dns= → a resolv.conf bind-mount in argv + a real file
    written naming that resolver (closes the gVisor embedded-DNS gap)."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct,dns=1.1.1.1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    launched_argv: list[list[str]] = []
    resolv_seen: dict[str, str] = {}

    def fake_runner(argv, **kw):
        launched_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            # The dispatcher writes the resolv.conf before launching the worker; capture its
            # on-disk content at run time (the job dir is cleaned up after).
            for tok in argv:
                if "dst=/etc/resolv.conf" in tok:
                    src = tok.split("src=", 1)[1].split(",", 1)[0]
                    resolv_seen["content"] = Path(src).read_text()
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    direct_engine = EngineSpec(
        name=_ENGINE_NAME,
        image=_ENGINE_IMAGE,
        worker_argv=["worker", "run"],
        net_policy="direct",
    )
    dispatcher = _make_dispatcher(
        store,
        job_root=tmp_path,
        engines={_ENGINE_NAME: direct_engine},
        subprocess_runner=fake_runner,
    )
    assert dispatcher.dispatch_once() is True

    docker_run_argv = next(
        (a for a in launched_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None, "docker run not called"
    assert any("dst=/etc/resolv.conf,readonly" in tok for tok in docker_run_argv), (
        f"resolv.conf mount missing: {docker_run_argv}"
    )
    assert resolv_seen.get("content") == "nameserver 1.1.1.1\n", (
        f"resolv.conf content wrong: {resolv_seen!r}"
    )


def test_netpolicy_direct_without_dns_no_resolv_conf(tmp_path, monkeypatch):
    """An egress personality with NO dns= leaves docker's resolv.conf untouched (opt-in)."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    launched_argv: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched_argv.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    direct_engine = EngineSpec(
        name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
        net_policy="direct",
    )
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, engines={_ENGINE_NAME: direct_engine},
        subprocess_runner=fake_runner,
    )
    assert dispatcher.dispatch_once() is True

    docker_run_argv = next(
        (a for a in launched_argv if len(a) >= 2 and a[:2] == ["docker", "run"]), None
    )
    assert docker_run_argv is not None
    assert "bb-net0" in docker_run_argv  # egress wired…
    assert not any("dst=/etc/resolv.conf" in tok for tok in docker_run_argv), (
        f"resolv.conf must NOT be injected without dns=: {docker_run_argv}"
    )


def _direct_dispatcher(store, tmp_path, fake_runner):
    direct_engine = EngineSpec(
        name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
        net_policy="direct",
    )
    return _make_dispatcher(
        store, job_root=tmp_path, engines={_ENGINE_NAME: direct_engine},
        subprocess_runner=fake_runner,
    )


def test_capture_label_set_for_egress_when_enabled(tmp_path, monkeypatch):
    """BLASTBOX_NET_CAPTURE=1 + an egress personality → the worker is labeled for netd."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "blastbox.net.capture=1" in argv


def test_capture_label_absent_when_disabled(tmp_path, monkeypatch):
    """Default (no BLASTBOX_NET_CAPTURE) → no capture label even for an egress personality."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.delenv("BLASTBOX_NET_CAPTURE", raising=False)

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert not any("blastbox.net.capture" in t for t in argv)


def test_network_capture_sealed_as_trusted_artifact(tmp_path, monkeypatch):
    """A netd pcap at <job>/capture/dump.pcap is sealed into metadata.json with a host hash."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    pcap_bytes = b"\xd4\xc3\xb2\xa1fake-pcap-capture-bytes"

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            # Simulate netd having written the host-only pcap during the worker's run.
            cap = tmp_path / job.job_id / "capture"
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(pcap_bytes)
            (cap / "dump.pcap.done").write_text("done")  # netd finalized the capture
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True

    sealed = _sealed_metadata(tmp_path, job)
    caps = [a for a in sealed["artifacts"] if a["kind"] == "network_capture"]
    assert len(caps) == 1, f"capture artifact not sealed: {sealed['artifacts']}"
    assert caps[0]["path"] == "capture/dump.pcap"
    assert caps[0]["sha256"] == hashlib.sha256(pcap_bytes).hexdigest()
    assert caps[0]["bytes"] == len(pcap_bytes)
    # The pcap is now servable from within the output dir.
    assert _durable_artifact(tmp_path, job, "capture/dump.pcap").read_bytes() == pcap_bytes


def test_network_capture_seal_proceeds_when_done_sentinel_never_lands(tmp_path, monkeypatch):
    """The .done-sentinel wait is BOUNDED: if netd never finalizes (no sentinel), the seal still
    proceeds after the (short) timeout rather than blocking — the pcap is still sealed best-effort."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE_WAIT_S", "0.2")  # short bound so the test is fast

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    pcap_bytes = b"\xd4\xc3\xb2\xa1pcap-without-a-done-sentinel"

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            cap = tmp_path / job.job_id / "capture"
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(pcap_bytes)  # NOTE: no .done sentinel
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    sealed = _sealed_metadata(tmp_path, job)
    caps = [a for a in sealed["artifacts"] if a["kind"] == "network_capture"]
    assert len(caps) == 1  # sealed anyway after the bounded wait
    assert caps[0]["sha256"] == hashlib.sha256(pcap_bytes).hexdigest()


class _FakeArt:
    def __init__(self, path, nbytes=0):
        self.path = path
        self.bytes = nbytes


class _FakeEnv:
    def __init__(self, artifacts):
        self.artifacts = artifacts

    def model_copy(self, update):
        self.artifacts = update["artifacts"]
        return self


def _capture_src(tmp_path, job_id="J"):
    cap = tmp_path / job_id / "capture"
    cap.mkdir(parents=True, exist_ok=True)
    (cap / "dump.pcap").write_bytes(b"\xd4\xc3\xb2\xa1pcap-bytes")
    (cap / "dump.pcap.done").write_text("done")
    out = tmp_path / job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    return out


def test_seal_capture_refuses_path_collision(tmp_path):
    """If the worker already declared an artifact at capture/dump.pcap, the host must NOT overwrite
    it (served bytes would mismatch that artifact's sealed sha) — leave the envelope unchanged."""
    d = _make_dispatcher(InMemoryJobStore(), job_root=tmp_path)
    out = _capture_src(tmp_path)
    env = _FakeEnv([_FakeArt("capture/dump.pcap", 10)])
    result = d._seal_network_capture(env, out)
    assert len(result.artifacts) == 1  # capture not sealed over the worker's artifact


def test_seal_capture_respects_artifact_count_cap(tmp_path):
    """The host capture artifact is appended after worker-output cap enforcement, so it must honor
    the same max_artifacts ceiling rather than silently exceed it."""
    d = _make_dispatcher(InMemoryJobStore(), job_root=tmp_path)
    d._limits = Limits(max_artifacts=1)
    out = _capture_src(tmp_path)
    env = _FakeEnv([_FakeArt("other", 10)])  # already at the cap of 1
    result = d._seal_network_capture(env, out)
    assert len(result.artifacts) == 1  # capture not appended past the cap


def test_capture_refuses_symlinked_capture_dir(tmp_path, monkeypatch):
    """A worker that plants output/capture as a SYMLINK must not be able to redirect the host pcap
    write outside the job tree — the seal refuses a symlinked capture dir and writes nothing."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    escape = tmp_path / "escape"
    escape.mkdir()

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            cap = tmp_path / job.job_id / "capture"
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(b"\xd4\xc3\xb2\xa1pcap")
            (cap / "dump.pcap.done").write_text("done")
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
            (output_dir / "capture").symlink_to(escape)  # worker tampering
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    sealed = _sealed_metadata(tmp_path, job)
    assert not [a for a in sealed["artifacts"] if a["kind"] == "network_capture"]  # refused
    assert not (escape / "dump.pcap").exists()  # nothing written through the symlink


class _FakePool:
    """Minimal warm pool stand-in that records claim() calls and never hands out a slot (so a job
    that DOES try the warm path cold-falls-back)."""
    def __init__(self):
        self.claim_calls = 0
        self.idle_count = 1
        self.runtime = RuntimeSelection(runtime="runc", secure=False, warnings=[])

    def claim(self, timeout_s=None):
        self.claim_calls += 1
        return None

    def release(self, slot):  # pragma: no cover - never reached (claim returns None)
        pass


def test_warm_egress_job_bypasses_warm_slot(tmp_path, monkeypatch):
    """An egress personality needs the COLD path (netd wiring + network args/labels), which the warm
    tier can't apply — so the dispatcher must NOT claim a warm slot for it (else it would silently
    run with no egress). A no-egress job still tries the warm slot."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    store = InMemoryJobStore()
    output_dirs = {}

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dirs["cur"], input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    # egress job (exit=direct) → must bypass the warm slot and run cold to DONE
    egress_pool = _FakePool()
    egress_job = _make_job()
    egress_job.input_sha256 = _INPUT_SHA
    egress_job.net_policy = "direct"
    store.create(egress_job)
    _setup_job_dirs(tmp_path, egress_job)
    output_dirs["cur"] = tmp_path / egress_job.job_id / "output"
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"])
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    d = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                         subprocess_runner=fake_runner, pool=egress_pool)
    assert d.dispatch_once() is True
    assert egress_pool.claim_calls == 0                      # warm slot bypassed
    assert store.get(egress_job.job_id).status == JobStatus.DONE

    # no-egress job (default none) → DOES try the warm slot (claim called, then cold-falls-back)
    none_pool = _FakePool()
    none_job = _make_job()
    none_job.input_sha256 = _INPUT_SHA
    store.create(none_job)
    _setup_job_dirs(tmp_path, none_job)
    output_dirs["cur"] = tmp_path / none_job.job_id / "output"
    d2 = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                          subprocess_runner=fake_runner, pool=none_pool)
    assert d2.dispatch_once() is True
    assert none_pool.claim_calls == 1                        # warm slot attempted


def test_netd_wired_personality_refused_under_runsc(tmp_path, monkeypatch):
    """tor/socks/vpn/inspect need netd to nsenter the worker netns, which a runsc (gVisor) worker
    doesn't expose. Under the default secure runtime such a job must FAIL FAST with a clear
    diagnostic, not silently wait-then-fail-closed."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_SX", "exit=socks,proxy=socks5://172.30.0.40:9050")
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="sx")
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
        runtime_selector=lambda: RuntimeSelection(runtime="runsc", secure=True, warnings=[]),
    )
    assert dispatcher.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED
    assert "host-visible netns" in (final.error or "")


def test_socks_dns_tcp_off_uses_dns_leakguard(tmp_path, monkeypatch):
    """A socks personality with dns_tcp=0 resolves over UDP:53 (its resolv.conf omits use-vc), so it
    must get the 'dns' leakguard (allow udp:53) — the default 'strict' guard would drop its DNS."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_SUDP",
        "exit=socks,proxy=socks5://172.30.0.40:9050,dns=172.30.0.40,dns_tcp=0",
    )
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="sudp")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                                  subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "blastbox.net.leakguard=dns" in argv
    assert "blastbox.net.leakguard=strict" not in argv


def test_egress_filter_labels_set_on_vpn_tier(tmp_path, monkeypatch):
    """egress_ports + block_internal on a gateway-routed all-IP tier (openvpn) → the worker carries the
    egress-filter labels AND the 'allip' leakguard (all-IP: keep non-internal UDP/ICMP). The decl uses
    whitespace for multi-value (',' is the KV separator)."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_WEBVPN",
        "exit=openvpn,gateway=10.8.0.1,egress_ports=53 80 443,block_internal=1",
    )
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="webvpn")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                                  subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "blastbox.net.egress-ports=53,80,443" in argv
    assert "blastbox.net.block-internal=1" in argv
    assert "blastbox.net.leakguard=allip" in argv   # all-IP tier keeps non-internal UDP/ICMP


@pytest.mark.parametrize("decl,driver", [
    ("exit=socks,proxy=socks5://172.30.0.40:9050,egress_ports=53 80 443", "socks"),
    ("exit=direct,block_internal=1", "direct"),
    ("exit=inetsim,egress_ports=80 443", "inetsim"),
])
def test_egress_filter_refused_on_unsupported_tier(tmp_path, monkeypatch, decl, driver):
    """egress_ports/block_internal are only sound on tor/openvpn/wireguard (the worker's OUTPUT carries
    the real dst:port AND egress is fail-closed until netd wires). On a proxy hop (socks/httpproxy) the
    filter would drop the tunnel; on a plain bridge (direct/inetsim) it fails open. Refuse, fail-closed."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_BAD", decl)
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="bad")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng})
    assert dispatcher.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED
    assert "tor, openvpn, or wireguard" in (final.error or "")


def test_egress_ports_invalid_value_refused(tmp_path, monkeypatch):
    """A non-empty but all-invalid egress_ports (typo) must FAIL the job, not silently widen egress."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_TYPO", "exit=openvpn,gateway=10.8.0.1,egress_ports=htts")
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="typo")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng})
    assert dispatcher.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED
    assert "egress_ports" in (final.error or "")


def test_httpproxy_env_validates_proxy_url(tmp_path):
    """The httpproxy proxy= URL is validated before injection — a malformed value injects no proxy
    env (fail closed), matching the socks tier's validation."""
    from blastbox.host.netpolicy import Personality
    d = _make_dispatcher(InMemoryJobStore(), job_root=tmp_path)
    good = Personality(name="brd", exit_driver="httpproxy",
                       config={"proxy": "http://172.30.0.30:8888"})
    assert d._httpproxy_env(good)["HTTP_PROXY"] == "http://172.30.0.30:8888"
    assert d._httpproxy_env(good)["https_proxy"] == "http://172.30.0.30:8888"
    for bad in ("not a url", "ftp://x:1", "http://", "http://h:99999x", "http://h:1 ; rm -rf"):
        p = Personality(name="brd", exit_driver="httpproxy", config={"proxy": bad})
        assert d._httpproxy_env(p) == {}
    # non-httpproxy driver → never injects proxy env
    assert d._httpproxy_env(Personality(name="d", exit_driver="direct", config={})) == {}
    # inline user:pass@ is STRIPPED before reaching the worker env (creds stay in the sidecar)
    creds = Personality(name="brd", exit_driver="httpproxy",
                        config={"proxy": "http://user:s3cr3t@172.30.0.30:8888"})
    env = d._httpproxy_env(creds)
    assert env["HTTP_PROXY"] == "http://172.30.0.30:8888"  # host:port kept, userinfo dropped
    assert all("s3cr3t" not in v and "user" not in v for v in env.values())
    # IPv6 literal: brackets must be preserved when rebuilding the credential-stripped netloc
    v6 = Personality(name="brd", exit_driver="httpproxy",
                     config={"proxy": "http://u:p@[2001:db8::1]:8080"})
    assert d._httpproxy_env(v6)["HTTP_PROXY"] == "http://[2001:db8::1]:8080"


def test_decrypt_seal_refuses_symlinked_output(tmp_path, monkeypatch):
    """A worker that plants output/capture/decrypted.pcap as a symlink must NOT get GoGoRoboCap's
    output written or hashed through it — ggrc writes to a host-only scratch and the copy into
    output/capture is symlink-checked, so the escape target is never touched and the symlinked
    artifact is skipped."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")
    monkeypatch.setenv("BLASTBOX_NET_DECRYPT", "1")
    monkeypatch.setenv("BLASTBOX_GOGOROBOCAP_BIN", "/bin/fake-ggrc")
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    cap = tmp_path / job.job_id / "capture"
    escape = tmp_path / "escape-secret"
    escape.write_bytes(b"DO NOT TOUCH")

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"raw-tls" * 40)
            (cap / "dump.pcap.done").write_text("done")
            (cap / "sslkeys.log").write_text("SERVER_HANDSHAKE_TRAFFIC_SECRET a b\n")
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
            (output_dir / "capture").mkdir(parents=True, exist_ok=True)
            (output_dir / "capture" / "decrypted.pcap").symlink_to(escape)  # worker tampering
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:1] == ["/bin/fake-ggrc"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1" + b"dec" * 40)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    assert escape.read_bytes() == b"DO NOT TOUCH"  # the symlink target was never written through
    sealed = _sealed_metadata(tmp_path, job)
    paths = [a["path"] for a in sealed["artifacts"]]
    assert "capture/decrypted.pcap" not in paths      # symlinked output skipped
    assert "capture/mixed.pcap" in paths              # the non-symlinked output still sealed


def test_routed_personality_without_gateway_fails_fast(tmp_path, monkeypatch):
    """A gateway-routed tier (tor/vpn/inspect) with no gateway= can't give the worker a wait target,
    so egress would race netd. The dispatcher must FAIL FAST with a clear diagnostic."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_TORNOGW", "exit=tor")  # routed tier, but NO gateway=
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="tornogw")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng})  # runc
    assert dispatcher.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.FAILED
    assert "gateway=" in (final.error or "")


def test_decrypt_seals_decrypted_and_mixed_when_keylog_present(tmp_path, monkeypatch):
    """With BLASTBOX_NET_DECRYPT + a keylog in the capture dir, the dispatcher runs GoGoRoboCap
    and seals decrypted+mixed pcaps as trusted artifacts."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")
    monkeypatch.setenv("BLASTBOX_NET_DECRYPT", "1")
    monkeypatch.setenv("BLASTBOX_GOGOROBOCAP_BIN", "/bin/fake-ggrc")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    cap = tmp_path / job.job_id / "capture"

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            # netd-style capture + an sslproxy-style keylog drop in the host-only capture dir.
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"raw-tls" * 40)
            (cap / "dump.pcap.done").write_text("done")  # netd finalized the capture
            (cap / "sslkeys.log").write_text("SERVER_HANDSHAKE_TRAFFIC_SECRET a b\n")
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:1] == ["/bin/fake-ggrc"]:
            # Emulate GoGoRoboCap writing a non-trivial output pcap.
            out = argv[argv.index("-o") + 1]
            Path(out).write_bytes(b"\xd4\xc3\xb2\xa1" + b"decrypted" * 40)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _direct_dispatcher(store, tmp_path, fake_runner)
    assert dispatcher.dispatch_once() is True

    sealed = _sealed_metadata(tmp_path, job)
    kinds = {a["kind"] for a in sealed["artifacts"]}
    assert "network_capture" in kinds
    assert "network_capture_decrypted" in kinds
    assert "network_capture_mixed" in kinds
    # The decrypted pcap is servable + its hash matches. Read the DURABLE copy: the job dir
    # is purged on every terminal path (issue #84), and this is the copy the API serves.
    dec = next(a for a in sealed["artifacts"] if a["kind"] == "network_capture_decrypted")
    served = _durable_artifact(tmp_path, job, dec["path"]).read_bytes()
    assert dec["sha256"] == hashlib.sha256(served).hexdigest()


def test_decrypt_noop_without_keylog(tmp_path, monkeypatch):
    """decrypt enabled but no keylog → no decrypted artifacts, job still DONE."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")
    monkeypatch.setenv("BLASTBOX_NET_DECRYPT", "1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    cap = tmp_path / job.job_id / "capture"

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            cap.mkdir(parents=True, exist_ok=True)
            (cap / "dump.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"raw" * 40)  # no keylog
            (cap / "dump.pcap.done").write_text("done")  # netd finalized the capture
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    sealed = _sealed_metadata(tmp_path, job)
    kinds = {a["kind"] for a in sealed["artifacts"]}
    assert "network_capture_decrypted" not in kinds
    assert store.get(job.job_id).status == JobStatus.DONE


@pytest.mark.parametrize("env,expected", [
    ("100", 60.0),     # clamped to the ceiling so a fat-fingered env can't wedge a dispatch thread
    ("-5", 0.0),       # negative → floored to 0 (no wait)
    ("3", 3.0),        # in-range value preserved
    (None, 8.0),       # default
])
def test_decrypt_keylog_wait_is_clamped(tmp_path, monkeypatch, env, expected):
    monkeypatch.delenv("BLASTBOX_NET_DECRYPT_KEYLOG_WAIT_S", raising=False)
    if env is not None:
        monkeypatch.setenv("BLASTBOX_NET_DECRYPT_KEYLOG_WAIT_S", env)
    store = InMemoryJobStore()
    d = _make_dispatcher(store, job_root=tmp_path)
    assert d._decrypt_keylog_wait_s == expected


@pytest.mark.parametrize("env,expected", [("100", 60.0), ("-5", 0.0), ("2", 2.0), (None, 5.0)])
def test_net_capture_wait_is_clamped(tmp_path, monkeypatch, env, expected):
    monkeypatch.delenv("BLASTBOX_NET_CAPTURE_WAIT_S", raising=False)
    if env is not None:
        monkeypatch.setenv("BLASTBOX_NET_CAPTURE_WAIT_S", env)
    store = InMemoryJobStore()
    d = _make_dispatcher(store, job_root=tmp_path)
    assert d._net_capture_wait_s == expected


def test_net_egress_env_reflects_personality(tmp_path, monkeypatch):
    """The dispatcher tells the worker BLASTBOX_NET_EGRESS=1 only when the personality has an
    exit (so an inner bwrap/nsjail net-shares); none/drop → '0' (isolate, fail-closed)."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")

    def run_with(net_policy_driver):
        store = InMemoryJobStore()
        job = _make_job()
        job.input_sha256 = _INPUT_SHA
        store.create(job)
        _setup_job_dirs(tmp_path, job)
        output_dir = tmp_path / job.job_id / "output"
        launched: list[list[str]] = []

        def fake_runner(argv, **kw):
            launched.append(list(argv))
            if argv[:2] == ["docker", "run"]:
                _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
            return subprocess.CompletedProcess(argv, 0, "", "")

        engine = EngineSpec(
            name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
            net_policy=net_policy_driver,
        )
        _make_dispatcher(
            store, job_root=tmp_path, engines={_ENGINE_NAME: engine},
            subprocess_runner=fake_runner,
        ).dispatch_once()
        argv = next(a for a in launched if a[:2] == ["docker", "run"])
        # find the -e BLASTBOX_NET_EGRESS=<v> token
        return next(t.split("=", 1)[1] for t in argv if t.startswith("BLASTBOX_NET_EGRESS="))

    assert run_with("direct") == "1"   # has an exit → net-share allowed
    assert run_with("none") == "0"     # sealed → isolate


def test_socks_personality_labels_worker_for_wiring_and_uses_bb_socks(tmp_path, monkeypatch):
    """A socks personality → worker on bb-socks (internal) + labeled blastbox.net.wire=socks."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_TOR", "exit=socks,dns=1.1.1.1,proxy=socks5://172.30.0.40:9050"
    )

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    socks_engine = EngineSpec(
        name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
        net_policy="tor",
    )
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, engines={_ENGINE_NAME: socks_engine},
        subprocess_runner=fake_runner,
    )
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "bb-socks" in argv
    assert "blastbox.net.wire=socks" in argv
    # DNS-over-TCP resolv.conf is injected for the socks exit.
    assert any("dst=/etc/resolv.conf" in t for t in argv)
    # The socks worker waits for the tun2socks TUN before detonating (egress barrier).
    assert any(t == "BLASTBOX_NET_WAIT_TUN=tun0" for t in argv)
    # TCP-only tier → non-TCP leak guard (strict: no UDP needed, DNS is TCP-over-vc).
    assert "blastbox.net.leakguard=strict" in argv
    # Per-personality SOCKS endpoint (e.g. a specific country tor exit) → labelled for netd.
    assert "blastbox.net.socks-proxy=socks5://172.30.0.40:9050" in argv


def test_httpproxy_personality_injects_proxy_env_on_bb_socks(tmp_path, monkeypatch):
    """An httpproxy personality → worker on internal bb-socks with HTTP(S)_PROXY env injected from
    the personality's proxy= (a creds-holding sidecar); NO net.wire wiring, NO resolv.conf."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_BRD", "exit=httpproxy,proxy=http://172.30.0.30:8888")
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="brd")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                                  subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "bb-socks" in argv
    assert any(t == "HTTPS_PROXY=http://172.30.0.30:8888" for t in argv)
    assert any(t == "http_proxy=http://172.30.0.30:8888" for t in argv)
    assert not any(t.startswith("blastbox.net.wire=") for t in argv)   # no netd wiring
    assert not any("dst=/etc/resolv.conf" in t for t in argv)          # no resolv injection
    assert "blastbox.net.leakguard=strict" in argv                     # TCP-only → non-TCP dropped


def test_inspect_httpproxy_fails_closed_no_inspect_label(tmp_path, monkeypatch):
    """inspect+httpproxy is unsupported (httpproxy is not a routed path). The worker must fail
    closed to --network=none and carry NO blastbox.net.wire=inspect label / gateway-wait — i.e. it
    is NOT silently routed onto the MITM gateway nor degraded to a plain proxy."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_BRDINS", "exit=httpproxy,inspect=1,proxy=http://172.30.0.30:8888"
    )
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="brdins")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                                  subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "--network=none" in argv                                    # fail-closed
    assert not any("blastbox.net.wire=inspect" in t for t in argv)     # NOT routed to MITM gw
    assert not any(t.startswith("BLASTBOX_NET_WAIT_GATEWAY=") and t != "BLASTBOX_NET_WAIT_GATEWAY="
                   for t in argv)                                       # no gateway wait


def test_transproxy_personality_labels_worker_and_waits_for_gateway(tmp_path, monkeypatch):
    """A first-class tor personality (CAPE transparent recipe) → worker on bb-socks labeled
    blastbox.net.wire=transproxy, and it waits for the host gateway route (not a TUN)."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_TORTP", "exit=tor,gateway=172.30.0.1,dns=172.30.0.1"
    )
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="tortp")
    dispatcher = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                                  subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "bb-socks" in argv
    assert "blastbox.net.wire=transproxy" in argv
    assert any(t == "BLASTBOX_NET_WAIT_GATEWAY=172.30.0.1" for t in argv)
    assert not any(t.startswith("BLASTBOX_NET_WAIT_TUN=tun0") for t in argv)
    # tor carries TCP + its own DNSPort (UDP:53) → leak guard in "dns" mode.
    assert "blastbox.net.leakguard=dns" in argv


def test_inspect_personality_labels_worker_for_inspect_wiring_and_uses_bb_inspect(
    tmp_path, monkeypatch
):
    """An inspect personality (egress exit + inspect=1) → worker on the internal bb-inspect bridge
    + labeled blastbox.net.wire=inspect, so netd routes it through the sslproxy/MITM gateway."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_MITM", "exit=inetsim,inspect=1,dns=172.28.100.2,gateway=172.32.0.10"
    )

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"
    launched: list[list[str]] = []

    def fake_runner(argv, **kw):
        launched.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    inspect_engine = EngineSpec(
        name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
        net_policy="mitm",
    )
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, engines={_ENGINE_NAME: inspect_engine},
        subprocess_runner=fake_runner,
    )
    assert dispatcher.dispatch_once() is True
    argv = next(a for a in launched if a[:2] == ["docker", "run"])
    assert "bb-inspect" in argv          # rides the inspect bridge, NOT bb-fakenet
    assert "bb-fakenet" not in argv
    assert "blastbox.net.wire=inspect" in argv
    # An inspected egress worker still has egress (through the gateway) → net-share granted.
    assert any(t == "BLASTBOX_NET_EGRESS=1" for t in argv)
    # The worker is told which gateway to wait for (netd wires it after start) — egress barrier.
    assert any(t == "BLASTBOX_NET_WAIT_GATEWAY=172.32.0.10" for t in argv)


def test_no_capture_artifact_when_netd_produced_none(tmp_path, monkeypatch):
    """capture enabled but no pcap on disk (netd not running) → envelope unchanged, job still DONE."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_NET_CAPTURE", "1")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)  # no pcap written
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    sealed = _sealed_metadata(tmp_path, job)
    assert not any(a["kind"] == "network_capture" for a in sealed["artifacts"])
    assert store.get(job.job_id).status == JobStatus.DONE


def test_cold_dispatch_requeues_when_no_gate_headroom(tmp_path):
    # PR #60 codex P1: a cold worker spawns footprint OUTSIDE the warm pool, so cold admission is
    # bounded by the node budget's cold headroom (the sizer's gate). With NO headroom, the job
    # must be REQUEUED — never detonated anyway (→ oversubscription) and never blocking the thread.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    job.created_at = 100.0                  # old timestamp
    store.create(job)
    _setup_job_dirs(tmp_path, job)

    ran: list = []

    def fake_runner(argv, **kw):
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    gate = DynamicConcurrencyGate(1)
    assert gate.acquire(0.0)               # consume the only permit → cold headroom is full
    dispatcher._concurrency_gate = gate
    dispatcher._warm_requeue_backoff_s = 0.0   # no sleep in the test

    assert dispatcher.dispatch_once() is True   # a job WAS claimed...
    assert ran == []                            # ...but the cold worker never spawned
    final = store.get(job.job_id)
    assert final is not None
    assert final.status == JobStatus.QUEUED     # requeued for a later worker/tick
    assert final.claim_id is None               # claim released
    # PR #60: DEFERRED via claimable_after (NOT created_at) so it's temporarily ineligible and
    # warm-eligible work is claimed first — created_at (submission time / max_queued_age) is
    # preserved.
    assert final.created_at == 100.0            # submission time unchanged
    assert final.claimable_after is not None and final.claimable_after > time.time()


def test_cold_dispatch_acquires_and_releases_gate_permit(tmp_path):
    # With headroom, the cold path acquires ONE permit for the detonation and releases it after,
    # so the gate's in-flight count returns to zero (the reservation is transient, per job).
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    output_dir = tmp_path / job.job_id / "output"
    _setup_job_dirs(tmp_path, job)

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate = gate

    assert dispatcher.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    assert gate.in_flight == 0                   # permit taken for the run, then released


def test_cold_permit_retained_when_container_kill_fails(tmp_path):
    # PR #60 codex P1: when a timed-out cold worker's `docker kill` fails, the container may still
    # run; releasing the gate permit would let another cold worker stack on the orphan and exceed
    # the node budget. The permit must be RETAINED until cleanup is confirmed.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)

    def runner(argv, **kw):
        if "kill" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "kill failed")   # kill FAILS (rc!=0)
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))             # worker times out

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=runner)
    gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate = gate

    assert dispatcher.dispatch_once() is True
    assert gate.in_flight == 1                    # permit RETAINED (orphan may still consume RAM)


def test_cold_permit_released_when_kill_confirms(tmp_path):
    # the flip side: a confirmed kill (rc 0) releases the permit as normal.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)

    def runner(argv, **kw):
        if "kill" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")             # kill CONFIRMED
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=runner)
    gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate = gate

    assert dispatcher.dispatch_once() is True
    assert gate.in_flight == 0                    # confirmed gone → permit released


def test_retained_cold_permit_reclaimed_when_container_confirmed_gone(tmp_path):
    # PR #60 codex P2: a permit retained for a failed-kill container must be RECLAIMED once
    # `docker ps` confirms the container is gone — else it leaks permanently and cold capacity
    # bleeds to zero. If docker ps can't be read, keep retaining (can't confirm absence).
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate = gate

    gate.acquire(0.0)                                    # the retained permit
    dispatcher._retained_cold_orphans["blastbox-worker-abc123def456"] = ("abc123def456", None)
    dispatcher._list_active_worker_job_ids = lambda: set()   # docker ps: no live workers
    dispatcher._reconcile_cold_orphans()
    assert gate.in_flight == 0                           # reclaimed
    assert not dispatcher._retained_cold_orphans

    gate.acquire(0.0)                                    # another orphan, but docker ps unreadable
    dispatcher._retained_cold_orphans["blastbox-worker-999888777666"] = ("999888777666", None)
    dispatcher._list_active_worker_job_ids = lambda: None
    dispatcher._reconcile_cold_orphans()
    assert gate.in_flight == 1                           # still retained (absence unconfirmed)


def test_confirmed_gone_cold_orphan_gets_its_tree_purged(tmp_path):
    """The failed-kill orphan's dir is DEFERRED, not forgiven.

    The inline terminal purge skips it on purpose: rmtree'ing under a live writer half-deletes
    the tree, fires a spurious "PURGE FAILED — sample bytes may remain", and reclaims nothing
    because the container's open fds pin the disk. That reservation expires the moment docker ps
    confirms the container is gone — the tree is inert and the security invariant applies again.
    Before this, the reconcile reclaimed only the PERMIT and the sample bytes sat until the age
    reclaim hours later, while the deferral comment promised a sweep that handled them.
    """
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._concurrency_gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate.acquire(0.0)

    jid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text("{}")
    (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")

    dispatcher._retained_cold_orphans[f"blastbox-worker-{jid[:12]}"] = (jid, "claim-1")
    dispatcher._list_active_worker_job_ids = lambda: set()

    dispatcher._reconcile_cold_orphans()

    assert not d.exists(), "the confirmed-gone orphan's sample bytes were left on disk"
    assert dispatcher._concurrency_gate.in_flight == 0


def test_failed_kill_orphan_registers_through_the_real_dispatch_path_with_no_gate(tmp_path):
    """Same hole as the test below, but exercised through _dispatch_claimed_job rather than by
    seeding the map — registration used to sit in the PERMIT's branch (`elif gate is not None`),
    so with the autosizer off it never ran at all and there was nothing for any sweep to find.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher._concurrency_gate is None          # autosizer off — the default

    job = Job.new(engine="redtusk", filename="s.doc")
    job.claim_id = "claim-1"
    job.status = JobStatus.RUNNING
    store.create(job)
    d = tmp_path / job.job_id
    (d / "output").mkdir(parents=True)
    (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")

    name = f"blastbox-worker-{job.job_id[:12]}"

    def fake_inner(j, input_path, output_dir, *, orphan_out=None):
        if orphan_out is not None:
            orphan_out.append(name)      # `docker kill` came back non-zero

    dispatcher._dispatch_inner = fake_inner
    dispatcher._dispatch_claimed_job(job)

    assert name in dispatcher._retained_cold_orphans, (
        "with no gate the failed-kill orphan is never recorded, so nothing ever purges its tree"
    )
    assert dispatcher._retained_cold_orphans[name] == (job.job_id, "claim-1")
    assert d.exists(), "the tree must be DEFERRED, not purged under a possibly-live container"


def test_failed_kill_orphan_is_registered_even_without_a_concurrency_gate(tmp_path):
    """The deferred purge must not depend on the node autosizer being switched on.

    Registration used to sit under `elif gate is not None:` — the permit's branch — while the
    "retaining until a sweep reclaims it" skip ran unconditionally. With BLASTBOX_NODE_* unset
    (gate is None) the tree was therefore never recorded, and _reconcile_cold_orphans returned at
    its first `gate is None` check on every tick, so NOTHING purged it. A terminal job kept its
    sample-derived output/ indefinitely, and the only remaining reclaim was the age sweep — which
    BLASTBOX_SCRATCH_MAX_AGE_S=0 disables, giving a setting that switches off a purge whose own
    docstring says there is deliberately no setting that disables it.

    Retention is about the TREE; the permit is a separate concern that simply has nothing to
    release when there is no gate.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    assert dispatcher._concurrency_gate is None          # autosizer off — the default

    jid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text("{}")

    dispatcher._retained_cold_orphans[f"blastbox-worker-{jid[:12]}"] = (jid, None)
    dispatcher._list_active_worker_job_ids = lambda: set()

    dispatcher._reconcile_cold_orphans()

    assert not d.exists(), "with no gate the reconcile never purges — the deferral is dead code"


def test_confirmed_gone_cold_orphan_is_not_purged_after_a_peer_reclaims_it(tmp_path):
    """The deferred purge runs LONG after the claim, which is exactly when a peer has had time
    to reclaim the job — and two dispatcher containers on one node share a single job_root bind
    mount. Purging then deletes the new owner's staged input mid-flight. This is why the tracker
    records the claim_id we held rather than just the job id: re-reading the store row and
    comparing it against itself would pass trivially and delete the peer's tree every time.
    """
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._concurrency_gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate.acquire(0.0)

    job = Job.new(engine="redtusk", filename="s.doc")
    job.claim_id = "peer-2"                      # the PEER owns it now
    job.status = JobStatus.RUNNING
    store.create(job)
    d = tmp_path / job.job_id
    d.mkdir()
    (d / "input.bin").write_bytes(b"PEER IS USING THIS")

    dispatcher._retained_cold_orphans[f"blastbox-worker-{job.job_id[:12]}"] = (
        job.job_id, "claim-1")                   # we held claim-1
    dispatcher._list_active_worker_job_ids = lambda: set()

    dispatcher._reconcile_cold_orphans()

    assert (d / "input.bin").exists(), "deleted a peer's staged input out from under it"
    assert dispatcher._concurrency_gate.in_flight == 0, "the permit must still be reclaimed"


def test_confirmed_gone_cold_orphan_with_a_failed_upload_is_retained(tmp_path):
    """The upload-exhaustion carve-out has to survive the deferral too: with results/<id> absent,
    this tree is the ONLY copy of a host-sealed result, including evidence that cannot be
    reproduced by re-running. The age reclaim still bounds it."""
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._concurrency_gate = DynamicConcurrencyGate(2)
    dispatcher._concurrency_gate.acquire(0.0)

    jid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"only": "copy"}')

    dispatcher._upload_failed_job_ids.add(jid)
    dispatcher._retained_cold_orphans[f"blastbox-worker-{jid[:12]}"] = (jid, None)
    dispatcher._list_active_worker_job_ids = lambda: set()

    dispatcher._reconcile_cold_orphans()

    assert (d / "output" / "metadata.json").exists(), "destroyed the only copy of a result"


def test_cold_dispatch_fenced_after_shutdown_begins(tmp_path):
    # PR #60 codex P1: once shutdown begins, a dispatch worker abandoned mid-claim must NOT acquire
    # a cold permit and spawn a container after the node reservation is torn down. It requeues.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)

    ran: list = []

    def fake_runner(argv, **kw):
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    gate = DynamicConcurrencyGate(4)               # plenty of headroom...
    dispatcher._concurrency_gate = gate
    dispatcher._warm_requeue_backoff_s = 0.0
    dispatcher._shutting_down.set()                # ...but shutdown has begun

    assert dispatcher.dispatch_once() is True      # claimed...
    assert ran == []                               # ...but NOT detonated (fenced)
    assert gate.in_flight == 0                     # no permit acquired
    final = store.get(job.job_id)
    assert final is not None and final.status == JobStatus.QUEUED   # requeued for restart


def test_terminal_job_leaves_nothing_on_this_workers_disk(tmp_path):
    """SECURITY INVARIANT parity with VmJobDispatcher._purge_job_dir (issue #84).

    A worker is a malware-analysis node, often spare hardware that is not a hardened sample
    repository, so nothing may survive a terminal state. VmJobDispatcher purges the whole job
    dir; the classic Dispatcher deleted only the INPUT and left output/ -- which holds
    metadata.json and rmeta, i.e. text and embedded objects extracted from the sample. On a
    real fleet that leaked 97,681 dirs / 184 GiB, filled a node's root filesystem, and
    collapsed its warm pool from 16 Firecracker guests to 3.

    The durable copy lives in the blob store (results/<job_id>/), so removing the local dir
    loses nothing.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    assert dispatcher.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE

    job_dir = tmp_path / job.job_id
    assert not job_dir.exists(), (
        f"the whole job dir must be gone; survivors: "
        f"{sorted(p.relative_to(job_dir).as_posix() for p in job_dir.rglob('*'))}"
    )


def test_a_peer_reclaimed_job_keeps_its_dir_for_the_new_owner(tmp_path):
    """The purge must stay ownership-gated, exactly as input deletion already is.

    Two dispatcher containers on one node share a single job_root bind mount, so a peer that
    reclaimed this job needs the staged bytes still on disk. Purging unconditionally would
    delete them out from under the new owner mid-flight; that peer's own terminal purge is
    what cleans up.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        # A peer reclaims mid-flight: the claim_id moves on while we are still running.
        cur = store.get(job.job_id)
        cur.claim_id = "peer-took-it"
        store.update(cur.job_id, claim_id="peer-took-it")
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    assert (tmp_path / job.job_id).exists(), (
        "a job reclaimed by a same-host peer must keep its dir for the new owner"
    )


def test_purge_refuses_a_job_id_that_escapes_the_job_root(tmp_path):
    """Containment: a job_id carrying traversal components must never delete outside job_root.

    The purge resolves the path first and refuses anything that does not land strictly under
    job_root. Without that check a crafted job_id would hand an attacker an arbitrary rmtree
    running as the dispatcher.
    """
    from blastbox.host.jobs.retention import purge_job_dir

    job_root = tmp_path / "jobs"
    (job_root / "safe").mkdir(parents=True)
    outsider = tmp_path / "outside"
    outsider.mkdir()
    (outsider / "keepme").write_text("must survive")

    purge_job_dir(job_root, "../outside", logging.getLogger("t"))

    assert (outsider / "keepme").exists(), "purge escaped job_root and deleted an outside tree"
    assert outsider.exists()


def test_orphan_recovery_deletes_input_but_spares_a_possibly_live_output(tmp_path):
    """The orphan sweep must NOT rmtree output/ — its CAS cannot prove the owner is dead (#85 review).

    _fail_if_running CASes on (RUNNING, claim_id), and a live owner mid-SEAL still holds exactly
    that state because it writes its terminal status only after sealing completes. The seal is
    explicitly not bounded by warm_deadline. So this sweep can fire against a live owner, and
    deleting output/ there destroys a result that actually succeeded.

    Deleting the input stays safe in that race (the owner no longer needs it by seal time and the
    sample is content-addressed in the blob store), which is what this path always did.
    """
    store = InMemoryJobStore()
    job = Job.new(engine=_ENGINE_NAME, filename="a.docx")
    job.status = JobStatus.RUNNING
    job.worker_runtime = "warm"
    job.started_at = time.time() - 100_000
    store.create(job)

    input_path = _setup_job_dirs(tmp_path, job)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    (out / "metadata.json").write_text("{}")

    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher.requeue_orphaned_jobs()

    assert store.get(job.job_id).status == JobStatus.FAILED
    assert not input_path.exists(), "the staged input is safe to delete and must be"
    assert (out / "metadata.json").exists(), (
        "output/ was destroyed — a live owner mid-seal would have lost a successful result"
    )


def test_an_upload_exhausted_result_is_retained_not_purged(tmp_path):
    """The purge's whole justification is that the blob store holds the durable copy. On this one
    branch that is false BY CONSTRUCTION — it is reached because the upload never landed (#85
    review). The tree is host-sealed, trust-gate-passed, and holds evidence a re-run cannot
    reproduce, so destroying it turns a transient object-store outage into permanent loss.
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    output_dir = tmp_path / job.job_id / "output"

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    # A blob store whose put_output never succeeds -> retries exhaust.
    blobs = _RecordingBlobs(fail_times=99)
    dispatcher = _make_dispatcher(
        store, job_root=tmp_path, subprocess_runner=fake_runner, blob_store=blobs
    )
    dispatcher.dispatch_once()

    assert store.get(job.job_id).status == JobStatus.FAILED
    assert (tmp_path / job.job_id / "output").exists(), (
        "the only copy of a sealed result was destroyed after the upload failed"
    )


def test_a_store_failure_during_purge_does_not_escape_or_delete(tmp_path):
    """The ownership lookup runs inside a terminal `finally`, so it must never raise (#85 review).

    An escaping exception there masks the job's real outcome. It must also fail SAFE: an
    unprovable owner means a peer may be mid-flight on this tree, so leave it. A leaked dir is
    recoverable; a job whose staged input vanished under it is not.

    Exercises the purge contract directly. (The same `finally` also calls _record_outcome, which
    has its own unguarded store lookup -- pre-existing and outside this change; noted on the PR.)
    """
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    (tmp_path / job.job_id / "output" / "rmeta").write_text("extracted sample text")

    dispatcher = _make_dispatcher(store, job_root=tmp_path)

    class _BrokenStore:
        def get(self, job_id):
            raise RuntimeError("job store unavailable")

    dispatcher._job_store = _BrokenStore()
    dispatcher._purge_job_dir_if_owned(job)      # must not raise

    assert (tmp_path / job.job_id).exists(), (
        "ownership was unprovable, so the tree must be left for its real owner, not deleted"
    )


def test_a_live_orphaned_container_keeps_its_bind_mounted_tree(tmp_path):
    """Do not rmtree a tree a possibly-live worker still has bind-mounted (#85 review).

    The same `finally` deliberately RETAINS the concurrency permit when `docker kill` was not
    confirmed, on the grounds the container may still be running. Purging its bind-mount source
    five lines later races a live writer into a half-deleted tree and a spurious
    "PURGE FAILED ... sample bytes may remain", and its open fds pin the disk regardless — so
    nothing is even reclaimed.
    """
    store = InMemoryJobStore()
    job = _make_job()
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    (out / "metadata.json").write_text("{}")

    def fake_runner(argv, **kw):
        if "kill" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "kill failed")   # NOT confirmed gone
        raise subprocess.TimeoutExpired(argv, 1)

    dispatcher = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=fake_runner)
    dispatcher.dispatch_once()

    assert (tmp_path / job.job_id).exists(), (
        "purged a tree whose worker container was never confirmed dead"
    )


def test_put_output_is_a_real_durability_barrier(tmp_path):
    """The terminal purge deletes the local tree on the strength of put_output succeeding, so a
    silent no-op there yields a DONE job with no copy anywhere (#85 review). rglob on a missing
    directory yields nothing and raises nothing, so the barrier has to be asserted explicitly.
    """
    from blastbox.host.blobs.local import LocalBlobStore

    store = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    with pytest.raises(FileNotFoundError):
        store.put_output("jid", tmp_path / "jobs" / "jid" / "output")   # never created


def test_scratch_reclaim_bounds_the_dirs_the_purge_deliberately_skips(tmp_path):
    """The terminal purge skips two trees on purpose — an unconfirmed-dead container's, and a
    result whose upload exhausted (the only copy). Without a bound those leak forever, because
    the retention sweeper is gated on job_retention_seconds > 0 and that knob also deletes
    results from the blob store. This is the bound, and it must not touch the blob store (#85).
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    stale = tmp_path / "11111111-1111-4111-8111-111111111111"
    (stale / "output").mkdir(parents=True)
    (stale / "output" / "rmeta").write_text("extracted sample text")
    # Age the WHOLE tree. Aging only the parent is not a stale tree -- a live worker writing into
    # output/ leaves the parent's mtime untouched, which is precisely why the sweep now looks at
    # the newest mtime anywhere beneath it.
    old_ts = time.time() - 3600
    for path in (stale / "output" / "rmeta", stale / "output", stale):
        os.utime(path, (old_ts, old_ts))

    fresh = tmp_path / "22222222-2222-4222-8222-222222222222"
    (fresh / "output").mkdir(parents=True)

    blobs_before = sorted((tmp_path.parent / "blobs").rglob("*")) if (tmp_path.parent / "blobs").exists() else []
    assert dispatcher._reap_stale_scratch() == 1
    assert not stale.exists(), "the aged tree was not reclaimed"
    assert fresh.exists(), "a live/recent tree must never be reclaimed on age"
    blobs_after = sorted((tmp_path.parent / "blobs").rglob("*")) if (tmp_path.parent / "blobs").exists() else []
    assert blobs_before == blobs_after, "scratch reclaim must never touch the blob store"


def test_scratch_reclaim_is_off_when_disabled(tmp_path):
    """0 disables it — an operator who wants trees kept must be able to keep them."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 0.0
    old = tmp_path / "33333333-3333-4333-8333-333333333333"
    old.mkdir(parents=True)
    os.utime(old, (time.time() - 99999, time.time() - 99999))
    assert dispatcher._reap_stale_scratch() == 0
    assert old.exists()


def test_purge_refuses_a_sibling_alias_job_id(tmp_path):
    """Containment alone is not enough: "victim/child/.." is strictly UNDER job_root yet resolves
    to a different job's tree, so a malformed store row could rmtree a live peer's working dir.
    Job.from_dict() does not validate IDs, so such a row can reach here (#85 review).
    """
    from blastbox.host.jobs.retention import purge_job_dir

    job_root = tmp_path / "jobs"
    (job_root / "victim" / "child").mkdir(parents=True)
    (job_root / "victim" / "keep").write_text("live peer's work")

    for hostile in ("victim/child/..", "", ".", "..", "../jobs", "a/b"):
        purge_job_dir(job_root, hostile, logging.getLogger("t"))

    assert (job_root / "victim" / "keep").exists(), "a sibling job's tree was destroyed"
    assert job_root.exists()


def test_purge_survives_a_path_that_cannot_be_canonicalised(tmp_path):
    """resolve() itself can raise (a symlink loop raises RuntimeError on 3.12). Both dispatchers
    call this from terminal cleanup, so an escape masks the job's outcome and skips its metrics.
    The docstring promises best-effort; the boundary must cover canonicalisation too.
    """
    from blastbox.host.jobs.retention import purge_job_dir

    job_root = tmp_path / "jobs"
    job_root.mkdir(parents=True)
    loop = job_root / "loopy"
    loop.symlink_to(job_root / "loopy2")
    (job_root / "loopy2").symlink_to(loop)

    purge_job_dir(job_root, "loopy", logging.getLogger("t"))   # must not raise


def test_scratch_reclaim_spares_a_live_job_writing_into_output(tmp_path):
    """The top-level dir mtime is NOT refreshed by writes into output/ (verified: a live worker
    writing job_root/<id>/output/artifact.bin leaves the parent's mtime untouched). A cold run
    with BLASTBOX_WORKER_TIMEOUT_S above the cutoff is supported, so age alone would delete a
    running job's tree — the exact failure this sweep exists to avoid elsewhere (#85 review).
    """
    store = InMemoryJobStore()
    job = _make_job()
    job.status = JobStatus.RUNNING
    store.create(job)

    d = tmp_path / job.job_id
    (d / "output").mkdir(parents=True)
    old = time.time() - 99_999
    os.utime(d, (old, old))                       # parent looks ancient...
    (d / "output" / "artifact.bin").write_bytes(b"live worker writing right now")

    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0
    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "deleted a live job's tree because only the parent mtime was checked"


def test_scratch_reclaim_spares_a_running_job_even_if_the_whole_tree_is_old(tmp_path):
    """Second, independent safeguard: age is a heuristic, job state is a fact. A RUNNING job is
    never reclaimable regardless of how stale every file looks."""
    store = InMemoryJobStore()
    job = _make_job()
    job.status = JobStatus.RUNNING
    store.create(job)

    d = tmp_path / job.job_id
    (d / "output").mkdir(parents=True)
    old = time.time() - 99_999
    for p in (d / "output", d):
        os.utime(p, (old, old))

    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0
    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "reclaimed a tree whose job is still RUNNING"


def test_scratch_reclaim_still_takes_a_genuinely_orphaned_tree(tmp_path):
    """The bound must still work: a dir the store knows nothing about is a real orphan."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    d = tmp_path / "44444444-4444-4444-8444-444444444444"
    (d / "output").mkdir(parents=True)
    old = time.time() - 99_999
    for p in (d / "output", d):
        os.utime(p, (old, old))

    assert dispatcher._reap_stale_scratch() == 1
    assert not d.exists()


def test_scratch_reclaim_spares_a_fresh_tree_the_store_does_not_know_yet(tmp_path):
    """The two safeguards are NOT redundant, and this is the case only the mtime one catches.

    Ingress spools job_root/<id>/input before the store row is durably visible to a dispatcher,
    so there is a window where the job is unknown (job is None = "genuine orphan, reclaimable")
    while the tree is being actively written. Age is what protects it there.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    d = tmp_path / "55555555-5555-4555-8555-555555555555"
    (d / "input").mkdir(parents=True)
    old = time.time() - 99_999
    os.utime(d, (old, old))                       # parent ancient, content brand new
    (d / "input" / "sample.doc").write_bytes(b"just spooled by ingress")

    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "deleted a tree being spooled, before its job row was visible"


def test_scratch_reclaim_leaves_the_tree_when_the_store_cannot_be_read(tmp_path):
    """Store trouble must never turn into deletion. Unprovable state = leave the bytes."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    d = tmp_path / "66666666-6666-4666-8666-666666666666"
    (d / "output").mkdir(parents=True)
    old = time.time() - 99_999
    for p in (d / "output", d):
        os.utime(p, (old, old))

    class _BrokenStore:
        def get(self, job_id):
            raise RuntimeError("job store unavailable")

    dispatcher._job_store = _BrokenStore()
    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "a store error caused a deletion"


def test_scratch_reclaim_never_touches_a_colocated_blob_store(tmp_path):
    """"The store has never heard of it" is NOT evidence of an orphan (#85 review).

    job_root can legitimately contain a co-located blob store — BLASTBOX_BLOB_LOCAL_ROOT under
    job_root is a documented multi-node layout — plus lost+found when it is its own filesystem.
    Reclaiming anything the job store doesn't recognise destroys every sample and every durable
    result on that mount: the copy the API serves, and the copy that makes the terminal purge
    safe in the first place. Only uuid4-shaped directories are candidates.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    old = time.time() - 99_999
    blobs = tmp_path / "blobs" / "results" / "some-job"
    blobs.mkdir(parents=True)
    (blobs / "metadata.json").write_text("{}")
    lostfound = tmp_path / "lost+found"
    lostfound.mkdir()
    for p in (blobs / "metadata.json", blobs, blobs.parent, tmp_path / "blobs", lostfound):
        os.utime(p, (old, old))

    assert dispatcher._reap_stale_scratch() == 0
    assert (blobs / "metadata.json").exists(), "the reclaim destroyed the durable blob store"
    assert lostfound.exists()


def test_scratch_reclaim_refuses_a_symlink_even_with_a_perfect_job_id_name(tmp_path):
    """A uuid4-NAMED SYMLINK is not a job dir, and following one is how this sweep would
    delete a tree it was never pointed at.

    purge_job_dir resolves before it deletes, so a symlink under job_root is dereferenced to
    whatever it points at — a sibling job's live tree, or the co-located blob store. The name
    passes the uuid4 shape check (names are free), and the link's own mtime is trivially old,
    so every other guard waves it through. Nothing but the is_symlink() refusal stops it.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    victim = tmp_path / "blobs" / "results" / "some-job"
    victim.mkdir(parents=True)
    (victim / "metadata.json").write_text("{}")

    link = tmp_path / "88888888-8888-4888-8888-888888888888"
    link.symlink_to(tmp_path / "blobs", target_is_directory=True)
    # The TARGET is old too, so every age-based guard waves it through and the
    # is_symlink() refusal is the only thing left holding the line. (stat() follows
    # the link, so a freshly-created target would spare it for the wrong reason and
    # the test would pass even with the refusal deleted.)
    old = time.time() - 99_999
    for pth in (victim / "metadata.json", victim, victim.parent, tmp_path / "blobs"):
        os.utime(pth, (old, old))
    os.utime(link, (old, old), follow_symlinks=False)

    assert dispatcher._reap_stale_scratch() == 0
    assert (victim / "metadata.json").exists(), "the reclaim followed a symlink out of its lane"
    assert link.is_symlink()


def test_scratch_reclaim_cannot_be_evaded_by_a_worker_setting_a_future_mtime(tmp_path):
    """The worker owns files under output/ (a 0o777 bind mount) and utime() is unprivileged, so a
    detonated sample could stamp a future mtime and make its tree immortal — defeating the only
    bound on job_root and reproducing #84 on purpose. A future mtime is not liveness.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    d = tmp_path / "77777777-7777-4777-8777-777777777777"
    (d / "output").mkdir(parents=True)
    pad = d / "output" / "pad.bin"
    pad.write_bytes(b"x")
    old = time.time() - 99_999
    os.utime(d, (old, old))
    os.utime(d / "output", (old, old))
    os.utime(pad, (2**31, 2**31))          # malware stamps the far future

    assert dispatcher._reap_stale_scratch() == 1, "a future mtime made the tree immortal"
    assert not d.exists()


def test_scratch_reclaim_cannot_be_evaded_by_a_worker_planting_a_symlink(tmp_path):
    """The other half of the mtime-evasion class, and the one the future-mtime guard cannot see.

    stat() DEREFERENCES. A detonated sample owns output/ (a 0o777 bind mount) and needs one
    `ln -s /tmp output/notes` to make its own tree immortal: every tick reads /tmp's mtime,
    which a busy host refreshes continuously, so the tree is "live" forever. The stamp is
    perfectly honest, so clamping the future does nothing. That permanently defeats the only
    bound this PR puts on job_root and reproduces #84's 184 GiB leak on demand.

    lstat() is the whole fix — rglob already refuses to descend INTO a symlinked directory,
    so the link's own (old) mtime is the only evidence it can offer.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    busy = tmp_path.parent / "busy-host-path"
    busy.mkdir(exist_ok=True)                      # mtime = now, refreshed on a real host

    d = tmp_path / "99999999-9999-4999-8999-999999999999"
    (d / "output").mkdir(parents=True)
    (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
    (d / "output" / "notes").symlink_to(busy, target_is_directory=True)

    old = time.time() - 99_999
    for pth in (d / "input.bin", d / "output" / "notes", d / "output", d):
        os.utime(pth, (old, old), follow_symlinks=False)

    assert dispatcher._reap_stale_scratch() == 1, "a planted symlink made the tree immortal"
    assert not d.exists()


def test_scratch_reclaim_leaves_a_tree_whose_container_is_still_retained(tmp_path):
    """The reclaim must not do what the inline purge refuses to do.

    A wedged container (its `docker kill` failed — that is WHY it is retained) writes nothing,
    so its tree's mtime stops advancing and it ages into this sweep, while _reconcile_cold_orphans
    — running LATER in the same maintenance tick — is still deliberately retaining it because
    docker ps keeps listing it. rmtree'ing there half-deletes the tree under a live 0o777 bind
    mount, fires the spurious "PURGE FAILED", and frees nothing (its open fds pin the blocks),
    so the operator-facing "removed N job dir(s)" reports bytes that are still allocated.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    jid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "partial.json").write_text("{}")
    old = time.time() - 99_999
    for pth in (d / "output" / "partial.json", d / "output", d):
        os.utime(pth, (old, old))

    dispatcher._retained_cold_orphans[f"blastbox-worker-{jid[:12]}"] = (jid, "claim-1")

    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "deleted a tree under a container this process still believes is alive"


def test_scratch_reclaim_never_deletes_a_sealed_result_that_has_no_durable_copy(tmp_path):
    """The sweep rests on "the blob store has the durable copy, so the local tree loses nothing" —
    and there are two states where that is false, each with its own HOST-only evidence.

    (1) A job completed BEFORE the blob store shipped was never put_output'd, and
    LocalBlobStore.open_output still serves it from the legacy <job_root>/<id>/output path — which
    is precisely the tree this sweep rmtrees. Evidence: a DONE row with nothing durable.
    (2) A result whose upload exhausted is host-sealed and unreproducible (the C2 pcap is MOVED
    into it; detonation is not deterministic). Evidence: the pending-upload sentinel.

    output/metadata.json is NOT evidence — the worker writes it (worker/harness.py) and the host
    only overwrites it once the trust gate passes. See the crash-orphan test below.
    """
    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    # (1) legacy: DONE row, only copy on local disk
    legacy = "11111111-1111-4111-8111-111111111111"
    dl = tmp_path / legacy
    (dl / "output").mkdir(parents=True)
    (dl / "output" / "metadata.json").write_text('{"sealed": true}')
    jl = Job.new(engine="redtusk", filename="a.doc")
    jl.job_id = legacy
    jl.status = JobStatus.DONE
    store.create(jl)

    # (2) upload exhausted: the host left its sentinel
    pending = "22222222-2222-4222-8222-222222222222"
    dp = tmp_path / pending
    (dp / "output").mkdir(parents=True)
    (dp / "output" / "metadata.json").write_text('{"sealed": true}')
    (dp / PENDING_UPLOAD_SENTINEL).write_text("")

    old = time.time() - 99_999
    for base in (dl, dp):
        for pth in (base / "output" / "metadata.json", base / "output", base):
            os.utime(pth, (old, old))
        if (base / PENDING_UPLOAD_SENTINEL).exists():
            os.utime(base / PENDING_UPLOAD_SENTINEL, (old, old))

    assert not dispatcher._blobs.has_output(legacy), "precondition: nothing durable"
    assert dispatcher._reap_stale_scratch() == 0
    assert (dl / "output" / "metadata.json").exists(), "deleted a legacy result's only copy"
    assert (dp / "output" / "metadata.json").exists(), "deleted a retained result's only copy"


def test_scratch_reclaim_still_takes_a_crash_orphaned_tree_the_host_never_vouched_for(tmp_path):
    """The counterpart, and the reason the gate cannot key on output/metadata.json.

    The WORKER writes that file itself. A cold job whose dispatcher was SIGKILLed before it could
    seal, upload and purge leaves one behind — and if its mere presence meant "sealed result with
    no durable copy", every such tree would be retained forever: has_output() is False, no sweep
    drains it (no sentinel), and #84's unbounded accumulation returns with the malware input still
    on disk. Without host evidence, the tree is scratch.
    """
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    jid = "33333333-3333-4333-8333-333333333333"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"written": "by the worker"}')
    (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
    job = Job.new(engine="redtusk", filename="a.doc")
    job.job_id = jid
    job.status = JobStatus.FAILED                      # orphan-recovered
    job.error = "orphaned"
    store.create(job)

    old = time.time() - 99_999
    for pth in (d / "output" / "metadata.json", d / "input.bin", d / "output", d):
        os.utime(pth, (old, old))

    assert dispatcher._reap_stale_scratch() == 1, "a crash-orphaned tree is immortal again"
    assert not d.exists()


def test_scratch_reclaim_takes_a_sealed_result_once_it_is_durably_stored(tmp_path):
    """The counterpart: once put_output has landed the bytes, the local tree really is redundant
    and the sweep must still collect it — otherwise the last-copy rule quietly disables the bound
    on every DONE job and #84 comes straight back."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    jid = "22222222-2222-4222-8222-222222222222"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"sealed": true}')
    dispatcher._blobs.put_output(jid, d / "output")                    # the durable copy lands
    assert dispatcher._blobs.has_output(jid)

    old = time.time() - 99_999
    for pth in (d / "output" / "metadata.json", d / "output", d):
        os.utime(pth, (old, old))

    assert dispatcher._reap_stale_scratch() == 1
    assert not d.exists()


def test_scratch_reclaim_still_takes_a_crash_stranded_tree_with_no_result(tmp_path):
    """The last-copy rule must NOT extend to scratch. A SIGKILL mid-detonation leaves a tree with
    no sealed output and no durable copy — and never will have one. Requiring durability there
    would retain it forever, reintroducing the exact leak this sweep exists to bound."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    jid = "33333333-3333-4333-8333-333333333333"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)                                  # started, never sealed
    (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
    old = time.time() - 99_999
    for pth in (d / "input.bin", d / "output", d):
        os.utime(pth, (old, old))

    assert dispatcher._reap_stale_scratch() == 1, "a crash-stranded tree is unbounded again"
    assert not d.exists()


def test_scratch_reclaim_reports_only_what_it_actually_removed(tmp_path):
    """purge_job_dir refuses and fails best-effort, so counting unconditionally made the
    operator-facing "removed N job dir(s)" line report directories still on disk — forever, on
    every tick, next to the ERROR explaining it had refused them."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    d = tmp_path / "88888888-8888-4888-8888-888888888888"
    d.mkdir()
    os.utime(d, (time.time() - 99_999,) * 2)

    import blastbox.host.jobs.retention as mod
    real = mod.purge_job_dir
    try:
        mod.purge_job_dir = lambda root, jid, log: False      # simulate a refusal/failure
        assert dispatcher._reap_stale_scratch() == 0, "counted a dir it did not remove"
    finally:
        mod.purge_job_dir = real


def test_scratch_reclaim_spares_a_uuid_named_blob_root(tmp_path, monkeypatch):
    """The uuid4 shape check is not enough on its own.

    BLASTBOX_BLOB_LOCAL_ROOT is operator-set: it may live under job_root (a documented layout)
    and it may be named anything — including a uuid. Then the shape check waves it straight
    through and the sweep deletes every durable result on the node, which is the opposite of what
    the last-copy rule is for. The configured root is protected by CANONICAL path, so a symlinked
    or ..-laden setting still matches.
    """
    blob_root = tmp_path / "55555555-5555-4555-8555-555555555555"
    (blob_root / "results" / "some-job").mkdir(parents=True)
    (blob_root / "results" / "some-job" / "metadata.json").write_text("{}")
    monkeypatch.setenv("BLASTBOX_BLOB_LOCAL_ROOT", str(tmp_path / "." / blob_root.name))

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0
    old = time.time() - 99_999
    for p in (blob_root / "results" / "some-job" / "metadata.json",
              blob_root / "results" / "some-job", blob_root / "results", blob_root):
        os.utime(p, (old, old))

    assert dispatcher._reap_stale_scratch() == 0
    assert (blob_root / "results" / "some-job" / "metadata.json").exists(), (
        "the reclaim destroyed the durable blob store because it was uuid-named"
    )


def test_scratch_reclaim_is_bounded_per_sweep_and_says_so(tmp_path):
    """The fleet state this exists to clean is 97,681 dirs / 184 GiB. Doing it in one pass puts a
    full recursive walk, a store lookup per candidate and 184 GiB of unlink ahead of every other
    maintenance task — including the cold-permit reclaim and crash recovery. The sweep is
    idempotent and runs every tick, so a cap still drains the backlog.

    The cap is ANNOUNCED: a silent truncation reads as "the disk is clean now" when it isn't.
    """
    import logging as _logging

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    old = time.time() - 99_999
    for i in range(7):
        d = tmp_path / f"{i:08d}-1111-4111-8111-111111111111"
        d.mkdir()
        os.utime(d, (old, old))

    from blastbox.host.jobs.retention import reap_stale_scratch
    removed = reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"), max_per_sweep=3)
    assert removed == 3, "the cap did not bound the sweep"
    assert len(list(tmp_path.iterdir())) == 4, "removed more than the cap allowed"

    # ...and the next tick continues where it left off.
    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                              max_per_sweep=3) == 3
    assert len(list(tmp_path.iterdir())) == 1


def test_scratch_reclaim_holds_a_pending_tree_until_its_repair_actually_lands(tmp_path):
    """Durable bytes are not enough to release the tree — the JOB has to be fixed too.

    The recovery path is: upload the bytes, then CAS the row FAILED->DONE. If that second step
    fails (a store blip mid-sweep) the fall-through repair needs this tree again next tick.
    Deleting it the moment has_output() went true stranded the job FAILED forever with a durable
    result it can never serve — every artifact route answering 409, and no sweep able to fix it.
    """
    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)
    dispatcher._scratch_max_age_s = 60.0

    jid = "44444444-4444-4444-8444-444444444444"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"sealed": true}')
    (d / PENDING_UPLOAD_SENTINEL).write_text("")
    dispatcher._blobs.put_output(jid, d / "output")          # bytes ARE durable
    job = Job.new(engine="redtusk", filename="a.doc")
    job.job_id = jid
    job.status = JobStatus.FAILED                            # ...but the repair never landed
    store.create(job)

    old = time.time() - 99_999
    for pth in (d / "output" / "metadata.json", d / PENDING_UPLOAD_SENTINEL, d / "output", d):
        os.utime(pth, (old, old))

    assert dispatcher._reap_stale_scratch() == 0
    assert d.exists(), "deleted the tree the repair needs, stranding the job FAILED forever"


def test_scratch_reclaim_asks_docker_not_just_its_own_memory(tmp_path):
    """The unconfirmed-kill guard was a PROCESS-LOCAL set, which is not where the danger is: two
    dispatcher containers share one job_root, the VM dispatcher keeps no such set, and a restart
    empties it — so the other sweeper deletes exactly the trees the guard exists to spare, under a
    live 0o777 bind mount. docker ps is node-wide and survives restarts."""
    from blastbox.host.jobs.retention import reap_stale_scratch
    import logging as _logging

    store = InMemoryJobStore()
    jid = "55555555-5555-4555-8555-555555555555"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    old = time.time() - 99_999
    for pth in (d / "output", d):
        os.utime(pth, (old, old))

    # No process-local knowledge at all — a fresh dispatcher after a restart.
    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                              live_job_ids=lambda: {jid}) == 0
    assert d.exists(), "deleted a tree whose container docker still reports as running"

    # ...and an unreadable probe must not become a deletion either way round.
    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                              live_job_ids=lambda: None) == 1


def test_scratch_reclaim_protects_a_blob_root_nested_under_a_candidate(tmp_path):
    """Equality protected nothing when the blob root lives INSIDE a uuid-named dir: deleting the
    candidate destroys the root within it. And the root is taken from the STORE, not the
    environment, so a store constructed in code (a public kwarg) is protected too."""
    from blastbox.host.blobs.local import LocalBlobStore
    from blastbox.host.jobs.retention import reap_stale_scratch
    import logging as _logging

    candidate = tmp_path / "66666666-6666-4666-8666-666666666666"
    blob_root = candidate / "blobs"
    (blob_root / "results" / "j").mkdir(parents=True)
    (blob_root / "results" / "j" / "metadata.json").write_text("{}")
    old = time.time() - 99_999
    for pth in (blob_root / "results" / "j" / "metadata.json", blob_root / "results" / "j",
                blob_root / "results", blob_root, candidate):
        os.utime(pth, (old, old))

    store = InMemoryJobStore()
    blobs = LocalBlobStore(tmp_path, blob_root=blob_root)     # no env var anywhere
    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                              blob_store=blobs) == 0
    assert (blob_root / "results" / "j" / "metadata.json").exists(), (
        "deleted the durable blob store because it was nested inside the candidate"
    )


def _blob_store_for(job_root):
    """A LocalBlobStore rooted OUTSIDE job_root, matching the production default."""
    from blastbox.host.blobs.local import LocalBlobStore
    return LocalBlobStore(job_root, blob_root=job_root.parent / "blobs-for-test")


def test_scratch_reclaim_cap_counts_work_not_just_deletions(tmp_path):
    """Capping on removals alone bounded nothing in the state this was written for.

    A tree that is RETAINED (last-copy hold) or that fails to delete still costs a full rglob
    walk, a store round-trip and a has_output() call — and none of that advanced a removal
    counter, so the sweep re-walked all 97,681 candidates on every tick and the "hit the cap" line
    never fired. The bound has to be on work done, not on work that succeeded.
    """
    from blastbox.host.jobs.retention import reap_stale_scratch
    import logging as _logging

    class CountingStore(InMemoryJobStore):
        gets = 0

        def get(self, job_id):
            type(self).gets += 1
            return super().get(job_id)

    store = CountingStore()
    old = time.time() - 99_999
    for i in range(10):
        jid = f"{i:08d}-7777-4777-8777-777777777777"
        d = tmp_path / jid
        (d / "output").mkdir(parents=True)
        (d / "output" / "metadata.json").write_text("{}")
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = jid
        job.status = JobStatus.DONE                    # legacy: retained, never removed
        store.create(job)
        for pth in (d / "output" / "metadata.json", d / "output", d):
            os.utime(pth, (old, old))

    blobs = _blob_store_for(tmp_path)
    removed = reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                                 blob_store=blobs, max_per_sweep=3)
    assert removed == 0, "these are all retained"
    assert CountingStore.gets <= 4, (
        f"examined {CountingStore.gets} candidates with a cap of 3 — the cap never bounds a "
        f"sweep whose trees are retained rather than removed"
    )
    assert len(list(tmp_path.iterdir())) == 10


def test_a_retained_orphan_is_marked_on_disk_for_every_sweeper(tmp_path):
    """The unconfirmed-kill hold has to be visible to processes that never saw the failed kill.

    It lived in a process-local set, but the danger is cross-process: two dispatcher containers
    share one job_root, VmJobDispatcher has no docker access to probe with at all, and a restart
    empties the set — so the OTHER sweeper deletes exactly the trees the hold exists to protect,
    under a live 0o777 bind mount. A file in the host-only job dir is seen by every sweeper.
    """
    from blastbox.host.jobs.retention import RETAINED_ORPHAN_SENTINEL, reap_stale_scratch
    import logging as _logging

    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)

    job = Job.new(engine="redtusk", filename="s.doc")
    job.claim_id = "claim-1"
    job.status = JobStatus.RUNNING
    store.create(job)
    d = tmp_path / job.job_id
    (d / "output").mkdir(parents=True)
    name = f"blastbox-worker-{job.job_id[:12]}"
    dispatcher._dispatch_inner = lambda j, i, o, *, orphan_out=None: orphan_out.append(name)
    dispatcher._dispatch_claimed_job(job)

    assert (d / RETAINED_ORPHAN_SENTINEL).is_file(), "no cross-process record of the hold"

    # A COMPLETELY SEPARATE sweeper — no shared memory, no docker probe — must honour it.
    # The job is made TERMINAL first, so the status check cannot be what saves the tree: the
    # on-disk marker has to be the only thing standing between it and the rmtree.
    store.update(job.job_id, status=JobStatus.FAILED)
    # Every timestamp is STALE — including the marker's own, which is 90s old against a 60s
    # reclaim age. So nothing here looks alive: the mtime walk would happily reclaim this tree,
    # and only the marker (whose hold runs to 2x the reclaim age) stands in the way. A fresh
    # marker would have made the tree look live and the test would pass without testing anything.
    now = time.time()
    for pth in (d / "output", d):
        os.utime(pth, (now - 99_999,) * 2)
    os.utime(d / RETAINED_ORPHAN_SENTINEL, (now - 90, now - 90))

    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t")) == 0
    assert d.exists(), "another process deleted a tree under a possibly-live container"


def test_the_retained_orphan_hold_expires_so_the_disk_bound_still_wins(tmp_path):
    """...but not forever. A container that still has not died at twice the reclaim age is an
    operator problem, and an unbounded hold is just #84 with extra steps."""
    from blastbox.host.jobs.retention import RETAINED_ORPHAN_SENTINEL, reap_stale_scratch
    import logging as _logging

    store = InMemoryJobStore()
    jid = "77777777-7777-4777-8777-777777777777"
    d = tmp_path / jid
    (d / "output").mkdir(parents=True)
    (d / RETAINED_ORPHAN_SENTINEL).write_text("")
    old = time.time() - 99_999
    for pth in (d / RETAINED_ORPHAN_SENTINEL, d / "output", d):
        os.utime(pth, (old, old))

    assert reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t")) == 1
    assert not d.exists()


def test_a_repaired_job_gets_the_result_summary_its_done_path_would_have_written(tmp_path):
    """A recovered job was DONE with result_summary=None forever: /v1/jobs and the status route
    report null artifact/warning counts, anything tallying off them under-reports every recovered
    job, and nothing re-walks DONE jobs to fix it."""
    store = InMemoryJobStore()
    dispatcher = _make_dispatcher(store, job_root=tmp_path)

    job = Job.new(engine="redtusk", filename="a.doc")
    job.status = JobStatus.DONE
    store.create(job)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True)
    # A minimal sealed envelope: the summary is built from it, so it must parse.
    (out / "metadata.json").write_text(json.dumps({
        "engine": "redtusk", "status": "ok", "input_sha256": "a" * 64,
        "detected": {"label": "docx", "mime": "x", "confidence": 1.0, "source": "magika"},
        "artifacts": [], "warnings": [],
        "payload": {"_type": "extracted_text", "text": "x", "char_count": 1},
    }))

    dispatcher._index_repaired_result(job.job_id, out)

    assert store.get(job.job_id).result_summary is not None, "recovered job left with null counts"


def test_the_capped_sweep_rotates_so_held_trees_cannot_starve_the_rest(tmp_path):
    """iterdir order is stable, so a capped sweep re-examined the same prefix every tick.

    A prefix of permanently-held trees — a legacy result with no durable copy, a retained orphan —
    would consume the entire cap forever and starve every candidate behind it, which is precisely
    the unbounded growth the cap was added to prevent.
    """
    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL, reap_stale_scratch
    import logging as _logging

    store = InMemoryJobStore()
    old = time.time() - 99_999
    held, reclaimable = [], []
    for i in range(3):                                  # held: sealed result, nothing durable
        jid = f"0000000{i}-1111-4111-8111-111111111111"
        d = tmp_path / jid
        (d / "output").mkdir(parents=True)
        (d / "output" / "metadata.json").write_text("{}")
        (d / PENDING_UPLOAD_SENTINEL).write_text("")
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = jid
        job.status = JobStatus.FAILED
        store.create(job)
        held.append(d)
    for i in range(3):                                  # plain scratch, behind them in sort order
        jid = f"9000000{i}-1111-4111-8111-111111111111"
        d = tmp_path / jid
        d.mkdir()
        reclaimable.append(d)
    for d in held + reclaimable:
        for pth in sorted(d.rglob("*"), reverse=True) + [d]:
            os.utime(pth, (old, old))

    blobs = _blob_store_for(tmp_path)
    total = 0
    for _ in range(8):                                  # a few ticks, cap smaller than the holds
        total += reap_stale_scratch(tmp_path, 60.0, store, _logging.getLogger("t"),
                                    blob_store=blobs, max_per_sweep=2)
    # Without rotation this is 0 forever: the three held trees fill the cap on every tick.
    assert total == 3, f"held trees starved the reclaimable ones (removed {total}/3)"
    assert all(d.exists() for d in held), "a held tree was deleted"
