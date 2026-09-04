"""TDD tests for Finding E1 (classic Dispatcher materialise-on-demand) + Finding E3
(consecutive, not lifetime, materialise_attempts).

``VmJobDispatcher`` already materialises a missing sample on demand (see
``tests/host/runtime/test_vm_dispatch_materialise.py``); the classic (cold/warm)
``Dispatcher`` had zero ``get_sample`` calls, so a job whose sample lives only in the
blob store (uploaded by another node's ingress in a shared-queue deployment) would
run with a garbage/missing input instead of fetching it first. These tests drive
BOTH the cold and warm paths through ``Dispatcher._materialise_sample``.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.dispatch import MAX_MATERIALISE_ATTEMPTS, Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.docker import RuntimeSelection
from blastbox.limits import Limits

from tests.host.test_dispatch_warm import (
    FakeWarmPool,
    _make_slot,
    _make_valid_output_dir as _make_valid_warm_output_dir,
    _start_fake_worker,
)

_ENGINE_NAME = "test-engine"
_ENGINE_IMAGE = "registry.example.com/test-worker:latest"
_INPUT_BYTES = b"the real sample bytes, fetched from the blob store"
# LocalBlobStore.get_sample re-hashes the fetched bytes and compares to the requested
# key (a real integrity check) -- the key must be the ACTUAL content hash, not an
# arbitrary placeholder, or every "successful fetch" test would instead exercise the
# BlobIntegrityError (a BlobFetchError subclass) release path by accident.
_INPUT_SHA = hashlib.sha256(_INPUT_BYTES).hexdigest()


def _limits() -> Limits:
    return Limits()


def _engine_spec() -> EngineSpec:
    return EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"])


def _fake_runtime() -> RuntimeSelection:
    return RuntimeSelection(runtime="runc", secure=False, warnings=["no runsc"])


def _make_job(filename: str = "malware.docx") -> Job:
    return Job.new(engine=_ENGINE_NAME, filename=filename)


def _make_valid_output_dir(output_dir: Path, *, input_sha256: str = _INPUT_SHA) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_content = b"PNG_DATA"
    (output_dir / "page-001.png").write_bytes(artifact_content)
    real_sha = hashlib.sha256(artifact_content).hexdigest()
    envelope = {
        "engine": _ENGINE_NAME,
        "status": "ok",
        "input_sha256": input_sha256,
        "detected": {
            "label": "docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "confidence": 0.99,
            "source": "magika",
        },
        "artifacts": [
            {"id": "page-001", "path": "page-001.png", "kind": "image",
             "sha256": real_sha, "bytes": len(artifact_content)}
        ],
        "warnings": [],
        "payload": {"_type": "extracted_text", "text": "hello world", "char_count": 11},
    }
    (output_dir / "metadata.json").write_bytes(json.dumps(envelope).encode())


def _make_dispatcher(
    store: InMemoryJobStore,
    *,
    job_root: Path,
    blob_store=None,
    subprocess_runner=None,
    blob_retry_backoff_s: float = 0.0,
) -> Dispatcher:
    return Dispatcher(
        job_store=store,
        engines={_ENGINE_NAME: _engine_spec()},
        limits=_limits(),
        job_root=job_root,
        runtime_selector=_fake_runtime,
        subprocess_runner=subprocess_runner
        or (lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", "")),
        blob_store=blob_store,
        put_output_retry_backoff_s=0.0,
        blob_retry_backoff_s=blob_retry_backoff_s,
    )


class UnreachableBlobStore:
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        raise BlobFetchError("object store unreachable")
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


# ===========================================================================
# E1 — cold path
# ===========================================================================


def test_cold_missing_input_is_materialised_then_processed(tmp_path):
    """A real LocalBlobStore holds the sample; the local input file is ABSENT (as it
    would be if another node's ingress spooled it). The cold path must fetch it on
    demand and run the job to completion."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    blobs = LocalBlobStore(job_root=job_root, blob_root=tmp_path / "blobs")
    seed = tmp_path / "seed_sample"
    seed.write_bytes(_INPUT_BYTES)
    blobs.put_sample(_INPUT_SHA, seed)

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    output_dir = job_root / job.job_id / "output"
    input_path = job_root / job.job_id / "input" / Path(job.filename).name
    seen_input_bytes: list[bytes] = []

    def fake_runner(argv, **kw):
        # The bind-mount source must exist with the CORRECT bytes by the time the
        # (fake) worker "runs" -- capture it here, before the caller's finally purges it.
        seen_input_bytes.append(input_path.read_bytes())
        _make_valid_output_dir(output_dir)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(
        store, job_root=job_root, blob_store=blobs, subprocess_runner=fake_runner
    )
    assert not input_path.exists()
    result = dispatcher.dispatch_once()

    assert result is True
    assert seen_input_bytes == [_INPUT_BYTES]
    final = store.get(job.job_id)
    assert final is not None
    assert final.status is JobStatus.DONE, final.error


def test_cold_fetch_failure_releases_not_fails(tmp_path):
    """An unreachable blob store must RELEASE the claim to QUEUED, not fail the job --
    a fetch failure says something about THIS node's connectivity, not the sample."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    dispatcher = _make_dispatcher(
        store, job_root=job_root, blob_store=UnreachableBlobStore(), blob_retry_backoff_s=30.0
    )
    result = dispatcher.dispatch_once()

    assert result is True
    final = store.get(job.job_id)
    assert final.status is JobStatus.QUEUED, "must be reclaimable, not FAILED"
    assert final.claim_id is None
    assert final.materialise_attempts == 1
    assert final.claimable_after is not None and final.claimable_after > time.time(), (
        "must back off, not be instantly re-claimable"
    )


def test_cold_permanently_missing_sample_eventually_fails_the_job(tmp_path):
    """A sample that can NEVER be materialised must not loop release -> reclaim ->
    release forever: it FAILs once MAX_MATERIALISE_ATTEMPTS is reached."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    dispatcher = _make_dispatcher(store, job_root=job_root, blob_store=UnreachableBlobStore())

    for attempt in range(1, MAX_MATERIALISE_ATTEMPTS + 1):
        assert dispatcher.dispatch_once() is True
        current = store.get(job.job_id)
        assert current.materialise_attempts == attempt
        if attempt < MAX_MATERIALISE_ATTEMPTS:
            assert current.status is JobStatus.QUEUED, f"attempt {attempt} should release"
            store.update(job.job_id, claimable_after=None)  # bypass backoff for the loop
        else:
            assert current.status is JobStatus.FAILED, "must give up once the bound is reached"
            assert current.error and "attempts" in current.error


def test_cold_present_input_is_not_refetched(tmp_path):
    """Single-node default: when this node's own ingress already spooled the input,
    the cold path must NOT call get_sample -- byte-identical to before this feature."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    class CountingBlobStore(LocalBlobStore):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.get_calls = 0

        def get_sample(self, sha256, dest):
            self.get_calls += 1
            return super().get_sample(sha256, dest)

    blobs = CountingBlobStore(job_root=job_root, blob_root=tmp_path / "blobs")

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    job_dir = job_root / job.job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    input_path = input_dir / Path(job.filename).name
    input_path.write_bytes(b"already spooled locally")

    def fake_runner(argv, **kw):
        _make_valid_output_dir(output_dir)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(
        store, job_root=job_root, blob_store=blobs, subprocess_runner=fake_runner
    )
    assert dispatcher.dispatch_once() is True
    assert blobs.get_calls == 0
    assert store.get(job.job_id).status is JobStatus.DONE


# ===========================================================================
# E1 — warm path
# ===========================================================================


def _make_warm_dispatcher(store, *, job_root: Path, pool, blob_store=None,
                           blob_retry_backoff_s: float = 0.0) -> Dispatcher:
    return Dispatcher(
        job_store=store,
        engines={_ENGINE_NAME: _engine_spec()},
        limits=_limits(),
        job_root=job_root,
        runtime_selector=_fake_runtime,
        subprocess_runner=lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
        pool=pool,
        tier="cold",
        warm_claim_timeout_s=0.5,
        warm_requeue_backoff_s=0.0,
        blob_store=blob_store,
        put_output_retry_backoff_s=0.0,
        blob_retry_backoff_s=blob_retry_backoff_s,
    )


def test_warm_missing_input_is_materialised_then_processed(tmp_path):
    """Warm path twin of the cold-path test above: the slot's file-based staging copy
    must see the sample AFTER it's fetched from the blob store, not a missing file."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    blobs = LocalBlobStore(job_root=job_root, blob_root=tmp_path / "blobs")
    seed = tmp_path / "seed_sample"
    seed.write_bytes(_INPUT_BYTES)
    blobs.put_sample(_INPUT_SHA, seed)

    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    _start_fake_worker(
        slot,
        output_fn=lambda out_dir: _make_valid_warm_output_dir(out_dir, input_sha256=_INPUT_SHA),
    )

    input_path = job_root / job.job_id / "input" / Path(job.filename).name
    dispatcher = _make_warm_dispatcher(store, job_root=job_root, pool=pool, blob_store=blobs)
    assert not input_path.exists()
    result = dispatcher.dispatch_once()

    assert result is True
    final = store.get(job.job_id)
    assert final is not None
    assert final.status is JobStatus.DONE, final.error
    assert final.worker_runtime == "warm"


def test_warm_fetch_failure_releases_not_fails(tmp_path):
    """Warm path twin: an unreachable blob store releases the claim (QUEUED), not FAILED."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    slot = _make_slot(tmp_path)
    pool = FakeWarmPool(slot)
    # No fake worker started: the job must never reach the go.json handshake.

    dispatcher = _make_warm_dispatcher(
        store, job_root=job_root, pool=pool, blob_store=UnreachableBlobStore()
    )
    result = dispatcher.dispatch_once()

    assert result is True
    final = store.get(job.job_id)
    assert final.status is JobStatus.QUEUED
    assert final.claim_id is None
    assert final.materialise_attempts == 1
    assert len(pool.release_calls) == 1, "the never-used slot must still be released"


# ===========================================================================
# E3 — consecutive, not lifetime
# ===========================================================================


class ScriptedBlobStore:
    """Fails on specific 1-indexed call numbers; materialises otherwise."""

    def __init__(self, fail_on, data: bytes = _INPUT_BYTES):
        self.fail_on = set(fail_on)
        self.data = data
        self.calls = 0

    def put_sample(self, sha256, src): ...

    def get_sample(self, sha256, dest):
        self.calls += 1
        if self.calls in self.fail_on:
            raise BlobFetchError("scripted failure")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.data)

    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_successful_materialisation_resets_the_counter(tmp_path):
    """A sample that fails once (counter -> 1, released) then materialises successfully
    on the very next attempt must complete DONE with the counter reset to 0 -- not left
    at 1 (Finding E3: the bound is on consecutive failures, not a lifetime total)."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    blobs = ScriptedBlobStore(fail_on={1})

    def fake_runner(argv, **kw):
        _make_valid_output_dir(job_root / job.job_id / "output")
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = _make_dispatcher(
        store, job_root=job_root, blob_store=blobs, subprocess_runner=fake_runner
    )

    assert dispatcher.dispatch_once() is True
    released = store.get(job.job_id)
    assert released.status is JobStatus.QUEUED
    assert released.materialise_attempts == 1
    store.update(job.job_id, claimable_after=None)

    assert dispatcher.dispatch_once() is True
    done = store.get(job.job_id)
    assert done.status is JobStatus.DONE
    assert done.materialise_attempts == 0, "a successful fetch must reset the counter"


def test_counter_is_consecutive_not_lifetime_across_a_reset(tmp_path):
    """Finding E3: the SAME job fails to materialise twice (counter -> 2, released each
    time), then materialises successfully (counter resets to 0). A LATER attempt --
    after the local copy is gone again (e.g. this job is reclaimed on a different node
    that never had the file, or this node's copy was lost some other way) -- must count
    its failure as attempt 1 (the post-reset baseline), not attempt 3, which is exactly
    the lifetime-vs-consecutive bug this finding fixes. Exercises
    ``Dispatcher._materialise_sample`` directly (the shared cold/warm helper), the same
    unit both dispatch paths call into -- see the full-flow dispatch_once() tests above
    for the end-to-end behaviour."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    # Calls 1 & 2 fail, call 3 succeeds (resets the counter), call 4 fails again.
    blobs = ScriptedBlobStore(fail_on={1, 2, 4})
    dispatcher = _make_dispatcher(store, job_root=job_root, blob_store=blobs)
    input_path = job_root / job.job_id / "input" / Path(job.filename).name

    for expected_attempt in (1, 2):
        claimed = store.claim_next()
        assert dispatcher._materialise_sample(claimed, input_path) is False
        current = store.get(job.job_id)
        assert current.status is JobStatus.QUEUED, f"attempt {expected_attempt} should release"
        assert current.materialise_attempts == expected_attempt
        store.update(job.job_id, claimable_after=None)

    # Attempt 3: fetch succeeds -> counter resets to 0.
    claimed = store.claim_next()
    assert dispatcher._materialise_sample(claimed, input_path) is True
    assert store.get(job.job_id).materialise_attempts == 0
    assert input_path.read_bytes() == blobs.data

    # Simulate the sample being gone again on the next attempt (this job is still
    # RUNNING under `claimed`'s claim -- put it back to QUEUED the way a non-terminal
    # requeue would, then reclaim) and fail once more.
    store.update(job.job_id, status=JobStatus.QUEUED, claim_id=None)
    input_path.unlink()
    claimed = store.claim_next()
    assert dispatcher._materialise_sample(claimed, input_path) is False
    final = store.get(job.job_id)
    assert final.status is JobStatus.QUEUED
    assert final.materialise_attempts == 1, (
        "a fetch failure after a reset must count as attempt 1 (consecutive), not "
        "accumulate the two earlier, already-resolved failures toward the cap"
    )
