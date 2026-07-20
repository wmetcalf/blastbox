"""TDD tests for blastbox.host.dispatch.Dispatcher.

11 test cases per the plan at docs/plans/2026-05-31-host-dispatch.md.
"""
from __future__ import annotations

import hashlib
import json
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
    served = json.loads((output_dir / "metadata.json").read_text())
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

    sealed = json.loads((output_dir / "metadata.json").read_text())
    caps = [a for a in sealed["artifacts"] if a["kind"] == "network_capture"]
    assert len(caps) == 1, f"capture artifact not sealed: {sealed['artifacts']}"
    assert caps[0]["path"] == "capture/dump.pcap"
    assert caps[0]["sha256"] == hashlib.sha256(pcap_bytes).hexdigest()
    assert caps[0]["bytes"] == len(pcap_bytes)
    # The pcap is now servable from within the output dir.
    assert (output_dir / "capture" / "dump.pcap").read_bytes() == pcap_bytes


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
    sealed = json.loads((output_dir / "metadata.json").read_text())
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
    sealed = json.loads((output_dir / "metadata.json").read_text())
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
    sealed = json.loads((output_dir / "metadata.json").read_text())
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

    sealed = json.loads((output_dir / "metadata.json").read_text())
    kinds = {a["kind"] for a in sealed["artifacts"]}
    assert "network_capture" in kinds
    assert "network_capture_decrypted" in kinds
    assert "network_capture_mixed" in kinds
    # The decrypted pcap is servable from the output dir + hash matches.
    dec = next(a for a in sealed["artifacts"] if a["kind"] == "network_capture_decrypted")
    served = (output_dir / dec["path"]).read_bytes()
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
    sealed = json.loads((output_dir / "metadata.json").read_text())
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
    sealed = json.loads((output_dir / "metadata.json").read_text())
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
    # PR #60 codex P1: DEFERRED — created_at bumped so it moves behind claimable work (a
    # capacity-blocked cold job at its original ts would be reclaimed in a loop, starving warm).
    assert final.created_at > 100.0


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
    dispatcher._retained_cold_orphans.add("blastbox-worker-abc123def456")
    dispatcher._list_active_worker_job_ids = lambda: set()   # docker ps: no live workers
    dispatcher._reconcile_cold_orphans()
    assert gate.in_flight == 0                           # reclaimed
    assert not dispatcher._retained_cold_orphans

    gate.acquire(0.0)                                    # another orphan, but docker ps unreadable
    dispatcher._retained_cold_orphans.add("blastbox-worker-999888777666")
    dispatcher._list_active_worker_job_ids = lambda: None
    dispatcher._reconcile_cold_orphans()
    assert gate.in_flight == 1                           # still retained (absence unconfirmed)
