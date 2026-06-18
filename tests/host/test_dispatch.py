"""TDD tests for blastbox.host.dispatch.Dispatcher.

11 test cases per the plan at docs/plans/2026-05-31-host-dispatch.md.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

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
    """Job with unknown engine → FAILED immediately, no subprocess, input gone."""
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

    def spy(*, claimant_tier=None):
        seen["tier"] = claimant_tier
        return orig(claimant_tier=claimant_tier)

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
            _make_valid_output_dir(output_dir, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    assert _direct_dispatcher(store, tmp_path, fake_runner).dispatch_once() is True
    sealed = json.loads((output_dir / "metadata.json").read_text())
    kinds = {a["kind"] for a in sealed["artifacts"]}
    assert "network_capture_decrypted" not in kinds
    assert store.get(job.job_id).status == JobStatus.DONE


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
    monkeypatch.setenv("BLASTBOX_NETPOLICY_TOR", "exit=socks,dns=1.1.1.1")

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


def test_transproxy_personality_labels_worker_and_waits_for_gateway(tmp_path, monkeypatch):
    """A socks personality with mode=transproxy (CAPE tor) → worker on bb-socks labeled
    blastbox.net.wire=transproxy, and it waits for the host gateway route (not a TUN)."""
    monkeypatch.setenv(
        "BLASTBOX_NETPOLICY_TORTP", "exit=socks,mode=transproxy,gateway=172.30.0.1"
    )
    store = InMemoryJobStore()
    job = _make_job(); job.input_sha256 = _INPUT_SHA
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
