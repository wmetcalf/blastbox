"""TDD tests for blastbox.worker.warm (5 plan tests).

Tests:
1. happy: warmup → signal_ready → wait_for_go → run_detonation → signal_done("ok") → rc=0;
   output accepted by validate_worker_output; warmup called BEFORE signal_ready.
2. one-job-only: fake control whose wait_for_go would return a second spec if called again;
   assert it is called exactly once.
3. warmup failure: warmup raises → signal_done("warmup_error"), non-zero return, no job.
4. idle timeout: wait_for_go raises WarmTimeout → signal_done("idle_timeout"), rc=0.
5. FileWarmControl round-trip: ready/go.json/done file handshake; WarmTimeout on missing
   go.json; atomic-write check (temp+rename).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest

from blastbox.contract import (
    ArtifactRef,
    DeclaredArtifact,
    Detection,
    Dimensions,
    Page,
)
from blastbox.host.trust import validate_worker_output
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult
from blastbox.worker.warm import (
    FileWarmControl,
    WarmJobSpec,
    WarmTimeout,
    serve_warm,
)

# ---------------------------------------------------------------------------
# Shared helpers / doubles
# ---------------------------------------------------------------------------

_ENGINE_NAME = "warm-test-engine"


def _limits() -> Limits:
    return Limits(
        max_metadata_bytes=4 * 1024 * 1024,
        max_artifact_bytes=50 * 1024 * 1024,
        max_total_artifact_bytes=500 * 1024 * 1024,
        max_artifacts=1000,
    )


class _WarmEngine:
    """Engine that records warmup() being called and writes a minimal PNG output."""

    name: str = _ENGINE_NAME
    formats: frozenset[str] = frozenset({"*"})

    def __init__(self) -> None:
        self.warmup_called: bool = False

    def warmup(self) -> None:
        self.warmup_called = True

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        img_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56
        (outdir / "page-001.png").write_bytes(img_data)
        return DetonationResult(
            payload=Page(
                index=0,
                dims=Dimensions(width=100.0, height=100.0, unit="px"),
                image=ArtifactRef(id="a0"),
            ),
            artifacts=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")],
            detected=Detection(
                label="docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                confidence=0.99,
                source="warm-test",
            ),
        )


class _FailWarmupEngine:
    """Engine whose warmup() raises."""

    name: str = "fail-warmup-engine"
    formats: frozenset[str] = frozenset({"*"})

    def warmup(self) -> None:
        raise RuntimeError("warmup exploded")

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        raise AssertionError("detonate must not be called when warmup fails")


class _FakeControl:
    """Injectable WarmControl that records call order and outcomes.

    Attributes:
        call_log: ordered list of ('signal_ready',), ('wait_for_go',),
                  ('signal_done', status) tuples for assertion.
        _specs: iterator of WarmJobSpec (or WarmTimeout) to yield on wait_for_go.
        done_status: the status string passed to the last signal_done call.
    """

    def __init__(self, specs: list[WarmJobSpec | type[WarmTimeout]]) -> None:
        self.call_log: list[tuple] = []
        self._specs: Iterator[WarmJobSpec | type[WarmTimeout]] = iter(specs)
        self.done_status: str | None = None
        self._wait_count: int = 0

    def signal_ready(self) -> None:
        self.call_log.append(("signal_ready",))

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        self._wait_count += 1
        self.call_log.append(("wait_for_go",))
        val = next(self._specs)
        if val is WarmTimeout or (isinstance(val, type) and issubclass(val, WarmTimeout)):
            raise WarmTimeout("idle timeout (fake)")
        return val  # type: ignore[return-value]

    def signal_done(self, *, status: str) -> None:
        self.done_status = status
        self.call_log.append(("signal_done", status))


# ---------------------------------------------------------------------------
# Test 1: happy path — warmup ordering + round-trip trust validation
# ---------------------------------------------------------------------------


def test_happy_path_warmup_before_ready_and_roundtrip(tmp_path: Path) -> None:
    """warmup() called BEFORE signal_ready; output accepted by validate_worker_output; rc=0."""
    # Stage a real input file
    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    content = b"warm happy path docx bytes"
    input_file.write_bytes(content)
    real_input_sha = hashlib.sha256(content).hexdigest()

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    spec = WarmJobSpec(input_path=input_file, output_dir=output_dir)
    engine = _WarmEngine()
    control = _FakeControl(specs=[spec])

    # Track warmup call order relative to control calls
    warmup_call_index: list[int] = []
    original_warmup = engine.warmup

    def tracked_warmup() -> None:
        warmup_call_index.append(len(control.call_log))
        original_warmup()

    engine.warmup = tracked_warmup  # type: ignore[method-assign]

    rc = serve_warm(engine, control=control, limits=_limits(), idle_timeout_s=10.0)

    assert rc == 0, f"expected rc=0, got {rc}"

    # warmup must have been called BEFORE any control method
    assert warmup_call_index, "warmup() was never called"
    assert warmup_call_index[0] == 0, (
        f"warmup() must be called before any control method; "
        f"control had {warmup_call_index[0]} calls before warmup"
    )
    assert engine.warmup_called, "warmup_called flag must be set"

    # Call order: signal_ready → wait_for_go → signal_done("ok")
    events = control.call_log
    assert ("signal_ready",) in events
    assert ("wait_for_go",) in events
    assert ("signal_done", "ok") in events
    sr_idx = events.index(("signal_ready",))
    wfg_idx = events.index(("wait_for_go",))
    sd_idx = events.index(("signal_done", "ok"))
    assert sr_idx < wfg_idx < sd_idx, (
        f"expected signal_ready < wait_for_go < signal_done; got indices {sr_idx},{wfg_idx},{sd_idx}"
    )

    # output_dir must have metadata.json
    assert (output_dir / "metadata.json").exists(), "metadata.json not written"

    # Host trust validator must accept the output without raising
    env = validate_worker_output(
        output_dir=output_dir,
        input_sha256=real_input_sha,
        engine=_ENGINE_NAME,
        limits=_limits(),
    )
    assert env.status == "ok"
    assert env.input_sha256 == real_input_sha
    assert len(env.artifacts) == 1


# ---------------------------------------------------------------------------
# Test 2: one-job-only — wait_for_go called exactly once
# ---------------------------------------------------------------------------


def test_one_job_only_wait_for_go_called_exactly_once(tmp_path: Path) -> None:
    """serve_warm exits after the first job; wait_for_go is called exactly once."""
    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    input_file.write_bytes(b"one-job-only content")

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    spec1 = WarmJobSpec(input_path=input_file, output_dir=output_dir)
    # If called a second time, the iterator would yield spec1 again
    # (we provide two copies but only one must be consumed)
    control = _FakeControl(specs=[spec1, spec1])

    engine = _WarmEngine()
    rc = serve_warm(engine, control=control, limits=_limits(), idle_timeout_s=10.0)

    assert rc == 0
    assert control._wait_count == 1, (
        f"wait_for_go must be called exactly once; called {control._wait_count} time(s)"
    )


# ---------------------------------------------------------------------------
# Test 3: warmup failure → signal_done("warmup_error"), non-zero return, no job
# ---------------------------------------------------------------------------


def test_warmup_failure_signals_done_and_exits_nonzero(tmp_path: Path) -> None:
    """Engine warmup raises → signal_done(status='warmup_error'), non-zero exit, no job processed."""
    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    input_file.write_bytes(b"content")

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # The spec is never reachable; providing it so a second call would be detectable
    spec = WarmJobSpec(input_path=input_file, output_dir=output_dir)
    control = _FakeControl(specs=[spec])

    engine = _FailWarmupEngine()
    rc = serve_warm(engine, control=control, limits=_limits(), idle_timeout_s=10.0)

    assert rc != 0, "non-zero exit expected on warmup failure"
    assert control.done_status == "warmup_error", (
        f"expected signal_done('warmup_error'), got {control.done_status!r}"
    )
    # wait_for_go must NOT have been called (no job processed)
    assert control._wait_count == 0, (
        f"wait_for_go must not be called when warmup fails; called {control._wait_count} time(s)"
    )
    # signal_ready must NOT have been called (slot is never marked ready)
    ready_calls = [e for e in control.call_log if e == ("signal_ready",)]
    assert not ready_calls, "signal_ready must not be called when warmup fails"


# ---------------------------------------------------------------------------
# Test 4: idle timeout → signal_done("idle_timeout"), rc=0
# ---------------------------------------------------------------------------


def test_idle_timeout_signals_done_and_exits_zero(tmp_path: Path) -> None:
    """wait_for_go raises WarmTimeout → signal_done('idle_timeout'), rc=0."""
    control = _FakeControl(specs=[WarmTimeout])  # type: ignore[list-item]

    engine = _WarmEngine()
    rc = serve_warm(engine, control=control, limits=_limits(), idle_timeout_s=10.0)

    assert rc == 0, f"idle timeout must return 0, got {rc}"
    assert control.done_status == "idle_timeout", (
        f"expected signal_done('idle_timeout'), got {control.done_status!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: FileWarmControl round-trip
# ---------------------------------------------------------------------------


def test_file_warm_control_signal_ready_creates_file(tmp_path: Path) -> None:
    """signal_ready atomically writes control_dir/ready."""
    ctrl = FileWarmControl(tmp_path)
    ctrl.signal_ready()
    assert (tmp_path / "ready").exists(), "ready file must exist after signal_ready"


def test_file_warm_control_signal_done_creates_file(tmp_path: Path) -> None:
    """signal_done atomically writes control_dir/done containing the status."""
    ctrl = FileWarmControl(tmp_path)
    ctrl.signal_done(status="ok")
    done_path = tmp_path / "done"
    assert done_path.exists(), "done file must exist after signal_done"
    content = done_path.read_text(encoding="utf-8").strip()
    assert content == "ok", f"done file must contain the status; got {content!r}"


def test_file_warm_control_wait_for_go_returns_spec(tmp_path: Path) -> None:
    """wait_for_go returns a WarmJobSpec when go.json is present."""
    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    input_file.write_bytes(b"content for file control test")

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    ctrl_dir = tmp_path / "ctrl"
    ctrl_dir.mkdir()
    ctrl = FileWarmControl(ctrl_dir)

    go_data = {
        "input_path": str(input_file),
        "output_dir": str(output_dir),
        "params": {"dpi": "150"},
    }
    (ctrl_dir / "go.json").write_text(json.dumps(go_data), encoding="utf-8")

    spec = ctrl.wait_for_go(timeout_s=1.0)

    assert spec.input_path == input_file
    assert spec.output_dir == output_dir
    assert spec.params == {"dpi": "150"}


def test_file_warm_control_wait_for_go_raises_warm_timeout(tmp_path: Path) -> None:
    """wait_for_go raises WarmTimeout when go.json never appears within timeout."""
    ctrl = FileWarmControl(tmp_path)
    with pytest.raises(WarmTimeout):
        ctrl.wait_for_go(timeout_s=0.1)


def test_file_warm_control_atomic_writes(tmp_path: Path) -> None:
    """ready and done files are written atomically (no partial file observed by racing reader)."""
    # We verify that the files are created via os.replace (temp+rename) by checking
    # that no temp file is left behind after the call, and the target exists atomically.
    ctrl = FileWarmControl(tmp_path)

    # Collect all files before
    before = set(tmp_path.iterdir())

    ctrl.signal_ready()

    after_ready = set(tmp_path.iterdir())
    new_files = after_ready - before
    # Only 'ready' should exist — no leftover temp files
    assert len(new_files) == 1, f"only 'ready' should be created, found: {[f.name for f in new_files]}"
    assert (tmp_path / "ready") in new_files

    before2 = set(tmp_path.iterdir())
    ctrl.signal_done(status="warmup_error")
    after_done = set(tmp_path.iterdir())
    new_files2 = after_done - before2
    assert len(new_files2) == 1, f"only 'done' should be created, found: {[f.name for f in new_files2]}"
    assert (tmp_path / "done") in new_files2


def test_file_warm_control_full_handshake(tmp_path: Path) -> None:
    """Full FileWarmControl handshake: ready → go.json written → spec returned → done."""
    input_file = tmp_path / "in.docx"
    input_file.write_bytes(b"handshake test doc")
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    ctrl_dir = tmp_path / "ctrl"
    ctrl_dir.mkdir()
    ctrl = FileWarmControl(ctrl_dir)

    # signal_ready
    ctrl.signal_ready()
    assert (ctrl_dir / "ready").exists()

    # simulate host writing go.json in background
    def _write_go() -> None:
        time.sleep(0.05)
        go_data = {
            "input_path": str(input_file),
            "output_dir": str(output_dir),
            "params": {},
        }
        tmp = ctrl_dir / ".go.json.tmp"
        tmp.write_text(json.dumps(go_data), encoding="utf-8")
        os.replace(tmp, ctrl_dir / "go.json")

    t = threading.Thread(target=_write_go)
    t.start()
    spec = ctrl.wait_for_go(timeout_s=2.0)
    t.join()

    assert spec.input_path == input_file
    assert spec.output_dir == output_dir

    ctrl.signal_done(status="ok")
    assert (ctrl_dir / "done").read_text(encoding="utf-8").strip() == "ok"


def test_host_wait_for_done_reads_regular_done(tmp_path: Path) -> None:
    from blastbox.worker.warm import HostWarmControl
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    (ctrl / "done").write_text("ok\n")
    assert HostWarmControl(ctrl).wait_for_done(timeout_s=0.5) == "ok"


def test_host_wait_for_done_rejects_symlinked_done(tmp_path: Path) -> None:
    """A hostile worker symlinking ctrl/done at a host file must NOT have its contents read back
    as a status — rejected (WarmTimeout). ctrl/ is worker-writable on the gVisor tier."""
    from blastbox.worker.warm import HostWarmControl
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    (tmp_path / "outside").write_text("SECRET-OUTSIDE")
    (ctrl / "done").symlink_to(tmp_path / "outside")
    with pytest.raises(WarmTimeout):
        HostWarmControl(ctrl).wait_for_done(timeout_s=0.5)
