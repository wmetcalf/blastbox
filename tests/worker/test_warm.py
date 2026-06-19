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
# Post-restore CRNG reseed
# ---------------------------------------------------------------------------


def test_serve_warm_reseeds_crng_after_restore(tmp_path: Path, monkeypatch) -> None:
    """A job arriving means the worker was just restored from the warm snapshot;
    serve_warm reseeds the CRNG exactly once, AFTER wait_for_go and BEFORE done."""
    import blastbox.worker.warm as warm

    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    input_file.write_bytes(b"x")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    spec = WarmJobSpec(input_path=input_file, output_dir=output_dir)
    engine = _WarmEngine()
    control = _FakeControl(specs=[spec])

    # Record the control-call count at reseed time to assert ordering.
    calls: list[int] = []
    monkeypatch.setattr(
        warm, "_reseed_crng_after_restore", lambda: calls.append(len(control.call_log))
    )

    rc = serve_warm(engine, control=control, limits=_limits(), idle_timeout_s=10.0)
    assert rc == 0
    assert len(calls) == 1, "reseed must run exactly once per job"
    # signal_ready + wait_for_go have happened (>=2 calls), signal_done has NOT yet.
    wfg_idx = control.call_log.index(("wait_for_go",))
    assert calls[0] >= wfg_idx + 1, "reseed must run after wait_for_go (post-restore)"


def test_serve_warm_does_not_reseed_on_idle_timeout(tmp_path: Path, monkeypatch) -> None:
    """No job arrived (idle timeout) → no restore-for-a-job → no reseed."""
    import blastbox.worker.warm as warm

    control = _FakeControl(specs=[WarmTimeout])  # type: ignore[list-item]
    calls: list[int] = []
    monkeypatch.setattr(warm, "_reseed_crng_after_restore", lambda: calls.append(1))

    rc = serve_warm(_WarmEngine(), control=control, limits=_limits(), idle_timeout_s=10.0)
    assert rc == 0
    assert calls == [], "reseed must not run when no job arrived"


def test_reseed_crng_after_restore_noop_without_hwrng(monkeypatch) -> None:
    """A tier without virtio-rng (no /dev/hwrng) → best-effort skip, never raises."""
    import builtins

    import blastbox.worker.warm as warm

    real_open = builtins.open

    def fake_open(path, *a, **k):
        if str(path) == "/dev/hwrng":
            raise FileNotFoundError("no /dev/hwrng on this tier")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    warm._reseed_crng_after_restore()  # must return cleanly, no exception


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


def test_file_warm_control_wait_for_go_survives_restore_clock_jump(
    tmp_path: Path, monkeypatch
) -> None:
    """A worker restored from a snapshot OLDER than the idle timeout must still pick
    up the job it was handed. The restore advances CLOCK_MONOTONIC past the original
    deadline; wait_for_go must detect that jump and restart the idle countdown rather
    than instantly raising WarmTimeout (the gVisor warm "metadata.json not found" bug).
    """
    import blastbox.worker.warm as warm

    input_file = tmp_path / "in" / "doc"
    input_file.parent.mkdir()
    input_file.write_bytes(b"x")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    ctrl_dir = tmp_path / "ctrl"
    ctrl_dir.mkdir()
    ctrl = FileWarmControl(ctrl_dir)

    timeout_s = 3600.0
    # monotonic samples: the deadline is seeded once at 0.0 (single sample, so a
    # checkpoint can't desync deadline/last), then the first poll tick reads a huge
    # leap (a multi-day restore) far past the original deadline.
    times = iter([0.0, timeout_s + 100.0, timeout_s + 100.0])
    monkeypatch.setattr(warm.time, "monotonic", lambda: next(times))

    go_data = {"input_path": str(input_file), "output_dir": str(output_dir), "params": {}}

    def fake_sleep(_seconds: float) -> None:
        # The host delivers the job just after the restore (between poll ticks).
        (ctrl_dir / "go.json").write_text(json.dumps(go_data), encoding="utf-8")

    monkeypatch.setattr(warm.time, "sleep", fake_sleep)

    spec = ctrl.wait_for_go(timeout_s=timeout_s)  # must NOT raise despite the clock jump
    assert spec.input_path == input_file
    assert spec.output_dir == output_dir


# ---------------------------------------------------------------------------
# _RestoreAwareDeadline (the shared restore-jump-resilient idle timer)
# ---------------------------------------------------------------------------


def test_restore_aware_deadline_seeds_from_a_single_monotonic_sample(monkeypatch):
    """Both the deadline and the leap reference must come from ONE monotonic
    sample — otherwise a checkpoint landing between two samples desyncs them and
    the very jump being watched for is hidden (PR #37 review, codex)."""
    import blastbox.worker.warm as warm

    calls = []

    def counting_monotonic():
        calls.append(1)
        return 100.0

    monkeypatch.setattr(warm.time, "monotonic", counting_monotonic)
    warm._RestoreAwareDeadline(60.0)
    assert len(calls) == 1  # exactly one sample at construction


def test_restore_aware_deadline_expires_normally(monkeypatch):
    """With no jump, expired() flips to True once the idle window elapses."""
    import blastbox.worker.warm as warm

    # Ticks step by <_RESTORE_JUMP_S each so none is misread as a restore jump.
    times = iter([0.0, 4.0, 8.0, 11.0])  # init, then three ticks
    monkeypatch.setattr(warm.time, "monotonic", lambda: next(times))
    d = warm._RestoreAwareDeadline(10.0)  # deadline = 10.0
    assert d.expired() is False  # t=4.0
    assert d.expired() is False  # t=8.0
    assert d.expired() is True   # t=11.0 >= 10.0 (gap 3.0 < jump threshold)


def test_restore_aware_deadline_restarts_on_clock_jump(monkeypatch):
    """A leap larger than _RESTORE_JUMP_S restarts the countdown (returns False)
    even though the raw clock is far past the original deadline."""
    import blastbox.worker.warm as warm

    # init=0.0 (deadline=10.0); first tick leaps to 10_000 (a multi-hour restore),
    # resetting the deadline to 10_010. The remaining ticks step by <_RESTORE_JUMP_S
    # so they're read as normal time, climbing to the RESTARTED deadline.
    times = iter([0.0, 10_000.0, 10_004.0, 10_008.0, 10_011.0])
    monkeypatch.setattr(warm.time, "monotonic", lambda: next(times))
    d = warm._RestoreAwareDeadline(10.0)
    assert d.expired() is False  # t=10_000: jump detected -> restart (deadline 10_010)
    assert d.expired() is False  # t=10_004: fresh window, not yet elapsed
    assert d.expired() is False  # t=10_008: still within the restarted window
    assert d.expired() is True   # t=10_011 >= restarted deadline 10_010


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


# ---------------------------------------------------------------------------
# Per-job param injection on the warm tier
# ---------------------------------------------------------------------------
# The warm process's env is frozen at snapshot time, so per-job toggles (a job
# sending REDTUSK_ENABLE_THUMBNAILS=0 / CLIPPYSHOT_OCR=1) can't arrive as
# container -e env the way the cold path gets them. serve_warm bridges that gap
# by applying the job's allowlisted UPPERCASE params to os.environ BEFORE
# detonate, so engine.detonate (which reads them via env) honours per-job
# toggles on warm. This guards that bridge — a regression here silently reverts
# warm tiers to "default-only", which is exactly the bug class it was added for.


def test_serve_warm_injects_uppercase_params_into_environ_before_detonate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_file = tmp_path / "input" / "doc.docx"
    input_file.parent.mkdir()
    input_file.write_bytes(b"warm param-injection docx bytes")
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # serve_warm writes the injected keys DIRECTLY to os.environ. monkeypatch.delenv
    # on an absent key registers no undo, so those writes would leak into other tests.
    # set-then-delete records the original (absent) state — teardown then removes
    # whatever serve_warm injects — while keeping each key absent at the test start.
    for k in ("CLIPPYSHOT_OCR", "REDTUSK_ENABLE_THUMBNAILS", "lowercase_key", "BAD-KEY"):
        monkeypatch.setenv(k, "")
        monkeypatch.delenv(k)

    seen: dict[str, str | None] = {}

    class _EnvCaptureEngine(_WarmEngine):
        def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
            # Snapshot the env exactly as engine.detonate would observe it.
            seen["ocr"] = os.environ.get("CLIPPYSHOT_OCR")
            seen["thumb_off"] = os.environ.get("REDTUSK_ENABLE_THUMBNAILS")
            seen["lower"] = os.environ.get("lowercase_key")
            seen["bad"] = os.environ.get("BAD-KEY")
            return super().detonate(input, outdir, limits)

    spec = WarmJobSpec(
        input_path=input_file,
        output_dir=output_dir,
        params={
            "CLIPPYSHOT_OCR": "1",            # uppercase, allowlisted shape → injected
            "REDTUSK_ENABLE_THUMBNAILS": "0",  # the toggle-OFF value must reach the engine
            "lowercase_key": "x",             # lowercase → dropped
            "BAD-KEY": "y",                   # has '-' → fails [A-Z][A-Z0-9_]* → dropped
        },
    )
    control = _FakeControl(specs=[spec])

    rc = serve_warm(_EnvCaptureEngine(), control=control, limits=_limits(), idle_timeout_s=10.0)

    assert rc == 0
    assert seen["ocr"] == "1"          # uppercase allowlisted param reached detonate
    assert seen["thumb_off"] == "0"    # toggle-OFF is honoured per job (not just the default)
    assert seen["lower"] is None       # lowercase dropped
    assert seen["bad"] is None         # malformed-shape key dropped
