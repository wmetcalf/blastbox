"""A failed gVisor boot must report the BOOT's error, not the teardown's.

`runsc run` discarded its stderr, and the teardown that follows a failure runs
`runsc kill` / `runsc delete` against a container that may never have been
created -- which prints `FetchSpec failed: loading container: file does not
exist`. That line was the only stderr an operator saw, and it describes the
cleanup rather than the failure. Measured on toolz3, the real message was
`cannot create gofer process: gofer: fork/exec /proc/self/exe: permission
denied` and was invisible.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from blastbox.host.runtime.gvisor_snapshot import (
    GvisorConfig,
    GvisorSnapshotBackend,
)

REAL_BOOT_ERROR = (
    b"running container: creating container: cannot create gofer process: "
    b"gofer: fork/exec /proc/self/exe: permission denied\n"
)
TEARDOWN_NOISE = b"FetchSpec failed: loading container: file does not exist\n"


def _write_stderr(target, payload: bytes) -> None:
    """Behave like runsc: write to the fd/file we were given, if we were given one."""
    if hasattr(target, "write"):
        target.write(payload)
        try:
            target.flush()
        except Exception:  # noqa: BLE001
            pass


def _backend(tmp_path: Path, run):
    (tmp_path / "rootfs").mkdir(parents=True, exist_ok=True)
    cfg = GvisorConfig(
        runsc_bin="runsc",
        root=tmp_path / "root",
        image_rootfs=tmp_path / "rootfs",
        network="none",
        warm_argv=["/usr/bin/true"],
    )
    return GvisorSnapshotBackend(cfg, run=run)


def test_the_boot_error_reaches_the_caller(tmp_path):
    calls: list[list[str]] = []

    def run(argv, **kw):
        calls.append([str(a) for a in argv])
        if "run" in argv:
            # Faithful to subprocess AND to runsc: it writes to whatever fd it was handed.
            # A fake that always supplies the text would pass even with stderr=DEVNULL
            # restored, which is the regression this test exists for. The launch is
            # DETACHED, so the capture target must be a file rather than a pipe -- see
            # test_a_detached_child_holding_stderr_does_not_block_the_launch.
            _write_stderr(kw.get("stderr"), REAL_BOOT_ERROR)
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=None)
        return 0   # teardown succeeds

    with pytest.raises(Exception) as caught:
        _backend(tmp_path, run).boot_base()

    message = str(caught.value)
    assert "cannot create gofer process" in message, (
        f"the boot's own stderr must reach the caller, got: {message}"
    )
    assert "FetchSpec" not in message, "the teardown's output must not be reported"


def test_the_teardown_does_not_print_over_the_real_error(tmp_path):
    """Its output is CAPTURED, so it cannot masquerade as the boot failure.

    Captured rather than discarded: this helper also runs during ordinary
    reaping, where a teardown failure is the actionable thing and its reason
    must survive (see `test_a_teardown_that_fails_entirely_reports_why`).
    """
    seen: list[dict] = []

    def run(argv, **kw):
        if "run" in argv:
            _write_stderr(kw.get("stderr"), REAL_BOOT_ERROR)
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=None)
        seen.append(kw)
        return 0

    with pytest.raises(Exception):
        _backend(tmp_path, run).boot_base()

    assert seen, "the teardown must have run"
    for kw in seen:
        assert kw.get("stderr") is subprocess.PIPE, (
            "teardown stderr must be captured, not inherited: it runs against a "
            "container that may never have existed, and its noise masked the "
            "real failure"
        )


def test_a_boot_failure_without_stderr_is_still_raised(tmp_path):
    """No captured output is not a reason to swallow the failure."""
    def run(argv, **kw):
        if "run" in argv:
            raise subprocess.CalledProcessError(1, argv)
        return 0

    with pytest.raises(Exception):
        _backend(tmp_path, run).boot_base()


REAL_RESTORE_ERROR = (
    b"loading checkpoint: unmarshalling: unexpected EOF\n"
)


def test_the_restore_error_reaches_the_caller(tmp_path):
    """Same treatment as the boot, and for the same reason.

    `CalledProcessError.__str__` omits captured stderr, so a bare re-raise left
    `SnapshotManager.restore()` reporting only a non-zero exit -- and with the
    teardown now quiet, that would be ALL an operator gets.
    """
    def run(argv, **kw):
        if "restore" in argv:
            _write_stderr(kw.get("stderr"), REAL_RESTORE_ERROR)
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=None)
        return 0

    with pytest.raises(Exception) as caught:
        _backend(tmp_path, run).restore_in(tmp_path / "slot", tmp_path / "artifact")
    assert "unmarshalling: unexpected EOF" in str(caught.value)


def test_a_failed_restore_teardown_keeps_its_kill_failed_marker(tmp_path):
    """SnapshotManager reads `kill_failed` to decide whether the checkpoint may
    be reclaimed. Replacing the exception must not drop it, or a generation an
    unmanaged sandbox is still using gets unpinned."""
    def run(argv, **kw):
        if "restore" in argv:
            _write_stderr(kw.get("stderr"), REAL_RESTORE_ERROR)
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=None)
        raise subprocess.CalledProcessError(1, argv)   # teardown fails too

    with pytest.raises(Exception) as caught:
        _backend(tmp_path, run).restore_in(tmp_path / "slot", tmp_path / "artifact")
    assert getattr(caught.value, "kill_failed", False) is True, (
        "the kill_failed marker must travel with the enriched error"
    )


def test_a_teardown_that_fails_entirely_reports_why(caplog, tmp_path):
    """The helper also runs during ORDINARY reaping, where the container existed.

    Silencing both streams there left callers able to log only "could not
    confirm teardown", with no reason for a quarantined slot or retained
    generation.
    """
    import logging

    from blastbox.host.runtime.gvisor_snapshot import _best_effort_delete

    cfg = GvisorConfig(
        runsc_bin="runsc", root=tmp_path / "root", image_rootfs=tmp_path / "rootfs",
        network="none", warm_argv=["/usr/bin/true"],
    )

    def run(argv, **kw):
        raise subprocess.CalledProcessError(
            1, argv, output=b"", stderr=b"permission denied opening /run/runsc\n"
        )

    with caplog.at_level(logging.WARNING):
        assert _best_effort_delete(cfg, run, "slot-abc") is False
    assert any("permission denied opening" in r.getMessage() for r in caplog.records), (
        f"the teardown's reason must be logged; got {[r.getMessage() for r in caplog.records]}"
    )


def test_a_detached_child_holding_stderr_does_not_block_the_launch(tmp_path):
    """A `-detach`ed sandbox INHERITS the stderr fd and holds it for its whole life.

    `subprocess.run(..., stderr=PIPE)` returns only at EOF on that pipe, so capturing a
    detached launch through a pipe waits for the guest to DIE. A guest that dies instantly
    closed the fd and the boot returned -- which is why this looked fine against a broken
    rootfs -- but a healthy warm base kept it open and the build hung: measured on toolz2 at
    >1500 s, with `ensure_build_started` refusing to start another build while that thread was
    alive, so the warm tier never rebuilt again.

    This drives the real runner with a fake runsc that detaches a child and exits, and pins the
    difference: a FILE returns at once, a PIPE waits for the child.
    """
    import time

    from blastbox.host.runtime.gvisor_snapshot import _default_run, _detached_stderr

    runsc = tmp_path / "runsc-detaching"
    # The background child inherits stderr and lives on, exactly like a detached sandbox.
    runsc.write_text("#!/bin/sh\nsleep 5 &\nexit 0\n")
    runsc.chmod(0o755)

    fh, path = _detached_stderr(tmp_path)
    try:
        started = time.monotonic()
        _default_run([str(runsc), "run", "-detach"], stderr=fh, timeout=30)
        file_elapsed = time.monotonic() - started
    finally:
        fh.close()
        path.unlink(missing_ok=True)

    assert file_elapsed < 2.0, (
        f"a file-captured detached launch waited {file_elapsed:.1f}s for the child"
    )

    # And the control, so the assertion above cannot pass for an unrelated reason: the pipe
    # form really does wait for the detached child.
    started = time.monotonic()
    _default_run([str(runsc), "run", "-detach"], stderr=subprocess.PIPE, timeout=30)
    pipe_elapsed = time.monotonic() - started

    assert pipe_elapsed > 3.0, (
        f"the pipe form returned in {pipe_elapsed:.1f}s -- this test no longer demonstrates "
        "the deadlock it exists to prevent"
    )
