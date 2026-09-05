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
            # Faithful to subprocess: stderr is only populated when the caller
            # asked to CAPTURE it. A fake that always supplies it would pass
            # even with stderr=DEVNULL restored, which is the regression here.
            captured = REAL_BOOT_ERROR if kw.get("stderr") is subprocess.PIPE else None
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=captured)
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
            captured = REAL_BOOT_ERROR if kw.get("stderr") is subprocess.PIPE else None
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=captured)
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
            captured = REAL_RESTORE_ERROR if kw.get("stderr") is subprocess.PIPE else None
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=captured)
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
            captured = REAL_RESTORE_ERROR if kw.get("stderr") is subprocess.PIPE else None
            raise subprocess.CalledProcessError(1, argv, output=b"", stderr=captured)
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
