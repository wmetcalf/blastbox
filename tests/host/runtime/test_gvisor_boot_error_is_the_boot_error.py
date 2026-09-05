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


def test_the_teardown_is_quiet(tmp_path):
    """Its failures are reported by the return value, not by printing."""
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
        assert kw.get("stderr") is subprocess.DEVNULL, (
            "teardown stderr must be silenced: it runs against a container that "
            "may never have existed, and its noise masked the real failure"
        )


def test_a_boot_failure_without_stderr_is_still_raised(tmp_path):
    """No captured output is not a reason to swallow the failure."""
    def run(argv, **kw):
        if "run" in argv:
            raise subprocess.CalledProcessError(1, argv)
        return 0

    with pytest.raises(Exception):
        _backend(tmp_path, run).boot_base()
