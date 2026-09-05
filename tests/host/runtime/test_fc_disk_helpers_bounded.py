"""The FC tier's host disk helpers run on the per-slot spawn path and must be bounded.

`subprocess.run` has no default timeout. `mkfs.ext4` (per-slot output disk) and the
`cp --reflink=auto` of the base outdisk both ran unbounded, so a stalled filesystem -- a wedged
overlay/NFS mount, a device error -- blocked the spawning thread with nothing to time it out.

The pool survives that, but not for free: `stop()` reports "background thread still running
(wedged spawn?)", and the in-flight spawn stays uncommitted while still counting against node
RAM/vCPU budget that no live worker is using. The sibling helpers in this module (debugfs
rdump, e2fsck) were already bounded; these two were not.

These tests EXECUTE a hanging stand-in rather than asserting a kwarg: a runner that accepted
`timeout=` and dropped it would satisfy any kwarg assertion (that exact mutation survived the
kwarg-only tests on the gVisor side).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest


# Long enough that a BOUNDED call (1 s) must time out, short enough that an UNBOUNDED one
# still returns -- so removing the bound makes these tests FAIL on "DID NOT RAISE" in ~20 s
# instead of hanging. A test that hangs instead of failing is its own defect.
_STALL_S = 20


def _hanging(tmp_path: Path, name: str) -> Path:
    """A stand-in binary that stalls, with `exec` so the kill lands on the sleep itself."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(f"#!/bin/sh\nexec sleep {_STALL_S}\n")
    p.chmod(0o755)
    return d


def test_make_ext4_is_bounded(tmp_path, monkeypatch):
    from blastbox.host.runtime.firecracker import make_ext4

    bin_dir = _hanging(tmp_path, "mkfs.ext4")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        make_ext4(tmp_path / "out.ext4", 8)
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"make_ext4 ran unbounded: it took {elapsed:.0f}s"


def test_the_outdisk_copy_is_bounded(tmp_path, monkeypatch):
    from blastbox.host.runtime.fc_snapshot_launcher import _default_copy_outdisk

    bin_dir = _hanging(tmp_path, "cp")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")
    src = tmp_path / "base.ext4"
    src.write_bytes(b"x" * 1024)

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _default_copy_outdisk(src, tmp_path / "slot.ext4")
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"the outdisk copy ran unbounded: it took {elapsed:.0f}s"


def test_a_timed_out_copy_does_not_fall_back_to_a_python_copy(tmp_path, monkeypatch):
    """The fallback is for "no cp, odd platform". A cp that TIMED OUT means the filesystem is
    stalled, and copying the same bytes again in Python stalls the same way -- spending the
    budget twice and turning a bounded failure back into a hang."""
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    bin_dir = _hanging(tmp_path, "cp")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")
    src = tmp_path / "base.ext4"
    src.write_bytes(b"x" * 1024)

    fell_back: list[bool] = []
    monkeypatch.setattr(fl.shutil, "copyfile",
                        lambda a, b: fell_back.append(True))

    with pytest.raises(subprocess.TimeoutExpired):
        fl._default_copy_outdisk(src, tmp_path / "slot.ext4")

    assert not fell_back, "a timed-out copy fell through to the Python fallback"


def test_a_missing_cp_still_falls_back(tmp_path, monkeypatch):
    """The control: the fallback this bound must not break."""
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))       # no `cp` anywhere
    src = tmp_path / "base.ext4"
    src.write_bytes(b"payload")
    dst = tmp_path / "slot.ext4"

    fl._default_copy_outdisk(src, dst)

    assert dst.read_bytes() == b"payload", "the no-cp fallback stopped working"
