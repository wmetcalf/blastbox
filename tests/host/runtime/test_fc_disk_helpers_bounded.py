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


class TestWhatTheBoundsChanged:
    """Follow-ups from review: introducing a timeout changes failure ATTRIBUTION and cleanup."""

    def test_a_disk_timeout_is_a_host_failure_not_a_tier_failure(self):
        """`is_host_resource_failure` only knew OSError errnos, and TimeoutExpired is not an
        OSError -- so repeated filesystem stalls would walk the pool's restore streak and the
        cascade's per-tier streak until a HEALTHY snapshot base was invalidated, punishing the
        tier for the disk."""
        from blastbox.errors import is_host_resource_failure

        assert is_host_resource_failure(subprocess.TimeoutExpired(cmd="cp", timeout=1))

        # Through the cause chain, which is how it actually arrives (a launcher wraps it).
        try:
            try:
                raise subprocess.TimeoutExpired(cmd="cp", timeout=1)
            except subprocess.TimeoutExpired as inner:
                raise RuntimeError("snapshot restore failed") from inner
        except RuntimeError as outer:
            assert is_host_resource_failure(outer), "the wrapped timeout was blamed on the tier"

        assert not is_host_resource_failure(RuntimeError("an ordinary tier failure"))

    def test_the_python_fallback_is_bounded_too(self, tmp_path, monkeypatch):
        """`cp` missing or without --reflink (a BusyBox image) lands in the fallback
        immediately -- and an unbounded copyfile there means the documented bound does not
        hold on the very path the fallback exists for."""
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        src = tmp_path / "base.ext4"
        src.write_bytes(b"x" * (8 << 20))          # 8 MiB, several chunks
        dst = tmp_path / "slot.ext4"

        started = time.monotonic()
        with pytest.raises(subprocess.TimeoutExpired):
            fl._copy_with_deadline(src, dst, 0.0)   # deadline already passed
        elapsed = time.monotonic() - started

        assert elapsed < 10, f"the bounded copy took {elapsed:.0f}s"
        assert not dst.exists(), (
            "a truncated outdisk was left behind; the guest would mount it"
        )

    def test_the_bounded_copy_still_copies(self, tmp_path):
        """The control: the bound must not break the copy it guards."""
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        src = tmp_path / "base.ext4"
        src.write_bytes(b"payload" * 1000)
        dst = tmp_path / "slot.ext4"

        fl._copy_with_deadline(src, dst, 60.0)

        assert dst.read_bytes() == src.read_bytes()

    def test_a_spawn_that_cannot_format_its_disk_removes_its_scratch_dir(
        self, tmp_path, monkeypatch
    ):
        """The exception escapes before a Slot exists, so the pool has nothing to hand
        reap(): every retry would leave another directory and partial image behind."""
        from blastbox.host.runtime import firecracker as fc

        scratch = tmp_path / "scratch"
        scratch.mkdir()

        class _Cfg:
            fc_outdisk_mib = 8

        rt = object.__new__(fc.FirecrackerSlotRuntime)
        rt._scratch_root = scratch          # type: ignore[attr-defined]
        rt._cfg = _Cfg()                    # type: ignore[attr-defined]

        monkeypatch.setattr(
            fc, "make_ext4",
            lambda p, m: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd="mkfs", timeout=1)),
        )

        for _ in range(5):
            with pytest.raises(subprocess.TimeoutExpired):
                fc.FirecrackerSlotRuntime.spawn(rt)

        leftovers = list(scratch.iterdir())
        assert not leftovers, f"5 failed spawns left scratch dirs behind: {leftovers}"

    def test_a_restore_whose_terminate_is_unconfirmed_retains_the_orphan(
        self, tmp_path, monkeypatch
    ):
        """`_terminate_proc` returning False means the process survived terminate AND kill.

        Ignoring that -- which restore_in did -- let SnapshotManager.restore() remove the
        workdir and forget the spawn, leaving a microVM neither the pool nor shutdown can
        account for, still holding that workdir's disk and sockets. Especially likely in the
        filesystem-stall case the copy timeout exists for, since firecracker is blocked on the
        same disk. boot_base already followed this rule; restore_in did not.
        """
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        base_dir = tmp_path / "base_dir"
        (base_dir / "base").mkdir(parents=True)
        base_outdisk = base_dir / "base" / fl.REL_OUTDISK
        base_outdisk.parent.mkdir(parents=True, exist_ok=True)
        base_outdisk.write_bytes(b"base image")

        launcher = object.__new__(fl.FcSnapshotLauncher)
        launcher._base_dir = base_dir                       # type: ignore[attr-defined]
        launcher._stranded_partials = []                    # type: ignore[attr-defined]
        launcher._spawn = lambda wd: (object(), object())   # type: ignore[attr-defined]
        launcher._copy_outdisk = (                          # type: ignore[attr-defined]
            lambda s, d: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="cp", timeout=1)
            )
        )
        monkeypatch.setattr(fl, "_terminate_proc", lambda p: False)   # survived both

        slot_wd = tmp_path / "slot"
        slot_wd.mkdir()
        with pytest.raises(subprocess.TimeoutExpired):
            fl.FcSnapshotLauncher.restore_in(launcher, slot_wd)

        assert str(slot_wd) in launcher._stranded_partials, (
            "an unconfirmed firecracker was forgotten; nothing can account for or reap it"
        )

    def test_the_no_cp_fallback_path_is_bounded_end_to_end(self, tmp_path, monkeypatch):
        """Through `_default_copy_outdisk`, not the helper directly.

        Testing `_copy_with_deadline` alone leaves the WIRING unverified: reverting the
        fallback to a bare `shutil.copyfile` passed that test, because it never went through
        the fallback at all.
        """
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        empty = tmp_path / "emptybin"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))              # no `cp`: straight to the fallback
        monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "0.001")
        src = tmp_path / "base.ext4"
        src.write_bytes(b"x" * (8 << 20))
        dst = tmp_path / "slot.ext4"

        with pytest.raises(subprocess.TimeoutExpired):
            fl._default_copy_outdisk(src, dst)

        assert not dst.exists(), "a truncated outdisk survived the bounded fallback"
