"""The rootfs is checked where it is BOOTED, not only at dispatcher start.

`build-images` publishes a rootfs in place, while a dispatcher that selected its tier hours ago
keeps booting from that path. Two failures follow:

* a new guest release boots unchecked on the next slot spawn or base rebuild -- the 300s
  timeout the stamp exists to prevent;
* a snapshot restore attaches the NEW rootfs file under a memory snapshot of the OLD one --
  the ext4 checksum corruption class generation-stamping the outdisk already guards against,
  left open for the shared rootfs.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blastbox.host import rootfs_stamp as rfs
from blastbox.host.runtime.fc_snapshot import SnapshotBuildError, SnapshotRestoreError


def _replace(path: Path, body: bytes) -> None:
    """Publish in place the way build-images does: a new file renamed over the old."""
    tmp = path.with_suffix(".new")
    tmp.write_bytes(body)
    os.replace(tmp, path)


# --- identity + the cached gate ------------------------------------------------------------


def test_identity_changes_when_the_file_is_republished(tmp_path) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    before = rfs.file_identity(f)
    assert rfs.file_identity(f) == before
    _replace(f, b"two")
    assert rfs.file_identity(f) != before
    assert rfs.file_identity(tmp_path / "missing") is None


def test_the_gate_rereads_the_stamp_only_when_the_file_changes(tmp_path, monkeypatch) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    calls: list[str] = []
    monkeypatch.setattr(rfs, "guest_problem",
                        lambda path, runtime: calls.append(path) or "")
    gate = rfs.GuestGate(str(f), "firecracker")
    for _ in range(5):
        assert gate.problem() == ""
    assert len(calls) == 1                        # cached: no debugfs per spawn
    _replace(f, b"two")
    gate.problem()
    assert len(calls) == 2


def test_the_gate_reports_a_republished_stale_guest(tmp_path, monkeypatch) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    verdict = {"now": ""}
    monkeypatch.setattr(rfs, "guest_problem", lambda path, runtime: verdict["now"])
    gate = rfs.GuestGate(str(f), "firecracker")
    assert gate.problem() == ""
    verdict["now"] = "guest is blastbox 0.0.1"
    _replace(f, b"two")
    assert "0.0.1" in gate.problem()


# --- Firecracker snapshot backend ----------------------------------------------------------


def _fc_backend(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotBackend

    from .test_fc_snapshot_backend import FakeLauncher

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    base = tmp_path / "base"
    launcher = FakeLauncher(base, base)
    launcher._cfg = type("Cfg", (), {"fc_rootfs": str(rootfs)})()
    return FcSnapshotBackend(base, launcher), launcher, rootfs, base


def test_fc_base_boot_refuses_a_stale_guest(tmp_path, monkeypatch) -> None:
    backend, launcher, _rootfs, _base = _fc_backend(tmp_path)
    monkeypatch.setattr(rfs, "guest_problem", lambda p, r: "guest is blastbox 0.0.1")
    with pytest.raises(SnapshotBuildError, match="0.0.1"):
        backend.boot_base()
    assert launcher.boots == []                   # refused BEFORE a microVM exists


def test_fc_restore_refuses_a_rootfs_changed_since_the_checkpoint(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rfs, "guest_problem", lambda p, r: "")
    backend, launcher, rootfs, base = _fc_backend(tmp_path)
    art = backend.boot_base().checkpoint(base)
    backend.restore_in(tmp_path / "s1", art)      # same disk: fine
    _replace(rootfs, b"gen-2")
    with pytest.raises(SnapshotRestoreError, match="changed since"):
        backend.restore_in(tmp_path / "s2", art)
    assert len(launcher.restores) == 1            # refused before spawning firecracker


# --- gVisor snapshot backend ---------------------------------------------------------------


def _gv_backend(tmp_path):
    from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend

    from .test_gvisor_snapshot import _cfg, _Rec

    rec = _Rec()
    (tmp_path / "rootfs").mkdir()
    return GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None), rec


def test_gvisor_base_boot_refuses_a_stale_guest(tmp_path, monkeypatch) -> None:
    backend, rec = _gv_backend(tmp_path)
    monkeypatch.setattr(rfs, "guest_problem", lambda p, r: "guest is blastbox 0.0.1")
    with pytest.raises(SnapshotBuildError, match="0.0.1"):
        backend.boot_base()
    assert not any("run" in c for c in rec.calls)


def test_gvisor_restore_refuses_a_rootfs_replaced_since_the_checkpoint(tmp_path,
                                                                        monkeypatch) -> None:
    monkeypatch.setattr(rfs, "guest_problem", lambda p, r: "")
    backend, rec = _gv_backend(tmp_path)
    boot = backend.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    # Published the way build-images does a directory rootfs: a new tree moved into place.
    new = tmp_path / "rootfs.new"
    new.mkdir()
    os.rename(tmp_path / "rootfs", tmp_path / "rootfs.old")
    os.rename(new, tmp_path / "rootfs")
    with pytest.raises(SnapshotRestoreError, match="changed since"):
        backend.restore_in(tmp_path / "slots" / "s1", art)


# --- plain Firecracker: every spawn boots the rootfs -------------------------------------


def test_a_plain_fc_spawn_refuses_a_republished_stale_guest(tmp_path, monkeypatch) -> None:
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    monkeypatch.setattr(rfs, "guest_problem", lambda p, r: "guest is blastbox 0.0.1")
    runner = _FakeSubprocessRunner()
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner,
                                ready_signal=_FakeReadySignal(ready=False))
    with pytest.raises(rfs.RootfsStampError, match="0.0.1"):
        rt.spawn()
