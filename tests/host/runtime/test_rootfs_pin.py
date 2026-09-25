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
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda path, runtime: (calls.append(path) or "", True))
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
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda path, runtime: (verdict["now"], True))
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
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("guest is blastbox 0.0.1", True))
    with pytest.raises(SnapshotBuildError, match="0.0.1"):
        backend.boot_base()
    assert launcher.boots == []                   # refused BEFORE a microVM exists


def test_fc_restore_refuses_a_rootfs_changed_since_the_checkpoint(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("", True))
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
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("guest is blastbox 0.0.1", True))
    with pytest.raises(SnapshotBuildError, match="0.0.1"):
        backend.boot_base()
    assert not any("run" in c for c in rec.calls)


def test_gvisor_restore_refuses_a_rootfs_replaced_since_the_checkpoint(tmp_path,
                                                                        monkeypatch) -> None:
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("", True))
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
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("guest is blastbox 0.0.1", True))
    runner = _FakeSubprocessRunner()
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner,
                                ready_signal=_FakeReadySignal(ready=False))
    with pytest.raises(rfs.RootfsStampError, match="0.0.1"):
        rt.spawn()


# --- round 1 of review on the pin -----------------------------------------------------


def test_a_stale_restore_invalidates_the_base_at_once(tmp_path, monkeypatch) -> None:
    """The backend KNOWS the artifact can never be restored again; waiting for the pool's
    statistical repair drained the tier (49/49 refused, still is_built(); suppressed entirely
    inside the rebuild cooldown or with repair disabled)."""
    from blastbox.host.runtime.fc_snapshot import SnapshotManager

    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("", True))
    backend, _launcher, rootfs, _base = _fc_backend(tmp_path)
    mgr = SnapshotManager(tmp_path / "mgr", backend)
    mgr.build()
    mgr.restore("s1")
    _replace(rootfs, b"gen-2")
    with pytest.raises(SnapshotRestoreError, match="changed since"):
        mgr.restore("s2")
    assert not mgr.is_built()                     # dropped: the next tick rebuilds


def test_a_failed_stamp_read_is_not_cached_as_a_pass(tmp_path, monkeypatch) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    outcomes = iter([rfs.RootfsStampError("debugfs timed out"), None, None])

    def read(path, **kw):
        exc = next(outcomes)
        if exc:
            raise exc
        return rfs.RootfsStamp(blastbox_version="0.0.1", platform={})

    monkeypatch.setattr(rfs, "read", read)
    now = [1000.0]
    monkeypatch.setattr(rfs.time, "monotonic", lambda: now[0])
    gate = rfs.GuestGate(str(f), "firecracker")
    assert gate.problem() == ""                   # could not look: allowed, as before...
    now[0] += rfs.UNDECIDED_RETRY_S + 1
    assert "0.0.1" in gate.problem()              # ...but looked again, and refused


def test_an_unstamped_rootfs_is_a_definitive_verdict(tmp_path, monkeypatch) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    calls: list[int] = []

    def read(path, **kw):
        calls.append(1)
        raise rfs.RootfsUnstamped("carries no stamp")

    monkeypatch.setattr(rfs, "read", read)
    gate = rfs.GuestGate(str(f), "firecracker")
    gate.problem()
    gate.problem()
    assert len(calls) == 1


def test_the_host_version_is_the_running_code_not_the_disk(tmp_path, monkeypatch) -> None:
    """A pip upgrade under a running dispatcher changes installed metadata, not the code in
    memory; judging the guest against the disk admitted a guest newer than the host."""
    import importlib.metadata as md

    import blastbox

    tree = tmp_path / "rootfs"
    rfs.write_into_tree(tree, rfs.RootfsStamp(
        blastbox_version="99.0.0", platform={"runtime": "gvisor"}))
    monkeypatch.setattr(md, "version", lambda name: "99.0.0")      # upgraded on disk
    monkeypatch.setattr(blastbox, "__version__", "0.1.42")        # still running this
    assert "99.0.0" in rfs.guest_problem(str(tree), "gvisor")


def test_before_boot_refuses_a_rootfs_republished_while_it_was_checked(tmp_path,
                                                                      monkeypatch) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")

    def check_then_republish(path, runtime):
        _replace(f, b"two")
        return "", True

    monkeypatch.setattr(rfs, "guest_verdict", check_then_republish)
    with pytest.raises(rfs.RootfsStampError, match="changed while"):
        rfs.RootfsPin(str(f), "firecracker").before_boot()


def test_gvisor_directory_identity_ignores_runsc_creating_mountpoints(tmp_path) -> None:
    tree = tmp_path / "rootfs"
    rfs.write_into_tree(tree, rfs.RootfsStamp(blastbox_version="0.1.42"))
    before = rfs.file_identity(tree)
    (tree / "in").mkdir()                         # what `runsc run` does to a bare tree
    assert rfs.file_identity(tree) == before


def test_a_refused_plain_fc_guest_makes_the_tier_not_ready(tmp_path, monkeypatch) -> None:
    """Refusing only in spawn() spun the pool's spawn loop with a traceback per attempt
    (~690k error lines a day). prepare() False is the pool's quiet "not now"."""
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    verdict = {"now": ""}
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: (verdict["now"], True))
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=False))
    assert rt.prepare() is True
    verdict["now"] = "guest is blastbox 0.0.1"
    _replace(rootfs, b"gen-2")
    assert rt.prepare() is False


def test_the_plain_fc_gate_runs_after_the_stranded_scratch_sweep(tmp_path, monkeypatch) -> None:
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    monkeypatch.setattr(rfs, "guest_verdict",
                        lambda p, r: ("stale", True))
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=False))
    swept: list[int] = []
    monkeypatch.setattr(rt, "_sweep_stranded_scratch", lambda: swept.append(1))
    with pytest.raises(rfs.RootfsStampError):
        rt.spawn()
    assert swept == [1]


def test_a_verdict_read_across_a_republish_is_not_cached(tmp_path, monkeypatch) -> None:
    """The identity was sampled BEFORE the read: a republish mid-read cached file B's verdict
    under file A's identity."""
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    calls: list[int] = []

    def verdict(path, runtime):
        calls.append(1)
        if len(calls) == 1:
            _replace(f, b"two")                   # republished while this read ran
        return "", True

    monkeypatch.setattr(rfs, "guest_verdict", verdict)
    gate = rfs.GuestGate(str(f), "firecracker")
    gate.problem()
    assert gate._key is None                      # nothing cached for a file that moved
    gate.problem()
    assert len(calls) == 2
    assert gate._key == rfs.file_identity(f)      # a stable read IS cached


# --- round 2 of review on the pin -----------------------------------------------------


def test_an_undecidable_verdict_is_retried_at_most_once_per_interval(tmp_path,
                                                                    monkeypatch) -> None:
    """prepare() runs every tick. A failure that never changes for an unchanged file
    (debugfs missing, a bad-magic image) re-ran debugfs and a WARNING ten times a second."""
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"one")
    calls: list[int] = []
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: calls.append(1) or ("", False))
    now = [1000.0]
    monkeypatch.setattr(rfs.time, "monotonic", lambda: now[0])
    gate = rfs.GuestGate(str(f), "firecracker")
    for _ in range(20):
        gate.problem()
    assert len(calls) == 1
    now[0] += rfs.UNDECIDED_RETRY_S + 1
    gate.problem()
    assert len(calls) == 2


def test_concurrent_stale_restores_invalidate_once(tmp_path, monkeypatch) -> None:
    """The still-current check and the invalidate were separate lock holds: a second restore
    seeing the same stale artifact invalidated again and rejected the replacement build."""
    from blastbox.host.runtime.fc_snapshot import SnapshotManager

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, _launcher, _rootfs, _base = _fc_backend(tmp_path)
    mgr = SnapshotManager(tmp_path / "mgr", backend)
    old = mgr.build()
    epoch = mgr.build_epoch
    assert mgr.invalidate(only_if=old) is True
    assert mgr.invalidate(only_if=old) is False   # already superseded: a no-op
    assert mgr.build_epoch == epoch + 1
