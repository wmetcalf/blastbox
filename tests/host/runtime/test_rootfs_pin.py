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

from .test_fc_snapshot import _wait_until


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
    assert _wait_until(rt.prepare)                # checked (in the background), then ready
    verdict["now"] = "guest is blastbox 0.0.1"
    _replace(rootfs, b"gen-2")
    assert _wait_until(lambda: rt.prepare() is False
                       and rt._gate().problem_nowait() not in ("", rfs.PENDING))


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



def test_a_rootfs_swapped_while_the_restore_opened_it_is_aborted(tmp_path, monkeypatch) -> None:
    """The pre-check samples the PATH; the runtime opens it later. A publish in between paired
    the old memory with the new disk. Re-checked once the runtime holds the file open."""
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, launcher, rootfs, base = _fc_backend(tmp_path)
    art = backend.boot_base().checkpoint(base)
    real = launcher.restore_in

    def restore_while_publishing(slot_workdir, **kw):
        _replace(rootfs, b"gen-2")                # lands after the check, before the open
        return real(slot_workdir, **kw)

    launcher.restore_in = restore_while_publishing
    with pytest.raises(SnapshotRestoreError, match="changed"):
        backend.restore_in(tmp_path / "s1", art)
    assert launcher.restores[-1].killed           # the restored VM is not left running


# --- codex bot, fourth pass --------------------------------------------------------------


def test_a_plain_fc_slot_whose_rootfs_changed_before_it_booted_is_not_promoted(
        tmp_path, monkeypatch) -> None:
    """The spawn-time check samples the PATH; firecracker opens it later. A publish in between
    boots an unchecked guest. READY is the first moment the disk is known to be open, so a
    rootfs that changed since the check is not promoted -- the slot is killed instead."""
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=True))
    monkeypatch.setattr("blastbox.host.runtime.firecracker.make_ext4", lambda p, mib: p.touch())
    ok = rt.spawn()
    assert rt.is_ready(ok) is True                # unchanged: promoted
    stale = rt.spawn()
    _replace(rootfs, b"gen-2")                    # published before this guest booted
    killed: list[str] = []
    monkeypatch.setattr(rt._procs[stale.slot_id], "kill", lambda: killed.append(stale.slot_id))
    assert rt.is_ready(stale) is False
    assert killed == [stale.slot_id]


def test_a_stale_gvisor_restore_that_cannot_be_deleted_is_kept_for_retry(tmp_path,
                                                                         monkeypatch) -> None:
    from blastbox.host.runtime import gvisor_snapshot as gs

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, rec = _gv_backend(tmp_path)
    boot = backend.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    real_run = backend._run

    def run_then_republish(argv, **kw):
        rc = real_run(argv, **kw)
        if "restore" in argv:                     # the tree changes under the restore
            new = tmp_path / "rootfs.new"
            new.mkdir()
            os.rename(tmp_path / "rootfs", tmp_path / "rootfs.old")
            os.rename(new, tmp_path / "rootfs")
        return rc

    backend._run = run_then_republish
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, cid: False)
    with pytest.raises(SnapshotRestoreError, match="changed") as info:
        backend.restore_in(tmp_path / "slots" / "s1", art)
    assert getattr(info.value, "kill_failed", False) is True
    # The SANDBOX is what must be retried: the directory sweep only rmtrees, and removing the
    # bundle under a live sandbox is worse than leaving it. Kept as (cid, workdir).
    (cid, wd), = backend._stranded_sandboxes
    assert cid.startswith("slot-") and wd == str(tmp_path / "slots" / "s1")
    assert wd not in backend._stranded_partials
    # The next boot retries `runsc delete` first; only once the sandbox is gone does its
    # bundle go to the directory sweep.
    deleted: list[str] = []
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, c: deleted.append(c) or True)
    backend.boot_base()                           # kicks the (background) retry
    assert _wait_until(lambda: cid in deleted and backend._stranded_sandboxes == [])


def test_a_failed_restore_that_cannot_be_deleted_retries_the_sandbox_too(tmp_path,
                                                                         monkeypatch) -> None:
    """The pre-existing failed-restore path recorded only the workdir, which the sweep can
    rmtree but never `runsc delete` -- the sandbox itself was never retried."""
    from blastbox.host.runtime import gvisor_snapshot as gs

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, rec = _gv_backend(tmp_path)
    boot = backend.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    real_run = backend._run

    def restore_fails(argv, **kw):
        if "restore" in argv:
            raise RuntimeError("runsc restore failed")
        return real_run(argv, **kw)

    backend._run = restore_fails
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, cid: False)
    with pytest.raises(Exception):
        backend.restore_in(tmp_path / "slots" / "s2", art)
    assert [wd for _cid, wd in backend._stranded_sandboxes] == [str(tmp_path / "slots" / "s2")]


def test_a_held_pin_is_released_once_the_backend_reaps_its_sandbox(tmp_path, monkeypatch) -> None:
    """kill_failed keeps the generation pinned -- right while a sandbox may still use it -- but
    the failed restore returned no handle to reap, so once the backend's retry DID reap the
    sandbox, nothing released the pin: the generation stayed referenced until restart."""
    from blastbox.host.runtime import gvisor_snapshot as gs
    from blastbox.host.runtime.fc_snapshot import SnapshotManager

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, _rec = _gv_backend(tmp_path)
    mgr = SnapshotManager(tmp_path / "mgr", backend)
    art = mgr.build()
    real_run = backend._run

    def restore_fails(argv, **kw):
        if "restore" in argv:
            raise RuntimeError("runsc restore failed")
        return real_run(argv, **kw)

    backend._run = restore_fails
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, cid: False)
    with pytest.raises(Exception):
        mgr.restore("s1")
    assert mgr._refs.get(id(art), 0) == 1         # held: a sandbox may still map it
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, cid: True)

    def tick_released() -> bool:
        mgr.ensure_build_started()                # pool ticks; the retry runs in the background
        return mgr._refs.get(id(art), 0) == 0

    assert _wait_until(tick_released)             # released once the sandbox is confirmed gone
    assert "s1" not in mgr._held_restores



# --- codex bot, seventh pass --------------------------------------------------------------


def test_a_plain_fc_slot_is_refused_before_ready_if_its_rootfs_changed(tmp_path,
                                                                     monkeypatch) -> None:
    """A mismatched guest may NEVER signal READY; gated on readiness, it survived the whole
    warm-up timeout instead of being rejected at once."""
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"gen-1")
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=False))
    monkeypatch.setattr("blastbox.host.runtime.firecracker.make_ext4", lambda p, mib: p.touch())
    slot = rt.spawn()
    _replace(rootfs, b"gen-2")
    killed: list[str] = []
    monkeypatch.setattr(rt._procs[slot.slot_id], "kill", lambda: killed.append(slot.slot_id))
    assert rt.is_ready(slot) is False
    assert killed == [slot.slot_id]               # not left to time out


def test_a_sandbox_being_retried_is_not_reported_reclaimed(tmp_path, monkeypatch) -> None:
    """The retry emptied the ledger BEFORE its slow deletes finished, so a concurrent
    restore_reclaimed() saw nothing pending and released the pin under a live sandbox."""
    import threading

    from blastbox.host.runtime import gvisor_snapshot as gs

    backend, _rec = _gv_backend(tmp_path)
    backend._strand_sandbox("slot-aaa", tmp_path / "slots" / "s1")
    entered, release = threading.Event(), threading.Event()

    def slow_delete(cfg, run, cid):
        entered.set()
        release.wait(5)
        return False                              # ...and it FAILS

    monkeypatch.setattr(gs, "_best_effort_delete", slow_delete)
    t = threading.Thread(target=backend._retry_stranded_sandboxes)
    t.start()
    assert entered.wait(5)
    assert backend.restore_reclaimed(str(tmp_path / "slots" / "s1")) is False
    release.set()
    t.join(5)
    assert [c for c, _wd in backend._stranded_sandboxes] == ["slot-aaa"]



# --- codex bot, eighth pass ---------------------------------------------------------------


def test_the_opened_inode_catches_an_aba_republish(tmp_path) -> None:
    """A publish of B over A and a rollback to A before the post-open check: the PATH is A
    again, but the process holds B. Only the inode actually opened can tell."""
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"A")
    key = rfs.file_identity(f)
    os.link(f, tmp_path / "A.bak")                # the rollback's backup of A
    _replace(f, b"B")
    held = open(f, "rb")                          # "firecracker" opens B
    try:
        os.replace(tmp_path / "A.bak", f)         # rolled back: the path is A (same inode)
        assert rfs.file_identity(f) == key        # the path check alone is fooled
        assert rfs.opened_matches(os.getpid(), str(f), key) is False
    finally:
        held.close()


def test_the_opened_inode_confirms_the_pinned_file(tmp_path) -> None:
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"A")
    key = rfs.file_identity(f)
    with open(f, "rb"):
        assert rfs.opened_matches(os.getpid(), str(f), key) is True
    assert rfs.opened_matches(2**31 - 7, str(f), key) is None     # unknowable: no such pid


def test_restore_reclaimed_never_blocks_on_a_wedged_delete(tmp_path, monkeypatch) -> None:
    """It runs on the pool tick; runsc kill/delete are bounded only by cli_timeout_s (900s)
    each, so a wedged sandbox held the maintenance thread for up to half an hour."""
    import threading
    import time as _t

    from blastbox.host.runtime import gvisor_snapshot as gs

    backend, _rec = _gv_backend(tmp_path)
    backend._strand_sandbox("slot-bbb", tmp_path / "slots" / "s9")
    release = threading.Event()
    monkeypatch.setattr(gs, "_best_effort_delete", lambda cfg, run, cid: release.wait(5) and False)
    t0 = _t.monotonic()
    assert backend.restore_reclaimed(str(tmp_path / "slots" / "s9")) is False
    assert _t.monotonic() - t0 < 1.0
    release.set()



# --- codex bot, ninth pass ----------------------------------------------------------------


def test_a_base_that_opened_a_different_rootfs_is_not_pinned(tmp_path, monkeypatch) -> None:
    """A publish rolled back between before_boot() and the checkpoint left the PATH at A while
    the base had opened B; the pin then recorded A and every restore passed."""
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"A")
    pin = rfs.RootfsPin(str(f), "firecracker")
    key = pin.before_boot()
    os.link(f, tmp_path / "A.bak")
    _replace(f, b"B")
    held = open(f, "rb")                          # the base booted B
    try:
        os.replace(tmp_path / "A.bak", f)         # rolled back before the checkpoint

        class Base:
            proc = type("P", (), {"pid": os.getpid()})()

            def checkpoint(self, dest):
                return "artifact-x"

        with pytest.raises(rfs.RootfsStampError, match="different file"):
            pin.wrap(Base(), key).checkpoint(tmp_path)
    finally:
        held.close()


def test_a_plain_fc_slot_is_judged_by_the_inode_it_opened(tmp_path, monkeypatch) -> None:
    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"A")
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=True))
    monkeypatch.setattr("blastbox.host.runtime.firecracker.make_ext4", lambda p, mib: p.touch())
    slot = rt.spawn()
    os.link(rootfs, tmp_path / "A.bak")
    _replace(rootfs, b"B")
    held = open(rootfs, "rb")                     # "firecracker" opened B
    try:
        os.replace(tmp_path / "A.bak", rootfs)    # path shows A again
        monkeypatch.setattr(rt._procs[slot.slot_id], "kill", lambda: None)
        monkeypatch.setattr(rt._procs[slot.slot_id], "pid", os.getpid(), raising=False)
        assert rt.is_ready(slot) is False
    finally:
        held.close()


def test_a_stamp_with_no_version_is_a_warning_not_a_refusal(tmp_path, caplog) -> None:
    """A guest with no blastbox installed (a pure-JVM worker) is valid -- verify_built accepts
    it -- so its version is unchecked, loudly, rather than refused; arch/runtime still apply."""
    tree = tmp_path / "rootfs"
    rfs.write_into_tree(tree, rfs.RootfsStamp(blastbox_version="", platform={
        "arch": __import__("platform").machine(), "runtime": "gvisor"}))
    with caplog.at_level("WARNING"):
        assert rfs.guest_problem(str(tree), "gvisor") == ""
    assert "no blastbox version" in caplog.text



def test_a_held_firecracker_restore_is_released_once_its_process_is_gone(tmp_path,
                                                                        monkeypatch) -> None:
    """Only gVisor answered restore_reclaimed(); an FC restore whose kill failed kept its pin
    and workdir for the dispatcher's life."""
    from blastbox.host.runtime.fc_snapshot import SnapshotManager

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, launcher, _rootfs, _base = _fc_backend(tmp_path)
    mgr = SnapshotManager(tmp_path / "mgr", backend)
    art = mgr.build()
    real = launcher.restore_in
    alive = {"v": True}

    def failing_restore(slot_workdir, **kw):
        h = real(slot_workdir, **kw)
        h.api._fail_on = ("PUT", "/snapshot/load")

        def kill():
            raise RuntimeError("could not kill firecracker")

        h.kill = kill
        h.proc = type("P", (), {"poll": lambda self: None if alive["v"] else 0, "pid": 0})()
        return h

    launcher.restore_in = failing_restore
    with pytest.raises(Exception):
        mgr.restore("s1")
    assert mgr._refs.get(id(art), 0) == 1          # held: the VM may still map it
    mgr.ensure_build_started()
    assert mgr._refs.get(id(art), 0) == 1          # still alive: still held
    held_wd = next(iter(mgr._held_restores.values()))[1]
    assert Path(held_wd).exists()                  # kept while the VM may still use it
    alive["v"] = False                             # the process finally exits
    mgr.ensure_build_started()
    assert mgr._refs.get(id(art), 0) == 0
    assert not Path(held_wd).exists()              # ...and reclaimed with the pin


# --- codex bot, thirteenth pass -----------------------------------------------------------


def test_an_unknown_held_fc_restore_is_not_reported_reclaimed(tmp_path) -> None:
    """A pre-handle failure (outdisk copy failed, terminate unconfirmed) is held by the manager
    but was never recorded here; answering True released the pin under a live VM."""
    backend, _launcher, _rootfs, _base = _fc_backend(tmp_path)
    assert backend.restore_reclaimed(str(tmp_path / "never-seen")) is False


def test_a_pre_handle_fc_failure_keeps_its_process_for_reclaim(tmp_path, monkeypatch) -> None:
    backend, launcher, _rootfs, base = _fc_backend(tmp_path)
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    art = backend.boot_base().checkpoint(base)
    alive = {"v": True}
    orphan = type("P", (), {"poll": lambda self: None if alive["v"] else 0, "pid": 0,
                            "kill": lambda self: None, "terminate": lambda self: None,
                            "wait": lambda self, timeout=None: 0})()

    def pre_handle_failure(slot_workdir, **kw):
        exc = OSError("outdisk copy failed")
        exc.kill_failed = True                    # type: ignore[attr-defined]
        exc.orphan_proc = orphan                  # type: ignore[attr-defined]
        raise exc

    launcher.restore_in = pre_handle_failure
    wd = tmp_path / "s1"
    with pytest.raises(OSError):
        backend.restore_in(wd, art)
    assert backend.restore_reclaimed(str(wd)) is False
    alive["v"] = False
    assert _wait_until(lambda: backend.restore_reclaimed(str(wd)))


def test_restore_reclaimed_never_waits_on_a_kill(tmp_path, monkeypatch) -> None:
    """_Handle.kill() waits up to 5s after terminate and 5s after kill -- on the pool tick."""
    import threading
    import time as _t

    backend, _launcher, _rootfs, _base = _fc_backend(tmp_path)
    release = threading.Event()
    slow = type("H", (), {"proc": type("P", (), {"poll": lambda self: None, "pid": 0})(),
                          "kill": lambda self: release.wait(5)})()
    backend._unreaped[str(tmp_path / "s9")] = slow
    t0 = _t.monotonic()
    assert backend.restore_reclaimed(str(tmp_path / "s9")) is False
    assert _t.monotonic() - t0 < 1.0
    release.set()


def test_fc_prepare_never_waits_on_a_stamp_read(tmp_path, monkeypatch) -> None:
    """prepare() runs on the pool tick; a stalled debugfs held it for the full deadline."""
    import threading
    import time as _t

    from blastbox.host.runtime.firecracker import FCConfig, FirecrackerSlotRuntime

    from .test_firecracker import _FakeReadySignal, _FakeSubprocessRunner

    rootfs = tmp_path / "rootfs.ext4"
    rootfs.write_bytes(b"A")
    release = threading.Event()
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: (release.wait(5), ("", True))[1])
    cfg = FCConfig(fc_bin="firecracker", fc_kernel="/mnt/vmlinux", fc_rootfs=str(rootfs),
                   fc_vcpu_count=1, fc_mem_mib=256, fc_outdisk_mib=64,
                   scratch_root=str(tmp_path / "scratch"))
    rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(),
                                ready_signal=_FakeReadySignal(ready=False))
    t0 = _t.monotonic()
    assert rt.prepare() is False                  # not ready until the guest has been checked
    assert _t.monotonic() - t0 < 1.0
    release.set()
    assert _wait_until(rt.prepare)


def test_a_held_restore_is_released_exactly_once(tmp_path, monkeypatch) -> None:
    """Two concurrent ticks both copied the held entry and both unpinned it -- decrementing the
    generation's refcount twice, under another slot still using it."""
    import threading

    from blastbox.host.runtime.fc_snapshot import SnapshotManager

    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    backend, _launcher, _rootfs, _base = _fc_backend(tmp_path)
    mgr = SnapshotManager(tmp_path / "mgr", backend)
    art = mgr.build()
    mgr.restore("live")                           # another slot uses this generation
    mgr._refs[id(art)] += 1                        # the held (failed) restore's reference
    mgr._hold_restore("held", art, tmp_path / "held")
    gate = threading.Barrier(2)

    def reclaimed(workdir):
        gate.wait(5)                              # both ticks inside at once
        return True

    backend.restore_reclaimed = reclaimed
    ts = [threading.Thread(target=mgr._release_held_restores) for _ in range(2)]
    [t.start() for t in ts]
    [t.join(5) for t in ts]
    assert mgr._refs.get(id(art), 0) == 1         # only the held reference was released



def test_a_rootfs_missing_mid_publish_is_not_a_pass(tmp_path, monkeypatch) -> None:
    """Between removing the old file and installing the new, the rootfs does not exist; a
    check answering "" with no identity let a spawn boot the new file unchecked and left the
    snapshot unbound to any disk."""
    monkeypatch.setattr(rfs, "guest_verdict", lambda p, r: ("", True))
    missing = tmp_path / "rootfs.ext4"
    gate = rfs.GuestGate(str(missing), "firecracker")
    assert "missing" in gate.checked()[0]
    assert gate.problem_nowait() not in ("", rfs.PENDING)
    with pytest.raises(rfs.RootfsStampError, match="missing"):
        rfs.RootfsPin(str(missing), "firecracker").before_boot()
    assert rfs.GuestGate("", "firecracker").checked() == ("", None)   # none configured: no-op
