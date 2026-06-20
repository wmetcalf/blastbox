"""Unit tests for the warm-snapshot SlotRuntime (no real Firecracker).

The SnapshotManager + launcher are faked, so these exercise the SlotRuntime
contract (spawn = build-once + restore; is_ready/is_alive track the restore;
reap kills + cleans) and the builder's manager wiring."""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host.pool import SlotState
from blastbox.host.runtime.fc_snapshot_runtime import (
    SnapshotSlotRuntime,
    select_snapshot_runtime,
)


class FakeProc:
    def __init__(self) -> None:
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def die(self) -> None:
        self._alive = False


class FakeHandle:
    def __init__(self, vsock_uds: Path) -> None:
        self.proc = FakeProc()
        self.vsock_uds = str(vsock_uds)
        self.killed = False

    def kill(self) -> None:
        self.killed = True
        self.proc.die()


class FakeManager:
    """Stands in for SnapshotManager: build() is idempotent-ish (counts calls);
    restore() creates a per-slot workdir + a touched vsock.sock like the launcher."""

    def __init__(self, base: Path) -> None:
        self._base = Path(base)
        self.builds = 0
        self.restored: list[str] = []
        self.handles: dict[str, FakeHandle] = {}

    def build(self):
        self.builds += 1
        return object()

    def restore(self, slot_id):
        wd = self._base / "slots" / str(slot_id)
        wd.mkdir(parents=True, exist_ok=True)
        vsock = wd / "vsock.sock"
        vsock.touch()  # FC re-creates the per-slot vsock on restore
        h = FakeHandle(vsock)
        self.restored.append(str(slot_id))
        self.handles[str(slot_id)] = h
        return h


class FakeCfg:
    max_extracted_bytes = 1024 * 1024


def _runtime(tmp_path):
    # settle_s=0 → is_ready is immediate (the post-restore settle is tested separately).
    mgr = FakeManager(tmp_path)
    return SnapshotSlotRuntime(FakeCfg(), mgr, settle_s=0.0), mgr


# --- spawn -----------------------------------------------------------------


def test_spawn_builds_and_restores(tmp_path):
    rt, mgr = _runtime(tmp_path)
    slot = rt.spawn()
    assert mgr.builds >= 1  # snapshot built (idempotent in the real manager)
    assert mgr.restored == [slot.slot_id]
    assert slot.state is SlotState.WARMING
    # spawn created the per-slot scratch dirs derived from the restore workdir.
    assert slot.output_dir.is_dir()
    assert slot.input_dir.is_dir()
    assert slot.output_dir.parent == tmp_path / "slots" / slot.slot_id


def test_spawn_unique_slots(tmp_path):
    rt, mgr = _runtime(tmp_path)
    a = rt.spawn()
    b = rt.spawn()
    assert a.slot_id != b.slot_id
    assert len(mgr.restored) == 2


# --- is_ready / is_alive ---------------------------------------------------


def test_is_ready_true_when_alive_and_vsock_present(tmp_path):
    rt, _ = _runtime(tmp_path)
    slot = rt.spawn()
    assert rt.is_ready(slot) is True


def test_is_ready_false_when_vsock_missing(tmp_path):
    rt, mgr = _runtime(tmp_path)
    slot = rt.spawn()
    Path(mgr.handles[slot.slot_id].vsock_uds).unlink()
    assert rt.is_ready(slot) is False


def test_is_ready_holds_during_settle_window(tmp_path):
    """is_ready stays False until the post-restore vsock settle window elapses
    (prevents pushing a job into a not-yet-ready restored vsock → ENOTCONN)."""
    now = [100.0]
    mgr = FakeManager(tmp_path)
    rt = SnapshotSlotRuntime(FakeCfg(), mgr, settle_s=3.0, clock=lambda: now[0])
    slot = rt.spawn()  # restored_at = 100.0
    assert rt.is_ready(slot) is False  # 0s elapsed
    now[0] = 102.9
    assert rt.is_ready(slot) is False  # still inside the 3s window
    now[0] = 103.1
    assert rt.is_ready(slot) is True   # settle elapsed → promotable
    assert rt.is_alive(slot) is True   # is_alive is NOT gated by settle


def test_is_ready_false_when_proc_dead(tmp_path):
    rt, mgr = _runtime(tmp_path)
    slot = rt.spawn()
    mgr.handles[slot.slot_id].proc.die()
    assert rt.is_ready(slot) is False
    assert rt.is_alive(slot) is False


def test_is_alive_false_for_unknown_slot(tmp_path):
    rt, _ = _runtime(tmp_path)
    slot = rt.spawn()
    rt.reap(slot)
    assert rt.is_alive(slot) is False


# --- reap ------------------------------------------------------------------


def test_reap_kills_handle_and_removes_workdir(tmp_path):
    rt, mgr = _runtime(tmp_path)
    slot = rt.spawn()
    handle = mgr.handles[slot.slot_id]
    workdir = slot.output_dir.parent
    assert workdir.exists()
    rt.reap(slot)
    assert handle.killed is True
    assert not workdir.exists()


def test_reap_is_safe_on_unknown_slot(tmp_path):
    rt, _ = _runtime(tmp_path)
    slot = rt.spawn()
    rt.reap(slot)
    rt.reap(slot)  # double reap must not raise


def test_reap_swallows_kill_errors(tmp_path):
    rt, mgr = _runtime(tmp_path)
    slot = rt.spawn()

    def boom():
        raise RuntimeError("kill failed")

    mgr.handles[slot.slot_id].kill = boom  # type: ignore[method-assign]
    rt.reap(slot)  # must not propagate
    assert not slot.output_dir.parent.exists()


# --- warm-path seam --------------------------------------------------------


def test_read_output_disk_missing_raises(tmp_path):
    from blastbox.host.runtime.firecracker import FCError

    rt, _ = _runtime(tmp_path)
    slot = rt.spawn()  # no outdisk.ext4 created by the fake
    with pytest.raises(FCError):
        rt.read_output_disk(slot)


def test_host_warm_control_points_at_slot_vsock(tmp_path):
    rt, _ = _runtime(tmp_path)
    slot = rt.spawn()
    ctrl = rt.host_warm_control(slot)
    # VsockHostWarmControl stores the uds; assert it targets the per-slot vsock.
    expected = slot.output_dir.parent / "vsock.sock"
    assert str(expected) in repr(vars(ctrl))


# --- builder ---------------------------------------------------------------


def test_select_snapshot_runtime_uses_injected_manager(tmp_path):
    mgr = FakeManager(tmp_path)
    rt = select_snapshot_runtime(cfg=FakeCfg(), manager=mgr)
    assert isinstance(rt, SnapshotSlotRuntime)
    # The injected manager drives spawn (no FCConfig.from_env / availability needed).
    slot = rt.spawn()
    assert mgr.restored == [slot.slot_id]


def test_select_snapshot_runtime_refuses_old_guest_kernel(tmp_path, monkeypatch):
    """A guest kernel < 5.18 (no VMGenID) is refused for the snapshot tier:
    restoring a snapshot clones the CRNG and an old guest won't reseed on restore."""
    import blastbox.host.runtime.firecracker as fc_mod
    from blastbox.host.runtime.firecracker import FCConfig, FCUnavailable

    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"\x00Linux version 5.10.0 (ci@fc) gcc\x00")
    rootfs = tmp_path / "rootfs.ext4"
    rootfs.touch()
    cfg = FCConfig(
        fc_bin="firecracker",
        fc_kernel=str(vmlinux),
        fc_rootfs=str(rootfs),
        scratch_root=str(tmp_path),
    )
    # Pass the binary/kvm/FC-version prerequisites so the KERNEL gate is what fires.
    monkeypatch.setattr(fc_mod, "firecracker_available", lambda c: True)

    with pytest.raises(FCUnavailable):
        select_snapshot_runtime(cfg=cfg, require_available=True)
    # Soft path: refuse quietly (falls back to cold FC) rather than raise.
    assert select_snapshot_runtime(cfg=cfg, require_available=False) is None
