"""Unit tests for the FC snapshot launcher (Phase 2 orchestration)."""
from __future__ import annotations

from pathlib import Path

from blastbox.host.runtime.fc_snapshot_launcher import (
    REL_OUTDISK,
    REL_VSOCK,
    FcSnapshotLauncher,
    api_boot_sequence,
)


class FakeCfg:
    fc_bin = "/opt/kata/bin/firecracker"
    fc_kernel = "/assets/vmlinux"
    fc_rootfs = "/assets/rootfs.ext4"
    fc_vcpu_count = 1
    fc_mem_mib = 1024
    fc_vsock_guest_cid = 3


# --- api_boot_sequence (pure) ---------------------------------------------


def test_api_boot_sequence_mirrors_cold_config_and_starts_last():
    seq = api_boot_sequence(FakeCfg())
    assert [p for p, _ in seq] == [
        "/boot-source",
        "/drives/rootfs",
        "/drives/outdisk",
        "/machine-config",
        "/vsock",
        "/actions",
    ]
    bodies = dict(seq)
    assert bodies["/boot-source"]["kernel_image_path"] == "/assets/vmlinux"
    assert bodies["/drives/rootfs"]["path_on_host"] == "/assets/rootfs.ext4"
    assert bodies["/drives/rootfs"]["is_read_only"] is True
    # writable per-slot resources are RELATIVE (the per-slot-cwd mechanism)
    assert bodies["/drives/outdisk"]["path_on_host"] == REL_OUTDISK
    assert bodies["/vsock"]["uds_path"] == REL_VSOCK
    assert bodies["/machine-config"] == {
        "vcpu_count": 1,
        "mem_size_mib": 1024,
        "smt": False,
    }
    assert seq[-1] == ("/actions", {"action_type": "InstanceStart"})


def test_api_boot_sequence_paths_overridable():
    seq = dict(api_boot_sequence(FakeCfg(), vsock_uds="/abs/v.sock", outdisk_path="/abs/o.ext4"))
    assert seq["/vsock"]["uds_path"] == "/abs/v.sock"
    assert seq["/drives/outdisk"]["path_on_host"] == "/abs/o.ext4"


# --- launcher (injected deps) ---------------------------------------------


class FakeApi:
    def __init__(self, sock):
        self.sock = sock
        self.calls = []

    def put(self, path, body=None):
        self.calls.append((path, body))
        return 204


class FakeProc:
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


def test_boot_base_uses_api_socket_and_runs_full_config(tmp_path):
    spawned = []
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append((argv, cwd)) or FakeProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: None,
    )
    handle = launcher.boot_base()

    argv, cwd = spawned[0]
    assert argv[0] == "/opt/kata/bin/firecracker"
    assert "--api-sock" in argv
    assert "--no-api" not in argv and "--config-file" not in argv
    assert cwd == str(tmp_path / "snap" / "base")
    assert [p for p, _ in handle.api.calls] == [
        "/boot-source",
        "/drives/rootfs",
        "/drives/outdisk",
        "/machine-config",
        "/vsock",
        "/actions",
    ]
    assert handle.vsock_uds == str(tmp_path / "snap" / "base" / REL_VSOCK)


def test_restore_in_spawns_in_slot_cwd_and_copies_base_outdisk(tmp_path):
    spawned = []
    made = []
    copied = []
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append((argv, cwd)) or FakeProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: made.append(Path(p)),
        copy_outdisk=lambda src, dst: copied.append((Path(src), Path(dst))),
    )
    # The base outdisk (copy source) must exist for restore_in to proceed.
    (tmp_path / "snap" / "base").mkdir(parents=True)
    (tmp_path / "snap" / "base" / REL_OUTDISK).write_bytes(b"")
    slot = tmp_path / "snap" / "slots" / "slot-7"
    handle = launcher.restore_in(slot)

    _, cwd = spawned[0]
    assert cwd == str(slot)  # firecracker runs in the per-slot cwd
    assert handle.vsock_uds == str(slot / REL_VSOCK)
    # The per-slot disk is a COPY of the base outdisk (snapshot-time-consistent ext4),
    # NOT a fresh mkfs — a fresh mkfs corrupts the restored guest's cached ext4 state.
    assert made == []  # no fresh mkfs on restore
    assert copied == [
        (tmp_path / "snap" / "base" / REL_OUTDISK, slot / REL_OUTDISK)
    ]


def test_spawn_kills_proc_when_api_socket_never_appears(tmp_path):
    """_spawn must terminate the spawned firecracker if the API socket times out."""
    class TrackProc:
        def __init__(self):
            self.terminated = False
        def poll(self):
            return None
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            return 0

    proc = TrackProc()

    def never_ready(p):
        raise TimeoutError("api socket never appeared")

    launcher = FcSnapshotLauncher(
        FakeCfg(), tmp_path,
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=never_ready,
        make_outdisk=lambda p: None,
    )
    import pytest
    with pytest.raises(TimeoutError):
        launcher.boot_base()
    assert proc.terminated is True


class _TrackProc:
    def __init__(self):
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


def test_boot_base_kills_proc_when_post_spawn_step_fails(tmp_path):
    """If make_outdisk / the boot PUTs raise AFTER _spawn, the FC proc must be killed
    (the caller never gets a _Handle to kill, so boot_base must do it)."""
    import pytest

    proc = _TrackProc()

    def boom(p):
        raise OSError("ENOSPC making outdisk")

    launcher = FcSnapshotLauncher(
        FakeCfg(), tmp_path / "snap",
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=boom,
    )
    with pytest.raises(OSError):
        launcher.boot_base()
    assert proc.terminated is True


def test_restore_in_kills_proc_when_copy_fails(tmp_path):
    """If the outdisk copy raises after _spawn, the restored FC proc must be killed."""
    import pytest

    proc = _TrackProc()
    base = tmp_path / "snap"
    (base / "base").mkdir(parents=True)
    (base / "base" / REL_OUTDISK).write_bytes(b"")  # base outdisk exists

    def boom(src, dst):
        raise OSError("disk full copying outdisk")

    launcher = FcSnapshotLauncher(
        FakeCfg(), base,
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: None,
        copy_outdisk=boom,
    )
    with pytest.raises(OSError):
        launcher.restore_in(base / "slots" / "s1")
    assert proc.terminated is True


def test_restore_in_raises_and_does_not_spawn_when_base_outdisk_missing(tmp_path):
    """No base outdisk → fail fast with FileNotFoundError and never spawn FC."""
    import pytest

    spawned = []
    launcher = FcSnapshotLauncher(
        FakeCfg(), tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append(1) or _TrackProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: None,
        copy_outdisk=lambda s, d: None,
    )
    with pytest.raises(FileNotFoundError):
        launcher.restore_in(tmp_path / "snap" / "slots" / "s1")
    assert spawned == []  # never spawned FC since the source is missing
