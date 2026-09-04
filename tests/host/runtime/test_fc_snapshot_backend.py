"""Unit tests for the Firecracker SnapshotBackend (the FC mechanics behind the seam).

These cover the FC-specific pieces that used to live on the manager:
- ``_create_snapshot`` / ``_restore_from_snapshot`` (the FC API call sequences),
- ``resolve_mem_dir`` + ``FcSnapshotBackend.from_env`` (the RAM-preload toggle),
- ``boot_base().checkpoint(dest)`` producing an ``FcSnapshotArtifact``, and
- ``restore_in`` issuing load+resume and exposing the per-slot vsock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host.runtime.fc_api import FcApiError
from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotRestoreError,
)
from blastbox.host.runtime.fc_snapshot_backend import (
    FcSnapshotArtifact,
    FcSnapshotBackend,
    _create_snapshot,
    _restore_from_snapshot,
    resolve_mem_dir,
)


# --- FC test doubles (copied from the old test_fc_snapshot.py) -------------


class FakeApi:
    def __init__(self, fail_on=None):
        self.calls = []
        self._fail_on = fail_on  # (method, path) to raise FcApiError on

    def put(self, path, body=None):
        self.calls.append(("PUT", path, body))
        if self._fail_on == ("PUT", path):
            raise FcApiError("PUT", path, 400, "bad request")
        return 204

    def patch(self, path, body=None):
        self.calls.append(("PATCH", path, body))
        if self._fail_on == ("PATCH", path):
            raise FcApiError("PATCH", path, 400, "bad request")
        return 204


# --- _create_snapshot / _restore_from_snapshot ----------------------------


def test_create_snapshot_pauses_then_snapshots():
    api = FakeApi()
    _create_snapshot(api, "/s/state", "/s/mem")
    assert api.calls == [
        ("PATCH", "/vm", {"state": "Paused"}),
        (
            "PUT",
            "/snapshot/create",
            {
                "snapshot_type": "Full",
                "snapshot_path": "/s/state",
                "mem_file_path": "/s/mem",
            },
        ),
    ]


def test_create_snapshot_wraps_api_error_as_build_error():
    api = FakeApi(fail_on=("PUT", "/snapshot/create"))
    with pytest.raises(SnapshotBuildError):
        _create_snapshot(api, "/s/state", "/s/mem")


def test_restore_loads_mem_backend_and_resumes():
    api = FakeApi()
    _restore_from_snapshot(api, "/s/state", "/s/mem")
    assert api.calls == [
        (
            "PUT",
            "/snapshot/load",
            {
                "snapshot_path": "/s/state",
                "mem_backend": {"backend_type": "File", "backend_path": "/s/mem"},
                "track_dirty_pages": False,
                "resume_vm": True,
            },
        ),
    ]


def test_restore_respects_resume_false():
    api = FakeApi()
    _restore_from_snapshot(api, "/s/state", "/s/mem", resume=False)
    assert api.calls[0][2]["resume_vm"] is False


def test_restore_wraps_api_error_as_restore_error():
    api = FakeApi(fail_on=("PUT", "/snapshot/load"))
    with pytest.raises(SnapshotRestoreError):
        _restore_from_snapshot(api, "/s/state", "/s/mem")


# --- RAM-preload toggle (resolve_mem_dir / from_env) ----------------------


def test_resolve_mem_dir_default_off(monkeypatch):
    """Unset toggle → None (mem stays on disk; safe on a low-RAM host)."""
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", raising=False)
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_DIR", raising=False)
    assert resolve_mem_dir() is None


def test_resolve_mem_dir_tmpfs_toggle(monkeypatch):
    """BLASTBOX_SNAPSHOT_MEM_TMPFS truthy → the default tmpfs /dev/shm."""
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_DIR", raising=False)
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", "1")
    assert resolve_mem_dir() == Path("/dev/shm")


def test_resolve_mem_dir_tmpfs_falsey_is_off(monkeypatch):
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_DIR", raising=False)
    for val in ("0", "false", "no", ""):
        monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", val)
        assert resolve_mem_dir() is None


def test_resolve_mem_dir_explicit_dir_wins(monkeypatch):
    """Explicit dir beats the tmpfs toggle (for non-/dev/shm tmpfs mounts)."""
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", "1")
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_DIR", "/mnt/hugeram")
    assert resolve_mem_dir() == Path("/mnt/hugeram")


def test_from_env_default_off_keeps_mem_on_base(tmp_path, monkeypatch):
    """Default OFF → from_env falls back to base_dir for the mem file."""
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", raising=False)
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_DIR", raising=False)
    backend = FcSnapshotBackend.from_env(tmp_path, object())
    assert backend.mem_dir == tmp_path


def test_from_env_tmpfs_toggle_points_mem_at_dev_shm(tmp_path, monkeypatch):
    """BLASTBOX_SNAPSHOT_MEM_TMPFS=1 → from_env points mem_dir at /dev/shm."""
    monkeypatch.delenv("BLASTBOX_SNAPSHOT_MEM_DIR", raising=False)
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", "1")
    backend = FcSnapshotBackend.from_env(tmp_path, object())
    assert backend.mem_dir == Path("/dev/shm")


def test_from_env_explicit_mem_dir_env(tmp_path, monkeypatch):
    """BLASTBOX_SNAPSHOT_MEM_DIR=<path> → from_env honors it."""
    ram = tmp_path / "ram"
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_DIR", str(ram))
    backend = FcSnapshotBackend.from_env(tmp_path / "base", object())
    assert backend.mem_dir == ram


def test_from_env_explicit_mem_dir_arg_overrides_env(tmp_path, monkeypatch):
    """An explicit mem_dir= arg short-circuits env resolution."""
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS", "1")  # would pick /dev/shm
    arg_dir = tmp_path / "explicit"
    backend = FcSnapshotBackend.from_env(tmp_path / "base", object(), mem_dir=arg_dir)
    assert backend.mem_dir == arg_dir


# --- boot_base().checkpoint + restore_in (fake launcher) ------------------


class FakeBootHandle:
    """A boot handle whose checkpoint() PATCHes /vm + PUTs /snapshot/create Full,
    like the real launcher._Handle, writing mem under mem_dir."""

    def __init__(self, base_dir: Path, mem_dir: Path):
        self.api = FakeApi()
        self._base_dir = Path(base_dir)
        self._mem_dir = Path(mem_dir)
        self.killed = False

    def wait_ready(self, timeout_s):
        pass

    def checkpoint(self, dest_dir):
        from blastbox.host.runtime.fc_snapshot_backend import _create_snapshot

        dest = Path(dest_dir)
        snap = dest / "warm.snapshot"
        mem = self._mem_dir / "warm.mem"
        _create_snapshot(self.api, str(snap), str(mem))
        return FcSnapshotArtifact(snap, mem)

    def kill(self):
        self.killed = True


class FakeRestoreHandle:
    def __init__(self, slot_workdir: Path, *, fail_load=False):
        self.api = FakeApi(fail_on=("PUT", "/snapshot/load") if fail_load else None)
        self.vsock_uds = str(Path(slot_workdir) / "vsock.sock")
        self.killed = False

    def kill(self):
        self.killed = True


class FakeLauncher:
    def __init__(self, base_dir: Path, mem_dir: Path, *, fail_load=False):
        self._base_dir = Path(base_dir)
        self._mem_dir = Path(mem_dir)
        self._fail_load = fail_load
        self.boots = []
        self.restores = []

    def boot_base(self):
        h = FakeBootHandle(self._base_dir, self._mem_dir)
        self.boots.append(h)
        return h

    def restore_in(self, slot_workdir, *, outdisk_src=None):
        h = FakeRestoreHandle(slot_workdir, fail_load=self._fail_load)
        self.restores.append(h)
        return h


def test_boot_base_checkpoint_pauses_creates_full_and_returns_artifact(tmp_path):
    base = tmp_path / "base"
    memdir = tmp_path / "ram"
    backend = FcSnapshotBackend(base, FakeLauncher(base, memdir), mem_dir=memdir)
    boot = backend.boot_base()
    art = boot.checkpoint(base)

    assert isinstance(art, FcSnapshotArtifact)
    assert art.snapshot_path == base / "warm.snapshot"
    assert art.mem_path == memdir / "warm.mem"  # mem under mem_dir
    # checkpoint PATCHed /vm Paused then PUT /snapshot/create Full with mem under mem_dir
    assert boot.api.calls == [
        ("PATCH", "/vm", {"state": "Paused"}),
        (
            "PUT",
            "/snapshot/create",
            {
                "snapshot_type": "Full",
                "snapshot_path": str(base / "warm.snapshot"),
                "mem_file_path": str(memdir / "warm.mem"),
            },
        ),
    ]


def test_restore_in_loads_resumes_and_exposes_vsock(tmp_path):
    base = tmp_path / "base"
    backend = FcSnapshotBackend(base, FakeLauncher(base, base))
    artifact = FcSnapshotArtifact(base / "warm.snapshot", base / "warm.mem")
    slot = base / "slots" / "slot-7"
    handle = backend.restore_in(slot, artifact)

    # restore_in PUT /snapshot/load with mem_backend File + resume.
    assert handle.api.calls == [
        (
            "PUT",
            "/snapshot/load",
            {
                "snapshot_path": str(base / "warm.snapshot"),
                "mem_backend": {
                    "backend_type": "File",
                    "backend_path": str(base / "warm.mem"),
                },
                "track_dirty_pages": False,
                "resume_vm": True,
            },
        ),
    ]
    # the handle exposes the per-slot vsock (read by SnapshotSlotRuntime)
    assert handle.vsock_uds == str(slot / "vsock.sock")
    assert handle.killed is False


def test_restore_in_kills_handle_on_load_failure(tmp_path):
    """If /snapshot/load fails, the spawned firecracker must be killed (no leak)."""
    base = tmp_path / "base"
    backend = FcSnapshotBackend(base, FakeLauncher(base, base, fail_load=True))
    artifact = FcSnapshotArtifact(base / "warm.snapshot", base / "warm.mem")
    with pytest.raises(SnapshotRestoreError):
        backend.restore_in(base / "slots" / "s1", artifact)
    assert backend._launcher.restores[0].killed is True


def test_available_is_true(tmp_path):
    backend = FcSnapshotBackend(tmp_path, FakeLauncher(tmp_path, tmp_path))
    assert backend.available() is True


def test_restore_tears_down_firecracker_on_cancellation(tmp_path):
    """A cancellation must not leave an unmanaged microVM behind.

    The cleanup caught only Exception, so a KeyboardInterrupt/SystemExit landing after the spawn
    skipped it entirely — leaving firecracker running with the memory file mapped, while the
    manager unpinned the generation and a later invalidation could unlink it underneath.
    """
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact

    killed: list[bool] = []

    class _Handle:
        api = object()
        vsock_uds = str(tmp_path / "vsock.sock")

        def kill(self):
            killed.append(True)

    class _Launcher:
        def restore_in(self, slot_workdir, *, outdisk_src=None):
            return _Handle()

    be = FcSnapshotBackend.__new__(FcSnapshotBackend)
    be._launcher = _Launcher()  # type: ignore[attr-defined]

    art = FcSnapshotArtifact(tmp_path / "s.snapshot", tmp_path / "m.mem", None)

    mp = pytest.MonkeyPatch()
    mp.setattr(
        "blastbox.host.runtime.fc_snapshot_backend._restore_from_snapshot",
        lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt("cancelled")),
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            be.restore_in(tmp_path / "slot", art)
    finally:
        mp.undo()

    assert killed, "a cancelled restore must still terminate the firecracker it spawned"
