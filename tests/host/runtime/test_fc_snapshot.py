"""Unit tests for FC snapshot/restore orchestration + SnapshotManager."""
from __future__ import annotations

import pytest

from blastbox.host.runtime.fc_api import FcApiError
from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotManager,
    SnapshotRestoreError,
    create_snapshot,
    restore_from_snapshot,
)


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


# --- create_snapshot / restore_from_snapshot ------------------------------


def test_create_snapshot_pauses_then_snapshots():
    api = FakeApi()
    create_snapshot(api, "/s/state", "/s/mem")
    assert api.calls == [
        ("PATCH", "/vm", {"state": "Paused"}),
        (
            "PUT",
            "/snapshot/create",
            {"snapshot_type": "Full", "snapshot_path": "/s/state", "mem_file_path": "/s/mem"},
        ),
    ]


def test_create_snapshot_wraps_api_error_as_build_error():
    api = FakeApi(fail_on=("PUT", "/snapshot/create"))
    with pytest.raises(SnapshotBuildError):
        create_snapshot(api, "/s/state", "/s/mem")


def test_restore_loads_mem_backend_and_resumes():
    api = FakeApi()
    restore_from_snapshot(api, "/s/state", "/s/mem")
    assert api.calls == [
        (
            "PUT",
            "/snapshot/load",
            {
                "snapshot_path": "/s/state",
                "mem_backend": {"backend_type": "File", "backend_path": "/s/mem"},
                "enable_diff_snapshots": False,
                "resume_vm": True,
            },
        ),
    ]


def test_restore_respects_resume_false():
    api = FakeApi()
    restore_from_snapshot(api, "/s/state", "/s/mem", resume=False)
    assert api.calls[0][2]["resume_vm"] is False


def test_restore_wraps_api_error_as_restore_error():
    api = FakeApi(fail_on=("PUT", "/snapshot/load"))
    with pytest.raises(SnapshotRestoreError):
        restore_from_snapshot(api, "/s/state", "/s/mem")


# --- SnapshotManager (fake launcher) --------------------------------------


class FakeBoot:
    def __init__(self, api, ready_ok=True):
        self.api = api
        self._ready_ok = ready_ok
        self.killed = False

    def wait_ready(self, timeout_s):
        if not self._ready_ok:
            raise TimeoutError("never became ready")

    def kill(self):
        self.killed = True


class FakeRestore:
    def __init__(self, api, vsock_uds):
        self.api = api
        self.vsock_uds = vsock_uds


class FakeLauncher:
    def __init__(self, ready_ok=True):
        self._ready_ok = ready_ok
        self.boots = []
        self.restores = []
        self.last_boot = None

    def boot_base(self):
        self.last_boot = FakeBoot(FakeApi(), self._ready_ok)
        self.boots.append(self.last_boot)
        return self.last_boot

    def restore_in(self, slot_workdir):
        h = FakeRestore(FakeApi(), vsock_uds=str(slot_workdir / "vsock.sock"))
        self.restores.append(h)
        return h


def test_build_snapshots_then_kills_base(tmp_path):
    launcher = FakeLauncher()
    art = SnapshotManager(tmp_path, launcher).build()
    assert art.snapshot_path == tmp_path / "warm.snapshot"
    assert art.mem_path == tmp_path / "warm.mem"
    assert launcher.last_boot.killed is True
    assert (
        "PUT",
        "/snapshot/create",
        {
            "snapshot_type": "Full",
            "snapshot_path": str(tmp_path / "warm.snapshot"),
            "mem_file_path": str(tmp_path / "warm.mem"),
        },
    ) in launcher.last_boot.api.calls


def test_build_is_idempotent(tmp_path):
    launcher = FakeLauncher()
    mgr = SnapshotManager(tmp_path, launcher)
    a = mgr.build()
    b = mgr.build()
    assert a is b
    assert len(launcher.boots) == 1  # built exactly once


def test_build_kills_base_even_on_failure(tmp_path):
    launcher = FakeLauncher(ready_ok=False)  # readiness times out
    mgr = SnapshotManager(tmp_path, launcher)
    with pytest.raises(SnapshotBuildError):
        mgr.build()
    assert launcher.last_boot.killed is True  # torn down in finally
    assert mgr.artifact is None


def test_restore_uses_unique_per_slot_workdir(tmp_path):
    launcher = FakeLauncher()
    mgr = SnapshotManager(tmp_path, launcher)
    mgr.build()
    h7 = mgr.restore("slot-7")
    h8 = mgr.restore("slot-8")
    assert h7.vsock_uds != h8.vsock_uds  # per-slot uniqueness via workdir
    assert (tmp_path / "slots" / "slot-7").is_dir()
    assert any(c[0:2] == ("PUT", "/snapshot/load") for c in launcher.restores[0].api.calls)


def test_restore_before_build_raises(tmp_path):
    with pytest.raises(SnapshotRestoreError):
        SnapshotManager(tmp_path, FakeLauncher()).restore("slot-1")
