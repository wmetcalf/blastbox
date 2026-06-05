"""Unit tests for the runtime-agnostic SnapshotManager.

The manager talks only to the :class:`SnapshotBackend` seam and round-trips an
OPAQUE artifact (it never inspects it). FC-specific mechanics
(create_snapshot/restore_from_snapshot/resolve_mem_dir, the FcSnapshotArtifact,
the FcSnapshotBackend wiring) are tested in ``test_fc_snapshot_backend.py``.
"""
from __future__ import annotations

import pytest

from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotManager,
    SnapshotRestoreError,
)


# --- fake backend (the seam) ----------------------------------------------


class FakeBoot:
    def __init__(self, artifact, *, ready_ok=True):
        self._artifact = artifact
        self._ready_ok = ready_ok
        self.killed = False
        self.checkpoint_dest = None

    def wait_ready(self, timeout_s):
        if not self._ready_ok:
            raise TimeoutError("never became ready")

    def checkpoint(self, dest_dir):
        self.checkpoint_dest = dest_dir
        return self._artifact

    def kill(self):
        self.killed = True


class FakeRestore:
    def __init__(self, slot_workdir, artifact):
        self.slot_workdir = slot_workdir
        self.artifact = artifact
        self.killed = False

    def kill(self):  # satisfies the RestoreHandle protocol
        self.killed = True


class FakeBackend:
    """An opaque-artifact backend the manager drives. ``artifact`` is an arbitrary
    sentinel object the manager must round-trip unchanged into ``restore_in``."""

    def __init__(self, *, ready_ok=True, artifact=None):
        self._ready_ok = ready_ok
        self.artifact = artifact if artifact is not None else object()
        self.boots = []
        self.restores = []
        self.last_boot = None

    def available(self):
        return True

    def boot_base(self):
        self.last_boot = FakeBoot(self.artifact, ready_ok=self._ready_ok)
        self.boots.append(self.last_boot)
        return self.last_boot

    def restore_in(self, slot_workdir, artifact):
        h = FakeRestore(slot_workdir, artifact)
        self.restores.append(h)
        return h


# --- build -----------------------------------------------------------------


def test_build_waits_ready_checkpoints_then_kills_base(tmp_path):
    backend = FakeBackend()
    mgr = SnapshotManager(tmp_path, backend)
    art = mgr.build()
    assert art is backend.artifact  # opaque artifact returned unchanged
    assert backend.last_boot.killed is True
    # checkpoint is written under/near the manager's base_dir
    assert backend.last_boot.checkpoint_dest == tmp_path


def test_build_returns_opaque_artifact_unchanged(tmp_path):
    sentinel = {"this": "is opaque", "n": 3}
    backend = FakeBackend(artifact=sentinel)
    art = SnapshotManager(tmp_path, backend).build()
    assert art is sentinel  # manager never reshapes the artifact


def test_build_is_idempotent(tmp_path):
    backend = FakeBackend()
    mgr = SnapshotManager(tmp_path, backend)
    a = mgr.build()
    b = mgr.build()
    assert a is b
    assert len(backend.boots) == 1  # built exactly once
    assert mgr.artifact is a


def test_build_kills_base_even_on_failure(tmp_path):
    backend = FakeBackend(ready_ok=False)  # readiness times out
    mgr = SnapshotManager(tmp_path, backend)
    with pytest.raises(SnapshotBuildError):
        mgr.build()
    assert backend.last_boot.killed is True  # torn down in finally
    assert mgr.artifact is None


def test_build_wraps_boot_base_failure_as_build_error(tmp_path):
    class BoomBackend(FakeBackend):
        def boot_base(self):
            raise RuntimeError("no kvm")

    with pytest.raises(SnapshotBuildError):
        SnapshotManager(tmp_path, BoomBackend()).build()


def test_build_preserves_snapshot_error_subclasses(tmp_path):
    """A backend that raises a SnapshotError (e.g. SnapshotBuildError) is NOT
    re-wrapped — it propagates as-is (the `except SnapshotError: raise` arm)."""
    class BoomBackend(FakeBackend):
        def boot_base(self):
            raise SnapshotBuildError("backend already chose the error")

    with pytest.raises(SnapshotBuildError, match="backend already chose"):
        SnapshotManager(tmp_path, BoomBackend()).build()


# --- restore ---------------------------------------------------------------


def test_restore_passes_opaque_artifact_to_backend(tmp_path):
    sentinel = object()
    backend = FakeBackend(artifact=sentinel)
    mgr = SnapshotManager(tmp_path, backend)
    mgr.build()
    handle = mgr.restore("slot-7")
    # the manager handed the exact artifact back to restore_in, unmodified
    assert handle.artifact is sentinel
    assert handle.slot_workdir == tmp_path / "slots" / "slot-7"


def test_restore_uses_unique_per_slot_workdir(tmp_path):
    backend = FakeBackend()
    mgr = SnapshotManager(tmp_path, backend)
    mgr.build()
    h7 = mgr.restore("slot-7")
    h8 = mgr.restore("slot-8")
    assert h7.slot_workdir != h8.slot_workdir
    assert (tmp_path / "slots" / "slot-7").is_dir()
    assert (tmp_path / "slots" / "slot-8").is_dir()
    assert len(backend.restores) == 2


def test_restore_before_build_raises(tmp_path):
    with pytest.raises(SnapshotRestoreError):
        SnapshotManager(tmp_path, FakeBackend()).restore("slot-1")


def test_restore_rejects_unsafe_slot_id(tmp_path):
    """slot_id becomes a path segment under slots/ — traversal/odd values rejected."""
    mgr = SnapshotManager(tmp_path, FakeBackend())
    mgr.build()
    for bad in ("", "../escape", "a/b", "..", ".", "x\x00y"):
        with pytest.raises(SnapshotRestoreError, match="unsafe slot_id"):
            mgr.restore(bad)


def test_restore_wraps_backend_failure_as_restore_error(tmp_path):
    class BoomBackend(FakeBackend):
        def restore_in(self, slot_workdir, artifact):
            raise RuntimeError("load failed")

    mgr = SnapshotManager(tmp_path, BoomBackend())
    mgr.build()
    with pytest.raises(SnapshotRestoreError):
        mgr.restore("slot-x")


def test_restore_preserves_snapshot_error_subclasses(tmp_path):
    class BoomBackend(FakeBackend):
        def restore_in(self, slot_workdir, artifact):
            raise SnapshotRestoreError("backend already chose the error")

    mgr = SnapshotManager(tmp_path, BoomBackend())
    mgr.build()
    with pytest.raises(SnapshotRestoreError, match="backend already chose"):
        mgr.restore("slot-x")
