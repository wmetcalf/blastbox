"""Unit tests for the runtime-agnostic SnapshotManager.

The manager talks only to the :class:`SnapshotBackend` seam and round-trips an
OPAQUE artifact (it never inspects it). FC-specific mechanics
(create_snapshot/restore_from_snapshot/resolve_mem_dir, the FcSnapshotArtifact,
the FcSnapshotBackend wiring) are tested in ``test_fc_snapshot_backend.py``.
"""
from __future__ import annotations

import threading
import time

import pytest

from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotManager,
    SnapshotRestoreError,
)


def _wait_until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


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


# --- async build (ensure_build_started) ------------------------------------


def test_ensure_build_started_is_async_and_nonblocking(tmp_path):
    """ensure_build_started() must return IMMEDIATELY (not block on the up-to-120s wait_ready),
    leaving the build in flight on a daemon thread; is_built() flips True once it completes."""
    gate = threading.Event()

    class _Boot(FakeBoot):
        def wait_ready(self, timeout_s):
            assert gate.wait(timeout_s), "gate not released within timeout"

    class _Backend(FakeBackend):
        def boot_base(self):
            b = _Boot(self.artifact)
            self.boots.append(b)
            self.last_boot = b
            return b

    backend = _Backend()
    mgr = SnapshotManager(tmp_path, backend)

    t0 = time.monotonic()
    mgr.ensure_build_started()
    assert time.monotonic() - t0 < 0.5  # did NOT block on wait_ready
    assert mgr.is_built() is False  # build still in flight

    gate.set()  # let the build complete
    assert _wait_until(mgr.is_built)
    assert mgr.artifact is backend.artifact
    assert mgr.build_error is None


def test_ensure_build_started_builds_exactly_once(tmp_path):
    """Many ensure_build_started() calls (every pool tick) must boot the base only once."""
    backend = FakeBackend()
    mgr = SnapshotManager(tmp_path, backend)
    for _ in range(8):
        mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    for _ in range(8):
        mgr.ensure_build_started()  # already built -> no-op
    time.sleep(0.05)
    assert len(backend.boots) == 1


def test_failed_build_records_error_and_backs_off(tmp_path):
    """A failing build must NOT churn: it records build_error, stays unbuilt, and a retry within
    build_retry_backoff_s does not start another base boot (no per-tick re-boot storm)."""
    backend = FakeBackend(ready_ok=False)  # wait_ready raises -> SnapshotBuildError
    mgr = SnapshotManager(tmp_path, backend, build_retry_backoff_s=60.0)

    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.build_error is not None)
    assert mgr.is_built() is False
    assert isinstance(mgr.build_error, SnapshotBuildError)
    assert len(backend.boots) == 1

    mgr.ensure_build_started()  # within the 60s backoff -> must not re-boot
    time.sleep(0.1)
    assert len(backend.boots) == 1


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
    # A failed restore returns no handle, so nothing reaps the slot — the manager must rmtree
    # the just-created workdir so it doesn't leak on the host.
    assert not (tmp_path / "slots" / "slot-x").exists()


def test_restore_preserves_snapshot_error_subclasses(tmp_path):
    class BoomBackend(FakeBackend):
        def restore_in(self, slot_workdir, artifact):
            raise SnapshotRestoreError("backend already chose the error")

    mgr = SnapshotManager(tmp_path, BoomBackend())
    mgr.build()
    with pytest.raises(SnapshotRestoreError, match="backend already chose"):
        mgr.restore("slot-x")
    assert not (tmp_path / "slots" / "slot-x").exists()  # cleanup on the SnapshotError path too


def test_a_failed_retirement_is_retried_by_the_next_build(tmp_path):
    """_sweep_retired ran only from release() and _unpin() — both need a restored, reaped slot.

    When cleanup of a retired generation fails, its RAM-sized memory file stays on the snapshot
    filesystem, which is itself a reason the replacement build fails before producing any slot.
    Neither trigger could then ever fire, so the tier stayed wedged even after the transient
    unlink problem cleared. The build/retry path has to sweep too.
    """
    import errno as _errno

    class _FlakyDiscard(FakeBackend):
        def __init__(self):
            super().__init__()
            self.fail_discard = True
            self._n = 0

        def boot_base(self):
            self._n += 1
            self.artifact = tmp_path / f"gen{self._n}.mem"
            self.artifact.write_bytes(b"x" * 16)
            return super().boot_base()

        def discard(self, artifact):
            if self.fail_discard:
                raise OSError(_errno.EIO, "unlink failed")
            artifact.unlink()

    backend = _FlakyDiscard()
    mgr = SnapshotManager(tmp_path, backend)
    gen1 = mgr.build()
    assert gen1.exists()

    # Nothing was ever restored from gen1, so no release()/_unpin() will follow.
    assert mgr.invalidate() is True
    assert gen1.exists(), "sanity: the failed discard left the generation on disk"

    # The transient problem clears, and the pool retries the build.
    backend.fail_discard = False
    mgr.build()

    assert not gen1.exists(), (
        "the retired generation was never retried: only a restored-and-reaped slot could have "
        "swept it, and a build that fails for lack of space never produces one"
    )


def test_a_failed_orphan_sweep_is_retried_on_the_next_build(tmp_path):
    """The latch was set BEFORE the sweep ran, so one transient EIO disabled it for the process.

    Startup orphan reclamation removes generations left by a dispatcher that is gone. Its RAM-
    sized .mem is itself a reason the replacement build fails for want of space, so a sweep that
    failed once and never ran again could leave the tier blocked long after the filesystem
    recovered.
    """
    import errno as _errno

    class _FlakySweep(FakeBackend):
        def __init__(self):
            super().__init__()
            self.sweeps = 0
            self.fail_sweep = True

        def sweep_orphan_generations(self):
            self.sweeps += 1
            if self.fail_sweep:
                raise OSError(_errno.EIO, "could not sweep orphan generations")
            return 0

    backend = _FlakySweep()
    mgr = SnapshotManager(tmp_path, backend)
    mgr.build()
    assert backend.sweeps == 1                      # tried, and failed

    mgr.invalidate()                                # force the next build to run for real
    backend.fail_sweep = False                      # the filesystem recovers
    mgr.build()
    assert backend.sweeps == 2, (
        "the orphan sweep never ran again: the latch was set before the call, so a single "
        "transient failure disabled reclamation for the life of the dispatcher"
    )

    # ...and once it SUCCEEDS the latch holds — no re-sweeping on every later build.
    mgr.invalidate()
    mgr.build()
    assert backend.sweeps == 2, "a successful sweep must latch; this is a once-per-process job"
