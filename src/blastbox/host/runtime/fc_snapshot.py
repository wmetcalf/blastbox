"""Firecracker snapshot/restore orchestration + the warm-snapshot manager.

The warm tier builds **one** memory snapshot of a running, idle microVM (e.g. a
warm ``unoserver``) on host first-boot, then restores it per job. This module is
the host-side orchestration; the real process-spawning is injected as a *launcher*
so the logic is unit-tested without a real Firecracker.

Key constraint (FC v1.12.1, from the embedded API schema): ``PUT /snapshot/load``
has **no vsock-uds override** — the host vsock path is baked into the snapshot. So
per-restore uniqueness comes from running each restored firecracker in its **own
working dir** (the same baked relative ``uds_path`` then resolves to a per-slot
socket), NOT from the load body. Runtime-confirm this before enabling (see the
spec's Phase 0 finding).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


class SnapshotError(RuntimeError):
    """Base class for snapshot/restore failures."""


class SnapshotBuildError(SnapshotError):
    """Building the warm snapshot failed (callers fall back to cold-boot)."""


class SnapshotRestoreError(SnapshotError):
    """Restoring a slot from the snapshot failed (caller reaps + cold-boots the job)."""


@runtime_checkable
class FcApi(Protocol):
    """The subset of the Firecracker API client the orchestration uses."""

    def put(self, path: str, body: Any = ...) -> int: ...
    def patch(self, path: str, body: Any = ...) -> int: ...


def create_snapshot(api: FcApi, snapshot_path: str, mem_path: str) -> None:
    """Pause the running microVM, then write a **Full** snapshot (state + memory).

    Order is load-bearing — the VM MUST be Paused before ``/snapshot/create`` or
    Firecracker rejects it. Field shapes per FC v1.12.1 ``CreateSnapshotParams``."""
    from blastbox.host.runtime.fc_api import FcApiError

    try:
        api.patch("/vm", {"state": "Paused"})
        api.put(
            "/snapshot/create",
            {
                "snapshot_type": "Full",
                "snapshot_path": snapshot_path,
                "mem_file_path": mem_path,
            },
        )
    except FcApiError as exc:
        raise SnapshotBuildError(f"create_snapshot failed: {exc}") from exc


def restore_from_snapshot(
    api: FcApi, snapshot_path: str, mem_path: str, *, resume: bool = True
) -> None:
    """Load a snapshot (state + memory) into a fresh firecracker and (optionally)
    resume. Field shapes per FC v1.12.1 ``LoadSnapshotConfig`` — ``mem_backend``
    (not the deprecated ``mem_file_path``), no vsock override (see module note)."""
    from blastbox.host.runtime.fc_api import FcApiError

    try:
        api.put(
            "/snapshot/load",
            {
                "snapshot_path": snapshot_path,
                "mem_backend": {"backend_type": "File", "backend_path": mem_path},
                "enable_diff_snapshots": False,
                "resume_vm": resume,
            },
        )
    except FcApiError as exc:
        raise SnapshotRestoreError(f"restore_from_snapshot failed: {exc}") from exc


@dataclass(frozen=True)
class SnapshotArtifact:
    """The built warm snapshot: a state file + a memory file."""

    snapshot_path: Path
    mem_path: Path


@runtime_checkable
class BootHandle(Protocol):
    """A launched base microVM used to build the snapshot."""

    api: FcApi

    def wait_ready(self, timeout_s: float) -> None: ...
    def kill(self) -> None: ...


@runtime_checkable
class RestoreHandle(Protocol):
    """A restored per-slot microVM."""

    api: FcApi
    vsock_uds: str


@runtime_checkable
class SnapshotLauncher(Protocol):
    """Spawns the real firecracker processes. Injected so SnapshotManager logic is
    testable without a host. The container/runtime implementation lives in Phase 2."""

    def boot_base(self) -> BootHandle: ...
    def restore_in(self, slot_workdir: Path) -> RestoreHandle: ...


class SnapshotManager:
    """Builds the warm snapshot once (first-boot), then serves restores to the pool.

    ``build()`` boots a base VM, waits READY, snapshots it, kills the base VM, and
    records the artifact (idempotent). ``restore(slot_id)`` launches a fresh
    firecracker in a **per-slot working dir** (vsock uniqueness — see module note)
    and loads+resumes the snapshot into it.
    """

    def __init__(
        self,
        base_dir: Path,
        launcher: SnapshotLauncher,
        *,
        ready_timeout_s: float = 120.0,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._launcher = launcher
        self._ready_timeout_s = ready_timeout_s
        self._artifact: SnapshotArtifact | None = None

    @property
    def artifact(self) -> SnapshotArtifact | None:
        return self._artifact

    def build(self) -> SnapshotArtifact:
        """Build the warm snapshot. Idempotent — a second call returns the same
        artifact without rebuilding. Raises :class:`SnapshotBuildError` on failure
        (callers fall back to cold-boot)."""
        if self._artifact is not None:
            return self._artifact
        snap = self._base_dir / "warm.snapshot"
        mem = self._base_dir / "warm.mem"
        self._base_dir.mkdir(parents=True, exist_ok=True)
        boot = self._launcher.boot_base()
        try:
            boot.wait_ready(self._ready_timeout_s)
            create_snapshot(boot.api, str(snap), str(mem))
        except SnapshotError:
            raise
        except Exception as exc:  # launcher / readiness failure
            raise SnapshotBuildError(f"warm snapshot build failed: {exc}") from exc
        finally:
            boot.kill()
        self._artifact = SnapshotArtifact(snap, mem)
        return self._artifact

    def restore(self, slot_id: object) -> RestoreHandle:
        """Restore the warm snapshot into a fresh per-slot microVM and return its
        handle. Raises :class:`SnapshotRestoreError` if the snapshot isn't built
        yet or the restore fails (caller reaps the slot + cold-boots that job)."""
        if self._artifact is None:
            raise SnapshotRestoreError("snapshot not built; call build() first")
        slot_workdir = self._base_dir / "slots" / str(slot_id)
        slot_workdir.mkdir(parents=True, exist_ok=True)
        handle = self._launcher.restore_in(slot_workdir)
        restore_from_snapshot(
            handle.api,
            str(self._artifact.snapshot_path),
            str(self._artifact.mem_path),
        )
        return handle
