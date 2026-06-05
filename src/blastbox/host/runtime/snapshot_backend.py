"""Runtime-agnostic warm-snapshot seam.

One generic SnapshotManager (fc_snapshot.py) drives any SnapshotBackend. The
artifact a backend produces at checkpoint time is OPAQUE to the manager — the
manager stores it and hands it back to restore_in(), never inspecting it. FC's
artifact is a {snapshot, mem} file pair; gVisor's is a runsc image-path dir.
"""
from __future__ import annotations
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class BootHandle(Protocol):
    """A launched base sandbox used to build the snapshot."""

    def wait_ready(self, timeout_s: float) -> None:
        """Block until the base sandbox's engine signals READY (warm-idle)."""
        ...

    def checkpoint(self, dest_dir: Path) -> object:
        """Capture the warm snapshot, writing artifacts under/near dest_dir.
        Returns an OPAQUE artifact the manager round-trips to restore_in()."""
        ...

    def kill(self) -> None:
        """Tear down the base sandbox."""
        ...


@runtime_checkable
class RestoreHandle(Protocol):
    """A restored per-slot sandbox. Backend-specific I/O accessors are added by
    the concrete handle; the seam only requires kill()."""

    def kill(self) -> None: ...


@runtime_checkable
class SnapshotBackend(Protocol):
    """Spawns/checkpoints/restores the real sandboxes for one runtime (FC, gVisor)."""

    def available(self) -> bool:
        """True iff this backend's prerequisites are present (fail-closed selection)."""
        ...

    def boot_base(self) -> BootHandle: ...

    def restore_in(self, slot_workdir: Path, artifact: object) -> RestoreHandle: ...
