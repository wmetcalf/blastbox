"""Runtime-agnostic warm-snapshot manager.

The warm tier builds **one** snapshot of a running, idle sandbox (e.g. a warm
``unoserver``) on host first-boot, then restores it per job. This module owns only
the **lifecycle** — build once, serve restores — and talks exclusively to the
:class:`~blastbox.host.runtime.snapshot_backend.SnapshotBackend` seam. The artifact
a backend produces at checkpoint time is **opaque** to the manager: it is stored
and handed straight back to ``restore_in`` without inspection, so the same manager
drives Firecracker (a {snapshot, mem} file pair) or gVisor (a runsc image dir)
unchanged.

The FC-specific mechanics (create/restore API calls, the mem-dir RAM-preload
toggle, the FcSnapshotArtifact) live in
:mod:`blastbox.host.runtime.fc_snapshot_backend`.
"""
from __future__ import annotations

from pathlib import Path

from blastbox.host.runtime.snapshot_backend import RestoreHandle, SnapshotBackend


class SnapshotError(RuntimeError):
    """Base class for snapshot/restore failures."""


class SnapshotBuildError(SnapshotError):
    """Building the warm snapshot failed (callers fall back to cold-boot)."""


class SnapshotRestoreError(SnapshotError):
    """Restoring a slot from the snapshot failed (caller reaps + cold-boots the job)."""


class SnapshotManager:
    """Builds the warm snapshot once (first-boot), then serves restores to the pool.

    ``build()`` boots a base sandbox, waits READY, checkpoints it, tears the base
    down, and records the OPAQUE artifact (idempotent). ``restore(slot_id)`` asks
    the backend to restore that artifact into a fresh per-slot working dir.

    The manager is runtime-agnostic: it never inspects the artifact and never
    touches FC/gVisor APIs — all of that is behind the injected ``backend``.
    """

    def __init__(
        self,
        base_dir: Path,
        backend: SnapshotBackend,
        *,
        ready_timeout_s: float = 120.0,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._backend = backend
        self._ready_timeout_s = ready_timeout_s
        self._artifact: object | None = None

    @property
    def artifact(self) -> object | None:
        return self._artifact

    def build(self) -> object:
        """Build the warm snapshot. Idempotent — a second call returns the same
        artifact without rebuilding. Raises :class:`SnapshotBuildError` on failure
        (callers fall back to cold-boot)."""
        if self._artifact is not None:
            return self._artifact
        self._base_dir.mkdir(parents=True, exist_ok=True)
        # boot_base() is its own try so a base-boot failure is wrapped as
        # SnapshotBuildError (as documented), not propagated raw. boot_base already
        # tears down its own sandbox on partial failure, so no handle/finally is
        # needed here — there is nothing to kill until it returns a BootHandle.
        try:
            boot = self._backend.boot_base()
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(f"warm snapshot base boot failed: {exc}") from exc
        try:
            boot.wait_ready(self._ready_timeout_s)
            artifact = boot.checkpoint(self._base_dir)
        except SnapshotError:
            raise
        except Exception as exc:  # readiness / checkpoint failure
            raise SnapshotBuildError(f"warm snapshot build failed: {exc}") from exc
        finally:
            boot.kill()
        self._artifact = artifact
        return artifact

    def restore(self, slot_id: object) -> RestoreHandle:
        """Restore the warm snapshot into a fresh per-slot sandbox and return its
        handle. Raises :class:`SnapshotRestoreError` if the snapshot isn't built
        yet or the restore fails (caller reaps the slot + cold-boots that job)."""
        if self._artifact is None:
            raise SnapshotRestoreError("snapshot not built; call build() first")
        # slot_id becomes a path component under base_dir/slots/ — keep the trust
        # boundary explicit (today's only caller passes a uuid4, but the signature is
        # `object`): reject anything that isn't a single safe path segment so a future
        # caller can't traverse out of slots/ with a stray "/" or "..".
        sid = str(slot_id)
        if not sid or "/" in sid or "\x00" in sid or sid in (".", ".."):
            raise SnapshotRestoreError(f"unsafe slot_id: {sid!r}")
        slot_workdir = self._base_dir / "slots" / sid
        slot_workdir.mkdir(parents=True, exist_ok=True)
        try:
            return self._backend.restore_in(slot_workdir, self._artifact)
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotRestoreError(f"restore failed: {exc}") from exc
