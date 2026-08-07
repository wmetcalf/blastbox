"""Firecracker SnapshotBackend — the FC-specific mechanics behind the runtime seam.

This is the Firecracker implementation of
:class:`~blastbox.host.runtime.snapshot_backend.SnapshotBackend`. It owns everything
FC-specific that the generic :class:`~blastbox.host.runtime.fc_snapshot.SnapshotManager`
used to know about:

- the **RAM-preload toggle** (``resolve_mem_dir`` / the ``BLASTBOX_SNAPSHOT_MEM_*``
  env vars) that decides where the big mem file lives;
- the FC artifact shape (:class:`FcSnapshotArtifact` — a ``{snapshot, mem}`` file
  pair); and
- the FC API call sequences for **CreateSnapshot Full** (``_create_snapshot``) and
  **load+resume** (``_restore_from_snapshot``).

Key constraint (FC v1.12.1, from the embedded API schema): ``PUT /snapshot/load``
has **no vsock-uds override** — the host vsock path is baked into the snapshot. So
per-restore uniqueness comes from running each restored firecracker in its **own
working dir** (the same baked relative ``uds_path`` then resolves to a per-slot
socket), NOT from the load body. **Runtime-confirmed on toolz2 (FC v1.12.1):** each
restore re-creates its own ``vsock.sock`` in its own cwd, and a full
snapshot→restore→convert round-trip is pixel-identical to cold (see the spec).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from blastbox.host.runtime.fc_snapshot import SnapshotBuildError, SnapshotRestoreError

_log = logging.getLogger("blastbox.host.runtime.fc_snapshot_backend")

# RAM-preload toggle (see resolve_mem_dir). Default tmpfs mount on Linux.
_DEFAULT_TMPFS_MEM_DIR = Path("/dev/shm")
_ENV_MEM_TMPFS = "BLASTBOX_SNAPSHOT_MEM_TMPFS"
_ENV_MEM_DIR = "BLASTBOX_SNAPSHOT_MEM_DIR"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def resolve_mem_dir() -> Path | None:
    """Resolve the snapshot mem-file directory from the RAM-preload toggle.

    The snapshot's mem file ≈ guest RAM (~2 GB with soffice live) and dominates
    the snapshot cost. Holding it on **tmpfs** (``/dev/shm``) pins it in RAM, so
    every restore reads the COW-shared base from memory (zero disk I/O) — fast,
    but it permanently occupies ~one guest-RAM of RAM for the warm baseline. Hosts
    differ in RAM, so this is **opt-in, default OFF**: unset → the mem file lives
    on disk (page-cache-backed) in the manager's base dir, which is safe on a small
    box (the kernel still caches it, just evictable under pressure).

    Precedence:

    - ``BLASTBOX_SNAPSHOT_MEM_DIR=<path>`` — preload into this explicit directory
      (wins; for hosts whose tmpfs is mounted somewhere other than ``/dev/shm``).
    - ``BLASTBOX_SNAPSHOT_MEM_TMPFS=1`` — preload into the default tmpfs ``/dev/shm``.
    - neither set — return ``None`` (caller keeps the mem file on disk).
    """
    explicit = os.environ.get(_ENV_MEM_DIR, "").strip()
    if explicit:
        return Path(explicit)
    if _env_truthy(_ENV_MEM_TMPFS):
        return _DEFAULT_TMPFS_MEM_DIR
    return None


@runtime_checkable

class FcApi(Protocol):
    """The subset of the Firecracker API client the orchestration uses."""

    def put(self, path: str, body: Any = ...) -> int: ...
    def patch(self, path: str, body: Any = ...) -> int: ...


def _create_snapshot(api: FcApi, snapshot_path: str, mem_path: str) -> None:
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


def _restore_from_snapshot(
    api: FcApi, snapshot_path: str, mem_path: str, *, resume: bool = True
) -> None:
    """Load a snapshot (state + memory) into a fresh firecracker and (optionally)
    resume. Field shapes valid FC v1.12.1–v1.16.0 ``LoadSnapshotConfig`` —
    ``mem_backend`` (not the deprecated ``mem_file_path``), ``track_dirty_pages``
    (the FC ≥1.13 replacement for the deprecated ``enable_diff_snapshots``; False
    since we only take Full snapshots), no vsock override (see module note).
    ``clock_realtime`` is intentionally left unset (default False): FC resumes the
    guest CLOCK_MONOTONIC frozen from snapshot time, which is exactly what the warm
    handshake relies on — advancing it would reintroduce the restore clock-jump."""
    from blastbox.host.runtime.fc_api import FcApiError

    try:
        api.put(
            "/snapshot/load",
            {
                "snapshot_path": snapshot_path,
                "mem_backend": {"backend_type": "File", "backend_path": mem_path},
                "track_dirty_pages": False,
                "resume_vm": resume,
            },
        )
    except FcApiError as exc:
        raise SnapshotRestoreError(f"restore_from_snapshot failed: {exc}") from exc


@dataclass(frozen=True)
class FcSnapshotArtifact:
    """The built warm snapshot: a state file + a memory file. This is the OPAQUE
    artifact the generic :class:`SnapshotManager` round-trips between ``checkpoint``
    and ``restore_in``; only the FC backend (and its launcher) ever inspect it."""

    snapshot_path: Path
    mem_path: Path


class FcSnapshotBackend:
    """Firecracker :class:`SnapshotBackend`.

    ``boot_base()`` and ``restore_in()`` delegate process spawning to the injected
    :class:`~blastbox.host.runtime.fc_snapshot_launcher.FcSnapshotLauncher`; this
    backend layers the FC ``/snapshot/load`` + resume on top of the restored
    firecracker the launcher spawns. ``checkpoint`` lives on the launcher's boot
    handle (it needs the launcher's mem-dir), so this backend's role on the build
    side is simply to hand the boot handle back to the manager.
    """

    def discard(self, artifact: object) -> None:
        """Unlink a fully drained generation's files.

        Only ever called once the manager's refcount for this artifact reaches zero, i.e. no
        live microVM still maps the memory file. Unlinking one that is still mapped would
        SIGBUS or silently corrupt the VMs using it.
        """
        # Attribute access, NOT getattr-with-default. The first version of this read
        # `artifact.snapshot` / `artifact.mem` -- fields that do not exist on
        # FcSnapshotArtifact (they are snapshot_path / mem_path) -- so both lookups returned
        # None, every file was skipped, and the whole reclamation was a silent no-op in
        # production while its tests passed against a fake that had invented the same wrong
        # names. A getattr default turns "this type changed" into "quietly leak gigabytes";
        # an AttributeError turns it into a test failure. Prefer the crash.
        if not isinstance(artifact, FcSnapshotArtifact):
            _log.warning("fc_snapshot: refusing to discard unknown artifact type %r",
                         type(artifact).__name__)
            return
        for path in (artifact.snapshot_path, artifact.mem_path):
            try:
                Path(path).unlink(missing_ok=True)
            except OSError as exc:
                _log.warning("fc_snapshot: could not unlink %s: %s", path, exc)

    def __init__(
        self,
        base_dir: Path,
        launcher: Any,
        *,
        mem_dir: Path | None = None,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._launcher = launcher
        # The mem file dominates the snapshot (~guest RAM). Point mem_dir at tmpfs
        # (/dev/shm) so every restore reads the COW-shared base from RAM, not disk
        # (FC mmaps it MAP_PRIVATE → base shared, per-VM copy-on-write). Defaults to
        # base_dir (page-cache-backed) when not set.
        self._mem_dir = Path(mem_dir) if mem_dir is not None else self._base_dir

    @classmethod
    def from_env(
        cls,
        base_dir: Path,
        launcher: Any,
        *,
        mem_dir: Path | None = None,
    ) -> "FcSnapshotBackend":
        """Construct a backend, honoring the RAM-preload toggle from the environment.

        When ``mem_dir`` is not passed explicitly, it is resolved via
        :func:`resolve_mem_dir` (``BLASTBOX_SNAPSHOT_MEM_TMPFS`` /
        ``BLASTBOX_SNAPSHOT_MEM_DIR``, default OFF → disk-backed). This is the entry
        point the runtime wiring uses so the toggle is respected per host."""
        if mem_dir is None:
            mem_dir = resolve_mem_dir() or Path(base_dir)
        return cls(base_dir, launcher, mem_dir=mem_dir)

    @property
    def mem_dir(self) -> Path:
        return self._mem_dir

    def available(self) -> bool:
        # The caller (select_snapshot_runtime) already gated on firecracker_available;
        # by the time a backend is constructed the FC prerequisites are present.
        return True

    def boot_base(self) -> Any:
        """Boot the base microVM (whose handle ``checkpoint(dest_dir)`` snapshots)."""
        return self._launcher.boot_base()

    def restore_in(self, slot_workdir: Path, artifact: object) -> Any:
        """Spawn a fresh firecracker in ``slot_workdir`` and load+resume the FC
        snapshot into it. ``artifact`` is the :class:`FcSnapshotArtifact` the build
        side produced; the manager passes it back here opaquely."""
        if not isinstance(artifact, FcSnapshotArtifact):
            # Explicit raise (not assert) so the validation survives `python -O`; fails closed
            # with a typed error the manager already maps + cleans up after.
            raise SnapshotRestoreError(
                f"FcSnapshotBackend.restore_in expected FcSnapshotArtifact, "
                f"got {type(artifact).__name__}"
            )
        handle = self._launcher.restore_in(slot_workdir)
        try:
            _restore_from_snapshot(
                handle.api, str(artifact.snapshot_path), str(artifact.mem_path)
            )
        except Exception:
            # Don't leak the spawned firecracker if load/resume fails.
            handle.kill()
            raise
        return handle
