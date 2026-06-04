"""Firecracker snapshot/restore orchestration + the warm-snapshot manager.

The warm tier builds **one** memory snapshot of a running, idle microVM (e.g. a
warm ``unoserver``) on host first-boot, then restores it per job. This module is
the host-side orchestration; the real process-spawning is injected as a *launcher*
so the logic is unit-tested without a real Firecracker.

Key constraint (FC v1.12.1, from the embedded API schema): ``PUT /snapshot/load``
has **no vsock-uds override** — the host vsock path is baked into the snapshot. So
per-restore uniqueness comes from running each restored firecracker in its **own
working dir** (the same baked relative ``uds_path`` then resolves to a per-slot
socket), NOT from the load body. **Runtime-confirmed on toolz2 (FC v1.12.1):** each
restore re-creates its own ``vsock.sock`` in its own cwd, and a full
snapshot→restore→convert round-trip is pixel-identical to cold (see the spec).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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

    def kill(self) -> None: ...


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
        mem_dir: Path | None = None,
    ) -> None:
        self._base_dir = Path(base_dir)
        # The mem file dominates the snapshot (~guest RAM). Point mem_dir at tmpfs
        # (/dev/shm) so every restore reads the COW-shared base from RAM, not disk
        # (FC mmaps it MAP_PRIVATE → base shared, per-VM copy-on-write). Defaults to
        # base_dir (page-cache-backed) when not set.
        self._mem_dir = Path(mem_dir) if mem_dir is not None else self._base_dir
        self._launcher = launcher
        self._ready_timeout_s = ready_timeout_s
        self._artifact: SnapshotArtifact | None = None

    @classmethod
    def from_env(
        cls,
        base_dir: Path,
        launcher: SnapshotLauncher,
        *,
        ready_timeout_s: float = 120.0,
        mem_dir: Path | None = None,
    ) -> "SnapshotManager":
        """Construct a manager, honoring the RAM-preload toggle from the environment.

        When ``mem_dir`` is not passed explicitly, it is resolved via
        :func:`resolve_mem_dir` (``BLASTBOX_SNAPSHOT_MEM_TMPFS`` /
        ``BLASTBOX_SNAPSHOT_MEM_DIR``, default OFF → disk-backed). This is the entry
        point the pool wiring should use so the toggle is respected per host."""
        if mem_dir is None:
            mem_dir = resolve_mem_dir()
        return cls(
            base_dir, launcher, ready_timeout_s=ready_timeout_s, mem_dir=mem_dir
        )

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
        mem = self._mem_dir / "warm.mem"
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._mem_dir.mkdir(parents=True, exist_ok=True)
        # boot_base() is its own try so a base-boot failure is wrapped as
        # SnapshotBuildError (as documented), not propagated raw. boot_base already
        # kills its own firecracker on partial failure, so no handle/finally is needed
        # here — there is nothing to kill until it returns a BootHandle.
        try:
            boot = self._launcher.boot_base()
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(f"warm snapshot base boot failed: {exc}") from exc
        try:
            boot.wait_ready(self._ready_timeout_s)
            create_snapshot(boot.api, str(snap), str(mem))
        except SnapshotError:
            raise
        except Exception as exc:  # readiness / snapshot failure
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
        # slot_id becomes a path component under base_dir/slots/ — keep the trust
        # boundary explicit (today's only caller passes a uuid4, but the signature is
        # `object`): reject anything that isn't a single safe path segment so a future
        # caller can't traverse out of slots/ with a stray "/" or "..".
        sid = str(slot_id)
        if not sid or "/" in sid or "\x00" in sid or sid in (".", ".."):
            raise SnapshotRestoreError(f"unsafe slot_id: {sid!r}")
        slot_workdir = self._base_dir / "slots" / sid
        slot_workdir.mkdir(parents=True, exist_ok=True)
        handle = self._launcher.restore_in(slot_workdir)
        try:
            restore_from_snapshot(
                handle.api,
                str(self._artifact.snapshot_path),
                str(self._artifact.mem_path),
            )
        except Exception:
            # Don't leak the spawned firecracker if load/resume fails.
            handle.kill()
            raise
        return handle
