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

import logging
import shutil
import threading
import time
from pathlib import Path

from blastbox.host.runtime.snapshot_backend import RestoreHandle, SnapshotBackend

_log = logging.getLogger("blastbox.host.runtime.fc_snapshot")


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
        build_retry_backoff_s: float = 30.0,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._backend = backend
        self._ready_timeout_s = ready_timeout_s
        self._build_retry_backoff_s = build_retry_backoff_s
        self._artifact: object | None = None
        # Generation reference counting. Restored microVMs keep the memory file mapped as their
        # backing store for as long as they live, so a superseded generation cannot be unlinked
        # until its LAST user is reaped. Without this the files simply accumulate: each rebuild
        # leaves a .mem roughly the size of guest RAM (gigabytes, often on /dev/shm), so repeated
        # rebuild episodes exhaust the tmpfs and every later build fails on ENOSPC.
        self._pins: dict[str, object] = {}          # slot_id -> the artifact it mapped
        self._refs: dict[int, int] = {}             # id(artifact) -> live restores
        self._retired: dict[int, object] = {}       # id(artifact) -> superseded, awaiting drain
        # Async-build state (used by ensure_build_started so the up-to-ready_timeout_s build
        # never runs on the pool's single tick thread). _build_lock guards only the cheap
        # bookkeeping below, never the slow boot/checkpoint inside build().
        self._build_lock = threading.Lock()
        self._build_thread: threading.Thread | None = None
        self._build_error: Exception | None = None
        self._retry_not_before: float = 0.0  # monotonic; backoff gate after a failed build

    @property
    def artifact(self) -> object | None:
        return self._artifact

    def is_built(self) -> bool:
        """True once the snapshot artifact exists (atomic reference read)."""
        return self._artifact is not None

    @property
    def build_error(self) -> Exception | None:
        """The most recent async-build failure (None if never failed / since recovered)."""
        return self._build_error

    def ensure_build_started(self) -> None:
        """Non-blocking: kick the (idempotent) build in a daemon thread if it isn't built and no
        build is already running. Returns immediately so the caller (the pool's tick loop) never
        blocks on the boot+wait_ready. After a failure it waits ``build_retry_backoff_s`` before
        retrying, so a persistently-failing base boot doesn't churn the host every tick."""
        with self._build_lock:
            if self._artifact is not None:
                return
            if self._build_thread is not None and self._build_thread.is_alive():
                return
            if time.monotonic() < self._retry_not_before:
                return
            self._build_thread = threading.Thread(
                target=self._build_worker, daemon=True, name="warm-snapshot-build"
            )
            self._build_thread.start()

    def _build_worker(self) -> None:
        try:
            self.build()
        except Exception as exc:  # noqa: BLE001 — surface + back off; the pool falls back to cold
            with self._build_lock:
                self._build_error = exc
                self._retry_not_before = time.monotonic() + self._build_retry_backoff_s
            _log.warning(
                "warm snapshot build failed; cold fallback active, retry after %.0fs: %s",
                self._build_retry_backoff_s,
                exc,
            )
        else:
            with self._build_lock:
                self._build_error = None

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

    def invalidate(self) -> bool:
        """Discard the built artifact so the next ``build()`` captures a fresh one.

        The warm base is checkpointed from a live sandbox, so it can capture a guest that was
        already wedged. Every restore then reproduces that wedge, and because the artifact is
        cached here forever, reaping and respawning slots cannot recover -- only restarting the
        process would. Dropping the artifact gives the pool a way to rebuild in place.

        Returns True if a built artifact was actually discarded. Never raises: a failed
        invalidation must not take down the caller's failure-handling path.
        """
        with self._build_lock:
            had = self._artifact is not None
            collect = None
            if self._artifact is not None:
                key = id(self._artifact)
                if self._refs.get(key, 0) > 0:
                    # RETIRE, don't unlink: slots restored from this generation are still mapping
                    # its memory file, and pulling it out from under a live microVM SIGBUSes or
                    # silently corrupts it. release() collects it when the last user is reaped.
                    self._retired[key] = self._artifact
                else:
                    # Already fully drained -- and this is the COMMON ordering, not the rare one:
                    # slots are usually reaped before the rebuild that supersedes their
                    # generation. Retiring it here instead would leave nothing to trigger the
                    # collection (no pins remain to release), and it would leak forever.
                    collect = self._artifact
            self._artifact = None
            self._build_error = None
            # Do not reuse the previous failure backoff: this is a deliberate rebuild request,
            # not a retry of a build that just failed.
            self._retry_not_before = 0.0
        if collect is not None:
            self._discard(collect)
        return had

    def release(self, slot_id: object) -> None:
        """Called when a restored slot is reaped: drop its pin and reclaim drained generations.

        Never raises -- reap must not be taken down by cleanup.
        """
        with self._build_lock:
            artifact = self._pins.pop(str(slot_id), None)
            if artifact is None:
                return
            key = id(artifact)
            self._refs[key] = self._refs.get(key, 1) - 1
            if self._refs[key] <= 0:
                self._refs.pop(key, None)
                retired = self._retired.pop(key, None)
            else:
                retired = None
        if retired is not None:
            self._discard(retired)

    def _discard(self, artifact: object) -> None:
        """Ask the backend to unlink a fully drained generation. Optional hook: a backend that
        does not implement it simply keeps its artifacts, exactly as before."""
        discard = getattr(self._backend, "discard", None)
        if not callable(discard):
            return
        try:
            discard(artifact)
        except Exception as exc:  # noqa: BLE001 -- reclamation must never raise into reap
            _log.warning("snapshot.discard_failed artifact=%r: %s", artifact, exc)

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
        artifact = self._artifact
        try:
            handle = self._backend.restore_in(slot_workdir, artifact)
            with self._build_lock:
                # Pin the exact generation this slot mapped -- NOT self._artifact, which a
                # concurrent invalidate+build may already have replaced.
                self._pins[sid] = artifact
                self._refs[id(artifact)] = self._refs.get(id(artifact), 0) + 1
            return handle
        except SnapshotError:
            # A failed restore never yields a handle, so the slot is never reaped —
            # remove the just-created (empty) workdir so it doesn't leak on the host.
            shutil.rmtree(slot_workdir, ignore_errors=True)
            raise
        except Exception as exc:
            shutil.rmtree(slot_workdir, ignore_errors=True)
            raise SnapshotRestoreError(f"restore failed: {exc}") from exc
