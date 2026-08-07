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

import contextlib
import logging
import shutil
import threading
import time
from pathlib import Path

# _accepts_kwarg is the ONE definition of "does this callable declare that parameter" --
# imported rather than copied, which is how the same optional-hook check drifted before.
# pool.py imports nothing from runtime/, so this direction cannot cycle.
from blastbox.host.pool import RuntimeAtCapacity, _accepts_kwarg
from blastbox.host.runtime.snapshot_backend import RestoreHandle, SnapshotBackend

_log = logging.getLogger("blastbox.host.runtime.fc_snapshot")


class SnapshotError(RuntimeError):
    """Base class for snapshot/restore failures."""


class SnapshotBuildInvalidated(SnapshotError, RuntimeAtCapacity):
    """The build completed but was REJECTED because invalidate() landed while it ran.

    Also a ``RuntimeAtCapacity``: if this surfaces through a synchronous spawn, the pool must
    read it as "no artifact right this instant, retry" rather than as a restore failure. A
    deliberate repair is the one thing that must never advance the restore-failure streak that
    triggers further repairs.

    Deliberately not a SnapshotBuildError: nothing failed, so arming the failure backoff would
    leave the tier cold for build_retry_backoff_s after a repair the operator (or the pool) just
    asked for -- the replacement build should start immediately (upstream, PR #82)."""


class SnapshotBuildError(SnapshotError):
    """Building the warm snapshot failed (callers fall back to cold-boot)."""


class SnapshotRestoreError(SnapshotError):
    """Restoring a slot from the snapshot failed (caller reaps + cold-boots the job)."""


def _restore_left_process_running(exc: BaseException) -> bool:
    """Whether a failed restore may have left its firecracker process alive.

    The backend raises SnapshotRestoreError after trying to kill the process it spawned; when
    that kill ALSO failed it chains the kill error, which is the only signal available here.
    Conservative by design: an unconfirmed teardown retains the pin, because retaining a
    generation costs disk while unlinking one under a live mapping corrupts it.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if getattr(cur, "kill_failed", False) is True:
            return True
        cur = cur.__cause__ or cur.__context__
    return False


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
        # Build epoch. invalidate() bumps it; a build that started under an older epoch has been
        # REJECTED while it was still running and must not publish. Without this, an invalidate
        # arriving while the (slow, async) build was in flight found _artifact None, recorded
        # nothing, and the build then published the very artifact the repair meant to reject --
        # so the second repair request was silently lost (upstream, PR #82).
        self._build_epoch = 0
        self._swept_orphans = False
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
        except SnapshotBuildInvalidated:
            # A repair landed mid-build. Nothing is broken, so do NOT arm the failure backoff:
            # the next tick should start the replacement build straight away.
            _log.info("snapshot.build_rejected reason=invalidated_mid_build; retrying at once")
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
        # Retry retirements whose cleanup failed, BEFORE consuming space for a new generation.
        # _sweep_retired() was reachable only from release() and _unpin(), both of which need a
        # slot that was actually restored and then reaped. When cleanup of a retired generation
        # fails, its RAM-sized .mem stays on the snapshot filesystem -- which is itself a reason
        # the next build fails before producing any slot. Neither trigger could then ever fire,
        # so the tier stayed wedged even after the transient unlink problem cleared. The build
        # path is the one thing guaranteed to run on every retry (upstream, PR #82).
        self._sweep_retired()
        # Reclaim generations left by a dispatcher that is gone. Done here rather than at import
        # or construction so it runs on the first real build, with the directories already
        # created. Best-effort: a failed sweep must never block bringing the tier up.
        if not self._swept_orphans:
            sweep = getattr(self._backend, "sweep_orphan_generations", None)
            if not callable(sweep):
                self._swept_orphans = True          # nothing to retry on this backend
            else:
                try:
                    # Hand over the checkpoint root when the backend asks for it. FC's launcher
                    # already owns its own base/mem dirs, but gVisor's backend only learns the
                    # path at checkpoint() time -- far too late for a sweep that must run BEFORE
                    # the first build consumes the space. Introspection, not except-TypeError: a
                    # TypeError raised INSIDE a sweep must never be mistaken for an older
                    # signature (same reasoning as _accepts_kwarg in pool.py).
                    if _accepts_kwarg(sweep, "base_dir"):
                        sweep(base_dir=self._base_dir)
                    else:
                        sweep()
                except Exception as exc:  # noqa: BLE001
                    # LATCH ONLY ON SUCCESS. The flag was set before the call, so a transient
                    # EIO/EROFS during startup reclamation left the orphan in place and the sweep
                    # never ran again for the life of the process. That orphan is a RAM-sized .mem
                    # -- itself a reason the replacement build fails for want of space -- so the
                    # tier could stay blocked long after the filesystem recovered. Leaving the
                    # flag clear costs one extra directory scan per retry and is idempotent
                    # (unlink is missing_ok) (upstream, PR #82).
                    _log.warning(
                        "snapshot.orphan_sweep_failed (retrying on the next build): %s", exc
                    )
                else:
                    self._swept_orphans = True
        # boot_base() is its own try so a base-boot failure is wrapped as
        # SnapshotBuildError (as documented), not propagated raw. boot_base already
        # tears down its own sandbox on partial failure, so no handle/finally is
        # needed here — there is nothing to kill until it returns a BootHandle.
        with self._build_lock:
            epoch = self._build_epoch
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
            # FAILURE paths still tear the base down unconditionally -- there is no artifact to
            # protect here, and leaving the base microVM running is a straight leak.
            with contextlib.suppress(Exception):
                boot.kill()
            raise
        except BaseException as exc:
            # BaseException, not Exception. Replacing the original `finally: boot.kill()` with
            # typed handlers let a KeyboardInterrupt, SystemExit or task cancellation during
            # wait_ready()/checkpoint() escape WITHOUT tearing the base down, leaving a
            # Firecracker VM or gVisor base container running -- interrupting the dispatcher
            # mid-build leaked one every time. Every unsuccessful exit tears down; only the
            # success path below publishes first (upstream, PR #82).
            with contextlib.suppress(Exception):
                boot.kill()
            if isinstance(exc, Exception):   # readiness / checkpoint failure
                raise SnapshotBuildError(f"warm snapshot build failed: {exc}") from exc
            raise

        # COMPARE AND PUBLISH UNDER ONE LOCK. Checking the epoch and then releasing before
        # assigning left a window in which invalidate() could bump the epoch, observe
        # _artifact is None (so it retires nothing), and this build would then publish the very
        # artifact that repair had just rejected -- losing the request silently and letting
        # restores keep reproducing the wedge. Locking the CHECK but not the ACT is the same
        # mistake as reading the failure streak under the lock and deciding outside it, and as
        # selecting the artifact outside the lock that pins it (upstream, PR #82).
        #
        # PUBLISH BEFORE TEARDOWN: if boot.kill() raised, an unassigned artifact could never be
        # discovered by invalidate() or the reference counting, and every async retry left another
        # generation-stamped, RAM-sized .mem behind. The snapshot is complete and usable here --
        # a failure tearing the BASE down says nothing about it.
        with self._build_lock:
            rejected = epoch != self._build_epoch
            if not rejected:
                self._artifact = artifact
        if rejected:
            # invalidate() landed while this build was running. Publishing now would install the
            # artifact the repair explicitly rejected; discard it instead and let the next build
            # produce a fresh one.
            _log.info("snapshot.build_discarded reason=invalidated_while_building")
            with contextlib.suppress(Exception):
                boot.kill()
            if not self._discard(artifact):
                # Never published and never in _retired, so nothing else can rediscover it: a
                # failed cleanup here leaks a generation-stamped snapshot AND its RAM-sized memory
                # file, permanently. Park it with the other retirements so the sweep retries.
                with self._build_lock:
                    self._retired[id(artifact)] = artifact
            raise SnapshotBuildInvalidated("snapshot invalidated while it was being built")
        try:
            boot.kill()
        except Exception as exc:  # noqa: BLE001 -- a live base VM is a leak, not a bad snapshot
            _log.warning(
                "snapshot.base_teardown_failed: the base microVM may still be running; its "
                "snapshot is registered and usable. %s", exc,
            )
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
            self._build_epoch += 1        # reject any build already in flight
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
        if collect is not None and not self._discard(collect):
            with self._build_lock:
                self._retired[id(collect)] = collect     # retryable, not forgotten
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
        if retired is not None and not self._discard(retired):
            # Cleanup failed (or no hook). Keep it RETRYABLE: popping it from _retired before
            # confirming meant a single failed unlink lost the generation forever -- no later
            # release or invalidation could rediscover it, so repeated rebuilds accumulated
            # RAM-sized files again, which is the leak this whole mechanism exists to stop.
            with self._build_lock:
                self._retired[id(retired)] = retired
        # Opportunistically retry anything whose cleanup failed earlier. Without this a
        # generation held back by one transient unlink error is never attempted again, and the
        # retention becomes the very leak it was meant to prevent.
        self._sweep_retired()

    def _sweep_retired(self) -> None:
        """Re-attempt cleanup for retired generations that nothing pins any more."""
        with self._build_lock:
            pending = [a for k, a in self._retired.items() if self._refs.get(k, 0) <= 0]
        for artifact in pending:
            if self._discard(artifact):
                with self._build_lock:
                    self._retired.pop(id(artifact), None)

    def _discard(self, artifact: object) -> bool:
        """Ask the backend to unlink a fully drained generation.

        Returns True when cleanup is CONFIRMED. Optional hook: a backend that does not implement
        it simply keeps its artifacts, exactly as before -- reported as False so the caller keeps
        the artifact retryable rather than forgetting it.
        """
        discard = getattr(self._backend, "discard", None)
        if not callable(discard):
            return False
        try:
            discard(artifact)
            return True
        except Exception as exc:  # noqa: BLE001 -- reclamation must never raise into reap
            _log.warning("snapshot.discard_failed artifact=%r: %s", artifact, exc)
            return False

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
        # RESERVE THE PIN BEFORE THE SLOW RESTORE. restore_in() reads the snapshot and memory
        # files for its whole duration; pinning only afterwards leaves that entire window
        # unprotected, so a pool-triggered invalidate() racing it sees zero references, calls
        # discard(), and unlinks the files out from under a restore that is still loading them --
        # the restore then fails even though the artifact was perfectly valid.
        #
        # Pin the exact generation used here, NOT self._artifact at the end, which a concurrent
        # invalidate+build may already have replaced.
        with self._build_lock:
            # SELECT and pin under the SAME lock. Reading self._artifact outside it left a
            # window where invalidate() could see no reference, discard that generation, and
            # then this code would pin an ALREADY-DELETED artifact and hand it to restore_in().
            # Taking the lock around only the pin protects the counter, not the choice it counts.
            artifact = self._artifact
            if artifact is None:
                raise SnapshotRestoreError("snapshot not built; call build() first")
            self._pins[sid] = artifact
            self._refs[id(artifact)] = self._refs.get(id(artifact), 0) + 1
        try:
            return self._backend.restore_in(slot_workdir, artifact)
        except SnapshotError as exc:
            # A failed restore never yields a handle, so the slot is never reaped —
            # remove the just-created (empty) workdir so it doesn't leak on the host.
            #
            # ...but only unpin if the backend CONFIRMS the spawned firecracker is gone. If
            # /snapshot/load failed and the subsequent kill ALSO failed, that process may still be
            # alive with the memory file mapped, and a later invalidation would unlink the
            # generation underneath it. Same rule as reap() and the spawn-cleanup path (PR #82).
            if not _restore_left_process_running(exc):
                self._unpin(sid, artifact)
            else:
                _log.warning(
                    "snapshot.restore_cleanup_unconfirmed sid=%s: could not confirm the "
                    "firecracker process is gone; retaining its generation pin", sid,
                )
            shutil.rmtree(slot_workdir, ignore_errors=True)
            raise
        except BaseException as exc:
            # BaseException, not Exception: a KeyboardInterrupt or a cancellation landing mid
            # restore must not strand the pin either -- this slot will never be reaped, so
            # nothing else would ever release it and the generation would be pinned forever,
            # turning the leak fix into a permanent leak.
            #
            # ...but the SAME confirmation rule applies here as on the SnapshotError path above.
            # Guarding one handler and not its sibling in the same function is how this class of
            # bug keeps recurring: an unconfirmed teardown retains the pin, because retaining a
            # generation costs disk while unlinking one under a live mapping corrupts it.
            if not _restore_left_process_running(exc):
                self._unpin(sid, artifact)
            else:
                _log.warning(
                    "snapshot.restore_cleanup_unconfirmed sid=%s (cancelled): could not confirm "
                    "the firecracker process is gone; retaining its generation pin", sid,
                )
            shutil.rmtree(slot_workdir, ignore_errors=True)
            if isinstance(exc, Exception):
                raise SnapshotRestoreError(f"restore failed: {exc}") from exc
            raise

    def _unpin(self, sid: str, artifact: object) -> None:
        """Undo a reservation whose restore never produced a handle.

        Collects the generation if this was its last user AND it was retired while we held it.
        """
        with self._build_lock:
            if self._pins.get(sid) is artifact:
                self._pins.pop(sid, None)
            key = id(artifact)
            self._refs[key] = self._refs.get(key, 1) - 1
            if self._refs[key] <= 0:
                self._refs.pop(key, None)
                retired = self._retired.pop(key, None)
            else:
                retired = None
        if retired is not None and not self._discard(retired):
            # Same rule as release(): an unconfirmed cleanup must stay RETRYABLE. This rollback
            # path was added alongside the retryable release and did not inherit it, so a
            # transient unlink failure here forgot the generation permanently -- the leak this
            # mechanism exists to prevent, reintroduced through its own error handling.
            with self._build_lock:
                self._retired[id(retired)] = retired
        self._sweep_retired()
