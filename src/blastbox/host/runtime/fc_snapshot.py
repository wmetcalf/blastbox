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
from typing import Protocol

# _accepts_kwarg is the ONE definition of "does this callable declare that parameter" --
# imported rather than copied, which is how the same optional-hook check drifted before.
# pool.py imports nothing from runtime/, so this direction cannot cycle.
from blastbox.host.pool import RuntimeAtCapacity, _accepts_kwarg

from blastbox.host.runtime.snapshot_backend import RestoreHandle, SnapshotBackend


class _AckPublishable(Protocol):
    """The slice of AckCapability the manager needs.

    Structural, not an import of the concrete class: worker.warm owns AckCapability and importing
    it here would tie the snapshot manager to the worker package for a one-method call.
    """

    def begin_build(self) -> None: ...
    def publish(self, epoch: "int | None") -> None: ...

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
        ack_capable: "_AckPublishable | None" = None,
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
        #: slot_id -> the build epoch of the artifact restore() actually pinned for it.
        #: Recorded in the SAME critical section as the selection, because reading the epoch
        #: separately (before or after) lets an invalidate+rebuild land in between and pair a
        #: slot with the wrong identity.
        self._pin_epoch: dict[str, int] = {}
        self._refs: dict[int, int] = {}             # id(artifact) -> live restores
        self._retired: dict[int, object] = {}       # id(artifact) -> superseded, awaiting drain
        # Build epoch. invalidate() bumps it; a build that started under an older epoch has been
        # REJECTED while it was still running and must not publish. Without this, an invalidate
        # arriving while the (slow, async) build was in flight found _artifact None, recorded
        # nothing, and the build then published the very artifact the repair meant to reject --
        # so the second repair request was silently lost (upstream, PR #82).
        self._build_epoch = 0
        # Optional. Set by the snapshot runtimes so PUBLICATION -- not readiness, and not even a
        # successful checkpoint -- is what makes a base's ACK advertisement believable.
        self._ack_capable = ack_capable
        if ack_capable is not None:
            # BIND THE EPOCH SOURCE OURSELVES. The backend stamps each base build with an epoch
            # it must SAMPLE from this manager; an embedder assembling the stack by hand
            # (backend + manager, both handed the same capability) had no reason to know about a
            # new optional sampler, so every advertisement was recorded under None while
            # publication used an integer -- the capability could never become true and the fast
            # repair was silently off. It used to work because the backend sampled the
            # capability's own counter, which no longer exists (issue #92). Wiring that only
            # holds when the caller remembers is not wiring.
            for _attr in ("_epoch_sampler", "_ack_sampler"):
                if getattr(backend, _attr, "missing") is None:
                    setattr(backend, _attr, lambda: self.build_epoch)
                _l = getattr(backend, "_launcher", None)
                if _l is not None and getattr(_l, _attr, "missing") is None:
                    setattr(_l, _attr, lambda: self.build_epoch)
        # Base boot handles whose kill() raised. Suppressing it discarded the ONLY reference to a
        # sandbox that may still be running, and the async retry then booted another beside it --
        # untracked, unreapable, for the life of the process (upstream, PR #82).
        self._undead_bases: list[object] = []
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

    def _install_ack(self, epoch: int) -> None:
        """Make this artifact's ACK advertisement believable. CALLER MUST HOLD ``_build_lock``.

        THE ONE PLACE it becomes true. Backends only OBSERVE at readiness, long before anyone
        knows whether the build yields a usable artifact: a build that advertises and then fails
        to checkpoint, or is rejected here, publishes nothing a slot could restore from.

        Called INSIDE the same critical section that assigns ``_artifact``, because the two are
        one fact. Publishing after the lock was released left a window in which prepare() /
        acquire_built() could expose and restore the new artifact while the capability still
        described the previous epoch -- a job dispatched there evaluates capable_for() at
        wait_for_done() time, reads UNKNOWN, and cannot contribute the missing-start evidence the
        fast repair needs. Fail-safe, but it disables the repair during exactly the rebuild churn
        it exists for.

        AckCapability never calls out, so taking its lock under _build_lock cannot invert.
        """
        assert self._ack_capable is not None
        self._ack_capable.publish(epoch)

    def pinned_epoch(self, slot_id: object) -> "int | None":
        """The build epoch of the artifact ``restore()`` actually pinned for this slot.

        Read this INSTEAD of :attr:`build_epoch` when stamping a slot. build_epoch answers "what
        is current now", and between that read and restore()'s selection an invalidation plus a
        replacement build can complete -- the slot then runs the new artifact carrying the old
        epoch, capable_for() answers False forever, and the fast repair path is silently disabled
        for it during exactly the rebuild churn it exists to handle.
        """
        with self._build_lock:
            return self._pin_epoch.get(str(slot_id))

    @property
    def build_epoch(self) -> int:
        """Identity of the artifact currently installed (or of the build in flight).

        Bumped inside invalidate() under _build_lock, atomically with retiring the artifact, and
        re-read there to reject a build superseded while it ran. It is therefore the only
        identity in the system that cannot drift from the thing it names -- which is why the ACK
        capability is keyed by it rather than by a counter of its own (issue #92).
        """
        with self._build_lock:
            return self._build_epoch

    @property
    def ack_capable(self) -> "_AckPublishable | None":
        """The capability this manager confirms into, for runtimes wired around an INJECTED
        manager.

        The base-readiness listener lives with the backend and the per-slot controls live with
        the runtime; they only work as one answer if both hold the SAME object. A runtime handed
        a ready-made manager cannot build that listener itself, so it has to take the manager's.
        Manufacturing its own left the published base advertising ACK while every restored slot
        read `capable` as false -- missing starts stay UNKNOWN and the three-slot fast repair is
        silently disabled on precisely the wiring an operator chose explicitly.
        """
        return self._ack_capable

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

    def _kill_base(self, boot: object) -> None:
        """Tear a base sandbox down, RETAINING it for retry if the teardown could not be confirmed.

        ``contextlib.suppress`` here threw away the only handle to a sandbox that may still be
        alive: gVisor's boot handle raises when neither teardown command succeeds, and FC's does
        on a process-control failure. The next async build then booted a second base beside the
        first, which nothing tracked and nothing could ever reap.
        """
        try:
            boot.kill()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 -- a failed teardown must not mask the build error
            with self._build_lock:
                self._undead_bases.append(boot)
            _log.warning(
                "snapshot.base_teardown_unconfirmed: the base sandbox may still be running; "
                "retained for retry on the next build. %s", exc,
            )

    def _retry_undead_bases(self) -> None:
        """Re-attempt teardown of base sandboxes a previous build could not confirm gone."""
        with self._build_lock:
            pending = list(self._undead_bases)
            self._undead_bases.clear()
        for boot in pending:
            try:
                boot.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001
                with self._build_lock:
                    self._undead_bases.append(boot)
                _log.warning("snapshot.base_teardown_retry_failed: %s", exc)

    def acquire_built(self) -> object:
        """Return the built artifact, or refuse -- ATOMICALLY against invalidate().

        The runtimes previously asked is_built() and then called build(): a job thread
        invalidating between those two steps left build() with no artifact, so it performed the
        full synchronous base boot on the pool's ONLY maintenance thread and stalled promotion,
        health checks and deferred reaping for up to the readiness timeout. That is the very
        stall the check exists to prevent, reintroduced by splitting it in two.

        invalidate() takes ``_build_lock`` to clear the artifact, so reading it under the same
        lock closes the gap: either we hold a real artifact or the repair already happened and we
        report capacity (upstream, PR #82).
        """
        # Retry here too, NOT only in build(). A checkpoint that succeeds but whose kill() fails
        # retains the base -- and from then on the artifact exists, so ensure_build_started()
        # returns immediately and production spawn() calls THIS method rather than build(). No
        # later call reached the retry while the artifact stayed installed, so the base VM and its
        # host RAM lived as long as the dispatcher. This is the per-spawn path and the list is
        # almost always empty (upstream, PR #82).
        self._retry_undead_bases()
        with self._build_lock:
            artifact = self._artifact
        if artifact is not None:
            return artifact
        self.ensure_build_started()
        raise SnapshotBuildInvalidated(
            "warm snapshot is not built; refusing to build inline on the maintenance thread"
        )

    def build(self) -> object:
        """Build the warm snapshot. Idempotent — a second call returns the same
        artifact without rebuilding. Raises :class:`SnapshotBuildError` on failure
        (callers fall back to cold-boot)."""
        # BEFORE the idempotent early return. A checkpoint that SUCCEEDS but whose boot.kill()
        # fails retains the possibly-live sandbox -- and from then on every build() returns here
        # immediately because the artifact exists, so the retry was unreachable until some
        # unrelated invalidation. The base VM sat running and consuming host RAM through normal
        # operation, which is exactly when the success path retains one (upstream, PR #82).
        self._retry_undead_bases()
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
        # Reclaim generations left by a dispatcher that is gone. EVERY build, deliberately not
        # once per process. The latch produced two separate bugs: it was set before the call, so
        # a transient EIO disabled reclamation for the whole process; and once that was fixed it
        # still latched on a sweep that had SKIPPED a live owner -- during a rolling deployment
        # the old dispatcher legitimately still held its lease, so the sweep "succeeded" having
        # removed nothing, and when that process later exited its RAM-sized generation (often the
        # very thing making this build fail for want of space) could never be reclaimed again.
        # A sweep is a directory glob against a boot-and-checkpoint, and it is idempotent and
        # conservative; running it per build costs nothing worth a latch (upstream, PR #82).
        sweep = getattr(self._backend, "sweep_orphan_generations", None)
        if callable(sweep):
            try:
                # Hand over the checkpoint root when the backend asks for it. FC's launcher
                # already owns its base/mem dirs, but gVisor's backend only learns the path at
                # checkpoint() time -- far too late for a sweep that must run BEFORE the build
                # consumes the space. Introspection, not except-TypeError: a TypeError raised
                # INSIDE a sweep must never be mistaken for an older signature.
                if _accepts_kwarg(sweep, "base_dir"):
                    sweep(base_dir=self._base_dir)
                else:
                    sweep()
            except Exception as exc:  # noqa: BLE001 -- a failed sweep must never block the tier
                _log.warning("snapshot.orphan_sweep_failed (retrying on the next build): %s", exc)
        # boot_base() is its own try so a base-boot failure is wrapped as
        # SnapshotBuildError (as documented), not propagated raw. boot_base already
        # tears down its own sandbox on partial failure, so no handle/finally is
        # needed here — there is nothing to kill until it returns a BootHandle.
        with self._build_lock:
            epoch = self._build_epoch
        # SCOPE the ACK advertisement to THIS attempt. A retry shares the generation of the
        # attempt it replaces (nothing invalidates in between), so a failed build's observation
        # would otherwise be available for a later, possibly ACK-incapable, build to confirm.
        if self._ack_capable is not None:
            self._ack_capable.begin_build()
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
            self._kill_base(boot)
            raise
        except BaseException as exc:
            # BaseException, not Exception. Replacing the original `finally: boot.kill()` with
            # typed handlers let a KeyboardInterrupt, SystemExit or task cancellation during
            # wait_ready()/checkpoint() escape WITHOUT tearing the base down, leaving a
            # Firecracker VM or gVisor base container running -- interrupting the dispatcher
            # mid-build leaked one every time. Every unsuccessful exit tears down; only the
            # success path below publishes first (upstream, PR #82).
            self._kill_base(boot)
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
                if self._ack_capable is not None:
                    self._install_ack(epoch)
        if rejected:
            # invalidate() landed while this build was running. Publishing now would install the
            # artifact the repair explicitly rejected; discard it instead and let the next build
            # produce a fresh one.
            _log.info("snapshot.build_discarded reason=invalidated_while_building")
            self._kill_base(boot)
            if not self._discard(artifact):
                # Never published and never in _retired, so nothing else can rediscover it: a
                # failed cleanup here leaks a generation-stamped snapshot AND its RAM-sized memory
                # file, permanently. Park it with the other retirements so the sweep retries.
                with self._build_lock:
                    self._retired[id(artifact)] = artifact
            raise SnapshotBuildInvalidated("snapshot invalidated while it was being built")
        # Same on the SUCCESS path: the snapshot is registered and usable either way, but a base
        # sandbox we could not confirm gone must stay reachable for retry rather than be logged
        # and forgotten.
        self._kill_base(boot)
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
            self._pin_epoch[sid] = self._build_epoch
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
                self._pin_epoch.pop(sid, None)
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
