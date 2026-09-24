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
import os
import shutil
import threading
import time
from collections.abc import Mapping
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


#: How long a published warm base may be restored before it is rebuilt. Six hours: a base
#: checkpointed minutes earlier served 12/12, one five days old hung every job, and the
#: earlier clock-jump investigation put the edge past 24h. A rebuild is one background base
#: boot, so a margin this wide is cheap. ``BLASTBOX_SNAPSHOT_MAX_AGE_S`` overrides; 0 disables.
DEFAULT_SNAPSHOT_MAX_AGE_S = 6 * 3600.0

#: Past ``SNAPSHOT_AGE_CEILING_FACTOR`` x max-age a base is invalidated even if its refresh keeps
#: failing, and idle slots whose checkpoint is that old are retired. Below it an aged base keeps
#: serving while it is refreshed; past it, restores are expected to hang every job at the worker
#: timeout, which is worse than the pool's cold fallback. 2 x 6h = 12h, half the measured edge.
SNAPSHOT_AGE_CEILING_FACTOR = 2.0



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
        max_age_s: float = 0.0,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._backend = backend
        self._ready_timeout_s = ready_timeout_s
        self._build_retry_backoff_s = build_retry_backoff_s
        # AGE, not failure, is what kills an idle warm tier. A base restored long after it was
        # checkpointed stops serving: measured on toolz2 2026-09-23, redtusk's FC base from
        # 09-18 hung every job while an identical base rebuilt minutes earlier served 12/12.
        # Every other repair path here is REACTIVE -- it waits for failures, each costing the
        # full worker timeout, and an idle tier produces none until the first real job pays.
        # Age is predictable, so it is handled before anyone restores the stale base.
        # 0 disables.
        self._max_age_s = max(0.0, float(max_age_s))
        # monotonic seconds at which the CURRENT artifact was published; None when unbuilt.
        self._published_at: float | None = None
        # A REFRESH builds the replacement while the current base keeps serving, and swaps them
        # only once the new one exists. The staged build observes its ACK under the epoch it
        # WILL have (see _epoch_unlocked); restores meanwhile keep pinning the current epoch.
        self._staging_epoch: int | None = None
        # Backoff for a failed refresh, separate from the build backoff: a failed refresh is not
        # an outage (the old base keeps serving), so it must not gate a real rebuild.
        self._refresh_not_before: float = 0.0
        # Set on a swap and drained by the runtime's take_repaired_tiers(), so the pool advances
        # its generation and old-generation failures stop being charged to the new base.
        self._repaired = False
        # A finished refresh is STAGED, not published: only take_repaired() -- the pool's drain,
        # on the thread that also stamps and spawns slots -- swaps it in. Published by the refresh
        # thread at an arbitrary moment, a slot restored from the new base could carry the
        # generation stamp the pool took just before, and be discarded as retired evidence.
        self._staged: object | None = None
        self._staged_for: object | None = None
        self._staged_epoch: int | None = None
        self._staged_at: float | None = None
        #: slot_id -> publish time of the artifact that slot restored from (its checkpoint age).
        self._pin_born: dict[str, float] = {}
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
                    setattr(backend, _attr, self._epoch_unlocked)
                _l = getattr(backend, "_launcher", None)
                if _l is not None and getattr(_l, _attr, "missing") is None:
                    setattr(_l, _attr, self._epoch_unlocked)
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

    def _retire_locked(self, artifact: object) -> object | None:
        """Supersede ``artifact``: retire it if slots still map it, else hand it back to collect.

        CALLER MUST HOLD ``_build_lock``. RETIRE, don't unlink: slots restored from this
        generation are still mapping its memory file, and pulling it out from under a live microVM
        SIGBUSes or silently corrupts it; release() collects it when the last user is reaped. When
        it is already fully drained -- the COMMON ordering, since slots are usually reaped before
        the rebuild that supersedes their generation -- retiring it would leave nothing to trigger
        the collection and it would leak forever, so it is returned for the caller to discard
        outside the lock.
        """
        key = id(artifact)
        if self._refs.get(key, 0) > 0:
            self._retired[key] = artifact
            return None
        return artifact

    def take_repaired(self) -> bool:
        """Swap in a staged refresh and report it -- True once per repair the pool must record.

        The pool's drain calls this on its tick thread, BEFORE it stamps and spawns slots, so
        the swap and the generation it advances are one step as far as any slot can tell.
        """
        with self._build_lock:
            out, self._repaired = self._repaired, False
            swapped, collect = self._swap_staged_locked()
            if collect is not None:
                # PARKED, not discarded here: the pool calls this under its own lock, and a
                # discard is a RAM-sized unlink. The next release/_unpin/build sweeps it.
                self._retired[id(collect)] = collect
        return out or swapped

    def _swap_staged_locked(self) -> "tuple[bool, object | None]":
        """Swap a staged refresh in. CALLER MUST HOLD ``_build_lock``.

        Returns (swapped, artifact to collect outside the lock).
        """
        if self._staged is None:
            return False, None
        swapped = False
        adopted = self._staged_for is None
        expected = self._build_epoch if adopted else self._build_epoch + 1
        if self._artifact is self._staged_for and self._staged_epoch == expected:
            collect = None if adopted else self._retire_locked(self._artifact)
            self._build_epoch = self._staged_epoch
            self._artifact = self._staged
            self._published_at = self._staged_at
            self._build_error = None
            if self._ack_capable is not None:
                self._install_ack(self._build_epoch)
            _log.info("snapshot.refreshed epoch=%d -- the superseded base is retired",
                      self._build_epoch)
            swapped = True
        else:   # unreachable: invalidate() discards a staged refresh
            collect = self._staged
        self._clear_staged_locked()
        return swapped, collect

    def slot_should_retire(self, slot_id: object) -> bool:
        """Retire an idle slot whose CHECKPOINT is past the age ceiling.

        Measured from the checkpoint the slot restored, not from its own restore: a slot restored
        from a base just under the limit would otherwise live another full window on a checkpoint
        nearly twice as old. Only past the ceiling -- below it an aged slot is still well inside the
        safe window, and retiring every one at a swap emptied the claimable pool at once; they
        turn over on use.
        """
        if self._max_age_s <= 0:
            return False
        with self._build_lock:
            born = self._pin_born.get(str(slot_id))
        if born is None:
            return False
        return time.monotonic() - born >= self._ceiling_s

    @classmethod
    def from_env(
        cls,
        base_dir: Path,
        backend: "SnapshotBackend",
        *,
        ack_capable: "_AckPublishable | None" = None,
        env: "Mapping[str, str] | None" = None,
    ) -> "SnapshotManager":
        """The ONE place the snapshot knobs are read, for every runtime that builds a manager.

        The Firecracker and gVisor factories each assembled these kwargs themselves, so a knob
        added to one could silently be missing from the other.
        """
        from blastbox.host.runtime.env_knobs import max_age_env, positive_float_env

        e = os.environ if env is None else env
        return cls(
            base_dir, backend, ack_capable=ack_capable,
            ready_timeout_s=positive_float_env(e, "BLASTBOX_SNAPSHOT_READY_S", 120.0),
            max_age_s=max_age_env(e, "BLASTBOX_SNAPSHOT_MAX_AGE_S", DEFAULT_SNAPSHOT_MAX_AGE_S),
        )

    def base_age_s(self) -> float | None:
        """Seconds since the current base was published, or None when there is none."""
        with self._build_lock:
            born = self._published_at if self._artifact is not None else None
        return None if born is None else max(0.0, time.monotonic() - born)

    @property
    def max_age_s(self) -> float:
        return self._max_age_s

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

    def _epoch_unlocked(self) -> int:
        """The build epoch WITHOUT taking _build_lock. For the sampler callbacks only.

        The bound sampler is invoked by the BACKEND from inside boot_base(), which today never
        holds _build_lock -- but the callback closes over `self`, so `lambda: self.build_epoch`
        re-enters this manager's lock, and _build_lock is a plain Lock: any future caller that
        samples while holding it self-deadlocks the build thread outright. Reading the int
        directly is atomic under the GIL and cannot deadlock, and the value is exactly what the
        property would have returned the instant after releasing. Two reviewers circled this
        independently; the hazard is not worth keeping for a lock that buys nothing here.
        """
        staged = self._staging_epoch
        return self._build_epoch if staged is None else staged

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
        retrying, so a persistently-failing base boot doesn't churn the host every tick.

        Also where AGE is decided, under the same lock that starts the build thread, so two ticks
        (or a cascade's concurrent prepare() calls) cannot both act on one aged base."""
        collect: list[object] = []
        try:
            with self._build_lock:
                if self._artifact is not None:
                    age = self._age_locked()
                    if age is None or age < self._ceiling_s:
                        self._maybe_start_refresh_locked(age)
                        return
                    if self._staged is not None:
                        # The replacement is already in hand -- tick() judges the ceiling before
                        # its drain swaps it in. Leave it for the drain (at most one tick):
                        # swapping here would publish mid-batch, since a cascade calls
                        # prepare() per spawn.
                        return
                    # PAST THE CEILING. The refresh has failed (or is still booting) for a whole
                    # max-age; restores from here are expected to hang. Drop the base: a refresh
                    # still in flight is then adopted as the repair (see _build), otherwise the
                    # ordinary build below starts. Reported so the pool retires the generation.
                    _log.error(
                        "snapshot.aged_past_ceiling age_s=%.0f ceiling_s=%.0f -- the refresh has "
                        "not replaced this base; dropping it rather than serving hangs",
                        age, self._ceiling_s,
                    )
                    collect = self._invalidate_locked()
                    self._repaired = True
                if self._build_thread is not None and self._build_thread.is_alive():
                    return
                if self._staged is not None:
                    return        # an adopted refresh is waiting for the pool's drain
                if time.monotonic() < self._retry_not_before:
                    return
                self._build_thread = threading.Thread(
                    target=self._build_worker, daemon=True, name="warm-snapshot-build"
                )
                self._build_thread.start()
        finally:
            for artifact in collect:
                self._collect(artifact)

    def _age_locked(self) -> "float | None":
        """Age of the published base, or None when max-age is off or nothing is published."""
        if self._max_age_s <= 0 or self._published_at is None:
            return None
        return time.monotonic() - self._published_at

    @property
    def _ceiling_s(self) -> float:
        return self._max_age_s * SNAPSHOT_AGE_CEILING_FACTOR

    def _maybe_start_refresh_locked(self, age: "float | None") -> None:
        """Start ONE background refresh of an aged base. CALLER MUST HOLD ``_build_lock``.

        It REFRESHES rather than invalidates: invalidate-then-build dropped the working base
        before its replacement existed, so a failed rebuild left the tier with nothing, and a
        second invalidation could reject the first one's build.
        """
        if (age is None or age < self._max_age_s or self._staged is not None
                or (self._build_thread is not None and self._build_thread.is_alive())
                or time.monotonic() < self._refresh_not_before):
            return
        _log.info(
            "snapshot.aged_out age_s=%.0f max_age_s=%.0f -- building a replacement; the current "
            "base keeps serving until it is ready (BLASTBOX_SNAPSHOT_MAX_AGE_S; 0 disables)",
            age, self._max_age_s,
        )
        # The refresh's epoch is fixed HERE, not when _build() gets round to sampling it: the
        # thread first runs housekeeping (undead-base retry, sweeps) that can take a runsc
        # timeout, and an invalidate landing in that window must count as one that landed on
        # the refresh -- adopted if it is the only one, rejecting it if a second follows. No other
        # build runs while this thread is alive, so the staged epoch is also what its boot's ACK
        # observation must name.
        start = self._build_epoch
        self._staging_epoch = start + 1
        self._build_thread = threading.Thread(
            target=self._refresh_worker, args=(self._artifact, start), daemon=True,
            name="warm-snapshot-refresh",
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
            # SUPERSEDED-CHECK, in the same critical section that arms the backoff. invalidate()
            # deliberately clears _retry_not_before ("this is a deliberate rebuild request, not a
            # retry of a build that just failed") -- but it does so under a SEPARATE hold, and the
            # async build spends its whole boot+wait_ready window outside the lock. A repair
            # landing after this build failed but before it reached here was then overwritten:
            # the replacement build was refused for build_retry_backoff_s, prepare() kept
            # returning False, and every job fell to the cold tier for 30s immediately after the
            # repair that was supposed to restore warm capacity.
            with self._build_lock:
                # Taken from the FAILURE, which carries the epoch its attempt ran under. Absent
                # means the attempt died before build() ever sampled one (mkdir/ENOSPC and the
                # sweeps run first), and that is judged GENUINE: the safe direction is a spurious
                # 30s cold window, not a hot retry loop of full base boots against a persistent
                # filesystem fault.
                _attempt = getattr(exc, "attempt_epoch", None)
                superseded = _attempt is not None and _attempt != self._build_epoch
                if not superseded:
                    self._build_error = exc
                    self._retry_not_before = time.monotonic() + self._build_retry_backoff_s
            if superseded:
                _log.info(
                    "snapshot.build_failed_but_superseded reason=repair_landed_during_failure "
                    "-- not arming the backoff; the replacement build starts at once: %s", exc,
                )
            else:
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
        # WAIT for a build already running rather than overlap it. A refresh adopted as the repair
        # of an invalidation holds the very epoch a second build would sample, and begin_build()
        # of one erases the other's ACK observation. Never join ourselves: the background build
        # thread runs this method.
        running = self._build_thread
        if (running is not None and running is not threading.current_thread()
                and running.is_alive()):
            running.join()
        with self._build_lock:
            # build() is the synchronous, pool-less entry point (the pool spawns through
            # acquire_built()), so there is no drain to wait for: take an adopted refresh here.
            if self._artifact is None and self._staged is not None and self._staged_for is None:
                self._swap_staged_locked()
            if self._artifact is not None:
                return self._artifact
        return self._build()

    def _refresh_worker(self, replacing: object, start_epoch: int) -> None:
        """Build a replacement for an aged base while it keeps serving; stage it on success."""
        # A full, idle pool never reaches acquire_built(), so this may be the only build path
        # running -- and each failed refresh can park another base whose teardown failed.
        self._retry_undead_bases()
        try:
            self._build(replacing=replacing, epoch=start_epoch)
        except SnapshotBuildInvalidated:
            _log.info("snapshot.refresh_superseded: a repair replaced the base while the "
                      "refresh was building; the next tick builds from that state")
        except Exception as exc:  # noqa: BLE001 -- the old base keeps serving; back off, retry
            with self._build_lock:
                self._refresh_not_before = time.monotonic() + self._build_retry_backoff_s
            _log.warning(
                "snapshot.refresh_failed -- the current base keeps serving; retry after %.0fs: %s",
                self._build_retry_backoff_s, exc,
            )

    def _build(self, replacing: object | None = None, epoch: int | None = None) -> object:
        """Boot, checkpoint and publish a base. ``replacing`` makes it a refresh: the artifact
        it names keeps serving throughout and is swapped out only if it is still current when the
        replacement is ready."""
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
            if epoch is None:           # a refresh brings the epoch it STARTED under
                epoch = self._build_epoch
            if replacing is not None:
                self._staging_epoch = epoch + 1
        try:
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
            outcome = "published"
            rejected = False
            with self._build_lock:
                if replacing is None:
                    rejected = epoch != self._build_epoch
                    if not rejected:
                        self._artifact = artifact
                        self._published_at = time.monotonic()
                        if self._ack_capable is not None:
                            self._install_ack(epoch)
                else:
                    if epoch == self._build_epoch and self._artifact is replacing:
                        # Nothing moved: STAGE it. take_repaired() swaps it in (see __init__).
                        self._staged = artifact
                        self._staged_for = replacing
                        self._staged_epoch = epoch + 1
                        self._staged_at = time.monotonic()
                        outcome = "staged"
                    elif self._artifact is None and self._build_epoch == epoch + 1:
                        # ONE invalidate() landed mid-refresh. This is a fresh boot -- exactly
                        # what the repair would build -- and its ACK was observed under the very
                        # epoch the repair gave the next build, so it IS the repair. Rejecting it
                        # left the tier cold behind this thread and then for a second full build.
                        # STAGED like any refresh, never published from this thread: the pool
                        # advances its generation only after drop() returns, and a base that
                        # appeared inside that window would be restored under the old stamp.
                        self._staged = artifact
                        self._staged_for = None              # nothing is serving
                        self._staged_epoch = self._build_epoch
                        self._staged_at = time.monotonic()
                        outcome = "adopted"
                    else:
                        rejected = True    # convicted again, or replaced: stale
                    self._staging_epoch = None
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
            if replacing is not None:
                _log.info("snapshot.refresh_%s epoch=%d", outcome, epoch + 1)
            return artifact
        except BaseException as exc:
            # THE EPOCH TRAVELS WITH THE FAILURE. It used to be published to instance state and
            # compared later, which is the same split read three earlier fixes on this branch each
            # reintroduced one layer further in -- and the last one assumed an unsampled attempt
            # would leave None. It does not: _retry_undead_bases(), _base_dir.mkdir() and
            # _sweep_retired() all run BEFORE the sample, so a failure there left the PREVIOUS
            # attempt's epoch behind. Stale, not None, so the None-guard never fired and a
            # persistent ENOSPC was reclassified as "superseded" and retried every tick.
            #
            # Attached to the exception, the value cannot be stale by construction: a failure
            # before the sample carries nothing, and absence reads as "judge it genuine", which
            # arms the backoff -- the safe direction.
            with contextlib.suppress(Exception):   # exotic exceptions may reject attributes
                exc.attempt_epoch = epoch          # type: ignore[attr-defined]
            raise
        finally:
            if replacing is not None:
                with self._build_lock:
                    if self._staging_epoch == epoch + 1:
                        self._staging_epoch = None

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
            collect = self._invalidate_locked()
        for artifact in collect:
            self._collect(artifact)
        return had

    def _invalidate_locked(self) -> "list[object]":
        """Drop the published (and any staged) base. CALLER MUST HOLD ``_build_lock``.

        Returns the artifacts to collect OUTSIDE the lock. A STAGED refresh is discarded rather
        than adopted: the invalidator advances the pool's generation right now, and a base
        appearing between that and a spawn's restore would carry the stamp of the one convicted.
        """
        self._build_epoch += 1        # reject any build already in flight
        collect: list[object] = []
        if self._artifact is not None:
            retired = self._retire_locked(self._artifact)
            if retired is not None:
                collect.append(retired)
        if self._staged is not None:
            collect.append(self._staged)    # never published: nothing maps it
            self._clear_staged_locked()
        self._artifact = None
        self._published_at = None
        self._build_error = None
        # Do not reuse the previous failure backoff: this is a deliberate rebuild request,
        # not a retry of a build that just failed.
        self._retry_not_before = 0.0
        return collect

    def _clear_staged_locked(self) -> None:
        self._staged = self._staged_for = None
        self._staged_epoch = None
        self._staged_at = None

    def _collect(self, artifact: object) -> None:
        """Discard a drained generation; on failure park it so the sweep retries."""
        if not self._discard(artifact):
            with self._build_lock:
                self._retired[id(artifact)] = artifact     # retryable, not forgotten

    def release(self, slot_id: object) -> None:
        """Called when a restored slot is reaped: drop its pin and reclaim drained generations.

        Never raises -- reap must not be taken down by cleanup.
        """
        with self._build_lock:
            # Only a FAILED restore goes through _unpin(), so without this line the normal reap
            # path never dropped the epoch entry: one dict entry per slot ever restored, for the
            # life of a dispatcher that recycles slots continuously.
            #
            # Placed before the early return DEFENSIVELY, not because a reachable state needs it:
            # restore(), release() and _unpin() all write _pins and _pin_epoch under one hold of
            # _build_lock, so an epoch entry without a matching pin should not exist. An earlier
            # version of this comment claimed the ordering was load-bearing; a reviewer showed it
            # is not, and an unreachable justification is worse than none -- it is what stops the
            # next person deleting a line that has become wrong.
            self._pin_epoch.pop(str(slot_id), None)
            self._pin_born.pop(str(slot_id), None)
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
            if self._published_at is not None:
                self._pin_born[sid] = self._published_at
            self._refs[id(artifact)] = self._refs.get(id(artifact), 0) + 1
        try:
            return self._backend.restore_in(slot_workdir, artifact)
        except SnapshotError as exc:
            _keep_workdir = False
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
                # ...and DO NOT remove the workdir either. Retaining the pin but deleting the
                # directory is half a rule: that firecracker may still have this slot's disk
                # and sockets open, so removing it pulls them out from under a live microVM.
                # The stranded-partial sweep reclaims it once the process is confirmed gone
                # (codex, #154).
                _keep_workdir = True
            if not _keep_workdir:
                shutil.rmtree(slot_workdir, ignore_errors=True)
            raise
        except BaseException as exc:
            _keep_workdir = False
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
                _keep_workdir = True    # same rule as the sibling handler above
            if not _keep_workdir:
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
                self._pin_born.pop(sid, None)
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
