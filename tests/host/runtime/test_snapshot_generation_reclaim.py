"""Superseded snapshot generations must be reclaimed — but never while still mapped.

Generation-stamped artifact names fixed a real corruption (rewriting a memory file under live
microVMs), but nothing ever deleted the superseded pair. Each rebuild leaves a .mem roughly the
size of guest RAM — often on /dev/shm — so repeated rebuild episodes exhaust the tmpfs and every
later build fails on ENOSPC. The constraint that makes this non-trivial: a restored microVM keeps
the memory file mapped as its backing store for its whole life, so the pair can only be unlinked
once its LAST user is reaped.
"""
from __future__ import annotations

import contextlib
import pathlib
import time

import pytest

from pathlib import Path

from blastbox.host.runtime.fc_snapshot import SnapshotError, SnapshotManager
from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend


class _FakeBoot:
    def __init__(self, backend: "_FakeBackend") -> None:
        self._be = backend

    def wait_ready(self, timeout_s: float) -> None:
        return None

    def checkpoint(self, dest_dir: Path) -> FcSnapshotArtifact:
        """Write a generation-stamped pair, like the real FC backend."""
        self._be.n += 1
        snap = self._be.root / f"warm-gen{self._be.n}.snapshot"
        mem = self._be.root / f"warm-gen{self._be.n}.mem"
        snap.write_bytes(b"snap")
        mem.write_bytes(b"m" * 1024)
        return FcSnapshotArtifact(snap, mem)

    def kill(self) -> None:
        return None


class _FakeBackend:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.n = 0
    
    def available(self) -> bool:
        return True

    def boot_base(self) -> _FakeBoot:
        return _FakeBoot(self)

    def restore_in(self, slot_workdir: Path, artifact: object) -> object:
        return object()

    # NOT a hand-written discard: delegate to the REAL backend implementation. The first
    # version of this fake invented `snapshot`/`mem` field names, the production discard()
    # read those same wrong names via getattr-with-default, and the pair agreed with each
    # other while unlinking nothing at all in production. A fake that reimplements the code
    # under test can only ever prove the fake works.
    discard = FcSnapshotBackend.discard

    def __getattr__(self, name: str):
        raise AttributeError(name)


def _mgr(tmp_path: Path) -> tuple[SnapshotManager, _FakeBackend]:
    root = tmp_path / "snap"
    root.mkdir(parents=True, exist_ok=True)
    be = _FakeBackend(root)
    return SnapshotManager(root, be), be


def _gens(tmp_path: Path) -> set[str]:
    return {p.name for p in (tmp_path / "snap").glob("warm-*.mem")}


def test_a_superseded_generation_is_reclaimed_once_its_last_user_is_reaped(tmp_path):
    mgr, be = _mgr(tmp_path)
    mgr.build()
    mgr.restore("slot-a")
    mgr.restore("slot-b")
    assert _gens(tmp_path) == {"warm-gen1.mem"}

    mgr.invalidate()
    mgr.build()
    mgr.restore("slot-c")
    assert _gens(tmp_path) == {"warm-gen1.mem", "warm-gen2.mem"}

    # gen1 still has TWO live users -- unlinking now would pull the backing store out from
    # under running microVMs.
    mgr.release("slot-a")
    assert "warm-gen1.mem" in _gens(tmp_path), "still mapped by slot-b — must not be unlinked"

    mgr.release("slot-b")
    assert _gens(tmp_path) == {"warm-gen2.mem"}, "gen1 drained; its files must be reclaimed"


def test_the_current_generation_is_never_reclaimed(tmp_path):
    """Only SUPERSEDED generations are collectable. Reaping every slot of the live generation
    must not delete the artifact the next spawn restores from."""
    mgr, _ = _mgr(tmp_path)
    mgr.build()
    mgr.restore("slot-a")
    mgr.release("slot-a")
    assert _gens(tmp_path) == {"warm-gen1.mem"}, "the CURRENT generation must survive"


def test_repeated_rebuilds_do_not_accumulate_generations(tmp_path):
    """The actual leak: without reclamation this grows without bound until the tmpfs is full."""
    mgr, _ = _mgr(tmp_path)
    for i in range(10):
        mgr.build()
        mgr.restore(f"slot-{i}")
        mgr.release(f"slot-{i}")
        mgr.invalidate()
    # every generation but the last was fully drained before being superseded
    assert len(_gens(tmp_path)) <= 1, (
        f"superseded generations accumulated: {sorted(_gens(tmp_path))}"
    )


def test_release_of_an_unknown_slot_is_a_no_op(tmp_path):
    """reap() must never be taken down by cleanup — including double-reap and unknown slots."""
    mgr, _ = _mgr(tmp_path)
    mgr.build()
    mgr.restore("slot-a")
    mgr.release("slot-a")
    mgr.release("slot-a")     # double reap
    mgr.release("never-seen")
    assert _gens(tmp_path) == {"warm-gen1.mem"}


def test_a_generation_is_pinned_before_the_slow_restore_not_after(tmp_path):
    """The pin must cover the ENTIRE restore, not just the moment after it.

    restore_in() reads the snapshot and memory files for its whole duration. Pinning only after
    it returns leaves that window unprotected: a pool-triggered invalidate() racing it sees zero
    references, discards the generation, and unlinks the files out from under a restore that is
    still loading them — so a perfectly valid artifact produces a failed restore.
    """
    mgr, be = _mgr(tmp_path)
    mgr.build()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"
    assert gen1.exists()

    seen: dict[str, bool] = {}

    real_restore = be.restore_in

    def _restore_racing_an_invalidate(slot_workdir, artifact):
        # mid-restore: the pool decides the base is bad and rebuilds
        mgr.invalidate()
        mgr.build()
        seen["files_present_during_restore"] = gen1.exists()
        return real_restore(slot_workdir, artifact)

    be.restore_in = _restore_racing_an_invalidate  # type: ignore[assignment]
    mgr.restore("slot-a")

    assert seen["files_present_during_restore"], (
        "the generation being restored was unlinked mid-restore — the pin came too late"
    )


def test_a_failed_restore_does_not_strand_the_pin(tmp_path):
    """Rolling the reservation back matters as much as taking it.

    A restore that raises never yields a handle, so its slot is never reaped and nothing would
    ever release the pin — the generation would be held forever, turning the leak fix into a
    permanent leak.
    """
    mgr, be = _mgr(tmp_path)
    mgr.build()

    def _boom(slot_workdir, artifact):
        raise RuntimeError("restore failed")

    be.restore_in = _boom  # type: ignore[assignment]
    with pytest.raises(Exception):
        mgr.restore("slot-a")

    # the generation is now unreferenced, so superseding it must reclaim it
    mgr.invalidate()
    assert _gens(tmp_path) == set(), (
        f"a failed restore stranded its pin — generation never reclaimed: {_gens(tmp_path)}"
    )


def test_a_restore_failing_with_a_SnapshotError_also_releases_its_pin(tmp_path):
    """Both failure handlers must roll the reservation back.

    restore() has two: one preserving the SnapshotError taxonomy, one wrapping everything else.
    A rollback added to only one leaves the other stranding pins forever — and mutation testing
    is the only thing that distinguishes them, since either alone makes the generic test pass.
    """
    from blastbox.host.runtime.fc_snapshot import SnapshotRestoreError

    mgr, be = _mgr(tmp_path)
    mgr.build()

    def _boom(slot_workdir, artifact):
        raise SnapshotRestoreError("restore failed inside the backend")

    be.restore_in = _boom  # type: ignore[assignment]
    with pytest.raises(SnapshotRestoreError):
        mgr.restore("slot-a")

    mgr.invalidate()
    assert _gens(tmp_path) == set(), (
        f"the SnapshotError path stranded its pin: {_gens(tmp_path)}"
    )


def test_the_generation_is_selected_and_pinned_under_one_lock(tmp_path):
    """Selecting the artifact outside the lock leaves it discardable before it is pinned.

    Taking the lock around only the pin protects the COUNTER, not the choice it counts: an
    invalidate() landing between an unlocked read and the lock sees no reference, discards that
    generation, and restore() then pins an already-deleted artifact and hands it to restore_in().

    The window exists only in the broken version, so it cannot be observed single-threaded. This
    forces the interleaving with EVENTS rather than sleeps — a timing-based version of this test
    caught the bug in isolation and missed it under load, which is worse than no test at all.
    """
    import threading

    mgr, be = _mgr(tmp_path)
    mgr.build()

    restored_with: list[Path] = []
    real_restore = be.restore_in

    def _record(slot_workdir, artifact):
        restored_with.append(Path(artifact.mem_path))
        return real_restore(slot_workdir, artifact)

    be.restore_in = _record  # type: ignore[assignment]

    entered = threading.Event()
    racer_done = threading.Event()

    class _GatedLock:
        """Delegates to the real lock, but the FIRST acquisition waits until the racer has
        finished invalidating. Only the first — otherwise the racer's own invalidate() would
        deadlock on this same wrapper."""

        def __init__(self, inner):
            self._inner = inner
            self._armed = True

        def __enter__(self):
            if self._armed:
                self._armed = False
                entered.set()
                racer_done.wait(5.0)      # deterministic: no sleeps, no timing assumptions
            return self._inner.__enter__()

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

    def _racer():
        entered.wait(5.0)
        mgr.invalidate()          # discards any generation nothing has pinned yet
        mgr.build()
        racer_done.set()

    mgr._build_lock = _GatedLock(mgr._build_lock)  # type: ignore[assignment]
    th = threading.Thread(target=_racer, daemon=True)
    th.start()
    mgr.restore("slot-a")
    th.join(10.0)
    assert racer_done.is_set(), "the racing invalidate never ran — the test proved nothing"

    assert restored_with, "restore_in must have been reached"
    assert restored_with[0].exists(), (
        f"restore_in() was handed a generation deleted out from under it: {restored_with[0]} — "
        "the artifact was selected before the lock that protects the pin"
    )


def test_a_spawn_that_cannot_publish_its_slot_releases_the_pin(tmp_path):
    """A restore that never becomes a Slot must not strand its generation.

    restore() pins before restore_in(), but the runtime then reads handle.vsock_uds and mkdirs
    the per-slot dirs. If any of that fails — a full host disk is the obvious way — spawn()
    raises without returning a Slot, so the pool can never reap it and nothing will ever call
    release(slot_id): the pin, and the running microVM behind it, are retained until the process
    restarts.
    """
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    mgr, be = _mgr(tmp_path)

    killed: list[bool] = []

    class _HandleWithBadUds:
        @property
        def vsock_uds(self):
            raise OSError("ENOSPC reading the restored handle")

        def kill(self):
            killed.append(True)

    be.restore_in = lambda w, a: _HandleWithBadUds()  # type: ignore[assignment]
    class _Cfg:
        max_extracted_bytes = 1 << 20

    rt = SnapshotSlotRuntime(_Cfg(), mgr, settle_s=0.0)
    mgr.build()   # spawn() no longer builds INLINE -- that is what stalled the tick thread

    with pytest.raises(Exception):
        rt.spawn()

    assert killed, "the un-publishable microVM must be killed, not leaked"
    # the pin must be gone: superseding the generation now reclaims it
    mgr.invalidate()
    assert _gens(tmp_path) == set(), (
        f"spawn stranded its pin — generation never reclaimed: {_gens(tmp_path)}"
    )


def test_a_generation_is_retained_when_the_vm_cannot_be_confirmed_dead(tmp_path):
    """Never unlink a file a live VM may still map.

    reap() swallows a kill() failure so it can finish cleaning up — but the microVM may still be
    running and still mapping this generation's memory file. Releasing the pin anyway can unlink
    it underneath. Retaining costs disk until restart; unlinking corrupts a live VM.
    """
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    mgr, be = _mgr(tmp_path)

    class _UnkillableHandle:
        vsock_uds = str(tmp_path / "slots" / "x" / "vsock.sock")

        def kill(self):
            raise RuntimeError("SIGKILL failed; the microVM may still be running")

    (tmp_path / "slots" / "x").mkdir(parents=True, exist_ok=True)
    be.restore_in = lambda w, a: _UnkillableHandle()  # type: ignore[assignment]
    class _Cfg:
        max_extracted_bytes = 1 << 20

    rt = SnapshotSlotRuntime(_Cfg(), mgr, settle_s=0.0)
    mgr.build()   # spawn() no longer builds INLINE -- that is what stalled the tick thread

    slot = rt.spawn()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"
    assert gen1.exists()

    mgr.invalidate()      # supersede it while the slot is live
    mgr.build()
    # kill() raises -> the VM is NOT provably gone. reap propagates so the pool quarantines the
    # slot rather than recording a successful disposal and replacing it.
    with pytest.raises(SnapshotError):
        rt.reap(slot)

    assert gen1.exists(), (
        "a generation was unlinked while its microVM could not be confirmed dead"
    )


def test_a_build_whose_base_teardown_fails_still_registers_its_artifact(tmp_path):
    """An artifact nobody can discover is a permanent leak.

    build() tore the base VM down in a finally BEFORE assigning self._artifact, so a kill() that
    raised meant the artifact was never registered — invisible to invalidate() and to the
    reference counting alike. With generation-stamped names, every async retry after such a
    failure left another RAM-sized .mem behind until the disk filled. The snapshot itself is
    complete and usable at that point; a failure tearing the BASE down says nothing about it.
    """
    mgr, be = _mgr(tmp_path)

    class _BootThatWontDie(_FakeBoot):
        def kill(self):
            raise RuntimeError("could not kill the base microVM")

    be.boot_base = lambda: _BootThatWontDie(be)  # type: ignore[assignment]

    art = mgr.build()
    assert art is not None
    assert mgr.artifact is art, "the artifact must be registered despite the teardown failure"

    # ...and being registered, it is now reclaimable like any other generation
    mgr.invalidate()
    assert _gens(tmp_path) == set(), (
        f"an orphaned generation was left behind: {_gens(tmp_path)}"
    )


def test_a_failed_build_still_tears_down_its_base(tmp_path):
    """Publishing before teardown must not stop failures from killing the base.

    There is no artifact to protect on a failure path, and leaving the base microVM running is a
    straight leak — the guard this replaced existed for exactly that.
    """
    mgr, be = _mgr(tmp_path)
    killed: list[bool] = []

    class _BootThatFails(_FakeBoot):
        def checkpoint(self, dest_dir):
            raise RuntimeError("checkpoint failed")

        def kill(self):
            killed.append(True)

    be.boot_base = lambda: _BootThatFails(be)  # type: ignore[assignment]

    with pytest.raises(Exception):
        mgr.build()
    assert killed, "a failed build must still tear its base down"


def test_a_build_failing_with_a_SnapshotError_also_tears_down_its_base(tmp_path):
    """Both failure handlers must kill the base.

    build() has two: one preserving the SnapshotError taxonomy, one wrapping everything else.
    A teardown added to only one leaks a base microVM on the other — and mutation testing is the
    only thing that tells them apart, since either alone makes the generic test pass.
    """
    from blastbox.host.runtime.fc_snapshot import SnapshotBuildError

    mgr, be = _mgr(tmp_path)
    killed: list[bool] = []

    class _BootThatFailsTyped(_FakeBoot):
        def checkpoint(self, dest_dir):
            raise SnapshotBuildError("checkpoint failed (typed)")

        def kill(self):
            killed.append(True)

    be.boot_base = lambda: _BootThatFailsTyped(be)  # type: ignore[assignment]

    with pytest.raises(SnapshotBuildError):
        mgr.build()
    assert killed, "the SnapshotError path must still tear its base down"


def test_a_failed_checkpoint_removes_the_files_it_wrote(tmp_path):
    """A checkpoint that wrote files and THEN failed leaves nothing that can discard them.

    /snapshot/create can write either file and then report an error — a lost response after
    Firecracker already committed is the obvious way. No artifact is returned, so SnapshotManager
    never learns those paths exist. Because every retry now picks a unique generation name,
    repeated build failures accumulate full RAM-sized .mem files instead of overwriting the
    previous attempt, until /dev/shm or the disk is exhausted.
    """
    from blastbox.host.runtime import fc_snapshot_launcher as launcher

    dest = tmp_path / "dest"
    mem_dir = tmp_path / "mem"
    dest.mkdir()
    mem_dir.mkdir()

    def _create_then_fail(api, snap, mem):
        Path(snap).write_bytes(b"partial")
        Path(mem).write_bytes(b"m" * 4096)     # a RAM-sized file, in miniature
        raise RuntimeError("snapshot create reported an error after committing")

    handle = launcher._Handle(None, object(), "vsock.sock", mem_dir=mem_dir)  # type: ignore[arg-type]

    for _ in range(3):                          # repeated build retries
        with pytest.raises(Exception):
            with _patched(launcher, "_create_snapshot", _create_then_fail):
                handle.checkpoint(dest)

    leftovers = list(dest.glob("warm-*")) + list(mem_dir.glob("warm-*"))
    assert leftovers == [], f"failed checkpoints leaked their files: {leftovers}"


import contextlib as _contextlib


@_contextlib.contextmanager
def _patched(mod, name, value):
    """Patch a name that the code under test imports lazily inside the function."""
    import blastbox.host.runtime.fc_snapshot_backend as backend
    old = getattr(backend, name)
    setattr(backend, name, value)
    try:
        yield
    finally:
        setattr(backend, name, old)


def test_spawn_cleanup_retains_the_pin_when_it_cannot_kill_the_vm(tmp_path):
    """The spawn-cleanup path owes the same guarantee as reap().

    When post-restore slot construction fails AND handle.kill() also raises, the microVM may
    still be alive and mapping this generation. Releasing the pin anyway lets a later
    invalidation unlink its backing files underneath. This cleanup path was added in the same
    commit that guarded reap(), and reproduced the exact bug that commit fixed.
    """
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    mgr, be = _mgr(tmp_path)

    class _UnkillableAndUnusable:
        @property
        def vsock_uds(self):
            raise OSError("ENOSPC reading the restored handle")

        def kill(self):
            raise RuntimeError("SIGKILL failed; the microVM may still be running")

    be.restore_in = lambda w, a: _UnkillableAndUnusable()  # type: ignore[assignment]

    class _Cfg:
        max_extracted_bytes = 1 << 20

    rt = SnapshotSlotRuntime(_Cfg(), mgr, settle_s=0.0)
    mgr.build()   # spawn() no longer builds INLINE -- that is what stalled the tick thread
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    with pytest.raises(Exception):
        rt.spawn()

    mgr.invalidate()
    assert gen1.exists(), (
        "the generation was reclaimed while its microVM could not be confirmed dead"
    )


def test_a_generation_whose_discard_fails_stays_retryable(tmp_path):
    """A single failed unlink must not lose a generation forever.

    release() popped the artifact from _retired BEFORE attempting cleanup, and _discard swallowed
    errors — so one transient EBUSY/EACCES meant no later release or invalidation could ever
    rediscover it, and repeated rebuilds accumulated RAM-sized files again. That is precisely the
    leak this whole mechanism exists to stop.
    """
    mgr, be = _mgr(tmp_path)
    mgr.build()
    mgr.restore("slot-a")
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    mgr.invalidate()
    mgr.build()

    broken = {"on": True}
    real_discard = be.discard

    def _flaky_discard(artifact):
        if broken["on"]:
            raise OSError("EBUSY unlinking the memory file")
        real_discard(artifact)

    be.discard = _flaky_discard  # type: ignore[assignment]

    mgr.release("slot-a")                    # cleanup fails, and the immediate retry fails too
    assert gen1.exists(), "sanity: the failed unlink left the file in place"

    # The generation must still be RETRYABLE once the underlying problem clears — the point is
    # that it was not silently forgotten by the first failure.
    broken["on"] = False
    mgr.restore("slot-b")
    mgr.release("slot-b")
    assert not gen1.exists(), (
        "a generation whose discard failed was never retried — it is leaked forever"
    )


def test_the_base_outdisk_is_versioned_with_its_generation(tmp_path):
    """Stamping two of three artifacts still corrupts.

    The guest's ext4 metadata (superblock, journal, dir checksums) lives in the captured guest
    RAM, so the disk and the memory snapshot are ONE unit. restore_in() copied a fixed
    base/outdisk.ext4 that boot_base() recreates on every build — so an in-flight restore could
    pair generation N's memory with generation N+1's disk, producing exactly the
    "EXT4-fs error: Directory block failed checksum" corruption the versioning exists to prevent.
    """
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact

    art = FcSnapshotArtifact(tmp_path / "s.snapshot", tmp_path / "m.mem",
                             tmp_path / "warm-gen1.outdisk.ext4")
    assert art.outdisk_path is not None, "the artifact must carry its own disk"

    # ...and discard() must remove all three, or the versioning just leaks a third file.
    for p in (art.snapshot_path, art.mem_path, art.outdisk_path):
        p.write_bytes(b"x")

    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotBackend
    FcSnapshotBackend.discard(object(), art)   # type: ignore[arg-type]

    assert not any(p.exists() for p in (art.snapshot_path, art.mem_path, art.outdisk_path)), (
        "every file of a drained generation must be reclaimed, including the disk"
    )


def test_the_restore_rollback_path_also_keeps_failed_discards_retryable(tmp_path):
    """release() and _unpin() must obey the same rule.

    When a restore raises after its generation was retired mid-flight, the rollback drops the last
    reference and tries to clean up. That path was added alongside the retryable release and did
    not inherit it, so a transient unlink failure there forgot the generation permanently.
    """
    mgr, be = _mgr(tmp_path)
    mgr.build()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    broken = {"on": True}
    real_discard = be.discard

    def _flaky_discard(artifact):
        if broken["on"]:
            raise OSError("EBUSY unlinking the memory file")
        real_discard(artifact)

    be.discard = _flaky_discard  # type: ignore[assignment]

    def _retire_then_fail(slot_workdir, artifact):
        mgr.invalidate()          # retire the generation we are holding
        mgr.build()
        raise RuntimeError("restore failed after the generation was retired")

    be.restore_in = _retire_then_fail  # type: ignore[assignment]

    with pytest.raises(Exception):
        mgr.restore("slot-a")
    assert gen1.exists(), "sanity: the failed unlink left the file in place"

    # It must still be RETRYABLE, not forgotten.
    broken["on"] = False
    be.restore_in = lambda w, a: object()  # type: ignore[assignment]
    mgr.restore("slot-b")
    mgr.release("slot-b")
    assert not gen1.exists(), (
        "a rollback whose discard failed forgot the generation — it is leaked forever"
    )


def test_a_build_invalidated_while_running_does_not_publish(tmp_path):
    """A repair request must not be silently lost to a slow build.

    invalidate() arriving while the (async) build is in flight found _artifact None, recorded
    nothing, and the build then published the very artifact the repair meant to reject — so
    old-generation slots kept failing against a base that had already been condemned.
    """
    from blastbox.host.runtime.fc_snapshot import SnapshotBuildInvalidated

    mgr, be = _mgr(tmp_path)

    class _BootThatGetsInvalidated(_FakeBoot):
        def wait_ready(self, timeout_s: float) -> None:
            mgr.invalidate()      # the repair lands mid-build

    be.boot_base = lambda: _BootThatGetsInvalidated(be)  # type: ignore[assignment]

    with pytest.raises(SnapshotBuildInvalidated):
        mgr.build()

    assert mgr.artifact is None, "a rejected build must not become the active artifact"
    assert _gens(tmp_path) == set(), (
        f"the discarded build left its files behind: {_gens(tmp_path)}"
    )


def test_an_interrupted_build_still_tears_down_its_base(tmp_path):
    """BaseException must not escape without teardown.

    Replacing the original `finally: boot.kill()` with typed handlers let a KeyboardInterrupt or
    cancellation during wait_ready()/checkpoint() leave a Firecracker VM or gVisor base container
    running — interrupting the dispatcher mid-build leaked one every time.
    """
    mgr, be = _mgr(tmp_path)
    killed: list[bool] = []

    class _BootInterrupted(_FakeBoot):
        def wait_ready(self, timeout_s: float) -> None:
            raise KeyboardInterrupt("operator interrupted the dispatcher")

        def kill(self):
            killed.append(True)

    be.boot_base = lambda: _BootInterrupted(be)  # type: ignore[assignment]

    with pytest.raises(KeyboardInterrupt):
        mgr.build()
    assert killed, "an interrupted build must still tear its base down"


def test_an_invalidate_racing_publication_still_rejects_the_build(tmp_path):
    """Comparing the epoch and publishing must be ONE locked step.

    invalidate() landing between the comparison and the assignment bumps the epoch, sees
    _artifact is None (so it retires nothing), and the build then publishes the very artifact
    that repair rejected — the request is lost silently and restores keep reproducing the wedge.
    """
    import threading

    from blastbox.host.runtime.fc_snapshot import SnapshotError

    mgr, be = _mgr(tmp_path)

    entered = threading.Event()
    invalidated = threading.Event()
    real_lock = mgr._build_lock

    class _GatedLock:
        """Stall the FIRST acquisition taken after the build produces its artifact, so an
        invalidate can land in the compare/publish window if one exists."""

        def __init__(self) -> None:
            self._armed = False

        def arm(self) -> None:
            self._armed = True

        def __enter__(self):
            return real_lock.__enter__()

        def __exit__(self, *a):
            r = real_lock.__exit__(*a)
            # Fire on EXIT, not entry: the window is between the epoch COMPARISON and the
            # publication. Gating entry only lets the racer land before the comparison, which
            # even the broken version rejects correctly — the test would prove nothing.
            if self._armed:
                self._armed = False
                entered.set()
                invalidated.wait(5.0)
            return r

    gate = _GatedLock()

    class _BootThatArms(_FakeBoot):
        def checkpoint(self, dest_dir):
            art = super().checkpoint(dest_dir)
            gate.arm()            # the next lock taken is the compare/publish one
            return art

    be.boot_base = lambda: _BootThatArms(be)  # type: ignore[assignment]
    mgr._build_lock = gate  # type: ignore[assignment]

    def _racer():
        entered.wait(5.0)
        mgr._build_lock = real_lock      # invalidate must not deadlock on the gate
        mgr.invalidate()
        mgr._build_lock = gate
        invalidated.set()

    th = threading.Thread(target=_racer, daemon=True)
    th.start()
    with contextlib.suppress(SnapshotError):
        mgr.build()
    th.join(10.0)

    assert invalidated.is_set(), "the racing invalidate never ran — the test proved nothing"
    # TWO orderings are correct, and the invariant spans both: either the build loses and is
    # discarded, or it publishes and the (serialized) invalidate then retires what it published.
    # Asserting one specific outcome would encode a scheduling accident rather than the rule.
    # What must NEVER happen is the third case — the compare says "keep", the invalidate finds
    # nothing to retire, and the publish then installs the artifact that repair rejected.
    assert mgr.artifact is None, (
        "the repair was lost: an artifact rejected mid-build ended up installed as the active one"
    )


def test_an_invalidated_build_retries_at_once(tmp_path):
    """A repair requested mid-build must not leave the tier cold for the failure backoff.

    The rejection raises through the same path as a genuine build failure, so _build_worker armed
    the normal retry gate — the snapshot tier stayed unavailable for build_retry_backoff_s after a
    repair the pool had just asked for. Nothing failed; the replacement build should start at once.
    """
    mgr, be = _mgr(tmp_path)

    class _BootThatGetsInvalidated(_FakeBoot):
        def wait_ready(self, timeout_s: float) -> None:
            mgr.invalidate()

    be.boot_base = lambda: _BootThatGetsInvalidated(be)  # type: ignore[assignment]

    mgr._build_worker()          # the worker swallows the rejection

    assert mgr._retry_not_before == 0.0, (
        f"a deliberate rejection armed the failure backoff (retry gate={mgr._retry_not_before})"
    )
    assert mgr.build_error is None, "an intentional rejection is not a build error"


def test_the_backend_reports_unlink_failures_so_they_stay_retryable(tmp_path):
    """The one place that decides whether cleanup happened must not lie.

    _discard treats a normal return as CONFIRMED, dropping the artifact from _retired — so a
    backend that logged a transient EIO/EROFS and returned normally defeated the whole retryable
    machinery built over the last several rounds.
    """
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    snap = tmp_path / "warm-x.snapshot"
    mem = tmp_path / "warm-x.mem"
    snap.write_bytes(b"s")
    mem.write_bytes(b"m")
    art = FcSnapshotArtifact(snap, mem, None)

    real_unlink = pathlib.Path.unlink

    def _boom(self, *a, **kw):
        if self.name.startswith("warm-x"):
            raise OSError(5, "Input/output error")
        return real_unlink(self, *a, **kw)

    mp = pytest.MonkeyPatch()
    mp.setattr(pathlib.Path, "unlink", _boom)
    try:
        with pytest.raises(OSError):
            FcSnapshotBackend.discard(object(), art)   # type: ignore[arg-type]
    finally:
        mp.undo()


def test_a_rejected_build_whose_cleanup_fails_is_retained(tmp_path):
    """Never published, never retired — so a failed cleanup here leaks forever.

    The rejected-build path is the one discard site that had no retention, because its artifact
    was never in _retired to begin with.
    """
    mgr, be = _mgr(tmp_path)

    class _BootThatGetsInvalidated(_FakeBoot):
        def wait_ready(self, timeout_s: float) -> None:
            mgr.invalidate()

    broken = {"on": True}
    real_discard = be.discard

    def _flaky(artifact):
        if broken["on"]:
            raise OSError("EBUSY unlinking the rejected generation")
        real_discard(artifact)

    be.boot_base = lambda: _BootThatGetsInvalidated(be)  # type: ignore[assignment]
    be.discard = _flaky  # type: ignore[assignment]

    with pytest.raises(Exception):
        mgr.build()
    assert _gens(tmp_path), "sanity: the failed cleanup left the generation on disk"

    # It must still be RETRYABLE rather than forgotten.
    broken["on"] = False
    mgr._sweep_retired()
    assert _gens(tmp_path) == set(), (
        f"a rejected build whose cleanup failed was never retried: {_gens(tmp_path)}"
    )


def test_a_restore_whose_cleanup_cannot_kill_firecracker_keeps_its_pin(tmp_path):
    """An unconfirmed teardown must retain the generation.

    When /snapshot/load fails and the subsequent kill ALSO fails, that firecracker may still be
    alive with the memory file mapped. Unpinning regardless let a later invalidation unlink the
    generation underneath it — defeating the mapping-safety guarantee the pin exists for. Same
    rule as reap() and the spawn-cleanup path.
    """
    from blastbox.host.runtime.fc_snapshot import SnapshotRestoreError

    mgr, be = _mgr(tmp_path)
    mgr.build()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    def _restore_fails_and_kill_fails(slot_workdir, artifact):
        exc = SnapshotRestoreError("load failed")
        exc.kill_failed = True        # the backend could not confirm the process is gone
        raise exc

    be.restore_in = _restore_fails_and_kill_fails  # type: ignore[assignment]

    with pytest.raises(SnapshotRestoreError):
        mgr.restore("slot-a")

    mgr.invalidate()
    assert gen1.exists(), (
        "the generation was reclaimed while a firecracker process may still map its memory file"
    )


def test_a_cancelled_restore_keeps_its_pin_when_teardown_is_unconfirmed(tmp_path):
    """The sibling handler in the SAME function.

    A KeyboardInterrupt/SystemExit landing after the spawn skipped the backend's cleanup (it
    caught only Exception), leaving an unmanaged firecracker with the memory file mapped — and
    the manager unpinned regardless, so a later invalidation could unlink it underneath. Guarding
    one handler and not its sibling is how this class of bug keeps recurring.
    """
    mgr, be = _mgr(tmp_path)
    mgr.build()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    def _cancelled_with_live_process(slot_workdir, artifact):
        exc = KeyboardInterrupt("operator interrupted mid-restore")
        exc.kill_failed = True        # the process could not be confirmed gone
        raise exc

    be.restore_in = _cancelled_with_live_process  # type: ignore[assignment]

    with pytest.raises(KeyboardInterrupt):
        mgr.restore("slot-a")

    mgr.invalidate()
    assert gen1.exists(), (
        "a cancelled restore released its pin while a firecracker may still map the memory file"
    )
