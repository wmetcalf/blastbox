"""Superseded snapshot generations must be reclaimed — but never while still mapped.

Generation-stamped artifact names fixed a real corruption (rewriting a memory file under live
microVMs), but nothing ever deleted the superseded pair. Each rebuild leaves a .mem roughly the
size of guest RAM — often on /dev/shm — so repeated rebuild episodes exhaust the tmpfs and every
later build fails on ENOSPC. The constraint that makes this non-trivial: a restored microVM keeps
the memory file mapped as its backing store for its whole life, so the pair can only be unlinked
once its LAST user is reaped.
"""
from __future__ import annotations

import time

import pytest

from pathlib import Path

from blastbox.host.runtime.fc_snapshot import SnapshotManager
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

    slot = rt.spawn()
    gen1 = tmp_path / "snap" / "warm-gen1.mem"
    assert gen1.exists()

    mgr.invalidate()      # supersede it while the slot is live
    mgr.build()
    rt.reap(slot)         # kill() raises -> the VM is NOT provably gone

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
    gen1 = tmp_path / "snap" / "warm-gen1.mem"

    with pytest.raises(Exception):
        rt.spawn()

    mgr.invalidate()
    assert gen1.exists(), (
        "the generation was reclaimed while its microVM could not be confirmed dead"
    )
