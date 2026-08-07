"""Superseded snapshot generations must be reclaimed — but never while still mapped.

Generation-stamped artifact names fixed a real corruption (rewriting a memory file under live
microVMs), but nothing ever deleted the superseded pair. Each rebuild leaves a .mem roughly the
size of guest RAM — often on /dev/shm — so repeated rebuild episodes exhaust the tmpfs and every
later build fails on ENOSPC. The constraint that makes this non-trivial: a restored microVM keeps
the memory file mapped as its backing store for its whole life, so the pair can only be unlinked
once its LAST user is reaped.
"""
from __future__ import annotations

import pytest

from dataclasses import dataclass
from pathlib import Path

from blastbox.host.runtime.fc_snapshot import SnapshotManager


@dataclass
class _Artifact:
    snapshot: Path
    mem: Path


class _FakeBoot:
    def __init__(self, backend: "_FakeBackend") -> None:
        self._be = backend

    def wait_ready(self, timeout_s: float) -> None:
        return None

    def checkpoint(self, dest_dir: Path) -> _Artifact:
        """Write a generation-stamped pair, like the real FC backend."""
        self._be.n += 1
        snap = self._be.root / f"warm-gen{self._be.n}.snapshot"
        mem = self._be.root / f"warm-gen{self._be.n}.mem"
        snap.write_bytes(b"snap")
        mem.write_bytes(b"m" * 1024)
        return _Artifact(snap, mem)

    def kill(self) -> None:
        return None


class _FakeBackend:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.n = 0
        self.discarded: list[_Artifact] = []

    def available(self) -> bool:
        return True

    def boot_base(self) -> _FakeBoot:
        return _FakeBoot(self)

    def restore_in(self, slot_workdir: Path, artifact: object) -> object:
        return object()

    def discard(self, artifact: object) -> None:
        self.discarded.append(artifact)   # type: ignore[arg-type]
        Path(artifact.snapshot).unlink(missing_ok=True)  # type: ignore[attr-defined]
        Path(artifact.mem).unlink(missing_ok=True)       # type: ignore[attr-defined]


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
