"""The FC tier's host disk helpers run on the per-slot spawn path and must be bounded.

`subprocess.run` has no default timeout. `mkfs.ext4` (per-slot output disk) and the
`cp --reflink=auto` of the base outdisk both ran unbounded, so a stalled filesystem -- a wedged
overlay/NFS mount, a device error -- blocked the spawning thread with nothing to time it out.

The pool survives that, but not for free: `stop()` reports "background thread still running
(wedged spawn?)", and the in-flight spawn stays uncommitted while still counting against node
RAM/vCPU budget that no live worker is using. The sibling helpers in this module (debugfs
rdump, e2fsck) were already bounded; these two were not.

These tests EXECUTE a hanging stand-in rather than asserting a kwarg: a runner that accepted
`timeout=` and dropped it would satisfy any kwarg assertion (that exact mutation survived the
kwarg-only tests on the gVisor side).
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
from pathlib import Path

import pytest


# Long enough that a BOUNDED call (1 s) must time out, short enough that an UNBOUNDED one
# still returns -- so removing the bound makes these tests FAIL on "DID NOT RAISE" in ~20 s
# instead of hanging. A test that hangs instead of failing is its own defect.
_STALL_S = 20


def _hanging(tmp_path: Path, name: str) -> Path:
    """A stand-in binary that stalls, with `exec` so the kill lands on the sleep itself."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(f"#!/bin/sh\nexec sleep {_STALL_S}\n")
    p.chmod(0o755)
    return d


def test_make_ext4_is_bounded(tmp_path, monkeypatch):
    from blastbox.host.runtime.firecracker import make_ext4

    bin_dir = _hanging(tmp_path, "mkfs.ext4")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        make_ext4(tmp_path / "out.ext4", 8)
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"make_ext4 ran unbounded: it took {elapsed:.0f}s"


def test_the_outdisk_copy_is_bounded(tmp_path, monkeypatch):
    from blastbox.host.runtime.fc_snapshot_launcher import _default_copy_outdisk

    bin_dir = _hanging(tmp_path, "cp")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")
    src = tmp_path / "base.ext4"
    src.write_bytes(b"x" * 1024)

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _default_copy_outdisk(src, tmp_path / "slot.ext4")
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"the outdisk copy ran unbounded: it took {elapsed:.0f}s"


def test_a_timed_out_copy_does_not_fall_back_to_a_python_copy(tmp_path, monkeypatch):
    """The fallback is for "no cp, odd platform". A cp that TIMED OUT means the filesystem is
    stalled, and copying the same bytes again in Python stalls the same way -- spending the
    budget twice and turning a bounded failure back into a hang."""
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    bin_dir = _hanging(tmp_path, "cp")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")
    src = tmp_path / "base.ext4"
    src.write_bytes(b"x" * 1024)

    fell_back: list[bool] = []
    monkeypatch.setattr(fl.shutil, "copyfile",
                        lambda a, b: fell_back.append(True))

    with pytest.raises(subprocess.TimeoutExpired):
        fl._default_copy_outdisk(src, tmp_path / "slot.ext4")

    assert not fell_back, "a timed-out copy fell through to the Python fallback"


def test_a_missing_cp_still_falls_back(tmp_path, monkeypatch):
    """The control: the fallback this bound must not break."""
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))       # no `cp` anywhere
    src = tmp_path / "base.ext4"
    src.write_bytes(b"payload")
    dst = tmp_path / "slot.ext4"

    fl._default_copy_outdisk(src, dst)

    assert dst.read_bytes() == b"payload", "the no-cp fallback stopped working"


@pytest.fixture
def stalled_source(tmp_path):
    """A source whose `read()` blocks forever: a fifo held open by a writer that never writes.

    Deterministic, unlike "a tiny timeout against a small file" -- with the copy now running in
    a joined worker, an 8 MiB copy can beat a 0.0 s deadline and the test flakes on DID NOT
    RAISE. A stall cannot be won by being fast.
    """
    import threading as _th

    fifo = tmp_path / "stalled.src"
    os.mkfifo(fifo)
    release = _th.Event()

    def _hold() -> None:
        with open(fifo, "wb"):
            release.wait(30)

    _th.Thread(target=_hold, daemon=True).start()
    yield fifo
    release.set()


class TestWhatTheBoundsChanged:
    """Follow-ups from review: introducing a timeout changes failure ATTRIBUTION and cleanup."""

    def test_a_disk_timeout_is_a_host_failure_not_a_tier_failure(self):
        """`is_host_resource_failure` only knew OSError errnos, and a timeout is not one -- so
        repeated filesystem stalls would walk the pool's restore streak and the cascade's
        per-tier streak until a HEALTHY snapshot base was invalidated: the disk's fault,
        charged to the tier."""
        from blastbox.errors import HostDiskTimeout, is_host_resource_failure

        assert is_host_resource_failure(HostDiskTimeout(cmd="mkfs.ext4", timeout=1))

        # Through the cause chain, which is how it actually arrives (a launcher wraps it).
        try:
            try:
                raise HostDiskTimeout(cmd="cp", timeout=1)
            except HostDiskTimeout as inner:
                raise RuntimeError("snapshot restore failed") from inner
        except RuntimeError as outer:
            assert is_host_resource_failure(outer), "the wrapped timeout was blamed on the tier"

        assert not is_host_resource_failure(RuntimeError("an ordinary tier failure"))

    def test_a_runtime_timeout_is_still_the_tier_failing(self):
        """The narrowing that matters. Excusing EVERY subprocess.TimeoutExpired was wrong: the
        gVisor tier bounds `runsc restore` with its own cli_timeout_s, and a wedged or
        incompatible RUNTIME timing out there is exactly what the streaks exist to detect.
        Excusing it would leave a broken tier unrepaired forever."""
        from blastbox.errors import is_host_resource_failure

        runsc_timeout = subprocess.TimeoutExpired(cmd="runsc restore", timeout=600)
        assert not is_host_resource_failure(runsc_timeout), (
            "a wedged runtime was excused as a stalled disk; the tier would never be repaired"
        )
        try:
            try:
                raise runsc_timeout
            except subprocess.TimeoutExpired as inner:
                raise RuntimeError("gvisor restore failed") from inner
        except RuntimeError as outer:
            assert not is_host_resource_failure(outer)

    def test_the_python_fallback_is_bounded_too(self, tmp_path, stalled_source):
        """`cp` missing or without --reflink (a BusyBox image) lands in the fallback
        immediately -- and an unbounded copy there means the documented bound does not hold on
        the very path the fallback exists for."""
        from blastbox.errors import HostDiskTimeout
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        dst = tmp_path / "slot.ext4"

        started = time.monotonic()
        with pytest.raises(HostDiskTimeout):
            fl._copy_with_deadline(stalled_source, dst, 1.0)
        elapsed = time.monotonic() - started

        assert elapsed < 20, f"the bounded copy took {elapsed:.0f}s"
        assert not dst.exists(), (
            "a truncated outdisk was left behind; the guest would mount it"
        )

    def test_the_bounded_copy_still_copies(self, tmp_path):
        """The control: the bound must not break the copy it guards."""
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        src = tmp_path / "base.ext4"
        src.write_bytes(b"payload" * 1000)
        dst = tmp_path / "slot.ext4"

        fl._copy_with_deadline(src, dst, 60.0)

        assert dst.read_bytes() == src.read_bytes()

    def test_a_spawn_that_cannot_format_its_disk_removes_its_scratch_dir(
        self, tmp_path, monkeypatch
    ):
        """The exception escapes before a Slot exists, so the pool has nothing to hand
        reap(): every retry would leave another directory and partial image behind."""
        from blastbox.host.runtime import firecracker as fc

        scratch = tmp_path / "scratch"
        scratch.mkdir()

        class _Cfg:
            fc_outdisk_mib = 8

        rt = object.__new__(fc.FirecrackerSlotRuntime)
        rt._scratch_root = scratch          # type: ignore[attr-defined]
        rt._cfg = _Cfg()                    # type: ignore[attr-defined]

        monkeypatch.setattr(
            fc, "make_ext4",
            lambda p, m: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd="mkfs", timeout=1)),
        )

        for _ in range(5):
            with pytest.raises(subprocess.TimeoutExpired):
                fc.FirecrackerSlotRuntime.spawn(rt)

        leftovers = list(scratch.iterdir())
        assert not leftovers, f"5 failed spawns left scratch dirs behind: {leftovers}"

    def test_a_restore_whose_terminate_is_unconfirmed_retains_the_orphan(
        self, tmp_path, monkeypatch
    ):
        """`_terminate_proc` returning False means the process survived terminate AND kill.

        Ignoring that -- which restore_in did -- let SnapshotManager.restore() remove the
        workdir and forget the spawn, leaving a microVM neither the pool nor shutdown can
        account for, still holding that workdir's disk and sockets. Especially likely in the
        filesystem-stall case the copy timeout exists for, since firecracker is blocked on the
        same disk. boot_base already followed this rule; restore_in did not.
        """
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        base_dir = tmp_path / "base_dir"
        (base_dir / "base").mkdir(parents=True)
        base_outdisk = base_dir / "base" / fl.REL_OUTDISK
        base_outdisk.parent.mkdir(parents=True, exist_ok=True)
        base_outdisk.write_bytes(b"base image")

        launcher = object.__new__(fl.FcSnapshotLauncher)
        launcher._base_dir = base_dir                       # type: ignore[attr-defined]
        launcher._stranded_partials = []                    # type: ignore[attr-defined]
        launcher._spawn = lambda wd: (object(), object())   # type: ignore[attr-defined]
        launcher._copy_outdisk = (                          # type: ignore[attr-defined]
            lambda s, d: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="cp", timeout=1)
            )
        )
        monkeypatch.setattr(fl, "_terminate_proc", lambda p: False)   # survived both

        slot_wd = tmp_path / "slot"
        slot_wd.mkdir()
        with pytest.raises(subprocess.TimeoutExpired):
            fl.FcSnapshotLauncher.restore_in(launcher, slot_wd)

        assert str(slot_wd) in launcher._stranded_partials, (
            "an unconfirmed firecracker was forgotten; nothing can account for or reap it"
        )

    def test_the_no_cp_fallback_path_is_bounded_end_to_end(
        self, tmp_path, monkeypatch, stalled_source
    ):
        """Through `_default_copy_outdisk`, not the helper directly.

        Testing `_copy_with_deadline` alone leaves the WIRING unverified: reverting the
        fallback to a bare `shutil.copyfile` passed that test, because it never went through
        the fallback at all.
        """
        from blastbox.errors import HostDiskTimeout
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        empty = tmp_path / "emptybin"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))              # no `cp`: straight to the fallback
        monkeypatch.setenv("BLASTBOX_FC_DISK_TIMEOUT_S", "1")
        dst = tmp_path / "slot.ext4"

        with pytest.raises(HostDiskTimeout):
            fl._default_copy_outdisk(stalled_source, dst)

        assert not dst.exists(), "a truncated outdisk survived the bounded fallback"

    def test_a_scratch_dir_whose_cleanup_fails_is_retried_on_the_next_spawn(
        self, tmp_path, monkeypatch
    ):
        """The storage incident that makes mkfs time out also breaks the rmtree that follows.

        `ignore_errors=True` alone would drop the only reference to that partial dir, and the
        plain FC tier has no orphan sweep -- so every retry would leave another behind.
        """
        from blastbox.host.runtime import firecracker as fc

        scratch = tmp_path / "scratch"
        scratch.mkdir()

        class _Cfg:
            fc_outdisk_mib = 8

        rt = object.__new__(fc.FirecrackerSlotRuntime)
        rt._scratch_root = scratch          # type: ignore[attr-defined]
        rt._cfg = _Cfg()                    # type: ignore[attr-defined]

        monkeypatch.setattr(
            fc, "make_ext4",
            lambda p, m: (_ for _ in ()).throw(fc.HostDiskTimeout(cmd="mkfs", timeout=1)),
        )
        # The removal fails too, exactly as it would on the stalled filesystem.
        real_rmtree = fc.shutil.rmtree
        broken = {"on": True}

        def _rmtree(path, onerror=None, **kw):
            if broken["on"]:
                if onerror:
                    onerror(os.rmdir, str(path), (OSError, OSError(5, "EIO"), None))
                return
            return real_rmtree(path, **kw)

        monkeypatch.setattr(fc.shutil, "rmtree", _rmtree)

        with pytest.raises(fc.HostDiskTimeout):
            fc.FirecrackerSlotRuntime.spawn(rt)

        assert rt._stranded_scratch, "the partial slot dir was forgotten; nothing can reclaim it"
        stuck = list(rt._stranded_scratch)

        # The disk recovers; the next spawn must clear what the last one could not.
        broken["on"] = False
        with pytest.raises(fc.HostDiskTimeout):
            fc.FirecrackerSlotRuntime.spawn(rt)

        assert not any(Path(p).exists() for p in stuck), (
            f"the retained dirs were never reclaimed: {stuck}"
        )

    def test_abandoned_copy_workers_are_capped(self, tmp_path, stalled_source, monkeypatch):
        """A stalled mount must not cost a thread and two descriptors per retry, forever.

        Host-resource failures are deliberately exempt from the pool's failure streaks, so the
        pool keeps retrying -- which is exactly when unbounded accumulation would bite.
        """
        from blastbox.errors import HostDiskTimeout
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        monkeypatch.setattr(fl, "_ABANDONED_COPIES", [])
        monkeypatch.setattr(fl, "_MAX_ABANDONED_COPIES", 3)

        for _ in range(10):
            with pytest.raises(HostDiskTimeout):
                fl._copy_with_deadline(stalled_source, tmp_path / "d.ext4", 0.2)

        alive = [t for t in fl._ABANDONED_COPIES if t.is_alive()]
        assert len(alive) <= 3, f"{len(alive)} stuck copy workers accumulated past the cap"

    def test_the_cap_says_why_it_refused(self, tmp_path, stalled_source, monkeypatch):
        """A refusal that reads like an ordinary timeout would send an operator hunting the
        wrong thing: the disk stalled earlier and never recovered."""
        from blastbox.errors import HostDiskTimeout
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        monkeypatch.setattr(fl, "_ABANDONED_COPIES", [])
        monkeypatch.setattr(fl, "_MAX_ABANDONED_COPIES", 1)

        with pytest.raises(HostDiskTimeout):
            fl._copy_with_deadline(stalled_source, tmp_path / "a.ext4", 0.2)
        with pytest.raises(HostDiskTimeout) as caught:
            fl._copy_with_deadline(stalled_source, tmp_path / "b.ext4", 0.2)

        assert "still stuck on this host" in str(caught.value.cmd)

    @pytest.mark.parametrize("confirmed", [False, True])
    def test_the_workdir_survives_exactly_when_teardown_is_unconfirmed(self, tmp_path, confirmed):
        """Retaining the generation pin but deleting the directory is HALF a rule.

        When firecracker survives terminate AND kill it may still hold this slot's disk and
        sockets open, so removing the workdir pulls them out from under a live microVM. Both
        handlers removed it unconditionally -- including the branch that had just decided the
        process could not be confirmed gone.

        Drives the REAL `SnapshotManager.restore()`. My first version of this test asserted
        only the classifier helper, and the mutation that removes the guard survived it -- it
        proved nothing.
        """

        from blastbox.host.runtime.fc_snapshot import SnapshotManager

        class _Boom(Exception):
            pass

        exc = _Boom("restore failed")
        if not confirmed:
            exc.kill_failed = True              # type: ignore[attr-defined]

        class _Backend:
            def restore_in(self, workdir, artifact):
                workdir.mkdir(parents=True, exist_ok=True)
                (workdir / "outdisk.ext4").write_bytes(b"a live VM may have this open")
                raise exc

        mgr = SnapshotManager(tmp_path / "snap", _Backend())
        mgr._artifact = object()                # type: ignore[attr-defined]

        with pytest.raises(Exception):
            mgr.restore("slot-a")

        workdir = (tmp_path / "snap") / "slots" / "slot-a"
        if confirmed:
            assert not workdir.exists(), (
                "a CONFIRMED teardown must still clean up; the guard must not leak every workdir"
            )
        else:
            assert workdir.exists(), (
                "the workdir was removed although firecracker could not be confirmed gone -- "
                "pulling the disk and sockets out from under a live microVM"
            )

    def test_the_cap_holds_under_concurrency(self, tmp_path, stalled_source, monkeypatch):
        """Check-then-act does not bound anything in the concurrency the cap exists for.

        With BLASTBOX_POOL_SPAWN_CONCURRENCY above the cap, every concurrent copy could observe
        zero stuck workers and start anyway. All threads are released from a barrier here so
        they contend on that window deliberately (codex, #154).
        """
        import threading as _th

        from blastbox.errors import HostDiskTimeout
        from blastbox.host.runtime import fc_snapshot_launcher as fl

        monkeypatch.setattr(fl, "_ABANDONED_COPIES", [])
        monkeypatch.setattr(fl, "_MAX_ABANDONED_COPIES", 2)

        n = 16
        start = _th.Barrier(n)

        def _attempt(i: int) -> None:
            start.wait(10)
            with contextlib.suppress(HostDiskTimeout):
                fl._copy_with_deadline(stalled_source, tmp_path / f"d{i}.ext4", 0.2)

        threads = [_th.Thread(target=_attempt, args=(i,), daemon=True) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        alive = [t for t in fl._ABANDONED_COPIES if t.is_alive()]
        assert len(alive) <= 2, (
            f"{len(alive)} copy workers started against a cap of 2: the check was not atomic"
        )
