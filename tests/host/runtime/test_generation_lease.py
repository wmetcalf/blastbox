"""Ownership of an on-disk generation must be provable ACROSS PID namespaces.

Two dispatcher containers share the snapshot directory through a rolling deployment. The old
container's pid is not observable from the new container's /proc, and both commonly see
themselves as pid 1 with different start times — so the pid/start-time rule declared the
still-running old owner DEAD and the startup sweep unlinked the .mem / checkpoint its live
microVMs were still mapping. That SIGBUSes them or silently corrupts guest memory.

A flock on a file in the shared directory is the one signal that crosses namespaces: the kernel
holds it while the owner lives and drops it the moment the owner dies, referring to no pid at all.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import textwrap

from blastbox.host.runtime.snapshot_backend import (
    hold_owner_lease,
    owner_alive,
    owner_lease_path,
    owner_token,
)


def test_a_live_owner_is_never_declared_dead_just_because_its_pid_is_invisible(
    tmp_path,
):
    """The P1 in one assertion.

    Simulate the rolling deployment exactly: a token whose pid IS live in our namespace but is a
    DIFFERENT process (which is what pid 1 looks like from a replacement container), holding its
    lease. The pid rule says dead; ownership must say alive.
    """
    token = f"{os.getpid()}_999999"  # our pid, a different start time
    lease = owner_lease_path(tmp_path, token)
    lease.write_bytes(b"")
    holder = open(lease, "a+b")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        from blastbox.host.runtime.snapshot_backend import _alive_in_this_namespace

        assert _alive_in_this_namespace(token) is False, (
            "sanity: this is exactly the shape the pid rule gets wrong"
        )
        assert owner_alive(token, lease_dir=tmp_path) is True, (
            "a live owner was declared dead; the sweep would unlink the memory file its microVMs "
            "are still mapping"
        )
    finally:
        holder.close()


def test_a_released_lease_proves_the_owner_is_gone(tmp_path):
    """The other direction: reclamation must still WORK, or the leak this exists to fix returns."""
    token = "999999999_4242"
    owner_lease_path(tmp_path, token).write_bytes(b"")  # written, nobody holds it
    assert owner_alive(token, lease_dir=tmp_path) is False


def test_the_kernel_releases_the_lease_when_the_holder_dies(tmp_path):
    """Not a mocked release — a real process exits and the lease becomes acquirable."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )
        + "/src"!r
    })
        from blastbox.host.runtime.snapshot_backend import hold_owner_lease, owner_token
        assert hold_owner_lease({str(tmp_path)!r})
        print(owner_token())
    """)
    token = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    ).stdout.strip()
    assert token, "the child never reported its token"
    # The child has exited. Its lease file is still there; the LOCK is not.
    assert owner_lease_path(tmp_path, token).exists()
    assert owner_alive(token, lease_dir=tmp_path) is False


def test_no_lease_at_all_is_treated_as_alive(tmp_path):
    """Unprovable must fail toward keeping the file.

    The cost of refusing is disk; the cost of the other mistake is a corrupted live VM.
    """
    assert owner_alive("999999999_4242", lease_dir=tmp_path) is True


def test_our_own_lease_is_held_for_the_life_of_the_process(tmp_path):
    """Letting the descriptor be collected would silently drop the lease — and flock is released
    when the last descriptor for the open file description closes."""
    import gc

    assert hold_owner_lease(tmp_path) is True
    gc.collect()
    assert owner_alive(owner_token(), lease_dir=tmp_path) is True, (
        "this process's own lease was dropped; another dispatcher would sweep our live generations"
    )
    assert hold_owner_lease(tmp_path) is True  # idempotent


def test_a_lease_that_could_not_be_locked_leaves_nothing_behind(tmp_path, monkeypatch):
    """Opening CREATES the file, so a transient flock failure left an UNLOCKED lease on disk.

    That is strictly worse than no lease: another dispatcher's sweep acquires it, concludes this
    still-running process is dead, and unlinks the memory files its live microVMs are mapping. An
    absent lease merely refuses to sweep.
    """
    import errno as _errno

    from blastbox.host.runtime import snapshot_backend as mod

    def _boom(fd, op):
        raise OSError(_errno.ENOLCK, "no locks available")

    monkeypatch.setattr(mod.fcntl, "flock", _boom)
    assert hold_owner_lease(tmp_path) is False
    assert not owner_lease_path(tmp_path, owner_token()).exists(), (
        "an unlocked lease file was left behind — another dispatcher will read it as proof this "
        "process is dead and delete the files its live VMs are using"
    )
    # ...and with no lease on disk, ownership is UNPROVABLE, so nothing may be swept.
    assert owner_alive(owner_token(), lease_dir=tmp_path) is True


def test_two_builders_racing_for_one_lease_do_not_unlink_it(tmp_path, monkeypatch):
    """Two snapshot tiers can share a checkpoint root and call this concurrently.

    One file description wins the flock; the LOSER used to unlink the shared pathname on its way
    out, leaving the winner holding a lock on an unlinked inode — so every generation it wrote had
    no lease anyone could find, and after the process exited nothing could prove those files
    reclaimable.
    """
    import threading
    import time as _time

    from blastbox.host.runtime import snapshot_backend as mod

    # WIDEN the window deterministically. Without this the dict write lands so quickly that the
    # losers usually observe it anyway, and the test passes with or without the lock -- it was
    # measuring scheduling luck, not the invariant.
    real_flock = mod.fcntl.flock

    def _slow_flock(fd, op):
        _time.sleep(0.05)
        return real_flock(fd, op)

    monkeypatch.setattr(mod.fcntl, "flock", _slow_flock)

    results: list[bool] = []
    barrier = threading.Barrier(8)

    def _race():
        barrier.wait()
        results.append(hold_owner_lease(tmp_path))

    threads = [threading.Thread(target=_race) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(results), (
        f"a concurrent caller failed to take the process lease: {results}"
    )
    assert owner_lease_path(tmp_path, owner_token()).exists(), (
        "the lease file was unlinked by a loser of the race, so the winner holds a lock on an "
        "unlinked inode and its generations are unprovable"
    )
    assert owner_alive(owner_token(), lease_dir=tmp_path) is True


def test_one_directory_spelled_two_ways_is_one_lease(tmp_path):
    """Different spellings of the same directory produced different cache keys.

    The second acquisition then opened the SAME lease file, failed its flock, and unlinked the
    pathname — leaving the first holding an unlinked inode whose generations no sweep could ever
    discover.
    """
    import os

    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)

    assert hold_owner_lease(nested) is True
    lease = owner_lease_path(nested, owner_token())
    assert lease.exists()

    # The SAME directory, spelled differently: via a relative path and via a symlink.
    link = tmp_path / "link"
    link.symlink_to(nested)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert hold_owner_lease("a/b") is True, (
            "a relative spelling was treated as a new lease"
        )
        assert hold_owner_lease(link) is True, (
            "a symlinked spelling was treated as a new lease"
        )
    finally:
        os.chdir(cwd)

    assert lease.exists(), (
        "a second spelling unlinked the lease, so the holder's generations became undiscoverable"
    )
    assert owner_alive(owner_token(), lease_dir=nested) is True


def test_a_lease_held_by_another_owner_is_never_unlinked(tmp_path, monkeypatch):
    """EAGAIN means somebody holds it right now — by definition not ours to remove."""
    import errno as _errno

    from blastbox.host.runtime import snapshot_backend as mod

    lease = owner_lease_path(tmp_path, owner_token())
    lease.write_bytes(b"")

    def _busy(fd, op):
        raise BlockingIOError(_errno.EAGAIN, "Resource temporarily unavailable")

    monkeypatch.setattr(mod.fcntl, "flock", _busy)
    assert hold_owner_lease(tmp_path) is False
    assert lease.exists(), (
        "a lease another owner is holding was deleted, stranding its generations exactly as the "
        "key mismatch did"
    )
