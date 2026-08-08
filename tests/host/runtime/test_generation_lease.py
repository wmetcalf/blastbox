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


def test_a_live_owner_is_never_declared_dead_just_because_its_pid_is_invisible(tmp_path):
    """The P1 in one assertion.

    Simulate the rolling deployment exactly: a token whose pid IS live in our namespace but is a
    DIFFERENT process (which is what pid 1 looks like from a replacement container), holding its
    lease. The pid rule says dead; ownership must say alive.
    """
    token = f"{os.getpid()}_999999"          # our pid, a different start time
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
    owner_lease_path(tmp_path, token).write_bytes(b"")     # written, nobody holds it
    assert owner_alive(token, lease_dir=tmp_path) is False


def test_the_kernel_releases_the_lease_when_the_holder_dies(tmp_path):
    """Not a mocked release — a real process exits and the lease becomes acquirable."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))) + "/src"!r})
        from blastbox.host.runtime.snapshot_backend import hold_owner_lease, owner_token
        assert hold_owner_lease({str(tmp_path)!r})
        print(owner_token())
    """)
    token = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=60).stdout.strip()
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
    assert hold_owner_lease(tmp_path) is True          # idempotent
