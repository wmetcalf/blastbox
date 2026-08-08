"""Runtime-agnostic warm-snapshot seam.

One generic SnapshotManager (fc_snapshot.py) drives any SnapshotBackend. The
artifact a backend produces at checkpoint time is OPAQUE to the manager — the
manager stores it and hands it back to restore_in(), never inspecting it. FC's
artifact is a {snapshot, mem} file pair; gVisor's is a runsc image-path dir.
"""
from __future__ import annotations

import contextlib
import fcntl
import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

_log = logging.getLogger(__name__)


# --- generation ownership (shared by every stamping backend) -----------------------
# Which process a on-disk generation belongs to, and whether that process still exists.
# Lives here rather than in one backend's launcher because BOTH FC and gVisor sweep
# orphans with exactly this rule; a second copy is how the two drift.


def proc_starttime(pid: int) -> str | None:
    """Field 22 of /proc/<pid>/stat: the process start time in clock ticks since boot.

    A pid ALONE is not an identity. A dispatcher running as PID 1 in a container -- the normal
    case -- sees every replacement container reuse PID 1, so a pid-only check treats every prior
    container's generations as its own and sweeps nothing, while each deployment adds another
    RAM-sized .mem (PR #82). (pid, starttime) is unique for the life of the boot.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    # The comm field can contain spaces and parentheses; everything after the LAST ')' is safe.
    tail = data.rsplit(b")", 1)[-1].split()
    return tail[19].decode() if len(tail) > 19 else None


def owner_token() -> str:
    """This process's generation-ownership token: ``<pid>_<starttime>``."""
    pid = os.getpid()
    return f"{pid}_{proc_starttime(pid) or '0'}"


def generation_owner(name: str, prefix: str = "warm-") -> str | None:
    """The owner token in a ``<prefix><pid>_<start>-<ns>...`` name, or None if it is not one.

    ``prefix`` because the two backends stamp differently -- FC writes ``warm-<gen>.mem`` /
    ``.snapshot`` / ``.outdisk.ext4``, gVisor a ``checkpoint-<gen>`` directory -- while the
    ownership RULE is identical. gVisor had generation stamping and no sweep at all, so every
    restart leaked its checkpoints permanently; giving it a private copy of this parser is how
    the two would then drift (upstream, PR #82).
    """
    if not name.startswith(prefix):
        return None
    head = name[len(prefix):].split("-", 1)[0]
    if "_" in head and head.split("_", 1)[0].isdigit():
        return head
    # LEGACY pid-only name from a build before ownership carried a start time. Still sweepable on
    # a pid check alone; a rolling upgrade would otherwise strand every pre-upgrade generation.
    return head if head.isdigit() else None


def owner_lease_path(lease_dir: "Path | str", token: str) -> Path:
    """Where the process owning ``token`` holds its lease."""
    return Path(lease_dir) / f".owner-{token}.lease"


# fd -> kept alive for the life of the process. flock is released when the last descriptor for
# the open file description is closed, so letting this be garbage-collected would silently drop
# the lease and invite exactly the sweep this exists to prevent.
_held_leases: dict[str, object] = {}


def hold_owner_lease(lease_dir: "Path | str") -> bool:
    """Take this process's generation lease in ``lease_dir``, and keep it for the process's life.

    Called before writing a generation, so any stamped file on disk is covered by a lease its
    owner holds. Idempotent per directory. Returns False if the lease could not be taken, which
    a caller must treat as "my generations are not protected", never as an error worth failing
    the build over.
    """
    key = str(Path(lease_dir))
    if key in _held_leases:
        return True
    path = owner_lease_path(lease_dir, owner_token())
    fh = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(path, "a+b")                             # noqa: SIM115 -- held for the process
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        # LEAVE NOTHING BEHIND. Opening creates the file, so a flock that failed transiently left
        # an UNLOCKED lease on disk -- which is strictly worse than no lease at all: another
        # dispatcher's _lease_state() acquires it, concludes this still-running process is dead,
        # and unlinks the memory files its live microVMs are mapping. An absent lease merely
        # refuses to sweep (upstream, PR #82).
        if fh is not None:
            fh.close()
            with contextlib.suppress(OSError):
                path.unlink()
        _log.warning("snapshot: could not take the generation lease in %s: %s", lease_dir, exc)
        return False
    _held_leases[key] = fh
    return True


def prune_owner_lease(lease_dir: "Path | str", token: str) -> None:
    """Remove a lease already PROVED unheld. Call after a sweep, never during one."""
    with contextlib.suppress(OSError):
        owner_lease_path(lease_dir, token).unlink()


def _lease_state(lease_dir: "Path | str", token: str) -> bool | None:
    """True = a live process holds this lease, False = provably nobody does, None = no lease."""
    path = owner_lease_path(lease_dir, token)
    try:
        # O_RDWR and NOT "a+b"/O_CREAT: opening in append mode CREATES the file, so a generation
        # with NO lease looked like a lease nobody holds -- i.e. provably dead -- which is the
        # unsafe default this whole mechanism exists to remove.
        fd = os.open(path, os.O_RDWR)
    except FileNotFoundError:
        return None
    except OSError:
        return True                                        # cannot tell -> refuse to sweep
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True                                    # somebody holds it: ALIVE
        # We took it, so no process holds it. The kernel released it when the owner died --
        # which it does regardless of PID namespace, container, or pid reuse.
        #
        # Do NOT unlink here. One owner usually has SEVERAL generations (FC alone writes a
        # .snapshot, a .mem and an outdisk, across two directories), and removing the lease while
        # proving the first one dead left the rest with no lease at all -- which correctly reads
        # as "unprovable, keep it", so the sweep reclaimed exactly one file per owner and leaked
        # the others. Callers prune the lease once, after the sweep.
        return False
    finally:
        os.close(fd)


def owner_alive(token: str, *, lease_dir: "Path | str | None" = None) -> bool:
    """Whether the process that created a generation is still running.

    Pass ``lease_dir`` for any decision that leads to DELETION. The /proc fallback below cannot
    answer this across PID namespaces: two dispatcher containers sharing a snapshot directory
    through a rolling deployment BOTH see themselves as pid 1, so the old container's pid is not
    observable from the new one's /proc, the start times differ, and the still-running owner is
    declared dead -- the sweep then unlinks the .mem/checkpoint its live microVMs are mapping,
    which SIGBUSes them or silently corrupts their memory. A flock on a shared file is the one
    signal that crosses namespaces: the kernel drops it when the holder dies, and holds it
    otherwise, with no reference to any pid at all (upstream, PR #82).

    Unknown counts as ALIVE throughout. Refusing to delete is always the safe error: the cost is
    disk, and the cost of the other mistake is a corrupted live VM.
    """
    if lease_dir is not None:
        state = _lease_state(lease_dir, token)
        if state is not None:
            return state
        # No lease file at all. Either the owner predates leases or it leased elsewhere; in both
        # cases its death is unprovable here, and a rolling deployment is exactly when that
        # happens. Refuse. (Generations have never existed WITHOUT leases in a released build --
        # pre-generation builds wrote fixed paths that this glob does not match -- so nothing
        # legitimate is stranded by this.)
        return True
    return _alive_in_this_namespace(token)


def _alive_in_this_namespace(token: str) -> bool:
    """The pid/start-time rule. Correct ONLY within one PID namespace -- see owner_alive."""
    pid_s, _, start = token.partition("_")
    try:
        pid = int(pid_s)
    except ValueError:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    # The pid exists -- but is it the SAME process? A recycled pid with a different start time is
    # a different process, and the generation belongs to the one that is gone.
    cur = proc_starttime(pid)
    if cur is None or not start:
        return True
    return cur == start




@runtime_checkable
class BootHandle(Protocol):
    """A launched base sandbox used to build the snapshot."""

    def wait_ready(self, timeout_s: float) -> None:
        """Block until the base sandbox's engine signals READY (warm-idle)."""
        ...

    def checkpoint(self, dest_dir: Path) -> object:
        """Capture the warm snapshot, writing artifacts under/near dest_dir.
        Returns an OPAQUE artifact the manager round-trips to restore_in()."""
        ...

    def kill(self) -> None:
        """Tear down the base sandbox."""
        ...


@runtime_checkable
class RestoreHandle(Protocol):
    """A restored per-slot sandbox. Backend-specific I/O accessors are added by
    the concrete handle; the seam only requires kill()."""

    def kill(self) -> None: ...


@runtime_checkable
class SnapshotBackend(Protocol):
    """Spawns/checkpoints/restores the real sandboxes for one runtime (FC, gVisor)."""

    def available(self) -> bool:
        """True iff this backend's prerequisites are present (fail-closed selection)."""
        ...

    def boot_base(self) -> BootHandle: ...

    def restore_in(self, slot_workdir: Path, artifact: object) -> RestoreHandle: ...

    # --- optional hooks (hasattr-guarded by the manager) -------------------------------
    #
    # discard(artifact) -> None
    #     Unlink a fully drained generation. RAISE if cleanup could not be confirmed: the
    #     manager treats a normal return as done and stops retrying.
    #
    # sweep_orphan_generations([base_dir]) -> int
    #     Reclaim generations left by a dispatcher that is GONE. Called from the first build
    #     and retried on later builds until it succeeds. Same contract as discard: raise
    #     rather than report a success you did not achieve. Declare a ``base_dir`` parameter
    #     to be handed the manager's checkpoint root -- a backend that owns its own directory
    #     layout (FC's launcher) can take no argument instead.
    #
    # A backend implementing NEITHER keeps its artifacts, exactly as before these existed;
    # the manager degrades by introspection, never by catching TypeError.
