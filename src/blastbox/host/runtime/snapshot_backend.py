"""Runtime-agnostic warm-snapshot seam.

One generic SnapshotManager (fc_snapshot.py) drives any SnapshotBackend. The
artifact a backend produces at checkpoint time is OPAQUE to the manager — the
manager stores it and hands it back to restore_in(), never inspecting it. FC's
artifact is a {snapshot, mem} file pair; gVisor's is a runsc image-path dir.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable


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


def owner_alive(token: str) -> bool:
    """Whether the process that created a generation is still running.

    Unknown counts as ALIVE: refusing to delete is always the safe error, because removing a
    generation a live dispatcher is still using pulls the backing store from under its microVMs.
    """
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
