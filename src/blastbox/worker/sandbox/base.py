"""Sandbox protocol and shared types for the blastbox worker SDK."""
from __future__ import annotations

import logging
import os
import signal

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from blastbox.limits import Limits  # noqa: F401 — re-exported for convenience

_log = logging.getLogger("blastbox.worker.sandbox")


def kill_sandbox_group(proc) -> None:
    """SIGKILL the timed-out sandbox's process group -- never the worker's own.

    Every backend launches its child with ``start_new_session=True``, which makes
    that child a process-group leader, so ``os.getpgid(proc.pid)`` names the
    sandbox's own group and killing it reaps the sandbox and its descendants.

    The whole guarantee rests on that one flag, four files away from the kill, and
    losing it is silent and fatal: the same expression then returns the WORKER's
    group, and this SIGKILL takes down the worker plus everything sharing it -- on
    a sandbox timeout, which is the most ordinary failure there is rather than an
    exotic one. Measured by removing the flag from bwrap alone:

        tests/worker/sandbox/ -> rc=137, killed partway through test_bwrap.py

    with no failure reported, because the test that reaches the timeout path
    (``TestBwrapRealRun::test_timeout_kills_sleep``) is the process the kill
    destroys. In CI an rc of 137 reads as an OOM or an infrastructure flake, not
    as a defect -- so no test could report this while the kill was unguarded.

    Hence the group is compared against ours before it is signalled. The fallback
    kills only the direct child, which leaks its descendants; a leak the caller's
    reaper can still see beats an outage it cannot.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return                      # already reaped: nothing to signal
    if pgid == os.getpgid(0):
        # Refusing is the whole point; log LOUDLY, because reaching here means a
        # backend stopped starting a new session and the sandbox's children are
        # now leaking on every timeout.
        _log.error(
            "sandbox.kill_group_refused pgid=%s reason=shares_worker_process_group "
            "impact=descendants_of_the_sandbox_leak "
            "fix=launch_the_child_with_start_new_session=True",
            pgid,
        )
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


@dataclass(frozen=True)
class Mount:
    """Describes a filesystem bind that an engine requests.

    For the :class:`ContainerSandbox` backend mounts are advisory — the files
    are already accessible from inside the container.  Future host-native
    backends (bwrap, nsjail) will honour them as real bind-mounts.
    """

    source: Path
    """Host-side source path."""

    target: Path
    """Target path inside the sandbox."""

    read_only: bool = True


@dataclass
class SandboxRequest:
    """Everything needed to run one sandboxed subprocess."""

    argv: list[str]
    """Argument vector.  Must be a list — ``shell=True`` is never used."""

    ro_mounts: list[Mount] = field(default_factory=list)
    """Read-only bind mounts (advisory for the container backend)."""

    rw_mounts: list[Mount] = field(default_factory=list)
    """Read-write bind mounts (advisory for the container backend)."""

    limits: Limits = field(default_factory=Limits)
    """Resource limits for this invocation."""

    env: dict[str, str] = field(default_factory=dict)
    """Extra environment variables to overlay on the minimal env.

    The subprocess never inherits ``os.environ``; it receives only a clean
    ``PATH`` + ``HOME=/tmp`` plus these explicit additions.
    """


@dataclass
class SandboxResult:
    """Outcome of a :meth:`Sandbox.run` call."""

    exit_code: int
    """Process exit code.  ``-9`` (``-SIGKILL``) when killed by timeout."""

    stdout: bytes
    """Captured standard output (possibly partial if killed)."""

    stderr: bytes
    """Captured standard error (possibly partial if killed)."""

    killed: bool = False
    """``True`` if the process was killed due to wall-clock timeout."""


@runtime_checkable
class Sandbox(Protocol):
    """Protocol that every sandbox backend must satisfy.

    Implementations: :class:`~blastbox.worker.sandbox.container.ContainerSandbox`
    (future: BwrapSandbox, NsjailSandbox).
    """

    name: str
    """Short identifier, e.g. ``"container"``."""

    @property
    def secure(self) -> bool:
        """``False`` if any insecurity reason was detected.

        Conservative by design — any single reason (including the structural
        ``"network_egress_not_verified"``) keeps this ``False``.
        """
        ...

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run ``request.argv`` inside the sandbox.

        Never uses ``shell=True``.  Strips the ambient environment.  Applies
        rlimits.  Kills the child on timeout and returns
        ``SandboxResult(killed=True)``.
        """
        ...
