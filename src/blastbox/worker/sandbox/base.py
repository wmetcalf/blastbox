"""Sandbox protocol and shared types for the blastbox worker SDK."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from blastbox.limits import Limits  # noqa: F401 — re-exported for convenience


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
