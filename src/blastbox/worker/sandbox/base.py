"""Sandbox protocol and shared types for the blastbox worker SDK."""
from __future__ import annotations

import logging
import os
import signal
import sys
import contextlib
import itertools
import threading
import time
from collections.abc import Callable, Iterator

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from blastbox.limits import Limits  # noqa: F401 — re-exported for convenience

_log = logging.getLogger("blastbox.worker.sandbox")


def host_platform() -> str:
    """``"darwin"`` or ``"linux"`` -- the one place backend selection asks which OS it is on.

    A function (not a constant) so tests can exercise either platform's selection logic on
    any host, and so the Linux and macOS backends agree on a single answer.
    """
    return "darwin" if sys.platform == "darwin" else "linux"


_CONFINED_RUNS = 0
_CONFINED_LOCK = threading.Lock()
# Open not_counted() blocks, process-wide (see not_counted).
_NOT_COUNTED_DEPTH = 0


@contextlib.contextmanager
def not_counted() -> Iterator[None]:
    """Runs made while this block is open don't count as confined parses: a backend probe
    running ``/usr/bin/true``, or an engine's ``detect()``, must not give the engine credit
    before (or instead of) its ``detonate()`` parser.

    Process-wide, not per-thread or per-context: a detector may make its sandbox call on a
    thread it starts (a ``ThreadPoolExecutor``, its own joined thread), which inherits no
    context. The agent that reads the count runs one job at a time, so nothing else of the job
    is running meanwhile; a probe overlapping another thread's run can only withhold credit
    (that result is refused), never grant it."""
    global _NOT_COUNTED_DEPTH
    with _CONFINED_LOCK:
        _NOT_COUNTED_DEPTH += 1
    try:
        yield
    finally:
        with _CONFINED_LOCK:
            _NOT_COUNTED_DEPTH -= 1


def note_confined_run() -> None:
    """Called by a backend that confines a run itself (seatbelt, appsandbox): on a host with no
    outer isolation boundary (macOS), the agent uses the count to prove an ``ok`` result came
    from a sandboxed parse rather than from the engine's own (unconfined) process."""
    global _CONFINED_RUNS
    with _CONFINED_LOCK:
        if _NOT_COUNTED_DEPTH:
            return
        _CONFINED_RUNS += 1


def confined_runs() -> int:
    with _CONFINED_LOCK:
        return _CONFINED_RUNS


# Cleanups for runs in flight, for the agent to call before it hard-exits (see
# run_emergency_cleanups). Only the macOS backends register: their children run in their own
# sessions, which a supervisor's process-group kill doesn't reach.
_EMERGENCY: dict[int, Callable[[], object]] = {}
_EMERGENCY_LOCK = threading.Lock()
_EMERGENCY_IDS = itertools.count()


def register_emergency_cleanup(fn: Callable[[], object]) -> int:
    """Register ``fn`` (kill and sweep one run in flight); returns a token for
    :func:`unregister_emergency_cleanup`."""
    with _EMERGENCY_LOCK:
        token = next(_EMERGENCY_IDS)
        _EMERGENCY[token] = fn
        return token


def unregister_emergency_cleanup(token: int) -> None:
    with _EMERGENCY_LOCK:
        _EMERGENCY.pop(token, None)


def run_emergency_cleanups(timeout_s: float) -> int:
    """Run every registered cleanup, each on its own daemon thread (one may hang on whatever
    hung the run), waiting at most ``timeout_s`` in all. Returns how many completed without
    raising. With nothing registered (every Linux backend) it returns 0 at once."""
    with _EMERGENCY_LOCK:
        fns = list(_EMERGENCY.values())
    if not fns:
        return 0
    done: list[bool] = []

    def _one(fn: Callable[[], object]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- reported, the others still run
            _log.error("sandbox: emergency cleanup failed: %s", exc)
        else:
            done.append(True)

    threads = [threading.Thread(target=_one, args=(fn,), daemon=True, name="bb-emergency")
               for fn in fns]
    for t in threads:
        t.start()
    deadline = time.monotonic() + max(0.0, timeout_s)
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    return len(done)


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

    accelerators: frozenset[str] = frozenset()
    """Hardware the child needs beyond the CPU: ``"gpu"`` (Metal) and/or ``"ane"`` (Neural Engine).

    Default-deny: an empty set grants no accelerator. Honoured by the macOS ``seatbelt``
    backend, which opens exactly the driver user clients and services each one needs; the
    ``appsandbox`` backend (Apple's own profile) already permits both. The Linux backends
    ignore it.
    """

    seed_home: Path | None = None
    """A directory cloned into the per-run scratch HOME before the child starts (macOS backends).

    For warm framework caches: Vision recompiles its Neural Engine plan into an empty cache on
    every run (~1 s); cloning a cache built by a TRUSTED run makes it ~0.15 s. The child gets
    its own APFS copy-on-write clone; nothing it writes ever flows back into the seed, so jobs
    cannot poison each other. Ignored by the Linux backends.
    """

    capture_home: Path | None = None
    """After the run, replace this directory's contents with the scratch HOME (minus ``tmp/``).

    How a ``seed_home`` is produced. **Only for trusted runs** -- a self-test on a generated
    input, never a job: whatever the child leaves in HOME becomes the seed every later run is
    cloned from. Ignored by the Linux backends.
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
