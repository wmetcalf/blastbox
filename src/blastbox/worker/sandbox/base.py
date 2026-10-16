"""Sandbox protocol and shared types for the blastbox worker SDK."""
from __future__ import annotations

import logging
import os
import signal
import sys
import contextlib
import contextvars
import itertools
import threading
import time
from collections.abc import Callable, Iterator

from dataclasses import dataclass, field
from pathlib import Path
from types import EllipsisType
from typing import Protocol, TypeVar, runtime_checkable

from blastbox.limits import Limits  # noqa: F401 — re-exported for convenience

_log = logging.getLogger("blastbox.worker.sandbox")

T = TypeVar("T")


def host_platform() -> str:
    """``"darwin"`` or ``"linux"`` -- the one place backend selection asks which OS it is on.

    A function (not a constant) so tests can exercise either platform's selection logic on
    any host, and so the Linux and macOS backends agree on a single answer.
    """
    return "darwin" if sys.platform == "darwin" else "linux"


_CONFINED_RUNS = 0
_CONFINED_LOCK = threading.Lock()


class ConfinementLedger:
    """The confined runs credited to ONE detonation (or one warmup).

    On a host with no outer isolation boundary (macOS) the agent refuses an ``ok`` result that
    no sandboxed run vouches for. A process-wide count diffed around ``detonate()`` could be
    moved by work that is not this parse: a detector's run finishing late on its own thread, a
    run left over from an earlier failed job. Credit is therefore scoped to a ledger that the
    agent opens for the detonation and carries in a context variable:

    * a backend reads the ledger when a run STARTS and credits it when the run finishes, and
      only while the ledger is still open -- so a run must start and end inside the detonation;
    * a run with no ledger in its context (a thread started without the caller's context, a
      detector inside :func:`not_counted`, a run of an earlier job) credits nothing.

    Fail closed: an engine that makes its sandbox calls on a thread it starts gets no credit
    unless it runs that work in the detonation's context -- :func:`in_this_context` wraps a
    callable for ``Thread(target=...)`` / ``executor.submit(...)``."""

    __slots__ = ("_runs", "_open")

    def __init__(self) -> None:
        self._runs = 0
        self._open = True

    @property
    def runs(self) -> int:
        with _CONFINED_LOCK:
            return self._runs

    def _credit(self) -> None:
        with _CONFINED_LOCK:
            if self._open:
                self._runs += 1

    def _close(self) -> None:
        with _CONFINED_LOCK:
            self._open = False


_LEDGER: contextvars.ContextVar[ConfinementLedger | None] = contextvars.ContextVar(
    "blastbox_confinement_ledger", default=None)


@contextlib.contextmanager
def confinement_ledger() -> Iterator[ConfinementLedger]:
    """Open a ledger for the work done in this block (in this context); closed on exit, after
    which a run that is still going credits nothing."""
    ledger = ConfinementLedger()
    token = _LEDGER.set(ledger)
    try:
        yield ledger
    finally:
        ledger._close()
        _LEDGER.reset(token)


def current_ledger() -> ConfinementLedger | None:
    """The ledger a run starting now would credit (None: it credits nothing)."""
    return _LEDGER.get()


def in_this_context(fn: Callable[..., T]) -> Callable[..., T]:
    """``fn`` bound to a copy of the caller's context, for an engine that runs its sandbox
    calls on a thread it starts: a plain thread starts with no ledger, so its runs would not be
    credited to the detonation that started it."""
    ctx = contextvars.copy_context()

    def _run(*args: object, **kwargs: object) -> T:
        return ctx.copy().run(fn, *args, **kwargs)
    return _run


@contextlib.contextmanager
def not_counted() -> Iterator[None]:
    """Runs started in this block (in this context) credit no ledger: a backend probe running
    ``/usr/bin/true``, or an engine's ``detect()``, must not give the engine credit before (or
    instead of) its ``detonate()`` parser. A thread the block starts without copying the context
    has no ledger either, so neither path can vouch for the parse."""
    token = _LEDGER.set(None)
    try:
        yield
    finally:
        _LEDGER.reset(token)


def note_confined_run(ledger: ConfinementLedger | None | EllipsisType = ...) -> None:
    """Called by a backend that confines a run itself (seatbelt, appsandbox) once the run has
    proven it ran confined. ``ledger`` is what :func:`current_ledger` returned when the run
    STARTED (default: the current one, for a caller whose run is instantaneous); it is credited
    only if still open. The process-wide :func:`confined_runs` total counts every such run."""
    global _CONFINED_RUNS
    target = current_ledger() if isinstance(ledger, EllipsisType) else ledger
    with _CONFINED_LOCK:
        _CONFINED_RUNS += 1
    if target is not None:
        target._credit()


def confined_runs() -> int:
    """Every confined run recorded in this process -- a diagnostic total. The agent's
    confinement gate does not use it (see :class:`ConfinementLedger`)."""
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


# Teardown steps a hard exit must not cut in half: a copy-back's renames, which move a host
# directory's entries aside and the new ones in. Exiting between two of them would leave the
# operator's directory part-replaced. A retiring agent waits for these sections to finish
# (bounded), and refuses new ones once it has started. A shutdown signal lands on the main
# thread, which may itself be inside a section (the warmup's runs are on it): the retirement
# then runs when that section ends, since waiting on itself would only time out.
_CRIT_COND = threading.Condition()
_CRIT_ACTIVE = 0
_CRIT_LOCAL = threading.local()
_SHUTTING_DOWN = False


@contextlib.contextmanager
def teardown_critical() -> Iterator[None]:
    """Mark a section a retiring agent waits for rather than exits in the middle of.

    Raises ``SandboxError`` once shutdown has begun: the work is abandoned before it starts
    (the backend's emergency cleanup removes what it staged), never interrupted midway."""
    from blastbox.errors import SandboxError

    global _CRIT_ACTIVE
    with _CRIT_COND:
        if _SHUTTING_DOWN:
            raise SandboxError("the worker is shutting down; teardown step not started")
        _CRIT_ACTIVE += 1
    depth = getattr(_CRIT_LOCAL, "depth", 0)
    _CRIT_LOCAL.depth = depth + 1
    try:
        yield
    finally:
        _CRIT_LOCAL.depth = depth
        with _CRIT_COND:
            _CRIT_ACTIVE -= 1
            _CRIT_COND.notify_all()
        if depth == 0:
            deferred = getattr(_CRIT_LOCAL, "deferred", None)
            _CRIT_LOCAL.deferred = None
            if deferred is not None:
                deferred()


def defer_until_teardown_done(fn: Callable[[], object]) -> bool:
    """If the calling thread is inside a :func:`teardown_critical` section, run ``fn`` when it
    ends (on this thread) and return True; else return False and do nothing."""
    if getattr(_CRIT_LOCAL, "depth", 0) == 0:
        return False
    _CRIT_LOCAL.deferred = fn
    return True


def begin_shutdown(timeout_s: float) -> bool:
    """Refuse new teardown sections, then wait up to ``timeout_s`` for the running ones (on
    other threads) to finish. True if none is left."""
    global _SHUTTING_DOWN
    deadline = time.monotonic() + max(0.0, timeout_s)
    with _CRIT_COND:
        _SHUTTING_DOWN = True
        while _CRIT_ACTIVE > getattr(_CRIT_LOCAL, "depth", 0):
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            _CRIT_COND.wait(left)
        return True


def end_shutdown() -> None:
    """Undo :func:`begin_shutdown` -- only for a retirement whose exit returned (a test's)."""
    global _SHUTTING_DOWN
    with _CRIT_COND:
        _SHUTTING_DOWN = False


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
