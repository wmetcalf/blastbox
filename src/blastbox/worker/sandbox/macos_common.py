"""Shared plumbing for the macOS sandbox backends (``seatbelt`` and ``appsandbox``).

Both backends confine the child with the kernel's Sandbox.kext (Seatbelt); they differ only
in HOW the profile is attached (``sandbox-exec`` + a generated profile vs. an ad-hoc-signed
App Sandbox launcher). Everything else -- the clean env, the per-run scratch HOME, rlimits
that Darwin actually enforces, the RSS watchdog, the timeout kill and the no-follow copier --
is identical and lives here, so the two backends cannot drift on the parts that matter.

Darwin realities this module encodes (all measured on macOS 26 / Apple silicon):

- ``RLIMIT_AS`` is not enforced by XNU, so ``Limits.memory_bytes`` cannot be an rlimit
  here. It is enforced instead by polling the sandbox's process group RSS and SIGKILLing the
  group when it goes over (:class:`RssWatchdog`).
- ``RLIMIT_NPROC`` is per-USER on Darwin; lowering it for one child throttles every process
  the worker user owns, so it is deliberately not set.
- Frameworks resolve caches from the user's home (``~/Library/Caches/<bundle-id>``), which
  would be shared by every job. ``CFFIXED_USER_HOME`` redirects CoreFoundation's notion of
  home, so caches (e.g. Vision's E5RT bundle cache) land in the per-run scratch dir and die
  with it -- no cross-job cache to poison.
"""
from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import json
import logging
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from blastbox.errors import SandboxError
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxResult, kill_sandbox_group

_log = logging.getLogger("blastbox.worker.sandbox.macos")

IS_DARWIN = sys.platform == "darwin"

#: The only PATH a sandboxed child gets. No /usr/local or /opt/homebrew: an engine that needs
#: a tool from there passes an absolute argv[0] and grants its directory read-only.
MINIMAL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

#: System executable dirs every child may exec from (the rest of the system tree is covered
#: by Apple's ``system.sb`` for reads).
SYSTEM_EXEC_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec")

#: Accelerators an engine may request via ``SandboxRequest.accelerators``.
KNOWN_ACCELERATORS = frozenset({"gpu", "ane"})

# Keys the backend sets itself; a request may not override them (they point the child's
# home / temp / caches at the per-run scratch dir, which is the whole cross-job guarantee).
_RESERVED_ENV = frozenset({"HOME", "CFFIXED_USER_HOME", "TMPDIR", "PATH"})

# Loader-control prefixes a request may not set. dyld honours ``DYLD_*`` (e.g.
# ``DYLD_INSERT_LIBRARIES``) in any process that isn't hardened, so a request env carrying one
# must never reach a process that runs before the sandbox is attached. Dropped outright: a
# sandboxed target has no legitimate need to re-point its own loader.
_LOADER_ENV_PREFIXES = ("DYLD_", "LD_")


def build_child_env(scratch: Path, extra: Mapping[str, str]) -> dict[str, str]:
    """A from-scratch env: minimal PATH, scratch HOME/TMPDIR, plus the request's additions.

    ``os.environ`` is never inherited. A request env key that would re-point the scratch
    (HOME, TMPDIR, ...) is dropped with a warning rather than honoured.
    """
    env: dict[str, str] = {}
    for key, val in extra.items():
        if "\0" in key or "\0" in val or "=" in key or not key:
            # execve would fail on it -- after the launcher started, before any sandbox
            raise SandboxError(f"invalid env entry {key!r}: empty, '=' or NUL in the key, or NUL "
                               "in the value")
        if key in _RESERVED_ENV:
            _log.warning("macos sandbox: ignoring reserved env key %s from the request", key)
            continue
        if key.startswith(_LOADER_ENV_PREFIXES):
            _log.warning("macos sandbox: dropping loader-control env key %s from the request", key)
            continue
        env[key] = val
    env.update({
        "PATH": MINIMAL_PATH,
        "HOME": str(scratch),
        "CFFIXED_USER_HOME": str(scratch),
        "TMPDIR": str(scratch / "tmp") + "/",
        "LANG": env.get("LANG", "C"),
    })
    return env


def make_scratch(base: Path | None = None) -> Path:
    """Create a fresh 0700 per-run scratch dir (``tmp/`` and ``Library/Caches`` inside).

    Returned path is ``realpath``-ed: Seatbelt matches the resolved path, and on macOS
    ``/tmp`` and ``/var`` are symlinks into ``/private``.
    """
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="bb-sbx-", dir=str(base) if base else None)).resolve()
    (scratch / "tmp").mkdir(mode=0o700)
    (scratch / "Library" / "Caches").mkdir(mode=0o700, parents=True)
    return scratch


def seed_scratch(scratch: Path, seed: Path | None, budget_bytes: int) -> None:
    """Clone ``seed``'s contents into ``scratch`` (no-follow, size-capped). Never written back."""
    if seed is None:
        return
    if not seed.is_dir():
        raise SandboxError(f"seed_home {seed} is not a directory")
    # ONE budget (bytes and entries) for the whole seed, merges included: a seed of many
    # top-level entries must not get the entry cap once per entry.
    budget = CopyBudget(budget_bytes)
    for child in seed.iterdir():
        if child.name == "tmp":
            continue
        dest = scratch / child.name
        if dest.is_dir() and child.is_dir() and not child.is_symlink():
            # Merge into the dirs make_scratch pre-created (Library/Caches).
            for sub in child.iterdir():
                _merge_into(sub, dest / sub.name, budget)
        else:
            remove_tree(dest)
            copy_no_follow(child, dest, budget=budget)


def _merge_into(src: Path, dest: Path, budget: CopyBudget) -> None:
    if dest.is_dir() and src.is_dir() and not src.is_symlink():
        for sub in src.iterdir():
            _merge_into(sub, dest / sub.name, budget)
        return
    remove_tree(dest)
    copy_no_follow(src, dest, budget=budget)


def capture_scratch(scratch: Path, dest: Path | None, budget_bytes: int) -> None:
    """Replace ``dest``'s contents with the scratch HOME (minus ``tmp/``). Trusted runs only."""
    if dest is None:
        return
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    for child in dest.iterdir():
        remove_tree(child)
    budget = CopyBudget(budget_bytes)
    for child in scratch.iterdir():
        if child.name == "tmp":
            continue
        copy_no_follow(child, dest / child.name, budget=budget)


def remove_tree(path: Path) -> None:
    """Best-effort recursive delete that never follows a symlink out of ``path``."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path, ignore_errors=True)
    except OSError as exc:
        _log.warning("macos sandbox: could not remove %s: %s", path, exc)


def unlock_tree(path: Path) -> None:
    """Clear user flags (``uchg``) and restore owner permissions under ``path``, never following
    a symlink. A sandboxed child owns its files and can lock them; the worker (same uid) can undo
    that, which is what makes a fail-closed wipe possible."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if hasattr(os, "lchflags"):
        with contextlib.suppress(OSError):
            os.lchflags(path, 0)
    if stat.S_ISLNK(st.st_mode):
        return
    if stat.S_ISDIR(st.st_mode):
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)
        with contextlib.suppress(OSError):
            for child in os.listdir(path):
                unlock_tree(path / child)
    else:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)


def wipe_dir(path: Path) -> None:
    """Empty ``path`` (keeping ``path`` itself) and PROVE it is empty, or raise ``SandboxError``.

    For directories a later run reuses (an App Sandbox slot's ``io/`` and container): a run that
    left something undeletable must not hand its state to the next one. A missing ``path`` is
    clean. ``path`` itself must be a real directory: a sandboxed child owns its container and
    could swap it for a symlink to a host directory, which a following wipe would then empty, so
    a symlink (or any non-directory) raises instead of being followed. Children are removed
    without following links (:func:`remove_tree`)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        kind = "a symlink" if stat.S_ISLNK(st.st_mode) else "not a directory"
        raise SandboxError(f"refusing to wipe {path}: it is {kind}")
    # The child owns the root too and may have locked it (chflags uchg, chmod 000). It is a real
    # directory (checked above), so undo that on the root itself, never following a link.
    if hasattr(os, "lchflags"):
        with contextlib.suppress(OSError):
            os.lchflags(path, 0)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700, follow_symlinks=False)
    try:
        for child in list(path.iterdir()):
            remove_tree(child)
            if os.path.lexists(child):
                unlock_tree(child)
                remove_tree(child)
        left = sorted(c.name for c in path.iterdir())
    except OSError as exc:
        # Anything the worker can't enumerate or remove is "not proven clean", and callers
        # retire on SandboxError -- a bare OSError would hand the slot out again.
        raise SandboxError(f"could not empty {path}: {exc}") from exc
    if left:
        raise SandboxError(f"could not empty {path}: {left[:5]}")


# Launches the child: a fresh, single-threaded interpreter applies the rlimits and execs.
# Setting rlimits from a ``preexec_fn`` in the threaded worker agent is unsafe (the forked child
# can deadlock on a lock another thread held), so the limits are applied here instead.
_LIMITS_LAUNCHER = r"""
import ctypes, ctypes.util, json, os, resource, sys
cfg = json.loads(sys.argv[1])
argv = sys.argv[2:]
def setlim(res, val):
    try:
        soft, hard = resource.getrlimit(res)
        v = val if hard == resource.RLIM_INFINITY else min(val, hard)
        resource.setrlimit(res, (v, v))
    except (ValueError, OSError):
        pass
setlim(resource.RLIMIT_FSIZE, cfg["fsize"])
setlim(resource.RLIMIT_NOFILE, cfg["nofile"])
setlim(resource.RLIMIT_CPU, cfg["cpu"])
setlim(resource.RLIMIT_CORE, 0)
# RLIMIT_NPROC is per-UID on Darwin: cap the uid at what it runs now plus this job's allowance.
try:
    lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
    n = lib.proc_listpids(4, os.getuid(), None, 0)          # PROC_UID_ONLY -> bytes needed
    if n > 0:
        buf = (ctypes.c_int * (n // 4 + 64))()
        got = lib.proc_listpids(4, os.getuid(), buf, ctypes.sizeof(buf))
        if got > 0:
            setlim(resource.RLIMIT_NPROC, got // 4 + cfg["nproc"])
except OSError:
    pass
os.execve(argv[0], argv, cfg["env"])
"""

# Processes a run may create on top of the uid's current count (Darwin's NPROC is per-UID).
NPROC_ALLOWANCE = 64
# Per-stream cap on captured child output held in the worker's memory.
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
# A run may create at most this many files/dirs in its writable dirs (inode-exhaustion guard).
MAX_SCRATCH_ENTRIES = 200_000


#: The launcher's OWN environment. The launcher is an unsandboxed interpreter, so the request's
#: env (which the target needs) is carried in its config and installed only by ``execve``.
LAUNCHER_ENV = {"PATH": MINIMAL_PATH}


def limits_launcher_argv(limits: Limits, argv: list[str],
                         env: Mapping[str, str] | None = None) -> list[str]:
    """``argv`` wrapped in the rlimit launcher (FSIZE, NOFILE, CPU, CORE, NPROC); ``env`` is
    what ``argv`` is exec'd with."""
    cfg = {"fsize": int(limits.tmpfs_bytes), "nofile": 4096, "cpu": int(limits.timeout_s) + 30,
           "nproc": NPROC_ALLOWANCE, "env": dict(env or {})}
    return [sys.executable, "-I", "-S", "-c", _LIMITS_LAUNCHER, json.dumps(cfg), *argv]


def unwrap_launcher(argv: list[str]) -> list[str]:
    """The command inside a :func:`limits_launcher_argv` wrapper (for tests and diagnostics)."""
    if len(argv) > 5 and argv[1:4] == ["-I", "-S", "-c"] and argv[4] == _LIMITS_LAUNCHER:
        return argv[6:]
    return argv


def launcher_child_env(argv: list[str]) -> dict[str, str] | None:
    """The env a :func:`limits_launcher_argv` wrapper execs its command with (tests/diagnostics)."""
    if len(argv) > 5 and argv[1:4] == ["-I", "-S", "-c"] and argv[4] == _LIMITS_LAUNCHER:
        return dict(json.loads(argv[5])["env"])
    return None


def make_apply_rlimits(limits: Limits) -> Callable[[], None]:
    """``preexec_fn`` applying the rlimits Darwin enforces (not AS, not NPROC -- see module doc)."""
    tmpfs_bytes = limits.tmpfs_bytes
    timeout_s = limits.timeout_s

    def _set() -> None:
        for res, val in (
            (resource.RLIMIT_FSIZE, (tmpfs_bytes, tmpfs_bytes)),
            (resource.RLIMIT_NOFILE, (4096, 4096)),
            (resource.RLIMIT_CPU, (timeout_s + 30, timeout_s + 30)),
            (resource.RLIMIT_CORE, (0, 0)),
        ):
            try:
                resource.setrlimit(res, val)
            except (ValueError, OSError):
                pass

    return _set


def group_rss_bytes(pgid: int, ps_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> int:
    """Sum RSS (bytes) of every live process in group ``pgid``; raises like :func:`process_table`."""
    return sum(r.rss for r in process_table(ps_runner) if r.pgid == pgid)


class _Proc:
    __slots__ = ("pid", "ppid", "pgid", "rss")

    def __init__(self, pid: int, ppid: int, pgid: int, rss: int) -> None:
        self.pid, self.ppid, self.pgid, self.rss = pid, ppid, pgid, rss


def process_table(ps_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[_Proc]:
    """Every process's pid, ppid, pgid and RSS (bytes).

    Raises ``SandboxError`` when ``ps`` fails, times out or lists nothing: an empty table would
    read as "the run uses no memory", and the watchdog would stop metering while ``ps`` is down.
    """
    try:
        proc = ps_runner(
            ["/bin/ps", "-A", "-o", "pid=,ppid=,pgid=,rss="],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxError(f"cannot read the process table: {exc}") from exc
    if proc.returncode != 0:
        raise SandboxError(f"cannot read the process table: ps exited {proc.returncode}")
    out = proc.stdout or ""
    rows: list[_Proc] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            pid, ppid, pgid, rss = (int(p) for p in parts)
            rows.append(_Proc(pid, ppid, pgid, rss * 1024))
    if not rows:
        # ps always lists at least itself and the worker.
        raise SandboxError("cannot read the process table: ps listed no processes")
    return rows


def dir_usage(paths: Iterable[Path], max_entries: int) -> tuple[int, int, bool]:
    """(bytes, entries, complete) under ``paths`` without following symlinks; stops counting at
    ``max_entries`` + 1 so a directory bomb can't make the measurement itself expensive.

    ``complete`` is False when part of the tree could not be read (a child can ``chmod 000`` a
    full subdirectory to hide it): the caller must treat that as over budget, never as empty. A
    path that vanished mid-walk (deleted by the run) is simply gone, not unmeasured."""
    total = entries = 0
    complete = True
    stack: list[str] = []
    for root in paths:
        # A root can be a file (an rw FILE mount) or a symlink: count it, never follow it. Only
        # a directory is walked.
        try:
            st = os.lstat(root)
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        if stat.S_ISDIR(st.st_mode):
            stack.append(str(root))
        else:
            entries += 1
            total += st.st_blocks * 512 if hasattr(st, "st_blocks") else st.st_size
    while stack:
        top = stack.pop()
        try:
            it = os.scandir(top)
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        with it:
            try:
                for e in it:
                    entries += 1
                    if entries > max_entries:
                        return total, entries, complete
                    try:
                        st = e.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        complete = False
                        continue
                    total += st.st_blocks * 512 if hasattr(st, "st_blocks") else st.st_size
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(e.path)
            except FileNotFoundError:
                continue
            except OSError:
                complete = False
    return total, entries, complete


class RssWatchdog:
    """Polls one sandboxed run and SIGKILLs everything it started when it goes over budget.

    Darwin has no cgroups and doesn't enforce ``RLIMIT_AS``, so this is the stand-in:

    - **memory**: summed RSS of the run's *family* -- its process group plus every descendant,
      including one that called ``setsid`` -- against ``limit_bytes``;
    - **disk**: bytes and entries under ``watch_dirs`` (the run's writable dirs) against
      ``disk_limit_bytes`` / ``MAX_SCRATCH_ENTRIES``. ``RLIMIT_FSIZE`` caps one file; this caps
      the run;
    - it records every family member it ever saw -- by pid AND start time, so a pid the kernel
      has since handed to an unrelated process is dropped, never metered or killed -- so
      :meth:`kill_family` can reap descendants that outlive the leader (reparented to launchd,
      or in their own session).

    Polling means a burst between samples can overshoot; it bounds a runaway run, it is not a
    hard ceiling.
    """

    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        limit_bytes: int,
        *,
        interval_s: float = 0.25,
        rss_fn: Callable[[int], int] | None = None,
        watch_dirs: Iterable[Path] = (),
        disk_limit_bytes: int | None = None,
        table_fn: Callable[[], list[_Proc]] = process_table,
        member_fn: Callable[[int], bool] | None = None,
        start_fn: Callable[[int], float | None] | None = None,
    ) -> None:
        self._proc = proc
        self._member_fn = member_fn
        self._start_fn = start_fn or proc_start_time
        self._limit = limit_bytes
        self._interval = interval_s
        self._rss_fn = rss_fn
        self._table_fn = table_fn
        self._watch = list(watch_dirs)
        self._disk_limit = disk_limit_bytes
        self._stop = threading.Event()
        self.tripped: str | None = None     # "memory" / "disk" / None
        self.peak_bytes = 0
        # pid -> start time when first seen: the identity a later sample must still match.
        self.seen: dict[int, float] = {}
        try:
            self._pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            self._pgid = None
        if self._pgid is not None and self._pgid == os.getpgid(0):
            self._pgid = None   # never measure (or kill) the worker's own group
        self._thread = threading.Thread(target=self._loop, name="bb-rss-watchdog", daemon=True)

    def __enter__(self) -> RssWatchdog:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        # Fully joined: a sample still in flight (``ps`` may block for seconds, a big walk too)
        # must not land after the run -- once the slot is wiped and reused, its stale view could
        # match the NEXT job (same container identity) and kill it with this job's limits.
        self._thread.join()

    def _seen_alive(self) -> set[int]:
        """Members seen before that are still the SAME process (same start time); a pid that
        exited -- and may since belong to another job -- is forgotten."""
        for pid, started in list(self.seen.items()):
            if self._start_fn(pid) != started:
                del self.seen[pid]
        return set(self.seen)

    def _remember(self, pids: Iterable[int]) -> None:
        for pid in pids:
            if pid not in self.seen:
                started = self._start_fn(pid)
                if started is not None:     # already gone: nothing to remember
                    self.seen[pid] = started

    def _ancestry(self, table: list[_Proc]) -> set[int]:
        """The run's group, its leader (until it is reaped: then its pid is free for reuse) and
        every member seen before that is still the same process."""
        leader = {self._proc.pid} if self._proc.returncode is None else set()
        return {r.pid for r in table if r.pgid == self._pgid} | leader | self._seen_alive()

    def _by_identity(self, table: list[_Proc]) -> set[int]:
        """Processes that carry the run's sandbox (``member_fn``), wherever they sit in the
        process tree: a grandchild that left through a short-lived intermediate and setsid()
        between two samples is still found, metered and killed while the run is going."""
        if self._member_fn is None:
            return set()
        me = os.getpid()
        mine = set(uid_pids())
        return {r.pid for r in table
                if r.pid in mine and r.pid != me and is_sandboxed(r.pid) and self._member_fn(r.pid)}

    def _family(self, table: list[_Proc]) -> list[_Proc]:
        if self._pgid is None:
            return []
        members = self._ancestry(table) | self._by_identity(table)
        by_parent: dict[int, list[_Proc]] = {}
        for r in table:
            by_parent.setdefault(r.ppid, []).append(r)
        frontier = list(members)
        while frontier:
            for c in by_parent.get(frontier.pop(), []):
                if c.pid not in members:
                    members.add(c.pid)
                    frontier.append(c.pid)
        return [r for r in table if r.pid in members]

    def _sample(self) -> None:
        try:
            table = self._table_fn()
            family = self._family(table)
        except SandboxError as exc:
            # The run's processes can't be enumerated: nothing can be metered, so stop the run.
            self._trip("process", str(exc))
            return
        if self._stop.is_set():
            return
        self._remember(r.pid for r in family)
        rss = self._rss_fn(self._pgid) if self._rss_fn else sum(r.rss for r in family)
        self.peak_bytes = max(self.peak_bytes, rss)
        if rss > self._limit:
            self._trip("memory", f"RSS {rss} > limit {self._limit}")
            return
        if self._watch and self._disk_limit is not None:
            used, entries, complete = dir_usage(self._watch, MAX_SCRATCH_ENTRIES)
            if not complete:
                # Fail closed: what can't be measured can't be shown to be under budget.
                self._trip("disk", "part of the writable dirs could not be read "
                                   "(permissions changed under the run?)")
            elif used > self._disk_limit or entries > MAX_SCRATCH_ENTRIES:
                self._trip("disk", f"writable dirs hold {used} bytes / {entries} entries "
                                   f"(limit {self._disk_limit} bytes / {MAX_SCRATCH_ENTRIES} entries)")

    def _trip(self, why: str, detail: str) -> None:
        if self._stop.is_set():
            return          # the run is over; its own exit path does the final kill
        self.tripped = why
        _log.warning("macos sandbox: %s; killing the run", detail)
        self.kill_family()

    def _loop(self) -> None:
        # Sample at once and then fast (5 ms, doubling up to ``interval``): a child that forks,
        # setsid()s and lets the leader exit is only findable while it is still parented under
        # the run. One more sample after the leader exits picks up whatever is left. What a
        # sample can still miss, the backends' post-run sweep (:func:`sweep_sandboxed`) catches.
        if self._pgid is None:
            return
        delay = 0.0
        while not self._stop.wait(delay):
            exited = self._proc.poll() is not None
            self._sample()
            if self.tripped or exited:
                return
            delay = min(self._interval, max(0.005, delay * 2))

    def kill_family(self) -> None:
        """SIGKILL the run's process group and every family member still alive -- also after the
        leader exited normally (a forked child that closed its pipes must not outlive the run)."""
        if self._pgid is None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self._pgid, signal.SIGKILL)
        table: list[_Proc] = []
        try:
            table = self._table_fn()
            family = {r.pid for r in self._family(table)}
        except SandboxError:
            # Can't list or match by sandbox identity: still kill everything known by ancestry.
            # (The post-run sweep then fails the run, since it can't prove the rest gone either.)
            family = {r.pid for r in table if r.pgid == self._pgid} | self._seen_alive()
        live = family - {os.getpid()}
        for pid in live:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)


class _CappedReader(threading.Thread):
    """Drains one pipe, keeping at most ``cap`` bytes; the rest is read and dropped so the child
    never blocks on a full pipe and the worker's memory stays bounded."""

    def __init__(self, stream, cap: int) -> None:
        super().__init__(daemon=True, name="bb-capped-reader")
        self._stream = stream
        self._cap = cap
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            while True:
                chunk = self._stream.read1(65536) if hasattr(self._stream, "read1") else self._stream.read(65536)
                if not chunk:
                    break
                room = self._cap - len(self.data)
                if room > 0:
                    self.data += chunk[:room]
                if len(chunk) > room:
                    self.truncated = True


def run_confined(
    argv: list[str],
    *,
    env: Mapping[str, str],
    limits: Limits,
    cwd: Path,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    rss_fn: Callable[[int], int] | None = None,
    watch_dirs: Iterable[Path] = (),
    max_output_bytes: int = MAX_CAPTURE_BYTES,
    sweep: Callable[[], object] | None = None,
    member_fn: Callable[[int], bool] | None = None,
    pass_fds: tuple[int, ...] = (),
) -> SandboxResult:
    """Launch an already-confining ``argv`` with the shared lifecycle.

    New session; stdin closed; every inherited fd closed; rlimits (FSIZE, NOFILE, CPU, CORE,
    NPROC) applied by a single-threaded launcher, not a ``preexec_fn``; wall-clock timeout;
    memory + disk watchdog over the run's whole process family; output captured up to
    ``max_output_bytes`` per stream; and the whole family killed before returning, even when
    the leader exited normally. ``sweep`` then kills whatever escaped the family (see
    :func:`sweep_sandboxed`); it raises ``SandboxError`` if it can't, failing the run.
    ``member_fn`` (pid -> carries this run's sandbox) lets the watchdog meter and kill such
    processes during the run too, not only after it.

    ``env`` is the TARGET's environment: the launcher (an unsandboxed interpreter) runs with
    :data:`LAUNCHER_ENV` and installs ``env`` only when it execs ``argv``.
    """
    try:
        proc = popen(
            limits_launcher_argv(limits, argv, env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=pass_fds,
            env=dict(LAUNCHER_ENV),
            cwd=str(cwd),
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError) as exc:
        raise SandboxError(f"failed to start sandboxed child: {exc}") from exc

    out = _CappedReader(proc.stdout, max_output_bytes)
    err = _CappedReader(proc.stderr, max_output_bytes)
    out.start()
    err.start()
    killed = False
    with RssWatchdog(proc, limits.memory_bytes, rss_fn=rss_fn, watch_dirs=watch_dirs,
                     disk_limit_bytes=limits.tmpfs_bytes, member_fn=member_fn) as dog:
        try:
            exit_code = proc.wait(timeout=limits.timeout_s)
        except subprocess.TimeoutExpired:
            killed = True
            dog.kill_family()
            kill_sandbox_group(proc)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass
            exit_code = -int(signal.SIGKILL)
    dog.kill_family()
    if sweep is not None:
        # Before draining the pipes: an escapee holding them open would otherwise hold EOF off.
        sweep()
    out.join(timeout=5.0)
    err.join(timeout=5.0)
    stdout, stderr = bytes(out.data), bytes(err.data)
    if dog.tripped:
        killed = True
        what = ("process-family RSS exceeded " + str(limits.memory_bytes) + " bytes"
                if dog.tripped == "memory" else
                "the run's processes could not be enumerated"
                if dog.tripped == "process" else
                "writable dirs exceeded " + str(limits.tmpfs_bytes) + " bytes or "
                + str(MAX_SCRATCH_ENTRIES) + " entries")
        stderr += f"\n[blastbox] killed: {what}\n".encode()
    for name, reader in (("stdout", out), ("stderr", err)):
        if reader.truncated:
            stderr += f"\n[blastbox] {name} truncated at {max_output_bytes} bytes\n".encode()
    return SandboxResult(exit_code=exit_code, stdout=stdout, stderr=stderr, killed=killed)


# --------------------------------------------------------------------------------------------
# Post-run sweep: find a run's processes by their SANDBOX, not their ancestry.
# --------------------------------------------------------------------------------------------
#
# A child that forks, setsid()s and lets the leader exit between two watchdog samples is no
# longer in the run's process group or under its leader. It still carries the run's sandbox,
# though, and the sandbox is specific to the run:
#
# - seatbelt: only this run's profile grants write to its per-run scratch dir, so a process that
#   is sandboxed AND may write that dir is this run's (``sandbox_check`` with a path filter);
# - appsandbox: the kernel reports a process's container (``sandbox_container_path_for_pid``),
#   which is per slot -- also for a forked, setsid()'d, exec'd orphan.
#
# Unsandboxed processes are never matched, nor is the worker itself.

_PROC_UID_ONLY = 4
_SANDBOX_FILTER_PATH = 1
_SANDBOX_CHECK_NO_REPORT = 0x40000000


def _libsystem() -> ctypes.CDLL | None:
    if not IS_DARWIN:
        return None
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        # Fixed args only: the rest is variadic, which ctypes must pass as such on arm64.
        lib.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        lib.sandbox_check.restype = ctypes.c_int
        lib.sandbox_container_path_for_pid.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
        lib.sandbox_container_path_for_pid.restype = ctypes.c_int
        lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listpids.restype = ctypes.c_int
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p,
                                     ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        return lib
    except (OSError, AttributeError):
        return None


_LIBSYSTEM = _libsystem()


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64)]


_PROC_PIDTBSDINFO = 3


def proc_start_time(pid: int) -> float | None:
    """When ``pid`` started (epoch seconds), or None."""
    if _LIBSYSTEM is None:
        return None
    info = _ProcBsdInfo()
    size = ctypes.sizeof(info)
    if _LIBSYSTEM.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, ctypes.byref(info), size) != size:
        return None
    return info.pbi_start_tvsec + info.pbi_start_tvusec / 1e6


def process_apis_available() -> bool:
    """The private libSystem calls the sweeps and the watchdog's identity match rely on."""
    return _LIBSYSTEM is not None


def uid_pids(uid: int | None = None) -> list[int]:
    """Every pid owned by ``uid`` (default: ours).

    Raises ``SandboxError`` when the process list can't be read: an empty answer would read as
    "nothing left" and let a sweep release a slot an escaped child still runs in. (Off Darwin
    there are no macOS sandboxes to find, so the answer is genuinely empty.)"""
    if _LIBSYSTEM is None:
        if IS_DARWIN:
            raise SandboxError("cannot enumerate processes: libSystem process APIs unavailable")
        return []
    uid = os.getuid() if uid is None else uid
    n = _LIBSYSTEM.proc_listpids(_PROC_UID_ONLY, uid, None, 0)
    if n <= 0:
        raise SandboxError(f"cannot enumerate processes: proc_listpids sizing returned {n}")
    buf = (ctypes.c_int * (n // 4 + 256))()
    got = _LIBSYSTEM.proc_listpids(_PROC_UID_ONLY, uid, buf, ctypes.sizeof(buf))
    if got <= 0:
        raise SandboxError(f"cannot enumerate processes: proc_listpids returned {got}")
    return [p for p in buf[: got // 4] if p > 0]


def is_sandboxed(pid: int) -> bool:
    return _LIBSYSTEM is not None and _LIBSYSTEM.sandbox_check(pid, None, 0) == 1


def sandbox_may_write(pid: int, path: Path) -> bool:
    """True if ``pid``'s sandbox allows writing under ``path`` (an existing directory)."""
    if _LIBSYSTEM is None:
        return False
    return _LIBSYSTEM.sandbox_check(pid, b"file-write-data",
                                    _SANDBOX_FILTER_PATH | _SANDBOX_CHECK_NO_REPORT,
                                    os.fsencode(path)) == 0


def container_of(pid: int) -> str | None:
    """``pid``'s App Sandbox container (``.../Containers/<id>/Data``), or None."""
    if _LIBSYSTEM is None:
        return None
    buf = ctypes.create_string_buffer(4096)
    if _LIBSYSTEM.sandbox_container_path_for_pid(pid, buf, len(buf)) != 0:
        return None
    return os.fsdecode(buf.value) or None


def sweep_sandboxed(match: Callable[[int], bool], *, what: str, rounds: int = 400) -> int:
    """SIGKILL every SANDBOXED process of our uid that ``match``es, until none is left.

    Loops because a match may fork while being killed (bounded by the launcher's NPROC cap).
    Returns how many were killed; raises ``SandboxError`` if they keep coming -- a run whose
    processes can't be removed must not be reported, nor its slot reused."""
    me = os.getpid()
    killed: set[int] = set()
    for _ in range(rounds):
        live = [p for p in uid_pids() if p != me and is_sandboxed(p) and match(p)]
        live = [p for p in live if p not in killed or _alive(p)]
        if not live:
            if killed:
                _log.warning("macos sandbox: swept %d process(es) that escaped %s",
                             len(killed), what)
            return len(killed)
        for p in live:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(p, signal.SIGKILL)
            killed.add(p)
        threading.Event().wait(0.005)
    raise SandboxError(f"could not kill the processes left by {what}")


def _alive(pid: int) -> bool:
    """False once ``pid`` is gone or a zombie (killed, awaiting its reaper)."""
    try:
        out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return True
    return bool(out) and not out.startswith("Z")


def writer_matcher(path: Path, *, started_after: float) -> Callable[[int], bool]:
    """Matches a (sandboxed) process that started at/after ``started_after`` and may write
    ``path`` -- a seatbelt run's scratch dir, which only that run's profile grants. The start
    time keeps out a long-running same-uid agent whose own profile happens to allow the
    user's temp dir."""
    def match(p: int) -> bool:
        t = proc_start_time(p)
        return (t is not None and t >= started_after and os.path.isdir(path)
                and sandbox_may_write(p, path))
    return match


def _container_identity(path: str | os.PathLike[str]) -> str:
    """``path`` with its PARENT resolved but its final component (``Data``) kept as named: the
    sandboxed child owns ``Data`` and can swap it for a symlink, which must not change which
    container a process is matched to. ``Containers/<id>`` above it is not the child's."""
    norm = os.path.normpath(os.fspath(path))
    return os.path.join(os.path.realpath(os.path.dirname(norm)), os.path.basename(norm))


def container_matcher(container: Path) -> Callable[[int], bool]:
    """Matches a process whose App Sandbox container is ``container`` (an appsandbox slot)."""
    want = _container_identity(container)
    return lambda p: (c := container_of(p)) is not None and _container_identity(c) == want


def sweep_writers(path: Path, *, started_after: float) -> int:
    """Kill every sandboxed process :func:`writer_matcher` matches."""
    if not os.path.isdir(path):
        return 0
    return sweep_sandboxed(writer_matcher(path, started_after=started_after),
                           what=f"the run in {path}")


def sweep_container(container: Path) -> int:
    """Kill every process whose App Sandbox container is ``container``."""
    return sweep_sandboxed(container_matcher(container), what=f"container {container}")


# --------------------------------------------------------------------------------------------
# No-follow copier (App Sandbox staging). Kept here so it is testable on any platform.
# --------------------------------------------------------------------------------------------

def _clonefile_fn() -> Callable[[bytes, bytes, int], int] | None:
    if not IS_DARWIN:
        return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        fn = libc.clonefile
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
    fn.restype = ctypes.c_int
    return fn


_CLONEFILE = _clonefile_fn()
_CLONE_NOFOLLOW = 0x0001


def _copy_regular(src: Path, dst: Path, mode: int) -> None:
    """APFS clone when possible (O(1), copy-on-write), else a byte copy. Either way the copy
    then gets only ``src``'s rwx bits: a clone keeps setuid/setgid, which must not survive into
    a host copy. Never follows links."""
    cloned = (_CLONEFILE is not None
              and _CLONEFILE(os.fsencode(src), os.fsencode(dst), _CLONE_NOFOLLOW) == 0)
    if not cloned:
        with open(src, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fin, \
                open(dst, "xb") as fout:
            shutil.copyfileobj(fin, fout, 1024 * 1024)
    os.chmod(dst, _perm_bits(mode), follow_symlinks=False)


def _perm_bits(mode: int) -> int:
    # rwx for user/group/other only: a copy never carries setuid/setgid/sticky.
    return stat.S_IMODE(mode) & 0o777


class CopyBudget:
    """Bytes and entries one run's copies may use together, across every call that shares it --
    so N mounts staged (or copied back) for one run can't each take the whole budget, and a
    tree of empty files or symlinks can't exhaust inodes."""

    def __init__(self, max_bytes: int, max_entries: int | None = None) -> None:
        self.max_bytes = max_bytes
        self.max_entries = MAX_SCRATCH_ENTRIES if max_entries is None else max_entries
        self.bytes = 0
        self.entries = 0

    def charge(self, nbytes: int, at: Path) -> None:
        self.entries += 1
        self.bytes += nbytes
        if self.bytes > self.max_bytes:
            raise SandboxError(f"sandbox copy exceeds budget of {self.max_bytes} bytes at {at}")
        if self.entries > self.max_entries:
            raise SandboxError(f"sandbox copy exceeds {self.max_entries} entries at {at}")


def copy_no_follow(src: Path, dst: Path, *, budget_bytes: int | None = None,
                   budget: CopyBudget | None = None) -> int:
    """Copy ``src`` (file or tree) to ``dst`` without ever following a symlink.

    Regular files and directories are copied with their permission bits; a symlink is recreated
    as a symlink (its target is never opened -- the host trust gate confines artifact paths);
    FIFOs, sockets and device nodes are skipped, because opening a FIFO a hostile child left
    behind would block the worker forever. Every entry is charged to ``budget`` (or a fresh one
    of ``budget_bytes``), which raises :class:`SandboxError` once its bytes or entries are
    exceeded, so a child cannot fill the worker's disk through the copy-back. Returns bytes
    copied by this call.
    """
    if budget is None:
        if budget_bytes is None:
            raise TypeError("copy_no_follow needs budget_bytes or budget")
        budget = CopyBudget(budget_bytes)
    start = budget.bytes

    def _one(s: Path, d: Path) -> None:
        st = os.lstat(s)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            budget.charge(0, s)
            os.symlink(os.readlink(s), d)
        elif stat.S_ISDIR(mode):
            budget.charge(0, s)
            d.mkdir(mode=0o700)
            with os.scandir(s) as it:
                for entry in it:
                    _one(Path(entry.path), d / entry.name)
            # After the children: a read-only source dir must not block filling its copy.
            os.chmod(d, _perm_bits(mode), follow_symlinks=False)
        elif stat.S_ISREG(mode):
            budget.charge(st.st_size, s)
            _copy_regular(s, d, mode)
        else:
            budget.charge(0, s)
            _log.warning("macos sandbox: skipping non-regular file %s (mode %o)", s, mode)

    _one(src, dst)
    return budget.bytes - start


def rewrite_path_args(
    args: Iterable[str], mapping: list[tuple[str, str]]
) -> list[str]:
    """Rewrite tokens naming a mounted path to its staged location.

    Matches a whole token equal to a mount target or under it (``target/...``), and the value
    half of a ``--flag=PATH`` token. Longest target first, so nested mounts map correctly.
    """
    ordered = sorted(mapping, key=lambda kv: len(kv[0]), reverse=True)

    def _map(token: str) -> str:
        for old, new in ordered:
            if token == old:
                return new
            if token.startswith(old.rstrip("/") + "/"):
                return new.rstrip("/") + token[len(old.rstrip("/")):]
        return token

    out: list[str] = []
    for tok in args:
        mapped = _map(tok)
        if mapped == tok and tok.startswith("-") and "=" in tok:
            flag, _, value = tok.partition("=")
            mapped_value = _map(value)
            if mapped_value != value:
                mapped = f"{flag}={mapped_value}"
        out.append(mapped)
    return out


def resolve_executable(argv0: str) -> tuple[Path, Path]:
    """``(as_invoked, resolved)`` for ``argv0``; bare names resolve on MINIMAL_PATH only.

    Both matter: the child must be exec'd by the path it was given (a venv's ``bin/python``
    is a symlink, and Python finds its venv from the INVOKED path -- exec the resolved base
    interpreter and the venv silently disappears), while the sandbox must also permit the
    symlink's real target, which is what the kernel actually maps.
    """
    if os.sep not in argv0:
        found = shutil.which(argv0, path=MINIMAL_PATH)
        if found is None:
            raise SandboxError(
                f"{argv0!r} is not on the sandbox PATH ({MINIMAL_PATH}); pass an absolute path"
            )
        argv0 = found
    p = Path(argv0)
    if not p.is_absolute():
        raise SandboxError(f"argv[0] must be absolute or a bare system command: {argv0!r}")
    try:
        resolved = p.resolve(strict=True)
    except OSError as exc:
        raise SandboxError(f"argv[0] does not exist: {argv0!r} ({exc})") from exc
    # The invoked path with its DIRECTORY resolved (Seatbelt matches real paths; /tmp, /var
    # are symlinks into /private) but its final component kept, so a venv symlink survives.
    invoked = p.parent.resolve(strict=True) / p.name
    return invoked, resolved


def is_under(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == r or r in path.parents for r in roots)
