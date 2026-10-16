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
import errno
import ctypes
import ctypes.util
import hmac
import json
import logging
import os
import pwd
import resource
import secrets
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
from blastbox.worker.sandbox.base import (
    SandboxResult, register_emergency_cleanup, teardown_critical, unregister_emergency_cleanup,
)

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


def seed_scratch(scratch: Path, seed: Path | None, budget_bytes: int | None = None, *,
                 budget: CopyBudget | None = None) -> None:
    """Clone ``seed``'s contents into ``scratch`` (no-follow, size-capped). Never written back.

    Charged to ``budget`` when given -- the run's one pre-launch budget, shared with mount
    staging -- else to a fresh one of ``budget_bytes``."""
    if seed is None:
        return
    if not seed.is_dir():
        raise SandboxError(f"seed_home {seed} is not a directory")
    # ONE budget (bytes and entries) for the whole seed, merges included: a seed of many
    # top-level entries must not get the entry cap once per entry.
    if budget is None:
        if budget_bytes is None:
            raise TypeError("seed_scratch needs budget_bytes or budget")
        budget = CopyBudget(budget_bytes)
    links: LinkMap = {}     # one seed is one tree: its hard links stay links across top-level entries
    for child in seed.iterdir():
        if child.name == "tmp":
            continue
        dest = scratch / child.name
        if dest.is_dir() and child.is_dir() and not child.is_symlink():
            # Merge into the dirs make_scratch pre-created (Library/Caches).
            for sub in child.iterdir():
                _merge_into(sub, dest / sub.name, budget, links)
        else:
            remove_tree(dest)
            copy_no_follow(child, dest, budget=budget, links=links)


def _merge_into(src: Path, dest: Path, budget: CopyBudget, links: LinkMap) -> None:
    if dest.is_dir() and src.is_dir() and not src.is_symlink():
        for sub in src.iterdir():
            _merge_into(sub, dest / sub.name, budget, links)
        return
    remove_tree(dest)
    copy_no_follow(src, dest, budget=budget, links=links)


class Leftovers:
    """Paths a run is building OUTSIDE its wiped roots -- a capture's or a copy-back's hidden
    sibling of the destination. Each is listed while it exists, so a backend's emergency
    cleanup (the agent retiring mid-teardown) can remove what an interrupted step left."""

    def __init__(self) -> None:
        self._paths: set[Path] = set()
        self._lock = threading.Lock()

    def add(self, path: Path) -> None:
        with self._lock:
            self._paths.add(path)

    def discard(self, path: Path) -> None:
        with self._lock:
            self._paths.discard(path)

    def remove_all(self) -> None:
        with self._lock:
            paths = list(self._paths)
        for path in paths:
            remove_tree(path)
            if not os.path.lexists(path):
                self.discard(path)


def capture_scratch(scratch: Path, dest: Path | None, budget_bytes: int,
                    leftovers: Leftovers | None = None) -> None:
    """Replace ``dest``'s contents with the scratch HOME (minus ``tmp/``). Trusted runs only.

    The capture is built complete in a hidden sibling of ``dest`` and only then swapped into
    place: a copy that fails partway (an entry the child made unreadable, the budget, a disk or
    I/O error) leaves the previous ``dest`` -- usually the warm cache the next run seeds from --
    exactly as it was, instead of emptied or half-written. The sibling is listed in
    ``leftovers`` while it exists."""
    if dest is None:
        return
    if dest.is_symlink():
        dest = dest.resolve()       # the operator's cache path; swap the directory it names
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    clear_recorded_siblings(dest)   # what an earlier capture's interrupted swap left beside it
    new = dest.parent / f".{dest.name}.capture-{os.urandom(6).hex()}"
    if leftovers is not None:
        leftovers.add(new)
    try:
        os.mkdir(new, 0o700)
        budget = CopyBudget(budget_bytes)
        links: LinkMap = {}
        for child in scratch.iterdir():
            if child.name == "tmp":
                continue
            copy_no_follow(child, new / child.name, budget=budget, links=links)
        swap_into_place(new, dest, leftovers)
    except BaseException:
        remove_tree(new)
        raise
    finally:
        if leftovers is not None and not os.path.lexists(new):
            leftovers.discard(new)


_RENAME_SWAP = 0x2


def _renamex_np() -> Callable[[bytes, bytes, int], int] | None:
    if not IS_DARWIN:
        return None
    try:
        fn = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).renamex_np
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    return fn


def swap_into_place(new: Path, dest: Path, leftovers: Leftovers | None = None) -> None:
    """Make the complete directory ``new`` become ``dest``; the old ``dest`` is removed after.

    ``renamex_np(RENAME_SWAP)`` exchanges the two in one step (APFS/HFS+), so ``dest`` is never
    missing or partial. Where that's unsupported, ``dest`` is renamed aside and ``new`` in,
    restoring the original if the second rename fails. On return ``new`` no longer exists.

    A teardown section (see :func:`teardown_critical`): a retiring agent waits for it rather
    than exit between the two renames, which would leave ``dest`` missing."""
    with teardown_critical():
        _swap_into_place(new, dest, leftovers)


def _swap_into_place(new: Path, dest: Path, leftovers: Leftovers | None = None) -> None:
    if not os.path.lexists(dest):
        os.rename(new, dest)
        return
    if not stat.S_ISDIR(os.lstat(dest).st_mode):
        raise SandboxError(f"cannot replace {dest}: it is not a directory")
    swap = _renamex_np()
    if swap is not None:
        if swap(os.fsencode(new), os.fsencode(dest), _RENAME_SWAP) == 0:
            remove_tree(new)            # now holds the old contents
            return
        err = ctypes.get_errno()
        if err not in (errno.ENOTSUP, errno.EINVAL, errno.ENOSYS):
            raise OSError(err, f"renamex_np(RENAME_SWAP) {new} -> {dest}: {os.strerror(err)}")
    tag = os.urandom(6).hex()
    old = dest.parent / f".{dest.name}.old-{tag}"
    os.rename(dest, old)
    try:
        os.rename(new, dest)
    except BaseException:
        os.rename(old, dest)
        raise
    # Both renames done: `old` is now only the previous capture. Recorded and renamed `done-`,
    # listed in `leftovers` until removed (a retiring agent finishes it), and a later capture
    # of this destination removes it if this worker dies first (clear_recorded_siblings).
    retire_replaced(old, dest.parent / f".{dest.name}{_COPY_BACK_DONE}{tag}", leftovers)


def remove_tree(path: Path) -> None:
    """Best-effort recursive delete that never follows a symlink out of ``path``.

    Classified by ``lstat``: everything that isn't a real directory -- a file, a symlink, but
    also a FIFO, socket or device node a sandboxed child made -- is unlinked; only a directory
    goes to ``rmtree`` (which itself unlinks every non-directory inside). Whatever a first pass
    leaves -- an entry a child locked with a flag or a deny ACL -- is unlocked
    (:func:`unlock_tree`) and removed again."""
    for attempt in (1, 2):
        try:
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                return
            if attempt == 2:
                unlock_tree(path)
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError as exc:
            if attempt == 2:
                _log.warning("macos sandbox: could not remove %s: %s", path, exc)
    if os.path.lexists(path):
        _log.warning("macos sandbox: could not remove %s", path)


_LOCK_FLAGS = (getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "UF_APPEND", 0)
               | getattr(stat, "SF_IMMUTABLE", 0) | getattr(stat, "SF_APPEND", 0))


def locked_entry(path: Path) -> Path | None:
    """The first entry at or under ``path`` (never following a link) that can't be renamed or
    removed as-is -- an immutable/append-only flag, or a directory its owner can't write or
    search -- else None. For host directories, whose flags are the operator's and not ours to
    clear."""
    def _walk(p: Path) -> Path | None:
        st = os.lstat(p)
        if getattr(st, "st_flags", 0) & _LOCK_FLAGS:
            return p
        if stat.S_ISDIR(st.st_mode):
            if st.st_mode & (stat.S_IWUSR | stat.S_IXUSR) != (stat.S_IWUSR | stat.S_IXUSR):
                return p
            with os.scandir(p) as it:
                for entry in it:
                    hit = _walk(Path(entry.path))
                    if hit is not None:
                        return hit
        return None
    return _walk(path)


def locked_file_target(path: Path) -> str | None:
    """Why the host FILE ``path`` can't be replaced by renaming a sibling over it (an
    immutable/append-only flag on it or its directory, or a directory its owner can't write),
    else None. The flags are the operator's: reported, never cleared."""
    st = os.lstat(path)
    if getattr(st, "st_flags", 0) & _LOCK_FLAGS:
        return f"{path} is immutable/append-only"
    parent = os.lstat(path.parent)
    if getattr(parent, "st_flags", 0) & _LOCK_FLAGS:
        return f"{path.parent} is immutable/append-only"
    if parent.st_mode & (stat.S_IWUSR | stat.S_IXUSR) != (stat.S_IWUSR | stat.S_IXUSR):
        return f"{path.parent} is not writable"
    return None


_ACL_TYPE_EXTENDED = 0x00000100


def _acl_stripper() -> Callable[[bytes], int] | None:
    """``acl_set_link_np(path, ACL_TYPE_EXTENDED, <empty ACL>)`` -- ``chmod -N`` on one entry,
    without following a symlink -- or None off Darwin."""
    if not IS_DARWIN:
        return None
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib.acl_init.restype = ctypes.c_void_p
        lib.acl_init.argtypes = [ctypes.c_int]
        lib.acl_set_link_np.restype = ctypes.c_int
        lib.acl_set_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
        empty = lib.acl_init(0)
    except (OSError, AttributeError):
        return None
    if not empty:
        return None
    return lambda p: lib.acl_set_link_np(p, _ACL_TYPE_EXTENDED, empty)


_STRIP_ACL = _acl_stripper()


def unlock_tree(path: Path) -> None:
    """Clear user flags (``uchg``), extended ACLs and restore owner permissions under ``path``,
    never following a symlink. A sandboxed child owns its files and can lock them -- a flag, or a
    deny ACL (``everyone deny delete``) on a file or its directory; the worker (same uid, the
    owner, who may always rewrite an ACL) can undo both, which is what makes a fail-closed wipe
    possible."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if hasattr(os, "lchflags"):
        with contextlib.suppress(OSError):
            os.lchflags(path, 0)
    if _STRIP_ACL is not None:
        _STRIP_ACL(os.fsencode(path))     # best effort, like the rest: wipe_dir proves the result
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
    # The child owns the root too and may have locked it (chflags uchg, chmod 000, a deny ACL).
    # It is a real directory (checked above), so undo that on the root itself, never following
    # a link.
    if hasattr(os, "lchflags"):
        with contextlib.suppress(OSError):
            os.lchflags(path, 0)
    if _STRIP_ACL is not None:
        _STRIP_ACL(os.fsencode(path))
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
# Mandatory: without it a fork bomb has until the next watchdog sample, so a baseline or limit
# that can't be installed stops the run here, before anything untrusted is exec'd.
def nproc_fail(why):
    sys.stderr.write("[blastbox] refusing to run: cannot install the process limit (%s)\n" % why)
    sys.stderr.flush()
    os._exit(cfg["nproc_fail_exit"])
try:
    lib = ctypes.CDLL(cfg.get("libproc") or ctypes.util.find_library("proc")
                      or "/usr/lib/libproc.dylib")
    n = lib.proc_listpids(4, os.getuid(), None, 0)          # PROC_UID_ONLY -> bytes needed
    if n <= 0:
        nproc_fail("proc_listpids size query failed")
    buf = (ctypes.c_int * (n // 4 + 64))()
    got = lib.proc_listpids(4, os.getuid(), buf, ctypes.sizeof(buf))
    if got <= 0:
        nproc_fail("proc_listpids failed")
    want = got // 4 + cfg["nproc"]
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    v = want if hard == resource.RLIM_INFINITY else min(want, hard)
    resource.setrlimit(resource.RLIMIT_NPROC, (v, v))
    # The kernel may clamp it lower still (kern.maxprocperuid); higher, or none, is a failure.
    cur = resource.getrlimit(resource.RLIMIT_NPROC)[0]
    if cur == resource.RLIM_INFINITY or cur > v:
        nproc_fail("limit did not take")
except (OSError, ValueError, AttributeError) as exc:
    nproc_fail(exc)
os.execve(argv[0], argv, cfg["env"])
"""

# Processes a run may create on top of the uid's current count (Darwin's NPROC is per-UID).
NPROC_ALLOWANCE = 64
# The launcher's exit status when it could not install the NPROC limit (nothing was exec'd;
# the run fails like any nonzero exit and, with no handshake, is never credited as confined).
NPROC_FAIL_EXIT = 121
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
           "nproc": NPROC_ALLOWANCE, "nproc_fail_exit": NPROC_FAIL_EXIT, "env": dict(env or {})}
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


def disjoint_roots(paths: Iterable[Path]) -> list[Path]:
    """``paths`` minus duplicates and any path under another one (compared resolved), so a tree
    watched twice -- the same rw mount listed twice, or one nested in another -- is counted once.
    The first spelling of each kept root is returned."""
    resolved = [(Path(p), Path(os.path.realpath(p))) for p in paths]
    kept: list[tuple[Path, Path]] = []
    for p, r in sorted(resolved, key=lambda t: len(t[1].parts)):
        if any(r == k or k in r.parents for _, k in kept):
            continue
        kept.append((p, r))
    order = {id(p): i for i, (p, _) in enumerate(resolved)}
    return [p for p, _ in sorted(kept, key=lambda t: order[id(t[0])])]


_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
# Deeper than this is not measured (and so trips the disk limit): every level holds one open
# directory fd, and no engine needs a tree this deep in its writable dirs.
MAX_WALK_DEPTH = 256


class WatchRoot:
    """One writable root of a run, pinned BEFORE the child starts: a directory by an
    ``O_NOFOLLOW`` fd -- its identity, whatever the child later does to the path (swap it for a
    symlink to another root, rename it) -- anything else (a file mount) by its path."""

    __slots__ = ("path", "fd")

    def __init__(self, path: Path, fd: int | None) -> None:
        self.path = path
        self.fd = fd

    def __repr__(self) -> str:
        return f"WatchRoot({str(self.path)!r}, fd={self.fd})"


def pin_watch_roots(paths: Iterable[Path]) -> list[WatchRoot]:
    """Deduplicate (:func:`disjoint_roots`) and pin a run's writable roots. Called before the
    child is launched, while every path still is what the request named: resolving them after
    launch would follow whatever the child swapped in. Raises ``SandboxError`` if a root can't
    be opened (it then couldn't be measured). Release with :func:`close_watch_roots`."""
    roots: list[WatchRoot] = []
    try:
        for p in disjoint_roots(paths):
            try:
                fd: int | None = os.open(p, _OPEN_DIR)
            except FileNotFoundError:
                fd = None               # not there (yet): measured by path, as a non-directory
            except OSError as exc:
                if exc.errno not in (errno.ENOTDIR, errno.ELOOP):
                    raise SandboxError(f"cannot open the writable dir {p} to meter it: {exc}") from exc
                fd = None               # a file (or link) root: measured by path, never followed
            roots.append(WatchRoot(Path(p), fd))
    except BaseException:
        close_watch_roots(roots)
        raise
    return roots


def close_watch_roots(roots: Iterable[WatchRoot]) -> None:
    for r in roots:
        if r.fd is not None:
            with contextlib.suppress(OSError):
                os.close(r.fd)
            r.fd = None


def _blocks(st: os.stat_result) -> int:
    return st.st_blocks * 512 if hasattr(st, "st_blocks") else st.st_size


def dir_usage(paths: Iterable[Path | WatchRoot], max_entries: int,
              stop: Callable[[], bool] | None = None) -> tuple[int, int, bool]:
    """(bytes, entries, complete) under ``paths`` without following symlinks; stops counting at
    ``max_entries`` + 1 so a directory bomb can't make the measurement itself expensive.

    The walk is file-descriptor relative: each subdirectory is opened from its parent's fd with
    ``O_NOFOLLOW | O_DIRECTORY`` and listed through that fd, never by re-resolving a textual
    path. A running child that swaps a directory for a symlink between being listed and being
    walked therefore can't redirect the (unsandboxed) watchdog into another host tree: the open
    fails and the swapped-in link is counted as itself on the next sample.

    ``complete`` is False when part of the tree could not be read (a child can ``chmod 000`` a
    full subdirectory to hide it), is deeper than :data:`MAX_WALK_DEPTH`, or ``stop`` asked to
    end the walk: the caller must treat that as over budget, never as empty. A path that
    vanished mid-walk (deleted by the run) is simply gone, not unmeasured.

    A :class:`WatchRoot` directory is walked from its pinned fd (re-opened as ``"."``), so the
    tree measured is the one pinned before launch, wherever the child moved its path."""
    total = entries = 0
    complete = True
    stack: list[tuple[int, object]] = []      # (dir fd, its scandir iterator)
    # Hard links share one inode's blocks: charge them once (each name still counts as an
    # entry). Only multiply-linked inodes need remembering.
    charged: set[tuple[int, int]] = set()

    def _charge(st: os.stat_result) -> int:
        if st.st_nlink > 1 and not stat.S_ISDIR(st.st_mode):
            key = (st.st_dev, st.st_ino)
            if key in charged:
                return 0
            charged.add(key)
        return _blocks(st)

    def _open(name: str | Path, dir_fd: int | None) -> tuple[int, object] | None:
        nonlocal complete
        try:
            fd = os.open(name, _OPEN_DIR, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
                complete = False
            return None     # replaced by a link/file since it was seen: never followed
        try:
            return fd, os.scandir(fd)
        except OSError:
            os.close(fd)
            complete = False
            return None

    try:
        for root in paths:
            if isinstance(root, WatchRoot) and root.fd is not None:
                frame = _open(".", root.fd)         # the pinned directory itself
            else:
                path = root.path if isinstance(root, WatchRoot) else root
                # A root can be a file (an rw FILE mount) or a symlink: count it, never follow
                # it. Only a directory is walked.
                try:
                    st = os.lstat(path)
                except FileNotFoundError:
                    continue
                except OSError:
                    complete = False
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    entries += 1
                    total += _charge(st)
                    continue
                frame = _open(path, None)
            if frame is not None:
                stack.append(frame)
            while stack:
                if stop is not None and stop():
                    return total, entries, False
                fd, it = stack[-1]
                try:
                    e = next(it, None)          # type: ignore[call-overload]
                except FileNotFoundError:
                    e = None
                except OSError:
                    complete = False
                    e = None
                if e is None:
                    it.close()                  # type: ignore[attr-defined]
                    os.close(fd)
                    stack.pop()
                    continue
                entries += 1
                if entries > max_entries:
                    return total, entries, complete
                try:
                    st = e.stat(follow_symlinks=False)     # fstatat(fd, name, NOFOLLOW)
                except FileNotFoundError:
                    continue
                except OSError:
                    complete = False
                    continue
                total += _charge(st)
                if stat.S_ISDIR(st.st_mode):
                    if len(stack) >= MAX_WALK_DEPTH:
                        complete = False
                        continue
                    frame = _open(e.name, fd)
                    if frame is not None:
                        stack.append(frame)
    finally:
        for fd, it in stack:
            with contextlib.suppress(OSError):
                it.close()                      # type: ignore[attr-defined]
            with contextlib.suppress(OSError):
                os.close(fd)
    return total, entries, complete


# How long a finished run waits for its watchdog's in-flight sample (``ps`` has its own
# timeout; the disk walk stops on request).
WATCHDOG_JOIN_S = 30.0


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
        watch_dirs: Iterable[Path | WatchRoot] = (),
        disk_limit_bytes: int | None = None,
        table_fn: Callable[[], list[_Proc]] = process_table,
        member_fn: Callable[[int], bool] | None = None,
        start_fn: Callable[[int], float | None] | None = None,
        held_fn: Callable[[Mapping[int, float]], int] | None = None,
    ) -> None:
        self._proc = proc
        self._member_fn = member_fn
        self._start_fn = start_fn or proc_start_time
        if held_fn is None:
            scan = held_unlinked_bytes

            def held_fn(identities: Mapping[int, float]) -> int:
                return scan(identities, start_fn=self._start_fn)
        self._held_fn = held_fn
        self._limit = limit_bytes
        self._interval = interval_s
        self._rss_fn = rss_fn
        self._table_fn = table_fn
        watch = list(watch_dirs)
        # Pinned roots (run_confined pins them before launch) are already disjoint; plain paths
        # (direct callers, tests) are deduplicated here.
        self._watch: list[Path | WatchRoot] = (
            watch if all(isinstance(w, WatchRoot) for w in watch)
            else [*disjoint_roots(w for w in watch if isinstance(w, Path))])
        self._disk_limit = disk_limit_bytes
        self._stop = threading.Event()
        self.tripped: str | None = None     # "memory" / "disk" / None
        self.peak_bytes = 0
        # pid -> start time when first seen: the identity a later sample must still match.
        self.seen: dict[int, float] = {}
        # Guards ``seen``: the sampling thread adds and drops members while a timeout or
        # emergency cleanup reads them in kill_family() -- unguarded, that iteration can raise
        # "dictionary changed size during iteration" and skip the kill.
        self._seen_lock = threading.Lock()
        self._pgid: int | None
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
        # Joined, so a sample still in flight can't land after the run -- once the slot is
        # wiped and reused, its stale view could match the NEXT job (same container identity).
        # A sample checks ``_stop`` before it kills and the disk walk polls it, so this is quick;
        # but it is bounded: a watchdog that won't stop is a failed run (and its stale sample,
        # should it ever finish, still can't kill: ``_stop`` is set).
        self._thread.join(timeout=WATCHDOG_JOIN_S)
        if self._thread.is_alive():
            raise SandboxError(f"the run's watchdog did not stop within {WATCHDOG_JOIN_S:g}s")

    def _seen_alive(self) -> set[int]:
        """Members seen before that are still the SAME process (same start time); a pid that
        exited -- and may since belong to another job -- is forgotten."""
        for pid, started in self.seen_snapshot().items():
            if self._start_fn(pid) != started:
                with self._seen_lock:
                    if self.seen.get(pid) == started:
                        del self.seen[pid]
        return set(self.seen_snapshot())

    def seen_snapshot(self) -> dict[int, float]:
        """A consistent copy of ``seen`` (pid -> start time)."""
        with self._seen_lock:
            return dict(self.seen)

    def _remember(self, pids: Iterable[int]) -> None:
        known = self.seen_snapshot()
        for pid in pids:
            if pid not in known:
                started = self._start_fn(pid)
                if started is not None:     # already gone: nothing to remember
                    with self._seen_lock:
                        self.seen.setdefault(pid, started)

    def _remember_confirmed(self, pids: Iterable[int]) -> None:
        """Remember the members first seen in this sample -- but only once re-confirmed. The pid
        of one listed by ``ps`` may have been reused before its start time is read; recorded,
        that newcomer's identity would be trusted from then on (metered, and killed by
        :meth:`kill_family`). So the family is listed again after the start times are read, and
        a pid is kept only if it is still a member and still the same process."""
        fresh: dict[int, float] = {}
        known = self.seen_snapshot()
        for pid in pids:
            if pid not in known:
                started = self._start_fn(pid)
                if started is not None:     # already gone: nothing to remember
                    fresh[pid] = started
        if not fresh:
            return
        try:
            again = {r.pid for r in self._family(self._table_fn())}
        except SandboxError:
            return      # not confirmed now; the next sample (or its trip) handles them
        for pid, started in fresh.items():
            if pid in again and self._start_fn(pid) == started:
                with self._seen_lock:
                    self.seen.setdefault(pid, started)

    def _group_is_ours(self) -> bool:
        """Whether ``_pgid`` still names THIS run's process group. It is the leader's pid, held
        for us until the leader is reaped; after that the group can empty and the number go to
        another job (as its pid, then its group).

        - leader unreaped: ours;
        - reaped, and the run has a sandbox identity (``member_fn``, which both macOS backends
          pass): never again -- the run's processes are found by identity, seen pid+start time
          and descent, and the backend's post-run sweep, not by the bare group number;
        - reaped, no identity: ours only while no live process holds the number as its pid
          (XNU won't hand out a pid that is still a live group's id, so a group whose number
          is free is still the one the leader made)."""
        if self._pgid is None:
            return False
        if self._proc.returncode is None:
            return True
        if self._member_fn is not None:
            return False
        return self._start_fn(self._pgid) is None

    def _ancestry(self, table: list[_Proc]) -> set[int]:
        """The run's group and its leader (both only until the leader is reaped: then the pid
        is free for reuse) and every member seen before that is still the same process."""
        if not self._group_is_ours():
            return self._seen_alive()
        group = {r.pid for r in table if r.pgid == self._pgid}
        leader = {self._proc.pid} if self._proc.returncode is None else set()
        return group | leader | self._seen_alive()

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
        self._remember_confirmed([r.pid for r in family])
        # rss_fn is keyed by group id; with no usable group, the leader's pid (which a
        # session leader's group id equals) rather than None.
        key = self._pgid if self._pgid is not None else self._proc.pid
        rss = self._rss_fn(key) if self._rss_fn else sum(r.rss for r in family)
        self.peak_bytes = max(self.peak_bytes, rss)
        if rss > self._limit:
            self._trip("memory", f"RSS {rss} > limit {self._limit}")
            return
        if self._watch and self._disk_limit is not None:
            used, entries, complete = dir_usage(self._watch, MAX_SCRATCH_ENTRIES,
                                                stop=self._stop.is_set)
            if self._stop.is_set():
                return
            # Only members with a confirmed identity (pid + start time), each revalidated
            # around its scan: a member that exited and whose pid another job reused since this
            # family was listed must not have that job's held files charged to this run. One
            # not confirmed yet is left to the next sample, as its kill identity is.
            seen = self.seen_snapshot()
            identities = {r.pid: seen[r.pid] for r in family if r.pid in seen}
            try:
                used += self._held_fn(identities)
            except SandboxError as exc:
                self._trip("disk", f"cannot measure files held open by the run: {exc}")
                return
            if not complete:
                # Fail closed: what can't be measured can't be shown to be under budget.
                self._trip("disk", "part of the writable dirs could not be read "
                                   "(permissions changed under the run?)")
            elif used > self._disk_limit or entries > MAX_SCRATCH_ENTRIES:
                self._trip("disk", f"writable dirs hold {used} bytes / {entries} entries "
                                   f"(limit {self._disk_limit} bytes / {MAX_SCRATCH_ENTRIES} entries)")

    def final_disk_check(self) -> None:
        """One synchronous disk measurement after the run is over -- its processes killed and
        swept, so the writable dirs can't change any more. Polling can miss a burst written
        after the last sample (each file under ``RLIMIT_FSIZE``, the total over the limit) just
        before a clean exit; this catches it, and an incomplete walk fails closed as in a
        sample. Sets ``tripped`` to "disk" (the run is then reported killed, never credited)."""
        if self.tripped or not self._watch or self._disk_limit is None:
            return
        used, entries, complete = dir_usage(self._watch, MAX_SCRATCH_ENTRIES)
        if not complete:
            self.tripped = "disk"
            _log.warning("macos sandbox: part of the writable dirs could not be read after the run")
        elif used > self._disk_limit or entries > MAX_SCRATCH_ENTRIES:
            self.tripped = "disk"
            _log.warning("macos sandbox: writable dirs hold %d bytes / %d entries after the run "
                         "(limit %d bytes / %d entries)", used, entries, self._disk_limit,
                         MAX_SCRATCH_ENTRIES)

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
        if self._group_is_ours():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self._pgid, signal.SIGKILL)
        for pid, started in self._kill_targets().items():
            # Every target is signalled only while it is still the process it was identified as.
            kill_if_same(pid, started, start_fn=self._start_fn)

    def _kill_targets(self) -> dict[int, float]:
        """pid -> start time of every family member to kill. A member seen by an earlier sample
        already has its identity. One first found by this scan gets its start time read NOW and
        is then re-confirmed as a member by a second scan: had its pid been reused between the
        first scan and the read, the start time would be the newcomer's, and the newcomer --
        not in the run's family -- fails the second scan. (``kill_if_same`` then re-checks that
        start time right before the signal.) If the run can't be listed or matched, only the
        members already known by identity are killed; the post-run sweep then fails the run,
        since it can't prove the rest gone either."""
        me = os.getpid()
        try:
            first = {r.pid for r in self._family(self._table_fn())}
        except SandboxError:
            first = set()
        known = {pid: started for pid, started in self.seen_snapshot().items() if pid != me}
        fresh: dict[int, float] = {}
        for pid in first - set(known) - {me}:
            started = self._start_fn(pid)
            if started is not None:
                fresh[pid] = started
        if fresh:
            try:
                again = {r.pid for r in self._family(self._table_fn())}
            except SandboxError:
                again = set()
            known.update({pid: s for pid, s in fresh.items() if pid in again})
        return known


def kill_if_same(pid: int, started: float, *,
                 start_fn: Callable[[int], float | None] | None = None) -> bool:
    """SIGKILL ``pid`` only if it is still the process that started at ``started`` (its start
    time, :func:`proc_start_time`): a pid that exited and was reused by an unrelated process --
    another job of the same uid -- is left alone. Returns whether the signal was sent.

    (Darwin has no pidfd, so a reuse in the microseconds between the check and ``kill`` can't
    be excluded; this narrows the window from a whole sweep round to that.)"""
    if (start_fn or proc_start_time)(pid) != started:
        return False
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return False
    return True


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
    # The writable roots are pinned now, before the child exists to swap them (see
    # pin_watch_roots), and stay pinned until the final disk check is done.
    roots = pin_watch_roots(watch_dirs)
    try:
        return _run_pinned(argv, env=env, limits=limits, cwd=cwd, popen=popen, rss_fn=rss_fn,
                           roots=roots, max_output_bytes=max_output_bytes, sweep=sweep,
                           member_fn=member_fn, pass_fds=pass_fds)
    finally:
        close_watch_roots(roots)


def _run_pinned(
    argv: list[str],
    *,
    env: Mapping[str, str],
    limits: Limits,
    cwd: Path,
    popen: Callable[..., subprocess.Popen[bytes]],
    rss_fn: Callable[[int], int] | None,
    roots: list[WatchRoot],
    max_output_bytes: int,
    sweep: Callable[[], object] | None,
    member_fn: Callable[[int], bool] | None,
    pass_fds: tuple[int, ...],
) -> SandboxResult:
    # The emergency cleanup (run if the agent hard-exits mid-run, skipping every `finally`
    # here) is registered BEFORE the child exists, so no instant of its life is uncovered.
    # ``spawn`` is held across Popen until the run's state is recorded: an emergency waits for
    # it rather than run while a forked launcher is not yet visible to anyone.
    spawn = threading.Lock()
    state: dict[str, object] = {}

    def _emergency() -> None:
        with spawn:
            proc_ = state.get("proc")
            dog_ = state.get("dog")
        try:
            if isinstance(dog_, RssWatchdog):
                dog_.kill_family()      # identity-gated, like every other kill here
            elif isinstance(proc_, subprocess.Popen) and proc_.poll() is None:
                # No watchdog yet: the leader is our unreaped child, so its pid is still its
                # own (it can't be reused before we reap it) and a plain kill is safe.
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    proc_.kill()
        finally:
            # By sandbox identity, so it also finds children the leader already forked -- and
            # with no child yet, it simply finds nothing.
            if sweep is not None:
                sweep()

    token = register_emergency_cleanup(_emergency)
    try:
        with spawn:
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
            state["proc"] = proc
            try:
                out = _CappedReader(proc.stdout, max_output_bytes)
                err = _CappedReader(proc.stderr, max_output_bytes)
                out.start()
                err.start()
                killed = False
                dog = RssWatchdog(proc, limits.memory_bytes, rss_fn=rss_fn, watch_dirs=roots,
                                  disk_limit_bytes=limits.tmpfs_bytes, member_fn=member_fn)
            except BaseException:
                # Set-up failed with the child already running: it is our unreaped child, so
                # a plain kill is safe; then sweep whatever it forked.
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=5.0)
                if sweep is not None:
                    sweep()
                raise
            state["dog"] = dog
        try:
            with dog:
                try:
                    exit_code = proc.wait(timeout=limits.timeout_s)
                except subprocess.TimeoutExpired:
                    killed = True
                    # Identity-gated: the group only while it is provably the run's (see
                    # RssWatchdog._group_is_ours), members by pid + start time. No bare
                    # getpgid()/killpg() on the leader's pid here: the watchdog's poll() may have
                    # reaped it at the timeout boundary, and the number may already name
                    # another job's group.
                    dog.kill_family()
                    try:
                        proc.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        pass
                    exit_code = -int(signal.SIGKILL)
        finally:
            # Also when the watchdog failed to stop (its ``__exit__`` raises) or anything above
            # raised: the run fails, but a detached child must not survive it with the run's
            # grants. The sweep runs before draining the pipes: an escapee holding them would
            # hold EOF off. Should the kill or sweep raise as well, the original error stays
            # chained to it. And the sweep runs even if the family kill raised.
            try:
                dog.kill_family()
            finally:
                if sweep is not None:
                    sweep()
    finally:
        unregister_emergency_cleanup(token)
    # Everything of the run is dead now, so its writable dirs are final: measure them once more.
    dog.final_disk_check()
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
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
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
        lib.proc_pidfdinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                       ctypes.c_int]
        lib.proc_pidfdinfo.restype = ctypes.c_int
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


# <sys/proc_info.h>
_PROC_PIDLISTFDS = 1
_PROC_PIDFDVNODEINFO = 1
_PROX_FDTYPE_VNODE = 1
_PROC_PIDREGIONPATHINFO = 8
_VNODE_FDINFO_SIZE = 176            # struct vnode_fdinfo; its vinfo_stat at offset 24
_VNODE_FDINFO_STAT = 24
_REGION_PATHINFO_SIZE = 1272        # struct proc_regionwithpathinfo; vinfo_stat at offset 96
_REGION_PATHINFO_STAT = 96
_REGION_ADDR, _REGION_SIZE = 80, 88  # pri_address / pri_size within it
# A process mapping more regions than this isn't measured (and so trips the disk limit): the
# walk is one call per region, and no engine maps anywhere near this many.
MAX_REGIONS = 50_000


class _ProcFdInfo(ctypes.Structure):
    _fields_ = [("proc_fd", ctypes.c_int32), ("proc_fdtype", ctypes.c_uint32)]


def _vinfo_stat(raw: bytes, off: int) -> tuple[int, int, int, int, int] | None:
    """(dev, ino, mode, nlink, bytes) from a ``struct vinfo_stat`` at ``off``; bytes is the
    larger of the size and the allocated blocks."""
    dev = int.from_bytes(raw[off:off + 4], "little")
    mode = int.from_bytes(raw[off + 4:off + 6], "little")
    nlink = int.from_bytes(raw[off + 6:off + 8], "little")
    ino = int.from_bytes(raw[off + 8:off + 16], "little")
    size = int.from_bytes(raw[off + 88:off + 96], "little", signed=True)
    blocks = int.from_bytes(raw[off + 96:off + 104], "little", signed=True)
    if not ino:
        return None
    return dev, ino, mode, nlink, max(size, blocks * 512, 0)


def held_unlinked_bytes(pids: Iterable[int] | Mapping[int, float], *,
                        start_fn: Callable[[int], float | None] = proc_start_time) -> int:
    """Bytes in regular files the processes ``pids`` hold open or mapped after unlinking them.

    ``pids`` may map each pid to its start time (the run's identity for it). Each such process
    is then checked to still be that process just before AND just after its tables are read; if
    not -- it exited and the pid went to another job, possibly mid-scan -- its sample is
    discarded, so another job's files are never charged to this run. A plain list of pids is
    read as-is.

    A file that is opened (or mmapped) and then unlinked keeps its blocks until the last
    reference goes, but no path leads to it, so :func:`dir_usage` can't see it: a run could
    park many such files near the per-file ``RLIMIT_FSIZE`` and fill the disk while the walk
    reads zero. Counted once per (device, inode). Linked files are left to :func:`dir_usage`.

    Raises ``SandboxError`` when a live process's descriptors or mappings can't be read -- what
    can't be measured can't be shown to be under budget. A process that exited is skipped."""
    if _LIBSYSTEM is None:
        if IS_DARWIN:
            raise SandboxError("cannot read open files: libSystem process APIs unavailable")
        return 0
    held: dict[tuple[int, int], int] = {}
    identities: dict[int, float | None] = (
        dict(pids) if isinstance(pids, Mapping) else dict.fromkeys(pids))
    vfi = ctypes.create_string_buffer(_VNODE_FDINFO_SIZE)
    region = ctypes.create_string_buffer(_REGION_PATHINFO_SIZE)

    def _same(pid: int, started: float | None) -> bool:
        return started is None or start_fn(pid) == started

    for pid, started in identities.items():
        if not _same(pid, started):
            continue            # gone, or the pid is another process now: nothing of ours
        mine: dict[tuple[int, int], int] = {}
        try:
            _scan_held(pid, vfi, region, mine)
        except SandboxError:
            if not _same(pid, started):
                continue        # the failure was another process's (pid reused mid-scan)
            raise               # ours, still alive, and unreadable: fail closed
        if not _same(pid, started):
            continue            # reused while it was read: the sample may be another job's
        held.update(mine)
    return sum(held.values())


def _scan_held(pid: int, vfi: ctypes.Array, region: ctypes.Array,
               held: dict[tuple[int, int], int]) -> None:
    """Add ``pid``'s unlinked open or mapped regular files to ``held`` ((dev, ino) -> bytes)."""
    lib = _LIBSYSTEM
    if lib is None:     # held_unlinked_bytes checks first
        raise SandboxError("cannot read open files: libSystem process APIs unavailable")

    def _note(st: tuple[int, int, int, int, int] | None) -> None:
        if st is not None:
            dev, ino, mode, nlink, nbytes = st
            if stat.S_ISREG(mode) and nlink == 0:
                held[(dev, ino)] = nbytes

    listed = _list_fds(pid)
    if listed is None:
        return                  # exited (or exiting): it holds nothing any more
    fds, got = listed
    for f in fds[: got // ctypes.sizeof(_ProcFdInfo)]:
        if f.proc_fdtype != _PROX_FDTYPE_VNODE:
            continue
        # A descriptor closed since the listing is simply gone.
        if lib.proc_pidfdinfo(pid, f.proc_fd, _PROC_PIDFDVNODEINFO, vfi,
                              _VNODE_FDINFO_SIZE) == _VNODE_FDINFO_SIZE:
            _note(_vinfo_stat(vfi.raw, _VNODE_FDINFO_STAT))
    # Mapped files: an mmap keeps an unlinked file alive after its descriptor is closed.
    addr = count = 0
    while lib.proc_pidinfo(pid, _PROC_PIDREGIONPATHINFO, addr, region,
                           _REGION_PATHINFO_SIZE) > 0:
        count += 1
        if count > MAX_REGIONS:
            raise SandboxError(f"pid {pid} maps more than {MAX_REGIONS} regions")
        raw = region.raw
        _note(_vinfo_stat(raw, _REGION_PATHINFO_STAT))
        start = int.from_bytes(raw[_REGION_ADDR:_REGION_ADDR + 8], "little")
        size = int.from_bytes(raw[_REGION_SIZE:_REGION_SIZE + 8], "little")
        nxt = start + size
        if nxt <= addr:
            break
        addr = nxt


# A process caught while it exits can fail the fd listing with an error other than ESRCH
# (measured: ENOTSUP) before it is a zombie; a failure on one not (yet) flagged exiting is
# retried this often.
_FD_LIST_TRIES = 5
# Listings that fill their buffer are retried with a larger one this often, then fail closed.
_PID_LIST_TRIES = 5


def _list_fds(pid: int) -> tuple[ctypes.Array, int] | None:
    """``pid``'s descriptor table as ``(buffer, bytes used)``, or None when it exited -- also
    one that is exiting: a zombie has closed every descriptor and dropped its mappings. A live
    process whose table still can't be read raises ``SandboxError``.

    ``proc_pidinfo`` returns 0 both on failure and for a process with no descriptors open (a
    child that closed its stdio, say): errno, cleared before each call, tells them apart."""
    lib = _LIBSYSTEM
    if lib is None:     # callers check first; kept so a new caller can't skip it silently
        raise SandboxError("cannot list descriptors: libSystem process APIs unavailable")
    err = 0
    for attempt in range(_FD_LIST_TRIES):
        ctypes.set_errno(0)
        n = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, None, 0)
        sized = n > 0 or (n == 0 and ctypes.get_errno() == 0)
        fds = (_ProcFdInfo * (max(n, 0) // ctypes.sizeof(_ProcFdInfo) + 64))()
        if sized:
            ctypes.set_errno(0)
            got = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, fds, ctypes.sizeof(fds)) \
                if n > 0 else 0
            if 0 < got < ctypes.sizeof(fds) or (got == 0 and ctypes.get_errno() == 0):
                return fds, got         # (an empty table is an answer too)
            if got >= ctypes.sizeof(fds):
                continue    # a full buffer may be truncated: size again (the table grew)
        err = ctypes.get_errno()
        if err == errno.ESRCH or proc_start_time(pid) is None \
                or _proc_state(pid) in ("gone", "zombie", "exiting"):
            return None
        threading.Event().wait(0.01 * (attempt + 1))
    raise SandboxError(f"cannot list pid {pid}'s open files "
                       f"(errno {err}: {os.strerror(err) if err else '?'})")


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
    # A FULL buffer may be a truncated one: the uid's process count can grow between the sizing
    # call and the listing (concurrent slots forking). A sweep that read a truncated list could miss
    # an escaped child and count a quiet round, so retry larger and fail closed if it stays full.
    extra = 256
    for _ in range(_PID_LIST_TRIES):
        n = _LIBSYSTEM.proc_listpids(_PROC_UID_ONLY, uid, None, 0)
        if n <= 0:
            raise SandboxError(f"cannot enumerate processes: proc_listpids sizing returned {n}")
        buf = (ctypes.c_int * (n // 4 + extra))()
        got = _LIBSYSTEM.proc_listpids(_PROC_UID_ONLY, uid, buf, ctypes.sizeof(buf))
        if got <= 0:
            raise SandboxError(f"cannot enumerate processes: proc_listpids returned {got}")
        if got < ctypes.sizeof(buf):
            return [p for p in buf[: got // 4] if p > 0]
        extra *= 4
    raise SandboxError("cannot enumerate processes: the process list kept filling its buffer")


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


# Consecutive conclusive empty rounds before a sweep calls the run gone (see sweep_sandboxed).
SWEEP_QUIET_ROUNDS = 3


def sweep_sandboxed(match: Callable[[int], bool], *, what: str, rounds: int = 400,
                    before_round: Callable[[], object] | None = None) -> int:
    """SIGKILL every SANDBOXED process of our uid that ``match``es, until none is left.

    Loops because a match may fork while being killed (bounded by the launcher's NPROC cap).
    It returns only after :data:`SWEEP_QUIET_ROUNDS` consecutive rounds that matched nothing
    AND in which every listed process was still there to be ruled out: a process that vanished
    mid-round may have handed off to a child the listing missed. Returns how many were killed;
    raises ``SandboxError`` if they keep coming (or the rounds never come out clean) -- a run
    whose processes can't be shown gone must not be reported, nor its slot reused."""
    me = os.getpid()
    # (pid, start time): the identity each kill was aimed at. A pid alone could by now name
    # another job's process.
    killed: set[tuple[int, float]] = set()
    quiet = 0
    for _ in range(rounds):
        if before_round is not None:
            before_round()
        live: list[tuple[int, float]] = []
        # A listed process that is gone before it could be ruled out may have been the run's: an
        # escapee that forks a successor and exits leaves the successor out of this listing and
        # itself out of the matching. Such a round proves nothing.
        inconclusive = False
        for p in uid_pids():
            if p == me:
                continue
            # The identity is taken BEFORE matching: a match then vouches for this start time.
            started = proc_start_time(p)
            if started is None:
                state = _proc_state(p)
                if state in ("zombie", "exiting"):
                    continue                # can't run any more: holds no grant
                if state == "gone":
                    inconclusive = True     # exited between listing and identifying
                    continue
                if proc_start_time(p) is None and is_sandboxed(p):
                    # A live sandboxed process whose identity can't be read can't be ruled out
                    # (the matchers need it) nor killed safely: fail the sweep rather than
                    # report the run clean.
                    raise SandboxError(f"cannot identify process {p} left by {what}")
                inconclusive = True         # readable again (or unsandboxed): look again
                continue
            if not (is_sandboxed(p) and match(p)):
                if proc_start_time(p) != started:
                    inconclusive = True     # exited (or was replaced) while being matched
                continue
            if (p, started) in killed and not _alive(p):
                continue                    # already killed, a zombie awaiting its reaper
            live.append((p, started))
        if not live:
            quiet = 0 if inconclusive else quiet + 1
            if quiet >= SWEEP_QUIET_ROUNDS:
                if killed:
                    _log.warning("macos sandbox: swept %d process(es) that escaped %s",
                                 len(killed), what)
                return len(killed)
            threading.Event().wait(0.005)
            continue
        quiet = 0
        for p, started in live:
            # Revalidated right before signalling: a target that exited after matching (its
            # pid possibly reused by an unrelated process) is skipped, not killed.
            if kill_if_same(p, started):
                killed.add((p, started))
        threading.Event().wait(0.005)
    raise SandboxError(f"could not kill the processes left by {what}")


def _proc_state(pid: int) -> str:
    """"gone", "zombie" (exited, awaiting its reaper), "exiting" or "alive" -- also when ``ps``
    fails, the answer that never lets a sweep call a process gone.

    "exiting" is ps's ``E`` flag ("trying to exit"): the kernel is tearing the process down (a
    killed process with a large address space can stay there a while). It can't return to user
    space -- run, write, fork -- again, so like a zombie it holds no grant; meanwhile the
    kernel may refuse to describe it (its fd list, its start time), which must not be taken for
    a live process that can't be identified."""
    try:
        out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "alive"
    if not out:
        return "gone"
    if out.startswith("Z"):
        return "zombie"
    return "exiting" if "E" in out[1:] else "alive"


def _alive(pid: int) -> bool:
    """False once ``pid`` is gone, exiting or a zombie (killed, awaiting its reaper)."""
    return _proc_state(pid) == "alive"


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
    return containers_matcher([container])


def containers_matcher(containers: Iterable[Path]) -> Callable[[int], bool]:
    """Matches a process whose App Sandbox container is any of ``containers``."""
    want = {_container_identity(c) for c in containers}
    return lambda p: (c := container_of(p)) is not None and _container_identity(c) in want


def restore_identity_dir(path: Path) -> None:
    """Put a real, empty-or-existing directory back at ``path`` if the run removed it or
    swapped it for a symlink/file. A seatbelt run is identified by the profile's write grant on
    this PATH (``sandbox_check`` is path-based), so a fresh directory at the same path
    identifies it again. Raises ``SandboxError`` if that can't be done."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as exc:
        raise SandboxError(f"cannot inspect {path} to sweep its run: {exc}") from exc
    if st is not None and stat.S_ISDIR(st.st_mode):
        return
    try:
        if st is not None:
            if hasattr(os, "lchflags"):
                with contextlib.suppress(OSError):
                    os.lchflags(path, 0)
            os.unlink(path)
        os.mkdir(path, 0o700)
    except FileExistsError:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise SandboxError(f"cannot restore {path} to sweep its run") from None
    except OSError as exc:
        raise SandboxError(f"cannot restore {path} to sweep its run: {exc}") from exc


def sweep_writers(path: Path, *, started_after: float) -> int:
    """Kill every sandboxed process :func:`writer_matcher` matches.

    A missing or replaced ``path`` is NOT an empty run: a detached child can remove its scratch
    dir (or swap in a symlink) to stop matching. The directory is put back before every round,
    so the path the profile grants is a real directory again and its writers match; if it
    can't be, the sweep fails (``SandboxError``) rather than reporting nothing to kill."""
    return sweep_sandboxed(writer_matcher(path, started_after=started_after),
                           what=f"the run in {path}",
                           before_round=lambda: restore_identity_dir(path))


def sweep_container(container: Path) -> int:
    """Kill every process whose App Sandbox container is ``container``."""
    return sweep_sandboxed(container_matcher(container), what=f"container {container}")


def sweep_containers(containers: Iterable[Path], *, what: str) -> int:
    """Kill every process whose App Sandbox container is any of ``containers``: one sweep
    (each lists every process of the uid, several rounds) rather than one per container."""
    return sweep_sandboxed(containers_matcher(containers), what=what)


# --------------------------------------------------------------------------------------------
# No-follow copier (App Sandbox staging). Kept here so it is testable on any platform.
# --------------------------------------------------------------------------------------------

def _clonefile_fn() -> Callable[[int, int, bytes, int], int] | None:
    """``fclonefileat(srcfd, dst_dirfd, dst, flags)``: clones the file an fd already pins, so
    the clone is of exactly the inode the copier opened and checked (a path-based clonefile
    would resolve the path again, through any directory swapped for a symlink meanwhile)."""
    if not IS_DARWIN:
        return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        fn = libc.fclonefileat
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    fn.restype = ctypes.c_int
    return fn


_CLONEFILE = _clonefile_fn()
_AT_FDCWD = -2          # Darwin's value; the destination is passed as an absolute path


# Extended attributes (incl. a resource fork, com.apple.ResourceFork). A clone carries them; a
# byte copy and a fresh directory don't, and a copy-back from such a copy would strip the host's
# entries even after a no-op run. So they are copied explicitly, from the pinned source fd, onto
# the new path without following a link, and charged (name + value) to the copy budget. NOT
# copied: ``com.apple.system.*`` -- the ACL and other kernel-managed state, which a copy never
# carries (the clone path strips the ACL too) -- and Linux's equivalents (``system.*`` POSIX
# ACLs, ``security.*``, ``trusted.*``), so the copier behaves the same where its tests run.
# Python's os.*xattr is Linux-only; on Darwin libc's f*xattr is called directly.
_XATTR_NOFOLLOW = 0x0001
_XATTR_SKIP_PREFIXES = ("com.apple.system.", "system.", "security.", "trusted.",
                        "user.blastbox.copyback-done")   # _DONE_XATTR: never reproduced


def _darwin_xattr() -> "ctypes.CDLL | None":
    if not IS_DARWIN:
        return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        libc.flistxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
        libc.flistxattr.restype = ctypes.c_ssize_t
        libc.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        libc.fgetxattr.restype = ctypes.c_ssize_t
        libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        libc.setxattr.restype = ctypes.c_int
    except (OSError, AttributeError):
        return None
    return libc


_XATTR_LIB = _darwin_xattr()
_NO_XATTRS = (errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP))


def _xattr_names(fd: int) -> list[bytes]:
    """The extended attribute names on the open file ``fd``; [] where unsupported."""
    if _XATTR_LIB is not None:
        for _ in range(4):
            n = _XATTR_LIB.flistxattr(fd, None, 0, 0)
            if n < 0:
                err = ctypes.get_errno()
                if err in _NO_XATTRS:
                    return []
                raise OSError(err, os.strerror(err))
            if n == 0:
                return []
            buf = ctypes.create_string_buffer(n)
            got = _XATTR_LIB.flistxattr(fd, buf, n, 0)
            if got >= 0:
                return [x for x in buf.raw[:got].split(b"\0") if x]
            if ctypes.get_errno() != errno.ERANGE:      # grew in between: size it again
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
        raise OSError(errno.ERANGE, "extended attribute list kept growing")
    if hasattr(os, "listxattr"):
        try:
            return [os.fsencode(n) for n in os.listxattr(fd)]
        except OSError as exc:
            if exc.errno in _NO_XATTRS:
                return []
            raise
    return []


def _xattr_get(fd: int, name: bytes) -> bytes:
    if _XATTR_LIB is not None:
        for _ in range(4):
            n = _XATTR_LIB.fgetxattr(fd, name, None, 0, 0, 0)
            if n < 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
            buf = ctypes.create_string_buffer(max(n, 1))
            got = _XATTR_LIB.fgetxattr(fd, name, buf, n, 0, 0)
            if got >= 0:
                return buf.raw[:got]
            if ctypes.get_errno() != errno.ERANGE:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
        raise OSError(errno.ERANGE, "extended attribute kept growing")
    return os.getxattr(fd, name)


def _xattr_set(path: Path, name: bytes, value: bytes) -> None:
    if _XATTR_LIB is not None:
        if _XATTR_LIB.setxattr(os.fsencode(path), name, value, len(value), 0,
                               _XATTR_NOFOLLOW) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return
    os.setxattr(path, name, value, follow_symlinks=False)


def _copy_xattrs(fd: int, dst: Path, budget: "CopyBudget", at: Path, *, write: bool) -> None:
    """Charge ``fd``'s extended attributes to ``budget`` and, if ``write``, set them on ``dst``
    (a clone already has them). One that can't be read or reproduced fails the copy
    (:class:`SandboxError`) rather than being dropped -- the copy-back would delete it."""
    try:
        names = _xattr_names(fd)
    except OSError as exc:
        raise SandboxError(f"sandbox copy: cannot list the extended attributes of {at}: "
                           f"{exc}") from exc
    for name in names:
        if os.fsdecode(name).startswith(_XATTR_SKIP_PREFIXES):
            continue
        try:
            value = _xattr_get(fd, name)
        except OSError as exc:
            raise SandboxError(f"sandbox copy: cannot read extended attribute "
                               f"{os.fsdecode(name)} of {at}: {exc}") from exc
        budget.charge_bytes(len(name) + len(value), at)
        if write:
            try:
                _xattr_set(dst, name, value)
            except OSError as exc:
                raise SandboxError(f"sandbox copy: cannot copy extended attribute "
                                   f"{os.fsdecode(name)} of {at}: {exc}") from exc


def _copy_regular_fd(fd: int, dst: Path, mode: int,
                     budget: "CopyBudget | None" = None, at: Path | None = None) -> None:
    """Copy the open regular file ``fd`` to the new path ``dst``: an APFS clone when possible
    (O(1), copy-on-write), else a byte copy. Either way the copy then gets only the source's
    rwx bits: a clone keeps setuid/setgid, flags and the extended ACL, none of which may survive
    into a host copy."""
    cloned = (_CLONEFILE is not None
              and _CLONEFILE(fd, _AT_FDCWD, os.fsencode(dst), 0) == 0)
    if not cloned:
        os.lseek(fd, 0, os.SEEK_SET)
        with open(dst, "xb") as fout:
            while chunk := os.read(fd, 1024 * 1024):
                fout.write(chunk)
    if budget is not None:
        # the clone already carries them (only charged); a byte copy gets them written
        _copy_xattrs(fd, dst, budget, at or dst, write=not cloned)
    if cloned:
        # A clone carries the source's flags and extended ACL: a child must not plant an
        # immutable or undeletable (``everyone deny delete``) file in the host tree. A byte copy
        # is a new file and gets neither from the source.
        if hasattr(os, "lchflags"):
            os.lchflags(dst, 0)
        if _STRIP_ACL is not None and _STRIP_ACL(os.fsencode(dst)) != 0:
            err = ctypes.get_errno()
            raise SandboxError(f"cannot clear the ACL on {dst}: {os.strerror(err)}")
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
        self.charge_bytes(nbytes, at)

    def charge_bytes(self, nbytes: int, at: Path) -> None:
        """Bytes with no new entry (an entry's extended attributes)."""
        self.bytes += nbytes
        if self.bytes > self.max_bytes:
            raise SandboxError(f"sandbox copy exceeds budget of {self.max_bytes} bytes at {at}")
        if self.entries > self.max_entries:
            raise SandboxError(f"sandbox copy exceeds {self.max_entries} entries at {at}")


#: Hard-link aliases seen by one copy: (st_dev, st_ino) of a source file -> its first copy.
LinkMap = dict[tuple[int, int], Path]


def find_special_entry(root: Path, *, max_entries: int = MAX_SCRATCH_ENTRIES) -> Path | None:
    """The first FIFO, socket or device node at or under ``root`` (never following a symlink),
    or None. :func:`copy_no_follow` skips those, so a WRITABLE mount holding one can't be
    staged faithfully: its copy-back would delete the host's entry (a live socket's path, say).
    Stops looking after ``max_entries`` -- a tree that large fails the copy's own entry budget.
    An unreadable directory raises ``SandboxError`` (the copy could not read it either)."""
    seen = 0
    stack = [root]
    while stack:
        p = stack.pop()
        try:
            mode = os.lstat(p).st_mode
        except FileNotFoundError:
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            return p
        if not stat.S_ISDIR(mode):
            continue
        try:
            with os.scandir(p) as it:
                for entry in it:
                    seen += 1
                    if seen > max_entries:
                        return None
                    stack.append(Path(entry.path))
        except OSError as exc:
            raise SandboxError(f"cannot read {p}: {exc}") from exc
    return None


#: Name marker of a copy-back's hidden entries (App Sandbox): ``<mark><tag>`` (the replacement
#: being built), ``<mark>old-<tag>`` (the host's entries moved aside mid-swap), ``<mark>done-<tag>``
#: (the replaced entries once every rename is done, being removed), and for a file mount the
#: sibling ``.<name><mark><tag>``.
COPY_BACK_MARK = ".blastbox-copyback-"
_COPY_BACK_DONE = COPY_BACK_MARK + "done-"

#: Where a ``done-`` tree is recorded while it is removed (per user; tests point it elsewhere).
#: A name alone proves nothing -- the mount's owner, or a sandboxed child, can create an entry
#: called ``.blastbox-copyback-done-x`` as real output -- so cleanup deletes only a ``done-``
#: entry whose (directory, name, device, inode) this worker recorded before renaming it there.
DONE_RECORD_DIR: Path | None = None

#: The tag a recorded ``done-`` tree carries: a per-retire random nonce, also kept in the record.
#: (device, inode) alone is not an identity -- a freed inode number is reused at once (ext4 and
#: tmpfs hand the next mkdir the same one), so an owner's own ``done-x`` made after the tree was
#: removed matched the record and was deleted. The nonce lives only in the record (in the
#: protected state dir) and on the tree itself; nobody else can put it on an entry. ``user.`` is
#: the namespace Linux requires; macOS takes the name as is. The copier never reproduces it.
_DONE_XATTR = b"user.blastbox.copyback-done"


def _done_record_dir() -> Path:
    d = DONE_RECORD_DIR or shared_state_dir() / "copyback-done"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def shared_state_dir(home: Path | None = None) -> Path:
    """The per-user directory of the native backends' shared state: App Sandbox bundle locks,
    the writable-source claim registry, copy-back cleanup records. Every worker of this user
    and every root relies on it, so no run may mount, seed from or capture over it."""
    return (home or Path(pwd.getpwuid(os.getuid()).pw_dir)) / "Library" / "Caches" / "blastbox"


def internal_state_dirs(home: Path | None = None) -> list[Path]:
    """Every directory holding state a run must never reach (see :func:`shared_state_dir`):
    a child with a writable grant there could release another run's lock or forge a cleanup
    record (and so get a later worker to delete an entry it chose), and a copy-back or capture
    over it would replace lock files still held by inode."""
    dirs = [shared_state_dir(home), _done_record_dir()]
    return [d for i, d in enumerate(dirs) if d not in dirs[:i]]


def check_clear_of_state(paths: Iterable[tuple[str, Path]], backend: str,
                         home: Path | None = None) -> None:
    """Raise ``SandboxError`` if any ``(what, path)`` is, holds, or sits inside one of the
    :func:`internal_state_dirs` (compared resolved)."""
    protected = [d.resolve() for d in internal_state_dirs(home)]
    for what, p in paths:
        rp = Path(p).expanduser().resolve()
        for area in protected:
            if paths_overlap(rp, area):
                raise SandboxError(f"{backend}: {what} {p} overlaps {area}, the workers' shared "
                                   "lock and cleanup state; use a path outside it")


def _fsync_dir(d: Path) -> None:
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_done_records(parent: Path) -> list[tuple[Path, dict]]:
    """(record file, record) for each done-record whose directory is ``parent`` (resolved)."""
    want = os.path.realpath(parent)
    out: list[tuple[Path, dict]] = []
    d = _done_record_dir()
    with os.scandir(d) as it:
        for e in it:
            if not e.name.endswith(".json"):
                continue
            try:
                with open(os.open(e.path, os.O_RDONLY | os.O_NOFOLLOW), encoding="utf-8") as fh:
                    rec = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(rec, dict) and rec.get("parent") == want:
                out.append((Path(e.path), rec))
    return out


def retire_replaced(old: Path, done: Path, leftovers: "Leftovers | None") -> None:
    """Rename ``old`` (replaced contents, every rename of its swap done) to ``done`` and remove
    it, recording it first so a later worker can tell it apart from a user's own entry of that
    name if this one dies or retires mid-removal (:func:`clear_stale_copy_backs`,
    :func:`clear_recorded_siblings`). Listed in ``leftovers`` meanwhile; the record is dropped
    once it is gone. Raises ``SandboxError`` if it can't be removed (the record then stays).

    Where the tree can't carry the nonce tag (no extended attributes on that filesystem, or the
    entry refuses one), nothing is recorded or renamed: it is removed in place under its
    ``old-`` name, and if that can't finish the name stays -- which a later run refuses over
    rather than deletes (fail closed)."""
    nonce = secrets.token_hex(16)
    try:
        _xattr_set(old, _DONE_XATTR, nonce.encode())
    except OSError:
        if leftovers is not None:
            leftovers.add(old)
        remove_tree(old)
        if os.path.lexists(old):
            raise SandboxError(f"could not remove the replaced contents ({old})") from None
        if leftovers is not None:
            leftovers.discard(old)
        return
    st = os.lstat(old)
    rec = {"parent": os.path.realpath(done.parent), "name": done.name, "from": old.name,
           "dev": st.st_dev, "ino": st.st_ino, "nonce": nonce}
    d = _done_record_dir()
    rec_path = d / f"{os.urandom(8).hex()}.json"
    fd = os.open(rec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(rec).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(d)       # on disk before the rename that makes the name mean "garbage"
    try:
        os.rename(old, done)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(rec_path)
        raise
    if leftovers is not None:
        leftovers.add(done)
    remove_tree(done)
    if os.path.lexists(done):
        raise SandboxError(f"could not remove the replaced contents ({done})")
    if leftovers is not None:
        leftovers.discard(done)
    with contextlib.suppress(OSError):
        os.unlink(rec_path)


def _done_nonce(path: Path) -> "tuple[os.stat_result, bytes] | None":
    """``path``'s identity and the nonce tag it carries (:data:`_DONE_XATTR`), read through one
    no-follow descriptor; None if it is not a directory or regular file, or carries no tag.
    Anything else (a symlink, FIFO, device node) is never opened -- a FIFO would block, a
    device open could act."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            return None             # swapped between the lstat and the open
        try:
            return fst, _xattr_get(fd, _DONE_XATTR)
        except OSError:
            return None
    finally:
        os.close(fd)


def _remove_recorded(path: Path, records: list[tuple[Path, dict]]) -> bool:
    """Remove ``path`` if a record names it -- same name, device, inode AND nonce tag (see
    :data:`_DONE_XATTR`); True if it's gone."""
    if not os.path.lexists(path):
        return True
    tagged = _done_nonce(path)
    if tagged is None:
        return False
    st, tag = tagged
    for rec_path, rec in records:
        nonce = rec.get("nonce")
        if (rec.get("name") == path.name and rec.get("dev") == st.st_dev
                and rec.get("ino") == st.st_ino and isinstance(nonce, str)
                and hmac.compare_digest(tag, nonce.encode())):
            remove_tree(path)
            if os.path.lexists(path):
                return False
            with contextlib.suppress(OSError):
                os.unlink(rec_path)
            return True
    return False


def _prune_records(parent: Path, records: list[tuple[Path, dict]]) -> None:
    """Drop records whose entry is gone under both names (removed by an emergency cleanup, say).
    Only for ``parent``, which the caller holds: a record of a swap still in flight elsewhere
    names an entry that exists under its ``from`` name."""
    for rec_path, rec in records:
        names = [rec.get("name"), rec.get("from")]
        if not any(isinstance(n, str) and os.path.lexists(parent / n) for n in names):
            with contextlib.suppress(OSError):
                os.unlink(rec_path)


def clear_recorded_siblings(dest: Path) -> None:
    """Before a capture replaces ``dest``: remove the recorded ``done-`` siblings an interrupted
    capture swap left beside it. Unrecorded entries are someone else's and are left alone (a
    capture never stages its destination's siblings)."""
    parent = dest.parent
    if not parent.is_dir():
        return
    records = _read_done_records(parent)
    if not records:
        return
    prefix = f".{dest.name}{_COPY_BACK_DONE}"
    with os.scandir(parent) as it:
        found = [Path(e.path) for e in it if e.name.startswith(prefix)]
    for p in found:
        _remove_recorded(p, records)
    _prune_records(parent, _read_done_records(parent))


def clear_stale_copy_backs(source: Path, *,
                           max_entries: int = MAX_SCRATCH_ENTRIES) -> Path | None:
    """Before ``source`` is staged as a writable mount: remove what an interrupted copy-back
    left that is certainly garbage, and return the first leftover that is NOT (or None).

    A worker that exits mid-copy-back (killed, or past its shutdown budget) leaves hidden entries
    in the host tree, which a later run would stage -- an earlier run's bytes in a new job. A
    ``done-`` tree is the replaced contents after every rename finished, and is removed here --
    but only one this worker RECORDED (:func:`retire_replaced`): the same name, device, inode
    and nonce tag (an inode number alone is reused as soon as it is freed).
    A ``done-`` name alone is not proof (the owner or a child may have made it), so an
    unrecorded one is returned like any other leftover (the replacement, or the host's own
    entries moved aside mid-swap) for the caller to refuse the mount over.
    Never follows a symlink; an unreadable directory, or more than ``max_entries`` entries,
    raises ``SandboxError`` (what can't be read can't be shown clean)."""
    candidates: list[Path] = []
    if not stat.S_ISDIR(os.lstat(source).st_mode):
        prefix = f".{source.name}{COPY_BACK_MARK}"
        with os.scandir(source.parent) as it:
            candidates.extend(Path(e.path) for e in it if e.name.startswith(prefix))
    else:
        seen = 0
        stack = [source]
        while stack:
            p = stack.pop()
            try:
                with os.scandir(p) as it:
                    for entry in it:
                        seen += 1
                        if seen > max_entries:
                            raise SandboxError(f"rw mount {source} holds over {max_entries} "
                                               "entries; it can't be checked for leftovers")
                        if COPY_BACK_MARK in entry.name:
                            candidates.append(Path(entry.path))
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
            except OSError as exc:
                raise SandboxError(f"cannot read {p}: {exc}") from exc
    records: dict[Path, list[tuple[Path, dict]]] = {}
    for c in sorted(candidates):
        if c.name.startswith(_COPY_BACK_DONE):
            if c.parent not in records:
                records[c.parent] = _read_done_records(c.parent)
            if _remove_recorded(c, records[c.parent]):
                continue
        return c
    if stat.S_ISDIR(os.lstat(source).st_mode):
        _prune_records(source, _read_done_records(source))
    return None


def find_split_hard_link(roots: Iterable[Path], *,
                         max_entries: int = MAX_SCRATCH_ENTRIES) -> Path | None:
    """A regular file under the writable ``roots`` with a hard-link name OUTSIDE them, or None.

    Counts the names of each multiply-linked file (``(st_dev, st_ino)``, never following a
    symlink) across all the roots; one seen fewer times than its ``st_nlink`` has a name
    elsewhere. Writable through one name and not the other, that splits the mount contract:
    under Seatbelt the child edits a file that is read-only (or unmounted) under its other name,
    and App Sandbox's copy-back replaces the mounted name with a new inode, cutting the host's
    link. Directories are skipped (their link count is their subdirectories). Nested roots are
    walked once. Fails closed: a tree over ``max_entries`` names, or an unreadable directory,
    raises ``SandboxError`` -- what can't be counted can't be shown complete."""
    names: dict[tuple[int, int], int] = {}
    nlink: dict[tuple[int, int], tuple[int, Path]] = {}
    seen = 0
    stack = list(disjoint_roots(roots))
    while stack:
        p = stack.pop()
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SandboxError(f"cannot read {p}: {exc}") from exc
        if stat.S_ISREG(st.st_mode):
            if st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                names[key] = names.get(key, 0) + 1
                nlink.setdefault(key, (st.st_nlink, p))
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        try:
            with os.scandir(p) as it:
                for entry in it:
                    seen += 1
                    if seen > max_entries:
                        raise SandboxError(
                            f"writable mounts hold over {max_entries} entries; their hard links "
                            "can't all be checked")
                    stack.append(Path(entry.path))
        except OSError as exc:
            raise SandboxError(f"cannot read {p}: {exc}") from exc
    for key, (count, path) in nlink.items():
        if names[key] < count:
            return path
    return None


def copy_no_follow(src: Path, dst: Path, *, budget_bytes: int | None = None,
                   budget: CopyBudget | None = None, links: LinkMap | None = None) -> int:
    """Copy ``src`` (file or tree) to ``dst`` without ever following a symlink.

    Regular files and directories are copied with their permission bits; a symlink is recreated
    as a symlink (its target is never opened -- the host trust gate confines artifact paths)
    and charged its target text's length;
    FIFOs, sockets and device nodes are skipped, because opening a FIFO a hostile child left
    behind would block the worker forever. Every entry is charged to ``budget`` (or a fresh one
    of ``budget_bytes``), which raises :class:`SandboxError` once its bytes or entries are
    exceeded, so a child cannot fill the worker's disk through the copy-back. Returns bytes
    copied by this call.

    Hard links WITHIN the copy stay hard links: a later name for an inode already copied is
    linked to that copy, so writes through one name show through the other (as on the host, and
    in a copy-back) and the bytes are charged once -- each name still counts as an entry.
    ``links`` lets several calls that build ONE tree (a seed, a capture) share that map; a
    fresh one per call otherwise, so separate trees (an ro and an rw mount) never share an inode.
    """
    if budget is None:
        if budget_bytes is None:
            raise TypeError("copy_no_follow needs budget_bytes or budget")
        budget = CopyBudget(budget_bytes)
    start = budget.bytes
    seen: LinkMap = {} if links is None else links

    # The SOURCE is walked from pinned descriptors: each directory is opened O_NOFOLLOW and its
    # children are looked up relative to that fd, and a file is opened O_NOFOLLOW and checked
    # (fstat) to be the inode lstat classified. The source can be a tree another run can still
    # write: a directory swapped for a symlink between the lstat and the open is refused, never
    # followed into whatever host tree the link names.
    def _open_checked(name: str | Path, dir_fd: int | None, st: os.stat_result,
                      flags: int, at: Path) -> int:
        try:
            fd = os.open(name, flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                raise SandboxError(f"sandbox copy: {at} changed while it was being copied") from exc
            raise
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) \
                or stat.S_IFMT(fst.st_mode) != stat.S_IFMT(st.st_mode):
            os.close(fd)
            raise SandboxError(f"sandbox copy: {at} changed while it was being copied")
        return fd

    def _one(name: str | Path, dir_fd: int | None, s: Path, d: Path) -> None:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            # Charged its target's length (what lstat reports as its size): a link stores that
            # text, so a tree of long symlinks can't copy back unmetered under a small budget.
            target = os.readlink(name, dir_fd=dir_fd)
            budget.charge(max(len(os.fsencode(target)), st.st_size), s)
            os.symlink(target, d)
        elif stat.S_ISDIR(mode):
            budget.charge(0, s)
            fd = _open_checked(name, dir_fd, st, os.O_RDONLY | os.O_DIRECTORY, s)
            try:
                d.mkdir(mode=0o700)
                _copy_xattrs(fd, d, budget, s, write=True)
                with os.scandir(fd) as it:
                    for entry in it:
                        _one(entry.name, fd, s / entry.name, d / entry.name)
            finally:
                os.close(fd)
            # After the children: a read-only source dir must not block filling its copy.
            os.chmod(d, _perm_bits(mode), follow_symlinks=False)
        elif stat.S_ISREG(mode):
            key = (st.st_dev, st.st_ino) if st.st_nlink > 1 else None
            first = seen.get(key) if key is not None else None
            if first is not None:
                try:
                    # the first copy already has the sanitized mode, no flags and no ACL
                    os.link(first, d, follow_symlinks=False)
                except OSError:
                    first = None        # (another filesystem, say): copy it on its own
                else:
                    budget.charge(0, s)
                    return
            budget.charge(st.st_size, s)
            # O_NONBLOCK: if the entry became a FIFO since the stat, the open must not hang
            # (and the fstat check then refuses it).
            fd = _open_checked(name, dir_fd, st, os.O_RDONLY | os.O_NONBLOCK, s)
            try:
                _copy_regular_fd(fd, d, mode, budget, s)
            finally:
                os.close(fd)
            if key is not None:
                seen.setdefault(key, d)
        else:
            budget.charge(0, s)
            _log.warning("macos sandbox: skipping non-regular file %s (mode %o)", s, mode)

    _one(src, None, src, dst)
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


def paths_overlap(a: Path, b: Path) -> bool:
    """Whether ``a`` and ``b`` (both resolved) are the same path or one contains the other."""
    return a == b or a in b.parents or b in a.parents


def check_homes_clear_of_mounts(seed_home: "Path | str | None", capture_home: "Path | str | None",
                                ro_sources: Iterable["Path | str"],
                                rw_sources: Iterable["Path | str"], backend: str) -> None:
    """Refuse a seed or capture directory that overlaps the request's mounts (compared resolved;
    equal, inside or containing), before anything is copied or launched.

    * A ``seed_home`` overlapping a WRITABLE mount: the child could persist changes into the
      seed every later job starts from -- Seatbelt writes the host tree in place, App Sandbox
      copies the staged mount back over it. (A read-only mount over the seed is harmless.)
    * A ``capture_home`` overlapping ANY mount: the capture replaces that tree with the run's
      cache at teardown, so (part of) a request's input or output source would be swapped for
      the scratch home -- and, for a read-only mount, the child would get to write it after all.
    """
    rw = [Path(p).expanduser().resolve() for p in rw_sources]
    ro = [Path(p).expanduser().resolve() for p in ro_sources]
    if seed_home is not None:
        seed = Path(seed_home).expanduser().resolve()
        for w in rw:
            if paths_overlap(seed, w):
                raise SandboxError(f"{backend}: seed_home {seed_home} overlaps writable mount {w}; "
                                   "the child could change what later runs are seeded from -- "
                                   "use disjoint paths")
    if capture_home is not None:
        cap = Path(capture_home).expanduser().resolve()
        for kind, sources in (("read-only", ro), ("writable", rw)):
            for m in sources:
                if paths_overlap(cap, m):
                    raise SandboxError(f"{backend}: capture_home {capture_home} overlaps {kind} "
                                       f"mount {m}; the capture would replace it with the run's "
                                       "cache -- use disjoint paths")
