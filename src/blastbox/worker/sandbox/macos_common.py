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

import ctypes
import ctypes.util
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


def build_child_env(scratch: Path, extra: Mapping[str, str]) -> dict[str, str]:
    """A from-scratch env: minimal PATH, scratch HOME/TMPDIR, plus the request's additions.

    ``os.environ`` is never inherited. A request env key that would re-point the scratch
    (HOME, TMPDIR, ...) is dropped with a warning rather than honoured.
    """
    env: dict[str, str] = {}
    for key, val in extra.items():
        if key in _RESERVED_ENV:
            _log.warning("macos sandbox: ignoring reserved env key %s from the request", key)
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


def remove_tree(path: Path) -> None:
    """Best-effort recursive delete that never follows a symlink out of ``path``."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path, ignore_errors=True)
    except OSError as exc:
        _log.warning("macos sandbox: could not remove %s: %s", path, exc)


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
    """Sum RSS (bytes) of every live process in group ``pgid``; 0 when unknown."""
    try:
        out = ps_runner(
            ["/bin/ps", "-A", "-o", "pgid=,rss="],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    total_kib = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == str(pgid) and parts[1].isdigit():
            total_kib += int(parts[1])
    return total_kib * 1024


class RssWatchdog:
    """Poll a sandbox's process-group RSS and SIGKILL the group over ``limit_bytes``.

    Darwin's stand-in for ``RLIMIT_AS`` / a cgroup memory cap. Polling means a burst between
    samples can overshoot; it bounds a runaway decoder, it is not a hard ceiling.
    """

    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        limit_bytes: int,
        *,
        interval_s: float = 0.5,
        rss_fn: Callable[[int], int] = group_rss_bytes,
    ) -> None:
        self._proc = proc
        self._limit = limit_bytes
        self._interval = interval_s
        self._rss_fn = rss_fn
        self._stop = threading.Event()
        self.tripped = False
        self.peak_bytes = 0
        self._thread = threading.Thread(target=self._loop, name="bb-rss-watchdog", daemon=True)

    def __enter__(self) -> RssWatchdog:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        try:
            pgid = os.getpgid(self._proc.pid)
        except (ProcessLookupError, OSError):
            return
        if pgid == os.getpgid(0):
            return  # never measure (or kill) the worker's own group
        while not self._stop.wait(self._interval):
            if self._proc.poll() is not None:
                return
            rss = self._rss_fn(pgid)
            self.peak_bytes = max(self.peak_bytes, rss)
            if rss > self._limit:
                self.tripped = True
                _log.warning(
                    "macos sandbox: RSS %d > limit %d; killing process group %d",
                    rss, self._limit, pgid,
                )
                kill_sandbox_group(self._proc)
                return


def run_confined(
    argv: list[str],
    *,
    env: Mapping[str, str],
    limits: Limits,
    cwd: Path,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    rss_fn: Callable[[int], int] = group_rss_bytes,
) -> SandboxResult:
    """Launch an already-confining ``argv`` with the shared lifecycle.

    New session (so the timeout/RSS kill hits only the sandbox's group), stdin closed, every
    inherited fd closed, rlimits in the child, wall-clock timeout, RSS watchdog.
    """
    try:
        proc = popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=dict(env),
            cwd=str(cwd),
            preexec_fn=make_apply_rlimits(limits),
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError) as exc:
        raise SandboxError(f"failed to start sandboxed child: {exc}") from exc

    killed = False
    with RssWatchdog(proc, limits.memory_bytes, rss_fn=rss_fn) as dog:
        try:
            stdout, stderr = proc.communicate(timeout=limits.timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            killed = True
            kill_sandbox_group(proc)
            try:
                stdout, stderr = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
            exit_code = -int(signal.SIGKILL)
    if dog.tripped:
        killed = True
        stderr = (stderr or b"") + (
            f"\n[blastbox] killed: process-group RSS exceeded "
            f"{limits.memory_bytes} bytes\n".encode()
        )
    return SandboxResult(
        exit_code=exit_code, stdout=stdout or b"", stderr=stderr or b"", killed=killed,
    )


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


def _copy_regular(src: Path, dst: Path) -> None:
    """APFS clone when possible (O(1), copy-on-write), else a byte copy. Never follows links."""
    if _CLONEFILE is not None:
        if _CLONEFILE(os.fsencode(src), os.fsencode(dst), _CLONE_NOFOLLOW) == 0:
            return
    with open(src, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fin, \
            open(dst, "xb") as fout:
        shutil.copyfileobj(fin, fout, 1024 * 1024)


def copy_no_follow(src: Path, dst: Path, *, budget_bytes: int) -> int:
    """Copy ``src`` (file or tree) to ``dst`` without ever following a symlink.

    Regular files and directories are copied; a symlink is recreated as a symlink (its target
    is never opened -- the host trust gate confines artifact paths); FIFOs, sockets and device
    nodes are skipped, because opening a FIFO a hostile child left behind would block the
    worker forever. Raises :class:`SandboxError` once more than ``budget_bytes`` would be
    copied, so a child cannot fill the worker's disk through the copy-back. Returns bytes copied.
    """
    copied = 0

    def _one(s: Path, d: Path) -> None:
        nonlocal copied
        st = os.lstat(s)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            os.symlink(os.readlink(s), d)
        elif stat.S_ISDIR(mode):
            d.mkdir(mode=0o700)
            with os.scandir(s) as it:
                for entry in it:
                    _one(Path(entry.path), d / entry.name)
        elif stat.S_ISREG(mode):
            copied += st.st_size
            if copied > budget_bytes:
                raise SandboxError(
                    f"sandbox copy exceeds budget of {budget_bytes} bytes at {s}"
                )
            _copy_regular(s, d)
        else:
            _log.warning("macos sandbox: skipping non-regular file %s (mode %o)", s, mode)

    _one(src, dst)
    return copied


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
