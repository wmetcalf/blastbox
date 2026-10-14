"""macOS App Sandbox backend for the blastbox worker SDK.

The Apple-supported alternative to :mod:`~blastbox.worker.sandbox.seatbelt`. Instead of
attaching a generated profile with ``sandbox-exec``, the child is exec'd by a tiny
**launcher** that is ad-hoc code-signed with the ``com.apple.security.app-sandbox``
entitlement. The kernel applies App Sandbox when the launcher starts -- the signature, not a
command line, carries the confinement, so a mis-built argv cannot skip it -- and the launcher
then verifies it is sandboxed (``sandbox_check``) and ``execv``s the real target, which
inherits the sandbox. Any unsigned binary works as a target (a Swift CLI, a venv Python, ...);
nothing is signed per engine.

Free: ad-hoc signing (``codesign -s -``) needs no Apple Developer account, and App Sandbox is
not a restricted entitlement, so no provisioning profile is involved.

**Slots.** Entitlements are fixed at signing time, so per-job paths cannot be granted per run.
``prepare()`` (``blastbox macos prepare``) builds N **slots** up front, each its own bundle id
(=> its own ``~/Library/Containers/<id>``) whose entitlement grants read-write on that slot's
private ``io/`` dir only, read-only on its ``ro/`` staging dir and the operator's engine
paths. A run:

1. locks a free slot (``flock``; concurrency == slot count);
2. **stages** each rw mount into ``io/`` and each ro mount into ``ro/`` (APFS clone, never
   following links) and rewrites argv / env tokens naming a mount to its staged path;
3. execs ``launcher <marker> <nonce> <exe> args...`` with the shared lifecycle (timeout, RSS
   watchdog, rlimits); once sandboxed, the launcher writes the run's nonce to ``<marker>`` in
   ``io/`` -- the proof the run was confined -- and execs the target;
4. copies rw mounts back (no-follow, size-capped; FIFOs/devices skipped);
5. wipes ``io/``, ``ro/`` AND the slot's container ``Data/`` -- so nothing a job wrote survives into
   the next job on that slot.

Versus ``seatbelt``: Apple maintains this profile (it already permits Metal and the Neural
Engine, so ``accelerators`` needs nothing here), but it is a general-purpose *application*
profile that allows far more system services than seatbelt's deny-default per-run profile,
and it costs a staging copy per mount. Hence seatbelt is the auto-selected default and this
backend is an explicit ``BLASTBOX_SANDBOX=appsandbox`` choice.

Constraints (measured, macOS 26):
- A target signed WITH an app-sandbox entitlement but without ``com.apple.security.inherit``
  is killed with SIGTRAP when exec'd from the launcher. Exit 133 / -5 gets an explicit hint.
- ``/usr/bin/python3`` (the xcrun shim) refuses to run under App Sandbox; point at a real
  interpreter and grant its prefix with ``prepare --ro``.
- An exec target outside the system dirs and the prepared ro paths is denied by the kernel
  (``execv: Operation not permitted``); ``run()`` checks first and says which path to add.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import math
import os
import plistlib
import pwd
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, note_confined_run
from blastbox.worker.sandbox import macos_common as mc

_log = logging.getLogger("blastbox.worker.sandbox.appsandbox")

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 2          # 2: the launcher takes <marker> <nonce> before the target
LAUNCHER_EXE = "bb-launcher"
_APP_SANDBOX = "com.apple.security.app-sandbox"
_RW_EXCEPTION = "com.apple.security.temporary-exception.files.absolute-path.read-write"
_RO_EXCEPTION = "com.apple.security.temporary-exception.files.absolute-path.read-only"
_SIGTRAP_CODES = (133, -5)

#: The launcher. Refuses to exec anything unless the kernel reports it sandboxed, so a slot
#: whose signature was stripped or whose entitlement was lost fails CLOSED (exit 70). Once it
#: is sandboxed it writes the run's nonce to the marker (a new file in the slot's io/, never
#: following a link): that handshake, made from inside the sandbox, is what credits the run
#: as confined -- a chain that fails before this point (a missing launcher, an execve error in
#: the rlimit launcher) leaves no marker.
LAUNCHER_C = r"""
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
int sandbox_check(pid_t pid, const char *operation, int type, ...);
int main(int argc, char **argv) {
    if (argc < 4 || argv[1][0] != '/' || argv[3][0] != '/') {
        fprintf(stderr, "bb-launcher: usage: bb-launcher /abs/marker nonce /abs/exe [args...]\n");
        return 64;
    }
    if (sandbox_check(getpid(), NULL, 0) != 1) {
        fprintf(stderr, "bb-launcher: not sandboxed; refusing to exec (re-run prepare)\n");
        return 70;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    size_t n = strlen(argv[2]);
    if (fd < 0 || write(fd, argv[2], n) != (ssize_t)n || close(fd) != 0) {
        perror("bb-launcher: handshake");
        return 72;
    }
    execv(argv[3], argv + 3);
    perror("bb-launcher: execv");
    return 71;
}
"""
HANDSHAKE_NAME = ".bb-handshake"

# A reverse-DNS bundle identifier: dot-separated labels of letters, digits and '-'. The id
# becomes a path component (~/Library/Containers/<id>, the per-id lock file), so a '/', '..'
# or an absolute value must never get through.
_BUNDLE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)*")


def _valid_bundle_id(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 200 and bool(_BUNDLE_ID_RE.fullmatch(value))


def _host_path(argv0: str, mounts: list) -> str:
    """``argv0`` with a mount TARGET prefix replaced by that mount's source (longest target
    first, as path rewriting does); unchanged when no mount covers it."""
    for m in sorted(mounts, key=lambda m: len(str(m.target)), reverse=True):
        target, source = str(Path(m.target)), str(Path(m.source))
        if target == source:
            continue
        if argv0 == target:
            return source
        if argv0.startswith(target.rstrip("/") + "/"):
            return source.rstrip("/") + argv0[len(target.rstrip("/")):]
    return argv0


class AppSandboxNotPrepared(SandboxUnavailable):
    """No manifest at the root: ``blastbox macos prepare`` was never run there."""


def _handshake_ok(marker: Path, nonce: str) -> bool:
    """The marker is a regular file (not followed) holding exactly ``nonce``; it is removed."""
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        got = os.read(fd, 64)
    finally:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(marker)
    return got == nonce.encode()


@dataclass(frozen=True)
class Slot:
    index: int
    bundle_id: str
    bundle: Path
    io_dir: Path
    lock_path: Path

    @property
    def launcher(self) -> Path:
        return self.bundle / "Contents" / "MacOS" / LAUNCHER_EXE

    @property
    def ro_dir(self) -> Path:
        """Where read-only mounts are staged: beside ``io/``, never under it, and granted
        read-only -- so the child cannot rewrite or chmod a mounted input or config mid-run."""
        return self.io_dir.parent / "ro"

    def container_data(self, home: Path) -> Path:
        return home / "Library" / "Containers" / self.bundle_id / "Data"


@dataclass(frozen=True)
class Manifest:
    root: Path
    bundle_prefix: str
    ro_paths: tuple[Path, ...]
    slots: tuple[Slot, ...]

    def to_json(self) -> dict:
        return {
            "version": MANIFEST_VERSION,
            "bundle_prefix": self.bundle_prefix,
            "ro_paths": [str(p) for p in self.ro_paths],
            "slots": [
                {"index": s.index, "bundle_id": s.bundle_id, "bundle": str(s.bundle),
                 "io_dir": str(s.io_dir), "lock_path": str(s.lock_path)}
                for s in self.slots
            ],
        }

    @classmethod
    def load(cls, root: Path) -> Manifest:
        path = root / MANIFEST_NAME
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise AppSandboxNotPrepared(
                f"appsandbox not prepared: {path} missing (run `blastbox macos prepare`)"
            ) from exc
        except (OSError, ValueError) as exc:
            raise SandboxUnavailable(f"appsandbox manifest unreadable: {path}: {exc}") from exc
        if raw.get("version") != MANIFEST_VERSION:
            raise SandboxUnavailable(
                f"appsandbox manifest version {raw.get('version')!r} != {MANIFEST_VERSION}; "
                "re-run `blastbox macos prepare`"
            )
        # Bundle ids are used as paths (container, lock): an edited manifest must not point a
        # wipe outside ~/Library/Containers.
        bad = [v for v in [raw.get("bundle_prefix"), *(s.get("bundle_id") for s in raw["slots"])]
               if not _valid_bundle_id(v)]
        if bad:
            raise SandboxUnavailable(f"appsandbox manifest has invalid bundle ids {bad!r}; "
                                     "re-run `blastbox macos prepare`")
        return cls(
            root=root,
            bundle_prefix=raw["bundle_prefix"],
            ro_paths=tuple(Path(p) for p in raw["ro_paths"]),
            slots=tuple(
                Slot(index=s["index"], bundle_id=s["bundle_id"], bundle=Path(s["bundle"]),
                     io_dir=Path(s["io_dir"]), lock_path=Path(s["lock_path"]))
                for s in raw["slots"]
            ),
        )


def default_root() -> Path:
    """``$BLASTBOX_APPSANDBOX_ROOT``, else ``~/Library/Application Support/blastbox/appsandbox``.

    Per-user on purpose: the slots' containers live in the worker user's
    ``~/Library/Containers``, so the root belongs to that same user.
    """
    env = os.environ.get("BLASTBOX_APPSANDBOX_ROOT", "")
    if env:
        return Path(env)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    return home / "Library" / "Application Support" / "blastbox" / "appsandbox"


def _dir_entitlement(p: Path) -> str:
    # A trailing slash makes the exception cover the whole subtree; without it, a file.
    return str(p).rstrip("/") + "/" if p.is_dir() else str(p)


def _run(argv: list[str], runner: Callable[..., subprocess.CompletedProcess]) -> str:
    proc = runner(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SandboxError(f"{argv[0]} failed (rc={proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def prepare(
    root: Path,
    *,
    slots: int,
    ro_paths: list[Path],
    bundle_prefix: str | None = None,
    cc: str = "/usr/bin/clang",
    codesign: str = "/usr/bin/codesign",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> Manifest:
    """Build (or rebuild) the slot bundles under ``root`` and write the manifest.

    Idempotent: every slot is rebuilt and re-signed, so changing ``ro_paths`` or the slot
    count is just a re-run. Needs the Xcode Command Line Tools (``clang``, ``codesign``).
    """
    if not 1 <= slots <= 256:
        raise SandboxError("slots must be between 1 and 256")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = root.resolve()
    os.chmod(root, 0o700)
    resolved_ro: list[Path] = []
    for p in ro_paths:
        rp = Path(p).expanduser().resolve(strict=True)
        if rp == root or root in rp.parents or rp in root.parents:
            raise SandboxError(f"--ro {rp} overlaps the appsandbox root {root}")
        resolved_ro.append(rp)
    prefix = bundle_prefix or "io.blastbox.sbx." + hashlib.sha256(
        str(root).encode()).hexdigest()[:10]
    if not _valid_bundle_id(prefix):
        raise SandboxError(f"invalid bundle prefix {prefix!r}: use reverse-DNS labels of "
                           "letters, digits and '-' (e.g. io.example.sbx)")
    # Every generated id (the longest is the last slot's) must pass the check Manifest.load()
    # applies, or prepare would sign slots its own manifest then refuses.
    if not _valid_bundle_id(f"{prefix}.slot{slots - 1}"):
        raise SandboxError(f"bundle prefix {prefix!r} is too long: {prefix}.slot{slots - 1} "
                           "exceeds the 200-character bundle id limit")

    build = root / "build"
    build.mkdir(exist_ok=True)
    (build / "launcher.c").write_text(LAUNCHER_C)
    _run([cc, "-O2", "-Wall", "-o", str(build / LAUNCHER_EXE), str(build / "launcher.c")], runner)
    launcher_bytes = (build / LAUNCHER_EXE).read_bytes()

    (root / "locks").mkdir(exist_ok=True, mode=0o700)
    built: list[Slot] = []
    for i in range(slots):
        slot_dir = root / "slots" / str(i)
        io_dir = slot_dir / "io"
        io_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (slot_dir / "ro").mkdir(exist_ok=True, mode=0o700)
        bundle = slot_dir / f"bb-slot-{i}.app"
        mc.remove_tree(bundle)
        # A fresh prepare is the operator's "I inspected it": clear any retirement.
        (root / "locks" / f"{i}.lock.retired").unlink(missing_ok=True)
        macos = bundle / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        exe = macos / LAUNCHER_EXE
        exe.write_bytes(launcher_bytes)
        os.chmod(exe, 0o755)
        bundle_id = f"{prefix}.slot{i}"
        with open(bundle / "Contents" / "Info.plist", "wb") as fh:
            plistlib.dump({
                "CFBundleIdentifier": bundle_id,
                "CFBundleExecutable": LAUNCHER_EXE,
                "CFBundlePackageType": "APPL",
                "CFBundleName": f"blastbox slot {i}",
                "LSUIElement": True,
            }, fh)
        slot = Slot(index=i, bundle_id=bundle_id, bundle=bundle, io_dir=io_dir.resolve(),
                    lock_path=root / "locks" / f"{i}.lock")
        ent = expected_entitlements(slot, resolved_ro)
        ent_path = slot_dir / "entitlements.plist"
        with open(ent_path, "wb") as fh:
            plistlib.dump(ent, fh)
        _run([codesign, "--force", "--sign", "-", "--options", "runtime",
              "--entitlements", str(ent_path), str(bundle)], runner)
        built.append(slot)

    # Drop slots beyond the new count so a shrink cannot leave stale signed launchers around.
    slots_root = root / "slots"
    for child in slots_root.iterdir():
        if child.name.isdigit() and int(child.name) >= slots:
            mc.remove_tree(child)

    manifest = Manifest(root=root, bundle_prefix=prefix, ro_paths=tuple(resolved_ro),
                        slots=tuple(built))
    tmp = root / (MANIFEST_NAME + ".tmp")
    tmp.write_text(json.dumps(manifest.to_json(), indent=2) + "\n")
    os.replace(tmp, root / MANIFEST_NAME)
    return manifest


def expected_entitlements(slot: Slot, ro_paths: tuple[Path, ...] | list[Path]) -> dict[str, object]:
    """Exactly what :func:`prepare` signs into ``slot``: App Sandbox, read-write on the slot's
    own ``io/``, read-only on its ``ro/`` staging dir and the manifest's paths -- nothing else.
    (Slots prepared before ``ro/`` existed fail :func:`verify_slot`; re-run prepare.)"""
    return {
        _APP_SANDBOX: True,
        _RW_EXCEPTION: [str(slot.io_dir).rstrip("/") + "/"],
        _RO_EXCEPTION: [str(slot.ro_dir).rstrip("/") + "/",
                        *(_dir_entitlement(Path(p)) for p in ro_paths)],
    }


def _codesign_text(proc: subprocess.CompletedProcess) -> str:
    out = []
    for stream in (proc.stdout, proc.stderr):
        out.append(stream.decode(errors="replace") if isinstance(stream, bytes) else (stream or ""))
    return "\n".join(out)


def verify_slot(
    slot: Slot,
    *,
    ro_paths: tuple[Path, ...] | list[Path] | None = None,
    codesign: str = "/usr/bin/codesign",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str | None:
    """None if the slot's signature is valid, names the slot's bundle id, and carries exactly
    the entitlements :func:`prepare` grants it (``ro_paths``: the manifest's), else why not.

    A launcher re-signed or copied with other grants -- a broader path, another slot's ``io/``,
    a network entitlement -- would run hostile parsers with permissions that match neither the
    manifest nor the slot's lock/container identity, so any difference fails the check."""
    if not slot.launcher.is_file():
        return f"slot {slot.index}: launcher missing"
    proc = runner([codesign, "--verify", "--strict", str(slot.bundle)],
                  capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return f"slot {slot.index}: signature invalid ({proc.stderr.strip()})"
    proc = runner([codesign, "-d", "-v", str(slot.bundle)], capture_output=True, text=True,
                  check=False)
    ident = next((ln.split("=", 1)[1].strip() for ln in _codesign_text(proc).splitlines()
                  if ln.startswith("Identifier=")), None)
    if ident != slot.bundle_id:
        return f"slot {slot.index}: signed as {ident!r}, expected {slot.bundle_id!r}"
    proc = runner([codesign, "-d", "--entitlements", "-", "--xml", str(slot.bundle)],
                  capture_output=True, check=False)
    blob = proc.stdout if isinstance(proc.stdout, bytes) else (proc.stdout or "").encode()
    try:
        ents = plistlib.loads(blob[blob.find(b"<?xml"):]) if b"<?xml" in blob else {}
    except Exception:  # noqa: BLE001 -- any parse failure means "not verified"
        ents = {}
    if ents.get(_APP_SANDBOX) is not True:
        return f"slot {slot.index}: app-sandbox entitlement missing"
    want = expected_entitlements(slot, tuple(ro_paths or ()))
    if ents != want:
        extra = sorted(set(ents) - set(want))
        changed = sorted(k for k in want if ents.get(k) != want[k])
        return (f"slot {slot.index}: entitlements differ from the manifest "
                f"(unexpected: {extra}, mismatched: {changed})")
    return None


def _slot_wait(value: float | None) -> float:
    """``slot_wait_s``, else ``$BLASTBOX_APPSANDBOX_SLOT_WAIT_S`` (default 30): finite and >= 0,
    or the backend refuses to start (a NaN deadline never expires, so a busy slot would hang
    the job until the agent's hard deadline)."""
    raw: object = value
    if raw is None:
        raw = os.environ.get("BLASTBOX_APPSANDBOX_SLOT_WAIT_S", "") or "30"
    try:
        wait = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise SandboxUnavailable(f"appsandbox slot wait {raw!r} is not a number") from exc
    if not math.isfinite(wait) or wait < 0:
        raise SandboxUnavailable(f"appsandbox slot wait {raw!r} must be finite and >= 0")
    return wait


class AppSandboxSandbox:
    """:class:`~blastbox.worker.sandbox.base.Sandbox` backed by signed App Sandbox launchers."""

    name = "appsandbox"

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        rss_fn: Callable[[int], int] | None = None,
        home: Path | None = None,
        slot_wait_s: float | None = None,
        platform_ok: bool = mc.IS_DARWIN,
        verify: bool = True,
    ) -> None:
        if not platform_ok:
            raise SandboxUnavailable("appsandbox is macOS-only")
        self._manifest = Manifest.load(Path(root) if root is not None else default_root())
        if not self._manifest.slots:
            raise SandboxUnavailable("appsandbox manifest has no slots")
        self._popen = popen
        self._rss_fn = rss_fn
        self._home = home or Path(pwd.getpwuid(os.getuid()).pw_dir)
        self._slot_wait_s = _slot_wait(slot_wait_s)
        if mc.IS_DARWIN and not mc.process_apis_available():
            # Without them a run's escaped processes can't be found, so a slot can't be proven
            # empty before reuse.
            raise SandboxUnavailable("appsandbox: libSystem process APIs unavailable")
        self._insecurity_reasons: list[str] = []
        if verify:
            for slot in self._manifest.slots:
                why = verify_slot(slot, ro_paths=self._manifest.ro_paths, runner=runner)
                if why:
                    raise SandboxUnavailable(f"appsandbox {why}; re-run `blastbox macos prepare`")

    @property
    def secure(self) -> bool:
        return not self._insecurity_reasons

    @property
    def insecurity_reasons(self) -> list[str]:
        return list(self._insecurity_reasons)

    @property
    def manifest(self) -> Manifest:
        return self._manifest

    # ------------------------------------------------------------------
    @staticmethod
    def retired_marker(slot: Slot) -> Path:
        """Present when a slot could not be proven clean; `blastbox macos prepare` clears it."""
        return slot.lock_path.with_name(slot.lock_path.name + ".retired")

    @contextlib.contextmanager
    def _acquire_slot(self) -> Iterator[Slot]:
        deadline = time.monotonic() + self._slot_wait_s
        while True:
            usable = [s for s in self._manifest.slots if not self.retired_marker(s).exists()]
            if not usable:
                raise SandboxError(
                    "every appsandbox slot is retired (a run left state that could not be "
                    "removed); inspect them, then re-run `blastbox macos prepare`")
            for slot in usable:
                fd = self._try_lock(slot.lock_path)
                if fd is None:
                    continue
                # The container is keyed by bundle id, not by root: two roots prepared with the
                # same --bundle-prefix share ~/Library/Containers/<id>. A per-user lock on the id,
                # held for the run and both wipes, keeps them from running in (and wiping) one
                # container at once.
                bfd = self._try_lock(self.bundle_lock_path(slot))
                if bfd is None:
                    self._unlock(fd)
                    continue
                try:
                    yield slot
                finally:
                    self._unlock(bfd)
                    self._unlock(fd)
                return
            if time.monotonic() >= deadline:
                raise SandboxError(
                    f"all {len(self._manifest.slots)} appsandbox slots busy for "
                    f"{self._slot_wait_s:.0f}s (raise `prepare --slots`)"
                )
            time.sleep(0.05)

    def _sweep_slot(self, slot: Slot) -> None:
        """Kill every process still in the slot's container -- including a forked, setsid()'d
        orphan that left the run's process family -- before the slot is wiped or reused."""
        mc.sweep_container(slot.container_data(self._home))

    def bundle_lock_path(self, slot: Slot) -> Path:
        """Per-user lock for ``slot``'s bundle id (and so its container), shared by every root."""
        d = self._home / "Library" / "Caches" / "blastbox" / "appsandbox-locks"
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        return d / f"{slot.bundle_id}.lock"

    @staticmethod
    def _try_lock(path: Path) -> int | None:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd

    @staticmethod
    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    def _wipe_slot(self, slot: Slot) -> None:
        """Kill what is left in the slot, then empty its io/ and container, or retire the slot
        and raise: a run that left a process or undeletable state (a ``uchg`` file, a locked dir,
        a container swapped for a symlink) must not hand it to the next run."""
        try:
            self._sweep_slot(slot)
            container = slot.container_data(self._home)
            parent = container.parent
            if os.path.lexists(parent) and os.path.islink(parent):
                raise SandboxError(f"refusing to wipe {container}: {parent} is a symlink")
            for d in (slot.io_dir, slot.ro_dir, container):
                mc.wipe_dir(d)
        except SandboxError as exc:
            self.retired_marker(slot).write_text(f"{exc}\n")
            _log.error("appsandbox: retired slot %s: %s", slot.bundle_id, exc)
            raise

    def _check_exec_allowed(self, exe: Path) -> None:
        roots = [Path(d) for d in mc.SYSTEM_EXEC_DIRS] + list(self._manifest.ro_paths)
        if not mc.is_under(exe, roots):
            raise SandboxError(
                f"{exe} is outside the paths this appsandbox was prepared with; "
                f"re-run `blastbox macos prepare --ro {exe.parent}` (or a parent dir)"
            )

    def run(self, request: SandboxRequest) -> SandboxResult:
        if not isinstance(request.argv, list) or not request.argv:
            raise SandboxError("argv must be a non-empty list of strings")
        if request.limits.net_egress:
            _log.warning("appsandbox: net_egress requested; network stays DENIED (fail-closed)")
        # argv[0] may name a mount TARGET (source /opt/engine at /engine, exe /engine/bin/x),
        # which need not exist on the host: resolve and check the mounted source it stands for,
        # and exec that -- the prepared ro paths, not the staged copy, are what may be exec'd.
        exe, exe_real = mc.resolve_executable(
            _host_path(request.argv[0], [*request.ro_mounts, *request.rw_mounts]))
        self._check_exec_allowed(exe)
        self._check_exec_allowed(exe_real)

        with self._acquire_slot() as slot:
            self._wipe_slot(slot)
            try:
                result, confined = self._run_in_slot(slot, exe, request)
            finally:
                self._wipe_slot(slot)
        # Credited only once the final sweep and wipe have succeeded: a run whose cleanup
        # raised is a failed run, and an engine falling back to an in-process parse after it
        # must not pass that parse off as confined.
        if confined:
            note_confined_run()
        return result

    def _run_in_slot(self, slot: Slot, exe: Path,
                     request: SandboxRequest) -> tuple[SandboxResult, bool]:
        """The run and whether it may be credited as confined (the caller credits it once the
        slot is clean)."""
        # Every staging and copy-back copy of the run draws on ONE budget (bytes and entries):
        # the run-wide limit holds before the watchdog starts, however many mounts there are.
        io = slot.io_dir
        home = io / "home"
        (home / "tmp").mkdir(parents=True)
        (home / "Library" / "Caches").mkdir(parents=True)
        budget = request.limits.tmpfs_bytes
        # Under App Sandbox the frameworks resolve "home" to the slot's CONTAINER (HOME and
        # CFFIXED_USER_HOME are ignored for caches -- measured: Vision's E5RT cache lands in
        # ~/Library/Containers/<id>/Data/Library/Caches). So that is what seed/capture target.
        # It is wiped before and after every run like io/. Before the slot's first launch the
        # container doesn't exist yet (containermanagerd creates it at launch), so a seeded run
        # on a fresh slot first primes it with a no-op launch -- the seed is never dropped.
        container = slot.container_data(self._home)
        # ONE pre-launch budget for the seed AND every staged mount: nothing is metered by the
        # watchdog until the child starts, so together they must stay within the run's limit.
        staging = mc.CopyBudget(budget)
        if request.seed_home is not None:
            if not container.is_dir():
                self._prime_container(slot, home)
            mc.seed_scratch(container, request.seed_home, budget=staging)

        mapping: list[tuple[str, str]] = []
        rw_staged: list[tuple[Path, Path, bool]] = []
        for i, m in enumerate([*request.ro_mounts, *request.rw_mounts]):
            src = Path(m.source).resolve(strict=True)
            # Read-only mounts go under ro/ (granted read-only), writable ones under io/.
            base = slot.ro_dir if i < len(request.ro_mounts) else io
            staged = base / "m" / str(i) / (src.name or "root")
            staged.parent.mkdir(parents=True)
            mc.copy_no_follow(src, staged, budget=staging)
            mapping.append((str(m.target), str(staged)))
            if str(Path(m.target)) != str(src):
                mapping.append((str(src), str(staged)))
            if i >= len(request.ro_mounts):
                rw_staged.append((src, staged, stat.S_ISDIR(os.lstat(src).st_mode)))

        args = mc.rewrite_path_args(request.argv[1:], mapping)
        extra_env = {k: mc.rewrite_path_args([v], mapping)[0] for k, v in request.env.items()}
        env = mc.build_child_env(home, extra_env)
        nonce = secrets.token_hex(16)
        marker = io / HANDSHAKE_NAME
        argv = [str(slot.launcher), str(marker), nonce, str(exe), *args]
        result = mc.run_confined(
            argv, env=env, limits=request.limits, cwd=home,
            popen=self._popen, rss_fn=self._rss_fn, watch_dirs=[io, container],
            sweep=lambda: self._sweep_slot(slot),
            member_fn=mc.container_matcher(container),
        )
        # The handshake the launcher writes once it is sandboxed proves the chain reached the
        # sandbox; read (and remove) it now, credit it only at the end.
        handshake = _handshake_ok(marker, nonce)

        copy_back = mc.CopyBudget(budget)
        # Parent-first, so a nested rw mount's result lands over its parent's stale snapshot of
        # that subtree, whatever order the request listed them in.
        for src, staged, was_dir in sorted(rw_staged, key=lambda t: len(t[0].parts)):
            self._copy_back(staged, src, copy_back, was_dir)
        ok = result.exit_code == 0 and not result.killed
        if ok and request.capture_home is not None and os.path.lexists(container):
            # The child owns its container and may have swapped Data/ for a symlink to a host
            # dir: never follow it into a capture.
            if not stat.S_ISDIR(os.lstat(container).st_mode):
                raise SandboxError(f"appsandbox: refusing to capture {container}: "
                                   "it is no longer a real directory")
            mc.capture_scratch(container, request.capture_home, budget)

        # Creditable only for a run that reached the sandbox AND completed: an engine that falls
        # back to parsing in-process after a failed or killed sandboxed run (or a copy-back that
        # raised) must not pass that parse off as confined.
        if not handshake:
            _log.warning("appsandbox: no handshake from the sandboxed launcher; run not counted "
                         "as confined (exit %s)", result.exit_code)

        if result.exit_code in _SIGTRAP_CODES and not result.killed:
            result.stderr += (
                b"\n[blastbox] child died with SIGTRAP under App Sandbox: if the target binary is "
                b"itself signed with an app-sandbox entitlement it must also carry "
                b"com.apple.security.inherit (or be re-signed without entitlements)\n"
            )
        elif result.exit_code == 70:
            result.stderr += b"\n[blastbox] launcher was not sandboxed; slot signature broken\n"
        return result, handshake and ok

    def _prime_container(self, slot: Slot, home: Path) -> None:
        """Launch the slot once with ``/usr/bin/true`` so its container exists, or raise."""
        container = slot.container_data(self._home)
        marker = slot.io_dir / HANDSHAKE_NAME
        mc.run_confined([str(slot.launcher), str(marker), secrets.token_hex(16), "/usr/bin/true"],
                        env=mc.build_child_env(home, {}), limits=Limits(timeout_s=30),
                        cwd=home, popen=self._popen)
        if not container.is_dir():
            raise SandboxError(
                f"appsandbox slot {slot.index}: container {container} was not created by a "
                "priming launch, so seed_home cannot be applied; check the slot signature")
        mc.remove_tree(marker)
        mc.wipe_dir(container)

    @staticmethod
    def _swap_children(dest: Path, new: Path, old: Path) -> None:
        """Replace ``dest``'s children with ``new``'s: old ones aside into ``old``, new ones in,
        then drop ``old``. A failed rename undoes every move made so far (best effort, logged)
        and re-raises, so ``dest`` ends up as it was rather than part-swapped."""
        os.mkdir(old, 0o700)
        moved_out: list[str] = []
        moved_in: list[str] = []
        try:
            for child in list(dest.iterdir()):
                if child not in (new, old):
                    os.rename(child, old / child.name)
                    moved_out.append(child.name)
            for child in list(new.iterdir()):
                os.rename(child, dest / child.name)
                moved_in.append(child.name)
        except BaseException:
            for name, src, dst in [*((n, dest, new) for n in reversed(moved_in)),
                                   *((n, old, dest) for n in reversed(moved_out))]:
                try:
                    os.rename(src / name, dst / name)
                except OSError as exc:
                    _log.error("appsandbox: could not undo copy-back move of %s: %s",
                               src / name, exc)
            mc.remove_tree(new)
            with contextlib.suppress(OSError):
                os.rmdir(old)
            raise
        os.rmdir(new)
        mc.remove_tree(old)
        if os.path.lexists(old):
            raise SandboxError(f"appsandbox: copy-back of {dest} could not remove the replaced "
                               f"contents ({old})")

    @staticmethod
    def _copy_back(staged: Path, dest: Path, budget: mc.CopyBudget, was_dir: bool) -> None:
        """Make ``dest`` mirror the staged copy the child left (bind-mount semantics).

        The staged ROOT must still be what was mounted -- a real directory for a directory
        mount, a regular file for a file mount. Its staging parent is writable, so the child can
        replace it (with a symlink, say), which a real bind mount does not allow: that would
        empty the host directory, or plant an attacker-chosen symlink at the host path. So the
        root is checked before ``dest`` is touched, and a changed type fails the run.

        The replacement is built first, beside the original (a hidden entry inside a directory
        mount, so the directory itself is kept as a bind mount would; a sibling for a file
        mount), and only swapped in by rename once it is complete: a copy-back that fails
        partway (budget, disk) leaves ``dest`` as it was, never half-written. For a directory the
        swap moves the old children aside and the new ones in, undoing every move if a rename
        fails; a host entry that can't be moved or removed (``uchg``/append-only flags, a
        non-writable directory -- the operator's, so never cleared) fails the run before anything
        is touched, rather than leaving the host directory part-erased.

        A staged root that is GONE fails too: a mounted root cannot be removed from inside a
        bind mount, and silently keeping the host's stale contents would report the run's
        output as written when it was not."""
        try:
            st = os.lstat(staged)
        except FileNotFoundError as exc:
            raise SandboxError(f"appsandbox: rw mount {dest} was deleted inside the sandbox; "
                               "not copied back") from exc
        same_type = stat.S_ISDIR(st.st_mode) if was_dir else stat.S_ISREG(st.st_mode)
        if not same_type:
            raise SandboxError(
                f"appsandbox: rw mount {dest} was replaced inside the sandbox (expected a "
                f"{'directory' if was_dir else 'regular file'}); not copied back")
        if was_dir:
            if not stat.S_ISDIR(os.lstat(dest).st_mode):
                raise SandboxError(f"appsandbox: rw mount {dest} is no longer a directory")
            locked = mc.locked_entry(dest)
            if locked is not None:
                raise SandboxError(f"appsandbox: rw mount {dest} holds {locked}, which can't be "
                                   "replaced (immutable/append-only or not writable); not copied back")
            tag = secrets.token_hex(8)
            new = dest / f".blastbox-copyback-{tag}"
            old = dest / f".blastbox-copyback-old-{tag}"
            try:
                mc.copy_no_follow(staged, new, budget=budget)
            except BaseException:
                mc.remove_tree(new)
                raise
            AppSandboxSandbox._swap_children(dest, new, old)
        else:
            locked = mc.locked_file_target(dest)
            if locked is not None:
                raise SandboxError(f"appsandbox: rw mount {dest} can't be replaced ({locked}); "
                                   "not copied back")
            new = dest.with_name(f".{dest.name}.blastbox-copyback-{secrets.token_hex(8)}")
            try:
                mc.copy_no_follow(staged, new, budget=budget)
                os.replace(new, dest)
            except BaseException:
                # Copy or swap failed: the sibling holds untrusted bytes outside every wipe and
                # watchdog path, so it never outlives the attempt.
                mc.remove_tree(new)
                raise
