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
private ``io/`` dir only, plus the operator's read-only engine paths. A run:

1. locks a free slot (``flock``; concurrency == slot count);
2. **stages** each mount into ``io/`` (APFS clone, never following links) and rewrites argv /
   env tokens naming a mount to its staged path;
3. execs ``launcher <exe> args...`` with the shared lifecycle (timeout, RSS watchdog, rlimits);
4. copies rw mounts back (no-follow, size-capped; FIFOs/devices skipped);
5. wipes ``io/`` AND the slot's container ``Data/`` -- so nothing a job wrote survives into
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
import os
import plistlib
import pwd
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, note_confined_run
from blastbox.worker.sandbox import macos_common as mc

_log = logging.getLogger("blastbox.worker.sandbox.appsandbox")

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1
LAUNCHER_EXE = "bb-launcher"
_APP_SANDBOX = "com.apple.security.app-sandbox"
_RW_EXCEPTION = "com.apple.security.temporary-exception.files.absolute-path.read-write"
_RO_EXCEPTION = "com.apple.security.temporary-exception.files.absolute-path.read-only"
_SIGTRAP_CODES = (133, -5)

#: The launcher. Refuses to exec anything unless the kernel reports it sandboxed, so a slot
#: whose signature was stripped or whose entitlement was lost fails CLOSED (exit 70).
LAUNCHER_C = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int sandbox_check(pid_t pid, const char *operation, int type, ...);
int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/') {
        fprintf(stderr, "bb-launcher: usage: bb-launcher /abs/exe [args...]\n");
        return 64;
    }
    if (sandbox_check(getpid(), NULL, 0) != 1) {
        fprintf(stderr, "bb-launcher: not sandboxed; refusing to exec (re-run prepare)\n");
        return 70;
    }
    execv(argv[1], argv + 1);
    perror("bb-launcher: execv");
    return 71;
}
"""


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
            raise SandboxUnavailable(
                f"appsandbox not prepared: {path} missing (run `blastbox macos prepare`)"
            ) from exc
        except (OSError, ValueError) as exc:
            raise SandboxUnavailable(f"appsandbox manifest unreadable: {path}: {exc}") from exc
        if raw.get("version") != MANIFEST_VERSION:
            raise SandboxUnavailable(
                f"appsandbox manifest version {raw.get('version')!r} != {MANIFEST_VERSION}; "
                "re-run `blastbox macos prepare`"
            )
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
        ent: dict[str, object] = {
            _APP_SANDBOX: True,
            _RW_EXCEPTION: [_dir_entitlement(io_dir.resolve())],
        }
        if resolved_ro:
            ent[_RO_EXCEPTION] = [_dir_entitlement(p) for p in resolved_ro]
        ent_path = slot_dir / "entitlements.plist"
        with open(ent_path, "wb") as fh:
            plistlib.dump(ent, fh)
        _run([codesign, "--force", "--sign", "-", "--options", "runtime",
              "--entitlements", str(ent_path), str(bundle)], runner)
        built.append(Slot(index=i, bundle_id=bundle_id, bundle=bundle,
                          io_dir=io_dir.resolve(), lock_path=root / "locks" / f"{i}.lock"))

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


def verify_slot(
    slot: Slot,
    *,
    codesign: str = "/usr/bin/codesign",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str | None:
    """None if the slot's signature is valid and carries App Sandbox, else why not."""
    if not slot.launcher.is_file():
        return f"slot {slot.index}: launcher missing"
    proc = runner([codesign, "--verify", "--strict", str(slot.bundle)],
                  capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return f"slot {slot.index}: signature invalid ({proc.stderr.strip()})"
    proc = runner([codesign, "-d", "--entitlements", "-", "--xml", str(slot.bundle)],
                  capture_output=True, check=False)
    blob = proc.stdout if isinstance(proc.stdout, bytes) else (proc.stdout or "").encode()
    try:
        ents = plistlib.loads(blob[blob.find(b"<?xml"):]) if b"<?xml" in blob else {}
    except Exception:  # noqa: BLE001 -- any parse failure means "not verified"
        ents = {}
    if ents.get(_APP_SANDBOX) is not True:
        return f"slot {slot.index}: app-sandbox entitlement missing"
    return None


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
        self._slot_wait_s = slot_wait_s if slot_wait_s is not None else float(
            os.environ.get("BLASTBOX_APPSANDBOX_SLOT_WAIT_S", "30") or "30")
        self._insecurity_reasons: list[str] = []
        if verify:
            for slot in self._manifest.slots:
                why = verify_slot(slot, runner=runner)
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
                fd = os.open(slot.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(fd)
                    continue
                try:
                    yield slot
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    os.close(fd)
                return
            if time.monotonic() >= deadline:
                raise SandboxError(
                    f"all {len(self._manifest.slots)} appsandbox slots busy for "
                    f"{self._slot_wait_s:.0f}s (raise `prepare --slots`)"
                )
            time.sleep(0.05)

    def _wipe_slot(self, slot: Slot) -> None:
        """Empty the slot's io/ and container, or retire the slot and raise: a run that left
        undeletable state (a ``uchg`` file, a locked dir) must not hand it to the next run."""
        try:
            for d in (slot.io_dir, slot.container_data(self._home)):
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
        exe, exe_real = mc.resolve_executable(request.argv[0])
        self._check_exec_allowed(exe)
        self._check_exec_allowed(exe_real)

        note_confined_run()
        with self._acquire_slot() as slot:
            self._wipe_slot(slot)
            try:
                return self._run_in_slot(slot, exe, request)
            finally:
                self._wipe_slot(slot)

    def _run_in_slot(self, slot: Slot, exe: Path, request: SandboxRequest) -> SandboxResult:
        io = slot.io_dir
        home = io / "home"
        (home / "tmp").mkdir(parents=True)
        (home / "Library" / "Caches").mkdir(parents=True)
        budget = request.limits.tmpfs_bytes
        # Under App Sandbox the frameworks resolve "home" to the slot's CONTAINER (HOME and
        # CFFIXED_USER_HOME are ignored for caches -- measured: Vision's E5RT cache lands in
        # ~/Library/Containers/<id>/Data/Library/Caches). So that is what seed/capture target.
        # It is wiped before and after every run like io/. Before the slot's first launch the
        # container doesn't exist yet; containermanagerd creates it, so seeding waits until then.
        container = slot.container_data(self._home)
        if request.seed_home is not None and container.is_dir():
            mc.seed_scratch(container, request.seed_home, budget)

        mapping: list[tuple[str, str]] = []
        rw_staged: list[tuple[Path, Path]] = []
        for i, m in enumerate([*request.ro_mounts, *request.rw_mounts]):
            src = Path(m.source).resolve(strict=True)
            staged = io / "m" / str(i) / (src.name or "root")
            staged.parent.mkdir(parents=True)
            mc.copy_no_follow(src, staged, budget_bytes=budget)
            mapping.append((str(m.target), str(staged)))
            if str(Path(m.target)) != str(src):
                mapping.append((str(src), str(staged)))
            if i >= len(request.ro_mounts):
                rw_staged.append((src, staged))

        args = mc.rewrite_path_args(request.argv[1:], mapping)
        extra_env = {k: mc.rewrite_path_args([v], mapping)[0] for k, v in request.env.items()}
        env = mc.build_child_env(home, extra_env)
        argv = [str(slot.launcher), str(exe), *args]
        result = mc.run_confined(
            argv, env=env, limits=request.limits, cwd=home,
            popen=self._popen, rss_fn=self._rss_fn, watch_dirs=[io, container],
        )

        for src, staged in rw_staged:
            self._copy_back(staged, src, budget)
        if result.exit_code == 0 and not result.killed and container.is_dir():
            mc.capture_scratch(container, request.capture_home, budget)

        if result.exit_code in _SIGTRAP_CODES and not result.killed:
            result.stderr += (
                b"\n[blastbox] child died with SIGTRAP under App Sandbox: if the target binary is "
                b"itself signed with an app-sandbox entitlement it must also carry "
                b"com.apple.security.inherit (or be re-signed without entitlements)\n"
            )
        elif result.exit_code == 70:
            result.stderr += b"\n[blastbox] launcher was not sandboxed; slot signature broken\n"
        return result

    @staticmethod
    def _copy_back(staged: Path, dest: Path, budget: int) -> None:
        """Make ``dest`` mirror the staged copy the child left (bind-mount semantics)."""
        if not os.path.lexists(staged):
            return
        if dest.is_dir() and not dest.is_symlink():
            for child in dest.iterdir():
                mc.remove_tree(child)
            used = 0
            if staged.is_dir() and not staged.is_symlink():
                for child in staged.iterdir():
                    used += mc.copy_no_follow(child, dest / child.name,
                                              budget_bytes=budget - used)
        else:
            mc.remove_tree(dest)
            mc.copy_no_follow(staged, dest, budget_bytes=budget)
