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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import (
    SandboxRequest,
    SandboxResult,
    current_ledger,
    note_confined_run,
    register_emergency_cleanup,
    teardown_critical,
    unregister_emergency_cleanup,
)
from blastbox.worker.sandbox import macos_common as mc

_log = logging.getLogger("blastbox.worker.sandbox.appsandbox")

MANIFEST_NAME = "manifest.json"
# Held by `prepare` for its whole run (locks/<this>); agents take only the per-slot locks.
PREPARE_LOCK = "prepare.lock"
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
    #: A fresh token per `prepare`, so every re-prepare changes the file a live instance
    #: compares against (see AppSandboxSandbox._check_manifest_current).
    generation: str = ""
    #: sha256 of the manifest file this was loaded from ("" when built in memory).
    digest: str = field(default="", compare=False)

    def to_json(self) -> dict:
        return {
            "version": MANIFEST_VERSION,
            "generation": self.generation,
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
            data = path.read_bytes()
            raw = json.loads(data)
        except FileNotFoundError as exc:
            raise AppSandboxNotPrepared(
                f"appsandbox not prepared: {path} missing (run `blastbox macos prepare`)"
            ) from exc
        except (OSError, ValueError) as exc:
            raise SandboxUnavailable(f"appsandbox manifest unreadable: {path}: {exc}") from exc
        return replace(_parse_manifest(raw, root, path), digest=hashlib.sha256(data).hexdigest())


def _check_mapping(mapping: list[tuple[str, str]]) -> None:
    """Refuse a request where one path would be rewritten to two different staged copies: two
    mounts at the same target, or a target equal to another mount's source (which is also
    rewritten). ``rewrite_path_args`` would silently pick one -- here the read-only copy, where
    Linux's later bind mount would expose the writable one -- so an ambiguous request fails
    instead of guessing. (Aliases of one writable tree map to the same copy and are fine.)"""
    claimed: dict[str, str] = {}
    for key, staged in mapping:
        norm = os.path.normpath(key)
        prior = claimed.setdefault(norm, staged)
        if prior != staged:
            raise SandboxError(
                f"appsandbox: {norm} names two different mounts (same target, or one mount's "
                "target is another's source); give each mount a distinct target")
    # A path nested under another mapped path must be staged at the same place inside that
    # one's copy (an alias of a writable tree is). Otherwise -- /mnt from X and /mnt/sub from Y
    # -- an argument naming /mnt/sub reaches Y but one that builds it from /mnt reaches X/sub,
    # where a nested bind mount would always show Y: refused rather than path-dependent.
    keys = sorted(claimed, key=lambda k: len(Path(k).parts))
    for i, outer in enumerate(keys):
        for inner in keys[i + 1:]:
            if not Path(inner).is_relative_to(outer) or inner == outer:
                continue
            want = os.path.normpath(Path(claimed[outer]) / Path(inner).relative_to(outer))
            if os.path.normpath(claimed[inner]) != want:
                raise SandboxError(
                    f"appsandbox: mount path {inner} is nested under {outer} but is a "
                    "different mount; App Sandbox stages copies and cannot overlay one inside "
                    "another -- use targets that don't contain each other")


def _check_ro_rw_disjoint(request: SandboxRequest) -> None:
    """Refuse a read-only mount whose source equals, lies inside, or contains a writable
    mount's source. Staged as separate copies, such views diverge -- a write through the
    writable one is invisible through the read-only one, where bind mounts share the inode --
    and staging the read-only view inside the writable copy would make it writable. Refused
    before anything is staged."""
    rw = [Path(m.source).resolve(strict=True) for m in request.rw_mounts]
    for m in request.ro_mounts:
        ro = Path(m.source).resolve(strict=True)
        for w in rw:
            if ro == w or ro.is_relative_to(w) or w.is_relative_to(ro):
                raise SandboxError(
                    f"appsandbox: read-only mount {ro} overlaps writable mount {w}; App Sandbox "
                    "stages copies, so the two views would not share writes -- mount disjoint "
                    "trees")


#: What containermanagerd creates in a bundle container (``~/Library/Containers/<id>/``),
#: measured on a prepared slot: the run's ``Data`` and the manager's own metadata.
_CONTAINER_ENTRIES = frozenset({"Data", ".com.apple.containermanagerd.metadata.plist"})


def _stray_container_entries(bundle_container: Path) -> list[str]:
    try:
        names = os.listdir(bundle_container)
    except FileNotFoundError:
        return []
    return [n for n in names if n not in _CONTAINER_ENTRIES]


def _empty_slot(slot: Slot, home: Path) -> list[str]:
    """Empty the (already swept) slot's io/, ro/ and container; remove anything beside its
    ``Data/`` and return those names. Raises ``SandboxError`` if any of it can't be removed."""
    container = slot.container_data(home)
    parent = container.parent
    if os.path.lexists(parent) and os.path.islink(parent):
        raise SandboxError(f"refusing to wipe {container}: {parent} is a symlink")
    for d in (slot.io_dir, slot.ro_dir, container):
        mc.wipe_dir(d)
    stray = _stray_container_entries(parent)
    for name in stray:
        mc.remove_tree(parent / name)
    left = _stray_container_entries(parent)
    if left:
        raise SandboxError(f"could not remove {sorted(left)} from {parent}")
    return stray


def _dir_identity(path: Path) -> tuple[int, int] | None:
    """``(st_dev, st_ino)`` of a real directory at ``path``; None if absent or not one."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    return (st.st_dev, st.st_ino) if stat.S_ISDIR(st.st_mode) else None


def _manifest_error(path: Path, why: str) -> SandboxUnavailable:
    return SandboxUnavailable(f"appsandbox manifest {path} is malformed: {why}; "
                              "re-run `blastbox macos prepare`")


def _parse_manifest(raw: object, root: Path, path: Path) -> Manifest:
    """Every field typed and every slot path where ``prepare`` puts it: slot paths are wiped
    and launched, so an edited manifest must not aim them outside the root (or index a missing
    key and crash backend selection)."""
    if not isinstance(raw, dict):
        raise _manifest_error(path, "not a JSON object")
    if "preparing" in raw:
        raise SandboxUnavailable(
            f"appsandbox manifest {path} marks a `blastbox macos prepare` that is running or "
            "failed part-way (slots may be half rebuilt); re-run `blastbox macos prepare`")
    if raw.get("version") != MANIFEST_VERSION:
        raise SandboxUnavailable(
            f"appsandbox manifest version {raw.get('version')!r} != {MANIFEST_VERSION}; "
            "re-run `blastbox macos prepare`"
        )
    prefix, ro_paths, slots = raw.get("bundle_prefix"), raw.get("ro_paths"), raw.get("slots")
    generation = raw.get("generation", "")
    if not isinstance(generation, str):
        raise _manifest_error(path, "generation must be a string")
    # Bundle ids are used as paths (container, lock): they must stay plain identifiers.
    if not isinstance(prefix, str) or not _valid_bundle_id(prefix):
        raise SandboxUnavailable(f"appsandbox manifest has invalid bundle ids {[prefix]!r}; "
                                 "re-run `blastbox macos prepare`")
    if not isinstance(ro_paths, list) or not all(
            isinstance(p, str) and os.path.isabs(p) for p in ro_paths):
        raise _manifest_error(path, "ro_paths must be a list of absolute paths")
    if not isinstance(slots, list):
        raise _manifest_error(path, "slots must be a list")
    real_root = root.resolve()
    parsed: list[Slot] = []
    for pos, s in enumerate(slots):
        if not isinstance(s, dict):
            raise _manifest_error(path, f"slot {pos} is not an object")
        index, bundle_id = s.get("index"), s.get("bundle_id")
        if type(index) is not int or index != pos:
            raise _manifest_error(path, f"slot {pos} has index {index!r}")
        if not _valid_bundle_id(bundle_id) or bundle_id != f"{prefix}.slot{index}":
            raise SandboxUnavailable(f"appsandbox manifest has invalid bundle ids {[bundle_id]!r}; "
                                     "re-run `blastbox macos prepare`")
        raw_fields = {k: s.get(k) for k in ("bundle", "io_dir", "lock_path")}
        fields = {k: v for k, v in raw_fields.items() if isinstance(v, str) and os.path.isabs(v)}
        if len(fields) != len(raw_fields):
            raise _manifest_error(path, f"slot {pos} paths must be absolute strings")
        want = {"bundle": real_root / "slots" / str(index) / f"bb-slot-{index}.app",
                "io_dir": real_root / "slots" / str(index) / "io",
                "lock_path": real_root / "locks" / f"{index}.lock"}
        for k, v in fields.items():
            if Path(v).resolve() != want[k]:
                raise _manifest_error(path, f"slot {pos} {k} {v!r} is not {want[k]}")
        parsed.append(Slot(index=index, bundle_id=bundle_id, bundle=Path(fields["bundle"]),
                           io_dir=Path(fields["io_dir"]), lock_path=Path(fields["lock_path"])))
    return Manifest(root=root, bundle_prefix=prefix, ro_paths=tuple(Path(p) for p in ro_paths),
                    slots=tuple(parsed), generation=generation)


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
    lock_wait_s: float | None = None,
    home: Path | None = None,
) -> Manifest:
    """Build (or rebuild) the slot bundles under ``root`` and write the manifest.

    Idempotent: every slot is rebuilt and re-signed, so changing ``ro_paths`` or the slot
    count is just a re-run. Needs the Xcode Command Line Tools (``clang``, ``codesign``).

    Safe beside a running agent: every slot's lock (the one a run holds from its first wipe
    to its last) is taken first -- waiting up to ``lock_wait_s`` (default
    ``$BLASTBOX_APPSANDBOX_PREPARE_WAIT_S``, else 60s) for runs in progress, else refusing --
    and held until the new manifest is in place. A live instance then sees a new manifest
    generation before its next run and refuses to run until restarted, so no job launches
    under a re-signed bundle (another bundle id, other grants) that its watchdog and sweep
    don't match.

    EVERY existing slot is swept and emptied under each bundle id it may have carried (the
    current manifest's, its signed bundle's, and the one it is about to get) before anything
    changes; a prepare that can't prove them empty refuses. A process can survive without its
    slot being RETIRED -- an agent SIGKILLed mid-run writes no marker, and relies on the next
    run's pre-run sweep -- and re-preparing under another prefix, or dropping the slot, would
    leave it its grant to the slot's ``io/`` with no future sweep that matches it. A retired
    slot whose previous id can't be read at all refuses. ``home`` is the user's home.
    """
    if not 1 <= slots <= 256:
        raise SandboxError("slots must be between 1 and 256")
    home = home or Path(pwd.getpwuid(os.getuid()).pw_dir)
    # Resolved before anything is created, so the overlap checks below run first.
    planned = root.expanduser().resolve()
    planned_prefix = bundle_prefix or "io.blastbox.sbx." + hashlib.sha256(
        str(planned).encode()).hexdigest()[:10]
    planned_ids = ([f"{planned_prefix}.slot{i}" for i in range(slots)]
                   if _valid_bundle_id(planned_prefix) else [])
    _check_root_outside_containers(planned, home, planned_ids)
    resolved_ro = [Path(p).expanduser().resolve(strict=True) for p in ro_paths]
    _check_ro_grants(resolved_ro, planned, home, planned_ids)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = root.resolve()
    os.chmod(root, 0o700)
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

    (root / "locks").mkdir(exist_ok=True, mode=0o700)
    wait_s = _prepare_wait(lock_wait_s)
    deadline = time.monotonic() + wait_s
    # ONE prepare at a time, and the slot set read only once it holds that: two overlapping
    # prepares that each listed the slots first could have the second (asking for fewer) lock
    # only the slots it saw, then delete the higher-numbered ones the first had just created --
    # while a freshly started agent ran in one. Agents never take this lock (only slot locks),
    # so it never delays a run; it lives in locks/, which no slot cleanup touches.
    #
    # LOCK ORDER (prepare): root prepare lock -> slot locks (ascending) -> bundle locks (sorted
    # by id). A run takes its slot lock and then its bundle lock, both NON-blocking, and drops the
    # slot lock when the bundle lock is busy -- it never waits holding one -- so prepare's waits
    # can't deadlock with a run; two prepares (on other roots sharing a prefix) take bundle locks
    # in the same global sorted order, so they can't deadlock with each other either.
    with _held_lock(root / "locks" / PREPARE_LOCK, deadline, wait_s,
                    "another `blastbox macos prepare` is running on this root"):
        existing = _existing_slots(root)
        indexes = range(max([slots, *(i + 1 for i in existing)]))
        with _all_slot_locks(root, indexes, wait_s, deadline=deadline):
            previous = _previous_bundle_ids(root, existing)
            # Every container this prepare may sweep, empty or rebuild: each existing slot's
            # previous ids and new id, and each new slot's id. A container is keyed by bundle
            # id, not root, so another root prepared with the same prefix shares it: its run
            # holds the per-user bundle lock, and without taking it here the sweep below would
            # SIGKILL that run's child and wipe its Data mid-job.
            ids = {bid for i in existing for bid in previous.get(i, set())}
            ids.update(f"{prefix}.slot{i}" for i in indexes)
            _check_root_outside_containers(root, home, ids)
            _check_ro_grants(resolved_ro, root, home, ids)
            with _all_bundle_locks(home, ids, wait_s, deadline=deadline):
                _sweep_previous_slots(root, existing, prefix, home, previous=previous)
                return _prepare_locked(root, slots=slots, resolved_ro=resolved_ro,
                                       prefix=prefix, cc=cc, codesign=codesign, runner=runner)


def _check_root_outside_containers(root: Path, home: Path, ids: Iterable[str]) -> None:
    """Refuse a root that is, sits inside, or holds the container of any of ``ids``.

    A slot's container (``~/Library/Containers/<id>``) is swept and wiped before and after
    every run: a root inside one would have its manifest, launchers and locks deleted by the
    first pre-run wipe; a root holding one would put the child's container -- and its grant --
    inside the tree prepare stages and signs."""
    for bid in sorted(set(ids)):
        container = (home / "Library" / "Containers" / bid).resolve()
        if mc.paths_overlap(root, container):
            raise SandboxError(f"appsandbox root {root} overlaps the slot container "
                               f"{container}; use a root outside ~/Library/Containers/{bid}")


def _check_ro_grants(ro: Iterable[Path], root: Path, home: Path, ids: Iterable[str]) -> None:
    """Refuse a read-only grant (``prepare --ro``, signed into EVERY slot's entitlements) that
    is, sits inside or holds this root, ``~/Library/Containers`` (as a whole), the container of
    any of ``ids`` (each slot's, previous and planned), or the workers' shared state: a child in
    one slot could then read the other slots' staging and ``Data`` -- their inputs, caches and
    job state -- or the cleanup records and claims every worker relies on."""
    ro = list(ro)
    if not ro:
        return
    for rp in ro:
        if mc.paths_overlap(rp, root):
            raise SandboxError(f"--ro {rp} overlaps the appsandbox root {root}")
    try:
        mc.check_clear_of_containers((("--ro", rp) for rp in ro), "appsandbox", home)
        mc.check_clear_of_state((("--ro", rp) for rp in ro), "appsandbox", home)
    except SandboxError as exc:
        raise SandboxError(str(exc).removeprefix("appsandbox: ")) from None
    for bid in sorted(set(ids)):
        container = (mc.containers_dir(home) / bid).resolve()
        for rp in ro:
            if mc.paths_overlap(rp, container):
                raise SandboxError(f"--ro {rp} overlaps the slot container {container}; a child "
                                   "in any slot could read it")


def _previous_bundle_ids(root: Path, indexes: Iterable[int]) -> dict[int, set[str]]:
    """Each slot's bundle id(s) before this prepare: from the current manifest, and from the
    slot's signed bundle on disk (all a failed earlier prepare leaves, its manifest being only
    the "preparing" marker)."""
    ids: dict[int, set[str]] = {}
    try:
        for s in Manifest.load(root).slots:
            ids.setdefault(s.index, set()).add(s.bundle_id)
    except SandboxError:
        pass
    for i in indexes:
        info = root / "slots" / str(i) / f"bb-slot-{i}.app" / "Contents" / "Info.plist"
        try:
            with open(info, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fh:
                bid = plistlib.load(fh).get("CFBundleIdentifier")
        except (OSError, ValueError, plistlib.InvalidFileException, AttributeError):
            continue
        if _valid_bundle_id(bid):
            ids.setdefault(i, set()).add(bid)
    return ids


def _existing_slots(root: Path) -> list[int]:
    """Every slot index this root may still have a process for: a slot directory, a slot in the
    current manifest, or a retirement marker."""
    found: set[int] = set()
    if (root / "slots").is_dir():
        found.update(int(c.name) for c in (root / "slots").iterdir() if c.name.isdigit())
    if (root / "locks").is_dir():
        for marker in (root / "locks").glob("*.lock.retired"):
            index = marker.name.split(".", 1)[0]
            if index.isdigit():
                found.add(int(index))
    try:
        found.update(s.index for s in Manifest.load(root).slots)
    except SandboxError:
        pass                    # none yet, or a failed prepare's "preparing" marker
    return sorted(i for i in found if 0 <= i < 256)


def _sweep_previous_slots(root: Path, indexes: Iterable[int], prefix: str, home: Path, *,
                          previous: dict[int, set[str]] | None = None) -> None:
    """Sweep every given slot under every identity it may carry, then empty it, or raise.

    Not only retired slots: an agent killed mid-run (SIGKILL) leaves no marker, and its
    surviving process is matched only by its container -- which this prepare may be about to
    rename (another prefix) or drop (a shrink). Nothing is changed if a slot can't be proven
    empty."""
    indexes = list(indexes)
    if not indexes:
        return
    if previous is None:
        previous = _previous_bundle_ids(root, indexes)
    for i in indexes:
        marker = root / "locks" / f"{i}.lock.retired"
        if marker.exists() and not previous.get(i):
            raise SandboxError(
                f"appsandbox: slot {i} is retired, but its previous bundle id can't be read "
                f"(manifest and slot bundle both unreadable), so a process it left can't be "
                f"swept; make sure none is left, delete {marker}, and re-run prepare")
    old = [Slot(index=i, bundle_id=bid,
                bundle=root / "slots" / str(i) / f"bb-slot-{i}.app",
                io_dir=root / "slots" / str(i) / "io",
                lock_path=root / "locks" / f"{i}.lock")
           for i in indexes
           for bid in sorted(previous.get(i, set()) | {f"{prefix}.slot{i}"})]
    try:
        mc.sweep_containers([s.container_data(home) for s in old],
                            what=f"appsandbox slots {indexes} of {root}")
    except SandboxError as exc:
        raise SandboxError(f"appsandbox: slots under {root} can't be proven free of a previous "
                           f"run's processes: {exc}; inspect them, then re-run prepare") from exc
    for s in old:
        try:
            _empty_slot(s, home)
        except SandboxError as exc:
            raise SandboxError(
                f"appsandbox: slot {s.index} ({s.bundle_id}) can't be proven empty: {exc}; "
                "inspect it, then re-run prepare") from exc


def _prepare_wait(value: float | None) -> float:
    raw: object = value
    if raw is None:
        raw = os.environ.get("BLASTBOX_APPSANDBOX_PREPARE_WAIT_S", "") or "60"
    try:
        wait = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise SandboxError(f"appsandbox prepare wait {raw!r} is not a number") from exc
    if not math.isfinite(wait) or wait < 0:
        raise SandboxError(f"appsandbox prepare wait {raw!r} must be finite and >= 0")
    return wait


def _wait_lock(path: Path, deadline: float, wait_s: float, why: str) -> int:
    """``path``'s lock fd, waiting until ``deadline``; else raise naming ``why``."""
    while (fd := AppSandboxSandbox._try_lock(path)) is None:
        if time.monotonic() >= deadline:
            raise SandboxError(f"appsandbox: {why} (lock {path} held for {wait_s:g}s)")
        time.sleep(0.05)
    return fd


@contextlib.contextmanager
def _held_lock(path: Path, deadline: float, wait_s: float, why: str) -> Iterator[None]:
    fd = _wait_lock(path, deadline, wait_s, why)
    try:
        yield
    finally:
        AppSandboxSandbox._unlock(fd)


@contextlib.contextmanager
def _all_slot_locks(root: Path, indexes: Iterable[int], wait_s: float, *,
                    deadline: float | None = None) -> Iterator[None]:
    """Hold every listed slot's run lock (``locks/<i>.lock``), or raise if a run keeps one
    past ``wait_s`` (or the given ``deadline``)."""
    held: list[int] = []
    if deadline is None:
        deadline = time.monotonic() + wait_s
    try:
        for i in indexes:
            held.append(_wait_lock(
                root / "locks" / f"{i}.lock", deadline, wait_s,
                f"slot {i} is in use by a running job; stop the agent, or retry when it is idle"))
        yield
    finally:
        for fd in reversed(held):
            AppSandboxSandbox._unlock(fd)


def bundle_lock_path(home: Path, bundle_id: str) -> Path:
    """Per-user lock for ``bundle_id`` (and so its container), shared by every root."""
    d = mc.shared_state_dir(home) / "appsandbox-locks"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d / f"{bundle_id}.lock"


def _rw_registry_dir(home: Path) -> Path:
    return mc.path_claims_dir(home)


def hold_rw_sources(home: Path, sources: list[Path],
                    reads: Iterable[Path] = ()) -> contextlib.AbstractContextManager[None]:
    """Claim the writable ``sources`` (copy-back and capture destinations) for writing and the
    ``reads`` (seed) for reading, in the per-user registry both native backends share, for the
    whole run (see :func:`mc.hold_path_claims`).

    Each run stages its OWN snapshot of a writable mount and replaces the host tree from it
    after: two runs on one tree (in any slot, any root, either backend) would each copy back a
    tree without the other's writes, silently undoing them -- bind mounts would have shared one
    tree. So such runs don't overlap; the second is refused rather than queued."""
    return mc.hold_path_claims([*(("write", p) for p in sources),
                                *(("read", p) for p in reads)], "appsandbox", home)


@contextlib.contextmanager
def _all_bundle_locks(home: Path, bundle_ids: Iterable[str], wait_s: float, *,
                      deadline: float) -> Iterator[None]:
    """Hold the per-user lock of every listed bundle id, in sorted order, or raise if a run
    (in this root or another sharing the prefix) keeps one past ``deadline``."""
    held: list[int] = []
    try:
        for bid in sorted(set(bundle_ids)):
            held.append(_wait_lock(
                bundle_lock_path(home, bid), deadline, wait_s,
                f"bundle {bid} is in use by a running job (in this root or another prepared "
                "with the same --bundle-prefix); stop it, or retry when it is idle"))
        yield
    finally:
        for fd in reversed(held):
            AppSandboxSandbox._unlock(fd)


def _write_manifest_file(root: Path, obj: dict) -> None:
    tmp = root / (MANIFEST_NAME + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    os.replace(tmp, root / MANIFEST_NAME)


def _prepare_locked(root: Path, *, slots: int, resolved_ro: list[Path], prefix: str, cc: str,
                    codesign: str, runner: Callable[..., subprocess.CompletedProcess]) -> Manifest:
    # Before any slot is touched, replace the manifest with a "preparing" marker: a live agent
    # sees the digest change and refuses (it never launches a half-rebuilt slot under its old
    # bundle id), and a fresh load refuses it too. Only a prepare that completes replaces the
    # marker with a real manifest, so one that fails part-way leaves every agent refusing.
    _write_manifest_file(root, {"version": MANIFEST_VERSION, "preparing": secrets.token_hex(8)})
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

    # Drop slots beyond the new count so a shrink cannot leave stale signed launchers around --
    # and their retirement markers, already swept and emptied (_sweep_previous_slots): a marker
    # left behind would retire the slot again, with no identity to sweep, if it is re-added.
    slots_root = root / "slots"
    for child in slots_root.iterdir():
        if child.name.isdigit() and int(child.name) >= slots:
            mc.remove_tree(child)
    for marker in (root / "locks").glob("*.lock.retired"):
        index = marker.name.split(".", 1)[0]
        if index.isdigit() and int(index) >= slots:
            marker.unlink(missing_ok=True)

    manifest = Manifest(root=root, bundle_prefix=prefix, ro_paths=tuple(resolved_ro),
                        slots=tuple(built), generation=secrets.token_hex(8))
    _write_manifest_file(root, manifest.to_json())
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


class _CopyBack:
    """A copy-back built beside its destination and not yet swapped in (see
    ``AppSandboxSandbox._copy_back``). ``commit`` swaps it in; ``abort`` removes it. Either
    way it is dropped from ``leftovers`` once it is gone."""

    def __init__(self, dest: Path, new: Path, old: Path | None,
                 leftovers: mc.Leftovers | None) -> None:
        self._dest, self._new, self._old, self._leftovers = dest, new, old, leftovers

    def commit(self) -> None:
        try:
            if self._old is not None:
                AppSandboxSandbox._swap_children(self._dest, self._new, self._old,
                                                 self._leftovers)
            else:
                try:
                    os.replace(self._new, self._dest)
                except BaseException:
                    mc.remove_tree(self._new)
                    raise
        finally:
            self._forget()

    def abort(self) -> None:
        try:
            mc.remove_tree(self._new)
        finally:
            self._forget()

    def _forget(self) -> None:
        if self._leftovers is not None and not os.path.lexists(self._new):
            self._leftovers.discard(self._new)


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
        self._root = Path(root) if root is not None else default_root()
        self._manifest = Manifest.load(self._root)
        # Set (for good) once the manifest on disk is no longer the one loaded here.
        self._stale: str | None = None
        if not self._manifest.slots:
            raise SandboxUnavailable("appsandbox manifest has no slots")
        self._popen = popen
        self._rss_fn = rss_fn
        self._home = home or Path(pwd.getpwuid(os.getuid()).pw_dir)
        # A manifest written before the check existed (or by hand) may still put the root in a
        # slot's container, which the first pre-run wipe would delete: refuse to start on it.
        try:
            _check_root_outside_containers(self._root.resolve(), self._home,
                                           (s.bundle_id for s in self._manifest.slots))
        except SandboxError as exc:
            raise SandboxUnavailable(f"{exc}; re-run `blastbox macos prepare` with another "
                                     "--root") from None
        # The same for read-only grants signed by a prepare that predates their check.
        try:
            _check_ro_grants([Path(p).resolve() for p in self._manifest.ro_paths],
                             self._root.resolve(), self._home,
                             (s.bundle_id for s in self._manifest.slots))
        except SandboxError as exc:
            raise SandboxUnavailable(f"appsandbox manifest: {exc}; re-run `blastbox macos "
                                     "prepare` without it") from None
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

    def _check_manifest_current(self) -> None:
        """Refuse to run once `prepare` has replaced the manifest this instance loaded (and
        verified): the slots may now carry another bundle id or other grants, which this
        instance's container matching and verification don't cover. Stays refused until the
        agent restarts and loads (and verifies) the new manifest. Called with the slot's lock
        held, which `prepare` needs to change anything."""
        if self._stale is None:
            path = self._root / MANIFEST_NAME
            try:
                now = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                now = f"unreadable ({exc})"
            if now != self._manifest.digest:
                self._stale = (f"appsandbox manifest {path} changed since this agent loaded it "
                               "(re-prepared); restart the agent to use the new slots")
                _log.error("appsandbox: %s", self._stale)
        if self._stale is not None:
            raise SandboxUnavailable(self._stale)

    @contextlib.contextmanager
    def _acquire_slot(self) -> Iterator[Slot]:
        if self._stale is not None:
            raise SandboxUnavailable(self._stale)
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
                # container at once. Both locks are taken NON-blocking (slot, then bundle) and the
                # slot lock dropped when the bundle one is busy: a run never waits holding a lock,
                # so prepare (which waits, in the order documented there) can't deadlock with it.
                bfd = self._try_lock(self.bundle_lock_path(slot))
                if bfd is None:
                    self._unlock(fd)
                    continue
                try:
                    self._check_manifest_current()
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
        return bundle_lock_path(self._home, slot.bundle_id)

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

    def _wipe_slot(self, slot: Slot) -> list[str]:
        """Kill what is left in the slot, then empty its io/ and container, or retire the slot
        and raise: a run that left a process or undeletable state (a ``uchg`` file, a locked dir,
        a container swapped for a symlink) must not hand it to the next run.

        The bundle container (``Data/``'s parent) should hold only what containermanagerd puts
        there. App Sandbox denies the child writes to it (measured: renaming ``Data`` or
        creating a sibling fails with EPERM), but anything else found there -- a ``Data``
        renamed aside with the run's files, say -- would sit outside every wiped root, so it is
        removed, and returned so the caller fails the run; what can't be removed retires the
        slot."""
        try:
            self._sweep_slot(slot)
            return _empty_slot(slot, self._home)
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
        # The detonation this run is part of, read at its START: credited only if the run also
        # finishes while that ledger is open (see ConfinementLedger).
        ledger = current_ledger()
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
        self._check_sources_clear(request)
        rw_sources = [Path(m.source).expanduser().resolve() for m in request.rw_mounts]
        # A capture replaces its destination as a whole tree, as a copy-back does: claimed with
        # the writable mounts, so it can't race another run's copy-back (or capture) of an
        # overlapping tree -- whichever committed last would silently discard the other's.
        claimed = [*rw_sources, *([request.capture_home.expanduser().resolve()]
                                  if request.capture_home is not None else [])]
        seed = ([request.seed_home.expanduser().resolve()]
                if request.seed_home is not None else [])
        with hold_rw_sources(self._home, claimed, seed), self._acquire_slot() as slot:
            # Under the claim, so no live run's copy-back is in flight in these trees: what an
            # interrupted one left is either removed or refused, never staged into this job.
            for src in rw_sources:
                stale = mc.clear_stale_copy_backs(src)
                if stale is not None:
                    raise SandboxError(
                        f"appsandbox: rw mount {src} holds {stale}, left by an interrupted "
                        "copy-back; it may hold the mount's original entries -- restore or "
                        "remove it, then retry")
            # The slot's own emergency cleanup, held from the first wipe to the last: the agent
            # retiring mid-run skips every `finally` here, and run_confined's covers only the
            # child's lifetime -- not the copy-back, capture and final wipe after it. It removes
            # a copy-back or capture left half-built beside its destination, then sweeps and
            # wipes the slot (retiring it if that fails, as a run's own wipe does).
            leftovers = mc.Leftovers()

            def _emergency() -> None:
                try:
                    leftovers.remove_all()
                finally:
                    self._wipe_slot(slot)

            token = register_emergency_cleanup(_emergency)
            try:
                self._wipe_slot(slot)
                try:
                    result, confined = self._run_in_slot(slot, exe, request, leftovers)
                finally:
                    stray = self._wipe_slot(slot)
            finally:
                unregister_emergency_cleanup(token)
            if stray:
                # Removed by the wipe, but nothing the run did beside its Data/ is legitimate.
                raise SandboxError(f"appsandbox: the run left {sorted(stray)} beside its "
                                   f"container {slot.container_data(self._home)}; removed, "
                                   "run failed")
        # Credited only once the final sweep and wipe have succeeded: a run whose cleanup
        # raised is a failed run, and an engine falling back to an in-process parse after it
        # must not pass that parse off as confined.
        if confined:
            note_confined_run(ledger)
        return result

    def _check_sources_clear(self, request: SandboxRequest) -> None:
        """Refuse a mount, seed or capture path that is, holds, or sits inside this root (every
        slot's io/ and ro/ staging) or a slot's container, before anything is created. Staging
        or seeding such a source would copy the growing copy into itself until a limit stops
        it; a capture there would land in a tree the next wipe empties."""
        root = self._root.resolve()
        protected = [root, *(s.container_data(self._home).parent for s in self._manifest.slots)]
        paths = [*(("mount", Path(m.source)) for m in (*request.ro_mounts, *request.rw_mounts)),
                 *(("seed_home", p) for p in [request.seed_home] if p is not None),
                 *(("capture_home", p) for p in [request.capture_home] if p is not None)]
        # The workers' shared locks, claim registry and cleanup records (mc.internal_state_dirs):
        # a copy-back or capture over them would replace lock files other runs hold by inode.
        # Checked before any claim is made.
        mc.check_clear_of_state(paths, "appsandbox", self._home)
        # Nor ~/Library/Containers as a whole: a copy of it would stage other roots' slots'
        # Data (their caches and job state) into this run.
        mc.check_clear_of_containers(paths, "appsandbox", self._home)
        # The seed and capture directories against the mounts: a writable mount over the seed
        # is copied back over it (later runs seeded from what the child wrote); a capture over
        # any mount replaces that tree with the slot's cache.
        mc.check_homes_clear_of_mounts(request.seed_home, request.capture_home,
                                       [m.source for m in request.ro_mounts],
                                       [m.source for m in request.rw_mounts], "appsandbox")
        for what, p in paths:
            rp = p.expanduser().resolve()
            for area in protected:
                if mc.paths_overlap(rp, area.resolve()):
                    raise SandboxError(f"appsandbox: {what} {p} overlaps {area}, where runs are "
                                       "staged; use a path outside it")
        # A writable mount is staged by copy and copied back over the host tree, and the copier
        # skips FIFOs, sockets and device nodes (opening a FIFO could block the worker): one
        # already in a writable mount would be missing from the copy and so DELETED from the
        # host by the copy-back. Refused up front instead. (Ones the child creates are dropped,
        # as before: they were never the host's.) Read-only mounts aren't copied back.
        for m in request.rw_mounts:
            special = mc.find_special_entry(Path(m.source).expanduser().resolve())
            if special is not None:
                raise SandboxError(f"appsandbox: rw mount {m.source} holds {special}, a FIFO, "
                                   "socket or device node, which App Sandbox staging can't "
                                   "carry; its copy-back would delete it. Mount a directory "
                                   "without it")
        # Staging keeps hard links shared WITHIN the writable mounts, but one whose other name is
        # outside them can't be: the copy-back would replace the mounted name with a new inode
        # and cut the host's link, even after a no-op run. Refused up front.
        if request.rw_mounts:
            split = mc.find_split_hard_link(
                [Path(m.source).expanduser().resolve() for m in request.rw_mounts])
            if split is not None:
                raise SandboxError(f"appsandbox: rw mount file {split} has a hard link whose "
                                   "other name is outside the writable mounts; its copy-back "
                                   "would split them -- mount a copy instead")

    def _run_in_slot(self, slot: Slot, exe: Path, request: SandboxRequest,
                     leftovers: mc.Leftovers | None = None) -> tuple[SandboxResult, bool]:
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
        _check_ro_rw_disjoint(request)
        # ONE pre-launch budget for the seed AND every staged mount: nothing is metered by the
        # watchdog until the child starts, so together they must stay within the run's limit.
        staging = mc.CopyBudget(budget)
        if request.seed_home is not None:
            if not container.is_dir():
                self._prime_container(slot, home)
            mc.seed_scratch(container, request.seed_home, budget=staging)

        mapping: list[tuple[str, str]] = []
        rw_staged: list[tuple[Path, Path, bool]] = []
        # Writable mounts of the same source, or of a source inside another writable mount, are
        # views of ONE host tree: stage only the outermost and point the others into its staged
        # copy, so aliases share state as bind mounts do and one copy-back carries every write
        # (separate snapshots copied back in turn would let an unchanged one undo another's).
        rw_srcs = [Path(m.source).resolve(strict=True) for m in request.rw_mounts]
        rw_root: dict[int, int] = {}
        for j, src in enumerate(rw_srcs):
            owners = [k for k, other in enumerate(rw_srcs)
                      if src == other or src.is_relative_to(other)]
            # outermost source; the first listed among equal ones
            rw_root[j] = min(owners, key=lambda k: (len(rw_srcs[k].parts), k))
        staged_rw: dict[int, Path] = {}
        # ONE hard-link map for every writable mount: a file linked into two of them is one
        # inode on the host, and as with bind mounts a write through one name must show through
        # the other (and its bytes count once). Read-only copies each get their own, so a write
        # through a writable copy can never reach a read-only one.
        rw_links: mc.LinkMap = {}
        mounts = list(enumerate([*request.ro_mounts, *request.rw_mounts]))
        n_ro = len(request.ro_mounts)
        # roots before the aliases that point into them, whatever order the request used
        for i, m in sorted(mounts, key=lambda im: im[0] >= n_ro and rw_root[im[0] - n_ro] != im[0] - n_ro):
            src = Path(m.source).resolve(strict=True)
            j = i - n_ro
            if j >= 0 and rw_root[j] != j:
                owner = rw_root[j]
                staged = staged_rw[owner] / src.relative_to(rw_srcs[owner])
            else:
                # Read-only mounts go under ro/ (granted read-only), writable ones under io/.
                base = slot.ro_dir if j < 0 else io
                staged = base / "m" / str(i) / (src.name or "root")
                staged.parent.mkdir(parents=True)
                mc.copy_no_follow(src, staged, budget=staging,
                                  links=rw_links if j >= 0 else None)
                if j >= 0:
                    staged_rw[j] = staged
                    rw_staged.append((src, staged, stat.S_ISDIR(os.lstat(src).st_mode)))
            mapping.append((str(m.target), str(staged)))
            if str(Path(m.target)) != str(src):
                mapping.append((str(src), str(staged)))

        _check_mapping(mapping)
        # The container's identity now (None on a fresh slot whose first launch creates it):
        # after the run Data/ must be the same directory, not one the child put in its place.
        container_id = _dir_identity(container)
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
        if container_id is not None and os.path.lexists(container) \
                and _dir_identity(container) != container_id:
            raise SandboxError(f"appsandbox: {container} was replaced during the run; run "
                               "failed, not credited")

        copy_back = mc.CopyBudget(budget)
        # Only outermost writable sources were staged, so these never overlap. Every
        # replacement is built first (sharing one link map, so links between the mounts stay
        # links on the host) and only then swapped in: a later mount's link must reach an
        # earlier one's copy before that copy has been renamed into place.
        back_links: mc.LinkMap = {}
        pending: list[_CopyBack] = []
        try:
            for src, staged, was_dir in rw_staged:
                pending.append(self._build_copy_back(staged, src, copy_back, was_dir,
                                                     leftovers, back_links))
            while pending:
                pending.pop(0).commit()
        finally:
            for left in pending:
                left.abort()
        ok = result.exit_code == 0 and not result.killed
        if ok and request.capture_home is not None:
            # The child owns its container and may have deleted Data/ or swapped it for a
            # symlink to a host dir: never follow it into a capture, and never report a capture
            # that didn't happen (the destination would keep an earlier run's contents).
            try:
                is_dir = stat.S_ISDIR(os.lstat(container).st_mode)
            except FileNotFoundError:
                raise SandboxError(f"appsandbox: cannot capture {container}: the run "
                                   "removed it") from None
            if not is_dir:
                raise SandboxError(f"appsandbox: refusing to capture {container}: "
                                   "it is no longer a real directory")
            mc.capture_scratch(container, request.capture_home, budget, leftovers)

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
    def _swap_children(dest: Path, new: Path, old: Path,
                       leftovers: mc.Leftovers | None = None) -> None:
        """Replace ``dest``'s children with ``new``'s: old ones aside into ``old``, new ones in,
        then drop ``old``. A failed rename undoes every move made so far (best effort, logged)
        and re-raises, so ``dest`` ends up as it was rather than part-swapped.

        A teardown section (see :func:`teardown_critical`): a retiring agent waits for the
        renames to finish rather than exit between them."""
        with teardown_critical():
            AppSandboxSandbox._swap_children_locked(dest, new, old, leftovers)

    @staticmethod
    def _swap_children_locked(dest: Path, new: Path, old: Path,
                              leftovers: mc.Leftovers | None = None) -> None:
        # The mount root is kept (as a bind mount would), but the swap's renames move its
        # modification time: restored, at the end, to the times of the tree the child left.
        times = os.stat(new, follow_symlinks=False)
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
        # Every rename is done: the replaced contents are now garbage. Renamed to say so -- a
        # `done-` tree a later worker finds (this one was killed, or retired past its budget,
        # while removing it) is removed before staging, never staged into a job -- and listed
        # in `leftovers` meanwhile, so a retiring agent's cleanup finishes the removal. (Not
        # before now: while the renames run, `old` holds the host's own entries.)
        # Recorded (directory, name, inode) before the rename, so a later worker removes only
        # THIS tree and refuses a user's own entry that merely has the name (mc.retire_replaced).
        done = old.with_name(old.name.replace(f"{mc.COPY_BACK_MARK}old-",
                                              f"{mc.COPY_BACK_MARK}done-", 1))
        try:
            mc.retire_replaced(old, done, leftovers)
        except SandboxError as exc:
            raise SandboxError(f"appsandbox: copy-back of {dest}: {exc}") from exc
        os.utime(dest, ns=(times.st_atime_ns, times.st_mtime_ns), follow_symlinks=False)

    @staticmethod
    def _copy_back(staged: Path, dest: Path, budget: mc.CopyBudget, was_dir: bool,
                   leftovers: mc.Leftovers | None = None,
                   links: mc.LinkMap | None = None) -> None:
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
        output as written when it was not.

        The hidden replacement is listed in ``leftovers`` while it exists: it holds the child's
        bytes outside every wiped root, so an agent retiring mid-copy removes it."""
        AppSandboxSandbox._build_copy_back(staged, dest, budget, was_dir, leftovers,
                                           links).commit()

    @staticmethod
    def _build_copy_back(staged: Path, dest: Path, budget: mc.CopyBudget, was_dir: bool,
                         leftovers: mc.Leftovers | None = None,
                         links: mc.LinkMap | None = None) -> _CopyBack:
        """The checks and the copy of :meth:`_copy_back`; the swap is the returned
        :class:`_CopyBack`'s ``commit`` (or ``abort`` to drop the copy)."""
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
        old: Path | None
        if was_dir:
            if not stat.S_ISDIR(os.lstat(dest).st_mode):
                raise SandboxError(f"appsandbox: rw mount {dest} is no longer a directory")
            locked = mc.locked_entry(dest)
            if locked is not None:
                raise SandboxError(f"appsandbox: rw mount {dest} holds {locked}, which can't be "
                                   "replaced (immutable/append-only or not writable); not copied back")
            tag = secrets.token_hex(8)
            new = dest / f"{mc.COPY_BACK_MARK}{tag}"
            old = dest / f"{mc.COPY_BACK_MARK}old-{tag}"
        else:
            locked_target = mc.locked_file_target(dest)
            if locked_target is not None:
                raise SandboxError(f"appsandbox: rw mount {dest} can't be replaced ({locked_target}); "
                                   "not copied back")
            new = dest.with_name(f".{dest.name}{mc.COPY_BACK_MARK}{secrets.token_hex(8)}")
            old = None
        if leftovers is not None:
            leftovers.add(new)
        try:
            mc.copy_no_follow(staged, new, budget=budget, links=links)
        except BaseException:
            # The copy holds untrusted bytes outside every wipe and watchdog path, so it never
            # outlives the attempt.
            mc.remove_tree(new)
            if leftovers is not None:
                leftovers.discard(new)
            raise
        return _CopyBack(dest, new, old, leftovers)
