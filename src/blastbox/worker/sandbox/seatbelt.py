"""macOS Seatbelt (``sandbox-exec``) backend for the blastbox worker SDK.

The default macOS backend. Each run gets a **deny-default** Seatbelt profile built from the
request and applied by the kernel's Sandbox.kext before the child execs:

- Apple's ``system.sb`` base (dyld, libSystem, read-only ``/System`` + ``/usr/lib``).
- Read: the request's ro AND rw mounts, ``argv[0]``, the system exec dirs, file *metadata*.
- Write: the request's rw mounts and a fresh per-run scratch dir (HOME / TMPDIR / caches).
- Exec: ``argv[0]``, the system exec dirs, and the ro mounts.
- Network: denied (``Limits.net_egress`` is NOT honoured -- see below).
- Accelerators (``SandboxRequest.accelerators``), default-deny:
  ``gpu`` -> the Metal user clients + the Metal compiler-cache service;
  ``ane`` -> the Neural Engine service + its user clients, and issuing READ sandbox extensions
  for the scratch dir (the out-of-process ANE compiler reads the plan the child cached there).

Everything else -- LaunchServices, TCC, Contacts, the window server, the shared per-user
Metal shader cache, the real home directory -- stays denied. Measured with Vision barcode
detection forced onto the Neural Engine (macOS 26, M4 Pro): it decodes under this profile,
and those are exactly the residual denials it logs.

**Injection-safe by construction.** Paths never appear in the profile text. Each grant is a
``(param "RO_3")`` reference and the value travels as ``sandbox-exec -D RO_3=<path>``; the
profile text is built only from this module's literals and counters.

**Why ``net_egress`` is ignored.** On Linux, granted egress means "share the worker netns that
netd/rooter already steers through fakenet/tor/VPN". macOS has no such rooter, so allowing the
network here would be direct host egress. Fail-closed: the network stays denied, and a request
that asked for it is logged. A JOB that needs egress never gets this far on a Mac: the
http_agent advertises ``"egress": false`` and refuses it (422 ``egress_unavailable``) before the
engine runs, because a run with the network silently denied returns a plausible wrong answer.

``sandbox-exec(1)`` is marked deprecated, but it is the documented front-end to the same
Sandbox.kext that App Sandbox, Chrome and Safari's helpers use, and ships in macOS 26. If it
disappears, :func:`select_sandbox` falls back to the ``appsandbox`` backend (or refuses).
"""
from __future__ import annotations

import contextlib
import logging
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.base import (
    ConfinementLedger,
    SandboxRequest,
    SandboxResult,
    current_ledger,
    note_confined_run,
    register_emergency_cleanup,
    teardown_critical,
    unregister_emergency_cleanup,
)
from blastbox.worker.sandbox import macos_common as mc

_log = logging.getLogger("blastbox.worker.sandbox.seatbelt")

_SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Device nodes every child may use. Writes to /dev/null only.
_DEV_READ = ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom")

#: Neural Engine user-client classes by chip generation. A class absent on this machine is a
#: harmless no-op in the profile; a NEW generation's class missing here fails the engine's
#: known-positive self-test (Vision then returns nothing), which is why engines that need the
#: ANE must self-test -- see docs/superpowers/specs/2026-10-10-macos-sandbox-design.md.
ANE_USER_CLIENTS = (
    "H11ANEInDirectPathClient",
    "H11ANEInUserClient",
    "H1xANELoadBalancerDirectPathClient",
    "H1xANEInDirectPathClient",
)
GPU_USER_CLIENTS = ("IOSurfaceRootUserClient", "AGXDeviceUserClient")

_ACCEL_RULES: dict[str, list[str]] = {
    "gpu": [
        "(allow iokit-open-user-client (iokit-user-client-class "
        + " ".join(f'"{c}"' for c in GPU_USER_CLIENTS) + "))",
        '(allow mach-lookup (global-name "com.apple.cvmsServ"))',
    ],
    "ane": [
        "(allow iokit-open-user-client (iokit-user-client-class "
        + " ".join(f'"{c}"' for c in ANE_USER_CLIENTS) + "))",
        '(allow mach-lookup (global-name "com.apple.appleneuralengine"))',
    ],
}


def build_profile(
    *,
    exec_paths: list[str],
    ro_paths: list[str],
    rw_paths: list[str],
    accelerators: frozenset[str],
    scratch: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Return ``(profile_text, params)`` for one run.

    Every path is a ``-D`` parameter; ``profile_text`` contains only literals. ``*_paths`` must
    already be ``realpath``-ed (Seatbelt matches resolved paths).
    """
    unknown = set(accelerators) - mc.KNOWN_ACCELERATORS
    if unknown:
        raise SandboxError(
            f"unknown accelerator(s) {sorted(unknown)}; known: {sorted(mc.KNOWN_ACCELERATORS)}"
        )
    params: dict[str, str] = {}

    def refs(prefix: str, paths: list[str], kind: str) -> str:
        out = []
        for i, p in enumerate(paths):
            key = f"{prefix}_{i}"
            params[key] = p
            out.append(f'({kind} (param "{key}"))')
        return " ".join(out)

    sys_dirs = list(mc.SYSTEM_EXEC_DIRS)
    lines = [
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(allow process-fork)",
        "(allow signal (target same-sandbox))",
        "(allow file-read-metadata)",
        "(allow sysctl-read)",
        "(allow file-read* " + " ".join(f'(literal "{d}")' for d in _DEV_READ) + ")",
        '(allow file-write-data (literal "/dev/null"))',
        "(allow file-read* process-exec " + refs("SYS", sys_dirs, "subpath") + ")",
        "(allow file-read* process-exec " + refs("EXE", exec_paths, "literal") + ")",
        # The executable's own DIRECTORY (a listing, not its subtree): CoreFoundation inspects
        # it to resolve the main bundle, and Vision refuses to build an ANE plan without a
        # bundle id ("Null bundleID") -- a silent empty result, not a crash.
        "(allow file-read* " + refs("EXEDIR", sorted({str(Path(p).parent) for p in exec_paths}),
                                    "literal") + ")",
    ]
    if ro_paths:
        lines.append("(allow file-read* process-exec " + refs("RO", ro_paths, "subpath") + ")")
    if rw_paths:
        lines.append("(allow file-read* file-write* " + refs("RW", rw_paths, "subpath") + ")")
        # ...but not file flags on the mounts: they are the REAL host trees, and a uchg/uappnd
        # file left in one makes the caller's cleanup fail (and the tree stick around). Later
        # rules win, so this carves chflags out of the grant above. The per-run scratch is
        # exempt: it is unlocked and wiped by the backend itself after every run.
        mounts = [p for p in rw_paths if p != scratch]
        if mounts:
            lines.append("(deny file-write-flags " + refs("RWF", mounts, "subpath") + ")")
        # No ACLs anywhere it may write, scratch included: a deny ACL (`everyone deny delete`)
        # would keep the worker's own cleanup from removing the tree. No engine needs one.
        lines.append("(deny file-write-acl " + refs("RWA", rw_paths, "subpath") + ")")
        # The roots themselves stay put, as a bind mount's mountpoint does: the subtree grant
        # would let the child unlink or rename the root (and so delete or move away the REAL
        # host path of a mount, or its scratch -- what identifies the run to the sweep).
        # file-write-unlink covers unlink, rmdir and either side of a rename. A root nested in
        # another rw root is also reachable by renaming a directory between the two, so those
        # are pinned as well. Everything beneath a directory root stays writable.
        lines.append("(deny file-write-unlink "
                     + refs("RWR", _pinned_paths(rw_paths), "literal") + ")")
        # No hard links at all (file-write* includes file-link). The preflight scan
        # (mc.find_split_hard_link) only sees links that exist BEFORE launch: a child could
        # otherwise link a read-only-granted file into a writable mount and then write through
        # that alias, mutating the "read-only" host file. Symlinks are unaffected (a symlink is
        # file-write-create), and no engine needs to hard-link.
        lines.append("(deny file-link)")
    for accel in sorted(accelerators):
        lines.extend(_ACCEL_RULES[accel])
    if "ane" in accelerators and scratch:
        # Vision compiles its ANE plan into the per-run cache, then hands the out-of-process
        # ANECompilerService a sandbox READ extension for it. Without this the first compile
        # fails ("Cannot load network ...") and Vision returns nothing. Scope: read-class
        # extensions, for the scratch dir only -- it lets a system service read files this run
        # wrote; it grants the child itself nothing.
        params["SCRATCH_EXT"] = scratch
        lines.append(
            '(allow file-issue-extension (require-all '
            '(extension-class "com.apple.app-sandbox.read") (subpath (param "SCRATCH_EXT"))))'
        )
    lines.append("(deny network*)")
    return "\n".join(lines) + "\n", params


def _check_ro_rw_disjoint(ro_paths: list[str], rw_paths: list[str]) -> None:
    """Refuse a read-only mount whose source equals, lies inside, or contains a writable
    mount's source (both resolved), before anything is launched.

    Inside or equal: the rw ``file-write*`` subpath grant covers the ro path as well, so the
    child could rewrite an input or config its ``ro_mounts`` contract protects. Containing:
    Seatbelt itself would keep the rest of the ro tree read-only, but App Sandbox refuses the
    same layout (it stages copies), and a request should not run on one macOS backend and be
    refused by the other. Only the request's mounts are compared, never the run's scratch."""
    for r in ro_paths:
        ro = Path(r)
        for w in rw_paths:
            rw = Path(w)
            if ro == rw or ro.is_relative_to(rw) or rw.is_relative_to(ro):
                raise SandboxError(
                    f"seatbelt: read-only mount {ro} overlaps writable mount {rw}; the "
                    "writable grant would cover it (and App Sandbox refuses the same layout) "
                    "-- mount disjoint trees")


def _pinned_paths(rw_paths: list[str]) -> list[str]:
    """Every rw root, plus each directory between a root and another rw root that contains
    it (renaming one of those would carry the nested root away)."""
    roots = [Path(p) for p in rw_paths]
    pinned = {str(r) for r in roots}
    for r in roots:
        for outer in roots:
            if outer != r and outer in r.parents:
                d = r.parent
                while d != outer:
                    pinned.add(str(d))
                    d = d.parent
    return sorted(pinned)


#: Runs INSIDE the profile: sandbox-exec execs it only after the profile attached, so the nonce it
#: writes to the scratch dir proves this run was confined. A rejected profile (bad SBPL, a
#: failed sandbox_init) never gets here. It then execs the target, which keeps its own argv[0].
HANDSHAKE_SHIM = 'printf %s "$1" > "$2" || exit 125; shift 2; exec "$@"'
HANDSHAKE_NAME = ".bb-handshake"


def shim_argv(nonce: str, marker: str, target: list[str]) -> list[str]:
    return ["/bin/sh", "-c", HANDSHAKE_SHIM, "bb-handshake", nonce, marker, *target]


class SeatbeltSandbox:
    """:class:`~blastbox.worker.sandbox.base.Sandbox` backed by ``sandbox-exec`` (macOS)."""

    name = "seatbelt"

    def __init__(
        self,
        *,
        sandbox_exec: str = _SANDBOX_EXEC,
        scratch_base: str | os.PathLike[str] | None = None,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        rss_fn: Callable[[int], int] | None = None,
        platform_ok: bool = mc.IS_DARWIN,
    ) -> None:
        if not platform_ok:
            raise SandboxUnavailable("seatbelt is macOS-only")
        if not (Path(sandbox_exec).is_file() and os.access(sandbox_exec, os.X_OK)):
            raise SandboxUnavailable(f"{sandbox_exec} not found")
        if mc.IS_DARWIN and not mc.process_apis_available():
            # Without them a run's escaped processes can't be found or swept.
            raise SandboxUnavailable("seatbelt: libSystem process APIs unavailable")
        self._sandbox_exec = sandbox_exec
        raw_base = scratch_base if scratch_base is not None else os.environ.get(
            "BLASTBOX_MACOS_SCRATCH_DIR", "")
        self._scratch_base = Path(raw_base) if raw_base else None
        self._popen = popen
        self._rss_fn = rss_fn
        self._insecurity_reasons: list[str] = []

    @property
    def secure(self) -> bool:
        return not self._insecurity_reasons

    @property
    def insecurity_reasons(self) -> list[str]:
        return list(self._insecurity_reasons)

    def run(self, request: SandboxRequest) -> SandboxResult:
        # The detonation this run is part of, read at its START: credited only if the run also
        # finishes while that ledger is open (see ConfinementLedger).
        ledger = current_ledger()
        if not isinstance(request.argv, list) or not request.argv:
            raise SandboxError("argv must be a non-empty list of strings")
        if request.limits.net_egress:
            _log.warning(
                "seatbelt: net_egress requested but macOS has no egress rooter; "
                "network stays DENIED (fail-closed)"
            )
        exe, exe_real = mc.resolve_executable(request.argv[0])
        ro = [str(Path(m.source).resolve(strict=True)) for m in request.ro_mounts]
        rw = [str(Path(m.source).resolve(strict=True)) for m in request.rw_mounts]
        for m in (*request.ro_mounts, *request.rw_mounts):
            if Path(m.target) != Path(m.source):
                # No mount namespace: the child sees real paths. Silently ignoring a
                # remap would hand the engine a path that does not exist inside.
                raise SandboxError(
                    f"seatbelt supports identity mounts only (source == target): {m}"
                )
        _check_ro_rw_disjoint(ro, rw)
        # Nothing writable may hold the executable (or its .app/.framework bundle): the grant is
        # the host tree itself, so a change would be executed by every later run.
        mc.check_writable_clear_of_exec(
            [*(("rw mount", Path(m.source)) for m in request.rw_mounts),
             *([("capture_home", request.capture_home)] if request.capture_home is not None
               else [])],
            [request.argv[0], exe, exe_real], [], "seatbelt")
        # The seed and capture directories against the mounts: a writable mount over the
        # seed lets the child poison later runs' seeds; a capture over any mount replaces it.
        mc.check_homes_clear_of_mounts(request.seed_home, request.capture_home, ro, rw,
                                       "seatbelt")
        # The workers' shared lock and cleanup state (mc.internal_state_dirs): a writable grant
        # there would let the child release another run's lock or forge a cleanup record, and
        # a seed or capture there would copy, or replace, files other runs hold.
        # A read-only grant there would let it read the cleanup records (and so the tags that
        # authenticate them) and every run's claims.
        homes = [(what, Path(p_)) for what, p_ in (("seed_home", request.seed_home),
                                                    ("capture_home", request.capture_home))
                 if p_ is not None]
        mounts = [*(("ro mount", Path(p)) for p in ro), *(("rw mount", Path(p)) for p in rw)]
        mc.check_clear_of_state([*mounts, *homes], "seatbelt")
        # Nor ~/Library/Containers as a whole: a grant there reaches every App Sandbox slot's
        # Data, with other runs' caches and job state.
        mc.check_clear_of_containers([*mounts, *homes], "seatbelt")
        # Nor any App Sandbox root of this user (mc.protected_roots): a grant there reaches
        # other jobs' staged io/ro state and their slot locks.
        mc.check_clear_of_roots([*mounts, *homes], "seatbelt")
        # A mount that holds the scratch root would grant the child every concurrent run's
        # scratch (each 0700, but same-UID): a writable one to change them (and the sweep's
        # restore point for its own), a read-only one to read their inputs, caches and output.
        # The scratch root, resolved ONCE: the spelling (BLASTBOX_MACOS_SCRATCH_DIR, or the
        # system temp dir) can run through a symlink a concurrent run's writable mount holds,
        # which it could re-point between this check and the scratch's creation. Everything
        # below uses `base`, and the scratch is created through a descriptor pinned to it.
        base_given = Path(os.path.abspath(os.path.expanduser(
            self._scratch_base if self._scratch_base is not None else tempfile.gettempdir())))
        if self._scratch_base is not None:
            base_given.mkdir(parents=True, exist_ok=True)
        base = Path(os.path.realpath(base_given))
        for what, p in mounts:
            if p == base or p in base.parents:
                raise SandboxError(f"seatbelt: {what} {p} contains the scratch root {base}; "
                                   "mount a narrower directory")
        # A seed that is or holds the scratch root would reach the run's own scratch (created
        # inside it) while being copied into it, copying the growing copy into itself until a
        # limit stops it; a capture there would swap the scratch root (every run's) aside.
        # Checked before the scratch exists. A path INSIDE the root is only the scratch's
        # sibling, which is harmless (the default root is the system temp dir).
        for what, p_ in (("seed_home", request.seed_home), ("capture_home", request.capture_home)):
            if p_ is None:
                continue
            rp = Path(p_).expanduser().resolve()
            if rp == base or rp in base.parents:
                raise SandboxError(f"seatbelt: {what} {p_} contains the scratch root {base}; "
                                   "use a path outside it")

        # This run's own emergency cleanup (the agent retiring mid-run skips every `finally`
        # below), registered before the scratch exists and dropped only after it is removed:
        # run_confined's covers the child's lifetime, this one the teardown after it -- the
        # capture, the handshake, the scratch wipe. It sweeps the scratch's writers, removes a
        # capture left half-built beside its destination, and removes the scratch.
        leftovers = mc.Leftovers()
        state: dict[str, Path] = {}
        sweep_after = time.time() - 1.0

        def _emergency() -> None:
            scratch_ = state.get("scratch")
            try:
                if scratch_ is not None:
                    mc.sweep_writers(scratch_, started_after=sweep_after)
            finally:
                try:
                    leftovers.remove_all()
                finally:
                    if scratch_ is not None:
                        mc.wipe_dir(scratch_)
                        os.rmdir(scratch_)

        # The host paths this run uses, claimed in the registry both native backends share for
        # the whole run (through the capture swap): a writable mount is written in place (live),
        # a capture replaces its destination as a whole tree (write), a seed is copied as a
        # snapshot (read). An App Sandbox copy-back or another capture over a live mount would
        # discard the child's writes, and a seed taken while a tree is written or swapped would
        # be a mix of both -- so conflicting runs are refused (mc.hold_path_claims).
        # The scratch root is claimed too (`base`, both spellings): a live run whose writable
        # mount is or holds it -- or holds a link on the way to it -- could list, read or change
        # this run's scratch, or re-point the link under it; such a run is refused (and, while
        # this one lives, one that would be is). Runs writing INSIDE the root are unaffected.
        # Read-only mounts are claimed as `view` (a live read grant): they don't stop anyone
        # else's use of the tree, but one that is or holds ANOTHER run's scratch root would let
        # this child read that run's scratch -- so it conflicts with that run's `base`.
        claims = [*(("live", Path(p)) for p in rw),
                  *(("view", Path(p)) for p in ro),
                  *(("write", Path(p_)) for p_ in [request.capture_home] if p_ is not None),
                  *(("read", Path(p_)) for p_ in [request.seed_home] if p_ is not None),
                  ("base", base_given), ("base", base)]
        with mc.hold_path_claims(claims, "seatbelt"):
            # The path checks above can't see hard links: a file linked into a writable mount
            # AND somewhere else (a read-only mount, an input) would let the child edit it
            # through the writable name. Every name of a multiply-linked file must be inside the
            # writable mounts. Scanned with the claims held, so no snapshot writer (an App
            # Sandbox copy-back) can add such a link after the scan; the child itself can't
            # make one (the profile denies file-link).
            split = mc.find_split_hard_link([Path(p) for p in rw])
            if split is not None:
                raise SandboxError(f"seatbelt: writable mount file {split} has a hard link whose "
                                   "other name is outside the writable mounts; the child could "
                                   "change it through this one -- mount a copy instead")
            token = register_emergency_cleanup(_emergency)
            try:
                # Pinned by descriptor, every component opened no-follow: the scratch is made
                # in the directory that was checked and claimed, never by resolving the spelling
                # again. (Opened before the critical section: a refusal leaves nothing behind.)
                base_fd = mc.open_dir_no_follow(base)
                try:
                    # a section, so a shutdown signal on this thread can't fall between the lines
                    with teardown_critical():
                        scratch = mc.make_scratch_at(base_fd, base)
                        state["scratch"] = scratch
                finally:
                    os.close(base_fd)
                return self._run_in_scratch(request, exe, exe_real, ro, rw, scratch, leftovers,
                                            ledger)
            finally:
                unregister_emergency_cleanup(token)

    def _run_in_scratch(self, request: SandboxRequest, exe: Path, exe_real: Path,
                        ro: list[str], rw: list[str], scratch: Path,
                        leftovers: mc.Leftovers,
                        ledger: ConfinementLedger | None) -> SandboxResult:
        # What the run's scratch IS: a sweep that finds it removed or replaced puts an empty
        # directory back at the path (to find the run's processes), which must never be taken
        # for the run's own scratch -- not captured, not read for the handshake.
        scratch_id = self._dir_identity(scratch)
        confined = False
        try:
            mc.seed_scratch(scratch, request.seed_home, request.limits.tmpfs_bytes)
            profile, params = build_profile(
                exec_paths=sorted({str(exe), str(exe_real)}),
                ro_paths=ro,
                rw_paths=[*rw, str(scratch)],
                accelerators=request.accelerators,
                scratch=str(scratch),
            )
            argv = [self._sandbox_exec, "-p", profile]
            for key, val in params.items():
                argv += ["-D", f"{key}={val}"]
            nonce = secrets.token_hex(16)
            marker = scratch / HANDSHAKE_NAME
            argv += ["--", *shim_argv(nonce, str(marker), [str(exe), *request.argv[1:]])]
            env = mc.build_child_env(scratch, request.env)
            # Slack for clock granularity; the scratch-write check is what scopes the match.
            launched = time.time() - 1.0
            result = mc.run_confined(
                argv, env=env, limits=request.limits, cwd=scratch,
                popen=self._popen, rss_fn=self._rss_fn,
                watch_dirs=[scratch, *(Path(p) for p in rw)],
                sweep=lambda: mc.sweep_writers(scratch, started_after=launched),
                member_fn=mc.writer_matcher(scratch, started_after=launched),
            )
            # The handshake proves a process ran under the profile (not a failure before launch,
            # nor a profile sandbox-exec rejected). Read -- and removed, so it is never captured
            # -- now; credited only at the end.
            intact = self._dir_identity(scratch) == scratch_id
            handshake = intact and self._handshake_ok(marker, nonce)
            ok = result.exit_code == 0 and not result.killed
            if ok and request.capture_home is not None and not intact:
                # The profile pins the scratch root, so only a broken profile gets here; never
                # capture the empty stand-in over the caller's cache (a later warmup would seed
                # from it).
                raise SandboxError(f"seatbelt: refusing to capture {scratch}: the run removed "
                                   "or replaced its scratch dir")
            if ok:
                mc.capture_scratch(scratch, request.capture_home, request.limits.tmpfs_bytes,
                                   leftovers)
            # Counted only for a run that reached the profile AND completed, and only after the
            # scratch removal below succeeded: an engine that falls back to an in-process parse
            # after a failed, killed or uncleanable sandboxed run must not pass it off as confined.
            confined = handshake and ok
            if not handshake:
                _log.warning("seatbelt: no handshake from inside the profile; run not counted "
                             "as confined (exit %s)", result.exit_code)
            return result
        finally:
            # The same unlock-and-verify wipe as a reused slot: a child can lock files or dirs
            # in its scratch. If it can't be removed, the run fails rather than leaving it.
            try:
                mc.wipe_dir(scratch)
                os.rmdir(scratch)
            except (SandboxError, OSError) as exc:
                raise SandboxError(
                    f"seatbelt: could not remove the run's scratch {scratch}: {exc}") from exc
            if confined:
                note_confined_run(ledger)

    @staticmethod
    def _dir_identity(path: Path) -> tuple[int, int] | None:
        """(device, inode) of the real directory at ``path``, or None if it is gone or is no
        longer a directory (a symlink, a file)."""
        try:
            st = os.lstat(path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino) if stat.S_ISDIR(st.st_mode) else None

    @staticmethod
    def _handshake_ok(marker: Path, nonce: str) -> bool:
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
                os.unlink(marker)       # never captured into a seed
        return got == nonce.encode()


def sandbox_exec_available() -> bool:
    return mc.IS_DARWIN and shutil.which("sandbox-exec", path="/usr/bin") is not None
