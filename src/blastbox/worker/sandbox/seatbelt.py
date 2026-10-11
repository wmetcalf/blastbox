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
that asked for it is logged.

``sandbox-exec(1)`` is marked deprecated, but it is the documented front-end to the same
Sandbox.kext that App Sandbox, Chrome and Safari's helpers use, and ships in macOS 26. If it
disappears, :func:`select_sandbox` falls back to the ``appsandbox`` backend (or refuses).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, note_confined_run
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

        scratch = mc.make_scratch(self._scratch_base)
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
            argv += ["--", str(exe), *request.argv[1:]]
            env = mc.build_child_env(scratch, request.env)
            # Slack for clock granularity; the scratch-write check is what scopes the sweep.
            launched = time.time() - 1.0
            result = mc.run_confined(
                argv, env=env, limits=request.limits, cwd=scratch,
                popen=self._popen, rss_fn=self._rss_fn,
                watch_dirs=[scratch, *(Path(p) for p in rw)],
                sweep=lambda: mc.sweep_writers(scratch, started_after=launched),
            )
            # Counted only once a sandboxed process actually ran: a failure before this point
            # (bad seed, Popen error) must not let an engine's in-process fallback pass as confined.
            note_confined_run()
            if result.exit_code == 0 and not result.killed:
                mc.capture_scratch(scratch, request.capture_home, request.limits.tmpfs_bytes)
            return result
        finally:
            mc.remove_tree(scratch)


def sandbox_exec_available() -> bool:
    return mc.IS_DARWIN and shutil.which("sandbox-exec", path="/usr/bin") is not None
