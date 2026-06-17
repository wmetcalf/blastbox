"""Docker runtime selection and worker container command assembly.

Public surface:
- ``RuntimeSelection`` — frozen dataclass describing the chosen runtime.
- ``InsecureRuntimeRefused`` — raised when a secure runtime is required but
  only an insecure one is available.
- ``select_worker_runtime`` — detect or accept injected runtimes, prefer
  runsc, honor BLASTBOX_WORKER_RUNTIME override, fail-closed when required.
- ``build_worker_docker_run_argv`` — assemble a narrow, fully-hardened
  ``docker run`` argv (a list[str] — no shell=True, no string commands).

Security properties (review WILL check these):
1. argv is ALWAYS a Python list.  No caller/job value (image, paths,
   container_name, labels, extra_env) can introduce a NEW flag: extra_env →
   single ``-e KEY=VALUE`` tokens; mounts → ``--mount type=bind,...`` single
   tokens; a value like ``K=V; --privileged`` appears as ONE token and
   ``--privileged`` is NOT a standalone argv element.
2. Every hardening flag present unconditionally: ``--rm``, ``--runtime=…``,
   ``--user UID:GID``, ``--network=none``, ``--cap-drop=ALL``,
   ``--security-opt=no-new-privileges``, ``--read-only``, ``--memory`` +
   ``--memory-swap`` (swap disabled = equal), ``--pids-limit``, ``--cpus``,
   ``--ulimit nofile``, input bind ``:readonly``, output bind (rw),
   ``--tmpfs /tmp:…,nosuid,noexec``.
3. Fail-closed BY DEFAULT: an insecure runtime (plain ``runc`` — no gVisor) is
   REFUSED unless the operator explicitly opts in with ``BLASTBOX_ALLOW_RUNC=1``.
   ``BLASTBOX_REQUIRE_SECURE_RUNTIME`` is a hard lockdown that refuses ``runc``
   even when the opt-in is present. Both raise ``InsecureRuntimeRefused`` early
   (a clear, actionable error) rather than letting the worker fail opaquely later.
4. ``-e BLASTBOX_WARN_ON_INSECURE=1`` is set under runsc (gVisor virtualises
   /proc, so the worker's self-check can't see the host-applied flags) AND under
   an opted-in ``runc`` run (so the deliberately-degraded worker runs its
   sandbox self-check leniently instead of aborting opaquely).
5. Optional MAC layers attached only if the operator wired host paths
   (``BLASTBOX_SECCOMP_JSON_HOST`` → ``--security-opt seccomp=<path>``;
   apparmor profile if loaded) — else record a warning, don't fail.
6. Runtime detection via ``docker info --format '{{json .Runtimes}}'``; on
   any error return empty set (caller's fail-closed logic decides).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from blastbox.errors import SandboxError


_log = logging.getLogger("blastbox.host.runtime.docker")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InsecureRuntimeRefused(SandboxError):
    """Raised when a secure runtime is required but only an insecure one exists.

    The dispatcher catches this and fails the job (fail-closed) instead of
    silently processing untrusted input under plain runc.
    """


# ---------------------------------------------------------------------------
# RuntimeSelection dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuntimeSelection:
    """Immutable record of the chosen Docker runtime.

    ``warnings`` is a list so it can be appended to by ``build_worker_docker_run_argv``
    after the selection is made (e.g. "seccomp profile not configured").
    Because the dataclass is frozen the *list object* cannot be replaced, but
    its contents can be extended — the append() calls below use that intentionally.
    """

    runtime: str        # "runsc" | "runc"
    secure: bool
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Warning/error message constants
# ---------------------------------------------------------------------------

_RUNSC_WARNING = "runsc unavailable; falling back to runc (insecure)"
_APPARMOR_WARNING = (
    "blastbox AppArmor profile not loaded; worker runs under docker-default"
)
_SECCOMP_WARNING = (
    "BLASTBOX_SECCOMP_JSON_HOST not set; worker runs under docker-default seccomp"
)
_NONO_SKIP_RUNSC_WARNING = (
    "BLASTBOX_WORKER_NONO_WRAP set but skipped under runsc: the gVisor Sentry does not "
    "implement Landlock (ENOSYS), so nono cannot enforce there — gVisor is the boundary"
)

# Optional outer nono (Landlock) wrap of the WHOLE worker command (cold path). Opt-in via
# BLASTBOX_WORKER_NONO_WRAP; Landlock-gated (runc + the FC guest, NOT runsc). A profile
# (BLASTBOX_WORKER_NONO_PROFILE) is preferred; otherwise a coarse write-confinement baseline
# (read system dirs, write only /tmp + the output mount + /dev, block net). nono's state goes
# on a dedicated tmpfs OFF the grants (the read-only worker rootfs has only /tmp writable, and
# /tmp is itself granted — so state can't live there).
_DEFAULT_WORKER_NONO_BIN = "/usr/local/bin/nono"
_DEFAULT_NONO_STATE_DIR = "/run/nono"
# Read-only roots a worker needs (engine install lands in /opt or /usr; fonts in /usr/share).
_NONO_RO_ROOTS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/var", "/proc", "/sys")

# ---------------------------------------------------------------------------
# Worker resource-cap defaults.  Overridable via BLASTBOX_WORKER_* env vars.
# ---------------------------------------------------------------------------

_DEFAULT_WORKER_MEMORY = "4g"
_DEFAULT_WORKER_PIDS_LIMIT = "256"
_DEFAULT_WORKER_CPUS = "1.0"
_DEFAULT_WORKER_NOFILE = "4096"

# 512m: headroom for large documents plus engine scratch files.
_DEFAULT_TMPFS = "/tmp:rw,nosuid,noexec,size=512m"

# Default UID/GID for the worker process inside the container.
_DEFAULT_WORKER_UID = 10001
_DEFAULT_WORKER_GID = 10001

# Default working directory inside the container.  /tmp is always present
# (it's the writable tmpfs mount) and avoids fragility around --read-only and
# auto-created non-existent workdir paths across runtimes.
_DEFAULT_WORKDIR = "/tmp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_secure_runtime() -> bool:
    """Return True when BLASTBOX_REQUIRE_SECURE_RUNTIME is set to a truthy value.

    Hard lockdown: refuses an insecure runtime even if BLASTBOX_ALLOW_RUNC is also set.
    """
    val = os.environ.get("BLASTBOX_REQUIRE_SECURE_RUNTIME", "0").strip().lower()
    return val not in ("", "0", "false", "no")


def _allow_runc() -> bool:
    """Return True when BLASTBOX_ALLOW_RUNC is set to a truthy value.

    The operator's EXPLICIT opt-in to run workers under plain ``runc`` (no gVisor
    isolation). Absent, an insecure runtime is refused fail-closed.
    """
    val = os.environ.get("BLASTBOX_ALLOW_RUNC", "0").strip().lower()
    return val not in ("", "0", "false", "no")


def _normalize_runtimes(runtimes: Iterable[str]) -> set[str]:
    return {
        str(r).strip().lower() for r in runtimes if str(r).strip()
    }


def _detect_docker_runtimes() -> set[str]:
    """Query ``docker info`` for available runtimes.

    Returns an empty set on any error — the caller's fail-closed logic handles
    the absence of a secure runtime.
    """
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return set()

    if proc.returncode != 0:
        return set()

    raw = proc.stdout.strip()
    if not raw:
        return set()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return set()

    if isinstance(parsed, dict):
        return _normalize_runtimes(parsed.keys())
    if isinstance(parsed, list):
        return _normalize_runtimes(parsed)
    return set()


def _apparmor_profile_loaded(profile_name: str) -> bool:
    """Check whether the named AppArmor profile is loaded on the host.

    Two probe paths, in order:

    1. Explicit operator assertion via ``BLASTBOX_APPARMOR_PROFILES`` env var
       (comma-separated list of loaded profile names).  Use this when the
       dispatcher runs inside a container that doesn't bind-mount
       ``/sys/kernel/security``.

    2. Direct read of ``/sys/kernel/security/apparmor/profiles``.  Works on
       bare metal and in containers that bind-mount securityfs.
    """
    listed = os.environ.get("BLASTBOX_APPARMOR_PROFILES", "")
    if listed:
        names = {x.strip() for x in listed.split(",") if x.strip()}
        if profile_name in names:
            return True
    try:
        with open("/sys/kernel/security/apparmor/profiles") as f:
            for line in f:
                name = line.split(" ", 1)[0].strip()
                if name == profile_name:
                    return True
    except OSError:
        return False
    return False


# ---------------------------------------------------------------------------
# Runtime selection
# ---------------------------------------------------------------------------

def _finalize_runtime(selection: RuntimeSelection) -> RuntimeSelection:
    """Enforce the fail-closed-by-default runtime policy.

    An insecure runtime (plain ``runc`` — no gVisor isolation) is refused EARLY with an
    actionable :class:`InsecureRuntimeRefused`, rather than letting the worker container
    start and then fail its own sandbox self-check opaquely. It is allowed ONLY when the
    operator explicitly opts in via ``BLASTBOX_ALLOW_RUNC=1`` — and ``BLASTBOX_REQUIRE_SECURE_RUNTIME``
    is a hard lockdown that refuses it even then.
    """
    if not selection.secure:
        if _require_secure_runtime():
            raise InsecureRuntimeRefused(
                f"runtime {selection.runtime!r} is insecure (gVisor/runsc unavailable) and "
                "BLASTBOX_REQUIRE_SECURE_RUNTIME is set; refusing to process the job."
            )
        if not _allow_runc():
            raise InsecureRuntimeRefused(
                f"runtime {selection.runtime!r} is insecure: gVisor/runsc is unavailable, so the "
                "worker would run WITHOUT gVisor isolation. Install/enable the runsc (gVisor) "
                "Docker runtime, or set BLASTBOX_ALLOW_RUNC=1 to run in EXPLICIT degraded mode "
                "under plain runc."
            )
    return selection


def select_worker_runtime(
    *,
    available_runtimes: Iterable[str] | None = None,
) -> RuntimeSelection:
    """Select the preferred Docker runtime for one-shot worker containers.

    Detection order:
    1. ``BLASTBOX_WORKER_RUNTIME`` env var forces a specific runtime.
    2. Injected ``available_runtimes`` or ``_detect_docker_runtimes()`` is
       searched for ``runsc`` (preferred) then ``runc`` (fallback).
    3. If fail-closed policy is active (``BLASTBOX_REQUIRE_SECURE_RUNTIME``
       truthy) and the chosen runtime is not secure, ``InsecureRuntimeRefused``
       is raised.

    Parameters
    ----------
    available_runtimes:
        Inject a runtime name iterable for testing; ``None`` → live detection
        via ``docker info``.
    """
    runtimes = (
        _normalize_runtimes(available_runtimes)
        if available_runtimes is not None
        else _detect_docker_runtimes()
    )

    # Operator override: BLASTBOX_WORKER_RUNTIME=runc|runsc forces the worker
    # runtime regardless of auto-detection.
    forced = os.environ.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower()
    if forced in ("runc", "runsc"):
        secure = forced == "runsc"
        warnings: list[str] = [] if secure else [_RUNSC_WARNING]
        return _finalize_runtime(
            RuntimeSelection(runtime=forced, secure=secure, warnings=warnings)
        )

    if "runsc" in runtimes:
        return _finalize_runtime(
            RuntimeSelection(runtime="runsc", secure=True, warnings=[])
        )

    _log.warning(
        _RUNSC_WARNING,
        extra={"available_runtimes": sorted(runtimes)},
    )
    return _finalize_runtime(
        RuntimeSelection(runtime="runc", secure=False, warnings=[_RUNSC_WARNING])
    )


# ---------------------------------------------------------------------------
# argv builder
# ---------------------------------------------------------------------------

# The AppArmor profile name to request for worker containers.
_WORKER_APPARMOR_PROFILE = "blastbox-worker"


def _nono_launch_wrap(
    worker_argv: Sequence[str],
    *,
    nono_bin: str,
    profile: str,
    state_dir: str,
    input_mount_path: str,
    output_mount_path: str,
) -> list[str]:
    """Wrap a worker command in ``nono wrap`` (Landlock). Returns the new command.

    Shape: ``env HOME=<state> nono wrap <grants> --block-net -- env HOME=/tmp <worker>``.
    The outer ``env`` relocates nono's own $HOME/.nono state onto a dedicated tmpfs OFF
    the grants; the inner ``env HOME=/tmp`` restores the worker's HOME while inheriting the
    rest of the container env. Every grant source is a value arg after its flag — no caller
    value lands in a flag position (the module's security contract). A profile (``-p``) is
    preferred; otherwise a coarse write-confinement baseline.
    """
    grants: list[str] = []
    if profile:
        grants += ["-p", profile]
    else:
        for d in _NONO_RO_ROOTS:
            grants += ["-r", d]
        grants += ["-a", "/tmp", "-a", "/dev", "-a", output_mount_path,
                   "--read-file", input_mount_path]
    return [
        "/usr/bin/env", f"HOME={state_dir}",
        nono_bin, "wrap", "--silent", *grants, "--block-net", "--",
        "/usr/bin/env", "HOME=/tmp", *worker_argv,
    ]


def build_worker_docker_run_argv(
    *,
    image: str,
    input_path: Path,
    input_mount_path: str,
    output_dir: Path,
    output_mount_path: str,
    worker_argv: Sequence[str],
    runtime: RuntimeSelection,
    network_args: list[str] | None = None,
    resolv_conf_src: str | None = None,
    container_name: str | None = None,
    worker_uid: int = _DEFAULT_WORKER_UID,
    worker_gid: int = _DEFAULT_WORKER_GID,
    workdir: str = _DEFAULT_WORKDIR,
    labels: Mapping[str, str] | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> list[str]:
    """Build a narrow, hardened ``docker run`` argv for a single worker job.

    **Security contract** (argv is a list[str] — no shell=True):

    * Every argument that originates from caller-supplied data (image, paths,
      container_name, labels, extra_env values) lands in a *value position*
      — never a *flag position*.  ``extra_env`` items become single
      ``-e KEY=VALUE`` tokens; ``--mount`` specs are single tokens; nothing
      can inject a new standalone flag element.
    * All hardening flags are present unconditionally.
    * gVisor virtualises /proc so in-container hardening self-checks (which
      read ``/proc/self/status``) can't observe docker's ``--security-opt``
      flags even though they ARE applied at the host level.  Under runsc we
      therefore opt the worker into ``BLASTBOX_WARN_ON_INSECURE=1`` so it
      doesn't falsely abort on its own self-check.
    * Under an insecure runtime (plain ``runc``) we ALSO set
      ``BLASTBOX_WARN_ON_INSECURE=1`` — but this path is reachable only after the
      operator explicitly opted in via ``BLASTBOX_ALLOW_RUNC=1`` (``select_worker_runtime``
      refuses runc otherwise), so the worker runs its self-check in DELIBERATE degraded
      mode instead of aborting opaquely. The honest insecurity is surfaced by the
      ``RuntimeSelection.warnings`` recorded at selection time.
    """
    bind_input = str(Path(input_path).expanduser().resolve(strict=False))
    bind_output = str(Path(output_dir).expanduser().resolve(strict=False))

    # Resource caps.  Each env var, if set to a NON-EMPTY value, overrides the default.
    # Use ``get(K) or default`` (not ``get(K, default)``): docker-compose passes
    # ``BLASTBOX_WORKER_MEMORY=${BLASTBOX_WORKER_MEMORY:-}`` which sets the var to the EMPTY
    # string when the operator leaves it unset — and ``get(K, default)`` returns that ""
    # (the key exists), yielding a bare ``--memory '' --cpus '' --pids-limit ''`` that makes
    # ``docker run`` fail at launch with ``invalid argument "" for "--memory"`` (RC 125), which
    # the cold path's ``check=False`` swallows into an opaque "metadata.json not found". Treat
    # set-but-empty — AND set-but-whitespace-only (e.g. ``BLASTBOX_WORKER_MEMORY=" "`` from a
    # malformed env file) — as unset; both would otherwise reach ``docker run`` as an invalid arg.
    memory = (os.environ.get("BLASTBOX_WORKER_MEMORY") or "").strip() or _DEFAULT_WORKER_MEMORY
    pids_limit = (
        os.environ.get("BLASTBOX_WORKER_PIDS_LIMIT") or ""
    ).strip() or _DEFAULT_WORKER_PIDS_LIMIT
    cpus = (os.environ.get("BLASTBOX_WORKER_CPUS") or "").strip() or _DEFAULT_WORKER_CPUS
    nofile = (os.environ.get("BLASTBOX_WORKER_NOFILE") or "").strip() or _DEFAULT_WORKER_NOFILE

    # Tell the worker's sandbox self-check to be lenient. Under runsc that's because
    # /proc doesn't reflect the host-applied flags (still secure); under an insecure
    # runtime it's a DELIBERATE degraded run (reachable only after BLASTBOX_ALLOW_RUNC,
    # which select_worker_runtime requires) so the worker doesn't abort opaquely.
    warn_on_insecure: str | None = None
    if runtime.runtime == "runsc" or not runtime.secure:
        warn_on_insecure = "1"

    # Optional outer nono (Landlock) wrap of the whole worker command — opt-in via
    # BLASTBOX_WORKER_NONO_WRAP, Landlock-gated. The gVisor Sentry returns ENOSYS for the
    # landlock_* syscalls, so under runsc it is SKIPPED + warned (gVisor is already the
    # boundary); runc + the FC guest expose Landlock and enforce it.
    nono_enabled = (os.environ.get("BLASTBOX_WORKER_NONO_WRAP") or "").strip().lower() \
        not in ("", "0", "false", "no")
    apply_nono = False
    nono_state_dir = (
        os.environ.get("BLASTBOX_WORKER_NONO_STATE_DIR") or ""
    ).strip() or _DEFAULT_NONO_STATE_DIR
    if nono_enabled:
        if runtime.runtime == "runsc":
            runtime.warnings.append(_NONO_SKIP_RUNSC_WARNING)
        else:
            apply_nono = True

    # ------------------------------------------------------------------
    # Core hardened argv — every flag is unconditional.
    # ------------------------------------------------------------------
    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        f"--runtime={runtime.runtime}",
        "--user",
        f"{worker_uid}:{worker_gid}",
        *(network_args if network_args is not None else ["--network=none"]),
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--memory",
        memory,
        "--memory-swap",
        memory,          # disable swap: memory-swap == memory
        "--pids-limit",
        pids_limit,
        "--cpus",
        cpus,
        "--ulimit",
        f"nofile={nofile}:{nofile}",
        # Self-check leniency env: set under runsc (/proc opt-in) AND under an
        # opted-in insecure runtime (deliberate degraded run); absent otherwise.
        *(["-e", f"BLASTBOX_WARN_ON_INSECURE={warn_on_insecure}"]
          if warn_on_insecure is not None else []),
        "-e",
        "HOME=/tmp",
        "--tmpfs",
        _DEFAULT_TMPFS,
        "--mount",
        f"type=bind,src={bind_input},dst={input_mount_path},readonly",
        "--mount",
        f"type=bind,src={bind_output},dst={output_mount_path}",
        # Optional: pin /etc/resolv.conf to a real resolver for an egress personality. On a
        # docker user-defined bridge the generated resolv.conf names only the embedded resolver
        # 127.0.0.11, which a gVisor (runsc) worker can't reach — so egress workers get L3 but
        # no DNS. Docker honors an explicit /etc/resolv.conf bind-mount (does not overwrite it),
        # so this restores DNS under runsc and is a no-op under runc. Read-only; value position.
        *(
            ["--mount", f"type=bind,src={resolv_conf_src},dst=/etc/resolv.conf,readonly"]
            if resolv_conf_src
            else []
        ),
        "--workdir",
        workdir,
    ]

    # Dedicated writable tmpfs for nono's state, OFF the grants (the worker rootfs is
    # read-only and /tmp is itself granted, so nono's $HOME/.nono can't live there).
    if apply_nono:
        argv.extend(["--tmpfs", f"{nono_state_dir}:rw,nosuid,nodev,size=32m"])

    # ------------------------------------------------------------------
    # Optional AppArmor profile (if loaded on the host kernel).
    # The host operator must load it ahead of time; we can't load profiles
    # from inside a cap-dropped container.
    # ------------------------------------------------------------------
    if _apparmor_profile_loaded(_WORKER_APPARMOR_PROFILE):
        argv.extend(["--security-opt", f"apparmor={_WORKER_APPARMOR_PROFILE}"])
    else:
        runtime.warnings.append(_APPARMOR_WARNING)

    # ------------------------------------------------------------------
    # Optional seccomp profile.
    # Docker reads --security-opt=seccomp=<path> from the HOST filesystem,
    # not the dispatcher's filesystem.  The operator must:
    #   1. mount the seccomp JSON to a host-readable path, and
    #   2. set BLASTBOX_SECCOMP_JSON_HOST to that host path.
    # If not set, docker-default seccomp still applies (blocks the most
    # dangerous syscalls).  A wrong path causes `docker run` to fail with
    # a clear error at launch time.
    # ------------------------------------------------------------------
    seccomp_host_path = os.environ.get("BLASTBOX_SECCOMP_JSON_HOST", "").strip()
    if seccomp_host_path:
        argv.extend(["--security-opt", f"seccomp={seccomp_host_path}"])
    else:
        runtime.warnings.append(_SECCOMP_WARNING)

    # ------------------------------------------------------------------
    # Caller-supplied extra_env — each entry becomes a SINGLE -e K=V token.
    # A value like "V; --privileged" arrives as ONE string and cannot split
    # into a new standalone flag element.
    # ------------------------------------------------------------------
    for name, value in (extra_env or {}).items():
        argv.extend(["-e", f"{name}={value}"])

    # ------------------------------------------------------------------
    # Optional container metadata — each stays a single value token.
    # ------------------------------------------------------------------
    if container_name:
        argv.extend(["--name", container_name])

    for key, value in (labels or {}).items():
        argv.extend(["--label", f"{key}={value}"])

    # ------------------------------------------------------------------
    # Image (single token — value position, after all flags).
    # ------------------------------------------------------------------
    argv.append(image)

    # ------------------------------------------------------------------
    # Worker command — verbatim, OR wrapped in `nono wrap` (opt-in, Landlock-gated).
    # ------------------------------------------------------------------
    if apply_nono:
        nono_bin = (
            os.environ.get("BLASTBOX_WORKER_NONO_BIN") or ""
        ).strip() or _DEFAULT_WORKER_NONO_BIN
        nono_profile = (os.environ.get("BLASTBOX_WORKER_NONO_PROFILE") or "").strip()
        argv.extend(
            _nono_launch_wrap(
                worker_argv,
                nono_bin=nono_bin,
                profile=nono_profile,
                state_dir=nono_state_dir,
                input_mount_path=input_mount_path,
                output_mount_path=output_mount_path,
            )
        )
    else:
        argv.extend(worker_argv)

    return argv
