"""Bubblewrap-backed sandbox backend for the blastbox worker SDK.

``BubblewrapSandbox`` wraps the ``bwrap`` binary from the bubblewrap package.
It creates a new user/mount/PID/network/IPC namespace for each child process,
drops all capabilities, and enforces rlimits from :class:`~blastbox.limits.Limits`.

Security guarantees on every :meth:`run` call:

* ``shell=True`` is NEVER used; ``argv`` is always passed as a list.
* Mount source/target values are placed in value positions in the bwrap
  argument vector — never adjacent to flag positions — so no caller value
  can inject a bwrap flag.
* The ambient ``os.environ`` is NEVER inherited — the subprocess receives only
  a minimal env (``PATH``, ``HOME=/tmp``) plus ``request.env`` overlay.
* ``resource.setrlimit`` is applied in a ``preexec_fn`` so RLIMIT_AS /
  RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CPU are enforced in the child before
  it exec()s the target binary.
* A child that exceeds ``request.limits.timeout_s`` is killed with SIGKILL;
  ``SandboxResult.killed`` is set to ``True``.

``insecurity_reasons`` / ``secure`` property:

* ``seccomp_not_implemented`` — recorded ONLY when ``python3-libseccomp`` is absent so no BPF
  can be built (a distro pkg, not on PyPI). When present, this backend builds the same denylist
  the nsjail backend applies as KAFEL and installs it via ``bwrap --seccomp <fd>``; the reason is
  then dropped and bwrap can self-certify secure. Fail-safe: no lib ⇒ marked insecure.
* ``apparmor_missing`` — ``aa-exec`` helper is not found; no AppArmor profile
  can be attached to the child.
* ``pid_limit_missing`` — bwrap does not support ``--cgroup-pids``; the fork-bomb
  defence is degraded.

Any single reason makes ``secure == False``.
"""
from __future__ import annotations

import logging
import os
import resource
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Callable

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult


_log = logging.getLogger("blastbox.worker.sandbox.bwrap")

_BWRAP = shutil.which("bwrap") or "/usr/bin/bwrap"

# Default AppArmor profile to attach to the child process via aa-exec.
# Profile must be loaded on the host kernel.
_DEFAULT_APPARMOR_PROFILE = "blastbox-sandbox"


def _apparmor_profile_loaded(profile: str) -> bool:
    """True only if we can CONFIRM the named AppArmor profile is loaded.

    ``aa-exec`` against an *unloaded* profile fails the exec, which would break
    every ``run``. So attach it only when sure: an explicit
    ``BLASTBOX_APPARMOR_PROFILES`` (comma list) assertion wins; otherwise read
    the world-readable apparmor securityfs. Any uncertainty (securityfs
    unreadable, profile absent) → ``False`` → skip aa-exec and record
    ``apparmor_missing``, so the sandbox still functions (just less hardened)
    instead of failing outright.
    """
    asserted = os.environ.get("BLASTBOX_APPARMOR_PROFILES", "").strip()
    if asserted:
        return profile in {p.strip() for p in asserted.split(",") if p.strip()}
    try:
        with open("/sys/kernel/security/apparmor/profiles", encoding="ascii") as fh:
            return any(line.split(" ", 1)[0] == profile for line in fh)
    except OSError:
        return False

# Minimal safe environment passed to every child process.
# HOST os.environ is NEVER inherited.
_MINIMAL_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
}

# libseccomp Python bindings — the ``seccomp`` package from the distro's ``python3-libseccomp``
# (NOT the ``libseccomp`` PyPI package). When present, the bwrap backend builds a BPF denylist
# from it (seccomp_denylist.build_bpf_bytes) and installs it via ``bwrap --seccomp``; when absent
# we proceed without an in-process filter and record ``seccomp_not_implemented`` — no crash.
# _LIBSECCOMP_AVAILABLE is also the monkeypatch seam the tests use to force the branches.
try:  # pragma: no cover - import path depends on host
    import seccomp as _libseccomp  # type: ignore[import-not-found]
    _LIBSECCOMP_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in unit tests via monkeypatch
    _libseccomp = None  # type: ignore[assignment]
    _LIBSECCOMP_AVAILABLE = False


def _probe_bwrap_cgroup_pids(bwrap_path: str) -> bool:
    """Return True if this bwrap binary supports the --cgroup-pids flag."""
    try:
        r = subprocess.run(
            [bwrap_path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "--cgroup-pids" in r.stdout or "--cgroup-pids" in r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# On merged-usr systems (Ubuntu 22.04+, Debian 12+) /bin, /sbin, /lib,
# /lib64 are symlinks into /usr.  bwrap bind-mounts resolve the symlink
# but don't recreate it inside the new rootfs, so /bin etc. become
# dangling inside the sandbox.  We detect this at import time and emit
# --symlink stanzas so the sandbox rootfs has working paths.
_MERGED_USR_SYMLINKS: list[tuple[str, str]] = []
for _d in ("/bin", "/sbin", "/lib", "/lib64"):
    _p = Path(_d)
    if _p.is_symlink():
        _target = os.readlink(_d)
        _MERGED_USR_SYMLINKS.append((_target, _d))

# Read-only system directories to bind into the sandbox.  Symlinks are
# handled via _MERGED_USR_SYMLINKS above; we skip them here.
_RO_SYSTEM_DIRS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc")


class BubblewrapSandbox:
    """Sandbox backend that wraps the ``bwrap`` binary.

    Construction probes the host for capabilities (cgroup-pids, seccomp,
    AppArmor) and records any deficiencies in :attr:`insecurity_reasons`.
    No exception is raised — callers inspect :attr:`secure` and
    :attr:`insecurity_reasons` to decide whether to proceed.

    Parameters
    ----------
    bwrap_path:
        Path to the ``bwrap`` binary.  Defaults to the result of
        ``shutil.which("bwrap")``.
    apparmor_profile:
        AppArmor profile name to attach to the child via ``aa-exec``.
    """

    name = "bwrap"

    def __init__(
        self,
        bwrap_path: str = _BWRAP,
        *,
        apparmor_profile: str = _DEFAULT_APPARMOR_PROFILE,
    ) -> None:
        # Binary presence is RECORDED, not enforced at construction. The backend
        # stays constructible-for-inspection (secure / insecurity_reasons /
        # _build_argv) on hosts without bwrap installed — run() raises
        # SandboxUnavailable when the binary is actually needed.
        self._binary_present = bool(shutil.which(bwrap_path)) or Path(bwrap_path).exists()
        self._bwrap = bwrap_path
        self._apparmor_profile = apparmor_profile

        # AppArmor: attach via ``aa-exec -p <profile> --`` ONLY when the profile
        # is confirmed loaded AND the helper exists. aa-exec against an unloaded
        # profile fails the exec — which would break every run — so when the
        # profile can't be confirmed we skip aa-exec (and record apparmor_missing)
        # rather than break the sandbox.
        self._aa_exec: str | None = None
        if _apparmor_profile_loaded(self._apparmor_profile):
            self._aa_exec = shutil.which("aa-exec")
        if self._aa_exec is not None:
            _log.info(
                "bwrap_apparmor_attach_enabled aa_exec=%s profile=%s",
                self._aa_exec,
                self._apparmor_profile,
            )
        else:
            _log.warning(
                "bwrap_apparmor_attach_skipped reason=profile_not_confirmed_loaded "
                "profile=%s note=run_proceeds_without_apparmor",
                self._apparmor_profile,
            )

        # Fork-bomb defence: --cgroup-pids (bubblewrap >= 0.5.0, cgroup v2).
        # If absent, the container runtime's PID limit is the fallback.
        self._cgroup_pids_supported = _probe_bwrap_cgroup_pids(bwrap_path)
        if self._cgroup_pids_supported:
            _log.info("bwrap_cgroup_pids_enabled limit=256")
        else:
            _log.warning(
                "bwrap_fork_bomb_defense_degraded "
                "reason=--cgroup-pids_not_supported_by_installed_bwrap "
                "mitigation=container_runtime_pid_limits"
            )

        # Seccomp: build a DEFAULT-ALLOW + ERRNO denylist BPF via libseccomp — the SAME denylist
        # the nsjail backend applies as KAFEL (ERRNO(1) names + clone-namespace arg-filter + clone3
        # → ENOSYS; a parity test guards against drift) — and pass it per-run via bwrap
        # `--seccomp <fd>` (see run() / _build_argv). The filter installs behind bwrap's
        # PR_SET_NO_NEW_PRIVS (no privilege) and survives the aa-exec execve. Where
        # python3-libseccomp is absent (a distro pkg, not on PyPI) build_bpf_bytes() returns None
        # and we keep marking the seccomp axis insecure — fail-safe, so the gate never mistakes an
        # UNFILTERED bwrap for secure.
        from blastbox.worker.sandbox.seccomp_denylist import build_bpf_bytes

        # Gate on _LIBSECCOMP_AVAILABLE (the tests' monkeypatch seam) so False forces no-filter.
        self._seccomp_bpf = build_bpf_bytes() if _LIBSECCOMP_AVAILABLE else None
        self._seccomp_active = self._seccomp_bpf is not None
        if not self._seccomp_active:
            _log.warning(
                "bwrap_seccomp_unavailable impact=child_runs_without_syscall_filter "
                "fix=install_python3-libseccomp_or_use_nsjail_backend_or_set_BLASTBOX_WARN_ON_INSECURE"
            )

        self._insecurity_reasons: list[str] = []
        if not self._binary_present:
            self._insecurity_reasons.append("binary_missing")
        if not self._seccomp_active:
            # No BPF attached -> insecure on the seccomp axis (keep the historical reason string).
            self._insecurity_reasons.append("seccomp_not_implemented")
        if not self._aa_exec:
            self._insecurity_reasons.append("apparmor_missing")
        if not self._cgroup_pids_supported:
            self._insecurity_reasons.append("pid_limit_missing")

        _log.info(
            "BubblewrapSandbox initialised",
            extra={
                "seccomp_active": self._seccomp_active,
                "apparmor": self._aa_exec,
                "cgroup_pids": self._cgroup_pids_supported,
                "insecurity_reasons": self._insecurity_reasons,
            },
        )

    # ------------------------------------------------------------------
    # Properties

    @property
    def secure(self) -> bool:
        """``False`` if any insecurity reason is present."""
        return not bool(self._insecurity_reasons)

    @property
    def insecurity_reasons(self) -> list[str]:
        """Copy of the list of insecurity reason strings."""
        return list(self._insecurity_reasons)

    @property
    def seccomp_active(self) -> bool:
        return self._seccomp_active

    @property
    def apparmor_active(self) -> bool:
        return self._aa_exec is not None

    @property
    def cgroup_pids_supported(self) -> bool:
        return self._cgroup_pids_supported

    # ------------------------------------------------------------------
    # Public interface

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run ``request.argv`` inside a bwrap sandbox.

        Security invariants:
        - ``shell=True`` is NEVER used.
        - The subprocess environment is built from scratch; ``os.environ`` is
          NOT inherited.  The child only sees ``_MINIMAL_ENV`` + ``request.env``.
        - ``_make_apply_rlimits`` is called as ``preexec_fn`` so RLIMIT_AS /
          RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CPU are set in the child before exec.
        - A child exceeding ``request.limits.timeout_s`` is SIGKILL-ed.
        - ``argv`` must be a non-empty list (never a string).
        - Mount source/target are passed as bwrap value arguments; no caller
          value can inject a bwrap flag.
        """
        if not isinstance(request.argv, list) or not request.argv:
            raise SandboxError("argv must be a non-empty list of strings")
        if not self._binary_present:
            raise SandboxUnavailable(f"bwrap not found at {self._bwrap!r}")

        # A FRESH memfd per run holds the BPF program bwrap reads via --seccomp <fd>. pass_fds
        # keeps it open + inheritable across the close_fds=True fork; the parent closes its copy
        # in the finally (the child already inherited it at fork time).
        seccomp_fd: int | None = None
        try:
            # memfd setup is INSIDE the try so a failure (os.write/lseek) can't leak the fd —
            # the finally owns closing it once it's been assigned.
            if self._seccomp_bpf is not None:
                seccomp_fd = os.memfd_create("blastbox_seccomp", 0)
                os.write(seccomp_fd, self._seccomp_bpf)
                os.lseek(seccomp_fd, 0, os.SEEK_SET)
                os.set_inheritable(seccomp_fd, True)
            argv = self._build_argv(request, seccomp_fd=seccomp_fd)
            killed = False

            try:
                proc = subprocess.Popen(
                    argv,                      # list, never shell=True
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=() if seccomp_fd is None else (seccomp_fd,),
                    preexec_fn=_make_apply_rlimits(request.limits),
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                raise SandboxError(f"failed to start bwrap: {exc}") from exc

            try:
                stdout, stderr = proc.communicate(timeout=request.limits.timeout_s)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                killed = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    stdout, stderr = proc.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    stdout, stderr = b"", b""
                exit_code = -int(signal.SIGKILL)

            return SandboxResult(
                exit_code=exit_code,
                stdout=stdout or b"",
                stderr=stderr or b"",
                killed=killed,
            )
        finally:
            if seccomp_fd is not None:
                os.close(seccomp_fd)

    # ------------------------------------------------------------------
    # Internal

    def _build_argv(self, req: SandboxRequest, *, seccomp_fd: int | None = None) -> list[str]:
        """Build the full bwrap argument vector for ``req``.

        All mount source/target paths are placed as value arguments after
        their respective flag tokens.  No shell expansion or concatenation
        is used, so no caller-supplied value can inject a bwrap flag.
        """
        argv: list[str] = [
            self._bwrap,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--tmpfs", "/run",
            "--cap-drop", "ALL",
        ]
        # Network namespace. `--unshare-all` already unshares net; by default we ALSO pass the
        # explicit `--unshare-net` (isolated, fail-closed). When the worker's netpolicy grants an
        # exit (limits.net_egress), RETAIN the parent netns with `--share-net` (undoes the net part
        # of `--unshare-all`) so the process rides the worker's rooter-routed netns and the
        # host-side rooter can steer its egress.
        argv.append("--share-net" if req.limits.net_egress else "--unshare-net")

        # Bind read-only system directories; skip symlinks (handled below).
        for d in _RO_SYSTEM_DIRS:
            p = Path(d)
            if p.is_symlink():
                continue
            if p.exists():
                argv += ["--ro-bind", d, d]

        # Recreate merged-usr symlinks inside the sandbox rootfs.
        for target, link in _MERGED_USR_SYMLINKS:
            argv += ["--symlink", target, link]

        # Caller-supplied ro/rw mounts — source/target in value positions only.
        for m in req.ro_mounts:
            argv += ["--ro-bind", str(m.source), str(m.target)]
        for m in req.rw_mounts:
            argv += ["--bind", str(m.source), str(m.target)]

        # Fork-bomb defence via cgroup PIDs limit (bubblewrap >= 0.5.0).
        if self._cgroup_pids_supported:
            argv += ["--cgroup-pids", "256"]

        # Environment: --clearenv was already passed; now inject values.
        # _MINIMAL_ENV is baked in via --setenv so the child never inherits
        # os.environ.  request.env overlays any engine-specific additions.
        for k, v in {**_MINIMAL_ENV, **req.env}.items():
            argv += ["--setenv", k, v]

        # Install the seccomp BPF (the inherited memfd from run()) — must precede the `--`.
        if seccomp_fd is not None:
            argv += ["--seccomp", str(seccomp_fd)]

        argv += ["--"]

        # AppArmor: prefix inner argv with ``aa-exec -p <profile> --``.
        # If the profile is not loaded on the host kernel, aa-exec errors
        # out loudly rather than silently running unconfined.
        inner: list[str] = list(req.argv)
        if self._aa_exec is not None:
            inner = [self._aa_exec, "-p", self._apparmor_profile, "--", *inner]
        argv += inner
        return argv


# ------------------------------------------------------------------
# Shared rlimit helper


def _make_apply_rlimits(limits: Limits) -> Callable[[], None]:
    """Return a ``preexec_fn`` that applies rlimits inside the child process.

    Called after ``fork()`` but before ``exec()`` in the child.  Any failure
    to set a limit is silently swallowed (best-effort) so a missing/too-high
    ceiling on a particular platform doesn't prevent the child from starting.
    """
    memory_bytes = limits.memory_bytes
    tmpfs_bytes = limits.tmpfs_bytes
    timeout_s = limits.timeout_s

    def _set() -> None:
        # Virtual address space — primary memory guard.
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        except (ValueError, OSError):
            pass

        # File size — prevent runaway writes.
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (tmpfs_bytes, tmpfs_bytes))
        except (ValueError, OSError):
            pass

        # Open file descriptors.
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
        except (ValueError, OSError):
            pass

        # CPU time hard limit — belt-and-suspenders behind wall-clock timeout.
        cpu_hard = timeout_s + 30
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_hard, cpu_hard))
        except (ValueError, OSError):
            pass

        # Suppress core dumps.
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass

    return _set
