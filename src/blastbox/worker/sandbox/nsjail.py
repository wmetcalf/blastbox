"""nsjail-backed sandbox backend for the blastbox worker SDK.

``NsjailSandbox`` wraps the ``nsjail`` binary.  It creates an isolated
one-shot environment with user/PID/network/mount/IPC namespaces, drops
privileges, enforces rlimits and an optional KAFEL seccomp policy.

Security guarantees on every :meth:`run` call:

* ``shell=True`` is NEVER used; ``argv`` is always passed as a list.
* Mount source/target values are placed in value positions in the nsjail
  argument vector — ``--bindmount_ro src:tgt`` format — so no caller value
  can inject an nsjail flag.
* The subprocess environment is rebuilt from scratch; ``os.environ`` is
  NOT inherited.  The child sees only a minimal PATH/HOME plus ``request.env``.
* rlimits are passed to nsjail as command-line flags (``--rlimit_as``,
  ``--rlimit_fsize``, ``--rlimit_nofile``, ``--rlimit_nproc``,
  ``--rlimit_core``) which nsjail applies inside the new namespace.
* The child is killed by nsjail's ``--time_limit`` if it exceeds the
  wall-clock timeout; ``SandboxResult.killed`` is set to ``True``.

``insecurity_reasons`` / ``secure`` property:

* ``seccomp_policy_missing`` — the KAFEL policy file was not found in any
  of the standard search locations; nsjail will run without syscall filtering.

Any single reason makes ``secure == False``.
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult


_log = logging.getLogger("blastbox.worker.sandbox.nsjail")

_NSJAIL = shutil.which("nsjail") or "/usr/local/bin/nsjail"

# Minimal safe environment passed to every child process.
# HOST os.environ is NEVER inherited.
_MINIMAL_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
}

# KAFEL seccomp policy search paths.  Checked in order; the first file
# that exists is used.
_SECCOMP_POLICY_CANDIDATES = (
    Path("/etc/blastbox/seccomp.policy"),
    Path(__file__).resolve().parents[4] / "deploy" / "seccomp" / "blastbox.seccomp.policy",
)

# Read-only system directories that must be bind-mounted into the jail.
# /etc is needed for resolv.conf and ld.so.conf; /usr provides all binaries.
_USR_DIRS = ("/usr", "/etc")

# On merged-usr systems (Ubuntu 22.04+, Debian 12+) /bin, /sbin, /lib,
# /lib64 are symlinks into /usr.  nsjail's --symlink recreates them
# inside the jail rather than bind-mounting the targets directly.
_USR_SYMLINKS = {
    "/bin": "usr/bin",
    "/sbin": "usr/sbin",
    "/lib": "usr/lib",
    "/lib64": "usr/lib64",
}


def _find_seccomp_policy() -> Path | None:
    """Return the first seccomp policy file found in the candidate list.

    NOTE: the repo-relative candidate (parents[4]/deploy/...) only resolves in a dev checkout;
    under ``pip install`` the bundled deploy/ tree is absent, so nsjail finds no policy, records
    ``seccomp_policy_missing``, and is correctly skipped as insecure (fail-closed) — but silently.
    Warn loudly so an operator knows to install the policy at /etc/blastbox/seccomp.policy."""
    for candidate in _SECCOMP_POLICY_CANDIDATES:
        if candidate.is_file():
            return candidate
    _log.warning(
        "nsjail_seccomp_policy_not_found searched=%s "
        "impact=backend_reports_insecure_and_is_skipped_unless_BLASTBOX_WARN_ON_INSECURE "
        "fix=install_the_policy_at_/etc/blastbox/seccomp.policy",
        [str(c) for c in _SECCOMP_POLICY_CANDIDATES],
    )
    return None


def _probe_nsjail_proc_apparmor(nsjail_path: str) -> bool:
    """Return True if this nsjail binary supports ``--proc_apparmor``."""
    try:
        r = subprocess.run(
            [nsjail_path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return "--proc_apparmor" in r.stdout or "--proc_apparmor" in r.stderr


class NsjailSandbox:
    """Sandbox backend that wraps the ``nsjail`` binary.

    Construction probes for the KAFEL policy file and AppArmor support,
    and records any deficiencies in :attr:`insecurity_reasons`.  No
    exception is raised — callers inspect :attr:`secure` and
    :attr:`insecurity_reasons` to decide whether to proceed.

    Parameters
    ----------
    nsjail_path:
        Path to the ``nsjail`` binary.  Defaults to ``shutil.which("nsjail")``.
    apparmor_profile:
        AppArmor profile name to attach via ``--proc_apparmor`` (if supported).
    seccomp_policy:
        Explicit path to the KAFEL policy file.  If ``None``, the standard
        candidate paths are tried in order.
    """

    name = "nsjail"

    def __init__(
        self,
        nsjail_path: str = _NSJAIL,
        *,
        apparmor_profile: str = "blastbox-sandbox",
        seccomp_policy: Path | None = None,
    ) -> None:
        # Binary presence is RECORDED, not enforced at construction — matching
        # this class's documented contract ("No exception is raised"). The
        # backend stays constructible-for-inspection on hosts without nsjail
        # installed; run() raises SandboxUnavailable when it is actually needed.
        self._binary_present = bool(shutil.which(nsjail_path)) or Path(nsjail_path).exists()
        self._nsjail = nsjail_path
        self._apparmor_profile = apparmor_profile

        # Resolve the seccomp policy path at construction time.
        # If an explicit path is provided, use it only if it actually exists;
        # a nonexistent path is treated as missing (same as not provided).
        if seccomp_policy is not None:
            self._seccomp_policy: Path | None = (
                seccomp_policy if seccomp_policy.is_file() else None
            )
        else:
            self._seccomp_policy = _find_seccomp_policy()

        self._proc_apparmor_supported = _probe_nsjail_proc_apparmor(self._nsjail)

        if self._seccomp_policy is None:
            _log.warning(
                "nsjail_seccomp_policy_missing searched=%s",
                [str(p) for p in _SECCOMP_POLICY_CANDIDATES],
            )
        else:
            _log.info(
                "nsjail_seccomp_policy_active path=%s",
                str(self._seccomp_policy),
            )

        if not self._proc_apparmor_supported:
            _log.warning(
                "nsjail_proc_apparmor_skipped reason=unsupported_by_installed_nsjail"
            )

        self._insecurity_reasons: list[str] = []
        if not self._binary_present:
            self._insecurity_reasons.append("binary_missing")
        if self._seccomp_policy is None:
            self._insecurity_reasons.append("seccomp_policy_missing")

        _log.info(
            "NsjailSandbox initialised",
            extra={
                "seccomp_policy": str(self._seccomp_policy),
                "proc_apparmor": self._proc_apparmor_supported,
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
        return self._seccomp_policy is not None

    @property
    def apparmor_active(self) -> bool:
        return self._proc_apparmor_supported

    # ------------------------------------------------------------------
    # Public interface

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run ``request.argv`` inside an nsjail one-shot sandbox.

        Security invariants:
        - ``shell=True`` is NEVER used.
        - The subprocess environment is built from scratch; ``os.environ`` is
          NOT inherited.
        - rlimits are enforced by nsjail inside the new namespace.
        - The child is killed by nsjail's --time_limit on wall-clock timeout.
        - ``argv`` must be a non-empty list (never a string).
        - Mount source/target are encoded as ``src:tgt`` in value positions;
          no caller value can inject an nsjail flag.
        """
        if not isinstance(request.argv, list) or not request.argv:
            raise SandboxError("argv must be a non-empty list of strings")
        if not self._binary_present:
            raise SandboxUnavailable(f"nsjail not found at {self._nsjail!r}")

        argv = self._build_argv(request)
        killed = False

        try:
            proc = subprocess.Popen(
                argv,                      # list, never shell=True
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise SandboxError(f"failed to start nsjail: {exc}") from exc

        timeout = request.limits.timeout_s
        try:
            # Give nsjail a few extra seconds beyond --time_limit to clean up.
            stdout, stderr = proc.communicate(timeout=timeout + 5)
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

        # nsjail reports a timed-out child with exit code 109 (signal 9 +
        # 100) or 137 (128 + SIGKILL) and/or messages in stderr.
        # Normalise all cases to killed=True.
        if not killed and (
            exit_code == 109
            or exit_code == 137
            or b"time >=" in (stderr or b"")
            or b"timed out" in (stderr or b"").lower()
            or b"SIGKILL" in (stderr or b"")
        ):
            killed = True

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout or b"",
            stderr=stderr or b"",
            killed=killed,
        )

    # ------------------------------------------------------------------
    # Internal

    def _build_argv(self, req: SandboxRequest) -> list[str]:
        """Build the full nsjail argument vector for ``req``.

        All mount source/target paths are encoded as ``src:tgt`` in value
        positions after the flag token.  No shell expansion or concatenation
        is used, so no caller-supplied value can inject an nsjail flag.
        """
        mem_mb = req.limits.memory_bytes // (1024 * 1024)
        fsize_mb = req.limits.tmpfs_bytes // (1024 * 1024)

        argv: list[str] = [
            self._nsjail,
            "--mode", "o",          # one-shot
            "--quiet",
            "--really_quiet",
            "--iface_no_lo",
            "--time_limit", str(req.limits.timeout_s),
            "--rlimit_as", str(mem_mb),
            "--rlimit_fsize", str(fsize_mb),
            "--rlimit_nofile", "4096",
            "--rlimit_nproc", "256",
            "--rlimit_core", "0",
            "--user", "65534",
            "--group", "65534",
            "--hostname", "blastbox",
        ]

        # Read-only system bind mounts.
        for d in _USR_DIRS:
            if Path(d).exists():
                argv += ["--bindmount_ro", f"{d}:{d}"]

        # Recreate merged-usr symlinks inside the jail.
        for link, target in _USR_SYMLINKS.items():
            if Path(link).is_symlink():
                argv += ["--symlink", f"{target}:{link}"]
            elif Path(link).exists():
                # Real directory on non-merged-usr distro.
                argv += ["--bindmount_ro", f"{link}:{link}"]

        # tmpfs for /tmp.
        argv += ["--tmpfsmount", "/tmp"]

        # Minimal /dev entries (null, zero, random, urandom).
        for dev in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
            if Path(dev).exists():
                argv += ["--bindmount_ro", f"{dev}:{dev}"]

        # Caller-supplied ro/rw mounts — source:target in value positions.
        for m in req.ro_mounts:
            argv += ["--bindmount_ro", f"{m.source}:{m.target}"]
        for m in req.rw_mounts:
            argv += ["--bindmount", f"{m.source}:{m.target}"]

        # Environment: minimal base + request overlay.
        # os.environ is never passed — only explicitly listed vars reach the child.
        for k, v in {**_MINIMAL_ENV, **req.env}.items():
            argv += ["--env", f"{k}={v}"]

        # KAFEL seccomp policy.
        if self._seccomp_policy is not None:
            argv += ["--seccomp_policy", str(self._seccomp_policy)]

        # AppArmor profile via nsjail's in-kernel AA_CHANGE_ONEXEC path.
        if self._proc_apparmor_supported:
            argv += ["--proc_apparmor", self._apparmor_profile]

        argv += ["--", *req.argv]
        return argv
