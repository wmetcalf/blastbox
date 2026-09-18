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
* ``apparmor_missing`` — no ``aa-exec`` helper, or the profile is not enforcing right
  now, so no MAC profile is attached to the child. Symmetric with bwrap, which has
  always reported this; nsjail used to gate it on a probe for an nsjail flag that does
  not exist, so it reported nothing at all (#160).
* ``binary_missing`` — the nsjail binary itself was not found.

Any single reason makes ``secure == False`` — including ``apparmor_missing``, which means a
host with no ``blastbox-sandbox`` profile loaded is skipped by ``select_sandbox`` unless
``BLASTBOX_WARN_ON_INSECURE=1``. See ``deploy/apparmor/README.md``.
"""
from __future__ import annotations

import contextlib
import logging
import shutil
import signal
import subprocess
from collections.abc import Iterator
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.apparmor import profile_loaded, resolve_profile
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, kill_sandbox_group


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


def _find_aa_exec() -> str | None:
    """The ``aa-exec`` helper, or None.

    NSJAIL HAS NO APPARMOR SUPPORT AT ALL. This module used to probe for
    ``--proc_apparmor`` and attach the profile with it, which meant an nsjail-sandboxed
    child never got a profile and never said so: the flag does not exist in nsjail and
    never has. Verified three ways against upstream — ``nsjail --help`` mentions apparmor
    zero times, and a GitHub code search for both ``proc_apparmor`` and plain ``apparmor``
    in google/nsjail returns 0 hits in the whole tree. So the probe was always False, the
    branch never ran, and `insecurity_reasons` gated its `apparmor_missing` on that same
    probe — reporting ``secure = True`` for a sandbox with no confinement mechanism, while
    bwrap in the identical situation correctly reported itself insecure.

    The confinement is applied the way bwrap applies it instead: by prefixing the child's
    argv with ``aa-exec -p <profile> --``, a userspace helper. It needs exactly one thing
    from nsjail — ``--proc_rw``, because aa-exec transitions by writing
    ``/proc/self/attr/exec`` and nsjail mounts ``/proc`` read-only by default, so without it
    the write returns EROFS and the **execve fails**: every job, not just the confinement.
    Both are attached together in :meth:`NsjailSandbox._build_argv`, and only when the
    profile is confirmed enforcing. That keeps the hardening the old code intended rather
    than deleting the intent along with the dead flag.
    """
    return shutil.which("aa-exec")


class NsjailSandbox:
    """Sandbox backend that wraps the ``nsjail`` binary.

    Construction probes for the KAFEL policy file and the ``aa-exec`` helper, and records
    any deficiencies in :attr:`insecurity_reasons`. The AppArmor profile's MODE is NOT a
    construction-time fact -- an operator can unload it under a running worker -- so it is
    re-read per launch (see :meth:`_apparmor_enforcing_now`).  No
    exception is raised — callers inspect :attr:`secure` and
    :attr:`insecurity_reasons` to decide whether to proceed.

    Parameters
    ----------
    nsjail_path:
        Path to the ``nsjail`` binary.  Defaults to ``shutil.which("nsjail")``.
    apparmor_profile:
        AppArmor profile name to attach to the child via ``aa-exec``.
    seccomp_policy:
        Explicit path to the KAFEL policy file.  If ``None``, the standard
        candidate paths are tried in order.
    """

    name = "nsjail"

    def __init__(
        self,
        nsjail_path: str = _NSJAIL,
        *,
        apparmor_profile: str | None = None,
        seccomp_policy: Path | None = None,
    ) -> None:
        # Binary presence is RECORDED, not enforced at construction — matching
        # this class's documented contract ("No exception is raised"). The
        # backend stays constructible-for-inspection on hosts without nsjail
        # installed; run() raises SandboxUnavailable when it is actually needed.
        self._binary_present = bool(shutil.which(nsjail_path)) or Path(nsjail_path).exists()
        self._nsjail = nsjail_path
        self._apparmor_profile = resolve_profile(apparmor_profile)

        # Resolve the seccomp policy path at construction time.
        # If an explicit path is provided, use it only if it actually exists;
        # a nonexistent path is treated as missing (same as not provided).
        if seccomp_policy is not None:
            self._seccomp_policy: Path | None = (
                seccomp_policy if seccomp_policy.is_file() else None
            )
        else:
            self._seccomp_policy = _find_seccomp_policy()

        self._aa_exec: str | None = _find_aa_exec()

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

        if self._aa_exec is None:
            _log.warning(
                "nsjail_apparmor_skipped reason=aa_exec_not_found "
                "note=child_runs_without_an_apparmor_profile"
            )
        else:
            _log.info("nsjail_apparmor_attach_enabled aa_exec=%s profile=%s",
                      self._aa_exec, self._apparmor_profile)

        # The profile's MODE is read per launch, not cached here -- see
        # _apparmor_enforcing_now(). This only remembers the last answer so a change can be
        # logged once instead of every job.
        self._apparmor_last_seen: bool | None = None

        self._static_insecurity_reasons: list[str] = []
        if not self._binary_present:
            self._static_insecurity_reasons.append("binary_missing")
        if self._seccomp_policy is None:
            self._static_insecurity_reasons.append("seccomp_policy_missing")

        _log.info(
            "NsjailSandbox initialised",
            extra={
                "seccomp_policy": str(self._seccomp_policy),
                "aa_exec": self._aa_exec,
                "apparmor_attached": self.apparmor_active,
                "insecurity_reasons": self.insecurity_reasons,
            },
        )

    @contextlib.contextmanager
    def apparmor_suspended(self) -> Iterator[None]:
        """Build argv WITHOUT the AppArmor prefix, for DIAGNOSIS ONLY.

        A child profile narrow enough for one parser may deny ``/usr/bin/true``, which is
        what `select_sandbox` runs as its smoketest -- so a perfectly good backend carrying a
        perfectly good profile can fail the probe and be rejected, and the operator is told
        only "smoketest failed" (codex, #177). Re-running the probe with the profile
        suspended distinguishes "this backend does not work" from "your profile does not
        permit the probe binary", which are different one-line fixes.

        It does NOT run a workload unconfined: the caller uses it for the probe only, and the
        rejection stands either way.
        """
        saved, self._aa_exec = self._aa_exec, None
        try:
            yield
        finally:
            self._aa_exec = saved

    def _apparmor_enforcing_now(self) -> bool:
        """Whether the profile is enforcing AT THIS MOMENT.

        A constructor snapshot goes stale in the direction that matters: switch the profile to
        complain mode -- or unload it -- under a long-lived worker and the cached True keeps
        attaching, and keeps REPORTING, a confinement the kernel stopped providing (codex,
        #159). securityfs is a few dozen lines; re-reading it per launch costs nothing beside
        spawning a sandbox.

        Note what "fail closed" can and cannot mean here. It means never CLAIM or attach
        confinement we cannot confirm. It does not mean refusing to run: the same False is what
        an unreadable securityfs produces, and a worker that refused every job because it
        cannot read /sys would be a worse outage than the one it prevents. The operator sees
        `apparmor_missing`, and BLASTBOX_APPARMOR_PROFILES is the assertion for that host.
        """
        loaded = profile_loaded(self._apparmor_profile)
        if loaded != self._apparmor_last_seen:
            if self._apparmor_last_seen is not None:
                _log.warning(
                    "nsjail_apparmor_state_changed profile=%s enforcing=%s "
                    "note=reevaluated_per_launch_not_cached_at_construction",
                    self._apparmor_profile,
                    loaded,
                )
            self._apparmor_last_seen = loaded
        return loaded

    # ------------------------------------------------------------------
    # Properties

    @property
    def secure(self) -> bool:
        """``False`` if any insecurity reason is present."""
        return not bool(self.insecurity_reasons)

    @property
    def insecurity_reasons(self) -> list[str]:
        """The insecurity reasons AS OF NOW.

        The AppArmor reason is recomputed rather than frozen at construction, so a profile
        switched to complain mid-life is visible here instead of nowhere at all.
        """
        reasons = list(self._static_insecurity_reasons)
        # SAY SO. Skipping the confinement quietly would report a sandbox as secure while
        # the child runs unconfined -- the same reason bwrap records this. The old
        # condition gated this on a probe for a flag that does not exist, so it was
        # ALWAYS False: nsjail reported secure=True with no confinement mechanism at all
        # while bwrap, in the identical situation, correctly reported itself insecure.
        # Two backends, opposite answers, and the silent one had nothing.
        if self._aa_exec is None or not self._apparmor_enforcing_now():
            reasons.append("apparmor_missing")
        return reasons

    @property
    def seccomp_active(self) -> bool:
        return self._seccomp_policy is not None

    @property
    def apparmor_active(self) -> bool:
        """Whether a profile is ACTUALLY attached, not merely whether nsjail could attach one.

        Returning the probe alone told callers and diagnostics that confinement was active
        while `_build_argv` was omitting the flag because the profile is not loaded (codex,
        #159).
        """
        return self._aa_exec is not None and self._apparmor_enforcing_now()

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
            kill_sandbox_group(proc)
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
        # Network namespace. By default nsjail clones a FRESH net namespace; `--iface_no_lo`
        # leaves it with no usable interface = sealed, fail-closed. When the worker's netpolicy
        # grants an exit (limits.net_egress), SHARE the parent (rooter-routed) netns instead via
        # `--disable_clone_newnet`. (No new netns ⇒ --iface_no_lo would be a no-op, so it's dropped.)
        argv.append("--disable_clone_newnet" if req.limits.net_egress else "--iface_no_lo")

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

        # AppArmor: prefix the INNER argv with ``aa-exec -p <profile> --``, exactly as the
        # bwrap backend does. nsjail has no apparmor flag of its own (see _find_aa_exec),
        # and aa-exec is a userspace helper that needs nothing from it.
        #
        # ONLY when the profile is confirmed ENFORCING. aa-exec against an unloaded profile
        # fails the execve, which would break every run — so an unconfirmed profile means
        # skip it and report `apparmor_missing`, keeping the sandbox working but honest
        # about being less hardened.
        #
        # Evaluated ONCE: the flag below and the argv prefix must agree. Two separate reads
        # of securityfs can disagree (the profile is re-read per launch, by design), and
        # either half alone is a broken run -- `--proc_rw` with no aa-exec needlessly
        # loosens /proc, aa-exec with no `--proc_rw` fails every execve (see below).
        aa_exec = self._aa_exec
        if aa_exec is not None and not self._apparmor_enforcing_now():
            aa_exec = None

        # `--proc_rw` is REQUIRED for aa-exec, and is why the userspace route was written off
        # as impossible for nsjail (deploy/apparmor/README.md, #160). aa-exec performs the
        # transition by writing /proc/self/attr/exec; nsjail mounts /proc read-only by
        # default, so that write returns EROFS and the execve fails -- every job, not just
        # the confinement. Measured inside this exact argv on an AppArmor 4.x host:
        #
        #   default   -> open('/proc/self/attr/exec','w').write(...) -> EROFS
        #               aa-exec: ERROR: Read-only file system   (rc=1, nothing runs)
        #   --proc_rw -> write succeeds; child reports the target profile
        #
        # What it costs: nothing measurable at the uid we run as. Re-probed both ways from
        # inside, /proc/sys/kernel/core_pattern, /proc/sys/vm/drop_caches, /proc/sysrq-trigger,
        # /proc/self/oom_score_adj and /proc/1/oom_score_adj all stayed unwritable (uid 65534
        # in a user namespace owns none of them, and /proc/sys is guarded separately), and the
        # child saw the same 3 pids. Only /proc/self/attr became writable -- which is the
        # point. It is therefore attached ONLY on the path that needs it, never by default.
        if aa_exec is not None:
            argv.append("--proc_rw")

        inner = list(req.argv)
        if aa_exec is not None:
            inner = [aa_exec, "-p", self._apparmor_profile, "--", *inner]
        argv += ["--", *inner]
        return argv
