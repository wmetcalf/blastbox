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
import os
import shutil
import signal
import subprocess
from collections.abc import Iterator
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.worker.sandbox.apparmor import (
    ASSERTED,
    find_aa_exec,
    profile_evidence,
    profile_loaded,
    resolve_profile,
)
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, kill_sandbox_group


_log = logging.getLogger("blastbox.worker.sandbox.nsjail")

def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


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
    return find_aa_exec()


def _supports_proc_rw(nsjail_path: str) -> bool:
    """Whether the INSTALLED nsjail accepts ``--proc_rw``.

    aa-exec cannot transition without it (nsjail's default read-only /proc turns the write
    to /proc/self/attr/exec into EROFS), so attaching the prefix to a build that rejects the
    flag does not weaken confinement -- it kills every job with `Unknown argument`. Worse,
    the failure looks exactly like a profile that denies the probe binary, so the operator is
    sent to edit a profile that is correct (claude-code-review lens, #177).

    Probing a flag that DOES exist upstream is not the mistake this module is recovering
    from: the dead ``--proc_apparmor`` probe was wrong because the flag it looked for never
    existed anywhere, so the answer was always False and the branch was dead. This one is
    checked against the binary actually installed, and a False answer changes behaviour
    (skip the attachment, report `apparmor_missing`) rather than silently doing nothing.
    """
    try:
        out = subprocess.run(
            [nsjail_path, "--help"], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        # Unreadable capability = not confirmed. Fail SAFE (no attachment, reported),
        # never fail-open into an argv that cannot run.
        return False
    return "--proc_rw" in (out.stdout + out.stderr)


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

        # Initialised before anything can call _apparmor_enforcing_now() (the log block
        # below does): it only remembers the last answer so a change logs once.
        self._apparmor_last_seen: bool | None = None

        self._aa_exec: str | None = _find_aa_exec()
        self._proc_rw_supported = (
            self._binary_present and _supports_proc_rw(nsjail_path)
            if self._aa_exec is not None
            else False
        )
        # A THIRD cause for apparmor_missing, kept distinct from the other two. Clearing
        # `_aa_exec` made the log block below announce `reason=aa_exec_not_found` -- the helper
        # was found -- and made the selector's remedy tell the operator to load a profile that
        # is already loaded and enforcing, which is the very defect the remedy was added to fix
        # (claude-code-review lens, round 2 of #177).
        self._apparmor_blocked_reason: str | None = None
        if self._aa_exec is not None and self._binary_present and not self._proc_rw_supported:
            self._apparmor_blocked_reason = (
                f"the installed nsjail at {nsjail_path} has no --proc_rw, so aa-exec would "
                f"fail with EROFS; no profile can be attached with this build"
            )
            _log.warning(
                "nsjail_apparmor_unavailable reason=installed_nsjail_has_no_--proc_rw "
                "path=%s note=aa_exec_would_fail_with_EROFS_so_no_profile_is_attached",
                nsjail_path,
            )
            self._aa_exec = None

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

        # Log what will ACTUALLY happen, not what the binaries make possible. Branching on
        # the helper alone announced `attach_enabled` on every host with apparmor-utils
        # installed and no profile loaded -- while bwrap, from identical state, logged
        # `attach_skipped ... run_proceeds_without_apparmor` at WARNING. That is the same
        # two-backends-disagree-about-their-own-hardening asymmetry #160 exists to remove,
        # one layer down, with the accurate line at the level that does NOT reach an alerting
        # pipeline (claude-code-review lens, #177).
        if self._apparmor_blocked_reason is not None:
            pass                    # already logged above, with the real cause
        elif self._aa_exec is None:
            _log.warning(
                "nsjail_apparmor_skipped reason=aa_exec_not_found "
                "note=child_runs_without_an_apparmor_profile"
            )
        elif not self._apparmor_enforcing_now():
            _log.warning(
                "nsjail_apparmor_attach_skipped reason=profile_not_confirmed_enforcing "
                "profile=%s note=run_proceeds_without_apparmor",
                self._apparmor_profile,
            )
        else:
            _log.info("nsjail_apparmor_attach_enabled aa_exec=%s profile=%s",
                      self._aa_exec, self._apparmor_profile)

        self._static_insecurity_reasons: list[str] = []
        if not self._binary_present:
            self._static_insecurity_reasons.append("binary_missing")
        if self._seccomp_policy is None:
            self._static_insecurity_reasons.append("seccomp_policy_missing")

        # What confinement looked like when the selector admitted this backend. A LOSS
        # of it later is a refusal (see _refuse_if_confinement_regressed); never having
        # had it is not.
        self._suspended_for_diagnosis = False
        # An ASSERTED profile is not a confirmed one. Measure it once, from inside the jail,
        # before anything is traded for it -- and drop the attachment if the child does not
        # come back wearing an enforcing profile of that name.
        if (
            self._aa_exec is not None
            and self._binary_present
            and profile_evidence(self._apparmor_profile) == ASSERTED
            and not self.apparmor_attachment_is_believable()
        ):
            self._aa_exec = None
        self._armed_at_admission = self.apparmor_active

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
        # The regression guard reads exactly the state this suspension fakes -- armed at
        # admission, not active now -- so without this flag the guard fires INSIDE the
        # diagnostic probe, `_smoketest` sees the suspended probe fail too, and
        # `_ProfileDeniesProbe` becomes unreachable from a real backend: the
        # demote-to-container path reopens, and the two round-1 fixes cancel each other out
        # (claude-security lens, round 2 of #177).
        self._suspended_for_diagnosis = True
        try:
            yield
        finally:
            self._aa_exec = saved
            self._suspended_for_diagnosis = False

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
    def apparmor_blocked_reason(self) -> str | None:
        """Why no profile can be attached on this host, when the cause is not the obvious two.

        `apparmor_missing` has three causes -- no helper, no enforcing profile, and an nsjail
        build without `--proc_rw` -- and the selector's remedy can only guess at the first two.
        """
        return self._apparmor_blocked_reason

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

    def prove_apparmor_attachment(self) -> str | None:
        """Ask the KERNEL, from inside the jail, what profile the child actually got.

        The one thing that turns an assertion into a measurement. When arming rests on
        ``BLASTBOX_APPARMOR_PROFILES`` -- which is the normal case for a non-root worker,
        because securityfs is root-only -- nothing so far has checked that the named profile
        exists, let alone that it is enforcing, and a complain-mode profile would buy
        `secure = True` plus (for nsjail) a writable /proc for the child with no confinement
        at all in exchange (claude-security lens, round 2 of #177).

        ``/proc/self/attr/current`` read from inside is the kernel naming the profile AND its
        mode, so it cannot be asserted away. Returns that string, or None if the probe could
        not run. The caller decides what to do with a mismatch; this method only measures.
        """
        if self._aa_exec is None:
            return None
        req = SandboxRequest(argv=["/bin/cat", "/proc/self/attr/current"])
        argv = self._build_argv(req, attach_apparmor=True)
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("apparmor_attachment_unprovable reason=%s", exc)
            return None
        if out.returncode != 0:
            _log.warning(
                "apparmor_attachment_unprovable rc=%s stderr=%s",
                out.returncode, out.stderr.strip()[-200:],
            )
            return None
        return out.stdout.strip()

    def apparmor_attachment_is_believable(self) -> bool:
        """True when the child really comes back wearing an ENFORCING profile of that name.

        Called only where the evidence is an assertion; a kernel reading needs no second
        opinion. A False here drops the attachment rather than proceeding, because the
        alternative is `--proc_rw` bought with nothing.
        """
        got = self.prove_apparmor_attachment()
        if got is None:
            return False
        ok = got.startswith(self._apparmor_profile) and (
            "(enforce)" in got or "(kill)" in got
        )
        if not ok:
            _log.warning(
                "apparmor_assertion_disproved profile=%s child_reports=%r "
                "note=asserted via BLASTBOX_APPARMOR_PROFILES but the kernel disagrees; "
                "no profile is attached",
                self._apparmor_profile, got,
            )
        return ok

    def _refuse_if_confinement_regressed(self, attached: bool | None = None) -> None:
        """A worker outlives its jobs; `secure` is checked once, at selection.

        `select_sandbox` reads `secure` at worker start and never again, and `run()` used to
        proceed regardless -- so a profile unloaded, switched to complain, or made
        unconfirmable under a long-lived worker silently dropped the `aa-exec` prefix (and
        `--proc_rw`) and kept detonating, on a backend the selector had certified. The
        per-launch re-read existed but nothing acted on it (claude-security lens, #177).

        The test is a REGRESSION, not a state: confinement that was there at admission and is
        gone now. A backend that never had a profile is not affected -- it was admitted on
        that basis, with `apparmor_missing` recorded -- so this cannot turn "cannot read
        /sys" into a worker that refuses every job, which would be a worse outage than the
        one it prevents.

        The override is DELIBERATELY not `BLASTBOX_WARN_ON_INSECURE`. That variable is set
        automatically by the dispatcher for every runsc worker (`host/runtime/docker.py`, and
        the warm/snapshot tier as of this PR) for an unrelated reason -- gVisor virtualises
        /proc, so a worker cannot observe host-level hardening flags that ARE applied -- so
        honouring it here would leave this control switched off everywhere the fleet actually
        runs, and on only where nobody does. `BLASTBOX_ALLOW_CONFINEMENT_LOSS=1` is the
        knowing opt-out, and it has to be set by someone who means this.
        """
        if self._suspended_for_diagnosis:
            # A probe, not a job. `_smoketest` suspends the profile deliberately to tell
            # "your profile denies the probe binary" from "this backend does not work".
            return
        if not self._armed_at_admission or (
            self.apparmor_active if attached is None else attached
        ):
            return
        msg = (
            f"{self.name}: the AppArmor profile {self._apparmor_profile!r} was enforcing when "
            f"this backend was admitted and is not now -- refusing to run unconfined on a "
            f"backend that was selected as confined"
        )
        if _env_truthy("BLASTBOX_ALLOW_CONFINEMENT_LOSS"):
            _log.warning("%s (allowed by BLASTBOX_ALLOW_CONFINEMENT_LOSS)", msg)
            return
        raise SandboxUnavailable(msg)

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
        # ONE read of securityfs for this launch, shared by the guard and the argv. They
        # used to read it independently, so a profile that stopped being confirmable between
        # the two produced exactly what the guard exists to prevent -- an unconfined argv on
        # a backend admitted as confined -- with no refusal and no error
        # (claude-security lens, round 2 of #177).
        attached = self._aa_exec is not None and self._apparmor_enforcing_now()
        self._refuse_if_confinement_regressed(attached)

        argv = self._build_argv(request, attach_apparmor=attached)
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

    def _build_argv(
        self, req: SandboxRequest, *, attach_apparmor: bool | None = None
    ) -> list[str]:
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
        # `attach_apparmor` is run()'s single answer for this launch; None means "decide
        # here", for the direct callers (tests, diagnostics) that have no launch context.
        aa_exec = self._aa_exec
        if aa_exec is not None:
            decided = (
                self._apparmor_enforcing_now() if attach_apparmor is None else attach_apparmor
            )
            if not decided:
                aa_exec = None

        # `--proc_rw` is REQUIRED for aa-exec, and is why the userspace route was written off
        # as impossible for nsjail (deploy/apparmor/README.md, #160). aa-exec performs the
        # transition by writing /proc/self/attr/exec; nsjail mounts /proc read-only by
        # default, so that write returns EROFS and the execve fails -- every job, not just
        # the confinement. Measured inside this argv on an AppArmor 4.x host:
        #
        #   default    open('/proc/self/attr/exec', O_WRONLY) -> EROFS
        #              aa-exec: ERROR: Read-only file system   (rc=1, nothing runs)
        #   --proc_rw  the open succeeds; the child reports the profile the argv asked for
        #
        # WHAT IT COSTS -- corrected, because the first measurement written here was wrong.
        # It probed with `echo x > $f`, which fails with EINVAL on files that reject the
        # content, and that was misread as "blocked"; the comment then claimed only
        # /proc/self/attr became writable. Re-probed with open(O_WRONLY), which cannot lie
        # about the errno, the real answer at uid 65534 in this jail is:
        #
        #   writable with --proc_rw: /proc/self/attr/*, /proc/self/mem, /proc/self/clear_refs,
        #     /proc/self/coredump_filter, /proc/self/oom_score_adj, /proc/1/oom_score_adj,
        #     /proc/self/{uid,gid}_map, /proc/self/timerslack_ns   (all EROFS without it)
        #   still refused either way: /proc/sys/** and /proc/sysrq-trigger (EACCES -- a
        #     different gate, ownership and the user namespace, not the mount flag)
        #
        # /proc/self/mem is the one that matters: a payload can rewrite its own read-only and
        # executable mappings without mprotect. Cross-process /proc/<pid>/mem is still gated
        # by ptrace_scope, so this is a widened surface inside the jail, not an escape from
        # it -- but it IS wider than the pre-#160 child had, and the comment that said
        # otherwise is exactly the kind of confident-and-disproved claim this repo keeps
        # finding (claude-security lens, #177).
        #
        # The trade only closes because the two travel together: the flag is attached ONLY
        # when an enforcing child profile is attached with it, and AppArmor mediates these
        # paths, so the profile is what takes the surface back (deploy/apparmor/README.md
        # lists the deny rules every child profile should carry). No profile => no --proc_rw
        # => the child keeps the read-only /proc it always had.
        if aa_exec is not None:
            argv.append("--proc_rw")

        inner = list(req.argv)
        if aa_exec is not None:
            inner = [aa_exec, "-p", self._apparmor_profile, "--", *inner]
        argv += ["--", *inner]
        return argv
