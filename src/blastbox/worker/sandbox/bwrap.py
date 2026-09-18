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

import contextlib
import logging
import os
import resource
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Callable

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.apparmor import (
    ASSERTED,
    profile_loaded,
    find_aa_exec as _find_aa_exec,
    DEFAULT_PROFILE,
    profile_evidence,
    resolve_profile,
)
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, kill_sandbox_group


# How long an in-jail proof of an ASSERTED profile is trusted before it is re-measured. A
# detonation costs seconds at least, so one extra jail launch per half-minute is noise next to
# it; the point is that the window is BOUNDED rather than the life of the worker.
_PROOF_TTL_S = 30.0

# The proof needs something that can print a file. /usr/bin FIRST: on a merged-/usr host
# (/bin -> usr/bin, which is every current Debian/Ubuntu) the kernel resolves the exec to
# /usr/bin/cat and that is the path AppArmor mediates -- so a remedy naming `/bin/cat`, which
# is what this used to print, sends the operator to write a profile rule that never matches
# (claude-code-review lens, round 3 of #177). None means the proof cannot run on this host,
# which is reported as unprovable rather than as a disproof.
_PROOF_READER: str | None = next(
    (p for p in ("/usr/bin/cat", "/bin/cat", "/usr/bin/head") if Path(p).exists()), None
)

_log = logging.getLogger("blastbox.worker.sandbox.bwrap")

def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_BWRAP = shutil.which("bwrap") or "/usr/bin/bwrap"

# Default AppArmor profile to attach to the child process via aa-exec.
# Profile must be loaded on the host kernel.
_DEFAULT_APPARMOR_PROFILE = DEFAULT_PROFILE


def _apparmor_profile_loaded(profile: str) -> bool:
    """True only if we can CONFIRM the named AppArmor profile is loaded.

    ``aa-exec`` against an *unloaded* profile fails the exec, which would break every ``run``.
    So attach it only when sure; any uncertainty means skip aa-exec and record
    ``apparmor_missing``, so the sandbox still functions (just less hardened) instead of
    failing outright.

    The check itself now lives in `apparmor.profile_loaded`, shared with the nsjail backend --
    which had the same hazard and no check at all (issue #158). Imported at MODULE level, like
    nsjail does it: the lazy import inside this function meant the name did not exist on this
    module, so a test patching `bwrap.profile_loaded` pinned nothing and the bwrap half silently
    read the host -- the same asymmetry that hid `_find_aa_exec` (codex, #177).
    """
    return profile_loaded(profile)


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
        apparmor_profile: str | None = None,
    ) -> None:
        # Binary presence is RECORDED, not enforced at construction. The backend
        # stays constructible-for-inspection (secure / insecurity_reasons /
        # _build_argv) on hosts without bwrap installed — run() raises
        # SandboxUnavailable when the binary is actually needed.
        self._binary_present = bool(shutil.which(bwrap_path)) or Path(bwrap_path).exists()
        self._bwrap = bwrap_path
        self._apparmor_profile = resolve_profile(apparmor_profile)

        # AppArmor: attach via ``aa-exec -p <profile> --`` ONLY when the profile
        # is confirmed loaded AND the helper exists. aa-exec against an unloaded
        # profile fails the exec — which would break every run — so when the
        # profile can't be confirmed we skip aa-exec (and record apparmor_missing)
        # rather than break the sandbox.
        # Two independent facts, and they were conflated: whether the HELPER exists (static,
        # a binary on disk) and whether the PROFILE is enforcing (dynamic, kernel state an
        # operator can change under a running worker). Only the first belongs in a constructor.
        # BEFORE the first apparmor_active read. That property is not a plain accessor: on
        # the asserted path it launches a jail to measure the profile and caches the result
        # here, and both constructors read it while deciding what to log -- so uninitialised
        # state crashed construction outright on any host with BLASTBOX_APPARMOR_PROFILES set
        # (found by running it).
        self._suspended_for_diagnosis = False
        self._proof: tuple[bool, float] | None = None
        self._warned: set[str] = set()
        self._aa_exec: str | None = _find_aa_exec()
        self._apparmor_last_seen: bool | None = None
        # NOT apparmor_active here. That property is not a plain accessor: on the asserted path
        # it builds an argv and launches a jail, which needs constructor state that does not
        # exist yet -- calling it from __init__ crashed construction outright (found by running
        # it). The cheap facts are enough to log an intention; the measurement happens on the
        # first real read, which is the selector's security check, still before any job.
        if self._aa_exec is not None and self._apparmor_enforcing_now():
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

        self._static_insecurity_reasons: list[str] = []
        if not self._binary_present:
            self._static_insecurity_reasons.append("binary_missing")
        if not self._seccomp_active:
            # No BPF attached -> insecure on the seccomp axis (keep the historical reason string).
            self._static_insecurity_reasons.append("seccomp_not_implemented")
        if not self._cgroup_pids_supported:
            self._static_insecurity_reasons.append("pid_limit_missing")

        # What confinement looked like when the selector admitted this backend. A LOSS
        # of it later is a refusal (see _refuse_if_confinement_regressed); never having
        # had it is not.
        # An ASSERTED profile is not a confirmed one -- see apparmor_active, which measures it
        # from inside the jail rather than believing it, on a TTL rather than once. Deliberately
        # NOT measured here: see the note above the log block.
        # None = not recorded yet, and deliberately NOT measured here: the measurement can
        # launch a jail (an asserted profile is proved, not believed), which a constructor
        # cannot do -- it crashed construction outright on a host with BLASTBOX_APPARMOR_PROFILES
        # set. `note_admitted()` records it when the selector admits this backend; a backend
        # built directly by an engine and never passed through `select_sandbox` takes its
        # baseline from its first launch instead.
        # The CHEAP facts, which are all a constructor may consult: the helper exists and the
        # profile reads as enforcing. Not apparmor_active -- that measures an asserted profile
        # by launching a jail, needs state this constructor has not built yet, and crashed
        # construction outright on a host with BLASTBOX_APPARMOR_PROFILES set (found by running
        # it). `note_admitted()` refines this at the moment the selector admits the backend,
        # which is the admission that actually matters.
        self._armed_at_admission: bool = (
            self._aa_exec is not None and self._apparmor_enforcing_now()
        )

        _log.info(
            "BubblewrapSandbox initialised",
            extra={
                "seccomp_active": self._seccomp_active,
                "apparmor": self._aa_exec,
                "cgroup_pids": self._cgroup_pids_supported,
                # The STATIC reasons only. `insecurity_reasons` derives the AppArmor one from
                # apparmor_active, which measures an asserted profile by launching a jail --
                # not something a constructor can do, and not something a log line should
                # trigger. The live answer is what the selector reads a moment later.
                "static_insecurity_reasons": list(self._static_insecurity_reasons),
            },
        )

    # ------------------------------------------------------------------
    # Properties

    @contextlib.contextmanager
    def apparmor_suspended(self) -> Iterator[None]:
        """Build argv WITHOUT the AppArmor prefix, for DIAGNOSIS ONLY.

        A child profile narrow enough for one parser may deny ``/usr/bin/true``, which is
        what `select_sandbox` runs as its smoketest -- so a perfectly good backend carrying a
        perfectly good profile can fail the probe and be rejected, and the operator is told
        only "smoketest failed" (codex, #177 — same hazard, same helper). Re-running the probe with the profile
        suspended distinguishes "this backend does not work" from "your profile does not
        permit the probe binary", which are different one-line fixes.

        It does NOT run a workload unconfined: the caller uses it for the probe only, and the
        rejection stands either way.
        """
        saved, self._aa_exec = self._aa_exec, None
        # See the nsjail copy: without this the regression guard fires inside the diagnostic
        # probe and `_ProfileDeniesProbe` becomes unreachable (claude-security lens, #177).
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
        loaded = _apparmor_profile_loaded(self._apparmor_profile)
        if loaded != self._apparmor_last_seen:
            if self._apparmor_last_seen is not None:
                _log.warning(
                    "bwrap_apparmor_state_changed profile=%s enforcing=%s "
                    "note=reevaluated_per_launch_not_cached_at_construction",
                    self._apparmor_profile,
                    loaded,
                )
            self._apparmor_last_seen = loaded
        return loaded

    @property
    def secure(self) -> bool:
        """``False`` if any insecurity reason is present."""
        return not bool(self.insecurity_reasons)

    @property
    def insecurity_reasons(self) -> list[str]:
        """The insecurity reasons AS OF NOW (the AppArmor one is re-read, not frozen)."""
        reasons = list(self._static_insecurity_reasons)
        if not self.apparmor_active:
            reasons.append("apparmor_missing")
        return reasons

    @property
    def seccomp_active(self) -> bool:
        return self._seccomp_active

    @property
    def apparmor_active(self) -> bool:
        """Both halves: the helper exists AND the profile is enforcing right now."""
        if self._aa_exec is None or not self._apparmor_enforcing_now():
            return False
        if profile_evidence(self._apparmor_profile) == ASSERTED:
            # The only evidence is an environment variable, which cannot tell enforce from
            # complain. Measure it (TTL-bounded) instead of taking its word.
            return self.apparmor_attachment_is_believable()
        return True

    @property
    def cgroup_pids_supported(self) -> bool:
        return self._cgroup_pids_supported

    # ------------------------------------------------------------------
    # Public interface

    def _attach_argv(self, req: SandboxRequest) -> list[str]:
        """The argv with the profile attached, whatever this backend's builder needs."""
        return self._build_argv(req, attach_apparmor=True)

    def _apparmor_attaches_at_all(self) -> bool:
        """Can the profile be attached to ANY child? Structural, no error-string matching.

        The reader probe below cannot tell "this profile denies /bin/cat" from "this profile
        does not exist", and the two demand opposite answers: the first must not punish a
        correctly narrow profile, the second is an assertion that is simply false. Measured on
        a host with no such profile loaded, aa-exec says
        `ERROR: profile 'blastbox-sandbox' does not exist` -- and the first version of this
        logic read that as merely unprovable and kept reporting `secure` with no confinement
        at all, which is the fail-open the proof exists to close (found by running it).

        So ask the cheap, structural question first, with the ONE binary every child profile is
        documented to permit: if `aa-exec -p <profile> -- /usr/bin/true` cannot run, the
        profile is unusable, whatever the reason.
        """
        probe = "/usr/bin/true" if Path("/usr/bin/true").exists() else "/bin/true"
        req = SandboxRequest(argv=[probe])
        try:
            out = subprocess.run(
                self._attach_argv(req), capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("apparmor_attach_probe_failed reason=%s", exc)
            return False
        if out.returncode != 0:
            _log.warning(
                "apparmor_attach_probe_failed rc=%s stderr=%s",
                out.returncode, out.stderr.strip()[-200:],
            )
            return False
        return True

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
        if _PROOF_READER is None:
            return None
        req = SandboxRequest(argv=[_PROOF_READER, "/proc/self/attr/current"])
        try:
            out = subprocess.run(
                self._attach_argv(req), capture_output=True, text=True, timeout=60,
            )
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
        """Whether an ASSERTED profile survives being measured. Three outcomes, not two.

        Called only where the evidence is an assertion (`profile_evidence` == ASSERTED); a
        kernel reading needs no second opinion.

        * DISPROVED -- the child ran and came back wearing another profile, or a non-enforcing
          one. The assertion is untrue: disarm, because the alternative is `--proc_rw` bought
          with nothing.
        * UNPROVABLE -- the probe could not run at all (no reader binary, or the profile denies
          it). A workload-specific profile may legitimately permit its parser and the
          documented `/usr/bin/true` without permitting a file reader, and rejecting such a
          backend would take a correctly-configured host down over a diagnostic
          (codex, #177). Keep the assertion, warn once, and say what to permit.
        * PROVEN -- the child reports this profile in enforce or kill mode.

        The answer is re-measured on a TTL rather than once at construction: with securityfs
        unreadable, `profile_loaded()` returns ASSERTED forever from a static environment
        variable, so a profile switched to complain mid-life would otherwise stay "active" for
        the life of the worker while nothing enforced anything (codex, #177). The window is
        bounded by `_PROOF_TTL_S`, and monotonic time cannot be stepped backwards under it.
        """
        if self._proof is not None and time.monotonic() - self._proof[1] < _PROOF_TTL_S:
            return self._proof[0]

        if not self._apparmor_attaches_at_all():
            # DISPROVED, not unprovable: the profile cannot be attached to anything, so the
            # assertion that it is loaded and enforcing is false.
            _log.warning(
                "apparmor_assertion_disproved profile=%s "
                "note=the profile cannot be attached at all (absent, or it denies the "
                "documented probe binary); no profile is attached",
                self._apparmor_profile,
            )
            self._proof = (False, time.monotonic())
            return False

        got = self.prove_apparmor_attachment()
        if got is None:
            # UNPROVABLE. Not evidence against the operator, and not evidence for them.
            self._warn_once(
                "apparmor_assertion_unprovable profile=%s "
                "note=the in-jail proof could not run (no reader binary, or the profile "
                "denies it); the assertion stands unverified. Permit %s in the profile to "
                "have it checked." % (self._apparmor_profile, _PROOF_READER or "a file reader")
            )
            # Stamped AFTER the probe. Stamping at entry made the entry `probe_duration`
            # seconds old on arrival, so any probe slower than the TTL (the launch allows 60s,
            # the TTL is 30) produced a cache that was expired when written -- every read
            # re-launched a jail and waited again, turning a loaded host into a worker that
            # looks hung (claude-code-review lens, round 3 of #177).
            self._proof = (True, time.monotonic())
            return True

        # The NAME, not a prefix of it. `startswith` accepted a child wearing
        # `blastbox-sandbox-permissive` as proof of `blastbox-sandbox` -- and this is the single
        # gate behind `secure` and `--proc_rw` on the asserted path (claude-code-review lens,
        # round 3 of #177). The kernel's format is `name (mode)`, so split on that separator,
        # exactly as apparmor._line_is_enforcing does.
        name, _, mode = got.partition(" (")
        ok = name.strip() == self._apparmor_profile and mode.startswith(("enforce", "kill"))
        if not ok:
            _log.warning(
                "apparmor_assertion_disproved profile=%s child_reports=%r "
                "note=asserted via BLASTBOX_APPARMOR_PROFILES but the kernel disagrees; "
                "no profile is attached",
                self._apparmor_profile, got,
            )
        self._proof = (ok, time.monotonic())
        return ok

    def _warn_once(self, msg: str) -> None:
        if msg in self._warned:
            return
        self._warned.add(msg)
        _log.warning(msg)

    def note_admitted(self) -> None:
        """Called by the selector on the backend it actually admits.

        `_armed_at_admission` was captured in the CONSTRUCTOR, which is not when admission
        happens: a profile that becomes enforcing between construction and the selector's
        security check gets the backend admitted as confined with the flag still False, and
        the regression guard is then inert for the life of that worker (codex, #177). The
        selector knows the real moment; this is it.
        """
        self._armed_at_admission = self.apparmor_active

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
        # ONE read for this launch, shared by the guard and the argv: two independent reads
        # can straddle a profile being unloaded, and the argv silently losing the prefix after
        # the guard approved it is exactly what the guard exists to prevent.
        attached = self.apparmor_active
        self._refuse_if_confinement_regressed(attached)

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
                kill_sandbox_group(proc)
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

    def _build_argv(
        self,
        req: SandboxRequest,
        *,
        seccomp_fd: int | None = None,
        attach_apparmor: bool | None = None,
    ) -> list[str]:
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
        aa_exec = self._aa_exec
        # `attach_apparmor` is the caller's single answer for this launch (run() reads
        # apparmor_active once and passes it); None means decide here. The proof probe passes
        # True explicitly -- it is the thing that ESTABLISHES belief, so it cannot wait on it.
        if aa_exec is not None:
            decided = self.apparmor_active if attach_apparmor is None else attach_apparmor
            if not decided:
                aa_exec = None
        if aa_exec is not None:
            inner = [aa_exec, "-p", self._apparmor_profile, "--", *inner]
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
