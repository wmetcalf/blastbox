"""Whether a named AppArmor profile is actually loaded on this host.

Shared by the bwrap and nsjail backends because attaching an UNLOADED profile does not
degrade either of them -- it breaks them:

* bwrap runs the child through ``aa-exec <profile>``, which fails the exec.
* nsjail does the same: it has no AppArmor flag of its own (``--proc_apparmor`` exists in no
  upstream build -- see :func:`blastbox.worker.sandbox.nsjail._find_aa_exec`), so the profile
  is attached with the same userspace helper, and fails the same way.

bwrap has always checked. nsjail used to gate on a probe for that nonexistent flag, which was
always False -- so it never attached anything, and never reported the lack either (#160). One
copy of the check, so the two backends cannot drift on a question with the same answer and the
same consequence.
"""

from __future__ import annotations

import contextlib
import subprocess
import time
import logging
import os
import shutil
from blastbox.errors import SandboxUnavailable
from blastbox.worker.sandbox.base import SandboxRequest

from collections.abc import Iterator
from typing import Any
from pathlib import Path

_PROFILES = "/sys/kernel/security/apparmor/profiles"


# How long an in-jail proof of an ASSERTED profile is trusted before it is re-measured. A
# detonation costs seconds at least, so one jail launch per half-minute is noise next to it; the
# point is that the window is BOUNDED rather than the life of the worker.
_PROOF_TTL_S = 30.0

# A probe that could not RUN is cached far more briefly: long enough to stop a storm of 60s
# launches (six per `insecurity_reasons` + `secure` read, measured), short enough that the
# backend recovers on its own the moment probes work again.
_TRANSIENT_TTL_S = 2.0

# The proof needs something that can print a file. /usr/bin FIRST: on a merged-/usr host
# (/bin -> usr/bin, which is every current Debian/Ubuntu) the kernel resolves the exec to
# /usr/bin/cat and that is the path AppArmor mediates -- so a remedy naming `/bin/cat` sends the
# operator to write a profile rule that never matches. None means the proof cannot run here,
# which is reported as unprovable rather than as a disproof.
_PROOF_READER: str | None = next(
    (p for p in ("/usr/bin/cat", "/bin/cat", "/usr/bin/head") if Path(p).exists()), None
)

_log = logging.getLogger("blastbox.worker.sandbox.apparmor")
_WARNED_ASSERTED: set[str] = set()

# The modes the kernel prints for a profile that actually DENIES. Measured against a real
# AppArmor 4.0.1 host (toolz2) by loading a scratch profile under each `flags=(...)` and
# reading the line back, rather than guessing at the strings:
#
#     flags=(enforce)   -> `name (enforce)`     denies
#     flags=(kill)      -> `name (kill)`        denies, and kills the violating task
#     flags=(complain)  -> `name (complain)`    logs and ALLOWS
#     flags=(unconfined)-> `name (unconfined)`  no confinement at all
#     flags=(prompt)    -> `name (user)`        denial is referred to a userspace agent
#
# `kill` is strictly stronger than `enforce` and belongs here (codex, #159). `user` (prompt
# mode) does not: its answer to a denial comes from a process outside this system, which can
# grant what the policy refuses, so it is not a confinement guarantee for untrusted input.
# Anything unrecognised is not a promise of enforcement either -- unknown modes fail closed.
# An operator who knows better has BLASTBOX_APPARMOR_PROFILES.
_ENFORCING_MODES = frozenset({"enforce", "kill"})


DEFAULT_PROFILE = "blastbox-sandbox"


def resolve_profile(explicit: str | None = None) -> str:
    """The profile name a backend should attach.

    There was no way to choose one. Both backends took `apparmor_profile` as a constructor
    argument, but `select_sandbox` -- the only path a real worker takes -- constructs them with
    no arguments, and nothing read an environment variable. So an operator could load a perfect
    profile and the worker would still look for `blastbox-sandbox` and report `apparmor_missing`
    (codex, #161: the deployment instructions were not actionable).

    Explicit argument wins over the environment, which wins over the built-in default; that
    order keeps a caller that passed a name in control of it.
    """
    if explicit:
        return explicit
    return os.environ.get("BLASTBOX_APPARMOR_PROFILE", "").strip() or DEFAULT_PROFILE


KERNEL = "kernel"
ASSERTED = "asserted"
NONE = "none"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def find_aa_exec() -> str | None:
    """The ``aa-exec`` helper, or None -- for BOTH backends, under one name.

    bwrap called `shutil.which("aa-exec")` inline while nsjail had a module-level
    `_find_aa_exec`, so a test could pin nsjail's answer and silently could not pin bwrap's:
    `monkeypatch.setattr(bwrap_module, "_find_aa_exec", ...)` created an unused attribute and
    the bwrap half of every parity test quietly read the host instead -- host-dependence of
    exactly the kind those tests were written to remove (claude-code-review lens, round 2 of
    #177). One name, both modules, one thing to patch.
    """
    return shutil.which("aa-exec")


def profile_evidence(profile: str) -> str:
    """WHERE the answer came from: :data:`KERNEL`, :data:`ASSERTED` or :data:`NONE`.

    Not decoration. ``/sys/kernel/security/apparmor/profiles`` is root-only and a worker is
    not root, so on the deployment posture this mechanism is written for the kernel can NEVER
    be consulted and ``BLASTBOX_APPARMOR_PROFILES`` is the sole authority -- an assertion that
    cannot distinguish enforce from complain, now deciding `secure` and (for nsjail)
    ``--proc_rw``. Making the kernel authoritative "where it can be read" therefore changed
    nothing for the case that matters (claude-security lens, round 2 of #177).

    Callers that are about to trade something for confinement can ask how the answer was
    reached and go and MEASURE it instead of believing it -- see
    ``Sandbox.prove_apparmor_attachment``.
    """
    try:
        with open(_PROFILES, encoding="utf-8", errors="surrogateescape") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        if profile in _asserted():
            _warn_asserted(profile)
            return ASSERTED
        return NONE

    if any(_line_is_enforcing(line, profile) for line in lines):
        return KERNEL
    if profile in _asserted():
        _log.warning(
            "apparmor_assertion_contradicted profile=%s "
            "note=BLASTBOX_APPARMOR_PROFILES names it but securityfs does not report it "
            "enforcing; the kernel wins and no profile is attached",
            profile,
        )
    return NONE


def profile_loaded(profile: str) -> bool:
    """True only if the named profile can be CONFIRMED enforcing.

    Any uncertainty -- securityfs unreadable and nothing asserted, profile absent -- is False,
    so the caller skips the confinement and records it rather than failing every run. See
    :func:`profile_evidence` for the ordering (the kernel outranks the environment wherever it
    can be read) and for why the caller should care which of the two answered.
    """
    return profile_evidence(profile) != NONE


def _asserted() -> set[str]:
    raw = os.environ.get("BLASTBOX_APPARMOR_PROFILES", "").strip()
    return {p.strip() for p in raw.split(",") if p.strip()}


def _warn_asserted(profile: str) -> None:
    """Say, once per process, that confinement is being taken on trust.

    `secure = True` now rides on this answer, and so does `--proc_rw`. An operator reading
    logs should be able to tell "the kernel says this profile is enforcing" from "someone set
    an environment variable".
    """
    if profile in _WARNED_ASSERTED:
        return
    _WARNED_ASSERTED.add(profile)
    _log.warning(
        "apparmor_profile_asserted_not_verified profile=%s "
        "note=securityfs unreadable; enforcement taken from BLASTBOX_APPARMOR_PROFILES, "
        "which cannot distinguish enforce from complain",
        profile,
    )


def _line_is_enforcing(line: str, profile: str) -> bool:
    """One securityfs line, as `name (mode)` -- True only for THIS profile in enforce mode.

    Matching the name alone treats a profile loaded in `complain` (log, allow) or `unconfined`
    mode as confinement: the backend attaches it, omits `apparmor_missing`, and can be reported
    `secure` while nothing is actually enforced. For untrusted workloads that has to fail
    closed, so a line with no mode -- an unexpected format -- is not enforcing either.
    """
    name, _, rest = line.strip().partition(" (")
    if name != profile:
        return False
    return rest.rstrip().rstrip(")") in _ENFORCING_MODES


class AppArmorProofMixin:
    """The shared half of both backends' AppArmor handling: prove, guard, report.

    ONE copy. It was two, ~236 identical lines in nsjail.py and bwrap.py, and that duplication
    is where this PR's defects came from rather than a stylistic complaint: over four review
    rounds the argv/guard TOCTOU fix landed in nsjail and not bwrap (live for two rounds), the
    seccomp-less probe existed only in bwrap, and every test for the proof cache and the name
    match exercised the nsjail copy only. Two copies, one of them fixed and tested.

    A host class must provide: ``_aa_exec``, ``_apparmor_profile``, ``_binary_present``,
    ``_apparmor_last_seen``, ``_proof``, ``_warned_unprovable``, ``_armed_at_admission``,
    ``name``, and ``_build_argv(req, *, attach_apparmor=...)``.
    """

    # The contract a host class must satisfy. Declared rather than implied so the type checker
    # holds both sides of the seam -- the duplication this mixin replaces drifted precisely
    # because nothing checked that the two copies still fit their classes.
    # What the HOST must provide (no default -- backend facts the mixin cannot invent):
    name: str
    _aa_exec: str | None
    _apparmor_profile: str

    # What the MIXIN owns, with class-level defaults. Annotation-only was a landmine: these are
    # read by a property that can launch a jail, so a host class that sets them late -- or a
    # third backend that does not know it must -- raised AttributeError out of a security check,
    # which is exactly what happened once already. Defaults make that unrepeatable
    # (claude-code-review lens, round 5 of #177).
    _apparmor_last_seen: bool | None = None
    _proof: tuple[bool, float, float] | None = None
    _warned_unprovable: bool = False
    _suspended_for_diagnosis: bool = False
    _armed_at_admission: bool | None = None

    def _apparmor_enforcing_now(self) -> bool:
        raise NotImplementedError

    # Each backend's builder takes its own extra keywords (bwrap's seccomp fd), so the mixin
    # pins only the argument it passes. Untyped on purpose: a stricter signature here just
    # makes every backend's real builder an "incompatible override" for keywords the mixin
    # never uses.
    _build_argv: Any

    def _run_probe(self, req: SandboxRequest) -> subprocess.CompletedProcess[str]:
        """Run one probe with the profile ATTACHED, and hand back the finished process.

        The seam is the whole execution, not just the argv. An argv-only seam let bwrap build a
        command referring to a seccomp memfd that the probe's own `subprocess.run` never passed
        to the child -- `bwrap: Can't read seccomp data: Bad file descriptor`, so every probe
        failed and a correctly loaded profile was reported as unattachable. A backend whose
        launch needs more than an argv can now say so in one place.

        `attach_apparmor=True` explicitly: these probes are what DECIDE whether the profile is
        believable, so they cannot wait on the answer they produce.
        """
        return subprocess.run(
            self._build_argv(req, attach_apparmor=True),
            capture_output=True, text=True, timeout=60,
        )

    def _apparmor_attaches_at_all(self) -> bool | None:
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
            out = self._run_probe(req)
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("apparmor_attach_probe_failed reason=%s", exc)
            return None
        if out.returncode != 0:
            _log.warning(
                "apparmor_attach_probe_failed backend=%s rc=%s stderr=%s",
                self.name, out.returncode, out.stderr.strip()[-200:],
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
            out = self._run_probe(req)
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("apparmor_attachment_unprovable backend=%s reason=%s", self.name, exc)
            return None
        if out.returncode != 0:
            _log.warning(
                "apparmor_attachment_unprovable backend=%s rc=%s stderr=%s",
                self.name, out.returncode, out.stderr.strip()[-200:],
            )
            return None
        return out.stdout.strip()

    def apparmor_attachment_is_believable(self) -> bool:
        """Whether an ASSERTED profile survives being measured. Three verdicts, plus "ask later".

        Reached only when `profile_evidence` is ASSERTED -- a kernel reading needs no second
        opinion, and is not re-probed. There the only evidence is an environment variable that
        cannot tell `enforce` from `complain`, while arming on it buys `--proc_rw` (a writable
        /proc/self/mem for the child), so it gets measured instead of believed.

        * PROVEN -- the child, asked from inside the jail, reports THIS profile in enforce or
          kill mode. Nothing can assert that away.
        * DISPROVED -- the reader could not report AND the profile cannot be attached to the
          documented probe binary at all: it is absent, or unusable. Disarm.
        * UNPROVABLE -- the profile attaches, but the reader could not run (a workload profile
          may legitimately permit its parser and `/usr/bin/true` without permitting a file
          reader). Keep the operator's assertion, warn once, name what to permit -- rejecting a
          correctly configured backend over a diagnostic is the worse error (codex, #177).
        * TRANSIENT -- the probe itself failed (a 60s timeout, ENOMEM on fork). Not a verdict:
          answer from the last one if there is one, and write NO cache entry, because caching
          a transient failure refused every job for the whole TTL on a host that had already
          recovered (claude-code-review lens, round 4 of #177).

        Order matters for cost: the proof comes FIRST, and the structural attach probe runs only
        when the proof cannot report -- it is load-bearing for exactly that branch. Asking it
        first cost a second jail launch on every healthy TTL miss.

        The verdict is cached for `_PROOF_TTL_S`, stamped AFTER the measurement (stamping at
        entry made every entry `probe_duration` seconds old on arrival, so a probe slower than
        the TTL produced a cache that was expired when written), on the monotonic clock, which
        cannot be stepped backwards.
        """
        if self._proof is not None and time.monotonic() - self._proof[1] < self._proof[2]:
            return self._proof[0]

        got = self.prove_apparmor_attachment()
        if got is not None:
            name, _, mode = got.partition(" (")
            ok = name.strip() == self._apparmor_profile and mode.startswith(("enforce", "kill"))
            if not ok:
                _log.warning(
                    "apparmor_assertion_disproved backend=%s profile=%s child_reports=%r "
                    "note=asserted via BLASTBOX_APPARMOR_PROFILES but the kernel disagrees; "
                    "no profile is attached",
                    self.name, self._apparmor_profile, got,
                )
            self._proof = (ok, time.monotonic(), _PROOF_TTL_S)
            return ok

        attaches = self._apparmor_attaches_at_all()
        if attaches is None:
            # RETRY once. A transient failure with no previous verdict is the one moment this
            # has nothing to fall back on, and "trust the assertion" there is a fail-open
            # window, however narrow (nemotron, round 5 of #177). One more attempt costs a
            # jail launch and removes the single-fork-failure case; if it is still transient
            # the honest answer is the operator's assertion, said out loud, because the
            # alternative -- refusing every job because one fork failed -- is the worse error.
            attaches = self._apparmor_attaches_at_all()
        if attaches is None:
            # TRANSIENT, twice. We know NOTHING about this profile -- not that it is absent, not
            # that it is enforcing -- so this is the one branch that must not fall back on the
            # operator's word. Before the round-4 refactor an exception here answered False and
            # the backend reported `apparmor_missing`; the refactor turned it into "trust the
            # assertion", so a host whose proof jail could not launch reported `secure = True`
            # and attached `--proc_rw` on the strength of an environment variable that was never
            # measured (claude-code-review lens, round 5 of #177 -- reproduced: reasons [],
            # secure True, six 60s probes, nothing cached). Back to fail-closed.
            #
            # Cached only for `_TRANSIENT_TTL_S`, not the verdict TTL: long enough to stop the
            # probe storm, short enough that the backend re-arms itself the moment probes work.
            self._warn_once_unprovable(
                "apparmor_proof_unmeasurable backend=%s profile=%s "
                "note=the probe failed transiently twice; confinement CANNOT be confirmed, so "
                "this backend reports apparmor_missing until a probe succeeds"
                % (self.name, self._apparmor_profile)
            )
            self._proof = (False, time.monotonic(), _TRANSIENT_TTL_S)
            return False
        if not attaches:
            _log.warning(
                "apparmor_assertion_disproved backend=%s profile=%s "
                "note=the profile cannot be attached at all (absent, or it denies the "
                "documented probe binary); no profile is attached",
                self.name, self._apparmor_profile,
            )
            self._proof = (False, time.monotonic(), _PROOF_TTL_S)
            return False

        self._warn_once_unprovable(
            "apparmor_assertion_unprovable backend=%s profile=%s "
            "note=the in-jail proof could not run (the profile denies %s); the assertion "
            "stands unverified. Permit it to have the assertion checked."
            % (self.name, self._apparmor_profile, _PROOF_READER or "a file reader")
        )
        self._proof = (True, time.monotonic(), _PROOF_TTL_S)
        return True

    def _warn_once_unprovable(self, msg: str) -> None:
        """One flag, not a set: the message is built from two per-instance constants, so the set
        could never hold more than one string -- and a set-shaped warn-once cache is the shape
        that grows unbounded elsewhere in this repo (claude-code-review lens, round 4 of #177).
        """
        if self._warned_unprovable:
            return
        self._warned_unprovable = True
        _log.warning(msg)

    def note_admitted(self, *, armed: bool) -> None:
        """Called by the selector on the backend it actually admits.

        `_armed_at_admission` was captured in the CONSTRUCTOR, which is not when admission
        happens: a profile that becomes enforcing between construction and the selector's
        security check gets the backend admitted as confined with the flag still False, and
        the regression guard is then inert for the life of that worker (codex, #177). The
        selector knows the real moment; this is it.

        It takes the selector's OWN observation rather than re-reading the kernel. A fresh read
        here could see confinement that vanished in the microseconds since the security check
        passed, and would then record False -- admitting a backend the selector judged confined
        while permanently disabling the guard that protects it, so every later job runs
        unconfined with nothing to notice (codex, round 3 of #177).
        """
        self._armed_at_admission = armed

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
            #
            # CHECKED FIRST, before the baseline branch below: a suspended launch reports
            # apparmor_active False by construction, so letting it define the baseline would
            # record "never confined" and disarm the guard for the life of the worker. No caller
            # reaches that order today; the guard's own reason for existing says it must not
            # depend on that (claude-code-review lens, round 5 of #177).
            return
        if self._armed_at_admission is None:
            # First launch of a backend nobody admitted through the selector (an engine building
            # one directly). This is its baseline, measured with the same yardstick the guard
            # uses; a REGRESSION from here is still refused.
            self._armed_at_admission = (
                self.apparmor_active if attached is None else attached
            )
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
        was_suspended = self._suspended_for_diagnosis
        self._suspended_for_diagnosis = True
        try:
            yield
        finally:
            self._aa_exec = saved
            # RESTORE, not clear: a nested suspension used to leave the outer one unprotected
            # (claude-code-review lens, round 5 of #177).
            self._suspended_for_diagnosis = was_suspended

    @property
    def apparmor_active(self) -> bool:
        """Whether a profile is ACTUALLY attached, not merely whether nsjail could attach one.

        Returning the probe alone told callers and diagnostics that confinement was active
        while `_build_argv` was omitting the flag because the profile is not loaded (codex,
        #159).
        """
        if self._aa_exec is None or not self._apparmor_enforcing_now():
            return False
        if profile_evidence(self._apparmor_profile) == ASSERTED:
            # The only evidence is an environment variable, which cannot tell enforce from
            # complain. Measure it (TTL-bounded) instead of taking its word.
            return self.apparmor_attachment_is_believable()
        return True

    # ------------------------------------------------------------------
    # Public interface
