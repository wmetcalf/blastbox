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

import logging
import os
import shutil

_PROFILES = "/sys/kernel/security/apparmor/profiles"

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
