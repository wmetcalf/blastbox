"""Whether a named AppArmor profile is actually loaded on this host.

Shared by the bwrap and nsjail backends because attaching an UNLOADED profile does not
degrade either of them -- it breaks them:

* bwrap runs the child through ``aa-exec <profile>``, which fails the exec.
* nsjail passes ``--proc_apparmor <profile>``, i.e. AA_CHANGE_ONEXEC, which fails the exec.

bwrap has always checked. nsjail did not, and attached the flag whenever the installed nsjail
advertised support -- naming ``blastbox-sandbox``, a profile this repository does not ship
(issue #158). One copy of the check, so the two backends cannot drift on a question with the
same answer and the same consequence.
"""

from __future__ import annotations

import os

_PROFILES = "/sys/kernel/security/apparmor/profiles"

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


def profile_loaded(profile: str) -> bool:
    """True only if the named profile can be CONFIRMED loaded.

    Any uncertainty -- securityfs unreadable, profile absent -- is False, so the caller skips
    the confinement and records it rather than failing every run. An explicit
    ``BLASTBOX_APPARMOR_PROFILES`` (comma list) assertion wins, for hosts where securityfs is
    not readable by the worker but the operator knows what is loaded.
    """
    asserted = os.environ.get("BLASTBOX_APPARMOR_PROFILES", "").strip()
    if profile in {p.strip() for p in asserted.split(",") if p.strip()}:
        # An operator assertion for hosts where securityfs is unreadable by the worker. It
        # asserts ENFORCEMENT, not mere presence -- naming a complain-mode profile here is the
        # operator telling us something untrue. It is an ADDITIONAL source of evidence, not an
        # override: an operator who lists A and B has said nothing about C, and refusing a C
        # the kernel reports as enforcing would drop real confinement for no gain.
        return True
    try:
        # `surrogateescape`, not `ascii`: an AppArmor profile name is usually a PATH, and a
        # path is bytes, so one profile with a non-UTF-8 byte -- belonging to some UNRELATED
        # program -- would abort the scan before reaching ours. Swallowing that error is not
        # enough: it would answer False for a profile that IS enforcing, so nsjail would drop
        # `--proc_apparmor` and run the workload unconfined because of somebody else's
        # filename. Surrogates round-trip losslessly and never equal an ASCII profile name.
        with open(_PROFILES, encoding="utf-8", errors="surrogateescape") as fh:
            return any(_line_is_enforcing(line, profile) for line in fh)
    except (OSError, UnicodeDecodeError):
        # This helper is called from a backend CONSTRUCTOR, and `select_sandbox` only treats
        # `SandboxUnavailable` as "try the next backend" -- anything else aborts auto-selection
        # rather than falling through to bwrap. It must answer, never raise (codex, #159).
        return False


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
