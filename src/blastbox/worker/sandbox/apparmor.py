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


def profile_loaded(profile: str) -> bool:
    """True only if the named profile can be CONFIRMED loaded.

    Any uncertainty -- securityfs unreadable, profile absent -- is False, so the caller skips
    the confinement and records it rather than failing every run. An explicit
    ``BLASTBOX_APPARMOR_PROFILES`` (comma list) assertion wins, for hosts where securityfs is
    not readable by the worker but the operator knows what is loaded.
    """
    asserted = os.environ.get("BLASTBOX_APPARMOR_PROFILES", "").strip()
    if asserted:
        # An operator assertion for hosts where securityfs is unreadable by the worker. It
        # asserts ENFORCEMENT, not mere presence -- naming a complain-mode profile here is the
        # operator telling us something untrue.
        return profile in {p.strip() for p in asserted.split(",") if p.strip()}
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
    return rest.rstrip().rstrip(")") == "enforce"
