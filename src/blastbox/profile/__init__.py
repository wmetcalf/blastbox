"""blastbox.profile — derive sandbox policies by tracing an engine over a corpus.

One capture pass yields BOTH enforcement axes: a syscall allowlist (seccomp: KAFEL / OCI
json) and a filesystem+network profile (Landlock: a nono profile). The cheap, safe use is
the **drift-gate**: assert the engine uses no syscall the shipped denylist forbids and
opens no real network egress — a CI regression check that catches a dependency bump
quietly widening the surface.

    from blastbox.profile import StraceCapture, profile_command
    draft = profile_command(["soffice", "--convert-to", "pdf", ...], trace_dir=tmp)
    assert not draft.denylist_violations(DENY)   # denylist still safe
    assert not draft.net.inet                     # no egress
    draft.to_oci_seccomp(); draft.to_nono_profile()   # candidate policies
"""
from blastbox.profile.capture import Capture, StraceCapture, profile_command
from blastbox.profile.draft import NetDraft, PolicyDraft

__all__ = [
    "Capture",
    "StraceCapture",
    "profile_command",
    "PolicyDraft",
    "NetDraft",
]
