"""``PolicyDraft`` — what a profiling run revealed about an engine's behaviour, plus
emitters that turn it into shippable sandbox-policy artifacts.

A draft is the union of (syscalls, read paths, write paths, network) observed while the
engine ran over a corpus. It feeds two enforcement backends from one capture:
seccomp (nsjail KAFEL / OCI json) and Landlock (a nono profile). Drafts union with
``|=`` so a corpus sweep accumulates into one.

NOTE: emitters produce **candidate** artifacts. An allowlist breaks on the first unseen
syscall a rare input needs, so a human reviews the diff before flipping a denylist to an
allowlist; the shipped denylist stays the safe default. ``denylist_violations`` is the
cheap, safe check (does the engine use a syscall we *deny*?) and is what the drift-gate runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NetDraft:
    """Network activity observed. ``inet`` non-empty ⇒ real egress (a finding)."""

    unix: bool = False
    inet: set[tuple[str, int]] = field(default_factory=set)  # (addr, port)

    def merge(self, other: "NetDraft") -> None:
        self.unix |= other.unix
        self.inet |= other.inet


@dataclass
class PolicyDraft:
    syscalls: set[str] = field(default_factory=set)
    read_paths: set[str] = field(default_factory=set)
    write_paths: set[str] = field(default_factory=set)
    net: NetDraft = field(default_factory=NetDraft)

    def __ior__(self, other: "PolicyDraft") -> "PolicyDraft":
        self.syscalls |= other.syscalls
        self.read_paths |= other.read_paths
        self.write_paths |= other.write_paths
        self.net.merge(other.net)
        return self

    # ---- analysis ----------------------------------------------------------
    def denylist_violations(self, denylist: set[str]) -> set[str]:
        """Syscalls the engine actually used that the given denylist forbids.

        Empty ⇒ the denylist is a safe superset for this corpus (the drift-gate's
        green condition)."""
        return self.syscalls & denylist

    def grant_roots(self, depth: int = 2) -> list[str]:
        """Collapse observed paths to their top ``depth`` path components (e.g.
        ``/usr/lib/...`` → ``/usr/lib``) — the read-grant roots for a Landlock profile."""
        roots: set[str] = set()
        for p in self.read_paths | self.write_paths:
            parts = [c for c in p.split("/") if c]
            if not parts:
                continue
            roots.add("/" + "/".join(parts[:depth]))
        return sorted(roots)

    # ---- emitters ----------------------------------------------------------
    def to_kafel(self, policy_name: str = "engine", default: str = "KILL") -> str:
        """nsjail KAFEL allowlist (candidate). DEFAULT KILL with an ALLOW{} of observed."""
        body = ", ".join(sorted(self.syscalls))
        return (
            f"# CANDIDATE allowlist — auto-derived; an allowlist breaks on the first unseen\n"
            f"# syscall, so validate over a broad corpus before shipping over the denylist.\n"
            f"POLICY {policy_name} {{\n  ALLOW {{\n    {body}\n  }}\n}}\n"
            f"USE {policy_name} DEFAULT {default}\n"
        )

    def to_oci_seccomp(self, arch: str = "SCMP_ARCH_X86_64") -> dict:
        """OCI seccomp.json (candidate). defaultAction ERRNO mirrors the recoverable-EPERM
        posture of the shipped denylist (not KILL)."""
        return {
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "architectures": [arch],
            "syscalls": [
                {"names": sorted(self.syscalls), "action": "SCMP_ACT_ALLOW"}
            ],
            "_comment": "CANDIDATE allowlist auto-derived from a profiling sweep; "
            "validate broadly before shipping.",
        }

    def to_nono_profile(self, name: str = "engine", depth: int = 2) -> dict:
        """A nono (Landlock) profile from the read roots + the net verdict.

        Conforms to nono's profile schema (validated via ``nono profile validate``):
        ``meta`` only takes name/version/description/author — no free-form comments.
        """
        return {
            "meta": {"name": name, "description": "auto-derived from a blastbox profiling sweep"},
            "groups": {"include": ["deny_credentials"]},
            "workdir": {"access": "readwrite"},
            "network": {"block": not self.net.inet},
            "filesystem": {"read": self.grant_roots(depth), "allow": ["$WORKDIR"]},
        }
