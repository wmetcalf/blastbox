"""Capture strategies that observe a command and produce a :class:`PolicyDraft`.

A ``Capture`` turns one argv into (a) a traced argv and (b) a parser of the trace. The
default :class:`StraceCapture` uses ``strace -f`` — one pass yields BOTH policy axes
(syscall histogram → seccomp; openat/stat/connect targets → Landlock/nono). nono's own
"learn" is interactive (its audit log is attestation, not an access trace), so strace is
the right *capture* tool while nsjail/nono are the *enforcement* backends.

The split mirrors the worker ``Sandbox`` protocol: a capture is pluggable (strace today,
eBPF later) behind the same ``PolicyDraft`` so swapping it touches no caller.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Callable, Protocol, Sequence

from blastbox.profile.draft import NetDraft, PolicyDraft

# A syscall line: optional "<pid> " prefix, then "name(" at the start.
# All parsing is LINE-BASED: a negated char class like [^"]+ matches newlines, so a
# whole-text regex bleeds across lines on a truncated/odd line. Anchor every match to one line.
_SYSCALL_RE = re.compile(r"^(?:\d+\s+)?([a-z_][a-z0-9_]*)\(")
# A path-taking syscall + its first quoted ABSOLUTE path argument, within one line.
_PATH_LINE_RE = re.compile(
    r"^(?:\d+\s+)?(?:openat2?|open|stat|lstat|newfstatat|access|faccessat[0-9]?"
    r"|readlink(?:at)?|statx)\([^\"]*\"(/[^\"]+)\"",
)
_INET_PORT_RE = re.compile(r"htons\((\d+)\)")
_INET_ADDR_RE = re.compile(r"inet6?_addr\(\"([^\"]+)\"\)")
_NON_SYSCALL = frozenset({"exit", "killed", "Process", "strace"})


class Capture(Protocol):
    def wrap(self, argv: Sequence[str], trace_path: Path) -> list[str]:
        """Return the argv that runs ``argv`` under tracing, writing to ``trace_path``."""
        ...

    def parse(self, trace_path: Path) -> PolicyDraft:
        """Parse a written trace into a PolicyDraft."""
        ...


class StraceCapture:
    """``strace -f`` capture: syscalls + fs paths + network in one pass."""

    name = "strace"

    def __init__(self, strace_bin: str = "strace") -> None:
        self.strace_bin = strace_bin

    def wrap(self, argv: Sequence[str], trace_path: Path) -> list[str]:
        # No -y: fd path annotations (<path>) add noise; paths come from the syscall args.
        return [
            self.strace_bin, "-f", "-qq", "-s", "256",
            "-e", "trace=all", "-o", str(trace_path), *argv,
        ]

    def parse(self, trace_path: Path) -> PolicyDraft:
        draft = PolicyDraft()
        syscalls: set[str] = set()
        reads: set[str] = set()
        writes: set[str] = set()
        net = NetDraft()
        # Stream the trace line-by-line — a `strace -f` log over a real corpus run can be
        # hundreds of MB; read_text() would load it all into memory.
        with open(trace_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                sm = _SYSCALL_RE.match(line)
                if sm and sm.group(1) not in _NON_SYSCALL:
                    syscalls.add(sm.group(1))
                pm = _PATH_LINE_RE.match(line)
                if pm:
                    path = pm.group(1)
                    if "O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line:
                        writes.add(path)
                    else:
                        reads.add(path)
                if "sa_family=AF_UNIX" in line:
                    net.unix = True
                if "connect(" in line and "AF_INET" in line:
                    port_m = _INET_PORT_RE.search(line)
                    addr_m = _INET_ADDR_RE.search(line)
                    net.inet.add(
                        (addr_m.group(1) if addr_m else "?",
                         int(port_m.group(1)) if port_m else 0)
                    )
        draft.syscalls = syscalls
        draft.write_paths = writes
        draft.read_paths = reads - writes
        draft.net = net
        return draft


def profile_command(
    argv: Sequence[str],
    *,
    trace_dir: Path,
    capture: Capture | None = None,
    runner: Callable[[Sequence[str]], object] | None = None,
    label: str = "0",
) -> PolicyDraft:
    """Run ``argv`` under ``capture`` and return the PolicyDraft.

    ``runner`` defaults to a plain subprocess; inject one (e.g. a sandboxed runner) to
    profile *inside* a worker image for path/syscall fidelity. The traced process's own
    exit status is ignored — a non-zero conversion still produced a useful trace.
    """
    cap = capture or StraceCapture()
    Path(trace_dir).mkdir(parents=True, exist_ok=True)  # else strace can't write the trace
    trace = Path(trace_dir) / f"trace_{label}.log"
    traced = cap.wrap(argv, trace)
    run = runner or (lambda a: subprocess.run(list(a), capture_output=True, timeout=180))
    run(traced)
    return cap.parse(trace)
