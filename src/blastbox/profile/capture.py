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
_SYSCALL_RE = re.compile(r"^(?:\d+\s+)?([a-z_][a-z0-9_]*)\(", re.MULTILINE)
# A path argument to a path-taking syscall: name(..."<path>"...
_PATH_RE = re.compile(
    r"\b(?:openat2?|open|stat|lstat|newfstatat|access|faccessat2?|readlink(?:at)?|statx)"
    r"\((?:[^)\"]*)\"([^\"]+)\"",
)
# Whether an open* call is for writing (O_WRONLY/O_RDWR/O_CREAT in the flags).
_WRITE_OPEN_RE = re.compile(
    r"\b(?:openat2?|open)\([^)]*\"([^\"]+)\"[^)]*O_(?:WRONLY|RDWR|CREAT)",
)
_HAS_AF_UNIX = re.compile(r"sa_family=AF_UNIX")
_INET_PORT_RE = re.compile(r"htons\((\d+)\)")
_INET_ADDR_RE = re.compile(r"inet6?_addr\(\"([^\"]+)\"\)")


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
        return [
            self.strace_bin, "-f", "-qq", "-y", "-s", "256",
            "-e", "trace=all", "-o", str(trace_path), *argv,
        ]

    def parse(self, trace_path: Path) -> PolicyDraft:
        text = Path(trace_path).read_text(errors="replace")
        draft = PolicyDraft()
        draft.syscalls = {m.group(1) for m in _SYSCALL_RE.finditer(text)}
        # signal/exit pseudo-lines aren't real syscalls
        draft.syscalls -= {"exit", "killed", "Process", "strace"}
        writes = {m.group(1) for m in _WRITE_OPEN_RE.finditer(text)}
        draft.write_paths = writes
        draft.read_paths = {m.group(1) for m in _PATH_RE.finditer(text)} - writes
        net = NetDraft(unix=bool(_HAS_AF_UNIX.search(text)))
        # Per-line: a connect() to an AF_INET sockaddr is real egress. Pair the port +
        # addr within the same line (robust against inet_addr(...)'s own parens).
        for line in text.splitlines():
            if "connect(" not in line or "AF_INET" not in line:
                continue
            port_m = _INET_PORT_RE.search(line)
            addr_m = _INET_ADDR_RE.search(line)
            net.inet.add(
                (addr_m.group(1) if addr_m else "?", int(port_m.group(1)) if port_m else 0)
            )
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
    trace = Path(trace_dir) / f"trace_{label}.log"
    traced = cap.wrap(argv, trace)
    run = runner or (lambda a: subprocess.run(list(a), capture_output=True, timeout=180))
    run(traced)
    return cap.parse(trace)
