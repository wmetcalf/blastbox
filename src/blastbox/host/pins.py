"""Find every place a consumer repo pins blastbox, and report disagreement.

A consumer pins blastbox in several unrelated files, resolved by two different
installers:

* ``pyproject.toml`` -- ``project.dependencies`` and every extra, as PEP 508
  requirements, with extras and environment markers.
* Dockerfiles -- ``ARG BLASTBOX_VERSION=...`` consumed by a later
  ``pip install "blastbox==${BLASTBOX_VERSION}"``, and direct install lines.
* A hashed lock installed with ``--require-hashes``.

Nothing connects them, so they drift independently. Observed 2026-09-01: host
0.1.26, cold-worker 0.1.25 and warm/guest images 0.1.17, against a PyPI release
of 0.1.26 and a ``main`` 250 commits ahead of it.

**Prose is not a pin.** These trees carry sentences like ``REQUIRES
blastbox>=0.1.8`` in a compose comment and superseded design docs saying
'bump "blastbox>=0.1.4"'. A naive grep across redtusk and clippyshot reported
twelve stale pins and every one was a comment. So this reads the INSTALL PATH
only: parsed requirements, install directives with comments stripped and
continuations joined, and lock pins -- and never ``docs/`` or ``tests/``.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_ARG_RE = re.compile(r'^\s*ARG\s+BLASTBOX_VERSION\s*=\s*["\']?([0-9][^"\'\s]*)["\']?')
# A real install: `pip install`, `pip3 install`, `uv pip install`, `python -m pip install`.
_INSTALL_RE = re.compile(r'\b(?:pip[0-9.]*|uv\s+pip)\s+install\b')
# `blastbox`, optional extras, then a specifier set. Stops at a PEP 508 marker (`;`),
# a quote, or whitespace.
_REQ_RE = re.compile(
    r'blastbox(?P<extras>\[[a-z0-9,._\-]+\])?\s*'
    r'(?P<spec>(?:[=<>!~]=|[<>])\s*[0-9][^"\';\s]*'
    r'(?:\s*,\s*(?:[=<>!~]=|[<>])\s*[0-9][^"\';\s]*)*)'
)
_LOCK_RE = re.compile(r'^blastbox(?:\[[a-z0-9,._\-]+\])?\s*==\s*([^\s\;]+)')
_ARG_USE_RE = re.compile(r'\$\{?BLASTBOX_VERSION\}?')


class PinScanError(RuntimeError):
    """A file that should have been readable was not.

    Raised rather than skipped: silently returning no pins from a malformed
    pyproject makes a drifted repo report OK, which is the failure this module
    exists to prevent.
    """


@dataclass(frozen=True)
class Pin:
    """One install-path pin on blastbox."""

    path: str
    line: int
    kind: str          # pyproject | dockerfile-arg | dockerfile-pip | lock
    raw: str
    specifier: str

    @property
    def floor(self) -> str | None:
        """The version this pin guarantees.

        For ``==X`` / ``>=X`` / ``~=X`` that is X. A bare upper bound (``<Y``)
        pins nothing on its own and yields None.
        """
        for part in self.specifier.split(","):
            part = part.strip()
            for op in ("==", ">=", "~=", "<="):
                if part.startswith(op):
                    return part[len(op):].strip()
        return None


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment. Prose lives there; pins do not."""
    hashpos = line.find("#")
    return line if hashpos < 0 else line[:hashpos]


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join shell continuations, so a wrapped ``RUN pip install \\`` is one line.

    Returns (line number of the FIRST physical line, joined text). Comments are
    stripped per physical line first: a ``#`` inside a continued RUN still ends
    that physical line.
    """
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = _strip_comment(raw).rstrip()
        if not buf:
            start = i
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        out.append((start, buf + stripped))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def _split_requirement(req: str) -> tuple[str, str] | None:
    """(name-with-extras, specifier) for a blastbox requirement, else None.

    Handles extras (``blastbox[host,s3]``) and drops PEP 508 environment markers
    (``blastbox>=0.1.27; python_version >= '3.12'``) -- the marker is not part of
    the version and must not leak into it.
    """
    head = req.split(";", 1)[0].strip()
    if not head.startswith("blastbox"):
        return None
    m = _REQ_RE.match(head)
    if not m:
        return None
    return head[: m.start("spec")].strip(), re.sub(r"\s+", "", m.group("spec"))


def _scan_pyproject(path: Path) -> list[Pin]:
    try:
        raw_text = path.read_text(encoding="utf-8")
        data = tomllib.loads(raw_text)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PinScanError(f"{path}: {exc}") from exc
    project = data.get("project") or {}
    reqs: list[str] = list(project.get("dependencies") or [])
    for extra_reqs in (project.get("optional-dependencies") or {}).values():
        reqs.extend(extra_reqs)

    lines = raw_text.splitlines()
    claimed: set[int] = set()
    out: list[Pin] = []
    for req in reqs:
        parsed = _split_requirement(req)
        if not parsed:
            continue
        name, spec = parsed
        # Attribute to the line the requirement is written on. Match the WHOLE
        # requirement, not just the name: `[project].description` here reads
        # "pdf-titan-arum PDF forensic engine for blastbox", so a bare-name needle
        # lands on the description. Not a comma split either -- that truncates
        # `blastbox[host,s3]` to `blastbox[host`. Comments are stripped, and a line
        # already claimed by an identical requirement in another extra is skipped.
        needles = [req.strip(), f"{name}{spec}"]
        lineno = next(
            (
                i + 1
                for i, ln in enumerate(lines)
                if (i + 1) not in claimed
                and any(n and n in _strip_comment(ln).replace(" ", "") for n in
                        (needle.replace(" ", "") for needle in needles))
            ),
            0,
        )
        claimed.add(lineno)
        out.append(Pin(str(path), lineno, "pyproject", req, spec))
    return out


def _scan_dockerfile(path: Path) -> list[Pin]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PinScanError(f"{path}: {exc}") from exc

    logical = _logical_lines(text)
    # An ARG is only a pin if something in the file installs blastbox THROUGH it.
    arg_is_used = any(
        _INSTALL_RE.search(line) and "blastbox" in line and _ARG_USE_RE.search(line)
        for _, line in logical
    )

    out: list[Pin] = []
    for lineno, line in logical:
        arg = _ARG_RE.match(line)
        if arg:
            if arg_is_used:
                out.append(Pin(str(path), lineno, "dockerfile-arg", line.strip(), "==" + arg.group(1)))
            continue
        if "blastbox" not in line or not _INSTALL_RE.search(line):
            continue
        parsed = _split_requirement(_isolate_requirement(line))
        if parsed:
            out.append(Pin(str(path), lineno, "dockerfile-pip", line.strip(), parsed[1]))
    return out


def _isolate_requirement(line: str) -> str:
    """Pull the blastbox requirement token out of an install command line."""
    m = _REQ_RE.search(line)
    if not m:
        return ""
    start = line.rfind("blastbox", 0, m.end())
    return line[start : m.end()]


def _scan_lock(path: Path) -> list[Pin]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PinScanError(f"{path}: {exc}") from exc
    out: list[Pin] = []
    for i, raw in enumerate(lines, 1):
        m = _LOCK_RE.match(raw)
        if m:
            out.append(Pin(str(path), i, "lock", raw.strip(), "==" + m.group(1)))
    return out


_SKIP_DIRS = {"docs", "tests", ".git", "node_modules", "target", ".venv", "__pycache__"}


def _walk(root: Path):
    """Yield candidate files, PRUNING skipped directories instead of statting them.

    rglob("*") walks into .venv/ and target/ in full before anything filters
    them, which on these repos is tens of thousands of pointless stats.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            else:
                yield entry


def scan(root: Path) -> list[Pin]:
    """Every install-path blastbox pin under ``root``."""
    pins: list[Pin] = []
    for path in _walk(root):
        name = path.name
        if name == "pyproject.toml":
            pins.extend(_scan_pyproject(path))
        elif name.startswith("Dockerfile"):
            pins.extend(_scan_dockerfile(path))
        elif re.fullmatch(r"requirements[\w.\-]*\.(txt|lock)|[\w.\-]+\.lock", name):
            pins.extend(_scan_lock(path))
    return sorted(pins, key=lambda p: (p.path, p.line))


def disagreements(pins: list[Pin]) -> dict[str, list[Pin]]:
    """Group pins by the version they guarantee; more than one group is drift."""
    groups: dict[str, list[Pin]] = {}
    for pin in pins:
        floor = pin.floor
        if floor:
            groups.setdefault(floor, []).append(pin)
    return groups
