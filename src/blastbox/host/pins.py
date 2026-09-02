"""Find and reconcile every place a consumer repo pins blastbox.

A consumer (redtusk, clippyshot, titanarum) pins blastbox in several unrelated
files, in several syntaxes, resolved by two different installers:

* ``pyproject.toml`` -- ``project.dependencies`` and every extra, as PEP 508
  requirements, with or without extras (``blastbox[host,s3]>=0.1.27,<0.2``).
* Dockerfiles -- ``ARG BLASTBOX_VERSION=0.1.27`` consumed by a later
  ``pip install "blastbox==${BLASTBOX_VERSION}"``, and direct
  ``pip install "blastbox[host]>=0.1.27,<0.2"`` lines.
* A hashed lock (``deploy/requirements.lock``) installed with
  ``--require-hashes``.

Nothing connects them, so they drift independently. Observed 2026-09-01: a
fleet running blastbox 0.1.26 on the host, 0.1.25 in the cold-worker image and
0.1.17 inside the warm/guest images, against a PyPI release of 0.1.26 and a
``main`` 250 commits ahead of it.

**Prose is not a pin.** These files are full of sentences like ``REQUIRES
blastbox>=0.1.8`` in a compose comment, ``blastbox>=0.1.8 enforces the
manifest`` in a test docstring, and whole superseded design docs. A grep counts
those and cries wolf -- verified: a naive grep reported twelve stale pins across
two repos and every one was a comment. So this module reads the INSTALL PATH
only: parsed TOML requirements, and Dockerfile directives with comments stripped.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

# `ARG BLASTBOX_VERSION=0.1.27` (optionally quoted).
_ARG_RE = re.compile(r'^\s*ARG\s+BLASTBOX_VERSION\s*=\s*["\']?([0-9][^"\'\s]*)["\']?')
# A blastbox requirement anywhere on a RUN/pip line: name, optional extras, specifier.
_REQ_RE = re.compile(r'blastbox(\[[a-z0-9,\-]+\])?\s*((?:[=<>!~]=?[0-9][^"\',\s]*)(?:\s*,\s*[=<>!~]=?[0-9][^"\',\s]*)*)')
# `blastbox==0.1.27 \` at the start of a lock line.
_LOCK_RE = re.compile(r'^blastbox==([^\s\\]+)')


@dataclass(frozen=True)
class Pin:
    """One install-path pin on blastbox."""

    path: str
    line: int
    kind: str          # pyproject | dockerfile-arg | dockerfile-pip | lock
    raw: str           # the text as written
    specifier: str     # e.g. ">=0.1.27,<0.2" or "==0.1.27"

    @property
    def floor(self) -> str | None:
        """The version this pin actually resolves to install, as a string.

        For a ``>=X,<Y`` range that is X: pip will take the newest release in
        the range, but X is what the repo GUARANTEES, and it is what drifts.
        """
        for part in self.specifier.split(","):
            part = part.strip()
            for op in ("==", ">="):
                if part.startswith(op):
                    return part[len(op):]
        return None


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment. Prose lives there; pins do not."""
    hashpos = line.find("#")
    return line if hashpos < 0 else line[:hashpos]


def _scan_pyproject(path: Path) -> list[Pin]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    project = data.get("project") or {}
    reqs: list[str] = list(project.get("dependencies") or [])
    for extra_reqs in (project.get("optional-dependencies") or {}).values():
        reqs.extend(extra_reqs)
    out: list[Pin] = []
    claimed: set[int] = set()
    text = path.read_text(encoding="utf-8").splitlines()
    for req in reqs:
        m = _REQ_RE.search(req)
        if not m or not req.strip().startswith("blastbox"):
            continue
        # Report the line the requirement is written on, for a usable diagnostic.
        # Skip comment lines and lines already claimed by an earlier requirement:
        # this file explains its own pins in prose right above them, and the same
        # requirement string appears in two extras.
        needle = req.split(",")[0]
        lineno = next(
            (
                i + 1
                for i, ln in enumerate(text)
                if needle in _strip_comment(ln) and (i + 1) not in claimed
            ),
            0,
        )
        claimed.add(lineno)
        out.append(Pin(str(path), lineno, "pyproject", req, m.group(2)))
    return out


def _scan_dockerfile(path: Path) -> list[Pin]:
    out: list[Pin] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for i, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        arg = _ARG_RE.match(line)
        if arg:
            out.append(Pin(str(path), i, "dockerfile-arg", raw.strip(), "==" + arg.group(1)))
            continue
        if "blastbox" not in line:
            continue
        # Only a line that actually installs counts; a COPY or an ENV mentioning
        # blastbox is not a pin.
        if not re.search(r"\bpip\b|\binstall\b", line):
            continue
        m = _REQ_RE.search(line)
        if m and m.group(2):
            out.append(Pin(str(path), i, "dockerfile-pip", raw.strip(), m.group(2)))
    return out


def _scan_lock(path: Path) -> list[Pin]:
    out: list[Pin] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for i, raw in enumerate(lines, 1):
        m = _LOCK_RE.match(raw)
        if m:
            out.append(Pin(str(path), i, "lock", raw.strip(), "==" + m.group(1)))
    return out


def scan(root: Path) -> list[Pin]:
    """Every install-path blastbox pin under ``root``.

    Deliberately narrow. ``docs/`` and ``tests/`` are excluded wholesale: a
    superseded design doc that says "bump to >=0.1.5" is history, not a pin, and
    a test docstring citing a feature floor is documentation.
    """
    pins: list[Pin] = []
    skip = {"docs", "tests", ".git", "node_modules", "target", ".venv"}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in skip for part in rel.parts):
            continue
        name = path.name
        if name == "pyproject.toml":
            pins.extend(_scan_pyproject(path))
        elif name.startswith("Dockerfile"):
            pins.extend(_scan_dockerfile(path))
        elif name.endswith(".lock") or name.startswith("requirements"):
            pins.extend(_scan_lock(path))
    return pins


def disagreements(pins: list[Pin]) -> dict[str, list[Pin]]:
    """Group pins by the version they resolve to; >1 group means drift."""
    groups: dict[str, list[Pin]] = {}
    for pin in pins:
        floor = pin.floor
        if floor:
            groups.setdefault(floor, []).append(pin)
    return groups
