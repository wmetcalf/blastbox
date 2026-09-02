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
# `pip install`, `pip3 install`, `uv pip install`, and pip global options in
# between (`python -m pip --isolated install ...`).
_INSTALL_RE = re.compile(r'\b(?:pip[0-9.]*|uv\s+pip)\s+(?:-[^\s]+\s+)*install\b')
# `blastbox`, optional extras, then a specifier set. Stops at a PEP 508 marker (`;`),
# a quote, or whitespace.
_REQ_RE = re.compile(
    r'(?<![\w.\-])(?i:blastbox)(?P<extras>\[[a-zA-Z0-9,._\-]+\])?\s*'
    r'(?P<spec>(?:[=<>!~]=|[<>])\s*v?[0-9][^"\';\s]*'
    r'(?:\s*,\s*(?:[=<>!~]=|[<>])\s*v?[0-9][^"\';\s]*)*)'
)
# Leading whitespace is legal in a requirements-format file.
_LOCK_RE = re.compile(r'^\s*(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*==\s*([^\s\;]+)')
_ARG_USE_RE = re.compile(r'\$\{?BLASTBOX_VERSION\}?')


def _version_key(version: str) -> tuple[int, ...]:
    """Sortable RELEASE tuple. Suffixes are ignored, not ordered.

    `0.1.27rc1` and `0.1.27` both key to (0, 1, 27) -- this compares releases
    only. The previous docstring claimed pre-releases sort BEFORE the release,
    which the truncation never did, so `max()` fell back to written order for
    such a tie.
    """
    m = re.match(r"^(\d+(?:\.\d+)*)", version)
    if not m:
        return (0,)
    return tuple(int(part) for part in m.group(1).split("."))


def _normalise_version(version: str) -> str:
    """Normalise a PEP 440 release for grouping.

    ``0.1.27`` and ``0.1.27.0`` are the same release; grouping on the raw
    spelling would report drift between two identical pins. Only the release
    segment is normalised -- suffixes (rc, post, local) are left alone rather
    than guessed at.
    """
    head, sep, rest = version.partition("+")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", head)
    if not m:
        return version
    parts = m.group(1).split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts) + m.group(2) + sep + rest


class PinScanError(RuntimeError):
    """A file that should have been readable was not.

    Raised rather than skipped: silently returning no pins from a malformed
    pyproject makes a drifted repo report OK, which is the failure this module
    exists to prevent.
    """


# `blastbox @ git+https://host/repo@v0.1.30` -- a direct reference. It has no
# comparison specifier, so the requirement pattern cannot see it, and dropping it
# silently is the worst outcome: it is the strongest pin a repo can express.
_DIRECT_REF_RE = re.compile(
    r"^(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*@\s*(?P<url>\S+)"
)


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
        """The version this pin guarantees, normalised.

        Only ``==`` / ``>=`` / ``~=`` are floors. An upper bound (``<``, ``<=``)
        constrains but guarantees nothing, and must not be read as the version --
        `blastbox<=0.2,>=0.1.27` guarantees 0.1.27, not 0.2. Order in the
        specifier is not meaningful, so every part is examined.
        """
        floors: list[str] = []
        for part in self.specifier.split(","):
            part = part.strip()
            for op in ("==", ">=", "~="):
                if part.startswith(op):
                    floors.append(_normalise_version(part[len(op):].strip().lstrip("vV")))
                    break
        if not floors:
            return None
        # A set may carry more than one lower bound; the strongest is what the
        # pin actually guarantees, and it is not necessarily written first.
        return max(floors, key=_version_key)


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
    if not head.lower().startswith("blastbox"):
        return None
    direct = _DIRECT_REF_RE.match(head)
    if direct:
        # Record the reference itself as the specifier. floor() yields None for
        # it (no comparison operator), so it does not fake a version -- but the
        # pin is now VISIBLE instead of vanishing.
        return head.split("@", 1)[0].strip(), "@" + direct.group("url")
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
    # PEP 735 dependency-groups live at the TOP level, not under [project].
    for group in (data.get("dependency-groups") or {}).values():
        reqs.extend(r for r in group if isinstance(r, str))

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
        _INSTALL_RE.search(line) and "blastbox" in line.lower() and _ARG_USE_RE.search(line)
        for _, line in logical
    )

    out: list[Pin] = []
    for lineno, line in logical:
        arg = _ARG_RE.match(line)
        if arg:
            if arg_is_used:
                out.append(Pin(str(path), lineno, "dockerfile-arg", line.strip(), "==" + arg.group(1)))
            continue
        if "blastbox" not in line.lower() or not _INSTALL_RE.search(line):
            continue
        # One logical RUN can install blastbox more than once
        # (`pip install a && pip install b`); report every pin.
        for token in _isolate_requirements(line):
            parsed = _split_requirement(token)
            if parsed:
                out.append(Pin(str(path), lineno, "dockerfile-pip", line.strip(), parsed[1]))
    return out


def _isolate_requirements(line: str) -> list[str]:
    """Every blastbox requirement token on an install command line."""
    out: list[str] = []
    for m in _REQ_RE.finditer(line):
        start = line.lower().rfind("blastbox", 0, m.end())
        out.append(line[start : m.end()])
    return out


_TOML_LOCK_NAMES = {"uv.lock", "poetry.lock", "pdm.lock"}


def _scan_toml_lock(path: Path) -> list[Pin]:
    """blastbox pins inside a TOML lock (uv/poetry/pdm).

    These were previously handed to the requirements-format scanner, whose
    pattern cannot match TOML -- so the file was read, produced nothing, and the
    repo reported clean. Silent under-reporting is the failure PinScanError
    exists to prevent.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PinScanError(f"{path}: {exc}") from exc
    out: list[Pin] = []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict):
            continue
        if str(pkg.get("name", "")).lower() != "blastbox":
            continue
        version = str(pkg.get("version", "")).strip()
        if version:
            out.append(Pin(str(path), 0, "lock", f"{pkg.get('name')}=={version}",
                           "==" + version))
    return out


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
        except OSError as exc:
            # Swallowing this under-reports pins and returns OK on a repo that
            # was never fully read -- the same vacuous pass as a malformed
            # pyproject.
            raise PinScanError(f"{current}: {exc}") from exc
        for entry in entries:
            # is_dir() follows symlinks: a link to / would walk the filesystem,
            # and a link back into the tree would loop. Scan the repo only.
            if entry.is_symlink():
                continue
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
        elif name.startswith("Dockerfile") or name.endswith((".Dockerfile", ".dockerfile")):
            pins.extend(_scan_dockerfile(path))
        elif name in _TOML_LOCK_NAMES:
            pins.extend(_scan_toml_lock(path))
        elif re.fullmatch(
            r"(requirements|constraints)[\w.\-]*\.(txt|lock)|[\w.\-]+\.lock", name
        ) or (path.parent.name == "requirements" and name.endswith(".txt")):
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
