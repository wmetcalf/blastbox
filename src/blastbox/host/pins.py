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

import os
import stat
import re
import shlex
from collections.abc import Callable, Sequence, Set as AbstractSet
from typing import Any
import tomllib
from dataclasses import dataclass
from pathlib import Path

_ARG_RE = re.compile(r'^\s*ARG\s+BLASTBOX_VERSION\s*=\s*["\']?([0-9][^"\'\s]*)["\']?')
# A real install: `pip install`, `pip3 install`, `uv pip install`, `python -m pip install`.
# `pip install`, `pip3 install`, `uv pip install`, and pip global options in
# between (`python -m pip --isolated install ...`).
_INSTALL_RE = re.compile(r"\b(?:pip[0-9.]*|uv\s+pip)\s+(?:-[^\s]+\s+)*install\b")
# `blastbox`, optional extras, then a specifier set. Stops at a PEP 508 marker (`;`),
# a quote, or whitespace.
_REQ_RE = re.compile(
    r"(?<![\w.\-])(?i:blastbox)(?P<extras>\[[a-zA-Z0-9,._\-]+\])?\s*"
    r'(?P<spec>(?:[=<>!~]=|[<>])\s*v?[0-9][^"\';\s]*'
    r'(?:\s*,\s*(?:[=<>!~]=|[<>])\s*v?[0-9][^"\';\s]*)*)'
)
# Leading whitespace is legal in a requirements-format file. A hashed lock pins
# with ==, but constraints.txt and requirements/*.txt legitimately carry any
# specifier -- matching only == silently skipped them.
_LOCK_RE = re.compile(
    r"^\s*(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*"
    r"((?:[=<>!~]=|[<>])\s*v?[0-9][^\s;]*(?:\s*,\s*(?:[=<>!~]=|[<>])\s*v?[0-9][^\s;]*)*)"
)
_ARG_USE_RE = re.compile(r"\$\{?BLASTBOX_VERSION\}?")


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
    r"(?<![\w.\-])(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*@\s*(?P<url>[^\s\"']+)"
)


@dataclass(frozen=True)
class Pin:
    """One install-path pin on blastbox."""

    path: str
    line: int
    kind: str  # pyproject | dockerfile-arg | dockerfile-pip | lock
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
                    floors.append(
                        _normalise_version(part[len(op) :].strip().lstrip("vV"))
                    )
                    break
        if not floors:
            return None
        # A set may carry more than one lower bound; the strongest is what the
        # pin actually guarantees, and it is not necessarily written first.
        return max(floors, key=_version_key)


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment. Prose lives there; pins do not.

    A comment starts only at the beginning of the line or after whitespace --
    pip's documented rule, and the shell's. Cutting at ANY ``#`` truncated a
    VCS requirement at its fragment, so
    `pip install git+https://.../blastbox.git#egg=blastbox[s3]` read as an
    install of nothing in particular.

    Quoted text is data, not a comment: `RUN echo "step # 1" && pip install
    blastbox==2` is one command whose pin lives AFTER the hash, and cutting
    there hid the install from `pins --set`, which then reported success while
    that Dockerfile stayed stale.
    """
    quote: str | None = None
    for index, char in enumerate(line):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


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
                and any(
                    n and n in _strip_comment(ln).replace(" ", "")
                    for n in (needle.replace(" ", "") for needle in needles)
                )
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
        _INSTALL_RE.search(line)
        and "blastbox" in line.lower()
        and _ARG_USE_RE.search(line)
        for _, line in logical
    )

    out: list[Pin] = []
    for lineno, line in logical:
        arg = _ARG_RE.match(line)
        if arg:
            if arg_is_used:
                out.append(
                    Pin(
                        str(path),
                        lineno,
                        "dockerfile-arg",
                        line.strip(),
                        "==" + arg.group(1),
                    )
                )
            continue
        if "blastbox" not in line.lower() or not _INSTALL_RE.search(line):
            continue
        # One logical RUN can install blastbox more than once
        # (`pip install a && pip install b`); report every pin.
        for token in _isolate_requirements(line):
            parsed = _split_requirement(token)
            if parsed:
                out.append(
                    Pin(str(path), lineno, "dockerfile-pip", line.strip(), parsed[1])
                )
    return out


def _split_commands(line: str) -> list[str]:
    """Split a shell line on `&&` / `|` that are OUTSIDE quotes.

    A regex split cannot do this: an option value may legitimately contain the
    separator -- `pip install --index-url "https://a|b" blastbox==1.0" -- and
    cutting there drops the requirement from the scan entirely, which is the
    silent under-report this module exists to prevent.

    A top-level `;` or `&` ends a command as surely as `&&` does. A PEP 508
    marker also uses a semicolon, but one that survives the shell is quoted,
    and quoted text never reaches the split.
    """
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    depth = 0  # $( … ) nesting
    backtick = False  # ` … `
    i = 0
    while i < len(line):
        ch = line[i]
        escaped = ch == "\\" and i + 1 < len(line)
        if quote:
            if escaped and quote == '"':
                buf.append(line[i : i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if escaped:
            buf.append(line[i : i + 2])
            i += 2
            continue
        # A pipeline inside a command substitution belongs to that substitution,
        # not to the install command: `--extra-index-url $(cmd | grep x)` is one
        # argument. Splitting there drops the requirement from the scan.
        # Process substitution opens a nested command too: `<(cmd | x)`.
        if line[i : i + 2] in ("$(", "${", "<(", ">("):
            depth += 1
            buf.append(line[i : i + 2])
            i += 2
            continue
        if ch == "}" and depth:
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")" and depth:
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if ch == "`":
            backtick = not backtick
            buf.append(ch)
            i += 1
            continue
        if depth or backtick:
            buf.append(ch)
            i += 1
            continue
        if line[i : i + 2] == "&&":
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch == "|":
            parts.append("".join(buf))
            buf = []
            i += 2 if line[i : i + 2] == "||" else 1
            continue
        # A top-level `;` or `&` ends a command too. These were excluded at
        # first out of a concern for PEP 508 markers -- but a marker's
        # semicolon only survives the shell if it is QUOTED, and quoted text is
        # already protected above. An UNQUOTED `;` really is a separator, so
        # treating it as one matches what the shell does rather than working
        # around a case that cannot occur.
        if (
            ch == "&"
            and (
                (buf and buf[-1] == ">")  # `2>&1`
                or line[i : i + 2] == "&>"  # bash `&>file`
            )
        ):
            buf.append(ch)
            i += 1
            continue
        if ch in ";&":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _isolate_requirements(line: str) -> list[str]:
    """Every blastbox requirement token on an install command line.

    Includes DIRECT REFERENCES (`blastbox @ git+https://…`): a Dockerfile can
    install one just as a pyproject can, and dropping it here would repeat the
    silent-omission bug already fixed for pyproject.
    """
    # Only what the install command is actually given. A continued RUN often
    # mentions the package outside the install -- `RUN echo "blastbox==0.1.19"
    # && pip install "blastbox==0.1.19"` -- and reading the whole line reported
    # the DIAGNOSTIC string as the repo's pin. `pins` then showed a version
    # nothing installs, and `--set` rewrote the echo while leaving the real
    # dependency stale, because both agree on "the first match".
    out: list[str] = []
    # One logical RUN can hold several commands, and only the arguments of the
    # INSTALLS are requirements. Each `&&`/`|` segment is considered on its own
    # so that `pip install X && echo X` reads the first and not the second,
    # while `pip install X && pip install Y` still reads both.
    for segment in _split_commands(line):
        m = _INSTALL_RE.search(segment)
        if not m:
            continue
        args = segment[m.end() :]
        for r in _REQ_RE.finditer(args):
            start = args.lower().rfind("blastbox", 0, r.end())
            out.append(args[start : r.end()])
        for r in _DIRECT_REF_RE.finditer(args):
            out.append(r.group(0))
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
            out.append(
                Pin(
                    str(path),
                    0,
                    "lock",
                    f"{pkg.get('name')}=={version}",
                    "==" + version,
                )
            )
    return out


def _scan_lock(path: Path) -> list[Pin]:
    try:
        lines = _read_requirements(path).splitlines()
    except OSError as exc:
        raise PinScanError(f"{path}: {exc}") from exc
    out: list[Pin] = []
    for i, raw in enumerate(lines, 1):
        m = _LOCK_RE.match(raw)
        if m:
            out.append(
                Pin(str(path), i, "lock", raw.strip(), re.sub(r"\s+", "", m.group(1)))
            )
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
            elif entry.is_file():
                # REGULAR files only, for the same reason symlinks are skipped:
                # a FIFO named `pipe.lock` looks like a candidate lock and
                # blocks forever when opened, and a character device reads
                # without end. `is_file()` is False for both.
                yield entry


_REQ_NAME_RE = re.compile(
    r"(requirements|constraints)[\w.\-]*\.(txt|lock)|[\w.\-]+\.lock"
)
# Files that plausibly RUN a pip install. Bounded by name on purpose: the
# alternative is reading every file in the repository, and a consumer tree
# holds VM images and corpora.
_INSTALL_SCRIPT_RE = re.compile(
    r"(?i)^(dockerfile.*|makefile|.*\.(sh|bash|mk|ya?ml|dockerfile))$"
)
# Enough for any install script; anything larger is data we should not open.
_READ_LIMIT = 1 << 20
# pip documents `--hash <hash>` and accepts `--hash=<hash>`; both are hashed.
_HASH_RE = re.compile(r"--hash[=\s]+\S+")
# Generated hash locks are legitimately large -- a full closure with two hashes
# per entry runs to megabytes -- so a RECOGNISED lock gets a generous bound and
# an error beyond it. Silently reading it as empty makes the file look like it
# holds no blastbox pin, and `pins --set` then updates every other pin and
# reports success while the lock stays stale.
_LOCK_READ_LIMIT = 64 << 20


# Anything pip would plausibly be handed with `-r`. Broader than the set we
# JUDGE: an aggregator named `all.txt` holds nothing but `-r` lines, so it is
# never a lock itself, but it is what makes its two siblings one install set.
_INSTALL_INPUT_RE = re.compile(r"(?i)^[\w.\-]+\.(txt|in|lock)$")


def _is_install_input(path: Path) -> bool:
    """Whether ``path`` could name other requirement files."""
    return bool(_INSTALL_INPUT_RE.fullmatch(path.name)) or _is_requirements_file(path)


def _is_requirements_file(path: Path) -> bool:
    """Whether ``path`` is a lock this check should JUDGE."""
    return bool(
        _REQ_NAME_RE.fullmatch(path.name)
        or (path.parent.name == "requirements" and path.name.endswith(".txt"))
    )


def _read_requirements(path: Path) -> str:
    """Read a recognised requirements file, refusing to treat it as absent.

    `_read_small` returns "" for anything oversized, which is the right answer
    for a file we merely guessed at and the WRONG one for a lock: it would look
    like it carries no blastbox pin, and the bump would be accepted with that
    lock left stale.
    """
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise PinScanError(f"{path}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise PinScanError(f"{path}: not a regular file; refusing to read it")
    if st.st_size > _LOCK_READ_LIMIT:
        raise PinScanError(
            f"{path}: {st.st_size} bytes is too large to read as a requirements "
            "file. Treating it as empty would report every dependency present."
        )
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise PinScanError(f"{path}: {exc}") from exc


def _read_small(path: Path) -> str:
    """Read a text file, or "" if it is unreadable or too large to be one.

    `_walk` yields every file in the repo, and reading them all as UTF-8 to look
    for `-r` lines pulls archives, database snapshots and VM images into memory.
    """
    try:
        st = os.lstat(path)
        # REGULAR files only, and checked here because this is the one place
        # that opens anything. `_walk` yields whatever is in the tree, so a FIFO
        # named `pipe.lock` looks like a candidate lock -- and opening it blocks
        # forever, from a file the scanner was merely told to look at. A
        # character device is the same hazard with unbounded reads instead.
        if not stat.S_ISREG(st.st_mode) or st.st_size > _READ_LIMIT:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def scan(root: Path) -> list[Pin]:
    """Every install-path blastbox pin under ``root``."""
    pins: list[Pin] = []
    for path in _walk(root):
        name = path.name
        if name == "pyproject.toml":
            pins.extend(_scan_pyproject(path))
        elif name.startswith("Dockerfile") or name.endswith(
            (".Dockerfile", ".dockerfile")
        ):
            pins.extend(_scan_dockerfile(path))
        elif name in _TOML_LOCK_NAMES:
            pins.extend(_scan_toml_lock(path))
        elif _is_requirements_file(path):
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


# ---------------------------------------------------------------------------
# Rewriting: one version input for every install path.
# ---------------------------------------------------------------------------
#
# Bumping a consumer by hand means editing every place `scan` reports -- and the
# whole reason this module exists is that people miss some. Three RedTusk bumps
# in one day each touched seven pins across four file formats, and the only
# reason none was missed is that `pins` was run afterwards. The scanner already
# knows every location; rewriting from the same list is what makes "one version
# input" true rather than aspirational.

_FLOOR_OPS = ("==", ">=", "~=")
_BOUND_OPS = ("<=", "<", "!=")

# Anchors the rewrite to the blastbox requirement itself. `line.find(specifier)`
# does not: given `["other==0.1.27", "blastbox==0.1.27"]` it finds the FIRST
# occurrence and rewrites somebody else's dependency, silently.
# The lookbehind is the same boundary `_REQ_RE` uses, and it is load-bearing:
# without it `blastbox` matches the SUFFIX of `not-blastbox`, so a continued
# install listing an unrelated distribution first had that one rewritten -- and
# the search stopped there, leaving the real pin stale.
_REQ_NAME = r"(?<![\w.\-])(?i:blastbox)(?:\[[A-Za-z0-9,._\-]+\])?"


_OP_RE = re.compile(r"^(==|>=|<=|~=|!=|<|>)\s*(.*)$")


def _spec_pattern(spec: str) -> str:
    """A whitespace-tolerant pattern for one specifier as written in a file.

    `scan` stores specifiers with whitespace stripped, so the pattern has to
    tolerate what the FILE may contain: spaces around the commas and between an
    operator and its version. Escaping the part whole matched `>=0.1.27` but
    not the equally valid `>= 0.1.27`, and the caller then refused a line it
    could have rewritten.
    """
    parts = []
    for part in spec.split(","):
        stripped = part.strip()
        m = _OP_RE.match(stripped)
        parts.append(
            re.escape(m.group(1)) + r"\s*" + re.escape(m.group(2))
            if m
            else re.escape(stripped)
        )
    # A trailing boundary, so `==0.1` does not match inside `==0.1.2`. Without
    # it, two pins on one logical line sharing a specifier made the second
    # search re-match the FIRST, already-rewritten occurrence and extend it to
    # `0.1.2.2` -- a legitimate bump failing on a version that merely extends
    # the old one.
    # The boundary covers every character a PEP 440 version can CONTINUE with:
    # `+` (local), `!` (epoch) and `-` as well as word characters and dots.
    # `(?![\w.])` alone let `==1.0` match inside `==1.0+cpu`, so a second pin on
    # the same line re-matched the first rewrite.
    return r"\s*,\s*".join(parts) + r"(?![\w.+!\-])"


def _rewrite_specifier(spec: str, version: str) -> str:
    """Point every FLOOR in ``spec`` at ``version``, leaving bounds alone.

    An upper bound is a deliberate compatibility ceiling: rewriting `<0.2` to
    `<0.1.31` would silently narrow what the consumer accepts, and rewriting it
    UP would raise a ceiling nobody chose. Only the floors move.
    """
    out = []
    for part in spec.split(","):
        stripped = part.strip()
        for op in _FLOOR_OPS:
            if stripped.startswith(op):
                out.append(f"{op}{version}")
                break
        else:
            out.append(stripped)
    return ",".join(out)


def _violated_bound(spec: str, version: str) -> str | None:
    """A preserved bound the target version does not satisfy, if any.

    Keeping `<0.2` while setting 0.2.0 yields `>=0.2.0,<0.2`: a specifier
    nothing can satisfy, written by a command that reported success.
    """
    key = _version_key(_normalise_version(version))
    for part in spec.split(","):
        stripped = part.strip()
        for op in _BOUND_OPS:
            if not stripped.startswith(op):
                continue
            bound = _normalise_version(stripped[len(op) :].strip().lstrip("vV"))
            if not bound:
                break
            bk = _version_key(bound)
            bad = (
                (key >= bk) if op == "<" else (key > bk) if op == "<=" else (key == bk)
            )
            if bad:
                return stripped
            break
    return None


def _logical_span(lines: list[str], start: int) -> range:
    """Physical line indices forming the logical line beginning at ``start``.

    A shell requirement is routinely written across continuations:

        RUN pip install --no-cache-dir \\
            "blastbox[host]==0.1.27" \\
            "fastapi"

    The scanner attributes the pin to the FIRST physical line, because that is
    where the logical line begins -- but the requirement text is on a later one,
    so rewriting only that first line finds nothing to replace.
    """
    # Mirrors `_logical_lines` exactly, comment stripping included: a `#` ends
    # that physical line even inside a continued RUN, so a span computed from
    # the RAW text would join lines the scanner did not -- and the two must
    # agree, or the rewriter searches a different region than the pin describes.
    end = start
    while end < len(lines) and _strip_comment(lines[end]).rstrip().endswith("\\"):
        end += 1
    return range(start, min(end + 1, len(lines)))


def _rewrite_line(line: str, pin: Pin, version: str) -> str:
    """Replace the version in one pin's line, touching nothing else on it."""
    if pin.kind == "dockerfile-arg":
        # `ARG BLASTBOX_VERSION=0.1.30`, possibly quoted. The quotes are part of
        # the file's style and are preserved rather than normalised away.
        new, n = re.subn(
            r"(=\s*[\"\']?)v?\d[\w.\-+!]*",
            lambda m: m.group(1) + version,
            line,
            count=1,
        )
        if not n:
            raise PinScanError(
                f"{pin.path}:{pin.line}: no version found after `=` to rewrite in "
                f"{line.strip()!r}"
            )
        return new

    new_spec = _rewrite_specifier(pin.specifier, version)
    pattern = re.compile(f"({_REQ_NAME}\\s*){_spec_pattern(pin.specifier)}")
    new, n = pattern.subn(lambda m: m.group(1) + new_spec, line, count=1)
    if not n:
        raise PinScanError(
            f"{pin.path}:{pin.line}: cannot locate the blastbox requirement "
            f"{pin.raw!r} on this line to rewrite it. A pin written across a "
            "line continuation is attributed to the first physical line, which "
            "is not where the text lives. Refusing to guess -- a partial "
            "rewrite leaves the repo pinned to two versions."
        )
    return new


def _hash_lines(indent: str, digests: list[str]) -> list[str]:
    """Render `--hash=sha256:...` continuation lines for a locked requirement."""
    return [f"{indent}--hash=sha256:{d}" for d in digests]


def _eol_of(line: str) -> str:
    """The line ending ``line`` uses, so a regenerated block keeps it.

    The hash block is rebuilt from scratch rather than edited, so it does not
    inherit the file's endings the way a rewritten line does: emitting "\n"
    into a CRLF lock would leave that file with mixed endings.
    """
    if line.endswith("\r\n"):
        return "\r\n"
    return "\n" if line.endswith("\n") else ""


def _dist_name(requirement: str) -> str:
    """The normalised distribution name in a requirement line, or "".

    Normalised per PEP 503, because a lock may spell what a requirement calls
    `ruamel.yaml` as `ruamel-yaml` and the two must compare equal.
    """
    text = _strip_comment(requirement).strip()
    text = text.split(";", 1)[0]  # environment marker
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", text)
    if not match:
        return ""
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


@dataclass(frozen=True)
class _Pin:
    """One pinned requirement as a lock states it."""

    version: str
    marker: str
    hashed: bool
    # Extras named on THIS entry (`blastbox[host]==...`). Kept per entry because
    # a portable lock can pin blastbox twice under exclusive markers, and
    # unioning both would check a closure pip never installs.
    extras: frozenset[str] = frozenset()


def missing_from_locks(
    root: Path,
    requires: Sequence[str],
    *,
    environment: dict[str, str] | None = None,
    requirements_of: Callable[[str, str], list[str] | None] | None = None,
) -> dict[str, list[str]]:
    """Requirements of a release that a hash-pinned blastbox lock cannot satisfy.

    `pip install --require-hashes` refuses the WHOLE file when a dependency it
    must resolve is not pinned there:

        ERROR: In --require-hashes mode, all requirements must have their
        versions pinned with ==. These do not: pydantic>=2.6.0 (from blastbox)

    So a release that gains a dependency turns every consumer's hash-pinned
    lock into a lock that cannot install -- and `pins --set` rewrites only the
    blastbox line, which makes the bump look successful right up until the
    image build fails. Measured: blastbox 0.1.39 added `packaging`, which no
    consumer lock carried.

    Judged per INSTALL SET, not per file. `-r` includes are followed and only
    the roots of the include graph are examined: `pip install -r all.txt` where
    `all.txt` names blastbox.lock and deps.lock installs them together, so
    judging blastbox.lock alone reports everything deps.lock carries.

    Every requirement is checked against the entries whose MARKERS apply to the
    lock's environment -- a portable lock legitimately pins one distribution
    twice under mutually exclusive markers -- and a pin only counts when it is
    HASHED, since an unhashed entry in an included file fails the same install
    it appears to satisfy.
    """
    out: dict[str, list[str]] = {}
    parsed = [_requirement(r) for r in requires]
    sets = _install_sets(root)
    for iset in sets:
        members = iset.members
        pins, env = _merged_pins(members, root)
        if "blastbox" not in pins:
            continue  # somebody else's requirements; not ours to judge
        if not any(pin.hashed for entries in pins.values() for pin in entries):
            continue  # not hash-pinned; pip resolves the rest itself
        # A universal lock is judged on EVERY branch it claims to cover.
        scopes = _scopes_for(env, environment)
        found: dict[str, list[str]] = {}
        for label, scope in scopes:
            for gap in _judge_scope(
                iset, root, len(sets), pins, scope, parsed, requirements_of
            ):
                found.setdefault(gap, []).append(label)
        gaps = [
            gap
            if len(scopes) == 1 or len(where) == len(scopes)
            else f"{gap} [on {', '.join(where)}]"
            for gap, where in found.items()
        ]
        if gaps:
            out[" + ".join(str(m) for m in members)] = gaps
    return out


def _transitive_gaps(
    parsed: Sequence[Any],
    extras: set[str],
    pins: dict[str, list[_Pin]],
    scope: dict[str, str],
    requirements_of: Callable[[str, str], list[str] | None],
) -> list[str]:
    """Everything the pinned packages themselves need and the lock lacks.

    pip resolves the whole graph, not just the top level, and refuses the file
    when any part of it is unpinned: removing `pydantic-core` from a lock that
    pins `pydantic` fails the install although blastbox never names it. Four of
    the seven packages in the differential fixture are of that kind, and the
    checker was silent about all four until this walk existed.

    Breadth-first from the requirements that apply, through the versions this
    lock actually pins, carrying each requirement's own extras.

    Silent when metadata cannot be fetched: one unreachable index is an unknown
    edge, not evidence of a gap, and refusing a bump over it would be worse
    than the drift it guards against.
    """
    gaps: list[str] = []
    seen: set[tuple[str, str, frozenset[str]]] = set()
    queue: list[tuple[Any, frozenset[str]]] = [
        (req, frozenset(extras))
        for req in parsed
        if req is not None and _applies(req, extras, scope)
    ]
    while queue:
        req, _active = queue.pop()
        name = _dist_name(req.name)
        usable = [
            pin
            for pin in pins.get(name, [])
            if pin.hashed
            and _marker_holds(pin.marker, scope)
            and (not req.specifier or _satisfies(req, pin.version))
        ]
        if not usable:
            continue  # the direct pass already reported it, or it does not apply
        wanted = frozenset(e.lower() for e in (req.extras or set()))
        # The extras are PART of the identity. `parent[feature]` requiring both
        # `child[a]` and `child[b]` visits child twice, and a key of
        # (name, version) makes the second visit a no-op -- so a lock carrying
        # a's dependencies but not b's is accepted although pip enables both.
        key = (name, usable[0].version, wanted)
        if key in seen:
            continue
        seen.add(key)
        nested = requirements_of(name, usable[0].version)
        if nested is None:
            continue
        for sub in (_requirement(r) for r in nested):
            if sub is None or not _applies(sub, wanted, scope):
                continue
            sub_name = _dist_name(sub.name)
            fits = [
                pin
                for pin in pins.get(sub_name, [])
                if pin.hashed
                and _marker_holds(pin.marker, scope)
                and (not sub.specifier or _satisfies(sub, pin.version))
            ]
            if not fits:
                gaps.append(f"{sub_name} (needed by {name})")
                continue
            queue.append((sub, wanted))
    return sorted(set(gaps))


def _pip_enforces(req, enforced: set[str], scope: dict[str, str]) -> bool:
    """Whether pip itself will demand ``req`` for this lock.

    A base requirement always. An extra-gated one only when the lock LINE names
    that extra -- `blastbox[host]==...` binds pip, a plain `blastbox==...` does
    not, whatever the repository declares elsewhere.
    """
    marker = str(getattr(req, "marker", "") or "")
    if "extra ==" not in marker:
        return True
    return _applies(req, enforced, scope) if enforced else False


def _gap(
    req,
    pins: dict[str, list[_Pin]],
    scope: dict[str, str],
    requirements_of: Callable[[str, str], list[str] | None] | None = None,
) -> str:
    """How ``req`` is unsatisfied by ``pins``, or "" when it is satisfied."""
    name = _dist_name(req.name)
    applicable = [p for p in pins.get(name, []) if _marker_holds(p.marker, scope)]
    if not applicable:
        return name
    usable = [p for p in applicable if p.hashed]
    if not usable:
        return f"{name} (pinned but not hashed)"
    matching = [p for p in usable if not req.specifier or _satisfies(req, p.version)]
    if not matching:
        shown = ", ".join(sorted({p.version for p in usable}))
        return f"{name} (pinned {shown}, needs {req.specifier})"
    return ""


def _install_roots(root: Path) -> list[Path]:
    """Requirement files that something actually installs -- one per set.

    A file included by another is installed as PART of that set, so judging it
    alone reports pins present in its sibling. But inclusion does not prove it
    is never an entrypoint: a Dockerfile may install `prod.lock` directly while
    `dev.lock` includes it, and dropping it from the roots would check only the
    dev closure and accept a bump that leaves production failing. So a file
    named by an install command counts as a root even when it is also included.
    """
    # A candidate is a lock by NAME, or a file that aggregates other
    # requirement files. An aggregator named `all.txt` holds nothing but `-r`
    # lines, so it is never a lock itself -- and excluding it while marking its
    # children included left NO roots, so nothing was judged and every closure
    # passed. Ordinary `.txt` files that include nothing stay out: they are
    # fixtures and corpora, not install sets.
    inputs: list[Path] = []
    # Direct references are resolved FIRST: pip imposes no suffix convention, so
    # `pip install -r prod.pins` names a real install set that the name filter
    # would otherwise keep out of the candidate list entirely.
    direct: set[Path] = set()
    for path in _walk(root):
        if _INSTALL_SCRIPT_RE.fullmatch(path.name) and not _is_install_input(path):
            direct |= set(_referenced(path, root))
    included: set[Path] = set()
    aggregates: set[Path] = set()
    for path in _walk(root):
        if not _is_install_input(path) and path.resolve() not in direct:
            continue
        inputs.append(path)
        names = _includes(path, root)  # read once; used for both decisions
        included |= set(names)
        if names:
            aggregates.add(path.resolve())

    candidates = [
        p
        for p in inputs
        if p.resolve() in aggregates
        or p.resolve() in direct
        or _is_requirements_file(p)
    ]
    return [
        p for p in candidates if p.resolve() not in included or p.resolve() in direct
    ]


def _constraint_conflicts(
    iset: _InstallSet,
    root: Path,
    pins: dict[str, list[_Pin]],
    scope: dict[str, str],
) -> list[str]:
    """Pins this set's own `-c` files exclude -- an install pip will refuse."""
    from packaging.version import InvalidVersion  # noqa: PLC0415

    out: list[str] = []
    specs = _constraint_specs(iset, root)
    if not specs:
        return out
    for name, entries in sorted(pins.items()):
        applicable = [
            (specifier, source)
            for specifier, marker, source in specs.get(name, [])
            if _marker_holds(marker, scope)
        ]
        if not applicable:
            continue
        for pin in entries:
            if not _marker_holds(pin.marker, scope):
                continue
            version = pin.version.lstrip("=").strip()
            if not version:
                continue
            try:
                # ALL of them: pip applies every constraint it was given.
                excluded = [
                    (specifier, source)
                    for specifier, source in applicable
                    if not specifier.contains(version, prereleases=True)
                ]
            except InvalidVersion:
                continue  # not a version we can compare; not evidence of a conflict
            if excluded:
                specifier, source = excluded[0]
                out.append(
                    f"{name}=={version} is excluded by the constraint "
                    f"{name}{specifier} in {source}"
                )
                break
    return out


def _constraint_specs(
    iset: _InstallSet, root: Path
) -> dict[str, list[tuple[Any, str, Path]]]:
    """`{name: [(specifier, marker, source), ...]}` constraining this set.

    A constraint installs nothing; it restricts what a version may be. A root
    pinning `packaging==26.3` under a constraint of `packaging==22` is a lock
    pip REFUSES to resolve -- and the closure check called it complete, because
    every name it wanted was present and hashed.

    EVERY constraint is kept, not the first one seen: pip documents `-c` as
    repeatable and applies all of them, so `packaging>=20` and `packaging<23`
    together reject a pinned 23 that either alone admits. Markers are kept with
    them, because `packaging<23; sys_platform == "win32"` does not constrain a
    Linux install and reporting it there refuses a correct lock.

    Both roles are walked: a requirements file contributes its `-c` targets, a
    constraint file contributes its own lines and its own references. Files
    named by `-c` on the COMMAND LINE are constraints of this resolution too,
    though nothing installs them.
    """
    out: dict[str, list[tuple[Any, str, Path]]] = {}
    seen: set[tuple[Path, bool]] = set()

    def walk(path: Path, *, constraining: bool) -> None:
        key = (path.resolve(), constraining)
        if key in seen:
            return
        seen.add(key)
        try:
            text = _read_requirements(path)
        except PinScanError:
            return  # unreadable here is not a verdict; the caller already reports it
        for line in _joined_lines(text):
            references = _requirement_args(line)
            constraints = _constraint_args(line)
            for name in constraints:
                target = _safe_include(path.parent / name, root)
                if target is not None:
                    walk(target, constraining=True)
            for name in references:
                target = _safe_include(path.parent / name, root)
                if target is not None:
                    walk(target, constraining=constraining)
            if not constraining or references or constraints:
                continue
            # A constraint file may be hashed like any other: the hash
            # arguments are not part of the requirement grammar, so they come
            # off before parsing or every hashed constraint reads as absent.
            req = _requirement(_HASH_RE.sub("", _strip_comment(line)).strip())
            if req is not None and str(req.specifier):
                marker = str(req.marker) if req.marker is not None else ""
                out.setdefault(_dist_name(req.name), []).append(
                    (req.specifier, marker, path)
                )

    for member in iset.members:
        walk(member, constraining=False)
    for limit in iset.constraints:
        walk(limit, constraining=True)
    return out


def _scopes_for(
    env: dict[str, str], environment: dict[str, str] | None
) -> list[tuple[str, dict[str, str]]]:
    """The marker environments one lock must be judged under.

    Normally one: what the lock's header says, with the caller's overrides on
    top. A `--universal` lock is a different promise -- one file for all
    operating systems -- so it is judged under each branch it covers, and a
    requirement that is missing on only some of them says which.

    An explicit caller value still wins: naming `sys_platform` is a deliberate
    question about one target, and answering a different one would be a lie.
    """
    base = {
        k: v
        for k, v in {**env, **(environment or {})}.items()
        if k not in ("__extras__", "__universal__")
    }
    if env.get("__universal__") != "1":
        return [("", base)]
    return [(label, {**values, **base}) for label, values in _UNIVERSAL_BRANCHES]


def _judge_scope(
    iset: _InstallSet,
    root: Path,
    n_sets: int,
    pins: dict[str, list[_Pin]],
    scope: dict[str, str],
    parsed: Sequence[Any],
    requirements_of: Callable[[str, str], list[str] | None] | None,
) -> list[str]:
    """What this install set is missing IN ONE marker environment."""
    members = iset.members
    gaps: list[str] = []
    # Two exact pins for one distribution, both applicable here. pip has to
    # satisfy both and cannot: the set is unresolvable however well it covers
    # the closure, and `_gap` was satisfied as soon as EITHER version matched.
    for name, entries in sorted(pins.items()):
        versions = {
            pin.version.lstrip("=").strip()
            for pin in entries
            if _marker_holds(pin.marker, scope)
        }
        if len(versions) > 1:
            spelled = ", ".join(sorted(versions))
            gaps.append(
                f"{name} is pinned to more than one version in this install "
                f"set ({spelled}); pip cannot satisfy both"
            )
    # An APPLICABLE blastbox entry. A portable lock whose only blastbox pin
    # is `; sys_platform == "win32"` does not install blastbox on Linux, so
    # demanding its dependency closure there refuses a correct lock.
    if not any(_marker_holds(pin.marker, scope) for pin in pins["blastbox"]):
        return []
    # Only from blastbox entries whose own markers apply: a portable lock
    # may pin `blastbox[host]` for one interpreter and `blastbox[s3]` for
    # another, and unioning both checks a closure pip never installs.
    # TWO kinds of extra, and they fail differently. Measured against real
    # pip in python:3.12-slim, on RedTusk's own lock with fastapi removed:
    #
    #     blastbox[host]==...  ->  pip install --require-hashes  FAILS
    #     blastbox==...        ->  pip install --require-hashes  SUCCEEDS
    #
    # Only the extras the LOCK LINE spells are enforced by pip. The ones the
    # repository merely declares (`blastbox[host,s3]` in pyproject) are not:
    # uv writes a plain `blastbox==` line, so the install succeeds and the
    # IMAGE is short a package it imports -- RedTusk's Dockerfiles then run
    # `pip install -e . --no-deps`, which does not re-check. That is a real
    # defect and worth reporting, but it is not the same defect, and saying
    # "pip will reject the file" about it would be false.
    enforced = {
        e
        for pin in pins["blastbox"]
        if _marker_holds(pin.marker, scope)
        for e in pin.extras
    }
    declared = set()
    for member in members:
        # The number of install SETS, not of files: two locks installed by one
        # command are one resolution, and counting them as two disabled the
        # single-set fallback that infers what the repository declares.
        declared |= _declared_extras_for(root, member, n_sets)
    if not enforced and not declared:
        declared = _extras_in_play(parsed, pins, scope)
    extras = enforced | declared
    extras = _with_nested_extras(extras, parsed, scope)
    for req in parsed:
        if req is None or not _applies(req, extras, scope):
            continue
        gap = _gap(req, pins, scope, requirements_of)
        if not gap:
            continue
        # Which failure is it? A requirement reachable only through an extra
        # the lock line does not spell is a RUNTIME hole, not an install
        # one, and the message says which so an operator is not sent looking
        # for a pip error that will not happen.
        if not _pip_enforces(req, enforced, scope):
            gap += " [not an install failure: the image would import it]"
        gaps.append(gap)
    # The TRANSITIVE closure, not just blastbox's own requirements. pip
    # resolves what the pinned packages themselves need, and refuses the
    # file when any of it is unpinned: removing `pydantic-core` from a lock
    # that pins `pydantic` fails the install even though blastbox never
    # names it. Measured -- four such packages in a seven-package fixture.
    #
    # Only with a resolver: without one there is no metadata to walk, and
    # reporting everything as unverifiable would be noise.
    if requirements_of is not None:
        deep = _transitive_gaps(parsed, extras, pins, scope, requirements_of)
        gaps.extend(g for g in deep if g not in gaps)
    # A pin the set's own constraints forbid. Everything above asks whether
    # a version is PRESENT; pip also refuses a resolution its constraints
    # exclude, and that lock fails the install the check just approved.
    gaps.extend(
        g for g in _constraint_conflicts(iset, root, pins, scope) if g not in gaps
    )
    return gaps


def _merged_pins(
    members: Sequence[Path], root: Path
) -> tuple[dict[str, list[_Pin]], dict[str, str]]:
    """One requirement set's pins and target environment, across its files."""
    pins: dict[str, list[_Pin]] = {}
    env: dict[str, str] = {}
    for member in members:
        sub, _unused, sub_env = _effective_pins(member, root)
        for name, entries in sub.items():
            pins.setdefault(name, []).extend(entries)
        env = {**env, **sub_env}
    return pins, env


def _install_segments(line: str) -> list[str]:
    """The parts of a shell line that are pip install commands.

    A script line is not one command. `echo -r prod.lock && pip install -r
    dev.lock` names two files to a naive reader, and promoting `prod.lock` to
    an install root judges it ALONE -- blocking a bump for dependencies the
    `dev.lock` that really includes it supplies. Two pip installs on one line
    are likewise two resolutions, not one.
    """
    segments = re.split(r"&&|\|\||[;|]", line)
    return [seg for seg in segments if _INSTALL_RE.search(seg)]


@dataclass(frozen=True)
class _InstallSet:
    """One pip resolution: the files it installs, and what constrains them."""

    members: tuple[Path, ...]
    constraints: tuple[Path, ...] = ()


def _install_sets(root: Path) -> list[_InstallSet]:
    """Install roots grouped by the COMMAND that installs them.

    `pip install -r blastbox.lock -r deps.lock` is a single resolution: pip
    documents `-r` as repeatable and merges the files before resolving.
    Treating each as its own root reported `blastbox.lock` incomplete for
    dependencies `deps.lock` supplies in the very same command.

    Per SEGMENT, not per line: `pip install -r a.lock && pip install -r b.lock`
    is two resolutions that happen to share a `RUN`, and merging them lets the
    second satisfy dependencies the first install would fail without.

    A command's own `-c` files travel with it. They are not installed, so they
    are not members -- but pip applies them to this resolution, and a pin they
    exclude is a lock pip refuses.
    """
    roots = _install_roots(root)
    known = {p.resolve(): p for p in roots}
    sets: list[_InstallSet] = []
    seen: set[tuple[frozenset[Path], frozenset[Path]]] = set()
    grouped: set[Path] = set()
    for path in _walk(root):
        if not _INSTALL_SCRIPT_RE.fullmatch(path.name) or _is_install_input(path):
            continue
        for line in _joined_lines(_read_small(path)):
            for segment in _install_segments(line):
                named = [
                    known[r]
                    for r in dict.fromkeys(_referenced_in(segment, path.parent, root))
                    if r in known
                ]
                if not named:
                    continue
                limits = tuple(
                    dict.fromkeys(
                        c
                        for name in _constraint_args(segment)
                        for base in (path.parent, root)
                        if (c := _safe_include(base / name, root)) is not None
                    )
                )
                key = (frozenset(p.resolve() for p in named), frozenset(limits))
                if key in seen:
                    continue
                seen.add(key)
                sets.append(_InstallSet(tuple(named), limits))
                grouped |= key[0]
    sets.extend(_InstallSet((p,)) for p in roots if p.resolve() not in grouped)
    return sets


def _referenced(path: Path, root: Path) -> list[Path]:
    """Requirement files an install script hands to pip with `-r`.

    Resolved against the repository root as well as the script's own directory.
    `docker build -f deploy/Dockerfile .` copies `prod.lock` from the CONTEXT,
    so `pip install -r prod.lock` inside it names `<root>/prod.lock`, not
    `deploy/prod.lock` -- and resolving only the latter drops the reference,
    which then removes that lock from the roots and accepts its incomplete
    closure.
    """
    out: list[Path] = []
    # A quoted path is the same path: the shell strips the quotes before pip
    # ever sees them, and refusing to match one drops a real install set.
    # Comments stripped: `# old: pip install -r prod.lock` is a note, and
    # promoting it to a root judges that lock alone -- refusing a bump for
    # dependencies its real parent install set supplies.
    # Only from a pip install command: see `_install_segments`.
    for line in _joined_lines(_read_small(path)):
        for segment in _install_segments(line):
            for name in _requirement_args(segment):
                for base in (path.parent, root):
                    target = _safe_include(base / name, root)
                    if target is not None:
                        out.append(target)
    return out


def _safe_include(path: Path, root: Path) -> Path | None:
    """``path`` if it is a plain file inside ``root``, else None.

    `_walk` deliberately refuses symlinks and stays inside the repository; an
    include naming `/dev/zero`, a FIFO, or `../../etc` walks straight past that
    policy. Reading a FIFO blocks forever and reading /dev/zero exhausts memory,
    both from a file the scanner was merely told to look at.
    """
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    if path.is_symlink() or not resolved.is_file():
        return None
    return resolved


def _includes(path: Path, root: Path) -> list[Path]:
    """Paths this requirement file pulls in with `-r` / `--requirement`."""
    out: list[Path] = []
    # The bounded LOCK reader for files we recognise: `_read_small` returns ""
    # past 1 MiB, so a large `dev.lock` looked like it included nothing and its
    # `prod.lock` stayed an independent root, reported incomplete though it is
    # only ever installed through the complete dev set.
    # Strict only for files we RECOGNISE as locks. `_is_install_input` accepts
    # any `.txt`/`.in`, so using it here sent an unrelated 65 MiB corpus through
    # the reader that raises -- blocking `pins --set` on a repository whose data
    # files are none of its business.
    text = (
        _read_requirements(path) if _is_requirements_file(path) else _read_small(path)
    )
    for raw in _joined_lines(text):
        for name in _requirement_args(raw):
            target = _safe_include(path.parent / name, root)
            if target is not None:
                out.append(target)
    return out


def _joined_lines(text: str) -> list[str]:
    """Logical requirement lines, with backslash continuations merged.

    A pin and its hashes are one requirement written across several lines; read
    separately, the hashes look like entries of their own and the pin looks
    unhashed.
    """
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((buf + line).strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


# uv's bare platform names carry its DEFAULT architecture, measured with
# `uv pip compile --python-platform <name>` against marker-guarded requirements.
_WIN = {
    "sys_platform": "win32",
    "os_name": "nt",
    "platform_system": "Windows",
    "platform_machine": "x86_64",
}
_MAC = {
    "sys_platform": "darwin",
    "os_name": "posix",
    "platform_system": "Darwin",
    "platform_machine": "arm64",
}
_NIX = {
    "sys_platform": "linux",
    "os_name": "posix",
    "platform_system": "Linux",
    "platform_machine": "x86_64",
}
# The branches a `--universal` lock promises to cover.
_UNIVERSAL_BRANCHES = (("linux", _NIX), ("windows", _WIN), ("macos", _MAC))


def _generated_command(text: str) -> str:
    """The compile command a lock records in its LEADING comment block.

    uv and pip-tools write the command they were run with at the top of the
    file. Searching the whole text for `--python-version` instead let any later
    note override it -- `# migration target: --python-version 3.13` above a
    lock generated for 3.12 made the checker evaluate the wrong interpreter and
    skip a dependency guarded by `python_version < "3.13"`. The header is the
    only part of a lock that describes the lock; everything after it describes
    a package.
    """
    out: list[str] = []
    capturing = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if capturing:
                break
            continue
        if not line.startswith("#"):
            break  # the header ends where the requirements begin
        body = line.lstrip("#").strip()
        if not capturing and re.search(
            r"\b(uv (pip compile|lock)|pip-compile)\b", body
        ):
            capturing = True
        if capturing:
            continued = body.endswith("\\")
            out.append(body.rstrip("\\").strip())
            if not continued:
                break
    return " ".join(out)


def _lock_environment(text: str) -> dict[str, str]:
    """The environment a lock says it was compiled for, if it says.

    uv records its own command line in the header, so a lock produced with
    `--python-version 3.12` states its target. Evaluating that lock's markers
    against whatever interpreter happens to run `pins` is how a dependency
    guarded by `python_version < "3.13"` gets skipped for a 3.12 lock.
    """
    out: dict[str, str] = {}
    # Only the generated header: see `_generated_command`.
    text = _generated_command(text)
    if re.search(r"--universal\b", text):
        # `uv pip compile --universal` generates ONE file compatible with all
        # operating systems, architectures and Python implementations. Judging
        # it under the machine that happens to run `pins` accepts a lock whose
        # Windows install fails: a newly required `winonly; sys_platform ==
        # "win32"` is simply skipped on Linux.
        out["__universal__"] = "1"
    match = re.search(r"--python-version[=\s]+(\d+(?:\.\d+)+)", text)
    if match:
        version = match.group(1)
        full = version if version.count(".") >= 2 else f"{version}.0"
        out["python_version"] = ".".join(version.split(".")[:2])
        out["python_full_version"] = full
        # uv resolves FOR this interpreter, so a marker that asks the
        # implementation's version is asking about the target too. Leaving it
        # on the host skipped a dependency guarded by
        # `implementation_version < "3.13"` when a 3.14 host judged a 3.12 lock.
        out["implementation_version"] = full
    # `uv pip compile --python-platform windows` resolves for a machine that is
    # not this one, so evaluating that lock's markers against the local
    # sys_platform skips the requirements it exists to carry. uv takes bare
    # names and target triples; both are matched here.
    # `--extra host` (repeatable) is uv recording which optional sets it
    # resolved. That is authoritative where inference is a guess, and an older
    # lock missing half a newly grown extra cannot be inferred at all.
    # NOT `--extra` from the header. That selects the CONSUMER's optional
    # dependency group, not blastbox's: RedTusk's lock says `--extra host`,
    # which is redtusk's own `host` group whose contents are
    # `blastbox[host,s3]`. The names coincide and the meaning does not -- taking
    # it as blastbox's extras claims `host` for the right reason by accident and
    # misses `s3` entirely. What the repo asks blastbox for is written in the
    # requirement itself, which `_declared_blastbox_extras` reads.
    platform = re.search(r"--python-platform[=\s]+(\S+)", text)
    if platform:
        token = platform.group(1).lower()
        # The bare names carry uv's DEFAULT architecture, which is not the
        # host's. Measured with `uv pip compile --python-platform <name>`
        # against marker-guarded requirements, because the help text lists the
        # aliases without saying what they resolve to:
        #     macos    -> platform_machine == "arm64"
        #     linux    -> platform_machine == "x86_64"
        #     windows  -> platform_machine == "x86_64"
        # Leaving it to the running interpreter skipped an arm64-guarded
        # dependency for a macos lock on an x86 Linux host. An explicit target
        # triple overrides these below.
        for needle, values in (
            ("windows", _WIN),
            ("win32", _WIN),
            ("msvc", _WIN),
            ("darwin", _MAC),
            ("macos", _MAC),
            ("apple", _MAC),
            ("linux", _NIX),
        ):
            if needle in token:
                out.update(values)
                break
        # The ARCHITECTURE in a target triple. Leaving it to the executing host
        # skips a requirement guarded by `platform_machine == "aarch64"`
        # whenever the lock was compiled for one and this machine is not.
        for arch in (
            "aarch64",
            "arm64",
            "x86_64",
            "i686",
            "ppc64le",
            "s390x",
            "armv7l",
        ):
            if arch not in token:
                continue
            # `aarch64-apple-darwin` evaluates as `platform_machine == "arm64"`:
            # that is what the platform calls the same architecture, and a
            # requirement guarded by `arm64` would otherwise be skipped.
            if arch in ("aarch64", "arm64"):
                out["platform_machine"] = (
                    "arm64" if out.get("sys_platform") == "darwin" else arch
                )
            else:
                out["platform_machine"] = arch
            break
    return out


def _exact_pin(line: str) -> tuple[str, frozenset[str], str] | None:
    """``(name, extras, version)`` for a lock entry pinning one exact version.

    `packaging!=21,==23` is an exact pin whose `==` is not first; pip resolves
    it to 23 and hashes it like any other. Parsed rather than pattern-matched
    so the ORDER of the specifiers cannot decide whether a pin is seen.
    """
    text = _HASH_RE.sub("", _strip_comment(line)).strip()
    if not text:
        return None
    req = _requirement(text)
    if req is None:
        return None
    exact = [
        s for s in req.specifier if s.operator in ("==", "===") and "*" not in s.version
    ]
    if len(exact) != 1:
        return None  # no single exact version: pip has a range here, not a pin
    extras = frozenset(e.strip().lower() for e in (req.extras or set()) if e.strip())
    return _dist_name(req.name), extras, exact[0].version


def _effective_pins(
    path: Path, root: Path | None = None, _seen: set[Path] | None = None
) -> tuple[dict[str, list[_Pin]], set[str], dict[str, str]]:
    """``({name: [pin, ...]}, extras, environment)`` for a file and its includes.

    pip installs `-r other.lock` as part of ONE requirement set, so a split
    lock is complete even though neither file is on its own.
    """
    seen = _seen if _seen is not None else set()
    resolved = path.resolve()
    if resolved in seen:
        return {}, set(), {}  # a cycle; whatever it holds has been read already
    seen.add(resolved)
    pins: dict[str, list[_Pin]] = {}
    extras: set[str] = set()  # kept for signature stability; see _declared_extras
    env: dict[str, str] = {}
    # The STRICT reader: this file is a lock we are judging, and reading it as
    # empty would report its whole closure present. Non-regular files (a FIFO
    # named `pipe.lock` blocks forever when opened) and oversized ones raise.
    text = _read_requirements(path)
    if not text:
        return pins, extras, env
    env.update(_lock_environment(text))
    for line in _joined_lines(text):
        # One parser for every `-r` spelling, shared with `_includes` and
        # `_referenced`. This was a third private regex, and it disagreed with
        # the other two: it stopped a filename at the first quote, so a lock
        # including `-r "prod set.txt"` had that file's pins silently missing
        # from its closure and was reported incomplete for pins it installs.
        references = _requirement_args(line)
        if references:
            for name in references:
                target = _safe_include(path.parent / name, root or path.parent)
                if target is None:
                    continue
                sub, sub_extras, sub_env = _effective_pins(target, root, seen)
                for pkg, entries in sub.items():
                    pins.setdefault(pkg, []).extend(entries)
                extras |= sub_extras
                env = {**sub_env, **env}
            continue
        # The whole requirement, not a leading `==`: a valid hashed entry may
        # spell its exact pin as `packaging!=21,==23`, and reading only the
        # first specifier dropped it from the pins entirely -- so a release
        # needing `packaging>=23` was reported missing against a lock that
        # pins exactly 23.
        entry = _exact_pin(line)
        if entry is None:
            continue
        name, entry_extras, version = entry
        _, _, after = line.partition(";")
        marker = after.split("--hash")[0].strip() if after else ""
        pins.setdefault(name, []).append(
            _Pin(
                version=version,
                marker=marker,
                # BOTH spellings. pip documents `--hash <hash>` and its parser
                # accepts the space form, so matching only `--hash=` reads a
                # perfectly good lock as unhashed -- and `set_version` then
                # rewrites the blastbox version without replacing its hashes.
                hashed=_HASH_RE.search(line) is not None,
                extras=entry_extras,
            )
        )
    return pins, extras, env


def _marker_holds(marker: str, scope: dict[str, str]) -> bool:
    """Whether a lock entry's own marker applies. No marker means always."""
    if not marker:
        return True
    from packaging.markers import InvalidMarker, Marker  # noqa: PLC0415

    try:
        return Marker(marker).evaluate(scope)
    except (InvalidMarker, Exception):  # noqa: BLE001 -- unreadable: assume it applies
        return True


def _requirement(text: str):
    """A parsed requirement, or None when it cannot be read.

    Unparseable metadata must not turn into a refusal: this decides whether to
    BLOCK a version bump, and a requirement nobody can parse is not evidence
    that a lock is incomplete.
    """
    from packaging.requirements import InvalidRequirement, Requirement  # noqa: PLC0415

    try:
        return Requirement(text)
    except InvalidRequirement:
        return None


def _applicable_names(pins: dict[str, list[_Pin]], scope: dict[str, str]) -> set[str]:
    """Distributions this lock actually installs in ``scope``.

    A portable lock carries names whose only entries are `sys_platform ==
    "win32"`. Counting those as present on Linux infers an extra from packages
    that are never installed there, and then reports every one of its
    dependencies missing.
    """
    return {
        name
        for name, entries in pins.items()
        if any(_marker_holds(pin.marker, scope) for pin in entries)
    }


def _declared_extras_for(root: Path, lock: Path, n_sets: int) -> set[str]:
    """Blastbox extras that apply to THIS install set.

    A declaration is evidence only about the set that selects it. A `dev`
    optional group containing `blastbox[host]` says nothing about a separate
    production lock installing plain blastbox, and demanding host's closure
    there rejects a correct lock.

    Attributed two ways, both narrow:

    * a file that installs this lock and also names blastbox extras -- a
      Dockerfile doing `pip install blastbox[host]` beside `-r prod.lock`;
    * the repository's declarations, but ONLY when there is a single install
      set, where there is nothing to confuse them with. RedTusk is that case:
      one lock, and `blastbox[host,s3]` in its pyproject.

    Anything else falls through to inference -- a guess, but a local one.
    """
    out: set[str] = set()
    target = lock.resolve()
    for path in _walk(root):
        if not _INSTALL_SCRIPT_RE.fullmatch(path.name) or _is_install_input(path):
            continue
        # Per COMMAND, not per file. A multi-stage Dockerfile can install plain
        # blastbox from prod.lock in one stage and `blastbox[host]` from
        # dev.lock in another; taking every occurrence in the file applies host
        # to prod.lock and rejects a lock whose stage never installs it.
        for line in _joined_lines(_read_small(path)):
            if target not in set(_referenced_in(line, path.parent, root)):
                continue
            out |= {
                e.strip().lower()
                for match in re.finditer(r"(?i)\bblastbox\[([^\]]+)\]", line)
                for e in match.group(1).split(",")
                if e.strip()
            }
    if out:
        return out
    return _declared_blastbox_extras(root) if n_sets == 1 else set()


def _shell_tokens(text: str) -> list[str]:
    """One line, tokenised as a shell would. Empty when it cannot be read.

    `comments=False` because `_strip_comment` has already applied pip's and the
    shell's rule (a comment opens at whitespace); letting shlex apply its own
    cut a VCS requirement at its `#egg=` fragment. The single tokeniser exists
    so the two callers cannot drift apart -- three private copies of the `-r`
    pattern is exactly how a quoted include stopped being followed.
    """
    try:
        return shlex.split(_strip_comment(text), comments=False)
    except ValueError:
        return []  # unbalanced quotes: not a command we can read


def _option_args(tokens: Sequence[str], names: tuple[str, str]) -> list[str]:
    """Filenames given to one repeatable pip option, in every spelling.

    pip accepts `-r file`, `-rfile`, `-r=file` and `--requirement=file`, and
    documents both `-r` and `-c` as repeatable. One reader for both, because
    three private copies of this pattern is how a quoted include stopped being
    followed.
    """
    short, long = names
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in (short, long):
            if index + 1 < len(tokens):
                out.append(tokens[index + 1])
            index += 2
            continue
        for prefix in (f"{long}=", f"{short}="):
            if token.startswith(prefix):
                out.append(token[len(prefix) :])
                break
        else:
            if token.startswith(short) and len(token) > len(short):
                out.append(token[len(short) :])  # the attached short form
        index += 1
    return out


def _requirement_args(text: str) -> list[str]:
    """Filenames given to `-r` / `--requirement`, parsed as a shell would.

    `pip install -r "prod lock.txt"` names a file with a space in it. A path
    character class stops at the space and resolves `prod`, which does not
    exist -- so the real lock is never promoted to a root and its closure is
    never checked.
    """
    return _option_args(_shell_tokens(text), ("-r", "--requirement"))


def _constraint_args(text: str) -> list[str]:
    """Filenames given to `-c` / `--constraint`, parsed as a shell would."""
    return _option_args(_shell_tokens(text), ("-c", "--constraint"))


def _referenced_in(line: str, base: Path, root: Path) -> list[Path]:
    """Requirement files named by ONE command SEGMENT.

    The caller has already isolated the segment (`_install_segments`), so no
    filtering happens here: splitting again would be the difference between
    `pip install -r a.lock && pip install -r b.lock` being two resolutions and
    one.
    """
    out: list[Path] = []
    for name in _requirement_args(line):
        for candidate in (base, root):
            target = _safe_include(candidate / name, root)
            if target is not None:
                out.append(target)
    return out


def _extras_of(spec: str) -> set[str]:
    """The extras named by one requirement string, if it names blastbox.

    Falls back to the name-and-extras PREFIX when the whole requirement will
    not parse. A Dockerfile writes `blastbox[s3]==${BLASTBOX_VERSION}`, whose
    specifier is a shell placeholder rather than a version -- ClippyShot's real
    install line, and dropping it lost the s3 extra entirely. The fallback is
    anchored, so it only ever reads a token that STARTS as a blastbox
    requirement, never prose that mentions one.
    """
    req = _requirement(spec)
    if req is not None:
        if _dist_name(req.name) != "blastbox":
            return set()
        return {e.strip().lower() for e in (req.extras or set()) if e.strip()}
    # Anywhere in the token, because every real spelling of an unparseable
    # blastbox requirement puts the extras somewhere other than position 0:
    # a local checkout (`-e /src/blastbox[host]`), a VCS install
    # (`git+https://.../blastbox.git#egg=blastbox[s3]`), and a placeholder
    # version (`blastbox[s3]==${BLASTBOX_VERSION}`) all genuinely install it.
    # Prose is excluded by the CALLER -- only install-command arguments and
    # declared dependency fields reach here -- not by anchoring this pattern.
    found: set[str] = set()
    for match in re.finditer(r"(?i)blastbox\[([^\]]+)\]", spec.strip()):
        found |= {e.strip().lower() for e in match.group(1).split(",") if e.strip()}
    return found


def _blastbox_extras_in(path: Path) -> set[str]:
    """Blastbox extras this file actually INSTALLS.

    Parsed, not grepped. `# develop with blastbox[host]` in a comment, or a
    project description mentioning it, is prose -- and matching it refused a
    base-only lock for missing every host dependency that no install path asks
    for.
    """
    out: set[str] = set()
    text = _read_small(path)
    if path.name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return out
        project = data.get("project") or {}
        specs = list(project.get("dependencies") or [])
        for group in (project.get("optional-dependencies") or {}).values():
            specs.extend(group or [])
        # PEP 735 groups live at the TOP level, not under [project], and a lock
        # is commonly compiled from one. `_scan_pyproject` already reads them.
        for group in (data.get("dependency-groups") or {}).values():
            specs.extend(group or [])
        for spec in specs:
            if isinstance(spec, str):
                out |= _extras_of(spec)
        return out
    # A Dockerfile or script: only arguments of an actual install command.
    for line in _joined_lines(text):
        tokens = _shell_tokens(line)
        if "install" not in tokens or not any("pip" in tok for tok in tokens):
            continue
        for token in tokens:
            out |= _extras_of(token)
    return out


def _declared_blastbox_extras(root: Path) -> set[str]:
    """Blastbox extras this repository asks for, from its own requirements.

    `blastbox[host,s3]>=0.1.39` says exactly which optional sets the consumer
    installs, and it is written in pyproject, a Dockerfile pip line, or the
    lock entry. Nothing has to be inferred from what a lock happens to carry.
    """
    out: set[str] = set()
    for path in _walk(root):
        # Declarations only. A LOCK's own `blastbox[...]` entries are read
        # per-entry with their markers, so scanning them here as plain text
        # would pool `blastbox[host]; python_version < "3.13"` together with
        # `blastbox[s3]; python_version >= "3.13"` and demand a closure pip
        # installs on neither.
        if not (
            path.name == "pyproject.toml"
            or path.name.startswith("Dockerfile")
            or path.name.endswith((".Dockerfile", ".dockerfile"))
        ):
            continue
        out |= _blastbox_extras_in(path)
    return out


def _declared_extras(parsed: Sequence[Any]) -> set[str]:
    """Every extra the release's own metadata mentions."""
    out: set[str] = set()
    for req in parsed:
        if req is None:
            continue
        marker = str(getattr(req, "marker", "") or "")
        out |= {e.lower() for e in re.findall(r"extra\s*==\s*[\"\']([^\"\']+)", marker)}
    return out


def _extras_in_play(
    parsed: Sequence[Any],
    pins: dict[str, list[_Pin]],
    environment: dict[str, str] | None,
) -> set[str]:
    """Extras this lock was compiled for, inferred from what it already holds.

    A uv-compiled lock records resolved names only: `uv pip compile --extra
    host` writes a plain `blastbox==0.1.39` line, so the extras cannot be read
    off the entry. But a lock that carries fastapi was compiled for the host
    extra whether or not it says so, and one with no boto3 was not compiled for
    s3 -- which is the distinction that keeps this from being noise.

    Evidence is counted only from requirements that APPLY. A host extra with a
    `pywin32; extra == "host" and sys_platform == "win32"` member has two
    dependencies on Windows and one on Linux; counting the Windows-only one
    against a Linux lock pushes it under the threshold, the extra is not
    recognised, and a genuinely missing pin is then accepted.

    Only dependencies UNIQUE to an extra count, and MORE THAN HALF of them must
    be present. On RedTusk's real lock the `dev` extra's only "present"
    dependency was `blastbox` itself -- dev depends on `blastbox[host]` -- which
    inferred dev and reported pytest, mypy and ruff missing from a RUNTIME lock.
    Noise like that is how a check stops being read. Half is not a majority
    either: an extra with two unique dependencies, one of which the lock pins
    for its own reasons, would otherwise be inferred from that single package.

    The limit worth knowing: an extra with exactly ONE dependency is invisible
    once that dependency is missing -- a lock without boto3 looks the same
    whether it dropped `blastbox[s3]` or never asked for it. A lock that spells
    its extras (`blastbox[s3]==...`) is not subject to that.
    """
    env = dict(environment or {})
    present = _applicable_names(pins, env)
    base: set[str] = set()
    by_extra: dict[str, set[str]] = {}
    for req in parsed:
        if req is None:
            continue
        marker = str(getattr(req, "marker", "") or "")
        name = _dist_name(req.name)
        if "extra ==" not in marker:
            base.add(name)
            continue
        for extra in re.findall(r"extra\s*==\s*[\"\']([^\"\']+)", marker):
            if not _marker_holds(marker, {**env, "extra": extra}):
                continue  # e.g. a win32-only member of an extra, on Linux
            by_extra.setdefault(extra.lower(), set()).add(name)
    found = set()
    for extra, names in by_extra.items():
        # Unique across EVERY extra, not just against the base. If `host` needs
        # a and b while `dev` needs a, b and pytest, a host-only lock carries a
        # majority of dev's requirements too -- and dev gets inferred from
        # evidence that belongs entirely to host.
        #
        # `blastbox` itself is excluded for the same reason: an extra that
        # depends on `blastbox[host]` would otherwise be inferred by the lock's
        # own entry, which every lock has.
        others = (
            set().union(*(v for k, v in by_extra.items() if k != extra))
            if len(by_extra) > 1
            else set()
        )
        unique = names - base - others - {"blastbox"}
        if not unique:
            continue
        if len(unique & present) * 2 > len(unique):
            found.add(extra)
    return found


def _with_nested_extras(
    extras: set[str], parsed: Sequence[Any], environment: dict[str, str] | None
) -> set[str]:
    """``extras`` plus every blastbox extra they enable, transitively.

    One extra can turn another on: `blastbox[host]; extra == "dev"` means a
    lock built for `dev` installs the whole host closure, and pip then demands
    hashes for all of it. Recording only the distribution name discarded the
    `[host]` part, so those dependencies were never checked -- the lock looked
    complete and the install failed.
    """
    env = dict(environment or {})
    out = set(extras)
    while True:
        grown = set(out)
        for req in parsed:
            if req is None or _dist_name(req.name) != "blastbox":
                continue
            nested = {e.lower() for e in getattr(req, "extras", set()) or set()}
            if not nested:
                continue
            marker = str(getattr(req, "marker", "") or "")
            if not marker:
                grown |= nested
                continue
            for extra in sorted(out) + [""]:
                if _marker_holds(marker, {**env, "extra": extra}):
                    grown |= nested
                    break
        if grown == out:
            return out
        out = grown


def _applies(req, extras: AbstractSet[str], environment: dict[str, str] | None) -> bool:
    """Whether ``req`` is one this lock actually has to carry."""
    if req.marker is None:
        return True
    env = dict(environment or {})
    # `extra` is only defined when evaluating for an extra, so try each the lock
    # asked for -- plus the empty one, which is how a base requirement guarded
    # by an ordinary marker gets evaluated.
    for extra in sorted(extras) + [""]:
        try:
            if req.marker.evaluate({**env, "extra": extra}):
                return True
        except Exception:  # noqa: BLE001 -- an unevaluable marker is not a gap
            return False
    return False


def _satisfies(req, version: str) -> bool:
    """Whether the locked ``version`` satisfies ``req``.

    Presence alone is not enough: `packaging==22` against a release needing
    `packaging>=23` is pinned, hashed, and still unresolvable by pip.
    """
    if not req.specifier:
        return True
    try:
        return req.specifier.contains(version, prereleases=True)
    except Exception:  # noqa: BLE001 -- an unreadable version is not a gap
        return True


def set_version(
    root: Path,
    version: str,
    *,
    digests: list[str] | None = None,
) -> list[str]:
    """Point every pin under ``root`` at ``version``. Returns changed paths.

    ``digests`` are the sha256 hashes of the release's PyPI artifacts, required
    only when a hash-pinned lock file is present: rewriting the version there
    without the hashes produces a lock that `pip install --require-hashes`
    rejects outright, which is a broken build rather than a bumped one.

    Rewrites nothing unless every file can be rewritten. A half-applied bump
    leaves a repo pinned to two versions -- exactly the drift this module
    reports -- so the work is staged in memory and written only at the end.
    """
    # `v0.1.30` is how the tag is spelled, and callers paste tags. Accepting it
    # verbatim wrote the `v` into every pin and then failed verification against
    # the scanner, which strips it -- a bump that damaged the repo and reported
    # failure. Strip it once, here, so what is written and what is verified are
    # the same string.
    version = version.strip().lstrip("vV")
    if not re.match(r"^\d+(\.\d+)*", version):
        raise PinScanError(
            f"{version!r} does not look like a version. Pass it as 0.1.30, not "
            "as a tag or a specifier."
        )

    pins = scan(root)
    if not pins:
        raise PinScanError(f"{root}: no blastbox pins found; nothing to set")

    # Pins this rewriter must not pretend to handle. Each would otherwise be
    # left untouched, and the re-scan below cannot notice: a direct reference
    # has no FLOOR, so `disagreements` never groups it and a stale
    # `blastbox @ git+...@v0.1.27` would survive a "successful" bump silently.
    unhandled = []
    for pin in pins:
        if pin.floor is None:
            unhandled.append(
                f"{pin.path}:{pin.line} ({pin.kind}) {pin.raw.strip()[:70]}"
            )
        elif pin.line <= 0:
            # TOML locks (uv/poetry/pdm) are reported without a line, because
            # the package is a table rather than a requirement line. Rewriting
            # by line number cannot work, and guessing would corrupt the lock.
            unhandled.append(f"{pin.path} ({pin.kind}) -- no line to rewrite")
    if unhandled:
        raise PinScanError(
            f"{root}: {len(unhandled)} pin(s) cannot be rewritten safely and would "
            f"be left at their current version while this reported success:\n  "
            + "\n  ".join(unhandled)
            + "\nUpdate these by hand (or with their own tool) and re-run."
        )

    conflicts = [
        f"{pin.path}:{pin.line} keeps {bad!r}"
        for pin in pins
        if (bad := _violated_bound(pin.specifier, version))
    ]
    if conflicts:
        raise PinScanError(
            f"{root}: {version} does not satisfy a bound that would be preserved:\n  "
            + "\n  ".join(conflicts)
            + "\nSetting it would write a specifier nothing can install. Raise "
            "the ceiling deliberately first."
        )

    by_path: dict[str, list[Pin]] = {}
    for pin in pins:
        by_path.setdefault(pin.path, []).append(pin)

    staged: dict[Path, str] = {}
    for rel, file_pins in by_path.items():
        path = root / rel
        # newline="" keeps CRLF intact: without it a SUCCESSFUL bump silently
        # rewrote every line ending in the file.
        with path.open(encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines(keepends=True)
        needs_hashes = False
        for pin in sorted(file_pins, key=lambda p: p.line, reverse=True):
            i = pin.line - 1
            if not 0 <= i < len(lines):
                raise PinScanError(f"{rel}:{pin.line}: line is gone; re-scan and retry")
            # Search the whole logical line, not just its first physical one.
            # Rewriting is still per-PHYSICAL-line so that continuations,
            # indentation and everything else on the other lines survive.
            span = (
                _logical_span(lines, i)
                if pin.kind != "dockerfile-arg"
                else range(i, i + 1)
            )
            first_error: PinScanError | None = None
            for j in span:
                try:
                    eol = "\n" if lines[j].endswith("\n") else ""
                    lines[j] = _rewrite_line(lines[j].rstrip("\n"), pin, version) + eol
                    break
                except PinScanError as exc:
                    first_error = first_error or exc
                    continue
            else:
                # A one-line span has nothing to search, so its specific
                # diagnosis -- "no version found after `=`" for an ARG -- is the
                # useful message. Replacing it with "not found anywhere in its
                # logical line" would describe a search that never happened.
                if len(span) == 1 and first_error is not None:
                    raise first_error
                raise PinScanError(
                    f"{pin.path}:{pin.line}: cannot locate the blastbox requirement "
                    f"{pin.raw.strip()[:60]!r} anywhere in its logical line "
                    f"(physical lines {span.start + 1}-{span.stop}). Refusing to "
                    "guess -- a partial rewrite leaves the repo pinned to two "
                    "versions."
                ) from first_error
            if pin.kind == "lock" and _HASH_RE.search("".join(lines[i : i + 4])):
                needs_hashes = True
        if needs_hashes:
            if not digests:
                raise PinScanError(
                    f"{rel} is hash-pinned, so bumping it needs the release's "
                    "sha256 digests. Without them `pip install --require-hashes` "
                    "rejects the lock and the build fails at install time."
                )
            lines = _replace_hashes(lines, file_pins, digests, rel)
        staged[path] = "".join(lines)

    # Keep the originals: the verification below runs against the files on
    # disk, so a failure at that point has already modified them. Restoring is
    # what makes "nothing is written unless every pin moved" true at the end of
    # the operation and not just at the start of it.
    # Bytes, not text: `read_text` performs universal-newline translation, so a
    # CRLF file restored through it comes back with LF endings -- a "rollback"
    # that rewrites every line of the file it was meant to leave alone.
    original = {path: path.read_bytes() for path in staged}
    for path, text in staged.items():
        # newline="" on the WRITE is unobservable on POSIX -- newline=None only
        # translates on platforms whose linesep is not "\n" -- so no test here
        # can kill a mutant that drops it. It is still required: on Windows the
        # default would translate the "\n" inside an already-CRLF line and
        # produce "\r\r\n".
        path.write_text(text, encoding="utf-8", newline="")

    # Verify by RE-SCANNING rather than by trusting the rewrite: the scanner is
    # what reports drift, so agreeing with it is the only check that means
    # anything. `disagreements` groups by version and always returns the
    # grouping, so drift is more than one key -- not a non-empty result.
    # Any failure from here on must restore, not just a stale-pin finding: if
    # the re-scan itself raises -- a file this rewrite made unparseable would do
    # it -- returning without restoring leaves exactly the half-applied state
    # the staging exists to prevent.
    def _restore() -> None:
        for path, data in original.items():
            path.write_bytes(data)

    try:
        after = scan(root)
        groups = disagreements(after)
        wanted = _normalise_version(version)
        stale = {v: q for v, q in groups.items() if _normalise_version(v) != wanted}
    except Exception:
        _restore()
        raise
    if stale:
        _restore()
        raise PinScanError(
            f"{root}: after setting {version}, {sum(len(q) for q in stale.values())} "
            f"pin(s) still resolve to {sorted(stale)}: "
            f"{[f'{q.path}:{q.line}' for qs in stale.values() for q in qs]}. "
            "The rewrite did not reach every pin. Every file has been restored."
        )
    # Only what actually CHANGED. Every staged file is written -- the atomic
    # restore below depends on that -- but a rewrite that produced identical
    # bytes is not an update, and reporting it as one tells an operator their
    # repo moved when it did not. Re-running `pins --set` on a correct repo
    # should say nothing happened, because nothing did.
    return sorted(
        str(q) for q, text in staged.items() if original[q] != text.encode("utf-8")
    )


def _replace_hashes(
    lines: list[str], file_pins: list[Pin], digests: list[str], rel: str
) -> list[str]:
    """Swap the `--hash=` continuation lines under each locked blastbox pin."""
    for pin in sorted(file_pins, key=lambda p: p.line, reverse=True):
        if pin.kind != "lock":
            continue
        start = pin.line  # first line AFTER the requirement
        end = start
        indent = "    "
        while end < len(lines) and _HASH_RE.search(lines[end]):
            indent = lines[end][: len(lines[end]) - len(lines[end].lstrip())]
            end += 1
        if end == start:
            # Hashes can live ON the requirement line rather than below it. The
            # version has already been rewritten by this point, so skipping here
            # leaves the OLD digests beside the NEW version -- a lock that fails
            # `--require-hashes` while the command reports success.
            req_line = lines[start - 1]
            # Either spelling: a lock written with `--hash sha256:...` would
            # otherwise keep its OLD digests beside a NEW version, and the
            # version-only rescan reports success while the install rejects it.
            inline = _HASH_RE.search(req_line)
            if inline:
                head = req_line[: inline.start()].rstrip()
                lines[start - 1] = (
                    head
                    + " "
                    + " ".join(f"--hash=sha256:{d}" for d in digests)
                    + (_eol_of(req_line) or "\n")
                )
            continue
        # The separator is " \\\n", with the SPACE: written as "...hash\\" the
        # backslash abuts the digest, and what pip reads as the hash value is
        # no longer the hash. Every continuation but the last gets one.
        eol = _eol_of(lines[start]) or _eol_of(lines[start - 1]) or "\n"
        block = [
            ln + (" \\" + eol if n < len(digests) - 1 else eol)
            for n, ln in enumerate(_hash_lines(indent, digests))
        ]
        # The requirement line itself ends in a backslash when hashes follow.
        req = lines[start - 1].rstrip("\r\n").rstrip().rstrip("\\").rstrip()
        lines[start - 1] = f"{req} \\" + (_eol_of(lines[start - 1]) or "\n")
        lines[start:end] = block
    return lines
