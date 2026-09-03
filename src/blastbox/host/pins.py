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
# Leading whitespace is legal in a requirements-format file. A hashed lock pins
# with ==, but constraints.txt and requirements/*.txt legitimately carry any
# specifier -- matching only == silently skipped them.
_LOCK_RE = re.compile(
    r'^\s*(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*'
    r'((?:[=<>!~]=|[<>])\s*v?[0-9][^\s;]*(?:\s*,\s*(?:[=<>!~]=|[<>])\s*v?[0-9][^\s;]*)*)'
)
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
    r"(?<![\w.\-])(?i:blastbox)(?:\[[a-zA-Z0-9,._\-]+\])?\s*@\s*(?P<url>[^\s\"']+)"
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
    """Every blastbox requirement token on an install command line.

    Includes DIRECT REFERENCES (`blastbox @ git+https://…`): a Dockerfile can
    install one just as a pyproject can, and dropping it here would repeat the
    silent-omission bug already fixed for pyproject.
    """
    out: list[str] = []
    for m in _REQ_RE.finditer(line):
        start = line.lower().rfind("blastbox", 0, m.end())
        out.append(line[start : m.end()])
    for m in _DIRECT_REF_RE.finditer(line):
        out.append(m.group(0))
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
            out.append(Pin(str(path), i, "lock", raw.strip(),
                           re.sub(r"\s+", "", m.group(1))))
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
            re.escape(m.group(1)) + r"\s*" + re.escape(m.group(2)) if m
            else re.escape(stripped)
        )
    return r"\s*,\s*".join(parts)


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
            bound = _normalise_version(stripped[len(op):].strip().lstrip("vV"))
            if not bound:
                break
            bk = _version_key(bound)
            bad = (key >= bk) if op == "<" else (key > bk) if op == "<=" else (key == bk)
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
            unhandled.append(f"{pin.path}:{pin.line} ({pin.kind}) {pin.raw.strip()[:70]}")
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
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        needs_hashes = False
        for pin in sorted(file_pins, key=lambda p: p.line, reverse=True):
            i = pin.line - 1
            if not 0 <= i < len(lines):
                raise PinScanError(f"{rel}:{pin.line}: line is gone; re-scan and retry")
            # Search the whole logical line, not just its first physical one.
            # Rewriting is still per-PHYSICAL-line so that continuations,
            # indentation and everything else on the other lines survive.
            span = _logical_span(lines, i) if pin.kind != "dockerfile-arg" else range(i, i + 1)
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
            if pin.kind == "lock" and "--hash=" in "".join(lines[i : i + 4]):
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
    original = {path: path.read_text(encoding="utf-8") for path in staged}
    for path, text in staged.items():
        path.write_text(text, encoding="utf-8")

    # Verify by RE-SCANNING rather than by trusting the rewrite: the scanner is
    # what reports drift, so agreeing with it is the only check that means
    # anything. `disagreements` groups by version and always returns the
    # grouping, so drift is more than one key -- not a non-empty result.
    # Any failure from here on must restore, not just a stale-pin finding: if
    # the re-scan itself raises -- a file this rewrite made unparseable would do
    # it -- returning without restoring leaves exactly the half-applied state
    # the staging exists to prevent.
    def _restore() -> None:
        for path, text in original.items():
            path.write_text(text, encoding="utf-8")

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
    return sorted(str(q) for q in staged)


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
        while end < len(lines) and "--hash=" in lines[end]:
            indent = lines[end][: len(lines[end]) - len(lines[end].lstrip())]
            end += 1
        if end == start:
            # Hashes can live ON the requirement line rather than below it. The
            # version has already been rewritten by this point, so skipping here
            # leaves the OLD digests beside the NEW version -- a lock that fails
            # `--require-hashes` while the command reports success.
            req_line = lines[start - 1]
            if "--hash=" in req_line:
                head = req_line.split("--hash=", 1)[0].rstrip()
                lines[start - 1] = (
                    head + " " + " ".join(f"--hash=sha256:{d}" for d in digests) + "\n"
                )
            continue
        # The separator is " \\\n", with the SPACE: written as "...hash\\" the
        # backslash abuts the digest, and what pip reads as the hash value is
        # no longer the hash. Every continuation but the last gets one.
        block = [ln + (" \\\n" if n < len(digests) - 1 else "\n")
                 for n, ln in enumerate(_hash_lines(indent, digests))]
        # The requirement line itself ends in a backslash when hashes follow.
        req = lines[start - 1].rstrip("\n").rstrip().rstrip("\\").rstrip()
        lines[start - 1] = f"{req} \\\n"
        lines[start:end] = block
    return lines
