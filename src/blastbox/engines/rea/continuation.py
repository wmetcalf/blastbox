"""Continuation archive for multi-pass REA analysis.

A pass ends by packing the sample, the Ghidra project and a small ``State`` into one
tar.gz; the next pass unpacks it. The archive crosses a trust boundary (it is produced by
a worker and re-read later), so ``unpack`` treats it as hostile: only regular files and
directories under three fixed roots, no traversal, and a hard cap on bytes *actually
written* (not the header-declared sizes, which a gzip/tar bomb can understate).
"""

from __future__ import annotations

import io
import json
import gzip
import os
import tarfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

GhidraStatus = Literal["ok", "timeout", "failed", "skipped"]

_STATE_NAME = "state.json"
_CHUNK = 64 * 1024
MAX_MEMBERS = 200_000
_HEADER_SLACK = 1024 * 1024  # fixed decompressed-stream allowance beyond max_bytes
_PER_MEMBER_OVERHEAD = 2048  # tar header + padding allowance per member


class _CountingReader:
    """Reads from a gzip stream and refuses to decompress past ``max_bytes`` plus tar overhead.

    tarfile reads GNU longname / pax headers fully into memory before any per-member size
    check can run, so the bound has to sit under tarfile, on the decompressed stream.
    """

    def __init__(self, raw: Any, max_bytes: int) -> None:
        self._raw = raw
        self._max = max_bytes
        self.read_total = 0
        self.members = 0

    def read(self, n: int = -1) -> bytes:
        allowed = self._max + _HEADER_SLACK + _PER_MEMBER_OVERHEAD * self.members - self.read_total
        if n < 0 or n > allowed:
            n = allowed + 1  # read just one past the budget so overflow is detected, not buffered
        data: bytes = self._raw.read(n)
        self.read_total += len(data)
        if len(data) > allowed:
            raise ContinuationError("archive exceeds max_bytes (decompressed)")
        return data
_FILE_MODE = 0o640
_DIR_MODE = 0o750


_OPINIONS = ("benign", "suspicious", "malicious", "unknown")  # prompts.REPORT_LABELS


def _opinion(v: Any) -> str | None:
    return v if isinstance(v, str) and v in _OPINIONS else None


class ContinuationError(Exception):
    """The archive is malformed, unsafe, or over its size budget."""


@dataclass
class State:
    pass_no: int
    sample_name: str
    sample_sha256: str
    program_name: str | None
    ghidra_status: GhidraStatus
    explored: list[str] = field(default_factory=list)
    todo: list[str] = field(default_factory=list)
    summary: str = ""
    started_at: float = 0.0
    # G3: the last valid rea.analysis/1 report (each pass rewrites it) and the sweep's evidence
    # for the report call (``{"kind", "iocs": [{"type", "value", "source"}]}``). Both are absent
    # from older continuations and default to empty.
    analysis_report: dict[str, Any] | None = None
    sweep: dict[str, Any] = field(default_factory=dict)
    # The deepening bar (sufficiency.py): every fact the chain has established so far, and the
    # gaps the last pass left (``[{"code", "detail"}]``) for the next pass to work on. Both are
    # absent from older continuations and default to empty.
    facts: list[str] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    # The program's own functions as the pass-1 seed found them (Go: main.* and third-party
    # modules), which a benign verdict must have read.
    program_functions: list[str] = field(default_factory=list)
    # The model's own call behind ``analysis_report``, before the verdict rule (verdict.py) set the
    # label: the bar reads it when a later pass writes no report of its own. Absent from older
    # continuations.
    opinion: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text: str | bytes) -> State:
        try:
            d: Any = json.loads(text)
            return cls(
                pass_no=int(d["pass_no"]),
                sample_name=str(d["sample_name"]),
                sample_sha256=str(d["sample_sha256"]),
                program_name=None if d["program_name"] is None else str(d["program_name"]),
                ghidra_status=d["ghidra_status"],
                explored=[str(x) for x in d["explored"]],
                todo=[str(x) for x in d["todo"]],
                summary=str(d["summary"]),
                started_at=float(d["started_at"]),
                analysis_report=_opt_dict(d.get("analysis_report")),
                sweep=_opt_dict(d.get("sweep")) or {},
                facts=[str(x) for x in d.get("facts") or []],
                gaps=[{"code": str(g["code"]), "detail": str(g["detail"])} for g in d.get("gaps") or []],
                program_functions=[str(x) for x in d.get("program_functions") or []],
                opinion=_opinion(d.get("opinion")),
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise ContinuationError(f"bad state.json: {exc}") from exc


def _opt_dict(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError("expected an object or null")
    return value


def pack(dest: Path, *, sample: Path, project_dir: Path | None, state: State) -> Path:
    """Write ``dest`` (tar.gz): ``sample/<name>``, ``project/...``, ``state.json``."""
    data = state.to_json().encode()
    with tarfile.open(dest, "w:gz") as tf:
        tf.add(sample, arcname=f"sample/{sample.name}", recursive=False)
        if project_dir is not None:
            for p in sorted(project_dir.rglob("*")):
                if p.is_symlink():
                    continue
                if p.is_dir() or p.is_file():
                    tf.add(p, arcname=f"project/{p.relative_to(project_dir).as_posix()}", recursive=False)
        ti = tarfile.TarInfo(_STATE_NAME)
        ti.size = len(data)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(data))
    return dest


def _safe_parts(name: str) -> tuple[str, ...]:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ContinuationError(f"unsafe member name: {name!r}")
    parts = PurePosixPath(name).parts
    if any(p in ("..", ".", "") for p in parts):
        raise ContinuationError(f"unsafe member name: {name!r}")
    return parts


def unpack(archive: Path, into: Path, *, max_bytes: int) -> tuple[Path, Path | None, State]:
    """Extract ``archive`` under ``into``; returns (sample_path, project_dir|None, State)."""
    into.mkdir(parents=True, exist_ok=True)
    total = 0
    sample: Path | None = None
    project: Path | None = None
    state: State | None = None
    try:
        gz = gzip.open(archive, "rb")
        reader = _CountingReader(gz, max_bytes)
        tf = tarfile.open(fileobj=reader, mode="r|")  # type: ignore[call-overload]
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ContinuationError(f"unreadable archive: {exc}") from exc
    with gz, tf:
        try:
            for m in tf:
                reader.members += 1
                if reader.members > MAX_MEMBERS:
                    raise ContinuationError("too many archive members")
                parts = _safe_parts(m.name)
                root = parts[0]
                if root not in ("sample", "project", _STATE_NAME):
                    raise ContinuationError(f"member outside allowed roots: {m.name!r}")
                if not (m.isreg() or m.isdir()):
                    raise ContinuationError(f"disallowed member type: {m.name!r}")
                if root == _STATE_NAME and (len(parts) != 1 or not m.isreg()):
                    raise ContinuationError("state.json must be a top-level file")
                if root == "sample" and (len(parts) != 2 or not m.isreg()):
                    raise ContinuationError("sample/ must hold exactly one flat file")
                if m.size < 0 or total + m.size > max_bytes:
                    raise ContinuationError("archive exceeds max_bytes")
                target = into.joinpath(*parts)
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    target.chmod(_DIR_MODE)
                    if root == "project" and len(parts) == 1:
                        project = target
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if root == "project":
                    project = into / "project"
                    # Intermediate directories we created implicitly must be owner-writable too.
                    d = target.parent
                    while d != into:
                        d.chmod(_DIR_MODE)
                        d = d.parent
                src = tf.extractfile(m)
                if src is None:
                    raise ContinuationError(f"cannot read member {m.name!r}")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE)
                buf = bytearray() if root == _STATE_NAME else None
                with src, os.fdopen(fd, "wb") as out:
                    while chunk := src.read(_CHUNK):
                        total += len(chunk)  # actual bytes, not the declared size
                        if total > max_bytes:
                            raise ContinuationError("archive exceeds max_bytes")
                        out.write(chunk)
                        if buf is not None:
                            buf += chunk
                target.chmod(_FILE_MODE)
                if root == "sample":
                    if sample is not None:
                        raise ContinuationError("multiple sample files")
                    sample = target
                elif buf is not None:
                    state = State.from_json(bytes(buf))
        except (tarfile.TarError, OSError, EOFError) as exc:
            if isinstance(exc, FileExistsError):
                raise ContinuationError("duplicate member") from exc
            raise ContinuationError(f"corrupt archive: {exc}") from exc
    if sample is None or state is None:
        raise ContinuationError("archive missing sample or state.json")
    return sample, project, state
