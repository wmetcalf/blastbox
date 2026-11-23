"""Inno Setup extraction for the sweep, on Binary Refinery's parser (nothing runs).

innoextract 1.9 (the latest release) rejects current Inno Setup ("Unexpected setup loader
revision"): a live adware installer built with 6.7.0 came back with nothing. Binary Refinery's
``xtinno`` reads every version up to 7.x, decrypts nothing it has no password for, and also
disassembles the compiled ``[Code]`` PascalScript, which is where such an installer's behaviour
is (download URLs, COM objects, registry and startup paths) when ``[Run]`` is empty.

THIS FILE RUNS AS A STANDALONE SCRIPT under the Refinery venv's python, as a bounded subprocess
(``installer.extract``: ``ulimit -v``/``-f``, a watched output tree, timeout), because the parser
reads a hostile file: ``python -I inno_unwrap.py <sample> <outdir> [max bytes]``. It imports only
the standard library and ``refinery``. Exit 0 when at least one member was written and the
archive was read to its end, 2 when the parser failed after writing some, 1 otherwise.

Members come out of the parser as ``(path, bytes)`` and are written here, never by the parser:
the paths are the installer's (``data/{app}/..\\..\\x``), so each is rebuilt from sanitised
components (:func:`safe_rel`) under ``outdir`` and created with ``O_EXCL | O_NOFOLLOW``. The tree:

- ``data/<destination>``: the installed files, by ``[Files]`` destination (``{app}``, ``{tmp}``...);
- ``embedded/script.ps``: the ``[Code]`` disassembly (``installer`` reads its string literals);
- ``meta/setup.json``, ``meta/files.json``: the decoded setup header and file table;
- ``embedded/images/*``: wizard images.

Left out: the parser's raw copies (``*.bin``, ``*.template``) and ``embedded/uninstaller.exe``,
which is the setup program itself without its data, so "the largest PE" would be the stub again.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path

MAX_FILES = 4096
MAX_BYTES = 512 * 1024 * 1024
MAX_SAMPLE = 1024 * 1024 * 1024
MAX_PARTS = 12
MAX_PART_CHARS = 96

_SKIP = frozenset({"embedded/uninstaller.exe", "embedded/script.bin", "meta/setup.bin", "meta/setup.template",
                   "meta/files.bin", "meta/files.template"})
_UNSAFE = re.compile(r"[^A-Za-z0-9._{}()\[\]+,=@$~ -]")
_SEP = re.compile(r"[\\/]+")


def safe_rel(path: str) -> str | None:
    """``path`` rebuilt from sanitised components (no ``.``/``..``/empty ones, no separators or
    control characters inside one, bounded depth and length); None when nothing is left."""
    parts: list[str] = []
    for raw in _SEP.split(path):
        part = _UNSAFE.sub("_", raw).strip(" .")[:MAX_PART_CHARS].strip(" .")
        if part:
            parts.append(part)
    if not parts:
        return None
    if len(parts) > MAX_PARTS:  # keep the top (data/embedded/meta) and the file's own end
        parts = parts[: MAX_PARTS // 2] + parts[-(MAX_PARTS - MAX_PARTS // 2):]
    return "/".join(parts)


def unwrap(items: Iterable[tuple[str, bytes]], outdir: Path, *, max_bytes: int = MAX_BYTES,
           max_files: int = MAX_FILES) -> int:
    """Write each ``(path, data)`` under ``outdir``; the number written. Stops at the caps."""
    written = count = 0
    for path, data in items:
        if count >= max_files:
            break
        rel = safe_rel(path)
        if rel is None or rel in _SKIP:
            continue
        if written + len(data) > max_bytes:
            break
        target = outdir / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            n = 0
            while target.exists() or target.is_symlink():  # two members, one destination
                n += 1
                target = target.with_name(f"{Path(rel).name}~{n}")
                if n > max_files:
                    raise FileExistsError(rel)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError:  # a file where a directory is needed, a name too long...
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        written += len(data)
        count += 1
    return count


def _members(sample: bytes) -> Iterable[tuple[str, bytes]]:
    from refinery.units.formats.archive.xtinno import xtinno  # type: ignore[import-not-found]

    for chunk in sample | xtinno():
        path = chunk.meta.get("path")
        if path is not None:
            yield str(path), bytes(chunk)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 1
    sample, outdir = Path(argv[1]), Path(argv[2])
    max_bytes = int(argv[3]) if len(argv) > 3 else MAX_BYTES
    if sample.stat().st_size > MAX_SAMPLE:
        return 1
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        count = unwrap(_members(sample.read_bytes()), outdir, max_bytes=max_bytes)
    except Exception:  # the parser gave up part-way: what is on disk is still evidence
        return 2 if any(outdir.iterdir()) else 1
    return 0 if count else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
