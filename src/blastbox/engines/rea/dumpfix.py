"""Static header repair of PE images rebuilt from process memory (CAPE's payload dumps).

CAPE writes its dumps back in file layout, but the headers it rebuilds are not always sane.
Two faults were seen live (2026-11-07, toolz4 tasks 25483-25534); this module reads only the
headers, never runs anything, and never modifies its source:

- **VirtualSize past the image.** Every section's ``Misc.VirtualSize`` held the section's
  absolute address (``ImageBase + VirtualAddress``, ~1.7 GiB each). Ghidra maps a block that size
  per section and timed out. A section whose ``VirtualAddress + VirtualSize`` overruns
  ``SizeOfImage`` gets the span up to the next section (the last: up to ``SizeOfImage``). No
  loadable image has such a section, so the rewrite cannot change how a real image maps.
  The repaired copy differs from the source only in those header fields.
- **Sections never captured.** Code or initialised-data sections larger than one page with no
  file bytes, or with file bytes past the end of the dump (``.rdata``/``.idata`` absent from the
  dump). Nothing static can recover them; they are reported so the analyst and the agent read
  "import table not file-mapped" as a capture gap, not as an anti-analysis trick.

Both are deliberately narrow: an image with neither fault returns ``None`` and is analysed as is.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

MAX_SECTIONS = 96
MAX_IMAGE = 1 << 30  # SizeOfImage above this is itself implausible: no rewrite
HEAD_BYTES = 64 * 1024
MISSING_MIN = 0x1000  # a one-page section with no bytes (.tls, .CRT) is ordinary

_CNT_CODE, _CNT_INITIALIZED = 0x20, 0x40


@dataclass(frozen=True)
class DumpFix:
    repaired: list[str] = field(default_factory=list)  # sections whose VirtualSize was rewritten
    missing: list[str] = field(default_factory=list)  # code/data sections whose bytes are absent


@dataclass
class _Section:
    name: str
    header: int  # offset of the section header in the file
    vsize: int
    va: int
    raw_size: int
    raw_off: int
    chars: int


def _read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            return f.read()
        except OSError:
            return None


def _parse(head: bytes) -> tuple[int, list[_Section]] | None:
    """``(SizeOfImage, sections)`` from the headers, or None when this is no PE we can read."""
    try:
        if head[:2] != b"MZ":
            return None
        (e,) = struct.unpack_from("<I", head, 0x3C)
        if head[e:e + 4] != b"PE\x00\x00":
            return None
        (n,) = struct.unpack_from("<H", head, e + 6)
        (optsz,) = struct.unpack_from("<H", head, e + 20)
        (size_of_image,) = struct.unpack_from("<I", head, e + 24 + 56)
        if not 0 < n <= MAX_SECTIONS:
            return None
        first = e + 24 + optsz
        out = []
        for i in range(n):
            o = first + 40 * i
            if o + 40 > len(head):
                return None
            vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", head, o + 8)
            (chars,) = struct.unpack_from("<I", head, o + 36)
            name = head[o:o + 8].rstrip(b"\x00").decode("latin-1")
            out.append(_Section(name, o, vsize, va, raw_size, raw_off, chars))
        return size_of_image, out
    except struct.error:
        return None


def repair(src: Path, dest: Path) -> DumpFix | None:
    """Diagnose ``src`` and, when a VirtualSize needs rewriting, write the repaired copy to ``dest``.

    Returns None for a non-PE, an unreadable header or an image with neither fault. ``dest`` is
    written only when ``repaired`` is non-empty; ``missing`` alone changes nothing on disk.
    """
    data = _read(src)
    parsed = _parse(data[:HEAD_BYTES]) if data else None
    if data is None or parsed is None:
        return None
    file_size = len(data)
    size_of_image, sections = parsed
    by_va = sorted(sections, key=lambda s: s.va)
    sane = 0 < size_of_image <= MAX_IMAGE and all(s.va < size_of_image for s in sections)

    repaired: list[_Section] = []
    if sane:
        for i, s in enumerate(by_va):
            if s.va + s.vsize > size_of_image:
                end = by_va[i + 1].va if i + 1 < len(by_va) else size_of_image
                s.vsize = max(0, end - s.va)
                repaired.append(s)

    missing = [s.name for s in sections
               if s.chars & (_CNT_CODE | _CNT_INITIALIZED) and s.vsize > MISSING_MIN
               and (s.raw_size == 0 or s.raw_off + s.raw_size > file_size)]
    if not repaired and not missing:
        return None
    if repaired:
        out = bytearray(data)
        for s in repaired:
            struct.pack_into("<I", out, s.header + 8, s.vsize)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(bytes(out))
    return DumpFix(repaired=[s.name for s in repaired], missing=missing)
