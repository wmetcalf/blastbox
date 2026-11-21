"""Exact Go string literals, recovered from the string headers the Go toolchain emits.

Go stores string literals back to back with no terminator (the linker packs ``go:string.*``
symbols, sorted by size), so any NUL-terminated or "printable run" string scan reads past the
end of one literal into the next. Live 2026-11-03, benign_go.elf: the literal
``http://loadout-go-fixture.example.org/ping`` (42 bytes) is followed by the strconv table
``173472347597680709441192448139190673828125...``, and the URL came out with the digits glued on.

A Go string value is a ``{ptr, len}`` header, and its exact length is visible in two places
without pclntab or type metadata:

1. **static headers** in the data sections (a constant converted to an interface, a global
   string, a string slice / map literal): a pointer-sized word holding the literal's virtual
   address, followed by a pointer-sized length. Little-endian ELF / PE / Mach-O, 32 or 64 bit.
2. **register arguments** on amd64 (ABIInternal passes a string in two consecutive integer
   registers ``RAX,RBX,RCX,RDI,RSI,R8..R11``): ``LEA reg, [rip+rel32]`` followed within a few
   instructions by ``MOV next_reg32, imm32`` with the length.

A candidate is kept only when ``ptr..ptr+len`` lies in one mapped file range and decodes as
printable UTF-8 (tab/newline allowed). A static header's length wins: a LEA/MOV pair is only
used for an address no header names. ``go_strings`` returns the literals; ``clip_overruns``
replaces an IOC that runs past a literal's end by the literal's own IOC.

Everything is bounded: the scanned bytes (``MAX_SCAN_BYTES``), the literal length
(``MAX_GO_STRING``), the number of literals (``limit``) and the wall clock (``deadline``).
Big-endian Go targets get no recovery (the IOCs keep their old boundaries).
"""

from __future__ import annotations

import mmap
import os
import re
import struct
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar

from blastbox.engines.rea.iocs import extract_iocs

__all__ = ["GO_MAGIC", "clip_overruns", "exact_iocs", "go_strings", "is_go"]

GO_MAGIC = b"\xff Go buildinf:"  # .go.buildinfo, every Go >= 1.13 binary
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_GO_STRING = 4096
DEFAULT_LIMIT = 200_000
LEA_WINDOW = 24  # bytes after the LEA searched for the paired length MOV

# ModRM reg field (with REX.R) of `LEA r64, [rip+rel32]` -> the opcode bytes of `MOV r32, imm32`
# into the next ABIInternal integer register (Go's string = two consecutive argument registers).
# RAX=0 RCX=1 RBX=3 RSI=6 RDI=7 R8..R11=8..11; order RAX RBX RCX RDI RSI R8 R9 R10 R11.
_ABI_NEXT_MOV: dict[int, bytes] = {
    0: b"\xbb",       # RAX -> MOV EBX
    3: b"\xb9",       # RBX -> MOV ECX
    1: b"\xbf",       # RCX -> MOV EDI
    7: b"\xbe",       # RDI -> MOV ESI
    6: b"\x41\xb8",   # RSI -> MOV R8D
    8: b"\x41\xb9",   # R8  -> MOV R9D
    9: b"\x41\xba",   # R9  -> MOV R10D
    10: b"\x41\xbb",  # R10 -> MOV R11D
}
_LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
_PRINTABLE_EXTRA = frozenset("\t\n\r")

_Range = tuple[int, int, int, bool]  # (file offset, virtual address, size, executable)


def is_go(data: Any) -> bool:
    """A Go binary: the build-info magic occurs in it."""
    return bool(data.find(GO_MAGIC) != -1)


def _elf_ranges(d: Any) -> tuple[list[_Range], int, str] | None:
    if d[:4] != b"\x7fELF" or d[5:6] != b"\x01":  # little-endian only
        return None
    cls, machine = d[4], struct.unpack_from("<H", d, 18)[0]
    out: list[_Range] = []
    if cls == 2:
        phoff, = struct.unpack_from("<Q", d, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
        fmt, ps = "<IIQQQQQQ", 8
    elif cls == 1:
        phoff, = struct.unpack_from("<I", d, 0x1C)
        phentsize, phnum = struct.unpack_from("<HH", d, 0x2A)
        fmt, ps = "<IIIIIIII", 4
    else:
        return None
    for k in range(min(phnum, 256)):
        at = phoff + k * phentsize
        if at + struct.calcsize(fmt) > len(d):
            break
        row = struct.unpack_from(fmt, d, at)
        if cls == 2:
            p_type, flags, off, va, _pa, filesz = row[:6]
        else:
            p_type, off, va, _pa, filesz, _memsz, flags = row[:7]
        if p_type == 1 and filesz:  # PT_LOAD
            out.append((off, va, filesz, bool(flags & 1)))
    return out, ps, "amd64" if machine == 62 else "other"


def _pe_ranges(d: Any) -> tuple[list[_Range], int, str] | None:
    if d[:2] != b"MZ" or len(d) < 0x40:
        return None
    pe, = struct.unpack_from("<I", d, 0x3C)
    if d[pe:pe + 4] != b"PE\x00\x00":
        return None
    machine, nsec = struct.unpack_from("<HH", d, pe + 4)
    opt_size, = struct.unpack_from("<H", d, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", d, opt)
    if magic == 0x20B:
        base, ps = struct.unpack_from("<Q", d, opt + 24)[0], 8
    elif magic == 0x10B:
        base, ps = struct.unpack_from("<I", d, opt + 28)[0], 4
    else:
        return None
    out: list[_Range] = []
    sec = opt + opt_size
    for k in range(min(nsec, 96)):
        at = sec + 40 * k
        if at + 40 > len(d):
            break
        _vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", d, at + 8)
        chars, = struct.unpack_from("<I", d, at + 36)
        if rawsize:
            out.append((rawptr, base + rva, rawsize, bool(chars & 0x20000000)))
    return out, ps, "amd64" if machine == 0x8664 else "other"


def _macho_ranges(d: Any) -> tuple[list[_Range], int, str] | None:
    if d[:4] != b"\xcf\xfa\xed\xfe":  # 64-bit little-endian only
        return None
    cputype, = struct.unpack_from("<I", d, 4)
    ncmds, = struct.unpack_from("<I", d, 16)
    at, out = 32, []
    for _ in range(min(ncmds, 512)):
        if at + 8 > len(d):
            break
        cmd, size = struct.unpack_from("<II", d, at)
        if cmd == 0x19 and at + 72 <= len(d):  # LC_SEGMENT_64
            vmaddr, _vmsize, fileoff, filesize, _maxprot, initprot = struct.unpack_from("<QQQQII", d, at + 24)
            if filesize:
                out.append((fileoff, vmaddr, filesize, bool(initprot & 4)))
        if size < 8:
            break
        at += size
    return out, 8, "amd64" if cputype == 0x01000007 else "other"


def _layout(d: Any) -> tuple[list[_Range], int, str] | None:
    try:
        for parse in (_elf_ranges, _pe_ranges, _macho_ranges):
            got = parse(d)
            if got is not None:
                ranges = [r for r in got[0] if r[0] < len(d)]
                ranges = [(o, v, min(n, len(d) - o), x) for o, v, n, x in ranges]
                return (ranges, got[1], got[2]) if ranges else None
    except struct.error:
        return None
    return None


def _text_at(d: Any, ranges: list[_Range], va: int, length: int) -> tuple[int, str] | None:
    """(file offset, text) of ``length`` bytes at ``va`` when they are printable UTF-8 in one range."""
    if not 0 < length <= MAX_GO_STRING:
        return None
    for off, base, size, _x in ranges:
        if base <= va and va + length <= base + size:
            at = off + (va - base)
            try:
                text = bytes(d[at:at + length]).decode("utf-8")
            except UnicodeDecodeError:
                return None
            if all(c.isprintable() or c in _PRINTABLE_EXTRA for c in text):
                return at, text
            return None
    return None


def _header_regex(ps: int, top: int) -> re.Pattern[bytes]:
    """Aligned ``{ptr, len}`` candidates: ptr has at most ``top`` significant bytes, 0 < len <= 0x10ff."""
    nb = max(1, min(ps, (top.bit_length() + 7) // 8))
    ptr = rb"." * nb + rb"\x00" * (ps - nb)
    length = rb"(?:[\x01-\xff][\x00-\x10]|\x00[\x01-\x10])" + rb"\x00" * (ps - 2)
    return re.compile(rb"(?=(" + ptr + length + rb"))", re.S)


def go_strings(path: Path, *, limit: int = DEFAULT_LIMIT,
               deadline: float | None = None, clock: Callable[[], float] = time.monotonic,
               ) -> list[tuple[int, str]]:
    """``[(virtual address, literal)]`` of the Go string literals whose exact length is known.

    ``[]`` when the file is not a little-endian Go ELF/PE/Mach-O. One literal may appear with
    several lengths (a constant and a compile-time slice of it). Stops at ``limit`` literals or
    when ``clock()`` passes ``deadline``.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return []
    with os.fdopen(fd, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            return []
        with mmap.mmap(f.fileno(), min(size, MAX_SCAN_BYTES), access=mmap.ACCESS_READ) as d:
            if not is_go(d):
                return []
            return _scan(d, limit, deadline, clock)


def _scan(d: Any, limit: int, deadline: float | None, clock: Callable[[], float]) -> list[tuple[int, str]]:
    layout = _layout(d)
    if layout is None:
        return []
    ranges, ps, arch = layout
    seen: set[tuple[int, int]] = set()
    out: list[tuple[int, str]] = []

    def late() -> bool:
        return deadline is not None and clock() >= deadline

    def add(va: int, length: int) -> bool:
        if (va, length) in seen:
            return True
        hit = _text_at(d, ranges, va, length)
        if hit is not None:
            seen.add((va, length))
            out.append((va, hit[1]))
        return len(out) < limit

    unpack = struct.Struct("<QQ" if ps == 8 else "<II").unpack
    top = max(v + n for _o, v, n, _x in ranges)
    rx = _header_regex(ps, top)
    for n, (off, _va, size, execu) in enumerate(ranges):
        if execu:
            continue
        for k, m in enumerate(rx.finditer(d, off, off + size)):
            if k % 4096 == 0 and late():
                return out
            if (m.start() - off) % ps:
                continue
            ptr, length = unpack(m.group(1))
            if length <= MAX_GO_STRING and not add(ptr, length):
                return out
    # A static header's length is authoritative; a LEA/MOV pair only adds literals no header names.
    known = {va for va, _len in seen}
    if arch == "amd64":
        for off, va, size, execu in ranges:
            if not execu:
                continue
            for k, m in enumerate(_LEA_RIP.finditer(d, off, off + size)):
                if k % 4096 == 0 and late():
                    return out
                at = m.start()
                if at + 7 > off + size:
                    break
                reg = ((d[at + 2] >> 3) & 7) | (8 if d[at] == 0x4C else 0)
                mov = _ABI_NEXT_MOV.get(reg)
                if mov is None:
                    continue
                rel, = struct.unpack_from("<i", d, at + 3)
                target = va + (at - off) + 7 + rel
                if target in known:
                    continue
                win = bytes(d[at + 7:min(at + 7 + LEA_WINDOW, off + size)])
                j = win.find(mov)
                if j < 0 or j + len(mov) + 4 > len(win):
                    continue
                if len(mov) == 1 and j > 0 and win[j - 1] == 0x41:
                    continue  # a REX.B prefix turns the one-byte MOV into R8D..R15D
                length, = struct.unpack_from("<I", win, j + len(mov))
                if not add(target, length):
                    return out
    return out


_T = TypeVar("_T")


def clip_overruns(iocs: Iterable[_T], exact: dict[str, set[str]], key: Callable[[_T], tuple[str, str]],
                  replace: Callable[[_T, str], _T]) -> list[_T]:
    """Each IOC that runs past a Go literal replaced by that literal's IOC, duplicates dropped.

    ``exact`` maps an IOC type to the IOC values found in the exact literals. An IOC whose value
    is not itself exact but starts with an exact value of its type (the longest such) was read
    across a literal boundary: it becomes that exact value. Order is kept; the first copy wins.
    """
    out: list[_T] = []
    seen: set[tuple[str, str]] = set()
    for item in iocs:
        typ, value = key(item)
        vals = exact.get(typ)
        if vals and value not in vals:
            best = max((e for e in vals if len(e) < len(value) and value.startswith(e)), key=len, default=None)
            if best is not None:
                item, value = replace(item, best), best
        if (typ, value) in seen:
            continue
        seen.add((typ, value))
        out.append(item)
    return out


def exact_iocs(literals: Iterable[tuple[int, str]], *, limit: int = 4096) -> dict[str, set[str]]:
    """IOC type -> values found in the exact literals (``iocs.extract_iocs``' own rules)."""
    out: dict[str, set[str]] = {}
    for i in extract_iocs(((f"gostring:{va:#x}", text) for va, text in literals), limit=limit):
        out.setdefault(i.type, set()).add(i.value)
    return out
