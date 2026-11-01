"""Cheap static signals that a native sample is not worth a model pass (rea.report/1 ``chain_stop``).

Both checks read only bounded header bytes and section/segment data from the sample; nothing
runs. They are deliberately conservative: a miss costs one wasted model pass, a false hit stops
a chain that could have produced findings.

- :func:`packed` -- UPX section names (``UPX0``/``UPX1``/``UPX2``) on a PE, the ``UPX!`` magic
  in the first 4 KiB of an ELF, or *both* very few Ghidra procedures (``<= FEW_PROCEDURES``) and
  an executable section/segment of at least ``MIN_ENTROPY_BYTES`` with Shannon entropy
  ``>= HIGH_ENTROPY`` bits/byte. Without a procedure count the entropy rule never fires.
- :func:`unsupported_arch` -- 32-bit MIPS ELF below release 2 (``EF_MIPS_ARCH`` MIPS-I..MIPS32,
  i.e. 0..6). REA's Ghidra provider lane refused such a MIPS-I target live with
  ``capability_unavailable`` ("needs 32R2"); R2 and R6 are left alone.
"""

from __future__ import annotations

import math
import os
from collections import Counter
import struct
from pathlib import Path

FEW_PROCEDURES = 16
HIGH_ENTROPY = 7.2
MIN_ENTROPY_BYTES = 4096
MAX_ENTROPY_BYTES = 4 * 1024 * 1024  # the first 4 MiB of a region decide
MAX_SECTIONS = 96
HEAD_BYTES = 64 * 1024

_UPX_SECTIONS = frozenset({b"UPX0", b"UPX1", b"UPX2"})
_SCN_MEM_EXECUTE = 0x20000000
_PF_X = 1
_EM_MIPS = 8
_EF_MIPS_ARCH_SHIFT = 28
_MIPS_PRE_R2 = frozenset(range(0, 7))


def _read(path: Path, offset: int, size: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return b""
    with os.fdopen(fd, "rb") as f:
        try:
            f.seek(offset)
            return f.read(max(0, size))
        except (OSError, ValueError, OverflowError):
            return b""


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _pe_sections(head: bytes) -> list[tuple[bytes, int, int, int]]:
    """``(name, characteristics, raw_offset, raw_size)`` from the PE section table, or []."""
    try:
        if head[:2] != b"MZ":
            return []
        (pe,) = struct.unpack_from("<I", head, 0x3C)
        if head[pe:pe + 4] != b"PE\x00\x00":
            return []
        nsec, opt_size = struct.unpack_from("<H", head, pe + 6)[0], struct.unpack_from("<H", head, pe + 20)[0]
        table = pe + 24 + opt_size
        out = []
        for i in range(min(nsec, MAX_SECTIONS)):
            o = table + 40 * i
            if o + 40 > len(head):
                break
            name = head[o:o + 8].rstrip(b"\x00")
            raw_size, raw_off = struct.unpack_from("<II", head, o + 16)
            (chars,) = struct.unpack_from("<I", head, o + 36)
            out.append((name, chars, raw_off, raw_size))
        return out
    except struct.error:
        return []


def _elf_header(head: bytes) -> tuple[int, str, int, int, int, int] | None:
    """``(class, struct endian, e_machine, e_flags, e_phoff, e_phnum << 16 | e_phentsize)`` or None."""
    if head[:4] != b"\x7fELF" or len(head) < 52:
        return None
    cls, data = head[4], head[5]
    if cls not in (1, 2) or data not in (1, 2):
        return None
    e = "<" if data == 1 else ">"
    try:
        machine = struct.unpack_from(e + "H", head, 18)[0]
        if cls == 1:
            phoff, flags = struct.unpack_from(e + "I", head, 28)[0], struct.unpack_from(e + "I", head, 36)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", head, 42)
        else:
            if len(head) < 64:
                return None
            phoff, flags = struct.unpack_from(e + "Q", head, 32)[0], struct.unpack_from(e + "I", head, 48)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", head, 54)
    except struct.error:
        return None
    return cls, e, machine, flags, phoff, (phnum << 16) | phentsize


def _elf_exec_segments(path: Path, head: bytes) -> list[tuple[int, int]]:
    hdr = _elf_header(head)
    if hdr is None:
        return []
    cls, e, _m, _f, phoff, packed = hdr
    phnum, phentsize = packed >> 16, packed & 0xFFFF
    if phnum == 0 or phentsize < (32 if cls == 1 else 56):
        return []
    table = _read(path, phoff, min(phnum, MAX_SECTIONS) * phentsize)
    out = []
    for i in range(len(table) // phentsize):
        o = i * phentsize
        try:
            if cls == 1:
                ptype, off, _va, _pa, filesz, _memsz, pflags = struct.unpack_from(e + "7I", table, o)
            else:
                ptype, pflags, off, _va, _pa, filesz = struct.unpack_from(e + "II4Q", table, o)
        except struct.error:
            break
        if ptype == 1 and pflags & _PF_X:
            out.append((off, filesz))
    return out


def _high_entropy(path: Path, regions: list[tuple[int, int]]) -> bool:
    for off, size in regions:
        if size < MIN_ENTROPY_BYTES:
            continue
        data = _read(path, off, min(size, MAX_ENTROPY_BYTES))
        if len(data) >= MIN_ENTROPY_BYTES and entropy(data) >= HIGH_ENTROPY:
            return True
    return False


def packed(path: Path, *, function_count: int | None) -> bool:
    """True when the sample looks packed (see the module docstring); never raises."""
    head = _read(path, 0, HEAD_BYTES)
    sections = _pe_sections(head)
    if sections:
        if any(name in _UPX_SECTIONS for name, *_ in sections):
            return True
        regions = [(off, size) for _n, chars, off, size in sections if chars & _SCN_MEM_EXECUTE]
    elif _elf_header(head) is not None:
        if b"UPX!" in head[:4096]:
            return True
        regions = _elf_exec_segments(path, head)
    else:
        return False
    if function_count is None or function_count > FEW_PROCEDURES:
        return False
    return _high_entropy(path, regions)


def unsupported_arch(path: Path) -> bool:
    """True for an architecture REA's Ghidra lane rejects: 32-bit MIPS ELF before release 2."""
    hdr = _elf_header(_read(path, 0, 64))
    if hdr is None:
        return False
    cls, _e, machine, flags, _o, _p = hdr
    return cls == 1 and machine == _EM_MIPS and (flags >> _EF_MIPS_ARCH_SHIFT) & 0xF in _MIPS_PRE_R2
