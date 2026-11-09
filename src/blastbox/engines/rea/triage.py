"""Cheap static signals that a native sample is not worth a model pass (rea.report/1 ``chain_stop``).

Both checks read only bounded header bytes and section/segment data from the sample; nothing
runs. They are deliberately conservative: a miss costs one wasted model pass, a false hit stops
a chain that could have produced findings.

- :func:`packed` -- UPX section names (``UPX0``/``UPX1``/``UPX2``) on a PE, the ``UPX!`` magic
  in the first 4 KiB of an ELF, or *both* very few Ghidra procedures (``<= FEW_PROCEDURES``) and
  an executable section/segment of at least ``MIN_ENTROPY_BYTES`` with Shannon entropy
  ``>= HIGH_ENTROPY`` bits/byte. Without a procedure count the entropy rule never fires.
- :func:`unsupported_arch` -- 32-bit MIPS ELF at ``EF_MIPS_ARCH`` MIPS I-V (0..4), either byte
  order. REA's Ghidra provider lane refused a MIPS-I target live with ``capability_unavailable``
  ("needs 32R2"); MIPS32 r1 (5), MIPS64 (6), R2 and R6 are left alone until verified live.
- .NET assemblies (``dotnet=True`` or a CLR header) are exempt from the entropy rule: their
  ``.text`` carries compressed resources and Ghidra sees few native procedures.
- :func:`nsis_marked` / :func:`inno_marked` -- a PE that is an NSIS installer (the first-header signature
  ``\xEF\xBE\xAD\xDE NullsoftInst`` or the stub's ``Nullsoft.NSIS`` manifest) or an Inno Setup
  installer (the setup loader's ``rDlPtS`` offset table or the ``Inno Setup Setup Data (``
  header), read from the first ``MAX_INSTALLER_SCAN`` bytes. ``installer.UNWRAPPERS`` uses them
  and the sweep unpacks those installers statically.
"""

from __future__ import annotations

import math
import mmap
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

MAX_INSTALLER_SCAN = 256 * 1024 * 1024
_NSIS_MARKERS = (b"\xef\xbe\xad\xdeNullsoftInst", b"Nullsoft.NSIS")
_INNO_MARKERS = (b"rDlPtS", b"Inno Setup Setup Data (")

_UPX_SECTIONS = frozenset({b"UPX0", b"UPX1", b"UPX2"})
_SCN_MEM_EXECUTE = 0x20000000
_PF_X = 1
_EM_MIPS = 8
_EF_MIPS_ARCH_SHIFT = 28
# MIPS I-V only. MIPS32 r1 (5) and MIPS64 (6) stay analysable until a live run confirms the
# lane rejects them; only a MIPS-I sample was observed.
_MIPS_UNSUPPORTED = frozenset(range(0, 5))


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


def _has_clr_header(head: bytes) -> bool:
    """A PE whose COM descriptor (CLR) data directory is non-empty."""
    try:
        (pe,) = struct.unpack_from("<I", head, 0x3C)
        opt = pe + 24
        (magic,) = struct.unpack_from("<H", head, opt)
        base = {0x10B: 96, 0x20B: 112}.get(magic)
        if base is None:
            return False
        (ndirs,) = struct.unpack_from("<I", head, opt + base - 4)
        if ndirs <= 14:
            return False
        rva, size = struct.unpack_from("<II", head, opt + base + 14 * 8)
        return rva != 0 and size != 0
    except struct.error:
        return False


def upx_marked(path: Path) -> bool:
    """True for a PE with UPX section names or an ELF with the ``UPX!`` magic; never raises."""
    head = _read(path, 0, HEAD_BYTES)
    sections = _pe_sections(head)
    if sections:
        return any(name in _UPX_SECTIONS for name, *_ in sections)
    return _elf_header(head) is not None and b"UPX!" in head[:4096]


def packed(path: Path, *, function_count: int | None, dotnet: bool = False) -> bool:
    """True when the sample looks packed (see the module docstring); never raises."""
    head = _read(path, 0, HEAD_BYTES)
    sections = _pe_sections(head)
    if sections:
        if any(name in _UPX_SECTIONS for name, *_ in sections):
            return True
        if dotnet or _has_clr_header(head):
            return False
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
    """True for an architecture REA's Ghidra lane rejects: 32-bit MIPS ELF at MIPS I-V."""
    hdr = _elf_header(_read(path, 0, 64))
    if hdr is None:
        return False
    cls, _e, machine, flags, _o, _p = hdr
    return cls == 1 and machine == _EM_MIPS and (flags >> _EF_MIPS_ARCH_SHIFT) & 0xF in _MIPS_UNSUPPORTED


def _scan_for(path: Path, markers: tuple[bytes, ...]) -> bool:
    """True when the PE ``path`` holds any of ``markers`` in its first ``MAX_INSTALLER_SCAN`` bytes."""
    if not _pe_sections(_read(path, 0, HEAD_BYTES)):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return False
        with mmap.mmap(fd, min(size, MAX_INSTALLER_SCAN), access=mmap.ACCESS_READ) as m:
            return any(m.find(marker) >= 0 for marker in markers)
    except (OSError, ValueError):
        return False
    finally:
        os.close(fd)


def nsis_marked(path: Path) -> bool:
    """An NSIS installer: the first-header signature or the exehead manifest; never raises."""
    return _scan_for(path, _NSIS_MARKERS)


def inno_marked(path: Path) -> bool:
    """An Inno Setup installer: the setup loader's offset table or the setup-data header."""
    return _scan_for(path, _INNO_MARKERS)
