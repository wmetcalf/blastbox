"""Hashed Windows API imports, resolved statically (the sweep's ``api_hashes``).

Loaders and shellcode hide their imports: they walk the PEB, hash each export name and compare
it with a constant (ROR13 for Metasploit/Cobalt Strike-style reflective loaders, CRC32, FNV-1a,
DJB2 ...). Those constants sit in the code as 32-bit immediates or in data as dword tables.
``resolve`` hashes every name in ``data/winapi_names.txt`` (10.7k exports of 21 core DLLs) with
each algorithm in ``ALGORITHMS`` and matches the PE's candidate values:

- immediates of ``mov r32, imm32`` (B8+r), ``push imm32`` (68), ``cmp/sub/xor/add eax, imm32``
  (3D/2D/35/05) and ``81 /r`` / ``C7 /0`` with an imm32, in executable sections;
- 4-byte-aligned dwords in other sections.

Random values collide with some hash now and then (live: at most 3 per algorithm over 385k
candidates), so an algorithm is reported only with ``min_hits`` distinct APIs, more for a
larger candidate set. Nothing is executed or emulated; a custom seed or algorithm is simply not
found. The result is a lead for the model, not a finding.
"""

from __future__ import annotations

import math
import struct
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

__all__ = ["ALGORITHMS", "ApiHashes", "resolve"]

_M = 0xFFFFFFFF
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_CANDIDATES = 2_000_000
MAX_HITS = 64
MAX_SITES = 3
BASE_MIN_HITS = 4


def _ror13(b: bytes) -> int:
    h = 0
    for c in b:
        h = (((h >> 13) | (h << 19)) + c) & _M
    return h


def _fnv1a(b: bytes) -> int:
    h = 0x811C9DC5
    for c in b:
        h = ((h ^ c) * 0x01000193) & _M
    return h


def _fnv1(b: bytes) -> int:
    h = 0x811C9DC5
    for c in b:
        h = ((h * 0x01000193) & _M) ^ c
    return h


def _djb2(b: bytes) -> int:
    h = 5381
    for c in b:
        h = (h * 33 + c) & _M
    return h


def _djb2_xor(b: bytes) -> int:
    h = 5381
    for c in b:
        h = ((h * 33) ^ c) & _M
    return h


def _sdbm(b: bytes) -> int:
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & _M
    return h


def _jenkins(b: bytes) -> int:
    h = 0
    for c in b:
        h = (h + c) & _M
        h = (h + (h << 10)) & _M
        h ^= h >> 6
    h = (h + (h << 3)) & _M
    h ^= h >> 11
    return (h + (h << 15)) & _M


ALGORITHMS: dict[str, Callable[[bytes], int]] = {
    "ror13": _ror13,
    "ror13_nul": lambda b: _ror13(b + b"\0"),
    "fnv1a": _fnv1a,
    "fnv1a_lower": lambda b: _fnv1a(b.lower()),
    "fnv1": _fnv1,
    "djb2": _djb2,
    "djb2_xor": _djb2_xor,
    "sdbm": _sdbm,
    "crc32": lambda b: zlib.crc32(b) & _M,
    "crc32_lower": lambda b: zlib.crc32(b.lower()) & _M,
    "jenkins": _jenkins,
}


@dataclass
class ApiHashes:
    algorithm: str
    # [{"hash": "0x..", "api": "kernel32!VirtualAlloc", "sites": ["0x<va>", ...]}], in API order
    hits: list[dict[str, object]] = field(default_factory=list)


_TABLE: dict[int, list[tuple[str, str]]] | None = None


def _names() -> list[tuple[str, str]]:
    text = resources.files("blastbox.engines.rea").joinpath("data/winapi_names.txt").read_text()
    out = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            dll, _, name = line.partition(" ")
            if name:
                out.append((dll, name))
    return out


def _table() -> dict[int, list[tuple[str, str]]]:
    global _TABLE
    if _TABLE is None:
        t: dict[int, list[tuple[str, str]]] = {}
        for dll, name in _names():
            b = name.encode()
            for algo, fn in ALGORITHMS.items():
                t.setdefault(fn(b), []).append((algo, f"{dll}!{name}"))
        _TABLE = t
    return _TABLE


def _sections(data: bytes) -> tuple[int, list[tuple[int, int, int, bool]]]:
    """(image base, [(virtual address, file offset, raw size, executable)]) of a PE, or raises."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE")
    e = struct.unpack_from("<I", data, 60)[0]
    if data[e:e + 4] != b"PE\0\0":
        raise ValueError("not a PE")
    nsec, = struct.unpack_from("<H", data, e + 6)
    optsz, = struct.unpack_from("<H", data, e + 20)
    magic, = struct.unpack_from("<H", data, e + 24)
    base = struct.unpack_from("<Q", data, e + 48)[0] if magic == 0x20B else struct.unpack_from("<I", data, e + 52)[0]
    out = []
    first = e + 24 + optsz
    for i in range(min(nsec, 96)):
        _n, _vsz, va, rsz, roff = struct.unpack_from("<8sIIII", data, first + 40 * i)
        chars, = struct.unpack_from("<I", data, first + 40 * i + 36)
        if roff < len(data) and rsz:
            out.append((va, roff, min(rsz, len(data) - roff), bool(chars & 0x20000000)))
    return base, out


def _candidates(data: bytes, deadline: float, clock: Callable[[], float]) -> dict[int, list[int]] | None:
    """Candidate value -> VAs it occurs at (at most MAX_SITES each), or None past the deadline."""
    base, secs = _sections(data)
    vals: dict[int, list[int]] = {}

    def add(v: int, va: int) -> None:
        if v and len(vals) < MAX_CANDIDATES:
            sites = vals.setdefault(v, [])
            if len(sites) < MAX_SITES:
                sites.append(va)

    for va, off, size, exe in secs:
        body = data[off:off + size]
        if exe:
            for i in range(len(body) - 4):  # an imm32 at i+1 ends at i+5
                if not i & 0xFFFF and clock() > deadline:
                    return None
                op = body[i]
                if 0xB8 <= op <= 0xBF or op in (0x68, 0x3D, 0x2D, 0x35, 0x05):
                    add(struct.unpack_from("<I", body, i + 1)[0], base + va + i)
                elif op in (0x81, 0xC7) and i + 6 <= len(body):
                    add(struct.unpack_from("<I", body, i + 2)[0], base + va + i)
        else:
            for i in range(0, len(body) - 3, 4):
                add(struct.unpack_from("<I", body, i)[0], base + va + i)
        if clock() > deadline:
            return None
    return vals


def min_hits(candidates: int) -> int:
    """APIs an algorithm needs to count: random collisions grow with the candidate set."""
    expected = candidates * len(_table()) / 2 ** 32 / max(1, len(ALGORITHMS))
    return BASE_MIN_HITS + math.ceil(3 * expected)


def resolve(sample: Path, *, deadline: float, clock: Callable[[], float] = time.monotonic) -> ApiHashes | None:
    """The best-supported hashing algorithm and its API hits, or None (no PE, nothing, deadline)."""
    if sample.stat().st_size > MAX_INPUT_BYTES:
        return None
    data = sample.read_bytes()
    try:
        vals = _candidates(data, deadline, clock)
    except (ValueError, struct.error):
        return None
    if vals is None:
        return None
    table = _table()
    by: dict[str, dict[str, tuple[int, list[int]]]] = {}
    for v, sites in vals.items():
        for algo, api in table.get(v, ()):
            by.setdefault(algo, {}).setdefault(api, (v, sites))
    need = min_hits(len(vals))
    best = max(by.items(), key=lambda kv: len(kv[1]), default=None)
    if best is None or len(best[1]) < need:
        return None
    algo, apis = best
    hits: list[dict[str, object]] = [{"hash": f"{v:#010x}", "api": api, "sites": [f"{s:#x}" for s in sites]}
                                     for api, (v, sites) in sorted(apis.items())[:MAX_HITS]]
    return ApiHashes(algorithm=algo, hits=hits)
