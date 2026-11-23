"""Static resolution of hashed API imports (``apihash.resolve``)."""

from __future__ import annotations

import struct
import time

from blastbox.engines.rea import apihash

BASE = 0x140000000
TEXT_VA, DATA_VA = 0x1000, 0x2000


def _pe(text: bytes, data: bytes = b"") -> bytes:
    """A minimal PE32+ with an executable .text and a .data section (headers only as parsed)."""
    e = 0x40
    optsz = 0xF0
    first = e + 24 + optsz
    text_off = 0x400
    data_off = text_off + len(text)
    hdr = bytearray(text_off)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 60, e)
    hdr[e:e + 4] = b"PE\0\0"
    struct.pack_into("<HH", hdr, e + 4, 0x8664, 2)
    struct.pack_into("<H", hdr, e + 20, optsz)
    struct.pack_into("<H", hdr, e + 24, 0x20B)
    struct.pack_into("<Q", hdr, e + 48, BASE)
    struct.pack_into("<8sIIII", hdr, first, b".text", len(text), TEXT_VA, len(text), text_off)
    struct.pack_into("<I", hdr, first + 36, 0x60000020)
    struct.pack_into("<8sIIII", hdr, first + 40, b".data", len(data), DATA_VA, len(data), data_off)
    struct.pack_into("<I", hdr, first + 40 + 36, 0xC0000040)
    return bytes(hdr) + text + data


LOADER = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect", "CreateThread"]


def _movs(algo: str, names: list[str]) -> bytes:
    return b"".join(b"\x90\xb9" + struct.pack("<I", apihash.ALGORITHMS[algo](n.encode())) for n in names)


def test_known_hash_algorithms():
    # Reference values: the classic shellcode ROR13 of "LoadLibraryA" and zlib CRC32.
    assert apihash.ALGORITHMS["ror13"](b"LoadLibraryA") == 0xEC0E4E8E
    assert apihash.ALGORITHMS["crc32"](b"LoadLibraryA") == 0x3FC1BD8D
    assert apihash.ALGORITHMS["fnv1a"](b"") == 0x811C9DC5


def test_immediates_in_code_resolve_with_their_sites(tmp_path):
    p = tmp_path / "s.exe"
    p.write_bytes(_pe(_movs("ror13", LOADER)))
    r = apihash.resolve(p, deadline=time.monotonic() + 30)
    assert r is not None and r.algorithm == "ror13"
    apis = {h["api"]: h for h in r.hits}
    assert set(apis) == {f"kernel32!{n}" for n in LOADER}
    # the site is the instruction's VA: 1 nop + (nop, mov) pairs of 6 bytes
    assert apis["kernel32!LoadLibraryA"]["sites"] == [f"{BASE + TEXT_VA + 1:#x}"]


def test_dword_tables_in_data_resolve(tmp_path):
    table = b"".join(struct.pack("<I", apihash.ALGORITHMS["crc32"](n.encode())) for n in LOADER)
    p = tmp_path / "s.exe"
    p.write_bytes(_pe(b"\xc3" * 16, b"\0\0\0\0" + table))
    r = apihash.resolve(p, deadline=time.monotonic() + 30)
    assert r is not None and r.algorithm == "crc32" and len(r.hits) == len(LOADER)


def test_too_few_hits_or_no_pe_is_nothing(tmp_path):
    p = tmp_path / "s.exe"
    p.write_bytes(_pe(_movs("ror13", LOADER[:3])))
    assert apihash.resolve(p, deadline=time.monotonic() + 30) is None
    p.write_bytes(b"\x7fELF" + b"\0" * 200)
    assert apihash.resolve(p, deadline=time.monotonic() + 30) is None
    p.write_bytes(b"MZ" + b"\0" * 10)
    assert apihash.resolve(p, deadline=time.monotonic() + 30) is None


def test_the_deadline_stops_the_scan(tmp_path):
    p = tmp_path / "s.exe"
    p.write_bytes(_pe(_movs("ror13", LOADER)))
    assert apihash.resolve(p, deadline=0.0) is None


def test_the_bar_rises_with_the_candidate_set():
    assert apihash.min_hits(10_000) == apihash.BASE_MIN_HITS + 1
    assert apihash.min_hits(400_000) > apihash.min_hits(10_000)
