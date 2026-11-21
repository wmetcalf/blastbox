"""Static header repair of PE images rebuilt from process memory (``dumpfix``)."""

from __future__ import annotations

import struct

from blastbox.engines.rea import dumpfix

BASE = 0x698C0000
CODE, IDATA, UDATA = 0x60000020, 0xC0000040, 0xC0000080

# (name, virtual_size, va, raw_size, characteristics); raw data is laid out in order after 0x400.
Section = tuple[bytes, int, int, int, int]


def _pe(sections: list[Section], *, size_of_image: int, pe32plus: bool = False) -> bytes:
    e, optsz = 0x40, 0xF0 if pe32plus else 0xE0
    first = e + 24 + optsz
    hlen = max(0x400, (first + 40 * len(sections) + 0x1FF) & ~0x1FF)
    hdr = bytearray(hlen)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 60, e)
    hdr[e:e + 4] = b"PE\0\0"
    struct.pack_into("<HH", hdr, e + 4, 0x8664 if pe32plus else 0x14C, len(sections))
    struct.pack_into("<H", hdr, e + 20, optsz)
    opt = e + 24
    struct.pack_into("<H", hdr, opt, 0x20B if pe32plus else 0x10B)
    if pe32plus:
        struct.pack_into("<Q", hdr, opt + 24, BASE)
    else:
        struct.pack_into("<I", hdr, opt + 28, BASE)
    struct.pack_into("<II", hdr, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", hdr, opt + 56, size_of_image, hlen)
    body, raw = b"", hlen
    for i, (name, vs, va, rs, chars) in enumerate(sections):
        struct.pack_into("<8sIIII", hdr, first + 40 * i, name, vs, va, rs, raw)
        struct.pack_into("<I", hdr, first + 40 * i + 36, chars)
        body += bytes([0xCC]) * rs
        raw += rs
    return bytes(hdr) + body


def _vsizes(data: bytes) -> list[int]:
    (e,) = struct.unpack_from("<I", data, 60)
    (n,) = struct.unpack_from("<H", data, e + 6)
    (optsz,) = struct.unpack_from("<H", data, e + 20)
    first = e + 24 + optsz
    return [struct.unpack_from("<I", data, first + 40 * i + 8)[0] for i in range(n)]


def test_virtual_size_past_the_image_is_rewritten_to_the_section_span(tmp_path):
    # Live 2026-11-07 (CAPE 25520/25534): every VirtualSize was the section's absolute address.
    src = tmp_path / "dump.dll"
    src.write_bytes(_pe([(b".text", BASE + 0x1000, 0x1000, 0x400, CODE),
                         (b".data", BASE + 0x3000, 0x3000, 0x200, IDATA)], size_of_image=0x5000))
    dest = tmp_path / "out" / "dump.dll"
    fix = dumpfix.repair(src, dest)
    assert fix is not None and fix.repaired == [".text", ".data"] and fix.missing == []
    out = dest.read_bytes()
    assert _vsizes(out) == [0x2000, 0x2000]  # next section's VA, then SizeOfImage
    original = src.read_bytes()
    assert len(out) == len(original)
    assert [i for i, (a, b) in enumerate(zip(out, original)) if a != b] and out[0x400:] == original[0x400:]


def test_a_well_formed_image_is_left_alone(tmp_path):
    src = tmp_path / "ok.exe"
    src.write_bytes(_pe([(b".text", 0x400, 0x1000, 0x400, CODE),
                         (b".bss", 0x8000, 0x2000, 0, UDATA)], size_of_image=0xA000, pe32plus=True))
    dest = tmp_path / "out" / "ok.exe"
    assert dumpfix.repair(src, dest) is None
    assert not dest.exists()


def test_code_or_initialised_data_with_no_bytes_is_reported_missing(tmp_path):
    # Live (CAPE 25483/25524/25525): .rdata/.idata declared but never captured into the dump.
    src = tmp_path / "trunc.exe"
    src.write_bytes(_pe([(b".text", 0x400, 0x1000, 0x400, CODE),
                         (b".rdata", 0xA5000, 0x2000, 0, IDATA),
                         (b".bss", 0x2A000, 0xA7000, 0, UDATA),
                         (b".tls", 0x1000, 0xD1000, 0, IDATA)], size_of_image=0xD2000))
    dest = tmp_path / "out" / "trunc.exe"
    fix = dumpfix.repair(src, dest)
    # .bss is uninitialised by design; a one-page .tls with no bytes is ordinary.
    assert fix is not None and fix.missing == [".rdata"] and fix.repaired == []
    assert not dest.exists()  # nothing to rewrite


def test_raw_data_past_the_end_of_the_file_is_missing(tmp_path):
    data = bytearray(_pe([(b".text", 0x400, 0x1000, 0x400, CODE),
                          (b".data", 0x4000, 0x2000, 0x4000, IDATA)], size_of_image=0x6000))
    src = tmp_path / "cut.exe"
    src.write_bytes(bytes(data[:0x900]))
    fix = dumpfix.repair(src, tmp_path / "out" / "cut.exe")
    assert fix is not None and fix.missing == [".data"]


def test_non_pe_and_garbage_never_raise(tmp_path):
    for i, blob in enumerate([b"", b"MZ", b"\x7fELF" + b"\0" * 60, b"MZ" + b"\xff" * 0x3E + b"\xff\xff\xff\x7f"]):
        p = tmp_path / f"g{i}"
        p.write_bytes(blob)
        assert dumpfix.repair(p, tmp_path / "out" / f"g{i}") is None


def test_an_implausible_size_of_image_disables_the_rewrite(tmp_path):
    src = tmp_path / "huge.dll"
    src.write_bytes(_pe([(b".text", BASE + 0x1000, 0x1000, 0x400, CODE)], size_of_image=0xFFFFF000))
    assert dumpfix.repair(src, tmp_path / "out" / "huge.dll") is None


def test_section_count_is_capped(tmp_path):
    many = [(b".s", 0x1000, 0x1000 * (i + 1), 0, UDATA) for i in range(dumpfix.MAX_SECTIONS + 4)]
    src = tmp_path / "many.exe"
    src.write_bytes(_pe(many, size_of_image=0x1000 * (len(many) + 1)))
    assert dumpfix.repair(src, tmp_path / "out" / "many.exe") is None


def test_source_is_never_modified(tmp_path):
    src = tmp_path / "dump.dll"
    blob = _pe([(b".text", BASE + 0x1000, 0x1000, 0x400, CODE)], size_of_image=0x2000)
    src.write_bytes(blob)
    dumpfix.repair(src, tmp_path / "out" / "dump.dll")
    assert src.read_bytes() == blob


def test_symlinked_source_is_refused(tmp_path):
    real = tmp_path / "real.dll"
    real.write_bytes(_pe([(b".text", BASE + 0x1000, 0x1000, 0x400, CODE)], size_of_image=0x2000))
    link = tmp_path / "link.dll"
    link.symlink_to(real)
    assert dumpfix.repair(link, tmp_path / "out" / "link.dll") is None

