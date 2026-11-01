"""Cheap static signals behind rea.report/1 ``chain_stop`` (packed / unsupported_arch)."""

import os
import struct
from pathlib import Path

from blastbox.engines.rea import triage

FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "fixtures"


def make_pe(path: Path, sections: list[tuple[bytes, int, bytes]], *, clr: bool = False) -> Path:
    """A minimal PE32: (name, characteristics, raw data) per section."""
    n = len(sections)
    pe_off = 0x40
    opt_size = 0xE0
    hdr_end = pe_off + 24 + opt_size + 40 * n
    raw = (hdr_end + 0x1FF) & ~0x1FF
    out = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_off))
    out += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, n, 0, 0, 0, opt_size, 0x102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    if clr:
        struct.pack_into("<II", opt, 96 + 14 * 8, 0x2008, 0x48)  # COM descriptor directory
    out += bytes(opt)
    datas = b""
    for name, chars, data in sections:
        out += name.ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", len(data), 0x1000, len(data),
                                                     raw + len(datas), 0, 0, 0, 0, chars)
        datas += data
    out = out.ljust(raw, b"\x00") + datas
    path.write_bytes(bytes(out))
    return path


def make_elf32(path: Path, *, machine: int, flags: int, segments: list[tuple[int, bytes]] = (),
               big: bool = False) -> Path:
    """A minimal ELF32 (little-endian unless ``big``) with (p_flags, data) PT_LOAD segments."""
    phoff, phnum = 52, len(segments)
    data_off = phoff + 32 * phnum
    e = ">" if big else "<"
    out = bytearray(b"\x7fELF\x01" + (b"\x02" if big else b"\x01") + b"\x01" + b"\x00" * 9)
    out += struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0x400000, phoff if phnum else 0, 0, flags, 52,
                       32, phnum, 40, 0, 0)
    blobs = b""
    for pflags, data in segments:
        out += struct.pack(e + "IIIIIIII", 1, data_off + len(blobs), 0x400000, 0x400000, len(data), len(data),
                           pflags, 0x1000)
        blobs += data
    path.write_bytes(bytes(out) + blobs)
    return path


X = 0x20000020 | 0x40000000  # IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ
CODE = (b"\x55\x8b\xec\x83\xec\x10\x89\x45\xfc\x8b\x45\x08\xc9\xc3" * 600)[:8192]


def test_upx_section_names_are_packed(tmp_path):
    p = make_pe(tmp_path / "upx.exe", [(b"UPX0", X, b""), (b"UPX1", X, CODE), (b".rsrc", 0x40000040, b"r" * 64)])
    assert triage.packed(p, function_count=None) is True
    assert triage.packed(p, function_count=500) is True


def test_benign_fixtures_are_not_packed(tmp_path):
    assert triage.packed(FIXTURES / "sample.exe", function_count=3) is False
    assert triage.packed(FIXTURES / "sample.elf", function_count=3) is False


def test_few_procedures_plus_high_entropy_code_is_packed(tmp_path):
    p = make_pe(tmp_path / "p.exe", [(b".text", X, os.urandom(64 * 1024)), (b".data", 0xC0000040, b"d" * 512)])
    assert triage.packed(p, function_count=5) is True
    # many procedures: real code, whatever the entropy (conservative)
    assert triage.packed(p, function_count=400) is False
    # unknown procedure count: no entropy verdict
    assert triage.packed(p, function_count=None) is False


def test_few_procedures_with_ordinary_code_is_not_packed(tmp_path):
    p = make_pe(tmp_path / "small.exe", [(b".text", X, CODE)])
    assert triage.packed(p, function_count=2) is False


def test_high_entropy_non_executable_section_does_not_count(tmp_path):
    p = make_pe(tmp_path / "rsrc.exe", [(b".text", X, CODE), (b".rsrc", 0x40000040, os.urandom(64 * 1024))])
    assert triage.packed(p, function_count=3) is False


def test_elf_upx_magic_and_entropy(tmp_path):
    upx = make_elf32(tmp_path / "upx.elf", machine=3, flags=0, segments=[(5, b"\x00" * 16 + b"UPX!" + CODE)])
    assert triage.packed(upx, function_count=None) is True
    hi = make_elf32(tmp_path / "hi.elf", machine=62, flags=0, segments=[(5, os.urandom(64 * 1024))])
    assert triage.packed(hi, function_count=5) is True
    ro = make_elf32(tmp_path / "ro.elf", machine=62, flags=0, segments=[(4, os.urandom(64 * 1024))])
    assert triage.packed(ro, function_count=5) is False


def test_truncated_and_garbage_headers_are_not_packed(tmp_path):
    for i, data in enumerate((b"MZ", b"MZ" + b"\xff" * 200, b"\x7fELF\x01\x01", b"\x7fELF" + b"\xff" * 100, b"")):
        p = tmp_path / f"g{i}"
        p.write_bytes(data)
        assert triage.packed(p, function_count=1) is False
        assert triage.unsupported_arch(p) is False


def test_mips_i_to_v_is_unsupported(tmp_path):
    for arch in (0x0, 0x1, 0x4):  # MIPS-I, MIPS-II, MIPS-V
        p = make_elf32(tmp_path / f"m{arch}.elf", machine=8, flags=(arch << 28) | 0x1007)
        assert triage.unsupported_arch(p) is True
    # MIPS32 r1 (the common Mirai 0x50001007) and arch 6 stay analysable until verified live
    for arch in (0x5, 0x6, 0x7, 0x9):  # MIPS32, MIPS64, MIPS32R2, MIPS32R6
        p = make_elf32(tmp_path / f"r{arch}.elf", machine=8, flags=arch << 28)
        assert triage.unsupported_arch(p) is False
    assert triage.unsupported_arch(FIXTURES / "sample.elf") is False
    assert triage.unsupported_arch(FIXTURES / "sample.exe") is False


def test_big_endian_mips(tmp_path):
    p = make_elf32(tmp_path / "be0.elf", machine=8, flags=0x1007, big=True)
    assert triage.unsupported_arch(p) is True
    p = make_elf32(tmp_path / "be5.elf", machine=8, flags=0x50001007, big=True)
    assert triage.unsupported_arch(p) is False


def test_dotnet_is_exempt_from_the_entropy_rule_but_not_upx(tmp_path):
    p = make_pe(tmp_path / "net.exe", [(b".text", X, os.urandom(64 * 1024))], clr=True)
    assert triage.packed(p, function_count=3) is False
    assert triage.packed(p, function_count=3, dotnet=True) is False
    plain = make_pe(tmp_path / "plain.exe", [(b".text", X, os.urandom(64 * 1024))])
    assert triage.packed(plain, function_count=3, dotnet=True) is False
    upx = make_pe(tmp_path / "upxnet.exe", [(b"UPX0", X, b""), (b"UPX1", X, CODE)], clr=True)
    assert triage.packed(upx, function_count=3) is True
