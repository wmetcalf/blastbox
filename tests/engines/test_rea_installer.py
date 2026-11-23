"""Static installer unwrapping (NSIS via 7-Zip or the in-process carver, Inno Setup via Binary
Refinery) in the REA sweep. Every fixture here is benign and synthetic."""

import hashlib
import json
import os
import shutil
import struct
import time
import zlib
from pathlib import Path

import pytest

from blastbox.engines.rea import inno_unwrap
from blastbox.engines.rea import installer as inst
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import unpack
from blastbox.engines.rea.prompts import Framer
from blastbox.engines.rea.continuation import State
from blastbox.engines.rea.runner import rea_env, watched_run
from tests.engines.test_rea_sweep import (  # noqa: F401  (_workdir is an autouse fixture)
    FIXTURES,
    FakeGhidra,
    FakeUnpack,
    _by_id,
    _codes,
    _fields,
    _run,
    _workdir,
    factory,
)
from tests.engines.test_rea_triage import X, make_pe

NSIS = FIXTURES / "installer.exe"
SAMPLE = FIXTURES / "sample.exe"
HELPER = SAMPLE.read_bytes() + b"\x00" * 262144  # installer.nsi: helper.dll, the largest PE member


NOISE = b"".join(hashlib.sha256(bytes([i, j])).digest() for i in range(16) for j in range(256))  # 128 KiB


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _pe(path: Path, *, dll=False, signed=False, export="", imports=(), pad=0) -> bytes:
    """A minimal PE with an export-directory name, an import table and/or a certificate table."""
    sec = bytearray(0x400 + pad)
    dirs: dict[int, tuple[int, int]] = {}
    if export:
        struct.pack_into("<I", sec, 12, 0x1040)
        sec[0x40:0x40 + len(export)] = export.encode()
        dirs[0] = (0x1000, 40)
    for i, name in enumerate(imports):
        sec[0x200 + 32 * i:0x200 + 32 * i + len(name)] = name.encode()
        struct.pack_into("<I", sec, 0x80 + 20 * i + 12, 0x1200 + 32 * i)
    if imports:
        dirs[1] = (0x1080, 20 * (len(imports) + 1))
    data = bytearray(make_pe(path, [(b".text", X, bytes(sec))]).read_bytes())
    if signed:
        dirs[4] = (len(data), 8)
        data += b"\x08\x00\x00\x00\x00\x02\x02\x00"
    if dll:
        struct.pack_into("<H", data, 0x40 + 22, 0x2102)
    for i, (rva, size) in dirs.items():
        struct.pack_into("<II", data, 0x40 + 24 + 96 + 8 * i, rva, size)
    path.write_bytes(bytes(data))
    return bytes(data)


def _altered(tmp_path: Path) -> Path:
    """The NSIS fixture with its 16 signature bytes overwritten (7-Zip no longer opens it). The
    fixture's stub has no exehead manifest, so one is appended for detection, as real stubs have."""
    data = bytearray(NSIS.read_bytes())
    at = data.find(inst._NSIS_SIG)
    data[at:at + 16] = bytes(range(0x41, 0x51))
    p = tmp_path / "altered.exe"
    p.write_bytes(bytes(data) + b'<assemblyIdentity name="Nullsoft.NSIS.exehead"/>')
    return p


def _nonsolid(path: Path, items: list[tuple[bytes, bool]], strings=(), magic=b"NullsoftInst",
              siginfo=0xDEADBEEF) -> Path:
    """A non-solid NSIS-format archive behind a PE stub: a deflated header block (string table
    only), then one ``(data, compressed)`` block per item."""
    stub = make_pe(path.with_suffix(".stub"), [(b".text", X, b"\x90" * 512)]).read_bytes()
    stub += b"\x00" * ((-len(stub)) % 512)
    header = bytearray(4 + 8 * 8)
    struct.pack_into("<II", header, 4 + 8 * 3, len(header), 0)
    header += b"".join(t.encode() + b"\x00" for t in ("Name", *strings))
    struct.pack_into("<II", header, 4 + 8 * 4, len(header), 0)
    header += b"\x00" * 16

    def block(data: bytes, compressed: bool) -> bytes:
        if not compressed:
            return struct.pack("<I", len(data)) + data
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        z = c.compress(data) + c.flush()
        return struct.pack("<I", len(z) | 0x80000000) + z

    body = block(bytes(header), True) + b"".join(block(d, c) for d, c in items)
    first = struct.pack("<II12sII", 0, siginfo, magic, len(header), 28 + len(body))
    path.write_bytes(stub + first + body)
    return path


# ------------------------------------------------------------------ detection


def test_nsis_fixture_is_detected_and_plain_pes_are_not(tmp_path):
    assert inst.detect(NSIS) == "nsis"
    assert inst.detect(SAMPLE) is None
    assert inst.detect(FIXTURES / "sample.elf") is None
    assert inst.detect(tmp_path / "missing.exe") is None


def test_nsis_signature_in_the_overlay_of_any_pe_is_nsis(tmp_path):
    p = tmp_path / "n.exe"
    body = make_pe(tmp_path / "stub.exe", [(b".text", X, b"\x90" * 512)]).read_bytes()
    pad = (-len(body)) % 512
    p.write_bytes(body + b"\x00" * pad + struct.pack("<I", 0) + b"\xef\xbe\xad\xdeNullsoftInst" + b"\x00" * 64)
    assert inst.detect(p) == "nsis"


def test_inno_setup_data_marker_is_inno(tmp_path):
    p = tmp_path / "i.exe"
    body = make_pe(tmp_path / "stub.exe", [(b".text", X, b"\x90" * 512)]).read_bytes()
    p.write_bytes(body + b"rDlPtS02\x87eVx" + b"\x00" * 32 + b"Inno Setup Setup Data (6.0.5) (u)" + b"\x00" * 64)
    assert inst.detect(p) == "inno"


def test_marker_inside_a_non_pe_is_not_an_installer(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 64 + b"\xef\xbe\xad\xdeNullsoftInst" + b"Inno Setup Setup Data (6.0.5)")
    assert inst.detect(p) is None


# ------------------------------------------------------------- NSIS script strings


def test_nsis_strings_render_variables_and_keep_the_exec_line():
    strings = inst.nsis_strings(NSIS)
    assert '"$INSTDIR\\payload.exe" --fixture' in strings
    assert "Software\\LoadoutFixture" in strings
    assert "$INSTDIR\\payload.exe" in strings


def test_nsis_strings_of_a_non_installer_are_empty(tmp_path):
    assert inst.nsis_strings(SAMPLE) == []
    p = tmp_path / "trunc.exe"
    data = NSIS.read_bytes()
    p.write_bytes(data[: data.find(b"NullsoftInst") + 40])  # header promised, body cut off
    assert inst.nsis_strings(p) == []


def test_script_excerpt_is_bounded_and_puts_behaviour_first():
    strings = ["Next >", "Cancel"] + [f"x{i}" * 400 for i in range(1000)] + ['"$INSTDIR\\a.exe" /s',
                                                                              "Software\\Run"]
    out = inst.script_excerpt(strings)
    assert out[:2] == ['"$INSTDIR\\a.exe" /s', "Software\\Run"]
    assert len(out) <= inst.MAX_SCRIPT_STRINGS
    assert sum(len(s) for s in out) <= inst.MAX_SCRIPT_CHARS
    assert all(len(s) <= inst.MAX_STRING_CHARS for s in out)


# ------------------------------------------------------------------ members


def _tree(root: Path, files: dict[str, bytes]) -> Path:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def test_collect_copies_regular_files_and_drops_links_and_oversize(tmp_path):
    root = _tree(tmp_path / "x", {"a/one.exe": SAMPLE.read_bytes(), "two.txt": b"hi", "big.bin": b"z" * 200_000})
    (root / "link").symlink_to(root / "a" / "one.exe")
    os.link(root / "two.txt", root / "hard")
    members, dropped = inst.collect(root, tmp_path / "members", max_members=10, max_member_bytes=100_000)
    assert [m.rel for m in members] == ["a/one.exe"]
    assert members[0].path.read_bytes() == SAMPLE.read_bytes() and members[0].size == SAMPLE.stat().st_size
    assert dict(dropped) == {"big.bin": "too_large", "hard": "not_regular", "link": "not_regular",
                             "two.txt": "not_regular"}
    assert members[0].path.parent == tmp_path / "members" and members[0].path.name == "member-0"


def test_collect_caps_the_member_count(tmp_path):
    root = _tree(tmp_path / "x", {f"f{i:02d}": b"x" for i in range(12)})
    members, dropped = inst.collect(root, tmp_path / "m", max_members=5, max_member_bytes=1 << 20)
    assert len(members) == 5 and sum(1 for _r, why in dropped if why == "member_cap") == 7


def test_choose_payload_prefers_the_pe_the_script_executes_over_the_largest(tmp_path):
    root = _tree(tmp_path / "x", {"payload.exe": SAMPLE.read_bytes(), "helper.dll": HELPER,
                                  "readme.txt": b"r"})
    members, _ = inst.collect(root, tmp_path / "m", max_members=10, max_member_bytes=1 << 26)
    chosen, reason = inst.choose_payload(members, inst.nsis_strings(NSIS))
    assert chosen.rel == "payload.exe" and reason == "script_reference"


def test_choose_payload_falls_back_to_the_largest_pe_outside_pluginsdir(tmp_path):
    root = _tree(tmp_path / "x", {"payload.exe": SAMPLE.read_bytes(), "$PLUGINSDIR/System.dll": HELPER * 2,
                                  "helper.dll": HELPER, "notes.txt": b"n" * 10_000_000})
    members, _ = inst.collect(root, tmp_path / "m", max_members=10, max_member_bytes=1 << 26)
    chosen, reason = inst.choose_payload(members, [])
    assert chosen.rel == "helper.dll" and reason == "largest_pe"


def test_choose_payload_none_without_a_pe(tmp_path):
    root = _tree(tmp_path / "x", {"readme.txt": b"r"})
    members, _ = inst.collect(root, tmp_path / "m", max_members=10, max_member_bytes=1 << 26)
    assert inst.choose_payload(members, ['"$INSTDIR\\readme.txt"']) is None


# ------------------------------------------------------------- the bounded extractor


def test_watched_run_kills_an_extractor_that_writes_too_much(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    argv = ["sh", "-c", 'i=0; while :; do head -c 65536 /dev/zero > "$1/f$i"; i=$((i+1)); done', "sh", str(out)]
    status = watched_run(argv, env={"PATH": os.environ["PATH"]}, cwd=out, timeout_s=20, watch=out,
                         max_bytes=1 << 20, max_files=10_000)
    assert status == "too_large"


def test_watched_run_caps_the_file_count(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    argv = ["sh", "-c", 'i=0; while :; do : > "$1/f$i"; i=$((i+1)); done', "sh", str(out)]
    assert watched_run(argv, env={"PATH": os.environ["PATH"]}, cwd=out, timeout_s=20, watch=out,
                       max_bytes=1 << 30, max_files=50) == "too_large"


def test_watched_run_times_out_and_reports_exit_status(tmp_path):
    env = {"PATH": os.environ["PATH"]}
    assert watched_run(["sleep", "30"], env=env, cwd=tmp_path, timeout_s=0.5, watch=tmp_path,
                       max_bytes=1 << 20, max_files=10) == "timeout"
    assert watched_run(["sh", "-c", "exit 3"], env=env, cwd=tmp_path, timeout_s=5, watch=tmp_path,
                       max_bytes=1 << 20, max_files=10) == "failed"
    assert watched_run(["true"], env=env, cwd=tmp_path, timeout_s=5, watch=tmp_path,
                       max_bytes=1 << 20, max_files=10) == "ok"


def test_extract_argv_is_fixed_per_packer(tmp_path):
    seen = []

    def fake(argv, **kw):
        seen.append(argv)
        return "ok"

    env = rea_env(tmp_path / "e", os.environ)
    for packer in ("nsis", "inno"):
        inst.extract(NSIS, tmp_path / packer, 10, packer=packer, env=env, max_bytes=1 << 20,
                          max_files=10, watch_fn=fake)
    nsis, inno = seen
    # sh -c <script> sh <ulimit blocks> <dest> <sample> [fixed extra args]
    assert nsis[6] == str(NSIS.resolve()) and len(nsis) == 7 and "7z" in nsis[2] and "-tNsis" in nsis[2]
    assert inno[6] == str(NSIS.resolve()) and inno[5] == str((tmp_path / "inno").resolve())
    assert inno[7:] == [inst.DEFAULT_REFINERY_PYTHON, str(Path(inno_unwrap.__file__).resolve()), str(1 << 20),
                        str(inst.INNO_MAX_KB)]
    assert 'exec "$4" -I "$5" "$3" "$2" "$6"' in inno[2] and 'ulimit -v "$7"' in inno[2]
    with pytest.raises(ValueError):
        inst.extract(NSIS, tmp_path / "z", 10, packer="zip", env=env, max_bytes=1, max_files=1,
                          watch_fn=fake)


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_real_7z_extracts_the_nsis_fixture(tmp_path):
    dest = tmp_path / "x"
    status = inst.extract(NSIS, dest, 60, packer="nsis", env=rea_env(tmp_path / "e", os.environ),
                               max_bytes=1 << 26, max_files=100)
    assert status == "ok"
    assert (dest / "payload.exe").read_bytes() == SAMPLE.read_bytes()
    assert (dest / "helper.dll").read_bytes() == HELPER


# ------------------------------------------------------------- the in-process carver


def _failed(argv, **kw):  # an extractor that could not open the archive
    return "failed"


def test_an_altered_signature_is_found_by_structure_and_its_script_still_decodes(tmp_path):
    alt = _altered(tmp_path)
    assert inst.detect(alt) == "nsis"
    assert inst.nsis_signature_altered(alt) and not inst.nsis_signature_altered(NSIS)
    assert not inst.nsis_signature_altered(SAMPLE)
    assert inst.nsis_strings(alt) == inst.nsis_strings(NSIS) != []


def test_extract_falls_back_to_the_carver_when_the_tool_writes_nothing(tmp_path):
    env = rea_env(tmp_path / "e", os.environ)
    dest = tmp_path / "x"
    status = inst.extract(_altered(tmp_path), dest, 60, packer="nsis", env=env, max_bytes=1 << 26, max_files=100,
                          watch_fn=_failed)
    assert status == "partial"
    carved = sorted(p.name for p in (dest / inst.CARVED).iterdir())
    assert carved == ["item-1.bin", "item-2.bin", "item-3.bin"]  # archive order: the File instructions
    assert (dest / inst.CARVED / "item-1.bin").read_bytes() == SAMPLE.read_bytes()
    assert (dest / inst.CARVED / "item-2.bin").read_bytes() == HELPER
    # Nothing to carve (not an archive) stays a failure; an extractor that wrote files is not carved over.
    assert inst.extract(SAMPLE, tmp_path / "y", 60, packer="nsis", env=env, max_bytes=1 << 26, max_files=100,
                        watch_fn=_failed) == "failed"

    def wrote(argv, **kw):
        (tmp_path / "z" / "a.bin").write_bytes(b"a")
        return "failed"

    assert inst.extract(NSIS, tmp_path / "z", 60, packer="nsis", env=env, max_bytes=1 << 26, max_files=100,
                        watch_fn=wrote) == "partial"
    assert not (tmp_path / "z" / inst.CARVED).exists()
    for status in ("timeout", "too_large"):
        assert inst.extract(NSIS, tmp_path / status, 60, packer="nsis", env=env, max_bytes=1 << 26,
                            max_files=100, watch_fn=lambda argv, **kw: status) == status  # noqa: B023
        assert not (tmp_path / status / inst.CARVED).exists()


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_real_7z_refuses_the_altered_fixture_and_the_carver_takes_over(tmp_path):
    dest = tmp_path / "x"
    status = inst.extract(_altered(tmp_path), dest, 60, packer="nsis", env=rea_env(tmp_path / "e", os.environ),
                          max_bytes=1 << 26, max_files=100)
    assert status == "partial" and (dest / inst.CARVED / "item-1.bin").read_bytes() == SAMPLE.read_bytes()


def test_the_solid_carver_stops_at_its_caps_and_keeps_only_whole_items(tmp_path):
    alt = _altered(tmp_path)
    far = time.monotonic() + 60
    one = len(SAMPLE.read_bytes())
    assert inst.nsis_carve(alt, tmp_path / "a", deadline=far, max_bytes=one + 10, max_files=10) == 1
    assert [p.name for p in (tmp_path / "a" / inst.CARVED).iterdir()] == ["item-1.bin"]
    assert inst.nsis_carve(alt, tmp_path / "b", deadline=far, max_bytes=1 << 26, max_files=2) == 2
    assert inst.nsis_carve(alt, tmp_path / "c", deadline=time.monotonic() - 1, max_bytes=1 << 26, max_files=10) == 0
    assert list((tmp_path / "c" / inst.CARVED).iterdir()) == []
    assert inst.nsis_carve(SAMPLE, tmp_path / "d", deadline=far, max_bytes=1 << 26, max_files=10) == 0
    cut = tmp_path / "cut.exe"  # the stream ends inside the second item: only the first is whole
    data = alt.read_bytes()
    cut.write_bytes(data[: data.find(bytes(range(0x41, 0x51))) + 24 + 600])
    n = inst.nsis_carve(cut, tmp_path / "e", deadline=far, max_bytes=1 << 26, max_files=10)
    names = sorted(p.name for p in (tmp_path / "e" / inst.CARVED).iterdir()) if n else []
    assert names == [f"item-{i}.bin" for i in range(1, n + 1)] and n < 3


def test_the_non_solid_carver_reads_compressed_and_stored_blocks(tmp_path):
    items = [(SAMPLE.read_bytes(), True), (b"A" * 5000, False), (NOISE, True), (b"", False), (b"tail", False)]
    arc = _nonsolid(tmp_path / "ns.exe", items, strings=("C:\\x\\side.dll",))
    assert inst.nsis_strings(arc) == ["Name", "C:\\x\\side.dll"] and not inst.nsis_signature_altered(arc)
    far = time.monotonic() + 60
    assert inst.nsis_carve(arc, tmp_path / "a", deadline=far, max_bytes=1 << 26, max_files=10) == 4
    got = {p.name: p.read_bytes() for p in (tmp_path / "a" / inst.CARVED).iterdir()}
    assert got == {"item-1.bin": items[0][0], "item-2.bin": items[1][0], "item-3.bin": NOISE, "item-5.bin": b"tail"}
    # Caps: the byte budget ends the carve at the item that would pass it; the count cap likewise.
    assert inst.nsis_carve(arc, tmp_path / "b", deadline=far, max_bytes=len(items[0][0]) + 5000, max_files=10) == 2
    assert inst.nsis_carve(arc, tmp_path / "c", deadline=far, max_bytes=1 << 26, max_files=1) == 1
    assert inst.nsis_carve(arc, tmp_path / "d", deadline=time.monotonic() - 1, max_bytes=1 << 26, max_files=9) == 0
    # A block that claims more bytes than the archive holds ends the carve; nothing is read past it.
    lying = _nonsolid(tmp_path / "ly.exe", [(b"ok", False)])
    lying.write_bytes(lying.read_bytes() + struct.pack("<I", 1 << 20) + b"short")
    assert inst.nsis_carve(lying, tmp_path / "f", deadline=far, max_bytes=1 << 26, max_files=9) == 1
    # The same archive with other signature bytes is still found, and flagged.
    alt = _nonsolid(tmp_path / "alt.exe", items, magic=b"QQQQQQQQQQQQ", siginfo=0x11223344)
    assert inst.nsis_signature_altered(alt)
    assert inst.nsis_carve(alt, tmp_path / "g", deadline=far, max_bytes=1 << 26, max_files=10) == 4


# ------------------------------------------------------------- which member is the payload


def _members(tmp_path: Path, files: dict[str, bytes]) -> list[inst.Member]:
    members, _ = inst.collect(_tree(tmp_path / "x", files), tmp_path / "m", max_members=64,
                              max_member_bytes=1 << 26)
    return members


def test_pe_facts_reads_the_dll_flag_signature_export_name_and_imports(tmp_path):
    _pe(tmp_path / "a.dll", dll=True, signed=True, export="Common.dll", imports=("KERNEL32.dll", "Side.DLL"))
    f = inst._pe_facts(tmp_path / "a.dll")
    assert f == inst._PeFacts(True, True, "Common.dll", frozenset({"kernel32.dll", "side.dll"}))
    _pe(tmp_path / "b.exe")
    assert inst._pe_facts(tmp_path / "b.exe") == inst._PeFacts(False, False, "", frozenset())
    (tmp_path / "junk").write_bytes(b"MZ" + b"\xff" * 300)
    assert inst._pe_facts(tmp_path / "junk") is None and inst._pe_facts(tmp_path / "missing") is None
    wild = bytearray(_pe(tmp_path / "w.dll", dll=True, export="x.dll", imports=("a.dll",)))
    struct.pack_into("<II", wild, 0x40 + 24 + 96, 0xFFFFFF00, 40)  # export directory outside every section
    struct.pack_into("<II", wild, 0x40 + 24 + 96 + 8, 0x7FFFFFFF, 40)
    (tmp_path / "w.dll").write_bytes(bytes(wild))
    assert inst._pe_facts(tmp_path / "w.dll") == inst._PeFacts(True, False, "", frozenset())


def test_a_signed_program_importing_an_unsigned_dll_beside_it_is_side_loading(tmp_path):
    files = {"app/Game.exe": _pe(tmp_path / "g", signed=True, imports=("evil.dll", "MSVCP140.dll"), pad=65536),
             "app/evil.dll": _pe(tmp_path / "e", dll=True, export="common.dll"),
             "app/msvcp140.dll": _pe(tmp_path / "v", dll=True, signed=True, pad=32768),
             "other/evil.dll": _pe(tmp_path / "o", dll=True, pad=4096)}
    members = _members(tmp_path, files)
    chosen, reason = inst.choose_payload(members, [])
    assert (chosen.rel, reason) == ("app/evil.dll", "unsigned_import")
    # The script naming the signed program does not make it the payload either.
    chosen, reason = inst.choose_payload(members, ['"$INSTDIR\\app\\Game.exe" /run'])
    assert (chosen.rel, reason) == ("app/evil.dll", "unsigned_import")
    got = inst.choose("nsis", members, SAMPLE)
    assert got.payload.rel == "app/evil.dll" and got.extra == {"loader_member": "app/Game.exe"}


def test_side_loading_needs_a_signed_program_and_an_unsigned_imported_dll(tmp_path):
    evil = _pe(tmp_path / "e", dll=True)
    cases = {
        "unsigned program": {"Game.exe": _pe(tmp_path / "a", imports=("evil.dll",), pad=8192), "evil.dll": evil},
        "signed dll": {"Game.exe": _pe(tmp_path / "b", signed=True, imports=("evil.dll",), pad=8192),
                       "evil.dll": _pe(tmp_path / "c", dll=True, signed=True)},
        "not imported": {"Game.exe": _pe(tmp_path / "d", signed=True, imports=("user32.dll",), pad=8192),
                         "evil.dll": evil},
        "another directory": {"Game.exe": _pe(tmp_path / "f", signed=True, imports=("evil.dll",), pad=8192),
                              "lib/evil.dll": evil},
    }
    for name, files in cases.items():
        (tmp_path / name).mkdir()
        chosen, reason = inst.choose_payload(_members(tmp_path / name, files), [])
        assert (chosen.rel, reason) == ("Game.exe", "largest_pe"), name


def test_a_program_is_chosen_before_a_larger_library(tmp_path):
    files = {"tool.exe": _pe(tmp_path / "t"), "big.dll": _pe(tmp_path / "b", dll=True, pad=65536)}
    chosen, reason = inst.choose_payload(_members(tmp_path, files), [])
    assert (chosen.rel, reason) == ("tool.exe", "largest_pe")


def test_carved_members_are_told_apart_by_export_name_and_imports(tmp_path):
    # Archive order as an NSIS side-loading dropper has it; carved members have positions, not names.
    items = [(_pe(tmp_path / "s", dll=True, export="System.dll"), True),
             (_pe(tmp_path / "e", dll=True, export="common.dll"), True),
             (_pe(tmp_path / "g", signed=True, imports=("7s9k2f.dll", "MSVCP140.dll"), pad=65536), True),
             (_pe(tmp_path / "v", dll=True, signed=True, export="MSVCP140.dll", pad=32768), True),
             (NOISE, False)]
    strings = ("$PLUGINSDIR\\System.dll", "C:\\app\\7s9k2f.dll", "C:\\app\\Game.exe", "C:\\app\\msvcp140.dll")
    arc = _nonsolid(tmp_path / "alt.exe", items, strings=strings, magic=b"QQQQQQQQQQQQ")
    dest = tmp_path / "tree"
    assert inst.extract(arc, dest, 60, packer="nsis", env=rea_env(tmp_path / "env", os.environ), max_bytes=1 << 26,
                        max_files=100, watch_fn=_failed) == "partial"
    members, _ = inst.collect(dest, tmp_path / "m", max_members=64, max_member_bytes=1 << 26)
    got = inst.choose("nsis", members, arc)
    assert got.payload.rel == "carved/item-2.bin" and got.reason == "unsigned_import"
    assert got.extra["loader_member"] == "carved/item-3.bin" and got.extra["signature"] == "altered"
    assert "C:\\app\\7s9k2f.dll" in got.extra["script_strings"]
    # Every import accounted for by a signed member: the signed program stands.
    items[2] = (_pe(tmp_path / "g2", signed=True, imports=("MSVCP140.dll",), pad=65536), True)
    arc2 = _nonsolid(tmp_path / "plain.exe", items, strings=strings)
    inst.extract(arc2, tmp_path / "tree2", 60, packer="nsis", env=rea_env(tmp_path / "env2", os.environ),
                 max_bytes=1 << 26, max_files=100, watch_fn=_failed)
    members, _ = inst.collect(tmp_path / "tree2", tmp_path / "m2", max_members=64, max_member_bytes=1 << 26)
    got = inst.choose("nsis", members, arc2)
    assert got.payload.rel == "carved/item-3.bin" and got.reason == "largest_pe" and "signature" not in got.extra


def test_stock_plugins_are_never_the_payload_and_the_stub_is_profiled(tmp_path):
    files = {"$PLUGINSDIR/System.dll": _pe(tmp_path / "s", dll=True, export="System.dll", pad=65536),
             "$PLUGINSDIR/nsDialogs.dll": _pe(tmp_path / "n", dll=True),
             "blob.bin": NOISE, "pad.dat": b"\x00" * 200_000, "notes.txt": b"hello"}
    members = _members(tmp_path, files)
    assert inst.choose_payload(members, []) is None
    got = inst.choose("nsis", members, NSIS)
    assert got.payload is None and got.reason == ""
    assert got.extra["member_count"] == 5 and got.extra["plugins"] == ["System.dll", "nsDialogs.dll"]
    assert got.extra["data_members"] == [{"name": "pad.dat", "size": 200_000, "entropy": 0.0},
                                         {"name": "blob.bin", "size": len(NOISE), "entropy": 8.0},
                                         {"name": "notes.txt", "size": 5, "entropy": 1.92}]
    assert "$INSTDIR\\payload.exe" in got.extra["script_strings"]  # the fixture's own script
    many = {f"d{i:02d}.bin": b"x" * (i + 1) for i in range(40)}
    profile = inst.stub_profile(_members(tmp_path / "sub", many), [])
    assert len(profile["data_members"]) == inst.MAX_PROFILE_MEMBERS and "plugins" not in profile


def test_a_dll_the_script_calls_as_a_plugin_is_the_payload_when_there_is_no_program(tmp_path):
    files = {"$PLUGINSDIR/System.dll": _pe(tmp_path / "s", dll=True, pad=65536),
             "$PLUGINSDIR/loader.dll": _pe(tmp_path / "l", dll=True)}
    (tmp_path / "t").mkdir()
    chosen, reason = inst.choose_payload(_members(tmp_path / "t", files), [])
    assert (chosen.rel, reason) == ("$PLUGINSDIR/loader.dll", "plugin_dll")


# ------------------------------------------------------------- Inno Setup


def test_safe_rel_rebuilds_hostile_paths_from_clean_components():
    rel = inno_unwrap.safe_rel
    assert rel("data/{app}/..\\..\\x.exe") == "data/{app}/x.exe"
    assert rel("/etc/passwd") == "etc/passwd" and rel("..\\..\\..") is None and rel("") is None
    assert rel("a/b\x00c\n;$(id)`x`.exe") == "a/b_c__$(id)_x_.exe"
    assert rel("data/ . /.hidden./x") == "data/hidden/x"
    deep = rel("/".join(f"d{i}" for i in range(40)))
    assert deep.count("/") == inno_unwrap.MAX_PARTS - 1 and deep.startswith("d0/") and deep.endswith("/d39")
    assert len(rel("x" * 5000)) == inno_unwrap.MAX_PART_CHARS


def test_unwrap_writes_only_under_outdir_and_never_over_or_through_anything(tmp_path):
    out = tmp_path / "out"
    (out / "data").mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    (out / "data" / "link.exe").symlink_to(victim)
    items = [("data/{app}/a.exe", b"A"), ("data/{app}/a.exe", b"B"), ("embedded/uninstaller.exe", b"U"),
             ("meta/setup.bin", b"S"), ("..\\..\\escape.exe", b"E"), ("data/link.exe", b"L"),
             ("data/{app}/a.exe/under-a-file", b"N"), ("", b"-")]
    assert inno_unwrap.unwrap(items, out) == 4
    got = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file() and not p.is_symlink()}
    assert got == {"data/{app}/a.exe": b"A", "data/{app}/a.exe~1": b"B", "escape.exe": b"E",
                   "data/link.exe~1": b"L"}
    assert victim.read_bytes() == b"keep" and not (tmp_path / "escape.exe").exists()
    assert inno_unwrap.unwrap([(f"f{i}", b"x") for i in range(9)], tmp_path / "n", max_files=3) == 3
    assert inno_unwrap.unwrap([("a", b"x" * 6), ("b", b"x" * 6), ("c", b"x")], tmp_path / "b", max_bytes=10) == 1


def test_inno_unwrap_exit_status_says_whether_members_came_out(tmp_path, monkeypatch):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    def run(members):
        monkeypatch.setattr(inno_unwrap, "_members", members)
        out = tmp_path / f"o{len(list(tmp_path.iterdir()))}"
        return inno_unwrap.main(["inno_unwrap.py", str(sample), str(out), "1000"]), out

    assert run(lambda data: [("data/a.exe", b"A")])[0] == 0
    assert run(lambda data: [])[0] == 1

    def breaks(data):
        yield "data/a.exe", b"A"
        raise ValueError("parser gave up")

    status, out = run(breaks)
    assert status == 2 and (out / "data" / "a.exe").read_bytes() == b"A"

    def broken(data):
        raise ImportError("no refinery")
        yield  # pragma: no cover

    assert run(broken)[0] == 1
    assert inno_unwrap.main(["inno_unwrap.py"]) == 1
    monkeypatch.setattr(inno_unwrap, "MAX_SAMPLE", 1)
    assert run(lambda data: [("a", b"A")])[0] == 1


SCRIPT_PS = """\
external function CreateOleObject(Argument0: String): Variant
external procedure !MAIN()
external function Exec(Argument0: String; Argument1: String): Boolean
external function kernel32.dll:GetTickCount(): Integer
begin function InitializeSetup(): Boolean
  0x0000  PushVar   'WinHttp.WinHttpRequest.5.1'
  0x0010  PushVar   'https://updates.example.invalid/offer'
  0x0020  PushVar   "{commonappdata}\\\\Start Menu\\\\Programs\\\\StartUp\\\\x.lnk"
  0x0030  PushVar   'it\\'s'
end
"""


def test_inno_script_strings_and_imports_come_from_the_header_and_the_code_script(tmp_path):
    setup = {"RunEntries": [{"Name": "{app}\\tool.exe", "Parameters": "/silent", "Flags": 3}],
             "RegistryEntries": [{"Subkey": "Software\\Fixture", "ValueName": "Path"}], "Files": "not-a-list"}
    files = {"meta/setup.json": json.dumps(setup).encode(), "embedded/script.ps": SCRIPT_PS.encode(),
             "embedded/images/big.dll": _pe(tmp_path / "i", dll=True, pad=65536),
             "data/{tmp}/tool.exe": _pe(tmp_path / "t"), "data/{app}/readme.txt": b"r"}
    members = _members(tmp_path, files)
    strings, imports = inst.inno_script(members)
    assert strings[:2] == ["[Run] {app}\\tool.exe /silent", "[Registry] Software\\Fixture Path"]
    assert strings[2:] == ["WinHttp.WinHttpRequest.5.1", "https://updates.example.invalid/offer",
                           "{commonappdata}\\Start Menu\\Programs\\StartUp\\x.lnk", "it's"]
    assert imports == ["CreateOleObject", "Exec", "kernel32.dll:GetTickCount"]
    got = inst.choose("inno", members, SAMPLE)
    assert got.payload.rel == "data/{tmp}/tool.exe" and got.reason == "largest_pe"  # never embedded/*
    assert got.extra["script_imports"] == imports
    assert "https://updates.example.invalid/offer" in got.extra["script_strings"]
    # Damaged or absent metadata is no script, not an error.
    (tmp_path / "bad").mkdir()
    bad = _members(tmp_path / "bad", {"meta/setup.json": b"{" * 100_000, "embedded/script.ps": b"\xff\xfe" * 9})
    assert inst.inno_script(bad) == ([], [])
    got = inst.choose("inno", bad, SAMPLE)
    assert got.payload is None and got.extra == {"member_count": 0}


# ------------------------------------------------------------------ the sweep


class RecordingGhidra(FakeGhidra):
    """FakeGhidra that also keeps each analysed image's name and bytes (the job dir is gone after)."""

    def __call__(self, sample, project_dir, timeout_s, *, env, post_script=None, **kw):
        self.seen = getattr(self, "seen", [])
        self.seen.append((sample.name, sample.read_bytes()))
        return super().__call__(sample, project_dir, timeout_s, env=env, post_script=post_script, **kw)


class FakeInstaller:
    """Stands in for installer_extract: writes ``files`` under dest on "ok"/"partial"."""

    def __init__(self, status="ok", files=None):
        self.status = status
        self.files = files if files is not None else {"payload.exe": SAMPLE.read_bytes(), "helper.dll": HELPER,
                                                      "readme.txt": b"read me"}
        self.calls: list[dict] = []

    def __call__(self, sample, dest, timeout_s, *, packer, env, max_bytes, max_files):
        self.calls.append(dict(sample=sample, dest=dest, packer=packer, max_bytes=max_bytes, max_files=max_files))
        if self.status in ("ok", "partial"):
            _tree(dest, self.files)
        return self.status


def _irun(sample, tmp_path, installer, **kw):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    ghidra = kw.pop("ghidra", None) or RecordingGhidra()
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=ghidra,
                            unpack_fn=kw.pop("unpack", None) or FakeUnpack("failed"),
                            capa_fn=lambda *a, **k: ("ok", b'{"rules": {}}'), installer_fn=installer)
    from blastbox.limits import Limits
    res = eng.detonate(sample, out, Limits(timeout_s=600))
    return res, out, ghidra


def test_nsis_payload_is_extracted_and_analysed_instead_of_the_stub(tmp_path):
    fi = FakeInstaller()
    res, out, g = _irun(NSIS, tmp_path, fi)
    f = _fields(res)
    assert fi.calls[0]["packer"] == "nsis" and fi.calls[0]["sample"] == NSIS
    assert g.seen[0] == ("payload.exe", SAMPLE.read_bytes())
    assert f["unpacked"] == "nsis" and f["unpacked_sha256"] == _sha(SAMPLE.read_bytes())
    assert f["kind"] == "pe" and f["more_pending"] is True and f["members"] == 3
    members = sorted((out / a.path).read_bytes() for a in res.artifacts if a.id.startswith("member-"))
    assert members == sorted([SAMPLE.read_bytes(), HELPER, b"read me"])
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sample_name == "payload.exe"
    ev = state.sweep["unpacked"]
    assert ev["packer"] == "nsis" and ev["packed_sha256"] == _sha(NSIS.read_bytes())
    assert ev["payload_member"] == "payload.exe" and ev["payload_reason"] == "script_reference"
    assert ev["payload_sha256"] == _sha(SAMPLE.read_bytes())
    assert '"$INSTDIR\\payload.exe" --fixture' in ev["script_strings"]
    assert "inner" not in ev


def test_inno_payload_is_the_largest_pe_and_carries_no_script(tmp_path):
    p = tmp_path / "setup.exe"
    p.write_bytes(SAMPLE.read_bytes() + b"Inno Setup Setup Data (6.0.5) (u)")
    fi = FakeInstaller(files={"app/tool.exe": SAMPLE.read_bytes(), "tmp/big.dll": HELPER})
    res, out, g = _irun(p, tmp_path, fi)
    assert fi.calls[0]["packer"] == "inno" and g.seen[0][0] == "big.dll"
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["unpacked"]
    assert ev["packer"] == "inno" and ev["payload_member"] == "tmp/big.dll" and ev["payload_reason"] == "largest_pe"
    assert "script_strings" not in ev and _fields(res)["unpacked"] == "inno"


def test_a_failed_installer_extraction_is_a_warning_and_the_stub_is_analysed(tmp_path):
    for status in ("failed", "timeout", "too_large"):
        fi = FakeInstaller(status)
        (tmp_path / status).mkdir()
        res, _out, g = _irun(NSIS, tmp_path / status, fi)
        f = _fields(res)
        assert "installer_unpack_failed" in _codes(res) and "unpacked" not in f
        assert g.calls[0]["sample"] == NSIS


def test_an_installer_without_a_pe_member_keeps_the_members_and_the_stub(tmp_path):
    fi = FakeInstaller(files={"readme.txt": b"r", "data.bin": b"d"})
    res, out, g = _irun(NSIS, tmp_path, fi)
    assert "installer_no_payload" in _codes(res) and "unpacked" not in _fields(res)
    assert g.calls[0]["sample"] == NSIS and _fields(res)["members"] == 2
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    stub = state.sweep["installer_stub"]
    assert stub["packer"] == "nsis" and stub["member_count"] == 2 and "plugins" not in stub
    assert "unpacked" not in state.sweep and state.sample_name == NSIS.name


def test_a_script_only_installer_is_profiled_and_its_stub_analysed(tmp_path):
    fi = FakeInstaller(files={"$PLUGINSDIR/System.dll": _pe(tmp_path / "s", dll=True, export="System.dll"),
                              "shell.bin": NOISE, "pad.dat": b"\x00" * 300_000})
    res, out, g = _irun(NSIS, tmp_path, fi)
    assert "installer_no_payload" in _codes(res) and "unpacked" not in _fields(res)
    assert g.calls[0]["sample"] == NSIS and len(g.calls) == 1
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    stub = state.sweep["installer_stub"]
    assert stub["plugins"] == ["System.dll"] and stub["member_count"] == 3
    assert stub["data_members"] == [{"name": "pad.dat", "size": 300_000, "entropy": 0.0},
                                    {"name": "shell.bin", "size": len(NOISE), "entropy": 8.0}]
    assert '"$INSTDIR\\payload.exe" --fixture' in stub["script_strings"]


def test_a_side_loaded_dll_is_analysed_instead_of_its_signed_loader(tmp_path):
    evil = _pe(tmp_path / "e", dll=True, export="common.dll")
    fi = FakeInstaller(files={"payload.exe": _pe(tmp_path / "g", signed=True, imports=("evil.dll",), pad=65536),
                              "evil.dll": evil})
    res, out, g = _irun(NSIS, tmp_path, fi)
    assert g.seen[0] == ("evil.dll", evil) and _fields(res)["unpacked_sha256"] == _sha(evil)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["unpacked"]
    assert ev["payload_member"] == "evil.dll" and ev["payload_reason"] == "unsigned_import"
    assert ev["loader_member"] == "payload.exe" and "installer_stub" not in state.sweep


def test_an_altered_signature_is_carved_and_recorded_by_the_sweep(tmp_path):
    def extract(sample, dest, timeout_s, **kw):
        return inst.extract(sample, dest, timeout_s, watch_fn=_failed, **kw)

    res, out, g = _irun(_altered(tmp_path), tmp_path, extract)
    f = _fields(res)
    assert f["unpacked"] == "nsis" and f["members"] == 3 and "installer_partial" in _codes(res)
    assert g.seen[0][1] == HELPER  # no names in a carved tree: the largest program
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["unpacked"]
    assert ev["signature"] == "altered" and ev["payload_member"] == "carved/item-2.bin"
    assert ev["payload_reason"] == "largest_pe" and '"$INSTDIR\\payload.exe" --fixture' in ev["script_strings"]


def test_an_extractor_exception_is_a_warning(tmp_path):
    def boom(*a, **kw):
        raise OSError("no 7z")

    res, _out, g = _irun(NSIS, tmp_path, boom)
    assert "installer_unpack_failed" in _codes(res) and g.calls[0]["sample"] == NSIS


def test_partial_extraction_still_unpacks_with_a_warning(tmp_path):
    res, _out, g = _irun(NSIS, tmp_path, FakeInstaller("partial"))
    assert "installer_partial" in _codes(res) and _fields(res)["unpacked"] == "nsis"
    assert g.seen[0][0] == "payload.exe"


def test_a_upx_packed_payload_is_unpacked_too(tmp_path):
    upx_pe = make_pe(tmp_path / "u.exe", [(b"UPX0", X, b""), (b"UPX1", X, b"\x90" * 4096)]).read_bytes()
    fi = FakeInstaller(files={"payload.exe": upx_pe})
    up = FakeUnpack("ok", SAMPLE.read_bytes())
    res, out, g = _irun(NSIS, tmp_path, fi, unpack=up)
    assert up.calls[0]["sample"].name == "payload.exe" and g.seen[0] == ("payload.exe", SAMPLE.read_bytes())
    assert g.calls[0]["sample"] == up.calls[0]["dest"]
    f = _fields(res)
    assert f["unpacked"] == "nsis" and f["unpacked_sha256"] == _sha(SAMPLE.read_bytes())
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["unpacked"]
    assert ev["inner"] == [{"packer": "upx"}] and ev["payload_sha256"] == _sha(upx_pe)


def test_an_installer_inside_an_installer_is_unwrapped_to_the_depth_cap(tmp_path, monkeypatch):
    inno_pe = SAMPLE.read_bytes() + b"Inno Setup Setup Data (6.0.5) (u)"

    class Nested(FakeInstaller):
        def __call__(self, sample, dest, timeout_s, **kw):
            # every layer yields another Inno installer, then plain code at the cap
            self.files = {"setup.exe": inno_pe} if len(self.calls) < 5 else {"app.exe": SAMPLE.read_bytes()}
            return super().__call__(sample, dest, timeout_s, **kw)

    fi = Nested()
    res, out, _g = _irun(NSIS, tmp_path, fi)
    assert [c["packer"] for c in fi.calls] == ["nsis"] + ["inno"] * (inst.MAX_DEPTH_UNWRAP - 1)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["unpacked"]
    assert ev["packer"] == "nsis" and [i["packer"] for i in ev["inner"]] == ["inno"] * (inst.MAX_DEPTH_UNWRAP - 1)
    ids = [a.id for a in res.artifacts if a.id.startswith("member-")]
    assert len(ids) == len(set(ids)) == inst.MAX_DEPTH_UNWRAP


def test_every_unwrapper_has_a_fixed_script_with_the_three_positional_args():
    for u in inst.UNWRAPPERS:
        assert '"$1"' in u.script and '"$2"' in u.script and '"$3"' in u.script


def test_a_dotnet_payload_switches_the_kind(tmp_path):
    clr = make_pe(tmp_path / "d.exe", [(b".text", X, b"\x00" * 1024)], clr=True).read_bytes()
    fi = FakeInstaller(files={"app.exe": clr})
    res, _out, g = _irun(NSIS, tmp_path, fi)
    assert _fields(res)["kind"] == "dotnet" and g.seen[0][0] == "app.exe"


def test_attacker_member_names_never_reach_the_payload_file_name(tmp_path):
    fi = FakeInstaller(files={"a/..evil;$(x)`name`\n.exe".replace("\n", "_"): SAMPLE.read_bytes()})
    _res, _out, g = _irun(NSIS, tmp_path, fi)
    name = g.seen[0][0]
    assert all(c.isalnum() or c in "._-" for c in name) and not name.startswith(".")


def test_plain_pes_never_call_the_installer_extractor(tmp_path):
    fi = FakeInstaller()
    _irun(SAMPLE, tmp_path, fi)
    assert fi.calls == []


def test_no_artifact_ids_collide_and_members_are_extracted_kind(tmp_path):
    res, _out, _g = _irun(NSIS, tmp_path, FakeInstaller())
    ids = [a.id for a in res.artifacts]
    assert len(ids) == len(set(ids))
    assert all(a.kind == "extracted" for a in res.artifacts if a.id.startswith("member-"))
    assert set(_by_id(res)) >= {"report", "continuation"}


# ------------------------------------------------------------------ the agent prompt


def test_the_agent_is_told_it_is_reading_an_installer_payload():
    st = State(pass_no=0, sample_name="payload.exe", sample_sha256="0" * 64, program_name="payload.exe",
               ghidra_status="ok", sweep={"unpacked": {"packer": "nsis", "packed_sha256": "1" * 64,
                                                       "payload_member": "payload.exe",
                                                       "payload_reason": "script_reference",
                                                       "script_strings": ['"$INSTDIR\\payload.exe"']}})
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "installer" in msg and "script_strings" in msg
    plain = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe",
                  ghidra_status="ok", sweep={"unpacked": {"packer": "upx", "packed_sha256": "1" * 64}})
    assert "installer" not in Framer("n").initial_user_message(plain, 1, todo=[], explored=[])["content"]


def test_the_agent_is_told_about_side_loading_and_an_altered_signature():
    st = State(pass_no=0, sample_name="evil.dll", sample_sha256="0" * 64, program_name="evil.dll",
               ghidra_status="ok", sweep={"unpacked": {"packer": "nsis", "packed_sha256": "1" * 64,
                                                       "payload_member": "carved/item-2.bin",
                                                       "payload_reason": "unsigned_import",
                                                       "loader_member": "carved/item-3.bin",
                                                       "signature": "altered"}})
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "side-loading" in msg and "loader_member" in msg and "signature altered" in msg
    assert "installer_stub" not in msg


def test_the_agent_is_told_a_program_less_installer_is_not_a_standard_installer():
    stub = {"packer": "nsis", "member_count": 15, "plugins": ["System.dll"],
            "data_members": [{"name": "heteroalbumose.ube", "size": 904637, "entropy": 0.16}]}
    st = State(pass_no=0, sample_name="setup.exe", sample_sha256="0" * 64, program_name="setup.exe",
               ghidra_status="ok", sweep={"installer_stub": stub})
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "heteroalbumose.ube" in msg and "shellcode-loader" in msg and "no program of its own" in msg
    assert "do not call the sample a standard installer" in msg
    plain = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe",
                  ghidra_status="ok", sweep={})
    assert "installer_stub" not in Framer("n").initial_user_message(plain, 1, todo=[], explored=[])["content"]


def test_report_prompt_explains_stubs_side_loading_and_altered_signatures():
    msgs = Framer("n").report_messages(pass_no=1, sample_name="p.exe", summary="", functions=[], iocs=[],
                                       sweep={"installer_stub": {"packer": "nsis", "plugins": ["System.dll"]}},
                                       prior_report=None)
    system = msgs[0]["content"]
    for needle in ("sweep.installer_stub", "shellcode-loader", "unsigned_import", "side-loading",
                   'signature "altered"', "script_imports", "at least suspicious"):
        assert needle in system, needle
    assert "System.dll" in "".join(m["content"] for m in msgs[1:])


def test_report_prompt_explains_installer_payloads():
    msgs = Framer("n").report_messages(pass_no=1, sample_name="p.exe", summary="", functions=[], iocs=[],
                                       sweep={"unpacked": {"packer": "inno"}}, prior_report=None)
    assert "installer" in msgs[0]["content"]

