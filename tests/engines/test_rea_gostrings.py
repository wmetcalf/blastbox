"""Exact Go string literals (the packed-string-table IOC boundary bug, live 2026-11-03)."""

import importlib.util
from pathlib import Path

from blastbox.engines.rea import gostrings as gs
from blastbox.engines.rea.iocs import extract_iocs

_spec = importlib.util.spec_from_file_location(
    "rea_go_fixture", Path(__file__).resolve().parent / "fixtures" / "rea" / "go_fixture.py")
assert _spec is not None and _spec.loader is not None
gf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gf)


def _write(tmp_path, data, name="benign_go.elf"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_static_headers_and_abi_register_pairs_give_exact_literals(tmp_path):
    lits = dict(gs.go_strings(_write(tmp_path, gf.go_elf())))
    assert lits[0x4b823d] == gf.URL
    assert lits[0x4b22f5] == gf.IP
    assert lits[0x4b3911] == gf.FORMAT  # LEA RCX + MOV EDI, no static header


def test_iocs_over_the_literals_are_exact(tmp_path):
    lits = gs.go_strings(_write(tmp_path, gf.go_elf()))
    got = {(i.type, i.value) for i in extract_iocs((f"gostring:{va:#x}", t) for va, t in lits)}
    assert ("url", gf.URL) in got and ("ipv4", gf.IP) in got
    assert not any(v.startswith(gf.URL) and v != gf.URL for _t, v in got)


def test_a_printable_run_scan_of_the_same_bytes_overruns():
    # The bug being fixed: the packed bytes alone carry no boundary.
    window = gf.WINDOWS[0x4b823d - 24][24:]  # from the literal start, as Ghidra would define it
    got = [i.value for i in extract_iocs([("ghidra:0x4b823d", window.decode())]) if i.type == "url"]
    assert got and got[0] != gf.URL and got[0].startswith(gf.URL)


def test_not_go_or_no_header_gives_nothing_wrong(tmp_path):
    assert gs.go_strings(_write(tmp_path, gf.go_elf(magic=False))) == []
    lits = dict(gs.go_strings(_write(tmp_path, gf.go_elf(headers=False), "nohdr.elf")))
    assert 0x4b823d not in lits and lits[0x4b3911] == gf.FORMAT
    assert gs.go_strings(_write(tmp_path, b"", "empty")) == []
    assert gs.go_strings(_write(tmp_path, b"\xff Go buildinf:" + b"\x00" * 64, "junk")) == []


def test_header_length_beats_a_conflicting_lea_length(tmp_path):
    import struct
    data = bytearray(gf.go_elf())
    # A LEA RAX,[rip+rel] / MOV EBX, 64 aimed at the URL: 64 bytes would run into the digits.
    at = 0x1000 + 0x100
    rel = 0x4b823d - (0x491000 + 0x100 + 7)
    data[at:at + 12] = b"\x48\x8d\x05" + struct.pack("<i", rel) + b"\xbb" + struct.pack("<I", 64)
    lits = gs.go_strings(_write(tmp_path, bytes(data)))
    assert [t for va, t in lits if va == 0x4b823d] == [gf.URL]


def test_deadline_and_limit_bound_the_scan(tmp_path):
    p = _write(tmp_path, gf.go_elf())
    assert gs.go_strings(p, deadline=0.0, clock=lambda: 1.0) == []
    assert len(gs.go_strings(p, limit=1)) == 1


def test_clip_overruns_replaces_the_live_overrun_by_the_literal():
    exact = {"url": {gf.URL}, "ipv4": {gf.IP}}
    rows = [("url", gf.URL_OVERRUN), ("url", gf.URL + "173472347597680709"), ("url", "http://other.example/x"),
            ("url", gf.URL)]
    out = gs.clip_overruns(rows, exact, key=lambda r: r, replace=lambda r, v: (r[0], v))
    assert out == [("url", gf.URL), ("url", "http://other.example/x")]


def test_clip_overruns_keeps_values_without_an_exact_prefix():
    rows = [("url", gf.URL_OVERRUN)]
    assert gs.clip_overruns(rows, {}, key=lambda r: r, replace=lambda r, v: (r[0], v)) == rows
    assert gs.clip_overruns(rows, {"domain": {"loadout-go-fixture.example.org"}}, key=lambda r: r,
                            replace=lambda r, v: (r[0], v)) == rows
