"""Emulated unpacking of native loaders: trigger, carving, evidence, payload choice, sweep, bar."""

import hashlib
import json
import os
import signal
import struct
import sys
import time
from pathlib import Path

import pefile
import pytest

from blastbox.engines.rea import emulate, emulate_runner, sufficiency
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import State, unpack
from blastbox.engines.rea.prompts import Framer
from blastbox.engines.rea.runner import rea_env, run_emulation
from blastbox.limits import Limits
from tests.engines.test_rea_sweep import (  # noqa: F401  (_workdir is an autouse fixture)
    FIXTURES,
    FakeGhidra,
    FakeUnpack,
    _codes,
    _fields,
    _iocs,
    _workdir,
    factory,
)

SAMPLE_PATH = FIXTURES / "sample.exe"
SAMPLE = SAMPLE_PATH.read_bytes()
SAMPLE_SHA = hashlib.sha256(SAMPLE).hexdigest()
UNPACK = FIXTURES / "unpack.exe"
SHELLCODE = b"\x90" * 48 + b"\xb8\x2a\x00\x00\x00\xc3"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mapped(data: bytes) -> bytes:
    """``data`` (a PE file) as a loader maps it: headers, then each section at its RVA."""
    pe = pefile.PE(data=data)
    img = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    img[:pe.OPTIONAL_HEADER.SizeOfHeaders] = data[:pe.OPTIONAL_HEADER.SizeOfHeaders]
    for s in pe.sections:
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        img[s.VirtualAddress:s.VirtualAddress + len(raw)] = raw
    return bytes(img)


def patched(tmp_path: Path, name: str, edit) -> Path:
    pe = pefile.PE(data=SAMPLE)
    edit(pe)
    p = tmp_path / name
    p.write_bytes(pe.write())
    return p


# ------------------------------------------------------------------- trigger

def test_only_native_x86_x64_pes_are_emulatable(tmp_path):
    assert emulate.emulatable(UNPACK) == "amd64"
    assert emulate.emulatable(FIXTURES / "peb.exe") == "amd64"
    assert emulate.emulatable(FIXTURES / "installer.exe") == "x86"
    assert emulate.emulatable(FIXTURES / "sample.elf") is None
    assert emulate.emulatable(FIXTURES / "dotnet.dll") is None
    arm = patched(tmp_path, "arm.exe", lambda pe: setattr(pe.FILE_HEADER, "Machine", 0xAA64))
    assert emulate.emulatable(arm) is None


def test_the_loader_fixtures_trigger_and_a_plain_program_does_not(tmp_path):
    assert {"high_entropy_section", "few_imports"} <= set(emulate.triggers(UNPACK))
    assert {"high_entropy_section", "few_imports"} <= set(emulate.triggers(FIXTURES / "unpack.dll"))
    assert "few_imports" in emulate.triggers(FIXTURES / "peb.exe")
    # mingw's CRT registers TLS callbacks: that alone is a (loose) signal...
    assert emulate.triggers(SAMPLE_PATH) == ["tls_callbacks"]
    # ...and without them the plain program has none.
    no_tls = patched(tmp_path, "notls.exe", lambda pe: setattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9], "VirtualAddress", 0))
    assert emulate.triggers(no_tls) == []
    assert emulate.triggers(FIXTURES / "sample.elf") == []


def test_trigger_signals_from_headers(tmp_path):
    def wx(pe):
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = 0
        pe.sections[0].Characteristics |= 0x80000000

    assert emulate.triggers(patched(tmp_path, "wx.exe", wx)) == ["wx_section"]

    def entry(pe):
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = 0
        data = next(s for s in pe.sections if s.Name.startswith(b".data"))
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = data.VirtualAddress + 16

    assert emulate.triggers(patched(tmp_path, "entry.exe", entry)) == ["entry_outside_code"]
    no_tls = patched(tmp_path, "n.exe", lambda pe: setattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9], "VirtualAddress", 0))
    assert emulate.triggers(no_tls, api_hashes=5, upx_failed=True) == ["api_hashes", "upx_unpack_failed"]


def test_loader_only_imports_trigger(monkeypatch):
    monkeypatch.setattr(emulate, "_imports_and_tls", lambda p: (["loadlibrarya", "getprocaddress"], 0))
    assert {"few_imports", "loader_imports_only"} <= set(emulate.triggers(SAMPLE_PATH))
    monkeypatch.setattr(emulate, "_imports_and_tls", lambda p: (None, 0))  # an unparsable table
    assert "few_imports" in emulate.triggers(SAMPLE_PATH)


def test_imports_mark_ordinal_imports_by_dll():
    names = emulate.imports(SAMPLE_PATH)
    assert names is not None and "createmutexa" not in names and "strlen" in names
    assert emulate.imports(FIXTURES / "peb.exe") == []


# ------------------------------------------------------------------- carving

def test_a_file_copy_is_carved_byte_exact():
    region = SAMPLE + b"\x00" * (0x13000 - len(SAMPLE))
    c = emulate.carve(region, 0, 0x50000, alloc_size=len(SAMPLE))
    assert c is not None and c.layout == "file" and c.data == SAMPLE and not c.dll
    # Without the allocation size, trailing zeros past the last section are not kept.
    loose = emulate.carve(region, 0, 0x50000)
    assert loose is not None and SAMPLE.rstrip(b"\x00") == loose.data.rstrip(b"\x00") and SAMPLE.startswith(loose.data)


def test_a_mapped_image_is_realigned_to_its_rvas_and_base():
    img = mapped(SAMPLE)
    c = emulate.carve(img + b"\x00" * 0x1000, 0, 0x74000)
    assert c is not None and c.layout == "memory" and len(c.data) == len(img)
    pe, orig = pefile.PE(data=c.data), pefile.PE(data=SAMPLE)
    assert pe.OPTIONAL_HEADER.ImageBase == 0x74000
    for s, o in zip(pe.sections, orig.sections):
        n = min(o.Misc_VirtualSize, o.SizeOfRawData)
        assert s.PointerToRawData == s.VirtualAddress == o.VirtualAddress and s.SizeOfRawData % 0x200 == 0
        assert c.data[s.VirtualAddress:s.VirtualAddress + n] == SAMPLE[o.PointerToRawData:o.PointerToRawData + n]


def test_pes_are_found_at_page_offsets_and_bad_headers_are_refused():
    region = b"\xcc" * 0x2000 + SAMPLE
    assert emulate.pe_offsets(region) == [0x2000]
    c = emulate.carve(region, 0x2000, 0x10000)
    assert c is not None and c.data.rstrip(b"\x00") == SAMPLE.rstrip(b"\x00")
    assert emulate.carve(b"MZ" + b"\x00" * 0x3E + b"\xff\xff\x00\x00", 0, 0) is None  # e_lfanew out of range
    assert emulate.carve(SAMPLE[:0x400].replace(b"PE\x00\x00", b"XX\x00\x00", 1), 0, 0) is None
    assert emulate.carve(SAMPLE[:0x2000], 0, 0) is None  # a file copy cut short
    assert emulate.pe_offsets(b"MZ" + b"\x00" * 0x2000) == []


# ------------------------------------------------------------------- evidence

def _write_regions(d: Path, blobs: dict[str, bytes]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for name, data in blobs.items():
        (d / name).write_bytes(data)


def _region(file, base, size, *, prot="rw-", executed=False, asked=False, source="alloc", alloc=None,
            tag=None):
    return {"file": file, "tag": tag or f"api.VirtualAlloc.{base:#x}", "base": base, "size": size, "prot": prot,
            "executed": executed, "exec_requested": asked, "source": source, "alloc_size": alloc}


def loader_doc() -> tuple[dict, dict[str, bytes]]:
    """What the runner reports for unpack.exe (recorded from a real Speakeasy run), with its regions."""
    img = mapped(SAMPLE)
    blobs = {"region-0.bin": SAMPLE + b"\x00" * (0x13000 - len(SAMPLE)), "region-1.bin": img,
             "region-2.bin": SHELLCODE + b"\x00" * (0x1000 - len(SHELLCODE))}
    doc = {
        "arch": "x64", "dll": False,
        "entry_points": [{"type": "module_entry", "error": None}],
        "apis_total": 11,
        "apis": [
            {"n": "kernel32.CreateMutexA", "a": [["ptr", "0x0"], ["bool", "FALSE"], ["str", "Local\\LoadoutFixtureMutex"]]},
            {"n": "kernel32.VirtualAlloc", "a": [["ptr", "0x0"], ["ptr", "0x125b1"], ["flags", "MEM_RESERVE|MEM_COMMIT"],
                                                 ["flags", "PAGE_READWRITE"]]},
            {"n": "kernel32.VirtualAlloc", "a": [["ptr", "0x0"], ["ptr", "0x12000"], ["flags", "MEM_RESERVE|MEM_COMMIT"],
                                                 ["flags", "PAGE_READWRITE"]]},
            {"n": "kernel32.VirtualProtect", "a": [["ptr", "0x74000"], ["ptr", "0x12000"],
                                                   ["flags", "PAGE_EXECUTE_READ"], ["ptr", "0x13fff1c"]]},
            {"n": "kernel32.VirtualAlloc", "a": [["ptr", "0x0"], ["ptr", "0x1000"], ["flags", "MEM_RESERVE|MEM_COMMIT"],
                                                 ["flags", "PAGE_READWRITE"]]},
            {"n": "kernel32.VirtualProtect", "a": [["ptr", "0x441000"], ["ptr", "0x1000"],
                                                   ["flags", "PAGE_EXECUTE_READ"], ["ptr", "0x13fff1c"]]},
            {"n": "wininet.InternetOpenA", "a": [["str", "LoadoutFixture/1.0"], ["int", "0x1"]]},
            {"n": "wininet.InternetOpenUrlA", "a": [["ptr", "0x20"], ["str", "http://stage.loadout.example/next.bin"],
                                                    ["text", "INTERNET_FLAG_RELOAD"]]},
            {"n": "wininet.InternetCloseHandle", "a": [["ptr", "0x28"]]},
            {"n": "wininet.InternetCloseHandle", "a": [["ptr", "0x20"]]},
            {"n": "kernel32.ExitProcess", "a": [["int", "0x2a"]]},
        ],
        "events": [{"event": "mem_alloc", "base": "0x50000", "size": "0x125b1"},
                   {"event": "net_http", "server": "stage.loadout.example", "port": "80", "proto": "tcp.http"}],
        "dynamic_code": [{"tag": "api.VirtualAlloc.0x441000", "base": "0x441000", "size": "0x1000"}],
        "regions": [_region("region-0.bin", 0x50000, 0x13000, alloc=len(SAMPLE)),
                    _region("region-1.bin", 0x74000, 0x12000, prot="PAGE_EXECUTE_READ", asked=True),
                    _region("region-2.bin", 0x441000, 0x1000, prot="PAGE_EXECUTE_READ", asked=True, executed=True)],
        "decoys": [{"name": "kernel32", "sha256": "1" * 64}],
        "module": {"base": 0x140000000, "size": 0x16000, "changed": 0},
    }
    return doc, blobs


def _shape(tmp_path, doc, blobs, *, input_sha="0" * 64, imported=None):
    _write_regions(tmp_path / "scan", blobs)
    return emulate.shape(doc, tmp_path / "scan", tmp_path / "work", input_sha256=input_sha, triggers=["few_imports"],
                         imported=imported)


def test_the_loader_run_is_shaped_into_captures_behaviour_and_strings(tmp_path):
    doc, blobs = loader_doc()
    em = _shape(tmp_path, doc, blobs, imported=emulate.imports(UNPACK))
    ev = em.evidence
    assert ev["status"] == "ok" and ev["stop"] == "exit" and ev["arch"] == "x64" and ev["triggers"] == ["few_imports"]
    assert ev["concealment"] == ["exec_alloc", "dynamic_code", "pe_in_memory"]
    kinds = [(c.kind, c.layout) for c in em.captures]
    assert kinds == [("pe", "file"), ("pe", "memory"), ("shellcode", None)]
    assert em.captures[0].sha256 == SAMPLE_SHA and em.captures[0].path.read_bytes() == SAMPLE
    assert em.captures[2].path.read_bytes() == SHELLCODE and em.captures[2].executed
    va = next(r for r in ev["apis"] if r["api"] == "kernel32.VirtualAlloc")
    assert va["count"] == 3 and va["category"] == "memory" and len(va["args"]) == 3
    assert next(r for r in ev["apis"] if r["api"] == "kernel32.ExitProcess") == {
        "api": "kernel32.ExitProcess", "category": "other", "count": 1}
    assert ev["apis_total"] == 11 and ev["apis_distinct"] == 7
    values = {s["value"] for s in ev["strings"]}
    assert {"Local\\LoadoutFixtureMutex", "http://stage.loadout.example/next.bin", "stage.loadout.example"} <= values
    assert "INTERNET_FLAG_RELOAD" not in values  # a flags rendering, not a string the stub built
    assert ("emulation:wininet.InternetOpenUrlA", "http://stage.loadout.example/next.bin") in em.strings
    assert ev["events"] == [{"event": "net_http", "server": "stage.loadout.example", "port": "80",
                             "proto": "tcp.http"}]  # mem_* events are already in apis
    assert ev["dynamic_code"] == [{"tag": "api.VirtualAlloc.0x441000", "base": "0x441000", "size": 4096}]
    assert "unimported_apis" not in ev  # every API it called is imported


def test_choose_prefers_the_strongest_signal_and_the_file_copy(tmp_path):
    doc, blobs = loader_doc()
    em = _shape(tmp_path, doc, blobs)
    cap, reason = emulate.choose(em.captures)
    # Both copies are one image; the mapped copy was made executable, the file copy is exact.
    assert reason == "executable_region" and cap.layout == "file" and cap.sha256 == SAMPLE_SHA


def _cap(identity, *, size=8192, layout="file", executed=False, asked=False, source="VirtualAlloc", kind="pe",
         machine=0x8664):
    return emulate.Capture(Path("x"), sha(repr((identity, layout, source)).encode()), size, kind, source,
                           {"base": "0x1", "size": size, "protect": "rw-"}, executed, asked, layout, False, machine,
                           identity)


def test_choose_ranks_groups():
    a = _cap((1, 1, 1, 1))
    b = _cap((2, 2, 2, 2), source="module", layout="memory")
    assert emulate.choose([a, b]) == (b, "self_modified_image")
    c = _cap((3, 3, 3, 3), executed=True, layout="memory")
    assert emulate.choose([a, b, c]) == (c, "executed_region")
    assert emulate.choose([_cap((4, 4, 4, 4), size=100)]) is None  # under PAYLOAD_MIN_BYTES
    assert emulate.choose([_cap((5, 5, 5, 5), machine=0xAA64)]) is None
    assert emulate.choose([_cap(None, kind="shellcode", layout=None)]) is None
    assert emulate.choose([]) is None


def test_captures_are_deduplicated_and_copies_of_the_input_or_decoys_dropped(tmp_path):
    img = mapped(SAMPLE)
    doc = {"regions": [_region("region-0.bin", 0x50000, 0x13000, alloc=len(SAMPLE)),
                       _region("region-1.bin", 0x90000, 0x13000, alloc=len(SAMPLE)),
                       _region("region-2.bin", 0x74000, len(img))],
           "decoys": [{"name": "kernel32", "sha256": sha(img)}]}
    blobs = {"region-0.bin": SAMPLE.ljust(0x13000, b"\x00"), "region-1.bin": SAMPLE.ljust(0x13000, b"\x00"),
             "region-2.bin": img}
    em = _shape(tmp_path, doc, blobs)
    assert [c.sha256 for c in em.captures] == [SAMPLE_SHA]
    assert em.evidence["captures_dropped"] == {"duplicate": 1, "decoy_module": 1}
    em2 = emulate.shape(doc, tmp_path / "scan", tmp_path / "work2", input_sha256=SAMPLE_SHA, triggers=[])
    assert em2.captures == [] and em2.evidence["captures_dropped"]["same_as_input"] == 2


def test_captures_are_capped_and_tiny_or_inert_regions_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(emulate, "MAX_CAPTURES", 2)
    regions, blobs = [], {}
    for i in range(4):
        blobs[f"region-{i}.bin"] = bytes([0x90 + i, 0xC3]) * 32
        regions.append(_region(f"region-{i}.bin", 0x10000 * (i + 1), 0x1000, executed=True))
    blobs["region-4.bin"] = b"\xc3\x00\x00"  # executed, but almost nothing there
    regions.append(_region("region-4.bin", 0x90000, 0x1000, executed=True))
    blobs["region-5.bin"] = b"\x90\xc3" * 32  # neither executable nor run: not a capture
    regions.append(_region("region-5.bin", 0xA0000, 0x1000))
    em = _shape(tmp_path, {"regions": regions}, blobs)
    assert len(em.captures) == 2 and all(c.kind == "shellcode" for c in em.captures)
    assert em.evidence["captures_dropped"] == {"capped": 2, "too_small": 1}


def test_fill_patterns_and_partial_images_are_not_captures(tmp_path):
    """A stub that fills buffers with one byte before asking for them executable, and a copy of
    only an image's headers, left "captures" that were neither code nor a loadable PE."""
    img = mapped(SAMPLE)
    blobs = {"region-0.bin": b"\xf8" * 0x3000, "region-1.bin": img[:0x1000], "region-2.bin": SAMPLE[:0x800],
             "region-3.bin": img}
    doc = {"regions": [_region("region-0.bin", 0x50000, 0x3000, prot="PAGE_EXECUTE_READWRITE", asked=True),
                       _region("region-1.bin", 0x60000, 0x1000), _region("region-2.bin", 0x70000, 0x1000),
                       _region("region-3.bin", 0x80000, len(img), executed=True)],
           "regions_skipped": {"duplicate": 317, "capped": 0}}
    em = _shape(tmp_path, doc, blobs)
    assert [(c.kind, c.layout, c.size) for c in em.captures] == [("pe", "memory", len(img))]
    assert em.evidence["captures_dropped"] == {"filler": 1, "partial": 2, "duplicate": 317}
    assert em.evidence["concealment"] == ["exec_alloc", "pe_in_memory"]  # it still asked for executable memory
    assert emulate.carve(img[:0x1000], 0, 0x60000) is None and emulate.carve(img, 0, 0x60000) is not None
    hostile = {"regions_skipped": {"duplicate": 10 ** 30, "capped": "many"}}
    ev = emulate.shape(hostile, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev["captures_dropped"] == {"duplicate": emulate.MAX_COUNT}


def test_hostile_runner_output_is_contained(tmp_path):
    secret = tmp_path / "secret.bin"
    secret.write_bytes(SAMPLE)
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "region-1.bin").symlink_to(secret)
    doc = {"arch": 7, "dll": "yes", "entry_points": [None, {"type": 3, "error": ["x"]}],
           "apis": [None, {"n": 5}, {"n": "kernel32.Sleep", "a": "nope"}, {"n": "k.X", "a": [[1, 2], ["str"]]}],
           "apis_total": -4, "events": [{"event": 1}, "x"], "dynamic_code": [{"base": "zz", "size": 1}],
           "regions": [{"file": "../secret.bin", "base": 1, "size": 1, "executed": True},
                       {"file": "region-1.bin", "base": 0x1000, "size": 0x1000, "executed": True},
                       {"file": "region-2.bin", "base": "0x1000", "size": True, "executed": True}],
           "decoys": "x", "module": "x"}
    em = emulate.shape(doc, tmp_path / "scan", tmp_path / "work", input_sha256="0" * 64, triggers=[])
    ev = em.evidence
    assert em.captures == [] and "arch" not in ev and "dll" not in ev
    assert ev["entry_points"] == [{"type": "?", "stop": "exception"}] and ev["apis_total"] == 0
    assert ev["dynamic_code"] == [] and ev["concealment"] == []
    assert [r["api"] for r in ev["apis"]] == ["kernel32.Sleep", "k.X"]
    assert ev["apis_top"] == [{"api": "kernel32.Sleep", "count": 1}, {"api": "k.X", "count": 1}]
    hostile = {"entry_points": [{"type": "t" * 500, "error": "e" * 500, "calls": 10 ** 40, "pc": -1, "addr": "0x" + "f" * 40,
                                 "code": []}, {"type": "x", "error": None, "calls": True}],
               "apis": [{"n": "k.A" * 100, "a": [["str", "v" * 5000]] * 50}] * 3,
               "stubbed": ["x", {"n": 7}, {"n": "msvcrt." + "a" * 500, "c": "many"}] + [{"n": f"k.F{i}"} for i in range(300)],
               "sleep_ms": 10 ** 40, "vectored": -3, "faults_total": "9",
               "faults": ["x", {"code": "nope", "pc": 1}, {"code": 5, "pc": 2 ** 70},
                          *[{"code": 0xC0000005, "pc": i, "addr": 4, "handled": "yes", "by": "magic"} for i in range(40)]],
               "regions_skipped": [1], "events": [{"event": "hard_error", "status": 5, "text": "t" * 5000}]}
    ev = emulate.shape(hostile, tmp_path / "scan", tmp_path / "work", input_sha256="0" * 64, triggers=[]).evidence
    assert len(json.dumps(ev)) <= emulate.MAX_EVIDENCE_BYTES
    assert ev["entry_points"][0] == {"type": "t" * 93 + "...", "stop": "exception", "detail": "e" * 61 + "...",
                                     "calls": emulate.MAX_COUNT}
    assert "calls" not in ev["entry_points"][1] and "last_calls" not in ev
    assert len(ev["stubbed_apis"]) == emulate.STATE_STUBBED and ev["stubbed_apis_total"] == 301
    assert all(len(n) <= 96 for n in ev["stubbed_apis"])
    assert ev["sleep_ms"] == emulate.MAX_COUNT and "vectored_exceptions" not in ev
    assert len(ev["faults"]) == emulate.STATE_FAULTS and ev["faults_total"] == 40
    assert ev["faults"][0] == {"code": "0xc0000005", "pc": "0x0", "address": "0x4", "handled": False}
    assert ev["events"] == [{"event": "hard_error", "text": "t" * 253 + "..."}]
    assert ev["stop"] == "exception" and ev["stop_detail"] == "e" * 61 + "..."  # no exit, so no hard-error detail


def test_stop_reasons_and_runner_errors():
    doc = {"entry_points": [{"type": "dll_entry.DLL_PROCESS_ATTACH", "error": None},
                            {"type": "export.A", "error": "unsupported_api", "api": "user32.Foo"},
                            {"type": "export.B", "error": "invalid_read"}]}
    ev = emulate.shape(doc, Path("/nonexistent"), Path("/nonexistent"), input_sha256="", triggers=[]).evidence
    assert [e["stop"] for e in ev["entry_points"]] == ["exit", "unsupported_api", "exception"]
    assert ev["entry_points"][1]["detail"] == "user32.Foo" and ev["entry_points"][2]["detail"] == "invalid_read"
    assert ev["stop"] == "unsupported_api" and ev["stop_detail"] == "user32.Foo"
    budget = {"entry_points": [{"type": "module_entry", "error": "max_total_time"}]}
    assert emulate.shape(budget, Path("/n"), Path("/n"), input_sha256="", triggers=[]).evidence["stop"] == "budget"
    crashed = {"error": "UcError: boom", "entry_points": []}
    ev = emulate.shape(crashed, Path("/n"), Path("/n"), input_sha256="", triggers=[]).evidence
    assert ev["stop"] == "exception" and ev["stop_detail"] == "UcError: boom"


def test_a_dead_emulator_process_names_how_it_died(tmp_path):
    """The runner's parent reports a child that left no document; the evidence keeps the reason
    (it used to be a bare ``failed``)."""
    for kind, status in (("cpu_limit", "budget"), ("wall_clock", "budget"), ("signal", "failed"), ("exit", "failed"),
                         ("output", "failed"), ("anything", "failed")):
        doc = {"error": "emulator process killed at its 150 s CPU limit (SIGKILL, cpu 150 s, peak rss 900 MiB)" * 9,
               "fatal": kind, "apis": [{"n": "k.X"}], "regions": [_region("region-0.bin", 0x1000, 0x1000, executed=True)]}
        em = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=["few_imports"])
        ev = em.evidence
        assert ev["status"] == status and ev["triggers"] == ["few_imports"] and em.captures == []
        assert ev["stop_detail"].startswith("emulator process killed at its 150 s CPU limit") and len(ev["stop_detail"]) <= 200
        assert set(ev) == ({"status", "triggers", "stop", "stop_detail"} if status == "budget" else
                           {"status", "triggers", "stop_detail"})
    ev = emulate.shape({"fatal": "signal", "error": 7}, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev == {"status": "failed", "triggers": [], "stop_detail": "signal"}


def _calls(*names):
    return [{"n": n, "a": [["int", "0x1"]]} for n in names]


def test_why_a_run_ended_is_reported(tmp_path):
    # An entry point that ended in the unhandled-exception filter is no clean exit.
    doc = {"entry_points": [{"type": "tls_callback_0", "error": None, "calls": 1},
                            {"type": "module_entry", "error": "unhandled_exception", "calls": 3, "code": 0xC0000005,
                             "pc": 0, "addr": 0}],
           "apis": _calls("k.A", "ole32.CoCreateInstance", "oleaut32.SysAllocString", "k.SetUnhandledExceptionFilter"),
           "apis_total": 4,
           "faults": [{"code": 0xC0000005, "pc": 0, "addr": 0, "handled": True, "by": "filter"}], "faults_total": 1}
    ev = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev["stop"] == "exception" and ev["stop_detail"] == "unhandled_exception 0xc0000005 at 0x0 (address 0x0)"
    assert ev["entry_points"] == [{"type": "tls_callback_0", "stop": "exit", "calls": 1},
                                  {"type": "module_entry", "stop": "exception", "calls": 3,
                                   "detail": "unhandled_exception 0xc0000005 at 0x0 (address 0x0)"}]
    assert ev["last_calls"] == {"entry_point": "module_entry", "calls": [
        {"api": "ole32.CoCreateInstance", "args": ["0x1"]}, {"api": "oleaut32.SysAllocString", "args": ["0x1"]},
        {"api": "k.SetUnhandledExceptionFilter", "args": ["0x1"]}]}
    assert ev["faults"] == [{"code": "0xc0000005", "pc": "0x0", "address": "0x0", "handled": True, "by": "filter"}]
    assert ev["faults_total"] == 1

    # The API cap names what used it up; the last calls are those of the entry point that hit it.
    names = ["k.GetStdHandle", "k.WriteFile", "k.OutputDebugStringA"] * 20
    doc = {"entry_points": [{"type": "module_entry", "error": None, "calls": 2},
                            {"type": "thread", "error": "max_api_count", "calls": 60, "pc": 0xF4F0B7}],
           "apis": _calls("k.CreateThread", "k.ExitProcess", *names), "apis_total": 62, "vectored": 1}
    ev = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev["stop"] == "api_limit"
    assert ev["stop_detail"] == "most calls: k.GetStdHandle x20, k.WriteFile x20, k.OutputDebugStringA x20, k.CreateThread x1"
    assert ev["apis_top"][0] == {"api": "k.GetStdHandle", "count": 20} and len(ev["apis_top"]) == 5
    assert ev["last_calls"]["entry_point"] == "thread" and len(ev["last_calls"]["calls"]) == emulate.STATE_LAST_CALLS
    assert ev["last_calls"]["calls"][-1]["api"] == "k.OutputDebugStringA" and ev["vectored_exceptions"] == 1

    # A clean exit: the checks made just before it, and the message a refusing protector showed.
    doc = {"entry_points": [{"type": "module_entry", "error": None, "calls": 3}],
           "apis": _calls("user32.GetCaretBlinkTime", "ntdll.ZwRaiseHardError", "kernel32.ExitProcess"), "apis_total": 3,
           "events": [{"event": "hard_error", "api": "ntdll.ZwRaiseHardError", "status": "0x50000018",
                       "text": "This fixture refuses to run | Fixture"}],
           "stubbed": [{"n": "msvcrt._access", "c": 2, "how": "stub"}, {"n": "user32.GetShellWindow", "c": 1, "how": "signature"},
                       {"n": "msvcrt._access", "c": 1, "how": "stub"}],
           "sleep_ms": 6550}
    em = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[])
    ev = em.evidence
    assert ev["stop"] == "exit"
    assert ev["stop_detail"] == "exit after a hard-error message box 0x50000018: This fixture refuses to run | Fixture"
    assert [c["api"] for c in ev["last_calls"]["calls"]] == ["user32.GetCaretBlinkTime", "ntdll.ZwRaiseHardError",
                                                             "kernel32.ExitProcess"]
    assert ev["stubbed_apis"] == ["msvcrt._access", "user32.GetShellWindow"] and ev["stubbed_apis_total"] == 2
    assert ev["sleep_ms"] == 6550 and "faults" not in ev and "vectored_exceptions" not in ev
    assert ("emulation:hard_error", "This fixture refuses to run | Fixture") in em.strings

    # Call counts that do not add up to the call list: no last calls rather than wrong ones.
    doc = {"entry_points": [{"type": "module_entry", "error": None, "calls": 9}], "apis": _calls("k.A")}
    assert "last_calls" not in emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    # A DLL: the clean exit's last calls are those of the last entry point that called anything.
    doc = {"entry_points": [{"type": "dll_entry.DLL_PROCESS_ATTACH", "error": None, "calls": 1},
                            {"type": "export.Run", "error": None, "calls": 1}, {"type": "export.Idle", "error": None, "calls": 0}],
           "apis": _calls("k.A", "k.B")}
    ev = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev["last_calls"] == {"entry_point": "export.Run", "calls": [{"api": "k.B", "args": ["0x1"]}]}


def test_a_delay_loop_is_concealment(tmp_path):
    n = emulate.DELAY_LOOP_CALLS
    loop = _calls(*["kernel32.GetTickCount", "user32.GetCursorPos", "kernel32.Sleep"] * n)
    ev = emulate.shape({"apis": loop}, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence
    assert ev["concealment"] == ["delay_loop"] and "delay_loop" in emulate.CONCEALMENT
    for quiet in (loop[:-3],  # one sleep short
                  _calls(*["kernel32.Sleep"] * 200),  # sleeping without watching the clock
                  _calls(*["kernel32.QueryPerformanceCounter"] * 200, "kernel32.Sleep")):  # a busy poll
        assert emulate.shape({"apis": quiet}, tmp_path, tmp_path / "w", input_sha256="", triggers=[]
                             ).evidence["concealment"] == []


def test_behaviour_signals_registry_injection_and_manual_resolution(tmp_path):
    doc = {"apis": [
        {"n": "advapi32.RegOpenKeyExA", "a": [["enum", "HKEY_CURRENT_USER"], ["str", "Software\\Fixture\\Run"]]},
        {"n": "kernel32.WriteProcessMemory", "a": [["handle", "0x4"], ["ptr", "0x1000"]]},
        {"n": "kernel32.GetProcAddress", "a": [["ptr", "0x7000"], ["str", "WinExec"]]},
        {"n": "kernel32.WinExec", "a": [["str", "cmd /c whoami"]]},
        {"n": "kernel32.CreateMutexA", "a": [["str", "Global\\Hashed"]]},
    ]}
    ev = emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[],
                       imported=["regopenkeyexa", "writeprocessmemory", "getprocaddress"]).evidence
    values = {s["value"] for s in ev["strings"]}
    assert "HKEY_CURRENT_USER\\Software\\Fixture\\Run" in values and "cmd /c whoami" in values
    assert "injection_apis" in ev["concealment"] and "manual_api_resolution" in ev["concealment"]
    # WinExec was looked up by name; CreateMutexA was resolved by hand.
    assert ev["unimported_apis"] == ["createmutexa"]
    assert emulate.manual_resolution(["ws2_32.connect"], ["#ws2_32"], []) == []  # imported by ordinal
    assert emulate.manual_resolution(["k.Sleep"], None, []) == []


def test_summary_rows_are_capped(monkeypatch):
    monkeypatch.setattr(emulate, "STATE_APIS", 3)
    apis = [{"n": f"kernel32.CreateFile{i}", "a": [["str", f"C:\\f{i}"]]} for i in range(5)] * 2
    ev = emulate.shape({"apis": apis}, Path("/n"), Path("/n"), input_sha256="", triggers=[]).evidence
    assert len(ev["apis"]) == 3 and ev["apis_distinct"] == 5 and ev["apis"][0]["count"] == 2
    assert ev["apis"][0]["args"] == [["C:\\f0"]]


def test_the_evidence_is_bounded_for_the_model_context():
    apis = [{"n": f"kernel32.CreateFile{i}", "a": [["str", f"C:\\{i}\\" + "x" * 300]] * 12} for i in range(200)]
    apis += [dict(a, a=[["str", f"C:\\{j}\\" + "y" * 300]] * 12) for a in apis for j in range(3)]
    ev = emulate.shape({"apis": apis}, Path("/n"), Path("/n"), input_sha256="", triggers=[]).evidence
    assert len(json.dumps(ev)) <= emulate.MAX_EVIDENCE_BYTES and ev["truncated"] is True
    assert ev["apis"] and all(len(r.get("args", [])) <= 1 for r in ev["apis"])
    assert all(len(a) <= emulate.MAX_ARGS for r in ev["apis"] for a in r.get("args", []))


# ------------------------------------------------------------------- the runner script

def test_runner_helpers():
    assert emulate_runner.exec_request("kernel32.VirtualAlloc", [{"display": "0x0"}, {"display": "PAGE_EXECUTE_READWRITE"}],
                                       "0x50000") == (0x50000, "PAGE_EXECUTE_READWRITE")
    assert emulate_runner.exec_request("kernel32.VirtualProtect", [{"display": "0x441000"}, {"display": "0x1000"},
                                                                   {"display": "PAGE_EXECUTE_READ"}], "0x1") == \
        (0x441000, "PAGE_EXECUTE_READ")
    assert emulate_runner.exec_request("kernel32.VirtualProtectEx", [{"display": "0x4"}, {"display": "0x9000"},
                                                                     {"display": "PAGE_EXECUTE"}], "0x1")[0] == 0x9000
    assert emulate_runner.exec_request("kernel32.VirtualAlloc", [{"display": "PAGE_READWRITE"}], "0x5") is None
    assert emulate_runner.exec_request("kernel32.VirtualAlloc", [{"display": "PAGE_EXECUTE"}], "0x0") is None
    assert emulate_runner.has_pe(b"\x00" * 0x1000 + SAMPLE) and not emulate_runner.has_pe(b"MZ" * 100)
    spans = emulate_runner.code_spans(SAMPLE)
    text = pefile.PE(data=SAMPLE).sections[0]
    assert (text.VirtualAddress, text.Misc_VirtualSize) in spans
    before = mapped(SAMPLE)
    after = bytearray(before)
    after[text.VirtualAddress:text.VirtualAddress + 600] = b"\xcc" * 600
    assert emulate_runner.changed_bytes(before, bytes(after), spans) >= 512
    assert emulate_runner.prot_text(5) == "r-x"


def test_runner_stubs_follow_the_calling_convention_and_do_not_lie():
    r = emulate_runner
    assert all(r.is_crt(d) for d in ("msvcrt", "MSVCR100", "ucrtbase", "api-ms-win-crt-runtime-l1-1-0", "vcruntime140"))
    assert not r.is_crt("kernel32") and not r.is_crt("user32")
    assert r.stub_return("msvcrt", "_access", [0x1000, 0]) == 0xFFFFFFFF  # the file is not there
    assert r.stub_return("ucrtbase", "_waccess_s", [0x1000, 0]) == 2  # ENOENT
    assert r.stub_return("msvcrt", "_onexit", [0x401000]) == 0x401000 and r.stub_return("msvcrt", "_onexit", []) == 0
    assert r.stub_return("msvcrt", "atexit", [0x401000]) == 0 and r.stub_return("ntdll", "NtFoo", []) == 0
    assert r.stub_return("ntdll", "RtlFoo", []) == 0 and r.stub_return("user32", "IsFoo", []) == 1
    assert r.stub_return("user32", "IsFoo", [], declared=7) == 7 and r.stub_return("msvcrt", "_access", [], declared=7) != 7
    assert r.stub_global("msvcrt", "__p__environ") == "pointer" and r.stub_global("ucrtbase", "__p___argv") == "pointer"
    assert r.stub_global("msvcrt", "__p__fmode") == "number" and r.stub_global("msvcrt", "_access") is None
    assert r.stub_global("kernel32", "__p__environ") is None


def test_runner_memory_and_exception_helpers():
    r = emulate_runner
    assert [r.page_perms(p) for p in (0x01, 0x02, 0x04, 0x20, 0x40, 0x104)] == [0, 1, 3, 5, 7, 3]  # PAGE_GUARD ignored
    assert r.page_perms(0) is None and r.page_perms(0x03) is None
    assert [r.page_protect(p) for p in (0, 1, 3, 5, 7)] == [0x01, 0x02, 0x04, 0x20, 0x40]
    spans = [(0x10000, 0x20000), (0x20000, 0x21000), (0x50000, 0x60000)]

    def clear(spans, size, addr):
        base, length = r.free_range(spans, size, addr)
        assert base % 0x1000 == 0 and length % 0x1000 == 0 and length >= size and base >= addr - addr % 0x1000
        assert all(end <= base or start >= base + length for start, end in spans)
        return base

    assert clear(spans, 0x1000, 0x10000) >= 0x21000  # steps past what is mapped
    assert clear(spans, 0x2F001, 0x10000) >= 0x60000  # the gap is too small for it
    assert r.free_range([], 1, 0x12345) == (0x12000, 0x1000) and r.free_range(spans, 0x1000, 0x70000) == (0x70000, 0x1000)
    assert r.free_range(spans, 0x2000, 0x21000) == (0x21000, 0x2000)  # a gap that fits is taken where asked
    assert clear([(0x30000, 0x31000), (0x10000, 0x40000)], 0x1000, 0x32000) >= 0x40000  # a span inside another
    with pytest.raises(MemoryError):
        r.free_range([(0, 1 << 62)], 0x1000, 0x10000)
    rec = r.exception_record(0xC0000005, 0x140001EFF, 8, (0, 0x832000))
    assert len(rec) == 152 and struct.unpack_from("<IIQQI4xQQ", rec) == (0xC0000005, 0, 0, 0x140001EFF, 2, 0, 0x832000)
    rec = r.exception_record(0xC0000005, 0x401000, 4, (1, 0x832000))
    assert len(rec) == 80 and struct.unpack_from("<IIIIIII", rec) == (0xC0000005, 0, 0, 0x401000, 2, 1, 0x832000)
    assert len(r.exception_record(1, 2, 8, tuple(range(40)))) == 152


def test_the_runner_keeps_cpu_time_back_and_names_a_dead_child():
    r = emulate_runner
    assert r.cpu_budget(120, None, 3) == 120 and r.cpu_budget(120, 150, 5) == 120
    assert r.cpu_budget(120, 100, 5) == 100 - 5 - r.CPU_RESERVE_S and r.cpu_budget(120, 10, 5) == 1.0
    assert r.GRACE_S < emulate.OVERHEAD_S  # the parent reports before the engine kills the process group
    use = {"cpu_s": 149.5, "wall_s": 145.0, "rss_kb": 900 * 1024, "got_bytes": 0}
    kind, text = r.death_reason(signal.SIGKILL, cpu_limit=150.0, wall_killed=False, **use)
    assert kind == "cpu_limit" and "150 s CPU limit" in text and "SIGKILL" in text and "900 MiB" in text
    assert r.death_reason(signal.SIGKILL, cpu_limit=None, wall_killed=False, **use)[0] == "signal"
    assert r.death_reason(signal.SIGSEGV, cpu_limit=150.0, wall_killed=False, **use) == (
        "signal", "emulator process killed by SIGSEGV (cpu 150 s, peak rss 900 MiB)")
    assert r.death_reason(signal.SIGKILL, cpu_limit=150.0, wall_killed=True, **use)[0] == "wall_clock"
    assert r.death_reason(3 << 8, cpu_limit=None, wall_killed=False, **use)[0] == "exit"
    assert r.death_reason(0, cpu_limit=None, wall_killed=False, **use)[0] == "output"
    assert r.death_reason(0, cpu_limit=None, wall_killed=False, **{**use, "got_bytes": r.MAX_DOC_BYTES + 1})[0] == "output"
    assert all(len(r.death_reason(s, cpu_limit=150.0, wall_killed=w, **use)[1]) <= 200
               for s in (0, 9, 3 << 8) for w in (False, True))


def test_the_runner_parent_always_has_a_document(tmp_path, monkeypatch):
    """The emulation runs in a forked child; however it ends, the parent returns one document."""
    r = emulate_runner
    monkeypatch.setattr(r, "emulate", lambda *a: {"arch": "x64", "entry_points": []})
    assert r.supervise("s", str(tmp_path), 5, 10, -1) == {"arch": "x64", "entry_points": []}

    def boom(*a):
        raise MemoryError("no room")
    monkeypatch.setattr(r, "emulate", boom)
    assert r.supervise("s", str(tmp_path), 5, 10, -1) == {"error": "MemoryError: no room"}
    monkeypatch.setattr(r, "emulate", lambda *a: os.kill(os.getpid(), signal.SIGKILL))
    doc = r.supervise("s", str(tmp_path), 5, 10, -1)
    assert doc["fatal"] == "signal" and "SIGKILL" in doc["error"]
    monkeypatch.setattr(r, "emulate", lambda *a: os._exit(3))
    assert r.supervise("s", str(tmp_path), 5, 10, -1)["fatal"] == "exit"
    monkeypatch.setattr(r, "GRACE_S", 0.2)
    monkeypatch.setattr(r, "emulate", lambda *a: time.sleep(30))
    began = time.monotonic()
    doc = r.supervise("s", str(tmp_path), 0.2, 10, -1)
    assert doc["fatal"] == "wall_clock" and time.monotonic() - began < 10
    assert emulate.shape(doc, tmp_path, tmp_path / "w", input_sha256="", triggers=[]).evidence["status"] == "budget"


def test_the_runner_imports_nothing_from_blastbox():
    src = Path(emulate_runner.__file__).read_text()
    assert "blastbox" not in src.split('"""', 2)[2]  # it runs under the Speakeasy venv's python


def test_the_runner_reports_a_missing_emulator_as_an_error_document(tmp_path):
    """Under a python without Speakeasy the script still prints one JSON document."""
    out = tmp_path / "o"
    status, data = run_emulation(UNPACK, out, 60, env=rea_env(tmp_path / "e", {"PATH": "/usr/bin:/bin"}),
                                 python=sys.executable, budget_s=5, max_api=100, max_insn=-1,
                                 max_kb=4 * 1024 * 1024, max_stdout=1 << 20, max_write_bytes=1 << 20)
    assert status == "ok" and "speakeasy" in json.loads(data)["error"]


def test_run_emulation_without_its_python_is_unavailable(tmp_path):
    status, _ = run_emulation(UNPACK, tmp_path / "o", 60, env={}, python="/nonexistent/python", budget_s=5,
                              max_api=1, max_insn=-1, max_kb=1 << 20, max_stdout=1 << 20, max_write_bytes=1 << 20)
    assert status == "unavailable"


def test_run_emulation_bounds_the_subprocess(tmp_path):
    calls = []

    def run_fn(argv, *, env, cwd, timeout_s, max_stdout):
        calls.append((argv, timeout_s, max_stdout))
        from blastbox.engines.rea.runner import RunOutcome
        return RunOutcome(None, timed_out=True)

    status, _ = run_emulation(UNPACK, tmp_path / "o", 150, env={}, python=sys.executable, budget_s=120, max_api=7,
                              max_insn=-1, max_kb=3 << 20, max_stdout=99, max_write_bytes=1 << 20, run_fn=run_fn)
    argv, timeout_s, max_stdout = calls[0]
    assert status == "timeout" and timeout_s == 150 and max_stdout == 99
    assert "ulimit -v" in argv[2] and "ulimit -f" in argv[2] and "ulimit -t" in argv[2] and '-I "$5"' in argv[2]
    assert argv[4:7] == [str(3 << 20), str((1 << 20) // 512), "151"]
    assert argv[-3:] == ["120", "7", "-1"]


SPEAKEASY = os.environ.get("REA_TEST_SPEAKEASY_PYTHON")


@pytest.mark.skipif(not SPEAKEASY, reason="REA_TEST_SPEAKEASY_PYTHON (a Speakeasy venv's python) not set")
def test_real_speakeasy_unpacks_the_loader_fixture(tmp_path):
    out = tmp_path / "o"
    status, data = run_emulation(UNPACK, out, 180, env=rea_env(tmp_path / "e", {"PATH": "/usr/bin:/bin"}),
                                 python=SPEAKEASY or "", budget_s=60, max_api=20000, max_insn=-1,
                                 max_kb=3 * 1024 * 1024, max_stdout=1 << 24, max_write_bytes=1 << 28)
    assert status == "ok"
    doc = json.loads(data)
    em = emulate.shape(doc, out, tmp_path / "w", input_sha256=sha(UNPACK.read_bytes()), triggers=[],
                       imported=emulate.imports(UNPACK))
    cap, reason = emulate.choose(em.captures)
    assert cap.sha256 == SAMPLE_SHA and reason == "executable_region"
    assert em.evidence["concealment"] == ["exec_alloc", "dynamic_code", "pe_in_memory"]
    assert any(c.kind == "shellcode" and c.path.read_bytes() == SHELLCODE for c in em.captures)
    peb = tmp_path / "p"
    status, data = run_emulation(FIXTURES / "peb.exe", peb, 180, env=rea_env(tmp_path / "e2", {"PATH": "/usr/bin"}),
                                 python=SPEAKEASY or "", budget_s=60, max_api=20000, max_insn=-1,
                                 max_kb=3 * 1024 * 1024, max_stdout=1 << 24, max_write_bytes=1 << 28)
    ev = emulate.shape(json.loads(data), peb, tmp_path / "w2", input_sha256="", triggers=[],
                       imported=emulate.imports(FIXTURES / "peb.exe")).evidence
    assert ev["concealment"] == ["manual_api_resolution"] and "createmutexa" in ev["unimported_apis"]
    dll = tmp_path / "d"
    status, data = run_emulation(FIXTURES / "unpack.dll", dll, 180, env=rea_env(tmp_path / "e3", {"PATH": "/usr/bin"}),
                                 python=SPEAKEASY or "", budget_s=60, max_api=20000, max_insn=-1,
                                 max_kb=3 * 1024 * 1024, max_stdout=1 << 24, max_write_bytes=1 << 28)
    doc = json.loads(data)
    assert [e["type"] for e in doc["entry_points"]] == ["dll_entry.DLL_PROCESS_ATTACH", "export.Stage"]
    em = emulate.shape(doc, dll, tmp_path / "w3", input_sha256="", triggers=[])
    assert emulate.choose(em.captures)[0].sha256 == SAMPLE_SHA


@pytest.mark.skipif(not SPEAKEASY, reason="REA_TEST_SPEAKEASY_PYTHON (a Speakeasy venv's python) not set")
def test_real_speakeasy_through_the_sweep(tmp_path):
    def real(sample, outdir, timeout_s, **kw):
        return run_emulation(sample, outdir, timeout_s, **{**kw, "python": SPEAKEASY})

    res, out, ghidra = _erun(UNPACK, tmp_path, real)
    f = _fields(res)
    assert f["unpacked"] == "emulated" and f["unpacked_sha256"] == SAMPLE_SHA and ghidra.data == SAMPLE
    assert ("url", "http://stage.loadout.example/next.bin", "emulation:wininet.InternetOpenUrlA") in _iocs(f)
    assert not {"emulation_failed", "emulation_budget"} & set(_codes(res))


# ------------------------------------------------------------------- the sweep

class FakeEmulate:
    """Stands in for run_emulation: writes ``blobs`` as region files and returns ``doc``."""

    def __init__(self, status="ok", doc=None, blobs=None, raises=None):
        self.status, self.raises = status, raises
        default_doc, default_blobs = loader_doc()
        self.doc = default_doc if doc is None else doc
        self.blobs = default_blobs if blobs is None else blobs
        self.calls: list[dict] = []

    def __call__(self, sample, outdir, timeout_s, *, env, python, budget_s, max_api, max_insn, max_kb, max_stdout,
                 max_write_bytes):
        self.calls.append(dict(sample=sample, outdir=outdir, timeout_s=timeout_s, python=python, budget_s=budget_s,
                               max_api=max_api, max_insn=max_insn, max_kb=max_kb))
        if self.raises:
            raise self.raises
        if self.status != "ok":
            return self.status, b""
        _write_regions(outdir, self.blobs)
        return "ok", json.dumps(self.doc).encode()


class ByteGhidra(FakeGhidra):
    """FakeGhidra that also keeps the bytes it was given (the job dir is gone afterwards)."""

    def __call__(self, sample, project_dir, timeout_s, **kw):
        self.data = sample.read_bytes()
        return super().__call__(sample, project_dir, timeout_s, **kw)


def _erun(sample, tmp_path, fake, *, unpack=None, limits=None):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    ghidra = ByteGhidra()
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=ghidra, unpack_fn=unpack or FakeUnpack("failed"),
                            capa_fn=lambda *a, **k: ("ok", b'{"rules": {}}'), emulate_fn=fake)
    return eng.detonate(sample, out, limits or Limits(timeout_s=900)), out, ghidra


def _state(out, tmp_path):
    return unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)[2]


def test_a_captured_stage_replaces_the_stub(tmp_path):
    fake = FakeEmulate()
    res, out, ghidra = _erun(UNPACK, tmp_path, fake)
    assert fake.calls[0]["python"] == "/opt/speakeasy/bin/python" and fake.calls[0]["sample"].name == "unpack.exe"
    assert fake.calls[0]["budget_s"] == 120 and fake.calls[0]["timeout_s"] == 150 and fake.calls[0]["max_insn"] == -1
    assert ghidra.data == SAMPLE  # Ghidra analyses the stage
    f = _fields(res)
    assert f["unpacked"] == "emulated" and f["unpacked_sha256"] == SAMPLE_SHA
    assert f["emulation"] == "ok" and f["emulation_captures"] == 3
    members = {(out / a.path).read_bytes() for a in res.artifacts if a.id.startswith("member-")}
    assert SAMPLE in members and SHELLCODE in members and len(members) == 3
    st = _state(out, tmp_path)
    assert st.sample_sha256 == SAMPLE_SHA
    layer = st.sweep["unpacked"]
    assert layer == {"packer": "emulated", "packed_sha256": sha(UNPACK.read_bytes()), "payload_sha256": SAMPLE_SHA,
                     "payload_reason": "executable_region",
                     "region": {"base": "0x50000", "size": 0x13000, "protect": "rw-"}}
    ev = st.sweep["emulation"]
    assert ev["payload_sha256"] == SAMPLE_SHA and ev["concealment"] == ["exec_alloc", "dynamic_code", "pe_in_memory"]
    assert [c["member"] for c in ev["captures"]] == ["member-0", "member-1", "member-2"]
    assert {"high_entropy_section", "few_imports"} <= set(ev["triggers"])
    assert ("url", "http://stage.loadout.example/next.bin", "emulation:wininet.InternetOpenUrlA") in _iocs(f)
    assert ("mutex", "Local\\LoadoutFixtureMutex", "emulation:kernel32.CreateMutexA") in _iocs(f)
    report = json.loads((out / "report.json").read_text())
    assert report["emulation"]["captures"][0]["sha256"] == SAMPLE_SHA and report["unpacked"] == "emulated"
    assert "emulation_failed" not in _codes(res) and "emulation_budget" not in _codes(res)


def test_a_stub_that_shows_no_stage_is_still_described(tmp_path):
    doc, blobs = loader_doc()
    doc["regions"] = [doc["regions"][2]]
    res, out, ghidra = _erun(UNPACK, tmp_path, FakeEmulate(doc=doc, blobs={"region-2.bin": blobs["region-2.bin"]}))
    f = _fields(res)
    assert "unpacked" not in f and f["emulation_captures"] == 1
    assert ghidra.calls[0]["sample"].name == "unpack.exe"
    ev = _state(out, tmp_path).sweep["emulation"]
    assert "payload_sha256" not in ev and ev["concealment"] == ["exec_alloc", "dynamic_code"]


def test_a_captured_upx_stage_is_unpacked_in_turn(tmp_path):
    def upx(pe):
        pe.sections[0].Name = b"UPX0\x00\x00\x00\x00"
        pe.sections[1].Name = b"UPX1\x00\x00\x00\x00"

    stage = patched(tmp_path, "upxstage.exe", upx).read_bytes()
    doc = {"entry_points": [{"type": "module_entry", "error": None}],
           "regions": [_region("region-0.bin", 0x50000, 0x13000, asked=True, alloc=len(stage))]}
    up = FakeUnpack("ok")
    res, out, ghidra = _erun(UNPACK, tmp_path, FakeEmulate(doc=doc, blobs={"region-0.bin": stage.ljust(0x13000, b"\0")}),
                             unpack=up)
    assert up.calls and up.calls[0]["sample"].name == f"stage-{sha(stage)[:12]}.exe"
    st = _state(out, tmp_path)
    assert st.sweep["unpacked"]["packer"] == "emulated" and st.sweep["unpacked"]["inner"] == [{"packer": "upx"}]
    assert _fields(res)["unpacked"] == "emulated" and ghidra.data == SAMPLE


@pytest.mark.parametrize("status,code,state", [("failed", "emulation_failed", "failed"),
                                               ("too_large", "emulation_failed", "failed"),
                                               ("unavailable", "emulation_failed", "failed"),
                                               ("timeout", "emulation_budget", "budget")])
def test_emulation_failures_are_warnings_and_the_stub_is_analysed(tmp_path, status, code, state):
    res, out, ghidra = _erun(UNPACK, tmp_path, FakeEmulate(status))
    f = _fields(res)
    assert code in _codes(res) and f["emulation"] == state and f["emulation_captures"] == 0
    assert "unpacked" not in f and ghidra.calls[0]["sample"].name == "unpack.exe"
    assert _state(out, tmp_path).sweep["emulation"]["status"] == state


def test_an_exception_or_a_malformed_document_is_emulation_failed(tmp_path):
    res, _out, _g = _erun(UNPACK, tmp_path, FakeEmulate(raises=OSError("x")))
    assert "emulation_failed" in _codes(res)
    bad = FakeEmulate(doc={"x": 1}, blobs={})
    bad.doc = None  # json "null"
    res, _out, _g = _erun(UNPACK, tmp_path / "b", bad)
    assert "emulation_failed" in _codes(res)


def test_a_speakeasy_error_or_budget_stop_keeps_partial_results(tmp_path):
    doc, blobs = loader_doc()
    doc["error"] = "UcError: Invalid memory read"
    res, _out, _g = _erun(UNPACK, tmp_path, FakeEmulate(doc=doc, blobs=blobs))
    assert "emulation_failed" in _codes(res) and _fields(res)["unpacked"] == "emulated"
    doc, blobs = loader_doc()
    doc["entry_points"] = [{"type": "module_entry", "error": "max_total_time"}]
    res, _out, _g = _erun(UNPACK, tmp_path / "b", FakeEmulate(doc=doc, blobs=blobs))
    assert "emulation_budget" in _codes(res) and _fields(res)["unpacked"] == "emulated"


@pytest.mark.parametrize("kind,state,code", [("cpu_limit", "budget", "emulation_budget"), ("signal", "failed", None)])
def test_a_killed_emulator_process_reaches_the_report_with_its_reason(tmp_path, kind, state, code):
    doc = {"error": "emulator process killed by SIGKILL (cpu 3 s, peak rss 40 MiB)", "fatal": kind}
    res, out, ghidra = _erun(UNPACK, tmp_path, FakeEmulate(doc=doc, blobs={}))
    f = _fields(res)
    assert f["emulation"] == state and f["emulation_captures"] == 0 and "unpacked" not in f
    assert "emulation_failed" in _codes(res) and (code is None or code in _codes(res))
    em = _state(out, tmp_path).sweep["emulation"]
    assert em["status"] == state and em["stop_detail"].startswith("emulator process killed by SIGKILL")
    assert ghidra.calls[0]["sample"].name == "unpack.exe"  # the stub is analysed as before


def test_no_trigger_no_emulation(tmp_path, monkeypatch):
    fake = FakeEmulate()
    monkeypatch.setattr(emulate, "triggers", lambda *a, **k: [])
    res, _out, _g = _erun(UNPACK, tmp_path, fake)
    assert fake.calls == [] and "emulation" not in _fields(res)
    fake2 = FakeEmulate()
    _erun(FIXTURES / "sample.elf", tmp_path / "elf", fake2)
    _erun(FIXTURES / "dotnet.dll", tmp_path / "net", fake2)
    assert fake2.calls == []


def test_the_budget_is_tunable_and_bounded_by_the_job(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_EMULATE_TIMEOUT_S", "30")
    monkeypatch.setenv("REA_EMULATE_MAX_API", "500")
    monkeypatch.setenv("REA_EMULATE_MAX_INSTRUCTIONS", "1000000")
    fake = FakeEmulate()
    _erun(UNPACK, tmp_path, fake)
    assert fake.calls[0]["budget_s"] == 30 and fake.calls[0]["timeout_s"] == 60
    assert fake.calls[0]["max_api"] == 500 and fake.calls[0]["max_insn"] == 1_000_000
    monkeypatch.setenv("REA_EMULATE_TIMEOUT_S", "-3")
    fake = FakeEmulate()
    _erun(UNPACK, tmp_path / "b", fake)
    assert fake.calls[0]["budget_s"] == 120
    fake = FakeEmulate()
    res, _out, _g = _erun(UNPACK, tmp_path / "c", fake, limits=Limits(timeout_s=40))
    assert fake.calls == [] and "emulation_budget" in _codes(res) and _fields(res)["emulation"] == "budget"


# ------------------------------------------------------------------- the bar and the prompts

def _report(label):
    return {"verdict": {"label": label, "confidence": "high", "rationale": "r"},
            "sections": [{"key": "execution_flow", "status": "observed"}]}


_CONCEALED = {"emulation": {"status": "ok", "concealment": ["exec_alloc", "dynamic_code"], "captures": []}}


def test_a_benign_stub_that_concealed_a_stage_does_not_meet_the_bar():
    s = sufficiency.assess(report=_report("benign"), sweep=_CONCEALED, explored=[])
    gap = next(g for g in s.gaps if g.code == "benign_emulated_stage")
    assert not s.met and "exec_alloc" in gap.detail and gap.targets == []
    assert all(g.code != "benign_emulated_stage"
               for g in sufficiency.assess(report=_report("suspicious"), sweep=_CONCEALED, explored=[]).gaps)
    swapped = {"emulation": {**_CONCEALED["emulation"], "payload_sha256": SAMPLE_SHA}}
    assert sufficiency.assess(report=_report("benign"), sweep=swapped, explored=[]).met
    assert sufficiency.assess(report=_report("benign"), sweep={"emulation": {"concealment": []}}, explored=[]).met
    # stalling alone is not a hidden stage; with another signal it is reported beside it
    assert sufficiency.assess(report=_report("benign"), sweep={"emulation": {"concealment": ["delay_loop"]}},
                              explored=[]).met
    both = sufficiency.assess(report=_report("benign"), explored=[],
                              sweep={"emulation": {"concealment": ["delay_loop", "exec_alloc"]}})
    assert "delay_loop, exec_alloc" in next(g for g in both.gaps if g.code == "benign_emulated_stage").detail


def test_the_agent_and_the_report_are_told_about_emulation():
    sweep = {**_CONCEALED, "unpacked": {"packer": "emulated", "payload_reason": "executed_region"}}
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=sweep)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert '"emulation"' in msg and "Speakeasy" in msg and "emulated" in msg and "not proof of absence" in msg
    assert "stubbed_apis" in msg and "last_calls" in msg
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=sweep, prior_report=None)[0]["content"]
    assert "sweep.emulation" in sys_msg and "OBSERVED" in sys_msg and "never benign" in sys_msg
    assert "stubbed_apis" in sys_msg and "delay_loop on its own" in sys_msg and "stop_detail" in sys_msg
    inner = {**_CONCEALED, "unpacked": {"packer": "nsis", "inner": [{"packer": "emulated"}]}}
    st.sweep = inner
    assert "\"emulated\" layer" in Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
