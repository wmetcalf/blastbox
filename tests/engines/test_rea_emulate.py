"""Emulated unpacking of native loaders: trigger, carving, evidence, payload choice, sweep, bar."""

import hashlib
import json
import os
import sys
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
        blobs[f"region-{i}.bin"] = bytes([0x90 + i]) * 64
        regions.append(_region(f"region-{i}.bin", 0x10000 * (i + 1), 0x1000, executed=True))
    blobs["region-4.bin"] = b"\xc3\x00\x00"  # executed, but almost nothing there
    regions.append(_region("region-4.bin", 0x90000, 0x1000, executed=True))
    blobs["region-5.bin"] = b"\x90" * 64  # neither executable nor run: not a capture
    regions.append(_region("region-5.bin", 0xA0000, 0x1000))
    em = _shape(tmp_path, {"regions": regions}, blobs)
    assert len(em.captures) == 2 and all(c.kind == "shellcode" for c in em.captures)
    assert em.evidence["captures_dropped"] == {"capped": 2, "too_small": 1}


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


def test_the_agent_and_the_report_are_told_about_emulation():
    sweep = {**_CONCEALED, "unpacked": {"packer": "emulated", "payload_reason": "executed_region"}}
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=sweep)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert '"emulation"' in msg and "Speakeasy" in msg and "emulated" in msg and "not proof of absence" in msg
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=sweep, prior_report=None)[0]["content"]
    assert "sweep.emulation" in sys_msg and "OBSERVED" in sys_msg and "never benign" in sys_msg
    inner = {**_CONCEALED, "unpacked": {"packer": "nsis", "inner": [{"packer": "emulated"}]}}
    st.sweep = inner
    assert "\"emulated\" layer" in Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
