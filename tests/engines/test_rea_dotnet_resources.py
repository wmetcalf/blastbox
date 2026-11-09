""".NET embedded resources: hidden payloads, decoys and the benign bar."""

import gzip
import hashlib
import json
import sys
from pathlib import Path

import pytest

from blastbox.engines.rea import dotnet_resources as dr
from blastbox.engines.rea import sufficiency
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import State, unpack
from blastbox.engines.rea.prompts import Framer
from blastbox.engines.rea.runner import rea_env, run_dotnet_resources
from blastbox.limits import Limits
from tests.engines.test_rea_sweep import (  # noqa: F401  (_workdir is an autouse fixture)
    FIXTURES,
    FakeGhidra,
    FakeUnpack,
    _codes,
    _fields,
    _workdir,
    factory,
)

DLL = FIXTURES / "dotnet.dll"
SAMPLE = (FIXTURES / "sample.exe").read_bytes()
dnfile = pytest.importorskip("dnfile")


def _by_name(doc):
    return {r["name"]: r for r in doc["resources"]}


def _hidden(doc):
    return {(h["resource"], h.get("entry")): h for h in doc["hidden"]}


# ------------------------------------------------------------------ the scanner


def test_scan_lists_every_resource_with_size_and_entropy(tmp_path):
    doc = dr.scan(DLL, tmp_path)
    assert doc["resources_total"] == 6
    res = _by_name(doc)
    assert res["Fixture.blob.bin"]["size"] == 72 * 1024 and res["Fixture.blob.bin"]["entropy"] > 7.9
    assert res["Fixture.blob.bin"]["container"] is False
    props = res["Fixture.Properties.Resources.resources"]
    assert props["container"] is True and props["entries_total"] == 3
    entries = {e["name"]: e for e in props["entries"]}
    assert entries["AppTitle"]["type"] == "System.String"
    assert entries["Blob"]["size"] == 66 * 1024 and entries["Blob"]["type"] == "System.ByteArray"
    assert entries["Pad"]["entropy"] == 0.0
    assert res["Fixture.logo.png"]["format"] == "png"


def test_scan_flags_large_high_entropy_resources_and_container_entries(tmp_path):
    hidden = _hidden(dr.scan(DLL, tmp_path))
    blob = hidden[("Fixture.blob.bin", None)]
    assert "decoded" not in blob and (tmp_path / blob["file"]).read_bytes() == dr_bytes("blob")
    entry = hidden[("Fixture.Properties.Resources.resources", "Blob")]
    assert entry["size"] == 66 * 1024 and (tmp_path / entry["file"]).stat().st_size == 66 * 1024
    assert ("Fixture.logo.png", None) not in hidden  # media, not a payload
    assert ("Fixture.Properties.Resources.resources", "Pad") not in hidden


def dr_bytes(seed: str) -> bytes:
    out = bytearray()
    h = seed.encode()
    while len(out) < 72 * 1024:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[: 72 * 1024])


def test_scan_decodes_gzip_xor_and_base64_pes(tmp_path):
    hidden = _hidden(dr.scan(DLL, tmp_path))
    gz = hidden[("Fixture.payload.gz", None)]
    assert gz["decoded"] == "gzip" and (tmp_path / gz["decoded_file"]).read_bytes() == SAMPLE
    x = hidden[("Fixture.x.dat", None)]
    assert x["decoded"] == "xor:0x5a" and (tmp_path / x["decoded_file"]).read_bytes() == SAMPLE[:1024]
    b = hidden[("Fixture.b64.txt", None)]
    assert b["decoded"] == "base64" and (tmp_path / b["decoded_file"]).read_bytes() == SAMPLE[:1024]


def test_scan_notes_loader_member_references(tmp_path):
    refs = dr.scan(DLL, tmp_path)["loader_refs"]
    assert {"Assembly.Load", "Assembly.GetManifestResourceStream", "SymmetricAlgorithm.CreateDecryptor"} <= set(refs)
    assert "Console.WriteLine" not in refs


def test_scan_caps_counts_and_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "MAX_RESOURCES", 2)
    monkeypatch.setattr(dr, "MAX_HIDDEN", 1)
    doc = dr.scan(DLL, tmp_path)
    assert len(doc["resources"]) == 2 and doc["resources_total"] == 6 and len(doc["hidden"]) == 1
    assert len(list(tmp_path.iterdir())) <= 2


def test_decode_only_accepts_a_real_pe_header():
    assert dr.decode(gzip.compress(b"MZ not a pe" * 100)) is None
    assert dr.decode(bytes(b ^ 0x11 for b in b"MZ" + b"\x00" * 200)) is None
    assert dr.decode(SAMPLE) == ("plain", SAMPLE)


def test_decode_caps_decompressed_output(monkeypatch):
    monkeypatch.setattr(dr, "MAX_DECODED_BYTES", 1024)
    assert dr.decode(gzip.compress(SAMPLE)) is None  # the PE is over the cap: not decoded


def test_scan_of_a_non_dotnet_file_is_an_error_not_a_crash(tmp_path):
    doc = dr.scan(FIXTURES / "sample.exe", tmp_path)
    assert doc["error"] == "not_dotnet" and doc["resources"] == []


def test_the_scanner_runs_as_an_isolated_subprocess(tmp_path):
    out = tmp_path / "o"
    status, data = run_dotnet_resources(DLL, out, 60, env=rea_env(tmp_path / "e", {"PATH": "/usr/bin:/bin"}),
                                        python=sys.executable, max_kb=4 * 1024 * 1024, max_stdout=1 << 20,
                                        max_write_bytes=1 << 26)
    assert status == "ok"
    doc = json.loads(data)
    assert doc["resources_total"] == 6 and any(h.get("decoded") == "gzip" for h in doc["hidden"])
    assert all((out / h["file"]).is_file() for h in doc["hidden"] if "file" in h)


def test_the_scanner_subprocess_fails_without_its_python(tmp_path):
    status, _ = run_dotnet_resources(DLL, tmp_path / "o", 60, env={}, python="/nonexistent/python",
                                     max_kb=1 << 20, max_stdout=1 << 20, max_write_bytes=1 << 20)
    assert status == "failed"


# ------------------------------------------------------------------ the sweep


class FakeDotnet:
    """Stands in for run_dotnet_resources: the real scan, in-process (or a fixed status)."""

    def __init__(self, status="ok", doc=None):
        self.status, self.doc = status, doc
        self.calls: list[dict] = []

    def __call__(self, sample, outdir, timeout_s, *, env, python, max_kb, max_stdout, max_write_bytes):
        self.calls.append(dict(sample=sample, outdir=outdir, python=python))
        if self.status != "ok":
            return self.status, b""
        outdir.mkdir(parents=True, exist_ok=True)
        doc = self.doc if self.doc is not None else dr.scan(DLL, outdir)
        return "ok", json.dumps(doc).encode()


def _drun(sample, tmp_path, dotnet):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=FakeGhidra(), unpack_fn=FakeUnpack("failed"),
                            capa_fn=lambda *a, **k: ("ok", b'{"rules": {}}'), dotnet_fn=dotnet)
    return eng.detonate(sample, out, Limits(timeout_s=600)), out


def test_hidden_payloads_become_members_warnings_and_evidence(tmp_path):
    fd = FakeDotnet()
    res, out = _drun(DLL, tmp_path, fd)
    f = _fields(res)
    assert fd.calls and f["kind"] == "dotnet" and f["hidden_payloads"] == 5
    assert _codes(res).count("hidden_payload") == 5
    members = {(out / a.path).read_bytes() for a in res.artifacts if a.id.startswith("member-")}
    assert SAMPLE in members and SAMPLE[:1024] in members and dr_bytes("blob") in members
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["dotnet_resources"]
    assert ev["resources_total"] == 6 and "Assembly.Load" in ev["loader_refs"]
    gz = next(h for h in ev["hidden_payloads"] if h["resource"] == "Fixture.payload.gz")
    assert gz["decoded"] == "gzip" and gz["decoded_sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    assert gz["decoded_member"].startswith("member-") and gz["member"].startswith("member-")
    report = json.loads((out / "report.json").read_text())
    assert report["dotnet_resources"]["resources_total"] == 6


def test_no_hidden_payload_is_zero_and_no_warning(tmp_path):
    doc = {"resources_total": 1, "resources": [{"name": "a", "size": 3, "entropy": 1.0, "container": False}],
           "loader_refs": [], "hidden": []}
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    assert _fields(res)["hidden_payloads"] == 0 and "hidden_payload" not in _codes(res)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dotnet_resources"]["hidden_payloads"] == []


@pytest.mark.parametrize("status", ["failed", "timeout", "too_large"])
def test_a_failed_scan_is_a_warning(tmp_path, status):
    res, _out = _drun(DLL, tmp_path, FakeDotnet(status))
    assert "dotnet_resources_failed" in _codes(res) and "hidden_payloads" not in _fields(res)


def test_a_malformed_scanner_document_is_a_warning(tmp_path):
    res, _out = _drun(DLL, tmp_path, FakeDotnet(doc={"resources": "nope", "hidden": [{"file": "../../etc/x"}]}))
    assert "dotnet_resources_failed" in _codes(res) and "hidden_payloads" not in _fields(res)


def test_scanner_file_names_cannot_escape_its_dir(tmp_path):
    doc = {"resources_total": 1, "resources": [], "loader_refs": [],
           "hidden": [{"resource": "r", "size": 1, "entropy": 8.0, "file": "../../../etc/passwd"}]}
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    for a in res.artifacts:
        if a.id.startswith("member-"):
            assert b"root:" not in (out / a.path).read_bytes()


def test_native_pes_are_not_scanned(tmp_path):
    fd = FakeDotnet()
    _drun(FIXTURES / "sample.exe", tmp_path, fd)
    assert fd.calls == []


# ------------------------------------------------------------------ the bar and the prompts

_HIDDEN_SWEEP = {"dotnet_resources": {"hidden_payloads": [{"resource": "Fixture.Properties.Resources.resources",
                                                           "entry": "Blob", "size": 695889, "entropy": 7.69}]}}


def _report(label):
    return {"verdict": {"label": label, "confidence": "high", "rationale": "r"},
            "sections": [{"key": "execution_flow", "status": "observed"}]}


def test_benign_with_a_hidden_payload_does_not_meet_the_bar():
    s = sufficiency.assess(report=_report("benign"), sweep=_HIDDEN_SWEEP, explored=[])
    gap = next(g for g in s.gaps if g.code == "benign_hidden_payload")
    assert not s.met and "Blob" in gap.detail and "695889" in gap.detail


def test_a_non_benign_verdict_with_a_hidden_payload_is_not_that_gap():
    s = sufficiency.assess(report=_report("malicious"), sweep=_HIDDEN_SWEEP, explored=[])
    assert all(g.code != "benign_hidden_payload" for g in s.gaps)
    assert sufficiency.assess(report=_report("benign"), sweep={"dotnet_resources": {"hidden_payloads": []}},
                              explored=[]).met


def test_the_agent_and_the_report_are_told_about_hidden_payloads_and_decoys():
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=_HIDDEN_SWEEP)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "hidden_payloads" in msg and "decoy" in msg
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=_HIDDEN_SWEEP, prior_report=None)[0]["content"]
    assert "decoy" in sys_msg and "hidden_payloads" in sys_msg


def test_the_scanner_imports_nothing_from_blastbox():
    src = Path(dr.__file__).read_text()
    assert "blastbox" not in src.split('"""', 2)[2]  # it runs under the capa venv's python
