import json
import zipfile
from pathlib import Path

import pytest

from blastbox.contract import Record
from blastbox.engines.rea import ReaSweepEngine
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import unpack
from blastbox.engines.rea.runner import INSPECT_MAP, MAX_MEMBERS, ExtractResult
from blastbox.limits import Limits

FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "fixtures"


class FakeRunner:
    """Stands in for ReaRunner; records every call."""

    instances: list["FakeRunner"] = []

    def __init__(self, rea_bin, env, workdir, *, inspect_fn=None, extract_fn=None):
        self.rea_bin, self.env, self.workdir = rea_bin, dict(env), Path(workdir)
        self.inspect_calls: list[tuple[str, Path, float]] = []
        self.extract_calls: list[tuple[Path, Path, float]] = []
        self._inspect_fn = inspect_fn
        self._extract_fn = extract_fn
        FakeRunner.instances.append(self)

    def inspect(self, cmd, sample, timeout_s):
        self.inspect_calls.append((cmd, sample, timeout_s))
        if self._inspect_fn:
            return self._inspect_fn(cmd)
        return {"ok": True, "result": {"cmd": cmd, "nested": [{"s": f"beacon http://{cmd}.example/x"}]}}

    def extract(self, sample, outdir, timeout_s):
        self.extract_calls.append((sample, outdir, timeout_s))
        if self._extract_fn:
            return self._extract_fn(outdir)
        return ExtractResult()


def factory(**kw):
    FakeRunner.instances = []

    def make(rea_bin, env, workdir):
        return FakeRunner(rea_bin, env, workdir, **kw)

    return make


class FakeGhidra:
    def __init__(self, status="ok", strings=None):
        self.status = status
        self.strings = strings if strings is not None else [
            {"address": "0x401000", "value": "GET http://evil.example/a.php?x=1"},
            {"address": "0x402000", "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ]
        self.calls: list[dict] = []

    def __call__(self, sample, project_dir, timeout_s, *, env, post_script=None, **kw):
        self.calls.append(dict(sample=sample, project_dir=project_dir, timeout_s=timeout_s,
                               env=dict(env), post_script=post_script))
        if self.status == "ok":
            project_dir.mkdir(parents=True, exist_ok=True)
            (project_dir / "sample.gpr").write_text("gpr")
            (project_dir / "sample.rep").mkdir(exist_ok=True)
            (project_dir / "sample.rep" / "db").write_text("db")
            if post_script is not None:
                post_script[2].write_text("".join(json.dumps(s) + "\n" for s in self.strings))
        return self.status


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    wd = tmp_path / "work"
    wd.mkdir()
    monkeypatch.setenv("BLASTBOX_WORK_DIR", str(wd))
    monkeypatch.setenv("REA_BIN", "/opt/rea/bin/rea")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
    monkeypatch.setenv("REA_GHIDRA_SCRIPTS", str(tmp_path / "scripts"))
    monkeypatch.setenv("REA_OPENAI_API_KEY", "sk-secret")
    monkeypatch.delenv("REA_GHIDRA_SWEEP_S", raising=False)
    return wd


def _run(sample: Path, tmp_path: Path, *, runner=None, ghidra=None, limits=None):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    ghidra = ghidra or FakeGhidra()
    eng = ReaSweepEngine(runner_factory=runner or factory(), ghidra_fn=ghidra)
    res = eng.detonate(sample, out, limits or Limits(timeout_s=600))
    return res, out, ghidra


def _fields(res) -> dict:
    assert isinstance(res.payload, Record)
    return res.payload.fields


def _by_id(res) -> dict:
    return {a.id: a for a in res.artifacts}


def _iocs(fields) -> list[tuple[str, str, str]]:
    io = fields["iocs"].fields
    return list(zip(io["type"], io["value"], io["source"]))


def _codes(res) -> list[str]:
    return [w.code for w in res.warnings]


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", "hello")
    return path


# ------------------------------------------------------------------- PE
def test_engine_identity() -> None:
    assert ReaSweepEngine.name == "rea"
    assert ReaSweepEngine.formats == frozenset({"*"})
    assert ReaSweepEngine.jobs_per_recycle == 1


def test_pe_full_sweep(tmp_path: Path, _workdir: Path) -> None:
    res, out, ghidra = _run(FIXTURES / "sample.exe", tmp_path)
    f = _fields(res)
    assert res.status == "ok"
    assert f["schema"] == "rea.report/1" and f["kind"] == "pe"
    runner = FakeRunner.instances[0]
    assert [c[0] for c in runner.inspect_calls] == list(INSPECT_MAP["pe"])
    assert set(f["inspect"].fields) == set(INSPECT_MAP["pe"])
    assert all(r.fields["ok"] is True for r in f["inspect"].fields.values())
    # no extract for PE
    assert runner.extract_calls == []
    # IOCs from inspect strings and from the Ghidra strings dump
    iocs = _iocs(f)
    assert ("url", "http://inspect-pe-imports.example/x", "inspect:inspect-pe-imports") in iocs
    assert ("url", "http://evil.example/a.php?x=1", "ghidra:0x401000") in iocs
    assert any(t == "registry" and s == "ghidra:0x402000" for t, _v, s in iocs)
    # icons
    arts = _by_id(res)
    assert arts["icon-0"].kind == "icon" and (out / arts["icon-0"].path).read_bytes()[:4] == b"\x89PNG"
    assert f["icons"] == 1 and f["members"] == 0
    # ghidra called with the post script, absolute, in the job dir
    call = ghidra.calls[0]
    assert call["post_script"][0] == tmp_path / "scripts"
    assert call["post_script"][1] == "ListStrings.java"
    assert call["timeout_s"] <= 420
    assert "REA_OPENAI_API_KEY" not in call["env"]
    assert call["env"]["TMPDIR"].startswith(str(_workdir))
    # continuation has the project
    cont = arts["continuation"]
    assert cont.kind == "rea_continuation"
    sample, proj, state = unpack(out / cont.path, tmp_path / "unp", max_bytes=1 << 30)
    assert proj is not None and (proj / "sample.gpr").exists()
    assert state.pass_no == 0 and state.ghidra_status == "ok"
    assert state.program_name == "sample.exe" and sample.name == "sample.exe"
    assert f["ghidra_status"] == "ok" and f["more_pending"] is True
    # report
    rep = json.loads((out / arts["report"].path).read_text())
    assert arts["report"].kind == "report"
    assert rep["schema"] == "rea.report/1"
    assert rep["inspect_results"]["inspect-pe-imports"]["result"]["cmd"] == "inspect-pe-imports"
    assert {"type": "url", "value": "http://evil.example/a.php?x=1", "source": "ghidra:0x401000"} in rep["iocs"]
    # the per-job work dir is cleaned up, and nothing escaped to the out dir
    assert list(_workdir.iterdir()) == []


def test_runner_gets_job_dir_under_work_dir(tmp_path: Path, _workdir: Path) -> None:
    _run(FIXTURES / "sample.exe", tmp_path)
    r = FakeRunner.instances[0]
    assert r.workdir.parents[1] == _workdir and r.workdir.parent.name.startswith("rea-sweep-")
    assert r.rea_bin == "/opt/rea/bin/rea"


# ------------------------------------------------------------------- ZIP
def test_zip_members_capped_no_ghidra(tmp_path: Path) -> None:
    def extract(outdir: Path) -> ExtractResult:
        outdir.mkdir(parents=True, exist_ok=True)
        files = []
        for n in range(MAX_MEMBERS):
            p = outdir / f"member-{n}"
            p.write_bytes(b"m%d" % n)
            files.append(p)
        return ExtractResult(files=files, dropped=[("x/257.bin", "member_cap"), ("evil", "not_regular")])

    res, out, ghidra = _run(_zip(tmp_path / "a.zip"), tmp_path, runner=factory(extract_fn=extract))
    f = _fields(res)
    arts = _by_id(res)
    members = [a for a in res.artifacts if a.kind == "extracted"]
    assert len(members) == 256 and f["members"] == 256
    assert arts["member-0"].kind == "extracted" and (out / arts["member-255"].path).read_bytes() == b"m255"
    assert "members_capped" in _codes(res)
    assert "member_dropped" in _codes(res)
    assert ghidra.calls == []
    assert f["kind"] == "archive" and f["ghidra_status"] == "skipped" and f["more_pending"] is False
    # no pass can follow an archive sweep: no continuation is packed or declared
    assert "continuation" not in arts
    assert not (out / "continuation.tar.gz").exists()


def test_extract_error_is_warning(tmp_path: Path) -> None:
    res, _out, _g = _run(_zip(tmp_path / "a.zip"), tmp_path,
                         runner=factory(extract_fn=lambda o: ExtractResult(error="timeout")))
    assert res.status == "ok" and "extract_failed" in _codes(res)


# ---------------------------------------------------------- ghidra timeout
def test_ghidra_timeout_still_ok(tmp_path: Path) -> None:
    # Ruling AL: a Ghidra timeout still seals ok with the inspect evidence, but no longer chains.
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="timeout"))
    f = _fields(res)
    assert res.status == "ok"
    assert f["ghidra_status"] == "timeout" and f["more_pending"] is False
    assert f["chain_stop"] == "ghidra_timeout"
    assert set(f["inspect"].fields) == set(INSPECT_MAP["pe"])
    assert any(s.startswith("inspect:") for _t, _v, s in _iocs(f))
    assert "continuation" not in _by_id(res) and not (out / "continuation.tar.gz").exists()
    assert "ghidra_timeout" in _codes(res)


def test_ghidra_failed_not_pending(tmp_path: Path) -> None:
    res, _out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(status="failed"))
    f = _fields(res)
    assert f["kind"] == "elf" and f["ghidra_status"] == "failed" and f["more_pending"] is False
    assert res.status == "ok"
    assert "continuation" not in _by_id(res)


def test_ghidra_exception_is_failed(tmp_path: Path) -> None:
    def boom(*a, **kw):
        raise OSError("no java")

    out = tmp_path / "out"
    out.mkdir()
    res = ReaSweepEngine(runner_factory=factory(), ghidra_fn=boom).detonate(
        FIXTURES / "sample.elf", out, Limits(timeout_s=600))
    assert res.status == "ok" and _fields(res)["ghidra_status"] == "failed"


def test_ghidra_budget_from_env_clamped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REA_GHIDRA_SWEEP_S", "30")
    _res, _o, g = _run(FIXTURES / "sample.elf", tmp_path)
    assert 0 < g.calls[0]["timeout_s"] <= 30
    # clamped to the job's remaining time
    monkeypatch.setenv("REA_GHIDRA_SWEEP_S", "100000")
    out2 = tmp_path / "o2"
    out2.mkdir()
    g2 = FakeGhidra()
    ReaSweepEngine(runner_factory=factory(), ghidra_fn=g2).detonate(
        FIXTURES / "sample.elf", out2, Limits(timeout_s=120))
    assert g2.calls[0]["timeout_s"] < 120


@pytest.mark.parametrize("raw", ["abc", "-5", "0", "nan"])
def test_ghidra_budget_bad_env_falls_back(tmp_path: Path, monkeypatch, raw: str) -> None:
    monkeypatch.setenv("REA_GHIDRA_SWEEP_S", raw)
    _res, _o, g = _run(FIXTURES / "sample.elf", tmp_path)
    assert 400 <= g.calls[0]["timeout_s"] <= 420


def test_non_native_skips_ghidra(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_text("plain text mentions 10.1.2.3")
    res, _o, g = _run(p, tmp_path)
    f = _fields(res)
    assert g.calls == [] and f["kind"] == "other" and f["ghidra_status"] == "skipped"
    assert f["more_pending"] is False
    assert "continuation" not in _by_id(res)
    assert [c[0] for c in FakeRunner.instances[0].inspect_calls] == list(INSPECT_MAP["other"])


# ------------------------------------------------------------ inspect failure
def test_one_inspect_failure_is_warning(tmp_path: Path) -> None:
    def insp(cmd):
        if cmd == "inspect-pe-certificates":
            return {"ok": False, "error": "timeout"}
        if cmd == "inspect-go-binary":
            raise FileNotFoundError("rea missing")
        return {"ok": True, "result": {"v": "x"}}

    res, _o, _g = _run(FIXTURES / "sample.exe", tmp_path, runner=factory(inspect_fn=insp))
    f = _fields(res)
    assert res.status == "ok"
    ins = f["inspect"].fields
    assert ins["inspect-pe-certificates"].fields == {"ok": False, "error": "timeout"}
    assert ins["inspect-go-binary"].fields["ok"] is False
    assert ins["inspect-pe-imports"].fields["ok"] is True
    assert _codes(res).count("inspect_failed") == 2


# ------------------------------------------------------------ ghidra strings
def test_ghidra_strings_bad_lines_and_cap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sw, "MAX_STRINGS_BYTES", 400)
    good = [{"address": f"0x{i:x}", "value": f"http://h{i}.example/"} for i in range(20)]

    class G(FakeGhidra):
        def __call__(self, sample, project_dir, timeout_s, *, env, post_script=None, **kw):
            st = super().__call__(sample, project_dir, timeout_s, env=env, post_script=post_script)
            txt = "not json\n" + json.dumps({"address": 5, "value": "x"}) + "\n"
            txt += "".join(json.dumps(s) + "\n" for s in good)
            post_script[2].write_text(txt)
            return st

    res, _o, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=G())
    srcs = [s for _t, _v, s in _iocs(_fields(res)) if s.startswith("ghidra:")]
    assert srcs and len(srcs) < 20  # capped by bytes
    assert "ghidra_strings_truncated" in _codes(res)
    assert "ghidra_strings_malformed" in _codes(res)


def test_iocs_limit(tmp_path: Path) -> None:
    strings = [{"address": f"0x{i:x}", "value": f"http://h{i}.example/"} for i in range(3000)]
    res, out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(strings=strings))
    f = _fields(res)
    assert f["iocs_total"] == 2048
    assert "iocs_capped" in _codes(res)


# ------------------------------------------------------------------ report
def test_report_truncated_over_cap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sw, "MAX_REPORT_BYTES", 20000)
    big = "A" * 50000
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path,
                        runner=factory(inspect_fn=lambda c: {"ok": True, "result": {"blob": big}}))
    arts = _by_id(res)
    data = (out / arts["report"].path).read_bytes()
    assert len(data) <= 20000
    rep = json.loads(data)
    assert rep["inspect_results"]["inspect-pe-imports"] == {"ok": True, "truncated": True}
    assert "report_truncated" in _codes(res)


def test_payload_fits_metadata_budget(tmp_path: Path) -> None:
    strings = [{"address": f"0x{i:x}", "value": "http://x.example/" + "a" * 4000 + str(i)} for i in range(2048)]
    res, _o, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(strings=strings))
    size = len(res.payload.model_dump_json(by_alias=True))
    assert size < Limits().max_metadata_bytes // 2
    assert "iocs_payload_truncated" in _codes(res)
    assert _fields(res)["iocs_total"] == 2048


# --------------------------------------------------------- artifact limits
def test_artifact_budget_respected(tmp_path: Path) -> None:
    def extract(outdir: Path) -> ExtractResult:
        outdir.mkdir(parents=True, exist_ok=True)
        files = []
        for n in range(10):
            p = outdir / f"member-{n}"
            p.write_bytes(b"x" * (2000 if n == 3 else 10))
            files.append(p)
        return ExtractResult(files=files)

    lim = Limits(timeout_s=600, max_artifacts=7, max_artifact_bytes=1 << 20)
    res, out, _g = _run(_zip(tmp_path / "a.zip"), tmp_path, runner=factory(extract_fn=extract), limits=lim)
    assert len(res.artifacts) <= 7
    ids = _by_id(res)
    assert "continuation" not in ids and "report" in ids  # an archive never chains
    assert "artifact_budget" in _codes(res)
    # undeclared files were removed from outdir
    declared = {a.path for a in res.artifacts}
    on_disk = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    assert on_disk == declared


def test_member_over_artifact_size_dropped(tmp_path: Path) -> None:
    def extract(outdir: Path) -> ExtractResult:
        outdir.mkdir(parents=True, exist_ok=True)
        a, b = outdir / "member-0", outdir / "member-1"
        a.write_bytes(b"x" * 5000)
        b.write_bytes(b"y")
        return ExtractResult(files=[a, b])

    lim = Limits(timeout_s=600, max_artifact_bytes=4096)
    res, _o, _g = _run(_zip(tmp_path / "a.zip"), tmp_path, runner=factory(extract_fn=extract), limits=lim)
    members = [a for a in res.artifacts if a.kind == "extracted"]
    assert [m.path for m in members] == ["members/member-1"]
    assert "artifact_budget" in _codes(res)


def test_continuation_too_large_not_pending(tmp_path: Path) -> None:
    lim = Limits(timeout_s=600, max_artifact_bytes=1024)
    res, _o, _g = _run(FIXTURES / "sample.exe", tmp_path, limits=lim)
    assert "continuation" not in _by_id(res)
    assert _fields(res)["more_pending"] is False
    assert "continuation_too_large" in _codes(res)


def test_no_tmp_literal_in_source() -> None:
    assert '"/tmp' not in Path(sw.__file__).read_text()


# ------------------------------------------------- IOC false positives (I4)
def test_version_and_go_symbol_noise_dropped_real_iocs_kept(tmp_path: Path) -> None:
    strings = [
        {"address": "0x1400106ae", "value": "FileVersion"},
        {"address": "0x1400106c8", "value": "1.0.0.0"},
        {"address": "0x1400106d0", "value": "8.0.0.0"},
        {"address": "0x401100", "value": "runtime.link"},
        {"address": "0x401200", "value": "godebugs.Info"},
        {"address": "0x401300", "value": "runtime.work"},
        {"address": "0x401400", "value": "beacon 185.220.101.47 via cdn-update.info"},
    ]
    res, _o, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(strings=strings),
                       runner=factory(inspect_fn=lambda cmd: {"ok": True, "result": {}}))
    got = {(t, v) for t, v, _s in _iocs(_fields(res))}
    assert ("ipv4", "185.220.101.47") in got and ("domain", "cdn-update.info") in got
    assert not {("ipv4", "1.0.0.0"), ("ipv4", "8.0.0.0")} & got
    assert not {v for t, v in got if t == "domain"} & {"runtime.link", "godebugs.info", "runtime.work"}


def test_utf16le_url_in_native_sample_bytes(tmp_path: Path) -> None:
    url = "https://loadout-dotnet-fixture.example.net/api/v1"
    sample = tmp_path / "s.exe"
    # a .NET #US heap entry: length byte, UTF-16LE chars, trailing flag byte
    sample.write_bytes((FIXTURES / "sample.exe").read_bytes() + b"\x63" + url.encode("utf-16-le") + b"\x00")
    res, _o, _g = _run(sample, tmp_path, ghidra=FakeGhidra(strings=[]),
                       runner=factory(inspect_fn=lambda cmd: {"ok": True, "result": {}}))
    rows = _iocs(_fields(res))
    assert ("url", url) in {(t, v) for t, v, _s in rows}
    assert ("domain", "loadout-dotnet-fixture.example.net") in {(t, v) for t, v, _s in rows}
    assert all(s.startswith("utf16le:0x") for t, v, s in rows if v == url)


def test_utf16le_scan_skipped_for_non_native(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_bytes("see http://wide.example/x".encode("utf-16-le"))
    res, _o, _g = _run(p, tmp_path, runner=factory(inspect_fn=lambda cmd: {"ok": True, "result": {}}))
    assert _iocs(_fields(res)) == []


# ------------------------------------------------------- chain_stop (Ruling AL)
from tests.engines.test_rea_triage import X, make_elf32, make_pe  # noqa: E402


def _not_pending(res, out, stop):
    f = _fields(res)
    assert f["more_pending"] is False and f["chain_stop"] == stop
    assert "continuation" not in _by_id(res) and not (out / "continuation.tar.gz").exists()
    assert sw.CHAIN_STOPS == ("ghidra_timeout", "ghidra_failed", "packed", "unsupported_arch", "not_native")


def test_chain_stop_absent_when_chaining(tmp_path):
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path)
    f = _fields(res)
    assert f["more_pending"] is True and "chain_stop" not in f
    assert "chain_stop" not in json.loads((tmp_path / "out" / "report.json").read_text())


def test_chain_stop_ghidra_timeout_packs_no_continuation(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="timeout"))
    _not_pending(res, out, "ghidra_timeout")
    assert json.loads((out / "report.json").read_text())["chain_stop"] == "ghidra_timeout"


def test_chain_stop_ghidra_failed(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(status="failed"))
    _not_pending(res, out, "ghidra_failed")


def test_chain_stop_not_native_for_archives_and_apks(tmp_path):
    res, out, _g = _run(_zip(tmp_path / "a.zip"), tmp_path)
    _not_pending(res, out, "not_native")
    apk = tmp_path / "x.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "x")
    res, out, _g = _run(apk, tmp_path)
    assert _fields(res)["kind"] == "apk"
    _not_pending(res, out, "not_native")


def test_chain_stop_packed_upx(tmp_path):
    p = make_pe(tmp_path / "upx.exe", [(b"UPX0", X, b""), (b"UPX1", X, b"\x90" * 4096)])
    res, out, _g = _run(p, tmp_path)
    _not_pending(res, out, "packed")


def test_chain_stop_packed_from_function_count(tmp_path):
    import os as _os
    p = make_pe(tmp_path / "hi.exe", [(b".text", X, _os.urandom(64 * 1024))])
    few = FakeGhidra(strings=[{"function_count": 4}, {"address": "0x401000", "value": "hello"}])
    res, out, _g = _run(p, tmp_path, ghidra=few)
    _not_pending(res, out, "packed")
    many = FakeGhidra(strings=[{"function_count": 300}])
    res, _out, _g = _run(p, tmp_path, ghidra=many)
    assert _fields(res)["more_pending"] is True and "chain_stop" not in _fields(res)


def test_function_count_line_is_not_a_bad_string_line(tmp_path):
    g = FakeGhidra(strings=[{"function_count": 300}, {"address": "0x401000", "value": "http://a.example/x"}])
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=g)
    assert "ghidra_strings_malformed" not in _codes(res)
    assert ("url", "http://a.example/x", "ghidra:0x401000") in _iocs(_fields(res))


def test_chain_stop_unsupported_arch_mips1(tmp_path):
    p = make_elf32(tmp_path / "mips.elf", machine=8, flags=0x1007, segments=[(5, b"\x00" * 4096)])
    res, out, _g = _run(p, tmp_path)
    f = _fields(res)
    assert f["kind"] == "elf" and f["ghidra_status"] == "ok"
    _not_pending(res, out, "unsupported_arch")


def test_chain_stop_priority_with_combined_conditions(tmp_path):
    mips = make_elf32(tmp_path / "m.elf", machine=8, flags=0x1007, segments=[(5, b"\x00" * 16 + b"UPX!" + b"\x00" * 4096)])
    res, out, _g = _run(mips, tmp_path, ghidra=FakeGhidra(status="timeout"))
    _not_pending(res, out, "ghidra_timeout")
    res, out, _g = _run(mips, tmp_path)  # UPX! magic + MIPS-I: the arch wins
    _not_pending(res, out, "unsupported_arch")
    res, out, _g = _run(mips, tmp_path, ghidra=FakeGhidra(status="failed"))
    _not_pending(res, out, "ghidra_failed")


def test_unknown_ghidra_status_is_failed_not_timeout(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="weird"))
    _not_pending(res, out, "ghidra_failed")
    assert sw.ReaSweepEngine._chain_stop(FIXTURES / "sample.exe", "pe", "skipped", None) == "ghidra_failed"


# ------------------------------------------- Go packed string table (G3, live 2026-11-03)
def _go_fixture():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rea_go_fixture", Path(__file__).resolve().parent / "fixtures" / "rea" / "go_fixture.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_go_iocs_end_at_the_literal_not_in_the_next_packed_string(tmp_path: Path) -> None:
    gf = _go_fixture()
    sample = tmp_path / "benign_go.elf"
    sample.write_bytes(gf.go_elf())
    # Ghidra-style defined strings run on through the packed table into the strconv digits.
    strings = [{"address": "0x4b823d", "value": gf.URL_OVERRUN},
               {"address": "0x4b22f5", "value": "198.51.100.233814697265625wakeableSleep"}]
    res, _o, _g = _run(sample, tmp_path, ghidra=FakeGhidra(strings=strings),
                       runner=factory(inspect_fn=lambda cmd: {"ok": True, "result": {}}))
    rows = _iocs(_fields(res))
    got = {(t, v) for t, v, _s in rows}
    assert ("url", gf.URL) in got and ("ipv4", gf.IP) in got
    assert ("domain", "loadout-go-fixture.example.org") in got
    assert not [v for t, v in got if t == "url" and v != gf.URL]
    assert dict(((t, v), s) for t, v, s in rows)[("url", gf.URL)] == "gostring:0x4b823d"


def test_go_literals_skipped_for_non_go_native(tmp_path: Path) -> None:
    res, _o, _g = _run(FIXTURES / "sample.exe", tmp_path,
                       runner=factory(inspect_fn=lambda cmd: {"ok": True, "result": {}}))
    assert not [s for _t, _v, s in _iocs(_fields(res)) if s.startswith("gostring:")]
