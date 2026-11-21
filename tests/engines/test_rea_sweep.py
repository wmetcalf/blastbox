import json
import zipfile
from pathlib import Path

import pytest

from blastbox.contract import Record
from blastbox.engines.rea import ReaSweepEngine
from blastbox.engines.rea import signatures as sig
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
                               env=dict(env), post_script=post_script, kw=kw))
        if self.status in ("ok", "partial"):
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


class FakeUnpack:
    """Stands in for upx_unpack: writes ``image`` to dest on "ok"."""

    def __init__(self, status="ok", image=None):
        self.status, self.image = status, image
        self.calls: list[dict] = []

    def __call__(self, sample, dest, timeout_s, *, env, max_bytes):
        self.calls.append(dict(sample=sample, dest=dest, timeout_s=timeout_s, max_bytes=max_bytes))
        if self.status == "ok":
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.image if self.image is not None else (FIXTURES / "sample.exe").read_bytes())
        return self.status


class FakeCapa:
    """Stands in for run_capa: returns ``doc`` as capa's JSON on "ok"."""

    def __init__(self, status="ok", doc=None):
        self.status, self.doc = status, doc if doc is not None else {"rules": {}}
        self.calls: list[dict] = []

    def __call__(self, sample, kind, timeout_s, *, env, capa_bin, rules, signatures, max_kb, max_stdout):
        self.calls.append(dict(sample=sample, kind=kind, timeout_s=timeout_s, max_kb=max_kb))
        return (self.status, json.dumps(self.doc).encode() if self.status == "ok" else b"")


class FakeSignatures:
    """Stands in for signatures.scan: every target gets a slot, ``rules`` match in the first one."""

    def __init__(self, status="ok", rules=(), reason="", raises=None):
        self.status, self.rules, self.reason, self.raises = status, rules, reason, raises
        self.calls: list[dict] = []

    def __call__(self, targets, *, timeout_s, cwd):
        self.calls.append(dict(labels=[t.label for t in targets], paths=[t.path for t in targets],
                               timeout_s=timeout_s, cwd=cwd))
        if self.raises is not None:
            raise self.raises
        if self.status == "unavailable":
            return sig.SigResult("unavailable", "no yara interpreter in this image")
        slots = [{"label": t.label, "sha256": f"{i:064x}", "size": t.path.stat().st_size}
                 for i, t in enumerate(targets)]
        matches = [{"rule": r, "family": fam, "target": slots[0]["label"], "sha256": slots[0]["sha256"],
                    "meta": {"cape_type": f"{fam} Payload"}} for r, fam in self.rules]
        return sig.SigResult(self.status, self.reason, rules_total=135, targets=slots, matches=matches,
                             matches_total=len(matches))


def _run(sample: Path, tmp_path: Path, *, runner=None, ghidra=None, limits=None, unpack=None, capa=None,
         signatures=None):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    ghidra = ghidra or FakeGhidra()
    eng = ReaSweepEngine(runner_factory=runner or factory(), ghidra_fn=ghidra, unpack_fn=unpack or FakeUnpack("failed"),
                         capa_fn=capa or FakeCapa(), signatures_fn=signatures or FakeSignatures("unavailable"))
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
def _bare():
    """A runner whose inspect commands find nothing: a sweep with no evidence to report from."""
    return factory(inspect_fn=lambda cmd: {"ok": True, "result": {}})


@pytest.mark.parametrize("status", ["timeout", "failed"])
def test_ghidra_stop_with_evidence_chains_without_a_project(tmp_path: Path, status: str) -> None:
    # Live (cape7): 5 of 20 samples sealed no report for a Ghidra timeout while the sweep held
    # IOCs, an unwrapped installer or emulation captures. The chain goes on from that evidence.
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status=status))
    f = _fields(res)
    assert res.status == "ok"
    assert f["ghidra_status"] == status and f["more_pending"] is True and "chain_stop" not in f
    assert set(f["inspect"].fields) == set(INSPECT_MAP["pe"])
    assert any(s.startswith("inspect:") for _t, _v, s in _iocs(f))
    assert f"ghidra_{status}" in _codes(res)
    assert _by_id(res)["continuation"].kind == "rea_continuation"
    _s, project, st = unpack(out / "continuation.tar.gz", tmp_path / "chk", max_bytes=1 << 26)
    assert project is None and st.program_name is None and st.ghidra_status == status
    assert st.sweep["iocs"] and "chain_stop" not in json.loads((out / "report.json").read_text())


def test_ghidra_stop_keeps_its_chain_stop_when_the_evidence_cannot_be_packed(tmp_path: Path) -> None:
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="timeout"),
                        limits=Limits(timeout_s=600, max_artifact_bytes=600))
    f = _fields(res)
    assert f["more_pending"] is False and f["chain_stop"] == "ghidra_timeout"
    assert "continuation" not in _by_id(res) and "continuation_too_large" in _codes(res)


def test_ghidra_gets_the_profile_and_an_analysis_cut_short_of_the_kill(tmp_path: Path, monkeypatch) -> None:
    # Live (cape7): 5 of 20 samples ended in ghidra_timeout. Every PE now gets the trimmed profile,
    # and Ghidra is told to stop its own analysis before the sweep's kill.
    _res, _o, g = _run(FIXTURES / "sample.exe", tmp_path)
    call = g.calls[0]
    assert call["kw"]["profile"] == "light"
    assert call["kw"]["analysis_timeout_s"] == int(call["timeout_s"]) - 60 > 0
    _res, _o, g = _run(FIXTURES / "sample.elf", tmp_path / "elf")
    assert g.calls[0]["kw"]["profile"] == "full"  # a small ELF with no Go or Rust runtime
    # too short a budget to cut inside: the kill is the only limit
    monkeypatch.setenv("REA_GHIDRA_SWEEP_S", "100")
    _res, _o, g = _run(FIXTURES / "sample.exe", tmp_path / "short")
    assert g.calls[0]["kw"]["analysis_timeout_s"] is None


def test_a_cut_ghidra_analysis_is_a_usable_project_the_agent_is_warned_about(tmp_path: Path) -> None:
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="partial"))
    f = _fields(res)
    assert f["ghidra_status"] == "ok" and f["more_pending"] is True and "chain_stop" not in f
    assert "ghidra_partial" in _codes(res) and "ghidra_timeout" not in _codes(res)
    assert any(s.startswith("ghidra") for _t, _v, s in _iocs(f))  # its strings were still read
    _s, project, st = unpack(out / "continuation.tar.gz", tmp_path / "chk", max_bytes=1 << 26)
    assert project is not None and st.ghidra_status == "ok" and st.sweep["ghidra_analysis"] == "cut"
    # a complete analysis leaves no such mark
    _res, out2, _g = _run(FIXTURES / "sample.exe", tmp_path / "full")
    _s, _p, st2 = unpack(out2 / "continuation.tar.gz", tmp_path / "chk2", max_bytes=1 << 26)
    assert "ghidra_analysis" not in st2.sweep


def test_ghidra_failed_not_pending(tmp_path: Path) -> None:
    res, _out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(status="failed"), runner=_bare())
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
    # Nothing to report from: the timeout ends the chain, as before.
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="timeout"), runner=_bare())
    _not_pending(res, out, "ghidra_timeout")
    assert json.loads((out / "report.json").read_text())["chain_stop"] == "ghidra_timeout"


def test_chain_stop_ghidra_failed(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=FakeGhidra(status="failed"), runner=_bare())
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
    assert "unpack_failed" in _codes(res) and "unpacked" not in _fields(res)


def test_upx_sample_is_unpacked_and_the_image_analysed(tmp_path):
    import hashlib
    p = make_pe(tmp_path / "upx.exe", [(b"UPX0", X, b""), (b"UPX1", X, b"\x90" * 4096)])
    image = (FIXTURES / "sample.exe").read_bytes()
    up = FakeUnpack("ok", image)
    res, out, g = _run(p, tmp_path, unpack=up)
    f = _fields(res)
    assert up.calls[0]["sample"] == p and up.calls[0]["dest"].name == "upx.exe"
    assert up.calls[0]["max_bytes"] == sw.MAX_UNPACKED_BYTES
    assert g.calls[0]["sample"] == up.calls[0]["dest"]  # Ghidra sees the unpacked image
    assert f["unpacked"] == "upx" and f["unpacked_sha256"] == hashlib.sha256(image).hexdigest()
    assert f["more_pending"] is True and "chain_stop" not in f and "unpack_failed" not in _codes(res)
    sample, _proj, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sample_name == "upx.exe" and sample.read_bytes() == image
    assert state.sweep["unpacked"] == {"packer": "upx", "packed_sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def test_unmarked_samples_are_never_unpacked(tmp_path):
    up = FakeUnpack("ok")
    _run(FIXTURES / "sample.exe", tmp_path, unpack=up)
    _run(FIXTURES / "sample.elf", tmp_path, unpack=up)
    assert up.calls == []


def test_unpack_exception_is_a_warning(tmp_path):
    p = make_pe(tmp_path / "upx.exe", [(b"UPX0", X, b""), (b"UPX1", X, b"\x90" * 4096)])

    def boom(*a, **kw):
        raise OSError("no upx")

    res, out, _g = _run(p, tmp_path, unpack=boom)
    assert _fields(res)["chain_stop"] == "packed" and "unpack_failed" in _codes(res)


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
    res, out, _g = _run(mips, tmp_path, ghidra=FakeGhidra(status="timeout"), runner=_bare())
    _not_pending(res, out, "ghidra_timeout")
    res, out, _g = _run(mips, tmp_path)  # UPX! magic + MIPS-I: the arch wins
    _not_pending(res, out, "unsupported_arch")
    res, out, _g = _run(mips, tmp_path, ghidra=FakeGhidra(status="failed"), runner=_bare())
    _not_pending(res, out, "ghidra_failed")


def test_unknown_ghidra_status_is_failed_not_timeout(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, ghidra=FakeGhidra(status="weird"), runner=_bare())
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


def test_continuation_carries_the_sweep_evidence_for_the_report(tmp_path: Path) -> None:
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path)
    _s, _p, st = unpack(out / "continuation.tar.gz", tmp_path / "chk", max_bytes=1 << 26)
    assert st.sweep["kind"] == _fields(res)["kind"]
    assert {"type": "url", "value": "http://evil.example/a.php?x=1", "source": "ghidra:0x401000"} in st.sweep["iocs"]
    assert st.analysis_report is None


CAPA_DOC = {
    "meta": {"analysis": {"base_address": {"type": "absolute", "value": 0x2000000},
                          "layout": {"functions": [{"address": {"type": "absolute", "value": 0x2001000},
                                                    "matched_basic_blocks": []}]}}},
    "rules": {"create reverse shell": {"meta": {"namespace": "communication/c2/shell", "lib": False,
                                                "is_subscope_rule": False, "attack": [{"id": "T1059"}],
                                                "mbc": []},
                                       "matches": [[{"type": "absolute", "value": 0x2001000}, {}]]}},
}


def test_capa_capabilities_are_rebased_and_reach_payload_report_and_continuation(tmp_path):
    ghidra = FakeGhidra(strings=[{"function_count": 40, "image_base": "0x100000"},
                                 {"address": "0x101000", "value": "hello"}])
    fc = FakeCapa(doc=CAPA_DOC)
    seen_ghidra = []
    real_call = fc.__call__

    def capa_after_ghidra(*a, **kw):
        seen_ghidra.append(len(ghidra.calls))  # capa runs after Ghidra, never beside it
        return real_call(*a, **kw)

    res, out, _g = _run(FIXTURES / "sample.elf", tmp_path, ghidra=ghidra, capa=capa_after_ghidra)
    assert seen_ghidra == [1]
    f = _fields(res)
    assert fc.calls[0]["kind"] == "elf" and fc.calls[0]["max_kb"] == sw.CAPA_MAX_KB
    assert f["capa_status"] == "ok" and f["capabilities_total"] == 1
    assert f["capabilities"].fields == {"rule": ["create reverse shell"], "namespace": ["communication/c2/shell"],
                                        "attack": ["T1059"]}
    report = json.loads((out / "report.json").read_text())
    assert report["capabilities"][0]["functions"] == ["0x101000"]  # vivisect 0x2001000 -> Ghidra's image
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["capabilities"] == report["capabilities"]


def test_capa_runs_only_on_pe_elf_dotnet(tmp_path):
    fc = FakeCapa()
    _run(FIXTURES / "sample.exe", tmp_path, capa=fc)
    assert [c["kind"] for c in fc.calls] == ["pe"]
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.txt", "hi")
    res, _out, _g = _run(z, tmp_path, capa=fc)
    assert len(fc.calls) == 1 and "capa_status" not in _fields(res)


@pytest.mark.parametrize("capa_fn,status,code", [
    (FakeCapa("unsupported"), "unsupported", None),
    (FakeCapa("timeout"), "timeout", "capa_timeout"),
    (lambda *a, **kw: (_ for _ in ()).throw(OSError("no capa")), "failed", "capa_failed"),
])
def test_capa_failures_are_warnings_and_the_sweep_goes_on(tmp_path, capa_fn, status, code):
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path, capa=capa_fn)
    f = _fields(res)
    assert res.status == "ok" and f["capa_status"] == status and f["capabilities_total"] == 0
    assert "capabilities" not in f
    assert (code in _codes(res)) if code else not any(c.startswith("capa") for c in _codes(res))


def test_ghidra_strings_first_line_carries_the_image_base(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text('{"function_count": 7, "image_base": "0x140000000"}\n{"address": "0x1", "value": "v"}\n')
    gs = sw._read_ghidra_strings(p)
    assert (gs.function_count, gs.image_base, gs.strings) == (7, 0x140000000, [("0x1", "v")])
    p.write_text('{"function_count": 7, "image_base": "ram:00400000"}\n')
    assert sw._read_ghidra_strings(p).image_base is None


def test_capa_skips_large_images(tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "CAPA_MAX_INPUT_BYTES", 1024)
    fc = FakeCapa()
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path, capa=fc)
    assert fc.calls == [] and _fields(res)["capa_status"] == "skipped" and "capa_skipped" in _codes(res)


def test_capa_skips_go_binaries(tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "go_strings", lambda *a, **kw: [(0x401000, "main.main")])
    fc = FakeCapa()
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path, capa=fc)
    assert fc.calls == [] and _fields(res)["capa_status"] == "skipped"
    assert any(w.message == "capa skipped: go binary" for w in res.warnings)


def test_hashed_api_imports_reach_the_report_and_continuation_not_the_payload(tmp_path):
    from test_rea_apihash import BASE, LOADER, TEXT_VA, _movs, _pe
    sample = tmp_path / "loader.exe"
    sample.write_bytes(_pe(_movs("ror13", LOADER)))
    ghidra = FakeGhidra(strings=[{"function_count": 40, "image_base": f"{BASE:#x}"}])
    res, out, _g = _run(sample, tmp_path, ghidra=ghidra)
    f = _fields(res)
    assert "api_hashes" not in f
    report = json.loads((out / "report.json").read_text())
    assert report["api_hashes"]["algorithm"] == "ror13"
    assert {h["api"] for h in report["api_hashes"]["hits"]} == {f"kernel32!{n}" for n in LOADER}
    sites = {h["api"]: h["sites"] for h in report["api_hashes"]["hits"]}
    # each (nop, mov ecx) pair is 6 bytes; the mov of the n-th name is at 6n + 1
    assert sites["kernel32!CreateThread"] == [f"{BASE + TEXT_VA + 6 * LOADER.index('CreateThread') + 1:#x}"]
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["api_hashes"] == report["api_hashes"]


def test_no_hashed_imports_is_null_in_the_report(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path)
    assert json.loads((out / "report.json").read_text())["api_hashes"] is None


def _dump_pe(path: Path, *, vsize: int, size_of_image: int = 0x4000, rdata_raw: int = 0x200) -> Path:
    """A PE32 shaped like CAPE's rebuilt dumps: .text, then .rdata (``rdata_raw=0``: never captured)."""
    import struct
    e = 0x40
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 60, e)
    hdr[e:e + 4] = b"PE\0\0"
    struct.pack_into("<HH", hdr, e + 4, 0x14C, 2)
    struct.pack_into("<H", hdr, e + 20, 0xE0)
    struct.pack_into("<H", hdr, e + 24, 0x10B)
    struct.pack_into("<I", hdr, e + 24 + 56, size_of_image)
    first = e + 24 + 0xE0
    struct.pack_into("<8sIIII", hdr, first, b".text", vsize, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", hdr, first + 36, 0x60000020)
    struct.pack_into("<8sIIII", hdr, first + 40, b".rdata", 0x1800, 0x2000, rdata_raw, 0x600)
    struct.pack_into("<I", hdr, first + 40 + 36, 0x40000040)
    path.write_bytes(bytes(hdr) + b"\xcc" * 0x200 + b"\x00" * rdata_raw)
    return path


def test_dump_with_corrupt_virtual_sizes_is_analysed_repaired(tmp_path):
    import hashlib
    p = _dump_pe(tmp_path / "dump.dll", vsize=0x69C81000)
    original = p.read_bytes()
    res, out, g = _run(p, tmp_path)
    runner = FakeRunner.instances[-1]
    seen = g.calls[0]["sample"]
    assert seen != p and seen.name == "dump.dll"  # Ghidra reads the repaired copy
    assert all(c[1] == seen for c in runner.inspect_calls)  # so does inspect
    assert p.read_bytes() == original
    assert "pe_header_repaired" in _codes(res) and "pe_sections_missing" not in _codes(res)
    sample, _proj, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert sample.read_bytes() != original and len(sample.read_bytes()) == len(original)
    assert state.sweep["dump_headers"] == {"repaired_sections": [".text"],
                                           "original_sha256": hashlib.sha256(original).hexdigest()}


def test_dump_missing_sections_is_a_warning_and_the_original_is_analysed(tmp_path):
    p = _dump_pe(tmp_path / "trunc.exe", vsize=0x200, rdata_raw=0)
    res, out, g = _run(p, tmp_path)
    assert g.calls[0]["sample"] == p
    assert "pe_sections_missing" in _codes(res) and "pe_header_repaired" not in _codes(res)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dump_headers"] == {"missing_sections": [".rdata"]}


def test_ordinary_samples_carry_no_dump_headers(tmp_path):
    res, out, g = _run(FIXTURES / "sample.exe", tmp_path)
    assert g.calls[0]["sample"] == FIXTURES / "sample.exe"
    assert not {"pe_header_repaired", "pe_sections_missing"} & set(_codes(res))
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert "dump_headers" not in state.sweep


def test_signature_matches_reach_payload_report_and_continuation(tmp_path):
    scan = FakeSignatures(rules=[("AgentTeslaV4", "AgentTesla"), ("AgentTeslaV4JIT", "AgentTesla")])
    res, out, ghidra = _run(FIXTURES / "sample.exe", tmp_path, signatures=scan)
    f = _fields(res)
    assert (f["signatures_status"], f["signatures_total"]) == ("ok", 2)
    assert f["signatures"] == ["AgentTeslaV4", "AgentTeslaV4JIT"]
    assert scan.calls[0]["labels"] == ["sample"] and 0 < scan.calls[0]["timeout_s"] <= sw.SIGNATURES_S
    assert scan.calls[0]["cwd"].name == "signatures" and ghidra.calls
    report = json.loads((out / "report.json").read_text())
    assert report["signature_matches"]["families"] == ["AgentTesla"]
    assert report["signature_matches"]["rules_total"] == 135 and report["signatures"] == f["signatures"]
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["signatures"] == report["signature_matches"]
    assert not [c for c in _codes(res) if c.startswith("signatures_")]


def test_a_clean_scan_is_recorded_as_a_scan_that_matched_nothing(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, signatures=FakeSignatures())
    f = _fields(res)
    assert (f["signatures_status"], f["signatures_total"], f["signatures"]) == ("ok", 0, [])
    assert json.loads((out / "report.json").read_text())["signature_matches"]["matches"] == []


def test_an_image_without_the_scanner_adds_no_signature_fields(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path)
    assert not [k for k in _fields(res) if k.startswith("signatures")]
    assert json.loads((out / "report.json").read_text())["signature_matches"] is None
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert "signatures" not in state.sweep


@pytest.mark.parametrize("scan,status,code", [
    (FakeSignatures("timeout", rules=[("Salat", "Salat")], reason="scanner killed"), "timeout", "signatures_timeout"),
    (FakeSignatures("failed", reason="scanner exited with status 1"), "failed", "signatures_failed"),
])
def test_signature_failures_are_warnings_and_keep_what_matched(tmp_path, scan, status, code):
    res, _out, _g = _run(FIXTURES / "sample.exe", tmp_path, signatures=scan)
    f = _fields(res)
    assert res.status == "ok" and code in _codes(res)
    assert f["signatures_status"] == status and f["signatures"] == [r for r, _f in scan.rules]
    assert f["more_pending"] is True


def test_a_signature_exception_never_fails_the_sweep(tmp_path):
    res, out, _g = _run(FIXTURES / "sample.exe", tmp_path, signatures=FakeSignatures(raises=RuntimeError("boom")))
    assert res.status == "ok" and "signatures_failed" in _codes(res)
    assert not [k for k in _fields(res) if k.startswith("signatures")]
    assert json.loads((out / "report.json").read_text())["signature_matches"] is None


def test_signatures_scan_the_unpacked_image_and_every_member(tmp_path):
    # A UPX-marked sample: the scan sees the submitted file and the image upx -d produced.
    p = make_pe(tmp_path / "upx.exe", [(b"UPX0", X, b""), (b"UPX1", X, b"\x90" * 4096)])
    up, scan = FakeUnpack("ok"), FakeSignatures()
    _run(p, tmp_path, unpack=up, signatures=scan)
    assert scan.calls[0]["labels"] == ["sample", "unpacked"]
    assert scan.calls[0]["paths"] == [p, up.calls[0]["dest"]]


def test_signatures_scan_extracted_members(tmp_path):
    def extract(outdir: Path) -> ExtractResult:
        outdir.mkdir(parents=True, exist_ok=True)
        files = [outdir / f"member-{n}" for n in range(3)]
        for f in files:
            f.write_bytes(f.name.encode())
        return ExtractResult(files=files)

    scan = FakeSignatures()
    _run(_zip(tmp_path / "a.zip"), tmp_path, runner=factory(extract_fn=extract), signatures=scan)
    assert scan.calls[0]["labels"] == ["sample", "member:member-0", "member:member-1", "member:member-2"]
