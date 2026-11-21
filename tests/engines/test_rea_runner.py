import json
import os
import struct
import sys
import time
import zipfile
from pathlib import Path

import pytest

from blastbox.engines.rea import runner as r
from blastbox.engines.rea.runner import (
    INSPECT_MAP,
    ExtractResult,
    ReaRunner,
    RunOutcome,
    bounded_run,
    classify,
    rea_env,
    run_ghidra_analysis,
    upx_unpack,
)

FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "fixtures"


class Fake:
    def __init__(self, outcome: RunOutcome | None = None, hook=None) -> None:
        self.outcome = outcome or RunOutcome(0, b"{}")
        self.hook = hook
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if self.hook:
            return self.hook(argv, kw)
        return self.outcome


def _runner(tmp_path: Path, fake) -> ReaRunner:
    return ReaRunner("/opt/rea/bin/rea", {"PATH": "/bin"}, tmp_path / "w", run_fn=fake)


# ------------------------------------------------------------------ env
def test_rea_env_scopes_and_filters(tmp_path: Path) -> None:
    base = {
        "PATH": "/bin", "JAVA_HOME": "/j", "GHIDRA_INSTALL_DIR": "/g", "REA_BIN": "/r",
        "LANG": "C", "REA_ANALYSIS_PROVIDER": "ghidra", "REA_GHIDRA_PROGRAM_NAME": "x",
        "REA_OPENAI_API_KEY": "sk-x", "REA_ANTHROPIC_API_KEY": "k", "REA_FOO": "1", "HTTPS_PROXY": "http://p",
        "http_proxy": "http://p", "SECRET": "s", "HOME": "/root", "TMPDIR": "/tmp",
    }
    env = rea_env(tmp_path / "w", base)
    w = tmp_path / "w"
    assert env["TMPDIR"] == str(w / "tmp") and env["HOME"] == str(w / "home")
    assert env["XDG_CACHE_HOME"] == str(w / "home" / ".cache")
    assert env["XDG_CONFIG_HOME"] == str(w / "home" / ".config")
    assert env["JAVA_TOOL_OPTIONS"] == (
        f"-Djava.io.tmpdir={w / 'tmp'} -Duser.home={w / 'home'} -XX:-UsePerfData"
    )
    for k in ("HTTPS_PROXY", "http_proxy", "SECRET", "REA_OPENAI_API_KEY",
              "REA_ANTHROPIC_API_KEY", "REA_FOO", "REA_GHIDRA_PROGRAM_NAME"):
        assert k not in env
    assert env["REA_ANALYSIS_PROVIDER"] == "ghidra" and env["GHIDRA_INSTALL_DIR"] == "/g"
    for d in ("tmp", "home", "home/.cache", "home/.config"):
        assert (w / d).is_dir()


# --------------------------------------------------------------- inspect
def test_inspect_argv_exact(tmp_path: Path) -> None:
    fake = Fake(RunOutcome(0, b'{"a": 1}'))
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    out = _runner(tmp_path, fake).inspect("inspect-pe-imports", sample, 5)
    assert out == {"ok": True, "result": {"a": 1}}
    argv, kw = fake.calls[0]
    assert argv == ["/opt/rea/bin/rea", "inspect-pe-imports", str(sample.resolve()), "--json"]
    assert kw["max_stdout"] == 4 * 1024 * 1024 and kw["env"]["TMPDIR"].endswith("w/tmp")


def test_inspect_rejects_unknown_command(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _runner(tmp_path, Fake()).inspect("inspect-adb-device", tmp_path / "x", 5)
    with pytest.raises(ValueError):
        _runner(tmp_path, Fake()).inspect("--help", tmp_path / "x", 5)


def test_inspect_failure_modes(tmp_path: Path) -> None:
    s = tmp_path / "s"
    s.write_bytes(b"")
    assert _runner(tmp_path, Fake(RunOutcome(0, b"x" * 10, capped=True))).inspect(
        "inspect-artifact", s, 5) == {"ok": False, "error": "output_capped"}
    big = RunOutcome(0, b"[" + b"0," * (3 * 1024 * 1024) + b"0]")
    assert _runner(tmp_path, Fake(big)).inspect("inspect-artifact", s, 5)["error"] == "output_capped"
    assert _runner(tmp_path, Fake(RunOutcome(0, b"nope"))).inspect(
        "inspect-artifact", s, 5) == {"ok": False, "error": "invalid_json"}
    assert _runner(tmp_path, Fake(RunOutcome(None, b"", timed_out=True))).inspect(
        "inspect-artifact", s, 5) == {"ok": False, "error": "timeout"}
    o = _runner(tmp_path, Fake(RunOutcome(1, b'{"code":"provider_unavailable"}'))).inspect(
        "inspect-artifact", s, 5)
    assert o == {"ok": False, "error": "provider_unavailable"}


def test_inspect_map_only_pinned_subcommands() -> None:
    spike = (Path(__file__).resolve().parents[2] / "deploy/rea/SPIKE.md").read_text()
    banned = ("binary-layout", "adb", "jeb", "web-page", "native-api", "native-data-type",
              "native-instruction", "native-load-image")
    assert set(INSPECT_MAP) == {"pe", "elf", "macho", "dotnet", "apk", "asar", "archive", "firmware", "other"}
    for cmds in INSPECT_MAP.values():
        for c in cmds:
            assert c in spike
            assert not any(b in c for b in banned)
    assert "inspect-macho" in INSPECT_MAP["macho"]
    assert "inspect-firmware-regions" in INSPECT_MAP["firmware"]


# -------------------------------------------------------------- classify
def _pe(clr: bool, pe32plus: bool = True) -> bytes:
    b = bytearray(1024)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    opt = 0x80 + 24
    struct.pack_into("<H", b, opt, 0x20B if pe32plus else 0x10B)
    nrva, dirs = (opt + 108, opt + 112) if pe32plus else (opt + 92, opt + 96)
    struct.pack_into("<I", b, nrva, 16)
    if clr:
        struct.pack_into("<II", b, dirs + 14 * 8, 0x2000, 0x48)
    return bytes(b)


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (_pe(False), "pe"), (_pe(True), "dotnet"), (_pe(True, False), "dotnet"), (_pe(False, False), "pe"),
        (b"MZ" + b"\0" * 100, "other"),
        (b"\x7fELF" + b"\0" * 20, "elf"),
        (b"\xcf\xfa\xed\xfe" + b"\0" * 20, "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\0" * 20, "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 20, "other"),
        (b"\x04\x00\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x00" + b'{"files":{}}', "asar"),
        (b"7z\xbc\xaf\x27\x1c" + b"\0" * 8, "archive"),
        (b"Rar!\x1a\x07\x00", "archive"),
        (b"\x1f\x8b\x08\x00", "archive"),
        (b"hsqs" + b"\0" * 8, "firmware"),
        (b"plain text", "other"),
        (b"", "other"),
    ],
)
def test_classify_bytes(tmp_path: Path, data: bytes, kind: str) -> None:
    p = tmp_path / "f"
    p.write_bytes(data)
    assert classify(p) == kind


def test_classify_zip_apk_vs_archive(tmp_path: Path) -> None:
    a, z = tmp_path / "a.apk", tmp_path / "z.zip"
    with zipfile.ZipFile(a, "w") as f:
        f.writestr("AndroidManifest.xml", "x")
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("hi.txt", "x")
    assert classify(a) == "apk" and classify(z) == "archive"
    assert classify(tmp_path / "missing") == "other"


def test_classify_fixtures() -> None:
    assert classify(FIXTURES / "sample.exe") == "pe"
    assert classify(FIXTURES / "sample.elf") == "elf"


# --------------------------------------------------------------- extract
REAL = Path(__file__).resolve().parent / "fixtures" / "rea"


def _envelope(root: Path, arts: list) -> dict:
    """The real extract-artifact envelope with output_root/artifacts substituted."""
    doc = json.loads((REAL / "extract_ok.json").read_text())
    doc["parameters"]["output_root"] = str(root)
    doc["normalized_result"]["output_root"] = str(root)
    doc["normalized_result"]["artifacts"] = arts
    return doc


def _extract_fake(tmp_path: Path, build, payload=None):
    """Fake REA: creates its extraction dir under TMPDIR, reports it."""
    def hook(argv, kw):
        root = Path(kw["env"]["TMPDIR"]) / "rea-extracted-abc"
        root.mkdir()
        arts = build(root)
        doc = payload(root, arts) if payload else _envelope(root, arts)
        return RunOutcome(0, json.dumps(doc).encode())
    return Fake(hook=hook)


def test_extract_copies_regular_files_and_cleans_up(tmp_path: Path) -> None:
    def build(root: Path):
        (root / "d").mkdir()
        (root / "d" / "a.txt").write_bytes(b"aaa")
        (root / "b.bin").write_bytes(b"bbb")
        return [{"relative_path": "d/a.txt", "bytes_written": 3}, {"relative_path": "b.bin"}]
    fake = _extract_fake(tmp_path, build)
    rr = _runner(tmp_path, fake)
    sample = tmp_path / "s.zip"
    sample.write_bytes(b"x")
    res = rr.extract(sample, tmp_path / "out", 5)
    assert fake.calls[0][0] == ["/opt/rea/bin/rea", "extract-artifact", str(sample.resolve()), "--json"]
    assert [p.name for p in res.files] == ["member-0", "member-1"]
    assert res.files[0].read_bytes() == b"aaa" and res.files[1].read_bytes() == b"bbb"
    assert res.dropped == [] and res.error is None
    assert not (tmp_path / "w" / "tmp" / "rea-extracted-abc").exists()


def test_extract_refuses_symlinks_and_escapes(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"s3cret")
    def build(root: Path):
        (root / "ok").write_bytes(b"ok")
        os.symlink(secret, root / "link")
        (root / "ldir").symlink_to(tmp_path, target_is_directory=True)
        return [{"relative_path": p} for p in ("ok", "link", "ldir/secret", "../../secret", "gone")]
    res = _runner(tmp_path, _extract_fake(tmp_path, build)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert [p.read_bytes() for p in res.files] == [b"ok"]
    reasons = dict(res.dropped)
    assert reasons["link"] == "not_regular" and reasons["ldir/secret"] == "escapes_root"
    assert reasons["../../secret"] in ("escapes_root", "not_regular", "missing")
    assert reasons["gone"] == "missing"
    assert secret.read_bytes() == b"s3cret"


def test_extract_caps_count_and_size(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(r, "MAX_MEMBERS", 2)
    monkeypatch.setattr(r, "MAX_MEMBER_BYTES", 4)
    def build(root: Path):
        for n, data in (("a", b"1"), ("big", b"12345"), ("b", b"2"), ("c", b"3")):
            (root / n).write_bytes(data)
        return [{"relative_path": n} for n in ("a", "big", "b", "c")]
    res = _runner(tmp_path, _extract_fake(tmp_path, build)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert [p.read_bytes() for p in res.files] == [b"1", b"2"]
    assert res.dropped == [("big", "too_large"), ("c", "member_cap")]
    assert r.MAX_STDOUT == 4 * 1024 * 1024


def test_extract_constants() -> None:
    assert (MAX := r.MAX_MEMBERS) == 256 and r.MAX_MEMBER_BYTES == 64 * 1024 * 1024 and MAX


def test_extract_unsupported_target_is_empty(tmp_path: Path) -> None:
    body = (REAL / "extract_unsupported.json").read_bytes()
    assert json.loads(body)["code"] == "unsupported_target"
    res = _runner(tmp_path, Fake(RunOutcome(1, body))).extract(tmp_path / "s", tmp_path / "o", 5)
    assert res == ExtractResult()


def test_extract_rejects_root_outside_tmp(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "f").write_bytes(b"x")
    doc = _envelope(victim, [{"relative_path": "f"}])
    res = _runner(tmp_path, Fake(RunOutcome(0, json.dumps(doc).encode()))).extract(
        tmp_path / "s", tmp_path / "o", 5)
    assert res.files == [] and res.error == "output_root_outside_tmp"
    assert (victim / "f").exists()


def test_extract_error_modes(tmp_path: Path) -> None:
    for out, err in (
        (RunOutcome(None, b"", timed_out=True), "timeout"),
        (RunOutcome(0, b"zzz"), "invalid_json"),
        (RunOutcome(0, b"{}"), "unrecognized_result"),
        (RunOutcome(0, b'{"raw_result":{"output_root":"/x","artifacts":[]}}'), "unrecognized_result"),
        (RunOutcome(1, b'{"code":"invalid_request"}'), "invalid_request"),
    ):
        res = _runner(tmp_path, Fake(out)).extract(tmp_path / "s", tmp_path / "o", 5)
        assert res.files == [] and res.error == err


# ---------------------------------------------------------------- ghidra
def _ghidra_env(tmp_path: Path) -> dict[str, str]:
    return rea_env(tmp_path / "w", {"GHIDRA_INSTALL_DIR": "/opt/ghidra", "PATH": "/bin"})


def test_ghidra_argv_and_ok(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    def hook(argv, kw):
        (proj / "sample.gpr").write_text("")
        return RunOutcome(0)
    fake = Fake(hook=hook)
    sample = tmp_path / "s.exe"
    assert run_ghidra_analysis(sample, proj, 9, env=_ghidra_env(tmp_path), run_fn=fake) == "ok"
    argv, kw = fake.calls[0]
    assert argv == ["/opt/ghidra/support/analyzeHeadless", str(proj), "sample", "-import", str(sample), "-overwrite",
                    "-max-cpu", "2"]
    assert kw["env"]["JAVA_TOOL_OPTIONS"].endswith("-XX:-UsePerfData") and kw["timeout_s"] == 9


def test_ghidra_outcomes(tmp_path: Path) -> None:
    env = _ghidra_env(tmp_path)
    s = tmp_path / "s"
    assert run_ghidra_analysis(s, tmp_path / "p1", 1, env=env,
                               run_fn=Fake(RunOutcome(None, timed_out=True))) == "timeout"
    assert run_ghidra_analysis(s, tmp_path / "p2", 1, env=env, run_fn=Fake(RunOutcome(1))) == "failed"
    # rc 0 but no .gpr => failed
    assert run_ghidra_analysis(s, tmp_path / "p3", 1, env=env, run_fn=Fake(RunOutcome(0))) == "failed"
    assert run_ghidra_analysis(s, tmp_path / "p4", 1, env={}, run_fn=Fake(RunOutcome(0))) == "failed"


# ------------------------------------------------- real bounded_run (no mocks)
def test_bounded_run_caps_while_reading(tmp_path: Path) -> None:
    code = "import sys\nwhile True: sys.stdout.buffer.write(b'x'*65536); sys.stdout.flush()"
    t0 = time.monotonic()
    out = bounded_run([sys.executable, "-c", code], env={}, cwd=tmp_path, timeout_s=20, max_stdout=100_000)
    assert out.capped and len(out.stdout) == 100_000 and time.monotonic() - t0 < 15


def test_bounded_run_timeout_kills_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "pid"
    code = (
        "import subprocess,sys,time\n"
        f"p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        f"open({str(pidfile)!r},'w').write(str(p.pid))\n"
        "time.sleep(60)"
    )
    out = bounded_run([sys.executable, "-c", code], env={}, cwd=tmp_path, timeout_s=1.5, max_stdout=1024)
    assert out.timed_out and out.rc is None
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("grandchild survived")


def test_bounded_run_normal_and_discard(tmp_path: Path) -> None:
    out = bounded_run([sys.executable, "-c", "print('hi')"], env={}, cwd=tmp_path, timeout_s=10, max_stdout=1024)
    assert out.rc == 0 and out.stdout == b"hi\n"
    out = bounded_run([sys.executable, "-c", "print('hi')"], env={}, cwd=tmp_path, timeout_s=10, max_stdout=0)
    assert out.rc == 0 and out.stdout == b""


def test_no_tmp_literal_in_source() -> None:
    assert '"/tmp' not in Path(r.__file__).read_text()


def test_extract_real_fixture_shape(tmp_path: Path) -> None:
    def build(root: Path):
        (root / "a.txt").write_bytes(b"hello")
        return json.loads((REAL / "extract_ok.json").read_text())["normalized_result"]["artifacts"]
    res = _runner(tmp_path, _extract_fake(tmp_path, build)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert res.error is None and [p.read_bytes() for p in res.files] == [b"hello"]


def test_extract_ignores_raw_result(tmp_path: Path) -> None:
    def hook(argv, kw):
        root = Path(kw["env"]["TMPDIR"]) / "rea-extracted-x"
        root.mkdir()
        (root / "good").write_bytes(b"g")
        doc = _envelope(root, [{"relative_path": "good"}])
        doc["raw_result"] = {"output_root": "/etc", "artifacts": [{"relative_path": "passwd"}]}
        return RunOutcome(0, json.dumps(doc).encode())
    res = _runner(tmp_path, Fake(hook=hook)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert [p.read_bytes() for p in res.files] == [b"g"]


def test_extract_drops_hardlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    def build(root: Path):
        os.link(outside, root / "hl")
        (root / "ok").write_bytes(b"ok")
        return [{"relative_path": "hl"}, {"relative_path": "ok"}]
    res = _runner(tmp_path, _extract_fake(tmp_path, build)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert [p.read_bytes() for p in res.files] == [b"ok"]
    assert res.dropped == [("hl", "not_regular")]
    assert outside.read_bytes() == b"private"


def test_extract_fstat_recheck_after_open(tmp_path: Path, monkeypatch) -> None:
    real_open = os.open
    def build(root: Path):
        (root / "f").write_bytes(b"data")
        return [{"relative_path": "f"}]
    def racy_open(path, flags, *a, **k):
        fd = real_open(path, flags, *a, **k)
        if str(path).endswith("/f"):
            os.link(path, str(path) + "_hl")  # file gains a second link after lstat
        return fd
    monkeypatch.setattr(r.os, "open", racy_open)
    res = _runner(tmp_path, _extract_fake(tmp_path, build)).extract(tmp_path / "s", tmp_path / "o", 5)
    assert res.files == [] and res.dropped == [("f", "not_regular")]


def test_extract_sweeps_leftover_dirs(tmp_path: Path) -> None:
    def hook(argv, kw):
        (Path(kw["env"]["TMPDIR"]) / "rea-extracted-left").mkdir()
        return RunOutcome(None, b"", timed_out=True)
    rr = _runner(tmp_path, Fake(hook=hook))
    rr.extract(tmp_path / "s", tmp_path / "o", 1)
    assert not list((tmp_path / "w" / "tmp").glob("rea-extracted-*"))


def test_ghidra_dash_sample_and_relative_project(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    env = _ghidra_env(tmp_path)
    fake = Fake(hook=lambda a, kw: (Path(a[1], "sample.gpr").write_text(""), RunOutcome(0))[1])
    res = run_ghidra_analysis(Path("-postScript"), Path("rel/proj"), 5, env=env, run_fn=fake)
    argv, kw = fake.calls[0]
    assert res == "ok"
    assert argv[1] == str(tmp_path / "rel" / "proj") and kw["cwd"] == tmp_path / "rel" / "proj"
    assert argv[4] == str(tmp_path / "-postScript") and argv[4].startswith("/")
    assert (tmp_path / "rel" / "proj" / "sample.gpr").exists()
    assert not (tmp_path / "rel" / "proj" / "rel").exists()


def test_ghidra_post_script_argv_absolute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    proj = tmp_path / "proj"
    fake = Fake(hook=lambda a, kw: ((proj / "sample.gpr").write_text(""), RunOutcome(0))[1])
    res = run_ghidra_analysis(
        tmp_path / "s.exe", proj, 9, env=_ghidra_env(tmp_path), run_fn=fake,
        post_script=(Path("scripts"), "ListStrings.java", Path("out/strings.jsonl")),
    )
    argv, _kw = fake.calls[0]
    assert res == "ok"
    assert argv == [
        "/opt/ghidra/support/analyzeHeadless", str(proj), "sample", "-import", str(tmp_path / "s.exe"),
        "-overwrite", "-max-cpu", "2", "-scriptPath", str(tmp_path / "scripts"),
        "-postScript", "ListStrings.java", str(tmp_path / "out" / "strings.jsonl"),
    ]


def test_ghidra_post_script_rejects_bad_name(tmp_path: Path) -> None:
    for name in ("../x.java", "-import", "a/b.java", ""):
        with pytest.raises(ValueError):
            run_ghidra_analysis(
                tmp_path / "s", tmp_path / "p", 1, env=_ghidra_env(tmp_path), run_fn=Fake(),
                post_script=(tmp_path, name, tmp_path / "o"),
            )


# ------------------------------------------------------------------- upx
def test_upx_unpack_argv_caps_the_output_size(tmp_path: Path) -> None:
    dest = tmp_path / "u" / "s.exe"
    fake = Fake(hook=lambda a, kw: (dest.write_bytes(b"MZ" * 10), RunOutcome(0))[1])
    assert upx_unpack(tmp_path / "s.exe", dest, 30, env={"PATH": "/bin"}, max_bytes=1 << 20, run_fn=fake) == "ok"
    argv, kw = fake.calls[0]
    assert argv[:3] == ["sh", "-c", 'ulimit -f "$1" && exec upx -d -q -o "$2" "$3"']
    assert argv[3:] == ["sh", str((1 << 20) // 512), str(dest), str(tmp_path / "s.exe")]
    assert kw["timeout_s"] == 30 and kw["max_stdout"] == 0


@pytest.mark.parametrize("outcome,write,expect", [
    (RunOutcome(2), b"", "failed"),                    # scrambled header: upx refuses
    (RunOutcome(0), None, "failed"),                   # rc 0 but nothing written
    (RunOutcome(0), b"x" * 2048, "failed"),            # over max_bytes
    (RunOutcome(None, timed_out=True), b"x", "timeout"),
])
def test_upx_unpack_failures_leave_no_output(tmp_path: Path, outcome, write, expect) -> None:
    dest = tmp_path / "s.exe"

    def hook(argv, kw):
        if write is not None:
            dest.write_bytes(write)
        return outcome

    assert upx_unpack(tmp_path / "in.exe", dest, 30, env={}, max_bytes=1024, run_fn=Fake(hook=hook)) == expect
    assert not dest.exists()


def test_run_capa_pins_format_backend_rules_and_caps(tmp_path: Path) -> None:
    fake = Fake(RunOutcome(0, b'{"rules": {}}'))
    status, out = r.run_capa(tmp_path / "s.exe", "pe", 90, env={"PATH": "/bin"}, capa_bin="/opt/capa/bin/capa",
                             rules=Path("/opt/capa/rules"), signatures=Path("/opt/capa/sigs"), max_kb=1024,
                             max_stdout=1 << 20, run_fn=fake)
    assert (status, out) == ("ok", b'{"rules": {}}')
    argv, kw = fake.calls[0]
    assert argv[3:] == ["sh", "1024", "/opt/capa/bin/capa", "pe", "vivisect", "/opt/capa/rules", "/opt/capa/sigs",
                        str((tmp_path / "s.exe").resolve())]
    assert kw["timeout_s"] == 90 and kw["max_stdout"] == 1 << 20
    assert kw["env"]["CAPA_SAVE_WORKSPACE"] == "0" and "CAPA_LOAD_VIV_WORKSPACE" not in kw["env"]
    r.run_capa(tmp_path / "s.exe", "dotnet", 9, env={}, capa_bin="c", rules=Path("r"), signatures=Path("s"),
               max_kb=1, max_stdout=1, run_fn=fake)
    assert fake.calls[1][0][6:8] == ["dotnet", "dotnet"]


@pytest.mark.parametrize("outcome,expect", [
    (RunOutcome(17), "unsupported"),                  # E_INVALID_FILE_ARCH (an ARM ELF)
    (RunOutcome(16), "unsupported"),
    (RunOutcome(1, b"{}"), "failed"),
    (RunOutcome(0, b""), "failed"),
    (RunOutcome(None, timed_out=True), "timeout"),
    (RunOutcome(None, b"{", capped=True), "too_large"),
])
def test_run_capa_statuses(tmp_path: Path, outcome, expect) -> None:
    status, out = r.run_capa(tmp_path / "s", "elf", 9, env={}, capa_bin="c", rules=Path("r"), signatures=Path("s"),
                             max_kb=1, max_stdout=1, run_fn=Fake(outcome))
    assert (status, out) == (expect, b"")


# ------------------------------------------------------- ghidra analysis profile
SCRIPTS = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "ghidra_scripts"


_ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 200


@pytest.mark.parametrize(("data", "kind", "expect"), [
    (_pe(clr=True), "dotnet", "light"),
    (_pe(clr=False, pe32plus=False), "pe", "light"),       # every PE: Decompiler Parameter ID default-on
    (_pe(clr=False), "pe", "light"),
    (_ELF, "elf", "full"),                                  # a small ELF keeps the full profile
    (_ELF + b"\0" * 64 + b"\xff Go buildinf:\x08\x02", "elf", "light"),
    (_ELF + b"/rustc/90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf/library/core", "elf", "light"),
    (_ELF + b"C:\\rustc\\abc\\library\\std", "macho", "light"),
    (b"\xcf\xfa\xed\xfe" + b"\0" * 200, "macho", "full"),
    (b"PK\x03\x04" + b"\0" * 100 + b"\xff Go buildinf:", "archive", "full"),  # Ghidra never sees it
    (_pe(clr=False), "other", "full"),
])
def test_ghidra_profile(tmp_path: Path, data: bytes, kind: str, expect: str) -> None:
    p = tmp_path / "img"
    p.write_bytes(data)
    assert r.ghidra_profile(p, kind) == expect


def test_ghidra_profile_size_and_bad_paths(tmp_path: Path) -> None:
    big = tmp_path / "big"
    with big.open("wb") as f:  # sparse: a small ELF header, LIGHT_MIN_BYTES long
        f.write(_ELF)
        f.truncate(r.LIGHT_MIN_BYTES)
    assert r.ghidra_profile(big, "elf") == "light"
    with big.open("r+b") as f:
        f.truncate(r.LIGHT_MIN_BYTES - 1)
    assert r.ghidra_profile(big, "elf") == "full"
    link = tmp_path / "link"
    small = tmp_path / "small"
    small.write_bytes(_ELF + b"/rustc/")
    link.symlink_to(small)
    assert r.ghidra_profile(small, "elf") == "light"
    assert r.ghidra_profile(link, "elf") == "full"            # never follows a link
    assert r.ghidra_profile(tmp_path / "missing", "elf") == "full"
    assert r.ghidra_profile(tmp_path, "elf") == "full"       # a directory
    (tmp_path / "empty").write_bytes(b"")
    assert r.ghidra_profile(tmp_path / "empty", "elf") == "full"


def test_ghidra_light_profile_argv(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    fake = Fake(hook=lambda a, kw: ((proj / "sample.gpr").write_text(""), RunOutcome(0))[1])
    res = run_ghidra_analysis(
        tmp_path / "s.exe", proj, 9, env=_ghidra_env(tmp_path), run_fn=fake, profile="light",
        post_script=(tmp_path / "scripts", "ListStrings.java", tmp_path / "o.jsonl"),
    )
    assert res == "ok"
    assert fake.calls[0][0] == [
        "/opt/ghidra/support/analyzeHeadless", str(proj), "sample", "-import", str(tmp_path / "s.exe"),
        "-overwrite", "-max-cpu", "2", "-scriptPath", str(tmp_path / "scripts"),
        "-preScript", "LightAnalysis.java", "-postScript", "ListStrings.java", str(tmp_path / "o.jsonl"),
    ]
    fake2 = Fake(hook=lambda a, kw: ((proj / "sample.gpr").write_text(""), RunOutcome(0))[1])
    assert run_ghidra_analysis(tmp_path / "s.exe", proj, 9, env=_ghidra_env(tmp_path), run_fn=fake2,
                               profile="light", script_dir=tmp_path / "scripts") == "ok"
    assert fake2.calls[0][0][8:] == ["-scriptPath", str(tmp_path / "scripts"), "-preScript", "LightAnalysis.java"]


def test_ghidra_profile_argument_errors(tmp_path: Path) -> None:
    env = _ghidra_env(tmp_path)
    s, p = tmp_path / "s", tmp_path / "p"
    with pytest.raises(ValueError):
        run_ghidra_analysis(s, p, 1, env=env, run_fn=Fake(), profile="light")  # no script dir
    with pytest.raises(ValueError):
        run_ghidra_analysis(s, p, 1, env=env, run_fn=Fake(), profile="fast")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        run_ghidra_analysis(s, p, 1, env=env, run_fn=Fake(), profile="light", script_dir=tmp_path / "a",
                            post_script=(tmp_path / "b", "ListStrings.java", tmp_path / "o"))
    for bad in (0, -5, True, 1.5):
        with pytest.raises(ValueError):
            run_ghidra_analysis(s, p, 1, env=env, run_fn=Fake(), analysis_timeout_s=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(("log_text", "expect"), [
    (b"INFO REPORT: Analysis succeeded for file: /x\n", "ok"),
    (b"ERROR (HeadlessAnalyzer) REPORT: Analysis timed out at 300 seconds. Processing not completed\n",
     "partial"),
    # the marker straddles the 1 MiB read boundary
    (b"x" * (1024 * 1024 - 10) + b"REPORT: Analysis timed out at 3 seconds\n", "partial"),
    (None, "ok"),                                         # no log written at all
])
def test_ghidra_analysis_timeout_partial(tmp_path: Path, log_text: bytes | None, expect: str) -> None:
    proj = tmp_path / "proj"

    def hook(argv, kw):
        if log_text is not None:
            Path(argv[argv.index("-log") + 1]).write_bytes(log_text)
        (proj / "sample.gpr").write_text("")
        return RunOutcome(0)

    fake = Fake(hook=hook)
    stale = tmp_path / "proj.log"
    stale.write_bytes(b"REPORT: Analysis timed out")    # a previous run's log never counts
    res = run_ghidra_analysis(tmp_path / "s.exe", proj, 420, env=_ghidra_env(tmp_path), run_fn=fake,
                              analysis_timeout_s=360)
    argv = fake.calls[0][0]
    assert argv[8:12] == ["-analysisTimeoutPerFile", "360", "-log", str(tmp_path / "proj.log")]
    assert res == expect


def test_ghidra_analysis_timeout_never_rescues_failures(tmp_path: Path) -> None:
    env = _ghidra_env(tmp_path)
    s = tmp_path / "s"
    assert run_ghidra_analysis(s, tmp_path / "p1", 1, env=env, analysis_timeout_s=5,
                               run_fn=Fake(RunOutcome(None, timed_out=True))) == "timeout"
    assert run_ghidra_analysis(s, tmp_path / "p2", 1, env=env, analysis_timeout_s=5,
                               run_fn=Fake(RunOutcome(1))) == "failed"
    assert run_ghidra_analysis(s, tmp_path / "p3", 1, env=env, analysis_timeout_s=5,
                               run_fn=Fake(RunOutcome(0))) == "failed"  # no .gpr


def test_light_analysis_script_names_known_analyzers() -> None:
    src = (SCRIPTS / r.LIGHT_SCRIPT).read_text()
    assert "public class LightAnalysis extends GhidraScript" in src
    for name in ("Decompiler Parameter ID", "Call Convention ID", "Decompiler Switch Analysis", "Stack",
                 "x86 Constant Reference Analyzer"):
        assert f'"{name}",' in src
