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
        "LANG": "C", "REA_GHIDRA_PROGRAM_NAME": "x", "HTTPS_PROXY": "http://p",
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
    for k in ("HTTPS_PROXY", "http_proxy", "SECRET"):
        assert k not in env
    assert env["REA_GHIDRA_PROGRAM_NAME"] == "x" and env["GHIDRA_INSTALL_DIR"] == "/g"
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
def _extract_fake(tmp_path: Path, build, payload=None):
    """Fake REA: creates its extraction dir under TMPDIR, reports it."""
    def hook(argv, kw):
        root = Path(kw["env"]["TMPDIR"]) / "rea-extracted-abc"
        root.mkdir()
        arts = build(root)
        doc = payload(root, arts) if payload else {
            "result": {"output_root": str(root), "artifacts": arts, "containment_verified": True}
        }
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
    body = b'{"code":"unsupported_target","message":"Artifact format has no extraction reader: pe"}'
    res = _runner(tmp_path, Fake(RunOutcome(1, body))).extract(tmp_path / "s", tmp_path / "o", 5)
    assert res == ExtractResult()


def test_extract_rejects_root_outside_tmp(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "f").write_bytes(b"x")
    doc = {"output_root": str(victim), "artifacts": [{"relative_path": "f"}]}
    res = _runner(tmp_path, Fake(RunOutcome(0, json.dumps(doc).encode()))).extract(
        tmp_path / "s", tmp_path / "o", 5)
    assert res.files == [] and res.error == "output_root_outside_tmp"
    assert (victim / "f").exists()


def test_extract_error_modes(tmp_path: Path) -> None:
    for out, err in (
        (RunOutcome(None, b"", timed_out=True), "timeout"),
        (RunOutcome(0, b"zzz"), "invalid_json"),
        (RunOutcome(0, b"{}"), "unrecognized_result"),
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
    assert argv == ["/opt/ghidra/support/analyzeHeadless", str(proj), "sample", "-import", str(sample), "-overwrite"]
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
