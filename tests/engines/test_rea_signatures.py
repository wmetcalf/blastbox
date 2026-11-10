"""YARA signature step: target handling, the runner's line protocol, caps, evidence, and a real match."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from blastbox.engines.rea import signatures as sg
from blastbox.engines.rea import signatures_runner
from blastbox.engines.rea.runner import RunOutcome


def lines(*docs: dict) -> bytes:
    return b"".join(json.dumps(d).encode() + b"\n" for d in docs)


class FakeRun:
    def __init__(self, outcome: RunOutcome) -> None:
        self.outcome = outcome
        self.calls: list[dict] = []

    def __call__(self, argv, *, env, cwd, timeout_s, max_stdout):
        self.calls.append(dict(argv=list(argv), env=dict(env), cwd=cwd, timeout_s=timeout_s, max_stdout=max_stdout))
        return self.outcome


@pytest.fixture
def tool(tmp_path: Path) -> dict:
    py = tmp_path / "python"
    py.write_text("")
    rules = tmp_path / "rules.yarx"
    rules.write_bytes(b"x")
    return {"python": py, "rules": rules}


def target(tmp_path: Path, name: str, data: bytes, label: str | None = None) -> sg.SigTarget:
    p = tmp_path / name
    p.write_bytes(data)
    return sg.SigTarget(label or name, p)


def test_unavailable_without_interpreter_or_rules(tmp_path: Path, tool: dict) -> None:
    t = [target(tmp_path, "a", b"A")]
    fake = FakeRun(RunOutcome(0, b""))
    r = sg.scan(t, timeout_s=10, python=tmp_path / "nope", rules=tool["rules"], run=fake)
    assert (r.status, r.reason) == ("unavailable", "no yara interpreter in this image")
    r = sg.scan(t, timeout_s=10, python=tool["python"], rules=tmp_path / "nope", run=fake)
    assert r.status == "unavailable" and not fake.calls
    assert sg.evidence(r) is None
    assert sg.summary_fields(r) == {"signatures_status": "unavailable", "signatures_total": 0, "signatures": []}


def test_matches_families_dedup_and_argv(tmp_path: Path, tool: dict) -> None:
    a = target(tmp_path, "a.bin", b"AAAA", "sample")
    dup = target(tmp_path, "dup.bin", b"AAAA", "capture:0")
    b = target(tmp_path, "b.bin", b"BBBBBB", "hidden:Res\x00ource\n.x")
    fake = FakeRun(RunOutcome(0, lines(
        {"rules_total": 143},
        {"i": 0, "size": 4, "scanned": 4, "matches": [
            {"rule": "AgentTesla", "namespace": "AgentTesla",
             "meta": {"cape_type": "AgentTesla Payload", "author": "kevoreilly", "secret": "dropped",
                      "description": "x" * 1000}, "patterns": ["$a"]}]},
        {"i": 1, "size": 6, "scanned": 6, "matches": [
            {"rule": "Remus", "meta": {"family": "Remus", "cape_type": "Remus Loader", "packed": "abc"}},
            {"rule": "NoMeta", "meta": {}},
            {"not": "a match"}, "junk"]},
        {"i": 7, "size": 1, "matches": [{"rule": "OutOfRange"}]},
        {"done": True},
    )))
    r = sg.scan([a, dup, b], timeout_s=20, run=fake, **tool)
    assert r.status == "ok" and r.reason == "" and r.rules_total == 143
    assert [t["label"] for t in r.targets] == ["sample", "hidden:Res ource .x"]
    assert r.targets[0]["also"] == ["capture:0"]
    assert r.targets[0]["sha256"] == hashlib.sha256(b"AAAA").hexdigest() and "scanned" not in r.targets[0]
    assert [(m["rule"], m["family"], m["target"]) for m in r.matches] == [
        ("AgentTesla", "AgentTesla", "sample"), ("Remus", "Remus", "hidden:Res ource .x"), ("NoMeta", "", "hidden:Res ource .x")]
    meta = r.matches[0]["meta"]
    assert set(meta) == {"cape_type", "author", "description"} and len(meta["description"]) == sg.MAX_TEXT
    assert r.matches_total == 3

    (call,) = fake.calls
    argv = call["argv"]
    assert argv[:2] == ["sh", "-c"] and "ulimit -d" in argv[2] and "ulimit -t" in argv[2] and "ulimit -f 0" in argv[2]
    assert argv[4:7] == [str(sg.MAX_DATA_KB), "21", str(tool["python"])]
    assert argv[7:10] == ["-I", str(Path(signatures_runner.__file__).resolve()), "scan"]
    assert argv[10:13] == [str(tool["rules"]), str(sg.MAX_TARGET_BYTES), str(min(sg.PER_TARGET_S, 20))]
    assert argv[13:] == [str(a.path.resolve()), str(b.path.resolve())]
    assert call["timeout_s"] == 20 and call["max_stdout"] == sg.MAX_STDOUT
    assert set(call["env"]) == {"PATH", "LANG"}

    ev = sg.evidence(r)
    assert ev is not None and ev["families"] == ["AgentTesla", "Remus"] and ev["engine"] == "yara-x"
    assert json.loads(json.dumps(ev)) == ev
    assert sg.summary_fields(r) == {"signatures_status": "ok", "signatures_total": 3,
                                    "signatures": ["AgentTesla", "Remus", "NoMeta"]}


def test_ok_without_matches_is_still_evidence(tmp_path: Path, tool: dict) -> None:
    fake = FakeRun(RunOutcome(0, lines({"rules_total": 5}, {"i": 0, "size": 3, "scanned": 3, "matches": []},
                                       {"done": True})))
    r = sg.scan([target(tmp_path, "a", b"abc")], timeout_s=5, run=fake, **tool)
    ev = sg.evidence(r)
    assert ev is not None and ev["status"] == "ok" and ev["matches"] == [] and ev["families"] == []


def test_truncated_target_and_target_errors(tmp_path: Path, tool: dict) -> None:
    fake = FakeRun(RunOutcome(0, lines({"rules_total": 1}, {"i": 0, "size": 10, "scanned": 4, "matches": []},
                                       {"i": 1, "error": "timeout"}, {"done": True})))
    r = sg.scan([target(tmp_path, "a", b"0123456789"), target(tmp_path, "b", b"zz")], timeout_s=5, run=fake, **tool)
    assert r.status == "ok"
    assert r.targets[0]["scanned"] == 4 and r.targets[1]["error"] == "timeout"


def test_timeout_keeps_finished_targets(tmp_path: Path, tool: dict) -> None:
    fake = FakeRun(RunOutcome(None, lines({"rules_total": 2}, {"i": 0, "size": 1, "matches": [
        {"rule": "Vidar", "meta": {"cape_type": "Vidar Payload"}}]}), timed_out=True))
    r = sg.scan([target(tmp_path, "a", b"a"), target(tmp_path, "b", b"b")], timeout_s=7, run=fake, **tool)
    assert r.status == "timeout" and "after 1 of 2" in r.reason
    assert [m["family"] for m in r.matches] == ["Vidar"]
    assert sg.summary_fields(r)["signatures"] == ["Vidar"]


@pytest.mark.parametrize("outcome, reason", [
    (RunOutcome(1, lines({"error": "rules: ValueError: bad"})), "rules: ValueError: bad"),
    (RunOutcome(137, b""), "scanner exited with status 137"),
    (RunOutcome(0, lines({"rules_total": 1})), "scanner exited with status 0"),
    (RunOutcome(0, b"x" * 10, capped=True), "scanner output over its cap"),
])
def test_failures_are_a_status_not_an_exception(tmp_path: Path, tool: dict, outcome, reason) -> None:
    r = sg.scan([target(tmp_path, "a", b"a")], timeout_s=5, run=FakeRun(outcome), **tool)
    assert (r.status, r.reason) == ("failed", reason)


def test_launch_error_and_no_targets(tmp_path: Path, tool: dict) -> None:
    def boom(argv, **kw):
        raise FileNotFoundError("sh")

    r = sg.scan([target(tmp_path, "a", b"a")], timeout_s=5, run=boom, **tool)
    assert r.status == "failed" and "FileNotFoundError" in r.reason
    r = sg.scan([sg.SigTarget("gone", tmp_path / "missing")], timeout_s=5, run=FakeRun(RunOutcome(0, b"")), **tool)
    assert (r.status, r.reason) == ("failed", "no readable target")
    (tmp_path / "link").symlink_to(tmp_path / "a")
    r = sg.scan([sg.SigTarget("link", tmp_path / "link")], timeout_s=5, run=FakeRun(RunOutcome(0, b"")), **tool)
    assert r.status == "failed"  # a symlink is never followed
    fake = FakeRun(RunOutcome(0, b""))
    r = sg.scan([target(tmp_path, "b", b"b")], timeout_s=0.5, run=fake, **tool)
    assert r.status == "timeout" and not fake.calls


def test_caps_on_targets_and_matches(tmp_path: Path, tool: dict) -> None:
    targets = [target(tmp_path, f"t{i}", str(i).encode()) for i in range(sg.MAX_TARGETS + 3)]
    many = [{"rule": f"R{j}", "meta": {}} for j in range(sg.MAX_MATCHES + 10)]
    fake = FakeRun(RunOutcome(0, lines({"rules_total": 1}, {"i": 0, "size": 1, "matches": many}, {"done": True})))
    r = sg.scan(targets, timeout_s=5, run=fake, **tool)
    assert len(fake.calls[0]["argv"]) == 13 + sg.MAX_TARGETS
    assert "3 target(s) over the" in r.reason
    assert len(r.matches) == sg.MAX_MATCHES and r.matches_total == sg.MAX_MATCHES + 10
    s = sg.summary_fields(r)
    assert s["signatures_total"] == sg.MAX_MATCHES and len(s["signatures"]) == sg.SUMMARY_NAMES
    assert all(isinstance(x, str) for x in s["signatures"])


@pytest.mark.parametrize("meta, want", [
    ({"cape_type": "AgentTesla Payload"}, "AgentTesla"),
    ({"cape_type": "XWorm payload"}, "XWorm"),
    ({"cape_type": "STXRat Loader"}, "STXRat"),
    ({"cape_type": "Payload"}, "Payload"),
    ({"cape_type": "EternalRomance Exploit"}, "EternalRomance Exploit"),
    ({"malware": "Formbook", "cape_type": "X Payload"}, "Formbook"),
    ({"family": " Remus ", "malware": "Other"}, "Remus"),
    ({"family": 3}, ""),
    ({}, ""),
])
def test_family(meta, want) -> None:
    assert sg.family(meta) == want


def test_runner_usage_needs_no_yara(capsys) -> None:
    assert signatures_runner.main(["x", "bogus"]) == 2
    assert "usage" in json.loads(capsys.readouterr().out)["error"]


def _yara_python() -> Path | None:
    if sg.DEFAULT_PYTHON.is_file():
        return sg.DEFAULT_PYTHON
    if importlib.util.find_spec("yara_x") is not None:
        return Path(sys.executable)
    return None


@pytest.mark.skipif(_yara_python() is None, reason="yara_x is not installed")
def test_real_compile_and_match(tmp_path: Path) -> None:
    py = _yara_python()
    assert py is not None
    src = tmp_path / "src"
    src.mkdir()
    (src / "Benign.yar").write_text(
        'rule BenignMarker {\n  meta:\n    cape_type = "BenignMarker Payload"\n    author = "test"\n'
        '  strings:\n    $a = "LOADOUT-BENIGN-MARKER"\n    $b = { 4D 5A 90 00 }\n  condition:\n    $a and $b\n}\n')
    (src / "Broken.yar").write_text("rule Broken { condition: nope( }\n")
    rules = tmp_path / "rules.yarx"
    out = subprocess.run([str(py), "-I", signatures_runner.__file__, "compile", str(src), str(rules), "1"],
                         capture_output=True, timeout=120, check=False)
    report = json.loads(out.stdout)
    assert out.returncode == 0, out.stderr
    assert report["files"] == 2 and report["compiled_files"] == 1 and report["rules"] == 1
    assert [s["file"] for s in report["skipped"]] == ["Broken.yar"]
    floor = subprocess.run([str(py), "-I", signatures_runner.__file__, "compile", str(src), str(tmp_path / "f"), "2"],
                           capture_output=True, timeout=120, check=False)
    assert floor.returncode == 1

    hit = target(tmp_path, "hit.bin", b"MZ\x90\x00" + b"\x00" * 64 + b"LOADOUT-BENIGN-MARKER" + b"\x00" * 16, "sample")
    miss = target(tmp_path, "miss.bin", b"just text, no marker", "capture:0")
    r = sg.scan([hit, miss], timeout_s=60, python=py, rules=rules)
    assert r.status == "ok", r.reason
    assert r.rules_total == 1
    assert [(m["rule"], m["family"], m["target"]) for m in r.matches] == [("BenignMarker", "BenignMarker", "sample")]
    assert r.matches[0]["meta"] == {"cape_type": "BenignMarker Payload", "author": "test"}
    assert all("error" not in t for t in r.targets)


def test_the_agent_and_the_report_are_told_about_signature_matches() -> None:
    from blastbox.engines.rea.continuation import State
    from blastbox.engines.rea.prompts import Framer

    match = {"rule": "AgentTeslaV4", "family": "AgentTesla", "target": "member:stage.bin", "sha256": "1" * 64,
             "meta": {"cape_type": "AgentTesla Payload"}}
    sweep = {"signatures": {"status": "ok", "rules": sg.RULESET, "targets": [], "matches": [match],
                            "matches_total": 1, "families": ["AgentTesla"]}}
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=sweep)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "signature_matches" in msg and "AgentTeslaV4" in msg and "strong lead" in msg
    clean = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
                  sweep={"signatures": {"status": "ok", "matches": []}})
    assert "signature_matches" not in Framer("n").initial_user_message(clean, 1, todo=[], explored=[])["content"]
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=sweep, prior_report=None)[0]["content"]
    assert "sweep.signatures" in sys_msg and "never evidence that the sample is benign" in sys_msg
