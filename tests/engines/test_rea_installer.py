"""Static installer unwrapping (NSIS via 7-Zip, Inno Setup via innoextract) in the REA sweep."""

import hashlib
import os
import shutil
import struct
from pathlib import Path

import pytest

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


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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
    assert nsis[-1] == str(NSIS.resolve()) and "7z" in nsis[2] and "-tNsis" in nsis[2]
    assert inno[-1] == str(NSIS.resolve()) and "innoextract" in inno[2]
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
    res, _out, g = _irun(NSIS, tmp_path, fi)
    assert "installer_no_payload" in _codes(res) and "unpacked" not in _fields(res)
    assert g.calls[0]["sample"] == NSIS and _fields(res)["members"] == 2


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


def test_report_prompt_explains_installer_payloads():
    msgs = Framer("n").report_messages(pass_no=1, sample_name="p.exe", summary="", functions=[], iocs=[],
                                       sweep={"unpacked": {"packer": "inno"}}, prior_report=None)
    assert "installer" in msgs[0]["content"]

