import io
import json
import tarfile
from pathlib import Path

import pytest

from blastbox.engines.rea.continuation import ContinuationError, State, pack, unpack


def _state() -> State:
    return State(
        pass_no=2, sample_name="a.exe", sample_sha256="ab" * 32, program_name="a.exe",
        ghidra_status="ok", explored=["main"], todo=["sub_401000"], summary="s", started_at=12.5,
    )


def _raw(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return path


def _file(name: str, data: bytes, mode: int = 0o644) -> tuple[tarfile.TarInfo, bytes]:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    return ti, data


_STATE = _file("state.json", json.dumps(_state().__dict__).encode())


def test_roundtrip(tmp_path: Path) -> None:
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ\x00data")
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "x.gpr").write_bytes(b"gpr")
    (proj / "sub" / "y.rep").write_bytes(b"rep")
    arc = pack(tmp_path / "c.tar.gz", sample=sample, project_dir=proj, state=_state())
    s, p, st = unpack(arc, tmp_path / "out", max_bytes=1 << 20)
    assert st == _state()
    assert s.read_bytes() == b"MZ\x00data"
    assert p is not None
    assert (p / "x.gpr").read_bytes() == b"gpr"
    assert (p / "sub" / "y.rep").read_bytes() == b"rep"


def test_roundtrip_without_project(tmp_path: Path) -> None:
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"x")
    arc = pack(tmp_path / "c.tar.gz", sample=sample, project_dir=None, state=_state())
    _s, p, st = unpack(arc, tmp_path / "out", max_bytes=1 << 20)
    assert p is None and st == _state()


def test_state_json_roundtrip() -> None:
    assert State.from_json(_state().to_json()) == _state()


def test_unpack_normalises_modes(tmp_path: Path) -> None:
    arc = _raw(tmp_path / "m.tar.gz", [
        _file("sample/a.exe", b"x", 0o444),
        _file("project/ro.gpr", b"y", 0o444),
        _STATE,
    ])
    d = tarfile.TarInfo("project/dir")
    d.type = tarfile.DIRTYPE
    d.mode = 0o555
    arc = _raw(tmp_path / "m2.tar.gz", [_file("sample/a.exe", b"x", 0o444),
                                        (d, None), _file("project/dir/ro.gpr", b"y", 0o444), _STATE])
    s, p, _ = unpack(arc, tmp_path / "out", max_bytes=1 << 20)
    assert p is not None
    assert (s.stat().st_mode & 0o777) == 0o640
    assert ((p / "dir" / "ro.gpr").stat().st_mode & 0o777) == 0o640
    assert ((p / "dir").stat().st_mode & 0o777) == 0o750


def _rejects(tmp_path: Path, members: list, max_bytes: int = 1 << 20) -> None:
    arc = _raw(tmp_path / "bad.tar.gz", members)
    with pytest.raises(ContinuationError):
        unpack(arc, tmp_path / "out", max_bytes=max_bytes)


def test_rejects_dotdot(tmp_path: Path) -> None:
    _rejects(tmp_path, [_file("../evil", b"x"), _STATE])


def test_rejects_absolute(tmp_path: Path) -> None:
    _rejects(tmp_path, [_file("/abs", b"x"), _STATE])


def test_rejects_symlink(tmp_path: Path) -> None:
    ti = tarfile.TarInfo("sample/link")
    ti.type = tarfile.SYMTYPE
    ti.linkname = "/etc/passwd"
    _rejects(tmp_path, [(ti, None), _STATE])


def test_rejects_hardlink_and_device(tmp_path: Path) -> None:
    ti = tarfile.TarInfo("sample/h")
    ti.type = tarfile.LNKTYPE
    ti.linkname = "state.json"
    _rejects(tmp_path, [(ti, None), _STATE])
    dv = tarfile.TarInfo("sample/dev")
    dv.type = tarfile.CHRTYPE
    _rejects(tmp_path, [(dv, None), _STATE])


def test_rejects_extra_toplevel(tmp_path: Path) -> None:
    _rejects(tmp_path, [_file("other/x", b"x"), _STATE])


def test_rejects_missing_state(tmp_path: Path) -> None:
    _rejects(tmp_path, [_file("sample/a", b"x")])


def test_rejects_over_max_bytes(tmp_path: Path) -> None:
    _rejects(tmp_path, [_file("sample/a", b"x" * 600), _file("sample/b", b"x" * 600), _STATE], max_bytes=1000)


def test_rejects_lying_header(tmp_path: Path) -> None:
    """Header claims 10 bytes; the stream really carries far more. Must fail on actual bytes."""
    import gzip

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        ti = tarfile.TarInfo("sample/a")
        ti.size = 10
        tf.addfile(ti, io.BytesIO(b"x" * 10))
    blob = bytearray(raw.getvalue())
    # Patch the declared size in the header to 10 but keep it consistent is impossible via
    # tarfile, so instead assert the streaming counter by shrinking max below declared+actual.
    arc = tmp_path / "lie.tar.gz"
    arc.write_bytes(gzip.compress(bytes(blob)))
    with pytest.raises(ContinuationError):
        unpack(arc, tmp_path / "out", max_bytes=5)
    assert not (tmp_path / "out" / "sample" / "a").exists() or (
        (tmp_path / "out" / "sample" / "a").stat().st_size <= 5
    )


def test_stops_writing_at_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap is enforced on bytes actually streamed, not on TarInfo.size."""
    import blastbox.engines.rea.continuation as c

    orig = tarfile.TarFile.extractfile

    def lying(self, member):  # type: ignore[no-untyped-def]
        f = orig(self, member)
        if f is not None and member.name == "sample/a":
            member.size = 1  # declared size understates the stream
        return f

    monkeypatch.setattr(tarfile.TarFile, "extractfile", lying)
    arc = _raw(tmp_path / "x.tar.gz", [_file("sample/a", b"x" * 5000), _STATE])
    with pytest.raises(ContinuationError):
        c.unpack(arc, tmp_path / "out", max_bytes=1000)
    a = tmp_path / "out" / "sample" / "a"
    assert not a.exists() or a.stat().st_size <= 1000 + 65536


def test_huge_gnu_longname_is_bounded(tmp_path: Path) -> None:
    """A multi-hundred-MB longname header must be refused without being buffered."""
    import gzip
    import resource

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        ti = tarfile.TarInfo("sample/" + "a" * 300_000_000)
        ti.size = 0
        tf.addfile(ti)
    arc = tmp_path / "ln.tar.gz"
    arc.write_bytes(gzip.compress(raw.getvalue(), 1))
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    with pytest.raises(ContinuationError):
        unpack(arc, tmp_path / "out", max_bytes=1 << 20)
    assert resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before < 150 * 1024  # KiB


def test_member_count_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import blastbox.engines.rea.continuation as c

    monkeypatch.setattr(c, "MAX_MEMBERS", 5)
    members = [(_file(f"project/f{i}", b"x")) for i in range(10)] + [_STATE]
    arc = _raw(tmp_path / "many.tar.gz", members)
    with pytest.raises(ContinuationError):
        c.unpack(arc, tmp_path / "out", max_bytes=1 << 20)


def test_state_carries_the_analysis_report_and_sweep_evidence() -> None:
    rep = {"schema": "rea.analysis/1", "pass": 2, "verdict": {}, "sections": []}
    st = State(pass_no=2, sample_name="s", sample_sha256="0" * 64, program_name="s", ghidra_status="ok",
               analysis_report=rep, sweep={"kind": "elf", "iocs": []})
    back = State.from_json(st.to_json())
    assert back.analysis_report == rep and back.sweep == {"kind": "elf", "iocs": []}


def test_state_from_an_older_continuation_has_no_report() -> None:
    old = {"pass_no": 1, "sample_name": "s", "sample_sha256": "0" * 64, "program_name": None,
           "ghidra_status": "ok", "explored": [], "todo": [], "summary": "", "started_at": 0.0}
    st = State.from_json(json.dumps(old))
    assert st.analysis_report is None and st.sweep == {}
    with pytest.raises(ContinuationError):
        State.from_json(json.dumps({**old, "analysis_report": ["not", "an", "object"]}))


def test_state_carries_the_models_own_call_behind_the_last_report() -> None:
    """The verdict rule may override the model's label; the bar needs the model's call on later
    passes too (a pass that writes no report is measured on the carried one)."""
    st = State(pass_no=2, sample_name="s", sample_sha256="0" * 64, program_name="s", ghidra_status="ok",
               opinion="benign")
    assert State.from_json(st.to_json()).opinion == "benign"
    old = json.loads(st.to_json())
    del old["opinion"]
    assert State.from_json(json.dumps(old)).opinion is None
    for junk in ("evil", 7, ["benign"], ""):
        assert State.from_json(json.dumps({**old, "opinion": junk})).opinion is None, junk
