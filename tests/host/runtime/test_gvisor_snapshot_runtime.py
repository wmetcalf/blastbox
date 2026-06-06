import json
from pathlib import Path

import pytest

from blastbox.host.runtime.gvisor_snapshot_runtime import (
    GvisorHostWarmControl,
    GvisorSnapshotSlotRuntime,
    GvisorUnavailable,
    select_gvisor_snapshot_runtime,
)
from blastbox.worker.warm import WarmJobSpec


class _FakeHandle:
    def __init__(self, wd):
        self.slot_workdir = wd
        self.killed = False

    def kill(self):
        self.killed = True


class _FakeMgr:
    def __init__(self, base):
        self.base = Path(base)
        self.built = 0
        self.restores = 0

    def build(self):
        self.built += 1

    def restore(self, slot_id):
        self.restores += 1
        wd = self.base / "slots" / str(slot_id)
        for s in ("in", "out", "ctrl"):
            (wd / s).mkdir(parents=True, exist_ok=True)
        return _FakeHandle(wd)


def test_spawn_builds_once_then_restores(tmp_path):
    m = _FakeMgr(tmp_path)
    rt = GvisorSnapshotSlotRuntime(m, settle_s=0.0)
    s1 = rt.spawn()
    rt.spawn()
    # build() called each spawn but is idempotent in the real mgr
    assert m.built == 2 and m.restores == 2
    assert s1.state.name == "WARMING" and s1.control_dir.name == "ctrl"
    assert rt.is_ready(s1) is True


def test_host_warm_control_returns_translating_control(tmp_path):
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    assert isinstance(rt.host_warm_control(rt.spawn()), GvisorHostWarmControl)


def test_gvisor_control_translates_paths_to_sandbox(tmp_path):
    ctrl_dir = tmp_path / "ctrl"
    ctrl_dir.mkdir()
    GvisorHostWarmControl(ctrl_dir).signal_go(
        WarmJobSpec(
            input_path=tmp_path / "slots" / "x" / "in" / "doc.docx",
            output_dir=tmp_path / "slots" / "x" / "out",
            params={"a": "b"},
        )
    )
    go = json.loads((ctrl_dir / "go.json").read_text())
    assert go["input_path"] == "/in/doc.docx"
    assert go["output_dir"] == "/out"
    assert go["params"] == {"a": "b"}


def test_warm_argv_rejects_non_list_json():
    """A bare JSON string / object / non-string array is valid JSON but not an argv —
    it must fall back to the default, not char-split or take dict keys into argv."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import _gvisor_config_from_env

    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": '"soffice"'}
    ).warm_argv == ["worker", "warm"]
    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": "[1, 2]"}
    ).warm_argv == ["worker", "warm"]
    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": "[]"}
    ).warm_argv == ["worker", "warm"]
    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": "{}"}
    ).warm_argv == ["worker", "warm"]
    # a well-formed argv passes through untouched
    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": '["python3", "/opt/blastbox/run_warm.py"]'}
    ).warm_argv == ["python3", "/opt/blastbox/run_warm.py"]


def test_settle_gates_readiness(tmp_path):
    clock = {"t": 0.0}
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=1.0, clock=lambda: clock["t"])
    s = rt.spawn()
    assert rt.is_ready(s) is False
    clock["t"] = 2.0
    assert rt.is_ready(s) is True


def test_is_ready_false_when_handle_dead(tmp_path):
    """control_dir exists (created on the host before restore) but the sandbox died
    (alive()=False) → NOT ready, so dead slots aren't promoted to IDLE."""
    class _DeadHandle(_FakeHandle):
        def alive(self):
            return False

    class _DeadMgr(_FakeMgr):
        def restore(self, slot_id):
            wd = self.base / "slots" / str(slot_id)
            for s in ("in", "out", "ctrl"):
                (wd / s).mkdir(parents=True, exist_ok=True)
            return _DeadHandle(wd)

    rt = GvisorSnapshotSlotRuntime(_DeadMgr(tmp_path), settle_s=0.0)
    assert rt.is_ready(rt.spawn()) is False


def test_materialize_output_noop_keeps_output(tmp_path):
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    s = rt.spawn()
    (s.output_dir / "x.pdf").write_bytes(b"%PDF")
    assert rt.materialize_warm_output(s) is None
    assert (s.output_dir / "x.pdf").exists()


def test_reap_kills_and_cleans(tmp_path):
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    s = rt.spawn()
    rt.reap(s)
    assert not Path(s.output_dir).parent.exists()
    assert rt.is_alive(s) is False


def test_is_alive_dead_handle_returns_false(tmp_path):
    """A handle whose alive() returns False makes is_alive() return False."""

    class _DeadHandle(_FakeHandle):
        def alive(self) -> bool:
            return False

    class _DeadMgr(_FakeMgr):
        def restore(self, slot_id):
            self.restores += 1
            wd = self.base / "slots" / str(slot_id)
            for s in ("in", "out", "ctrl"):
                (wd / s).mkdir(parents=True, exist_ok=True)
            return _DeadHandle(wd)

    rt = GvisorSnapshotSlotRuntime(_DeadMgr(tmp_path), settle_s=0.0)
    slot = rt.spawn()
    assert rt.is_alive(slot) is False


def test_is_alive_alive_handle_returns_true(tmp_path):
    """A handle whose alive() returns True makes is_alive() return True."""

    class _AliveHandle(_FakeHandle):
        def alive(self) -> bool:
            return True

    class _AliveMgr(_FakeMgr):
        def restore(self, slot_id):
            self.restores += 1
            wd = self.base / "slots" / str(slot_id)
            for s in ("in", "out", "ctrl"):
                (wd / s).mkdir(parents=True, exist_ok=True)
            return _AliveHandle(wd)

    rt = GvisorSnapshotSlotRuntime(_AliveMgr(tmp_path), settle_s=0.0)
    slot = rt.spawn()
    assert rt.is_alive(slot) is True


def test_is_alive_handle_without_alive_method_returns_true(tmp_path):
    """A handle without alive() (e.g. legacy fake) is assumed alive."""
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    slot = rt.spawn()
    # _FakeHandle has no alive() method — should default to True
    assert rt.is_alive(slot) is True


def test_stage_warm_input_copies(tmp_path):
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    s = rt.spawn()
    src = tmp_path / "src.docx"
    src.write_bytes(b"doc")
    dst = rt.stage_warm_input(s, src)
    assert dst.read_bytes() == b"doc" and dst.parent == s.input_dir


def test_select_with_injected_manager(tmp_path):
    rt = select_gvisor_snapshot_runtime(manager=_FakeMgr(tmp_path), settle_s=0.0)
    assert isinstance(rt, GvisorSnapshotSlotRuntime)


def test_select_unavailable_returns_none(monkeypatch):
    import blastbox.host.runtime.gvisor_snapshot as g
    monkeypatch.setattr(g, "shutil", g.shutil)  # noop; force backend.available() False via a bad binary
    monkeypatch.setenv("BLASTBOX_GVISOR_RUNSC", "definitely-not-a-real-binary-xyz")
    assert select_gvisor_snapshot_runtime(require_available=False) is None


def test_select_unavailable_raises_when_required(monkeypatch):
    monkeypatch.setenv("BLASTBOX_GVISOR_RUNSC", "definitely-not-a-real-binary-xyz")
    with pytest.raises(GvisorUnavailable):
        select_gvisor_snapshot_runtime(require_available=True)
