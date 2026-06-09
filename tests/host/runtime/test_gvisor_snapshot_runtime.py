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


def test_prepare_gates_on_async_build(tmp_path):
    """prepare() kicks the async build (once) and reports readiness — False until is_built(),
    True after — so the pool can spawn off the tick thread without blocking on build()."""
    class _AsyncMgr:
        def __init__(self):
            self.started = 0
            self._built = False

        def ensure_build_started(self):
            self.started += 1

        def is_built(self):
            return self._built

    m = _AsyncMgr()
    rt = GvisorSnapshotSlotRuntime(m, settle_s=0.0)
    assert rt.prepare() is False  # not built -> kicks build, not ready to spawn
    assert m.started == 1
    m._built = True
    assert rt.prepare() is True  # now ready


def test_prepare_true_for_manager_without_async_seam(tmp_path):
    # A bare/test manager lacking ensure_build_started is always ready (back-compat).
    rt = GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    assert rt.prepare() is True


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


def test_config_from_env_sources_worker_rlimits():
    from blastbox.host.runtime.gvisor_snapshot_runtime import _gvisor_config_from_env

    # Generous defense-in-depth defaults for the whole warm worker tree.
    cfg = _gvisor_config_from_env({})
    assert cfg.rlimit_nproc == 4096
    assert cfg.rlimit_nofile == 65536
    cfg2 = _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_NPROC": "8192", "BLASTBOX_GVISOR_NOFILE": "131072"}
    )
    assert cfg2.rlimit_nproc == 8192
    assert cfg2.rlimit_nofile == 131072
    # A garbage value falls back to the default rather than crashing host startup.
    assert _gvisor_config_from_env({"BLASTBOX_GVISOR_NPROC": "garbage"}).rlimit_nproc == 4096


def test_warm_argv_rejects_non_list_json():
    """A bare JSON string / object / non-string array is valid JSON but not an argv —
    it must fall back to the default, not char-split or take dict keys into argv."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import (
        _DEFAULT_WARM_ARGV,
        _gvisor_config_from_env,
    )

    # The default itself must be the real run_warm.py entrypoint, NOT a nonexistent
    # `worker warm` command (which would exec a missing `worker` binary).
    assert _DEFAULT_WARM_ARGV == ["python3", "/opt/blastbox/run_warm.py"]
    for bad in ('"soffice"', "[1, 2]", "[]", "{}"):
        assert (
            _gvisor_config_from_env({"BLASTBOX_GVISOR_WARM_ARGV": bad}).warm_argv
            == _DEFAULT_WARM_ARGV
        ), bad
    # an absent override also yields the default
    assert _gvisor_config_from_env({}).warm_argv == _DEFAULT_WARM_ARGV
    # a well-formed argv passes through untouched
    assert _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_WARM_ARGV": '["python3", "/custom/entry.py"]'}
    ).warm_argv == ["python3", "/custom/entry.py"]


def test_extra_env_passthrough_into_oci_spec():
    """BLASTBOX_GVISOR_EXTRA_ENV lets an adopter hand the worker engine-specific env
    (e.g. clippyshot's CLIPPYSHOT_SANDBOX=container + CLIPPYSHOT_WARN_ON_INSECURE=1 for the
    runsc inner-sandbox, which gVisor's virtualized /proc/self/status hides). A JSON array of
    'KEY=VALUE' strings that must flow through to the OCI process.env, with malformed input
    ignored rather than crashing host startup."""
    from pathlib import Path

    from blastbox.host.runtime.gvisor_snapshot import _oci_config
    from blastbox.host.runtime.gvisor_snapshot_runtime import _gvisor_config_from_env

    # absent → empty (no behaviour change for engines that need nothing)
    assert _gvisor_config_from_env({}).extra_env == []

    # a valid KEY=VALUE array passes through AND reaches the OCI spec env
    cfg = _gvisor_config_from_env(
        {"BLASTBOX_GVISOR_EXTRA_ENV": '["CLIPPYSHOT_SANDBOX=container", "CLIPPYSHOT_WARN_ON_INSECURE=1"]'}
    )
    assert cfg.extra_env == ["CLIPPYSHOT_SANDBOX=container", "CLIPPYSHOT_WARN_ON_INSECURE=1"]
    spec_env = _oci_config(cfg, Path("/tmp/slot"), in_ro=True)["process"]["env"]
    assert "CLIPPYSHOT_SANDBOX=container" in spec_env
    assert "CLIPPYSHOT_WARN_ON_INSECURE=1" in spec_env

    # malformed (bad JSON / non-list / entries missing '=') is ignored, not fatal
    for bad in ("not json", '"KEY=VALUE"', "[1, 2]", '["NO_EQUALS_SIGN"]', "{}"):
        assert _gvisor_config_from_env({"BLASTBOX_GVISOR_EXTRA_ENV": bad}).extra_env == [], bad


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


def test_secure_snapshot_base_chmods_0700(tmp_path):
    """L3: the warm-snapshot base (holds the checkpoint image restored into every slot) must be
    created 0o700 so a co-tenant can't traverse it under a world-writable parent like /dev/shm."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import _secure_snapshot_base

    base = _secure_snapshot_base(tmp_path / "gvisor-snapshot")
    assert base.exists()
    assert (base.stat().st_mode & 0o777) == 0o700


def test_secure_snapshot_base_refuses_non_owned(tmp_path, monkeypatch):
    """L3: refuse to ADOPT a pre-existing base owned by another uid (fail closed) rather than
    silently restoring from a possibly-attacker-planted checkpoint image."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import _secure_snapshot_base

    base = tmp_path / "gvisor-snapshot"
    base.mkdir()
    import os as _os

    # Pretend the existing dir is owned by someone else.
    real_stat = _os.stat
    monkeypatch.setattr(_os, "geteuid", lambda: real_stat(base).st_uid + 1)
    with pytest.raises(PermissionError):
        _secure_snapshot_base(base)


def test_secure_snapshot_base_refuses_symlink(tmp_path):
    """L3 hardening: a co-tenant who pre-creates the predictable base path as a SYMLINK must not
    get us to follow it — else our ownership check / chmod 0o700 would hit the symlink's target
    (symlink traversal → arbitrary permission change). The O_NOFOLLOW open refuses it."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import _secure_snapshot_base

    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    link = tmp_path / "gvisor-snapshot"
    link.symlink_to(victim)
    with pytest.raises(PermissionError):
        _secure_snapshot_base(link)
    # The victim's perms must be untouched (no fchmod-through-symlink).
    assert (victim.stat().st_mode & 0o777) == 0o755
