"""Unit tests for the generic golden rotation/gate (pure; runner + runtime injected)."""
from __future__ import annotations

import pytest

from blastbox.host.runtime import golden


class _Rec:
    """Records argv of each call; returns rc 0."""

    def __init__(self):
        self.cmds: list[list[str]] = []

    def __call__(self, argv, **k):
        self.cmds.append(argv)

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()


class _FakeRT:
    def __init__(self, slot, raise_spawn=False):
        self.slot = slot
        self.raise_spawn = raise_spawn
        self.reaped = False

    def spawn_ready(self, timeout_s=240.0):
        if self.raise_spawn:
            raise RuntimeError("no boot")
        return self.slot

    def reap(self, slot):
        self.reaped = True


def test_rotate_backs_up_promotes_and_chmods(tmp_path):
    live = tmp_path / "golden-base.qcow2"
    live.write_text("CURRENT")
    shm = tmp_path / "shm-golden.qcow2"
    rec = _Rec()
    golden.rotate(str(tmp_path / "cand.qcow2"), live_disk=str(live), live_shm=str(shm),
                  backup_dir=str(tmp_path / "b"), keep_n=5, ts="20260626-000000", runner=rec)
    flat = [" ".join(c) for c in rec.cmds]
    assert any(f"cp --reflink=auto {live} {tmp_path}/b/golden-base.20260626-000000.qcow2" in c for c in flat)
    assert any(f"cp --reflink=auto {tmp_path}/cand.qcow2 {live}.new" in c for c in flat)   # promote disk
    assert any(f"{shm}.new" in c for c in flat)                                            # promote shm
    assert any(c[:2] == ["sudo", "chmod"] for c in rec.cmds)


def test_rotate_aborts_on_failed_copy(tmp_path):
    # a failed cp/mv (disk full, no perms) must raise — not press on and report a stale/partial golden.
    live = tmp_path / "g.qcow2"
    live.write_text("cur")

    class _FailCpMv:
        def __call__(self, argv, **k):
            rc = 1 if argv and argv[0] in ("cp", "mv") else 0  # fail copies/moves, pass mkdir/chmod

            class _R:
                returncode = rc
                stdout = ""
                stderr = "No space left on device"
            return _R()

    with pytest.raises(RuntimeError, match="golden rotate"):
        golden.rotate(str(tmp_path / "cand.qcow2"), live_disk=str(live), backup_dir=str(tmp_path / "b"),
                      ts="T", sudo=False, runner=_FailCpMv())


def test_prune_keeps_newest_n(tmp_path):
    for i in range(5):
        (tmp_path / f"golden-base.2026010{i}-000000.qcow2").write_text("x")
    rec = _Rec()
    golden.prune_backups(str(tmp_path), 2, sudo=False, runner=rec)
    rms = [c for c in rec.cmds if c[0] == "rm"]
    assert len(rms) == 3                       # 3 oldest pruned, newest 2 kept
    assert all("2026010" in c[-1] for c in rms)


def test_validate_golden_pass_and_reaps():
    rt = _FakeRT("SLOT")
    assert golden.validate_golden("/c.qcow2", runtime_factory=lambda q: rt,
                                  check=lambda s: s == "SLOT") is True
    assert rt.reaped


def test_validate_golden_rejects_on_check_false_or_no_boot():
    rt = _FakeRT("SLOT")
    assert golden.validate_golden("/c", runtime_factory=lambda q: rt, check=lambda s: False) is False
    assert rt.reaped
    dead = _FakeRT(None, raise_spawn=True)
    assert golden.validate_golden("/c", runtime_factory=lambda q: dead, check=lambda s: True) is False


def test_promote_if_valid_rotates_only_on_pass(tmp_path):
    live = tmp_path / "g.qcow2"
    live.write_text("cur")
    rec = _Rec()
    ok = golden.promote_if_valid(str(tmp_path / "cand.qcow2"), runtime_factory=lambda q: _FakeRT("S"),
                                 check=lambda s: True, live_disk=str(live), backup_dir=str(tmp_path / "b"),
                                 ts="T", keep_n=3, sudo=False, runner=rec)
    assert ok is True and any(c[0] == "cp" for c in rec.cmds)


def test_promote_if_valid_keeps_current_on_reject(tmp_path):
    rejected: list[str] = []
    rec = _Rec()
    ok = golden.promote_if_valid("/cand.qcow2", runtime_factory=lambda q: _FakeRT("S"),
                                 check=lambda s: False, live_disk="/g", backup_dir="/b", ts="T",
                                 runner=rec, on_reject=rejected.append)
    assert ok is False
    assert rejected == ["/cand.qcow2"]
    assert not any(c[0] == "cp" for c in rec.cmds)   # no rotation on a rejected candidate
