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
    golden.rotate(
        str(tmp_path / "cand.qcow2"),
        live_disk=str(live),
        live_shm=str(shm),
        backup_dir=str(tmp_path / "b"),
        keep_n=5,
        ts="20260626-000000",
        runner=rec,
    )
    flat = [" ".join(c) for c in rec.cmds]
    assert any(
        f"cp --reflink=auto {live} {tmp_path}/b/golden-base.20260626-000000.qcow2" in c
        for c in flat
    )
    assert any(
        f"cp --reflink=auto {tmp_path}/cand.qcow2 {live}.new" in c for c in flat
    )  # promote disk
    assert any(f"{shm}.new" in c for c in flat)  # promote shm
    assert any(c[:2] == ["sudo", "chmod"] for c in rec.cmds)


def test_rotate_aborts_on_failed_copy(tmp_path):
    # a failed cp/mv (disk full, no perms) must raise — not press on and report a stale/partial golden.
    live = tmp_path / "g.qcow2"
    live.write_text("cur")

    class _FailCpMv:
        def __call__(self, argv, **k):
            rc = (
                1 if argv and argv[0] in ("cp", "mv") else 0
            )  # fail copies/moves, pass mkdir/chmod

            class _R:
                returncode = rc
                stdout = ""
                stderr = "No space left on device"

            return _R()

    with pytest.raises(RuntimeError, match="golden rotate"):
        golden.rotate(
            str(tmp_path / "cand.qcow2"),
            live_disk=str(live),
            backup_dir=str(tmp_path / "b"),
            ts="T",
            sudo=False,
            runner=_FailCpMv(),
        )


def test_rotate_backs_up_root_only_golden_via_privileged_check(tmp_path):
    # the live golden lives in a root-only dir: an unprivileged Path.exists() would say "absent" and
    # SKIP the backup. The existence check must go through the SAME privileged runner as cp/mv.
    live = (
        tmp_path / "rootonly" / "golden-base.qcow2"
    )  # NOT created on the unprivileged fs
    rec = _Rec()  # recorder: `test -e` returns rc 0 (as a sudo check would for a root-readable file)
    golden.rotate(
        str(tmp_path / "cand.qcow2"),
        live_disk=str(live),
        backup_dir=str(tmp_path / "b"),
        ts="T",
        sudo=True,
        runner=rec,
    )
    flat = [" ".join(c) for c in rec.cmds]
    assert any(
        c[:3] == ["sudo", "test", "-e"] for c in rec.cmds
    )  # privileged existence probe
    assert any(
        "cp --reflink=auto" in c and "golden-base.T.qcow2" in c for c in flat
    )  # backup taken


def test_prune_keeps_newest_n(tmp_path):
    for i in range(5):
        (tmp_path / f"golden-base.2026010{i}-000000.qcow2").write_text("x")
    rec = _Rec()
    golden.prune_backups(str(tmp_path), 2, sudo=False, runner=rec)
    rms = [c for c in rec.cmds if c[0] == "rm"]
    assert len(rms) == 3  # 3 oldest pruned, newest 2 kept
    assert all("2026010" in c[-1] for c in rms)


def test_prune_backups_enumerates_with_privileged_runner():
    # under sudo, backup enumeration must go through the runner (find), not unprivileged Path.glob —
    # a root-only image dir would otherwise raise/see-nothing AFTER the promote and fail rotate().
    listing = "\n".join(
        f"/root/img/golden-base.2026010{i}-000000.qcow2" for i in range(5)
    )

    class _R:
        def __init__(self):
            self.rm = []

        def __call__(self, argv, **k):
            if "find" in argv:
                return type(
                    "C", (), {"returncode": 0, "stdout": listing, "stderr": ""}
                )()
            if "rm" in argv:
                self.rm.append(argv)
            return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    r = _R()
    golden.prune_backups("/root/img", 2, sudo=True, runner=r)
    assert len(r.rm) == 3  # 3 oldest of the 5 found are pruned
    assert all("2026010" in a[-1] for a in r.rm)


def test_validate_golden_pass_and_reaps():
    rt = _FakeRT("SLOT")
    assert (
        golden.validate_golden(
            "/c.qcow2", runtime_factory=lambda q: rt, check=lambda s: s == "SLOT"
        )
        is True
    )
    assert rt.reaped


def test_validate_golden_rejects_on_check_false_or_no_boot():
    rt = _FakeRT("SLOT")
    assert (
        golden.validate_golden(
            "/c", runtime_factory=lambda q: rt, check=lambda s: False
        )
        is False
    )
    assert rt.reaped
    dead = _FakeRT(None, raise_spawn=True)
    assert (
        golden.validate_golden(
            "/c", runtime_factory=lambda q: dead, check=lambda s: True
        )
        is False
    )


def test_promote_if_valid_rotates_only_on_pass(tmp_path):
    live = tmp_path / "g.qcow2"
    live.write_text("cur")
    rec = _Rec()
    ok = golden.promote_if_valid(
        str(tmp_path / "cand.qcow2"),
        runtime_factory=lambda q: _FakeRT("S"),
        check=lambda s: True,
        live_disk=str(live),
        backup_dir=str(tmp_path / "b"),
        ts="T",
        keep_n=3,
        sudo=False,
        runner=rec,
    )
    assert ok is True and any(c[0] == "cp" for c in rec.cmds)


def test_rotate_stages_all_targets_before_swapping(tmp_path):
    # all-or-nothing: BOTH candidate->.new stages must precede ANY mv into place, so a failure
    # staging the RAM mirror can't leave the disk golden already advanced while the mirror is stale.
    live = tmp_path / "g.qcow2"
    live.write_text("cur")
    shm = tmp_path / "shm.qcow2"
    rec = _Rec()
    golden.rotate(
        str(tmp_path / "cand.qcow2"),
        live_disk=str(live),
        live_shm=str(shm),
        backup_dir=str(tmp_path / "b"),
        ts="T",
        sudo=False,
        runner=rec,
    )
    stage = [
        i for i, c in enumerate(rec.cmds) if c[0] == "cp" and c[-1].endswith(".new")
    ]
    promote = [
        i for i, c in enumerate(rec.cmds) if c[0] == "mv" and c[1].endswith(".new")
    ]
    assert len(stage) == 2 and len(promote) == 2  # both .new staged, both promoted
    assert max(stage) < min(promote)  # stage disk+shm, THEN swap both into place


def test_rotate_rolls_back_split_promotion(tmp_path):
    # if the SHM mirror promote fails after the disk was already swapped, both must be rolled back to
    # the previous consistent pair (never leave live_disk advanced + mirror stale).
    live = tmp_path / "g.qcow2"
    live.write_text("cur")
    shm = tmp_path / "shm.qcow2"
    shm.write_text("curshm")

    class _R:
        def __init__(self):
            self.cmds = []

        def __call__(self, argv, **k):
            self.cmds.append(argv)
            rc = (
                1 if (argv[:1] == ["mv"] and argv[1].endswith("shm.qcow2.new")) else 0
            )  # fail SHM promote
            return type("C", (), {"returncode": rc, "stdout": "", "stderr": "boom"})()

    r = _R()
    with pytest.raises(RuntimeError, match="promote"):
        golden.rotate(
            str(tmp_path / "cand.qcow2"),
            live_disk=str(live),
            live_shm=str(shm),
            backup_dir=str(tmp_path / "b"),
            ts="T",
            sudo=False,
            runner=r,
        )
    flat = [" ".join(c) for c in r.cmds]
    assert any(
        f"mv {live}.rollback {live}" in c for c in flat
    )  # disk restored from its stash
    assert any(f"mv {shm}.rollback {shm}" in c for c in flat)  # mirror restored too


def test_rotate_raises_on_failed_readability_chmod(tmp_path):
    # a failed chmod (golden stuck 0600, qemu can't read it) is a FAILED rotation, not success — AND
    # because the chmod now runs INSIDE the try (before the stashes are dropped), the failure must
    # ALSO roll back: the previous golden is restored from its .rollback stash, not left chmod-failed.
    live = tmp_path / "g.qcow2"
    live.write_text("cur")

    cmds: list[str] = []

    class _R:
        def __call__(self, argv, **k):
            cmds.append(" ".join(argv))
            rc = 1 if (argv[:1] == ["chmod"] and "644" in argv) else 0
            return type("C", (), {"returncode": rc, "stdout": "", "stderr": "denied"})()

    with pytest.raises(RuntimeError, match="chmod golden readable"):
        golden.rotate(
            str(tmp_path / "cand.qcow2"),
            live_disk=str(live),
            backup_dir=str(tmp_path / "b"),
            ts="T",
            sudo=False,
            runner=_R(),
        )
    # rollback restored the previous golden from its stash (not left at .rollback / chmod-failed)
    assert any(c == f"mv {live}.rollback {live}" for c in cmds)


def test_rotate_rolls_back_when_a_later_stash_fails(tmp_path):
    # if stashing the SHM mirror fails AFTER the live disk was already moved to .rollback, the disk
    # must be restored (not left missing at .rollback).
    live = tmp_path / "g.qcow2"
    live.write_text("disk")
    shm = tmp_path / "shm.qcow2"
    shm.write_text("mirror")

    class _R:
        def __init__(self):
            self.cmds = []

        def __call__(self, argv, **k):
            self.cmds.append(argv)
            # both targets exist (test -e rc0); fail the SHM stash (mv shm shm.rollback)
            rc = (
                1
                if (
                    argv[:1] == ["mv"]
                    and argv[1].endswith("shm.qcow2")
                    and argv[2].endswith(".rollback")
                )
                else 0
            )
            return type("C", (), {"returncode": rc, "stdout": "", "stderr": "busy"})()

    r = _R()
    with pytest.raises(RuntimeError):
        golden.rotate(
            str(tmp_path / "cand.qcow2"),
            live_disk=str(live),
            live_shm=str(shm),
            backup_dir=str(tmp_path / "b"),
            ts="T",
            sudo=False,
            runner=r,
        )
    flat = [" ".join(c) for c in r.cmds]
    assert any(
        f"mv {live}.rollback {live}" in c for c in flat
    )  # already-stashed disk restored


def test_rotate_removes_half_promoted_target_on_first_rotation(tmp_path):
    # FIRST rotation (no prior live files → nothing stashed): if live_disk promotes but the shm mirror
    # promote fails, rollback must REMOVE the already-promoted disk (not leave a half-promoted pair).
    live = tmp_path / "g.qcow2"  # does NOT exist yet (first rotation)
    shm = tmp_path / "shm.qcow2"

    class _R:
        def __init__(self):
            self.cmds = []

        def __call__(self, argv, **k):
            self.cmds.append(argv)
            # nothing exists yet (test -e fails); fail the SHM promote (2nd mv)
            rc = 0
            if argv[:1] == ["test"]:
                rc = 1  # no existing file → not stashed
            elif argv[:1] == ["mv"] and argv[1].endswith("shm.qcow2.new"):
                rc = 1  # SHM promote fails
            return type("C", (), {"returncode": rc, "stdout": "", "stderr": "x"})()

    r = _R()
    with pytest.raises(RuntimeError, match="promote"):
        golden.rotate(
            str(tmp_path / "cand.qcow2"),
            live_disk=str(live),
            live_shm=str(shm),
            backup_dir=str(tmp_path / "b"),
            ts="T",
            sudo=False,
            runner=r,
        )
    flat = [" ".join(c) for c in r.cmds]
    assert any(
        c == f"rm -f {live}" for c in flat
    )  # the half-promoted disk golden is removed


def test_promote_if_valid_rejects_when_factory_raises(tmp_path):
    # a malformed candidate that makes runtime_factory() itself raise is a FAILED gate (False +
    # on_reject), not an uncaught crash — the factory call is inside the guarded path now.
    def boom_factory(q):
        raise RuntimeError("bad candidate config")

    rejected: list[str] = []
    ok = golden.promote_if_valid(
        "/cand.qcow2",
        runtime_factory=boom_factory,
        check=lambda s: True,
        live_disk="/g",
        backup_dir="/b",
        ts="T",
        runner=_Rec(),
        on_reject=rejected.append,
    )
    assert ok is False and rejected == ["/cand.qcow2"]


def test_promote_if_valid_keeps_current_on_reject(tmp_path):
    rejected: list[str] = []
    rec = _Rec()
    ok = golden.promote_if_valid(
        "/cand.qcow2",
        runtime_factory=lambda q: _FakeRT("S"),
        check=lambda s: False,
        live_disk="/g",
        backup_dir="/b",
        ts="T",
        runner=rec,
        on_reject=rejected.append,
    )
    assert ok is False
    assert rejected == ["/cand.qcow2"]
    assert not any(
        c[0] == "cp" for c in rec.cmds
    )  # no rotation on a rejected candidate
