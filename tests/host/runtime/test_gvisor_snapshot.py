import time
import json
from pathlib import Path

import pytest

from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend, GvisorConfig, _oci_config


class _Rec:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: object) -> int:
        self.calls.append(argv)
        return 0


def _cfg(tmp_path: Path, **kw: object) -> GvisorConfig:
    base: dict = dict(
        runsc_bin="runsc",
        root=tmp_path / "root",
        image_rootfs=tmp_path / "rootfs",
        network="none",
        warm_argv=["/warm-entrypoint"],
    )
    base.update(kw)
    return GvisorConfig(**base)


def test_boot_base_runs_then_checkpoint(tmp_path: Path) -> None:
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    boot = be.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    joined = [" ".join(c) for c in rec.calls]
    assert any("run" in c and "-detach" in c for c in joined)
    assert any("checkpoint" in c and "-image-path" in c for c in joined)
    # Generation-stamped: a rebuild must never write the directory an in-flight restore is
    # still reading, so the name carries a per-build suffix rather than being fixed.
    assert Path(str(art)).name.startswith("checkpoint-")


def test_restore_in_creates_dirs_and_restores(tmp_path: Path) -> None:
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    wd = tmp_path / "slots" / "s1"
    wd.mkdir(parents=True)
    h = be.restore_in(wd, str(tmp_path / "ckpt" / "checkpoint"))
    joined = [" ".join(c) for c in rec.calls]
    assert any("restore" in c and "-image-path" in c for c in joined)
    for sub in ("in", "out", "ctrl"):
        assert (wd / sub).is_dir()
    assert h.output_dir == wd / "out" and h.control_dir == wd / "ctrl"


def test_restore_in_force_deletes_leaked_container_on_failure(tmp_path: Path) -> None:
    # A restore that fails partway can leave registered runsc state; restore_in must
    # tear down its cid (best-effort) before re-raising rather than orphan a sandbox.
    calls: list[list[str]] = []

    def run(argv: list[str], **kw: object) -> int:
        calls.append(argv)
        if "restore" in argv:
            raise RuntimeError("restore failed mid-way")
        return 0

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=run, ready_wait=lambda d, t: None)
    with pytest.raises(RuntimeError):
        be.restore_in(tmp_path / "s", "img")
    joined = [" ".join(c) for c in calls]
    assert any("restore" in c for c in joined)
    assert any("delete" in c and "-force" in c for c in joined), joined


def test_boot_base_uses_unique_cid_per_call(tmp_path: Path) -> None:
    # Two builds sharing this -root parent must not collide on a fixed cid / bundle path.
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    be.boot_base()
    be.boot_base()
    run_cids = [c[-1] for c in rec.calls if "run" in c and "-detach" in c]
    assert len(run_cids) == 2
    assert run_cids[0] != run_cids[1]
    assert all(cid != "warm-base" for cid in run_cids)


def test_available_uses_probe(tmp_path: Path) -> None:
    assert GvisorSnapshotBackend(_cfg(tmp_path), run=lambda a, **k: 0, probe=lambda: True).available() is True
    assert GvisorSnapshotBackend(_cfg(tmp_path), run=lambda a, **k: 0, probe=lambda: False).available() is False


def test_available_missing_binary_is_false(tmp_path: Path) -> None:
    # No probe override + a binary that doesn't resolve -> fail-closed before the C/R probe.
    be = GvisorSnapshotBackend(
        _cfg(tmp_path, runsc_bin="definitely-not-a-real-binary-xyz"),
        cr_capable=lambda b: pytest.fail("cr_capable must not run when the binary is missing"),
    )
    assert be.available() is False


def test_available_requires_checkpoint_restore_capability(tmp_path: Path) -> None:
    # Binary EXISTS (sys.executable resolves) but the runsc build lacks C/R -> fail-closed,
    # so the pool never selects gVisor and then errors at restore time.
    import sys

    seen: list[str] = []

    def _incapable(binary: str) -> bool:
        seen.append(binary)
        return False

    be = GvisorSnapshotBackend(_cfg(tmp_path, runsc_bin=sys.executable), cr_capable=_incapable)
    assert be.available() is False
    assert seen == [sys.executable]  # the capability probe actually ran on the resolved binary

    ok = GvisorSnapshotBackend(_cfg(tmp_path, runsc_bin=sys.executable), cr_capable=lambda b: True)
    assert ok.available() is True


def test_default_cr_capable_parses_help_output(monkeypatch, tmp_path: Path) -> None:
    # _default_cr_capable runs `runsc help` and requires BOTH subcommands in the output.
    import subprocess as _sp

    from blastbox.host.runtime import gvisor_snapshot as gs

    class _Completed:
        def __init__(self, out: str) -> None:
            self.stdout, self.stderr = out, ""

    def _fake_run_both(argv, **kw):
        return _Completed("Subcommands:\n\tcheckpoint\n\trestore\n\trun\n")

    def _fake_run_missing(argv, **kw):
        return _Completed("Subcommands:\n\trun\n\tdelete\n")  # no checkpoint/restore

    monkeypatch.setattr(gs.subprocess, "run", _fake_run_both)
    assert gs._default_cr_capable("runsc") is True

    monkeypatch.setattr(gs.subprocess, "run", _fake_run_missing)
    assert gs._default_cr_capable("runsc") is False

    def _boom(argv, **kw):
        raise _sp.TimeoutExpired(argv, 5)

    monkeypatch.setattr(gs.subprocess, "run", _boom)
    assert gs._default_cr_capable("runsc") is False  # timeout -> not capable (fail-closed)


def test_restore_in_propagates_run_error(tmp_path: Path) -> None:
    def boom(argv: list[str], **kw: object) -> int:
        raise RuntimeError("runsc gone")

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=boom, ready_wait=lambda d, t: None)
    # The `runsc restore` failure must propagate (the best-effort cleanup that runs in the
    # except — swallowing its own errors — must not mask it). The leaked-container teardown
    # itself is asserted by test_restore_in_force_deletes_leaked_container_on_failure.
    with pytest.raises(RuntimeError):
        be.restore_in(tmp_path / "s", "img")


def test_oci_config_has_bind_mounts_args_and_ld_preload(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, warm_argv=["/bin/sh", "-c", "x"], ld_preload="/opt/clippyshot/accept-retry.so")
    spec = _oci_config(cfg, tmp_path / "wd", in_ro=True)
    assert spec["process"]["args"] == ["/bin/sh", "-c", "x"]
    assert any(e == "LD_PRELOAD=/opt/clippyshot/accept-retry.so" for e in spec["process"]["env"])
    dests = {m["destination"]: m for m in spec["mounts"]}
    assert dests["/in"]["options"][-1] == "ro" and dests["/out"]["options"][-1] == "rw"
    assert dests["/ctrl"]["source"] == str(tmp_path / "wd" / "ctrl")


def test_oci_config_no_ld_preload_when_unset(tmp_path: Path) -> None:
    spec = _oci_config(_cfg(tmp_path), tmp_path / "wd", in_ro=True)
    assert not any(e.startswith("LD_PRELOAD") for e in spec["process"]["env"])


def test_oci_config_security_posture_non_root_no_caps_no_new_privs(tmp_path: Path) -> None:
    # The untrusted-document worker must run NON-ROOT with NO capabilities and no-new-privs,
    # matching the docker (--user/--cap-drop=ALL) and FC (setpriv 65532) tiers.
    spec = _oci_config(_cfg(tmp_path), tmp_path / "wd", in_ro=True)
    proc = spec["process"]
    assert proc["user"]["uid"] != 0 and proc["user"]["uid"] == 65532
    assert proc["noNewPrivileges"] is True
    assert all(caps == [] for caps in proc["capabilities"].values())
    assert spec["root"]["readonly"] is True


def test_oci_config_honors_custom_uid(tmp_path: Path) -> None:
    spec = _oci_config(_cfg(tmp_path, uid=10001, gid=10001), tmp_path / "wd", in_ro=True)
    assert spec["process"]["user"] == {"uid": 10001, "gid": 10001}


def test_oci_config_sets_resource_rlimits(tmp_path: Path) -> None:
    # Bound the untrusted worker so a malicious-doc fork-bomb / fd-exhaustion can't degrade the
    # pool (the FC tier bounds via the microVM; -ignore-cgroups disables cgroup pids here).
    spec = _oci_config(_cfg(tmp_path), tmp_path / "wd", in_ro=True)
    rlimits = {r["type"]: r for r in spec["process"].get("rlimits", [])}
    assert rlimits["RLIMIT_NPROC"]["hard"] == 4096  # generous fork-bomb bound
    assert rlimits["RLIMIT_NOFILE"]["hard"] == 65536  # generous fd-exhaustion bound
    assert all(r["soft"] == r["hard"] for r in rlimits.values())


def test_oci_config_omits_rlimits_when_disabled(tmp_path: Path) -> None:
    spec = _oci_config(
        _cfg(tmp_path, rlimit_nproc=0, rlimit_nofile=0), tmp_path / "wd", in_ro=True
    )
    assert "rlimits" not in spec["process"]


def test_prepare_slot_dirs_perms_are_locked_down(tmp_path: Path) -> None:
    import stat

    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    wd = tmp_path / "slots" / "s1"
    be.restore_in(wd, "img")
    # The 0o700 leaf is what blocks other local users from reaching the 0o777 out/ctrl scratch.
    assert stat.S_IMODE(wd.stat().st_mode) == 0o700
    assert stat.S_IMODE((wd / "in").stat().st_mode) == 0o755
    assert stat.S_IMODE((wd / "out").stat().st_mode) == 0o777
    assert stat.S_IMODE((wd / "ctrl").stat().st_mode) == 0o777


def test_restore_handle_alive_running(tmp_path: Path) -> None:
    from blastbox.host.runtime.gvisor_snapshot import GvisorRestoreHandle
    cfg = _cfg(tmp_path)
    handle = GvisorRestoreHandle(
        cfg,
        run=lambda a, **k: 0,
        cid="test-cid",
        slot_workdir=tmp_path,
        run_text=lambda argv: '{"status": "running"}',
    )
    assert handle.alive() is True


def test_restore_handle_alive_created_is_not_live(tmp_path: Path) -> None:
    from blastbox.host.runtime.gvisor_snapshot import GvisorRestoreHandle
    cfg = _cfg(tmp_path)
    handle = GvisorRestoreHandle(
        cfg,
        run=lambda a, **k: 0,
        cid="test-cid",
        slot_workdir=tmp_path,
        run_text=lambda argv: '{"status": "created"}',
    )
    # 'created' = restored but init never started → must NOT be promoted to live, else a
    # wedged slot gets a job and hangs until the worker timeout.
    assert handle.alive() is False


def test_restore_handle_alive_stopped(tmp_path: Path) -> None:
    from blastbox.host.runtime.gvisor_snapshot import GvisorRestoreHandle
    cfg = _cfg(tmp_path)
    handle = GvisorRestoreHandle(
        cfg,
        run=lambda a, **k: 0,
        cid="test-cid",
        slot_workdir=tmp_path,
        run_text=lambda argv: '{"status": "stopped"}',
    )
    assert handle.alive() is False


def test_restore_handle_alive_runsc_error(tmp_path: Path) -> None:
    from blastbox.host.runtime.gvisor_snapshot import GvisorRestoreHandle

    def _boom(argv: list[str]) -> str:
        raise RuntimeError("runsc gone")

    cfg = _cfg(tmp_path)
    handle = GvisorRestoreHandle(
        cfg,
        run=lambda a, **k: 0,
        cid="test-cid",
        slot_workdir=tmp_path,
        run_text=_boom,
    )
    # alive() must be False (not raise) when run_text raises
    assert handle.alive() is False


def test_each_checkpoint_gets_its_own_generation_directory(tmp_path: Path) -> None:
    """A rebuild must never write the directory an in-flight restore is still reading.

    restore_in() reads the checkpoint dir for the whole life of a `runsc restore`, so a fixed
    <base>/checkpoint path lets a rebuild overwrite files that restore is consuming — it fails,
    or worse observes a mix of two checkpoints. A pin stops the old generation being DELETED;
    only a distinct path stops it being OVERWRITTEN. FC's mem/snapshot pair got this; gVisor's
    checkpoint dir did not.
    """
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)

    seen: set[str] = set()
    for _ in range(3):
        boot = be.boot_base()
        boot.wait_ready(5.0)
        art = boot.checkpoint(tmp_path / "ckpt")
        name = Path(str(art)).name
        assert name.startswith("checkpoint-"), name
        seen.add(name)

    assert len(seen) == 3, f"checkpoint dirs collided across builds: {sorted(seen)}"


def test_a_superseded_checkpoint_generation_is_reclaimed(tmp_path: Path) -> None:
    """Stamping without reclamation is not a fix, it is a slower leak.

    Generation-stamped names stop a rebuild overwriting a checkpoint an in-flight restore is
    reading — but SnapshotManager can only reclaim retired artifacts through a backend discard()
    hook. Without one, every superseded runsc checkpoint stayed on disk until the filesystem
    filled: the exact same half-a-mechanism as the FC artifact whose discard read fields that did
    not exist.
    """
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)

    boot = be.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    img = Path(str(art))
    (img / "state").write_bytes(b"checkpoint payload")
    assert img.exists()

    be.discard(art)
    assert not img.exists(), "a drained checkpoint generation must be removed"


def test_discard_refuses_an_artifact_that_is_not_a_generation_dir(tmp_path: Path) -> None:
    """discard() removes a TREE, so an unexpected artifact shape must never become an rmtree."""
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)

    precious = tmp_path / "not-a-generation"
    precious.mkdir()
    (precious / "keep").write_bytes(b"important")

    be.discard(str(precious))
    assert precious.exists(), "discard must refuse anything that is not one of our checkpoint dirs"


def test_a_partial_checkpoint_cleans_up_its_own_directory(tmp_path: Path) -> None:
    """runsc can write part of a checkpoint and then fail.

    No artifact is returned, so SnapshotManager never learns the directory exists and can never
    retire or discard it — and because every attempt now gets a unique name, each async retry
    leaves another partial checkpoint behind instead of overwriting the last.
    """
    def _run_that_fails(argv, *a, **kw):
        if "checkpoint" in argv:
            img = Path(argv[argv.index("-image-path") + 1])
            img.mkdir(parents=True, exist_ok=True)
            (img / "partial").write_bytes(b"half a checkpoint")
            raise RuntimeError("runsc checkpoint failed")
        return 0

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=_run_that_fails, ready_wait=lambda d, t: None)
    dest = tmp_path / "ckpt"

    for _ in range(3):                          # repeated retries
        boot = be.boot_base()
        boot.wait_ready(5.0)
        with pytest.raises(Exception):
            boot.checkpoint(dest)

    leftovers = list(dest.glob("checkpoint-*")) if dest.exists() else []
    assert leftovers == [], f"partial checkpoints accumulated: {leftovers}"


def test_discard_reports_removal_failures(tmp_path: Path) -> None:
    """ignore_errors=True made a failed removal look like confirmed cleanup.

    SnapshotManager._discard drops the artifact from _retired on a normal return, so a transient
    EIO/EROFS meant that checkpoint directory was never retried and rebuilds accumulated them
    until the filesystem filled — the same swallowing the FC backend's unlink had.
    """
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    boot = be.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    img = Path(str(art))
    (img / "state").write_bytes(b"payload")

    import shutil as _shutil

    real_rmtree = _shutil.rmtree

    def _boom(path, *a, **kw):
        onerror = kw.get("onerror")
        if onerror is not None:
            onerror(None, str(path), (OSError, OSError(5, "Input/output error"), None))
            return
        return real_rmtree(path, *a, **kw)

    mp = pytest.MonkeyPatch()
    mp.setattr("blastbox.host.runtime.gvisor_snapshot.shutil.rmtree", _boom)
    try:
        with pytest.raises(OSError):
            be.discard(art)
    finally:
        mp.undo()


def test_a_partial_checkpoint_whose_cleanup_fails_is_retried(tmp_path: Path) -> None:
    """No artifact is returned for a failed checkpoint, so nothing else can rediscover it.

    ignore_errors=True suppressed any EIO/EROFS from the cleanup before re-raising, and every
    retry uses a NEW directory — so partial checkpoint data accumulated permanently. The same
    hole the FC launcher's partial files had.
    """
    made: list[Path] = []

    def _run(argv, *a, **kw):
        if "checkpoint" in argv:
            img = Path(argv[argv.index("-image-path") + 1])
            img.mkdir(parents=True, exist_ok=True)
            (img / "partial").write_bytes(b"half")
            made.append(img)
            raise RuntimeError("runsc checkpoint failed")
        return 0

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    dest = tmp_path / "ckpt"

    import shutil as _shutil

    real_rmtree = _shutil.rmtree
    broken = {"on": True}

    def _flaky(path, *a, **kw):
        onerror = kw.get("onerror")
        if broken["on"] and onerror is not None:
            onerror(None, str(path), (OSError, OSError(5, "Input/output error"), None))
            return
        return real_rmtree(path, *a, **{k: v for k, v in kw.items() if k != "onerror"})

    mp = pytest.MonkeyPatch()
    mp.setattr("blastbox.host.runtime.gvisor_snapshot.shutil.rmtree", _flaky)
    try:
        boot = be.boot_base()
        boot.wait_ready(5.0)
        with pytest.raises(Exception):
            boot.checkpoint(dest)
        assert made and made[0].exists(), "sanity: cleanup failed, the partial remains"

        # A NEW handle, as production does: SnapshotManager kills and abandons the failed one,
        # so a retry list recorded on the handle would go with it.
        broken["on"] = False
        boot2 = be.boot_base()
        with pytest.raises(Exception):
            boot2.checkpoint(dest)
        assert not made[0].exists(), (
            f"a partial whose cleanup failed was never retried: {made[0]}"
        )

    finally:
        mp.undo()


def test_kill_reports_an_unconfirmed_teardown(tmp_path: Path) -> None:
    """_best_effort_delete swallowed every failure, defeating the caller's pin guard.

    When both `runsc kill` and `runsc delete -force` fail, kill() returned normally, so the reap's
    `sandbox_gone` check stayed True and released the generation pin — a later invalidation could
    then reclaim a checkpoint a live sandbox was still restoring from.
    """
    def _teardown_fails(argv, *a, **kw):
        # Boot must SUCCEED, or we never get a handle to test; only the teardown commands fail.
        if any(x in argv for x in ("kill", "delete")):
            raise RuntimeError("runsc unavailable")
        return 0

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=_teardown_fails, ready_wait=lambda d, t: None)
    handle = be.boot_base()

    with pytest.raises(Exception):
        handle.kill()


def test_kill_is_quiet_when_teardown_succeeds(tmp_path: Path) -> None:
    """The carve-out stays narrow: a successful teardown must not raise."""
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    handle = be.boot_base()
    handle.kill()          # must not raise


def test_the_retry_list_stays_shared_across_handles(tmp_path: Path) -> None:
    """Rebinding detaches the handle from the backend's list.

    After one failed cleanup the sweep did `self._stranded_partials = still`, pointing the HANDLE
    at a private copy — every later append lands there, and the next handle (still holding the
    original) never sees those directories. The FC launcher had the identical bug.
    """
    def _run(argv, *a, **kw):
        if "checkpoint" in argv:
            img = Path(argv[argv.index("-image-path") + 1])
            img.mkdir(parents=True, exist_ok=True)
            (img / "partial").write_bytes(b"half")
            raise RuntimeError("runsc checkpoint failed")
        return 0

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    dest = tmp_path / "ckpt"

    import shutil as _shutil

    def _always_fails(path, *a, **kw):
        onerror = kw.get("onerror")
        if onerror is not None:
            onerror(None, str(path), (OSError, OSError(5, "Input/output error"), None))
            return
        return _shutil.rmtree(path, *a, **kw)

    mp = pytest.MonkeyPatch()
    mp.setattr("blastbox.host.runtime.gvisor_snapshot.shutil.rmtree", _always_fails)
    try:
        boot = be.boot_base()
        boot.wait_ready(5.0)
        # TWO failures on one handle: the first populates the list, the second appends AFTER the
        # sweep has run once, which is where the rebinding took effect.
        for _ in range(2):
            with pytest.raises(Exception):
                boot.checkpoint(dest)
    finally:
        mp.undo()

    # BOTH failures must be recorded on the backend. With the rebinding, the first one lands
    # there (before the sweep runs) and only the SECOND goes to the private copy — so asserting
    # merely "non-empty" passes against the bug.
    assert len(be._stranded_partials) >= 2, (
        f"only {len(be._stranded_partials)} of 2 stranded directories reached the backend's "
        "durable list — the handle rebound to a private copy after the first sweep"
    )


def test_a_failed_restore_signals_an_unconfirmed_teardown(tmp_path: Path) -> None:
    """The manager reads this flag to decide whether the checkpoint may be reclaimed.

    restore_in() called the teardown helper but ignored its result, so when both commands failed
    the original exception carried no signal — the manager unpinned the generation even though an
    unmanaged sandbox might still be using it, and a later invalidation could reclaim it
    underneath.
    """
    def _run(argv, *a, **kw):
        # The restore itself fails, and so does every teardown command.
        raise RuntimeError("runsc failure")

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)

    with pytest.raises(Exception) as ei:
        be.restore_in(tmp_path / "slot", str(tmp_path / "checkpoint-1-1"))

    assert getattr(ei.value, "kill_failed", False) is True, (
        "a restore whose teardown could not be confirmed must flag it, or the manager reclaims "
        "the checkpoint while a sandbox may still be using it"
    )


# --- orphan reclamation across dispatcher restarts --------------------------


def _mk_checkpoint(root, token, ns="0000000000000000001"):
    d = root / f"checkpoint-{token}-{ns}"
    d.mkdir(parents=True)
    (d / "pages.img").write_bytes(b"x" * 64)
    return d


def test_a_dead_dispatchers_checkpoint_is_reclaimed(tmp_path, monkeypatch):
    """gVisor stamped generations but had NO sweep at all.

    Nothing retires the current artifact at shutdown, so every restart -- clean or not --
    stranded a whole runsc checkpoint directory that no code path could rediscover. FC has swept
    its warm-* files since generations were introduced; this side only got the other half.
    """
    from blastbox.host.runtime.snapshot_backend import owner_token

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    dead = _mk_checkpoint(tmp_path, "999999_4242")
    mine = _mk_checkpoint(tmp_path, owner_token(), "0000000000000000002")
    # Death is proved by an UNHELD lease -- what the kernel leaves when the holder dies -- not by
    # a pid, which is invisible from another PID namespace.
    owner_lease_path(tmp_path, "999999_4242").write_bytes(b"")

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0)
    assert backend.sweep_orphan_generations(tmp_path) == 1
    assert not dead.exists(), "a checkpoint whose owner is gone must be reclaimed"
    assert mine.exists(), "never sweep THIS process's own generation"


def test_a_live_dispatchers_checkpoint_is_never_touched(tmp_path, monkeypatch):
    """Deleting a generation a live dispatcher is still restoring from is worse than the leak."""

    import fcntl

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    theirs = _mk_checkpoint(tmp_path, "999999_4242")
    lease = owner_lease_path(tmp_path, "999999_4242")
    lease.write_bytes(b"")
    holder = open(lease, "a+b")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0)
    try:
        assert backend.sweep_orphan_generations(tmp_path) == 0
        assert theirs.exists(), "a live owner's checkpoint was swept out from under its sandboxes"
    finally:
        holder.close()


def test_an_unparseable_name_is_left_alone(tmp_path, monkeypatch):
    """Only OUR generation names are candidates — this deletes trees."""

    stray = tmp_path / "checkpoint-not-a-generation"
    stray.mkdir()

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0)
    assert backend.sweep_orphan_generations(tmp_path) == 0
    assert stray.exists()


def test_a_checkpoint_it_could_not_remove_is_reported(tmp_path, monkeypatch):
    """SnapshotManager latches 'swept' on a clean return, so a swallowed EIO would disable
    reclamation for the whole process."""
    from blastbox.host.runtime import gvisor_snapshot as mod

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    _mk_checkpoint(tmp_path, "999999_4242")
    owner_lease_path(tmp_path, "999999_4242").write_bytes(b"")

    def _boom(path, onerror=None, **kw):
        onerror(None, str(path), (OSError, OSError(5, "EIO"), None))

    monkeypatch.setattr(mod.shutil, "rmtree", _boom)
    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0)
    with pytest.raises(OSError) as ei:
        backend.sweep_orphan_generations(tmp_path)
    assert "checkpoint-999999_4242" in str(ei.value)


def test_stranded_checkpoints_are_retried_before_the_base_boots(tmp_path):
    """The FC sibling's fix, in its twin: a stranded checkpoint big enough to fill the filesystem
    blocked the boot that would have reached the cleanup."""
    leftover = tmp_path / "checkpoint-old-000000000000000001"
    leftover.mkdir(parents=True)
    (leftover / "pages.img").write_bytes(b"x" * 32)

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0,
                                    ready_wait=lambda d, t: None)
    backend._stranded_partials.append(str(leftover))

    backend.boot_base()

    assert not leftover.exists(), (
        "the stranded checkpoint survived the boot -- if it is what filled the disk, the boot "
        "fails before checkpoint() and the retry is unreachable forever"
    )
    assert backend._stranded_partials == []


def test_no_checkpoint_is_written_without_a_lease(tmp_path, monkeypatch):
    """The FC rule in its twin: an uncovered checkpoint can be reclaimed by another dispatcher
    while this process's sandboxes are still restoring from it."""
    from blastbox.host.runtime import gvisor_snapshot as mod

    monkeypatch.setattr(mod, "hold_owner_lease", lambda d: False)
    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=lambda *a, **k: 0,
                                    ready_wait=lambda d, t: None)
    handle = backend.boot_base()
    with pytest.raises(RuntimeError):
        handle.checkpoint(tmp_path)
    assert not list(tmp_path.glob("checkpoint-*")), (
        "a checkpoint generation was written with no lease covering it"
    )


def test_a_cancelled_restore_still_tears_its_sandbox_down(tmp_path):
    """`except Exception` skipped an interrupt entirely.

    A KeyboardInterrupt/SystemExit during `runsc restore` still leaves registered container state
    with live sandbox/gofer processes — and SnapshotManager.restore() then saw an escaping
    exception with no kill_failed marker and UNPINNED the checkpoint, so a later invalidation
    could delete a generation that untracked sandbox was still using.
    """
    deleted: list[str] = []

    def _run(argv, **kw):
        if "restore" in argv:
            raise KeyboardInterrupt("operator interrupted the dispatcher")
        if "delete" in argv:
            deleted.append(argv[-1])
        return 0

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    with pytest.raises(KeyboardInterrupt):
        backend.restore_in(tmp_path / "slot", str(tmp_path / "checkpoint-x"))
    assert deleted, (
        "a cancelled restore left its registered container behind: nothing else knows the cid, "
        "so nothing can ever reap it"
    )


def test_a_cancelled_base_boot_still_tears_down(tmp_path):
    """The boot_base sibling, same rule."""
    deleted: list[str] = []

    def _run(argv, **kw):
        if "run" in argv:
            raise KeyboardInterrupt("interrupted")
        if "delete" in argv:
            deleted.append(argv[-1])
        return 0

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    with pytest.raises(KeyboardInterrupt):
        backend.boot_base()
    assert deleted, "a cancelled base boot leaked its registered container"


def test_an_unconfirmed_base_deletion_retains_its_bundle(tmp_path):
    """Both teardown commands failed, so the sandbox/gofer processes may still be live.

    Ignoring that result and removing the bundle anyway forgot the only cid anything could retry,
    and every later build retry leaked another base.
    """
    def _run(argv, **kw):
        if "run" in argv:
            raise RuntimeError("runsc run failed after registering the container")
        # BOTH teardown commands must fail: _best_effort_delete reports success if EITHER the
        # kill or the force-delete lands, so failing only one still counts as confirmed.
        if "delete" in argv or "kill" in argv:
            raise RuntimeError("teardown failed too")
        return 0

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    with pytest.raises(RuntimeError):
        backend.boot_base()

    assert backend._stranded_partials, (
        "an unconfirmed base deletion forgot its bundle, so nothing can retry the teardown and "
        "every build retry leaks another sandbox"
    )
    # Assert on the path it actually recorded, not on a guess about where the bundle lives.
    retained = Path(backend._stranded_partials[0])
    assert retained.name.startswith("gvisor-base-")
    assert retained.exists(), (
        "the bundle was removed anyway, so the retained path has nothing left to clean up"
    )


def test_an_unconfirmed_restore_teardown_retains_its_bundle(tmp_path):
    """kill_failed keeps the generation PINNED, but the manager then discards the cid.

    So nothing could ever retry the teardown or release that pin: repeated restores leaked
    sandbox/gofer processes and the checkpoint could never be reclaimed. The base-boot path
    already retains; this is its sibling.
    """
    def _run(argv, **kw):
        if "restore" in argv:
            raise RuntimeError("runsc restore failed after registering the sandbox")
        if "delete" in argv or "kill" in argv:
            raise RuntimeError("teardown failed too")
        return 0

    backend = GvisorSnapshotBackend(_cfg(tmp_path), run=_run, ready_wait=lambda d, t: None)
    with pytest.raises(RuntimeError) as ei:
        backend.restore_in(tmp_path / "slot", str(tmp_path / "checkpoint-x"))

    assert getattr(ei.value, "kill_failed", False) is True, "sanity: the pin must be retained"
    assert backend._stranded_partials, (
        "the bundle was forgotten, so nothing can retry the teardown and the checkpoint stays "
        "pinned for the life of the dispatcher"
    )


# ---------------------------------------------------------------------------
# The ready-timeout must carry the cause the guest left behind
# ---------------------------------------------------------------------------


class TestReadyTimeoutReportsTheBreadcrumb:
    """`run_warm.py` writes `ctrl/setup_error` for one stated reason: without it "the host
    only sees a bare ready-timeout". Nothing read it, and the failure path rmtree's the
    bundle, so the explanation was destroyed unread -- measured on toolz2, where a fleet
    rootfs produced `warm base not READY within 120.0s` and no cause at all.
    """

    def test_the_timeout_names_the_cause_the_guest_recorded(self, tmp_path):
        from blastbox.host.runtime.gvisor_snapshot import _default_ready_wait

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()
        (ctrl / "setup_error").write_text("engine setup failed: ModuleNotFoundError('pytesseract')")

        with pytest.raises(TimeoutError) as ei:
            _default_ready_wait(ctrl, 0.3)

        msg = str(ei.value)
        assert "not READY" in msg
        assert "engine setup failed" in msg, f"the timeout dropped the recorded cause: {msg}"
        assert "pytesseract" in msg

    def test_a_timeout_with_no_breadcrumb_is_unchanged(self, tmp_path):
        """The common case -- a genuinely slow base -- must not gain a bogus cause."""
        from blastbox.host.runtime.gvisor_snapshot import _default_ready_wait

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()

        with pytest.raises(TimeoutError) as ei:
            _default_ready_wait(ctrl, 0.3)

        msg = str(ei.value)
        assert "not READY" in msg
        # The knob hint is expected; an empty CAUSE is not. Anchor on the ctrl dir being
        # followed straight by the hint, so a stray ": " with nothing after it still fails.
        assert "); " not in msg and ": \n" not in msg, (
            f"a trailing empty cause was appended: {msg}"
        )
        assert "BLASTBOX_SNAPSHOT_READY_S" in msg, (
            "a timeout with no recorded cause must still say which knob governs it"
        )

    def test_a_worker_written_cause_cannot_smuggle_control_characters(self, tmp_path):
        """ctrl/ is bind-mounted 0o777 and this string is written by the sandboxed worker.

        It lands in operator logs and an exception message, so newlines (log-line injection)
        and control bytes must not survive the read.
        """
        from blastbox.host.runtime.gvisor_snapshot import read_setup_breadcrumb

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()
        (ctrl / "setup_error").write_text(
            "boom\n2026-01-01 CRITICAL fleet is on fire\x00\x1b[31m"
        )

        cause = read_setup_breadcrumb(ctrl)

        assert cause is not None
        assert "\n" not in cause and "\x00" not in cause and "\x1b" not in cause
        assert cause.startswith("boom")

    def test_an_oversized_breadcrumb_is_capped(self, tmp_path):
        from blastbox.host.runtime.gvisor_snapshot import read_setup_breadcrumb

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()
        (ctrl / "setup_error").write_text("A" * 100_000)

        cause = read_setup_breadcrumb(ctrl, max_bytes=4096)

        assert cause is not None and len(cause) <= 4096

    def test_a_breadcrumb_that_is_not_a_regular_file_is_ignored(self, tmp_path):
        """A symlink out of the confined dir must not be followed: the worker owns this dir."""
        from blastbox.host.runtime.gvisor_snapshot import read_setup_breadcrumb

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()
        secret = tmp_path / "secret"
        secret.write_text("host-side secret")
        (ctrl / "setup_error").symlink_to(secret)

        assert read_setup_breadcrumb(ctrl) is None


class TestReadyTimeoutDistinguishesDeadFromSlow:
    """A guest that has EXITED can never write `ready`, so the budget is irrelevant to it.

    Measured on toolz2 with a fleet clippyshot rootfs: the default warm argv runs plain
    `python3`, but blastbox lives in the image's venv, so run_warm.py died with
    `ModuleNotFoundError: No module named 'blastbox'` at import -- before main(), hence before
    the setup_error breadcrumb could be written. The container was gone in under a second and
    the host still waited the full 120 s to report only "not READY within 120.0s".
    """

    def _handle(self, tmp_path, status: str | None):
        from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle, GvisorConfig

        ctrl = tmp_path / "ctrl"
        ctrl.mkdir()
        cfg = GvisorConfig(
            runsc_bin="runsc",
            root=tmp_path / "root",
            image_rootfs=tmp_path / "rootfs",
            network="none",
            warm_argv=["python3", "/opt/blastbox/run_warm.py"],
        )

        def never_ready(_ctrl, _timeout):
            raise TimeoutError("warm base not READY within 0.1s (ctrl)")

        def run_text(argv):
            if status is None:
                return ""            # `runsc state` itself failed / not parseable
            return json.dumps({"status": status})

        return GvisorBootHandle(
            cfg, lambda *a, **k: 0, "warm-base-x", tmp_path / "base", ctrl,
            never_ready, run_text=run_text,
        )

    def test_a_container_that_exited_says_so(self, tmp_path):
        h = self._handle(tmp_path, "stopped")

        with pytest.raises(TimeoutError) as ei:
            h.wait_ready(0.1)

        msg = str(ei.value)
        assert "stopped" in msg
        assert "exited before signalling READY" in msg
        assert "no budget would have helped" in msg, (
            f"a dead guest was reported as if a longer timeout could fix it: {msg}"
        )

    def test_a_container_still_running_is_reported_as_a_plain_timeout(self, tmp_path):
        """The genuinely-slow case must NOT gain a 'it exited' claim -- that would send the
        operator to fix an argv that is fine."""
        h = self._handle(tmp_path, "running")

        with pytest.raises(TimeoutError) as ei:
            h.wait_ready(0.1)

        assert "exited before signalling READY" not in str(ei.value)

    def test_an_unknowable_state_does_not_invent_a_cause(self, tmp_path):
        h = self._handle(tmp_path, None)

        with pytest.raises(TimeoutError) as ei:
            h.wait_ready(0.1)

        assert "exited before signalling READY" not in str(ei.value)


class TestEveryRunscCallIsBounded:
    """An unbounded runsc call disables warm rebuilds for the life of the process.

    `_default_run` is `subprocess.run(check=True)` with no timeout, and the build runs on a
    daemon thread that `ensure_build_started` refuses to replace while it is alive
    (`_build_thread.is_alive()`) -- with no watchdog anywhere. So one wedged
    `checkpoint`/`run`/`restore`/`exec` meant the warm tier never rebuilt again: no error, no
    log, every job on the cold tier permanently. The query helpers were already bounded
    (`runsc state` 3s, `runsc help` 5s); the build path was not.

    These drive the REAL call sites with a recording runner and assert a timeout was passed,
    then prove end-to-end against an actually-hanging runsc that the call returns.
    """

    def _cfg(self, tmp_path, **kw):
        from blastbox.host.runtime.gvisor_snapshot import GvisorConfig

        return GvisorConfig(
            runsc_bin="runsc", root=tmp_path / "root", image_rootfs=tmp_path / "rootfs",
            network="none", warm_argv=["python3", "/opt/blastbox/run_warm.py"], **kw,
        )

    def test_the_checkpoint_call_is_bounded(self, tmp_path):
        from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

        seen: list[dict] = []

        def run(argv, **kw):
            seen.append({"argv": argv, "kw": kw})
            return 0

        cfg = self._cfg(tmp_path, cli_timeout_s=42.0)
        base = tmp_path / "base"
        (base / "ctrl").mkdir(parents=True)
        h = GvisorBootHandle(cfg, run, "cid", base, base / "ctrl", lambda c, t: None)
        dest = tmp_path / "dest"
        dest.mkdir()

        h.checkpoint(dest)

        ckpt = [c for c in seen if "checkpoint" in c["argv"]]
        assert ckpt, f"no checkpoint call was made: {seen}"
        assert ckpt[0]["kw"].get("timeout") == 42.0, (
            f"runsc checkpoint ran unbounded; a wedge here never rebuilds: {ckpt[0]['kw']}"
        )

    def test_the_boot_call_is_bounded(self, tmp_path):
        from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend

        seen: list[dict] = []

        def run(argv, **kw):
            seen.append({"argv": argv, "kw": kw})
            return 0

        cfg = self._cfg(tmp_path, cli_timeout_s=37.0)
        (tmp_path / "root").mkdir(parents=True, exist_ok=True)
        be = GvisorSnapshotBackend(cfg, run=run)
        be.boot_base()

        boots = [c for c in seen if "run" in c["argv"] and "-detach" in c["argv"]]
        assert boots, f"no runsc run call was made: {seen}"
        assert boots[0]["kw"].get("timeout") == 37.0, (
            f"runsc run ran unbounded: {boots[0]['kw']}"
        )

    def test_a_hanging_runsc_actually_returns(self, tmp_path):
        """The property that matters, proved by EXECUTING a runsc that never exits.

        Asserting the kwarg alone would pass even if `_default_run` dropped it on the floor.
        """
        import subprocess as sp

        from blastbox.host.runtime.gvisor_snapshot import _default_run

        hang = tmp_path / "runsc-that-hangs"
        # `exec`, so the timeout kill lands on the sleep itself. Without it only the shell
        # is killed and the sleep is orphaned for five minutes, accumulating across runs and
        # holding inherited fds (codex, #149).
        hang.write_text("#!/bin/sh\nexec sleep 300\n")
        hang.chmod(0o755)

        started = time.monotonic()
        with pytest.raises(sp.TimeoutExpired):
            _default_run([str(hang), "checkpoint"], timeout=1.0)
        elapsed = time.monotonic() - started

        assert elapsed < 30, f"the call was not bounded: it took {elapsed:.0f}s"


class TestTheBoundsCodexFound:
    """Follow-ups from the review of #149 -- each one defeats the bound it sits next to."""

    def test_a_non_finite_timeout_is_refused(self):
        """`float()` accepts inf/nan; neither is a deadline.

        `subprocess.run(timeout=inf)` never expires and nan compares false against
        everything, so both slip past a bare `val <= 0` check and silently restore the
        unbounded call the knob exists to prevent.
        """
        from blastbox.host.runtime.gvisor_snapshot_runtime import _gvisor_config_from_env

        for raw in ("inf", "-inf", "nan", "0", "-5"):
            cfg = _gvisor_config_from_env(
                {"BLASTBOX_GVISOR_ROOTFS": "/x", "BLASTBOX_GVISOR_CLI_TIMEOUT_S": raw}
            )
            assert cfg.cli_timeout_s == 900.0, f"{raw!r} was accepted as a timeout"
        ok = _gvisor_config_from_env(
            {"BLASTBOX_GVISOR_ROOTFS": "/x", "BLASTBOX_GVISOR_CLI_TIMEOUT_S": "300"}
        )
        assert ok.cli_timeout_s == 300.0, "a valid override must still be honoured"

    def test_the_teardown_commands_are_bounded_too(self, tmp_path):
        """They run on the SAME thread as a launch that just timed out, against a runsc that
        is by hypothesis wedged. Unbounded here reinstates the hang the timeouts remove."""
        from blastbox.host.runtime.gvisor_snapshot import GvisorConfig, _best_effort_delete

        seen: list[dict] = []

        def run(argv, **kw):
            seen.append(kw)
            raise RuntimeError("teardown fails, so both commands are attempted")

        cfg = GvisorConfig(
            runsc_bin="runsc", root=tmp_path / "root", image_rootfs=tmp_path / "rootfs",
            network="none", warm_argv=["x"], cli_timeout_s=77.0,
        )
        _best_effort_delete(cfg, run, "cid")

        assert seen, "no teardown command ran"
        for kw in seen:
            assert kw.get("timeout") == 77.0, f"an unbounded teardown call: {kw}"

    def test_a_flood_of_stderr_is_bounded_in_memory(self):
        """The sandbox holds this fd for its whole life and an untrusted document can make the
        worker log without limit, so the sink must keep only the tail -- and must keep DRAINING,
        or a busy guest blocks on a full pipe instead of running.

        The write end is put in NON-BLOCKING mode deliberately. A sink that stops draining
        would otherwise block the writer forever, and closing the fd does not reliably wake a
        thread already blocked in `os.write` -- so the test would HANG rather than fail, which
        is its own defect. Non-blocking turns "not draining" into a named failure in seconds.
        """
        import os as _os
        import time as _time

        from blastbox.host.runtime.gvisor_snapshot import _StderrSink

        sink = _StderrSink(max_bytes=4096)
        target = 4 * 1024 * 1024                    # 4 MiB through a 4 KiB sink
        written = 0
        try:
            _os.set_blocking(sink.write_fd, False)
            deadline = _time.monotonic() + 15.0
            while written < target and _time.monotonic() < deadline:
                try:
                    written += _os.write(sink.write_fd, b"A" * 65536)
                except BlockingIOError:
                    _time.sleep(0.005)              # only reachable if nobody is draining
            assert written >= target, (
                f"the writer stalled after {written} bytes: the sink stopped draining, so a "
                "busy guest would block on a full pipe instead of running"
            )
            # Same retry: a drained pipe can still be momentarily full, and this marker is
            # what the tail assertion below looks for.
            marker = b"THE-INTERESTING-TAIL\n"
            deadline = _time.monotonic() + 5.0
            while marker and _time.monotonic() < deadline:
                try:
                    marker = marker[_os.write(sink.write_fd, marker):]
                except BlockingIOError:
                    _time.sleep(0.005)
            assert not marker, "could not write the tail marker even with the sink draining"
        finally:
            sink.close_write()

        tail = sink.tail()
        assert "THE-INTERESTING-TAIL" in tail, "runsc's useful line is the LAST one"
        assert len(tail) <= 4096, f"the sink kept {len(tail)} bytes of a {target}-byte stream"

    def test_worker_written_stderr_cannot_smuggle_control_characters(self):
        """This text is influenced by the sandboxed worker and lands in an operator's log, so
        newlines (log-line injection) and control bytes must not survive."""
        import os as _os

        from blastbox.host.runtime.gvisor_snapshot import _StderrSink

        sink = _StderrSink()
        try:
            _os.write(sink.write_fd, b"boom\n2026-01-01 CRITICAL fleet is on fire\x00\x1b[31m")
        finally:
            sink.close_write()

        tail = sink.tail()
        assert "\n" not in tail and "\x00" not in tail and "\x1b" not in tail
        assert tail.startswith("boom")


class TestControlFlowAndBundleCleanup:
    """The second review round on #149: both of these were caused by the fixes themselves."""

    def test_an_interrupt_is_not_turned_into_a_snapshot_error(self):
        """The callers catch BaseException to clean up and re-raise a shutdown UNCHANGED.

        Enriching one gives it a `stderr`, and `_with_runsc_stderr` then replaces it with a
        GvisorCommandError -- so a Ctrl-C during a boot came back as an ordinary snapshot
        failure and the shutdown was swallowed.
        """
        from blastbox.host.runtime.gvisor_snapshot import (
            _attach_stderr_text,
            _with_runsc_stderr,
        )

        for exc in (KeyboardInterrupt(), SystemExit(1)):
            out = _attach_stderr_text(exc, "cannot create gofer process: permission denied")
            assert out is exc, f"{type(exc).__name__} was replaced by {type(out).__name__}"
            assert _with_runsc_stderr(out, "runsc run") is exc, (
                f"{type(exc).__name__} survived the attach but not the render"
            )

    def test_an_ordinary_failure_is_still_enriched(self):
        """The control: this is what the enrichment exists for."""
        from blastbox.host.runtime.gvisor_snapshot import (
            _attach_stderr_text,
            _with_runsc_stderr,
        )

        exc = RuntimeError("runsc exited 1")
        rendered = _with_runsc_stderr(
            _attach_stderr_text(exc, "cannot create gofer process: permission denied"),
            "runsc run",
        )
        assert "cannot create gofer process" in str(rendered)

    def test_a_capture_file_failure_does_not_leak_the_bundle(self, tmp_path, monkeypatch):
        """The bundle dir and OCI config are already on disk and no container exists yet, so
        nothing else knows this base is there. Every async retry would leak another."""
        from blastbox.host.runtime import gvisor_snapshot as gs

        monkeypatch.setattr(gs, "_prepare_slot_dirs",
                            lambda cfg, base: (base / "ctrl").mkdir(parents=True))
        monkeypatch.setattr(gs, "_write_oci_config", lambda cfg, base, in_ro=True: None)
        # EMFILE creating the sink: the bundle dir and OCI config are already on disk and no
        # container exists, so nothing else knows this base is here.
        monkeypatch.setattr(gs, "_StderrSink",
                            lambda *a, **k: (_ for _ in ()).throw(OSError(24, "Too many open files")))

        root = tmp_path / "root" / "r"
        cfg = gs.GvisorConfig(
            runsc_bin="runsc", root=root, image_rootfs=tmp_path / "rootfs",
            network="none", warm_argv=["x"],
        )
        be = gs.GvisorSnapshotBackend(cfg, run=lambda *a, **k: 0)

        with pytest.raises(OSError):
            be.boot_base()

        leaked = list(root.parent.glob("gvisor-base-*"))
        assert not leaked, f"a prepared bundle was left behind: {leaked}"


def test_a_successful_boot_leaves_no_capture_file_behind(tmp_path, monkeypatch):
    """There is no capture FILE any more -- the sink is a drained pipe -- so a healthy boot
    can leave nothing on disk at all. Kept as a regression on the file-based design, which
    left one growing file per base (codex, #149/#150)."""
    from blastbox.host.runtime import gvisor_snapshot as gs

    monkeypatch.setattr(gs, "_prepare_slot_dirs",
                        lambda cfg, base: (base / "ctrl").mkdir(parents=True))
    monkeypatch.setattr(gs, "_write_oci_config", lambda cfg, base, in_ro=True: None)

    root = tmp_path / "root" / "r"
    cfg = gs.GvisorConfig(
        runsc_bin="runsc", root=root, image_rootfs=tmp_path / "rootfs",
        network="none", warm_argv=["x"],
    )
    handle = gs.GvisorSnapshotBackend(cfg, run=lambda *a, **k: 0).boot_base()

    bundles = list(root.parent.glob("gvisor-base-*"))
    assert bundles, "fixture: the bundle should exist after a successful boot"
    leftovers = [p for b in bundles for p in b.glob("runsc-stderr-*")]
    assert not leftovers, f"a successful boot left a stderr capture file behind: {leftovers}"
    assert handle is not None
