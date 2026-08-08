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
