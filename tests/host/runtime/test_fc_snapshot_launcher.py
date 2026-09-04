"""Unit tests for the FC snapshot launcher (Phase 2 orchestration)."""

from __future__ import annotations
import subprocess

from pathlib import Path

import pytest

from blastbox.host.runtime.fc_snapshot_launcher import (
    REL_OUTDISK,
    REL_VSOCK,
    FcSnapshotLauncher,
    api_boot_sequence,
)


class FakeCfg:
    fc_bin = "/opt/kata/bin/firecracker"
    fc_kernel = "/assets/vmlinux"
    fc_rootfs = "/assets/rootfs.ext4"
    fc_vcpu_count = 1
    fc_mem_mib = 1024
    fc_vsock_guest_cid = 3


# --- api_boot_sequence (pure) ---------------------------------------------


def test_api_boot_sequence_mirrors_cold_config_and_starts_last():
    seq = api_boot_sequence(FakeCfg())
    assert [p for p, _ in seq] == [
        "/boot-source",
        "/drives/rootfs",
        "/drives/outdisk",
        "/machine-config",
        "/vsock",
        "/entropy",
        "/actions",
    ]
    bodies = dict(seq)
    assert bodies["/boot-source"]["kernel_image_path"] == "/assets/vmlinux"
    # virtio-rng entropy device + RDRAND seeding so the guest CRNG inits promptly
    # (otherwise getrandom() blocks ~120s and the warm worker times out).
    assert bodies["/entropy"] == {}
    assert "random.trust_cpu=on" in bodies["/boot-source"]["boot_args"]
    assert bodies["/drives/rootfs"]["path_on_host"] == "/assets/rootfs.ext4"
    assert bodies["/drives/rootfs"]["is_read_only"] is True
    # writable per-slot resources are RELATIVE (the per-slot-cwd mechanism)
    assert bodies["/drives/outdisk"]["path_on_host"] == REL_OUTDISK
    assert bodies["/vsock"]["uds_path"] == REL_VSOCK
    assert bodies["/machine-config"] == {
        "vcpu_count": 1,
        "mem_size_mib": 1024,
        "smt": False,
    }
    assert seq[-1] == ("/actions", {"action_type": "InstanceStart"})


def test_api_boot_sequence_paths_overridable():
    seq = dict(
        api_boot_sequence(
            FakeCfg(), vsock_uds="/abs/v.sock", outdisk_path="/abs/o.ext4"
        )
    )
    assert seq["/vsock"]["uds_path"] == "/abs/v.sock"
    assert seq["/drives/outdisk"]["path_on_host"] == "/abs/o.ext4"


# --- launcher (injected deps) ---------------------------------------------


class FakeApi:
    def __init__(self, sock):
        self.sock = sock
        self.calls = []

    def put(self, path, body=None):
        self.calls.append((path, body))
        return 204


class FakeProc:
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


def _make_outdisk_file(p) -> None:
    """Stand-in for mkfs: the base outdisk must EXIST for checkpoint to freeze it."""
    from pathlib import Path as _P

    path = _P(p)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"ext4")


def test_boot_base_uses_api_socket_and_runs_full_config(tmp_path):
    spawned = []
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append((argv, cwd)) or FakeProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()

    argv, cwd = spawned[0]
    assert argv[0] == "/opt/kata/bin/firecracker"
    assert "--api-sock" in argv
    assert "--no-api" not in argv and "--config-file" not in argv
    # Build-UNIQUE, not the fixed base/: two dispatchers sharing scratch_root both recreated that
    # one path, so one could publish its memory snapshot paired with the other's ext4 image.
    assert cwd.startswith(str(tmp_path / "snap" / "base-")), cwd
    assert cwd != str(tmp_path / "snap" / "base")
    assert [p for p, _ in handle.api.calls] == [
        "/boot-source",
        "/drives/rootfs",
        "/drives/outdisk",
        "/machine-config",
        "/vsock",
        "/entropy",
        "/actions",
    ]
    assert handle.vsock_uds == str(Path(cwd) / REL_VSOCK)  # the build's OWN workdir


class FakeApiPatch(FakeApi):
    """FakeApi that also records PATCH (checkpoint needs Pause + CreateSnapshot)."""

    def patch(self, path, body=None):
        self.calls.append((path, body))
        return 204


def test_boot_base_handle_checkpoint_writes_artifact_under_base_and_mem_dir(tmp_path):
    """boot_base()'s handle.checkpoint(dest) Pause+Full-snapshots: the state file lands
    under dest (base), the mem file under the launcher's mem_dir (the RAM-preload toggle
    flows through the launcher to the boot handle)."""
    base = tmp_path / "snap"
    memdir = tmp_path / "ram"  # stand-in for /dev/shm
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=memdir,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    dest = base / "base"
    art = handle.checkpoint(dest)

    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact

    assert isinstance(art, FcSnapshotArtifact)
    # Generation-stamped, NOT fixed: a rebuild must never overwrite files that live restored
    # microVMs are still using as memory backing (upstream, PR #82).
    assert art.snapshot_path.parent == dest
    assert (
        art.snapshot_path.name.startswith("warm-")
        and art.snapshot_path.suffix == ".snapshot"
    )
    assert art.mem_path.parent == memdir  # mem on the launcher's mem_dir
    assert art.mem_path.name.startswith("warm-") and art.mem_path.suffix == ".mem"
    # The boot PUTs ran first; checkpoint appended PATCH /vm Paused + PUT create Full.
    assert ("/vm", {"state": "Paused"}) in handle.api.calls
    assert (
        "/snapshot/create",
        {
            "snapshot_type": "Full",
            "snapshot_path": str(art.snapshot_path),
            "mem_file_path": str(art.mem_path),
        },
    ) in handle.api.calls


def test_boot_base_handle_checkpoint_defaults_mem_to_base_dir(tmp_path):
    """No mem_dir given → the boot handle's checkpoint writes its mem file under base_dir."""
    base = tmp_path / "snap"
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    art = handle.checkpoint(base / "base")
    assert art.mem_path.parent == base  # defaults to base_dir
    assert art.mem_path.name.startswith("warm-") and art.mem_path.suffix == ".mem"


def test_restore_in_spawns_in_slot_cwd_and_copies_base_outdisk(tmp_path):
    spawned = []
    made = []
    copied = []
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append((argv, cwd)) or FakeProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: made.append(Path(p)),
        copy_outdisk=lambda src, dst: copied.append((Path(src), Path(dst))),
    )
    # The base outdisk (copy source) must exist for restore_in to proceed.
    (tmp_path / "snap" / "base").mkdir(parents=True)
    (tmp_path / "snap" / "base" / REL_OUTDISK).write_bytes(b"")
    slot = tmp_path / "snap" / "slots" / "slot-7"
    handle = launcher.restore_in(slot)

    _, cwd = spawned[0]
    assert cwd == str(slot)  # firecracker runs in the per-slot cwd
    assert handle.vsock_uds == str(slot / REL_VSOCK)
    # The per-slot disk is a COPY of the base outdisk (snapshot-time-consistent ext4),
    # NOT a fresh mkfs — a fresh mkfs corrupts the restored guest's cached ext4 state.
    assert made == []  # no fresh mkfs on restore
    assert copied == [(tmp_path / "snap" / "base" / REL_OUTDISK, slot / REL_OUTDISK)]


def test_spawn_kills_proc_when_api_socket_never_appears(tmp_path):
    """_spawn must terminate the spawned firecracker if the API socket times out."""

    class TrackProc:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    proc = TrackProc()

    def never_ready(p):
        raise TimeoutError("api socket never appeared")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path,
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=never_ready,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
    )
    import pytest

    with pytest.raises(TimeoutError):
        launcher.boot_base()
    assert proc.terminated is True


class _TrackProc:
    def __init__(self):
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


def test_boot_base_kills_proc_when_post_spawn_step_fails(tmp_path):
    """If make_outdisk / the boot PUTs raise AFTER _spawn, the FC proc must be killed
    (the caller never gets a _Handle to kill, so boot_base must do it)."""
    import pytest

    proc = _TrackProc()

    def boom(p):
        raise OSError("ENOSPC making outdisk")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        make_outdisk=boom,
    )
    with pytest.raises(OSError):
        launcher.boot_base()
    assert proc.terminated is True


def test_restore_in_kills_proc_when_copy_fails(tmp_path):
    """If the outdisk copy raises after _spawn, the restored FC proc must be killed."""
    import pytest

    proc = _TrackProc()
    base = tmp_path / "snap"
    (base / "base").mkdir(parents=True)
    (base / "base" / REL_OUTDISK).write_bytes(b"")  # base outdisk exists

    def boom(src, dst):
        raise OSError("disk full copying outdisk")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        popen=lambda argv, cwd=None: proc,
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
        copy_outdisk=boom,
    )
    with pytest.raises(OSError):
        launcher.restore_in(base / "slots" / "s1")
    assert proc.terminated is True


def test_restore_in_raises_and_does_not_spawn_when_base_outdisk_missing(tmp_path):
    """No base outdisk → fail fast with FileNotFoundError and never spawn FC."""
    import pytest

    spawned = []
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        tmp_path / "snap",
        popen=lambda argv, cwd=None: spawned.append(1) or _TrackProc(),
        api_factory=FakeApi,
        wait_socket=lambda p: None,
        # Actually create it: checkpoint now REFUSES to publish an artifact without its
        # generation disk, because a None outdisk makes restore fall back to the shared
        # fixed path and can pair this memory snapshot with a disk another build made.
        make_outdisk=_make_outdisk_file,
        copy_outdisk=lambda s, d: None,
    )
    with pytest.raises(FileNotFoundError):
        launcher.restore_in(tmp_path / "snap" / "slots" / "s1")
    assert spawned == []  # never spawned FC since the source is missing


def test_checkpoint_fails_when_its_generation_disk_is_missing(tmp_path):
    """Publishing without the snapshot-time disk reintroduces the corruption stamping prevents.

    An artifact with outdisk_path=None makes restore_in() fall back to the fixed shared
    base/outdisk.ext4 — which is either still absent (every restore fails) or gets recreated by a
    later build, pairing THIS generation's memory with a different disk: the "EXT4-fs error:
    Directory block failed checksum" case.
    """
    from blastbox.host.runtime.fc_snapshot import SnapshotBuildError

    base = tmp_path / "snap"
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=tmp_path / "ram",
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=lambda p: None,  # deliberately does NOT create it
    )
    handle = launcher.boot_base()

    with pytest.raises(SnapshotBuildError):
        handle.checkpoint(base)


def test_a_partial_checkpoint_whose_cleanup_fails_is_retried(tmp_path, monkeypatch):
    """Stranded partials are invisible to the manager, so the launcher must retry them itself.

    No artifact is returned for a failed checkpoint, and the unique generation name means no
    later build or sweep can rediscover the files — a RAM-sized memory file would be stranded on
    /dev/shm on every such failure.
    """
    base = tmp_path / "snap"
    memdir = tmp_path / "ram"
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=memdir,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()

    created: list[Path] = []

    def _create_then_fail(api, snap, mem):
        for s in (snap, mem):
            Path(s).parent.mkdir(parents=True, exist_ok=True)
            Path(s).write_bytes(b"partial")
            created.append(Path(s))
        raise RuntimeError("snapshot create failed after writing")

    monkeypatch.setattr(
        "blastbox.host.runtime.fc_snapshot_backend._create_snapshot", _create_then_fail
    )

    unlink_broken = {"on": True}
    real_unlink = Path.unlink

    def _flaky_unlink(self, *a, **kw):
        if unlink_broken["on"] and self.name.startswith("warm-"):
            raise OSError(5, "Input/output error")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", _flaky_unlink)
    with pytest.raises(Exception):
        handle.checkpoint(base)
    assert any(p.exists() for p in created), "sanity: cleanup failed, files remain"

    # A NEW handle, as production does: SnapshotManager kills and abandons the failed one, so a
    # retry list recorded on the handle would go with it. Reusing the same handle here is why the
    # first version of this test passed against that bug.
    unlink_broken["on"] = False
    monkeypatch.undo()
    monkeypatch.setattr(
        "blastbox.host.runtime.fc_snapshot_backend._create_snapshot",
        lambda api, snap, mem: (
            Path(snap).write_bytes(b"s"),
            Path(mem).write_bytes(b"m"),
        ),
    )
    handle2 = launcher.boot_base()
    handle2.checkpoint(base)

    assert not any(p.exists() for p in created), (
        f"stranded partials were never retried: {[p for p in created if p.exists()]}"
    )


def test_orphan_generations_from_a_dead_dispatcher_are_swept(tmp_path):
    """Nothing reclaimed generations across a restart.

    The current artifact is never retired at shutdown and no startup path looked for older ones,
    so every restart — clean or not — left its .snapshot, RAM-sized .mem and copied outdisk
    behind, and repeated deployments filled the scratch filesystem or /dev/shm.
    """

    base = tmp_path / "snap"
    memdir = tmp_path / "ram"
    base.mkdir()
    memdir.mkdir()

    from blastbox.host.runtime.snapshot_backend import owner_lease_path, owner_token

    # A dead owner is one whose LEASE nobody holds -- provable across PID namespaces, unlike a
    # pid check. Create the lease file and leave it unlocked: that is what the kernel leaves
    # behind when the holder dies.
    dead = "999999999_4242"
    owner_lease_path(base, dead).write_bytes(b"")
    mine = owner_token()

    orphan_snap = base / f"warm-{dead}-000000000000000001.snapshot"
    orphan_mem = memdir / f"warm-{dead}-000000000000000001.mem"
    ours = base / f"warm-{mine}-000000000000000002.snapshot"
    unrelated = base / "warm.snapshot"  # legacy fixed name, not a generation
    for f in (orphan_snap, orphan_mem, ours, unrelated):
        f.write_bytes(b"x")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=memdir,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    removed = launcher.sweep_orphan_generations()

    assert removed == 2, f"expected the two dead-pid files to be swept (got {removed})"
    assert not orphan_snap.exists() and not orphan_mem.exists()
    assert ours.exists(), "a generation owned by THIS process must never be swept"
    assert unrelated.exists(), "an unparseable name must be left alone"


def test_the_sweep_never_touches_a_live_dispatchers_generation(tmp_path):
    """Deleting a running dispatcher's generation pulls the backing store out from under its live
    microVMs — far worse than the leak. A pid we cannot signal counts as alive."""

    import fcntl

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    base = tmp_path / "snap"
    base.mkdir()
    # A DIFFERENT owner -- one whose lease is genuinely held, as a live dispatcher in another PID
    # namespace would hold it. The pid rule called this one dead; the flock cannot.
    other = "999999999_4242"
    lease = owner_lease_path(base, other)
    lease.write_bytes(b"")
    holder = open(lease, "a+b")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    live = base / f"warm-{other}-000000000000000003.mem"
    live.write_bytes(b"x")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    try:
        assert launcher.sweep_orphan_generations() == 0
        assert live.exists(), (
            "a live owner's generation was swept -- its microVMs map that file"
        )
    finally:
        holder.close()


def test_generation_ownership_survives_pid_reuse(tmp_path):
    """A pid ALONE is not an identity.

    A dispatcher running as PID 1 in a container — the normal case — sees every replacement
    container reuse PID 1, so a pid-only check treated each prior container's generations as its
    own and swept nothing, while every deployment added another RAM-sized .mem.
    """
    import os

    from blastbox.host.runtime.fc_snapshot_launcher import (
        _generation_owner,
        _owner_alive,
        owner_token,
    )

    mine = owner_token()
    assert "_" in mine, "the token must carry more than a pid"
    assert _owner_alive(mine) is True

    # SAME pid, different start time: a recycled pid is a different process.
    recycled = f"{os.getpid()}_1"
    assert _owner_alive(recycled) is False, (
        "a reused pid with a different start time must not be treated as the live owner"
    )

    assert _generation_owner(f"warm-{mine}-0000000000000000001.mem") == mine
    # A legacy pid-only name is still parseable, or a rolling upgrade strands every pre-upgrade
    # generation forever.
    assert _generation_owner("warm-999999999-0000000000000000001.mem") == "999999999"
    assert _generation_owner("warm.snapshot") is None


def test_a_generation_from_a_reused_pid_is_swept(tmp_path):
    """The end-to-end consequence of the identity fix — now gated on a LEASE.

    "Our pid with a different start time" is precisely what a still-running dispatcher in another
    PID namespace looks like from here, so the pid rule alone must no longer authorise deletion:
    it is the rolling-deployment shape that unlinked a live owner's memory file. Only an unheld
    lease proves death.
    """
    import os

    from blastbox.host.runtime.snapshot_backend import owner_lease_path, owner_token

    base = tmp_path / "snap"
    base.mkdir()

    stale = (
        base / f"warm-{os.getpid()}_1-0000000000000000001.mem"
    )  # our pid, old start time
    ours = base / f"warm-{owner_token()}-0000000000000000002.mem"
    stale.write_bytes(b"x")
    ours.write_bytes(b"x")

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    assert launcher.sweep_orphan_generations() == 0, (
        "with no lease its death is unprovable -- that pid may be a LIVE dispatcher in another "
        "namespace, and unlinking its .mem corrupts the microVMs mapping it"
    )
    assert stale.exists()

    # Its lease, released (what the kernel leaves behind when the owner dies).
    owner_lease_path(base, f"{os.getpid()}_1").write_bytes(b"")
    assert launcher.sweep_orphan_generations() == 1
    assert not stale.exists(), "a prior container's generation must be reclaimed"
    assert ours.exists(), "our own generation must never be swept"


def test_the_retry_list_stays_shared_across_handles(tmp_path, monkeypatch):
    """Rebinding the reference detaches the handle from the owner's list.

    After one failed cleanup the sweep did `self._stranded_partials = still`, which points the
    HANDLE at a private copy — every later extend() lands there, and the next handle (still
    holding the original) never sees those files. That silently undid the durability fix.
    """
    base = tmp_path / "snap"
    memdir = tmp_path / "ram"
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=memdir,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()

    created: list[Path] = []

    def _create_then_fail(api, snap, mem):
        for s in (snap, mem):
            Path(s).parent.mkdir(parents=True, exist_ok=True)
            Path(s).write_bytes(b"partial")
            created.append(Path(s))
        raise RuntimeError("create failed")

    monkeypatch.setattr(
        "blastbox.host.runtime.fc_snapshot_backend._create_snapshot", _create_then_fail
    )
    real_unlink = Path.unlink

    def _always_fails(self, *a, **kw):
        if self.name.startswith("warm-"):
            raise OSError(5, "Input/output error")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", _always_fails)

    # TWO failed checkpoints on the same handle: the first populates the list, the second appends
    # after the sweep has run once -- which is where the rebinding took effect.
    for _ in range(2):
        with pytest.raises(Exception):
            handle.checkpoint(base)

    assert launcher._stranded_partials, (
        "the launcher's durable list is empty — the handle rebound to a private copy, so the "
        "next build would never retry these files"
    )
    assert len(launcher._stranded_partials) >= len(created), (
        f"only {len(launcher._stranded_partials)} of {len(created)} stranded files reached the "
        "shared list"
    )


def test_a_sweep_that_could_not_remove_an_orphan_reports_it(tmp_path, monkeypatch):
    """The launcher logged per-path unlink failures and returned a success count anyway.

    SnapshotManager latches "swept" on a clean return, so a swallowed EIO/EROFS meant the orphan
    was never retried for the life of the dispatcher. The layer that decides whether cleanup
    happened must not lie about it — same rule as discard().
    """
    import errno as _errno

    base = tmp_path / "base"
    base.mkdir()
    mem = tmp_path / "mem"
    mem.mkdir()
    # An orphan owned by a token whose process is gone.
    orphan = mem / "warm-999999_1234-000000000000000001.mem"
    orphan.write_bytes(b"x" * 8)

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    owner_lease_path(base, "999999_1234").write_bytes(b"")

    def _boom(self, missing_ok=False):
        raise OSError(_errno.EIO, "unlink failed")

    monkeypatch.setattr(Path, "unlink", _boom)

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=mem)
    with pytest.raises(OSError) as ei:
        launcher.sweep_orphan_generations()
    assert "warm-999999_1234" in str(ei.value)


def test_a_clean_sweep_still_reports_success(tmp_path, monkeypatch):
    """The carve-out stays narrow: an orphan that IS removed reports normally."""

    base = tmp_path / "base"
    base.mkdir()
    mem = tmp_path / "mem"
    mem.mkdir()
    orphan = mem / "warm-999999_1234-000000000000000001.mem"
    orphan.write_bytes(b"x" * 8)
    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    owner_lease_path(base, "999999_1234").write_bytes(b"")

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=mem)
    assert launcher.sweep_orphan_generations() == 1
    assert not orphan.exists()


def test_a_lease_survives_an_owner_whose_deletion_failed(tmp_path, monkeypatch):
    """The retry was enabled and then made ineffective by its own cleanup.

    The owner went into reclaimed_owners before the unlink was attempted, so a transient EIO
    pruned its lease anyway. On the next build the retry finds no lease, reads the owner as
    conservatively alive, and skips that RAM-sized artifact permanently.
    """
    import errno as _errno

    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    base = tmp_path / "base"
    base.mkdir()
    mem = tmp_path / "mem"
    mem.mkdir()
    # ONE owner, SEVERAL generations -- the real FC shape (.snapshot + .mem + outdisk, across two
    # directories). The first is removed, the second is not: that is the case where the guard is
    # load-bearing, because the owner is both reclaimed AND failed.
    ok = base / "warm-999999_1234-000000000000000001.snapshot"
    ok.write_bytes(b"x")
    orphan = mem / "warm-999999_1234-000000000000000002.mem"
    orphan.write_bytes(b"x" * 8)
    lease = owner_lease_path(base, "999999_1234")
    lease.write_bytes(b"")

    # Fail ONLY the .mem unlink. Breaking every unlink would also break the lease prune, so the
    # assertion below would hold no matter what the code did.
    real_unlink = Path.unlink

    def _boom(self, missing_ok=False):
        if self.name.endswith(".mem"):
            raise OSError(_errno.EIO, "unlink failed")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _boom)

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=mem)
    with pytest.raises(OSError):
        launcher.sweep_orphan_generations()

    assert orphan.exists(), "sanity: the .mem really did survive"
    assert lease.exists(), (
        "the lease was pruned for an owner whose generation is still on disk — the next sweep "
        "has nothing left to prove death with, so it skips that file forever"
    )


def test_a_lease_is_pruned_once_every_generation_is_gone(tmp_path):
    """...and it must still be cleaned up on success, or leases accumulate per deployment."""
    from blastbox.host.runtime.snapshot_backend import owner_lease_path

    base = tmp_path / "base"
    base.mkdir()
    mem = tmp_path / "mem"
    mem.mkdir()
    (mem / "warm-999999_1234-000000000000000001.mem").write_bytes(b"x")
    (base / "warm-999999_1234-000000000000000001.snapshot").write_bytes(b"x")
    lease = owner_lease_path(base, "999999_1234")
    lease.write_bytes(b"")

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=mem)
    assert launcher.sweep_orphan_generations() == 2
    assert not lease.exists()


def test_stranded_partials_are_retried_before_the_base_boots(tmp_path):
    """The retry ran only in checkpoint(), which happens AFTER a successful boot.

    boot_base() creates the outdisk in the same base_dir, so when the stranded leftovers were
    themselves what filled the filesystem, the boot failed on ENOSPC and the cleanup that would
    have freed the space was never reached — the tier stayed cold permanently, long after the
    transient unlink problem cleared.
    """
    base = tmp_path / "snap"
    base.mkdir()
    leftover = base / "warm-old-000000000000000001.snapshot"
    leftover.write_bytes(b"x" * 32)

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    launcher._stranded_partials.append(str(leftover))

    launcher.boot_base()

    assert not leftover.exists(), (
        "the leftover was still on disk after the boot -- if it is what filled the filesystem, "
        "the boot fails before checkpoint() and the retry is unreachable forever"
    )
    assert launcher._stranded_partials == []


def test_no_generation_is_written_without_a_lease(tmp_path, monkeypatch):
    """Not best-effort. The sweep's whole rule is that a lease nobody holds proves its owner
    dead, so a generation with no lease can be reclaimed by another dispatcher while this
    process's microVMs are still mapping it. Failing the build leaves the tier cold; proceeding
    risks corrupting live guests."""
    from blastbox.host.runtime import fc_snapshot_launcher as mod
    from blastbox.host.runtime.fc_snapshot import SnapshotBuildError

    monkeypatch.setattr(mod, "_hold_owner_lease", lambda d: False)

    base = tmp_path / "snap"
    base.mkdir()
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    with pytest.raises(SnapshotBuildError):
        handle.checkpoint(base)
    assert not list(base.glob("warm-*")), (
        "a generation was written with no lease covering it"
    )


def test_legacy_pre_generation_artifacts_are_surfaced(tmp_path, monkeypatch, caplog):
    """The sweep only visits warm-*, so pre-generation names are invisible to it.

    On an upgrade the old warm.mem is guest-RAM-sized and typically sits on the very tmpfs the
    replacement generation needs, so the tier can fail EVERY build with ENOSPC while the new
    per-build sweep skips those files entirely.
    """
    import logging as _logging

    monkeypatch.delenv("BLASTBOX_SNAPSHOT_RECLAIM_LEGACY", raising=False)
    base = tmp_path / "snap"
    base.mkdir()
    mem = tmp_path / "ram"
    mem.mkdir()
    legacy_snap = base / "warm.snapshot"
    legacy_mem = mem / "warm.mem"
    legacy_snap.write_bytes(b"x" * 16)
    legacy_mem.write_bytes(b"y" * 32)

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=mem)
    with caplog.at_level(
        _logging.WARNING, logger="blastbox.host.runtime.fc_snapshot_launcher"
    ):
        launcher.sweep_orphan_generations()

    assert "legacy_artifacts_present" in caplog.text, (
        "an upgraded tier failing every build with ENOSPC had nothing pointing at the cause"
    )
    assert legacy_snap.exists() and legacy_mem.exists(), (
        "they were deleted on a guess -- their owner predates leases, so an overlapping old "
        "dispatcher may still be mapping them"
    )


def test_legacy_artifacts_are_reclaimed_only_on_an_explicit_opt_in(
    tmp_path, monkeypatch
):
    """...and the operator, who alone knows the old dispatcher is gone, can say so."""
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_RECLAIM_LEGACY", "1")
    base = tmp_path / "snap"
    base.mkdir()
    legacy = base / "warm.mem"
    legacy.write_bytes(b"y" * 32)
    keep = (
        base / "warm-999999_1-000000000000000001.mem"
    )  # a real generation, not legacy
    keep.write_bytes(b"z")

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=base)
    launcher.sweep_orphan_generations()

    assert not legacy.exists()
    assert keep.exists(), (
        "a generation-stamped file was reclaimed by the LEGACY path, which has no lease check"
    )


def test_a_dead_dispatchers_base_workdir_is_reclaimed(tmp_path):
    """Each build now gets its OWN base workdir, so they accumulate one per build.

    The same lease-proved rule must reclaim them: its outdisk is only a copy SOURCE until
    checkpoint freezes the generation's own copy, so a dead owner's base dir is as safe to remove
    as its warm-* files — and as unsafe to remove while its owner lives.
    """
    from blastbox.host.runtime.snapshot_backend import owner_lease_path, owner_token

    base = tmp_path / "snap"
    base.mkdir()
    dead = base / "base-999999_4242-0000000000000000001"
    dead.mkdir()
    (dead / "outdisk.ext4").write_bytes(b"x" * 8)
    owner_lease_path(base, "999999_4242").write_bytes(
        b""
    )  # released: owner provably gone
    mine = base / f"base-{owner_token()}-0000000000000000002"
    mine.mkdir()

    launcher = FcSnapshotLauncher(FakeCfg(), base, mem_dir=base)
    launcher.sweep_orphan_generations()

    assert not dead.exists(), (
        "per-build base workdirs are never reclaimed, so they accumulate one per build forever"
    )
    assert mine.exists(), "this process's own base workdir must never be swept"


def test_a_completed_base_workdir_is_removed(tmp_path):
    """Each rebuild gets its OWN base dir, holding a 600 MiB outdisk.

    The orphan sweep deliberately skips paths owned by THIS process, so repeated in-process
    invalidations accumulated one per rebuild until the snapshot filesystem filled. Its outdisk is
    only a copy SOURCE — checkpoint has frozen the generation's own copy by the time the manager
    kills the base.
    """
    base = tmp_path / "snap"
    base.mkdir()
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    workdir = Path(handle.vsock_uds).parent
    assert workdir.exists() and workdir.name.startswith("base-")

    handle.kill()

    assert not workdir.exists(), (
        "the finished base workdir was kept, so every in-process rebuild leaves another 600 MiB "
        "behind and the sweep will not touch it (it belongs to a LIVE owner)"
    )


def test_a_base_workdir_is_retained_when_its_vm_will_not_die(tmp_path):
    """The carve-out: a firecracker we could not reap may still be writing to it."""
    base = tmp_path / "snap"
    base.mkdir()

    class _Undead(FakeProc):
        def poll(self):
            return None  # never exits

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("fc", timeout or 5)

        def kill(self):
            pass  # SIGKILL lands, but the process still will not reap

    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: _Undead(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    workdir = Path(handle.vsock_uds).parent

    # ...and it must SAY SO. Returning normally told both callers the teardown was confirmed:
    # reap() then releases the generation pin and the pool forgets the slot, so a later
    # invalidation can unlink snapshot memory beneath a still-running microVM.
    from blastbox.host.runtime.fc_snapshot import SnapshotError

    with pytest.raises(SnapshotError):
        handle.kill()

    assert workdir.exists(), (
        "the workdir was removed under a microVM that could not be confirmed gone"
    )


def test_a_base_workdir_that_could_not_be_removed_is_retried(tmp_path, monkeypatch):
    """Discarding the handle after a transient failure leaked up to 600 MiB per rebuild.

    sweep_orphan_generations skips base-* paths owned by THIS process, so nothing else can ever
    reclaim it — the leak outlives the problem that caused it.
    """
    from blastbox.host.runtime import fc_snapshot_launcher as mod

    base = tmp_path / "snap"
    base.mkdir()
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=FakeApiPatch,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    handle = launcher.boot_base()
    workdir = Path(handle.vsock_uds).parent

    failing = {"on": True}
    real_rmtree = mod.shutil.rmtree

    def _rmtree(path, onerror=None, **kw):
        if failing["on"] and onerror is not None:
            onerror(None, str(path), (OSError, OSError(5, "EIO"), None))
            return
        return real_rmtree(path, **kw)

    monkeypatch.setattr(mod.shutil, "rmtree", _rmtree)
    handle.kill()

    assert workdir.exists(), "sanity: the cleanup really did fail"
    assert str(workdir) in launcher._stranded_partials, (
        "the only retry handle was discarded, so nothing can ever reclaim this workdir"
    )

    # ...and the next build retries it once the problem clears.
    failing["on"] = False
    launcher.boot_base()
    assert not workdir.exists(), "the retained workdir was never retried"
    assert str(workdir) not in launcher._stranded_partials


def test_a_failed_base_boot_removes_its_unique_workdir(tmp_path):
    """_make_outdisk may already have written 600 MiB before a later boot step raises.

    No handle is returned on failure, so nothing else knows the directory exists — and the sweep
    skips base-* paths owned by THIS process, so every async build retry left another one behind
    until the snapshot filesystem filled.
    """

    class _BoomApi(FakeApiPatch):
        def put(self, path, body):
            raise RuntimeError("boot sequence failed")

    base = tmp_path / "snap"
    base.mkdir()
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: FakeProc(),
        api_factory=_BoomApi,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    with pytest.raises(RuntimeError):
        launcher.boot_base()

    leftovers = list(base.glob("base-*"))
    assert leftovers == [], (
        f"a failed boot left its unique workdir behind: {leftovers} -- nothing else can ever "
        f"reclaim it, so every retry adds another"
    )


def test_a_failed_boot_retains_the_workdir_of_a_live_microvm(tmp_path):
    """_terminate_proc used to swallow the second TimeoutExpired and return nothing.

    So the failed-boot cleanup could not tell a dead process from a live one: it unlinked a LIVE
    microVM's workdir — its disk and sockets — and dropped the only process handle, leaving an
    untracked VM per retry.
    """

    class _Undead(FakeProc):
        def poll(self):
            return None

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("fc", timeout or 5)

        def kill(self):
            pass

    class _BoomApi(FakeApiPatch):
        def put(self, path, body):
            raise RuntimeError("boot sequence failed")

    base = tmp_path / "snap"
    base.mkdir()
    launcher = FcSnapshotLauncher(
        FakeCfg(),
        base,
        mem_dir=base,
        popen=lambda argv, cwd=None: _Undead(),
        api_factory=_BoomApi,
        wait_socket=lambda p: None,
        make_outdisk=_make_outdisk_file,
    )
    with pytest.raises(RuntimeError):
        launcher.boot_base()

    leftovers = list(base.glob("base-*"))
    assert leftovers, (
        "the workdir of a microVM that could NOT be confirmed gone was removed -- its disk and "
        "sockets pulled out from under a live VM"
    )
    assert str(leftovers[0]) in launcher._stranded_partials, (
        "...and it was not retained for retry either, so nothing can ever reclaim it"
    )
