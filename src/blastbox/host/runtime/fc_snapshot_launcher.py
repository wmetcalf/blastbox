"""Firecracker launcher for the snapshot tier (Phase 2).

The cold tier launches ``firecracker --no-api --config-file``; the snapshot tier
needs the **API socket** so it can configure + start a base VM, snapshot it, and
later load+resume per slot. This module is the ``SnapshotLauncher`` implementation
``SnapshotManager`` calls — process spawning + socket waiting + the READY signal
are injected so the orchestration is unit-tested without a real Firecracker.

Per-slot vsock uniqueness (the Phase 0 finding: ``/snapshot/load`` has no vsock
override): the writable per-slot resources — the vsock UDS and the output disk —
are configured with **relative** paths and each firecracker runs with its own
**cwd**, so the same baked-in relative path resolves to a distinct per-slot socket
+ disk after restore. rootfs/kernel stay absolute (shared, read-only). **Confirmed on
toolz2 (FC v1.12.1):** FC re-creates the relative vsock UDS in each restore's cwd, and
the full snapshot→restore→convert round-trip works pixel-identically (see the spec).
"""
from __future__ import annotations

import shutil
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from blastbox.host.runtime.fc_api import FcApiClient
from blastbox.host.runtime.snapshot_backend import (
    generation_owner as _generation_owner,
)
from blastbox.host.runtime.snapshot_backend import (
    hold_owner_lease as _hold_owner_lease,
)
from blastbox.host.runtime.snapshot_backend import (
    prune_owner_lease as _prune_owner_lease,
)
from blastbox.host.runtime.snapshot_backend import (
    owner_alive as _owner_alive,
)
from blastbox.host.runtime.snapshot_backend import (
    owner_token,
)
from blastbox.host.runtime.fc_snapshot import SnapshotBuildError, SnapshotError

_log = logging.getLogger("blastbox.host.runtime.fc_snapshot_launcher")

# Relative per-slot resource names (resolved against each firecracker's cwd).
REL_VSOCK = "vsock.sock"
REL_OUTDISK = "outdisk.ext4"
# `random.trust_cpu=on` seeds the guest CRNG from RDRAND at boot; paired with the
# virtio-rng `/entropy` device in `api_boot_sequence`, this stops a guest workload
# (e.g. a JVM's SecureRandom/getrandom) blocking ~120s on an uninitialised CRNG —
# which otherwise collides with the warm worker timeout and fails every job.
_BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off init=/init ro random.trust_cpu=on"
_DEFAULT_OUTDISK_MIB = 600


def api_boot_sequence(
    cfg: Any,
    *,
    vsock_uds: str = REL_VSOCK,
    outdisk_path: str = REL_OUTDISK,
) -> list[tuple[str, dict[str, Any]]]:
    """The ordered ``(api_path, body)`` PUTs that configure + start a base microVM
    over the API — the API-socket equivalent of the cold ``fc-config.json``.

    rootfs/kernel are absolute (shared, read-only); ``vsock_uds`` + ``outdisk_path``
    default to **relative** names so each restore's cwd yields a distinct socket +
    disk. ``InstanceStart`` is last."""
    return [
        (
            "/boot-source",
            {"kernel_image_path": cfg.fc_kernel, "boot_args": _BOOT_ARGS},
        ),
        (
            "/drives/rootfs",
            {
                "drive_id": "rootfs",
                "path_on_host": cfg.fc_rootfs,
                "is_root_device": True,
                "is_read_only": True,
            },
        ),
        (
            "/drives/outdisk",
            {
                "drive_id": "outdisk",
                "path_on_host": outdisk_path,
                "is_root_device": False,
                "is_read_only": False,
            },
        ),
        (
            "/machine-config",
            {
                "vcpu_count": cfg.fc_vcpu_count,
                "mem_size_mib": cfg.fc_mem_mib,
                "smt": False,
            },
        ),
        (
            "/vsock",
            {"guest_cid": cfg.fc_vsock_guest_cid, "uds_path": vsock_uds},
        ),
        # virtio-rng entropy device — host-fed randomness so the guest CRNG seeds
        # promptly (see _BOOT_ARGS). Captured in the snapshot, so every restore has it.
        # REQUIRES Firecracker >= 1.15.1 (earlier versions have a guest-reachable
        # virtio-rng host-memory DoS); we run v1.16.0.
        # NOTE: seeding before checkpoint means the CRNG STATE is cloned into every
        # restore. The reseed is the guest kernel's job via VMGenID, so the snapshot
        # tier REQUIRES a >= 5.18 guest kernel (enforced in select_snapshot_runtime);
        # a privilege-dropped userspace reseed can't credit entropy and was dropped.
        ("/entropy", {}),
        ("/actions", {"action_type": "InstanceStart"}),
    ]


def _retry_stranded_partials(stranded: "list[str]") -> None:
    """Re-attempt deletion of partial checkpoints a previous failed attempt could not remove.

    MUTATED IN PLACE. Rebinding detaches the caller from the launcher/backend list it was given,
    so every later extend() lands on a private copy and the next handle -- still holding the
    original -- never sees those files. That silently undid the durability this list exists for
    (PR #82).
    """
    if not stranded:
        return
    still: list[str] = []
    for leftover in stranded:
        p = Path(leftover)
        try:
            if p.is_dir():
                # base-* workdirs land here too: a failed cleanup parks the whole directory.
                errs: list[str] = []
                shutil.rmtree(p, onerror=lambda fn, q, exc: errs.append(str(q)))
                if errs:
                    still.append(leftover)
            else:
                p.unlink(missing_ok=True)
        except OSError:
            still.append(leftover)
    stranded[:] = still


class _Handle:
    def __init__(
        self, proc, api, vsock_uds: str, ready_check=None, mem_dir: Path | None = None,
        base_outdisk: Path | None = None, stranded: list[str] | None = None,
    ) -> None:
        self.proc = proc
        self.api = api
        self.vsock_uds = vsock_uds
        self._ready_check = ready_check
        # Only the base (boot) handle carries a mem_dir — it's the one that gets
        # checkpoint()ed. Restore handles don't snapshot, so they leave it None.
        self._mem_dir = mem_dir
        # The snapshot-time ext4 image this base booted with; frozen per generation at checkpoint.
        self._base_outdisk = Path(base_outdisk) if base_outdisk is not None else None
        # This build's OWN base workdir (base handles only); removed once its VM is provably gone.
        self._base_workdir = Path(base_outdisk).parent if base_outdisk is not None else None
        # Partial-checkpoint files whose cleanup failed. This list is OWNED BY THE LAUNCHER and
        # shared in, because SnapshotManager kills and abandons this handle after a failed
        # checkpoint -- anything recorded here alone would be discarded with it (PR #82).
        self._stranded_partials: list[str] = stranded if stranded is not None else []

    def wait_ready(self, timeout_s: float) -> None:
        if self._ready_check is not None:
            self._ready_check(timeout_s)

    def checkpoint(self, dest_dir: Path) -> object:
        """Pause + Full-snapshot this base microVM. The state file lands under
        ``dest_dir`` (the manager's base dir); the big mem file lands under the
        launcher's ``mem_dir`` (tmpfs when the RAM-preload toggle is on). Returns the
        opaque :class:`FcSnapshotArtifact` the manager round-trips to ``restore_in``."""
        from blastbox.host.runtime.fc_snapshot_backend import (
            FcSnapshotArtifact,
            _create_snapshot,
        )

        if self._mem_dir is None:
            raise RuntimeError("checkpoint() called on a handle without a mem_dir")
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        self._mem_dir.mkdir(parents=True, exist_ok=True)
        # GENERATION-STAMPED, never fixed names. invalidate_base() drops the in-memory artifact
        # and the next build() checkpoints again -- into these same paths if they are constant. But
        # restored microVMs keep using the memory file as their backing store for as long as they
        # live, so rewriting it under them can SIGBUS or silently corrupt every old-generation VM,
        # including slots that are mid-job. A fresh generation per build means a rebuild can never
        # touch a file another VM is still mapping; the old files are reclaimed when their last
        # user is reaped (upstream, PR #82).
        # Retry anything a previous failed checkpoint could not remove. Also attempted BEFORE the
        # base boots (see boot_base) -- reaching only this point is too late when the leftovers
        # are what filled the filesystem.
        _retry_stranded_partials(self._stranded_partials)

        # Take the lease BEFORE the first generation exists, and REFUSE to write one without it.
        # `dest` is the manager's base dir -- the very directory the launcher's sweep consults,
        # and deliberately NOT mem_dir, which is usually a separate tmpfs.
        #
        # Not best-effort. An uncovered generation is not merely leaked: the sweep's whole rule is
        # that a lease nobody holds proves its owner dead, so a generation with no lease can be
        # reclaimed by another dispatcher while this process's microVMs are still mapping it.
        # Failing the build leaves the tier cold; proceeding risks corrupting live guests
        # (upstream, PR #82).
        if not _hold_owner_lease(dest):
            raise SnapshotBuildError(
                f"refusing to write a snapshot generation without a lease in {dest}: another "
                f"dispatcher could reclaim it while this one is still using it"
            )
        gen = f"{owner_token()}-{time.monotonic_ns():019d}"
        snap = dest / f"warm-{gen}.snapshot"
        mem = self._mem_dir / f"warm-{gen}.mem"
        outdisk: Path | None = dest / f"warm-{gen}.outdisk.ext4"
        try:
            _create_snapshot(self.api, str(snap), str(mem))
            # Freeze THIS generation's disk alongside its memory. boot_base() recreates the base
            # workdir's outdisk on every build, so copying it at RESTORE time would pair a rebuilt
            # disk with a retired memory snapshot. `dest` is the manager's base_dir, so the
            # snapshot-time image is dest/base/outdisk.ext4.
            # From the handle's OWN workdir, not derived from `dest`: boot_base knows exactly
            # where it made the disk, while `dest` is the caller's artifact directory and the two
            # only coincide in production. Inferring it made this depend on a caller convention.
            base_outdisk = self._base_outdisk
            if base_outdisk is None or not base_outdisk.exists() or outdisk is None:
                # FAIL the build. Publishing with outdisk_path=None makes restore_in() fall back
                # to the fixed shared base/outdisk.ext4 -- which is either still missing (every
                # restore fails) or gets recreated by a later build, pairing THIS generation's
                # memory with a different disk. That is exactly the ext4 checksum corruption
                # generation-stamping exists to prevent (PR #82).
                raise SnapshotBuildError(
                    f"snapshot-time base outdisk missing after checkpoint: {base_outdisk}"
                )
            shutil.copy2(base_outdisk, outdisk)
        except BaseException:
            # /snapshot/create can write EITHER file and then report an error (a lost response
            # after Firecracker already committed the snapshot is the obvious way). No artifact
            # is returned, so SnapshotManager never learns these paths exist and can never
            # discard them. Because every retry now picks a unique generation name, repeated
            # build failures accumulate full RAM-sized .mem files instead of overwriting the
            # previous attempt, until /dev/shm or the disk is exhausted (upstream, PR #82).
            stranded: list[str] = []
            for path in (snap, mem, outdisk):
                if path is None:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except OSError as unlink_exc:
                    stranded.append(str(path))
                    _log.warning("fc_snapshot: could not remove partial %s: %s", path, unlink_exc)
            if stranded:
                # No artifact is returned, so the manager never learns these paths exist -- and the
                # unique generation name means no later build or sweep can rediscover them. A
                # RAM-sized memory file would be stranded on /dev/shm on every such failure, so
                # record them for the launcher's own retry rather than dropping them (PR #82).
                self._stranded_partials.extend(stranded)
            raise
        return FcSnapshotArtifact(snap, mem, outdisk)

    def kill(self) -> None:
        gone = True
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    gone = False
        self._remove_base_workdir(confirmed=gone)
        if not gone:
            # RAISE. Recording `gone=False` and returning normally told both callers the teardown
            # was CONFIRMED: FcSnapshotRuntime.reap() then releases the generation pin and lets
            # the pool forget the slot, so a later invalidation can unlink snapshot memory beneath
            # a still-running microVM; and SnapshotManager._kill_base() drops the only handle to
            # the base process, so replacement capacity is launched beside an untracked one. Both
            # callers already treat an exception as "unconfirmed" -- this one just never told
            # them (upstream, PR #82).
            raise SnapshotError(
                "firecracker did not exit after SIGKILL; its microVM may still be running"
            )

    def _remove_base_workdir(self, *, confirmed: bool) -> None:
        """Drop this build's own base workdir once its VM is provably gone.

        Every rebuild now gets a UNIQUE base-<owner>-<ns> dir (so two dispatchers cannot pair one's
        memory snapshot with the other's ext4), and each holds a default 600 MiB outdisk. The
        orphan sweep deliberately skips paths owned by THIS process, so repeated in-process
        invalidations accumulated one of those per rebuild until the snapshot filesystem filled.
        Its outdisk is only a copy SOURCE -- checkpoint has already frozen the generation's own
        copy by the time the manager kills the base -- so once the VM is gone the directory is
        dead weight.

        RETAINED when teardown is unconfirmed: a firecracker we could not reap may still be
        writing to it, and the next sweep reclaims it once this process is gone (upstream, PR #82).
        """
        if self._base_workdir is None:
            return
        if not confirmed:
            _log.warning(
                "fc_snapshot: base workdir %s retained -- its microVM could not be confirmed "
                "gone", self._base_workdir,
            )
            return
        errs: list[str] = []
        shutil.rmtree(self._base_workdir, onerror=lambda fn, p, exc: errs.append(str(p)))
        if errs:
            # RETRYABLE, not forgotten. Discarding the only handle after a transient EIO / RO
            # mount / permission failure left up to a 600 MiB outdisk per rebuild that nothing
            # could ever reclaim: sweep_orphan_generations skips base-* paths owned by THIS
            # process, so the leak outlives the problem that caused it. The stranded list is the
            # existing durable mechanism -- it is owned by the launcher and retried before every
            # boot and every checkpoint (upstream, PR #82).
            self._stranded_partials.append(str(self._base_workdir))
            _log.warning("fc_snapshot: could not remove base workdir %s (retained for retry)",
                         self._base_workdir)
        self._base_workdir = None


def _terminate_proc(proc: "subprocess.Popen | None") -> bool:
    """Kill a spawned firecracker so partial-failure paths don't leak an orphaned microVM.

    Returns True when exit is CONFIRMED. It used to swallow the second TimeoutExpired and return
    nothing, so a caller could not tell a dead process from a live one -- and the failed-boot
    cleanup then unlinked a LIVE microVM's workdir (its disk and sockets) and dropped the only
    process handle, leaving an untracked VM per retry (upstream, PR #82). Safe on None /
    already-exited procs.
    """
    if proc is None or proc.poll() is not None:
        return True
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return False
    return True


def _default_wait_socket(path: Path, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"firecracker API socket {path} did not appear within {timeout_s}s")


def _default_make_outdisk(path: Path) -> None:
    # Host-only: a fast single-use ext4 (no root needed). Injected in tests.
    from blastbox.host.runtime.firecracker import make_ext4

    make_ext4(path, _DEFAULT_OUTDISK_MIB)


def _default_copy_outdisk(src: Path, dst: Path) -> None:
    # Copy the base outdisk image byte-for-byte (preserves the exact ext4 the guest
    # snapshotted with). Prefer a reflink (CoW clone — near-instant on xfs/btrfs);
    # ``--reflink=auto`` falls back to a full copy on filesystems without CoW (ext4,
    # tmpfs), so this is safe everywhere and only speeds up reflink-capable hosts. On
    # any failure (no ``cp``, odd platform) fall back to a plain Python copy.
    try:
        subprocess.run(
            ["cp", "--reflink=auto", str(src), str(dst)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        shutil.copyfile(src, dst)


class FcSnapshotLauncher:
    """Spawns ``firecracker --api-sock`` processes for snapshot build + restore.

    All host-touching deps (process spawn, API-socket wait, output-disk creation,
    READY signal) are injected so boot/restore orchestration is unit-tested.
    """

    def __init__(
        self,
        cfg: Any,
        base_dir: Path,
        *,
        mem_dir: Path | None = None,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        api_factory: Callable[[str], Any] = FcApiClient,
        wait_socket: Callable[[Path], None] | None = None,
        make_outdisk: Callable[[Path], None] = _default_make_outdisk,
        copy_outdisk: Callable[[Path, Path], None] = _default_copy_outdisk,
        ready_check_factory: Callable[[Path], Callable[[float], None]] | None = None,
    ) -> None:
        self._cfg = cfg
        self._base_dir = Path(base_dir)
        # Durable across boot handles: a handle is abandoned after a failed checkpoint.
        self._stranded_partials: list[str] = []
        # Where the snapshot mem file (~guest RAM) is written at checkpoint time. The
        # base handle carries this so its checkpoint() places mem on the right dir
        # (tmpfs /dev/shm when the RAM-preload toggle is on). Defaults to base_dir.
        self._mem_dir = Path(mem_dir) if mem_dir is not None else self._base_dir
        self._popen = popen
        self._api_factory = api_factory
        self._wait_socket = wait_socket or (lambda p: _default_wait_socket(p))
        self._make_outdisk = make_outdisk
        self._copy_outdisk = copy_outdisk
        self._ready_check_factory = ready_check_factory

    def _spawn(self, workdir: Path):
        workdir.mkdir(parents=True, exist_ok=True)
        api_sock = workdir / "fc-api.sock"
        # Drop stale sockets from a previous crashed run in this workdir so (a)
        # _wait_socket can't return on a stale fc-api.sock, and (b) firecracker can
        # bind the vsock UDS instead of failing on an existing path. The per-port
        # guest→host sockets (vsock.sock_<port>) are re-created by VsockReadySignal.
        for stale in (api_sock, workdir / REL_VSOCK, *workdir.glob(f"{REL_VSOCK}_*")):
            try:
                stale.unlink(missing_ok=True)
            except OSError:
                pass
        # cwd=workdir so the relative vsock/outdisk paths resolve per-slot.
        proc = self._popen(
            [self._cfg.fc_bin, "--api-sock", str(api_sock)], cwd=str(workdir)
        )
        try:
            self._wait_socket(api_sock)
        except Exception:
            # Don't leak the spawned firecracker if the API socket never appears.
            _terminate_proc(proc)
            raise
        return proc, self._api_factory(str(api_sock))

    def boot_base(self):
        """Boot the base microVM (fresh) for snapshotting."""
        # BEFORE _make_outdisk, which writes into this same base_dir. The retry used to live only
        # in checkpoint(), which runs after a successful boot -- so when the stranded leftovers
        # were themselves what filled the filesystem, boot_base failed on ENOSPC creating the
        # outdisk and the cleanup that would have freed the space was never reached. The tier
        # stayed cold permanently, long after the transient unlink problem cleared. Same shape as
        # the retired-generation sweep: a retry is worthless if the condition it fixes is what
        # stops you reaching it (upstream, PR #82).
        _retry_stranded_partials(self._stranded_partials)
        # A BUILD-UNIQUE base workdir, never the fixed base/. Two dispatchers sharing scratch_root
        # -- the rolling-deployment overlap this whole module is hardened for -- both booted from
        # base/outdisk.ext4 and both RECREATED it. If B remade that path after A booted but before
        # A copied it at checkpoint, A published its memory snapshot paired with B's different
        # ext4 image, and restoring that generation produces exactly the metadata/checksum
        # corruption generation stamping exists to prevent. The gVisor builder already uses a
        # per-build bundle dir; this side did not (upstream, PR #82).
        workdir = self._base_dir / f"base-{owner_token()}-{time.monotonic_ns():019d}"
        proc, api = self._spawn(workdir)
        # Everything after _spawn must kill the FC process on failure — the caller only
        # gets a _Handle (and its kill()) if boot_base RETURNS, so a raise here would
        # otherwise orphan the microVM (e.g. make_outdisk hits ENOSPC, a PUT errors).
        try:
            self._make_outdisk(workdir / REL_OUTDISK)
            for path, body in api_boot_sequence(self._cfg):
                api.put(path, body)
            ready = (
                self._ready_check_factory(workdir / REL_VSOCK)
                if self._ready_check_factory
                else None
            )
        except Exception:
            if not _terminate_proc(proc):
                # UNCONFIRMED: the microVM may still be running with this workdir's disk and
                # sockets open. Removing it now would pull them out from under a live VM, and the
                # process handle would be gone too -- so retain both and let the next build retry.
                self._stranded_partials.append(str(workdir))
                _log.warning("fc_snapshot: firecracker for base workdir %s could not be confirmed "
                             "gone; retaining it for retry", workdir)
                raise
            # The workdir is UNIQUE per build now, and _make_outdisk may already have written a
            # 600 MiB image into it. No handle is returned on failure, so nothing else knows this
            # directory exists -- and the orphan sweep deliberately skips base-* paths owned by
            # THIS process, so every async build retry left another one behind until the snapshot
            # filesystem filled. Remove it, and park it for retry if that fails (upstream, PR #82).
            errs: list[str] = []
            shutil.rmtree(workdir, onerror=lambda fn, p, exc: errs.append(str(p)))
            if errs:
                self._stranded_partials.append(str(workdir))
                _log.warning("fc_snapshot: could not remove failed base workdir %s "
                             "(retained for retry)", workdir)
            raise
        return _Handle(
            proc,
            api,
            str(workdir / REL_VSOCK),
            ready_check=ready,
            mem_dir=self._mem_dir,
            base_outdisk=workdir / REL_OUTDISK,
            # SHARED list owned by the launcher: SnapshotManager kills and abandons this handle
            # after a failed checkpoint, so anything recorded on the handle itself is discarded
            # with it and the next build starts empty -- the retry could never fire (PR #82).
            stranded=self._stranded_partials,
        )

    def sweep_orphan_generations(self) -> int:
        """Remove generation files left behind by a dispatcher that is no longer running.

        Generation names are ``warm-<pid>-<monotonic_ns>.*``. Nothing retires the CURRENT artifact
        at shutdown and no startup path looked for older ones, so every restart -- clean or not --
        left its .snapshot, RAM-sized .mem and copied outdisk behind, and repeated deployments
        filled the scratch filesystem or /dev/shm (upstream, PR #82).

        Deliberately conservative: a file is removed ONLY when its owning pid is not a live
        process. Deleting a generation belonging to another RUNNING dispatcher would pull the
        backing store out from under its live microVMs, which is far worse than the leak. Files
        whose name does not parse are left alone.
        """
        removed = 0
        failed: list[str] = []
        reclaimed_owners: set[str] = set()
        failed_owners: set[str] = set()
        for directory in {self._base_dir, self._mem_dir}:
            if directory is None or not directory.exists():
                continue
            # base-* too: each build now gets its OWN base workdir (so two dispatchers cannot
            # pair one's memory snapshot with the other's ext4), which means they accumulate one
            # per build unless the same lease-proved sweep reclaims them. Its outdisk is only a
            # copy SOURCE until checkpoint freezes the generation's own copy, so a dead owner's
            # base dir is as safe to remove as its warm-* files -- and as unsafe to remove while
            # its owner lives (upstream, PR #82).
            for path in sorted(directory.glob("warm-*")) + sorted(directory.glob("base-*")):
                token = _generation_owner(
                    path.name, prefix="base-" if path.name.startswith("base-") else "warm-"
                )
                # lease_dir: ownership must be proved by a flock on the SHARED filesystem, not by
                # a pid. Two dispatcher containers overlapping through a rolling deployment both
                # see themselves as pid 1, so the /proc rule declares the live one dead and this
                # sweep would unlink the .mem its microVMs are still mapping (upstream, PR #82).
                # The lease lives beside the base dir for BOTH sweeps -- mem_dir is often a
                # separate tmpfs, so it cannot be the canonical location.
                if (token is None or token == owner_token()
                        or _owner_alive(token, lease_dir=self._base_dir)):
                    continue
                try:
                    if path.is_dir():
                        # NOT ignore_errors: it would report success for a tree this call could
                        # not actually remove, and the caller latches "swept" on a clean return.
                        errs: list[str] = []
                        shutil.rmtree(path, onerror=lambda fn, p, e: errs.append(f"{p}: {e[1]}"))
                        if errs:
                            raise OSError("; ".join(errs))
                    else:
                        path.unlink(missing_ok=True)
                    removed += 1
                    reclaimed_owners.add(token)
                except OSError as exc:
                    # REPORT, don't just log. SnapshotManager runs this once per process and
                    # latches the flag on a clean return, so swallowing a transient EIO/EROFS here
                    # meant the orphan -- a RAM-sized .mem -- was never retried for the life of
                    # the dispatcher. Same reasoning as discard() above: the layer that decides
                    # whether cleanup happened must not lie about it (upstream, PR #82).
                    failed.append(f"{path}: {exc}")
                    failed_owners.add(token)
                    _log.warning("fc_snapshot: could not sweep orphan %s: %s", path, exc)
        # AFTER the loop, and ONLY for owners whose every generation is actually gone.
        #
        # The lease is what proves this owner dead. Pruning it for an owner whose unlink FAILED
        # means the retry -- the whole point of raising below -- finds no lease next build, reads
        # the owner as conservatively alive, and skips that RAM-sized file forever. The retry was
        # enabled and then made ineffective by its own cleanup (upstream, PR #82).
        for token in reclaimed_owners - failed_owners:
            _prune_owner_lease(self._base_dir, token)
        if removed:
            _log.info("fc_snapshot.swept_orphan_generations count=%d", removed)
        self._report_legacy_artifacts()
        if failed:
            raise OSError("could not sweep orphan generations: " + "; ".join(failed))
        return removed

    # Pre-generation names from the parent implementation. A build BEFORE generation stamping
    # wrote these fixed paths; every build since writes warm-<gen>.* and nothing overwrites or
    # retires them.
    _LEGACY_NAMES = ("warm.snapshot", "warm.mem")

    def _report_legacy_artifacts(self) -> None:
        """Surface -- and, only on an explicit opt-in, reclaim -- pre-generation artifacts.

        On an upgrade the old warm.mem is guest-RAM-sized and typically sits on the very tmpfs the
        replacement generation needs, so the upgraded tier can fail EVERY build with ENOSPC while
        the new per-build sweep skips those files entirely (they carry no generation, so they have
        no owner to prove dead).

        Deleting them on a guess is the one thing this module refuses to do: their owner predates
        leases, so there is no way to prove an overlapping old dispatcher is not still mapping
        them -- and unlinking a live one corrupts its microVMs, which is exactly the hazard the
        lease mechanism exists to remove. So: say plainly what is there, how much space it holds
        and how to reclaim it, and act only when an operator says to
        (BLASTBOX_SNAPSHOT_RECLAIM_LEGACY=1) (upstream, PR #82).
        """
        found: list[tuple[Path, int]] = []
        for directory in {self._base_dir, self._mem_dir}:
            if directory is None:
                continue
            for name in self._LEGACY_NAMES:
                path = directory / name
                try:
                    if path.is_file():
                        found.append((path, path.stat().st_size))
                except OSError:
                    continue
        if not found:
            return
        total = sum(size for _, size in found)
        names = ", ".join(f"{p} ({size / (1 << 20):.0f} MiB)" for p, size in found)
        if os.environ.get("BLASTBOX_SNAPSHOT_RECLAIM_LEGACY", "").strip().lower() not in {
            "1", "true", "yes", "on",
        }:
            _log.warning(
                "fc_snapshot.legacy_artifacts_present total=%.0fMiB [%s] -- written by a build "
                "that predates generation stamping. Nothing reclaims them automatically: their "
                "owner predates leases, so an overlapping old dispatcher may still be mapping "
                "them and unlinking one corrupts its microVMs. If no pre-upgrade dispatcher is "
                "running, remove them or set BLASTBOX_SNAPSHOT_RECLAIM_LEGACY=1.",
                total / (1 << 20), names,
            )
            return
        for path, _size in found:
            try:
                path.unlink(missing_ok=True)
                _log.info("fc_snapshot.legacy_artifact_reclaimed path=%s", path)
            except OSError as exc:
                _log.warning("fc_snapshot: could not reclaim legacy artifact %s: %s", path, exc)

    def restore_in(self, slot_workdir: Path, *, outdisk_src: Path | None = None):
        """Spawn a fresh firecracker in ``slot_workdir`` for a snapshot restore. The
        caller (SnapshotManager) issues load+resume; the relative vsock/outdisk
        resolve under this cwd → per-slot uniqueness.

        The per-slot output disk is a **copy of the base outdisk**, NOT a fresh mkfs.
        The base VM snapshotted with its outdisk mounted, so the guest's ext4 metadata
        (superblock, journal, dir checksums) is captured in guest RAM. A fresh mkfs has
        different metadata/UUID → the restored guest's cached state mismatches the disk
        → ``EXT4-fs error: Directory block failed checksum`` corruption. Copying the
        snapshot-time base image (empty at READY) keeps the (disk, guest-RAM) pair
        consistent; writes still land on the isolated per-slot copy (one job per slot)."""
        # Prefer THIS generation's frozen disk; fall back to the shared base only for artifacts
        # built before the disk was versioned.
        # No fixed-path fallback. Every generation carries its OWN frozen disk (checkpoint fails
        # the build otherwise), and borrowing whatever sits at a shared path is how a memory
        # snapshot gets paired with another build's ext4 image (upstream, PR #82).
        base_outdisk = outdisk_src if outdisk_src is not None else self._base_dir / "base" / REL_OUTDISK
        if not base_outdisk.exists():
            # The base outdisk (the snapshot-time ext4 image) MUST survive for the life
            # of the manager — it is the per-slot copy source. Fail clearly rather than
            # deep inside the copy if the base workdir was cleaned.
            raise FileNotFoundError(
                f"base outdisk missing for restore: {base_outdisk} "
                "(the base workdir must be preserved after build())"
            )
        proc, api = self._spawn(Path(slot_workdir))
        # Post-spawn work must kill the FC process on failure (same reason as boot_base):
        # the caller only gets a killable _Handle once restore_in RETURNS.
        try:
            self._copy_outdisk(base_outdisk, Path(slot_workdir) / REL_OUTDISK)
        except BaseException:
            # BaseException: the caller only gets a killable _Handle once restore_in RETURNS, so
            # a KeyboardInterrupt/SystemExit/cancellation here leaks the firecracker process this
            # method just spawned -- permanently, since nothing else knows its pid (PR #82).
            _terminate_proc(proc)
            raise
        return _Handle(proc, api, str(Path(slot_workdir) / REL_VSOCK))
