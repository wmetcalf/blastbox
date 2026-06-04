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
+ disk after restore. rootfs/kernel stay absolute (shared, read-only). The runtime
spike must confirm FC re-creates the relative vsock UDS relative to the restore's
cwd before this is enabled.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from blastbox.host.runtime.fc_api import FcApiClient

# Relative per-slot resource names (resolved against each firecracker's cwd).
REL_VSOCK = "vsock.sock"
REL_OUTDISK = "outdisk.ext4"
_BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off init=/init ro"
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
        ("/actions", {"action_type": "InstanceStart"}),
    ]


class _Handle:
    def __init__(self, proc, api, vsock_uds: str, ready_check=None) -> None:
        self.proc = proc
        self.api = api
        self.vsock_uds = vsock_uds
        self._ready_check = ready_check

    def wait_ready(self, timeout_s: float) -> None:
        if self._ready_check is not None:
            self._ready_check(timeout_s)

    def kill(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def _terminate_proc(proc: "subprocess.Popen | None") -> None:
    """Best-effort kill of a spawned firecracker so partial-failure paths don't leak
    an orphaned microVM. Safe on None / already-exited procs."""
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


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
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        api_factory: Callable[[str], Any] = FcApiClient,
        wait_socket: Callable[[Path], None] | None = None,
        make_outdisk: Callable[[Path], None] = _default_make_outdisk,
        copy_outdisk: Callable[[Path, Path], None] = _default_copy_outdisk,
        ready_check_factory: Callable[[Path], Callable[[float], None]] | None = None,
    ) -> None:
        self._cfg = cfg
        self._base_dir = Path(base_dir)
        self._popen = popen
        self._api_factory = api_factory
        self._wait_socket = wait_socket or (lambda p: _default_wait_socket(p))
        self._make_outdisk = make_outdisk
        self._copy_outdisk = copy_outdisk
        self._ready_check_factory = ready_check_factory

    def _spawn(self, workdir: Path):
        workdir.mkdir(parents=True, exist_ok=True)
        api_sock = workdir / "fc-api.sock"
        # Drop any stale socket so _wait_socket can't return on an old file (and
        # firecracker won't fail to bind an existing path).
        try:
            api_sock.unlink(missing_ok=True)
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
        workdir = self._base_dir / "base"
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
            _terminate_proc(proc)
            raise
        return _Handle(proc, api, str(workdir / REL_VSOCK), ready_check=ready)

    def restore_in(self, slot_workdir: Path):
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
        base_outdisk = self._base_dir / "base" / REL_OUTDISK
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
        except Exception:
            _terminate_proc(proc)
            raise
        return _Handle(proc, api, str(Path(slot_workdir) / REL_VSOCK))
