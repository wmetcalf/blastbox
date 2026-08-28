"""Firecracker microVM slot runtime — strongest isolation tier.

Each slot is a fresh hardware-virtualised Firecracker microVM launched as a
subprocess.  The VM boots the warm worker image from a read-only root disk,
writes output to a per-slot writable ext4 virtio-blk disk, and communicates
the control handshake over AF_VSOCK.  After the VM exits the host reads the
output disk via ``debugfs rdump`` — no mount, no root, no VirtioFS.

Security properties (review will check):
1. Launch argv is ALWAYS a Python list — no shell=True, no shell metacharacters
   from caller values can become new flag elements.
2. The firecracker binary path comes exclusively from operator config
   (``BLASTBOX_FC_BIN`` / ``FCConfig.fc_bin``); job data cannot influence it.
3. vcpu_count defaults to 1.  This is the hard-won mitigation for the
   guest virtio-vsock stream-corruption bug: under concurrent workloads with
   >1 vCPU the guest virtio-vsock driver produces interleaved frames.
   The test suite ASSERTS this default.
4. Output is read from the ext4 disk via ``debugfs rdump`` — never mounted,
   never trusted directly from the guest vsock stream after the job bytes.
   This defends against a compromised guest crafting a malicious disk image
   (ext4 superblock magic is verified; dest path whitespace is rejected;
   extracted size is capped).
5. ``firecracker_available()`` checks binary + /dev/kvm + kernel + rootfs.
   If any component is missing, the FC tier is unavailable and selection falls
   back / refuses with a clear error.
6. The ``subprocess_runner`` and ``ReadySignal`` seams are injectable so the
   unit test suite can drive the full spawn→is_ready→reap state machine
   without a real Firecracker binary, kernel, or rootfs.

Hard-won lessons from RedTusk FirecrackerWorkerRuntime (ported + adapted):
- fc_vcpu_count=1  (vsock corruption mitigation — NEVER increase without
  validating the guest virtio-vsock driver is bug-free at that count)
- Output via virtio-blk ext4 disk, NOT vsock (zero vsock corruption on output)
- debugfs rdump for host-side disk read (no mount, no root)
- ext4 superblock magic check before invoking debugfs
- Extracted-size cap enforced host-side (guest cannot evade it)
"""
from __future__ import annotations

import json
import logging
import os
import re
import selectors
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:
    from blastbox.worker.warm import WarmJobSpec

from blastbox.worker.warm import AckCapability
from blastbox.errors import HOST_RESOURCE_ERRNOS, SandboxError, WarmTimeout
from blastbox.host.pool import Slot, SlotState
from blastbox.worker.fc_guest import (
    MAX_STATUS_BYTES,
    recv_frame,
    recv_line,
    send_frame,
    send_frame_from_file,
    WARM_ACK,
    READY_ACK_SUFFIX,
)

__all__ = [
    "FCConfig",
    "FCError",
    "FCUnavailable",
    "FirecrackerSlotRuntime",
    "firecracker_available",
    "make_ext4",
    "rdump_ext4",
    "FileReadySignal",
    "VsockReadySignal",
    "VsockHostWarmControl",
]


_log = logging.getLogger("blastbox.host.runtime.firecracker")

# ---------------------------------------------------------------------------
# Environment variable keys
# ---------------------------------------------------------------------------

_ENV_FC_BIN = "BLASTBOX_FC_BIN"
_ENV_FC_KERNEL = "BLASTBOX_FC_KERNEL"
_ENV_FC_ROOTFS = "BLASTBOX_FC_ROOTFS"
_ENV_FC_VCPU = "BLASTBOX_FC_VCPU"
_ENV_FC_MEM_MIB = "BLASTBOX_FC_MEM_MIB"
_ENV_FC_OUTDISK_MIB = "BLASTBOX_FC_OUTDISK_MIB"

# Minimum supported Firecracker version. The FC tier unconditionally configures a
# virtio-rng `entropy` device (so the guest CRNG seeds promptly — see the per-slot
# fc-config and the snapshot launcher). FC < 1.15.1 has a virtio-rng bug where
# guest-controlled descriptor chains can drive excessive HOST memory allocation,
# reachable by an untrusted detonation guest. Below this, firecracker_available()
# refuses the tier (falls back to cold) rather than expose the host to that DoS.
_MIN_FC_VERSION: tuple[int, int, int] = (1, 15, 1)

# Minimum guest kernel for the warm-SNAPSHOT tier. Restoring a snapshot clones the
# base VM's kernel CRNG state into every worker; only a VMGenID-aware guest
# (Linux >= 5.18) reseeds the CRNG automatically on restore, so without it clones
# can repeat random output. The snapshot-runtime selector enforces this (the cold
# FC tier boots fresh per job and is unaffected).
_MIN_SNAPSHOT_KERNEL: tuple[int, int] = (5, 18)

# Ready marker filename written by the guest worker into the output disk root.
# The host checks for this file via debugfs after the VM exits.  In the vsock
# control plane the worker sends a READY frame before the warm signal.
_READY_MARKER = "ready"

# AF_VSOCK control plane.  Firecracker's vsock Unix-socket backend: when the
# guest opens an AF_VSOCK connection to CID 2 (host) on port P, firecracker
# connects to a host Unix socket at ``<uds_path>_<P>``.  We pre-bind that socket
# for the READY port so the guest's post-warmup READY frame is received live —
# the disk/marker proxy (FileReadySignal) can only be read AFTER the VM exits,
# so it cannot signal a *warm* slot.  Output stays on the ext4 disk; vsock only
# ever carries small control frames (the "no large vsock transfers" lesson).
_READY_PORT = 10000
_READY_TOKEN = b"READY"
_READY_MAX_BYTES = 64
# Job control plane: the host connects to the guest on this vsock port (via the FC
# UDS + "CONNECT <port>") to deliver one job and read back the status. Must match
# worker.fc_guest.JOB_PORT.
_JOB_PORT = 10001
# A guest connection must send READY within this grace window or it is dropped —
# a connect-but-stall must never delay readiness or wedge the accept thread.
_CONN_GRACE_S = 1.0
# Cap concurrent in-flight (accepted, not-yet-READY) connections so a compromised
# guest cannot exhaust host file descriptors by opening connections in a loop.
_MAX_PENDING_CONNS = 8

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FCError(SandboxError):
    """A Firecracker-specific error (config, launch, or I/O)."""


class FCUnavailable(FCError):
    """Firecracker runtime is not available on this host.

    Raised by ``firecracker_available()`` callers that need a hard failure, and
    by ``FCConfig.from_env()`` when prerequisites are missing.
    """


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FCConfig:
    """Firecracker slot runtime configuration.

    All fields have sane defaults except ``fc_kernel`` and ``fc_rootfs`` which
    MUST be set — there is no meaningful default path.

    Attributes
    ----------
    fc_bin:
        Path to the ``firecracker`` binary.  Must be an executable file.
    fc_kernel:
        Path to the vmlinux / bzImage kernel image (host path).
    fc_rootfs:
        Path to the root filesystem ext4 image (read-only in the guest).
    fc_vcpu_count:
        Number of vCPUs.  **Default 1** — the documented mitigation for the
        guest virtio-vsock stream-corruption bug.  Do not increase without
        validating the guest vsock driver under concurrent load.
    fc_mem_mib:
        Guest RAM in MiB.
    fc_outdisk_mib:
        Size of the per-slot writable output disk in MiB.
    fc_vsock_guest_cid:
        AF_VSOCK guest CID.  Always 3 (FC convention).
    scratch_root:
        Directory under which per-slot scratch dirs are created.  **Keep it
        short**: FC's vsock UDS lives at ``<scratch>/<uuid>/vsock.sock`` and
        AF_UNIX paths cap at ~108 bytes, so a long scratch root silently breaks
        vsock (FC's own control plane AND the readiness listener).  The default
        ``/tmp/blastbox-fc-slots`` is well under the cap; ``__post_init__`` warns
        if a custom value risks exceeding it.
    max_extracted_bytes:
        Host-side cap on total bytes extracted from the output disk.
    """

    fc_bin: str = "firecracker"
    fc_kernel: str = ""
    fc_rootfs: str = ""
    # vcpu_count=1 is the vsock-corruption mitigation — asserted by unit tests.
    fc_vcpu_count: int = 1
    fc_mem_mib: int = 512
    fc_outdisk_mib: int = 256
    fc_vsock_guest_cid: int = 3
    scratch_root: str = "/tmp/blastbox-fc-slots"
    max_extracted_bytes: int = 512 * 1024 * 1024  # 512 MiB

    def __post_init__(self) -> None:
        if self.fc_vcpu_count < 1:
            raise ValueError(
                f"fc_vcpu_count must be >= 1, got {self.fc_vcpu_count}"
            )
        if self.fc_mem_mib < 64:
            raise ValueError(
                f"fc_mem_mib must be >= 64 MiB, got {self.fc_mem_mib}"
            )
        if self.fc_outdisk_mib < 16:
            raise ValueError(
                f"fc_outdisk_mib must be >= 16 MiB, got {self.fc_outdisk_mib}"
            )
        # AF_UNIX paths cap at ~108 bytes. The worst-case vsock UDS is the
        # snapshot tier's <scratch>/slots/<36-char uuid>/vsock.sock_<port> (longer
        # than the cold tier by the "/slots" segment). Warn loudly at config time
        # (an operator sees this) rather than only at per-slot bind-failure.
        worst_case_uds = (
            len(self.scratch_root) + len("/slots/") + 36 + len("/vsock.sock_10000")
        )
        if worst_case_uds > 100:
            _log.warning(
                "fc.scratch_root_long len=%d worst_case_uds=%d (>100) — AF_UNIX "
                "paths cap at ~108 bytes; vsock readiness may fail to bind. Use a "
                "short BLASTBOX_FC_SCRATCH (default /tmp/blastbox-fc-slots).",
                len(self.scratch_root),
                worst_case_uds,
            )

    @classmethod
    def from_env(cls, **overrides: object) -> "FCConfig":
        """Build an FCConfig from ``BLASTBOX_FC_*`` environment variables.

        Unset variables fall back to field defaults.  Raises ``ValueError`` on
        parse failures and ``FCUnavailable`` if kernel or rootfs is unset and
        not supplied via overrides.
        """
        values: dict[str, object] = {}

        def _get_str(key: str) -> str | None:
            return os.environ.get(key, "").strip() or None

        def _get_int(key: str) -> int | None:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return None
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(
                    f"invalid integer for {key}={raw!r}: {exc}"
                ) from exc

        for env_key, field_name, coerce in [
            (_ENV_FC_BIN, "fc_bin", _get_str),
            (_ENV_FC_KERNEL, "fc_kernel", _get_str),
            (_ENV_FC_ROOTFS, "fc_rootfs", _get_str),
            (_ENV_FC_VCPU, "fc_vcpu_count", _get_int),
            (_ENV_FC_MEM_MIB, "fc_mem_mib", _get_int),
            (_ENV_FC_OUTDISK_MIB, "fc_outdisk_mib", _get_int),
        ]:
            val = coerce(env_key)
            if val is not None:
                values[field_name] = val

        values.update(overrides)

        # Validate that the required paths are present.
        kernel = values.get("fc_kernel") or cls.__dataclass_fields__["fc_kernel"].default
        rootfs = values.get("fc_rootfs") or cls.__dataclass_fields__["fc_rootfs"].default
        if not kernel:
            raise FCUnavailable(
                f"{_ENV_FC_KERNEL} must be set to use the Firecracker runtime"
            )
        if not rootfs:
            raise FCUnavailable(
                f"{_ENV_FC_ROOTFS} must be set to use the Firecracker runtime"
            )

        return cls(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def firecracker_version(fc_bin: str) -> tuple[int, int, int] | None:
    """Parse ``<fc_bin> --version`` into a ``(major, minor, patch)`` tuple.

    Returns ``None`` if the binary can't be run or no version can be parsed —
    callers MUST treat that as "unknown / unusable", never as "new enough".
    """
    try:
        proc = subprocess.run(
            [fc_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # First line is e.g. "Firecracker v1.16.0" (possibly with a build suffix).
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)", proc.stdout + proc.stderr)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def guest_kernel_version(vmlinux_path: str) -> tuple[int, int] | None:
    """Best-effort ``(major, minor)`` of the guest kernel from its vmlinux image.

    Reads the ``Linux version X.Y.Z`` banner that lives in the (uncompressed, as
    Firecracker requires) vmlinux ``.rodata``. Returns ``None`` if the file can't
    be read or no banner is found — callers MUST treat that as "unknown", never as
    "new enough". Bounded + chunked so a large image isn't slurped whole.
    """
    pat = re.compile(rb"Linux version (\d+)\.(\d+)")
    try:
        with open(vmlinux_path, "rb") as fh:
            prev = b""
            read = 0
            while read < 128 * 1024 * 1024:  # cap the scan at 128 MiB
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                m = pat.search(prev + chunk)
                if m:
                    return (int(m.group(1)), int(m.group(2)))
                prev = chunk[-32:]  # overlap so a boundary-straddling match isn't lost
    except OSError:
        return None
    return None


def firecracker_available(cfg: FCConfig | None = None) -> bool:
    """Return True iff all FC prerequisites are present on this host.

    Checks:
    - The firecracker binary exists and is executable.
    - ``/dev/kvm`` is present (hardware virtualisation).
    - The kernel image path is set and the file exists.
    - The rootfs image path is set and the file exists.
    - The firecracker binary is >= ``_MIN_FC_VERSION`` (the virtio-rng entropy
      device this tier configures is a guest-reachable host DoS on older FC).

    Any missing/too-old component → False.  This function never raises.
    """
    try:
        if cfg is None:
            try:
                cfg = FCConfig.from_env()
            except (FCUnavailable, ValueError):
                return False

        # Binary
        fc_bin = cfg.fc_bin
        if not fc_bin:
            return False
        bin_path = shutil.which(fc_bin) or fc_bin
        if not os.access(bin_path, os.X_OK):
            _log.debug("firecracker binary not found/executable: %s", bin_path)
            return False

        # KVM
        if not Path("/dev/kvm").exists():
            _log.debug("firecracker_available=False: /dev/kvm missing")
            return False

        # Kernel
        if not cfg.fc_kernel or not Path(cfg.fc_kernel).is_file():
            _log.debug("firecracker_available=False: kernel %r not found", cfg.fc_kernel)
            return False

        # Rootfs
        if not cfg.fc_rootfs or not Path(cfg.fc_rootfs).is_file():
            _log.debug("firecracker_available=False: rootfs %r not found", cfg.fc_rootfs)
            return False

        # Version (probe LAST — only spawn the subprocess once the cheap checks pass).
        # The FC config adds an unconditional virtio-rng entropy device, which is a
        # guest-reachable host-memory DoS on FC < 1.15.1; refuse an older/unknown binary.
        ver = firecracker_version(bin_path)
        if ver is None or ver < _MIN_FC_VERSION:
            _log.warning(
                "firecracker_available=False: %s is version %s, need >= %s "
                "(the virtio-rng entropy device has a guest-reachable host-memory DoS "
                "below this) — falling back off the FC tier",
                bin_path,
                ".".join(map(str, ver)) if ver else "unknown",
                ".".join(map(str, _MIN_FC_VERSION)),
            )
            return False

        return True

    except Exception as exc:  # noqa: BLE001
        _log.debug("firecracker_available check error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# ext4 image helpers (ported from RedTusk, adapted for blastbox)
# ---------------------------------------------------------------------------


def make_ext4(path: Path, size_mib: int) -> None:
    """Create a sparse ext4 image at ``path`` of ``size_mib`` MiB.

    Uses ``mkfs.ext4 -F -O ^has_journal,^metadata_csum -m 0`` for fast, single-use
    images:
    - no journal (the disk is written once in-guest, read once on the host);
    - 0 reserved blocks (maximum usable space for small output disks);
    - NO metadata_csum: this disk is a single-use transfer medium that the guest
      is SIGKILLed off of (never cleanly unmounted), so its block/inode bitmaps are
      always left inconsistent at reap. With metadata_csum, that inconsistency is a
      *checksum mismatch* and ``debugfs`` REFUSES to open the filesystem ("Block
      bitmap checksum does not match bitmap" -> "Filesystem not open"), so rdump
      extracts nothing and a successful job is recorded as
      "metadata.json not found". The intact, fsync'd inodes + dir entries are still
      readable by inode; dropping the checksum lets debugfs open the fs and rdump
      them. Checksums add no value here (they detect long-term on-disk corruption,
      irrelevant for a read-once disk). rdump_ext4 also e2fsck-recovers as a fallback.

    No root required; the caller must own the target path.
    """
    file_path = Path(path)
    with open(file_path, "wb") as f:
        f.truncate(size_mib * 1024 * 1024)
    subprocess.run(
        [
            "mkfs.ext4",
            "-q",
            "-F",
            "-O",
            "^has_journal,^metadata_csum",
            "-m",
            "0",
            str(file_path),
        ],
        check=True,
        capture_output=True,
    )


# What debugfs/e2fsck say when the HOST filesystem -- not the image -- is the problem. Matched
# on the tool's own diagnosis because a CalledProcessError carries no errno.
_HOST_DISK_MARKERS = (
    b"no space left on device",
    b"read-only file system",
    b"input/output error",
    b"disk quota exceeded",
    b"too many open files",
    b"cannot allocate memory",
)

_RDUMP_TIMEOUT_S = 300.0  # debugfs rdump over a fixed-size (<=512 MiB) image completes in seconds;
#                           bound it so a crafted image can't hang the dispatcher indefinitely.


def rdump_ext4(
    image: Path, dest: Path, max_bytes: int, *, timeout_s: float = _RDUMP_TIMEOUT_S
) -> list[str]:
    """Extract an ext4 image's root to ``dest`` WITHOUT mounting (debugfs rdump).

    Defense-in-depth against a compromised worker producing a crafted image:

    1. Whitespace in ``dest`` is rejected outright — debugfs's ``-R`` request
       is space-tokenised and would misparse, silently dropping output.
       ``dest`` derives from ``scratch_root``/<slot_id>/out so this guards
       against misconfigured operators; reject early either way.
    2. The ext4 superblock magic (0xEF53 at offset 0x438) is verified before
       invoking debugfs — catches obviously-corrupt images and gives a smaller
       surface for e2fsprogs CVEs.
    3. Total extracted size is capped at ``max_bytes``.  A runaway worker
       cannot fill the slot dir up to the full disk size.

    Returns the top-level names written to ``dest``.
    Raises ``ValueError`` on any confinement failure.
    """
    dest_str = str(dest)
    if any(c.isspace() for c in dest_str):
        raise ValueError(
            f"rdump dest path must not contain whitespace: {dest_str!r}"
        )

    # Verify ext4 superblock magic before invoking debugfs.
    try:
        with open(image, "rb") as f:
            f.seek(0x438)
            magic = f.read(2)
    except OSError as exc:
        # Keep the HOST-I/O nature visible through the wrapper. EMFILE/EIO/ENOMEM opening the
        # per-slot image is this dispatcher failing, not the guest -- and the warm path convicts
        # on a materialization failure, so flattening it to a bare ValueError blamed healthy
        # guests during a host outage that hits every job at once (PR #82).
        err = ValueError(f"cannot read ext4 image {image}: {exc}")
        err.host_io = True  # type: ignore[attr-defined]
        raise err from exc

    if magic != b"\x53\xef":
        raise ValueError(
            f"ext4 magic check failed on {image} (got {magic!r}); "
            "refusing to invoke debugfs"
        )

    dest.mkdir(parents=True, exist_ok=True)

    def _debugfs_rdump(check: bool) -> "subprocess.CompletedProcess[bytes]":
        return subprocess.run(
            ["debugfs", "-R", f"rdump / {dest_str}", str(image)],
            check=check,
            capture_output=True,
            timeout=timeout_s,
        )

    # First pass is TOLERANT (check=False): the common failure isn't a non-zero exit but
    # "exit 0, extracts nothing" (see below) — but a non-zero exit must ALSO fall through
    # to the e2fsck recovery rather than raise and bypass it.
    proc = _debugfs_rdump(check=False)
    # The guest is SIGKILLed off this disk (never cleanly unmounted), so on a no-journal
    # ext4 its block/inode bitmaps can be left inconsistent at reap. debugfs then refuses
    # to OPEN the filesystem ("Block bitmap checksum does not match bitmap" -> "Filesystem
    # not open") and silently extracts NOTHING despite exit 0 — turning a successful job
    # into "metadata.json not found". make_ext4 drops metadata_csum so this no longer
    # presents as a fatal checksum error, but recover defensively too: if debugfs reports
    # an unreadable fs (or extracts nothing), e2fsck -fy rebuilds the bitmaps from the
    # intact, fsync'd inode tree (userspace, no mount — same trust posture as debugfs),
    # then re-rdump. The retry is OFF the common path (only fires on the failure signature).
    _stderr = proc.stderr if isinstance(proc.stderr, (bytes, bytearray)) else b""
    _bad = (
        proc.returncode != 0
        or b"Filesystem not open" in _stderr
        or b"checksum does not match" in _stderr
    )
    if _bad or not any(dest.iterdir()):
        subprocess.run(
            ["e2fsck", "-fy", str(image)],
            check=False,  # rc 0=clean, 1=fixed; both fine. >1 -> let the retry rdump decide.
            capture_output=True,
            timeout=timeout_s,
        )
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        # After recovery a failure IS fatal (check=True) — surface it loudly rather than
        # silently producing empty output that becomes an opaque "metadata.json not found".
        try:
            _debugfs_rdump(check=True)
        except subprocess.CalledProcessError as exc:
            # debugfs WRITES the extracted tree to the host, so it fails on ENOSPC/EROFS/EIO
            # here -- after the image-open guard above, and as a CalledProcessError, which is
            # neither an OSError nor carries host_io. The warm path convicts on a materialization
            # failure, so a host output filesystem filling up burned out healthy slots and
            # invalidated healthy FC bases, on an outage that hits every job at once. Look at
            # what the tool SAID: only its own diagnosis can distinguish "the host disk failed"
            # from "this image is corrupt" (upstream, PR #82).
            blob = b" ".join(
                x for x in (exc.stderr, exc.stdout) if isinstance(x, (bytes, bytearray))
            ).lower()
            if any(m in blob for m in _HOST_DISK_MARKERS):
                exc.host_io = True  # type: ignore[attr-defined]
            raise

    # debugfs rdump always creates lost+found; remove it so it isn't mistaken
    # for an artifact.
    lf = dest / "lost+found"
    if lf.exists():
        shutil.rmtree(lf, ignore_errors=True)

    # Enforce host-side size cap.
    total = 0
    for p in dest.rglob("*"):
        if p.is_file() and not p.is_symlink():
            total += p.stat().st_size
            if total > max_bytes:
                shutil.rmtree(dest, ignore_errors=True)
                dest.mkdir(parents=True, exist_ok=True)
                raise ValueError(
                    f"extracted output exceeds cap: >{max_bytes} bytes"
                )

    return [p.name for p in dest.iterdir()]


# ---------------------------------------------------------------------------
# Injectable protocol — ready-signal seam
# ---------------------------------------------------------------------------


@runtime_checkable
class ReadySignal(Protocol):
    """Injectable seam: check whether a slot's worker has signalled ready.

    The real implementation polls for a ``ready`` file in the slot's output dir
    (written by the guest after boot + warm).  Test doubles return a preset bool.
    """

    def is_ready(self, slot: Slot) -> bool:
        """Return True if the worker has signalled it is ready."""
        ...


class FileReadySignal:
    """Production ReadySignal: check for a ``ready`` marker in the output dir.

    The guest worker writes an empty ``ready`` file to the root of the output
    disk mount point (``/mnt/outdisk/ready`` inside the guest, which maps to
    the ext4 output disk drive[1]).  On the host we check for this file in
    the slot's output_dir AFTER the VM exits (since we cannot read the mounted
    disk while FC is live without mounting it ourselves).

    For the warm-pool flow, the guest signals READY over vsock before any job
    arrives.  This implementation checks the output_dir for a ``ready`` file as
    a host-side proxy for that signal — suitable for the unit test seam.
    """

    def is_ready(self, slot: Slot) -> bool:
        return (slot.output_dir / _READY_MARKER).exists()


@dataclass
class _VsockReadyState:
    """Per-slot listener state for :class:`VsockReadySignal`."""

    srv: socket.socket
    uds: Path
    ready: threading.Event
    stop: threading.Event
    thread: threading.Thread | None = None


class VsockReadySignal:
    """Production ReadySignal for the FC tier: detect the guest's READY over vsock.

    Firecracker's AF_VSOCK Unix-socket backend works thus: when the guest opens
    an AF_VSOCK connection to CID 2 (the host) on port ``P``, firecracker connects
    to a host Unix socket at ``<uds_path>_<P>``.  So to receive the guest's READY
    frame we pre-bind a Unix listener at ``<slot vsock uds>_<READY_PORT>`` and wait
    for firecracker to connect and forward the guest's bytes.

    Unlike :class:`FileReadySignal` (a post-exit disk proxy that can never signal
    a *live* warm slot), this fires while the VM is running — which is what the
    warm pool needs to promote WARMING → IDLE.

    Lifecycle (driven by :class:`FirecrackerSlotRuntime`):
    - ``prepare(slot)`` MUST run before the VM is launched, so the listener exists
      when the guest connects.  Idempotent.
    - ``is_ready(slot)`` is non-blocking.
    - ``cleanup(slot)`` stops the thread, closes the socket, unlinks the UDS.

    The accept loop reads at most ``max_bytes`` and only ever sets a flag — a
    compromised guest cannot make the host do anything except observe READY.
    """

    def __init__(self, *, max_bytes: int = _READY_MAX_BYTES,
                 ack_capable: "AckCapability | None" = None,
                 defer_ack: bool = False) -> None:
        # Shared with the runtime's warm controls. Populated HERE, at readiness, so a base that is
        # wedged from its very first slot -- no job ever completes, so no ack is ever seen -- is
        # still known to be ack-capable and can arm the fast repair. Learning it only from a
        # completed ack left the repair inert on exactly the poisoned-from-the-outset base it
        # exists to fix, which is what a dispatcher restarting onto a bad artifact produces.
        self._ack_capable = ack_capable if ack_capable is not None else AckCapability()
        # BASE-BUILD listeners defer: their advertisement is only believed once the build has a
        # usable artifact (see AckCapability.observe/publish). Per-slot listeners do not -- a
        # live slot's READY is about an artifact that already published.
        self._defer_ack = defer_ack
        self._max_bytes = max_bytes
        self._slots: dict[str, _VsockReadyState] = {}
        self._lock = threading.Lock()
        # NOTE: the READY port is the module constant _READY_PORT, NOT a parameter
        # — the guest's port (worker.fc_guest.READY_PORT) is fixed, so a divergent
        # host port would silently break the handshake.

    def _uds_for(self, slot: Slot) -> Path:
        # FC's vsock uds_path is ``<slot_dir>/vsock.sock``; ``output_dir`` is
        # ``<slot_dir>/out`` so the slot dir is its parent.  FC connects to
        # ``<uds_path>_<port>`` for guest→host streams.
        return slot.output_dir.parent / f"vsock.sock_{_READY_PORT}"

    def prepare(self, slot: Slot, ack_generation: "int | None" = None) -> None:
        """Bind the READY listener for ``slot``.  Call before launching FC.

        ``ack_generation`` is the generation the caller sampled BEFORE starting the launch this
        listener belongs to. For a base build that is the only honest stamp: prepare() runs after
        _spawn() and the API boot sequence, so an invalidate_base() during those seconds would
        otherwise have this listener teach the REPLACEMENT generation with the retiring base's
        advertisement. Defaults to sampling here, which is right for a per-slot listener.
        """
        with self._lock:
            if slot.slot_id in self._slots:
                return
            uds = self._uds_for(slot)
            try:
                if uds.exists():
                    uds.unlink()
            except OSError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                srv.bind(str(uds))
                srv.listen(16)
                srv.setblocking(False)
            except OSError as exc:
                srv.close()
                # Non-fatal (the pool reaps a slot that never reaches IDLE), but
                # LOUD: a failed bind means readiness can NEVER fire for this slot.
                # The usual cause is the AF_UNIX 108-byte path cap — FC itself hits
                # it too, so keep BLASTBOX_FC_SCRATCH short.
                _log.error(
                    "fc.vsock_ready_bind_failed slot_id=%s uds=%s: %s "
                    "(readiness will never fire; shorten the scratch root — "
                    "AF_UNIX paths cap at 108 bytes)",
                    slot.slot_id, uds, exc,
                )
                return
            state = _VsockReadyState(
                srv=srv, uds=uds, ready=threading.Event(), stop=threading.Event()
            )
            # The generation this listener STARTED under. Without it a listener still running
            # when the base is replaced could teach the new generation with the old base's
            # advertisement -- the same slot-vs-job confusion, one layer out. The caller may have
            # sampled it EARLIER still (before a slow launch); prefer that.
            _gen = ack_generation
            thread = threading.Thread(
                target=self._accept_loop,
                args=(slot.slot_id, state, _gen),
                name=f"fc-vsock-ready-{slot.slot_id[:8]}",
                daemon=True,
            )
            state.thread = thread
            self._slots[slot.slot_id] = state
            thread.start()

    def _accept_loop(self, slot_id: str, state: _VsockReadyState,
                     ack_generation: "int | None" = None) -> None:
        # Non-blocking via selectors so a guest that connects-but-stalls can never
        # head-of-line-block the listener (delaying READY) or wedge this thread
        # (which would stall reap() and the pool). Connections that do not send
        # READY within _CONN_GRACE_S are dropped; in-flight connections are capped
        # so a compromised guest cannot exhaust host fds.
        sel = selectors.DefaultSelector()
        pending: dict[socket.socket, float] = {}

        buffers: dict[socket.socket, bytes] = {}
        try:
            try:
                sel.register(state.srv, selectors.EVENT_READ)
            except (OSError, ValueError):
                # srv was already closed (e.g. cleanup() raced this thread's
                # start). Nothing to listen on; the finally tidies up.
                return
            while not state.stop.is_set():
                try:
                    events = sel.select(timeout=0.5)
                except OSError:
                    break
                for key, _ in events:
                    if key.fileobj is state.srv:
                        try:
                            conn, _ = state.srv.accept()
                        except OSError:
                            continue
                        if len(pending) >= _MAX_PENDING_CONNS:
                            conn.close()  # fd-exhaustion guard
                            continue
                        conn.setblocking(False)
                        sel.register(conn, selectors.EVENT_READ)
                        pending[conn] = time.monotonic() + _CONN_GRACE_S
                        buffers[conn] = b""
                        continue
                    conn = key.fileobj  # type: ignore[assignment]
                    try:
                        data = conn.recv(self._max_bytes)
                    except (BlockingIOError, OSError):
                        data = b""
                    # ACCUMULATE. This is a SOCK_STREAM: one sendall() of "READY+ack1" can arrive
                    # as "READY" then "+ack1", and deciding on the first recv() accepted readiness
                    # and closed the connection -- permanently losing the advertisement on a valid
                    # split. In snapshot mode this listener is the ONLY place it is ever visible,
                    # so that loss makes the fast repair inert on a base wedged from its first
                    # restore. Bounded by _READY_MAX_BYTES and the existing connection grace.
                    buf = (buffers.get(conn, b"") + data)[: self._max_bytes]
                    buffers[conn] = buf
                    _full = _READY_TOKEN + READY_ACK_SUFFIX
                    _decidable = (
                        READY_ACK_SUFFIX in buf      # the advertisement arrived
                        or not data                  # EOF: nothing more is coming
                        or len(buf) >= len(_full)    # enough bytes that a suffix would be here
                    )
                    if _READY_TOKEN in buf and not _decidable:
                        continue                     # READY seen, suffix may still be in flight
                    sel.unregister(conn)
                    pending.pop(conn, None)
                    buffers.pop(conn, None)
                    conn.close()
                    if _READY_TOKEN in buf:
                        if READY_ACK_SUFFIX in buf:
                            # Learned BEFORE any job, which is what makes the fast repair usable
                            # on a base that was already poisoned when this dispatcher started.
                            if self._defer_ack:
                                self._ack_capable.observe(ack_generation)
                            else:
                                self._ack_capable.learn(ack_generation)
                        _log.info("fc.vsock_ready_received slot_id=%s ack_capable=%s",
                                  slot_id, READY_ACK_SUFFIX in buf)
                        state.ready.set()
                        return
                # Drop connections that connected but never sent READY in time.
                now = time.monotonic()
                for conn in [c for c, dl in pending.items() if now > dl]:
                    sel.unregister(conn)
                    pending.pop(conn, None)
                    buffers.pop(conn, None)   # or the buffer outlives the connection
                    conn.close()
        finally:
            buffers.clear()
            for conn in list(pending):
                try:
                    sel.unregister(conn)
                    conn.close()
                except OSError:
                    pass
            sel.close()

    def is_ready(self, slot: Slot) -> bool:
        with self._lock:
            state = self._slots.get(slot.slot_id)
        return bool(state is not None and state.ready.is_set())

    def cleanup(self, slot: Slot) -> None:
        """Stop the listener for ``slot`` and remove its UDS.  Idempotent."""
        with self._lock:
            state = self._slots.pop(slot.slot_id, None)
        if state is None:
            return
        state.stop.set()
        try:
            state.srv.close()
        except OSError:
            pass
        if state.thread is not None:
            state.thread.join(timeout=2.0)
        try:
            if state.uds.exists():
                state.uds.unlink()
        except OSError:
            pass


class VsockHostWarmControl:
    """Host-side vsock counterpart to ``worker.fc_warm.VsockWarmControl``.

    Delivers one job to a warm FC guest over a single host→guest vsock connection
    and reads back the status, mirroring ``worker.warm.HostWarmControl``'s
    interface (``signal_go`` / ``wait_for_done``) so the dispatcher warm path is
    transport-agnostic.

    Firecracker host→guest connect: open the slot's vsock UDS, send
    ``CONNECT <port>\\n``; FC replies ``OK <port>\\n`` once the guest's listener
    accepts, then the stream is full-duplex to the guest. Output is NOT returned
    over vsock — only the status frame is; artifacts come off the ext4 disk via
    ``read_output_disk`` after DONE.
    """

    # Signalling here writes to the guest OVER VSOCK, so a failure is evidence about the worker.
    # The file handshake's equivalent is a host-side write and deliberately does NOT set this.
    signal_is_transport = True

    # None = UNKNOWN (no ack observed: an older guest image, which simply does not send one).
    # True = the guest confirmed it HAS the job. Never False -- absence of evidence is not
    # evidence of absence, and the whole point of this field is to stop the caller guessing.
    guest_started: "bool | None" = None

    def __init__(
        self,
        vsock_uds: Path,
        *,
        job_port: int = _JOB_PORT,
        connect_timeout_s: float = 10.0,
        connect_fn: "Callable[[], socket.socket] | None" = None,
        ack_capable: "AckCapability | None" = None,
        ack_generation: "int | None" = None,
    ) -> None:
        # Shared with the runtime (see host_warm_control); true once the CURRENT base advertised.
        self._ack_capable = ack_capable if ack_capable is not None else AckCapability()
        # The SLOT's generation, taken at SPAWN. Reading it here instead meant an old-generation
        # slot -- left IDLE and claimable by a base invalidation -- picked up the NEW stamp when a
        # job claimed it, and its ack then re-taught the replacement base a capability that only
        # the retired image had. Falls back to the current generation only when nobody can say.
        # None is MEANINGFUL now: "no artifact lifecycle" for the plain FC tier, and
        # "unidentifiable, teaches nothing" for a snapshot slot. There is no current-generation
        # fallback to reach for any more -- that was the second counter #92 deleted.
        self._ack_gen = ack_generation
        self._uds = Path(vsock_uds)
        self._job_port = job_port
        self._connect_timeout = connect_timeout_s
        self._connect_fn = connect_fn  # injectable for tests (no real VM)
        self._conn: "socket.socket | None" = None

    def _connect(self, *, deadline: float | None = None) -> "socket.socket":
        if self._connect_fn is not None:
            return self._connect_fn()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Cap the handshake at the warm deadline (never looser than connect_timeout) so the
        # CONNECT-reply read is inside the same budget as the rest of signal_go — a slowloris
        # guest dribbling the OK\n reply can't pin dispatch.
        s.settimeout(
            self._connect_timeout
            if deadline is None
            else min(self._connect_timeout, max(0.0, deadline - time.monotonic()))
        )
        s.connect(str(self._uds))
        s.sendall(f"CONNECT {self._job_port}\n".encode())
        line = recv_line(s, deadline=deadline)
        if not line.startswith(b"OK"):
            s.close()
            raise FCError(
                f"vsock CONNECT to guest port {self._job_port} failed: {line!r}"
            )
        return s

    def signal_go(self, spec: "WarmJobSpec", *, deadline: float | None = None) -> None:
        """Connect to the guest and send the job header + input frame.

        The input body is STREAMED from disk in fixed chunks (send_frame_from_file), not read
        into RAM — so a warm dispatch holds at most one chunk per in-flight job instead of the
        whole file plus send_frame's len+data copy (~2x). The on-disk input is already bounded
        by max_input_bytes at ingress; the guest's recv_frame independently caps the frame. The
        wire format is unchanged (8-byte length + body), so the guest decodes it identically.

        ``deadline`` (a ``time.monotonic()`` value) bounds the upload so a slow-reading guest
        can't pin the dispatcher during the send (the send runs BEFORE wait_for_done's timeout
        starts, so without this it would otherwise be unbounded).
        """
        # HOST-LOCAL work happens here as well as the transport: creating the Unix socket can
        # fail with EMFILE/ENOMEM, and streaming the staged input stat()s, opens and reads a HOST
        # file, which can fail with EIO. signal_is_transport marks this seam as worker evidence,
        # so without the split a dispatcher outage burned out healthy FC slots and could
        # invalidate their base (PR #82). Connection/protocol failures stay the worker's.
        try:
            return self._signal_go_inner(spec, deadline=deadline)
        except OSError as exc:
            if exc.errno in HOST_RESOURCE_ERRNOS:
                exc.host_io = True  # type: ignore[attr-defined]
            raise

    def _signal_go_inner(self, spec: "WarmJobSpec", *, deadline: float | None = None) -> None:
        path = Path(spec.input_path)
        # ``ack``: ask the guest to send a START frame the moment it has the job, before it
        # begins work. OPT-IN from the host, and unknown header keys are ignored by the guest's
        # .get() parsing, so BOTH mixed-version directions stay safe: an old guest never sends one
        # (the host just never learns the answer), and a new guest never sends one unsolicited, so
        # an old host is not handed a frame it would mistake for the status.
        header = json.dumps(
            {"filename": path.name, "params": dict(spec.params), "ack": True}
        ).encode("utf-8")
        conn = self._connect(deadline=deadline)
        self._conn = conn
        if deadline is not None:
            conn.settimeout(max(0.0, deadline - time.monotonic()))
        send_frame(conn, header)
        send_frame_from_file(conn, path, deadline=deadline)


    def wait_for_done(self, *, timeout_s: float) -> str:
        """Read the guest's status frame; raise WarmTimeout if it never arrives.

        Uses an ABSOLUTE deadline (not a per-recv timeout), so a compromised guest
        that dribbles the status frame cannot pin the dispatcher past ``timeout_s``.

        A guest that honours ``ack`` sends START first. That frame is what separates "this slot
        never executed anything" (the warm base is wedged) from "it started and hung on this
        document" -- indistinguishable otherwise, because the phase timer only records `guest`
        once the work COMPLETES. Absent it, ``guest_started`` stays None, meaning "unknown", and
        nothing downstream is entitled to guess.
        """
        if self._conn is None:
            raise WarmTimeout("signal_go was not called before wait_for_done")
        # SET ONLY HERE, where the host actually waits to find out. Every earlier placement
        # claimed "never started" about a job nobody listened for:
        #   * before the upload -- a guest correctly REFUSING an oversized input frame closes the
        #     connection, and the broken pipe read as a wedge;
        #   * after a successful upload -- a transfer that consumed the whole dispatch deadline
        #     makes the caller return WITHOUT calling this method, so an ack the healthy guest had
        #     already sent was never read.
        # Both convict a base for something the guest did right. Reaching this line means we are
        # about to listen, so a missing ack is genuinely the guest's silence.
        #
        # Only meaningful once this image has been SEEN to ack. Before that a missing ack is
        # indistinguishable from an older worker, and False would be a guess.
        if self._ack_capable.capable_for(self._ack_gen):
            self.guest_started = False
        deadline = time.monotonic() + timeout_s
        try:
            frame = recv_frame(
                self._conn, max_len=MAX_STATUS_BYTES, deadline=deadline
            ).decode("utf-8")
            if frame == WARM_ACK:
                # Ack-capable guest, and it HAS the job. The status is the next frame.
                self.guest_started = True
                self._ack_capable.learn(self._ack_gen)
                frame = recv_frame(
                    self._conn, max_len=MAX_STATUS_BYTES, deadline=deadline
                ).decode("utf-8")
            return frame
        except (OSError, ValueError, ConnectionError) as exc:
            err = WarmTimeout(f"warm worker did not signal done: {exc}")
            # HOST-RESOURCE ATTRIBUTION, mirroring signal_go and the file control's `done` read.
            # An ENOMEM/EMFILE on OUR side of the socket says nothing about the guest -- but we
            # have already set guest_started=False, so without this the host's own resource
            # exhaustion is charged to the worker, and three concurrent ones invalidate a healthy
            # base. Leave the verdict UNKNOWN: we never actually heard from the guest.
            if isinstance(exc, OSError) and exc.errno in HOST_RESOURCE_ERRNOS:
                err.host_io = True  # type: ignore[attr-defined]
                self.guest_started = None
            raise err from exc
        finally:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None


# ---------------------------------------------------------------------------
# Per-slot process handle
# ---------------------------------------------------------------------------


@dataclass
class _FCProcess:
    """Wraps a running FC subprocess for one slot."""

    proc: subprocess.Popen  # type: ignore[type-arg]
    slot_id: str
    config_path: Path
    log_path: Path

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        try:
            self.proc.kill()
        except (ProcessLookupError, OSError):
            pass

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            return self.proc.wait()


# ---------------------------------------------------------------------------
# FirecrackerSlotRuntime
# ---------------------------------------------------------------------------

# Type alias for the injectable subprocess runner — accepts the argv list plus
# keyword args and returns a running Popen-like handle.  The default is the
# real subprocess.Popen; tests inject a factory that returns a FakePopen.
SubprocessRunner = Callable[..., "subprocess.Popen[bytes]"]


def _default_subprocess_runner(argv: list[str], **kwargs: object) -> "subprocess.Popen[bytes]":
    return subprocess.Popen(argv, **kwargs)  # type: ignore[call-overload]


class FirecrackerSlotRuntime:
    """SlotRuntime implementation backed by Firecracker microVMs.

    This is the strongest isolation tier in the blastbox framework — each slot
    gets a fresh hardware-virtualised microVM.  The VM lifecycle is:

    1. ``spawn()`` — create per-slot scratch dirs + output ext4 disk, write the
       FC config JSON (drives, vsock, machine-config), launch FC as a
       subprocess.  Returns a WARMING Slot.
    2. ``is_ready()`` — delegate to the injected ``ReadySignal``.  The real
       implementation polls for a ``ready`` marker that the guest worker writes.
    3. ``is_alive()`` — check whether the FC subprocess is still running.
    4. ``reap()`` — kill FC if alive, remove the scratch dir.

    Injectable seams for testing (no real FC binary, kernel, rootfs needed):
    - ``subprocess_runner``: returns a fake Popen-compatible object.
    - ``ready_signal``: returns a preset bool without touching the filesystem.

    Security properties:
    - Launch argv is a Python list — never shell=True.
    - vcpu_count defaults to 1 (vsock-corruption mitigation).
    - rootfs is read-only (``is_read_only: True``).
    - Output disk is written by the guest, read host-side via debugfs rdump
      (no mount, no root).
    """

    def __init__(
        self,
        cfg: FCConfig,
        *,
        subprocess_runner: SubprocessRunner = _default_subprocess_runner,
        ready_signal: ReadySignal | None = None,
    ) -> None:
        # Shared with every VsockHostWarmControl this runtime hands out: one warm base
        # image, so ack-capability is a property of the image rather than of a job.
        self._ack_capable = AckCapability()
        self._cfg = cfg
        self._subprocess_runner = subprocess_runner
        # Default to the live vsock signal — FileReadySignal cannot signal a warm
        # (still-running) slot, so the warm pool could never promote an FC slot.
        self._ready_signal: ReadySignal = (
            ready_signal if ready_signal is not None
            else VsockReadySignal(ack_capable=self._ack_capable)
        )
        self._scratch_root = Path(cfg.scratch_root)
        # Per-slot process handles; all mutations under _lock.
        self._procs: dict[str, _FCProcess] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # SlotRuntime protocol
    # ------------------------------------------------------------------

    def spawn(self) -> Slot:
        """Create a scratch dir, write fc-config.json, launch Firecracker.

        Returns a Slot in WARMING state.  The slot_id is a UUID-like string
        derived from the scratch dir name.

        Security:
        - argv is a list[str] — no shell.
        - The FC binary comes from ``cfg.fc_bin`` (operator config only).
        - vcpu_count comes from ``cfg.fc_vcpu_count`` (default 1).
        - No caller / job value can influence the argv elements.
        """
        import uuid

        slot_id = str(uuid.uuid4())
        slot_dir = self._scratch_root / slot_id
        output_dir = slot_dir / "out"
        # input_dir and control_dir are not used by the FC runtime (vsock IPC
        # is the control plane); we create them to satisfy the Slot dataclass.
        input_dir = slot_dir / "in"
        control_dir = slot_dir / "ctrl"

        for d in (slot_dir, output_dir, input_dir, control_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Create the per-slot output disk.  The guest mounts this as vdb and
        # writes results here; the host reads it via rdump_ext4 after exit.
        outdisk_path = slot_dir / "outdisk.ext4"
        make_ext4(outdisk_path, self._cfg.fc_outdisk_mib)

        # Build the vsock UDS path.  FC creates <uds_path> for the host side
        # and <uds_path>_<port> for guest connects; we give FC ownership.
        vsock_uds = slot_dir / "vsock.sock"

        # fc-config.json — the sole source of FC configuration.
        fc_config = {
            "boot-source": {
                "kernel_image_path": self._cfg.fc_kernel,
                # `random.trust_cpu=on`: seed the guest CRNG from RDRAND at boot so a
                # workload that needs randomness (e.g. a JVM's SecureRandom/getrandom)
                # doesn't block ~120s on an uninitialised CRNG. Paired with the
                # virtio-rng `entropy` device below — together they cover guests with
                # CONFIG_RANDOM_TRUST_CPU and/or CONFIG_HW_RANDOM_VIRTIO.
                "boot_args": (
                    "console=ttyS0 reboot=k panic=1 pci=off init=/init ro "
                    "random.trust_cpu=on"
                ),
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": self._cfg.fc_rootfs,
                    "is_root_device": True,
                    "is_read_only": True,
                },
                {
                    # drive[1] = per-slot output disk (vdb).  The guest writes
                    # results here; output goes on the disk NOT on vsock (the
                    # hard-won lesson: large vsock transfers corrupt under concurrency).
                    "drive_id": "outdisk",
                    "path_on_host": str(outdisk_path),
                    "is_root_device": False,
                    "is_read_only": False,
                },
            ],
            "machine-config": {
                # vcpu_count=1 is the vsock-corruption mitigation; NEVER
                # increase without validating the guest virtio-vsock driver.
                "vcpu_count": self._cfg.fc_vcpu_count,
                "mem_size_mib": self._cfg.fc_mem_mib,
                "smt": False,
            },
            "vsock": {
                "guest_cid": self._cfg.fc_vsock_guest_cid,
                "uds_path": str(vsock_uds),
            },
            # virtio-rng: a host-fed entropy source so the guest CRNG initialises
            # promptly. Without it (and with no RDRAND trust) getrandom() blocks until
            # the kernel self-seeds (~2 min), which collides with the warm worker
            # timeout and fails the job. Empty body = no rate limiter.
            # REQUIRES Firecracker >= 1.15.1: earlier versions have a virtio-rng bug
            # where guest-controlled descriptor chains can drive excessive HOST memory
            # allocation — reachable by an untrusted detonation guest. We run v1.16.0.
            "entropy": {},
        }

        config_path = slot_dir / "fc-config.json"
        config_path.write_text(json.dumps(fc_config, indent=2))

        log_path = slot_dir / "fc.log"

        # Build the launch argv — ALWAYS a list, NEVER shell=True.
        # Security: fc_bin is the only source of the executable path.
        # No job / caller value can inject new flag elements because each
        # piece (binary, flags, config path) is a separate list element.
        argv: list[str] = [
            self._cfg.fc_bin,
            "--no-api",
            "--config-file",
            str(config_path),
        ]

        _log.info(
            "fc.spawn slot_id=%s argv=%r", slot_id, argv
        )

        slot = Slot(
            slot_id=slot_id,
            control_dir=control_dir,
            input_dir=input_dir,
            output_dir=output_dir,
            state=SlotState.WARMING,
            spawned_at=0.0,
        )

        # Bind the vsock READY listener BEFORE launching FC, so the host socket
        # exists when the guest connects post-warmup.  FileReadySignal has no
        # prepare() and is skipped (it has no live signal).
        prepare = getattr(self._ready_signal, "prepare", None)
        if callable(prepare):
            prepare(slot)

        with open(log_path, "w") as log_fh:
            proc = self._subprocess_runner(
                argv,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )

        fc_proc = _FCProcess(
            proc=proc,
            slot_id=slot_id,
            config_path=config_path,
            log_path=log_path,
        )

        with self._lock:
            self._procs[slot_id] = fc_proc

        # Stamp the generation this slot was SPAWNED from; see Slot.ack_generation.

        # The PLAIN FC runtime has no artifact lifecycle -- every slot is a fresh boot, so there
        # is one image and nothing to tell apart. None means exactly that, and capable_for()
        # answers with the flag alone.
        slot.ack_generation = None


        return slot

    def is_ready(self, slot: Slot) -> bool:
        """Delegate to the injected ReadySignal."""
        try:
            return self._ready_signal.is_ready(slot)
        except Exception as exc:  # noqa: BLE001
            _log.debug("fc.is_ready error slot_id=%s: %s", slot.slot_id, exc)
            return False

    def is_alive(self, slot: Slot) -> bool:
        """Return True iff the Firecracker subprocess is still running."""
        with self._lock:
            fc_proc = self._procs.get(slot.slot_id)
        if fc_proc is None:
            return False
        return fc_proc.is_alive()

    def reap(self, slot: Slot) -> None:
        """Kill FC if alive, remove the scratch dir.

        Safe to call on already-dead or already-reaped slots.
        """
        with self._lock:
            fc_proc = self._procs.pop(slot.slot_id, None)

        # Tear down the vsock READY listener (if any) before removing the dir.
        cleanup = getattr(self._ready_signal, "cleanup", None)
        if callable(cleanup):
            cleanup(slot)

        if fc_proc is not None:
            if fc_proc.is_alive():
                fc_proc.kill()
                try:
                    fc_proc.proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    _log.warning(
                        "fc.reap_wait_timeout slot_id=%s", slot.slot_id
                    )

        # Remove the entire scratch dir.
        slot_dir = self._scratch_root / slot.slot_id
        if slot_dir.exists():
            shutil.rmtree(slot_dir, ignore_errors=True)
            _log.debug("fc.reap_cleaned slot_id=%s", slot.slot_id)

    # ------------------------------------------------------------------
    # Output-disk read (called by the dispatcher after the VM exits)
    # ------------------------------------------------------------------

    def read_output_disk(self, slot: Slot) -> list[str]:
        """Extract the slot's output ext4 disk into ``slot.output_dir``.

        Uses ``rdump_ext4`` — no mount, no root.  The ext4 magic is verified
        before debugfs is invoked.  Extracted size is capped at
        ``cfg.max_extracted_bytes``.

        Returns the top-level names extracted.  Raises ``ValueError`` on
        confinement failures (bad magic, whitespace in dest, size exceeded).
        """
        slot_dir = self._scratch_root / slot.slot_id
        image = slot_dir / "outdisk.ext4"
        if not image.exists():
            raise FCError(
                f"output disk not found for slot {slot.slot_id}: {image}"
            )
        names = rdump_ext4(image, slot.output_dir, self._cfg.max_extracted_bytes)
        _log.info("fc.outdisk_read slot_id=%s entries=%d", slot.slot_id, len(names))
        return names

    # ------------------------------------------------------------------
    # Warm-path seam (duck-typed; the dispatcher uses these for FC slots and
    # falls back to the file-based HostWarmControl for runtimes without them)
    # ------------------------------------------------------------------

    def host_warm_control(self, slot: Slot) -> VsockHostWarmControl:
        """The vsock warm control for this slot — input/status over vsock.

        ``ack_capable`` is shared across slots on purpose: every slot restores from the SAME warm
        base, so whether the guest image speaks the start-ack is a property of the image, not of
        the job. One ack from any slot proves the image sends them -- and only then is a MISSING
        ack meaningful. Until then it just means "older worker", which must not convict anything.
        """
        vsock_uds = self._scratch_root / slot.slot_id / "vsock.sock"
        return VsockHostWarmControl(vsock_uds, ack_capable=self._ack_capable,
                                    ack_generation=slot.ack_generation)

    def stage_warm_input(self, slot: Slot, staged_input_path: Path) -> Path:
        """FC input travels over vsock (signal_go reads this path), NOT through a
        shared slot dir — so return the host-staged path unchanged (no copy)."""
        return staged_input_path

    def materialize_warm_output(self, slot: Slot) -> None:
        """Read the guest's output ext4 disk into slot.output_dir via rdump, so the
        trust gate validates it from a regular directory (no mount, no root)."""
        self.read_output_disk(slot)


# ---------------------------------------------------------------------------
# Runtime selection helper
# ---------------------------------------------------------------------------


def select_fc_runtime(
    *,
    cfg: FCConfig | None = None,
    require_available: bool = False,
    subprocess_runner: SubprocessRunner = _default_subprocess_runner,
    ready_signal: ReadySignal | None = None,
) -> "FirecrackerSlotRuntime | None":
    """Attempt to build a FirecrackerSlotRuntime.

    Returns a configured ``FirecrackerSlotRuntime`` if the FC tier is
    available (binary + /dev/kvm + kernel + rootfs all present), or ``None``
    if it is not.

    Parameters
    ----------
    cfg:
        FCConfig to use; if None, built from env via ``FCConfig.from_env()``.
    require_available:
        If True and the FC tier is not available, raise ``FCUnavailable``
        instead of returning None.  Use when ``BLASTBOX_WORKER_RUNTIME=firecracker``
        was explicitly requested by the operator.
    subprocess_runner, ready_signal:
        Injectable seams passed through to ``FirecrackerSlotRuntime``.
    """
    if cfg is None:
        try:
            cfg = FCConfig.from_env()
        except (FCUnavailable, ValueError) as exc:
            if require_available:
                raise FCUnavailable(
                    f"Firecracker runtime config failed: {exc}"
                ) from exc
            _log.debug("select_fc_runtime: config unavailable: %s", exc)
            return None

    if not firecracker_available(cfg):
        if require_available:
            raise FCUnavailable(
                "Firecracker runtime required (BLASTBOX_WORKER_RUNTIME=firecracker) "
                "but prerequisites missing: check firecracker binary, /dev/kvm, "
                "BLASTBOX_FC_KERNEL, and BLASTBOX_FC_ROOTFS."
            )
        _log.debug("select_fc_runtime: prerequisites not met")
        return None

    return FirecrackerSlotRuntime(
        cfg,
        subprocess_runner=subprocess_runner,
        ready_signal=ready_signal,
    )
