"""SlotRuntime backed by warm-snapshot restore — the warm-UNO Firecracker tier.

``spawn()`` builds **one** warm snapshot on its first call (``SnapshotManager.build``,
constructed via ``SnapshotManager.from_env`` so the RAM-preload toggle —
``BLASTBOX_SNAPSHOT_MEM_TMPFS`` / ``BLASTBOX_SNAPSHOT_MEM_DIR`` — is honored), then
restores it into a fresh per-slot microVM on every subsequent ``spawn()``. The
restored guest resumes **already warm** (the snapshot captured the READY/idle state,
e.g. a live ``unoserver``), so promotion is near-instant — no soffice cold boot per
job. The job protocol (vsock GO/DONE + a fresh per-slot output ext4 disk) and the
warm-path seam (``host_warm_control`` / ``materialize_warm_output``) are **identical**
to the cold :class:`FirecrackerSlotRuntime`; only the boot differs (restore vs
cold-boot). This keeps the dispatcher's per-slot job flow unchanged.

Security properties carry over from the cold tier: no caller value influences any
argv (the launcher builds it from operator ``cfg`` only); the restored rootfs is
read-only; output crosses the trust boundary only via the per-slot ext4 disk, read
host-side via ``rdump_ext4`` (no mount, no root).
"""
from __future__ import annotations

import logging
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from blastbox.host.pool import Slot, SlotState
from blastbox.host.runtime.fc_snapshot import SnapshotManager
from blastbox.host.runtime.fc_snapshot_launcher import REL_OUTDISK, REL_VSOCK

_log = logging.getLogger(__name__)


def _vsock_ready_check_factory(vsock_path: Path) -> Callable[[float], None]:
    """Build a blocking ``ready_check(timeout_s)`` for the base-VM build.

    The base VM warms its engine (e.g. ``unoserver``) then signals READY over vsock;
    we must wait for that *warm-idle* state before snapshotting, or the snapshot would
    capture a half-booted guest. ``vsock_path`` is ``<base>/vsock.sock``; the guest→host
    READY stream lands on ``<base>/vsock.sock_<port>``, which :class:`VsockReadySignal`
    binds from ``slot.output_dir.parent``. We hand it a faux Slot rooted at the base dir."""
    from blastbox.host.runtime.firecracker import VsockReadySignal

    base_dir = vsock_path.parent
    signal = VsockReadySignal()
    faux = Slot(
        slot_id="warm-base",
        control_dir=base_dir,
        input_dir=base_dir,
        output_dir=base_dir / "out",  # parent == base_dir → listener on base/vsock.sock_<port>
        state=SlotState.WARMING,
    )
    signal.prepare(faux)  # bind the listener now (before the guest's READY retries)

    def _wait(timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline:
                if signal.is_ready(faux):
                    return
                time.sleep(0.1)
            raise TimeoutError(
                f"warm base did not signal READY within {timeout_s}s"
            )
        finally:
            signal.cleanup(faux)

    return _wait


class SnapshotSlotRuntime:
    """A :class:`~blastbox.host.pool.SlotRuntime` whose ``spawn`` restores a warm
    snapshot instead of cold-booting.

    Parameters
    ----------
    cfg:
        The FC config (``FCConfig``); used for ``max_extracted_bytes`` on output read.
    manager:
        A :class:`SnapshotManager`, normally built via ``SnapshotManager.from_env``
        so the RAM-preload toggle is respected. Injected for testability.
    """

    def __init__(
        self,
        cfg: object,
        manager: SnapshotManager,
        *,
        settle_s: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cfg = cfg
        self._manager = manager
        # cfg.max_extracted_bytes bounds rdump output; fall back to a 512 MiB default
        # if a bare/stub cfg is injected in tests.
        self._max_extracted_bytes = int(
            getattr(cfg, "max_extracted_bytes", 512 * 1024 * 1024)
        )
        # A freshly-restored guest's vsock DATA path isn't ready the instant resume
        # returns: pushing the job immediately races the device resume and the guest's
        # recv fails with ENOTCONN (observed on toolz2). Hold the slot WARMING for a
        # short settle window after restore before is_ready() promotes it, so the host
        # only pushes a job once the vsock can carry it. Host-side clock (injectable).
        # Default 1.0 s: a settle-sweep (settle_sweep.py, toolz2) found the race resolves
        # sub-second (0.0–2.0 s all passed 6/6); 1.0 s is a conservative margin over the
        # rare intermittent case, and in a steady-state pool it overlaps pre-warming so it
        # adds no per-job latency. Tunable via BLASTBOX_SNAPSHOT_SETTLE_S.
        self._settle_s = settle_s
        self._clock = clock
        self._handles: dict[str, object] = {}
        self._restored_at: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # SlotRuntime protocol
    # ------------------------------------------------------------------

    def spawn(self) -> Slot:
        """Build the warm snapshot once (idempotent), then restore it into a fresh
        per-slot microVM. Returns a WARMING Slot."""
        # build() is idempotent — the snapshot is captured on the first spawn only.
        self._manager.build()
        slot_id = str(uuid.uuid4())
        handle = self._manager.restore(slot_id)
        # The launcher restores in base_dir/slots/<id>; the vsock UDS lives there, so
        # its parent IS the per-slot workdir (vsock.sock + outdisk.ext4 + fc-api.sock).
        slot_workdir = Path(handle.vsock_uds).parent
        output_dir = slot_workdir / "out"
        input_dir = slot_workdir / "in"
        control_dir = slot_workdir / "ctrl"
        for d in (output_dir, input_dir, control_dir):
            d.mkdir(parents=True, exist_ok=True)

        with self._lock:
            self._handles[slot_id] = handle
            self._restored_at[slot_id] = self._clock()

        _log.info("snapshot.spawn slot_id=%s workdir=%s", slot_id, slot_workdir)
        return Slot(
            slot_id=slot_id,
            control_dir=control_dir,
            input_dir=input_dir,
            output_dir=output_dir,
            state=SlotState.WARMING,
            spawned_at=0.0,
        )

    def is_ready(self, slot: Slot) -> bool:
        """The restored guest resumes already-warm (snapshot taken at READY), so it
        never re-signals READY. Readiness = the restore process is alive AND FC
        re-created the per-slot vsock socket (the vsock device restored). A dead guest
        agent is surfaced later by the job protocol's GO failing → the pool reaps it."""
        with self._lock:
            handle = self._handles.get(slot.slot_id)
            restored_at = self._restored_at.get(slot.slot_id)
        if handle is None:
            return False
        if not self._proc_alive(handle):
            return False
        # Hold WARMING until the post-restore vsock settle window elapses.
        if restored_at is not None and self._clock() - restored_at < self._settle_s:
            return False
        try:
            return Path(handle.vsock_uds).exists()  # type: ignore[attr-defined]
        except OSError:
            return False

    def is_alive(self, slot: Slot) -> bool:
        """True iff the restored Firecracker process is still running."""
        handle = self._get(slot.slot_id)
        return handle is not None and self._proc_alive(handle)

    def reap(self, slot: Slot) -> None:
        """Kill the restored microVM (if alive) and remove its per-slot workdir.

        Safe on already-dead / already-reaped slots. The shared snapshot artifact
        (``warm.snapshot`` + ``warm.mem``) lives OUTSIDE ``slots/`` and is preserved."""
        with self._lock:
            handle = self._handles.pop(slot.slot_id, None)
            self._restored_at.pop(slot.slot_id, None)
        if handle is not None:
            try:
                handle.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 — reap must never raise
                _log.warning(
                    "snapshot.reap_kill_error slot_id=%s: %s", slot.slot_id, exc
                )
        # slot.output_dir is <slot_workdir>/out — its parent is the per-slot workdir.
        slot_workdir = Path(slot.output_dir).parent
        if slot_workdir.exists():
            shutil.rmtree(slot_workdir, ignore_errors=True)
            _log.debug("snapshot.reap_cleaned slot_id=%s", slot.slot_id)

    # ------------------------------------------------------------------
    # Warm-path seam (mirrors FirecrackerSlotRuntime so the dispatcher's per-slot
    # job flow is identical: input over vsock, output via the per-slot ext4 disk)
    # ------------------------------------------------------------------

    def host_warm_control(self, slot: Slot) -> object:
        """The vsock warm control for this slot — input/status over vsock."""
        from blastbox.host.runtime.firecracker import VsockHostWarmControl

        vsock_uds = Path(slot.output_dir).parent / REL_VSOCK
        return VsockHostWarmControl(vsock_uds)

    def stage_warm_input(self, slot: Slot, staged_input_path: Path) -> Path:
        """FC input travels over vsock (signal_go reads this path), not via a shared
        dir — so return the host-staged path unchanged (no copy)."""
        return staged_input_path

    def materialize_warm_output(self, slot: Slot) -> None:
        """Read the guest's output ext4 disk into ``slot.output_dir`` (rdump, no mount,
        no root) so the trust gate validates it from a regular directory."""
        self.read_output_disk(slot)

    def read_output_disk(self, slot: Slot) -> list[str]:
        """Extract the slot's per-slot output ext4 disk into ``slot.output_dir``."""
        from blastbox.host.runtime.firecracker import FCError, rdump_ext4

        slot_workdir = Path(slot.output_dir).parent
        image = slot_workdir / REL_OUTDISK
        if not image.exists():
            raise FCError(
                f"output disk not found for slot {slot.slot_id}: {image}"
            )
        names = rdump_ext4(image, slot.output_dir, self._max_extracted_bytes)
        _log.info(
            "snapshot.outdisk_read slot_id=%s entries=%d", slot.slot_id, len(names)
        )
        return names

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _get(self, slot_id: str) -> object | None:
        with self._lock:
            return self._handles.get(slot_id)

    @staticmethod
    def _proc_alive(handle: object) -> bool:
        proc = getattr(handle, "proc", None)
        # A fake/handle without a proc is treated as alive (tests inject this).
        return proc is None or proc.poll() is None


# ---------------------------------------------------------------------------
# Builder — used by pool_config when the warm-snapshot tier is enabled
# ---------------------------------------------------------------------------


def select_snapshot_runtime(
    *,
    cfg: object | None = None,
    require_available: bool = False,
    manager: SnapshotManager | None = None,
) -> "SnapshotSlotRuntime | None":
    """Build a :class:`SnapshotSlotRuntime`, or ``None`` if the FC tier is unavailable.

    When ``manager`` is not injected, it is built via ``SnapshotManager.from_env`` —
    so the **RAM-preload toggle** (``BLASTBOX_SNAPSHOT_MEM_TMPFS`` /
    ``BLASTBOX_SNAPSHOT_MEM_DIR``, default OFF) is honored — over a
    :class:`FcSnapshotLauncher` that waits for the base VM's READY (warm-idle) before
    the snapshot is taken. ``cfg`` defaults to ``FCConfig.from_env()``.

    ``require_available=True`` raises ``FCUnavailable`` when the FC prerequisites
    (binary + /dev/kvm + kernel + rootfs) are missing — use when the operator
    explicitly requested the snapshot tier.
    """
    from blastbox.host.runtime.fc_snapshot_launcher import FcSnapshotLauncher
    from blastbox.host.runtime.firecracker import (
        FCConfig,
        FCUnavailable,
        firecracker_available,
    )

    # Post-restore vsock settle window (see SnapshotSlotRuntime); tunable per host.
    # Guarded parse: a garbage value falls back to the default + a warning rather than
    # aborting pool construction (mirrors PoolConfig._float).
    _raw_settle = os.environ.get("BLASTBOX_SNAPSHOT_SETTLE_S", "").strip()
    try:
        settle_s = float(_raw_settle) if _raw_settle else 1.0
    except ValueError:
        _log.warning(
            "invalid BLASTBOX_SNAPSHOT_SETTLE_S=%r; using 1.0", _raw_settle
        )
        settle_s = 1.0

    # An injected manager (tests / custom wiring) bypasses environment probing — the
    # caller owns the launcher + snapshot lifecycle. cfg must then be supplied too.
    if manager is not None:
        if cfg is None:
            cfg = FCConfig.from_env()
        return SnapshotSlotRuntime(cfg, manager, settle_s=settle_s)

    if cfg is None:
        try:
            cfg = FCConfig.from_env()
        except (FCUnavailable, ValueError) as exc:
            if require_available:
                raise FCUnavailable(
                    f"snapshot runtime config failed: {exc}"
                ) from exc
            _log.debug("select_snapshot_runtime: config unavailable: %s", exc)
            return None

    if not firecracker_available(cfg):  # type: ignore[arg-type]
        if require_available:
            raise FCUnavailable(
                "snapshot warm tier required but prerequisites missing: check "
                "firecracker binary, /dev/kvm, BLASTBOX_FC_KERNEL, BLASTBOX_FC_ROOTFS."
            )
        _log.debug("select_snapshot_runtime: prerequisites not met")
        return None

    base_dir = Path(cfg.scratch_root)  # type: ignore[attr-defined]
    launcher = FcSnapshotLauncher(
        cfg,
        base_dir,
        ready_check_factory=_vsock_ready_check_factory,
    )
    manager = SnapshotManager.from_env(base_dir, launcher)
    return SnapshotSlotRuntime(cfg, manager, settle_s=settle_s)
