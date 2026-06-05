"""SlotRuntime backed by gVisor (runsc) C/R restore — the warm tier for runsc hosts.

spawn() builds ONE warm snapshot on its first call (SnapshotManager.build), then
restores it into a fresh per-slot container on every spawn(). Control is the
existing file-trigger (HostWarmControl over the per-slot ctrl/ bind mount); output
is read DIRECTLY from the per-slot out/ bind mount (no vsock, no ext4 — so
materialize_warm_output is a no-op). Mirrors the FC SnapshotSlotRuntime's
SlotRuntime + warm-path seam so the dispatcher's per-slot job flow is identical.
"""
from __future__ import annotations

import logging
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from blastbox.host.pool import Slot, SlotState

_log = logging.getLogger(__name__)


class GvisorSnapshotSlotRuntime:
    def __init__(self, manager, *, settle_s: float = 1.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._mgr = manager
        self._settle_s = settle_s
        self._clock = clock
        self._handles: dict[str, object] = {}
        self._restored_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def spawn(self) -> Slot:
        self._mgr.build()  # idempotent: snapshot built on first spawn only
        slot_id = str(uuid.uuid4())
        handle = self._mgr.restore(slot_id)
        wd = Path(handle.slot_workdir)  # type: ignore[attr-defined]
        with self._lock:
            self._handles[slot_id] = handle
            self._restored_at[slot_id] = self._clock()
        _log.info("gvisor_snapshot.spawn slot_id=%s workdir=%s", slot_id, wd)
        return Slot(
            slot_id=slot_id,
            control_dir=wd / "ctrl",
            input_dir=wd / "in",
            output_dir=wd / "out",
            state=SlotState.WARMING,
        )

    def is_ready(self, slot: Slot) -> bool:
        with self._lock:
            handle = self._handles.get(slot.slot_id)
            restored_at = self._restored_at.get(slot.slot_id)
        if handle is None:
            return False
        # Hold WARMING for a short post-restore settle window (mirrors the FC tier);
        # in a steady-state pool it overlaps background pre-warming, adding no per-job latency.
        if restored_at is not None and self._clock() - restored_at < self._settle_s:
            return False
        try:
            return Path(slot.control_dir).exists()
        except OSError:
            return False

    def is_alive(self, slot: Slot) -> bool:
        with self._lock:
            handle = self._handles.get(slot.slot_id)
        if handle is None:
            return False
        alive = getattr(handle, "alive", None)
        return alive() if callable(alive) else True

    def reap(self, slot: Slot) -> None:
        with self._lock:
            handle = self._handles.pop(slot.slot_id, None)
            self._restored_at.pop(slot.slot_id, None)
        if handle is not None:
            try:
                handle.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 — reap must never raise
                _log.warning("gvisor_snapshot.reap_kill_error slot_id=%s: %s", slot.slot_id, exc)
        slot_workdir = Path(slot.output_dir).parent
        if slot_workdir.exists():
            shutil.rmtree(slot_workdir, ignore_errors=True)

    # --- warm-path seam (file-trigger control; output already on the bind mount) ---
    def host_warm_control(self, slot: Slot) -> GvisorHostWarmControl:
        return GvisorHostWarmControl(slot.control_dir)

    def stage_warm_input(self, slot: Slot, staged_input_path: Path) -> Path:
        dst = Path(slot.input_dir) / Path(staged_input_path).name
        Path(slot.input_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged_input_path, dst)
        return dst

    def materialize_warm_output(self, slot: Slot) -> None:
        # Output is written directly into the bind-mounted out/ dir; nothing to read back.
        return None


class GvisorHostWarmControl:
    """Wraps HostWarmControl, rewriting the job spec's host paths to the fixed
    in-sandbox bind-mount destinations (/in, /out) before writing go.json — the
    worker validates + reads those in its own (sandbox) namespace.  The host still
    reads results from the host-side slot.output_dir (same bind mount)."""

    SANDBOX_IN = Path("/in")
    SANDBOX_OUT = Path("/out")

    def __init__(self, control_dir: Path) -> None:
        from blastbox.worker.warm import HostWarmControl
        self._inner = HostWarmControl(control_dir)

    def signal_go(self, spec: object) -> None:
        from blastbox.worker.warm import WarmJobSpec
        translated = WarmJobSpec(
            input_path=self.SANDBOX_IN / Path(spec.input_path).name,  # type: ignore[attr-defined]
            output_dir=self.SANDBOX_OUT,
            params=dict(spec.params),  # type: ignore[attr-defined]
        )
        self._inner.signal_go(translated)

    def wait_for_done(self, *, timeout_s: float) -> str:
        return self._inner.wait_for_done(timeout_s=timeout_s)


class GvisorUnavailable(RuntimeError):
    """The gVisor C/R warm tier was required but runsc/prereqs are missing."""


def select_gvisor_snapshot_runtime(*, cfg=None, require_available=False, manager=None,
                                   settle_s=None):
    """Build a GvisorSnapshotSlotRuntime, or None if runsc is unavailable (unless
    require_available, which raises GvisorUnavailable)."""
    import os

    def _settle():
        raw = (str(settle_s) if settle_s is not None else os.environ.get("BLASTBOX_SNAPSHOT_SETTLE_S", "")).strip()
        try:
            return float(raw) if raw else 1.0
        except ValueError:
            _log.warning("invalid BLASTBOX_SNAPSHOT_SETTLE_S=%r; using 1.0", raw)
            return 1.0

    if manager is not None:
        return GvisorSnapshotSlotRuntime(manager, settle_s=_settle())
    from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend
    from blastbox.host.runtime.fc_snapshot import SnapshotManager
    gcfg = cfg or _gvisor_config_from_env(os.environ)
    backend = GvisorSnapshotBackend(gcfg)
    if not backend.available():
        if require_available:
            raise GvisorUnavailable("gVisor C/R warm tier required but runsc not found; "
                                    "set BLASTBOX_GVISOR_RUNSC / install runsc")
        _log.debug("select_gvisor_snapshot_runtime: runsc unavailable")
        return None
    base_dir = Path(gcfg.root).parent / "gvisor-snapshot"
    mgr = SnapshotManager(base_dir, backend)
    return GvisorSnapshotSlotRuntime(mgr, settle_s=_settle())


def _gvisor_config_from_env(env):
    import json
    from blastbox.host.runtime.gvisor_snapshot import GvisorConfig
    root = env.get("BLASTBOX_GVISOR_ROOT", "/var/lib/blastbox/gvisor-root")
    rootfs = env.get("BLASTBOX_GVISOR_ROOTFS", "/var/lib/blastbox/gvisor-rootfs")
    raw_argv = env.get("BLASTBOX_GVISOR_WARM_ARGV", "").strip()
    warm_argv = json.loads(raw_argv) if raw_argv else ["worker", "warm"]
    return GvisorConfig(
        runsc_bin=env.get("BLASTBOX_GVISOR_RUNSC", "runsc"),
        root=Path(root),
        image_rootfs=Path(rootfs),
        network=env.get("BLASTBOX_GVISOR_NETWORK", "none"),
        warm_argv=warm_argv,
        ld_preload=env.get("BLASTBOX_GVISOR_LD_PRELOAD") or None,
        platform=env.get("BLASTBOX_GVISOR_PLATFORM") or None,
        cpu_features_annotation=env.get("BLASTBOX_GVISOR_CPUFEATURES") or None,
    )
