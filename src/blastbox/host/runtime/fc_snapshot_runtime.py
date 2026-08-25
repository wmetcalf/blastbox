"""SlotRuntime backed by warm-snapshot restore — the warm-UNO Firecracker tier.

``spawn()`` builds **one** warm snapshot on its first call (``SnapshotManager.build``,
driving an ``FcSnapshotBackend`` constructed via ``FcSnapshotBackend.from_env`` so the
RAM-preload toggle — ``BLASTBOX_SNAPSHOT_MEM_TMPFS`` / ``BLASTBOX_SNAPSHOT_MEM_DIR`` —
is honored), then
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

import contextlib
import logging
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from blastbox.worker.warm import AckCapability
from blastbox.host.pool import Slot, SlotState
from blastbox.host.runtime.fc_snapshot import SnapshotError, SnapshotManager
from blastbox.host.runtime.fc_snapshot_launcher import REL_OUTDISK, REL_VSOCK

_log = logging.getLogger(__name__)


def _vsock_ready_check_factory(vsock_path: Path,
                               ack_capable: "AckCapability | None" = None
                               ) -> Callable[[float], None]:
    """Build a blocking ``ready_check(timeout_s)`` for the base-VM build.

    The base VM warms its engine (e.g. ``unoserver``) then signals READY over vsock;
    we must wait for that *warm-idle* state before snapshotting, or the snapshot would
    capture a half-booted guest. ``vsock_path`` is ``<base>/vsock.sock``; the guest→host
    READY stream lands on ``<base>/vsock.sock_<port>``, which :class:`VsockReadySignal`
    binds from ``slot.output_dir.parent``. We hand it a faux Slot rooted at the base dir."""
    from blastbox.host.runtime.firecracker import VsockReadySignal

    base_dir = vsock_path.parent
    # THE ONLY PLACE the advertisement is observable in snapshot mode, and the comment that stood
    # here claimed the opposite. Restored guests never re-signal readiness -- is_ready() relies on
    # restore liveness alone -- so nothing after the base build ever sees READY again. And the
    # base VM IS the image the slots run: every slot is a restore of this very guest. Without
    # this, a base wedged from its first restore never populates the set and the repair is inert.
    signal = VsockReadySignal(ack_capable=ack_capable)
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
        A :class:`SnapshotManager` driving an ``FcSnapshotBackend`` (normally built
        via ``FcSnapshotBackend.from_env`` so the RAM-preload toggle is respected).
        Injected for testability.
    """

    def __init__(
        self,
        cfg: object,
        manager: SnapshotManager,
        *,
        settle_s: float = 1.0,
        ack_capable: "AckCapability | None" = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # Shared with every VsockHostWarmControl handed out (see host_warm_control) AND with the
        # base-build ready listener, which is the only place the advertisement is visible in
        # snapshot mode -- restored guests never signal readiness again.
        self._ack_capable = ack_capable if ack_capable is not None else AckCapability()
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

    def prepare(self) -> bool:
        """Non-blocking readiness gate the pool calls each tick before spawning: kicks the async
        snapshot build (once, with backoff) and reports whether the warm tier can spawn yet. Until
        the snapshot is built the pool spawns nothing (dispatch falls back to cold) instead of
        blocking its single background loop for up to ready_timeout_s inside build()."""
        ensure = getattr(self._manager, "ensure_build_started", None)
        if callable(ensure):
            ensure()
            return bool(self._manager.is_built())
        return True  # a manager without the async seam (test double) is always ready

    def spawn(self) -> Slot:
        """Build the warm snapshot once (idempotent), then restore it into a fresh
        per-slot microVM. Returns a WARMING Slot."""
        # NEVER build INLINE. prepare() reports readiness and the pool's generation fence tries
        # to avoid spawning against a base that was just invalidated -- but both are check-then-act
        # against a job thread that can invalidate in the window between the check and this call,
        # and build() then runs the FULL base boot plus readiness timeout on the pool's ONLY
        # maintenance thread, stalling promotion, health checks and deferred reaping behind it.
        # No lock discipline in the pool can close that window from the outside; the runtime has
        # to refuse. Kick the async build and report CAPACITY -- not a failure, so it never
        # touches the restore-failure streak -- and the next tick spawns once the artifact exists
        # (upstream, PR #82).
        # ATOMIC against invalidate(): asking "is it built?" and then building is a
        # check-then-act, and a job thread invalidating in that gap sends build() down the full
        # synchronous boot on the pool's only maintenance thread (upstream, PR #82).
        _acquire = getattr(self._manager, "acquire_built", None)
        if callable(_acquire):
            _acquire()
        else:
            self._manager.build()   # a manager without the seam (a test double)
        slot_id = str(uuid.uuid4())
        handle = self._manager.restore(slot_id)
        # The launcher restores in base_dir/slots/<id>; the vsock UDS lives there, so
        # its parent IS the per-slot workdir (vsock.sock + outdisk.ext4 + fc-api.sock).
        # vsock_uds is a concrete-FC-handle accessor not on the generic RestoreHandle
        # seam (kill-only) — the FC backend's handle always provides it.
        # EVERYTHING between a successful restore and publishing the handle must clean up after
        # itself. restore() has already pinned this generation, but no Slot exists yet, so the
        # pool can never reap it and nothing would ever call release(slot_id): a failure here
        # (reading vsock_uds, or mkdir hitting ENOSPC) would strand the pin AND leak a running
        # microVM, permanently, until the process restarts.
        try:
            slot_workdir = Path(handle.vsock_uds).parent  # type: ignore[attr-defined]
            output_dir = slot_workdir / "out"
            input_dir = slot_workdir / "in"
            control_dir = slot_workdir / "ctrl"
            for d in (output_dir, input_dir, control_dir):
                d.mkdir(parents=True, exist_ok=True)
        except BaseException:
            vm_gone = True
            try:
                handle.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001
                # Identical rule to reap(): a kill() that raised leaves the microVM possibly
                # ALIVE and still mapping this generation. Releasing the pin anyway lets a later
                # invalidation unlink its backing files underneath. This cleanup path was added
                # in the same commit that guarded reap() and repeated the very bug it fixed.
                vm_gone = False
                _log.warning(
                    "snapshot.spawn_cleanup_kill_error slot_id=%s: %s", slot_id, exc
                )
            release = getattr(self._manager, "release", None)
            if callable(release) and vm_gone:
                with contextlib.suppress(Exception):
                    release(slot_id)
            raise

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
            # The generation this slot was SPAWNED from; see Slot.ack_generation.
            ack_generation=self._ack_capable.generation,
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

    def invalidate_base(self) -> None:
        """Drop the persisted warm snapshot so the next spawn rebuilds it.

        Called by the pool after sustained pool-wide dirty releases: at that point the shared
        base -- not the individual slots -- is the likely culprit, and slots restored from it are
        born wedged. ``reap()`` deliberately preserves ``warm.snapshot``/``warm.mem``, so without
        this the only cure is a dispatcher restart.
        """
        # A NEW BASE MAY BE A DIFFERENT IMAGE. The capability set outlived the generation
        # that taught it, so a rootfs rolled back to an older worker kept the previous "yes" --
        # and controls then read a missing ack as proof of no start, letting three
        # document-induced hangs convict a healthy older base instead of staying UNKNOWN, which
        # is exactly what the mixed-version contract promises. Re-learned at the next base build.
        self._ack_capable.reset()
        drop = getattr(self._manager, "invalidate", None)
        if not callable(drop):
            _log.warning("snapshot.invalidate_unsupported manager=%s", type(self._manager).__name__)
            return
        discarded = drop()
        _log.warning("snapshot.base_invalidated had_artifact=%s -- next spawn rebuilds the base",
                     bool(discarded))

    def reap(self, slot: Slot) -> None:
        """Kill the restored microVM (if alive) and remove its per-slot workdir.

        Safe on already-dead / already-reaped slots. The shared snapshot artifact
        (``warm.snapshot`` + ``warm.mem``) lives OUTSIDE ``slots/`` and is preserved."""
        with self._lock:
            handle = self._handles.pop(slot.slot_id, None)
            self._restored_at.pop(slot.slot_id, None)
        vm_gone = True
        if handle is not None:
            try:
                handle.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 — reap must never raise
                # The microVM may still be RUNNING and still mapping this generation's memory
                # file. Releasing the pin anyway can unlink it under a live VM.
                vm_gone = False
                _log.warning(
                    "snapshot.reap_kill_error slot_id=%s: %s", slot.slot_id, exc
                )
        # slot.output_dir is <slot_workdir>/out — its parent is the per-slot workdir.
        slot_workdir = Path(slot.output_dir).parent
        if slot_workdir.exists():
            shutil.rmtree(slot_workdir, ignore_errors=True)
            _log.debug("snapshot.reap_cleaned slot_id=%s", slot.slot_id)
        # Drop this slot's pin on its snapshot generation; if it was the last user of a
        # SUPERSEDED generation, its files are unlinked now. Without this every rebuild leaks a
        # memory file the size of guest RAM until the tmpfs fills.
        # ...but ONLY once the VM is provably gone. The whole guarantee of generation stamping
        # is that a file is never removed while something still maps it; a kill() that raised
        # leaves that unproven, so the pin is deliberately retained. Retaining a generation costs
        # disk until the process restarts; unlinking one under a live VM corrupts it.
        release = getattr(self._manager, "release", None)
        if callable(release):
            if vm_gone:
                release(slot.slot_id)
            else:
                _log.warning(
                    "snapshot.generation_retained slot_id=%s: could not confirm the microVM is "
                    "gone, so its snapshot generation is kept rather than risk unlinking a file "
                    "a live VM still maps", slot.slot_id,
                )
        if not vm_gone:
            # PROPAGATE, and put the handle back. Retaining the pin stops the backing file being
            # deleted under a VM that may still be running -- but returning NORMALLY told the pool
            # the disposal SUCCEEDED, so _reap_and_count removed the slot and allowed a
            # replacement. That left a live microVM and its now-permanent pin outside pool
            # accounting entirely: nothing tracks it, nothing ever retries the kill, and its
            # generation is held until the process restarts. Raising makes the pool quarantine the
            # slot instead (kept tracked, DRAINING, never reused), which is exactly what an
            # unconfirmed teardown means. The handle goes back so a later reap can retry the kill
            # (upstream, PR #82).
            with self._lock:
                self._handles.setdefault(slot.slot_id, handle)
            raise SnapshotError(
                f"could not confirm the microVM for slot {slot.slot_id} is gone; "
                f"quarantining the slot rather than replacing it"
            )

    # ------------------------------------------------------------------
    # Warm-path seam (mirrors FirecrackerSlotRuntime so the dispatcher's per-slot
    # job flow is identical: input over vsock, output via the per-slot ext4 disk)
    # ------------------------------------------------------------------

    def host_warm_control(self, slot: Slot) -> object:
        """The vsock warm control for this slot — input/status over vsock.

        ``ack_capable`` is shared across every control this runtime hands out, exactly as in
        FirecrackerSlotRuntime: all slots restore from ONE warm base, so whether the guest image
        speaks the start-ack is a property of the image, not of a job. Built per-control it would
        be learned by a disposable object and forgotten, leaving guest_started permanently None --
        and this is the runtime BLASTBOX_POOL_WARM_SNAPSHOT=1 selects, i.e. the one the wedge was
        actually observed on, so the repair would have been inert precisely where it is needed.
        """
        from blastbox.host.runtime.firecracker import VsockHostWarmControl

        vsock_uds = Path(slot.output_dir).parent / REL_VSOCK
        return VsockHostWarmControl(vsock_uds, ack_capable=self._ack_capable,
                                    ack_generation=getattr(slot, "ack_generation", None))

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

    When ``manager`` is not injected, it drives an ``FcSnapshotBackend`` built via
    ``FcSnapshotBackend.from_env`` — so the **RAM-preload toggle**
    (``BLASTBOX_SNAPSHOT_MEM_TMPFS`` / ``BLASTBOX_SNAPSHOT_MEM_DIR``, default OFF) is
    honored — over a :class:`FcSnapshotLauncher` that waits for the base VM's READY
    (warm-idle) before the snapshot is taken. ``cfg`` defaults to ``FCConfig.from_env()``.

    ``require_available=True`` raises ``FCUnavailable`` when the FC prerequisites
    (binary + /dev/kvm + kernel + rootfs) are missing — use when the operator
    explicitly requested the snapshot tier.
    """
    from blastbox.host.runtime.fc_snapshot_backend import (
        FcSnapshotBackend,
        resolve_mem_dir,
    )
    from blastbox.host.runtime.fc_snapshot_launcher import FcSnapshotLauncher
    from blastbox.host.runtime.firecracker import (
        _MIN_SNAPSHOT_KERNEL,
        FCConfig,
        FCUnavailable,
        firecracker_available,
        guest_kernel_version,
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

    # VMGenID guest-kernel gate (snapshot tier ONLY — cold FC boots fresh per job
    # and never clones CRNG state). Restoring a snapshot clones the base VM's kernel
    # CRNG; only a >= 5.18 guest (VMGenID) reseeds it automatically on restore, so an
    # older guest would let restored clones repeat random output. Refuse the snapshot
    # tier on a detectably-too-old kernel (falls back to cold FC). An unparseable
    # version is left to proceed — we can't verify, and must not break on a parse miss.
    kver = guest_kernel_version(cfg.fc_kernel)  # type: ignore[attr-defined]
    if kver is not None and kver < _MIN_SNAPSHOT_KERNEL:
        need = ".".join(map(str, _MIN_SNAPSHOT_KERNEL))
        have = ".".join(map(str, kver))
        msg = (
            f"snapshot warm tier needs a VMGenID-capable guest kernel >= {need} so "
            f"the CRNG reseeds on restore; {cfg.fc_kernel} is {have}."  # type: ignore[attr-defined]
        )
        if require_available:
            raise FCUnavailable(msg)
        _log.warning("%s Snapshot tier unavailable; falling back to cold FC.", msg)
        return None

    base_dir = Path(cfg.scratch_root)  # type: ignore[attr-defined]
    # Resolve the RAM-preload mem dir once, hand it to BOTH the launcher (whose base
    # handle writes warm.mem there at checkpoint) and the backend (whose restore loads
    # mem from there) so build/restore agree on the mem-file location.
    mem_dir = resolve_mem_dir() or base_dir
    # Created HERE so the base-build listener and the runtime that serves restores share one set:
    # the base advertises at build time, every restored slot then reads the answer.
    ack_capable = AckCapability()
    launcher = FcSnapshotLauncher(
        cfg,
        base_dir,
        mem_dir=mem_dir,
        ready_check_factory=lambda p: _vsock_ready_check_factory(p, ack_capable=ack_capable),
    )
    backend = FcSnapshotBackend.from_env(base_dir, launcher, mem_dir=mem_dir)
    manager = SnapshotManager(base_dir, backend)
    return SnapshotSlotRuntime(cfg, manager, settle_s=settle_s, ack_capable=ack_capable)
