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
import os
import shutil
import tarfile
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from blastbox.worker.warm import AckCapability
from blastbox.host.pool import Slot, SlotState
from blastbox.host.runtime.fc_snapshot import SnapshotError

_log = logging.getLogger(__name__)

# The warm worker entrypoint baked into the gVisor warm image (deploy/gvisor/Dockerfile.shim
# COPYs run_warm.py + engines.py to /opt/blastbox/). There is intentionally NO `worker warm`
# CLI — the file-trigger warm loop IS run_warm.py (the gVisor analog of FC's run_guest.py), so
# the default must invoke it directly. A bare `["worker","warm"]` would exec a nonexistent
# `worker` binary and the restore would never become ready.
_DEFAULT_WARM_ARGV = ["python3", "/opt/blastbox/run_warm.py"]


class GvisorSnapshotSlotRuntime:
    def __init__(self, manager, *, settle_s: float = 1.0,
                 clock: Callable[[], float] = time.monotonic,
                 ack_capable: "AckCapability | None" = None) -> None:
        # Shared with every GvisorHostWarmControl handed out (see host_warm_control) AND with the
        # base build, which is the only place the advertisement is ever visible on this tier.
        self._ack_capable = ack_capable if ack_capable is not None else AckCapability()
        self._mgr = manager
        self._settle_s = settle_s
        self._clock = clock
        self._handles: dict[str, object] = {}
        self._restored_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def prepare(self) -> bool:
        """Non-blocking readiness gate the pool calls each tick before spawning: kicks the async
        snapshot build (once, with backoff) and reports whether the warm tier can spawn yet. Until
        the snapshot is built the pool spawns nothing (dispatch falls back to cold) instead of
        blocking its single background loop for up to ready_timeout_s inside build()."""
        ensure = getattr(self._mgr, "ensure_build_started", None)
        if callable(ensure):
            ensure()
            return bool(self._mgr.is_built())
        return True  # a manager without the async seam (test double) is always ready

    def spawn(self) -> Slot:
        # NEVER build INLINE -- see the FC sibling. A job thread can invalidate between the pool's
        # generation check and this call, and a synchronous build then blocks the pool's only
        # maintenance thread for a full boot plus readiness timeout (upstream, PR #82).
        # ATOMIC against invalidate(): asking "is it built?" and then building is a
        # check-then-act, and a job thread invalidating in that gap sends build() down the full
        # synchronous boot on the pool's only maintenance thread (upstream, PR #82).
        _acquire = getattr(self._mgr, "acquire_built", None)
        if callable(_acquire):
            _acquire()
        else:
            self._mgr.build()   # a manager without the seam (a test double)
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
            # The generation this slot was SPAWNED from; see Slot.ack_generation.
            ack_generation=self._ack_capable.generation,
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
            if not Path(slot.control_dir).exists():
                return False
        except OSError:
            return False
        # control_dir is created on the HOST before `runsc restore`, so its mere existence
        # doesn't prove the sandbox came up — a restore that immediately exited would still
        # pass. Gate on liveness too (mirrors the FC tier) so dead slots aren't promoted to IDLE.
        alive = getattr(handle, "alive", None)
        return alive() if callable(alive) else True

    def is_alive(self, slot: Slot) -> bool:
        with self._lock:
            handle = self._handles.get(slot.slot_id)
        if handle is None:
            return False
        alive = getattr(handle, "alive", None)
        return alive() if callable(alive) else True

    def invalidate_base(self) -> None:
        """Drop the persisted warm snapshot so the next spawn rebuilds it.

        The FC snapshot runtime has had this since the wedge work landed; this one did not, so the
        pool's lookup always failed here and sustained failures merely logged
        pool.base_rebuild_unavailable while every replacement kept restoring the poisoned snapshot
        until a dispatcher restart (upstream, PR #82). Same SnapshotManager underneath."""
        # A NEW BUNDLE MAY BE A DIFFERENT IMAGE. Same reset as the FC snapshot runtime: the
        # set outlives the generation that taught it, so a bundle rolled back to an older worker
        # kept the previous "yes" and a missing start marker was then read as proof of no start --
        # letting three document-induced hangs convict a healthy mixed-version base.
        self._ack_capable.reset()
        drop = getattr(self._mgr, "invalidate", None)
        if callable(drop):
            drop()

    def reap(self, slot: Slot) -> None:
        with self._lock:
            handle = self._handles.pop(slot.slot_id, None)
            self._restored_at.pop(slot.slot_id, None)
        sandbox_gone = True
        if handle is not None:
            try:
                handle.kill()  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 — reap must never raise
                # The sandbox may still be RUNNING and still reading this checkpoint directory.
                sandbox_gone = False
                _log.warning("gvisor_snapshot.reap_kill_error slot_id=%s: %s", slot.slot_id, exc)
        slot_workdir = Path(slot.output_dir).parent
        if slot_workdir.exists():
            shutil.rmtree(slot_workdir, ignore_errors=True)

        # Mirror the FC runtime: drop this slot's pin so a superseded generation can be
        # reclaimed once its last user is gone -- but ONLY once the sandbox is provably gone.
        # Found by sweeping every generation-release site rather than by a report: the FC reap,
        # the FC spawn-cleanup and both FC restore-cleanup paths all carry this guard, and this
        # one did not. Retaining a checkpoint costs disk; removing one a live sandbox is still
        # restoring from breaks it (PR #82).
        release = getattr(self._mgr, "release", None)
        if callable(release):
            if sandbox_gone:
                release(slot.slot_id)
            else:
                _log.warning(
                    "gvisor_snapshot.generation_retained slot_id=%s: could not confirm the "
                    "sandbox is gone, so its checkpoint generation is kept", slot.slot_id,
                )
        if not sandbox_gone:
            # PROPAGATE, and put the handle back -- the same hole as the FC reap, in its twin.
            # Retaining the pin protects the checkpoint files, but returning NORMALLY told the
            # pool the disposal succeeded, so it removed the slot and allowed a replacement while
            # a live sandbox and its permanent pin sat outside pool accounting: untracked, never
            # retried, holding its generation until the process restarts. Raising quarantines the
            # slot (kept tracked, DRAINING, never reused), which is what an unconfirmed teardown
            # actually means (upstream, PR #82).
            with self._lock:
                self._handles.setdefault(slot.slot_id, handle)
            raise SnapshotError(
                f"could not confirm the gVisor sandbox for slot {slot.slot_id} is gone; "
                f"quarantining the slot rather than replacing it"
            )

    # --- warm-path seam (file-trigger control; output already on the bind mount) ---

    def host_warm_control(self, slot: Slot) -> GvisorHostWarmControl:
        # Shared across slots: one warm base image, so start-marker capability is a property of
        # the image, not of a job. Per-control it would be learned and immediately forgotten.
        return GvisorHostWarmControl(slot.control_dir, ack_capable=self._ack_capable,
                                     ack_generation=getattr(slot, "ack_generation", None))

    def stage_warm_input(self, slot: Slot, staged_input_path: Path) -> Path:
        dst = Path(slot.input_dir) / Path(staged_input_path).name
        Path(slot.input_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged_input_path, dst)
        return dst

    def materialize_warm_output(self, slot: Slot) -> None:
        # A C/R-restored container propagates FILES written at the /out root to the host bind
        # source, but NOT directories it creates post-restore (the restored process's gofer/VFS view
        # is stale) — so a TREE-output engine (e.g. RedTusk's rmeta/) loses everything below /out
        # from the host's view, while a FLAT-output engine (clippyshot's page-NNN.png at the root)
        # is unaffected. Recover the tree: have the still-alive container pack /out into a ROOT-level
        # archive (which DOES propagate), then extract it here over the host slot out/. Fail-OPEN:
        # any error leaves whatever the bind mount already carried, so flat-output engines (and the
        # case where there's nothing nested to recover) are never worse off than the old no-op.
        from blastbox.host.runtime.gvisor_snapshot import WARM_OUTPUT_ARCHIVE

        with self._lock:
            handle = self._handles.get(slot.slot_id)
        archiver = getattr(handle, "archive_output", None)
        if not callable(archiver):
            return
        out = Path(slot.output_dir)
        arc = out / WARM_OUTPUT_ARCHIVE
        try:
            if not archiver():
                _log.warning("gvisor materialize: archive_output exec failed slot=%s", slot.slot_id)
                return
            if not arc.is_file():
                # The container's root-level archive didn't reach the host bind source — nothing to
                # recover beyond what already propagated (e.g. flat output).
                return
            with tarfile.open(arc, "r:") as tf:
                # 'data' filter (3.12+) blocks path traversal, absolute paths, and special files.
                tf.extractall(out, filter="data")
            _log.info(
                "gvisor materialize: recovered warm output tree slot=%s (%d bytes)",
                slot.slot_id, arc.stat().st_size,
            )
        except Exception as exc:  # noqa: BLE001 — materialize must never raise
            _log.warning(
                "gvisor materialize_warm_output recovery failed slot=%s: %s", slot.slot_id, exc
            )
        finally:
            try:
                arc.unlink(missing_ok=True)
            except OSError:
                pass


class GvisorHostWarmControl:
    """Wraps HostWarmControl, rewriting the job spec's host paths to the fixed
    in-sandbox bind-mount destinations (/in, /out) before writing go.json — the
    worker validates + reads those in its own (sandbox) namespace.  The host still
    reads results from the host-side slot.output_dir (same bind mount)."""

    SANDBOX_IN = Path("/in")
    SANDBOX_OUT = Path("/out")

    def __init__(self, control_dir: Path, *, ack_capable: "AckCapability | None" = None,
                 ack_generation: "int | None" = None) -> None:
        from blastbox.worker.warm import HostWarmControl
        self._inner = HostWarmControl(control_dir, ack_capable=ack_capable,
                                      ack_generation=ack_generation)

    @property
    def guest_started(self) -> "bool | None":
        """Forwarded from the wrapped control: the dispatcher reads it off whatever object
        host_warm_control returned, and a wrapper that swallows it leaves the whole start signal
        invisible for this tier."""
        return self._inner.guest_started

    def signal_go(self, spec: object, *, deadline: float | None = None) -> None:
        from blastbox.worker.warm import WarmJobSpec
        translated = WarmJobSpec(
            input_path=self.SANDBOX_IN / Path(spec.input_path).name,  # type: ignore[attr-defined]
            output_dir=self.SANDBOX_OUT,
            params=dict(spec.params or {}),  # type: ignore[attr-defined]
        )
        # File-trigger (go.json) — the write is instant, so the deadline is a no-op here; the
        # warm interaction is bounded by wait_for_done. Accepted for a uniform signal_go signature.
        self._inner.signal_go(translated, deadline=deadline)

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
    # Created before both so the BASE BUILD and the runtime serving restores share it: the base
    # advertises the start-marker protocol in `ready`, and that is the only moment it is visible
    # (a restore gets a fresh ctrl/, and the checkpointed worker resumes past signal_ready).
    ack_capable = AckCapability()
    backend = GvisorSnapshotBackend(gcfg, ack_capable=ack_capable)
    if not backend.available():
        if require_available:
            raise GvisorUnavailable("gVisor C/R warm tier required but runsc not found; "
                                    "set BLASTBOX_GVISOR_RUNSC / install runsc")
        _log.debug("select_gvisor_snapshot_runtime: runsc unavailable")
        return None
    # RAM-preload (COW-image-to-RAM): the runsc checkpoint image holds the guest's memory pages
    # (~guest RAM with soffice live) and dominates restore cost. Holding the checkpoint dir on
    # tmpfs (/dev/shm) pins it in RAM, so every per-slot restore pages the COW-shared base in from
    # RAM, not disk — the gVisor twin of the FC mem-dir toggle. Same generic engine toggle
    # (BLASTBOX_SNAPSHOT_MEM_TMPFS / BLASTBOX_SNAPSHOT_MEM_DIR); opt-in, default disk.
    from blastbox.host.runtime.fc_snapshot_backend import resolve_mem_dir

    snapshot_parent = resolve_mem_dir() or Path(gcfg.root).parent
    base_dir = _secure_snapshot_base(snapshot_parent / "gvisor-snapshot")
    mgr = SnapshotManager(base_dir, backend)
    return GvisorSnapshotSlotRuntime(mgr, settle_s=_settle(), ack_capable=ack_capable)


def _secure_snapshot_base(base_dir: Path) -> Path:
    """Create the warm-snapshot base dir 0o700 and owned by us, refusing to ADOPT a pre-existing
    dir owned by another uid OR a symlink (L3).

    The base holds the runsc checkpoint memory image that is restored into EVERY per-slot
    container, so under a world-writable parent — notably ``/dev/shm`` when
    ``BLASTBOX_SNAPSHOT_MEM_TMPFS=1`` pins it in RAM — a co-tenant could otherwise pre-create the
    predictable path and read or replace the image. 0o700 makes the whole subtree (the checkpoint
    AND the per-slot ``slots/`` dirs) untraversable by anyone else; refusing a non-owned/symlinked
    base fails closed rather than silently adopting an attacker's.

    The hardening is done over a single ``O_NOFOLLOW | O_DIRECTORY`` fd: a co-tenant must not be
    able to pre-create the path as a SYMLINK and redirect our ownership check / chmod to an
    arbitrary target (symlink traversal → arbitrary permission change), and the ownership check +
    chmod must operate on the SAME object (no exists()->stat()->chmod() TOCTOU). The mkdir uses
    mode 0o700 directly so a freshly-created base is never briefly group/other-accessible."""
    base_dir = Path(base_dir)
    euid = os.geteuid()
    base_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(base_dir, mode=0o700)
    except FileExistsError:
        pass  # already exists — validated (not adopted blindly) via the O_NOFOLLOW open below
    # O_NOFOLLOW refuses a symlink (ELOOP), O_DIRECTORY refuses a non-dir (ENOTDIR); both close the
    # symlink-swap. fstat + fchmod operate on the opened fd, so ownership is checked and 0o700 set
    # on the exact same object — no path is re-resolved after the open.
    try:
        fd = os.open(base_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PermissionError(
            f"warm-snapshot base {base_dir} is not a real directory we can safely open "
            f"(a symlink or non-dir may have been swapped in): {exc}"
        ) from exc
    try:
        owner = os.fstat(fd).st_uid
        if owner != euid:
            raise PermissionError(
                f"warm-snapshot base {base_dir} is owned by uid {owner}, not {euid}; refusing to "
                "adopt it — a co-tenant under a world-writable parent may have pre-created it. "
                "Point BLASTBOX_SNAPSHOT_MEM_DIR at a dir you own (0o700), or disable the tmpfs "
                "toggle."
            )
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return base_dir


def _int_env(env, key: str, default: int) -> int:
    raw = str(env.get(key, "")).strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        _log.warning("invalid %s=%r; using %d", key, raw, default)
        return default


def _gvisor_config_from_env(env):
    import json
    from blastbox.host.runtime.gvisor_snapshot import GvisorConfig
    root = env.get("BLASTBOX_GVISOR_ROOT", "/var/lib/blastbox/gvisor-root")
    rootfs = env.get("BLASTBOX_GVISOR_ROOTFS", "/var/lib/blastbox/gvisor-rootfs")
    raw_argv = env.get("BLASTBOX_GVISOR_WARM_ARGV", "").strip()
    try:
        warm_argv = json.loads(raw_argv) if raw_argv else list(_DEFAULT_WARM_ARGV)
    except json.JSONDecodeError:
        # A malformed override must not crash host startup — fall back to the default argv.
        _log.warning(
            "invalid BLASTBOX_GVISOR_WARM_ARGV JSON %r; using default %r",
            raw_argv,
            _DEFAULT_WARM_ARGV,
        )
        warm_argv = list(_DEFAULT_WARM_ARGV)
    # Type-validate the SHAPE, not just JSON well-formedness: a bare string ('"soffice"')
    # or object is valid JSON but `list(...)` in the OCI spec would char-split it / take dict
    # keys into a malformed argv. Require a non-empty list of strings or fall back loudly.
    if not (isinstance(warm_argv, list) and warm_argv and all(isinstance(a, str) for a in warm_argv)):
        _log.warning(
            "BLASTBOX_GVISOR_WARM_ARGV must be a non-empty JSON array of strings; got %r; "
            "using default %r",
            raw_argv,
            _DEFAULT_WARM_ARGV,
        )
        warm_argv = list(_DEFAULT_WARM_ARGV)
    # Extra env injected into the warm worker's OCI process env (e.g.
    # ["JAVA_TOOL_OPTIONS=-XX:ActiveProcessorCount=2"] for the redtusk JVM tier, or
    # ["CLIPPYSHOT_SANDBOX=container", ...] for clippyshot). A JSON array of "KEY=VALUE"
    # strings; same fail-loud-to-default shape validation as warm_argv (a malformed value
    # must not crash host startup, and a non-list/non-string entry would corrupt the OCI env).
    raw_extra = env.get("BLASTBOX_GVISOR_EXTRA_ENV", "").strip()
    extra_env: list[str] = []
    if raw_extra:
        try:
            parsed = json.loads(raw_extra)
        except json.JSONDecodeError:
            _log.warning("invalid BLASTBOX_GVISOR_EXTRA_ENV JSON %r; ignoring", raw_extra)
            parsed = None
        if isinstance(parsed, list) and all(isinstance(e, str) and "=" in e for e in parsed):
            extra_env = parsed
        elif parsed is not None:
            _log.warning(
                "BLASTBOX_GVISOR_EXTRA_ENV must be a JSON array of 'KEY=VALUE' strings; got %r; ignoring",
                raw_extra,
            )
    return GvisorConfig(
        runsc_bin=env.get("BLASTBOX_GVISOR_RUNSC", "runsc"),
        root=Path(root),
        image_rootfs=Path(rootfs),
        network=env.get("BLASTBOX_GVISOR_NETWORK", "none"),
        warm_argv=warm_argv,
        extra_env=extra_env,
        ld_preload=env.get("BLASTBOX_GVISOR_LD_PRELOAD") or None,
        platform=env.get("BLASTBOX_GVISOR_PLATFORM") or None,
        cpu_features_annotation=env.get("BLASTBOX_GVISOR_CPUFEATURES") or None,
        # Generous defense-in-depth bounds for the whole warm worker tree (see GvisorConfig).
        rlimit_nproc=_int_env(env, "BLASTBOX_GVISOR_NPROC", 4096),
        rlimit_nofile=_int_env(env, "BLASTBOX_GVISOR_NOFILE", 65536),
    )
