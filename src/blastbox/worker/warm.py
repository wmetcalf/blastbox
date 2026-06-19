"""Worker service lifecycle — warm protocol.

A warm worker pre-pays startup cost (``engine.warmup()``) **before** any
untrusted input exists, signals READY to the host, waits for exactly one job,
processes it through the identical harness/trust path as the cold-path worker,
signals DONE, and exits.

Warm ≠ reuse: one untrusted document per disposable slot.

Public API
----------
- ``WarmJobSpec``     — input/output paths + params for the one job.
- ``WarmControl``     — Protocol: ``signal_ready`` / ``wait_for_go`` / ``signal_done``.
- ``WarmTimeout``     — raised by ``wait_for_go`` when no job arrives in time.
- ``FileWarmControl`` — container-friendly file-based handshake implementation.
- ``HostWarmControl`` — host-side counterpart: ``signal_go`` / ``wait_for_done``.
- ``serve_warm``      — the top-level warm lifecycle function.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from blastbox.errors import WarmTimeout
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation

if TYPE_CHECKING:
    from blastbox.worker.engine import Engine

logger = logging.getLogger(__name__)

# Polling interval for FileWarmControl.wait_for_go
_POLL_INTERVAL_S: float = 0.05

# A jump in CLOCK_MONOTONIC larger than this between two poll ticks cannot be a
# normal sleep — it means the sandbox was checkpoint/restored (gVisor C/R, FC
# snapshot), which advances the monotonic clock by the time spent checkpointed.
# When detected, the idle countdown is restarted so a restore from a snapshot
# older than the idle timeout does not instantly abandon the job it was handed.
_RESTORE_JUMP_S: float = 5.0


class _RestoreAwareDeadline:
    """An idle-timeout deadline that survives a checkpoint/restore clock-jump.

    A warm worker is checkpointed BLOCKED waiting for its single job. gVisor C/R
    (and, defensively, FC snapshot restore) can advance CLOCK_MONOTONIC by the
    wall-time spent checkpointed; a deadline computed *before* the checkpoint is
    then already-expired the instant the worker resumes and would abandon the
    job the host just handed it (empty output → "metadata.json not found").
    :meth:`expired` watches for a monotonic leap far larger than the caller's
    poll cadence — which can only be a restore, never a normal sleep/accept tick
    — and restarts the countdown, so a restored worker behaves like a freshly
    ready one.

    Both the deadline and the leap reference are seeded from a SINGLE
    ``time.monotonic()`` sample, so a checkpoint can never land *between* two
    samples and desync them (which would hide the very jump being watched for).
    """

    __slots__ = ("_timeout", "_deadline", "_last")

    def __init__(self, timeout_s: float) -> None:
        self._timeout = timeout_s
        self._restart(time.monotonic())

    def _restart(self, now: float) -> None:
        self._deadline = now + self._timeout
        self._last = now

    def expired(self) -> bool:
        """Whether the idle timeout has genuinely elapsed; call once per tick.

        A monotonic jump greater than ``_RESTORE_JUMP_S`` since the previous call
        is treated as a restore: the countdown restarts and this returns ``False``
        (the worker is effectively freshly ready).
        """
        now = time.monotonic()
        if now - self._last > _RESTORE_JUMP_S:
            self._restart(now)
            return False
        self._last = now
        return now >= self._deadline


# ---------------------------------------------------------------------------
# WarmJobSpec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WarmJobSpec:
    """Specification for the single job a warm worker will process."""

    input_path: Path
    """Absolute path to the (staged) input file."""

    output_dir: Path
    """Absolute path to the output directory for artifacts + metadata.json."""

    params: dict[str, str] = field(default_factory=dict)
    """Optional engine-specific string parameters forwarded from the host."""


# ---------------------------------------------------------------------------
# WarmControl protocol
# ---------------------------------------------------------------------------


class WarmControl(Protocol):
    """Host↔warm-worker handshake abstraction.

    Implementations must be injectable (so ``serve_warm`` is unit-testable
    with no real container / filesystem).
    """

    def signal_ready(self) -> None:
        """Notify the host that this slot is warm and ready to accept one job."""
        ...

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        """Block until the host delivers a job spec, then return it.

        Raises:
            WarmTimeout: if no job arrives within ``timeout_s`` seconds.
        """
        ...

    def signal_done(self, *, status: str) -> None:
        """Notify the host that this slot has finished (or failed).

        ``status`` is a short ASCII string, e.g. ``"ok"``, ``"idle_timeout"``,
        ``"warmup_error"``.  The host uses it to decide whether to reap or
        replace the slot.
        """
        ...


# ---------------------------------------------------------------------------
# FileWarmControl
# ---------------------------------------------------------------------------


class FileWarmControl:
    """Container-friendly file-based implementation of ``WarmControl``.

    Handshake files under ``control_dir``:

    * ``ready``    — written (atomically) by the worker after warmup.
    * ``go.json``  — written by the host when a job is ready; contains
                     ``{"input_path": "...", "output_dir": "...", "params": {...}}``.
    * ``done``     — written (atomically) by the worker; contains the status
                     string as plain text.

    All writes use a temp-file + ``os.replace`` (atomic rename) so the host
    never observes a half-written signal file.
    """

    def __init__(self, control_dir: Path) -> None:
        self._dir = control_dir

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _atomic_write(self, name: str, content: str) -> None:
        """Write *content* to ``control_dir/<name>`` atomically via temp+rename."""
        target = self._dir / name
        tmp = self._dir / f".{name}.tmp"
        try:
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, target)
        except Exception:
            # Best-effort cleanup of the temp file on failure
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # WarmControl implementation
    # ------------------------------------------------------------------

    def signal_ready(self) -> None:
        """Atomically create ``control_dir/ready``."""
        self._atomic_write("ready", "ready\n")

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        """Poll for ``control_dir/go.json`` until present or ``timeout_s`` elapsed.

        Parses ``go.json`` (``input_path``, ``output_dir``, ``params``), validates
        that paths are absolute and exist, then returns a ``WarmJobSpec``.

        Raises:
            WarmTimeout: if ``go.json`` does not appear before the deadline.
        """
        go_path = self._dir / "go.json"
        # This worker is checkpointed BLOCKED in this loop (at "ready"); a restore
        # from a snapshot older than `timeout_s` resumes with the monotonic clock
        # already advanced past the original deadline, which would instantly raise
        # WarmTimeout and abandon the job the host just handed us (empty output ->
        # "metadata.json not found"). _RestoreAwareDeadline restarts the countdown
        # when it detects the restore jump, so the worker is "freshly ready".
        deadline = _RestoreAwareDeadline(timeout_s)

        while True:
            if go_path.exists():
                try:
                    raw = go_path.read_text(encoding="utf-8")
                    data = json.loads(raw)
                except (OSError, json.JSONDecodeError) as exc:
                    raise WarmTimeout(f"go.json unreadable: {exc}") from exc

                input_path = Path(data["input_path"])
                output_dir = Path(data["output_dir"])

                # Light sanity checks — the host controls these paths
                if not input_path.is_absolute():
                    raise ValueError(f"input_path is not absolute: {input_path}")
                if not output_dir.is_absolute():
                    raise ValueError(f"output_dir is not absolute: {output_dir}")
                if not input_path.exists():
                    raise ValueError(f"input_path does not exist: {input_path}")
                if not output_dir.exists():
                    raise ValueError(f"output_dir does not exist: {output_dir}")

                params: dict[str, str] = data.get("params", {})
                return WarmJobSpec(
                    input_path=input_path,
                    output_dir=output_dir,
                    params=params,
                )

            if deadline.expired():
                raise WarmTimeout(
                    f"no job arrived within {timeout_s}s idle timeout"
                )

            time.sleep(_POLL_INTERVAL_S)

    def signal_done(self, *, status: str) -> None:
        """Atomically create ``control_dir/done`` containing the status string."""
        self._atomic_write("done", status)


# ---------------------------------------------------------------------------
# HostWarmControl (host side)
# ---------------------------------------------------------------------------


# Polling interval for HostWarmControl.wait_for_done
_HOST_POLL_INTERVAL_S: float = 0.05


class HostWarmControl:
    """Host-side counterpart to ``FileWarmControl``.

    Handshake files under ``control_dir``:

    * ``go.json``  — written (atomically) by the host when a job is assigned;
                     contains ``{"input_path": "...", "output_dir": "...",
                     "params": {...}}``.
    * ``done``     — written by the worker; contains the status string.

    All writes use a temp-file + ``os.replace`` (atomic rename), symmetric
    with ``FileWarmControl``.
    """

    def __init__(self, control_dir: Path) -> None:
        self._dir = control_dir

    def _atomic_write(self, name: str, content: str) -> None:
        """Write *content* to ``control_dir/<name>`` atomically AND symlink-safely.

        control_dir is WORKER-WRITABLE (the gVisor tier bind-mounts ctrl/ at 0o777), so a worker
        could pre-plant ``.<name>.tmp`` or ``<name>`` as a symlink to redirect this HOST-authored
        write to clobber an outside file. ``atomic_write_confined`` uses a random
        ``O_EXCL|O_NOFOLLOW`` temp + ``renameat`` so the write can never follow a worker symlink."""
        from blastbox.contract.envelope import atomic_write_confined
        # 0o644: control files are HOST-authored but READ BY THE WORKER, which runs as a DIFFERENT
        # uid on the gVisor tier (65532) — 0o600 would make go.json unreadable and hang the warm
        # job. Not secret (the worker already knows its own job); the per-slot 0o700 ctrl dir keeps
        # other local users out.
        atomic_write_confined(self._dir, name, content.encode("utf-8"), mode=0o644)

    def signal_go(self, spec: WarmJobSpec, *, deadline: float | None = None) -> None:
        """Atomically write ``control_dir/go.json`` with the job spec.

        Symmetric with ``FileWarmControl.wait_for_go``.
        The payload matches the format parsed by that method:
        ``{"input_path": str, "output_dir": str, "params": dict}``.

        ``deadline`` is accepted for a uniform signal_go signature but unused: the go.json write
        is instant (no network), so the file-trigger warm path is bounded by wait_for_done.
        """
        payload = json.dumps(
            {
                "input_path": str(spec.input_path),
                "output_dir": str(spec.output_dir),
                "params": spec.params,
            }
        )
        self._atomic_write("go.json", payload)

    def wait_for_done(self, *, timeout_s: float) -> str:
        """Poll ``control_dir/done`` until present or ``timeout_s`` elapsed.

        Returns the status string written by the worker.

        Raises:
            WarmTimeout: if ``done`` does not appear before the deadline.
        """
        from blastbox.contract.envelope import read_confined_regular_bytes

        deadline = time.monotonic() + timeout_s

        while True:
            try:
                # Symlink-safe, capped, confined read: ctrl/ is WORKER-WRITABLE on the gVisor tier,
                # so a hostile worker could symlink `done` at a host file (info disclosure) or a
                # FIFO/huge file (block/pressure the single-threaded dispatcher). O_NOFOLLOW +
                # S_ISREG + a 4 KiB cap defeat that; a non-regular/oversized done fails closed.
                raw = read_confined_regular_bytes(self._dir, "done", max_bytes=4096)
                return raw.decode("utf-8", "replace").strip()
            except FileNotFoundError:
                pass  # not signalled yet → keep polling
            except (OSError, ValueError) as exc:
                raise WarmTimeout(f"invalid done file: {exc}") from exc

            if time.monotonic() >= deadline:
                raise WarmTimeout(
                    f"warm worker did not signal done within {timeout_s}s"
                )

            time.sleep(_HOST_POLL_INTERVAL_S)


# ---------------------------------------------------------------------------
# Post-restore CRNG reseed
# ---------------------------------------------------------------------------

# RNDADDENTROPY = _IOW('R', 3, int[2]) from <linux/random.h>: mix a buffer into
# the input pool AND credit entropy, forcing a CRNG reseed.
_RNDADDENTROPY = 0x40085203
_RESEED_BYTES = 32


def _reseed_crng_after_restore() -> None:
    """Mix fresh per-restore entropy from virtio-rng into the kernel CRNG.

    The warm-snapshot tier checkpoints ONE base VM (CRNG already seeded by the
    virtio-rng device + boot) and restores it per job, so the kernel CRNG state is
    *cloned* into every restored worker. Without a reseed, clones can repeat
    "random" output (UUIDs / secrets / nonces) right after restore until the
    kernel self-reseeds — VMGenID handles this automatically only on Linux >= 5.18
    guests, so older guests are exposed. ``/dev/hwrng`` is the Firecracker
    virtio-rng device, fed FRESH by the host on each restore, so its bytes differ
    per clone; mixing them in diverges every clone regardless of guest kernel.

    Best-effort and never fatal: a tier without virtio-rng (no ``/dev/hwrng``, e.g.
    the gVisor file tier) or a missing privilege just logs and skips.
    """
    import fcntl
    import struct

    try:
        with open("/dev/hwrng", "rb") as hw:
            seed = hw.read(_RESEED_BYTES)
    except OSError as exc:
        logger.debug("crng reseed skipped: /dev/hwrng unavailable (%s)", exc)
        return
    if len(seed) < _RESEED_BYTES:
        logger.debug("crng reseed skipped: short hwrng read (%d bytes)", len(seed))
        return

    # Prefer RNDADDENTROPY (mixes AND credits → forces an immediate reseed); the
    # microVM guest worker runs as uid 0 with CAP_SYS_ADMIN. Fall back to a plain
    # write to /dev/urandom (mixes into the pool without crediting) if not allowed.
    try:
        fd = os.open("/dev/random", os.O_WRONLY)
        try:
            # struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
            payload = struct.pack("ii", len(seed) * 8, len(seed)) + seed
            fcntl.ioctl(fd, _RNDADDENTROPY, payload)
            logger.info("crng reseeded from /dev/hwrng after restore (RNDADDENTROPY)")
            return
        finally:
            os.close(fd)
    except OSError as exc:
        logger.debug("RNDADDENTROPY failed (%s); writing /dev/urandom instead", exc)

    try:
        with open("/dev/urandom", "wb") as ur:
            ur.write(seed)
        logger.info("crng reseeded from /dev/hwrng after restore (/dev/urandom write)")
    except OSError as exc:
        logger.warning("crng reseed after restore failed entirely: %s", exc)


# ---------------------------------------------------------------------------
# serve_warm
# ---------------------------------------------------------------------------


def serve_warm(
    engine: "Engine",
    *,
    control: WarmControl,
    limits: Limits,
    idle_timeout_s: float = 600.0,
) -> int:
    """Warm worker lifecycle: warmup() → READY → wait one job → run_detonation → DONE → exit.

    Exactly one job is processed — this function never loops back to fetch a
    second job.  The disposable-slot guarantee is enforced structurally: there
    is no loop and ``wait_for_go`` is called exactly once after the warmup
    succeeds.

    Flow
    ----
    1. Call ``engine.warmup()`` if the engine has it — **before** any input
       exists, so the warm state is captured in a pristine context.
       On failure → ``signal_done(status="warmup_error")`` + exit non-zero.
    2. ``control.signal_ready()`` — host can now dispatch a job to this slot.
    3. ``spec = control.wait_for_go(timeout_s=idle_timeout_s)`` — block for
       exactly one job.  On ``WarmTimeout`` → ``signal_done(status="idle_timeout")``
       + exit 0 (the slot self-retires).
    4. ``rc = run_detonation(engine, ...)`` — identical to the cold path; output
       is host-trust-validatable unchanged.
    5. ``control.signal_done(status="ok")`` + return ``rc``.

    Returns:
        0 on success or idle timeout; non-zero on warmup failure or harness
        internal error.
    """
    # ------------------------------------------------------------------
    # Step 1: warmup (pre-input — no untrusted data exists at this point)
    # ------------------------------------------------------------------
    if hasattr(engine, "warmup"):
        try:
            engine.warmup()
        except Exception as exc:  # noqa: BLE001
            logger.error("engine.warmup() failed: %s", exc)
            try:
                control.signal_done(status="warmup_error")
            except Exception as sig_exc:  # noqa: BLE001
                logger.error("signal_done(warmup_error) failed: %s", sig_exc)
            return 1

    # ------------------------------------------------------------------
    # Step 2: signal that this slot is ready to accept one job
    # ------------------------------------------------------------------
    control.signal_ready()

    # ------------------------------------------------------------------
    # Step 3: wait for exactly one job (no loop — one job per disposable slot)
    # ------------------------------------------------------------------
    try:
        spec = control.wait_for_go(timeout_s=idle_timeout_s)
    except WarmTimeout as to_exc:
        # Log the underlying cause too — distinguishes a genuine timeout ("timed out")
        # from an immediate accept() error (e.g. a vsock device issue post-restore).
        logger.info(
            "warm slot idle timeout after %.1fs; retiring (%s)", idle_timeout_s, to_exc
        )
        try:
            control.signal_done(status="idle_timeout")
        except Exception as sig_exc:  # noqa: BLE001
            logger.error("signal_done(idle_timeout) failed: %s", sig_exc)
        return 0

    # A job arrived → this worker has just been restored from the warm snapshot.
    # Reseed the kernel CRNG with fresh per-restore entropy BEFORE detonation so a
    # workload's randomness doesn't repeat across snapshot clones (best-effort).
    _reseed_crng_after_restore()

    # ------------------------------------------------------------------
    # Step 4: process the one job through the unchanged cold-path harness
    # ------------------------------------------------------------------
    # The warm process's environment is frozen at snapshot time, so per-job params
    # can't arrive as container `-e` env the way the cold path gets them. Apply the
    # dispatcher-allowlisted params (e.g. clippyshot's CLIPPYSHOT_* scanner toggles)
    # to os.environ here — before detonation — so engine.detonate honours them. The
    # dispatcher already restricts these to the engine's allowlist; the key-shape
    # check is belt-and-braces against a malformed go.json.
    for _k, _v in (spec.params or {}).items():
        if isinstance(_k, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", _k):
            os.environ[_k] = str(_v)

    rc: int = 1
    try:
        rc = run_detonation(
            engine,
            input_path=spec.input_path,
            output_dir=spec.output_dir,
            limits=limits,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("run_detonation raised unexpectedly: %s", exc)
        rc = 1

    # ------------------------------------------------------------------
    # Step 5: signal done — always reached for the one job
    # ------------------------------------------------------------------
    try:
        control.signal_done(status="ok")
    except Exception as sig_exc:  # noqa: BLE001
        logger.error("signal_done(ok) failed: %s", sig_exc)

    return rc
