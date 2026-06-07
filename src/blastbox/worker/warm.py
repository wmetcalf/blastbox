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
        deadline = time.monotonic() + timeout_s

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

            if time.monotonic() >= deadline:
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

    # ------------------------------------------------------------------
    # Step 4: process the one job through the unchanged cold-path harness
    # ------------------------------------------------------------------
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
