"""Guest-side vsock WarmControl for the Firecracker tier.

``VsockWarmControl`` is the AF_VSOCK implementation of the ``WarmControl``
protocol (``signal_ready`` / ``wait_for_go`` / ``signal_done``) that
``serve_warm`` drives inside the microVM. It carries one job over a single
host→guest connection:

    host signal_go  -> [header frame][input frame]  (the host connects to JOB_PORT)
    guest detonate  -> writes artifacts + metadata.json to output_dir (the ext4 disk)
    guest signal_done -> [status frame]             (same connection, reverse)
    host wait_for_done -> reads status; then reads the disk via rdump

Output never travels over vsock — only the small control frames do (the
"no large vsock transfers" lesson); the harness writes artifacts to the output
disk, which the host reads with debugfs rdump after DONE.

The job listener is bound in ``__init__`` (before ``signal_ready``) so the host's
post-READY connect always finds a listener. The listening socket is injectable so
the protocol is unit-testable over an AF_UNIX socketpair (AF_VSOCK needs a VM).
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any, Callable

from blastbox.errors import WarmTimeout
from blastbox.worker.fc_guest import (
    JOB_PORT,
    MAX_HEADER_BYTES,
    MAX_INPUT_BYTES,
    READY_PORT,
    _default_vsock_factory,
    recv_frame,
    send_frame,
    signal_ready_vsock,
)
from blastbox.worker.warm import WarmJobSpec

_log = logging.getLogger("blastbox.worker.fc_warm")

# VMADDR_CID_ANY — bind a guest vsock listener on any local CID.
_VMADDR_CID_ANY = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)

ListenerFactory = Callable[[int], "socket.socket"]


def _default_vsock_listener(port: int) -> "socket.socket":
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
    s.bind((_VMADDR_CID_ANY, port))
    s.listen(1)
    return s


def _safe_name(name: str) -> str:
    """Reduce a host-supplied filename to a safe basename (no traversal).

    ``Path("..").name == ".."`` — Python does NOT strip the parent token — so the
    dot-only components must be rejected explicitly or ``input_dir / ".."`` would
    escape one level.
    """
    base = Path(name).name.strip()
    if base in ("", ".", ".."):
        return "input"
    return base


class VsockWarmControl:
    """AF_VSOCK ``WarmControl`` for the guest worker inside an FC microVM."""

    def __init__(
        self,
        input_dir: Path | str,
        output_dir: Path | str,
        *,
        job_port: int = JOB_PORT,
        ready_port: int = READY_PORT,
        max_input_bytes: int = MAX_INPUT_BYTES,
        listener: "socket.socket | None" = None,
        listener_factory: ListenerFactory = _default_vsock_listener,
        ready_socket_factory: Callable[[], "socket.socket"] = _default_vsock_factory,
    ) -> None:
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)
        self._ready_port = ready_port
        self._max_input = max_input_bytes
        self._ready_factory = ready_socket_factory
        # Bind the job listener NOW — before signal_ready — so a host connect that
        # races just after READY still finds a listener (listen backlog queues it).
        self._listener = listener if listener is not None else listener_factory(job_port)
        self._conn: "socket.socket | None" = None

    def signal_ready(self) -> None:
        ok = signal_ready_vsock(
            port=self._ready_port, socket_factory=self._ready_factory
        )
        if not ok:
            raise ConnectionError("failed to signal READY over vsock")

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        self._listener.settimeout(timeout_s)
        try:
            conn, _ = self._listener.accept()
        except (TimeoutError, socket.timeout, OSError) as exc:
            raise WarmTimeout(f"no job within {timeout_s}s: {exc}") from exc
        self._conn = conn
        # The accepted conn does NOT inherit the listener timeout — bound the
        # header/input reads with an absolute deadline, and close the conn if the
        # read fails (else it leaks: signal_done would never run to close it).
        deadline = time.monotonic() + timeout_s
        try:
            header_raw = recv_frame(conn, max_len=MAX_HEADER_BYTES, deadline=deadline)
            header_obj = json.loads(header_raw.decode("utf-8"))
            if not isinstance(header_obj, dict):
                # A header decoding to a list/scalar would make header.get(...) raise
                # AttributeError (NOT caught below) — validate the shape so it fails cleanly.
                raise ValueError("warm job header must be a JSON object")
            header: dict[str, Any] = header_obj
            input_bytes = recv_frame(conn, max_len=self._max_input, deadline=deadline)
        except (OSError, ValueError, ConnectionError) as exc:
            try:
                conn.close()
            except OSError:
                pass
            self._conn = None
            raise WarmTimeout(f"job header/input read failed: {exc}") from exc

        self._input_dir.mkdir(parents=True, exist_ok=True)
        input_path = self._input_dir / _safe_name(header.get("filename", "input"))
        input_path.write_bytes(input_bytes)
        _log.info("fc_warm.job_received bytes=%d -> %s", len(input_bytes), input_path)

        params = header.get("params")
        if not isinstance(params, dict):  # never forward a non-dict params to the engine
            params = {}
        return WarmJobSpec(
            input_path=input_path, output_dir=self._output_dir, params=params
        )

    def _fsync_output(self) -> None:
        """Flush output to the disk so the host's post-DONE debugfs rdump sees the
        bytes even though the VM is SIGKILLed (not unmounted). Without this, output
        sits in the guest page cache and is lost on reap.

        Each file fsync is ISOLATED: a single transient open/fsync error (more likely
        on big multi-page jobs) must NOT skip the subsequent files or — critically —
        the directory fsync that persists the dir entries (esp. the last-written
        metadata.json). A final os.sync() is the belt-and-braces global flush of every
        dirty page on every mount; combined with the outdisk's Writeback cache_type it
        forces a virtio FLUSH that FC writes through to the host backing file."""
        try:
            for path in self._output_dir.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    fd = os.open(path, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                except OSError as exc:
                    _log.warning("fc_warm.fsync_output file %s failed: %s", path, exc)
        except OSError as exc:
            # rglob itself failed (dir unreadable) — fall through to fsync(dir)+sync.
            _log.warning("fc_warm.fsync_output walk failed: %s", exc)
        # Directory fsync persists the dir entries; run it regardless of any per-file error.
        try:
            dfd = os.open(self._output_dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError as exc:
            _log.warning("fc_warm.fsync_output dir fsync failed: %s", exc)
        # Global flush: catches anything the targeted fsyncs missed (subdir inodes,
        # allocation bitmaps) and issues the virtio FLUSH honored under Writeback.
        try:
            os.sync()
        except OSError as exc:  # noqa: BLE001 — never fail the job on a flush hiccup
            _log.warning("fc_warm.fsync_output os.sync failed: %s", exc)

    def signal_done(self, *, status: str) -> None:
        # Flush output to the disk BEFORE telling the host we're done — the host
        # reads the ext4 disk via rdump as soon as it sees this status frame.
        self._fsync_output()
        if self._conn is None:
            _log.warning("fc_warm.signal_done with no connection (status=%s)", status)
            return
        try:
            send_frame(self._conn, status.encode("utf-8"))
        except OSError as exc:
            _log.warning("fc_warm.signal_done send failed: %s", exc)
        finally:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
