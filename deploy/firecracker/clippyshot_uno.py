"""Warm-UNO conversion path — a persistent LibreOffice UNO server.

ClippyShot's default conversion shells out to a one-shot ``soffice --convert-to``
per document, paying the ~750 ms soffice boot every time. The warm path keeps a
persistent ``unoserver`` (which supervises one ``soffice --accept`` instance) alive
for the worker's lifetime and converts each document with ``unoconvert``. The
2026-05-31 spike (``uno_spike.sh``) proved this is byte/pixel-identical to the cold
path for the same PDF-export filters.

Lifecycle: the server is started once in the engine's ``warmup()`` (pre-input, no
untrusted data present), bound to loopback only, and torn down with the disposable
slot — never shared across documents (one slot, one doc). The Firecracker-snapshot
tier that captures this warm server in a memory snapshot is a separate layer (see
``docs/specs/2026-06-03-warm-uno-fc-snapshot-design.md`` in the blastbox repo); this
module is the conversion path the snapshot restores into, and it also works as a
plain warm pool.
"""
from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from clippyshot.errors import LibreOfficeError

# Filter selection MUST mirror ``LibreOfficeRunner.convert_to_pdf`` so warm output is
# identical to the cold ``--convert-to`` path. The cold path encodes filter options
# in LibreOffice's filter-string form
# (``calc_pdf_Export:{"SinglePageSheets":{"type":"boolean","value":"true"}}``), while
# ``unoconvert`` takes them as ``--filter <name> --filter-options key=value`` — so we
# return a (name, options) pair and let ``unoconvert_argv`` format them.
_CALC_LABELS = frozenset({"xlsx", "xlsm", "xls", "ods", "fods", "csv", "xlsb"})
_IMPRESS_LABELS = frozenset({"pptx", "pptm", "ppt", "pps", "ppsx", "odp", "fodp"})
_DRAW_LABELS = frozenset({"odg", "fodg", "xps", "oxps"})

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2003


def pdf_filter_for_label(label: str) -> tuple[str, dict[str, str]]:
    """Return the (UNO PDF export-filter name, filter-options) for a detected
    format ``label``, mirroring ``LibreOfficeRunner`` so warm output matches cold.

    Calc family → ``calc_pdf_Export`` + ``SinglePageSheets`` (one page per sheet);
    Impress family → ``impress_pdf_Export``; Draw family → ``draw_pdf_Export``;
    everything else (Writer + unknown) → ``writer_pdf_Export``.
    """
    label = (label or "").lower()
    if label in _CALC_LABELS:
        return "calc_pdf_Export", {"SinglePageSheets": "true"}
    if label in _IMPRESS_LABELS:
        return "impress_pdf_Export", {}
    if label in _DRAW_LABELS:
        return "draw_pdf_Export", {}
    return "writer_pdf_Export", {}


def unoconvert_argv(
    unoconvert_bin: str,
    input_path: Path,
    output_path: Path,
    label: str,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> list[str]:
    """Build the ``unoconvert`` command for one document against a running
    unoserver. Filter + options mirror the cold path (``pdf_filter_for_label``);
    this is the exact invocation shape the 2026-05-31 spike validated."""
    filter_name, options = pdf_filter_for_label(label)
    argv = [
        unoconvert_bin,
        "--host", host,
        "--port", str(port),
        "--convert-to", "pdf",
        "--filter", filter_name,
    ]
    for key, value in options.items():
        argv += ["--filter-options", f"{key}={value}"]
    argv += [str(input_path), str(output_path)]
    return argv


def _port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class UnoServer:
    """A persistent LibreOffice UNO server (``unoserver --daemon``).

    Bound to **loopback only** — the URP ``--accept`` socket is new attack surface,
    so it never listens on a routable interface. Started once in ``warmup()``, polled
    until the port accepts a connection, and stopped on teardown. Not safe to share
    across documents; the disposable-slot model tears it down per job.

    All process/socket/time dependencies are injectable so the lifecycle is unit
    tested without a real LibreOffice.
    """

    def __init__(
        self,
        unoserver_bin: str = "unoserver",
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        user_installation: str | None = None,
        ready_timeout_s: float = 30.0,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        port_check: Callable[[str, int], bool] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._bin = unoserver_bin
        self._host = host
        self._port = port
        self._user_installation = user_installation
        self._ready_timeout_s = ready_timeout_s
        self._popen = popen
        self._port_check = port_check or _port_listening
        self._sleep = sleep
        self._monotonic = monotonic
        self._proc: subprocess.Popen | None = None

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def argv(self) -> list[str]:
        # Foreground (NOT --daemon): we want the Popen handle to BE the server so
        # stop()/poll() control its lifecycle. --daemon double-forks and detaches,
        # leaving us tracking a launcher that has already exited.
        argv = [
            self._bin,
            "--interface", self._host,
            "--port", str(self._port),
        ]
        if self._user_installation:
            argv += ["--user-installation", self._user_installation]
        return argv

    def start(self) -> None:
        """Ensure a warm UNO server is listening. Idempotent.

        If the port is already serving — e.g. unoserver was started by the FC
        rootfs init and captured in the snapshot — **adopt** it (no second spawn,
        nothing to manage). Otherwise spawn unoserver in the foreground and block
        until the UNO port accepts a connection. Raises :class:`LibreOfficeError`
        if a spawned unoserver exits early or never becomes ready."""
        if self._proc is not None:
            return
        if self._port_check(self._host, self._port):
            return  # adopt an already-running server (snapshot / rootfs-started)
        self._proc = self._popen(self.argv())
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = self._monotonic() + self._ready_timeout_s
        while self._monotonic() < deadline:
            rc = self._proc.poll() if self._proc is not None else None
            if rc is not None:
                self._proc = None
                raise LibreOfficeError(f"unoserver exited during warmup (rc={rc})")
            if self._port_check(self._host, self._port):
                return
            self._sleep(0.1)
        self.stop()
        raise LibreOfficeError(
            f"unoserver not ready on {self._host}:{self._port} "
            f"within {self._ready_timeout_s}s"
        )

    def is_ready(self) -> bool:
        # If we spawned it and it has since exited, it's not ready. Otherwise the
        # real signal is whether the UNO port responds — which also covers an
        # adopted server we did not spawn (the snapshot / rootfs case).
        if self._proc is not None and self._proc.poll() is not None:
            return False
        return self._port_check(self._host, self._port)

    def stop(self) -> None:
        """Terminate the server (SIGTERM, then SIGKILL after a 5 s grace period)."""
        proc = self._proc
        self._proc = None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def convert_via_uno(
    server: UnoServer,
    input_path: Path,
    output_path: Path,
    label: str,
    *,
    unoconvert_bin: str = "unoconvert",
    timeout_s: float = 120.0,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Convert ``input_path`` → ``output_path`` (PDF) via the running unoserver.

    Raises :class:`LibreOfficeError` on non-zero exit, timeout, or missing/empty
    output so the caller can fall back to the cold ``--convert-to`` path — a UNO
    hiccup must never fail the job. The caller owns that fallback."""
    argv = unoconvert_argv(
        unoconvert_bin, input_path, output_path, label,
        host=server.host, port=server.port,
    )
    try:
        proc = run(argv, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise LibreOfficeError(f"unoconvert timed out after {timeout_s}s") from exc
    if proc.returncode != 0:
        stderr = proc.stderr or b""
        detail = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr)
        raise LibreOfficeError(
            f"unoconvert failed (rc={proc.returncode}): {detail[:500]}"
        )
    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise LibreOfficeError("unoconvert produced no output PDF")
