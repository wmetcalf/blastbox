"""Guest-side Firecracker worker entry points — run *inside* the microVM.

The guest signals readiness to the host over AF_VSOCK: after ``engine.warmup()``
it connects to the host (CID 2 = ``VMADDR_CID_HOST``) on ``READY_PORT`` and sends
a ``READY`` frame. Firecracker forwards that connection to the host Unix socket
that :class:`blastbox.host.runtime.firecracker.VsockReadySignal` listens on, which
flips the slot to ready — the live signal the warm pool needs to promote an FC slot.

The wire protocol is deliberately tiny (one small control frame). Job output still
travels on the ext4 output disk, never over vsock (the "no large vsock transfers"
lesson). The job round-trip (GO/DONE) is a documented follow-on that reuses this
same channel.

``READY_PORT`` / ``READY_TOKEN`` MUST match the host side. A drift-guard test
(`test_fc_protocol_constants_match`) asserts they equal the host constants.
"""
from __future__ import annotations

import logging
import socket
import struct
import time
from pathlib import Path
from typing import Callable

_log = logging.getLogger("blastbox.worker.fc_guest")

# VMADDR_CID_HOST — the well-known vsock CID of the host from inside a guest.
HOST_CID = 2
# Must match host firecracker._READY_PORT / _READY_TOKEN.
READY_PORT = 10000
READY_TOKEN = b"READY"
# Job control plane: the host connects to the guest on this vsock port to deliver
# one job (header + input bytes) and read back the status — full-duplex, one
# connection per job. Must match host firecracker._JOB_PORT.
JOB_PORT = 10001

# Wire framing: 8-byte big-endian length prefix + payload. Used for the job
# header, the input bytes, and the status. Transport-agnostic (works over the FC
# vsock stream or, in tests, an AF_UNIX socketpair).
_LEN = struct.Struct(">Q")

# Frame-size caps (defence against a corrupt length prefix → giant allocation).
MAX_HEADER_BYTES = 1 * 1024 * 1024  # job header JSON (filename + params)
MAX_INPUT_BYTES = 1024 * 1024 * 1024  # input document hard ceiling
MAX_STATUS_BYTES = 64 * 1024  # status string


def send_frame(sock: "socket.socket", data: bytes) -> None:
    """Send a length-prefixed frame."""
    sock.sendall(_LEN.pack(len(data)) + data)


# Stream chunk for send_frame_from_file — bounds the host-side buffer per write.
_FILE_FRAME_CHUNK = 64 * 1024


def send_frame_from_file(
    sock: "socket.socket",
    path: "Path",
    *,
    chunk: int = _FILE_FRAME_CHUNK,
    deadline: float | None = None,
) -> int:
    """Send a length-prefixed frame whose body is streamed from ``path`` in fixed chunks.

    Wire-identical to ``send_frame(sock, path.read_bytes())`` — an 8-byte length prefix then
    the file bytes, which the peer's ``recv_frame`` reads as length + ``recv_exact(length)`` —
    but the host never materializes the whole file (nor ``send_frame``'s ``len+data`` copy) in
    RAM. The announced length is ``path.stat().st_size``; a staged input is written once before
    the frame is sent, so the size is stable. As a belt-and-suspenders guard against a short
    read (truncated file), any shortfall is zero-padded IN BOUNDED CHUNKS to the announced
    length (so a large post-stat shrink can't allocate a huge buffer) — the peer's ``recv_exact``
    never blocks waiting for bytes that won't arrive (the document simply fails to parse).

    ``deadline`` (a ``time.monotonic()`` value) bounds the WHOLE send: each ``sendall`` is
    capped by the remaining time, so a slow-reading guest can't pin the host past it (raises
    ``TimeoutError``/``socket.timeout``). Returns the number of bytes announced.
    """
    def _sendall(buf: bytes) -> None:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("send deadline exceeded")
            sock.settimeout(remaining)
        sock.sendall(buf)

    size = path.stat().st_size
    _sendall(_LEN.pack(size))
    sent = 0
    with path.open("rb") as f:
        while sent < size:
            buf = f.read(min(chunk, size - sent))
            if not buf:
                break
            _sendall(buf)
            sent += len(buf)
    # Bounded zero-pad on a short read — never allocate more than one chunk at a time.
    zeros = bytes(min(chunk, size - sent)) if sent < size else b""
    while sent < size:
        pad = min(chunk, size - sent)
        _sendall(zeros if pad == len(zeros) else bytes(pad))
        sent += pad
    return size


def recv_exact(
    sock: "socket.socket", n: int, *, deadline: float | None = None
) -> bytes:
    """Read exactly ``n`` bytes or raise ConnectionError if the peer closes.

    A per-``recv`` socket timeout is NOT an absolute deadline: a peer that
    dribbles one byte just under the timeout keeps the call alive forever. When
    ``deadline`` (a ``time.monotonic()`` value) is given, each ``recv`` is bounded
    by the *remaining* time, so the whole read is capped — the slowloris defence
    the host needs against a compromised guest.
    """
    buf = bytearray()
    while len(buf) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read deadline exceeded")
            sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return bytes(buf)


def recv_frame(
    sock: "socket.socket", *, max_len: int, deadline: float | None = None
) -> bytes:
    """Read one length-prefixed frame, rejecting frames larger than ``max_len``."""
    (n,) = _LEN.unpack(recv_exact(sock, 8, deadline=deadline))
    if n > max_len:
        raise ValueError(f"frame too large: {n} > {max_len}")
    return recv_exact(sock, n, deadline=deadline)


def recv_line(
    sock: "socket.socket", *, max_len: int = 256, deadline: float | None = None
) -> bytes:
    """Read bytes up to and including the first newline (for FC's CONNECT reply).

    ``deadline`` (a ``time.monotonic()`` value), when given, bounds the WHOLE read: each
    ``recv`` is capped by the remaining time, so a guest that dribbles the reply one byte
    just under a per-recv timeout can't pin the caller (raises ``TimeoutError``)."""
    buf = bytearray()
    while b"\n" not in buf:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read deadline exceeded")
            sock.settimeout(remaining)
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_len:
            raise ValueError("line too long")
    return bytes(buf)

# Injectable seam: returns a connected-capable AF_VSOCK socket. Tests inject a
# fake so the framing + retry logic runs without a real microVM.
SocketFactory = Callable[[], "socket.socket"]


def _default_vsock_factory() -> "socket.socket":
    # AF_VSOCK exists on Linux; this code path only runs inside the guest VM.
    return socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]


def signal_ready_vsock(
    *,
    cid: int = HOST_CID,
    port: int = READY_PORT,
    token: bytes = READY_TOKEN,
    retries: int = 60,
    backoff_s: float = 0.5,
    socket_factory: SocketFactory = _default_vsock_factory,
) -> bool:
    """Connect to ``(cid, port)`` over vsock and send ``token``.

    Retries up to ``retries`` times with ``backoff_s`` between attempts — the host
    may bind its listener fractionally after the guest boots, so a transient
    connect failure is expected and retried. Returns True once the token is sent.
    """
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        s = socket_factory()
        try:
            s.settimeout(2.0)
            s.connect((cid, port))
            s.sendall(token)
            _log.info("fc_guest.ready_sent attempt=%d", attempt)
            return True
        except OSError as exc:
            last_exc = exc
            time.sleep(backoff_s)
        finally:
            try:
                s.close()
            except OSError:
                pass
    _log.error(
        "fc_guest.ready_failed after %d attempts: %s", retries, last_exc
    )
    return False


def run_fc_guest(
    engine: object,
    *,
    warmup: bool = True,
    **ready_kwargs: object,
) -> bool:
    """Warm the engine, then signal READY to the host. Called by the rootfs init.

    A warmup error is logged but NOT fatal — the slot can still serve a job; the
    point of READY is "the worker process is up and the engine is loaded". Returns
    the result of :func:`signal_ready_vsock`.
    """
    if warmup:
        warm = getattr(engine, "warmup", None)
        if callable(warm):
            try:
                warm()
            except Exception as exc:  # noqa: BLE001
                _log.warning("fc_guest.warmup_error: %s", exc)
    return signal_ready_vsock(**ready_kwargs)  # type: ignore[arg-type]
