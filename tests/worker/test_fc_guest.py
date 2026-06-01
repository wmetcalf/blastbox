"""Unit tests for the guest-side FC worker (worker/fc_guest.py).

AF_VSOCK needs a real microVM, so the socket is injected: a fake records the
connect target + bytes sent, letting us exercise the framing and retry logic on
any host. A drift-guard asserts the guest's wire constants match the host's.
"""
from __future__ import annotations

import socket
import struct

import pytest

from blastbox.worker.fc_guest import (
    HOST_CID,
    READY_PORT,
    READY_TOKEN,
    _default_vsock_factory,
    recv_exact,
    recv_frame,
    recv_line,
    run_fc_guest,
    send_frame,
    signal_ready_vsock,
)


class _FakeVsock:
    def __init__(self, *, fail_connect: bool = False) -> None:
        self.fail_connect = fail_connect
        self.connected: tuple[int, int] | None = None
        self.sent = b""
        self.closed = False
        self.timeout: float | None = None

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def connect(self, addr: tuple[int, int]) -> None:
        if self.fail_connect:
            raise OSError("connection refused")
        self.connected = addr

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


class _Factory:
    """Yields a preset sequence of fake sockets, recording each handed out."""

    def __init__(self, fakes: list[_FakeVsock]) -> None:
        self._fakes = list(fakes)
        self.made: list[_FakeVsock] = []

    def __call__(self) -> _FakeVsock:
        fake = self._fakes.pop(0)
        self.made.append(fake)
        return fake


def test_signal_ready_success_sends_token_to_host_cid():
    fac = _Factory([_FakeVsock()])
    ok = signal_ready_vsock(socket_factory=fac)
    assert ok is True
    sock = fac.made[0]
    assert sock.connected == (HOST_CID, READY_PORT)
    assert sock.sent == READY_TOKEN
    assert sock.closed is True


def test_signal_ready_retries_then_succeeds():
    # Two failed connects, then success — covers the host-binds-late race.
    fac = _Factory([
        _FakeVsock(fail_connect=True),
        _FakeVsock(fail_connect=True),
        _FakeVsock(),
    ])
    ok = signal_ready_vsock(socket_factory=fac, retries=5, backoff_s=0.0)
    assert ok is True
    assert len(fac.made) == 3
    assert fac.made[-1].sent == READY_TOKEN
    # Every socket, including the failed ones, is closed.
    assert all(s.closed for s in fac.made)


def test_signal_ready_all_fail_returns_false():
    fac = _Factory([_FakeVsock(fail_connect=True) for _ in range(3)])
    ok = signal_ready_vsock(socket_factory=fac, retries=3, backoff_s=0.0)
    assert ok is False
    assert len(fac.made) == 3


def test_run_fc_guest_warms_then_signals():
    class _Engine:
        def __init__(self) -> None:
            self.warmed = False

        def warmup(self) -> None:
            self.warmed = True

    eng = _Engine()
    fac = _Factory([_FakeVsock()])
    ok = run_fc_guest(eng, socket_factory=fac)
    assert ok is True
    assert eng.warmed is True
    assert fac.made[0].sent == READY_TOKEN


def test_run_fc_guest_warmup_error_is_nonfatal():
    class _Engine:
        def warmup(self) -> None:
            raise RuntimeError("warmup blew up")

    fac = _Factory([_FakeVsock()])
    ok = run_fc_guest(_Engine(), socket_factory=fac)
    assert ok is True  # signalled ready despite the warmup error
    assert fac.made[0].sent == READY_TOKEN


def test_run_fc_guest_skip_warmup():
    class _Engine:
        def __init__(self) -> None:
            self.warmed = False

        def warmup(self) -> None:
            self.warmed = True

    eng = _Engine()
    fac = _Factory([_FakeVsock()])
    run_fc_guest(eng, warmup=False, socket_factory=fac)
    assert eng.warmed is False


def test_fc_protocol_constants_match_host():
    """Guest wire constants must equal the host's, or the handshake silently breaks."""
    from blastbox.worker.fc_guest import JOB_PORT
    from blastbox.host.runtime import firecracker as host_fc

    assert READY_PORT == host_fc._READY_PORT
    assert READY_TOKEN == host_fc._READY_TOKEN
    assert JOB_PORT == host_fc._JOB_PORT


def test_default_factory_makes_vsock_socket():
    if not hasattr(socket, "AF_VSOCK"):
        pytest.skip("AF_VSOCK not available")
    try:
        s = _default_vsock_factory()
    except OSError:
        pytest.skip("vsock module not available on this host")
    try:
        assert s.family == socket.AF_VSOCK
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Wire framing (transport-agnostic — tested over an AF_UNIX socketpair)
# ---------------------------------------------------------------------------


def test_send_recv_frame_roundtrip():
    a, b = socket.socketpair()
    try:
        send_frame(a, b"\x00\x01\x02hello")
        assert recv_frame(b, max_len=100) == b"\x00\x01\x02hello"
    finally:
        a.close()
        b.close()


def test_multiple_frames_preserved_in_order():
    a, b = socket.socketpair()
    try:
        send_frame(a, b"one")
        send_frame(a, b"two")
        assert recv_frame(b, max_len=100) == b"one"
        assert recv_frame(b, max_len=100) == b"two"
    finally:
        a.close()
        b.close()


def test_recv_frame_rejects_oversize_length():
    a, b = socket.socketpair()
    try:
        send_frame(a, b"x" * 10)
        with pytest.raises(ValueError):
            recv_frame(b, max_len=5)
    finally:
        a.close()
        b.close()


def test_recv_exact_raises_on_truncated_stream():
    a, b = socket.socketpair()
    try:
        a.sendall(b"ab")
        a.close()
        with pytest.raises(ConnectionError):
            recv_exact(b, 10)
    finally:
        b.close()


def test_recv_line_stops_at_newline():
    a, b = socket.socketpair()
    try:
        a.sendall(b"OK 1024\nleftover")
        assert recv_line(b) == b"OK 1024\n"
    finally:
        a.close()
        b.close()


def test_recv_frame_deadline_bounds_a_dribbling_peer():
    """An absolute deadline caps the whole read — a peer that sends the length
    prefix then stalls cannot pin the reader past the deadline (slowloris guard)."""
    import time

    a, b = socket.socketpair()
    try:
        # Send a length prefix promising 100 bytes, then send nothing.
        a.sendall(struct.pack(">Q", 100))
        t0 = time.monotonic()
        with pytest.raises((TimeoutError, OSError)):
            recv_frame(b, max_len=1000, deadline=time.monotonic() + 0.3)
        assert time.monotonic() - t0 < 1.5  # bounded, not hung
    finally:
        a.close()
        b.close()
