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


def test_send_frame_from_file_wire_identical_to_send_frame(tmp_path):
    # Streaming the body from disk must produce the exact same wire bytes as
    # send_frame(sock, path.read_bytes()) so the guest's recv_frame is unaffected.
    from blastbox.worker.fc_guest import send_frame_from_file

    body = b"".join(bytes([i % 256]) for i in range(200_000))  # > one 64 KiB chunk
    p = tmp_path / "input.bin"
    p.write_bytes(body)

    a, b = socket.socketpair()
    try:
        ret = send_frame_from_file(a, p, chunk=64 * 1024)
        assert ret == len(body)
        assert recv_frame(b, max_len=len(body) + 16) == body  # reassembles identically
    finally:
        a.close()
        b.close()


def test_send_frame_from_file_streams_in_chunks(tmp_path):
    # Prove it never materializes the whole file: record every sendall() and assert no single
    # write exceeds the chunk size + the 8-byte length prefix (i.e. no read_bytes()+concat copy).
    from blastbox.worker.fc_guest import send_frame_from_file

    p = tmp_path / "big.bin"
    p.write_bytes(b"Z" * 300_000)

    class _Rec:
        def __init__(self) -> None:
            self.writes: list[int] = []

        def sendall(self, data: bytes) -> None:
            self.writes.append(len(data))

    rec = _Rec()
    send_frame_from_file(rec, p, chunk=64 * 1024)
    assert rec.writes[0] == 8  # length prefix sent on its own
    assert max(rec.writes[1:]) <= 64 * 1024  # body never sent as one giant buffer
    assert sum(rec.writes[1:]) == 300_000  # all bytes accounted for


def test_send_frame_from_file_zero_pads_short_read(tmp_path):
    # Belt-and-suspenders: if the file shrinks below its announced stat size, the frame is
    # padded to length so the peer's recv_exact never blocks (the doc just fails to parse).
    from blastbox.worker.fc_guest import send_frame_from_file

    p = tmp_path / "shrinks.bin"
    p.write_bytes(b"abcd")

    class _ShrinkFile:
        """stat() reports 8 bytes but the stream only yields 4 — simulates a truncation race."""

        def stat(self):
            import os as _os

            real = p.stat()
            return _os.stat_result((real.st_mode, 0, 0, 1, 0, 0, 8, 0, 0, 0))

        def open(self, mode):
            return p.open(mode)

    a, b = socket.socketpair()
    try:
        send_frame_from_file(a, _ShrinkFile(), chunk=64 * 1024)
        frame = recv_frame(b, max_len=100)
        assert len(frame) == 8 and frame[:4] == b"abcd" and frame[4:] == b"\x00\x00\x00\x00"
    finally:
        a.close()
        b.close()


def test_send_frame_from_file_pads_short_read_in_bounded_chunks(tmp_path):
    """A large post-stat shrink must pad in bounded chunks — never allocate (size - sent) at
    once — so the chunked memory bound holds even on a truncation race."""
    from blastbox.worker.fc_guest import send_frame_from_file

    real = tmp_path / "real.bin"
    real.write_bytes(b"abc")  # only 3 real bytes on disk

    class _BigStat:
        """stat() claims 5 MB but the stream yields 3 bytes -> ~5 MB of zero-pad."""

        def stat(self):
            import os as _os

            r = real.stat()
            return _os.stat_result((r.st_mode, 0, 0, 1, 0, 0, 5_000_000, 0, 0, 0))

        def open(self, mode):
            return real.open(mode)

    class _Rec:
        def __init__(self):
            self.max_write = 0
            self.total = 0

        def settimeout(self, t):
            pass

        def sendall(self, b):
            self.max_write = max(self.max_write, len(b))
            self.total += len(b)

    rec = _Rec()
    send_frame_from_file(rec, _BigStat(), chunk=64 * 1024)
    assert rec.max_write <= 64 * 1024  # never one giant ~5 MB buffer
    assert rec.total == 8 + 5_000_000  # 8-byte length prefix + announced size (3 real + pad)


def test_send_frame_from_file_honors_deadline(tmp_path):
    """An already-passed deadline aborts the send so a slow-reading guest can't pin the host."""
    import time

    from blastbox.worker.fc_guest import send_frame_from_file

    p = tmp_path / "in.bin"
    p.write_bytes(b"x" * 200_000)

    class _Sock:
        def settimeout(self, t):
            pass

        def sendall(self, b):
            pass

    with pytest.raises(TimeoutError):
        send_frame_from_file(_Sock(), p, deadline=time.monotonic() - 1.0)


def test_send_frame_from_file_sets_per_send_timeout_from_deadline(tmp_path):
    """With a future deadline, each sendall is bounded by the remaining time."""
    import time

    from blastbox.worker.fc_guest import send_frame_from_file

    p = tmp_path / "in.bin"
    p.write_bytes(b"y" * 100_000)

    class _Rec:
        def __init__(self):
            self.timeouts = []
            self.body = bytearray()

        def settimeout(self, t):
            self.timeouts.append(t)

        def sendall(self, b):
            self.body += b

    rec = _Rec()
    send_frame_from_file(rec, p, deadline=time.monotonic() + 30.0)
    assert rec.timeouts and all(t > 0 for t in rec.timeouts)  # every send bounded
    assert rec.body[8:] == b"y" * 100_000  # body intact after the length prefix


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
