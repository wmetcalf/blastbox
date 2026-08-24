"""Tests for the vsock job round-trip: VsockHostWarmControl <-> VsockWarmControl.

AF_VSOCK needs a microVM, so the transport is an AF_UNIX socketpair (the framing
is transport-agnostic) and the host's FC CONNECT handshake is exercised against a
tiny local AF_UNIX server that plays firecracker's role.
"""
from __future__ import annotations

import json
import struct
import socket
import threading

import pytest

from blastbox.errors import WarmTimeout
from blastbox.host.runtime.firecracker import FCError, VsockHostWarmControl
from blastbox.worker.fc_warm import VsockWarmControl, _safe_name
from blastbox.worker.warm import WarmJobSpec


class _FakeListener:
    """Listener double whose accept() hands back a preset connection once."""

    def __init__(self, conn: socket.socket) -> None:
        self._conn = conn
        self._given = False

    def settimeout(self, t: float) -> None:
        pass

    def accept(self):
        if self._given:
            raise TimeoutError("no more connections")
        self._given = True
        return self._conn, ("vsock", 0)


# ---------------------------------------------------------------------------
# Full job round-trip
# ---------------------------------------------------------------------------


def test_vsock_job_roundtrip(tmp_path):
    host_end, guest_end = socket.socketpair()
    src = tmp_path / "doc.bin"
    src.write_bytes(b"hello-untrusted-document")

    host = VsockHostWarmControl(tmp_path / "vsock.sock", connect_fn=lambda: host_end)
    indir = tmp_path / "in"
    outdir = tmp_path / "out"
    outdir.mkdir()
    guest = VsockWarmControl(indir, outdir, listener=_FakeListener(guest_end))

    # Host delivers the job → guest receives input + params.
    host.signal_go(
        WarmJobSpec(input_path=src, output_dir=tmp_path / "hostout", params={"dpi": "150"})
    )
    spec = guest.wait_for_go(timeout_s=5.0)
    assert spec.input_path.read_bytes() == b"hello-untrusted-document"
    assert spec.params == {"dpi": "150"}
    assert spec.output_dir == outdir

    # Guest produces output + signals done → host reads the status.
    (outdir / "page-001.txt").write_text("rendered")
    guest.signal_done(status="ok")
    assert host.wait_for_done(timeout_s=5.0) == "ok"


def test_done_status_propagates(tmp_path):
    host_end, guest_end = socket.socketpair()
    src = tmp_path / "d"
    src.write_bytes(b"x")
    host = VsockHostWarmControl(tmp_path / "u", connect_fn=lambda: host_end)
    outdir = tmp_path / "out"
    outdir.mkdir()
    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_FakeListener(guest_end))
    host.signal_go(WarmJobSpec(input_path=src, output_dir=outdir, params={}))
    guest.wait_for_go(timeout_s=5.0)
    guest.signal_done(status="engine_error")
    assert host.wait_for_done(timeout_s=5.0) == "engine_error"


# ---------------------------------------------------------------------------
# Guest-side edge cases
# ---------------------------------------------------------------------------


def test_wait_for_go_times_out_when_no_job(tmp_path):
    # Listener that always reports timeout → WarmTimeout.
    class _Idle:
        def settimeout(self, t):
            pass

        def accept(self):
            raise TimeoutError("idle")

    guest = VsockWarmControl(tmp_path / "in", tmp_path / "out", listener=_Idle())
    with pytest.raises(WarmTimeout):
        guest.wait_for_go(timeout_s=0.1)


def test_wait_for_go_survives_restore_clock_jump(tmp_path, monkeypatch):
    """The FC vsock warm path must restart its idle countdown after a restore
    clock-jump, like the gVisor file path (PR #37 review, codex P1). Without the
    reset, a restore from a snapshot older than timeout_s makes the first
    post-restore accept() deadline already-expired and drops the just-sent job.
    """
    import blastbox.worker.warm as warm

    host_end, guest_end = socket.socketpair()
    src = tmp_path / "doc.bin"
    src.write_bytes(b"restored-doc")
    outdir = tmp_path / "out"
    outdir.mkdir()

    class _RestoreListener:
        """First accept() reports a timeout (still 'blocked' at the checkpoint),
        then hands back the connection (host connected after the restore)."""

        def __init__(self, conn: socket.socket) -> None:
            self._conn = conn
            self._calls = 0

        def settimeout(self, t: float) -> None:
            pass

        def accept(self):
            self._calls += 1
            if self._calls == 1:
                raise TimeoutError("still waiting at checkpoint")
            return self._conn, ("vsock", 0)

    # monotonic: init=0.0 (deadline=5.0); the first expired() check leaps to
    # 10_000 (a multi-hour restore) — already past the original deadline, so
    # WITHOUT the reset this would raise WarmTimeout. Stable after, so the
    # post-accept recv deadline stays in the future and the header/input read OK.
    state = {"n": 0}
    seq = [0.0, 10_000.0]

    def fake_monotonic() -> float:
        i = state["n"]
        state["n"] += 1
        return seq[i] if i < len(seq) else 10_000.0

    monkeypatch.setattr(warm.time, "monotonic", fake_monotonic)

    host = VsockHostWarmControl(tmp_path / "vsock.sock", connect_fn=lambda: host_end)
    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_RestoreListener(guest_end))
    host.signal_go(WarmJobSpec(input_path=src, output_dir=outdir, params={}))

    spec = guest.wait_for_go(timeout_s=5.0)  # must NOT raise despite the clock jump
    assert spec.input_path.read_bytes() == b"restored-doc"


def test_safe_name_strips_traversal():
    assert _safe_name("../../etc/passwd") == "passwd"
    assert _safe_name("/abs/path/doc.docx") == "doc.docx"
    assert _safe_name("") == "input"
    assert _safe_name("   ") == "input"
    # Path("..").name == ".." — must NOT escape input_dir.
    assert _safe_name("..") == "input"
    assert _safe_name("a/b/..") == "input"
    assert _safe_name(".") == "input"


def test_signal_done_without_connection_is_safe(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_FakeListener(socket.socketpair()[0]))
    # No wait_for_go → no connection; signal_done must not raise.
    guest.signal_done(status="idle_timeout")


# ---------------------------------------------------------------------------
# Host-side FC CONNECT handshake (against a local AF_UNIX server playing FC)
# ---------------------------------------------------------------------------


def _fc_server(uds_path, reply: bytes, *, read_job: bool = False, send_status: bytes | None = None):
    """A tiny server emulating firecracker's host->guest vsock proxy on a UDS."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(uds_path))
    srv.listen(1)
    captured: dict = {}

    def _run():
        conn, _ = srv.accept()
        with conn:
            line = b""
            while not line.endswith(b"\n"):
                c = conn.recv(1)
                if not c:
                    break
                line += c
            captured["connect_line"] = line
            conn.sendall(reply)
            if read_job:
                from blastbox.worker.fc_guest import recv_frame as _rf

                captured["header"] = _rf(conn, max_len=1 << 20)
                captured["input"] = _rf(conn, max_len=1 << 20)
            if send_status is not None:
                from blastbox.worker.fc_guest import send_frame as _sf

                _sf(conn, send_status)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return srv, t, captured


def test_host_connect_handshake_ok(tmp_path):
    uds = tmp_path / "vsock.sock"
    srv, t, captured = _fc_server(
        uds, b"OK 1024\n", read_job=True, send_status=b"ok"
    )
    try:
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload-bytes")
        host = VsockHostWarmControl(uds)  # real _connect path
        host.signal_go(WarmJobSpec(input_path=src, output_dir=tmp_path, params={"a": "b"}))
        assert host.wait_for_done(timeout_s=5.0) == "ok"
        t.join(timeout=5.0)
        assert captured["connect_line"] == b"CONNECT 10001\n"
        assert captured["input"] == b"payload-bytes"
    finally:
        srv.close()


def test_host_connect_handshake_rejected(tmp_path):
    uds = tmp_path / "vsock.sock"
    srv, t, _ = _fc_server(uds, b"ERR no listener\n")
    try:
        src = tmp_path / "in.bin"
        src.write_bytes(b"x")
        host = VsockHostWarmControl(uds)
        with pytest.raises(FCError):
            host.signal_go(WarmJobSpec(input_path=src, output_dir=tmp_path, params={}))
    finally:
        srv.close()


def test_wait_for_done_before_signal_go_raises(tmp_path):
    host = VsockHostWarmControl(tmp_path / "vsock.sock")
    with pytest.raises(WarmTimeout):
        host.wait_for_done(timeout_s=0.1)


# ---------------------------------------------------------------------------
# _fsync_output durability hardening
# ---------------------------------------------------------------------------


def test_fsync_output_dir_and_sync_run_even_if_a_file_fsync_raises(tmp_path, monkeypatch):
    """A transient per-file fsync error (more likely on big multi-page jobs) must
    NOT skip the directory fsync (persists the metadata.json dir entry) or the final
    os.sync(). Regression for the shared-try that aborted the whole flush on one
    file's error -> host rdumped an empty disk ('metadata.json not found')."""
    import os as _os

    import blastbox.worker.fc_warm as fc_warm

    outdir = tmp_path / "out"
    outdir.mkdir()
    for i in range(3):
        (outdir / f"page_{i}.png").write_bytes(b"x" * 100)
    (outdir / "metadata.json").write_text("{}")

    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_FakeListener(socket.socketpair()[0]))

    real_open, real_fsync = _os.open, _os.fsync
    fsynced_dir = {"hit": False}
    sync_called = {"hit": False}

    def fake_fsync(fd):
        # Raise on the FIRST file fsync to simulate a transient error mid-loop.
        if not fake_fsync.first and not fsynced_dir["hit"]:
            fake_fsync.first = True
            raise OSError("simulated transient fsync failure")
        return real_fsync(fd)

    fake_fsync.first = False

    # Detect the directory fsync: the dir fd is the one opened on outdir itself.
    dir_fd_holder = {}

    def fake_open(path, flags, *a, **k):
        fd = real_open(path, flags, *a, **k)
        if _os.path.realpath(path) == _os.path.realpath(outdir):
            dir_fd_holder["fd"] = fd
        return fd

    def fsync_wrapper(fd):
        if dir_fd_holder.get("fd") == fd:
            fsynced_dir["hit"] = True
        return fake_fsync(fd)

    monkeypatch.setattr(fc_warm.os, "open", fake_open)
    monkeypatch.setattr(fc_warm.os, "fsync", fsync_wrapper)
    monkeypatch.setattr(fc_warm.os, "sync", lambda: sync_called.__setitem__("hit", True))

    guest._fsync_output()  # must not raise; must reach dir-fsync + os.sync()

    assert fsynced_dir["hit"], "directory fsync was skipped after a per-file fsync error"
    assert sync_called["hit"], "os.sync() global flush was not reached"


# ---------------------------------------------------------------------------
# Start-ack: the real guest, not a stand-in
# ---------------------------------------------------------------------------


def test_the_guest_acks_before_it_starts_work_when_asked(tmp_path):
    """The host asks with `"ack": true`; the guest must answer BEFORE detonating.

    That frame is the only thing separating "this slot never executed anything" (a wedged warm
    base) from "it started and hung on this document" -- the phase timer records `guest` only
    once the work COMPLETES, so both otherwise look like a timeout with no guest phase.
    """
    from blastbox.worker.fc_guest import WARM_ACK

    host_end, guest_end = socket.socketpair()
    src = tmp_path / "doc.bin"
    src.write_bytes(b"payload")
    host = VsockHostWarmControl(tmp_path / "vsock.sock", connect_fn=lambda: host_end)
    outdir = tmp_path / "out"
    outdir.mkdir()
    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_FakeListener(guest_end))

    host.signal_go(WarmJobSpec(input_path=src, output_dir=tmp_path / "ho", params={}))
    guest.wait_for_go(timeout_s=5.0)          # the REAL guest: it should ack in here
    guest.signal_done(status="ok")

    assert host.wait_for_done(timeout_s=5.0) == "ok", "the status must still arrive after the ack"
    assert host.guest_started is True, "the guest confirmed it had the job before starting"
    assert WARM_ACK                            # the sentinel is shared, not duplicated


def test_the_guest_stays_silent_when_the_host_does_not_ask(tmp_path):
    """An OLDER host sends no `ack` key. A guest that volunteered the frame anyway would hand
    that host something it would read as the status -- so the ack must be strictly on request."""
    host_end, guest_end = socket.socketpair()
    outdir = tmp_path / "out"
    outdir.mkdir()
    guest = VsockWarmControl(tmp_path / "in", outdir, listener=_FakeListener(guest_end))

    # An old host's header: no "ack" key at all.
    header = json.dumps({"filename": "doc.bin", "params": {}}).encode()
    _send(host_end, header)
    _send(host_end, b"payload")
    guest.wait_for_go(timeout_s=5.0)
    guest.signal_done(status="ok")

    # The FIRST frame the old host reads must be the status, not an ack.
    assert _recv(host_end) == b"ok"


def _send(sock, payload: bytes) -> None:
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def _recv(sock) -> bytes:
    (n,) = struct.unpack(">Q", _recv_n(sock, 8))
    return _recv_n(sock, n)


def _recv_n(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf
