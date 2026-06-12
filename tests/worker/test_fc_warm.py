"""Tests for the vsock job round-trip: VsockHostWarmControl <-> VsockWarmControl.

AF_VSOCK needs a microVM, so the transport is an AF_UNIX socketpair (the framing
is transport-agnostic) and the host's FC CONNECT handshake is exercised against a
tiny local AF_UNIX server that plays firecracker's role.
"""
from __future__ import annotations

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
