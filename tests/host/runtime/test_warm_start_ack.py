"""The guest's START frame: the only thing that separates a wedged warm base from a document
that hangs a healthy one.

`phases.mark("guest")` lands only after the work COMPLETES, so from the host both look identical
-- a timeout with no guest phase. Convicting a base on that inference would destroy a healthy
artifact over three bad documents, which is worse than the wedge it repairs. So the guest says so
itself, before it starts work.

Backward compatibility is the design constraint, in BOTH directions: host and worker images are
upgraded separately here, and the FC vsock protocol has deliberately stayed byte-identical across
releases. The ack is therefore opt-in from the host (`"ack": true` in the job header) and sent
only on request.
"""
import json
import socket
import struct
import threading
from pathlib import Path

import pytest

from blastbox.host.runtime.firecracker import VsockHostWarmControl
from blastbox.worker.fc_guest import WARM_ACK


def _read_frame(sock):
    (n,) = struct.unpack(">Q", _recv_exactly(sock, 8))
    return _recv_exactly(sock, n)


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _send_frame(sock, payload: bytes):
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def _control(host_sock, *, ack_capable=None):
    return VsockHostWarmControl(Path("/unused"), connect_fn=lambda: host_sock,
                                ack_capable=ack_capable)


def _guest(guest_sock, *, behaviour):
    """A guest that reads the header, then behaves as told."""
    def run():
        header = json.loads(_read_frame(guest_sock).decode())
        _read_frame(guest_sock)                             # the input body
        if behaviour == "acks_then_done":
            if header.get("ack"):
                _send_frame(guest_sock, WARM_ACK.encode())
            _send_frame(guest_sock, "ok".encode())
        elif behaviour == "acks_then_hangs":
            if header.get("ack"):
                _send_frame(guest_sock, WARM_ACK.encode())
            # ...and never sends a status: hung ON the document
        elif behaviour == "old_worker":
            _send_frame(guest_sock, "ok".encode())          # ignores `ack` entirely
        elif behaviour == "wedged":
            pass                                            # never woke up
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def _run(behaviour, *, ack_capable=None):
    host_sock, guest_sock = socket.socketpair()
    ctl = _control(host_sock, ack_capable=ack_capable)
    _guest(guest_sock, behaviour=behaviour)
    from blastbox.worker.warm import WarmJobSpec
    tmp = Path("/tmp/blastbox-ack-test-input")
    tmp.write_bytes(b"x")
    ctl.signal_go(WarmJobSpec(input_path=tmp, output_dir=Path("/tmp"), params={}))
    try:
        status = ctl.wait_for_done(timeout_s=1.5)
    except Exception:
        status = None
    return ctl, status


def test_a_guest_that_starts_and_finishes_reports_started():
    ctl, status = _run("acks_then_done")
    assert status == "ok"
    assert ctl.guest_started is True


def test_a_guest_that_starts_and_then_HANGS_is_not_blamed_on_the_base():
    """The exact case the inference got wrong. It ran; the document is the suspect, not the base."""
    ctl, status = _run("acks_then_hangs")
    assert status is None                      # timed out
    assert ctl.guest_started is True, "it acked before hanging — the base produced a usable worker"


def test_a_wedged_guest_reports_not_started_once_the_image_is_known_to_ack():
    seen = {"yes"}                             # this image has acked before
    ctl, status = _run("wedged", ack_capable=seen)
    assert status is None
    assert ctl.guest_started is False, "no ack from an ack-capable image means it never ran"


def test_an_older_worker_stays_UNKNOWN_rather_than_being_blamed():
    """An old image never sends an ack. Absence of evidence is not evidence of absence, and
    reading it as 'never started' would convict a base for running an older worker."""
    ctl, status = _run("old_worker")
    assert status == "ok"
    assert ctl.guest_started is None


def test_a_wedged_guest_on_an_UNPROVEN_image_stays_unknown():
    """Before any ack has ever been seen, a missing one means nothing."""
    ctl, status = _run("wedged")               # no ack_capable memory
    assert status is None
    assert ctl.guest_started is None


def test_the_header_asks_for_the_ack():
    host_sock, guest_sock = socket.socketpair()
    ctl = _control(host_sock)
    from blastbox.worker.warm import WarmJobSpec
    tmp = Path("/tmp/blastbox-ack-test-input2")
    tmp.write_bytes(b"x")
    ctl.signal_go(WarmJobSpec(input_path=tmp, output_dir=Path("/tmp"), params={}))
    header = json.loads(_read_frame(guest_sock).decode())
    assert header.get("ack") is True


@pytest.mark.parametrize("behaviour,expect", [
    ("acks_then_done", True), ("acks_then_hangs", True), ("old_worker", None),
])
def test_capability_memory_is_learned_from_any_slot(behaviour, expect):
    seen: set[str] = set()
    ctl, _ = _run(behaviour, ack_capable=seen)
    assert ctl.guest_started is expect
    assert bool(seen) is (expect is True), "an ack must teach the runtime the image is capable"


def test_the_snapshot_runtime_shares_ack_capability_across_slots(tmp_path):
    """BLASTBOX_POOL_WARM_SNAPSHOT=1 selects SnapshotSlotRuntime, which is what the production
    wedge was observed on. Building each control with its own set means an ack is learned by a
    disposable object and forgotten, guest_started stays None forever, and the fast path can
    never arm -- inert in exactly the configuration it was written for.
    """
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    rt = object.__new__(SnapshotSlotRuntime)          # no VM setup needed for this seam
    rt._ack_capable = set()
    slot_a = type("S", (), {"output_dir": tmp_path / "a" / "out"})()
    slot_b = type("S", (), {"output_dir": tmp_path / "b" / "out"})()

    ctl_a = SnapshotSlotRuntime.host_warm_control(rt, slot_a)
    ctl_b = SnapshotSlotRuntime.host_warm_control(rt, slot_b)
    assert ctl_a._ack_capable is ctl_b._ack_capable, "capability must be shared, not per-control"

    ctl_a._ack_capable.add("yes")                     # slot A acks once
    assert ctl_b._ack_capable, "slot B must inherit what slot A proved about the image"
