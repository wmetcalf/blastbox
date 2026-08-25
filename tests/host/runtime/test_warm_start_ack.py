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


def test_an_input_the_guest_refuses_is_not_blamed_on_the_base(tmp_path):
    """A guest correctly REJECTING a frame larger than its own MAX_INPUT_BYTES closes the
    connection, and the broken pipe looked identical to a wedge -- so three oversized documents
    would rebuild a healthy base. The evidence must not begin until the bytes are demonstrably
    delivered."""
    from blastbox.worker.warm import WarmJobSpec

    host_sock, guest_sock = socket.socketpair()
    seen = {"yes"}                                  # this image HAS acked before
    ctl = _control(host_sock, ack_capable=seen)
    guest_sock.close()                              # the guest refuses/closes mid-transfer

    big = Path("/tmp/blastbox-ack-test-big")
    big.write_bytes(b"x" * (1 << 20))
    with pytest.raises(Exception):
        ctl.signal_go(WarmJobSpec(input_path=big, output_dir=Path("/tmp"), params={}))
    assert ctl.guest_started is None, (
        "a transfer that never landed says nothing about whether the guest can execute")


def test_a_transfer_that_eats_the_deadline_is_not_blamed_on_the_base(tmp_path):
    """A large but SUCCESSFUL upload can consume the whole dispatch deadline, after which the
    caller returns without ever calling wait_for_done -- so an ack the healthy guest already sent
    is never read. Claiming "never started" there convicts a base for a slow document."""
    from blastbox.worker.warm import WarmJobSpec

    host_sock, guest_sock = socket.socketpair()
    seen = {"yes"}                                  # image is known to ack
    ctl = _control(host_sock, ack_capable=seen)
    big = Path("/tmp/blastbox-ack-deadline-input")
    big.write_bytes(b"x" * 4096)

    # transfer succeeds; the caller then gives up before waiting (remaining <= 0)
    ctl.signal_go(WarmJobSpec(input_path=big, output_dir=Path("/tmp"), params={}))
    assert ctl.guest_started is None, (
        "the host never listened for the ack, so it cannot claim the guest never started")


def test_the_state_is_claimed_only_once_the_host_listens(tmp_path):
    """The whole rule in one line: signal_go never decides; wait_for_done does."""
    ctl, status = _run("wedged", ack_capable={"yes"})
    assert status is None and ctl.guest_started is False


def test_the_ready_token_advertises_ack_capability_and_stays_old_host_safe():
    """BOOTSTRAP for the vsock path. Capability learned only from a completed ack leaves a base
    wedged from its first slot permanently UNKNOWN. The host's readiness check is a SUBSTRING test
    (`READY_TOKEN in data`), so appending a suffix teaches a new host at readiness while an older
    one still matches a plain READY."""
    from blastbox.host.runtime.firecracker import _READY_TOKEN
    from blastbox.worker.fc_guest import READY_ACK_SUFFIX, READY_TOKEN

    advertised = READY_TOKEN + READY_ACK_SUFFIX
    assert _READY_TOKEN in advertised, "an older host must still recognise this as READY"
    assert READY_ACK_SUFFIX in advertised
    assert _READY_TOKEN not in READY_ACK_SUFFIX, "the suffix must not itself look like READY"


def test_snapshot_mode_learns_capability_from_the_BASE_build():
    """In snapshot mode restored guests never re-signal readiness -- is_ready() relies on restore
    liveness alone -- so the base build is the only place the advertisement is ever visible. And
    the base VM IS the image the slots run: every slot is a restore of that guest. Without this
    the set stays empty on a base wedged from its first restore, and the repair is inert on
    exactly the base it exists to fix."""
    import inspect

    from blastbox.host.runtime import fc_snapshot_runtime as m

    src = inspect.getsource(m.select_fc_snapshot_runtime) \
        if hasattr(m, "select_fc_snapshot_runtime") else inspect.getsource(m)
    assert "ack_capable=ack_capable" in src, (
        "the base-build listener and the restore runtime must share one capability set")

    # the factory really does forward it
    sig = inspect.signature(m._vsock_ready_check_factory)
    assert "ack_capable" in sig.parameters


def test_the_snapshot_runtime_accepts_a_shared_capability_set():
    import inspect

    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    assert "ack_capable" in inspect.signature(SnapshotSlotRuntime.__init__).parameters
    rt = object.__new__(SnapshotSlotRuntime)
    shared: set[str] = set()
    rt._ack_capable = shared
    a = type("S", (), {"output_dir": Path("/tmp/a/out")})()
    ctl = SnapshotSlotRuntime.host_warm_control(rt, a)
    shared.add("yes")                      # learned at base build...
    assert ctl._ack_capable, "...and visible to a control handed out before that"


def test_a_split_readiness_advertisement_is_not_lost():
    """SOCK_STREAM: one sendall() of READY+ack1 can arrive as READY then +ack1. Deciding on the
    first recv() accepted readiness and closed the connection, permanently losing the
    advertisement -- and in snapshot mode this listener is the ONLY place it is ever visible, so
    a base wedged from its first restore would fall back to the ordinary large threshold."""
    import socket as _socket
    import threading
    import time as _t

    from blastbox.host.runtime.firecracker import VsockReadySignal, _VsockReadyState
    from blastbox.worker.fc_guest import READY_ACK_SUFFIX, READY_TOKEN

    seen: set[str] = set()
    sig = VsockReadySignal(ack_capable=seen)
    srv_path = Path("/tmp") / f"bb-ready-{_t.time_ns()}.sock"
    srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    srv.bind(str(srv_path))
    srv.listen(4)
    srv.setblocking(False)

    st = _VsockReadyState.__new__(_VsockReadyState)
    st.srv = srv
    st.ready = threading.Event()
    st.stop = threading.Event() if hasattr(_VsockReadyState, "stop") else threading.Event()

    t = threading.Thread(target=sig._accept_loop, args=("slot-1", st), daemon=True)
    t.start()
    try:
        c = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        c.connect(str(srv_path))
        c.sendall(READY_TOKEN)                 # ...deliberately split
        _t.sleep(0.2)
        c.sendall(READY_ACK_SUFFIX)
        c.close()
        assert st.ready.wait(5.0), "readiness must still be recognised across the split"
        assert seen, "a split advertisement must still teach the capability"
    finally:
        st.ready.set()
        t.join(timeout=3.0)
        srv.close()
        srv_path.unlink(missing_ok=True)
