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
from blastbox.worker.warm import AckCapability
import json
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from blastbox.host.runtime.firecracker import VsockHostWarmControl, VsockReadySignal
from blastbox.worker.fc_guest import WARM_ACK


def _capable():
    """An AckCapability that has already been taught — the "this image advertises" fixture."""
    c = AckCapability()
    c.learn()
    return c



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
    seen = _capable()                             # this image has acked before
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
    seen = AckCapability()
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
    rt._ack_capable = AckCapability()
    slot_a = type("S", (), {"output_dir": tmp_path / "a" / "out"})()
    slot_b = type("S", (), {"output_dir": tmp_path / "b" / "out"})()

    ctl_a = SnapshotSlotRuntime.host_warm_control(rt, slot_a)
    ctl_b = SnapshotSlotRuntime.host_warm_control(rt, slot_b)
    assert ctl_a._ack_capable is ctl_b._ack_capable, "capability must be shared, not per-control"

    ctl_a._ack_capable.learn()                     # slot A acks once
    assert ctl_b._ack_capable, "slot B must inherit what slot A proved about the image"


def test_an_input_the_guest_refuses_is_not_blamed_on_the_base(tmp_path):
    """A guest correctly REJECTING a frame larger than its own MAX_INPUT_BYTES closes the
    connection, and the broken pipe looked identical to a wedge -- so three oversized documents
    would rebuild a healthy base. The evidence must not begin until the bytes are demonstrably
    delivered."""
    from blastbox.worker.warm import WarmJobSpec

    host_sock, guest_sock = socket.socketpair()
    seen = _capable()                                  # this image HAS acked before
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
    seen = _capable()                                  # image is known to ack
    ctl = _control(host_sock, ack_capable=seen)
    big = Path("/tmp/blastbox-ack-deadline-input")
    big.write_bytes(b"x" * 4096)

    # transfer succeeds; the caller then gives up before waiting (remaining <= 0)
    ctl.signal_go(WarmJobSpec(input_path=big, output_dir=Path("/tmp"), params={}))
    assert ctl.guest_started is None, (
        "the host never listened for the ack, so it cannot claim the guest never started")


def test_the_state_is_claimed_only_once_the_host_listens(tmp_path):
    """The whole rule in one line: signal_go never decides; wait_for_done does."""
    ctl, status = _run("wedged", ack_capable=_capable())
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
    shared = AckCapability()
    rt._ack_capable = shared
    a = type("S", (), {"output_dir": Path("/tmp/a/out")})()
    ctl = SnapshotSlotRuntime.host_warm_control(rt, a)
    shared.learn()                      # learned at base build...
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

    seen = AckCapability()
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


def test_a_host_resource_error_leaves_the_verdict_unknown(tmp_path):
    """ENOMEM/EMFILE on OUR side of the socket says nothing about the guest -- but guest_started
    is already False by then, so without attribution the host's own resource exhaustion is
    charged to the worker and three concurrent ones invalidate a healthy base."""
    import errno
    import socket

    from blastbox.errors import WarmTimeout
    from blastbox.worker.warm import WarmJobSpec

    host_sock, guest_sock = socket.socketpair()
    ctl = _control(host_sock, ack_capable=_capable())
    tmp = Path("/tmp/blastbox-hostres-input")
    tmp.write_bytes(b"x")
    ctl.signal_go(WarmJobSpec(input_path=tmp, output_dir=Path("/tmp"), params={}))

    class _Boom:
        def recv(self, *a, **k):
            raise OSError(errno.ENOMEM, "Cannot allocate memory")
        def close(self): pass
        def settimeout(self, *a): pass
    ctl._conn = _Boom()

    with pytest.raises(WarmTimeout) as ei:
        ctl.wait_for_done(timeout_s=1.0)
    assert getattr(ei.value, "host_io", False) is True
    assert ctl.guest_started is None, "we never heard from the guest, so the answer is UNKNOWN"
    guest_sock.close()


def test_capability_learn_and_reset_are_mutually_exclusive():
    """The compare and the mutation are one decision. Unsynchronised, a slot could pass the
    generation check, have invalidate_base() bump it underneath, and set capable=True anyway --
    re-enabling capability for a replacement that never advertised it.

    Asserted on the exclusion itself rather than by racing threads: the window is a few
    instructions wide and a probabilistic test for it reports "passed" almost every time it is
    actually broken.
    """
    import threading

    from blastbox.worker.warm import AckCapability

    cap = AckCapability()
    entered = threading.Event()
    finished = threading.Event()

    def _learn():
        entered.set()
        cap.learn()
        finished.set()

    with cap._lock:                      # hold it: nothing may mutate while we do
        t = threading.Thread(target=_learn, daemon=True)
        t.start()
        assert entered.wait(2.0)
        assert not finished.wait(0.3), (
            "learn() ran while the capability was locked — the check and the set are not atomic")

    assert finished.wait(2.0), "learn() must proceed once the lock is released"
    assert bool(cap) is True


def test_snapshot_mode_capability_is_epoch_scoped_end_to_end(tmp_path):
    """EVERY other capability assertion in this file uses learn() with no epoch and bare
    truthiness, so after the #92 refactor they all exercise only the plain, no-artifact path --
    this file has zero publish() calls. Proof: hardcoding snapshot-mode capable_for() to
    `return False` left all 19 of them green. So the tests named for snapshot behaviour stopped
    covering it, and this one restores that coverage."""
    from blastbox.worker.warm import AckCapability, HostWarmControl

    cap = AckCapability(artifact_scoped=True)
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()

    # Nothing published yet: a control cannot be judged, whatever it acks.
    early = HostWarmControl(ctrl, ack_capable=cap, ack_generation=0)
    cap.learn(early._ack_gen)
    assert cap.capable_for(0) is False, "capability before any artifact must be UNKNOWN"

    # The base build advertises and its artifact is installed.
    cap.observe(0)
    cap.publish(0)
    assert cap.capable_for(0) is True

    # A slot from the RETIRED artifact is not judged by the current one, and vice versa.
    cap.publish(1)                                  # a silent replacement
    assert cap.capable_for(1) is False, "a silent replacement must not inherit"
    assert cap.capable_for(0) is False, "a retired epoch is no longer the published one"


def _drive_ready(sig, tmp_path, *, ack_generation: int) -> None:
    """Send one READY+ack over a real socket, through the PUBLIC prepare() path.

    Driving `_accept_loop` directly would skip the handoff that carries the
    caller-sampled generation into the accept thread's arguments (codex): with
    the loop invoked by hand, `prepare()` could stop forwarding `ack_generation`
    and every test here would still pass -- the listener would then `observe(None)`
    and the later `publish(actual_epoch)` could not confirm the advertisement,
    silently disabling capability detection. So prepare() binds the socket and
    starts the thread, exactly as a launch does.
    """
    import socket as _socket

    from blastbox.host.pool import Slot, SlotState
    from blastbox.host.runtime.firecracker import _READY_PORT
    from blastbox.worker.fc_guest import READY_ACK_SUFFIX, READY_TOKEN

    slot_dir = tmp_path / "s"
    (slot_dir / "out").mkdir(parents=True, exist_ok=True)
    slot = Slot(slot_id="ack-slot", control_dir=slot_dir / "ctrl",
                input_dir=slot_dir / "in", output_dir=slot_dir / "out",
                state=SlotState.WARMING)

    sig.prepare(slot, ack_generation=ack_generation)
    try:
        uds = slot.output_dir.parent / f"vsock.sock_{_READY_PORT}"
        # prepare() only LOGS a failed bind and returns, so without this the test
        # would hang on a 108-byte path overrun and read as a product defect.
        assert uds.exists(), f"prepare() never bound the readiness listener at {uds}"
        c = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        c.connect(str(uds))
        c.sendall(READY_TOKEN + READY_ACK_SUFFIX)
        c.close()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not sig.is_ready(slot):
            time.sleep(0.01)
        assert sig.is_ready(slot), "readiness was never recognised"
    finally:
        sig.cleanup(slot)


def test_a_base_build_advertisement_is_not_believed_until_it_publishes(tmp_path):
    """`defer_ack=True` must OBSERVE, not LEARN.

    A base build's advertisement is only meaningful once the build produced a
    usable artifact: `observe` parks it, `publish` confirms it, and a build that
    never publishes leaves it disbelieved. `learn` would believe it -- arming the
    fast repair from an artifact that may never exist.

    fc_snapshot_runtime.py passes `defer_ack=True` for exactly this, and nothing
    tested the wiring: forcing `self._defer_ack = False` left tests/host green.

    ARTIFACT-SCOPED, matching fc_snapshot_runtime.py:536, because the scoping
    changes what the defect looks like (codex). Unscoped, a wrong `learn(7)` sets
    the flag at once and the first assertion catches it; scoped, `learn(7)` finds
    no published epoch to match, records nothing, and the miss only surfaces at
    `publish(7)` -- which then has an empty `_pending` and clears the flag. Both
    assertions are load-bearing here, and only in the production configuration
    does the second one describe the real failure.
    """
    seen = AckCapability(artifact_scoped=True)
    seen.begin_build()
    sig = VsockReadySignal(ack_capable=seen, defer_ack=True)

    _drive_ready(sig, tmp_path, ack_generation=7)

    assert not seen.capable_for(7), (
        "a base build's advertisement was believed before it published"
    )
    seen.publish(7)
    assert seen.capable_for(7), (
        "publishing the build must confirm the observed advertisement"
    )


def test_a_per_slot_advertisement_is_believed_immediately(tmp_path):
    """The control: a live slot's READY is about an artifact that ALREADY
    published, so it LEARNS. Without this, "always observe" would pass the test
    above.

    The publish() is the lifecycle, not setup noise -- a per-slot listener only
    ever runs against a published artifact, and under artifact scoping an ack
    naming an epoch that was never published teaches nothing at all.
    """
    seen = AckCapability(artifact_scoped=True)
    seen.publish(7)
    assert not seen.capable_for(7), "the artifact published without advertising"

    sig = VsockReadySignal(ack_capable=seen, defer_ack=False)

    _drive_ready(sig, tmp_path, ack_generation=7)

    assert seen.capable_for(7), "a per-slot advertisement must be believed at once"


def test_the_snapshot_factory_defers_the_base_builds_ack(tmp_path, monkeypatch):
    """The production wiring, not just the class branch.

    The two tests above prove VsockReadySignal honours `defer_ack`; they say
    nothing about `_vsock_ready_check_factory` still passing it. Measured: dropping
    `defer_ack=True` from fc_snapshot_runtime.py leaves the whole tests/host suite
    green, so a base-build listener could silently revert to the immediate `learn()`
    (codex).

    The recorder is installed on `firecracker.VsockReadySignal`, NOT on
    `fc_snapshot_runtime`: the factory does a function-local
    `from ... import VsockReadySignal`, so that is the name it resolves at call
    time. Patching the importing module's namespace binds nothing -- checked, and
    the test then fails with an empty `captured`, which is how it should behave.
    """
    import blastbox.host.runtime.firecracker as fc
    from blastbox.host.runtime.fc_snapshot_runtime import _vsock_ready_check_factory

    captured: dict = {}

    class _Recorder:
        def __init__(self, **kw):
            captured.update(kw)

        def prepare(self, slot, ack_generation=None):
            captured["prepared_generation"] = ack_generation

    monkeypatch.setattr(fc, "VsockReadySignal", _Recorder)

    shared = AckCapability(artifact_scoped=True)
    _vsock_ready_check_factory(tmp_path / "vsock.sock",
                               ack_capable=shared, ack_generation=9)

    assert captured.get("defer_ack") is True, (
        f"the base-build listener was built without defer_ack: {captured}"
    )
    # IDENTITY, not truthiness (codex): a factory that built its own AckCapability
    # would satisfy `is not None` while readiness observations landed in an object
    # SnapshotManager.publish() never updates, leaving every restored slot's shared
    # capability unset.
    assert captured.get("ack_capable") is shared, (
        f"the shared capability object was not forwarded: {captured.get('ack_capable')!r}"
    )
    assert captured.get("prepared_generation") == 9, (
        "the generation sampled before the spawn must be the one bound"
    )
