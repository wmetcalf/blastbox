"""The file-protocol twin of the vsock start ack, for the gVisor warm tier.

`done` arriving late is indistinguishable from a guest that never woke up, so without this the
gVisor tier -- one of the two that wedged in production -- still needs 2 x warm_size real jobs at
the full worker timeout to discover a poisoned base. Unlike the vsock ack there is no ordering
hazard: an old host simply never looks at the file, and an old worker simply never writes it.
"""

from blastbox.worker.warm import (
    WARM_STARTED,
    FileWarmControl,
    HostWarmControl,
    WarmJobSpec,
)


def _dirs(tmp_path):
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    ind = tmp_path / "in"
    ind.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    src = ind / "doc.bin"
    src.write_bytes(b"x")
    return ctrl, src, out


def test_the_worker_marks_the_job_before_it_starts(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    assert not (ctrl / WARM_STARTED).exists(), "nothing has picked the job up yet"

    FileWarmControl(ctrl).wait_for_go(timeout_s=2.0)
    assert (ctrl / WARM_STARTED).exists(), "the worker must mark that it has the job"


def test_the_host_reads_the_marker_and_reports_started(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    seen = {"yes"}                                   # image known to mark
    host = HostWarmControl(ctrl, ack_capable=seen)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    guest = FileWarmControl(ctrl)
    guest.wait_for_go(timeout_s=2.0)
    guest.signal_done(status="ok")

    assert host.wait_for_done(timeout_s=2.0) == "ok"
    assert host.guest_started is True


def test_a_wedged_worker_reports_not_started(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl, ack_capable={"yes"})
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)            # nothing ever picks it up
    except Exception:
        pass
    assert host.guest_started is False


def test_an_older_worker_stays_unknown(tmp_path):
    """No marker has ever been seen from this image, so a missing one means "old worker", not
    "wedged" -- and must convict nothing."""
    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl)                     # no capability memory
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)
    except Exception:
        pass
    assert host.guest_started is None


def test_capability_is_learned_and_shared(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    seen: set[str] = set()
    host = HostWarmControl(ctrl, ack_capable=seen)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    guest = FileWarmControl(ctrl)
    guest.wait_for_go(timeout_s=2.0)
    guest.signal_done(status="ok")
    host.wait_for_done(timeout_s=2.0)
    assert seen, "one marker must teach the runtime that this image marks starts"


def test_the_gvisor_wrapper_forwards_the_signal(tmp_path):
    """The dispatcher reads guest_started off whatever host_warm_control returned. A wrapper that
    swallows it leaves the entire start signal invisible for this tier."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorHostWarmControl

    ctrl, _src, _out = _dirs(tmp_path)
    seen = {"yes"}
    w = GvisorHostWarmControl(ctrl, ack_capable=seen)
    assert w.guest_started is None
    w._inner.guest_started = True
    assert w.guest_started is True, "the wrapper must forward the wrapped control's state"


def test_the_gvisor_runtime_shares_capability_across_slots(tmp_path):
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    rt = object.__new__(GvisorSnapshotSlotRuntime)
    rt._ack_capable = set()
    a = type("S", (), {"control_dir": tmp_path / "a"})()
    b = type("S", (), {"control_dir": tmp_path / "b"})()
    ca = GvisorSnapshotSlotRuntime.host_warm_control(rt, a)
    cb = GvisorSnapshotSlotRuntime.host_warm_control(rt, b)
    assert ca._inner._ack_capable is cb._inner._ack_capable


def test_a_worker_that_cannot_mark_its_start_refuses_the_job(tmp_path, monkeypatch):
    """The same rule as the vsock ack, which this reintroduced by copying its first, wrong
    comment: once the image is known to mark starts the host initialises to "not started", so a
    swallowed write failure means the worker runs while the host records False -- and three
    filesystem hiccups on distinct slots convict a base whose workers all ran."""
    import pytest

    from blastbox.errors import WarmTimeout

    ctrl, src, out = _dirs(tmp_path)
    HostWarmControl(ctrl).signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))

    guest = FileWarmControl(ctrl)
    def _boom(name, content):
        if name == WARM_STARTED:
            raise OSError("no space left on device")
    monkeypatch.setattr(guest, "_atomic_write", _boom)

    with pytest.raises(WarmTimeout, match="mark job start"):
        guest.wait_for_go(timeout_s=2.0)


def test_capability_is_learned_from_readiness_not_from_a_completed_job(tmp_path):
    """BOOTSTRAP. A base wedged from its very first slot never completes a job, so learning
    capability only from a written marker left it permanently UNKNOWN -- inert on exactly the
    poisoned-from-the-outset base this repairs, which is what a dispatcher restarting onto a bad
    artifact produces. `ready` is written when the slot WARMS, which a wedged base still does."""
    ctrl, src, out = _dirs(tmp_path)
    FileWarmControl(ctrl).signal_ready()          # the slot warms...
    host = HostWarmControl(ctrl)                  # ...with NO prior capability memory
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)         # ...and then never executes anything
    except Exception:
        pass
    assert host.guest_started is False, (
        "readiness advertised the capability, so a missing marker is the guest, not an old image")


def test_an_older_image_that_advertises_nothing_stays_unknown(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    (ctrl / "ready").write_text("ready\n")        # old worker: no advertisement
    host = HostWarmControl(ctrl)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)
    except Exception:
        pass
    assert host.guest_started is None


def test_a_hostile_ready_file_cannot_block_or_exhaust_the_dispatcher(tmp_path):
    """ctrl/ is WORKER-WRITABLE on the gVisor tier, so `ready` is attacker-controlled. A plain
    read follows a symlink or FIFO and has no size cap -- and it runs BEFORE the timeout loop, so
    it could pin the dispatcher outside timeout_s entirely. `done` has been read through the
    confined helper since PR #82; this read must be too."""
    import os

    ctrl, src, out = _dirs(tmp_path)
    outside = tmp_path / "secret"
    outside.write_text("ack=1\n")
    os.symlink(outside, ctrl / "ready")            # symlink out of the confined dir

    host = HostWarmControl(ctrl)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)
    except Exception:
        pass
    assert host.guest_started is None, (
        "a symlinked `ready` must not be followed, and must not teach capability")


def test_an_oversized_ready_file_is_refused(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    (ctrl / "ready").write_bytes(b"ack=1\n" + b"x" * 100_000)
    host = HostWarmControl(ctrl)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    try:
        host.wait_for_done(timeout_s=0.3)
    except Exception:
        pass
    assert host.guest_started is None, "an oversized ready must be refused, not read"


def test_the_gvisor_base_build_records_ack_capability(tmp_path):
    """The ONLY chance on this tier. A restore gets a fresh ctrl/ and the checkpointed worker
    resumes past its one-time signal_ready(), so `ready` is never written again -- and a base
    wedged from its first restore never completes a job either. Read it while the base is still
    the live container that wrote it."""
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    FileWarmControl(ctrl).signal_ready()               # the base advertises

    seen: set[str] = set()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None                     # readiness already satisfied
    h._ack_capable = seen
    GvisorBootHandle.wait_ready(h, 1.0)
    assert seen, "the base's advertisement must be recorded at build time"


def test_an_older_gvisor_base_teaches_nothing(tmp_path):
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    (ctrl / "ready").write_text("ready\n")             # old image: no advertisement

    seen: set[str] = set()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None
    h._ack_capable = seen
    GvisorBootHandle.wait_ready(h, 1.0)
    assert not seen, "no advertisement means UNKNOWN, which must convict nothing"
