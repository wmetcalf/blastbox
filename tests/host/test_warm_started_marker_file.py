"""The file-protocol twin of the vsock start ack, for the gVisor warm tier.

`done` arriving late is indistinguishable from a guest that never woke up, so without this the
gVisor tier -- one of the two that wedged in production -- still needs 2 x warm_size real jobs at
the full worker timeout to discover a poisoned base. Unlike the vsock ack there is no ordering
hazard: an old host simply never looks at the file, and an old worker simply never writes it.
"""

from blastbox.worker.warm import AckCapability
import json

from blastbox.worker.warm import (
    WARM_STARTED,
    FileWarmControl,
    HostWarmControl,
    WarmJobSpec,
)


def _capable():
    """An AckCapability that has already been taught — the "this image advertises" fixture."""
    c = AckCapability()
    c.learn()
    return c



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
    seen = _capable()                                   # image known to mark
    host = HostWarmControl(ctrl, ack_capable=seen)
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    guest = FileWarmControl(ctrl)
    guest.wait_for_go(timeout_s=2.0)
    guest.signal_done(status="ok")

    assert host.wait_for_done(timeout_s=2.0) == "ok"
    assert host.guest_started is True


def test_a_wedged_worker_reports_not_started(tmp_path):
    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl, ack_capable=_capable())
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
    seen = AckCapability()
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
    seen = _capable()
    w = GvisorHostWarmControl(ctrl, ack_capable=seen)
    assert w.guest_started is None
    w._inner.guest_started = True
    assert w.guest_started is True, "the wrapper must forward the wrapped control's state"


def test_the_gvisor_runtime_shares_capability_across_slots(tmp_path):
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    rt = object.__new__(GvisorSnapshotSlotRuntime)
    rt._ack_capable = AckCapability()
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

    seen = AckCapability()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None                     # readiness already satisfied
    h._ack_capable = seen
    h._ack_gen = seen.generation          # the generation this build started under
    GvisorBootHandle.wait_ready(h, 1.0)
    assert not seen, (
        "readiness must only OBSERVE: checkpoint() has not run, so there is no artifact yet and "
        "no base a slot could be restored from")
    seen.confirm(h._ack_gen)                           # ...the build then checkpoints
    assert seen, "the base's advertisement must be believed once its artifact exists"


def test_a_gvisor_build_that_never_checkpoints_teaches_nothing(tmp_path):
    """Readiness proves the guest speaks the protocol; it does not prove the pool will ever run a
    slot from it. A base that advertises and then fails to checkpoint publishes no artifact -- but
    used to leave the capability permanently true. Roll the worker bundle back before the retry
    and the older image's missing start markers are read as PROVEN non-starts, so a
    document-induced hang invalidates an ACK-incapable base instead of staying UNKNOWN."""
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    FileWarmControl(ctrl).signal_ready()               # this base DOES advertise

    seen = AckCapability()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None
    h._ack_capable = seen
    h._ack_gen = seen.generation
    GvisorBootHandle.wait_ready(h, 1.0)                # ...and then its checkpoint fails

    assert not seen, (
        "a build that published no artifact taught the capability anyway")


def test_a_confirmation_from_a_superseded_build_is_ignored(tmp_path):
    """An invalidation during the build moves the generation and makes SnapshotManager reject the
    artifact via _build_epoch. The confirmation must be discarded on the same evidence."""
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    FileWarmControl(ctrl).signal_ready()

    seen = AckCapability()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None
    h._ack_capable = seen
    h._ack_gen = seen.generation
    GvisorBootHandle.wait_ready(h, 1.0)
    seen.reset()                                       # invalidate_base landed mid-build
    seen.confirm(h._ack_gen)                           # the doomed build checkpoints anyway

    assert not seen, "a build whose artifact was rejected still taught its replacement"


def test_an_older_gvisor_base_teaches_nothing(tmp_path):
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    (ctrl / "ready").write_text("ready\n")             # old image: no advertisement

    seen = AckCapability()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None
    h._ack_capable = seen
    h._ack_gen = seen.generation          # the generation this build started under
    GvisorBootHandle.wait_ready(h, 1.0)
    assert not seen, "no advertisement means UNKNOWN, which must convict nothing"


def test_a_host_filesystem_failure_is_not_charged_to_the_base(tmp_path):
    """ctrl/ is a bind mount. If the HOST filesystem is full, read-only or erroring, the marker
    write fails on every slot at once -- and the host has already set guest_started=False, so
    without host-I/O attribution a storage incident convicts a healthy base three slots later."""
    from blastbox.errors import WarmTimeout
    from blastbox.worker.warm import FileWarmControl

    import pytest

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    src = tmp_path / "doc.bin"
    src.write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir()
    (ctrl / "go.json").write_text(
        json.dumps({"ack": True, "input_path": str(src), "output_dir": str(out), "params": {}}))

    guest = FileWarmControl(ctrl)

    def _boom(name, content):
        raise OSError(28, "No space left on device")
    guest._atomic_write = _boom

    with pytest.raises(WarmTimeout) as ei:
        guest.wait_for_go(timeout_s=1.0)
    assert getattr(ei.value, "host_io", False) is True, (
        "a host-filesystem failure must carry host_io so it is not blamed on the worker")


def test_the_snapshot_capability_is_reset_when_the_base_is_replaced():
    """The set outlived the generation that taught it, so a rootfs rolled back to an OLDER worker
    kept the previous "yes" -- and controls then read a missing ack as proof of no start, letting
    three document hangs convict a healthy older base instead of staying UNKNOWN."""
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    rt = object.__new__(SnapshotSlotRuntime)
    rt._ack_capable = _capable()
    rt._manager = type("M", (), {"invalidate": lambda self: None})()
    try:
        SnapshotSlotRuntime.invalidate_base(rt)
    except Exception:
        pass
    assert not rt._ack_capable, (
        "a new base may be a different image; capability must be re-learned, not inherited")


def test_an_unwritable_control_dir_is_not_read_as_a_wedged_guest(tmp_path, monkeypatch):
    """Flagging the WORKER's exception is useless: serve_warm() catches it and tries to write
    `idle_timeout`, so nothing the worker knows reaches the host -- and a full or read-only ctrl/
    means it cannot tell the host anything at all, by definition. But the host shares that
    filesystem, so it asks itself: an unwritable ctrl/ silences every worker at once, and reading
    that silence as "never started" convicts a healthy base across the whole pool."""
    import pytest

    from blastbox.errors import WarmTimeout

    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl, ack_capable=_capable())     # image known to mark starts
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    monkeypatch.setattr(type(host), "_ctrl_writable", lambda self: False)

    with pytest.raises(WarmTimeout) as ei:
        host.wait_for_done(timeout_s=0.3)
    assert getattr(ei.value, "host_io", False) is True
    assert host.guest_started is None, (
        "a storage incident must leave the answer UNKNOWN, not 'the guest never started'")


def test_a_writable_control_dir_still_reports_a_wedged_guest(tmp_path):
    """The other half: with the filesystem healthy, silence really is the guest."""
    import pytest

    from blastbox.errors import WarmTimeout

    ctrl, src, out = _dirs(tmp_path)
    host = HostWarmControl(ctrl, ack_capable=_capable())
    host.signal_go(WarmJobSpec(input_path=src, output_dir=out, params={}))
    with pytest.raises(WarmTimeout):
        host.wait_for_done(timeout_s=0.3)
    assert host.guest_started is False


def test_the_gvisor_capability_is_reset_when_the_bundle_is_replaced():
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    rt = object.__new__(GvisorSnapshotSlotRuntime)
    rt._ack_capable = _capable()
    # `_mgr`, not `_manager` -- this test only passed before because the reset ran BEFORE the
    # manager was touched, so the wrong name never mattered.
    rt._mgr = type("M", (), {"invalidate": lambda self: None})()
    try:
        GvisorSnapshotSlotRuntime.invalidate_base(rt)
    except Exception:
        pass
    assert not rt._ack_capable, "a replaced bundle must re-advertise, not inherit"


def test_the_writability_probe_actually_probes(tmp_path):
    """The attribution is only as good as this. Patched out in the test above, so the probe
    itself needs its own: a read-only control dir must report unwritable."""
    import os
    import stat

    import pytest

    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions, so this cannot be exercised")

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    host = HostWarmControl(ctrl)
    assert host._ctrl_writable() is True, "a normal dir is writable"
    assert not any(ctrl.iterdir()), "the probe must not leave its temp file behind"

    ctrl.chmod(stat.S_IRUSR | stat.S_IXUSR)          # read-only
    try:
        assert host._ctrl_writable() is False, "a read-only dir must report unwritable"
    finally:
        ctrl.chmod(stat.S_IRWXU)


def test_the_probe_cannot_be_used_to_truncate_a_host_file(tmp_path):
    """ctrl/ is a 0o777 bind mount on the gVisor tier. A predictable probe name plus a plain
    write_bytes() hands the worker an arbitrary-truncation primitive: pre-plant a symlink, wait
    for any timeout, and the HOST opens the target with O_TRUNC. A health probe must not be a
    write gadget."""
    import os

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("PRECIOUS")

    # every name the probe could plausibly use, pre-planted as a symlink to the victim
    for name in (f".bb-probe-{os.getpid()}", ".bb-probe", "probe"):
        (ctrl / name).symlink_to(victim)

    host = HostWarmControl(ctrl)
    assert host._ctrl_writable() is True, "a writable dir is still writable"
    assert victim.read_text() == "PRECIOUS", "the probe must never follow a planted symlink"


def test_the_probe_leaves_nothing_behind(tmp_path):
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    host = HostWarmControl(ctrl)
    for _ in range(5):
        assert host._ctrl_writable() is True
    assert not list(ctrl.iterdir()), f"probe residue: {list(ctrl.iterdir())}"


def test_a_failed_probe_stays_failed_even_if_cleanup_also_fails(tmp_path, monkeypatch):
    """A `return` inside a finally discards the value the try block already produced. With both
    the write and the cleanup failing -- ctrl/ gone, or EIO -- the cleanup's True overrode the
    probe's False, and the host blamed the guest for a control-filesystem outage."""
    import os

    from blastbox.contract import envelope

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    host = HostWarmControl(ctrl)

    def _no_write(*a, **k):
        raise OSError(5, "I/O error")
    monkeypatch.setattr(envelope, "atomic_write_confined", _no_write)

    real_open = os.open
    def _no_open(path, *a, **k):
        if str(path) == str(ctrl):
            raise OSError(5, "I/O error")
        return real_open(path, *a, **k)
    monkeypatch.setattr(os, "open", _no_open)

    assert host._ctrl_writable() is False, (
        "a failed probe must stay failed when the cleanup fails too")


def test_a_retired_control_cannot_resurrect_a_stale_capability():
    """Clearing the set on invalidate was not enough: an old-generation slot still assigned keeps
    its control, and when its ack finally arrives that control put "yes" straight back -- so a
    replacement base built from a rolled-back worker WITHOUT the protocol inherited a capability
    it does not have, and its missing markers were then read as proof of no start."""
    cap = AckCapability()
    old_gen = cap.generation
    cap.learn(old_gen)
    assert bool(cap) is True

    cap.reset()                                   # a new base is built...
    assert bool(cap) is False, "a replaced base must re-advertise"

    cap.learn(old_gen)                            # ...and the RETIRED control's ack lands late
    assert bool(cap) is False, (
        "a late ack from a retired generation must not teach the base that replaced it")

    cap.learn(cap.generation)                     # the new base advertising still works
    assert bool(cap) is True


def test_a_control_stamps_the_generation_it_was_built_under(tmp_path):
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    cap = AckCapability()
    host = HostWarmControl(ctrl, ack_capable=cap)
    assert host._ack_gen == cap.generation
    cap.reset()
    assert host._ack_gen != cap.generation, "the control is now stale by construction"


def test_an_old_slot_claimed_after_a_reset_keeps_its_own_generation(tmp_path):
    """The stamp has to travel with the SLOT, not the job. A base invalidation leaves
    old-generation slots IDLE and claimable, so a control built at claim time took the NEW
    generation -- and that slot's ack then re-taught the replacement base a capability only the
    retired image had. If the replacement is a rolled-back worker without the protocol, its
    missing markers are read as proof of no start and three document hangs convict it."""
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    cap = AckCapability()
    old_gen = cap.generation

    cap.reset()                                   # the base is replaced while a slot is idle
    # the OLD slot is claimed afterwards and carries its own stamp
    stale_ctl = HostWarmControl(ctrl, ack_capable=cap, ack_generation=old_gen)
    assert stale_ctl._ack_gen == old_gen

    FileWarmControl(ctrl).signal_ready()          # its worker advertises, late
    (ctrl / "go.json").write_text(
        json.dumps({"ack": True, "input_path": "/", "output_dir": "/", "params": {}}))
    try:
        stale_ctl.wait_for_done(timeout_s=0.2)
    except Exception:
        pass
    assert bool(cap) is False, (
        "a slot from the retired generation must not teach the base that replaced it")


def test_a_slot_spawned_after_the_reset_does_teach_the_new_base(tmp_path):
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    cap = AckCapability()
    cap.reset()
    fresh = HostWarmControl(ctrl, ack_capable=cap, ack_generation=cap.generation)
    FileWarmControl(ctrl).signal_ready()
    (ctrl / "go.json").write_text(
        json.dumps({"ack": True, "input_path": "/", "output_dir": "/", "params": {}}))
    try:
        fresh.wait_for_done(timeout_s=0.2)
    except Exception:
        pass
    assert bool(cap) is True, "the current generation's advertisement must still count"


def test_a_retired_base_build_cannot_teach_the_replacement(tmp_path):
    """A build still waiting for readiness when invalidate_base() runs is rejected by
    SnapshotManager's build epoch -- but an UNSTAMPED learn() would still have marked the
    REPLACEMENT generation capable on the way out. An older bundle without start markers would
    then inherit a capability it does not have."""
    from blastbox.host.runtime.gvisor_snapshot import GvisorBootHandle

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    FileWarmControl(ctrl).signal_ready()

    cap = AckCapability()
    h = object.__new__(GvisorBootHandle)
    h._ctrl = ctrl
    h._ready = lambda _d, _t: None
    h._ack_capable = cap
    h._ack_gen = cap.generation           # this build started under the OLD generation
    cap.reset()                           # ...and the base was replaced while it waited

    GvisorBootHandle.wait_ready(h, 1.0)
    assert bool(cap) is False, (
        "a retired build's advertisement must not describe the base that replaced it")


def test_the_probe_allocates_a_real_data_block(tmp_path):
    """A filesystem out of DATA BLOCKS but with an inode to spare accepts a zero-byte file while
    the worker's real writes fail with ENOSPC -- so an empty probe reported the mount writable
    during the exact incident it exists to detect."""
    import blastbox.worker.warm as warm_mod

    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    written = []
    real = warm_mod.atomic_write_confined if hasattr(warm_mod, "atomic_write_confined") else None
    from blastbox.contract import envelope

    real_write = envelope.atomic_write_confined

    def _spy(base, name, data, **kw):
        written.append(data)
        return real_write(base, name, data, **kw)

    envelope.atomic_write_confined = _spy
    try:
        assert HostWarmControl(ctrl)._ctrl_writable() is True
    finally:
        envelope.atomic_write_confined = real_write
    _ = real
    assert written and all(d for d in written), (
        f"the probe must write a non-empty payload, got {written!r}")


def test_the_capability_reset_happens_after_the_artifact_is_retired():
    """Resetting first opens a window where the old artifact is still acquirable while the
    generation has already advanced -- so a spawn racing the invalidation gets the RETIRED
    artifact stamped with the NEW generation, and its late ack teaches the replacement a
    capability only the old image had.

    Ordering is the observable: the manager's invalidate() must run BEFORE the generation moves.
    """
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    class _RecordingCapability(AckCapability):
        """AckCapability uses __slots__, so the hook has to be a subclass, not a patch."""

        def __init__(self, order):
            super().__init__()
            self._order = order

        def reset(self):
            self._order.append("reset")
            super().reset()

    for cls, mgr_attr in ((SnapshotSlotRuntime, "_manager"),
                          (GvisorSnapshotSlotRuntime, "_mgr")):
        order: list = []
        rt = object.__new__(cls)
        rt._ack_capable = _RecordingCapability(order)
        setattr(rt, mgr_attr, type("M", (), {
            "invalidate": lambda self, _o=order: (_o.append("invalidate"), True)[1]})())
        cls.invalidate_base(rt)
        assert order == ["invalidate", "reset"], (
            f"{cls.__name__}: the artifact must be retired before the generation moves, "
            f"got {order}")
