"""A control-filesystem incident that CLEARS before the deadline must still be attributed to it.

The host cannot hear the worker: serve_warm() raises its own host_io WarmTimeout inside the
guest, and if ctrl/ is full or read-only the worker cannot report anything at all -- by
definition. The host's only channel is probing the shared filesystem itself.

That probe used to run once, at the deadline. So a transient ENOSPC that silenced the worker's
`started` and `done` writes and then cleared was invisible: the point-in-time probe said
"writable", guest_started stayed False, the WarmTimeout carried no host_io, and the dispatcher
recorded a pre_guest worker fault. Three slots hit by one storage blip is enough to invalidate a
healthy base -- just after storage recovered.
"""

import time

import pytest

from blastbox.errors import WarmTimeout
from blastbox.worker import warm as W
from blastbox.worker.warm import AckCapability, HostWarmControl


def _ctrl(tmp_path):
    d = tmp_path / "ctrl"
    d.mkdir()
    cap = AckCapability()
    cap.learn()                      # this image advertises start markers
    return HostWarmControl(d, ack_capable=cap)


def test_a_storage_blip_that_clears_before_the_deadline_is_still_host_io(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "_CTRL_PROBE_INTERVAL_S", 0.02)
    ctl = _ctrl(tmp_path)

    recovered_at = time.monotonic() + 0.20

    # Unwritable for the first 200ms of the job, healthy well before the 500ms deadline.
    monkeypatch.setattr(ctl, "_ctrl_writable",
                        lambda: time.monotonic() >= recovered_at)

    with pytest.raises(WarmTimeout) as ei:
        ctl.wait_for_done(timeout_s=0.5)

    assert getattr(ei.value, "host_io", False) is True, (
        "the incident was over by the deadline, so the single end-of-timeout probe saw a healthy "
        "filesystem and the storage outage was charged to the worker")
    assert ctl.guest_started is None, (
        "guest_started must be UNKNOWN, not False -- False is base evidence and convicts")


def test_a_genuinely_wedged_guest_is_still_convicted(tmp_path, monkeypatch):
    """The latch must not fail open: a healthy ctrl/ throughout still blames the guest."""
    monkeypatch.setattr(W, "_CTRL_PROBE_INTERVAL_S", 0.02)
    ctl = _ctrl(tmp_path)
    monkeypatch.setattr(ctl, "_ctrl_writable", lambda: True)

    with pytest.raises(WarmTimeout) as ei:
        ctl.wait_for_done(timeout_s=0.2)

    assert getattr(ei.value, "host_io", False) is False
    assert ctl.guest_started is False, "a silent guest on a healthy filesystem IS base evidence"


def test_a_worker_that_starts_is_never_charged_to_the_base(tmp_path, monkeypatch):
    """Once the marker lands the verdict is about the DOCUMENT; a later blip must not undo that."""
    monkeypatch.setattr(W, "_CTRL_PROBE_INTERVAL_S", 0.02)
    ctl = _ctrl(tmp_path)
    (tmp_path / "ctrl" / W.WARM_STARTED).write_text("1")
    monkeypatch.setattr(ctl, "_ctrl_writable", lambda: False)

    with pytest.raises(WarmTimeout):
        ctl.wait_for_done(timeout_s=0.15)

    assert ctl.guest_started is True


def test_the_latch_does_not_leak_into_the_next_job(tmp_path, monkeypatch):
    """A control reused for a second job must not excuse a genuine wedge with the first job's blip."""
    monkeypatch.setattr(W, "_CTRL_PROBE_INTERVAL_S", 0.02)
    ctl = _ctrl(tmp_path)

    monkeypatch.setattr(ctl, "_ctrl_writable", lambda: False)
    with pytest.raises(WarmTimeout) as first:
        ctl.wait_for_done(timeout_s=0.1)
    assert getattr(first.value, "host_io", False) is True   # blip during job 1

    monkeypatch.setattr(ctl, "_ctrl_writable", lambda: True)
    with pytest.raises(WarmTimeout) as second:
        ctl.wait_for_done(timeout_s=0.1)
    assert getattr(second.value, "host_io", False) is False, (
        "job 1's storage incident is still excusing job 2")
    assert ctl.guest_started is False
