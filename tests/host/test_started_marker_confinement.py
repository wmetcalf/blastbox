"""The `started` marker must be inspected under the same confinement as `ready` and `done`.

ctrl/ is WORKER-WRITABLE on the gVisor tier (bind-mounted 0o777). Path.exists() follows symlinks,
so a compromised worker could point `started` at any host path and have the dispatcher's poll stat
it -- a control-boundary escape, and against a blocking automount or a FIFO it pins the dispatch
thread outside timeout_s entirely. Worse, honouring such a marker reads "the guest ran" for a
worker that never did, excusing exactly the poisoned base this machinery exists to convict.
"""

import os

import pytest

from blastbox.errors import WarmTimeout
from blastbox.worker.warm import WARM_STARTED, AckCapability, HostWarmControl


def _ctrl(tmp_path):
    d = tmp_path / "ctrl"
    d.mkdir()
    cap = AckCapability()
    cap.learn()
    return HostWarmControl(d, ack_capable=cap), d


def test_a_real_marker_is_honoured(tmp_path):
    """Positive control -- without this the others pass on a probe that always says no."""
    ctl, d = _ctrl(tmp_path)
    (d / WARM_STARTED).write_text("1")
    assert ctl._started_marker_present() is True
    with pytest.raises(WarmTimeout):
        ctl.wait_for_done(timeout_s=0.1)
    assert ctl.guest_started is True


def test_a_symlinked_marker_is_not_a_start(tmp_path):
    ctl, d = _ctrl(tmp_path)
    outside = tmp_path / "host-secret"
    outside.write_text("not the worker's to point at")
    (d / WARM_STARTED).symlink_to(outside)

    assert ctl._started_marker_present() is False, (
        "the probe followed a symlink out of the confined control dir")
    with pytest.raises(WarmTimeout):
        ctl.wait_for_done(timeout_s=0.1)
    assert ctl.guest_started is False, (
        "a symlinked marker was read as proof the guest ran, excusing the base")


def test_a_fifo_marker_is_not_a_start_and_does_not_block(tmp_path):
    """O_NONBLOCK + S_ISREG: a FIFO must fail the check instantly, not stall the dispatcher."""
    ctl, d = _ctrl(tmp_path)
    os.mkfifo(d / WARM_STARTED)
    assert ctl._started_marker_present() is False


def test_a_directory_marker_is_not_a_start(tmp_path):
    ctl, d = _ctrl(tmp_path)
    (d / WARM_STARTED).mkdir()
    assert ctl._started_marker_present() is False


def test_a_missing_marker_is_simply_absent(tmp_path):
    ctl, _ = _ctrl(tmp_path)
    assert ctl._started_marker_present() is False
