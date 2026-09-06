"""A sandbox timeout must kill the sandbox, not the worker that launched it.

Every backend handles `subprocess.TimeoutExpired` the same way::

    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)

which is correct ONLY while the child leads a process group of its own. That is
what `start_new_session=True` on the launch buys, and nothing tested it: removing
the flag from any backend left the whole suite green. Measured mechanism --

    this process pgid                     : 1788630
    child pgid WITH start_new_session=True: 1788631   differs
    child pgid WITHOUT it                 : 1788630   IDENTICAL

-- so without the flag `os.getpgid(proc.pid)` returns the WORKER's group and the
SIGKILL lands on the worker itself, plus everything else sharing that group. A
sandbox timeout is the most ordinary failure there is (that is what `limits.
timeout_s` is for), so this would fire on the routine path, not an exotic one.

The nearest existing test monkeypatches `os.killpg` AND `os.getpgid` to no-ops,
so it can assert the killed/exit-code bookkeeping but by construction cannot see
which group was chosen.

These tests assert the EFFECT, not the argument: they compute the very expression
the timeout path computes -- `os.getpgid(proc.pid)` on the real child -- and
require it to differ from ours. A test that merely checked
`start_new_session=True` appeared in the kwargs would keep passing if the flag
stopped having that effect.
"""
import os
import shutil
import subprocess

import pytest

from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest


def _bwrap():
    from blastbox.worker.sandbox.bwrap import BubblewrapSandbox
    return BubblewrapSandbox()


def _nsjail():
    from blastbox.worker.sandbox.nsjail import NsjailSandbox
    return NsjailSandbox()


def _container():
    from blastbox.worker.sandbox.container import ContainerSandbox
    return ContainerSandbox()


# Gated on the HOST capability -- the binary being installed -- and never on the
# backend's own smoketest: gating a backend's test on that backend turns a
# malformed launch into a skip of the test written to catch it. ContainerSandbox
# execs directly and needs no binary.
BACKENDS = [
    pytest.param(_bwrap, marks=pytest.mark.skipif(
        not shutil.which("bwrap"), reason="bwrap is not installed on this host")),
    pytest.param(_nsjail, marks=pytest.mark.skipif(
        not shutil.which("nsjail"), reason="nsjail is not installed on this host")),
    pytest.param(_container),
]


@pytest.mark.parametrize("make_backend", BACKENDS, ids=["bwrap", "nsjail", "container"])
def test_a_sandbox_child_never_shares_the_workers_process_group(make_backend, monkeypatch):
    """The group `run()` would SIGKILL on timeout must not be our own.

    Parameterized over every backend rather than whichever one `select_sandbox()`
    happens to return: they each carry their own copy of the launch, so one
    losing the flag is invisible in a test that only exercises the selected one.
    """
    backend = make_backend()
    real_popen = subprocess.Popen
    seen: dict = {}

    def recording_popen(argv, **kwargs):
        proc = real_popen(argv, **kwargs)
        # Read BEFORE returning to the backend, which is the only point the child
        # is guaranteed unreaped -- `communicate()` has not run yet. getpgid works
        # on a zombie, so a fast-exiting child is not a race.
        seen.setdefault("child_pgid", os.getpgid(proc.pid))
        return proc

    monkeypatch.setattr(subprocess, "Popen", recording_popen)

    result = backend.run(SandboxRequest(argv=["/bin/true"], limits=Limits(timeout_s=20)))

    assert result.exit_code == 0, f"the probe command did not run: {result}"
    assert "child_pgid" in seen, "the backend never launched a child process"
    assert seen["child_pgid"] != os.getpgid(0), (
        f"the sandbox child shares the worker's process group ({seen['child_pgid']}); "
        "on timeout os.killpg(os.getpgid(proc.pid), SIGKILL) would SIGKILL this worker"
    )
