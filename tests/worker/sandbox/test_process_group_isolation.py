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
import subprocess

import pytest

from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest

from .conftest import bwrap_usable, nsjail_usable

# nono is launched through its own `popen` seam rather than the module-level
# `subprocess.Popen`, so `/usr/bin/true` stands in for the binary: the backend
# still builds and launches a REAL child, which is all this test reads.
_FAKE_NONO = "/usr/bin/true"


def _run_via_module_popen(make_backend, recording, monkeypatch):
    """bwrap / nsjail / container resolve `subprocess.Popen` at call time.

    The backend is CONSTRUCTED BEFORE the recorder is installed. Construction
    probes the host (cgroup-pids, seccomp, AppArmor) by running the binary, and
    `subprocess.run` builds those probes on the very `Popen` being patched -- so
    recording from construction captures a PROBE child, which is correctly in our
    own process group, and the test fails on its own setup. Measured: it did.
    """
    backend = make_backend()
    monkeypatch.setattr(subprocess, "Popen", recording)
    return backend.run(
        SandboxRequest(argv=["/bin/true"], limits=Limits(timeout_s=20))
    )


def _bwrap(recording, monkeypatch, tmp_path):
    from blastbox.worker.sandbox.bwrap import BubblewrapSandbox
    return _run_via_module_popen(BubblewrapSandbox, recording, monkeypatch)


def _nsjail(recording, monkeypatch, tmp_path):
    from blastbox.worker.sandbox.nsjail import NsjailSandbox
    return _run_via_module_popen(NsjailSandbox, recording, monkeypatch)


def _container(recording, monkeypatch, tmp_path):
    from blastbox.worker.sandbox.container import ContainerSandbox
    return _run_via_module_popen(ContainerSandbox, recording, monkeypatch)


def _nono(recording, monkeypatch, tmp_path):
    """nono binds `subprocess.Popen` as a DEFAULT ARGUMENT, evaluated at import.

    Monkeypatching the module attribute afterwards therefore binds nothing, which
    is why this backend needs its documented `popen` seam instead -- and why it
    would have gone on regressing unnoticed had the matrix only patched the
    module (codex).
    """
    from blastbox.worker.sandbox.nono import NonoSandbox
    sb = NonoSandbox(nono_bin=_FAKE_NONO, state_dir=tmp_path / "state", popen=recording)
    return sb.run(SandboxRequest(argv=["/bin/true"], limits=Limits(timeout_s=20)))


# Gated on whether the backend can actually RUN here, not merely on the binary
# being installed. `shutil.which` answers a different question: bwrap and nsjail
# are installed on hosts whose unprivileged user namespaces are restricted, where
# the backend correctly returns nonzero -- and this test would then fail on the
# host's configuration while reading as a process-group defect.
#
# `bwrap_usable()` / `nsjail_usable()` ask the HOST by invoking the binary
# directly; they do not ask `select_sandbox()`, so gating on them is not the
# circular case where a backend's own selector decides whether to test it.
BACKENDS = [
    pytest.param(_bwrap, "bwrap", marks=pytest.mark.skipif(
        bwrap_usable() is not None, reason=f"bwrap unusable here: {bwrap_usable()}")),
    pytest.param(_nsjail, "nsjail", marks=pytest.mark.skipif(
        nsjail_usable() is not None, reason=f"nsjail unusable here: {nsjail_usable()}")),
    pytest.param(_container, "container"),
    pytest.param(_nono, "nono"),
]


@pytest.mark.parametrize("launch,name", BACKENDS,
                         ids=[p.values[1] for p in BACKENDS])
def test_a_sandbox_child_never_shares_the_workers_process_group(
    launch, name, monkeypatch, tmp_path
):
    """The group `run()` would SIGKILL on timeout must not be our own.

    Parameterized over EVERY backend rather than whichever one `select_sandbox()`
    happens to return: each carries its own copy of the launch, so one losing the
    flag is invisible to a test that only exercises the selected one. `detect.py`
    enumerates four, and nono is the one a module-level patch cannot reach.
    """
    real_popen = subprocess.Popen
    seen: dict = {}

    def recording_popen(argv, **kwargs):
        proc = real_popen(argv, **kwargs)
        # Read BEFORE returning to the backend, which is the only point the child
        # is guaranteed unreaped -- `communicate()` has not run yet. getpgid works
        # on a zombie, so a fast-exiting child is not a race.
        seen.setdefault("child_pgid", os.getpgid(proc.pid))
        return proc

    result = launch(recording_popen, monkeypatch, tmp_path)

    assert result.exit_code == 0, f"the probe command did not run under {name}: {result}"
    assert "child_pgid" in seen, f"{name} never launched a child process"
    assert seen["child_pgid"] != os.getpgid(0), (
        f"the {name} sandbox child shares the worker's process group "
        f"({seen['child_pgid']}); on timeout os.killpg(os.getpgid(proc.pid), SIGKILL) "
        "would SIGKILL this worker"
    )
