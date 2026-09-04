"""Automated proof that the accept-retry LD_PRELOAD shim fixes the restore-EINTR bail.

The shim (deploy/gvisor/accept_retry.c) exists because gVisor's restore delivers EINTR to
LibreOffice's osl_acceptPipe, whose single non-retrying accept() then bails and hangs the warm
conversion. We can't run a full runsc+soffice checkpoint/restore in CI, but we CAN reproduce the
exact failure mode with a signal (_accept_retry_probe.c) and prove the shim flips bail -> retry on
every PR. gcc-gated; Linux-only (the shim is Linux/glibc accept/accept4 EINTR semantics)."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_SHIM_SRC = _REPO / "deploy" / "gvisor" / "accept_retry.c"
_PROBE_SRC = Path(__file__).parent / "_accept_retry_probe.c"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("gcc") is None,
    reason="needs gcc + Linux (the shim is Linux/glibc accept/accept4 EINTR semantics)",
)


def _gcc(*args: str) -> None:
    subprocess.run(["gcc", *args], check=True, capture_output=True, text=True)


def test_shim_flips_eintr_bail_to_retry(tmp_path):
    shim_so = tmp_path / "accept-retry.so"
    probe = tmp_path / "probe"
    _gcc("-shared", "-fPIC", "-O2", "-o", str(shim_so), str(_SHIM_SRC), "-ldl")
    _gcc("-O2", "-o", str(probe), str(_PROBE_SRC))

    # Baseline: WITHOUT the shim, the osl-style single accept() bails on the EINTR.
    base = subprocess.run(
        [str(probe), str(tmp_path / "a.sock")],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert base.returncode == 1 and "bailed" in base.stdout, (
        base.returncode,
        base.stdout,
        base.stderr,
    )

    # WITH the shim preloaded, accept() retries past the EINTR and returns the connection.
    fixed = subprocess.run(
        [str(probe), str(tmp_path / "b.sock")],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "LD_PRELOAD": str(shim_so)},
    )
    assert fixed.returncode == 0 and "retried" in fixed.stdout, (
        fixed.returncode,
        fixed.stdout,
        fixed.stderr,
    )
