"""The installer's guest-kernel logic (scripts/lib/fc-kernel.sh), tested on its own.

It shipped three defects in three days and none had a test: a 404 URL whose fallback installed a
2021 kernel that cannot boot on current firecracker; a version probe that ABORTED the installer
under `set -euo pipefail` when a kernel had no banner (after firecracker was already installed,
printing nothing useful); and a refusal that told operators to set BLASTBOX_FC_KERNEL while never
reading it. Each case below is one of those, run the way the installer runs it.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
LIB = REPO / "scripts" / "lib" / "fc-kernel.sh"


def _kernel(path: pathlib.Path, banner: "str | None", *, repeat: int = 1) -> pathlib.Path:
    body = b"\x7fELF" + os.urandom(64)
    if banner:
        body += (f"Linux version {banner} (builder@ci) #1 SMP\n".encode()) * repeat
    path.write_bytes(body + os.urandom(64))
    return path


def _run(dest: pathlib.Path, *, override: "str | None" = None, fetch_ok: bool = False):
    """Source the lib and call it exactly as install-firecracker.sh does, under strict mode.

    `curl` is stubbed on PATH: it fails unless `fetch_ok`, in which case it writes a 6.1 kernel --
    so no test ever touches the network.
    """
    stub = dest / "bin"
    stub.mkdir(exist_ok=True)
    fake61 = dest / "fetched-6.1"
    _kernel(fake61, "6.1.128")
    (stub / "curl").write_text(
        "#!/usr/bin/env bash\n"
        + (f'out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done; '
           f'cp "{fake61}" "$out"\n' if fetch_ok else "exit 22\n"))
    (stub / "curl").chmod(0o755)
    env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}"}
    env.pop("BLASTBOX_FC_KERNEL", None)
    if override is not None:
        env["BLASTBOX_FC_KERNEL"] = override
    script = (f'set -euo pipefail; DEST="{dest}"; ARCH=x86_64; source "{LIB}"; '
              'fc_kernel_setup; echo REACHED-NEXT-STEPS')
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env,
                          timeout=60)


def test_a_cached_kernel_too_old_to_boot_is_refused_and_moved_aside(tmp_path):
    """Left in place, test-fc.sh would boot it next time (it runs the installer only when the
    firecracker BINARY is missing), so the panic came back on the second run."""
    _kernel(tmp_path / "vmlinux", "5.10.0")
    r = _run(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "too old" in r.stdout
    assert not (tmp_path / "vmlinux").exists(), "the refused kernel was left where test-fc.sh boots it"
    assert (tmp_path / "vmlinux.refused-linux-5.10").exists(), "the evidence was deleted, not moved"


def test_an_operators_own_kernel_is_refused_but_never_touched(tmp_path):
    mine = _kernel(tmp_path / "my-kernel", "5.10.0")
    r = _run(tmp_path, override=str(mine))
    assert r.returncode == 1
    assert mine.exists(), "the installer moved a file the operator pointed it at"


def test_the_override_it_recommends_is_actually_honoured(tmp_path):
    """The refusal says 'point BLASTBOX_FC_KERNEL at a >= 5.18 image'. With a stale file still in
    DEST, that used to change nothing: the installer re-checked the stale file and exited 1."""
    _kernel(tmp_path / "vmlinux", "5.10.0")
    good = _kernel(tmp_path / "good", "6.1.128")
    r = _run(tmp_path, override=str(good))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHED-NEXT-STEPS" in r.stdout


def test_a_kernel_with_no_banner_warns_instead_of_aborting(tmp_path):
    """Under pipefail, grep's no-match exit made the whole installer abort here -- silently, after
    firecracker was already installed."""
    _kernel(tmp_path / "vmlinux", None)
    r = _run(tmp_path)
    assert r.returncode == 0, f"aborted on a bannerless kernel: {r.stdout}{r.stderr}"
    assert "could not read a version banner" in r.stdout
    assert "REACHED-NEXT-STEPS" in r.stdout


def test_a_repeated_banner_does_not_die_of_sigpipe(tmp_path):
    """`head -1` closes the pipe early; under pipefail a banner repeated many times made the probe
    exit 141 (SIGPIPE) -- a VALID kernel aborting the installer. The `|| true` covers it."""
    _kernel(tmp_path / "vmlinux", "6.1.128", repeat=200_000)
    r = _run(tmp_path)
    assert r.returncode == 0, f"a valid kernel aborted the installer: rc={r.returncode}"


def test_with_nothing_cached_a_supported_kernel_is_fetched(tmp_path):
    r = _run(tmp_path, fetch_ok=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "guest kernel: Linux 6.1" in r.stdout


def test_when_every_url_fails_it_says_so_and_continues(tmp_path):
    r = _run(tmp_path, fetch_ok=False)
    assert r.returncode == 0
    assert "kernel download failed" in r.stdout


@pytest.mark.parametrize("script", ["scripts/install-firecracker.sh", "scripts/lib/fc-kernel.sh"])
def test_the_scripts_parse(script):
    assert subprocess.run(["bash", "-n", str(REPO / script)]).returncode == 0
