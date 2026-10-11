"""Seatbelt (sandbox-exec) backend: profile generation, argv shape, and real confinement.

The ``Real*`` classes run only on macOS with ``/usr/bin/sandbox-exec``; everything else is
platform-independent.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest
from blastbox.worker.sandbox import macos_common as mc
from blastbox.worker.sandbox.seatbelt import SeatbeltSandbox, build_profile

pytestmark = pytest.mark.host_platform

DARWIN = sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists()
needs_darwin = pytest.mark.skipif(not DARWIN, reason="needs macOS sandbox-exec")


class TestProfile:
    def test_deny_default_and_network_denied(self):
        text, _ = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=[],
                                accelerators=frozenset())
        lines = text.splitlines()
        assert lines[:2] == ["(version 1)", "(deny default)"]
        assert "(deny network*)" in lines
        assert "allow network" not in text

    def test_paths_never_appear_in_the_profile_text(self):
        hostile = '/tmp/a") (allow default) ("'
        text, params = build_profile(exec_paths=[hostile], ro_paths=[hostile + "ro"],
                                     rw_paths=[hostile + "rw"], accelerators=frozenset())
        assert hostile not in text and "(allow default)" not in text
        assert hostile in params.values()
        assert all(k.replace("_", "").isalnum() for k in params)

    def test_no_accelerator_by_default(self):
        text, _ = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=[],
                                accelerators=frozenset())
        assert "iokit-open-user-client" not in text
        assert "appleneuralengine" not in text

    def test_gpu_and_ane_are_separate_grants(self):
        gpu, _ = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=[],
                               accelerators=frozenset({"gpu"}))
        assert "AGXDeviceUserClient" in gpu and "appleneuralengine" not in gpu
        ane, _ = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=[],
                               accelerators=frozenset({"ane"}))
        assert "appleneuralengine" in ane and "AGXDeviceUserClient" not in ane

    def test_ane_extension_issue_is_scoped_to_scratch_read(self):
        text, params = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=["/s"],
                                     accelerators=frozenset({"ane"}), scratch="/s")
        assert params["SCRATCH_EXT"] == "/s"
        ext = [ln for ln in text.splitlines() if "file-issue-extension" in ln]
        assert ext == ['(allow file-issue-extension (require-all (extension-class '
                       '"com.apple.app-sandbox.read") (subpath (param "SCRATCH_EXT"))))']
        gpu_only, _ = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=["/s"],
                                    accelerators=frozenset({"gpu"}), scratch="/s")
        assert "file-issue-extension" not in gpu_only

    def test_unknown_accelerator_refused(self):
        with pytest.raises(SandboxError, match="unknown accelerator"):
            build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=[],
                          accelerators=frozenset({"tpu"}))


class _FakeProc:
    def __init__(self, argv, **kwargs):
        self.launched = argv
        self.argv = mc.unwrap_launcher(argv)    # the command inside the rlimit launcher
        self.kwargs = kwargs
        self.pid = os.getpid()      # the watchdog refuses to touch our own group
        self.returncode = 0
        self.stdout = io.BytesIO(b"out")
        self.stderr = io.BytesIO(b"")

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


class TestRunShape:
    def _sb(self, calls, tmp_path):
        def popen(argv, **kw):
            p = _FakeProc(argv, **kw)
            calls.append(p)
            return p
        return SeatbeltSandbox(popen=popen, platform_ok=True, sandbox_exec="/bin/sh",
                               scratch_base=tmp_path / "scratch")

    def test_argv_env_and_scratch_cleanup(self, tmp_path):
        calls: list[_FakeProc] = []
        sb = self._sb(calls, tmp_path)
        data = tmp_path / "data"
        data.mkdir()
        r = sb.run(SandboxRequest(argv=["/bin/echo", "hi"], ro_mounts=[Mount(data, data)],
                                  env={"K": "v"}))
        assert r.stdout == b"out"
        argv = calls[0].argv
        assert argv[:2] == ["/bin/sh", "-p"]
        dashdash = argv.index("--")
        assert argv[dashdash + 2:] == ["hi"]
        params = dict(a.split("=", 1) for a in argv[3:dashdash] if a != "-D")
        assert str(data.resolve()) in params.values()
        env = calls[0].kwargs["env"]
        assert env["K"] == "v" and env["HOME"].startswith(str((tmp_path / "scratch").resolve()))
        assert calls[0].kwargs["start_new_session"] is True
        # rlimits come from a single-threaded launcher, never a preexec_fn in the threaded agent
        assert "preexec_fn" not in calls[0].kwargs
        assert calls[0].launched[1:4] == ["-I", "-S", "-c"]
        assert calls[0].kwargs["stdin"] == subprocess.DEVNULL
        assert not any((tmp_path / "scratch").iterdir())   # scratch removed after the run

    def test_remapped_mount_refused(self, tmp_path):
        sb = self._sb([], tmp_path)
        with pytest.raises(SandboxError, match="identity mounts"):
            sb.run(SandboxRequest(argv=["/bin/echo"], ro_mounts=[Mount(tmp_path, Path("/in"))]))

    def test_refuses_off_darwin(self):
        with pytest.raises(SandboxUnavailable):
            SeatbeltSandbox(platform_ok=False)

    def test_secure(self, tmp_path):
        assert self._sb([], tmp_path).secure


@needs_darwin
class TestRealConfinement:
    @pytest.fixture
    def sb(self):
        return SeatbeltSandbox()

    def test_true_runs(self, sb):
        assert sb.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0

    def test_home_is_unreadable(self, sb):
        target = Path(__file__).resolve()          # under the checkout, i.e. ungranted
        r = sb.run(SandboxRequest(argv=["/bin/cat", str(target)]))
        assert r.exit_code != 0 and b"Operation not permitted" in r.stderr

    def test_write_outside_grants_denied(self, sb, tmp_path):
        victim = tmp_path / "escape"
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", f"echo x > '{victim}'"]))
        assert r.exit_code != 0 and not victim.exists()

    def test_rw_mount_and_hostile_name(self, sb, tmp_path):
        out = tmp_path / 'o"ut (x)'
        out.mkdir()
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo hi > "$0/f"', str(out)],
                                  rw_mounts=[Mount(out, out)]))
        assert r.exit_code == 0, r.stderr
        assert (out / "f").read_text() == "hi\n"

    def test_network_denied(self, sb):
        r = sb.run(SandboxRequest(argv=["/usr/bin/nc", "-z", "-w", "3", "1.1.1.1", "80"],
                                  limits=Limits(timeout_s=20)))
        assert r.exit_code != 0

    def test_net_egress_request_still_denied(self, sb):
        r = sb.run(SandboxRequest(argv=["/usr/bin/nc", "-z", "-w", "3", "1.1.1.1", "80"],
                                  limits=Limits(timeout_s=20, net_egress=True)))
        assert r.exit_code != 0

    def test_scratch_is_per_run(self, sb):
        a = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo s > "$HOME/state" && echo ok']))
        assert a.stdout == b"ok\n", a.stderr
        b = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'cat "$HOME/state"']))
        assert b.exit_code != 0 and b"No such file" in b.stderr

    def test_timeout(self, sb):
        r = sb.run(SandboxRequest(argv=["/bin/sleep", "30"], limits=Limits(timeout_s=1)))
        assert r.killed

    def test_venv_python_keeps_its_venv(self, sb):
        if sys.prefix == sys.base_prefix:
            pytest.skip("not running in a venv")
        venv_py = Path(sys.prefix) / "bin" / "python"
        grants = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
        r = sb.run(SandboxRequest(argv=[str(venv_py), "-I", "-c", "import sys;print(sys.prefix)"],
                                  ro_mounts=[Mount(g, g) for g in grants]))
        assert r.exit_code == 0, r.stderr
        assert r.stdout.decode().strip() == sys.prefix


@needs_darwin
def test_selected_by_default_on_macos(monkeypatch):
    from blastbox.worker.sandbox.detect import select_sandbox
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    assert select_sandbox().name == "seatbelt"



@needs_darwin
def test_a_child_cannot_modify_its_seed(tmp_path):
    sb = SeatbeltSandbox()
    seed = tmp_path / "seed"
    sb.run(SandboxRequest(
        argv=["/bin/sh", "-c", 'mkdir -p "$HOME/Library/Caches/x" && echo plan > "$HOME/Library/Caches/x/p"'],
        capture_home=seed))
    assert (seed / "Library" / "Caches" / "x" / "p").read_text() == "plan\n"
    hostile = sb.run(SandboxRequest(
        argv=["/bin/sh", "-c", 'cat "$HOME/Library/Caches/x/p" && echo poisoned > "$HOME/Library/Caches/x/p"'],
        seed_home=seed))
    assert hostile.stdout == b"plan\n"
    assert (seed / "Library" / "Caches" / "x" / "p").read_text() == "plan\n"   # seed untouched
    nxt = sb.run(SandboxRequest(
        argv=["/bin/sh", "-c", 'cat "$HOME/Library/Caches/x/p"'], seed_home=seed))
    assert nxt.stdout == b"plan\n"                                            # next run clean
