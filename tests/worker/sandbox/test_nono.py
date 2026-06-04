"""Tests for the NonoSandbox (Landlock) backend.

Structure:
1. argv-building unit tests (inject nono_bin + Popen; no real nono needed).
2. secure / insecurity_reasons.
3. run() with an injected Popen (no real nono) — env relocation + timeout.
"""
from __future__ import annotations

import signal
import subprocess

import pytest

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest, SandboxResult
from blastbox.worker.sandbox.nono import NonoSandbox

# A real path that exists, used as a stand-in nono binary so _binary_present is True
# (argv building never executes it).
_FAKE_NONO = "/usr/bin/true"


def _sb(**kw):
    return NonoSandbox(nono_bin=_FAKE_NONO, **kw)


# --- Part 1: argv building -------------------------------------------------

class TestArgv:
    def test_argv_is_list_of_str(self):
        argv = _sb()._build_argv(SandboxRequest(argv=["/usr/bin/soffice", "--x"]))
        assert isinstance(argv, list) and all(isinstance(t, str) for t in argv)

    def test_starts_with_nono_wrap_and_blocks_net(self):
        argv = _sb()._build_argv(SandboxRequest(argv=["/usr/bin/true"]))
        assert argv[0] == _FAKE_NONO and argv[1] == "wrap"
        assert "--block-net" in argv

    def test_grants_system_dirs_read_only(self):
        argv = _sb()._build_argv(SandboxRequest(argv=["/usr/bin/true"]))
        # -r /usr present (read-only system dir grant)
        assert any(argv[i] == "-r" and argv[i + 1] == "/usr" for i in range(len(argv) - 1))
        # /tmp is granted read+write (the child HOME)
        assert any(argv[i] == "-a" and argv[i + 1] == "/tmp" for i in range(len(argv) - 1))

    def test_ro_mount_becomes_read_grant_rw_becomes_allow(self, tmp_path):
        ro = tmp_path / "in"
        ro.mkdir()
        rw = tmp_path / "out"
        rw.mkdir()
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            ro_mounts=[Mount(source=ro, target=ro, read_only=True)],
            rw_mounts=[Mount(source=rw, target=rw, read_only=False)],
        )
        argv = _sb()._build_argv(req)
        assert any(argv[i] == "-r" and argv[i + 1] == str(ro) for i in range(len(argv) - 1))
        assert any(argv[i] == "-a" and argv[i + 1] == str(rw) for i in range(len(argv) - 1))

    def test_file_mounts_use_file_grants(self, tmp_path):
        rofile = tmp_path / "input.bin"
        rofile.write_bytes(b"x")
        wfile = tmp_path / "out.bin"
        wfile.write_bytes(b"")
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            ro_mounts=[Mount(source=rofile, target=rofile)],
            rw_mounts=[Mount(source=wfile, target=wfile)],
        )
        argv = _sb()._build_argv(req)
        assert any(argv[i] == "--read-file" and argv[i + 1] == str(rofile)
                   for i in range(len(argv) - 1))
        assert any(argv[i] == "--allow-file" and argv[i + 1] == str(wfile)
                   for i in range(len(argv) - 1))

    def test_child_gets_clean_env_via_env_i(self):
        req = SandboxRequest(argv=["/usr/bin/soffice"], env={"FOO": "bar"})
        argv = _sb()._build_argv(req)
        i = argv.index("--")
        tail = argv[i + 1:]
        assert tail[0] == "/usr/bin/env" and tail[1] == "-i"
        assert "HOME=/tmp" in tail and "FOO=bar" in tail
        # the real command is appended after the env prefix
        assert tail[-1] == "/usr/bin/soffice"

    def test_no_caller_value_can_inject_a_flag(self, tmp_path):
        # A mount source that looks like a flag is still a value arg (after -r/-a).
        weird = tmp_path / "--block-net-not-a-flag"
        weird.mkdir()
        argv = _sb()._build_argv(SandboxRequest(
            argv=["/usr/bin/true"],
            ro_mounts=[Mount(source=weird, target=weird)],
        ))
        idx = argv.index(str(weird))
        assert argv[idx - 1] == "-r"  # it is a value of -r, not a standalone token


# --- Part 2: secure / insecurity_reasons -----------------------------------

class TestSecurity:
    def test_nono_is_not_secure_records_gaps(self):
        sb = _sb()
        assert sb.secure is False
        assert "no_seccomp" in sb.insecurity_reasons
        assert "no_pid_namespace" in sb.insecurity_reasons

    def test_binary_missing_flagged(self):
        sb = NonoSandbox(nono_bin="/nonexistent/nono")
        assert "binary_missing" in sb.insecurity_reasons
        assert sb.secure is False

    def test_bare_command_name_resolves_via_path(self):
        from blastbox.worker.sandbox.nono import _resolve_bin

        # A bare name on PATH resolves (matches the BLASTBOX_NONO_BIN=nono ergonomics).
        assert _resolve_bin("true") is not None
        # A directory path is NOT a valid binary.
        assert _resolve_bin("/usr") is None
        # An absolute path to a real file is returned as-is.
        assert _resolve_bin("/usr/bin/true") == "/usr/bin/true"

    def test_run_without_binary_raises_unavailable(self):
        sb = NonoSandbox(nono_bin="/nonexistent/nono")
        with pytest.raises(SandboxUnavailable):
            sb.run(SandboxRequest(argv=["/usr/bin/true"]))

    def test_empty_argv_raises(self):
        with pytest.raises(SandboxError):
            _sb().run(SandboxRequest(argv=[]))


# --- Part 3: run() with injected Popen -------------------------------------

class _FakeProc:
    def __init__(self):
        self.returncode = 0
        self.pid = 4321

    def communicate(self, timeout=None):
        return b"out", b"err"


def test_run_relocates_state_and_returns_result(tmp_path):
    captured = {}

    def fake_popen(argv, **kw):
        captured["argv"] = argv
        captured["env"] = kw.get("env")
        return _FakeProc()

    sb = NonoSandbox(nono_bin=_FAKE_NONO, state_dir=tmp_path / "state", popen=fake_popen)
    res = sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert isinstance(res, SandboxResult)
    assert res.exit_code == 0 and res.stdout == b"out" and res.killed is False
    # nono's own process env relocates HOME to the state dir (OFF the grants), so the
    # child can't reach nono's state; the child's HOME=/tmp comes from the env -i prefix.
    assert captured["env"]["HOME"] == str(tmp_path / "state")
    assert (tmp_path / "state").is_dir()


def test_run_timeout_kills_and_flags(tmp_path, monkeypatch):
    class _Timeouter:
        returncode = None
        pid = 999

        def __init__(self):
            self._calls = 0

        def communicate(self, timeout=None):
            self._calls += 1
            if self._calls == 1:
                raise subprocess.TimeoutExpired(cmd="nono", timeout=timeout)
            return b"", b""

    monkeypatch.setattr("os.killpg", lambda *a: None)
    monkeypatch.setattr("os.getpgid", lambda *a: 999)
    sb = NonoSandbox(nono_bin=_FAKE_NONO, state_dir=tmp_path / "s", popen=lambda *a, **k: _Timeouter())
    res = sb.run(SandboxRequest(argv=["/usr/bin/true"], limits=Limits(timeout_s=1)))
    assert res.killed is True and res.exit_code == -int(signal.SIGKILL)


def test_state_dir_unwritable_raises_unavailable(tmp_path):
    # A state dir whose parent is a file → mkdir fails → SandboxUnavailable.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    sb = NonoSandbox(nono_bin=_FAKE_NONO, state_dir=blocker / "state",
                     popen=lambda *a, **k: _FakeProc())
    with pytest.raises(SandboxUnavailable):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
