"""Seatbelt (sandbox-exec) backend: profile generation, argv shape, and real confinement.

The ``Real*`` classes run only on macOS with ``/usr/bin/sandbox-exec``; everything else is
platform-independent.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest, SandboxResult
from blastbox.worker.sandbox import macos_common as mc
from blastbox.worker.sandbox.seatbelt import (
    HANDSHAKE_SHIM, SeatbeltSandbox, _pinned_paths, build_profile,
)

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
    def __init__(self, argv, handshake=True, **kwargs):
        self.launched = argv
        self.argv = mc.unwrap_launcher(argv)    # the command inside the rlimit launcher
        self.kwargs = kwargs
        if handshake and HANDSHAKE_SHIM in self.argv:
            # what the shim does once sandbox-exec has attached the profile
            i = self.argv.index(HANDSHAKE_SHIM)
            Path(self.argv[i + 3]).write_text(self.argv[i + 2])
        self.pid = os.getpid()      # the watchdog refuses to touch our own group
        self.returncode = 0
        self.stdout = io.BytesIO(b"out")
        self.stderr = io.BytesIO(b"")

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


class TestPinnedRoots:
    def test_roots_and_dirs_between_nested_roots_are_pinned(self):
        assert _pinned_paths(["/w", "/w/a/b/n", "/s"]) == ["/s", "/w", "/w/a", "/w/a/b", "/w/a/b/n"]
        assert _pinned_paths(["/x", "/y"]) == ["/x", "/y"]

    def test_the_profile_denies_unlinking_them(self):
        text, params = build_profile(exec_paths=["/x"], ro_paths=[], rw_paths=["/w", "/w/a/n"],
                                     accelerators=frozenset(), scratch="/s")
        line = next(ln for ln in text.splitlines() if ln.startswith("(deny file-write-unlink"))
        keys = [k for k, v in params.items() if k.startswith("RWR_")]
        assert sorted(params[k] for k in keys) == ["/w", "/w/a", "/w/a/n"]
        assert all(f'(literal (param "{k}"))' in line for k in keys)


@needs_darwin
def test_a_removed_or_replaced_scratch_is_never_captured(tmp_path, monkeypatch):
    # The sweep puts an empty directory back where a run removed its scratch (to find its
    # processes); that stand-in must not be captured over the caller's cache.
    dest = tmp_path / "cache"
    dest.mkdir()
    (dest / "keep").write_text("earlier")

    def removes_its_scratch(argv, *, cwd, **kw):
        mc.remove_tree(Path(cwd))
        os.mkdir(cwd, 0o700)
        return SandboxResult(exit_code=0, stdout=b"", stderr=b"", killed=False)
    monkeypatch.setattr(mc, "run_confined", removes_its_scratch)
    with pytest.raises(SandboxError, match="refusing to capture"):
        SeatbeltSandbox(scratch_base=tmp_path / "s").run(
            SandboxRequest(argv=["/usr/bin/true"], capture_home=dest))
    assert (dest / "keep").read_text() == "earlier"


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
        # sandbox-exec runs the handshake shim, which execs the target with its own argv
        assert argv[dashdash + 1:dashdash + 4] == ["/bin/sh", "-c", HANDSHAKE_SHIM]
        # the target is resolved (no symlinks): /bin/echo on macOS, /usr/bin/echo on a
        # merged-/usr Linux
        assert argv[dashdash + 7:] == [os.path.realpath("/bin/echo"), "hi"]
        params = dict(a.split("=", 1) for a in argv[3:dashdash] if a != "-D")
        assert str(data.resolve()) in params.values()
        # the request env reaches the target through the launcher, never the launcher itself
        env = mc.launcher_child_env(calls[0].launched)
        assert env["K"] == "v" and env["HOME"].startswith(str((tmp_path / "scratch").resolve()))
        assert calls[0].kwargs["env"] == mc.LAUNCHER_ENV
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

    def test_a_read_only_mount_under_a_writable_one_is_refused(self, sb, tmp_path):
        # The rw subtree grant would cover the ro path too: the child could rewrite an input
        # its ro_mounts contract says is protected. Refused before launch, nothing written.
        out = tmp_path / "out"
        out.mkdir()
        cfg = out / "config"
        cfg.write_text("original\n")
        with pytest.raises(SandboxError, match="overlaps writable mount"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo pwned > "$0"', str(cfg)],
                                  ro_mounts=[Mount(cfg, cfg)], rw_mounts=[Mount(out, out)]))
        assert cfg.read_text() == "original\n"

    @pytest.mark.parametrize("layout", ["equal", "ro_contains_rw"])
    def test_other_ro_rw_overlaps_are_refused_like_app_sandbox(self, sb, tmp_path, layout):
        # Same rule as App Sandbox, so a request behaves the same on either macOS backend.
        top = tmp_path / "top"
        (top / "w").mkdir(parents=True)
        ro, rw = (top, top) if layout == "equal" else (top, top / "w")
        with pytest.raises(SandboxError, match="overlaps writable mount"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"],
                                  ro_mounts=[Mount(ro, ro)], rw_mounts=[Mount(rw, rw)]))

    def test_disjoint_ro_and_rw_mounts_still_run(self, sb, tmp_path):
        inp, out = tmp_path / "in", tmp_path / "out"
        inp.write_text("data\n")
        out.mkdir()
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'cat "$0" > "$1/copy"', str(inp), str(out)],
                                  ro_mounts=[Mount(inp, inp)], rw_mounts=[Mount(out, out)]))
        assert r.exit_code == 0, r.stderr
        assert (out / "copy").read_text() == "data\n"

    def test_a_child_cannot_set_file_flags_on_an_rw_mount(self, sb, tmp_path):
        # The mount is the real host tree: a uchg/uappnd file there would make the caller's own
        # cleanup fail. Ordinary writes, chmod and utimes still work.
        out = tmp_path / "out"
        out.mkdir()
        try:
            r = sb.run(SandboxRequest(argv=["/bin/sh", "-c",
                                            'echo hi > "$0/f" && chmod 600 "$0/f" && touch "$0/f" '
                                            '&& mkdir "$0/d" && echo ok; '
                                            'chflags uchg "$0/f"; chflags uappnd "$0/d"; '
                                            'chflags -R uchg "$0"; exit 0', str(out)],
                                      rw_mounts=[Mount(out, out)]))
            assert r.exit_code == 0 and r.stdout == b"ok\n", r.stderr
            for p in (out, out / "f", out / "d"):
                assert os.lstat(p).st_flags == 0, p
        finally:
            subprocess.run(["/usr/bin/chflags", "-R", "nouchg,nouappnd", str(out)], check=False)

    def test_a_child_cannot_set_acls_on_scratch_or_an_rw_mount(self, sb, tmp_path):
        # A deny ACL ("everyone deny delete") would keep the worker's own cleanup from removing
        # the tree; ordinary writes and chmod still work.
        out = tmp_path / "out"
        out.mkdir()
        try:
            r = sb.run(SandboxRequest(argv=["/bin/sh", "-c",
                                            'echo hi > "$0/f" && chmod 600 "$0/f" && echo ok; '
                                            'echo s > "$HOME/s"; '
                                            'chmod +a "everyone deny delete" "$0/f" && echo mount-acl; '
                                            'chmod +a "everyone deny delete_child" "$0" && echo root-acl; '
                                            'chmod +a "everyone deny delete" "$HOME/s" && echo scratch-acl; '
                                            'exit 0', str(out)],
                                      rw_mounts=[Mount(out, out)]))
            assert r.exit_code == 0 and r.stdout == b"ok\n", (r.stdout, r.stderr)
            assert subprocess.run(["/bin/ls", "-led", str(out), str(out / "f")],
                                  capture_output=True, text=True).stdout.count(" deny ") == 0
        finally:
            subprocess.run(["/bin/chmod", "-RN", str(out)], check=False)

    def test_a_child_cannot_remove_or_rename_its_mount_roots_or_scratch(self, sb, tmp_path):
        # The roots stay put like a bind mount's mountpoint; beneath a directory root anything
        # goes. Each denial echoes a marker.
        out = tmp_path / "out"
        (out / "sub").mkdir(parents=True)
        nested = out / "a" / "nested"
        nested.mkdir(parents=True)
        single = tmp_path / "single"
        single.write_text("orig")
        script = (
            'echo hi > "$0/new" && mkdir "$0/d" && mv "$0/d" "$0/e" && rmdir "$0/e" '
            '&& rmdir "$0/sub" && rm "$0/new" && echo "x" > "$1" && echo ok; '
            'rm "$1" 2>/dev/null || echo file-root-kept; '
            'mv "$0/a" "$0/b" 2>/dev/null || echo ancestor-kept; '
            'rmdir "$2" 2>/dev/null || echo nested-kept; '
            'rmdir "$0/a/nested" 2>/dev/null; '
            'cd /; rm -rf "$HOME"/* "$HOME"/.bb-handshake; rmdir "$HOME" 2>/dev/null || echo scratch-kept; '
            'exit 0')
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", script, str(out), str(single), str(nested)],
                                  rw_mounts=[Mount(out, out), Mount(single, single),
                                             Mount(nested, nested)]))
        assert r.exit_code == 0, r.stderr
        assert r.stdout.split() == [b"ok", b"file-root-kept", b"ancestor-kept", b"nested-kept",
                                    b"scratch-kept"], (r.stdout, r.stderr)
        assert out.is_dir() and nested.is_dir() and single.read_text() == "x\n"
        assert not (out / "sub").exists()        # beneath the root: the child's to change

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


class TestConfinedRunCounter:
    def _sb(self, tmp_path, popen):
        return SeatbeltSandbox(popen=popen, platform_ok=True, sandbox_exec="/bin/sh",
                               scratch_base=tmp_path / "scratch")

    def test_counted_after_a_launch(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        before = confined_runs()
        self._sb(tmp_path, lambda argv, **kw: _FakeProc(argv, **kw)).run(
            SandboxRequest(argv=["/bin/echo"]))
        assert confined_runs() == before + 1

    def test_not_counted_when_nothing_was_launched(self, tmp_path):
        # An engine that catches this and parses in-process must not look confined.
        from blastbox.worker.sandbox.base import confined_runs
        before = confined_runs()

        def no_popen(argv, **kw):
            raise PermissionError("denied")
        with pytest.raises(SandboxError):
            self._sb(tmp_path, no_popen).run(SandboxRequest(argv=["/bin/echo"]))
        not_a_dir = tmp_path / "seed-file"
        not_a_dir.write_text("x")
        with pytest.raises(SandboxError):
            self._sb(tmp_path, lambda argv, **kw: _FakeProc(argv, **kw)).run(
                SandboxRequest(argv=["/bin/echo"], seed_home=not_a_dir))
        assert confined_runs() == before


# fork, setsid, close every inherited fd, let the leader exit at once, then linger
_ESCAPE = ("use POSIX; my $pid = fork(); "
           "if ($pid) { select(undef, undef, undef, 0.01) until -s $ARGV[0]; exit 0 } "
           "POSIX::setsid(); close STDIN; close STDOUT; close STDERR; "
           "open(my $f, '>', $ARGV[0] . '.tmp') or die; print $f $$; close $f; "
           "rename($ARGV[0] . '.tmp', $ARGV[0]); sleep 30;")


def _gone(pid: int) -> bool:
    out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                         text=True).stdout.strip()
    return not out or out.startswith("Z")


@needs_darwin
def test_an_escapee_the_watchdog_never_saw_is_swept(tmp_path, monkeypatch):
    # Blind the watchdog entirely: only the post-run sandbox sweep can find the orphan.
    monkeypatch.setattr(mc.RssWatchdog, "_sample", lambda self: None)
    rw = tmp_path / "rw"
    rw.mkdir()
    pidfile = rw / "pid"
    r = SeatbeltSandbox().run(SandboxRequest(argv=["/usr/bin/perl", "-e", _ESCAPE, str(pidfile)],
                                             rw_mounts=[Mount(rw, rw)]))
    assert r.exit_code == 0, r.stderr
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while not _gone(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _gone(pid), f"escapee {pid} survived the run"


def test_a_launch_without_the_handshake_is_not_counted(tmp_path):
    # sandbox-exec ran but never exec'd the shim (what a rejected profile looks like).
    from blastbox.worker.sandbox.base import confined_runs
    before = confined_runs()
    sb = SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, handshake=False, **kw),
                         platform_ok=True, sandbox_exec="/bin/sh", scratch_base=tmp_path / "s")
    sb.run(SandboxRequest(argv=["/bin/echo"]))
    assert confined_runs() == before


@needs_darwin
def test_a_rejected_profile_is_not_counted_as_confined(monkeypatch):
    from blastbox.worker.sandbox import seatbelt as sbmod
    from blastbox.worker.sandbox.base import confined_runs
    real = sbmod.build_profile

    def bad(**kw):
        text, params = real(**kw)
        return text + "(allow no-such-operation)\n", params
    monkeypatch.setattr(sbmod, "build_profile", bad)
    before = confined_runs()
    r = SeatbeltSandbox().run(SandboxRequest(argv=["/usr/bin/true"]))
    assert r.exit_code != 0
    assert confined_runs() == before
    monkeypatch.setattr(sbmod, "build_profile", real)
    assert SeatbeltSandbox().run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0
    assert confined_runs() == before + 1


@needs_darwin
def test_a_scratch_the_worker_cannot_remove_fails_the_run(monkeypatch, tmp_path):
    def stuck(path):
        raise SandboxError(f"could not empty {path}: ['locked']")
    monkeypatch.setattr(mc, "wipe_dir", stuck)
    with pytest.raises(SandboxError, match="could not remove the run's scratch"):
        SeatbeltSandbox(scratch_base=tmp_path / "s").run(SandboxRequest(argv=["/usr/bin/true"]))


@needs_darwin
def test_a_locked_scratch_is_unlocked_and_removed(tmp_path):
    base = tmp_path / "s"
    r = SeatbeltSandbox(scratch_base=base).run(SandboxRequest(argv=[
        "/bin/sh", "-c", 'mkdir "$HOME/d" && touch "$HOME/d/f" && chflags uchg "$HOME/d/f" '
                         '&& chmod 000 "$HOME/d"']))
    assert r.exit_code == 0, r.stderr
    assert list(base.iterdir()) == []


# A grandchild that leaves through a short-lived intermediate + setsid, waits until it is
# reparented, then allocates (the size is a runtime value: perl would constant-fold a literal
# into the LEADER at compile time).
_HIDDEN_HOG = ("use POSIX; my $p = fork(); if ($p == 0) { my $q = fork(); "
               "if ($q == 0) { POSIX::setsid(); close STDIN; close STDOUT; close STDERR; "
               "select(undef, undef, undef, 0.5); my $x = 'a' x ($ARGV[0] * 1048576); sleep 60; "
               "POSIX::_exit(0) } POSIX::_exit(0) } sleep 60;")


@needs_darwin
def test_a_hidden_grandchild_is_metered_and_killed_during_the_run(monkeypatch):
    # Blind the ancestry tracking entirely: only the sandbox-identity match can see the hog.
    monkeypatch.setattr(mc.RssWatchdog, "_ancestry", lambda self, table: {self._proc.pid})
    t0 = time.monotonic()
    r = SeatbeltSandbox().run(SandboxRequest(
        argv=["/usr/bin/perl", "-e", _HIDDEN_HOG, "400"],
        limits=Limits(timeout_s=40, memory_bytes=150 * 1024 * 1024)))
    assert r.killed and b"RSS" in r.stderr, r.stderr
    assert time.monotonic() - t0 < 30          # killed for memory, not by the timeout


@needs_darwin
def test_selecting_a_sandbox_is_not_a_confined_run(monkeypatch):
    # select_sandbox()'s smoketest really launches /usr/bin/true under the profile; that probe
    # must not give an engine confinement credit before its parser runs.
    from blastbox.worker.sandbox.base import confinement_ledger
    from blastbox.worker.sandbox.detect import select_sandbox
    with confinement_ledger() as ledger:
        assert select_sandbox(backend="seatbelt").name == "seatbelt"
    assert ledger.runs == 0


class _FailingProc(_FakeProc):
    def wait(self, timeout=None):
        return 3

    def poll(self):
        return 3


def test_a_failed_launch_is_not_counted(tmp_path):
    # The shim ran (handshake written) but the target exited nonzero: an engine falling back to
    # an in-process parse after this must not look confined.
    from blastbox.worker.sandbox.base import confined_runs
    sb = SeatbeltSandbox(popen=lambda argv, **kw: _FailingProc(argv, **kw), platform_ok=True,
                         sandbox_exec="/bin/sh", scratch_base=tmp_path / "s")
    before = confined_runs()
    assert sb.run(SandboxRequest(argv=["/bin/echo"])).exit_code == 3
    assert confined_runs() == before


@needs_darwin
def test_a_killed_run_is_not_counted(tmp_path):
    from blastbox.worker.sandbox.base import confined_runs
    before = confined_runs()
    r = SeatbeltSandbox(scratch_base=tmp_path / "s").run(
        SandboxRequest(argv=["/bin/sleep", "5"], limits=Limits(timeout_s=1)))
    assert r.killed
    assert confined_runs() == before


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin requires the process APIs")
def test_seatbelt_refuses_without_process_apis(monkeypatch):
    monkeypatch.setattr(mc, "_LIBSYSTEM", None)
    with pytest.raises(SandboxUnavailable, match="process APIs"):
        SeatbeltSandbox(platform_ok=True, sandbox_exec="/bin/sh")


def test_a_run_whose_scratch_cannot_be_removed_is_not_credited(monkeypatch, tmp_path):
    # The credit comes after the final scratch removal: an engine that catches this failure and
    # falls back to parsing in-process must not pass the fallback off as confined.
    from blastbox.worker.sandbox.base import confined_runs

    def stuck(path):
        raise SandboxError(f"could not empty {path}: ['locked']")
    monkeypatch.setattr(mc, "wipe_dir", stuck)
    before = confined_runs()
    sb = SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                         sandbox_exec="/bin/sh", scratch_base=tmp_path / "scratch")
    with pytest.raises(SandboxError, match="could not remove the run's scratch"):
        sb.run(SandboxRequest(argv=["/bin/echo"]))
    assert confined_runs() == before


class TestShutdownCoversTheTeardown:
    """The agent retiring after the child is gone (run_confined's own cleanup dropped) but
    while the backend still captures and wipes must still remove the scratch and any capture
    left half-built beside its destination."""

    def test_an_emergency_during_the_capture_removes_scratch_and_leftovers(self, tmp_path,
                                                                           monkeypatch):
        from blastbox.worker.sandbox import base
        seen: dict[str, bool] = {}

        def fake_run_confined(argv, *, cwd, **kw):
            return SandboxResult(exit_code=0, stdout=b"", stderr=b"", killed=False)

        def capture(scratch, dest, budget, leftovers=None):
            half = tmp_path / ".cap-half"
            half.mkdir()
            leftovers.add(half)
            assert base.run_emergency_cleanups(5) == 1      # the agent retires here
            seen["half gone"] = not half.exists()
            seen["scratch gone"] = not scratch.exists()
            raise SandboxError("interrupted by the retirement")

        monkeypatch.setattr(mc, "run_confined", fake_run_confined)
        monkeypatch.setattr(mc, "sweep_writers", lambda path, started_after: 0)
        monkeypatch.setattr(mc, "capture_scratch", capture)
        sb = SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                             sandbox_exec="/bin/sh", scratch_base=tmp_path / "scratch")
        registered = len(base._EMERGENCY)
        with pytest.raises(SandboxError):
            sb.run(SandboxRequest(argv=["/bin/echo", "hi"], capture_home=tmp_path / "cap"))
        assert seen == {"half gone": True, "scratch gone": True}
        assert len(base._EMERGENCY) == registered           # dropped once the run is over

    def test_the_cleanup_stays_registered_until_the_scratch_is_removed(self, tmp_path,
                                                                       monkeypatch):
        from blastbox.worker.sandbox import base
        counts: list[int] = []
        real_wipe = mc.wipe_dir

        def wipe(path):
            counts.append(len(base._EMERGENCY))
            real_wipe(path)
        monkeypatch.setattr(mc, "run_confined", lambda argv, **kw: SandboxResult(
            exit_code=0, stdout=b"", stderr=b"", killed=False))
        monkeypatch.setattr(mc, "wipe_dir", wipe)
        sb = SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                             sandbox_exec="/bin/sh", scratch_base=tmp_path / "scratch")
        before = len(base._EMERGENCY)
        sb.run(SandboxRequest(argv=["/bin/echo", "hi"]))
        assert counts == [before + 1]                       # the final wipe was still covered
        assert len(base._EMERGENCY) == before


def test_a_writable_mount_holding_the_scratch_root_is_refused(tmp_path):
    base = tmp_path / "scratch"
    base.mkdir()
    sb = SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                         sandbox_exec="/bin/sh", scratch_base=base)
    for rw in (tmp_path, base):
        with pytest.raises(SandboxError, match="contains the scratch root"):
            sb.run(SandboxRequest(argv=["/bin/echo"], rw_mounts=[Mount(rw, rw)]))
    assert list(base.iterdir()) == []                       # refused before any scratch


class TestCreditGoesToTheLedgerTheRunStartedIn:
    """A run credits the detonation it STARTED in, and only if it finishes while that
    detonation's ledger is open: not a ledger opened while it ran, not one already closed."""

    def _sb(self, tmp_path, during=None):
        def popen(argv, **kw):
            if during is not None:
                during()
            return _FakeProc(argv, **kw)
        return SeatbeltSandbox(popen=popen, platform_ok=True, sandbox_exec="/bin/sh",
                               scratch_base=tmp_path / "scratch")

    def test_a_run_inside_the_ledger_is_credited(self, tmp_path):
        from blastbox.worker.sandbox.base import confinement_ledger
        with confinement_ledger() as ledger:
            self._sb(tmp_path).run(SandboxRequest(argv=["/bin/echo"]))
        assert ledger.runs == 1

    def test_a_run_started_before_the_ledger_opened_is_not_credited(self, tmp_path):
        from blastbox.worker.sandbox import base
        late = base.ConfinementLedger()
        # the context gains a ledger while the run is in flight (as a new detonation would)
        self._sb(tmp_path, during=lambda: base._LEDGER.set(late)).run(
            SandboxRequest(argv=["/bin/echo"]))
        base._LEDGER.set(None)
        assert late.runs == 0

    def test_a_run_still_going_when_its_ledger_closes_is_not_credited(self, tmp_path):
        from blastbox.worker.sandbox.base import confinement_ledger
        with confinement_ledger() as ledger:
            sb = self._sb(tmp_path, during=lambda: ledger._close())   # the detonation ended
            sb.run(SandboxRequest(argv=["/bin/echo"]))
        assert ledger.runs == 0

    def test_a_run_with_no_ledger_credits_nothing_but_is_recorded(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs, current_ledger
        assert current_ledger() is None
        before = confined_runs()
        self._sb(tmp_path).run(SandboxRequest(argv=["/bin/echo"]))
        assert confined_runs() == before + 1        # the diagnostic total still sees it


class TestSeedAndCaptureStayOutOfTheScratchRoot:
    """A seed that is or holds the scratch root would reach the run's own scratch while being
    copied into it; a capture there would swap the scratch root aside. A path inside the root
    is only the scratch's sibling (the default root is the system temp dir), so it is fine."""

    @staticmethod
    def _sb(base):
        return SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                               sandbox_exec="/bin/sh", scratch_base=base)

    @pytest.mark.parametrize("which", ["seed_home", "capture_home"])
    @pytest.mark.parametrize("holder", ["equal", "parent"])
    def test_a_path_that_is_or_holds_the_root_is_refused(self, tmp_path, which, holder):
        cache = tmp_path / "cache"
        base = cache / "scratch"
        base.mkdir(parents=True)
        path = base if holder == "equal" else cache
        with pytest.raises(SandboxError, match="contains the scratch root"):
            self._sb(base).run(SandboxRequest(argv=["/bin/echo", "hi"], **{which: path}))
        assert list(base.iterdir()) == []               # refused before the scratch existed

    def test_a_seed_beside_the_scratch_is_fine(self, tmp_path):
        base = tmp_path / "scratch"
        seed = base / "seed"
        (seed / "Library" / "Caches").mkdir(parents=True)
        (seed / "Library" / "Caches" / "k").write_text("v")
        r = self._sb(base).run(SandboxRequest(argv=["/bin/echo", "hi"], seed_home=seed))
        assert r.exit_code == 0


class TestHardLinksOutOfTheWritableMountsAreRefused:
    """The ro/rw overlap check compares paths; a hard link aliases a file under another path.
    A writable name for a file that is also read-only (or unmounted) elsewhere is refused."""

    @staticmethod
    def _sb(calls, tmp_path):
        def popen(argv, **kw):
            p = _FakeProc(argv, **kw)
            calls.append(p)
            return p
        return SeatbeltSandbox(popen=popen, platform_ok=True, sandbox_exec="/bin/sh",
                               scratch_base=tmp_path / "scratch")

    def test_a_read_only_file_linked_into_a_writable_mount_is_refused(self, tmp_path):
        ro, rw = tmp_path / "ro", tmp_path / "rw"
        ro.mkdir()
        rw.mkdir()
        (ro / "config").write_text("protected")
        os.link(ro / "config", rw / "alias")
        calls: list[_FakeProc] = []
        with pytest.raises(SandboxError, match="hard link"):
            self._sb(calls, tmp_path).run(SandboxRequest(
                argv=["/bin/echo", "hi"], ro_mounts=[Mount(ro, ro)], rw_mounts=[Mount(rw, rw)]))
        assert calls == []

    def test_links_kept_within_the_writable_mounts_run(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "f").write_text("x")
        os.link(a / "f", b / "g")
        calls: list[_FakeProc] = []
        r = self._sb(calls, tmp_path).run(SandboxRequest(
            argv=["/bin/echo", "hi"], rw_mounts=[Mount(a, a), Mount(b, b)]))
        assert r.stdout == b"out" and len(calls) == 1


class TestSeatbeltNeverGrantsTheSharedState:
    """Codex P1 (#198): a writable grant on the workers' shared state (locks, claims, cleanup
    records) would let the child release another run's lock or forge a cleanup record."""

    @staticmethod
    def _sb(tmp_path):
        return SeatbeltSandbox(popen=lambda argv, **kw: _FakeProc(argv, **kw), platform_ok=True,
                               sandbox_exec="/bin/sh", scratch_base=tmp_path / "scratch")

    def test_a_writable_mount_of_the_records_is_refused(self, tmp_path):
        records = mc.internal_state_dirs()[-1]      # the per-test dir (conftest)
        with pytest.raises(SandboxError, match="shared lock and cleanup state"):
            self._sb(tmp_path).run(SandboxRequest(argv=["/bin/echo", "hi"],
                                                  rw_mounts=[Mount(records, records)]))

    def test_a_capture_into_the_records_is_refused(self, tmp_path):
        records = mc.internal_state_dirs()[-1]
        with pytest.raises(SandboxError, match="shared lock and cleanup state"):
            self._sb(tmp_path).run(SandboxRequest(argv=["/bin/echo", "hi"],
                                                  capture_home=records / "cache"))

