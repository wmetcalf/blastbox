"""Shared macOS sandbox plumbing: env, copier, argv rewriting, watchdog, lifecycle.

Pure-logic tests run on any POSIX host; nothing here needs Seatbelt.
"""
from __future__ import annotations

import contextlib
import errno
import ctypes
import signal
import os
import shutil
import stat
import subprocess
import sys
import threading
import time

import pytest

from blastbox.errors import SandboxError
from blastbox.limits import Limits
from blastbox.worker.sandbox import macos_common as mc

# What only macOS has. The launcher refuses to run without its libproc process limit, and BSD
# file flags (chflags) and extended ACLs (chmod +a) don't exist on Linux: tests that run the
# real launcher or set those are macOS-only. Everything else here runs on any POSIX host.
macos_launcher = pytest.mark.skipif(sys.platform != "darwin",
                                    reason="runs the macOS launcher (libproc process limit)")
macos_file_flags = pytest.mark.skipif(not hasattr(os, "chflags"),
                                      reason="BSD file flags are macOS's")

class TestChildEnv:
    def test_points_home_tmp_and_caches_at_scratch(self, tmp_path):
        env = mc.build_child_env(tmp_path, {})
        assert env["HOME"] == str(tmp_path)
        assert env["CFFIXED_USER_HOME"] == str(tmp_path)
        assert env["TMPDIR"] == str(tmp_path / "tmp") + "/"
        assert env["PATH"] == mc.MINIMAL_PATH

    def test_request_cannot_repoint_the_scratch(self, tmp_path):
        env = mc.build_child_env(tmp_path, {
            "HOME": "/Users/victim", "TMPDIR": "/tmp", "CFFIXED_USER_HOME": "/", "PATH": "/evil",
            "ENGINE_KNOB": "1",
        })
        assert env["HOME"] == str(tmp_path)
        assert env["PATH"] == mc.MINIMAL_PATH
        assert env["ENGINE_KNOB"] == "1"

    def test_ambient_environment_is_not_inherited(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
        assert "AWS_SECRET_ACCESS_KEY" not in mc.build_child_env(tmp_path, {})


class TestScratch:
    def test_fresh_resolved_dir_with_tmp_and_caches(self, tmp_path):
        s = mc.make_scratch(tmp_path)
        assert s == s.resolve()
        assert (s / "tmp").is_dir() and (s / "Library" / "Caches").is_dir()
        assert oct(s.stat().st_mode & 0o777) == "0o700"
        assert mc.make_scratch(tmp_path) != s


class TestCopyNoFollow:
    def test_copies_tree_and_recreates_symlinks_without_following(self, tmp_path):
        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("A")
        (src / "sub" / "b.bin").write_bytes(b"\x00" * 10)
        secret = tmp_path / "secret"
        secret.write_text("host secret")
        (src / "link").symlink_to(secret)
        dst = tmp_path / "dst"
        n = mc.copy_no_follow(src, dst, budget_bytes=1000)
        # file bytes, plus the symlink's target text (a link stores it)
        assert n == 11 + len(os.fsencode(str(secret)))
        assert (dst / "a.txt").read_text() == "A"
        assert (dst / "link").is_symlink()
        assert os.readlink(dst / "link") == str(secret)

    def test_fifo_is_skipped_not_opened(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        os.mkfifo(src / "fifo")      # opening this would block the worker forever
        (src / "ok").write_text("x")
        dst = tmp_path / "dst"
        mc.copy_no_follow(src, dst, budget_bytes=100)
        assert sorted(p.name for p in dst.iterdir()) == ["ok"]

    def test_budget_is_enforced(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "big").write_bytes(b"x" * 101)
        with pytest.raises(SandboxError, match="budget"):
            mc.copy_no_follow(src, tmp_path / "dst", budget_bytes=100)

    def test_single_file(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("hello")
        mc.copy_no_follow(f, tmp_path / "g", budget_bytes=10)
        assert (tmp_path / "g").read_text() == "hello"


class TestRewritePathArgs:
    M = [("/job/in", "/slot/m/0/in"), ("/job/out", "/slot/m/1/out")]

    def test_exact_and_nested(self):
        assert mc.rewrite_path_args(["/job/in", "/job/out/x.png"], self.M) == [
            "/slot/m/0/in", "/slot/m/1/out/x.png"]

    def test_flag_equals_value(self):
        assert mc.rewrite_path_args(["--out=/job/out", "-x"], self.M) == [
            "--out=/slot/m/1/out", "-x"]

    def test_prefix_without_separator_is_not_a_match(self):
        assert mc.rewrite_path_args(["/job/input2", "/job/outside"], self.M) == [
            "/job/input2", "/job/outside"]

    def test_longest_target_wins(self):
        m = [("/a", "/s/0"), ("/a/b", "/s/1")]
        assert mc.rewrite_path_args(["/a/b/c", "/a/c"], m) == ["/s/1/c", "/s/0/c"]


class TestResolveExecutable:
    def test_bare_name_resolves_on_minimal_path_only(self):
        invoked, real = mc.resolve_executable("sh")
        assert invoked.is_absolute() and real.is_absolute()

    def test_relative_path_refused(self):
        with pytest.raises(SandboxError):
            mc.resolve_executable("./tool")

    def test_symlink_keeps_invoked_name(self, tmp_path):
        target = tmp_path / "real-python"
        target.write_text("#!/bin/sh\n")
        link = tmp_path / "venv-python"
        link.symlink_to(target)
        invoked, real = mc.resolve_executable(str(link))
        assert invoked.name == "venv-python"
        assert real == target.resolve()

    def test_missing_refused(self, tmp_path):
        with pytest.raises(SandboxError, match="does not exist"):
            mc.resolve_executable(str(tmp_path / "nope"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
class TestLifecycle:
    @macos_launcher
    def test_timeout_kills_the_group(self, tmp_path):
        t0 = time.monotonic()
        r = mc.run_confined(["/bin/sleep", "30"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=1), cwd=tmp_path)
        assert r.killed and r.exit_code == -9
        assert time.monotonic() - t0 < 10

    @macos_launcher
    def test_rss_watchdog_kills_over_limit(self, tmp_path):
        r = mc.run_confined(["/bin/sleep", "30"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=20), cwd=tmp_path,
                            rss_fn=lambda pgid: 10 * 1024 ** 4)
        assert r.killed
        assert b"RSS exceeded" in r.stderr

    @macos_launcher
    def test_stdin_closed_and_output_captured(self, tmp_path):
        r = mc.run_confined(["/bin/sh", "-c", "cat; echo done"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=10), cwd=tmp_path)
        assert r.exit_code == 0 and r.stdout == b"done\n"

    def _alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    @macos_launcher
    def test_a_forked_child_does_not_outlive_a_normal_exit(self, tmp_path):
        pidfile = tmp_path / "pid"
        r = mc.run_confined(["/bin/sh", "-c", f'sleep 60 </dev/null >/dev/null 2>&1 & echo $! > {pidfile}; exit 0'],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=10), cwd=tmp_path)
        assert r.exit_code == 0 and not r.killed
        pid = int(pidfile.read_text())
        time.sleep(0.2)
        assert not self._alive(pid)

    @macos_launcher
    def test_a_setsid_escapee_is_reaped(self, tmp_path):
        # Leaves the process group, so only the watchdog's family tracking can find it.
        pidfile = tmp_path / "pid"
        code = (f"import os,time\npid=os.fork()\nif pid==0:\n os.setsid(); time.sleep(60)\n"
                f"else:\n open({str(pidfile)!r},'w').write(str(pid)); time.sleep(1)\n")
        r = mc.run_confined([sys.executable, "-I", "-c", code], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=10), cwd=tmp_path)
        assert r.exit_code == 0
        pid = int(pidfile.read_text())
        time.sleep(0.2)
        assert not self._alive(pid)

    @macos_launcher
    def test_captured_output_is_bounded(self, tmp_path):
        r = mc.run_confined(["/bin/sh", "-c", "head -c 5000000 /dev/zero"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=10), cwd=tmp_path, max_output_bytes=1000)
        assert len(r.stdout) == 1000
        assert b"stdout truncated at 1000 bytes" in r.stderr

    @macos_launcher
    def test_disk_watchdog_caps_the_whole_run(self, tmp_path):
        # Many files, each under RLIMIT_FSIZE, adding up past tmpfs_bytes.
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        r = mc.run_confined(["/bin/sh", "-c", "i=0; while [ $i -lt 400 ]; do head -c 200000 /dev/zero > f$i; i=$((i+1)); done; sleep 30"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=20, tmpfs_bytes=10_000_000),
                            cwd=scratch, watch_dirs=[scratch])
        assert r.killed
        assert b"writable dirs exceeded" in r.stderr

    @macos_launcher
    def test_process_count_is_capped(self, tmp_path):
        r = mc.run_confined(["/bin/sh", "-c", "i=0; while [ $i -lt 300 ]; do sleep 5 & i=$((i+1)); done; wait"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=20), cwd=tmp_path)
        assert b"fork" in r.stderr.lower() or b"resource temporarily unavailable" in r.stderr.lower()

    @macos_launcher
    def test_rlimits_come_from_the_launcher_not_preexec_fn(self, tmp_path):
        seen = {}

        def popen(argv, **kw):
            seen.update(kw)
            return subprocess.Popen(argv, **kw)
        r = mc.run_confined([sys.executable, "-I", "-c",
                             "import resource; print(resource.getrlimit(resource.RLIMIT_FSIZE)[0])"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=10, tmpfs_bytes=12345678),
                            cwd=tmp_path, popen=popen)
        assert "preexec_fn" not in seen
        assert r.stdout.strip() == b"12345678"

    def test_group_rss_parses_ps(self):
        fake = subprocess.CompletedProcess([], 0, stdout="  1 0 42  100\n  2 1 42  50\n  3 1 7 9999\n")
        assert mc.group_rss_bytes(42, ps_runner=lambda *a, **k: fake) == 150 * 1024


class TestSeedAndCapture:
    def test_seed_merges_into_prebuilt_scratch_and_skips_tmp(self, tmp_path):
        seed = tmp_path / "seed"
        (seed / "Library" / "Caches" / "app").mkdir(parents=True)
        (seed / "Library" / "Caches" / "app" / "plan").write_text("compiled")
        (seed / "tmp").mkdir()
        (seed / "tmp" / "junk").write_text("x")
        scratch = mc.make_scratch(tmp_path / "base")
        mc.seed_scratch(scratch, seed, budget_bytes=1000)
        assert (scratch / "Library" / "Caches" / "app" / "plan").read_text() == "compiled"
        assert list((scratch / "tmp").iterdir()) == []

    def test_seed_budget(self, tmp_path):
        seed = tmp_path / "seed"
        seed.mkdir()
        (seed / "big").write_bytes(b"x" * 50)
        with pytest.raises(SandboxError, match="budget"):
            mc.seed_scratch(mc.make_scratch(tmp_path / "b"), seed, budget_bytes=10)

    def test_capture_replaces_dest_and_excludes_tmp(self, tmp_path):
        scratch = mc.make_scratch(tmp_path / "b")
        (scratch / "Library" / "Caches" / "c").write_text("new")
        (scratch / "tmp" / "t").write_text("t")
        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "stale").write_text("old")
        mc.capture_scratch(scratch, dest, budget_bytes=1000)
        assert (dest / "Library" / "Caches" / "c").read_text() == "new"
        assert not (dest / "stale").exists() and not (dest / "tmp").exists()

    def test_none_is_a_no_op(self, tmp_path):
        mc.seed_scratch(tmp_path, None, 0)
        mc.capture_scratch(tmp_path, None, 0)

    def _cache(self, tmp_path):
        scratch = tmp_path / "scratch"
        (scratch / "Library" / "Caches").mkdir(parents=True)
        (scratch / "Library" / "Caches" / "c").write_text("new")
        dest = tmp_path / "cache"
        dest.mkdir()
        (dest / "warm").write_text("previous capture")
        return scratch, dest

    def test_an_unreadable_entry_leaves_the_previous_cache_intact(self, tmp_path):
        scratch, dest = self._cache(tmp_path)
        bad = scratch / "Library" / "locked"
        bad.write_text("x")
        bad.chmod(0)
        try:
            with pytest.raises(OSError):
                mc.capture_scratch(scratch, dest, budget_bytes=1 << 20)
        finally:
            bad.chmod(0o600)
        assert sorted(os.listdir(dest)) == ["warm"]
        assert (dest / "warm").read_text() == "previous capture"
        assert [p.name for p in tmp_path.iterdir() if ".capture-" in p.name] == []

    def test_an_io_error_partway_leaves_the_previous_cache_intact(self, tmp_path, monkeypatch):
        scratch, dest = self._cache(tmp_path)
        (scratch / "second").write_text("y")
        real = mc.copy_no_follow
        calls = []

        def flaky(src, dst, **kw):
            calls.append(src)
            if len(calls) == 2:
                raise OSError(errno.EIO, "simulated I/O error")
            return real(src, dst, **kw)
        monkeypatch.setattr(mc, "copy_no_follow", flaky)
        with pytest.raises(OSError, match="simulated"):
            mc.capture_scratch(scratch, dest, budget_bytes=1 << 20)
        assert sorted(os.listdir(dest)) == ["warm"]
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".cache.")] == []

    def test_over_budget_leaves_the_previous_cache_intact(self, tmp_path):
        scratch, dest = self._cache(tmp_path)
        (scratch / "big").write_bytes(b"x" * 10_000)
        with pytest.raises(SandboxError):
            mc.capture_scratch(scratch, dest, budget_bytes=1000)
        assert sorted(os.listdir(dest)) == ["warm"]

    def test_a_complete_capture_replaces_the_cache_in_place(self, tmp_path):
        scratch, dest = self._cache(tmp_path)
        ino = os.stat(tmp_path).st_ino
        mc.capture_scratch(scratch, dest, budget_bytes=1 << 20)
        assert (dest / "Library" / "Caches" / "c").read_text() == "new"
        assert not (dest / "warm").exists()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["cache", "scratch"]
        assert os.stat(tmp_path).st_ino == ino
        # a missing destination is simply created
        mc.capture_scratch(scratch, tmp_path / "fresh", budget_bytes=1 << 20)
        assert (tmp_path / "fresh" / "Library" / "Caches" / "c").read_text() == "new"

    def test_the_fallback_swap_restores_the_original_if_the_rename_fails(self, tmp_path,
                                                                         monkeypatch):
        scratch, dest = self._cache(tmp_path)
        monkeypatch.setattr(mc, "_renamex_np", lambda: None)
        real_rename = os.rename

        def rename(a, b):
            if ".capture-" in str(a):
                raise OSError(errno.EIO, "simulated rename failure")
            return real_rename(a, b)
        monkeypatch.setattr(mc.os, "rename", rename)
        with pytest.raises(OSError, match="simulated"):
            mc.capture_scratch(scratch, dest, budget_bytes=1 << 20)
        monkeypatch.setattr(mc.os, "rename", real_rename)
        assert sorted(os.listdir(dest)) == ["warm"]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["cache", "scratch"]

    def test_a_symlinked_cache_path_keeps_its_symlink(self, tmp_path):
        scratch, real = self._cache(tmp_path)
        link = tmp_path / "link"
        link.symlink_to(real)
        mc.capture_scratch(scratch, link, budget_bytes=1 << 20)
        assert link.is_symlink()
        assert (real / "Library" / "Caches" / "c").read_text() == "new"


class TestWipeDir:
    @macos_file_flags
    def test_unlocks_and_empties(self, tmp_path):
        d = tmp_path / "slot"
        (d / "locked").mkdir(parents=True)
        f = d / "locked" / "immutable"
        f.write_text("x")
        os.chflags(f, stat.UF_IMMUTABLE)
        os.chmod(d / "locked", 0)
        (d / "link").symlink_to("/etc/hosts")
        mc.wipe_dir(d)
        assert list(d.iterdir()) == []
        assert os.path.exists("/etc/hosts")

    def test_missing_is_clean(self, tmp_path):
        mc.wipe_dir(tmp_path / "nope")

    def test_what_cannot_be_removed_raises(self, tmp_path, monkeypatch):
        d = tmp_path / "slot"
        d.mkdir()
        (d / "stuck").write_text("x")
        monkeypatch.setattr(mc, "remove_tree", lambda p: None)
        with pytest.raises(SandboxError, match="could not empty"):
            mc.wipe_dir(d)


class TestLoaderEnv:
    def test_loader_control_vars_are_dropped(self, tmp_path):
        env = mc.build_child_env(tmp_path, {"DYLD_INSERT_LIBRARIES": "/x.dylib",
                                            "DYLD_LIBRARY_PATH": "/x", "LD_PRELOAD": "/x", "K": "v"})
        assert not [k for k in env if k.startswith(("DYLD_", "LD_"))]
        assert env["K"] == "v"

    @macos_launcher
    def test_the_launcher_runs_with_its_own_env_and_execs_the_child_with_the_requested_one(
            self, tmp_path):
        seen = {}

        def popen(argv, **kw):
            seen["env"] = kw["env"]
            return subprocess.Popen(argv, **kw)
        r = mc.run_confined(["/bin/sh", "-c", 'echo "$MARK"'], env={"PATH": mc.MINIMAL_PATH,
                                                                   "MARK": "child-env"},
                            limits=Limits(timeout_s=10), cwd=tmp_path, popen=popen)
        assert r.stdout == b"child-env\n"
        # the unsandboxed launcher interpreter never sees the request's env
        assert seen["env"] == mc.LAUNCHER_ENV


class TestWipeDirRoot:
    def test_a_root_swapped_for_a_symlink_is_refused_not_followed(self, tmp_path):
        victim = tmp_path / "engine"
        victim.mkdir()
        (victim / "keep").write_text("x")
        data = tmp_path / "Data"
        data.symlink_to(victim)
        with pytest.raises(SandboxError, match="symlink"):
            mc.wipe_dir(data)
        assert (victim / "keep").read_text() == "x"

    def test_a_root_that_is_a_file_is_refused(self, tmp_path):
        f = tmp_path / "Data"
        f.write_text("x")
        with pytest.raises(SandboxError, match="not a directory"):
            mc.wipe_dir(f)


@pytest.mark.skipif(sys.platform != "darwin" or not os.path.exists("/usr/bin/sandbox-exec"),
                    reason="needs macOS")
class TestSweep:
    def _sandboxed_sleeper(self, rw):
        prof = (f'(version 1)(allow default)(deny file-write*)'
                f'(allow file-write* (subpath "{rw}"))')
        p = subprocess.Popen(["/usr/bin/sandbox-exec", "-p", prof, "/bin/sleep", "30"],
                             start_new_session=True)
        # Wait until the kernel has it sandboxed (a fixed sleep raced a loaded machine: the
        # sweep then ran before the profile applied and found nothing to kill).
        deadline = time.monotonic() + 10
        while not mc.is_sandboxed(p.pid):
            assert p.poll() is None and time.monotonic() < deadline, "sleeper never got sandboxed"
            time.sleep(0.02)
        return p

    def test_kills_only_sandboxed_processes_that_may_write_the_run_dir(self, tmp_path):
        mine, other = (tmp_path / "mine").resolve(), (tmp_path / "other").resolve()
        mine.mkdir()
        other.mkdir()
        t0 = time.time() - 1
        a, b = self._sandboxed_sleeper(mine), self._sandboxed_sleeper(other)
        plain = subprocess.Popen(["/bin/sleep", "30"])     # unsandboxed: never matched
        try:
            time.sleep(0.5)
            assert mc.sweep_writers(mine, started_after=t0) == 1
            assert a.wait(5) == -9
            assert b.poll() is None and plain.poll() is None
            # a process older than the run is left alone even if it could write the dir
            assert mc.sweep_writers(other, started_after=time.time() + 60) == 0
            assert b.poll() is None
        finally:
            for p in (a, b, plain):
                p.kill()
                p.wait()

    @pytest.mark.parametrize("swap", ["removed", "symlink"])
    def test_a_removed_or_swapped_scratch_root_still_sweeps_its_run(self, tmp_path, swap):
        # the child deletes (or symlinks away) its scratch dir to stop matching: the sweep puts
        # the directory back and still finds -- and kills -- the run's detached processes
        mine = (tmp_path / "mine").resolve()
        mine.mkdir()
        t0 = time.time() - 1
        a = self._sandboxed_sleeper(mine)
        try:
            time.sleep(0.5)
            mine.rmdir()
            if swap == "symlink":
                (tmp_path / "elsewhere").mkdir()
                mine.symlink_to(tmp_path / "elsewhere")
            assert mc.sweep_writers(mine, started_after=t0) == 1
            assert a.wait(5) == -9
            assert mine.is_dir() and not mine.is_symlink()
        finally:
            a.kill()
            a.wait()

    def test_the_worker_itself_is_not_sandboxed(self):
        assert not mc.is_sandboxed(os.getpid())



class TestSweepRevalidatesIdentity:
    def test_a_target_whose_pid_was_reused_after_matching_is_not_killed(self, monkeypatch):
        # matched at start time 100.0; by the time of the kill the pid is another process
        starts = iter([100.0, 200.0])
        listings = iter([[4242]])                  # listed once; then it (the newcomer) exits
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: next(listings, []))
        monkeypatch.setattr(mc, "is_sandboxed", lambda p: True)
        monkeypatch.setattr(mc, "proc_start_time", lambda p: next(starts, None))
        monkeypatch.setattr(mc, "_proc_state", lambda p: "gone")
        sent = []
        monkeypatch.setattr(mc.os, "kill", lambda p, sig: sent.append(p))
        assert mc.sweep_sandboxed(lambda p: True, what="test") == 0
        assert sent == []

    def test_the_same_process_is_killed(self, monkeypatch):
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: [4242])
        monkeypatch.setattr(mc, "is_sandboxed", lambda p: True)
        monkeypatch.setattr(mc, "proc_start_time", lambda p: 100.0)
        monkeypatch.setattr(mc, "_alive", lambda p: False)
        sent = []
        monkeypatch.setattr(mc.os, "kill", lambda p, sig: sent.append(p))
        assert mc.sweep_sandboxed(lambda p: True, what="test") == 1
        assert sent == [4242]

    def test_a_live_match_with_no_readable_identity_fails_the_sweep(self, monkeypatch):
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: [4242])
        monkeypatch.setattr(mc, "is_sandboxed", lambda p: True)
        monkeypatch.setattr(mc, "proc_start_time", lambda p: None)
        monkeypatch.setattr(mc, "_proc_state", lambda p: "alive")
        monkeypatch.setattr(mc.os, "kill", lambda p, sig: None)
        with pytest.raises(SandboxError, match="cannot identify"):
            mc.sweep_sandboxed(lambda p: True, what="test")


class TestHardLinks:
    def test_hard_links_are_charged_once_but_counted_per_name(self, tmp_path):
        d = tmp_path / "w"
        (d / "sub").mkdir(parents=True)
        (d / "f").write_bytes(os.urandom(1 << 20))
        for i in range(5):
            os.link(d / "f", d / "sub" / f"l{i}")
        one = os.lstat(d / "f").st_blocks * 512
        total, entries, complete = mc.dir_usage([d], 1000)
        assert complete
        assert entries == 7                      # f, sub, l0..l4
        assert one <= total < 2 * one            # the 1 MiB inode once, plus a directory
        # also across roots: a hard link in a second watched tree is the same blocks
        e = tmp_path / "e"
        e.mkdir()
        os.link(d / "f", e / "g")
        both, _, _ = mc.dir_usage([d, e], 1000)
        assert both - total < one // 2

    def test_distinct_files_are_each_charged(self, tmp_path):
        d = tmp_path / "w"
        d.mkdir()
        for i in range(3):
            (d / f"f{i}").write_bytes(os.urandom(1 << 20))
        total, entries, _ = mc.dir_usage([d], 1000)
        assert entries == 3 and total >= 3 * (1 << 20)

    def test_a_copy_keeps_hard_links_within_the_tree(self, tmp_path):
        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        (src / "f").write_bytes(b"x" * 600_000)
        os.chmod(src / "f", 0o4755)               # setuid: the copy (both names) must drop it
        os.link(src / "f", src / "sub" / "g")
        budget = mc.CopyBudget(1_000_000)         # the two names together would be 1.2 MB
        mc.copy_no_follow(src, tmp_path / "dst", budget=budget)
        f, g = tmp_path / "dst" / "f", tmp_path / "dst" / "sub" / "g"
        assert os.lstat(f).st_ino == os.lstat(g).st_ino
        assert budget.bytes == 600_000 and budget.entries == 4    # src, f, sub, g
        assert stat.S_IMODE(os.lstat(g).st_mode) == 0o755
        with open(f, "ab") as fh:                 # a write through one name shows through the other
            fh.write(b"y")
        assert g.read_bytes().endswith(b"y")
        assert os.lstat(src / "f").st_ino != os.lstat(f).st_ino   # never linked to the source

    def test_a_link_to_a_file_outside_the_tree_is_copied(self, tmp_path):
        outside = tmp_path / "outside"
        outside.write_bytes(b"secret")
        src = tmp_path / "src"
        src.mkdir()
        os.link(outside, src / "only")
        mc.copy_no_follow(src, tmp_path / "dst", budget_bytes=1 << 20)
        copied = tmp_path / "dst" / "only"
        assert copied.read_bytes() == b"secret"
        assert os.lstat(copied).st_ino != os.lstat(outside).st_ino
        assert os.lstat(copied).st_nlink == 1

    def test_separate_copies_never_share_an_inode(self, tmp_path):
        # an ro and an rw mount staged by separate calls: a write through the rw copy must not
        # reach the ro one, even when the host files are links to one inode
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "f").write_bytes(b"x")
        os.link(a / "f", b / "f")
        budget = mc.CopyBudget(1 << 20)
        mc.copy_no_follow(a, tmp_path / "ro", budget=budget)
        mc.copy_no_follow(b, tmp_path / "rw", budget=budget)
        assert os.lstat(tmp_path / "ro" / "f").st_ino != os.lstat(tmp_path / "rw" / "f").st_ino

    def test_a_seed_keeps_links_across_its_top_level_entries(self, tmp_path):
        seed = tmp_path / "seed"
        (seed / "one").mkdir(parents=True)
        (seed / "two").mkdir()
        (seed / "one" / "f").write_bytes(b"x" * 600_000)
        os.link(seed / "one" / "f", seed / "two" / "f")
        scratch = mc.make_scratch(tmp_path / "s")
        mc.seed_scratch(scratch, seed, budget_bytes=1_000_000)
        assert os.lstat(scratch / "one" / "f").st_ino == os.lstat(scratch / "two" / "f").st_ino

    def test_a_capture_keeps_links_across_its_top_level_entries(self, tmp_path):
        scratch = tmp_path / "scratch"
        (scratch / "one").mkdir(parents=True)
        (scratch / "two").mkdir()
        (scratch / "one" / "f").write_bytes(b"x" * 600_000)
        os.link(scratch / "one" / "f", scratch / "two" / "f")
        dest = tmp_path / "cache"
        mc.capture_scratch(scratch, dest, 1_000_000)
        assert os.lstat(dest / "one" / "f").st_ino == os.lstat(dest / "two" / "f").st_ino


class TestFailClosedMeasurement:
    def test_an_unreadable_subdir_makes_usage_incomplete(self, tmp_path):
        d = tmp_path / "w"
        (d / "hidden").mkdir(parents=True)
        (d / "hidden" / "big").write_bytes(b"x" * 100_000)
        os.chmod(d / "hidden", 0)
        try:
            _, _, complete = mc.dir_usage([d], 1000)
            assert complete is False
        finally:
            os.chmod(d / "hidden", 0o700)
        assert mc.dir_usage([d], 1000)[2] is True
        assert mc.dir_usage([tmp_path / "missing"], 1000) == (0, 0, True)

    @macos_launcher
    def test_the_watchdog_trips_on_what_it_cannot_measure(self, tmp_path):
        w = tmp_path / "w"
        w.mkdir()
        r = mc.run_confined(["/bin/sh", "-c", f'mkdir "{w}/h" && chmod 000 "{w}/h" && sleep 20'],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=30),
                            cwd=tmp_path, watch_dirs=[w])
        os.chmod(w / "h", 0o700)
        assert r.killed and b"writable dirs" in r.stderr


class TestWipeDirLockedRoot:
    @macos_file_flags
    def test_a_root_chmodded_000_is_unlocked_and_emptied(self, tmp_path):
        d = tmp_path / "Data"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "f").write_text("x")
        os.chmod(d, 0)
        os.chflags(d, stat.UF_IMMUTABLE)       # locked after the chmod (uchg blocks chmod)
        mc.wipe_dir(d)
        assert list(d.iterdir()) == []

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")
    def test_deny_acls_on_the_root_and_children_are_stripped_and_emptied(self, tmp_path):
        # what a sandboxed child (App Sandbox, or Seatbelt before ACLs were denied) can leave:
        # deny-delete ACLs on files, a deny-delete_child ACL on a subdir and on the root itself
        d = tmp_path / "Data"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "f").write_text("x")
        (d / "g").write_text("x")
        acl = ["/bin/chmod", "+a"]
        subprocess.run([*acl, "everyone deny delete,writesecurity", str(d / "sub" / "f")], check=True)
        subprocess.run([*acl, "everyone deny delete,writesecurity", str(d / "g")], check=True)
        subprocess.run([*acl, "everyone deny delete,delete_child,writesecurity", str(d / "sub")],
                       check=True)
        subprocess.run([*acl, "everyone deny delete_child,writesecurity", str(d)], check=True)
        try:
            mc.wipe_dir(d)
            assert list(d.iterdir()) == []
        finally:
            subprocess.run(["/bin/chmod", "-RN", str(d)], check=False)

    def test_an_enumeration_failure_is_a_sandbox_error(self, tmp_path, monkeypatch):
        d = tmp_path / "Data"
        d.mkdir()
        monkeypatch.setattr(mc.Path, "iterdir",
                            lambda self: (_ for _ in ()).throw(PermissionError(13, "denied")))
        with pytest.raises(SandboxError, match="could not empty"):
            mc.wipe_dir(d)



class TestDirUsageRoots:
    def test_a_file_root_is_counted_not_incomplete(self, tmp_path):
        f = tmp_path / "rw-file"
        f.write_bytes(b"x" * 50_000)
        used, entries, complete = mc.dir_usage([f], 1000)
        assert complete is True and entries == 1 and used >= 50_000

    def test_a_symlink_root_counts_the_link_not_its_target(self, tmp_path):
        big = tmp_path / "big"
        big.mkdir()
        (big / "f").write_bytes(b"x" * 200_000)
        link = tmp_path / "link"
        link.symlink_to(big)
        used, entries, complete = mc.dir_usage([link], 1000)
        assert complete is True and entries == 1 and used < 200_000

    def test_env_nul_is_refused(self, tmp_path):
        with pytest.raises(SandboxError, match="invalid env entry"):
            mc.build_child_env(tmp_path, {"K": "a\0b"})


class TestCopyPreservesModes:
    def test_byte_copy_keeps_permission_bits(self, tmp_path, monkeypatch):
        # The fallback path (no clonefile, e.g. across APFS volumes) must not reset modes.
        monkeypatch.setattr(mc, "_CLONEFILE", None)
        src = tmp_path / "src"
        (src / "d").mkdir(parents=True)
        (src / "secret").write_text("s")
        os.chmod(src / "secret", 0o600)
        (src / "tool").write_text("#!/bin/sh\n")
        os.chmod(src / "tool", 0o755)
        os.chmod(src / "d", 0o750)
        (src / "ro").mkdir()
        (src / "ro" / "f").write_text("x")
        os.chmod(src / "ro", 0o555)                     # read-only dir still gets filled
        dst = tmp_path / "dst"
        try:
            mc.copy_no_follow(src, dst, budget_bytes=1000)
            mode = lambda p: stat.S_IMODE(os.lstat(p).st_mode)  # noqa: E731
            assert mode(dst / "secret") == 0o600
            assert mode(dst / "tool") == 0o755
            assert mode(dst / "d") == 0o750
            assert mode(dst / "ro") == 0o555 and (dst / "ro" / "f").read_text() == "x"
        finally:
            for d in (src / "ro", dst / "ro"):
                if d.exists():
                    os.chmod(d, 0o755)

    def test_setuid_bits_are_never_copied(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "_CLONEFILE", None)
        f = tmp_path / "f"
        f.write_text("x")
        os.chmod(f, 0o4755)
        mc.copy_no_follow(f, tmp_path / "g", budget_bytes=10)
        assert stat.S_IMODE(os.lstat(tmp_path / "g").st_mode) == 0o755


class TestSharedCopyBudget:
    def test_bytes_are_shared_across_copies(self, tmp_path):
        for n in ("a", "b"):
            (tmp_path / n).write_bytes(b"x" * 60)
        budget = mc.CopyBudget(100)
        mc.copy_no_follow(tmp_path / "a", tmp_path / "a2", budget=budget)
        with pytest.raises(SandboxError, match="budget"):
            mc.copy_no_follow(tmp_path / "b", tmp_path / "b2", budget=budget)

    def test_entries_are_capped(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(20):
            (src / f"e{i}").symlink_to("/nowhere")      # zero bytes each: only entries count
        with pytest.raises(SandboxError, match="entries"):
            mc.copy_no_follow(src, tmp_path / "dst", budget=mc.CopyBudget(1000, max_entries=10))


class TestWatchdogStop:
    def test_exit_waits_for_an_in_flight_sample_and_it_kills_nothing(self):
        # A sample still running when the run ends (a slow `ps`) must finish before the context
        # exits, and must not trip afterwards -- by then the slot may be serving the next job.
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        calls = []

        def slow_rss(pgid):
            calls.append(pgid)
            if len(calls) == 2:
                time.sleep(2.5)
                return 10 ** 15                      # "over budget", but only after the run
            return 0
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=slow_rss, table_fn=lambda: [])
            with dog:
                while len(calls) < 2:
                    time.sleep(0.01)
            assert not dog._thread.is_alive()
            assert dog.tripped is None
            assert proc.poll() is None                # not killed by the stale sample
        finally:
            proc.kill()
            proc.wait()


class TestEnumerationFailsClosed:
    class _Lib:
        def __init__(self, sizing, listing):
            self.sizing, self.listing = sizing, listing

        def proc_listpids(self, kind, uid, buf, size):
            return self.sizing if buf is None else self.listing

    @pytest.mark.parametrize("sizing,listing", [(0, 0), (-1, -1), (4096, 0), (4096, -1)])
    def test_a_failed_listing_raises_not_empty(self, monkeypatch, sizing, listing):
        monkeypatch.setattr(mc, "_LIBSYSTEM", self._Lib(sizing, listing))
        with pytest.raises(SandboxError, match="enumerate"):
            mc.uid_pids()
        with pytest.raises(SandboxError, match="enumerate"):
            mc.sweep_sandboxed(lambda p: True, what="test")

    @pytest.mark.skipif(sys.platform != "darwin", reason="Darwin requires the process APIs")
    def test_missing_apis_raise_on_darwin(self, monkeypatch):
        monkeypatch.setattr(mc, "_LIBSYSTEM", None)
        with pytest.raises(SandboxError, match="enumerate"):
            mc.uid_pids()

    def test_the_watchdog_stops_a_run_it_cannot_enumerate(self, monkeypatch):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)

        def broken():
            raise SandboxError("cannot enumerate processes: test")
        monkeypatch.setattr(mc, "uid_pids", broken)
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda pgid: 0, table_fn=lambda: [],
                                 member_fn=lambda pid: True)
            with dog:
                proc.wait(timeout=10)
            assert dog.tripped == "process"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


class TestProcessTableFailsClosed:
    @pytest.mark.parametrize("runner", [
        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("ps", 5)),
        lambda *a, **k: (_ for _ in ()).throw(OSError("no ps")),
        lambda *a, **k: subprocess.CompletedProcess([], 1, stdout="", stderr="boom"),
        lambda *a, **k: subprocess.CompletedProcess([], 0, stdout="", stderr=""),
    ])
    def test_an_unreadable_table_raises_not_empty(self, runner):
        with pytest.raises(SandboxError, match="process table"):
            mc.process_table(runner)

    def test_the_watchdog_trips_when_ps_is_unavailable(self):
        def no_ps():
            raise SandboxError("cannot read the process table: ps exited 1")
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, table_fn=no_ps)
            dog._sample()
            assert dog.tripped == "process"
            assert proc.wait(timeout=5) != 0       # killed, not left running unmetered
        finally:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            proc.wait()


class TestWatchdogPidIdentity:
    def test_a_reused_pid_is_forgotten_not_trusted(self):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            starts = {4242: 100.0}
            dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [],
                                 start_fn=lambda pid: starts.get(pid))
            dog._remember([4242])
            assert 4242 in dog._ancestry([])
            starts[4242] = 200.0                   # same pid, a different (unrelated) process
            assert 4242 not in dog._ancestry([])
            assert 4242 not in dog.seen
        finally:
            proc.kill()
            proc.wait()

    def test_a_gone_pid_is_never_recorded(self):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [], start_fn=lambda pid: None)
            dog._remember([4242])
            assert dog.seen == {}
        finally:
            proc.kill()
            proc.wait()

    def test_a_reaped_leader_pid_is_not_part_of_the_family(self):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [], start_fn=lambda pid: None)
        assert proc.pid in dog._ancestry([])
        proc.kill()
        proc.wait()
        assert proc.pid not in dog._ancestry([])


    def test_a_new_member_is_remembered_only_once_reconfirmed(self):
        # ps lists a family member; before its start time is read, the pid is reused by an
        # unrelated process (the re-scan no longer finds it in the family): never trusted
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            pgid = os.getpgid(proc.pid)
            member = mc._Proc(pid=999_991, ppid=proc.pid, pgid=pgid, rss=0)
            stranger = mc._Proc(pid=999_991, ppid=1, pgid=1, rss=0)
            tables = iter([[member], [stranger]])
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda g: 0,
                                 table_fn=lambda: next(tables, []),
                                 start_fn=lambda p: 7.0 if p == 999_991 else None)
            dog._sample()
            assert 999_991 not in dog.seen
            assert dog.tripped is None
        finally:
            proc.kill()
            proc.wait()

    def test_a_reconfirmed_new_member_is_remembered(self):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            pgid = os.getpgid(proc.pid)
            member = mc._Proc(pid=999_991, ppid=proc.pid, pgid=pgid, rss=0)
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda g: 0,
                                 table_fn=lambda: [member],
                                 start_fn=lambda p: 7.0 if p == 999_991 else None)
            dog._sample()
            assert dog.seen == {999_991: 7.0}
        finally:
            proc.kill()
            proc.wait()


class TestWatchdogProcessGroup:
    def test_the_group_is_not_trusted_once_its_leader_is_reaped(self, monkeypatch):
        # after the leader is reaped its pid -- the group number -- can become another job's
        # group: neither killpg nor "same pgid" membership may reach it
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [], start_fn=lambda pid: None,
                             member_fn=lambda pid: False)   # a backend's sandbox identity
        monkeypatch.setattr(mc, "uid_pids", lambda: [])
        pgid = dog._pgid
        stranger = mc._Proc(pid=999_991, ppid=1, pgid=pgid, rss=0)
        assert 999_991 in dog._ancestry([stranger])        # leader alive: the group is ours
        proc.kill()
        proc.wait()
        assert 999_991 not in dog._ancestry([stranger])
        signalled = []
        monkeypatch.setattr(mc.os, "killpg", lambda g, sig: signalled.append(("pg", g)))
        monkeypatch.setattr(mc.os, "kill", lambda p, sig: signalled.append(("pid", p)))
        dog._table_fn = lambda: [stranger]
        dog.kill_family()
        assert signalled == []

    def test_without_an_identity_a_reaped_groups_reused_number_is_not_trusted(self, monkeypatch):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        starts: dict[int, float] = {}
        dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [], start_fn=lambda p: starts.get(p))
        pgid = dog._pgid
        member = mc._Proc(pid=999_991, ppid=1, pgid=pgid, rss=0)
        proc.kill()
        proc.wait()
        assert 999_991 in dog._ancestry([member])          # number still free: still our group
        starts[pgid] = 12345.0                             # a new process now holds that pid
        assert 999_991 not in dog._ancestry([member])
        signalled = []
        monkeypatch.setattr(mc.os, "killpg", lambda g, sig: signalled.append(g))
        dog.kill_family()
        assert signalled == []

    def test_the_group_is_killed_while_the_leader_is_unreaped(self, monkeypatch):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: [], start_fn=lambda pid: None)
            dog.kill_family()
            assert proc.wait(timeout=5) == -9
        finally:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            proc.wait()


class TestWatchRoots:
    def test_duplicate_and_nested_roots_are_counted_once(self, tmp_path):
        parent = tmp_path / "p"
        (parent / "nested").mkdir(parents=True)
        (parent / "nested" / "f").write_bytes(b"x" * 8192)
        other = tmp_path / "o"
        other.mkdir()
        roots = mc.disjoint_roots([parent / "nested", parent, parent, other,
                                   tmp_path / "p" / "." / "nested"])
        assert roots == [parent, other]
        once = mc.dir_usage([parent], 1000)
        assert mc.dir_usage(roots, 1000)[:2] == (once[0], once[1])

    def test_the_watchdog_meters_overlapping_mounts_once(self, tmp_path):
        parent = tmp_path / "p"
        (parent / "nested").mkdir(parents=True)
        (parent / "nested" / "f").write_bytes(b"x" * 600_000)
        used = mc.dir_usage([parent], 1000)[0]
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda g: 0, table_fn=lambda: [],
                                 watch_dirs=[parent, parent / "nested", parent],
                                 disk_limit_bytes=used + used // 2)
            dog._sample()
            assert dog.tripped is None
        finally:
            proc.kill()
            proc.wait()


class TestNprocIsMandatory:
    def test_a_launcher_that_cannot_install_nproc_never_execs(self, tmp_path):
        import json
        marker = tmp_path / "ran"
        argv = mc.limits_launcher_argv(Limits(timeout_s=10), ["/usr/bin/touch", str(marker)],
                                       {"PATH": mc.MINIMAL_PATH})
        cfg = json.loads(argv[5])
        cfg["libproc"] = str(tmp_path / "no-such-libproc.dylib")
        argv[5] = json.dumps(cfg)
        r = subprocess.run(argv, capture_output=True, env=dict(mc.LAUNCHER_ENV), timeout=30)
        assert r.returncode == mc.NPROC_FAIL_EXIT
        assert b"process limit" in r.stderr
        assert not marker.exists()

    @pytest.mark.skipif(sys.platform != "darwin", reason="libproc is Darwin's")
    def test_the_launcher_installs_nproc_and_execs(self, tmp_path):
        r = mc.run_confined([sys.executable, "-I", "-c",
                             "import resource; print(resource.getrlimit(resource.RLIMIT_NPROC)[0])"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=10), cwd=tmp_path)
        assert r.exit_code == 0, r.stderr
        assert 0 < int(r.stdout) < 1 << 20


class TestContainerIdentity:
    def test_a_data_root_swapped_for_a_symlink_still_matches(self, tmp_path, monkeypatch):
        cont = tmp_path / "Containers" / "io.x.slot0"
        data = cont / "Data"
        data.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        match = mc.container_matcher(data)
        monkeypatch.setattr(mc, "container_of", lambda pid: str(data))
        assert match(1)
        data.rmdir()
        data.symlink_to(elsewhere)             # the child swaps its own Data root
        assert match(1)
        monkeypatch.setattr(mc, "container_of", lambda pid: str(elsewhere))
        assert not match(1)
        other = tmp_path / "Containers" / "io.x.slot1" / "Data"
        monkeypatch.setattr(mc, "container_of", lambda pid: str(other))
        assert not match(1)


class TestCloneSanitizesModes:
    def test_a_cloned_file_loses_setuid(self, tmp_path, monkeypatch):
        src = tmp_path / "f"
        src.write_text("x")
        try:
            os.chmod(src, 0o4755)
        except PermissionError:
            pytest.skip("cannot set setuid here")
        if not os.stat(src).st_mode & stat.S_ISUID:
            pytest.skip("setuid not kept on this filesystem")

        def fake_clone(fd, dirfd, d, flags):
            # Like APFS fclonefileat: the copy keeps the source's mode, special bits included.
            with open(d, "wb") as f:
                f.write(os.pread(fd, 1 << 20, 0))
            os.chmod(d, stat.S_IMODE(os.fstat(fd).st_mode))
            return 0
        monkeypatch.setattr(mc, "_CLONEFILE", fake_clone)
        dst = tmp_path / "g"
        mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
        assert stat.S_IMODE(os.stat(dst).st_mode) == 0o755


class TestSeedEntryBudgetIsShared:
    def test_many_top_level_entries_hit_one_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "MAX_SCRATCH_ENTRIES", 3)
        seed = tmp_path / "seed"
        seed.mkdir()
        for i in range(5):
            (seed / f"f{i}").write_text("")
        with pytest.raises(SandboxError, match="entries"):
            mc.seed_scratch(mc.make_scratch(tmp_path / "s"), seed, budget_bytes=1 << 20)

    def test_merged_entries_share_the_cap_too(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "MAX_SCRATCH_ENTRIES", 3)
        seed = tmp_path / "seed"
        caches = seed / "Library" / "Caches"
        caches.mkdir(parents=True)
        for i in range(5):
            (caches / f"f{i}").write_text("")
        with pytest.raises(SandboxError, match="entries"):
            mc.seed_scratch(mc.make_scratch(tmp_path / "s"), seed, budget_bytes=1 << 20)


darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="libproc / macOS")


class TestSpecialFilesAreWiped:
    """A FIFO or socket the child leaves at the top of a wiped dir is neither a file nor a
    symlink: it must still be unlinked, so the wipe proves the dir empty."""

    def _specials(self, d):
        import socket
        os.mkfifo(d / "fifo")
        s = socket.socket(socket.AF_UNIX)
        with contextlib.chdir(d):        # a relative name: tmp paths overflow sun_path
            s.bind("sock")
        s.close()
        (d / "sub").mkdir()
        os.mkfifo(d / "sub" / "nested-fifo")

    def test_remove_tree_unlinks_fifos_and_sockets(self, tmp_path):
        self._specials(tmp_path)
        for name in ("fifo", "sock", "sub"):
            mc.remove_tree(tmp_path / name)
        assert list(tmp_path.iterdir()) == []

    def test_wipe_dir_empties_special_files(self, tmp_path):
        d = tmp_path / "slot"
        d.mkdir()
        self._specials(d)
        mc.wipe_dir(d)
        assert list(d.iterdir()) == []


class TestDiskWalkNeverFollowsASwappedDir:
    def test_a_dir_swapped_for_a_symlink_mid_walk_is_not_followed(self, tmp_path, monkeypatch):
        # Listed as a directory, then -- before the walk descends -- replaced by a symlink to a
        # big host tree: the watchdog must not count (or block on) what the link points at.
        root = tmp_path / "scratch"
        (root / "sub").mkdir(parents=True)
        outside = tmp_path / "host"
        outside.mkdir()
        (outside / "big").write_bytes(b"x" * (4 << 20))
        swapped = []

        def swap():
            if not swapped:
                swapped.append(1)
                (root / "sub").rename(tmp_path / "moved")
                (root / "sub").symlink_to(outside)

        real_open, real_scandir = os.open, os.scandir

        def hooked_open(path, flags, *a, dir_fd=None, **kw):
            if os.fsdecode(path).endswith("sub"):
                swap()
            return real_open(path, flags, *a, dir_fd=dir_fd, **kw)

        def hooked_scandir(path="."):
            if isinstance(path, (str, os.PathLike)) and os.fsdecode(path).endswith("sub"):
                swap()
            return real_scandir(path)

        monkeypatch.setattr(os, "open", hooked_open)
        monkeypatch.setattr(os, "scandir", hooked_scandir)
        used, entries, complete = mc.dir_usage([root], mc.MAX_SCRATCH_ENTRIES)
        assert swapped
        assert used < (1 << 20), used          # the 4 MiB behind the link was not counted
        assert complete

    def test_a_tree_deeper_than_the_walk_limit_is_unmeasured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "MAX_WALK_DEPTH", 3)
        (tmp_path / "a" / "b" / "c" / "d").mkdir(parents=True)
        assert mc.dir_usage([tmp_path], 1000)[2] is False
        assert mc.dir_usage([tmp_path / "a" / "b"], 1000)[2] is True

    def test_the_walk_stops_when_asked(self, tmp_path):
        for i in range(20):
            (tmp_path / f"d{i}").mkdir()
        assert mc.dir_usage([tmp_path], 1000, stop=lambda: True)[2] is False


_HOLDER = r'''
import mmap, os, sys, time
d = sys.argv[1]
f = open(os.path.join(d, "a"), "wb"); os.unlink(f.name); f.write(b"x" * (3 << 20)); f.flush()
g = os.open(os.path.join(d, "b"), os.O_RDWR | os.O_CREAT); os.unlink(os.path.join(d, "b"))
os.ftruncate(g, 5 << 20); m = mmap.mmap(g, 5 << 20); m[:] = b"y" * (5 << 20); os.close(g)
print("ready", flush=True); time.sleep(60)
'''


class TestHeldFilesRevalidateIdentity:
    """A run's held-file scan reads each process's tables by pid, after the family was listed.
    A member that exited by then may have its pid reused by another job: that job's held files
    must not be charged to this run (they could trip its disk limit)."""

    def _scan(self, monkeypatch, per_pid):
        calls = []
        monkeypatch.setattr(mc, "_LIBSYSTEM", object())    # the real scan is replaced below

        def scan(pid, vfi, region, held):
            calls.append(pid)
            out = per_pid[pid]
            if isinstance(out, Exception):
                raise out
            held[(1, pid)] = out
        monkeypatch.setattr(mc, "_scan_held", scan)
        return calls

    def test_a_pid_reused_before_the_scan_is_not_read(self, monkeypatch):
        calls = self._scan(monkeypatch, {7: 500})
        assert mc.held_unlinked_bytes({7: 100.0}, start_fn=lambda pid: 200.0) == 0
        assert calls == []

    def test_a_pid_reused_during_the_scan_is_discarded(self, monkeypatch):
        self._scan(monkeypatch, {7: 500, 8: 30})
        starts = iter([100.0, 200.0])           # matches before the read, not after
        start_fn = lambda pid: next(starts) if pid == 7 else 50.0   # noqa: E731
        assert mc.held_unlinked_bytes({7: 100.0, 8: 50.0}, start_fn=start_fn) == 30

    def test_a_matching_process_is_counted(self, monkeypatch):
        self._scan(monkeypatch, {7: 500})
        assert mc.held_unlinked_bytes({7: 100.0}, start_fn=lambda pid: 100.0) == 500

    def test_an_unreadable_process_fails_closed_only_while_it_is_still_ours(self, monkeypatch):
        self._scan(monkeypatch, {7: SandboxError("cannot list pid 7's open files")})
        with pytest.raises(SandboxError):
            mc.held_unlinked_bytes({7: 100.0}, start_fn=lambda pid: 100.0)
        starts = iter([100.0, 200.0])           # the failure came from the pid's new owner
        assert mc.held_unlinked_bytes({7: 100.0}, start_fn=lambda pid: next(starts)) == 0

    def test_the_watchdog_scans_confirmed_members_by_identity(self, tmp_path):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            pgid = os.getpgid(proc.pid)
            member = mc._Proc(pid=999_991, ppid=proc.pid, pgid=pgid, rss=0)
            starts = {proc.pid: 10.0, 999_991: 20.0}
            got = []

            def held(identities):
                got.append(dict(identities))
                return 0
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda pgid: 0,
                                 table_fn=lambda: [member], start_fn=starts.get,
                                 watch_dirs=[tmp_path], disk_limit_bytes=1 << 30, held_fn=held)
            dog._sample()
            assert got and got[-1].get(999_991) == 20.0     # passed with its start time
            # a member that was never confirmed is not scanned at all
            dog.seen.pop(999_991)
            dog._table_fn = lambda: [mc._Proc(pid=999_992, ppid=proc.pid, pgid=pgid, rss=0)]
            dog._start_fn = lambda pid: None if pid == 999_992 else starts.get(pid)
            dog._sample()
            assert 999_992 not in got[-1]
        finally:
            proc.kill()
            proc.wait()


@darwin_only
class TestOpenUnlinkedFilesCount:
    def test_held_unlinked_bytes_sees_open_and_mapped_files(self, tmp_path):
        p = subprocess.Popen([sys.executable, "-I", "-c", _HOLDER, str(tmp_path)],
                             stdout=subprocess.PIPE)
        try:
            assert p.stdout.readline() == b"ready\n"
            assert list(tmp_path.iterdir()) == []                 # no path leads to them
            assert mc.dir_usage([tmp_path], 1000)[0] == 0
            assert mc.held_unlinked_bytes([p.pid]) >= (8 << 20)   # 3 MiB fd + 5 MiB mmap
        finally:
            p.kill()
            p.wait()

    def test_an_exited_pid_is_skipped(self):
        p = subprocess.Popen(["/usr/bin/true"])
        p.wait()
        assert mc.held_unlinked_bytes([p.pid]) == 0

    def test_a_run_hiding_bytes_in_unlinked_files_trips_the_disk_limit(self, tmp_path):
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        r = mc.run_confined([sys.executable, "-I", "-c", _HOLDER, str(scratch)],
                            env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=20, tmpfs_bytes=6_000_000),
                            cwd=scratch, watch_dirs=[scratch])
        assert r.killed
        assert b"writable dirs exceeded" in r.stderr

    def test_unreadable_open_files_trip_the_run(self, tmp_path):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)

        def blind(pids):
            raise SandboxError("cannot list pid 1's open files")
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, rss_fn=lambda pgid: 0, table_fn=lambda: [],
                                 watch_dirs=[tmp_path], disk_limit_bytes=1 << 30, held_fn=blind)
            with dog:
                proc.wait(timeout=10)
            assert dog.tripped == "disk"
        finally:
            proc.kill()
            proc.wait()


class TestWatchdogExitIsBounded:
    @macos_launcher
    @pytest.mark.timeout(60)
    def test_a_stuck_watchdog_still_gets_the_run_killed_and_swept(self, tmp_path, monkeypatch):
        # __exit__ raising (the watchdog would not stop) must not skip the family kill and the
        # backend sweep: a detached child would otherwise outlive the failed run
        monkeypatch.setattr(mc, "WATCHDOG_JOIN_S", 0.5)
        monkeypatch.setattr(mc, "held_unlinked_bytes", lambda pids, **kw: time.sleep(5) or 0)
        w = tmp_path / "w"
        w.mkdir()
        pidfile = tmp_path / "bg.pid"
        swept = []
        with pytest.raises(SandboxError, match="did not stop"):
            mc.run_confined(["/bin/sh", "-c", f'/bin/sleep 30 & echo $! > "{pidfile}"; /bin/sleep 1'],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=30),
                            cwd=tmp_path, watch_dirs=[w], sweep=lambda: swept.append(1))
        assert swept == [1]
        bg = int(pidfile.read_text())
        deadline = time.monotonic() + 5
        while mc.proc_start_time(bg) is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            assert mc.proc_start_time(bg) is None, "the detached child outlived the failed run"
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(bg, signal.SIGKILL)

    @pytest.mark.timeout(30)
    def test_a_watchdog_that_will_not_stop_fails_the_run(self, monkeypatch):
        monkeypatch.setattr(mc, "WATCHDOG_JOIN_S", 0.5)
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        entered = []

        def stuck_table():
            entered.append(1)
            time.sleep(5)
            return []
        try:
            dog = mc.RssWatchdog(proc, 1 << 30, table_fn=stuck_table)
            with pytest.raises(SandboxError, match="did not stop"), dog:
                while not entered:
                    time.sleep(0.01)
            assert proc.poll() is None        # its stale sample, when it ends, kills nothing
        finally:
            proc.kill()
            proc.wait()


class TestSweepNeedsAStableEmptyState:
    def test_an_escapee_that_hands_off_mid_round_is_still_swept(self, monkeypatch):
        # Round 1 lists the parent P, which forks C (not listed) and exits before it can be
        # matched; round 2 lists C. A single empty round must not end the sweep.
        listings = iter([[700], [701]])
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: next(listings, []))
        p_starts = iter([100.0])
        monkeypatch.setattr(mc, "proc_start_time",
                            lambda p: next(p_starts, None) if p == 700 else 300.0)
        monkeypatch.setattr(mc, "is_sandboxed", lambda p: p == 701)   # P is gone by then
        monkeypatch.setattr(mc, "_proc_state", lambda p: "gone")
        monkeypatch.setattr(mc, "_alive", lambda p: False)
        sent = []
        monkeypatch.setattr(mc.os, "kill", lambda p, sig: sent.append(p))
        assert mc.sweep_sandboxed(lambda p: True, what="test") == 1
        assert sent == [701]

    def test_it_takes_several_conclusive_empty_rounds_to_finish(self, monkeypatch):
        calls = []
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: calls.append(1) or [])
        assert mc.sweep_sandboxed(lambda p: True, what="test") == 0
        assert len(calls) == mc.SWEEP_QUIET_ROUNDS

    def test_rounds_that_never_come_out_clean_fail_the_sweep(self, monkeypatch):
        # every round lists a process that is gone before it can be ruled out
        pids = iter(range(5000, 6000))
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: [next(pids)])
        monkeypatch.setattr(mc, "proc_start_time", lambda p: None)
        monkeypatch.setattr(mc, "_proc_state", lambda p: "gone")
        with pytest.raises(SandboxError, match="could not kill"):
            mc.sweep_sandboxed(lambda p: True, what="test", rounds=20)

    def test_a_zombie_does_not_keep_the_sweep_from_finishing(self, monkeypatch):
        monkeypatch.setattr(mc, "uid_pids", lambda uid=None: [4242])
        monkeypatch.setattr(mc, "proc_start_time", lambda p: None)
        monkeypatch.setattr(mc, "_proc_state", lambda p: "zombie")
        assert mc.sweep_sandboxed(lambda p: True, what="test", rounds=20) == 0


class TestKillFamilyChecksNewMembers:
    def _dog(self, proc, tables, starts):
        it = iter(tables)
        return mc.RssWatchdog(proc, 1 << 30, table_fn=lambda: next(it, []),
                              start_fn=lambda p: starts.get(p))

    def test_a_member_first_found_at_kill_time_is_reconfirmed_before_the_signal(self, monkeypatch):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            pgid = os.getpgid(proc.pid)
            child = mc._Proc(pid=999_991, ppid=proc.pid, pgid=pgid, rss=0)
            # the scan finds the child; by the re-check its pid belongs to an unrelated process
            dog = self._dog(proc, [[child], [mc._Proc(pid=999_991, ppid=1, pgid=1, rss=0)]],
                            {999_991: 500.0})
            sent = []
            monkeypatch.setattr(mc.os, "killpg", lambda g, sig: None)
            monkeypatch.setattr(mc.os, "kill", lambda p, sig: sent.append(p))
            dog.kill_family()
            assert sent == []
        finally:
            proc.kill()
            proc.wait()

    def test_a_confirmed_new_member_is_killed(self, monkeypatch):
        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            pgid = os.getpgid(proc.pid)
            child = mc._Proc(pid=999_991, ppid=proc.pid, pgid=pgid, rss=0)
            dog = self._dog(proc, [[child], [child]], {999_991: 500.0})
            sent = []
            monkeypatch.setattr(mc.os, "killpg", lambda g, sig: None)
            monkeypatch.setattr(mc.os, "kill", lambda p, sig: sent.append(p))
            dog.kill_family()
            assert sent == [999_991]
        finally:
            proc.kill()
            proc.wait()


class TestFinalDiskSample:
    @macos_launcher
    def test_a_burst_after_the_last_sample_fails_the_run(self, tmp_path, monkeypatch):
        # each file is under RLIMIT_FSIZE (= tmpfs_bytes); together they are over the limit.
        # The watchdog never samples (as if the burst landed between samples and the run
        # exited): the final measurement must still catch it.
        monkeypatch.setattr(mc.RssWatchdog, "_loop", lambda self: None)
        w = tmp_path / "w"
        w.mkdir()
        r = mc.run_confined(
            ["/bin/sh", "-c", f'head -c 600000 /dev/zero > "{w}/a"; head -c 600000 /dev/zero > "{w}/b"'],
            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=30, tmpfs_bytes=1_000_000),
            cwd=tmp_path, watch_dirs=[w])
        assert r.exit_code == 0
        assert r.killed
        assert b"writable dirs exceeded" in r.stderr

    @macos_launcher
    def test_a_run_under_the_limit_is_not_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc.RssWatchdog, "_loop", lambda self: None)
        w = tmp_path / "w"
        w.mkdir()
        r = mc.run_confined(["/bin/sh", "-c", f'head -c 1000 /dev/zero > "{w}/a"'],
                            env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=30, tmpfs_bytes=1_000_000),
                            cwd=tmp_path, watch_dirs=[w])
        assert r.exit_code == 0 and not r.killed


def _has_acl(path) -> bool:
    out = subprocess.run(["/bin/ls", "-led", str(path)], capture_output=True, text=True).stdout
    return any(line.strip().startswith("0:") for line in out.splitlines())


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")
class TestCopiesDropTheSourceACL:
    @pytest.mark.parametrize("clone", [True, False])
    def test_a_deny_delete_acl_does_not_reach_the_copy(self, tmp_path, monkeypatch, clone):
        if not clone:
            monkeypatch.setattr(mc, "_CLONEFILE", None)
        src = tmp_path / "staged"
        src.write_bytes(b"x" * 4096)
        dst = tmp_path / "copy"
        try:
            subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(src)], check=True)
            assert _has_acl(src)
            mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
            assert dst.read_bytes() == b"x" * 4096
            assert not _has_acl(dst)
            os.unlink(dst)                  # deletable: nothing undeletable left behind
        finally:
            subprocess.run(["/bin/chmod", "-N", str(src)], check=False)
            for p in (src, dst):
                if os.path.lexists(p):
                    subprocess.run(["/bin/chmod", "-N", str(p)], check=False)

    def test_a_clone_that_carries_the_acl_has_it_stripped(self, tmp_path, monkeypatch):
        # clonefile(2) on current macOS doesn't copy the ACL, but nothing promises that (and
        # it does carry flags and modes): a clone that brings the source's ACL along must not
        # put an undeletable file into the host tree.
        def acl_clone(fd, dirfd, d, flags):
            with open(d, "wb") as f:
                f.write(os.pread(fd, 1 << 20, 0))
            subprocess.run(["/bin/chmod", "+a", "everyone deny delete", os.fsdecode(d)], check=True)
            return 0
        monkeypatch.setattr(mc, "_CLONEFILE", acl_clone)
        src, dst = tmp_path / "staged", tmp_path / "copy"
        src.write_bytes(b"x")
        try:
            mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
            assert not _has_acl(dst)
            os.unlink(dst)
        finally:
            if os.path.lexists(dst):
                subprocess.run(["/bin/chmod", "-N", str(dst)], check=False)

    def test_a_clone_whose_acl_cannot_be_cleared_fails_the_copy(self, tmp_path, monkeypatch):
        if mc._CLONEFILE is None:
            pytest.skip("no clonefile")
        monkeypatch.setattr(mc, "_STRIP_ACL", lambda p: -1)
        src = tmp_path / "staged"
        src.write_bytes(b"x")
        with pytest.raises(SandboxError, match="cannot clear the ACL"):
            mc.copy_no_follow(src, tmp_path / "copy", budget_bytes=1 << 20)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")
class TestRemoveTreeUnlocks:
    def test_a_tree_holding_a_deny_delete_acl_is_removed(self, tmp_path):
        # e.g. a copy-back's half-built replacement, abandoned after a staged file's ACL could
        # not be cleared: it must not stay behind on the host
        d = tmp_path / ".blastbox-copyback-x"
        (d / "sub").mkdir(parents=True)
        f = d / "sub" / "locked"
        f.write_bytes(b"x")
        subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(f)], check=True)
        subprocess.run(["/bin/chmod", "+a", "everyone deny delete_child", str(d / "sub")], check=True)
        try:
            mc.remove_tree(d)
            assert not os.path.lexists(d)
        finally:
            if os.path.lexists(d):
                subprocess.run(["/bin/chmod", "-RN", str(d)], check=False)


class TestPinnedWatchRoots:
    def test_roots_swapped_right_after_launch_are_still_measured(self, tmp_path):
        # The child swaps the first rw root for a symlink to the second before the watchdog is
        # built: resolved after launch, both spellings would name one tree and the real second
        # root would go unmetered. Pinned before launch, both trees are measured.
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (b / "big").write_bytes(b"x" * 3_000_000)

        def popen(*args, **kw):
            p = subprocess.Popen(*args, **kw)
            a.rmdir()
            a.symlink_to(b)
            return p
        r = mc.run_confined(["/bin/sleep", "1"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=20, tmpfs_bytes=2_000_000), cwd=tmp_path,
                            popen=popen, watch_dirs=[a, b])
        assert r.killed and b"writable dirs exceeded" in r.stderr

    def test_a_pinned_root_is_measured_wherever_its_path_goes(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        roots = mc.pin_watch_roots([d])
        try:
            d.rename(tmp_path / "moved")
            d.symlink_to(tmp_path / "elsewhere")
            (tmp_path / "moved" / "f").write_bytes(b"x" * 100_000)
            used, entries, complete = mc.dir_usage(roots, 1000)
            assert complete and entries == 1 and used >= 100_000
        finally:
            mc.close_watch_roots(roots)
        assert roots[0].fd is None

    def test_a_file_root_is_measured_by_path(self, tmp_path):
        f = tmp_path / "f"
        f.write_bytes(b"x" * 10_000)
        roots = mc.pin_watch_roots([f])
        try:
            assert roots[0].fd is None
            assert mc.dir_usage(roots, 1000)[1:] == (1, True)
        finally:
            mc.close_watch_roots(roots)


class TestTimeoutKill:
    @macos_launcher
    def test_the_timeout_path_never_kills_by_a_bare_group_lookup(self, tmp_path, monkeypatch):
        # After the leader is reaped (the watchdog's poll() can do it at the timeout boundary)
        # getpgid(leader pid) may name another job's group: only identity-gated kills remain.
        import blastbox.worker.sandbox.base as base
        calls: list[object] = []
        monkeypatch.setattr(base, "kill_sandbox_group", calls.append)
        monkeypatch.setattr(mc, "kill_sandbox_group", calls.append, raising=False)
        t0 = time.monotonic()
        r = mc.run_confined(["/bin/sleep", "30"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=1), cwd=tmp_path)
        assert r.killed and r.exit_code == -9
        assert time.monotonic() - t0 < 15
        assert calls == []


class TestEmergencyCleanup:
    def test_an_emergency_cleanup_kills_a_run_in_flight(self, tmp_path):
        from blastbox.worker.sandbox import base
        out: dict[str, object] = {}
        t = threading.Thread(target=lambda: out.update(r=mc.run_confined(
            ["/bin/sleep", "60"], env={"PATH": mc.MINIMAL_PATH},
            limits=Limits(timeout_s=60), cwd=tmp_path)))
        t.start()
        deadline = time.monotonic() + 10
        while not base._EMERGENCY and time.monotonic() < deadline:
            time.sleep(0.01)
        assert base.run_emergency_cleanups(10) == 1
        t.join(15)
        assert not t.is_alive()
        assert out["r"].exit_code == -9          # type: ignore[attr-defined]
        assert base._EMERGENCY == {}             # unregistered when the run ended

    def test_the_emergency_cleanup_covers_the_child_from_its_spawn(self, tmp_path):
        # The deadline passes while the child is being spawned: the cleanup is already
        # registered, waits for the spawn to finish, and kills it (and sweeps).
        from blastbox.worker.sandbox import base
        swept: list[bool] = []
        seen_registered: list[int] = []
        ran: dict[str, int] = {}

        def popen(*a, **kw):
            seen_registered.append(len(base._EMERGENCY))
            t = threading.Thread(target=lambda: ran.update(n=base.run_emergency_cleanups(10)))
            t.start()
            time.sleep(0.3)           # the emergency fires mid-spawn
            return subprocess.Popen(*a, **kw)

        t0 = time.monotonic()
        r = mc.run_confined(["/bin/sleep", "60"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=30), cwd=tmp_path, popen=popen,
                            sweep=lambda: swept.append(True))
        assert seen_registered == [1]            # registered before Popen ran
        assert r.exit_code == -9 and time.monotonic() - t0 < 15
        deadline = time.monotonic() + 5
        while "n" not in ran and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ran["n"] == 1
        assert swept                              # the emergency path swept too
        assert base._EMERGENCY == {}

    def test_a_failed_set_up_after_spawn_kills_the_child(self, tmp_path, monkeypatch):
        from blastbox.worker.sandbox import base
        procs: list[subprocess.Popen] = []
        swept: list[bool] = []

        def popen(*a, **kw):
            procs.append(subprocess.Popen(*a, **kw))
            return procs[-1]

        def boom(*a, **kw):
            raise RuntimeError("watchdog set-up failed")

        monkeypatch.setattr(mc, "RssWatchdog", boom)
        with pytest.raises(RuntimeError, match="set-up failed"):
            mc.run_confined(["/bin/sleep", "60"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=30), cwd=tmp_path, popen=popen,
                            sweep=lambda: swept.append(True))
        assert procs and procs[0].wait(5) == -9
        assert swept and base._EMERGENCY == {}

    def test_a_hung_cleanup_does_not_hold_the_exit(self):
        from blastbox.worker.sandbox import base
        release = threading.Event()
        token = base.register_emergency_cleanup(lambda: release.wait(10))
        try:
            t0 = time.monotonic()
            assert base.run_emergency_cleanups(0.2) == 0
            assert time.monotonic() - t0 < 2
        finally:
            release.set()
            base.unregister_emergency_cleanup(token)

    def test_nothing_registered_is_a_no_op(self):
        from blastbox.worker.sandbox import base
        assert base._EMERGENCY == {}
        assert base.run_emergency_cleanups(5) == 0


class TestKillThenSweep:
    def test_the_sweep_runs_even_when_the_family_kill_raises(self, tmp_path, monkeypatch):
        swept: list[bool] = []

        def kill_family(self):
            raise RuntimeError("family kill failed")

        monkeypatch.setattr(mc.RssWatchdog, "kill_family", kill_family)
        with pytest.raises(RuntimeError, match="family kill failed"):
            mc.run_confined(["/usr/bin/true"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=10), cwd=tmp_path,
                            sweep=lambda: swept.append(True))
        assert swept == [True]

    def test_the_emergency_sweep_runs_even_when_the_family_kill_raises(self, tmp_path,
                                                                       monkeypatch):
        from blastbox.worker.sandbox import base
        swept: list[bool] = []
        real_kill = mc.RssWatchdog.kill_family
        calls = {"n": 0}

        def kill_family(self):
            calls["n"] += 1
            if calls["n"] == 1:         # the emergency's kill
                raise RuntimeError("family kill failed")
            real_kill(self)

        monkeypatch.setattr(mc.RssWatchdog, "kill_family", kill_family)
        out: dict[str, object] = {}
        t = threading.Thread(target=lambda: out.update(r=mc.run_confined(
            ["/bin/sleep", "3"], env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=30),
            cwd=tmp_path, sweep=lambda: swept.append(True))))
        t.start()
        deadline = time.monotonic() + 10
        while not base._EMERGENCY and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.3)
        assert base.run_emergency_cleanups(10) == 0     # it raised ...
        assert swept                                     # ... but still swept
        t.join(15)
        assert not t.is_alive()


class TestSeenIsThreadSafe:
    def test_kill_targets_survive_concurrent_membership_changes(self, tmp_path):
        # The sampling thread adds and drops members while a timeout/emergency cleanup lists
        # them: that listing must never raise "dictionary changed size during iteration".
        leader = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        old_switch = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)          # switch threads as often as possible
        try:
            gone: set[int] = set()
            dog = mc.RssWatchdog(leader, 1 << 40, table_fn=lambda: [],
                                 start_fn=lambda pid: None if pid in gone else 1.0)
            dog._remember(range(1_000_000, 1_020_000))      # a long dict to iterate
            stop = threading.Event()

            def churn():
                # what samples do: remember new members, forget ones that exited
                i = 0
                while not stop.is_set():
                    dog._remember(range(2_000_000 + i * 20, 2_000_000 + i * 20 + 20))
                    gone.update(range(2_000_000 + (i - 2) * 20, 2_000_000 + (i - 1) * 20))
                    dog._seen_alive()
                    i += 1

            th = threading.Thread(target=churn, daemon=True)
            th.start()
            try:
                for _ in range(200):
                    dog._kill_targets()
            finally:
                stop.set()
                th.join(5)
        finally:
            sys.setswitchinterval(old_switch)
            leader.kill()
            leader.wait()


class TestFdListing:
    """A process caught exiting (or execing) can fail PROC_PIDLISTFDS with ENOTSUP before it is
    a zombie: that is not a reason to kill the whole run for disk."""

    class _Lib:
        def __init__(self, fails: int) -> None:
            self.fails = fails

        def proc_pidinfo(self, pid, flavor, arg, buf, size):
            if self.fails > 0:
                self.fails -= 1
                return 0
            return ctypes.sizeof(mc._ProcFdInfo)

    def _patch(self, monkeypatch, fails, state, started=1.0):
        lib = self._Lib(fails)
        monkeypatch.setattr(mc, "_LIBSYSTEM", lib)
        monkeypatch.setattr(ctypes, "get_errno", lambda: errno.ENOTSUP)
        monkeypatch.setattr(mc, "_proc_state", lambda pid: state)
        monkeypatch.setattr(mc, "proc_start_time", lambda pid: started)
        return lib

    def test_a_transient_failure_is_retried(self, monkeypatch):
        self._patch(monkeypatch, fails=2, state="alive")
        listed = mc._list_fds(4242)
        assert listed is not None and listed[1] == ctypes.sizeof(mc._ProcFdInfo)

    def test_an_exiting_process_holds_nothing(self, monkeypatch):
        for state in ("zombie", "gone"):
            self._patch(monkeypatch, fails=99, state=state)
            assert mc._list_fds(4242) is None
        self._patch(monkeypatch, fails=99, state="alive", started=None)
        assert mc._list_fds(4242) is None

    @pytest.mark.skipif(not mc.IS_DARWIN, reason="needs libproc")
    def test_a_process_with_no_descriptors_holds_nothing(self):
        # A child that closed its stdio has an empty table: proc_pidinfo returns 0 with no
        # error. That is an answer (nothing held), not a failure that kills the run for disk.
        p = subprocess.Popen(["/usr/bin/perl", "-e", "close STDIN; close STDOUT; close STDERR; "
                              "sleep 30"], close_fds=True)
        try:
            time.sleep(0.5)
            assert mc._list_fds(p.pid) is not None
            assert mc.held_unlinked_bytes([p.pid]) == 0
        finally:
            p.kill()
            p.wait()

    def test_a_live_process_that_keeps_failing_fails_closed(self, monkeypatch):
        lib = self._patch(monkeypatch, fails=99, state="alive")
        with pytest.raises(SandboxError, match="cannot list pid 4242's open files"):
            mc._list_fds(4242)
        assert lib.fails == 99 - mc._FD_LIST_TRIES        # one (failed) sizing call per try


class TestSymlinksAreChargedTheirTargetText:
    """A link stores its target: a tree of long symlinks must not copy (back) unmetered."""

    def test_long_symlinks_exhaust_a_small_byte_budget(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(5):
            (src / f"l{i}").symlink_to("x" * 200)
        with pytest.raises(SandboxError, match="exceeds budget of 500 bytes"):
            mc.copy_no_follow(src, tmp_path / "dst", budget_bytes=500)

    def test_each_link_still_counts_as_an_entry(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(3):
            (src / f"l{i}").symlink_to("t")
        budget = mc.CopyBudget(1 << 20)
        mc.copy_no_follow(src, tmp_path / "dst", budget=budget)
        assert budget.entries == 4 and budget.bytes == 3     # the dir + 3 links, 1 byte each

    def test_a_capture_charges_symlinks_too(self, tmp_path):
        scratch = tmp_path / "scratch"
        (scratch / "Library").mkdir(parents=True)
        for i in range(5):
            (scratch / "Library" / f"l{i}").symlink_to("y" * 300)
        with pytest.raises(SandboxError, match="exceeds budget"):
            mc.capture_scratch(scratch, tmp_path / "cap", budget_bytes=1000)
        assert not (tmp_path / "cap").exists()


class TestCaptureListsItsSibling:
    def test_listed_while_building_and_dropped_once_swapped_in(self, tmp_path, monkeypatch):
        scratch = tmp_path / "scratch"
        (scratch / "Library").mkdir(parents=True)
        (scratch / "Library" / "f").write_text("x")
        leftovers = mc.Leftovers()
        during: list[list] = []
        real = mc.copy_no_follow

        def copy(src, dst, **kw):
            during.append(list(leftovers._paths))
            return real(src, dst, **kw)
        monkeypatch.setattr(mc, "copy_no_follow", copy)
        mc.capture_scratch(scratch, tmp_path / "cap", 1 << 20, leftovers)
        assert len(during[0]) == 1 and during[0][0].name.startswith(".cap.capture-")
        assert leftovers._paths == set()
        assert (tmp_path / "cap" / "Library" / "f").read_text() == "x"

    def test_remove_all_deletes_what_an_interrupted_step_left(self, tmp_path):
        leftovers = mc.Leftovers()
        half = tmp_path / ".half"
        (half / "d").mkdir(parents=True)
        (half / "d" / "f").write_text("x")
        leftovers.add(half)
        leftovers.remove_all()
        assert not half.exists() and leftovers._paths == set()


class TestNestedEmergencyCleanupsRunInOrder:
    """run_confined's family cleanup is registered inside a backend's run-wide one, on the same
    thread. Run side by side they raced: the inner sweep restores the scratch root each round
    while the outer cleanup removes it. A family now runs on one thread, innermost first."""

    def test_the_inner_cleanup_finishes_before_the_outer_one_starts(self, tmp_path):
        from blastbox.worker.sandbox import base
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        order: list[str] = []

        def inner():                     # a late sweep round puts the scratch back
            time.sleep(0.3)
            scratch.mkdir(exist_ok=True)
            order.append("inner")

        def outer():
            order.append("outer")
            shutil.rmtree(scratch, ignore_errors=True)

        t_outer = base.register_emergency_cleanup(outer)
        t_inner = base.register_emergency_cleanup(inner)
        try:
            assert base.run_emergency_cleanups(10) == 2
        finally:
            base.unregister_emergency_cleanup(t_inner)
            base.unregister_emergency_cleanup(t_outer)
        assert order == ["inner", "outer"]
        assert not scratch.exists()      # nothing recreated it after the outer cleanup

    def test_unrelated_runs_still_clean_up_in_parallel(self):
        from blastbox.worker.sandbox import base
        both = threading.Barrier(2, timeout=5)
        tokens: list[int] = []
        hold = threading.Event()
        registered = threading.Barrier(3, timeout=5)

        def run_on_its_own_thread():
            tokens.append(base.register_emergency_cleanup(both.wait))
            registered.wait()
            hold.wait(10)

        threads = [threading.Thread(target=run_on_its_own_thread) for _ in range(2)]
        for t in threads:
            t.start()
        try:
            registered.wait()
            # sequential would leave each waiting for the other at the barrier
            assert base.run_emergency_cleanups(10) == 2
        finally:
            hold.set()
            for t in threads:
                t.join()
            for tok in tokens:
                base.unregister_emergency_cleanup(tok)

    def test_a_cleanup_whose_outer_one_is_gone_runs_on_its_own(self):
        from blastbox.worker.sandbox import base
        ran: list[str] = []
        t_outer = base.register_emergency_cleanup(lambda: ran.append("outer"))
        t_inner = base.register_emergency_cleanup(lambda: ran.append("inner"))
        base.unregister_emergency_cleanup(t_outer)
        try:
            assert base.run_emergency_cleanups(5) == 1
        finally:
            base.unregister_emergency_cleanup(t_inner)
        assert ran == ["inner"]
        # and the thread's stack is clean: a new registration is a root again
        t = base.register_emergency_cleanup(lambda: None)
        try:
            assert base._EMERGENCY_PARENT[t] is None
        finally:
            base.unregister_emergency_cleanup(t)


class TestFindSpecialEntry:
    def test_finds_a_nested_fifo_and_ignores_regular_trees(self, tmp_path):
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a" / "f").write_text("x")
        (tmp_path / "a" / "l").symlink_to("/dev/null")       # a link TO a device: not followed
        assert mc.find_special_entry(tmp_path) is None
        os.mkfifo(tmp_path / "a" / "b" / "p")
        assert mc.find_special_entry(tmp_path) == tmp_path / "a" / "b" / "p"

    def test_a_special_root_is_found(self, tmp_path):
        os.mkfifo(tmp_path / "p")
        assert mc.find_special_entry(tmp_path / "p") == tmp_path / "p"


class TestFindSplitHardLink:
    """Every name of a multiply-linked file under the writable mounts must be inside them:
    one elsewhere would be changed through the writable name (Seatbelt), or cut from the host's
    file by the copy-back (App Sandbox)."""

    def test_a_group_inside_one_root_is_complete(self, tmp_path):
        w = tmp_path / "w"
        (w / "d").mkdir(parents=True)
        (w / "a").write_text("x")
        os.link(w / "a", w / "d" / "b")
        assert mc.find_split_hard_link([w]) is None

    def test_a_group_across_two_roots_is_complete(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "f").write_text("x")
        os.link(a / "f", b / "g")
        assert mc.find_split_hard_link([a, b]) is None

    def test_a_name_outside_the_roots_is_found(self, tmp_path):
        w = tmp_path / "w"
        w.mkdir()
        (tmp_path / "outside").write_text("x")
        os.link(tmp_path / "outside", w / "inside")
        assert mc.find_split_hard_link([w]) == w / "inside"

    def test_a_file_mount_is_checked_too(self, tmp_path):
        (tmp_path / "f").write_text("x")
        os.link(tmp_path / "f", tmp_path / "g")
        assert mc.find_split_hard_link([tmp_path / "f"]) == tmp_path / "f"
        assert mc.find_split_hard_link([tmp_path / "f", tmp_path / "g"]) is None

    def test_a_nested_root_is_walked_once(self, tmp_path):
        # walked twice, the inner name would count twice and hide the outside one
        w = tmp_path / "w"
        (w / "x").mkdir(parents=True)
        (tmp_path / "outside").write_text("x")
        os.link(tmp_path / "outside", w / "x" / "f")
        assert mc.find_split_hard_link([w, w / "x"]) == w / "x" / "f"

    def test_symlinks_are_not_followed(self, tmp_path):
        w = tmp_path / "w"
        w.mkdir()
        (tmp_path / "outside").write_text("x")
        os.link(tmp_path / "outside", tmp_path / "outside2")
        (w / "l").symlink_to(tmp_path / "outside")
        assert mc.find_split_hard_link([w]) is None

    def test_too_many_entries_fail_closed(self, tmp_path):
        w = tmp_path / "w"
        w.mkdir()
        for i in range(5):
            (w / f"f{i}").write_text("")
        with pytest.raises(SandboxError, match="can't all be checked"):
            mc.find_split_hard_link([w], max_entries=3)


class TestSaturatedListingsAreRetried:
    """Codex P2 (#198): a listing that fills its buffer may be truncated (the uid's processes, or
    a pid's descriptors, grew between the sizing call and the listing). A sweep that read a
    truncated process list could miss an escaped child: retry larger, then fail closed."""

    class _Lib:
        def __init__(self, pids, full_times):
            self.pids, self.full_times, self.calls = pids, full_times, 0

        def proc_listpids(self, kind, uid, buf, size):
            if buf is None:
                return len(self.pids) * 4
            self.calls += 1
            if self.calls <= self.full_times:
                return size                     # filled to the brim: maybe truncated
            for i, p in enumerate(self.pids):
                buf[i] = p
            return len(self.pids) * 4

    def test_a_full_buffer_is_retried_larger(self, monkeypatch):
        lib = self._Lib([11, 12, 13], full_times=2)
        monkeypatch.setattr(mc, "_LIBSYSTEM", lib)
        assert mc.uid_pids(501) == [11, 12, 13]
        assert lib.calls == 3

    def test_a_buffer_that_stays_full_fails_closed(self, monkeypatch):
        monkeypatch.setattr(mc, "_LIBSYSTEM", self._Lib([11], full_times=10 ** 6))
        with pytest.raises(SandboxError, match="kept filling"):
            mc.uid_pids(501)

    def test_a_full_descriptor_table_is_listed_again(self, monkeypatch):
        sizes: list[int] = []

        class _Lib:
            def proc_pidinfo(self, pid, flavor, arg, buf, size):
                if buf is None:
                    return 8 * ctypes.sizeof(mc._ProcFdInfo)
                sizes.append(size)
                return size if len(sizes) == 1 else 3 * ctypes.sizeof(mc._ProcFdInfo)

        monkeypatch.setattr(mc, "_LIBSYSTEM", _Lib())
        listed = mc._list_fds(4242)
        assert listed is not None and listed[1] == 3 * ctypes.sizeof(mc._ProcFdInfo)
        assert len(sizes) == 2


class TestCopierNeverFollowsASwappedSource:
    """Codex P1 (#198): the copier classifies an entry with lstat and then reads it. A source
    another run can still write may swap a directory (or file) for a symlink in between; the
    walk is pinned to O_NOFOLLOW descriptors, so the swap is refused, never followed."""

    def _swap_on_open(self, monkeypatch, victim: str, target):
        real_open = os.open

        def opener(path, flags, mode=0o777, *, dir_fd=None):
            if os.fspath(path) == victim and dir_fd is not None:
                os.rename(victim, victim + ".moved", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                os.symlink(target, victim, dir_fd=dir_fd)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(mc.os, "open", opener)

    def test_a_directory_swapped_for_a_symlink_is_not_followed(self, tmp_path, monkeypatch):
        secret = tmp_path / "secret"
        secret.mkdir()
        (secret / "key").write_text("host secret")
        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f").write_text("x")
        self._swap_on_open(monkeypatch, "sub", str(secret))
        dst = tmp_path / "dst"
        with pytest.raises(SandboxError, match="changed while it was being copied"):
            mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
        assert not any(p.name == "key" for p in dst.rglob("*"))

    def test_a_file_swapped_for_a_symlink_is_not_followed(self, tmp_path, monkeypatch):
        secret = tmp_path / "secret"
        secret.write_text("host secret")
        src = tmp_path / "src"
        src.mkdir()
        (src / "f").write_text("x")
        self._swap_on_open(monkeypatch, "f", str(secret))
        dst = tmp_path / "dst"
        with pytest.raises(SandboxError, match="changed while it was being copied"):
            mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
        assert not (dst / "f").exists() or (dst / "f").read_text() != "host secret"

    def test_an_untouched_tree_still_copies(self, tmp_path):
        src = tmp_path / "src"
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "b" / "f").write_text("data")
        (src / "l").symlink_to("a/b/f")
        dst = tmp_path / "dst"
        mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
        assert (dst / "a" / "b" / "f").read_text() == "data"
        assert os.readlink(dst / "l") == "a/b/f"


class TestOnlyRecordedDoneTreesAreRemoved:
    """Codex P2 (#198): a `.blastbox-copyback-done-*` NAME proves nothing -- the owner or a child
    may have made it. Cleanup removes only a tree this worker recorded (directory, name, device,
    inode) before renaming it; anything else is refused, not deleted."""

    @staticmethod
    def _interrupted(tmp_path, monkeypatch, src):
        # a copy-back whose final removal of the replaced contents was cut short
        old = src / f"{mc.COPY_BACK_MARK}old-abcd"
        old.mkdir(parents=True)
        _need_done_tags(old)
        (old / "earlier-run").write_text("x")
        done = src / f"{mc.COPY_BACK_MARK}done-abcd"
        monkeypatch.setattr(mc, "remove_tree", lambda p: None)
        with pytest.raises(SandboxError, match="could not remove"):
            mc.retire_replaced(old, done, None)
        monkeypatch.undo()
        return done

    def test_a_recorded_done_tree_is_removed_before_staging(self, tmp_path, monkeypatch):
        records = mc.DONE_RECORD_DIR
        src = tmp_path / "data"
        done = self._interrupted(tmp_path, monkeypatch, src)
        monkeypatch.setattr(mc, "DONE_RECORD_DIR", records)
        assert done.exists() and list(records.iterdir())
        assert mc.clear_stale_copy_backs(src) is None
        assert not done.exists()
        assert list(records.iterdir()) == []                # record dropped with it

    def test_a_done_name_with_another_inode_is_refused(self, tmp_path, monkeypatch):
        records = mc.DONE_RECORD_DIR
        src = tmp_path / "data"
        done = self._interrupted(tmp_path, monkeypatch, src)
        monkeypatch.setattr(mc, "DONE_RECORD_DIR", records)
        mc.remove_tree(done)
        done.mkdir()                                        # the user's own, same name
        (done / "keep").write_text("mine")
        assert mc.clear_stale_copy_backs(src) == done
        assert (done / "keep").read_text() == "mine"

    def test_a_record_in_another_directory_does_not_count(self, tmp_path, monkeypatch):
        records = mc.DONE_RECORD_DIR
        self._interrupted(tmp_path, monkeypatch, tmp_path / "a")
        monkeypatch.setattr(mc, "DONE_RECORD_DIR", records)
        other = tmp_path / "b" / f"{mc.COPY_BACK_MARK}done-abcd"
        other.mkdir(parents=True)
        assert mc.clear_stale_copy_backs(tmp_path / "b") == other
        assert other.exists()

    def test_a_completed_retire_leaves_no_record(self, tmp_path):
        old = tmp_path / "d" / f"{mc.COPY_BACK_MARK}old-x"
        old.mkdir(parents=True)
        mc.retire_replaced(old, old.with_name(f"{mc.COPY_BACK_MARK}done-x"), None)
        assert list((tmp_path / "d").iterdir()) == []
        assert list(mc.DONE_RECORD_DIR.iterdir()) == []

    def test_a_record_whose_tree_is_gone_is_pruned(self, tmp_path, monkeypatch):
        records = mc.DONE_RECORD_DIR
        src = tmp_path / "data"
        done = self._interrupted(tmp_path, monkeypatch, src)
        monkeypatch.setattr(mc, "DONE_RECORD_DIR", records)
        mc.remove_tree(done)                                # an emergency cleanup finished it
        assert mc.clear_stale_copy_backs(src) is None
        assert list(records.iterdir()) == []


class TestCaptureFallbackSwapRecordsTheOldTree:
    """Codex P2 (#198): where RENAME_SWAP is unsupported, the capture swap renames the previous
    capture aside. It is now renamed `done-` with a record, listed in `leftovers` while removed,
    and a later capture of the same destination removes it if the worker died first."""

    @staticmethod
    def _scratch(tmp_path, text):
        scratch = tmp_path / f"scratch-{text}"
        (scratch / "Library").mkdir(parents=True)
        (scratch / "Library" / "f").write_text(text)
        return scratch

    def test_the_old_capture_is_listed_while_removed(self, tmp_path, monkeypatch):
        _need_done_tags(tmp_path)
        monkeypatch.setattr(mc, "_renamex_np", lambda: None)
        dest = tmp_path / "cache"
        mc.capture_scratch(self._scratch(tmp_path, "one"), dest, 1 << 20)
        leftovers = mc.Leftovers()
        seen: list[set] = []
        real = mc.remove_tree
        monkeypatch.setattr(mc, "remove_tree",
                            lambda p: (seen.append(set(leftovers._paths)), real(p))[1])
        mc.capture_scratch(self._scratch(tmp_path, "two"), dest, 1 << 20, leftovers)
        assert any(any("done-" in q.name for q in paths) for paths in seen)
        assert (dest / "Library" / "f").read_text() == "two"
        assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".cache")) == []
        assert leftovers._paths == set()

    def test_an_interrupted_removal_is_finished_by_the_next_capture(self, tmp_path, monkeypatch):
        _need_done_tags(tmp_path)
        monkeypatch.setattr(mc, "_renamex_np", lambda: None)
        dest = tmp_path / "cache"
        mc.capture_scratch(self._scratch(tmp_path, "one"), dest, 1 << 20)
        real = mc.remove_tree
        monkeypatch.setattr(mc, "remove_tree",
                            lambda p: None if "done-" in p.name else real(p))
        with pytest.raises(SandboxError, match="could not remove"):
            mc.capture_scratch(self._scratch(tmp_path, "two"), dest, 1 << 20)
        left = [p for p in tmp_path.iterdir() if "done-" in p.name]
        assert len(left) == 1
        monkeypatch.setattr(mc, "remove_tree", real)
        mc.capture_scratch(self._scratch(tmp_path, "three"), dest, 1 << 20)
        assert not left[0].exists()
        assert (dest / "Library" / "f").read_text() == "three"

    def test_an_unrecorded_sibling_is_left_alone(self, tmp_path):
        dest = tmp_path / "cache"
        mine = tmp_path / f".cache{mc.COPY_BACK_MARK}done-user"
        mine.mkdir()
        mc.capture_scratch(self._scratch(tmp_path, "one"), dest, 1 << 20)
        assert mine.exists()


def _xattr_name() -> bytes:
    return b"com.example.blastbox-test" if sys.platform == "darwin" else b"user.blastbox-test"


def _xattrs_supported(path) -> bool:
    try:
        mc._xattr_set(path, _xattr_name(), b"probe")
    except OSError:
        return False
    return True


def _xattr_of(path) -> bytes:
    fd = os.open(path, os.O_RDONLY)
    try:
        return mc._xattr_get(fd, _xattr_name())
    finally:
        os.close(fd)


class TestByteCopyKeepsExtendedAttributes:
    """Codex P2 (#198): where a clone isn't possible (another volume, a non-APFS filesystem) the
    byte copy dropped extended attributes, so a copy-back stripped them from the host even after
    a no-op run. They are copied from the pinned fd, charged to the budget, and one that can't
    be reproduced fails the copy instead of vanishing."""

    @pytest.fixture
    def tree(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "_CLONEFILE", None)         # force the byte copy
        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f").write_text("data")
        if not _xattrs_supported(src / "sub" / "f"):
            pytest.skip("this filesystem has no user extended attributes")
        mc._xattr_set(src / "sub" / "f", _xattr_name(), b"file-value")
        mc._xattr_set(src / "sub", _xattr_name(), b"dir-value")
        return src

    def test_files_and_directories_keep_them(self, tmp_path, tree):
        dst = tmp_path / "dst"
        mc.copy_no_follow(tree, dst, budget_bytes=1 << 20)
        assert _xattr_of(dst / "sub" / "f") == b"file-value"
        assert _xattr_of(dst / "sub") == b"dir-value"

    def test_they_are_charged_to_the_budget(self, tmp_path, tree):
        budget = mc.CopyBudget(1 << 20)
        mc.copy_no_follow(tree, tmp_path / "dst", budget=budget)
        assert budget.bytes >= 4 + 2 * len(_xattr_name()) + len(b"file-value") + len(b"dir-value")
        small = 4 + len(_xattr_name()) + len(b"dir-value")   # the data and the dir's, not the file's
        with pytest.raises(SandboxError, match="budget"):
            mc.copy_no_follow(tree, tmp_path / "dst2", budget_bytes=small)

    def test_one_that_cannot_be_set_fails_the_copy(self, tmp_path, tree, monkeypatch):
        def refuse(path, name, value):
            raise OSError(1, "Operation not permitted")
        monkeypatch.setattr(mc, "_xattr_set", refuse)
        with pytest.raises(SandboxError, match="cannot copy extended attribute"):
            mc.copy_no_follow(tree, tmp_path / "dst", budget_bytes=1 << 20)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS resource forks")
    def test_a_resource_fork_survives(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "_CLONEFILE", None)
        f = tmp_path / "src" / "f"
        f.parent.mkdir()
        f.write_text("data")
        fork = os.urandom(70_000)
        mc._xattr_set(f, b"com.apple.ResourceFork", fork)
        mc.copy_no_follow(f.parent, tmp_path / "dst", budget_bytes=1 << 20)
        fd = os.open(tmp_path / "dst" / "f", os.O_RDONLY)
        try:
            assert mc._xattr_get(fd, b"com.apple.ResourceFork") == fork
        finally:
            os.close(fd)


def _need_done_tags(path) -> None:
    """Skip where ``path``'s filesystem has no user extended attributes: retire_replaced then
    records nothing (by design), so the recorded-cleanup path can't be exercised there."""
    probe = path / ".xattr-probe"
    probe.write_text("")
    try:
        mc._xattr_set(probe, mc._DONE_XATTR, b"probe")
    except OSError:
        pytest.skip("no user extended attributes on this filesystem")
    finally:
        probe.unlink()


class TestDoneTreesCarryANonce:
    """Linux CI (#198): a freed inode number is reused at once (ext4/tmpfs give the next mkdir
    the same one), so a `done-` record matched by (name, device, inode) deleted an owner's own
    directory of that name made after the recorded tree was gone. A recorded tree now also
    carries a per-retire random nonce (an extended attribute, kept in the record); without it,
    nothing is deleted. Where the tag can't be set, nothing is recorded at all."""

    @staticmethod
    def _recorded(tmp_path, monkeypatch):
        src = tmp_path / "data"
        old = src / f"{mc.COPY_BACK_MARK}old-n"
        old.mkdir(parents=True)
        _need_done_tags(old)
        done = src / f"{mc.COPY_BACK_MARK}done-n"
        with monkeypatch.context() as m:
            m.setattr(mc, "remove_tree", lambda p: None)
            with pytest.raises(SandboxError, match="could not remove"):
                mc.retire_replaced(old, done, None)
        return src, done

    @staticmethod
    def _record():
        recs = list(mc.DONE_RECORD_DIR.iterdir())
        assert len(recs) == 1
        return recs[0]

    def test_a_reused_inode_without_the_tag_is_refused(self, tmp_path, monkeypatch):
        import json
        src, done = self._recorded(tmp_path, monkeypatch)
        mc.remove_tree(done)
        done.mkdir()                                        # the owner's own, same name
        (done / "keep").write_text("mine")
        st = os.lstat(done)
        rec_path = self._record()                           # as if the inode number were reused
        rec = json.loads(rec_path.read_text())
        rec.update(dev=st.st_dev, ino=st.st_ino)
        rec_path.write_text(json.dumps(rec))
        assert mc.clear_stale_copy_backs(src) == done
        assert (done / "keep").read_text() == "mine"

    def test_a_wrong_tag_is_refused(self, tmp_path, monkeypatch):
        src, done = self._recorded(tmp_path, monkeypatch)
        mc._xattr_set(done, mc._DONE_XATTR, b"0" * 32)
        assert mc.clear_stale_copy_backs(src) == done
        assert done.exists()

    def test_the_tagged_tree_is_removed(self, tmp_path, monkeypatch):
        src, done = self._recorded(tmp_path, monkeypatch)
        assert "nonce" in __import__("json").loads(self._record().read_text())
        assert mc.clear_stale_copy_backs(src) is None
        assert not done.exists()
        assert list(mc.DONE_RECORD_DIR.iterdir()) == []

    def test_a_fifo_with_the_name_is_never_opened(self, tmp_path, monkeypatch):
        src, done = self._recorded(tmp_path, monkeypatch)
        mc.remove_tree(done)
        os.mkfifo(done)                                     # opening it would block the worker
        assert mc.clear_stale_copy_backs(src) == done
        assert stat.S_ISFIFO(os.lstat(done).st_mode)

    @staticmethod
    def _untaggable(monkeypatch):
        def refuse(path, name, value):
            raise OSError(errno.ENOTSUP, "no extended attributes here")
        monkeypatch.setattr(mc, "_xattr_set", refuse)

    def test_without_tags_the_tree_is_removed_unrecorded(self, tmp_path, monkeypatch):
        self._untaggable(monkeypatch)
        old = tmp_path / "d" / f"{mc.COPY_BACK_MARK}old-x"
        (old / "sub").mkdir(parents=True)
        leftovers = mc.Leftovers()
        mc.retire_replaced(old, old.with_name(f"{mc.COPY_BACK_MARK}done-x"), leftovers)
        assert list((tmp_path / "d").iterdir()) == []
        assert list(mc.DONE_RECORD_DIR.iterdir()) == []
        assert leftovers._paths == set()

    def test_without_tags_an_unfinished_removal_is_refused_later(self, tmp_path, monkeypatch):
        self._untaggable(monkeypatch)
        src = tmp_path / "data"
        old = src / f"{mc.COPY_BACK_MARK}old-x"
        old.mkdir(parents=True)
        leftovers = mc.Leftovers()
        with monkeypatch.context() as m:
            m.setattr(mc, "remove_tree", lambda p: None)
            with pytest.raises(SandboxError, match="could not remove"):
                mc.retire_replaced(old, old.with_name(f"{mc.COPY_BACK_MARK}done-x"), leftovers)
        assert old.exists()                                 # kept its old- name: never "garbage"
        assert old in leftovers._paths                      # the emergency cleanup still has it
        assert list(mc.DONE_RECORD_DIR.iterdir()) == []
        assert mc.clear_stale_copy_backs(src) == old        # refused, not deleted
        assert old.exists()


class TestPathClaimModes:
    """Codex P2 (#198): one per-user registry of the host paths live runs hold, for both native
    backends. A whole-tree replacement (write) excludes everything; a tree written in place
    (live) admits other live writers but no snapshot writer or seed reader; a seed (read)
    excludes only writers."""

    @pytest.mark.parametrize("held,wanted,conflict", [
        ("write", "write", True), ("write", "live", True), ("write", "read", True),
        ("live", "write", True), ("live", "live", False), ("live", "read", True),
        ("read", "write", True), ("read", "live", True), ("read", "read", False)])
    def test_the_conflict_matrix(self, tmp_path, held, wanted, conflict):
        home = tmp_path / "home"
        data = tmp_path / "data"
        (data / "sub").mkdir(parents=True)
        with mc.hold_path_claims([(held, data)], "test", home):
            if conflict:
                with pytest.raises(SandboxError, match="in use by another run"):
                    with mc.hold_path_claims([(wanted, data / "sub")], "test", home):
                        pass
            else:
                with mc.hold_path_claims([(wanted, data / "sub")], "test", home):
                    pass

    def test_disjoint_paths_never_conflict(self, tmp_path):
        home = tmp_path / "home"
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with mc.hold_path_claims([("write", a)], "test", home), \
                mc.hold_path_claims([("write", b)], "test", home):
            pass

    def test_a_claim_without_a_mode_is_read_as_a_writer(self, tmp_path):
        # a claim file in the older format (paths only) must never be ignored
        home = tmp_path / "home"
        data = tmp_path / "data"
        data.mkdir()
        import fcntl
        claim = mc.path_claims_dir(home) / "old.claim"
        fd = os.open(claim, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, os.fsencode(data.resolve()) + b"\0")
            with pytest.raises(SandboxError, match="in use by another run"):
                with mc.hold_path_claims([("read", data)], "test", home):
                    pass
        finally:
            os.close(fd)

    def test_an_unknown_mode_is_a_programming_error(self, tmp_path):
        with pytest.raises(ValueError):
            with mc.hold_path_claims([("borrow", tmp_path)], "test", tmp_path / "home"):
                pass

    def test_the_registry_is_internal_state(self, tmp_path):
        home = tmp_path / "home"
        assert mc.shared_state_dir(home) in mc.path_claims_dir(home).parents


class TestByteCopyPinsTheExtent:
    """Codex P2 (#198): the byte-copy fallback streamed to EOF, charging only the size first
    seen: a source still being appended to could be copied past the budget, or forever. It now
    copies exactly the extent it pinned at open, and a source that changes mid-copy fails it."""

    def test_a_file_growing_while_it_is_copied_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "_CLONEFILE", None)
        src = tmp_path / "src"
        src.write_bytes(b"a" * 3_000_000)
        real_read = os.read
        grown = []

        def read(fd, n):
            if not grown:
                grown.append(1)
                with open(src, "ab") as fh:
                    fh.write(b"b" * 5_000_000)
            return real_read(fd, n)
        monkeypatch.setattr(mc.os, "read", read)
        dst = tmp_path / "dst"
        with pytest.raises(SandboxError, match="changed while it was being copied"):
            mc.copy_no_follow(src, dst, budget_bytes=4_000_000)
        assert not dst.exists() or dst.stat().st_size <= 3_000_000

    def test_a_size_that_changed_since_the_stat_is_refused(self, tmp_path):
        src = tmp_path / "src"
        src.write_bytes(b"a" * 10)
        fd = os.open(src, os.O_RDONLY)
        try:
            with pytest.raises(SandboxError, match="changed while"):
                mc._copy_regular_fd(fd, tmp_path / "dst", 0o644, size=5)
        finally:
            os.close(fd)

    @pytest.mark.parametrize("clone", [True, False])
    def test_an_unchanged_file_copies_whole(self, tmp_path, monkeypatch, clone):
        if not clone:
            monkeypatch.setattr(mc, "_CLONEFILE", None)
        src = tmp_path / "src"
        src.write_bytes(os.urandom(3_000_123))
        mc.copy_no_follow(src, tmp_path / "dst", budget_bytes=4_000_000)
        assert (tmp_path / "dst").read_bytes() == src.read_bytes()


class TestCopiesKeepTimestamps:
    """Codex P2 (#198): a copy recreated every directory with fresh times, so even a no-op
    copy-back rewrote modification times through the host tree (build caches, backups and
    timestamp-keyed inputs go by them). Directories, files and links keep the source's."""

    @pytest.mark.parametrize("clone", [True, False])
    def test_the_tree_keeps_its_times(self, tmp_path, monkeypatch, clone):
        if not clone:
            monkeypatch.setattr(mc, "_CLONEFILE", None)
        src = tmp_path / "src"
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "b" / "f").write_text("x")
        (src / "a" / "link").symlink_to("b/f")
        old = 1_500_000_000_123_456_789
        links = os.utime in os.supports_follow_symlinks
        for p in [src / "a" / "b" / "f", src / "a" / "b", src / "a", src]:
            os.utime(p, ns=(old, old))
        if links:
            os.utime(src / "a" / "link", ns=(old, old), follow_symlinks=False)
        dst = tmp_path / "dst"
        mc.copy_no_follow(src, dst, budget_bytes=1 << 20)
        for rel in ["", "a", "a/b", "a/b/f", *(["a/link"] if links else [])]:
            assert os.stat(dst / rel, follow_symlinks=False).st_mtime_ns == old, rel


class TestSymlinkHopsAndPathForms:
    """Codex P1 (#198): the helpers behind the symlinked seed/capture refusal."""

    def test_hops_follow_chains_and_relative_links(self, tmp_path):
        real = tmp_path / "real"
        (real / "d").mkdir(parents=True)
        (tmp_path / "b").symlink_to("real")                  # relative
        (tmp_path / "a").symlink_to(tmp_path / "b")          # absolute, to another link
        hops = mc.symlink_hops(tmp_path / "a" / "d")
        base = tmp_path.resolve()
        assert base / "a" in hops and base / "b" in hops

    def test_dotdot_after_a_link_is_the_targets_parent(self, tmp_path):
        (tmp_path / "x" / "y").mkdir(parents=True)
        (tmp_path / "l").symlink_to(tmp_path / "x" / "y")
        (tmp_path / "x" / "z").symlink_to(tmp_path)          # reached only via l/..
        hops = mc.symlink_hops(tmp_path / "l" / ".." / "z")
        assert tmp_path.resolve() / "x" / "z" in hops

    def test_a_loop_is_refused(self, tmp_path):
        (tmp_path / "p").symlink_to(tmp_path / "q")
        (tmp_path / "q").symlink_to(tmp_path / "p")
        with pytest.raises(SandboxError, match="too many levels"):
            mc.symlink_hops(tmp_path / "p" / "x")

    def test_path_forms_keeps_both_spellings(self, tmp_path):
        (tmp_path / "t").mkdir()
        (tmp_path / "s").symlink_to(tmp_path / "t")
        from pathlib import Path
        forms = mc.path_forms(tmp_path / "s")
        assert Path(os.path.abspath(tmp_path / "s")) in forms
        assert (tmp_path / "t").resolve() in forms

    def test_a_claim_spelled_through_another_runs_mount_conflicts(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        (tmp_path / "elsewhere").mkdir()
        (data / "link").symlink_to(tmp_path / "elsewhere")
        with mc.hold_path_claims([("live", data)], "test"):
            with pytest.raises(SandboxError):
                with mc.hold_path_claims([("read", data / "link")], "test"):
                    pass


class TestTheSeedIsCopiedFromAPinnedRoot:
    """Codex P1 (#198): seed_scratch resolves the seed once, opens it no-follow and walks by
    descriptor, so the copy reads the directory the backend checked."""

    def test_the_seed_contents_are_copied_and_merged(self, tmp_path):
        seed = tmp_path / "seed"
        (seed / "Library" / "Caches").mkdir(parents=True)
        (seed / "Library" / "Caches" / "c").write_text("cache")
        (seed / "top").write_text("t")
        (seed / "tmp").mkdir()
        (seed / "tmp" / "skip").write_text("no")
        scratch = mc.make_scratch(tmp_path / "s")
        mc.seed_scratch(scratch, seed, budget_bytes=1 << 20)
        assert (scratch / "Library" / "Caches" / "c").read_text() == "cache"
        assert (scratch / "top").read_text() == "t"
        assert not (scratch / "tmp" / "skip").exists()

    def test_a_seed_that_is_not_a_directory_is_refused(self, tmp_path):
        f = tmp_path / "seed"
        f.write_text("x")
        with pytest.raises(SandboxError, match="not a directory"):
            mc.seed_scratch(mc.make_scratch(tmp_path / "s"), f, budget_bytes=1 << 20)

    def test_a_subdirectory_swapped_for_a_symlink_is_not_followed(self, tmp_path, monkeypatch):
        seed = tmp_path / "seed"
        (seed / "Library" / "Caches").mkdir(parents=True)
        secret = tmp_path / "secret"
        secret.mkdir()
        (secret / "key").write_text("s3cret")
        scratch = mc.make_scratch(tmp_path / "s")
        real_stat = os.stat
        swapped = []

        def stat_then_swap(name, *a, **kw):
            st = real_stat(name, *a, **kw)
            if name == "Library" and not swapped:          # classified a dir; now swap it
                swapped.append(1)
                os.rename(seed / "Library", seed / "Library.old")
                os.symlink(secret, seed / "Library")
            return st
        monkeypatch.setattr(mc.os, "stat", stat_then_swap)
        with pytest.raises((SandboxError, OSError)):
            mc.seed_scratch(scratch, seed, budget_bytes=1 << 20)
        assert not any(p.name == "key" for p in scratch.rglob("*"))


class TestTheNativeCaptureSwapRetiresTheOldTree:
    """Codex P2 (#198): after a successful RENAME_SWAP the previous capture is retired through
    the recorded `done-` path like the fallback's, so an entry that can't be removed is cleaned
    by the next capture instead of being left as an unrecorded `.capture-*` sibling."""

    @staticmethod
    def _swap(a: bytes, b: bytes, flags: int) -> int:
        tmp = a + b".swap"
        os.rename(a, tmp)
        os.rename(b, a)
        os.rename(tmp, b)
        return 0

    @staticmethod
    def _scratch(tmp_path, text):
        scratch = tmp_path / f"scratch-{text}"
        (scratch / "Library").mkdir(parents=True)
        (scratch / "Library" / "f").write_text(text)
        return scratch

    def test_the_old_capture_goes_through_the_recorded_path(self, tmp_path, monkeypatch):
        _need_done_tags(tmp_path)
        monkeypatch.setattr(mc, "_renamex_np", lambda: self._swap)
        dest = tmp_path / "cache"
        mc.capture_scratch(self._scratch(tmp_path, "one"), dest, 1 << 20)
        seen: list[str] = []
        real = mc.remove_tree
        monkeypatch.setattr(mc, "remove_tree", lambda p: (seen.append(p.name), real(p))[1])
        mc.capture_scratch(self._scratch(tmp_path, "two"), dest, 1 << 20)
        assert any("done-" in n for n in seen)
        assert (dest / "Library" / "f").read_text() == "two"
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".cache")] == []

    def test_an_undeletable_old_capture_is_finished_by_the_next_capture(self, tmp_path,
                                                                         monkeypatch):
        _need_done_tags(tmp_path)
        monkeypatch.setattr(mc, "_renamex_np", lambda: self._swap)
        dest = tmp_path / "cache"
        mc.capture_scratch(self._scratch(tmp_path, "one"), dest, 1 << 20)
        real = mc.remove_tree
        monkeypatch.setattr(mc, "remove_tree", lambda p: None if "done-" in p.name else real(p))
        with pytest.raises(SandboxError, match="could not remove"):
            mc.capture_scratch(self._scratch(tmp_path, "two"), dest, 1 << 20)
        left = [p for p in tmp_path.iterdir() if p.name.startswith(".cache")]
        assert len(left) == 1 and "done-" in left[0].name         # recorded, never `.capture-*`
        monkeypatch.setattr(mc, "remove_tree", real)
        mc.capture_scratch(self._scratch(tmp_path, "three"), dest, 1 << 20)
        assert not left[0].exists()
        assert (dest / "Library" / "f").read_text() == "three"
