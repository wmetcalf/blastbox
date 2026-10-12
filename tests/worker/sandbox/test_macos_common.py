"""Shared macOS sandbox plumbing: env, copier, argv rewriting, watchdog, lifecycle.

Pure-logic tests run on any POSIX host; nothing here needs Seatbelt.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import time

import pytest

from blastbox.errors import SandboxError
from blastbox.limits import Limits
from blastbox.worker.sandbox import macos_common as mc


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
        assert n == 11
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
    def test_timeout_kills_the_group(self, tmp_path):
        t0 = time.monotonic()
        r = mc.run_confined(["/bin/sleep", "30"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=1), cwd=tmp_path)
        assert r.killed and r.exit_code == -9
        assert time.monotonic() - t0 < 10

    def test_rss_watchdog_kills_over_limit(self, tmp_path):
        r = mc.run_confined(["/bin/sleep", "30"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=20), cwd=tmp_path,
                            rss_fn=lambda pgid: 10 * 1024 ** 4)
        assert r.killed
        assert b"RSS exceeded" in r.stderr

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

    def test_a_forked_child_does_not_outlive_a_normal_exit(self, tmp_path):
        pidfile = tmp_path / "pid"
        r = mc.run_confined(["/bin/sh", "-c", f'sleep 60 </dev/null >/dev/null 2>&1 & echo $! > {pidfile}; exit 0'],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=10), cwd=tmp_path)
        assert r.exit_code == 0 and not r.killed
        pid = int(pidfile.read_text())
        time.sleep(0.2)
        assert not self._alive(pid)

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

    def test_captured_output_is_bounded(self, tmp_path):
        r = mc.run_confined(["/bin/sh", "-c", "head -c 5000000 /dev/zero"], env={"PATH": mc.MINIMAL_PATH},
                            limits=Limits(timeout_s=10), cwd=tmp_path, max_output_bytes=1000)
        assert len(r.stdout) == 1000
        assert b"stdout truncated at 1000 bytes" in r.stderr

    def test_disk_watchdog_caps_the_whole_run(self, tmp_path):
        # Many files, each under RLIMIT_FSIZE, adding up past tmpfs_bytes.
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        r = mc.run_confined(["/bin/sh", "-c", "i=0; while [ $i -lt 400 ]; do head -c 200000 /dev/zero > f$i; i=$((i+1)); done; sleep 30"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=20, tmpfs_bytes=10_000_000),
                            cwd=scratch, watch_dirs=[scratch])
        assert r.killed
        assert b"writable dirs exceeded" in r.stderr

    def test_process_count_is_capped(self, tmp_path):
        r = mc.run_confined(["/bin/sh", "-c", "i=0; while [ $i -lt 300 ]; do sleep 5 & i=$((i+1)); done; wait"],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=20), cwd=tmp_path)
        assert b"fork" in r.stderr.lower() or b"resource temporarily unavailable" in r.stderr.lower()

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


class TestWipeDir:
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
        return subprocess.Popen(["/usr/bin/sandbox-exec", "-p", prof, "/bin/sleep", "30"],
                                start_new_session=True)

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

    def test_the_worker_itself_is_not_sandboxed(self):
        assert not mc.is_sandboxed(os.getpid())



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

    def test_the_watchdog_trips_on_what_it_cannot_measure(self, tmp_path):
        w = tmp_path / "w"
        w.mkdir()
        r = mc.run_confined(["/bin/sh", "-c", f'mkdir "{w}/h" && chmod 000 "{w}/h" && sleep 20'],
                            env={"PATH": mc.MINIMAL_PATH}, limits=Limits(timeout_s=30),
                            cwd=tmp_path, watch_dirs=[w])
        os.chmod(w / "h", 0o700)
        assert r.killed and b"writable dirs" in r.stderr


class TestWipeDirLockedRoot:
    def test_a_root_chmodded_000_is_unlocked_and_emptied(self, tmp_path):
        d = tmp_path / "Data"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "f").write_text("x")
        os.chmod(d, 0)
        os.chflags(d, stat.UF_IMMUTABLE)       # locked after the chmod (uchg blocks chmod)
        mc.wipe_dir(d)
        assert list(d.iterdir()) == []

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
