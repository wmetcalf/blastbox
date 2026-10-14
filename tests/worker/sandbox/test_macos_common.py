"""Shared macOS sandbox plumbing: env, copier, argv rewriting, watchdog, lifecycle.

Pure-logic tests run on any POSIX host; nothing here needs Seatbelt.
"""
from __future__ import annotations

import contextlib
import signal
import os
import shutil
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

        def fake_clone(s, d, flags):
            # Like APFS clonefile: the copy keeps the source's mode, special bits included.
            shutil.copyfile(s, d)
            os.chmod(d, stat.S_IMODE(os.stat(s).st_mode))
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
    @pytest.mark.timeout(60)
    def test_a_stuck_watchdog_still_gets_the_run_killed_and_swept(self, tmp_path, monkeypatch):
        # __exit__ raising (the watchdog would not stop) must not skip the family kill and the
        # backend sweep: a detached child would otherwise outlive the failed run
        monkeypatch.setattr(mc, "WATCHDOG_JOIN_S", 0.5)
        monkeypatch.setattr(mc, "held_unlinked_bytes", lambda pids: time.sleep(5) or 0)
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
        def acl_clone(s, d, flags):
            shutil.copyfile(s, d)
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
