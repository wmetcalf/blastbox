"""Shared macOS sandbox plumbing: env, copier, argv rewriting, watchdog, lifecycle.

Pure-logic tests run on any POSIX host; nothing here needs Seatbelt.
"""
from __future__ import annotations

import os
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

    def test_group_rss_parses_ps(self):
        fake = subprocess.CompletedProcess([], 0, stdout="  42  100\n  42  50\n  7 9999\n")
        assert mc.group_rss_bytes(42, ps_runner=lambda *a, **k: fake) == 150 * 1024
