"""TDD tests for NsjailSandbox.

Structure
---------
1. argv-building unit tests (call _build_argv without running nsjail).
2. insecurity_reasons unit tests (monkeypatch seccomp policy path).
3. Real smoke-run tests (nsjail IS installed; skip if userns restricted).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest
from blastbox.worker.sandbox.nsjail import NsjailSandbox, _SECCOMP_POLICY_CANDIDATES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sandbox(
    *,
    nsjail_path: str | None = None,
    seccomp_policy: Path | None = None,
) -> NsjailSandbox:
    """Construct an NsjailSandbox; skip if nsjail is not found."""
    import shutil

    path = nsjail_path or shutil.which("nsjail") or "/usr/local/bin/nsjail"
    if not Path(path).exists():
        pytest.skip("nsjail not installed on this host")
    return NsjailSandbox(nsjail_path=path, seccomp_policy=seccomp_policy)


# ---------------------------------------------------------------------------
# Part 1: argv-building unit tests
# ---------------------------------------------------------------------------


class TestNsjailArgvBuilding:
    """Test _build_argv without running nsjail."""

    def test_argv_is_a_list(self) -> None:
        """_build_argv returns a plain list[str]."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        result = sb._build_argv(req)
        assert isinstance(result, list)
        assert all(isinstance(t, str) for t in result)

    def test_one_shot_mode(self) -> None:
        """--mode o (one-shot) is always present."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--mode" in argv
        idx = argv.index("--mode")
        assert argv[idx + 1] == "o"

    def test_no_lo_interface(self) -> None:
        """--iface_no_lo is present BY DEFAULT (net_egress off → sealed netns, fail-closed)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--iface_no_lo" in argv
        assert "--disable_clone_newnet" not in argv

    def test_net_shares_when_egress_enabled(self) -> None:
        """net_egress on → --disable_clone_newnet (share the rooter-routed parent netns)."""
        from blastbox.limits import Limits

        sb = _make_sandbox(nsjail_path="/bin/true")
        req = SandboxRequest(argv=["/usr/bin/true"], limits=Limits(net_egress=True))
        argv = sb._build_argv(req)
        assert "--disable_clone_newnet" in argv
        assert "--iface_no_lo" not in argv

    def test_time_limit_from_limits(self) -> None:
        """--time_limit matches request.limits.timeout_s."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"], limits=Limits(timeout_s=42))
        argv = sb._build_argv(req)
        assert "--time_limit" in argv
        idx = argv.index("--time_limit")
        assert argv[idx + 1] == "42"

    def test_rlimit_as_from_limits(self) -> None:
        """--rlimit_as matches memory_bytes // 1MiB."""
        sb = _make_sandbox()
        mem = 512 * 1024 * 1024  # 512 MiB
        req = SandboxRequest(argv=["/usr/bin/true"], limits=Limits(memory_bytes=mem))
        argv = sb._build_argv(req)
        assert "--rlimit_as" in argv
        idx = argv.index("--rlimit_as")
        assert argv[idx + 1] == str(mem // (1024 * 1024))

    def test_user_group_65534(self) -> None:
        """--user 65534 and --group 65534 (nobody) are always present."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--user" in argv
        assert "--group" in argv
        assert argv[argv.index("--user") + 1] == "65534"
        assert argv[argv.index("--group") + 1] == "65534"

    def test_ro_mount_as_bindmount_ro(self) -> None:
        """ro_mounts appear as --bindmount_ro src:tgt value pairs."""
        sb = _make_sandbox()
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            ro_mounts=[
                Mount(source=Path("/tmp/input"), target=Path("/jail/input")),
            ],
        )
        argv = sb._build_argv(req)
        bm_values = [
            argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "--bindmount_ro"
        ]
        assert "/tmp/input:/jail/input" in bm_values, (
            f"ro mount not found in --bindmount_ro values; bm_values={bm_values}"
        )

    def test_rw_mount_as_bindmount(self) -> None:
        """rw_mounts appear as --bindmount src:tgt value pairs."""
        sb = _make_sandbox()
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            rw_mounts=[
                Mount(
                    source=Path("/tmp/output"),
                    target=Path("/jail/output"),
                    read_only=False,
                ),
            ],
        )
        argv = sb._build_argv(req)
        bm_values = [
            argv[i + 1]
            for i in range(len(argv) - 1)
            if argv[i] == "--bindmount" and i + 1 < len(argv) and ":" in argv[i + 1]
        ]
        assert "/tmp/output:/jail/output" in bm_values, (
            f"rw mount not found in --bindmount values; bm_values={bm_values}"
        )

    def test_env_as_env_flag(self) -> None:
        """request.env items appear as --env KEY=VALUE."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"], env={"MYVAR": "hello"})
        argv = sb._build_argv(req)
        env_values = [argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "--env"]
        assert "MYVAR=hello" in env_values

    def test_minimal_env_always_injected(self) -> None:
        """PATH and HOME are always present via --env (from _MINIMAL_ENV)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        env_values = [argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "--env"]
        env_keys = {v.split("=", 1)[0] for v in env_values}
        assert "PATH" in env_keys
        assert "HOME" in env_keys

    def test_shell_meta_in_mount_stays_single_token(self) -> None:
        """Shell metacharacters in a mount target stay as one list element.

        The critical flag-injection guard: because argv is a Python list,
        a target like '/out;rm -rf /' is always a single token in ``src:tgt``
        format, never interpreted by a shell.

        Note: Path normalises trailing slashes (Path('/a/') == Path('/a')), so
        we compare with str(Path(evil_target)) rather than the raw string.
        """
        sb = _make_sandbox()
        evil_target = "/out;rm -rf /"
        # Path normalises trailing slashes.
        normalised_target = str(Path(evil_target))
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            rw_mounts=[
                Mount(
                    source=Path("/tmp/safe"),
                    target=Path(evil_target),
                    read_only=False,
                ),
            ],
        )
        argv = sb._build_argv(req)
        # The evil target is encoded inside the src:tgt token.
        encoded = f"/tmp/safe:{normalised_target}"
        assert encoded in argv, (
            f"encoded mount {encoded!r} not found as a single token in argv"
        )
        # That token must follow --bindmount, not appear as a flag.
        idx = argv.index(encoded)
        assert argv[idx - 1] == "--bindmount"

    def test_inner_argv_after_double_dash(self) -> None:
        """The request.argv appears after '--' in the nsjail argv."""
        sb = _make_sandbox()
        inner = ["/usr/bin/echo", "hello world"]
        req = SandboxRequest(argv=inner)
        argv = sb._build_argv(req)
        assert "--" in argv
        dd_idx = argv.index("--")
        assert argv[dd_idx + 1 :] == inner

    def test_seccomp_policy_in_argv_when_present(self, tmp_path: Path) -> None:
        """--seccomp_policy is added when a policy file exists."""
        policy = tmp_path / "test.policy"
        policy.write_text("POLICY test { ERRNO(1) { } } USE test DEFAULT ALLOW\n")
        sb = _make_sandbox(seccomp_policy=policy)
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--seccomp_policy" in argv
        idx = argv.index("--seccomp_policy")
        assert argv[idx + 1] == str(policy)

    def test_seccomp_policy_absent_when_missing(self) -> None:
        """--seccomp_policy is omitted when the policy file is not found."""
        # Pass a nonexistent path so _find_seccomp_policy returns None.
        sb = NsjailSandbox(seccomp_policy=Path("/nonexistent/path.policy"))
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--seccomp_policy" not in argv


# ---------------------------------------------------------------------------
# Part 2: insecurity_reasons unit tests
# ---------------------------------------------------------------------------


class TestNsjailInsecurityReasons:
    """Test insecurity_reasons without running nsjail."""

    def test_seccomp_policy_missing_in_reasons(self) -> None:
        """If the policy file is not found, 'seccomp_policy_missing' in reasons."""
        sb = NsjailSandbox(seccomp_policy=Path("/nonexistent_xyz.policy"))
        assert "seccomp_policy_missing" in sb.insecurity_reasons

    def test_secure_false_when_policy_missing(self) -> None:
        """secure is False when seccomp policy is missing."""
        sb = NsjailSandbox(seccomp_policy=Path("/nonexistent_xyz.policy"))
        assert sb.secure is False

    def test_secure_true_when_policy_present(self, tmp_path: Path) -> None:
        """secure is True when the policy file is found (and proc_apparmor is n/a)."""
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        sb = _make_sandbox(seccomp_policy=policy)
        # Only seccomp_policy_missing drives insecurity for nsjail; apparmor is advisory.
        assert "seccomp_policy_missing" not in sb.insecurity_reasons
        assert sb.secure is True

    def test_insecurity_reasons_returns_copy(self) -> None:
        """insecurity_reasons returns a new list (copy, not reference)."""
        sb = NsjailSandbox(seccomp_policy=Path("/nonexistent_xyz.policy"))
        r1 = sb.insecurity_reasons
        r1.append("injected")
        r2 = sb.insecurity_reasons
        assert "injected" not in r2

    def test_seccomp_policy_candidates_checked(self) -> None:
        """_SECCOMP_POLICY_CANDIDATES contains the bundled policy path."""
        # The deploy/seccomp path should be in the candidate list.
        paths_str = [str(p) for p in _SECCOMP_POLICY_CANDIDATES]
        assert any("blastbox.seccomp.policy" in p for p in paths_str), (
            f"Bundled policy not in candidates: {paths_str}"
        )


# ---------------------------------------------------------------------------
# Part 3: Real smoke-run tests
# ---------------------------------------------------------------------------


class TestNsjailRealRun:
    """Integration tests that actually invoke nsjail.

    Skipped if nsjail cannot create user namespaces on this host.
    """

    @pytest.fixture(autouse=True)
    def check_nsjail_usable(self) -> None:
        """Skip if nsjail can't run a one-shot on this host."""
        import shutil

        if not shutil.which("nsjail"):
            pytest.skip("nsjail not installed")
        true_path = "/usr/bin/true" if Path("/usr/bin/true").exists() else "/bin/true"
        try:
            r = subprocess.run(
                [
                    "nsjail",
                    "--mode",
                    "o",
                    "--user",
                    "65534",
                    "--group",
                    "65534",
                    "--quiet",
                    "--really_quiet",
                    "--bindmount_ro",
                    "/usr:/usr",
                    "--symlink",
                    "usr/bin:/bin",
                    "--symlink",
                    "usr/lib:/lib",
                    "--symlink",
                    "usr/lib64:/lib64",
                    "--symlink",
                    "usr/sbin:/sbin",
                    "--bindmount_ro",
                    "/etc:/etc",
                    "--tmpfsmount",
                    "/tmp",
                    "--",
                    true_path,
                ],
                capture_output=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            pytest.skip(f"nsjail probe failed: {exc}")
        if r.returncode != 0:
            pytest.skip(
                f"nsjail user-namespace not usable on this host "
                f"(exit={r.returncode}, "
                f"stderr={r.stderr.decode(errors='replace')[:200]!r})"
            )

    def test_echo_hi(self, tmp_path: Path) -> None:
        """run(['/usr/bin/echo', 'hi']) → exit 0, stdout=b'hi\\n', not killed."""
        # Use a valid (or missing) policy to allow construction.
        policy_path = tmp_path / "dummy.policy"
        policy_path.write_text(
            "POLICY dummy { ERRNO(1) { } } USE dummy DEFAULT ALLOW\n"
        )
        sb = _make_sandbox(seccomp_policy=policy_path)
        req = SandboxRequest(argv=["/usr/bin/echo", "hi"])
        result = sb.run(req)
        assert result.exit_code == 0, (
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert result.stdout == b"hi\n"
        assert not result.killed

    def test_timeout_kills_sleep(self, tmp_path: Path) -> None:
        """`run(['/usr/bin/sleep', '10'], timeout_s=1)` → killed=True."""
        policy_path = tmp_path / "dummy.policy"
        policy_path.write_text(
            "POLICY dummy { ERRNO(1) { } } USE dummy DEFAULT ALLOW\n"
        )
        sb = _make_sandbox(seccomp_policy=policy_path)
        req = SandboxRequest(
            argv=["/usr/bin/sleep", "10"],
            limits=Limits(timeout_s=1),
        )
        result = sb.run(req)
        assert result.killed, "process should have been killed by timeout"

    def test_env_stripped(self, tmp_path: Path) -> None:
        """Host os.environ sentinel must NOT appear in nsjail child's env."""
        import os as _os

        policy_path = tmp_path / "dummy.policy"
        policy_path.write_text(
            "POLICY dummy { ERRNO(1) { } } USE dummy DEFAULT ALLOW\n"
        )
        sentinel = "BLASTBOX_NSJAIL_SECRET_XYZ"
        _os.environ[sentinel] = "must-not-appear"
        try:
            sb = _make_sandbox(seccomp_policy=policy_path)
            req = SandboxRequest(argv=["/usr/bin/env"])
            result = sb.run(req)
            text = result.stdout.decode(errors="replace")
            assert sentinel not in text
        finally:
            del _os.environ[sentinel]

    def test_request_env_passed(self, tmp_path: Path) -> None:
        """request.env={'CUSTOM':'val'} → 'CUSTOM=val' in env output."""
        policy_path = tmp_path / "dummy.policy"
        policy_path.write_text(
            "POLICY dummy { ERRNO(1) { } } USE dummy DEFAULT ALLOW\n"
        )
        sb = _make_sandbox(seccomp_policy=policy_path)
        req = SandboxRequest(argv=["/usr/bin/env"], env={"CUSTOM": "val"})
        result = sb.run(req)
        assert b"CUSTOM=val" in result.stdout

    def test_result_fields(self, tmp_path: Path) -> None:
        """SandboxResult has exit_code (int), stdout (bytes), stderr (bytes), killed (bool)."""
        policy_path = tmp_path / "dummy.policy"
        policy_path.write_text(
            "POLICY dummy { ERRNO(1) { } } USE dummy DEFAULT ALLOW\n"
        )
        sb = _make_sandbox(seccomp_policy=policy_path)
        req = SandboxRequest(argv=["/usr/bin/true"])
        result = sb.run(req)
        assert isinstance(result.exit_code, int)
        assert isinstance(result.stdout, bytes)
        assert isinstance(result.stderr, bytes)
        assert isinstance(result.killed, bool)
