"""TDD tests for BubblewrapSandbox.

Structure
---------
1. argv-building unit tests (inject _build_argv, no real bwrap needed).
2. insecurity_reasons unit tests (monkeypatch the module-level _LIBSECCOMP_AVAILABLE).
3. Real smoke-run tests (bwrap IS installed on this host; skip if userns
   is restricted).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest
from blastbox.worker.sandbox.bwrap import BubblewrapSandbox, _make_apply_rlimits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sandbox(
    *,
    bwrap_path: str | None = None,
    apparmor_profile: str = "test-profile",
) -> BubblewrapSandbox:
    """Construct a BubblewrapSandbox; skip if bwrap is not found."""
    import shutil
    path = bwrap_path or shutil.which("bwrap") or "/usr/bin/bwrap"
    if not Path(path).exists():
        pytest.skip("bwrap not installed on this host")
    return BubblewrapSandbox(bwrap_path=path, apparmor_profile=apparmor_profile)


# ---------------------------------------------------------------------------
# Part 1: argv-building unit tests
# ---------------------------------------------------------------------------

class TestBwrapArgvBuilding:
    """Test _build_argv without running bwrap."""

    def test_argv_is_a_list(self) -> None:
        """_build_argv returns a plain list[str]."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        result = sb._build_argv(req)
        assert isinstance(result, list)
        assert all(isinstance(t, str) for t in result)

    def test_contains_unshare_net(self) -> None:
        """--unshare-net is always present (network isolation)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--unshare-net" in argv

    def test_contains_cap_drop_all(self) -> None:
        """--cap-drop ALL is always present."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        # --cap-drop is followed by ALL
        assert "--cap-drop" in argv
        idx = argv.index("--cap-drop")
        assert argv[idx + 1] == "ALL"

    def test_contains_clearenv(self) -> None:
        """--clearenv is always present (env stripping)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--clearenv" in argv

    def test_contains_die_with_parent(self) -> None:
        """--die-with-parent is always present."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--die-with-parent" in argv

    def test_contains_unshare_all(self) -> None:
        """--unshare-all is always present."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "--unshare-all" in argv

    def test_ro_mount_in_argv(self) -> None:
        """ro_mounts appear as --ro-bind <source> <target> in value positions."""
        sb = _make_sandbox()
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            ro_mounts=[
                Mount(source=Path("/tmp/input"), target=Path("/sandbox/input")),
            ],
        )
        argv = sb._build_argv(req)
        # Find --ro-bind for the caller mount
        pairs = [
            (argv[i + 1], argv[i + 2])
            for i in range(len(argv) - 2)
            if argv[i] == "--ro-bind"
        ]
        assert ("/tmp/input", "/sandbox/input") in pairs, (
            f"ro_mount not found as --ro-bind value pair; argv={argv}"
        )

    def test_rw_mount_in_argv(self) -> None:
        """rw_mounts appear as --bind <source> <target> in value positions."""
        sb = _make_sandbox()
        req = SandboxRequest(
            argv=["/usr/bin/true"],
            rw_mounts=[
                Mount(
                    source=Path("/tmp/output"),
                    target=Path("/sandbox/output"),
                    read_only=False,
                ),
            ],
        )
        argv = sb._build_argv(req)
        pairs = [
            (argv[i + 1], argv[i + 2])
            for i in range(len(argv) - 2)
            if argv[i] == "--bind"
        ]
        assert ("/tmp/output", "/sandbox/output") in pairs, (
            f"rw_mount not found as --bind value pair; argv={argv}"
        )

    def test_env_appears_as_setenv(self) -> None:
        """request.env items appear as --setenv KEY VALUE."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"], env={"MYVAR": "hello"})
        argv = sb._build_argv(req)
        setenv_pairs = [
            (argv[i + 1], argv[i + 2])
            for i in range(len(argv) - 2)
            if argv[i] == "--setenv"
        ]
        assert ("MYVAR", "hello") in setenv_pairs

    def test_minimal_env_path_always_set(self) -> None:
        """PATH is always injected via --setenv even if request.env is empty."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        setenv_pairs = [
            (argv[i + 1], argv[i + 2])
            for i in range(len(argv) - 2)
            if argv[i] == "--setenv"
        ]
        keys = {k for k, _ in setenv_pairs}
        assert "PATH" in keys

    def test_minimal_env_home_always_set(self) -> None:
        """HOME is always /tmp (from _MINIMAL_ENV)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        setenv_pairs = {
            argv[i + 1]: argv[i + 2]
            for i in range(len(argv) - 2)
            if argv[i] == "--setenv"
        }
        assert setenv_pairs.get("HOME") == "/tmp"

    def test_shell_meta_in_mount_target_stays_single_token(self) -> None:
        """A mount target containing shell metacharacters stays a single token.

        This is the critical flag-injection guard: if the target were
        interpolated into a shell string, a value like '/out;rm -rf /' could
        inject flags.  Because argv is a Python list, it's always a single token.

        Note: Path normalises trailing slashes (Path('/a/') == Path('/a')), so
        we compare with str(Path(evil_target)) rather than the raw string.
        """
        sb = _make_sandbox()
        evil_target = "/out;rm -rf /"
        # Path normalises trailing slashes: str(Path('/out;rm -rf /')) == '/out;rm -rf '
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
        # The evil target must appear as exactly one list element.
        assert normalised_target in argv, (
            f"normalised target {normalised_target!r} not found as a single token in argv"
        )
        # For bwrap: --bind <source> <target>.  The target is at idx,
        # the source is at idx-1, and the flag is at idx-2.
        idx = argv.index(normalised_target)
        assert argv[idx - 2] in ("--bind", "--ro-bind"), (
            f"evil target must be preceded by source then flag, "
            f"got argv[idx-2]={argv[idx-2]!r}"
        )
        # The target is a single list element, not split by the shell.
        assert " " in normalised_target or ";" in normalised_target, (
            "sanity: test value should contain shell-special chars"
        )

    def test_inner_argv_after_double_dash(self) -> None:
        """The request.argv appears after '--' in the bwrap argv."""
        sb = _make_sandbox()
        inner = ["/usr/bin/echo", "hello world"]
        req = SandboxRequest(argv=inner)
        argv = sb._build_argv(req)
        assert "--" in argv
        # Inner argv is the last part after the final --
        # (aa-exec may be prepended, but inner argv always ends the list)
        assert argv[-len(inner):] == inner

    def test_no_shell_true_flag(self) -> None:
        """_build_argv never produces a 'shell=True' token (just a sanity check)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        assert "shell=True" not in argv
        assert "shell" not in argv


# ---------------------------------------------------------------------------
# Part 2: insecurity_reasons unit tests
# ---------------------------------------------------------------------------

class TestBwrapInsecurityReasons:
    """Test insecurity_reasons without running bwrap."""

    def test_seccomp_missing_when_lib_unavailable(self, monkeypatch) -> None:
        """When the seccomp lib is absent, 'seccomp_missing' is in reasons."""
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)
        sb = _make_sandbox()
        assert "seccomp_missing" in sb.insecurity_reasons

    def test_secure_false_when_seccomp_missing(self, monkeypatch) -> None:
        """secure is False when seccomp lib is absent."""
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)
        sb = _make_sandbox()
        assert sb.secure is False

    def test_apparmor_missing_when_no_aa_exec(self, monkeypatch) -> None:
        """When aa-exec is absent, 'apparmor_missing' is in reasons."""
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        # Patch shutil.which in the bwrap module namespace so aa-exec is not found.
        original_which = bwrap_mod.shutil.which
        monkeypatch.setattr(
            bwrap_mod.shutil,
            "which",
            lambda name: None if name == "aa-exec" else original_which(name),
        )
        sb = _make_sandbox()
        assert "apparmor_missing" in sb.insecurity_reasons

    def test_insecurity_reasons_returns_copy(self, monkeypatch) -> None:
        """insecurity_reasons returns a new list each time (copy, not reference)."""
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)
        sb = _make_sandbox()
        r1 = sb.insecurity_reasons
        r1.append("injected")
        r2 = sb.insecurity_reasons
        assert "injected" not in r2

    def test_venv_has_no_seccomp_lib(self) -> None:
        """The test venv does NOT have the seccomp library installed.

        This is the specific case described in the task brief.  We verify
        that the module correctly detects the absence and records the reason
        rather than crashing.
        """
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        # The venv should have _LIBSECCOMP_AVAILABLE == False per the brief.
        # If it's True (user installed it), we just skip this assertion.
        if bwrap_mod._LIBSECCOMP_AVAILABLE:
            pytest.skip("seccomp lib IS available in this venv; skipping absence test")
        sb = _make_sandbox()
        assert "seccomp_missing" in sb.insecurity_reasons
        assert sb.secure is False


# ---------------------------------------------------------------------------
# Part 3: Real smoke-run tests
# ---------------------------------------------------------------------------

class TestBwrapRealRun:
    """Integration tests that actually invoke bwrap.

    All tests are skipped if the host's user namespace is restricted (common
    in CI environments or some kernels with userns_clone disabled).
    """

    @pytest.fixture(autouse=True)
    def check_userns(self) -> None:
        """Skip if user namespaces are not usable on this host."""
        import shutil
        if not shutil.which("bwrap"):
            pytest.skip("bwrap not installed")
        # Quick probe: attempt a minimal bwrap run
        try:
            true_path = "/usr/bin/true" if Path("/usr/bin/true").exists() else "/bin/true"
            r = subprocess.run(
                [
                    "bwrap",
                    "--unshare-user",
                    "--unshare-all",
                    "--die-with-parent",
                    "--clearenv",
                    "--proc", "/proc",
                    "--dev", "/dev",
                    "--ro-bind", "/usr", "/usr",
                    "--symlink", "usr/bin", "/bin",
                    "--symlink", "usr/lib", "/lib",
                    "--symlink", "usr/lib64", "/lib64",
                    "--symlink", "usr/sbin", "/sbin",
                    "--ro-bind", "/etc", "/etc",
                    "--tmpfs", "/tmp",
                    "--",
                    true_path,
                ],
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            pytest.skip(f"bwrap userns probe failed: {exc}")
        if r.returncode != 0:
            pytest.skip(
                f"bwrap user-namespace not usable on this host "
                f"(exit={r.returncode}, stderr={r.stderr.decode(errors='replace')!r})"
            )

    def _make_real_sandbox(self, monkeypatch) -> BubblewrapSandbox:
        """Create a BubblewrapSandbox suitable for real execution.

        Patches out the seccomp lib (not installed in venv) and aa-exec
        (profile blastbox-sandbox may not be loaded on the host).
        """
        import blastbox.worker.sandbox.bwrap as bwrap_mod
        monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)
        sb = BubblewrapSandbox()
        # Disable aa-exec so bwrap doesn't try to attach a non-existent profile.
        sb._aa_exec = None
        return sb

    def test_echo_hi(self, monkeypatch) -> None:
        """run(['/usr/bin/echo', 'hi']) → exit 0, stdout=b'hi\\n', not killed."""
        sb = self._make_real_sandbox(monkeypatch)
        req = SandboxRequest(argv=["/usr/bin/echo", "hi"])
        result = sb.run(req)
        assert result.exit_code == 0, (
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert result.stdout == b"hi\n"
        assert not result.killed

    def test_timeout_kills_sleep(self, monkeypatch) -> None:
        """`run(['/usr/bin/sleep', '10'], timeout_s=1)` → killed=True."""
        sb = self._make_real_sandbox(monkeypatch)
        req = SandboxRequest(
            argv=["/usr/bin/sleep", "10"],
            limits=Limits(timeout_s=1),
        )
        result = sb.run(req)
        assert result.killed, "process should have been killed by timeout"

    def test_env_stripped(self, monkeypatch) -> None:
        """Host os.environ sentinel must NOT appear in bwrap child's env."""
        import os as _os
        sentinel = "BLASTBOX_BWRAP_SECRET_XYZ"
        _os.environ[sentinel] = "must-not-appear"
        try:
            sb = self._make_real_sandbox(monkeypatch)
            req = SandboxRequest(argv=["/usr/bin/env"])
            result = sb.run(req)
            text = result.stdout.decode(errors="replace")
            assert sentinel not in text
        finally:
            del _os.environ[sentinel]

    def test_request_env_passed(self, monkeypatch) -> None:
        """request.env={'CUSTOM':'val'} → 'CUSTOM=val' in env output."""
        sb = self._make_real_sandbox(monkeypatch)
        req = SandboxRequest(argv=["/usr/bin/env"], env={"CUSTOM": "val"})
        result = sb.run(req)
        assert b"CUSTOM=val" in result.stdout

    def test_result_fields(self, monkeypatch) -> None:
        """SandboxResult has exit_code (int), stdout (bytes), stderr (bytes), killed (bool)."""
        sb = self._make_real_sandbox(monkeypatch)
        req = SandboxRequest(argv=["/usr/bin/true"])
        result = sb.run(req)
        assert isinstance(result.exit_code, int)
        assert isinstance(result.stdout, bytes)
        assert isinstance(result.stderr, bytes)
        assert isinstance(result.killed, bool)

    def test_nonexistent_argv_raises_sandbox_error(self, monkeypatch) -> None:
        """If the inner binary doesn't exist, bwrap exits non-zero (not raises)."""
        sb = self._make_real_sandbox(monkeypatch)
        req = SandboxRequest(argv=["/nonexistent_binary_xyz_abc"])
        # bwrap itself starts fine; the inner exec fails → non-zero exit_code
        result = sb.run(req)
        assert result.exit_code != 0 or result.killed


# ---------------------------------------------------------------------------
# Part 4: make_apply_rlimits helper
# ---------------------------------------------------------------------------

def test_make_apply_rlimits_returns_callable() -> None:
    """_make_apply_rlimits returns a callable."""
    fn = _make_apply_rlimits(Limits())
    assert callable(fn)


def test_make_apply_rlimits_callable_has_expected_signature() -> None:
    """The returned function takes no arguments (it's a preexec_fn)."""
    import inspect
    fn = _make_apply_rlimits(Limits())
    sig = inspect.signature(fn)
    assert len(sig.parameters) == 0, "preexec_fn must take no arguments"


def test_make_apply_rlimits_different_limits_produce_distinct_closures() -> None:
    """Different Limits instances produce distinct closures (closure test)."""
    mem1 = 128 * 1024 * 1024
    mem2 = 256 * 1024 * 1024
    fn1 = _make_apply_rlimits(Limits(memory_bytes=mem1))
    fn2 = _make_apply_rlimits(Limits(memory_bytes=mem2))
    # Each closure captures different values; they should not be identical.
    assert fn1 is not fn2
    # Inspect the closure cells to confirm different memory_bytes are captured.
    cells1 = {cell.cell_contents for cell in (fn1.__closure__ or [])}
    cells2 = {cell.cell_contents for cell in (fn2.__closure__ or [])}
    assert mem1 in cells1, f"Expected {mem1} in closure cells, got {cells1}"
    assert mem2 in cells2, f"Expected {mem2} in closure cells, got {cells2}"
    assert cells1 != cells2, "Different Limits should produce different closures"


def test_aa_exec_gated_on_profile_loaded(monkeypatch):
    """aa-exec is attached only when the profile is CONFIRMED loaded.

    Attaching aa-exec with an unloaded profile fails the exec and would break
    every run; an unconfirmed profile must degrade to apparmor_missing, not break.
    """
    from blastbox.worker.sandbox.bwrap import (
        BubblewrapSandbox,
        _apparmor_profile_loaded,
    )

    # An unloaded/bogus profile is not confirmed -> no aa-exec, flagged insecure.
    monkeypatch.delenv("BLASTBOX_APPARMOR_PROFILES", raising=False)
    assert _apparmor_profile_loaded("no-such-profile-xyzzy") is False
    sb = BubblewrapSandbox(apparmor_profile="no-such-profile-xyzzy")
    assert sb._aa_exec is None
    assert "apparmor_missing" in sb.insecurity_reasons
    assert sb.secure is False

    # An explicit env assertion confirms a profile (operator opt-in).
    monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILES", "myprofile, other")
    assert _apparmor_profile_loaded("myprofile") is True
    assert _apparmor_profile_loaded("notlisted") is False
