"""TDD tests for ContainerSandbox.

All tests run on the host (no container needed).  The subprocess-based tests
invoke real binaries (/bin/echo, /bin/sleep, /usr/bin/env, python3).  The
hardening self-check tests feed a fake status_path so we never need /proc.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from blastbox.limits import Limits
from blastbox.worker.sandbox.container import ContainerSandbox
from blastbox.worker.sandbox.base import SandboxRequest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_STATUS = """\
Name:\tpython3
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""

_BAD_STATUS = """\
Name:\tpython3
NoNewPrivs:\t0
Seccomp:\t0
CapEff:\t0000003fffffffff
"""

_PARTIAL_STATUS = """\
Name:\tpython3
"""


def _good_sandbox(tmp_path: Path, **kwargs) -> ContainerSandbox:
    """ContainerSandbox with a 'good' /proc status (warn_on_insecure=True so
    the per-flag checks are advisory and construction succeeds)."""
    status_file = tmp_path / "status_good"
    status_file.write_text(_GOOD_STATUS)
    return ContainerSandbox(
        warn_on_insecure=True,
        status_path=status_file,
        **kwargs,
    )


def _bad_sandbox(tmp_path: Path, **kwargs) -> ContainerSandbox:
    """ContainerSandbox with a 'bad' /proc status."""
    status_file = tmp_path / "status_bad"
    status_file.write_text(_BAD_STATUS)
    return ContainerSandbox(
        warn_on_insecure=True,
        status_path=status_file,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Test: basic echo
# ---------------------------------------------------------------------------

def test_run_echo_exit_zero(tmp_path: Path) -> None:
    """`run(['/bin/echo', 'hi'])` → exit 0, stdout=b'hi\\n', not killed."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(argv=["/bin/echo", "hi"])
    result = sb.run(req)
    assert result.exit_code == 0
    assert result.stdout == b"hi\n"
    assert not result.killed


# ---------------------------------------------------------------------------
# Test: timeout → killed=True
# ---------------------------------------------------------------------------

def test_run_timeout_killed(tmp_path: Path) -> None:
    """`run(['/bin/sleep','5'], timeout_s=1)` → killed=True."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(
        argv=["/bin/sleep", "5"],
        limits=Limits(timeout_s=1),
    )
    result = sb.run(req)
    assert result.killed, "process should have been killed by timeout"


# ---------------------------------------------------------------------------
# Test: environment stripping
# ---------------------------------------------------------------------------

def test_env_sentinel_not_leaked(tmp_path: Path) -> None:
    """Host os.environ sentinel must NOT appear in subprocess env."""
    sentinel = "BLASTBOX_SECRET_SENTINEL_XYZ"
    os.environ[sentinel] = "should-not-appear"
    try:
        sb = _good_sandbox(tmp_path)
        req = SandboxRequest(argv=["/usr/bin/env"])
        result = sb.run(req)
        stdout_text = result.stdout.decode()
        assert sentinel not in stdout_text, (
            f"host env var {sentinel!r} leaked into subprocess env"
        )
    finally:
        del os.environ[sentinel]


def test_env_request_env_passed(tmp_path: Path) -> None:
    """`request.env={'MYVAR':'hello'}` → 'MYVAR=hello' appears in /usr/bin/env output."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(
        argv=["/usr/bin/env"],
        env={"MYVAR": "hello"},
    )
    result = sb.run(req)
    stdout_text = result.stdout.decode()
    assert "MYVAR=hello" in stdout_text


def test_env_minimal_path_present(tmp_path: Path) -> None:
    """Subprocess always gets a minimal PATH even if request.env is empty."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(argv=["/usr/bin/env"])
    result = sb.run(req)
    stdout_text = result.stdout.decode()
    assert "PATH=" in stdout_text


def test_env_home_is_tmp(tmp_path: Path) -> None:
    """Subprocess HOME must be /tmp, not the host user's HOME."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(argv=["/usr/bin/env"])
    result = sb.run(req)
    stdout_text = result.stdout.decode()
    assert "HOME=/tmp" in stdout_text


# ---------------------------------------------------------------------------
# Test: rlimits applied
# ---------------------------------------------------------------------------

def test_rlimit_as_applied_in_child(tmp_path: Path) -> None:
    """Child process can read its own RLIMIT_AS and it equals memory_bytes."""
    # Use a small but non-trivial memory limit (128 MiB)
    mem = 128 * 1024 * 1024
    sb = _good_sandbox(tmp_path)
    # Use python3 to read rlimit from inside the child
    python3 = "/usr/bin/python3"
    if not Path(python3).exists():
        python3 = "/usr/bin/python3"
    code = (
        "import resource, sys; "
        "soft, hard = resource.getrlimit(resource.RLIMIT_AS); "
        f"assert soft == {mem}, f'expected {mem}, got {{soft}}'; "
        "print('ok')"
    )
    req = SandboxRequest(
        argv=[python3, "-c", code],
        limits=Limits(memory_bytes=mem),
    )
    result = sb.run(req)
    assert result.exit_code == 0, (
        f"rlimit check failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.stdout.strip() == b"ok"


def test_rlimit_kills_excess_allocation(tmp_path: Path) -> None:
    """A child that tries to allocate > RLIMIT_AS exits non-zero (MemoryError)."""
    # Set RLIMIT_AS to 64 MiB; try to allocate 256 MiB
    mem = 64 * 1024 * 1024
    python3 = "/usr/bin/python3"
    code = (
        "import sys; "
        "try: "
        "    x = bytearray(256 * 1024 * 1024); "
        "    sys.exit(0); "
        "except MemoryError: "
        "    sys.exit(1)"
    )
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(
        argv=[python3, "-c", code],
        limits=Limits(memory_bytes=mem),
    )
    result = sb.run(req)
    # Should exit non-zero (MemoryError caught → sys.exit(1)) or killed
    assert result.exit_code != 0 or result.killed, (
        "child should have been limited by RLIMIT_AS"
    )


# ---------------------------------------------------------------------------
# Test: hardening self-check — good status, warn_on_insecure=False
# ---------------------------------------------------------------------------

def test_good_status_strict_only_structural_egress_reason(tmp_path: Path) -> None:
    """'Good' /proc status + warn_on_insecure=False → only structural egress reason."""
    status_file = tmp_path / "status_good"
    status_file.write_text(_GOOD_STATUS)
    sb = ContainerSandbox(warn_on_insecure=False, status_path=status_file)
    reasons = sb.insecurity_reasons
    # Per-flag checks should be clear
    assert "no_new_privs_off" not in reasons
    assert "seccomp_off" not in reasons
    assert "cap_not_dropped" not in reasons
    # But network egress is always there (structural)
    assert "network_egress_not_verified" in reasons
    # secure is False because of the structural egress reason
    assert sb.secure is False


def test_good_status_strict_secure_false_due_to_egress(tmp_path: Path) -> None:
    """secure is always False for ContainerSandbox (structural egress reason)."""
    status_file = tmp_path / "status_good"
    status_file.write_text(_GOOD_STATUS)
    sb = ContainerSandbox(warn_on_insecure=False, status_path=status_file)
    assert sb.secure is False


# ---------------------------------------------------------------------------
# Test: hardening self-check — bad status
# ---------------------------------------------------------------------------

def test_bad_status_has_all_per_flag_reasons(tmp_path: Path) -> None:
    """'Bad' status → insecurity_reasons contains all three per-flag reasons + egress."""
    status_file = tmp_path / "status_bad"
    status_file.write_text(_BAD_STATUS)
    sb = ContainerSandbox(warn_on_insecure=True, status_path=status_file)
    reasons = sb.insecurity_reasons
    assert "no_new_privs_off" in reasons
    assert "seccomp_off" in reasons
    assert "cap_not_dropped" in reasons
    assert "network_egress_not_verified" in reasons
    assert sb.secure is False


# ---------------------------------------------------------------------------
# Test: hardening self-check — missing fields (partial status)
# ---------------------------------------------------------------------------

def test_partial_status_still_constructs(tmp_path: Path) -> None:
    """Missing /proc fields are treated as insecure (per-flag reasons recorded)."""
    status_file = tmp_path / "status_partial"
    status_file.write_text(_PARTIAL_STATUS)
    sb = ContainerSandbox(warn_on_insecure=True, status_path=status_file)
    reasons = sb.insecurity_reasons
    # Missing fields → all per-flag reasons recorded
    assert "no_new_privs_off" in reasons
    assert "seccomp_off" in reasons
    assert "cap_not_dropped" in reasons


# ---------------------------------------------------------------------------
# Test: warn_on_insecure=True (advisory) vs warn_on_insecure=False (strict)
# ---------------------------------------------------------------------------

def test_warn_on_insecure_false_bad_status_still_constructs(tmp_path: Path) -> None:
    """warn_on_insecure=False with bad status still constructs; caller uses secure/reasons."""
    status_file = tmp_path / "status_bad"
    status_file.write_text(_BAD_STATUS)
    # Should NOT raise on construction — secure/insecurity_reasons carry the result
    sb = ContainerSandbox(warn_on_insecure=False, status_path=status_file)
    assert "no_new_privs_off" in sb.insecurity_reasons
    assert sb.secure is False


def test_warn_on_insecure_env_default(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_WARN_ON_INSECURE=1 sets warn_on_insecure=True when omitted from constructor."""
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    status_file = tmp_path / "status_good"
    status_file.write_text(_GOOD_STATUS)
    sb = ContainerSandbox(status_path=status_file)
    # Should not raise and should have warn_on_insecure=True
    assert sb._warn_on_insecure is True


def test_warn_on_insecure_env_default_false(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_WARN_ON_INSECURE unset → warn_on_insecure=False by default."""
    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
    status_file = tmp_path / "status_good"
    status_file.write_text(_GOOD_STATUS)
    sb = ContainerSandbox(status_path=status_file)
    assert sb._warn_on_insecure is False


# ---------------------------------------------------------------------------
# Test: SandboxResult fields
# ---------------------------------------------------------------------------

def test_result_has_expected_fields(tmp_path: Path) -> None:
    """SandboxResult has exit_code, stdout, stderr, killed."""
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(argv=["/bin/echo", "test"])
    result = sb.run(req)
    assert isinstance(result.exit_code, int)
    assert isinstance(result.stdout, bytes)
    assert isinstance(result.stderr, bytes)
    assert isinstance(result.killed, bool)


# ---------------------------------------------------------------------------
# Test: shell=False / argv is a list (structural check via subprocess mock)
# ---------------------------------------------------------------------------

def test_run_uses_list_argv_not_shell(tmp_path: Path, monkeypatch) -> None:
    """Verify shell=True is never passed to subprocess.Popen (structural test)."""
    captured_kwargs: list[dict] = []
    original_popen = subprocess.Popen

    class CapturingPopen(original_popen):  # type: ignore[misc]
        def __init__(self, *args, **kwargs):
            captured_kwargs.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", CapturingPopen)
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(argv=["/bin/echo", "hello"])
    sb.run(req)
    assert captured_kwargs, "subprocess.Popen should have been called"
    for kw in captured_kwargs:
        assert not kw.get("shell", False), "shell=True must never be passed to Popen"


# ---------------------------------------------------------------------------
# Test: mounts advisory (no-op for container backend)
# ---------------------------------------------------------------------------

def test_mounts_are_advisory(tmp_path: Path) -> None:
    """ro_mounts / rw_mounts are accepted and don't raise; run succeeds."""
    from blastbox.worker.sandbox.base import Mount
    sb = _good_sandbox(tmp_path)
    req = SandboxRequest(
        argv=["/bin/echo", "hi"],
        ro_mounts=[Mount(source=tmp_path, target=Path("/in"))],
        rw_mounts=[Mount(source=tmp_path, target=Path("/out"), read_only=False)],
    )
    result = sb.run(req)
    assert result.exit_code == 0
