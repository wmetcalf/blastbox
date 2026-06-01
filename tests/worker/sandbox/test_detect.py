"""TDD tests for select_sandbox().

Tests run on the host.  We inject a fake status_path so no /proc needed,
and use monkeypatching to control which backends are available.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.errors import SandboxUnavailable
from blastbox.worker.sandbox.detect import select_sandbox, _in_container
from blastbox.worker.sandbox.container import ContainerSandbox
from blastbox.worker.sandbox.bwrap import BubblewrapSandbox
from blastbox.worker.sandbox.nsjail import NsjailSandbox


_GOOD_STATUS = """\
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""


def _good_status_file(tmp_path: Path) -> Path:
    p = tmp_path / "proc_status"
    p.write_text(_GOOD_STATUS)
    return p


# ---------------------------------------------------------------------------
# Test: forced backend selection
# ---------------------------------------------------------------------------

def test_select_sandbox_container_backend(monkeypatch, tmp_path: Path) -> None:
    """select_sandbox(backend='container') returns a ContainerSandbox."""
    status_file = _good_status_file(tmp_path)
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")

    sb = select_sandbox(
        backend="container",
        _status_path=status_file,
    )
    assert isinstance(sb, ContainerSandbox)
    assert sb.name == "container"


def test_select_sandbox_env_override_container(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=container forces container backend."""
    status_file = _good_status_file(tmp_path)
    monkeypatch.setenv("BLASTBOX_SANDBOX", "container")
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")

    sb = select_sandbox(_status_path=status_file)
    assert isinstance(sb, ContainerSandbox)


def test_select_sandbox_env_override_bwrap(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=bwrap forces bwrap backend."""
    import shutil
    if not shutil.which("bwrap"):
        pytest.skip("bwrap not installed")
    monkeypatch.setenv("BLASTBOX_SANDBOX", "bwrap")
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    # Patch seccomp lib to False so bwrap can be used without the lib.
    import blastbox.worker.sandbox.bwrap as bwrap_mod
    monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)

    # The smoketest in select_sandbox runs /usr/bin/true through bwrap.
    # We monkeypatch _make_backend so we can disable aa-exec on the
    # BubblewrapSandbox instance (the default profile may not be loaded).
    import blastbox.worker.sandbox.detect as detect_mod
    original_make_backend = detect_mod._make_backend

    def _patched_make_backend(name, *, warn_on_insecure, status_path):
        sb = original_make_backend(name, warn_on_insecure=warn_on_insecure, status_path=status_path)
        if name == "bwrap":
            sb._aa_exec = None  # disable aa-exec so profile isn't required
        return sb

    monkeypatch.setattr(detect_mod, "_make_backend", _patched_make_backend)

    sb = select_sandbox(_status_path=tmp_path / "unused")
    assert isinstance(sb, BubblewrapSandbox)
    assert sb.name == "bwrap"


def test_select_sandbox_env_override_nsjail(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=nsjail forces nsjail backend."""
    import shutil
    if not shutil.which("nsjail"):
        pytest.skip("nsjail not installed")
    monkeypatch.setenv("BLASTBOX_SANDBOX", "nsjail")
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")

    sb = select_sandbox(_status_path=tmp_path / "unused")
    assert isinstance(sb, NsjailSandbox)
    assert sb.name == "nsjail"


# ---------------------------------------------------------------------------
# Test: auto-selection
# ---------------------------------------------------------------------------

def test_select_sandbox_auto_container_inside_container(monkeypatch, tmp_path: Path) -> None:
    """Inside a container, auto mode picks the container backend."""
    import blastbox.worker.sandbox.detect as detect_mod
    status_file = _good_status_file(tmp_path)
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    # Force _in_container() to return True.
    monkeypatch.setattr(detect_mod, "_in_container", lambda: True)

    sb = select_sandbox(_status_path=status_file)
    assert isinstance(sb, ContainerSandbox)


def test_select_sandbox_auto_host_prefers_nsjail_or_bwrap(monkeypatch, tmp_path: Path) -> None:
    """On a bare-metal host, auto mode picks nsjail or bwrap (not container).

    If neither nsjail nor bwrap is functional, falls back to container.
    """
    import shutil
    import blastbox.worker.sandbox.detect as detect_mod
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
    # Patch seccomp so bwrap can be used even without the lib.
    import blastbox.worker.sandbox.bwrap as bwrap_mod
    monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)

    sb = select_sandbox(_status_path=tmp_path / "unused")
    # On this host nsjail and bwrap are installed, so we expect one of them.
    has_nsjail = shutil.which("nsjail") is not None
    has_bwrap = shutil.which("bwrap") is not None
    if has_nsjail or has_bwrap:
        assert sb.name in ("nsjail", "bwrap"), (
            f"Expected nsjail or bwrap on bare-metal host, got {sb.name!r}"
        )
    else:
        # Falls back to container if neither is available.
        assert isinstance(sb, ContainerSandbox)


# ---------------------------------------------------------------------------
# Test: smoketest
# ---------------------------------------------------------------------------

def test_select_sandbox_smoketest_passes(monkeypatch, tmp_path: Path) -> None:
    """/usr/bin/true smoketest succeeds for container backend."""
    status_file = _good_status_file(tmp_path)
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")

    sb = select_sandbox(backend="container", _status_path=status_file)
    from blastbox.worker.sandbox.base import SandboxRequest
    result = sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert result.exit_code == 0
    assert not result.killed


# ---------------------------------------------------------------------------
# Test: invalid / unknown backend
# ---------------------------------------------------------------------------

def test_select_sandbox_invalid_backend_raises(monkeypatch) -> None:
    """Unknown backend name → SandboxUnavailable."""
    with pytest.raises(SandboxUnavailable):
        select_sandbox(backend="nonexistent_backend_xyz")


def test_select_sandbox_env_invalid_raises(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=<unknown> → SandboxUnavailable."""
    monkeypatch.setenv("BLASTBOX_SANDBOX", "totally_unknown_backend_xyz")
    with pytest.raises(SandboxUnavailable):
        select_sandbox(_status_path=tmp_path / "nope")


# ---------------------------------------------------------------------------
# Test: insecure backend rejected in auto mode without WARN_ON_INSECURE
# ---------------------------------------------------------------------------

def test_select_sandbox_refuses_insecure_in_auto(monkeypatch, tmp_path: Path) -> None:
    """In auto mode without WARN_ON_INSECURE, an insecure backend is skipped.

    We force container to be the only candidate (simulate inside-container),
    and the container backend is always insecure (network_egress_not_verified).
    With BLASTBOX_WARN_ON_INSECURE unset, no backend passes → SandboxUnavailable.
    """
    import blastbox.worker.sandbox.detect as detect_mod
    status_file = _good_status_file(tmp_path)
    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    # Force container-only auto-selection (simulate inside a container).
    monkeypatch.setattr(detect_mod, "_in_container", lambda: True)

    with pytest.raises(SandboxUnavailable):
        select_sandbox(_status_path=status_file)


def test_select_sandbox_allows_insecure_with_warn_on_insecure(monkeypatch, tmp_path: Path) -> None:
    """With BLASTBOX_WARN_ON_INSECURE=1, an insecure backend is accepted."""
    import blastbox.worker.sandbox.detect as detect_mod
    status_file = _good_status_file(tmp_path)
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    monkeypatch.setattr(detect_mod, "_in_container", lambda: True)

    sb = select_sandbox(_status_path=status_file)
    assert isinstance(sb, ContainerSandbox)


# ---------------------------------------------------------------------------
# Test: forced insecure backend refused without WARN_ON_INSECURE
# ---------------------------------------------------------------------------

def test_select_sandbox_forced_insecure_refused(monkeypatch, tmp_path: Path) -> None:
    """Forced backend that is insecure → SandboxUnavailable without WARN_ON_INSECURE."""
    status_file = _good_status_file(tmp_path)
    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)

    # ContainerSandbox is always insecure (network_egress_not_verified).
    with pytest.raises(SandboxUnavailable, match="insecure"):
        select_sandbox(backend="container", _status_path=status_file)


# ---------------------------------------------------------------------------
# Test: _in_container helper
# ---------------------------------------------------------------------------

def test_in_container_returns_bool() -> None:
    """_in_container() always returns a bool (not None)."""
    result = _in_container()
    assert isinstance(result, bool)
