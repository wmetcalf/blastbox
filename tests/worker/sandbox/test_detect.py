"""TDD tests for select_sandbox().

Tests run on the host.  We inject a fake status_path so no /proc needed,
and use monkeypatching to control which backends are available.
"""
from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

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
    from .conftest import bwrap_usable

    # USABILITY, not presence: an installed bwrap that cannot unshare a namespace is one
    # select_sandbox correctly declines, so forcing it must skip rather than fail.
    _why_bwrap = bwrap_usable()
    if _why_bwrap:
        pytest.skip(_why_bwrap)
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


def test_select_sandbox_env_override_nono(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=nono forces the nono backend (wiring test, no real nono).

    nono is secure=False (no seccomp/namespaces), so forcing it also needs
    BLASTBOX_WARN_ON_INSECURE. The smoketest runs /usr/bin/true through nono — we
    inject a NonoSandbox with a fake Popen so the test needs neither nono nor Landlock.
    """
    from blastbox.worker.sandbox.nono import NonoSandbox

    monkeypatch.setenv("BLASTBOX_SANDBOX", "nono")
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")

    class _OkProc:
        returncode = 0
        pid = 1

        def communicate(self, timeout=None):
            return b"", b""

    import blastbox.worker.sandbox.detect as detect_mod

    def _patched(name, *, warn_on_insecure, status_path):
        assert name == "nono"
        return NonoSandbox(
            nono_bin="/usr/bin/true",
            state_dir=tmp_path / "nono-state",
            popen=lambda *a, **k: _OkProc(),
        )

    monkeypatch.setattr(detect_mod, "_make_backend", _patched)
    sb = select_sandbox(_status_path=tmp_path / "unused")
    assert isinstance(sb, NonoSandbox)
    assert sb.name == "nono"


def test_select_sandbox_env_override_nsjail(monkeypatch, tmp_path: Path) -> None:
    """BLASTBOX_SANDBOX=nsjail forces nsjail backend."""
    # USABILITY, not presence. On a host where nsjail is installed but unprivileged user
    # namespaces are restricted (Ubuntu 24.04's default), select_sandbox correctly refuses
    # with SandboxUnavailable -- so guarding on `which` alone let this test run where it
    # could not pass. Invisible until nsjail was installed somewhere that runs these tests.
    from .conftest import nsjail_usable

    why = nsjail_usable()
    if why:
        pytest.skip(why)
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
    import blastbox.worker.sandbox.detect as detect_mod
    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
    # Patch seccomp so bwrap can be used even without the lib.
    import blastbox.worker.sandbox.bwrap as bwrap_mod
    monkeypatch.setattr(bwrap_mod, "_LIBSECCOMP_AVAILABLE", False)

    sb = select_sandbox(_status_path=tmp_path / "unused")
    # USABILITY, not presence -- the second instance of the same mistake in this file. An
    # nsjail that is installed but cannot create user namespaces is one select_sandbox
    # correctly declines, so counting it as available made this expect a backend the product
    # had rightly refused. Caught the first time nsjail was actually installed where these
    # tests run (CI, #157).
    from .conftest import bwrap_usable, nsjail_usable

    has_nsjail = nsjail_usable() is None
    has_bwrap = bwrap_usable() is None
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


# ---------------------------------------------------------------------------
# Test: the "nothing is available" message names every rejection, not the last
# ---------------------------------------------------------------------------

class TestTheNothingAvailableMessageIsDiagnosable:
    """`last error` pointed at whichever backend happened to be LAST in the order.

    After #160 the realistic total failure is `apparmor_missing` on nsjail and bwrap --
    both of them, same cause, one command to fix. The old message reported `container`'s
    complaint instead (a different subsystem entirely), so the operator would start
    debugging container hardening for a problem in /sys/kernel/security/apparmor.
    """

    def _no_backend_at_all(self, monkeypatch, tmp_path: Path):
        import blastbox.worker.sandbox.detect as detect_mod

        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)

        class _Insecure:
            def __init__(self, name: str, reasons: list[str]) -> None:
                self._name, self.insecurity_reasons = name, reasons

            @property
            def secure(self) -> bool:
                return not self.insecurity_reasons

        reasons = {
            "nsjail": ["apparmor_missing"],
            "bwrap": ["seccomp_not_implemented", "apparmor_missing"],
            "nono": ["landlock_missing"],
            "container": ["network_egress_not_verified"],
        }
        monkeypatch.setattr(detect_mod, "_make_backend",
                            lambda name, **kw: _Insecure(name, list(reasons[name])))
        monkeypatch.setattr(detect_mod, "_smoketest", lambda sb: (True, None))
        return _good_status_file(tmp_path)

    def test_every_backend_is_named_with_its_own_reason(self, monkeypatch, tmp_path: Path) -> None:
        status = self._no_backend_at_all(monkeypatch, tmp_path)
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=status)
        msg = str(ei.value)
        for name in ("nsjail", "bwrap", "nono", "container"):
            assert name in msg, msg
        assert "apparmor_missing" in msg
        assert "seccomp_not_implemented" in msg
        assert "network_egress_not_verified" in msg

    def test_the_apparmor_case_names_both_ways_out(self, monkeypatch, tmp_path: Path) -> None:
        status = self._no_backend_at_all(monkeypatch, tmp_path)
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=status)
        msg = str(ei.value)
        assert "deploy/apparmor" in msg, "no pointer to the profile that fixes it"
        assert "BLASTBOX_WARN_ON_INSECURE" in msg, "no pointer to the knowing override"

    def test_the_hint_is_absent_when_apparmor_is_not_the_problem(
            self, monkeypatch, tmp_path: Path) -> None:
        """A hint that appears on every failure is noise, and teaches operators to set the
        override reflexively for problems it cannot fix."""
        import blastbox.worker.sandbox.detect as detect_mod

        self._no_backend_at_all(monkeypatch, tmp_path)

        class _Broken:
            secure = False
            insecurity_reasons = ["seccomp_off"]

        monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: _Broken())
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=_good_status_file(tmp_path))
        assert "deploy/apparmor" not in str(ei.value)


# ---------------------------------------------------------------------------
# Test: a child profile that denies the probe is diagnosed, not just "failed"
# ---------------------------------------------------------------------------

class TestAProfileThatDeniesTheProbeSaysSo:
    """The smoketest runs the REAL argv, AppArmor prefix included -- as it should, since a
    probe that skips the confinement tests something we never run.

    The cost: a child profile narrow enough for one parser can deny `/usr/bin/true`, and then
    a working backend carrying a working profile is rejected with nothing but "smoketest
    failed" to go on (codex, #177). The rejection stands -- a profile that cannot run the
    probe is a profile to fix, not one to bypass -- but it now says which of the two it is.
    """

    class _FakeSandbox:
        """Fails the probe while confined, passes with the profile suspended."""

        name = "nsjail"
        secure = True
        insecurity_reasons: list[str] = []
        apparmor_active = True
        _apparmor_profile = "my-parser-profile"

        def __init__(self) -> None:
            self.confined = True
            self.runs: list[bool] = []

        @contextlib.contextmanager
        def apparmor_suspended(self):
            self.confined = False
            try:
                yield
            finally:
                self.confined = True

        def run(self, req):
            self.runs.append(self.confined)
            code = 126 if self.confined else 0
            return SimpleNamespace(exit_code=code, killed=False, stdout=b"", stderr=b"")

    def _select(self, monkeypatch, tmp_path: Path):
        import blastbox.worker.sandbox.detect as detect_mod

        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        sb = self._FakeSandbox()
        monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: sb)
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=_good_status_file(tmp_path))
        return sb, str(ei.value)

    def test_the_message_names_the_profile_and_the_probe(self, monkeypatch, tmp_path: Path) -> None:
        _sb, msg = self._select(monkeypatch, tmp_path)
        assert "my-parser-profile" in msg
        assert "true" in msg
        assert "passes without it" in msg

    def test_the_backend_is_still_rejected(self, monkeypatch, tmp_path: Path) -> None:
        """Diagnosis is not permission. A probe that only passes unconfined has not shown
        that the workload can run, and running it anyway would be the 'configuration is
        present' answer to a question about whether it is in force."""
        _sb, msg = self._select(monkeypatch, tmp_path)
        assert "passes without it" in msg

    def test_selection_stops_here_instead_of_demoting_to_a_weaker_backend(
            self, monkeypatch, tmp_path: Path) -> None:
        """THE ONE THAT MATTERS. Falling through walks past bwrap (same profile, same
        denial), past nono, to `container` -- a plain subprocess on the host with no
        namespace, no seccomp and no MAC. Under BLASTBOX_WARN_ON_INSECURE=1, which this
        change's own error message recommends, that backend is selectable, so a too-narrow
        profile would silently move live malware from nsjail onto bare fork/exec
        (claude-security lens, #177).
        """
        import blastbox.worker.sandbox.detect as detect_mod

        seen: list[str] = []
        real = detect_mod._make_backend

        def _tracking(name, **kw):
            seen.append(name)
            if name == "nsjail":
                return self._FakeSandbox()
            return real(name, **kw)

        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        monkeypatch.setattr(detect_mod, "_make_backend", _tracking)

        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=_good_status_file(tmp_path))
        assert "denies the probe" in str(ei.value)
        assert seen == ["nsjail"], f"selection continued past the misconfigured profile: {seen}"

    def test_warn_on_insecure_does_not_unlock_it_either(
            self, monkeypatch, tmp_path: Path) -> None:
        """The variable relaxes the SECURITY gate, which this failure never reaches -- so
        offering it here would send an operator to permanently disable that gate for no
        benefit."""
        import blastbox.worker.sandbox.detect as detect_mod

        monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        monkeypatch.setattr(detect_mod, "_make_backend",
                            lambda name, **kw: self._FakeSandbox())
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=_good_status_file(tmp_path))
        assert "BLASTBOX_WARN_ON_INSECURE" not in str(ei.value)

    def test_the_confined_failure_is_confirmed_before_the_profile_is_blamed(
            self, monkeypatch, tmp_path: Path) -> None:
        """Three probes, in this order: confined (failed), confined again (confirm), then
        suspended. The conclusion aborts selection with no fallback, so one flaky run must not
        reach it (claude-code-review lens, round 2 of #177)."""
        sb, _msg = self._select(monkeypatch, tmp_path)
        assert sb.runs[:3] == [True, True, False], sb.runs
        assert sb.confined is True, "the suspension leaked past the probe"

    def test_a_probe_that_fails_once_and_then_passes_is_not_blamed_on_the_profile(
            self, monkeypatch, tmp_path: Path) -> None:
        """The flaky-host case: fail, then succeed. That is not a denial, and treating it as
        one stops a worker from starting on a host whose profile is fine."""
        import blastbox.worker.sandbox.detect as detect_mod

        sb = self._FakeSandbox()
        calls = {"n": 0}

        def _flaky(req):
            from types import SimpleNamespace
            calls["n"] += 1
            sb.runs.append(sb.confined)
            return SimpleNamespace(exit_code=(1 if calls["n"] == 1 else 0), killed=False,
                                   stdout=b"", stderr=b"")

        sb.run = _flaky                                  # type: ignore[method-assign]
        ok, err = detect_mod._smoketest(sb)
        assert not isinstance(err, detect_mod._ProfileDeniesProbe), (
            "a transient failure was attributed to the AppArmor profile"
        )

    def test_a_timeout_is_never_a_denial(self, monkeypatch, tmp_path: Path) -> None:
        """`killed` means the host was slow, and it arrives through the same failure channel
        as a refused execve."""
        import blastbox.worker.sandbox.detect as detect_mod

        sb = self._FakeSandbox()

        def _killed(req):
            from types import SimpleNamespace
            sb.runs.append(sb.confined)
            # Killed while confined: a slow host, not a denial.
            return SimpleNamespace(exit_code=-9, killed=sb.confined,
                                   stdout=b"", stderr=b"")

        sb.run = _killed                                 # type: ignore[method-assign]
        ok, err = detect_mod._smoketest(sb)
        assert not isinstance(err, detect_mod._ProfileDeniesProbe), str(err)

    def test_a_backend_with_no_profile_is_not_probed_twice(
            self, monkeypatch, tmp_path: Path) -> None:
        """No profile attached ⇒ nothing to suspend, and re-running a failing probe would
        only double the outage's cost."""
        import blastbox.worker.sandbox.detect as detect_mod

        sb = self._FakeSandbox()
        sb.apparmor_active = False
        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)

        def _only_nsjail(name, **kw):
            if name == "nsjail":
                return sb
            raise SandboxUnavailable(f"{name} not available in this test")

        monkeypatch.setattr(detect_mod, "_make_backend", _only_nsjail)
        with pytest.raises(SandboxUnavailable):
            select_sandbox(_status_path=_good_status_file(tmp_path))
        # The COUNT is the claim. `all(confined)` was true for one probe, two or ten, so the
        # test could not detect the doubling it is named for (claude-code-review lens, #177).
        assert sb.runs == [True], f"the failing probe ran {len(sb.runs)} times"


class TestTheRecoveryHintNamesTheHalfThatIsActuallyMissing:
    """`apparmor_missing` has two independent causes -- no `aa-exec` helper, or no enforcing
    profile -- and telling an operator with no helper to go load a profile sends them to fix
    the half that is already fine (codex, #177)."""

    def _msg(self, monkeypatch, tmp_path: Path, *, aa_exec: str | None) -> str:
        import blastbox.worker.sandbox.detect as detect_mod

        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        monkeypatch.setattr(detect_mod.shutil, "which", lambda _n: aa_exec)

        class _Insecure:
            secure = False
            insecurity_reasons = ["apparmor_missing"]

        monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: _Insecure())
        monkeypatch.setattr(detect_mod, "_smoketest", lambda sb: (True, None))
        with pytest.raises(SandboxUnavailable) as ei:
            select_sandbox(_status_path=_good_status_file(tmp_path))
        return str(ei.value)

    def test_no_helper_points_at_the_package(self, monkeypatch, tmp_path: Path) -> None:
        msg = self._msg(monkeypatch, tmp_path, aa_exec=None)
        assert "aa-exec" in msg
        assert "BLASTBOX_APPARMOR_PROFILE" not in msg, (
            "sent the operator to load a profile when the helper is what is missing"
        )

    def test_a_present_helper_points_at_the_profile(self, monkeypatch, tmp_path: Path) -> None:
        msg = self._msg(monkeypatch, tmp_path, aa_exec="/usr/bin/aa-exec")
        assert "BLASTBOX_APPARMOR_PROFILE" in msg
        assert "enforce or kill" in msg

    def test_both_ways_out_are_always_offered(self, monkeypatch, tmp_path: Path) -> None:
        for aa in (None, "/usr/bin/aa-exec"):
            msg = self._msg(monkeypatch, tmp_path, aa_exec=aa)
            assert "deploy/apparmor" in msg
            assert "BLASTBOX_WARN_ON_INSECURE" in msg


def test_forced_mode_gets_the_same_remedy_as_auto(monkeypatch, tmp_path: Path) -> None:
    """`BLASTBOX_SANDBOX` is the documented override, it is what the pre-#160 deployment
    recipe told operators to set, and it is what the in-tree bench uses -- so the operator who
    pinned a backend was the one who got `insecure: apparmor_missing` with none of the three
    remedies named, while auto-mode handed over all of them (claude-blast-radius lens, #177).
    """
    import blastbox.worker.sandbox.detect as detect_mod

    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)

    class _Insecure:
        name = "nsjail"
        secure = False
        insecurity_reasons = ["apparmor_missing"]

    monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: _Insecure())
    monkeypatch.setattr(detect_mod, "_smoketest", lambda sb: (True, None))

    with pytest.raises(SandboxUnavailable) as ei:
        select_sandbox(backend="nsjail", _status_path=_good_status_file(tmp_path))
    msg = str(ei.value)
    assert "deploy/apparmor" in msg
    assert "BLASTBOX_WARN_ON_INSECURE" in msg


def test_forced_mode_does_not_bolt_the_hint_onto_unrelated_failures(
        monkeypatch, tmp_path: Path) -> None:
    import blastbox.worker.sandbox.detect as detect_mod

    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)

    class _Insecure:
        name = "container"
        secure = False
        insecurity_reasons = ["seccomp_off"]

    monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: _Insecure())
    monkeypatch.setattr(detect_mod, "_smoketest", lambda sb: (True, None))
    with pytest.raises(SandboxUnavailable) as ei:
        select_sandbox(backend="container", _status_path=_good_status_file(tmp_path))
    assert "deploy/apparmor" not in str(ei.value)


def test_the_diagnosis_survives_the_regression_guard_on_a_REAL_backend(monkeypatch) -> None:
    """Two fixes from the previous round cancelled each other out.

    `apparmor_suspended()` fakes exactly the state the confinement-regression guard watches
    for -- armed at admission, not active now -- so the guard fired INSIDE the diagnostic
    probe, the suspended probe "failed" too, and `_ProfileDeniesProbe` became unreachable from
    a real backend. The demote-to-`container` path reopened, and the tests passed because the
    fake sandbox in this file has no guard: a mock talking to a mock
    (claude-security lens, round 2 of #177).

    So this one uses the REAL NsjailSandbox, with only the subprocess faked.
    """
    import logging

    import blastbox.worker.sandbox.detect as detect_mod
    import blastbox.worker.sandbox.nsjail as nj
    from blastbox.worker.sandbox.base import SandboxResult
    from blastbox.worker.sandbox.nsjail import NsjailSandbox

    logging.disable(logging.CRITICAL)
    monkeypatch.setattr(nj, "profile_loaded", lambda _p: True)
    monkeypatch.setattr(nj, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
    monkeypatch.setattr(nj, "_supports_proc_rw", lambda _p: True)
    sb = NsjailSandbox(nsjail_path="/bin/sh")
    assert sb._armed_at_admission and sb.apparmor_active

    def _run(self, req):
        # Confined: the profile denies the probe. Suspended: it runs.
        self._refuse_if_confinement_regressed()
        return SandboxResult(exit_code=(126 if self._aa_exec else 0),
                             stdout=b"", stderr=b"", killed=False)

    monkeypatch.setattr(NsjailSandbox, "run", _run)
    ok, err = detect_mod._smoketest(sb)
    logging.disable(logging.NOTSET)
    assert ok is False
    assert isinstance(err, detect_mod._ProfileDeniesProbe), (
        f"the profile denial was not diagnosed: {type(err).__name__}: {err}"
    )
    assert sb._suspended_for_diagnosis is False, "the suspension leaked past the probe"


def test_admission_is_recorded_when_the_selector_admits_not_at_construction(
        monkeypatch, tmp_path: Path) -> None:
    """`_armed_at_admission` was captured in the CONSTRUCTOR, which is not when admission
    happens.

    A profile that becomes enforcing between construction and the selector's security check
    gets the backend admitted as confined with the flag still False -- and the
    confinement-regression guard is then inert for the life of that worker (codex, #177). The
    selector knows the real moment.
    """
    import blastbox.worker.sandbox.detect as detect_mod

    class _LateArming:
        name = "nsjail"
        insecurity_reasons: list[str] = []
        secure = True

        def __init__(self) -> None:
            self.apparmor_active = False          # absent at construction ...
            self._armed_at_admission = False

        def note_admitted(self) -> None:
            self._armed_at_admission = self.apparmor_active

        def run(self, req):
            from types import SimpleNamespace
            self.apparmor_active = True            # ... enforcing by the time it is probed
            return SimpleNamespace(exit_code=0, killed=False, stdout=b"", stderr=b"")

    sb = _LateArming()
    monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
    monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
    monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: sb)

    got = select_sandbox(_status_path=_good_status_file(tmp_path))
    assert got is sb
    assert sb._armed_at_admission is True, (
        "the backend was admitted as confined but the guard will treat it as never armed"
    )


class TestBothAdmissionPathsRecordAdmissionOnTheRealBackends:
    """`note_admitted` is called through `getattr`, so a backend that loses or renames it gets
    no admission record and the regression guard silently falls back to the constructor
    snapshot -- the bug the call exists to fix.

    Verified that deleting the `_select_forced` call AND renaming `NsjailSandbox.note_admitted`
    left 191/191 tests passing: the one existing test used a hand-rolled fake that implements
    the method itself, so it pinned detect.py's auto path and nothing else
    (claude-code-review lens, round 3 of #177).
    """

    @pytest.mark.parametrize("backend", ["nsjail", "bwrap"])
    def test_the_real_backends_have_the_method(self, backend: str) -> None:
        import blastbox.worker.sandbox.bwrap as bw
        import blastbox.worker.sandbox.nsjail as nj

        cls = nj.NsjailSandbox if backend == "nsjail" else bw.BubblewrapSandbox
        assert callable(getattr(cls, "note_admitted", None)), (
            f"{cls.__name__} has no note_admitted, so the selector silently records nothing"
        )

    def _armed(self, monkeypatch, tmp_path: Path, *, forced: bool) -> bool:
        import blastbox.worker.sandbox.detect as detect_mod

        class _LateArming:
            name = "nsjail"
            insecurity_reasons: list[str] = []
            secure = True
            apparmor_active = False
            _armed_at_admission = False

            def note_admitted(self) -> None:
                self._armed_at_admission = self.apparmor_active

            def run(self, req):
                from types import SimpleNamespace
                self.apparmor_active = True
                return SimpleNamespace(exit_code=0, killed=False, stdout=b"", stderr=b"")

        sb = _LateArming()
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        monkeypatch.setattr(detect_mod, "_make_backend", lambda name, **kw: sb)
        status = _good_status_file(tmp_path)
        if forced:
            select_sandbox(backend="nsjail", _status_path=status)
        else:
            select_sandbox(_status_path=status)
        return sb._armed_at_admission

    def test_the_auto_path_records_it(self, monkeypatch, tmp_path: Path) -> None:
        assert self._armed(monkeypatch, tmp_path, forced=False) is True

    def test_the_forced_path_records_it_too(self, monkeypatch, tmp_path: Path) -> None:
        """`BLASTBOX_SANDBOX` is the documented override and what the pre-#160 recipe told
        operators to set; it had no coverage at all."""
        assert self._armed(monkeypatch, tmp_path, forced=True) is True
