"""TDD tests for NsjailSandbox.

Structure
---------
1. argv-building unit tests (call _build_argv without running nsjail).
2. insecurity_reasons unit tests (monkeypatch seccomp policy path).
3. Real smoke-run tests (nsjail IS installed; skip if userns restricted).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blastbox.limits import Limits
from blastbox.worker.sandbox.base import Mount, SandboxRequest
from blastbox.worker.sandbox.nsjail import NsjailSandbox, _SECCOMP_POLICY_CANDIDATES


# A stand-in nsjail for tests that only need the binary to EXIST. It answers --help the way
# a real one does, because the backend now asks whether this build has `--proc_rw` before
# attaching an AppArmor prefix that cannot execve without it.
_FAKE_NSJAIL = "#!/bin/sh\ncase \"$1\" in --help) echo '  --proc_rw';; esac\nexit 0\n"


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
            argv[i + 1]
            for i in range(len(argv) - 1)
            if argv[i] == "--bindmount_ro"
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
            if argv[i] == "--bindmount"
            and i + 1 < len(argv)
            and ":" in argv[i + 1]
        ]
        assert "/tmp/output:/jail/output" in bm_values, (
            f"rw mount not found in --bindmount values; bm_values={bm_values}"
        )

    def test_env_as_env_flag(self) -> None:
        """request.env items appear as --env KEY=VALUE."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"], env={"MYVAR": "hello"})
        argv = sb._build_argv(req)
        env_values = [
            argv[i + 1]
            for i in range(len(argv) - 1)
            if argv[i] == "--env"
        ]
        assert "MYVAR=hello" in env_values

    def test_minimal_env_always_injected(self) -> None:
        """PATH and HOME are always present via --env (from _MINIMAL_ENV)."""
        sb = _make_sandbox()
        req = SandboxRequest(argv=["/usr/bin/true"])
        argv = sb._build_argv(req)
        env_values = [
            argv[i + 1]
            for i in range(len(argv) - 1)
            if argv[i] == "--env"
        ]
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
        assert argv[dd_idx + 1:] == inner

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

    def test_secure_true_when_policy_present(self, tmp_path: Path, monkeypatch) -> None:
        """secure is True when the policy file is found AND AppArmor is really applied.

        BOTH probes are pinned. Reading them from the host made this test host-dependent the
        moment `apparmor_missing` became a reason: on a machine whose nsjail advertises
        --proc_apparmor with no `blastbox-sandbox` profile loaded -- the exact case this change
        is about -- `secure` is legitimately False and the assertion below would fail for a
        correct product (codex, #159).
        """
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now", lambda self: True)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        sb = _make_sandbox(seccomp_policy=policy)
        # Both reasons must be clear for secure: apparmor_missing is a reason now too.
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
        """Skip if nsjail cannot run a one-shot on this host.

        The probe is shared with test_detect via conftest: the two had different answers to
        the same question, and the weaker one let a test run where it could not pass.
        """
        from .conftest import nsjail_usable

        why = nsjail_usable()
        if why:
            pytest.skip(why)

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


class TestAppArmorIsAttachedWithAaExecBecauseNsjailHasNoFlagForIt:
    """NSJAIL HAS NO APPARMOR SUPPORT AT ALL, and this backend spent its life pretending
    otherwise.

    It probed for `--proc_apparmor` and attached the profile with it. That flag does not
    exist in nsjail and never has — verified three ways against upstream: `nsjail --help`
    mentions apparmor zero times, and a GitHub code search for both `proc_apparmor` and
    plain `apparmor` in google/nsjail returns 0 hits across the entire tree. So the probe
    was always False, the branch never ran, and an nsjail-sandboxed child never received a
    profile.

    The reporting made it worse than silent: `insecurity_reasons` gated `apparmor_missing`
    on that same always-False probe, so nsjail reported `secure = True` with no
    confinement mechanism whatsoever — while bwrap, in the identical situation, correctly
    reported itself insecure. Two backends, opposite answers about their own hardening, and
    the one that stayed quiet was the one with nothing.

    The profile is now attached the way bwrap attaches it: `aa-exec -p <profile> --` on the
    inner argv, a userspace helper that needs nothing from nsjail. That keeps the hardening
    the dead code intended rather than deleting the intent along with the flag.
    """

    def _sb(self, tmp_path, monkeypatch, *, aa_exec="/usr/sbin/aa-exec", enforcing=True):
        """A fully-equipped sandbox with both AppArmor probes pinned.

        Constructed directly rather than through _make_sandbox: this whole class is about
        what the backend REPORTS, and _make_sandbox skips when nsjail is absent -- which
        would have silently skipped the regression tests for this very bug on every host
        that does not happen to have nsjail installed (including the host it was written
        on). A stand-in executable satisfies the binary_present probe so the only reasons
        left are the ones under test.
        """
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: aa_exec)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now",
                            lambda self: enforcing)
        fake_nsjail = tmp_path / "nsjail"
        fake_nsjail.write_text(_FAKE_NSJAIL)
        fake_nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        return NsjailSandbox(nsjail_path=str(fake_nsjail), seccomp_policy=policy)

    def test_nsjail_is_never_given_an_apparmor_flag(self, tmp_path, monkeypatch) -> None:
        """The whole premise. If a flag reappears, it is one nsjail will reject or ignore,
        and the confinement will silently not happen again."""
        argv = self._sb(tmp_path, monkeypatch)._build_argv(
            SandboxRequest(argv=["/usr/bin/true"]))
        assert not any("apparmor" in a for a in argv if a.startswith("--")), (
            f"an apparmor flag was passed to nsjail: {argv}"
        )

    def test_the_profile_is_attached_to_the_inner_argv(self, tmp_path, monkeypatch) -> None:
        argv = self._sb(tmp_path, monkeypatch)._build_argv(
            SandboxRequest(argv=["/usr/bin/true"]))
        sep = argv.index("--")
        assert argv[sep + 1:] == ["/usr/sbin/aa-exec", "-p", "blastbox-sandbox", "--",
                                  "/usr/bin/true"], argv[sep:]

    def test_an_unconfirmed_profile_is_skipped_rather_than_breaking_every_run(
            self, tmp_path, monkeypatch) -> None:
        """aa-exec against a profile that is not loaded fails the execve, so attaching it
        unconditionally would not weaken the sandbox -- it would break it."""
        argv = self._sb(tmp_path, monkeypatch, enforcing=False)._build_argv(
            SandboxRequest(argv=["/usr/bin/true"]))
        assert "aa-exec" not in " ".join(argv)
        assert argv[argv.index("--") + 1:] == ["/usr/bin/true"]

    def test_a_missing_helper_is_skipped_too(self, tmp_path, monkeypatch) -> None:
        argv = self._sb(tmp_path, monkeypatch, aa_exec=None)._build_argv(
            SandboxRequest(argv=["/usr/bin/true"]))
        assert "aa-exec" not in " ".join(argv)
        assert argv[argv.index("--") + 1:] == ["/usr/bin/true"]

    def test_no_helper_is_reported_insecure_not_silently_secure(
            self, tmp_path, monkeypatch) -> None:
        """THE BUG THIS CLASS REPLACES. The old test here asserted that "nothing is
        reported when nsjail cannot do it anyway" -- pinning the defect as intended
        behaviour. A backend with no confinement mechanism must not call itself secure."""
        sb = self._sb(tmp_path, monkeypatch, aa_exec=None)
        assert "apparmor_missing" in sb.insecurity_reasons
        assert sb.secure is False

    def test_an_unenforcing_profile_is_reported_insecure(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, enforcing=False)
        assert "apparmor_missing" in sb.insecurity_reasons
        assert sb.secure is False

    def test_both_present_and_enforcing_is_secure(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch)
        assert sb.insecurity_reasons == []
        assert sb.secure is True
        assert sb.apparmor_active is True

    def test_apparmor_active_means_attached_not_merely_possible(
            self, tmp_path, monkeypatch) -> None:
        assert self._sb(tmp_path, monkeypatch, enforcing=False).apparmor_active is False
        assert self._sb(tmp_path, monkeypatch, aa_exec=None).apparmor_active is False

    def test_proc_is_made_writable_only_when_aa_exec_is_attached(
            self, tmp_path, monkeypatch) -> None:
        """THE REASON THIS WAS CALLED IMPOSSIBLE FOR NSJAIL.

        aa-exec performs the transition by writing /proc/self/attr/exec, and nsjail mounts
        /proc read-only by default, so the write returns EROFS and the execve FAILS -- not
        the confinement, the whole job. Measured inside this exact argv on an AppArmor 4.x
        host with the repo's own nsjail:

            default    open('/proc/self/attr/exec','w') -> [Errno EROFS]
                       aa-exec: ERROR: Read-only file system   (rc=1, nothing runs)
            --proc_rw  write succeeds, child reports the target profile

        So `--proc_rw` is not optional decoration next to the prefix -- without it the
        prefix is an outage. The two must appear together or not at all.
        """
        with_aa = self._sb(tmp_path, monkeypatch)._build_argv(
            SandboxRequest(argv=["/usr/bin/true"]))
        assert "--proc_rw" in with_aa
        assert with_aa.index("--proc_rw") < with_aa.index("--"), (
            "--proc_rw landed after the separator, where nsjail will not read it"
        )

    def test_proc_stays_read_only_when_no_profile_is_attached(
            self, tmp_path, monkeypatch) -> None:
        """The converse: a writable /proc buys nothing without aa-exec, so a malware
        sandbox does not get one. (Cheap at uid 65534 -- re-probed both ways, every
        sensitive /proc write stayed blocked -- but 'cheap' is not 'free'.)"""
        for kwargs in ({"aa_exec": None}, {"enforcing": False}):
            argv = self._sb(tmp_path, monkeypatch, **kwargs)._build_argv(
                SandboxRequest(argv=["/usr/bin/true"]))
            assert "--proc_rw" not in argv, kwargs

    def test_the_profile_is_read_once_per_launch_not_twice(
            self, tmp_path, monkeypatch) -> None:
        """The flag and the prefix must be decided by the SAME answer. Two reads of
        securityfs can straddle a profile being unloaded, and either half alone is broken:
        `--proc_rw` with no aa-exec loosens /proc for nothing, aa-exec with no `--proc_rw`
        fails every execve."""
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        calls = {"n": 0}

        def _counting(self) -> bool:
            calls["n"] += 1
            return calls["n"] == 1   # True first, False after: a profile unloaded mid-build

        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now", _counting)
        fake_nsjail = tmp_path / "nsjail"
        fake_nsjail.write_text(_FAKE_NSJAIL)
        fake_nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        sb = mod.NsjailSandbox(nsjail_path=str(fake_nsjail), seccomp_policy=policy)
        calls["n"] = 0

        argv = sb._build_argv(SandboxRequest(argv=["/usr/bin/true"]))
        assert calls["n"] == 1, f"securityfs read {calls['n']} times while building one argv"
        assert ("--proc_rw" in argv) == ("aa-exec" in " ".join(argv))

    def test_the_mode_is_re_read_so_a_switch_to_complain_shows_up(
            self, tmp_path, monkeypatch) -> None:
        """A profile flipped to complain mid-life must stop counting as confinement, so
        the mode cannot be cached at construction."""
        import blastbox.worker.sandbox.nsjail as mod

        state = {"enforcing": True}
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now",
                            lambda self: state["enforcing"])
        fake_nsjail = tmp_path / "nsjail"
        fake_nsjail.write_text(_FAKE_NSJAIL)
        fake_nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        sb = NsjailSandbox(nsjail_path=str(fake_nsjail), seccomp_policy=policy)

        assert "apparmor_missing" not in sb.insecurity_reasons
        assert "aa-exec" in " ".join(sb._build_argv(SandboxRequest(argv=["/usr/bin/true"])))
        state["enforcing"] = False
        assert "apparmor_missing" in sb.insecurity_reasons
        assert "aa-exec" not in " ".join(
            sb._build_argv(SandboxRequest(argv=["/usr/bin/true"])))



def test_the_two_backends_apply_and_report_apparmor_the_same_way(tmp_path, monkeypatch) -> None:
    """The issue's core complaint: bwrap and nsjail in the SAME state gave opposite answers
    about their own hardening, and the silent one had no mechanism at all.

    This asserted it by grepping each module's SOURCE for the strings "apparmor_missing" and
    "aa-exec" -- which the PRE-FIX nsjail.py also contained (the reason string was there,
    gated on the dead probe, and "aa-exec" appeared in a comment about what bwrap does). So
    the test could not tell "nsjail attaches a profile" from "nsjail has a comment mentioning
    that bwrap does", and passed against the exact code it was written to condemn
    (claude-code-review lens, #177). Behaviour, not text, from here on.
    """
    import blastbox.worker.sandbox.bwrap as bw
    import blastbox.worker.sandbox.nsjail as nj

    fake = tmp_path / "bin"
    fake.mkdir()
    for n in ("nsjail", "bwrap"):
        (fake / n).write_text(_FAKE_NSJAIL)
        (fake / n).chmod(0o755)
    policy = tmp_path / "ok.policy"
    policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")

    for mod in (nj, bw):
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: None)
    monkeypatch.setattr(nj, "_supports_proc_rw", lambda _p: True)
    without = [
        nj.NsjailSandbox(nsjail_path=str(fake / "nsjail"), seccomp_policy=policy),
        bw.BubblewrapSandbox(bwrap_path=str(fake / "bwrap")),
    ]
    for sb in without:
        assert "apparmor_missing" in sb.insecurity_reasons, sb.name
        assert sb.apparmor_active is False, sb.name
        assert "aa-exec" not in " ".join(sb._build_argv(SandboxRequest(argv=["/bin/true"])))

    for mod in (nj, bw):
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "profile_loaded", lambda _n: True)
        monkeypatch.setattr(type(without[0]) if mod is nj else type(without[1]),
                            "_apparmor_enforcing_now", lambda self: True)
    with_profile = [
        nj.NsjailSandbox(nsjail_path=str(fake / "nsjail"), seccomp_policy=policy),
        bw.BubblewrapSandbox(bwrap_path=str(fake / "bwrap")),
    ]
    for sb in with_profile:
        assert "apparmor_missing" not in sb.insecurity_reasons, sb.name
        assert sb.apparmor_active is True, sb.name
        argv = sb._build_argv(SandboxRequest(argv=["/bin/true"]))
        assert "aa-exec" in " ".join(argv), f"{sb.name} claims a profile it does not attach"


class TestTheInstalledNsjailIsAskedWhetherItHasProcRw:
    """aa-exec needs ``--proc_rw``; a build without it turns the prefix into
    `Unknown argument: --proc_rw` on every job.

    Worse, that failure is indistinguishable at the selector from a profile that denies the
    probe binary -- the diagnosis re-probes with the profile suspended, which ALSO drops
    --proc_rw, so the second probe passes and the operator is told to go fix a profile that
    is correct (claude-code-review lens, #177). So the flag is probed, and an nsjail without
    it reports `apparmor_missing` instead of attaching an argv that cannot run.
    """

    def _sb(self, tmp_path, monkeypatch, *, supported: bool):
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: supported)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now", lambda self: True)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        return mod.NsjailSandbox(nsjail_path=str(nsjail), seccomp_policy=policy)

    def test_no_proc_rw_means_no_attachment_and_an_honest_reason(
            self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, supported=False)
        argv = sb._build_argv(SandboxRequest(argv=["/usr/bin/true"]))
        assert "aa-exec" not in " ".join(argv), "attached a prefix that cannot execve"
        assert "--proc_rw" not in argv
        assert "apparmor_missing" in sb.insecurity_reasons
        assert sb.apparmor_active is False

    def test_with_proc_rw_the_attachment_happens(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, supported=True)
        argv = sb._build_argv(SandboxRequest(argv=["/usr/bin/true"]))
        assert "--proc_rw" in argv and "aa-exec" in " ".join(argv)
        assert sb.apparmor_active is True

    def test_an_unprobeable_binary_fails_safe(self, tmp_path, monkeypatch) -> None:
        """An nsjail that cannot be asked is not an nsjail that can be trusted with an argv
        that fails closed on every job."""
        import blastbox.worker.sandbox.nsjail as mod

        assert mod._supports_proc_rw(str(tmp_path / "does-not-exist")) is False

    def test_the_real_installed_nsjail_is_measured_not_assumed(self) -> None:
        import shutil

        import blastbox.worker.sandbox.nsjail as mod

        nsjail = shutil.which("nsjail")
        if nsjail is None:
            pytest.skip("nsjail not installed on this host")
        assert mod._supports_proc_rw(nsjail) is True, (
            "the installed nsjail rejects --proc_rw, so AppArmor cannot be attached here"
        )


class TestTheConstructorLogSaysWhatWillActuallyHappen:
    """`attach_enabled` was logged whenever aa-exec existed, profile or no profile -- at INFO,
    while bwrap logged `attach_skipped` at WARNING from identical state. Two backends
    disagreeing about their own hardening in the logs, with the accurate one at the level
    that does not page anyone (claude-code-review lens, #177)."""

    def _logs(self, tmp_path, monkeypatch, caplog, *, enforcing: bool) -> str:
        import logging

        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now",
                            lambda self: enforcing)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        with caplog.at_level(logging.INFO, logger="blastbox.worker.sandbox.nsjail"):
            mod.NsjailSandbox(nsjail_path=str(nsjail))
        return caplog.text

    def test_no_profile_logs_skipped_not_enabled(self, tmp_path, monkeypatch, caplog) -> None:
        text = self._logs(tmp_path, monkeypatch, caplog, enforcing=False)
        assert "attach_skipped" in text
        assert "attach_enabled" not in text

    def test_a_profile_logs_enabled(self, tmp_path, monkeypatch, caplog) -> None:
        text = self._logs(tmp_path, monkeypatch, caplog, enforcing=True)
        assert "attach_enabled" in text


@pytest.mark.skipif(
    shutil.which("nsjail") is None, reason="nsjail not installed on this host"
)
@pytest.mark.skipif(
    shutil.which("aa-exec") is None, reason="aa-exec not installed on this host"
)
@pytest.mark.skipif(
    not Path("/sys/kernel/security/apparmor").is_dir(), reason="AppArmor not enabled"
)
def test_the_product_argv_really_transitions_the_child(monkeypatch) -> None:
    """END TO END, through the PRODUCT's own argv -- which the previous version of this test
    did not do.

    It built the argv, and if `--proc_rw` was absent it compared that argv against itself
    plus the flag. That measures upstream nsjail's /proc semantics; it says nothing about
    whether this backend attaches anything, and it PASSED against the pre-#160 nsjail.py
    with the dead probe and no aa-exec anywhere (claude-code-review lens, #177 — verified by
    reverting the file and watching it pass).

    Here the sandbox is constructed the way a worker constructs it and `run()` is called.
    `unconfined` is used as the profile because it is the one name always valid as a
    transition target, so the test needs no root and no loaded profile: it asserts the child
    reports the profile the argv asked for, which is only true if the transition reached the
    kernel. Reverting the fix leaves the child reporting the host's own profile, and this
    fails.
    """
    import blastbox.worker.sandbox.nsjail as mod

    monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILE", "unconfined")
    monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILES", "unconfined")
    # `unconfined` is the one profile name always valid as a transition target, which is what
    # lets this test run without root and without a loaded profile. It is deliberately NOT
    # enforcing, so the assertion-believability check correctly refuses to arm on it -- and
    # that check is not this test's subject. Tell the backend the kernel confirmed the
    # profile, so the attach path under test runs; what the child reports back is still the
    # kernel's own answer, and is still the only thing asserted.
    import blastbox.worker.sandbox.apparmor as aa

    monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.KERNEL)

    from .conftest import nsjail_usable

    # Namespace creation, not just installation. Without this the test FAILS where the
    # existing smoke-run tests skip -- nsjail exits 255 with "Couldn't initialize net
    # namespace" on a host with restricted userns, and the assertions below then report an
    # AppArmor problem that is really a kernel policy one (codex, #177).
    why = nsjail_usable()
    if why:
        pytest.skip(f"nsjail not usable here: {why}")

    nsjail = shutil.which("nsjail")
    assert nsjail is not None                       # guarded by the skipif above
    if not mod._supports_proc_rw(nsjail):
        pytest.skip("this nsjail build has no --proc_rw, so no profile can be attached")

    # NOT a skip. Every prerequisite is present and asserted above, so a backend that does
    # not arm here is the product failing, and the reverted-code version of this test
    # SKIPPED instead of failing -- which is how a test that cannot catch its own regression
    # looks from the outside (it went green against pre-#160 nsjail.py).
    sb = NsjailSandbox()
    assert sb.apparmor_active is True, (
        f"aa-exec, nsjail --proc_rw and an asserted enforcing profile are all present, yet "
        f"the backend did not arm: {sb.insecurity_reasons}"
    )

    argv = sb._build_argv(SandboxRequest(argv=["/bin/sh", "-c", "cat /proc/self/attr/current"]))
    assert "--proc_rw" in argv, argv
    assert "aa-exec" in " ".join(argv), argv

    res = sb.run(SandboxRequest(argv=["/bin/sh", "-c", "cat /proc/self/attr/current"]))
    assert res.exit_code == 0, (res.exit_code, res.stderr[-300:])
    assert res.stdout.decode().strip() == "unconfined", (
        f"the child reports {res.stdout!r}, so the transition did not happen -- it is "
        f"running under the host's own profile, not the one the argv asked for"
    )

    # ... and the flag is load-bearing, not decoration: the same argv without it is the
    # EROFS outage that made this route look impossible for nsjail.
    import subprocess

    stripped = [a for a in argv if a not in ("--proc_rw", "--really_quiet")]
    p = subprocess.run(stripped, capture_output=True, text=True, timeout=120)
    assert p.returncode != 0 and "Read-only file system" in p.stderr, (
        f"expected EROFS without --proc_rw, got rc={p.returncode} {p.stderr[-300:]!r}"
    )


class TestConfinementLostAfterAdmissionIsARefusal:
    """`secure` is read once, by `select_sandbox`, at worker start. `run()` never looked at it
    again -- so a profile unloaded (or switched to complain, or made unconfirmable) under a
    long-lived worker silently dropped the aa-exec prefix and kept detonating, on a backend
    the selector had certified as confined. The per-launch re-read existed and nothing acted
    on it (claude-security lens, #177).

    The test is a REGRESSION, not a state: a backend that never had a profile was admitted on
    that basis and keeps running, so this cannot turn an unreadable /sys into a worker that
    refuses every job.
    """

    def _sb(self, tmp_path, monkeypatch, state):
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now",
                            lambda self: state["on"])
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        return mod.NsjailSandbox(nsjail_path=str(nsjail), seccomp_policy=policy)

    def test_a_profile_that_disappears_stops_the_jobs(self, tmp_path, monkeypatch) -> None:
        from blastbox.errors import SandboxUnavailable

        monkeypatch.delenv("BLASTBOX_ALLOW_CONFINEMENT_LOSS", raising=False)
        state = {"on": True}
        sb = self._sb(tmp_path, monkeypatch, state)
        sb.note_admitted(armed=True)
        assert sb._armed_at_admission is True

        state["on"] = False
        with pytest.raises(SandboxUnavailable, match="was enforcing"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"]))

    def test_a_backend_that_never_had_one_keeps_running(self, tmp_path, monkeypatch) -> None:
        """The outage this must not become: 'cannot confirm a profile' is the same False as
        'the profile went away', and only the second is a regression."""
        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        state = {"on": False}
        sb = self._sb(tmp_path, monkeypatch, state)
        sb.note_admitted(armed=False)
        assert sb._armed_at_admission is False
        sb._refuse_if_confinement_regressed()          # must not raise

    def test_the_knowing_override_downgrades_it_to_a_warning(
            self, tmp_path, monkeypatch, caplog) -> None:
        import logging

        monkeypatch.setenv("BLASTBOX_ALLOW_CONFINEMENT_LOSS", "1")
        state = {"on": True}
        sb = self._sb(tmp_path, monkeypatch, state)
        sb.note_admitted(armed=True)
        state["on"] = False
        with caplog.at_level(logging.WARNING, logger="blastbox.worker.sandbox.nsjail"):
            sb._refuse_if_confinement_regressed()      # must not raise
        assert "was enforcing" in caplog.text

    def test_bwrap_answers_the_same_way(self, tmp_path, monkeypatch) -> None:
        """Both backends attach the profile the same way, so both must lose it the same way --
        the asymmetry between them is the whole subject of #160."""
        import blastbox.worker.sandbox.bwrap as bw
        from blastbox.errors import SandboxUnavailable

        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        state = {"on": True}
        monkeypatch.setattr(bw, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(bw.BubblewrapSandbox, "_apparmor_enforcing_now",
                            lambda self: state["on"])
        bwrap = tmp_path / "bwrap"
        bwrap.write_text(_FAKE_NSJAIL)
        bwrap.chmod(0o755)
        sb = bw.BubblewrapSandbox(bwrap_path=str(bwrap))
        sb.note_admitted(armed=True)
        assert sb._armed_at_admission is True
        state["on"] = False
        with pytest.raises(SandboxUnavailable, match="was enforcing"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"]))


def test_the_dispatchers_blanket_leniency_does_not_switch_off_the_regression_guard(
        tmp_path, monkeypatch) -> None:
    """A control that is disabled everywhere the fleet runs is not a control.

    `BLASTBOX_WARN_ON_INSECURE=1` is set automatically by the dispatcher for every runsc
    worker -- for an unrelated reason (gVisor virtualises /proc, so the worker cannot see
    host-level hardening that IS applied) -- and this PR adds it to the warm/snapshot tier
    too. If the confinement-regression refusal honoured it, the refusal would exist only on
    bare metal, which is the deployment tier this repo treats as the fallback.
    """
    import blastbox.worker.sandbox.nsjail as mod
    from blastbox.errors import SandboxUnavailable

    monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
    monkeypatch.delenv("BLASTBOX_ALLOW_CONFINEMENT_LOSS", raising=False)
    state = {"on": True}
    monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
    monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
    monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now", lambda self: state["on"])
    nsjail = tmp_path / "nsjail"
    nsjail.write_text(_FAKE_NSJAIL)
    nsjail.chmod(0o755)
    sb = mod.NsjailSandbox(nsjail_path=str(nsjail))
    sb.note_admitted(armed=True)          # the selector admitted it as confined
    state["on"] = False
    with pytest.raises(SandboxUnavailable, match="was enforcing"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))


def test_the_guard_and_the_argv_share_one_reading_of_the_profile(tmp_path, monkeypatch) -> None:
    """They used to read securityfs independently, twice per launch.

    `run()` asked the guard (read #1), then `_build_argv` asked again (read #2). A profile that
    stopped being confirmable between them passed the guard on the stale True and produced an
    argv with no aa-exec and no --proc_rw: the exact outcome the guard exists to prevent,
    with no refusal and no error (claude-security lens, round 2 of #177).
    """
    import subprocess

    import blastbox.worker.sandbox.nsjail as mod

    reads = {"n": 0}
    state = {"on": True}

    def _counting(_profile: str) -> bool:
        reads["n"] += 1
        return state["on"]

    monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
    monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
    monkeypatch.setattr(mod, "profile_loaded", _counting)
    nsjail = tmp_path / "nsjail"
    nsjail.write_text(_FAKE_NSJAIL)
    nsjail.chmod(0o755)
    policy = tmp_path / "ok.policy"
    policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
    sb = mod.NsjailSandbox(nsjail_path=str(nsjail), seccomp_policy=policy)
    sb.note_admitted(armed=True)
    assert sb._armed_at_admission is True

    captured: dict[str, list[str]] = {}

    class _Popen:
        def __init__(self, argv, *a, **k):
            captured["argv"] = argv
            self.args, self.returncode, self.pid = argv, 0, 1

        def communicate(self, *a, **k):
            return (b"", b"")

    monkeypatch.setattr(subprocess, "Popen", _Popen)

    # THE CASE THAT MATTERS: the profile is still there when the guard looks, and gone by the
    # time the argv is built. With one shared reading the argv carries what the guard
    # approved; with two, the guard passes and the child runs unconfined -- silently.
    reads["n"] = 0
    sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert reads["n"] == 1, (
        f"securityfs was read {reads['n']} times for one launch -- the guard and the argv can "
        f"disagree again"
    )
    argv = captured["argv"]
    assert "aa-exec" in " ".join(argv), (
        "the guard approved a confined launch and the argv dropped the profile anyway"
    )
    assert "--proc_rw" in argv

    # And the refusal still works when the profile is gone BEFORE the guard looks.
    from blastbox.errors import SandboxUnavailable

    state["on"] = False
    monkeypatch.delenv("BLASTBOX_ALLOW_CONFINEMENT_LOSS", raising=False)
    captured.clear()
    with pytest.raises(SandboxUnavailable, match="was enforcing"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert "argv" not in captured, "an unconfined argv reached Popen"


class TestAnAssertedProfileIsMeasuredNotBelieved:
    """`/sys/kernel/security/apparmor/profiles` is root-only and a worker is not root, so on
    the posture this mechanism is written for the kernel can NEVER be consulted and
    `BLASTBOX_APPARMOR_PROFILES` is the sole authority. Making the kernel "authoritative where
    readable" therefore changed nothing for the case that matters: a single environment
    variable still bought `secure = True`, `apparmor_active = True` and `--proc_rw` -- a
    measurably wider /proc for the child -- with no confinement in exchange
    (claude-security lens, round 2 of #177).

    So an asserted profile is now proved from inside the jail: /proc/self/attr/current is the
    kernel naming the profile and its mode, and it cannot be asserted away.
    """

    def _sb(self, tmp_path, monkeypatch, *, child_reports: str, rc: int = 0,
            attaches: bool = True):

        import blastbox.worker.sandbox.apparmor as aa
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.ASSERTED)
        monkeypatch.setattr(mod, "profile_loaded", lambda _p: True)

        def _fake_run(argv, **kw):
            # TWO probes now, and the distinction is the point: the structural one attaches the
            # profile to /usr/bin/true (can it be attached at all?), the reader one prints
            # /proc/self/attr/current. A fake that answers both the same way cannot tell
            # "absent profile" from "profile denies the reader".
            from types import SimpleNamespace
            joined = " ".join(argv)
            if "attr/current" in joined:
                return SimpleNamespace(returncode=rc, stdout=child_reports, stderr="")
            return SimpleNamespace(returncode=0 if attaches else 1, stdout="",
                                   stderr="" if attaches else "profile does not exist")

        monkeypatch.setattr(aa.subprocess, "run", _fake_run)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        policy = tmp_path / "ok.policy"
        policy.write_text("POLICY ok { ERRNO(1) { } } USE ok DEFAULT ALLOW\n")
        return mod.NsjailSandbox(nsjail_path=str(nsjail), seccomp_policy=policy)

    def test_a_child_wearing_the_enforcing_profile_arms_it(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, child_reports="blastbox-sandbox (enforce)\n")
        assert sb.apparmor_active is True
        assert "apparmor_missing" not in sb.insecurity_reasons
        assert "--proc_rw" in sb._build_argv(SandboxRequest(argv=["/usr/bin/true"]))

    def test_complain_mode_is_not_confinement_and_does_not_arm(
            self, tmp_path, monkeypatch) -> None:
        """The case the assertion cannot see and this proof can."""
        sb = self._sb(tmp_path, monkeypatch, child_reports="blastbox-sandbox (complain)\n")
        assert sb.apparmor_active is False
        assert "apparmor_missing" in sb.insecurity_reasons
        assert "--proc_rw" not in sb._build_argv(SandboxRequest(argv=["/usr/bin/true"])), (
            "/proc was widened for a profile that logs and allows"
        )

    def test_a_profile_that_is_not_there_at_all_does_not_arm(
            self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, child_reports="blastbox-nsjail (unconfined)\n")
        assert sb.apparmor_active is False
        assert "apparmor_missing" in sb.insecurity_reasons

    def test_a_profile_that_cannot_be_attached_at_all_is_a_DISPROOF(
            self, tmp_path, monkeypatch, caplog) -> None:
        """The fail-open I found by running the thing.

        On a host where the asserted profile is simply absent, aa-exec says
        `ERROR: profile 'blastbox-sandbox' does not exist` -- and the first version of this
        logic could not tell that from "the profile denies the reader", so it kept the
        assertion and reported `secure` with no confinement whatsoever. The structural probe
        asks the cheap question first, with the one binary every child profile is documented to
        permit: if the profile cannot be attached to /usr/bin/true, the assertion is false.
        """
        import logging

        sb = self._sb(tmp_path, monkeypatch, child_reports="", attaches=False)
        with caplog.at_level(logging.WARNING, logger="blastbox.worker.sandbox.nsjail"):
            assert sb.apparmor_active is False
        assert "apparmor_missing" in sb.insecurity_reasons
        assert "disproved" in caplog.text

    def test_an_unprovable_probe_keeps_the_assertion_and_says_so(
            self, tmp_path, monkeypatch, caplog) -> None:
        """UNPROVABLE is not DISPROVED, and the difference decides whether a correctly
        configured host runs.

        A workload-specific profile may legitimately permit its parser and the documented
        /usr/bin/true probe without permitting a file reader, and the probe then cannot run at
        all. Treating that as a disproof rejected a valid confined backend over a diagnostic
        (codex, #177). The operator keeps their assertion, and the log says it is unverified
        and what to permit to have it checked.
        """
        import logging

        sb = self._sb(tmp_path, monkeypatch, child_reports="", rc=1)
        with caplog.at_level(logging.WARNING, logger="blastbox.worker.sandbox.nsjail"):
            assert sb.apparmor_active is True
        assert "unprovable" in caplog.text

    def test_a_disproved_assertion_still_disarms(self, tmp_path, monkeypatch) -> None:
        """The probe RAN and the kernel disagreed -- that is evidence, and it wins."""
        sb = self._sb(tmp_path, monkeypatch, child_reports="something-else (enforce)\n")
        assert sb.apparmor_active is False

    def test_the_proof_is_re_measured_on_a_ttl_not_once_for_the_worker_life(
            self, tmp_path, monkeypatch) -> None:
        """With securityfs unreadable, `profile_loaded()` returns ASSERTED forever from a static
        environment variable, so a profile switched to complain mid-life would stay "active" for
        the life of the worker while nothing enforced anything (codex, #177)."""
        import blastbox.worker.sandbox.nsjail as mod

        sb = self._sb(tmp_path, monkeypatch, child_reports="blastbox-sandbox (enforce)\n")
        assert sb.apparmor_active is True

        # The profile is switched to complain under the running worker ...
        monkeypatch.setattr(mod.NsjailSandbox, "prove_apparmor_attachment",
                            lambda self: "blastbox-sandbox (complain)")
        assert sb.apparmor_active is True, "the cached proof should still hold inside the TTL"

        # ... and the next launch after the TTL sees it.
        import blastbox.worker.sandbox.apparmor as aa

        clock = {"t": aa.time.monotonic() + aa._PROOF_TTL_S + 1}
        monkeypatch.setattr(aa.time, "monotonic", lambda: clock["t"])
        assert sb.apparmor_active is False

    def test_kill_mode_counts(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch, child_reports="blastbox-sandbox (kill)\n")
        assert sb.apparmor_active is True

    def test_a_kernel_reading_is_not_re_probed(self, tmp_path, monkeypatch) -> None:
        """A profile the kernel itself reported needs no second opinion, and an extra jail
        launch per worker is not free."""

        import blastbox.worker.sandbox.apparmor as aa
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.KERNEL)
        monkeypatch.setattr(mod, "profile_loaded", lambda _p: True)
        calls = {"n": 0}

        def _counting(argv, **kw):
            calls["n"] += 1
            raise AssertionError("the kernel's answer was re-probed")

        monkeypatch.setattr(aa.subprocess, "run", _counting)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        sb = mod.NsjailSandbox(nsjail_path=str(nsjail))
        assert sb.apparmor_active is True
        assert calls["n"] == 0


class TestAnNsjailWithoutProcRwNamesItself:
    """`apparmor_missing` has THREE causes: no helper, no enforcing profile, and an nsjail
    build without `--proc_rw`. Clearing `_aa_exec` for the third made the constructor log
    `reason=aa_exec_not_found` -- the helper was right there -- and made the selector's remedy
    tell the operator to load a profile that was already loaded and enforcing, which is the
    defect that remedy was added to fix (claude-code-review lens, round 2 of #177).
    """

    def _sb(self, tmp_path, monkeypatch):
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: False)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_enforcing_now", lambda self: True)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        return mod.NsjailSandbox(nsjail_path=str(nsjail))

    def test_the_log_does_not_blame_the_helper(self, tmp_path, monkeypatch, caplog) -> None:
        import logging

        with caplog.at_level(logging.INFO, logger="blastbox.worker.sandbox.nsjail"):
            self._sb(tmp_path, monkeypatch)
        assert "aa_exec_not_found" not in caplog.text
        assert "installed_nsjail_has_no_--proc_rw" in caplog.text

    def test_the_backend_can_name_the_cause(self, tmp_path, monkeypatch) -> None:
        sb = self._sb(tmp_path, monkeypatch)
        assert "apparmor_missing" in sb.insecurity_reasons
        assert sb.apparmor_blocked_reason is not None
        assert "--proc_rw" in sb.apparmor_blocked_reason

    def test_the_selector_passes_that_cause_through_instead_of_the_stock_remedy(
            self, tmp_path, monkeypatch) -> None:
        import blastbox.worker.sandbox.detect as detect_mod
        from blastbox.errors import SandboxUnavailable

        sb = self._sb(tmp_path, monkeypatch)
        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        monkeypatch.delenv("BLASTBOX_SANDBOX", raising=False)
        monkeypatch.setattr(detect_mod, "_in_container", lambda: False)
        monkeypatch.setattr(detect_mod, "_smoketest", lambda _sb: (True, None))

        def _only_nsjail(name, **kw):
            if name == "nsjail":
                return sb
            raise SandboxUnavailable(f"{name} not available in this test")

        monkeypatch.setattr(detect_mod, "_make_backend", _only_nsjail)
        with pytest.raises(SandboxUnavailable) as ei:
            detect_mod.select_sandbox(_status_path=tmp_path / "status")
        msg = str(ei.value)
        assert "--proc_rw" in msg, msg
        assert "in enforce or kill mode" not in msg, (
            "the stock remedy told the operator to load a profile that is already enforcing"
        )


def test_both_backends_find_aa_exec_through_one_patchable_name(monkeypatch) -> None:
    """bwrap called `shutil.which("aa-exec")` inline while nsjail had a module-level finder,
    so `monkeypatch.setattr(bwrap, "_find_aa_exec", ...)` created an unused attribute and the
    bwrap half of every parity test silently read the HOST -- host-dependence of exactly the
    kind those tests exist to remove (claude-code-review lens, round 2 of #177)."""
    import blastbox.worker.sandbox.bwrap as bw
    import blastbox.worker.sandbox.nsjail as nj

    for mod in (nj, bw):
        assert hasattr(mod, "_find_aa_exec"), f"{mod.__name__} has no patchable finder"
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: None)

    assert nj.NsjailSandbox(nsjail_path="/bin/sh")._aa_exec is None
    assert bw.BubblewrapSandbox(bwrap_path="/bin/sh")._aa_exec is None


@pytest.mark.parametrize("backend", ["nsjail", "bwrap"])
def test_construction_never_calls_the_property_that_launches_a_jail(
        backend: str, monkeypatch, tmp_path) -> None:
    """`apparmor_active` is not a plain accessor: on the asserted path it builds an argv and
    launches a jail to measure the profile. Reading it from __init__ therefore needs state the
    constructor has not built yet, and it crashed construction outright on any host with
    BLASTBOX_APPARMOR_PROFILES set -- `AttributeError: 'BubblewrapSandbox' object has no
    attribute '_cgroup_pids_supported'` (found by running it, not by reading it).

    The measurement belongs on the first real read, which is the selector's security check and
    still happens before any job.
    """
    import blastbox.worker.sandbox.apparmor as aa
    import blastbox.worker.sandbox.bwrap as bw
    import blastbox.worker.sandbox.nsjail as nj

    mod = nj if backend == "nsjail" else bw
    monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
    monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.ASSERTED)
    monkeypatch.setattr(mod, "profile_loaded", lambda _p: True)
    if backend == "nsjail":
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)

    # Cheap capability probes (`--help`) are fine and expected from a constructor; what is
    # forbidden is launching a JAIL to measure the profile, which needs state that does not
    # exist yet.
    launched: list[list[str]] = []
    real_run = mod.subprocess.run

    def _watch(argv, **kw):
        launched.append(list(argv))
        if any("aa-exec" in a for a in argv):
            raise AssertionError(f"a profiled jail was launched from the constructor: {argv}")
        return real_run(argv, **kw)

    monkeypatch.setattr(mod.subprocess, "run", _watch)
    binary = tmp_path / backend
    binary.write_text(_FAKE_NSJAIL)
    binary.chmod(0o755)
    if backend == "nsjail":
        mod.NsjailSandbox(nsjail_path=str(binary))
    else:
        mod.BubblewrapSandbox(bwrap_path=str(binary))
    assert not any("aa-exec" in a for argv in launched for a in argv), launched


class TestTheProofCacheAndTheNameMatch:
    """Two defects in the proof's bookkeeping, neither of which any behaviour test could see."""

    def _sb(self, tmp_path, monkeypatch, reports: str, *, probe_seconds: float = 0.0):
        import blastbox.worker.sandbox.apparmor as aa
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.ASSERTED)
        monkeypatch.setattr(mod, "profile_loaded", lambda _p: True)
        monkeypatch.setattr(mod.NsjailSandbox, "_apparmor_attaches_at_all", lambda self: True)
        calls = {"n": 0}

        def _prove(_self):
            calls["n"] += 1
            if probe_seconds:
                import time as _t
                _t.sleep(probe_seconds)
            return reports

        monkeypatch.setattr(mod.NsjailSandbox, "prove_apparmor_attachment", _prove)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        return mod.NsjailSandbox(nsjail_path=str(nsjail)), calls

    def test_a_probe_slower_than_the_ttl_still_caches(self, tmp_path, monkeypatch) -> None:
        """The timestamp was taken at ENTRY and written after the launch, so the entry was
        `probe_duration` seconds old on arrival. The launch allows 60s and the TTL is 30, so a
        slow probe produced a cache that was expired when written: every read re-launched a
        jail and waited again, and a loaded host became a worker that looks hung
        (claude-code-review lens, round 3 of #177).
        """
        import blastbox.worker.sandbox.apparmor as aa
        import blastbox.worker.sandbox.nsjail as mod          # noqa: F401 - patched by _sb

        monkeypatch.setattr(aa, "_PROOF_TTL_S", 0.5)
        sb, calls = self._sb(tmp_path, monkeypatch, "blastbox-sandbox (enforce)",
                             probe_seconds=0.7)
        before = calls["n"]
        for _ in range(4):
            assert sb.apparmor_active is True
        assert calls["n"] == before + 1, (
            f"{calls['n'] - before} jail launches for four reads -- the entry was already "
            f"expired when it was written"
        )

    def test_a_longer_profile_name_is_not_proof_of_this_one(self, tmp_path, monkeypatch) -> None:
        """`startswith` accepted a child wearing `blastbox-sandbox-permissive` as proof of
        `blastbox-sandbox` -- and this is the single gate behind `secure` and `--proc_rw` on the
        asserted path (claude-code-review lens, round 3 of #177)."""
        sb, _ = self._sb(tmp_path, monkeypatch, "blastbox-sandbox-permissive (enforce)")
        assert sb.apparmor_active is False

    def test_the_exact_name_in_enforce_or_kill_is(self, tmp_path, monkeypatch) -> None:
        for reports in ("blastbox-sandbox (enforce)", "blastbox-sandbox (kill)"):
            sb, _ = self._sb(tmp_path, monkeypatch, reports)
            assert sb.apparmor_active is True, reports

    def test_the_reader_is_the_usr_path_the_kernel_resolves(self) -> None:
        """AppArmor mediates the resolved path. On a merged-/usr host (/bin -> usr/bin) that is
        /usr/bin/cat, so a remedy naming /bin/cat sends the operator to write a rule that never
        matches."""
        import blastbox.worker.sandbox.apparmor as aa

        if aa._PROOF_READER is None:
            pytest.skip("no file reader on this host")
        if Path("/bin").is_symlink():
            assert aa._PROOF_READER.startswith("/usr/"), aa._PROOF_READER


def test_a_single_transient_probe_failure_is_retried_before_it_is_believed(
        tmp_path, monkeypatch) -> None:
    """A transient probe failure with no earlier verdict is the one moment the proof has
    nothing to fall back on, and trusting the assertion there is a fail-open window, however
    narrow (nemotron, round 5 of #177).

    One retry removes the single-fork-failure case. Two in a row is reported out loud and the
    operator's assertion stands -- refusing every job because one fork failed is the worse
    error, and the next TTL re-measures.
    """
    import subprocess

    import blastbox.worker.sandbox.apparmor as aa
    import blastbox.worker.sandbox.nsjail as mod

    monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
    monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
    monkeypatch.setattr(aa, "profile_evidence", lambda _p: aa.ASSERTED)
    monkeypatch.setattr(mod, "profile_loaded", lambda _p: True)

    # The READER probe never reports here (the profile denies it), so the verdict rests on the
    # structural attach probe -- and that is the one made transiently flaky, because it is the
    # only path where a transient failure has nothing to fall back on.
    calls = {"reader": 0, "attach": 0}

    def _flaky(argv, **kw):
        from types import SimpleNamespace
        joined = " ".join(argv)
        if "/proc/self/attr/current" in joined:
            calls["reader"] += 1
            return SimpleNamespace(returncode=1, stdout="", stderr="denied")
        calls["attach"] += 1
        if calls["attach"] == 1:
            raise OSError(12, "Cannot allocate memory")     # transient, once
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(aa.subprocess, "run", _flaky)
    nsjail = tmp_path / "nsjail"
    nsjail.write_text(_FAKE_NSJAIL)
    nsjail.chmod(0o755)
    sb = mod.NsjailSandbox(nsjail_path=str(nsjail))

    assert sb.apparmor_active is True
    assert calls["attach"] == 2, (
        f"the attach probe ran {calls['attach']}x -- a single transient failure was believed "
        f"without a retry"
    )
    assert sb._proof is not None and sb._proof[0] is True, (
        "the recovered probe produced no verdict to cache"
    )
    assert subprocess is not None


class TestAProbeThatCannotRunFailsClosed:
    """The regression my own round-4 change introduced, and the fix.

    Before the mixin refactor, an exception in the attach probe answered False: the backend
    reported `apparmor_missing` and the selector rejected it. The refactor turned that into
    "transient", and transient fell back to the operator's assertion -- so a host whose proof
    jail could not launch at all reported `secure = True` and attached `--proc_rw` (a writable
    /proc/self/mem for the child) on the strength of an environment variable that had never been
    measured. Reproduced: `reasons [] secure True`, with SIX 60s probe launches for one read and
    nothing cached (claude-code-review lens, round 5 of #177).
    """

    def _sb(self, tmp_path, monkeypatch, fail):
        import blastbox.worker.sandbox.apparmor as aa
        import blastbox.worker.sandbox.nsjail as mod

        monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILES", "blastbox-sandbox")
        monkeypatch.setattr(aa, "_PROFILES", "/nonexistent")     # securityfs unreadable
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec")
        monkeypatch.setattr(mod, "_supports_proc_rw", lambda _p: True)
        calls = {"n": 0}

        def _run(argv, **kw):
            calls["n"] += 1
            return fail(argv, calls["n"])

        monkeypatch.setattr(aa.subprocess, "run", _run)
        nsjail = tmp_path / "nsjail"
        nsjail.write_text(_FAKE_NSJAIL)
        nsjail.chmod(0o755)
        return mod.NsjailSandbox(nsjail_path=str(nsjail)), calls

    def test_an_unlaunchable_probe_reports_apparmor_missing(self, tmp_path, monkeypatch) -> None:
        import subprocess

        def _always_transient(argv, n):
            raise subprocess.TimeoutExpired(argv, 60)

        sb, _ = self._sb(tmp_path, monkeypatch, _always_transient)
        assert sb.apparmor_active is False
        assert "apparmor_missing" in sb.insecurity_reasons
        assert sb.secure is False
        assert "--proc_rw" not in sb._build_argv(SandboxRequest(argv=["/usr/bin/true"])), (
            "/proc was widened for confinement that was never measured"
        )

    def test_the_probe_storm_is_bounded(self, tmp_path, monkeypatch) -> None:
        """Answering without caching turned a bounded wrong answer into an unbounded slow one:
        each read paid up to 60s per launch, and the next read repeated it."""
        import subprocess

        def _always_transient(argv, n):
            raise subprocess.TimeoutExpired(argv, 60)

        sb, calls = self._sb(tmp_path, monkeypatch, _always_transient)
        sb.apparmor_active
        after_first = calls["n"]
        for _ in range(5):
            sb.apparmor_active
        assert calls["n"] == after_first, (
            f"{calls['n'] - after_first} extra probe launches for five reads inside the TTL"
        )

    def test_it_re_arms_itself_when_probes_work_again(self, tmp_path, monkeypatch) -> None:
        """The short TTL is the point: an outage must not leave the backend disarmed once the
        host recovers."""
        import subprocess
        from types import SimpleNamespace

        import blastbox.worker.sandbox.apparmor as aa

        state = {"broken": True}

        def _flaky(argv, n):
            if state["broken"]:
                raise subprocess.TimeoutExpired(argv, 60)
            ok = "blastbox-sandbox (enforce)\n" if "attr/current" in " ".join(argv) else ""
            return SimpleNamespace(returncode=0, stdout=ok, stderr="")

        sb, _ = self._sb(tmp_path, monkeypatch, _flaky)
        assert sb.apparmor_active is False

        state["broken"] = False
        clock = {"t": aa.time.monotonic() + aa._TRANSIENT_TTL_S + 0.1}
        monkeypatch.setattr(aa.time, "monotonic", lambda: clock["t"])
        assert sb.apparmor_active is True
        assert "apparmor_missing" not in sb.insecurity_reasons

    def test_a_permanently_broken_probe_settles_instead_of_re_probing_every_job(
            self, tmp_path, monkeypatch) -> None:
        """Fail-closed must not mean fail-slow-forever.

        A probe can be broken PERMANENTLY, not transiently -- memfd unsupported, a wrapper
        binary that always times out, a reader the profile always denies -- and the short TTL
        then re-measures for every job. Measured before this: 3 launches per job, forever, each
        waiting out the probe timeout. After `_TRANSIENT_SETTLED_AFTER` consecutive failures the
        answer is held for the full TTL: still apparmor_missing, still re-measured, but once per
        window rather than once per detonation (round 6 of #177).
        """
        import subprocess

        import blastbox.worker.sandbox.apparmor as aa

        def _always_transient(argv, n):
            raise subprocess.TimeoutExpired(argv, 1)

        sb, calls = self._sb(tmp_path, monkeypatch, _always_transient)

        # Each read is a fresh window until the failures settle.
        clock = {"t": aa.time.monotonic()}
        monkeypatch.setattr(aa.time, "monotonic", lambda: clock["t"])
        for _ in range(aa._TRANSIENT_SETTLED_AFTER):
            assert sb.apparmor_active is False
            clock["t"] += aa._TRANSIENT_TTL_S + 0.1

        assert sb._proof is not None
        assert sb._proof[2] == aa._PROOF_TTL_S, "a broken probe is still on the short TTL"

        before = calls["n"]
        clock["t"] += aa._TRANSIENT_TTL_S + 0.1        # past the SHORT ttl, inside the long one
        assert sb.apparmor_active is False
        assert calls["n"] == before, "it re-probed inside the settled window"

    def test_a_settled_probe_still_recovers(self, tmp_path, monkeypatch) -> None:
        """Settling bounds the cost; it must not make the state permanent."""
        import subprocess
        from types import SimpleNamespace

        import blastbox.worker.sandbox.apparmor as aa

        state = {"broken": True}

        def _flaky(argv, n):
            if state["broken"]:
                raise subprocess.TimeoutExpired(argv, 1)
            ok = "blastbox-sandbox (enforce)\n" if "attr/current" in " ".join(argv) else ""
            return SimpleNamespace(returncode=0, stdout=ok, stderr="")

        sb, _ = self._sb(tmp_path, monkeypatch, _flaky)
        clock = {"t": aa.time.monotonic()}
        monkeypatch.setattr(aa.time, "monotonic", lambda: clock["t"])
        for _ in range(aa._TRANSIENT_SETTLED_AFTER):
            sb.apparmor_active
            clock["t"] += aa._TRANSIENT_TTL_S + 0.1

        state["broken"] = False
        clock["t"] += aa._PROOF_TTL_S + 0.1
        assert sb.apparmor_active is True
        assert sb._consecutive_transients == 0, "the failure count survived a success"

    def test_the_probe_timeout_is_bounded(self) -> None:
        """A probe is `aa-exec -p <profile> -- /usr/bin/true` in a jail. The old 60s meant a
        broken probe cost a minute per launch on a path that runs before every job."""
        import blastbox.worker.sandbox.apparmor as aa

        assert aa._PROBE_TIMEOUT_S <= 30.0, aa._PROBE_TIMEOUT_S

    def test_the_short_ttl_is_much_shorter_than_a_verdict(self) -> None:
        import blastbox.worker.sandbox.apparmor as aa

        assert aa._TRANSIENT_TTL_S < aa._PROOF_TTL_S / 5, (
            "an unmeasurable probe is cached nearly as long as a real verdict"
        )
