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
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: None, raising=False)
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
        monkeypatch.setattr(mod, "_find_aa_exec", lambda: "/usr/sbin/aa-exec", raising=False)
        monkeypatch.setattr(mod, "profile_loaded", lambda _n: True, raising=False)
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
    monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILE", "unconfined")
    monkeypatch.setenv("BLASTBOX_APPARMOR_PROFILES", "unconfined")

    import blastbox.worker.sandbox.nsjail as mod

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

        monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
        state = {"on": True}
        sb = self._sb(tmp_path, monkeypatch, state)
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
        assert sb._armed_at_admission is False
        sb._refuse_if_confinement_regressed()          # must not raise

    def test_the_knowing_override_downgrades_it_to_a_warning(
            self, tmp_path, monkeypatch, caplog) -> None:
        import logging

        monkeypatch.setenv("BLASTBOX_WARN_ON_INSECURE", "1")
        state = {"on": True}
        sb = self._sb(tmp_path, monkeypatch, state)
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
        monkeypatch.setattr(bw, "_find_aa_exec", lambda: "/usr/sbin/aa-exec", raising=False)
        monkeypatch.setattr(bw.BubblewrapSandbox, "_apparmor_enforcing_now",
                            lambda self: state["on"])
        bwrap = tmp_path / "bwrap"
        bwrap.write_text(_FAKE_NSJAIL)
        bwrap.chmod(0o755)
        sb = bw.BubblewrapSandbox(bwrap_path=str(bwrap))
        assert sb._armed_at_admission is True
        state["on"] = False
        with pytest.raises(SandboxUnavailable, match="was enforcing"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"]))
