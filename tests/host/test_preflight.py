"""`blastbox preflight` reports host readiness per tier without touching the host.

Every check runs against a FakeHost: no test here reads the real /proc, /sys, /dev or
spawns a real binary, so the suite means the same thing on a laptop and on toolz2.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Sequence

import pytest

from blastbox.host import preflight as pf
from blastbox.host.preflight import Status

_RUNTIMES_JSON = '{"io.containerd.runc.v2":{"path":"runc"},"runc":{"path":"runc"},' \
    '"runsc":{"path":"/usr/bin/runsc"}}'


class FakeHost(pf.HostView):
    """A host made of dicts. Anything not declared is absent."""

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        files: dict[str, str] | None = None,
        paths: set[str] | None = None,
        rw: set[str] | None = None,
        executables: dict[str, str] | None = None,
        commands: dict[tuple[str, ...], tuple[int, str, str]] | None = None,
    ) -> None:
        self.env = dict(env or {})
        self.files = dict(files or {})
        self.paths = set(paths or ()) | set(self.files)
        self.rw = set(rw or ())
        self.executables = dict(executables or {})   # name -> resolved path
        self.commands = dict(commands or {})
        self.ran: list[tuple[str, ...]] = []

    def read(self, path: str) -> str | None:
        return self.files.get(path)

    def exists(self, path: str) -> bool:
        return path in self.paths

    def rw_access(self, path: str) -> bool:
        return path in self.rw

    def which(self, name: str) -> str | None:
        if name.startswith("/"):
            return name if name in self.executables.values() else None
        return self.executables.get(name)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        key = tuple(argv)
        self.ran.append(key)
        if key not in self.commands:
            return None
        rc, out, err = self.commands[key]
        return subprocess.CompletedProcess(list(argv), rc, out, err)


def _healthy(**over) -> FakeHost:
    """A host prepared exactly as HOST-PREP.md says."""
    base = dict(
        env={"BLASTBOX_FC_KERNEL": "/var/lib/blastbox/fc/vmlinux",
             "BLASTBOX_FC_ROOTFS": "/var/lib/blastbox/fc/rootfs.ext4"},
        files={
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n",
            "/proc/sys/user/max_user_namespaces": "63367\n",
            "/sys/module/apparmor/parameters/enabled": "Y\n",
            "/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu sse2 avx2 avx512f\n",
        },
        paths={"/dev/kvm", "/var/lib/blastbox/jobs", "/var/lib/blastbox/fc/vmlinux",
               "/var/lib/blastbox/fc/rootfs.ext4"},
        rw={"/dev/kvm"},
        executables={
            "docker": "/usr/bin/docker",
            "runsc": "/usr/bin/runsc",
            "firecracker": "/usr/local/bin/firecracker",
            "timedatectl": "/usr/bin/timedatectl",
        },
        commands={
            ("/usr/bin/docker", "version", "--format", "{{.Server.Version}}"):
                (0, "29.1.3\n", ""),
            ("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"):
                (0, _RUNTIMES_JSON + "\n", ""),
            ("/usr/bin/runsc", "--version"): (0, "runsc version release-20251110.0\n", ""),
            ("/usr/local/bin/firecracker", "--version"): (0, "Firecracker v1.16.0\n", ""),
            ("/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"):
                (0, "yes\n", ""),
        },
    )
    for k, v in over.items():
        if k in ("env", "files", "commands"):          # merged; everything else replaces
            merged = dict(base[k])
            merged.update(v)
            base[k] = merged
        else:
            base[k] = v
    return FakeHost(**base)


def _by_name(checks: list[pf.Check]) -> dict[str, pf.Check]:
    return {c.name: c for c in checks}


ALL = ["docker", "gvisor", "firecracker"]


# --- tier resolution --------------------------------------------------------------------

def test_tiers_default_to_every_local_tier_when_nothing_is_configured():
    assert pf.resolve_tiers([], {}) == ["docker", "gvisor", "firecracker"]


def test_tiers_follow_the_pool_runtime_plus_the_cold_dispatcher():
    assert pf.resolve_tiers([], {"BLASTBOX_POOL_RUNTIME": "firecracker"}) == [
        "docker", "firecracker"]
    assert pf.resolve_tiers([], {"BLASTBOX_POOL_RUNTIME": "aws-ec2"}) == ["docker", "remote"]
    assert pf.resolve_tiers([], {"BLASTBOX_POOL_RUNTIME": "static"}) == ["docker", "remote"]


def test_explicit_tiers_win_and_are_deduplicated_in_canonical_order():
    assert pf.resolve_tiers(["firecracker", "gvisor", "firecracker"], {}) == [
        "gvisor", "firecracker"]
    assert pf.resolve_tiers(["all"], {}) == ["docker", "gvisor", "firecracker", "remote"]


def test_unknown_tier_is_rejected():
    with pytest.raises(ValueError, match="unknown tier"):
        pf.resolve_tiers(["kvm"], {})


# --- a healthy host ---------------------------------------------------------------------

def test_a_prepared_host_has_no_failures_or_warnings():
    checks = pf.run_preflight(_healthy(), ALL)
    bad = [c for c in checks if c.status is not Status.PASS]
    assert bad == []
    names = {c.name for c in checks}
    assert {"kvm", "firecracker", "runsc", "docker", "docker-runsc-runtime", "userns",
            "apparmor", "bwrap-userns-restrict", "clock", "cpu-flags", "scratch"} <= names


def test_only_the_selected_tiers_are_checked():
    names = {c.name for c in pf.run_preflight(_healthy(), ["remote"])}
    assert "kvm" not in names and "runsc" not in names and "docker" not in names
    assert "clock" in names


# --- firecracker ------------------------------------------------------------------------

def test_missing_kvm_fails_the_firecracker_tier():
    host = _healthy(paths={"/var/lib/blastbox/jobs"}, rw=set())
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["kvm"]
    assert c.status is Status.FAIL and "/dev/kvm" in c.detail


def test_kvm_without_rw_access_fails_and_names_the_kvm_group():
    host = _healthy(rw=set())
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["kvm"]
    assert c.status is Status.FAIL and "kvm group" in c.detail


def test_firecracker_below_the_minimum_version_fails():
    host = _healthy(commands={("/usr/local/bin/firecracker", "--version"):
                              (0, "Firecracker v1.10.0\n", "")})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["firecracker"]
    assert c.status is Status.FAIL and "1.10.0" in c.detail


def test_firecracker_binary_comes_from_the_env_knob_first():
    host = _healthy(env={"BLASTBOX_FC_BIN": "/opt/fc/firecracker"},
                    executables={"fcx": "/opt/fc/firecracker"},
                    commands={("/opt/fc/firecracker", "--version"): (0, "v1.15.1\n", "")})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["firecracker"]
    assert c.status is Status.PASS and "/opt/fc/firecracker" in c.detail


def test_missing_firecracker_binary_fails():
    host = _healthy(executables={"docker": "/usr/bin/docker"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["firecracker"]
    assert c.status is Status.FAIL


def test_fc_guest_artifacts_set_but_missing_fail():
    host = _healthy(env={"BLASTBOX_FC_KERNEL": "/srv/fc/vmlinux",
                         "BLASTBOX_FC_ROOTFS": "/srv/fc/rootfs.ext4"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"]
    assert c.status is Status.FAIL and "/srv/fc/vmlinux" in c.detail


def test_fc_guest_artifacts_unset_here_warn_rather_than_pass():
    host = _healthy(env={"BLASTBOX_FC_KERNEL": "", "BLASTBOX_FC_ROOTFS": ""})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"]
    assert c.status is Status.WARN


def test_disabled_snapshot_refresh_warns_about_aged_checkpoints():
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MAX_AGE_S": "0"})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["snapshot-age"]
    assert c.status is Status.WARN and "clock" in c.detail


# --- gVisor / docker --------------------------------------------------------------------

def test_runsc_not_registered_with_docker_fails_and_says_reload_not_restart():
    host = _healthy(commands={("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"):
                              (0, '{"runc":{"path":"runc"}}\n', "")})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["docker-runsc-runtime"]
    assert c.status is Status.FAIL
    assert "systemctl reload docker" in c.detail


def test_runsc_missing_is_only_a_warning_when_runc_is_explicitly_consented():
    host = _healthy(env={"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1"},
                    commands={("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"):
                              (0, '{"runc":{}}', "")})
    c = _by_name(pf.run_preflight(host, ["docker"]))["docker-runsc-runtime"]
    assert c.status is Status.WARN


def test_missing_runsc_binary_fails_the_gvisor_tier():
    host = _healthy(executables={"docker": "/usr/bin/docker"})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["runsc"]
    assert c.status is Status.FAIL


def test_unreachable_docker_fails():
    host = _healthy(commands={("/usr/bin/docker", "version", "--format", "{{.Server.Version}}"):
                              (1, "", "Cannot connect to the Docker daemon\n")})
    c = _by_name(pf.run_preflight(host, ["docker"]))["docker"]
    assert c.status is Status.FAIL and "Cannot connect" in c.detail


def test_no_docker_cli_fails():
    host = _healthy(executables={})
    c = _by_name(pf.run_preflight(host, ["docker"]))["docker"]
    assert c.status is Status.FAIL and "not found" in c.detail


# --- AppArmor / userns ------------------------------------------------------------------

def test_stock_bwrap_profile_present_warns_with_a_doc_pointer():
    host = _healthy(files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ..."})
    c = _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"]
    assert c.status is Status.WARN
    assert c.doc.startswith("docs/HOST-PREP.md#")


def test_stock_bwrap_profile_disabled_and_unloaded_passes():
    host = _healthy(
        files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ...",
               "/sys/kernel/security/apparmor/profiles": "docker-default (enforce)\n"},
        paths={"/etc/apparmor.d/disable/bwrap-userns-restrict", "/dev/kvm",
               "/var/lib/blastbox/jobs"},
    )
    c = _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"]
    assert c.status is Status.PASS and "disabled" in c.detail


def test_stock_bwrap_profile_disabled_but_still_loaded_warns_to_unload():
    host = _healthy(
        files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ...",
               "/sys/kernel/security/apparmor/profiles":
                   "bwrap (unconfined)\nunpriv_bwrap (enforce)\n"},
        paths={"/etc/apparmor.d/disable/bwrap-userns-restrict", "/dev/kvm",
               "/var/lib/blastbox/jobs"},
    )
    c = _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"]
    assert c.status is Status.WARN and "apparmor_parser -R" in c.detail


def test_apparmor_disabled_warns():
    host = _healthy(files={"/sys/module/apparmor/parameters/enabled": "N\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["apparmor"]
    assert c.status is Status.WARN


def test_restricted_userns_is_fine_for_rootful_runsc_and_firecracker():
    c = _by_name(pf.run_preflight(_healthy(), ALL))["userns"]
    assert c.status is Status.PASS and "restrict" in c.detail


def test_restricted_userns_warns_when_an_inner_namespace_sandbox_is_configured():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.WARN and "deploy/apparmor" in c.detail


def test_restricted_userns_passes_when_the_scoped_profiles_are_loaded():
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.PASS


def test_user_namespaces_switched_off_fails_when_one_is_needed():
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap"},
                    files={"/proc/sys/user/max_user_namespaces": "0\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.FAIL


# --- clock / cpu / scratch --------------------------------------------------------------

def test_unsynchronised_clock_warns():
    host = _healthy(commands={("/usr/bin/timedatectl", "show", "-p", "NTPSynchronized",
                               "--value"): (0, "no\n", "")})
    c = _by_name(pf.run_preflight(host, ["remote"]))["clock"]
    assert c.status is Status.WARN


def test_clock_falls_back_to_chrony_when_timedatectl_is_absent():
    host = _healthy(executables={"chronyc": "/usr/bin/chronyc"},
                    commands={("/usr/bin/chronyc", "-n", "tracking"):
                              (0, "Reference ID    : 0A000001\nLeap status     : Normal\n", "")})
    c = _by_name(pf.run_preflight(host, ["remote"]))["clock"]
    assert c.status is Status.PASS and "chrony" in c.detail


def test_clock_unknown_warns_rather_than_passing():
    host = _healthy(executables={})
    c = _by_name(pf.run_preflight(host, ["remote"]))["clock"]
    assert c.status is Status.WARN


def test_avx512_vbmi_warns_about_the_jvm_base64_intrinsic():
    host = _healthy(files={"/proc/cpuinfo": "flags\t: fpu avx512f avx512vbmi avx512_vbmi2\n"})
    c = _by_name(pf.run_preflight(host, ["remote"]))["cpu-flags"]
    assert c.status is Status.WARN
    assert "-XX:-UseBASE64Intrinsics" in c.detail


def test_avx512_vbmi2_alone_is_not_mistaken_for_vbmi():
    host = _healthy(files={"/proc/cpuinfo": "flags\t: fpu avx512_vbmi2\n"})
    c = _by_name(pf.run_preflight(host, ["remote"]))["cpu-flags"]
    assert c.status is Status.PASS


def test_scratch_under_tmp_warns():
    host = _healthy(env={"BLASTBOX_JOB_ROOT": "/tmp/bbjobs"}, paths={"/tmp/bbjobs"})
    c = _by_name(pf.run_preflight(host, ["remote"]))["scratch"]
    assert c.status is Status.WARN and "/tmp/bbjobs" in c.detail


def test_snapshot_mem_dir_under_tmp_warns():
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MEM_DIR": "/tmp/snap"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["scratch"]
    assert c.status is Status.WARN and "/tmp/snap" in c.detail


def test_dev_shm_tmpfs_is_not_flagged_as_tmp():
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MEM_DIR": "/dev/shm/bb"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["scratch"]
    assert c.status is Status.PASS


# --- read-only guarantee + output -------------------------------------------------------

def test_every_command_preflight_runs_is_on_the_read_only_allowlist():
    host = _healthy(executables={**_healthy().executables, "chronyc": "/usr/bin/chronyc"})
    pf.run_preflight(host, ["docker", "gvisor", "firecracker", "remote"])
    assert host.ran
    for argv in host.ran:
        assert pf.is_read_only(argv), argv


@pytest.mark.parametrize("argv", [
    ["docker", "rm", "-f", "x"],
    ["docker", "info"],                      # not the exact allowlisted form
    ["systemctl", "reload", "docker"],
    ["apparmor_parser", "-R", "/etc/apparmor.d/bwrap-userns-restrict"],
    ["timedatectl", "set-ntp", "true"],
])
def test_mutating_commands_are_refused_by_the_real_runner(argv):
    assert not pf.is_read_only(argv)
    with pytest.raises(pf.NotReadOnly):
        pf.RealHost().run(argv)


def test_exit_code_is_nonzero_only_on_failure_unless_strict():
    ok = [pf.Check("a", Status.PASS, "")]
    warn = ok + [pf.Check("b", Status.WARN, "")]
    fail = warn + [pf.Check("c", Status.FAIL, "")]
    assert pf.exit_code(ok) == 0
    assert pf.exit_code(warn) == 0
    assert pf.exit_code(warn, strict=True) == 1
    assert pf.exit_code(fail) == 1


def test_text_report_has_one_line_per_check_and_a_summary():
    checks = pf.run_preflight(_healthy(files={"/sys/module/apparmor/parameters/enabled": "N"}),
                              ["docker"])
    text = pf.render_text(checks, ["docker"])
    assert "tiers: docker" in text
    assert any(line.startswith("WARN") and "apparmor" in line for line in text.splitlines())
    assert "docs/HOST-PREP.md#" in text
    assert text.rstrip().splitlines()[-1].startswith("summary:")


def test_json_report_round_trips():
    checks = pf.run_preflight(_healthy(), ["docker"])
    doc = json.loads(pf.render_json(checks, ["docker"]))
    assert doc["tiers"] == ["docker"]
    assert doc["ok"] is True
    assert {c["status"] for c in doc["checks"]} == {"PASS"}


def test_cli_wires_the_preflight_subcommand(capsys, monkeypatch):
    from blastbox.host import cli

    monkeypatch.setattr(pf, "RealHost", lambda: _healthy())
    rc = cli.main(["preflight", "--tier", "docker"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "summary:" in out


def test_real_host_reads_procfs_in_small_chunks(tmp_path, monkeypatch):
    """/proc/sys handlers fail a single large read() with ENOMEM (measured: a 4 MiB read of
    /proc/sys/user/max_user_namespaces), which made every userns sysctl look absent."""
    import builtins
    import errno
    import io

    target = tmp_path / "max_user_namespaces"
    target.write_text("63367\n")
    real_open = builtins.open

    class ProcLike(io.StringIO):
        def read(self, size=-1):
            if size is None or size < 0 or size > 64 * 1024:
                raise OSError(errno.ENOMEM, "Cannot allocate memory")
            return super().read(size)

    def fake_open(path, *a, **kw):
        if str(path) == str(target):
            return ProcLike(real_open(path, *a, **kw).read())
        return real_open(path, *a, **kw)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert pf.RealHost().read(str(target)) == "63367\n"


def test_real_host_read_is_bounded(tmp_path):
    big = tmp_path / "big"
    big.write_text("x" * (pf._READ_CAP + 10))
    assert len(pf.RealHost().read(str(big)) or "") == pf._READ_CAP


def _github_slug(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def test_every_doc_pointer_names_a_real_heading_in_host_prep():
    from pathlib import Path

    doc = Path(__file__).resolve().parents[2] / "docs" / "HOST-PREP.md"
    slugs = {_github_slug(line.lstrip("#")) for line in doc.read_text().splitlines()
             if line.startswith("#")}
    src = Path(pf.__file__).read_text()
    anchors = set(re.findall(r'\{DOC\}#([a-z0-9\-]+)', src))
    assert anchors, "no doc pointers found"
    assert anchors <= slugs, f"dangling anchors: {sorted(anchors - slugs)}"
