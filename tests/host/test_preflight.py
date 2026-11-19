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
        links: dict[str, str] | None = None,
        special: set[str] | None = None,
        kernels: dict[str, tuple[int, int]] | None = None,
        euid: int = 1000,
        mounts: str = "",
    ) -> None:
        self.env = dict(env or {})
        self.files = dict(files or {})
        self.paths = set(paths or ()) | set(self.files)
        self.rw = set(rw or ())
        self.executables = dict(executables or {})   # name -> resolved path
        self.commands = dict(commands or {})
        self.ran: list[tuple[str, ...]] = []
        self.links = dict(links or {})
        self.special = set(special or ())      # exists, but not a regular file (dir/dangling)
        self.kernels = dict(kernels or {})
        self.euid = euid
        if mounts:
            self.files["/proc/mounts"] = mounts

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

    def is_file(self, path: str) -> bool:
        return path in self.paths and path not in self.special

    def realpath(self, path: str) -> str:
        return self.links.get(path, path)

    def guest_kernel_version(self, path: str) -> tuple[int, int] | None:
        return self.kernels.get(path)

    def guest_problem(self, rootfs: str, runtime: str) -> str:
        return getattr(self, "guest_problems", {}).get(rootfs, "")

    def listdir(self, path: str) -> list[str] | None:
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/", 1)[0] for p in self.paths if p.startswith(prefix)}
        return sorted(names) if names or path in self.paths else None

    def readlink(self, path: str) -> str | None:
        return self.links.get(path)

    def stat_path(self, path: str) -> tuple[int, int, int, bool] | None:
        # Undeclared paths are an ordinary root-owned 0755 dir; None marks "cannot stat".
        stats = getattr(self, "stats", {})
        return stats[path] if path in stats else (0o40755, 0, 0, False)

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
               "/var/lib/blastbox/fc/rootfs.ext4", "/var/lib/blastbox/gvisor-rootfs/bin/sh"},
        rw={"/dev/kvm", "/var/lib/blastbox/jobs"},
        executables={
            "docker": "/usr/bin/docker",
            "runsc": "/usr/bin/runsc",
            "firecracker": "/usr/local/bin/firecracker",
            "timedatectl": "/usr/bin/timedatectl",
        },
        links={},
        commands={
            ("/usr/bin/docker", "version", "--format", "{{.Server.Version}}"):
                (0, "29.1.3\n", ""),
            ("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"):
                (0, _RUNTIMES_JSON + "\n", ""),
            ("/usr/bin/runsc", "--version"): (0, "runsc version release-20251110.0\n", ""),
            ("/usr/bin/runsc", "help"): (0, "Subcommands:\n  checkpoint\n  restore\n  run\n", ""),
            ("/usr/local/bin/firecracker", "--version"): (0, "Firecracker v1.16.0\n", ""),
            ("/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"):
                (0, "yes\n", ""),
        },
    )
    for k, v in over.items():
        if k in ("env", "files", "commands", "links"):          # merged; everything else replaces
            merged = dict(base[k])
            merged.update(v)
            base[k] = merged
        else:
            base[k] = v
    return FakeHost(**base)


def _by_name(checks: list[pf.Check]) -> dict[str, pf.Check]:
    return {c.name: c for c in checks}


ALL = ["docker", "gvisor", "firecracker"]
#: Cold workers on plain runc (consented): the only case with a host-kernel inner sandbox.
_RUNC = {"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1"}


# --- tier resolution --------------------------------------------------------------------

def test_tiers_default_to_every_local_tier_when_nothing_is_configured():
    assert pf.resolve_tiers([], {}) == ["docker", "gvisor", "firecracker"]


def test_tiers_follow_the_pool_runtime_plus_the_cold_dispatcher():
    assert pf.resolve_tiers([], {"BLASTBOX_POOL_RUNTIME": "firecracker"}) == [
        "docker", "firecracker"]
    assert pf.resolve_tiers([], {"BLASTBOX_POOL_RUNTIME": "none"}) == ["docker"]


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
    c = _by_name(pf.run_preflight(host, ["docker"]))["docker-runsc-runtime"]
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
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap", **_RUNC},
                    files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ..."})
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
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail", **_RUNC})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.WARN and "deploy/apparmor" in c.detail


def test_restricted_userns_passes_when_the_scoped_profiles_are_loaded():
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.PASS


def test_user_namespaces_switched_off_fails_when_one_is_needed():
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap", **_RUNC},
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
    c = _by_name(pf.run_preflight(host, ["docker"]))["cpu-flags"]
    assert c.status is Status.WARN
    assert "-XX:-UseBASE64Intrinsics" in c.detail


def test_avx512_vbmi2_alone_is_not_mistaken_for_vbmi():
    host = _healthy(files={"/proc/cpuinfo": "flags\t: fpu avx512_vbmi2\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["cpu-flags"]
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
def test_mutating_commands_are_refused_by_the_real_runner(argv, monkeypatch):
    assert not pf.is_read_only(argv)

    def never(*a, **k):  # a regressed guard must not mutate the host running the tests
        raise AssertionError(f"preflight spawned {a!r}")

    monkeypatch.setattr(pf.subprocess, "run", never)
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


# --- running sandbox processes: host root, AppArmor confinement, jailer -------------------

_IDENTITY = "         0          0 4294967295\n"
_REMAPPED = "         0     100000      65536\n"
# CapEff bits: DAC_OVERRIDE=1, DAC_READ_SEARCH=2, SYS_CHROOT=18.
_SANDBOX_CAPS = f"{(1 << 1) | (1 << 2):016x}"
_GOFER_CAPS = f"{1 << 18:016x}"


def _proc(pid: int, argv: list[str], *, uid: int = 0, uid_map: str | None = _IDENTITY,
          caps: str = "0000000000000000", aa: str | None = "docker-default (enforce)\n",
          comm: str | None = None) -> dict[str, str]:
    files = {
        f"/proc/{pid}/cmdline": "\0".join(argv) + "\0",
        f"/proc/{pid}/comm": (comm or argv[0].rsplit("/", 1)[-1])[:15] + "\n",
        f"/proc/{pid}/status": f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t{caps}\n",
    }
    if uid_map is not None:
        files[f"/proc/{pid}/uid_map"] = uid_map
    if aa is not None:
        files[f"/proc/{pid}/attr/current"] = aa
    return files


def _with_procs(*procs: dict[str, str], links: dict[str, str] | None = None, **over) -> FakeHost:
    files: dict[str, str] = {}
    for p in procs:
        files.update(p)
    files["/proc/1/cmdline"] = "/sbin/init\0"
    return _healthy(files=files, links=links or {}, **over)


def test_no_sandbox_processes_running_passes_the_process_checks():
    by = _by_name(pf.run_preflight(_healthy(), ALL))
    assert by["runsc-host-root"].status is Status.PASS
    assert by["sandbox-confinement"].status is Status.PASS


def test_runsc_processes_running_as_real_host_root_warn_with_their_caps():
    host = _with_procs(
        _proc(200, ["runsc-sandbox", "--root=/var/run/docker/runtime-runc/moby", "boot"],
              caps=_SANDBOX_CAPS, comm="exe"),
        _proc(201, ["runsc-gofer", "--root=/x", "gofer"], caps=_GOFER_CAPS, comm="exe"))
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["runsc-host-root"]
    assert c.status is Status.WARN
    assert "DAC_OVERRIDE" in c.detail and "DAC_READ_SEARCH" in c.detail
    assert "SYS_CHROOT" in c.detail and "user-namespace" in c.detail
    assert c.doc.endswith("#runsc-processes-and-host-root")


def test_userns_remapped_runsc_passes():
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid=0, uid_map=_REMAPPED,
                             caps=_SANDBOX_CAPS))
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["runsc-host-root"].status is Status.PASS


def test_unreadable_process_identity_degrades_to_unknown_not_fail():
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid_map=None, aa=None))
    by = _by_name(pf.run_preflight(host, ["gvisor"]))
    for name in ("runsc-host-root", "sandbox-confinement"):
        assert by[name].status is Status.WARN
        assert "unknown (run as root)" in by[name].detail
    assert pf.exit_code(list(by.values())) == 0


def test_unconfined_runsc_or_firecracker_warns():
    host = _with_procs(
        _proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED, aa="unconfined\n"),
        _proc(300, ["/usr/local/bin/firecracker", "--id", "a", "--start-time-us", "1"],
              uid=10001, aa="unconfined\n"))
    c = _by_name(pf.run_preflight(host, ALL))["sandbox-confinement"]
    assert c.status is Status.WARN
    assert "unconfined" in c.detail and "200" in c.detail and "300" in c.detail
    assert c.doc.endswith("#confining-firecracker-and-runsc-processes")


def test_firecracker_without_the_jailer_warns():
    host = _with_procs(
        _proc(300, ["/var/lib/blastbox-fc/firecracker", "--api-sock", "/s/fc.sock"], uid=10001),
        links={"/proc/300/root": "/"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["sandbox-confinement"]
    assert c.status is Status.WARN
    assert "without the jailer" in c.detail and "API/vsock sockets" in c.detail


def test_jailed_and_confined_firecracker_passes():
    jailed = _proc(300, ["firecracker", "--id", "a", "--start-time-us", "1",
                         "--start-time-cpu-us", "2"], uid=10001,
                   aa="blastbox-fc-slot-3 (enforce)\n")
    c = _by_name(pf.run_preflight(_with_procs(jailed), ["firecracker"]))["sandbox-confinement"]
    assert c.status is Status.PASS, c.detail


def test_a_chrooted_or_containerised_firecracker_is_not_taken_for_jailed():
    """A firecracker in a docker container (or any non-/ root) is not the jailer: only the
    jailer's own --start-time-us argument counts."""
    host = _with_procs(_proc(301, ["firecracker", "--api-sock", "/run/fc.sock"], uid=10001),
                       links={"/proc/301/root": "/var/lib/docker/overlay2/x/merged"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "without the jailer" in c.detail


def test_process_checks_only_inspect_processes_for_the_selected_tiers():
    host = _with_procs(_proc(300, ["firecracker", "--api-sock", "/s"], aa="unconfined\n"),
                       links={"/proc/300/root": "/"})
    by = _by_name(pf.run_preflight(host, ["gvisor"]))
    assert by["sandbox-confinement"].status is Status.PASS
    assert "firecracker" not in {c.name for c in pf.run_preflight(host, ["remote"])}
    assert "sandbox-confinement" not in {c.name for c in pf.run_preflight(host, ["remote"])}


def test_real_host_listdir_and_is_file(tmp_path):
    h = pf.RealHost()
    assert h.listdir(str(tmp_path / "missing")) is None
    (tmp_path / "f").write_text("x")
    (tmp_path / "dangling").symlink_to(tmp_path / "gone")
    assert set(h.listdir(str(tmp_path)) or []) == {"f", "dangling"}
    assert h.is_file(str(tmp_path / "f"))
    assert not h.is_file(str(tmp_path / "dangling")) and not h.is_file(str(tmp_path))


# --- upstream review (codex) on #208 ------------------------------------------------------

def test_cascade_tiers_resolve_to_their_local_members():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "firecracker:2,gvisor:2"}
    assert pf.resolve_tiers([], env) == ["docker", "gvisor", "firecracker"]
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "static:4,aws-ec2:16"}
    assert pf.resolve_tiers([], env) == ["remote"]


@pytest.mark.parametrize("env", [
    {"BLASTBOX_WORKER_RUNTIME": "runc"},
    {"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1",
     "BLASTBOX_REQUIRE_SECURE_RUNTIME": "1"},
])
def test_forced_runc_that_the_dispatcher_refuses_fails_even_with_runsc_registered(env):
    c = _by_name(pf.run_preflight(_healthy(env=env), ["docker"]))["docker-runsc-runtime"]
    assert c.status is Status.FAIL
    assert "BLASTBOX_WORKER_RUNTIME=runc" in c.detail


def test_forced_runc_with_consent_is_a_degraded_warning():
    env = {"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1"}
    c = _by_name(pf.run_preflight(_healthy(env=env), ["docker"]))["docker-runsc-runtime"]
    assert c.status is Status.WARN and "degraded" in c.detail


@pytest.mark.parametrize("result", [None, (127, "", "error while loading shared libraries")])
def test_runsc_that_cannot_run_its_version_query_fails(result):
    commands = {} if result is None else {("/usr/bin/runsc", "--version"): result}
    host = _healthy(commands=commands)
    if result is None:
        del host.commands[("/usr/bin/runsc", "--version")]
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["runsc"]
    assert c.status is Status.FAIL
    if result is not None:
        assert "shared libraries" in c.detail


def test_rootless_gvisor_fails_the_warm_gvisor_tier():
    host = _healthy(env={"BLASTBOX_GVISOR_ROOTLESS": "1"})
    by = _by_name(pf.run_preflight(host, ["gvisor"]))
    assert by["gvisor-rootless"].status is Status.FAIL
    assert "restore" in by["gvisor-rootless"].detail
    assert "gvisor-rootless" not in _by_name(pf.run_preflight(_healthy(), ["gvisor"]))


def test_forced_runsc_missing_fails_even_with_runc_consent():
    host = _healthy(env={"BLASTBOX_WORKER_RUNTIME": "runsc", "BLASTBOX_ALLOW_RUNC": "1"},
                    commands={("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"):
                              (0, '{"runc":{}}', "")})
    assert _by_name(pf.run_preflight(host, ["docker"]))["docker-runsc-runtime"].status \
        is Status.FAIL


# --- marla round 1 on #208 ----------------------------------------------------------------

def test_fc_guest_artifact_that_is_not_a_regular_file_fails():
    host = _healthy(special={"/var/lib/blastbox/fc/rootfs.ext4"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"]
    assert c.status is Status.FAIL and "BLASTBOX_FC_ROOTFS" in c.detail


def test_warm_fc_with_a_pre_5_18_guest_kernel_fails_but_cold_fc_passes():
    old = {"/var/lib/blastbox/fc/vmlinux": (5, 10)}
    warm = _healthy(env={"BLASTBOX_POOL_WARM_SNAPSHOT": "1"}, kernels=old)
    c = _by_name(pf.run_preflight(warm, ["firecracker"]))["fc-guest"]
    assert c.status is Status.FAIL and "5.18" in c.detail
    assert _by_name(pf.run_preflight(_healthy(kernels=old), ["firecracker"]))["fc-guest"].status \
        is Status.PASS
    new = _healthy(env={"BLASTBOX_POOL_WARM_SNAPSHOT": "1"},
                   kernels={"/var/lib/blastbox/fc/vmlinux": (6, 1)})
    assert _by_name(pf.run_preflight(new, ["firecracker"]))["fc-guest"].status is Status.PASS


def test_runsc_without_checkpoint_restore_fails_the_gvisor_tier():
    host = _healthy(commands={("/usr/bin/runsc", "help"): (0, "Subcommands:\n  run\n  create\n", "")})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["runsc"]
    assert c.status is Status.FAIL and "checkpoint" in c.detail
    assert pf.is_read_only(["/usr/bin/runsc", "help"])


def test_scoped_profile_attached_to_another_path_than_the_binary_warns():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail", **_RUNC},
                    executables={"nsjail": "/usr/bin/nsjail", "docker": "/usr/bin/docker",
                                 "runsc": "/usr/bin/runsc", "firecracker":
                                 "/usr/local/bin/firecracker", "timedatectl": "/usr/bin/timedatectl"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n",
                           "/etc/apparmor.d/blastbox-nsjail":
                           "abi <abi/4.0>,\nprofile blastbox-nsjail /usr/local/bin/nsjail flags=(unconfined) {\n}\n"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["userns"]
    assert c.status is Status.WARN
    assert "/usr/local/bin/nsjail" in c.detail and "/usr/bin/nsjail" in c.detail


def test_unknown_pool_runtime_fails():
    for env in ({"BLASTBOX_POOL_RUNTIME": "firecrakcer"},
                {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvsior:1,firecracker:2"},
                {"BLASTBOX_POOL_RUNTIME": "cascade"}):
        c = _by_name(pf.run_preflight(_healthy(env=env), ["docker"]))["pool-runtime"]
        assert c.status is Status.FAIL, env
    assert "pool-runtime" not in _by_name(pf.run_preflight(_healthy(), ["docker"]))
    ok = _healthy(env={"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "static:4,aws-ec2:8"})
    assert _by_name(pf.run_preflight(ok, ["remote"]))["pool-runtime"].status is Status.PASS


def test_json_ok_honours_strict():
    checks = [pf.Check("clock", Status.WARN, "x")]
    assert json.loads(pf.render_json(checks, ["docker"]))["ok"] is True
    assert json.loads(pf.render_json(checks, ["docker"], strict=True))["ok"] is False


def test_scoped_profile_matching_the_resolved_binary_passes():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail"},
                    executables={"nsjail": "/usr/bin/nsjail", "docker": "/usr/bin/docker"},
                    links={"/usr/bin/nsjail": "/usr/local/bin/nsjail"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n",
                           "/etc/apparmor.d/blastbox-nsjail":
                           "profile blastbox-nsjail /usr/local/bin/nsjail flags=(unconfined) {\n}\n"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS


# --- marla round 1 Claude lens on #208 -----------------------------------------------------

@pytest.mark.parametrize("env", [
    {"BLASTBOX_POOL_RUNTIME": "aws-ec2"},
    {"BLASTBOX_POOL_RUNTIME": "static"},
    {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "static:4,aws-ec2:16"},
])
def test_remote_only_dispatchers_have_no_cold_docker_tier(env):
    assert pf.resolve_tiers([], env) == ["remote"]


def test_warm_only_local_dispatchers_have_no_cold_docker_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "firecracker", "BLASTBOX_DISPATCH_WARM_ONLY": "1"}
    assert pf.resolve_tiers([], env) == ["firecracker"]


@pytest.mark.parametrize("label", ["blastbox-runsc (unconfined)\n", "docker-default (complain)\n",
                                   "unconfined\n"])
def test_unconfined_or_complain_mode_profiles_are_not_confinement(label):
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED, aa=label))
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "200" in c.detail


@pytest.mark.parametrize("result", [None, (0, "no version here\n", "")])
def test_firecracker_whose_version_cannot_be_read_fails(result):
    host = _healthy()
    if result is None:
        del host.commands[("/usr/local/bin/firecracker", "--version")]
    else:
        host.commands[("/usr/local/bin/firecracker", "--version")] = result
    assert _by_name(pf.run_preflight(host, ["firecracker"]))["firecracker"].status is Status.FAIL


def test_renamed_runsc_binary_can_be_probed_for_checkpoint_restore():
    assert pf.is_read_only(["/opt/gvisor/bin/gvisor-runsc", "help"])


@pytest.mark.parametrize("value", ["", " /usr/bin/runsc"])
def test_set_but_empty_or_padded_runsc_knob_fails_like_the_runtime(value):
    host = _healthy(env={"BLASTBOX_GVISOR_RUNSC": value})
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["runsc"].status is Status.FAIL


@pytest.mark.parametrize("value,status", [("0", Status.WARN), ("0.0", Status.WARN),
                                          ("00", Status.WARN), ("6h", Status.WARN),
                                          ("-5", Status.WARN), ("3600", Status.PASS)])
def test_snapshot_age_parses_like_the_runtime(value, status):
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MAX_AGE_S": value})
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["snapshot-age"].status is status


@pytest.mark.parametrize("tiers", ["firecracker:2,aws-ec2:4", "firecracker", "firecracker:0",
                                   "Firecracker:2"])
def test_cascade_specs_the_dispatcher_refuses_fail(tiers):
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": tiers}
    assert _by_name(pf.run_preflight(_healthy(env=env), ["remote"]))["pool-runtime"].status \
        is Status.FAIL


def test_fc_slot_scratch_on_a_tmpfs_tmp_warns():
    host = _healthy(mounts="tmpfs /tmp tmpfs rw,nosuid 0 0\n/dev/sda1 / ext4 rw 0 0\n")
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["fc-scratch"]
    assert c.status is Status.WARN and "/tmp/blastbox-fc-slots" in c.detail
    disk = _healthy(mounts="/dev/sda1 / ext4 rw 0 0\n")
    assert _by_name(pf.run_preflight(disk, ["firecracker"]))["fc-scratch"].status is Status.PASS


def test_profile_attachment_compares_the_resolved_binary_only():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail", **_RUNC},
                    executables={"nsjail": "/usr/local/bin/nsjail", "docker": "/usr/bin/docker"},
                    links={"/usr/local/bin/nsjail": "/opt/nsjail/bin/nsjail"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n",
                           "/etc/apparmor.d/blastbox-nsjail":
                           "profile blastbox-nsjail /usr/local/bin/nsjail flags=(unconfined) {\n}\n"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.WARN


def test_acknowledged_warnings_do_not_fail_strict():
    checks = [pf.Check("cpu-flags", Status.WARN, "x"), pf.Check("clock", Status.PASS, "")]
    assert pf.exit_code(checks, strict=True) == 1
    assert pf.exit_code(checks, strict=True, ack={"cpu-flags"}) == 0
    assert json.loads(pf.render_json(checks, ["docker"], strict=True, ack={"cpu-flags"}))["ok"]


def test_stock_bwrap_profile_only_warns_when_something_nests_bwrap():
    host = _healthy(paths={"/etc/apparmor.d/bwrap-userns-restrict", "/dev/kvm",
                           "/var/lib/blastbox/jobs", "/var/lib/blastbox/fc/vmlinux",
                           "/var/lib/blastbox/fc/rootfs.ext4"})
    assert _by_name(pf.run_preflight(host, ["firecracker"]))["bwrap-userns-restrict"].status \
        is Status.PASS
    host.env.update({"BLASTBOX_SANDBOX": "bwrap", **_RUNC})
    assert _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"].status \
        is Status.WARN


def test_kvm_as_root_says_the_dispatcher_user_is_unverified():
    c = _by_name(pf.run_preflight(_healthy(euid=0), ["firecracker"]))["kvm"]
    assert c.status is Status.PASS and "dispatcher user" in c.detail


def test_warm_only_gvisor_does_not_need_docker():
    env = {"BLASTBOX_POOL_RUNTIME": "gvisor", "BLASTBOX_DISPATCH_WARM_ONLY": "1"}
    host = _healthy(env=env, executables={"runsc": "/usr/bin/runsc"})
    tiers = pf.resolve_tiers([], env)
    names = {c.name for c in pf.run_preflight(host, tiers)}
    assert tiers == ["gvisor"] and "docker" not in names and "docker-runsc-runtime" not in names


@pytest.mark.parametrize("pool", ["none", ""])
def test_warm_only_without_a_pool_fails(pool):
    env = {"BLASTBOX_DISPATCH_WARM_ONLY": "1"}
    if pool:
        env["BLASTBOX_POOL_RUNTIME"] = pool
    c = _by_name(pf.run_preflight(_healthy(env=env), pf.resolve_tiers([], env)))["pool-runtime"]
    assert c.status is Status.FAIL and "WARM_ONLY" in c.detail


# --- marla round 2 Claude lens on #208 -----------------------------------------------------

def test_set_but_empty_pool_runtime_fails():
    c = _by_name(pf.run_preflight(_healthy(env={"BLASTBOX_POOL_RUNTIME": ""}), ["docker"]))
    assert c["pool-runtime"].status is Status.FAIL


def test_fc_guest_unset_fails_when_this_env_selects_the_fc_pool():
    for env in ({"BLASTBOX_POOL_RUNTIME": "firecracker"},
                {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "firecracker:2"}):
        host = _healthy(env=env)
        del host.env["BLASTBOX_FC_KERNEL"], host.env["BLASTBOX_FC_ROOTFS"]
        assert _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"].status is Status.FAIL


def test_fc_tmpfs_scratch_is_its_own_check_and_hides_nothing():
    host = _healthy(env={"BLASTBOX_JOB_ROOT": "/tmp/jobs"},
                    mounts="tmpfs /tmp tmpfs rw 0 0\n")
    checks = pf.run_preflight(host, ["firecracker"])
    by = _by_name(checks)
    assert by["fc-scratch"].status is Status.WARN
    assert by["scratch"].status is Status.WARN and "/tmp/jobs" in by["scratch"].detail
    assert pf.exit_code(checks, strict=True, ack={"fc-scratch"}) == 1


def test_real_host_run_survives_non_utf8_output(tmp_path, monkeypatch):
    fake = tmp_path / "fc"
    fake.write_text("#!/bin/sh\nprintf '\\377'\n")
    fake.chmod(0o755)
    proc = pf.RealHost().run([str(fake), "--version"])
    assert proc is not None and proc.returncode == 0


def test_cli_honours_strict_ack_and_json(capsys, monkeypatch):
    from blastbox.host import cli

    host = _healthy(files={"/proc/cpuinfo": "flags\t: avx512vbmi\n"})
    monkeypatch.setattr(pf, "RealHost", lambda: host)
    assert cli.main(["preflight", "--tier", "docker", "--strict"]) == 1
    assert cli.main(["preflight", "--tier", "docker", "--strict", "--ack", "cpu-flags"]) == 0
    capsys.readouterr()
    assert cli.main(["preflight", "--tier", "docker", "--strict", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_stock_bwrap_profile_warns_for_runc_like_userns():
    host = _healthy(env={"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1",
                         "BLASTBOX_SANDBOX": "bwrap"},
                    files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ..."})
    assert _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"].status \
        is Status.WARN


def test_unknown_overflow_cascade_member_warns_unknown_primary_fails():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "firecracker:2,gvsior:1"}
    assert _by_name(pf.run_preflight(_healthy(env=env), ["firecracker"]))["pool-runtime"].status \
        is Status.WARN
    env["BLASTBOX_POOL_TIERS"] = "gvsior:1,firecracker:2"
    assert _by_name(pf.run_preflight(_healthy(env=env), ["firecracker"]))["pool-runtime"].status \
        is Status.FAIL


def test_non_apparmor_label_is_unknown_not_confined():
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED,
                             aa="unconfined_u:unconfined_r:unconfined_t:s0\n"))
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "cannot be verified" in c.detail


def test_apparmor_specific_attr_is_preferred():
    files = _proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED,
                  aa="system_u:system_r:spc_t:s0\n")
    files["/proc/200/attr/apparmor/current"] = "blastbox-runsc (unconfined)\n"
    c = _by_name(pf.run_preflight(_with_procs(files), ["gvisor"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "not confined" in c.detail


@pytest.mark.parametrize("value", ["", " /var/lib/blastbox/jobs"])
def test_set_but_empty_or_padded_job_root_warns(value):
    c = _by_name(pf.run_preflight(_healthy(env={"BLASTBOX_JOB_ROOT": value}), ["docker"]))
    assert c["scratch"].status is Status.WARN


def test_snapshot_age_does_not_log_a_wrong_knob(caplog):
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MAX_AGE_S": "6h"})
    with caplog.at_level("WARNING"):
        pf.run_preflight(host, ["gvisor"])
    assert "invalid v=" not in caplog.text


def test_stock_bwrap_profile_is_irrelevant_to_nsjail_only():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail"},
                    files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ..."})
    assert _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"].status \
        is Status.PASS


# --- marla round 3 Claude lens on #208 -----------------------------------------------------

def test_cascade_member_names_are_case_sensitive_like_the_dispatcher():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "firecracker:2,AWS-EC2:1"}
    assert pf.resolve_tiers([], env) == ["docker", "firecracker"]


def test_cascade_primary_skips_empty_items_like_the_parser():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": ",firecracker:2"}
    host = _healthy(env=env)
    del host.env["BLASTBOX_FC_KERNEL"], host.env["BLASTBOX_FC_ROOTFS"]
    assert _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"].status is Status.FAIL


def test_fc_overflow_without_guest_knobs_says_the_dispatcher_drops_it():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2"}
    host = _healthy(env=env)
    del host.env["BLASTBOX_FC_KERNEL"], host.env["BLASTBOX_FC_ROOTFS"]
    c = _by_name(pf.run_preflight(host, ["gvisor", "firecracker"]))["fc-guest"]
    assert c.status is Status.WARN and "skips" in c.detail


def test_runc_userns_needs_only_count_on_the_docker_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "gvisor", "BLASTBOX_DISPATCH_WARM_ONLY": "1",
           "BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1"}
    host = _healthy(env=env, files={"/proc/sys/user/max_user_namespaces": "0"})
    by = _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env)))
    assert by["userns"].status is not Status.FAIL


def test_non_apparmor_label_says_no_apparmor_label_not_run_as_root():
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED,
                             aa="system_u:system_r:container_runtime_t:s0\n"))
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "no AppArmor label" in c.detail
    assert "run as root" not in c.detail


@pytest.mark.parametrize("value", ["", " /var/lib/blastbox/gvisor-root"])
def test_empty_or_padded_gvisor_root_warns(value):
    c = _by_name(pf.run_preflight(_healthy(env={"BLASTBOX_GVISOR_ROOT": value}), ["gvisor"]))
    assert c["scratch"].status is Status.WARN


def test_gvisor_rootfs_missing_fails_when_this_env_selects_gvisor():
    env = {"BLASTBOX_POOL_RUNTIME": "gvisor"}
    bare = {"paths": {"/var/lib/blastbox/jobs"}}
    c = _by_name(pf.run_preflight(_healthy(env=env, **bare), ["gvisor"]))["gvisor-rootfs"]
    assert c.status is Status.FAIL and "/var/lib/blastbox/gvisor-rootfs" in c.detail
    assert _by_name(pf.run_preflight(_healthy(**bare), ["gvisor"]))["gvisor-rootfs"].status \
        is Status.WARN
    ok = _healthy(env=env, paths={"/var/lib/blastbox/gvisor-rootfs/bin/sh", "/var/lib/blastbox/jobs"})
    assert _by_name(pf.run_preflight(ok, ["gvisor"]))["gvisor-rootfs"].status is Status.PASS


# --- marla round 4 on #208 -----------------------------------------------------------------

def test_rootless_gvisor_knob_is_a_userns_need_only_on_the_gvisor_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "firecracker", "BLASTBOX_DISPATCH_WARM_ONLY": "1",
           "BLASTBOX_GVISOR_ROOTLESS": "1"}
    host = _healthy(env=env, files={"/proc/sys/user/max_user_namespaces": "0"})
    assert _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env)))["userns"].status \
        is not Status.FAIL


@pytest.mark.parametrize("drop", [("BLASTBOX_FC_ROOTFS",), ()])
def test_fc_overflow_problems_warn_because_the_dispatcher_skips_the_tier(drop):
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2",
           "BLASTBOX_POOL_WARM_SNAPSHOT": "1"}
    host = _healthy(env=env, kernels={"/var/lib/blastbox/fc/vmlinux": (5, 10)},
                    paths={"/var/lib/blastbox/jobs", "/var/lib/blastbox/fc/vmlinux",
                           "/var/lib/blastbox/fc/rootfs.ext4", "/var/lib/blastbox/gvisor-rootfs/x"})
    for k in drop:
        del host.env[k]
    by = _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False))
    for name in ("fc-guest", "kvm"):   # kvm here: /dev/kvm missing, a startup gate
        assert by[name].status is Status.WARN, (name, by[name])
        assert "skips" in by[name].detail


def test_apparmor_off_without_another_lsm_is_named():
    host = _with_procs(_proc(200, ["runsc-sandbox", "boot"], uid_map=_REMAPPED, aa=None), euid=0)
    host.files["/sys/module/apparmor/parameters/enabled"] = "N\n"
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["sandbox-confinement"]
    assert "run as root" not in c.detail and "AppArmor" in c.detail


def test_gvisor_root_under_tmp_matters_only_on_the_gvisor_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "firecracker", "BLASTBOX_DISPATCH_WARM_ONLY": "1",
           "BLASTBOX_GVISOR_ROOT": "/tmp/gv-root"}
    host = _healthy(env=env)
    assert _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env)))["scratch"].status \
        is Status.PASS


def test_runc_with_nsjail_inner_sandbox_ignores_the_stock_bwrap_profile():
    host = _healthy(env={"BLASTBOX_WORKER_RUNTIME": "runc", "BLASTBOX_ALLOW_RUNC": "1",
                         "BLASTBOX_SANDBOX": "nsjail"},
                    files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap ..."})
    assert _by_name(pf.run_preflight(host, ["docker"]))["bwrap-userns-restrict"].status \
        is Status.PASS


# --- final sweep on #208 -------------------------------------------------------------------

def test_remote_only_host_does_not_need_local_userns_for_the_sandbox_knob():
    env = {"BLASTBOX_POOL_RUNTIME": "static", "BLASTBOX_SANDBOX": "bwrap"}
    host = _healthy(env=env, files={"/proc/sys/user/max_user_namespaces": "0"})
    checks = pf.run_preflight(host, pf.resolve_tiers([], host.env))
    assert all(c.status is not Status.FAIL for c in checks if c.name == "userns")


def test_scratch_symlinked_into_tmp_warns():
    host = _healthy(links={"/var/lib/blastbox/jobs": "/tmp/blastbox/jobs"})
    c = _by_name(pf.run_preflight(host, ["docker"]))["scratch"]
    assert c.status is Status.WARN and "/tmp" in c.detail


def test_renamed_firecracker_binary_is_inspected():
    host = _with_procs(_proc(300, ["/opt/fc/fc-v1.16", "--api-sock", "/s"], uid=10001,
                             aa="unconfined\n", comm="fc-v1.16"),
                       env={"BLASTBOX_FC_BIN": "/opt/fc/fc-v1.16"})
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["sandbox-confinement"]
    assert c.status is Status.WARN and "300" in c.detail


def test_only_the_configured_sandboxs_profile_is_required():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail"},
                    files={"/sys/kernel/security/apparmor/profiles": "blastbox-nsjail (unconfined)\n"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS


# --- full-PR sweep on #208 -----------------------------------------------------------------

def test_default_tiers_on_an_unconfigured_host_warn_rather_than_fail_unselected_tiers():
    host = _healthy(paths={"/var/lib/blastbox/jobs"}, rw=set())
    host.executables.pop("firecracker")
    checks = pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False)
    by = _by_name(checks)
    assert by["kvm"].status is Status.WARN and by["firecracker"].status is Status.WARN
    assert "not selected" in by["firecracker"].detail
    assert pf.exit_code(checks) == 0
    # An explicit --tier keeps FAIL: the operator asked about that tier.
    assert _by_name(pf.run_preflight(host, ["firecracker"]))["kvm"].status is Status.FAIL


@pytest.mark.parametrize("mounts,status", [
    ("/dev/sda1 /tmp ext4 rw 0 0\ntmpfs /tmp/blastbox-fc-slots tmpfs rw 0 0\n", Status.WARN),
    ("tmpfs /tmp tmpfs rw 0 0\n/dev/sdb1 /tmp/blastbox-fc-slots ext4 rw 0 0\n", Status.PASS),
    ("/dev/sda1 /tmp ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n", Status.WARN),
    ("tmpfs / tmpfs rw 0 0\n", Status.WARN),
])
def test_fc_scratch_resolves_the_mount_holding_the_slot_dir(mounts, status):
    c = _by_name(pf.run_preflight(_healthy(mounts=mounts), ["firecracker"]))["fc-scratch"]
    assert c.status is status, c.detail


def test_overflow_non_gate_problems_on_warm_tiers_warn_never_ready():
    """A missing gVisor rootfs / non-rw kvm on a WARM overflow tier is admitted, its base never
    builds, and the cascade serves on the primary: degraded (WARN), not refused."""
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "firecracker:2,gvisor:2"}
    host = _healthy(env=env, paths={"/dev/kvm", "/var/lib/blastbox/jobs",
                                    "/var/lib/blastbox/fc/vmlinux", "/var/lib/blastbox/fc/rootfs.ext4"})
    c = _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False))["gvisor-rootfs"]
    assert c.status is Status.WARN and "never" in c.detail
    env2 = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2",
            "BLASTBOX_POOL_WARM_SNAPSHOT": "1"}
    host2 = _healthy(env=env2, rw=set())
    assert _by_name(pf.run_preflight(host2, pf.resolve_tiers([], host2.env), explicit=False))["kvm"].status \
        is Status.WARN
    # A COLD firecracker overflow tier really spawns on a non-rw kvm, and every spawn fails.
    env3 = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2"}
    host3 = _healthy(env=env3, rw=set())
    assert _by_name(pf.run_preflight(host3, pf.resolve_tiers([], host3.env), explicit=False))["kvm"].status \
        is Status.FAIL


def test_snapshot_age_counts_the_runtime_ceiling_factor():
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MAX_AGE_S": "43200"})
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["snapshot-age"].status is Status.WARN


def test_stock_bwrap_profile_ignores_the_sandbox_knob_off_the_docker_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "firecracker", "BLASTBOX_DISPATCH_WARM_ONLY": "1",
           "BLASTBOX_SANDBOX": "bwrap"}
    host = _healthy(env=env, files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap"})
    assert _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env)))[
        "bwrap-userns-restrict"].status is Status.PASS


def test_attachment_mismatch_only_for_the_configured_tool():
    host = _healthy(env={"BLASTBOX_SANDBOX": "bwrap"},
                    executables={"docker": "/usr/bin/docker", "bwrap": "/usr/bin/bwrap",
                                 "nsjail": "/usr/bin/nsjail"},
                    files={"/sys/kernel/security/apparmor/profiles":
                           "blastbox-bwrap (unconfined)\nblastbox-nsjail (unconfined)\n",
                           "/etc/apparmor.d/blastbox-bwrap": "profile blastbox-bwrap /usr/bin/bwrap {\n}\n",
                           "/etc/apparmor.d/blastbox-nsjail":
                           "profile blastbox-nsjail /usr/local/bin/nsjail {\n}\n"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS


def test_cli_without_tier_previews_unselected_tiers(capsys, monkeypatch):
    from blastbox.host import cli
    host = _healthy(paths={"/var/lib/blastbox/jobs"}, rw=set())
    host.executables.pop("firecracker")
    monkeypatch.setattr(pf, "RealHost", lambda: host)
    assert cli.main(["preflight"]) == 0
    assert cli.main(["preflight", "--tier", "firecracker"]) == 1
    capsys.readouterr()


def test_sandbox_knob_needs_host_userns_only_on_the_docker_tier():
    env = {"BLASTBOX_POOL_RUNTIME": "firecracker", "BLASTBOX_DISPATCH_WARM_ONLY": "1",
           "BLASTBOX_SANDBOX": "nsjail"}
    host = _healthy(env=env, files={"/proc/sys/user/max_user_namespaces": "0"})
    assert _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env)))["userns"].status \
        is Status.PASS


def test_userns_off_with_nothing_needing_it_passes():
    host = _healthy(files={"/proc/sys/kernel/unprivileged_userns_clone": "0\n"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS


@pytest.mark.parametrize("value,status", [("86400", Status.WARN), ("172800", Status.WARN),
                                          ("21600", Status.PASS)])
def test_snapshot_age_past_a_day_warns(value, status):
    host = _healthy(env={"BLASTBOX_SNAPSHOT_MAX_AGE_S": value})
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["snapshot-age"].status is status


def test_remote_only_hosts_skip_local_worker_checks():
    host = _healthy(files={"/proc/cpuinfo": "flags\t: avx512vbmi\n"})
    del host.files["/sys/module/apparmor/parameters/enabled"]
    names = {c.name for c in pf.run_preflight(host, ["remote"])}
    assert not names & {"apparmor", "cpu-flags", "bwrap-userns-restrict", "userns"}


def test_a_skipped_overflow_tier_downgrades_all_its_fails():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2"}
    host = _healthy(env=env, rw=set())          # /dev/kvm present but not rw (not a gate)
    host.executables.pop("firecracker")         # ...but the binary is missing (a gate)
    by = _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False))
    assert by["firecracker"].status is Status.WARN
    assert by["kvm"].status is Status.WARN      # moot: the whole tier is skipped


def test_snapshot_age_only_matters_for_warm_snapshot_tiers():
    env = {"BLASTBOX_SNAPSHOT_MAX_AGE_S": "43200"}
    assert "snapshot-age" not in _by_name(pf.run_preflight(_healthy(env=env), ["firecracker"]))
    env["BLASTBOX_POOL_WARM_SNAPSHOT"] = "1"
    assert _by_name(pf.run_preflight(_healthy(env=env), ["firecracker"]))["snapshot-age"].status \
        is Status.WARN


def test_fc_overflow_skipped_for_unset_guest_knobs_downgrades_kvm():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2"}
    host = _healthy(env=env, rw=set())
    del host.env["BLASTBOX_FC_KERNEL"], host.env["BLASTBOX_FC_ROOTFS"]
    checks = pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False)
    assert _by_name(checks)["kvm"].status is Status.WARN
    assert pf.exit_code(checks) == 0


# --- final sweep 2 on #208 -----------------------------------------------------------------

_NO_RUNSC = {("/usr/bin/docker", "info", "--format", "{{json .Runtimes}}"): (0, '{"runc":{}}', "")}


def test_fallback_runc_counts_like_forced_runc():
    host = _healthy(env={"BLASTBOX_ALLOW_RUNC": "1", "BLASTBOX_SANDBOX": "bwrap"}, commands=_NO_RUNSC,
                    files={"/proc/sys/user/max_user_namespaces": "0"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.FAIL


def test_sandbox_knob_under_runsc_needs_no_host_userns():
    host = _healthy(env={"BLASTBOX_SANDBOX": "nsjail"},
                    files={"/proc/sys/user/max_user_namespaces": "0"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS
    host2 = _healthy(env={"BLASTBOX_SANDBOX": "bwrap"},
                     files={"/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap"})
    assert _by_name(pf.run_preflight(host2, ["docker"]))["bwrap-userns-restrict"].status \
        is Status.PASS


def test_cascade_mixing_mtls_and_public_tls_tiers_fails():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "static:4,aws-lambda-microvm:16",
           "BLASTBOX_DISPATCH_TLS_CA": "/etc/blastbox/ca.pem"}
    assert _by_name(pf.run_preflight(_healthy(env=env), ["remote"]))["pool-runtime"].status \
        is Status.FAIL
    del env["BLASTBOX_DISPATCH_TLS_CA"]
    assert _by_name(pf.run_preflight(_healthy(env=env), ["remote"]))["pool-runtime"].status \
        is Status.PASS


def test_text_output_survives_non_utf8_env_bytes():
    checks = [pf.Check("scratch", Status.WARN, "BLASTBOX_JOB_ROOT=/var/lib/x\\udcff")]
    checks[0] = pf.Check("scratch", Status.WARN, "BLASTBOX_JOB_ROOT=/var/lib/x" + chr(0xDCFF))
    pf.render_text(checks, ["remote"]).encode("utf-8")


def test_unwritable_job_root_warns():
    host = _healthy(rw={"/dev/kvm"})          # job root exists but is not read/write
    host.rw.discard("/var/lib/blastbox/jobs")
    c = _by_name(pf.run_preflight(host, ["docker"]))["scratch"]
    assert c.status is Status.WARN and "not writable" in c.detail


def test_tls_mix_is_checked_before_the_overflow_typo_warn():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade",
           "BLASTBOX_POOL_TIERS": "static:4,aws-lambda-microvm:16,unknown:1",
           "BLASTBOX_DISPATCH_TLS_CA": "/etc/blastbox/ca.pem"}
    assert _by_name(pf.run_preflight(_healthy(env=env), ["remote"]))["pool-runtime"].status \
        is Status.FAIL


@pytest.mark.parametrize("backend", ["container", "nono"])
def test_runc_with_a_non_namespace_backend_needs_no_userns(backend):
    host = _healthy(env={**_RUNC, "BLASTBOX_SANDBOX": backend},
                    files={"/proc/sys/user/max_user_namespaces": "0"})
    assert _by_name(pf.run_preflight(host, ["docker"]))["userns"].status is Status.PASS


def test_runc_with_the_default_container_backend_needs_no_userns():
    host = _healthy(env=dict(_RUNC), files={"/proc/sys/user/max_user_namespaces": "0",
                                            "/etc/apparmor.d/bwrap-userns-restrict": "profile bwrap"})
    by = _by_name(pf.run_preflight(host, ["docker"]))
    assert by["userns"].status is Status.PASS
    assert by["bwrap-userns-restrict"].status is Status.PASS


def test_explicit_tier_keeps_overflow_fails():
    env = {"BLASTBOX_POOL_RUNTIME": "cascade", "BLASTBOX_POOL_TIERS": "gvisor:2,firecracker:2"}
    host = _healthy(env=env)
    host.executables.pop("firecracker")
    assert _by_name(pf.run_preflight(host, ["firecracker"], explicit=True))["firecracker"].status \
        is Status.FAIL
    assert _by_name(pf.run_preflight(host, pf.resolve_tiers([], host.env), explicit=False))[
        "firecracker"].status is Status.WARN


def test_gvisor_rootfs_with_an_incompatible_stamp_fails():
    env = {"BLASTBOX_POOL_RUNTIME": "gvisor"}
    host = _healthy(env=env)
    host.guest_problems = {"/var/lib/blastbox/gvisor-rootfs": "stamped for blastbox 0.1.10"}
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-rootfs"]
    assert c.status is Status.FAIL and "0.1.10" in c.detail


def test_fc_rootfs_with_an_incompatible_stamp_fails():
    host = _healthy(env={"BLASTBOX_POOL_RUNTIME": "firecracker"})
    host.guest_problems = {"/var/lib/blastbox/fc/rootfs.ext4": "stamped for aarch64"}
    c = _by_name(pf.run_preflight(host, ["firecracker"]))["fc-guest"]
    assert c.status is Status.FAIL and "aarch64" in c.detail


# --- warm gVisor in a user namespace (BLASTBOX_GVISOR_USERNS_HOST_BASE) ---------------------

_UNS = {"BLASTBOX_GVISOR_USERNS_HOST_BASE": "2000000"}
_SUBIDS = {"/etc/subuid": "coz:100000:65536\nblastbox:2000000:65536\n",
           "/etc/subgid": "coz:100000:65536\nblastbox:2000000:65536\n"}


def test_gvisor_userns_check_only_when_opted_in():
    assert "gvisor-userns" not in _by_name(pf.run_preflight(_healthy(), ["gvisor"]))
    host = _healthy(env=_UNS, files=_SUBIDS)
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.PASS and "2000000..2065535" in c.detail
    assert "gvisor-userns" not in _by_name(pf.run_preflight(host, ["docker"]))


@pytest.mark.parametrize("raw", ["root", "0", "1000", "4294967290"])
def test_gvisor_userns_value_the_runtime_ignores_fails(raw):
    host = _healthy(env={"BLASTBOX_GVISOR_USERNS_HOST_BASE": raw}, files=_SUBIDS)
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.FAIL and "host root" in c.detail


def test_gvisor_userns_rootfs_under_a_0750_home_fails():
    host = _healthy(env={**_UNS, "BLASTBOX_GVISOR_ROOTFS": "/home/coz/rootfs"}, files=_SUBIDS)
    host.stats = {"/home/coz": (0o40750, 1000, 1000, False)}
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.FAIL and "/home/coz " in c.detail and "refuses to start" in c.detail


def test_gvisor_userns_rootfs_check_follows_symlinks():
    host = _healthy(env={**_UNS, "BLASTBOX_GVISOR_ROOTFS": "/var/lib/blastbox/gvisor-rootfs"},
                    files=_SUBIDS, links={"/var/lib/blastbox/gvisor-rootfs": "/home/coz/rootfs"})
    host.stats = {"/home/coz": (0o40700, 1000, 1000, False)}
    assert _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"].status is Status.FAIL


def test_gvisor_userns_unverifiable_rootfs_warns_never_fails():
    host = _healthy(env=_UNS, files=_SUBIDS)
    host.stats = {"/var/lib/blastbox": None}
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.WARN and "cannot verify" in c.detail


@pytest.mark.parametrize("subuid,why", [
    ("coz:100000:65536\n", "reserves no range"),
    ("blastbox:2000000:65535\n", "overlaps"),                  # one id short
    ("dockremap:1999000:2000\nblastbox:2000000:65536\n", "overlaps"),
])
def test_gvisor_userns_subuid_reservation_warns(subuid, why):
    host = _healthy(env=_UNS, files={**_SUBIDS, "/etc/subuid": subuid})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.WARN and "/etc/subuid" in c.detail and why in c.detail
    assert "/etc/subgid" not in c.detail


def test_gvisor_userns_unreadable_subgid_warns():
    host = _healthy(env=_UNS, files={"/etc/subuid": _SUBIDS["/etc/subuid"]})
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["gvisor-userns"]
    assert c.status is Status.WARN and "/etc/subgid unreadable" in c.detail


def test_gvisor_userns_on_an_overflow_tier_only_the_startup_gate_skips_it():
    env = {**_UNS, "BLASTBOX_POOL_RUNTIME": "cascade",
           "BLASTBOX_POOL_TIERS": "firecracker:2,gvisor:2"}
    bad = _healthy(env={**env, "BLASTBOX_GVISOR_ROOTFS": "/home/coz/rootfs"}, files=_SUBIDS)
    bad.stats = {"/home/coz": (0o40750, 1000, 1000, False)}
    tiers = pf.resolve_tiers([], bad.env)
    c = _by_name(pf.run_preflight(bad, tiers, explicit=False))["gvisor-userns"]
    assert c.status is Status.WARN and "skips it at startup" in c.detail


def test_runsc_host_root_points_at_the_userns_knob():
    host = _healthy(files={"/proc/42/cmdline": "runsc-gofer\0--root\0",
                           "/proc/42/uid_map": "0 0 4294967295\n",
                           "/proc/42/status": "Uid:\t0\t0\t0\t0\nCapEff:\t0\n"},
                    paths={"/proc/42"})
    host.paths |= {"/var/lib/blastbox/gvisor-rootfs/bin/sh", "/var/lib/blastbox/jobs"}
    c = _by_name(pf.run_preflight(host, ["gvisor"]))["runsc-host-root"]
    assert c.status is Status.WARN and "BLASTBOX_GVISOR_USERNS_HOST_BASE" in c.detail
