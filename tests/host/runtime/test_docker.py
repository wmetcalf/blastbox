"""Tests for blastbox.host.runtime.docker — runtime selection and argv builder."""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.errors import SandboxError
from blastbox.host.runtime.docker import (
    InsecureRuntimeRefused,
    RuntimeSelection,
    build_worker_docker_run_argv,
    select_worker_runtime,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _argv(
    *,
    image: str = "blastbox-worker:latest",
    input_path: Path | None = None,
    output_dir: Path | None = None,
    worker_argv: list[str] | None = None,
    runtime: RuntimeSelection | None = None,
    container_name: str | None = None,
    labels: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    worker_uid: int = 10001,
    worker_gid: int = 10001,
    tmp_path: Path | None = None,
) -> list[str]:
    if tmp_path is None:
        tmp_path = Path("/tmp/test_job")
    if input_path is None:
        input_path = tmp_path / "input.docx"
    if output_dir is None:
        output_dir = tmp_path / "output"
    if worker_argv is None:
        worker_argv = ["worker", "run"]
    if runtime is None:
        runtime = RuntimeSelection(runtime="runsc", secure=True, warnings=[])
    return build_worker_docker_run_argv(
        image=image,
        input_path=input_path,
        input_mount_path="/job/input",
        output_dir=output_dir,
        output_mount_path="/job/output",
        worker_argv=worker_argv,
        runtime=runtime,
        container_name=container_name,
        labels=labels,
        extra_env=extra_env,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
    )


# ---------------------------------------------------------------------------
# InsecureRuntimeRefused is a SandboxError
# ---------------------------------------------------------------------------

def test_insecure_runtime_refused_is_sandbox_error():
    e = InsecureRuntimeRefused("test")
    assert isinstance(e, SandboxError)
    assert isinstance(e, Exception)


# ---------------------------------------------------------------------------
# select_worker_runtime — runtime selection logic
# ---------------------------------------------------------------------------

def test_select_runsc_when_available(monkeypatch):
    """runsc in detected set → RuntimeSelection(runtime='runsc', secure=True)."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    sel = select_worker_runtime(available_runtimes=["runsc", "runc"])
    assert sel.runtime == "runsc"
    assert sel.secure is True
    assert sel.warnings == []


def test_select_runc_refused_by_default(monkeypatch):
    """Only runc available + NO opt-in → fail-closed (InsecureRuntimeRefused) early."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_ALLOW_RUNC", raising=False)
    with pytest.raises(InsecureRuntimeRefused, match="BLASTBOX_ALLOW_RUNC"):
        select_worker_runtime(available_runtimes=["runc"])


def test_select_runc_allowed_with_explicit_opt_in(monkeypatch):
    """BLASTBOX_ALLOW_RUNC=1 → runc allowed in explicit degraded mode (insecure + warning)."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    monkeypatch.setenv("BLASTBOX_ALLOW_RUNC", "1")
    sel = select_worker_runtime(available_runtimes=["runc"])
    assert sel.runtime == "runc"
    assert sel.secure is False
    assert any("runsc" in w.lower() or "insecure" in w.lower() or "runc" in w.lower()
               for w in sel.warnings)


def test_require_secure_overrides_allow_runc(monkeypatch):
    """BLASTBOX_REQUIRE_SECURE_RUNTIME=1 is a hard lockdown — refuses runc EVEN with ALLOW_RUNC."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.setenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", "1")
    monkeypatch.setenv("BLASTBOX_ALLOW_RUNC", "1")
    with pytest.raises(InsecureRuntimeRefused, match="REQUIRE_SECURE_RUNTIME"):
        select_worker_runtime(available_runtimes=["runc"])


def test_fail_closed_empty_runtime_set_by_default(monkeypatch):
    """No runtimes detected + no opt-in → fail-closed (the dispatcher refuses early)."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_ALLOW_RUNC", raising=False)
    with pytest.raises(InsecureRuntimeRefused):
        select_worker_runtime(available_runtimes=[])


def test_force_runc_still_needs_opt_in(monkeypatch):
    """BLASTBOX_WORKER_RUNTIME=runc is an explicit runtime choice but still insecure — it
    requires the ALLOW_RUNC consent flag too (otherwise refused)."""
    monkeypatch.setenv("BLASTBOX_WORKER_RUNTIME", "runc")
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_ALLOW_RUNC", raising=False)
    with pytest.raises(InsecureRuntimeRefused):
        select_worker_runtime(available_runtimes=["runsc", "runc"])


def test_force_runc_with_opt_in(monkeypatch):
    """BLASTBOX_WORKER_RUNTIME=runc + BLASTBOX_ALLOW_RUNC=1 → runc (insecure, deliberate)."""
    monkeypatch.setenv("BLASTBOX_WORKER_RUNTIME", "runc")
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    monkeypatch.setenv("BLASTBOX_ALLOW_RUNC", "1")
    sel = select_worker_runtime(available_runtimes=["runsc", "runc"])
    assert sel.runtime == "runc"
    assert sel.secure is False


def test_force_runsc_via_env(monkeypatch):
    """BLASTBOX_WORKER_RUNTIME=runsc forces runsc even without detection."""
    monkeypatch.setenv("BLASTBOX_WORKER_RUNTIME", "runsc")
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    sel = select_worker_runtime(available_runtimes=["runc"])  # no runsc detected
    assert sel.runtime == "runsc"
    assert sel.secure is True


def test_require_secure_satisfied_by_runsc(monkeypatch):
    """BLASTBOX_REQUIRE_SECURE_RUNTIME=1 + runsc available → selects runsc, no exception."""
    monkeypatch.setenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", "1")
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    sel = select_worker_runtime(available_runtimes=["runsc", "runc"])
    assert sel.runtime == "runsc"
    assert sel.secure is True


def test_allow_runc_falsy_values_still_refuse(monkeypatch):
    """BLASTBOX_ALLOW_RUNC=0/false/no/empty → NOT opted in → still fail-closed under runc."""
    monkeypatch.delenv("BLASTBOX_WORKER_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
    for falsy in ("0", "false", "False", "no", ""):
        monkeypatch.setenv("BLASTBOX_ALLOW_RUNC", falsy)
        with pytest.raises(InsecureRuntimeRefused):
            select_worker_runtime(available_runtimes=["runc"])


def test_selection_is_frozen():
    """RuntimeSelection must be a frozen dataclass (immutable)."""
    sel = RuntimeSelection(runtime="runsc", secure=True, warnings=[])
    with pytest.raises((AttributeError, TypeError)):
        sel.runtime = "runc"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# build_worker_docker_run_argv — argv shape and security properties
# ---------------------------------------------------------------------------

def test_argv_is_list_of_str(tmp_path):
    """argv must be list[str] — not a string, never shell=True fodder."""
    argv = _argv(tmp_path=tmp_path)
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)


def test_argv_starts_with_docker_run(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert argv[0] == "docker"
    assert argv[1] == "run"


def test_rm_flag_present(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--rm" in argv


def test_network_none_present(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--network=none" in argv


def test_cap_drop_all_present(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--cap-drop=ALL" in argv


def test_security_opt_no_new_privileges_present(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--security-opt=no-new-privileges" in argv


def test_read_only_present(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--read-only" in argv


def test_runtime_flag_present(tmp_path):
    argv = _argv(tmp_path=tmp_path, runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]))
    assert "--runtime=runsc" in argv


def test_runtime_flag_runc(tmp_path):
    argv = _argv(tmp_path=tmp_path, runtime=RuntimeSelection(runtime="runc", secure=False, warnings=[]))
    assert "--runtime=runc" in argv


def test_warn_on_insecure_set_under_runsc(tmp_path):
    argv = _argv(tmp_path=tmp_path, runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]))
    assert "BLASTBOX_WARN_ON_INSECURE=1" in argv


def test_warn_on_insecure_set_under_opted_in_runc(tmp_path):
    """An insecure (runc) RuntimeSelection -> the worker is told to run its self-check in
    DELIBERATE degraded mode (this selection is only produced after BLASTBOX_ALLOW_RUNC),
    so it doesn't abort opaquely instead of failing cleanly at dispatch time."""
    argv = _argv(
        tmp_path=tmp_path,
        runtime=RuntimeSelection(runtime="runc", secure=False, warnings=["insecure"]),
    )
    assert "BLASTBOX_WARN_ON_INSECURE=1" in argv


def test_user_flag_present(tmp_path):
    argv = _argv(tmp_path=tmp_path, worker_uid=10001, worker_gid=10001)
    assert "--user" in argv
    uid_idx = argv.index("--user")
    assert argv[uid_idx + 1] == "10001:10001"


def test_memory_and_swap_present(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_MEMORY", raising=False)
    argv = _argv(tmp_path=tmp_path)
    assert "--memory" in argv
    assert "--memory-swap" in argv
    # swap == memory (disable swap)
    mem_idx = argv.index("--memory")
    swap_idx = argv.index("--memory-swap")
    assert argv[mem_idx + 1] == argv[swap_idx + 1]


def test_pids_limit_present(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_PIDS_LIMIT", raising=False)
    argv = _argv(tmp_path=tmp_path)
    assert "--pids-limit" in argv


def test_cpus_present(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_CPUS", raising=False)
    argv = _argv(tmp_path=tmp_path)
    assert "--cpus" in argv


def test_ulimit_nofile_present(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_NOFILE", raising=False)
    argv = _argv(tmp_path=tmp_path)
    assert "--ulimit" in argv
    ulimit_idx = argv.index("--ulimit")
    assert argv[ulimit_idx + 1].startswith("nofile=")


def test_tmpfs_nosuid_noexec(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--tmpfs" in argv
    tmpfs_idx = argv.index("--tmpfs")
    val = argv[tmpfs_idx + 1]
    assert "nosuid" in val
    assert "noexec" in val


def test_input_mount_is_readonly(tmp_path):
    """Input bind-mount must end with :ro or include readonly."""
    input_path = tmp_path / "input.docx"
    argv = build_worker_docker_run_argv(
        image="img",
        input_path=input_path,
        input_mount_path="/job/input",
        output_dir=tmp_path / "out",
        output_mount_path="/job/output",
        worker_argv=["worker"],
        runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]),
    )
    # find the --mount token for input
    for i, tok in enumerate(argv):
        if tok == "--mount" and "input" in argv[i + 1]:
            assert "readonly" in argv[i + 1]
            break
    else:
        pytest.fail("No --mount token found for input mount")


def test_output_mount_is_readwrite(tmp_path):
    """Output bind-mount must NOT have readonly."""
    argv = build_worker_docker_run_argv(
        image="img",
        input_path=tmp_path / "input.docx",
        input_mount_path="/job/input",
        output_dir=tmp_path / "out",
        output_mount_path="/job/output",
        worker_argv=["worker"],
        runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]),
    )
    # Match on the mount destination path to avoid false-positives when
    # tmp_path itself contains the word "output" (pytest names the tmpdir
    # after the test function).
    for i, tok in enumerate(argv):
        if tok == "--mount" and "dst=/job/output" in argv[i + 1]:
            assert "readonly" not in argv[i + 1]
            break
    else:
        pytest.fail("No --mount token found for output mount")


def test_image_at_end_before_worker_argv(tmp_path):
    """Image name must appear after all docker flags, immediately before worker_argv."""
    img = "myrepo/blastbox-worker:v1.2.3"
    wa = ["run", "--job-id", "abc123"]
    argv = _argv(image=img, worker_argv=wa, tmp_path=tmp_path)
    img_idx = argv.index(img)
    # everything after image is worker_argv
    assert argv[img_idx + 1 :] == wa


def test_worker_argv_appended(tmp_path):
    wa = ["run", "--job-id", "xyz"]
    argv = _argv(worker_argv=wa, tmp_path=tmp_path)
    assert argv[-len(wa) :] == wa


# ---------------------------------------------------------------------------
# No flag-injection via caller-controlled values
# ---------------------------------------------------------------------------

def test_extra_env_injection_is_single_token(tmp_path):
    """extra_env value containing '; --privileged' stays as ONE token, not a new flag."""
    malicious_value = "V; --privileged"
    argv = _argv(extra_env={"K": malicious_value}, tmp_path=tmp_path)
    # The combined token must appear as a single element
    assert "-e" in argv
    # Find the -e token for K
    combined = None
    for i, tok in enumerate(argv):
        if tok == "-e" and argv[i + 1].startswith("K="):
            combined = argv[i + 1]
            break
    assert combined is not None, "Expected -e K=... token"
    assert combined == f"K={malicious_value}"
    # --privileged must NOT appear as a standalone argv element
    assert "--privileged" not in argv


def test_extra_env_newline_injection_is_single_token(tmp_path):
    """A newline in an env value cannot split into a new argv element."""
    argv = _argv(extra_env={"FOO": "bar\n--privileged"}, tmp_path=tmp_path)
    assert "--privileged" not in argv


def test_image_with_shell_metachars_is_single_token(tmp_path):
    """An image name with shell metacharacters stays as a single value position."""
    evil_image = "img; rm -rf /"
    argv = _argv(image=evil_image, tmp_path=tmp_path)
    # image must appear exactly as given, as a single element
    assert evil_image in argv
    # 'rm' and '-rf' must NOT be standalone elements
    assert "rm" not in argv
    assert "-rf" not in argv


def test_container_name_with_metachars_is_single_token(tmp_path):
    """container_name with shell metachars stays as a value, not a flag."""
    name = "job; --privileged"
    argv = _argv(container_name=name, tmp_path=tmp_path)
    # --name val must be the single combined string
    name_idx = argv.index("--name")
    assert argv[name_idx + 1] == name
    assert "--privileged" not in argv


def test_label_injection_is_single_token(tmp_path):
    """label value cannot inject new flags."""
    argv = _argv(labels={"job": "x; --privileged"}, tmp_path=tmp_path)
    assert "--privileged" not in argv


def test_no_shell_true_in_argv(tmp_path):
    """Sanity: argv never contains 'sh', '-c', 'bash', or 'shell=True' strings."""
    argv = _argv(tmp_path=tmp_path)
    for tok in argv:
        assert tok not in ("sh", "bash", "-c", "shell=True")


# ---------------------------------------------------------------------------
# gVisor / runc warn-on-insecure env propagation
# ---------------------------------------------------------------------------

def test_runsc_sets_warn_on_insecure_env(tmp_path):
    """Under runsc, BLASTBOX_WARN_ON_INSECURE=1 must be in argv."""
    argv = _argv(
        runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]),
        tmp_path=tmp_path,
    )
    # Find -e BLASTBOX_WARN_ON_INSECURE=...
    for i, tok in enumerate(argv):
        if tok == "-e" and argv[i + 1].startswith("BLASTBOX_WARN_ON_INSECURE="):
            assert argv[i + 1] == "BLASTBOX_WARN_ON_INSECURE=1"
            break
    else:
        pytest.fail("BLASTBOX_WARN_ON_INSECURE not set in argv for runsc")


def test_runc_sets_warn_on_insecure_for_deliberate_degraded_mode(tmp_path, monkeypatch):
    """POLICY: an insecure (runc) RuntimeSelection now SETS BLASTBOX_WARN_ON_INSECURE=1.

    runc is only reachable after the operator's explicit BLASTBOX_ALLOW_RUNC opt-in
    (select_worker_runtime refuses it otherwise), so the worker runs its sandbox self-check
    in DELIBERATE degraded mode rather than aborting opaquely. The honest insecurity is
    surfaced by the RuntimeSelection.warnings, not by silently killing the worker."""
    monkeypatch.delenv("BLASTBOX_WARN_ON_INSECURE", raising=False)
    argv = _argv(
        runtime=RuntimeSelection(runtime="runc", secure=False, warnings=[]),
        tmp_path=tmp_path,
    )
    assert "BLASTBOX_WARN_ON_INSECURE=1" in argv


# ---------------------------------------------------------------------------
# Resource caps — env override works
# ---------------------------------------------------------------------------

def test_worker_memory_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_MEMORY", "2g")
    argv = _argv(tmp_path=tmp_path)
    mem_idx = argv.index("--memory")
    assert argv[mem_idx + 1] == "2g"


def test_worker_pids_limit_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_PIDS_LIMIT", "128")
    argv = _argv(tmp_path=tmp_path)
    pids_idx = argv.index("--pids-limit")
    assert argv[pids_idx + 1] == "128"


def test_worker_cpus_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_CPUS", "2.0")
    argv = _argv(tmp_path=tmp_path)
    cpus_idx = argv.index("--cpus")
    assert argv[cpus_idx + 1] == "2.0"


def test_worker_nofile_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_NOFILE", "8192")
    argv = _argv(tmp_path=tmp_path)
    ulimit_idx = argv.index("--ulimit")
    assert argv[ulimit_idx + 1] == "nofile=8192:8192"


@pytest.mark.parametrize("blank", ["", "   ", "\t", " \n "])
def test_worker_caps_blank_env_use_defaults(tmp_path, monkeypatch, blank):
    """docker-compose passes ``BLASTBOX_WORKER_MEMORY=${BLASTBOX_WORKER_MEMORY:-}`` which sets the
    var to the EMPTY string when the operator leaves it unset. ``get(K, default)`` returns that ""
    (the key exists) → a bare ``--memory '' --cpus '' --pids-limit ''`` that makes ``docker run``
    fail at launch with ``invalid argument "" for "--memory"`` (RC 125). Set-but-empty AND
    set-but-whitespace-only (a malformed env file) MUST fall back to the default exactly like
    unset — and no empty/whitespace token may ever land in a value position."""
    for var in (
        "BLASTBOX_WORKER_MEMORY",
        "BLASTBOX_WORKER_PIDS_LIMIT",
        "BLASTBOX_WORKER_CPUS",
        "BLASTBOX_WORKER_NOFILE",
    ):
        monkeypatch.setenv(var, blank)
    argv = _argv(tmp_path=tmp_path)
    assert argv[argv.index("--memory") + 1] == "4g"
    assert argv[argv.index("--memory-swap") + 1] == "4g"
    assert argv[argv.index("--pids-limit") + 1] == "256"
    assert argv[argv.index("--cpus") + 1] == "1.0"
    assert argv[argv.index("--ulimit") + 1] == "nofile=4096:4096"
    assert "" not in argv  # no empty value in any position
    assert blank not in argv  # the raw blank value never lands in a value position


# ---------------------------------------------------------------------------
# seccomp / apparmor optional attachment
# ---------------------------------------------------------------------------

def test_missing_seccomp_host_path_records_warning_not_failure(tmp_path, monkeypatch):
    """If BLASTBOX_SECCOMP_JSON_HOST is unset, argv builds OK + warning recorded."""
    monkeypatch.delenv("BLASTBOX_SECCOMP_JSON_HOST", raising=False)
    runtime = RuntimeSelection(runtime="runsc", secure=True, warnings=[])
    argv = build_worker_docker_run_argv(
        image="img",
        input_path=tmp_path / "in",
        input_mount_path="/job/input",
        output_dir=tmp_path / "out",
        output_mount_path="/job/output",
        worker_argv=["run"],
        runtime=runtime,
    )
    assert isinstance(argv, list)
    # No seccomp= in argv
    assert not any("seccomp=" in a for a in argv)
    # Warning recorded
    assert any("seccomp" in w.lower() for w in runtime.warnings)


def test_seccomp_host_path_attached_when_set(tmp_path, monkeypatch):
    """If BLASTBOX_SECCOMP_JSON_HOST is set, --security-opt seccomp=<path> appears."""
    monkeypatch.setenv("BLASTBOX_SECCOMP_JSON_HOST", "/host/path/seccomp.json")
    monkeypatch.delenv("BLASTBOX_APPARMOR_PROFILES", raising=False)
    runtime = RuntimeSelection(runtime="runsc", secure=True, warnings=[])
    argv = build_worker_docker_run_argv(
        image="img",
        input_path=tmp_path / "in",
        input_mount_path="/job/input",
        output_dir=tmp_path / "out",
        output_mount_path="/job/output",
        worker_argv=["run"],
        runtime=runtime,
    )
    # --security-opt seccomp=/host/path/seccomp.json must be in argv
    found = False
    for i, tok in enumerate(argv):
        if tok == "--security-opt" and argv[i + 1].startswith("seccomp="):
            assert argv[i + 1] == "seccomp=/host/path/seccomp.json"
            found = True
            break
    assert found, "seccomp security-opt not found in argv"


# ---------------------------------------------------------------------------
# extra_env and labels are fully propagated
# ---------------------------------------------------------------------------

def test_extra_env_propagated(tmp_path):
    argv = _argv(extra_env={"MY_VAR": "my_val", "ANOTHER": "123"}, tmp_path=tmp_path)
    assert "-e" in argv
    e_values = {argv[i + 1] for i, t in enumerate(argv) if t == "-e"}
    assert "MY_VAR=my_val" in e_values
    assert "ANOTHER=123" in e_values


def test_labels_propagated(tmp_path):
    argv = _argv(labels={"job_id": "abc", "engine": "soffice"}, tmp_path=tmp_path)
    assert "--label" in argv
    label_values = {argv[i + 1] for i, t in enumerate(argv) if t == "--label"}
    assert "job_id=abc" in label_values
    assert "engine=soffice" in label_values


def test_container_name_propagated(tmp_path):
    argv = _argv(container_name="worker-abc123", tmp_path=tmp_path)
    assert "--name" in argv
    name_idx = argv.index("--name")
    assert argv[name_idx + 1] == "worker-abc123"


def test_no_container_name_when_none(tmp_path):
    argv = _argv(container_name=None, tmp_path=tmp_path)
    assert "--name" not in argv


# ---------------------------------------------------------------------------
# workdir
# ---------------------------------------------------------------------------

def test_workdir_defaults_to_tmp(tmp_path):
    argv = _argv(tmp_path=tmp_path)
    assert "--workdir" in argv
    wd_idx = argv.index("--workdir")
    assert argv[wd_idx + 1] == "/tmp"


def test_workdir_custom(tmp_path):
    argv = build_worker_docker_run_argv(
        image="img",
        input_path=tmp_path / "in",
        input_mount_path="/job/input",
        output_dir=tmp_path / "out",
        output_mount_path="/job/output",
        worker_argv=["run"],
        runtime=RuntimeSelection(runtime="runsc", secure=True, warnings=[]),
        workdir="/workspace",
    )
    wd_idx = argv.index("--workdir")
    assert argv[wd_idx + 1] == "/workspace"


# ---------------------------------------------------------------------------
# Optional outer nono (Landlock) wrap of the worker command (cold path)
# ---------------------------------------------------------------------------

def _runc():
    return RuntimeSelection(runtime="runc", secure=False, warnings=[])


def _runsc():
    return RuntimeSelection(runtime="runsc", secure=True, warnings=[])


def test_nono_wrap_off_by_default(monkeypatch):
    monkeypatch.delenv("BLASTBOX_WORKER_NONO_WRAP", raising=False)
    argv = _argv(worker_argv=["blastbox", "worker"], runtime=_runc())
    assert argv[-2:] == ["blastbox", "worker"]          # verbatim, no wrap
    assert "nono" not in " ".join(argv)
    assert "/run/nono" not in " ".join(argv)


def test_nono_wrap_on_under_runc(monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_NONO_WRAP", "1")
    monkeypatch.delenv("BLASTBOX_WORKER_NONO_PROFILE", raising=False)
    monkeypatch.delenv("BLASTBOX_WORKER_NONO_BIN", raising=False)
    argv = _argv(worker_argv=["blastbox", "worker"], runtime=_runc())
    # dedicated off-grant state tmpfs added
    assert "--tmpfs" in argv and any("/run/nono:rw" in a for a in argv)
    # worker command wrapped: env HOME=/run/nono nono wrap ... -- env HOME=/tmp blastbox worker
    assert "/usr/local/bin/nono" in argv and "wrap" in argv and "--block-net" in argv
    assert "HOME=/run/nono" in argv and "HOME=/tmp" in argv
    assert argv[-2:] == ["blastbox", "worker"]           # real worker still the tail
    # baseline grants present (read system dirs, write /tmp + output + dev)
    assert "-r" in argv and "/usr" in argv
    assert argv[argv.index("/job/output") - 1] == "-a"


def test_nono_wrap_skipped_under_runsc(monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_NONO_WRAP", "1")
    rt = _runsc()
    argv = _argv(worker_argv=["blastbox", "worker"], runtime=rt)
    assert "nono" not in " ".join(argv)                  # ENOSYS on gVisor -> skipped
    assert argv[-2:] == ["blastbox", "worker"]
    assert any("Landlock" in w for w in rt.warnings)     # and warned


def test_nono_wrap_with_profile(monkeypatch):
    monkeypatch.setenv("BLASTBOX_WORKER_NONO_WRAP", "1")
    monkeypatch.setenv("BLASTBOX_WORKER_NONO_PROFILE", "/etc/blastbox/worker.nono.json")
    argv = _argv(worker_argv=["blastbox", "worker"], runtime=_runc())
    assert "-p" in argv and "/etc/blastbox/worker.nono.json" in argv
    assert "/usr" not in argv                            # profile replaces the baseline grants
