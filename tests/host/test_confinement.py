"""Host-LSM detection for the confinement tier (detection/reporting only; nothing enforces).

Every distro is a fixture of the /sys files it actually exposes, so the suite means the same
thing on any machine: no test reads the real /sys or spawns a real binary.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from blastbox.host import attest
from blastbox.host import confinement as cf
from blastbox.host import preflight as pf
from blastbox.host.preflight import Status
from tests.host.test_preflight import FakeHost, _healthy

# --- distro fixtures: what /sys looks like -------------------------------------------------

UBUNTU = {  # 24.04: AppArmor on, Landlock stacked; dispatcher unconfined (systemd, root)
    "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,ima,evm",
    "/sys/module/apparmor/parameters/enabled": "Y\n",
    "/proc/self/attr/apparmor/current": "unconfined\n",
}
ROCKY = {  # Rocky/RHEL 9: SELinux enforcing
    "/sys/kernel/security/lsm": "lockdown,capability,yama,selinux,bpf,landlock",
    "/sys/fs/selinux/enforce": "1",
}
AL2023 = {  # Amazon Linux 2023 ships SELinux permissive
    "/sys/kernel/security/lsm": "lockdown,capability,yama,selinux,bpf,landlock",
    "/sys/fs/selinux/enforce": "0",
}
ALPINE = {  # no major LSM; Landlock only
    "/sys/kernel/security/lsm": "capability,landlock,yama",
}
ALPINE_BARE = {  # no LSM stack worth the name, no Landlock
    "/sys/kernel/security/lsm": "capability",
}
CONTAINER = {  # securityfs not mounted; /sys/module still visible read-only
    "/sys/module/apparmor/parameters/enabled": "Y\n",
}


_REAL_DETECT = cf.detect


def _host(files: dict[str, str], **kw) -> FakeHost:
    return FakeHost(files=dict(files), **kw)


def _state(files, abi=0) -> cf.HostLsm:
    return cf.probe(_host(files), env={}, landlock=abi)


# --- probe --------------------------------------------------------------------------------

def test_ubuntu_apparmor():
    st = _state(UBUNTU, abi=6)
    assert (st.apparmor, st.selinux, st.landlock_abi) == (True, "absent", 6)
    assert st.would_use("gvisor") == st.would_use("firecracker") == "apparmor"


def test_rocky_selinux_enforcing_beats_everything():
    st = _state(ROCKY, abi=4)
    assert st.selinux == "enforcing" and not st.apparmor
    assert st.would_use("gvisor") == st.would_use("firecracker") == "selinux"


def test_al2023_permissive_selinux_is_not_usable():
    st = _state(AL2023, abi=4)
    assert st.selinux == "permissive"
    assert st.would_use("gvisor") == "none"            # runsc mounts: Landlock cannot hold it
    assert st.would_use("firecracker") == "landlock"


def test_alpine_landlock_only_covers_firecracker():
    st = _state(ALPINE, abi=3)
    assert (st.apparmor, st.selinux) == (False, "absent")
    assert st.would_use("gvisor") == "none" and st.would_use("firecracker") == "landlock"


def test_listed_without_landlock_ignores_the_syscall():
    assert _state(ALPINE_BARE, abi=5).landlock_abi == 0


def test_container_without_securityfs_degrades():
    st = _state(CONTAINER, abi=2)
    assert st.lsms is None
    assert st.apparmor and st.selinux == "unknown" and st.landlock_abi == 2
    assert st.would_use("gvisor") == "none"              # host's flag; nothing loadable here
    assert st.would_use("firecracker") == "landlock"


def test_nothing_readable_is_none_not_an_error():
    st = _state({})
    assert (st.lsms, st.apparmor, st.selinux, st.landlock_abi) == (None, False, "unknown", 0)
    assert st.would_use("firecracker") == "none"


def test_apparmor_module_disabled_at_boot():
    st = _state({**UBUNTU, "/sys/module/apparmor/parameters/enabled": "N\n"})
    assert not st.apparmor


def test_apparmor_param_but_not_in_stack():
    st = _state({"/sys/kernel/security/lsm": "capability,landlock",
                 "/sys/module/apparmor/parameters/enabled": "Y\n"})
    assert not st.apparmor


def test_off_mode_uses_nothing():
    assert _state(ROCKY).would_use("gvisor", "off") == "none"


@pytest.mark.parametrize("raw,mode", [(None, "auto"), ("", "auto"), (" Require ", "require"),
                                      ("off", "off")])
def test_mode_parse(raw, mode):
    assert cf.parse_mode(raw) == mode


def test_mode_typo_is_an_error_not_off():
    with pytest.raises(ValueError, match="BLASTBOX_CONFINEMENT"):
        cf.parse_mode("of")


def test_kinds_for_tiers():
    assert cf.kinds_for_tiers({"cold"}) == ["gvisor"]
    assert cf.kinds_for_tiers({"docker", "firecracker"}) == ["gvisor", "firecracker"]
    assert cf.kinds_for_tiers({"aws-ec2", "remote"}) == []


def test_require_fails_closed_only_for_unmet_kinds():
    st = _state(ALPINE, abi=3)
    cf.check_required(st, "require", ["firecracker"])
    with pytest.raises(cf.ConfinementUnavailable, match="gvisor"):
        cf.check_required(st, "require", ["gvisor", "firecracker"])
    cf.check_required(st, "auto", ["gvisor"])           # auto never raises


def test_detect_never_spawns(monkeypatch):
    """The production reader and the real Landlock query: no process is ever started."""
    def boom(*a, **kw):
        raise AssertionError("spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(cf.os, "posix_spawn", boom, raising=False)
    d = cf.detect({"BLASTBOX_CONFINEMENT": "auto"})
    assert d.state.runsc is None and d.state.apparmor_parser is None
    assert set(d.receipt("gvisor") or {}) == {"mode", "available", "applied"}


def test_detect_with_fixture_host():
    d = cf.detect({"BLASTBOX_CONFINEMENT": "auto"}, host=_host(ROCKY), landlock=0)
    assert d.receipt("gvisor") == {"mode": "auto", "available": "selinux", "applied": "none"}


def test_landlock_abi_is_a_harmless_int():
    assert isinstance(cf.landlock_abi(), int) and cf.landlock_abi() >= 0


# --- tools ---------------------------------------------------------------------------------

def _tools(files, *, runsc="runsc version release-20261012.0\n", parser="4.0.1", extra=()):
    return FakeHost(
        files=dict(files), paths=set(extra),
        executables={"runsc": "/usr/bin/runsc", "apparmor_parser": "/usr/sbin/apparmor_parser",
                     "firecracker": "/usr/local/bin/firecracker"},
        commands={("/usr/bin/runsc", "--version"): (0, runsc, ""),
                  ("/usr/sbin/apparmor_parser", "--version"):
                      (0, f"AppArmor parser version {parser}\nCopyright (C) ...\n", "")})


def test_runsc_split_sentry_by_release():
    new = cf.probe(_tools(UBUNTU), env={}, kinds=["gvisor"])
    old = cf.probe(_tools(UBUNTU, runsc="runsc version release-20251110.0\n"), env={},
                   kinds=["gvisor"])
    assert (new.runsc, new.runsc_split_sentry) == ("release-20261012.0", True)
    assert (old.runsc, old.runsc_split_sentry) == ("release-20251110.0", False)


def test_runsc_split_sentry_by_sibling_binary():
    st = cf.probe(_tools(UBUNTU, runsc="runsc version ???\n",
                         extra={"/usr/bin/gvisor-bin/gvisor_sentry"}), env={}, kinds=["gvisor"])
    assert st.runsc_split_sentry is True


def test_runsc_unknown_layout():
    st = cf.probe(_tools(UBUNTU, runsc="weird\n"), env={}, kinds=["gvisor"])
    assert st.runsc == "weird" and st.runsc_split_sentry is None


def test_parser_4_0_1_is_flagged_only_with_apparmor_on():
    assert cf.probe(_tools(UBUNTU), env={}, kinds=["gvisor"]).flags == [
        "apparmor-parser-4.0.1-audit-deny-umount-allows-mount"]
    assert cf.probe(_tools(UBUNTU, parser="4.1.0"), env={}, kinds=["gvisor"]).flags == []
    assert cf.probe(_tools(ROCKY), env={}, kinds=["gvisor"]).apparmor_parser is None


def test_firecracker_and_jailer_presence():
    host = _tools(ALPINE)
    st = cf.probe(host, env={}, kinds=["firecracker"])
    assert (st.firecracker, st.jailer) == ("/usr/local/bin/firecracker", None)
    host.executables["jailer"] = "/usr/local/bin/jailer"
    assert cf.probe(host, env={}, kinds=["firecracker"]).jailer == "/usr/local/bin/jailer"
    assert ("/usr/local/bin/firecracker", "--version") not in host.ran   # presence only


def test_no_kinds_no_spawn():
    host = _tools(UBUNTU)
    cf.probe(host, env={})
    assert host.ran == []


# --- preflight ----------------------------------------------------------------------------

def _pf(files, *, env=None, abi=0, tiers=("docker", "gvisor", "firecracker"), commands=None):
    host = _healthy(files=files, env=env or {}, commands=commands or {})
    host.landlock_abi = lambda: abi    # type: ignore[method-assign]
    return next(c for c in pf.run_preflight(host, list(tiers)) if c.name == "confinement")


def test_preflight_ubuntu_reports_would_use():
    c = _pf(UBUNTU, abi=6)
    assert c.status is Status.PASS
    assert "would use: gvisor=apparmor, firecracker=apparmor" in c.detail
    assert "nothing enforced" in c.detail
    assert c.facts is not None and c.facts["enforced"] is False


def test_preflight_al2023_permissive():
    c = _pf(AL2023, abi=4)
    assert c.status is Status.PASS and "selinux=permissive" in c.detail
    assert "gvisor=none" in c.detail and "firecracker=landlock" in c.detail


def test_preflight_require_fails_where_unmet():
    c = _pf(AL2023, abi=4, env={"BLASTBOX_CONFINEMENT": "require"})
    assert c.status is Status.FAIL and "require unmet for gvisor" in c.detail
    # --tier firecracker still reaches the cold fallback (gVisor) unless warm-only
    cold = _pf(AL2023, abi=4, env={"BLASTBOX_CONFINEMENT": "require"}, tiers=("firecracker",))
    assert cold.status is Status.FAIL and "gvisor" in cold.detail
    ok = _pf(AL2023, abi=4, env={"BLASTBOX_CONFINEMENT": "require",
                                 "BLASTBOX_DISPATCH_WARM_ONLY": "1"}, tiers=("firecracker",))
    assert ok.status is Status.PASS


def test_preflight_require_on_rocky_passes():
    assert _pf(ROCKY, env={"BLASTBOX_CONFINEMENT": "require"}).status is Status.PASS


def test_preflight_bad_mode_fails():
    c = _pf(UBUNTU, env={"BLASTBOX_CONFINEMENT": "yes"})
    assert c.status is Status.FAIL and "refuses to start" in c.detail


def test_preflight_container_without_securityfs():
    c = _pf(CONTAINER)
    assert c.status is Status.PASS and "securityfs not readable" in c.detail
    assert "lsm=unknown" in c.detail


def test_preflight_flags_parser_4_0_1():
    host = _healthy(files=UBUNTU, commands={("/usr/sbin/apparmor_parser", "--version"):
                                            (0, "AppArmor parser version 4.0.1\n", "")})
    host.executables["apparmor_parser"] = "/usr/sbin/apparmor_parser"
    c = next(c for c in pf.run_preflight(host, ["gvisor"]) if c.name == "confinement")
    assert c.status is Status.WARN and "ALLOW mount" in c.detail
    assert c.facts is not None
    assert c.facts["host"]["flags"] == [  # type: ignore[index]
        "apparmor-parser-4.0.1-audit-deny-umount-allows-mount"]


def test_preflight_remote_only_reports_no_local_kind():
    host = _healthy(files=UBUNTU)
    c = next(c for c in pf.run_preflight(host, ["remote"]) if c.name == "confinement")
    assert c.status is Status.PASS and "would use" not in c.detail


def test_preflight_json_carries_facts():
    host = _healthy(files=ROCKY)
    checks = pf.run_preflight(host, ["gvisor"])
    out = json.loads(pf.render_json(checks, ["gvisor"]))
    row = next(r for r in out["checks"] if r["name"] == "confinement")
    assert row["facts"]["would_use"] == {"gvisor": "selinux"}
    assert all("facts" not in r for r in out["checks"] if r["name"] != "confinement")


def test_preflight_spawns_only_read_only_queries():
    host = _healthy(files=UBUNTU)
    host.executables["apparmor_parser"] = "/usr/sbin/apparmor_parser"
    pf.run_preflight(host, ["docker", "gvisor", "firecracker"])
    assert all(pf.is_read_only(argv) for argv in host.ran)


# --- receipts -----------------------------------------------------------------------------

def test_receipt_carries_confinement_and_omits_when_absent():
    obs = dict(job_id="j", engine="e", input_sha256="a" * 64, worker_runtime="runsc",
               worker_tier=None, started_at_ms=1, finished_at_ms=2)
    plain = attest.build_receipt(attest.RunObservation(**obs), key_id="k" * 16,
                                 metadata_sha256="c" * 64, host="h")
    assert "confinement" not in plain
    rec = {"mode": "auto", "available": "apparmor", "applied": "none"}
    doc = attest.build_receipt(attest.RunObservation(**obs, confinement=rec), key_id="k" * 16,
                               metadata_sha256="c" * 64, host="h")
    assert doc["confinement"] == rec
    attest.canonical(doc)    # no floats: signable


def _cold_receipt(tmp_path, runtime: str, confinement):
    from blastbox.host.dispatch import Dispatcher, EngineSpec, RuntimeSelection
    from blastbox.host.jobs.memory import InMemoryJobStore
    from tests.host.test_attest_dispatch import (
        _ENGINE_IMAGE,
        _ENGINE_NAME,
        _blobs,
        _limits,
        _queue,
        _receipt_path,
        _runner,
        _verify,
    )

    key = attest.load_or_create_key(tmp_path / "keys" / "attest.key")
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy="none")
    d = Dispatcher(
        job_store=store, engines={_ENGINE_NAME: eng}, limits=_limits(),
        job_root=tmp_path / "jobs",
        runtime_selector=lambda: RuntimeSelection(runtime=runtime, secure=runtime == "runsc",
                                                  warnings=[]),
        subprocess_runner=_runner(tmp_path, job), worker_timeout_s=30,
        blob_store=_blobs(tmp_path), put_output_max_attempts=1,
        put_output_retry_backoff_s=0.0, attest_key=key, confinement=confinement)
    assert d.dispatch_once() is True
    return _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))


@pytest.fixture
def _attest_env(monkeypatch):
    import os
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_") or k in (
                "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BLASTBOX_HOST_ID", "dispatch-host")


def test_cold_runsc_receipt_signs_detection(tmp_path, _attest_env):
    det = cf.detect({}, host=_host(UBUNTU), landlock=0)
    doc = _cold_receipt(tmp_path, "runsc", det)
    assert doc["confinement"] == {"mode": "auto", "available": "apparmor", "applied": "none"}


def test_cold_runc_receipt_has_no_confinement(tmp_path, _attest_env):
    det = cf.detect({}, host=_host(UBUNTU), landlock=0)
    assert "confinement" not in _cold_receipt(tmp_path, "runc", det)


def test_undetected_dispatcher_omits_confinement(tmp_path, _attest_env):
    assert "confinement" not in _cold_receipt(tmp_path, "runsc", None)


def test_warm_gvisor_receipt_signs_detection(tmp_path, _attest_env):
    from blastbox.host.dispatch import Dispatcher
    from blastbox.host.jobs.base import JobStatus
    from blastbox.host.jobs.memory import InMemoryJobStore
    from tests.host.test_attest_dispatch import (
        _ENGINE_NAME,
        _INPUT_SHA,
        _blobs,
        _limits,
        _queue,
        _receipt_path,
        _verify,
    )
    from tests.host.test_dispatch_warm import FakeWarmPool, _make_slot, _start_fake_worker
    from tests.host.test_dispatch_warm import _engine_spec as _warm_engine
    from tests.host.test_dispatch_warm import _fake_runtime as _warm_runtime
    from tests.host.test_dispatch_warm import _make_valid_output_dir as _warm_out

    key = attest.load_or_create_key(tmp_path / "keys" / "attest.key")
    store = InMemoryJobStore()
    job = _queue(tmp_path, store, net_policy="undeclared")
    slot = _make_slot(tmp_path)
    _start_fake_worker(slot, output_fn=lambda o: _warm_out(o, input_sha256=_INPUT_SHA))
    d = Dispatcher(
        job_store=store, engines={_ENGINE_NAME: _warm_engine()}, limits=_limits(),
        job_root=tmp_path / "jobs", runtime_selector=_warm_runtime,
        subprocess_runner=lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
        worker_timeout_s=10, pool=FakeWarmPool(slot), tier="gvisor",
        warm_claim_timeout_s=0.5, warm_requeue_backoff_s=0.0, blob_store=_blobs(tmp_path),
        attest_key=key, confinement=cf.detect({}, host=_host(AL2023), landlock=4))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    # permissive SELinux does not count, and Landlock cannot hold runsc
    assert doc["confinement"] == {"mode": "auto", "available": "none", "applied": "none"}


# --- dispatcher startup -------------------------------------------------------------------

class _Built(Exception):
    pass


def _start(monkeypatch, *, mode: str, files: dict[str, str]):
    """Drive `blastbox dispatch` (cold) up to Dispatcher construction; return its kwargs."""
    import argparse

    import blastbox.host.dispatch as dispatch_mod
    import blastbox.host.jobs.factory as factory
    from blastbox.host.cli import _dispatch_cmd
    from blastbox.host.jobs.memory import InMemoryJobStore

    seen: dict = {}

    def fake(**kw):
        seen.update(kw)
        raise _Built

    monkeypatch.setattr(cf, "detect", lambda: _REAL_DETECT(
        {"BLASTBOX_CONFINEMENT": mode}, host=_host(files), landlock=3))
    monkeypatch.setattr(factory, "build_job_store_from_env", InMemoryJobStore)
    monkeypatch.setattr(dispatch_mod, "Dispatcher", fake)
    monkeypatch.delenv("BLASTBOX_POOL_RUNTIME", raising=False)
    monkeypatch.delenv("BLASTBOX_CLAIM_UNTARGETED_AFTER_S", raising=False)
    with pytest.raises(_Built):
        _dispatch_cmd(argparse.Namespace(engines="e=img:tag"))
    return seen


def test_dispatch_cmd_passes_detection(monkeypatch):
    det = _start(monkeypatch, mode="auto", files=UBUNTU)["confinement"]
    assert det.receipt("gvisor")["available"] == "apparmor"


def test_dispatch_cmd_require_refuses_cold_on_landlock_only_host(monkeypatch):
    with pytest.raises(cf.ConfinementUnavailable, match="gvisor"):
        _start(monkeypatch, mode="require", files=ALPINE)


def test_dispatch_cmd_require_starts_where_met(monkeypatch):
    assert _start(monkeypatch, mode="require", files=ROCKY)["confinement"].mode == "require"


def test_dispatch_cmd_invalid_mode_refuses(monkeypatch):
    import argparse

    from blastbox.host.cli import _dispatch_cmd
    monkeypatch.setenv("BLASTBOX_CONFINEMENT", "enforce")
    monkeypatch.delenv("BLASTBOX_POOL_RUNTIME", raising=False)
    import blastbox.host.jobs.factory as factory
    from blastbox.host.jobs.memory import InMemoryJobStore
    monkeypatch.setattr(factory, "build_job_store_from_env", InMemoryJobStore)
    with pytest.raises(ValueError, match="BLASTBOX_CONFINEMENT"):
        _dispatch_cmd(argparse.Namespace(engines="e=img:tag"))


# --- round 1 review fixes -----------------------------------------------------------------

CONTAINER_UNDER_DOCKER_DEFAULT = {   # Ubuntu host, dispatcher inside a docker container
    "/sys/module/apparmor/parameters/enabled": "Y\n",
    "/proc/self/attr/apparmor/current": "docker-default (enforce)\n",
}
SELINUX_RO_CONTAINER = {   # Rocky host, container with selinuxfs bind-mounted read-only
    "/sys/fs/selinux/enforce": "1",
    "/proc/self/mounts": "overlay / overlay rw 0 0\nselinuxfs /sys/fs/selinux selinuxfs "
                         "ro,nosuid,nodev,noexec,relatime 0 0\n",
}


def test_apparmor_without_securityfs_is_not_usable():
    st = _state(CONTAINER, abi=0)
    assert st.apparmor and st.apparmor_blocker
    assert st.would_use("gvisor") == "none"
    assert cf.unmet(st, "require", ["gvisor"]) == ["gvisor"]


def test_apparmor_confined_caller_is_not_usable():
    files = {**UBUNTU, "/proc/self/attr/apparmor/current": "docker-default (enforce)\n"}
    st = _state(files)
    assert "docker-default" in (st.apparmor_blocker or "")
    assert st.would_use("firecracker") == "none"
    assert _state(CONTAINER_UNDER_DOCKER_DEFAULT).would_use("gvisor") == "none"


def test_apparmor_unconfined_caller_is_usable():
    st = _state({**UBUNTU, "/proc/self/attr/apparmor/current": "unconfined\n"})
    assert st.apparmor_blocker is None and st.would_use("gvisor") == "apparmor"


def test_read_only_selinuxfs_is_not_usable():
    st = _state(SELINUX_RO_CONTAINER, abi=4)
    assert st.selinux == "enforcing" and st.selinux_blocker
    assert st.would_use("gvisor") == "none" and st.would_use("firecracker") == "landlock"


def test_rw_selinuxfs_is_usable():
    files = {**ROCKY, "/proc/self/mounts": "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n"}
    assert _state(files).would_use("gvisor") == "selinux"


def test_preflight_names_the_blocker():
    c = _pf(CONTAINER)
    assert "gvisor=none" in c.detail and "securityfs" in c.detail


def test_preflight_notes_missing_apparmor_parser():
    c = _pf(UBUNTU)    # the healthy host has no apparmor_parser
    assert "apparmor_parser not found" in c.detail


def test_off_mode_omits_the_receipt_field():
    d = cf.detect({"BLASTBOX_CONFINEMENT": "off"}, host=_host(UBUNTU), landlock=0)
    assert d.receipt("gvisor") is None


def test_preflight_validates_mode_on_remote_only():
    host = _healthy(files=UBUNTU, env={"BLASTBOX_CONFINEMENT": "enforce"})
    c = next(c for c in pf.run_preflight(host, ["remote"]) if c.name == "confinement")
    assert c.status is Status.FAIL


def _embedded(tmp_path, monkeypatch, mode: str, files: dict[str, str]):
    from blastbox.host.dispatch import Dispatcher, EngineSpec
    from blastbox.host.jobs.memory import InMemoryJobStore
    from tests.host.test_dispatch import _fake_runtime, _limits

    monkeypatch.setattr(cf, "detect", lambda env=None, **kw: _REAL_DETECT(
        env, host=_host(files), landlock=3))
    monkeypatch.setenv("BLASTBOX_CONFINEMENT", mode)
    return Dispatcher(job_store=InMemoryJobStore(),
                      engines={"e": EngineSpec(name="e", image="i", worker_argv=["w"])},
                      limits=_limits(), job_root=tmp_path, runtime_selector=_fake_runtime,
                      attest_key=None)


def test_embedded_dispatcher_honours_require(tmp_path, monkeypatch):
    with pytest.raises(cf.ConfinementUnavailable):
        _embedded(tmp_path, monkeypatch, "require", ALPINE)
    _embedded(tmp_path, monkeypatch, "require", ROCKY)


def test_embedded_dispatcher_refuses_invalid_mode(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="BLASTBOX_CONFINEMENT"):
        _embedded(tmp_path, monkeypatch, "requird", ROCKY)


def test_verify_cli_prints_confinement(capsys):
    from blastbox.client import verify as v
    from blastbox.client.cli import _print_human
    r = v.VerifiedReceipt(
        job_id="j", engine="e", status="done", key_id="k", host="h", executor="local",
        input_sha256="a" * 64, metadata_sha256="b" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2, issued_at_ms=3, network=None,
        input_bound=False, metadata_bound=True, signed={},
        confinement=v.AttestedConfinement("auto", "apparmor", "none"))
    _print_human(r)
    out = capsys.readouterr().out
    assert "confinement" in out and "apparmor" in out
    _print_human(v.VerifiedReceipt(**{**r.__dict__, "confinement": None}))
    assert "NOT RECORDED" in capsys.readouterr().out


def test_landlock_query_is_linux_only(monkeypatch):
    monkeypatch.setattr(cf.sys, "platform", "darwin")
    def no_libc(*a, **kw):
        raise AssertionError("syscall attempted off Linux")
    monkeypatch.setattr(cf.ctypes, "CDLL", no_libc)
    assert cf.landlock_abi() == 0


def test_selinux_unknown_without_securityfs_or_selinuxfs():
    st = _state({})
    assert st.selinux == "unknown" and st.would_use("gvisor") == "none"
    assert _state(ALPINE).selinux == "absent"     # listed stack without selinux: known absent


def test_parser_warn_names_the_shipped_profile():
    host = _healthy(files=UBUNTU, commands={("/usr/sbin/apparmor_parser", "--version"):
                                            (0, "AppArmor parser version 4.0.1\n", "")})
    host.executables["apparmor_parser"] = "/usr/sbin/apparmor_parser"
    c = next(c for c in pf.run_preflight(host, ["gvisor"]) if c.name == "confinement")
    assert "deploy/apparmor/blastbox-sandbox" in c.detail


def test_runsc_version_failure_is_not_not_found():
    host = _tools(UBUNTU)
    del host.commands[("/usr/bin/runsc", "--version")]
    st = cf.probe(host, env={}, kinds=["gvisor"])
    assert st.runsc == "present (--version failed)" and st.runsc_split_sentry is None


def test_runsc_empty_env_means_no_binary_like_the_runtime():
    st = cf.probe(_tools(UBUNTU), env={"BLASTBOX_GVISOR_RUNSC": ""}, kinds=["gvisor"])
    assert st.runsc is None


def test_verified_signed_does_not_share_the_callers_confinement(tmp_path):
    from blastbox.client import verify as v
    from tests.client.test_verify import _body, _doc, _verify
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    pinned = v.load_pinned_keys(key.public_key_pem)
    body = json.loads(_body(key, _doc(key, net={"confinement": {
        "mode": "auto", "available": "none", "applied": "none"}})))
    r = _verify(body, pinned)
    body["attestation"]["confinement"]["available"] = "selinux"
    assert r.signed["confinement"]["available"] == "none"   # type: ignore[index]
    json.dumps(dict(r.signed))     # the signed view stays JSON-serialisable


def test_unreadable_apparmor_label_is_a_blocker():
    st = _state({k: v for k, v in UBUNTU.items() if not k.startswith("/proc/")})
    assert st.apparmor_blocker and "label" in st.apparmor_blocker
    assert st.would_use("gvisor") == "none"


def test_non_apparmor_shaped_attr_current_is_a_blocker():
    st = _state({**{k: v for k, v in UBUNTU.items() if not k.startswith("/proc/")},
                 "/proc/self/attr/current": "system_u:system_r:unconfined_t:s0"})
    assert st.would_use("gvisor") == "none"


def test_legacy_attr_current_unconfined_is_usable():
    assert _state({**{k: v for k, v in UBUNTU.items() if not k.startswith("/proc/")},
                   "/proc/self/attr/current": "unconfined\n"}).would_use(
        "gvisor") == "apparmor"


@pytest.mark.parametrize("label,usable", [
    ("unconfined", True), ("vscode (unconfined)", True), ("snap.astral-uv.uv (complain)", True),
    ("docker-default (enforce)", False), ("x (kill)", False), ("x (user)", False),
])
def test_label_mode_not_name_decides(label, usable):
    st = _state({**UBUNTU, "/proc/self/attr/apparmor/current": label + "\n"})
    assert (st.would_use("gvisor") == "apparmor") is usable
    assert pf._is_unconfined(label) is usable      # agrees with sandbox-confinement's reading


def test_listed_selinux_without_selinuxfs_is_unknown_not_absent():
    st = _state({"/sys/kernel/security/lsm": "lockdown,capability,yama,selinux,bpf,landlock"})
    assert st.selinux == "unknown" and st.would_use("gvisor") == "none"


def test_require_unmet_only_by_an_overflow_tier_is_a_warn():
    env = {"BLASTBOX_CONFINEMENT": "require", "BLASTBOX_POOL_RUNTIME": "cascade",
           "BLASTBOX_POOL_TIERS": "firecracker:4,gvisor:2", "BLASTBOX_DISPATCH_WARM_ONLY": "1"}
    c = _pf(AL2023, abi=4, env=env, tiers=("gvisor", "firecracker"))
    assert c.status is Status.WARN and "overflow" in c.detail


def test_preflight_says_whose_context_it_judged():
    assert "as seen by this process" in _pf(UBUNTU).detail
