"""Unit tests for the declarative libvirt 'compose' layer (pure; no libvirt)."""

from __future__ import annotations

import pytest

from blastbox.host.pool import SlotRuntime
from blastbox.host.runtime.libvirt_vm import LibvirtVmRuntime
from blastbox.host.runtime.vm_compose import (
    VmImageSpec,
    VmWorkerSpec,
    _ports,
    _run_provisioner,
    slot_bound_validate,
)


class _FakeSlot:
    def __init__(self, sid: str = "slot-abcdef12") -> None:
        self.slot_id = sid


class _FakePool:
    """Minimal WarmPool double: records claim/release calls + the dirty flag."""

    def __init__(self, slot=None) -> None:
        self._slot = slot if slot is not None else _FakeSlot()
        self.claimed = 0
        self.released: list[bool] = []  # dirty flag per release
        self.retired: list[str] = []  # slot_ids force-retired (hung path)

    def claim(self, *, timeout_s):
        self.claimed += 1
        return self._slot

    def release(self, slot, *, dirty=False):
        self.released.append(dirty)

    def retire(self, slot):
        self.retired.append(slot.slot_id)


def test_slot_bound_validate_clean_run_releases_clean():
    pool = _FakePool()
    v = slot_bound_validate(pool, lambda slot, p: ({"k": 1}, True))
    summary, ok = v("/in")
    assert (summary, ok) == ({"k": 1}, True)
    assert pool.claimed == 1 and pool.released == [False]  # clean → reuse (not dirty)


def test_slot_bound_validate_ok_false_releases_dirty():
    pool = _FakePool()
    v = slot_bound_validate(pool, lambda slot, p: ({}, False))
    assert v("/in") == ({}, False)
    assert pool.released == [True]  # ok=False → force-recycle


def test_slot_bound_validate_run_raises_releases_dirty():
    pool = _FakePool()

    def boom(slot, p):
        raise RuntimeError("agent died")

    v = slot_bound_validate(pool, boom)
    with pytest.raises(RuntimeError, match="agent died"):
        v("/in")
    assert pool.released == [True]  # raised → force-recycle, slot returned


def test_slot_bound_validate_hung_run_reclaims_slot():
    import threading

    pool = _FakePool()
    gate = threading.Event()

    def hang(slot, p):
        gate.wait(timeout=10)  # blocks past the tiny work_timeout below
        return ({}, True)

    v = slot_bound_validate(pool, hang, work_timeout_s=0.2)
    with pytest.raises(TimeoutError, match="exceeded"):
        v("/in")
    # hung thread still alive → slot must be RETIRED (VM destroyed), NOT recycled+reused (which would
    # let the abandoned thread corrupt a later job's worker).
    assert pool.retired == [pool._slot.slot_id] and pool.released == []
    gate.set()  # let the abandoned daemon thread finish


def test_slot_bound_validate_no_slot_raises():
    pool = _FakePool(slot=None)
    pool._slot = None  # claim returns None
    v = slot_bound_validate(pool, lambda slot, p: ({}, True), claim_timeout_s=0.1)
    with pytest.raises(RuntimeError, match="no warm VM slot"):
        v("/in")
    assert pool.released == []  # nothing claimed → nothing to release


def test_build_image_qemu_removes_partial_first_build(monkeypatch, tmp_path):
    # a FAILED first qemu build must delete the partial golden, else a later build_image(force=False)
    # would return the half-provisioned image as if valid.
    import blastbox.host.runtime.vm_compose as mod

    g = tmp_path / "g.qcow2"  # does not exist at start (first build)
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["qemu-img", "create"]:
            g.write_text("partial")  # create produced the file...
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": {
                "golden": str(g),
                "builder": "qemu",
                "base_qcow2": "/b.qcow2",
                "provisioners": ["false"],
            },  # ...but the provisioner (real `false`) fails
        },
    )
    with pytest.raises(RuntimeError):
        spec.build_image()
    assert [
        "rm",
        "-f",
        str(g),
        str(g) + ".flat",
    ] in calls  # partial first-build golden removed


def test_build_image_packer_removes_partial_first_build(monkeypatch, tmp_path):
    # a FAILED first packer build must delete the partial golden (parity with the qemu first build).
    import blastbox.host.runtime.vm_compose as mod

    g = tmp_path / "g.qcow2"  # does not exist (first build)
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["packer", "build"]:
            g.write_text("partial")  # packer created it...
            raise RuntimeError("packer then failed")
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": {
                "golden": str(g),
                "builder": "packer",
                "packer_template": "/t.pkr.hcl",
            },
        },
    )
    with pytest.raises(RuntimeError):
        spec.build_image()
    assert ["rm", "-f", str(g)] in calls  # partial first-build golden removed


def test_build_image_packer_restores_golden_on_failed_forced_rebuild(
    monkeypatch, tmp_path
):
    # a forced packer rebuild that fails must restore the previous working golden, not destroy it.
    import blastbox.host.runtime.vm_compose as mod

    g = tmp_path / "g.qcow2"
    g.write_text("old-working")  # existing golden → force rebuild
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["packer", "build"]:
            raise RuntimeError("packer failed")
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": {
                "golden": str(g),
                "builder": "packer",
                "packer_template": "/t.pkr.hcl",
            },
        },
    )
    with pytest.raises(RuntimeError):
        spec.build_image(force=True)
    assert ["mv", str(g), str(g) + ".prev"] in calls  # moved aside before the build
    assert ["mv", str(g) + ".prev", str(g)] in calls  # restored after the failure


def test_build_image_packer_requires_golden(monkeypatch, tmp_path):
    # parity with the qemu branch: a packer template that exits 0 but doesn't produce image.golden
    # must fail at build time, not return a missing/stale path that the pool trips over later.
    import blastbox.host.runtime.vm_compose as mod

    class _OK:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        mod, "_run", lambda *a, **k: _OK()
    )  # packer build "succeeds", writes nothing
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": {
                "golden": str(tmp_path / "missing.qcow2"),
                "builder": "packer",
                "packer_template": "/t.pkr.hcl",
            },
        },
    )
    with pytest.raises(RuntimeError, match="packer build ran but"):
        spec.build_image()


def test_from_dict_rejects_malformed_block_internal():
    # a typo'd security knob (block_internal: "treu") must be REJECTED, not silently disabled.
    with pytest.raises(ValueError, match="boolean"):
        VmWorkerSpec.from_dict(
            "w",
            {
                "image": "/g.qcow2",
                "egress": {"exit": "direct", "block_internal": "treu"},
            },
        )


@pytest.mark.parametrize(
    "key", ["nwfilter", "nwfilter_ip_learning", "worker_ip_pool", "mac_prefix"]
)
@pytest.mark.parametrize("bad", [None, False, True, 0, ["clean-traffic"]])
def test_from_dict_rejects_non_string_security_knob(key, bad):
    # `key:` (None) or `key: false` (bool) must be REJECTED, not read as falsy — a malformed
    # worker_ip_pool silently falls back to DHCP-learning (disables assign+enforce); a malformed
    # nwfilter drops the <filterref>. Fail closed on these security-sensitive fields.
    with pytest.raises(ValueError, match="must be a string"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", key: bad})


def test_from_dict_accepts_empty_string_nwfilter_as_disable():
    # the ONE disable sentinel is an explicit "" (not None/false)
    spec = VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", "nwfilter": ""})
    assert spec.nwfilter == ""


def test_nwfilter_threads_through_spec_to_vm_config():
    # the nwfilter + its IP-learning mode are configurable on the spec and flow to LibvirtVmConfig,
    # so a vmcompose deployment can tune/disable the anti-spoof filter (closes the config gap).
    spec = VmWorkerSpec.from_dict(
        "w",
        {
            "image": "/g.qcow2",
            "nwfilter": "no-mac-spoofing",
            "nwfilter_ip_learning": "any",
        },
    )
    assert spec.nwfilter == "no-mac-spoofing" and spec.nwfilter_ip_learning == "any"
    cfg = spec.to_vm_config()
    assert cfg.nwfilter == "no-mac-spoofing" and cfg.nwfilter_ip_learning == "any"
    # defaults: clean-traffic + dhcp learning
    dflt = VmWorkerSpec.from_dict("w", {"image": "/g.qcow2"}).to_vm_config()
    assert dflt.nwfilter == "clean-traffic" and dflt.nwfilter_ip_learning == "dhcp"


def test_assign_enforce_pool_threads_to_vm_config():
    # worker_ip_pool + mac_prefix flow from the spec to LibvirtVmConfig (opt-in assign+enforce).
    spec = VmWorkerSpec.from_dict(
        "w",
        {
            "image": "/g.qcow2",
            "worker_ip_pool": "192.168.122.200-192.168.122.250",
            "mac_prefix": "52:54:00:cc",
        },
    )
    cfg = spec.to_vm_config()
    assert (
        cfg.worker_ip_pool == "192.168.122.200-192.168.122.250"
        and cfg.mac_prefix == "52:54:00:cc"
    )
    # default: no pool (DHCP-learning mode)
    assert (
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2"}).to_vm_config().worker_ip_pool
        == ""
    )
    # dhcp_server threads through too
    cfg2 = VmWorkerSpec.from_dict(
        "w", {"image": "/g.qcow2", "dhcp_server": "10.0.0.1"}
    ).to_vm_config()
    assert cfg2.dhcp_server == "10.0.0.1"


def test_from_dict_accepts_all_exit_routing_fields():
    # the unknown-key allowlist is DERIVED from ExitRouting's fields, so every valid routing knob
    # (incl. rule_priority_base, previously omitted) parses and threads through.
    spec = VmWorkerSpec.from_dict(
        "w",
        {
            "image": "/g.qcow2",
            "egress": {
                "exit": "openvpn",
                "rule_priority_base": 5000,
                "vpn_table": "vpn",
                "vpn_tun": "tun7",
            },
        },
    )
    assert spec.routing.rule_priority_base == 5000
    assert spec.routing.vpn_table == "vpn" and spec.routing.vpn_tun == "tun7"


@pytest.mark.parametrize("badkey", ["egres", "rooting", "warmsize", "mem_md"])
def test_from_dict_rejects_unknown_top_level_key(badkey):
    # a misspelled SECURITY-critical top-level key (e.g. `egres:` instead of `egress:`) must be
    # REJECTED, not silently dropped → egress=None → VM on the unrestricted libvirt network.
    with pytest.raises(ValueError, match="unknown top-level key"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", badkey: "x"})


@pytest.mark.parametrize(
    "badkey", ["exitt", "block_internl", "egress_port", "fakenet_address"]
)
def test_from_dict_rejects_unknown_egress_key(badkey):
    # a misspelled egress key must be REJECTED, not silently ignored → defaulting to direct/unblocked.
    with pytest.raises(ValueError, match="unknown egress key"):
        VmWorkerSpec.from_dict(
            "w", {"image": "/g.qcow2", "egress": {"exit": "tor", badkey: "x"}}
        )


@pytest.mark.parametrize("bad", [[], {}, ["x"]])
def test_from_dict_rejects_non_scalar_block_internal(bad):
    # a non-scalar YAML value (block_internal: [] / {}) must be REJECTED, not coerced via bool([])
    # =False — that would SILENTLY DISABLE the RFC1918/internal-destination block.
    with pytest.raises(ValueError, match="boolean"):
        VmWorkerSpec.from_dict(
            "w",
            {"image": "/g.qcow2", "egress": {"exit": "direct", "block_internal": bad}},
        )


def test_from_dict_rejects_non_mapping_egress():
    # a malformed egress block must NOT silently disable the per-worker firewall (egress=None).
    for bad in ("drop", ["drop"], 5):
        with pytest.raises(ValueError, match="egress"):
            VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", "egress": bad})


def test_from_dict_coerces_quoted_gateway_masquerade():
    # a quoted YAML scalar "false" must disable SNAT, not stay a truthy string that installs MASQUERADE.
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": "/g.qcow2",
            "egress": {
                "exit": "openvpn",
                "gateway": "10.99.0.2",
                "leg": "br-r",
                "gateway_masquerade": "false",
            },
        },
    )
    assert spec.routing is not None and spec.routing.gateway_masquerade is False


def test_from_dict_threads_worker_cidr_into_routing():
    # non-/24 nets need ExitRouting.worker_cidr; the compose egress allowlist must not drop it.
    spec = VmWorkerSpec.from_dict(
        "auth",
        {
            "image": "/g.qcow2",
            "egress": {
                "exit": "openvpn",
                "worker_cidr": "192.168.0.0/16",
                "vpn_tun": "tun0",
            },
        },
    )
    assert spec.routing is not None and spec.routing.worker_cidr == "192.168.0.0/16"


def test_run_provisioner_string_runs_through_shell(tmp_path):
    # the spec documents provisioners as SHELL commands — && / redirection must work (argv-splitting
    # would silently drop everything after the && and leave an incomplete golden looking successful).
    marker = tmp_path / "ok"
    _run_provisioner(f"true && echo hi > {marker}")
    assert marker.read_text().strip() == "hi"


def test_run_provisioner_failure_fails_closed():
    with pytest.raises(RuntimeError, match="provisioner failed"):
        _run_provisioner("false && echo never-reached")


def test_run_provisioner_list_runs_as_argv():
    # list form is argv (no shell) — a successful argv command returns without raising
    _run_provisioner(["true"])
    with pytest.raises(RuntimeError, match="provisioner failed"):
        _run_provisioner(["false"])


def test_from_dict_block_internal_quoted_false_is_false():
    # A quoted YAML scalar "false" must not read as truthy.
    spec = VmWorkerSpec.from_dict(
        "w",
        {"image": "/g.qcow2", "egress": {"exit": "direct", "block_internal": "false"}},
    )
    assert spec.egress.block_internal is False
    spec2 = VmWorkerSpec.from_dict(
        "w",
        {"image": "/g.qcow2", "egress": {"exit": "direct", "block_internal": "true"}},
    )
    assert spec2.egress.block_internal is True


def test_from_dict_parses_trust_anchors_and_guest_ssh():
    spec = VmWorkerSpec.from_dict(
        "interceptor",
        {
            "image": "/g.qcow2",
            "trust_anchors": ["./fakenet_ca.crt"],
            "guest_os": "windows",
            "guest_ssh_user": "Administrator",
            "guest_ssh_key": "/home/x/.ssh/win_golden",
        },
    )
    cfg = spec.to_vm_config()
    assert cfg.trust_anchors == ["./fakenet_ca.crt"]
    assert cfg.guest_ssh_user == "Administrator"
    assert cfg.guest_os == "windows"


def test_ports_accepts_single_int_and_rejects_bool():
    assert _ports(443) == (443,)  # a single port
    assert _ports("80,443") == (80, 443)
    assert _ports([80, 443]) == (80, 443)
    assert _ports(None) is None  # OMITTED → None (no allowlist)
    assert _ports(True) == ()  # a PROVIDED bool is malformed → fail closed, not open
    assert _ports(False) == ()
    # out-of-range tokens are range-filtered; a partially-valid list keeps the valid ones.
    assert _ports([80, 70000, 443]) == (80, 443)
    # PROVIDED but ALL-invalid must FAIL CLOSED to () (drop everything), NOT None (which would widen
    # a web-only policy to unrestricted egress).
    assert _ports("70000 99999") == ()
    assert _ports([70000]) == ()
    # a PROVIDED but unsupported YAML type (e.g. a mapping) also fails closed to (), not None
    assert _ports({"http": 80}) == ()


def test_from_dict_builds_full_spec():
    spec = VmWorkerSpec.from_dict(
        "authenticode",
        {
            "image": "/g.qcow2",
            "mem_mb": 8192,
            "vcpus": 4,
            "warm_size": 3,
            "agent_port": 9000,
            "jobs_per_recycle": 10,
            "network": "cape-100",
            "egress": {
                "exit": "openvpn",
                "egress_ports": "53 80 443",
                "block_internal": True,
                "vpn_table": "vpn",
                "gateway": "10.99.0.2",
                "leg": "br-r",
            },
        },
    )
    assert spec.image.golden == "/g.qcow2" and spec.mem_mb == 8192 and spec.vcpus == 4
    assert (
        spec.warm_size == 3 and spec.agent_port == 9000 and spec.network == "cape-100"
    )
    assert spec.jobs_per_recycle == 10
    assert spec.egress.exit_driver == "openvpn" and spec.egress.egress_ports == (
        53,
        80,
        443,
    )
    assert spec.egress.block_internal is True
    assert (
        spec.routing.gateway == "10.99.0.2"
        and spec.routing.leg == "br-r"
        and spec.routing.vpn_table == "vpn"
    )


def test_image_as_bare_path():
    spec = VmWorkerSpec.from_dict("x", {"image": "/g.qcow2"})
    assert spec.image.golden == "/g.qcow2" and spec.egress is None


def test_to_vm_config_threads_through():
    cfg = VmWorkerSpec(
        name="x",
        image=VmImageSpec(golden="/g"),
        mem_mb=2048,
        vcpus=1,
        agent_port=8765,
        network="default",
    ).to_vm_config()
    assert cfg.golden_base == "/g" and cfg.mem_mb == 2048 and cfg.agent_port == 8765


def test_runtime_is_a_slotruntime_with_recycle():
    rt = VmWorkerSpec(name="x", image=VmImageSpec(golden="/g")).runtime()
    assert isinstance(rt, LibvirtVmRuntime) and isinstance(rt, SlotRuntime)
    assert hasattr(rt, "recycle")  # opts the VM tier into WarmPool reuse


def test_build_pool_jobs_per_recycle_override():
    spec = VmWorkerSpec(name="x", image=VmImageSpec(golden="/g"), jobs_per_recycle=5)
    assert spec.build_pool()._jobs_per_recycle == 5  # spec default
    assert (
        spec.build_pool(jobs_per_recycle=25)._jobs_per_recycle == 25
    )  # engine's declaration wins


def test_ports_parser():
    assert _ports("53 80 443") == (53, 80, 443)
    assert _ports("53,80,443") == (53, 80, 443)
    assert _ports([53, 80]) == (53, 80)
    assert _ports(None) is None


def test_build_image_needs_recipe():
    spec = VmWorkerSpec(
        name="x", image=VmImageSpec(golden="/no/such.qcow2", builder="qemu")
    )
    with pytest.raises(ValueError):  # qemu builder with no base_qcow2
        spec.build_image()


class _FaultPool(_FakePool):
    """A pool whose release() ACCEPTS attribution (the current WarmPool shape)."""

    def __init__(self, slot=None) -> None:
        super().__init__(slot)
        self.faults: list[str | None] = []

    def release(self, slot, *, dirty=False, fault=None):
        self.released.append(dirty)
        self.faults.append(fault)


def test_a_transport_failure_convicts_the_worker():
    """Releasing dirty with no fault leaves it 'unknown' — force-recycled, streak unmoved.

    A broken VM agent that fails every request was therefore snapshot-reverted and offered again
    indefinitely, never reaching burnout protection or a base rebuild.
    """
    import ssl

    pool = _FaultPool()

    def unreachable(slot, p):
        raise ssl.SSLError("worker TLS stack is broken")

    with pytest.raises(ssl.SSLError):
        slot_bound_validate(pool, unreachable)("/in")
    assert pool.released == [True]
    assert pool.faults == ["worker"], (
        "a transport failure is positive evidence the WORKER misbehaved; without it the wedge "
        "never advances toward eviction"
    )


def test_an_engine_verdict_on_the_sample_is_not_a_worker_fault():
    """ok=False means the engine RAN and judged the input.

    Convicting the worker there would burn out healthy slots on a run of malformed samples -- and
    leaving it UNATTRIBUTED is not enough either: unknown preserves both streaks, so a transport
    failure on either side of a successful run counted as consecutive. A completed run is
    positive proof the VM is responsive, so it must RESET them.
    """
    pool = _FaultPool()
    assert slot_bound_validate(pool, lambda slot, p: ({}, False))("/in") == ({}, False)
    assert pool.released == [True] and pool.faults == ["job"]


def test_an_ambiguous_exception_stays_unattributed():
    """Positive-evidence conviction: anything that isn't demonstrably the worker fails OPEN."""
    pool = _FaultPool()

    def boom(slot, p):
        raise ValueError("engine could not parse this sample")

    with pytest.raises(ValueError):
        slot_bound_validate(pool, boom)("/in")
    assert pool.released == [True] and pool.faults == [None]


def test_attribution_degrades_on_a_pool_that_predates_it():
    """_FakePool.release() takes no fault=; the seam must drop it, not raise TypeError and leak
    the slot (that ladder-of-except-TypeError bug is why release_kwargs exists)."""
    import ssl

    pool = _FakePool()

    def unreachable(slot, p):
        raise ssl.SSLError("broken")

    with pytest.raises(ssl.SSLError):
        slot_bound_validate(pool, unreachable)("/in")
    assert pool.released == [True]  # still released, just unattributed


def test_an_http_rejection_is_not_a_worker_fault():
    """HTTPError subclasses URLError, so a 4xx looked identical to an unreachable box.

    The remote_http transport learned that 413 (sample over the agent's own max_bytes), 401/403
    (token skew) and 404 (version skew) are verdicts on the REQUEST — and fail identically on
    every box. Its sibling here did not, so repeated rejections advanced burnout and base
    rebuilding against perfectly healthy slots.
    """
    import io as _io
    import urllib.error

    for code in (400, 401, 403, 404, 413, 422):
        pool = _FaultPool()

        def rejected(slot, p, _c=code):
            raise urllib.error.HTTPError(
                "https://vm.invalid/x", _c, "rejected", {}, _io.BytesIO(b"{}")
            )

        with pytest.raises(urllib.error.HTTPError):
            slot_bound_validate(pool, rejected)("/in")
        assert pool.faults == ["job"], (
            f"HTTP {code} must RESET the streaks, not merely avoid incrementing them: the agent "
            f"answered, so it and its base are demonstrably responsive (got {pool.faults})"
        )


def test_a_5xx_from_the_vm_agent_is_still_a_worker_fault():
    """The carve-out stays narrow: the agent itself breaking IS about this box."""
    import io as _io
    import urllib.error

    for code in (500, 502, 503):
        pool = _FaultPool()

        def broken(slot, p, _c=code):
            raise urllib.error.HTTPError(
                "https://vm.invalid/x", _c, "boom", {}, _io.BytesIO(b"{}")
            )

        with pytest.raises(urllib.error.HTTPError):
            slot_bound_validate(pool, broken)("/in")
        assert pool.faults == ["worker"], (
            f"HTTP {code} is the agent failing, not our request"
        )


def test_a_hung_agent_is_attributed_even_though_the_slot_is_retired():
    """The work thread is still alive after work_timeout_s — a wedged VM agent.

    Retiring recorded nothing, so if every VM restored from a poisoned snapshot hangs, each is
    destroyed and replaced from that SAME snapshot forever and the base-rebuild protection is
    never reached. The hard retire must stay: the abandoned thread may still be talking to this
    VM, so it must not be recycled and re-offered.
    """
    import threading

    class _RetirePool(_FaultPool):
        def __init__(self) -> None:
            super().__init__()
            self.retire_faults: list[str | None] = []

        def retire(self, slot, *, fault=None):
            self.retired.append(slot.slot_id)
            self.retire_faults.append(fault)

    pool = _RetirePool()
    started = threading.Event()

    def hangs(slot, p):
        started.set()
        threading.Event().wait(5.0)  # never returns within the work timeout

    with pytest.raises(TimeoutError):
        slot_bound_validate(pool, hangs, work_timeout_s=0.05)("/in")

    assert pool.retired, "sanity: the hung slot was hard-retired"
    assert pool.retire_faults == ["worker"], (
        f"a wedged agent recorded no evidence (got {pool.retire_faults}) -- a poisoned snapshot "
        f"that hangs every VM would be rebuilt into forever"
    )
    assert pool.released == [], "a hung slot must NOT be released for reuse"
