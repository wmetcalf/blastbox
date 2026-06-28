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
        self.released: list[bool] = []   # dirty flag per release
        self.retired: list[str] = []     # slot_ids force-retired (hung path)

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
    assert pool.claimed == 1 and pool.released == [False]   # clean → reuse (not dirty)


def test_slot_bound_validate_ok_false_releases_dirty():
    pool = _FakePool()
    v = slot_bound_validate(pool, lambda slot, p: ({}, False))
    assert v("/in") == ({}, False)
    assert pool.released == [True]                          # ok=False → force-recycle


def test_slot_bound_validate_run_raises_releases_dirty():
    pool = _FakePool()

    def boom(slot, p):
        raise RuntimeError("agent died")

    v = slot_bound_validate(pool, boom)
    with pytest.raises(RuntimeError, match="agent died"):
        v("/in")
    assert pool.released == [True]                          # raised → force-recycle, slot returned


def test_slot_bound_validate_hung_run_reclaims_slot():
    import threading
    pool = _FakePool()
    gate = threading.Event()

    def hang(slot, p):
        gate.wait(timeout=10)        # blocks past the tiny work_timeout below
        return ({}, True)

    v = slot_bound_validate(pool, hang, work_timeout_s=0.2)
    with pytest.raises(TimeoutError, match="exceeded"):
        v("/in")
    # hung thread still alive → slot must be RETIRED (VM destroyed), NOT recycled+reused (which would
    # let the abandoned thread corrupt a later job's worker).
    assert pool.retired == [pool._slot.slot_id] and pool.released == []
    gate.set()                                              # let the abandoned daemon thread finish


def test_slot_bound_validate_no_slot_raises():
    pool = _FakePool(slot=None)
    pool._slot = None                                       # claim returns None
    v = slot_bound_validate(pool, lambda slot, p: ({}, True), claim_timeout_s=0.1)
    with pytest.raises(RuntimeError, match="no warm VM slot"):
        v("/in")
    assert pool.released == []                              # nothing claimed → nothing to release


def test_build_image_qemu_removes_partial_first_build(monkeypatch, tmp_path):
    # a FAILED first qemu build must delete the partial golden, else a later build_image(force=False)
    # would return the half-provisioned image as if valid.
    import blastbox.host.runtime.vm_compose as mod
    g = tmp_path / "g.qcow2"   # does not exist at start (first build)
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["qemu-img", "create"]:
            g.write_text("partial")     # create produced the file...
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict("auth", {
        "image": {"golden": str(g), "builder": "qemu", "base_qcow2": "/b.qcow2",
                  "provisioners": ["false"]},   # ...but the provisioner (real `false`) fails
    })
    with pytest.raises(RuntimeError):
        spec.build_image()
    assert ["rm", "-f", str(g), str(g) + ".flat"] in calls       # partial first-build golden removed


def test_build_image_packer_removes_partial_first_build(monkeypatch, tmp_path):
    # a FAILED first packer build must delete the partial golden (parity with the qemu first build).
    import blastbox.host.runtime.vm_compose as mod
    g = tmp_path / "g.qcow2"   # does not exist (first build)
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["packer", "build"]:
            g.write_text("partial")          # packer created it...
            raise RuntimeError("packer then failed")
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict("auth", {
        "image": {"golden": str(g), "builder": "packer", "packer_template": "/t.pkr.hcl"},
    })
    with pytest.raises(RuntimeError):
        spec.build_image()
    assert ["rm", "-f", str(g)] in calls         # partial first-build golden removed


def test_build_image_packer_restores_golden_on_failed_forced_rebuild(monkeypatch, tmp_path):
    # a forced packer rebuild that fails must restore the previous working golden, not destroy it.
    import blastbox.host.runtime.vm_compose as mod
    g = tmp_path / "g.qcow2"
    g.write_text("old-working")            # existing golden → force rebuild
    calls = []

    def fake_run(args, check=False):
        calls.append(args)
        if args[:2] == ["packer", "build"]:
            raise RuntimeError("packer failed")
        return type("C", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(mod, "_run", fake_run)
    spec = VmWorkerSpec.from_dict("auth", {
        "image": {"golden": str(g), "builder": "packer", "packer_template": "/t.pkr.hcl"},
    })
    with pytest.raises(RuntimeError):
        spec.build_image(force=True)
    assert ["mv", str(g), str(g) + ".prev"] in calls       # moved aside before the build
    assert ["mv", str(g) + ".prev", str(g)] in calls       # restored after the failure


def test_build_image_packer_requires_golden(monkeypatch, tmp_path):
    # parity with the qemu branch: a packer template that exits 0 but doesn't produce image.golden
    # must fail at build time, not return a missing/stale path that the pool trips over later.
    import blastbox.host.runtime.vm_compose as mod

    class _OK:
        returncode = 0
        stdout = ""
        stderr = ""
    monkeypatch.setattr(mod, "_run", lambda *a, **k: _OK())   # packer build "succeeds", writes nothing
    spec = VmWorkerSpec.from_dict("auth", {
        "image": {"golden": str(tmp_path / "missing.qcow2"), "builder": "packer",
                  "packer_template": "/t.pkr.hcl"},
    })
    with pytest.raises(RuntimeError, match="packer build ran but"):
        spec.build_image()


def test_from_dict_rejects_malformed_block_internal():
    # a typo'd security knob (block_internal: "treu") must be REJECTED, not silently disabled.
    with pytest.raises(ValueError, match="boolean"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2",
                                     "egress": {"exit": "direct", "block_internal": "treu"}})


def test_from_dict_accepts_all_exit_routing_fields():
    # the unknown-key allowlist is DERIVED from ExitRouting's fields, so every valid routing knob
    # (incl. rule_priority_base, previously omitted) parses and threads through.
    spec = VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", "egress": {
        "exit": "openvpn", "rule_priority_base": 5000, "vpn_table": "vpn", "vpn_tun": "tun7"}})
    assert spec.routing.rule_priority_base == 5000
    assert spec.routing.vpn_table == "vpn" and spec.routing.vpn_tun == "tun7"


@pytest.mark.parametrize("badkey", ["egres", "rooting", "warmsize", "mem_md"])
def test_from_dict_rejects_unknown_top_level_key(badkey):
    # a misspelled SECURITY-critical top-level key (e.g. `egres:` instead of `egress:`) must be
    # REJECTED, not silently dropped → egress=None → VM on the unrestricted libvirt network.
    with pytest.raises(ValueError, match="unknown top-level key"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", badkey: "x"})


@pytest.mark.parametrize("badkey", ["exitt", "block_internl", "egress_port", "fakenet_address"])
def test_from_dict_rejects_unknown_egress_key(badkey):
    # a misspelled egress key must be REJECTED, not silently ignored → defaulting to direct/unblocked.
    with pytest.raises(ValueError, match="unknown egress key"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2",
                                     "egress": {"exit": "tor", badkey: "x"}})


@pytest.mark.parametrize("bad", [[], {}, ["x"]])
def test_from_dict_rejects_non_scalar_block_internal(bad):
    # a non-scalar YAML value (block_internal: [] / {}) must be REJECTED, not coerced via bool([])
    # =False — that would SILENTLY DISABLE the RFC1918/internal-destination block.
    with pytest.raises(ValueError, match="boolean"):
        VmWorkerSpec.from_dict("w", {"image": "/g.qcow2",
                                     "egress": {"exit": "direct", "block_internal": bad}})


def test_from_dict_rejects_non_mapping_egress():
    # a malformed egress block must NOT silently disable the per-worker firewall (egress=None).
    for bad in ("drop", ["drop"], 5):
        with pytest.raises(ValueError, match="egress"):
            VmWorkerSpec.from_dict("w", {"image": "/g.qcow2", "egress": bad})


def test_from_dict_coerces_quoted_gateway_masquerade():
    # a quoted YAML scalar "false" must disable SNAT, not stay a truthy string that installs MASQUERADE.
    spec = VmWorkerSpec.from_dict("auth", {
        "image": "/g.qcow2",
        "egress": {"exit": "openvpn", "gateway": "10.99.0.2", "leg": "br-r",
                   "gateway_masquerade": "false"},
    })
    assert spec.routing is not None and spec.routing.gateway_masquerade is False


def test_from_dict_threads_worker_cidr_into_routing():
    # non-/24 nets need ExitRouting.worker_cidr; the compose egress allowlist must not drop it.
    spec = VmWorkerSpec.from_dict("auth", {
        "image": "/g.qcow2",
        "egress": {"exit": "openvpn", "worker_cidr": "192.168.0.0/16", "vpn_tun": "tun0"},
    })
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
    spec = VmWorkerSpec.from_dict("w", {"image": "/g.qcow2",
                                        "egress": {"exit": "direct", "block_internal": "false"}})
    assert spec.egress.block_internal is False
    spec2 = VmWorkerSpec.from_dict("w", {"image": "/g.qcow2",
                                         "egress": {"exit": "direct", "block_internal": "true"}})
    assert spec2.egress.block_internal is True


def test_from_dict_parses_trust_anchors_and_guest_ssh():
    spec = VmWorkerSpec.from_dict("interceptor", {
        "image": "/g.qcow2",
        "trust_anchors": ["./fakenet_ca.crt"],
        "guest_os": "windows",
        "guest_ssh_user": "Administrator",
        "guest_ssh_key": "/home/x/.ssh/win_golden",
    })
    cfg = spec.to_vm_config()
    assert cfg.trust_anchors == ["./fakenet_ca.crt"]
    assert cfg.guest_ssh_user == "Administrator"
    assert cfg.guest_os == "windows"


def test_ports_accepts_single_int_and_rejects_bool():
    assert _ports(443) == (443,)            # a single port
    assert _ports("80,443") == (80, 443)
    assert _ports([80, 443]) == (80, 443)
    assert _ports(None) is None             # OMITTED → None (no allowlist)
    assert _ports(True) == ()               # a PROVIDED bool is malformed → fail closed, not open
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
    spec = VmWorkerSpec.from_dict("authenticode", {
        "image": "/g.qcow2", "mem_mb": 8192, "vcpus": 4, "warm_size": 3, "agent_port": 9000,
        "jobs_per_recycle": 10, "network": "cape-100",
        "egress": {"exit": "openvpn", "egress_ports": "53 80 443", "block_internal": True,
                   "vpn_table": "vpn", "gateway": "10.99.0.2", "leg": "br-r"}})
    assert spec.image.golden == "/g.qcow2" and spec.mem_mb == 8192 and spec.vcpus == 4
    assert spec.warm_size == 3 and spec.agent_port == 9000 and spec.network == "cape-100"
    assert spec.jobs_per_recycle == 10
    assert spec.egress.exit_driver == "openvpn" and spec.egress.egress_ports == (53, 80, 443)
    assert spec.egress.block_internal is True
    assert spec.routing.gateway == "10.99.0.2" and spec.routing.leg == "br-r" and spec.routing.vpn_table == "vpn"


def test_image_as_bare_path():
    spec = VmWorkerSpec.from_dict("x", {"image": "/g.qcow2"})
    assert spec.image.golden == "/g.qcow2" and spec.egress is None


def test_to_vm_config_threads_through():
    cfg = VmWorkerSpec(name="x", image=VmImageSpec(golden="/g"), mem_mb=2048, vcpus=1,
                       agent_port=8765, network="default").to_vm_config()
    assert cfg.golden_base == "/g" and cfg.mem_mb == 2048 and cfg.agent_port == 8765


def test_runtime_is_a_slotruntime_with_recycle():
    rt = VmWorkerSpec(name="x", image=VmImageSpec(golden="/g")).runtime()
    assert isinstance(rt, LibvirtVmRuntime) and isinstance(rt, SlotRuntime)
    assert hasattr(rt, "recycle")  # opts the VM tier into WarmPool reuse


def test_build_pool_jobs_per_recycle_override():
    spec = VmWorkerSpec(name="x", image=VmImageSpec(golden="/g"), jobs_per_recycle=5)
    assert spec.build_pool()._jobs_per_recycle == 5           # spec default
    assert spec.build_pool(jobs_per_recycle=25)._jobs_per_recycle == 25  # engine's declaration wins


def test_ports_parser():
    assert _ports("53 80 443") == (53, 80, 443)
    assert _ports("53,80,443") == (53, 80, 443)
    assert _ports([53, 80]) == (53, 80)
    assert _ports(None) is None


def test_build_image_needs_recipe():
    spec = VmWorkerSpec(name="x", image=VmImageSpec(golden="/no/such.qcow2", builder="qemu"))
    with pytest.raises(ValueError):  # qemu builder with no base_qcow2
        spec.build_image()
