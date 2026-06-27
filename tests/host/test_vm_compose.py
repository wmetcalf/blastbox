"""Unit tests for the declarative libvirt 'compose' layer (pure; no libvirt)."""
from __future__ import annotations

import pytest

from blastbox.host.pool import SlotRuntime
from blastbox.host.runtime.libvirt_vm import LibvirtVmRuntime
from blastbox.host.runtime.vm_compose import VmImageSpec, VmWorkerSpec, _ports, _run_provisioner


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
    assert _ports(True) is None             # YAML bool is not a port list
    assert _ports(None) is None
    # out-of-range / invalid tokens are range-filtered (not emitted as a broken --dports that would
    # reap every worker for the spec); a list that filters to nothing fails closed to None.
    assert _ports([80, 70000, 443]) == (80, 443)
    assert _ports("70000 99999") is None


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
