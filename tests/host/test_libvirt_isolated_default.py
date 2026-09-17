"""A libvirt VM that declares no egress must not be able to reach the internet.

TWO DEFAULTS CONSPIRED. `VmConfig.network` was `"default"` — libvirt's shipped network,
which is `<forward mode='nat'/>` and has working internet — and `egress_policy` was None,
whose own docstring read "worker reaches whatever the libvirt network allows". Neither
was wrong alone, which is why nothing caught the pairing: a VmConfig specifying nothing
put a malware VM on NAT with no host-side rules.

The default is now libvirt's isolated idiom (a <network> with no <forward> element). But
a default is a wish — a config file, an env var or a caller overrides it silently — so the
control is the spawn-time check that reads what the guest will ACTUALLY attach to.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig as VmConfig, LibvirtVmRuntime as VmRuntime

ISOLATED = "<network><name>bb-isolated</name><bridge name='bb-virbr0'/></network>"
NAT = ("<network><name>default</name><forward mode='nat'/>"
       "<bridge name='virbr0'/></network>")


def _runtime(monkeypatch, *, xml=ISOLATED, rc=0, stderr="", egress_policy=None, network=None):
    cfg = VmConfig(golden_base="/nonexistent/golden.qcow2",
                   egress_policy=egress_policy,
                   **({"network": network} if network else {}))
    rt = VmRuntime(cfg)

    def fake_virsh(*args, **kw):
        return subprocess.CompletedProcess(list(args), rc, xml if rc == 0 else "", stderr)

    monkeypatch.setattr(rt, "_virsh", fake_virsh)
    return rt


# --------------------------------------------------------------------- the default

def test_the_default_network_is_not_libvirts_forwarding_one():
    assert VmConfig(golden_base="/x").network != "default", (
        "libvirt's `default` network is <forward mode='nat'/> — it has internet"
    )
    assert VmConfig(golden_base="/x").network == "bb-isolated"


def test_the_shipped_network_definition_does_not_forward():
    """The other half of the fix, and the half a reviewer is most likely to 'tidy' by
    adding a forward element so the guests can reach updates."""
    import xml.etree.ElementTree as ET

    path = Path(__file__).resolve().parents[2] / "deploy/libvirt/bb-isolated.xml"
    root = ET.parse(path).getroot()
    assert root.findtext("name") == "bb-isolated"
    assert root.findall("forward") == [], (
        "bb-isolated has grown a <forward> element; that is the entire property it "
        "exists to have, and adding one gives every unpoliced VM worker internet"
    )


# --------------------------------------------------------------------- the control

def test_an_unpoliced_vm_is_refused_on_a_forwarding_network(monkeypatch):
    rt = _runtime(monkeypatch, xml=NAT, network="default")
    with pytest.raises(RuntimeError, match="reaches the physical network"):
        rt._assert_egress_is_governed()


@pytest.mark.parametrize("mode", ["nat", "route", "bridge", "open", "private",
                                  "vepa", "passthrough", "hostdev"])
def test_every_forwarding_mode_is_refused(monkeypatch, mode):
    """`route` matters as much as `nat`: it does not translate addresses, but it
    forwards, and a malware VM on a routed network is on the LAN."""
    xml = f"<network><name>n</name><forward mode='{mode}'/></network>"
    rt = _runtime(monkeypatch, xml=xml, network="n")
    with pytest.raises(RuntimeError, match=mode):
        rt._assert_egress_is_governed()


def test_an_isolated_network_is_allowed(monkeypatch):
    """No <forward> element at all — libvirt's isolated mode. Without this the check
    would be a refuse-everything stub that no positive case distinguishes."""
    _runtime(monkeypatch, xml=ISOLATED)._assert_egress_is_governed()


def test_a_forwarding_network_is_allowed_WITH_an_egress_policy(monkeypatch):
    """A worker that needs egress gets it the governed way — per-worker rooter rules on
    its IP — and then the network's own mode is no longer what decides."""
    policy = object()      # any non-None policy; its content is libvirt_egress's business
    _runtime(monkeypatch, xml=NAT, network="default",
             egress_policy=policy)._assert_egress_is_governed()


# --------------------------------------------------------------- failing closed

def test_an_unreadable_network_definition_refuses(monkeypatch):
    """"I could not determine whether this VM has internet" is not "probably fine". It is
    precisely the state in which an operator most wants to be stopped."""
    rt = _runtime(monkeypatch, rc=1, stderr="error: failed to get network 'bb-isolated'")
    with pytest.raises(RuntimeError, match="not known whether this VM would have internet"):
        rt._assert_egress_is_governed()


def test_empty_output_from_virsh_refuses(monkeypatch):
    """rc=0 with no XML — a wrapper that swallowed the error, a truncated read."""
    rt = _runtime(monkeypatch, xml="")
    with pytest.raises(RuntimeError, match="not known whether this VM would have internet"):
        rt._assert_egress_is_governed()


def test_a_bare_forward_element_with_no_mode_is_treated_as_forwarding(monkeypatch):
    """libvirt defaults a modeless <forward/> to nat. Reading "no mode attribute" as
    "not forwarding" would invert the check on the most compact way to write NAT."""
    rt = _runtime(monkeypatch, xml="<network><name>n</name><forward/></network>")
    with pytest.raises(RuntimeError, match="reaches the physical network"):
        rt._assert_egress_is_governed()


# ------------------------------------------------------- the check actually runs

def test_spawn_checks_before_it_boots_anything(monkeypatch, tmp_path):
    """The guest is reachable on the libvirt network from `start` onward, so a check
    after that races the thing it checks. Assert ordering by making the check raise and
    requiring that nothing was allocated."""
    rt = _runtime(monkeypatch, xml=NAT, network="default")
    allocated: list = []
    monkeypatch.setattr(rt, "_alloc_overlay_name",
                        lambda: allocated.append(1) or ("s", "n", Path("/x")))
    with pytest.raises(RuntimeError, match="reaches the physical network"):
        rt.spawn()
    assert allocated == [], "spawn began provisioning before checking for internet access"


def test_the_compose_layer_agrees_with_the_runtime_default():
    """A SECOND COPY OF THE SAME DEFAULT. `VmSpec.network` is the YAML-facing field and
    it overrides `LibvirtVmConfig.network` on every compose-driven pool — so changing one
    and not the other left the entire compose path on libvirt's NAT network while the
    runtime's default looked correct. The spawn check catches it either way; that is the
    control compensating for a wrong default, not a reason to leave one."""
    from blastbox.host.runtime.vm_compose import VmWorkerSpec as VmSpec

    assert VmSpec.network == VmConfig.network == "bb-isolated", (
        f"VmSpec.network={VmSpec.network!r} and LibvirtVmConfig.network="
        f"{VmConfig.network!r} have drifted; the YAML default wins in production"
    )


def test_no_default_in_the_tree_points_at_libvirts_nat_network():
    """Catches a third copy appearing. Test fixtures may name it explicitly — that is a
    choice, made visibly — but no DEFAULT may."""
    import dataclasses

    from blastbox.host.runtime.vm_compose import VmWorkerSpec as VmSpec

    for cls in (VmConfig, VmSpec):
        for f in dataclasses.fields(cls):
            if f.name == "network":
                assert f.default != "default", (
                    f"{cls.__name__}.network defaults to libvirt's NAT network"
                )
