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


# ------------------------------------------- the ADDRESS defaults must move too

def test_the_subnet_defaults_track_the_network_default():
    """FOUND BY UPSTREAM REVIEW, an hour after the network default moved. `network`
    became bb-isolated (192.168.221.0/24) and `subnet_prefix` stayed at libvirt's
    `default` subnet — so with pure defaults `_domain_xml()` pinned DHCPSERVER to a
    bridge address that does not exist and `_ip_for_mac()` rejected every neighbour on
    the real subnet: the VM boots and is never discovered as ready.

    The same "second copy of a default" mistake as `network` itself, one field over,
    made while writing the test that catches it for `network`."""
    from blastbox.host.runtime.vm_compose import VmWorkerSpec as VmSpec

    cfg = VmConfig(golden_base="/x")
    assert cfg.subnet_prefix == "192.168.221.", (
        f"subnet_prefix={cfg.subnet_prefix!r} does not serve {cfg.network!r}"
    )
    assert VmSpec.subnet_prefix == cfg.subnet_prefix, "the YAML copy drifted, and it wins"
    assert cfg.resolved_gateway == "192.168.221.1"


def test_a_subnet_mismatch_is_reported(monkeypatch, caplog):
    """A wrong subnet is an availability bug, not a containment one, so it warns rather
    than refusing — but it must not be silent, because the symptom (a VM that boots and
    never becomes ready) looks nothing like its cause."""
    import logging

    rt = _runtime(monkeypatch,
                  xml="<network><name>bb-isolated</name><ip address='10.9.9.1'/></network>")
    with caplog.at_level(logging.WARNING):
        rt._assert_subnet_matches_network()
    assert "subnet_prefix" in caplog.text and "10.9.9." in caplog.text


def test_a_matching_subnet_says_nothing(monkeypatch, caplog):
    import logging

    rt = _runtime(monkeypatch,
                  xml="<network><name>bb-isolated</name><ip address='192.168.221.1'/></network>")
    with caplog.at_level(logging.WARNING):
        rt._assert_subnet_matches_network()
    assert "subnet_prefix" not in caplog.text


# ------------------------------------ 'direct' egress needs a network that forwards

def test_direct_egress_is_refused_on_a_network_that_cannot_carry_it(monkeypatch):
    """`direct` means "go straight out" and `routing_commands()` emits no routing and no
    NAT for it — it relies on the NETWORK for the path. On an isolated network the filter
    chain accepts the packet and it dies with no return route: the job loses connectivity
    and nothing says why. A contradiction should be loud."""
    policy = type("P", (), {"exit_driver": "direct"})()
    rt = _runtime(monkeypatch, xml=ISOLATED, egress_policy=policy)
    with pytest.raises(RuntimeError, match="does not forward"):
        rt._assert_egress_is_governed()


def test_direct_egress_is_fine_on_a_forwarding_network(monkeypatch):
    policy = type("P", (), {"exit_driver": "direct"})()
    _runtime(monkeypatch, xml=NAT, network="default",
             egress_policy=policy)._assert_egress_is_governed()


@pytest.mark.parametrize("driver", ["openvpn", "wireguard", "socks", "tor"])
def test_a_tunnel_driver_is_fine_on_an_isolated_network(monkeypatch, driver):
    """These build their own path; they do not need the network to provide one. Without
    this the fix above would be a blanket ban on isolated networks."""
    policy = type("P", (), {"exit_driver": driver})()
    _runtime(monkeypatch, xml=ISOLATED, egress_policy=policy)._assert_egress_is_governed()


# ------------------------------------------- the checks the review round disproved

DNS_ISOLATED = ("<network><name>bb-isolated</name><bridge name='bb-virbr0'/>"
                "<dns><forwarder addr='192.168.221.1'/></dns>"
                "<ip address='192.168.221.1' netmask='255.255.255.0'/></network>")


def test_a_dns_forwarder_is_not_a_forward_element(monkeypatch):
    """`"<forward" in xml` also matches `<forwarder`, and `<dns><forwarder/></dns>` is
    perfectly ordinary on an ISOLATED network — so adding split-DNS to bb-isolated
    inverted this check in BOTH directions at once: an unpoliced worker was refused with
    a message claiming the network was NAT, and a `direct` worker was allowed onto a
    network that cannot carry it."""
    rt = _runtime(monkeypatch, xml=DNS_ISOLATED)
    rt._assert_egress_is_governed()                      # must NOT refuse
    assert rt._network_forwards() is False
    assert rt._forward_mode(DNS_ISOLATED) is None

    policy = type("P", (), {"exit_driver": "direct"})()
    with pytest.raises(RuntimeError, match="does not forward"):
        _runtime(monkeypatch, xml=DNS_ISOLATED, egress_policy=policy
                 )._assert_egress_is_governed()


@pytest.mark.parametrize("mode", ["tomato", "NAT", "Route", "some-future-mode"])
def test_an_unrecognised_forward_mode_is_refused(monkeypatch, mode):
    """The test was `mode in FORWARDING_MODES` — an ALLOWLIST OF BAD MODES — so any mode
    libvirt adds later, or any capitalisation, read as safe and an unpoliced malware VM
    booted onto it. The only safe shape is "no <forward> element at all"."""
    xml = f"<network><name>n</name><forward mode='{mode}'/></network>"
    with pytest.raises(RuntimeError, match="reaches the physical network"):
        _runtime(monkeypatch, xml=xml, network="n")._assert_egress_is_governed()


def test_an_unreadable_network_is_refused_WHATEVER_the_policy(monkeypatch):
    """The unreadable-network refusal sat BELOW the has-a-policy branch's unconditional
    return, so it only ever fired for an unpoliced worker: every tunnel driver sailed
    past it, and `direct` got a refusal that misdiagnosed a down libvirtd as a wrong exit
    driver ("use a forwarding network" — an instruction to build the NAT network this
    whole change exists to eliminate)."""
    for driver in (None, "direct", "openvpn", "wireguard", "socks", "tor"):
        policy = None if driver is None else type("P", (), {"exit_driver": driver})()
        rt = _runtime(monkeypatch, rc=1, stderr="error: failed to get network", 
                      egress_policy=policy)
        with pytest.raises(RuntimeError, match="not known whether this VM would have"):
            rt._assert_egress_is_governed()


def test_the_shipped_network_and_the_code_default_are_the_same_subnet():
    """A THIRD copy of the subnet, asserted by nothing. Re-subnetting the shipped XML to
    avoid a site collision left every default VM worker with a DHCPSERVER and neighbour
    filter pointed at an empty range — the "boots and is never discovered as ready"
    failure — with all tests green."""
    import xml.etree.ElementTree as ET
    from pathlib import Path as _P

    root = ET.parse(_P(__file__).resolve().parents[2] / "deploy/libvirt/bb-isolated.xml").getroot()
    ip = root.find("ip")
    assert ip is not None, "the shipped network no longer declares an address"
    shipped = ip.get("address").rsplit(".", 1)[0] + "."
    assert shipped == VmConfig(golden_base="/x").subnet_prefix, (
        f"bb-isolated.xml serves {shipped}0/24 but subnet_prefix is "
        f"{VmConfig(golden_base='/x').subnet_prefix!r}"
    )
    rng = root.find("./ip/dhcp/range")
    assert rng is not None and rng.get("start").startswith(shipped), (
        "the DHCP range is not on the network's own subnet"
    )
