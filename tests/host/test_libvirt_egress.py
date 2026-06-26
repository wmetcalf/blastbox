"""Unit tests for the libvirt VM-worker egress rule builder (pure; no iptables needed)."""
from __future__ import annotations

import pytest

from blastbox.host.netpolicy import Personality
from blastbox.host.runtime.libvirt_egress import (
    LibvirtEgress,
    VmEgressPolicy,
    _chain_name,
    forward_chain_rules,
)


def _flat(rules):
    return [" ".join(r) for r in rules]


def test_apply_fails_closed_when_routed_exit_has_no_routing():
    # A routed exit (vpn/tor/inetsim) with no ExitRouting would egress via the host default route
    # (its real IP) — apply() must refuse rather than install a leaky filter-only policy. The raise
    # happens before any iptables call, so this is safe to run without root.
    eg = LibvirtEgress(sudo=False, routing=None)
    pol = VmEgressPolicy(exit_driver="openvpn", block_internal=True)
    with pytest.raises(ValueError):
        eg.apply("192.168.122.5", pol, "192.168.122.1", mac="52:54:00:aa:bb:cc")


def test_apply_fails_closed_for_inetsim_without_fakenet_addr():
    # inetsim with routing but no fakenet_addr DNATs nothing -> would egress via host default route.
    eg = LibvirtEgress(sudo=False, routing=ExitRouting())  # fakenet_addr unset
    with pytest.raises(ValueError):
        eg.apply("192.168.122.5", VmEgressPolicy(exit_driver="inetsim"), "192.168.122.1",
                 mac="52:54:00:aa:bb:cc")


def test_apply_rejects_unsupported_exit_driver():
    # socks/httpproxy have no VM routing path -> must NOT fall through to a permissive ACCEPT.
    eg = LibvirtEgress(sudo=False, routing=ExitRouting())
    for drv in ("socks", "httpproxy", "bogus"):
        with pytest.raises(ValueError):
            eg.apply("192.168.122.5", VmEgressPolicy(exit_driver=drv), "192.168.122.1",
                     mac="52:54:00:aa:bb:cc")


def test_drop_policy_has_no_dns_exemption():
    # exit=none/drop must not leak even gateway DNS.
    rules = _flat(forward_chain_rules("192.168.122.5", VmEgressPolicy(exit_driver="drop"),
                                      "192.168.122.1"))
    assert not any("--dport 53" in r and "ACCEPT" in r for r in rules)


def test_chain_name():
    assert _chain_name("192.168.122.87") == "BBVM_192_168_122_87"
    assert len(_chain_name("192.168.122.250")) <= 28  # iptables chain-name limit


def test_web_only_block_internal():
    pol = VmEgressPolicy(exit_driver="openvpn", egress_ports=(53, 80, 443), block_internal=True)
    flat = _flat(forward_chain_rules("192.168.122.50", pol, gateway="192.168.122.1"))
    c = "BBVM_192_168_122_50"
    # return traffic first
    assert flat[0] == f"-A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    # gateway DNS exempted before the internal block
    assert f"-A {c} -d 192.168.122.1 -p udp --dport 53 -j ACCEPT" in flat
    # block-internal: one DROP per internal net
    drops = [f for f in flat if f.endswith("-j DROP") and "-d " in f]
    assert len(drops) == 4
    # web allowlist + catch-all drop
    assert f"-A {c} -p udp --dport 53 -j ACCEPT" in flat
    assert f"-A {c} -p tcp -m multiport --dports 53,80,443 -j ACCEPT" in flat
    assert flat[-1] == f"-A {c} -j DROP"


def test_exit_drop_drops_everything():
    rules = forward_chain_rules("10.0.0.5", VmEgressPolicy(exit_driver="drop"), gateway=None)
    assert rules[-1] == ["-A", "BBVM_10_0_0_5", "-j", "DROP"]
    assert not any("multiport" in " ".join(r) for r in rules)


def test_exit_none_drops_everything():
    rules = forward_chain_rules("10.0.0.6", VmEgressPolicy(exit_driver="none"), gateway=None)
    assert rules[-1][-1] == "DROP"


def test_direct_no_ports_accepts():
    rules = forward_chain_rules("192.168.122.9", VmEgressPolicy(exit_driver="direct"), gateway=None)
    assert rules[-1] == ["-A", "BBVM_192_168_122_9", "-j", "ACCEPT"]


def test_multiport_chunks_over_15():
    ports = tuple(range(1000, 1020))  # 20 ports → 15 + 5
    pol = VmEgressPolicy(exit_driver="direct", egress_ports=ports)
    rules = forward_chain_rules("192.168.122.9", pol, gateway=None)
    multiport = [r for r in rules if "multiport" in " ".join(r)]
    assert len(multiport) == 2


def test_udp_dns_only_when_53_allowlisted():
    pol = VmEgressPolicy(exit_driver="direct", egress_ports=(80, 443))  # no 53
    flat = _flat(forward_chain_rules("192.168.122.9", pol, gateway=None))
    assert not any("-p udp --dport 53" in f for f in flat)


def test_from_personality():
    p = Personality(name="w", exit_driver="openvpn",
                    config={"egress_ports": "53 80 443", "block_internal": "1"})
    pol = VmEgressPolicy.from_personality(p)
    assert pol.exit_driver == "openvpn"
    assert pol.egress_ports == (53, 80, 443)
    assert pol.block_internal is True


def test_from_personality_defaults_off():
    pol = VmEgressPolicy.from_personality(Personality(name="n", exit_driver="none"))
    assert pol.egress_ports is None and pol.block_internal is False


# --- exit routing (rooter model: policy-route / REDIRECT / DNAT) -------------------
from blastbox.host.runtime.libvirt_egress import (  # noqa: E402
    ExitRouting,
    routing_commands,
    routing_teardown_commands,
)


def test_routing_direct_and_drop_are_noops():
    R = ExitRouting()
    for drv in ("direct", "none", "drop"):
        assert routing_commands("192.168.122.5", drv, R) == []


def test_routing_vpn_policy_routes_with_local_exemption():
    cmds = _flat(routing_commands("192.168.122.5", "openvpn", ExitRouting(vpn_table="vpn", vpn_tun="tun0")))
    # local subnet stays on main, everything else -> vpn table, MASQUERADE on the tun
    assert any("rule add from 192.168.122.5 to 192.168.122.0/24 lookup main" in c for c in cmds)
    assert any("rule add from 192.168.122.5 lookup vpn" in c for c in cmds)
    assert any("POSTROUTING -s 192.168.122.5 -o tun0 -j MASQUERADE" in c for c in cmds)


def test_routing_tor_redirects_tcp_and_dns_keeps_local():
    cmds = _flat(routing_commands("192.168.122.7", "tor", ExitRouting(tor_trans_port=9040, tor_dns_port=9053)))
    assert any("-d 192.168.122.0/24 -j RETURN" in c for c in cmds)
    assert any("-p tcp -j REDIRECT --to-ports 9040" in c for c in cmds)
    assert any("--dport 53 -j REDIRECT --to-ports 9053" in c for c in cmds)
    # DNS redirect MUST precede the local RETURN, else DNS to the bridge resolver resolves outside
    # tor (a deanonymization leak).
    assert cmds.index(next(c for c in cmds if "--dport 53" in c)) < \
        cmds.index(next(c for c in cmds if "RETURN" in c))


def test_routing_fakenet_dnats_when_addr_set():
    assert routing_commands("192.168.122.9", "inetsim", ExitRouting()) == []  # no addr -> disabled
    cmds = _flat(routing_commands("192.168.122.9", "inetsim", ExitRouting(fakenet_addr="172.28.100.2")))
    # DNS redirected to FakeNet (so C2 domains resolve to the sinkhole, not NXDOMAIN at dnsmasq)
    assert any("--dport 53 -j DNAT --to-destination 172.28.100.2:53" in c for c in cmds)
    # catch-all DNAT for everything else, host/agent control path stays local
    assert any(c.endswith("-j DNAT --to-destination 172.28.100.2") for c in cmds)
    assert any("-d 192.168.122.0/24 -j RETURN" in c for c in cmds)
    # DNS rules must precede the local RETURN so DNS to the bridge resolver is still caught
    flat = cmds
    assert flat.index(next(c for c in flat if "--dport 53" in c)) < \
        flat.index(next(c for c in flat if "RETURN" in c))


def test_tor_all_tcp_without_egress_ports():
    # No allow-list: tor carries ALL TCP (catch-all REDIRECT); tor owns the exit policy.
    cmds = _flat(routing_commands("192.168.122.7", "tor", ExitRouting(tor_trans_port=9040)))
    assert any(c.endswith("-p tcp -j REDIRECT --to-ports 9040") for c in cmds)  # catch-all


def test_tor_port_scoped_with_egress_ports():
    # egress_ports composes onto tor: only those TCP ports REDIRECT into tor; the rest (and all
    # non-TCP) fall through to the FORWARD drop. 53 is excluded (DNS goes to the DNSPort).
    cmds = _flat(routing_commands("192.168.122.7", "tor", ExitRouting(tor_trans_port=9040, tor_dns_port=9053),
                                  egress_ports=(53, 80, 443, 8080)))
    for p in (80, 443, 8080):
        assert any(f"--dport {p} -j REDIRECT --to-ports 9040" in c for c in cmds)
    assert not any(c.endswith("-p tcp -j REDIRECT --to-ports 9040") for c in cmds)  # no catch-all
    assert any("--dport 53 -j REDIRECT --to-ports 9053" in c for c in cmds)         # DNS -> DNSPort


def test_tor_forward_blocks_non_tcp_regardless_of_ports():
    # FORWARD for tor drops everything reaching it (TCP+DNS were REDIRECTed away) — so non-allowlisted
    # TCP AND all non-TCP are blocked, with or without egress_ports.
    for ep in (None, (80, 443)):
        fwd = _flat(forward_chain_rules("192.168.122.5",
                    VmEgressPolicy(exit_driver="tor", egress_ports=ep), "192.168.122.1"))
        assert fwd[-1].endswith("-j DROP")
        assert not any("multiport" in r for r in fwd)               # tor port-scoping is in nat, not FORWARD
        assert not any(r.endswith("-p tcp -j ACCEPT") for r in fwd)  # no blanket TCP accept in FORWARD


def test_routing_teardown_inverts_port_scoped_tor():
    R = ExitRouting(tor_trans_port=9040, tor_dns_port=9053)
    add = routing_commands("192.168.122.7", "tor", R, egress_ports=(80, 443))
    rm = routing_teardown_commands("192.168.122.7", "tor", R, egress_ports=(80, 443))
    assert len(rm) == len(add)
    for a, d in zip(add, rm):
        assert d == [("-D" if t == "-A" else t) for t in a]


def test_vpn_killswitch_scopes_egress_to_tunnel():
    # A tunneled exit (openvpn/wireguard) must only ACCEPT egress OUT the tunnel interface, with a
    # trailing DROP — so if the tunnel drops and packets fall to the host route, they're blocked
    # (fail closed) instead of leaking out the host WAN.
    fwd = _flat(forward_chain_rules("192.168.122.5", VmEgressPolicy(exit_driver="openvpn"),
                                    "192.168.122.1", egress_if="tun0"))
    assert any(r.endswith("-o tun0 -j ACCEPT") for r in fwd)  # egress only via the tunnel
    assert fwd[-1].endswith("-j DROP")                        # kill-switch
    # with an allow-list, even the allowlisted ports are tunnel-scoped
    fwd2 = _flat(forward_chain_rules("192.168.122.5",
                 VmEgressPolicy(exit_driver="openvpn", egress_ports=(80, 443)), "192.168.122.1",
                 egress_if="tun0"))
    assert any("multiport --dports 80,443 -o tun0 -j ACCEPT" in r for r in fwd2)


def test_direct_egress_is_not_tunnel_scoped():
    # direct egress (via the host) has no egress_if -> plain ACCEPT, no kill-switch DROP.
    fwd = _flat(forward_chain_rules("192.168.122.5", VmEgressPolicy(exit_driver="direct"),
                                    "192.168.122.1"))
    assert fwd[-1].endswith("-j ACCEPT")
    assert not any("-o tun" in r for r in fwd)


def test_routing_teardown_inverts():
    R = ExitRouting(fakenet_addr="172.28.100.1")
    for drv in ("openvpn", "tor", "inetsim"):
        add = routing_commands("192.168.122.5", drv, R)
        rm = routing_teardown_commands("192.168.122.5", drv, R)
        assert len(rm) == len(add)
        for a, d in zip(add, rm):
            if a[:2] == ["ip", "rule"]:
                assert d[:3] == ["ip", "rule", "del"]
            else:
                assert "-D" in d and "-A" not in d


def test_routing_next_hop_shared_router_mode():
    R = ExitRouting(gateway="10.99.0.2", leg="br-routers", gateway_table_base=200)
    cmds = _flat(routing_commands("192.168.122.5", "openvpn", R))
    # per-gateway table default via the router VM on the leg
    assert any("route replace default via 10.99.0.2 dev br-routers table 202" in c for c in cmds)
    # local exemption + select the per-gateway table
    assert any("rule add from 192.168.122.5 to 192.168.122.0/24 lookup main" in c for c in cmds)
    assert any("rule add from 192.168.122.5 lookup 202" in c for c in cmds)
    # SNAT onto the leg so the router replies to this host
    assert any("POSTROUTING -s 192.168.122.5 -o br-routers -j MASQUERADE" in c for c in cmds)


def test_routing_next_hop_no_masquerade():
    R = ExitRouting(gateway="10.99.0.3", leg="br-routers", gateway_masquerade=False)
    cmds = _flat(routing_commands("192.168.122.5", "wireguard", R))
    assert not any("MASQUERADE" in c for c in cmds)
    assert any("route replace default via 10.99.0.3 dev br-routers table 203" in c for c in cmds)


def test_routing_next_hop_teardown_keeps_shared_route():
    R = ExitRouting(gateway="10.99.0.2", leg="br-routers")
    rm = _flat(routing_teardown_commands("192.168.122.5", "openvpn", R))
    # the shared per-gateway route must NOT be torn down (other workers/hosts use it)
    assert not any(c.startswith("ip route") for c in rm)
    # but the per-worker rules + masquerade are removed
    assert any("rule del from 192.168.122.5 lookup 202" in c for c in rm)
    assert any("POSTROUTING -s 192.168.122.5 -o br-routers -j MASQUERADE" in c and "-D" in c for c in rm)
