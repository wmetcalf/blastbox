"""Unit tests for the libvirt VM-worker egress rule builder (pure; no iptables needed)."""
from __future__ import annotations

import pytest

from blastbox.host.netpolicy import Personality
import subprocess

from blastbox.host.runtime.libvirt_egress import (
    _MAIN_RULE_PRIORITY,
    ExitRouting,
    LibvirtEgress,
    VmEgressPolicy,
    _chain_name,
    _ip_rule_deletes,
    _nat_chain_deletes,
    _rule_priority,
    _spoof_drop_deletes,
    forward_chain_rules,
    input_chain_rules,
)


def test_rule_priority_stays_below_main():
    r = ExitRouting()
    # high third octet must NOT collide with / sort after the kernel `main` rule (32766), else the
    # worker rule never selects the tunnel table.
    for ip in ("192.168.124.22", "10.0.255.255", "192.168.200.7"):
        assert _rule_priority(ip, r) < _MAIN_RULE_PRIORITY
    # within a /24, every host gets a distinct priority
    prios = {_rule_priority(f"192.168.124.{n}", r) for n in range(256)}
    assert len(prios) == 256


def test_ip_rule_deletes_use_full_selector_for_target_worker():
    dump = "\n".join([
        "0:\tfrom all lookup local",
        "32237:\tfrom 192.168.122.5 lookup vpn",
        "32236:\tfrom 192.168.122.5 to 192.168.122.0/24 lookup main",
        "1500:\tfrom 192.168.122.50 lookup vpn",        # different worker (.50, not .5)
        "32766:\tfrom all lookup main",
    ])
    dels = _ip_rule_deletes("192.168.122.5", dump)
    # only .5's two rules, deleted by FULL selector + priority (not bare priority, which could hit a
    # sibling worker sharing a priority).
    assert dels == [
        ["ip", "rule", "del", "from", "192.168.122.5", "lookup", "vpn", "priority", "32237"],
        ["ip", "rule", "del", "from", "192.168.122.5", "to", "192.168.122.0/24", "lookup", "main",
         "priority", "32236"],
    ]


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
    # direct exit: it keeps the host-resolver (gateway) DNS exemption (a tunneled exit must resolve
    # tunnel-side, so openvpn/wireguard intentionally do NOT get this gateway-DNS accept).
    pol = VmEgressPolicy(exit_driver="direct", egress_ports=(53, 80, 443), block_internal=True)
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


def test_from_personality_fails_closed_on_invalid_ports():
    # a provided-but-all-invalid egress_ports (typo) must NOT collapse to None (= unrestricted egress
    # for direct/VPN); it becomes an EMPTY allowlist (deny-all + trailing DROP), failing closed.
    p = Personality(name="w", exit_driver="direct", config={"egress_ports": "70000 nope"})
    pol = VmEgressPolicy.from_personality(p)
    assert pol.egress_ports == ()        # deny-all, NOT None
    # and the FORWARD filter for direct then emits a trailing DROP instead of a bare ACCEPT-all
    flat = _flat(forward_chain_rules("192.168.122.7", pol, gateway="192.168.122.1"))
    assert any(f.endswith("-j DROP") for f in flat)
    assert not any(f == "-A BBVM_192_168_122_7 -j ACCEPT" for f in flat)


def test_from_personality_blank_ports_stays_unrestricted():
    # an omitted / whitespace-only value is "no allowlist" (None), distinct from a typo — unchanged.
    p = Personality(name="w", exit_driver="direct", config={"egress_ports": "   "})
    assert VmEgressPolicy.from_personality(p).egress_ports is None


# --- exit routing (rooter model: policy-route / REDIRECT / DNAT) -------------------
from blastbox.host.runtime.libvirt_egress import (  # noqa: E402
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
    # No gateway known → NOTHING is exempted from the FakeNet DNAT (fail-closed): no subnet RETURN, so
    # a guest can't reach sibling VMs on the bridge — everything is sunk.
    cmds = _flat(routing_commands("192.168.122.9", "inetsim", ExitRouting(fakenet_addr="172.28.100.2")))
    assert any("--dport 53 -j DNAT --to-destination 172.28.100.2:53" in c for c in cmds)
    assert any(c.endswith("-j DNAT --to-destination 172.28.100.2") for c in cmds)
    assert not any("RETURN" in c for c in cmds)                      # no subnet-wide exemption
    assert not any("192.168.122.0/24" in c for c in cmds)


def test_routing_fakenet_exempts_only_gateway_not_subnet():
    # With a gateway, ONLY the bridge host is RETURNed (guest↔host control stays local); sibling VMs on
    # the subnet are NOT exempted — they get DNATed into FakeNet, blocking lateral movement.
    cmds = _flat(routing_commands("192.168.122.9", "inetsim",
                                  ExitRouting(fakenet_addr="172.28.100.2"), gateway="192.168.122.1"))
    assert any("-d 192.168.122.1 -j RETURN" in c for c in cmds)      # host/gateway exempt
    assert not any("192.168.122.0/24" in c for c in cmds)            # but NOT the whole subnet
    # DNS rules must precede the gateway RETURN so DNS to the bridge resolver is still sunk
    assert cmds.index(next(c for c in cmds if "--dport 53" in c)) < \
        cmds.index(next(c for c in cmds if "RETURN" in c))


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
    # the established-flow accept is ALSO tunnel-scoped, else an in-flight connection would leak over
    # the host WAN when the tunnel drops mid-stream (the conntrack accept beats the -o tun accepts).
    assert fwd[0] == "-A BBVM_192_168_122_5 -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    # with an allow-list, even the allowlisted ports are tunnel-scoped
    fwd2 = _flat(forward_chain_rules("192.168.122.5",
                 VmEgressPolicy(exit_driver="openvpn", egress_ports=(80, 443)), "192.168.122.1",
                 egress_if="tun0"))
    assert any("multiport --dports 80,443 -o tun0 -j ACCEPT" in r for r in fwd2)


def test_routing_tor_dns_redirect_gated_on_allowlist():
    rt = ExitRouting()
    # 53 omitted from the allowlist => NO DNS redirect into tor (unredirected DNS falls to FORWARD drop)
    flat = [" ".join(c) for c in routing_commands("192.168.122.5", "tor", rt, egress_ports=(80, 443))]
    assert not any("--dport 53 -j REDIRECT" in f for f in flat)
    # 53 present => DNS resolves via tor's DNSPort
    flat2 = [" ".join(c) for c in routing_commands("192.168.122.5", "tor", rt, egress_ports=(53, 80))]
    assert any("udp --dport 53 -j REDIRECT" in f for f in flat2)
    # unset allowlist => DNS via tor (unchanged default)
    flat3 = [" ".join(c) for c in routing_commands("192.168.122.5", "tor", rt)]
    assert any("udp --dport 53 -j REDIRECT" in f for f in flat3)


def test_input_chain_tor_dnsport_gated_on_allowlist():
    rt = ExitRouting(tor_trans_port=9040, tor_dns_port=9053)
    # 53 omitted => no DNSPort accept (the redirect isn't installed either); TransPort still accepted
    flat = _flat(input_chain_rules("192.168.122.9", VmEgressPolicy(exit_driver="tor", egress_ports=(80, 443)),
                                   gateway="192.168.122.1", routing=rt))
    assert not any("--dport 9053 -j ACCEPT" in f for f in flat)
    assert any("--dport 9040 -j ACCEPT" in f for f in flat)


def test_nat_chain_deletes_sweep_target_worker_by_source_ip():
    pre = "\n".join([
        "-A PREROUTING -s 192.168.122.50/32 -p udp --dport 53 -j DNAT --to-destination 172.28.100.1:53",
        "-A PREROUTING -s 192.168.122.50/32 -j DNAT --to-destination 172.28.100.1",         # DNAT
        "-A PREROUTING -s 192.168.122.50/32 -p tcp -j REDIRECT --to-ports 7777",            # REDIRECT (any port)
        "-A PREROUTING -s 192.168.122.5/32 -j DNAT --to-destination 10.0.0.1",              # other worker
    ])
    dels = _nat_chain_deletes("192.168.122.50", "PREROUTING", ("REDIRECT", "DNAT"), pre)
    assert len(dels) == 3                                  # all .50 REDIRECT+DNAT (any port), not .5
    assert all(d[:4] == ["iptables", "-t", "nat", "-D"] for d in dels)
    assert all("192.168.122.50/32" in " ".join(d) for d in dels)
    # POSTROUTING MASQUERADE swept too (e.g. a now-disabled gateway_masquerade leftover)
    post = "\n".join([
        "-A POSTROUTING -s 192.168.122.50/32 -o br-r -j MASQUERADE",
        "-A POSTROUTING -s 192.168.122.5/32 -o tun0 -j MASQUERADE",                          # other worker
    ])
    md = _nat_chain_deletes("192.168.122.50", "POSTROUTING", ("MASQUERADE",), post)
    assert len(md) == 1 and "br-r" in " ".join(md[0])


def test_nat_chain_deletes_sweeps_return_bypass_rules():
    # tor/inetsim install `-s <ip> -d <internal> -j RETURN` bypasses AHEAD of the DNS REDIRECT; on IP
    # reuse a leftover RETURN short-circuits PREROUTING and DNS escapes tor/FakeNet. Must be swept too.
    pre = "\n".join([
        "-A PREROUTING -s 192.168.122.50/32 -d 192.168.122.0/24 -j RETURN",   # local-net bypass
        "-A PREROUTING -s 192.168.122.50/32 -d 10.0.0.0/8 -j RETURN",          # RFC1918 bypass
        "-A PREROUTING -s 192.168.122.50/32 -p tcp -j REDIRECT --to-ports 9040",
        "-A PREROUTING -s 192.168.122.5/32 -d 10.0.0.0/8 -j RETURN",           # other worker — untouched
    ])
    dels = _nat_chain_deletes("192.168.122.50", "PREROUTING", ("REDIRECT", "DNAT", "RETURN"), pre)
    assert sum("-j RETURN" in " ".join(d) for d in dels) == 2     # both .50 RETURNs swept, not .5's
    assert all("192.168.122.50/32" in " ".join(d) for d in dels)


def test_v6_drop_raises_on_permission_denied(monkeypatch):
    # legacy iptables reports a privilege problem as "can't initialize ... Permission denied" — that
    # is NOT a benign "no v6 table" case: the drop didn't install while v6 may work → fail closed.
    eg = LibvirtEgress(sudo=False)
    monkeypatch.setattr(eg, "_priv", lambda argv, **k: subprocess.CompletedProcess(
        argv, 4, "", "ip6tables: can't initialize ip6tables table `filter': Permission denied"))
    with pytest.raises(RuntimeError, match="v6 fail-closed"):
        eg._v6_drop("FORWARD", "52:54:00:aa:bb:cc")


def test_forward_gateway_dns_skipped_for_vpn_exits():
    # openvpn/wireguard must NOT get the gateway-DNS exemption: the policy route keeps gateway traffic
    # in `main`, so it would resolve OUTSIDE the tunnel while the rest is kill-switched.
    for drv in ("openvpn", "wireguard"):
        flat = _flat(forward_chain_rules("192.168.122.5",
                                         VmEgressPolicy(exit_driver=drv, egress_ports=(53, 80)),
                                         gateway="192.168.122.1"))
        assert not any("-d 192.168.122.1" in f and "--dport 53" in f for f in flat)


def test_v6_drop_raises_on_missing_mac_match_extension(monkeypatch):
    # ip6tables present but the `mac` match is unavailable: the drop wouldn't install while the guest
    # may have working IPv6 → must FAIL CLOSED (raise), not be tolerated as "no v6 stack".
    eg = LibvirtEgress(sudo=False)
    monkeypatch.setattr(eg, "_priv", lambda argv, **k: subprocess.CompletedProcess(
        argv, 1, "", "ip6tables: Couldn't load match `mac':No such file or directory"))
    with pytest.raises(RuntimeError, match="v6 fail-closed"):
        eg._v6_drop("FORWARD", "52:54:00:aa:bb:cc")


def test_apply_installs_routing_before_forward_jump(monkeypatch):
    # L460: the sink/tunnel routing (nat DNAT/REDIRECT) must be wired BEFORE the FORWARD jump goes
    # live, else an inetsim worker's traffic is ACCEPTed out the host route before the DNAT exists.
    eg = LibvirtEgress(sudo=False, routing=ExitRouting(fakenet_addr="172.28.100.1"))
    issued = []

    def fake_ipt(*a, **k):
        issued.append(" ".join(a))
        return subprocess.CompletedProcess(list(a), 1 if "-D" in a else 0, "", "")

    monkeypatch.setattr(eg, "_ipt_run", fake_ipt)
    monkeypatch.setattr(eg, "_priv",
                        lambda argv, **k: issued.append(" ".join(argv)) or subprocess.CompletedProcess(argv, 0, "", ""))
    eg.apply("192.168.122.5", VmEgressPolicy(exit_driver="inetsim"), gateway="192.168.122.1",
             mac="52:54:00:aa:bb:cc")
    dnat = next(i for i, s in enumerate(issued) if "DNAT --to-destination 172.28.100.1" in s)
    jump = next(i for i, s in enumerate(issued) if "FORWARD 1 -s 192.168.122.5 -j BBVM_192_168_122_5" in s)
    assert dnat < jump   # sink DNAT installed before the FORWARD jump → no clearnet window


def test_apply_exempts_dhcp_above_input_antispoof(monkeypatch):
    # DHCP renewal from 0.0.0.0 (worker MAC, no IP) must be ACCEPTed ABOVE the INPUT anti-spoof DROP,
    # else the guest can never re-lease after a lease expiry / snapshot revert.
    eg = LibvirtEgress(sudo=False)
    issued = []

    def fake_ipt(*a, **k):
        issued.append(" ".join(a))
        return subprocess.CompletedProcess(list(a), 1 if "-D" in a else 0, "", "")

    monkeypatch.setattr(eg, "_ipt_run", fake_ipt)
    monkeypatch.setattr(eg, "_priv", lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", ""))
    eg.apply("192.168.122.5", VmEgressPolicy(exit_driver="direct"), gateway="192.168.122.1",
             mac="52:54:00:aa:bb:cc")
    dhcp = next(i for i, s in enumerate(issued)
                if "INPUT 1 -m mac --mac-source 52:54:00:aa:bb:cc -p udp --dport 67 -j ACCEPT" in s)
    anti = next(i for i, s in enumerate(issued)
                if "INPUT 1 -m mac --mac-source 52:54:00:aa:bb:cc ! -s 192.168.122.5 -j DROP" in s)
    assert dhcp > anti   # inserted LATER at pos 1 → ends up ABOVE the anti-spoof in the chain


def test_apply_installs_sibling_spoof_complement(monkeypatch):
    eg = LibvirtEgress(sudo=False)  # routing=None → direct exit, no routing commands
    issued = []

    def fake_ipt(*a, **k):
        issued.append(" ".join(a))
        # `-D` is delete-by-match: remove()'s `while ...returncode == 0` jump-deletion loop must see a
        # nonzero ("rule not found") to terminate — return rc 1 for deletes, rc 0 for -N/-A/-I/-F/-X.
        return subprocess.CompletedProcess(list(a), 1 if "-D" in a else 0, "", "")

    monkeypatch.setattr(eg, "_ipt_run", fake_ipt)
    monkeypatch.setattr(eg, "_priv",
                        lambda argv, **k: issued.append(" ".join(argv)) or subprocess.CompletedProcess(argv, 0, "", ""))
    eg.apply("192.168.122.5", VmEgressPolicy(exit_driver="direct"), gateway="192.168.122.1",
             mac="52:54:00:aa:bb:cc")
    # a sibling VM spoofing worker_ip from a DIFFERENT mac is dropped on both FORWARD and INPUT
    assert any("FORWARD 1 -s 192.168.122.5 -m mac ! --mac-source 52:54:00:aa:bb:cc -j DROP" in s for s in issued)
    assert any("INPUT 1 -s 192.168.122.5 -m mac ! --mac-source 52:54:00:aa:bb:cc -j DROP" in s for s in issued)


def test_v6_drop_raises_on_real_rejection(monkeypatch):
    # a working v6 firewall that REFUSES the drop = a live v6 bypass → must fail closed (raise).
    import subprocess
    eg = LibvirtEgress(sudo=False)
    monkeypatch.setattr(eg, "_priv",
                        lambda argv, **k: subprocess.CompletedProcess(argv, 1, "", "Bad rule (does a matching rule exist?)"))
    with pytest.raises(RuntimeError, match="v6 fail-closed"):
        eg._v6_drop("FORWARD", "52:54:00:aa:bb:cc")


def test_v6_drop_tolerates_absent_v6_stack(monkeypatch):
    # a host with no usable IPv6 filter table has no v6 path to bypass — tolerate (don't reap workers).
    import subprocess
    eg = LibvirtEgress(sudo=False)
    monkeypatch.setattr(eg, "_priv",
                        lambda argv, **k: subprocess.CompletedProcess(argv, 3, "", "ip6tables v1.8: can't initialize ip6tables table `filter': Table does not exist"))
    eg._v6_drop("FORWARD", "52:54:00:aa:bb:cc")  # no raise


def test_v6_drop_ok_is_silent(monkeypatch):
    import subprocess
    eg = LibvirtEgress(sudo=False)
    monkeypatch.setattr(eg, "_priv", lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", ""))
    eg._v6_drop("INPUT", "52:54:00:aa:bb:cc")


def test_forward_gateway_dns_gated_on_allowlist():
    # an explicit egress_ports omitting 53 must withhold the gateway-DNS exemption too — a forwarded
    # /custom resolver can't bypass a no-DNS policy (parity with the INPUT chain).
    flat = _flat(forward_chain_rules("192.168.122.5",
                                     VmEgressPolicy(exit_driver="direct", egress_ports=(80, 443)),
                                     gateway="10.0.0.53"))
    assert not any("--dport 53 -j ACCEPT" in f for f in flat)
    # 53 in the allowlist (or unset) → gateway DNS accepted
    flat2 = _flat(forward_chain_rules("192.168.122.5",
                                      VmEgressPolicy(exit_driver="direct", egress_ports=(53, 80)),
                                      gateway="10.0.0.53"))
    assert any("-d 10.0.0.53 -p udp --dport 53 -j ACCEPT" in f for f in flat2)


def test_spoof_drop_deletes_sweep_all_macs():
    dump = "\n".join([
        "-A FORWARD -m mac --mac-source 52:54:00:aa:bb:cc ! -s 192.168.122.5/32 -j DROP",   # anti-spoof
        "-A FORWARD -s 192.168.122.5/32 -m mac ! --mac-source 52:54:00:de:ad:00 -j DROP",   # STALE sibling
        "-A FORWARD -s 192.168.122.50/32 -m mac ! --mac-source 52:54:00:11:22:33 -j DROP",  # other worker
        "-A FORWARD -s 192.168.122.5/32 -j BBVM_192_168_122_5",                              # the jump (no mac)
    ])
    dels = _spoof_drop_deletes("192.168.122.5", "FORWARD", dump)
    assert len(dels) == 2                          # both .5 spoof DROPs (any mac), not .50, not the jump
    assert all(d[:2] == ["iptables", "-D"] for d in dels)
    assert all("192.168.122.5/32" in " ".join(d) for d in dels)


def test_forward_inetsim_sink_exempt_from_port_allowlist():
    # inetsim sinks ALL ports to FakeNet — the sink dest must be ACCEPTed regardless of egress_ports,
    # else non-web malware ports (DNATed to the sink) hit the allowlist DROP and never reach FakeNet.
    pol = VmEgressPolicy(exit_driver="inetsim", egress_ports=(80, 443))
    flat = _flat(forward_chain_rules("192.168.122.5", pol, gateway="192.168.122.1",
                                     sink_addr="172.28.100.1"))
    assert any("-d 172.28.100.1 -j ACCEPT" in f for f in flat)
    sink_i = next(i for i, f in enumerate(flat) if "-d 172.28.100.1 -j ACCEPT" in f)
    assert sink_i < len(flat) - 1 and flat[-1].endswith("-j DROP")   # before the catch-all drop


def test_flush_conntrack_both_directions(monkeypatch):
    eg = LibvirtEgress(sudo=False)
    calls = []
    monkeypatch.setattr(eg, "_priv",
                        lambda argv, **k: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    eg._flush_conntrack("192.168.122.5")
    assert ["conntrack", "-D", "-s", "192.168.122.5"] in calls
    assert ["conntrack", "-D", "-d", "192.168.122.5"] in calls


def test_flush_conntrack_tolerates_missing_binary(monkeypatch):
    eg = LibvirtEgress(sudo=False)

    def boom(argv, **k):
        raise FileNotFoundError("conntrack")

    monkeypatch.setattr(eg, "_priv", boom)
    eg._flush_conntrack("192.168.122.5")   # conntrack(8) absent → best-effort, must not raise


def test_run_tolerates_missing_binary(monkeypatch):
    # _run must turn a missing binary (e.g. ip6tables on an IPv4-only host) into a nonzero result, not
    # an uncaught FileNotFoundError — else remove()'s v6 deletes (issued BEFORE the IPv4 cleanup) would
    # abort teardown and leak the IPv4 rules.
    import blastbox.host.runtime.libvirt_egress as eg_mod

    def no_binary(args, **k):
        raise FileNotFoundError(2, "No such file or directory", args[0])

    monkeypatch.setattr(eg_mod.subprocess, "run", no_binary)
    cp = eg_mod._run(["ip6tables", "-D", "FORWARD", "-j", "DROP"])
    assert cp.returncode == 127        # nonzero → check=False deletes no-op, teardown continues


def test_remove_continues_to_ipv4_cleanup_when_ip6tables_absent(monkeypatch):
    # End-to-end through the REAL _run: with ip6tables absent, remove() must still issue the IPv4
    # anti-spoof/chain deletes (the v6 deletes are emitted first and must not abort teardown).
    import blastbox.host.runtime.libvirt_egress as eg_mod
    eg = LibvirtEgress(sudo=False)               # no sudo prefix → args[0] is the binary
    seen: list[list[str]] = []

    def fake_subprocess_run(args, **k):
        seen.append(args)
        if args and args[0] == "ip6tables":
            raise FileNotFoundError(2, "No such file or directory", "ip6tables")
        return subprocess.CompletedProcess(args, 1, "", "")   # IPv4 deletes: "not found" no-op

    monkeypatch.setattr(eg_mod.subprocess, "run", fake_subprocess_run)
    eg.remove("192.168.122.8", mac="52:54:00:aa:bb:cc")       # must NOT raise
    assert any(a[0] == "ip6tables" for a in seen)             # v6 delete was attempted (and tolerated)
    assert any(a[0] == "iptables" and "-D" in a for a in seen)  # IPv4 cleanup STILL ran afterwards


def test_forward_inetsim_block_internal_exempts_sink():
    # inetsim DNATs everything to the RFC1918 FakeNet sink; without the exemption block_internal would
    # DROP the very traffic it's meant to sink. The sink ACCEPT must precede the internal DROPs.
    pol = VmEgressPolicy(exit_driver="inetsim", block_internal=True)
    flat = _flat(forward_chain_rules("192.168.122.9", pol, gateway="192.168.122.1",
                                     sink_addr="172.28.100.1"))
    assert any("-d 172.28.100.1 -j ACCEPT" in f for f in flat)
    sink_i = next(i for i, f in enumerate(flat) if "-d 172.28.100.1 -j ACCEPT" in f)
    drops = [i for i, f in enumerate(flat) if f.endswith("-j DROP") and " -d " in f]
    assert drops and sink_i < min(drops)


def test_routing_tor_block_internal_returns_internal_before_redirect():
    rt = ExitRouting()
    flat = [" ".join(c) for c in routing_commands("192.168.122.5", "tor", rt, None, block_internal=True)]
    ret = [i for i, f in enumerate(flat) if "-p tcp -j RETURN" in f]                       # internal RETURNs
    red = [i for i, f in enumerate(flat) if "REDIRECT --to-ports" in f and "--dport 53" not in f]
    assert ret and red and max(ret) < min(red)        # internal RETURNs precede the TransPort REDIRECT
    # default (block_internal off) installs no internal RETURNs
    flat2 = [" ".join(c) for c in routing_commands("192.168.122.5", "tor", rt)]
    assert not any("-p tcp -j RETURN" in f for f in flat2)


def test_tor_teardown_inverts_block_internal_returns():
    td = [" ".join(c) for c in routing_teardown_commands("192.168.122.5", "tor", ExitRouting(),
                                                         None, block_internal=True)]
    assert any("-D PREROUTING" in f and "-p tcp -j RETURN" in f for f in td)


def test_input_chain_direct_allows_host_resolver_dns_only():
    pol = VmEgressPolicy(exit_driver="direct")
    flat = _flat(input_chain_rules("192.168.122.9", pol, gateway="192.168.122.1", routing=None))
    c = "BBVMIN_192_168_122_9"
    assert flat[0] == f"-A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"  # agent return
    assert f"-A {c} -p udp --dport 67 -j ACCEPT" in flat                              # DHCP renew
    assert f"-A {c} -d 192.168.122.1 -p udp --dport 53 -j ACCEPT" in flat             # host resolver
    assert f"-A {c} -d 192.168.122.1 -p tcp --dport 53 -j ACCEPT" in flat
    assert flat[-1] == f"-A {c} -j DROP"                                              # everything else


def test_input_chain_vpn_drops_host_resolver_dns():
    # the DNS leak fix: a tunneled exit must NOT be able to resolve via the host's clearnet dnsmasq.
    flat = _flat(input_chain_rules("192.168.122.9", VmEgressPolicy(exit_driver="openvpn"),
                                   gateway="192.168.122.1", routing=None))
    assert not any("--dport 53" in f for f in flat)   # no host-resolver DNS exemption at all
    assert flat[-1].endswith("-j DROP")


def test_input_chain_none_reaches_no_host_service():
    flat = _flat(input_chain_rules("10.0.0.5", VmEgressPolicy(exit_driver="none"),
                                   gateway="10.0.0.1", routing=None))
    # only established (agent) + DHCP survive; no DNS, then drop.
    assert any("ESTABLISHED,RELATED -j ACCEPT" in f for f in flat)
    assert any("--dport 67 -j ACCEPT" in f for f in flat)
    assert not any("--dport 53" in f for f in flat)
    assert flat[-1].endswith("-j DROP")


def test_input_chain_tor_accepts_redirect_targets():
    rt = ExitRouting(tor_trans_port=9040, tor_dns_port=9053)
    flat = _flat(input_chain_rules("192.168.122.9", VmEgressPolicy(exit_driver="tor"),
                                   gateway="192.168.122.1", routing=rt))
    # tor REDIRECTs land DNS+TCP on the host's tor ports (post-NAT, host-destined) — accept those,
    # not raw :53 (that would resolve outside tor).
    assert any("-p udp --dport 9053 -j ACCEPT" in f for f in flat)
    assert any("-p tcp --dport 9040 -j ACCEPT" in f for f in flat)
    assert not any("--dport 53 " in f or f.endswith("--dport 53") for f in flat)


def test_input_chain_inetsim_accepts_fakenet_listener():
    rt = ExitRouting(fakenet_addr="172.28.100.1")
    flat = _flat(input_chain_rules("192.168.122.9", VmEgressPolicy(exit_driver="inetsim"),
                                   gateway="192.168.122.1", routing=rt))
    assert any("-d 172.28.100.1 -j ACCEPT" in f for f in flat)


def test_nat_chain_deletes_sweep_redirects_regardless_of_port():
    # REDIRECTs to DIFFERENT tor ports (a port changed between incarnations) are ALL swept by source IP
    dump = "\n".join([
        "-P PREROUTING ACCEPT",
        "-A PREROUTING -s 192.168.122.50/32 -p tcp -j REDIRECT --to-ports 9040",        # old TransPort
        "-A PREROUTING -s 192.168.122.50/32 -p tcp -j REDIRECT --to-ports 19040",       # NEW TransPort
        "-A PREROUTING -s 192.168.122.50/32 -p udp --dport 53 -j REDIRECT --to-ports 9053",  # DNSPort
        "-A PREROUTING -s 192.168.122.5/32 -p tcp -j REDIRECT --to-ports 9040",         # other worker
    ])
    dels = _nat_chain_deletes("192.168.122.50", "PREROUTING", ("REDIRECT", "DNAT"), dump)
    assert len(dels) == 3                # all .50 redirects regardless of --to-ports, not .5
    assert all("192.168.122.50/32" in " ".join(d) for d in dels)
    assert any("9053" in " ".join(d) for d in dels)       # the DNS→DNSPort redirect is swept too


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
    # per-gateway table default via the router VM on the leg (table id = base + low-24-bits of gw IP)
    assert any("route replace default via 10.99.0.2 dev br-routers table 174260226" in c for c in cmds)
    # local exemption + select the per-gateway table
    assert any("rule add from 192.168.122.5 to 192.168.122.0/24 lookup main" in c for c in cmds)
    assert any("rule add from 192.168.122.5 lookup 174260226" in c for c in cmds)
    # SNAT onto the leg so the router replies to this host
    assert any("POSTROUTING -s 192.168.122.5 -o br-routers -j MASQUERADE" in c for c in cmds)


def test_routing_local_exemption_uses_worker_cidr_override():
    # a non-/24 worker net must keep host/agent traffic on `main` across the WHOLE subnet, not just
    # the worker IP's /24 — else the bridge/agent address outside that /24 gets steered to the VPN.
    R = ExitRouting(vpn_table="vpn", vpn_tun="tun0", worker_cidr="192.168.0.0/16")
    flat = _flat(routing_commands("192.168.122.5", "openvpn", R))
    assert any("from 192.168.122.5 to 192.168.0.0/16 lookup main" in c for c in flat)
    # default (no override) keeps the /24 derivation (libvirt default net)
    flat2 = _flat(routing_commands("192.168.122.5", "openvpn", ExitRouting()))
    assert any("to 192.168.122.0/24 lookup main" in c for c in flat2)


def test_routing_next_hop_table_id_avoids_collisions():
    # the full-IP table id must separate gateways differing in ANY octet — last-octet-only collided
    # .0.2/.1.2; 16-bit collided 10.98/10.99; 24-bit collided 10.99/172.99 (1st octet). All distinct now.
    def _table(gw):
        cmds = _flat(routing_commands("192.168.122.5", "openvpn",
                                      ExitRouting(gateway=gw, leg="br-routers")))
        return next(c.split("table ")[1] for c in cmds if "route replace default" in c)
    gws = ("10.99.0.2", "10.99.1.2", "10.98.0.2", "10.99.0.3", "172.99.0.2")
    assert len({_table(gw) for gw in gws}) == len(gws)     # all distinct, incl. the cross-/8 pair
    assert _table("10.99.0.2") == "174260226"              # full IP as u32


def test_routing_next_hop_no_masquerade():
    R = ExitRouting(gateway="10.99.0.3", leg="br-routers", gateway_masquerade=False)
    cmds = _flat(routing_commands("192.168.122.5", "wireguard", R))
    assert not any("MASQUERADE" in c for c in cmds)
    assert any("route replace default via 10.99.0.3 dev br-routers table 174260227" in c for c in cmds)


def test_routing_next_hop_teardown_keeps_shared_route():
    R = ExitRouting(gateway="10.99.0.2", leg="br-routers")
    rm = _flat(routing_teardown_commands("192.168.122.5", "openvpn", R))
    # the shared per-gateway route must NOT be torn down (other workers/hosts use it)
    assert not any(c.startswith("ip route") for c in rm)
    # but the per-worker rules + masquerade are removed
    assert any("rule del from 192.168.122.5 lookup 174260226" in c for c in rm)
    assert any("POSTROUTING -s 192.168.122.5 -o br-routers -j MASQUERADE" in c and "-D" in c for c in rm)
