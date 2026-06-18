"""TDD tests for blastbox.host.netwire — pure builders for netd's SOCKS-tier netns wiring.

The exact command sequence was validated live on toolz2 (tun2socks 2.6.0, a dual-homed SOCKS5
proxy, internal worker bridge): fail-closed pre-check (no egress) → wire → HTTP 200 with the
exit IP = the proxy. This module is the pure, unit-testable form of those commands.
"""
from __future__ import annotations

import pytest

from blastbox.host.netwire import (
    TUN_ADDR,
    TUN_DEV,
    WireTarget,
    gateway_route_commands,
    leak_guard_rules,
    leak_guard_rules_v6,
    leakguard_from_inspect,
    socks_proxy_url,
    socks_resolv_conf,
    transproxy_redirect_rules,
    tun2socks_argv,
    tun_setup_commands,
    validate_socks_url,
    wire_target_from_inspect,
)


def _wire_inspect(*, mode="socks", job_id="J1", pid=4242):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.wire": mode, "blastbox.job_id": job_id}},
        "State": {"Pid": pid, "Running": True},
    }


# --------------------------------------------------------------------------- proxy URL
def test_proxy_url_no_auth():
    assert socks_proxy_url("172.30.0.10:1080", user=None, password=None) == \
        "socks5://172.30.0.10:1080"


def test_proxy_url_with_auth():
    assert socks_proxy_url("10.0.0.5:1080", user="bb", password="bb") == \
        "socks5://bb:bb@10.0.0.5:1080"


@pytest.mark.parametrize("bad", ["", "noport", "h:p:x", "host:notaport", "host:99999", " h:1"])
def test_proxy_url_rejects_bad_endpoint(bad):
    with pytest.raises(ValueError):
        socks_proxy_url(bad, user=None, password=None)


# --------------------------------------------------------------------------- validate_socks_url
def test_validate_socks_url_no_auth_roundtrips():
    assert validate_socks_url("socks5://172.30.0.40:9050") == "socks5://172.30.0.40:9050"


def test_validate_socks_url_with_auth_roundtrips():
    assert validate_socks_url("socks5://bb:bb@10.0.0.5:1080") == "socks5://bb:bb@10.0.0.5:1080"


@pytest.mark.parametrize("bad", [
    "http://h:1",                  # wrong scheme
    "socks5://h:1 ",               # trailing whitespace (would split into a stray arg)
    " socks5://h:1",               # leading whitespace
    "socks5://nocreds@h:1",        # '@' but no user:pass
    "socks5://a b:c@h:1",          # space in creds
    "socks5://h:notaport",         # bad port
    "socks5://h:1:2",              # extra colon in endpoint
])
def test_validate_socks_url_rejects_malformed(bad):
    with pytest.raises(ValueError):
        validate_socks_url(bad)


def test_proxy_url_rejects_injection_in_creds():
    # creds land in a URL that becomes a process arg; a space/newline/@ must be rejected.
    with pytest.raises(ValueError):
        socks_proxy_url("h:1", user="a b", password="x")
    with pytest.raises(ValueError):
        socks_proxy_url("h:1", user="a", password="p@ss")


# --------------------------------------------------------------------------- tun2socks argv
def test_tun2socks_argv_proven_shape():
    argv = tun2socks_argv("socks5://bb:bb@172.30.0.10:1080")
    assert argv == [
        "tun2socks", "-device", f"tun://{TUN_DEV}",
        "-proxy", "socks5://bb:bb@172.30.0.10:1080",
        "-loglevel", "info",
    ]


def test_tun2socks_rejects_warning_loglevel():
    # 'warning' is fatal to tun2socks (must be silent/error/warn/info/debug) — caught early.
    with pytest.raises(ValueError):
        tun2socks_argv("socks5://h:1", loglevel="warning")


def test_tun2socks_accepts_valid_loglevels():
    for lvl in ("silent", "error", "warn", "info", "debug"):
        assert tun2socks_argv("socks5://h:1", loglevel=lvl)[-1] == lvl


# --------------------------------------------------------------------------- tun setup commands
def test_tun_setup_commands_proven_sequence():
    cmds = tun_setup_commands()
    assert cmds == [
        ["ip", "addr", "add", TUN_ADDR, "dev", TUN_DEV],
        ["ip", "link", "set", TUN_DEV, "up"],
        ["ip", "route", "replace", "default", "dev", TUN_DEV],
    ]


def test_tun_setup_uses_fakenet_addr_off_rfc1918():
    # 198.18.0.0/15 (benchmark range) avoids colliding with the worker's RFC1918 bridge IP.
    assert TUN_ADDR.startswith("198.18.")


# --------------------------------------------------------------------------- resolv.conf
def test_socks_resolv_forces_tcp():
    # No-UDP-ASSOCIATE SOCKS (tor included) can't carry UDP DNS → DNS MUST go over TCP.
    out = socks_resolv_conf("1.1.1.1")
    assert "nameserver 1.1.1.1" in out
    assert "options use-vc" in out


def test_socks_resolv_rejects_non_ip():
    with pytest.raises(ValueError):
        socks_resolv_conf("not-an-ip")


# --------------------------------------------------------------------------- wire_target
def test_wire_target_built_for_socks_worker():
    wt = wire_target_from_inspect(_wire_inspect(pid=9999))
    assert isinstance(wt, WireTarget)
    assert wt.mode == "socks" and wt.job_id == "J1" and wt.pid == 9999
    assert wt.socks_proxy == ""  # no per-worker proxy label → use netd's global


def test_wire_target_extracts_per_worker_socks_proxy():
    insp = _wire_inspect(pid=5)
    insp["Config"]["Labels"]["blastbox.net.socks-proxy"] = "socks5://172.30.0.40:9050"
    wt = wire_target_from_inspect(insp)
    assert wt is not None and wt.socks_proxy == "socks5://172.30.0.40:9050"


def test_wire_target_none_without_label():
    insp = _wire_inspect()
    insp["Config"]["Labels"] = {"blastbox.job_id": "J1"}
    assert wire_target_from_inspect(insp) is None


def test_wire_target_none_for_unknown_mode():
    assert wire_target_from_inspect(_wire_inspect(mode="teleport")) is None


def test_wire_target_none_without_pid():
    # A gVisor worker exposes no host pid (0) → not wireable (gVisor is SOCKS-excluded).
    insp = _wire_inspect()
    insp["State"]["Pid"] = 0
    assert wire_target_from_inspect(insp) is None


def test_wire_target_accepts_vpn_mode():
    wt = wire_target_from_inspect(_wire_inspect(mode="vpn", pid=321))
    assert wt is not None and wt.mode == "vpn" and wt.pid == 321


def test_wire_target_accepts_inspect_mode():
    wt = wire_target_from_inspect(_wire_inspect(mode="inspect", pid=654))
    assert wt is not None and wt.mode == "inspect" and wt.pid == 654


def test_wire_target_extracts_worker_ip_for_transproxy():
    insp = _wire_inspect(mode="transproxy", pid=99)
    insp["NetworkSettings"] = {"Networks": {"bb-socks": {"IPAddress": "172.30.0.7"}}}
    wt = wire_target_from_inspect(insp)
    assert wt is not None and wt.mode == "transproxy" and wt.worker_ip == "172.30.0.7"


# --------------------------------------------------------------------------- transproxy (CAPE tor)
def test_transproxy_rules_redirect_tcp_and_dns_keyed_on_worker_ip():
    rules = transproxy_redirect_rules("172.30.0.7", trans_port=9040, dns_port=5353, add=True)
    # 3 nat REDIRECTs (udp53, tcp53, tcp-syn) + 1 filter FORWARD DROP, all -s the worker IP
    assert all("172.30.0.7" in r for r in rules) and len(rules) == 4
    # nat rules are APPENDED (-A) so the DNS :53 rules stay ABOVE the TCP-SYN catch-all in-chain.
    assert ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", "172.30.0.7", "-p", "udp",
            "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"] == rules[0]
    assert rules[1][:6] == ["iptables", "-t", "nat", "-A", "PREROUTING", "-s"] and "--dport" in rules[1]
    assert rules[2][-3:] == ["REDIRECT", "--to-ports", "9040"] and "--syn" in rules[2]
    # the FORWARD DROP is inserted (-I) at the head for leak-guard precedence
    assert rules[3] == ["iptables", "-t", "filter", "-I", "FORWARD", "-s", "172.30.0.7", "-j", "DROP"]


def test_transproxy_rules_teardown_is_symmetric_delete():
    add = transproxy_redirect_rules("10.0.0.5", trans_port=9040, dns_port=5353, add=True)
    rm = transproxy_redirect_rules("10.0.0.5", trans_port=9040, dns_port=5353, add=False)
    # teardown is all -D; the add ops are -A (nat) / -I (filter). Same match spec once the op token
    # is stripped, so teardown removes exactly what wiring installed.
    assert all(("-A" in a or "-I" in a) and ("-D" in d) for a, d in zip(add, rm))
    assert [[t for t in r if t not in ("-A", "-I", "-D")] for r in add] == \
           [[t for t in r if t not in ("-A", "-I", "-D")] for r in rm]


@pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.1; rm -rf"])
def test_transproxy_rules_reject_bad_ip(bad):
    with pytest.raises(ValueError):
        transproxy_redirect_rules(bad, trans_port=9040, dns_port=5353)


# --------------------------------------------------------------------------- non-TCP leak guard
def _lg(mode="strict", pid=77):
    return {
        "Config": {"Labels": {"blastbox.net.leakguard": mode, "blastbox.job_id": "J"}},
        "State": {"Pid": pid, "Running": True},
    }


def test_leakguard_from_inspect_strict_and_dns():
    assert leakguard_from_inspect(_lg("strict", 5)) == (5, False)
    assert leakguard_from_inspect(_lg("dns", 9)) == (9, True)


def test_leakguard_from_inspect_none_without_label_or_pid():
    assert leakguard_from_inspect({"Config": {"Labels": {}}, "State": {"Pid": 5}}) is None
    assert leakguard_from_inspect(_lg("bogus")) is None
    assert leakguard_from_inspect(_lg("strict", 0)) is None  # gVisor: no host pid


def test_leak_guard_rules_strict_drops_all_non_tcp():
    rules = leak_guard_rules(allow_udp_dns=False)
    # ACCEPT lo, ACCEPT tcp, LOG non-tcp, DROP non-tcp — no udp:53 accept
    assert ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"] == rules[0]
    assert ["iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"] == rules[1]
    assert not any("--dport" in r and "53" in r for r in rules)
    assert rules[-1] == ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"]
    assert any("LOG" in r and "blastbox-leak-drop " in r for r in rules)


def test_leak_guard_rules_dns_mode_allows_udp_53():
    rules = leak_guard_rules(allow_udp_dns=True)
    assert ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"] in rules
    assert rules[-1] == ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"]


def test_leak_guard_rules_v6_fails_closed():
    # The proxy tiers egress over IPv4 only — v6 has NO legitimate path (incl. DNS), so v6 OUTPUT
    # is dropped entirely except loopback. All rules are ip6tables (iptables can't express v6).
    rules = leak_guard_rules_v6()
    assert all(r[0] == "ip6tables" for r in rules)
    assert ["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"] == rules[0]
    assert rules[-1] == ["ip6tables", "-A", "OUTPUT", "-j", "DROP"]
    # no udp:53 carve-out even for the tor/dns case (tor's DNSPort REDIRECT is v4)
    assert not any("--dport" in r for r in rules)
    assert any("LOG" in r and "blastbox-leak-drop6 " in r for r in rules)


def test_transproxy_rules_reject_bad_port():
    with pytest.raises(ValueError):
        transproxy_redirect_rules("10.0.0.1", trans_port=70000, dns_port=5353)


# --------------------------------------------------------------------------- gateway (vpn) route
def test_gateway_route_replaces_default_via_gw():
    assert gateway_route_commands("172.31.0.10") == \
        [["ip", "route", "replace", "default", "via", "172.31.0.10"]]


def test_gateway_route_rejects_non_ip():
    with pytest.raises(ValueError):
        gateway_route_commands("not-an-ip")
    with pytest.raises(ValueError):
        gateway_route_commands("10.0.0.1 ; rm -rf")
