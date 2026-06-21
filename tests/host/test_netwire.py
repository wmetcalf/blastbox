"""TDD tests for blastbox.host.netwire — pure builders for netd's SOCKS-tier netns wiring.

The exact command sequence was validated live on toolz2 (tun2socks 2.6.0, a dual-homed SOCKS5
proxy, internal worker bridge): fail-closed pre-check (no egress) → wire → HTTP 200 with the
exit IP = the proxy. This module is the pure, unit-testable form of those commands.
"""
from __future__ import annotations

import pytest

from blastbox.host.netwire import (
    BLOCK_INTERNAL_LABEL,
    EGRESS_PORTS_LABEL,
    TUN_ADDR,
    TUN_DEV,
    WireTarget,
    egress_filter_from_inspect,
    gateway_route_commands,
    leak_guard_rules,
    leak_guard_rules_v6,
    leakguard_from_inspect,
    parse_egress_ports,
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


def test_leakguard_from_inspect_modes():
    # (pid, allow_udp_dns, drop_non_tcp)
    assert leakguard_from_inspect(_lg("strict", 5)) == (5, False, True)
    assert leakguard_from_inspect(_lg("dns", 9)) == (9, True, True)
    assert leakguard_from_inspect(_lg("allip", 7)) == (7, False, False)  # all-IP tier: keep non-TCP


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


# ------------------------------------------------------------ egress port allowlist + internal block
# Two composable personality knobs that harden ANY egress tier:
#   egress_ports=53 80 443  → web-only L4 allowlist (DNS/HTTP/HTTPS), drop everything else.
#   block_internal=1        → drop RFC1918 + link-local/metadata destinations (no SSRF/lateral).
# Proven live (toolz3, 2026-06-20): worker egressed via PIA on 53/80/443 only; non-web + internal
# blocked. These build the worker-netns OUTPUT rules that express exactly that.


def test_parse_egress_ports_accepts_comma_or_whitespace():
    assert parse_egress_ports("53,80,443") == (53, 80, 443)
    assert parse_egress_ports("53 80 443") == (53, 80, 443)
    assert parse_egress_ports("53, 80   443") == (53, 80, 443)


def test_parse_egress_ports_skips_invalid_and_out_of_range():
    # a typo'd / non-numeric / out-of-range token is dropped, not fatal.
    assert parse_egress_ports("53 nope 80 0 70000 443") == (53, 80, 443)


def test_parse_egress_ports_empty_is_none():
    assert parse_egress_ports("") is None
    assert parse_egress_ports("   ") is None
    assert parse_egress_ports(None) is None
    assert parse_egress_ports("bogus 99999") is None  # nothing valid survives


def test_leak_guard_rules_web_only_allowlist():
    rules = leak_guard_rules(allow_udp_dns=True, allowed_ports=(53, 80, 443))
    # DNS over UDP allowed; TCP restricted to the allowlist via multiport.
    assert ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"] in rules
    assert ["iptables", "-A", "OUTPUT", "-p", "tcp", "-m", "multiport",
            "--dports", "53,80,443", "-j", "ACCEPT"] in rules
    # NO blanket "ACCEPT -p tcp" (that would defeat the allowlist).
    assert ["iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"] not in rules


def test_leak_guard_rules_web_only_drops_everything_unlisted():
    # Web-only ends in a CATCH-ALL drop (not the legacy "! -p tcp"): a non-allowed TCP port AND any
    # non-TCP both fall through to DROP. The audit LOG immediately precedes it.
    rules = leak_guard_rules(allow_udp_dns=True, allowed_ports=(80, 443))
    assert rules[-1] == ["iptables", "-A", "OUTPUT", "-j", "DROP"]
    assert rules[-2] == ["iptables", "-A", "OUTPUT", "-m", "limit", "--limit", "10/min",
                         "-j", "LOG", "--log-prefix", "blastbox-leak-drop ", "--log-level", "4"]
    # the legacy non-tcp-only DROP must NOT be present in web-only mode.
    assert ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"] not in rules


def test_leak_guard_rules_block_internal_drops_rfc1918_before_accepts():
    rules = leak_guard_rules(allow_udp_dns=True, allowed_ports=(80, 443), block_internal=True)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"):
        assert ["iptables", "-A", "OUTPUT", "-d", net, "-j", "DROP"] in rules
    # every internal DROP must precede the first non-loopback ACCEPT (internal :443 dropped, not allowed).
    first_accept = next(i for i, r in enumerate(rules) if "ACCEPT" in r and "lo" not in r)
    last_block = max(i for i, r in enumerate(rules) if "-d" in r and "DROP" in r)
    assert last_block < first_accept


def test_leak_guard_rules_block_internal_composes_with_legacy_tcp_tier():
    # block_internal with NO allowed_ports → legacy TCP-only tier PLUS the internal drops.
    rules = leak_guard_rules(allow_udp_dns=False, block_internal=True)
    assert ["iptables", "-A", "OUTPUT", "-d", "192.168.0.0/16", "-j", "DROP"] in rules
    assert ["iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"] in rules   # still TCP-only tier
    assert rules[-1] == ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"]


def test_leak_guard_rules_legacy_unchanged_when_no_new_knobs():
    # Regression: the existing callers pass neither knob → byte-identical to the historical output.
    assert leak_guard_rules(allow_udp_dns=False) == [
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-m", "limit", "--limit", "10/min",
         "-j", "LOG", "--log-prefix", "blastbox-leak-drop ", "--log-level", "4"],
        ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"],
    ]


def _egress_inspect(*, ports=None, block=None):
    labels = {"blastbox.job_id": "J"}
    if ports is not None:
        labels[EGRESS_PORTS_LABEL] = ports
    if block is not None:
        labels[BLOCK_INTERNAL_LABEL] = block
    return {"Config": {"Labels": labels}, "State": {"Pid": 7, "Running": True}}


def test_egress_filter_from_inspect_reads_labels():
    assert egress_filter_from_inspect(_egress_inspect(ports="53,80,443", block="1")) == \
        ((53, 80, 443), True)


def test_egress_filter_from_inspect_absent_is_none_false():
    assert egress_filter_from_inspect(_egress_inspect()) == (None, False)
    assert egress_filter_from_inspect({"Config": {"Labels": {}}}) == (None, False)
    assert egress_filter_from_inspect({}) == (None, False)


def test_egress_filter_from_inspect_block_internal_falsey():
    assert egress_filter_from_inspect(_egress_inspect(block="0")) == (None, False)


def test_parse_egress_ports_dedups_preserving_order():
    # Duplicate ports waste multiport slots (which are capped at 15) — dedup, keep first-seen order.
    assert parse_egress_ports("80,443,80,53,443") == (80, 443, 53)


def test_leak_guard_rules_web_only_chunks_over_multiport_limit():
    # iptables multiport caps at 15 ports per rule; >15 ports must split into multiple ACCEPT rules
    # (else iptables rejects the rule and the worker fails closed with no egress).
    ports = tuple(range(1000, 1020))  # 20 ports
    rules = leak_guard_rules(allow_udp_dns=False, allowed_ports=ports)
    multiport = [r for r in rules if "multiport" in r]
    assert len(multiport) == 2
    for r in multiport:
        assert 1 <= len(r[r.index("--dports") + 1].split(",")) <= 15
    covered = [int(p) for r in multiport for p in r[r.index("--dports") + 1].split(",")]
    assert covered == list(ports)  # every port covered, order preserved


def test_leak_guard_rules_web_only_dns_only_when_53_listed():
    # UDP/53 is allowed iff 53 is in the allowlist — an explicit list that omits 53 must not get DNS.
    assert any("udp" in r for r in leak_guard_rules(allow_udp_dns=True, allowed_ports=(53, 80, 443)))
    assert not any("udp" in r for r in leak_guard_rules(allow_udp_dns=True, allowed_ports=(80, 443)))


def test_leak_guard_rules_block_internal_only_allip_preserves_non_tcp():
    # An all-IP tier (drop_non_tcp=False) that only blocks internal must keep non-internal UDP/ICMP:
    # just loopback ACCEPT + the internal DROPs, no protocol match at all.
    rules = leak_guard_rules(allow_udp_dns=False, block_internal=True, drop_non_tcp=False)
    assert rules[0] == ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]
    assert ["iptables", "-A", "OUTPUT", "-d", "10.0.0.0/8", "-j", "DROP"] in rules
    assert ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"] not in rules
    assert ["iptables", "-A", "OUTPUT", "-j", "DROP"] not in rules  # no catch-all
    assert not any("-p" in r for r in rules)  # nothing matched/dropped by protocol


def test_egress_filter_from_inspect_tolerates_none_label_values():
    # Labels come from `docker inspect` (Mapping[str, object]) — a present-but-None value must not
    # crash or be mis-parsed as the string "None".
    inspect = {"Config": {"Labels": {
        EGRESS_PORTS_LABEL: None, BLOCK_INTERNAL_LABEL: None, "blastbox.job_id": "J"}}}
    assert egress_filter_from_inspect(inspect) == (None, False)


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
