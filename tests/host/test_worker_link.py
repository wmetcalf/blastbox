"""Pure tests for ``blastbox worker-link`` (host half): validation, allocation, rendering, and
its COEXISTENCE with the egress overlay.

The egress compatibility block at the bottom is the reason this file exists as much as the
rest: worker-link is a second WireGuard overlay on hosts and workers that may already run the
egress tier, and the two point in opposite trust directions. Each of those tests names the
specific way they could interfere.
"""
from __future__ import annotations

import ipaddress
import json

import pytest

from blastbox.host.worker_link import (
    NFT_TABLE,
    RFC1918,
    JoinBundle,
    WorkerLinkConfig,
    firewall_in_force,
    firewall_unit,
    host_firewall_nft,
    host_wg_config,
    link_peer_stanza,
    next_free_ip,
    parse_endpoint,
)

KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _chain(ruleset: str, name: str) -> str:
    """The body of one chain (up to its closing tab-brace; sets contain braces too)."""
    return ruleset.split(f"chain {name} {{\n", 1)[1].split("\n\t}", 1)[0]


def _cfg(**kw) -> WorkerLinkConfig:
    kw.setdefault("endpoint", "gw.example.org")
    return WorkerLinkConfig(**kw)


# ------------------------------------------------------------------------------ config

def test_defaults_are_the_documented_ones():
    c = WorkerLinkConfig()
    assert (c.wg_iface, c.overlay_net, c.host_ip, c.wg_port, c.agent_port) == (
        "wtwg0", "10.78.0.0/24", "10.78.0.1", 51822, 8765)


@pytest.mark.parametrize("iface", ["", "wt wg0", "wtwg0;rm", "a" * 16, "-wt", "../x"])
def test_unsafe_or_overlong_interface_names_are_refused(iface):
    # The name reaches argv, a filename and an nft string; 15 is IFNAMSIZ-1 (and wg-quick's
    # own limit on macOS).
    with pytest.raises(ValueError):
        WorkerLinkConfig(wg_iface=iface)


@pytest.mark.parametrize("net", ["203.0.113.0/24", "100.64.0.0/24", "fd00::/64", "10.78.0.0/30",
                                 "10.0.0.0/15", "nonsense"])
def test_overlay_must_be_a_sane_rfc1918_v4_prefix(net):
    with pytest.raises(ValueError):
        WorkerLinkConfig(overlay_net=net)


def test_every_allowed_overlay_range_is_one_the_job_leak_guard_already_blocks():
    """The leak guard's block_internal drops netwire._INTERNAL_NETS. Restricting the overlay to
    RFC 1918 is what makes "a sample cannot reach the control link" true at that layer too,
    not only at the worker firewall. If either list changes, this must be re-decided."""
    from blastbox.host.netwire import _INTERNAL_NETS

    internal = [ipaddress.ip_network(n) for n in _INTERNAL_NETS]
    for block in RFC1918:
        assert any(ipaddress.ip_network(block).subnet_of(i) for i in internal), block


@pytest.mark.parametrize("host", ["10.78.0.0", "10.78.0.255", "10.79.0.1", "x"])
def test_host_ip_must_be_usable_inside_the_overlay(host):
    with pytest.raises(ValueError):
        WorkerLinkConfig(host_ip=host)


@pytest.mark.parametrize("port", [0, 65536, -1, "x"])
def test_ports_are_validated(port):
    with pytest.raises(ValueError):
        WorkerLinkConfig(wg_port=port)
    with pytest.raises(ValueError):
        WorkerLinkConfig(agent_port=port)


@pytest.mark.parametrize("src,why", [("0.0.0.0/0", "ANY"), ("10.78.0.0/16", "overlaps"),
                                     ("fe80::/10", "IPv4")])
def test_dispatcher_sources_cannot_open_the_link_to_everything(src, why):
    with pytest.raises(ValueError, match=why):
        WorkerLinkConfig(dispatcher_sources=(src,))


def test_env_round_trip_and_no_key_material():
    c = _cfg(dispatcher_sources=("172.18.0.0/16",), overlay_net="192.168.77.0/24")
    lines = c.to_env_lines()
    env = dict(line.split("=", 1) for line in lines)
    assert WorkerLinkConfig.from_env(env) == c
    text = "\n".join(lines).lower()
    for secret in ("private", "secret", "token", "key=", "pass"):
        assert secret not in text


@pytest.mark.parametrize("raw,want", [
    ("gw.example.org", ("gw.example.org", 51822)),
    ("GW.Example.org:4500", ("gw.example.org", 4500)),
    ("192.0.2.7", ("192.0.2.7", 51822)),
    ("[2001:db8::1]:51900", ("[2001:db8::1]", 51900)),
])
def test_endpoint_parsing(raw, want):
    assert parse_endpoint(raw) == want


@pytest.mark.parametrize("raw", ["", "http://gw:1", "gw:0", "gw:70000", "gw /x", "2001:db8::1",
                                 "-gw.example.org", "gw.example.org:1:2", "a b", "1.2.3"])
def test_bad_endpoints_are_refused(raw):
    # It lands in an `Endpoint =` line on every worker that joins.
    with pytest.raises(ValueError):
        parse_endpoint(raw)


# -------------------------------------------------------------------------- allocation

def test_next_free_ip_is_the_lowest_unused_and_skips_the_host():
    c = _cfg()
    assert next_free_ip(c, []) == "10.78.0.2"
    assert next_free_ip(c, ["10.78.0.2/32", "10.78.0.3"]) == "10.78.0.4"
    assert next_free_ip(c, ["garbage", "10.78.0.2/32"]) == "10.78.0.3"


def test_next_free_ip_reports_a_full_overlay():
    c = _cfg(overlay_net="10.78.0.0/29")     # .1 host, .2-.6 workers
    taken = [f"10.78.0.{i}" for i in range(2, 7)]
    with pytest.raises(RuntimeError, match="full"):
        next_free_ip(c, taken)


def test_member_refuses_the_host_and_out_of_overlay_addresses():
    c = _cfg()
    for bad in ("10.78.0.1", "10.78.1.2", "10.78.0.255", "10.78.0.0", "nope"):
        with pytest.raises(ValueError):
            c.member(bad)
    assert c.member(" 10.78.0.9 ") == "10.78.0.9"


# ------------------------------------------------------------------------------ wg config

def test_host_config_never_enables_forwarding():
    """Unlike the egress exit host, nothing is ever routed THROUGH this end."""
    conf = host_wg_config(_cfg(), "PRIV")
    assert "ip_forward" not in conf and "PostUp" not in conf and "PostDown" not in conf
    assert "Address = 10.78.0.1/24" in conf and "ListenPort = 51822" in conf


def test_peer_stanza_pins_the_worker_to_its_own_32():
    s = link_peer_stanza("mac1", "10.78.0.5", KEY_A, cfg=_cfg(), expires="2026-11-01T00:00:00+00:00")
    assert "\n# peer:mac1\n# expires:2026-11-01T00:00:00+00:00\n[Peer]\n" in s
    assert "AllowedIPs = 10.78.0.5/32\n" in s
    assert "Endpoint" not in s and "Keepalive" not in s      # the worker dials and keeps alive


@pytest.mark.parametrize("name,ip,key", [
    ("bad name", "10.78.0.5", KEY_A), ("mac1", "10.78.0.1", KEY_A),
    ("mac1", "10.99.0.5", KEY_A), ("mac1", "10.78.0.5", "A" * 43),
    ("mac1", "10.78.0.5", "A" * 44 + "AA=="),
])
def test_peer_stanza_validates_everything(name, ip, key):
    with pytest.raises(ValueError):
        link_peer_stanza(name, ip, key, cfg=_cfg())


def test_stanza_parses_back_through_the_shared_egress_helpers():
    """Worker-link reuses egress's # peer: parsing; the formats must agree byte-for-byte."""
    from blastbox.host.egress_apply import _peer_blocks, drop_peer_blocks

    c = _cfg()
    body = host_wg_config(c, "P") + link_peer_stanza("a", "10.78.0.2", KEY_A, cfg=c) \
        + link_peer_stanza("b", "10.78.0.3", KEY_B, cfg=c)
    assert _peer_blocks(body) == [("a", "10.78.0.2/32", KEY_A), ("b", "10.78.0.3/32", KEY_B)]
    left = drop_peer_blocks(body, ["a"])
    assert _peer_blocks(left) == [("b", "10.78.0.3/32", KEY_B)]
    assert left.startswith(host_wg_config(c, "P"))


# ------------------------------------------------------------------------------ firewall

def test_host_firewall_lets_only_the_host_open_the_agent_port():
    fw = host_firewall_nft(_cfg())
    assert f"table inet {NFT_TABLE} {{}}\ndelete table inet {NFT_TABLE}\n" in fw   # atomic replace
    out = _chain(fw, "output")
    assert 'oifname "wtwg0" ip saddr 10.78.0.1 ip daddr 10.78.0.0/24 tcp dport 8765 ct state new accept' in out
    assert out.strip().splitlines()[-1].strip() == 'oifname "wtwg0" drop'
    inp = _chain(fw, "input")
    # a worker can never start anything toward the host
    lines = [ln.strip() for ln in inp.strip().splitlines()]
    assert lines[1:4] == ['iifname "wtwg0" ct state established,related accept',
                          'iifname "wtwg0" drop',
                          'iifname != { "lo", "wtwg0" } ip daddr 10.78.0.0/24 drop']
    fwd = _chain(fw, "forward")
    # nothing is routed from a link peer; with no dispatcher source nothing is routed INTO it
    assert 'iifname "wtwg0" drop' in fwd and "ct state new accept" not in fwd
    assert "masquerade" not in fw and "ip_forward" not in fw


def test_a_containerised_dispatcher_is_admitted_and_masqueraded_only_from_its_source():
    fw = host_firewall_nft(_cfg(dispatcher_sources=("172.18.0.0/16", "172.19.0.0/16")))
    fwd = _chain(fw, "forward")
    assert ('oifname "wtwg0" ip saddr { 172.18.0.0/16, 172.19.0.0/16 } ip daddr 10.78.0.0/24 '
            'tcp dport 8765 ct state new accept') in fwd
    # worker-originated forwarding is dropped BEFORE the dispatcher accept can be reached
    assert fwd.index('iifname "wtwg0" drop') < fwd.index("ct state new accept")
    assert 'oifname "wtwg0" ip saddr { 172.18.0.0/16, 172.19.0.0/16 } masquerade' in fw
    assert "type nat hook postrouting priority srcnat" in fw


def test_every_base_chain_is_policy_accept_and_matches_only_the_link():
    """nftables requires EVERY base chain on a hook to accept, so an accept here cannot
    override docker's FORWARD drop, and a rule that is not scoped to the link interface would
    change verdicts for docker / egress traffic. Every rule names the link."""
    fw = host_firewall_nft(_cfg(dispatcher_sources=("172.18.0.0/16",)))
    rules = [ln.strip() for ln in fw.splitlines()
             if ln.startswith("\t\t") and not ln.strip().startswith("type ")]
    assert rules and all('"wtwg0"' in r for r in rules), rules
    assert fw.count("policy accept;") == 4


def test_firewall_in_force_reads_the_kernel_listing_not_the_file():
    fw = host_firewall_nft(_cfg(dispatcher_sources=("172.18.0.0/16",)))
    # The shape `nft list table` prints (the table without our preamble).
    listing = fw.split(f"delete table inet {NFT_TABLE}\n", 1)[1]
    assert firewall_in_force(listing, fw) == []
    # EVERY drop is required, not just one per chain
    for drop in ('\t\tiifname != { "lo", "wtwg0" } ip daddr 10.78.0.0/24 drop\n',
                 '\t\toifname "wtwg0" drop\n'):
        assert firewall_in_force(listing.replace(drop, "", 1), fw), drop
    unhooked = listing.replace("type filter hook output priority filter; policy accept;", "")
    assert any("output" in m and "declared" in m for m in firewall_in_force(unhooked, fw))
    assert len(firewall_in_force("", fw)) == 4
    # an accept slipped in ahead of the drops is not ours
    extra = listing.replace('\t\tiifname "wtwg0" drop\n',
                            '\t\tiifname "wtwg0" accept\n\t\tiifname "wtwg0" drop\n', 1)
    assert any("rules" in m for m in firewall_in_force(extra, fw))
    # the masquerade is required when sources are configured
    assert firewall_in_force(listing.replace(" masquerade", " accept"), fw)
    # another interface's drops are not ours
    assert firewall_in_force(listing.replace('"wtwg0"', '"other"'), fw)


def test_a_counter_on_a_rule_still_counts():
    fw = host_firewall_nft(_cfg())
    listing = fw.split(f"delete table inet {NFT_TABLE}\n", 1)[1].replace(
        'iifname "wtwg0" drop', 'iifname "wtwg0" counter packets 3 bytes 180 drop')
    assert firewall_in_force(listing, fw) == []


#: GOLDEN: the real `nft list table inet blastbox_worker_link` output (nftables 1.0.9,
#: Ubuntu) after `init --iface wltest0 --overlay-net 10.79.0.0/24 --dispatcher-source
#: 172.31.0.0/16`. Note the kernel's re-rendering: our one-element `{ 172.31.0.0/16 }` sets
#: come back as the bare prefix. Whatever the comparison checks, it must accept this.
REAL_NFT_1_0_9_LISTING = """table inet blastbox_worker_link {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname "wltest0" ct state established,related accept
\t\tiifname "wltest0" drop
\t\tiifname != { "lo", "wltest0" } ip daddr 10.79.0.0/24 drop
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname "wltest0" ct state established,related accept
\t\tiifname "wltest0" drop
\t\toifname "wltest0" ip saddr 172.31.0.0/16 ip daddr 10.79.0.0/24 tcp dport 8765 ct state new accept
\t\toifname "wltest0" ct state established,related accept
\t\toifname "wltest0" drop
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toifname "wltest0" ip saddr 10.79.0.1 ip daddr 10.79.0.0/24 tcp dport 8765 ct state new accept
\t\toifname "wltest0" ct state established,related accept
\t\toifname "wltest0" drop
\t}
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname "wltest0" ip saddr 172.31.0.0/16 masquerade
\t}
}
"""


def _real_cfg(**kw) -> WorkerLinkConfig:
    kw.setdefault("dispatcher_sources", ("172.31.0.0/16",))
    return WorkerLinkConfig(wg_iface="wltest0", overlay_net="10.79.0.0/24", agent_port=8765, **kw)


def test_the_real_kernel_listing_reads_as_in_force():
    assert firewall_in_force(REAL_NFT_1_0_9_LISTING, host_firewall_nft(_real_cfg())) == []


def test_a_broadened_accept_is_not_in_force_even_with_the_same_rule_count():
    """REGRESSION (review): accepts were compared by COUNT, so replacing the host's
    port-scoped output accept with a blanket one -- same number of rules, every drop intact --
    read as in force."""
    fw = host_firewall_nft(_real_cfg())
    scoped = ('oifname "wltest0" ip saddr 10.79.0.1 ip daddr 10.79.0.0/24 tcp dport 8765 '
              "ct state new accept")
    assert scoped in REAL_NFT_1_0_9_LISTING
    for broader in ('oifname "wltest0" accept',
                    'oifname "wltest0" ip daddr 10.79.0.0/24 tcp dport 8765 ct state new accept',
                    scoped.replace("8765", "22"),
                    scoped.replace("10.79.0.0/24", "10.0.0.0/8")):
        missing = firewall_in_force(REAL_NFT_1_0_9_LISTING.replace(scoped, broader), fw)
        assert any("output" in m for m in missing), broader
    # the forward accept's SOURCE widened
    wide = REAL_NFT_1_0_9_LISTING.replace(
        "ip saddr 172.31.0.0/16 ip daddr", "ip saddr 172.16.0.0/12 ip daddr")
    assert any("forward" in m for m in firewall_in_force(wide, fw))
    # an accept moved AHEAD of a drop (same rules, different order) is not ours either
    reordered = REAL_NFT_1_0_9_LISTING.replace(
        '\t\toifname "wltest0" ct state established,related accept\n'
        '\t\toifname "wltest0" drop\n\t}\n\tchain postrouting',
        '\t\toifname "wltest0" drop\n'
        '\t\toifname "wltest0" ct state established,related accept\n\t}\n\tchain postrouting')
    assert reordered != REAL_NFT_1_0_9_LISTING
    assert any("order" in m for m in firewall_in_force(reordered, fw))


def test_set_rendering_differences_are_cosmetic():
    """nft may reorder a set, merge adjacent prefixes, or print a one-element set bare; the
    SAME set must compare equal however it is spelled, and a different one must not."""
    fw = host_firewall_nft(_real_cfg(dispatcher_sources=("172.18.0.0/16", "172.19.0.0/16",
                                                         "10.200.0.0/16")))
    listing = fw.split(f"delete table inet {NFT_TABLE}\n", 1)[1]
    assert "{ 172.18.0.0/16, 172.19.0.0/16, 10.200.0.0/16 }" in listing
    for spelled in ("{ 10.200.0.0/16, 172.18.0.0/15 }", "{ 172.19.0.0/16, 10.200.0.0/16, "
                    "172.18.0.0/16 }"):
        assert firewall_in_force(listing.replace(
            "{ 172.18.0.0/16, 172.19.0.0/16, 10.200.0.0/16 }", spelled), fw) == [], spelled
    assert firewall_in_force(listing.replace(
        "{ 172.18.0.0/16, 172.19.0.0/16, 10.200.0.0/16 }", "{ 172.18.0.0/16, 10.200.0.0/16 }"),
        fw)
    assert firewall_in_force(listing.replace('{ "lo", "wltest0" }', '{ "wltest0", "lo" }'),
                             fw) == []
    assert firewall_in_force(listing.replace('{ "lo", "wltest0" }', '{ "lo", "eth0" }'), fw)


def test_the_reassert_units_restore_a_flushed_ruleset_or_stop_the_link():
    from blastbox.host.worker_link import reassert_units

    svc, timer = reassert_units(nft_bin="/usr/sbin/nft", nft_file="/etc/blastbox/worker-link.nft",
                                iface="wtwg0", base="blastbox-worker-link-fw", description="d")
    assert ("ExecStart=/bin/sh -c '/usr/sbin/nft -f /etc/blastbox/worker-link.nft || "
            "{ systemctl stop wg-quick@wtwg0.service; wg-quick down wtwg0 >/dev/null 2>&1; "
            "ip link delete dev wtwg0 >/dev/null 2>&1; exit 1; }'") in svc
    assert "OnUnitActiveSec=1min" in timer and "Unit=blastbox-worker-link-fw-reassert.service" in timer


def test_the_reassert_service_stops_the_link_when_the_ruleset_file_is_gone(tmp_path):
    """REGRESSION (review): `ConditionPathExists=<ruleset>` made systemd SKIP the re-assert
    when the file was deleted, so the `|| systemctl stop` never ran and a later flush left the
    link up unfirewalled. No condition/assertion now gates it, and the command itself -- run
    here for real with stub nft/systemctl -- stops the link when the file is missing."""
    import shlex
    import subprocess

    from blastbox.host.worker_link import reassert_units

    rec = tmp_path / "calls"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("nft", f'echo "nft $*" >> {rec}\n[ -f "$2" ]\n'),
                       ("systemctl", f'echo "systemctl $*" >> {rec}\n'),
                       ("wg-quick", f'echo "wg-quick $*" >> {rec}\nexit 1\n'),
                       ("ip", f'echo "ip $*" >> {rec}\n')):
        (bindir / name).write_text("#!/bin/sh\n" + body)
        (bindir / name).chmod(0o755)
    missing = tmp_path / "worker-link.nft"
    svc, _timer = reassert_units(nft_bin=str(bindir / "nft"), nft_file=str(missing),
                                 iface="wtwg0", base="b", description="d")
    assert "ConditionPath" not in svc and "AssertPath" not in svc
    line = next(ln for ln in svc.splitlines() if ln.startswith("ExecStart="))
    argv = shlex.split(line.removeprefix("ExecStart="))
    env = {"PATH": f"{bindir}:/usr/bin:/bin"}
    proc = subprocess.run(argv, env=env, capture_output=True, text=True)
    assert proc.returncode != 0                       # visible as a failed unit
    assert "systemctl stop wg-quick@wtwg0.service" in rec.read_text()
    rec.write_text("")
    # REGRESSION (review): a link brought up by the direct `wg-quick up` FALLBACK has no
    # active unit, so `systemctl stop` alone left it up unfirewalled. The failure path also
    # runs `wg-quick down` and, should that fail (stubbed to here), deletes the interface.
    missing.unlink(missing_ok=True)
    assert subprocess.run(argv, env=env).returncode != 0
    calls = rec.read_text()
    assert "wg-quick down wtwg0" in calls and "ip link delete dev wtwg0" in calls
    rec.write_text("")
    missing.write_text("table inet x {}\n")          # present and loadable: link left alone
    assert subprocess.run(argv, env=env).returncode == 0
    assert "systemctl" not in rec.read_text()


def test_firewall_unit_loads_before_the_link_and_deletes_only_its_table():
    u = firewall_unit(nft_bin="/usr/sbin/nft", nft_file="/etc/blastbox/worker-link.nft",
                      table=NFT_TABLE, iface="wtwg0", description="d")
    assert "Before=wg-quick@wtwg0.service" in u
    # REQUIRED by the link, not merely wanted: a ruleset that fails to load at boot must keep
    # the interface down rather than let it come up open.
    assert "RequiredBy=wg-quick@wtwg0.service" in u
    assert "AssertPathExists=/etc/blastbox/worker-link.nft" in u and "ConditionPath" not in u
    assert "ExecStart=/usr/sbin/nft -f /etc/blastbox/worker-link.nft" in u
    assert f"ExecStop=-/usr/sbin/nft delete table inet {NFT_TABLE}" in u
    assert "flush ruleset" not in u
    assert "PartOf=nftables.service" in u and "After=nftables.service" in u


# ------------------------------------------------------------------------------- bundle

def _bundle(**kw) -> JoinBundle:
    base = dict(name="mac1", iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                overlay_net="10.78.0.0/24", endpoint="gw.example.org:51822",
                host_public_key=KEY_A, agent_port=8765, ca_pem=CERT, cert_pem=CERT)
    if "worker_public_key" in JoinBundle.__dataclass_fields__:
        base["worker_public_key"] = "W" * 43 + "="
    base.update(kw)
    return JoinBundle(**base)


def test_bundle_round_trips_and_carries_no_private_material():
    b = _bundle()
    text = b.to_json()
    assert JoinBundle.from_json(text) == b
    assert "PRIVATE" not in text and "PrivateKey" not in text


@pytest.mark.parametrize("kw", [
    {"worker_ip": "10.78.0.1"}, {"worker_ip": "10.99.0.5"}, {"host_public_key": "x"},
    {"endpoint": "http://x"}, {"cert_pem": CERT + CERT}, {"ca_pem": "nope"},
    {"name": "a/b"}, {"iface": "wt;wg"},
])
def test_bundle_validates_every_field(kw):
    with pytest.raises(ValueError):
        _bundle(**kw)


def test_bundle_from_json_refuses_foreign_or_partial_documents():
    with pytest.raises(ValueError, match="not a blastbox"):
        JoinBundle.from_json(json.dumps({"name": "x"}))
    obj = json.loads(_bundle().to_json())
    del obj["cert_pem"]
    with pytest.raises(ValueError, match="missing cert_pem"):
        JoinBundle.from_json(json.dumps(obj))
    obj = json.loads(_bundle().to_json())
    obj["blastbox_worker_link"] = 2
    with pytest.raises(ValueError, match="version"):
        JoinBundle.from_json(json.dumps(obj))
    with pytest.raises(ValueError, match="not JSON"):
        JoinBundle.from_json("{")


# ------------------------------------------------------------- coexistence with egress (1)

def test_egress_teardown_cannot_touch_the_worker_link():
    """`egress teardown` deletes by match. Nothing it matches may be worker-link's: not the
    interface, not the nft table, not an ip rule over the link overlay."""
    from blastbox.host.egress import EgressConfig, teardown_steps

    for cfg in (EgressConfig(), EgressConfig(mode="global", upstream_gw="10.77.0.1",
                                             exit_host=True)):
        text = "\n".join(" ".join(s.argv) for s in teardown_steps(cfg, exit_iface="br-x"))
        assert "wtwg0" not in text and "10.78." not in text and "nft" not in text
        assert NFT_TABLE not in text


def test_the_worker_link_ruleset_never_touches_egress_state():
    """Worker-link is nftables in its own table: no iptables, no BB-WG-* chain, no ip rule
    (egress owns priorities 99-101), no routing table, no egress unit."""
    link = _cfg(dispatcher_sources=("172.18.0.0/16",))
    text = host_firewall_nft(link) + host_wg_config(link, "P") + firewall_unit(
        nft_bin="nft", nft_file="f", table=NFT_TABLE, iface="wtwg0", description="d")
    for forbidden in ("iptables", "BB-WG", "ip rule", "lookup", "priority 99", "priority 100",
                      "priority 101", "bbwg", "blastbox-egress", "flush ruleset", "table ip "):
        assert forbidden not in text, forbidden


def test_default_overlays_ports_and_interfaces_are_disjoint():
    from blastbox.host.egress import EgressConfig

    e, w = EgressConfig(), WorkerLinkConfig()
    assert e.wg_iface != w.wg_iface and e.wg_port != w.wg_port
    assert not ipaddress.ip_network(e.overlay_net).overlaps(ipaddress.ip_network(w.overlay_net))


# ------------------------------------------------------- coexistence with egress (2): underlay

def test_egress_global_mode_never_captures_the_worker_links_underlay_traffic():
    """In egress GLOBAL mode a worker node source-routes the forwarder's traffic into bbwg0.
    The worker-link handshake is this node's OWN UDP to the host endpoint: it must not be
    selected by any rule egress installs, or the control link would ride the egress exit.

    Proven from the plan, not assumed: every `ip rule add` egress emits selects either the
    forwarder's /32 source or the EGRESS overlay as destination; neither can match a packet
    sourced from the node's own address toward a public endpoint or the link overlay. And the
    egress peer config is `Table = off` with no fwmark, so wg-quick adds no catch-all rules.
    """
    from blastbox.host.egress import EgressConfig, forwarder_source_route_steps, peer_wg_config

    eg = EgressConfig(mode="global", upstream_gw="10.77.0.1")
    link = WorkerLinkConfig()
    fwd = ipaddress.ip_network(f"{eg.forwarder_uplink_ip}/32")
    for st in forwarder_source_route_steps(eg, "br-net0"):
        a = list(st.argv)
        if a[:3] != ["ip", "rule", "add"]:
            continue
        sel, val = a[3], ipaddress.ip_network(a[4], strict=False)
        if sel == "from":
            assert val == fwd, a          # only the forwarder's own source is captured
        else:
            assert sel == "to" and val == ipaddress.ip_network(eg.overlay_net), a
            assert not val.overlaps(ipaddress.ip_network(link.overlay_net))
    peer = peer_wg_config(eg, "PRIV", "10.77.0.2", "192.0.2.10", KEY_A)
    assert "Table = off" in peer and "FwMark" not in peer


def test_an_endpoint_inside_the_overlay_is_rejected():
    """REGRESSION (review): `--endpoint 10.78.0.1` (the host's own overlay address) was
    accepted and distributed: the worker routes that /32 INTO the tunnel, so WireGuard's own
    packets to its endpoint went into the tunnel they establish -- a link that can never
    handshake, reported as joined."""
    for ep in ("10.78.0.1", "10.78.0.5:51822", "10.78.0.200"):
        with pytest.raises(ValueError, match="inside the link overlay"):
            WorkerLinkConfig(endpoint=ep)
    WorkerLinkConfig(endpoint="192.0.2.10")              # an underlay address is fine
    with pytest.raises(ValueError, match="inside the link overlay"):
        _bundle(endpoint="10.78.0.1:51822")


def test_a_loopback_or_unroutable_endpoint_is_rejected():
    """Sweep (review round 9): an endpoint the worker can only reach as ITSELF (loopback) or
    not at all is refused at the source, before any bundle carries it."""
    for ep in ("127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1:51822"):
        with pytest.raises(ValueError, match="loopback|non-unicast"):
            WorkerLinkConfig(endpoint=ep)


def test_a_base_chain_whose_policy_changed_is_not_in_force():
    """REGRESSION (review): only the part of a base-chain declaration before the first `;` was
    compared, so a chain flipped to `policy drop` (a reload, a hand edit) -- dropping unrelated
    traffic on every interface -- still read as in force. The whole declaration counts."""
    fw = host_firewall_nft(_real_cfg())
    assert firewall_in_force(REAL_NFT_1_0_9_LISTING, fw) == []
    for chain, hook in (("input", "input priority filter"), ("output", "output priority filter"),
                        ("postrouting", "postrouting priority srcnat")):
        flipped = REAL_NFT_1_0_9_LISTING.replace(f"hook {hook}; policy accept;",
                                                 f"hook {hook}; policy drop;")
        assert flipped != REAL_NFT_1_0_9_LISTING
        assert any(chain in m and "policy accept" in m for m in firewall_in_force(flipped, fw))
    moved = REAL_NFT_1_0_9_LISTING.replace("hook input priority filter;",
                                           "hook input priority filter - 10;")
    assert any("input" in m for m in firewall_in_force(moved, fw))


def test_the_worker_readback_checks_chain_policies_too():
    """Sweep: the worker's read-back goes through the same predicate."""
    from blastbox.worker import link

    fw = link.worker_firewall_nft(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                  agent_port=8765)
    listing = fw.split(f"delete table inet {link.NFT_TABLE}\n", 1)[1]
    assert firewall_in_force(listing, fw) == []
    assert firewall_in_force(listing.replace("policy accept;", "policy drop;", 1), fw)


@pytest.mark.parametrize("ep", ["240.0.0.1", "255.255.255.255", "250.1.2.3:51822",
                                "[::ffff:127.0.0.1]:51822", "[::ffff:240.0.0.9]:51822"])
def test_reserved_and_broadcast_endpoints_are_rejected(ep):
    """REGRESSION (review): 240.0.0.0/4 and the limited broadcast 255.255.255.255 passed as an
    endpoint (neither loopback, unspecified, multicast nor link-local). Reserved classes are
    refused too -- and an IPv4-mapped IPv6 literal is judged as the IPv4 address it is."""
    with pytest.raises(ValueError, match="loopback|non-unicast"):
        WorkerLinkConfig(endpoint=ep)


def test_a_resolved_reserved_endpoint_is_refused_by_the_same_check():
    from blastbox.host.worker_link import refuse_endpoint_in_overlay

    with pytest.raises(ValueError, match="non-unicast"):
        refuse_endpoint_in_overlay(["192.0.2.10", "255.255.255.255"], "10.78.0.0/24",
                                   what="endpoint gw.example.org")


def test_the_bundle_carries_and_requires_the_registered_worker_key():
    b = _bundle()
    assert JoinBundle.from_json(b.to_json()).worker_public_key == "W" * 43 + "="
    with pytest.raises(ValueError, match="worker_public_key"):
        _bundle(worker_public_key="not-a-key")
    with pytest.raises(ValueError, match="same key"):
        _bundle(worker_public_key=KEY_A)
