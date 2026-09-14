"""Unit tests for the node egress tier.

Every test here is about a failure mode that was observed on a live two-node setup and
that is invisible from the inside: the tier reports healthy, the tunnel handshakes, and
traffic either leaks to the node's WAN or silently goes nowhere. They exist so those
four traps stay closed, and so the allocator can never pick the management LAN.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from blastbox.host.egress import (
    CHAIN_EXIT,
    CHAIN_FWD,
    PRIO_BLACKHOLE,
    PRIO_LOOKUP,
    PRIO_OVERLAY_MAIN,
    EgressConfig,
    allocate_subnets,
    exit_host_steps,
    forwarder_health,
    forwarder_run_argv,
    forwarder_source_route_steps,
    gateway_peer_stanza,
    peer_wg_config,
    teardown_steps,
)


def _argvs(steps):
    return [" ".join(s.argv) for s in steps]


GLOBAL = EgressConfig(mode="global", upstream_gw="10.77.0.1")


# ----------------------------------------------------------------------------- config

def test_global_mode_requires_an_upstream():
    # Otherwise the forwarder starts pointing nowhere and reads as a crash rather than
    # as the misconfiguration it is.
    with pytest.raises(ValueError, match="upstream_gw"):
        EgressConfig(mode="global")


def test_gateway_must_be_inside_the_worker_subnet():
    # A worker does `ip route replace default via <gw>`; off-subnet there is no link
    # route to resolve the next hop against and the kernel rejects it outright.
    with pytest.raises(ValueError, match="not inside vpn_subnet"):
        EgressConfig(vpn_gateway_ip="10.9.9.9")


def test_forwarder_uplink_must_be_inside_net0():
    # The node-side source route keys on this address; if the forwarder never holds it,
    # enforcement silently matches nothing.
    with pytest.raises(ValueError, match="not inside net0_subnet"):
        EgressConfig(mode="global", upstream_gw="10.77.0.1",
                     forwarder_uplink_ip="192.0.2.10")


def test_persisted_config_carries_no_credentials():
    text = "\n".join(GLOBAL.to_env_lines()).lower()
    for secret in ("pass", "secret", "token", "key", "cred"):
        assert secret not in text


# -------------------------------------------------------------------------- allocation

def test_allocator_relocates_a_colliding_bridge_and_moves_its_gateway():
    taken = ["172.29.0.0/16", "172.30.0.0/16", "172.31.0.0/16", "172.28.100.0/24"]
    plan = allocate_subnets(EgressConfig(), taken)
    assert len(plan.conflicts) == 4
    assert plan.changed
    # The gateway keeps its host offset inside whatever range bb-vpn landed on, so only
    # one address in the personalities needs updating.
    vpn = next(c for b, _w, c in plan.reallocated if b == "bb-vpn")
    assert ipaddress.ip_address(plan.config.vpn_gateway_ip) in ipaddress.ip_network(vpn)
    assert plan.config.vpn_gateway_ip.endswith(".0.10")


def test_allocator_never_picks_a_range_the_host_already_routes():
    # THE regression that matters. Fed only docker's pools, the allocator happily picked
    # 172.18.0.0/16 — the management LAN on these hosts. Cutting ssh to a node while
    # "installing egress" is the worst possible outcome.
    lan = "172.18.0.0/16"
    taken = ["172.29.0.0/16", "172.30.0.0/16", "172.31.0.0/16", "172.28.100.0/24",
             lan, "172.17.0.0/16"]
    plan = allocate_subnets(EgressConfig(), taken)
    for _bridge, _wanted, chosen in plan.reallocated:
        assert not ipaddress.ip_network(chosen).overlaps(ipaddress.ip_network(lan))


def test_allocator_does_not_place_two_bridges_on_the_same_pool():
    plan = allocate_subnets(EgressConfig(),
                            ["172.29.0.0/16", "172.30.0.0/16", "172.31.0.0/16"])
    nets = [ipaddress.ip_network(s) for _n, s, _i in plan.config.bridges]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)


def test_allocator_reports_conflicts_without_moving_when_auto_is_off():
    plan = allocate_subnets(EgressConfig(), ["172.31.0.0/16"], auto=False)
    assert plan.conflicts and not plan.reallocated
    assert plan.config == EgressConfig()


# ------------------------------------------------------------------ trap 1: fall-through

def test_every_lookup_rule_has_a_blackhole_behind_it():
    # An ip rule that matches but finds an empty table falls through to main, i.e. the
    # node's WAN. Observed live: with wg down the source route became direct egress.
    for steps in (forwarder_source_route_steps(GLOBAL, "eth0"),
                  exit_host_steps(GLOBAL, "br-x")):
        text = _argvs(steps)
        lookups = [c for c in text if f"priority {PRIO_LOOKUP}" in c]
        holes = [c for c in text if f"priority {PRIO_BLACKHOLE}" in c]
        assert lookups, "expected a lookup rule"
        assert len(holes) == len(lookups)
        assert all("blackhole" in c for c in holes)


def test_overlay_internal_traffic_stays_on_main_and_is_consulted_first():
    # Otherwise this host's own replies to a peer are posted to the exit sidecar and the
    # tunnel handshakes while carrying nothing.
    steps = _argvs(exit_host_steps(GLOBAL, "br-x"))
    main = next(c for c in steps if "lookup main" in c and "priority" in c)
    assert f"priority {PRIO_OVERLAY_MAIN}" in main
    assert PRIO_OVERLAY_MAIN < PRIO_LOOKUP < PRIO_BLACKHOLE


# ------------------------------------------------------------------ trap 2: cryptokey

def test_peer_config_pairs_full_allowedips_with_table_off():
    conf = peer_wg_config(GLOBAL, "PRIV", "10.77.0.3", "192.0.2.1", "A" * 43 + "=")
    # /0 alone would make wg-quick install a default route (an egress grant);
    # the overlay prefix alone would silently discard every internet-bound packet.
    assert "AllowedIPs = 0.0.0.0/0" in conf
    assert "Table = off" in conf
    # With Table=off nothing else adds the overlay route, so the config must.
    assert f"ip route replace {GLOBAL.overlay_net} dev %i" in conf


def test_exit_host_pins_each_peer_to_a_single_slash_32():
    # Anything wider lets one compromised node source another's address, which defeats
    # the per-worker rooter chains keyed on source IP.
    stanza = gateway_peer_stanza("toolz3", "10.77.0.3", "B" * 43 + "=")
    assert "AllowedIPs = 10.77.0.3/32" in stanza


def test_peer_stanza_rejects_a_non_key_and_an_unsafe_name():
    with pytest.raises(ValueError):
        gateway_peer_stanza("toolz3", "10.77.0.3", "not-a-key")
    with pytest.raises(ValueError):
        gateway_peer_stanza("../../etc/passwd", "10.77.0.3", "C" * 43 + "=")


# --------------------------------------------------------------------- trap 3: return leg

@pytest.mark.parametrize("builder,iface", [
    (forwarder_source_route_steps, "eth0"),
    (exit_host_steps, "br-x"),
])
def test_both_sides_allow_the_established_return_leg(builder, iface):
    # FORWARD policy is DROP on these hosts; source-matched chains cover only the
    # outbound leg, so without this the path works and the client still times out.
    text = _argvs(builder(GLOBAL, iface))
    assert any("ESTABLISHED,RELATED" in c and "ACCEPT" in c for c in text)


def test_exit_chain_matches_the_interface_not_the_destination():
    # Peer packets are addressed to the internet and merely routed VIA the sidecar, so a
    # `-d <gateway>` rule matches nothing and the chain drops everything.
    text = _argvs(exit_host_steps(GLOBAL, "br-x"))
    accept = next(c for c in text if c.startswith(f"iptables -A {CHAIN_EXIT}") and "ACCEPT" in c)
    assert "-o br-x" in accept
    assert f"-d {GLOBAL.vpn_gateway_ip}" not in accept


def test_outbound_chains_end_in_a_drop():
    for chain, steps in ((CHAIN_FWD, forwarder_source_route_steps(GLOBAL, "eth0")),
                         (CHAIN_EXIT, exit_host_steps(GLOBAL, "br-x"))):
        rules = [c for c in _argvs(steps) if c.startswith(f"iptables -A {chain} ")]
        assert rules[-1].endswith("-j DROP")


# ------------------------------------------------------------------------- trap 4: health

def test_running_is_not_health():
    ok_log = "forwarder: overlay peer 10.77.0.1 reachable via eth0/10.29.0.1"
    assert forwarder_health(running=True, logs_since_start=ok_log).healthy
    # Up, but this incarnation never got through its gate.
    assert not forwarder_health(running=True, logs_since_start="starting...").healthy
    assert not forwarder_health(running=False, logs_since_start=ok_log).healthy


def test_a_recovered_node_is_healthy_again():
    """Restart count is monotonic; disqualifying on it ejects a node permanently.

    The first version of this rule did exactly that — it reported DEGRADED for a node
    that was provably carrying traffic, because a transient overlay blip earlier had
    bumped the counter. What matters is the incarnation running now.
    """
    ok_log = "forwarder: overlay peer 10.77.0.1 reachable via eth0/10.29.0.1"
    h = forwarder_health(running=True, restart_count=2, logs_since_start=ok_log)
    assert h.healthy and "recovered" in h.reason


def test_a_crash_looping_forwarder_is_still_unhealthy():
    # Each new incarnation's log has no gate line, so scoping logs to the current start
    # keeps the crash-loop case failing even though restart_count no longer disqualifies.
    assert not forwarder_health(
        running=True, restart_count=3,
        logs_since_start="forwarder: overlay peer 10.77.0.1 unreachable after 15 tries.").healthy


def test_forwarder_restart_policy_does_not_mask_a_failed_gate():
    argv = forwarder_run_argv(GLOBAL)
    assert "unless-stopped" not in argv
    assert "on-failure:3" in argv


def test_forwarder_starts_on_the_routable_bridge_first():
    # bb-vpn is internal and has no default route; a container started there has no
    # uplink for its entrypoint to find and exits before one can be attached.
    argv = forwarder_run_argv(GLOBAL)
    assert argv[argv.index("--network") + 1] == "bb-net0"
    assert "bb-vpn" not in argv


# -------------------------------------------------------------------------- idempotence

def test_chain_jumps_are_guarded_so_reapply_does_not_stack_duplicates():
    for steps in (forwarder_source_route_steps(GLOBAL, "eth0"),
                  exit_host_steps(GLOBAL, "br-x")):
        for st in steps:
            if "-I" in st.argv and "FORWARD" in st.argv:
                assert st.guard is not None and "-C" in st.guard


def test_rule_adds_are_preceded_by_a_delete():
    # `ip rule add` has no check-then-add form and will happily create duplicates on
    # every boot, which the persistence unit would otherwise do forever.
    text = _argvs(forwarder_source_route_steps(GLOBAL, "eth0"))
    for i, cmd in enumerate(text):
        if cmd.startswith("ip rule add"):
            selector = cmd.split(" priority ")[0].replace("ip rule add ", "")
            assert any(prev.startswith("ip rule del") and selector in prev
                       for prev in text[:i]), f"no delete before: {cmd}"


def test_teardown_never_deletes_a_rule_by_index():
    # These hosts run a co-resident CAPE rooter; deleting by index renumbers its rules.
    for st in teardown_steps(GLOBAL):
        if st.argv[0] == "iptables" and "-D" in st.argv:
            idx = st.argv.index("-D")
            assert not st.argv[idx + 2].isdigit(), f"index delete: {' '.join(st.argv)}"


def test_teardown_is_entirely_best_effort():
    # A partially-applied node must still tear down cleanly.
    assert all(st.ignore_fail for st in teardown_steps(GLOBAL))


def test_claimed_cidrs_includes_host_routes_not_just_docker(monkeypatch):
    """The composition that makes the previous test meaningful in production.

    The allocator is only as safe as its `taken` list. Feeding it docker's pools alone is
    exactly how 172.18/16 — the management LAN — became a candidate.
    """
    from blastbox.host import egress_apply as ea

    monkeypatch.setattr(ea, "docker_network_cidrs", lambda: ["172.17.0.0/16"])
    monkeypatch.setattr(ea, "host_route_cidrs", lambda: ["172.18.0.0/16", "172.18.0.5/32"])
    claimed = ea.claimed_cidrs()
    assert "172.18.0.0/16" in claimed
    assert "172.17.0.0/16" in claimed


# ------------------------------------------------------------------ dispatcher gating

def test_egress_health_gate_is_off_unless_the_node_is_managed(monkeypatch, tmp_path):
    """The gate must never fire on a node this module does not manage.

    A node running netd-wired tiers without `blastbox egress apply` has no
    /etc/blastbox/egress.env, so the probe would report "degraded" purely because the
    tier was set up by hand — and gating on that would defer every egress job forever on
    a host that was working perfectly. This is the default, so it is the case to pin.
    """
    from blastbox.host import dispatch as d

    probe = d.Dispatcher._node_egress_health

    class Fake:
        _egress_health = None
        _egress_health_at = 0.0
        _egress_health_ttl_s = 15.0

    monkeypatch.delenv("BLASTBOX_EGRESS_HEALTH_GATE", raising=False)
    monkeypatch.setattr("blastbox.host.egress_apply.ENV_FILE", tmp_path / "absent.env")
    assert probe(Fake()) is None

    # Explicitly disabled stays disabled even on a managed node.
    marker = tmp_path / "egress.env"
    marker.write_text("BLASTBOX_EGRESS_MODE=local\n")
    monkeypatch.setattr("blastbox.host.egress_apply.ENV_FILE", marker)
    monkeypatch.setenv("BLASTBOX_EGRESS_HEALTH_GATE", "0")
    assert probe(Fake()) is None


def test_egress_health_gate_never_raises_into_the_dispatch_path(monkeypatch):
    """A broken probe must not fail jobs. Refusing work because a health check is broken
    is a worse failure than the outage it guards against."""
    from blastbox.host import dispatch as d

    class Fake:
        _egress_health = None
        _egress_health_at = 0.0
        _egress_health_ttl_s = 15.0

    monkeypatch.setenv("BLASTBOX_EGRESS_HEALTH_GATE", "1")
    monkeypatch.setattr("blastbox.host.egress_apply.node_health",
                        lambda cfg: (_ for _ in ()).throw(OSError("docker is gone")))
    assert d.Dispatcher._node_egress_health(Fake()) is None


def test_a_summary_route_does_not_veto_every_candidate():
    """A host routing 10.0.0.0/8 to a corporate gateway has not claimed every /16 in it.

    Observed on toolz3: treating the summary as blocking vetoed the whole 10/8 candidate
    pool AND flagged the node's own working bridges as conflicted, so allocation became
    impossible on a node that was already running fine.
    """
    plan = allocate_subnets(EgressConfig(), ["10.0.0.0/8", "172.16.0.0/12"])
    assert plan.advisory == ("10.0.0.0/8",)
    # 172.16/12 is specific enough to block, so it must have relocated into 10/8.
    assert plan.changed
    assert all(chosen.startswith("10.") for _b, _w, chosen in plan.reallocated)


def test_the_management_lan_still_blocks_even_though_a_summary_does_not():
    # The /16 case is the one that must stay strict — picking it cuts ssh to the node.
    plan = allocate_subnets(EgressConfig(),
                            ["10.0.0.0/8", "172.16.0.0/12", "10.77.0.0/16"])
    for _b, _w, chosen in plan.reallocated:
        assert not ipaddress.ip_network(chosen).overlaps(ipaddress.ip_network("10.77.0.0/16"))


def test_existing_bridges_are_adopted_not_re_decided():
    # A live bridge has containers on it; renumbering it because its own route appears
    # in the host's table would be destructive.
    plan = allocate_subnets(EgressConfig(), ["172.31.0.0/16"], skip=frozenset({"bb-vpn"}))
    assert plan.conflicts == () and plan.reallocated == ()


def test_the_forwarder_return_chain_targets_the_bridge_not_the_tunnel():
    """Replies arrive FROM the tunnel and must be forwarded ONTO the bridge.

    Naming the tunnel as the return interface makes the chain match nothing, so the
    forward path works and the forwarder's own gate probe never sees a reply — the tier
    then reports GATE FAILED on a node whose routing is otherwise correct.
    """
    from blastbox.host.egress import CHAIN_FWD_RET

    steps = _argvs(forwarder_source_route_steps(GLOBAL, "br-deadbeef"))
    accept = next(c for c in steps
                  if c.startswith(f"iptables -A {CHAIN_FWD_RET}") and "ACCEPT" in c)
    assert "-o br-deadbeef" in accept
    assert f"-o {GLOBAL.wg_iface}" not in accept


def test_apply_does_not_rewrite_its_own_unit_when_systemd_invoked(monkeypatch):
    """The unit runs `egress apply`; a blind re-install means it rewrites itself at every
    boot — and ProtectSystem=full makes /etc/systemd/system read-only, so it crashes the
    very unit whose job is to restore egress. Observed on toolz3."""
    from blastbox.host import egress_apply as ea

    monkeypatch.setenv("INVOCATION_ID", "deadbeef")
    msg = ea.install_persistence_unit()
    assert "invoked by systemd" in msg


def test_apply_survives_an_unwritable_unit_path(monkeypatch, tmp_path):
    """Losing persistence is worth a warning, not an outage — the tier is applied either
    way, so a read-only /etc must not fail the whole apply."""
    from blastbox.host import egress_apply as ea

    monkeypatch.delenv("INVOCATION_ID", raising=False)
    monkeypatch.setattr(ea, "UNIT_DST", tmp_path / "ro" / "blastbox-egress.service")
    monkeypatch.setattr(Path, "mkdir",
                        lambda *a, **k: (_ for _ in ()).throw(OSError(30, "Read-only file system")))
    msg = ea.install_persistence_unit()
    assert "NOT installed" in msg and "Read-only" in msg
