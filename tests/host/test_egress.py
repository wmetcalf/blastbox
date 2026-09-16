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
    """Rendered argv with the xtables `-w` wait flag removed.

    Tests here assert ROUTING AND FILTER INTENT, not lock handling, so the flag would
    only make every assertion brittle. `test_every_iptables_call_waits_for_the_xtables_lock`
    pins the flag itself.
    """
    out = []
    for st in steps:
        a = list(st.argv)
        if a and a[0] == "iptables" and len(a) > 2 and a[1] == "-w":
            del a[1:3]
        out.append(" ".join(a))
    return out


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

def test_chain_jumps_are_re_hoisted_to_position_1_not_merely_confirmed():
    """`iptables -C` matches at ANY index, so an existence guard is position-blind.

    Docker re-inserts DOCKER-USER/DOCKER-FORWARD at the head of FORWARD on every daemon
    start, and DOCKER-FORWARD holds a terminal ACCEPT for the non-internal bb-net0
    bridge. Once our jump is below that, the chain's `-j DROP` is dead code and no
    re-apply could ever hoist it back. So the jump must be delete-then-insert-at-1, and
    the delete must repeat to collapse any duplicates an older state left.
    """
    for steps in (forwarder_source_route_steps(GLOBAL, "eth0"),
                  exit_host_steps(GLOBAL, "br-x")):
        text = _argvs(steps)
        inserts = [c for c in text if c.startswith("iptables -I FORWARD 1")]
        assert inserts, "expected the jump to be inserted at position 1"
        for ins in inserts:
            chain = ins.split()[-1]
            dels = [c for c in text if c.startswith("iptables -D FORWARD") and c.endswith(chain)]
            assert len(dels) >= 2, f"{chain}: need repeated deletes to collapse duplicates"
            # and every delete must precede the insert
            assert text.index(ins) > max(text.index(d) for d in dels)
        for st in steps:
            if st.argv[:4] == ("iptables", "-I", "FORWARD", "1"):
                assert st.guard is None, "an existence guard would defeat the re-hoist"


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


def test_a_broken_probe_on_a_managed_node_degrades_rather_than_waving_work_through():
    """This REVERSES an earlier decision here, and the reasoning is worth keeping.

    The first version returned None (don't gate) for any probe exception, on the
    principle that refusing work because a health check is broken is worse than the
    outage it guards against. That principle is right for an UNMANAGED node — and an
    unmanaged node never reaches this code, because the gate arms on
    /etc/blastbox/egress.env existing.

    On a MANAGED node the same code path meant an unanticipated parse error in any of
    node_health's five shell-outs silently disarmed containment gating for a TTL at a
    time, logged at DEBUG. That is the opposite posture of the ValueError branch beside
    it, which degrades deliberately. And the cost is not symmetric: degrading here
    DEFERS to a peer, it does not fail the job.

    Only "this build has no egress module" still fails open.
    """
    from blastbox.host import dispatch as d

    class Fake:
        _egress_health = None
        _egress_health_at = 0.0
        _egress_health_ttl_s = 15.0

    import os

    os.environ["BLASTBOX_EGRESS_HEALTH_GATE"] = "1"
    try:
        import blastbox.host.egress_apply as ea

        real = ea.node_health
        ea.node_health = lambda cfg: (_ for _ in ()).throw(OSError("docker is gone"))
        try:
            verdict = d.Dispatcher._node_egress_health(Fake())
            assert verdict is not None, "a managed node must not skip the gate"
            assert not verdict.healthy
            assert "probe itself failed" in verdict.reason
        finally:
            ea.node_health = real

        # ...but a build without the module at all still fails open.
        import builtins

        real_import = builtins.__import__

        def no_egress(name, *a, **kw):
            if "egress_apply" in name:
                raise ImportError("no egress module in this build")
            return real_import(name, *a, **kw)

        builtins.__import__ = no_egress
        try:
            Fake._egress_health = None
            assert d.Dispatcher._node_egress_health(Fake()) is None
        finally:
            builtins.__import__ = real_import
    finally:
        os.environ.pop("BLASTBOX_EGRESS_HEALTH_GATE", None)


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



# --------------------------------------------------- health must assert containment

def _fake_host(monkeypatch, *, rules: str, forward: str, chain: str):
    """Stand in for the host, using REAL `ip rule show` / `iptables -S` output shapes.

    Built from captured formatting (tab after the priority, `-A FORWARD ...` lines),
    not from the implementation's own f-strings — a fixture echoing the matcher back at
    itself certifies the control without constraining it, which is how the first version
    of these tests passed while enforcement_present was blind to an orphaned chain.
    """
    from blastbox.host import egress_apply as ea

    def fake(argv, **kw):
        a = list(argv)
        if a[:3] == ["ip", "rule", "show"]:
            out = rules
        elif a[-1] == "FORWARD":
            out = forward
        elif a[-1] == "BB-WG-FWD":
            out = chain
        else:
            out = ""
        return type("P", (), {"returncode": 0, "stdout": out, "stderr": ""})()

    monkeypatch.setattr(ea, "_run", fake)
    return ea


_GOOD_RULES = ("0:\tfrom all lookup local\n"
               "99:\tfrom all to 10.77.0.0/24 lookup main\n"
               "100:\tfrom 172.29.0.10 lookup bbwg\n"
               "101:\tfrom 172.29.0.10 blackhole\n"
               "32766:\tfrom all lookup main\n")
_GOOD_FWD = ("-P FORWARD DROP\n"
             "-A FORWARD -d 172.29.0.10/32 -j BB-WG-FWD-RET\n"
             "-A FORWARD -s 172.29.0.10/32 -j BB-WG-FWD\n"
             "-A FORWARD -j DOCKER-FORWARD\n")
_GOOD_CHAIN = "-N BB-WG-FWD\n-A BB-WG-FWD -o bbwg0 -j ACCEPT\n-A BB-WG-FWD -j DROP\n"


def test_health_passes_only_when_every_layer_is_in_the_path(monkeypatch):
    ea = _fake_host(monkeypatch, rules=_GOOD_RULES, forward=_GOOD_FWD, chain=_GOOD_CHAIN)
    ok, why = ea.enforcement_present(GLOBAL)
    assert ok, why


def test_an_orphaned_chain_is_not_enforcement(monkeypatch):
    """`iptables -S BB-WG-FWD` prints the chain's own rules and NEVER the jump into it.
    Checking the chain alone reported a fully-enforced node whose jump had been flushed
    away — the chain sitting there enforcing nothing."""
    ea = _fake_host(monkeypatch, rules=_GOOD_RULES,
                    forward="-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n",
                    chain=_GOOD_CHAIN)
    ok, why = ea.enforcement_present(GLOBAL)
    assert not ok and "orphaned" in why


def test_a_jump_below_an_earlier_accept_is_not_enforcement(monkeypatch):
    """ACCEPT in a jumped-to chain ends filter traversal, so a jump below docker's
    terminal bridge ACCEPT makes our DROP dead code. A docker daemon restart does this."""
    ea = _fake_host(monkeypatch, rules=_GOOD_RULES,
                    forward=("-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n"
                             "-A FORWARD -s 172.29.0.10/32 -j BB-WG-FWD\n"),
                    chain=_GOOD_CHAIN)
    ok, why = ea.enforcement_present(GLOBAL)
    assert not ok and "BELOW" in why


def test_rules_below_the_main_lookup_are_not_enforcement(monkeypatch):
    """Matching the rule body as a bare substring of the whole output could not tell our
    priority-100 rule from the same text below `32766: from all lookup main`, which
    provides no containment at all."""
    ea = _fake_host(monkeypatch,
                    rules=("32766:\tfrom all lookup main\n"
                           "32800:\tfrom 172.29.0.10 lookup bbwg\n"
                           "32801:\tfrom 172.29.0.10 blackhole\n"),
                    forward=_GOOD_FWD, chain=_GOOD_CHAIN)
    assert not ea.enforcement_present(GLOBAL)[0]


def test_a_numeric_table_id_still_counts_as_enforcement(monkeypatch):
    """/etc/iproute2/rt_tables is a dpkg conffile an iproute2 upgrade can replace, after
    which `ip rule show` prints `lookup 220` instead of `lookup bbwg`. Routing is
    unaffected, so insisting on the name would turn a cosmetic file change into a
    fleet-wide false outage."""
    ea = _fake_host(monkeypatch,
                    rules=_GOOD_RULES.replace("lookup bbwg", "lookup 220"),
                    forward=_GOOD_FWD, chain=_GOOD_CHAIN)
    assert ea.enforcement_present(GLOBAL)[0]


def test_a_blanket_accept_ahead_of_the_drop_is_not_enforcement(monkeypatch):
    ea = _fake_host(monkeypatch, rules=_GOOD_RULES, forward=_GOOD_FWD,
                    chain="-N BB-WG-FWD\n-A BB-WG-FWD -j ACCEPT\n-A BB-WG-FWD -j DROP\n")
    assert not ea.enforcement_present(GLOBAL)[0]


def test_missing_rules_are_named_individually(monkeypatch):
    ea = _fake_host(monkeypatch, rules="", forward=_GOOD_FWD, chain=_GOOD_CHAIN)
    ok, why = ea.enforcement_present(GLOBAL)
    assert not ok
    assert "source route" in why and "blackhole" in why


def test_a_missing_binary_does_not_raise_out_of_teardown(monkeypatch):
    """check=False suppresses a non-zero exit but NOT FileNotFoundError, and only _ok
    wrapped that — so teardown on a host without systemctl raised AFTER the rules were
    removed but BEFORE the env file, leaving the dispatch gate armed on a dead tier."""
    from blastbox.host import egress_apply as ea

    proc = ea._run(["definitely-not-a-real-binary-xyz"], check=False)
    assert proc.returncode == 127


def test_teardown_disarms_the_dispatch_gate(monkeypatch, tmp_path):
    """Leaving egress.env behind keeps the dispatch gate armed on a node with no tier —
    every egress job deferred forever — and ConditionPathExists resurrects the tier at
    the next boot."""
    from blastbox.host import egress_apply as ea

    marker = tmp_path / "egress.env"
    marker.write_text("BLASTBOX_EGRESS_MODE=global\n")
    monkeypatch.setattr(ea, "ENV_FILE", marker)
    monkeypatch.setattr(ea, "_run", lambda argv, **k: type(
        "P", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    monkeypatch.setattr(ea, "run_steps", lambda steps, **k: [])
    monkeypatch.setattr(ea, "_ok", lambda argv: False)
    notes = ea.teardown_node(GLOBAL)
    assert not marker.exists()
    assert any("disarmed" in n for n in notes)


def test_persisted_config_is_what_the_dispatcher_probes_with(monkeypatch, tmp_path):
    """The gate arms on egress.env's existence, so it must probe with its CONTENT.
    Reading os.environ instead gave the class defaults — and on a relocated node that
    means pinging an address nothing holds."""
    from blastbox.host import egress_apply as ea

    marker = tmp_path / "egress.env"
    marker.write_text("# comment\nBLASTBOX_EGRESS_MODE=global\n"
                      "BLASTBOX_EGRESS_UPSTREAM_GW=10.77.0.1\n"
                      "BLASTBOX_EGRESS_VPN_SUBNET=10.88.0.0/16\n"
                      "BLASTBOX_EGRESS_VPN_GATEWAY_IP=10.88.0.10\n")
    monkeypatch.setattr(ea, "ENV_FILE", marker)
    cfg = ea.persisted_config()
    assert cfg.mode == "global"
    assert cfg.vpn_gateway_ip == "10.88.0.10"


def test_start_forwarder_checks_the_image_before_destroying_the_running_one(monkeypatch):
    """Removing first turned a working, gate-passed forwarder into no forwarder at all
    on a node whose image tag had been pruned — and the boot unit retries every 30s."""
    from blastbox.host import egress_apply as ea

    calls: list[list[str]] = []
    monkeypatch.setattr(ea, "_ok", lambda argv: not (argv[:3] == ["docker", "image", "inspect"]))
    monkeypatch.setattr(ea, "_run", lambda argv, **k: calls.append(list(argv)))
    with pytest.raises(RuntimeError, match="is missing"):
        ea.start_forwarder(GLOBAL)
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in calls), \
        "the running forwarder was destroyed before the image check"


def test_the_persistence_unit_is_generated_not_read_from_deploy():
    """A wheel ships no deploy/ tree, so reading the unit off disk always took the
    'not found' branch on a pip-installed node — the reboot fix was inert on exactly
    the installs that needed it. The shipped copy must match the generated one."""
    from pathlib import Path as _P

    from blastbox.host.egress import persistence_unit

    shipped = _P(__file__).resolve().parents[2] / "deploy" / "systemd" / "blastbox-egress.service"
    assert shipped.read_text() == persistence_unit("/usr/local/bin/blastbox egress apply")


def test_the_reconcile_timer_is_shipped_and_matches_what_apply_installs():
    """Boot persistence alone leaves three measured holes — an unattended dockerd
    restart burying the FORWARD jump, a forwarder that has spent its on-failure:3
    budget, and a node that booted before its exit host — in all of which systemd still
    reports blastbox-egress active(exited) and nothing re-asserts enforcement."""
    from pathlib import Path as _P

    from blastbox.host.egress import reconcile_service_unit, reconcile_timer_unit
    from blastbox.host.egress_apply import RECONCILE_INTERVAL

    d = _P(__file__).resolve().parents[2] / "deploy" / "systemd"
    ex = "/usr/local/bin/blastbox egress apply"
    assert (d / "blastbox-egress.timer").read_text() == reconcile_timer_unit(RECONCILE_INTERVAL)
    assert (d / "blastbox-egress-reconcile.service").read_text() == reconcile_service_unit(ex)


def test_the_reconcile_service_does_not_remain_after_exit():
    """It must be a plain oneshot. RemainAfterExit is what makes the BOOT unit able to
    say "this node's tier is set up"; carrying it here would make the timer's repeated
    triggers either no-ops or a fight with Restart=on-failure."""
    from blastbox.host.egress import reconcile_service_unit

    body = reconcile_service_unit("/x/blastbox egress apply")
    assert "RemainAfterExit" not in body
    assert "Restart=" not in body
    assert "ConditionPathExists=/etc/blastbox/egress.env" in body


def test_the_timer_fires_repeatedly_not_only_at_boot():
    """OnBootSec alone would make this a second boot unit and leave every non-reboot
    hole open."""
    from blastbox.host.egress import reconcile_timer_unit

    body = reconcile_timer_unit("3min")
    assert "OnUnitInactiveSec=3min" in body
    assert "Unit=blastbox-egress-reconcile.service" in body
    # A fleet must not rewrite its FORWARD chains in lockstep.
    assert "RandomizedDelaySec" in body


def test_the_generated_unit_carries_its_load_bearing_directives():
    from blastbox.host.egress import persistence_unit

    body = persistence_unit("/x/python -m blastbox.host.cli egress apply", "bbwg9")
    assert "ExecStart=/x/python -m blastbox.host.cli egress apply" in body
    # Ordering after wg-quick: the source route needs the interface to exist.
    assert "After=docker.service network-online.target wg-quick@bbwg9.service" in body
    # Wants, not Requires — a local-mode node has no overlay and must still run.
    assert "Requires=docker.service" in body and "Wants=network-online.target" in body
    assert "ConditionPathExists=/etc/blastbox/egress.env" in body


def test_adopting_a_relocated_bridge_carries_its_gateway_along(monkeypatch):
    """Replacing vpn_subnet while leaving vpn_gateway_ip in the OLD range makes
    EgressConfig's validator raise from inside the planner — an uncaught ValueError that
    the boot unit repeats every 30s. Reproduced on a live node whose bridges had been
    relocated to 10.31.0.0/16 while the config still said 172.31.0.10."""
    from blastbox.host import egress_apply as ea

    live = {"bb-net0": "10.29.0.0/16", "bb-fakenet": "10.28.100.0/24",
            "bb-socks": "10.30.0.0/16", "bb-vpn": "10.31.0.0/16"}

    def fake_run(argv, **k):
        out = ""
        if argv[:3] == ["docker", "network", "inspect"]:
            out = live.get(argv[3], "")
            return type("P", (), {"returncode": 0 if out else 1, "stdout": out, "stderr": ""})()
        return type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(ea, "_run", fake_run)
    monkeypatch.setattr(ea, "claimed_cidrs", lambda: list(live.values()))
    # A real host always has routes; without this the allocator correctly refuses to
    # allocate blind (see test_refuses_to_allocate_when_it_cannot_read_the_hosts_routes).
    monkeypatch.setattr(ea, "host_route_cidrs", lambda: ["172.18.0.0/16"])
    plan = ea.plan_subnets(EgressConfig())          # defaults say 172.31.0.10
    assert plan.config.vpn_subnet == "10.31.0.0/16"
    assert plan.config.vpn_gateway_ip == "10.31.0.10"   # offset preserved, not stale
    assert plan.config.forwarder_uplink_ip == "10.29.0.10"


def test_every_iptables_call_waits_for_the_xtables_lock():
    """dockerd and the co-resident CAPE rooter mutate iptables constantly, and an
    unwaited call does not queue — it fails outright. A `-C` guard failing that way is
    indistinguishable from "rule absent", and the delete-then-insert jump is DESTRUCTIVE
    if the delete wins the lock and the insert loses it."""
    for steps in (forwarder_source_route_steps(GLOBAL, "eth0"),
                  exit_host_steps(GLOBAL, "br-x"),
                  teardown_steps(GLOBAL)):
        for st in steps:
            if st.argv[0] == "iptables":
                assert st.argv[1] == "-w", f"unwaited: {' '.join(st.argv)}"


def test_an_unprivileged_probe_does_not_condemn_a_healthy_node(monkeypatch):
    """`ip rule show` works unprivileged; `iptables -S` exits 4 with Permission denied.

    The dispatcher is cap-dropped BY DESIGN — netd exists as a separate privileged helper
    for exactly that reason — so counting an unreadable filter table as "missing" would
    report every healthy node as uncontained and defer all of its egress work forever.
    CANNOT OBSERVE is not OBSERVED ABSENT.
    """
    from blastbox.host import egress_apply as ea

    rules = ("100:\tfrom 172.29.0.10 lookup bbwg\n"
             "101:\tfrom 172.29.0.10 blackhole\n")

    def unprivileged(argv, **kw):
        a = list(argv)
        if a[:3] == ["ip", "rule", "show"]:
            return type("P", (), {"returncode": 0, "stdout": rules, "stderr": ""})()
        return type("P", (), {"returncode": 4, "stdout": "",
                              "stderr": "Permission denied"})()

    monkeypatch.setattr(ea, "_run", unprivileged)
    ok, why = ea.enforcement_present(GLOBAL)
    assert ok, why
    assert "unverified" in why          # reported, not silently ignored


def test_an_unprivileged_probe_still_catches_a_missing_source_route(monkeypatch):
    """The routing layer IS readable unprivileged, so a verdict still means something —
    degrading gracefully must not become degrading to useless."""
    from blastbox.host import egress_apply as ea

    monkeypatch.setattr(ea, "_run", lambda argv, **kw: type(
        "P", (), {"returncode": 0 if list(argv)[:3] == ["ip", "rule", "show"] else 4,
                  "stdout": "", "stderr": "Permission denied"})())
    ok, why = ea.enforcement_present(GLOBAL)
    assert not ok and "source route" in why


def test_a_tiny_adopted_subnet_still_yields_an_in_range_gateway(monkeypatch):
    """The adopted subnet is one an OPERATOR created, not one docker chose. The `.10`
    convention puts the gateway outside a /29 and re-raises the exact ValueError the
    adoption fix exists to prevent."""
    from blastbox.host import egress_apply as ea

    live = {"bb-vpn": "10.31.5.0/29"}

    def fake(argv, **kw):
        a = list(argv)
        if a[:3] == ["docker", "network", "inspect"]:
            out = live.get(a[3], "")
            return type("P", (), {"returncode": 0 if out else 1, "stdout": out, "stderr": ""})()
        return type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(ea, "_run", fake)
    monkeypatch.setattr(ea, "claimed_cidrs", lambda: list(live.values()))
    monkeypatch.setattr(ea, "host_route_cidrs", lambda: ["172.18.0.0/16"])
    plan = ea.plan_subnets(EgressConfig())          # no exception
    assert ipaddress.ip_address(plan.config.vpn_gateway_ip) in \
        ipaddress.ip_network(plan.config.vpn_subnet)


def test_an_explicit_namespaced_env_var_outranks_the_persisted_file(monkeypatch, tmp_path):
    """A stray legacy `VPN_SUBNET` must not redescribe a managed node, but an explicit
    BLASTBOX_EGRESS_* is unambiguous intent and is how an operator repairs one."""
    from blastbox.host import egress_apply as ea

    marker = tmp_path / "egress.env"
    marker.write_text("BLASTBOX_EGRESS_MODE=global\n"
                      "BLASTBOX_EGRESS_UPSTREAM_GW=10.77.0.1\n"
                      "BLASTBOX_EGRESS_VPN_SUBNET=10.88.0.0/16\n"
                      "BLASTBOX_EGRESS_VPN_GATEWAY_IP=10.88.0.10\n")
    monkeypatch.setattr(ea, "ENV_FILE", marker)

    monkeypatch.setenv("VPN_SUBNET", "192.168.77.0/24")          # legacy: must lose
    assert ea.persisted_config().vpn_subnet == "10.88.0.0/16"

    monkeypatch.setenv("BLASTBOX_EGRESS_VPN_SUBNET", "10.99.0.0/16")   # explicit: must win
    monkeypatch.setenv("BLASTBOX_EGRESS_VPN_GATEWAY_IP", "10.99.0.10")
    assert ea.persisted_config().vpn_subnet == "10.99.0.0/16"


def test_allocator_stays_correct_and_fast_with_a_large_claimed_set():
    """The small-input overlap test did NOT catch a real regression here.

    Indexing the host's claimed set for speed made ranges chosen DURING the call
    invisible to later bridges, and all four were allocated the same /16 — while the
    existing test passed, because its input was too small to take the indexed path. A
    performance structure has to be exercised at the size it exists for.
    """
    import time

    # A wg exit host with a /32 route per fleet peer, plus a busy CAPE host's 172.16/12.
    taken = ["172.16.0.0/12"] + [f"10.{a}.{b}.7/32" for a in range(60) for b in range(256)]
    started = time.perf_counter()
    plan = allocate_subnets(EgressConfig(), taken)
    elapsed = time.perf_counter() - started

    nets = [ipaddress.ip_network(s) for _n, s, _i in plan.config.bridges]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b), f"{a} overlaps {b}"
    # ...and none may land on anything the host already claims.
    claimed = [ipaddress.ip_network(t) for t in taken]
    for n in nets:
        assert not any(n.overlaps(c) for c in claimed), f"{n} collides with the host"
    # Generous: this runs inside a boot oneshot that retries every 30s.
    assert elapsed < 5.0, f"allocation took {elapsed:.1f}s with {len(taken)} claimed entries"


def test_every_egress_action_parses_without_the_suppressed_options():
    """`default=argparse.SUPPRESS` omits the attribute entirely when the option is
    unused, which is exactly what stops the sub-parser clobbering a pre-verb value — but
    it means any unconditional `args.mode` would raise AttributeError. Pin the contract
    for all eight actions so a future `args.mode` is caught here, not in production."""
    from blastbox.host.cli import build_parser

    p = build_parser()
    key = "A" * 43 + "="
    for argv in (["egress", "check"], ["egress", "health"], ["egress", "apply"],
                 ["egress", "teardown"], ["egress", "gateway"], ["egress", "gateway-exit"],
                 ["egress", "peer-add", "--name", "n", "--peer-ip", "10.77.0.3",
                  "--public-key", key],
                 ["egress", "peer", "--peer-ip", "10.77.0.3", "--gateway-addr", "1.2.3.4",
                  "--gateway-pubkey", key]):
        ns = p.parse_args(argv)
        for opt in ("mode", "gateway_ip", "wg_iface", "upstream_gw"):
            assert getattr(ns, opt, None) is None, f"{argv[1]}: {opt} unexpectedly set"


def test_both_argv_positions_survive_for_every_action():
    """argparse writes a sub-parser's defaults back over the parent namespace, so an
    option declared in both places loses its pre-verb value. That regression made
    `egress --mode global apply` silently fall back to LOCAL mode — applying a global
    node with no enforcement and reporting OK."""
    from blastbox.host.cli import build_parser

    p = build_parser()
    for action in ("apply", "check", "health", "teardown"):
        pre = p.parse_args(["egress", "--mode", "global", action])
        post = p.parse_args(["egress", action, "--mode", "global"])
        assert getattr(pre, "mode", None) == "global", f"{action}: pre-verb lost"
        assert getattr(post, "mode", None) == "global", f"{action}: post-verb lost"


def test_an_unrelated_accept_does_not_read_as_burying_our_chain(monkeypatch):
    """A narrow ACCEPT for some other source — the CAPE rooter has dozens — cannot
    swallow our traffic. Treating every earlier ACCEPT as fatal reported a
    correctly-ordered node as uncontained."""
    from blastbox.host import egress_apply as ea

    fwd = ("-P FORWARD DROP\n"
           "-A FORWARD -s 192.0.2.7/32 -j ACCEPT\n"              # unrelated, narrow
           "-A FORWARD -s 172.29.0.10/32 -j BB-WG-FWD\n"
           "-A FORWARD -j DOCKER-FORWARD\n")
    ea_ = _fake_host(monkeypatch, rules=_GOOD_RULES, forward=fwd, chain=_GOOD_CHAIN)
    ok, why = ea_.enforcement_present(GLOBAL)
    assert ok, why


def test_refuses_to_allocate_when_it_cannot_read_the_hosts_routes(monkeypatch):
    """An empty claimed set is indistinguishable between "this host routes nothing"
    (impossible) and "`ip` is missing" — and allocating on it is exactly how a bridge
    lands on the management LAN and cuts the node off."""
    from blastbox.host import egress_apply as ea

    monkeypatch.setattr(ea, "host_route_cidrs", lambda: [])
    monkeypatch.setattr(ea, "docker_network_cidrs", lambda: [])
    monkeypatch.setattr(ea, "_run", lambda argv, **kw: type(
        "P", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    with pytest.raises(ea.HostFactsUnavailable, match="management LAN"):
        ea.plan_subnets(EgressConfig())


@pytest.mark.parametrize("rule,buries", [
    # --- buries us: could match a NEW outbound packet, OR is not fully understood ---
    ("-A FORWARD -j DOCKER-FORWARD", True),                       # docker's terminal ACCEPT
    ("-A FORWARD -j ACCEPT", True),                               # unrestricted
    ("-A FORWARD -s 172.29.0.10/32 -j ACCEPT", True),             # matches the forwarder
    ("-A FORWARD -s 172.29.0.0/16 -j ACCEPT", True),              # contains the forwarder
    ("-A FORWARD -i br-bb0 -j ACCEPT", True),                     # our own ingress bridge
    # negation: every one of these failed OPEN in an earlier version
    ("-A FORWARD ! --ctstate ESTABLISHED,RELATED -j ACCEPT", True),
    ("-A FORWARD ! -i docker0 -j ACCEPT", True),
    ("-A FORWARD ! -s 192.0.2.0/24 -j ACCEPT", True),
    ("-A FORWARD -i br+ -j ACCEPT", True),                        # interface wildcard
    ("-A FORWARD -m physdev --physdev-in eth0 -j ACCEPT", True),  # unknown match module
    # --- does not bury us: a shape the predicate fully understands ---
    ("-A FORWARD -s 192.0.2.7/32 -j ACCEPT", False),              # unrelated (CAPE rooter)
    ("-A FORWARD -s 10.9.9.0/24 -j ACCEPT", False),               # unrelated subnet
    ("-A FORWARD -i docker0 -o eth0 -j ACCEPT", False),           # other ingress interface
    ("-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", False),  # return only
    ("-A FORWARD -j DOCKER-USER", False),                         # RETURNs by default
    ("-A FORWARD -s 172.29.0.10/32 -j BB-WG-FWD", False),         # our own jump
])
def test_unparsed_iptables_syntax_counts_as_burying_the_chain(rule, buries):
    """The default is inverted on purpose, and every negation case here was a live bug.

    Four review rounds each found another piece of iptables syntax an earlier version
    mis-parsed — `! --ctstate`, `! -s`, `-i br+`, unknown match modules — and every miss
    failed OPEN, reporting a buried chain as fine. Enumerating the ways a rule can be
    harmless is a losing game against a matcher with negation, wildcards and arbitrary
    extensions, so a rule buries us UNLESS it is a shape the predicate fully understands.

    A false positive degrades a node (loud). A false negative lets malware out of the
    analyst's own WAN while the check says OK. Do not rebalance this toward "prove safe".
    """
    from blastbox.host.egress_apply import _accepts_our_traffic

    assert _accepts_our_traffic(rule, "172.29.0.10", "br-bb0") is buries


def test_a_forwarder_matching_accept_above_our_jump_fails_containment(monkeypatch):
    fwd = ("-P FORWARD DROP\n"
           "-A FORWARD -s 172.29.0.0/16 -j ACCEPT\n"          # swallows us first
           "-A FORWARD -s 172.29.0.10/32 -j BB-WG-FWD\n")
    ea_ = _fake_host(monkeypatch, rules=_GOOD_RULES, forward=fwd, chain=_GOOD_CHAIN)
    ok, why = ea_.enforcement_present(GLOBAL)
    assert not ok and "BELOW" in why


def test_the_exit_host_role_is_persisted_so_a_reboot_replays_it():
    """The boot unit runs `egress apply`, whose local path never calls exit_host_steps.
    Without a recorded role the CENTRAL host came back from a reboot with WireGuard up
    and peer-to-sidecar forwarding gone — a fleet-wide egress outage, not one node's."""
    cfg = EgressConfig(mode="global", upstream_gw="10.77.0.1", exit_host=True)
    assert "BLASTBOX_EGRESS_EXIT_HOST=1" in cfg.to_env_lines()
    back = EgressConfig.from_env(dict(l.split("=", 1) for l in cfg.to_env_lines()))
    assert back.exit_host is True


def test_a_peer_address_outside_the_overlay_is_refused():
    """The exit host's source route and BB-WG-EXIT chain both match overlay_net, so a
    typo'd peer address outside it matches neither and follows ordinary host forwarding
    — bypassing sidecar routing and the DROP entirely."""
    with pytest.raises(ValueError, match="outside the overlay"):
        peer_wg_config(GLOBAL, "KEY", "10.78.0.3", "192.0.2.1", "A" * 43 + "=")
    assert "Address = 10.77.0.3/24" in peer_wg_config(
        GLOBAL, "KEY", "10.77.0.3", "192.0.2.1", "A" * 43 + "=")


def test_teardown_deletes_ip_rules_by_selector_not_bare_priority():
    """`ip rule del priority N` selects solely by preference, so on a shared host using
    99/100/101 it silently removes someone else's rule while claiming to remove only
    blastbox state."""
    for st in teardown_steps(GLOBAL):
        if st.argv[:3] == ("ip", "rule", "del"):
            assert "priority" not in st.argv, f"bare-priority delete: {' '.join(st.argv)}"
            assert any(t in st.argv for t in ("from", "to")), \
                f"unqualified delete: {' '.join(st.argv)}"


def test_an_existing_non_internal_bridge_is_refused(monkeypatch):
    """A same-named network created without --internal keeps docker's host-NAT path, so
    an inetsim worker egresses directly and a failed netd wiring leaves a live default
    route — silently, since everything else reports the bridge as present."""
    from blastbox.host import egress_apply as ea

    def fake(argv, **kw):
        a = list(argv)
        if a[:3] == ["docker", "network", "inspect"] and a[-1] == "{{.Internal}}":
            return type("P", (), {"returncode": 0, "stdout": "false", "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(ea, "_run", fake)
    monkeypatch.setattr(ea, "_ok", lambda argv: True)
    with pytest.raises(RuntimeError, match="NOT internal"):
        ea.ensure_bridges(EgressConfig())


def test_an_empty_managed_env_file_is_not_silently_treated_as_local(monkeypatch, tmp_path):
    """The gate arms on the file's EXISTENCE, so falling back to defaults gives
    mode='local' on a managed global node — skipping every global containment check."""
    from blastbox.host import egress_apply as ea

    marker = tmp_path / "egress.env"
    marker.write_text("# nothing but a comment\n")
    monkeypatch.setattr(ea, "ENV_FILE", marker)
    with pytest.raises(ValueError, match="empty or unreadable"):
        ea.persisted_config()


def test_a_claimed_routing_table_id_is_refused(monkeypatch, tmp_path):
    """Two names for one kernel table means `ip route replace ... table bbwg` overwrites
    the other subsystem's routes and teardown flushes a table we do not own."""
    from blastbox.host import egress_apply as ea

    rt = tmp_path / "rt_tables"
    rt.write_text("# reserved\n255 local\n220 cape_vpn\n")
    monkeypatch.setattr(ea, "RT_TABLES", rt)
    with pytest.raises(RuntimeError, match="already claimed by 'cape_vpn'"):
        ea.ensure_rt_table(EgressConfig())


def test_a_leftover_rule_at_the_same_priority_does_not_shadow_ours(monkeypatch):
    """A priority is not unique. Reading only the FIRST rule at 100/101 let a leftover
    from an earlier experiment shadow the correct one, and a fully-enforced node was
    reported uncontained. Observed live on the exit host."""
    from blastbox.host import egress_apply as ea

    rules = ("99:\tfrom all to 10.77.0.0/24 lookup main\n"
             "100:\tfrom 172.20.0.10 lookup bbwg\n"        # stale, listed first
             "100:\tfrom 172.29.0.10 lookup bbwg\n"        # ours
             "101:\tfrom 172.20.0.10 blackhole\n"          # stale, listed first
             "101:\tfrom 172.29.0.10 blackhole\n")         # ours
    ea_ = _fake_host(monkeypatch, rules=rules, forward=_GOOD_FWD, chain=_GOOD_CHAIN)
    ok, why = ea_.enforcement_present(GLOBAL)
    assert ok, why


# ------------------------------------------- revocation has to reach the overlay

def test_an_expired_peers_certificate_marks_it_for_pruning():
    """A node cert lives days; a wg peer stanza lives forever. Without enforcing the
    recorded expiry, "revocation is stop renewing" revokes nothing at the overlay and
    the short lifetime buys nothing."""
    import datetime as dt

    from blastbox.host.egress import expired_peers, gateway_peer_stanza

    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)).isoformat()
    conf = ("[Interface]\nPrivateKey = x\n"
            + gateway_peer_stanza("lapsed", "10.77.0.4", "A" * 43 + "=", past)
            + gateway_peer_stanza("live", "10.77.0.5", "B" * 43 + "=", future))
    assert expired_peers(conf) == ["lapsed"]


def test_a_peer_with_no_recorded_expiry_is_left_alone():
    """It predates enrolment or was force-registered. Silently dropping it would be a
    worse surprise than leaving it — the operator gets no signal either way."""
    from blastbox.host.egress import expired_peers, gateway_peer_stanza

    conf = "[Interface]\n" + gateway_peer_stanza("legacy", "10.77.0.6", "C" * 43 + "=")
    assert expired_peers(conf) == []


def test_an_unparseable_expiry_does_not_drop_the_peer():
    from blastbox.host.egress import expired_peers

    conf = "# peer:weird\n# expires:soon-ish\n[Peer]\nPublicKey = x\n"
    assert expired_peers(conf) == []


def test_pruning_removes_only_the_lapsed_stanza(tmp_path, monkeypatch):
    import datetime as dt

    from blastbox.host import egress_apply as ea
    from blastbox.host.egress import gateway_peer_stanza

    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)).isoformat()
    conf = tmp_path / "bbwg0.conf"
    conf.write_text("[Interface]\nPrivateKey = secret\n"
                    + gateway_peer_stanza("lapsed", "10.77.0.4", "A" * 43 + "=", past)
                    + gateway_peer_stanza("live", "10.77.0.5", "B" * 43 + "=", future))
    monkeypatch.setattr(ea, "WG_DIR", tmp_path)
    monkeypatch.setattr(ea, "_run", lambda argv, **kw: type(
        "P", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    assert ea.prune_expired_peers(GLOBAL) == ["lapsed"]
    body = conf.read_text()
    assert "# peer:live" in body and "PrivateKey = secret" in body
    assert "# peer:lapsed" not in body and "A" * 43 not in body


# ------------------------------------------- prefix matching was a containment hole

def test_a_stale_rule_for_a_similar_address_does_not_satisfy_containment(monkeypatch):
    """`"from 172.29.0.10" in body` is TRUE for `from 172.29.0.100`. A host carrying only
    stale rules for a different forwarder address reported full containment while the
    current forwarder's packets matched nothing and followed ordinary host forwarding."""
    ea_ = _fake_host(
        monkeypatch,
        rules=("100:\tfrom 172.29.0.100 lookup bbwg\n"
               "101:\tfrom 172.29.0.100 blackhole\n"),
        forward=("-P FORWARD DROP\n"
                 "-A FORWARD -s 172.29.0.100/32 -j BB-WG-FWD\n"),
        chain=_GOOD_CHAIN)
    ok, why = ea_.enforcement_present(GLOBAL)
    assert not ok
    assert "source route" in why and "blackhole" in why


def test_a_forward_jump_for_another_source_is_not_our_jump(monkeypatch):
    """A jump into the same chain for a DIFFERENT source protects nothing of ours."""
    ea_ = _fake_host(monkeypatch, rules=_GOOD_RULES,
                     forward=("-P FORWARD DROP\n"
                              "-A FORWARD -s 10.9.9.9/32 -j BB-WG-FWD\n"),
                     chain=_GOOD_CHAIN)
    ok, why = ea_.enforcement_present(GLOBAL)
    assert not ok and "orphaned" in why


# ------------------------------------------------- owning the address, not routing to it

def test_a_forwarder_that_lost_the_gateway_address_is_not_healthy(monkeypatch):
    """A forwarder disconnected from bb-vpn keeps running its overlay loop and keeps its
    gate line, while nothing holds the address every worker routes to."""
    from blastbox.host import egress_apply as ea

    monkeypatch.setattr(ea, "enforcement_present", lambda cfg: (True, "ok"))
    monkeypatch.setattr(ea, "container_state",
                        lambda n: (True, 0, "forwarder: overlay peer 10.77.0.1 reachable"))
    monkeypatch.setattr(ea, "address_owner", lambda cfg, addr: None)
    h = ea.node_health(GLOBAL)
    assert not h.healthy and "does not own" in h.reason

    monkeypatch.setattr(ea, "address_owner", lambda cfg, addr: GLOBAL.forwarder_name)
    assert ea.node_health(GLOBAL).healthy


def test_an_exit_host_with_no_sidecar_is_not_healthy(monkeypatch):
    """`ip route get` passes whenever the bb-vpn bridge exists, because the subnet's
    connected route remains — so the check passed with the sidecar stopped entirely and
    every peer forwarded toward an address nothing answers."""
    from blastbox.host import egress_apply as ea

    exit_cfg = EgressConfig(mode="global", upstream_gw="10.77.0.1", exit_host=True)
    monkeypatch.setattr(ea, "enforcement_present", lambda cfg: (True, "ok"))
    monkeypatch.setattr(ea, "address_owner", lambda cfg, addr: None)
    h = ea.node_health(exit_cfg)
    assert not h.healthy and "NOTHING holds" in h.reason


def test_the_exit_host_role_is_judged_before_the_local_shortcut(monkeypatch):
    """`gateway-exit` records exit_host=True while mode stays at its default "local", so
    the local shortcut skipped every containment check on the central host."""
    from blastbox.host import egress_apply as ea

    seen: list = []
    monkeypatch.setattr(ea, "enforcement_present",
                        lambda cfg: (seen.append(cfg.exit_host), (True, "ok"))[1])
    monkeypatch.setattr(ea, "address_owner", lambda cfg, addr: "bb-vpn-gw")
    cfg = EgressConfig(exit_host=True)          # mode defaults to "local"
    assert ea.node_health(cfg).healthy
    assert seen == [True], "an exit host's containment must be checked, not skipped"


def test_an_exit_hosts_containment_is_checked_despite_mode_local(monkeypatch):
    """The role, not the mode, decides the shape — and an exit host cannot simply be
    coerced to mode=global, because the validator rightly refuses a global config with
    no upstream and an exit host has none."""
    from blastbox.host import egress_apply as ea

    ea_ = _fake_host(monkeypatch, rules="", forward="", chain="")
    ok, why = ea_.enforcement_present(EgressConfig(exit_host=True))
    assert not ok, "an exit host with no rules must not read as 'local mode is fine'"


def test_a_poisoned_routing_table_is_not_containment(monkeypatch):
    """The rule sends our source to a table; the blackhole behind it fires only when that
    table yields NO route. So a table holding `default dev <WAN>` is a complete bypass
    that every other check reports as contained — and nothing ever ran
    `ip route show table` at all."""
    from blastbox.host import egress_apply as ea

    def host(table):
        def fake(argv, **kw):
            a = list(argv)
            if a[:3] == ["ip", "rule", "show"]:
                out = _GOOD_RULES
            elif a[:4] == ["ip", "route", "show", "table"]:
                out = table
            elif a[-1] == "FORWARD":
                out = _GOOD_FWD
            else:
                out = _GOOD_CHAIN
            return type("P", (), {"returncode": 0, "stdout": out, "stderr": ""})()
        monkeypatch.setattr(ea, "_run", fake)
        return ea

    ok, why = host("default dev eth0 scope link\n").enforcement_present(GLOBAL)
    assert not ok and "not bbwg0" in why

    assert host("default dev bbwg0 scope link\n").enforcement_present(GLOBAL)[0]
    # An EMPTY table is the wg-is-down case the blackhole exists for: fails closed.
    assert host("").enforcement_present(GLOBAL)[0]


@pytest.mark.parametrize("chain_rule,escapes", [
    ("-A BB-WG-FWD -o eth0 -j ACCEPT", True),               # a total WAN escape
    ('-A BB-WG-FWD -m comment --comment "x-o-x" -j ACCEPT', True),   # blanket, "-o" in a comment
    ("-A BB-WG-FWD -j ACCEPT", True),                       # unrestricted
    ("-A BB-WG-FWD -o bbwg0 -j ACCEPT", False),             # the sanctioned device
])
def test_a_chain_accept_must_name_the_sanctioned_device(chain_rule, escapes):
    """The old test was `"-o" not in ln` — a substring over the whole rule that never
    compared the interface to anything."""
    from blastbox.host.egress_apply import _chain_accept_escapes

    assert _chain_accept_escapes(chain_rule, "bbwg0") is escapes


def test_an_unqualified_jump_counts_but_a_narrowed_one_does_not(monkeypatch):
    """A jump with no `-s` was accepted as ours. One narrowed by any OTHER selector is
    reachable by traffic that is not ours, so accepting it certified an orphan chain."""
    for forward, contained in (
            ("-P FORWARD DROP\n-A FORWARD -j BB-WG-FWD\n", True),          # unqualified
            ("-P FORWARD DROP\n-A FORWARD -i lo -j BB-WG-FWD\n", False),   # narrowed
    ):
        ea_ = _fake_host(monkeypatch, rules=_GOOD_RULES, forward=forward,
                         chain=_GOOD_CHAIN)
        monkeypatch.setattr(ea_, "_run", ea_._run)
        assert ea_.enforcement_present(GLOBAL)[0] is contained


def test_no_auto_subnets_does_not_disable_the_host_facts_check(monkeypatch):
    """The guard sat behind `if auto`, and its own error message pointed the operator at
    --no-auto-subnets as the workaround — which turned the safety check OFF rather than
    narrowing it. Choosing your own subnets and being unable to see the host's are
    different decisions."""
    from blastbox.host import egress_apply as ea

    monkeypatch.setattr(ea, "host_route_cidrs", lambda: [])
    monkeypatch.setattr(ea, "docker_network_cidrs", lambda: [])
    monkeypatch.setattr(ea, "_run", lambda argv, **kw: type(
        "P", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    monkeypatch.delenv("BLASTBOX_EGRESS_ALLOW_UNKNOWN_ROUTES", raising=False)

    for auto in (True, False):
        with pytest.raises(ea.HostFactsUnavailable):
            ea.plan_subnets(EgressConfig(), auto=auto)

    # The deliberate override is separate, and explicit.
    monkeypatch.setenv("BLASTBOX_EGRESS_ALLOW_UNKNOWN_ROUTES", "1")
    ea.plan_subnets(EgressConfig(), auto=False)


def test_the_gate_success_regex_matches_a_line_the_forwarder_can_actually_emit():
    """The one string the dispatcher's health gate keys on lived in four hand-copied
    places with nothing tying them together: the entrypoint (the source of truth),
    GATE_OK_PATTERN, hardcoded literals in this file, and a third spelling in
    scripts/test-egress-leak.sh. CI only ever exercised the FAILURE line, so rewording
    the success line would keep every test and the whole CI job green while every
    global-mode node reported "has not logged a successful overlay probe" and the
    dispatcher deferred 100% of egress jobs fleet-wide.

    So: read the shell script and check the regex against what it can really print.
    """
    import re
    from pathlib import Path as _P

    from blastbox.host.egress import GATE_OK_PATTERN

    src = (_P(__file__).resolve().parents[2] / "deploy/egress-forwarder/entrypoint.sh").read_text()
    # Every double-quoted echo the script can emit, with shell expansions stood in for.
    emitted = [
        re.sub(r"\$\{?\w+\}?", "VALUE", m)
        for m in re.findall(r'^\s*echo "([^"]*)"', src, re.M)
    ]
    assert emitted, "no echo lines found — the extraction, not the contract, is broken"
    matching = [line for line in emitted if GATE_OK_PATTERN.search(line)]
    assert matching, (
        "GATE_OK_PATTERN matches NOTHING the forwarder prints. Every global-mode node "
        f"will read as unhealthy. Pattern: {GATE_OK_PATTERN.pattern!r}; lines: {emitted}"
    )


def test_the_leak_script_and_the_health_gate_look_for_the_same_line():
    """Third copy of the same contract. A divergence here means the operator's proof
    and the dispatcher's gate disagree about whether a node is carrying traffic."""
    import re
    from pathlib import Path as _P

    from blastbox.host.egress import GATE_OK_PATTERN

    script = (_P(__file__).resolve().parents[2] / "scripts/test-egress-leak.sh").read_text()
    greps = re.findall(r"grep -q '([^']+)'", script)
    overlay = [g for g in greps if "overlay peer" in g]
    assert overlay, "the leak test no longer greps for the gate line at all"
    for g in overlay:
        probe = g.replace(".*", "10.77.0.1")
        assert GATE_OK_PATTERN.search(probe), (
            f"the leak test greps {g!r}, which GATE_OK_PATTERN "
            f"({GATE_OK_PATTERN.pattern!r}) does not accept"
        )
