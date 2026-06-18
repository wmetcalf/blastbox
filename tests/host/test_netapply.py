"""TDD tests for blastbox.host.netapply.docker_network_args."""
from __future__ import annotations

import logging

import pytest

from blastbox.host.netapply import docker_network_args, worker_resolv_conf
from blastbox.host.netpolicy import Personality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _p(
    exit_driver: str,
    name: str | None = None,
    config: dict[str, str] | None = None,
) -> Personality:
    return Personality(
        name=name or exit_driver, exit_driver=exit_driver, config=config or {}
    )


# ---------------------------------------------------------------------------
# No-egress exits
# ---------------------------------------------------------------------------


def test_none_driver_returns_network_none():
    assert docker_network_args(_p("none")) == ["--network=none"]


def test_drop_driver_returns_network_none():
    assert docker_network_args(_p("drop")) == ["--network=none"]


# ---------------------------------------------------------------------------
# Bridge exits
# ---------------------------------------------------------------------------


def test_direct_driver_returns_bb_net0():
    args = docker_network_args(_p("direct"))
    assert args == ["--network", "bb-net0"]


def test_inetsim_driver_returns_bb_fakenet():
    args = docker_network_args(_p("inetsim"))
    assert args == ["--network", "bb-fakenet"]


# ---------------------------------------------------------------------------
# Unsupported / not-yet-implemented exits — fail-closed + warn
# ---------------------------------------------------------------------------


def test_socks_driver_returns_bb_socks():
    # socks → the INTERNAL bb-socks bridge (netd wires the TUN+tun2socks egress).
    assert docker_network_args(_p("socks")) == ["--network", "bb-socks"]


@pytest.mark.parametrize("driver", ["openvpn", "wireguard"])
def test_vpn_drivers_return_bb_vpn(driver):
    # IP-tunnel VPN exits → the INTERNAL bb-vpn bridge (netd routes via the VPN gateway sidecar).
    assert docker_network_args(_p(driver)) == ["--network", "bb-vpn"]


def test_tor_driver_returns_bb_socks_internal():
    # tor (CAPE transparent) rides the INTERNAL bb-socks bridge; the host REDIRECTs it to tor.
    assert docker_network_args(_p("tor")) == ["--network", "bb-socks"]


def test_httpproxy_driver_returns_bb_socks_internal():
    # httpproxy rides the INTERNAL bb-socks bridge; egress is only the injected HTTP(S)_PROXY env.
    assert docker_network_args(_p("httpproxy")) == ["--network", "bb-socks"]


def test_httpproxy_honors_dns_for_sidecar_resolution():
    # The proxy does CONNECT-by-hostname for the TARGET (DNS at the exit), but the worker STILL must
    # resolve the proxy SIDECAR's hostname — and a runsc worker can't reach docker's 127.0.0.11 — so
    # httpproxy honors dns= when set. NOT use-vc (httpproxy isn't a no-UDP SOCKS proxy).
    out = worker_resolv_conf(_p("httpproxy", config={"dns": "1.1.1.1"}))
    assert out == "nameserver 1.1.1.1\n"


def test_httpproxy_no_resolv_without_dns():
    # No dns= set → keep docker's default resolv.conf (opt-in only).
    assert worker_resolv_conf(_p("httpproxy")) is None


def test_resolv_skips_non_ip_dns_servers():
    # A typo'd / non-IP dns= token is dropped (would otherwise write a broken resolv.conf).
    out = worker_resolv_conf(_p("direct", config={"dns": "1.1.1.1 not-an-ip 8.8.8.8"}))
    assert out == "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"


def test_resolv_none_when_all_dns_invalid():
    assert worker_resolv_conf(_p("direct", config={"dns": "bogus"})) is None


def test_resolv_tor_is_udp_not_use_vc():
    # tor DNS is REDIRECTed to tor's DNSPort (UDP-only); use-vc would break it.
    out = worker_resolv_conf(_p("tor", config={"dns": "172.30.0.1"}))
    assert out == "nameserver 172.30.0.1\n"
    assert "use-vc" not in out


# ---------------------------------------------------------------------------
# Inspect layer: an inspected egress worker rides bb-inspect (faces the MITM gateway), regardless
# of the underlying exit driver. Inspect is ignored for no-egress (none/drop) exits.
# ---------------------------------------------------------------------------


def _inspect_p(exit_driver: str, config: dict[str, str] | None = None) -> Personality:
    return Personality(
        name=f"inspect-{exit_driver}", exit_driver=exit_driver, inspect=True, config=config or {}
    )


@pytest.mark.parametrize("driver", ["direct", "inetsim", "tor", "socks", "openvpn", "wireguard"])
def test_inspect_egress_rides_bb_inspect(driver):
    # The worker faces the sslproxy/MITM gateway on bb-inspect, NOT the exit's own bridge. Every
    # route-inspectable egress driver qualifies (httpproxy does NOT — see below).
    assert docker_network_args(_inspect_p(driver)) == ["--network", "bb-inspect"]


@pytest.mark.parametrize("driver", ["none", "drop"])
def test_inspect_ignored_for_no_egress(driver):
    # Nothing to intercept without an exit — fail-closed to --network=none, inspect is a no-op.
    assert docker_network_args(_inspect_p(driver)) == ["--network=none"]


def test_inspect_with_unknown_driver_still_fails_closed(caplog):
    # An unknown exit driver must not be granted bb-inspect on the strength of inspect=True.
    with caplog.at_level(logging.WARNING, logger="blastbox.host.netapply"):
        assert docker_network_args(_inspect_p("i2p")) == ["--network=none"]


def test_inspect_httpproxy_fails_closed_not_degraded(caplog):
    # httpproxy is an app-level CONNECT proxy (not a routed path) → cannot be route-MITM'd. inspect
    # must NOT silently degrade it to a plain proxy on bb-socks (that would drop the inspection
    # guarantee); it fails closed to --network=none + warns.
    with caplog.at_level(logging.WARNING, logger="blastbox.host.netapply"):
        assert docker_network_args(
            _inspect_p("httpproxy", {"proxy": "http://172.30.0.30:8888"})
        ) == ["--network=none"]
    assert any("inspect is not supported" in r.message for r in caplog.records)


def test_httpproxy_without_inspect_still_rides_bb_socks():
    # Sanity: plain (un-inspected) httpproxy is unaffected — still its normal internal bridge.
    assert docker_network_args(_p("httpproxy")) == ["--network", "bb-socks"]


def test_inspect_routes_via_gateway_predicate():
    from blastbox.host.netapply import inspect_routes_via_gateway
    assert inspect_routes_via_gateway(_inspect_p("socks")) is True
    assert inspect_routes_via_gateway(_inspect_p("tor")) is True
    assert inspect_routes_via_gateway(_inspect_p("httpproxy")) is False  # not route-inspectable
    assert inspect_routes_via_gateway(_p("socks")) is False  # inspect not requested


def test_driver_set_consistency():
    # Guard against the "added a driver to one set but forgot another" drift class. Every set the
    # netapply/netwire layer keys on must be a subset of the canonical VALID_EXIT_DRIVERS.
    from blastbox.host import netapply
    from blastbox.host.netpolicy import VALID_EXIT_DRIVERS

    valid = set(VALID_EXIT_DRIVERS)
    assert netapply._EGRESS_DRIVERS <= valid
    assert netapply._SOCKS_DRIVERS <= netapply._EGRESS_DRIVERS
    assert netapply._RESOLV_DRIVERS <= valid
    assert netapply._EGRESS_DRIVERS <= netapply._RESOLV_DRIVERS  # resolv covers egress + httpproxy
    assert set(netapply._BRIDGE_NETWORKS) <= valid
    # httpproxy is the one egress driver deliberately excluded from the route-inspectable set.
    assert "httpproxy" in valid and "httpproxy" not in netapply._EGRESS_DRIVERS
    # Every non-no-egress valid driver has a bridge mapping (else docker_network_args fails closed).
    assert set(netapply._BRIDGE_NETWORKS) == valid - {"none", "drop"}


# ---------------------------------------------------------------------------
# Return type is always list[str]
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("driver", ["none", "drop", "direct", "inetsim", "socks"])
def test_return_type_is_list_of_str(driver):
    result = docker_network_args(_p(driver))
    assert isinstance(result, list)
    assert all(isinstance(x, str) for x in result)


# ---------------------------------------------------------------------------
# Fail-closed: an unknown (future) driver also falls back
# ---------------------------------------------------------------------------


def test_unknown_driver_falls_back_to_none(caplog):
    """Any exit_driver that is not none/drop/direct/inetsim falls back to --network=none."""
    with caplog.at_level(logging.WARNING, logger="blastbox.host.netapply"):
        result = docker_network_args(_p("i2p"))  # hypothetical future driver

    assert result == ["--network=none"]
    assert any("not yet supported" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# worker_resolv_conf — inject a real resolver for egress personalities
#
# On a docker user-defined bridge, docker forces the container's only nameserver to its
# embedded resolver 127.0.0.11, which a gVisor (runsc) worker cannot reach — so an egress
# worker on the default cold runtime gets L3 connectivity but no DNS. Bind-mounting a
# resolv.conf naming a real resolver restores it (harmless under runc). Opt-in per
# personality via ``dns=`` in the BLASTBOX_NETPOLICY_<NAME> declaration.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("driver", ["none", "drop"])
def test_resolv_none_for_no_egress_drivers(driver):
    # no-egress personalities never reach a network — nothing to inject, even with dns set.
    assert worker_resolv_conf(_p(driver, config={"dns": "1.1.1.1"})) is None


@pytest.mark.parametrize("driver", ["direct", "inetsim", "socks", "wireguard", "openvpn"])
def test_resolv_none_when_no_dns_configured(driver):
    # Opt-in: with no dns= the operator keeps docker's default resolv.conf (prior behavior).
    assert worker_resolv_conf(_p(driver)) is None


def test_resolv_direct_with_public_resolver():
    out = worker_resolv_conf(_p("direct", config={"dns": "1.1.1.1"}))
    assert out == "nameserver 1.1.1.1\n"


def test_resolv_inetsim_points_at_fakenet_sidecar():
    out = worker_resolv_conf(_p("inetsim", config={"dns": "10.7.0.53"}))
    assert out == "nameserver 10.7.0.53\n"


def test_resolv_multiple_whitespace_separated_resolvers():
    # comma is the decl KV separator, so multiple resolvers are whitespace-separated.
    out = worker_resolv_conf(_p("direct", config={"dns": "1.1.1.1 8.8.8.8"}))
    assert out == "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"


def test_resolv_blank_dns_is_treated_as_unset():
    assert worker_resolv_conf(_p("direct", config={"dns": "   "})) is None


def test_resolv_ends_with_newline():
    out = worker_resolv_conf(_p("socks", config={"dns": "9.9.9.9"}))
    assert out is not None and out.endswith("\n")


def test_resolv_socks_forces_dns_over_tcp():
    # A socks exit can't carry UDP DNS → resolv.conf must add options use-vc (force TCP).
    out = worker_resolv_conf(_p("socks", config={"dns": "1.1.1.1"}))
    assert out == "nameserver 1.1.1.1\noptions use-vc\n"


def test_resolv_direct_does_not_force_tcp():
    # A direct egress worker has normal UDP DNS — no use-vc.
    out = worker_resolv_conf(_p("direct", config={"dns": "1.1.1.1"}))
    assert "use-vc" not in out


def test_resolv_socks_dns_tcp_opt_out():
    # dns_tcp=0 → DNS goes UDP-direct to a dedicated resolver (e.g. tor's DNSPort, which refuses
    # TCP); use-vc must NOT be forced or resolution breaks.
    out = worker_resolv_conf(_p("socks", config={"dns": "172.30.0.20", "dns_tcp": "0"}))
    assert out == "nameserver 172.30.0.20\n"
    assert "use-vc" not in out
