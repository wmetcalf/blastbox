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


@pytest.mark.parametrize("driver", ["socks", "wireguard", "openvpn"])
def test_unsupported_driver_falls_back_to_none(driver, caplog):
    with caplog.at_level(logging.WARNING, logger="blastbox.host.netapply"):
        result = docker_network_args(_p(driver))

    assert result == ["--network=none"], f"expected --network=none for {driver!r}"
    assert any(
        "not yet supported" in r.message and driver in r.message
        for r in caplog.records
    ), f"expected warning mentioning {driver!r}, got: {[r.message for r in caplog.records]}"


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
        result = docker_network_args(_p("tor"))  # hypothetical future driver

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
