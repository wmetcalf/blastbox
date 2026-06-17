"""TDD tests for blastbox.host.netapply.docker_network_args."""
from __future__ import annotations

import logging

import pytest

from blastbox.host.netapply import docker_network_args
from blastbox.host.netpolicy import Personality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _p(exit_driver: str, name: str | None = None) -> Personality:
    return Personality(name=name or exit_driver, exit_driver=exit_driver)


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
