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
    socks_proxy_url,
    socks_resolv_conf,
    tun2socks_argv,
    tun_setup_commands,
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


# --------------------------------------------------------------------------- gateway (vpn) route
def test_gateway_route_replaces_default_via_gw():
    assert gateway_route_commands("172.31.0.10") == \
        [["ip", "route", "replace", "default", "via", "172.31.0.10"]]


def test_gateway_route_rejects_non_ip():
    with pytest.raises(ValueError):
        gateway_route_commands("not-an-ip")
    with pytest.raises(ValueError):
        gateway_route_commands("10.0.0.1 ; rm -rf")
