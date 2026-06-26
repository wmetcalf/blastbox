"""Unit tests for the VPN/tunnel monitor (pure; no real interface)."""
from __future__ import annotations

from blastbox.host.runtime.tunnel_guard import TunnelGuard, interface_is_up


class _Link:
    def __init__(self, out, rc=0):
        self.stdout = out
        self.returncode = rc


def _runner(out, rc=0):
    def run(*a, **k):
        return _Link(out, rc)
    return run


def test_interface_is_up_parses_flags():
    assert interface_is_up("tun0", runner=_runner(
        "3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500")) is True
    assert interface_is_up("tun0", runner=_runner(
        "3: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500")) is False
    assert interface_is_up("tun0", runner=_runner("", rc=1)) is False


def test_guard_fires_down_then_recovers():
    events: list[str] = []
    state = {"up": True}
    g = TunnelGuard("tun0",
                    on_down=lambda t: events.append("down"),
                    on_up=lambda t: events.append("up"),
                    recover=lambda t: events.append("recover"),
                    is_up=lambda t: state["up"])
    assert g.check() is True
    assert events == []                 # first healthy probe: no spurious "recovered"
    state["up"] = False
    assert g.check() is False
    assert events == ["down", "recover"]  # down-edge: alert THEN recover
    assert g.check() is False
    assert events == ["down", "recover"]  # still down: no re-fire (edge-triggered)
    state["up"] = True
    assert g.check() is True
    assert events == ["down", "recover", "up"]  # up-edge fires on_up


def test_guard_callback_failure_is_non_fatal():
    def boom(t):
        raise RuntimeError("pager down")
    g = TunnelGuard("tun0", on_down=boom, is_up=lambda t: False)
    assert g.check() is False  # raising hook doesn't propagate
