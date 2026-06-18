"""Translate a resolved Personality into Docker ``--network`` argv fragments.

This module is the *application* side of the netpolicy layer: given a fully-resolved
:class:`~blastbox.host.netpolicy.Personality` (returned by ``resolve_net_policy``), return
the list of ``--network``-related flags to splice into the worker ``docker run`` argv.

Plan 2 implements the docker-native exit drivers only:

* ``none`` / ``drop``  → ``["--network=none"]``   (no egress, default/safe)
* ``direct``           → ``["--network", "bb-net0"]``
* ``inetsim``          → ``["--network", "bb-fakenet"]``

Exit drivers that require a sidecar (``socks``, ``wireguard``, ``openvpn``) are NOT yet
wired on the docker path.  They fall back FAIL-CLOSED to ``--network=none`` and log a
warning — the operator must not be silently granted unexpected egress.

Operators are responsible for pre-creating ``bb-net0`` / ``bb-fakenet`` docker networks on
the host before launching the dispatcher.  This module only names them in the argv; it
never creates or inspects them.
"""
from __future__ import annotations

import logging

from blastbox.host.netpolicy import Personality


_log = logging.getLogger("blastbox.host.netapply")

# Maps exit_driver → docker network name for bridge-attached exits.
# ``none`` and ``drop`` are handled directly (no bridge needed).
#   direct  → bb-net0    (egress bridge)
#   inetsim → bb-fakenet (internal; FakeNet-NG sidecar answers everything)
#   socks   → bb-socks   (INTERNAL: no direct egress. netd wires a TUN + tun2socks → the SOCKS
#             proxy sidecar [dual-homed on bb-socks + an egress net], so the worker can ONLY
#             egress through the proxy — fail-closed. The internal bridge IS the fail-closed
#             property; if netd never wires it, the worker simply has no egress.)
_BRIDGE_NETWORKS: dict[str, str] = {
    "direct": "bb-net0",
    "inetsim": "bb-fakenet",
    # tor (CAPE transparent recipe): INTERNAL bridge; netd default-routes the worker at the host
    # gateway and the HOST REDIRECTs its TCP→tor TransPort / DNS→tor DNSPort (keyed on worker IP),
    # dropping everything else. Same fail-closed property as bb-socks — no host rules ⇒ no egress.
    "tor": "bb-socks",
    "socks": "bb-socks",
    # IP-tunnel VPN exits (all-IP). INTERNAL bridge: no direct egress; netd points the worker's
    # default route at the VPN+NAT gateway sidecar on bb-vpn (an OpenVPN/WireGuard client). Same
    # fail-closed property as bb-socks — no gateway wiring ⇒ no egress.
    "openvpn": "bb-vpn",
    "wireguard": "bb-vpn",
}

# Every named driver is now wired on the docker path; nothing is fail-closed-unsupported.
_UNSUPPORTED_DRIVERS: frozenset[str] = frozenset()

# Exit drivers that put the worker on a network where name resolution matters. ``none`` /
# ``drop`` never reach a resolver, so they are excluded.
_EGRESS_DRIVERS = frozenset({"direct", "inetsim", "tor", "socks", "wireguard", "openvpn"})

# Drivers whose egress is a SOCKS proxy that can't carry UDP DNS — DNS must go over TCP. NOT ``tor``:
# its DNS is REDIRECTed straight to tor's DNSPort (UDP), which refuses TCP, so use-vc would break it.
_SOCKS_DRIVERS = frozenset({"socks"})

# The internal bridge an INSPECTED worker rides. When ``personality.inspect`` is set, the worker
# faces an sslproxy/MITM gateway sidecar here (which forges TLS certs, exports master keys for
# decrypt, then forwards to the real exit network). The worker never attaches the exit's own
# bridge — netd points its default route at the gateway. Operators pre-create ``bb-inspect``.
INSPECT_BRIDGE = "bb-inspect"


def docker_network_args(personality: Personality) -> list[str]:
    """Return the ``--network`` fragment for a worker ``docker run`` argv.

    Always returns a non-empty list (fail-closed to ``["--network=none"]``).

    Parameters
    ----------
    personality:
        The fully-resolved :class:`~blastbox.host.netpolicy.Personality` for this job.
    """
    driver = personality.exit_driver

    # Fast path: no-network exits.
    if driver in ("none", "drop"):
        return ["--network=none"]

    # Inspect layer: an inspected egress worker rides the internal bb-inspect bridge facing the
    # MITM gateway, NOT the exit's own bridge (the gateway forwards to the real exit). Only applies
    # to a valid egress driver — an unknown driver still falls through to the fail-closed warning.
    if personality.inspect and driver in _EGRESS_DRIVERS:
        return ["--network", INSPECT_BRIDGE]

    # Known bridge exits: directly supported.
    bridge = _BRIDGE_NETWORKS.get(driver)
    if bridge is not None:
        return ["--network", bridge]

    # Unsupported driver — fail-closed + warn so operators notice misconfiguration.
    _log.warning(
        "netpolicy: exit_driver %r not yet supported on the docker path; "
        "falling back to --network=none",
        driver,
    )
    return ["--network=none"]


def worker_resolv_conf(personality: Personality) -> str | None:
    """Return ``/etc/resolv.conf`` content to inject into an egress worker, or ``None`` to
    leave docker's generated resolv.conf untouched.

    Why this exists: on a docker *user-defined* bridge (``bb-net0`` / ``bb-fakenet``) docker
    pins the container's only nameserver to its embedded resolver ``127.0.0.11`` and forwards
    to the real upstream(s) internally. A gVisor (``runsc``) worker — the default cold runtime
    — cannot reach ``127.0.0.11`` through gVisor's netstack, so an egress worker gets L3/TCP
    connectivity but no DNS. Bind-mounting a resolv.conf that names a *real* resolver (docker
    honors an explicit ``/etc/resolv.conf`` bind-mount and does not overwrite it) restores name
    resolution under ``runsc`` and is a harmless no-op under ``runc``.

    The resolver is per-personality: a public resolver for ``direct``, the fakenet DNS sidecar
    for ``inetsim``, etc. Declared with ``dns=`` in the ``BLASTBOX_NETPOLICY_<NAME>`` entry
    (whitespace-separated for multiple — ``,`` is the decl's KV separator). With no ``dns=``
    set, return ``None`` so the operator keeps docker's default (opt-in, prior behavior).
    """
    if personality.exit_driver not in _EGRESS_DRIVERS:
        return None
    servers = (personality.config.get("dns") or "").split()
    if not servers:
        return None
    body = "".join(f"nameserver {s}\n" for s in servers)
    # A SOCKS exit (tor included) usually can't carry UDP DNS (no UDP ASSOCIATE), so DNS tunneled
    # THROUGH the proxy must go over TCP (options use-vc). But when ``dns=`` points at a dedicated
    # UDP resolver reached DIRECTLY (not via the proxy) — e.g. tor's own DNSPort, which answers UDP
    # and REFUSES TCP — forcing use-vc breaks resolution. Operators opt out with ``dns_tcp=0``.
    if personality.exit_driver in _SOCKS_DRIVERS and \
            personality.config.get("dns_tcp", "1").strip().lower() not in ("0", "false", "no"):
        body += "options use-vc\n"
    return body
