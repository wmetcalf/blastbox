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

# Maps exit_driver → docker network name for bridge-type exits.
# ``none`` and ``drop`` are handled directly (no bridge needed).
_BRIDGE_NETWORKS: dict[str, str] = {
    "direct": "bb-net0",
    "inetsim": "bb-fakenet",
}

# Drivers not yet implemented on the docker path (Plan 2 scope).
_UNSUPPORTED_DRIVERS = frozenset({"socks", "wireguard", "openvpn"})


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
