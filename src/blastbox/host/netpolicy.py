"""Network-personality policy core — declare, default, gate, resolve.

A *personality* is a named egress chain. This module is PURE policy/config: it parses
operator-declared personalities, holds the per-engine default + per-job request, and resolves
the effective personality FAIL-CLOSED. It applies no networking — a later plan reads the
resolved Personality and wires the worker's network.
"""
from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field

# Exit drivers the design names. `none` (default) and `drop` need no sidecar; `direct`/`inetsim`
# are ship-cheap; `socks` (tor/BrightData) + `wireguard`/`openvpn` (BYO creds) come with config.
VALID_EXIT_DRIVERS = (
    "none", "drop", "direct", "inetsim", "socks", "wireguard", "openvpn",
)


@dataclass
class Personality:
    """A named egress personality. ``config`` is opaque exit-specific data (socks endpoint,
    wireguard conf ref, dns, …) consumed by a later plan — kept verbatim here."""

    name: str
    exit_driver: str
    inspect: bool = False
    config: dict[str, str] = field(default_factory=dict)


# The always-present safe default: no egress. Resolution falls back here fail-closed.
NONE = Personality(name="none", exit_driver="none")
