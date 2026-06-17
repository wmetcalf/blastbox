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


_NETPOLICY_PREFIX = "BLASTBOX_NETPOLICY_"


def _parse_decl(name: str, raw: str) -> Personality | None:
    """Parse one ``exit=...,k=v,...`` declaration into a Personality, or None (warn) if
    malformed. Comma-separated KEY=VALUE (values can't contain a comma — fine here)."""
    kv: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            print(f"warning: ignoring malformed netpolicy {name!r} entry {item!r} "
                  "(expected KEY=VALUE)", file=sys.stderr)
            return None
        k, _, v = item.partition("=")
        kv[k.strip().lower()] = v.strip()

    exit_driver = kv.pop("exit", "")
    if exit_driver not in VALID_EXIT_DRIVERS:
        print(f"warning: ignoring netpolicy {name!r}: exit={exit_driver!r} not one of "
              f"{', '.join(VALID_EXIT_DRIVERS)}", file=sys.stderr)
        return None
    inspect = kv.pop("inspect", "").lower() in ("1", "true", "yes", "on")
    return Personality(name=name, exit_driver=exit_driver, inspect=inspect, config=kv)


def parse_personalities(env: Mapping[str, str]) -> dict[str, Personality]:
    """Build the personality registry from ``BLASTBOX_NETPOLICY_<NAME>`` env vars. ``none`` is
    always present (the fail-closed default). A declaration with an unknown exit-driver or
    missing ``exit`` is warned-and-skipped, so it never becomes selectable."""
    registry: dict[str, Personality] = {"none": NONE}
    for env_key, raw in env.items():
        if not env_key.startswith(_NETPOLICY_PREFIX):
            continue
        name = env_key[len(_NETPOLICY_PREFIX):].lower()
        if not name:
            continue
        p = _parse_decl(name, raw or "")
        if p is not None:
            registry[name] = p
    return registry


def resolve_net_policy(
    *,
    job_net_policy: str | None,
    engine_default: str,
    registry: Mapping[str, Personality],
    allow_override: bool,
) -> Personality:
    """Resolve the effective personality, FAIL-CLOSED to ``none``. Order: per-job override
    (only when ``allow_override`` AND the name is declared) → per-engine default (when declared)
    → ``none``. An unknown name at any step collapses to ``none`` rather than erroring."""
    if allow_override and job_net_policy and job_net_policy in registry:
        return registry[job_net_policy]
    if engine_default in registry:
        return registry[engine_default]
    return registry.get("none", NONE)
