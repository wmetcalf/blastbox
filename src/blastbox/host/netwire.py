"""Pure builders for ``blastbox-netd``'s SOCKS-tier netns wiring (P3).

The SOCKS tier routes an *uncooperative* sample transparently through a SOCKS5 exit (tor /
BrightData) — the sample needs no proxy awareness. The mechanism, validated live on toolz2
(tun2socks 2.6.0):

1. The worker runs on an **internal** bridge (``bb-socks``) with NO direct egress — fail-closed.
2. A SOCKS proxy sidecar is dual-homed: ``bb-socks`` (worker-facing) + an egress network.
3. netd, in the worker's netns, runs ``tun2socks`` against a TUN and moves the default route
   onto it, so every connection is tunneled to the SOCKS proxy. The proxy is on the worker's
   subnet, so it stays reachable via the link route after the default route moves to the TUN.
4. DNS is forced over **TCP** (``options use-vc``): a no-``UDP ASSOCIATE`` SOCKS proxy — which
   includes tor — cannot carry UDP DNS, so UDP :53 would silently fail. Over TCP it tunnels fine.

This module is the pure, unit-testable form of those commands; ``netd`` runs them in the worker's
netns via ``nsenter``. The proven egress check: before wiring, the netns has no route out
(``Network is unreachable``); after, traffic egresses with the proxy's exit IP.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass

# Docker label an egress worker carries to request netd netns wiring (set by the dispatcher).
# Value is the wire mode — only "socks" today.
WIRE_LABEL = "blastbox.net.wire"
JOB_ID_LABEL = "blastbox.job_id"
_WIRE_MODES = frozenset({"socks"})


@dataclass(frozen=True)
class WireTarget:
    """What netd needs to wire one worker's netns for a SOCKS exit."""

    container: str
    job_id: str
    pid: int
    mode: str


def wire_target_from_inspect(inspect: Mapping[str, object]) -> WireTarget | None:
    """Decide whether a container wants netns wiring, from its ``docker inspect`` payload. Returns
    ``None`` unless it is labeled ``blastbox.net.wire=<mode>`` with a known mode AND the runtime
    exposed a real ``State.Pid`` (the netns to enter). A gVisor worker has no host-visible
    pid/netns to wire — it would yield pid 0 here and be skipped (gVisor is SOCKS-excluded)."""
    config = inspect.get("Config") or {}
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return None
    mode = str(labels.get(WIRE_LABEL, "")).strip().lower()
    if mode not in _WIRE_MODES:
        return None
    job_id = labels.get(JOB_ID_LABEL)
    if not job_id:
        return None
    state = inspect.get("State") or {}
    pid = state.get("Pid") if isinstance(state, Mapping) else None
    if not isinstance(pid, int) or pid <= 0:
        return None
    name = str(inspect.get("Name") or "").lstrip("/") or str(job_id)
    return WireTarget(container=name, job_id=str(job_id), pid=pid, mode=mode)

# tun2socks' default fake gateway range; 198.18.0.0/15 (RFC 2544 benchmark) deliberately avoids
# the worker's RFC1918 bridge IP so the TUN addressing never collides with bb-socks.
TUN_DEV = "tun0"
TUN_ADDR = "198.18.0.1/15"

# tun2socks accepts exactly these (NOT "warning" — that is a fatal arg).
_VALID_LOGLEVELS = ("silent", "error", "warn", "info", "debug")

# A conservative token: no whitespace, no '@', no '/', no ':' — safe to splice into a URL/arg.
_SAFE_CRED = re.compile(r"^[A-Za-z0-9._~%-]+$")


def _validate_endpoint(endpoint: str) -> str:
    """Validate a ``host:port`` SOCKS endpoint (host is an IP or a hostname label, port 1-65535).
    The endpoint becomes part of a process argument, so it must contain exactly one ``:`` and no
    shell/URL-significant characters."""
    if endpoint != endpoint.strip() or " " in endpoint:
        raise ValueError(f"invalid socks endpoint {endpoint!r}")
    if endpoint.count(":") != 1:
        raise ValueError(f"socks endpoint must be host:port, got {endpoint!r}")
    host, _, port = endpoint.partition(":")
    if not host or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
        raise ValueError(f"invalid socks host {host!r}")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ValueError(f"invalid socks port {port!r}")
    return endpoint


def socks_proxy_url(endpoint: str, *, user: str | None, password: str | None) -> str:
    """Build a ``socks5://[user:pass@]host:port`` URL for tun2socks. Credentials, if present,
    must be simple tokens (no ``@``/``:``/whitespace) since they go unescaped into the URL."""
    _validate_endpoint(endpoint)
    if bool(user) != bool(password):
        raise ValueError("socks user and password must be set together or both omitted")
    if user and password:
        if not _SAFE_CRED.match(user) or not _SAFE_CRED.match(password):
            raise ValueError("socks credentials contain disallowed characters")
        return f"socks5://{user}:{password}@{endpoint}"
    return f"socks5://{endpoint}"


def tun2socks_argv(proxy_url: str, *, device: str = TUN_DEV, loglevel: str = "info") -> list[str]:
    """The proven ``tun2socks`` invocation: create+serve ``device`` (a TUN), forward everything to
    ``proxy_url`` (a ``socks5://…`` URL). ``loglevel`` is allow-listed — ``warning`` is fatal."""
    if loglevel not in _VALID_LOGLEVELS:
        raise ValueError(
            f"invalid tun2socks loglevel {loglevel!r}; use one of {', '.join(_VALID_LOGLEVELS)}"
        )
    return ["tun2socks", "-device", f"tun://{device}", "-proxy", proxy_url, "-loglevel", loglevel]


def tun_setup_commands(*, device: str = TUN_DEV, tun_addr: str = TUN_ADDR) -> list[list[str]]:
    """The ``ip(8)`` sequence run in the worker netns AFTER tun2socks created ``device``: address
    the TUN, bring it up, and move the default route onto it (``replace`` — there may be no
    pre-existing default on an internal bridge). The proxy stays reachable via the subnet link
    route, so no extra proxy host-route is needed when the proxy is on the worker's subnet."""
    return [
        ["ip", "addr", "add", tun_addr, "dev", device],
        ["ip", "link", "set", device, "up"],
        ["ip", "route", "replace", "default", "dev", device],
    ]


def socks_resolv_conf(nameserver: str) -> str:
    """``/etc/resolv.conf`` content for a SOCKS worker: a real resolver plus ``options use-vc`` to
    force DNS over TCP (so it tunnels through a no-UDP SOCKS proxy)."""
    ipaddress.ip_address(nameserver.strip())  # raises ValueError on a non-IP
    return f"nameserver {nameserver.strip()}\noptions use-vc\n"
