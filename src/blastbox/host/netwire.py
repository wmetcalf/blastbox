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
# Value is the wire MODE:
#   socks      → tun2socks in the worker netns → a SOCKS5 exit (TCP+TCP-DNS; tor/BrightData).
#   vpn        → move the worker's default route onto a VPN+NAT gateway sidecar (all-IP; OpenVPN/WG).
#   inspect    → move the default route onto an sslproxy/MITM gateway sidecar (transparent TLS
#                intercept that exports master keys for decrypt, then forwards to the real exit).
#   transproxy → CAPE's tor recipe: default route → host gateway + HOST-side iptables REDIRECT of
#                the worker's TCP → tor TransPort and DNS → tor DNSPort, keyed on the worker IP.
#                Block everything else. tor runs on the host netns so SO_ORIGINAL_DST works.
WIRE_LABEL = "blastbox.net.wire"
JOB_ID_LABEL = "blastbox.job_id"
# Per-worker SOCKS5 endpoint for the socks tier (overrides netd's global --socks-proxy). Lets one
# netd serve MANY socks backends at once — e.g. a fleet of country-pinned tor SocksPort exits, each
# personality routing to a different one. Value is a socks5://[user:pass@]host:port URL.
SOCKS_PROXY_LABEL = "blastbox.net.socks-proxy"
_WIRE_MODES = frozenset({"socks", "vpn", "inspect", "transproxy"})


@dataclass(frozen=True)
class WireTarget:
    """What netd needs to wire one worker's netns for a SOCKS exit. ``worker_ip`` is the worker's
    egress-bridge address (needed only by the host-side ``transproxy`` rooter, keyed on source IP).
    ``socks_proxy`` is the per-worker SOCKS5 URL (socks tier), empty → netd's global proxy."""

    container: str
    job_id: str
    pid: int
    mode: str
    worker_ip: str = ""
    socks_proxy: str = ""


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
    return WireTarget(
        container=name, job_id=str(job_id), pid=pid, mode=mode,
        worker_ip=_first_worker_ip(inspect),
        socks_proxy=str(labels.get(SOCKS_PROXY_LABEL, "")).strip(),
    )


def _first_worker_ip(inspect: Mapping[str, object]) -> str:
    """The worker's egress-bridge IPv4 (an egress worker is single-homed by design). Empty if none —
    only the host-side ``transproxy`` rooter needs it; other modes nsenter the netns by pid."""
    netsettings = inspect.get("NetworkSettings") or {}
    networks = netsettings.get("Networks") if isinstance(netsettings, Mapping) else None
    if not isinstance(networks, Mapping):
        return ""
    for net in networks.values():
        if isinstance(net, Mapping) and net.get("IPAddress"):
            try:
                return str(ipaddress.ip_address(str(net["IPAddress"])))
            except ValueError:
                continue
    return ""

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


def validate_socks_url(url: str) -> str:
    """Validate a FULL ``socks5://[user:pass@]host:port`` URL (netd's ``--socks-proxy`` default OR a
    per-worker ``blastbox.net.socks-proxy`` label) before it becomes a ``tun2socks`` argument, by
    round-tripping it through the same endpoint/credential validators as :func:`socks_proxy_url`.

    The per-worker URL is operator-supplied (not attacker-supplied), and it lands as a single argv
    element (no shell), so this is not an injection fix — it closes a validation ASYMMETRY: an
    operator typo (stray whitespace/newline, malformed ``user:pass@``) would otherwise be passed
    verbatim to the proxy process. Returns the canonical URL; raises ``ValueError`` on anything
    malformed so the caller can fail closed (no wire ⇒ no egress)."""
    if url != url.strip() or not url.startswith("socks5://"):
        raise ValueError(f"socks proxy url must be socks5://…, got {url!r}")
    rest = url[len("socks5://"):]
    user: str | None = None
    password: str | None = None
    if "@" in rest:
        creds, _, endpoint = rest.rpartition("@")
        if ":" not in creds:
            raise ValueError(f"socks credentials must be user:pass, got {creds!r}")
        user, _, password = creds.partition(":")
    else:
        endpoint = rest
    return socks_proxy_url(endpoint, user=user, password=password)


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


def gateway_route_commands(gateway_ip: str) -> list[list[str]]:
    """The ``ip(8)`` sequence (run in the worker netns) for the VPN tier: point the default route
    at a VPN+NAT gateway sidecar. ``replace`` because an internal bridge has no pre-existing
    default. The gateway (an OpenVPN/WireGuard client that NATs through its tunnel) is on the
    worker's subnet, so it stays reachable via the link route after the default moves.

    Unlike the SOCKS tier this is a full IP path (ICMP/UDP/raw all work) and needs no in-netns
    TUN — the gateway sidecar owns the tunnel; the worker just routes through it."""
    ip = str(ipaddress.ip_address(gateway_ip.strip()))  # raises ValueError on a non-IP
    return [["ip", "route", "replace", "default", "via", ip]]


def _port(p: int) -> str:
    if not isinstance(p, int) or not (1 <= p <= 65535):
        raise ValueError(f"invalid port {p!r}")
    return str(p)


def transproxy_redirect_rules(
    worker_ip: str, *, trans_port: int, dns_port: int, add: bool = True
) -> list[list[str]]:
    """CAPE's tor recipe as HOST-netns ``iptables`` argv, keyed on the worker's source IP:

    * DNS (udp+tcp :53)  → REDIRECT to tor's DNSPort  — tor resolves over the tor network.
    * TCP (--syn)        → REDIRECT to tor's TransPort — tor connects to SO_ORIGINAL_DST over tor.
    * everything else    → FORWARD DROP (leak guard; the worker's only escape is the two REDIRECTs).

    These run in the HOST netns (where tor listens, so REDIRECT's SO_ORIGINAL_DST is readable),
    NOT the worker netns. ``add`` toggles add vs ``-D`` (delete, on teardown); the match spec is
    identical so teardown removes exactly what wiring inserted. The worker's default route must
    already point at the host bridge gateway (see ``gateway_route_commands``).

    The nat REDIRECTs are **appended** (``-A``) so their in-chain order matches this list order — the
    DNS (:53) rules must sit ABOVE the TCP-SYN catch-all, or a TCP-DNS SYN would match the catch-all
    first and be sent to TransPort instead of DNSPort. The FORWARD DROP is **inserted** (``-I``) at
    the head so it takes precedence over any broader docker ACCEPT (the leak-guard property)."""
    ip = str(ipaddress.ip_address(worker_ip.strip()))  # raises ValueError on a non-IP
    tp, dp = _port(trans_port), _port(dns_port)
    nat_op = "-A" if add else "-D"
    filt_op = "-I" if add else "-D"
    return [
        ["iptables", "-t", "nat", nat_op, "PREROUTING",
         "-s", ip, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dp],
        ["iptables", "-t", "nat", nat_op, "PREROUTING",
         "-s", ip, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dp],
        ["iptables", "-t", "nat", nat_op, "PREROUTING",
         "-s", ip, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", tp],
        ["iptables", "-t", "filter", filt_op, "FORWARD", "-s", ip, "-j", "DROP"],
    ]


# A worker carries this label so netd installs an in-netns non-TCP leak guard. Value is the mode:
#   strict → drop ALL non-TCP egress (the SOCKS/httpproxy tiers carry only TCP).
#   dns    → also ACCEPT UDP:53 (the tor tier needs it to reach the host DNSPort REDIRECT).
LEAKGUARD_LABEL = "blastbox.net.leakguard"
_LEAKGUARD_MODES = frozenset({"strict", "dns"})


def leakguard_from_inspect(inspect: Mapping[str, object]) -> tuple[int, bool] | None:
    """``(pid, allow_udp_dns)`` if the container is labeled ``blastbox.net.leakguard=strict|dns`` and
    exposes a host-visible ``State.Pid`` (runc/FC), else ``None``. ``allow_udp_dns`` is True for the
    ``dns`` mode (tor tier)."""
    config = inspect.get("Config") or {}
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return None
    mode = str(labels.get(LEAKGUARD_LABEL, "")).strip().lower()
    if mode not in _LEAKGUARD_MODES:
        return None
    state = inspect.get("State") or {}
    pid = state.get("Pid") if isinstance(state, Mapping) else None
    if not isinstance(pid, int) or pid <= 0:
        return None
    return (pid, mode == "dns")


# Two composable egress-hardening knobs, set by the dispatcher from the personality config and read
# here so netd can fold them into the worker-netns OUTPUT firewall:
#   blastbox.net.egress-ports = "53,80,443"  → an L4 allowlist (web-only: DNS/HTTP/HTTPS). Drop the
#                                              rest — other TCP ports AND all non-TCP.
#   blastbox.net.block-internal = "1"         → drop RFC1918 + link-local/metadata destinations.
# Both apply to ANY egress tier (they ride the same leak-guard wiring). Proven live on toolz3.
EGRESS_PORTS_LABEL = "blastbox.net.egress-ports"
BLOCK_INTERNAL_LABEL = "blastbox.net.block-internal"


def egress_filter_from_inspect(
    inspect: Mapping[str, object],
) -> tuple[tuple[int, ...] | None, bool]:
    """``(allowed_ports, block_internal)`` read from a container's labels. ``allowed_ports`` is the
    parsed :data:`EGRESS_PORTS_LABEL` allowlist (``None`` if unset/empty/all-invalid);
    ``block_internal`` is the :data:`BLOCK_INTERNAL_LABEL` flag. Returns ``(None, False)`` when a
    worker opted into neither — a no-op for every existing personality."""
    config = inspect.get("Config") or {}
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return (None, False)
    allowed_ports = parse_egress_ports(str(labels.get(EGRESS_PORTS_LABEL, "")) or None)
    block_internal = str(labels.get(BLOCK_INTERNAL_LABEL, "")).strip().lower() in (
        "1", "true", "yes", "on",
    )
    return (allowed_ports, block_internal)


# RFC1918 + link-local/cloud-metadata destinations a hardened egress worker must never reach: no
# SSRF into the host LAN, no 169.254.169.254 metadata, no lateral movement to sibling workers.
_INTERNAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")


def parse_egress_ports(raw: str | None) -> tuple[int, ...] | None:
    """Parse an ``egress_ports`` value (comma- or whitespace-separated port numbers) into a validated
    tuple, or ``None`` if nothing valid survives. Non-numeric / out-of-range (not 1-65535) tokens are
    skipped — a typo must neither widen the allowlist nor write a broken ``--dports``."""
    if not raw:
        return None
    ports: list[int] = []
    for tok in re.split(r"[,\s]+", raw.strip()):
        if not tok:
            continue
        try:
            p = int(tok)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            ports.append(p)
    return tuple(ports) or None


def leak_guard_rules(
    *,
    allow_udp_dns: bool,
    allowed_ports: tuple[int, ...] | None = None,
    block_internal: bool = False,
) -> list[list[str]]:
    """The WORKER-netns ``OUTPUT`` firewall. Run via ``nsenter`` into the worker netns; OUTPUT is
    empty there (the worker has no CAP_NET_ADMIN), so appended rules apply in order. The LOG
    (``blastbox-leak-drop`` prefix → kernel log) is the audit trail of dropped egress.

    Default (no ``allowed_ports``/``block_internal``) is the historical TCP-only leak guard: ACCEPT
    loopback + TCP (+ UDP:53 when ``allow_udp_dns``), LOG+DROP everything else — so a sample's
    UDP/ICMP/raw can NEVER leave the netns.

    ``block_internal`` prepends a DROP for every :data:`_INTERNAL_NETS` destination (RFC1918 +
    link-local/metadata), before any ACCEPT, so internal egress is denied regardless of port/proto.

    ``allowed_ports`` switches to **web-only** mode: ACCEPT only DNS (UDP:53 when ``allow_udp_dns``)
    + the TCP port allowlist, then a CATCH-ALL LOG+DROP — so a non-allowed TCP port *and* any non-TCP
    both fall closed. This composes with any egress tier (it is strictly more restrictive)."""
    rules: list[list[str]] = [["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]]
    if block_internal:
        rules += [["iptables", "-A", "OUTPUT", "-d", net, "-j", "DROP"] for net in _INTERNAL_NETS]

    if allowed_ports is not None:
        # WEB-ONLY: explicit allowlist, then drop EVERYTHING unmatched (other ports + all non-TCP).
        if allow_udp_dns:
            rules.append(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        if allowed_ports:
            rules.append([
                "iptables", "-A", "OUTPUT", "-p", "tcp", "-m", "multiport",
                "--dports", ",".join(_port(p) for p in allowed_ports), "-j", "ACCEPT",
            ])
        rules += [
            ["iptables", "-A", "OUTPUT", "-m", "limit", "--limit", "10/min",
             "-j", "LOG", "--log-prefix", "blastbox-leak-drop ", "--log-level", "4"],
            ["iptables", "-A", "OUTPUT", "-j", "DROP"],
        ]
        return rules

    # LEGACY TCP-only tier — byte-identical to the historical output when block_internal is unset.
    rules.append(["iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "ACCEPT"])
    if allow_udp_dns:
        rules.append(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    rules += [
        ["iptables", "-A", "OUTPUT", "!", "-p", "tcp",
         "-m", "limit", "--limit", "10/min",
         "-j", "LOG", "--log-prefix", "blastbox-leak-drop ", "--log-level", "4"],
        ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"],
    ]
    return rules


def leak_guard_rules_v6() -> list[list[str]]:
    """The IPv6 twin of :func:`leak_guard_rules`. The leak-guarded proxy tiers (socks/httpproxy/tor)
    egress over **IPv4 only** — the ``bb-socks`` bridge, the SOCKS proxy, and tor's TransPort/DNSPort
    REDIRECT are all v4 — so a leak-guarded worker has NO legitimate IPv6 egress, including DNS (tor's
    DNSPort is v4). Fail v6 fully closed: ACCEPT loopback (``::1``), LOG (rate-limited) then DROP all
    other OUTPUT, so a sample cannot escape over IPv6 even if an egress bridge were (mis)configured
    with ``--ipv6``. ``iptables`` is v4-only and cannot express this; hence a separate ``ip6tables``
    rule set. netd runs these BEST-EFFORT (a v4-only host may lack the ip6tables module) — a failure
    here must never tear down the (hard-guarantee) v4 guard."""
    return [
        ["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["ip6tables", "-A", "OUTPUT",
         "-m", "limit", "--limit", "10/min",
         "-j", "LOG", "--log-prefix", "blastbox-leak-drop6 ", "--log-level", "4"],
        ["ip6tables", "-A", "OUTPUT", "-j", "DROP"],
    ]
