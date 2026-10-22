"""``blastbox worker-link``: a WireGuard overlay that lets a dispatcher reach workers behind NAT.

A remote worker runs ``python -m blastbox.worker.http_agent`` (mTLS) and the dispatcher dials it
at ``https://<ip>:8765``. That only works when the dispatcher can open a TCP connection TO the
worker, and a worker on a home LAN, behind carrier NAT or behind a one-way corporate firewall
cannot be dialled at all. Worker-link turns the direction round at the transport layer: the
WORKER dials the host over UDP (``PersistentKeepalive`` holds the NAT mapping open), and the
dispatcher then reaches ``https://<worker-overlay-ip>:8765`` through that tunnel. The agent,
its mTLS and the static pool are unchanged; only the address the pool is given is new.

This module is the PURE half (validation, allocation, rendering); the effects live in
:mod:`blastbox.host.worker_link_apply`, the same split :mod:`blastbox.host.egress` /
:mod:`blastbox.host.egress_apply` use, so everything that decides something is testable
without root, ``wg`` or ``nft``.

SEPARATE FROM THE EGRESS OVERLAY, BY CONSTRUCTION
-------------------------------------------------
Egress (``bbwg0``, 10.77.0.0/24, udp/51821) carries untrusted SAMPLE traffic toward an exit.
Worker-link (``wtwg0``, 10.78.0.0/24, udp/51822) carries CONTROL traffic: dispatcher to agent.
They must never share an interface, a prefix, a port, a firewall table or a unit, because
their failure modes point in opposite directions -- an egress peer is allowed to send almost
anything (to the exit), a worker-link peer is allowed to send almost nothing (replies to the
dispatcher). Mixing them would let a sample reach the control plane, or let a control-plane
rule open a path for samples. So:

* own interface, own overlay, own port, own ``/etc/blastbox/worker-link.env``;
* own nftables table (``inet blastbox_worker_link``), never an iptables chain -- the egress
  tier's ``BB-WG-*`` chains, its ``ip rule`` priorities 99-101 and its routing table are not
  read, written or deleted by anything here, and ``egress teardown`` does not know this
  table exists;
* no ``ip_forward`` PostUp: the host never routes between link peers, and its firewall drops
  any attempt to.

THE TRUST DIRECTION
-------------------
The host may open NEW connections to ``tcp/<agent port>`` on a worker. A worker may open
NOTHING toward the host, toward another worker, or through the host -- it may only answer.
WireGuard's ``AllowedIPs`` already pins each worker to its own /32 (cryptokey routing: a
worker cannot source another's address), the firewall in :func:`host_firewall_nft`
enforces the direction, and TLS (``CertAuthority.sign_csr_for_ip``) makes the certificate
name exactly the /32 the tunnel delivers from. Three layers, each sufficient for a
different mistake.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from blastbox.host.egress import _SAFE_NAME, _iface, _is_wg_key

__all__ = [
    "refuse_endpoint_in_overlay",
    "DEFAULT_IFACE",
    "DEFAULT_OVERLAY",
    "DEFAULT_PORT",
    "NFT_TABLE",
    "FW_UNIT_NAME",
    "JoinBundle",
    "WorkerLinkConfig",
    "firewall_in_force",
    "reassert_units",
    "firewall_unit",
    "host_firewall_nft",
    "host_wg_config",
    "link_peer_stanza",
    "next_free_ip",
    "parse_endpoint",
]

DEFAULT_IFACE = "wtwg0"
DEFAULT_OVERLAY = "10.78.0.0/24"
DEFAULT_PORT = 51822
DEFAULT_AGENT_PORT = 8765
#: The host's own nftables table. ``inet`` so one table covers v4 and v6: the overlay is v4
#: only, and the terminal per-interface drops are what keep v6 off the link entirely.
NFT_TABLE = "blastbox_worker_link"
FW_UNIT_NAME = "blastbox-worker-link-fw.service"

#: Linux IFNAMSIZ is 16 including the NUL; wg-quick on macOS enforces the same 15.
_IFACE_MAX = 15

#: RFC 1123 hostname (labels of 1-63 alnum/hyphen, no leading/trailing hyphen). An endpoint
#: reaches a WireGuard config line and a bundle a worker parses; nothing else is accepted.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


#: The only ranges a link overlay may use. Each is also in netwire._INTERNAL_NETS (asserted by
#: the tests), which is what lets the job leak guard's `block_internal` cover the link.
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def in_rfc1918(net: "ipaddress.IPv4Network | ipaddress.IPv4Address") -> bool:
    for block in RFC1918:
        b = ipaddress.IPv4Network(block)
        if (net.subnet_of(b) if isinstance(net, ipaddress.IPv4Network) else net in b):
            return True
    return False


def _link_iface(value: str) -> str:
    v = _iface(value)
    if len(v) > _IFACE_MAX:
        raise ValueError(f"interface name {value!r} is longer than {_IFACE_MAX} characters")
    return v


def _port(value: object, what: str) -> int:
    try:
        p = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"invalid {what} {value!r}") from None
    if not 1 <= p <= 65535:
        raise ValueError(f"invalid {what} {value!r} (1-65535)")
    return p


def _v4_net(value: str, what: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise ValueError(f"invalid {what} {value!r}") from None
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError(f"{what} {value!r} must be IPv4 (the link overlay is v4-only)")
    return net


def parse_endpoint(value: str, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """``host[:port]`` -> ``(host, port)``. Host is an IPv4 literal, ``[v6]``, or an RFC 1123
    name; anything else (spaces, a scheme, a path, a second colon) is refused because the
    value lands in a WireGuard ``Endpoint =`` line on every worker that joins."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("endpoint is empty")
    if raw.startswith("["):
        host, sep, rest = raw[1:].partition("]")
        if not sep:
            raise ValueError(f"invalid endpoint {value!r}")
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError(f"invalid IPv6 endpoint {value!r}") from None
        if rest and not rest.startswith(":"):
            raise ValueError(f"invalid endpoint {value!r}")
        port = _port(rest[1:], "endpoint port") if rest else default_port
        return f"[{ip6}]", port
    host, sep, port_s = raw.rpartition(":")
    if not sep:
        host, port_s = raw, ""
    if ":" in host:
        raise ValueError(f"invalid endpoint {value!r} (bracket an IPv6 address: [addr]:port)")
    port = _port(port_s, "endpoint port") if sep else default_port
    try:
        return str(ipaddress.IPv4Address(host)), port
    except ValueError:
        pass
    if not _HOSTNAME.match(host) or host.replace(".", "").isdigit():
        raise ValueError(f"invalid endpoint host {host!r}")
    return host.lower(), port


def refuse_endpoint_in_overlay(addrs: Iterable[str], overlay: "ipaddress.IPv4Network | str",
                               *, what: str) -> None:
    """Raise if any of ``addrs`` (the endpoint, literal or as resolved) is inside the link's
    overlay. The worker routes the host's overlay /32 INTO the tunnel; an endpoint there sends
    WireGuard's own UDP into the tunnel it is meant to establish, and the link can never
    handshake. Any overlay address is refused, not only the host's: none is an underlay."""
    net = ipaddress.ip_network(overlay) if isinstance(overlay, str) else overlay
    for a in addrs:
        try:
            ip = ipaddress.ip_address(str(a).strip("[]"))
        except ValueError:
            continue                      # a hostname: checked once resolved
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped                # ::ffff:a.b.c.d is that IPv4 address
        if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
                or ip.is_reserved):            # 240.0.0.0/4 incl. 255.255.255.255; IPv6 too
            raise ValueError(f"{what} is a {'loopback' if ip.is_loopback else 'non-unicast/reserved'} "
                             "address: a worker would dial itself (or nothing), never the "
                             "host. Use the host's public/underlay address.")
        if ip.version == 4 and ip in net:
            raise ValueError(f"{what} is inside the link overlay {net}: WireGuard's packets "
                             "to it would be routed into the tunnel they establish. Use the "
                             "host's public/underlay address.")


@dataclass(frozen=True)
class WorkerLinkConfig:
    """The host side of one worker-link overlay, validated on construction.

    ``host_ip`` defaults to the first usable address of the overlay. ``endpoint`` is what
    workers dial (this host's PUBLIC address, as seen from behind their NAT); it is only
    required when issuing a join bundle, so ``status``/``teardown`` work without it.

    ``dispatcher_sources`` are the source CIDRs a CONTAINERISED dispatcher's connections
    arrive from (its docker network). A dispatcher running on the host itself needs none.
    A forwarded source is MASQUERADEd to ``host_ip`` on the way into the link -- see
    :func:`host_firewall_nft` -- because the worker only routes, and only allows, the host's
    overlay /32.
    """

    wg_iface: str = DEFAULT_IFACE
    overlay_net: str = DEFAULT_OVERLAY
    host_ip: str = ""
    wg_port: int = DEFAULT_PORT
    agent_port: int = DEFAULT_AGENT_PORT
    endpoint: str = ""
    dispatcher_sources: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "wg_iface", _link_iface(self.wg_iface))
        net = _v4_net(self.overlay_net, "overlay_net")
        # RFC 1918 only. A job's leak guard (`block_internal`, netwire._INTERNAL_NETS) drops
        # exactly these ranges, so an overlay inside them is one a sample is already denied
        # by that layer as well as by the worker firewall; a public or CGNAT prefix would be
        # covered by the firewall alone, and would put real addresses behind the tunnel.
        if not in_rfc1918(net):
            raise ValueError(f"overlay_net {net} is not inside RFC 1918 space "
                             f"({', '.join(RFC1918)})")
        if not 16 <= net.prefixlen <= 29:
            raise ValueError(f"overlay_net {net} must be between /16 and /29")
        object.__setattr__(self, "overlay_net", str(net))
        host = self.host_ip.strip() if self.host_ip else str(next(net.hosts()))
        try:
            hip = ipaddress.IPv4Address(host)
        except ValueError:
            raise ValueError(f"invalid host_ip {self.host_ip!r}") from None
        if hip not in net or hip in (net.network_address, net.broadcast_address):
            raise ValueError(f"host_ip {hip} is not a usable address inside {net}")
        object.__setattr__(self, "host_ip", str(hip))
        object.__setattr__(self, "wg_port", _port(self.wg_port, "wg_port"))
        object.__setattr__(self, "agent_port", _port(self.agent_port, "agent_port"))
        if self.endpoint:
            h, p = parse_endpoint(self.endpoint, self.wg_port)
            refuse_endpoint_in_overlay([h], net, what=f"endpoint {h}")
            object.__setattr__(self, "endpoint", f"{h}:{p}")
        srcs: list[str] = []
        for s in self.dispatcher_sources:
            if not str(s).strip():
                continue
            src = _v4_net(s, "dispatcher source")
            if src.prefixlen == 0:
                raise ValueError(
                    "a dispatcher source of 0.0.0.0/0 would let ANY forwarded packet -- a job "
                    "container on this host included -- open connections to every worker")
            if src.overlaps(net):
                raise ValueError(f"dispatcher source {src} overlaps the link overlay {net}")
            if str(src) not in srcs:
                srcs.append(str(src))
        object.__setattr__(self, "dispatcher_sources", tuple(srcs))

    @property
    def prefixlen(self) -> int:
        return ipaddress.IPv4Network(self.overlay_net).prefixlen

    def member(self, ip: str) -> str:
        """Validate ``ip`` is a usable WORKER address in this overlay, or raise."""
        try:
            addr = ipaddress.IPv4Address(str(ip).strip())
        except ValueError:
            raise ValueError(f"invalid worker address {ip!r}") from None
        net = ipaddress.IPv4Network(self.overlay_net)
        if addr not in net or addr in (net.network_address, net.broadcast_address):
            raise ValueError(f"worker address {addr} is not a usable address inside {net}")
        if str(addr) == self.host_ip:
            raise ValueError(f"worker address {addr} is the host's own overlay address")
        return str(addr)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "WorkerLinkConfig":
        """Build from ``BLASTBOX_WORKER_LINK_*`` (names spelled out in full so a grep -- and
        the docs check -- finds every one)."""
        def pick(key: str, default: str) -> str:
            v = env.get(key)
            return default if v is None or not str(v).strip() else str(v).strip()

        return cls(
            wg_iface=pick("BLASTBOX_WORKER_LINK_IF", DEFAULT_IFACE),
            overlay_net=pick("BLASTBOX_WORKER_LINK_OVERLAY_NET", DEFAULT_OVERLAY),
            host_ip=pick("BLASTBOX_WORKER_LINK_HOST_IP", ""),
            wg_port=_port(pick("BLASTBOX_WORKER_LINK_WG_PORT", str(DEFAULT_PORT)),
                          "BLASTBOX_WORKER_LINK_WG_PORT"),
            agent_port=_port(pick("BLASTBOX_WORKER_LINK_AGENT_PORT", str(DEFAULT_AGENT_PORT)),
                             "BLASTBOX_WORKER_LINK_AGENT_PORT"),
            endpoint=pick("BLASTBOX_WORKER_LINK_ENDPOINT", ""),
            dispatcher_sources=tuple(
                s for s in pick("BLASTBOX_WORKER_LINK_DISPATCHER_SOURCES", "").split(",")
                if s.strip()),
        )

    def to_env_lines(self) -> list[str]:
        """``KEY=value`` lines for /etc/blastbox/worker-link.env. No key material, ever."""
        return [
            f"BLASTBOX_WORKER_LINK_IF={self.wg_iface}",
            f"BLASTBOX_WORKER_LINK_OVERLAY_NET={self.overlay_net}",
            f"BLASTBOX_WORKER_LINK_HOST_IP={self.host_ip}",
            f"BLASTBOX_WORKER_LINK_WG_PORT={self.wg_port}",
            f"BLASTBOX_WORKER_LINK_AGENT_PORT={self.agent_port}",
            f"BLASTBOX_WORKER_LINK_ENDPOINT={self.endpoint}",
            "BLASTBOX_WORKER_LINK_DISPATCHER_SOURCES=" + ",".join(self.dispatcher_sources),
        ]


# --------------------------------------------------------------------------------------
# Allocation
# --------------------------------------------------------------------------------------

def next_free_ip(cfg: WorkerLinkConfig, taken: Iterable[str]) -> str:
    """The lowest usable overlay address not held by the host or any registered worker.

    ``taken`` is the ``AllowedIPs`` of the peers already in the config (``a.b.c.d/32`` or
    bare); unparseable entries are ignored rather than trusted, and anything outside the
    overlay cannot collide anyway. Lowest-first keeps allocation deterministic, which is
    what lets the operator read the address off ``worker-link list`` BEFORE the worker's
    CSR is generated and have ``add`` arrive at the same one.
    """
    net = ipaddress.IPv4Network(cfg.overlay_net)
    used = {ipaddress.IPv4Address(cfg.host_ip)}
    for t in taken:
        try:
            used.add(ipaddress.IPv4Address(str(t).strip().split("/")[0]))
        except ValueError:
            continue
    for addr in net.hosts():
        if addr not in used:
            return str(addr)
    raise RuntimeError(f"the worker-link overlay {net} is full ({net.num_addresses - 3} workers)")


# --------------------------------------------------------------------------------------
# WireGuard configs
# --------------------------------------------------------------------------------------

def host_wg_config(cfg: WorkerLinkConfig, private_key: str) -> str:
    """``wg-quick`` [Interface] for the HOST end of the link.

    NO ``PostUp = sysctl -w net.ipv4.ip_forward=1``, deliberately, and unlike the egress
    exit host: nothing ever needs to be routed THROUGH this end. The dispatcher talks to
    workers from this host (or from a container on it, which is forwarded out, not in).
    ``Address`` carries the overlay prefix so wg-quick installs the one route the host
    needs -- the overlay, on this interface -- and nothing else.
    """
    return (
        "# blastbox worker-link — HOST end. Workers are added by `blastbox worker-link add`.\n"
        "# Separate from the egress overlay by design; see blastbox.host.worker_link.\n"
        "[Interface]\n"
        f"Address = {cfg.host_ip}/{cfg.prefixlen}\n"
        f"ListenPort = {cfg.wg_port}\n"
        f"PrivateKey = {private_key}\n"
    )


def link_peer_stanza(name: str, worker_ip: str, public_key: str, *,
                     cfg: WorkerLinkConfig, expires: str | None = None) -> str:
    """One ``[Peer]`` block for a worker, in the same ``# peer:<name>`` format the egress
    helpers (``_peer_blocks``, ``drop_peer_blocks``, ``_refuse_peer_collision``) parse.

    ``AllowedIPs`` is the worker's /32 and nothing else: WireGuard then refuses any packet
    from this peer sourced from another address, so one worker cannot speak as another, and
    the host only ever sends this peer traffic addressed to it. No ``Endpoint``: the worker
    dials in and WireGuard learns (and roams) its NATed address from the handshake. No
    keepalive on this side either -- the worker holds the mapping open.

    ``# expires:`` records the TLS certificate's expiry for ``list``/``status``. It is
    informational here, never a prune trigger: a lapsed cert already fails the dispatcher's
    TLS check closed, and silently deleting the tunnel too would only hide which worker
    needs renewing.
    """
    if not _SAFE_NAME.match(name):
        raise ValueError(f"unsafe worker name {name!r}")
    key = public_key.strip()
    if not _is_wg_key(key):
        raise ValueError("public key is not a 32-byte base64 WireGuard key")
    ip = cfg.member(worker_ip)
    exp = f"# expires:{expires}\n" if expires else ""
    return (
        f"\n# peer:{name}\n"
        f"{exp}"
        "[Peer]\n"
        f"PublicKey = {key}\n"
        f"AllowedIPs = {ip}/32\n"
    )


# --------------------------------------------------------------------------------------
# Firewall (nftables)
# --------------------------------------------------------------------------------------

def _nft_preamble(table: str) -> list[str]:
    """Atomic replace: declare-then-delete-then-define in one ``nft -f`` transaction.

    ``delete table`` alone fails when the table is absent, and ``flush table`` keeps chains
    whose definitions changed. Declaring an empty table first makes the delete always
    succeed, and because ``nft -f`` applies the whole file as ONE transaction there is no
    instant at which the old rules are gone and the new ones not yet loaded.
    """
    return [f"table inet {table} {{}}", f"delete table inet {table}"]


def host_firewall_nft(cfg: WorkerLinkConfig) -> str:
    """The HOST end's nftables ruleset: NEW connections only host -> worker tcp/agent_port.

    On the link interface:

    * ``output``: the host may open ``tcp/<agent_port>`` to an overlay address, and continue
      connections it opened; everything else out the link is dropped (no host-initiated
      ssh/anything to workers, no v6).
    * ``input``: only replies to the host's own connections; any NEW connection a worker
      starts toward the host is dropped. And the overlay is reachable ONLY from the link:
      Linux accepts a packet for a local address on any interface (weak host model), so a
      job container on this host, or a packet arriving over the EGRESS overlay, could
      otherwise reach ``host_ip`` -- that is dropped too.
    * ``forward``: nothing from a link peer is ever routed (worker -> worker, worker ->
      anything beyond this host). Into the link, only a dispatcher in a container on one of
      ``dispatcher_sources`` may open ``tcp/<agent_port>``; the replies come back as
      ESTABLISHED. With no sources configured nothing is forwarded into the link at all.
    * ``postrouting`` (only with sources): MASQUERADE those connections to ``host_ip``. The
      worker routes and allows only the host's /32, so an unmasqueraded docker source would
      handshake, send, and never see a reply. Docker's own MASQUERADE for a non-internal
      bridge usually does this already; this makes it independent of docker's config.

    COEXISTENCE WITH DOCKER (and the egress tier). Every base chain here has policy
    ACCEPT and matches only the link interface, so it changes the verdict for nothing else.
    nftables requires a packet to be accepted by EVERY base chain on a hook, so an accept
    here can never override docker's FORWARD DROP policy -- and docker already accepts
    ``-i <bridge> ! -o <bridge>`` (container egress, which is what the dispatcher's
    connection is) and ESTABLISHED replies back to the bridge. A drop here is final, which
    is the property that matters.
    """
    t = NFT_TABLE
    i = cfg.wg_iface
    net, host, port = cfg.overlay_net, cfg.host_ip, cfg.agent_port
    # ESTABLISHED IS PINNED TO THE PERMITTED FLOW. conntrack outlives the ruleset: a flow a
    # worker opened while the table was flushed (the gap the re-assert timer closes) would stay
    # "established" after the reload and pass an unrestricted `ct state established` accept for
    # days. So established/related traffic is accepted only in the direction, and with the
    # original tuple, of a connection this ruleset would have admitted NEW: host (or a
    # dispatcher source) -> an overlay address : agent_port.
    flow = f"ct original ip daddr {net} ct original proto-dst {port}"
    lines = [
        f"# blastbox worker-link — HOST firewall for {i} ({net}). Generated by",
        "# `blastbox worker-link init` from blastbox.host.worker_link.host_firewall_nft.",
        "# A worker may only ANSWER. See that function's docstring before editing.",
        *_nft_preamble(t),
        f"table inet {t} {{",
        "\tchain input {",
        "\t\ttype filter hook input priority filter; policy accept;",
        f'\t\tiifname "{i}" ct direction reply ct original ip saddr {host} {flow} '
        "ct state established,related accept",
        f'\t\tiifname "{i}" drop',
        f'\t\tiifname != {{ "lo", "{i}" }} ip daddr {net} drop',
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority filter; policy accept;",
    ]
    if cfg.dispatcher_sources:
        srcs = ", ".join(cfg.dispatcher_sources)
        lines.append(f'\t\tiifname "{i}" ct direction reply ct original ip saddr {{ {srcs} }} '
                     f"{flow} ct state established,related accept")
    lines += [
        f'\t\tiifname "{i}" drop',
        # A container publishing a port on an OVERLAY address (the dispatcher's, on host_ip) is
        # reached by DNAT -- forwarded, so the input chain's off-link drop never sees it. Nothing
        # that neither arrives on nor leaves by the link may reach an overlay destination
        # (original tuple, original direction: replies, and the dispatcher's own path out over
        # the link, are untouched).
        f'\t\tiifname != "{i}" oifname != "{i}" ct direction original '
        f"ct original ip daddr {net} drop",
    ]
    if cfg.dispatcher_sources:
        srcs = ", ".join(cfg.dispatcher_sources)
        lines.append(f'\t\toifname "{i}" ip saddr {{ {srcs} }} ip daddr {net} '
                     f"tcp dport {port} ct state new accept")
        lines.append(f'\t\toifname "{i}" ct direction original ct original ip saddr '
                     f"{{ {srcs} }} {flow} ct state established accept")
    lines += [
        f'\t\toifname "{i}" drop',
        "\t}",
        "\tchain output {",
        "\t\ttype filter hook output priority filter; policy accept;",
        f'\t\toifname "{i}" ip saddr {host} ip daddr {net} tcp dport {port} ct state new accept',
        f'\t\toifname "{i}" ct direction original ct original ip saddr {host} {flow} '
        "ct state established accept",
        f'\t\toifname "{i}" drop',
        "\t}",
    ]
    if cfg.dispatcher_sources:
        srcs = ", ".join(cfg.dispatcher_sources)
        lines += [
            "\tchain postrouting {",
            "\t\ttype nat hook postrouting priority srcnat; policy accept;",
            f'\t\toifname "{i}" ip saddr {{ {srcs} }} masquerade',
            "\t}",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def firewall_unit(*, nft_bin: str, nft_file: str, table: str, iface: str,
                  description: str) -> str:
    """systemd oneshot that (re)loads a worker-link ruleset at boot, BEFORE the link is up.

    nftables state does not survive a reboot. Ordered ``Before=wg-quick@<iface>`` so the
    interface never comes up unfirewalled; the rules match ``iifname``/``oifname`` STRINGS,
    which load fine before the interface exists. ``ExecStop`` deletes only our table.

    ``RequiredBy=wg-quick@<iface>`` and not merely ``WantedBy``: with ``Wants`` a ruleset that
    fails to load (a corrupted file, nft missing after an upgrade) still lets the interface
    start, i.e. the link comes up OPEN at boot. ``Requires`` + ``Before`` means a failed load
    keeps the link down -- and so does a MISSING file, via ``AssertPathExists`` (a
    ``ConditionPathExists`` would skip the unit, which its dependents treat as success).
    """
    return f"""# {description}
# Generated by blastbox.worker_link from blastbox.host.worker_link.firewall_unit.
# Loads {nft_file} (table inet {table}) before wg-quick@{iface} so the link is never
# up without its firewall. Touches no other table.

[Unit]
Description={description}
Before=wg-quick@{iface}.service
# A restart of nftables.service (whose stock config flushes EVERY table) restarts this unit
# after it, so the table is put back rather than silently lost.
After=nftables.service
PartOf=nftables.service
# ASSERT, not Condition: a failed condition counts as success to a unit that Requires this
# one, so a missing ruleset file would let the link start open. An assertion fails it.
AssertPathExists={nft_file}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft_bin} -f {nft_file}
ExecStop=-{nft_bin} delete table inet {table}

[Install]
WantedBy=multi-user.target
RequiredBy=wg-quick@{iface}.service
"""


_COUNTER = re.compile(r"\bcounter packets \d+ bytes \d+ ")


def _chains(text: str) -> dict[str, list[str]]:
    """``chain name -> [normalised rule lines]`` for an nft table listing (or our rendering).
    Whitespace is collapsed and ``counter packets N bytes N`` dropped, so a counter on a rule
    does not make it a different rule."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for raw in (text or "").splitlines():
        line = _COUNTER.sub("", " ".join(raw.split()) + " ").strip()
        m = re.match(r"^chain (\S+) \{$", line)
        if m:
            current = m.group(1)
            blocks[current] = []
            continue
        if line == "}":
            current = None
            continue
        if current is not None and line and not line.startswith("#"):
            blocks[current].append(line)
    return blocks


_SET = re.compile(r"\{([^{}]*)\}")


def _canon_atom(tok: str) -> str:
    """One match operand in canonical form: an IPv4 address or prefix as nft prints it
    (``10.0.0.0/24``, a /32 as the bare address), a comma list of keywords sorted
    (``established,related``), anything else unchanged."""
    if "/" in tok or tok.count(".") == 3:
        try:
            net = ipaddress.IPv4Network(tok, strict=False)
        except ValueError:
            pass
        else:
            return str(net.network_address) if net.prefixlen == 32 else str(net)
    if "," in tok and '"' not in tok:
        return ",".join(sorted(tok.split(",")))
    return tok


def _canon_set(body: str) -> str:
    """An anonymous set's elements in canonical form. nft re-renders sets: it may reorder
    their elements, merge adjacent/overlapping prefixes, and print a one-element set as the
    bare element (``ip saddr { 172.31.0.0/16 }`` lists as ``ip saddr 172.31.0.0/16``). So
    address elements are collapsed, every element sorted, and a single element unbraced --
    the SAME set compares equal however it was spelled, a different one never does."""
    elems = [e.strip() for e in body.split(",") if e.strip()]
    nets: list[ipaddress.IPv4Network] = []
    other: list[str] = []
    for e in elems:
        try:
            nets.append(ipaddress.IPv4Network(e, strict=False))
        except ValueError:
            other.append(e)
    canon = sorted(other) + [_canon_atom(str(n)) for n in ipaddress.collapse_addresses(nets)]
    return canon[0] if len(canon) == 1 else "{ " + ", ".join(canon) + " }"


def _canon_rule(line: str) -> str:
    """A rule line in canonical form, for comparing what we rendered with what the kernel
    lists. Only RENDERING is normalised (set spelling, prefix spelling, keyword-list order,
    whitespace, counters -- see :func:`_chains`); every match, operand and verdict is kept,
    so a rule that matches more (or less) than ours never compares equal to it."""
    out: list[str] = []
    pos = 0
    for m in _SET.finditer(line):
        out += [_canon_atom(t) for t in line[pos:m.start()].split()]
        out.append(_canon_set(m.group(1)))
        pos = m.end()
    out += [_canon_atom(t) for t in line[pos:].split()]
    return " ".join(out)


def _chain_decl(line: str) -> tuple[str, ...]:
    """A base-chain declaration (``type filter hook input priority filter; policy accept;``)
    as its normalised clauses, e.g. ``("type filter hook input priority filter",
    "policy accept")`` -- every clause compared, whitespace and the trailing ``;`` aside."""
    return tuple(" ".join(part.split()) for part in line.split(";") if part.strip())


def firewall_in_force(listing: str, expected: str) -> list[str]:
    """What is MISSING from a live ``nft list table`` listing, or [] if ``expected`` (the
    ruleset we rendered) is in force.

    PRESENT IS NOT IN FORCE: the ruleset file on disk, or an enabled unit, proves nothing
    about the kernel, so this reads the kernel's own listing. For every chain we rendered it
    requires the chain, its hook, and EXACTLY our rules in our order -- accepts included, so
    a port-scoped accept rewritten as a broader one (``oifname "wtwg0" accept``) is caught
    even though the rule count and every drop are unchanged, and an accept inserted ahead
    of a drop cannot pass as ours. Each rule is compared in canonical form
    (:func:`_canon_rule`): nft re-renders sets and prefixes in its own spelling, and a
    cosmetic difference there must not read as "the firewall is down".
    """
    missing: list[str] = []
    have = _chains(listing)
    for chain, want in _chains(expected).items():
        got = have.get(chain)
        if got is None:
            missing.append(f"chain {chain}")
            continue
        # The WHOLE base-chain declaration -- type, hook, priority AND policy. Comparing only
        # the part before the first `;` let a chain flipped to `policy drop` (a reload, a hand
        # edit) read as in force while it dropped unrelated traffic on every other interface.
        hook = next((ln for ln in want if ln.startswith("type ")), None)
        if hook:
            got_decl = [_chain_decl(ln) for ln in got if ln.startswith("type ")]
            if _chain_decl(hook) not in got_decl:
                shown = "; ".join(_chain_decl(hook))
                found = " / ".join("; ".join(d) for d in got_decl) or "none"
                missing.append(f"chain {chain} is not declared as `{shown}` (found: {found})")
        rules_want = [_canon_rule(ln) for ln in want if not ln.startswith("type ")]
        rules_got = [_canon_rule(ln) for ln in got if not ln.startswith("type ")]
        if rules_got == rules_want:
            continue
        for ln in rules_want:
            if ln not in rules_got:
                missing.append(f"chain {chain}: `{ln}`")
        for ln in rules_got:
            if ln not in rules_want:
                missing.append(f"chain {chain}: unexpected rule `{ln}`")
        if sorted(rules_got) == sorted(rules_want):
            missing.append(f"chain {chain}: our rules are present but in a different order")
        elif len(rules_got) != len(rules_want):
            missing.append(f"chain {chain} holds {len(rules_got)} rules, not the "
                           f"{len(rules_want)} rendered (something was added or removed)")
    return missing


def reassert_units(*, nft_bin: str, nft_file: str, iface: str, base: str,
                   description: str, interval: str = "1min") -> tuple[str, str]:
    """``(service, timer)`` that re-load the ruleset every ``interval`` while the link exists.

    A loaded ruleset can disappear with the interface still up: ``systemctl restart
    nftables`` (Debian's /etc/nftables.conf begins with ``flush ruleset``), a firewalld or
    ufw reload, or a hand-run ``nft flush ruleset``. The boot unit is ``RemainAfterExit`` and
    never runs again, so nothing would put it back. ``nft -f`` replaces our table atomically
    (no window), and if it FAILS the link is stopped: an unfirewalled link is worse than none.
    """
    import shlex

    # NO ConditionPathExists / AssertPathExists on the ruleset file. A failed CONDITION skips
    # the unit without running ExecStart, and a failed ASSERTION fails it -- either way the
    # `|| systemctl stop` below never runs, so a DELETED ruleset file would leave a live link
    # unfirewalled after the next flush. A missing file must reach the command and fail it:
    # `nft -f <missing>` exits non-zero, which stops the link. (While the link is down the
    # stop is a no-op, so a timer that outlives a teardown is harmless.) The unit still exits
    # non-zero after stopping the link so the failure is visible in `systemctl --failed`.
    #
    # Stopping the UNIT is not enough: `wg_up` (host) and `join` (Linux worker) fall back to a
    # direct `wg-quick up` when systemd will not start it, leaving the interface live with the
    # unit INACTIVE -- `systemctl stop` is then a no-op and the link stays up unfirewalled. So
    # the failure path also runs `wg-quick down`, and as a last resort deletes the interface;
    # each step is a harmless no-op when the one before it already took the link down.
    i = _link_iface(iface)
    cmd = (f"{shlex.quote(nft_bin)} -f {shlex.quote(nft_file)} || "
           f"{{ systemctl stop wg-quick@{i}.service; wg-quick down {i} >/dev/null 2>&1; "
           f"ip link delete dev {i} >/dev/null 2>&1; exit 1; }}")
    service = f"""# {description} -- periodic re-assert. Generated from
# blastbox.host.worker_link.reassert_units; triggered by {base}-reassert.timer.
# Deliberately unconditional: a missing ruleset file must STOP the link, not skip this.

[Unit]
Description={description} (re-assert)
After={base}.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c {shlex.quote(cmd)}
"""
    timer = f"""# {description} -- re-load the ruleset every {interval} while the link is up.

[Unit]
Description={description} (re-assert timer)

[Timer]
OnBootSec={interval}
OnUnitActiveSec={interval}
AccuracySec=10s
Unit={base}-reassert.service

[Install]
WantedBy=timers.target
"""
    return service, timer


# --------------------------------------------------------------------------------------
# Join bundle (host -> worker; public material only)
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class JoinBundle:
    """Everything a worker needs to join, and nothing it must not have.

    Carries PUBLIC material only: the host's WireGuard public key, the CA certificate and the
    worker's own signed certificate. The worker's private keys never left the worker, so the
    bundle can travel over any channel -- what it must not be is ALTERED in transit (a
    swapped host key or CA would point the worker at someone else), which is why it is meant
    to be carried by the operator who ran ``add``, like the CSR was.
    """

    name: str
    iface: str
    worker_ip: str
    host_ip: str
    overlay_net: str
    endpoint: str
    host_public_key: str
    agent_port: int
    ca_pem: str
    cert_pem: str
    #: The WireGuard key the host REGISTERED as this worker's peer. join compares it with the
    #: worker's own: a mixed-up key at `add` is caught before anything is installed.
    worker_public_key: str
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError(f"unsupported join bundle version {self.version!r}")
        if not _SAFE_NAME.match(self.name):
            raise ValueError(f"unsafe worker name {self.name!r}")
        object.__setattr__(self, "iface", _link_iface(self.iface))
        cfg = WorkerLinkConfig(wg_iface=self.iface, overlay_net=self.overlay_net,
                               host_ip=self.host_ip, agent_port=self.agent_port,
                               endpoint=self.endpoint)
        object.__setattr__(self, "worker_ip", cfg.member(self.worker_ip))
        object.__setattr__(self, "endpoint", cfg.endpoint)
        if not _is_wg_key(self.host_public_key.strip()):
            raise ValueError("host_public_key is not a 32-byte base64 WireGuard key")
        object.__setattr__(self, "host_public_key", self.host_public_key.strip())
        if not isinstance(self.worker_public_key, str) or not _is_wg_key(
                self.worker_public_key.strip()):
            raise ValueError("worker_public_key is not a 32-byte base64 WireGuard key")
        object.__setattr__(self, "worker_public_key", self.worker_public_key.strip())
        if self.worker_public_key == self.host_public_key:
            raise ValueError("the bundle's worker and host keys are the same key")
        for what in ("ca_pem", "cert_pem"):
            pem = getattr(self, what)
            if not (isinstance(pem, str) and pem.count("-----BEGIN CERTIFICATE-----") == 1
                    and pem.strip().endswith("-----END CERTIFICATE-----")):
                raise ValueError(f"{what} is not exactly one PEM certificate")

    def to_json(self) -> str:
        return json.dumps({
            "blastbox_worker_link": self.version, "name": self.name, "iface": self.iface,
            "worker_ip": self.worker_ip, "host_ip": self.host_ip,
            "overlay_net": self.overlay_net, "endpoint": self.endpoint,
            "host_public_key": self.host_public_key, "agent_port": self.agent_port,
            "ca_pem": self.ca_pem, "cert_pem": self.cert_pem,
            "worker_public_key": self.worker_public_key,
        }, indent=1) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "JoinBundle":
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"join bundle is not JSON: {exc}") from None
        if not isinstance(obj, dict) or "blastbox_worker_link" not in obj:
            raise ValueError("not a blastbox worker-link join bundle")
        keys = ("name", "iface", "worker_ip", "host_ip", "overlay_net", "endpoint",
                "host_public_key", "agent_port", "ca_pem", "cert_pem", "worker_public_key")
        missing = [k for k in keys if k not in obj]
        if missing:
            raise ValueError(f"join bundle is missing {', '.join(missing)}")
        try:
            return cls(**{k: obj[k] for k in keys}, version=int(obj["blastbox_worker_link"]))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid join bundle: {exc}") from None
