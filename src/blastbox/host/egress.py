"""Node-level egress setup: bridges, exit mode, and the WireGuard overlay transport.

This is the *node* half of the netpolicy layer. :mod:`blastbox.host.netwire` wires an
individual worker's namespace once netd sees it; this module prepares the node so that
wiring has somewhere to go — the ``bb-*`` bridges, and whatever sits at the gateway
address the personalities point at.

TWO EXIT MODES, ONE TOPOLOGY
----------------------------
``local``
    This node runs its own exit sidecars and holds the provider credentials. The gateway
    address *is* the OpenVPN client / tor transproxy / SOCKS sidecar.
``global``
    This node holds no credentials at all. The gateway address is a credential-free
    forwarder (``deploy/egress-forwarder``) that carries worker traffic over a WireGuard
    overlay to the one host that does run the exits.

**The gateway address is identical in both modes** — a node's mode is only ever *which
container sits at that address*. Personalities, netd flags, worker labels and the
in-netns routes are byte-identical, which is why neither mode needs a change to
:func:`blastbox.host.netwire.gateway_route_commands`: it takes a plain IP and always did.

WHY WIREGUARD RATHER THAN A SWARM/VXLAN OVERLAY
-----------------------------------------------
A dead tunnel is a dead *route*. No route, no egress — fail-closed stays a property of
the kernel routing table rather than of a distributed control plane's health. VXLAN
forwards happily over a degraded fabric and swarm ties the boundary to swarm state; both
fail OPEN exactly when you need otherwise.

FOUR WAYS THIS FAILS OPEN, ALL MEASURED
---------------------------------------
Each of these presented as "it works" or as a plain outage, never as a visible leak. They
are the reason this module exists as code with tests instead of as a runbook:

1. **An ``ip rule`` that matches but finds an empty table falls through to ``main``** — so
   a dead tunnel silently becomes direct WAN egress. Every lookup rule here is followed by
   a blackhole rule at the next priority. See :func:`forwarder_source_route_steps`.
2. **``AllowedIPs`` is cryptokey routing, not a route.** Set to the overlay prefix alone it
   discards every internet-bound packet *inside* the tunnel, with no error anywhere. The
   peer config uses ``0.0.0.0/0`` plus ``Table = off``. See :func:`peer_wg_config`.
3. **Both hosts run ``FORWARD`` policy DROP.** Chains matching on source cover only the
   outbound leg; the return leg needs its own conntrack chain or the path works and the
   client still times out. See :func:`return_chain_steps`.
4. **A restart policy can mask a failed startup gate** — a crash-looping forwarder looks
   healthy in ``docker ps`` forever. Health is asserted from the gate's log line and a
   zero restart count, never from "running". See :func:`forwarder_health`.

Every rule lives in a dedicated ``BB-WG-*`` chain reached by a single jump and is removed
by match, never by index — these nodes run a co-resident CAPE rooter whose rules must not
be renumbered out from under it. This is the same discipline ``libvirt_egress`` uses.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field, replace
from typing import Iterable, Mapping, Sequence


__all__ = [
    "EgressConfig",
    "Step",
    "EgressMode",
    "SubnetPlan",
    "allocate_subnets",
    "exit_host_steps",
    "forwarder_health",
    "forwarder_run_argv",
    "forwarder_source_route_steps",
    "gateway_wg_config",
    "persistence_unit",
    "peer_wg_config",
    "return_chain_steps",
    "teardown_steps",
]

EgressMode = str  # "local" | "global"
_MODES = ("local", "global")

# Chain names. Prefixed so `iptables -S | grep BB-` distinguishes ours from the rooter's,
# which is how install/--check asserts we left a co-resident CAPE rooter alone.
CHAIN_FWD = "BB-WG-FWD"
CHAIN_FWD_RET = "BB-WG-FWD-RET"
CHAIN_EXIT = "BB-WG-EXIT"
CHAIN_EXIT_RET = "BB-WG-EXIT-RET"
ALL_CHAINS = (CHAIN_FWD, CHAIN_EXIT, CHAIN_FWD_RET, CHAIN_EXIT_RET)

# ip rule priorities. The ORDER is load-bearing, not cosmetic:
#   99  overlay-internal traffic -> main   (or this host's own replies to a peer get posted
#                                           to the exit sidecar and the tunnel carries nothing)
#   100 our source              -> tunnel table
#   101 our source              -> blackhole  (the fall-through guard; see module docstring)
PRIO_OVERLAY_MAIN = 99
PRIO_LOOKUP = 100
PRIO_BLACKHOLE = 101
ALL_PRIORITIES = (PRIO_OVERLAY_MAIN, PRIO_LOOKUP, PRIO_BLACKHOLE)

@dataclass(frozen=True)
class Step:
    """One command, plus how to make running it twice safe.

    ``netwire`` emits plain argv lists because netd applies them once to a fresh worker
    netns. Node setup is different: it is re-run on every boot by the persistence unit and
    by any operator re-applying config, so every step has to be idempotent on its own.

    Every ``iptables`` invocation carries ``-w``: dockerd and the co-resident CAPE rooter
    mutate iptables constantly, and an unwaited call does not queue — it fails outright
    with "another app is currently holding the xtables lock". A guard failing that way is
    indistinguishable from "rule absent", and a delete/insert pair losing the lock
    halfway leaves the chain orphaned.

    ``guard``  — if this command SUCCEEDS, ``argv`` is skipped. ``iptables -C`` is the
                 canonical case: check-then-add, so a re-apply does not stack duplicate
                 jump rules in a chain the CAPE rooter also lives in.
    ``ignore_fail`` — a non-zero exit is expected and fine (``-N`` on a chain that exists,
                 ``rule del`` for a rule that was never added, teardown of a partial state).
    """

    argv: tuple[str, ...]
    guard: tuple[str, ...] | None = None
    ignore_fail: bool = False
    desc: str = ""

    @staticmethod
    def of(argv: Sequence[str], **kw: object) -> "Step":
        return Step(argv=tuple(argv), **kw)  # type: ignore[arg-type]

    @staticmethod
    def ensure(guard: Sequence[str], argv: Sequence[str], desc: str = "") -> "Step":
        """Run ``argv`` only if ``guard`` fails. The check-then-add idiom."""
        return Step(argv=tuple(argv), guard=tuple(guard), desc=desc)

    @staticmethod
    def best_effort(argv: Sequence[str], desc: str = "") -> "Step":
        return Step(argv=tuple(argv), ignore_fail=True, desc=desc)


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$")


def _ip(value: str) -> str:
    """Validate and normalise a bare IP. Raises ValueError on anything else."""
    return str(ipaddress.ip_address(str(value).strip()))


def _net(value: str) -> str:
    """Validate and normalise a CIDR. ``strict=False`` so 10.77.0.3/24 is accepted and
    normalised to its network, which is what an operator usually means."""
    return str(ipaddress.ip_network(str(value).strip(), strict=False))


def _iface(value: str) -> str:
    """Interface names reach argv and a wg-quick config filename, so constrain them."""
    v = str(value).strip()
    if not _SAFE_NAME.match(v):
        raise ValueError(f"unsafe interface name {value!r}")
    return v


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class EgressConfig:
    """Everything a node needs to stand up its egress tier, in one validated object.

    Defaults match what a greenfield host gets. On a busy CAPE host they will collide with
    the existing docker pools — :func:`allocate_subnets` exists precisely because
    172.16/12 is mostly spoken for there.
    """

    mode: EgressMode = "local"
    # Bridges. bb-net0 is the only non-internal one; the rest have no route off the box
    # until netd wires a worker, which IS the fail-closed property.
    net0_subnet: str = "172.29.0.0/16"
    fakenet_subnet: str = "172.28.100.0/24"
    socks_subnet: str = "172.30.0.0/16"
    vpn_subnet: str = "172.31.0.0/16"
    # The gateway address personalities point at. Identical in both modes by design.
    vpn_gateway_ip: str = "172.31.0.10"
    # global mode only: the forwarder's STATIC uplink address on bb-net0, and the overlay
    # address of the exit host it forwards to.
    forwarder_uplink_ip: str = "172.29.0.10"
    upstream_gw: str = ""
    # Overlay transport.
    wg_iface: str = "bbwg0"
    wg_port: int = 51821
    overlay_net: str = "10.77.0.0/24"
    overlay_gateway_ip: str = "10.77.0.1"
    rt_table: str = "bbwg"
    rt_table_id: int = 220
    forwarder_image: str = "blastbox-egress-forwarder:dev"
    forwarder_name: str = "bb-egress-forwarder"

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, got {self.mode!r}")
        for f in ("net0_subnet", "fakenet_subnet", "socks_subnet", "vpn_subnet", "overlay_net"):
            object.__setattr__(self, f, _net(getattr(self, f)))
        for f in ("vpn_gateway_ip", "forwarder_uplink_ip", "overlay_gateway_ip"):
            object.__setattr__(self, f, _ip(getattr(self, f)))
        object.__setattr__(self, "wg_iface", _iface(self.wg_iface))
        if self.upstream_gw:
            object.__setattr__(self, "upstream_gw", _ip(self.upstream_gw))
        if not 1 <= int(self.wg_port) <= 65535:
            raise ValueError(f"invalid wg_port {self.wg_port!r}")
        if not _SAFE_NAME.match(self.rt_table):
            raise ValueError(f"unsafe rt_table {self.rt_table!r}")
        # A global-mode node with no upstream would start a forwarder pointing nowhere.
        # Catch it here rather than at the forwarder's startup gate, where it costs a
        # container start and reads like a crash.
        if self.mode == "global" and not self.upstream_gw:
            raise ValueError("mode=global requires upstream_gw (the exit host's overlay IP)")
        # The gateway must live on the bridge the workers are placed on, or the worker's
        # `ip route replace default via <gw>` has no link route to resolve it against and
        # netd's wiring fails with "Nexthop has invalid gateway".
        if ipaddress.ip_address(self.vpn_gateway_ip) not in ipaddress.ip_network(self.vpn_subnet):
            raise ValueError(
                f"vpn_gateway_ip {self.vpn_gateway_ip} is not inside vpn_subnet {self.vpn_subnet};"
                " a worker could not resolve it as a next hop"
            )
        if self.mode == "global" and (
            ipaddress.ip_address(self.forwarder_uplink_ip)
            not in ipaddress.ip_network(self.net0_subnet)
        ):
            raise ValueError(
                f"forwarder_uplink_ip {self.forwarder_uplink_ip} is not inside net0_subnet "
                f"{self.net0_subnet}; the node-side source route would key on an address the "
                "forwarder never holds"
            )

    @property
    def bridges(self) -> tuple[tuple[str, str, bool], ...]:
        """``(name, subnet, internal)`` for every bridge this node needs."""
        return (
            ("bb-net0", self.net0_subnet, False),
            ("bb-fakenet", self.fakenet_subnet, True),
            ("bb-socks", self.socks_subnet, True),
            ("bb-vpn", self.vpn_subnet, True),
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "EgressConfig":
        """Build from ``BLASTBOX_EGRESS_*`` (falling back to the legacy bare names the
        shell installer used, so an existing node's env keeps working)."""
        e = os.environ if env is None else env

        def pick(new: str, legacy: str, default: str) -> str:
            return str(e.get(f"BLASTBOX_EGRESS_{new}", e.get(legacy, default)))

        return cls(
            mode=pick("MODE", "EGRESS_MODE", "local"),
            net0_subnet=pick("NET0_SUBNET", "NET0_SUBNET", cls.net0_subnet),
            fakenet_subnet=pick("FAKENET_SUBNET", "FAKENET_SUBNET", cls.fakenet_subnet),
            socks_subnet=pick("SOCKS_SUBNET", "SOCKS_SUBNET", cls.socks_subnet),
            vpn_subnet=pick("VPN_SUBNET", "VPN_SUBNET", cls.vpn_subnet),
            vpn_gateway_ip=pick("VPN_GATEWAY_IP", "VPN_GATEWAY_IP", cls.vpn_gateway_ip),
            forwarder_uplink_ip=pick(
                "FORWARDER_UPLINK_IP", "FORWARDER_UPLINK_IP", cls.forwarder_uplink_ip),
            upstream_gw=pick("UPSTREAM_GW", "UPSTREAM_GW", ""),
            wg_iface=pick("WG_IF", "WG_IF", cls.wg_iface),
            wg_port=int(pick("WG_PORT", "WG_PORT", str(cls.wg_port))),
            overlay_net=pick("OVERLAY_NET", "OVERLAY_NET", cls.overlay_net),
            overlay_gateway_ip=pick("OVERLAY_GW", "GW_OVERLAY_IP", cls.overlay_gateway_ip),
            forwarder_image=pick("FORWARDER_IMAGE", "FORWARDER_IMAGE", cls.forwarder_image),
        )

    def to_env_lines(self) -> list[str]:
        """Serialise to ``KEY=value`` lines for the persistence unit's EnvironmentFile.

        Deliberately carries NO credential: the whole point of global mode is that a
        worker node's egress state is non-secret. A local-mode node's provider secrets
        live in the sidecar's own config, never here.
        """
        return [
            f"BLASTBOX_EGRESS_MODE={self.mode}",
            f"BLASTBOX_EGRESS_NET0_SUBNET={self.net0_subnet}",
            f"BLASTBOX_EGRESS_FAKENET_SUBNET={self.fakenet_subnet}",
            f"BLASTBOX_EGRESS_SOCKS_SUBNET={self.socks_subnet}",
            f"BLASTBOX_EGRESS_VPN_SUBNET={self.vpn_subnet}",
            f"BLASTBOX_EGRESS_VPN_GATEWAY_IP={self.vpn_gateway_ip}",
            f"BLASTBOX_EGRESS_FORWARDER_UPLINK_IP={self.forwarder_uplink_ip}",
            f"BLASTBOX_EGRESS_UPSTREAM_GW={self.upstream_gw}",
            f"BLASTBOX_EGRESS_WG_IF={self.wg_iface}",
            f"BLASTBOX_EGRESS_WG_PORT={self.wg_port}",
            f"BLASTBOX_EGRESS_OVERLAY_NET={self.overlay_net}",
            f"BLASTBOX_EGRESS_OVERLAY_GW={self.overlay_gateway_ip}",
            f"BLASTBOX_EGRESS_FORWARDER_IMAGE={self.forwarder_image}",
        ]


# --------------------------------------------------------------------------------------
# Subnet allocation
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SubnetPlan:
    """The outcome of :func:`allocate_subnets`: what to use, and what forced the change."""

    config: EgressConfig
    conflicts: tuple[tuple[str, str, str], ...] = ()   # (bridge, wanted, conflicting cidr)
    reallocated: tuple[tuple[str, str, str], ...] = ()  # (bridge, wanted, chosen)
    #: Summary routes (/8 or broader) that CONTAIN a chosen range but did not block it.
    #: Reported so an operator can overrule if their 10/8 really is fully allocated.
    advisory: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.reallocated)


# Candidate pools, in preference order. 172.16/12 first because that is where docker's own
# defaults live and operators expect blastbox there; 10.x as the fallback because a busy
# CAPE host has usually exhausted 172.16/12 (cape_default, fakenet-ng, per-branch compose
# stacks). 192.168/16 is deliberately absent — it collides with real lab LANs far more
# often than it helps.
_CANDIDATE_BASES = ("172.16.0.0/12", "10.0.0.0/8")


def _iter_candidates(prefixlen: int) -> Iterable[ipaddress.IPv4Network]:
    for base in _CANDIDATE_BASES:
        net = ipaddress.IPv4Network(base)
        if prefixlen < net.prefixlen:
            continue
        yield from net.subnets(new_prefix=prefixlen)


#: Claimed prefixes at least this broad are ADVISORY, not blocking. A host that routes a
#: summary like 10.0.0.0/8 to a corporate gateway has not actually claimed every /16
#: inside it — docker bridges live inside such ranges routinely, and the more-specific
#: bridge route wins. Treating a summary as blocking vetoed every candidate on a real
#: node and made allocation impossible. A /12 or longer IS treated as blocking, which
#: keeps the case that matters: the management LAN (a /16) can never be chosen.
SUMMARY_PREFIXLEN = 8


def allocate_subnets(
    cfg: EgressConfig,
    taken: Sequence[str],
    *,
    auto: bool = True,
    skip: frozenset[str] = frozenset(),
) -> SubnetPlan:
    """Resolve ``cfg``'s bridge subnets against the pools already in use on this host.

    ``taken`` is every CIDR docker (or anything else) already claims — the caller supplies
    it so this stays a pure function. Docker rejects an overlapping pool with *"invalid
    pool request: Pool overlaps with other one on this address space"*, which names neither
    the network nor the range; this reports both.

    With ``auto`` the colliding bridge is moved to the first free candidate of the same
    prefix length and any address pinned inside it (the gateway, the forwarder uplink)
    moves with it, preserving its host offset — so a relocated ``bb-vpn`` keeps its
    ``.0.10`` gateway and the personalities only need the one address updated.

    Relocating is safe precisely because the gateway address is per-node config rather
    than code: netd takes it as a flag and ``gateway_route_commands`` takes a plain IP.
    """
    # v4 only: every candidate pool and every bridge here is v4, and an IPv6 entry in
    # `taken` can never overlap one, so filtering keeps the types honest rather than
    # silently comparing across families.
    claimed = [n for n in (ipaddress.ip_network(t, strict=False) for t in taken)
               if isinstance(n, ipaddress.IPv4Network)]
    advisory = [c for c in claimed if c.prefixlen <= SUMMARY_PREFIXLEN]
    claimed = [c for c in claimed if c.prefixlen > SUMMARY_PREFIXLEN]

    def collides(candidate: ipaddress.IPv4Network) -> ipaddress.IPv4Network | None:
        for c in claimed:
            if candidate.overlaps(c):
                return c
        return None

    conflicts: list[tuple[str, str, str]] = []
    reallocated: list[tuple[str, str, str]] = []
    updates: dict[str, object] = {}
    # Newly chosen ranges must not collide with each other either, so they join `claimed`
    # as we go. Without this two relocated bridges can both land on the same free pool.
    field_for = {
        "bb-net0": "net0_subnet",
        "bb-fakenet": "fakenet_subnet",
        "bb-socks": "socks_subnet",
        "bb-vpn": "vpn_subnet",
    }

    for name, subnet, _internal in cfg.bridges:
        # A bridge that already exists is not a candidate — it is a fact. Re-checking it
        # against the host's routes would flag a working node as conflicted (its own
        # bridge route is in the routing table) and try to move it out from under running
        # containers.
        if name in skip:
            continue
        want = ipaddress.IPv4Network(subnet)
        hit = collides(want)
        if hit is None:
            claimed.append(want)
            continue
        conflicts.append((name, str(want), str(hit)))
        if not auto:
            continue
        chosen = None
        for cand in _iter_candidates(want.prefixlen):
            if collides(cand) is None:
                chosen = cand
                break
        if chosen is None:
            # Nothing free at this size. Report the conflict and leave the value alone —
            # a silent downgrade to a smaller prefix would surprise the operator far more
            # than an explicit failure.
            continue
        claimed.append(chosen)
        updates[field_for[name]] = str(chosen)
        reallocated.append((name, str(want), str(chosen)))
        # Carry pinned addresses across with their host offset intact.
        if name == "bb-vpn":
            updates["vpn_gateway_ip"] = str(
                chosen.network_address + (int(ipaddress.ip_address(cfg.vpn_gateway_ip))
                                          - int(want.network_address)))
        if name == "bb-net0":
            updates["forwarder_uplink_ip"] = str(
                chosen.network_address + (int(ipaddress.ip_address(cfg.forwarder_uplink_ip))
                                          - int(want.network_address)))

    new_cfg = replace(cfg, **updates) if updates else cfg  # type: ignore[arg-type]
    return SubnetPlan(config=new_cfg, conflicts=tuple(conflicts),
                      reallocated=tuple(reallocated),
                      advisory=tuple(str(a) for a in advisory))


# --------------------------------------------------------------------------------------
# WireGuard configs
# --------------------------------------------------------------------------------------

def gateway_wg_config(cfg: EgressConfig, private_key: str) -> str:
    """``wg-quick`` config for the EXIT HOST.

    ``ip_forward`` is enabled so this host can carry peer traffic INTO its local exit
    sidecars. It deliberately installs no NAT-to-WAN rule: what a peer's traffic is
    allowed to do is the exit layer's decision (see :func:`exit_host_steps`), never
    this file's.
    """
    prefixlen = ipaddress.ip_network(cfg.overlay_net).prefixlen
    return (
        "# blastbox egress overlay — EXIT HOST. Peers are appended by `blastbox egress peer-add`.\n"
        "[Interface]\n"
        f"Address = {cfg.overlay_gateway_ip}/{prefixlen}\n"
        f"ListenPort = {cfg.wg_port}\n"
        "PostUp = sysctl -w net.ipv4.ip_forward=1\n"
        f"PrivateKey = {private_key}\n"
    )


def gateway_peer_stanza(name: str, peer_ip: str, public_key: str) -> str:
    """One ``[Peer]`` block for the exit host.

    ``AllowedIPs`` is a single ``/32``: a peer may only ever source its own overlay
    address. Anything wider lets one compromised node impersonate another's traffic — and
    the per-worker rooter chains are keyed on source IP, so that would defeat them.
    """
    if not _SAFE_NAME.match(name):
        raise ValueError(f"unsafe peer name {name!r}")
    key = public_key.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{1,2}", key):
        raise ValueError("public_key is not a base64 WireGuard key")
    return (
        f"\n# peer:{name}\n"
        "[Peer]\n"
        f"PublicKey = {key}\n"
        f"AllowedIPs = {_ip(peer_ip)}/32\n"
    )


def peer_wg_config(cfg: EgressConfig, private_key: str, peer_ip: str,
                   gateway_addr: str, gateway_pubkey: str) -> str:
    """``wg-quick`` config for a WORKER NODE peer.

    TWO SETTINGS THAT LOOK CONTRADICTORY AND ARE NOT. ``AllowedIPs`` is ``0.0.0.0/0``
    while ``Table = off``.

    ``AllowedIPs`` is *cryptokey routing*, not a routing table: the set of destinations
    WireGuard will encrypt for this peer. Anything outside it is dropped inside the tunnel
    with no ICMP and no log. Since the point is to carry worker traffic for arbitrary
    internet destinations to the exit host, it has to be ``0.0.0.0/0`` — with the overlay
    prefix alone every packet not addressed to the overlay vanishes silently, which
    presents as "the tunnel is up, the peer pings, nothing else works".

    ``Table = off`` is what stops that becoming an egress grant. Left on, wg-quick would
    see the ``/0`` and install a default route plus fwmark rules, quietly routing the whole
    NODE out the tunnel. Off, wg-quick installs no routes at all and the only traffic that
    ever enters the tunnel is what :func:`forwarder_source_route_steps` deliberately
    puts there. Permission to *encrypt* is decided here; permission to *egress* is decided
    there.
    """
    prefixlen = ipaddress.ip_network(cfg.overlay_net).prefixlen
    return (
        "# blastbox egress overlay — WORKER NODE peer. See blastbox.host.egress.peer_wg_config\n"
        "# for why AllowedIPs is /0 and Table is off; they are load-bearing together.\n"
        "[Interface]\n"
        f"Address = {_ip(peer_ip)}/{prefixlen}\n"
        f"PrivateKey = {private_key}\n"
        "Table = off\n"
        f"PostUp = ip route replace {cfg.overlay_net} dev %i\n"
        "\n[Peer]\n"
        f"PublicKey = {gateway_pubkey.strip()}\n"
        f"Endpoint = {gateway_addr}:{cfg.wg_port}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )


# --------------------------------------------------------------------------------------
# Host rules
# --------------------------------------------------------------------------------------

def _chain_jump_steps(chain: str, match: list[str]) -> list[Step]:
    """Create ``chain``, put its FORWARD jump back at POSITION 1, then flush it.

    DELETE-THEN-INSERT, not check-then-insert. ``iptables -C`` matches a rule at ANY
    index, so a guard on existence is position-blind: once anything lands above our jump
    the guard keeps passing and no re-apply can ever hoist it back. That is not
    hypothetical — docker re-inserts DOCKER-USER/DOCKER-FORWARD at the head of FORWARD on
    every daemon start, and DOCKER-FORWARD holds a terminal ACCEPT for the non-internal
    bb-net0 bridge. ACCEPT in a jumped-to chain ends filter traversal, so a buried
    BB-WG-FWD means its ``-j DROP`` is dead code and the only thing left holding the line
    is the routing layer. Deleting first (repeatedly — an older buggy state may hold
    several) and re-inserting at 1 both de-duplicates and re-asserts precedence on every
    apply, which is exactly what the boot unit is for.

    The flush happens AFTER the jump is re-seated so the chain is never wired-but-empty
    for longer than the refill takes; an empty user chain RETURNs, falling through to
    docker's bridge ACCEPT.
    """
    steps: list[Step] = [Step.best_effort(["iptables", "-w", "5", "-N", chain], f"create {chain}")]
    steps += [Step.best_effort(["iptables", "-w", "5", "-D", "FORWARD", *match, "-j", chain])
              for _ in range(4)]
    steps.append(Step.of(["iptables", "-w", "5", "-I", "FORWARD", "1", *match, "-j", chain],
                         desc=f"jump FORWARD[1] -> {chain} (re-hoisted above docker's)"))
    steps.append(Step.of(["iptables", "-w", "5", "-F", chain], desc=f"flush {chain}"))
    return steps


def return_chain_steps(chain: str, out_iface: str, dest: str) -> list[Step]:
    """Allow the RETURN leg of an established flow, and nothing else.

    Both an exit host and a worker node run ``FORWARD`` policy DROP (docker plus the CAPE
    rooter). The outbound chains here match on SOURCE, so the reply direction matches
    nothing and dies on the policy: the forward path works perfectly, tcpdump shows the
    replies arriving, and the client still times out. Every tier needs its return leg
    allowed explicitly — and only for conntrack state already established, so this opens
    no inbound path.
    """
    oif = _iface(out_iface)
    return [
        *_chain_jump_steps(chain, ["-d", _net(dest)]),
        Step.of(["iptables", "-w", "5", "-A", chain, "-o", oif,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                desc="accept established return traffic"),
        Step.of(["iptables", "-w", "5", "-A", chain, "-j", "DROP"], desc="drop new inbound flows"),
    ]


def _rule_steps(selector: list[str], table: str) -> list[Step]:
    """A lookup rule plus the blackhole behind it, both re-appliable.

    ``ip rule add`` has no check-then-add form and happily creates duplicates, so each is
    deleted first (best-effort — it may not exist) and then added.

    The blackhole is not optional. An ``ip rule`` that matches but finds no route in its
    table does **not** stop; it falls through to the next rule, i.e. ``main``, i.e. this
    node's WAN. With the tunnel down the source route would silently become direct egress
    — observed on a live node before this rule existed.
    """
    return [
        Step.best_effort(["ip", "rule", "del", *selector, "lookup", table]),
        Step.of(["ip", "rule", "add", *selector, "lookup", table,
                 "priority", str(PRIO_LOOKUP)], desc=f"source route -> table {table}"),
        Step.best_effort(["ip", "rule", "del", *selector, "blackhole"]),
        Step.of(["ip", "rule", "add", *selector, "blackhole",
                 "priority", str(PRIO_BLACKHOLE)], desc="blackhole guard (no table => no egress)"),
    ]


def _overlay_main_steps(overlay_net: str) -> list[Step]:
    """Keep overlay-internal traffic on the main table.

    Without this the source-based rule below also captures this host's OWN replies to a
    peer — their source is an overlay address too — and posts them to the exit sidecar
    instead of back down the tunnel. The tunnel then handshakes, shows traffic, and
    carries nothing: the peer pings and gets silence.
    """
    return [
        Step.best_effort(["ip", "rule", "del", "to", overlay_net, "lookup", "main"]),
        Step.of(["ip", "rule", "add", "to", overlay_net, "lookup", "main",
                 "priority", str(PRIO_OVERLAY_MAIN)], desc="overlay-internal stays on main"),
    ]


def forwarder_source_route_steps(cfg: EgressConfig, bridge_iface: str) -> list[Step]:
    """WORKER NODE, global mode: force the forwarder's traffic into the overlay and make
    it impossible for that traffic to reach this node's WAN.

    This is the ENFORCEMENT half; the forwarder container is only plumbing. Keying on the
    forwarder's source IP is the same rooter model ``libvirt_egress`` uses for KVM and
    Firecracker workers, for the same reasons: runtime-agnostic, and resident on the host
    where a compromised guest cannot edit it.

    The SNAT is load-bearing too: WireGuard drops any packet whose source falls outside
    the peer's ``AllowedIPs``, and the exit host pins that to a single ``/32``, so traffic
    still sourced from the forwarder's docker address is discarded inside the tunnel with
    no error anywhere.
    """
    fwd = _ip(cfg.forwarder_uplink_ip)
    wg = _iface(cfg.wg_iface)
    return [
        # A table whose ONLY route is the tunnel: wg down => no default => no egress.
        Step.of(["ip", "route", "replace", "default", "dev", wg, "table", cfg.rt_table],
                desc=f"table {cfg.rt_table}: default via the tunnel"),
        *_overlay_main_steps(cfg.overlay_net),
        *_rule_steps(["from", fwd], cfg.rt_table),
        # Belt and braces: even if something restores a main-table default for this source,
        # anything not leaving via the tunnel is dropped.
        *_chain_jump_steps(CHAIN_FWD, ["-s", fwd]),
        Step.of(["iptables", "-w", "5", "-A", CHAIN_FWD, "-o", wg, "-j", "ACCEPT"]),
        Step.of(["iptables", "-w", "5", "-A", CHAIN_FWD, "-j", "DROP"], desc="no WAN escape"),
        Step.ensure(["iptables", "-w", "5", "-t", "nat", "-C", "POSTROUTING", "-o", wg, "-j", "MASQUERADE"],
                    ["iptables", "-w", "5", "-t", "nat", "-A", "POSTROUTING", "-o", wg, "-j", "MASQUERADE"],
                    "SNAT onto the tunnel address (AllowedIPs is a /32)"),
        # The return leg goes back to the forwarder over its DOCKER BRIDGE, not over the
        # tunnel — replies arrive from wg and must be forwarded onto the bridge. Naming
        # the tunnel here instead makes the chain match nothing, so the forward path works
        # and the forwarder's own gate probe never sees a reply.
        *return_chain_steps(CHAIN_FWD_RET, bridge_iface, f"{fwd}/32"),
        Step.of(["sysctl", "-qw", "net.ipv4.ip_forward=1"]),
    ]


def exit_host_steps(cfg: EgressConfig, exit_iface: str) -> list[Step]:
    """EXIT HOST: hand traffic arriving from peers to the LOCAL exit sidecar.

    Without this the overlay faithfully delivers worker traffic to this host and then
    leaks it out the front door.

    The filter rule matches the OUTPUT INTERFACE, not the destination. These packets are
    addressed to the internet and merely *routed via* the sidecar, so a ``-d <gateway>``
    rule matches nothing and the chain silently drops every packet — which presents as a
    tunnel that handshakes and then times out.

    The SNAT is required too: the exit sidecars (OpenVPN client, tor transproxy)
    masquerade their OWN subnet, so a packet still sourced from an overlay address matches
    none of their rules and is dropped inside the container. Rewriting the source makes a
    peer's traffic indistinguishable from a local worker's — which is the entire point.
    """
    gw = _ip(cfg.vpn_gateway_ip)
    eif = _iface(exit_iface)
    return [
        Step.of(["ip", "route", "replace", "default", "via", gw, "table", cfg.rt_table],
                desc="table: default via the local exit sidecar"),
        *_overlay_main_steps(cfg.overlay_net),
        *_rule_steps(["from", cfg.overlay_net], cfg.rt_table),
        *_chain_jump_steps(CHAIN_EXIT, ["-s", cfg.overlay_net]),
        Step.of(["iptables", "-w", "5", "-A", CHAIN_EXIT, "-o", eif, "-j", "ACCEPT"],
                desc="peer traffic may ONLY leave by the exit bridge"),
        Step.of(["iptables", "-w", "5", "-A", CHAIN_EXIT, "-j", "DROP"]),
        Step.ensure(["iptables", "-w", "5", "-t", "nat", "-C", "POSTROUTING",
                     "-s", cfg.overlay_net, "-o", eif, "-j", "MASQUERADE"],
                    ["iptables", "-w", "5", "-t", "nat", "-A", "POSTROUTING",
                     "-s", cfg.overlay_net, "-o", eif, "-j", "MASQUERADE"],
                    "SNAT so the sidecar sees a local source"),
        *return_chain_steps(CHAIN_EXIT_RET, cfg.wg_iface, cfg.overlay_net),
        Step.of(["sysctl", "-qw", "net.ipv4.ip_forward=1"]),
    ]


def teardown_steps(cfg: EgressConfig) -> list[Step]:
    """Remove only what we created.

    Rules are deleted **by match or by our own priority**, never by index: these hosts run
    a co-resident CAPE rooter (13 FORWARD rules on one, 77 on another) and deleting by
    index would renumber its rules out from under it. Everything is best-effort so a
    partially-applied state still tears down cleanly.
    """
    cmds: list[Step] = []
    for prio in ALL_PRIORITIES:
        # Loop: a re-applied node can hold more than one rule at a priority if an earlier
        # version added without deleting first.
        for _ in range(4):
            cmds.append(Step.best_effort(["ip", "rule", "del", "priority", str(prio)]))
    cmds.append(Step.best_effort(["ip", "route", "flush", "table", cfg.rt_table]))
    cmds.append(Step.best_effort(["iptables", "-w", "5", "-t", "nat", "-D", "POSTROUTING",
                                  "-o", cfg.wg_iface, "-j", "MASQUERADE"]))
    for chain in ALL_CHAINS:
        cmds.append(Step.best_effort(["iptables", "-w", "5", "-F", chain]))
        cmds.append(Step.best_effort(["iptables", "-w", "5", "-X", chain]))
    return cmds


def forwarder_run_argv(cfg: EgressConfig) -> list[str]:
    """``docker run`` argv for the credential-free forwarder.

    Two details are load-bearing:

    * **bb-net0 first, bb-vpn second** (the second attach is a separate
      ``docker network connect``). bb-vpn is internal and carries no default route, so a
      container started there has no uplink for its entrypoint to find and exits before
      one can be attached.
    * **``--restart on-failure:3``, not ``unless-stopped``.** A forwarder whose startup
      gate fails is supposed to be visibly dead; restarting it forever makes ``docker ps``
      report a healthy container that forwards nothing — a silent outage, which is worse
      than a loud one.
    """
    if cfg.mode != "global":
        raise ValueError("forwarder_run_argv is only meaningful in mode=global")
    return [
        "docker", "run", "-d", "--name", cfg.forwarder_name,
        "--restart", "on-failure:3",
        "--network", "bb-net0", "--ip", cfg.forwarder_uplink_ip,
        "--cap-add", "NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1",
        "-e", f"BLASTBOX_UPSTREAM_GW={cfg.upstream_gw}",
        "-e", f"BLASTBOX_WORKER_SUBNET={cfg.vpn_subnet}",
        cfg.forwarder_image,
    ]


def forwarder_connect_argv(cfg: EgressConfig) -> list[str]:
    """Attach the forwarder to the internal worker bridge at the gateway address."""
    return ["docker", "network", "connect", "--ip", cfg.vpn_gateway_ip,
            "bb-vpn", cfg.forwarder_name]


# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Health:
    healthy: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.healthy


#: The line the forwarder's entrypoint prints once its startup gate has passed, i.e. once
#: it has actually reached the exit host across the overlay. Matching on this rather than
#: on container state is what distinguishes "up" from "up and useful".
GATE_OK_PATTERN = re.compile(r"overlay peer \S+ reachable")


def forwarder_health(
    *,
    running: bool,
    logs_since_start: str,
    restart_count: int = 0,
) -> Health:
    """Decide whether a global-mode node can actually egress.

    "Running" is not proof: a crash-looping container is running most of the time, and a
    restart policy keeps one alive after its startup gate failed. So health requires the
    container to be up AND its own gate line to be present — the gate only prints after a
    successful probe across the overlay, so it is positive evidence that the node-side
    source routing is live and the exit host is reachable.

    ``logs_since_start``, NOT the whole log, and ``restart_count`` is informational only.
    Restart count is monotonic for the container's life, so disqualifying on it means one
    transient overlay blip ejects a node from the dispatch pool permanently — even after
    it fully recovers. That was the first version of this rule and it marked a node
    DEGRADED that was provably carrying traffic. What matters is whether the incarnation
    running *now* got through its gate, which is exactly what the logs since its last
    start answer. A container that is still crash-looping fails anyway: each new
    incarnation's log has no gate line, and once the policy gives up it is not running.
    """
    if not running:
        return Health(False, "forwarder container is not running")
    if not GATE_OK_PATTERN.search(logs_since_start or ""):
        return Health(
            False,
            "the running forwarder has not logged a successful overlay probe "
            f"(restarts so far: {restart_count})")
    note = f" (recovered after {restart_count} restart(s))" if restart_count else ""
    return Health(True, f"forwarder up and past its overlay probe{note}")


#: The boot-time re-apply unit, as a STRING rather than a file read from ``deploy/``.
#:
#: ``deploy/`` is not shipped in the wheel (no MANIFEST.in, and package-data lists only
#: ``py.typed``), and a pip install is the distribution channel this repo actually has.
#: Reading the unit off disk therefore always took the "not found" branch on a real
#: node — so the reboot-persistence fix was inert on exactly the installs that needed
#: it, while printing a note that scrolled past among a dozen others. Generating it here
#: makes persistence work identically from a wheel and a checkout.
#: ``deploy/systemd/blastbox-egress.service`` is kept as the hand-install copy and is
#: asserted to match this text by ``tests/host/test_egress.py``.
def persistence_unit(exec_start: str, wg_iface: str = "bbwg0") -> str:
    """Render the systemd unit that re-applies this node's egress tier at boot."""
    return f"""# blastbox-egress — re-apply this node's egress tier at boot.
#
# WHY THIS UNIT EXISTS. The egress tier is `ip rule`s, a dedicated routing table and
# BB-WG-* iptables chains. None of that survives a reboot. Without this unit a node comes
# back with its bridges intact (docker persists those) and its ENFORCEMENT gone — the
# forwarder fails its startup gate and stays down, so the tier fails closed rather than
# leaking, but the node is silently useless for egress work until someone notices.
# Fail-closed is the correct failure; staying failed until a human intervenes is not.
#
# Oneshot with RemainAfterExit: applying is idempotent (every step is guarded, deleted
# first, or best-effort), so a restart re-converges rather than stacking duplicates.
#
# ORDERING IS LOAD-BEARING. After docker (the bridges and the forwarder are containers)
# and after wg-quick (the source route installs `default dev <wg>` into its own table,
# which needs the interface to exist). `Wants=` not `Requires=` on wg-quick: a local-mode
# node has no overlay at all and this unit must still run.
#
# Generated by `blastbox egress apply` from blastbox.host.egress.persistence_unit.

[Unit]
Description=blastbox egress tier (bridges, exit mode, overlay source routing)
After=docker.service network-online.target wg-quick@{wg_iface}.service
Wants=network-online.target wg-quick@{wg_iface}.service
Requires=docker.service
# Without the env file there is no configured tier to re-apply, and `apply` would fall
# back to defaults that may not match this node. Do nothing rather than guess.
ConditionPathExists=/etc/blastbox/egress.env

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=/etc/blastbox/egress.env
ExecStart={exec_start}
# Re-applying is cheap and idempotent, and a node that comes up before its exit host is
# reachable should keep trying rather than sit degraded until someone logs in.
Restart=on-failure
RestartSec=30

# This genuinely needs privilege: it creates docker networks, writes routing tables and
# iptables chains, and starts a NET_ADMIN container. Runs as root, bounded to the
# capabilities it actually uses.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_OVERRIDE
ProtectSystem=full
ReadWritePaths=/etc/wireguard /etc/blastbox /etc/iproute2

[Install]
WantedBy=multi-user.target
"""
