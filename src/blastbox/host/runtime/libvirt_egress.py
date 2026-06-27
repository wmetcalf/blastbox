"""Host-side egress policy for libvirt VM workers (the rooter model).

A container worker is leak-guarded *inside its own netns* (``netwire.leak_guard_rules`` on the
netns OUTPUT chain). A full VM has no netns to ``nsenter`` — its traffic is **forwarded** by the
host, so the same netpolicy personality (exit driver, ``egress_ports``, ``block_internal``) is
enforced on the **host FORWARD chain**, matched on the worker's source IP, in a dedicated
per-worker chain. This is the model the CAPE rooter uses and that win-validator P0 proved
(web-only 53/80/443 + block-internal, real CRL fetched, non-web + RFC1918 blocked).

Reuses :data:`blastbox.host.netwire._INTERNAL_NETS` and ``parse_egress_ports`` so the VM path and
the container path share one definition of "internal" and one port parser. The exit *routing*
(direct NAT vs vpn/tor policy-route) is host/gateway-specific and layered separately; this module
owns the **filter** (what the worker may reach) — the security-critical half — plus the drop/none
dispositions. A dedicated chain + a single ``-s <ip>`` jump means install/teardown never touches
sibling workers or a co-resident rooter's rules.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

from blastbox.host.netpolicy import Personality
from blastbox.host.netwire import _INTERNAL_NETS, parse_egress_ports

logger = logging.getLogger(__name__)


def _run(args: list[str], timeout: float = 20) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # a hung iptables/ip call must not abort apply/remove mid-rule with an uncaught exception
        return subprocess.CompletedProcess(args, 124, "", "timeout")


@dataclass(frozen=True)
class VmEgressPolicy:
    """The filter half of a netpolicy personality, for a VM worker."""

    exit_driver: str  # none | drop | direct | openvpn | wireguard | tor
    egress_ports: tuple[int, ...] | None = None
    block_internal: bool = False

    @classmethod
    def from_personality(cls, p: Personality) -> "VmEgressPolicy":
        cfg = p.config
        block = cfg.get("block_internal", "").strip().lower() in ("1", "true", "yes", "on")
        return cls(
            exit_driver=p.exit_driver,
            egress_ports=parse_egress_ports(cfg.get("egress_ports")),
            block_internal=block,
        )


def _chain_name(worker_ip: str) -> str:
    # iptables chain names: ≤28 chars, no dots. BBVM_<ip-with-underscores> fits IPv4.
    return "BBVM_" + worker_ip.replace(".", "_")


def _input_chain_name(worker_ip: str) -> str:
    # The host-INPUT counterpart of _chain_name. "BBVMIN_"+15 = ≤22 chars, fits the 28-char limit.
    return "BBVMIN_" + worker_ip.replace(".", "_")


@dataclass(frozen=True)
class ExitRouting:
    """Host-side endpoints for rooter-style exit routing (single-NIC, route-tables + iptables).

    The worker stays on its management network (so the host reaches its agent on the local
    subnet); only its *external* egress is steered per exit driver. Defaults match toolz3's
    CAPE infra (PIA tun0 + ``vpn`` table, FakeNet on br-fakenet)."""

    vpn_table: str = "vpn"          # rt_tables entry whose default route is the VPN tun
    vpn_tun: str = "tun0"           # device to MASQUERADE the worker's source onto
    tor_trans_port: int = 9040      # tor TransPort (transparent TCP)
    tor_dns_port: int = 9053        # tor DNSPort (NOT 5353 — that collides with mDNS/avahi)
    fakenet_addr: str | None = None  # FakeNet-NG listen IP (e.g. 172.28.100.1); None disables inetsim
    rule_priority_base: int = 1000  # ip-rule priority = base + low-16-bits of IP (unique per /16)
    worker_cidr: str | None = None  # the worker network's CIDR (e.g. 192.168.0.0/16) for the local
    # "keep host/agent traffic on main" exemption. None ⇒ derive worker_ip's /24 (the libvirt
    # default). Set this when the worker net is NOT a /24, else the bridge/agent address can fall
    # outside the assumed /24 and host-control traffic gets steered through the VPN table.

    # --- shared-router / next-hop mode -------------------------------------------------
    # When ``gateway`` + ``leg`` are set, openvpn/wireguard route the worker to a next-hop ROUTER VM
    # on the ``leg`` network (which holds the VPN), instead of a local tun. Different gateways = the
    # different provider routers (vpn1, vpn2, …); many blastbox hosts pointing at the same router
    # share one VPN link. The default route ``via <gateway> dev <leg>`` lives in a per-gateway table
    # (shared across this host's workers); per-worker ``ip rule``s select it.
    gateway: str | None = None       # next-hop router IP on the leg network (None = local-tun mode)
    leg: str | None = None           # host interface into the router network
    gateway_table_base: int = 200    # per-gateway table = base + last octet of the gateway IP
    gateway_masquerade: bool = True  # SNAT the worker onto the leg so the router replies to the host


_ROUTING_DRIVERS = ("openvpn", "wireguard", "tor", "inetsim")  # drivers that install routing rules
_SUPPORTED_EXITS = frozenset({"none", "drop", "direct", *_ROUTING_DRIVERS})  # exits the VM rooter wires


_MAIN_RULE_PRIORITY = 32766  # the kernel's default `main` ip-rule priority


def _rule_priority(worker_ip: str, routing: ExitRouting) -> int:
    # Use the low 16 bits of the IP (third+fourth octets), not just the last octet, so two workers
    # in *different* /24s of the same supernet rarely share a priority slot. CLAMP into a window
    # strictly BELOW `main` (32766): a raw base + 16-bit value reaches ~33000, so for a third octet
    # >= ~124 the worker rule would sort at/after `main` and never select the tunnel table (traffic
    # then follows the host route → killed by the kill-switch or misrouted). The modulo keeps every
    # priority in [base, base+span) < main; within a /24 the 256 values stay distinct.
    o = worker_ip.split(".")
    span = (_MAIN_RULE_PRIORITY - 1) - routing.rule_priority_base  # leave the slot just under main free
    return routing.rule_priority_base + (((int(o[2]) << 8) + int(o[3])) % span)


def _tor_tcp_redirects(worker_ip: str, routing: ExitRouting,
                       egress_ports: tuple[int, ...] | None) -> list[list[str]]:
    """TCP REDIRECT(s) into tor's TransPort. With an egress_ports allow-list set, only those TCP
    ports (minus 53, handled by the DNS redirect) are sent to tor — so the allow-list composes with
    tor (the rest fall through to the FORWARD drop). Unset = catch-all (all TCP), since tor applies
    its own exit policy. (Non-TCP is always dropped in FORWARD regardless.)"""
    tcp_ports = [p for p in (egress_ports or ()) if p != 53]
    base = ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-p", "tcp"]
    tail = ["-j", "REDIRECT", "--to-ports", str(routing.tor_trans_port)]
    if egress_ports is not None:
        return [base + ["--dport", str(p)] + tail for p in tcp_ports]
    return [base + tail]


def routing_commands(worker_ip: str, exit_driver: str, routing: ExitRouting,
                     egress_ports: tuple[int, ...] | None = None,
                     block_internal: bool = False) -> list[list[str]]:
    """The privileged argv (``ip``/``iptables`` nat) that *steer* the worker's external egress for
    its exit driver — the rooter half, separate from the FORWARD *filter*. ``direct``/``none``/
    ``drop`` need none (direct = main-table default; none/drop are filter-dropped). Each command is
    idempotently torn down by :meth:`LibvirtEgress.remove` (delete-by-match, no priority guessing).

    ``egress_ports`` (the policy's destination-port allow-list) port-scopes a tor exit's TCP REDIRECT
    so the allow-list composes with tor; unset means all TCP via tor. ``block_internal`` makes a tor
    exit RETURN RFC1918-destined TCP from nat *before* the tor REDIRECT, so it falls through to the
    FORWARD block-internal DROP instead of being transparently proxied (which would bypass it)."""
    if exit_driver in ("direct", "none", "drop"):
        return []
    # keep host/agent traffic on the local subnet: the configured worker CIDR if given, else the
    # worker IP's /24 (libvirt default). A non-/24 net MUST set ExitRouting.worker_cidr.
    local = routing.worker_cidr or (".".join(worker_ip.split(".")[:3]) + ".0/24")
    if exit_driver in ("openvpn", "wireguard"):
        prio = _rule_priority(worker_ip, routing)
        if routing.gateway and routing.leg:
            # SHARED-ROUTER / next-hop mode: forward the worker to a router VM on the leg network
            # that holds the VPN. The per-gateway table's default is via that router; many
            # workers/hosts reusing the same router share one VPN link.
            # Key the table on the gateway's LOW 16 BITS (3rd+4th octet), not just the last octet:
            # otherwise 10.99.0.2 and 10.99.1.2 would both hash to base+2 and the later worker's
            # `ip route replace ... table <id>` would silently re-point the earlier gateway's table,
            # sending in-flight workers' tunnel traffic through the wrong router (isolation break).
            go = routing.gateway.split(".")
            table = str(routing.gateway_table_base + (int(go[2]) << 8) + int(go[3]))
            cmds = [
                ["ip", "route", "replace", "default", "via", routing.gateway, "dev", routing.leg, "table", table],
                ["ip", "rule", "add", "from", worker_ip, "to", local, "lookup", "main", "priority", str(prio - 1)],
                ["ip", "rule", "add", "from", worker_ip, "lookup", table, "priority", str(prio)],
            ]
            if routing.gateway_masquerade:
                cmds.append(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", worker_ip,
                             "-o", routing.leg, "-j", "MASQUERADE"])
            return cmds
        # LOCAL-TUN mode: this host runs the VPN itself
        return [
            # local subnet (host + agent) stays on the main table; everything else → the VPN table
            ["ip", "rule", "add", "from", worker_ip, "to", local, "lookup", "main", "priority", str(prio - 1)],
            ["ip", "rule", "add", "from", worker_ip, "lookup", routing.vpn_table, "priority", str(prio)],
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", worker_ip,
             "-o", routing.vpn_tun, "-j", "MASQUERADE"],
        ]
    if exit_driver == "tor":
        cmds = []
        # DNS redirect is gated on the allowlist (parity with the container leak guard + the direct/
        # INPUT DNS gate): an explicit egress_ports that omits 53 means "no DNS", so we DON'T redirect
        # it into tor — unredirected DNS (udp 53 / non-allowlisted tcp 53) then falls through to the
        # FORWARD chain and is dropped. Unset allowlist or one including 53 ⇒ resolve via tor's DNSPort.
        if egress_ports is None or 53 in egress_ports:
            cmds += [
                # DNS FIRST (udp+tcp 53), BEFORE the local-subnet RETURN — otherwise DNS to the bridge
                # resolver (192.168.122.1:53) matches the RETURN and resolves OUTSIDE tor (a deanon leak).
                ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
                 "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(routing.tor_dns_port)],
                ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
                 "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(routing.tor_dns_port)],
            ]
        cmds.append(
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-d", local, "-j", "RETURN"])
        if block_internal:
            # RETURN RFC1918-destined TCP from nat (after the local /24 RETURN above) so it is NOT
            # transparently proxied to tor — it falls through to FORWARD where block_internal DROPs
            # it. Without this, block_internal's intent is bypassed at the redirect layer (tor's own
            # exit policy refuses private addrs, but don't rely on that). -p tcp only: DNS(53) was
            # already redirected to the DNSPort above, and resolving a name doesn't reach an internal host.
            cmds += [["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-d", net,
                      "-p", "tcp", "-j", "RETURN"] for net in _INTERNAL_NETS]
        # TCP → tor's TransPort: all of it (tor is a SOCKS proxy), OR only the allowlisted ports
        # when egress_ports composes a port restriction onto tor. Non-allowlisted TCP + all
        # non-TCP fall through to the FORWARD drop.
        return cmds + _tor_tcp_redirects(worker_ip, routing, egress_ports)
    if exit_driver == "inetsim":
        if not routing.fakenet_addr:
            return []
        fn = routing.fakenet_addr
        # DNS FIRST (even to the local bridge resolver) → FakeNet, so attacker C2 domains resolve to
        # the sinkhole instead of NXDOMAIN'ing at dnsmasq. Then keep other host/agent control traffic
        # local, and DNAT everything else (preserving dport) to the FakeNet-NG listener.
        return [
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", fn + ":53"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", fn + ":53"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-d", local, "-j", "RETURN"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-j", "DNAT", "--to-destination", fn],
        ]
    return []


def routing_teardown_commands(worker_ip: str, exit_driver: str, routing: ExitRouting,
                              egress_ports: tuple[int, ...] | None = None,
                              block_internal: bool = False) -> list[list[str]]:
    """Inverse of :func:`routing_commands` — ``ip rule del`` + ``iptables -t nat -D`` by exact match.
    ``egress_ports`` must match what was applied so a port-scoped tor's per-port REDIRECTs are torn
    down (deployments are homogeneous, so the worker's own policy ports are the right set).
    ``block_internal`` is passed straight through; ``remove()`` sets it True so the internal-net
    RETURNs are swept even if the live policy didn't set it (del-by-match is a harmless no-op)."""
    cmds: list[list[str]] = []
    for c in routing_commands(worker_ip, exit_driver, routing, egress_ports, block_internal):
        if c[:2] == ["ip", "route"]:
            continue  # the shared per-gateway default route is reusable infra — leave it in place
        if c[:2] == ["ip", "rule"]:
            cmds.append(["ip", "rule", "del"] + c[3:])  # del <selector...> (drop the "add")
        else:  # iptables -t nat -A ... -> -D ...
            cmds.append([("-D" if tok == "-A" else tok) for tok in c])
    return cmds


def forward_chain_rules(worker_ip: str, policy: VmEgressPolicy, gateway: str | None,
                        egress_if: str | None = None, sink_addr: str | None = None) -> list[list[str]]:
    """The ordered ``iptables`` rule bodies (sans ``iptables``) for the worker's dedicated FORWARD
    chain. Order: return-traffic → gateway DNS → sink exemption → block-internal → exit disposition
    → web allowlist.

    ``gateway`` (the libvirt bridge IP, dnsmasq) is exempted for DNS *before* the internal block so a
    NAT/direct worker can still resolve revocation responders even with ``block_internal``.
    ``sink_addr`` (the FakeNet listener, for an ``inetsim`` exit reached by forwarding) is exempted
    before the block too: PREROUTING DNATs everything to that RFC1918 sink, so without the exemption
    ``block_internal`` would DROP the very traffic it's meant to redirect into the sink."""
    c = _chain_name(worker_ip)
    # ``egress_if`` (set only for tunneled openvpn/wireguard exits) scopes EVERY accept — including
    # this established-flow accept — to the tunnel. The chain is entered only via ``FORWARD -s
    # <worker>`` so it sees the worker's OUTBOUND packets only (replies, ``-s <remote>``, never reach
    # it), so scoping the established accept can't strand inbound return traffic — and it closes the
    # kill-switch hole where an already-established flow would otherwise leak over the host WAN if the
    # tunnel drops mid-connection (the conntrack ACCEPT short-circuits before the ``-o tun`` accepts).
    oif = ["-o", egress_if] if egress_if else []
    r: list[list[str]] = [
        ["-A", c, *oif, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    if gateway and policy.exit_driver not in ("none", "drop", "tor"):
        # DNS to the bridge resolver only (not arbitrary internal hosts). Skipped for none/drop —
        # a no-egress policy must not leak even DNS — and for tor, whose DNS is fully REDIRECTed to
        # the DNSPort in PREROUTING (so no FORWARD exemption is needed or wanted).
        r.append(["-A", c, "-d", gateway, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        r.append(["-A", c, "-d", gateway, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    if policy.block_internal:
        if sink_addr:  # inetsim DNATs to this RFC1918 sink; exempt it so the block doesn't kill it
            r.append(["-A", c, "-d", sink_addr, "-j", "ACCEPT"])
        r += [["-A", c, "-d", net, "-j", "DROP"] for net in _INTERNAL_NETS]

    if policy.exit_driver in ("none", "drop"):
        r.append(["-A", c, "-j", "DROP"])
        return r

    if policy.exit_driver == "tor":
        # tor is a SOCKS/transparent TCP proxy. ALL TCP and DNS(53) were REDIRECTed into tor in
        # PREROUTING, so they never traverse FORWARD; anything reaching here is a NON-TCP protocol
        # (UDP≠53, ICMP, QUIC over UDP, …) that tor's TCP-only transport can't carry. DROP it so it
        # can't leak straight to clearnet around tor. egress_ports does NOT port-restrict tor —
        # tor applies its own exit policy. (ESTABLISHED return traffic was ACCEPTed above.)
        r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
                  "--log-prefix", "bbvm-tor-nontcp-drop ", "--log-level", "4"])
        r.append(["-A", c, "-j", "DROP"])
        return r

    # direct / openvpn / wireguard. ``egress_if`` (set for tunneled exits) is the KILL-SWITCH: scope
    # the egress ACCEPTs to the tunnel/leg interface so that if the tunnel drops — and the worker's
    # packets fall back to the host's default route — they hit the catch-all DROP instead of leaking
    # out the host's WAN with the worker's traffic. ``direct`` has no egress_if (egress via host is
    # the intent), so it ACCEPTs unscoped.
    if policy.egress_ports is not None:  # oif computed at the top of this function
        if 53 in policy.egress_ports:
            r.append(["-A", c, "-p", "udp", "--dport", "53", *oif, "-j", "ACCEPT"])
        for i in range(0, len(policy.egress_ports), 15):  # multiport caps at 15 dports/rule
            chunk = ",".join(str(p) for p in policy.egress_ports[i:i + 15])
            r.append(["-A", c, "-p", "tcp", "-m", "multiport", "--dports", chunk, *oif, "-j", "ACCEPT"])
        r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
                  "--log-prefix", "bbvm-egress-drop ", "--log-level", "4"])
        r.append(["-A", c, "-j", "DROP"])
    elif oif:
        # tunneled exit, no port allowlist: permit ALL traffic, but ONLY out the tunnel. The trailing
        # DROP is the kill-switch — tunnel down → no egress (fail closed), not a host-IP leak.
        r.append(["-A", c, *oif, "-j", "ACCEPT"])
        r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
                  "--log-prefix", "bbvm-killswitch-drop ", "--log-level", "4"])
        r.append(["-A", c, "-j", "DROP"])
    else:
        # direct: no port allowlist, no tunnel → permit (egress via the host is the intent)
        r.append(["-A", c, "-j", "ACCEPT"])
    return r


def input_chain_rules(worker_ip: str, policy: VmEgressPolicy, gateway: str | None,
                      routing: ExitRouting | None) -> list[list[str]]:
    """The ordered ``iptables`` rule bodies for the worker's dedicated host-**INPUT** chain.

    Packets the guest sends to a HOST-LOCAL address — the libvirt bridge IP (dnsmasq), or a
    PREROUTING REDIRECT/DNAT target that lands on the host itself (tor's TransPort/DNSPort, the
    FakeNet listener) — are delivered locally via the host ``INPUT`` chain, **not** ``FORWARD``, so
    the per-worker FORWARD filter never sees them. Without this chain, ``none``/``drop``/
    ``block_internal`` can still reach host daemons on the bridge, and a vpn/tor worker can resolve
    through the host's *clearnet* resolver (a DNS deanonymization leak while the payload rides the
    tunnel). This chain accepts ONLY the control-plane essentials the worker legitimately needs from
    the host for its exit driver, then DROPs the rest — so it fully governs host-destined traffic."""
    c = _input_chain_name(worker_ip)
    r: list[list[str]] = [
        # agent return-flow: the host dials the guest agent; the guest's replies are ESTABLISHED.
        ["-A", c, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        # DHCP lease renewal to the bridge (unicast from the assigned IP; the initial DISCOVER is
        # from 0.0.0.0 and never enters this -s <ip> chain — libvirt's own INPUT rules carry that).
        ["-A", c, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
    ]
    drv = policy.exit_driver
    if drv == "direct" and gateway and (policy.egress_ports is None or 53 in policy.egress_ports):
        # direct: the worker may use the host's dnsmasq resolver — clearnet DNS is the intent (CRL/
        # OCSP responders resolve here, then the connection itself is FORWARDed under egress_ports).
        # Gated on the allowlist the same way FORWARD is: an explicit egress_ports that omits 53
        # means "no DNS", so the host-resolver exemption is withheld too (no INPUT-side bypass).
        r.append(["-A", c, "-d", gateway, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        r.append(["-A", c, "-d", gateway, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    elif drv == "tor" and routing is not None:
        # tor REDIRECTs the guest's DNS(53) and all TCP onto the host's tor ports; post-NAT that
        # traffic is host-destined, so accept exactly those local ports (nothing else reaches clearnet).
        # The DNSPort accept is gated on the allowlist to match the routing-side gate: if 53 isn't
        # allowed, no DNS redirect is installed, so accepting the DNSPort would be dead anyway.
        if policy.egress_ports is None or 53 in policy.egress_ports:
            r.append(["-A", c, "-p", "udp", "--dport", str(routing.tor_dns_port), "-j", "ACCEPT"])
            r.append(["-A", c, "-p", "tcp", "--dport", str(routing.tor_dns_port), "-j", "ACCEPT"])
        r.append(["-A", c, "-p", "tcp", "--dport", str(routing.tor_trans_port), "-j", "ACCEPT"])
    elif drv == "inetsim" and routing is not None and routing.fakenet_addr:
        # inetsim DNATs DNS + everything to the FakeNet listener (a host-local addr → INPUT). The
        # sink captures ALL ports by design — egress_ports does NOT constrain it (the allowlist
        # governs real egress drivers; reaching a controlled local sinkhole on any port is not a
        # leak), so this accept is intentionally not port-scoped.
        r.append(["-A", c, "-d", routing.fakenet_addr, "-j", "ACCEPT"])
    # openvpn / wireguard / none / drop: NO host-resolver DNS exemption. A tunneled exit must resolve
    # THROUGH the tunnel (an external resolver reached over the policy route), never via the host's
    # clearnet dnsmasq — else the domains it looks up leak over the host default route while the
    # payload rides the VPN. none/drop must reach no host service at all.
    r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
              "--log-prefix", "bbvm-host-drop ", "--log-level", "4"])
    r.append(["-A", c, "-j", "DROP"])
    return r


def _ip_rule_deletes(worker_ip: str, ip_rule_dump: str) -> list[list[str]]:
    """From ``ip rule show`` output, the ``ip rule del`` argv for EVERY rule selecting ``from
    <worker_ip>`` — by its FULL selector, not bare priority.

    The per-driver teardown only deletes the exact argv generated from the CURRENT ExitRouting, so a
    reused DHCP IP whose prior worker used a different vpn_table / next-hop gateway / worker_cidr
    leaves a stale ``ip rule from <worker_ip> lookup <old-table>``. Deleting by bare ``priority``
    would be wrong: adjacent workers share priorities (worker .6's local-main rule can sit at the same
    priority as worker .5's tunnel rule), so ``ip rule del priority <p>`` could remove a SIBLING's
    route. Reconstruct the full selector (``from <ip> [to ..] lookup ..``) + its priority so each
    delete matches exactly this worker's own rule."""
    out: list[list[str]] = []
    for line in ip_rule_dump.splitlines():
        # e.g. "32237:\tfrom 192.168.122.5 lookup vpn" → prio 32237, selector "from <ip> lookup vpn"
        toks = line.replace(":", " ", 1).split()
        if len(toks) >= 3 and toks[0].isdigit() and toks[1] == "from" and toks[2] == worker_ip:
            prio, selector = toks[0], toks[1:]
            out.append(["ip", "rule", "del", *selector, "priority", prio])
    return out


def _fakenet_dnat_deletes(worker_ip: str, prerouting_dump: str) -> list[list[str]]:
    """From ``iptables -t nat -S PREROUTING``, the ``-D`` argv for EVERY DNAT this worker has —
    whatever sink address installed it. del-by-match teardown only removes DNATs for the CURRENT
    ``fakenet_addr``, so a reused DHCP IP whose prior inetsim worker DNATed to a now-changed sink
    would leave an orphan catch-all DNAT ahead of the new rules, silently sending its traffic to the
    OLD sink. Enumerate and delete all of the worker's DNATs regardless of target."""
    src = f"-s {worker_ip}/32"
    out: list[list[str]] = []
    for line in prerouting_dump.splitlines():
        toks = line.split()
        if toks[:2] == ["-A", "PREROUTING"] and src in line and "-j DNAT" in line:
            out.append(["iptables", "-t", "nat", "-D", *toks[1:]])
    return out


def _tor_redirect_deletes(worker_ip: str, tor_trans_port: int, prerouting_dump: str) -> list[list[str]]:
    """From ``iptables -t nat -S PREROUTING`` output, the ``-D`` argv for EVERY TCP REDIRECT this
    worker has into tor's TransPort — whatever port set installed them (catch-all vs per-port).

    del-by-match teardown can only remove the exact ports the *current* policy names, so a reused
    DHCP IP whose prior worker had a different ``egress_ports`` (e.g. a catch-all tor worker followed
    by a port-scoped one) would otherwise leave an orphan REDIRECT that silently bypasses the new
    allow-list. Enumerating the live rules and deleting them all closes that, regardless of history."""
    src = f"-s {worker_ip}/32"  # iptables -S always prints /32 for a host; exact match avoids a
    needle = f"--to-ports {tor_trans_port}"  # .5 prefix-matching .50/32
    out: list[list[str]] = []
    for line in prerouting_dump.splitlines():
        toks = line.split()
        if toks[:2] == ["-A", "PREROUTING"] and src in line and "-p tcp" in line and needle in line:
            out.append(["iptables", "-t", "nat", "-D", *toks[1:]])
    return out


class LibvirtEgress:
    """Installs / removes a VM worker's per-IP FORWARD egress chain via host iptables.

    A dedicated chain + a single ``FORWARD -s <ip> -j BBVM_<ip>`` jump (inserted at the top so it
    wins for this worker) keeps a co-resident rooter / sibling workers untouched, and ``remove()``
    fully unhooks + flushes + deletes — no orphan rules.
    """

    def __init__(self, *, sudo: bool = True, routing: ExitRouting | None = None) -> None:
        self._pfx = ["sudo"] if sudo else []
        self._routing = routing

    def _priv(self, argv: list[str], check: bool = False) -> subprocess.CompletedProcess:
        cp = _run(self._pfx + argv)
        if check and cp.returncode != 0:
            raise RuntimeError(f"{' '.join(argv)} failed: {cp.stderr.strip()}")
        return cp

    def _ipt_run(self, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        return self._priv(["iptables", *args], check=check)

    def apply(self, worker_ip: str, policy: VmEgressPolicy, gateway: str | None,
              mac: str | None = None) -> None:
        """Install the worker's egress (filter chain + jump + routing + v6 fail-closed).

        Atomic / fail-closed: any failed rule rolls back the whole install via ``remove`` and
        re-raises, so a worker is never left with a half-built (permissive) chain.
        """
        # Fail closed: a routed exit (vpn/tor/inetsim) needs ExitRouting to actually pin the worker's
        # egress through the tunnel/redirect. Without it the FORWARD filter alone would let traffic
        # take the host's default route (its real IP) — a silent deanonymization leak. Refuse rather
        # than install a filter-only policy that looks restrictive but isn't.
        if policy.exit_driver in _ROUTING_DRIVERS and self._routing is None:
            raise ValueError(
                f"exit_driver {policy.exit_driver!r} requires ExitRouting; refusing a leaky "
                "filter-only policy (traffic would egress via the host default route)")
        if policy.exit_driver == "inetsim" and not (self._routing and self._routing.fakenet_addr):
            raise ValueError(
                "exit_driver 'inetsim' requires ExitRouting.fakenet_addr (the FakeNet sink) — "
                "without it nothing is DNATed and traffic egresses via the host default route")
        if policy.exit_driver not in _SUPPORTED_EXITS:
            # socks / httpproxy / anything else have no VM routing path here; the filter chain would
            # otherwise ACCEPT and the worker would get direct host-network egress. Fail closed.
            raise ValueError(
                f"exit_driver {policy.exit_driver!r} is not supported by the VM rooter "
                "(no routing path) — refusing to apply a permissive filter")
        chain = _chain_name(worker_ip)
        # clear any prior incarnation; pass this policy's ports so a prior port-scoped tor's per-port
        # REDIRECTs are swept (deployments are homogeneous).
        self.remove(worker_ip, mac=mac, egress_ports=policy.egress_ports)
        try:
            # Install the rooter-style exit ROUTING (nat DNAT/REDIRECT + policy routes) FIRST — before
            # the FORWARD jump goes live — so an inetsim/tor/vpn worker's traffic is already steered to
            # the sink/tor/tunnel the instant the filter jump is hooked. Otherwise the per-worker
            # FORWARD chain (which ACCEPTs for inetsim) would briefly let traffic out the host route
            # before the DNAT exists (L460). Routing decides WHERE traffic goes; the filter chain below
            # decides WHAT's allowed — wiring the destination first leaves no clearnet window.
            if self._routing is not None:
                for cmd in routing_commands(worker_ip, policy.exit_driver, self._routing,
                                            policy.egress_ports, policy.block_internal):
                    self._priv(cmd, check=True)
            self._ipt_run("-N", chain, check=True)
            # Kill-switch interface for a tunneled exit: the local tun for an on-host VPN, or the leg
            # for next-hop/shared-router mode (the worker's traffic must leave via the router's leg).
            egress_if = None
            if policy.exit_driver in ("openvpn", "wireguard") and self._routing is not None:
                egress_if = (self._routing.leg
                             if (self._routing.gateway and self._routing.leg)
                             else self._routing.vpn_tun)
            sink_addr = (self._routing.fakenet_addr
                         if (policy.exit_driver == "inetsim" and self._routing is not None) else None)
            for body in forward_chain_rules(worker_ip, policy, gateway, egress_if, sink_addr):
                self._ipt_run(*body, check=True)
            # hook at the TOP of FORWARD so the worker's policy is evaluated before generic rules
            self._ipt_run("-I", "FORWARD", "1", "-s", worker_ip, "-j", chain, check=True)
            # ANTI-SPOOF (inserted above the jump): a sample with guest admin/root could re-IP the VM
            # to dodge the per-IP jump + policy routes above. Drop any forwarded packet from this
            # worker's MAC whose source is NOT its assigned IP, so it can't egress around the policy.
            if mac:
                self._ipt_run("-I", "FORWARD", "1", "-m", "mac", "--mac-source", mac,
                              "!", "-s", worker_ip, "-j", "DROP", check=True)
                # COMPLEMENT: a co-resident VM with a DIFFERENT mac that spoofs worker_ip would
                # otherwise match the `-s worker_ip` jump + the `ip rule from worker_ip` and borrow
                # this worker's VPN/tor/direct policy. Drop worker_ip sourced from a non-matching MAC.
                self._ipt_run("-I", "FORWARD", "1", "-s", worker_ip, "-m", "mac",
                              "!", "--mac-source", mac, "-j", "DROP", check=True)
            # host-INPUT chain: traffic the guest sends to a host-local addr (bridge resolver, tor/
            # FakeNet redirect targets) is delivered via INPUT and bypasses the FORWARD filter above;
            # this governs it with the same dedicated-chain + single -s jump model (see
            # input_chain_rules). Anti-spoof + v6 drop get INPUT copies too, for parity with FORWARD.
            in_chain = _input_chain_name(worker_ip)
            self._ipt_run("-N", in_chain, check=True)
            for body in input_chain_rules(worker_ip, policy, gateway, self._routing):
                self._ipt_run(*body, check=True)
            self._ipt_run("-I", "INPUT", "1", "-s", worker_ip, "-j", in_chain, check=True)
            if mac:
                self._ipt_run("-I", "INPUT", "1", "-m", "mac", "--mac-source", mac,
                              "!", "-s", worker_ip, "-j", "DROP", check=True)
                self._ipt_run("-I", "INPUT", "1", "-s", worker_ip, "-m", "mac",
                              "!", "--mac-source", mac, "-j", "DROP", check=True)  # sibling-spoof drop
            # (exit routing was installed at the TOP of this try, before the FORWARD jump — see L460.)
            # IPv6 fail-closed: the filter/routing above is IPv4-only, so drop ALL forwarded v6 from
            # the worker (matched on its MAC) — a v6-capable guest must not egress around the policy.
            if mac:
                # Insert at the HEAD of FORWARD + INPUT (like the IPv4 jumps) so it beats any
                # permissive IPv6 ACCEPT already in those chains — appending could let v6 slip past.
                self._v6_drop("FORWARD", mac)
                self._v6_drop("INPUT", mac)
        except Exception:
            self.remove(worker_ip, mac=mac, egress_ports=policy.egress_ports)  # roll back fail-closed
            raise

    def remove(self, worker_ip: str, exit_driver: str | None = None, mac: str | None = None,
               egress_ports: tuple[int, ...] | None = None) -> None:
        # Tear down routing for EVERY driver (a prior incarnation on this IP may have used a different
        # exit), so no orphan nat/policy-route rule survives an exit-driver switch on a reused IP.
        # egress_ports lets a port-scoped tor's per-port REDIRECTs be swept by del-by-match.
        if self._routing is not None:
            for drv in _ROUTING_DRIVERS:
                # block_internal=True unconditionally so the tor internal-net RETURNs are swept even
                # when this defensive teardown has no policy (del-by-match no-ops if absent).
                for cmd in routing_teardown_commands(worker_ip, drv, self._routing, egress_ports,
                                                     block_internal=True):
                    self._priv(cmd)  # best-effort: del-by-match, ignore "not found"
            self._sweep_tor_tcp_redirects(worker_ip)  # orphan REDIRECTs left by a prior port set
            self._sweep_fakenet_dnat(worker_ip)       # orphan DNATs left by a changed sink address
            self._sweep_ip_rules(worker_ip)           # orphan policy routes left by changed routing
        if mac:
            self._priv(["ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
            self._priv(["ip6tables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
            self._priv(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac,
                        "!", "-s", worker_ip, "-j", "DROP"])  # anti-spoof teardown (FORWARD)
            self._priv(["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac,
                        "!", "-s", worker_ip, "-j", "DROP"])  # anti-spoof teardown (INPUT)
            self._priv(["iptables", "-D", "FORWARD", "-s", worker_ip, "-m", "mac",
                        "!", "--mac-source", mac, "-j", "DROP"])  # sibling-spoof teardown (FORWARD)
            self._priv(["iptables", "-D", "INPUT", "-s", worker_ip, "-m", "mac",
                        "!", "--mac-source", mac, "-j", "DROP"])  # sibling-spoof teardown (INPUT)
        chain = _chain_name(worker_ip)
        while self._ipt_run("-D", "FORWARD", "-s", worker_ip, "-j", chain).returncode == 0:
            pass
        self._ipt_run("-F", chain)
        self._ipt_run("-X", chain)
        in_chain = _input_chain_name(worker_ip)
        while self._ipt_run("-D", "INPUT", "-s", worker_ip, "-j", in_chain).returncode == 0:
            pass
        self._ipt_run("-F", in_chain)
        self._ipt_run("-X", in_chain)

    def _v6_drop(self, chain: str, mac: str) -> None:
        """Install the IPv6 fail-closed DROP for this worker's MAC at the head of ``chain``.

        RAISES on a real rule rejection — a working v6 firewall that REFUSED the rule means the v6
        bypass is live and unguarded, so finalize must fail closed (reap), not silently proceed (the
        old best-effort behaviour). A host with no IPv6 filter table at all (worker nets are v4-only
        by design; nothing to bypass) is tolerated with a warning. A missing ip6tables BINARY raises
        from subprocess and is caught by apply()'s rollback — also fail-closed."""
        cp = self._priv(["ip6tables", "-I", chain, "1", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        if cp.returncode == 0:
            return
        err = (cp.stderr or "").lower()
        # benign ONLY when the host has no usable IPv6 filter TABLE/stack — there is no v6 path to
        # bypass, so don't reap every worker over it. A narrow list: a missing `mac` MATCH extension
        # ("couldn't load match `mac`: no such file...") must NOT be tolerated — the v6 drop wouldn't
        # install while the guest may still have working IPv6, so that case raises (fail closed).
        benign = ("table does not exist", "can't initialize", "address family not supported")
        if not any(b in err for b in benign):
            raise RuntimeError(f"ip6tables {chain} v6 fail-closed DROP failed (rc={cp.returncode}): "
                               f"{(cp.stderr or '').strip()[:160]}")
        logger.warning("ip6tables %s v6 DROP not installed (%s) — host has no IPv6 filter stack; "
                       "worker nets are v4-only by design", chain, err.strip()[:80] or "rc!=0")

    def _sweep_tor_tcp_redirects(self, worker_ip: str) -> None:
        """Delete EVERY live nat-PREROUTING TCP REDIRECT this worker has into tor's TransPort, so an
        orphan left by a prior incarnation with a different ``egress_ports`` (catch-all ↔ port-scoped)
        can't survive a reused DHCP IP and bypass the new allow-list. Best-effort; no-op without
        routing or if the dump fails."""
        if self._routing is None:
            return
        cp = self._ipt_run("-t", "nat", "-S", "PREROUTING")
        if cp.returncode != 0:
            return
        for argv in _tor_redirect_deletes(worker_ip, self._routing.tor_trans_port, cp.stdout):
            self._priv(argv)

    def _sweep_ip_rules(self, worker_ip: str) -> None:
        """Delete EVERY live ``ip rule`` selecting ``from <worker_ip>``, whatever table/priority a
        prior incarnation installed — so a reused DHCP IP can't keep a stale policy route to an old
        VPN table after ExitRouting changed. Best-effort; no-op without routing or on a dump fail."""
        if self._routing is None:
            return
        cp = self._priv(["ip", "rule", "show"])
        if cp.returncode != 0:
            return
        for argv in _ip_rule_deletes(worker_ip, cp.stdout):
            self._priv(argv)

    def _sweep_fakenet_dnat(self, worker_ip: str) -> None:
        """Delete EVERY live nat-PREROUTING DNAT this worker has, so an orphan from a prior inetsim
        incarnation whose sink address has since changed can't survive a reused DHCP IP and keep
        sending traffic to the old FakeNet sink. Best-effort; no-op without routing or on a dump fail."""
        if self._routing is None:
            return
        cp = self._ipt_run("-t", "nat", "-S", "PREROUTING")
        if cp.returncode != 0:
            return
        for argv in _fakenet_dnat_deletes(worker_ip, cp.stdout):
            self._priv(argv)

    def installed(self, worker_ip: str) -> bool:
        return self._ipt_run("-L", _chain_name(worker_ip)).returncode == 0
