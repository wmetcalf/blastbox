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

import subprocess
from dataclasses import dataclass

from blastbox.host.netpolicy import Personality
from blastbox.host.netwire import _INTERNAL_NETS, parse_egress_ports


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


@dataclass(frozen=True)
class ExitRouting:
    """Host-side endpoints for rooter-style exit routing (single-NIC, route-tables + iptables).

    The worker stays on its management network (so the host reaches its agent on the local
    subnet); only its *external* egress is steered per exit driver. Defaults match toolz3's
    CAPE infra (PIA tun0 + ``vpn`` table, FakeNet on br-fakenet)."""

    vpn_table: str = "vpn"          # rt_tables entry whose default route is the VPN tun
    vpn_tun: str = "tun0"           # device to MASQUERADE the worker's source onto
    tor_trans_port: int = 9040      # tor TransPort (transparent TCP)
    tor_dns_port: int = 5353        # tor DNSPort
    fakenet_addr: str | None = None  # FakeNet-NG listen IP (e.g. 172.28.100.1); None disables inetsim
    rule_priority_base: int = 1000  # ip-rule priority = base + low-16-bits of IP (unique per /16)

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


def _rule_priority(worker_ip: str, routing: ExitRouting) -> int:
    # Use the low 16 bits of the IP (third+fourth octets), not just the last octet, so two workers
    # in *different* /24s of the same supernet (or a /16 libvirt net) never share a priority slot.
    o = worker_ip.split(".")
    return routing.rule_priority_base + (int(o[2]) << 8) + int(o[3])


def routing_commands(worker_ip: str, exit_driver: str, routing: ExitRouting) -> list[list[str]]:
    """The privileged argv (``ip``/``iptables`` nat) that *steer* the worker's external egress for
    its exit driver — the rooter half, separate from the FORWARD *filter*. ``direct``/``none``/
    ``drop`` need none (direct = main-table default; none/drop are filter-dropped). Each command is
    idempotently torn down by :meth:`LibvirtEgress.remove` (delete-by-match, no priority guessing)."""
    if exit_driver in ("direct", "none", "drop"):
        return []
    local = ".".join(worker_ip.split(".")[:3]) + ".0/24"  # keep host/agent traffic on the local subnet
    if exit_driver in ("openvpn", "wireguard"):
        prio = _rule_priority(worker_ip, routing)
        if routing.gateway and routing.leg:
            # SHARED-ROUTER / next-hop mode: forward the worker to a router VM on the leg network
            # that holds the VPN. The per-gateway table's default is via that router; many
            # workers/hosts reusing the same router share one VPN link.
            table = str(routing.gateway_table_base + int(routing.gateway.split(".")[-1]))
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
        return [
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-d", local, "-j", "RETURN"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(routing.tor_dns_port)],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(routing.tor_trans_port)],
        ]
    if exit_driver == "inetsim":
        if not routing.fakenet_addr:
            return []
        # everything external → the FakeNet-NG listener (preserving dport); local stays local
        return [
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip, "-d", local, "-j", "RETURN"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-s", worker_ip,
             "-j", "DNAT", "--to-destination", routing.fakenet_addr],
        ]
    return []


def routing_teardown_commands(worker_ip: str, exit_driver: str, routing: ExitRouting) -> list[list[str]]:
    """Inverse of :func:`routing_commands` — ``ip rule del`` + ``iptables -t nat -D`` by exact match."""
    cmds: list[list[str]] = []
    for c in routing_commands(worker_ip, exit_driver, routing):
        if c[:2] == ["ip", "route"]:
            continue  # the shared per-gateway default route is reusable infra — leave it in place
        if c[:2] == ["ip", "rule"]:
            cmds.append(["ip", "rule", "del"] + c[3:])  # del <selector...> (drop the "add")
        else:  # iptables -t nat -A ... -> -D ...
            cmds.append([("-D" if tok == "-A" else tok) for tok in c])
    return cmds


def forward_chain_rules(worker_ip: str, policy: VmEgressPolicy, gateway: str | None) -> list[list[str]]:
    """The ordered ``iptables`` rule bodies (sans ``iptables``) for the worker's dedicated FORWARD
    chain. Order: return-traffic → gateway DNS → block-internal → exit disposition → web allowlist.

    ``gateway`` (the libvirt bridge IP, dnsmasq) is exempted for DNS *before* the internal block so a
    NAT/direct worker can still resolve revocation responders even with ``block_internal``."""
    c = _chain_name(worker_ip)
    r: list[list[str]] = [
        ["-A", c, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    if gateway and policy.exit_driver not in ("none", "drop"):
        # DNS to the bridge resolver only (not arbitrary internal hosts). Skipped for none/drop —
        # a no-egress policy must not leak even DNS.
        r.append(["-A", c, "-d", gateway, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        r.append(["-A", c, "-d", gateway, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    if policy.block_internal:
        r += [["-A", c, "-d", net, "-j", "DROP"] for net in _INTERNAL_NETS]

    if policy.exit_driver in ("none", "drop"):
        r.append(["-A", c, "-j", "DROP"])
        return r

    # direct / openvpn / wireguard / tor: the routing is layered separately; here we filter.
    if policy.egress_ports is not None:
        if 53 in policy.egress_ports:
            r.append(["-A", c, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        for i in range(0, len(policy.egress_ports), 15):  # multiport caps at 15 dports/rule
            chunk = ",".join(str(p) for p in policy.egress_ports[i:i + 15])
            r.append(["-A", c, "-p", "tcp", "-m", "multiport", "--dports", chunk, "-j", "ACCEPT"])
        r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
                  "--log-prefix", "bbvm-egress-drop ", "--log-level", "4"])
        r.append(["-A", c, "-j", "DROP"])
    elif policy.exit_driver == "tor":
        # tor transports TCP (transparent) + DNS only. Without an egress_ports allowlist the worker
        # would otherwise ACCEPT-all here, and non-redirected protocols (QUIC/UDP, raw) would forward
        # straight to clearnet around the REDIRECT. Permit only TCP + DNS; LOG+DROP the rest.
        r.append(["-A", c, "-p", "tcp", "-j", "ACCEPT"])
        r.append(["-A", c, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        r.append(["-A", c, "-m", "limit", "--limit", "10/min", "-j", "LOG",
                  "--log-prefix", "bbvm-egress-drop ", "--log-level", "4"])
        r.append(["-A", c, "-j", "DROP"])
    else:
        # direct / openvpn / wireguard: no port allowlist → permit (NAT/tunnel handles the path)
        r.append(["-A", c, "-j", "ACCEPT"])
    return r


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
        chain = _chain_name(worker_ip)
        self.remove(worker_ip, mac=mac)  # idempotent: clear any prior incarnation (any exit driver)
        try:
            self._ipt_run("-N", chain, check=True)
            for body in forward_chain_rules(worker_ip, policy, gateway):
                self._ipt_run(*body, check=True)
            # hook at the TOP of FORWARD so the worker's policy is evaluated before generic rules
            self._ipt_run("-I", "FORWARD", "1", "-s", worker_ip, "-j", chain, check=True)
            # rooter-style exit routing (policy-route / REDIRECT / DNAT), single-NIC
            if self._routing is not None:
                for cmd in routing_commands(worker_ip, policy.exit_driver, self._routing):
                    self._priv(cmd, check=True)
            # IPv6 fail-closed: the filter/routing above is IPv4-only, so drop ALL forwarded v6 from
            # the worker (matched on its MAC) — a v6-capable guest must not egress around the policy.
            # Best-effort: requires ip6tables (worker nets are v4-only by design, this is belt-and-braces).
            if mac:
                # Insert at the HEAD of FORWARD (like the IPv4 jump) so it beats any permissive
                # IPv6 ACCEPT already in the chain — appending could let v6 slip past a prior accept.
                self._priv(["ip6tables", "-I", "FORWARD", "1", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        except Exception:
            self.remove(worker_ip, mac=mac)  # roll back to fail-closed (no partial chain)
            raise

    def remove(self, worker_ip: str, exit_driver: str | None = None, mac: str | None = None) -> None:
        # Tear down routing for EVERY driver (a prior incarnation on this IP may have used a different
        # exit), so no orphan nat/policy-route rule survives an exit-driver switch on a reused IP.
        if self._routing is not None:
            for drv in _ROUTING_DRIVERS:
                for cmd in routing_teardown_commands(worker_ip, drv, self._routing):
                    self._priv(cmd)  # best-effort: del-by-match, ignore "not found"
        if mac:
            self._priv(["ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        chain = _chain_name(worker_ip)
        while self._ipt_run("-D", "FORWARD", "-s", worker_ip, "-j", chain).returncode == 0:
            pass
        self._ipt_run("-F", chain)
        self._ipt_run("-X", chain)

    def installed(self, worker_ip: str) -> bool:
        return self._ipt_run("-L", _chain_name(worker_ip)).returncode == 0
