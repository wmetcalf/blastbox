"""Libvirt full-VM warm-worker runtime — a snapshot-recycle worker tier.

The container runtimes (runc/runsc/FC/gVisor) run the engine *inside* the worker. Some
engines can't: they validate/detonate against a full guest OS (e.g. a Windows code-signing
validator) and talk to a **guest agent** over the network. This runtime manages such
workers: a copy-on-write **qcow2 overlay off a read-only golden image**, booted under
libvirt, primed once, then frozen with a libvirt **running-state snapshot** (disk + RAM).

The warmth model is the same family as the FC-snapshot / gVisor-C/R tiers, at the full-VM
layer:

  * **Hot path** — a job is just the engine talking to the already-running guest agent over
    `endpoint` (TCP). No boot, no revert. (~0.1-0.5s for the win-validator agent.)
  * **Recycle** — `recycle()` does ``virsh snapshot-revert clean`` (~8s): disk+RAM restored
    to the primed checkpoint, wiping per-job contamination while the agent + any warmed
    caches (CRL/OCSP) survive because they were captured *in* the snapshot. Cheap reset
    between batches, NOT paid per job.
  * **Reprovision** — destroy+undefine+rm overlay → fresh overlay off the golden.

This implements the engine-agnostic :class:`~blastbox.host.pool.SlotRuntime` shape
(``spawn``/``is_ready``/``is_alive``/``reap``) plus a ``recycle`` extension for the
warm-restore reset. The guest transport (how a job is sent to ``slot.endpoint``) is the
engine's concern; this runtime only owns slot lifecycle, readiness, and snapshot-recycle.

Prereqs: ``virsh`` (libvirt), ``qemu-img``, a golden qcow2, and a guest that brings up the
agent on ``agent_port`` at boot. Egress policy for the worker's IP/MAC is applied separately by
the host-side rooter (``libvirt_egress``): per-worker FORWARD/INPUT chains + tor/vpn/inetsim/
fakenet exit steering.

NOT WIRED for the VM tier (container/netns-only today, via ``netd``/``capture``/the cold
dispatcher labels): per-job **pcap capture** and **TLS keydump** (``SSLKEYLOGFILE`` →
GoGoRoboCap decrypt). A VM has no per-worker netns to tcpdump or inject env into; wiring it
would need a netd "tap mode" (capture on the worker's ``vnet*``/bridge filtered by its MAC/IP)
plus guest-side keylog extraction over the agent, or routing the VM through the sslproxy MITM
gateway for gateway-side keys. See the network primitive.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from blastbox.host.pool import SlotState
from blastbox.host.runtime import guest_ca
from blastbox.host.runtime.libvirt_egress import ExitRouting, LibvirtEgress, VmEgressPolicy


logger = logging.getLogger(__name__)


def _run(args: list[str], timeout: float = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")
    except OSError as exc:
        # The helper binary isn't installed (e.g. `sudo` missing with the default config, or `virsh`
        # missing when sudo=False). available() probes through here and must FAIL CLOSED (return a
        # nonzero result → available()=False), not crash runtime selection with a raw FileNotFoundError.
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def _parse_ip_pool(spec: str) -> list[str]:
    """Parse an inclusive IPv4 range ``"A.B.C.D-A.B.C.E"`` into its list of addresses (in order).
    The range MUST fit in a single /16: the MAC is derived from the IP's 3rd+4th octets only, so two
    IPs that differ in octets 1/2 would collapse to the same MAC (duplicate MACs → libvirt/bridge
    conflicts). Reject a multi-/16 pool rather than hand out colliding MACs."""
    start, _, end = spec.partition("-")
    if not end:
        raise ValueError(f"worker_ip_pool must be 'START-END', got {spec!r}")
    s, e = start.strip(), end.strip()
    lo = int(ipaddress.IPv4Address(s))
    hi = int(ipaddress.IPv4Address(e))
    if hi < lo:
        raise ValueError(f"worker_ip_pool END < START: {spec!r}")
    if s.split(".")[:2] != e.split(".")[:2]:
        raise ValueError(f"worker_ip_pool must fit in one /16 (MAC derives from octets 3+4), got "
                         f"{spec!r}")
    return [str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1)]


def _mac_for_ip(prefix: str, ip: str) -> str:
    """Deterministic MAC from the IP's 3rd+4th octets (1:1 within a /16) → no MAC bookkeeping."""
    o = ip.split(".")
    return f"{prefix}:{int(o[2]):02x}:{int(o[3]):02x}"


@dataclass(frozen=True)
class LibvirtVmConfig:
    """How to mint and run one VM worker off a golden image."""

    golden_base: str
    """Read-only qcow2 the overlays are layered on (COW). Never written."""

    overlay_dir: str = "/dev/shm"
    """Where per-worker overlays live (tmpfs for RAM-speed recycle/boot)."""

    agent_port: int = 8765
    """TCP port the in-guest agent listens on — the warm-ready signal + job transport."""

    mem_mb: int = 4096
    vcpus: int = 2
    network: str = "default"
    """libvirt network the worker NIC attaches to."""

    machine: str = "pc"
    emulator: str = ""
    """QEMU binary path for the domain. Default "" OMITS <emulator> so libvirt picks its capabilities
    default — portable across distros (e.g. RHEL/CentOS package qemu-kvm outside /usr/bin). Set an
    explicit path only to pin a specific binary."""
    disk_bus: str = "sata"
    nic_model: str = "e1000"
    nwfilter: str = "clean-traffic"
    """libvirt nwfilter on the worker NIC (default ``clean-traffic``: no-mac/no-ip/no-arp-spoofing).
    The host egress policy keys on the worker's IP + MAC; a guest with root could change BOTH to dodge
    the per-IP jump + MAC anti-spoof and follow the bridge default route. This pins them at the
    libvirt/ebtables layer so they can't. Set to "" to disable (e.g. a host pinning MAC elsewhere)."""
    nwfilter_ip_learning: str = "dhcp"
    """``CTRL_IP_LEARNING`` for the nwfilter's ``no-ip-spoofing`` (only emitted when ``nwfilter`` is
    set AND ``worker_ip_pool`` is unset — assign+enforce pins the IP explicitly instead of learning).
    ``dhcp`` snoops the DHCP exchange to learn the worker IP — RELIABLE for DHCP guests. The libvirt
    default (``any``, learn from the first IP packet) is racy and silently FAILS for some guests (e.g.
    Windows): it learns no IP, so ``no-ip-spoofing`` black-holes ALL unicast and the worker never
    becomes reachable. Set ``any`` for first-packet learning, or "" to omit (libvirt default)."""
    worker_ip_pool: str = ""
    """Opt-in ASSIGN+ENFORCE mode: an inclusive IPv4 range ``"START-END"`` (within ``network``'s DHCP
    range) from which blastbox hands each worker a fixed IP. When set, blastbox: assigns the worker a
    deterministic ``(MAC, IP)``, adds a per-worker libvirt DHCP **reservation** (so the guest gets
    exactly that IP), and pins the IP **explicitly** in ``no-ip-spoofing`` (``CTRL_IP_LEARNING=none`` +
    ``IP=<assigned>``) — no DHCP learning. Stronger than learning: nothing to poison via a rogue DHCP
    reply, and no DHCP lease to expire under snapshot/restore. The reservation is removed + the IP
    freed on reap. Empty ⇒ DHCP-learning mode (above). Each worker gets a distinct IP, so it autoscales
    up to the pool size; size the pool ≥ the engine's ``concurrent_ceiling``."""
    mac_prefix: str = "52:54:00:bb"
    """4-octet OUI prefix for assign+enforce MACs; the last 2 octets are derived from the assigned IP's
    3rd+4th octets (1:1 within a /16), so MAC↔IP is deterministic — no separate MAC bookkeeping."""
    dhcp_server: str = ""
    """Trusted DHCP server IP for the clean-traffic ``DHCPSERVER`` parameter — constrains the guest's
    DHCP to the bridge's dnsmasq so a compromised worker can't run a rogue DHCP server and make
    ``no-ip-spoofing`` learn an attacker-supplied lease (DHCP-learning mode), nor disturb a sibling's
    learning. "" auto-derives ``subnet_prefix + "1"`` (the libvirt default bridge/dnsmasq IP); set
    explicitly for a non-standard network gateway. Only emitted for the ``clean-traffic`` nwfilter."""
    subnet_prefix: str = "192.168.122."
    """DHCP subnet of ``network``; used to resolve the worker IP via the host neigh table."""

    boot_timeout_s: float = 240.0
    """Max wait for the guest to boot + bring the agent up at provision time."""

    snapshot_name: str = "clean"
    sudo: bool = True
    """Prefix virsh/qemu-img/rm with sudo (libvirt usually needs root)."""

    egress_policy: VmEgressPolicy | None = None
    """Optional host-side egress policy applied to the worker's IP at spawn, removed at reap
    (the rooter model — see libvirt_egress). None = no per-worker egress rules (worker reaches
    whatever the libvirt network allows)."""

    gateway: str | None = None
    """Bridge/resolver IP exempted for DNS under ``block_internal``. Defaults to
    ``subnet_prefix + '1'`` (the libvirt default-network gateway) when egress is enabled."""

    exit_routing: ExitRouting | None = None
    """Rooter-style exit routing endpoints (VPN table/tun, tor ports, FakeNet addr). Needed for
    ``exit=openvpn/wireguard/tor/inetsim`` to actually steer egress through the tunnel/sink; ``direct``
    needs none. None = filter only (the exit driver's routing is a no-op)."""

    health_check: Callable[["VmSlot"], bool] | None = None
    """Engine-supplied SMOKE TEST: given a ready slot (use ``slot.endpoint``), return True iff the
    worker is actually functional — not just port-open. For a validator: send a known benign sample
    to the agent and assert the expected verdict; for a renderer: render a known doc and check the
    output. Run BEFORE the clean snapshot (so the warm-restore baseline is known-good) and after each
    recycle. A failed smoke means the slot never goes IDLE (re-checked/reaped) — a booted-but-broken
    worker (corrupt cert store, dead .NET, wedged agent) is never handed a real job. None = port-only."""

    pre_snapshot: Callable[["VmSlot"], None] | None = None
    """Engine hook run AFTER the smoke passes and JUST BEFORE the clean snapshot, to bake transient
    state into the warm baseline. For the cert validator this warms the CRL/OCSP cache (an agent call
    that fetches the common CAs' revocation lists), so every warm-restore inherits a hot cache and
    revocation is served from cache (~tens of ms, no live fetch) rather than re-fetched per job.
    Best-effort: a failure here is logged, not fatal (the worker is already healthy)."""

    on_ready: Callable[["VmSlot"], None] | None = None
    """Engine hook run EVERY time the worker becomes ready — at first finalize (before the smoke +
    snapshot) AND after each snapshot-revert (in ``recycle``) — to correct environment state before
    use. The canonical use is CLOCK SYNC: both a fresh golden boot and a snapshot-revert can leave a
    wrong/frozen guest clock, and the system clock IS the cert-trust decision (validity windows,
    revocation freshness). The engine resets it to host time the CAPE way — an in-guest
    ``SetLocalTime`` to a host-provided 'now' (no qemu-ga / NTP). The runtime also tries
    ``virsh domtime --sync`` post-revert as a best-effort for qemu-ga goldens. Best-effort, not fatal."""

    # --- guest TLS trust anchors (for HTTPS/TLS interception workers) ---------
    trust_anchors: list[str] = field(default_factory=list)
    """CA cert files (host paths) to install into the GUEST trust store at finalize, before the
    clean snapshot, so every warm-restore inherits them. The use case is a TLS-interception worker:
    routing its egress through a FakeNet/mitmproxy sinkhole that MITMs HTTPS only decrypts if the
    guest trusts the interceptor's CA. Requires ``guest_ssh_user`` + ``guest_ssh_key``.
    SECURITY: a MITM CA is a trusted root — NEVER set this on a worker whose job is to *judge* trust
    (a cert validator); it would let anything the CA signs validate. Interception workers only."""
    guest_os: str = "windows"
    """``windows`` (LocalMachine\\Root via Import-Certificate) or ``linux`` (ca-certificates dir)."""
    guest_ssh_user: str | None = None
    guest_ssh_key: str | None = None
    guest_ssh_port: int = 22
    """SSH used to push + install ``trust_anchors`` (and available to engines for guest provisioning)."""

    @property
    def resolved_gateway(self) -> str:
        return self.gateway or (self.subnet_prefix + "1")


# virsh exits rc=1 for BOTH "libvirtd can't be reached" (UNKNOWN — correlated across every slot at
# once, so reading it as death wipes the tier) and "that domain is gone" (CONFIRMED dead). Only the
# stderr distinguishes them, and conflating them either destroys healthy slots (the original #77
# bug) or strands deleted ones forever (its mirror image). Same vocabulary as _destroy_domain's
# benign set, minus "not running" — that is a live domain in a different STATE, not an absent one.
# NB "does not exist"/"failed to get domain", never a bare "not found": `sudo virsh` with virsh
# missing from root's PATH says "virsh: command not found", which is a broken control plane.
_DOMAIN_ABSENT_MARKERS = ("domain not found", "failed to get domain", "does not exist")


def _domain_is_absent(stderr: str) -> bool:
    """True iff libvirt CONFIRMED there is no such domain (vs. failing to answer at all)."""
    low = (stderr or "").lower()
    return any(m in low for m in _DOMAIN_ABSENT_MARKERS)


@dataclass
class VmSlot:
    """One VM worker. Unlike a container Slot this carries a network ``endpoint``
    (the guest agent) rather than control/input/output dirs."""

    slot_id: str
    domain: str
    overlay: str
    agent_port: int
    ip: str | None = None
    mac: str | None = None
    finalized: bool = False   # egress applied + clean snapshot taken (one-time, on first readiness)
    # Reuse the pool's SlotState vocabulary (spawning/warming/idle/assigned/draining) so the state
    # field matches the Slot contract. NOTE: a VmSlot is not a pool.Slot — it carries a network
    # ``endpoint`` instead of the control/input/output dirs. WarmPool drives this runtime fine
    # anyway because it only touches the common state/jobs/slot_id/spawned_at fields (the engine
    # talks to ``endpoint`` over TCP rather than the file handshake); the static types diverge, so
    # vm_compose's WarmPool construction carries a localized arg-type ignore.
    state: SlotState = SlotState.SPAWNING
    jobs: int = 0
    recycles: int = 0
    spawned_at: float = 0.0
    reserved: bool = False  # assign-enforce: THIS spawn created the DHCP reservation (gate teardown)

    @property
    def endpoint(self) -> tuple[str, int] | None:
        return None if self.ip is None else (self.ip, self.agent_port)


class LibvirtVmRuntime:
    """SlotRuntime for libvirt full-VM workers with snapshot-recycle.

    Engine-agnostic: parameterised by a golden image + an agent port. The guest is expected
    to autostart its agent on ``agent_port`` (bake it into the golden as an ONSTART task).
    """

    def __init__(self, config: LibvirtVmConfig) -> None:
        self.cfg = config
        self._bridge_name: str | None = None  # resolved lazily from cfg.network (cached)
        # Assign+enforce IP allocator (opt-in via worker_ip_pool). In-memory free-list + lock; the
        # MAC is derived from the IP (1:1) so there's no separate MAC pool. Stale reservations from a
        # prior (crashed) run are cleared at startup so the pool can't leak across restarts.
        self._ip_pool: list[str] = _parse_ip_pool(config.worker_ip_pool) if config.worker_ip_pool else []
        self._ip_free: list[str] = list(self._ip_pool)
        self._ip_lock = threading.Lock()
        if self._ip_pool:
            self._reconcile_reservations()

    @property
    def assigns_ip(self) -> bool:
        return bool(self._ip_pool)

    def _alloc_ip_mac(self) -> tuple[str, str]:
        with self._ip_lock:
            if not self._ip_free:
                raise RuntimeError(f"worker_ip_pool exhausted ({len(self._ip_pool)} addrs); raise the "
                                   "range or lower concurrent_ceiling")
            ip = self._ip_free.pop(0)
        return ip, _mac_for_ip(self.cfg.mac_prefix, ip)

    def _free_ip(self, ip: str | None) -> None:
        if not ip:
            return
        with self._ip_lock:
            if ip in self._ip_pool and ip not in self._ip_free:
                self._ip_free.append(ip)

    def _reservation_xml(self, mac: str, ip: str) -> str:
        return f"<host mac='{mac}' ip='{ip}'/>"

    def _reserve(self, mac: str, ip: str) -> None:
        """Add a per-worker libvirt DHCP reservation so the guest gets exactly ``ip``. Fail closed:
        a failed reservation must abort the spawn (else the worker DHCPs a different IP and no-ip-
        spoofing, pinned to ``ip``, would black-hole it)."""
        r = self._virsh("net-update", self.cfg.network, "add", "ip-dhcp-host",
                        self._reservation_xml(mac, ip), "--live", "--config")
        if r.returncode != 0:
            raise RuntimeError(f"DHCP reservation add failed for {mac}/{ip}: {(r.stderr or '').strip()}")

    def _unreserve(self, mac: str | None, ip: str | None) -> bool:
        """Delete a DHCP reservation. Returns whether it's GONE — callers must not reuse the IP until
        the delete actually succeeds, else a stale reservation makes the next _reserve() of that IP
        fail (wedging a small pool)."""
        if not (mac and ip):
            return True
        return self._virsh("net-update", self.cfg.network, "delete", "ip-dhcp-host",
                           self._reservation_xml(mac, ip), "--live", "--config").returncode == 0

    def _reconcile_reservations(self) -> None:
        """Reconcile our DHCP reservations with RUNNING domains at startup so the pool never hands a
        new worker an IP a still-running old worker (from a crashed manager) already owns — that would
        put a duplicate MAC/IP on the bridge and let readiness/jobs talk to the wrong, possibly
        contaminated VM. A reservation whose domain is STILL RUNNING is kept and its IP marked in-use
        (removed from the free-list); a reservation with NO running domain is truly stale → deleted.
        Best-effort (a missing virsh just leaves the pool fully free)."""
        running_macs = set()
        for dom in (self._virsh("list", "--name").stdout or "").split():
            for tok in (self._virsh("domiflist", dom).stdout or "").split():
                if tok.lower().startswith(self.cfg.mac_prefix.lower() + ":"):
                    running_macs.add(tok.lower())
        pool = set(self._ip_pool)
        xml = self._virsh("net-dumpxml", self.cfg.network).stdout or ""
        for mac, ip in re.findall(rf"<host mac='({re.escape(self.cfg.mac_prefix)}:[0-9a-fA-F:]+)' "
                                  r"ip='([0-9.]+)'", xml):
            if ip not in pool:
                continue                        # NOT ours — another tier / hand-managed entry that just
                #                                 happens to share the MAC prefix; never touch it.
            if mac.lower() in running_macs or not self._unreserve(mac, ip):
                # live worker owns it (keep reserved), OR the stale delete FAILED (reservation persists)
                # — either way don't hand this IP out, or the next _reserve() would fail on a dup.
                with self._ip_lock:
                    if ip in self._ip_free:
                        self._ip_free.remove(ip)

    # ---- prereq check (fail-closed selection) --------------------------------
    def available(self) -> bool:
        # Probe the golden with the SAME privilege model as spawn (`sudo test -e` when cfg.sudo):
        # libvirt image dirs are commonly root-only, so an unprivileged Path.exists() would falsely
        # report this tier unavailable on a perfectly usable layout.
        if self._sh(["test", "-e", self.cfg.golden_base]).returncode != 0:
            return False
        if _run(self._virsh_argv("version"), timeout=15).returncode != 0:
            return False
        # qemu-img is a hard prerequisite used BEFORE the domain is defined (spawn() creates the COW
        # overlay with `qemu-img create`). Probe it with the same privilege model, else the pool could
        # select this tier on a host that has virsh but not qemu-img and every spawn would fail
        # immediately at overlay creation. Fail closed instead of accepting an unusable tier.
        return self._sh(["qemu-img", "--version"], sudo_tool="qemu-img").returncode == 0

    def _alloc_overlay_name(self) -> tuple[str, str, str]:
        """Allocate a unique ``(sid, domain, overlay_path)`` for a new VM slot.

        16 hex (64 bits), not 8 (32 bits): in a long-running warm pool that reprovisions many slots a
        32-bit name space has a realistic birthday collision, and a collision is DESTRUCTIVE — spawn()
        unconditionally ``_destroy_domain(name)`` + rm's the overlay, so a duplicate ``bbvm-<sid>``
        would tear down a LIVE sibling VM and clobber its pool entry. 64 bits makes that astronomically
        unlikely; the existence re-roll makes the destructive case impossible."""
        overlay_dir = Path(self.cfg.overlay_dir)
        for _ in range(8):
            sid = uuid.uuid4().hex[:16]
            name = f"bbvm-{sid}"
            overlay = str(overlay_dir / f"{name}.qcow2")
            # An existing overlay at this name means a live sibling already owns it — re-roll rather
            # than destroy+overwrite it. (test -e via the privileged runner: the overlay dir may be
            # root-only, so an unprivileged exists() could miss a sibling and falsely accept the name.)
            if self._sh(["test", "-e", overlay]).returncode != 0:
                return sid, name, overlay
        raise RuntimeError("could not allocate a unique VM overlay name after 8 attempts")

    # ---- SlotRuntime ---------------------------------------------------------
    def spawn(self) -> VmSlot:
        """Provision a COW overlay off the golden, define+start the domain, and return a WARMING
        slot IMMEDIATELY. Readiness (agent up) and the one-time finalize (egress + clean snapshot)
        happen in ``is_ready()`` so the ~60s guest boot never blocks the pool's tick loop —
        matching the async-spawn contract of the FC/gVisor runtimes."""
        sid, name, overlay = self._alloc_overlay_name()
        # Assign+enforce: hand this worker a fixed (MAC, IP) and pin it. Allocated BEFORE the try so a
        # pool-exhaustion error doesn't leave a half-built domain; the reservation + explicit pin go in
        # below. slot.ip/mac are known UPFRONT (no DHCP-learn / neigh-resolution race).
        assigned_mac = assigned_ip = None
        if self._ip_pool:
            assigned_ip, assigned_mac = self._alloc_ip_mac()
        slot = VmSlot(slot_id=sid, domain=name, overlay=overlay,
                      agent_port=self.cfg.agent_port, spawned_at=time.time())
        if assigned_ip:
            slot.ip, slot.mac = assigned_ip, assigned_mac

        self._destroy_domain(name)
        self._sh(["rm", "-f", overlay])
        try:  # any failure → reap (no leaked domain/overlay) and re-raise
            if self._sh(["qemu-img", "create", "-f", "qcow2", "-b", self.cfg.golden_base,
                         "-F", "qcow2", overlay], sudo_tool="qemu-img").returncode != 0:
                raise RuntimeError(f"{name}: qemu-img create overlay off {self.cfg.golden_base} failed")
            # 600, NOT 644: the overlay (default in world-readable /dev/shm) accumulates the submitted
            # sample + guest-side state, so a world-readable mode leaks detonation inputs to any local
            # user. libvirt's dynamic DAC ownership chowns the disk to the qemu user on domain start
            # and restores it on stop, so owner-only is sufficient for qemu to read it.
            # CHECK the chmod: it's the only step making the overlay private. If it fails (denied,
            # unsupported fs, timeout) the VM must NOT start with a possibly world-readable overlay in
            # /dev/shm — raise so the spawn try/except reaps + re-raises before virsh define.
            if self._sh(["chmod", "600", overlay]).returncode != 0:
                raise RuntimeError(f"{name}: chmod 600 overlay failed — refusing to start a VM with a "
                                   "possibly world-readable overlay (would leak the sample)")
            # Private 0600 tempfile (random name) for the domain XML, NOT a predictable /tmp/<name>.xml:
            # on a multi-user host another local user could race a predictable path and swap in
            # attacker-controlled XML before `sudo virsh define` reads it (defining a hostile domain
            # with the dispatcher's libvirt privileges). mkstemp gives an unguessable name + 0600;
            # root (virsh) can still read it.
            # Reserve the worker's IP (so it DHCPs exactly that) BEFORE start. Fail-closed: a failed
            # reservation aborts the spawn, since the explicit no-ip-spoofing pin would otherwise
            # black-hole a different DHCP-assigned IP.
            if assigned_ip and assigned_mac:
                self._reserve(assigned_mac, assigned_ip)
                slot.reserved = True   # only WE may delete this reservation (see reap)
            fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix=f"{name}-")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(self._domain_xml(name, overlay, mac=assigned_mac, assigned_ip=assigned_ip))
                if self._virsh("define", xml_path).returncode != 0:
                    raise RuntimeError(f"{name}: virsh define failed")
            finally:
                Path(xml_path).unlink(missing_ok=True)  # don't leave per-spawn XML behind
            if self._virsh("start", name).returncode != 0:
                raise RuntimeError(f"{name}: virsh start failed")
            if not assigned_mac:        # assign-enforce already set slot.mac; else read libvirt's auto MAC
                slot.mac = self._domain_mac(name)
            # NOTE (boot-window residual risk): the guest is on the libvirt network from `start` until
            # is_ready() installs the IP-keyed egress policy (it needs the DHCP-assigned IP first). A
            # pre-boot blanket block was tried and reverted — it had to permit DHCP (else the guest
            # never gets an IP to become ready) and collided with the policy's own MAC rules. The
            # exposure is low here: the golden is trusted and the untrusted sample only arrives as a
            # job AFTER warm+snapshot, so nothing hostile runs during boot. Revisit with a DHCP-aware
            # pre-policy drop if the threat model ever includes an untrusted golden.
            slot.state = SlotState.WARMING
            return slot
        except Exception:
            self.reap(slot)
            raise

    def is_ready(self, slot: VmSlot) -> bool:
        """WARMING→ready check (polled by the pool). On the FIRST readiness, finalize once: apply
        egress + take the ``clean`` snapshot. Thereafter just confirm the agent port is live."""
        if slot.finalized:
            return slot.ip is not None and self._port_up(slot.ip, timeout=2)
        ip = slot.ip or self._ip_for_mac(slot.mac)
        if not (ip and self._port_up(ip, timeout=2)):
            return False
        slot.ip = ip
        # FAIL-CLOSED finalize: if applying egress (or any finalize step) RAISES, the guest is
        # already reachable on the libvirt network — reap it rather than leave a booted, un-firewalled
        # VM running until the warming timeout. (A smoke/snapshot that merely returns False is a
        # transient retry, not an error, so it is NOT reaped.)
        try:
            if self.cfg.egress_policy is not None:
                # Fail closed without a MAC: the anti-spoof + IPv6-drop rules are MAC-matched, so a
                # None mac (e.g. a transient `virsh domiflist` miss) would silently apply a WEAKER
                # egress (a re-IP'ing guest could dodge the per-IP policy, and v6 wouldn't be dropped).
                # Raise so this finalize is reaped rather than warming an under-firewalled VM.
                if not slot.mac:
                    raise RuntimeError(
                        f"{slot.domain}: egress requires the worker MAC for anti-spoof/v6 rules but "
                        "domiflist returned none — refusing to finalize an under-firewalled guest")
                LibvirtEgress(sudo=self.cfg.sudo, routing=self.cfg.exit_routing).apply(
                    ip, self.cfg.egress_policy, self.cfg.resolved_gateway, mac=slot.mac)
            # Correct the clock before the worker is smoked + snapshotted — a fresh golden boot can
            # carry a stale/wrong clock (observed ~7h off), and for a cert validator the clock IS the
            # trust decision, so the baseline must be time-correct. PRIMARY = the libvirt-native
            # `virsh domtime` (qemu-ga, TZ-robust).
            self._sync_time(slot.domain)
            # on_ready runs at EVERY ready transition (finalize + each revert), NOT only as the clock
            # fallback: engines use it for guest-side readiness repair beyond the clock, so it must run
            # even when domtime succeeded (it's also the clock fallback if qemu-ga is down).
            self._on_ready(slot)
            # Install guest TLS trust anchors (e.g. a FakeNet/mitmproxy CA for HTTPS interception)
            # BEFORE the snapshot, so every warm-restore inherits them. Best-effort.
            self._install_trust_anchors(slot)
            # SMOKE before snapshot: only checkpoint a worker that actually validates correctly, so
            # the warm-restore baseline is known-good (port-open alone can hide a broken validator).
            if self.cfg.health_check is not None and not self._smoke(slot):
                logger.warning("%s: smoke test failed pre-snapshot; not ready", slot.domain)
                return False
            # Warm transient state (e.g. CRL/OCSP cache) INTO the snapshot. Best-effort.
            if self.cfg.pre_snapshot is not None:
                try:
                    self.cfg.pre_snapshot(slot)
                except Exception:
                    logger.warning("%s: pre_snapshot hook failed (non-fatal)", slot.domain, exc_info=True)
            # --atomic: all-or-nothing snapshot creation. Without it a failed create can leave partial
            # snapshot metadata/disk state that makes the retry fail on a duplicate name or revert to
            # an incomplete baseline; --atomic guarantees no half-created `clean` snapshot is left.
            if self._virsh("snapshot-create-as", slot.domain, self.cfg.snapshot_name,
                           "warm clean checkpoint", "--atomic").returncode != 0:
                logger.warning("%s: snapshot-create-as failed; retry next tick", slot.domain)
                return False
            slot.finalized = True
            return True
        except Exception:
            logger.warning("%s: finalize failed; reaping fail-closed", slot.domain, exc_info=True)
            self.reap(slot)
            return False

    def _smoke(self, slot: VmSlot) -> bool:
        """Run the engine health_check, treating any exception as unhealthy."""
        try:
            return bool(self.cfg.health_check(slot))  # type: ignore[misc]
        except Exception:
            logger.warning("%s: health_check raised", slot.domain, exc_info=True)
            return False

    def _on_ready(self, slot: VmSlot) -> None:
        """Run the engine's on_ready hook (clock sync etc.) at each ready transition — first finalize
        and post-revert. Non-fatal: a hook failure must not strand the worker."""
        if self.cfg.on_ready is not None:
            try:
                self.cfg.on_ready(slot)
            except Exception:
                logger.warning("%s: on_ready hook failed (non-fatal)", slot.domain, exc_info=True)

    def _install_trust_anchors(self, slot: VmSlot) -> None:
        """Push the configured guest CA trust anchors into the worker over SSH (finalize-time, so the
        warm snapshot captures them). No-op unless ``trust_anchors`` + SSH creds are set. Non-fatal."""
        if not (self.cfg.trust_anchors and self.cfg.guest_ssh_user
                and self.cfg.guest_ssh_key and slot.ip):
            return
        try:
            if not guest_ca.install_trust_anchors(
                slot.ip, self.cfg.trust_anchors,
                user=self.cfg.guest_ssh_user, key_path=self.cfg.guest_ssh_key,
                port=self.cfg.guest_ssh_port, guest_os=self.cfg.guest_os,
            ):
                logger.warning("%s: one or more guest trust anchors failed to install "
                               "(HTTPS interception may not decrypt)", slot.domain)
        except Exception:
            logger.warning("%s: trust-anchor install raised (non-fatal)", slot.domain, exc_info=True)

    def spawn_ready(self, timeout_s: float | None = None) -> VmSlot:
        """Convenience for non-pool callers: spawn() then block until ready (or timeout). The
        WarmPool uses the async spawn()/is_ready() pair instead and never calls this."""
        slot = self.spawn()
        deadline = time.time() + (timeout_s if timeout_s is not None else self.cfg.boot_timeout_s)
        while time.time() < deadline:
            if self.is_ready(slot):
                slot.state = SlotState.IDLE
                return slot
            time.sleep(2)
        self.reap(slot)
        raise RuntimeError(f"{slot.domain}: not ready within {self.cfg.boot_timeout_s:.0f}s")

    def is_alive(self, slot: VmSlot) -> "bool | None":
        """True iff libvirt CONFIRMS the domain is running.

        issue #77: this used to test the stdout substring alone. ``_virsh`` never raises — a
        subprocess timeout returns rc=124, a missing binary rc=127, and a libvirtd connect failure
        rc=1 with the message on STDERR and stdout EMPTY — so every transient local control-plane
        fault read as "not running", and the pool's health check then ``virsh destroy``d healthy
        warm VMs. libvirtd is a single shared daemon, so that fault is correlated across every slot
        at once (a `systemctl restart libvirtd` would wipe the tier). Only a SUCCESSFUL query is
        evidence: on any non-zero rc, keep the slot (unknown, not dead) and let the next tick ask
        again — a genuinely dead domain is still caught then, and at claim time."""
        cp = self._virsh("domstate", slot.domain)
        if cp.returncode != 0:
            if _domain_is_absent(cp.stderr):
                # CONFIRMED gone (deleted out from under us). Not "unknown": keeping it would hold a
                # warm slot that can never be claimed and never be replaced — _spawn_to_deficit
                # counts it, so a warm_size=1 tier would sit dead until the process restarted.
                logger.warning("libvirt.domain_absent domain=%s — reaping slot (confirmed gone)",
                               slot.domain)
                return False
            # UNKNOWN, not True: the pool keeps an unknown slot exactly as before, but reporting
            # it honestly is what lets the pool bound how long that may last. Claiming "alive" here
            # meant a permanently unqueryable libvirtd (a sudoers change, a missing binary) kept a
            # slot alive forever -- never claimable, never replaced (issue #77 marla-loop).
            logger.warning("libvirt.domstate_failed domain=%s rc=%s stderr=%s — reporting UNKNOWN",
                         slot.domain, cp.returncode, (cp.stderr or "").strip()[:160])
            return None
        return "running" in cp.stdout

    def is_alive_for_claim(self, slot: VmSlot, *, budget_s: float | None = None) -> "bool | None":
        """Claim-time check: UNKNOWN (None) when libvirt cannot be queried (issue #77).

        ``is_alive`` keeps such a slot (a virsh/libvirtd blip is not evidence the domain died, and
        destroying healthy warm VMs over it is the worse failure). But the pool falls back to
        ``is_alive`` for the HAND-OUT probe when a runtime has no fresh hook, and there "keep" would
        mean "give this slot to a job" — handing out a VM we cannot confirm is running. Split the
        two: background = keep, hand-out = skip this slot and try another."""
        # Bound virsh by whatever the caller has left on its claim deadline (issue #77 round 2):
        # a wedged libvirtd otherwise blocks the default 90s inside a claim(timeout_s=2). _run maps
        # a timeout to rc=124, which is not an absent-domain marker -> UNKNOWN -> skip, exactly right.
        kw = {} if budget_s is None else {"timeout": max(1.0, float(budget_s))}
        cp = self._virsh("domstate", slot.domain, **kw)
        if cp.returncode != 0:
            if _domain_is_absent(cp.stderr):
                return False   # confirmed gone -> dead, so the pool drops + replaces it
            logger.warning("libvirt.domstate_failed_at_claim domain=%s rc=%s — skipping slot "
                           "(unknown, not dead)", slot.domain, cp.returncode)
            return None
        return "running" in cp.stdout

    def reap(self, slot: VmSlot) -> None:
        slot.state = SlotState.DRAINING
        # Destroy the guest FIRST, while its egress filter is still in place — so there is never a
        # window where a live guest is forwarding with its rules already gone. Only once the VM is
        # confirmed dead do we tear egress down + free the overlay. If destroy FAILS (the guest may
        # still be running), LEAVE the egress rules + overlay in place so it stays contained, and
        # surface it for manual cleanup rather than unconfining a leaked, unmanaged VM.
        if not self._destroy_domain(slot.domain):
            # The guest may still be running. Leave egress + overlay in place (containment) and RAISE
            # so the pool QUARANTINES this slot (keeps it in accounting) instead of treating reap as a
            # success and dropping a live, untracked VM while spawning a replacement.
            raise RuntimeError(
                f"{slot.domain}: virsh destroy failed; guest may still be running — egress + overlay "
                "left in place, slot quarantined for manual cleanup")
        if self.cfg.egress_policy is not None and slot.ip is not None:
            LibvirtEgress(sudo=self.cfg.sudo, routing=self.cfg.exit_routing).remove(
                slot.ip, self.cfg.egress_policy.exit_driver, mac=slot.mac,
                egress_ports=self.cfg.egress_policy.egress_ports)  # unhook AFTER the guest is gone
        # Assign-enforce: the guest is GONE, so drop ITS DHCP reservation + return the IP to the pool.
        # Only delete the reservation if THIS slot created it (slot.reserved) — a spawn whose own
        # _reserve() FAILED (e.g. the IP was already reserved by another live runtime) must NOT delete
        # that other reservation on the except→reap path. The IP is still ours to return to the pool
        # (it came from our allocator). (Only reached on a SUCCESSFUL destroy; a failed destroy raises
        # above + keeps everything in place so a still-running guest's address can't be reused.)
        if self._ip_pool and slot.ip in self._ip_pool:
            # Free the IP for reuse ONLY once its reservation is confirmed gone — a failed delete
            # leaves the reservation, so reusing the IP would make the next _reserve() fail. A
            # not-reserved slot (our _reserve never succeeded) has nothing to delete → free it back.
            if not slot.reserved or self._unreserve(slot.mac, slot.ip):
                self._free_ip(slot.ip)
        # CHECK the overlay rm: a failed remove (perm/busy/immutable/timeout) leaves a stale qcow2
        # holding the sample under /dev/shm, leaking it + consuming tmpfs while replacements spawn.
        # Raise so the pool QUARANTINES the slot (keeps it tracked) and the leaked overlay surfaces.
        if self._sh(["rm", "-f", slot.overlay]).returncode != 0:
            raise RuntimeError(f"{slot.domain}: overlay {slot.overlay} could not be removed — leaked "
                               "qcow2 holds the sample + consumes tmpfs; slot quarantined")

    # ---- snapshot-recycle extension -----------------------------------------
    def recycle(self, slot: VmSlot, ready_timeout_s: float = 60.0) -> None:
        """Warm-restore to the ``clean`` snapshot — discards per-job contamination, keeps the
        agent + caches primed. ~8s; use between batches, not per job.

        Post-revert the guest clock is frozen at snapshot time, so sync it to host time FIRST —
        for a cert validator the system clock IS the trust decision (validity windows, revocation
        freshness). Then confirm the worker is still healthy (smoke) before returning it to IDLE."""
        rv = self._virsh("snapshot-revert", slot.domain, self.cfg.snapshot_name)
        if rv.returncode != 0:
            # The revert FAILED — the guest is still the contaminated post-job VM (its agent port
            # may well still answer). Raise so WarmPool.release() falls back to reap+respawn instead
            # of smoke-checking and returning a dirty slot to IDLE.
            slot.state = SlotState.DRAINING
            raise RuntimeError(
                f"{slot.domain}: snapshot-revert failed (rc={rv.returncode}): {rv.stderr.strip()[:200]}")
        # NB: do NOT reset slot.jobs here — WarmPool owns that counter and uses the cumulative count
        # to enforce max_jobs_per_slot (reap+respawn after M total jobs). Zeroing it would make the
        # reprovision ceiling unreachable. recycles is our own informational tally.
        slot.recycles += 1
        # Sync the clock only AFTER the guest is back on the network: a revert restores the saved
        # RAM state, and qemu-ga's virtio channel (and SSH) take a moment to reconnect — syncing at
        # the instant of revert no-ops and leaves the stale snapshot clock. So wait for the agent
        # port, THEN clock-sync (domtime primary, on_ready fallback), THEN smoke with a correct clock.
        deadline = time.time() + ready_timeout_s
        synced = False
        while time.time() < deadline:
            if slot.ip and self._port_up(slot.ip, timeout=2):
                if not synced:
                    self._sync_time(slot.domain)
                    self._on_ready(slot)   # runs at every revert too (readiness repair, not just clock)
                    synced = True
                if self.cfg.health_check is None or self._smoke(slot):
                    # Do NOT set IDLE here. When WarmPool.release() drives recycle the slot must stay
                    # ASSIGNED until release() republishes it under the pool lock — flipping it to
                    # IDLE mid-recycle would let a concurrent claim grab this VM before release()
                    # finishes (double-claim). The caller owns the IDLE transition; recycle just
                    # returns on success / raises on failure.
                    return
            time.sleep(1)
        slot.state = SlotState.DRAINING
        raise RuntimeError(f"{slot.domain}: not healthy/back {ready_timeout_s:.0f}s after revert")

    def _sync_time(self, domain: str) -> bool:
        """Set the guest clock to the host's real UTC via the QEMU guest agent — the libvirt-native,
        TZ-robust path: qemu-ga sets the guest's UTC system clock, so it's correct for any guest
        timezone. The host must itself hold real time (be NTP-disciplined).

        Uses an EXPLICIT ``virsh domtime --time <host-utc-epoch>``, NOT ``--sync``: ``--sync`` syncs
        the guest to QEMU's emulated RTC, but a ``snapshot-revert`` rolls that RTC back too — so
        ``--sync`` no-ops post-revert (returns rc 0, clock stays stale). Passing the host's current
        epoch explicitly bypasses the restored RTC. Needs qemu-ga in the guest + the
        org.qemu.guest_agent.0 channel (both in the baked golden + the domain XML). Returns True on
        success; False (best-effort, debug-logged) when qemu-ga isn't connected, so callers can fall
        back to the on_ready in-guest clock set."""
        epoch = int(time.time())  # host UTC epoch; host is the real-time source (NTP-disciplined)
        r = self._virsh("domtime", domain, "--time", str(epoch), timeout=20)
        if r.returncode != 0:
            logger.debug("%s: domtime --time unavailable (no qemu-ga); falling back to on_ready hook",
                         domain)
            return False
        return True

    # ---- internals -----------------------------------------------------------
    def _virsh_argv(self, *a: str) -> list[str]:
        return (["sudo"] if self.cfg.sudo else []) + ["virsh", *a]

    def _virsh(self, *a: str, timeout: float = 90) -> subprocess.CompletedProcess:
        return _run(self._virsh_argv(*a), timeout=timeout)

    def _sh(self, args: list[str], sudo_tool: str | None = None) -> subprocess.CompletedProcess:
        return _run((["sudo"] if self.cfg.sudo else []) + args, timeout=600)

    def _destroy_domain(self, name: str) -> bool:
        """Destroy + undefine ``name``. Returns whether the guest is GONE (destroyed, or already
        off/absent). On a non-benign destroy failure the VM may STILL be running, so we do NOT
        undefine it (undefining a live domain leaves it running but unmanaged) and return False so
        the caller keeps it contained."""
        r = self._virsh("destroy", name)
        err = (r.stderr or "").lower()
        # benign: the DOMAIN was already off / already gone (we still undefine to clean metadata).
        # NB "domain not found"/"failed to get domain", NOT a bare "not found" — `sudo virsh` with
        # virsh missing from root's PATH says "virsh: command not found", which is NOT a benign absent
        # domain: treating it benign would let reap() unconfine + orphan a still-running VM.
        benign = ("not running", "domain not found", "failed to get domain", "does not exist")
        if r.returncode != 0 and not any(b in err for b in benign):
            logger.warning("%s: virsh destroy failed (rc=%s): %s — guest may still be running",
                           name, r.returncode, (r.stderr or "").strip()[:160])
            return False
        self._virsh("undefine", name, "--snapshots-metadata")
        return True

    def _domain_mac(self, name: str) -> str | None:
        for line in self._virsh("domiflist", name).stdout.splitlines():
            p = line.split()
            if len(p) >= 5 and ":" in p[-1]:
                return p[-1]
        return None

    def _bridge(self) -> str:
        """The host bridge device for the configured libvirt network (e.g. ``default`` → virbr0).
        Cached. Derived via ``virsh net-info`` so a non-default ``network`` still resolves IPs from
        the right bridge (the neighbour table is per-device)."""
        if self._bridge_name is None:
            self._bridge_name = "virbr0"
            for line in self._virsh("net-info", self.cfg.network).stdout.splitlines():
                if line.lower().startswith("bridge:"):
                    self._bridge_name = line.split(":", 1)[1].strip() or "virbr0"
                    break
        return self._bridge_name

    def _ip_for_mac(self, mac: str | None) -> str | None:
        if not mac:
            return None
        for line in _run(["ip", "neigh", "show", "dev", self._bridge()]).stdout.splitlines():
            p = line.split()
            # Find the lladdr token by NAME, not a fixed index: `ip neigh show dev X` emits
            # "IP lladdr MAC STATE" but some forms include the dev ("IP dev X lladdr MAC STATE").
            if not p or "lladdr" not in p or not p[0].startswith(self.cfg.subnet_prefix):
                continue
            li = p.index("lladdr")
            if li + 1 < len(p) and p[li + 1].lower() == mac.lower():
                return p[0]
        return None

    def _port_up(self, ip: str, timeout: float = 2) -> bool:
        try:
            socket.create_connection((ip, self.cfg.agent_port), timeout=timeout).close()
            return True
        except OSError:
            return False

    def _domain_xml(self, name: str, overlay: str, *,
                    mac: str | None = None, assigned_ip: str | None = None) -> str:
        c = self.cfg
        # virtio-blk attaches directly to the PCI root and has NO controller element — libvirt has no
        # `<controller type='virtio'>` type, so emitting one makes `virsh define` reject the XML and
        # the tier can't spawn. sata/scsi/usb DO take a matching controller; ide is implicit. Only
        # emit a controller for the bus types that have one. virtio disks target vd*, the rest sd*.
        _ctrl = "" if c.disk_bus in ("virtio", "ide") else f"<controller type='{c.disk_bus}' index='0'/>"
        _dev = "vda" if c.disk_bus == "virtio" else "sda"
        _macref = f"<mac address='{mac}'/>" if mac else ""   # assign-enforce: pin the worker MAC
        # DHCPSERVER (clean-traffic only): restrict the guest's DHCP to the trusted bridge dnsmasq so a
        # compromised worker can't rogue-DHCP itself a different lease (which DHCP-learning would then
        # pin) or poison a sibling's learning. Derived from subnet_prefix when not set explicitly.
        _dhcpsrv = ""
        if c.nwfilter == "clean-traffic":
            # Derive the bridge dnsmasq IP from subnet_prefix, tolerating a missing trailing dot
            # ("192.168.122" → "192.168.122.1", not "192.168.1221") so a typo doesn't emit an invalid
            # IP that fails `virsh define`.
            _pfx = (c.subnet_prefix or "").rstrip(".")
            _server = c.dhcp_server or (f"{_pfx}.1" if _pfx else "")
            if _server:
                _dhcpsrv = f"<parameter name='DHCPSERVER' value='{_server}'/>"
        # nwfilter on the worker NIC. ASSIGN-ENFORCE (assigned_ip): pin the IP EXPLICITLY in
        # no-ip-spoofing (CTRL_IP_LEARNING=none + IP=<assigned>) — nothing to learn, so no rogue-DHCP
        # poisoning and no lease to expire. DHCP-LEARNING (no assigned_ip): emit CTRL_IP_LEARNING
        # (default "dhcp") so no-ip-spoofing learns the IP from the DHCP exchange (libvirt's "any"
        # default is racy and black-holes some guests). libvirt only accepts dhcp/any/none — validate
        # up front so a typo fails fast here, not as a cryptic XML-validation error at `virsh define`.
        if c.nwfilter and assigned_ip:
            _filterref = (f"<filterref filter='{c.nwfilter}'>"
                          "<parameter name='CTRL_IP_LEARNING' value='none'/>"
                          f"<parameter name='IP' value='{assigned_ip}'/>{_dhcpsrv}</filterref>")
        elif c.nwfilter and c.nwfilter_ip_learning:
            # DHCP-learning path (no assigned IP). 'none' is only valid WITH an explicit IP (the
            # assign-enforce branch above supplies it) — emitting CTRL_IP_LEARNING=none here, where
            # no-ip-spoofing has no IP, is a libvirt define error. Only dhcp/any learn an IP.
            if c.nwfilter_ip_learning not in ("dhcp", "any"):
                raise ValueError(
                    f"Invalid nwfilter_ip_learning {c.nwfilter_ip_learning!r} without worker_ip_pool; "
                    "must be 'dhcp', 'any', or '' (omit). 'none' needs an assigned IP (worker_ip_pool).")
            _filterref = (f"<filterref filter='{c.nwfilter}'>"
                          f"<parameter name='CTRL_IP_LEARNING' value='{c.nwfilter_ip_learning}'/>"
                          f"{_dhcpsrv}</filterref>")
        elif c.nwfilter:
            _filterref = f"<filterref filter='{c.nwfilter}'/>"
        else:
            _filterref = ""
        return (
            "<domain type='kvm'>"
            f"<name>{name}</name>"
            f"<memory unit='MiB'>{c.mem_mb}</memory><currentMemory unit='MiB'>{c.mem_mb}</currentMemory>"
            f"<vcpu placement='static'>{c.vcpus}</vcpu>"
            f"<os><type arch='x86_64' machine='{c.machine}'>hvm</type><boot dev='hd'/><bootmenu enable='no'/></os>"
            "<features><acpi/><apic/></features>"
            "<cpu mode='host-passthrough' check='none' migratable='on'/>"
            "<clock offset='localtime'><timer name='rtc' tickpolicy='catchup'/>"
            "<timer name='pit' tickpolicy='delay'/><timer name='hpet' present='no'/></clock>"
            "<on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>"
            # Omit <emulator> by default so libvirt uses its capabilities default (portable across
            # distros that package qemu outside /usr/bin); emit it only when explicitly pinned.
            f"<devices>{f'<emulator>{c.emulator}</emulator>' if c.emulator else ''}"
            "<disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/>"
            f"<source file='{overlay}'/><target dev='{_dev}' bus='{c.disk_bus}'/></disk>"
            f"{_ctrl}"
            f"<interface type='network'>{_macref}<source network='{c.network}'/><model type='{c.nic_model}'/>"
            # clean-traffic nwfilter: pin MAC + IP (no-mac/no-ip/no-arp-spoofing) at the libvirt
            # ebtables layer so a root guest can't change them to escape the IP/MAC-keyed host policy.
            # CTRL_IP_LEARNING=dhcp: snoop DHCP to learn the worker IP reliably — without it (libvirt's
            # racy "any" default) no-ip-spoofing can learn NO IP and black-hole all unicast (the worker
            # then never becomes reachable; seen with Windows guests).
            f"{_filterref}</interface>"
            "<serial type='pty'><target type='isa-serial' port='0'/></serial><console type='pty'/>"
            # QEMU guest-agent channel — enables `virsh domtime --sync` (post-revert clock sync) +
            # in-guest exec; needs qemu-ga running in the golden.
            "<channel type='unix'><source mode='bind'/>"
            "<target type='virtio' name='org.qemu.guest_agent.0'/></channel>"
            "<input type='tablet' bus='usb'/><input type='keyboard' bus='ps2'/>"
            "<graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>"
            "<video><model type='vga' vram='16384' heads='1'/></video><memballoon model='none'/></devices></domain>"
        )
