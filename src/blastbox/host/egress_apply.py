"""Execute :mod:`blastbox.host.egress` plans against a real host.

Everything that decides *what* to do lives in :mod:`blastbox.host.egress` as pure
functions over validated config; this module is the part that shells out, touches
``/etc`` and talks to docker. Keeping the split sharp is what lets the interesting
logic — subnet allocation, the blackhole guard, the health rule — be unit-tested
without root or a docker daemon.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from blastbox.host.egress import (
    ALL_CHAINS,
    EgressConfig,
    Health,
    Step,
    SubnetPlan,
    allocate_subnets,
    exit_host_steps,
    forwarder_connect_argv,
    forwarder_health,
    forwarder_run_argv,
    forwarder_source_route_steps,
    gateway_peer_stanza,
    gateway_wg_config,
    peer_wg_config,
    teardown_steps,
)

_log = logging.getLogger("blastbox.host.egress")

WG_DIR = Path("/etc/wireguard")
KEY_DIR = WG_DIR / "blastbox"
ENV_FILE = Path("/etc/blastbox/egress.env")
UNIT_SRC_NAME = "blastbox-egress.service"
UNIT_DST = Path("/etc/systemd/system/blastbox-egress.service")
RT_TABLES = Path("/etc/iproute2/rt_tables")


# --------------------------------------------------------------------------------------
# Shelling out
# --------------------------------------------------------------------------------------

def _run(argv, *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv), check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def _ok(argv) -> bool:
    try:
        return _run(argv, check=False).returncode == 0
    except FileNotFoundError:
        return False


@dataclass
class StepResult:
    step: Step
    ran: bool
    ok: bool
    detail: str = ""


def run_steps(steps, *, dry_run: bool = False) -> list[StepResult]:
    """Apply a plan. A guard that succeeds skips its step; ``ignore_fail`` swallows a
    non-zero exit. Anything else that fails aborts — a half-applied egress tier is worse
    than none, because the operator believes it is enforced."""
    out: list[StepResult] = []
    for st in steps:
        if dry_run:
            out.append(StepResult(st, ran=False, ok=True, detail="dry-run"))
            continue
        if st.guard and _ok(st.guard):
            out.append(StepResult(st, ran=False, ok=True, detail="already present"))
            continue
        proc = _run(st.argv, check=False)
        ok = proc.returncode == 0 or st.ignore_fail
        detail = (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else ""
        out.append(StepResult(st, ran=True, ok=ok, detail=detail))
        if not ok:
            raise RuntimeError(f"step failed: {' '.join(st.argv)}\n  {detail}")
    return out


# --------------------------------------------------------------------------------------
# Host facts
# --------------------------------------------------------------------------------------

def docker_network_cidrs() -> list[str]:
    """Every subnet docker already claims on this host."""
    out: list[str] = []
    names = _run(["docker", "network", "ls", "--format", "{{.Name}}"], check=False)
    if names.returncode != 0:
        return out
    for name in names.stdout.split():
        insp = _run(["docker", "network", "inspect", name, "--format",
                     "{{range .IPAM.Config}}{{.Subnet}} {{end}}"], check=False)
        if insp.returncode == 0:
            out.extend(c for c in insp.stdout.split() if c)
    return out


def host_route_cidrs() -> list[str]:
    """Every prefix this host already routes or holds an address in.

    THIS IS A SAFETY REQUIREMENT, NOT A REFINEMENT. Allocating a bridge over the
    management LAN or an existing VPN route would cut the node off — and on these hosts
    the LAN is 172.18/16, squarely inside the first candidate pool the allocator tries.
    An allocator fed only docker's networks will happily pick it.
    """
    out: list[str] = []
    for argv in (["ip", "-j", "route", "show"], ["ip", "-j", "addr", "show"]):
        proc = _run(argv, check=False)
        if proc.returncode != 0:
            continue
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            continue
        for row in rows:
            dst = row.get("dst")
            if isinstance(dst, str) and dst not in ("default",):
                out.append(dst if "/" in dst else f"{dst}/32")
            for a in row.get("addr_info", []) or []:
                if a.get("family") == "inet" and a.get("local"):
                    out.append(f"{a['local']}/{a.get('prefixlen', 32)}")
    return out


def claimed_cidrs() -> list[str]:
    """Everything an allocator must avoid: docker's pools plus the host's own routing."""
    seen: list[str] = []
    for c in [*docker_network_cidrs(), *host_route_cidrs()]:
        try:
            n = str(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
        if n not in seen:
            seen.append(n)
    return seen


def iface_for(target: str) -> str | None:
    """The interface the host would use to reach ``target`` (``ip route get``)."""
    proc = _run(["ip", "-j", "route", "get", target], check=False)
    if proc.returncode != 0:
        return None
    try:
        rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return None
    return rows[0].get("dev") if rows else None


def container_state(name: str) -> tuple[bool, int, str]:
    """``(running, restart_count, logs_since_last_start)``; absent reads as not running.

    The logs are scoped to the CURRENT incarnation via ``--since StartedAt``. Reading the
    whole log would let a gate line from a previous, since-failed start vouch for a
    container that is now crash-looping.
    """
    insp = _run(["docker", "inspect", "-f",
                 "{{.State.Running}} {{.RestartCount}} {{.State.StartedAt}}", name],
                check=False)
    if insp.returncode != 0:
        return False, 0, ""
    parts = insp.stdout.split()
    running = parts[0] == "true" if parts else False
    restarts = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    argv = ["docker", "logs", "--tail", "100"]
    if len(parts) > 2 and parts[2] not in ("", "0001-01-01T00:00:00Z"):
        argv += ["--since", parts[2]]
    logs = _run([*argv, name], check=False)
    return running, restarts, (logs.stdout or "") + (logs.stderr or "")


def node_health(cfg: EgressConfig) -> Health:
    """Whether this node can currently egress under its configured mode.

    A ``local``-mode node's health is its sidecar's, which blastbox does not own — we
    only assert the gateway address answers. A ``global``-mode node's health is the
    forwarder's, and that one we can judge properly.
    """
    if cfg.mode == "local":
        reachable = _ok(["ping", "-c1", "-W2", cfg.vpn_gateway_ip])
        return Health(reachable,
                      "exit sidecar reachable at the gateway address" if reachable
                      else f"nothing answers at the gateway address {cfg.vpn_gateway_ip}")
    running, restarts, logs = container_state(cfg.forwarder_name)
    return forwarder_health(running=running, restart_count=restarts, logs_since_start=logs)


# --------------------------------------------------------------------------------------
# Bridges
# --------------------------------------------------------------------------------------

def plan_subnets(cfg: EgressConfig, *, auto: bool = True) -> SubnetPlan:
    """Resolve the config's bridges against everything already claimed on this host."""
    existing: dict[str, str] = {}
    for name, _subnet, _internal in cfg.bridges:
        insp = _run(["docker", "network", "inspect", name, "--format",
                     "{{range .IPAM.Config}}{{.Subnet}}{{end}}"], check=False)
        if insp.returncode == 0 and insp.stdout.strip():
            existing[name] = insp.stdout.strip()
    # ADOPT what already exists rather than re-deciding it. A live bridge is a fact: its
    # own route is in the host's table, so re-checking it would report the node as
    # conflicted with itself and try to renumber a bridge that has containers on it.
    field_for = {"bb-net0": "net0_subnet", "bb-fakenet": "fakenet_subnet",
                 "bb-socks": "socks_subnet", "bb-vpn": "vpn_subnet"}
    adopted = {field_for[n]: v for n, v in existing.items() if n in field_for}
    if adopted:
        from dataclasses import replace as _replace
        cfg = _replace(cfg, **adopted)
    claimed = [c for c in claimed_cidrs() if c not in existing.values()]
    return allocate_subnets(cfg, claimed, auto=auto, skip=frozenset(existing))


def ensure_bridges(cfg: EgressConfig, *, dry_run: bool = False) -> list[str]:
    notes: list[str] = []
    for name, subnet, internal in cfg.bridges:
        if _ok(["docker", "network", "inspect", name]):
            notes.append(f"{name}: present")
            continue
        argv = ["docker", "network", "create", "--subnet", subnet]
        if internal:
            argv.append("--internal")
        argv.append(name)
        if dry_run:
            notes.append(f"{name}: would create {subnet}")
            continue
        _run(argv)
        notes.append(f"{name}: created {subnet}{' (internal)' if internal else ''}")
    return notes


# --------------------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------------------

def _require_wg() -> None:
    if shutil.which("wg"):
        return
    if shutil.which("apt-get"):
        _run(["apt-get", "install", "-y", "-qq", "wireguard-tools"], check=False)
    if not shutil.which("wg"):
        raise RuntimeError("wireguard-tools is not installed and could not be installed")


def ensure_keypair(stem: str) -> tuple[Path, str]:
    """Create (or reuse) a keypair. Returns ``(private_path, public_key)``.

    The private key is written 0600 and never returned, logged or printed; only the
    public half leaves this function, because the far side legitimately needs it.
    """
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)
    priv, pub = KEY_DIR / f"{stem}.key", KEY_DIR / f"{stem}.pub"
    if not priv.exists() or priv.stat().st_size == 0:
        old = os.umask(0o077)
        try:
            priv.write_text(_run(["wg", "genkey"]).stdout.strip() + "\n")
        finally:
            os.umask(old)
        os.chmod(priv, 0o600)
        pub.write_text(
            subprocess.run(["wg", "pubkey"], input=priv.read_text(),
                           text=True, capture_output=True, check=True).stdout.strip() + "\n")
        os.chmod(pub, 0o644)
    return priv, pub.read_text().strip()


def _write_conf(path: Path, content: str) -> None:
    old = os.umask(0o077)
    try:
        path.write_text(content)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)


def ensure_rt_table(cfg: EgressConfig) -> None:
    RT_TABLES.parent.mkdir(parents=True, exist_ok=True)
    line = f"{cfg.rt_table_id} {cfg.rt_table}"
    existing = RT_TABLES.read_text() if RT_TABLES.exists() else ""
    if line not in existing:
        with RT_TABLES.open("a") as fh:
            fh.write(line + "\n")


def wg_up(cfg: EgressConfig) -> None:
    if not _ok(["systemctl", "enable", "--now", f"wg-quick@{cfg.wg_iface}"]):
        _run(["wg-quick", "up", cfg.wg_iface], check=False)


def setup_gateway(cfg: EgressConfig) -> str:
    """Stand up the exit host's overlay endpoint. Returns its public key."""
    _require_wg()
    priv, pub = ensure_keypair(cfg.wg_iface)
    conf = WG_DIR / f"{cfg.wg_iface}.conf"
    if not conf.exists():
        _write_conf(conf, gateway_wg_config(cfg, priv.read_text().strip()))
    wg_up(cfg)
    return pub


def add_peer(cfg: EgressConfig, name: str, peer_ip: str, public_key: str) -> bool:
    """Register a peer on the exit host. Returns False if it was already present.

    Only the peer's PUBLIC key is accepted — the peer generates its own keypair and the
    private half never travels. There is deliberately no option to generate a peer's key
    here.
    """
    conf = WG_DIR / f"{cfg.wg_iface}.conf"
    body = conf.read_text() if conf.exists() else ""
    if f"# peer:{name}\n" in body:
        return False
    stanza = gateway_peer_stanza(name, peer_ip, public_key)
    _write_conf(conf, body + stanza)
    _run(["systemctl", "restart", f"wg-quick@{cfg.wg_iface}"], check=False)
    return True


def setup_peer(cfg: EgressConfig, peer_ip: str, gateway_addr: str, gateway_pubkey: str) -> str:
    """Stand up a worker node's overlay endpoint. Returns its public key to register."""
    _require_wg()
    priv, pub = ensure_keypair(cfg.wg_iface)
    _write_conf(WG_DIR / f"{cfg.wg_iface}.conf",
                peer_wg_config(cfg, priv.read_text().strip(), peer_ip,
                               gateway_addr, gateway_pubkey))
    wg_up(cfg)
    return pub


# --------------------------------------------------------------------------------------
# Whole-node apply
# --------------------------------------------------------------------------------------

def persist_config(cfg: EgressConfig) -> None:
    """Write the EnvironmentFile the persistence unit re-applies from at boot."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text("\n".join([
        "# Written by `blastbox egress apply`. Re-applied at boot by blastbox-egress.service.",
        "# Contains no credentials by design.",
        *cfg.to_env_lines(), "",
    ]))
    os.chmod(ENV_FILE, 0o644)


def install_persistence_unit() -> str:
    """Install the boot-time re-apply unit, pointed at the interpreter that is running.

    Without this the tier is gone after a reboot: ip rules, the routing table and the
    BB-WG-* chains are all runtime state. The node then fails CLOSED (correct) and stays
    that way until a human notices (not correct), so persistence is part of applying,
    not an optional extra step.

    THREE WAYS THIS IS A NO-OP, all of which were failures first:

    * **Running under systemd.** The unit invokes ``egress apply``, so a blind re-install
      means the unit rewrites itself on every boot — and ``ProtectSystem=full`` makes
      /etc/systemd/system read-only, so it does not merely churn, it CRASHES the very
      unit whose job is to restore egress. Detected via ``INVOCATION_ID``.
    * **Content already correct.** Nothing to do, and writing would bump mtime for no
      reason.
    * **Read-only or unwritable /etc.** Report it; never fail the apply. The tier is
      applied either way — losing persistence is worth a warning, not an outage.
    """
    if os.environ.get("INVOCATION_ID"):
        return "persistence unit: already managing this run (invoked by systemd)"
    src = Path(__file__).resolve().parents[3] / "deploy" / "systemd" / UNIT_SRC_NAME
    if not src.exists():
        # Installed from a wheel with no deploy/ tree alongside. Not fatal, but say so
        # rather than silently skipping persistence.
        return (f"persistence unit NOT installed ({UNIT_SRC_NAME} not found; "
                "the tier will not survive a reboot)")
    # Use the RUNNING interpreter, not `which blastbox`. Under sudo the console script is
    # frequently not on PATH (a venv install is the normal case on these nodes), and the
    # fallback silently wrote an ExecStart pointing at a file that does not exist — a
    # unit that looks installed and fails at every boot.
    exec_start = f"{sys.executable} -m blastbox.host.cli egress apply"
    body = "\n".join(
        f"ExecStart={exec_start}" if line.startswith("ExecStart=") else line
        for line in src.read_text().splitlines()
    ) + "\n"
    try:
        if UNIT_DST.exists() and UNIT_DST.read_text() == body:
            return "persistence unit: already installed and current"
        UNIT_DST.parent.mkdir(parents=True, exist_ok=True)
        UNIT_DST.write_text(body)
        os.chmod(UNIT_DST, 0o644)
    except OSError as exc:
        return f"persistence unit NOT installed ({exc.strerror}); tier applied but will not survive a reboot"
    _run(["systemctl", "daemon-reload"], check=False)
    _run(["systemctl", "enable", "blastbox-egress"], check=False)
    return f"persistence unit installed and enabled (ExecStart={exec_start})"


def await_health(cfg: EgressConfig, *, timeout_s: float = 45.0) -> Health:
    """Poll until the node is healthy, or give up.

    The forwarder's startup gate probes across the overlay with retries, so it is
    legitimately not healthy for the first few seconds. Judging immediately after
    starting it reports DEGRADED on a node that is about to be fine — which, with the
    dispatcher gate wired to this verdict, would eject a healthy node from the pool.
    """
    deadline = time.monotonic() + timeout_s
    verdict = node_health(cfg)
    while not verdict.healthy and time.monotonic() < deadline:
        time.sleep(2.0)
        verdict = node_health(cfg)
    return verdict


def start_forwarder(cfg: EgressConfig) -> None:
    """(Re)start the credential-free forwarder at the gateway address."""
    _run(["docker", "rm", "-f", cfg.forwarder_name], check=False)
    if not _ok(["docker", "image", "inspect", cfg.forwarder_image]):
        raise RuntimeError(
            f"image {cfg.forwarder_image} is missing — build it with:\n"
            f"  docker build -t {cfg.forwarder_image} deploy/egress-forwarder")
    _run(forwarder_run_argv(cfg))
    _run(forwarder_connect_argv(cfg))


def apply_node(cfg: EgressConfig, *, dry_run: bool = False,
               auto_subnets: bool = True) -> tuple[EgressConfig, list[str]]:
    """Bring this node's egress tier to the configured state. Idempotent.

    Ordering is not arbitrary. The node-side source route goes in BEFORE the forwarder
    starts, because the forwarder's startup gate probes across the overlay and will
    (correctly) refuse to run without it.
    """
    notes: list[str] = []
    plan = plan_subnets(cfg, auto=auto_subnets)
    cfg = plan.config
    for bridge, wanted, hit in plan.conflicts:
        notes.append(f"conflict: {bridge} wanted {wanted}, taken by {hit}")
    for bridge, wanted, chosen in plan.reallocated:
        notes.append(f"reallocated: {bridge} {wanted} -> {chosen}")
    if plan.conflicts and not plan.reallocated and auto_subnets:
        raise RuntimeError("subnet conflicts with nothing free to relocate to; "
                           "set the ranges explicitly")

    notes += ensure_bridges(cfg, dry_run=dry_run)
    if dry_run:
        return cfg, notes

    ensure_rt_table(cfg)
    if cfg.mode == "global":
        # The bridge the forwarder is reachable on — where its return traffic must go.
        bridge = iface_for(cfg.forwarder_uplink_ip)
        if not bridge:
            raise RuntimeError(
                f"no route to the forwarder address {cfg.forwarder_uplink_ip}; "
                "is the bb-net0 bridge up?")
        run_steps(forwarder_source_route_steps(cfg, bridge))
        notes.append(f"source route: {cfg.forwarder_uplink_ip} -> {cfg.wg_iface} "
                     f"(blackhole behind it; WAN escape dropped)")
        start_forwarder(cfg)
        verdict = await_health(cfg)
        notes.append(f"forwarder: started at {cfg.vpn_gateway_ip} -> overlay {cfg.upstream_gw}"
                     f" ({'gate passed' if verdict.healthy else 'GATE FAILED'})")
    persist_config(cfg)
    notes.append(f"config persisted to {ENV_FILE}")
    notes.append(install_persistence_unit())
    return cfg, notes


def apply_exit_host(cfg: EgressConfig) -> list[str]:
    """Point peer traffic at this host's local exit sidecar."""
    eif = iface_for(cfg.vpn_gateway_ip)
    if not eif:
        raise RuntimeError(f"no interface route to {cfg.vpn_gateway_ip} — is the sidecar up?")
    ensure_rt_table(cfg)
    run_steps(exit_host_steps(cfg, eif))
    return [f"peer traffic {cfg.overlay_net} -> exit sidecar {cfg.vpn_gateway_ip} via {eif}",
            "everything else from the overlay is DROPped"]


def teardown_node(cfg: EgressConfig, *, remove_bridges: bool = False) -> list[str]:
    notes: list[str] = []
    _run(["docker", "rm", "-f", cfg.forwarder_name], check=False)
    run_steps(teardown_steps(cfg))
    notes.append("ip rules, routing table and BB-WG-* chains removed (by match)")
    _run(["systemctl", "disable", "--now", f"wg-quick@{cfg.wg_iface}"], check=False)
    _run(["wg-quick", "down", cfg.wg_iface], check=False)
    notes.append(f"{cfg.wg_iface} down; keys left in {KEY_DIR}")
    if remove_bridges:
        for name, _s, _i in cfg.bridges:
            if _ok(["docker", "network", "rm", name]):
                notes.append(f"{name}: removed")
    return notes


def foreign_forward_rules() -> int:
    """FORWARD rules we did not create — the invariant that proves we left the CAPE
    rooter alone. ``check`` prints it before and after any change."""
    proc = _run(["iptables", "-S", "FORWARD"], check=False)
    if proc.returncode != 0:
        return -1
    return sum(1 for line in proc.stdout.splitlines() if "BB-" not in line)


def check_node(cfg: EgressConfig) -> list[str]:
    rows = [f"mode: {cfg.mode}", f"gateway address: {cfg.vpn_gateway_ip}"]
    for name, subnet, internal in cfg.bridges:
        present = _ok(["docker", "network", "inspect", name])
        rows.append(f"{name}: {'present' if present else 'absent'} "
                    f"({subnet}{', internal' if internal else ''})")
    if cfg.mode == "global":
        running, restarts, logs = container_state(cfg.forwarder_name)
        rows.append(f"forwarder: running={running} restarts={restarts}")
    h = node_health(cfg)
    rows.append(f"health: {'OK' if h.healthy else 'DEGRADED'} — {h.reason}")
    wg = _run(["wg", "show", "interfaces"], check=False)
    rows.append(f"wg interfaces: {(wg.stdout or '').strip() or 'none'}")
    rules = _run(["ip", "rule", "show"], check=False).stdout or ""
    rows.append(f"ip rules referencing {cfg.rt_table}: {rules.count(cfg.rt_table)}")
    rows.append(f"blackhole guards present: {rules.count('blackhole')}")
    chains = _run(["iptables", "-S"], check=False).stdout or ""
    rows.append(f"BB-WG-* chains: {sum(chains.count(c) > 0 for c in ALL_CHAINS)}/4")
    rows.append(f"foreign FORWARD rules (must be unchanged by us): {foreign_forward_rules()}")
    return rows
