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
    expired_peers,
    CHAIN_EXIT,
    CHAIN_FWD,
    PRIO_BLACKHOLE,
    PRIO_LOOKUP,
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
    persistence_unit,
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
    """Run a command. A MISSING BINARY is a normal outcome here, not an exception.

    ``check=False`` suppresses a non-zero exit but not ``FileNotFoundError``, and only
    ``_ok`` wrapped that. So teardown on a host without ``systemctl`` raised out of
    ``teardown_node`` after the rules were already gone but BEFORE the env file was
    removed — leaving the dispatch gate armed on a node with no tier.
    """
    try:
        return subprocess.run(
            list(argv), check=check, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(list(argv), 127, "", f"{exc.strerror}: {argv[0]}")


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
    """Every prefix this host routes, plus every address it actually holds, as a /32.

    THIS IS A SAFETY REQUIREMENT, NOT A REFINEMENT. Allocating a bridge over the
    management LAN or an existing VPN route would cut the node off.

    Both forms are emitted deliberately. A summary prefix alone is not enough: an
    interface configured ``10.0.12.34/8`` — the classic flat-10 lab — yields only
    ``10.0.0.0/8``, which :data:`~blastbox.host.egress.SUMMARY_PREFIXLEN` treats as
    advisory, so the allocator would happily take ``10.0.0.0/16`` and swallow the node's
    own address, its default gateway and the operator's ssh peer. The bare host /32 is
    NOT advisory, so it blocks exactly the candidate containing it while still letting
    the rest of a flat /8 be used. Default-route gateways are captured for the same
    reason: ``dst`` is the string ``default`` there, so without this their address is
    never claimed at all.
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
            if isinstance(dst, str) and dst != "default":
                out.append(dst if "/" in dst else f"{dst}/32")
            # Next hops are real, occupied addresses even when dst is "default".
            for key in ("gateway", "prefsrc"):
                gw = row.get(key)
                if isinstance(gw, str) and ":" not in gw:
                    out.append(f"{gw}/32")
            for a in row.get("addr_info", []) or []:
                if a.get("family") == "inet" and a.get("local"):
                    out.append(f"{a['local']}/{a.get('prefixlen', 32)}")
                    out.append(f"{a['local']}/32")
    return out


class HostFactsUnavailable(RuntimeError):
    """We cannot enumerate what this host already uses, so we must not allocate.

    ``host_route_cidrs`` returning nothing is indistinguishable between "this host routes
    nothing" (impossible) and "`ip` is not installed / not on PATH under sudo". Allocating
    on an empty claimed set is precisely how a bridge lands on the management LAN and cuts
    the node off — the failure the /32 emission exists to prevent. Refuse instead.
    """


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


def _rules_at(rules: str, priority: int) -> list[str]:
    """EVERY ``ip rule`` body at ``priority`` — a priority is not unique.

    Returning only the first match was a live misreport: a host carrying a leftover rule
    at the same preference (an earlier experiment, another tool, a previous version of
    this tier) had its correct rule shadowed and the node was declared uncontained while
    fully enforced. Anchoring to the priority is still necessary — the same body below
    ``32766: from all lookup main`` provides no containment — but the anchor selects a
    SET, not a single line.
    """
    out: list[str] = []
    for line in (rules or "").splitlines():
        head, sep, body = line.partition(":")
        if sep and head.strip().isdigit() and int(head.strip()) == priority:
            out.append(" ".join(body.split()))
    return out


#: iptables match tokens this predicate understands well enough to reason about. A rule
#: using anything else is not analysed — see :func:`_accepts_our_traffic`.
_UNDERSTOOD_MATCHES = frozenset({
    "-A", "FORWARD", "-j", "ACCEPT", "-s", "-i", "-o", "-d",
    "-m", "conntrack", "--ctstate", "state", "--state",
})


def _accepts_our_traffic(rule: str, fwd: str, bridge: str | None = None) -> bool:
    """Would this FORWARD rule terminally accept a NEW outbound packet from the forwarder?

    ACCEPT in a jumped-to chain ends filter traversal, so such a rule reached BEFORE our
    jump makes the WAN-escape DROP dead code.

    THE DEFAULT IS INVERTED ON PURPOSE, AND THAT IS THE WHOLE DESIGN. Four review rounds
    went into this one predicate, each finding another piece of iptables syntax the
    previous version mis-parsed — negated matches (``! --ctstate``, ``! -s``), interface
    wildcards (``-i br+``) — and every miss failed OPEN, reporting a buried chain as
    fine. Trying to enumerate the ways a rule can be harmless is a losing game against a
    matcher with negation, wildcards and arbitrary extension modules.

    So: a rule buries us UNLESS it is one of a few shapes this function fully and exactly
    understands. Unknown syntax, any negation, any wildcard — all count as burying. The
    cost of a false positive is a node reported uncontained (degraded, deferred work,
    loud); the cost of a false negative is malware egressing the analyst's own WAN while
    the check says OK. Those are not comparable, so do not "simplify" this back into
    proving safety.
    """
    if "-j DOCKER-FORWARD" in rule or "-j DOCKER-ISOLATION" in rule:
        return True
    if not rule.rstrip().endswith("-j ACCEPT"):
        return False

    tokens = rule.split()
    # Negation anywhere: not analysed.
    if "!" in tokens or any(t.startswith("!") for t in tokens):
        return True
    # Any match token we do not recognise: not analysed. (Values are skipped by only
    # inspecting tokens that look like flags.)
    for t in tokens:
        if t.startswith("-") and t not in _UNDERSTOOD_MATCHES and not _is_value(t):
            return True

    def val(flag: str) -> str | None:
        try:
            return tokens[tokens.index(flag) + 1]
        except (ValueError, IndexError):
            return None

    # Return traffic only: a NEW outbound connection cannot match it.
    states = val("--ctstate") or val("--state")
    if states and set(states.split(",")) <= {"ESTABLISHED", "RELATED"}:
        return False

    # Ingress is deterministic: our packets enter FORWARD from the forwarder's bridge and
    # no other. A wildcard (`br+`) is not analysed.
    iif = val("-i")
    if bridge and iif and "+" not in iif and iif != bridge:
        return False

    src = val("-s")
    if src:
        try:
            if ipaddress.ip_address(fwd) not in ipaddress.ip_network(src, strict=False):
                return False
        except ValueError:
            return True
    return True


def _is_value(token: str) -> bool:
    """A leading '-' that is part of a VALUE (a negative number, a range) rather than a
    flag. Kept separate so the unknown-flag check above stays readable."""
    return len(token) > 1 and (token[1].isdigit() or token[1] == ".")


def enforcement_present(cfg: EgressConfig) -> tuple[bool, str]:
    """Is this node's egress ENFORCEMENT installed and actually in the path, right now?

    The forwarder's startup gate cannot answer this and must not be trusted to. It pings
    the overlay peer, which lies INSIDE ``overlay_net`` — so the probe matches the
    priority-99 ``to <overlay> lookup main`` rule and is resolved out of the MAIN table
    without the priority-100 source route, the priority-101 blackhole or the BB-WG-FWD
    chain being consulted at all. The gate proves the tunnel is up and nothing more.

    Three things are checked, and each was a false-pass in an earlier version:

    * **The ip rules, anchored to their priority** — see :func:`_rule_at`. The table may
      render as its name or as the bare numeric id (``lookup 220``): ``ensure_rt_table``
      writes the ``/etc/iproute2/rt_tables`` alias, but that is a dpkg conffile an
      iproute2 upgrade can replace fleet-wide. Routing is unaffected either way, so
      insisting on the name would turn a cosmetic file change into a fleet-wide outage.
    * **The FORWARD jump, and its position.** ``iptables -S BB-WG-FWD`` prints only the
      chain's OWN rules — never the jump into it — so checking the chain alone reports a
      fully-enforced node when the jump has been flushed away and the chain is an orphan
      enforcing nothing. Position matters too: docker's DOCKER-FORWARD holds a terminal
      ACCEPT for the non-internal bb-net0 bridge, and ACCEPT in a jumped-to chain ends
      filter traversal, so a jump below it is dead code.
    * **The chain's verdict.** A blanket ACCEPT ahead of the DROP would neuter it.
    """
    if cfg.mode != "global":
        return True, "local mode: the sidecar itself is the enforcement"
    missing: list[str] = []
    # AN EXIT HOST HAS A DIFFERENT SHAPE. It records mode="global" because its peers are
    # global, but it runs no forwarder — it IS the exit. Its containment is the overlay
    # source route plus BB-WG-EXIT, keyed on the overlay prefix rather than a forwarder
    # /32. Checking it for forwarder rules reported the working central host as degraded.
    fwd = cfg.overlay_net if cfg.exit_host else cfg.forwarder_uplink_ip
    chain = CHAIN_EXIT if cfg.exit_host else CHAIN_FWD

    rules = _run(["ip", "rule", "show"], check=False).stdout or ""
    if not any(f"from {fwd}" in r and (f"lookup {cfg.rt_table}" in r
                                       or f"lookup {cfg.rt_table_id}" in r)
               for r in _rules_at(rules, PRIO_LOOKUP)):
        missing.append(f"source route (priority {PRIO_LOOKUP}: from {fwd} -> {cfg.rt_table})")
    if not any(f"from {fwd}" in r and "blackhole" in r
               for r in _rules_at(rules, PRIO_BLACKHOLE)):
        missing.append(f"blackhole fall-through guard (priority {PRIO_BLACKHOLE})")

    # THE FILTER LAYER IS ONLY OBSERVABLE AS ROOT. `ip rule show` works unprivileged;
    # `iptables -S` does not — it exits 4 with "Permission denied". The dispatcher is
    # cap-dropped BY DESIGN (netd exists as a separate privileged helper for exactly that
    # reason), so treating an unreadable filter table as "missing" would report every
    # healthy node as uncontained and defer all of its egress work forever. Distinguish
    # CANNOT OBSERVE from OBSERVED ABSENT: the routing layer above is the primary
    # enforcement and is readable, so a verdict still means something; the filter layer is
    # reported as unverified rather than counted against the node.
    unverified: list[str] = []
    # The bridge our packets enter FORWARD from. Knowing it lets an ACCEPT restricted to
    # some other input interface be excluded instead of condemning the node.
    bridge_iface = iface_for(fwd)
    fwd_probe = _run(["iptables", "-w", "2", "-S", "FORWARD"], check=False)
    if fwd_probe.returncode != 0:
        unverified.append(f"{chain} jump (needs root; `blastbox egress check` as root "
                          "verifies it)")
    else:
        jump_at = docker_at = None
        for i, line in enumerate((fwd_probe.stdout or "").splitlines()):
            if not line.startswith("-A FORWARD"):
                continue
            if line.endswith(f"-j {chain}") and jump_at is None:
                jump_at = i
            # Does this rule swallow OUR traffic before we are reached? Narrowing the
            # last version to "docker jumps only" went too far the other way: an ACCEPT
            # that explicitly matches the forwarder's own source sails past it. Decide by
            # whether the rule could actually match us, not by which chain it names.
            if docker_at is None and _accepts_our_traffic(line, fwd, bridge_iface):
                docker_at = i
        if jump_at is None:
            missing.append(f"FORWARD jump into {chain} (the chain is orphaned)")
        elif docker_at is not None and docker_at < jump_at:
            missing.append(
                f"{chain} is BELOW an earlier ACCEPT in FORWARD (its DROP is dead code)")

        probe = _run(["iptables", "-w", "2", "-S", chain], check=False)
        body = [ln for ln in (probe.stdout or "").splitlines()
                if ln.startswith(f"-A {chain}")]
        if probe.returncode != 0 or not body:
            missing.append(f"{chain} chain")
        elif not body[-1].endswith("-j DROP") or any(
                ln.endswith("-j ACCEPT") and "-o" not in ln for ln in body):
            missing.append(f"{chain} WAN-escape DROP (a blanket ACCEPT precedes it)")

    if missing:
        return False, "enforcement MISSING: " + ", ".join(missing)
    if unverified:
        return True, ("source route and blackhole guard present; unverified: "
                      + ", ".join(unverified))
    return True, "source route, blackhole guard and an in-path WAN-escape DROP all present"


def node_health(cfg: EgressConfig) -> Health:
    """Whether this node can currently egress UNDER ITS POLICY.

    Two independent questions, both of which must hold:

    * **Is the path up?** A ``local``-mode node's exit sidecar is not ours to judge, so we
      only assert the gateway address answers. A ``global``-mode node's forwarder we can
      judge properly, from its own startup gate.
    * **Is containment installed?** Asked separately and from the host, because the
      forwarder's gate structurally cannot answer it (see :func:`enforcement_present`).
      Reporting a node healthy with its source route deleted would hand live malware to a
      node whose traffic exits the analyst's own WAN — the exact outcome this tier exists
      to prevent, dressed as a green check.
    """
    enforced, why = enforcement_present(cfg)
    if not enforced:
        return Health(False, why)
    if cfg.mode == "local":
        reachable = _ok(["ping", "-c1", "-W2", cfg.vpn_gateway_ip])
        return Health(reachable,
                      "exit sidecar reachable at the gateway address" if reachable
                      else f"nothing answers at the gateway address {cfg.vpn_gateway_ip}")
    if cfg.exit_host:
        # NOT a ping. An exit sidecar is a container that may well drop ICMP (the PIA
        # client here does), and judging the central host on that reported a working
        # exit as dead — which, with the dispatch gate wired to this verdict, would
        # have taken the whole fleet's egress work out of circulation. What is both
        # observable and load-bearing is that the sidecar's address still resolves on a
        # link route: that is exactly what the peers' default route depends on.
        on_link = iface_for(cfg.vpn_gateway_ip)
        return Health(bool(on_link),
                      f"exit host: sidecar {cfg.vpn_gateway_ip} on {on_link}; {why}"
                      if on_link else
                      f"exit host: {cfg.vpn_gateway_ip} is not reachable on any link — "
                      "is the exit sidecar running?")
    running, restarts, logs = container_state(cfg.forwarder_name)
    verdict = forwarder_health(running=running, restart_count=restarts,
                               logs_since_start=logs)
    if verdict.healthy:
        return Health(True, f"{verdict.reason}; {why}")
    return verdict


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
    adopted: dict[str, str] = {field_for[n]: v for n, v in existing.items() if n in field_for}
    # ADOPTING A SUBNET MUST CARRY ITS PINNED ADDRESS WITH IT. Replacing vpn_subnet alone
    # while leaving vpn_gateway_ip pointing into the OLD range makes EgressConfig's own
    # validator raise out of the middle of the planner — an uncaught ValueError that the
    # CLI turns into a traceback and the boot unit repeats every 30s forever. Observed on
    # a live node whose bridges had been relocated: "vpn_gateway_ip 172.31.0.10 is not
    # inside vpn_subnet 10.31.0.0/16". The host offset is what is meaningful (the .0.10
    # gateway), not the absolute address, so move it the same way reallocation does.
    for subnet_field, addr_field, old_default in (
            ("vpn_subnet", "vpn_gateway_ip", cfg.vpn_subnet),
            ("net0_subnet", "forwarder_uplink_ip", cfg.net0_subnet)):
        if subnet_field not in adopted:
            continue
        new_net = ipaddress.ip_network(adopted[subnet_field])
        addr = ipaddress.ip_address(getattr(cfg, addr_field))
        if addr in new_net:
            continue
        offset = int(addr) - int(ipaddress.ip_network(old_default).network_address)
        if 0 < offset < new_net.num_addresses - 1:
            adopted[addr_field] = str(new_net.network_address + offset)
        elif new_net.num_addresses > 11:
            # .10 is this tier's convention, but the adopted subnet was created by an
            # OPERATOR, not by docker — a /29 bb-vpn would put .10 outside it and raise
            # the very ValueError this block exists to avoid. Only use it when it fits.
            adopted[addr_field] = str(new_net.network_address + 10)
        else:
            # Too small for the convention: take the first usable host address.
            adopted[addr_field] = str(new_net.network_address + 1)
    if adopted:
        from dataclasses import replace as _replace
        cfg = _replace(cfg, **adopted)  # type: ignore[arg-type]
    # NOTE the adopted ranges stay IN `claimed`. `skip` already stops the allocator
    # re-deciding a live bridge; stripping its range as well would make that address
    # space look FREE and let another bridge be relocated on top of it — docker then
    # rejects the create with the exact "Pool overlaps" error this allocator exists to
    # prevent, and `ensure_bridges` raises CalledProcessError (which the CLI does not
    # catch) rather than a clean message.
    claimed = claimed_cidrs()
    if auto and not host_route_cidrs():
        raise HostFactsUnavailable(
            "cannot read this host's routes (`ip` missing or not permitted), so the "
            "allocator cannot tell which ranges are already in use — it would happily "
            "take the management LAN. Install iproute2, or pass --no-auto-subnets and "
            "set the subnets explicitly.")
    return allocate_subnets(cfg, claimed, auto=auto, skip=frozenset(existing))


def ensure_bridges(cfg: EgressConfig, *, dry_run: bool = False) -> list[str]:
    notes: list[str] = []
    for name, subnet, internal in cfg.bridges:
        if _ok(["docker", "network", "inspect", name]):
            # PRESENT IS NOT ENOUGH. The whole fail-closed property of bb-socks/bb-vpn/
            # bb-fakenet is that docker installs no route off the box for an INTERNAL
            # network. A same-named network created without --internal keeps docker's
            # ordinary host-NAT path, so an inetsim worker egresses directly and a failed
            # netd wiring leaves a live default route — silently, since everything else
            # reports the bridge as present.
            actual = (_run(["docker", "network", "inspect", name, "--format",
                            "{{.Internal}}"], check=False).stdout or "").strip()
            if internal and actual != "true":
                raise RuntimeError(
                    f"{name} exists but is NOT internal — its workers would egress "
                    f"directly, defeating the fail-closed property. Remove it "
                    f"(`docker network rm {name}`) and re-run so it is recreated with "
                    "--internal, after stopping anything attached to it.")
            notes.append(f"{name}: present{' (internal)' if internal else ''}")
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
    # Regenerate the PUBLIC half from the private one if it is missing. An interrupt
    # between the two writes (Ctrl-C, OOM) otherwise left the node permanently wedged:
    # every later gateway/peer/apply died on a bare FileNotFoundError with no hint that
    # deleting the .key was the fix.
    if priv.exists() and priv.stat().st_size and not pub.exists():
        pub.write_text(subprocess.run(
            ["wg", "pubkey"], input=priv.read_text(), text=True,
            capture_output=True, check=True).stdout.strip() + "\n")
        os.chmod(pub, 0o644)
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
    os.chmod(priv, 0o600)  # also correct a key an earlier tool left world-readable
    return priv, pub.read_text().strip()


def _write_conf(path: Path, content: str) -> None:
    old = os.umask(0o077)
    try:
        path.write_text(content)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)


def ensure_rt_table(cfg: EgressConfig) -> None:
    """Register our routing-table alias, refusing to share an ID with anything else.

    Appending `220 bbwg` when 220 is already mapped to another subsystem gives the SAME
    kernel table two names: `ip route replace ... table bbwg` then overwrites that
    subsystem's routes, and teardown later flushes a table we do not own. These are
    exactly the hosts where that happens — a co-resident CAPE rooter writes per-VPN
    tables with operator-chosen numeric IDs.
    """
    RT_TABLES.parent.mkdir(parents=True, exist_ok=True)
    line = f"{cfg.rt_table_id} {cfg.rt_table}"
    existing = RT_TABLES.read_text() if RT_TABLES.exists() else ""
    for raw in existing.splitlines():
        entry = raw.split("#", 1)[0].split()
        if len(entry) < 2:
            continue
        tid, name = entry[0], entry[1]
        if tid == str(cfg.rt_table_id) and name != cfg.rt_table:
            raise RuntimeError(
                f"routing table id {cfg.rt_table_id} is already claimed by {name!r} in "
                f"{RT_TABLES}. Sharing it would overwrite that subsystem's routes and "
                f"teardown would flush them. Set BLASTBOX_EGRESS_RT_TABLE_ID to a free id.")
        if name == cfg.rt_table and tid != str(cfg.rt_table_id):
            raise RuntimeError(
                f"routing table name {cfg.rt_table!r} already maps to id {tid} in "
                f"{RT_TABLES}, not {cfg.rt_table_id}.")
    if line not in existing:
        with RT_TABLES.open("a") as fh:
            fh.write(line + "\n")


def wg_up(cfg: EgressConfig) -> None:
    """Bring the overlay interface up, or raise. Both paths failing is not a warning.

    Discarding the fallback's return code meant `egress gateway`/`peer` printed a public
    key and exited zero while the interface had never started — an operator would go on
    configuring an overlay that does not exist (missing kernel module, invalid config).
    """
    if _ok(["systemctl", "enable", "--now", f"wg-quick@{cfg.wg_iface}"]):
        return
    proc = _run(["wg-quick", "up", cfg.wg_iface], check=False)
    if proc.returncode != 0 and not _ok(["ip", "link", "show", cfg.wg_iface]):
        tail = (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else "no detail"
        raise RuntimeError(f"could not bring up {cfg.wg_iface}: {tail}")


def setup_gateway(cfg: EgressConfig) -> str:
    """Stand up the exit host's overlay endpoint. Returns its public key."""
    _require_wg()
    WG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WG_DIR, 0o700)
    priv, pub = ensure_keypair(cfg.wg_iface)
    conf = WG_DIR / f"{cfg.wg_iface}.conf"
    want = gateway_wg_config(cfg, priv.read_text().strip())
    if not conf.exists():
        _write_conf(conf, want)
    else:
        # RECONCILE the [Interface], KEEP the [Peer] stanzas. Skipping the rewrite meant
        # a changed overlay address or port — or a regenerated keypair — was printed back
        # to the operator while the live interface kept the old values, so newly
        # configured peers could never handshake. Peers are appended by `peer-add` and
        # must survive.
        body = conf.read_text()
        peers = body[body.index("\n# peer:"):] if "\n# peer:" in body else ""
        if body != want + peers:
            _write_conf(conf, want + peers)
            _run(["systemctl", "restart", f"wg-quick@{cfg.wg_iface}"], check=False)
        # It holds a PrivateKey line. A conf left 0644 by a predecessor installer or a
        # restore was never corrected here, and the exit host's key is the one that lets
        # an attacker impersonate the central exit for every peer.
        os.chmod(conf, 0o600)
    wg_up(cfg)
    return pub


def prune_expired_peers(cfg: EgressConfig) -> list[str]:
    """Remove peers whose recorded certificate expiry has passed. Returns their names.

    This is what makes "revocation is stop renewing" real at the overlay. Without it a
    lapsed node keeps its tunnel indefinitely and the short cert lifetime buys nothing.
    Run on every apply on the exit host, so the boot unit enforces it too.
    """
    conf = WG_DIR / f"{cfg.wg_iface}.conf"
    if not conf.exists():
        return []
    body = conf.read_text()
    gone = expired_peers(body)
    if not gone:
        return []
    out, drop, current = [], False, None
    for line in body.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("# peer:"):
            current = stripped[len("# peer:"):].strip()
            drop = current in gone
        if not drop:
            out.append(line)
    _write_conf(conf, "".join(out))
    _run(["systemctl", "restart", f"wg-quick@{cfg.wg_iface}"], check=False)
    return gone


def add_peer(cfg: EgressConfig, name: str, peer_ip: str, public_key: str,
             expires: str | None = None) -> bool:
    """Register a peer on the exit host. Returns False if it was already present.

    Only the peer's PUBLIC key is accepted — the peer generates its own keypair and the
    private half never travels. There is deliberately no option to generate a peer's key
    here.
    """
    conf = WG_DIR / f"{cfg.wg_iface}.conf"
    body = conf.read_text() if conf.exists() else ""
    if f"# peer:{name}\n" in body:
        return False
    stanza = gateway_peer_stanza(name, peer_ip, public_key, expires)
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

def load_persisted_env() -> dict[str, str]:
    """Parse /etc/blastbox/egress.env into a plain mapping.

    The dispatcher arms its health gate on this file's EXISTENCE, so it has to probe with
    this file's CONTENT too. ``EgressConfig.from_env()`` reads ``os.environ``, and nothing
    loads egress.env into a dispatcher's environment — only the egress unit has an
    ``EnvironmentFile=``. Without this the dispatcher probed the class DEFAULTS, which on
    the very node this module exists for (one whose subnets were relocated) means pinging
    an address nothing holds and deferring every egress job forever.
    """
    out: dict[str, str] = {}
    try:
        text = ENV_FILE.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def persisted_config() -> EgressConfig:
    """The node's own persisted egress config, merged with the environment.

    Precedence is deliberately split rather than "file wins" or "env wins":

        legacy bare names  <  /etc/blastbox/egress.env  <  BLASTBOX_EGRESS_*

    The legacy names (``VPN_SUBNET``, ``WG_PORT``, ``NET0_SUBNET`` …) are unnamespaced
    enough to collide with an unrelated shell variable by accident, so a managed node's
    persisted state must outrank them — otherwise a stray export silently redescribes the
    node. An explicit ``BLASTBOX_EGRESS_*`` is unambiguous intent and outranks the file,
    which is what lets an operator inspect or repair without editing it. A dispatcher
    normally sets none of these, so it simply gets the file.
    """
    env = load_persisted_env()
    if not env:
        # ABSENT is not the same as PRESENT-BUT-EMPTY. The dispatch gate arms on the
        # file's existence, so falling back to defaults here gives mode='local' on a
        # managed global node — the gate then skips every global containment check and
        # merely pings the default gateway, where a stale forwarder answering makes a
        # node with no source route and no DROP rules look healthy.
        if ENV_FILE.exists():
            raise ValueError(
                f"{ENV_FILE} exists but is empty or unreadable; this node is marked "
                "managed and its egress configuration cannot be determined")
        return EgressConfig.from_env(None)
    namespaced = {k: v for k, v in os.environ.items() if k.startswith("BLASTBOX_EGRESS_")}
    legacy = {k: v for k, v in os.environ.items() if not k.startswith("BLASTBOX_EGRESS_")}
    return EgressConfig.from_env({**legacy, **env, **namespaced})


def persist_config(cfg: EgressConfig) -> None:
    """Write the EnvironmentFile the persistence unit re-applies from at boot."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text("\n".join([
        "# Written by `blastbox egress apply`. Re-applied at boot by blastbox-egress.service.",
        "# Contains no credentials by design.",
        *cfg.to_env_lines(), "",
    ]))
    os.chmod(ENV_FILE, 0o644)


def install_persistence_unit(cfg: EgressConfig | None = None) -> str:
    """Install the boot-time re-apply unit, pointed at the interpreter that is running.

    Without this the tier is gone after a reboot: ip rules, the routing table and the
    BB-WG-* chains are all runtime state. The node then fails CLOSED (correct) and stays
    that way until a human notices (not correct), so persistence is part of applying.

    The unit text is GENERATED (``egress.persistence_unit``), not read from ``deploy/``.
    A wheel ships no ``deploy/`` tree, so the file-reading version always took its
    "not found" branch on a pip-installed node — the reboot fix was inert on precisely
    the installs that needed it.

    THREE WAYS THIS IS A NO-OP, each of which was a failure first:

    * **Running under systemd.** The unit invokes ``egress apply``, so a blind re-install
      means the unit rewrites itself every boot — and ``ProtectSystem=full`` makes
      /etc/systemd/system read-only, so it does not merely churn, it CRASHES the very
      unit whose job is to restore egress. Detected via ``INVOCATION_ID``.
    * **Content already correct.** Nothing to do.
    * **Read-only or unwritable /etc.** Report it; never fail the apply. The tier is
      applied either way — losing persistence is worth a warning, not an outage.
    """
    if os.environ.get("INVOCATION_ID"):
        return "persistence unit: already managing this run (invoked by systemd)"
    # sys.executable, not `which blastbox`: under sudo the console script is frequently
    # not on PATH (a venv install is the normal case on these nodes), and the fallback
    # silently wrote an ExecStart pointing at a file that does not exist.
    exec_start = f"{sys.executable} -m blastbox.host.cli egress apply"
    body = persistence_unit(exec_start, (cfg or EgressConfig()).wg_iface)
    # "is it ENABLED", not "does the file match". An early return on content alone meant
    # a node whose first `systemctl enable` failed never retried it on any later apply:
    # the unit sat in /etc/systemd/system with no multi-user.target symlink while every
    # apply reported "already installed and current", and reboot persistence — the whole
    # point — was silently absent.
    enabled = _run(["systemctl", "is-enabled", "blastbox-egress"], check=False).returncode == 0
    try:
        if UNIT_DST.exists() and UNIT_DST.read_text() == body and enabled:
            return "persistence unit: already installed and enabled"
        UNIT_DST.parent.mkdir(parents=True, exist_ok=True)
        UNIT_DST.write_text(body)
        os.chmod(UNIT_DST, 0o644)
    except OSError as exc:
        return (f"persistence unit NOT installed ({exc.strerror}); tier applied but "
                "will not survive a reboot")
    _run(["systemctl", "daemon-reload"], check=False)
    rc = _run(["systemctl", "enable", "blastbox-egress"], check=False)
    if rc.returncode != 0:
        # Never claim it. A swallowed enable failure is how a node reports persistent and
        # comes back from a reboot with no enforcement.
        return (f"persistence unit written but NOT ENABLED "
                f"({(rc.stderr or '').strip().splitlines()[-1] if rc.stderr else 'systemctl failed'})"
                " — the tier will not survive a reboot")
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
    # CHECK BEFORE DESTROY. Removing first meant a re-apply on a node whose image tag had
    # been pruned turned a working, gate-passed forwarder into no forwarder at all and
    # then aborted — leaving the gateway address empty. The boot unit retries every 30s,
    # so the destructive half would repeat while the tier stayed down.
    if not _ok(["docker", "image", "inspect", cfg.forwarder_image]):
        raise RuntimeError(
            f"image {cfg.forwarder_image} is missing — build it with:\n"
            f"  docker build -t {cfg.forwarder_image} deploy/egress-forwarder\n"
            "(the running forwarder, if any, was left alone)")
    _run(["docker", "rm", "-f", cfg.forwarder_name], check=False)
    for argv in (forwarder_run_argv(cfg), forwarder_connect_argv(cfg)):
        proc = _run(argv, check=False)
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else "no detail"
            raise RuntimeError(f"could not start the forwarder: {tail}")


def apply_node(cfg: EgressConfig, *, dry_run: bool = False,
               auto_subnets: bool = True) -> tuple[EgressConfig, list[str]]:
    """Bring this node's egress tier to the configured state. Idempotent.

    Ordering is not arbitrary. The node-side source route goes in BEFORE the forwarder
    starts, because the forwarder's startup gate probes across the overlay and will
    (correctly) refuse to run without it.
    """
    notes: list[str] = []
    try:
        plan = plan_subnets(cfg, auto=auto_subnets)
    except ValueError as exc:
        # A config contradiction is an operator-actionable message, not a crash — and the
        # boot unit would otherwise repeat the traceback every 30s.
        raise RuntimeError(f"cannot plan this node's egress: {exc}") from exc
    cfg = plan.config
    for bname, wanted, hit in plan.conflicts:
        notes.append(f"conflict: {bname} wanted {wanted}, taken by {hit}")
    for bname, wanted, chosen in plan.reallocated:
        notes.append(f"reallocated: {bname} {wanted} -> {chosen}")
    # ANY unresolved conflict aborts. The old condition only fired when auto was on AND
    # nothing at all had been reallocated, so --no-auto-subnets proceeded straight into
    # ensure_bridges, and a partial allocation (one conflict resolved, another not) did
    # too. docker does not necessarily reject an overlap with a non-docker host route, so
    # the result can be a connected route over the management LAN.
    unresolved = [c for c in plan.conflicts
                  if c[0] not in {r[0] for r in plan.reallocated}]
    if unresolved:
        detail = "; ".join(f"{b} wants {w}, taken by {h}" for b, w, h in unresolved)
        raise RuntimeError(
            f"unresolved subnet conflict(s): {detail}. "
            + ("Nothing free to relocate to — set the ranges explicitly."
               if auto_subnets else "Re-run without --no-auto-subnets, or set them explicitly."))

    notes += ensure_bridges(cfg, dry_run=dry_run)
    if dry_run:
        return cfg, notes

    ensure_rt_table(cfg)
    if cfg.mode == "local":
        # CONVERGE, do not merely skip. A node previously applied in global mode still
        # has the credential-free forwarder (with a restart policy that revives it at the
        # same gateway address the local sidecar must occupy), plus source-routing rules
        # and BB-WG chains. Leaving them means `apply` does not bring the node to the
        # requested mode and the local exit may be unable to start.
        if _ok(["docker", "inspect", cfg.forwarder_name]):
            _run(["docker", "rm", "-f", cfg.forwarder_name], check=False)
            run_steps(teardown_steps(cfg))
            notes.append("removed stale global-mode state (forwarder, source route, "
                         "BB-WG-* chains) before applying local mode")
    if cfg.mode == "global" and not cfg.exit_host:
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
    if cfg.exit_host:
        pruned = prune_expired_peers(cfg)
        if pruned:
            notes.append(f"pruned expired peers: {', '.join(pruned)} "
                         "(their certs lapsed; re-enrol to restore)")
        # Replay the exit-host role at boot. This is the other half of persistence: the
        # peer side was already covered, but the CENTRAL host's forwarding is what every
        # peer depends on, so losing it on reboot is a fleet-wide outage rather than one
        # node's.
        try:
            notes += apply_exit_host(cfg)
        except RuntimeError as exc:
            notes.append(f"exit-host rules NOT applied ({exc}) — peers cannot egress here")
    persist_config(cfg)
    notes.append(f"config persisted to {ENV_FILE}")
    notes.append(install_persistence_unit(cfg))
    return cfg, notes


def apply_exit_host(cfg: EgressConfig, *, persist: bool = False) -> list[str]:
    """Point peer traffic at this host's local exit sidecar.

    ``persist`` records the exit-host role in egress.env so the boot unit replays it;
    the CLI sets it, the boot-time replay does not (it is already acting on the record).
    """
    eif = iface_for(cfg.vpn_gateway_ip)
    if not eif:
        raise RuntimeError(f"no interface route to {cfg.vpn_gateway_ip} — is the sidecar up?")
    ensure_rt_table(cfg)
    run_steps(exit_host_steps(cfg, eif))
    notes = [f"peer traffic {cfg.overlay_net} -> exit sidecar {cfg.vpn_gateway_ip} via {eif}",
             "everything else from the overlay is DROPped"]
    if persist:
        from dataclasses import replace as _replace
        persist_config(_replace(cfg, exit_host=True))
        notes.append(install_persistence_unit(cfg))
        notes.append("exit-host role recorded — the boot unit will replay these rules")
    return notes


def teardown_node(cfg: EgressConfig, *, remove_bridges: bool = False) -> list[str]:
    notes: list[str] = []
    _run(["docker", "rm", "-f", cfg.forwarder_name], check=False)
    run_steps(teardown_steps(cfg))
    # The exit-host SNAT names the bb-vpn bridge, whose interface teardown_steps cannot
    # know. Resolve it here; without this the rule survived every teardown and a later
    # re-apply stacked a second one naming a bridge that no longer exists.
    eif = iface_for(cfg.vpn_gateway_ip)
    if eif:
        for _ in range(4):
            _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
                  "-s", cfg.overlay_net, "-o", eif, "-j", "MASQUERADE"], check=False)
    notes.append("ip rules, routing table, BB-WG-* chains and SNAT removed (by match)")
    _run(["systemctl", "disable", "--now", f"wg-quick@{cfg.wg_iface}"], check=False)
    _run(["wg-quick", "down", cfg.wg_iface], check=False)
    notes.append(f"{cfg.wg_iface} down; keys left in {KEY_DIR}")
    if remove_bridges:
        for name, _s, _i in cfg.bridges:
            if _ok(["docker", "network", "rm", name]):
                notes.append(f"{name}: removed")
    # DISARM. ENV_FILE is the marker that says "this node's egress is managed": the
    # dispatch gate arms on its existence and the persistence unit's ConditionPathExists
    # keys on it. Leaving it behind means a torn-down node keeps claiming egress jobs and
    # deferring every one of them forever, and the next reboot silently resurrects the
    # tier we just removed.
    _run(["systemctl", "disable", "--now", "blastbox-egress"], check=False)
    try:
        ENV_FILE.unlink()
        notes.append(f"{ENV_FILE} removed; dispatch gate disarmed, boot unit disabled")
    except FileNotFoundError:
        notes.append("no persisted config to remove (dispatch gate was not armed)")
    except OSError as exc:
        notes.append(f"WARNING: could not remove {ENV_FILE} ({exc.strerror}) — the "
                     "dispatch gate stays armed and will defer egress jobs")
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
