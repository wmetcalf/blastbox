"""Execute :mod:`blastbox.host.worker_link` plans on the dispatcher host.

The decisions (validation, allocation, the ruleset, the bundle) are pure functions in
:mod:`blastbox.host.worker_link`. This module does the shelling out, and it reuses the egress
tier's WireGuard plumbing -- :func:`~blastbox.host.egress_apply.conf_lock`,
``_reload_wg``, ``wg_up``, ``ensure_keypair``, the ``# peer:`` block helpers -- rather than
a second copy of each. Every one of those was hardened by a failure (a lost enrolment, a
reload that silently did nothing, a key left world-readable), and a second copy would have to
relearn them. They take anything with ``wg_iface`` and ``overlay_net``; nothing they do is
egress-specific. What IS egress-specific -- iptables chains, ``ip rule``s, the routing table,
the egress units -- is never called from here, and the tests assert that.

Every command goes through ``egress_apply._run``/``_ok`` (argv lists, never a shell), so a
test can patch one seam and see everything this module would have run.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
from dataclasses import replace
from pathlib import Path

from blastbox.host import egress_apply as ea
from blastbox.host.worker_link import (
    FW_UNIT_NAME,
    NFT_TABLE,
    JoinBundle,
    WorkerLinkConfig,
    firewall_in_force,
    firewall_unit,
    host_firewall_nft,
    host_wg_config,
    link_peer_stanza,
    next_free_ip,
    reassert_units,
)

ENV_FILE = Path("/etc/blastbox/worker-link.env")
FW_FILE = Path("/etc/blastbox/worker-link.nft")
FW_UNIT = Path("/etc/systemd/system") / FW_UNIT_NAME
_FW_BASE = FW_UNIT_NAME.removesuffix(".service")
REASSERT_TIMER_NAME = f"{_FW_BASE}-reassert.timer"


def _reassert_paths() -> tuple[Path, Path]:
    """``(service, timer)`` paths, beside FW_UNIT -- resolved at CALL time so they follow it."""
    return (FW_UNIT.with_name(f"{_FW_BASE}-reassert.service"),
            FW_UNIT.with_name(REASSERT_TIMER_NAME))
#: Signed worker certificates, by worker name, under the PKI dir. Public material; kept so
#: an operator can see what was issued (and when it lapses) without the worker.
CERT_SUBDIR = "worker-link"


class WorkerLinkNotInitialised(RuntimeError):
    """``init`` has not been run on this host (no persisted config / interface config)."""


# --------------------------------------------------------------------------------------
# Config persistence
# --------------------------------------------------------------------------------------

def _parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def load_config(*, required: bool = True) -> WorkerLinkConfig | None:
    """This host's persisted worker-link config, with ``BLASTBOX_WORKER_LINK_*`` overriding.

    Same precedence as the egress tier: the file is the base, an explicit environment value
    is unambiguous intent and wins. An EXISTING-but-empty file raises rather than falling
    back to defaults -- defaults would describe some other host's link.
    """
    try:
        text = ENV_FILE.read_text()
    except FileNotFoundError:
        if required:
            raise WorkerLinkNotInitialised(
                f"{ENV_FILE} does not exist: run `blastbox worker-link init` first") from None
        return None
    except OSError as exc:
        raise RuntimeError(f"cannot read {ENV_FILE}: {exc.strerror}") from None
    env = _parse_env(text)
    if not env:
        raise RuntimeError(f"{ENV_FILE} exists but holds no configuration")
    env.update({k: v for k, v in os.environ.items() if k.startswith("BLASTBOX_WORKER_LINK_")})
    return WorkerLinkConfig.from_env(env)


def persist_config(cfg: WorkerLinkConfig) -> None:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text("\n".join([
        "# Written by `blastbox worker-link init`. Contains no key material by design.",
        *cfg.to_env_lines(), "",
    ]))
    os.chmod(ENV_FILE, 0o644)


# --------------------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------------------

def _require(binary: str, package: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise RuntimeError(f"`{binary}` is not installed (package: {package})")
    return path


def egress_conflicts(cfg: WorkerLinkConfig) -> list[str]:
    """Why this link would collide with the EGRESS overlay on this host, or [].

    The two may run side by side on one host -- that is a supported shape (a central host
    that is both the egress exit and the dispatcher) -- but only on disjoint interfaces,
    ports and prefixes. The egress config is read from its persisted env when present and
    its DEFAULTS otherwise: a host with no egress tier today must still not take the
    address range ``egress gateway`` would claim tomorrow, because the failure would land on
    whichever is set up second, silently (a shared prefix is a route over a live network).
    """
    from blastbox.host.egress import EgressConfig

    try:
        egress = EgressConfig.from_env(ea.load_persisted_env() or {})
    except ValueError:
        egress = EgressConfig()
    out: list[str] = []
    if egress.wg_iface == cfg.wg_iface:
        out.append(f"interface {cfg.wg_iface} is the egress overlay's interface")
    if egress.wg_port == cfg.wg_port:
        out.append(f"udp/{cfg.wg_port} is the egress overlay's listen port")
    if ipaddress.ip_network(egress.overlay_net).overlaps(ipaddress.ip_network(cfg.overlay_net)):
        out.append(f"{cfg.overlay_net} overlaps the egress overlay {egress.overlay_net}")
    return out


def check_host(cfg: WorkerLinkConfig) -> None:
    """Refuse a link that collides with egress or with anything this host already routes."""
    clash = egress_conflicts(cfg)
    if clash:
        raise RuntimeError(
            "worker-link must be disjoint from the egress overlay: " + "; ".join(clash)
            + ". Choose a different --iface / --port / --overlay-net.")
    if not ea.host_route_cidrs():
        # The same refusal the egress allocator makes, for the same reason: "routes
        # nothing" and "cannot read the routes" look identical, and only one is safe.
        raise RuntimeError(
            "cannot read this host's routes (`ip` missing or not permitted), so the overlay "
            "cannot be checked against them")
    cidr = ea.overlay_conflict(cfg, own_addresses=True)
    if cidr is not None:
        raise RuntimeError(
            f"the worker-link overlay {cfg.overlay_net} overlaps {cidr}, which this host "
            "already routes; bringing it up would put the link over a live network. Choose a "
            "free range with --overlay-net.")


# --------------------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------------------

def _nft_listing(table: str = NFT_TABLE) -> tuple[str | None, str]:
    """``(listing, why)``: the kernel's ``nft list table`` text, or None and why not."""
    proc = ea._run(["nft", "list", "table", "inet", table], check=False)
    if proc.returncode == 0:
        return proc.stdout or "", ""
    err = (proc.stderr or "").strip()
    if proc.returncode == 127:
        return None, "nft is not installed"
    if "Operation not permitted" in err or "Permission denied" in err:
        return None, "cannot read nftables (needs root)"
    return None, "table not loaded"


def firewall_status(cfg: WorkerLinkConfig) -> tuple[bool | None, str]:
    """True = in force (read back from the kernel), False = absent or incomplete,
    None = could not observe. The ruleset FILE is never consulted: it is what was meant."""
    listing, why = _nft_listing()
    if listing is None:
        return (None if "needs root" in why or "not installed" in why else False), why
    missing = firewall_in_force(listing, host_firewall_nft(cfg))
    if missing:
        return False, "INCOMPLETE: missing " + ", ".join(missing)
    return True, f"in force (table inet {NFT_TABLE})"


def install_firewall(cfg: WorkerLinkConfig) -> list[str]:
    """Load the host ruleset NOW and make it survive a reboot. Raises if it is not in force.

    Loaded before the interface is brought up by :func:`init_host`, so there is no window in
    which the link exists without it.
    """
    nft = _require("nft", "nftables")
    FW_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Loaded from a temp file and moved into place only once the kernel took it: the boot
    # unit loads FW_FILE, so a ruleset nft refuses must never replace the last good one.
    tmp = FW_FILE.with_name(FW_FILE.name + ".new")
    tmp.write_text(host_firewall_nft(cfg))
    os.chmod(tmp, 0o644)
    proc = ea._run([nft, "-f", str(tmp)], check=False)
    if proc.returncode != 0:
        tmp.unlink(missing_ok=True)
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise RuntimeError(f"nft refused the worker-link ruleset: {tail[0]}")
    os.replace(tmp, FW_FILE)
    state, why = firewall_status(cfg)
    if state is not True:
        raise RuntimeError(f"loaded the worker-link ruleset but it is not in force: {why}")
    notes = [f"firewall: {why}"]
    # Persistence is part of the guarantee, not a nicety: without the boot unit enabled
    # (RequiredBy=wg-quick@<iface>) the link would come up OPEN after a reboot, and without
    # the re-assert timer a `systemctl restart nftables` would leave it open until one. So a
    # failure here is fatal -- raised before init brings the interface up.
    body = firewall_unit(nft_bin=nft, nft_file=str(FW_FILE), table=NFT_TABLE,
                         iface=cfg.wg_iface,
                         description="blastbox worker-link host firewall")
    service, timer = reassert_units(nft_bin=nft, nft_file=str(FW_FILE), iface=cfg.wg_iface,
                                    base=_FW_BASE,
                                    description="blastbox worker-link host firewall")
    try:
        changed = False
        for path, text in ((FW_UNIT, body), (_reassert_paths()[0], service), (_reassert_paths()[1], timer)):
            if not (path.exists() and path.read_text() == text):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
                os.chmod(path, 0o644)
                changed = True
    except OSError as exc:
        raise RuntimeError(f"could not install the firewall units ({exc.strerror}); without "
                           "them the link would come up unfirewalled after a reboot") from None
    if changed:
        ea._run(["systemctl", "daemon-reload"], check=False)
    for argv in (["systemctl", "enable", FW_UNIT_NAME],
                 ["systemctl", "enable", "--now", REASSERT_TIMER_NAME]):
        rc = ea._run(argv, check=False)
        if rc.returncode != 0 or not ea._ok(["systemctl", "is-enabled", argv[-1]]):
            tail = (rc.stderr or "").strip().splitlines()[-1:] or ["systemctl failed"]
            raise RuntimeError(f"could not enable {argv[-1]} ({tail[0]}); refusing to bring the "
                               "link up without its firewall persisted")
    notes.append(f"firewall units enabled: {FW_UNIT_NAME} (loads before the link at boot; "
                 f"the link Requires it) and {REASSERT_TIMER_NAME} (re-asserts every minute)")
    return notes


# --------------------------------------------------------------------------------------
# init / add / remove / list / status / teardown
# --------------------------------------------------------------------------------------

def _conf(cfg: WorkerLinkConfig) -> Path:
    return ea.WG_DIR / f"{cfg.wg_iface}.conf"


def _persisted_env() -> dict[str, str]:
    """The persisted env FILE's keys -- never the environment -- or {} when it is absent."""
    try:
        return _parse_env(ENV_FILE.read_text())
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeError(f"cannot read {ENV_FILE}: {exc.strerror}") from None


def _retained_interface(cfg: WorkerLinkConfig, body: str) -> WorkerLinkConfig | None:
    """The config a retained interface file was written with, from its ``[Interface]``
    (``Address = <host_ip>/<prefix>``, ``ListenPort``), or None if it cannot be read back.
    Fields the file does not carry (endpoint, agent port, sources) are taken from ``cfg``."""
    head = body.split("\n# peer:", 1)[0]
    addr = port = None
    for line in head.splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k == "address":
            addr = v
        elif k == "listenport":
            port = v
    if not addr:
        return None
    try:
        iface = ipaddress.IPv4Interface(addr)
        return replace(cfg, overlay_net=str(iface.network), host_ip=str(iface.ip),
                       wg_port=int(port) if port else cfg.wg_port)
    except ValueError:
        return None


def _installed_ifaces() -> set[str]:
    """The link interface(s) THIS host's installed worker-link records name: the persisted
    env file and the firewall boot unit (``RequiredBy=wg-quick@<iface>.service``). Read from
    disk only -- never the environment or the command line, which describe intent, not what
    is installed."""
    found: set[str] = set()
    iface = _persisted_env().get("BLASTBOX_WORKER_LINK_IF", "").strip()
    if iface:
        found.add(iface)
    try:
        unit = FW_UNIT.read_text()
    except FileNotFoundError:
        unit = ""
    except OSError as exc:
        raise RuntimeError(f"cannot read {FW_UNIT}: {exc.strerror}") from None
    found.update(re.findall(r"^RequiredBy=wg-quick@(\S+)\.service$", unit, flags=re.M))
    return found


def _refuse_incompatible_reinit(cfg: WorkerLinkConfig) -> list[str]:
    """A re-run of ``init`` may change what workers can absorb, never what strands them.

    * A different INTERFACE would leave the old one up, firewalled by a table that now
      describes the new one. Tear down first.
    * A different HOST ADDRESS or an overlay that no longer contains a registered worker breaks
      every such worker silently: their config allows and routes only the old host /32, their
      firewall admits only it, and their certificate names an address outside the new prefix.
    * A different PORT or ENDPOINT is allowed but every worker must re-join (their config
      carries the old one), so say so.
    """
    # The FILE alone, not load_config(): that merges BLASTBOX_WORKER_LINK_* from the
    # environment, which is also how `cfg` was built -- so an override in the environment
    # would make prev == cfg and strand every worker unchecked.
    file_env = _persisted_env()
    notes: list[str] = []
    conf = _conf(cfg)
    try:
        body = conf.read_text()
    except FileNotFoundError:
        body = ""
    except OSError as exc:
        raise RuntimeError(f"cannot read {conf}: {exc.strerror}") from None
    workers = _registered(body)
    if file_env:
        prev = WorkerLinkConfig.from_env(file_env)
        if prev.wg_iface != cfg.wg_iface:
            raise RuntimeError(f"worker-link is already set up on {prev.wg_iface}; run "
                               "`blastbox worker-link teardown` before moving it to "
                               f"{cfg.wg_iface}")
    elif workers:
        # No env file -- `teardown` removed it -- but teardown deliberately KEEPS the interface
        # config and its registered workers, so a later init restores them. Those workers still
        # route and firewall only the OLD host address, so the checks below must run against
        # the parameters the retained config was written with, recovered from its [Interface].
        recovered = _retained_interface(cfg, body)
        if recovered is None:
            raise RuntimeError(
                f"{conf} keeps {len(workers)} registered worker(s) but its [Interface] cannot be "
                "read back, so this init cannot be checked against the host address they were "
                "configured for. Restore the file or remove the workers first.")
        prev = recovered
        notes.append(f"NOTE: {ENV_FILE} was absent; checked against {conf} "
                     f"({prev.host_ip}/{prev.prefixlen}, udp/{prev.wg_port}), which keeps "
                     f"{len(workers)} registered worker(s). Their endpoint and agent port are "
                     "not recorded there: if either changed, re-add and re-join each worker")
    else:
        return notes
    if workers and prev.host_ip != cfg.host_ip:
        raise RuntimeError(
            f"{len(workers)} registered worker(s) are configured for the host address "
            f"{prev.host_ip}; changing it to {cfg.host_ip} would strand them. Remove them first.")
    for name, (ip, _key) in workers.items():
        try:
            cfg.member(ip)
        except ValueError:
            raise RuntimeError(
                f"registered worker {name} ({ip}) is outside the new overlay "
                f"{cfg.overlay_net}; remove it first") from None
    if not file_env:
        if prev.wg_port != cfg.wg_port:
            notes.append(f"NOTE: the listen port changed (udp/{prev.wg_port} -> udp/"
                         f"{cfg.wg_port}); the {len(workers)} registered worker(s) must be "
                         "re-added and re-joined to dial the new one")
        return notes
    if workers and (prev.wg_port != cfg.wg_port or prev.endpoint != cfg.endpoint):
        notes.append(f"NOTE: the endpoint/port changed; the {len(workers)} registered worker(s) "
                     "must be re-added and re-joined to dial the new one")
    if workers and prev.agent_port != cfg.agent_port:
        notes.append(f"NOTE: the agent port changed ({prev.agent_port} -> {cfg.agent_port}); every "
                     f"worker's firewall and agent env are pinned to the old one: re-add and "
                     "re-join each, then restart its agent on the new port")
    return notes


def init_host(cfg: WorkerLinkConfig) -> tuple[str, list[str]]:
    """Stand up the host end. Idempotent. Returns ``(host public key, notes)``.

    Order is the safety property: preconditions, then the FIREWALL (loaded and read back),
    then the interface. A failure at any step leaves the link down rather than up and open.
    """
    _require("wg", "wireguard-tools")
    _require("wg-quick", "wireguard-tools")
    changed = _refuse_incompatible_reinit(cfg)
    check_host(cfg)
    notes = install_firewall(cfg)
    notes += changed
    ea.WG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ea.WG_DIR, 0o700)
    priv, pub = ea.ensure_keypair(cfg.wg_iface)
    conf = _conf(cfg)
    want = host_wg_config(cfg, priv.read_text().strip())
    with ea.conf_lock(cfg):
        rewritten = True
        if not conf.exists():
            ea._write_conf(conf, want)
        else:
            # Reconcile [Interface], KEEP the registered workers -- same rule as the egress
            # gateway, for the same reason (a changed port or address must reach the file).
            body = conf.read_text()
            peers = body[body.index("\n# peer:"):] if "\n# peer:" in body else ""
            rewritten = body != want + peers
            if rewritten:
                ea._write_conf(conf, want + peers)
            os.chmod(conf, 0o600)
        # An idempotent re-run with the link already up and its config unchanged leaves the
        # interface alone: wg_up would RESTART it, forgetting every worker's learned endpoint.
        # A changed [Interface] (address, port) does need the restart, and gets it.
        if rewritten or not ea._ok(["ip", "link", "show", cfg.wg_iface]):
            ea.wg_up(cfg)
    persist_config(cfg)
    notes.append(f"{cfg.wg_iface} up at {cfg.host_ip}/{cfg.prefixlen}, udp/{cfg.wg_port}")
    notes.append(f"config persisted to {ENV_FILE}")
    if not cfg.endpoint:
        notes.append("NOTE: no --endpoint recorded; `add` needs the address workers dial "
                     "(re-run init with --endpoint <public-host>[:port])")
    if not cfg.dispatcher_sources:
        notes.append("NOTE: no --dispatcher-source: only a dispatcher running ON this host "
                     "can reach workers. A dispatcher in docker needs its network's CIDR here "
                     "(its connections are then MASQUERADEd to "
                     f"{cfg.host_ip}).")
    return pub, notes


def _registered(body: str) -> dict[str, tuple[str, str]]:
    """``name -> (bare worker ip, public key)`` from the host config."""
    return {name: (ip.split("/")[0], key) for name, ip, key in ea._peer_blocks(body)}


def _refuse_uninstalled_override(cfg: WorkerLinkConfig, what: str) -> None:
    """Refuse an enrolment change made with a config the host is not RUNNING.

    ``cfg`` merges BLASTBOX_WORKER_LINK_* (and CLI flags) over the persisted file. Every value
    a worker is configured with -- interface, overlay, host address, listen port, agent port,
    endpoint -- is what ``init`` put on the live interface, routes and firewall. An override
    left in the environment would have ``add`` register a peer and hand out a bundle for an
    address or port nothing on this host serves: a worker enrolled unable to communicate.
    Changing any of them is ``init``'s job (which also checks it against the registered fleet).
    """
    file_env = _persisted_env()
    if not file_env:
        raise WorkerLinkNotInitialised(
            f"{ENV_FILE} does not exist: run `blastbox worker-link init` first")
    installed = WorkerLinkConfig.from_env(file_env)
    diff = [f"{label} {got!r} (installed: {want!r})"
            for label, got, want in (
                ("interface", cfg.wg_iface, installed.wg_iface),
                ("overlay", cfg.overlay_net, installed.overlay_net),
                ("host address", cfg.host_ip, installed.host_ip),
                ("listen port", cfg.wg_port, installed.wg_port),
                ("agent port", cfg.agent_port, installed.agent_port),
                ("endpoint", cfg.endpoint, installed.endpoint))
            if got != want]
    if diff:
        raise RuntimeError(
            f"refusing to {what} with a configuration this host is not running: "
            + "; ".join(diff) + ". Unset the BLASTBOX_WORKER_LINK_* override (or drop the flag), "
            "or change the installed link with `blastbox worker-link init` first.")


def _apply_peers(cfg: WorkerLinkConfig, old_body: str, new_body: str) -> None:
    """Apply a PEER-ONLY change to the live link interface, without restarting it.

    ``egress_apply._reload_wg`` restarts ``wg-quick@<iface>`` when systemd manages it. Here that
    is wrong: the host learns each worker's NATed endpoint from its handshakes (peers carry no
    ``Endpoint``), so a restart forgets every one of them and cuts EVERY worker off until its
    next keepalive -- for a routine add, a removal or a monthly renewal. ``wg syncconf`` diffs
    the peer set in place and keeps learned endpoints of unchanged peers. It is run against THIS
    link's interface only; no other WireGuard interface (the egress overlay, a hand-managed one)
    is touched. A change to the comments alone (``# expires:``) reaches nothing live at all.
    """
    if ea._peer_blocks(old_body) == ea._peer_blocks(new_body):
        return
    iface = cfg.wg_iface
    if not ea._ok(["ip", "link", "show", iface]):
        return          # down: wg-quick reads the file when it comes up
    conf = _conf(cfg)
    stripped = ea._run(["wg-quick", "strip", str(conf)], check=False)
    if stripped.returncode == 0 and stripped.stdout:
        tmp = conf.with_suffix(".stripped")
        try:
            ea._write_conf(tmp, stripped.stdout)
            synced = ea._run(["wg", "syncconf", iface, str(tmp)], check=False)
        finally:
            tmp.unlink(missing_ok=True)
        if synced.returncode == 0:
            return
        tail = (synced.stderr or "").strip().splitlines()[-1:] or ["no detail"]
    else:
        tail = (stripped.stderr or "").strip().splitlines()[-1:] or ["no detail"]
    raise RuntimeError(
        f"changed {conf} but could NOT apply it to the live {iface} ({tail[0]}); the running "
        f"interface still has the old peers. Run `wg syncconf {iface} <(wg-quick strip {iface})` "
        "by hand before trusting this.")


def _cert_expiry(cert_pem: bytes) -> str:
    from cryptography import x509

    return x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc.isoformat()


def add_worker(cfg: WorkerLinkConfig, name: str, public_key: str, csr_pem: bytes, *,
               ip: str | None = None, days: int = 30,
               pki_dir: Path) -> tuple[JoinBundle, bool]:
    """Register a worker and sign its CSR. Returns ``(join bundle, changed)``.

    Re-running for an existing name RECONCILES (a renewed cert, a rotated key, a moved
    address) instead of skipping, the lesson ``egress peer-add`` learned: treating presence
    as success meant a renewal changed nothing. The address is kept across a renewal unless
    ``ip`` says otherwise.

    The CSR is signed only if its subjectAltName is EXACTLY the address allocated here
    (``CertAuthority.sign_csr_for_ip``), so the certificate the dispatcher verifies names
    the same /32 the tunnel delivers from.
    """
    try:
        from blastbox.host.pki import load_ca
    except ImportError as exc:
        raise RuntimeError(f"signing needs blastbox[host] (cryptography): {exc}") from None

    from blastbox.host.egress import _SAFE_NAME, _is_wg_key

    if not _SAFE_NAME.match(name):
        raise ValueError(f"unsafe worker name {name!r} (letters, digits, . _ -; 1-31 chars)")
    if not _is_wg_key(public_key.strip()):
        raise ValueError("--public-key is not a 32-byte base64 WireGuard public key")
    if not 1 <= int(days) <= 397:
        raise ValueError("--days must be between 1 and 397")
    if not cfg.endpoint:
        raise RuntimeError("no endpoint recorded for this host: re-run `blastbox worker-link "
                           "init --endpoint <public-host>[:port]` so workers know where to dial")
    _refuse_uninstalled_override(cfg, "add a worker")
    conf = _conf(cfg)
    pub_path = ea.KEY_DIR / f"{cfg.wg_iface}.pub"
    if not conf.exists() or not pub_path.exists():
        raise WorkerLinkNotInitialised(
            f"{conf} or its key is missing: run `blastbox worker-link init` first")
    try:
        ca = load_ca(Path(pki_dir))
    except FileNotFoundError:
        # NEVER mint a CA here. `ensure_ca` would happily create one, and the dispatcher
        # (which trusts BLASTBOX_DISPATCH_TLS_CA) would then reject every worker signed by it.
        raise RuntimeError(f"no CA in {pki_dir}: run `blastbox pki init` (the dispatcher's CA) "
                           "first, or pass --pki-dir") from None
    ca_pem = (Path(pki_dir) / "ca.crt").read_text()
    host_pub = pub_path.read_text().strip()
    key = public_key.strip()
    with ea.conf_lock(cfg):
        body = conf.read_text()
        reg = _registered(body)
        if ip:
            want = cfg.member(ip)
        elif name in reg and reg[name][0]:
            want = cfg.member(reg[name][0])
        else:
            want = next_free_ip(cfg, [v[0] for n, v in reg.items() if n != name])
        ea._refuse_peer_collision(body, name=name, peer_ip=want, public_key=key,
                                  iface=cfg.wg_iface)
        try:
            cert_pem = ca.sign_csr_for_ip(csr_pem, want, cn=f"worker-link:{name}", days=days)
        except ValueError as exc:
            raise RuntimeError(
                f"{exc}. On the worker, run `blastbox worker-link keygen --ip {want}` and bring "
                "back the new CSR (or pass --ip to match the one it was made for).") from None
        stanza = link_peer_stanza(name, want, key, cfg=cfg, expires=_cert_expiry(cert_pem))
        marker = f"\n# peer:{name}\n"
        if marker in body:
            start = body.index(marker)
            nxt = body.find("\n# peer:", start + 1)
            new_body = body[:start] + stanza + body[len(body) if nxt == -1 else nxt:]
        else:
            new_body = body + stanza
        changed = new_body != body
        if changed:
            ea._write_conf(conf, new_body)
            _apply_peers(cfg, body, new_body)
    cert_dir = Path(pki_dir) / CERT_SUBDIR
    cert_dir.mkdir(parents=True, exist_ok=True)
    (cert_dir / f"{name}.crt").write_bytes(cert_pem)
    os.chmod(cert_dir / f"{name}.crt", 0o644)
    bundle = JoinBundle(name=name, iface=cfg.wg_iface, worker_ip=want, host_ip=cfg.host_ip,
                        overlay_net=cfg.overlay_net, endpoint=cfg.endpoint,
                        host_public_key=host_pub, agent_port=cfg.agent_port,
                        ca_pem=ca_pem, cert_pem=cert_pem.decode())
    return bundle, changed


def remove_worker(cfg: WorkerLinkConfig, name: str, *, pki_dir: Path | None = None) -> bool:
    """Drop a worker from the live interface and the config. False if it was not registered.

    The certificate is deleted from the host's record too, but a signed cert cannot be
    unsigned: what stops a removed worker is that its tunnel is gone (WireGuard drops its
    handshakes) -- and if it were re-added at another address, its old cert names the old
    one. Remove its address from BLASTBOX_STATIC_WORKERS as well.
    """
    conf = _conf(cfg)
    if not conf.exists():
        raise WorkerLinkNotInitialised(f"{conf} does not exist: nothing is registered")
    _refuse_uninstalled_override(cfg, "remove a worker")
    with ea.conf_lock(cfg):
        body = conf.read_text()
        if name not in _registered(body):
            return False
        new_body = ea.drop_peer_blocks(body, [name])
        ea._write_conf(conf, new_body)
        _apply_peers(cfg, body, new_body)
    if pki_dir is not None:
        (Path(pki_dir) / CERT_SUBDIR / f"{name}.crt").unlink(missing_ok=True)
    return True


def list_workers(cfg: WorkerLinkConfig) -> list[dict[str, str]]:
    from blastbox.host.egress import peer_expiries

    conf = _conf(cfg)
    try:
        body = conf.read_text()
    except FileNotFoundError:
        raise WorkerLinkNotInitialised(f"{conf} does not exist") from None
    expiry = {n: when.isoformat() for n, when in peer_expiries(body)}
    return [{"name": n, "ip": ip.split("/")[0], "public_key": k, "cert_expires": expiry.get(n, "")}
            for n, ip, k in ea._peer_blocks(body)]


def status(cfg: WorkerLinkConfig, *, now: float | None = None) -> tuple[bool, list[str]]:
    """What is IN FORCE right now, read back from the kernel. Returns ``(ok, rows)``.

    ``ok`` is True only when the interface is up AND the firewall was read back complete.
    "Could not observe" (not root) is reported as such and is not ok -- it is not evidence
    the link is safe. Per worker: the last handshake as WireGuard itself reports it, which
    is the only proof a worker behind NAT is actually holding its tunnel open.
    """
    from blastbox.host.exit_attest import parse_wg_dump

    rows: list[str] = []
    up = ea._ok(["ip", "link", "show", cfg.wg_iface])
    rows.append(f"interface {cfg.wg_iface}: {'up' if up else 'DOWN'}"
                f" ({cfg.host_ip}/{cfg.prefixlen}, udp/{cfg.wg_port})")
    fw, why = firewall_status(cfg)
    rows.append("firewall: " + (why if fw is True else
                                ("NOT IN FORCE — " if fw is False else "UNVERIFIED — ") + why))
    for unit in (f"wg-quick@{cfg.wg_iface}", FW_UNIT_NAME, REASSERT_TIMER_NAME):
        enabled = ea._ok(["systemctl", "is-enabled", unit])
        rows.append(f"{unit}: {'enabled' if enabled else 'NOT enabled (will not survive a reboot)'}")
    try:
        workers = list_workers(cfg)
    except WorkerLinkNotInitialised:
        workers = []
    by_key = {w["public_key"]: w for w in workers}
    dump = ea._run(["wg", "show", cfg.wg_iface, "dump"], check=False)
    observed = parse_wg_dump(dump.stdout or "", observed_at=now) if dump.returncode == 0 else None
    if observed is None:
        rows.append("handshakes: UNVERIFIED — cannot read `wg show` (needs root, interface up)")
    seen: set[str] = set()
    for p in observed or []:
        w = by_key.get(p.public_key)
        label = f"{w['name']} {w['ip']}" if w else f"UNREGISTERED key {p.public_key[:10]}…"
        seen.add(p.public_key)
        if not p.ever_connected:
            state = "never handshaked"
        else:
            age = (p.observed_at - p.latest_handshake)
            state = (f"handshake {age:.0f}s ago" + ("" if p.connected(now=p.observed_at)
                                                  else " (STALE — worker not holding the tunnel)"))
        exp = f"; cert expires {w['cert_expires'][:10]}" if w and w["cert_expires"] else ""
        rows.append(f"  {label}: {state}{exp}")
    if observed is not None:
        for w in workers:
            if w["public_key"] not in seen:
                rows.append(f"  {w['name']} {w['ip']}: registered but NOT on the live interface")
    ok = bool(up) and fw is True and observed is not None
    return ok, rows


def teardown(cfg: WorkerLinkConfig) -> list[str]:
    """Remove only what ``init`` created: the interface, its unit, the firewall table, its
    unit and file, and the env file. Never an iptables chain, an ``ip rule``, a routing
    table or an egress unit -- those are the egress tier's.

    The interface goes down BEFORE the firewall is removed, so the link is never up
    unfirewalled. The interface config, keys and issued certificates are kept, so a later
    ``init`` restores every registered worker; say so rather than leave the operator to
    discover it. Every outcome is VERIFIED, not announced.
    """
    # Destructive, and the firewall table and units it deletes are GLOBAL to worker-link, so
    # the interface it stops first must be the INSTALLED one. `cfg` merges
    # BLASTBOX_WORKER_LINK_IF / --iface over the persisted file; an override naming some other
    # interface would stop (and verify down) the wrong one, then strip the firewall from the
    # real link while it stays up.
    installed = _installed_ifaces()
    if installed and installed != {cfg.wg_iface}:
        raise RuntimeError(
            "worker-link is installed on " + ", ".join(sorted(installed)) + f", not "
            f"{cfg.wg_iface}: refusing to tear down. Unset BLASTBOX_WORKER_LINK_IF / drop "
            "--iface so teardown acts on the installed interface.")
    notes: list[str] = []
    ea._run(["systemctl", "disable", "--now", f"wg-quick@{cfg.wg_iface}"], check=False)
    ea._run(["wg-quick", "down", cfg.wg_iface], check=False)
    if ea._ok(["ip", "link", "show", cfg.wg_iface]):
        notes.append(f"WARNING: {cfg.wg_iface} is STILL UP; the firewall is left in place "
                     "until it is down. Bring it down by hand and re-run teardown.")
        return notes
    notes.append(f"{cfg.wg_iface} down; wg-quick@{cfg.wg_iface} disabled")
    ea._run(["systemctl", "disable", "--now", REASSERT_TIMER_NAME], check=False)
    ea._run(["systemctl", "disable", "--now", FW_UNIT_NAME], check=False)
    ea._run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    listing, why = _nft_listing()
    if listing is not None:
        notes.append(f"WARNING: table inet {NFT_TABLE} is still loaded")
    elif why == "table not loaded":
        notes.append(f"table inet {NFT_TABLE} removed (no other table touched)")
    else:
        notes.append(f"WARNING: could not verify table inet {NFT_TABLE} was removed ({why})")
    for path in (*_reassert_paths(), FW_UNIT, FW_FILE, ENV_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            notes.append(f"WARNING: could not remove {path} ({exc.strerror})")
    ea._run(["systemctl", "daemon-reload"], check=False)
    notes.append(f"kept {_conf(cfg)} (registered workers), keys in {ea.KEY_DIR}; a later "
                 "`init` restores them")
    return notes
