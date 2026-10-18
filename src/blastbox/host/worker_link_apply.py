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
import shutil
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
)

ENV_FILE = Path("/etc/blastbox/worker-link.env")
FW_FILE = Path("/etc/blastbox/worker-link.nft")
FW_UNIT = Path("/etc/systemd/system") / FW_UNIT_NAME
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
    missing = firewall_in_force(listing, iface=cfg.wg_iface)
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
    body = firewall_unit(nft_bin=nft, nft_file=str(FW_FILE), table=NFT_TABLE,
                         iface=cfg.wg_iface,
                         description="blastbox worker-link host firewall")
    try:
        if not (FW_UNIT.exists() and FW_UNIT.read_text() == body):
            FW_UNIT.parent.mkdir(parents=True, exist_ok=True)
            FW_UNIT.write_text(body)
            os.chmod(FW_UNIT, 0o644)
            ea._run(["systemctl", "daemon-reload"], check=False)
    except OSError as exc:
        notes.append(f"WARNING: firewall unit NOT installed ({exc.strerror}); the ruleset "
                     "will not be reloaded after a reboot")
        return notes
    rc = ea._run(["systemctl", "enable", FW_UNIT_NAME], check=False)
    notes.append(f"firewall unit {FW_UNIT_NAME}: "
                 + ("enabled (reloads before the link at boot)" if rc.returncode == 0 else
                    "NOT ENABLED — the ruleset will not survive a reboot"))
    return notes


# --------------------------------------------------------------------------------------
# init / add / remove / list / status / teardown
# --------------------------------------------------------------------------------------

def _conf(cfg: WorkerLinkConfig) -> Path:
    return ea.WG_DIR / f"{cfg.wg_iface}.conf"


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
    prev = load_config(required=False) if ENV_FILE.exists() else None
    notes: list[str] = []
    if prev is None:
        return notes
    if prev.wg_iface != cfg.wg_iface:
        raise RuntimeError(f"worker-link is already set up on {prev.wg_iface}; run "
                           "`blastbox worker-link teardown` before moving it to "
                           f"{cfg.wg_iface}")
    conf = _conf(cfg)
    workers = _registered(conf.read_text()) if conf.exists() else {}
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
    if workers and (prev.wg_port != cfg.wg_port or prev.endpoint != cfg.endpoint):
        notes.append(f"NOTE: the endpoint/port changed; the {len(workers)} registered worker(s) "
                     "must be re-added and re-joined to dial the new one")
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
        if not conf.exists():
            ea._write_conf(conf, want)
        else:
            # Reconcile [Interface], KEEP the registered workers -- same rule as the egress
            # gateway, for the same reason (a changed port or address must reach the file).
            body = conf.read_text()
            peers = body[body.index("\n# peer:"):] if "\n# peer:" in body else ""
            if body != want + peers:
                ea._write_conf(conf, want + peers)
            os.chmod(conf, 0o600)
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
            ea._reload_wg(cfg)
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
    with ea.conf_lock(cfg):
        body = conf.read_text()
        if name not in _registered(body):
            return False
        ea._write_conf(conf, ea.drop_peer_blocks(body, [name]))
        ea._reload_wg(cfg)
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
    for unit in (f"wg-quick@{cfg.wg_iface}", FW_UNIT_NAME):
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
    notes: list[str] = []
    ea._run(["systemctl", "disable", "--now", f"wg-quick@{cfg.wg_iface}"], check=False)
    ea._run(["wg-quick", "down", cfg.wg_iface], check=False)
    if ea._ok(["ip", "link", "show", cfg.wg_iface]):
        notes.append(f"WARNING: {cfg.wg_iface} is STILL UP; the firewall is left in place "
                     "until it is down. Bring it down by hand and re-run teardown.")
        return notes
    notes.append(f"{cfg.wg_iface} down; wg-quick@{cfg.wg_iface} disabled")
    ea._run(["systemctl", "disable", "--now", FW_UNIT_NAME], check=False)
    ea._run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    listing, why = _nft_listing()
    if listing is not None:
        notes.append(f"WARNING: table inet {NFT_TABLE} is still loaded")
    elif why == "table not loaded":
        notes.append(f"table inet {NFT_TABLE} removed (no other table touched)")
    else:
        notes.append(f"WARNING: could not verify table inet {NFT_TABLE} was removed ({why})")
    for path in (FW_UNIT, FW_FILE, ENV_FILE):
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
