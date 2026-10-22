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


def _lock_path() -> Path:
    """The node-wide installation lock, beside the env file (resolved at CALL time)."""
    return ENV_FILE.with_name(".worker-link.lock")


def _installation_locked(fn):  # type: ignore[no-untyped-def]
    """Run ``fn`` holding ONE node-wide exclusive lock for every host mutation (init, add,
    remove, teardown).

    ``conf_lock`` serialises only the interface-config read-modify-write. Each of these
    commands also checks, installs and persists things OUTSIDE it -- compatibility checks,
    the firewall, the unit files, the env record -- so two overlapping commands could
    interleave: init B loads its firewall, init A then applies its interface and both report
    success; or an ``add`` registers a worker after a concurrent init's compatibility check
    saw none, and that init then moves the host address under it. One lock across the whole
    command makes each one atomic with respect to the others. ``flock``: released by the
    kernel if the process dies, never left stale."""
    import fcntl
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        path = _lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fn(*args, **kwargs)
        finally:
            os.close(fd)        # releases the lock

    return wrapper


class FirewallNotInForce(RuntimeError):
    """The NEW ruleset was loaded but could not be verified, or could not be persisted. Unlike
    nft refusing the file (the previous ruleset then stays loaded), a live link is no longer
    known to be firewalled -- see init_host."""


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


def load_config(*, required: bool = True, recover: bool = False) -> WorkerLinkConfig | None:
    """This host's persisted worker-link config, with ``BLASTBOX_WORKER_LINK_*`` overriding.

    Same precedence as the egress tier: the file is the base, an explicit environment value
    is unambiguous intent and wins. An EXISTING-but-empty file raises rather than falling
    back to defaults -- defaults would describe some other host's link.

    ``recover``: for the actions that INSPECT or DISMANTLE what is installed (status, list,
    remove, teardown), a missing env file is not the end of the road -- the link and its
    firewall can still be installed (the file was deleted by hand, or a teardown died
    half-way). Their configuration is then recovered from what IS on disk
    (:func:`recover_installed_config`), so the operator can still see and remove it.
    """
    try:
        text = ENV_FILE.read_text()
    except FileNotFoundError:
        if recover:
            rec = recover_installed_config()
            if rec is not None:
                return rec
        if required:
            raise WorkerLinkNotInitialised(
                f"{ENV_FILE} does not exist: run `blastbox worker-link init` first") from None
        # Not installed yet (a first `init`): the documented BLASTBOX_WORKER_LINK_* settings
        # still apply -- returning nothing made init silently install the DEFAULT interface,
        # overlay and ports with no endpoint, after which `add` refused the configured endpoint
        # as an uninstalled override. CLI flags are applied over this by the caller.
        return WorkerLinkConfig.from_env(
            {k: v for k, v in os.environ.items() if k.startswith("BLASTBOX_WORKER_LINK_")})
    except OSError as exc:
        raise RuntimeError(f"cannot read {ENV_FILE}: {exc.strerror}") from None
    env = _parse_env(text)
    try:
        if not env:
            raise ValueError(f"{ENV_FILE} exists but holds no configuration")
        file_cfg = WorkerLinkConfig.from_env(env)
    except ValueError as exc:
        # Empty or garbled (an interrupted write by an older version, a hand edit): the
        # commands that inspect or dismantle the install must still reach it.
        if recover:
            rec = recover_installed_config()
            if rec is not None:
                return rec
        raise RuntimeError(str(exc) if not env else f"{ENV_FILE} is not usable: {exc}") from None
    del file_cfg
    env.update({k: v for k, v in os.environ.items() if k.startswith("BLASTBOX_WORKER_LINK_")})
    return WorkerLinkConfig.from_env(env)


def persisted_config_usable() -> bool:
    """Whether the env record exists AND parses into a config (status uses this to say when
    it is showing a recovered one)."""
    env = _persisted_env()
    if not env:
        return False
    try:
        WorkerLinkConfig.from_env(env)
    except ValueError:
        return False
    return True


def recover_installed_config() -> WorkerLinkConfig | None:
    """The installed link's config from the records that outlive the env file, or None.

    The interface comes from the firewall boot unit (``RequiredBy=wg-quick@<iface>``) -- and
    the env file when present, via :func:`_installed_ifaces`; address, overlay and listen port
    from that interface's retained ``[Interface]``. The agent port, endpoint and dispatcher
    sources live only in the env file, so they are the defaults here: good enough to inspect
    and dismantle the link, never to enrol a worker (``add`` refuses without the file).
    """
    ifaces = _installed_ifaces()
    if len(ifaces) != 1:
        return None
    base = WorkerLinkConfig(wg_iface=next(iter(ifaces)))
    try:
        body = _conf(base).read_text()
    except OSError:
        return base
    return _retained_interface(base, body) or base


def persist_config(cfg: WorkerLinkConfig) -> None:
    # Atomic (temp + fsync + rename): an interrupted write must never leave an empty or partial
    # record where the install's recovery commands look for it.
    ea.atomic_write(ENV_FILE, "\n".join([
        "# Written by `blastbox worker-link init`. Contains no key material by design.",
        *cfg.to_env_lines(), "",
    ]), 0o644)


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
    # ONLY nft's own not-found answer (ENOENT for the table) is absence. Any other failure --
    # netlink ENOMEM/EIO, a crashed nft -- says nothing about the table, and teardown treats
    # "table not loaded" as permission to delete its recovery records.
    if "No such file or directory" in err:
        return None, "table not loaded"
    tail = err.splitlines()[-1:] or [f"exit {proc.returncode}"]
    return None, f"cannot read nftables ({tail[0]})"


def firewall_status(cfg: WorkerLinkConfig) -> tuple[bool | None, str]:
    """True = in force (read back from the kernel), False = absent or incomplete,
    None = could not observe. The ruleset FILE is never consulted: it is what was meant."""
    listing, why = _nft_listing()
    if listing is None:
        # absent is a verdict (False); not being able to ask is not (None)
        return (False if why == "table not loaded" else None), why
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
    ea.atomic_write(tmp, host_firewall_nft(cfg), 0o644)
    proc = ea._run([nft, "-f", str(tmp)], check=False)
    if proc.returncode != 0:
        tmp.unlink(missing_ok=True)
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise RuntimeError(f"nft refused the worker-link ruleset: {tail[0]}")
    os.replace(tmp, FW_FILE)
    ea.fsync_dir(FW_FILE.parent)
    state, why = firewall_status(cfg)
    if state is not True:
        raise FirewallNotInForce(f"loaded the worker-link ruleset but it is not in force: {why}")
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
                ea.atomic_write(path, text, 0o644)
                changed = True
    except OSError as exc:
        raise FirewallNotInForce(f"could not install the firewall units ({exc.strerror}); "
                                 "without them the link would come up unfirewalled after a "
                                 "reboot") from None
    if changed:
        ea._run(["systemctl", "daemon-reload"], check=False)
    # ENABLED *and* STARTED (`--now`), both verified. The rules were loaded with `nft -f` above,
    # so merely enabling left the boot unit INACTIVE -- and `PartOf=nftables.service` only
    # propagates a restart to an ACTIVE unit: `systemctl restart nftables` (a flush) would then
    # leave the live link unfiltered until the re-assert timer fired. Starting the oneshot just
    # re-loads the same ruleset atomically.
    for argv in (["systemctl", "enable", "--now", FW_UNIT_NAME],
                 ["systemctl", "enable", "--now", REASSERT_TIMER_NAME]):
        rc = ea._run(argv, check=False)
        if (rc.returncode != 0 or not ea._ok(["systemctl", "is-enabled", argv[-1]])
                or not ea._ok(["systemctl", "is-active", argv[-1]])):
            tail = (rc.stderr or "").strip().splitlines()[-1:] or ["not enabled and active"]
            raise FirewallNotInForce(f"could not enable and start {argv[-1]} ({tail[0]}); "
                                     "refusing to bring the link up without its firewall "
                                     "persisted and active")
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
    # The firewall table, ruleset file and boot unit are node-global. If ANY record on disk --
    # the env file or the boot unit (which survives a deleted env file) -- names another
    # interface, installing for this one would replace that link's firewall while its tunnel
    # stays up. Checked first, before the per-interface config below is even consulted.
    other = sorted(_installed_ifaces() - {cfg.wg_iface})
    if other:
        raise RuntimeError(f"worker-link is already set up on {', '.join(other)}; run "
                           "`blastbox worker-link teardown` before moving it to "
                           f"{cfg.wg_iface}")
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


#: First line of every interface config ``init`` writes (host_wg_config). It is the proof,
#: surviving a teardown that keeps the config, that a /etc/wireguard/<iface>.conf is ours.
HOST_CONF_MARKER = "# blastbox worker-link — HOST end."


def _refuse_foreign_interface(cfg: WorkerLinkConfig) -> None:
    """Raise if ``cfg.wg_iface`` is a WireGuard interface worker-link cannot prove it created.

    ``init`` rewrites ``/etc/wireguard/<iface>.conf`` (a foreign config's ordinary peer blocks,
    without our ``# peer:`` markers, would be dropped) and starts or restarts ``wg-quick@<iface>``.
    For the operator's own ``wg1`` that is a destroyed VPN. Ours means: an install record names
    it (:func:`_installed_ifaces`), or its config carries the line ``init`` writes first.
    Anything else that already exists under that name -- a config, a live interface, an
    enabled or active wg-quick unit -- is refused before anything is written.
    """
    iface = cfg.wg_iface
    if iface in _installed_ifaces():
        return
    conf = _conf(cfg)
    try:
        body = conf.read_text()
    except FileNotFoundError:
        body = None
    except OSError as exc:
        raise RuntimeError(f"cannot read {conf}: {exc.strerror}") from None
    if body is not None and body.startswith(HOST_CONF_MARKER):
        return
    evidence = []
    if body is not None:
        evidence.append(f"{conf} exists and was not written by worker-link")
    if ea._ok(["ip", "link", "show", iface]):
        evidence.append(f"interface {iface} is up")
    unit = f"wg-quick@{iface}"
    if ea._ok(["systemctl", "is-enabled", unit]) or ea._ok(["systemctl", "is-active", unit]):
        evidence.append(f"{unit} is enabled or running")
    if evidence:
        raise RuntimeError(
            f"{iface} is not a worker-link interface ({'; '.join(evidence)}); refusing to "
            "overwrite or restart it. Choose another --iface for the link.")


def _derive_public_key(private_key: str) -> str:
    """``wg pubkey`` of ``private_key`` (one seam, so tests need no wireguard-tools)."""
    import subprocess

    try:
        proc = subprocess.run(["wg", "pubkey"], input=private_key.strip() + "\n", text=True,
                              capture_output=True, check=False)
    except FileNotFoundError:
        raise RuntimeError("`wg` is not installed (package: wireguard-tools)") from None
    pub = (proc.stdout or "").strip()
    if proc.returncode != 0 or not pub:
        raise RuntimeError("`wg pubkey` could not derive the host public key")
    return pub


def _host_public_key(cfg: WorkerLinkConfig) -> str:
    """The host's public key, DERIVED from the private key the link runs with -- never read from
    the ``.pub`` file. ``ensure_keypair`` only regenerates a MISSING ``.pub``: a stale or
    corrupted one was trusted, handed to every worker in its join bundle, and none of them
    could ever handshake. The ``.pub`` file is rewritten when it disagrees."""
    priv = ea.KEY_DIR / f"{cfg.wg_iface}.key"
    try:
        private = priv.read_text().strip()
    except FileNotFoundError:
        raise WorkerLinkNotInitialised(
            f"{priv} is missing: run `blastbox worker-link init` first") from None
    if not private:
        raise WorkerLinkNotInitialised(f"{priv} is empty: run `blastbox worker-link init`")
    pub = _derive_public_key(private)
    pub_path = ea.KEY_DIR / f"{cfg.wg_iface}.pub"
    try:
        current = pub_path.read_text().strip()
    except FileNotFoundError:
        current = ""
    if current != pub:
        ea.atomic_write(pub_path, pub + "\n", 0o644)
    return pub


def _conf_private_key(body: str) -> str:
    head = body.split("\n# peer:", 1)[0]
    for line in head.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() == "PrivateKey":
            return v.strip()
    return ""


def _reconcile_host_key(cfg: WorkerLinkConfig, *, rotate: bool) -> list[str]:
    """Make sure ``init`` keeps the host key every registered worker pins, unless told not to.

    ``ensure_keypair`` GENERATES a key when the key file is missing or empty, and ``init`` then
    rewrites and restarts the interface with it: every worker's bundle pins the previous public
    key, so all of them silently lose their handshakes. The retained interface config holds
    the key the link actually runs with (``PrivateKey``), so:

    * key file missing/empty, config has the key -> restore the file from it (same key);
    * key file DIFFERENT from the config's key while workers are registered -> refuse;
    * no key anywhere while workers are registered -> refuse;
    * ``rotate`` -> a new key on purpose, with the re-join that implies spelled out.
    """
    conf = _conf(cfg)
    try:
        body = conf.read_text()
    except FileNotFoundError:
        body = ""
    workers = _registered(body)
    in_conf = _conf_private_key(body)
    priv = ea.KEY_DIR / f"{cfg.wg_iface}.key"
    pub = ea.KEY_DIR / f"{cfg.wg_iface}.pub"
    try:
        on_disk = priv.read_text().strip()
    except FileNotFoundError:
        on_disk = ""
    if rotate:
        priv.unlink(missing_ok=True)
        pub.unlink(missing_ok=True)
        return [f"NOTE: the host key was ROTATED on request: every one of the {len(workers)} "
                "registered worker(s) pins the old public key and must be re-added "
                "(`worker-link add`) and re-joined with its new bundle"] if workers else []
    if not on_disk and in_conf:
        ea.KEY_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(ea.KEY_DIR, 0o700)
        ea.atomic_write(priv, in_conf + "\n", 0o600)
        pub.unlink(missing_ok=True)          # ensure_keypair re-derives it from the private key
        return [f"NOTE: {priv} was missing; restored from {conf} (the key the link runs with), "
                "so registered workers keep their bundles"]
    if workers and in_conf and on_disk != in_conf:
        raise RuntimeError(
            f"{priv} does not hold the key {conf} runs with, and {len(workers)} registered "
            "worker(s) pin that key: re-init would silently rotate it and cut every one of them "
            "off. Restore the key file, or pass --rotate-key to rotate on purpose (every worker "
            "must then be re-added and re-joined).")
    if workers and not on_disk:
        raise RuntimeError(
            f"{priv} is missing and {conf} records no key, but {len(workers)} registered "
            "worker(s) pin the old one: restore the key file, or pass --rotate-key (every "
            "worker must then be re-added and re-joined).")
    return []


@_installation_locked
def init_host(cfg: WorkerLinkConfig, *, rotate_key: bool = False) -> tuple[str, list[str]]:
    """Stand up the host end. Idempotent. Returns ``(host public key, notes)``.

    Order is the safety property: preconditions, then the FIREWALL (loaded and read back),
    then the interface. A failure at any step leaves the link down rather than up and open.
    Every refusal (a foreign interface, an incompatible re-init, a key that would rotate)
    happens before anything is written.
    """
    _require("wg", "wireguard-tools")
    _require("wg-quick", "wireguard-tools")
    _refuse_foreign_interface(cfg)
    changed = _refuse_incompatible_reinit(cfg)
    check_host(cfg)
    changed += _reconcile_host_key(cfg, rotate=rotate_key)
    _refuse_endpoint_resolving_into_overlay(cfg)
    try:
        notes = install_firewall(cfg)
    except FirewallNotInForce as exc:
        # On a re-init the link may be LIVE: it must not keep running (or boot) behind a
        # ruleset nobody can vouch for. Down it, verified, and disable its unit.
        raise FirewallNotInForce(str(exc) + _host_fail_closed(cfg)) from None
    notes += changed
    ea.WG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ea.WG_DIR, 0o700)
    priv, _stale_pub = ea.ensure_keypair(cfg.wg_iface)
    pub = _host_public_key(cfg)           # derived from priv; a stale .pub is repaired
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
        if not ea._ok(["ip", "link", "show", cfg.wg_iface]):
            ea.wg_up(cfg)
        elif rewritten or _live_interface_mismatch(cfg, pub):
            # Also when the FILE is unchanged: a previous run may have written it and then
            # failed to restart, leaving the interface on the old address, port or key -- a
            # retry must apply it, not see "nothing changed".
            _restart_link(cfg)
        _verify_live_address(cfg)
        stale = _live_interface_mismatch(cfg, pub)
        if stale:
            raise RuntimeError(f"{cfg.wg_iface} is up but does not run the config just written "
                               f"({'; '.join(stale)}); restart it (`systemctl restart wg-quick@"
                               f"{cfg.wg_iface}`) and re-run init")
        # ...and its PEERS: a previous `add`/`remove` may have written the file and failed to
        # apply it to the live interface (a no-op when they already match).
        _apply_peers(cfg, conf.read_text())
        _ensure_link_enabled(cfg)
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


def _ensure_link_enabled(cfg: WorkerLinkConfig) -> None:
    """Raise unless ``wg-quick@<iface>`` is ENABLED. ``egress_apply.wg_up`` falls back to a
    direct ``wg-quick up`` when ``enable --now`` fails: the link is then up but would not
    return after a reboot, while init persisted everything else as if it would."""
    unit = f"wg-quick@{cfg.wg_iface}"
    if ea._ok(["systemctl", "is-enabled", unit]):
        return
    ea._run(["systemctl", "enable", unit], check=False)
    if not ea._ok(["systemctl", "is-enabled", unit]):
        raise RuntimeError(f"{cfg.wg_iface} is up but {unit} could not be ENABLED, so the link "
                           "would not come back after a reboot (its firewall is installed and "
                           f"kept). Run `systemctl enable {unit}` and re-run init.")


def _host_fail_closed(cfg: WorkerLinkConfig) -> str:
    """Take a live host link DOWN (verified) and disable its unit, because its firewall
    cannot be vouched for; returns the sentence to append to the error."""
    iface, unit = cfg.wg_iface, f"wg-quick@{cfg.wg_iface}"
    ea._run(["systemctl", "disable", unit], check=False)
    if not ea._ok(["ip", "link", "show", iface]):
        return ""
    ea._run(["systemctl", "stop", unit], check=False)
    ea._run(["wg-quick", "down", iface], check=False)
    if ea._ok(["ip", "link", "show", iface]):
        ea._run(["ip", "link", "delete", "dev", iface], check=False)
    if ea._ok(["ip", "link", "show", iface]):
        return (f". {iface} could NOT be taken down and may be running without its firewall: "
                f"`ip link delete dev {iface}` by hand NOW")
    return f". {iface} was taken DOWN (and {unit} disabled) rather than left running without it"


def _resolve_host(host: str) -> list[str]:
    """Addresses ``host`` resolves to from here, or [] if it does not (one seam for tests)."""
    import socket

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_UDP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({str(i[4][0]) for i in infos})


def _refuse_endpoint_resolving_into_overlay(cfg: WorkerLinkConfig) -> None:
    """A HOSTNAME endpoint that resolves into the overlay is as recursive as a literal one
    (rejected in WorkerLinkConfig). Resolved here, best effort: a name that does not resolve
    from this host is not proof of anything, and every worker checks it again at join."""
    from blastbox.host.worker_link import refuse_endpoint_in_overlay

    if not cfg.endpoint:
        return
    host = cfg.endpoint.rsplit(":", 1)[0].strip("[]")
    addrs = _resolve_host(host)
    if not addrs:
        return
    try:
        refuse_endpoint_in_overlay(addrs, cfg.overlay_net,
                                   what=f"endpoint {host} (resolves to {', '.join(addrs)})")
    except ValueError as exc:
        raise RuntimeError(str(exc)) from None


def _restart_link(cfg: WorkerLinkConfig) -> None:
    """Bring a LIVE link down and up again from its (changed) config, or raise.

    Not ``egress_apply.wg_up``: when the restart fails it accepts a ``wg-quick strip`` +
    ``wg syncconf`` fallback, and the stripped config has no ``Address`` -- syncconf cannot
    move the interface address or its route. A changed host address or overlay would then be
    persisted and reported while the interface kept the old one, under a firewall loaded for
    the new one. Only a real down/up applies it.
    """
    unit = f"wg-quick@{cfg.wg_iface}"
    if ea._ok(["systemctl", "is-active", unit]):
        proc = ea._run(["systemctl", "restart", unit], check=False)
    else:
        ea._run(["wg-quick", "down", cfg.wg_iface], check=False)
        proc = ea._run(["wg-quick", "up", cfg.wg_iface], check=False)
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise RuntimeError(f"could not restart {cfg.wg_iface} with its changed address/port "
                           f"({tail[0]}); it is NOT running the new config")


def _live_addresses(cfg: WorkerLinkConfig) -> list[str]:
    """The IPv4 ``ip/prefix`` list the LIVE interface carries, read from the kernel."""
    import json as _json

    proc = ea._run(["ip", "-j", "addr", "show", "dev", cfg.wg_iface], check=False)
    try:
        info = _json.loads(proc.stdout or "[]") if proc.returncode == 0 else []
    except ValueError:
        info = []
    return sorted(f"{a.get('local')}/{a.get('prefixlen')}"
                  for dev in info if isinstance(dev, dict)
                  for a in dev.get("addr_info", []) if a.get("family") == "inet")


def _live_interface_mismatch(cfg: WorkerLinkConfig, pub: str) -> list[str]:
    """How the LIVE interface differs from the config just written, read from the kernel:
    its address, its listen port and its public key (= the private key it runs). Any of them
    can be stale after a run that rewrote the file and was interrupted before the restart --
    and a retry then sees an unchanged file."""
    out: list[str] = []
    got = _live_addresses(cfg)
    if got != [f"{cfg.host_ip}/{cfg.prefixlen}"]:
        out.append(f"address {', '.join(got) or 'none'} (want {cfg.host_ip}/{cfg.prefixlen})")
    port = ea._run(["wg", "show", cfg.wg_iface, "listen-port"], check=False)
    if port.returncode != 0 or (port.stdout or "").strip() != str(cfg.wg_port):
        out.append(f"listen port {(port.stdout or '').strip() or '?'} (want {cfg.wg_port})")
    key = ea._run(["wg", "show", cfg.wg_iface, "public-key"], check=False)
    if key.returncode != 0 or (key.stdout or "").strip() != pub:
        out.append(f"public key {((key.stdout or '').strip() or '?')[:10]}… (want {pub[:10]}…)")
    return out


def _verify_live_address(cfg: WorkerLinkConfig) -> None:
    """Raise unless the LIVE interface carries exactly ``host_ip/prefix`` -- what the firewall
    just loaded describes and what every worker routes to. Read from the kernel."""
    got = _live_addresses(cfg)
    want = f"{cfg.host_ip}/{cfg.prefixlen}"
    if got != [want]:
        raise RuntimeError(f"{cfg.wg_iface} is up with {', '.join(got) or 'no IPv4 address'}, "
                           f"not {want}: the live interface does not match the config just "
                           "written. Restart it (`systemctl restart wg-quick@"
                           f"{cfg.wg_iface}`) and re-run init.")


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
        if what.startswith("remove") and cfg.wg_iface in _installed_ifaces():
            return      # dropping a peer from the INSTALLED interface needs nothing else
        raise WorkerLinkNotInitialised(
            f"{ENV_FILE} does not exist, so the endpoint and agent port workers must be given "
            "are unknown: re-run `blastbox worker-link init` (with the same --iface / "
            "--endpoint / --agent-port) to restore it first")
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


def _live_peers(iface: str) -> "set[tuple[str, str]] | None":
    """``{(public key, allowed-ips)}`` on the LIVE interface, or None if it cannot be read."""
    proc = ea._run(["wg", "show", iface, "allowed-ips"], check=False)
    if proc.returncode != 0:
        return None
    out: set[tuple[str, str]] = set()
    for line in (proc.stdout or "").splitlines():
        key, _, ips = line.partition("\t")
        if key.strip():
            out.add((key.strip(), ",".join(sorted(ips.split()))))
    return out


def _apply_peers(cfg: WorkerLinkConfig, body: str) -> None:
    """Make the LIVE link interface's peers match ``body`` (the config on disk), in place.

    Compared against the interface itself, not against the previous file: the file is written
    first, so after a sync that FAILED the file already holds the new peer and a retry would
    see "nothing changed" and hand out a bundle for a peer the interface never got. Reading
    the live peer set makes every run reconcile, whatever an earlier one left behind.

    ``egress_apply._reload_wg`` restarts ``wg-quick@<iface>`` when systemd manages it. Here that
    is wrong: the host learns each worker's NATed endpoint from its handshakes (peers carry no
    ``Endpoint``), so a restart forgets every one of them and cuts EVERY worker off until its
    next keepalive -- for a routine add, a removal or a monthly renewal. ``wg syncconf`` diffs
    the peer set in place and keeps learned endpoints of unchanged peers. It is run against THIS
    link's interface only; no other WireGuard interface (the egress overlay, a hand-managed one)
    is touched. A change to the comments alone (``# expires:``) reaches nothing live at all.
    """
    iface = cfg.wg_iface
    if not ea._ok(["ip", "link", "show", iface]):
        return          # down: wg-quick reads the file when it comes up
    want = {(key, ",".join(sorted(ip.replace(",", " ").split())))
            for _n, ip, key in ea._peer_blocks(body)}
    if _live_peers(iface) == want:
        return
    conf = _conf(cfg)
    stripped = ea._run(["wg-quick", "strip", str(conf)], check=False)
    if stripped.returncode == 0 and stripped.stdout:
        tmp = conf.with_suffix(".stripped")
        try:
            ea._write_conf(tmp, stripped.stdout)
            synced = ea._run(["wg", "syncconf", iface, str(tmp)], check=False)
        finally:
            tmp.unlink(missing_ok=True)
        if synced.returncode == 0 and _live_peers(iface) == want:
            return
        tail = ((synced.stderr or "").strip().splitlines()[-1:]
                or ["the live peers still differ after syncconf"])
    else:
        tail = (stripped.stderr or "").strip().splitlines()[-1:] or ["no detail"]
    raise RuntimeError(
        f"{conf} is written but could NOT be applied to the live {iface} ({tail[0]}); the "
        "running interface still has the old peers. Re-run the same command once the cause is "
        f"fixed (it reconciles the live interface), or run `wg syncconf {iface} "
        f"<(wg-quick strip {iface})` by hand.")


def _cert_expiry(cert_pem: bytes) -> str:
    from cryptography import x509

    return x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc.isoformat()


@_installation_locked
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
    if not conf.exists():
        raise WorkerLinkNotInitialised(f"{conf} is missing: run `blastbox worker-link init` first")
    try:
        ca = load_ca(Path(pki_dir))
    except FileNotFoundError:
        # NEVER mint a CA here. `ensure_ca` would happily create one, and the dispatcher
        # (which trusts BLASTBOX_DISPATCH_TLS_CA) would then reject every worker signed by it.
        raise RuntimeError(f"no CA in {pki_dir}: run `blastbox pki init` (the dispatcher's CA) "
                           "first, or pass --pki-dir") from None
    ca_pem = (Path(pki_dir) / "ca.crt").read_text()
    # DERIVED from the private key (and checked against the interface config it runs with),
    # never read from the .pub file, so a stale .pub cannot be handed to workers.
    host_pub = _host_public_key(cfg)
    in_conf = _conf_private_key(conf.read_text())
    if in_conf and _derive_public_key(in_conf) != host_pub:
        raise RuntimeError(
            f"{ea.KEY_DIR / (cfg.wg_iface + '.key')} does not hold the key {conf} runs with; "
            "re-run `blastbox worker-link init` (it restores/reconciles the key) before `add`")
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
        # ALWAYS, not only when the file changed: a previous run may have written the file and
        # then failed to apply it. This reconciles against the live interface (a no-op if equal).
        _apply_peers(cfg, new_body)
    cert_dir = Path(pki_dir) / CERT_SUBDIR
    cert_dir.mkdir(parents=True, exist_ok=True)
    ea.atomic_write(cert_dir / f"{name}.crt", cert_pem, 0o644)
    bundle = JoinBundle(name=name, iface=cfg.wg_iface, worker_ip=want, host_ip=cfg.host_ip,
                        overlay_net=cfg.overlay_net, endpoint=cfg.endpoint,
                        host_public_key=host_pub, agent_port=cfg.agent_port,
                        ca_pem=ca_pem, cert_pem=cert_pem.decode(), worker_public_key=key)
    return bundle, changed


@_installation_locked
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
            # ...but still reconcile: a previous remove may have dropped it from the file and
            # then failed to take it off the live interface, where it would keep its tunnel.
            _apply_peers(cfg, body)
            return False
        new_body = ea.drop_peer_blocks(body, [name])
        ea._write_conf(conf, new_body)
        _apply_peers(cfg, new_body)
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
    # A status for an interface that is not the installed one (a BLASTBOX_WORKER_LINK_IF /
    # --iface override, a typo) would compare the node-wide firewall against the wrong
    # interface and report on a link that does not exist. Say which one IS installed.
    installed = _installed_ifaces()
    foreign = bool(installed) and cfg.wg_iface not in installed
    if foreign:
        rows.append(f"WARNING: worker-link is installed on {', '.join(sorted(installed))}, not "
                    f"{cfg.wg_iface}; this status describes {cfg.wg_iface} (unset "
                    "BLASTBOX_WORKER_LINK_IF / drop --iface to see the installed link)")
    recovered = not persisted_config_usable()
    if recovered:
        rows.append(f"WARNING: {ENV_FILE} is MISSING or unusable; showing the link recovered "
                    "from its "
                    "installed unit/config. Re-run `blastbox worker-link init` (same --iface, "
                    "--endpoint, --agent-port) to restore it, or `teardown` to remove it.")
    up = ea._ok(["ip", "link", "show", cfg.wg_iface])
    rows.append(f"interface {cfg.wg_iface}: {'up' if up else 'DOWN'}"
                f" ({cfg.host_ip}/{cfg.prefixlen}, udp/{cfg.wg_port})")
    if recovered:
        # The agent port and dispatcher sources are recorded only in the missing file, so the
        # rules cannot be compared; report what can be observed, and never call it OK.
        listing, why = _nft_listing()
        fw = None
        rows.append("firewall: UNVERIFIED — " + (
            f"table inet {NFT_TABLE} is loaded, but its rules cannot be checked without "
            f"{ENV_FILE}" if listing is not None else why))
    else:
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
    ok = bool(up) and fw is True and observed is not None and not foreign
    return ok, rows


@_installation_locked
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
    # ...and DISABLED, verified. The interface config is deliberately kept, so a wg-quick unit
    # still enabled (its `disable` failed even though `wg-quick down` then worked) would bring
    # that interface back at the next boot -- after this function removed the firewall unit
    # it Requires. `is-enabled` exits 0 for every state that starts at boot.
    if ea._ok(["systemctl", "is-enabled", f"wg-quick@{cfg.wg_iface}"]):
        notes.append(f"WARNING: wg-quick@{cfg.wg_iface} is STILL ENABLED, so it would start "
                     f"{cfg.wg_iface} at the next boot; the firewall is left in place. Run "
                     f"`systemctl disable wg-quick@{cfg.wg_iface}` and re-run teardown.")
        return notes
    notes.append(f"{cfg.wg_iface} down; wg-quick@{cfg.wg_iface} disabled")
    ea._run(["systemctl", "disable", "--now", REASSERT_TIMER_NAME], check=False)
    ea._run(["systemctl", "disable", "--now", FW_UNIT_NAME], check=False)
    ea._run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    listing, why = _nft_listing()
    # The env file and the firewall boot unit are the RECOVERY RECORDS: _installed_ifaces()
    # reads them to find this install again. Removing them while the table may still be
    # loaded left a retry nothing to find -- and a stale table filtering whatever interface
    # later takes that name. So they go only once the table is confirmed gone, and LAST.
    if listing is not None:
        notes.append(f"WARNING: table inet {NFT_TABLE} is still loaded; {ENV_FILE} and "
                     f"{FW_UNIT_NAME} are kept so teardown can be re-run")
        return notes
    if why != "table not loaded":
        notes.append(f"WARNING: could not verify table inet {NFT_TABLE} was removed ({why}); "
                     f"{ENV_FILE} and {FW_UNIT_NAME} are kept so teardown can be re-run")
        return notes
    notes.append(f"table inet {NFT_TABLE} removed (no other table touched)")
    failed = False
    for path in (*_reassert_paths(), FW_FILE, FW_UNIT, ENV_FILE):
        if failed and path in (FW_UNIT, ENV_FILE):
            break                   # keep the recovery records if anything before them stuck
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            failed = True
            notes.append(f"WARNING: could not remove {path} ({exc.strerror})")
    ea.fsync_dir(ENV_FILE.parent)
    ea._run(["systemctl", "daemon-reload"], check=False)
    notes.append(f"kept {_conf(cfg)} (registered workers), keys in {ea.KEY_DIR}; a later "
                 "`init` restores them")
    return notes
