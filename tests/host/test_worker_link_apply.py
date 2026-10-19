"""Effects tests for ``blastbox worker-link`` on the HOST, against a simulated host.

No root, no ``wg``, no ``nft``: every command goes through ``egress_apply._run``/``_ok`` and is
answered by :class:`FakeHost`, which keeps just enough state (loaded ruleset, live interfaces)
to make ordering and read-back observable. All paths are redirected into ``tmp_path``.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blastbox.host import egress_apply as ea
from blastbox.host import worker_link_apply as wla
from blastbox.host.pki import ensure_ca
from blastbox.host.worker_link import NFT_TABLE, JoinBundle, WorkerLinkConfig

KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
HOST_PUB = "H" * 43 + "="


class FakeHost:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.loaded: str | None = None      # what the kernel would list for our table
        self.links: set[str] = set()
        self.root = True
        self.nft_refuses = False
        self.dump = ""
        self.stuck_up = False
        #: iface -> {public key: allowed-ips} on the LIVE interface
        self.live_peers: dict[str, dict[str, str]] = {}
        self.syncconf_fails = False
        self.enabled: set[str] = set()                 # unit names `systemctl enable`d
        self.disable_fails = False
        self.addrs: dict[str, str] = {}               # iface -> LIVE "ip/prefix"
        self.restart_fails = False
        self.nft_delete_fails = False

    def _up(self, iface: str) -> None:
        """A (re)start reads the interface's config file, as wg-quick does."""
        self.links.add(iface)
        for ln in (ea.WG_DIR / f"{iface}.conf").read_text().splitlines():
            if ln.split("=")[0].strip() == "Address":
                self.addrs[iface] = ln.split("=", 1)[1].strip()

    def run(self, argv, check: bool = True, capture: bool = True):
        a = [str(x) for x in argv]
        self.calls.append(a)
        rc, out, err = 0, "", ""
        tool = Path(a[0]).name
        if tool == "nft" and a[1] == "-f":
            if self.nft_refuses:
                rc, err = 1, "Error: syntax error"
            else:
                text = Path(a[2]).read_text()
                self.loaded = text.split(f"delete table inet {NFT_TABLE}\n", 1)[1]
        elif tool == "nft" and a[1:3] == ["list", "table"]:
            if not self.root:
                rc, err = 1, "Error: Operation not permitted"
            elif self.loaded is None:
                rc, err = 1, "Error: No such file or directory"
            else:
                out = self.loaded
        elif tool == "nft" and a[1:3] == ["delete", "table"]:
            if self.nft_delete_fails:
                rc, err = 1, "Error: Could not process rule: Device or resource busy"
            else:
                self.loaded = None
        elif a[:3] == ["ip", "link", "show"]:
            rc = 0 if a[3] in self.links else 1
        elif a[:5] == ["ip", "-j", "addr", "show", "dev"]:
            ip, _, plen = self.addrs.get(a[5], "/").partition("/")
            out = json.dumps([{"ifname": a[5], "addr_info": [
                {"family": "inet", "local": ip, "prefixlen": int(plen)}]}]
                if a[5] in self.links and ip else [])
        elif a[:3] == ["ip", "-j", "route"] or a[:3] == ["ip", "-j", "addr"]:
            out = "[]"
        elif a[:2] == ["systemctl", "restart"] and a[2].startswith("wg-quick@"):
            if self.restart_fails:
                rc, err = 1, "Job for wg-quick failed"
            else:
                self._up(a[2].split("@")[1])
        elif a[:2] == ["wg-quick", "up"]:
            self._up(a[2])
        elif a[:2] == ["systemctl", "is-enabled"]:
            rc = 0 if a[2] in self.enabled else 1
        elif a[:2] == ["systemctl", "enable"]:
            self.enabled.add(a[-1])
            if a[2] == "--now" and a[3].startswith("wg-quick@"):
                self._up(a[3].split("@")[1])
        elif a[:2] == ["systemctl", "disable"] and self.disable_fails \
                and a[-1].startswith("wg-quick@"):
            rc, err = 1, "Failed to disable unit"
        elif a[:2] == ["systemctl", "disable"]:
            self.enabled.discard(a[-1])
            if a[2] == "--now" and a[3].startswith("wg-quick@") and not self.stuck_up:
                self.links.discard(a[3].split("@")[1])
        elif a[:2] == ["systemctl", "is-active"]:
            rc = 0 if a[2].split("@")[-1] in self.links else 3
        elif a[:2] == ["wg-quick", "strip"]:
            body = Path(a[2]).read_text()
            out = "\n".join(ln for ln in body.splitlines()
                            if ln.split("=")[0].strip() not in ("Address", "DNS", "MTU"))
        elif a[:2] == ["wg", "syncconf"]:
            if self.syncconf_fails:
                rc, err = 1, "Unable to modify interface"
            else:
                peers: dict[str, str] = {}
                key = ""
                for ln in Path(a[3]).read_text().splitlines():
                    k, _, v = ln.partition("=")
                    if k.strip() == "PublicKey":
                        key = v.strip()
                        peers[key] = ""
                    elif k.strip() == "AllowedIPs" and key:
                        peers[key] = v.strip()
                self.live_peers[a[2]] = peers
        elif a[:2] == ["wg", "show"] and a[3:] == ["allowed-ips"]:
            out = "".join(f"{k}\t{v}\n" for k, v in self.live_peers.get(a[2], {}).items())
        elif a[:2] == ["wg-quick", "down"]:
            if not self.stuck_up:
                self.links.discard(a[2])
        elif a[:2] == ["wg", "show"]:
            if not self.root:
                rc, err = 1, "Operation not permitted"
            else:
                out = self.dump
        return subprocess.CompletedProcess(a, rc, out, err)

    def ok(self, argv) -> bool:
        return self.run(argv).returncode == 0

    def flat(self) -> str:
        return "\n".join(" ".join(c) for c in self.calls)


@pytest.fixture
def host(tmp_path, monkeypatch):
    h = FakeHost()
    monkeypatch.setattr(ea, "_run", h.run)
    monkeypatch.setattr(ea, "_ok", h.ok)
    monkeypatch.setattr(ea, "WG_DIR", tmp_path / "wireguard")
    monkeypatch.setattr(ea, "KEY_DIR", tmp_path / "wireguard" / "blastbox")
    monkeypatch.setattr(ea, "ENV_FILE", tmp_path / "egress.env")          # absent: no egress
    monkeypatch.setattr(ea, "host_route_cidrs", lambda: ["192.168.1.0/24"])
    monkeypatch.setattr(ea, "claimed_cidrs", lambda: ["192.168.1.0/24", "172.17.0.0/16"])
    monkeypatch.setattr(wla, "ENV_FILE", tmp_path / "worker-link.env")
    monkeypatch.setattr(wla, "FW_FILE", tmp_path / "worker-link.nft")
    monkeypatch.setattr(wla, "FW_UNIT", tmp_path / "units" / "blastbox-worker-link-fw.service")
    monkeypatch.setattr(wla, "_require", lambda binary, package: binary)

    generated = []

    def keypair(stem):
        """Like the real ensure_keypair: REUSE a non-empty key, generate only when missing."""
        ea.KEY_DIR.mkdir(parents=True, exist_ok=True)
        priv, pub = ea.KEY_DIR / f"{stem}.key", ea.KEY_DIR / f"{stem}.pub"
        if not priv.exists() or not priv.read_text().strip():
            generated.append(stem)
            priv.write_text("PRIVATE-HOST-KEY\n" if len(generated) == 1
                            else f"PRIVATE-HOST-KEY-{len(generated)}\n")
        os.chmod(priv, 0o600)
        key = priv.read_text().strip()
        pubkey = HOST_PUB if key == "PRIVATE-HOST-KEY" else (key[-1] * 43 + "=")
        pub.write_text(pubkey + "\n")
        return priv, pubkey

    monkeypatch.setattr(ea, "ensure_keypair", keypair)
    return h


def _cfg(**kw) -> WorkerLinkConfig:
    kw.setdefault("endpoint", "gw.example.org")
    return WorkerLinkConfig(**kw)


def _csr(*sans, key=None) -> bytes:
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "whatever-the-worker-says")]))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _ip(a: str) -> x509.IPAddress:
    return x509.IPAddress(ipaddress.ip_address(a))


@pytest.fixture
def pki(tmp_path):
    d = tmp_path / "pki"
    ensure_ca(d)
    return d


# ------------------------------------------------------------------------------- init

def test_init_loads_and_reads_back_the_firewall_before_the_link_exists(host):
    pub, notes = wla.init_host(_cfg())
    assert pub == HOST_PUB
    flat = [" ".join(c) for c in host.calls]
    load = next(i for i, c in enumerate(flat) if c.startswith("nft -f"))
    readback = next(i for i, c in enumerate(flat) if c.startswith("nft list table"))
    up = next(i for i, c in enumerate(flat) if c == "systemctl enable --now wg-quick@wtwg0")
    assert load < readback < up
    assert "wtwg0" in host.links
    assert any("in force" in n for n in notes)
    assert "systemctl enable blastbox-worker-link-fw.service" in flat


def test_init_does_not_bring_the_link_up_when_nft_refuses_the_ruleset(host):
    host.nft_refuses = True
    with pytest.raises(RuntimeError, match="nft refused"):
        wla.init_host(_cfg())
    assert "wtwg0" not in host.links
    assert not (ea.WG_DIR / "wtwg0.conf").exists()


def test_a_refused_ruleset_never_replaces_the_one_the_boot_unit_loads(host):
    wla.init_host(_cfg())
    good = wla.FW_FILE.read_text()
    host.nft_refuses = True
    with pytest.raises(RuntimeError, match="nft refused"):
        wla.init_host(_cfg(agent_port=9443))
    assert wla.FW_FILE.read_text() == good
    assert not wla.FW_FILE.with_name(wla.FW_FILE.name + ".new").exists()


def test_init_writes_a_0600_config_without_forwarding_and_persists_no_keys(host):
    wla.init_host(_cfg())
    conf = ea.WG_DIR / "wtwg0.conf"
    assert oct(conf.stat().st_mode & 0o777) == "0o600"
    body = conf.read_text()
    assert "PostUp" not in body and "ip_forward" not in body
    env = wla.ENV_FILE.read_text()
    assert "PRIVATE" not in env and "BLASTBOX_WORKER_LINK_ENDPOINT=gw.example.org:51822" in env


def test_init_is_idempotent_and_keeps_registered_workers(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.init_host(cfg)
    wla.init_host(_cfg(wg_port=51900))        # a changed port reaches the file, peers kept
    body = (ea.WG_DIR / "wtwg0.conf").read_text()
    assert "ListenPort = 51900" in body and "# peer:mac1" in body


def test_init_refuses_to_bring_the_link_up_if_the_firewall_cannot_be_persisted(host, monkeypatch):
    real = host.run

    def run(argv, **kw):
        if list(argv)[:2] == ["systemctl", "enable"] and "--now" not in argv:
            return subprocess.CompletedProcess(list(argv), 1, "", "Failed to enable unit")
        return real(argv, **kw)

    monkeypatch.setattr(ea, "_run", run)
    with pytest.raises(RuntimeError, match="without its firewall persisted"):
        wla.init_host(_cfg())
    assert "wtwg0" not in host.links


def test_an_environment_override_cannot_strand_workers_past_the_reinit_check(
        host, pki, monkeypatch):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    monkeypatch.setenv("BLASTBOX_WORKER_LINK_HOST_IP", "10.78.0.9")
    with pytest.raises(RuntimeError, match="strand"):
        wla.init_host(wla.load_config())


def test_reinit_refuses_changes_that_would_strand_registered_workers(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.9")), ip="10.78.0.9", pki_dir=pki)
    with pytest.raises(RuntimeError, match="teardown"):
        wla.init_host(_cfg(wg_iface="wtwg1"))
    with pytest.raises(RuntimeError, match="strand"):
        wla.init_host(_cfg(host_ip="10.78.0.2"))
    with pytest.raises(RuntimeError, match="outside the new overlay"):
        wla.init_host(_cfg(overlay_net="10.78.0.0/29"))
    _pub, notes = wla.init_host(_cfg(endpoint="gw2.example.org"))
    assert any("re-joined" in n for n in notes)
    _pub, notes = wla.init_host(_cfg(endpoint="gw2.example.org", agent_port=9443))
    assert any("agent port changed" in n for n in notes)


@pytest.mark.parametrize("egress_env,why", [
    ("BLASTBOX_EGRESS_OVERLAY_NET=10.78.0.0/24\n", "overlaps the egress overlay"),
    ("BLASTBOX_EGRESS_WG_IF=wtwg0\n", "egress overlay's interface"),
    ("BLASTBOX_EGRESS_WG_PORT=51822\n", "egress overlay's listen port"),
])
def test_init_refuses_to_share_anything_with_the_egress_overlay(host, egress_env, why):
    ea.ENV_FILE.write_text(egress_env)
    with pytest.raises(RuntimeError, match=why):
        wla.init_host(_cfg())
    assert host.calls == [] or not any(c[0] == "nft" for c in host.calls)


def test_init_refuses_the_egress_DEFAULT_overlay_even_with_no_egress_tier_yet(host):
    with pytest.raises(RuntimeError, match="egress overlay"):
        wla.init_host(_cfg(overlay_net="10.77.0.0/24"))


def test_init_refuses_an_overlay_the_host_already_routes(host, monkeypatch):
    monkeypatch.setattr(ea, "claimed_cidrs", lambda: ["10.78.0.0/16"])
    with pytest.raises(RuntimeError, match="already routes"):
        wla.init_host(_cfg())


def test_init_refuses_when_the_hosts_routes_cannot_be_read(host, monkeypatch):
    monkeypatch.setattr(ea, "host_route_cidrs", lambda: [])
    with pytest.raises(RuntimeError, match="cannot read"):
        wla.init_host(_cfg())


def test_a_rerun_with_the_link_up_does_not_refuse_its_own_address(host, monkeypatch):
    """host_route_cidrs reports every held address as a /32, so with wtwg0 up its own
    10.78.0.1 is "claimed" -- a second init must recognise it as ours."""
    import json

    monkeypatch.setattr(ea, "claimed_cidrs", lambda: ["10.78.0.0/24", "10.78.0.1/32"])
    real = host.run

    def run(argv, **kw):
        a = list(argv)
        if a[:5] == ["ip", "-j", "route", "show", "dev"]:
            return subprocess.CompletedProcess(a, 0, json.dumps([{"dst": "10.78.0.0/24"}]), "")
        if a[:5] == ["ip", "-j", "addr", "show", "dev"]:
            return subprocess.CompletedProcess(a, 0, json.dumps([{"addr_info": [
                {"family": "inet", "local": "10.78.0.1", "prefixlen": 24}]}]), "")
        return real(argv, **kw)

    monkeypatch.setattr(ea, "_run", run)
    wla.init_host(_cfg())


def test_the_host_side_never_runs_anything_that_belongs_to_egress(host, pki):
    cfg = _cfg(dispatcher_sources=("172.18.0.0/16",))
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.status(cfg)
    wla.remove_worker(cfg, "mac1")
    wla.teardown(cfg)
    flat = host.flat()
    for forbidden in ("iptables", "ip rule", "BB-WG", "bbwg", "blastbox-egress", "rt_tables",
                      "flush ruleset", "route flush"):
        assert forbidden not in flat, forbidden
    assert all(c[1:4] != ["delete", "table", "inet"] or c[4] == NFT_TABLE
               for c in host.calls if Path(c[0]).name == "nft")


# -------------------------------------------------------------------------------- add

def test_add_allocates_signs_exactly_that_address_and_returns_a_public_bundle(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    bundle, changed = wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    assert changed and bundle.worker_ip == "10.78.0.2"
    assert bundle.host_public_key == HOST_PUB and bundle.endpoint == "gw.example.org:51822"
    assert bundle.ca_pem == (pki / "ca.crt").read_text()
    cert = x509.load_pem_x509_certificate(bundle.cert_pem.encode())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert list(sans) == [_ip("10.78.0.2")]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]        # never clientAuth
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "worker-link:mac1"
    body = (ea.WG_DIR / "wtwg0.conf").read_text()
    assert "# peer:mac1\n# expires:" in body and "AllowedIPs = 10.78.0.2/32" in body
    assert (pki / "worker-link" / "mac1.crt").read_text() == bundle.cert_pem
    assert JoinBundle.from_json(bundle.to_json()) == bundle
    assert "PRIVATE" not in bundle.to_json()


def test_a_csr_for_another_address_is_refused_with_the_fix(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    before = (ea.WG_DIR / "wtwg0.conf").read_text()
    with pytest.raises(RuntimeError, match=r"exactly IP:10\.78\.0\.2.*keygen --ip 10\.78\.0\.2"):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.9")), pki_dir=pki)
    assert (ea.WG_DIR / "wtwg0.conf").read_text() == before


@pytest.mark.parametrize("sans", [
    (), (x509.DNSName("mac1.example.org"),), (_ip("10.78.0.2"), _ip("10.78.0.3")),
    (_ip("10.78.0.2"), x509.DNSName("evil")),
])
def test_only_a_single_exact_ip_san_is_ever_signed(host, pki, sans):
    """A second SAN would let this worker's cert answer for ANOTHER worker's address."""
    cfg = _cfg()
    wla.init_host(cfg)
    with pytest.raises(RuntimeError):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(*sans), pki_dir=pki)


def test_a_weak_csr_key_is_refused(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(RuntimeError, match="RSA"):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2"), key=weak), pki_dir=pki)


def test_add_never_mints_a_ca(host, tmp_path):
    cfg = _cfg()
    wla.init_host(cfg)
    empty = tmp_path / "no-pki"
    with pytest.raises(RuntimeError, match="pki init"):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=empty)
    assert not (empty / "ca.key").exists()


def test_add_requires_init_and_an_endpoint(host, pki):
    with pytest.raises(wla.WorkerLinkNotInitialised):
        wla.add_worker(_cfg(), "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.init_host(_cfg())
    with pytest.raises(RuntimeError, match="endpoint"):
        wla.add_worker(WorkerLinkConfig(), "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)


def test_readding_reconciles_and_keeps_the_address(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.add_worker(cfg, "mac2", KEY_B, _csr(_ip("10.78.0.3")), pki_dir=pki)
    rotated = "C" * 43 + "="
    b, changed = wla.add_worker(cfg, "mac1", rotated, _csr(_ip("10.78.0.2")), pki_dir=pki)
    assert changed and b.worker_ip == "10.78.0.2"
    rows = {r["name"]: r for r in wla.list_workers(cfg)}
    assert rows["mac1"]["public_key"] == rotated and rows["mac2"]["ip"] == "10.78.0.3"
    assert (ea.WG_DIR / "wtwg0.conf").read_text().count("# peer:mac1") == 1


@pytest.mark.parametrize("kw,why", [({"ip": "10.78.0.2"}, "already registered"),
                                    ({"key": KEY_A}, "public key is already registered")])
def test_add_refuses_a_collision_with_another_worker(host, pki, kw, why):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    ip = kw.get("ip", "10.78.0.3")
    with pytest.raises(RuntimeError, match=why):
        wla.add_worker(cfg, "mac2", kw.get("key", KEY_B), _csr(_ip(ip)), ip=ip, pki_dir=pki)


def test_add_refuses_the_host_address_and_nonsense(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    with pytest.raises(ValueError):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.1")), ip="10.78.0.1", pki_dir=pki)
    with pytest.raises(ValueError):
        wla.add_worker(cfg, "bad name", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    with pytest.raises(ValueError):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki, days=0)


# ------------------------------------------------------------------------- remove/list

def test_remove_takes_the_worker_off_the_live_interface(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.add_worker(cfg, "mac2", KEY_B, _csr(_ip("10.78.0.3")), pki_dir=pki)
    host.calls.clear()
    assert wla.remove_worker(cfg, "mac1", pki_dir=pki) is True
    # applied IN PLACE to the live link (wg syncconf), never by restarting it
    assert any(c[:3] == ["wg", "syncconf", "wtwg0"] for c in host.calls)
    assert set(host.live_peers["wtwg0"]) == {KEY_B}
    assert not any(c[:2] == ["systemctl", "restart"] for c in host.calls)
    assert [r["name"] for r in wla.list_workers(cfg)] == ["mac2"]
    assert not (pki / "worker-link" / "mac1.crt").exists()
    assert wla.remove_worker(cfg, "mac1") is False


def test_add_and_remove_refuse_an_override_the_host_is_not_running(host, pki, monkeypatch):
    """REGRESSION (review): BLASTBOX_WORKER_LINK_* overrides reach every host action. `add`
    with a stale HOST_IP / OVERLAY_NET / AGENT_PORT in the environment registered a peer and
    issued a bundle for an address or port the live interface and firewall do not serve."""
    wla.init_host(_cfg())
    conf = ea.WG_DIR / "wtwg0.conf"
    before = conf.read_text()
    for key, val in (("BLASTBOX_WORKER_LINK_HOST_IP", "10.78.0.9"),
                     ("BLASTBOX_WORKER_LINK_AGENT_PORT", "9443"),
                     ("BLASTBOX_WORKER_LINK_OVERLAY_NET", "10.78.0.0/25"),
                     ("BLASTBOX_WORKER_LINK_ENDPOINT", "other.example.org")):
        monkeypatch.setenv(key, val)
        with pytest.raises(RuntimeError, match="not running"):
            wla.add_worker(wla.load_config(), "mac1", KEY_A, _csr(_ip("10.78.0.2")),
                           pki_dir=pki)
        monkeypatch.delenv(key)
    assert conf.read_text() == before                         # nothing registered
    wla.add_worker(wla.load_config(), "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    monkeypatch.setenv("BLASTBOX_WORKER_LINK_AGENT_PORT", "9443")
    with pytest.raises(RuntimeError, match="agent port 9443"):
        wla.remove_worker(wla.load_config(), "mac1")


def test_peer_changes_are_synced_in_place_never_by_restarting_any_tunnel(host, pki):
    """REGRESSION (review): every add/remove/renewal went through egress_apply._reload_wg,
    which RESTARTS wg-quick@<iface> under systemd -- forgetting every worker's learned
    (roaming) endpoint and cutting them all off until their next keepalive. Peer-only
    changes are now `wg syncconf` on the LINK interface alone; a comment-only change (a
    renewal's new `# expires:`) touches nothing live; no other tunnel is ever named."""
    cfg = _cfg()
    wla.init_host(cfg)
    host.links.add("bbwg0")                                    # the egress overlay, also up
    host.calls.clear()
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.add_worker(cfg, "mac2", KEY_B, _csr(_ip("10.78.0.3")), pki_dir=pki)
    assert set(host.live_peers["wtwg0"]) == {KEY_A, KEY_B}
    host.calls.clear()
    _b, changed = wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), days=20,
                                 pki_dir=pki)                  # renewal: only # expires: moves
    assert changed and not any(c[:2] == ["wg", "syncconf"] for c in host.calls)
    flat = host.flat()
    assert "systemctl restart" not in flat and "wg-quick down" not in flat
    assert "bbwg0" not in flat
    # an idempotent re-init does not bounce a live, unchanged link either
    host.calls.clear()
    wla.init_host(cfg)
    assert "systemctl restart" not in host.flat() and "wg syncconf" not in host.flat()


def test_a_peer_change_that_cannot_reach_the_live_link_is_loud(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    host.syncconf_fails = True
    with pytest.raises(RuntimeError, match="to the live wtwg0"):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    assert not any(c[:2] == ["systemctl", "restart"] for c in host.calls)


def test_a_retry_after_a_failed_live_sync_reconciles_the_interface(host, pki):
    """REGRESSION (review): the file is written before `wg syncconf`; when the sync failed, a
    retry compared the file with ITSELF ("nothing changed"), skipped the sync and returned a
    bundle for a peer the live interface never got. The live peer set is now what is compared."""
    cfg = _cfg()
    wla.init_host(cfg)
    host.syncconf_fails = True
    with pytest.raises(RuntimeError, match="to the live wtwg0"):
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    assert "# peer:mac1" in (ea.WG_DIR / "wtwg0.conf").read_text()     # on disk already
    assert not host.live_peers.get("wtwg0")
    with pytest.raises(RuntimeError, match="to the live wtwg0"):     # still failing: loud
        wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    host.syncconf_fails = False
    _b, changed = wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    assert host.live_peers["wtwg0"] == {KEY_A: "10.78.0.2/32"}
    # the same for remove: file updated, live sync failed, the retry still takes it off
    host.syncconf_fails = True
    with pytest.raises(RuntimeError, match="to the live wtwg0"):
        wla.remove_worker(cfg, "mac1")
    host.syncconf_fails = False
    assert wla.remove_worker(cfg, "mac1") is False                      # gone from the file...
    assert host.live_peers["wtwg0"] == {}                               # ...and now live too


def test_teardown_keeps_the_firewall_while_the_link_unit_is_still_enabled(host):
    """REGRESSION (review): `systemctl disable --now` failing while `wg-quick down` succeeded
    passed the interface check, so teardown removed the firewall unit the still-ENABLED
    wg-quick unit Requires -- and the kept interface config came up unfirewalled at boot."""
    cfg = _cfg()
    wla.init_host(cfg)
    host.enabled.add("wg-quick@wtwg0")
    host.disable_fails = True
    notes = wla.teardown(cfg)
    assert "STILL ENABLED" in notes[-1]
    assert "wtwg0" not in host.links                                    # it did go down
    assert host.loaded is not None and wla.FW_UNIT.exists() and wla.FW_FILE.exists()
    assert wla.ENV_FILE.exists()
    host.disable_fails = False
    wla.teardown(cfg)
    assert host.loaded is None and not wla.FW_UNIT.exists()


def test_init_refuses_a_second_interface_when_the_env_file_is_gone(host):
    """REGRESSION (review): with the env file deleted but the old link's boot unit (and
    tunnel) still in place, init on a disjoint interface looked like a fresh install and
    replaced the node-global table and boot unit, leaving the old tunnel up unfirewalled."""
    wla.init_host(_cfg())
    loaded, unit = host.loaded, wla.FW_UNIT.read_text()
    wla.ENV_FILE.unlink()
    with pytest.raises(RuntimeError, match="already set up on wtwg0"):
        wla.init_host(_cfg(wg_iface="wtwg1", overlay_net="10.79.0.0/24", wg_port=51900))
    assert host.loaded == loaded and wla.FW_UNIT.read_text() == unit
    assert "wtwg1" not in host.links
    wla.init_host(_cfg())                                  # the installed one: fine


def test_a_changed_address_on_a_live_link_needs_a_real_restart(host):
    """REGRESSION (review): re-init with a new host address on a LIVE link went through
    egress_apply.wg_up, which accepts a `wg-quick strip` + `wg syncconf` fallback when the
    restart fails -- and the stripped config has no Address, so the interface kept the OLD
    address while init persisted and reported the new one under a firewall for the new one."""
    wla.init_host(_cfg())
    assert host.addrs["wtwg0"] == "10.78.0.1/24"
    host.restart_fails = True
    with pytest.raises(RuntimeError, match="NOT running the new config"):
        wla.init_host(_cfg(host_ip="10.78.0.7"))
    assert host.addrs["wtwg0"] == "10.78.0.1/24"
    assert not any(c[:2] == ["wg", "syncconf"] for c in host.calls)
    assert "HOST_IP=10.78.0.7" not in wla.ENV_FILE.read_text()      # not persisted
    host.restart_fails = False
    wla.init_host(_cfg(host_ip="10.78.0.7"))
    assert host.addrs["wtwg0"] == "10.78.0.7/24"
    assert "HOST_IP=10.78.0.7" in wla.ENV_FILE.read_text()


def test_init_checks_the_live_address_not_just_the_file(host):
    """The file can be current while the interface is not (a restart that failed after the
    file was written; a hand edit of the live address): init compares the KERNEL's address,
    restarts to apply the config, and refuses to report success if it still differs."""
    wla.init_host(_cfg())
    host.addrs["wtwg0"] = "10.78.0.99/24"          # drifted under an unchanged file
    host.calls.clear()
    wla.init_host(_cfg())
    assert ["systemctl", "restart", "wg-quick@wtwg0"] in host.calls
    assert host.addrs["wtwg0"] == "10.78.0.1/24"
    host.addrs["wtwg0"] = "10.78.0.99/24"
    host.restart_fails = True
    with pytest.raises(RuntimeError, match="NOT running the new config"):
        wla.init_host(_cfg())
    # and a restart that "succeeds" but leaves another address is still caught
    real = host._up
    host.restart_fails = False
    host._up = lambda iface: (real(iface), host.addrs.__setitem__(iface, "10.78.0.99/24"))
    with pytest.raises(RuntimeError, match="is up with 10.78.0.99/24, not 10.78.0.1/24"):
        wla.init_host(_cfg())


def test_status_teardown_list_and_remove_recover_without_the_env_file(host, pki, capsys):
    """REGRESSION (review): with /etc/blastbox/worker-link.env deleted but the link and its
    firewall unit still installed, `status` and `teardown` died loading the missing file --
    and for a non-default interface there was no way to name it. They now recover the
    installed config from the boot unit and the retained interface config."""
    from blastbox.worker import link

    cfg = _cfg(wg_iface="wtwg3", overlay_net="10.79.0.0/24")
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.79.0.2")), pki_dir=pki)
    wla.add_worker(cfg, "mac2", KEY_B, _csr(_ip("10.79.0.3")), pki_dir=pki)
    wla.ENV_FILE.unlink()
    capsys.readouterr()
    assert link._role(type("A", (), {"role": None})()) == "host"     # the unit still says so
    assert link.main(["status"]) == 1                                # never OK, but it RUNS
    out = capsys.readouterr().out
    assert "MISSING" in out and "interface wtwg3: up (10.79.0.1/24" in out
    assert link.main(["list"]) == 0 and "mac1" in capsys.readouterr().out
    assert link.main(["remove", "mac2", "--pki-dir", str(pki)]) == 0
    assert set(host.live_peers["wtwg3"]) == {KEY_A}
    csr = pki / "w.csr"
    csr.write_bytes(_csr(_ip("10.79.0.4")))
    assert link.main(["add", "mac3", "--public-key", KEY_B, "--csr", str(csr),
                      "--pki-dir", str(pki)]) == 1                   # enrolment needs the file
    assert "worker-link init" in capsys.readouterr().err
    assert link.main(["teardown"]) == 0
    assert "wtwg3" not in host.links and host.loaded is None and not wla.FW_UNIT.exists()


def test_status_for_a_name_that_is_not_installed_says_so_and_is_never_ok(host, monkeypatch):
    """Sweep (review round 5): a status for an interface other than the installed one compared
    the node-wide firewall against the wrong interface and described a link that does not
    exist. It now names the installed link and is never OK."""
    host.dump = "PRIV\tPUB\t51822\toff\n"
    wla.init_host(_cfg())
    ok, _rows = wla.status(_cfg())
    assert ok
    monkeypatch.setenv("BLASTBOX_WORKER_LINK_IF", "wtwg9")
    ok, rows = wla.status(wla.load_config())
    assert not ok and "installed on wtwg0, not wtwg9" in rows[0]


def test_init_refuses_a_wireguard_interface_it_did_not_create(host):
    """REGRESSION (review): `init --iface wg1` on the operator's own VPN rewrote
    /etc/wireguard/wg1.conf (its plain [Peer] blocks dropped) and restarted wg-quick@wg1.
    Refused before anything is written unless an install record or our own header proves
    the interface is worker-link's."""
    ea.WG_DIR.mkdir(parents=True, exist_ok=True)
    theirs = "[Interface]\nAddress = 10.66.0.2/24\nPrivateKey = THEIRS\n\n[Peer]\nPublicKey = X\n"
    (ea.WG_DIR / "wg1.conf").write_text(theirs)
    with pytest.raises(RuntimeError, match="wg1 is not a worker-link interface .*not written"):
        wla.init_host(_cfg(wg_iface="wg1"))
    assert (ea.WG_DIR / "wg1.conf").read_text() == theirs
    assert host.loaded is None and not wla.ENV_FILE.exists()
    assert not any(c[:2] in (["systemctl", "restart"], ["systemctl", "enable"]) for c in host.calls)
    # a live interface / an enabled unit under that name, with no config, is not ours either
    host.links.add("wg2")
    with pytest.raises(RuntimeError, match="interface wg2 is up"):
        wla.init_host(_cfg(wg_iface="wg2"))
    host.enabled.add("wg-quick@wg3")
    with pytest.raises(RuntimeError, match="wg-quick@wg3 is enabled or running"):
        wla.init_host(_cfg(wg_iface="wg3"))
    # ours (fresh, or retained by a teardown with our header) is fine
    wla.init_host(_cfg())
    wla.teardown(_cfg())
    wla.init_host(_cfg())


def test_reinit_never_silently_rotates_the_host_key(host, pki):
    """REGRESSION (review): with the key file deleted or emptied, ensure_keypair generated a
    NEW key and init restarted the interface with it -- every registered worker pins the old
    public key, so all of them lost their handshakes. The key is restored from the retained
    config; a mismatching one is refused; rotating takes --rotate-key."""
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    key = ea.KEY_DIR / "wtwg0.key"
    conf = ea.WG_DIR / "wtwg0.conf"
    for damage in (key.unlink, lambda: key.write_text("")):
        damage()
        pub, notes = wla.init_host(cfg)
        assert pub == HOST_PUB and "PrivateKey = PRIVATE-HOST-KEY\n" in conf.read_text()
        assert any("restored from" in n for n in notes)
    key.write_text("SOME-OTHER-KEY\n")
    with pytest.raises(RuntimeError, match="would silently rotate it"):
        wla.init_host(cfg)
    assert "PrivateKey = PRIVATE-HOST-KEY\n" in conf.read_text()        # untouched
    pub, notes = wla.init_host(cfg, rotate_key=True)
    assert pub != HOST_PUB and "PrivateKey = PRIVATE-HOST-KEY\n" not in conf.read_text()
    assert any("ROTATED" in n and "re-joined" in n for n in notes)
    assert "# peer:mac1" in conf.read_text()


def test_an_unverified_teardown_exits_non_zero(host, capsys):
    from blastbox.worker import link

    assert link.main(["init"]) == 0
    host.enabled.add("wg-quick@wtwg0")
    host.disable_fails = True
    assert link.main(["teardown"]) == 1
    assert "STILL ENABLED" in capsys.readouterr().out
    host.disable_fails = False
    assert link.main(["teardown"]) == 0


def _lock_is_held() -> bool:
    """True if another holder has the node-wide install lock (a non-blocking try fails)."""
    import fcntl

    path = wla.ENV_FILE.with_name(".worker-link.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def test_every_host_mutation_holds_one_node_wide_lock_end_to_end(host, pki, monkeypatch):
    """REGRESSION (review): init loaded its firewall BEFORE taking conf_lock, so two inits
    could interleave (B's firewall, A's interface, both "succeeding"), and an add could slip
    between an init's compatibility check and its address change. One lock now spans the
    whole of init / add / remove / teardown -- observed from inside each one's steps."""
    seen: dict[str, bool] = {}

    def spy(name, fn):
        def wrapped(*a, **kw):
            seen[name] = _lock_is_held()
            return fn(*a, **kw)
        return wrapped

    monkeypatch.setattr(wla, "_refuse_incompatible_reinit",
                        spy("init:checks", wla._refuse_incompatible_reinit))
    monkeypatch.setattr(wla, "install_firewall", spy("init:firewall", wla.install_firewall))
    monkeypatch.setattr(wla, "persist_config", spy("init:persist", wla.persist_config))
    monkeypatch.setattr(wla, "_apply_peers", spy("add/remove:apply", wla._apply_peers))
    monkeypatch.setattr(wla, "_nft_listing", spy("teardown:verify", wla._nft_listing))
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.remove_worker(cfg, "mac1")
    wla.teardown(cfg)
    assert seen and all(seen.values()), seen
    assert not _lock_is_held()                      # and released afterwards


def test_teardown_keeps_its_recovery_records_until_the_table_is_gone(host):
    """REGRESSION (review): a failed `nft delete table` was only a warning -- the env file and
    firewall unit were deleted anyway, so a retry had nothing left to find the install by,
    while the stale table kept filtering whatever later took that interface name."""
    wla.init_host(_cfg())
    host.nft_delete_fails = True
    notes = wla.teardown(_cfg())
    assert "still loaded" in notes[-1] and host.loaded is not None
    assert wla.ENV_FILE.exists() and wla.FW_UNIT.exists()
    assert wla._installed_ifaces() == {"wtwg0"}      # the retry can still find it
    # a removal that cannot be VERIFIED (no permission to list nftables) keeps them too
    host.nft_delete_fails = False
    host.root = False
    notes = wla.teardown(wla.load_config(recover=True))
    assert "could not verify" in notes[-1]
    assert wla.ENV_FILE.exists() and wla.FW_UNIT.exists()
    host.root = True
    wla.teardown(wla.load_config(recover=True))
    assert host.loaded is None and not wla.ENV_FILE.exists() and not wla.FW_UNIT.exists()


def test_an_interrupted_env_write_never_leaves_a_partial_record(host, monkeypatch):
    """REGRESSION (review): ENV_FILE.write_text truncated the record in place, so a failure
    mid-write left an empty or partial file where every recovery command looks."""
    from pathlib import Path as _P

    wla.init_host(_cfg())
    good = wla.ENV_FILE.read_text()
    real_write_text = _P.write_text

    def torn_write_text(self, data, *a, **kw):
        if self == wla.ENV_FILE:
            real_write_text(self, data[:10])          # what an interrupted write leaves
            raise OSError(28, "No space left on device")
        return real_write_text(self, data, *a, **kw)

    def failing_replace(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(_P, "write_text", torn_write_text)
    monkeypatch.setattr(ea.os, "replace", failing_replace)
    with pytest.raises(OSError):
        wla.persist_config(_cfg(agent_port=9443))
    assert wla.ENV_FILE.read_text() == good
    assert not [p for p in wla.ENV_FILE.parent.iterdir() if p.name.startswith(".worker-link.env.")]


def test_recovery_commands_survive_a_garbled_env_file(host, pki, capsys):
    """An env record that EXISTS but is empty or garbled (left by an older version, a hand
    edit) no longer blocks status/list/remove/teardown: they recover from the install."""
    from blastbox.worker import link

    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    for garbage in ("", "BLASTBOX_WORKER_LINK_OVERLAY_NET=not-a-network\n"):
        wla.ENV_FILE.write_text(garbage)
        capsys.readouterr()
        assert link.main(["status"]) == 1
        assert "MISSING or unusable" in capsys.readouterr().out
        assert link.main(["list"]) == 0 and "mac1" in capsys.readouterr().out
    assert link.main(["teardown"]) == 0
    assert host.loaded is None and not wla.ENV_FILE.exists()


# ----------------------------------------------------------------------------- status

def _dump(*peers) -> str:
    rows = ["PRIVATEKEYLINE\tpub\t51822\toff"]
    for key, hs in peers:
        rows.append(f"{key}\t(none)\t198.51.100.4:4500\t10.78.0.2/32\t{hs}\t10\t20\t25")
    return "\n".join(rows) + "\n"


def test_status_is_ok_only_when_the_kernel_says_so(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    now = 1_000_000.0
    host.dump = _dump((KEY_A, now - 12), (KEY_B, 0))
    ok, rows = wla.status(cfg, now=now)
    text = "\n".join(rows)
    assert ok, text
    assert "firewall: in force" in text and "mac1 10.78.0.2: handshake 12s ago" in text
    assert "UNREGISTERED key" in text and "PRIVATEKEYLINE" not in text
    # the ruleset FILE is still on disk, but the kernel lost the table: NOT in force
    host.loaded = None
    ok, rows = wla.status(cfg, now=now)
    assert not ok and any("NOT IN FORCE" in r for r in rows)


def test_status_reports_a_stale_or_absent_worker(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.add_worker(cfg, "mac2", KEY_B, _csr(_ip("10.78.0.3")), pki_dir=pki)
    now = 1_000_000.0
    host.dump = _dump((KEY_A, now - 3600))
    _ok, rows = wla.status(cfg, now=now)
    text = "\n".join(rows)
    assert "STALE" in text and "mac2 10.78.0.3: registered but NOT on the live interface" in text


def test_status_without_root_is_unverified_not_ok(host):
    cfg = _cfg()
    wla.init_host(cfg)
    host.root = False
    ok, rows = wla.status(cfg)
    assert not ok
    assert any(r.startswith("firewall: UNVERIFIED") for r in rows)
    assert any("handshakes: UNVERIFIED" in r for r in rows)


# --------------------------------------------------------------------------- teardown

def test_teardown_downs_the_link_before_removing_its_firewall_and_keeps_workers(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    host.calls.clear()
    notes = wla.teardown(cfg)
    flat = [" ".join(c) for c in host.calls]
    down = flat.index("systemctl disable --now wg-quick@wtwg0")
    delete = next(i for i, c in enumerate(flat) if c.startswith(f"nft delete table inet {NFT_TABLE}"))
    assert down < delete
    assert host.loaded is None and not wla.ENV_FILE.exists() and not wla.FW_FILE.exists()
    assert (ea.WG_DIR / "wtwg0.conf").exists()                 # registrations survive
    assert any("removed" in n for n in notes)


def test_teardown_leaves_the_firewall_if_the_link_will_not_go_down(host):
    cfg = _cfg()
    wla.init_host(cfg)
    host.stuck_up = True
    notes = wla.teardown(cfg)
    assert host.loaded is not None and "STILL UP" in notes[0]
    assert wla.ENV_FILE.exists()


def test_teardown_acts_on_the_persisted_interface_not_an_override(host, monkeypatch):
    """REGRESSION (review): `cfg` merges BLASTBOX_WORKER_LINK_IF over the persisted file. An
    override naming another interface made teardown stop and verify THAT one, then delete the
    (global) worker-link table and units -- leaving the real link up without its firewall."""
    wla.init_host(_cfg())
    host.links.add("other0")
    monkeypatch.setenv("BLASTBOX_WORKER_LINK_IF", "other0")
    host.calls.clear()
    with pytest.raises(RuntimeError, match="installed on wtwg0, not other0"):
        wla.teardown(wla.load_config())
    assert host.calls == []                         # nothing stopped, nothing deleted
    assert "wtwg0" in host.links and host.loaded is not None
    assert wla.FW_UNIT.exists() and wla.ENV_FILE.exists()
    # the firewall unit names the installed interface even if the env file is gone
    wla.ENV_FILE.unlink()
    with pytest.raises(RuntimeError, match="installed on wtwg0"):
        wla.teardown(_cfg(wg_iface="other0"))
    assert host.loaded is not None
    monkeypatch.delenv("BLASTBOX_WORKER_LINK_IF")
    wla.teardown(_cfg())                            # the installed one: proceeds
    assert host.loaded is None and "wtwg0" not in host.links


def test_reinit_after_teardown_still_refuses_to_strand_retained_workers(host, pki):
    """REGRESSION (review): teardown removes the env file but KEEPS the interface config and
    its registered workers. With no env file the re-init compatibility check returned early,
    so a new host address or a narrower overlay rewrote [Interface] under workers that still
    route and firewall only the old host /32. It is now checked against the retained file."""
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.9")), ip="10.78.0.9", pki_dir=pki)
    wla.teardown(cfg)
    assert not wla.ENV_FILE.exists() and "# peer:mac1" in (ea.WG_DIR / "wtwg0.conf").read_text()
    with pytest.raises(RuntimeError, match="10.78.0.1; changing it to 10.78.0.2 would strand"):
        wla.init_host(_cfg(host_ip="10.78.0.2"))
    with pytest.raises(RuntimeError, match="outside the new overlay"):
        wla.init_host(_cfg(overlay_net="10.78.0.0/29"))
    assert "Address = 10.78.0.1/24" in (ea.WG_DIR / "wtwg0.conf").read_text()   # untouched
    _pub, notes = wla.init_host(_cfg(wg_port=51900))
    assert any("listen port changed" in n for n in notes)
    assert any("was absent" in n for n in notes)
    assert "# peer:mac1" in (ea.WG_DIR / "wtwg0.conf").read_text()


def test_reinit_refuses_when_retained_workers_config_cannot_be_read_back(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), pki_dir=pki)
    wla.teardown(cfg)
    conf = ea.WG_DIR / "wtwg0.conf"
    conf.write_text(conf.read_text().replace("Address = 10.78.0.1/24\n", ""))
    with pytest.raises(RuntimeError, match="cannot be read back"):
        wla.init_host(cfg)


# ----------------------------------------------------------------------------- config

def test_load_config_requires_init_and_lets_the_environment_override(host, monkeypatch):
    with pytest.raises(wla.WorkerLinkNotInitialised):
        wla.load_config()
    assert wla.load_config(required=False) is None
    wla.persist_config(_cfg())
    monkeypatch.setenv("BLASTBOX_WORKER_LINK_AGENT_PORT", "9443")
    cfg = wla.load_config()
    assert cfg is not None and cfg.agent_port == 9443 and cfg.endpoint == "gw.example.org:51822"
    wla.ENV_FILE.write_text("# nothing\n")
    with pytest.raises(RuntimeError, match="no configuration"):
        wla.load_config()


def test_cert_expiry_is_recorded_for_list_and_status(host, pki):
    cfg = _cfg()
    wla.init_host(cfg)
    wla.add_worker(cfg, "mac1", KEY_A, _csr(_ip("10.78.0.2")), days=10, pki_dir=pki)
    exp = datetime.datetime.fromisoformat(wla.list_workers(cfg)[0]["cert_expires"])
    left = exp - datetime.datetime.now(datetime.timezone.utc)
    assert datetime.timedelta(days=9) < left <= datetime.timedelta(days=10)


# -------------------------------------------------------------------------------- CLI

def test_the_cli_drives_init_add_list_remove(host, pki, tmp_path, capsys):
    from blastbox.worker import link

    assert link.main(["init", "--endpoint", "gw.example.org:4500",
                      "--dispatcher-source", "172.18.0.0/16"]) == 0
    cfg = wla.load_config()
    assert cfg is not None and cfg.dispatcher_sources == ("172.18.0.0/16",)
    assert "masquerade" in host.loaded
    capsys.readouterr()
    csr = tmp_path / "w.csr"
    csr.write_bytes(_csr(_ip("10.78.0.2")))
    assert link.main(["add", "mac1", "--public-key", KEY_A, "--csr", str(csr),
                      "--pki-dir", str(pki)]) == 0
    out, err = capsys.readouterr()
    b = JoinBundle.from_json(out)                       # stdout is exactly the bundle
    assert b.endpoint == "gw.example.org:4500" and b.worker_ip == "10.78.0.2"
    assert "BLASTBOX_STATIC_WORKERS=https://10.78.0.2:8765" in err
    assert link.main(["list"]) == 0
    out, err = capsys.readouterr()
    assert "mac1" in out and "next free address: 10.78.0.3" in err
    assert link.main(["remove", "mac1", "--pki-dir", str(pki)]) == 0
    assert link.main(["remove", "mac1"]) == 1
    assert link.main(["init", "--no-dispatcher-source"]) == 0
    assert wla.load_config().dispatcher_sources == ()


def test_the_cli_reports_errors_without_a_traceback(host, capsys):
    from blastbox.worker import link

    assert link.main(["list"]) == 1
    assert "worker-link init" in capsys.readouterr().err
    assert link.main(["init", "--overlay-net", "203.0.113.0/24"]) == 1
    assert "RFC 1918" in capsys.readouterr().err
