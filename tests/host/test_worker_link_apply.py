"""Effects tests for ``blastbox worker-link`` on the HOST, against a simulated host.

No root, no ``wg``, no ``nft``: every command goes through ``egress_apply._run``/``_ok`` and is
answered by :class:`FakeHost`, which keeps just enough state (loaded ruleset, live interfaces)
to make ordering and read-back observable. All paths are redirected into ``tmp_path``.
"""
from __future__ import annotations

import datetime
import ipaddress
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
            self.loaded = None
        elif a[:3] == ["ip", "link", "show"]:
            rc = 0 if a[3] in self.links else 1
        elif a[:3] == ["ip", "-j", "route"] or a[:3] == ["ip", "-j", "addr"]:
            out = "[]"
        elif a[:2] == ["systemctl", "is-active"]:
            rc = 0 if a[2].split("@")[-1] in self.links else 3
        elif a[:3] == ["systemctl", "enable", "--now"] and a[3].startswith("wg-quick@"):
            self.links.add(a[3].split("@")[1])
        elif a[:3] == ["systemctl", "disable", "--now"] and a[3].startswith("wg-quick@"):
            if not self.stuck_up:
                self.links.discard(a[3].split("@")[1])
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

    def keypair(stem):
        ea.KEY_DIR.mkdir(parents=True, exist_ok=True)
        priv, pub = ea.KEY_DIR / f"{stem}.key", ea.KEY_DIR / f"{stem}.pub"
        priv.write_text("PRIVATE-HOST-KEY\n")
        os.chmod(priv, 0o600)
        pub.write_text(HOST_PUB + "\n")
        return priv, HOST_PUB

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
    assert ["systemctl", "restart", "wg-quick@wtwg0"] in host.calls   # the reload happened
    assert [r["name"] for r in wla.list_workers(cfg)] == ["mac2"]
    assert not (pki / "worker-link" / "mac1.crt").exists()
    assert wla.remove_worker(cfg, "mac1") is False


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


def test_the_cli_reports_errors_without_a_traceback(host, capsys):
    from blastbox.worker import link

    assert link.main(["list"]) == 1
    assert "worker-link init" in capsys.readouterr().err
    assert link.main(["init", "--overlay-net", "203.0.113.0/24"]) == 1
    assert "RFC 1918" in capsys.readouterr().err
