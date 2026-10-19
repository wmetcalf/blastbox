"""The WORKER end of ``blastbox worker-link`` (Linux and macOS), without root, wg, nft or launchd.

Platform is SIMULATED (``link._platform``), never skipped: both branches run on Linux CI and on
a Mac. Commands go through ``link._run``; ``openssl`` is the one tool run for real, because the
CSR it makes and the certificate checks it does are exactly what must interoperate with the
host's ``cryptography`` signer (and LibreSSL on macOS vs OpenSSL on Linux is a real
difference). The macOS watchdog is executed for real under ``/bin/sh`` against fake
``wg``/``wg-quick``/``pfctl``, because its two regressions were behavioural.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from blastbox.worker import link

KEY_HOST = "H" * 43 + "="
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


def _wg_pub(private: str) -> str:
    return base64.b64encode(hashlib.sha256(private.strip().encode()).digest()).decode()


class FakeNode:
    """Answers every non-openssl command a worker would run; openssl runs for real."""

    def __init__(self, tmp: Path, platform: str) -> None:
        self.tmp, self.platform = tmp, platform
        self.calls: list[list[str]] = []
        self.loaded: str | None = None
        self.links: set[str] = set()
        self.route_dev = "eth0"
        self.handshake = True
        self.root = True
        self.nft_drop_missing = False
        self.genkeys = 0
        #: device -> `ip -d -j link` info_kind for a tunnel; anything else reads as ethernet
        self.tunnels: dict[str, str] = {}
        #: what `route -n get` (macOS) reports as the endpoint's interface
        self.mac_route_dev = "en0"
        self.wg_quick_down_works = True

    def run(self, argv, *, input=None):
        a = [str(x) for x in argv]
        tool = Path(a[0]).name
        if tool == "openssl":
            self.calls.append(a)
            return subprocess.run(a, input=input, text=True, capture_output=True, check=False)
        self.calls.append(a)
        rc, out, err = 0, "", ""
        if tool == "wg" and a[1] == "genkey":
            self.genkeys += 1
            out = base64.b64encode(os.urandom(32)).decode() + "\n"
        elif tool == "wg" and a[1] == "pubkey":
            out = _wg_pub(input or "") + "\n"
        elif tool == "wg" and a[1] == "show":
            if not self.root:
                rc, err = 1, "Operation not permitted"
            else:
                hs = "1700000000" if self.handshake else "0"
                out = ("PRIV\tPUB\t0\toff\n"
                       f"{KEY_HOST}\t(none)\t192.0.2.10:51822\t10.78.0.1/32\t{hs}\t1\t2\t25\n")
                if self.handshake:
                    import time
                    out = out.replace("1700000000", str(int(time.time()) - 5))
        elif tool == "nft" and a[1] == "-f":
            text = Path(a[2]).read_text()
            body = text.split(f"delete table inet {link.NFT_TABLE}\n", 1)[1]
            if self.nft_drop_missing:
                body = body.replace('\t\tiifname "wtwg0" drop\n', "")
            self.loaded = body
        elif tool == "nft" and a[1:3] == ["list", "table"]:
            if not self.root:
                rc, err = 1, "Error: Operation not permitted"
            elif self.loaded is None:
                rc, err = 1, "Error: No such file or directory"
            else:
                out = self.loaded
        elif tool == "nft" and a[1:3] == ["delete", "table"]:
            self.loaded = None
        elif a[:4] == ["ip", "-d", "-j", "link"]:
            dev = a[-1]
            kind = self.tunnels.get(dev)
            out = json.dumps([{"ifname": dev, "link_type": "none" if kind else "ether",
                               **({"linkinfo": {"info_kind": kind}} if kind else {})}])
        elif a[:3] == ["route", "-n", "get"]:
            out = (f"   route to: {a[-1]}\ndestination: default\n"
                   f"  interface: {self.mac_route_dev}\n")
        elif tool == "wg-quick" and a[1] in ("down", "up"):
            if a[1] == "down" and self.wg_quick_down_works:
                self.links.discard(a[2])
                (link.WG_RUN_DIR / f"{a[2]}.name").unlink(missing_ok=True)
            elif a[1] == "up":
                self.links.add(a[2])
        elif a[:3] == ["ip", "-j", "route"] and "get" in a:
            out = json.dumps([{"dst": a[-1], "dev": self.route_dev}])
        elif a[:2] == ["ip", "-j"]:
            out = "[]"
        elif a[:3] == ["ip", "link", "show"]:
            rc = 0 if a[3] in self.links else 1
        elif a[:2] == ["systemctl", "is-active"]:
            rc = 3
        elif a[:3] == ["systemctl", "enable", "--now"] and a[3].startswith("wg-quick@"):
            self.links.add(a[3].split("@")[1])
        elif a[:3] == ["systemctl", "disable", "--now"] and a[3].startswith("wg-quick@"):
            self.links.discard(a[3].split("@")[1])
        elif tool == "launchctl" and a[1] == "print":
            rc = 1
        elif tool == "launchctl" and a[1] == "bootstrap":
            # what RunAtLoad would do: the watchdog brings the tunnel up as some utun
            (link.WG_RUN_DIR / "wtwg0.name").write_text("utun7\n")
        elif tool == "launchctl" and a[1] == "bootout":
            (link.WG_RUN_DIR / "wtwg0.name").unlink(missing_ok=True)
        elif tool == "pfctl" and "info" in a:
            out = "Status: Enabled for 0 days\n"
        elif tool == "pfctl" and "rules" in a and "-a" not in a:
            out = 'anchor "com.apple/*" all\n'
        elif tool == "pfctl" and "rules" in a:
            out = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                agent_port=8765)
        return subprocess.CompletedProcess(a, rc, out, err)

    def flat(self) -> list[str]:
        return [" ".join(c) for c in self.calls]


@pytest.fixture
def node(tmp_path, monkeypatch):
    from blastbox.host import egress_apply as ea

    def make(platform: str = "linux") -> FakeNode:
        n = FakeNode(tmp_path, platform)
        monkeypatch.setattr(link, "_run", n.run)
        monkeypatch.setattr(link, "_platform", lambda: platform)
        monkeypatch.setattr(link, "_euid", lambda: 0)
        monkeypatch.setattr(link, "_sleep", lambda s: None)
        monkeypatch.setattr(link, "_chown", lambda path, uid, gid: None)
        monkeypatch.setattr(link, "_root_owned_and_private", lambda st: True)
        monkeypatch.setattr(link, "HANDSHAKE_WAIT_S", 0.0)
        monkeypatch.setattr(link, "_resolve", lambda host: ["192.0.2.10"])
        monkeypatch.setattr(link, "_which", lambda name: (
            shutil.which("openssl") if name == "openssl" else f"/fake/bin/{name}"))
        for attr, sub in (("WG_DIR", "wireguard"), ("STATE_DIR", "state"),
                          ("LAUNCHD_DIR", "LaunchDaemons"), ("SUPPORT_DIR", "support"),
                          ("WG_RUN_DIR", "run")):
            monkeypatch.setattr(link, attr, tmp_path / sub)
        monkeypatch.setattr(link, "KEY_DIR", tmp_path / "wireguard" / "blastbox")
        monkeypatch.setattr(link, "FW_FILE", tmp_path / "worker-link-peer.nft")
        monkeypatch.setattr(link, "FW_UNIT", tmp_path / "units" / link.FW_UNIT_NAME)
        monkeypatch.setattr(link, "EGRESS_ENV", tmp_path / "egress.env")
        (tmp_path / "run").mkdir()
        # linux_preflight's route checks go through egress_apply's seam
        monkeypatch.setattr(ea, "_run", lambda argv, **kw: n.run(argv))
        monkeypatch.setattr(ea, "host_route_cidrs", lambda: ["192.168.1.0/24"])
        monkeypatch.setattr(ea, "claimed_cidrs", lambda: ["192.168.1.0/24"])
        return n

    return make


def _host_sign(tmp_path: Path, csr: str, ip: str) -> tuple[str, str]:
    pytest.importorskip("cryptography")
    from blastbox.host.pki import ensure_ca

    ca = ensure_ca(tmp_path / "pki")
    cert = ca.sign_csr_for_ip(csr.encode(), ip, cn="worker-link:w1", days=5)
    return ca.cert_pem.decode(), cert.decode()


def _bundle(tmp_path: Path, csr: str, ip: str = "10.78.0.5", **kw) -> str:
    from blastbox.host.worker_link import JoinBundle

    ca, cert = _host_sign(tmp_path, csr, kw.pop("san", ip))
    b = dict(name="w1", iface="wtwg0", worker_ip=ip, host_ip="10.78.0.1",
             overlay_net="10.78.0.0/24", endpoint="gw.example.org:51822",
             host_public_key=KEY_HOST, agent_port=8765, ca_pem=ca, cert_pem=cert)
    b.update(kw)
    return JoinBundle(**b).to_json()


# ---------------------------------------------------------------------------- renderers

def test_worker_config_routes_only_the_host_and_keeps_the_nat_open():
    c = link.worker_wg_config(private_key="PRIV\n", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                              host_public_key=KEY_HOST, endpoint="gw.example.org:51822")
    assert "Address = 10.78.0.5/32\n" in c
    assert "AllowedIPs = 10.78.0.1/32\n" in c and "0.0.0.0/0" not in c
    assert "PersistentKeepalive = 25\n" in c and "Endpoint = gw.example.org:51822\n" in c
    assert "Table" not in c and "FwMark" not in c and "PostUp" not in c


def test_worker_firewall_admits_only_the_host_to_the_agent_port():
    fw = link.worker_firewall_nft(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                  agent_port=8765)
    inp = fw.split("chain input {\n", 1)[1].split("\n\t}", 1)[0]
    assert ('iifname "wtwg0" ip saddr 10.78.0.1 ip daddr 10.78.0.5 tcp dport 8765 '
            "ct state new accept") in inp
    assert 'iifname != { "lo", "wtwg0" } ip daddr 10.78.0.5 drop' in inp
    fwd = fw.split("chain forward {\n", 1)[1].split("\n\t}", 1)[0]
    assert 'iifname "wtwg0" drop' in fwd and 'oifname "wtwg0" drop' in fwd
    out = fw.split("chain output {\n", 1)[1].split("\n\t}", 1)[0]
    assert "new" not in out and out.strip().endswith('oifname "wtwg0" drop')
    from blastbox.host.worker_link import firewall_in_force
    assert firewall_in_force(fw.split(f"delete table inet {link.NFT_TABLE}\n", 1)[1], fw) == []


def test_a_job_container_cannot_reach_the_control_link_from_inside_the_worker():
    """Compatibility with egress (2): a job's netns is routed by THIS node. Whatever its
    personality, a packet toward the host's overlay address is FORWARDED (dropped: no
    forwarding into the link), and a packet toward this worker's own overlay address arrives
    on a docker bridge, not the link (dropped: off-link traffic to the overlay address)."""
    fw = link.worker_firewall_nft(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                  agent_port=8765)
    assert '\t\toifname "wtwg0" drop\n' in fw.split("chain forward {")[1]
    assert 'iifname != { "lo", "wtwg0" } ip daddr 10.78.0.5 drop' in fw


def test_a_containerised_agent_published_on_the_overlay_address_is_reachable():
    """docker publishes `-p 10.78.0.5:8765:8765` by DNAT, so the host's connection is a
    FORWARD. Admit exactly that (matched on the pre-DNAT tuple) -- and still nothing else."""
    fw = link.worker_firewall_nft(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                  agent_port=8765)
    fwd = fw.split("chain forward {\n", 1)[1].split("\n\t}", 1)[0]
    rule = ('iifname "wtwg0" ip saddr 10.78.0.1 ct original ip daddr 10.78.0.5 '
            "ct original proto-dst 8765 ct status dnat ct state new accept")
    assert rule in fwd
    lines = [ln.strip() for ln in fwd.splitlines()]
    assert lines[-2:] == ['iifname "wtwg0" drop', 'oifname "wtwg0" drop']
    assert sum("ct state new accept" in ln for ln in lines) == 1   # nothing NEW leaves via the link


@pytest.mark.parametrize("bad", [dict(worker_ip="x"), dict(host_ip="10.78.0.1/24"),
                                 dict(agent_port=0), dict(iface="wt wg")])
def test_renderers_validate(bad):
    kw = dict(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1", agent_port=8765)
    kw.update(bad)
    with pytest.raises(ValueError):
        link.worker_firewall_nft(**kw)


def test_csr_config_has_a_single_ip_san():
    c = link.csr_config("10.78.0.5")
    assert "subjectAltName = IP:10.78.0.5\n" in c and "DNS" not in c
    with pytest.raises(ValueError):
        link.csr_config("10.78.0.5\nsubjectAltName = DNS:evil")


# --------------------------------------------------------------------- macOS: launchd

def test_launchd_plist_abandons_its_process_group():
    """REGRESSION (live Mac): without AbandonProcessGroup launchd kills wireguard-go -- left in
    the watchdog's process group by `wg-quick up` -- as soon as the watchdog exits."""
    p = plistlib.loads(link.launchd_plist(label="io.blastbox.worker-link.wtwg0",
                                          script="/Library/x.sh"))
    assert p["AbandonProcessGroup"] is True
    assert p["RunAtLoad"] is True and p["StartInterval"] == 30
    assert p["ProgramArguments"] == ["/bin/sh", "/Library/x.sh"]
    assert "UserName" not in p and "KeepAlive" not in p          # a root, periodic daemon


def test_watchdog_never_asks_wg_about_the_wg_quick_name():
    """REGRESSION (live Mac): `wg show wtwg0` cannot work on macOS -- the kernel knows only the
    utunN recorded in /var/run/wireguard/wtwg0.name -- so a watchdog asking it saw "down"
    every 30 s and tore down a healthy tunnel."""
    s = link.watchdog_script(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                             agent_port=8765, wg="/opt/homebrew/bin/wg",
                             wg_quick="/opt/homebrew/bin/wg-quick")
    assert "NAMEFILE='/var/run/wireguard/wtwg0.name'" in s
    assert '"$WG" show "$REAL"' in s
    for wrong in ('show "$IFACE"', "show wtwg0", 'show "wtwg0"'):
        assert wrong not in s


def _fake_bin(d: Path, name: str, body: str) -> str:
    p = d / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return str(p)


@pytest.fixture
def mac(tmp_path):
    """The real watchdog, under /bin/sh, against fake wireguard-tools and pfctl."""
    bin_d, run_d = tmp_path / "bin", tmp_path / "run"
    bin_d.mkdir()
    run_d.mkdir()
    log = tmp_path / "calls.log"
    state = tmp_path / "state"
    state.mkdir()
    (state / "up").write_text("")
    (state / "pf").write_text("Enabled")
    (state / "main").write_text('anchor "com.apple/*" all\n')
    env_hdr = f'LOG={log}; ST={state}; RUN={run_d}\necho "$(basename "$0") $*" >> "$LOG"\n'
    wg = _fake_bin(bin_d, "wg", env_hdr + (
        '[ "$1" = show ] && grep -qx "$2" "$ST/up" && exit 0\nexit 1\n'))
    wgq = _fake_bin(bin_d, "wg-quick", env_hdr + (
        'if [ "$1" = up ]; then echo utun9 > "$RUN/$2.name"; echo utun9 >> "$ST/up"; fi\n'
        'if [ "$1" = down ]; then rm -f "$RUN/$2.name"; fi\nexit 0\n'))
    pfctl = _fake_bin(bin_d, "pfctl", env_hdr + (
        'case "$*" in\n'
        '  *"-s info"*) echo "Status: $(cat "$ST/pf")"; exit 0 ;;\n'
        '  *"-E"*) echo Enabled > "$ST/pf"; exit 0 ;;\n'
        '  *"-a "*"-s rules"*) cat "$ST/anchor" 2>/dev/null; exit 0 ;;\n'
        '  *"-s rules"*) cat "$ST/main"; exit 0 ;;\n'
        '  *"-f -"*) cat > "$ST/anchor"; echo "LOADED $(head -1 "$ST/anchor")" >> "$LOG"; exit 0 ;;\n'
        "esac\nexit 0\n"))
    script = tmp_path / "watchdog.sh"
    script.write_text(link.watchdog_script(
        iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1", agent_port=8765,
        wg=wg, wg_quick=wgq, pfctl=pfctl, run_dir=str(run_d), state_dir=str(state)))

    class Mac:
        def run(self) -> list[str]:
            log.write_text("")
            r = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True,
                               timeout=30, check=False)
            assert r.returncode == 0, r.stdout + r.stderr
            return log.read_text().splitlines()

        def up(self, real: str) -> None:
            (run_d / "wtwg0.name").write_text(real + "\n")
            (state / "up").write_text(real + "\n")

        def name(self, text: str) -> None:
            (run_d / "wtwg0.name").write_text(text)

        def pf(self, status: str) -> None:
            (state / "pf").write_text(status)

        def anchor(self) -> str:
            return (state / "anchor").read_text()

        def main_rules(self, text: str) -> None:
            (state / "main").write_text(text)

        def rerender(self, **kw) -> None:
            args = dict(iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                        agent_port=8765, wg=wg, wg_quick=wgq, pfctl=pfctl, run_dir=str(run_d),
                        state_dir=str(state))
            args.update(kw)
            script.write_text(link.watchdog_script(**args))

    return Mac()


def test_watchdog_leaves_a_healthy_tunnel_alone(mac):
    mac.up("utun7")
    calls = mac.run()
    assert not any(c.startswith("wg-quick") for c in calls), calls
    assert "wg show utun7" in calls
    # ...but still asserts pf for the CURRENT utun
    assert "pass in quick on utun7 inet proto tcp from 10.78.0.1 to 10.78.0.5 port 8765" in mac.anchor()
    calls = mac.run()           # converged: nothing reloaded the second time
    assert not any(c.startswith("LOADED") for c in calls), calls


def test_watchdog_brings_a_down_tunnel_up_behind_closed_rules(mac):
    calls = mac.run()
    up = calls.index("wg-quick up wtwg0")
    closed = next(i for i, c in enumerate(calls) if c.startswith("LOADED block drop quick inet"))
    opened = next(i for i, c in enumerate(calls) if c.startswith("LOADED pass in quick on utun9"))
    assert closed < up < opened
    assert "wg-quick down wtwg0" in calls[:up]


def test_watchdog_reups_when_the_recorded_utun_is_dead(mac):
    mac.name("utun7\n")          # name file present, but wg does not know utun7
    calls = mac.run()
    assert "wg show utun7" in calls and "wg-quick up wtwg0" in calls


def test_watchdog_does_not_trust_a_malformed_name_file(mac):
    mac.name("utun7; touch /tmp/pwned\n")
    calls = mac.run()
    assert "wg-quick up wtwg0" in calls
    assert not any("pwned" in c for c in calls if c.startswith("wg "))


def test_watchdog_enables_pf_when_macos_left_it_disabled(mac):
    mac.up("utun7")
    mac.pf("Disabled")
    calls = mac.run()
    assert "pfctl -E" in calls


def test_watchdog_takes_the_link_down_when_pf_no_longer_evaluates_the_anchor(mac):
    """A VPN/kill-switch app that loads its own main ruleset drops anchor "com.apple/*": our
    anchor is then text, so the link must go down."""
    mac.up("utun7")
    mac.main_rules("pass all\n")
    with pytest.raises(AssertionError, match="does not evaluate"):
        mac.run()


def test_a_changed_agent_port_reloads_pf_even_with_the_tunnel_up(mac):
    mac.up("utun7")
    mac.run()
    mac.rerender(agent_port=9443)
    calls = mac.run()
    assert not any(c.startswith("wg-quick") for c in calls)
    assert "port 9443" in mac.anchor()


def test_watchdog_takes_the_link_down_when_pf_cannot_be_enabled(tmp_path):
    """Rules in a disabled pf are text, not enforcement: no pf, no link."""
    bin_d, run_d = tmp_path / "bin", tmp_path / "run"
    bin_d.mkdir()
    run_d.mkdir()
    log = tmp_path / "calls.log"
    hdr = f'echo "$(basename "$0") $*" >> {log}\n'
    wg = _fake_bin(bin_d, "wg", hdr + "exit 0\n")
    wgq = _fake_bin(bin_d, "wg-quick", hdr + "exit 0\n")
    pfctl = _fake_bin(bin_d, "pfctl", hdr + 'case "$*" in *"-s info"*) echo "Status: Disabled";; esac\nexit 0\n')
    (run_d / "wtwg0.name").write_text("utun7\n")
    script = tmp_path / "w.sh"
    script.write_text(link.watchdog_script(
        iface="wtwg0", worker_ip="10.78.0.5", host_ip="10.78.0.1", agent_port=8765,
        wg=wg, wg_quick=wgq, pfctl=pfctl, run_dir=str(run_d)))
    r = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, timeout=30)
    calls = log.read_text().splitlines()
    assert r.returncode == 1 and "pfctl -E" in calls and "wg-quick down wtwg0" in calls
    assert "wg-quick up wtwg0" not in calls


def test_pf_rules_and_their_read_back():
    rules = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                          agent_port=8765)
    ok = dict(info="Status: Enabled for 1 days", main_rules='anchor "com.apple/*" all',
              anchor_rules=rules, real_iface="utun7", worker_ip="10.78.0.5",
              host_ip="10.78.0.1", agent_port=8765)
    assert link.pf_in_force(**ok) == []
    assert link.pf_in_force(**{**ok, "info": "Status: Disabled"})
    assert link.pf_in_force(**{**ok, "main_rules": ""})
    assert link.pf_in_force(**{**ok, "real_iface": "utun8"})          # stale utun
    assert link.pf_in_force(**{**ok, "anchor_rules": rules.splitlines()[0]})
    assert link.pf_in_force(**{**ok, "agent_port": 9443})               # stale port
    # pfctl's own rendering (`port = N`) is accepted
    assert link.pf_in_force(**{**ok, "anchor_rules": rules.replace("port 8765", "port = 8765")}) == []
    with pytest.raises(ValueError):
        link.pf_rules(real_iface="en0", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                      agent_port=8765)


# ------------------------------------------------------------------------------ keygen

@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_keygen_keeps_private_keys_on_disk_and_prints_only_public_material(node, platform):
    n = node(platform)
    pub, csr, notes = link.keygen("wtwg0", "10.78.0.5")
    p = link._paths("wtwg0")
    priv = p["wg_key"].read_text().strip()
    assert pub == _wg_pub(priv)
    for f in (p["wg_key"], p["tls_key"]):
        assert oct(f.stat().st_mode & 0o777) == "0o600"
    out = pub + csr + "\n".join(notes)
    assert priv not in out and "PRIVATE KEY" not in out
    # the private key never appears in any argv either
    assert not any(priv in " ".join(c) for c in n.calls)
    pytest.importorskip("cryptography")
    from cryptography import x509
    req = x509.load_pem_x509_csr(csr.encode())
    sans = req.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(g.value) for g in sans] == ["10.78.0.5"]


def test_keygen_is_idempotent_and_rotates_only_on_request(node):
    n = node("linux")
    pub1, _c, _ = link.keygen("wtwg0", "10.78.0.5")
    tls1 = link._paths("wtwg0")["tls_key"].read_text()
    pub2, csr2, _ = link.keygen("wtwg0", "10.78.0.6")      # new address: new CSR, same keys
    assert pub2 == pub1 and link._paths("wtwg0")["tls_key"].read_text() == tls1
    assert json.loads(link._paths("wtwg0")["state"].read_text())["worker_ip"] == "10.78.0.6"
    pub3, _c, _ = link.keygen("wtwg0", "10.78.0.6", rotate=True)
    assert pub3 != pub1 and n.genkeys == 2


def test_keygen_refuses_non_root_public_addresses_and_windows(node, monkeypatch):
    node("linux")
    with pytest.raises(ValueError):
        link.keygen("wtwg0", "203.0.113.7")
    monkeypatch.setattr(link, "_euid", lambda: 501)
    with pytest.raises(RuntimeError, match="sudo"):
        link.keygen("wtwg0", "10.78.0.5")
    monkeypatch.setattr(link, "_euid", lambda: 0)
    monkeypatch.setattr(link, "_platform", lambda: "win32")
    with pytest.raises(RuntimeError, match="libvirt"):
        link.keygen("wtwg0", "10.78.0.5")


# ------------------------------------------------------------------------- join: Linux

def test_linux_join_firewalls_before_the_link_and_prints_the_agent_env(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    notes = link.join(_bundle(tmp_path, csr), agent_user=None)
    flat = n.flat()
    fw = next(i for i, c in enumerate(flat) if c.startswith("/fake/bin/nft -f"))
    up = flat.index("systemctl enable --now wg-quick@wtwg0")
    assert fw < up
    p = link._paths("wtwg0")
    conf = p["conf"].read_text()
    assert oct(p["conf"].stat().st_mode & 0o777) == "0o600"
    assert "AllowedIPs = 10.78.0.1/32" in conf and "Endpoint = gw.example.org:51822" in conf
    text = "\n".join(notes)
    for want in ("BLASTBOX_WORKER_AGENT_BIND=10.78.0.5",
                 "BLASTBOX_WORKER_AGENT_ALLOW_CIDRS=10.78.0.1/32",
                 f"BLASTBOX_WORKER_AGENT_TLS_CERT={p['cert']}",
                 f"BLASTBOX_WORKER_AGENT_TLS_KEY={p['tls_key']}",
                 f"BLASTBOX_WORKER_AGENT_CLIENT_CA={p['ca']}", "handshake with the host: OK",
                 "firewall: in force"):
        assert want in text, want
    assert f"systemctl enable {link.FW_UNIT_NAME}" in flat
    assert link.FW_UNIT.read_text().count("Before=wg-quick@wtwg0.service") == 1


def test_join_refuses_a_bundle_for_another_address(node, tmp_path):
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    other = link.csr_config  # noqa: F841 -- (readability: the CSR is for .5, the bundle for .6)
    with pytest.raises(RuntimeError, match="keygen made"):
        link.join(_bundle(tmp_path, csr, ip="10.78.0.6", san="10.78.0.5"))
    assert not link._paths("wtwg0")["conf"].exists()


def test_join_refuses_a_certificate_for_another_key(node, tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import ipaddress

    node("linux")
    link.keygen("wtwg0", "10.78.0.5")
    foreign = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([]))
               .add_extension(x509.SubjectAlternativeName(
                   [x509.IPAddress(ipaddress.ip_address("10.78.0.5"))]), critical=False)
               .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
               .public_bytes(serialization.Encoding.PEM).decode())
    with pytest.raises(RuntimeError, match="not for this worker's TLS key"):
        link.join(_bundle(tmp_path, foreign))
    assert not link._paths("wtwg0")["conf"].exists()


def test_join_refuses_a_certificate_from_another_ca(node, tmp_path):
    from blastbox.host.worker_link import JoinBundle

    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    good = JoinBundle.from_json(_bundle(tmp_path, csr))
    other_ca, _ = _host_sign(tmp_path / "other", csr, "10.78.0.5")
    swapped = JoinBundle(**{**good.__dict__, "ca_pem": other_ca})
    with pytest.raises(RuntimeError, match="does not verify"):
        link.join(swapped.to_json())


def test_join_refuses_when_the_endpoint_would_ride_the_egress_tunnel(node, tmp_path):
    """Compatibility with egress (2): the handshake must use the UNDERLAY. If this node routes
    the endpoint via bbwg0 (or via the link itself), refuse rather than build a control link
    that silently depends on the egress exit."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.route_dev = "bbwg0"
    with pytest.raises(RuntimeError, match="via bbwg0"):
        link.join(_bundle(tmp_path, csr))
    assert n.loaded is None and "wtwg0" not in n.links
    p = link._paths("wtwg0")
    assert not p["conf"].exists() and not p["cert"].exists()     # refused before any write


def test_join_refuses_to_share_the_egress_interface_or_overlay(node, tmp_path):
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.EGRESS_ENV.write_text("BLASTBOX_EGRESS_OVERLAY_NET=10.78.0.0/16\n")
    with pytest.raises(RuntimeError, match="egress overlay"):
        link.join(_bundle(tmp_path, csr))
    link.EGRESS_ENV.write_text("BLASTBOX_EGRESS_WG_IF=wtwg0\n")
    with pytest.raises(RuntimeError, match="egress overlay interface"):
        link.join(_bundle(tmp_path, csr))


def test_join_does_not_bring_the_link_up_unless_the_firewall_reads_back(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.nft_drop_missing = True
    with pytest.raises(RuntimeError, match="not in force"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


# ------------------------------------------------------------------------- join: macOS

def test_macos_join_installs_the_watchdog_daemon_and_no_linux_machinery(node, tmp_path):
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    notes = link.join(_bundle(tmp_path, csr))
    p = link._paths("wtwg0")
    assert oct(p["conf"].stat().st_mode & 0o777) == "0o600"
    plist = plistlib.loads(p["plist"].read_bytes())
    assert plist["AbandonProcessGroup"] is True and plist["ProgramArguments"][1] == str(p["script"])
    assert oct(p["script"].stat().st_mode & 0o777) == "0o755"
    assert "/fake/bin/wg-quick" in p["script"].read_text()
    flat = n.flat()
    assert f"launchctl bootstrap system {p['plist']}" in flat
    assert not any(c.startswith(("systemctl", "/fake/bin/nft", "nft", "ip ")) for c in flat)
    assert any("up as utun7" in x for x in notes)


def test_macos_status_reads_pf_and_the_real_utun(node, tmp_path):
    node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    ok, rows = link.status("wtwg0")
    assert ok, rows
    assert "interface wtwg0: up as utun7" in rows and "firewall (pf): in force" in rows


# ------------------------------------------------------------------------ status/leave

def test_linux_status_is_ok_only_with_firewall_and_a_fresh_handshake(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    ok, rows = link.status("wtwg0")
    assert ok, rows
    n.loaded = None                       # file still on disk; the kernel lost the table
    ok, rows = link.status("wtwg0")
    assert not ok and any("NOT IN FORCE" in r for r in rows)
    n.root = False
    ok, rows = link.status("wtwg0")
    assert not ok and any("UNVERIFIED" in r for r in rows)


def test_leave_downs_the_link_before_dropping_its_firewall(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.calls.clear()
    link.leave("wtwg0")
    flat = n.flat()
    assert flat.index("systemctl disable --now wg-quick@wtwg0") < flat.index(
        f"nft delete table inet {link.NFT_TABLE}")
    p = link._paths("wtwg0")
    assert not p["conf"].exists() and p["wg_key"].exists()
    link.leave("wtwg0", purge=True)
    assert not p["wg_key"].exists() and not p["tls_key"].exists()


# ------------------------------------------------------------------------------ wiring

def test_the_worker_half_never_imports_cryptography():
    """A worker may install blastbox without [host]; the whole worker-link CLI must load."""
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'cryptography' or name.startswith('cryptography.'):\n"
        "            raise ImportError('blocked: ' + name)\n"
        "sys.meta_path.insert(0, Block())\n"
        "from blastbox.worker import link\n"
        "import argparse\n"
        "p = argparse.ArgumentParser(); link.add_parser(p.add_subparsers(dest='c'))\n"
        "p.parse_args(['worker-link', 'keygen', '--ip', '10.78.0.5'])\n"
        "link.worker_wg_config(private_key='k', worker_ip='10.78.0.5', host_ip='10.78.0.1',\n"
        "                      host_public_key='k', endpoint='h:1')\n"
        "assert not any(m.startswith('cryptography') for m in sys.modules)\n"
    )
    src = str(Path(__file__).resolve().parents[2] / "src")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": src}, check=False)
    assert r.returncode == 0, r.stderr


def test_the_full_cli_registers_worker_link():
    pytest.importorskip("fastapi")
    from blastbox.host.cli import build_parser

    args = build_parser().parse_args(["worker-link", "status", "--role", "worker"])
    assert args.worker_link_action == "status"


def test_macos_rejoin_with_a_changed_config_re_ups_the_live_tunnel(node, tmp_path):
    """The watchdog never touches a tunnel that is up -- so a re-join (new host key, endpoint,
    address) must take it down itself, or the old config stays live indefinitely."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.calls.clear()
    link.join(_bundle(tmp_path, csr))                      # identical: tunnel left alone
    assert "/fake/bin/wg-quick down wtwg0" not in n.flat()
    link.join(_bundle(tmp_path, csr, endpoint="gw2.example.org:51822"))
    assert "/fake/bin/wg-quick down wtwg0" in n.flat()


def test_a_linux_rejoin_with_the_link_up_does_not_refuse_its_own_routes(node, tmp_path, monkeypatch):
    """REGRESSION (review): iproute2 prints the host /32 wg-quick installs as a BARE address
    ("10.78.0.1"), while claimed_cidrs() reports "10.78.0.1/32". Compared raw, the link's own
    route read as someone else's and every renewal re-join was refused."""
    from blastbox.host import egress_apply as ea

    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    monkeypatch.setattr(ea, "claimed_cidrs", lambda: ["192.168.1.0/24", "10.78.0.1/32",
                                                      "10.78.0.5/32"])

    def run(argv, **kw):
        a = list(argv)
        if a[:5] == ["ip", "-j", "route", "show", "dev"]:
            return subprocess.CompletedProcess(a, 0, json.dumps(
                [{"dst": "10.78.0.1", "dev": "wtwg0", "scope": "link"}]), "")
        if a[:5] == ["ip", "-j", "addr", "show", "dev"]:
            return subprocess.CompletedProcess(a, 0, json.dumps([{"addr_info": [
                {"family": "inet", "local": "10.78.0.5", "prefixlen": 32}]}]), "")
        return n.run(argv)

    monkeypatch.setattr(ea, "_run", run)
    link.join(_bundle(tmp_path, csr))                      # renewal: must not raise


def test_an_unroutable_aaaa_record_does_not_block_a_v4_endpoint(node, tmp_path, monkeypatch):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    monkeypatch.setattr(link, "_resolve", lambda host: ["192.0.2.10", "2001:db8::10"])
    real = n.run

    def run(argv, **kw):
        if list(argv)[:2] == ["ip", "-6"]:
            return subprocess.CompletedProcess(list(argv), 2, "", "Network is unreachable")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    notes = link.join(_bundle(tmp_path, csr))
    assert any("2001:db8::10 (unused)" in x for x in notes)
    monkeypatch.setattr(link, "_resolve", lambda host: ["2001:db8::10"])
    with pytest.raises(RuntimeError, match="no underlay route"):
        link.join(_bundle(tmp_path, csr))


def test_join_refuses_to_bring_the_link_up_when_the_firewall_cannot_be_persisted(
        node, tmp_path, monkeypatch):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        if list(argv)[:2] == ["systemctl", "enable"] and "--now" not in argv:
            return subprocess.CompletedProcess(list(argv), 1, "", "Failed to enable")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="persisted"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


def test_join_tells_the_operator_to_restart_the_agent(node, tmp_path):
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    assert any("RESTARTED" in x for x in link.join(_bundle(tmp_path, csr)))


def test_the_macos_root_script_refuses_a_user_writable_path(node, tmp_path, monkeypatch):
    node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    monkeypatch.setattr(link, "_root_owned_and_private", lambda st: False)
    with pytest.raises(RuntimeError, match="not root-owned"):
        link.join(_bundle(tmp_path, csr))


def test_a_failed_restart_with_the_stale_interface_up_is_not_success(node, tmp_path, monkeypatch):
    """REGRESSION (review): on a Linux re-join with the link up, a FAILED `systemctl restart`
    was accepted whenever the old interface still existed -- which it does, holding the
    previous host key/endpoint/address. Now a failed (re)start takes the interface down and
    brings it up from the new file; if it will not go down, join raises."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    real = n.run
    state = {"stuck": True}

    def run(argv, **kw):
        a = [str(x) for x in argv]
        if a[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(a, 0, "", "")
        if a[:2] == ["systemctl", "restart"]:
            n.calls.append(a)
            return subprocess.CompletedProcess(a, 1, "", "Job failed")
        if Path(a[0]).name == "wg-quick":
            n.calls.append(a)
            if a[1] == "down" and not state["stuck"]:
                n.links.discard(a[2])
            if a[1] == "up":
                n.links.add(a[2])
            return subprocess.CompletedProcess(a, 0, "", "")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    assert "wtwg0" in n.links
    with pytest.raises(RuntimeError, match="still up with what may be the previous config"):
        link.join(_bundle(tmp_path, csr, endpoint="gw2.example.org:51822"))
    state["stuck"] = False
    n.calls.clear()
    notes = link.join(_bundle(tmp_path, csr, endpoint="gw2.example.org:51822"))
    flat = n.flat()
    assert flat.index("wg-quick down wtwg0") < flat.index("wg-quick up wtwg0")
    assert any("wtwg0 up" in x for x in notes)


def test_join_refuses_a_live_interface_holding_another_hosts_peer(node, tmp_path, monkeypatch):
    """The link being UP is not proof it runs this bundle's config: the live peer set is read
    back from `wg show dump` and must be exactly the bundle's host key, allowed its /32."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        p = real(argv, **kw)
        a = [str(x) for x in argv]
        if Path(a[0]).name == "wg" and a[1] == "show":
            p = subprocess.CompletedProcess(a, 0, p.stdout.replace(KEY_HOST, "Z" * 43 + "="), "")
        return p

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="previous config is still in effect"):
        link.join(_bundle(tmp_path, csr))


def test_a_planted_symlink_at_the_root_script_path_is_replaced_not_followed(node, tmp_path):
    """REGRESSION (review): the support dir may pre-exist, made by a non-root user, who could
    plant `worker-link-<iface>.sh -> <some root file>`. The write followed the link and root
    truncated + chmodded the target before the path check ran. Writes now go to a fresh file
    renamed over the ENTRY, so the target is never opened."""
    node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    p = link._paths("wtwg0")
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    victim.chmod(0o600)
    p["script"].parent.mkdir(parents=True, exist_ok=True)
    p["script"].symlink_to(victim)
    p["plist"].parent.mkdir(parents=True, exist_ok=True)
    p["plist"].symlink_to(victim)
    link.join(_bundle(tmp_path, csr))
    assert victim.read_text() == "precious\n"
    assert oct(victim.stat().st_mode & 0o777) == "0o600"
    for f in (p["script"], p["plist"]):
        assert not f.is_symlink() and f.is_file()
    assert "/fake/bin/wg-quick" in p["script"].read_text()
    assert not [x for x in p["script"].parent.iterdir() if x.name.startswith(".")]


def test_writers_never_follow_a_symlink_and_refuse_a_directory(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep\n")
    for writer in (link._write_public, link._write_private):
        target = tmp_path / f"t-{writer.__name__}"
        target.symlink_to(victim)
        writer(target, "new\n")
        assert victim.read_text() == "keep\n" and target.read_text() == "new\n"
        assert not target.is_symlink()
    assert oct((tmp_path / "t-_write_private").stat().st_mode & 0o777) == "0o600"
    (tmp_path / "adir").mkdir()
    with pytest.raises(RuntimeError, match="not a regular file"):
        link._write_public(tmp_path / "adir", "x")


# ------------------------------------------------------------------ review round 2

def test_macos_rejoin_refuses_when_the_old_tunnel_does_not_go_down(node, tmp_path):
    """REGRESSION (review): a failed / no-op `wg-quick down` on a changed re-join was ignored;
    the watchdog leaves a live utun alone, so the PREVIOUS config stayed up and join reported
    success off the old peer's handshake."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.wg_quick_down_works = False
    with pytest.raises(RuntimeError, match="did not stop utun7"):
        link.join(_bundle(tmp_path, csr, endpoint="gw2.example.org:51822"))
    n.wg_quick_down_works = True
    assert any("up as utun7" in x
               for x in link.join(_bundle(tmp_path, csr, endpoint="gw2.example.org:51822")))


def test_macos_join_verifies_the_live_peer_not_just_a_handshake(node, tmp_path, monkeypatch):
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        p = real(argv, **kw)
        a = [str(x) for x in argv]
        if Path(a[0]).name == "wg" and a[1] == "show":
            p = subprocess.CompletedProcess(a, 0, p.stdout.replace(KEY_HOST, "Z" * 43 + "="), "")
        return p

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="previous config is still in effect"):
        link.join(_bundle(tmp_path, csr))


def test_the_pf_read_back_rejects_a_broader_rule_added_to_the_anchor():
    """REGRESSION (review): the verifier only searched for our lines, so an EARLIER broad rule
    (`pass in quick on utun7 all` -- quick, so final) left it reporting in force."""
    rules = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                          agent_port=8765)
    ok = dict(info="Status: Enabled", main_rules='anchor "com.apple/*" all', anchor_rules=rules,
              real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1", agent_port=8765)
    broad = "pass in quick on utun7 all\n" + rules
    assert any("unexpected rule `pass in quick on utun7 all`" in m
               for m in link.pf_in_force(**{**ok, "anchor_rules": broad}))
    swapped = "\n".join([rules.splitlines()[1], rules.splitlines()[0], *rules.splitlines()[2:]])
    assert any("different order" in m for m in link.pf_in_force(**{**ok, "anchor_rules": swapped}))
    # pfctl's re-rendering is cosmetic: `port = N`, explicit default flags/state, spacing
    rendered = ("pass in quick on utun7 inet proto tcp from 10.78.0.1 to 10.78.0.5 port = 8765 "
                "flags S/SA keep state\n"
                "block drop in quick on utun7 all\nblock drop out  quick on utun7 all\n"
                "block drop in quick on ! utun7 inet from any to 10.78.0.5\n")
    assert link.pf_in_force(**{**ok, "anchor_rules": rendered}) == []
    stateless = rendered.replace(" flags S/SA keep state", "")
    assert link.pf_in_force(**{**ok, "anchor_rules": stateless}) == []


def test_the_watchdog_reloads_an_anchor_that_gained_a_broader_rule(mac, tmp_path):
    """The same check in the watchdog: an anchor that still CONTAINS our pass line but has
    gained another rule is reloaded, not left in force; pfctl's own rendering converges."""
    mac.up("utun7")
    mac.run()
    anchor = tmp_path / "state" / "anchor"
    anchor.write_text("pass in quick on utun7 all\n" + anchor.read_text())
    calls = mac.run()
    assert any(c.startswith("LOADED pass in quick on utun7 inet") for c in calls), calls
    assert "pass in quick on utun7 all" not in mac.anchor()
    # what pfctl prints back (`port = N`, extra spacing) must not reload every 30 s
    anchor.write_text(mac.anchor().replace("port 8765", "port = 8765").replace(" all", "  all"))
    assert not any(c.startswith("LOADED") for c in mac.run())


def test_a_second_linux_link_is_refused_before_the_firewall_is_replaced(node, tmp_path):
    """REGRESSION (review): the Linux nft table, ruleset file and firewall units are node-wide.
    Joining another interface replaced the first link's firewall with one for the new
    interface only (first tunnel left up, unfirewalled) and rewrote the boot unit it Requires."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    loaded, unit = n.loaded, link.FW_UNIT.read_text()
    _pub, csr2, _ = link.keygen("wtwg1", "10.79.0.5")
    with pytest.raises(RuntimeError, match="already has a worker-link on wtwg0"):
        link.join(_bundle(tmp_path, csr2, ip="10.79.0.5", iface="wtwg1", host_ip="10.79.0.1",
                          overlay_net="10.79.0.0/24"))
    assert n.loaded == loaded and link.FW_UNIT.read_text() == unit
    assert "wtwg1" not in n.links and not link._paths("wtwg1")["conf"].exists()
    link.join(_bundle(tmp_path, csr))                      # re-joining the SAME link is fine


@pytest.mark.parametrize("kind", ["wireguard", "tun", "gre", "ipip"])
def test_an_endpoint_route_through_any_tunnel_is_refused_with_the_fix(node, tmp_path, kind):
    """REGRESSION (review): only the link's own name and bbwg0 were recognised, so a route to
    the host endpoint through `tun0`/`wg1`/a corporate VPN was accepted as underlay -- the
    control link then silently depended on that VPN."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.route_dev = "vpn0"
    n.tunnels["vpn0"] = kind
    with pytest.raises(RuntimeError, match=r"via vpn0 .*Exclude the host's address"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links and n.loaded is None


def test_an_unreadable_device_type_is_not_assumed_to_be_underlay(node, tmp_path, monkeypatch):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        if list(argv)[:2] == ["ip", "-d"]:
            return subprocess.CompletedProcess(list(argv), 1, "", "Cannot find device")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="could not be read"):
        link.join(_bundle(tmp_path, csr))


def test_macos_coexists_with_other_vpns_unless_the_endpoint_route_uses_one(node, tmp_path):
    """Other VPN utuns may exist and stay up (a split-tunnel corporate VPN): only the
    endpoint's OWN route going through a tunnel is refused, and the error says how to fix it."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.mac_route_dev = "utun3"
    with pytest.raises(RuntimeError, match=r"via utun3 .*split-tunnel 192\.0\.2\.10/32"):
        link.join(_bundle(tmp_path, csr))
    n.mac_route_dev = "en0"                     # VPN still up elsewhere; endpoint via en0
    notes = link.join(_bundle(tmp_path, csr))
    assert any("underlay route to the endpoint 192.0.2.10: via en0" in x for x in notes)


# ------------------------------------------------------------------ review round 5

def test_linux_leave_of_another_name_never_strips_the_installed_links_firewall(node, tmp_path):
    """REGRESSION (review): `leave --iface <other>` (a typo) only checked that <other> was
    down, then removed the NODE-WIDE nft table and units -- the installed link stayed up,
    its wg-quick unit enabled, with no worker-side firewall. Refused before anything runs."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    link.keygen("wtwg1", "10.79.0.5")              # even with a keygen record for the typo
    loaded = n.loaded
    n.calls.clear()
    with pytest.raises(RuntimeError, match="worker-link on this node is wtwg0, not wtwg1"):
        link.leave("wtwg1")
    assert n.calls == []
    assert n.loaded == loaded and link.FW_UNIT.exists() and link.FW_FILE.exists()
    assert "wtwg0" in n.links
    link.leave("wtwg0")                             # the installed one: proceeds
    assert n.loaded is None and "wtwg0" not in n.links


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_leave_never_takes_down_an_interface_worker_link_did_not_create(node, platform):
    """The same sweep, both platforms: `leave --iface wg0` on a node where worker-link never
    made wg0 (the operator's own VPN) ran `wg-quick down wg0` / `systemctl disable --now
    wg-quick@wg0`, and on macOS booted out and flushed the anchor/label derived from it."""
    n = node(platform)
    with pytest.raises(RuntimeError, match="no worker-link was set up on wg0"):
        link.leave("wg0")
    assert n.calls == []


def test_macos_leave_of_another_name_touches_no_label_anchor_or_tunnel(node, tmp_path):
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.calls.clear()
    with pytest.raises(RuntimeError, match="no worker-link was set up on wtwg1"):
        link.leave("wtwg1")
    assert n.calls == []
    assert link._paths("wtwg0")["plist"].exists()
    notes = link.leave("wtwg0")
    assert any("LaunchDaemon" in x and "unloaded" in x for x in notes)
