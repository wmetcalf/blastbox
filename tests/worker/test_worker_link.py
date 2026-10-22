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
        self.enabled: set[str] = set()          # units `systemctl enable`d
        self.disable_fails = False
        self.launchd_loaded = False
        self.bootout_fails = False
        #: macOS: addr -> (destination, interface) for `route -n get`; default via mac_route_dev
        self.mac_routes: dict[str, tuple[str, str]] = {}
        self.ifconfig_a = ""                    # `ifconfig -a` output (no overlay addresses)
        self.stale_utun = False                 # a utun still runs our key, name file gone
        self.kickstart_fails = False
        self.pf_anchor_override: str | None = None
        self.stale_sock_kills = False           # removing its control socket stops it
        self.route_type = "unicast"
        self.nft_list_error: str | None = None
        #: utun -> public key of ANOTHER WireGuard tunnel (macOS reuses utun numbers)
        self.foreign_utuns: dict[str, str] = {}
        self.name_at_down: list = []            # what each `wg-quick down` would have acted on
        self.pf_flushed = False
        self.pf_flush_fails = False
        self.active: set[str] = set()           # non-link units that were STARTED
        self.disable_fails_units: set[str] = set()
        self.activating: set[str] = set()
        self.stop_fails: set[str] = set()
        #: what the LIVE tunnel runs (wg show dump / addresses), as a restart would set it
        self.live_endpoint = "192.0.2.10:51822"
        self.live_addr = "10.78.0.5"
        self.live_own_key: str | None = None
        self.start_fails: set[str] = set()

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
        elif tool == "wg" and a[1] == "show" and a[2] != "all" and a[3:] != ["public-key"]:
            if not self.root:
                rc, err = 1, "Operation not permitted"
            else:
                hs = "1700000000" if self.handshake else "0"
                key = link._paths("wtwg0")["wg_key"]
                own = (self.live_own_key or (_wg_pub(key.read_text()) if key.exists() else "PUB"))
                out = (f"PRIV\t{own}\t0\toff\n"
                       f"{KEY_HOST}\t(none)\t{self.live_endpoint}\t10.78.0.1/32\t{hs}\t1\t2\t25\n")
                if self.handshake:
                    import time
                    out = out.replace("1700000000", str(int(time.time()) - 5))
        elif tool == "nft" and a[1] == "-f":
            text = Path(a[2]).read_text()
            body = text.split(f"delete table inet {link.NFT_TABLE}\n", 1)[1]
            if self.nft_drop_missing:
                body = body.replace('\t\tiifname "wtwg0" drop\n', "")
            self.loaded = body
        elif tool == "nft" and a[1:3] == ["list", "table"] and self.nft_list_error:
            rc, err = 1, self.nft_list_error
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
            ether = kind in (None, "vxlan", "geneve", "fancytun")
            info = {"info_kind": kind}
            if kind == "fancytun":                  # an unlisted kind naming a remote endpoint
                info["info_data"] = {"remote": "198.51.100.7", "id": 42}
            out = json.dumps([{"ifname": dev, "link_type": "ether" if ether else "none",
                               **({"linkinfo": info} if kind else {})}])
        elif a[:3] == ["route", "-n", "get"]:
            dest, dev = self.mac_routes.get(a[-1], ("default", self.mac_route_dev))
            out = (f"   route to: {a[-1]}\ndestination: {dest}\n"
                   f"  interface: {dev}\n")
        elif tool == "ifconfig" and a[1:] == ["-a"]:
            out = self.ifconfig_a
        elif tool == "ifconfig":
            dev = a[1]
            p2p = dev in self.tunnels or not dev.startswith("en")
            out = (f"{dev}: flags=8051<UP,{'POINTOPOINT' if p2p else 'BROADCAST'},RUNNING,"
                   "MULTICAST> mtu 1500\n")
            if dev == "utun7" and (link.WG_RUN_DIR / "wtwg0.name").exists():
                out += f"\tinet {self.live_addr} --> {self.live_addr} netmask 0xffffffff\n"
        elif tool == "wg" and a[1] == "show" and a[2] != "all" and a[3:] == ["public-key"]:
            key = link._paths("wtwg0")["wg_key"]
            stale = self.stale_utun and not (self.stale_sock_kills
                                             and not (link.WG_RUN_DIR / "utun7.sock").exists())
            ours_live = (link.WG_RUN_DIR / "wtwg0.name").exists() or stale
            if a[2] in self.foreign_utuns:
                out = self.foreign_utuns[a[2]] + "\n"
            elif a[2] == "utun7" and ours_live and key.exists():
                out = _wg_pub(key.read_text()) + "\n"
            else:
                rc, err = 1, "Unable to access interface: No such device"
        elif tool == "wg" and a[1:3] == ["show", "all"]:
            key = link._paths("wtwg0")["wg_key"]
            stale = self.stale_utun and not (self.stale_sock_kills
                                             and not (link.WG_RUN_DIR / "utun7.sock").exists())
            live = (link.WG_RUN_DIR / "wtwg0.name").exists() or stale
            out = f"utun7\t{_wg_pub(key.read_text())}\n" if live and key.exists() else ""
        elif tool == "wg-quick" and a[1] in ("down", "up"):
            if a[1] == "down":
                name = link.WG_RUN_DIR / f"{a[2]}.name"
                self.name_at_down.append(name.read_text().strip() if name.exists() else None)
            if a[1] == "down" and self.wg_quick_down_works:
                self.links.discard(a[2])
                (link.WG_RUN_DIR / f"{a[2]}.name").unlink(missing_ok=True)
            elif a[1] == "up":
                self.links.add(a[2])
        elif a[:3] == ["ip", "-j", "route"] and "get" in a:
            out = json.dumps([{"dst": a[-1], "dev": self.route_dev, "type": self.route_type}])
        elif a[:5] == ["ip", "-j", "addr", "show", "dev"] and a[5] in self.links:
            out = json.dumps([{"ifname": a[5], "addr_info": [
                {"family": "inet", "local": self.live_addr, "prefixlen": 32}]}])
        elif a[:2] == ["ip", "-j"]:
            out = "[]"
        elif a[:3] == ["ip", "link", "show"]:
            rc = 0 if a[3] in self.links else 1
        elif a[:2] == ["systemctl", "is-active"] and a[2] in self.activating:
            rc, out = 3, "activating\n"
        elif a[:2] == ["systemctl", "stop"] and a[2] in self.activating:
            if a[2] not in self.stop_fails:
                self.activating.discard(a[2])
            else:
                rc, err = 1, f"Failed to stop {a[2]}"
        elif a[:2] == ["systemctl", "is-active"]:
            rc = 0 if a[2] in self.active else 3
        elif a[:2] == ["systemctl", "is-enabled"]:
            rc = 0 if a[2] in self.enabled else 1
        elif a[:2] == ["systemctl", "enable"] and "--now" in a and a[-1] in self.start_fails:
            self.enabled.add(a[-1])
            rc, err = 1, f"Job for {a[-1]} failed because the control process exited"
        elif a[:2] == ["systemctl", "enable"]:
            self.enabled.add(a[-1])
            if a[2] == "--now" and not a[3].startswith("wg-quick@"):
                self.active.add(a[3])
            if a[2] == "--now" and a[3].startswith("wg-quick@"):
                self.links.add(a[3].split("@")[1])
        elif a[:2] == ["systemctl", "disable"]:
            if a[2] == "--now" and a[3].startswith("wg-quick@"):
                self.links.discard(a[3].split("@")[1])
            if (self.disable_fails and a[-1].startswith("wg-quick@")) \
                    or a[-1] in self.disable_fails_units:
                rc, err = 1, "Failed to disable unit"
            else:
                self.enabled.discard(a[-1])
                if a[2] == "--now":
                    self.active.discard(a[-1])
        elif tool == "launchctl" and a[1] == "print":
            rc = 0 if self.launchd_loaded else 1
        elif tool == "launchctl" and a[1] == "bootstrap":
            # what RunAtLoad would do: the watchdog brings the tunnel up as some utun
            self.launchd_loaded = True
            self.pf_flushed = False
            (link.WG_RUN_DIR / "wtwg0.name").write_text("utun7\n")
        elif tool == "launchctl" and a[1] == "kickstart" and self.kickstart_fails:
            rc, err = 113, "Could not find service"
        elif tool == "launchctl" and a[1] == "kickstart" and self.launchd_loaded:
            (link.WG_RUN_DIR / "wtwg0.name").write_text("utun7\n")   # the watchdog re-ups it
        elif tool == "launchctl" and a[1] == "bootout":
            if self.bootout_fails:
                rc, err = 5, "Boot-out failed: 5: Input/output error"
            else:
                self.launchd_loaded = False
                (link.WG_RUN_DIR / "wtwg0.name").unlink(missing_ok=True)
        elif tool == "pfctl" and "info" in a:
            out = "Status: Enabled for 0 days\n"
        elif tool == "pfctl" and "rules" in a and "-a" not in a:
            out = 'anchor "com.apple/*" all\n'
        elif tool == "pfctl" and "-F" in a:
            if not self.pf_flush_fails:
                self.pf_flushed = True
        elif tool == "pfctl" and "rules" in a:
            out = ("" if self.pf_flushed else
                   self.pf_anchor_override if self.pf_anchor_override is not None else
                   link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                                 agent_port=8765))
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
    if "worker_public_key" not in b and "worker_public_key" in JoinBundle.__dataclass_fields__:
        pub = link._paths(str(b["iface"]))["wg_pub"]
        b["worker_public_key"] = pub.read_text().strip() if pub.exists() else "W" * 43 + "="
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
        'if [ "$1" = show ] && [ "$2" != all ] && [ "$3" = public-key ]; then\n'
        '  [ -f "$ST/keys" ] && awk -v u="$2" \'$1 == u { print $2 }\' "$ST/keys"\n'
        '  exit 0\nfi\n'
        'if [ "$1" = show ] && [ "$2" = all ]; then\n'
        '  [ -f "$ST/keys" ] && while read -r u k; do\n'
        '    [ -e "${RUN:?}/$u.sock" ] && printf "%s\\t%s\\n" "$u" "$k"; done < "$ST/keys"\n'
        '  exit 0\nfi\n'
        '[ "$1" = show ] && grep -qx "$2" "$ST/up" && exit 0\nexit 1\n'))
    wgq = _fake_bin(bin_d, "wg-quick", env_hdr + (
        'if [ "$1" = up ]; then echo utun9 > "$RUN/$2.name"; echo utun9 >> "$ST/up"; fi\n'
        'if [ "$1" = down ] && [ -n "$2" ]; then\n'
        '  [ -f "${RUN:?}/$2.name" ] && rm -f "${RUN:?}/$(cat "${RUN:?}/$2.name").sock"\n'
        '  rm -f "${RUN:?}/$2.name"\nfi\nexit 0\n'))
    pfctl = _fake_bin(bin_d, "pfctl", env_hdr + (
        'case "$*" in\n'
        '  *"-s info"*) echo "Status: $(cat "$ST/pf")"; exit 0 ;;\n'
        '  *"-E"*) echo Enabled > "$ST/pf"; echo "pf enabled" >&2; echo "Token : 4242" >&2; exit 0 ;;\n'
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

        def drop_name(self) -> None:
            (run_d / "wtwg0.name").unlink(missing_ok=True)

        def name_file(self) -> str:
            return (run_d / "wtwg0.name").read_text().strip()

        def keys(self, text: str) -> None:
            (state / "keys").write_text(text)
            for line in text.splitlines():          # each listed utun is a live wireguard-go
                (run_d / f"{line.split()[0]}.sock").write_text("")

        def touch_sock(self, utun: str) -> None:
            (run_d / f"{utun}.sock").write_text("")

        def sock(self, utun: str) -> bool:
            return (run_d / f"{utun}.sock").exists()

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
    assert f"systemctl enable --now {link.FW_UNIT_NAME}" in flat
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
        if list(argv)[:2] == ["systemctl", "enable"] and argv[-1] == link.FW_UNIT_NAME:
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


# ------------------------------------------------------------------ review round 6

@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_join_refuses_to_overwrite_a_wireguard_config_it_did_not_write(node, tmp_path, platform):
    """Sweep (review round 6): join wrote /etc/wireguard/<iface>.conf unconditionally, so a
    bundle for `wg1` -- the operator's own VPN -- replaced its config and restarted it."""
    n = node(platform)
    _pub, csr, _ = link.keygen("wg1", "10.78.0.5")
    conf = link._paths("wg1")["conf"]
    theirs = "[Interface]\nPrivateKey = THEIRS\n\n[Peer]\nPublicKey = X\n"
    conf.write_text(theirs)
    n.calls.clear()
    with pytest.raises(RuntimeError, match="not written by worker-link"):
        link.join(_bundle(tmp_path, csr, iface="wg1"))
    assert conf.read_text() == theirs
    assert not any(c.startswith(("systemctl", "/fake/bin/nft", "launchctl", "/fake/bin/wg-quick"))
                   for c in n.flat())


def test_linux_join_refuses_a_live_interface_it_has_no_config_for(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wg1", "10.78.0.5")
    n.links.add("wg1")                              # up, brought up by something else
    with pytest.raises(RuntimeError, match="already exists here and is not worker-link's"):
        link.join(_bundle(tmp_path, csr, iface="wg1"))
    assert n.loaded is None


def test_leave_refuses_a_config_it_did_not_write_even_with_a_keygen_record(node):
    n = node("linux")
    link.keygen("wg1", "10.78.0.5")
    conf = link._paths("wg1")["conf"]
    conf.write_text("[Interface]\nPrivateKey = THEIRS\n")
    n.calls.clear()
    with pytest.raises(RuntimeError, match="not written by worker-link"):
        link.leave("wg1")
    assert conf.exists()
    assert not any(c.startswith(("systemctl disable", "wg-quick", "nft")) for c in n.flat())


def test_linux_leave_keeps_everything_while_the_unit_is_still_enabled(node, tmp_path):
    """REGRESSION (review): `disable --now` stopped the unit but failed to remove its
    enablement; leave then deleted the config and reported it disabled, leaving an enabled
    wg-quick@ to fail at every boot. Verified with is-enabled, as host teardown does."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.disable_fails = True
    notes = link.leave("wtwg0")
    assert "STILL ENABLED" in notes[-1]
    assert link._paths("wtwg0")["conf"].exists() and link.FW_UNIT.exists()
    assert n.loaded is not None
    assert link.main(["leave"]) == 1                     # not reported as a clean leave
    n.disable_fails = False
    assert link.main(["leave"]) == 0
    assert n.loaded is None and not link._paths("wtwg0")["conf"].exists()


def test_macos_leave_keeps_pf_while_the_watchdog_is_still_loaded(node, tmp_path):
    """REGRESSION (review): a failed `launchctl bootout` was ignored; with the interface down
    leave flushed the pf anchor and removed the watchdog files -- and the still-loaded
    watchdog brought the tunnel back up with no rules."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    p = link._paths("wtwg0")
    n.bootout_fails = True
    n.calls.clear()
    notes = link.leave("wtwg0")
    assert "STILL LOADED" in notes[-1]
    assert not any("-F all" in c for c in n.flat())                  # pf untouched
    assert p["plist"].exists() and p["script"].exists() and p["conf"].exists()
    n.bootout_fails = False
    n.calls.clear()
    link.leave("wtwg0")
    assert any("-F all" in c for c in n.flat()) and not p["plist"].exists()


def test_purge_removes_the_keygen_directories_once_they_are_empty(node, tmp_path):
    """From the live Linux run: `leave --purge` left an empty /etc/blastbox/worker-link."""
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.keygen("wtwg1", "10.79.0.5")               # a second record keeps the dirs in use
    link.join(_bundle(tmp_path, csr))
    link.leave("wtwg0", purge=True)
    assert link.STATE_DIR.is_dir() and link.KEY_DIR.is_dir()
    assert link._paths("wtwg1")["state"].exists()
    link.leave("wtwg1", purge=True)
    assert not link.STATE_DIR.exists() and not link.KEY_DIR.exists()


# ------------------------------------------------------------------ review round 7

def test_keygen_join_and_leave_hold_one_node_wide_lock(node, tmp_path, monkeypatch):
    """Sweep (review round 7): keygen / join / leave each read state, check it and rewrite
    keys, configs, the firewall and units; overlapping runs could interleave. One node-wide
    lock spans each -- observed from inside their steps."""
    import fcntl

    def held() -> bool:
        path = tmp_path / ".worker-link-peer.lock"     # STATE_DIR.parent in the fixture
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

    seen: dict[str, bool] = {}

    def spy(name, fn):
        def wrapped(*a, **kw):
            seen[name] = held()
            return fn(*a, **kw)
        return wrapped

    node("linux")
    monkeypatch.setattr(link, "csr_config", spy("keygen", link.csr_config))
    monkeypatch.setattr(link, "_apply_linux", spy("join:apply", link._apply_linux))
    monkeypatch.setattr(link, "_refuse_leaving_what_is_not_ours",
                        spy("leave", link._refuse_leaving_what_is_not_ours))
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    link.leave("wtwg0")
    assert len(seen) == 3 and all(seen.values()), seen
    assert not held()


# ------------------------------------------------------------------ review round 8

def test_macos_rejoin_takes_the_link_down_when_pf_cannot_be_verified(node, tmp_path):
    """REGRESSION (review): on a re-join of a live link a failed `launchctl kickstart` was
    ignored; the name file and live peer passed, so join reported success with the pf anchor
    (flushed by something else) never restored. pf is now read back; unverifiable -> down."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.pf_anchor_override = ""                     # the anchor was flushed under the live link
    n.kickstart_fails = True
    with pytest.raises(RuntimeError, match=r"NOT in force.*kickstart` also failed.*taken DOWN"):
        link.join(_bundle(tmp_path, csr))
    assert not n.launchd_loaded and not (link.WG_RUN_DIR / "wtwg0.name").exists()
    n.pf_anchor_override = None
    n.kickstart_fails = False
    assert any("pf: in force" in x for x in link.join(_bundle(tmp_path, csr)))


def test_macos_leave_finds_the_live_tunnel_by_its_key_not_its_name_file(node, tmp_path):
    """REGRESSION (review): leave took a missing /var/run/wireguard/<iface>.name as proof the
    utun was gone, then flushed pf and deleted the config with the tunnel still running."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    (link.WG_RUN_DIR / "wtwg0.name").unlink()
    n.stale_utun = True                            # still running our key, and stuck
    n.calls.clear()
    notes = link.leave("wtwg0")
    assert "not confirmed down" in notes[-1] and "utun7 still runs this link's key" in notes[-1]
    assert not any("-F all" in c for c in n.flat())
    assert link._paths("wtwg0")["conf"].exists() and link._paths("wtwg0")["plist"].exists()
    n.stale_utun = False
    link.leave("wtwg0")
    assert not link._paths("wtwg0")["conf"].exists()


@pytest.mark.parametrize("where", ["route", "address"])
def test_macos_join_refuses_overlay_addresses_this_mac_already_uses(node, tmp_path, where):
    """REGRESSION (review): the macOS preflight never checked whether worker_ip / host_ip were
    already routed or assigned (Linux does), so the watchdog's closed pf rules could cut off a
    LAN or VPN using them -- and keep doing so on every run."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    if where == "route":
        n.mac_routes["10.78.0.1"] = ("10.78.0.0", "en0")
    else:
        n.ifconfig_a = ("en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
                        "\tinet 10.78.0.5 netmask 0xffffff00 broadcast 10.78.0.255\n")
    with pytest.raises(RuntimeError, match="collide with this Mac's network"):
        link.join(_bundle(tmp_path, csr))
    assert not link._paths("wtwg0")["plist"].exists() and not n.launchd_loaded
    # ...but the link's OWN utun holding them (a re-join) is not a collision
    n.mac_routes.clear()
    n.ifconfig_a = ""
    link.join(_bundle(tmp_path, csr))
    n.mac_routes["10.78.0.1"] = ("10.78.0.1", "utun7")
    n.ifconfig_a = "utun7: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1380\n\tinet 10.78.0.5 --> 10.78.0.5\n"
    link.join(_bundle(tmp_path, csr))


@pytest.mark.parametrize("dev", ["gif0", "stf0", "ppp0", "vpnx3"])
def test_macos_endpoint_routes_through_any_tunnel_family_are_refused(node, tmp_path, dev):
    """REGRESSION (review): only utun/ipsec/tun names counted as tunnels; gif (IP-in-IP), stf
    (6to4), ppp (L2TP/PPTP) -- or any POINTOPOINT interface -- passed as underlay."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.mac_route_dev = dev
    with pytest.raises(RuntimeError, match=f"via {dev} "):
        link.join(_bundle(tmp_path, csr))


def test_linux_ppp_endpoint_route_is_a_tunnel_too(node, tmp_path):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        if list(argv)[:4] == ["ip", "-d", "-j", "link"] and argv[-1] == "ppp0":
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(
                [{"ifname": "ppp0", "link_type": "ppp"}]), "")
        return real(argv, **kw)

    n.route_dev = "ppp0"
    link._run, saved = run, link._run
    try:
        with pytest.raises(RuntimeError, match="via ppp0"):
            link.join(_bundle(tmp_path, csr))
    finally:
        link._run = saved


def test_a_linux_rejoin_whose_firewall_fails_read_back_takes_the_link_down(node, tmp_path):
    """REGRESSION (review): on a re-join the old interface is live; a new ruleset that then
    failed read-back raised with that tunnel still running behind an incomplete firewall."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    assert "wtwg0" in n.links
    n.nft_drop_missing = True
    with pytest.raises(RuntimeError, match="not in force.*taken DOWN"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


def test_a_linux_join_verifies_its_unit_is_enabled_after_the_fallback(node, tmp_path, monkeypatch):
    """Sweep (review round 8, the worker twin of the host fix): the direct `wg-quick up`
    fallback brought the link up with wg-quick@ NOT enabled -- gone after a reboot."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        a = [str(x) for x in argv]
        if a[:2] == ["systemctl", "enable"] and a[-1] == "wg-quick@wtwg0":
            n.calls.append(a)
            return subprocess.CompletedProcess(a, 1, "", "Unit file is masked.")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="could not be ENABLED"):
        link.join(_bundle(tmp_path, csr))


def test_join_refuses_an_endpoint_name_resolving_into_the_overlay(node, tmp_path, monkeypatch):
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    monkeypatch.setattr(link, "_resolve", lambda host: ["10.78.0.1"])
    with pytest.raises(RuntimeError, match="inside the link overlay"):
        link.join(_bundle(tmp_path, csr))


def test_watchdog_finds_a_live_tunnel_by_key_when_its_name_file_is_gone(mac):
    """Sweep (review round 8, the same name-file trust as leave): with wg-quick's name file
    missing but the utun still running our key, the watchdog took the link for DOWN and ran
    `wg-quick up` -- a second tunnel with the same key. It now finds the tunnel by its key."""
    pub = "P" * 43 + "="
    mac.rerender(public_key=pub)
    mac.up("utun7")
    mac.run()
    mac.drop_name()                          # the note is gone; the tunnel is not
    mac.keys(f"utun7\t{pub}\n")
    calls = mac.run()
    assert not any(c.startswith("wg-quick") for c in calls), calls
    assert mac.name_file() == "utun7"
    # a tunnel running some OTHER key is not ours: the link really is down -> re-up
    mac.drop_name()
    mac.keys(f"utun3\t{'Q' * 43}=\n")
    assert "wg-quick up wtwg0" in mac.run()


# ------------------------------------------------------------------ review round 9

def test_watchdog_forces_a_tunnel_down_by_key_when_wg_quick_cannot(mac):
    """REGRESSION (review): on losing pf enforcement the watchdog ran `wg-quick down`, ignored
    the result and exited -- with the name file gone that does nothing, and the tunnel stayed
    up with no enforcement on every retry. It now stops wireguard-go by its control socket for
    every utun running the link's key, and checks."""
    pub = "P" * 43 + "="
    mac.rerender(public_key=pub)
    mac.up("utun7")
    mac.keys(f"utun7\t{pub}\n")
    mac.run()
    mac.drop_name()                            # wg-quick down can no longer find it
    mac.main_rules("pass all\n")               # enforcement lost
    with pytest.raises(AssertionError, match="does not evaluate"):
        mac.run()
    assert not mac.sock("utun7")               # wireguard-go stopped, verified by key


@pytest.mark.parametrize("main,bad", [
    ('pass quick all flags S/SA keep state\nanchor "com.apple/*" all\n', True),
    ('pass in quick on ! en0 all\nanchor "com.apple/*" all\n', True),
    ('pass quick on utun all\nanchor "com.apple/*" all\n', True),
    ('pass in quick on utun7 all\nanchor "com.apple/*" all\n', True),
    ('pass quick on utun3 all\nanchor "com.apple/*" all\n', False),   # another VPN's utun
    ('pass quick on lo0 all\nanchor "com.apple/*" all\n', False),
    ('anchor "com.apple/*" all\npass quick all\n', False),             # AFTER our anchor
    ('pass in all\nanchor "com.apple/*" all\n', False),                 # not quick
])
def test_a_main_ruleset_pass_quick_before_the_anchor_is_not_enforcement(mac, main, bad):
    """REGRESSION (review): only the PRESENCE of `anchor "com.apple/*"` was checked; a
    `pass ... quick` placed before it that can match the link's utun ends evaluation first, so
    status and the watchdog called a bypassed anchor enforced."""
    rules = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                          agent_port=8765)
    missing = link.pf_in_force(info="Status: Enabled", main_rules=main, anchor_rules=rules,
                               real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                               agent_port=8765)
    assert bool(missing) is bad, missing
    mac.up("utun7")
    mac.main_rules(main)
    if bad:
        with pytest.raises(AssertionError, match="passes"):
            mac.run()
    else:
        mac.run()


def test_macos_leave_stops_a_tunnel_whose_name_file_is_gone(node, tmp_path):
    """The Python side of the same fix: leave stops wireguard-go by its control socket when
    wg-quick cannot, then verifies by key -- and proceeds only once it is gone."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    (link.WG_RUN_DIR / "wtwg0.name").unlink()
    (link.WG_RUN_DIR / "utun7.sock").write_text("")
    n.stale_utun = n.stale_sock_kills = True
    n.calls.clear()
    link.leave("wtwg0")
    assert not (link.WG_RUN_DIR / "utun7.sock").exists()
    assert any("-F all" in c for c in n.flat()) and not link._paths("wtwg0")["conf"].exists()


@pytest.mark.parametrize("how", ["lo", "local", "loopback-literal"])
def test_a_linux_endpoint_that_is_this_machine_is_refused(node, tmp_path, monkeypatch, how):
    """REGRESSION (review): an endpoint routed via `lo` (127.0.0.1, or a name resolving to one
    of this worker's own addresses) was accepted as underlay -- WireGuard dialled itself."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    if how == "lo":
        n.route_dev = "lo"
    elif how == "local":
        n.route_type = "local"
    else:
        monkeypatch.setattr(link, "_resolve", lambda host: ["127.0.0.1"])
    with pytest.raises(RuntimeError, match="is THIS machine|loopback"):
        link.join(_bundle(tmp_path, csr))
    assert n.loaded is None


def test_a_macos_endpoint_that_is_this_machine_is_refused(node, tmp_path):
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.mac_route_dev = "lo0"
    with pytest.raises(RuntimeError, match="is THIS machine"):
        link.join(_bundle(tmp_path, csr))


def test_a_macos_rejoin_restarts_and_then_fails_closed_on_a_stale_live_peer(node, tmp_path):
    """REGRESSION (review): a retry after a join that wrote the new config but failed before
    applying it saw conf_changed=False, left the old tunnel running and raised on the stale
    peer without taking anything down -- every retry repeating it."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    other = "O" * 43 + "="
    new = _bundle(tmp_path, csr, host_public_key=other)
    p = link._paths("wtwg0")
    p["conf"].write_text(link.worker_wg_config(          # the failed join's leftover
        private_key=p["wg_key"].read_text(), worker_ip="10.78.0.5", host_ip="10.78.0.1",
        host_public_key=other, endpoint="gw.example.org:51822"))
    n.calls.clear()
    with pytest.raises(RuntimeError, match="this bundle's host.*taken DOWN"):
        link.join(new)                     # the live peer stays the OLD host (fake dump)
    assert "/fake/bin/wg-quick down wtwg0" in n.flat()          # restarted despite same file
    assert not n.launchd_loaded and not (link.WG_RUN_DIR / "wtwg0.name").exists()


def test_a_linux_join_whose_live_peer_stays_stale_takes_the_link_down(node, tmp_path,
                                                                       monkeypatch):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    real = n.run

    def run(argv, **kw):
        p = real(argv, **kw)
        a = [str(x) for x in argv]
        if Path(a[0]).name == "wg" and a[1] == "show" and a[2] != "all":
            p = subprocess.CompletedProcess(a, 0, p.stdout.replace(KEY_HOST, "Z" * 43 + "="), "")
        return p

    monkeypatch.setattr(link, "_run", run)
    with pytest.raises(RuntimeError, match="previous config is still in effect.*taken DOWN"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


def test_linux_status_does_not_read_an_nft_failure_as_an_absent_table(node, tmp_path):
    """Sweep (review round 9): only nft's not-found answer means "no table"; another failure
    (netlink ENOMEM, EIO) is UNVERIFIED, not "NOT IN FORCE -- missing the table"."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.nft_list_error = "Error: netlink: Cannot allocate memory"
    ok, rows = link.status("wtwg0")
    assert not ok and any("UNVERIFIED" in r and "Cannot allocate memory" in r for r in rows)


# ------------------------------------------------------------------ review round 11

@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_keygen_rotate_is_refused_while_the_link_is_live(node, tmp_path, platform):
    """REGRESSION (review): `keygen --rotate` replaced the key the live tunnel is FOUND by (and
    the running config still carries the old one). A later leave then derived the new key,
    found no tunnel and called it down while it still handshook with the host."""
    n = node(platform)
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    key = link._paths("wtwg0")["wg_key"].read_text()
    with pytest.raises(RuntimeError, match="refusing to generate a new wtwg0 key"):
        link.keygen("wtwg0", "10.78.0.5", rotate=True)
    assert link._paths("wtwg0")["wg_key"].read_text() == key
    link.leave("wtwg0")
    if platform == "darwin":
        n.launchd_loaded = False
    link.keygen("wtwg0", "10.78.0.5", rotate=True)      # down and uninstalled: allowed
    assert link._paths("wtwg0")["wg_key"].read_text() != key


def test_watchdog_never_adopts_a_utun_that_runs_another_key(mac):
    """REGRESSION (review): the name-file fast path accepted ANY live WireGuard utun -- macOS
    reuses utun numbers, so a stale note naming another VPN's tunnel made the watchdog load
    this link's block rules on it (and a later down could hit it). The recorded utun must run
    the link's key; a foreign one is ignored, never brought down, and the link is re-upped."""
    pub = "P" * 43 + "="
    mac.rerender(public_key=pub)
    mac.up("utun3")                                   # the note names utun3 ...
    mac.keys(f"utun3\t{'F' * 43}=\n")                 # ... which runs SOMEONE ELSE'S key
    calls = mac.run()
    assert mac.sock("utun3")                          # their tunnel untouched
    assert "wg-quick up wtwg0" in calls
    assert "utun3" not in mac.anchor() and "on utun9" in mac.anchor()


def test_python_paths_never_trust_a_name_file_naming_another_key(node, tmp_path):
    """Sweep (review round 11): status, leave and re-join used the name file's utun without
    checking its key. A stale note naming another VPN's utun read as "up", and `wg-quick down`
    would have acted on it."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    (link.WG_RUN_DIR / "wtwg0.name").write_text("utun3\n")   # the note names a reused utun
    n.foreign_utuns["utun3"] = "F" * 43 + "="
    _ok, rows = link.status("wtwg0")
    assert any(r.startswith("interface wtwg0:") for r in rows), rows
    assert all("utun3" not in r for r in rows), rows
    n.name_at_down.clear()
    link._darwin_link_down("/fake/bin/wg", "/fake/bin/wg-quick", "wtwg0")
    assert n.name_at_down == [None]                  # the foreign note was dropped first


# ------------------------------------------------------------------ review round 12

def test_keygen_holds_the_node_lock_for_its_whole_run(node, tmp_path, monkeypatch):
    """REGRESSION (review): the lock decorator had slid onto the rotation check, so keygen's
    key, CSR and state writes ran UNLOCKED -- racing a join or leave."""
    import fcntl

    def held() -> bool:
        fd = os.open(tmp_path / ".worker-link-peer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    seen = []
    real_csr, real_write = link.csr_config, link._write_public

    def csr(ip):
        seen.append(("csr", held()))
        return real_csr(ip)

    def write(path, *a, **kw):
        seen.append((Path(path).name, held()))
        return real_write(path, *a, **kw)

    node("linux")
    monkeypatch.setattr(link, "csr_config", csr)
    monkeypatch.setattr(link, "_write_public", write)
    link.keygen("wtwg0", "10.78.0.5")
    link.keygen("wtwg0", "10.78.0.5", rotate=True)
    assert seen and all(h for _n, h in seen), seen


def test_a_name_file_whose_utun_key_cannot_be_read_is_never_acted_on(node, tmp_path):
    """REGRESSION (review): only a utun POSITIVELY running another key counted as foreign; one
    whose key could not be read (not WireGuard, `wg show` failing) was kept, and
    `wg-quick down` acted through it. Only a verified OWN key keeps the note now."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    link.leave("wtwg0")
    n.launchd_loaded = False
    (link.WG_RUN_DIR / "wtwg0.name").write_text("utun3\n")   # utun3: key unreadable
    n.name_at_down.clear()
    link._darwin_link_down("/fake/bin/wg", "/fake/bin/wg-quick", "wtwg0")
    assert n.name_at_down == [None]


def test_watchdog_drops_a_name_file_whose_utun_key_cannot_be_read(mac):
    pub = "P" * 43 + "="
    mac.rerender(public_key=pub)
    mac.name("utun3\n")                         # names utun3: not WireGuard, no key
    mac.touch_sock("utun3")                      # ...something else's socket lives there
    mac.run()
    assert mac.sock("utun3")                     # `wg-quick down` never acted through it


@pytest.mark.parametrize("kind", ["vxlan", "geneve", "fancytun"])
def test_encapsulating_overlays_are_not_an_underlay(node, tmp_path, kind):
    """REGRESSION (review): VXLAN/Geneve devices report an ETHERNET link type and were not in
    the tunnel set, so an endpoint routed over one passed as underlay. They are listed now,
    and any kind whose kernel description names a remote endpoint is classified as a tunnel."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.route_dev = "ovl0"
    n.tunnels["ovl0"] = kind
    with pytest.raises(RuntimeError, match="via ovl0"):
        link.join(_bundle(tmp_path, csr))


# ------------------------------------------------------------------ review round 13

@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize("damage", ["deleted", "emptied"])
def test_an_implicit_key_regeneration_is_refused_under_an_installed_link(node, tmp_path,
                                                                          platform, damage):
    """REGRESSION (review): only --rotate was checked; a key file deleted or emptied made plain
    keygen generate a NEW key under a live/installed link -- the identity its tunnel is found
    by. Every key generation is checked now, by the install records as well as the key."""
    node(platform)
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    key = link._paths("wtwg0")["wg_key"]
    if damage == "deleted":
        key.unlink()
    else:
        key.write_text("")
    with pytest.raises(RuntimeError, match="refusing to generate a new wtwg0 key"):
        link.keygen("wtwg0", "10.78.0.5")
    assert not key.exists() or key.read_text() == ""          # nothing generated


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_a_fresh_node_can_still_keygen(node, platform):
    """...and the check does not block the FIRST keygen on a node with nothing installed, nor
    re-creating a lost key on a node that is NOT joined."""
    node(platform)
    link.keygen("wtwg0", "10.78.0.5")
    link._paths("wtwg0")["wg_key"].unlink()
    link.keygen("wtwg0", "10.78.0.5")
    assert link._paths("wtwg0")["wg_key"].read_text().strip()


def test_linux_leave_keeps_every_recovery_file_until_the_table_is_gone(node, tmp_path):
    """REGRESSION (review, twice): with `nft delete table` failing, leave removed the firewall
    units and ruleset BEFORE checking, then the config -- and with --purge the keys and state
    -- so a stale hooked table was left with nothing to find the install by."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    loaded = n.loaded
    real = n.run

    def run(argv, **kw):
        a = [str(x) for x in argv]
        if a[:3] == ["nft", "delete", "table"]:
            n.calls.append(a)
            return subprocess.CompletedProcess(a, 1, "", "Error: Device or resource busy")
        return real(argv, **kw)

    link._run, saved = run, link._run
    try:
        notes = link.leave("wtwg0", purge=True)
    finally:
        link._run = saved
    assert "could not verify" in notes[-1] and n.loaded == loaded
    p = link._paths("wtwg0")
    for f in (link.FW_UNIT, link.FW_FILE, *link._reassert_paths(), p["conf"], p["wg_key"],
              p["state"]):
        assert f.exists(), f
    notes = link.leave("wtwg0", purge=True)                # once the table goes: all of it
    assert n.loaded is None and not link.FW_UNIT.exists() and not p["wg_key"].exists()


def test_macos_leave_keeps_its_files_until_the_anchor_is_verified_empty(node, tmp_path):
    """Sweep: the macOS leave flushed the anchor, warned when it could not verify it empty --
    and removed the plist, script, config (and on --purge the keys) anyway."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.pf_flush_fails = True
    notes = link.leave("wtwg0", purge=True)
    p = link._paths("wtwg0")
    assert "could not verify pf anchor" in notes[-1]
    assert p["plist"].exists() and p["conf"].exists() and p["wg_key"].exists()
    n.pf_flush_fails = False
    link.leave("wtwg0", purge=True)
    assert not p["plist"].exists() and not p["wg_key"].exists()


def test_join_refuses_a_bundle_that_registered_another_workers_key(node, tmp_path):
    """REGRESSION (review): the bundle did not carry the key the host registered, so A's CSR
    with B's public key at `add` installed a link that could never handshake -- and join only
    noted a slow handshake. The registered key is now compared before anything is written."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.calls.clear()
    with pytest.raises(RuntimeError, match="registers .* as this worker's key"):
        link.join(_bundle(tmp_path, csr, worker_public_key="B" * 43 + "="))
    assert not link._paths("wtwg0")["conf"].exists() and n.loaded is None


def test_a_bundle_without_the_registered_worker_key_is_refused():
    from blastbox.host.worker_link import JoinBundle

    with pytest.raises(ValueError, match="missing worker_public_key"):
        JoinBundle.from_json(json.dumps({"blastbox_worker_link": 1, "name": "w1"}).replace(
            '"name": "w1"', '"name": "w1", "iface": "wtwg0", "worker_ip": "10.78.0.5", '
            '"host_ip": "10.78.0.1", "overlay_net": "10.78.0.0/24", "endpoint": "gw.example.org", '
            '"host_public_key": "' + "H" * 43 + '=", "agent_port": 8765, "ca_pem": "x", '
            '"cert_pem": "x"'))


def test_a_mistyped_agent_user_is_refused_before_the_trust_files_change(node, tmp_path):
    """REGRESSION (review): --agent-user was resolved only after the bundle's certificate and
    CA had replaced the installed ones, so a typo on a re-join failed with the agent's trust
    files already changed. It is resolved before anything is installed now."""
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    p = link._paths("wtwg0")
    cert, ca = p["cert"].read_bytes(), p["ca"].read_bytes()
    renewed = _bundle(tmp_path / "other-ca", csr)            # a different CA and certificate
    with pytest.raises(RuntimeError, match="no such user .*nothing was installed"):
        link.join(renewed, agent_user="no-such-user-blastbox-test")
    assert p["cert"].read_bytes() == cert and p["ca"].read_bytes() == ca


def test_linux_join_starts_the_firewall_boot_unit_not_just_enables_it(node, tmp_path):
    """The worker twin of the host fix: enabled AND started (verified), or the join fails
    before the link is up."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    assert f"systemctl enable --now {link.FW_UNIT_NAME}" in n.flat()
    assert link.FW_UNIT_NAME in n.active
    link.leave("wtwg0")
    n.start_fails.add(link.FW_UNIT_NAME)
    with pytest.raises(RuntimeError, match="could not enable and start"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


@pytest.mark.parametrize("stale", ["endpoint", "port", "own-key", "address"])
def test_a_macos_rejoin_restarts_a_tunnel_still_running_old_settings(node, tmp_path, stale):
    """REGRESSION (review): a join that wrote a new config (here: only the endpoint changed)
    and was interrupted before applying it left, on retry, conf_changed=False -- and the live
    check compared only the host key and AllowedIPs, so the tunnel kept dialling the OLD
    endpoint while join reported success. Every field the bundle sets is compared now."""
    n = node("darwin")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    if stale == "endpoint":
        n.live_endpoint = "198.51.100.9:51822"         # the old host address
    elif stale == "port":
        n.live_endpoint = "192.0.2.10:4500"
    elif stale == "own-key":
        n.live_own_key = "Q" * 43 + "="
    else:
        n.live_addr = "10.78.0.66"
    n.calls.clear()
    with pytest.raises(RuntimeError, match="previous config is still in effect.*taken DOWN"):
        link.join(_bundle(tmp_path, csr))                # same file: only the LIVE side is stale
    assert "/fake/bin/wg-quick down wtwg0" in n.flat()  # it was restarted, then failed closed


def test_a_linux_join_verifies_the_live_endpoint_too(node, tmp_path):
    """The Linux counterpart: the post-start verification now covers the endpoint, keepalive,
    own key and address, failing closed (link taken down) on any mismatch."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    n.live_endpoint = "198.51.100.9:51822"
    with pytest.raises(RuntimeError, match="endpoint .* is not gw.example.org:51822.*taken DOWN"):
        link.join(_bundle(tmp_path, csr))
    assert "wtwg0" not in n.links


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_a_csr_refresh_on_a_joined_worker_keeps_it_joined(node, tmp_path, platform):
    """REGRESSION (review): a non-rotating keygen (a fresh CSR for a renewal) on a JOINED
    worker rewrote the state record with only iface/worker_ip, dropping host_ip, agent_port and
    name -- status then called the running link "not joined" and skipped every live check. The
    record is merged now; the join fields stay until a join or leave changes them."""
    node(platform)
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    before = json.loads(link._paths("wtwg0")["state"].read_text())
    link.keygen("wtwg0", "10.78.0.5")                    # same keys, fresh CSR
    after = json.loads(link._paths("wtwg0")["state"].read_text())
    for k in ("host_ip", "agent_port", "name", "joined_worker_ip"):
        assert after.get(k) == before.get(k), k
    _ok, rows = link.status("wtwg0")
    assert not any("has not joined" in r for r in rows), rows


def test_a_keygen_for_a_new_address_keeps_status_on_the_installed_link(node, tmp_path):
    """Sweep: keygen for a NEW address on a joined worker (the address-move flow, before the
    re-join) records the new CSR address but status keeps checking the link that is actually
    installed, at its joined address; leave clears every join field."""
    node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    link.keygen("wtwg0", "10.78.0.6")
    rec = json.loads(link._paths("wtwg0")["state"].read_text())
    assert rec["worker_ip"] == "10.78.0.6" and rec["joined_worker_ip"] == "10.78.0.5"
    _ok, rows = link.status("wtwg0")
    assert any(r == "overlay address: 10.78.0.5" for r in rows), rows
    link.leave("wtwg0")
    rec = json.loads(link._paths("wtwg0")["state"].read_text())
    assert not any(k in rec for k in ("host_ip", "agent_port", "name", "joined_worker_ip"))


#: What `pfctl -s rules` prints for the stock macOS /etc/pf.conf (observed as root on a Mac).
STOCK_MAIN_RULES = 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'


@pytest.mark.parametrize("main,ok", [
    (STOCK_MAIN_RULES, True),                                            # the stock form
    ('anchor "com.apple/*"    all\n', True),                             # spacing only
    ('anchor "com.apple/*" on en0 all\n', False),                        # an interface
    ('anchor "com.apple/*" in all\n', False),                            # one direction
    ('anchor "com.apple/*" inet6 all\n', False),                         # another family
    ('anchor "com.apple/*" proto tcp all\n', False),                     # one protocol
    ('anchor "com.apple/*" from 192.0.2.0/24 to any\n', False),          # addresses
    ('anchor "com.apple/*" tagged X all\n', False),                      # a tag
    ('anchor "com.apple/*" on en0 all\nanchor "com.apple/*" all\n', True),  # plus the real one
])
def test_only_an_unconditional_parent_anchor_counts_as_enforcement(mac, main, ok):
    """REGRESSION (review): any main-ruleset line CONTAINING `anchor "com.apple/*"` passed --
    but `anchor "com.apple/*" on en0 all` (or a direction/family/proto/address/tag selector)
    never evaluates the child anchor for the link's utun. Only the bare form counts, in
    pf_in_force and in the watchdog."""
    rules = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                          agent_port=8765)
    missing = link.pf_in_force(info="Status: Enabled", main_rules=main, anchor_rules=rules,
                               real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                               agent_port=8765)
    assert (missing == []) is ok, missing
    mac.up("utun7")
    mac.main_rules(main)
    if ok:
        mac.run()
    else:
        with pytest.raises(AssertionError, match="unconditionally"):
            mac.run()


def test_a_bypass_before_the_unconditional_anchor_is_still_caught_behind_a_conditional_one(mac):
    """The pass-quick ordering check now stops only at the UNCONDITIONAL invocation: a broad
    `pass quick` placed after a conditional anchor but before the real one still bypasses."""
    main = ('anchor "com.apple/*" on en0 all\npass quick all\nanchor "com.apple/*" all\n')
    rules = link.pf_rules(real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                          agent_port=8765)
    assert link.pf_main_bypass(main, "utun7") == ["pass quick all"]
    assert link.pf_in_force(info="Status: Enabled", main_rules=main, anchor_rules=rules,
                            real_iface="utun7", worker_ip="10.78.0.5", host_ip="10.78.0.1",
                            agent_port=8765)
    mac.up("utun7")
    mac.main_rules(main)
    with pytest.raises(AssertionError, match="passes"):
        mac.run()


def test_linux_leave_keeps_everything_while_the_reassert_timer_still_runs(node, tmp_path):
    """Sweep (review round 19): the worker's Linux leave had the same unchecked timer/boot-unit
    shutdown as host teardown."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.disable_fails_units.add(link.REASSERT_TIMER_NAME)
    notes = link.leave("wtwg0")
    assert "could not be stopped and disabled" in notes[-1]
    assert n.loaded is not None and link.FW_UNIT.exists() and link._paths("wtwg0")["conf"].exists()
    n.disable_fails_units.clear()
    link.leave("wtwg0")
    assert n.loaded is None


def test_linux_fail_closed_verifies_the_link_unit_was_really_disabled(node, tmp_path,
                                                                      monkeypatch):
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))                 # installed, wg-quick@ enabled
    real = n.run

    def run(argv, **kw):
        if list(argv)[:2] == ["systemctl", "enable"] and argv[-1] == link.FW_UNIT_NAME:
            return subprocess.CompletedProcess(list(argv), 1, "", "Failed to enable")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    n.disable_fails = True                            # ...and its disable will fail
    with pytest.raises(RuntimeError, match="wg-quick@wtwg0 could NOT be disabled"):
        link.join(_bundle(tmp_path, csr))


def test_the_watchdog_keeps_its_pf_enable_token(mac, tmp_path):
    """REGRESSION (review): `pfctl -E` returns an enable-reference token, which was discarded
    -- so removing worker-link left pf globally enabled when it had been off. The watchdog
    keeps the token for `leave` to release."""
    mac.up("utun7")
    mac.pf("Disabled")
    mac.run()
    tokens = tmp_path / "state" / "blastbox-worker-link.wtwg0.pftokens"
    assert tokens.read_text().split() == ["4242"]


def test_the_watchdog_kills_worker_initiated_pf_states_when_it_loads_the_anchor(mac):
    """Sweep of the established-flow finding for macOS: pf matches STATES before rules, so a
    connection the worker opened while the anchor was flushed would survive the reload. The
    watchdog kills states from this worker to the host whenever it (re)loads the anchor."""
    mac.up("utun7")
    calls = mac.run()
    assert "pfctl -k 10.78.0.5 -k 10.78.0.1" in calls


def test_leave_releases_the_pf_enable_token_and_handles_a_lapsed_one(node, tmp_path,
                                                                     monkeypatch):
    n = node("darwin")
    monkeypatch.setattr(link, "PF_STATE_DIR", tmp_path / "varrun")
    (tmp_path / "varrun").mkdir()
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    tok = Path(link.pf_token_file("wtwg0"))
    tok.write_text("4242\n5151\n")
    real = n.run

    def run(argv, **kw):
        a = [str(x) for x in argv]
        if Path(a[0]).name == "pfctl" and a[1:2] == ["-X"]:
            n.calls.append(a)
            return subprocess.CompletedProcess(a, 0 if a[2] == "4242" else 1, "", "")
        return real(argv, **kw)

    monkeypatch.setattr(link, "_run", run)
    notes = link.leave("wtwg0")
    assert any(c[-2:] == ["-X", "4242"] for c in n.calls)
    assert any("released 1 enable reference" in x and "1 had already lapsed" in x for x in notes)
    assert not tok.exists()


def test_linux_leave_stops_and_verifies_an_in_flight_reassert_run(node, tmp_path):
    """The worker twin of the host fix: the re-assert oneshot, not only its timer."""
    n = node("linux")
    _pub, csr, _ = link.keygen("wtwg0", "10.78.0.5")
    link.join(_bundle(tmp_path, csr))
    n.activating.add(link.REASSERT_SERVICE_NAME)
    n.stop_fails.add(link.REASSERT_SERVICE_NAME)
    notes = link.leave("wtwg0")
    assert link.REASSERT_SERVICE_NAME in notes[-1] and "could not be stopped" in notes[-1]
    assert n.loaded is not None and link.FW_UNIT.exists()
    n.stop_fails.clear()
    link.leave("wtwg0")
    assert n.loaded is None
