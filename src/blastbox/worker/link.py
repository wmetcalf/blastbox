"""``blastbox worker-link {keygen,join,status,leave}`` -- the WORKER end of the worker-link overlay.

The host end (``init``/``add``/``remove``/``list``/``teardown``) and the design live in
:mod:`blastbox.host.worker_link`; read its docstring first. In one line: the worker dials the
dispatcher host over WireGuard (``PersistentKeepalive`` holds its NAT open), and the dispatcher
reaches this worker's ``http_agent`` at ``https://<overlay ip>:8765`` through that tunnel.

Lean on purpose, like :mod:`blastbox.worker.sandbox.macos_tool`: a worker may install
``blastbox`` without the ``[host]`` extra, so nothing here imports ``cryptography``. The TLS
key and CSR are made with the ``openssl`` binary, and the WireGuard key with ``wg``. Only the
stdlib-only host modules (the validators, the bundle format, ``parse_wg_dump``) are imported.

KEYS NEVER LEAVE THIS MACHINE. ``keygen`` generates the WireGuard key and the TLS key here,
as root, into root-only files, and prints ONLY the public key and a CSR. Neither private key
is ever printed, logged, put in an argv, or included in anything the operator carries.

Linux and macOS. Windows is out of scope: Windows workers are libvirt VMs on a Linux host, so
the Linux host joins and the VM is reached through it.

Per platform:

* **Linux**: ``wg-quick@<iface>`` under systemd, plus an nftables table
  (``inet blastbox_worker_link_peer``) loaded by its own oneshot unit BEFORE the interface.
* **macOS**: a root LaunchDaemon running a root-owned watchdog script every 30 s, plus a pf
  anchor under Apple's ``com.apple/*``. Two details were each found the hard way on a live
  Mac, and both have regression tests:

  - ``AbandonProcessGroup`` MUST be true. ``wg-quick up`` leaves ``wireguard-go`` running in
    the watchdog's process group; without it launchd kills that group the moment the
    watchdog exits, and the tunnel dies 0-30 s after every successful bring-up.
  - ``wg show <name>`` does not work on macOS for a wg-quick name: the kernel only knows the
    ``utunN`` it was given, recorded in ``/var/run/wireguard/<iface>.name``. A watchdog that
    asks ``wg show wtwg0`` sees "down" every time and tears a healthy tunnel down every 30 s.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from blastbox.host.worker_link import (
    DEFAULT_IFACE,
    JoinBundle,
    _link_iface,
    firewall_in_force,
    firewall_unit,
    in_rfc1918,
    reassert_units,
)

WG_DIR = Path("/etc/wireguard")
KEY_DIR = WG_DIR / "blastbox"
#: TLS key, CSR, cert, CA and the keygen state, per interface. Root-owned.
STATE_DIR = Path("/etc/blastbox/worker-link")

# Linux
NFT_TABLE = "blastbox_worker_link_peer"
FW_FILE = Path("/etc/blastbox/worker-link-peer.nft")
FW_UNIT_NAME = "blastbox-worker-link-peer-fw.service"
FW_UNIT = Path("/etc/systemd/system") / FW_UNIT_NAME
_FW_BASE = FW_UNIT_NAME.removesuffix(".service")
REASSERT_TIMER_NAME = f"{_FW_BASE}-reassert.timer"


def _reassert_paths() -> tuple[Path, Path]:
    """``(service, timer)`` paths, beside FW_UNIT -- resolved at CALL time so they follow it."""
    return (FW_UNIT.with_name(f"{_FW_BASE}-reassert.service"),
            FW_UNIT.with_name(REASSERT_TIMER_NAME))
EGRESS_ENV = Path("/etc/blastbox/egress.env")

# macOS
LAUNCHD_DIR = Path("/Library/LaunchDaemons")
SUPPORT_DIR = Path("/Library/Application Support/blastbox")
WG_RUN_DIR = Path("/var/run/wireguard")
LOG_FILE = Path("/var/log/blastbox-worker-link.log")
PFCTL = "/sbin/pfctl"
#: Extra places to find wireguard-tools under sudo, whose secure_path usually omits Homebrew.
_EXTRA_BIN = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/sbin", "/sbin")
#: How often launchd re-runs the watchdog.
WATCHDOG_INTERVAL_S = 30
#: Upper bound on waiting for the first handshake at the end of `join` (informational only).
HANDSHAKE_WAIT_S = 15.0


def label_for(iface: str) -> str:
    return f"io.blastbox.worker-link.{_link_iface(iface)}"


def pf_anchor_for(iface: str) -> str:
    """Under ``com.apple/``: Apple's stock /etc/pf.conf already evaluates ``anchor "com.apple/*"``,
    so the rules are reached without editing pf.conf (an OS update rewrites it)."""
    return f"com.apple/250.blastbox.worker-link.{_link_iface(iface)}"


# --------------------------------------------------------------------------------------
# Shelling out (one seam, argv lists only, secrets via stdin)
# --------------------------------------------------------------------------------------

def _run(argv: list[str], *, input: str | None = None) -> subprocess.CompletedProcess:
    """Run argv (never a shell). A missing binary is an ordinary failed result (127)."""
    try:
        return subprocess.run(list(argv), input=input, text=True, capture_output=True,
                              check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(list(argv), 127, "", f"{exc.strerror}: {argv[0]}")


def _ok(argv: list[str]) -> bool:
    return _run(argv).returncode == 0


def _platform() -> str:
    return sys.platform


def _euid() -> int:
    return os.geteuid()


_sleep: Callable[[float], None] = time.sleep


def _chown(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)


def _refuse_untrusted_path(path: Path) -> None:
    """Raise unless ``path`` and every directory above it are root-owned and not writable by
    group or other: the file is executed or loaded by root, so anyone who can replace any
    component of its path runs code as root."""
    for p in (path, *path.parents):
        st = os.lstat(p)
        if not _root_owned_and_private(st):
            raise RuntimeError(f"{p} is not root-owned and private (uid {st.st_uid}, mode "
                               f"{oct(st.st_mode & 0o7777)}); refusing to install a root-run "
                               f"file under it")


def _root_owned_and_private(st: os.stat_result) -> bool:
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode) and st.st_uid == 0:
        return True     # e.g. macOS's /etc -> private/etc: root's own link
    return st.st_uid == 0 and not st.st_mode & 0o022


def _which(name: str) -> str | None:
    path = os.pathsep.join([os.environ.get("PATH", ""), *_EXTRA_BIN])
    return shutil.which(name, path=path)


def _need(name: str, package: str) -> str:
    p = _which(name)
    if not p:
        raise RuntimeError(f"`{name}` is not installed (package: {package})")
    return p


def _require_root(what: str) -> None:
    if _euid() != 0:
        raise RuntimeError(f"`worker-link {what}` writes root-only key material and network "
                           "config; run it with sudo")


def _supported_platform() -> str:
    plat = _platform()
    if plat.startswith("linux"):
        return "linux"
    if plat == "darwin":
        return "darwin"
    raise RuntimeError(
        f"worker-link supports Linux and macOS workers, not {plat}. Windows workers are libvirt "
        "VMs on a Linux host: join that host, and reach the VM through it.")


def _write_atomic(path: Path, data: str | bytes, mode: int) -> None:
    """Write ``path`` as a NEW file and rename it into place; never open the old one.

    Opening ``path`` itself (``O_TRUNC``, ``Path.write_text``) FOLLOWS a symlink at the leaf:
    if anyone else could create entries in the directory before it was locked down (the
    macOS support dir may have been made by a user tool), a pre-planted
    ``worker-link-<iface>.sh -> /some/root/file`` would have root truncate, overwrite and
    chmod the target. Instead the data goes to a fresh ``mkstemp`` file (``O_CREAT|O_EXCL``:
    never an existing entry, never through a link), gets its mode by ``fchmod`` on that fd,
    and ``rename`` replaces the directory ENTRY -- a symlink there is replaced, its target
    never touched. A directory or other non-file at ``path`` is refused before anything is
    written.
    """
    import stat as _stat

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not (_stat.S_ISREG(st.st_mode) or _stat.S_ISLNK(st.st_mode)):
            raise RuntimeError(f"{path} exists and is not a regular file; refusing to replace it")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _write_private(path: Path, data: str) -> None:
    """0600 from creation (never a looser window), replacing -- not following -- whatever
    entry was at ``path``."""
    _write_atomic(path, data, 0o600)


def _write_public(path: Path, data: str | bytes, mode: int = 0o644) -> None:
    _write_atomic(path, data, mode)


# --------------------------------------------------------------------------------------
# Pure renderers
# --------------------------------------------------------------------------------------

def _v4(value: str, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        raise ValueError(f"invalid {what} {value!r} (IPv4 expected)") from None


def worker_wg_config(*, private_key: str, worker_ip: str, host_ip: str,
                     host_public_key: str, endpoint: str) -> str:
    """``wg-quick`` config for the WORKER end.

    ``AllowedIPs`` is the HOST'S /32 and nothing else, which is the opposite of the egress
    peer's ``0.0.0.0/0``: this tunnel carries dispatcher -> agent traffic only. WireGuard
    therefore drops anything arriving from the host that is not sourced from the host's own
    overlay address, and never encrypts toward anything but it -- so a worker cannot use the
    link to reach other workers or anything behind the host, whatever its routing table says,
    and wg-quick installs exactly one route (the host /32), no default route and no fwmark
    rules that could capture this node's other traffic (including the egress overlay's).

    ``Address`` is a /32 for the same reason: the worker has no business routing the rest of
    the overlay. ``PersistentKeepalive = 25`` is what makes NAT work: it keeps the worker's
    outbound UDP mapping alive so the host's packets can find their way back in.
    """
    w, h = _v4(worker_ip, "worker ip"), _v4(host_ip, "host ip")
    return (
        "# blastbox worker-link — WORKER end. Generated by `blastbox worker-link join`.\n"
        "# AllowedIPs is the host /32 ONLY; see blastbox.worker.link.worker_wg_config.\n"
        "[Interface]\n"
        f"Address = {w}/32\n"
        f"PrivateKey = {private_key.strip()}\n"
        "\n[Peer]\n"
        f"PublicKey = {host_public_key.strip()}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {h}/32\n"
        "PersistentKeepalive = 25\n"
    )


def worker_firewall_nft(*, iface: str, worker_ip: str, host_ip: str, agent_port: int) -> str:
    """Linux worker ruleset: on the link, ONLY the host may open tcp/<agent_port> to us.

    * ``input``: NEW from the host's /32 to our /32 on ``agent_port``; replies; drop the
      rest. And our overlay address is reachable ONLY over the link -- Linux delivers a
      packet for a local address arriving on any interface (weak host), so a job container on
      a docker bridge (a ``direct``/``inetsim`` personality, or any netns routed by this host)
      could otherwise connect to the agent's overlay address from inside the node.
    * ``forward``: nothing is routed into or out of the link, except the host's connection
      to an agent in a docker container published on our overlay address (DNAT makes that a
      forward) and its replies. A job container's packets toward the host's overlay address
      are FORWARDED by this node and NEW, so they are dropped: this is the rule that keeps a
      sample from reaching the dispatcher over the control link -- whatever its egress
      personality, and independent of the leak guard's optional ``block_internal``.
    * ``output``: only replies. Nothing on this worker may open a connection to the host
      over the link; there is no legitimate reason to, and the host drops it as well.
    """
    i = _link_iface(iface)
    w, h = _v4(worker_ip, "worker ip"), _v4(host_ip, "host ip")
    p = int(agent_port)
    if not 1 <= p <= 65535:
        raise ValueError(f"invalid agent port {agent_port!r}")
    t = NFT_TABLE
    return "\n".join([
        f"# blastbox worker-link — WORKER firewall for {i}. Generated by `blastbox worker-link",
        "# join` from blastbox.worker.link.worker_firewall_nft. Only the host may open",
        f"# tcp/{p}; nothing is routed through the link.",
        f"table inet {t} {{}}",
        f"delete table inet {t}",
        f"table inet {t} {{",
        "\tchain input {",
        "\t\ttype filter hook input priority filter; policy accept;",
        f'\t\tiifname "{i}" ip saddr {h} ip daddr {w} tcp dport {p} ct state new accept',
        f'\t\tiifname "{i}" ct state established,related accept',
        f'\t\tiifname "{i}" drop',
        f'\t\tiifname != {{ "lo", "{i}" }} ip daddr {w} drop',
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority filter; policy accept;",
        # An agent in a docker container with its port published on the overlay address is
        # reached by DNAT, i.e. FORWARDED: admit exactly the host's connection to that
        # published address/port, matched on conntrack's ORIGINAL tuple (pre-DNAT).
        f'\t\tiifname "{i}" ip saddr {h} ct original ip daddr {w} ct original proto-dst {p} '
        "ct status dnat ct state new accept",
        f'\t\tiifname "{i}" ct state established,related accept',
        f'\t\toifname "{i}" ct state established,related accept',
        f'\t\tiifname "{i}" drop',
        f'\t\toifname "{i}" drop',
        "\t}",
        "\tchain output {",
        "\t\ttype filter hook output priority filter; policy accept;",
        f'\t\toifname "{i}" ct state established,related accept',
        f'\t\toifname "{i}" drop',
        "\t}",
        "}",
    ]) + "\n"


def pf_rules(*, real_iface: str, worker_ip: str, host_ip: str, agent_port: int) -> str:
    """macOS pf anchor rules for the link, on its CURRENT utun.

    pf keeps state, so the replies of the one connection we pass skip the blocks; the
    ``block out`` is what stops anything on this Mac opening a connection to the host over the
    link. ``real_iface`` may be the shell placeholder ``$REAL`` (the watchdog substitutes the
    utun it read from wg-quick's name file); anything else must be a ``utunN``.
    """
    if real_iface != "$REAL" and not re.fullmatch(r"utun[0-9]{1,3}", real_iface):
        raise ValueError(f"unexpected macOS WireGuard interface {real_iface!r}")
    w, h = _v4(worker_ip, "worker ip"), _v4(host_ip, "host ip")
    p = int(agent_port)
    return (
        f"pass in quick on {real_iface} inet proto tcp from {h} to {w} port {p} "
        "flags S/SA keep state\n"
        f"block drop in quick on {real_iface} all\n"
        f"block drop out quick on {real_iface} all\n"
        f"block drop in quick on ! {real_iface} inet from any to {w}\n"
    )


def pf_closed_rules(*, worker_ip: str, host_ip: str) -> str:
    """Loaded BEFORE ``wg-quick up`` so the link is never up without rules: nothing reaches
    our overlay address and nothing leaves for the host's, on any interface, until the real
    rules for the new utun replace these."""
    w, h = _v4(worker_ip, "worker ip"), _v4(host_ip, "host ip")
    return (f"block drop quick inet from any to {w}\n"
            f"block drop out quick inet from any to {h}\n")


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def watchdog_script(*, iface: str, worker_ip: str, host_ip: str, agent_port: int,
                    wg: str, wg_quick: str, pfctl: str = PFCTL,
                    run_dir: str = str(WG_RUN_DIR), state_dir: str = "/var/run") -> str:
    """The root-owned script the macOS LaunchDaemon runs every 30 s. Re-ups ONLY when down.

    It reads the REAL interface from ``<run_dir>/<iface>.name`` -- wg-quick's record of the
    ``utunN`` it was given -- because ``wg show <iface>`` cannot work on macOS (the kernel
    never heard of that name). "Up" means: the name file exists, names a utun, and
    ``wg show <utun>`` answers. Only then is nothing done to the tunnel. Otherwise: load the
    CLOSED pf rules, ``wg-quick down`` (clears a half-up state) and ``up``.

    After that, every run re-asserts pf: enable it if macOS left it disabled (it ships that
    way, and is disabled again after every boot), and reload the anchor if it is not the one
    for the current utun. pf is what is IN FORCE; the anchor text on disk proves nothing.

    A shell script, not Python, on purpose: it runs as ROOT, so it must not execute anything
    the logged-in user can modify -- a user-owned virtualenv would be exactly that. Every
    value it uses was validated and rendered in at ``join`` time. (The wireguard-tools it
    pins are typically Homebrew's, which ARE user-writable; that is the standard trade-off
    for WireGuard on macOS and is documented in DEPLOYMENT.md.)
    """
    i = _link_iface(iface)
    namefile = f"{run_dir.rstrip('/')}/{i}.name"
    anchor = pf_anchor_for(i)
    rules = pf_rules(real_iface="$REAL", worker_ip=worker_ip, host_ip=host_ip,
                     agent_port=agent_port)
    closed = pf_closed_rules(worker_ip=worker_ip, host_ip=host_ip)
    # What the loaded anchor must be FOR: the current utun and THESE rules. A changed agent port
    # (or address) changes the digest, so a re-join reloads pf even with the tunnel left up.
    import hashlib

    digest = hashlib.sha256(rules.encode()).hexdigest()[:16]
    canon = "\n".join(pf_canon(rules))
    sed = _PF_CANON_SED
    stamp = f"{state_dir.rstrip('/')}/blastbox-worker-link.{i}.pf"
    path = ":".join([*_EXTRA_BIN[:2], "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    return f"""#!/bin/sh
# blastbox worker-link watchdog for {i} (macOS). Generated by `blastbox worker-link join`
# from blastbox.worker.link.watchdog_script; run by the {label_for(i)} LaunchDaemon every
# {WATCHDOG_INTERVAL_S}s. Re-ups the tunnel ONLY when it is down, and re-asserts its pf rules.
set -u
PATH={_sh_quote(path)}
export PATH
IFACE={_sh_quote(i)}
WG={_sh_quote(wg)}
WG_QUICK={_sh_quote(wg_quick)}
PFCTL={_sh_quote(pfctl)}
NAMEFILE={_sh_quote(namefile)}
ANCHOR={_sh_quote(anchor)}
STAMP={_sh_quote(stamp)}
DIGEST={_sh_quote(digest)}
REAL=''

log() {{ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) worker-link[$IFACE]: $*"; }}

# The utun wg-quick actually created. `wg show $IFACE` can never work on macOS.
real_iface() {{
    [ -r "$NAMEFILE" ] || return 1
    REAL=$(cat "$NAMEFILE" 2>/dev/null) || return 1
    case "$REAL" in
        utun[0-9]|utun[0-9][0-9]|utun[0-9][0-9][0-9]) return 0 ;;
    esac
    REAL=''
    return 1
}}

pf_closed() {{
    "$PFCTL" -a "$ANCHOR" -f - 2>/dev/null <<EOF
{closed}EOF
}}

pf_open() {{
    "$PFCTL" -a "$ANCHOR" -f - 2>/dev/null <<EOF
{rules}EOF
}}

# pf must be ENABLED for any anchor to be evaluated; macOS boots with it disabled. If it cannot
# be enabled the link must not be up: its rules would be text, not enforcement.
if ! "$PFCTL" -s info 2>/dev/null | grep -q '^Status: Enabled'; then
    "$PFCTL" -E >/dev/null 2>&1
    if ! "$PFCTL" -s info 2>/dev/null | grep -q '^Status: Enabled'; then
        log "pf could not be enabled; taking the link DOWN"
        "$WG_QUICK" down "$IFACE" >/dev/null 2>&1
        exit 1
    fi
fi
# ...and the main ruleset must still EVALUATE our anchor. A VPN client or kill-switch app that
# loads its own main ruleset drops `anchor "com.apple/*"`, and every rule below is then text.
if ! "$PFCTL" -s rules 2>/dev/null | grep -qF 'anchor "com.apple/*"'; then
    log 'the main pf ruleset does not evaluate anchor "com.apple/*"; taking the link DOWN'
    "$WG_QUICK" down "$IFACE" >/dev/null 2>&1
    exit 1
fi

if real_iface && "$WG" show "$REAL" >/dev/null 2>&1; then
    :   # up: leave the tunnel alone
else
    log "link down; bringing it up"
    if ! pf_closed; then
        log "pf refused the closed ruleset; NOT bringing the link up"
        exit 1
    fi
    rm -f "$STAMP"
    "$WG_QUICK" down "$IFACE" >/dev/null 2>&1 || true
    if ! "$WG_QUICK" up "$IFACE"; then
        log "wg-quick up failed"
        exit 1
    fi
    if ! real_iface; then
        log "wg-quick up left no usable $NAMEFILE"
        exit 1
    fi
fi

WANT="$REAL $DIGEST"
# The anchor must hold EXACTLY our rules (canonicalised as blastbox.worker.link.pf_canon does):
# a broader rule added ahead of ours -- `pass in quick on $REAL all` -- is not ours, and the
# expected pass line being present somewhere proves nothing once one is.
EXPECTED=$(cat <<EOF
{canon}
EOF
)
LIVE=$("$PFCTL" -a "$ANCHOR" -s rules 2>/dev/null | {sed})
if [ "$(cat "$STAMP" 2>/dev/null)" != "$WANT" ] || [ "$LIVE" != "$EXPECTED" ]; then
    if ! pf_open; then
        log "pf refused the link ruleset for $REAL; taking the link DOWN"
        rm -f "$STAMP"
        "$WG_QUICK" down "$IFACE" >/dev/null 2>&1
        exit 1
    fi
    echo "$WANT" > "$STAMP"
    log "pf rules loaded for $REAL"
fi
exit 0
"""


def launchd_plist(*, label: str, script: str, log_file: str = str(LOG_FILE)) -> bytes:
    """The root LaunchDaemon that runs the watchdog. See the module docstring for why
    ``AbandonProcessGroup`` is not optional."""
    return plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/bin/sh", script],
        "RunAtLoad": True,
        "StartInterval": WATCHDOG_INTERVAL_S,
        # REQUIRED: wireguard-go is left in this job's process group by `wg-quick up`; without
        # this launchd kills it as soon as the watchdog exits.
        "AbandonProcessGroup": True,
        "StandardOutPath": log_file,
        "StandardErrorPath": log_file,
    })


def csr_config(ip: str) -> str:
    """An ``openssl req -config`` file for a CSR whose ONLY SAN is ``IP:<ip>``.

    A config file rather than ``-addext``/``-subj`` flags: the macOS ``openssl`` is LibreSSL,
    whose flag set differs from OpenSSL's, while ``req_extensions`` in a config file is
    understood by both. The host signs only a CSR whose SAN is exactly the allocated address.
    """
    a = _v4(ip, "overlay ip")
    return ("[req]\nprompt = no\ndistinguished_name = dn\nreq_extensions = ext\n"
            f"[dn]\nCN = blastbox-worker-link-{a}\n"
            f"[ext]\nsubjectAltName = IP:{a}\n")


def agent_env_lines(*, worker_ip: str, host_ip: str, agent_port: int,
                    cert: Path, key: Path, ca: Path) -> list[str]:
    return [
        f"BLASTBOX_WORKER_AGENT_BIND={worker_ip}",
        f"BLASTBOX_WORKER_AGENT_PORT={agent_port}",
        f"BLASTBOX_WORKER_AGENT_ALLOW_CIDRS={host_ip}/32",
        f"BLASTBOX_WORKER_AGENT_TLS_CERT={cert}",
        f"BLASTBOX_WORKER_AGENT_TLS_KEY={key}",
        f"BLASTBOX_WORKER_AGENT_CLIENT_CA={ca}",
    ]


#: How the watchdog canonicalises a pf listing; MUST stay identical to :func:`pf_canon`.
#: pfctl re-renders what it was given: runs of whitespace, ``port 8765`` as ``port = 8765``,
#: and the defaults ``flags S/SA keep state`` it adds to (or prints on) a pass rule. None of
#: that changes which packets match, so it is normalised away; every address, interface,
#: direction and verdict is kept.
_PF_CANON_SED = (r"sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' "
                 r"-e 's/ port = / port /g' -e 's| flags S/SA||g' -e 's/ keep state//g' "
                 r"-e '/^$/d'")


def pf_canon(text: str) -> list[str]:
    """A pf rule listing as canonical lines (see ``_PF_CANON_SED``, its shell twin)."""
    out: list[str] = []
    for raw in (text or "").splitlines():
        ln = " ".join(raw.split())
        ln = ln.replace(" port = ", " port ").replace(" flags S/SA", "").replace(" keep state", "")
        if ln:
            out.append(ln)
    return out


def pf_in_force(*, info: str, main_rules: str, anchor_rules: str, real_iface: str | None,
                worker_ip: str, host_ip: str, agent_port: int) -> list[str]:
    """What is missing for the macOS pf rules to be IN FORCE, or [].

    The anchor must hold EXACTLY our rules, in our order (canonical form, :func:`pf_canon`):
    a rule that is merely PRESENT proves nothing if a broader one -- ``pass in quick on utun7
    all`` -- was added ahead of it, since ``quick`` makes the first match final."""
    missing: list[str] = []
    if not re.search(r"^Status: Enabled", info or "", re.M):
        missing.append("pf is DISABLED (no anchor is evaluated)")
    if 'anchor "com.apple/*"' not in (main_rules or ""):
        missing.append('the main pf ruleset does not evaluate anchor "com.apple/*"')
    if not real_iface:
        missing.append("no live utun recorded for the link")
        return missing
    want = pf_canon(pf_rules(real_iface=real_iface, worker_ip=worker_ip, host_ip=host_ip,
                             agent_port=agent_port))
    got = pf_canon(anchor_rules)
    if got != want:
        missing += [f"`{ln}`" for ln in want if ln not in got]
        missing += [f"unexpected rule `{ln}`" for ln in got if ln not in want]
        if sorted(got) == sorted(want):
            missing.append("the anchor's rules are ours but in a different order")
    return missing


# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------

def _paths(iface: str) -> dict[str, Path]:
    i = _link_iface(iface)
    return {
        "wg_key": KEY_DIR / f"{i}.key",
        "wg_pub": KEY_DIR / f"{i}.pub",
        "conf": WG_DIR / f"{i}.conf",
        "tls_key": STATE_DIR / f"{i}.key",
        "csr": STATE_DIR / f"{i}.csr",
        "cert": STATE_DIR / f"{i}.crt",
        "ca": STATE_DIR / f"{i}-ca.crt",
        "state": STATE_DIR / f"{i}.json",
        "plist": LAUNCHD_DIR / f"{label_for(i)}.plist",
        "script": SUPPORT_DIR / f"worker-link-{i}.sh",
    }


def _load_state(iface: str) -> dict:
    p = _paths(iface)["state"]
    try:
        obj = json.loads(p.read_text())
    except FileNotFoundError:
        raise RuntimeError(f"no keygen state for {iface} ({p}): run `blastbox worker-link "
                           "keygen --ip <addr>` first") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {p}: {exc}") from None
    if not isinstance(obj, dict) or obj.get("iface") != iface or "worker_ip" not in obj:
        raise RuntimeError(f"{p} is not a worker-link keygen record for {iface}")
    return obj


# --------------------------------------------------------------------------------------
# keygen
# --------------------------------------------------------------------------------------

def _wg_pubkey(wg: str, private: str) -> str:
    proc = _run([wg, "pubkey"], input=private)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError("`wg pubkey` failed")
    return proc.stdout.strip()


def keygen(iface: str, ip: str, *, rotate: bool = False) -> tuple[str, str, list[str]]:
    """Make (or reuse) this worker's WireGuard key, TLS key and a CSR for ``ip``.

    Returns ``(wireguard public key, CSR PEM, notes)``. Idempotent: an existing key is reused
    unless ``rotate`` -- re-running to change ``ip`` regenerates only the CSR. Both private
    keys are written root-only 0600 and never returned.
    """
    _require_root("keygen")
    _supported_platform()
    iface = _link_iface(iface)
    addr = ipaddress.IPv4Address(_v4(ip, "overlay ip"))
    if not in_rfc1918(addr):
        raise ValueError(f"{addr} is not an RFC 1918 address; use the one `worker-link list` "
                         "on the host shows as next free")
    wg = _need("wg", "wireguard-tools")
    openssl = _need("openssl", "openssl")
    p = _paths(iface)
    notes: list[str] = []
    for d in (KEY_DIR, STATE_DIR):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700 if d == KEY_DIR else 0o755)
    os.chmod(WG_DIR, 0o700)

    if rotate or not p["wg_key"].exists() or p["wg_key"].stat().st_size == 0:
        gen = _run([wg, "genkey"])
        if gen.returncode != 0 or not gen.stdout.strip():
            raise RuntimeError("`wg genkey` failed")
        _write_private(p["wg_key"], gen.stdout.strip() + "\n")
        notes.append(f"WireGuard key generated ({p['wg_key']}, 0600)")
    else:
        os.chmod(p["wg_key"], 0o600)
        notes.append(f"WireGuard key reused ({p['wg_key']})")
    pub = _wg_pubkey(wg, p["wg_key"].read_text())
    _write_public(p["wg_pub"], pub + "\n")

    if rotate or not p["tls_key"].exists() or p["tls_key"].stat().st_size == 0:
        with tempfile.TemporaryDirectory(dir=STATE_DIR) as td:
            tmp = Path(td) / "key.pem"
            old = os.umask(0o077)
            try:
                proc = _run([openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                             "-out", str(tmp)])
            finally:
                os.umask(old)
            if proc.returncode != 0 or not tmp.exists():
                raise RuntimeError("openssl could not generate the TLS key")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p["tls_key"])
        notes.append(f"TLS key generated ({p['tls_key']}, 0600)")
    else:
        os.chmod(p["tls_key"], 0o600)
        notes.append(f"TLS key reused ({p['tls_key']})")

    with tempfile.TemporaryDirectory(dir=STATE_DIR) as td:
        cfg_file = Path(td) / "req.cnf"
        cfg_file.write_text(csr_config(str(addr)))
        out = Path(td) / "req.csr"
        proc = _run([openssl, "req", "-new", "-sha256", "-key", str(p["tls_key"]),
                     "-config", str(cfg_file), "-out", str(out)])
        if proc.returncode != 0 or not out.exists():
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
            raise RuntimeError(f"openssl could not make the CSR: {tail[0]}")
        csr = out.read_text()
    _write_public(p["csr"], csr)
    _write_public(p["state"], json.dumps({"iface": iface, "worker_ip": str(addr)}) + "\n")
    return pub, csr, notes


# --------------------------------------------------------------------------------------
# join
# --------------------------------------------------------------------------------------

def _openssl_pub(openssl: str, argv: list[str]) -> str:
    proc = _run([openssl, *argv])
    if proc.returncode != 0:
        return ""
    return "".join(proc.stdout.split())


def verify_cert(openssl: str, *, cert: Path, ca: Path, key: Path, ip: str) -> None:
    """Refuse a certificate that is not for THIS key, THIS address, from THIS CA."""
    if _run([openssl, "verify", "-CAfile", str(ca), str(cert)]).returncode != 0:
        raise RuntimeError("the bundle's certificate does not verify against its CA")
    mine = _openssl_pub(openssl, ["pkey", "-in", str(key), "-pubout"])
    theirs = _openssl_pub(openssl, ["x509", "-in", str(cert), "-noout", "-pubkey"])
    if not mine or mine != theirs:
        raise RuntimeError("the bundle's certificate is not for this worker's TLS key (was the "
                           "CSR from another machine, or was keygen re-run with --rotate?)")
    text = _run([openssl, "x509", "-in", str(cert), "-noout", "-text"]).stdout or ""
    sans = re.findall(r"IP Address:([0-9.]+)", text)
    if sans != [ip]:
        raise RuntimeError(f"the bundle's certificate names {sans or 'no IP'}, not {ip}")


def _resolve(host: str) -> list[str]:
    h = host[1:-1] if host.startswith("[") else host
    try:
        infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_UDP)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve the host endpoint {host!r}: {exc}") from None
    return sorted({str(i[4][0]) for i in infos})


def _egress_env() -> dict[str, str]:
    try:
        text = EGRESS_ENV.read_text()
    except OSError:
        return {}
    out = {}
    for line in text.splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and not k.startswith("#"):
            out[k.strip()] = v.strip()
    return out


#: ``ip -d link`` kinds / link types that are a tunnel or VPN, not an underlay. A route to the
#: host endpoint through any of them makes the control link depend on that tunnel.
_TUNNEL_KINDS = frozenset({"wireguard", "tun", "ipip", "gre", "gretap", "ip6gre", "ip6gretap",
                           "sit", "vti", "vti6", "ip6tnl", "xfrm", "erspan", "ip6erspan"})
_TUNNEL_LINK_TYPES = frozenset({"none", "ipip", "gre", "sit", "tunnel6", "ip6gre", "ip6tnl"})


def _linux_tunnel_kind(dev: str) -> str | None:
    """What kind of tunnel ``dev`` is (``"wireguard"``, ``"tun"``, ...), or None for an
    ordinary underlay device. Asked of the kernel (``ip -d -j link show``), not guessed from
    the name. A device whose kind cannot be read is refused: "cannot tell" is not "underlay"."""
    import json as _json

    proc = _run(["ip", "-d", "-j", "link", "show", "dev", dev])
    try:
        info = (_json.loads(proc.stdout or "[]") or [None])[0]
    except (ValueError, IndexError):
        info = None
    if proc.returncode != 0 or not isinstance(info, dict):
        return f"a device whose type could not be read ({dev})"
    kind = str((info.get("linkinfo") or {}).get("info_kind") or "")
    if kind in _TUNNEL_KINDS:
        return f"a {kind} tunnel"
    link_type = str(info.get("link_type") or "")
    if link_type in _TUNNEL_LINK_TYPES:
        return f"a tunnel (link type {link_type})"
    return None


def _tunnel_route_error(ip: str, dev: str, kind: str) -> str:
    return (f"the route to the host endpoint {ip} goes via {dev} ({kind}): the link's handshake "
            "would ride that tunnel instead of the underlay, so the control link would break "
            "whenever it restarts or changes policy. Exclude the host's address from that VPN "
            f"(split-tunnel {ip}/32 to the local network, or add a host route for {ip} via your "
            "underlay gateway) and re-run join. Other VPNs may stay up; only the route to "
            f"{ip} must not use one.")


def darwin_preflight(bundle: JoinBundle) -> list[str]:
    """macOS: the route to the host endpoint must not go through a tunnel. Other VPN utuns
    may exist and stay up (a corporate split-tunnel VPN is fine); what is refused is the
    endpoint's OWN route using one, as ``route -n get`` reports it for that address."""
    notes: list[str] = []
    host = bundle.endpoint.rsplit(":", 1)[0]
    routable = 0
    for ip in _resolve(host):
        proc = _run(["route", "-n", "get", *(["-inet6"] if ":" in ip else []), ip])
        m = re.search(r"^\s*interface:\s*(\S+)", proc.stdout or "", re.M)
        if proc.returncode != 0 or not m:
            notes.append(f"no underlay route to the endpoint address {ip} (unused)")
            continue
        routable += 1
        dev = m.group(1)
        if re.fullmatch(r"(utun|ipsec|tun)[0-9]+", dev):
            raise RuntimeError(_tunnel_route_error(ip, dev, "a VPN/tunnel interface"))
        notes.append(f"underlay route to the endpoint {ip}: via {dev}")
    if not routable:
        raise RuntimeError(f"no underlay route to the host endpoint {host}")
    return notes


def linux_preflight(bundle: JoinBundle) -> list[str]:
    """Linux-only checks against the EGRESS overlay and this node's routing. Raises on a
    conflict; returns notes.

    1. The link must not reuse the egress interface or overlap its overlay (read from
       /etc/blastbox/egress.env when this node is an egress peer).
    2. The link's two /32s must not already be routed somewhere on this node.
    3. THE UNDERLAY ROUTE TO THE HOST ENDPOINT must not go through a tunnel. In egress global
       mode nothing captures it -- the egress peer runs ``Table = off`` and its only policy
       rules select the forwarder's source address, never this node's own -- but a
       full-tunnel VPN, a stray default via ``bbwg0``, or a route through the link itself
       would. Then the handshake would ride the tunnel it is meant to establish (or the
       egress exit), and the link either never comes up or silently depends on egress.
       ``ip route get`` evaluates the policy rules exactly as the kernel will for the
       WireGuard socket, so it is asked rather than reasoned about.
    """
    import json as _json

    notes: list[str] = []
    eg = _egress_env()
    egress_if = eg.get("BLASTBOX_EGRESS_WG_IF") or "bbwg0"
    egress_net = eg.get("BLASTBOX_EGRESS_OVERLAY_NET") or "10.77.0.0/24"
    if bundle.iface == egress_if:
        raise RuntimeError(f"{bundle.iface} is this node's egress overlay interface")
    try:
        if ipaddress.ip_network(egress_net, strict=False).overlaps(
                ipaddress.ip_network(bundle.overlay_net)):
            raise RuntimeError(f"the link overlay {bundle.overlay_net} overlaps this node's "
                               f"egress overlay {egress_net}")
    except ValueError:
        pass
    from blastbox.host import egress_apply as ea

    if not ea.host_route_cidrs():
        raise RuntimeError("cannot read this node's routes (`ip` missing?); refusing to guess")

    class _One:
        def __init__(self, net: str) -> None:
            self.wg_iface, self.overlay_net = bundle.iface, net

    for addr in (bundle.worker_ip, bundle.host_ip):
        hit = ea.overlay_conflict(_One(f"{addr}/32"), own_addresses=True)
        if hit is not None:
            raise RuntimeError(f"{addr} is already routed on this node ({hit}); the link "
                               "would shadow it")
    host = bundle.endpoint.rsplit(":", 1)[0]
    routable = 0
    for ip in _resolve(host):
        fam = ["-6"] if ":" in ip else []
        proc = _run(["ip", *fam, "-j", "route", "get", ip])
        try:
            dev = (_json.loads(proc.stdout or "[]") or [{}])[0].get("dev")
        except (ValueError, AttributeError, IndexError):
            dev = None
        if proc.returncode != 0 or not dev:
            # An address family this node cannot route (an AAAA record on a v4-only node) is
            # not a refusal: WireGuard will use one it can. What must never happen is ANY
            # resolved address leaving through a tunnel.
            notes.append(f"no underlay route to the endpoint address {ip} (unused)")
            continue
        routable += 1
        kind = "the link itself" if dev == bundle.iface else (
            "the egress overlay" if dev == egress_if else _linux_tunnel_kind(dev))
        if kind:
            raise RuntimeError(_tunnel_route_error(ip, dev, kind))
        notes.append(f"underlay route to the endpoint {ip}: via {dev}")
    if not routable:
        raise RuntimeError(f"no underlay route to the host endpoint {host}")
    return notes


def _wait_handshake(wg: str, real_iface: str) -> str:
    from blastbox.host.exit_attest import parse_wg_dump

    deadline = time.monotonic() + HANDSHAKE_WAIT_S
    while True:
        proc = _run([wg, "show", real_iface, "dump"])
        peers = parse_wg_dump(proc.stdout or "") if proc.returncode == 0 else []
        if any(p.ever_connected for p in peers):
            return "handshake with the host: OK"
        if time.monotonic() >= deadline:
            return ("handshake with the host: NOT YET — check the host registered this key "
                    "(`worker-link list`) and that udp to the endpoint is not blocked")
        _sleep(1.0)


def _verify_live_peer(wg: str, bundle: JoinBundle, real_iface: str | None = None) -> None:
    """Raise unless the LIVE interface holds exactly the bundle's host as its one peer,
    allowed only the host /32 -- read from ``wg show <iface> dump``, not from the file. A link
    that is up with some earlier config (another host key, another host address) is not the
    link this join configured."""
    from blastbox.host.exit_attest import parse_wg_dump

    iface = real_iface or bundle.iface
    proc = _run([wg, "show", iface, "dump"])
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise RuntimeError(f"cannot read the live config of {iface} ({tail[0]})")
    peers = parse_wg_dump(proc.stdout or "")
    want = (bundle.host_public_key.strip(), (f"{bundle.host_ip}/32",))
    got = [(p.public_key, tuple(sorted(p.allowed_ips))) for p in peers]
    if got != [want]:
        raise RuntimeError(
            f"{iface} is up but its live peers are not this bundle's host "
            f"({bundle.host_public_key[:10]}… allowed {bundle.host_ip}/32): the previous config "
            "is still in effect. Bring it down by hand and re-run join")


def _installed_linux_links() -> set[str]:
    """Link interfaces this Linux node already has a worker-link installed for, from disk:
    the firewall boot unit (``RequiredBy=wg-quick@<iface>.service``) and every joined
    keygen record (one with a ``host_ip``) whose interface config still exists."""
    found: set[str] = set()
    try:
        unit = FW_UNIT.read_text()
    except FileNotFoundError:
        unit = ""
    except OSError as exc:
        raise RuntimeError(f"cannot read {FW_UNIT}: {exc.strerror}") from None
    found.update(re.findall(r"^RequiredBy=wg-quick@(\S+)\.service$", unit, flags=re.M))
    for rec in sorted(STATE_DIR.glob("*.json")) if STATE_DIR.is_dir() else []:
        try:
            st = json.loads(rec.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(st, dict) and st.get("host_ip") and isinstance(st.get("iface"), str):
            if _paths(st["iface"])["conf"].exists():
                found.add(st["iface"])
    return found


def _refuse_second_linux_link(iface: str) -> None:
    """ONE worker-link per Linux node. Its nft table, ruleset file and firewall units are
    node-global, so joining a second interface would atomically replace the first link's
    firewall with one that matches only the new interface -- leaving the first tunnel up
    unfirewalled -- and rewrite the boot unit the first link Requires."""
    other = sorted(_installed_linux_links() - {iface})
    if other:
        raise RuntimeError(
            f"this node already has a worker-link on {', '.join(other)}; a Linux node runs one "
            f"link (its firewall is node-wide). Run `blastbox worker-link leave --iface "
            f"{other[0]}` first, or re-join on {other[0]}.")


def _apply_linux(bundle: JoinBundle, p: dict[str, Path], wg: str) -> list[str]:
    notes: list[str] = []
    _refuse_second_linux_link(bundle.iface)     # (also in join's preflight; cheap, and safe)
    nft = _need("nft", "nftables")
    _need("wg-quick", "wireguard-tools")
    # FIREWALL FIRST, read back, before the link exists. Loaded from a temp file and moved into
    # place only once the kernel took it, so the boot unit never inherits a refused ruleset.
    tmp = FW_FILE.with_name(FW_FILE.name + ".new")
    _write_public(tmp, worker_firewall_nft(iface=bundle.iface, worker_ip=bundle.worker_ip,
                                           host_ip=bundle.host_ip,
                                           agent_port=bundle.agent_port))
    proc = _run([nft, "-f", str(tmp)])
    if proc.returncode != 0:
        tmp.unlink(missing_ok=True)
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise RuntimeError(f"nft refused the worker ruleset: {tail[0]}")
    os.replace(tmp, FW_FILE)
    expected = worker_firewall_nft(iface=bundle.iface, worker_ip=bundle.worker_ip,
                                   host_ip=bundle.host_ip, agent_port=bundle.agent_port)
    listing = _run([nft, "list", "table", "inet", NFT_TABLE])
    missing = firewall_in_force(listing.stdout or "", expected) if (
        listing.returncode == 0) else ["the table itself"]
    if missing:
        raise RuntimeError("loaded the worker ruleset but it is not in force: missing "
                           + ", ".join(missing))
    notes.append(f"firewall: in force (table inet {NFT_TABLE})")
    # Persisting it is part of the guarantee (see the host's install_firewall): the boot unit
    # the link Requires, and a re-assert timer for a ruleset flushed under a live link. Any
    # failure is fatal BEFORE the interface comes up.
    desc = "blastbox worker-link worker firewall"
    service, timer = reassert_units(nft_bin=nft, nft_file=str(FW_FILE), iface=bundle.iface,
                                    base=_FW_BASE, description=desc)
    for path, text in ((FW_UNIT, firewall_unit(nft_bin=nft, nft_file=str(FW_FILE),
                                               table=NFT_TABLE, iface=bundle.iface,
                                               description=desc)),
                       (_reassert_paths()[0], service), (_reassert_paths()[1], timer)):
        _write_public(path, text)
    _run(["systemctl", "daemon-reload"])
    for argv in (["systemctl", "enable", FW_UNIT_NAME],
                 ["systemctl", "enable", "--now", REASSERT_TIMER_NAME]):
        if not _ok(argv) or not _ok(["systemctl", "is-enabled", argv[-1]]):
            raise RuntimeError(f"could not enable {argv[-1]}; refusing to bring the link up "
                               "without its firewall persisted")
    notes.append(f"firewall units enabled: {FW_UNIT_NAME}, {REASSERT_TIMER_NAME}")
    unit = f"wg-quick@{bundle.iface}"
    if _ok(["systemctl", "is-active", unit]):
        ok = _ok(["systemctl", "restart", unit])     # the config may have changed
    else:
        ok = _ok(["systemctl", "enable", "--now", unit])
    if not ok:
        # A FAILED start/restart proves nothing about which config is live: on a re-join the
        # old interface can still be up holding the PREVIOUS host key / endpoint / address, and
        # "the interface exists" would then pass for success. Take it down (it must really go)
        # and bring it up once from the file just written.
        _run(["systemctl", "stop", unit])
        _run(["wg-quick", "down", bundle.iface])
        if _ok(["ip", "link", "show", bundle.iface]):
            raise RuntimeError(
                f"{unit} failed to (re)start and {bundle.iface} is still up with what may be "
                f"the previous config; bring it down by hand (`wg-quick down {bundle.iface}`) "
                "and re-run join")
        proc = _run(["wg-quick", "up", bundle.iface])
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
            raise RuntimeError(f"could not bring up {bundle.iface}: {tail[0]}")
    if not _ok(["ip", "link", "show", bundle.iface]):
        raise RuntimeError(f"{bundle.iface} is not up after starting {unit}")
    _verify_live_peer(wg, bundle)
    notes.append(f"{bundle.iface} up ({unit})")
    notes.append(_wait_handshake(wg, bundle.iface))
    return notes


def _apply_darwin(bundle: JoinBundle, p: dict[str, Path], wg: str, *,
                  conf_changed: bool = True) -> list[str]:
    notes: list[str] = []
    wg_quick = _need("wg-quick", "wireguard-tools (brew install wireguard-tools)")
    if conf_changed and _real_iface_darwin(bundle.iface) is not None:
        # The watchdog deliberately never touches a tunnel that is UP, so a re-join with a new
        # host key / endpoint / address would otherwise leave the old config live indefinitely.
        # Down it here; the watchdog run below brings it up behind closed rules, as at boot.
        _run([wg_quick, "down", bundle.iface])
        # VERIFIED, not assumed: the watchdog leaves any live utun alone, so a down that failed
        # (or did nothing) would leave the PREVIOUS host key / endpoint / address running and
        # the handshake check below would happily observe the old peer.
        stale = _real_iface_darwin(bundle.iface)
        if stale is not None and _ok([wg, "show", stale]):
            raise RuntimeError(
                f"`wg-quick down {bundle.iface}` did not stop {stale}, which still runs the "
                f"previous config; stop it by hand (`sudo wg-quick down {bundle.iface}`) and "
                "re-run join")
        notes.append(f"{bundle.iface} taken down to apply the changed config")
    label = label_for(bundle.iface)
    script = watchdog_script(iface=bundle.iface, worker_ip=bundle.worker_ip,
                             host_ip=bundle.host_ip, agent_port=bundle.agent_port,
                             wg=wg, wg_quick=wg_quick)
    # The script runs as ROOT every 30 s: nothing on its path may be writable by anyone else,
    # or that someone could swap it. Our own directory is made root-owned 0755 (it may
    # pre-exist, created by a user tool), and every ancestor is checked.
    SUPPORT_DIR.mkdir(parents=True, exist_ok=True)
    if SUPPORT_DIR.is_symlink():
        raise RuntimeError(f"{SUPPORT_DIR} is a symlink; refusing to put a root script there")
    _chown(SUPPORT_DIR, 0, 0)
    os.chmod(SUPPORT_DIR, 0o755)
    _write_public(p["script"], script, 0o755)
    _chown(p["script"], 0, 0)
    plist = launchd_plist(label=label, script=str(p["script"]))
    changed = not (p["plist"].exists() and p["plist"].read_bytes() == plist)
    _write_public(p["plist"], plist, 0o644)
    _chown(p["plist"], 0, 0)
    for path in (p["script"], p["plist"]):
        _refuse_untrusted_path(path)
    loaded = _ok(["launchctl", "print", f"system/{label}"])
    if loaded and changed:
        _run(["launchctl", "bootout", f"system/{label}"])
        loaded = False
    if not loaded:
        proc = _run(["launchctl", "bootstrap", "system", str(p["plist"])])
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
            raise RuntimeError(f"launchctl could not load {label}: {tail[0]}")
    # Run it now (RunAtLoad already did on a fresh bootstrap; -k on a reload is harmless:
    # the watchdog only re-ups a tunnel that is down).
    _run(["launchctl", "kickstart", f"system/{label}"])
    notes.append(f"LaunchDaemon {label} loaded (watchdog every {WATCHDOG_INTERVAL_S}s)")
    deadline = time.monotonic() + HANDSHAKE_WAIT_S
    while True:
        real = _real_iface_darwin(bundle.iface)
        if real is not None or time.monotonic() >= deadline:
            break
        _sleep(1.0)
    if real is None:
        raise RuntimeError(f"the watchdog did not bring {bundle.iface} up; see {LOG_FILE}")
    _verify_live_peer(wg, bundle, real)
    notes.append(f"{bundle.iface} up as {real}")
    notes.append(_wait_handshake(wg, real))
    return notes


def _real_iface_darwin(iface: str) -> str | None:
    try:
        real = (WG_RUN_DIR / f"{iface}.name").read_text().strip()
    except OSError:
        return None
    return real if re.fullmatch(r"utun[0-9]{1,3}", real) else None


def join(bundle_text: str, *, agent_user: str | None = None) -> list[str]:
    """Install the bundle the host's ``add`` printed and bring the link up. Idempotent.

    The bundle is checked against THIS machine before anything is written: it must be for
    the address ``keygen`` made the CSR for, and its certificate must verify against its CA,
    carry exactly that address, and be for the TLS key on this disk. The firewall is in force
    before the interface exists.
    """
    _require_root("join")
    plat = _supported_platform()
    bundle = JoinBundle.from_json(bundle_text)
    st = _load_state(bundle.iface)
    if st["worker_ip"] != bundle.worker_ip:
        raise RuntimeError(
            f"the bundle is for {bundle.worker_ip}, but keygen made this worker's CSR for "
            f"{st['worker_ip']}; re-run keygen with --ip {bundle.worker_ip} and `add` again")
    wg = _need("wg", "wireguard-tools")
    openssl = _need("openssl", "openssl")
    p = _paths(bundle.iface)
    if not p["wg_key"].exists() or not p["tls_key"].exists():
        raise RuntimeError("this worker's keys are missing; run keygen first")
    # Every check that can refuse runs before anything is written.
    if plat == "linux":
        _refuse_second_linux_link(bundle.iface)
    pre = linux_preflight(bundle) if plat == "linux" else darwin_preflight(bundle)
    if _wg_pubkey(wg, p["wg_key"].read_text()) == bundle.host_public_key:
        raise RuntimeError("the bundle's host key is THIS worker's own key")
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as td:
        cert_t, ca_t = Path(td) / "c.crt", Path(td) / "ca.crt"
        cert_t.write_text(bundle.cert_pem)
        ca_t.write_text(bundle.ca_pem)
        verify_cert(openssl, cert=cert_t, ca=ca_t, key=p["tls_key"], ip=bundle.worker_ip)
        os.replace(cert_t, p["cert"])
        os.replace(ca_t, p["ca"])
    for f in (p["cert"], p["ca"]):
        os.chmod(f, 0o644)
    notes = [*pre, f"certificate for {bundle.worker_ip} verified and installed"]
    if agent_user:
        import pwd

        try:
            pw = pwd.getpwnam(agent_user)
        except KeyError:
            raise RuntimeError(f"no such user {agent_user!r}") from None
        os.chown(p["tls_key"], pw.pw_uid, pw.pw_gid)
        os.chmod(p["tls_key"], 0o600)
        notes.append(f"TLS key owned by {agent_user} (0600) so the agent can read it")
    else:
        notes.append(f"NOTE: {p['tls_key']} is root-only; if the agent does not run as root, "
                     "re-run join with --agent-user <its user>")
    conf = worker_wg_config(private_key=p["wg_key"].read_text(), worker_ip=bundle.worker_ip,
                            host_ip=bundle.host_ip, host_public_key=bundle.host_public_key,
                            endpoint=bundle.endpoint)
    try:
        conf_changed = p["conf"].read_text() != conf
    except OSError:
        conf_changed = True
    _write_private(p["conf"], conf)
    notes.append(f"{p['conf']} written (0600)")
    if plat == "linux":
        notes += _apply_linux(bundle, p, wg)
    else:
        notes += _apply_darwin(bundle, p, wg, conf_changed=conf_changed)
    st.update(host_ip=bundle.host_ip, agent_port=bundle.agent_port, name=bundle.name)
    _write_public(p["state"], json.dumps(st) + "\n")
    notes.append("(re)start the agent with the environment below -- it loads its certificate "
                 "once, so after a renewal it must be RESTARTED to serve the new one:")
    notes += ["  " + ln for ln in agent_env_lines(
        worker_ip=bundle.worker_ip, host_ip=bundle.host_ip, agent_port=bundle.agent_port,
        cert=p["cert"], key=p["tls_key"], ca=p["ca"])]
    return notes


# --------------------------------------------------------------------------------------
# status / leave
# --------------------------------------------------------------------------------------

def status(iface: str = DEFAULT_IFACE) -> tuple[bool, list[str]]:
    """What is IN FORCE on this worker. ``ok`` only when the tunnel is up with a fresh
    handshake AND the firewall was read back complete. Unprivileged reads that cannot see
    the answer report UNVERIFIED, never OK."""
    from blastbox.host.exit_attest import parse_wg_dump

    plat = _supported_platform()
    iface = _link_iface(iface)
    rows: list[str] = []
    try:
        st = _load_state(iface)
        ip = st["worker_ip"]
    except RuntimeError as exc:
        return False, [str(exc)]
    host_ip, agent_port = st.get("host_ip"), st.get("agent_port")
    if not host_ip or not agent_port:
        return False, [f"{iface}: keys made for {ip}, but this worker has not joined yet"]
    wg = _which("wg") or "wg"
    if plat == "darwin":
        real = _real_iface_darwin(iface)
        rows.append(f"interface {iface}: " + (f"up as {real}" if real else "DOWN (no utun recorded)"))
        info = _run([PFCTL, "-s", "info"])
        main = _run([PFCTL, "-s", "rules"])
        anchor = _run([PFCTL, "-a", pf_anchor_for(iface), "-s", "rules"])
        if info.returncode != 0:
            fw: bool | None = None
            rows.append("firewall (pf): UNVERIFIED — cannot read pf (needs root)")
        else:
            missing = pf_in_force(info=info.stdout, main_rules=main.stdout,
                                  anchor_rules=anchor.stdout, real_iface=real, worker_ip=ip,
                                  host_ip=str(host_ip), agent_port=int(agent_port))
            fw = not missing
            rows.append("firewall (pf): " + ("in force" if fw else
                                             "NOT IN FORCE — missing " + "; ".join(missing)))
        loaded = _ok(["launchctl", "print", f"system/{label_for(iface)}"])
        rows.append(f"LaunchDaemon {label_for(iface)}: {'loaded' if loaded else 'NOT loaded'}")
        dump_if = real
    else:
        up = _ok(["ip", "link", "show", iface])
        rows.append(f"interface {iface}: {'up' if up else 'DOWN'}")
        listing = _run(["nft", "list", "table", "inet", NFT_TABLE])
        err = listing.stderr or ""
        if listing.returncode != 0 and ("Operation not permitted" in err
                                        or "Permission denied" in err or listing.returncode == 127):
            fw = None
            rows.append("firewall: UNVERIFIED — cannot read nftables (needs root)")
        else:
            expected = worker_firewall_nft(iface=iface, worker_ip=ip, host_ip=host_ip,
                                           agent_port=agent_port)
            missing = (firewall_in_force(listing.stdout, expected)
                       if listing.returncode == 0 else ["the table itself"])
            fw = not missing
            rows.append("firewall: " + ("in force" if fw else
                                        "NOT IN FORCE — missing " + ", ".join(missing)))
        for unit in (f"wg-quick@{iface}", FW_UNIT_NAME, REASSERT_TIMER_NAME):
            rows.append(f"{unit}: {'enabled' if _ok(['systemctl', 'is-enabled', unit]) else 'NOT enabled'}")
        dump_if = iface if up else None
    fresh = False
    if dump_if:
        proc = _run([wg, "show", dump_if, "dump"])
        if proc.returncode != 0:
            rows.append("handshake: UNVERIFIED — cannot read `wg show` (needs root)")
        else:
            peers = parse_wg_dump(proc.stdout or "")
            for peer in peers:
                if not peer.ever_connected:
                    rows.append("handshake with the host: NEVER")
                else:
                    age = peer.observed_at - peer.latest_handshake
                    fresh = fresh or peer.connected(now=peer.observed_at)
                    rows.append(f"handshake with the host: {age:.0f}s ago"
                                + ("" if peer.connected(now=peer.observed_at) else " (STALE)"))
            if not peers:
                rows.append("handshake: no peer configured on the live interface")
    rows.append(f"overlay address: {ip}")
    return bool(dump_if) and fresh and fw is True, rows


def leave(iface: str = DEFAULT_IFACE, *, purge: bool = False) -> list[str]:
    """Take the link down and remove what ``join`` installed. The tunnel goes down BEFORE the
    firewall is removed. Keys and TLS material stay unless ``purge``."""
    _require_root("leave")
    plat = _supported_platform()
    iface = _link_iface(iface)
    p = _paths(iface)
    notes: list[str] = []
    if plat == "darwin":
        label = label_for(iface)
        _run(["launchctl", "bootout", f"system/{label}"])
        wg_quick = _which("wg-quick")
        if wg_quick:
            _run([wg_quick, "down", iface])
        if _real_iface_darwin(iface) is not None:
            notes.append(f"WARNING: {iface} still appears up; pf rules left in place")
            return notes
        notes.append(f"{iface} down; LaunchDaemon {label} unloaded")
        _run([PFCTL, "-a", pf_anchor_for(iface), "-F", "all"])
        left = _run([PFCTL, "-a", pf_anchor_for(iface), "-s", "rules"])
        notes.append(f"pf anchor {pf_anchor_for(iface)} flushed (pf itself left as it was)"
                     if left.returncode == 0 and not left.stdout.strip() else
                     f"WARNING: could not verify pf anchor {pf_anchor_for(iface)} is empty")
        for f in (p["plist"], p["script"]):
            f.unlink(missing_ok=True)
    else:
        _run(["systemctl", "disable", "--now", f"wg-quick@{iface}"])
        _run(["wg-quick", "down", iface])
        if _ok(["ip", "link", "show", iface]):
            notes.append(f"WARNING: {iface} is STILL UP; firewall left in place")
            return notes
        notes.append(f"{iface} down; wg-quick@{iface} disabled")
        _run(["systemctl", "disable", "--now", REASSERT_TIMER_NAME])
        _run(["systemctl", "disable", "--now", FW_UNIT_NAME])
        _run(["nft", "delete", "table", "inet", NFT_TABLE])
        for f in (*_reassert_paths(), FW_UNIT, FW_FILE):
            f.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        still = _run(["nft", "list", "table", "inet", NFT_TABLE])
        gone = still.returncode != 0 and "No such file" in (still.stderr or "")
        notes.append(f"table inet {NFT_TABLE} and its unit removed (no other table touched)"
                     if gone else
                     f"WARNING: could not verify table inet {NFT_TABLE} was removed")
    p["conf"].unlink(missing_ok=True)
    if purge:
        for key in ("wg_key", "wg_pub", "tls_key", "csr", "cert", "ca", "state"):
            p[key].unlink(missing_ok=True)
        notes.append("keys, certificates and keygen state removed")
    else:
        notes.append(f"keys kept in {KEY_DIR} and {STATE_DIR} (--purge removes them)")
    return notes


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def _host_mod():
    try:
        from blastbox.host import worker_link_apply
    except ImportError as exc:      # pragma: no cover - depends on the install
        raise RuntimeError(f"this is a host command and needs blastbox[host] ({exc})") from None
    return worker_link_apply


#: Host actions that inspect or dismantle what is INSTALLED, and so must work from the
#: installed unit/config when the env file is missing (see worker_link_apply.load_config).
_RECOVERABLE_ACTIONS = frozenset({"status", "list", "remove", "teardown"})


def _host_cfg(args: argparse.Namespace, *, base_required: bool):
    from dataclasses import replace

    from blastbox.host.worker_link import WorkerLinkConfig

    wla = _host_mod()
    base = wla.load_config(
        required=base_required,
        recover=getattr(args, "worker_link_action", None) in _RECOVERABLE_ACTIONS,
    ) or WorkerLinkConfig()
    over: dict[str, object] = {}
    for attr, field_name in (("iface", "wg_iface"), ("overlay_net", "overlay_net"),
                             ("host_ip", "host_ip"), ("port", "wg_port"),
                             ("agent_port", "agent_port"), ("endpoint", "endpoint")):
        v = getattr(args, attr, None)
        if v not in (None, ""):
            over[field_name] = v
    if getattr(args, "no_dispatcher_source", False):
        if getattr(args, "dispatcher_source", None):
            raise ValueError("--no-dispatcher-source and --dispatcher-source contradict")
        over["dispatcher_sources"] = ()
    elif getattr(args, "dispatcher_source", None):
        over["dispatcher_sources"] = tuple(args.dispatcher_source)
    if "overlay_net" in over and "host_ip" not in over:
        over["host_ip"] = ""          # re-derive from the new overlay
    return replace(base, **over) if over else base  # type: ignore[arg-type]


def _role(args: argparse.Namespace) -> str:
    if args.role:
        return str(args.role)
    try:
        from blastbox.host import worker_link_apply as wla
        # The env file OR the host's firewall boot unit: with the file deleted, the installed
        # unit still says this is a host (the worker's unit has a different name).
        if wla.ENV_FILE.exists() or wla.FW_UNIT.exists():
            return "host"
    except ImportError:             # pragma: no cover - lean worker install
        pass
    return "worker"


def _cmd(args: argparse.Namespace) -> int:
    try:
        return _dispatch(args)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace) -> int:
    action = args.worker_link_action
    if action == "keygen":
        pub, csr, notes = keygen(args.iface or DEFAULT_IFACE, args.ip, rotate=args.rotate)
        for n in notes:
            print(f"  {n}", file=sys.stderr)
        csr_path = _paths(args.iface or DEFAULT_IFACE)["csr"]
        print(f"WireGuard public key: {pub}")
        print(csr, end="" if csr.endswith("\n") else "\n")
        print(f"\nCarry the public key and the CSR ({csr_path}) to the host, then run:\n"
              f"  blastbox worker-link add <name> --public-key {pub} --csr <file> --ip {args.ip}",
              file=sys.stderr)
        return 0
    if action == "join":
        text = sys.stdin.read() if args.bundle == "-" else Path(args.bundle).read_text()
        for n in join(text, agent_user=args.agent_user):
            print(f"  {n}")
        return 0
    if action == "leave":
        for n in leave(args.iface or DEFAULT_IFACE, purge=args.purge):
            print(f"  {n}")
        return 0
    if action == "status" and _role(args) == "worker":
        ok, rows = status(args.iface or DEFAULT_IFACE)
        for r in rows:
            print(f"  {r}")
        return 0 if ok else 1

    # Host side.
    wla = _host_mod()
    if action == "init":
        cfg = _host_cfg(args, base_required=False)
        pub, notes = wla.init_host(cfg)
        for n in notes:
            print(f"  {n}")
        print(f"  host public key: {pub}")
        return 0
    cfg = _host_cfg(args, base_required=True)
    if action == "add":
        csr_pem = Path(args.csr).read_bytes()
        bundle, changed = wla.add_worker(cfg, args.name, args.public_key, csr_pem, ip=args.ip,
                                         days=args.days, pki_dir=Path(args.pki_dir))
        out = bundle.to_json()
        if args.out:
            _write_public(Path(args.out), out)
        else:
            sys.stdout.write(out)
        msg = [f"worker {bundle.name} {'registered' if changed else 'already current'} at "
               f"{bundle.worker_ip}/32; cert ({args.days}d) in "
               f"{Path(args.pki_dir) / wla.CERT_SUBDIR / (bundle.name + '.crt')}",
               "join bundle: " + (args.out if args.out else "printed above (stdout)")
               + " — public material only; carry it to the worker and run "
               "`sudo blastbox worker-link join --bundle <file>`",
               "dispatcher (add this worker to the static pool):",
               f"  BLASTBOX_STATIC_WORKERS=https://{bundle.worker_ip}:{bundle.agent_port}",
               f"  BLASTBOX_DISPATCH_TLS_CA={Path(args.pki_dir) / 'ca.crt'}   "
               "(+ _TLS_CERT/_TLS_KEY = the dispatcher client cert from `pki init`)"]
        for m in msg:
            print(f"  {m}", file=sys.stderr)
        return 0
    if action == "remove":
        gone = wla.remove_worker(cfg, args.name, pki_dir=Path(args.pki_dir))
        print(f"  worker {args.name} " + ("removed from the link" if gone else "was not registered"))
        return 0 if gone else 1
    if action == "list":
        from blastbox.host.worker_link import next_free_ip

        rows = wla.list_workers(cfg)
        if args.json:
            print(json.dumps(rows, indent=1))
        else:
            for r in rows:
                print(f"  {r['name']:<24} {r['ip']:<15} {r['public_key']}  "
                      f"cert expires {r['cert_expires'][:10] or '?'}")
            if not rows:
                print("  no workers registered")
        try:
            print(f"  next free address: {next_free_ip(cfg, [r['ip'] for r in rows])}",
                  file=sys.stderr)
        except RuntimeError as exc:
            print(f"  {exc}", file=sys.stderr)
        return 0
    if action == "status":
        ok, rows = wla.status(cfg)
        for r in rows:
            print(f"  {r}")
        return 0 if ok else 1
    if action == "teardown":
        for n in wla.teardown(cfg):
            print(f"  {n}")
        return 0
    raise SystemExit(f"unknown worker-link action {action!r}")


def add_parser(sub: argparse._SubParsersAction) -> None:
    pw = sub.add_parser(
        "worker-link",
        help="WireGuard control link so a dispatcher can reach workers behind NAT")
    pws = pw.add_subparsers(dest="worker_link_action", required=True)

    def iface(p: argparse.ArgumentParser) -> None:
        p.add_argument("--iface", default=None, help=f"link interface (default {DEFAULT_IFACE})")

    pki_default = os.environ.get("BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki")

    # host
    pi = pws.add_parser("init", help="HOST: create the link endpoint + firewall (idempotent)")
    iface(pi)
    pi.add_argument("--overlay-net", default=None, help="default 10.78.0.0/24")
    pi.add_argument("--host-ip", default=None, help="host overlay address (default: first)")
    pi.add_argument("--port", type=int, default=None, help="UDP listen port (default 51822)")
    pi.add_argument("--agent-port", type=int, default=None, help="worker agent port (8765)")
    pi.add_argument("--endpoint", default=None,
                    help="public host[:port] workers dial (required before `add`)")
    pi.add_argument("--dispatcher-source", action="append", default=None, metavar="CIDR",
                    help="docker network of a CONTAINERISED dispatcher (repeatable); its "
                         "connections are allowed into the link and MASQUERADEd")
    pi.add_argument("--no-dispatcher-source", action="store_true",
                    help="clear every recorded --dispatcher-source (they are otherwise kept)")
    pi.set_defaults(func=_cmd)

    pa = pws.add_parser("add", help="HOST: register a worker and sign its CSR -> join bundle")
    pa.add_argument("name")
    pa.add_argument("--public-key", required=True, help="the worker's WireGuard PUBLIC key")
    pa.add_argument("--csr", required=True, help="the worker's CSR (from `keygen`)")
    pa.add_argument("--ip", default=None, help="overlay address (default: next free; the "
                    "CSR's subjectAltName must equal it)")
    pa.add_argument("--days", type=int, default=30, help="certificate lifetime (default 30)")
    pa.add_argument("--pki-dir", default=pki_default)
    pa.add_argument("--out", default=None, help="write the bundle here instead of stdout")
    pa.set_defaults(func=_cmd)

    pr = pws.add_parser("remove", help="HOST: drop a worker from the link")
    pr.add_argument("name")
    pr.add_argument("--pki-dir", default=pki_default)
    pr.set_defaults(func=_cmd)

    pl = pws.add_parser("list", help="HOST: registered workers (+ the next free address)")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=_cmd)

    pt = pws.add_parser("teardown", help="HOST: remove the link endpoint + firewall")
    pt.set_defaults(func=_cmd)

    # both
    ps = pws.add_parser("status", help="what is IN FORCE (host or worker; exit 1 unless all of it)")
    iface(ps)
    ps.add_argument("--role", choices=("host", "worker"), default=None,
                    help="default: host if /etc/blastbox/worker-link.env exists, else worker")
    ps.set_defaults(func=_cmd)

    # worker
    pk = pws.add_parser("keygen", help="WORKER: make keys + a CSR (prints public key + CSR only)")
    iface(pk)
    pk.add_argument("--ip", required=True, help="the overlay address the host will allocate "
                    "(`worker-link list` on the host shows the next free one)")
    pk.add_argument("--rotate", action="store_true", help="generate NEW keys")
    pk.set_defaults(func=_cmd)

    pj = pws.add_parser("join", help="WORKER: install a join bundle and bring the link up")
    pj.add_argument("--bundle", required=True, help="bundle file from `add` (- for stdin)")
    pj.add_argument("--agent-user", default=None,
                    help="user the http_agent runs as (gets read access to the TLS key)")
    pj.set_defaults(func=_cmd)

    pv = pws.add_parser("leave", help="WORKER: take the link down and remove it")
    iface(pv)
    pv.add_argument("--purge", action="store_true", help="also delete keys and certificates")
    pv.set_defaults(func=_cmd)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blastbox")
    add_parser(p.add_subparsers(dest="command", required=True))
    args = p.parse_args(["worker-link", *(argv if argv is not None else sys.argv[1:])])
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
