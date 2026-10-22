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
    refuse_endpoint_in_overlay,
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
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename into it survives a crash (best effort)."""
    try:
        dfd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)


def _replace_durably(src: Path, dst: Path) -> None:
    """fsync ``src``, rename it over ``dst``, fsync the directory: the rename is atomic, and
    neither the file's bytes nor the rename are lost to a crash."""
    fd = os.open(src, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(src, dst)
    _fsync_dir(dst.parent)


def _lock_path() -> Path:
    """The worker's node-wide lock (resolved at CALL time, so it follows STATE_DIR)."""
    return STATE_DIR.parent / ".worker-link-peer.lock"


def _node_locked(fn):  # type: ignore[no-untyped-def]
    """Hold ONE node-wide exclusive lock across keygen / join / leave.

    Each of them reads state, checks it, then rewrites keys, configs, the firewall and the
    service units: two overlapping runs (a re-join racing a leave, two joins) could interleave
    those steps and leave a link up under another run's firewall, or a firewall removed under a
    link the other run just brought up. ``flock``: released if the process dies."""
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
            os.close(fd)

    return wrapper


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
        # ...and NOTHING else may reach a DNAT target that was addressed to our overlay address:
        # a job bridge or physical interface sending to <w>:<published port> is forwarded (not
        # input), so the input chain's off-link drop never sees it. Matched on the ORIGINAL
        # destination and the ORIGINAL direction only, so the agent's replies still flow.
        f'\t\tiifname != "{i}" ct direction original ct original ip daddr {w} drop',
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
                    run_dir: str = str(WG_RUN_DIR), state_dir: str = "/var/run",
                    public_key: str | None = None) -> str:
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
    if public_key is not None and not re.fullmatch(r"[A-Za-z0-9+/]{42,43}=", public_key):
        raise ValueError("public_key is not a WireGuard public key")
    pub = public_key or ""
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
RUNDIR={_sh_quote(run_dir.rstrip('/'))}
ANCHOR={_sh_quote(anchor)}
STAMP={_sh_quote(stamp)}
DIGEST={_sh_quote(digest)}
PUB={_sh_quote(pub)}
REAL=''

log() {{ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) worker-link[$IFACE]: $*"; }}

# The utun(s) running THIS link's key (wg-quick's name file is only a note; see join/leave).
our_utuns() {{
    [ -n "$PUB" ] || return 0
    "$WG" show all public-key 2>/dev/null | awk -v k="$PUB" '$2 == k {{ print $1 }}'
}}

# Is the utun named by wg-quick's name file OURS? It must be live AND (with a known key) run
# THIS link's key: macOS reuses utun numbers, so a stale name file can name another VPN's tunnel.
ours_live() {{
    real_iface || return 1
    "$WG" show "$REAL" >/dev/null 2>&1 || return 1
    [ -z "$PUB" ] && return 0
    [ "$("$WG" show "$REAL" public-key 2>/dev/null)" = "$PUB" ]
}}

# A name file that does not name OUR tunnel must not steer `wg-quick down $IFACE` onto someone
# else's: drop it first (wg-quick recreates it on `up`).
drop_foreign_name() {{
    [ -n "$PUB" ] || return 0
    # kept ONLY when its utun's key is positively ours; unreadable (not WireGuard, `wg show`
    # failed) counts as foreign -- wg-quick down acts on whatever the note names
    if real_iface && [ "$("$WG" show "$REAL" public-key 2>/dev/null)" != "$PUB" ]; then
        log "$NAMEFILE names $REAL, which is not verifiably this link's tunnel: ignoring it"
        rm -f "${{NAMEFILE:?}}"
    fi
    REAL=''
}}

# Take the link DOWN and verify it by key. A failed `wg-quick down` (no name file, a stale one)
# must not leave the tunnel up without enforcement: wireguard-go exits when its control socket
# is removed -- exactly how wg-quick stops it on macOS -- so that is done for every utun still
# running our key, and the result is checked. Still up: logged; the next run tries again.
force_down() {{
    drop_foreign_name
    "$WG_QUICK" down "$IFACE" >/dev/null 2>&1
    for U in $(our_utuns); do
        case "$U" in
            utun[0-9]|utun[0-9][0-9]|utun[0-9][0-9][0-9]) rm -f "${{RUNDIR:?}}/$U.sock" ;;
        esac
    done
    i=0
    while [ -n "$(our_utuns)" ] && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
    rm -f "$STAMP"
    if [ -n "$(our_utuns)" ]; then
        log "$1; the link could NOT be taken down: $(our_utuns | tr '\n' ' ')still runs its key"
    else
        log "$1; link taken DOWN"
    fi
}}

# `pass ... quick` rules in the MAIN ruleset, before our anchor, that can match the link's
# utun ($1, or empty before the link is up): they make every rule in our anchor moot.
# Mirrors blastbox.worker.link.pf_main_bypass.
main_bypass() {{
    "$PFCTL" -s rules 2>/dev/null | awk -v real="$1" '
        /^anchor "com\\.apple\\/\\*" all[ \\t]*$/ {{ exit }}
        $1 == "pass" {{
            q = 0; on = ""
            for (i = 2; i <= NF; i++) {{
                if ($i == "quick") q = 1
                if ($i == "on" && on == "" && i < NF) on = $(i + 1)
            }}
            if (!q) next
            if (on == "" || on == "!" || on == "{{" || on == "utun" || (real != "" && on == real)) print
        }}'
}}

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
        force_down "pf could not be enabled"
        exit 1
    fi
fi
# ...and the main ruleset must still EVALUATE our anchor. A VPN client or kill-switch app that
# loads its own main ruleset drops `anchor "com.apple/*"`, and every rule below is then text.
# UNCONDITIONALLY: only the bare `anchor "com.apple/*" all` (how pfctl prints the stock
# /etc/pf.conf's invocation) reaches our child anchor for every packet. A parent narrowed by
# interface, direction, family, protocol, address or tag (`anchor "com.apple/*" on en0 all`)
# never evaluates it for the link's utun. Mirrors blastbox.worker.link.pf_parent_anchor_ok.
if ! "$PFCTL" -s rules 2>/dev/null | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' \
        | grep -qx 'anchor "com\\.apple/\\*" all'; then
    force_down 'the main pf ruleset does not evaluate anchor "com.apple/*" unconditionally'
    exit 1
fi
# ...and nothing BEFORE it may pass the link's traffic with `quick` (that would bypass it).
BYPASS=$(main_bypass "")
if [ -n "$BYPASS" ]; then
    force_down "the main pf ruleset passes traffic before our anchor: $BYPASS"
    exit 1
fi

# wg-quick's name file is only its NOTE of the utun it got. If it is missing or stale while a
# utun still runs THIS link's key, that tunnel is up: re-record it rather than `wg-quick up` a
# second tunnel with the same key next to it (found by key via `wg show all public-key`).
if [ -n "$PUB" ] && ! ours_live; then
    LIVE=$("$WG" show all public-key 2>/dev/null | awk -v k="$PUB" '$2 == k {{ print $1; exit }}')
    case "$LIVE" in
        utun[0-9]|utun[0-9][0-9]|utun[0-9][0-9][0-9])
            echo "$LIVE" > "$NAMEFILE"
            log "found the live tunnel $LIVE by its key; re-recorded $NAMEFILE" ;;
    esac
fi

if ours_live; then
    :   # up, and ours: leave the tunnel alone
else
    log "link down; bringing it up"
    if ! pf_closed; then
        log "pf refused the closed ruleset; NOT bringing the link up"
        exit 1
    fi
    rm -f "$STAMP"
    drop_foreign_name
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
        force_down "pf refused the link ruleset for $REAL"
        exit 1
    fi
    echo "$WANT" > "$STAMP"
    log "pf rules loaded for $REAL"
fi
# Now that the utun is known, a rule naming IT before our anchor counts too.
BYPASS=$(main_bypass "$REAL")
if [ -n "$BYPASS" ]; then
    force_down "the main pf ruleset passes $REAL traffic before our anchor: $BYPASS"
    exit 1
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


#: The parent invocation that evaluates our child anchor for EVERY packet: pfctl's
#: normalised form of the stock /etc/pf.conf line ``anchor "com.apple/*"``.
_PF_PARENT_ANCHOR = 'anchor "com.apple/*" all'


def pf_parent_anchor_ok(main_rules: str) -> bool:
    """Whether the main ruleset invokes ``com.apple/*`` UNCONDITIONALLY. A line merely
    CONTAINING the anchor is not enough: ``anchor "com.apple/*" on en0 all`` (or narrowed by
    direction, family, protocol, address or tag) never evaluates our child anchor for the
    link's utun, so its rules would be text. Only the bare form counts. Mirrored in the
    watchdog."""
    return any(" ".join(raw.split()) == _PF_PARENT_ANCHOR
               for raw in (main_rules or "").splitlines())


def pf_main_bypass(main_rules: str, real_iface: str | None) -> list[str]:
    """Rules in the MAIN pf ruleset that let the link's traffic bypass our anchor.

    pf evaluates the main ruleset top-down and a ``quick`` match is final, so a ``pass ...
    quick`` rule BEFORE ``anchor "com.apple/*"`` that can match the link's utun (a VPN or
    firewall manager inserting one) means our anchor -- however exactly in force -- is never
    reached for that traffic. Such a rule can match the link unless it names another
    interface: no ``on``, a negated or listed interface, the ``utun`` group, or the link's own
    utun all can. ``real_iface`` None (link not up yet): only the rules that would match
    WHICHEVER utun it gets are counted, so another VPN's ``pass quick on utun3`` does not keep
    the link down. Mirrored in the watchdog's ``main_bypass`` (awk).
    """
    out: list[str] = []
    for raw in (main_rules or "").splitlines():
        line = " ".join(raw.split())
        if line == _PF_PARENT_ANCHOR:
            break
        toks = line.split()
        if not toks or toks[0] != "pass" or "quick" not in toks:
            continue
        on = toks[toks.index("on") + 1] if "on" in toks[:-1] else ""
        if on in ("", "!", "{", "utun") or (real_iface is not None and on == real_iface):
            out.append(line)
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
    if not pf_parent_anchor_ok(main_rules):
        missing.append('the main pf ruleset does not evaluate anchor "com.apple/*" '
                       "unconditionally (only `anchor \"com.apple/*\" all` reaches the link's "
                       "anchor for all of its traffic)")
    for rule in pf_main_bypass(main_rules, real_iface):
        missing.append(f'the main ruleset passes the link\'s traffic before our anchor (`{rule}`)')
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


def _refuse_rotating_a_live_link(wg: str, iface: str) -> None:
    """``keygen --rotate`` replaces the private key the link is FOUND by (macOS: the live utun
    is identified by its public key; the running tunnel and the installed config keep the old
    one until a re-join). Rotating under a live or installed link would leave a tunnel nothing
    can identify any more: leave/re-join would then call it down while it still handshakes
    with the host. So the link must be down and uninstalled first."""
    plat = _supported_platform()
    p = _paths(iface)
    why: list[str] = []
    # Install records first: they are there whatever has happened to the key file, and with the
    # key gone the live tunnel can no longer be found by it.
    if _conf_is_ours(iface):
        why.append(f"{p['conf']} is installed")
    try:
        joined = bool(json.loads(p["state"].read_text()).get("host_ip"))
    except (OSError, ValueError, AttributeError):
        joined = False
    if joined:
        why.append(f"{iface} is joined")
    if plat == "darwin":
        if p["plist"].exists() or _ok(["launchctl", "print", f"system/{label_for(iface)}"]):
            why.append(f"LaunchDaemon {label_for(iface)} is installed")
        if _real_iface_darwin(iface) is not None:
            why.append(f"{WG_RUN_DIR / (iface + '.name')} records a live tunnel")
        if p["wg_key"].exists() and p["wg_key"].stat().st_size:
            live = _our_live_utuns(wg, iface)
            if live is None:
                why.append("its tunnel cannot be verified down")
            elif live:
                why.append(f"{', '.join(live)} runs its current key")
    else:
        if _ok(["ip", "link", "show", iface]):
            why.append(f"{iface} is up")
        if _ok(["systemctl", "is-enabled", f"wg-quick@{iface}"]):
            why.append(f"wg-quick@{iface} is enabled")
    if why:
        raise RuntimeError(
            f"refusing to generate a new {iface} key while the link is live or installed "
            f"({'; '.join(why)}): the running tunnel would no longer be identifiable. If a key "
            "file was lost, restore it; otherwise run `blastbox worker-link leave --iface "
            f"{iface}` first, then keygen (--rotate), `add` on the host, and join again.")


@_node_locked
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

    def _missing(path: Path) -> bool:
        return not path.exists() or path.stat().st_size == 0

    if rotate or _missing(p["wg_key"]) or _missing(p["tls_key"]):
        # EVERY key generation, explicit (--rotate) or implicit (a deleted or emptied key
        # file): a new key under a live or installed link leaves a tunnel nothing can identify,
        # or an installed certificate for a key that no longer exists.
        _refuse_rotating_a_live_link(wg, iface)
    if rotate or _missing(p["wg_key"]):
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
            _replace_durably(tmp, p["tls_key"])
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
    # MERGE into the existing record, never replace it: a keygen on a JOINED worker (a fresh
    # CSR for a renewal, the same keys) used to rewrite it with only iface/worker_ip, dropping
    # the join's host_ip/agent_port/name -- and status then reported the running link as not
    # joined and skipped every live check. The join fields describe the INSTALLED link (whose
    # address is joined_worker_ip), so they stay until a join or leave changes them.
    try:
        rec = json.loads(p["state"].read_text())
    except (OSError, ValueError):
        rec = None
    if not isinstance(rec, dict) or rec.get("iface") != iface:
        rec = {}
    if rec.get("host_ip") and "joined_worker_ip" not in rec:
        rec["joined_worker_ip"] = rec.get("worker_ip")      # a record written before this field
    rec.update(iface=iface, worker_ip=str(addr))
    _write_public(p["state"], json.dumps(rec) + "\n")
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
                           "sit", "vti", "vti6", "ip6tnl", "xfrm", "erspan", "ip6erspan",
                           # encapsulating overlays: they report an ETHERNET link type
                           "vxlan", "geneve", "bareudp", "gtp", "amt", "l2tp_eth", "batadv",
                           # OpenVPN's data-channel-offload drivers
                           "ovpn", "ovpn-dco"})
_TUNNEL_LINK_TYPES = frozenset({"none", "ipip", "gre", "sit", "tunnel6", "ip6gre", "ip6tnl",
                                "ppp"})


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
    linkinfo = info.get("linkinfo") or {}
    kind = str(linkinfo.get("info_kind") or "")
    if kind in _TUNNEL_KINDS:
        return f"a {kind} tunnel"
    data = linkinfo.get("info_data")
    if isinstance(data, dict) and any(k in data for k in ("remote", "remote6", "peer")):
        # any device whose kernel description names a REMOTE endpoint is an encapsulation,
        # whatever its kind is called -- a kind added after this list still reads as a tunnel
        return f"a {kind or 'tunnel'} device with a remote endpoint"
    link_type = str(info.get("link_type") or "")
    if link_type in _TUNNEL_LINK_TYPES:
        return f"a tunnel (link type {link_type})"
    return None


def _local_endpoint_error(ip: str, dev: str | None) -> str:
    return (f"the host endpoint {ip} is THIS machine (routed via {dev or 'loopback'}): "
            "WireGuard would dial itself, never the host, and the link could never handshake. "
            "The bundle's endpoint must be the host's public/underlay address.")


def _tunnel_route_error(ip: str, dev: str, kind: str) -> str:
    return (f"the route to the host endpoint {ip} goes via {dev} ({kind}): the link's handshake "
            "would ride that tunnel instead of the underlay, so the control link would break "
            "whenever it restarts or changes policy. Exclude the host's address from that VPN "
            f"(split-tunnel {ip}/32 to the local network, or add a host route for {ip} via your "
            "underlay gateway) and re-run join. Other VPNs may stay up; only the route to "
            f"{ip} must not use one.")


#: macOS interface families that are tunnels/VPNs, never an underlay (utun: WireGuard and most
#: VPN clients; ipsec; tun/tap: third-party drivers; gif: IP-in-IP; stf: 6to4; ppp: L2TP/PPTP).
_DARWIN_TUNNEL_NAME = re.compile(r"(utun|ipsec|tun|tap|gif|stf|ppp)[0-9]+")


def _darwin_tunnel_kind(dev: str) -> str | None:
    """What kind of tunnel ``dev`` is on macOS, or None for an ordinary underlay. Asked of the
    system (``ifconfig <dev>``: a POINTOPOINT interface is a tunnel or a dial-up link, never a
    LAN), as well as by name family. A device whose flags cannot be read is refused."""
    if _DARWIN_TUNNEL_NAME.fullmatch(dev):
        return "a VPN/tunnel interface"
    proc = _run(["ifconfig", dev])
    m = re.search(r"flags=[0-9a-fA-F]+<([^>]*)>", proc.stdout or "")
    if proc.returncode != 0 or not m:
        return f"a device whose type could not be read ({dev})"
    if "POINTOPOINT" in m.group(1).split(","):
        return "a point-to-point (tunnel/VPN) interface"
    return None


def _darwin_own_utuns(iface: str) -> set[str]:
    """The utun(s) this link itself is running on, so a re-join does not refuse its own
    overlay routes/addresses."""
    wg = _which("wg")
    own = {r for r in [_our_real_iface_darwin(wg, iface)] if r}
    if wg:
        own.update(_our_live_utuns(wg, iface) or [])
    return own


def _darwin_overlay_conflicts(bundle: JoinBundle) -> list[str]:
    """Where the link's two /32s are already routed or assigned on this Mac (outside the
    link itself). The watchdog's CLOSED pf rules block both addresses before the tunnel comes
    up; if they belong to a LAN or VPN, those rules cut it off -- and wg-quick's host route
    then conflicts, so the link never comes up and the watchdog keeps re-installing them."""
    own = _darwin_own_utuns(bundle.iface)
    out: list[str] = []
    for addr in (bundle.worker_ip, bundle.host_ip):
        proc = _run(["route", "-n", "get", addr])
        if proc.returncode == 0:
            dest = re.search(r"^\s*destination:\s*(\S+)", proc.stdout or "", re.M)
            dev = re.search(r"^\s*interface:\s*(\S+)", proc.stdout or "", re.M)
            if dest and dest.group(1) != "default" and (not dev or dev.group(1) not in own):
                out.append(f"{addr} is already routed here (to {dest.group(1)} via "
                           f"{dev.group(1) if dev else '?'})")
    proc = _run(["ifconfig", "-a"])
    current = ""
    for line in (proc.stdout or "").splitlines():
        head = re.match(r"^(\S+?):\s+flags=", line)
        if head:
            current = head.group(1)
            continue
        m = re.match(r"^\s+inet\s+(\S+)", line)
        if m and m.group(1) in (bundle.worker_ip, bundle.host_ip) and current not in own:
            out.append(f"{m.group(1)} is already assigned to {current}")
    return out


def _refuse_endpoint_resolving_into_overlay(bundle: JoinBundle, addrs: list[str]) -> None:
    try:
        refuse_endpoint_in_overlay(addrs, bundle.overlay_net,
                                   what=f"the host endpoint {bundle.endpoint} (resolves to "
                                        f"{', '.join(addrs)})")
    except ValueError as exc:
        raise RuntimeError(str(exc)) from None


def darwin_preflight(bundle: JoinBundle) -> list[str]:
    """macOS: the route to the host endpoint must not go through a tunnel, and the link's
    overlay /32s must not already be routed or assigned here.

    Other VPN utuns may exist and stay up (a corporate split-tunnel VPN is fine); what is
    refused is the endpoint's OWN route using one, as ``route -n get`` reports it for that
    address -- tunnel-ness read from the interface itself (:func:`_darwin_tunnel_kind`).
    """
    notes: list[str] = []
    clash = _darwin_overlay_conflicts(bundle)
    if clash:
        raise RuntimeError("the link's overlay addresses collide with this Mac's network: "
                           + "; ".join(clash) + ". Ask the host operator for a free overlay "
                           "(`worker-link init --overlay-net`) or remove the conflicting route.")
    host = bundle.endpoint.rsplit(":", 1)[0]
    resolved = _resolve(host)
    _refuse_endpoint_resolving_into_overlay(bundle, resolved)
    routable = 0
    for ip in resolved:
        proc = _run(["route", "-n", "get", *(["-inet6"] if ":" in ip else []), ip])
        m = re.search(r"^\s*interface:\s*(\S+)", proc.stdout or "", re.M)
        if proc.returncode != 0 or not m:
            notes.append(f"no underlay route to the endpoint address {ip} (unused)")
            continue
        routable += 1
        dev = m.group(1)
        if re.fullmatch(r"lo[0-9]*", dev) or ipaddress.ip_address(ip).is_loopback:
            raise RuntimeError(_local_endpoint_error(ip, dev))
        kind = _darwin_tunnel_kind(dev)
        if kind:
            raise RuntimeError(_tunnel_route_error(ip, dev, kind))
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
    resolved = _resolve(host)
    _refuse_endpoint_resolving_into_overlay(bundle, resolved)
    routable = 0
    for ip in resolved:
        fam = ["-6"] if ":" in ip else []
        proc = _run(["ip", *fam, "-j", "route", "get", ip])
        try:
            entry = (_json.loads(proc.stdout or "[]") or [{}])[0]
            dev, rtype = entry.get("dev"), entry.get("type")
        except (ValueError, AttributeError, IndexError):
            dev, rtype = None, None
        if proc.returncode != 0 or not dev:
            # An address family this node cannot route (an AAAA record on a v4-only node) is
            # not a refusal: WireGuard will use one it can. What must never happen is ANY
            # resolved address leaving through a tunnel.
            notes.append(f"no underlay route to the endpoint address {ip} (unused)")
            continue
        routable += 1
        if rtype == "local" or dev == "lo" or ipaddress.ip_address(ip).is_loopback:
            raise RuntimeError(_local_endpoint_error(ip, dev))
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


def _live_peer_matches(wg: str, bundle: JoinBundle, real_iface: str) -> bool:
    return not _live_mismatch(wg, bundle, real_iface)


def _live_mismatch(wg: str, bundle: JoinBundle, real_iface: str | None = None) -> list[str]:
    """How the LIVE interface differs from what this bundle configures, read from the kernel /
    wireguard-go -- never from the file: exactly the bundle's host as the one peer (key and
    AllowedIPs = the host /32), that peer's ENDPOINT (port, and an address the endpoint name
    resolves to) and keepalive, the interface's own key (this worker's) and its overlay address.
    A retry after a join that wrote the config but was interrupted before applying it sees an
    unchanged file over a tunnel still running the old endpoint/peer/key; only this catches it."""
    iface = real_iface or bundle.iface
    proc = _run([wg, "show", iface, "dump"])
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        return [f"its live config cannot be read ({tail[0]})"]
    lines = (proc.stdout or "").splitlines()
    out: list[str] = []
    peers = [ln.split("\t") for ln in lines[1:] if len(ln.split("\t")) >= 8]
    keys = [(f[0], tuple(sorted(x for x in f[3].split(",") if x))) for f in peers]
    if keys != [(bundle.host_public_key, (f"{bundle.host_ip}/32",))]:
        out.append(f"its peers are not exactly this bundle's host ({bundle.host_public_key[:10]}… "
                   f"allowed {bundle.host_ip}/32)")
    else:
        f = peers[0]
        live_ep, keepalive = f[2], f[7]
        want_host, _, want_port = bundle.endpoint.rpartition(":")
        live_host, _, live_port = live_ep.rpartition(":")
        if live_ep in ("", "(none)") or live_port != want_port:
            out.append(f"its endpoint is {live_ep or 'unset'}, not port {want_port} of "
                       f"{bundle.endpoint}")
        else:
            try:
                resolved = set(_resolve(want_host))
            except RuntimeError:
                resolved = set()
            if resolved and live_host.strip("[]") not in resolved:
                out.append(f"its endpoint {live_ep} is not {bundle.endpoint} "
                           f"({', '.join(sorted(resolved))})")
        if keepalive.strip() not in ("25",):
            out.append(f"its keepalive is {keepalive or 'off'}, not 25")
    own = (lines[0].split("\t") + ["", ""])[1] if lines else ""
    if own != bundle.worker_public_key:
        out.append(f"it runs another key ({own[:10] or '?'}…, not this worker's "
                   f"{bundle.worker_public_key[:10]}…)")
    if bundle.worker_ip not in _live_iface_addresses(iface):
        out.append(f"it does not carry {bundle.worker_ip}")
    return out


def _live_iface_addresses(iface: str) -> set[str]:
    """IPv4 addresses on ``iface`` (Linux ``ip -j addr``, macOS ``ifconfig``)."""
    if _supported_platform() == "darwin":
        proc = _run(["ifconfig", iface])
        return set(re.findall(r"^\s*inet\s+(\S+)", proc.stdout or "", re.M))
    proc = _run(["ip", "-j", "addr", "show", "dev", iface])
    try:
        info = json.loads(proc.stdout or "[]") if proc.returncode == 0 else []
    except ValueError:
        info = []
    return {str(a.get("local")) for dev in info if isinstance(dev, dict)
            for a in dev.get("addr_info", []) if a.get("family") == "inet"}


def _verify_live_peer(wg: str, bundle: JoinBundle, real_iface: str | None = None) -> None:
    """Raise unless the LIVE interface runs exactly what this bundle configures (see
    :func:`_live_mismatch`). A link that is up with some earlier config is not the link this
    join configured."""
    why = _live_mismatch(wg, bundle, real_iface)
    if why:
        raise RuntimeError(
            f"{real_iface or bundle.iface} is up but {'; '.join(why)}: the previous config is "
            "still in effect. Bring it down by hand and re-run join")


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


def _linux_fail_closed(iface: str, *, disable: bool = False) -> str:
    """Take a live Linux link DOWN (verified) because its firewall cannot be vouched for;
    returns the sentence to append to the error. A link that is already down is left so."""
    unit = f"wg-quick@{iface}"
    if disable:
        _run(["systemctl", "disable", unit])
    if not _ok(["ip", "link", "show", iface]):
        return ""
    _run(["systemctl", "stop", unit])
    _run(["wg-quick", "down", iface])
    if _ok(["ip", "link", "show", iface]):
        _run(["ip", "link", "delete", "dev", iface])
    if _ok(["ip", "link", "show", iface]):
        return (f". {iface} could NOT be taken down and may be running without its firewall: "
                f"`ip link delete dev {iface}` by hand NOW")
    return f". {iface} was taken DOWN rather than left running without it"


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
    _replace_durably(tmp, FW_FILE)
    expected = worker_firewall_nft(iface=bundle.iface, worker_ip=bundle.worker_ip,
                                   host_ip=bundle.host_ip, agent_port=bundle.agent_port)
    listing = _run([nft, "list", "table", "inet", NFT_TABLE])
    missing = firewall_in_force(listing.stdout or "", expected) if (
        listing.returncode == 0) else ["the table itself"]
    if missing:
        # On a RE-join the old link may be live: raising alone would leave it running with an
        # absent or incomplete firewall. Take it down, verified, first.
        raise RuntimeError("loaded the worker ruleset but it is not in force: missing "
                           + ", ".join(missing) + _linux_fail_closed(bundle.iface))
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
    # ENABLED *and* STARTED, both verified (see the host's install_firewall): an enabled but
    # inactive boot unit is not restarted by `PartOf=nftables.service`, so a nftables restart
    # would leave the live link unfiltered until the re-assert timer fired.
    for argv in (["systemctl", "enable", "--now", FW_UNIT_NAME],
                 ["systemctl", "enable", "--now", REASSERT_TIMER_NAME]):
        if (not _ok(argv) or not _ok(["systemctl", "is-enabled", argv[-1]])
                or not _ok(["systemctl", "is-active", argv[-1]])):
            # Not persisted: a live link (re-join) would come back at boot WITHOUT the unit it
            # Requires. Down it and disable its unit, so it neither runs nor boots unfirewalled.
            raise RuntimeError(f"could not enable and start {argv[-1]}; refusing to bring the "
                               "link up without its firewall persisted and active"
                               + _linux_fail_closed(bundle.iface, disable=True))
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
    # ENABLED, verified: the direct `wg-quick up` fallback brings the interface up without
    # enabling its unit, and the link would then silently not return after a reboot.
    if not _ok(["systemctl", "is-enabled", unit]):
        _run(["systemctl", "enable", unit])
        if not _ok(["systemctl", "is-enabled", unit]):
            raise RuntimeError(f"{bundle.iface} is up but {unit} could not be ENABLED, so it would "
                               "not come back after a reboot; enable it (`systemctl enable "
                               f"{unit}`) and re-run join")
    try:
        _verify_live_peer(wg, bundle)
    except RuntimeError as exc:
        raise RuntimeError(str(exc) + _linux_fail_closed(bundle.iface)) from None
    notes.append(f"{bundle.iface} up ({unit})")
    notes.append(_wait_handshake(wg, bundle.iface))
    return notes


def _apply_darwin(bundle: JoinBundle, p: dict[str, Path], wg: str, *,
                  conf_changed: bool = True) -> list[str]:
    notes: list[str] = []
    wg_quick = _need("wg-quick", "wireguard-tools (brew install wireguard-tools)")
    live_real = _our_real_iface_darwin(wg, bundle.iface)
    # Restart when the FILE changed -- or when the LIVE peer is not this bundle's: a previous
    # join may have written the new config and failed before applying it, and the retry then
    # sees an unchanged file over a tunnel still running the old host's peer.
    if live_real is not None and (conf_changed
                                  or not _live_peer_matches(wg, bundle, live_real)):
        # The watchdog deliberately never touches a tunnel that is UP, so a re-join with a new
        # host key / endpoint / address would otherwise leave the old config live indefinitely.
        # Down it here; the watchdog run below brings it up behind closed rules, as at boot.
        # VERIFIED, not assumed -- and by the KEY the tunnel runs, not wg-quick's name file:
        # the watchdog leaves any live utun alone, so a down that failed (or did nothing) would
        # leave the PREVIOUS host key / endpoint / address running and the handshake check
        # below would happily observe the old peer.
        stale = live_real
        why = _darwin_link_down(wg, wg_quick, bundle.iface)
        if why:
            raise RuntimeError(
                f"`wg-quick down {bundle.iface}` did not stop {stale or 'the old tunnel'} ({why}), "
                f"which still runs the previous config; stop it by hand (`sudo wg-quick down "
                f"{bundle.iface}`) and re-run join")
        notes.append(f"{bundle.iface} taken down to apply the changed config")
    label = label_for(bundle.iface)
    script = watchdog_script(iface=bundle.iface, worker_ip=bundle.worker_ip,
                             host_ip=bundle.host_ip, agent_port=bundle.agent_port,
                             wg=wg, wg_quick=wg_quick,
                             public_key=_wg_pubkey(wg, p["wg_key"].read_text()))
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
    kick = _run(["launchctl", "kickstart", f"system/{label}"])
    notes.append(f"LaunchDaemon {label} loaded (watchdog every {WATCHDOG_INTERVAL_S}s)")
    # Up AND enforced: the pf anchor is read back, not assumed. On a re-join of a live link
    # the name file and peer already pass, so a kickstart that failed (or a watchdog run that
    # could not restore a flushed anchor) would otherwise be reported as success with the link
    # live and unfirewalled until some later run.
    deadline = time.monotonic() + HANDSHAKE_WAIT_S
    missing: list[str] = ["the watchdog has not run"]
    while True:
        real = _our_real_iface_darwin(wg, bundle.iface)
        if real is not None:
            missing = _darwin_pf_missing(bundle, real)
        if (real is not None and not missing) or time.monotonic() >= deadline:
            break
        _sleep(1.0)
    if real is None:
        raise RuntimeError(f"the watchdog did not bring {bundle.iface} up; see {LOG_FILE}")
    if missing:
        _run(["launchctl", "bootout", f"system/{label}"])
        why = _darwin_link_down(wg, wg_quick, bundle.iface)
        raise RuntimeError(
            f"{bundle.iface} is up but its pf rules are NOT in force ({'; '.join(missing)})"
            + (f"; `launchctl kickstart` also failed (exit {kick.returncode})"
               if kick.returncode != 0 else "")
            + (". The watchdog was unloaded and the link taken DOWN" if not why else
               f". The watchdog was unloaded but the link could NOT be confirmed down ({why})")
            + f"; see {LOG_FILE}, fix pf and re-run join.")
    notes.append(f"pf: in force (anchor {pf_anchor_for(bundle.iface)})")
    try:
        _verify_live_peer(wg, bundle, real)
    except RuntimeError as exc:
        # Fail CLOSED: a tunnel up with someone else's peer is not left running for the next
        # retry to trip over. Unload the watchdog (it would re-up it) and verify it is down.
        _run(["launchctl", "bootout", f"system/{label}"])
        why = _darwin_link_down(wg, wg_quick, bundle.iface)
        raise RuntimeError(f"{exc}. The watchdog was unloaded and "
                           + ("the link taken DOWN" if not why else
                              f"the link could NOT be confirmed down ({why})")) from None
    notes.append(f"{bundle.iface} up as {real}")
    notes.append(_wait_handshake(wg, real))
    return notes


def _our_live_utuns(wg: str, iface: str) -> "list[str] | None":
    """The live WireGuard interfaces running THIS link's key, or None if that cannot be read.

    ``/var/run/wireguard/<iface>.name`` is only wg-quick's note of the utun it got: missing
    or stale, it proves nothing about what is running. ``wg show all public-key`` lists every
    live WireGuard interface (wireguard-go's control sockets) with its public key, so the
    tunnel is found by the key it holds."""
    try:
        priv = _paths(iface)["wg_key"].read_text()
    except OSError:
        return None
    try:
        pub = _wg_pubkey(wg, priv)
    except RuntimeError:
        return None
    proc = _run([wg, "show", "all", "public-key"])
    if proc.returncode != 0:
        return None
    out = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == pub:
            out.append(parts[0])
    return out


def _utun_key(wg: str, utun: str) -> "str | None":
    proc = _run([wg, "show", utun, "public-key"])
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def _our_pub(wg: str, iface: str) -> "str | None":
    try:
        return _wg_pubkey(wg, _paths(iface)["wg_key"].read_text())
    except (OSError, RuntimeError):
        return None


def _name_file_is_foreign(wg: str, iface: str) -> bool:
    """True unless wg-quick's name file names a utun POSITIVELY verified to run this link's key.
    macOS reuses utun numbers, so a stale note can point at someone else's VPN; a key that
    cannot be read (the utun is not WireGuard's, `wg show` failed, or our own key is missing)
    is not proof of ownership -- and `wg-quick down <iface>` acts on whatever the note names."""
    named = _real_iface_darwin(iface)
    if named is None:
        return False                      # no note: nothing for wg-quick to act on
    key, ours = _utun_key(wg, named), _our_pub(wg, iface)
    return key is None or ours is None or key != ours


def _our_real_iface_darwin(wg: str | None, iface: str) -> str | None:
    """The utun THIS link runs on, verified by key: the name file's utun only if it runs our
    key, else whichever live utun does (the note may be gone). Without ``wg`` or our key,
    nothing can be verified, so nothing is claimed."""
    if not wg:
        return None
    named = _real_iface_darwin(iface)
    ours = _our_pub(wg, iface)
    if ours is None:
        return None
    if named is not None and _utun_key(wg, named) == ours:
        return named
    live = _our_live_utuns(wg, iface) or []
    return live[0] if live else None


def _darwin_link_down(wg: str, wg_quick: str, iface: str) -> "str | None":
    """Take this macOS link down and VERIFY it, by key; None when confirmed down, otherwise why
    not. A failed ``wg-quick down`` is fatal unless the tunnel is verified gone (a re-run on an
    already-down link fails the command but has nothing running)."""
    if _name_file_is_foreign(wg, iface):
        # never let `wg-quick down <iface>` act on another VPN's tunnel through a stale note
        (WG_RUN_DIR / f"{iface}.name").unlink(missing_ok=True)
    down = _run([wg_quick, "down", iface])
    live = _our_live_utuns(wg, iface)
    if live:
        # wg-quick could not (its name file is gone or stale): stop wireguard-go the way
        # wg-quick does on macOS -- by removing its control socket -- and look again.
        for utun in live:
            if re.fullmatch(r"utun[0-9]{1,3}", utun):
                (WG_RUN_DIR / f"{utun}.sock").unlink(missing_ok=True)
        for _ in range(10):
            live = _our_live_utuns(wg, iface)
            if not live:
                break
            _sleep(0.5)
    if live is None:
        return ("cannot verify the tunnel is down (`wg show all public-key` unreadable or no "
                "key on disk)" + ("" if down.returncode == 0 else
                                  "; `wg-quick down` failed too"))
    still = sorted(set(live))
    if still:
        return f"{', '.join(still)} still runs this link's key"
    return None


def _darwin_pf_missing(bundle: JoinBundle, real: str) -> list[str]:
    info = _run([PFCTL, "-s", "info"])
    if info.returncode != 0:
        return ["pf cannot be read"]
    main = _run([PFCTL, "-s", "rules"])
    anchor = _run([PFCTL, "-a", pf_anchor_for(bundle.iface), "-s", "rules"])
    return pf_in_force(info=info.stdout, main_rules=main.stdout, anchor_rules=anchor.stdout,
                       real_iface=real, worker_ip=bundle.worker_ip, host_ip=bundle.host_ip,
                       agent_port=bundle.agent_port)


def _real_iface_darwin(iface: str) -> str | None:
    try:
        real = (WG_RUN_DIR / f"{iface}.name").read_text().strip()
    except OSError:
        return None
    return real if re.fullmatch(r"utun[0-9]{1,3}", real) else None


@_node_locked
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
    _refuse_foreign_interface(bundle.iface, plat)
    pre = linux_preflight(bundle) if plat == "linux" else darwin_preflight(bundle)
    agent_pw = None
    if agent_user:
        # Resolved BEFORE anything is installed: a mistyped account used to fail only after the
        # bundle's certificate and CA had replaced the ones the agent loads on its next start.
        import pwd

        try:
            agent_pw = pwd.getpwnam(agent_user)
        except KeyError:
            raise RuntimeError(f"no such user {agent_user!r} (--agent-user); nothing was "
                               "installed") from None
    mine = _wg_pubkey(wg, p["wg_key"].read_text())
    if mine == bundle.host_public_key:
        raise RuntimeError("the bundle's host key is THIS worker's own key")
    if mine != bundle.worker_public_key:
        # The host registered ANOTHER key as this worker's peer (a mixed-up --public-key at
        # `add`): the certificate would verify, the handshake never would, and join would only
        # note a slow handshake. Refused before anything is installed.
        raise RuntimeError(
            f"the bundle registers {bundle.worker_public_key[:10]}… as this worker's key, but this "
            f"worker's key is {mine[:10]}… -- re-run `worker-link add` on the host with the "
            "public key `keygen` printed here")
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as td:
        cert_t, ca_t = Path(td) / "c.crt", Path(td) / "ca.crt"
        cert_t.write_text(bundle.cert_pem)
        ca_t.write_text(bundle.ca_pem)
        verify_cert(openssl, cert=cert_t, ca=ca_t, key=p["tls_key"], ip=bundle.worker_ip)
        _replace_durably(cert_t, p["cert"])
        _replace_durably(ca_t, p["ca"])
    for f in (p["cert"], p["ca"]):
        os.chmod(f, 0o644)
    notes = [*pre, f"certificate for {bundle.worker_ip} verified and installed"]
    if agent_pw is not None:
        os.chown(p["tls_key"], agent_pw.pw_uid, agent_pw.pw_gid)
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
    st.update(host_ip=bundle.host_ip, agent_port=bundle.agent_port, name=bundle.name,
              joined_worker_ip=bundle.worker_ip)
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
        # the INSTALLED link's address: a later keygen for a new address (before the re-join)
        # changes worker_ip, not what is running
        ip = st.get("joined_worker_ip") or st["worker_ip"]
    except RuntimeError as exc:
        return False, [str(exc)]
    host_ip, agent_port = st.get("host_ip"), st.get("agent_port")
    if not host_ip or not agent_port:
        return False, [f"{iface}: keys made for {ip}, but this worker has not joined yet"]
    wg = _which("wg") or "wg"
    if plat == "darwin":
        # verified by KEY: the name file's utun only if it runs ours (macOS reuses utun numbers)
        real = _our_real_iface_darwin(_which("wg"), iface)
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
        elif listing.returncode != 0 and "No such file or directory" not in err:
            # only nft's not-found answer means the table is absent; anything else is unknown
            fw = None
            tail = err.strip().splitlines()[-1:] or [f"exit {listing.returncode}"]
            rows.append(f"firewall: UNVERIFIED — cannot read nftables ({tail[0]})")
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


#: First line of every interface config ``join`` writes (worker_wg_config): the proof that a
#: /etc/wireguard/<iface>.conf is ours.
WORKER_CONF_MARKER = "# blastbox worker-link — WORKER end."


def _conf_is_ours(iface: str) -> "bool | None":
    """True/False for an existing interface config written / not written by ``join``; None
    when there is none."""
    try:
        return _paths(iface)["conf"].read_text().startswith(WORKER_CONF_MARKER)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError(f"cannot read {_paths(iface)['conf']}: {exc.strerror}") from None


def _iface_is_live(iface: str, plat: str) -> bool:
    if plat == "darwin":
        return _real_iface_darwin(iface) is not None
    return _ok(["ip", "link", "show", iface]) or _ok(["systemctl", "is-enabled",
                                                      f"wg-quick@{iface}"])


def _refuse_foreign_interface(iface: str, plat: str) -> None:
    """Raise if ``iface`` is a WireGuard interface worker-link did not create on this node.

    ``join`` overwrites ``/etc/wireguard/<iface>.conf`` and (re)starts the interface; for the
    operator's own ``wg1`` that is a destroyed VPN. Ours: its config carries the line ``join``
    writes first. With no config, a live interface (or an enabled wg-quick unit) under that
    name is someone else's.
    """
    ours = _conf_is_ours(iface)
    if ours is False:
        raise RuntimeError(
            f"{_paths(iface)['conf']} exists and was not written by worker-link; refusing to "
            "overwrite it. Use another interface name for the link (`keygen --iface ...`).")
    if ours is None and _iface_is_live(iface, plat):
        raise RuntimeError(
            f"a WireGuard interface {iface} already exists here and is not worker-link's; "
            "refusing to take it over. Use another interface name for the link.")


def _refuse_leaving_what_is_not_ours(iface: str, plat: str) -> None:
    """Raise unless ``iface`` is a link worker-link set up here -- checked BEFORE ``leave``
    touches anything.

    ``leave`` stops ``wg-quick@<iface>`` / runs ``wg-quick down <iface>`` and then removes
    firewall state. Two ways a mistyped ``--iface`` did damage:

    * Linux: the nft table, ruleset file and firewall units are NODE-WIDE. Leaving another
      name (merely confirmed down) removed the firewall of the link that IS installed, which
      stayed up -- its wg-quick unit still enabled -- with no worker-side firewall.
    * Either platform: a name worker-link never created (``wg0``, the operator's own VPN) was
      taken down. The pf anchor and LaunchDaemon label on macOS are derived from the name, so
      they are ours exactly when the name is.

    Ours means: this node's keygen record for ``iface`` (``join`` requires it), its
    LaunchDaemon plist (macOS), or the installed Linux link itself.
    """
    p = _paths(iface)
    installed = _installed_linux_links() if plat == "linux" else set()
    if plat == "linux" and installed and iface not in installed:
        other = sorted(installed)
        raise RuntimeError(
            f"the worker-link on this node is {', '.join(other)}, not {iface}: refusing to "
            f"leave. Its firewall is node-wide, so leaving {iface} would strip it from the "
            f"running link. Did you mean `leave --iface {other[0]}`?")
    ours = (p["state"].exists() or iface in installed
            or (plat == "darwin" and p["plist"].exists()))
    if not ours:
        raise RuntimeError(
            f"no worker-link was set up on {iface} here (no keygen record"
            + (", no LaunchDaemon" if plat == "darwin" else "")
            + "); refusing to take down an interface worker-link did not create. Check "
            "--iface: it must be the name given to `worker-link keygen` / `join`.")
    # A keygen record alone is not ownership of the INTERFACE: keygen for a name that is also
    # the operator's own VPN leaves their config / live tunnel under it, which join refuses to
    # take over -- so leave must not take it down or delete that config either.
    conf_ours = _conf_is_ours(iface)
    if conf_ours is False:
        raise RuntimeError(
            f"{p['conf']} was not written by worker-link; refusing to take {iface} down or "
            "delete that config. Check --iface.")
    if conf_ours is None and iface not in installed and _iface_is_live(iface, plat) \
            and not (plat == "darwin" and p["plist"].exists()):
        raise RuntimeError(
            f"{iface} is up but worker-link has no config for it here; refusing to take down an "
            "interface it did not bring up. Check --iface.")


@_node_locked
def leave(iface: str = DEFAULT_IFACE, *, purge: bool = False) -> list[str]:
    """Take the link down and remove what ``join`` installed. The tunnel goes down BEFORE the
    firewall is removed. Keys and TLS material stay unless ``purge``."""
    _require_root("leave")
    plat = _supported_platform()
    iface = _link_iface(iface)
    p = _paths(iface)
    _refuse_leaving_what_is_not_ours(iface, plat)
    notes: list[str] = []
    if plat == "darwin":
        label = label_for(iface)
        _run(["launchctl", "bootout", f"system/{label}"])
        # VERIFIED, not assumed: a watchdog still loaded (bootout failed, or an invocation was
        # already running) brings the tunnel straight back up -- after this function flushed
        # its pf rules. So nothing is removed until launchd no longer knows the label.
        if _ok(["launchctl", "print", f"system/{label}"]):
            notes.append(f"WARNING: LaunchDaemon {label} is STILL LOADED (bootout failed); the "
                         "link, its pf rules and its files are left in place. Run "
                         f"`sudo launchctl bootout system/{label}` and re-run leave.")
            return notes
        wg_quick, wg_bin = _which("wg-quick"), _which("wg")
        why = (_darwin_link_down(wg_bin, wg_quick, iface) if wg_quick and wg_bin
               else "wireguard-tools (wg, wg-quick) not found, so the tunnel cannot be stopped "
                    "or verified")
        if why:
            notes.append(f"WARNING: {iface} is not confirmed down ({why}); pf rules and files "
                         "left in place. Stop it by hand and re-run leave.")
            return notes
        notes.append(f"{iface} down; LaunchDaemon {label} unloaded")
        _run([PFCTL, "-a", pf_anchor_for(iface), "-F", "all"])
        left = _run([PFCTL, "-a", pf_anchor_for(iface), "-s", "rules"])
        if left.returncode != 0 or left.stdout.strip():
            # Nothing is removed until the anchor is VERIFIED empty: the plist, script, config
            # and keys are what a re-run of leave identifies this install by.
            notes.append(f"WARNING: could not verify pf anchor {pf_anchor_for(iface)} is empty; "
                         "its files, config and keys are left in place. Re-run leave.")
            return notes
        notes.append(f"pf anchor {pf_anchor_for(iface)} flushed (pf itself left as it was)")
        for f in (p["plist"], p["script"]):
            f.unlink(missing_ok=True)
    else:
        _run(["systemctl", "disable", "--now", f"wg-quick@{iface}"])
        _run(["wg-quick", "down", iface])
        if _ok(["ip", "link", "show", iface]):
            notes.append(f"WARNING: {iface} is STILL UP; firewall left in place")
            return notes
        # ...and DISABLED, verified (as host teardown does): `disable --now` can stop the unit
        # yet fail to remove its enablement, and an enabled wg-quick@ would start the link at
        # the next boot with its config and firewall gone.
        if _ok(["systemctl", "is-enabled", f"wg-quick@{iface}"]):
            notes.append(f"WARNING: wg-quick@{iface} is STILL ENABLED; its config and firewall "
                         f"are left in place. Run `systemctl disable wg-quick@{iface}` and "
                         "re-run leave.")
            return notes
        notes.append(f"{iface} down; wg-quick@{iface} disabled")
        _run(["systemctl", "disable", "--now", REASSERT_TIMER_NAME])
        _run(["systemctl", "disable", "--now", FW_UNIT_NAME])
        _run(["nft", "delete", "table", "inet", NFT_TABLE])
        # VERIFY BEFORE REMOVING ANYTHING (as host teardown does): the firewall unit, ruleset
        # file, config and -- with --purge -- keys and state are the recovery records a re-run
        # of leave finds this install by. Only nft's own not-found answer is "gone".
        still = _run(["nft", "list", "table", "inet", NFT_TABLE])
        if not (still.returncode != 0 and "No such file or directory" in (still.stderr or "")):
            detail = "it is still loaded" if still.returncode == 0 else (
                (still.stderr or "").strip().splitlines()[-1:] or [f"exit {still.returncode}"])[0]
            notes.append(f"WARNING: could not verify table inet {NFT_TABLE} was removed ({detail}); "
                         "its units, ruleset, config and keys are left in place. Re-run leave.")
            return notes
        for f in (*_reassert_paths(), FW_UNIT, FW_FILE):
            f.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        notes.append(f"table inet {NFT_TABLE} and its unit removed (no other table touched)")
    p["conf"].unlink(missing_ok=True)
    if purge:
        for key in ("wg_key", "wg_pub", "tls_key", "csr", "cert", "ca", "state"):
            p[key].unlink(missing_ok=True)
        # ...and the directories keygen created, once nothing else is in them (another
        # interface's keys may be): rmdir refuses a non-empty directory, never recurses.
        for d in (STATE_DIR, KEY_DIR):
            try:
                d.rmdir()
            except OSError:
                pass
        notes.append("keys, certificates and keygen state removed")
    else:
        # The link is gone: the keygen record must no longer say JOINED (status, and the
        # key-generation check, read it). The keys and the address they were made for stay.
        try:
            st = json.loads(p["state"].read_text())
        except (OSError, ValueError):
            st = None
        joined = ("host_ip", "agent_port", "name", "joined_worker_ip")
        if isinstance(st, dict) and any(k in st for k in joined):
            for k in joined:
                st.pop(k, None)
            _write_public(p["state"], json.dumps(st) + "\n")
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
        notes = leave(args.iface or DEFAULT_IFACE, purge=args.purge)
        for n in notes:
            print(f"  {n}")
        # A step that could not be verified (still up / enabled / loaded) is not a clean
        # leave: say so in the exit status too, so automation does not read it as done.
        return 1 if any(n.startswith("WARNING") for n in notes) else 0
    if action == "status" and _role(args) == "worker":
        ok, rows = status(args.iface or DEFAULT_IFACE)
        for r in rows:
            print(f"  {r}")
        return 0 if ok else 1

    # Host side.
    wla = _host_mod()
    if action == "init":
        cfg = _host_cfg(args, base_required=False)
        pub, notes = wla.init_host(cfg, rotate_key=bool(getattr(args, "rotate_key", False)))
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
        notes = wla.teardown(cfg)
        for n in notes:
            print(f"  {n}")
        return 1 if any(n.startswith("WARNING") for n in notes) else 0
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
    pi.add_argument("--rotate-key", action="store_true",
                    help="generate a NEW host key; every registered worker must then be "
                         "re-added and re-joined (init otherwise always keeps the key)")
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
