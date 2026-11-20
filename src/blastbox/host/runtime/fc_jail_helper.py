"""Root-side launcher that runs every Firecracker microVM under the upstream ``jailer``.

WHY A HELPER. The dispatcher runs as an unprivileged uid in a container (no capabilities,
``no-new-privileges``). The jailer needs root: chroot/pivot_root, mknod, chown, cgroup writes,
setns into a network namespace and the uid/gid drop. Granting the dispatcher capabilities or
shipping a setuid wrapper were both rejected (owner, 2026-11-19), so a small root daemon does
exactly the privileged steps and nothing else. It is the ONLY privileged component, and the
dispatcher that talks to it is less trusted than it is -- so the API is deliberately narrow:

* No path, argv element or environment value ever comes from the client. Jail ids, generation
  ids and asset ids are validated against fixed patterns and only ever name objects the helper
  itself created FOR THAT CLIENT PROCESS. Files the client wants booted (kernel, rootfs) arrive
  as OPEN FILE DESCRIPTORS (SCM_RIGHTS): the helper reads only what the client could already
  read, so it can never be used as a confused deputy to read a root-only file.
* Every request is one SOCK_SEQPACKET message with a fixed per-op schema: unknown ops, unknown
  keys, wrong types (``True`` is not an int here) and out-of-range numbers are refused.
* Peers are authenticated with ``SO_PEERCRED`` (an allow-list of uids). Every jail, generation
  and asset pin is OWNED by the peer PROCESS that created it (a pidfd), so one dispatcher can
  never signal, connect to, read or destroy another dispatcher's microVMs -- the five engine
  stacks on one host share this helper. When an owner process exits, its jails are killed and
  its generations reclaimed (the container used to do this implicitly: its pid namespace took
  every child firecracker down with it).
* Anything the helper touches inside a jail root after the jailed process started is opened
  ``O_NOFOLLOW`` from a directory fd and type/owner-checked, because the jail uid owns that
  directory and can plant symlinks, FIFOs or hard links in it.

WHAT A JAIL IS. One microVM = one jail: the upstream ``jailer`` (pivot_root into a private
chroot, mknod'd devices, its own cgroup v2 leaf, an EMPTY network namespace, and a uid/gid
unique among live jails), with Firecracker's own seccomp filters. On top of that the helper:

* drops the capability bounding set to the few capabilities the jailer itself uses and sets
  ``no_new_privs`` before exec'ing it (``setpriv``) -- the jailer runs as root, so dropping the
  set entirely would stop it working; after its setuid the effective/permitted sets are empty;
* confines the firecracker process with a per-jail AppArmor profile (attachment by the jail's
  unique exec-file name), rendered with that jail's exact host paths;
* parents every jail cgroup under a delegated subtree with a host-level ``memory.max``, so the
  microVMs stay inside a memory cap after leaving the dispatcher container's memcg;
* refuses to hand a jail back as usable (``seal``) unless every thread of the firecracker
  process has a seccomp filter, ``no_new_privs`` and empty effective/permitted/inheritable/
  ambient capability sets.

This module is STDLIB-ONLY and imports nothing from blastbox: it runs as root, and is installed
as a single file (``python3 -I fc_jail_helper.py ...``) so what runs privileged is one auditable
file with no third-party import surface. The dispatcher-side client is ``fc_jail.py``.
"""
from __future__ import annotations

import argparse
import array
import contextlib
import errno
import fcntl
import grp
import hashlib
import json
import logging
import os
import re
import resource
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PROTOCOL_VERSION = 1

# --------------------------------------------------------------------------- protocol (shared)
#: Largest request/response message. Requests are tiny; responses carry at most a log tail.
MAX_MSG = 16 * 1024
#: Most fds one request may attach (``asset`` passes exactly one).
MAX_REQUEST_FDS = 1
#: The kernel's per-message SCM_RIGHTS maximum: the helper always makes room for all of them.
SCM_MAX_FD = 253
_LISTEN_BACKLOG = 64

#: Names INSIDE a jail. The jailer pivot_root()s into the jail and firecracker's cwd is ``/``.
JAIL_KERNEL = "vmlinux"
JAIL_ROOTFS = "rootfs.ext4"
JAIL_OUTDISK = "outdisk.ext4"
JAIL_VSOCK = "vsock.sock"
#: The oldest Firecracker the helper runs (as the dispatcher's own gate, firecracker.py).
MIN_FC_VERSION = (1, 15, 1)
JAIL_API_SOCK = "fc-api.sock"
JAIL_SNAPSHOT = "warm.snapshot"
JAIL_MEM = "warm.mem"
#: The guest's READY vsock port (``blastbox.worker.fc_guest.READY_PORT``); firecracker forwards a
#: guest connect on it to ``<uds>_<port>``. Asserted equal to the dispatcher's constant in tests.
READY_PORT = 10000

#: Jail ids are client-chosen but pattern-bound (a uuid4 is 36 chars). Lowercase only, so a
#: jail id is always a valid jailer ``--id``, AppArmor profile name, netns name and cgroup name.
JAIL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
GEN_ID_RE = re.compile(r"^g[0-9a-f]{32}$")
ASSET_ID_RE = re.compile(r"^a[0-9a-f]{32}$")

MODES = ("boot", "restore")
TARGETS = ("api", "vsock")
SIGNALS = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
ASSET_KINDS = ("kernel", "rootfs")

# Numeric bounds a client may ask for. The cgroup limits derived from them are what bound a
# jail; the bounds only stop a nonsense request from being turned into a nonsense cgroup.
MEM_MIB_RANGE = (64, 256 * 1024)
VCPU_RANGE = (1, 32)
OUTDISK_MIB_RANGE = (16, 64 * 1024)

_INT = "int"
_BOOL = "bool"
_JAIL = "jail"
_GEN = "gen"
_ASSET = "asset"
_OPT_ASSET = "asset?"
_OPT_GEN = "gen?"

#: op -> {key: kind}. EXACTLY these keys (besides "op"): anything else is refused.
SCHEMAS: "dict[str, dict[str, Any]]" = {
    "hello": {},
    "asset": {"kind": ASSET_KINDS},
    "spawn": {
        "jail": _JAIL, "mode": MODES, "kernel": _OPT_ASSET, "rootfs": _OPT_ASSET,
        "gen": _OPT_GEN, "outdisk_mib": (_INT, OUTDISK_MIB_RANGE),
        "mem_mib": (_INT, MEM_MIB_RANGE), "vcpus": (_INT, VCPU_RANGE),
        "ready_listener": _BOOL,
    },
    "connect": {"jail": _JAIL, "target": TARGETS},
    "status": {"jail": _JAIL},
    "signal": {"jail": _JAIL, "sig": tuple(SIGNALS)},
    "seal": {"jail": _JAIL},
    "outdisk": {"jail": _JAIL},
    "publish": {"jail": _JAIL},
    "destroy": {"jail": _JAIL},
    "discard": {"gen": _GEN},
}
#: Ops whose request carries exactly one fd.
FD_OPS = frozenset({"asset"})


class ProtocolError(ValueError):
    """A request that does not match its schema. Never reaches any privileged code."""


class HelperError(RuntimeError):
    """A well-formed request the helper refuses or could not complete."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def validate_request(msg: object, nfds: int) -> "dict[str, Any]":
    """Return the request if it matches its op's schema EXACTLY, else raise ProtocolError."""
    if not isinstance(msg, dict):
        raise ProtocolError("request is not an object")
    op = msg.get("op")
    if not isinstance(op, str) or op not in SCHEMAS:
        raise ProtocolError(f"unknown op {op!r}")
    schema = SCHEMAS[op]
    keys = set(msg) - {"op"}
    if keys != set(schema):
        raise ProtocolError(
            f"{op}: keys {sorted(keys)} != {sorted(schema)}")
    want_fds = 1 if op in FD_OPS else 0
    if nfds != want_fds:
        raise ProtocolError(f"{op}: expected {want_fds} fd(s), got {nfds}")
    for key, kind in schema.items():
        _check_value(op, key, kind, msg[key])
    return msg


def _check_value(op: str, key: str, kind: Any, value: object) -> None:
    where = f"{op}.{key}"
    if kind == _BOOL:
        if not isinstance(value, bool):
            raise ProtocolError(f"{where} must be a boolean")
    elif isinstance(kind, tuple) and kind and kind[0] == _INT:
        lo, hi = kind[1]
        # bool is an int subclass; refuse it explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or not (lo <= value <= hi):
            raise ProtocolError(f"{where} must be an integer in [{lo}, {hi}]")
    elif isinstance(kind, tuple):
        if not isinstance(value, str) or value not in kind:
            raise ProtocolError(f"{where} must be one of {list(kind)}")
    elif kind in (_JAIL, _GEN, _ASSET, _OPT_ASSET, _OPT_GEN):
        if value is None and kind in (_OPT_ASSET, _OPT_GEN):
            return
        pattern = {_JAIL: JAIL_ID_RE, _GEN: GEN_ID_RE, _OPT_GEN: GEN_ID_RE,
                   _ASSET: ASSET_ID_RE, _OPT_ASSET: ASSET_ID_RE}[kind]
        if not isinstance(value, str) or not pattern.match(value):
            raise ProtocolError(f"{where} is not a valid id")
    else:  # pragma: no cover - schema typo
        raise ProtocolError(f"{where}: unknown schema kind {kind!r}")


def encode(msg: "dict[str, Any]") -> bytes:
    data = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(data) > MAX_MSG:
        raise ProtocolError("message too large")
    return data


def decode(data: bytes) -> object:
    if len(data) > MAX_MSG:
        raise ProtocolError("message too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(f"malformed message: {exc}") from exc


# --------------------------------------------------------------------------- file helpers
_FICLONE = 0x40049409


def sparse_copy(src_fd: int, dst_fd: int, size: int, *, deadline: "float | None" = None) -> None:
    """Copy ``size`` bytes of ``src_fd`` into ``dst_fd`` preserving holes.

    MOVES ``src_fd``'s file offset (SEEK_DATA/SEEK_HOLE): never pass a description another
    process shares -- reopen it first (see ``op_asset``).

    Tries a reflink first (free on xfs/btrfs). Otherwise copies only the data extents
    (SEEK_DATA/SEEK_HOLE) with copy_file_range, so a mostly-empty multi-GiB ext4 image costs
    what it contains. ``deadline`` (monotonic) bounds the loop between extents.
    """
    os.ftruncate(dst_fd, 0)
    try:
        fcntl.ioctl(dst_fd, _FICLONE, src_fd)
        if os.fstat(dst_fd).st_size == size:
            return
    except OSError:
        pass
    os.ftruncate(dst_fd, size)
    pos = 0
    while pos < size:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("copy exceeded its deadline")
        try:
            data = os.lseek(src_fd, pos, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:  # no more data: the rest is a hole
                break
            if exc.errno in (errno.EINVAL, errno.EOPNOTSUPP):
                data = pos                # no SEEK_DATA support: copy densely
            else:
                raise
        if data >= size:
            break
        try:
            hole = os.lseek(src_fd, data, os.SEEK_HOLE)
        except OSError:
            hole = size
        hole = min(hole, size)
        _copy_range(src_fd, dst_fd, data, hole - data, deadline=deadline)
        pos = hole


def _copy_range(src_fd: int, dst_fd: int, offset: int, count: int, *,
                deadline: "float | None" = None) -> None:
    done = 0
    while done < count:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("copy exceeded its deadline")
        want = min(count - done, 64 << 20)
        try:
            n = os.copy_file_range(src_fd, dst_fd, want, offset + done, offset + done)
        except OSError as exc:
            if exc.errno not in (errno.EXDEV, errno.EINVAL, errno.EOPNOTSUPP, errno.ENOSYS):
                raise
            buf = os.pread(src_fd, min(want, 4 << 20), offset + done)
            n = os.pwrite(dst_fd, buf, offset + done) if buf else 0
        if n <= 0:
            raise OSError(errno.EIO, f"short copy at {offset + done} (source shrank?)")
        done += n


def identity(st: os.stat_result) -> "tuple[int, int, int, int]":
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


# --------------------------------------------------------------------------- jailer argv
#: Capabilities left in the bounding set for the jailer -- MEASURED (jailer v1.16.0, toolz2
#: 2026-11-19: each removed in turn; every one of these is fatal to the jailer without it):
#: chown (the jail tree), dac_override (creating /dev in the 0700 chroot), mknod (the devices),
#: setgid/setuid (the drop), sys_admin (mount ns, pivot_root, setns into the netns). Everything
#: else -- 35+ capabilities, including net_admin, sys_module, sys_ptrace, sys_rawio, sys_chroot,
#: bpf, perfmon -- is gone before the jailer runs, and with no_new_privs and its setuid the
#: firecracker process can never regain even these.
JAILER_BOUNDING_CAPS = ("chown", "dac_override", "mknod", "setgid", "setuid", "sys_admin")

#: Linux capability numbers, for verifying CapBnd from /proc.
_CAP_NUMBERS = {
    "chown": 0, "dac_override": 1, "dac_read_search": 2, "fowner": 3, "fsetid": 4, "kill": 5,
    "setgid": 6, "setuid": 7, "setpcap": 8, "mknod": 27, "sys_admin": 21, "sys_chroot": 18,
    "sys_resource": 24,
}


def bounding_mask(caps: "tuple[str, ...]" = JAILER_BOUNDING_CAPS) -> int:
    mask = 0
    for cap in caps:
        mask |= 1 << _CAP_NUMBERS[cap]
    return mask


def exec_name(jail_id: str) -> str:
    """The per-jail exec-file name. Unique per jail so AppArmor attaches THIS jail's profile by
    path (the jailer requires the name to contain "firecracker")."""
    return f"firecracker-{jail_id}"


def jailer_argv(cfg: "HelperConfig", jail_id: str, uid: int, *, exec_file: str,
                cgroups: "dict[str, str]", netns_path: str, fsize: int = 0) -> "list[str]":
    """The exact command line. Built ONLY from operator config and helper-chosen values; the one
    client-supplied element, the jail id, is pattern-validated before it gets here.

    ``--new-pid-ns`` and ``--daemonize`` are deliberately absent: without them the jailer exec()s
    firecracker IN PLACE, so the pid the helper spawned is the VMM itself (one pidfd tracks it).
    """
    if not JAIL_ID_RE.match(jail_id):
        raise HelperError("bad_id", jail_id)
    caps = ",".join(["-all", *(f"+{c}" for c in cfg.bounding_caps)])
    argv = [
        cfg.setpriv, "--no-new-privs", "--inh-caps", "-all", "--ambient-caps", "-all",
        "--bounding-set", caps, "--",
        cfg.jailer, "--id", jail_id, "--exec-file", exec_file,
        "--uid", str(uid), "--gid", str(uid),
        "--chroot-base-dir", str(cfg.chroot_base),
        "--netns", netns_path,
        "--cgroup-version", "2", "--parent-cgroup", cfg.cgroup_parent_rel,
    ]
    for key in sorted(cgroups):
        argv += ["--cgroup", f"{key}={cgroups[key]}"]
    argv += ["--resource-limit", f"no-file={cfg.nofile}"]
    if fsize:
        # No file the VMM writes may exceed what it legitimately writes (the memory snapshot or
        # the output disk): a compromised VMM growing a file past it gets SIGXFSZ.
        argv += ["--resource-limit", f"fsize={fsize}"]
    return argv + ["--", "--api-sock", f"/{JAIL_API_SOCK}"]


# --------------------------------------------------------------------------- AppArmor
def render_profile(cfg: "HelperConfig", jail_id: str, *, boot: bool, listener_host_path: "str | None") -> str:
    """The AppArmor profile for ONE jail. Paths are jail-relative (AppArmor resolves them against
    the jail's mount namespace after pivot_root) except the READY listener, which the helper
    binds from the host namespace and is therefore mediated by its HOST path -- rendered exactly,
    never as a glob (measured on toolz2 2026-11-19)."""
    name = exec_name(jail_id)
    lines = [
        "abi <abi/3.0>,",
        "include <tunables/global>",
        f"profile {profile_name(jail_id)} /{name} flags=(attach_disconnected) {{",
        f"  /{name} mr,",
        "  /dev/kvm rw,",
        "  /dev/urandom r,",
        "  /dev/userfaultfd rw,",
        "  deny /dev/net/tun rw,",
        f"  /{JAIL_ROOTFS} r,",
        f"  /{JAIL_OUTDISK} rw,",
        f"  /{JAIL_API_SOCK} rw,",
        f"  /{JAIL_VSOCK} rw,",
        "  /run/ r,",
        "  /dev/null rw,",
        "  unix (create, bind, listen, accept, connect, send, receive, getattr, getopt, setopt,"
        " shutdown) type=stream,",
        "  signal (receive) peer=unconfined,",
        # Firecracker kicks its own vCPU threads with a signal to pause them (snapshot create):
        # without this PATCH /vm Paused fails with "Failed to message the vCPUs".
        f"  signal (send, receive) peer={profile_name(jail_id)},",
        "  deny ptrace,",
        "  deny capability,",
        "  deny mount,",
        "  deny umount,",
        "  deny pivot_root,",
        "  deny network inet,",
        "  deny network inet6,",
        "  deny network netlink,",
        "  deny network packet,",
        "  deny @{PROC}/** w,",
        "  deny /sys/** w,",
    ]
    if boot:
        lines += [f"  /{JAIL_KERNEL} r,", f"  owner /{JAIL_SNAPSHOT} rw,", f"  owner /{JAIL_MEM} rw,"]
    else:
        lines += [f"  /{JAIL_SNAPSHOT} r,", f"  /{JAIL_MEM} r,"]
    if listener_host_path is not None:
        lines.append(f"  {listener_host_path} rw,")
    lines.append("}")
    return "\n".join(lines) + "\n"


def profile_name(jail_id: str) -> str:
    return f"blastbox-fc-jail-{jail_id}"


# --------------------------------------------------------------------------- configuration
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]+$")


@dataclass(frozen=True)
class HelperConfig:
    socket_path: Path
    socket_gid: int
    allowed_uids: "frozenset[int]"
    firecracker: str
    jailer: str
    chroot_base: Path
    setpriv: str = "/usr/bin/setpriv"
    ip: str = "/usr/sbin/ip"
    mkfs: str = "/usr/sbin/mkfs.ext4"
    apparmor_parser: str = "/sbin/apparmor_parser"
    apparmor: str = "auto"                # auto | require | off
    uid_min: int = 200000
    uid_max: int = 200999
    #: cgroup v2 path (relative to the cgroup root) the jailer creates <id> leaves under.
    cgroup_parent_rel: str = ""
    cgroup_root: Path = Path("/sys/fs/cgroup")
    jails_memory_max: int = 0             # bytes; 0 = derive from MemTotal at startup
    jail_mem_overhead_mib: int = 256
    jail_pids_max: int = 128
    nofile: int = 1024
    max_jails: int = 512
    max_jails_per_owner: int = 256
    max_owners: int = 64
    max_gens_per_owner: int = 4
    max_conns: int = 128
    max_conns_per_peer: int = 32
    max_asset_bytes: int = 16 << 30
    max_snapshot_bytes: int = 64 << 20
    spawn_timeout_s: float = 10.0
    copy_timeout_s: float = 600.0
    bounding_caps: "tuple[str, ...]" = JAILER_BOUNDING_CAPS

    def __post_init__(self) -> None:
        for label, path in (("chroot base", str(self.chroot_base)),):
            if not _SAFE_PATH_RE.match(path) or "/.." in path or "/./" in path:
                raise ValueError(f"{label} {path!r} must be an absolute path of [A-Za-z0-9/_.-]")
        if not (0 < self.uid_min <= self.uid_max):
            raise ValueError(f"bad uid range {self.uid_min}..{self.uid_max}")
        if self.apparmor not in ("auto", "require", "off"):
            raise ValueError(f"apparmor must be auto|require|off, not {self.apparmor!r}")
        if self.allowed_uids & {0}:
            raise ValueError("uid 0 may not be an allowed client")
        if any(u in range(self.uid_min, self.uid_max + 1) for u in self.allowed_uids):
            raise ValueError("an allowed client uid lies inside the jail uid range")

    @property
    def assets_dir(self) -> Path:
        return self.chroot_base / "assets"

    @property
    def gens_dir(self) -> Path:
        return self.chroot_base / "gens"

    @property
    def bin_dir(self) -> Path:
        return self.chroot_base / "bin"



# --------------------------------------------------------------------------- state
@dataclass
class Owner:
    pid: int
    pidfd: int
    jails: "set[str]" = field(default_factory=set)
    gens: "set[str]" = field(default_factory=set)
    assets: "deque[str]" = field(default_factory=lambda: deque(maxlen=8))
    dead: bool = False
    #: Publishes in flight, reserved against max_gens_per_owner under the state lock.
    publishing: int = 0


@dataclass
class Asset:
    id: str
    kind: str
    path: str        # a plain string: see _copy_asset
    key: "tuple[int, int, int, int]"
    refs: int = 0
    dropping: bool = False      # being unlinked: no new references


@dataclass
class Gen:
    id: str
    owner: Owner
    dir: str          # plain strings for per-object paths: see _jp
    rootfs: str           # asset id
    mem_bytes: int
    refs: "set[str]" = field(default_factory=set)
    retired: bool = False


@dataclass
class Jail:
    id: str
    owner: Owner
    uid: int
    mode: str
    top: str                      # <chroot_base>/<exec name>  (removed on destroy)
    root: str                     # <top>/<id>/root
    netns: str
    cgroup: str
    mem_mib: int
    #: The staged output disk's size: the jail's VMM holds that file read-write, so its size
    #: as seen later is attacker-controlled -- op_outdisk refuses anything else.
    outdisk_bytes: int = 0
    profile: "str | None" = None
    gen: "str | None" = None
    assets: "list[str]" = field(default_factory=list)
    proc: "subprocess.Popen[bytes] | None" = None
    pidfd: "int | None" = None
    outdisk_fd: "int | None" = None
    listener_path: "str | None" = None
    sealed: bool = False
    destroyed: bool = False
    #: Its spawn failed and cleanup did not complete: the monitor retries it.
    orphaned: bool = False
    #: True from registration until _start has a process (or has given up).
    spawning: bool = True
    log: "deque[bytes]" = field(default_factory=lambda: deque(maxlen=64))
    lock: threading.Lock = field(default_factory=threading.Lock)
    #: Guards pidfd's lifetime only (never held across slow work): a signal must not be sent
    #: through a number destroy has closed and the kernel has reused for another process.
    pidfd_lock: threading.Lock = field(default_factory=threading.Lock)

    def exited(self) -> bool:
        if self.proc is None:
            # Registered but still being staged/started: NOT exited. Treating it as exited let a
            # destroy (or an owner reap) tear it down and free its uid while _start went on to
            # add a netns, load a profile and launch the jailer for a jail nobody tracks.
            return not self.spawning
        return self.proc.poll() is not None


class UidPool:
    """One uid (== gid) per LIVE jail. FIFO, so a released uid is reused as late as possible.
    Released only after a CONFIRMED destroy: reusing a uid while its previous holder may still
    run would let the new jail signal/ptrace-check/open the old one's files."""

    def __init__(self, lo: int, hi: int) -> None:
        self._free: deque[int] = deque(range(lo, hi + 1))
        self._lock = threading.Lock()

    def take(self) -> int:
        with self._lock:
            if not self._free:
                raise HelperError("exhausted", "jail uid range exhausted")
            return self._free.popleft()

    def give(self, uid: int) -> None:
        with self._lock:
            self._free.append(uid)



# --------------------------------------------------------------------------- client-file sink
_SINK_CODE = r"""
import os, socket, sys, threading
s = socket.socket(fileno=int(sys.argv[1]))

def close_all(seq, fds):
    for fd in fds:
        try:
            os.close(fd)               # the FINAL release -- here, never in the helper
        except OSError:
            pass
    try:
        s.send(b"D" + seq)             # THIS batch is closed (they finish in any order)
    except OSError:
        pass

while True:
    try:
        data, fds, _, _ = socket.recv_fds(s, 16, 253)
    except OSError:
        break
    if not data or data[:1] != b"F":
        break
    # HOW MANY it holds: with a full fd table the kernel installs only some and drops the rest;
    # the helper must not drop its copies of those (its close would be their final release).
    s.send(b"A" + len(fds).to_bytes(4, "big"))
    try:
        s.recv(16)                     # "G": the helper's copies are gone
    except OSError:
        break
    # Closed on a thread of its own: a close that lingers must not delay the NEXT batch's
    # acknowledgement (the helper waits for it under a lock every client shares).
    threading.Thread(target=close_all, args=(data[1:9], fds), daemon=True).start()
"""


#: How long a handed-over batch may stay un-closed before its sink is presumed wedged.
_SINK_GRACE_S = 0.5
#: Most client descriptors one sink may hold at once (stuck closes included): far below its
#: RLIMIT_NOFILE, so it is replaced before the kernel ever has to drop a batch's tail.
_SINK_MAX_HELD = 4096


class FdSink:
    """Where every client-supplied file is finally released: a disposable child process.

    Closing the last reference to a client's file runs its release in the closing thread, and
    a client controls what that costs -- a socket set to linger with unsent data, an AF_UNIX
    socket whose queue holds such a socket, a connection with such records queued -- so the
    helper never drops a last reference itself. It hands the descriptors (and the client's
    connection) to the sink, which acknowledges holding them before the helper closes its own
    copies; the sink then closes them. A sink still busy with an earlier batch is presumed
    wedged and replaced: SIGKILL ends a lingering close, and the dying sink's remaining files
    are released by its own exit.
    """

    def __init__(self, popen: "Callable[..., subprocess.Popen[bytes]]" = subprocess.Popen) -> None:
        self._popen = popen
        self._lock = threading.Lock()
        self._proc: "subprocess.Popen[bytes] | None" = None
        self._sock: "socket.socket | None" = None
        # batch sequence number -> when it was handed over, until ITS "D" arrives. Per batch,
        # not a count: closes finish out of order, and a count would let later batches' "D"s
        # hide a batch stuck closing forever.
        self._outstanding: "dict[int, float]" = {}
        self._counts: "dict[int, int]" = {}    # descriptors each outstanding batch holds
        self._seq = 0
        self._spare_lock = threading.Lock()
        self._spare: "tuple[socket.socket, subprocess.Popen[bytes]] | None" = None
        self._closed = False

    def _spawn_sink(self) -> "tuple[socket.socket, subprocess.Popen[bytes]]":
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            proc = self._popen(
                [sys.executable, "-I", "-c", _SINK_CODE, str(b.fileno())],
                pass_fds=(b.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True, env={})
        except BaseException:
            a.close()
            raise
        finally:
            b.close()
        a.settimeout(2.0)            # only the ACK wait uses it: a fresh sink answers at once
        return a, proc

    def _refill_spare(self) -> None:
        """Keep one sink started ahead of need, off the caller's path: replacing a wedged sink
        must cost a swap, not a Python start-up under the lock every client shares."""
        def _run() -> None:
            try:
                spare = self._spawn_sink()
            except Exception:  # noqa: BLE001 - the synchronous path starts one if needed
                return
            with self._spare_lock:
                if self._spare is None and not self._closed:
                    self._spare = spare
                    return
            spare[0].close()
            _reap_async(spare[1])
        with contextlib.suppress(RuntimeError):   # no spare this time: started on demand
            threading.Thread(target=_run, daemon=True, name="fcj-sink-spare").start()

    def _start(self) -> None:
        with self._spare_lock:
            spare, self._spare = self._spare, None
        if spare is None:
            spare = self._spawn_sink()
        self._sock, self._proc = spare
        self._outstanding.clear()
        self._counts.clear()
        self._refill_spare()

    def _kill(self) -> None:
        if self._sock is not None:
            # Its peer end holds nothing of the client's: closing ours cannot block.
            self._sock.close()
            self._sock = None
        if self._proc is not None:
            # SIGKILL ends a lingering close; reaping happens off this thread.
            proc, self._proc = self._proc, None
            with contextlib.suppress(OSError):
                proc.kill()
            _reap_async(proc)

    def _settle(self) -> None:
        """Collect "D"s WITHOUT blocking (poll with a zero timeout: the socket itself has a
        timeout, which would make a MSG_DONTWAIT recv wait for it); a sink with work still
        outstanding is presumed wedged and replaced."""
        assert self._sock is not None
        poller = select.poll()
        poller.register(self._sock.fileno(), select.POLLIN)
        while self._outstanding and poller.poll(0):
            try:
                got = self._sock.recv(16)
            except OSError:
                got = b""
            if not self._done(got):
                self._kill()
                return
        # Wedged only if some batch has been outstanding for longer than closing a handful of
        # descriptors can take: a "D" merely not here YET is the normal case on a busy helper,
        # and replacing a healthy sink on it re-forked an interpreter every few requests.
        # (The sink closes each batch on its own thread, so a wedged batch never delays the
        # ACK of the next one -- it is only ever replaced here, never waited for.)
        if (self._outstanding
                and time.monotonic() - min(self._outstanding.values()) > _SINK_GRACE_S):
            self._kill()

    def _done(self, msg: bytes) -> bool:
        """Account a "D<seq>" message; False for anything else (a broken or foreign sink)."""
        if len(msg) != 9 or msg[:1] != b"D":
            return False
        seq = int.from_bytes(msg[1:], "big")
        self._outstanding.pop(seq, None)
        self._counts.pop(seq, None)
        return True

    def release(self, fds: "list[int]") -> None:
        """Take ownership of ``fds``. Never blocks on anything a client controls."""
        todo = [fd for fd in fds if fd >= 0]
        with self._lock:
            failures = 0
            while todo:
                batch = todo[:SCM_MAX_FD]
                try:
                    taken = self._hand_over(batch)
                except Exception:  # noqa: BLE001 - OSError, SubprocessError: try a new sink
                    self._kill()
                    taken = 0
                if taken < len(batch):
                    # The sink did not take all of them (its fd table is full, or it failed):
                    # those copies are still ours, and closing them could be their FINAL
                    # release. Retire this sink and hand the rest to a fresh one.
                    self._kill()
                    # Count only attempts that made NO progress: a full sink still took a
                    # prefix, and the next one takes more.
                    failures = failures + 1 if taken == 0 else 0
                    if failures > 2:
                        _log.error("fc_jail.fd_sink_failed: keeping %d client descriptors",
                                   len(todo) - taken)
                        return
                todo = todo[taken:]

    def _hand_over(self, batch: "list[int]") -> int:
        """Send ``batch``; return how many (a prefix) the sink installed -- those copies are
        closed here, safely, since the sink still holds each one."""
        if self._sock is not None:
            self._settle()
        if self._sock is not None and self._held() + len(batch) > _SINK_MAX_HELD:
            self._kill()            # replace a sink BEFORE its fd table can fill
        if self._sock is None:
            self._start()           # EAGAIN/ENOMEM here must not escape (caller catches)
        assert self._sock is not None
        self._seq += 1
        seq = self._seq
        socket.send_fds(self._sock, [b"F" + seq.to_bytes(8, "big")], batch)
        while True:
            # An earlier batch's "D" may arrive ahead of this batch's "A".
            got = self._sock.recv(16)
            if len(got) == 5 and got[:1] == b"A":
                taken = min(int.from_bytes(got[1:], "big"), len(batch))
                break
            if not self._done(got):
                raise OSError("sink did not acknowledge")
        for fd in batch[:taken]:    # not the last reference: the sink holds them
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            self._sock.send(b"G")
        self._outstanding[seq] = time.monotonic()
        self._counts[seq] = taken
        return taken

    def _held(self) -> int:
        return sum(self._counts.get(q, 0) for q in self._outstanding)

    def close(self) -> None:
        with self._lock:
            self._kill()
            with self._spare_lock:
                self._closed = True
                spare, self._spare = self._spare, None
            if spare is not None:
                spare[0].close()
                with contextlib.suppress(OSError):
                    spare[1].kill()
                _reap_async(spare[1])


def _reap_async(proc: "subprocess.Popen[bytes]") -> None:
    try:
        threading.Thread(target=lambda: proc.wait(), daemon=True, name="fcj-sink-reap").start()
    except RuntimeError:
        # No thread to spare: leave the (SIGKILLed) child for the next poll -- subprocess reaps
        # finished children when new ones are spawned. Never raise into a release.
        with contextlib.suppress(Exception):
            proc.poll()

# --------------------------------------------------------------------------- the helper
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)


class Helper:
    """All privileged state and operations. ``serve()`` runs the socket loop."""

    def __init__(self, cfg: HelperConfig, *,
                 popen: "Callable[..., subprocess.Popen[bytes]]" = subprocess.Popen,
                 run: "Callable[..., subprocess.CompletedProcess[bytes]]" = subprocess.run,
                 apparmor_enabled: "bool | None" = None,
                 proc_root: Path = Path("/proc"),
                 fchown: "Callable[[int, int, int], None]" = os.fchown,
                 lchown: "Callable[[str | Path, int, int], None]" = (
                     lambda p, u, g: os.chown(p, u, g, follow_symlinks=False)),
                 netns_dir: Path = Path("/run/netns")) -> None:
        self.cfg = cfg
        self._fchown = fchown
        self._lchown = lchown
        self._netns_dir = netns_dir
        self._popen = popen
        self._run = run
        self._proc_root = proc_root
        self._lock = threading.RLock()
        self._owners: dict[int, Owner] = {}
        self._jails: dict[str, Jail] = {}
        self._gens: dict[str, Gen] = {}
        self._assets: dict[str, Asset] = {}
        # STRIPED, bounded: a lock per asset identity would grow with every distinct file a
        # client ever registers.
        self._asset_locks = [threading.Lock() for _ in range(64)]
        self._peer_conns: dict[int, int] = {}
        self._uids = UidPool(cfg.uid_min, cfg.uid_max)
        self._stop = threading.Event()
        self._sink = FdSink()
        if apparmor_enabled is None:
            apparmor_enabled = _apparmor_enabled()
        if cfg.apparmor == "require" and not apparmor_enabled:
            raise RuntimeError("apparmor=require but AppArmor is not enabled on this kernel")
        self.apparmor = cfg.apparmor != "off" and apparmor_enabled
        self.fc_version = ""

    # ------------------------------------------------------------------ startup
    def prepare_host(self) -> None:
        """Verify binaries, create the state tree and cgroup parent, and remove anything a
        previous helper instance left behind (its clients' handles died with it)."""
        for label, path in (("firecracker", self.cfg.firecracker), ("jailer", self.cfg.jailer),
                            ("setpriv", self.cfg.setpriv), ("ip", self.cfg.ip),
                            ("mkfs.ext4", self.cfg.mkfs)):
            _check_root_owned_exec(label, path)
        if self.apparmor:
            _check_root_owned_exec("apparmor_parser", self.cfg.apparmor_parser)
        self.fc_version = _version(self._run, self.cfg.firecracker)
        # Enforced HERE, not only by each dispatcher at its own start: a helper restarted with
        # an older binary must not serve the dispatchers already running against it.
        if tuple(int(x) for x in self.fc_version.split(".")) < MIN_FC_VERSION:
            raise RuntimeError(f"firecracker {self.fc_version} is older than "
                               f"{'.'.join(map(str, MIN_FC_VERSION))} (guest-reachable "
                               f"virtio-rng host-memory DoS)")
        if not Path("/dev/kvm").exists():
            raise RuntimeError("/dev/kvm is missing: no hardware virtualisation on this host")
        self._prepare_state_tree()
        self._setup_cgroups()

    def _prepare_state_tree(self) -> None:
        base = self.cfg.chroot_base
        base.mkdir(parents=True, exist_ok=True)
        _check_root_dir(base)
        # ROOT-ONLY, like everything under it: asset copies and generations are 0444 for the
        # jails (which reach them through hard links in their own roots, never through these
        # directories), and a private 0600 rootfs must not become readable host-wide.
        os.chmod(base, 0o700)
        self.cleanup_leftovers()
        for d in (self.cfg.assets_dir, self.cfg.gens_dir, self.cfg.bin_dir):
            d.mkdir(mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
        # The binary every jail gets a hard link of (same filesystem as the jail tree, so the
        # per-jail exec-file name costs one link, not a copy).
        master = self.cfg.bin_dir / "firecracker"
        tmp = self.cfg.bin_dir / ".firecracker.tmp"
        tmp.unlink(missing_ok=True)
        shutil.copyfile(self.cfg.firecracker, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, master)

    def _setup_cgroups(self) -> None:
        cfg = self.cfg
        if not cfg.cgroup_parent_rel:
            raise RuntimeError("cgroup parent not configured")
        parent = cfg.cgroup_root / cfg.cgroup_parent_rel
        parent.mkdir(parents=True, exist_ok=True)
        # Every level from the delegated root down needs the controllers enabled.
        _enable_controllers(parent.parent)
        _enable_controllers(parent)
        limit = cfg.jails_memory_max or _default_memory_cap()
        (parent / "memory.max").write_text(str(limit))
        _log.info("fc_jail.cgroup parent=%s memory.max=%d", parent, limit)
        sup = parent.parent / "supervisor"
        if sup.is_dir():
            # The helper and its fd sinks: a client forcing sink replacements (each a fresh
            # interpreter) must not take more than this much root CPU from the microVMs.
            with contextlib.suppress(OSError):
                (sup / "cpu.max").write_text("200000 100000")

    def cleanup_leftovers(self) -> None:
        """Remove what a previous instance of THIS helper left: its jail cgroups, trees, and the
        network namespaces and AppArmor profiles named after those trees' jail ids. Keyed off
        its own --chroot-base, never a global pattern, so a second helper instance on the host
        (another chroot base) is not touched."""
        base = self.cfg.chroot_base
        parent = (self.cfg.cgroup_root / self.cfg.cgroup_parent_rel
                  if self.cfg.cgroup_parent_rel else None)
        if parent is not None and parent.is_dir():
            for leaf in parent.iterdir():
                if leaf.is_dir() and JAIL_ID_RE.match(leaf.name):
                    _kill_cgroup(str(leaf))
        entries = list(base.iterdir()) if base.is_dir() else []
        loaded = set(_loaded_profiles()) if self.apparmor else set()
        for entry in entries:
            jail_id = entry.name[len("firecracker-"):] if entry.name.startswith("firecracker-") else ""
            if JAIL_ID_RE.match(jail_id):
                if (self._netns_dir / f"bbfcj-{jail_id}").exists():
                    self._run([self.cfg.ip, "netns", "del", f"bbfcj-{jail_id}"],
                              capture_output=True, check=False, timeout=10)
                if profile_name(jail_id) in loaded:
                    _remove_profile(profile_name(jail_id))
            if entry.name.startswith("firecracker-") or entry.name in ("gens", "assets"):
                shutil.rmtree(entry, ignore_errors=True)

    # ------------------------------------------------------------------ owners
    def owner_for(self, pid: int, pidfd: int) -> Owner:
        """The owner record for a connected process. A record whose process has exited is
        reaped first, so a recycled pid is a NEW owner with nothing."""
        with self._lock:
            known = self._owners.get(pid)
            if known is not None and not _pidfd_exited(known.pidfd):
                os.close(pidfd)
                return known
            # Get-or-create under ONE lock: two first connections from the same process must
            # not each build an Owner (the loser's jails would never be reaped).
            if len(self._owners) >= self.cfg.max_owners and known is None:
                os.close(pidfd)
                raise HelperError("exhausted", "too many client processes")
            owner = Owner(pid=pid, pidfd=pidfd)
            self._owners[pid] = owner
            if known is not None:
                known.dead = True         # its objects are unreachable from now on
        if known is not None:
            self._reap(known)
        return owner

    def reap_owner(self, owner: Owner) -> None:
        """Kill and destroy everything a dead owner held."""
        with self._lock:
            if owner.dead:
                return
            owner.dead = True
            if self._owners.get(owner.pid) is owner:
                del self._owners[owner.pid]
        self._reap(owner)

    def _reap(self, owner: Owner) -> None:
        with self._lock:
            jails = [self._jails[j] for j in owner.jails if j in self._jails]
            gens = list(owner.gens)
        _log.warning("fc_jail.owner_gone pid=%d jails=%d gens=%d", owner.pid, len(jails), len(gens))
        for jail in jails:
            with contextlib.suppress(Exception):
                self._kill_and_wait(jail, timeout=5.0)
            try:
                self._destroy(jail, wait=False)
            except Exception as exc:  # noqa: BLE001 - retried by the monitor
                _log.error("fc_jail.reap_destroy_failed jail=%s: %s", jail.id, exc)
        for gid in gens:
            with contextlib.suppress(Exception):
                self._discard(gid)
        with self._lock:
            pins = list(owner.assets)
            owner.assets.clear()
        for aid in pins:
            self._unpin_asset(aid)
        with contextlib.suppress(OSError):
            os.close(owner.pidfd)

    def monitor_once(self) -> None:
        with self._lock:
            owners = list(self._owners.values())
            jails = list(self._jails.values())
        for owner in owners:
            if _pidfd_exited(owner.pidfd):
                self.reap_owner(owner)
        with self._lock:
            stale = [g for g in self._gens.values() if g.retired and not g.refs]
            loose = [a for a, x in self._assets.items()
                     if x.refs <= 0 and not self._asset_pinned(a)]
        for gen in stale:
            self._remove_gen(gen)         # a previous removal failed: retry it
        for aid in loose:
            self._maybe_drop_asset(aid)   # a drop skipped while its stripe was busy
        for jail in jails:
            if jail.proc is not None:
                jail.proc.poll()          # reap the zombie promptly
            # RETRY teardown nobody else can ask for: a dead owner's jail (its owner record is
            # gone, so no client can destroy it) or a failed spawn's (the client got an error and
            # never learned it exists). Without this a single failed destroy strands its uid, its
            # disk and its generation reference for the life of the helper.
            if not jail.destroyed and (jail.owner.dead or jail.orphaned):
                with contextlib.suppress(Exception):
                    if self._kill_and_wait(jail, timeout=1.0):
                        self._destroy(jail, wait=False)

    # ------------------------------------------------------------------ dispatch
    def handle(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        op = req["op"]
        fn = getattr(self, f"op_{op}")
        return fn(owner, req, fds)  # type: ignore[no-any-return]

    def _jail_of(self, owner: Owner, jail_id: str) -> Jail:
        with self._lock:
            jail = self._jails.get(jail_id)
        # The SAME answer for "no such jail" and "someone else's jail": an owner must not be
        # able to probe which ids other dispatchers are using.
        # By OBJECT, not pid: a dead owner's pid can be recycled by a new process before the
        # monitor reaps it, and that process must not inherit the old one's microVMs.
        if jail is None or jail.owner is not owner or owner.dead or jail.destroyed:
            raise HelperError("unknown_jail", jail_id)
        return jail

    # ------------------------------------------------------------------ ops
    def op_hello(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        return {"protocol": PROTOCOL_VERSION, "firecracker": self.fc_version,
                "apparmor": self.apparmor, "ready_port": READY_PORT}, []

    def op_asset(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        st = os.fstat(fds[0])
        if not stat.S_ISREG(st.st_mode):
            raise HelperError("bad_asset", "not a regular file")
        if st.st_size <= 0 or st.st_size > self.cfg.max_asset_bytes:
            raise HelperError("bad_asset", f"size {st.st_size} out of range")
        flags = fcntl.fcntl(fds[0], fcntl.F_GETFL)
        if flags & os.O_PATH or flags & os.O_ACCMODE == os.O_WRONLY:
            raise HelperError("bad_asset", "the descriptor is not open for reading")
        key = identity(st)
        kind = req["kind"]
        aid = "a" + hashlib.sha256(repr((kind, key)).encode()).hexdigest()[:32]
        # PER ASSET, not helper-wide: one client's slow (or deliberately stalled) copy must not
        # hold every other dispatcher's registration hostage.
        evicted: "str | None" = None
        with self._asset_locks[int(aid[1:9], 16) % len(self._asset_locks)]:
            with self._lock:
                existing = self._assets.get(aid)
            if existing is None:
                # Read through the CLIENT's own descriptor (positioned reads only, so its offset
                # is untouched). Reopening it via /proc/self/fd would make a new description
                # with ROOT credentials -- files whose content depends on the opener (sysfs PCI
                # config) would then hand root-only bytes to the client.
                existing = self._copy_asset(aid, kind, fds[0], st, key)
            # PIN while still holding the stripe: the monitor's sweep drops any unreferenced,
            # unpinned asset whose stripe it can take, and would otherwise catch this one
            # between its registration and its pin.
            with self._lock:
                # Reaped while the copy ran: pinning to a dead owner would keep the copy forever.
                dead = owner.dead
                if not dead and aid not in owner.assets:
                    if len(owner.assets) == owner.assets.maxlen:
                        evicted = owner.assets[0]
                    owner.assets.append(aid)
        # Outside the state lock (dropping takes the asset's stripe lock first).
        if evicted is not None:
            self._maybe_drop_asset(evicted)
        if dead:
            self._maybe_drop_asset(aid)
            raise HelperError("unknown_jail", "client process is gone")
        return {"asset": aid, "identity": list(key)}, []

    def _copy_asset(self, aid: str, kind: str, src: int, st: os.stat_result,
                    key: "tuple[int, int, int, int]") -> Asset:
        # Plain strings: pathlib interns every component (immortal in 3.12), and these names are
        # client-driven -- one per distinct file registered.
        base = str(self.cfg.assets_dir)
        path = os.path.join(base, aid)
        tmp = os.path.join(base, f".{aid}.{secrets.token_hex(4)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            try:
                # Hole-preserving (a sparse multi-GiB rootfs must not expand onto a tmpfs chroot
                # base). sparse_copy seeks, and src is the CLIENT's description, so put its
                # offset back (the client is blocked on this request and opened it privately).
                pos = os.lseek(src, 0, os.SEEK_CUR)
                try:
                    sparse_copy(src, fd, st.st_size,
                                deadline=time.monotonic() + self.cfg.copy_timeout_s)
                finally:
                    os.lseek(src, pos, os.SEEK_SET)
                if identity(os.fstat(src)) != key:
                    raise HelperError("bad_asset", "the file changed while it was copied")
                os.fchmod(fd, 0o444)
            finally:
                os.close(fd)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        asset = Asset(id=aid, kind=kind, path=path, key=key)
        with self._lock:
            self._assets[aid] = asset
        return asset

    def _asset_pinned(self, aid: str) -> bool:
        return any(aid in o.assets for o in self._owners.values())

    def _maybe_drop_asset(self, aid: str) -> None:
        # Under the asset's stripe lock, like registration: otherwise a registration of the
        # same file could recreate the path between our registry removal and the unlink, and
        # the unlink would delete the NEW copy out from under its pinned entry.
        # NON-blocking: a registration can hold the stripe for a whole copy (up to the copy
        # timeout) and callers include the monitor; an unreferenced asset left behind is swept
        # by the monitor on a later tick.
        stripe = self._asset_locks[int(aid[1:9], 16) % len(self._asset_locks)]
        if not stripe.acquire(blocking=False):
            return
        try:
            with self._lock:
                asset = self._assets.get(aid)
                if (asset is None or asset.refs > 0 or asset.dropping
                        or self._asset_pinned(aid)):
                    return
                asset.dropping = True       # spawns now treat it as gone
            try:
                os.unlink(asset.path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                # Still TRACKED (and retried by the monitor's sweep): forgetting it now would
                # strand a file of up to max_asset_bytes that nothing could ever reclaim.
                _log.error("fc_jail.asset_unlink_failed asset=%s: %s (retried)", aid, exc)
                with self._lock:
                    asset.dropping = False
                return
            with self._lock:
                if self._assets.get(aid) is asset:
                    del self._assets[aid]
        finally:
            stripe.release()

    def _unpin_asset(self, aid: str) -> None:
        self._maybe_drop_asset(aid)

    def op_spawn(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail_id = req["jail"]
        mode = req["mode"]
        cfg = self.cfg
        with self._lock:
            if owner.dead:
                # Reaped while this request was in flight: a jail registered now would belong to
                # an owner nothing watches any more.
                raise HelperError("unknown_jail", jail_id)
            if jail_id in self._jails:
                raise HelperError("exists", jail_id)
            if len(self._jails) >= cfg.max_jails:
                raise HelperError("exhausted", "helper jail limit reached")
            if len(owner.jails) >= cfg.max_jails_per_owner:
                raise HelperError("exhausted", "per-owner jail limit reached")
            gen: "Gen | None" = None
            assets: list[str] = []
            if mode == "boot":
                if req["gen"] is not None or req["kernel"] is None or req["rootfs"] is None:
                    raise HelperError("bad_request", "boot takes kernel+rootfs and no gen")
                for aid, kind in ((req["kernel"], "kernel"), (req["rootfs"], "rootfs")):
                    asset = self._assets.get(aid)
                    if (asset is None or asset.kind != kind or asset.dropping
                            or aid not in owner.assets):
                        raise HelperError("unknown_asset", aid)
                    assets.append(aid)
                mem_mib = req["mem_mib"]
            else:
                if req["gen"] is None or req["kernel"] is not None or req["rootfs"] is not None:
                    raise HelperError("bad_request", "restore takes a gen and no assets")
                gen = self._gens.get(req["gen"])
                if gen is None or gen.owner is not owner or gen.retired:
                    raise HelperError("unknown_gen", req["gen"])
                assets.append(gen.rootfs)
                mem_mib = max(req["mem_mib"], (gen.mem_bytes + (1 << 20) - 1) >> 20)
            # The uid FIRST: exhaustion raises, and must not leave the reference counts below
            # incremented with no jail to ever release them.
            uid = self._uids.take()
            for aid in assets:
                self._assets[aid].refs += 1
            name = exec_name(jail_id)
            top = _jp(str(cfg.chroot_base), name)
            jail = Jail(
                id=jail_id, owner=owner, uid=uid, mode=mode, top=top,
                root=_jp(top, jail_id, "root"), netns=f"bbfcj-{jail_id}",
                cgroup=_jp(str(cfg.cgroup_root), cfg.cgroup_parent_rel, jail_id),
                mem_mib=mem_mib, gen=gen.id if gen else None, assets=assets,
            )
            if gen is not None:
                gen.refs.add(jail_id)
            self._jails[jail_id] = jail
            owner.jails.add(jail_id)
        try:
            listener_fd = self._start(jail, req, gen)
        except BaseException:
            # _start only returns the listener on success; on failure it closed it itself.
            jail.spawning = False
            jail.orphaned = True
            with contextlib.suppress(Exception):
                self._kill_and_wait(jail, timeout=5.0)
            with contextlib.suppress(Exception):
                self._destroy(jail)
            raise
        return {"jail": jail_id}, ([listener_fd] if listener_fd is not None else [])

    def _start(self, jail: Jail, req: "dict[str, Any]", gen: "Gen | None") -> "int | None":
        cfg = self.cfg
        # STAGE as root before anything runs as the jail uid: the jail dirs, the per-jail
        # binary name, the drives and (optionally) the READY listener.
        os.mkdir(jail.top, 0o700)
        os.mkdir(_jp(jail.top, jail.id), 0o700)
        os.mkdir(jail.root, 0o700)
        exec_src = _jp(str(cfg.bin_dir), exec_name(jail.id))
        with contextlib.suppress(FileNotFoundError):
            os.unlink(exec_src)
        os.link(_jp(str(cfg.bin_dir), "firecracker"), exec_src)
        root_fd = os.open(jail.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if jail.mode == "boot":
                kernel = self._assets[jail.assets[0]]
                rootfs = self._assets[jail.assets[1]]
                os.link(kernel.path, JAIL_KERNEL, dst_dir_fd=root_fd)
                os.link(rootfs.path, JAIL_ROOTFS, dst_dir_fd=root_fd)
                out_fd = os.open(JAIL_OUTDISK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                 0o600, dir_fd=root_fd)
                try:
                    os.ftruncate(out_fd, req["outdisk_mib"] << 20)
                    self._run([cfg.mkfs, "-q", "-F", "-O", "^has_journal,^metadata_csum",
                               "-m", "0", f"/proc/self/fd/{out_fd}"], check=True,
                              capture_output=True, timeout=cfg.copy_timeout_s,
                              pass_fds=(out_fd,))
                    self._fchown(out_fd, jail.uid, jail.uid)
                finally:
                    os.close(out_fd)
            else:
                assert gen is not None
                rootfs = self._assets[jail.assets[0]]
                os.link(rootfs.path, JAIL_ROOTFS, dst_dir_fd=root_fd)
                gen_fd = os.open(gen.dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    for name in (JAIL_SNAPSHOT, JAIL_MEM):
                        os.link(name, name, src_dir_fd=gen_fd, dst_dir_fd=root_fd)
                    src = os.open(JAIL_OUTDISK, os.O_RDONLY | os.O_CLOEXEC, dir_fd=gen_fd)
                    try:
                        out_fd = os.open(JAIL_OUTDISK, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                         | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
                        try:
                            sparse_copy(src, out_fd, os.fstat(src).st_size,
                                        deadline=time.monotonic() + cfg.copy_timeout_s)
                            self._fchown(out_fd, jail.uid, jail.uid)
                        finally:
                            os.close(out_fd)
                    finally:
                        os.close(src)
                finally:
                    os.close(gen_fd)
            # Held from staging: every later read of the output disk goes through THIS inode, not
            # through a name the jail uid can replace.
            jail.outdisk_fd = os.open(JAIL_OUTDISK, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                      dir_fd=root_fd)
            jail.outdisk_bytes = os.fstat(jail.outdisk_fd).st_size
        finally:
            os.close(root_fd)
        listener_fd: "int | None" = None
        if req["ready_listener"]:
            # Bound by the helper in the jail root, owned by the jail uid (firecracker must be
            # able to connect), and handed to the client: the client never needs a path into
            # the jail. AppArmor mediates this connect by the HOST path (see render_profile).
            path = _jp(jail.root, f"{JAIL_VSOCK}_{READY_PORT}")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # Through a directory fd: the full host path is ~108 bytes plus the chroot base,
            # past the AF_UNIX limit. The socket's path (what AppArmor mediates) is still the
            # real host path.
            dir_fd = os.open(jail.root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                sock.bind(f"/proc/self/fd/{dir_fd}/{JAIL_VSOCK}_{READY_PORT}")
            except BaseException:
                sock.close()
                raise
            finally:
                os.close(dir_fd)
            # The jail root is still root:0700 here (nothing has run as the jail uid yet), so
            # these path operations cannot be redirected.
            self._lchown(path, jail.uid, jail.uid)
            os.chmod(path, 0o600)
            sock.listen(16)
            jail.listener_path = path
            # Handed over, not kept: the reply path closes the descriptor it sends, so the
            # helper owning it too would double-close a reused fd number.
            listener_fd = sock.detach()
        try:
            self._run([cfg.ip, "netns", "add", jail.netns], check=True, capture_output=True,
                      timeout=10)
            if self.apparmor:
                jail.profile = profile_name(jail.id)
                text = render_profile(cfg, jail.id, boot=jail.mode == "boot",
                                      listener_host_path=str(jail.listener_path)
                                      if jail.listener_path else None)
                self._run([cfg.apparmor_parser, "-r", "-K", "-q"], input=text.encode(),
                          check=True, capture_output=True, timeout=30)
            cgroups = {
                "memory.max": str(_jail_memory_max(jail, cfg.jail_mem_overhead_mib)),
                "memory.swap.max": "0",
                "pids.max": str(cfg.jail_pids_max),
                # One CPU per vCPU thread PLUS one for the VMM's own threads (device emulation,
                # API): vcpus alone throttles the I/O path of a guest using every vCPU.
                "cpu.max": f"{(req['vcpus'] + 1) * 100000} 100000",
            }
            argv = jailer_argv(cfg, jail.id, jail.uid, exec_file=exec_src, cgroups=cgroups,
                               netns_path=_jp(str(self._netns_dir), jail.netns),
                           fsize=max(jail.outdisk_bytes, (jail.mem_mib << 20) + (1 << 20)))
            proc = self._popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env={}, cwd="/", close_fds=True,
                               start_new_session=True)
            jail.proc = proc
            jail.spawning = False
            # Unreaped (we hold the Popen), so the pid cannot be reused yet: _signal falls back
            # to it if this pidfd_open fails, and the failed spawn's cleanup can still kill it.
            jail.pidfd = os.pidfd_open(proc.pid)
            threading.Thread(target=_drain, args=(proc, jail.log), daemon=True,
                             name=f"fcj-log-{jail.id[:8]}").start()
            self._wait_api(jail)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(exec_src)
            _log.info("fc_jail.spawned jail=%s mode=%s uid=%d pid=%d", jail.id, jail.mode, jail.uid,
                      proc.pid)
        except BaseException:
            if listener_fd is not None:
                os.close(listener_fd)
            raise
        return listener_fd

    def _wait_api(self, jail: Jail) -> None:
        deadline = time.monotonic() + self.cfg.spawn_timeout_s
        while time.monotonic() < deadline:
            if jail.exited():
                raise HelperError("spawn_failed", f"jailer/firecracker exited: {_tail(jail)}")
            with contextlib.suppress(OSError):
                pfd = self._jail_socket(jail, JAIL_API_SOCK)
                if pfd is not None:
                    os.close(pfd)
                    return
            time.sleep(0.005)
        raise HelperError("spawn_failed", f"API socket did not appear: {_tail(jail)}")

    def _jail_socket(self, jail: Jail, name: str) -> "int | None":
        """An O_PATH fd on the jail's socket ``name``, if it is a socket the JAIL UID owns.
        Opened from a directory fd with O_NOFOLLOW: the jail owns its root and can plant a
        symlink there (to a host socket such as docker's) -- following it would hand the client
        a root-opened connection to anything on the host."""
        root_fd = os.open(jail.root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                pfd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            except FileNotFoundError:
                return None
        finally:
            os.close(root_fd)
        st = os.fstat(pfd)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != jail.uid:
            os.close(pfd)
            return None
        return pfd

    def op_connect(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        if jail.exited():
            raise HelperError("exited", jail.id)
        name = JAIL_API_SOCK if req["target"] == "api" else JAIL_VSOCK
        pfd = self._jail_socket(jail, name)
        if pfd is None:
            raise HelperError("no_socket", name)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(5.0)
            # Through the O_PATH fd: the kernel resolves the magic link to the inode we checked.
            sock.connect(f"/proc/self/fd/{pfd}")
            sock.settimeout(None)
        except OSError as exc:
            sock.close()
            raise HelperError("connect_failed", f"{name}: {exc.strerror}") from exc
        finally:
            os.close(pfd)
        return {}, [sock.detach()]

    def op_status(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        rc = jail.proc.poll() if jail.proc is not None else -1
        vsock = False
        if rc is None:
            with contextlib.suppress(OSError):
                pfd = self._jail_socket(jail, JAIL_VSOCK)
                if pfd is not None:
                    os.close(pfd)
                    vsock = True
        out: dict[str, Any] = {"returncode": rc, "vsock": vsock, "sealed": jail.sealed}
        if rc is not None:
            out["log"] = _tail(jail)
        return out, []

    def op_signal(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        self._signal(jail, SIGNALS[req["sig"]])
        return {}, []

    def op_seal(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        if jail.exited() or jail.proc is None:
            raise HelperError("exited", jail.id)
        # A vCPU thread installs its seccomp filter as it starts, so a seal racing the last
        # thread's start can see it unfiltered for an instant: re-check briefly before refusing.
        deadline = time.monotonic() + 2.0
        while True:
            problems = self.verify_confinement(jail.proc.pid, jail.profile)
            if not problems or time.monotonic() >= deadline or jail.exited():
                break
            time.sleep(0.05)
        if problems:
            _log.error("fc_jail.seal_refused jail=%s: %s", jail.id, problems)
            with contextlib.suppress(Exception):
                self._kill_and_wait(jail, timeout=5.0)
            raise HelperError("unconfined", "; ".join(problems))
        jail.sealed = True
        return {}, []

    def verify_confinement(self, pid: int, profile: "str | None" = None) -> "list[str]":
        """What is wrong with the confinement of every thread of ``pid`` ([] = nothing)."""
        problems: list[str] = []
        task_dir = self._proc_root / str(pid) / "task"
        want_bnd = bounding_mask(self.cfg.bounding_caps)
        try:
            tids = sorted(task_dir.iterdir())
        except OSError as exc:
            return [f"cannot read {task_dir}: {exc}"]
        if not tids:
            return ["no threads"]
        for tid in tids:
            try:
                fields = _status_fields((tid / "status").read_text())
            except OSError as exc:
                problems.append(f"tid {tid.name}: {exc}")
                continue
            if fields.get("Seccomp") != "2":
                problems.append(f"tid {tid.name}: Seccomp={fields.get('Seccomp')}")
            if fields.get("NoNewPrivs") != "1":
                problems.append(f"tid {tid.name}: NoNewPrivs={fields.get('NoNewPrivs')}")
            for capf in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
                if int(fields.get(capf, "1"), 16) != 0:
                    problems.append(f"tid {tid.name}: {capf}={fields.get(capf)}")
            bnd = int(fields.get("CapBnd", "f" * 16), 16)
            if bnd & ~want_bnd:
                problems.append(f"tid {tid.name}: CapBnd={fields.get('CapBnd')}")
            uid = fields.get("Uid", "").split()
            if not uid or "0" in uid:
                problems.append(f"tid {tid.name}: Uid={fields.get('Uid')}")
        if self.apparmor:
            try:
                label = (self._proc_root / str(pid) / "attr" / "current").read_text().strip()
            except OSError as exc:
                label = f"<{exc}>"
            if label.split(" (")[0] != profile:
                problems.append(f"apparmor label {label!r}, want {profile!r}")
        return problems

    def op_outdisk(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        # UNDER the jail lock: _destroy closes outdisk_fd under it, and a number closed between
        # the size check and the /proc reopen could be reused by another owner's file.
        with jail.lock:
            if jail.destroyed or jail.outdisk_fd is None:
                raise HelperError("no_outdisk", jail.id)
            return self._outdisk_locked(jail)

    def _outdisk_locked(self, jail: Jail) -> "tuple[dict[str, Any], list[int]]":
        assert jail.outdisk_fd is not None
        st = os.fstat(jail.outdisk_fd)
        if st.st_size != jail.outdisk_bytes:
            # A compromised VMM grew (or shrank) the image past what was staged: never hand the
            # client an unbounded copy of a jail-controlled size.
            raise HelperError("bad_outdisk", f"size {st.st_size} != staged {jail.outdisk_bytes}")
        # A fresh description: the client's reads must not share an offset with ours.
        fd = os.open(f"/proc/self/fd/{jail.outdisk_fd}", os.O_RDONLY | os.O_CLOEXEC)
        return {"size": st.st_size}, [fd]

    def op_publish(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        """Turn an EXITED boot jail's snapshot into a root-owned, read-only generation."""
        jail = self._jail_of(owner, req["jail"])
        if jail.mode != "boot":
            raise HelperError("bad_request", "only a boot jail can be published")
        # The VMM must be GONE, and so must anything else in its cgroup: a live process could
        # keep a writable descriptor on the memory file and rewrite it under every restore.
        if not jail.exited():
            raise HelperError("alive", "kill the base before publishing it")
        if _cgroup_populated(jail.cgroup):
            raise HelperError("alive", "the jail cgroup still has processes")
        with self._lock:
            live = sum(1 for g in owner.gens if g in self._gens and not self._gens[g].retired)
            # RESERVE under the same lock: concurrent publishes each counting "live" before any
            # registered would all pass the cap.
            if live + owner.publishing >= self.cfg.max_gens_per_owner:
                raise HelperError("exhausted", "too many live generations; discard one first")
            owner.publishing += 1
        try:
            with jail.lock:              # outdisk_fd must not be closed by a racing destroy
                if jail.destroyed:
                    raise HelperError("unknown_jail", jail.id)
                return self._publish(owner, jail)
        finally:
            with self._lock:
                owner.publishing -= 1

    def _publish(self, owner: Owner, jail: Jail) -> "tuple[dict[str, Any], list[int]]":
        gid = "g" + secrets.token_hex(16)
        gdir = _jp(str(self.cfg.gens_dir), gid)
        os.mkdir(gdir, 0o700)
        mem_bytes = 0
        try:
            root_fd = os.open(jail.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            gen_fd = os.open(gdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for name, cap in ((JAIL_SNAPSHOT, self.cfg.max_snapshot_bytes),
                                  (JAIL_MEM, (jail.mem_mib << 20) + (1 << 20))):
                    st = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if (not stat.S_ISREG(st.st_mode) or st.st_uid != jail.uid
                            or st.st_nlink != 1 or not (0 < st.st_size <= cap)):
                        raise HelperError("bad_snapshot", f"{name}: unexpected file")
                    os.rename(name, name, src_dir_fd=root_fd, dst_dir_fd=gen_fd)
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gen_fd)
                    try:
                        moved = os.fstat(fd)
                        if (moved.st_dev, moved.st_ino) != (st.st_dev, st.st_ino):
                            raise HelperError("bad_snapshot", f"{name} changed while published")
                        self._fchown(fd, 0, 0)
                        os.fchmod(fd, 0o444)
                    finally:
                        os.close(fd)
                    if name == JAIL_MEM:
                        mem_bytes = st.st_size
                # The snapshot-time ext4 image, frozen WITH the memory it matches (the guest's
                # cached ext4 metadata lives in that memory) -- copied from the inode held since
                # staging, never re-resolved through the jail.
                assert jail.outdisk_fd is not None
                dst = os.open(JAIL_OUTDISK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                              0o444, dir_fd=gen_fd)
                try:
                    sparse_copy(jail.outdisk_fd, dst, os.fstat(jail.outdisk_fd).st_size,
                                deadline=time.monotonic() + self.cfg.copy_timeout_s)
                finally:
                    os.close(dst)
            finally:
                os.close(root_fd)
                os.close(gen_fd)
        except BaseException:
            shutil.rmtree(gdir, ignore_errors=True)
            raise
        with self._lock:
            if owner.dead:
                shutil.rmtree(gdir, ignore_errors=True)
                raise HelperError("unknown_jail", jail.id)
            rootfs = jail.assets[1]
            self._assets[rootfs].refs += 1
            self._gens[gid] = Gen(id=gid, owner=owner, dir=gdir, rootfs=rootfs,
                                  mem_bytes=mem_bytes)
            owner.gens.add(gid)
        _log.info("fc_jail.published gen=%s from=%s mem=%d", gid, jail.id, mem_bytes)
        return {"gen": gid, "dir": gdir}, []

    def op_destroy(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        jail = self._jail_of(owner, req["jail"])
        if not jail.exited():
            raise HelperError("alive", "signal and wait for the jail before destroying it")
        self._destroy(jail)
        return {}, []

    def op_discard(self, owner: Owner, req: "dict[str, Any]", fds: "list[int]") -> "tuple[dict[str, Any], list[int]]":
        with self._lock:
            gen = self._gens.get(req["gen"])
            if gen is None or gen.owner is not owner:
                raise HelperError("unknown_gen", req["gen"])
        self._discard(gen.id)
        return {}, []

    # ------------------------------------------------------------------ teardown
    def _kill_and_wait(self, jail: Jail, *, timeout: float) -> bool:
        if jail.exited():
            return True
        self._signal(jail, signal.SIGKILL)
        if jail.proc is None:
            return False
        try:
            jail.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return True

    @staticmethod
    def _signal(jail: Jail, sig: int) -> None:
        with jail.pidfd_lock:
            if jail.exited():
                return
            if jail.pidfd is not None:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(jail.pidfd, sig)
            elif jail.proc is not None and jail.proc.returncode is None:
                # No pidfd (its open failed): the child is still ours and unreaped, so its pid
                # is not reusable and Popen's signal is safe.
                with contextlib.suppress(ProcessLookupError):
                    jail.proc.send_signal(sig)

    def _destroy(self, jail: Jail, *, wait: bool = True) -> None:
        """Remove every trace of an EXITED jail. Idempotent; raises if something is left that
        could still hold the jail's resources (then nothing is released, and it is retried).

        ``wait=False`` (the monitor and owner reaping): a jail whose lock is held -- a publish
        copying its disk, for up to the copy timeout -- is skipped and retried next tick, so
        one owner's slow publish cannot stall every other owner's reaping."""
        if not jail.lock.acquire(blocking=wait):
            raise HelperError("busy", f"{jail.id} is in use; retried")
        try:
            self._destroy_locked(jail)
        finally:
            jail.lock.release()

    def _destroy_locked(self, jail: Jail) -> None:
        if jail.destroyed:
            return
        if not jail.exited():
            raise HelperError("alive", jail.id)
        if _cgroup_populated(jail.cgroup):
            _kill_cgroup(jail.cgroup)
            if _cgroup_populated(jail.cgroup):
                raise HelperError("alive", f"{jail.id}: cgroup still populated")
        with contextlib.suppress(FileNotFoundError):
            os.rmdir(jail.cgroup)
        if jail.outdisk_fd is not None:
            os.close(jail.outdisk_fd)
            jail.outdisk_fd = None
        with jail.pidfd_lock:
            if jail.pidfd is not None:
                os.close(jail.pidfd)
                jail.pidfd = None
        if jail.profile is not None:
            _remove_profile(jail.profile)
            jail.profile = None
        self._run([self.cfg.ip, "netns", "del", jail.netns], capture_output=True,
                  check=False, timeout=10)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_jp(str(self.cfg.bin_dir), exec_name(jail.id)))
        errs: list[str] = []
        if os.path.lexists(jail.top):
            shutil.rmtree(jail.top, onerror=lambda fn, p, exc: errs.append(str(p)))
        if errs:
            raise HelperError("cleanup_failed", ", ".join(errs[:3]))
        jail.destroyed = True
        with self._lock:
            self._jails.pop(jail.id, None)
            jail.owner.jails.discard(jail.id)
            for aid in jail.assets:
                if aid in self._assets:
                    self._assets[aid].refs -= 1
            gen = self._gens.get(jail.gen) if jail.gen else None
            if gen is not None:
                gen.refs.discard(jail.id)
            drop_gen = gen is not None and gen.retired and not gen.refs
        self._uids.give(jail.uid)
        for aid in jail.assets:
            self._maybe_drop_asset(aid)
        if drop_gen and gen is not None:
            self._remove_gen(gen)
        _log.info("fc_jail.destroyed jail=%s", jail.id)

    def _discard(self, gid: str) -> None:
        with self._lock:
            gen = self._gens.get(gid)
            if gen is None:
                return
            gen.retired = True
            busy = bool(gen.refs)
        if not busy:
            self._remove_gen(gen)

    def _remove_gen(self, gen: Gen) -> None:
        with self._lock:
            if self._gens.get(gen.id) is not gen or gen.refs:
                return
        # The files FIRST: the entry is forgotten only once they are gone, so a transient
        # failure leaves it tracked (retired, ref-less) for the monitor to retry instead of
        # stranding a RAM-sized memory file nothing knows about.
        errs: list[str] = []
        if os.path.lexists(gen.dir):
            shutil.rmtree(gen.dir, onerror=lambda fn, p, exc: errs.append(str(p)))
        if errs:
            _log.error("fc_jail.gen_remove_failed gen=%s: %s (retried)", gen.id, errs[:3])
            return
        with self._lock:
            if self._gens.get(gen.id) is not gen or gen.refs:
                return
            del self._gens[gen.id]
            gen.owner.gens.discard(gen.id)
            if gen.rootfs in self._assets:
                self._assets[gen.rootfs].refs -= 1
        self._maybe_drop_asset(gen.rootfs)

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            owners = list(self._owners.values())
        for owner in owners:
            self.reap_owner(owner)

    # ------------------------------------------------------------------ socket loop
    def serve(self, *, ready: "Callable[[], None] | None" = None) -> None:
        cfg = self.cfg
        parent = cfg.socket_path.parent
        if not parent.exists():
            # Ours: make it the dispatcher group's (0750) so the socket can be bind-mounted.
            parent.mkdir(parents=True)
            self._lchown(parent, 0, cfg.socket_gid)
            os.chmod(parent, 0o750)
        # An EXISTING directory is never re-owned or re-moded: it may be shared (/run itself, or
        # another helper instance's), and taking it over would lock its other users out. It is
        # REFUSED instead when anyone but us could replace the socket in it: whoever can would
        # answer every dispatcher in the helper's place.
        _check_owned_dir(parent, os.geteuid())
        # (os.stat: a symlinked directory is judged by what it points at -- its chain was
        # verified node by node just above; a link's own mode is always 0777.)
        if os.stat(parent).st_mode & 0o022:
            # Sticky does not help HERE: in a sticky world-writable directory anyone can take
            # the socket's name while the helper is down (a restart) and answer dispatchers.
            raise RuntimeError(f"{parent} must not be group/other-writable (sticky or not)")
        # Bound, owned and listening under a private name, THEN renamed over the configured
        # path: a dispatcher probing during a restart sees the old socket or the new one, never
        # a root:root (EACCES -- decided, for good) or not-yet-listening one. (Nobody else can
        # write the directory -- checked above -- so the by-path chmod cannot be redirected.)
        prefix = f".{cfg.socket_path.name}."
        for name in os.listdir(parent):
            # Earlier instances' private names (a start that failed before its rename): only
            # this helper can write here, so every such name is ours to sweep.
            if name.startswith(prefix) and name[len(prefix):].isdigit():
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(parent / name)
        tmp = parent / f"{prefix}{os.getpid()}"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            srv.bind(str(tmp))
            self._lchown(tmp, 0, cfg.socket_gid)
            os.chmod(tmp, 0o660)
            srv.listen(_LISTEN_BACKLOG)
            os.rename(tmp, cfg.socket_path)
        except BaseException:
            srv.close()
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise
        srv.settimeout(1.0)
        threading.Thread(target=self._monitor_loop, daemon=True, name="fcj-monitor").start()
        slots = threading.BoundedSemaphore(self.cfg.max_conns)
        _log.info("fc_jail.listening socket=%s apparmor=%s firecracker=%s", cfg.socket_path,
                  self.apparmor, self.fc_version)
        if ready is not None:
            ready()
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = srv.accept()
                except TimeoutError:
                    continue
                except OSError as exc:
                    # EMFILE/ENFILE/ENOMEM: shed load, never fall out of the loop (that would
                    # run shutdown() and kill every tenant's microVMs).
                    _log.error("fc_jail.accept_failed: %s", exc)
                    time.sleep(0.2)
                    continue
                peer = _peer_pid(conn)
                with self._lock:
                    busy_peer = self._peer_conns.get(peer, 0) >= self.cfg.max_conns_per_peer
                    if not busy_peer:
                        self._peer_conns[peer] = self._peer_conns.get(peer, 0) + 1
                if busy_peer or not slots.acquire(blocking=False):
                    if not busy_peer:
                        self._release_peer(peer)
                    # Overloaded: SAY so (the client retries "busy"); a silent close is
                    # indistinguishable from a refused uid. Read the queued request first
                    # (non-blocking: this is the accept thread) so "busy" is what the client
                    # reads; its descriptors and the connection itself go to the sink.
                    taken: list[int] = []
                    with contextlib.suppress(OSError):
                        _, taken, _, _ = socket.recv_fds(conn, MAX_MSG + 1, SCM_MAX_FD,
                                                         socket.MSG_DONTWAIT)
                    with contextlib.suppress(OSError):
                        conn.send(encode({"ok": False, "error": "busy", "detail": "overloaded"}),
                                  socket.MSG_DONTWAIT)
                    self._release_safely([*taken, conn.detach()])
                    continue

                def _run(c: socket.socket = conn, p: int = peer) -> None:
                    try:
                        self.serve_conn(c)
                    finally:
                        slots.release()
                        self._release_peer(p)
                try:
                    threading.Thread(target=_run, daemon=True, name="fcj-conn").start()
                except Exception as exc:  # noqa: BLE001 - "can't start new thread": shed it
                    _log.error("fc_jail.conn_thread_failed: %s", exc)
                    slots.release()
                    self._release_peer(peer)
                    self._release_safely([conn.detach()])
        finally:
            srv.close()
            self._sink.close()

    def _release_safely(self, fds: "list[int]") -> None:
        """FdSink.release from the ACCEPT thread: nothing may escape the loop (an exception
        there ends serve() and main() would shut down every tenant's microVMs)."""
        try:
            self._sink.release(fds)
        except Exception as exc:  # noqa: BLE001
            _log.error("fc_jail.fd_sink_release_failed: %s (descriptors kept)", exc)

    def _release_peer(self, peer: int) -> None:
        with self._lock:
            n = self._peer_conns.get(peer, 0) - 1
            if n > 0:
                self._peer_conns[peer] = n
            else:
                self._peer_conns.pop(peer, None)

    def _monitor_loop(self) -> None:
        while not self._stop.wait(1.0):
            try:
                self.monitor_once()
            except Exception as exc:  # noqa: BLE001 - never let the monitor die
                _log.error("fc_jail.monitor_error: %s", exc)

    def serve_conn(self, conn: socket.socket) -> None:
        fds: list[int] = []
        out_fds: list[int] = []
        try:
            conn.settimeout(10.0)
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, _gid = array.array("i", cred).tolist()
            if uid not in self.cfg.allowed_uids or pid <= 0:
                _log.warning("fc_jail.refused_peer uid=%d pid=%d", uid, pid)
                # Say so: the client must tell "never allowed" from "dropped under load", or a
                # startup gate retries a misconfiguration forever. Its request is TAKEN first
                # (never parsed or acted on; its descriptors go to the sink below): closing
                # with it still queued is an ECONNRESET the client reads INSTEAD of the reply.
                # Waits (briefly) for a request not sent yet: this is the connection's own
                # thread, and the client sends right after connecting.
                with contextlib.suppress(OSError):
                    conn.settimeout(1.0)
                    _, fds, _, _ = socket.recv_fds(conn, MAX_MSG + 1, SCM_MAX_FD)
                with contextlib.suppress(OSError):
                    self._reply(conn, {"ok": False, "error": "forbidden",
                                       "detail": f"uid {uid} is not allowed (--allow-uid)"}, [])
                return
            # Room for the kernel's per-message maximum: descriptors that do not fit are
            # released BY THE KERNEL inside recvmsg, where a lingering socket's close blocks this
            # thread -- every one must be installed so the FdSink can take it.
            data, fds, flags, _ = socket.recv_fds(conn, MAX_MSG + 1, SCM_MAX_FD)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(data) > MAX_MSG:
                self._reply(conn, {"ok": False, "error": "protocol", "detail": "truncated"}, [])
                return
            try:
                req = validate_request(decode(data), len(fds))
            except ProtocolError as exc:
                self._reply(conn, {"ok": False, "error": "protocol", "detail": str(exc)}, [])
                return
            pidfd = _peer_pidfd(conn, pid)
            try:
                owner = self.owner_for(pid, pidfd)
            except HelperError as exc:
                self._reply(conn, {"ok": False, "error": exc.code, "detail": exc.detail}, [])
                return
            try:
                result, out_fds = self.handle(owner, req, fds)
                reply = {"ok": True, **result}
            except HelperError as exc:
                reply = {"ok": False, "error": exc.code, "detail": exc.detail[:2000]}
            except Exception as exc:  # noqa: BLE001 - reported, never crashes the helper
                _log.exception("fc_jail.op_failed op=%s", req.get("op"))
                reply = {"ok": False, "error": "internal", "detail": type(exc).__name__}
            try:
                self._reply(conn, reply, out_fds)
            except OSError:
                if req.get("op") == "spawn" and reply.get("ok"):
                    # The client gave up (timed out, died) before learning the jail exists, so
                    # nothing would ever destroy it: undo the spawn here.
                    self._abandon(owner, req["jail"])
                elif req.get("op") == "publish" and reply.get("ok"):
                    with contextlib.suppress(Exception):     # nor would it ever discard this
                        self._discard(str(reply["gen"]))
                raise
        except (OSError, ValueError) as exc:
            _log.warning("fc_jail.conn_error: %s", exc)
        finally:
            for fd in out_fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
            # The client's descriptors AND its connection (whose queue may hold more of them):
            # their final release must not happen in this thread.
            self._sink.release([*fds, conn.detach()])

    def _abandon(self, owner: Owner, jail_id: str) -> None:
        with self._lock:
            jail = self._jails.get(jail_id)
        if jail is None or jail.owner is not owner:
            return
        _log.warning("fc_jail.spawn_reply_lost jail=%s: undoing the spawn", jail_id)
        jail.orphaned = True          # the monitor retries if this attempt does not finish
        with contextlib.suppress(Exception):
            if self._kill_and_wait(jail, timeout=5.0):
                self._destroy(jail)

    @staticmethod
    def _reply(conn: socket.socket, msg: "dict[str, Any]", fds: "list[int]") -> None:
        data = encode(msg)
        if fds:
            socket.send_fds(conn, [data], fds)
        else:
            conn.send(data)


# --------------------------------------------------------------------------- host utilities
_log = logging.getLogger("blastbox.fc_jail_helper")


def _peer_pid(conn: socket.socket) -> int:
    try:
        cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return int(array.array("i", cred)[0])
    except OSError:
        return -1


def _peer_pidfd(conn: socket.socket, pid: int) -> int:
    """A pidfd for the connected peer: SO_PEERPIDFD where the kernel has it (6.5+; immune to
    pid reuse), else pidfd_open on the SO_PEERCRED pid."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
        fd = int.from_bytes(raw, sys.byteorder, signed=True)
        if fd >= 0:
            return fd
    except OSError:
        pass
    return os.pidfd_open(pid)


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(0))


def _status_fields(text: str) -> "dict[str, str]":
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def _jail_memory_max(jail: Jail, overhead_mib: int) -> int:
    """Guest RAM + VMM overhead + what the jail itself WRITES into its root: on a tmpfs
    --chroot-base (the documented way to keep snapshots in RAM) those pages are charged to the
    writer's memcg and cannot be reclaimed (swap.max=0) -- the output disk the guest fills, and
    for a boot jail (a warm base) the guest-RAM-sized memory snapshot it dumps. Sized for guest
    RAM alone, a base was OOM-killed mid-snapshot on tmpfs. On a disk-backed base this is only
    headroom: the extra pages are reclaimable page cache."""
    mem = jail.mem_mib << 20
    extra = jail.outdisk_bytes + (mem if jail.mode == "boot" else 0)
    return mem + extra + (overhead_mib << 20)


def _jp(*parts: str) -> str:
    """os.path.join for per-jail / per-generation paths. Deliberately NOT pathlib: pathlib
    interns every component (immortal in Python 3.12), and these names are unique per spawn and
    client-chosen -- a long-lived root helper would keep every one forever."""
    return os.path.join(*parts)


def _cgroup_populated(cg: str) -> bool:
    try:
        with open(_jp(cg, "cgroup.events")) as fh:
            text = fh.read()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return "populated 1" in text


def _kill_cgroup(cg: str) -> None:
    with contextlib.suppress(OSError):
        with open(_jp(cg, "cgroup.kill"), "w") as fh:
            fh.write("1")
    deadline = time.monotonic() + 5.0
    while _cgroup_populated(cg) and time.monotonic() < deadline:
        time.sleep(0.02)
    with contextlib.suppress(OSError):
        os.rmdir(cg)


def _enable_controllers(cg: Path) -> None:
    ctl = cg / "cgroup.subtree_control"
    have = set(ctl.read_text().split())
    want = {"cpu", "memory", "pids"} - have
    if want:
        ctl.write_text(" ".join(f"+{c}" for c in sorted(want)))


def _default_memory_cap() -> int:
    with open("/proc/meminfo") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024 * 3 // 4
    raise RuntimeError("cannot read MemTotal")


def _apparmor_enabled() -> bool:
    try:
        return Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    except OSError:
        return False


def _loaded_profiles() -> "list[str]":
    try:
        text = Path("/sys/kernel/security/apparmor/profiles").read_text()
    except OSError:
        return []
    return [line.rsplit(" (", 1)[0] for line in text.splitlines() if line]


def _remove_profile(name: str) -> None:
    with contextlib.suppress(OSError):
        Path("/sys/kernel/security/apparmor/.remove").write_text(name)


def _drain(proc: "subprocess.Popen[bytes]", sink: "deque[bytes]") -> None:
    """Keep the last few KiB of the jail's console/log. The guest controls the serial console,
    so it is never written to disk or kept unbounded."""
    stream = proc.stdout
    if stream is None:
        return
    with contextlib.suppress(Exception):
        while True:
            chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
            if not chunk:
                break
            sink.append(chunk)


def _tail(jail: Jail) -> str:
    return b"".join(jail.log)[-2000:].decode("utf-8", "replace")


def _version(run: "Callable[..., Any]", fc: str) -> str:
    proc = run([fc, "--version"], capture_output=True, timeout=10, check=False)
    out = (proc.stdout or b"") + (proc.stderr or b"")
    m = re.search(rb"v?(\d+\.\d+\.\d+)", out)
    if not m:
        raise RuntimeError(f"cannot determine the version of {fc}")
    return m.group(1).decode()


def _check_root_owned_exec(label: str, path: str) -> None:
    """The helper exec()s these as root: every directory and symlink its resolution passes
    through must be root-owned and (directories) not group/other-writable, or whoever can write
    one of them can swap what root executes."""
    p = Path(path)
    if not p.is_absolute():
        raise RuntimeError(f"{label} path must be absolute: {path!r}")
    st = os.stat(p)
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o100:
        raise RuntimeError(f"{label} {path} is not an executable file")
    for node in _resolution_nodes(path):
        nst = os.lstat(node)
        if nst.st_uid != 0 or (not stat.S_ISLNK(nst.st_mode) and nst.st_mode & 0o022):
            raise RuntimeError(f"{label}: {node} must be root-owned and not group/other-writable")


def _resolution_nodes(path: str) -> "list[str]":
    """Every directory, symlink and final file that resolving ``path`` touches -- INCLUDING the
    directories holding intermediate links of a chain (``p -> D/current -> /opt/fc/bin``), which
    neither the configured path's ancestors nor the final target's ancestors cover."""
    seen: list[str] = ["/"]
    pending = [c for c in path.split("/") if c]
    cur = "/"
    hops = 0
    while pending:
        comp = pending.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = os.path.dirname(cur.rstrip("/")) or "/"
            continue
        nxt = os.path.join(cur, comp)
        seen.append(nxt)
        if os.path.islink(nxt):
            hops += 1
            if hops > 40:
                raise RuntimeError(f"{path}: too many levels of symbolic links")
            target = os.readlink(nxt)
            pending = [c for c in target.split("/") if c] + pending
            if target.startswith("/"):
                cur = "/"
            continue
        cur = nxt
    return seen


def _check_root_dir(path: Path) -> None:
    _check_owned_dir(path, 0)


def _check_owned_dir(path: Path, uid: int) -> None:
    """Refuse ``path`` unless every node its resolution passes through (symlink chains
    included, as for executables) is owned by root or ``uid`` and not group/other-writable
    (sticky directories excepted)."""
    for node in _resolution_nodes(str(path)):
        st = os.lstat(node)
        if st.st_uid not in (0, uid) or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022
                                         and not st.st_mode & stat.S_ISVTX):
            who = "root-owned" if uid == 0 else f"owned by root or uid {uid}"
            raise RuntimeError(f"{node} must be {who} and not group/other-writable")


def _own_cgroup() -> str:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:].strip().lstrip("/")
    raise RuntimeError("not on a unified (v2) cgroup hierarchy")


def delegate_own_cgroup(cgroup_root: Path = Path("/sys/fs/cgroup")) -> str:
    """Move this process into ``<own>/supervisor`` and return ``<own>/jails`` (relative).

    Run as a systemd service with ``Delegate=yes``, the helper owns its cgroup subtree: jails go
    under ``<service>/jails/<id>``, so the service's ``MemoryMax=`` caps them all and stopping
    the service kills every microVM with it."""
    own = _own_cgroup()
    base = cgroup_root / own
    sup = base / "supervisor"
    sup.mkdir(exist_ok=True)
    (sup / "cgroup.procs").write_text(str(os.getpid()))
    (base / "jails").mkdir(exist_ok=True)
    return f"{own}/jails" if own else "jails"


# --------------------------------------------------------------------------- main
def parse_args(argv: "list[str] | None" = None) -> HelperConfig:
    ap = argparse.ArgumentParser(prog="blastbox-fc-jail-helper", description=__doc__.split("\n")[0])
    ap.add_argument("--socket", default="/run/blastbox-fc-jail/helper.sock")
    ap.add_argument("--socket-group", required=True, help="group (name or gid) of the dispatcher")
    ap.add_argument("--allow-uid", type=int, action="append", required=True,
                    help="dispatcher uid allowed to connect (repeatable)")
    ap.add_argument("--firecracker", required=True)
    ap.add_argument("--jailer", required=True)
    ap.add_argument("--chroot-base", default="/srv/blastbox-fc-jail")
    ap.add_argument("--setpriv", default="/usr/bin/setpriv")
    ap.add_argument("--ip", default="/usr/sbin/ip")
    ap.add_argument("--mkfs", default="/usr/sbin/mkfs.ext4")
    ap.add_argument("--apparmor-parser", default="/sbin/apparmor_parser")
    ap.add_argument("--apparmor", choices=("auto", "require", "off"), default="auto")
    ap.add_argument("--uid-min", type=int, default=200000)
    ap.add_argument("--uid-max", type=int, default=200999)
    ap.add_argument("--cgroup-parent", default="auto",
                    help="cgroup v2 path for jails, or 'auto' (systemd Delegate=yes)")
    ap.add_argument("--jails-memory-max", type=int, default=0,
                    help="bytes; host-level cap over all jails (0 = 75%% of MemTotal)")
    ap.add_argument("--jail-mem-overhead-mib", type=int, default=256)
    ap.add_argument("--jail-pids-max", type=int, default=128)
    ap.add_argument("--max-jails", type=int, default=512)
    ap.add_argument("--max-jails-per-owner", type=int, default=256)
    ap.add_argument("--max-owners", type=int, default=64)
    ap.add_argument("--max-gens-per-owner", type=int, default=4)
    ap.add_argument("--max-conns", type=int, default=128)
    ap.add_argument("--max-conns-per-peer", type=int, default=32)
    ns = ap.parse_args(argv)
    try:
        gid = int(ns.socket_group)
    except ValueError:
        gid = grp.getgrnam(ns.socket_group).gr_gid
    cgroup = ns.cgroup_parent
    if cgroup == "auto":
        cgroup = delegate_own_cgroup()
    return HelperConfig(
        socket_path=Path(ns.socket), socket_gid=gid, allowed_uids=frozenset(ns.allow_uid),
        firecracker=ns.firecracker, jailer=ns.jailer, chroot_base=Path(ns.chroot_base),
        setpriv=ns.setpriv, ip=ns.ip, mkfs=ns.mkfs, apparmor_parser=ns.apparmor_parser, apparmor=ns.apparmor,
        uid_min=ns.uid_min, uid_max=ns.uid_max, cgroup_parent_rel=cgroup.strip("/"),
        jails_memory_max=ns.jails_memory_max, jail_mem_overhead_mib=ns.jail_mem_overhead_mib,
        jail_pids_max=ns.jail_pids_max, max_jails=ns.max_jails,
        max_jails_per_owner=ns.max_jails_per_owner, max_owners=ns.max_owners,
        max_gens_per_owner=ns.max_gens_per_owner, max_conns=ns.max_conns,
        max_conns_per_peer=ns.max_conns_per_peer,
    )


def main(argv: "list[str] | None" = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if os.geteuid() != 0:
        print("blastbox-fc-jail-helper must run as root", file=sys.stderr)
        return 2
    os.umask(0o077)
    # Each live jail holds ~3 helper descriptors and each client process one pidfd: the 1024
    # soft default is below max_jails. Raise the soft limit to the hard one.
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 1 << 20 if hard == resource.RLIM_INFINITY else hard
    if soft != resource.RLIM_INFINITY and soft < want:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    cfg = parse_args(argv)
    helper = Helper(cfg)
    helper.prepare_host()

    def _term(signum: int, frame: object) -> None:
        # Only ask the loop to stop: the teardown runs ONCE, in the finally below, not inside a
        # signal handler that a second signal could interrupt half way.
        helper._stop.set()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        helper.serve()
    finally:
        helper.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
