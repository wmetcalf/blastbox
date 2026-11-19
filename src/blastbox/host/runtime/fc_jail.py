"""Dispatcher-side client for the root Firecracker jail helper (``fc_jail_helper.py``).

With jailing ON (the default) the dispatcher never runs ``firecracker`` itself: every microVM --
the warm snapshot base, each restored slot, each cold-tier slot -- is spawned by the root helper
under the upstream ``jailer`` (private chroot, unique uid/gid, its own cgroup leaf under a
host-level memory cap, an empty network namespace, a per-jail AppArmor profile, Firecracker's
seccomp filters verified on every thread). This module is the dispatcher's whole view of that:

* :class:`JailSettings` -- ``BLASTBOX_FC_JAILER`` (``on`` default, ``off`` = today's unjailed
  launch) and ``BLASTBOX_FC_JAIL_SOCKET``;
* :class:`JailClient` -- one request per connection over the helper's SOCK_SEQPACKET socket.
  Files cross as descriptors in both directions; the client never builds a path into a jail;
* :class:`JailedProcess` -- a ``Popen``-shaped proxy for a jailed microVM, so the runtimes'
  kill/poll/wait handling (and its "unconfirmed teardown" rules) apply unchanged;
* :func:`require_jail` -- the startup gate. When jailing is on and the helper cannot be reached
  the FC tier FAILS CLOSED with an error naming the opt-out; it never falls back to unjailed.
"""
from __future__ import annotations

import errno
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blastbox.host.runtime.fc_jail_helper import (
    JAIL_API_SOCK,
    MAX_MSG,
    PROTOCOL_VERSION,
    READY_PORT,
    decode,
    encode,
    sparse_copy,
)

_log = logging.getLogger("blastbox.host.runtime.fc_jail")

ENV_JAILER = "BLASTBOX_FC_JAILER"
ENV_JAIL_SOCKET = "BLASTBOX_FC_JAIL_SOCKET"
DEFAULT_SOCKET = "/run/blastbox-fc-jail/helper.sock"

_ON = {"", "on", "1", "true", "yes"}
_OFF = {"off", "0", "false", "no"}

#: Jail-relative names the dispatcher's API calls use (firecracker's cwd in a jail is ``/``).
JAIL_KERNEL_PATH = "/vmlinux"
JAIL_ROOTFS_PATH = "rootfs.ext4"
JAIL_SNAPSHOT_PATH = "/warm.snapshot"
JAIL_MEM_PATH = "/warm.mem"


#: Error codes that say the HELPER (this host's control plane) failed, not the guest/VMM. A
#: failure carrying one of these is host I/O for fault attribution: a helper outage hits every
#: job at once and must never be charged to -- or burn out -- healthy workers.
INFRA_CODES = frozenset({"unreachable", "timeout", "refused", "internal", "protocol", "busy"})

#: Per-op client deadlines. Staging work in the helper (an asset copy, mkfs or a sparse copy of
#: an output disk, a publish) is bounded by its own copy timeout (600 s): the client must wait
#: longer than that, or a slow-but-successful spawn finishes after the client gave up. (The
#: helper also undoes a spawn whose reply it could not deliver.)
_SLOW_OPS = {"asset": 900.0, "spawn": 900.0, "publish": 900.0}
_BUSY_RETRIES = 6


class JailError(RuntimeError):
    """The helper refused a request or could not be reached."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"fc jail helper: {code}{': ' + detail if detail else ''}")
        self.code = code
        self.detail = detail
        if code in INFRA_CODES:
            self.host_io = True


@dataclass(frozen=True)
class JailSettings:
    enabled: bool
    socket_path: str

    @classmethod
    def from_env(cls, env: "dict[str, str] | None" = None) -> "JailSettings":
        """Jailing is ON unless ``BLASTBOX_FC_JAILER`` says off. An unrecognised value is an
        ERROR, not "off": a typo must never be the thing that disables the jail."""
        env = dict(os.environ) if env is None else env
        raw = env.get(ENV_JAILER, "").strip().lower()
        if raw in _ON:
            enabled = True
        elif raw in _OFF:
            enabled = False
        else:
            raise ValueError(f"{ENV_JAILER}={raw!r}: expected 'on' (default) or 'off'")
        sock = env.get(ENV_JAIL_SOCKET, "").strip() or DEFAULT_SOCKET
        return cls(enabled=enabled, socket_path=sock)


def opt_out_hint() -> str:
    return (f"set {ENV_JAILER}=off to run Firecracker unjailed (NOT recommended), or install "
            f"and start the jail helper (docs/HOST-PREP.md, 'Firecracker jail helper')")


class JailClient:
    """Talks to the helper. Thread-safe: every call is its own connection."""

    def __init__(self, socket_path: str, *, timeout_s: float = 60.0) -> None:
        self.socket_path = socket_path
        self._timeout = timeout_s
        self._assets: dict[tuple[str, tuple[int, ...]], str] = {}
        self._assets_lock = threading.Lock()
        self.info: dict[str, Any] = {}

    # ------------------------------------------------------------------ transport
    def call(self, op: str, *, fds: "tuple[int, ...]" = (), **fields: Any) -> "tuple[dict[str, Any], list[int]]":
        delay = 0.05
        for attempt in range(_BUSY_RETRIES + 1):
            try:
                return self._call_once(op, fds=fds, **fields)
            except JailError as exc:
                if exc.code != "busy" or attempt == _BUSY_RETRIES:
                    raise
            time.sleep(delay)
            delay = min(delay * 2, 1.0)
        raise AssertionError("unreachable")  # pragma: no cover

    def _call_once(self, op: str, *, fds: "tuple[int, ...]" = (), **fields: Any) -> "tuple[dict[str, Any], list[int]]":
        msg = encode({"op": op, **fields})
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            sock.settimeout(max(self._timeout, _SLOW_OPS.get(op, 0.0)))
            try:
                sock.connect(self.socket_path)
            except OSError as exc:
                raise JailError("unreachable", f"{self.socket_path}: {exc.strerror or exc}") from exc
            if fds:
                socket.send_fds(sock, [msg], list(fds))
            else:
                sock.send(msg)
            data, got, flags, _ = socket.recv_fds(sock, MAX_MSG + 1, 4)
        except TimeoutError as exc:
            raise JailError("timeout", op) from exc
        except (ConnectionError, OSError) as exc:
            # The helper dropped the request unread (a uid it does not allow, or it died mid-
            # request): ECONNRESET/EPIPE, never a clean EOF. Still a control-plane failure, and
            # must be attributed to the host, not to a guest.
            raise JailError("refused", f"{op}: {exc}") from exc
        finally:
            sock.close()
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            for fd in got:
                os.close(fd)
            raise JailError("protocol", "truncated reply")
        if not data:
            for fd in got:
                os.close(fd)
            raise JailError("refused", f"the helper closed the connection ({op}); is this uid "
                                       f"allowed (--allow-uid)?")
        try:
            reply = decode(data)
        except ValueError as exc:
            for fd in got:
                os.close(fd)
            raise JailError("protocol", f"undecodable reply to {op}: {exc}") from exc
        if not isinstance(reply, dict) or not reply.get("ok"):
            for fd in got:
                os.close(fd)
            code = reply.get("error", "error") if isinstance(reply, dict) else "protocol"
            detail = reply.get("detail", "") if isinstance(reply, dict) else ""
            raise JailError(str(code), str(detail))
        return reply, got

    def _one_fd(self, op: str, **fields: Any) -> "tuple[dict[str, Any], int]":
        reply, fds = self.call(op, **fields)
        if len(fds) != 1:
            for fd in fds:
                os.close(fd)
            raise JailError("protocol", f"{op}: expected one descriptor, got {len(fds)}")
        return reply, fds[0]

    # ------------------------------------------------------------------ ops
    def hello(self) -> "dict[str, Any]":
        reply, _ = self.call("hello")
        if reply.get("protocol") != PROTOCOL_VERSION:
            raise JailError("protocol", f"helper speaks protocol {reply.get('protocol')}, "
                                        f"this dispatcher {PROTOCOL_VERSION}")
        if reply.get("ready_port") != READY_PORT:
            raise JailError("protocol", "helper READY port disagrees with this dispatcher")
        self.info = reply
        return reply

    def asset(self, kind: str, path: str) -> "tuple[str, tuple[int, int, int, int]]":
        """Register ``path`` (opened HERE, with the dispatcher's own permissions) as a boot asset.
        Returns ``(asset_id, identity)`` where identity is the (dev, ino, size, mtime_ns) of the
        file the helper actually copied -- the caller compares it to what it checked."""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
            with self._assets_lock:
                cached = self._assets.get((kind, key))
            if cached is not None:
                return cached, key
            reply, _ = self.call("asset", fds=(fd,), kind=kind)
        finally:
            os.close(fd)
        aid = str(reply["asset"])
        ident = tuple(int(x) for x in reply["identity"])
        if ident != key:
            raise JailError("bad_asset", f"{path} changed while it was registered")
        with self._assets_lock:
            self._assets[(kind, key)] = aid
        return aid, key

    def forget_assets(self) -> None:
        with self._assets_lock:
            self._assets.clear()

    def spawn(self, jail_id: str, *, mode: str, mem_mib: int, vcpus: int,
              outdisk_mib: int = 16, kernel: "str | None" = None, rootfs: "str | None" = None,
              gen: "str | None" = None, ready_listener: bool = False) -> "socket.socket | None":
        """Start a jailed firecracker (API socket mode). Returns the READY listener when asked."""
        reply, fds = self.call("spawn", jail=jail_id, mode=mode, kernel=kernel, rootfs=rootfs,
                               gen=gen, outdisk_mib=outdisk_mib, mem_mib=mem_mib, vcpus=vcpus,
                               ready_listener=ready_listener)
        if ready_listener:
            if len(fds) != 1:
                for fd in fds:
                    os.close(fd)
                raise JailError("protocol", "spawn: no READY listener returned")
            return socket.socket(fileno=fds[0])
        for fd in fds:
            os.close(fd)
        return None

    def connect(self, jail_id: str, target: str) -> socket.socket:
        """A connected stream socket to the jail's API (``api``) or vsock (``vsock``) UDS."""
        _, fd = self._one_fd("connect", jail=jail_id, target=target)
        return socket.socket(fileno=fd)

    def status(self, jail_id: str) -> "dict[str, Any]":
        return self.call("status", jail=jail_id)[0]

    def signal(self, jail_id: str, sig: str) -> None:
        self.call("signal", jail=jail_id, sig=sig)

    def seal(self, jail_id: str) -> None:
        self.call("seal", jail=jail_id)

    def outdisk(self, jail_id: str) -> "tuple[int, int]":
        reply, fd = self._one_fd("outdisk", jail=jail_id)
        return fd, int(reply["size"])

    def publish(self, jail_id: str) -> "dict[str, Any]":
        return self.call("publish", jail=jail_id)[0]

    def destroy(self, jail_id: str) -> None:
        self.call("destroy", jail=jail_id)

    def discard(self, gen: str) -> None:
        self.call("discard", gen=gen)


def require_jail(settings: "JailSettings | None" = None) -> "JailClient | None":
    """The FC tier's startup gate: a connected client when jailing is on, None when off.

    Raises :class:`JailError` (with the opt-out named) when jailing is on and the helper is not
    usable. Never returns None for "on": there is no silent unjailed fallback.
    """
    settings = settings or JailSettings.from_env()
    if not settings.enabled:
        _log.warning("fc.jailer_disabled %s=off: Firecracker runs UNJAILED as the dispatcher "
                     "uid, sharing its filesystem view, cgroup and network namespace", ENV_JAILER)
        return None
    client = JailClient(settings.socket_path)
    try:
        client.hello()
    except JailError as exc:
        raise JailError(exc.code, f"{exc.detail} -- the Firecracker tier requires the jail "
                                  f"helper ({ENV_JAILER} defaults to on); {opt_out_hint()}") from exc
    return client


class JailedProcess:
    """``subprocess.Popen``-shaped proxy for one jailed firecracker.

    ``pid`` is None on purpose: the process lives in the HOST pid namespace, and a host pid
    looked up in this container's /proc would name an unrelated process. Every caller that
    inspects /proc/<pid> already treats None as "cannot observe" and falls back.
    """

    pid = None

    def __init__(self, client: JailClient, jail_id: str) -> None:
        self._client = client
        self.jail_id = jail_id
        self.returncode: "int | None" = None
        self._destroyed = False
        self._lock = threading.Lock()

    def poll(self) -> "int | None":
        if self.returncode is not None:
            return self.returncode
        try:
            rc = self._client.status(self.jail_id).get("returncode")
        except JailError as exc:
            if exc.code == "unknown_jail":
                # The helper no longer has it (destroyed, or the helper restarted -- which kills
                # every jail it ran). Gone either way.
                self.returncode = -9
                return self.returncode
            raise
        if rc is not None:
            self.returncode = int(rc)
        return self.returncode

    def _signal(self, sig: str) -> None:
        if self.returncode is not None:
            return
        try:
            self._client.signal(self.jail_id, sig)
        except JailError as exc:
            if exc.code != "unknown_jail":
                raise

    def terminate(self) -> None:
        self._signal("TERM")

    def kill(self) -> None:
        self._signal("KILL")

    def wait(self, timeout: "float | None" = None) -> int:
        import subprocess

        deadline = None if timeout is None else time.monotonic() + timeout
        delay = 0.01
        while True:
            rc = self.poll()
            if rc is not None:
                return rc
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(f"jail {self.jail_id}", timeout or 0)
            time.sleep(delay)
            delay = min(delay * 2, 0.2)

    def destroy(self) -> None:
        """Remove the jail (its chroot, cgroup, netns, profile) once the process is CONFIRMED
        exited. Raises if the helper could not confirm; idempotent once it succeeded."""
        with self._lock:
            if self._destroyed:
                return
            if self.poll() is None:
                raise JailError("alive", f"jail {self.jail_id} is still running")
            try:
                self._client.destroy(self.jail_id)
            except JailError as exc:
                if exc.code != "unknown_jail":
                    raise
            self._destroyed = True

    # Jail-specific accessors the runtimes use in place of paths into the slot directory.
    def connect_api(self) -> socket.socket:
        return self._client.connect(self.jail_id, "api")

    def connect_vsock(self) -> socket.socket:
        return self._client.connect(self.jail_id, "vsock")

    def alive(self) -> "bool | None":
        """Tri-state liveness for the pool: True, False = CONFIRMED gone, None = the helper could
        not be asked (a control-plane failure is not a dead VM; the pool keeps the slot and asks
        again within its unknown-grace bound)."""
        try:
            return self.poll() is None
        except JailError:
            return None

    def vsock_present(self) -> bool:
        try:
            st = self._client.status(self.jail_id)
        except JailError:
            return False
        return st.get("returncode") is None and bool(st.get("vsock"))

    def seal(self) -> None:
        self._client.seal(self.jail_id)

    def copy_outdisk(self, dest: Path) -> None:
        """Copy the jail's output disk into ``dest`` (a dispatcher-owned file), sparsely.

        A copy -- not the jail's own inode -- is what rdump/e2fsck then operate on, so a guest
        still running cannot change the image under the host-side parser."""
        fd, size = self._client.outdisk(self.jail_id)
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
                          0o600)
            try:
                # Bounded like the other host disk work: a stalled disk must not pin the
                # dispatch thread (the helper already refused a size other than the staged one).
                from blastbox.host.runtime.firecracker import disk_timeout_s

                sparse_copy(fd, out, size, deadline=time.monotonic() + disk_timeout_s())
            finally:
                os.close(out)
        except OSError as exc:
            if exc.errno in (errno.ENOSPC, errno.EIO, errno.EROFS, errno.EDQUOT):
                exc.host_io = True  # type: ignore[attr-defined]
            raise
        finally:
            os.close(fd)

    def api_client(self, timeout: float = 30.0) -> Any:
        from blastbox.host.runtime.fc_api import FcApiClient

        return FcApiClient(f"jail:{self.jail_id}/{JAIL_API_SOCK}", timeout=timeout,
                           connector=self.connect_api)


def new_jail_id() -> str:
    import uuid

    return str(uuid.uuid4())
