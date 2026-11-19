"""Firecracker under the jail helper, from the dispatcher's side.

Jailing is ON by default. These tests pin: the setting and its fail-closed gate (an unreachable
helper never degrades to unjailed firecracker), the Popen-shaped proxy the runtimes' teardown
rules rely on, and that the snapshot launcher/backend and the cold runtime drive a jailed
microVM only through the helper -- jail-relative drives, seal before use, publish only after
the base is gone, and no path into a jail on this side.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from blastbox.host.runtime import fc_jail
from blastbox.host.runtime import fc_jail_helper as h
from blastbox.host.runtime.fc_jail import JailClient, JailError, JailedProcess, JailSettings

JID = "0b4f6d1e-1111-4222-8333-944455556666"


# --------------------------------------------------------------------------- settings / gate
def test_jailing_is_on_by_default():
    s = JailSettings.from_env({})
    assert s.enabled and s.socket_path == "/run/blastbox-fc-jail/helper.sock"


@pytest.mark.parametrize("raw", ["off", "OFF", "0", "false", "no"])
def test_jailing_can_be_turned_off_explicitly(raw):
    assert not JailSettings.from_env({"BLASTBOX_FC_JAILER": raw}).enabled


@pytest.mark.parametrize("raw", ["of", "disabled", "maybe", "2"])
def test_an_unrecognised_value_is_an_error_not_off(raw):
    with pytest.raises(ValueError):
        JailSettings.from_env({"BLASTBOX_FC_JAILER": raw})


def test_require_jail_off_returns_none_and_on_without_helper_fails_naming_the_opt_out(tmp_path):
    assert fc_jail.require_jail(JailSettings(enabled=False, socket_path="x")) is None
    with pytest.raises(JailError) as exc:
        fc_jail.require_jail(JailSettings(enabled=True, socket_path=str(tmp_path / "none.sock")))
    assert "BLASTBOX_FC_JAILER=off" in str(exc.value)


def _fc_env(monkeypatch, tmp_path, **extra):
    for name, var in (("vmlinux", "BLASTBOX_FC_KERNEL"), ("rootfs.ext4", "BLASTBOX_FC_ROOTFS")):
        f = tmp_path / name
        f.write_bytes(b"x")
        monkeypatch.setenv(var, str(f))
    monkeypatch.setenv("BLASTBOX_FC_JAIL_SOCKET", str(tmp_path / "missing.sock"))
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


@pytest.mark.parametrize("snapshot", [False, True])
def test_the_fc_tier_fails_closed_when_the_helper_is_missing(monkeypatch, tmp_path, snapshot):
    """Even with a perfectly usable LOCAL firecracker: no silent unjailed fallback."""
    from blastbox.host.runtime import firecracker as fc
    from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime

    _fc_env(monkeypatch, tmp_path)
    monkeypatch.delenv("BLASTBOX_FC_JAILER", raising=False)
    monkeypatch.setattr(fc, "firecracker_available", lambda *a, **k: True)
    select = select_snapshot_runtime if snapshot else fc.select_fc_runtime
    with pytest.raises(fc.FCUnavailable) as exc:
        select(require_available=True)
    assert "BLASTBOX_FC_JAILER=off" in str(exc.value)
    assert select(require_available=False) is None


@pytest.mark.parametrize("snapshot", [False, True])
def test_a_jailer_typo_refuses_the_tier(monkeypatch, tmp_path, snapshot):
    from blastbox.host.runtime import firecracker as fc
    from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime

    _fc_env(monkeypatch, tmp_path, BLASTBOX_FC_JAILER="of")
    monkeypatch.setattr(fc, "firecracker_available", lambda *a, **k: True)
    select = select_snapshot_runtime if snapshot else fc.select_fc_runtime
    with pytest.raises(fc.FCUnavailable):
        select(require_available=True)


def test_snapshot_mem_dir_knobs_are_refused_under_the_jailer(monkeypatch, tmp_path):
    from blastbox.host.runtime import firecracker as fc
    from blastbox.host.runtime import fc_snapshot_runtime as sr

    _fc_env(monkeypatch, tmp_path, BLASTBOX_SNAPSHOT_MEM_TMPFS="1")
    monkeypatch.setattr(fc, "firecracker_available", lambda *a, **k: True)
    monkeypatch.setattr(fc, "_jail_client", lambda: _FakeJail(tmp_path))
    monkeypatch.setattr(fc, "guest_kernel_version", lambda p: (6, 1))
    with pytest.raises(fc.FCUnavailable, match="jail helper's --chroot-base"):
        sr.select_snapshot_runtime(require_available=True)


def test_availability_under_the_jailer_uses_the_helpers_firecracker(tmp_path, monkeypatch):
    from blastbox.host.runtime import firecracker as fc

    k, r = tmp_path / "vmlinux", tmp_path / "rootfs.ext4"
    k.write_bytes(b"k")
    r.write_bytes(b"r")
    monkeypatch.setattr(fc, "rootfs_guest_problem", lambda p: "")
    cfg = fc.FCConfig(fc_bin="/nonexistent/firecracker", fc_kernel=str(k), fc_rootfs=str(r))
    jail = _FakeJail(tmp_path)
    assert fc.firecracker_available(cfg, jail=jail)          # no local binary or /dev/kvm needed
    jail.info = {"firecracker": "1.12.1"}
    assert not fc.firecracker_available(cfg, jail=jail)      # the helper's FC is too old
    jail.info = {"firecracker": "garbage"}
    assert not fc.firecracker_available(cfg, jail=jail)


# --------------------------------------------------------------------------- client <-> helper
@pytest.fixture
def live_helper(tmp_path):
    """A real Helper serving its socket (unprivileged: chown is a no-op, no spawns)."""
    sock_path = tmp_path / "run" / "h.sock"
    cfg = h.HelperConfig(socket_path=sock_path, socket_gid=os.getgid(),
                         allowed_uids=frozenset({os.getuid()}), firecracker="/x/fc",
                         jailer="/x/jailer", chroot_base=tmp_path / "jail",
                         cgroup_parent_rel="x", cgroup_root=tmp_path / "cg", apparmor="off")
    helper = h.Helper(cfg, apparmor_enabled=False, lchown=lambda p, u, g: None)
    helper.fc_version = "1.16.0"
    for d in (cfg.chroot_base, cfg.assets_dir, cfg.gens_dir):
        d.mkdir(parents=True, exist_ok=True)
    ready = threading.Event()
    t = threading.Thread(target=helper.serve, kwargs={"ready": ready.set}, daemon=True)
    t.start()
    assert ready.wait(5)
    yield helper, str(sock_path)
    helper._stop.set()
    t.join(5)


def test_client_hello_and_asset_round_trip_over_the_real_socket(live_helper, tmp_path):
    helper, path = live_helper
    client = JailClient(path)
    info = client.hello()
    assert info["firecracker"] == "1.16.0" and info["ready_port"] == h.READY_PORT
    f = tmp_path / "rootfs.ext4"
    f.write_bytes(b"R" * 4096)
    aid, key = client.asset("rootfs", str(f))
    st = f.stat()
    assert key == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    assert Path(helper._assets[aid].path).read_bytes() == b"R" * 4096
    assert client.asset("rootfs", str(f))[0] == aid          # cached by identity
    with pytest.raises(JailError) as exc:
        client.status(JID)
    assert exc.value.code == "unknown_jail"


def test_require_jail_succeeds_against_a_live_helper(live_helper):
    _, path = live_helper
    client = fc_jail.require_jail(JailSettings(enabled=True, socket_path=path))
    assert client is not None and client.info["protocol"] == h.PROTOCOL_VERSION


# --------------------------------------------------------------------------- fakes
class _FakeApiServer:
    """Answers each connection with one HTTP 204, recording (method, path, body)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def connect(self) -> socket.socket:
        a, b = socket.socketpair()
        threading.Thread(target=self._serve, args=(b,), daemon=True).start()
        return a

    def _serve(self, s: socket.socket) -> None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                return
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        method, path, _ = lines[0].split(" ")
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(":")
            if k.lower() == "content-length":
                length = int(v)
        while len(body) < length:
            body += s.recv(65536)
        self.calls.append((method, path, json.loads(body) if body else None))
        s.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        s.close()


class _FakeJail:
    """A JailClient double: records requests, serves API PUTs, models process state."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.info = {"firecracker": "1.16.0", "protocol": 1}
        self.calls: list[tuple] = []
        self.api = _FakeApiServer()
        self.alive: dict[str, bool] = {}
        self.order: list[str] = []
        self.identity = None
        self.outdisk_bytes = b""

    def asset(self, kind, path):
        self.calls.append(("asset", kind, path))
        st = os.stat(path)
        key = self.identity or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        return f"a{kind:0>32}"[-33:], key

    def forget_assets(self):
        self.calls.append(("forget",))

    def spawn(self, jail_id, **kw):
        self.calls.append(("spawn", jail_id, kw))
        self.alive[jail_id] = True
        if kw.get("ready_listener"):
            p = self.tmp / f"l-{len(self.calls)}.sock"
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(p))
            s.listen(1)
            return s
        return None

    def connect(self, jail_id, target, timeout_s=None):
        self.calls.append(("connect", jail_id, target))
        if target == "api":
            return self.api.connect()
        a, b = socket.socketpair()

        def guest() -> None:          # firecracker's host-initiated CONNECT handshake
            b.recv(64)
            b.sendall(b"OK 1234\n")
        threading.Thread(target=guest, daemon=True).start()
        self.vsock_peer = b
        return a

    def status(self, jail_id, timeout_s=None):
        if jail_id not in self.alive:
            raise JailError("unknown_jail", jail_id)
        return {"returncode": None if self.alive[jail_id] else -9, "vsock": True}

    def signal(self, jail_id, sig):
        if jail_id not in self.alive:
            raise JailError("unknown_jail", jail_id)
        self.order.append(f"signal:{sig}")
        self.alive[jail_id] = False

    def seal(self, jail_id):
        self.order.append("seal")
        self.calls.append(("seal", jail_id))

    def outdisk(self, jail_id):
        p = self.tmp / "jail-outdisk"
        p.write_bytes(self.outdisk_bytes)
        return os.open(p, os.O_RDONLY), len(self.outdisk_bytes)

    def publish(self, jail_id):
        self.order.append("publish")
        assert not self.alive[jail_id], "published while the base was still running"
        return {"gen": "g" + "a" * 32, "dir": "/srv/blastbox-fc-jail/gens/g" + "a" * 32}

    def destroy(self, jail_id):
        if jail_id not in self.alive:
            raise JailError("unknown_jail", jail_id)
        self.order.append("destroy")
        assert not self.alive[jail_id]
        del self.alive[jail_id]

    def discard(self, gen):
        self.calls.append(("discard", gen))


def _cfg(tmp_path: Path):
    from blastbox.host.runtime.firecracker import FCConfig

    k, r = tmp_path / "vmlinux", tmp_path / "rootfs.ext4"
    k.write_bytes(b"k")
    r.write_bytes(b"r")
    return FCConfig(fc_kernel=str(k), fc_rootfs=str(r), fc_mem_mib=256, fc_vcpu_count=1,
                    scratch_root=str(tmp_path / "slots"))


# --------------------------------------------------------------------------- JailedProcess
def test_jailed_process_is_popen_shaped_and_has_no_host_pid(tmp_path):
    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    p = JailedProcess(jail, JID)
    assert p.pid is None and p.poll() is None
    with pytest.raises(JailError, match="alive"):
        p.destroy()
    with pytest.raises(subprocess.TimeoutExpired):
        p.wait(timeout=0.05)
    p.kill()
    assert p.wait(timeout=1) == -9
    p.destroy()
    p.destroy()                       # idempotent
    assert jail.order == ["signal:KILL", "destroy"]


def test_a_jail_the_helper_no_longer_knows_is_gone(tmp_path):
    p = JailedProcess(_FakeJail(tmp_path), JID)
    assert p.poll() == -9
    p.kill()                          # no error
    p.destroy()


def test_outdisk_is_copied_into_a_dispatcher_owned_file(tmp_path):
    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    jail.outdisk_bytes = b"\x00" * 1024 + b"data"
    dest = tmp_path / "slot" / "outdisk.ext4"
    JailedProcess(jail, JID).copy_outdisk(dest)
    assert dest.read_bytes() == jail.outdisk_bytes
    assert dest.stat().st_mode & 0o777 == 0o600


# --------------------------------------------------------------------------- snapshot launcher
def _launcher(tmp_path, jail, **kw):
    from blastbox.host.runtime.fc_snapshot_launcher import FcSnapshotLauncher

    seen: dict[str, Any] = {}

    def factory(p, ack_generation=None, listener=None):
        seen["listener"] = listener
        seen["path"] = p
        return lambda timeout_s: None

    launcher = FcSnapshotLauncher(_cfg(tmp_path), tmp_path / "base", jail=jail,
                                  ready_check_factory=factory, **kw)
    return launcher, seen


def test_a_jailed_base_boots_with_jail_relative_drives_and_is_sealed(tmp_path):
    jail = _FakeJail(tmp_path)
    launcher, seen = _launcher(tmp_path, jail)
    handle = launcher.boot_base()
    spawn = next(c for c in jail.calls if c[0] == "spawn")
    assert spawn[2]["mode"] == "boot" and spawn[2]["ready_listener"]
    puts = {path: body for _, path, body in jail.api.calls}
    assert puts["/boot-source"]["kernel_image_path"] == "/vmlinux"
    assert puts["/drives/rootfs"]["path_on_host"] == "rootfs.ext4"
    assert puts["/drives/outdisk"]["path_on_host"] == "outdisk.ext4"
    assert puts["/vsock"]["uds_path"] == "vsock.sock"
    assert ("seal", spawn[1]) in jail.calls
    assert isinstance(seen["listener"], socket.socket)     # the helper's listener, adopted
    assert handle.opened_rootfs_identity is not None
    assert not (tmp_path / "base").exists() or not any((tmp_path / "base").iterdir())


def test_a_jailed_checkpoint_kills_the_base_before_the_helper_publishes(tmp_path):
    jail = _FakeJail(tmp_path)
    launcher, _ = _launcher(tmp_path, jail)
    handle = launcher.boot_base()
    artifact = handle.checkpoint(tmp_path / "base")
    snap = [c for c in jail.api.calls if c[1] == "/snapshot/create"][0][2]
    assert snap == {"snapshot_type": "Full", "snapshot_path": "/warm.snapshot",
                    "mem_file_path": "/warm.mem"}
    assert jail.order.index("publish") > jail.order.index("signal:TERM")
    assert artifact.jail_gen == "g" + "a" * 32
    handle.kill()
    assert jail.order[-1] == "destroy"


def test_a_jailed_restore_names_the_generation_and_never_copies_a_disk(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    jail = _FakeJail(tmp_path)
    copies: list = []
    launcher, _ = _launcher(tmp_path, jail, copy_outdisk=lambda s, d: copies.append((s, d)))
    backend = FcSnapshotBackend(tmp_path / "base", launcher)
    art = FcSnapshotArtifact(Path("/h/warm.snapshot"), Path("/h/warm.mem"), Path("/h/o"),
                             jail_gen="g" + "b" * 32)
    handle = backend.restore_in(tmp_path / "slots" / "s1", art)
    spawn = [c for c in jail.calls if c[0] == "spawn"][-1]
    assert spawn[2]["mode"] == "restore" and spawn[2]["gen"] == "g" + "b" * 32
    load = [c for c in jail.api.calls if c[1] == "/snapshot/load"][0][2]
    assert load["snapshot_path"] == "/warm.snapshot"
    assert load["mem_backend"]["backend_path"] == "/warm.mem"
    assert jail.order[-1] == "seal" and copies == []
    assert handle.vsock_present() is True
    assert (tmp_path / "slots" / "s1").is_dir()


def test_a_failed_seal_kills_the_restored_jail(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    jail = _FakeJail(tmp_path)

    def bad_seal(jail_id):
        raise JailError("unconfined", "tid 7: Seccomp=0")
    jail.seal = bad_seal
    launcher, _ = _launcher(tmp_path, jail)
    backend = FcSnapshotBackend(tmp_path / "base", launcher)
    art = FcSnapshotArtifact(Path("/h/s"), Path("/h/m"), Path("/h/o"), jail_gen="g" + "c" * 32)
    with pytest.raises(JailError):
        backend.restore_in(tmp_path / "slots" / "s2", art)
    assert jail.alive == {}       # killed and destroyed


@pytest.mark.parametrize("jailed_launcher", [True, False])
def test_artifact_and_launcher_must_agree_about_jailing(tmp_path, jailed_launcher):
    from blastbox.host.runtime.fc_snapshot import SnapshotError
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    launcher, _ = _launcher(tmp_path, _FakeJail(tmp_path) if jailed_launcher else None)
    backend = FcSnapshotBackend(tmp_path / "base", launcher)
    gen = None if jailed_launcher else "g" + "d" * 32
    art = FcSnapshotArtifact(tmp_path / "s", tmp_path / "m", tmp_path / "o", jail_gen=gen)
    with pytest.raises(SnapshotError, match="disagree about jailing"):
        backend.restore_in(tmp_path / "slots" / "s3", art)


def test_discarding_a_jailed_generation_asks_the_helper_and_unlinks_nothing(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    jail = _FakeJail(tmp_path)
    launcher, _ = _launcher(tmp_path, jail)
    victim = tmp_path / "looks-like-a-host-file"
    victim.write_bytes(b"keep")
    art = FcSnapshotArtifact(victim, victim, victim, jail_gen="g" + "e" * 32)
    FcSnapshotBackend(tmp_path / "base", launcher).discard(art)
    assert ("discard", "g" + "e" * 32) in jail.calls and victim.exists()
    assert launcher.sweep_orphan_generations() == 0


def test_the_rootfs_pin_refuses_a_jailed_base_that_booted_another_file(tmp_path):
    from blastbox.host.rootfs_stamp import RootfsPin, RootfsStale

    jail = _FakeJail(tmp_path)
    launcher, _ = _launcher(tmp_path, jail)
    jail.identity = (1, 2, 3, 4)       # the helper copied a DIFFERENT file than was checked
    pin = RootfsPin(str(tmp_path / "rootfs.ext4"), "firecracker")
    boot = pin.wrap(launcher.boot_base(), (9, 9, 9, 9))
    with pytest.raises(RootfsStale, match="jailed base booted a different file"):
        boot.checkpoint(tmp_path / "base")


# --------------------------------------------------------------------------- cold runtime
def _cold(tmp_path, jail):
    from blastbox.host.runtime.firecracker import FirecrackerSlotRuntime, VsockReadySignal

    rt = FirecrackerSlotRuntime(_cfg(tmp_path), jail=jail, ready_signal=VsockReadySignal())
    rt._guest_checked = lambda: ("", None)          # type: ignore[method-assign]
    return rt


def test_a_jailed_cold_slot_boots_through_the_helper_and_is_sealed(tmp_path):
    jail = _FakeJail(tmp_path)
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    spawn = next(c for c in jail.calls if c[0] == "spawn")
    assert spawn[1] == slot.slot_id and spawn[2]["outdisk_mib"] == rt._cfg.fc_outdisk_mib
    assert [c[1] for c in jail.api.calls][-1] == "/actions"
    assert ("seal", slot.slot_id) in jail.calls
    assert not (Path(rt._cfg.scratch_root) / slot.slot_id / "outdisk.ext4").exists()
    rt.reap(slot)
    assert jail.order[-2:] == ["signal:KILL", "destroy"]
    assert not (Path(rt._cfg.scratch_root) / slot.slot_id).exists()


def test_a_jailed_cold_slot_refuses_a_rootfs_that_changed_since_its_check(tmp_path):
    from blastbox.host.rootfs_stamp import RootfsStampError

    jail = _FakeJail(tmp_path)
    jail.identity = (1, 2, 3, 4)
    rt = _cold(tmp_path, jail)
    rt._guest_checked = lambda: ("", (5, 6, 7, 8))   # type: ignore[method-assign]
    with pytest.raises(RootfsStampError):
        rt.spawn()
    assert not any(c[0] == "spawn" for c in jail.calls)
    assert not any((Path(rt._cfg.scratch_root)).iterdir())


def test_a_jailed_cold_spawn_failure_leaves_no_jail(tmp_path):
    jail = _FakeJail(tmp_path)

    def bad_seal(jail_id):
        raise JailError("unconfined", "x")
    jail.seal = bad_seal
    rt = _cold(tmp_path, jail)
    with pytest.raises(JailError):
        rt.spawn()
    assert jail.alive == {} and not any(Path(rt._cfg.scratch_root).iterdir())


def test_jailed_cold_output_and_vsock_go_through_the_helper(tmp_path, monkeypatch):
    from blastbox.host.runtime import firecracker as fc

    jail = _FakeJail(tmp_path)
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    jail.outdisk_bytes = b"ext4-image"
    parsed: list[Path] = []
    monkeypatch.setattr(fc, "rdump_ext4", lambda img, dest, cap: parsed.append(img) or [])
    rt.read_output_disk(slot)
    assert parsed[0].read_bytes() == b"ext4-image"
    ctl = rt.host_warm_control(slot)
    s = ctl._connect()
    s.close()
    assert ("connect", slot.slot_id, "vsock") in jail.calls
    rt.reap(slot)


# --------------------------------------------------------------------------- vsock pieces
def test_the_ready_signal_adopts_a_helper_bound_listener(tmp_path):
    from blastbox.host.pool import Slot, SlotState
    from blastbox.host.runtime.firecracker import VsockReadySignal

    path = tmp_path / "jailroot-vsock.sock_10000"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)
    sig = VsockReadySignal()
    slot = Slot(slot_id="s", control_dir=tmp_path / "nowhere", input_dir=tmp_path / "nowhere",
                output_dir=tmp_path / "nowhere" / "out", state=SlotState.WARMING)
    sig.prepare(slot, listener=srv)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(path))
    c.sendall(b"READY")
    c.close()
    pass
    deadline = time.monotonic() + 5
    while not sig.is_ready(slot) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert sig.is_ready(slot)
    sig.cleanup(slot)
    assert path.exists()      # the helper's socket: not ours to unlink
    assert not (tmp_path / "nowhere").exists()


@pytest.mark.parametrize("code,host_io", [("unreachable", True), ("refused", True),
                                          ("no_socket", False), ("exited", False)])
def test_a_jailed_vsock_connect_failure_is_attributed(tmp_path, code, host_io):
    from blastbox.host.runtime.firecracker import VsockHostWarmControl

    def connect(timeout_s=None):
        raise JailError(code, "x")
    ctl = VsockHostWarmControl(tmp_path / "v.sock", uds_connect=connect)
    with pytest.raises(ConnectionError) as exc:
        ctl._connect()
    assert bool(getattr(exc.value, "host_io", False)) is host_io


# --------------------------------------------------------------------------- helper outages
class _DownJail(_FakeJail):
    """The helper stops answering status/signal (overloaded, restarting)."""

    down = False

    def status(self, jail_id, timeout_s=None):
        if self.down:
            raise JailError("timeout", "status")
        return super().status(jail_id, timeout_s)

    def signal(self, jail_id, sig):
        if self.down:
            raise JailError("unreachable", "signal")
        return super().signal(jail_id, sig)


def test_a_helper_outage_is_unknown_liveness_not_death(tmp_path):
    jail = _DownJail(tmp_path)
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    assert rt.is_alive(slot) is True
    jail.down = True
    assert rt.is_alive(slot) is None               # UNKNOWN: the pool keeps it and asks again


def test_an_unconfirmed_jailed_reap_quarantines_and_keeps_the_handle(tmp_path):
    from blastbox.host.runtime.firecracker import FCError

    jail = _DownJail(tmp_path)
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    jail.down = True
    with pytest.raises(FCError, match="quarantining"):
        rt.reap(slot)
    assert slot.slot_id in rt._procs               # a later reap can retry
    jail.down = False
    rt.reap(slot)
    assert slot.slot_id not in rt._procs and jail.alive == {}


def test_a_snapshot_slot_with_an_unreachable_helper_is_unknown(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    from blastbox.host.pool import Slot, SlotState

    jail = _DownJail(tmp_path)
    launcher, _ = _launcher(tmp_path, jail)
    handle = FcSnapshotBackend(tmp_path / "base", launcher).restore_in(
        tmp_path / "slots" / "s9",
        FcSnapshotArtifact(Path("/h/s"), Path("/h/m"), Path("/h/o"), jail_gen="g" + "f" * 32))
    rt = SnapshotSlotRuntime.__new__(SnapshotSlotRuntime)
    rt._lock = threading.Lock()
    rt._handles = {"s9": handle}
    rt._restored_at = {}
    rt._settle_s = 0.0
    slot = Slot(slot_id="s9", control_dir=tmp_path, input_dir=tmp_path,
                output_dir=tmp_path / "slots" / "s9" / "out", state=SlotState.IDLE)
    assert rt.is_alive(slot) is True
    jail.down = True
    assert rt.is_alive(slot) is None
    with pytest.raises(JailError):                 # UNKNOWN for the pool: warming timeout paused
        rt.is_ready(slot)


def test_a_helper_failure_reading_output_is_host_io(tmp_path):
    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True

    def down(jail_id):
        raise JailError("timeout", "outdisk")
    jail.outdisk = down
    with pytest.raises(JailError) as exc:
        JailedProcess(jail, JID).copy_outdisk(tmp_path / "o.ext4")
    assert getattr(exc.value, "host_io", False) is True
    assert not getattr(JailError("unknown_jail", "x"), "host_io", False)


def test_an_undecodable_reply_closes_its_descriptors_and_is_a_jail_error(tmp_path):
    path = tmp_path / "h.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    srv.bind(str(path))
    srv.listen(1)
    r, w = os.pipe()

    def serve():
        c, _ = srv.accept()
        c.recv(65536)
        socket.send_fds(c, [b"{not json"], [r])
        c.close()
    t = threading.Thread(target=serve)
    t.start()
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(JailError) as exc:
        JailClient(str(path)).call("hello")
    t.join()
    os.close(r)
    os.close(w)
    srv.close()
    assert exc.value.code == "protocol" and exc.value.host_io
    assert len(os.listdir("/proc/self/fd")) <= before - 2      # r, w closed; nothing received kept


def test_a_generation_the_helper_forgot_is_stale_not_flaky(tmp_path):
    from blastbox.host.runtime.fc_snapshot import SnapshotStale
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, FcSnapshotBackend

    jail = _FakeJail(tmp_path)

    def gone(jail_id, **kw):
        raise JailError("unknown_gen", kw.get("gen"))
    jail.spawn = gone
    launcher, _ = _launcher(tmp_path, jail)
    with pytest.raises(SnapshotStale):
        FcSnapshotBackend(tmp_path / "base", launcher).restore_in(
            tmp_path / "slots" / "s7",
            FcSnapshotArtifact(Path("/h/s"), Path("/h/m"), Path("/h/o"), jail_gen="g" + "1" * 32))


def test_restore_reclaimed_tolerates_an_unreachable_helper(tmp_path):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotBackend

    jail = _DownJail(tmp_path)
    jail.alive[JID] = True
    jail.down = True
    backend = FcSnapshotBackend(tmp_path / "base", None)

    class _H:
        proc = JailedProcess(jail, JID)
    backend._unreaped[str(tmp_path / "w")] = _H()
    assert backend.restore_reclaimed(str(tmp_path / "w")) is False


def test_a_peer_the_helper_drops_unread_is_a_host_side_refusal(tmp_path, monkeypatch):
    from blastbox.host.runtime import fc_jail as fj

    monkeypatch.setattr(fj.time, "sleep", lambda s: None)
    path = tmp_path / "h.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    srv.bind(str(path))
    srv.listen(8)

    seen = []
    srv.settimeout(5)

    def drop():
        for _ in range(fj._BUSY_RETRIES + 1):   # every (retried) attempt is dropped
            try:
                c, _ = srv.accept()
            except TimeoutError:
                return
            seen.append(1)
            c.close()                   # unread: the client sees ECONNRESET, not EOF
    t = threading.Thread(target=drop)
    t.start()
    with pytest.raises(JailError) as exc:
        JailClient(str(path)).call("status", jail=JID)
    t.join(10)
    srv.close()
    assert exc.value.code in ("refused", "busy") and exc.value.host_io
    assert len(seen) == fj._BUSY_RETRIES + 1          # a dropped request IS retried


def test_a_cold_reap_whose_vm_is_gone_but_destroy_fails_is_not_quarantined(tmp_path):
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    jail = _FakeJail(tmp_path)
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    real = jail.destroy
    jail.destroy = lambda jid: (_ for _ in ()).throw(JailError("cleanup_failed", "x"))
    rt.reap(slot)                                  # the VM exit was confirmed: no raise
    assert slot.slot_id not in rt._procs
    assert any(getattr(p, "jail_id", None) == slot.slot_id for p in fl._PENDING_DESTROY)
    jail.destroy = real
    fl._retry_pending_destroys()
    assert not any(getattr(p, "jail_id", None) == slot.slot_id for p in fl._PENDING_DESTROY)


def test_a_jail_helper_failure_at_signal_go_is_not_worker_evidence(tmp_path):
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import test_dispatch_warm as tdw

    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.runtime.firecracker import VsockHostWarmControl

    store = InMemoryJobStore()
    job = tdw._make_job()
    job.input_sha256 = tdw._INPUT_SHA
    store.create(job)
    tdw._setup_job_dirs(tmp_path / "jobs", job)
    slot = tdw._make_slot(tmp_path)
    runtime = tdw._FakeVsockRuntime()

    def helper_dropped(timeout_s=None):
        raise JailError("refused", "[Errno 104] Connection reset by peer")
    runtime.host_warm_control = lambda s: VsockHostWarmControl(   # type: ignore[assignment]
        tmp_path / "v.sock", uds_connect=helper_dropped)
    pool = tdw.FakeWarmPool(slot, runtime=runtime)
    dispatcher = tdw._make_dispatcher_with_pool(store, job_root=tmp_path / "jobs", pool=pool,
                                                worker_timeout_s=10)
    dispatcher.dispatch_once()
    assert pool.release_fault == ["unknown"]


def test_an_overloaded_real_helper_is_retried_not_refused(live_helper, monkeypatch):
    helper, path = live_helper
    from blastbox.host.runtime import fc_jail as fj

    capped = h.HelperConfig(**{**helper.cfg.__dict__, "max_conns_per_peer": 0})
    open_ = h.HelperConfig(**{**helper.cfg.__dict__, "max_conns_per_peer": 32})
    helper.cfg = capped
    monkeypatch.setattr(fj, "_BUSY_RETRIES", 0)
    with pytest.raises(JailError) as exc:
        JailClient(path).hello()
    assert exc.value.code == "busy" and exc.value.host_io      # drained, so "busy" arrives
    monkeypatch.setattr(fj, "_BUSY_RETRIES", 6)
    threading.Timer(0.2, lambda: setattr(helper, "cfg", open_)).start()
    assert JailClient(path).hello()["protocol"] == h.PROTOCOL_VERSION   # ...and is retried


def test_a_failed_cold_spawn_whose_kill_is_unconfirmed_is_parked_not_forgotten(tmp_path):
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    jail = _DownJail(tmp_path)

    def bad_seal(jail_id):
        jail.down = True                         # the helper becomes unreachable mid-cleanup
        raise JailError("unconfined", "x")
    jail.seal = bad_seal
    rt = _cold(tmp_path, jail)
    with pytest.raises(JailError):
        rt.spawn()
    parked = [p for p in fl._PENDING_DESTROY if getattr(p, "_client", None) is jail]
    assert len(parked) == 1
    jail.down = False
    fl._retry_pending_destroys()          # re-sends the kill (never waits on the spawn path)
    fl._retry_pending_destroys()          # ...and destroys it once it has exited
    assert jail.alive == {}
    assert not [p for p in fl._PENDING_DESTROY if getattr(p, "_client", None) is jail]


def test_a_timed_out_output_copy_leaves_no_partial_image_and_abandoned_copies_are_capped(
        tmp_path, monkeypatch):
    from blastbox.errors import HostDiskTimeout
    from blastbox.host.runtime import fc_jail as fj
    from blastbox.host.runtime import firecracker as fc

    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    jail.outdisk_bytes = b"x" * 4096
    gate = threading.Event()
    monkeypatch.setattr(fj, "sparse_copy", lambda s, d, n: gate.wait(10))
    monkeypatch.setattr(fc, "disk_timeout_s", lambda: 0.05)
    monkeypatch.setattr(fj, "_MAX_ABANDONED", 2)
    monkeypatch.setattr(fj, "_ABANDONED", [])
    dest = tmp_path / "o.ext4"
    for _ in range(2):
        with pytest.raises(HostDiskTimeout):
            JailedProcess(jail, JID).copy_outdisk(dest)
        assert not dest.exists()
    with pytest.raises(HostDiskTimeout, match="refused"):
        JailedProcess(jail, JID).copy_outdisk(dest)
    gate.set()


def test_a_stalled_output_copy_is_host_io(tmp_path, monkeypatch):
    from blastbox.errors import HostDiskTimeout
    from blastbox.host.runtime import fc_jail as fj
    from blastbox.host.runtime import firecracker as fc

    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    jail.outdisk_bytes = b"x"
    gate = threading.Event()
    monkeypatch.setattr(fj, "sparse_copy", lambda s, d, n: gate.wait(10))
    monkeypatch.setattr(fc, "disk_timeout_s", lambda: 0.05)
    monkeypatch.setattr(fj, "_ABANDONED", [])
    with pytest.raises(HostDiskTimeout) as exc:
        JailedProcess(jail, JID).copy_outdisk(tmp_path / "o.ext4")
    gate.set()
    assert exc.value.host_io


def test_healthy_concurrent_output_copies_are_never_refused(tmp_path, monkeypatch):
    from blastbox.host.runtime import fc_jail as fj

    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    jail.outdisk_bytes = b"x" * 4096
    monkeypatch.setattr(fj, "_ABANDONED", [])
    real = fj.sparse_copy
    monkeypatch.setattr(fj, "sparse_copy", lambda s, d, n: (time.sleep(0.2), real(s, d, n)))
    import concurrent.futures as cf
    pass
    futs = []
    with cf.ThreadPoolExecutor(12) as ex:
        for i in range(12):                    # STAGGERED: each starts while the others run
            futs.append(ex.submit(JailedProcess(jail, JID).copy_outdisk, tmp_path / f"o{i}.ext4"))
            time.sleep(0.01)
        for f in futs:
            f.result()                         # none refused as "stuck"


def test_retrying_parked_destroys_never_waits_on_the_spawn_path(tmp_path):
    from blastbox.host.runtime import fc_snapshot_launcher as fl

    class _Stubborn:                           # kill delivered, never honoured (D-state VMM)
        jail_id = "stubborn"

        def poll(self):
            return None

        def kill(self):
            pass

        def wait(self, timeout=None):
            time.sleep(timeout or 0)
            raise subprocess.TimeoutExpired("x", timeout)

        def destroy(self):
            raise JailError("alive", "x")
    pass
    p = _Stubborn()
    with fl._STRANDED_LOCK:
        fl._PENDING_DESTROY.extend([p, p, p])
    t0 = time.monotonic()
    fl._retry_pending_destroys()
    assert time.monotonic() - t0 < 1.0
    with fl._STRANDED_LOCK:
        fl._PENDING_DESTROY[:] = [x for x in fl._PENDING_DESTROY if x is not p]


def test_claim_probes_and_vsock_connects_carry_the_callers_budget(tmp_path):
    jail = _FakeJail(tmp_path)
    seen = []
    real_status, real_connect = jail.status, jail.connect
    jail.status = lambda jid, timeout_s=None: (seen.append(("status", timeout_s)),
                                               real_status(jid))[1]
    jail.connect = lambda jid, tgt, timeout_s=None: (seen.append(("connect", timeout_s)),
                                                     real_connect(jid, tgt))[1]
    rt = _cold(tmp_path, jail)
    slot = rt.spawn()
    seen.clear()
    assert rt.is_alive_for_claim(slot, budget_s=0.01) is True
    assert ("status", 0.01) in seen
    ctl = rt.host_warm_control(slot)
    ctl._connect(deadline=time.monotonic() + 0.5).close()
    t = [x for x in seen if x[0] == "connect"][-1][1]
    assert t is not None and t <= 0.5
    rt.reap(slot)


def test_a_call_with_a_budget_never_waits_the_default_timeout(tmp_path):
    path = tmp_path / "silent.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    srv.bind(str(path))
    srv.listen(1)                                        # accepts (backlog) but never answers
    t0 = time.monotonic()
    with pytest.raises(JailError):
        JailClient(str(path)).status(JID, timeout_s=0.2)
    assert time.monotonic() - t0 < 1.5
    srv.close()


def test_a_budget_bounds_connect_send_and_receive_together(tmp_path, monkeypatch):
    path = tmp_path / "silent2.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    srv.bind(str(path))
    srv.listen(1)
    real_connect = socket.socket.connect

    def slow_connect(self, addr):
        time.sleep(0.15)                           # the connect itself eats most of the budget
        return real_connect(self, addr)
    monkeypatch.setattr(socket.socket, "connect", slow_connect)
    t0 = time.monotonic()
    with pytest.raises(JailError):
        JailClient(str(path)).call("status", jail=JID, timeout_s=0.2)
    assert time.monotonic() - t0 < 0.3             # not 0.15 + a fresh 0.2 for the receive
    srv.close()


def test_wait_and_tick_probes_never_use_the_default_helper_timeout(tmp_path):
    jail = _FakeJail(tmp_path)
    jail.alive[JID] = True
    seen = []
    real = jail.status
    jail.status = lambda jid, timeout_s=None: (seen.append(timeout_s), real(jid))[1]
    p = JailedProcess(jail, JID)
    with pytest.raises(subprocess.TimeoutExpired):
        p.wait(timeout=0.3)
    assert seen and all(t is not None and t <= 0.3 for t in seen)
    seen.clear()
    p.vsock_present()
    p.poll()
    assert seen and all(t is not None and t <= fc_jail._TICK_BUDGET_S for t in seen)


@pytest.mark.parametrize("code,cleaned", [("timeout", True), ("protocol", True),
                                          ("unknown_asset", False), ("exhausted", False)])
def test_a_spawn_whose_reply_was_lost_is_torn_down(tmp_path, monkeypatch, code, cleaned):
    client = JailClient(str(tmp_path / "x.sock"))
    monkeypatch.setattr(client, "call", lambda *a, **k: (_ for _ in ()).throw(JailError(code, "x")))
    parked = []
    from blastbox.host.runtime import fc_snapshot_launcher as fl
    monkeypatch.setattr(fl, "_park_or_destroy", lambda proc: parked.append(proc.jail_id))
    with pytest.raises(JailError):
        client.spawn(JID, mode="boot", mem_mib=64, vcpus=1, kernel="a" * 33, rootfs="a" * 33)
    assert (parked == [JID]) is cleaned
