"""The root Firecracker jail helper: its request validation, owner scoping and jail lifecycle.

The helper runs as root, and the dispatcher that talks to it is less trusted than it is. These
tests pin the narrow API: fixed per-op schemas, no client paths or argv, every object scoped to
the process that created it, symlink-safe access to anything a jail can write. The lifecycle
tests drive a real Helper against a temp tree with the privileged primitives (chown, the jailer
itself) replaced, so they run unprivileged.
"""
from __future__ import annotations

import ast
import threading
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from blastbox.host.runtime import fc_jail_helper as h

JID = "0b4f6d1e-1111-4222-8333-944455556666"
JID2 = "1c5a7e2f-2222-4333-8444-a55566667777"


# --------------------------------------------------------------------------- module shape
def test_the_helper_module_imports_only_the_standard_library():
    """It runs as root from a single installed file: no blastbox, no third-party imports."""
    tree = ast.parse(Path(h.__file__).read_text())
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    assert mods <= set(sys.stdlib_module_names) | {"__future__"}, mods - set(sys.stdlib_module_names)


def test_the_ready_port_and_jail_names_match_the_dispatcher():
    from blastbox.host.runtime import fc_jail, fc_snapshot_launcher, firecracker

    assert h.READY_PORT == firecracker._READY_PORT
    assert h.JAIL_VSOCK == fc_snapshot_launcher.REL_VSOCK
    assert h.JAIL_OUTDISK == fc_snapshot_launcher.REL_OUTDISK
    assert fc_jail.JAIL_SNAPSHOT_PATH == "/" + h.JAIL_SNAPSHOT
    assert fc_jail.JAIL_MEM_PATH == "/" + h.JAIL_MEM
    assert fc_jail.JAIL_KERNEL_PATH == "/" + h.JAIL_KERNEL
    assert fc_jail.JAIL_ROOTFS_PATH == h.JAIL_ROOTFS


# --------------------------------------------------------------------------- validation
def _spawn_req(**over):
    req = {"op": "spawn", "jail": JID, "mode": "boot", "kernel": "a" + "0" * 32,
           "rootfs": "a" + "1" * 32, "gen": None, "outdisk_mib": 600, "mem_mib": 2048,
           "vcpus": 2, "ready_listener": True}
    req.update(over)
    return req


def test_well_formed_requests_validate():
    h.validate_request({"op": "hello"}, 0)
    h.validate_request({"op": "asset", "kind": "rootfs"}, 1)
    h.validate_request(_spawn_req(), 0)
    h.validate_request(_spawn_req(mode="restore", kernel=None, rootfs=None, gen="g" + "a" * 32), 0)
    for op in ("status", "seal", "outdisk", "publish", "destroy"):
        h.validate_request({"op": op, "jail": JID}, 0)
    h.validate_request({"op": "connect", "jail": JID, "target": "vsock"}, 0)
    h.validate_request({"op": "signal", "jail": JID, "sig": "KILL"}, 0)
    h.validate_request({"op": "discard", "gen": "g" + "f" * 32}, 0)


@pytest.mark.parametrize("bad", [
    "not a dict",
    {"op": "exec", "argv": ["/bin/sh"]},                  # no such op
    {"op": "hello", "extra": 1},                          # unknown key
    {"op": "status"},                                     # missing key
    {"op": "status", "jail": "../../etc"},                # path in an id
    {"op": "status", "jail": "/srv/blastbox-fc-jail/x"},
    {"op": "status", "jail": "ABCDEFGH-1234"},            # uppercase
    {"op": "status", "jail": "short"},                    # too short
    {"op": "status", "jail": "a" * 49},                   # too long
    {"op": "status", "jail": "-leading-dash"},
    {"op": "status", "jail": 12345678},
    {"op": "connect", "jail": JID, "target": "/run/docker.sock"},
    {"op": "signal", "jail": JID, "sig": "STOP"},
    {"op": "discard", "gen": "../gens"},
    _spawn_req(mem_mib=True),                             # bool is not an int
    _spawn_req(mem_mib=10**9),
    _spawn_req(vcpus=0),
    _spawn_req(outdisk_mib="600"),
    _spawn_req(ready_listener=1),
    _spawn_req(mode="exec"),
    _spawn_req(kernel="/boot/vmlinuz"),
])
def test_malformed_requests_are_refused(bad):
    with pytest.raises(h.ProtocolError):
        h.validate_request(bad, 0)


def test_descriptor_counts_are_exact():
    with pytest.raises(h.ProtocolError):
        h.validate_request({"op": "asset", "kind": "kernel"}, 0)
    with pytest.raises(h.ProtocolError):
        h.validate_request({"op": "hello"}, 1)


def test_oversized_messages_are_refused():
    with pytest.raises(h.ProtocolError):
        h.decode(b"{" + b" " * h.MAX_MSG + b"}")


# --------------------------------------------------------------------------- config / argv
def _cfg(tmp_path: Path, **over) -> h.HelperConfig:
    base = dict(socket_path=tmp_path / "run" / "h.sock", socket_gid=os.getgid(),
                allowed_uids=frozenset({os.getuid()}) if os.getuid() else frozenset({10001}),
                firecracker="/opt/fc/firecracker", jailer="/opt/fc/jailer",
                chroot_base=tmp_path / "jail", cgroup_parent_rel="blastbox.slice/jails",
                cgroup_root=tmp_path / "cg", uid_min=300000, uid_max=300003,
                apparmor="off", spawn_timeout_s=5.0)
    base.update(over)
    return h.HelperConfig(**base)  # type: ignore[arg-type]


def test_config_refuses_root_or_jail_uids_as_clients(tmp_path):
    with pytest.raises(ValueError):
        _cfg(tmp_path, allowed_uids=frozenset({0}))
    with pytest.raises(ValueError):
        _cfg(tmp_path, allowed_uids=frozenset({300001}))
    with pytest.raises(ValueError):
        _cfg(tmp_path, chroot_base=Path("/srv/x y"))


def test_jailer_argv_is_built_from_config_and_a_validated_id(tmp_path):
    cfg = _cfg(tmp_path)
    argv = h.jailer_argv(cfg, JID, 300001, exec_file="/x/firecracker-" + JID,
                         cgroups={"memory.max": "1"}, netns_path="/run/netns/bbfcj-" + JID)
    assert argv[0] == cfg.setpriv and "--no-new-privs" in argv
    assert argv[argv.index("--bounding-set") + 1].startswith("-all,")
    assert "+net_admin" not in argv[argv.index("--bounding-set") + 1]
    jailer = argv.index(cfg.jailer)
    assert argv[jailer:jailer + 3] == [cfg.jailer, "--id", JID]
    assert argv[-3:] == ["--", "--api-sock", "/fc-api.sock"]
    # in-place exec (the spawned pid IS the VMM), and Firecracker's seccomp never disabled
    for flag in ("--new-pid-ns", "--daemonize", "--no-seccomp", "--seccomp-filter"):
        assert flag not in argv
    with pytest.raises(h.HelperError):
        h.jailer_argv(cfg, "../x", 300001, exec_file="x", cgroups={}, netns_path="x")


def test_bounding_set_is_exactly_what_the_jailer_was_measured_to_need():
    assert set(h.JAILER_BOUNDING_CAPS) == {"chown", "dac_override", "mknod", "setgid", "setuid",
                                          "sys_admin"}
    mask = h.bounding_mask()
    assert bin(mask).count("1") == 6
    # net_admin, sys_module, sys_rawio, sys_chroot, ptrace, dac_read_search, kill, perfmon, bpf
    for cap in (12, 16, 17, 18, 19, 2, 5, 38, 39):
        assert not mask & (1 << cap)


def test_profile_is_per_jail_and_names_the_exact_listener_path(tmp_path):
    cfg = _cfg(tmp_path)
    listener = str(tmp_path / "jail" / f"firecracker-{JID}" / JID / "root" / "vsock.sock_10000")
    boot = h.render_profile(cfg, JID, boot=True, listener_host_path=listener)
    assert f"profile blastbox-fc-jail-{JID} /firecracker-{JID} " in boot
    assert f"  {listener} rw," in boot and "*/root" not in boot
    assert "owner /warm.mem rw," in boot and "deny capability," in boot
    assert "deny network inet," in boot and "deny /dev/net/tun rw," in boot
    restore = h.render_profile(cfg, JID, boot=False, listener_host_path=None)
    assert "/warm.mem r," in restore and "warm.mem rw" not in restore
    assert "/vmlinux" not in restore and "vsock.sock_" not in restore
    # No glob may grant write: every writable name is one fixed file (a glob lets an escaped VMM
    # create unboundedly many files in its own root, AppArmor or not).
    for profile in (boot, restore):
        assert not [ln for ln in profile.splitlines() if "*" in ln and " rw," in ln]


# --------------------------------------------------------------------------- live helper
FAKE_FC = r"""
import os, signal, socket, sys, time
root = sys.argv[1]
os.chdir(root)
api = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
api.bind("fc-api.sock"); api.listen(4)
vs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
vs.bind("vsock.sock"); vs.listen(4)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
while True:
    c, _ = api.accept()
    c.sendall(b"api-hello")
    c.close()
"""


class _SameUid:
    def __init__(self) -> None:
        self._free = [os.getuid()]

    def take(self) -> int:
        return os.getuid()

    def give(self, uid: int) -> None:
        self.given = uid


class _Env:
    """A Helper over a temp tree; the jailer is replaced by a fake firecracker that binds the
    API and vsock sockets in the jail root."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.cfg = _cfg(tmp_path)
        self.chowns: list[tuple] = []
        self.ran: list[list[str]] = []
        self.argvs: list[list[str]] = []
        (tmp_path / "cg" / self.cfg.cgroup_parent_rel).mkdir(parents=True)
        self.helper = h.Helper(self.cfg, popen=self._popen, run=self._run,
                               apparmor_enabled=False, fchown=self._fchown,
                               lchown=lambda p, u, g: self.chowns.append(("l", str(p), u, g)),
                               netns_dir=tmp_path / "netns")
        # Unprivileged: every jail "runs as" this uid, so the fake firecracker's sockets and
        # files carry the uid the helper allocated (the real jailer setuid()s to it).
        self.helper._uids = _SameUid()
        for d in (self.cfg.chroot_base, self.cfg.assets_dir, self.cfg.gens_dir,
                  self.cfg.bin_dir):
            d.mkdir(parents=True, exist_ok=True)
        (self.cfg.bin_dir / "firecracker").write_bytes(b"#!fake\n")
        self.owner = self.owner_for_self()

    def owner_for_self(self, pid: "int | None" = None) -> h.Owner:
        pid = pid or os.getpid()
        return self.helper.owner_for(pid, os.pidfd_open(os.getpid()))

    def _fchown(self, fd, u, g):
        self.chowns.append(("f", fd, u, g))

    def _run(self, argv, **kw):
        self.ran.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def _popen(self, argv, **kw):
        self.argvs.append(list(argv))
        jail_id = argv[argv.index("--id") + 1]
        root = self.cfg.chroot_base / h.exec_name(jail_id) / jail_id / "root"
        return subprocess.Popen([sys.executable, "-c", FAKE_FC, str(root)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def asset(self, kind: str, data: bytes) -> str:
        p = self.tmp / f"src-{kind}"
        p.write_bytes(data)
        fd = os.open(p, os.O_RDONLY)
        try:
            reply, _ = self.helper.op_asset(self.owner, {"op": "asset", "kind": kind}, [fd])
        finally:
            os.close(fd)
        return reply["asset"]

    def boot(self, jail_id: str = JID, owner: "h.Owner | None" = None, listener: bool = True):
        owner = owner or self.owner
        k = self.asset("kernel", b"KERNEL")
        r = self.asset("rootfs", b"ROOTFS" * 100)
        if owner is not self.owner:
            owner.assets.extend([k, r])
        reply, fds = self.helper.op_spawn(owner, {
            "op": "spawn", "jail": jail_id, "mode": "boot", "kernel": k, "rootfs": r,
            "gen": None, "outdisk_mib": 16, "mem_mib": 64, "vcpus": 1,
            "ready_listener": listener}, [])
        return self.helper._jails[jail_id], fds

    def kill(self, jail: h.Jail):
        self.helper.op_signal(self.owner, {"op": "signal", "jail": jail.id, "sig": "KILL"}, [])
        jail.proc.wait(5)


@pytest.fixture
def env(tmp_path):
    e = _Env(tmp_path)
    yield e
    for jail in list(e.helper._jails.values()):
        if jail.proc is not None and jail.proc.poll() is None:
            jail.proc.kill()
            jail.proc.wait(5)


def test_an_asset_is_copied_from_the_descriptor_and_made_read_only(env):
    aid = env.asset("rootfs", b"x" * 5000)
    asset = env.helper._assets[aid]
    assert Path(asset.path).read_bytes() == b"x" * 5000
    assert Path(asset.path).stat().st_mode & 0o777 == 0o444
    assert aid in env.owner.assets


def test_an_asset_must_be_a_regular_readable_file(env):
    r, w = os.pipe()
    try:
        with pytest.raises(h.HelperError, match="regular"):
            env.helper.op_asset(env.owner, {"op": "asset", "kind": "kernel"}, [r])
    finally:
        os.close(r)
        os.close(w)
    p = env.tmp / "f"
    p.write_bytes(b"k")
    fd = os.open(p, os.O_PATH)
    try:
        with pytest.raises(h.HelperError, match="not open for reading"):
            env.helper.op_asset(env.owner, {"op": "asset", "kind": "kernel"}, [fd])
    finally:
        os.close(fd)


def test_boot_spawn_stages_the_jail_and_hands_back_the_listener(env):
    jail, fds = env.boot()
    assert len(fds) == 1
    listener = socket.socket(fileno=fds[0])
    try:
        root = Path(jail.root)
        assert (root / "vmlinux").read_bytes() == b"KERNEL"
        assert (root / "rootfs.ext4").stat().st_nlink >= 2       # a hard link of the asset
        assert (root / "outdisk.ext4").stat().st_size == 16 << 20
        assert (root / "outdisk.ext4").stat().st_mode & 0o777 == 0o600
        assert any(c[0] == "f" and c[2] == jail.uid for c in env.chowns)
        import stat as _stat
        assert _stat.S_ISSOCK(os.lstat(root / "vsock.sock_10000").st_mode)
        assert jail.listener_path == str(root / "vsock.sock_10000")
        assert any(argv[1:4] == ["netns", "add", f"bbfcj-{JID}"] for argv in env.ran)
        assert any(argv[0] == env.cfg.mkfs for argv in env.ran)
        argv = env.argvs[-1]
        assert argv[argv.index("--uid") + 1] == str(jail.uid)
        assert "--cgroup" in argv and "memory.swap.max=0" in argv
    finally:
        listener.close()


def test_connect_hands_back_a_connected_socket_to_the_jails_own_api(env):
    jail, fds = env.boot(listener=False)
    assert fds == []
    _, out = env.helper.op_connect(env.owner, {"op": "connect", "jail": JID, "target": "api"}, [])
    s = socket.socket(fileno=out[0])
    try:
        assert s.recv(64) == b"api-hello"
    finally:
        s.close()


def test_connect_never_follows_a_symlink_the_jail_planted(env, tmp_path):
    """The jail uid owns its root: a symlink named fc-api.sock pointing at a host socket must
    not become a root-opened connection handed to the client."""
    jail, _ = env.boot(listener=False)
    target = tmp_path / "host.sock"
    host = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    host.bind(str(target))
    host.listen(1)
    try:
        (Path(jail.root) / "vsock.sock").unlink()
        (Path(jail.root) / "vsock.sock").symlink_to(target)
        with pytest.raises(h.HelperError, match="no_socket"):
            env.helper.op_connect(env.owner, {"op": "connect", "jail": JID, "target": "vsock"}, [])
    finally:
        host.close()


def test_a_socket_not_owned_by_the_jail_uid_is_not_connected(env):
    jail, _ = env.boot(listener=False)
    jail.uid = os.getuid() + 1     # the sockets below were NOT created by this jail's uid
    with pytest.raises(h.HelperError, match="no_socket"):
        env.helper.op_connect(env.owner, {"op": "connect", "jail": JID, "target": "vsock"}, [])


def test_another_owner_cannot_see_or_touch_a_jail(env):
    env.boot(listener=False)
    other = h.Owner(pid=999999, pidfd=os.pidfd_open(os.getpid()))
    for op, extra in (("status", {}), ("seal", {}), ("outdisk", {}), ("publish", {}),
                      ("destroy", {}), ("signal", {"sig": "KILL"}),
                      ("connect", {"target": "api"})):
        with pytest.raises(h.HelperError) as exc:
            env.helper.handle(other, {"op": op, "jail": JID, **extra}, [])
        assert exc.value.code == "unknown_jail", op
    assert env.helper._jails[JID].proc.poll() is None


def test_destroy_refuses_a_live_jail_and_cleans_up_an_exited_one(env):
    jail, fds = env.boot()
    socket.socket(fileno=fds[0]).close()
    with pytest.raises(h.HelperError, match="alive"):
        env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    env.kill(jail)
    uid = jail.uid
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    assert not Path(jail.top).exists()
    assert JID not in env.helper._jails and JID not in env.owner.jails
    assert any(argv[1:4] == ["netns", "del", f"bbfcj-{JID}"] for argv in env.ran)
    assert env.helper._uids.given == uid


def _snapshot(jail: h.Jail, mem_size: int = 64 << 20) -> None:
    (Path(jail.root) / "warm.snapshot").write_bytes(b"state")
    with open(Path(jail.root) / "warm.mem", "wb") as f:
        f.truncate(mem_size)


def test_publish_requires_the_base_to_be_gone(env):
    jail, _ = env.boot(listener=False)
    _snapshot(jail)
    with pytest.raises(h.HelperError, match="alive"):
        env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])


def test_publish_makes_a_root_owned_read_only_generation(env):
    jail, _ = env.boot(listener=False)
    _snapshot(jail)
    env.kill(jail)
    reply, _ = env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])
    gdir = Path(reply["dir"])
    for name in ("warm.snapshot", "warm.mem", "outdisk.ext4"):
        assert (gdir / name).stat().st_mode & 0o777 == 0o444
    assert not (Path(jail.root) / "warm.mem").exists()      # moved out of the jail's reach
    assert any(c[0] == "f" and c[2:] == (0, 0) for c in env.chowns)
    assert reply["gen"] in env.owner.gens
    assert gdir.stat().st_mode & 0o777 == 0o700          # root-only, like gens/ itself


def test_the_state_tree_is_root_only(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "_check_root_dir", lambda p: None)
    fcbin = tmp_path / "fc"
    fcbin.write_bytes(b"#!fake\n")
    cfg = _cfg(tmp_path, firecracker=str(fcbin), chroot_base=tmp_path / "base")
    (tmp_path / "base").mkdir(mode=0o755)
    helper = h.Helper(cfg, apparmor_enabled=False, lchown=lambda p, u, g: None)
    helper._prepare_state_tree()
    for d in (cfg.chroot_base, cfg.assets_dir, cfg.gens_dir, cfg.bin_dir):
        assert d.stat().st_mode & 0o777 == 0o700, d


@pytest.mark.parametrize("plant", ["symlink", "hardlink", "oversized"])
def test_publish_refuses_files_the_jail_could_have_planted(env, tmp_path, plant):
    jail, _ = env.boot(listener=False)
    _snapshot(jail)
    env.kill(jail)
    mem = Path(jail.root) / "warm.mem"
    if plant == "symlink":
        mem.unlink()
        secret = tmp_path / "secret"
        secret.write_bytes(b"root-only")
        mem.symlink_to(secret)
    elif plant == "hardlink":
        os.link(mem, tmp_path / "elsewhere")
    else:
        with open(mem, "r+b") as f:
            f.truncate((64 << 20) + (2 << 20))
    with pytest.raises(h.HelperError, match="bad_snapshot"):
        env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])
    assert not list(env.cfg.gens_dir.iterdir())


def test_restore_uses_the_generation_and_a_discarded_one_waits_for_its_jails(env):
    base, _ = env.boot(listener=False)
    _snapshot(base)
    env.kill(base)
    gen = env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])[0]["gen"]
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    env.helper.op_spawn(env.owner, {
        "op": "spawn", "jail": JID2, "mode": "restore", "kernel": None, "rootfs": None,
        "gen": gen, "outdisk_mib": 16, "mem_mib": 64, "vcpus": 1, "ready_listener": False}, [])
    slot = env.helper._jails[JID2]
    assert (Path(slot.root) / "warm.mem").stat().st_ino == (Path(env.helper._gens[gen].dir) / "warm.mem").stat().st_ino
    assert (Path(slot.root) / "outdisk.ext4").stat().st_mode & 0o777 == 0o600
    gdir = Path(env.helper._gens[gen].dir)
    env.helper.op_discard(env.owner, {"op": "discard", "gen": gen}, [])
    assert gdir.exists(), "a generation a live jail maps was deleted"
    with pytest.raises(h.HelperError, match="unknown_gen"):
        env.helper.op_spawn(env.owner, {
            "op": "spawn", "jail": "2d6b8f3a-3333-4444-8555-b66677778888", "mode": "restore",
            "kernel": None, "rootfs": None, "gen": gen, "outdisk_mib": 16, "mem_mib": 64,
            "vcpus": 1, "ready_listener": False}, [])
    env.kill(slot)
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID2}, [])
    assert not gdir.exists()


def test_a_generation_belongs_to_its_owner(env):
    base, _ = env.boot(listener=False)
    _snapshot(base)
    env.kill(base)
    gen = env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])[0]["gen"]
    other = h.Owner(pid=999998, pidfd=os.pidfd_open(os.getpid()))
    with pytest.raises(h.HelperError, match="unknown_gen"):
        env.helper.op_discard(other, {"op": "discard", "gen": gen}, [])
    with pytest.raises(h.HelperError, match="unknown_gen"):
        env.helper.op_spawn(other, {
            "op": "spawn", "jail": JID2, "mode": "restore", "kernel": None, "rootfs": None,
            "gen": gen, "outdisk_mib": 16, "mem_mib": 64, "vcpus": 1, "ready_listener": False}, [])


def test_a_dead_owners_jails_are_killed_and_reclaimed(env):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        owner = env.helper.owner_for(child.pid, os.pidfd_open(child.pid))
        jail, _ = env.boot(owner=owner, listener=False)
        assert jail.proc.poll() is None
        child.kill()
        child.wait(5)
        env.helper.monitor_once()
        assert jail.proc.poll() is not None
        assert JID not in env.helper._jails and not Path(jail.top).exists()
        assert child.pid not in env.helper._owners
    finally:
        if child.poll() is None:
            child.kill()


def test_per_owner_jail_limit(env):
    env.helper.cfg = h.HelperConfig(**{**env.cfg.__dict__, "max_jails_per_owner": 1})
    env.boot(listener=False)
    with pytest.raises(h.HelperError, match="exhausted"):
        env.boot(jail_id=JID2, listener=False)


def test_a_failed_spawn_leaves_nothing_behind(env):
    def boom(argv, **kw):
        raise OSError("jailer missing")
    env.helper._popen = boom
    with pytest.raises(OSError):
        env.boot(listener=False)
    assert JID not in env.helper._jails
    assert not (env.cfg.chroot_base / h.exec_name(JID)).exists()
    assert env.helper._uids.given == os.getuid()        # the uid went back


# --------------------------------------------------------------------------- confinement check
def _proc_tree(tmp_path: Path, threads: dict[str, dict[str, str]], label: str) -> Path:
    root = tmp_path / "proc"
    for tid, fields in threads.items():
        d = root / "4242" / "task" / tid
        d.mkdir(parents=True)
        (d / "status").write_text("".join(f"{k}:\t{v}\n" for k, v in fields.items()))
    (root / "4242" / "attr").mkdir(parents=True)
    (root / "4242" / "attr" / "current").write_text(label + "\n")
    return root


_GOOD = {"Uid": "300001\t300001\t300001\t300001", "Seccomp": "2", "NoNewPrivs": "1",
         "CapInh": "0" * 16, "CapPrm": "0" * 16, "CapEff": "0" * 16, "CapAmb": "0" * 16,
         "CapBnd": f"{h.bounding_mask():016x}"}


@pytest.mark.parametrize("bad,expect", [
    ({"Seccomp": "0"}, "Seccomp"),
    ({"NoNewPrivs": "0"}, "NoNewPrivs"),
    ({"CapEff": "0000000000200000"}, "CapEff"),
    ({"CapBnd": "000001ffffffffff"}, "CapBnd"),
    ({"Uid": "0\t0\t0\t0"}, "Uid"),
])
def test_seal_refuses_any_thread_that_is_not_confined(tmp_path, bad, expect):
    root = _proc_tree(tmp_path, {"4242": _GOOD, "4250": {**_GOOD, **bad}},
                      f"blastbox-fc-jail-{JID} (enforce)")
    helper = h.Helper(_cfg(tmp_path), apparmor_enabled=False, proc_root=root)
    problems = helper.verify_confinement(4242)
    assert problems and all("4250" in p for p in problems) and expect in problems[0]


def test_seal_accepts_a_confined_vmm_and_checks_its_own_profile(tmp_path):
    root = _proc_tree(tmp_path, {"4242": _GOOD, "4243": _GOOD}, f"blastbox-fc-jail-{JID} (enforce)")
    helper = h.Helper(_cfg(tmp_path), apparmor_enabled=False, proc_root=root)
    assert helper.verify_confinement(4242) == []
    helper.apparmor = True
    assert helper.verify_confinement(4242, f"blastbox-fc-jail-{JID}") == []
    assert helper.verify_confinement(4242, f"blastbox-fc-jail-{JID2}")   # someone else's profile


# --------------------------------------------------------------------------- socket loop
def test_serve_conn_answers_an_allowed_peer_and_validates(env):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        a.send(h.encode({"op": "hello"}))
        env.helper.serve_conn(b)
        reply = h.decode(a.recv(h.MAX_MSG))
        assert reply["ok"] and reply["protocol"] == h.PROTOCOL_VERSION
    finally:
        a.close()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        a.send(b'{"op":"spawn","jail":"../../x"}')
        env.helper.serve_conn(b)
        reply = h.decode(a.recv(h.MAX_MSG))
        assert reply == {"ok": False, "error": "protocol", "detail": reply["detail"]}
    finally:
        a.close()


def test_serve_conn_refuses_a_peer_whose_uid_is_not_allowed(tmp_path):
    cfg = _cfg(tmp_path, allowed_uids=frozenset({os.getuid() + 1}))
    helper = h.Helper(cfg, apparmor_enabled=False)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        a.send(h.encode({"op": "hello"}))
        helper.serve_conn(b)
        time.sleep(0.5)          # the sink has closed the connection by now, warm or cold
        # The reply survives the close: the request was read (not left queued, which makes the
        # close an ECONNRESET the client sees INSTEAD of the reply -- "refused", undecided).
        reply = h.decode(a.recv(h.MAX_MSG))
        # Told it is not allowed (decided, never retried as an outage), and nothing it sent
        # was acted on: no owner registered, no hello answered.
        assert reply == {"ok": False, "error": "forbidden",
                         "detail": f"uid {os.getuid()} is not allowed (--allow-uid)"}
        assert not helper._owners
        assert a.recv(h.MAX_MSG) == b""
    finally:
        a.close()


def test_sparse_copy_keeps_holes_and_data(tmp_path):
    src = tmp_path / "src"
    with open(src, "wb") as f:
        f.truncate(64 << 20)
        f.seek(10 << 20)
        f.write(b"middle")
        f.seek((64 << 20) - 3)
        f.write(b"end")
    s = os.open(src, os.O_RDONLY)
    d = os.open(tmp_path / "dst", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        h.sparse_copy(s, d, 64 << 20)
    finally:
        os.close(s)
        os.close(d)
    assert (tmp_path / "dst").read_bytes() == src.read_bytes()
    assert os.stat(tmp_path / "dst").st_blocks * 512 < 8 << 20


def test_signal_constants_cover_only_term_and_kill():
    assert set(h.SIGNALS.values()) == {signal.SIGTERM, signal.SIGKILL}


def test_monitor_reaps_exited_jail_processes(env):
    jail, _ = env.boot(listener=False)
    jail.proc.kill()
    deadline = time.monotonic() + 5
    while jail.proc.poll() is None and time.monotonic() < deadline:
        env.helper.monitor_once()
        time.sleep(0.02)
    assert jail.proc.returncode is not None


def test_a_recycled_pid_does_not_inherit_the_dead_owners_jails(env):
    """The old owner died and its pid was reused before the monitor noticed: the newcomer
    connecting under that pid is a NEW owner with nothing."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    old = env.helper.owner_for(424242, os.pidfd_open(child.pid))
    jail, _ = env.boot(owner=old, listener=False)
    child.kill()
    child.wait(5)
    new = env.helper.owner_for(424242, os.pidfd_open(os.getpid()))
    assert new is not old and old.dead
    with pytest.raises(h.HelperError, match="unknown_jail"):
        env.helper.op_status(new, {"op": "status", "jail": JID}, [])
    assert jail.proc.poll() is not None and JID not in env.helper._jails


def test_concurrent_first_contacts_share_one_owner(env):
    import concurrent.futures as cf

    with cf.ThreadPoolExecutor(8) as ex:
        owners = list(ex.map(lambda _: env.helper.owner_for(515151, os.pidfd_open(os.getpid())),
                             range(16)))
    assert all(o is owners[0] for o in owners)


def test_leftover_cleanup_touches_only_this_helpers_own_jails(env):
    """A second helper instance on the host (another chroot base) must keep its namespaces."""
    mine = env.cfg.chroot_base / h.exec_name(JID) / JID / "root"
    mine.mkdir(parents=True)
    env.helper._netns_dir.mkdir(parents=True, exist_ok=True)
    for jid in (JID, JID2):
        (env.helper._netns_dir / f"bbfcj-{jid}").write_text("")
    env.ran.clear()
    env.helper.cleanup_leftovers()
    deleted = [argv[3] for argv in env.ran if argv[1:3] == ["netns", "del"]]
    assert deleted == [f"bbfcj-{JID}"]
    assert not (env.cfg.chroot_base / h.exec_name(JID)).exists()


def _open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_spawn_and_destroy_leak_no_descriptors(env):
    jail, _ = env.boot(listener=False)            # warm-up: asset copies, threads
    env.kill(jail)
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    before = _open_fds()
    for _ in range(3):
        jail, _ = env.boot(listener=False)
        env.helper._wait_api(jail)                # the readiness probe must close its O_PATH fd
        env.kill(jail)
        env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    assert _open_fds() <= before


def test_the_monitor_retries_a_dead_owners_failed_teardown(env):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    owner = env.helper.owner_for(child.pid, os.pidfd_open(child.pid))
    jail, _ = env.boot(owner=owner, listener=False)
    real = env.helper._destroy
    calls = {"n": 0}

    def flaky(j, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise h.HelperError("cleanup_failed", "transient")
        real(j, **kw)
    env.helper._destroy = flaky
    child.kill()
    child.wait(5)
    env.helper.monitor_once()        # reaps the owner (the first destroy fails), then retries
    assert calls["n"] == 2
    assert JID not in env.helper._jails and not Path(jail.top).exists()


def test_a_reaped_owner_cannot_register_a_jail_after_the_fact(env):
    env.owner.dead = True
    with pytest.raises(h.HelperError, match="unknown_jail"):
        env.boot(listener=False)
    assert JID not in env.helper._jails


def test_uid_exhaustion_leaks_no_asset_references(env):
    class _Empty:
        def take(self):
            raise h.HelperError("exhausted", "uid range")

        def give(self, uid):
            pass
    env.helper._uids = _Empty()
    with pytest.raises(h.HelperError, match="exhausted"):
        env.boot(listener=False)
    assert all(a.refs == 0 for a in env.helper._assets.values())


def test_a_spawn_whose_reply_is_lost_is_undone(env):
    """The client timed out (or died) mid-spawn: nobody would ever destroy that jail."""
    k = env.asset("kernel", b"K")
    r = env.asset("rootfs", b"R" * 64)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    a.send(h.encode({"op": "spawn", "jail": JID, "mode": "boot", "kernel": k, "rootfs": r,
                     "gen": None, "outdisk_mib": 16, "mem_mib": 64, "vcpus": 1,
                     "ready_listener": False}))
    real_spawn = env.helper.op_spawn

    def spawn_then_client_leaves(owner, req, fds):
        out = real_spawn(owner, req, fds)
        a.close()
        return out
    env.helper.op_spawn = spawn_then_client_leaves
    env.helper.serve_conn(b)
    assert JID not in env.helper._jails


def test_an_overloaded_helper_says_busy_and_the_client_retries(tmp_path, monkeypatch):
    from blastbox.host.runtime import fc_jail

    client = fc_jail.JailClient(str(tmp_path / "x.sock"))
    answers = [fc_jail.JailError("busy", "overloaded")] * 2 + [({"ok": True, "v": 1}, [])]
    monkeypatch.setattr(fc_jail.time, "sleep", lambda s: None)

    def once(op, **kw):
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    monkeypatch.setattr(client, "_call_once", once)
    assert client.call("hello")[0]["v"] == 1


def test_a_vmm_grown_output_disk_is_refused(env):
    jail, _ = env.boot(listener=False)
    with open(Path(jail.root) / "outdisk.ext4", "r+b") as f:
        f.truncate(4 << 30)
    with pytest.raises(h.HelperError, match="bad_outdisk"):
        env.helper.op_outdisk(env.owner, {"op": "outdisk", "jail": JID}, [])


def test_the_jail_gets_a_file_size_limit(env):
    env.boot(listener=False)
    argv = env.argvs[-1]
    limits = [argv[i + 1] for i, a in enumerate(argv) if a == "--resource-limit"]
    assert any(x.startswith("fsize=") and int(x.split("=")[1]) >= 64 << 20 for x in limits)


def test_a_jail_still_being_staged_is_not_exited_and_cannot_be_destroyed(env):
    seen = {}
    real_start = env.helper._start

    def start_with_a_destroy_racing_it(jail, req, gen):
        with pytest.raises(h.HelperError, match="alive"):
            env.helper.op_destroy(env.owner, {"op": "destroy", "jail": jail.id}, [])
        seen["uid_still_held"] = jail.uid
        return real_start(jail, req, gen)
    env.helper._start = start_with_a_destroy_racing_it
    jail, _ = env.boot(listener=False)
    assert not jail.destroyed and jail.proc.poll() is None
    assert seen["uid_still_held"] == jail.uid


def test_an_asset_is_read_through_the_clients_own_descriptor(env, tmp_path, monkeypatch):
    """No root reopen of the client's fd (a new description would carry ROOT credentials)."""
    p = tmp_path / "k"
    p.write_bytes(b"K" * 9000)
    fd = os.open(p, os.O_RDONLY)
    os.lseek(fd, 123, os.SEEK_SET)
    real_open = os.open

    def no_proc_reopen(path, *a, **k):
        assert not str(path).startswith("/proc/self/fd/"), "reopened the client's descriptor"
        return real_open(path, *a, **k)
    monkeypatch.setattr(h.os, "open", no_proc_reopen)
    try:
        aid = env.helper.op_asset(env.owner, {"op": "asset", "kind": "kernel"}, [fd])[0]["asset"]
        assert os.lseek(fd, 0, os.SEEK_CUR) == 123          # the client's offset is untouched
    finally:
        os.close(fd)
    assert Path(env.helper._assets[aid].path).read_bytes() == b"K" * 9000


def test_client_processes_and_generations_are_capped(env):
    env.helper.cfg = h.HelperConfig(**{**env.cfg.__dict__, "max_owners": 1})
    with pytest.raises(h.HelperError, match="exhausted"):
        env.helper.owner_for(777001, os.pidfd_open(os.getpid()))
    env.helper.cfg = h.HelperConfig(**{**env.cfg.__dict__, "max_gens_per_owner": 1})
    base, _ = env.boot(listener=False)
    _snapshot(base)
    env.kill(base)
    env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    second, _ = env.boot(jail_id=JID2, listener=False)
    _snapshot(second)
    env.kill(second)
    with pytest.raises(h.HelperError, match="exhausted"):
        env.helper.op_publish(env.owner, {"op": "publish", "jail": JID2}, [])


def test_the_profile_grants_no_writable_tree():
    cfg = h.HelperConfig(socket_path=Path("/run/x/h.sock"), socket_gid=1,
                         allowed_uids=frozenset({10001}), firecracker="/f", jailer="/j",
                         chroot_base=Path("/srv/j"))
    text = h.render_profile(cfg, JID, boot=False, listener_host_path=None)
    assert "/run/** " not in text and "** rw" not in text


def test_a_sparse_asset_stays_sparse_and_the_client_offset_is_restored(env, tmp_path):
    p = tmp_path / "sparse-rootfs"
    with open(p, "wb") as f:
        f.truncate(256 << 20)
        f.seek(100 << 20)
        f.write(b"data")
    fd = os.open(p, os.O_RDONLY)
    os.lseek(fd, 77, os.SEEK_SET)
    try:
        aid = env.helper.op_asset(env.owner, {"op": "asset", "kind": "rootfs"}, [fd])[0]["asset"]
        assert os.lseek(fd, 0, os.SEEK_CUR) == 77
    finally:
        os.close(fd)
    copy = Path(env.helper._assets[aid].path)
    assert copy.stat().st_size == 256 << 20 and copy.stat().st_blocks * 512 < 16 << 20


def test_releasing_a_lingering_client_socket_does_not_block():
    c, peer, srv = _lingering_socket()
    sink = h.FdSink()
    try:
        t0 = time.monotonic()
        sink.release([c.detach()])
        sink.release([os.open("/dev/null", os.O_RDONLY)])    # the wedged sink is replaced
        assert time.monotonic() - t0 < 5.0
    finally:
        sink.close()
        peer.close()
        srv.close()


def test_a_nested_lingering_socket_cannot_pin_the_helper(env):
    """An AF_UNIX socket whose queue holds a lingering socket: its final release would run the
    inner socket's linger in whichever thread drops the last reference."""
    c, peer, srv = _lingering_socket()
    x, y = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    socket.send_fds(x, [b"n"], [c.fileno()])
    c.close()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        socket.send_fds(a, [h.encode({"op": "hello"})], [y.fileno()])
        x.close()
        y.close()
        t0 = time.monotonic()
        env.helper.serve_conn(b)
        assert time.monotonic() - t0 < 5.0
    finally:
        a.close()
        env.helper._sink.close()
        peer.close()
        srv.close()

def test_concurrent_publishes_cannot_exceed_the_generation_cap(env):
    env.helper.cfg = h.HelperConfig(**{**env.cfg.__dict__, "max_gens_per_owner": 1})
    base, _ = env.boot(listener=False)
    _snapshot(base)
    env.kill(base)
    env.owner.publishing = 1                     # another publish is in flight
    with pytest.raises(h.HelperError, match="exhausted"):
        env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])
    env.owner.publishing = 0
    env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])
    assert env.owner.publishing == 0


def test_outdisk_reads_the_descriptor_under_the_jail_lock(env):
    """A destroy closing outdisk_fd between the size check and the reopen would let the number
    be reused by another owner's file."""
    jail, _ = env.boot(listener=False)
    held = []

    class _Rec:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            self.inner.acquire()
            held.append(True)

        def __exit__(self, *a):
            held.append(False)
            self.inner.release()
    jail.lock = _Rec(threading.Lock())
    real = env.helper._outdisk_locked

    def check(j):
        assert held and held[-1] is True, "outdisk_fd used without the jail lock"
        return real(j)
    env.helper._outdisk_locked = check
    _, fds = env.helper.op_outdisk(env.owner, {"op": "outdisk", "jail": JID}, [])
    os.close(fds[0])
    jail.lock = threading.Lock()
    env.kill(jail)
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])


def _lingering_socket():
    import struct
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    c = socket.create_connection(srv.getsockname())
    peer, _ = srv.accept()
    c.setblocking(False)
    try:
        while True:
            c.send(b"x" * 65536)
    except BlockingIOError:
        pass
    c.setblocking(True)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 30))
    return c, peer, srv


@pytest.mark.parametrize("shape", ["excess-fds", "second-message", "empty-record-first"])
def test_a_lingering_socket_the_kernel_would_release_cannot_pin_the_helper(env, shape):
    c, peer, srv = _lingering_socket()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    r, w = os.pipe()
    try:
        if shape == "excess-fds":
            socket.send_fds(a, [h.encode({"op": "hello"})], [r, w, c.fileno()])
        elif shape == "second-message":
            a.send(h.encode({"op": "hello"}))
            socket.send_fds(a, [b"x"], [c.fileno()])
        else:
            a.send(h.encode({"op": "hello"}))
            a.send(b"")
            socket.send_fds(a, [b"x"], [c.fileno()])
        c.close()
        os.close(r)
        os.close(w)
        t0 = time.monotonic()
        env.helper.serve_conn(b)
        assert time.monotonic() - t0 < 5.0
    finally:
        a.close()
        env.helper._sink.close()
        peer.close()
        srv.close()


def test_reaping_skips_a_jail_whose_publish_holds_its_lock(env):
    """A slow publish must not stall the monitor (and every other owner's reaping)."""
    jail, _ = env.boot(listener=False)
    env.kill(jail)
    jail.lock.acquire()
    try:
        t0 = time.monotonic()
        with pytest.raises(h.HelperError, match="busy"):
            env.helper._destroy(jail, wait=False)
        assert time.monotonic() - t0 < 1.0
    finally:
        jail.lock.release()
    env.helper._destroy(jail, wait=False)
    assert jail.destroyed


def test_a_sink_that_cannot_start_never_raises_into_the_helper():
    def no_processes(*a, **kw):
        raise OSError(11, "Resource temporarily unavailable")
    sink = h.FdSink(popen=no_processes)
    r, w = os.pipe()
    sink.release([r])                  # logged and kept, never raised
    os.close(w)


def test_replacing_a_wedged_sink_is_a_swap_not_a_two_second_stall():
    c, peer, srv = _lingering_socket()
    sink = h.FdSink()
    try:
        sink.release([os.open("/dev/null", os.O_RDONLY)])     # starts a sink (+ a spare)
        sink.release([c.detach()])                            # wedges it in a lingering close
        time.sleep(h._SINK_GRACE_S + 0.1)
        deadline = time.monotonic() + 5
        while sink._spare is None and time.monotonic() < deadline:
            time.sleep(0.02)
        t0 = time.monotonic()
        sink.release([os.open("/dev/null", os.O_RDONLY)])
        assert time.monotonic() - t0 < 0.5
    finally:
        sink.close()
        peer.close()
        srv.close()


def test_no_thread_to_reap_a_sink_never_raises_into_a_release(monkeypatch):
    sink = h.FdSink()
    try:
        sink.release([os.open("/dev/null", os.O_RDONLY)])
        real = threading.Thread.start

        def no_threads(self):
            raise RuntimeError("can't start new thread")
        monkeypatch.setattr(threading.Thread, "start", no_threads)
        sink._outstanding[999] = time.monotonic() - 10   # looks wedged: killed and replaced
        sink.release([os.open("/dev/null", os.O_RDONLY)])
        monkeypatch.setattr(threading.Thread, "start", real)
    finally:
        sink.close()


def test_ordinary_traffic_does_not_replace_a_healthy_sink():
    sink = h.FdSink()
    started = []
    real = sink._spawn_sink

    def counting():
        started.append(1)
        return real()
    sink._spawn_sink = counting
    try:
        for _ in range(200):
            sink.release([os.open("/dev/null", os.O_RDONLY)])
        time.sleep(0.3)
        assert len(started) <= 2               # the first sink and its spare
    finally:
        sink.close()


def test_every_link_in_an_executables_resolution_chain_is_checked(tmp_path, monkeypatch):
    """p -> D/current -> real: the directory D holding the INTERMEDIATE link must be checked
    too (a user who can write D repoints 'current' at their own binary)."""
    good = tmp_path / "opt"
    good.mkdir()
    (good / "fc").write_text("#!/bin/sh\n")
    (good / "fc").chmod(0o755)
    d = tmp_path / "builder"
    d.mkdir()
    (d / "current").symlink_to(good / "fc")
    link = tmp_path / "link"
    link.symlink_to(d / "current")
    real_lstat = os.lstat
    d_ident = (real_lstat(d).st_dev, real_lstat(d).st_ino)

    def faked(p, *a, **k):              # everything root-owned and 0755, except D (writable)
        st = real_lstat(p, *a, **k)
        vals = list(st)
        vals[4] = 0
        mode = st.st_mode & ~0o022
        if (st.st_dev, st.st_ino) == d_ident:
            mode |= 0o002
        vals[0] = mode
        return os.stat_result(vals)
    monkeypatch.setattr(h.os, "lstat", faked)
    with pytest.raises(RuntimeError, match="builder"):
        h._check_root_owned_exec("firecracker", str(link))
    # ...and the same chain with D not writable passes.
    monkeypatch.setattr(h.os, "lstat", lambda p, *a, **k: os.stat_result(
        [real_lstat(p, *a, **k).st_mode & ~0o022, *list(real_lstat(p, *a, **k))[1:4], 0,
         *list(real_lstat(p, *a, **k))[5:]]))
    h._check_root_owned_exec("firecracker", str(link))

def test_a_generation_whose_files_cannot_be_removed_stays_tracked(env, monkeypatch):
    base, _ = env.boot(listener=False)
    _snapshot(base)
    env.kill(base)
    gen = env.helper.op_publish(env.owner, {"op": "publish", "jail": JID}, [])[0]["gen"]
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    real = h.shutil.rmtree
    monkeypatch.setattr(h.shutil, "rmtree",
                        lambda p, onerror=None, **k: onerror(None, p, None) if onerror else None)
    env.helper.op_discard(env.owner, {"op": "discard", "gen": gen}, [])
    assert gen in env.helper._gens                       # failed removal: still tracked
    monkeypatch.setattr(h.shutil, "rmtree", real)
    env.helper.monitor_once()                            # ...and retried
    assert gen not in env.helper._gens


def test_an_asset_copied_for_an_owner_reaped_meanwhile_is_not_kept(env):
    real = env.helper._copy_asset

    def copy_then_owner_dies(*a, **k):
        out = real(*a, **k)
        env.owner.dead = True
        return out
    env.helper._copy_asset = copy_then_owner_dies
    with pytest.raises(h.HelperError, match="unknown_jail"):
        env.asset("kernel", b"K" * 100)
    assert not env.helper._assets


def test_signals_go_through_the_pidfd_only_under_its_lock(env):
    jail, _ = env.boot(listener=False)
    with jail.pidfd_lock:
        t = threading.Thread(target=env.helper._signal, args=(jail, signal.SIGKILL))
        t.start()
        t.join(0.3)
        assert t.is_alive()                              # waits for the lock destroy also takes
    t.join(5)
    jail.proc.wait(5)
    env.helper.op_destroy(env.owner, {"op": "destroy", "jail": JID}, [])
    assert jail.pidfd is None
    env.helper._signal(jail, signal.SIGKILL)             # a closed pidfd is never used


def test_a_wedged_close_never_delays_the_next_acknowledgement():
    """Inside the grace period the wedged sink is still in use: its next ACK must be prompt."""
    c, peer, srv = _lingering_socket()
    sink = h.FdSink()
    try:
        sink.release([os.open("/dev/null", os.O_RDONLY)])
        sink.release([c.detach()])                 # its close lingers
        t0 = time.monotonic()
        sink.release([os.open("/dev/null", os.O_RDONLY)])   # within the grace: same sink
        assert time.monotonic() - t0 < 0.5
    finally:
        sink.close()
        peer.close()
        srv.close()


def test_a_batch_stuck_closing_is_caught_even_while_later_batches_complete():
    """Per-batch accounting: later batches finishing must not hide one stuck forever."""
    c, peer, srv = _lingering_socket()
    sink = h.FdSink()
    try:
        sink.release([os.open("/dev/null", os.O_RDONLY)])
        first_proc = sink._proc
        sink.release([c.detach()])                       # stuck in a lingering close
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and sink._proc is first_proc:
            sink.release([os.open("/dev/null", os.O_RDONLY)])   # healthy batches keep flowing
            time.sleep(0.05)
        assert sink._proc is not first_proc, "the wedged sink was never replaced"
    finally:
        sink.close()
        peer.close()
        srv.close()


def test_descriptors_a_full_sink_could_not_install_go_to_a_fresh_sink():
    """The kernel installs only what fits and drops the rest: the helper must not close its
    copies of those (that close would be their final release) -- they go to a new sink."""
    import resource

    def small_sink(argv, **kw):
        kw["preexec_fn"] = lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        return subprocess.Popen(argv, **kw)
    sink = h.FdSink(popen=small_sink)
    pipes = [os.pipe() for _ in range(40)]
    try:
        sink.release([w for _, w in pipes])           # 40 write ends: no sink can take them all
        deadline = time.monotonic() + 10
        for r, _ in pipes:                             # EOF on every read end: every copy closed
            os.set_blocking(r, False)
            while True:
                try:
                    if os.read(r, 1) == b"":
                        break
                except BlockingIOError:
                    assert time.monotonic() < deadline, "a write end was never closed"
                    time.sleep(0.02)
    finally:
        for r, _ in pipes:
            os.close(r)
        sink.close()


def test_dropping_an_asset_never_waits_for_a_registration_holding_its_stripe(env):
    aid = env.asset("kernel", b"K" * 10)
    env.owner.assets.clear()
    stripe = env.helper._asset_locks[int(aid[1:9], 16) % len(env.helper._asset_locks)]
    with stripe:
        t0 = time.monotonic()
        env.helper._maybe_drop_asset(aid)
        assert time.monotonic() - t0 < 0.5 and aid in env.helper._assets
    env.helper.monitor_once()                          # swept on a later tick
    assert aid not in env.helper._assets


def test_a_lingering_socket_beyond_a_full_sinks_table_never_closes_in_the_helper():
    import resource

    def small_sink(argv, **kw):
        kw["preexec_fn"] = lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        return subprocess.Popen(argv, **kw)
    c, peer, srv = _lingering_socket()
    sink = h.FdSink(popen=small_sink)
    pipes = [os.pipe() for _ in range(20)]
    try:
        t0 = time.monotonic()
        sink.release([w for _, w in pipes] + [c.detach()])   # the socket lands past the limit
        assert time.monotonic() - t0 < 5.0
    finally:
        for r, _ in pipes:
            os.close(r)
        sink.close()
        peer.close()
        srv.close()


def test_a_registered_asset_is_pinned_before_the_sweep_can_see_it(env, tmp_path):
    stop = threading.Event()

    def sweeper():
        while not stop.is_set():
            env.helper.monitor_once()
    t = threading.Thread(target=sweeper, daemon=True)
    t.start()
    try:
        for i in range(40):
            p = tmp_path / f"k{i}"
            p.write_bytes(b"K" * (i + 1))
            fd = os.open(p, os.O_RDONLY)
            try:
                aid = env.helper.op_asset(env.owner, {"op": "asset", "kind": "kernel"}, [fd])[0]["asset"]
            finally:
                os.close(fd)
            assert aid in env.helper._assets, f"swept between registration and pin ({i})"
    finally:
        stop.set()
        t.join(5)


def test_a_sink_is_replaced_before_it_holds_too_many_descriptors(monkeypatch):
    monkeypatch.setattr(h, "_SINK_MAX_HELD", 2)
    c, peer, srv = _lingering_socket()
    sink = h.FdSink()
    try:
        sink.release([c.detach()])                 # stuck closing: stays held
        first = sink._proc
        sink.release([os.open("/dev/null", os.O_RDONLY), os.open("/dev/null", os.O_RDONLY)])
        assert sink._proc is not first             # 1 held + 2 > cap: replaced at once
    finally:
        sink.close()
        peer.close()
        srv.close()


def test_a_jail_without_a_pidfd_is_still_signalled_through_its_unreaped_child(env):
    jail, _ = env.boot(listener=False)
    with jail.pidfd_lock:
        os.close(jail.pidfd)
        jail.pidfd = None                      # as if pidfd_open had failed
    env.helper._signal(jail, signal.SIGKILL)
    assert jail.proc.wait(5) is not None


def test_the_chroot_base_check_follows_symlink_chains(tmp_path, monkeypatch):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    w = tmp_path / "w"
    w.mkdir()
    (w / "hop").symlink_to(real_dir)
    base = tmp_path / "base"
    base.symlink_to(w / "hop")
    real_lstat = os.lstat
    w_ident = (real_lstat(w).st_dev, real_lstat(w).st_ino)

    def faked(p, *a, **k):
        st = real_lstat(p, *a, **k)
        vals = list(st)
        vals[4] = 0
        vals[0] = (st.st_mode & ~0o022) | (0o002 if (st.st_dev, st.st_ino) == w_ident else 0)
        return os.stat_result(vals)
    monkeypatch.setattr(h.os, "lstat", faked)
    with pytest.raises(RuntimeError, match=str(w)):
        h._check_root_dir(base)


def test_a_jails_memory_cap_covers_what_it_writes_on_a_tmpfs_chroot_base(env):
    jail, _ = env.boot(listener=False)
    argv = env.argvs[-1]
    cap = int([a for a in argv if a.startswith("memory.max=")][0].split("=")[1])
    # boot jail: guest RAM (64 MiB) + memory snapshot (64 MiB) + outdisk (16 MiB) + overhead
    assert cap == ((64 + 64 + 16) << 20) + (env.cfg.jail_mem_overhead_mib << 20)


def test_serve_never_reowns_an_existing_socket_directory(tmp_path):
    shared = tmp_path / "run"
    shared.mkdir(mode=0o755)
    cfg = _cfg(tmp_path, socket_path=shared / "h.sock")
    chowned = []
    helper = h.Helper(cfg, apparmor_enabled=False,
                      lchown=lambda p, u, g: chowned.append(str(p)))
    for d in (cfg.chroot_base, cfg.assets_dir, cfg.gens_dir):
        d.mkdir(parents=True, exist_ok=True)
    ready = threading.Event()
    t = threading.Thread(target=helper.serve, kwargs={"ready": ready.set}, daemon=True)
    t.start()
    assert ready.wait(5)
    helper._stop.set()
    t.join(5)
    assert shared.stat().st_mode & 0o777 == 0o755 and str(shared) not in chowned


def test_an_asset_whose_unlink_fails_stays_tracked_and_is_retried(env, monkeypatch):
    aid = env.asset("kernel", b"K" * 10)
    env.owner.assets.clear()
    real = h.os.unlink

    def eio(p, *a, **k):
        if str(p) == env.helper._assets[aid].path:
            raise OSError(5, "Input/output error")
        return real(p, *a, **k)
    monkeypatch.setattr(h.os, "unlink", eio)
    env.helper._maybe_drop_asset(aid)
    assert aid in env.helper._assets and not env.helper._assets[aid].dropping
    monkeypatch.setattr(h.os, "unlink", real)
    env.helper.monitor_once()
    assert aid not in env.helper._assets


@pytest.mark.parametrize("out,ok", [(b"Firecracker v1.16.0\n", True), (b"Firecracker v1.15.1", True),
                                    (b"Firecracker v1.12.1\n", False), (b"Firecracker v1.15.0", False)])
def test_the_helper_refuses_a_firecracker_older_than_the_minimum(tmp_path, monkeypatch, out, ok):
    # The helper enforces it itself: a dispatcher only checks once, at its own start, and a
    # helper restarted with an older binary must not serve the dispatchers already running.
    monkeypatch.setattr(h, "_check_root_owned_exec", lambda label, path: None)
    monkeypatch.setattr(h.Helper, "_prepare_state_tree", lambda self: None)
    monkeypatch.setattr(h.Helper, "_setup_cgroups", lambda self: None)
    run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, out, b"")  # noqa: E731
    helper = h.Helper(_cfg(tmp_path), apparmor_enabled=False, run=run, lchown=lambda p, u, g: None)
    monkeypatch.setattr(h.Path, "exists", lambda self: True)
    if ok:
        helper.prepare_host()
    else:
        with pytest.raises(RuntimeError, match="1.15.1"):
            helper.prepare_host()


def test_the_helper_minimum_matches_the_dispatcher_gate():
    from blastbox.host.runtime import firecracker as fc

    assert h.MIN_FC_VERSION == fc._MIN_FC_VERSION
