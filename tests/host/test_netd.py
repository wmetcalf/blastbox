"""TDD tests for blastbox.host.netd.CaptureDaemon — the event-driven capture lifecycle.

The daemon's docker-events loop is a thin untestable shell; the per-container handlers
(start → spawn tcpdump, die → stop it) carry the logic and are tested here with injected fakes
(no docker, no root, no tcpdump).
"""
from __future__ import annotations

from blastbox.host.netd import CaptureDaemon


class _FakeProc:
    def __init__(self, argv):
        self.argv = argv
        self.terminated = False
        self.waited = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def poll(self):
        return None


def _labeled_inspect(job_id="J1", ip="172.20.0.2", net_id="netid0"):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.capture": "1", "blastbox.job_id": job_id}},
        "NetworkSettings": {"Networks": {"bb-net0": {"IPAddress": ip, "NetworkID": net_id}}},
    }


def _make_daemon(tmp_path, inspect_map, spawned):
    def inspect_fn(cid):
        return inspect_map[cid]

    def network_iface_fn():
        return {"netid0": "br-netid0"}

    def spawn_fn(argv, pcap_path):
        p = _FakeProc(argv)
        spawned.append((argv, pcap_path, p))
        return p

    return CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=inspect_fn,
        network_iface_fn=network_iface_fn,
        spawn_fn=spawn_fn,
    )


def test_start_spawns_tcpdump_for_labeled_worker(tmp_path):
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect()}, spawned)

    d.handle_start("c1")

    assert len(spawned) == 1
    argv, pcap_path, _ = spawned[0]
    assert argv[0] == "tcpdump"
    assert "br-netid0" in argv
    assert any("172.20.0.2" in t for t in argv)
    assert pcap_path == str(tmp_path / "J1" / "capture" / "dump.pcap")
    # The host-only capture dir is created.
    assert (tmp_path / "J1" / "capture").is_dir()


def test_start_noop_for_unlabeled_worker(tmp_path):
    spawned: list = []
    insp = _labeled_inspect()
    insp["Config"]["Labels"] = {"blastbox.job_id": "J1"}  # no capture label
    d = _make_daemon(tmp_path, {"c1": insp}, spawned)

    d.handle_start("c1")
    assert spawned == []


def test_die_terminates_the_capture(tmp_path):
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect()}, spawned)
    d.handle_start("c1")
    proc = spawned[0][2]

    d.handle_die("c1")
    assert proc.terminated is True
    assert proc.waited is True
    # No longer tracked.
    assert "c1" not in d.active


def test_die_unknown_container_is_noop(tmp_path):
    d = _make_daemon(tmp_path, {}, [])
    d.handle_die("never-seen")  # must not raise


def test_double_start_does_not_double_capture(tmp_path):
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect()}, spawned)
    d.handle_start("c1")
    d.handle_start("c1")  # duplicate event
    assert len(spawned) == 1


def test_start_swallows_inspect_errors(tmp_path):
    # A container that vanished between event and inspect must not crash the daemon.
    def inspect_fn(cid):
        raise RuntimeError("no such container")

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=inspect_fn,
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
    )
    d.handle_start("gone")  # must not raise
    assert d.active == {}


# --------------------------------------------------------------------------- SOCKS wiring
def _wire_inspect(job_id="J1", pid=4242):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.wire": "socks", "blastbox.job_id": job_id}},
        "NetworkSettings": {"Networks": {"bb-socks": {"IPAddress": "172.30.0.5", "NetworkID": "x"}}},
        "State": {"Pid": pid, "Running": True},
    }


def _wire_daemon(tmp_path, inspect_map, *, spawned, runs):
    def nsenter_spawn(pid, argv):
        p = _FakeProc(argv)
        spawned.append((pid, argv, p))
        return p

    def nsenter_run(pid, argv):
        runs.append((pid, argv))
        return 0  # tun0 probe + ip cmds all succeed

    return CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: inspect_map[cid],
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        socks_proxy_url="socks5://bb:bb@172.30.0.10:1080",
        nsenter_spawn_fn=nsenter_spawn,
        nsenter_run_fn=nsenter_run,
        sleep_fn=lambda s: None,
    )


def test_wire_spawns_tun2socks_and_sets_routes(tmp_path):
    spawned: list = []
    runs: list = []
    d = _wire_daemon(tmp_path, {"c1": _wire_inspect(pid=7777)}, spawned=spawned, runs=runs)

    d.handle_start("c1")

    # tun2socks launched in the worker's netns (pid 7777) with the configured proxy.
    assert len(spawned) == 1
    pid, argv, _ = spawned[0]
    assert pid == 7777 and argv[0] == "tun2socks"
    assert "socks5://bb:bb@172.30.0.10:1080" in argv
    # The default route was moved onto the TUN inside the netns.
    assert any(a[:3] == ["ip", "route", "replace"] and a[-1] == "tun0" for _, a in runs)
    assert "c1" in d.wired


def test_wire_inert_without_proxy_configured(tmp_path):
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _wire_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        # no socks_proxy_url / nsenter seams → wiring disabled
    )
    d.handle_start("c1")
    assert d.wired == {}


def test_wire_aborts_if_tun_never_appears(tmp_path):
    spawned: list = []
    def nsenter_run(pid, argv):
        return 1  # tun0 probe always fails → TUN never ready

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _wire_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        socks_proxy_url="socks5://h:1",
        nsenter_spawn_fn=lambda pid, argv: spawned.append(_FakeProc(argv)) or spawned[-1],
        nsenter_run_fn=nsenter_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("c1")
    assert "c1" not in d.wired
    assert spawned[0].terminated is True  # tun2socks killed on abort


def test_die_tears_down_wiring(tmp_path):
    spawned: list = []
    runs: list = []
    d = _wire_daemon(tmp_path, {"c1": _wire_inspect()}, spawned=spawned, runs=runs)
    d.handle_start("c1")
    wproc = spawned[0][2]
    d.handle_die("c1")
    assert wproc.terminated is True
    assert "c1" not in d.wired


# --------------------------------------------------------------------------- VPN wiring
def _vpn_inspect(job_id="V1", pid=555):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.wire": "vpn", "blastbox.job_id": job_id}},
        "NetworkSettings": {"Networks": {"bb-vpn": {"IPAddress": "172.31.0.5", "NetworkID": "y"}}},
        "State": {"Pid": pid, "Running": True},
    }


def test_vpn_wire_sets_default_route_via_gateway(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _vpn_inspect(pid=888),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        vpn_gateway_ip="172.31.0.10",
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        sleep_fn=lambda s: None,
    )
    d.handle_start("v1")
    assert runs == [(888, ["ip", "route", "replace", "default", "via", "172.31.0.10"])]
    assert "v1" in d.wired and d.wired["v1"] is None  # route-only, no proc


def test_vpn_wire_inert_without_gateway(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _vpn_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        # no vpn_gateway_ip → vpn wiring disabled
    )
    d.handle_start("v1")
    assert runs == [] and d.wired == {}


def test_vpn_die_is_clean_noop(tmp_path):
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _vpn_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        vpn_gateway_ip="172.31.0.10",
        nsenter_run_fn=lambda pid, argv: 0,
    )
    d.handle_start("v1")
    d.handle_die("v1")  # route-only wire → no proc to terminate, must not raise
    assert "v1" not in d.wired


# --------------------------------------------------------------------------- inspect wiring
def _inspect_mode_inspect(job_id="I1", pid=777):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.wire": "inspect", "blastbox.job_id": job_id}},
        "NetworkSettings": {"Networks": {"bb-inspect": {"IPAddress": "172.32.0.5", "NetworkID": "z"}}},
        "State": {"Pid": pid, "Running": True},
    }


def test_inspect_wire_sets_default_route_via_gateway(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _inspect_mode_inspect(pid=4242),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        inspect_gateway_ip="172.32.0.10",
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        sleep_fn=lambda s: None,
    )
    d.handle_start("i1")
    assert runs == [(4242, ["ip", "route", "replace", "default", "via", "172.32.0.10"])]
    assert "i1" in d.wired and d.wired["i1"] is None  # route-only, no proc


def test_inspect_wire_inert_without_gateway(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _inspect_mode_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        # no inspect_gateway_ip → inspect wiring disabled (fail-closed: worker has no egress)
    )
    d.handle_start("i1")
    assert runs == [] and d.wired == {}


def test_inspect_die_is_clean_noop(tmp_path):
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _inspect_mode_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        inspect_gateway_ip="172.32.0.10",
        nsenter_run_fn=lambda pid, argv: 0,
    )
    d.handle_start("i1")
    d.handle_die("i1")  # route-only wire → no proc to terminate, must not raise
    assert "i1" not in d.wired


# --------------------------------------------------------------------------- inspect keylog snapshot
def _inspect_captured(job_id="K1", ip="172.32.0.5", net_id="netidI", pid=999):
    """An inspect worker that is BOTH captured (net.capture=1) and inspect-wired."""
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {
            "blastbox.net.capture": "1",
            "blastbox.net.wire": "inspect",
            "blastbox.job_id": job_id,
        }},
        "NetworkSettings": {"Networks": {"bb-inspect": {"IPAddress": ip, "NetworkID": net_id}}},
        "State": {"Pid": pid, "Running": True},
    }


def _keylog_daemon(tmp_path, inspect_fn, keylog_path):
    return CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=inspect_fn,
        network_iface_fn=lambda: {"netidI": "br-inspect"},
        spawn_fn=lambda argv, pcap: _FakeProc(argv),
        inspect_gateway_ip="172.32.0.10",
        inspect_keylog_path=keylog_path,
        nsenter_run_fn=lambda pid, argv: 0,
        sleep_fn=lambda s: None,
    )


def test_inspect_die_snapshots_keylog_next_to_pcap(tmp_path):
    keylog = tmp_path / "gw" / "master_keys.log"
    keylog.parent.mkdir()
    keylog.write_text("CLIENT_TRAFFIC_SECRET_0 deadbeef cafef00d\n")
    d = _keylog_daemon(tmp_path, lambda cid: _inspect_captured(), str(keylog))
    d.handle_start("k1")
    assert "k1" in d.active and "k1" in d.inspect_wired  # captured AND inspect-wired
    d.handle_die("k1")
    dst = tmp_path / "K1" / "capture" / "sslkeys.log"
    assert dst.is_file()
    assert dst.read_text() == "CLIENT_TRAFFIC_SECRET_0 deadbeef cafef00d\n"
    assert "k1" not in d.inspect_wired  # cleared


def test_inspect_die_no_keylog_snapshot_without_capture(tmp_path):
    # inspect-wired but NOT captured → no pcap to pair the keys with → no snapshot.
    keylog = tmp_path / "master_keys.log"
    keylog.write_text("X Y Z\n")
    d = _keylog_daemon(tmp_path, lambda cid: _inspect_mode_inspect(job_id="K2", pid=7), str(keylog))
    d.handle_start("k2")
    assert "k2" in d.inspect_wired and "k2" not in d.active
    d.handle_die("k2")
    assert not (tmp_path / "K2" / "capture" / "sslkeys.log").exists()


def test_inspect_die_no_keylog_snapshot_when_unconfigured(tmp_path):
    # captured + inspect-wired but no keylog path configured → nothing copied.
    d = _keylog_daemon(tmp_path, lambda cid: _inspect_captured(job_id="K3"), None)
    d.handle_start("k3")
    d.handle_die("k3")
    assert not (tmp_path / "K3" / "capture" / "sslkeys.log").exists()
