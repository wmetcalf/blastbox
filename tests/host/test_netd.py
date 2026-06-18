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
    # A .done sentinel is written next to the pcap AFTER tcpdump exits, so the dispatcher's seal
    # can wait for a complete capture instead of copying one mid-write.
    assert (tmp_path / "J1" / "capture" / "dump.pcap.done").is_file()


def test_capture_done_sentinel_skipped_when_proc_wont_stop(tmp_path):
    """The .done sentinel must only appear once tcpdump has actually exited. If the proc can't be
    confirmed stopped, skip it so the dispatcher falls back to its bounded wait (not a false
    'complete' signal over a still-flushing pcap)."""
    class _StuckProc:
        def terminate(self): pass
        def wait(self, timeout=None): raise RuntimeError("won't die")
        def kill(self): pass
        def poll(self): return None  # never confirmed dead

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _labeled_inspect(job_id="J1"),
        network_iface_fn=lambda: {"netid0": "br-netid0"},
        spawn_fn=lambda argv, pcap: _StuckProc(),
    )
    d.handle_start("c1")
    d.handle_die("c1")
    assert not (tmp_path / "J1" / "capture" / "dump.pcap.done").is_file()


def test_capture_clears_stale_done_sentinel_on_start(tmp_path):
    """A retried job (same job_id, capture/ kept) must not inherit the prior attempt's .done — it
    is cleared before the fresh tcpdump so the dispatcher waits for THIS capture."""
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect(job_id="J1")}, spawned)
    cap = tmp_path / "J1" / "capture"
    cap.mkdir(parents=True, exist_ok=True)
    stale = cap / "dump.pcap.done"
    stale.write_text("stale")
    d.handle_start("c1")
    assert not stale.is_file()  # cleared before the new capture spawned


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


def test_wire_socks_uses_per_worker_proxy_over_global(tmp_path):
    """A worker labeled blastbox.net.socks-proxy=<url> (e.g. a specific country's tor exit) is
    wired through THAT proxy, not netd's global --socks-proxy — so one netd serves a fleet."""
    insp = _wire_inspect(pid=8888)
    insp["Config"]["Labels"]["blastbox.net.socks-proxy"] = "socks5://172.30.0.41:9050"
    spawned: list = []
    runs: list = []
    d = _wire_daemon(tmp_path, {"c1": insp}, spawned=spawned, runs=runs)
    d.handle_start("c1")
    _, argv, _ = spawned[0]
    assert "socks5://172.30.0.41:9050" in argv           # the per-worker DE tor exit
    assert "socks5://bb:bb@172.30.0.10:1080" not in argv  # NOT the global default
    assert "c1" in d.wired


def test_wire_socks_refuses_malformed_per_worker_proxy(tmp_path):
    """A malformed per-worker socks-proxy label is rejected before it reaches tun2socks — the worker
    stays unwired (fail-closed: no egress), rather than passing the bad URL verbatim to the proxy."""
    insp = _wire_inspect(pid=8888)
    insp["Config"]["Labels"]["blastbox.net.socks-proxy"] = "socks5://h:1 ; rm -rf"
    spawned: list = []
    runs: list = []
    d = _wire_daemon(tmp_path, {"c1": insp}, spawned=spawned, runs=runs)
    d.handle_start("c1")
    assert spawned == []          # tun2socks never spawned
    assert "c1" not in d.wired    # fail-closed: no wire


def test_wire_socks_aborts_and_kills_tun2socks_if_route_cmd_fails(tmp_path):
    """If a tun_setup route command fails (non-zero rc), the worker would be left with no default
    route (broken/no egress) — so fail closed: don't record it as wired, and terminate tun2socks
    so it isn't orphaned."""
    spawned: list = []

    def nsenter_run(pid, argv):
        # tun0 probe (link show) succeeds; the route-setup `ip route replace` fails.
        if argv[:3] == ["ip", "link", "show"]:
            return 0
        if argv[:2] == ["ip", "route"]:
            return 1  # route command fails
        return 0

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _wire_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        socks_proxy_url="socks5://bb:bb@172.30.0.10:1080",
        nsenter_spawn_fn=lambda pid, argv: spawned.append(_FakeProc(argv)) or spawned[-1],
        nsenter_run_fn=nsenter_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("c1")
    assert "c1" not in d.wired                  # fail-closed: not recorded as wired
    assert spawned[0].terminated is True        # tun2socks killed, not orphaned


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


# --------------------------------------------------------------------------- transproxy (CAPE tor)
def _transproxy_inspect(job_id="T1", ip="172.30.0.9", pid=321):
    return {
        "Name": f"/blastbox-worker-{job_id}-1",
        "Config": {"Labels": {"blastbox.net.wire": "transproxy", "blastbox.job_id": job_id}},
        "NetworkSettings": {"Networks": {"bb-socks": {"IPAddress": ip, "NetworkID": "s"}}},
        "State": {"Pid": pid, "Running": True},
    }


def _transproxy_daemon(tmp_path, runs, host_cmds):
    return CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _transproxy_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        transproxy_gateway="172.30.0.1",
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        host_run_fn=lambda argv: host_cmds.append(argv) or 0,
        sleep_fn=lambda s: None,
    )


def test_transproxy_wire_routes_and_installs_host_redirects(tmp_path):
    runs, host_cmds = [], []
    d = _transproxy_daemon(tmp_path, runs, host_cmds)
    d.handle_start("t1")
    # in-netns: default route via the host gateway
    assert runs == [(321, ["ip", "route", "replace", "default", "via", "172.30.0.1"])]
    # host: 4 iptables rules keyed on the worker IP — 3 nat REDIRECTs appended (-A, so DNS sits
    # above the TCP-SYN catch-all), 1 FORWARD DROP inserted (-I, head precedence).
    assert len(host_cmds) == 4 and all("172.30.0.9" in c for c in host_cmds)
    assert sum("-A" in c for c in host_cmds) == 3 and sum("-I" in c for c in host_cmds) == 1
    assert d.transproxy_wired["t1"] == "172.30.0.9"


def test_transproxy_installs_host_rules_before_route(tmp_path):
    """Host REDIRECT/DROP enforcement is installed BEFORE the in-netns default route (the barrier
    signal) — so a worker can't observe the route and egress through the host gateway before the
    REDIRECT/DROP rules exist."""
    order: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _transproxy_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        transproxy_gateway="172.30.0.1",
        nsenter_run_fn=lambda pid, argv: order.append("route") or 0,  # the in-netns route
        host_run_fn=lambda argv: order.append("host") or 0,          # the host REDIRECT/DROP rules
        sleep_fn=lambda s: None,
    )
    d.handle_start("t1")
    assert order.count("host") == 4 and order.count("route") == 1
    assert order[-1] == "route" and all(x == "host" for x in order[:-1])  # route is strictly last


def test_transproxy_host_rule_failure_leaves_no_route(tmp_path):
    """If a host enforcement rule fails, the in-netns route must NEVER be installed (fail closed —
    no live route without the REDIRECT/DROP behind it)."""
    routes: list = []
    calls = {"n": 0}

    def host_run(argv):
        calls["n"] += 1
        return 0 if calls["n"] <= 2 else 1  # 3rd host rule fails

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _transproxy_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        transproxy_gateway="172.30.0.1",
        nsenter_run_fn=lambda pid, argv: routes.append(argv) or 0,
        host_run_fn=host_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("t1")
    assert routes == []                       # route never installed
    assert "t1" not in d.transproxy_wired     # fail closed


def test_leakguard_v6_link_local_fails_closed(tmp_path):
    """If ip6tables can't install AND the netns has link-local v6 (ff02::1 reachable) but no global
    route, still fail closed — link-local v6 is real v6 the guard couldn't cover."""
    def nsenter_run(pid, argv):
        if argv[0] == "ip6tables":
            return 1                                   # v6 guard fails
        if argv[:4] == ["ip", "-6", "route", "get"]:
            return 1 if argv[-1] == "2606:4700:4700::1111" else 0  # no GUA, but ff02::1 reachable
        return 0
    d = _leakguard_only_daemon(tmp_path, nsenter_run)
    d.handle_start("l3")
    assert "l3" not in d.leakguarded and "l3" in d.leakguard_failed


def test_transproxy_die_tears_down_host_redirects(tmp_path):
    runs, host_cmds = [], []
    d = _transproxy_daemon(tmp_path, runs, host_cmds)
    d.handle_start("t1")
    host_cmds.clear()
    d.handle_die("t1")
    # teardown issues the symmetric -D rules and forgets the worker
    assert len(host_cmds) == 4 and all("-D" in c and "172.30.0.9" in c for c in host_cmds)
    assert "t1" not in d.transproxy_wired


def test_leakguard_installs_in_netns_output_drop(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: {
            "Config": {"Labels": {"blastbox.net.leakguard": "strict", "blastbox.job_id": "L1"}},
            "State": {"Pid": 4321, "Running": True},
        },
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
    )
    d.handle_start("l1")
    assert "l1" in d.leakguarded
    # all rules run in the worker netns (pid 4321), ending in a non-TCP DROP
    assert all(pid == 4321 for pid, _ in runs)
    assert (4321, ["iptables", "-A", "OUTPUT", "!", "-p", "tcp", "-j", "DROP"]) in runs
    assert not any("--dport" in argv and "53" in argv for _, argv in runs)  # strict = no udp:53
    # IPv6 twin installed too — v6 fully dropped (the proxy tiers are v4-only).
    assert (4321, ["ip6tables", "-A", "OUTPUT", "-j", "DROP"]) in runs


def _leakguard_only_daemon(tmp_path, nsenter_run, job_id="L3"):
    return CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: {
            "Config": {"Labels": {"blastbox.net.leakguard": "strict", "blastbox.job_id": job_id}},
            "State": {"Pid": 7, "Running": True},
        },
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=nsenter_run,
    )


def test_leakguard_v6_fail_without_v6_route_stays_guarded(tmp_path):
    """On a v4-only host (no ip6tables module / no v6 route), a failing ip6tables rule is harmless:
    there's no IPv6 to leak, so the v4 guard (the hard guarantee) stays in force and the worker is
    still leakguarded."""
    def nsenter_run(pid, argv):
        if argv[0] == "ip6tables":
            return 1                       # v6 guard can't install
        if argv[:3] == ["ip", "-6", "route"]:
            return 1                       # ...and there is NO v6 route → nothing to leak
        return 0                           # v4 rules succeed
    d = _leakguard_only_daemon(tmp_path, nsenter_run)
    d.handle_start("l3")
    assert "l3" in d.leakguarded and "l3" not in d.leakguard_failed


def test_leakguard_v6_fail_with_v6_route_fails_closed(tmp_path):
    """If ip6tables fails AND the netns actually has IPv6 egress, that's a real leak path the guard
    is meant to close → fail closed: the worker is NOT marked guarded (and handle_start will refuse
    to wire it)."""
    def nsenter_run(pid, argv):
        if argv[0] == "ip6tables":
            return 1                       # v6 guard fails
        if argv[:3] == ["ip", "-6", "route"]:
            return 0                       # ...but a v6 route EXISTS → real leak path
        return 0
    d = _leakguard_only_daemon(tmp_path, nsenter_run)
    d.handle_start("l3")
    assert "l3" not in d.leakguarded and "l3" in d.leakguard_failed


def test_leakguard_failure_refuses_egress_wiring(tmp_path):
    """The leak guard is a PRECONDITION for egress: if a required guard can't be installed, the
    worker must NOT be wired (no egress without the non-TCP DROP). tun2socks is never spawned."""
    insp = _wire_inspect(pid=4242)
    insp["Config"]["Labels"]["blastbox.net.leakguard"] = "strict"
    spawned: list = []

    def nsenter_run(pid, argv):
        if argv[0] == "iptables":
            return 1   # the v4 leak-guard rule fails → fail closed
        return 0

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: insp,
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        socks_proxy_url="socks5://bb:bb@172.30.0.10:1080",
        nsenter_spawn_fn=lambda pid, argv: spawned.append(_FakeProc(argv)) or spawned[-1],
        nsenter_run_fn=nsenter_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("c1")
    assert "c1" in d.leakguard_failed
    assert "c1" not in d.wired       # egress refused
    assert spawned == []             # tun2socks never spawned


def test_reconcile_tears_down_vanished_worker(tmp_path):
    """A worker that died during an events-stream gap is absent from the running set on reconnect;
    reconcile must handle_die it so its capture proc + host rules don't survive (bridge-IP reuse
    would otherwise mis-capture an unrelated container)."""
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect(job_id="J1")}, spawned)
    d.handle_start("c1")
    assert "c1" in d.active
    proc = spawned[0][2]
    # c1 is no longer running (died during the gap) — reconcile sees an empty running set.
    d.list_running_fn = lambda: []
    d._reconcile()
    assert proc.terminated is True   # its capture was torn down
    assert "c1" not in d.active
    """The non-TCP DROP must be in place BEFORE the route out — otherwise the worker's egress
    barrier could release (it watches the route) while the guard is not yet up. Assert ordering:
    every leakguard rule precedes the first wiring command in the call sequence."""
    order: list = []
    insp = _wire_inspect(pid=4242)
    insp["Config"]["Labels"]["blastbox.net.leakguard"] = "strict"

    def nsenter_run(pid, argv):
        order.append(argv[0])
        return 0  # tun0 probe + ip cmds succeed

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: insp,
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        socks_proxy_url="socks5://bb:bb@172.30.0.10:1080",
        nsenter_spawn_fn=lambda pid, argv: _FakeProc(argv),
        nsenter_run_fn=nsenter_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("c1")
    # the wiring uses `ip` (link/route); the guard uses iptables/ip6tables. Last guard rule must
    # come before the first `ip` wiring command.
    last_guard = max(i for i, t in enumerate(order) if t in ("iptables", "ip6tables"))
    first_wire = min(i for i, t in enumerate(order) if t == "ip")
    assert last_guard < first_wire


def test_leakguard_dns_mode_allows_udp53(tmp_path):
    runs: list = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: {
            "Config": {"Labels": {"blastbox.net.leakguard": "dns", "blastbox.job_id": "L2"}},
            "State": {"Pid": 99, "Running": True},
        },
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
    )
    d.handle_start("l2")
    assert (99, ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]) in runs
    d.handle_die("l2")
    assert "l2" not in d.leakguarded  # forgotten on die (rules die with the netns)


def test_transproxy_inert_without_gateway_or_host_seam(tmp_path):
    runs = []
    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _transproxy_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        nsenter_run_fn=lambda pid, argv: runs.append((pid, argv)) or 0,
        # no transproxy_gateway / host_run_fn → disabled
    )
    d.handle_start("t1")
    assert runs == [] and "t1" not in d.transproxy_wired


def test_transproxy_rolls_back_on_partial_host_failure(tmp_path):
    calls = {"n": 0}

    def host_run(argv):
        calls["n"] += 1
        return 0 if calls["n"] <= 2 else 1  # 3rd rule fails

    d = CaptureDaemon(
        job_root=str(tmp_path),
        inspect_fn=lambda cid: _transproxy_inspect(),
        network_iface_fn=lambda: {},
        spawn_fn=lambda *a, **k: None,
        transproxy_gateway="172.30.0.1",
        nsenter_run_fn=lambda pid, argv: 0,
        host_run_fn=host_run,
        sleep_fn=lambda s: None,
    )
    d.handle_start("t1")
    # the failed wire is not recorded, and teardown (-D) rules were issued to clean up
    assert "t1" not in d.transproxy_wired


# --------------------------------------------------------------------------- reconcile
def test_reconcile_replays_handle_start_over_running_workers(tmp_path):
    """On (re)connect netd replays handle_start over already-running workers (e.g. started during a
    docker-events stream gap), so capture/wiring isn't silently dropped for them."""
    spawned: list = []
    d = _make_daemon(tmp_path, {"c1": _labeled_inspect(job_id="J1")}, spawned)
    d.list_running_fn = lambda: ["c1"]
    d._reconcile()
    assert len(spawned) == 1  # the running worker got captured
    # idempotent: a second reconcile (next reconnect) does not double-capture
    d._reconcile()
    assert len(spawned) == 1


def test_reconcile_noop_without_seam(tmp_path):
    spawned: list = []
    d = _make_daemon(tmp_path, {}, spawned)  # list_running_fn defaults to None
    d._reconcile()
    assert spawned == []


def test_reconcile_survives_listing_error(tmp_path):
    spawned: list = []
    d = _make_daemon(tmp_path, {}, spawned)

    def boom():
        raise RuntimeError("docker ps failed")

    d.list_running_fn = boom
    d._reconcile()  # must not raise
    assert spawned == []
