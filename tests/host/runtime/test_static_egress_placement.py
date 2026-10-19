"""Placement by advertised egress: a static pool serving an egress-granting policy only claims
workers whose /healthz says ``"egress": true``, and a tier that could never place such a job
refuses to start. The agent's own 422 refusal is the backstop for runtimes that do not place
(tested in tests/worker/test_agent_egress_capability.py)."""
from __future__ import annotations

import pytest

from blastbox.host.runtime.static_pool import (
    StaticPoolConfig,
    StaticPoolExhausted,
    StaticPoolNoEgress,
    StaticPoolRuntime,
    StaticWorker,
)


def _rt(adverts: dict[str, object], *, healthy=None) -> StaticPoolRuntime:
    """adverts: host -> the /healthz body's "egress" value (missing key = legacy agent),
    or None = could not ask."""
    workers = tuple(StaticWorker.parse(h, default_port=8765, default_token=None) for h in adverts)

    def caps(url, headers, timeout):
        host = url.split("//")[1].split(":")[0]
        v = adverts[host]
        if v is None:
            return None
        return {} if v == "legacy" else {"ok": True, "egress": v}

    return StaticPoolRuntime(StaticPoolConfig(workers=workers),
                             http_probe=lambda u, h, t: True if healthy is None else healthy(u),
                             capability_probe=caps)


def test_without_an_egress_policy_capability_is_never_asked():
    asked = []
    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="mac1"),)),
                           http_probe=lambda u, h, t: True,
                           capability_probe=lambda *a: asked.append(a) or {"egress": False})
    assert rt.spawn().ip == "mac1" and asked == []


def test_an_egress_tier_skips_workers_that_cannot_provide_it():
    rt = _rt({"mac1": False, "legacy": "legacy", "linux1": True})
    rt.require_egress()
    assert rt.spawn().ip == "linux1"


def test_a_legacy_agent_that_advertises_nothing_is_not_trusted_with_egress():
    rt = _rt({"old": "legacy"})
    rt.require_egress()
    with pytest.raises(StaticPoolNoEgress):
        rt.spawn()


def test_only_incapable_workers_is_a_loud_configuration_fault():
    rt = _rt({"mac1": False, "mac2": False})
    rt.require_egress()
    with pytest.raises(StaticPoolNoEgress, match="advertises egress"):
        rt.spawn()


def test_an_unanswered_capability_question_is_not_a_verdict():
    rt = _rt({"mac1": None})
    rt.require_egress()
    with pytest.raises(StaticPoolExhausted):       # backpressure, not a fault
        rt.spawn()


def test_the_census_separates_yes_no_and_unknown():
    rt = _rt({"a": True, "b": False, "c": "legacy", "d": None})
    assert rt.egress_census() == (1, 2, 1)


def test_the_dispatcher_refuses_to_start_a_tier_that_can_never_place_egress():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    rt = _rt({"mac1": False, "mac2": False})
    with pytest.raises(ValueError, match="none of its 2 static worker"):
        _place_egress(rt, "static")


def test_a_partly_capable_fleet_starts_and_places_only_on_the_capable():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    rt = _rt({"mac1": False, "linux1": True})
    _place_egress(rt, "static")
    assert rt.spawn().ip == "linux1"


def test_an_unreachable_fleet_does_not_block_startup():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    _place_egress(_rt({"mac1": None}), "static")


def test_other_runtimes_rely_on_the_agents_refusal():
    from types import SimpleNamespace

    from blastbox.host.runtime.vm_dispatch import _place_egress

    _place_egress(SimpleNamespace(), "aws")          # no attributes touched, no raise


def test_a_fleet_that_is_merely_down_at_startup_is_unknown_not_incapable(monkeypatch):
    """The default capability probe must not read "unreachable" as "advertises no egress":
    that made a fleet that was down at dispatcher start look permanently unable to serve the
    policy, and the dispatcher refused to start."""
    import urllib.error

    from blastbox.host.runtime import remote_http
    from blastbox.host.runtime.static_pool import make_capability_probe

    def refused(req, timeout, context=None):
        raise urllib.error.URLError(ConnectionRefusedError(61, "refused"))

    monkeypatch.setattr(remote_http, "_default_open", refused)
    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="mac1"),)),
                           http_probe=lambda u, h, t: False,
                           capability_probe=make_capability_probe(None))
    assert rt.egress_census() == (0, 0, 1)


def test_a_busy_capable_worker_is_backpressure_not_a_fault():
    """REGRESSION (review): with the only capable worker CLAIMED, the free set is all Macs --
    that is the fleet being busy, and the next release frees it."""
    rt = _rt({"mac1": False, "linux1": True})
    rt.require_egress()
    assert rt.spawn().ip == "linux1"
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


def test_an_unanswered_capable_worker_is_not_a_fault_either():
    rt = _rt({"mac1": False, "linux1": None})
    rt.require_egress()
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


def test_an_odd_responder_does_not_crash_the_census():
    import http.client

    def boom(url, headers, timeout):
        raise http.client.BadStatusLine("garbage")

    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="x"),)),
                           http_probe=lambda u, h, t: True, capability_probe=boom)
    assert rt.egress_census() == (0, 0, 1)


# ------------------------------------------------------------------ review round 2

def test_the_startup_census_is_bounded_not_one_timeout_per_unreachable_worker():
    """REGRESSION (review): the census probed every worker SERIALLY, so one healthy box plus
    99 unreachable ones delayed dispatcher construction by ~99 probe timeouts (minutes at the
    5 s default). It now asks concurrently and waits about one timeout in total; a straggler is
    UNKNOWN, which is not a verdict."""
    import threading
    import time

    hosts = ["linux0"] + [f"dead{i}" for i in range(99)]
    workers = tuple(StaticWorker.parse(h, default_port=8765, default_token=None) for h in hosts)
    peak = {"now": 0, "max": 0}
    lock = threading.Lock()

    def caps(url, headers, timeout):
        host = url.split("//")[1].split(":")[0]
        if host == "linux0":
            return {"ok": True, "egress": True}
        with lock:
            peak["now"] += 1
            peak["max"] = max(peak["max"], peak["now"])
        time.sleep(timeout)             # an unreachable box: the probe runs out its timeout
        with lock:
            peak["now"] -= 1
        return None

    rt = StaticPoolRuntime(StaticPoolConfig(workers=workers, probe_timeout_s=0.25),
                           http_probe=lambda u, h, t: True, capability_probe=caps)
    t0 = time.monotonic()
    yes, no, unknown = rt.egress_census()
    elapsed = time.monotonic() - t0
    assert (yes, no, yes + no + unknown) == (1, 0, 100)
    assert elapsed < 3.0, elapsed               # serially: 99 x 0.25 s ~ 25 s
    assert peak["max"] <= StaticPoolRuntime.CENSUS_PARALLELISM


class _Slot:
    def __init__(self, sid):
        self.slot_id = sid


class _AwsTier:
    """A tier that builds its own workers and does not advertise per worker."""
    dispatch_style = "network"
    ssl_context = None

    def __init__(self):
        self.spawned = 0

    def spawn(self):
        self.spawned += 1
        return _Slot(f"aws-{self.spawned}")


def test_a_cascade_passes_the_egress_requirement_to_its_static_tiers_including_late_ones():
    """REGRESSION (review): `_place_egress` returned early for anything but a bare
    StaticPoolRuntime, so in a static -> AWS cascade the static tier never learned the policy
    grants egress and handed the job to a macOS worker, which refused it (422) -- a permanent
    failure instead of falling through to capable capacity. Tiers admitted LATER (deferred at
    startup) must be told as well."""
    from blastbox.host.runtime.cascade import CascadingRuntime, DeferredTier, Tier
    from blastbox.host.runtime.vm_dispatch import _place_egress

    macs = _rt({"mac1": False})
    late = _rt({"mac2": False})
    aws = _AwsTier()
    cascade = CascadingRuntime(
        [Tier("static", macs, 2), Tier("aws-ec2", aws, 2)],
        deferred=[DeferredTier(name="static", capacity=2, reason="throttled",
                               build=lambda: late, pos=2, dispatch_style="network")],
        admit_retry_s=0.0)
    _place_egress(cascade, "cascade")                  # AWS present: no fleet verdict, no raise
    assert macs._require_egress is True
    slot = cascade._spawn_from_admitted()              # the Mac is skipped, AWS takes the job
    assert slot.slot_id == "aws-1" and aws.spawned == 1
    assert late._require_egress is False
    cascade._admit_probe(list(cascade._deferred))
    assert cascade.tiers[-1].runtime is late and late._require_egress is True


def test_an_all_static_cascade_that_can_never_place_egress_refuses_to_start():
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier
    from blastbox.host.runtime.vm_dispatch import _place_egress

    cascade = CascadingRuntime([Tier("static", _rt({"mac1": False}), 1),
                                Tier("static", _rt({"mac2": False}), 1)])
    with pytest.raises(ValueError, match="none of its 2 static worker"):
        _place_egress(cascade, "cascade")
    ok = CascadingRuntime([Tier("static", _rt({"mac1": False}), 1),
                           Tier("static", _rt({"linux1": True}), 1)])
    _place_egress(ok, "cascade")
    assert ok._spawn_from_admitted().ip == "linux1"


# ------------------------------------------------------------------ review round 4

def test_a_health_unknown_worker_is_unknown_egress_capacity_not_a_no():
    """REGRESSION (review): with one healthy `egress: false` worker and one whose health probe
    could not even be ATTEMPTED (None: local EMFILE/ENOMEM), the second set no flag, so spawn
    raised StaticPoolNoEgress -- a configuration FAULT, advancing cascade repair streaks -- as
    though every worker had answered no."""
    rt = _rt({"mac1": False, "linux1": True},
             healthy=lambda url: None if "linux1" in url else True)
    rt.require_egress()
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()
    # ...whereas a fleet that really did all answer "no" is still the loud fault
    rt = _rt({"mac1": False, "mac2": False})
    rt.require_egress()
    with pytest.raises(StaticPoolNoEgress):
        rt.spawn()


def _trickle_server(chunks: "list[bytes]", gap: float):
    """A one-request HTTP server that sends ``chunks`` with ``gap`` seconds between them --
    each gap well inside a socket timeout, the total far beyond it."""
    import socket
    import threading
    import time

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.recv(65536)
                    for c in chunks:
                        if stop.is_set():
                            break
                        conn.sendall(c)
                        time.sleep(gap)
                except OSError:
                    pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}", stop, srv


def test_a_trickled_capability_body_is_cut_off_by_a_wall_clock_deadline():
    """REGRESSION (review): `resp.read(65536)` is bounded in size, not time -- the socket
    timeout only limits each idle gap -- so a worker sending its /healthz body one byte at a
    time kept the read (and the spawn thread calling it) going indefinitely."""
    import time

    from blastbox.host.runtime.static_pool import make_capability_probe

    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n"
    url, stop, srv = _trickle_server([head] + [b" "] * 4000, gap=0.05)
    try:
        t0 = time.monotonic()
        assert make_capability_probe(None)(url + "/healthz", {}, 0.5) is None
        assert time.monotonic() - t0 < 2.0             # unbounded: 4000 x 0.05 s = 200 s
    finally:
        stop.set()
        srv.close()


@pytest.mark.parametrize("probe_name", ["plain", "tls-seam"])
def test_a_trickled_health_answer_is_cut_off_too(probe_name):
    """The same pattern in the /healthz HEALTH probes (status line + headers trickled): held to
    the probe timeout of wall-clock time, and read as an answer that came too slowly (False)."""
    import time

    from blastbox.host.runtime.aws_worker import _default_http_probe
    from blastbox.host.runtime.remote_http import make_tls_probe

    status = b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 3000 + b"\r\n\r\n"
    url, stop, srv = _trickle_server([status[i:i + 1] for i in range(len(status))], gap=0.05)
    probe = _default_http_probe if probe_name == "plain" else make_tls_probe(None)
    try:
        t0 = time.monotonic()
        assert probe(url + "/healthz", {}, 0.5) is False
        assert time.monotonic() - t0 < 2.0
    finally:
        stop.set()
        srv.close()


def test_a_trickled_refusal_body_does_not_hold_the_job_thread(monkeypatch):
    """The 422 refusal body is worker-controlled too: `exc.read(4096)` on a buffered stream
    blocks until 4096 bytes arrive, however slowly they trickle."""
    import io
    import time
    import urllib.error

    from blastbox.host.runtime import remote_http

    class Trickle(io.RawIOBase):
        def readable(self):
            return True

        def readinto(self, b):
            time.sleep(0.02)
            b[0:1] = b" "
            return 1

    monkeypatch.setattr(remote_http, "_REFUSAL_READ_S", 0.3, raising=False)
    exc = urllib.error.HTTPError("http://w/detonate", 422, "Unprocessable", {},
                                 io.BufferedReader(Trickle(), buffer_size=1))
    t0 = time.monotonic()
    assert remote_http._egress_refusal(exc) is False
    assert time.monotonic() - t0 < 1.5            # 4096 bytes x 0.02 s unbounded = 80 s


# ------------------------------------------------------------------ review round 7

def test_repeated_probes_against_a_trickling_worker_do_not_leak_threads():
    """REGRESSION (review): a timed-out opener was only ABANDONED -- its daemon thread stayed
    blocked in urllib for as long as the worker kept trickling bytes, so every recurring
    /healthz or capability probe leaked another thread and socket. The deadline now shuts the
    connection's socket down, so the opener thread returns."""
    import socket
    import threading
    import time

    from blastbox.host.runtime.aws_worker import _default_http_probe
    from blastbox.host.runtime.static_pool import make_capability_probe

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    stop = threading.Event()

    def trickle(conn):
        with conn:
            try:
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 200 OK\r\n")
                while not stop.is_set():          # a header that never ends, one byte at a time
                    conn.sendall(b"X")
                    time.sleep(0.02)
            except OSError:
                pass                              # the client cut us off: what we want

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            threading.Thread(target=trickle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://127.0.0.1:{srv.getsockname()[1]}/healthz"
    cap = make_capability_probe(None)

    def openers() -> int:
        return sum(1 for t in threading.enumerate() if t.name == "bb-open" and t.is_alive())

    try:
        base = openers()
        for _ in range(8):
            assert _default_http_probe(url, {}, 0.3) is False
            assert cap(url, {}, 0.3) is None
        deadline = time.monotonic() + 3.0
        while openers() > base and time.monotonic() < deadline:
            time.sleep(0.05)
        assert openers() <= base, f"{openers() - base} opener threads leaked over 16 probes"
    finally:
        stop.set()
        srv.close()
