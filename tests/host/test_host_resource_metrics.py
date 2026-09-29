"""Host resource gauges on the ingress ``/metrics`` (CPU / RAM / disk / node budget).

``/proc`` and cgroupfs are read inline on every scrape; the filesystem part (``os.statvfs`` of the
job/blob roots, the node share dir) comes from one single-flight background refresher PER SOURCE
with a TTL and a staleness bound, so a hung mount can never block a request thread nor blank another
source's series. The proc root, statvfs, loadavg, clock and the node view are injectable so these
tests never depend on the machine running them. The contract under test: a series that cannot be
read truthfully is OMITTED — a scrape never raises and never emits a fabricated zero.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, generate_latest

from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.node_share import DemandSnapshot, FileNodeShare
from blastbox.observability.host_metrics import (
    HostResourceCollector,
    NodeView,
    parse_meminfo,
    parse_proc_stat,
    read_node_view,
)
from blastbox.host.node_share import read_snapshots_readonly

_STAT = """\
cpu  1000 20 300 50000 400 5 6 7 0 0
cpu0 500 10 150 25000 200 2 3 3 0 0
cpu1 500 10 150 25000 200 3 3 4 0 0
intr 12345
ctxt 999
"""

_MEMINFO = """\
MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8192000 kB
Buffers:          100000 kB
"""


def _proc(tmp_path: Path, *, stat: str | None = _STAT, meminfo: str | None = _MEMINFO) -> Path:
    root = tmp_path / "proc"
    root.mkdir(exist_ok=True)
    if stat is not None:
        (root / "stat").write_text(stat)
    if meminfo is not None:
        (root / "meminfo").write_text(meminfo)
    return root


def _samples(collector: HostResourceCollector) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for fam in collector.collect():
        for s in fam.samples:
            out[(s.name, tuple(sorted(s.labels.items())))] = s.value
    return out


def _names(collector: HostResourceCollector) -> set[str]:
    return {name for name, _ in _samples(collector)}


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def test_parse_proc_stat_aggregate_line_in_seconds():
    got = parse_proc_stat(_STAT, clk_tck=100)
    assert got == {
        "user": 10.0, "nice": 0.2, "system": 3.0, "idle": 500.0,
        "iowait": 4.0, "irq": 0.05, "softirq": 0.06, "steal": 0.07,
    }


def test_parse_proc_stat_short_line_keeps_only_present_modes():
    # an old kernel without iowait/irq/softirq/steal columns: those modes are absent, not zero
    got = parse_proc_stat("cpu  100 0 50 1000\n", clk_tck=100)
    assert got == {"user": 1.0, "nice": 0.0, "system": 0.5, "idle": 10.0}


@pytest.mark.parametrize("text", ["", "cpu0 1 2 3 4\n", "cpu  a b c d\n", "intr 5\n"])
def test_parse_proc_stat_garbage_is_empty(text):
    assert parse_proc_stat(text, clk_tck=100) == {}


def test_parse_meminfo_bytes():
    got = parse_meminfo(_MEMINFO)
    assert got["MemTotal"] == 16384000 * 1024
    assert got["MemAvailable"] == 8192000 * 1024


def test_parse_meminfo_skips_malformed_lines():
    assert parse_meminfo("MemTotal: nope kB\nMemAvailable: 10 kB\n") == {"MemAvailable": 10240}


# ---------------------------------------------------------------------------
# collector
# ---------------------------------------------------------------------------


def _collector(tmp_path: Path, **kw) -> HostResourceCollector:
    if "proc_root" not in kw:
        kw["proc_root"] = _proc(tmp_path)
    kw.setdefault("disk_roots", {})
    kw.setdefault("hostname", "bb-host-1")
    kw.setdefault("loadavg_fn", lambda: (0.5, 0.25, 0.125))
    kw.setdefault("cpu_count_fn", lambda: 8)
    kw.setdefault("clk_tck", 100)
    kw.setdefault("cgroup_root", tmp_path / "no-cgroup")
    kw.setdefault("proc_self_cgroup", tmp_path / "no-self-cgroup")
    return HostResourceCollector(**kw)


def test_collector_emits_cpu_load_memory_info(tmp_path):
    s = _samples(_collector(tmp_path))
    assert s[("blastbox_host_cpu_seconds_total", (("mode", "user"),))] == 10.0
    assert s[("blastbox_host_cpu_seconds_total", (("mode", "steal"),))] == 0.07
    assert s[("blastbox_host_cpu_count", ())] == 8
    assert s[("blastbox_host_load1", ())] == 0.5
    assert s[("blastbox_host_load5", ())] == 0.25
    assert s[("blastbox_host_load15", ())] == 0.125
    assert s[("blastbox_host_memory_total_bytes", ())] == 16384000 * 1024
    assert s[("blastbox_host_memory_available_bytes", ())] == 8192000 * 1024
    info = [k for k in s if k[0] == "blastbox_host_info"]
    assert len(info) == 1
    labels = dict(info[0][1])
    assert labels["hostname"] == "bb-host-1"
    assert labels["version"]
    assert s[info[0]] == 1


def test_no_hostname_label_unless_host_id_set(tmp_path, monkeypatch):
    # /metrics is unauthenticated by default: the machine's real hostname must not leak there.
    # Only an operator-chosen BLASTBOX_HOST_ID is published.
    monkeypatch.delenv("BLASTBOX_HOST_ID", raising=False)
    c = _collector(tmp_path, hostname=None)
    info = [dict(k[1]) for k in _samples(c) if k[0] == "blastbox_host_info"]
    assert len(info) == 1 and set(info[0]) == {"version"}


def test_hostname_prefers_blastbox_host_id(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_HOST_ID", "toolz3")
    c = _collector(tmp_path, hostname=None)
    info = [dict(k[1]) for k in _samples(c) if k[0] == "blastbox_host_info"]
    assert info == [{"hostname": "toolz3", "version": info[0]["version"]}]


def test_unreadable_proc_omits_series_without_raising(tmp_path):
    c = _collector(tmp_path, proc_root=tmp_path / "does-not-exist")
    names = _names(c)
    assert not any(n.startswith("blastbox_host_cpu_seconds") for n in names)
    assert "blastbox_host_memory_total_bytes" not in names
    assert "blastbox_host_memory_available_bytes" not in names
    # what IS readable still comes through
    assert "blastbox_host_load1" in names
    assert "blastbox_host_info" in names


def test_meminfo_missing_available_omits_only_that_series(tmp_path):
    c = _collector(tmp_path, proc_root=_proc(tmp_path, meminfo="MemTotal: 100 kB\n"))
    names = _names(c)
    assert "blastbox_host_memory_total_bytes" in names
    assert "blastbox_host_memory_available_bytes" not in names


def test_loadavg_and_cpu_count_failures_are_omitted(tmp_path):
    def boom():
        raise OSError("no loadavg here")

    c = _collector(tmp_path, loadavg_fn=boom, cpu_count_fn=lambda: None)
    names = _names(c)
    assert not {"blastbox_host_load1", "blastbox_host_load5", "blastbox_host_load15"} & names
    assert "blastbox_host_cpu_count" not in names


def test_disk_series_by_role(tmp_path):
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    s = _samples(_collector(tmp_path, disk_roots={"jobs": jobs}))
    st = os.statvfs(jobs)
    assert s[("blastbox_host_disk_total_bytes", (("role", "jobs"),))] == st.f_blocks * st.f_frsize
    free = s[("blastbox_host_disk_free_bytes", (("role", "jobs"),))]
    assert 0 < free <= st.f_blocks * st.f_frsize
    # role labels only — no filesystem path is ever a label value
    for (name, labels), _ in s.items():
        if name.startswith("blastbox_host_disk"):
            assert all(str(tmp_path) not in v for _, v in labels)


def test_disk_same_filesystem_deduplicated_into_one_series(tmp_path):
    jobs, blobs = tmp_path / "jobs", tmp_path / "blobs"
    jobs.mkdir()
    blobs.mkdir()
    s = _samples(_collector(tmp_path, disk_roots={"jobs": jobs, "blobs": blobs}))
    disk_total = [k for k in s if k[0] == "blastbox_host_disk_total_bytes"]
    assert disk_total == [("blastbox_host_disk_total_bytes", (("role", "jobs+blobs"),))]


def test_disk_distinct_filesystems_are_separate(tmp_path):
    jobs, blobs = tmp_path / "jobs", tmp_path / "blobs"
    jobs.mkdir()
    blobs.mkdir()

    class _St:
        def __init__(self, blocks):
            self.f_blocks, self.f_frsize, self.f_bavail = blocks, 4096, blocks // 2

    fake = {str(jobs): _St(1000), str(blobs): _St(2000)}
    devs = {str(jobs): 1, str(blobs): 2}
    c = _collector(
        tmp_path,
        disk_roots={"jobs": jobs, "blobs": blobs},
        statvfs_fn=lambda p: fake[str(p)],
        dev_fn=lambda p: devs[str(p)],
    )
    s = _samples(c)
    assert s[("blastbox_host_disk_total_bytes", (("role", "jobs"),))] == 1000 * 4096
    assert s[("blastbox_host_disk_total_bytes", (("role", "blobs"),))] == 2000 * 4096
    assert s[("blastbox_host_disk_free_bytes", (("role", "blobs"),))] == 1000 * 4096


def test_disk_missing_or_unset_root_is_omitted(tmp_path):
    c = _collector(tmp_path, disk_roots={"jobs": tmp_path / "nope", "blobs": None})
    assert not any(n.startswith("blastbox_host_disk") for n in _names(c))


def test_node_view_series_when_available(tmp_path):
    view = NodeView(budget_ram_mib=1024.0, budget_vcpus=8.0,
                    allocated_ram_mib=512.0, allocated_vcpus=2.0)
    s = _samples(_collector(tmp_path, node_view_fn=lambda: view))
    assert s[("blastbox_node_budget_bytes", ())] == 1024 * 1024 * 1024
    assert s[("blastbox_node_budget_vcpus", ())] == 8.0
    assert s[("blastbox_node_allocated_bytes", ())] == 512 * 1024 * 1024
    assert s[("blastbox_node_allocated_vcpus", ())] == 2.0


def test_node_view_absent_or_raising_is_omitted(tmp_path):
    def boom():
        raise RuntimeError("share dir gone")

    for fn in (None, lambda: None, boom):
        names = _names(_collector(tmp_path, node_view_fn=fn))
        assert not any(n.startswith("blastbox_node_") for n in names)


def test_collect_never_raises_even_if_everything_fails(tmp_path):
    def boom(*_a):
        raise OSError("x")

    c = HostResourceCollector(
        proc_root=tmp_path / "nope", disk_roots={"jobs": tmp_path}, hostname="h",
        loadavg_fn=boom, cpu_count_fn=boom, statvfs_fn=boom, dev_fn=boom,
        node_view_fn=boom, clk_tck=100, cgroup_root=tmp_path / "nope",
        proc_self_cgroup=tmp_path / "nope",
    )
    assert _names(c) == {"blastbox_host_info"}


def test_collector_registers_and_renders(tmp_path):
    reg = CollectorRegistry()
    reg.register(_collector(tmp_path))
    text = generate_latest(reg).decode()
    assert 'blastbox_host_cpu_seconds_total{mode="idle"} 500.0' in text
    assert "# TYPE blastbox_host_cpu_seconds_total counter" in text


# ---------------------------------------------------------------------------
# node view from the shared node dir (read-only)
# ---------------------------------------------------------------------------


def _snap(engine: str, *, assigned: int, ram: float, vcpus: float, budget_ram: float,
          budget_vcpus: float, node: str = "") -> DemandSnapshot:
    return DemandSnapshot(
        engine=engine, backlog=0, assigned=assigned, slot_ram_mib=ram, slot_vcpus=vcpus,
        min_warm=0, max_ceiling=8, weight=1.0, ts=time.time(), node=node, tier="firecracker",
        instance="abc123", stale_after_s=20.0, budget_ram_mib=budget_ram,
        budget_vcpus=budget_vcpus,
    )


def test_read_node_view_consensus_budget_and_reservation(tmp_path):
    share = FileNodeShare(str(tmp_path / "node"))
    share.publish(_snap("aa", assigned=2, ram=1024, vcpus=1, budget_ram=8000, budget_vcpus=16))
    share.publish(_snap("bb", assigned=3, ram=512, vcpus=2, budget_ram=6000, budget_vcpus=20))
    view = read_node_view(str(tmp_path / "node"), stale_after_s=20.0, node="")
    assert view == NodeView(budget_ram_mib=6000, budget_vcpus=16,
                            allocated_ram_mib=2 * 1024 + 3 * 512, allocated_vcpus=2 + 6)


def test_read_node_view_filters_other_nodes(tmp_path):
    share = FileNodeShare(str(tmp_path / "node"))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=1000, budget_vcpus=4,
                        node="h1"))
    share.publish(_snap("bb", assigned=5, ram=100, vcpus=1, budget_ram=500, budget_vcpus=2,
                        node="h2"))
    view = read_node_view(str(tmp_path / "node"), stale_after_s=20.0, node="h1")
    assert view == NodeView(budget_ram_mib=1000, budget_vcpus=4,
                            allocated_ram_mib=100, allocated_vcpus=1)


def test_read_node_view_missing_dir_is_none_and_not_created(tmp_path):
    d = tmp_path / "absent"
    assert read_node_view(str(d), stale_after_s=20.0, node="") is None
    assert not d.exists()  # a scrape must never create the share dir


def test_read_node_view_does_not_gc(tmp_path):
    d = tmp_path / "node"
    d.mkdir()
    old = d / "leftover.json"
    old.write_text(json.dumps({"garbage": True}))
    os.utime(old, (1, 1))  # far past the GC floor
    read_node_view(str(d), stale_after_s=20.0, node="")
    assert old.exists()  # the scrape path is read-only


def test_read_node_view_no_budget_published_is_none(tmp_path):
    share = FileNodeShare(str(tmp_path / "node"))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=0, budget_vcpus=0))
    assert read_node_view(str(tmp_path / "node"), stale_after_s=20.0, node="") is None


# ---------------------------------------------------------------------------
# /metrics route
# ---------------------------------------------------------------------------


def test_metrics_route_includes_host_series(tmp_path):
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    app = build_app(job_store=InMemoryJobStore(), job_root=job_root, allowed_engines={"x"})
    body = TestClient(app).get("/metrics").text
    assert "blastbox_host_info{" in body
    assert 'blastbox_host_disk_total_bytes{role="' in body
    # the pre-existing process metrics are still served alongside
    assert "blastbox_jobs_in_flight" in body
    if Path("/proc/stat").exists():
        assert 'blastbox_host_cpu_seconds_total{mode="user"}' in body
        assert "blastbox_host_memory_total_bytes" in body


def test_two_apps_in_one_process_do_not_collide(tmp_path):
    for i in range(2):
        root = tmp_path / f"jobs{i}"
        root.mkdir()
        app = build_app(job_store=InMemoryJobStore(), job_root=root, allowed_engines={"x"})
        body = TestClient(app).get("/metrics").text
        assert body.count("# TYPE blastbox_host_info gauge") == 1


# ---------------------------------------------------------------------------
# review round 1
# ---------------------------------------------------------------------------


def test_hung_filesystem_cannot_starve_the_ingress(tmp_path):
    """A statvfs that never returns (hard NFS mount) must pin AT MOST one thread (for that source); every scrape
    still returns promptly and healthz keeps answering."""
    import asyncio
    import threading

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import Response

    gate = threading.Event()
    blocked = []

    def hung_statvfs(_p):
        blocked.append(threading.current_thread().name)
        gate.wait()
        raise OSError("nfs")

    reg = CollectorRegistry(auto_describe=False)
    reg.register(_collector(tmp_path, disk_roots={"blobs": tmp_path}, statvfs_fn=hung_statvfs,
                            refresh_wait_s=0.05))
    app = FastAPI()

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(reg))

    @app.get("/v1/healthz")
    def healthz():
        return {"ok": True}

    async def main():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://x") as c:
            scrapes = [asyncio.create_task(c.get("/metrics")) for _ in range(50)]
            done = await asyncio.wait_for(asyncio.gather(*scrapes), 10)
            assert all(r.status_code == 200 for r in done)
            assert all("blastbox_host_disk" not in r.text for r in done)  # omitted, not faked
            r = await asyncio.wait_for(c.get("/v1/healthz"), 3)
            assert r.status_code == 200

    try:
        asyncio.run(main())
        assert len(blocked) == 1  # single-flight: only ONE refresher ever entered statvfs
    finally:
        gate.set()


def test_disk_values_served_from_cache_then_omitted_when_too_stale(tmp_path):
    now = [1000.0]
    calls = []
    gate_hang = [False]
    import threading
    release = threading.Event()

    class _St:
        f_blocks, f_frsize, f_bavail = 100, 4096, 50

    def statvfs(_p):
        calls.append(1)
        if gate_hang[0]:
            release.wait()
        return _St()

    c = _collector(tmp_path, disk_roots={"jobs": tmp_path}, statvfs_fn=statvfs,
                   clock=lambda: now[0], refresh_ttl_s=10.0, max_stale_s=60.0,
                   refresh_wait_s=0.05)
    try:
        assert ("blastbox_host_disk_total_bytes", (("role", "jobs"),)) in _samples(c)
        # within TTL: served from cache, no new filesystem call
        now[0] += 5
        _samples(c)
        assert len(calls) == 1
        # past TTL, refresh hangs: last good values still served (within max_stale)
        gate_hang[0] = True
        now[0] += 20
        assert ("blastbox_host_disk_total_bytes", (("role", "jobs"),)) in _samples(c)
        # hung beyond max_stale: series omitted, scrape still returns
        now[0] += 60
        assert not any(n.startswith("blastbox_host_disk") for n in _names(c))
        assert len(calls) == 2  # still only the one hung refresh in flight
    finally:
        release.set()


def test_read_node_view_refuses_mixed_node_ids(tmp_path):
    share = FileNodeShare(str(tmp_path / "node"))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=8192, budget_vcpus=4,
                        node="h1"))
    share.publish(_snap("bb", assigned=1, ram=100, vcpus=1, budget_ram=8192, budget_vcpus=4,
                        node="h2"))
    # an untagged reader matches both hosts; summing them would be a lie → omitted
    assert read_node_view(str(tmp_path / "node"), stale_after_s=20.0, node="") is None


def test_readonly_reader_skips_fifo_symlink_and_oversize(tmp_path):
    d = tmp_path / "node"
    share = FileNodeShare(str(d))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=1000, budget_vcpus=4))
    os.mkfifo(d / "fifo.json")                      # would block a plain open()
    (d / "zero.json").symlink_to("/dev/zero")        # would read forever
    (d / "big.json").write_text("{" + " " * (128 * 1024) + "}")
    # a VALID snapshot outside the dir, linked in under its canonical name: only O_NOFOLLOW (or
    # the lstat prefilter) keeps it out — S_ISREG on the target would accept it
    outside = tmp_path / "outside"
    FileNodeShare(str(outside)).publish(
        _snap("cc", assigned=1, ram=100, vcpus=1, budget_ram=1000, budget_vcpus=4))
    (d / "cc@firecracker@abc123.json").symlink_to(outside / "cc@firecracker@abc123.json")
    got = read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time())
    assert got is not None and [s.engine for s in got] == ["aa"]


def _publish_n(d: Path, n: int) -> None:
    share = FileNodeShare(str(d))
    for i in range(n):
        share.publish(_snap(f"e{i:03d}", assigned=1, ram=100, vcpus=1, budget_ram=100000,
                            budget_vcpus=400))


def test_readonly_reader_over_cap_is_omitted_not_truncated(tmp_path, monkeypatch):
    d = tmp_path / "node"
    _publish_n(d, 20)
    opens = []
    real_open = os.open

    def counting_open(path, *a, **k):
        if str(path).startswith(str(d)):
            opens.append(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", counting_open)
    # more live candidates than the cap: a partial view would UNDERCOUNT → omitted instead
    assert read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time(), max_files=5) is None
    assert len(opens) <= 5
    opens.clear()
    got = read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time(), max_files=20)
    assert got is not None and len(got) == 20


def test_readonly_reader_junk_does_not_consume_the_cap(tmp_path):
    d = tmp_path / "node"
    _publish_n(d, 3)
    for i in range(10):
        os.mkfifo(d / f"fifo{i}.json")
        (d / f"link{i}.json").symlink_to("/dev/zero")
    got = read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time(), max_files=5)
    assert got is not None and len(got) == 3


def test_read_node_view_over_cap_is_omitted_with_warning(tmp_path, monkeypatch, caplog):
    import logging

    import blastbox.host.node_share as ns

    import blastbox.observability.host_metrics as hm

    monkeypatch.setattr(hm, "_warned_over_cap", False)
    d = tmp_path / "node"
    _publish_n(d, 10)
    monkeypatch.setattr(ns, "_RO_MAX_FILES", 4)
    with caplog.at_level(logging.WARNING):
        assert read_node_view(str(d), stale_after_s=20.0, node="") is None
    assert any("cap" in r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)


def test_mixed_node_omission_warns(tmp_path, caplog):
    import logging

    import blastbox.observability.host_metrics as hm

    hm._warned_mixed_nodes = False
    share = FileNodeShare(str(tmp_path / "node"))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=8192, budget_vcpus=4,
                        node="h1"))
    share.publish(_snap("bb", assigned=1, ram=100, vcpus=1, budget_ram=8192, budget_vcpus=4))
    with caplog.at_level(logging.WARNING):
        # "" counts as a distinct id — exact parity with DispatcherSizer.tick
        assert read_node_view(str(tmp_path / "node"), stale_after_s=20.0, node="") is None
    assert any("node id" in r.getMessage() for r in caplog.records
               if r.levelno == logging.WARNING)


def test_fs_cache_recovers_when_thread_start_fails(monkeypatch):
    import blastbox.observability.host_metrics as hm

    t = [0.0]
    cache = hm._FsCache(lambda: ("jobs", 1, 1),
                        clock=lambda: t[0], ttl_s=10, max_stale_s=60, wait_s=1)
    assert cache.get() is not None
    real = hm.threading.Thread.start

    def boom(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(hm.threading.Thread, "start", boom)
    t[0] = 11
    assert cache.get() is not None  # never raises; last good values still within max_stale
    monkeypatch.setattr(hm.threading.Thread, "start", real)
    t[0] = 20
    got = cache.get()                # the NEXT scrape retries (not wedged on a phantom refresh)
    assert got is not None
    t[0] = 75                        # 55s after the retry read the values: still fresh
    assert cache.get() is not None


def test_fs_cache_refresh_exception_clears_inflight():
    import blastbox.observability.host_metrics as hm

    t = [0.0]
    n = [0]

    def refresh():
        n[0] += 1
        if n[0] == 1:
            raise OSError("boom")
        return ("jobs", 1, 1)

    cache = hm._FsCache(refresh, clock=lambda: t[0], ttl_s=10, max_stale_s=60, wait_s=1)
    assert cache.get() is None
    t[0] = 11
    assert cache.get() is not None and n[0] == 2


def test_fs_cache_staleness_counts_from_refresh_start():
    import blastbox.observability.host_metrics as hm

    t = [1000.0]

    def slow_refresh():
        t[0] += 50  # the read took 50s (slow mount) — values are as old as its START
        return ("jobs", 1, 1)

    cache = hm._FsCache(slow_refresh, clock=lambda: t[0], ttl_s=100, max_stale_s=60, wait_s=1)
    assert cache.get() is not None   # age 50 <= 60
    t[0] += 15                       # age 65 from start (only 15 from completion)
    assert cache.get() is None


def test_readonly_reader_never_creates_dir(tmp_path, monkeypatch):
    d = tmp_path / "absent"
    calls = []
    monkeypatch.setattr(FileNodeShare, "__init__",
                        lambda *a, **k: calls.append(a) or None)
    assert read_node_view(str(d), stale_after_s=20.0, node="") is None
    assert not d.exists() and calls == []


def test_share_dir_permission_error_is_logged_once(tmp_path, caplog):
    import logging

    def denied():
        raise PermissionError("EACCES")

    c = _collector(tmp_path, node_view_fn=denied)
    with caplog.at_level(logging.WARNING):
        _names(c)
        c._node_cache.force_stale()  # next scrape refreshes again
        _names(c)
    warns = [r for r in caplog.records if "node" in r.getMessage().lower()
             and r.levelno == logging.WARNING]
    assert len(warns) == 1


def _cgroup(tmp_path: Path, files: dict[str, str], *, rel: str = "/") -> dict:
    root = tmp_path / "cg"
    target = root / rel.strip("/") if rel.strip("/") else root
    target.mkdir(parents=True, exist_ok=True)
    (root / "cgroup.controllers").write_text("cpu memory\n")
    for k, v in files.items():
        (target / k).write_text(v)
    selfcg = tmp_path / "self_cgroup"
    selfcg.write_text(f"0::{rel}\n")
    return {"cgroup_root": root, "proc_self_cgroup": selfcg}


def test_cgroup_v2_limits(tmp_path):
    kw = _cgroup(tmp_path, {"memory.max": "2147483648\n", "memory.current": "1048576\n",
                            "cpu.max": "200000 100000\n"}, rel="/docker/abc")
    s = _samples(_collector(tmp_path, **kw))
    assert s[("blastbox_cgroup_memory_max_bytes", ())] == 2147483648
    assert s[("blastbox_cgroup_memory_current_bytes", ())] == 1048576
    assert s[("blastbox_cgroup_cpu_quota_cores", ())] == 2.0


def test_cgroup_unlimited_is_omitted(tmp_path):
    kw = _cgroup(tmp_path, {"memory.max": "max\n", "memory.current": "5\n",
                            "cpu.max": "max 100000\n"})
    names = _names(_collector(tmp_path, **kw))
    assert "blastbox_cgroup_memory_max_bytes" not in names
    assert "blastbox_cgroup_cpu_quota_cores" not in names
    assert "blastbox_cgroup_memory_current_bytes" in names


def test_cgroup_v1_is_omitted(tmp_path):
    root = tmp_path / "cg"
    (root / "memory").mkdir(parents=True)
    (root / "memory" / "memory.limit_in_bytes").write_text("123\n")
    names = _names(_collector(tmp_path, cgroup_root=root))
    assert not any(n.startswith("blastbox_cgroup") for n in names)


# ---------------------------------------------------------------------------
# review round 3
# ---------------------------------------------------------------------------


def test_hung_node_share_does_not_blank_disk_series(tmp_path):
    import threading

    hang = threading.Event()

    def node_fn():
        hang.wait()
        return None

    t = [0.0]
    c = _collector(tmp_path, disk_roots={"jobs": tmp_path}, node_view_fn=node_fn,
                   clock=lambda: t[0], refresh_wait_s=0.1)
    try:
        assert "blastbox_host_disk_free_bytes" in _names(c)
        t[0] = 61
        assert "blastbox_host_disk_free_bytes" in _names(c)
    finally:
        hang.set()


def test_blocked_disk_root_only_omits_its_own_role(tmp_path, caplog):
    import logging
    import threading

    jobs, blobs = tmp_path / "jobs", tmp_path / "blobs"
    jobs.mkdir()
    blobs.mkdir()
    hang = threading.Event()

    class _St:
        f_blocks, f_frsize, f_bavail = 100, 4096, 50

    def statvfs(p):
        if str(p) == str(blobs):
            hang.wait()
        return _St()

    view = NodeView(budget_ram_mib=1, budget_vcpus=1, allocated_ram_mib=0, allocated_vcpus=0)
    t = [0.0]
    c = _collector(tmp_path, disk_roots={"jobs": jobs, "blobs": blobs}, statvfs_fn=statvfs,
                   dev_fn=lambda p: 1 if str(p) == str(jobs) else 2, node_view_fn=lambda: view,
                   clock=lambda: t[0], refresh_wait_s=0.1)
    try:
        with caplog.at_level(logging.WARNING):
            s = _samples(c)
            assert ("blastbox_host_disk_total_bytes", (("role", "jobs"),)) in s
            assert ("blastbox_host_disk_total_bytes", (("role", "blobs"),)) not in s
            assert ("blastbox_node_budget_bytes", ()) in s
            t[0] = 61
            s = _samples(c)
            _samples(c)
            assert ("blastbox_host_disk_total_bytes", (("role", "jobs"),)) in s
            assert ("blastbox_node_budget_bytes", ()) in s
        blocked = [r for r in caplog.records if r.levelno == logging.WARNING
                   and "blocked" in r.getMessage()]
        assert len(blocked) == 1 and "blobs" in blocked[0].getMessage()
    finally:
        hang.set()


def test_blocked_warning_rearms_after_recovery(caplog):
    import logging
    import threading

    import blastbox.observability.host_metrics as hm

    t = [0.0]
    gate = threading.Event()
    hang = [True]

    def refresh():
        if hang[0]:
            gate.wait()
        return 1

    cache = hm._FsCache(refresh, clock=lambda: t[0], ttl_s=10, max_stale_s=60, wait_s=0.05,
                        name="jobs")
    with caplog.at_level(logging.WARNING):
        cache.get()
        t[0] = 61
        cache.get()
        cache.get()
        hang[0] = False
        gate.set()
        for _ in range(100):  # let the released refresh finish
            if cache._inflight is None:
                break
            time.sleep(0.01)
        hang[0] = True
        gate.clear()
        t[0] = 80
        cache.get()          # new refresh, hangs again
        t[0] = 150
        cache.get()
    gate.set()
    blocked = [r for r in caplog.records if "blocked" in r.getMessage()]
    assert len(blocked) == 2


def test_cgroup_path_escape_falls_back_to_mount_root(tmp_path):
    root = tmp_path / "cg"
    root.mkdir()
    (root / "cgroup.controllers").write_text("memory\n")
    (root / "memory.max").write_text("1000\n")
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "memory.max").write_text("999999\n")
    selfcg = tmp_path / "self_cgroup"
    selfcg.write_text("0::/../evil\n")
    s = _samples(_collector(tmp_path, cgroup_root=root, proc_self_cgroup=selfcg))
    assert s[("blastbox_cgroup_memory_max_bytes", ())] == 1000


def test_readonly_reader_survives_short_reads(tmp_path, monkeypatch):
    d = tmp_path / "node"
    _publish_n(d, 3)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 7)))
    got = read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time())
    assert got is not None and len(got) == 3


def test_readonly_reader_unparseable_candidate_voids_the_view(tmp_path):
    d = tmp_path / "node"
    _publish_n(d, 3)
    (d / "e999.json").write_text('{"engine": "e999", "backl')  # torn/corrupt candidate
    assert read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time()) is None


def test_readonly_reader_still_skips_stale_snapshots(tmp_path):
    d = tmp_path / "node"
    share = FileNodeShare(str(d))
    share.publish(_snap("aa", assigned=1, ram=100, vcpus=1, budget_ram=1000, budget_vcpus=4))
    old = _snap("bb", assigned=1, ram=100, vcpus=1, budget_ram=1000, budget_vcpus=4)
    share.publish(DemandSnapshot(**{**old.__dict__, "ts": time.time() - 3600}))
    got = read_snapshots_readonly(str(d), max_age_s=20.0, now=time.time())
    assert got is not None and [s.engine for s in got] == ["aa"]
