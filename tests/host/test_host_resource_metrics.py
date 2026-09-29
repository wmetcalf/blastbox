"""Host resource gauges on the ingress ``/metrics`` (CPU / RAM / disk / node budget).

Everything is computed at SCRAPE time from ``/proc`` + ``os.statvfs`` by a custom collector; the
proc root, statvfs, loadavg and the node view are injectable so these tests never depend on the
machine running them. The contract under test: a series that cannot be read truthfully is
OMITTED — a scrape never raises and never emits a fabricated zero.
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
        node_view_fn=boom, clk_tck=100,
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
