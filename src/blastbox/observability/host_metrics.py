"""Host resource gauges (CPU / RAM / disk / node budget) computed at SCRAPE time.

A custom Prometheus collector, not a background thread: every ``GET /metrics`` reads ``/proc``,
``os.getloadavg`` and ``os.statvfs`` fresh, so the numbers are as current as the scrape and cost
nothing between scrapes. No new dependency (no psutil) — ``/proc`` + ``os`` only.

Truthfulness rule: a series that cannot be read is OMITTED. On a non-Linux host, a container with
``/proc`` masked, a missing job root, etc. the affected series simply vanish from the exposition;
``collect()`` never raises and never emits a fabricated zero (a zero would read as "idle" / "full"
on a dashboard, which is worse than a gap).

Inside a container ``/proc/stat``, ``/proc/meminfo`` and the load average describe the HOST kernel
(they are not namespaced), while the disk series describe the filesystems mounted INTO the
container at the job/blob roots.
"""
from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

#: /proc/stat aggregate ``cpu`` columns, in kernel order. guest/guest_nice are deliberately
#: excluded — the kernel already folds them into user/nice, so exporting them double-counts.
CPU_MODES: tuple[str, ...] = (
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
)

_MIB = 1024 * 1024


def _clk_tck() -> int:
    try:
        v = os.sysconf("SC_CLK_TCK")
        return v if v > 0 else 100
    except (AttributeError, ValueError, OSError):
        return 100


def parse_proc_stat(text: str, *, clk_tck: int) -> dict[str, float]:
    """The aggregate ``cpu`` line of ``/proc/stat`` as ``{mode: seconds}``.

    Only columns actually present are returned (an old kernel without iowait/steal yields fewer
    modes, never zero-filled ones). Anything unparseable → ``{}``."""
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "cpu":
            continue
        out: dict[str, float] = {}
        try:
            for mode, raw in zip(CPU_MODES, parts[1:]):
                out[mode] = int(raw) / float(clk_tck)
        except ValueError:
            return {}
        return out
    return {}


def parse_meminfo(text: str) -> dict[str, int]:
    """``/proc/meminfo`` as ``{key: bytes}`` (the kernel reports kB = KiB). Malformed lines are
    skipped, not zero-filled."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        fields = rest.split()
        if not fields:
            continue
        try:
            n = int(fields[0])
        except ValueError:
            continue
        unit = fields[1].lower() if len(fields) > 1 else ""
        out[key.strip()] = n * 1024 if unit == "kb" else n
    return out


@dataclass(frozen=True)
class NodeView:
    """The node autosizer's budget vs what the node's pools currently reserve."""

    budget_ram_mib: float
    budget_vcpus: float
    allocated_ram_mib: float
    allocated_vcpus: float


def read_node_view(share_dir: str, *, stale_after_s: float, node: str) -> Optional[NodeView]:
    """Read the dispatchers' shared node view (``BLASTBOX_NODE_SHARE_DIR``) READ-ONLY.

    budget    = the consensus node budget every dispatcher plans against (elementwise MIN of the
                published budgets — see ``DispatcherSizer.tick``).
    allocated = Σ each pool's published reservation (``assigned`` = resident/in-flight slots in
                warm-slot units) × its per-slot footprint — what the pools are holding now.

    Never creates the dir and never GCs it (a scrape is an observer, not a dispatcher). ``None``
    when the dir is absent or no live snapshot published a budget."""
    from blastbox.host.node_share import FileNodeShare

    if not Path(share_dir).is_dir():
        return None  # checked BEFORE constructing: FileNodeShare() would mkdir it
    snaps = [
        s for s in FileNodeShare(share_dir).read_all(
            max_age_s=stale_after_s, now=time.time(), gc=False)
        # same symmetric node filter the dispatchers apply
        if s.node == "" or node == "" or s.node == node
    ]
    ram = [s.budget_ram_mib for s in snaps if s.budget_ram_mib > 0]
    vcpu = [s.budget_vcpus for s in snaps if s.budget_vcpus > 0]
    if not ram or not vcpu:
        return None
    return NodeView(
        budget_ram_mib=min(ram),
        budget_vcpus=min(vcpu),
        allocated_ram_mib=sum(s.assigned * s.slot_ram_mib for s in snaps),
        allocated_vcpus=sum(s.assigned * s.slot_vcpus for s in snaps),
    )


def node_view_fn_from_env() -> Optional[Callable[[], Optional[NodeView]]]:
    """A scrape-time node-view reader when the node autosizer is configured in THIS process's env
    (``BLASTBOX_NODE_*``), else ``None``. The sizer itself runs in the dispatch process; the
    ingress sees it only through the shared node dir, so that dir must be mounted here too."""
    try:
        from blastbox.host.node_config import NodeConfig

        cfg = NodeConfig.from_env()
        if not cfg.active:
            return None
        share_dir, stale = cfg.share_dir, cfg.stale_after_s
        node = os.environ.get("BLASTBOX_NODE_ID", "").strip()
    except Exception:
        return None
    return lambda: read_node_view(share_dir, stale_after_s=stale, node=node)


def _default_hostname() -> str:
    return os.environ.get("BLASTBOX_HOST_ID", "").strip() or socket.gethostname()


class HostResourceCollector(Collector):
    """Emits ``blastbox_host_*`` (and, when available, ``blastbox_node_*``) at collect time."""

    def __init__(
        self,
        *,
        disk_roots: Mapping[str, "Path | str | None"],
        proc_root: "Path | str" = "/proc",
        hostname: Optional[str] = None,
        node_view_fn: Optional[Callable[[], Optional[NodeView]]] = None,
        loadavg_fn: Callable[[], "tuple[float, float, float]"] = os.getloadavg,
        cpu_count_fn: Callable[[], Optional[int]] = os.cpu_count,
        statvfs_fn: Callable[[str], object] = os.statvfs,
        dev_fn: Callable[[str], int] = lambda p: os.stat(p).st_dev,
        clk_tck: Optional[int] = None,
    ) -> None:
        self._disk_roots = dict(disk_roots)
        self._proc = Path(proc_root)
        self._hostname = hostname
        self._node_view_fn = node_view_fn
        self._loadavg_fn = loadavg_fn
        self._cpu_count_fn = cpu_count_fn
        self._statvfs_fn = statvfs_fn
        self._dev_fn = dev_fn
        self._clk_tck = clk_tck

    def collect(self) -> Iterable[GaugeMetricFamily | CounterMetricFamily]:
        for section in (self._info, self._cpu, self._load, self._memory, self._disk, self._node):
            try:
                families = list(section())
            except Exception:  # noqa: BLE001 - a scrape must never raise; the section is omitted
                continue
            yield from families

    # -- sections ------------------------------------------------------------

    def _info(self) -> Iterable[GaugeMetricFamily]:
        from blastbox import __version__

        try:
            host = self._hostname or _default_hostname()
        except Exception:  # noqa: BLE001
            host = ""
        g = GaugeMetricFamily("blastbox_host_info", "blastbox host identity (value is always 1)",
                              labels=["hostname", "version"])
        g.add_metric([host, __version__], 1)
        yield g

    def _cpu(self) -> Iterable[GaugeMetricFamily | CounterMetricFamily]:
        try:
            count = self._cpu_count_fn()
        except Exception:  # noqa: BLE001 - omit the count, still report CPU time
            count = None
        if count:
            yield GaugeMetricFamily("blastbox_host_cpu_count", "Logical CPUs on the host",
                                    value=count)
        try:
            text = (self._proc / "stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            return
        modes = parse_proc_stat(text, clk_tck=self._clk_tck or _clk_tck())
        if not modes:
            return
        c = CounterMetricFamily("blastbox_host_cpu_seconds",
                                "Host CPU time by mode, all CPUs summed (/proc/stat)",
                                labels=["mode"])
        for mode, secs in modes.items():
            c.add_metric([mode], secs)
        yield c

    def _load(self) -> Iterable[GaugeMetricFamily]:
        l1, l5, l15 = self._loadavg_fn()
        for name, v, window in (("load1", l1, "1m"), ("load5", l5, "5m"),
                                ("load15", l15, "15m")):
            yield GaugeMetricFamily(f"blastbox_host_{name}", f"Host load average ({window})",
                                    value=float(v))

    def _memory(self) -> Iterable[GaugeMetricFamily]:
        try:
            text = (self._proc / "meminfo").read_text(encoding="ascii", errors="replace")
        except OSError:
            return
        mem = parse_meminfo(text)
        if "MemTotal" in mem:
            yield GaugeMetricFamily("blastbox_host_memory_total_bytes",
                                    "Host RAM (/proc/meminfo MemTotal)", value=mem["MemTotal"])
        if "MemAvailable" in mem:
            yield GaugeMetricFamily("blastbox_host_memory_available_bytes",
                                    "Host RAM available for new work (/proc/meminfo MemAvailable)",
                                    value=mem["MemAvailable"])

    def _disk(self) -> Iterable[GaugeMetricFamily]:
        # group roles by filesystem (st_dev) so a shared filesystem is reported ONCE — summing
        # per-role series on a dashboard must not double-count one disk.
        groups: dict[int, tuple[list[str], str]] = {}
        for role, root in self._disk_roots.items():
            if root is None:
                continue
            path = str(root)
            try:
                dev = self._dev_fn(path)
            except Exception:  # noqa: BLE001 - missing/unreadable root → omitted
                continue
            if dev in groups:
                groups[dev][0].append(role)
            else:
                groups[dev] = ([role], path)
        total = GaugeMetricFamily("blastbox_host_disk_total_bytes",
                                  "Size of the filesystem backing a blastbox storage role",
                                  labels=["role"])
        free = GaugeMetricFamily("blastbox_host_disk_free_bytes",
                                 "Bytes available to non-root on that filesystem (f_bavail)",
                                 labels=["role"])
        any_ok = False
        for roles, path in groups.values():
            try:
                st = self._statvfs_fn(path)
                t = int(st.f_blocks) * int(st.f_frsize)  # type: ignore[attr-defined]
                f = int(st.f_bavail) * int(st.f_frsize)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                continue
            label = "+".join(roles)
            total.add_metric([label], t)
            free.add_metric([label], f)
            any_ok = True
        if any_ok:
            yield total
            yield free

    def _node(self) -> Iterable[GaugeMetricFamily]:
        if self._node_view_fn is None:
            return
        view = self._node_view_fn()
        if view is None:
            return
        yield GaugeMetricFamily("blastbox_node_budget_bytes",
                                "Node autosizer consensus RAM budget for pools",
                                value=view.budget_ram_mib * _MIB)
        yield GaugeMetricFamily("blastbox_node_budget_vcpus",
                                "Node autosizer consensus vCPU budget for pools",
                                value=view.budget_vcpus)
        yield GaugeMetricFamily("blastbox_node_allocated_bytes",
                                "RAM the node's pools currently reserve (published reservations)",
                                value=view.allocated_ram_mib * _MIB)
        yield GaugeMetricFamily("blastbox_node_allocated_vcpus",
                                "vCPU the node's pools currently reserve (published reservations)",
                                value=view.allocated_vcpus)
