"""Host resource gauges (CPU / RAM / disk / node budget) computed at SCRAPE time.

A custom Prometheus collector, not a background thread: every ``GET /metrics`` reads ``/proc``,
``os.getloadavg`` and ``os.statvfs`` fresh, so the numbers are as current as the scrape and cost
nothing between scrapes. No new dependency (no psutil) — ``/proc`` + ``os`` only.

Truthfulness rule: a series that cannot be read is OMITTED. On a non-Linux host, a container with
``/proc`` masked, a missing job root, etc. the affected series simply vanish from the exposition;
``collect()`` never raises and never emits a fabricated zero (a zero would read as "idle" / "full"
on a dashboard, which is worse than a gap).

Inside a container ``/proc/stat``, ``/proc/meminfo`` and the load average normally describe the
HOST kernel (they are not namespaced — unless LXCFS or a gVisor sandbox virtualizes them), while the
disk series describe the filesystems mounted INTO the container at the job/blob roots. The cgroup v2
series show the container's own ceiling.

Filesystem work (statvfs of the job/blob roots, the node share dir) can block uninterruptibly on a
hung network mount, and ``/metrics`` shares the ingress's sync-route thread pool with ``/v1/healthz``.
So that part is NEVER done on the request thread without a bound: a single-flight background refresh
fills a cache, the scrape waits for it only briefly, serves the last good values up to a staleness
bound, and then omits them. At most ONE thread can ever be stuck on a hung filesystem.
"""
from __future__ import annotations

import logging
import os
import threading
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


_log = logging.getLogger("blastbox.observability.host_metrics")
_warned_mixed_nodes = False


def read_node_view(share_dir: str, *, stale_after_s: float, node: str) -> Optional[NodeView]:
    """Read the dispatchers' shared node view (``BLASTBOX_NODE_SHARE_DIR``) READ-ONLY.

    budget    = the consensus node budget every dispatcher plans against (elementwise MIN of the
                published budgets — see ``DispatcherSizer.tick``).
    allocated = Σ each pool's published reservation (``assigned`` = resident/in-flight slots in
                warm-slot units) × its per-slot footprint — what the pools are holding now.

    Uses ``read_snapshots_readonly``: never creates, chmods or GCs the dir, reads only bounded
    regular files. ``None`` when the dir is absent, no live snapshot published a budget, or the
    matched snapshots MIX node ids (the same fail-closed condition as ``DispatcherSizer.tick`` —
    summing two hosts' pools into one budget would be a lie). A permission error propagates."""
    global _warned_mixed_nodes
    from blastbox.host.node_share import read_snapshots_readonly

    snaps = [
        s for s in read_snapshots_readonly(share_dir, max_age_s=stale_after_s, now=time.time())
        # same symmetric node filter the dispatchers apply
        if s.node == "" or node == "" or s.node == node
    ]
    if len({s.node for s in snaps}) > 1:
        if not _warned_mixed_nodes:
            _warned_mixed_nodes = True
            _log.debug("node view mixes distinct node ids %s; omitting blastbox_node_* series "
                       "(set a consistent BLASTBOX_NODE_ID)", sorted({s.node for s in snaps}))
        return None
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


@dataclass(frozen=True)
class _FsValues:
    disk: "tuple[tuple[str, int, int], ...]"   # (role label, total bytes, free bytes)
    node: Optional[NodeView]


class _FsCache:
    """Single-flight, TTL'd cache of the filesystem-derived values.

    A refresh runs on its own daemon thread, and a new one is started only when none is in flight,
    so a hung mount pins at most one thread no matter how many scrapes arrive. The scrape that
    started a refresh waits for it up to ``wait_s``; values older than ``max_stale_s`` (measured
    from when they were read) are not served at all."""

    def __init__(self, refresh: "Callable[[], _FsValues]", *, clock: Callable[[], float],
                 ttl_s: float, max_stale_s: float, wait_s: float) -> None:
        self._refresh = refresh
        self._clock = clock
        self._ttl_s = ttl_s
        self._max_stale_s = max_stale_s
        self._wait_s = wait_s
        self._lock = threading.Lock()
        self._values: Optional[_FsValues] = None
        self._done_at: Optional[float] = None
        self._started_at: Optional[float] = None
        self._inflight: Optional[threading.Event] = None

    def get(self) -> Optional[_FsValues]:
        started: Optional[threading.Event] = None
        with self._lock:
            now = self._clock()
            due = self._started_at is None or now - self._started_at >= self._ttl_s
            if self._inflight is None and due:
                started = self._inflight = threading.Event()
                self._started_at = now
                threading.Thread(target=self._run, args=(started,), daemon=True,
                                 name="blastbox-metrics-fs-refresh").start()
        if started is not None:
            started.wait(self._wait_s)
        with self._lock:
            if self._values is None or self._done_at is None:
                return None
            if self._clock() - self._done_at > self._max_stale_s:
                return None
            return self._values

    def force_stale(self) -> None:
        """Make the next ``get`` start a refresh (if none is in flight). For tests."""
        with self._lock:
            self._started_at = None

    def _run(self, done: threading.Event) -> None:
        try:
            values: Optional[_FsValues] = self._refresh()
        except Exception:  # noqa: BLE001 - keep the last good values
            values = None
        with self._lock:
            if values is not None:
                self._values = values
                self._done_at = self._clock()
            self._inflight = None
        done.set()


def _read_small(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None


class HostResourceCollector(Collector):
    """Emits ``blastbox_host_*``, ``blastbox_cgroup_*`` and (when available) ``blastbox_node_*``."""

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
        cgroup_root: "Path | str" = "/sys/fs/cgroup",
        proc_self_cgroup: "Path | str | None" = None,
        clock: Callable[[], float] = time.monotonic,
        refresh_ttl_s: float = 10.0,
        max_stale_s: float = 60.0,
        refresh_wait_s: float = 1.0,
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
        self._cgroup_root = Path(cgroup_root)
        self._proc_self_cgroup = (Path(proc_self_cgroup) if proc_self_cgroup is not None
                                  else self._proc / "self" / "cgroup")
        self._warned_node_perm = False
        self._fs = _FsCache(self._refresh_fs, clock=clock, ttl_s=refresh_ttl_s,
                            max_stale_s=max_stale_s, wait_s=refresh_wait_s)

    def collect(self) -> Iterable[GaugeMetricFamily | CounterMetricFamily]:
        for section in (self._info, self._cpu, self._load, self._memory, self._cgroup,
                        self._fs_sections):
            try:
                families = list(section())
            except Exception:  # noqa: BLE001 - a scrape must never raise; the section is omitted
                continue
            yield from families

    # -- inline (procfs / cgroupfs: never block on storage) ------------------

    def _info(self) -> Iterable[GaugeMetricFamily]:
        from blastbox import __version__

        # The machine's real hostname is NOT published: /metrics is unauthenticated by default.
        # Only an operator-chosen public name (BLASTBOX_HOST_ID) becomes a label.
        host = self._hostname or os.environ.get("BLASTBOX_HOST_ID", "").strip()
        if host:
            g = GaugeMetricFamily("blastbox_host_info",
                                  "blastbox host identity (value is always 1)",
                                  labels=["hostname", "version"])
            g.add_metric([host, __version__], 1)
        else:
            g = GaugeMetricFamily("blastbox_host_info",
                                  "blastbox host identity (value is always 1)",
                                  labels=["version"])
            g.add_metric([__version__], 1)
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

    def _cgroup_dir(self) -> Optional[Path]:
        root = self._cgroup_root
        if not (root / "cgroup.controllers").is_file():
            return None  # cgroup v1 (or no cgroupfs): omitted
        text = _read_small(self._proc_self_cgroup) or ""
        for line in text.splitlines():
            if line.startswith("0::"):
                rel = line[3:].strip().lstrip("/")
                cand = root / rel if rel else root
                # without a cgroup namespace the recorded path may not exist under this mount;
                # the mount root is then the process's own cgroup (container) — use it
                return cand if cand.is_dir() else root
        return root

    def _cgroup(self) -> Iterable[GaugeMetricFamily]:
        d = self._cgroup_dir()
        if d is None:
            return
        mx = _read_small(d / "memory.max")
        if mx and mx != "max":
            try:
                yield GaugeMetricFamily("blastbox_cgroup_memory_max_bytes",
                                        "cgroup v2 memory.max of this process's cgroup",
                                        value=int(mx))
            except ValueError:
                pass
        cur = _read_small(d / "memory.current")
        if cur:
            try:
                yield GaugeMetricFamily("blastbox_cgroup_memory_current_bytes",
                                        "cgroup v2 memory.current of this process's cgroup",
                                        value=int(cur))
            except ValueError:
                pass
        cpu = _read_small(d / "cpu.max")
        if cpu:
            parts = cpu.split()
            if len(parts) == 2 and parts[0] != "max":
                try:
                    quota, period = int(parts[0]), int(parts[1])
                except ValueError:
                    return
                if period > 0:
                    yield GaugeMetricFamily("blastbox_cgroup_cpu_quota_cores",
                                            "cgroup v2 cpu.max quota / period, in cores",
                                            value=quota / period)

    # -- filesystem (cached, single-flight, off the request thread) ----------

    def _refresh_fs(self) -> _FsValues:
        return _FsValues(disk=self._read_disks(), node=self._read_node())

    def _read_disks(self) -> "tuple[tuple[str, int, int], ...]":
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
        out: list[tuple[str, int, int]] = []
        for roles, path in groups.values():
            try:
                st = self._statvfs_fn(path)
                t = int(st.f_blocks) * int(st.f_frsize)  # type: ignore[attr-defined]
                f = int(st.f_bavail) * int(st.f_frsize)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                continue
            out.append(("+".join(roles), t, f))
        return tuple(out)

    def _read_node(self) -> Optional[NodeView]:
        if self._node_view_fn is None:
            return None
        try:
            return self._node_view_fn()
        except PermissionError as exc:
            if not self._warned_node_perm:
                self._warned_node_perm = True
                _log.warning("cannot read the node share dir (%s); blastbox_node_* series are "
                             "omitted. The ingress uid needs read+execute on "
                             "BLASTBOX_NODE_SHARE_DIR (e.g. membership of its group).", exc)
            return None
        except Exception as exc:  # noqa: BLE001
            _log.debug("node view unavailable: %s", exc)
            return None

    def _fs_sections(self) -> Iterable[GaugeMetricFamily]:
        vals = self._fs.get()
        if vals is None:
            return
        if vals.disk:
            total = GaugeMetricFamily("blastbox_host_disk_total_bytes",
                                      "Size of the filesystem backing a blastbox storage role",
                                      labels=["role"])
            free = GaugeMetricFamily("blastbox_host_disk_free_bytes",
                                     "Bytes available to non-root on that filesystem (f_bavail)",
                                     labels=["role"])
            for label, t, f in vals.disk:
                total.add_metric([label], t)
                free.add_metric([label], f)
            yield total
            yield free
        view = vals.node
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
