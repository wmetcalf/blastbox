"""Host resource gauges (CPU / RAM / disk / node budget) computed at SCRAPE time.

A custom Prometheus collector. ``/proc`` (stat, meminfo), ``os.getloadavg`` and cgroupfs are read
inline on every ``GET /metrics``, so those numbers are as current as the scrape. The FILESYSTEM part
(``os.statvfs`` of each job/blob root, the node share dir) is NOT read on the request thread: each
SOURCE has its own single-flight background refresher that re-reads it at most every
``refresh_ttl_s`` (10s); a scrape waits for them at most ``refresh_wait_s`` (1s) in total, and each
source's cached values are served until ``max_stale_s`` (60s) after they were read, then omitted. No new dependency (no psutil) — ``/proc`` + ``os`` only.

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
So that part is NEVER done on the request thread without a bound: per source, a single-flight
background refresh fills a cache, the scrape waits for it only briefly, serves the last good values
up to a staleness bound, and then omits that source's series only. At most one thread PER SOURCE
(each disk root + the node share, so <= 3) can ever be stuck on a hung filesystem, and a source
blocked longer than the staleness bound logs one WARNING.
"""
from __future__ import annotations

import functools
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

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
_warned_over_cap = False
_warned_thread_start = False


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
    global _warned_mixed_nodes, _warned_over_cap
    from blastbox.host.node_share import read_snapshots_readonly

    listed = read_snapshots_readonly(share_dir, max_age_s=stale_after_s, now=time.time())
    if listed is None:
        if not _warned_over_cap:
            _warned_over_cap = True
            _log.warning("node share dir %s holds more snapshot files than the read cap, or a "
                         "snapshot file that cannot be parsed; omitting blastbox_node_* series "
                         "rather than reporting a partial (undercounted) view", share_dir)
        return None
    snaps = [
        s for s in listed
        # same symmetric node filter the dispatchers apply
        if s.node == "" or node == "" or s.node == node
    ]
    # Exact parity with DispatcherSizer.tick: "" counts as a distinct id, so tagged + untagged
    # snapshots in one view is "mixed" too — the dispatchers fail closed on that same view.
    if len({s.node for s in snaps}) > 1:
        if not _warned_mixed_nodes:
            _warned_mixed_nodes = True
            _log.warning("node view mixes distinct node ids %s; omitting blastbox_node_* series "
                         "(set a CONSISTENT BLASTBOX_NODE_ID on every co-located dispatcher)",
                         sorted({s.node for s in snaps}))
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


def _warn_thread_start_once(exc: BaseException) -> None:
    global _warned_thread_start
    if not _warned_thread_start:
        _warned_thread_start = True
        _log.warning("could not start the metrics filesystem refresher (%s); disk/node series "
                     "will be retried on the next scrape", exc)


class _FsCache:
    """Single-flight, TTL'd cache of ONE filesystem-derived source (one disk root, or the node
    view). The collector keeps one per source, so a hung source ages out only its own series.

    A refresh runs on its own daemon thread, and a new one is started only when none is in flight,
    so a hung mount pins at most one thread PER SOURCE no matter how many scrapes arrive. The
    scrape that started a refresh waits for it up to ``wait_s``; values older than ``max_stale_s``
    (measured from when they were read) are not served at all. A refresh that raises keeps the
    last good value; one that RETURNS (including ``None``) replaces it. A refresh in flight longer
    than ``max_stale_s`` logs one WARNING, re-armed once it completes."""

    def __init__(self, refresh: "Callable[[], Any]", *, clock: Callable[[], float],
                 ttl_s: float, max_stale_s: float, wait_s: float, name: str = "fs") -> None:
        self._refresh = refresh
        self._clock = clock
        self._ttl_s = ttl_s
        self._max_stale_s = max_stale_s
        self._wait_s = wait_s
        self._name = name
        self._lock = threading.Lock()
        self._has_value = False
        self._value: Any = None
        self._done_at: Optional[float] = None   # when the served value was READ
        self._started_at: Optional[float] = None
        self._inflight: Optional[threading.Event] = None
        self._warned_blocked = False

    def kick(self) -> Optional[threading.Event]:
        """Start a refresh if one is due and none is in flight; return its completion event."""
        with self._lock:
            now = self._clock()
            if self._inflight is not None:
                if (self._started_at is not None and not self._warned_blocked
                        and now - self._started_at > self._max_stale_s):
                    self._warned_blocked = True
                    _log.warning("metrics refresh of %s has been blocked for %.0fs; its series "
                                 "are omitted", self._name, now - self._started_at)
                return None
            if self._started_at is not None and now - self._started_at < self._ttl_s:
                return None
            started = self._inflight = threading.Event()
            self._started_at = now
            try:
                threading.Thread(target=self._run, args=(started, now), daemon=True,
                                 name=f"blastbox-metrics-refresh-{self._name}").start()
            except Exception as exc:  # noqa: BLE001 - e.g. pids.max / RLIMIT_NPROC
                # Un-wedge: nothing will ever clear _inflight for a thread that never ran,
                # so clear it here and let the NEXT scrape retry.
                self._inflight = None
                self._started_at = None
                _warn_thread_start_once(exc)
                return None
            return started

    def peek(self) -> Any:
        """The cached value if it is fresh enough, else ``None``. Never blocks on the source."""
        with self._lock:
            if not self._has_value or self._done_at is None:
                return None
            if self._clock() - self._done_at > self._max_stale_s:
                return None
            return self._value

    def get(self) -> Any:
        started = self.kick()
        if started is not None:
            started.wait(self._wait_s)
        return self.peek()

    def force_stale(self) -> None:
        """Make the next ``get`` start a refresh (if none is in flight). For tests."""
        with self._lock:
            self._started_at = None

    def _run(self, done: threading.Event, read_at: float) -> None:
        ok, value = False, None
        try:
            value, ok = self._refresh(), True
        except Exception:  # noqa: BLE001 - keep the last good value
            ok = False
        finally:
            with self._lock:
                if ok:
                    self._has_value, self._value = True, value
                    # stamped with the refresh START: the value is as old as when it was read,
                    # so a slow mount can't stretch max_stale_s
                    self._done_at = read_at
                self._inflight = None
                if self._warned_blocked:
                    self._warned_blocked = False
                    _log.info("metrics refresh of %s recovered", self._name)
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
        self._wait_s = refresh_wait_s

        def cache(refresh: "Callable[[], Any]", name: str) -> _FsCache:
            return _FsCache(refresh, clock=clock, ttl_s=refresh_ttl_s, max_stale_s=max_stale_s,
                            wait_s=refresh_wait_s, name=name)

        # ONE independent cache per filesystem source: a hung blob mount must not blank the job
        # root's series or the node view (at most one stuck thread per source).
        self._disk_caches: dict[str, _FsCache] = {
            role: cache(functools.partial(self._read_disk, str(root)), role)
            for role, root in self._disk_roots.items() if root is not None
        }
        self._node_cache = cache(self._read_node, "node share")

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
        """This process's OWN cgroup v2 dir under the mount, or None. Never a guess: the mount
        root is used only when /proc/self/cgroup says the process IS in it (``0::/``, e.g. under
        a cgroup namespace). If the path is unreadable, missing, escapes the mount (``..``) or
        doesn't exist under it, the mount root is SOME OTHER cgroup (an ancestor / the ns root),
        and publishing its values as ours is exactly the misreport these series exist to avoid —
        so they are omitted."""
        root = self._cgroup_root
        if not (root / "cgroup.controllers").is_file():
            return None  # cgroup v1 (or no cgroupfs): omitted
        text = _read_small(self._proc_self_cgroup)
        if text is None:
            return None
        for line in text.splitlines():
            if line.startswith("0::"):
                rel = line[3:].strip().lstrip("/")
                if not rel:
                    return root
                if any(part in ("..", ".") for part in rel.split("/")):
                    return None
                cand = root / rel
                return cand if cand.is_dir() else None
        return None

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

    def _read_disk(self, path: str) -> "tuple[int, int, int]":
        """(st_dev, total bytes, free bytes) of one root. Raises if unreadable."""
        dev = self._dev_fn(path)
        st = self._statvfs_fn(path)
        return (dev,
                int(st.f_blocks) * int(st.f_frsize),  # type: ignore[attr-defined]
                int(st.f_bavail) * int(st.f_frsize))  # type: ignore[attr-defined]

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
        caches = [*self._disk_caches.values(), self._node_cache]
        # kick every due refresh FIRST, then wait on them under ONE shared deadline, so a scrape
        # waits at most refresh_wait_s in total however many sources are slow
        events = [e for e in (c.kick() for c in caches) if e is not None]
        deadline = time.monotonic() + self._wait_s
        for ev in events:
            ev.wait(max(0.0, deadline - time.monotonic()))
        # group roles by filesystem (st_dev) so a shared filesystem is reported ONCE — summing
        # per-role series on a dashboard must not double-count one disk.
        groups: dict[int, tuple[list[str], int, int]] = {}
        for role, c in self._disk_caches.items():
            got = c.peek()
            if got is None:
                continue
            dev, t, f = got
            if dev in groups:
                groups[dev][0].append(role)
            else:
                groups[dev] = ([role], t, f)
        if groups:
            total = GaugeMetricFamily("blastbox_host_disk_total_bytes",
                                      "Size of the filesystem backing a blastbox storage role",
                                      labels=["role"])
            free = GaugeMetricFamily("blastbox_host_disk_free_bytes",
                                     "Bytes available to non-root on that filesystem (f_bavail)",
                                     labels=["role"])
            for roles, t, f in groups.values():
                total.add_metric(["+".join(roles)], t)
                free.add_metric(["+".join(roles)], f)
            yield total
            yield free
        view = self._node_cache.peek()
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
