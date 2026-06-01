"""Host-aware default worker caps.

The dispatcher launches one worker container per job.  Hard-coding memory /
CPU / concurrency defaults regardless of host means we either over-commit on
small machines (OOM / CPU thrash) or under-utilize on large ones.

``compute_host_defaults`` accepts injected ``cpu_count`` and ``mem_gb``
values so it is pure and unit-testable without reading ``/proc/meminfo``.
``apply_host_defaults`` reads the real host and pokes defaults into a dict
(defaulting to ``os.environ``) so unset ``BLASTBOX_*`` keys are filled in
at dispatcher startup.

Operator env overrides (``BLASTBOX_DISPATCH_CONCURRENCY``,
``BLASTBOX_WORKER_MEMORY``, ``BLASTBOX_WORKER_CPUS``,
``BLASTBOX_WORKER_PIDS_LIMIT``) always win — we only fill in values the
operator has not set.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass


_log = logging.getLogger("blastbox.host.runtime.host_limits")


@dataclass(frozen=True)
class HostDefaults:
    """Resolved worker caps for this host.

    Numbers are already formatted as the strings docker-cli expects
    (``"4g"``, ``"2.0"``, etc.) so downstream code can drop them into
    ``docker run`` argv without further processing.
    """

    concurrency: int
    worker_memory: str      # e.g. "3g"
    worker_cpus: str        # e.g. "2.0"
    worker_pids_limit: str  # e.g. "256"
    # Raw probe results — kept for observability.
    host_cpus: int
    host_mem_gb: float


# Hard caps so we never produce pathological values even on huge hosts.
_MAX_CONCURRENCY = 16
_MIN_WORKER_MEMORY_GB = 1.0
_MAX_WORKER_MEMORY_GB = 4.0
_MIN_WORKER_CPUS = 1.0
_MAX_WORKER_CPUS = 4.0
_DEFAULT_PIDS_LIMIT = 256
# Reserve this many GB of host memory for the OS + dispatcher + api +
# postgres so the worker budget doesn't starve the control plane.
_HEADROOM_GB = 1.0


def parse_memory_gb(spec: str) -> float:
    """Parse a docker-style memory spec like ``'4g'``, ``'512m'``, ``'1024'`` into GB."""
    if not spec:
        return 0.0
    s = spec.strip().lower()
    try:
        if s.endswith("g"):
            return float(s[:-1])
        if s.endswith("m"):
            return float(s[:-1]) / 1024.0
        if s.endswith("k"):
            return float(s[:-1]) / (1024.0 * 1024.0)
        # Plain number — assume bytes.
        return float(s) / (1024.0 ** 3)
    except ValueError:
        return 0.0


def _read_mem_available_gb() -> float:
    """Return MemAvailable (GB) from ``/proc/meminfo``, or ``MemTotal`` fallback.

    Returns ``0.0`` if ``/proc/meminfo`` isn't readable (e.g. non-Linux dev
    host); callers treat that as "don't auto-size memory, use the hardcoded
    fallback."
    """
    try:
        with open("/proc/meminfo") as f:
            fields: dict[str, int] = {}
            for line in f:
                key, _, rest = line.partition(":")
                rest = rest.strip()
                if rest.endswith(" kB"):
                    fields[key.strip()] = int(rest[:-3])
            kb = fields.get("MemAvailable") or fields.get("MemTotal") or 0
            return kb / (1024 * 1024)  # kB → GB
    except OSError:
        return 0.0


def compute_host_defaults(
    *,
    cpu_count: int | None = None,
    mem_gb: float | None = None,
    env: dict[str, str] | None = None,
) -> HostDefaults:
    """Compute worker-cap defaults sized to the host.

    Parameters
    ----------
    cpu_count:
        Injected CPU count; defaults to ``os.cpu_count()`` (or 2 on failure).
    mem_gb:
        Injected total/available memory in GB; defaults to reading
        ``/proc/meminfo``.  Pass ``0.0`` to simulate a probe failure.
    env:
        Environment dict to consult for operator overrides.  Defaults to a
        snapshot of ``os.environ``.  Values already set there are preserved
        verbatim; anything else is filled in from the host probe.
    """
    if env is None:
        env = dict(os.environ)
    if cpu_count is None:
        cpu_count = os.cpu_count() or 2
    if mem_gb is None:
        mem_gb = _read_mem_available_gb()

    # ------------------------------------------------------------------
    # Concurrency — half the host CPUs, clamped.
    # ------------------------------------------------------------------
    if env.get("BLASTBOX_DISPATCH_CONCURRENCY"):
        try:
            concurrency = max(1, int(env["BLASTBOX_DISPATCH_CONCURRENCY"]))
        except ValueError:
            concurrency = max(1, min(_MAX_CONCURRENCY, cpu_count // 2))
    else:
        concurrency = max(1, min(_MAX_CONCURRENCY, cpu_count // 2))

    # ------------------------------------------------------------------
    # Per-worker CPUs — split total among concurrent workers, clamped.
    # ------------------------------------------------------------------
    if env.get("BLASTBOX_WORKER_CPUS"):
        worker_cpus_str = env["BLASTBOX_WORKER_CPUS"]
    else:
        worker_cpus = max(_MIN_WORKER_CPUS, min(_MAX_WORKER_CPUS, cpu_count / concurrency))
        # Preserve the ".0" suffix docker expects for non-integer values.
        if worker_cpus == int(worker_cpus):
            worker_cpus_str = f"{int(worker_cpus)}.0"
        else:
            worker_cpus_str = f"{worker_cpus:.1f}"

    # ------------------------------------------------------------------
    # Per-worker memory — divide headroom-adjusted host memory by
    # concurrency, clamped.  If probe failed, fall back to 4g.
    # ------------------------------------------------------------------
    if env.get("BLASTBOX_WORKER_MEMORY"):
        worker_mem_str = env["BLASTBOX_WORKER_MEMORY"]
    elif mem_gb <= 0:
        worker_mem_str = "4g"
    else:
        usable = max(0.0, mem_gb - _HEADROOM_GB)
        per = max(_MIN_WORKER_MEMORY_GB, min(_MAX_WORKER_MEMORY_GB, usable / concurrency))
        # Round down to the nearest 256 MB so docker-cli output is tidy.
        quantum = 0.25
        per_rounded = max(_MIN_WORKER_MEMORY_GB, int(per / quantum) * quantum)
        if per_rounded == int(per_rounded):
            worker_mem_str = f"{int(per_rounded)}g"
        else:
            worker_mem_str = f"{int(per_rounded * 1024)}m"

    pids_limit = env.get("BLASTBOX_WORKER_PIDS_LIMIT") or str(_DEFAULT_PIDS_LIMIT)

    return HostDefaults(
        concurrency=concurrency,
        worker_memory=worker_mem_str,
        worker_cpus=worker_cpus_str,
        worker_pids_limit=pids_limit,
        host_cpus=cpu_count,
        host_mem_gb=round(mem_gb, 2),
    )


def apply_host_defaults(
    *,
    cpu_count: int | None = None,
    mem_gb: float | None = None,
    env: dict[str, str] | None = None,
) -> HostDefaults:
    """Resolve defaults and poke them into an environment dict for unset keys.

    Called once from the dispatcher bootstrap.  After this, anything that
    reads ``BLASTBOX_WORKER_MEMORY`` / ``_CPUS`` / ``_PIDS_LIMIT`` or
    ``BLASTBOX_DISPATCH_CONCURRENCY`` sees the computed values as if the
    operator had set them explicitly — including ``build_worker_docker_run_argv``.

    Parameters
    ----------
    cpu_count, mem_gb:
        Injected values for testability; default to real host probe.
    env:
        Mutable environment dict to update.  Defaults to ``os.environ``.

    Returns
    -------
    The resolved ``HostDefaults``, so callers can log them.
    """
    # Use a concrete dict reference so mypy can confirm .get() and assignment.
    effective_env: dict[str, str] = env if env is not None else dict(os.environ)
    # When defaulting to os.environ we want to mutate os.environ itself so that
    # the running process picks up the defaults.  Re-bind to os.environ for
    # the mutation path when env was None.
    target_env: dict[str, str] = env if env is not None else os.environ  # type: ignore[assignment]

    defaults = compute_host_defaults(cpu_count=cpu_count, mem_gb=mem_gb, env=effective_env)

    def _set_if_blank(key: str, value: str) -> None:
        # Treat both missing AND empty-string (compose sets "" when unset) as
        # unset so we always end up with a meaningful value.
        if not target_env.get(key):
            target_env[key] = value

    _set_if_blank("BLASTBOX_DISPATCH_CONCURRENCY", str(defaults.concurrency))
    _set_if_blank("BLASTBOX_WORKER_MEMORY", defaults.worker_memory)
    _set_if_blank("BLASTBOX_WORKER_CPUS", defaults.worker_cpus)
    _set_if_blank("BLASTBOX_WORKER_PIDS_LIMIT", defaults.worker_pids_limit)

    _log.info(
        "worker_caps_resolved host_cpus=%d host_mem_gb=%.2f concurrency=%d "
        "worker_memory=%s worker_cpus=%s worker_pids=%s",
        defaults.host_cpus,
        defaults.host_mem_gb,
        defaults.concurrency,
        defaults.worker_memory,
        defaults.worker_cpus,
        defaults.worker_pids_limit,
    )
    return defaults
