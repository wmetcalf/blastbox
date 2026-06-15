"""JobStore factory — select the backing store from ``BLASTBOX_DATABASE_URL``.

``blastbox serve`` (ingress) and ``blastbox dispatch`` run as SEPARATE processes; an
in-memory store is per-process, so jobs submitted to ``serve`` are invisible to ``dispatch``
unless both point at a SHARED store. This factory wires that one knob into both CLIs.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from blastbox.host.jobs.base import JobStore
from blastbox.host.jobs.memory import InMemoryJobStore

_log = logging.getLogger(__name__)
_warned_in_memory = False


def build_job_store_from_env(env: dict[str, str] | None = None) -> JobStore:
    """Return the JobStore selected by ``BLASTBOX_DATABASE_URL``.

    - unset                        -> ``InMemoryJobStore`` (SINGLE-PROCESS only — warns once,
                                      because ``serve`` + ``dispatch`` won't share it)
    - ``sqlite://`` / ``postgresql://`` (``postgres://``) -> ``SqlJobStore``
    - ``redis://`` / ``rediss://`` -> ``RedisJobStore``
    """
    e = os.environ if env is None else env
    url = e.get("BLASTBOX_DATABASE_URL", "").strip()
    if not url:
        global _warned_in_memory
        if not _warned_in_memory:
            _warned_in_memory = True
            _log.warning(
                "BLASTBOX_DATABASE_URL unset -> in-memory JobStore; `blastbox serve` and "
                "`blastbox dispatch` are SEPARATE processes and will NOT share it. Set "
                "BLASTBOX_DATABASE_URL (sqlite:///path, postgresql://..., or redis://...) "
                "for any multi-process deployment."
            )
        return InMemoryJobStore()

    scheme = urlparse(url).scheme.lower()
    if scheme in ("redis", "rediss"):
        import redis  # type: ignore[import-not-found]

        from blastbox.host.jobs.redis_store import RedisJobStore

        # NOTE: RedisJobStore list()/count()/claim_next() are O(N) in the live job count
        # (full scan_iter + decode; no server-side ORDER BY/LIMIT). Fine for modest histories
        # bounded by the TTL; for LARGE/high-throughput deployments prefer Postgres
        # (postgresql://...), whose SqlJobStore pushes the window + COUNT down into the query.
        #
        # BLASTBOX_REDIS_TTL_SECONDS overrides the per-key expiry (default 24h). The on-disk
        # job dir under BLASTBOX_JOB_ROOT is reaped by the store-driven retention sweeper, which
        # can only see jobs that still have a Redis key — so if a key TTL-expires before the
        # sweeper runs, its dir is orphaned (no record left for retention/API-delete). Keep the
        # Redis TTL >= BLASTBOX_JOB_RETENTION_SECONDS, or set BLASTBOX_REDIS_TTL_SECONDS=0 to
        # disable key expiry entirely and let retention own all cleanup.
        redis_kwargs: dict[str, int] = {}
        ttl_raw = e.get("BLASTBOX_REDIS_TTL_SECONDS", "").strip()
        if ttl_raw:
            try:
                ttl_val = int(ttl_raw)
            except ValueError:
                _log.warning(
                    "BLASTBOX_REDIS_TTL_SECONDS=%r is not an integer; using the store default",
                    ttl_raw,
                )
            else:
                if ttl_val < 0:
                    _log.warning(
                        "BLASTBOX_REDIS_TTL_SECONDS=%r is negative; using the store default "
                        "(set 0 to disable key expiry)",
                        ttl_raw,
                    )
                else:
                    redis_kwargs["ttl_seconds"] = ttl_val
        return RedisJobStore(redis.from_url(url), **redis_kwargs)

    from blastbox.host.jobs.sql_store import SqlJobStore

    return SqlJobStore(url)
