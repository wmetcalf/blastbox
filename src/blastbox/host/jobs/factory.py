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

        return RedisJobStore(redis.from_url(url))

    from blastbox.host.jobs.sql_store import SqlJobStore

    return SqlJobStore(url)
