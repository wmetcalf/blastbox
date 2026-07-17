"""Process-level handle to this serve process's warm pool + job store, so the pool
status/resize routes can reach them without threading them through build_app.

A serve process builds exactly one warm pool (cli._serve_cmd); it registers it here and
the `/v1/pool/*` routes read it back. Empty until registered — the status route then
reports `runtime: "cold"` and resize 503s, so nothing breaks on a cold (pool-less) node.
"""

from __future__ import annotations

from typing import Optional

_pool: object = None
_job_store: object = None


def register(pool: object, job_store: object) -> None:
    global _pool, _job_store
    _pool, _job_store = pool, job_store


def get_pool() -> Optional[object]:
    return _pool


def get_job_store() -> Optional[object]:
    return _job_store
