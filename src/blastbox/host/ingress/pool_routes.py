"""`/v1/pool/*` control surface for the node coordinator.

  GET  /v1/pool/status  — this engine's pool state + queue backlog (read-only telemetry,
                          low sensitivity, like /metrics). What the coordinator scrapes.
  POST /v1/pool/resize  — apply a new warm_size / concurrent_ceiling. MUTATING, so it is
                          fail-closed behind BLASTBOX_ADMIN_TOKEN: unset → 503 (feature
                          off, nothing to attack), present → Bearer must match.

Both read the process's pool via pool_registry; a cold (pool-less) node reports
runtime "cold" and resize returns 409.
"""

from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from blastbox.host import pool_registry


class ResizeRequest(BaseModel):
    warm_size: int | None = None
    concurrent_ceiling: int | None = None


def _backlog(job_store: object) -> int:
    if job_store is None:
        return 0
    try:
        from blastbox.host.jobs.base import JobStatus
        return int(job_store.count(JobStatus.QUEUED))  # type: ignore[attr-defined]
    except Exception:
        return 0


def _require_admin(authorization: str | None) -> None:
    token = os.environ.get("BLASTBOX_ADMIN_TOKEN", "").strip()
    if not token:
        # feature not enabled → present nothing to attack
        raise HTTPException(status_code=503, detail="pool resize disabled (set BLASTBOX_ADMIN_TOKEN)")
    presented = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if not hmac.compare_digest(presented, token):
        raise HTTPException(status_code=401, detail="invalid admin token")


def build_pool_router() -> APIRouter:
    router = APIRouter()

    @router.get("/v1/pool/status")
    def pool_status() -> dict:
        pool = pool_registry.get_pool()
        if pool is None:
            return {"runtime": "cold", "assigned": 0, "burst_active": False,
                    "backlog": _backlog(pool_registry.get_job_store()),
                    "warm_size": 0, "concurrent_ceiling": 0, "slot_count": 0}
        return {
            "runtime": os.environ.get("BLASTBOX_POOL_RUNTIME", "none").strip().lower(),
            "assigned": getattr(pool, "assigned_count", 0),
            "burst_active": getattr(pool, "burst_active", False),
            "backlog": _backlog(pool_registry.get_job_store()),
            "warm_size": getattr(pool, "warm_size", 0),
            "concurrent_ceiling": getattr(pool, "concurrent_ceiling", 0),
            "slot_count": getattr(pool, "slot_count", 0),
        }

    @router.post("/v1/pool/resize")
    def pool_resize(body: ResizeRequest, authorization: str | None = Header(default=None)) -> dict:
        _require_admin(authorization)
        pool = pool_registry.get_pool()
        if pool is None or not hasattr(pool, "resize"):
            raise HTTPException(status_code=409, detail="no resizable warm pool in this process")
        try:
            pool.resize(warm_size=body.warm_size, concurrent_ceiling=body.concurrent_ceiling)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {"warm_size": getattr(pool, "warm_size", None),
                "concurrent_ceiling": getattr(pool, "concurrent_ceiling", None)}

    return router
