"""Product-route extension seam for the shared blastbox ingress.

A product (clippyshot, redtusk, …) mounts its own FastAPI routers on top of the
shared core (submit/status/artifacts/auth/health/metrics) without forking
build_app. The core owns auth, limits, and the traversal-safe artifact path;
product routers inherit the app's middleware — do NOT re-implement auth in them.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter


@dataclass(frozen=True)
class IngressExtension:
    """Operator-provided product routes mounted on the shared ingress."""

    routers: tuple[APIRouter, ...] = ()
