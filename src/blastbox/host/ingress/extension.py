"""Product-route extension seam for the shared blastbox ingress.

A product (clippyshot, redtusk, …) mounts its own FastAPI routers on top of the
shared core (submit/status/artifacts/auth/health/metrics) without forking
build_app. The core owns auth, limits, and the traversal-safe artifact path;
product routers inherit the app's middleware — do NOT re-implement auth in them.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass

from fastapi import APIRouter


@dataclass(frozen=True)
class IngressExtension:
    """Operator-provided product routes mounted on the shared ingress."""

    routers: tuple[APIRouter, ...] = ()


def load_ingress_extension(spec: str | None) -> IngressExtension | None:
    """Resolve ``BLASTBOX_INGRESS_EXTENSION='module:factory'`` to an
    IngressExtension.

    ``factory`` is a zero-arg callable returning an IngressExtension. This is
    operator-configured and never derived from job data — it mirrors the engine
    seam (``BLASTBOX_FC_ENGINE='module:Class'``). Returns None for an empty or
    whitespace-only spec.
    """
    spec = (spec or "").strip()
    if not spec:
        return None
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise ValueError(
            f"BLASTBOX_INGRESS_EXTENSION must be 'module:factory', got {spec!r}"
        )
    ext = getattr(importlib.import_module(mod), attr)()
    if not isinstance(ext, IngressExtension):
        raise TypeError(f"{spec!r} factory did not return an IngressExtension")
    return ext
