"""Product-route extension seam for the shared blastbox ingress.

A product (clippyshot, redtusk, …) mounts its own FastAPI routers — and,
optionally, its own static web UI — on top of the shared core
(submit/status/artifacts/auth/health/metrics) without forking build_app. The
core owns auth, limits, and the traversal-safe artifact path; product routers
inherit the app's middleware — do NOT re-implement auth in them.

Per-engine UI: an engine that ships a web front-end provides a ``StaticUI`` and
``build_app`` serves it at the site root. The UI is a peer of the engine's data
routes — both live in the engine's extension, so the generic core stays
UI-agnostic and each engine owns its own front-end + the routes that feed it.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter


@dataclass(frozen=True)
class StaticUI:
    """A per-engine web UI served by the ingress at the site root.

    ``directory`` is a filesystem path to the (built) UI; it must contain
    ``index`` (served for ``GET /``).  If an ``assets`` subdir exists it is
    mounted read-only at ``/assets``.  These paths are OPERATOR-configured (an
    engine's packaged ``static/`` dir), never derived from job data, so they are
    a trusted input — but ``build_app`` still resolves + confines them.
    """

    directory: str
    index: str = "index.html"
    assets_subdir: str = "assets"

    def index_path(self) -> Path:
        """Resolved path to the index file, confined under ``directory``."""
        base = Path(self.directory).resolve()
        candidate = (base / self.index).resolve()
        # Defense-in-depth: a stray '../' in `index` must not escape the UI dir.
        candidate.relative_to(base)
        return candidate

    def assets_path(self) -> Path | None:
        """Resolved ``assets`` subdir if it exists as a real directory, else None."""
        base = Path(self.directory).resolve()
        candidate = (base / self.assets_subdir).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            return None
        return candidate if candidate.is_dir() else None


@dataclass(frozen=True)
class IngressExtension:
    """Operator-provided product routes (+ optional web UI) on the shared ingress."""

    routers: tuple[APIRouter, ...] = ()
    static_ui: StaticUI | None = None


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
