"""Resolve an engine selector ``'module:Class'`` to an Engine instance.

The reusable, package-level form of the FC demo's ``deploy/firecracker/engines.py``
``get_engine()`` resolver: operator-configured (``BLASTBOX_ENGINE`` env or a baked
``/opt/blastbox/engine`` file), never derived from job data.
"""
from __future__ import annotations

import importlib

from blastbox.worker.engine import Engine


def load_engine(spec: str) -> Engine:
    """Import ``module`` and instantiate ``Class`` from ``'module:Class'``."""
    mod, sep, cls = spec.partition(":")
    if not sep or not mod or not cls:
        raise ValueError(f"engine selector must be 'module:Class', got {spec!r}")
    engine = getattr(importlib.import_module(mod), cls)()
    return engine
