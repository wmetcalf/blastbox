"""Resolve an engine selector ``'module:Class'`` to an Engine instance.

The reusable, package-level form of the FC demo's ``deploy/firecracker/engines.py``
``get_engine()`` resolver. The selector string itself is operator-configured and
never derived from job data; how it reaches a worker (the ``BLASTBOX_ENGINE`` env
var for the cold path, a baked ``/opt/blastbox/engine`` file read by the FC/gVisor
entrypoints) is the caller's concern — this function only resolves a ``module:Class``
string to an instance.
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
