"""blastbox — reusable detonation framework for untrusted documents.

Engine authors need only the lean core (`pip install blastbox`): implement the
``Engine`` protocol's ``detonate()`` and return a ``DetonationResult``; the
host orchestrator (``blastbox[host]``) handles ingress, disposable-worker
launch, output-trust validation, and serving.
"""
from blastbox.worker.engine import DetonationResult, Engine
from blastbox.worker.harness import run_detonation

__version__ = "0.1.5"  # keep in sync with pyproject [project].version

__all__ = ["Engine", "DetonationResult", "run_detonation", "__version__"]
