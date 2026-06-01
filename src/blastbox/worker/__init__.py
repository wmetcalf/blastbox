"""Worker SDK for the blastbox framework.

The worker SDK is the keystone of Layer 2 — the code that runs inside the
disposable worker container.  Projects implement the ``Engine`` protocol
and call ``main()`` as their entrypoint; the harness handles everything else.

Typical engine usage::

    # my_engine/__main__.py
    import sys
    from blastbox.worker.harness import main
    from my_engine.engine import MyEngine

    if __name__ == "__main__":
        sys.exit(main(MyEngine()))
"""
from .engine import DetonationResult, Engine
from .harness import main, run_detonation

__all__ = [
    "DetonationResult",
    "Engine",
    "main",
    "run_detonation",
]
