"""REA engine: Ghidra-backed static reverse engineering through REA's MCP server.

Runs only in the ``rea`` cold-worker image (deploy/docker/Dockerfile.rea-cold-worker),
which bundles REA (built from a pinned source commit), Ghidra and JDK 21.
``ReaSweepEngine`` (``rea``) is the deterministic pass 0.
"""

from blastbox.engines.rea.sweep import ReaSweepEngine

__all__ = ["ReaSweepEngine"]
