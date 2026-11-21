"""REA engine: Ghidra-backed static reverse engineering through REA's MCP server.

Runs only in the ``rea`` cold-worker image (deploy/docker/Dockerfile.rea-cold-worker),
which bundles REA (built from a pinned source commit), Ghidra and JDK 21.
``ReaSweepEngine`` (``rea``) is the deterministic pass 0; ``ReaAgentEngine`` (``rea-agent``)
runs the model-driven passes 1..N over the continuation pass 0 produced.
"""

from blastbox.engines.rea.agent import ReaAgentEngine
from blastbox.engines.rea.sweep import ReaSweepEngine

__all__ = ["ReaAgentEngine", "ReaSweepEngine"]
