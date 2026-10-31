"""REA engine: Ghidra-backed static reverse engineering through REA's MCP server.

Runs only in the ``rea`` cold-worker image (deploy/docker/Dockerfile.rea-cold-worker),
which bundles REA (built from a pinned source commit), Ghidra and JDK 21. The engine
classes are added separately; this package exists so the image's build-time smoke can
import it.
"""
