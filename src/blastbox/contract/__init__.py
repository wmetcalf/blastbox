"""Typed data contract for the detonation framework.

Engines emit a typed payload tree + declared artifacts; the worker SDK seals
them into an Envelope (hashes, sizes, path-confinement); the host re-validates.
"""
from .leaf import Hash, Detection, Warning, ArtifactRef, Dimensions, Lang
from .nodes import (
    Record, ExtractedText, Page, EmbeddedResource,
    parse_node, register_node_type, rebuild_node_union,
)
from .envelope import (
    DeclaredArtifact, Artifact, Envelope,
    seal_envelope, validate_envelope, envelope_from_json,
)
from .walk import iter_nodes, find_by_type


def json_schema() -> dict:
    """Canonical JSON Schema for the Envelope (for non-Python engines)."""
    return Envelope.model_json_schema()


__all__ = [
    "Hash", "Detection", "Warning", "ArtifactRef", "Dimensions", "Lang",
    "Record", "ExtractedText", "Page", "EmbeddedResource",
    "parse_node", "register_node_type", "rebuild_node_union",
    "DeclaredArtifact", "Artifact", "Envelope",
    "seal_envelope", "validate_envelope", "envelope_from_json",
    "iter_nodes", "find_by_type", "json_schema",
]
