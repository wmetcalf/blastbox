"""The security envelope: sealed by the worker SDK, re-validated by the host."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .leaf import Detection, Warning
from .nodes import ChildNode, _REBUILD_CALLBACKS, parse_node


class DeclaredArtifact(BaseModel):
    """What an engine declares; the SDK turns it into a sealed Artifact."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    path: str = Field(max_length=4096)   # outdir-relative
    kind: str = Field(min_length=1, max_length=64)


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    path: str
    kind: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=0)


class Envelope(BaseModel):
    """A signed, sealed, and validated job result envelope.

    The ``payload`` field is typed as ``Annotated[ChildNode, ...]`` at class
    definition time.  After each ``register_node_type()`` call,
    ``_rebuild_envelope()`` is triggered via ``nodes._REBUILD_CALLBACKS`` and
    calls ``Envelope.model_rebuild(force=True, _types_namespace=...)`` so that
    pydantic re-evaluates the ``"_PayloadNode"`` forward-ref string against the
    current live union — without any top-level circular import.
    """
    model_config = ConfigDict(extra="forbid")
    engine: str = Field(min_length=1, max_length=64)
    status: Literal["ok", "rejected", "engine_error"] = "ok"
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    detected: Detection
    artifacts: list[Artifact] = Field(default_factory=list)
    warnings: list[Warning] = Field(default_factory=list)
    # Initial annotation uses ChildNode (the base union); _rebuild_envelope()
    # replaces model_fields["payload"].annotation with the live Node union after
    # each register_node_type() call so engine subtypes are also accepted.
    payload: Annotated[ChildNode, Field(discriminator="type")]


def _rebuild_envelope() -> None:
    """Rebuild Envelope against the current live Node union.

    Called by nodes.rebuild_node_union() via _REBUILD_CALLBACKS.
    Uses a lazy import to avoid a circular dependency at module-top level.
    Updates the ``payload`` field's annotation to the current live ``Node``
    union so pydantic regenerates the discriminated-union validator correctly.
    """
    import blastbox.contract.nodes as _nodes
    Envelope.model_fields["payload"].annotation = _nodes.Node  # type: ignore[assignment]
    Envelope.model_rebuild(force=True)


# Register so every rebuild_node_union() call (triggered by register_node_type)
# also refreshes the Envelope discriminated union.
_REBUILD_CALLBACKS.append(_rebuild_envelope)
# Apply immediately so the initial union is in place.
_rebuild_envelope()


def _collect_refs(node) -> set[str]:
    """Walk a node tree and collect every ArtifactRef.id it references."""
    from .leaf import ArtifactRef as _ArtifactRef

    refs: set[str] = set()
    stack: list = [node]
    while stack:
        v = stack.pop()
        if isinstance(v, _ArtifactRef):
            refs.add(v.id)
        elif isinstance(v, BaseModel):
            for f in type(v).model_fields:
                stack.append(getattr(v, f))
        elif isinstance(v, (list, tuple)):
            for it in v:
                stack.append(it)
        elif isinstance(v, dict):
            for it in v.values():
                stack.append(it)
    return refs


def seal_envelope(*, engine: str, outdir: Path, input_sha256: str,
                  detected: Detection, declared: list[DeclaredArtifact],
                  warnings: list[Warning], payload: ChildNode,
                  status: Literal["ok", "rejected", "engine_error"] = "ok",
                  max_artifact_bytes: int | None = None) -> Envelope:
    """Seal declared artifacts + payload into a validated Envelope.

    Computes sha256/bytes from disk, confines every path under outdir, and
    verifies every ArtifactRef in the payload resolves to a declared id.
    Raises ValueError on any violation — the worker must not emit on failure.

    Size is taken from ``stat()`` and (when ``max_artifact_bytes`` is set) the cap is
    enforced **before** any bytes are read, then the hash is computed in CHUNKS — so a
    malicious worker declaring a giant artifact is rejected without the host ever reading
    the whole file into memory.
    """
    outdir_resolved = outdir.resolve(strict=False)
    artifacts: list[Artifact] = []
    declared_ids: set[str] = set()
    for d in declared:
        if d.id in declared_ids:
            raise ValueError(f"duplicate artifact id: {d.id}")
        declared_ids.add(d.id)
        target = (outdir / d.path).resolve(strict=False)
        if outdir_resolved != target and outdir_resolved not in target.parents:
            raise ValueError(f"artifact path not confined to outdir: {d.path}")
        if not target.is_file():
            raise ValueError(f"declared artifact file missing or not a regular file: {d.path}")
        size = target.stat().st_size
        if max_artifact_bytes is not None and size > max_artifact_bytes:
            # Reject BEFORE reading — no unbounded read into memory from a hostile worker.
            raise ValueError(
                f"declared artifact {d.path} size {size} exceeds {max_artifact_bytes}"
            )
        digest = hashlib.sha256()
        with target.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        artifacts.append(Artifact(id=d.id, path=d.path, kind=d.kind,
                                  sha256=digest.hexdigest(), bytes=size))
    unresolved = _collect_refs(payload) - declared_ids
    if unresolved:
        raise ValueError(f"payload has unresolved ArtifactRef(s): {sorted(unresolved)}")
    return Envelope(engine=engine, status=status, input_sha256=input_sha256,
                    detected=detected, artifacts=artifacts, warnings=warnings,
                    payload=payload)


def validate_envelope(env: Envelope, *, outdir: Path, max_artifact_bytes: int,
                      max_total_bytes: int, max_artifacts: int) -> Envelope:
    """Host-side re-validation: enforce count/size bounds and verify on-disk sizes.

    Re-stats every artifact file under outdir to confirm st_size matches
    the declared bytes (so a tampered worker-reported size is caught).
    Raises ValueError on any violation.
    """
    if len(env.artifacts) > max_artifacts:
        raise ValueError(f"artifact count {len(env.artifacts)} exceeds {max_artifacts}")
    outdir_resolved = outdir.resolve(strict=False)
    total = 0
    for a in env.artifacts:
        target = (outdir / a.path).resolve(strict=False)
        if outdir_resolved != target and outdir_resolved not in target.parents:
            raise ValueError(f"artifact path not confined to outdir: {a.path}")
        if not target.is_file():
            raise ValueError(f"artifact file missing or not a regular file: {a.path}")
        actual_size = target.stat().st_size
        if actual_size != a.bytes:
            raise ValueError(
                f"artifact {a.id} declared bytes={a.bytes} but on-disk size={actual_size}"
            )
        if actual_size > max_artifact_bytes:
            raise ValueError(f"artifact {a.id} bytes {actual_size} exceeds {max_artifact_bytes}")
        total += actual_size
    if total > max_total_bytes:
        raise ValueError(f"total artifact bytes {total} exceeds {max_total_bytes}")
    return env


def envelope_from_json(raw: bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Envelope:
    """Parse a worker-emitted metadata.json into an Envelope (size-bounded)."""
    if len(raw) > max_bytes:
        raise ValueError(f"metadata json {len(raw)} bytes exceeds {max_bytes}")
    import json
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("envelope JSON must be a JSON object")
    payload_data = obj.get("payload")
    if payload_data is None:
        raise ValueError("envelope JSON missing required 'payload' field")
    obj["payload"] = parse_node(payload_data)
    return Envelope.model_validate(obj)
