"""Engine protocol and DetonationResult for the worker SDK.

Every project that uses the blastbox framework implements the ``Engine``
protocol: a single ``detonate()`` method that reads an input file, writes
output artifacts into ``outdir``, and returns a ``DetonationResult``.

The harness (``harness.py``) calls ``engine.detonate()``, seals the result
into the contract ``Envelope``, and writes ``output_dir/metadata.json``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from blastbox.contract import (
    DeclaredArtifact,
    Detection,
    Warning,
)
from blastbox.contract.nodes import _Node
from blastbox.limits import Limits


@dataclass
class DetonationResult:
    """The ergonomic return type from ``Engine.detonate()``.

    The engine populates this with the payload tree, declared artifacts,
    detection metadata, optional warnings, and an optional status string.
    The harness takes care of hashing, path-confinement, and sealing.
    """

    # _Node, not ChildNode: ChildNode is the STATIC four-member union, but
    # contract.register_node_type() exists precisely so an engine can add its own payload
    # node, and Envelope.payload's annotation is rebuilt at registration. Annotating the
    # narrow union made every engine that uses the documented mechanism fail mypy, which
    # pushed authors back to stuffing typed data into Record.fields -- the thing the registry
    # exists to avoid.
    payload: _Node
    """The typed payload node tree (Page, Record, EmbeddedResource, …)."""

    artifacts: list[DeclaredArtifact]
    """id/path/kind of every file the engine wrote under outdir."""

    detected: Detection
    """The file-type detection result (from the engine's own detector, or
    forwarded from the host's pre-detonation detection)."""

    warnings: list[Warning] = field(default_factory=list)
    """Non-fatal advisory messages to surface to the caller."""

    status: Literal["ok", "rejected", "engine_error"] = "ok"
    """Detonation outcome: ``"ok"``, ``"rejected"``, or ``"engine_error"``."""


@runtime_checkable
class Engine(Protocol):
    """Protocol that every blastbox engine must satisfy.

    Only ``name``, ``formats``, and ``detonate`` are required.
    ``detect`` and ``warmup`` are optional and tested via ``hasattr``.
    """

    name: str
    """Short, URL-safe engine identifier (e.g. ``"clippyshot"``)."""

    formats: frozenset[str]
    """Set of format labels this engine handles (or ``frozenset({"*"})``)."""

    # Optional, read via getattr — default 1 (reset every job) when omitted.
    #
    #   jobs_per_recycle: int
    #
    # The engine author's RISK × COST call, surfaced to the warm pool. It says "how many jobs may a
    # warm worker serve before it must be reset", and is only honoured on tiers whose runtime can
    # reset a worker in place (``recycle()``); the cheap-reset container/microVM tiers stay
    # disposable-per-job regardless. Raise it when exploitation threat is LOW *and* recycle is
    # EXPENSIVE (e.g. a parse-only validator on a full-VM tier where reset = a multi-second
    # snapshot-revert). Leave it at 1 — the safe default — for anything that renders or executes
    # untrusted input, where every job needs a pristine worker. Generic to any engine; not a
    # special case.

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        """Run the detonation.

        Write any output artifacts as regular files under ``outdir``.
        Return a ``DetonationResult`` referencing every file written.
        Do NOT write ``metadata.json`` — the harness does that.

        Raises any exception to signal a fatal engine failure; the harness
        catches it and writes a clean ``engine_error`` envelope.
        """
        ...

    # ---------- optional methods (hasattr-guarded in the harness) ----------

    def detect(self, input: Path) -> Detection:
        """Pre-detonation detection (optional).

        If present, called before ``detonate()``; its result feeds
        ``DetonationResult.detected``.
        """
        ...

    def warmup(self) -> None:
        """Warm-pool initialisation (optional, warm-pool slice)."""
        ...
