"""Framework-provided engines.

blastbox is mostly a framework (domain engines like ClippyShot live in their own
repos), but it ships one *generic* engine: :class:`~blastbox.engines.detonate.DetonateEngine`,
which runs an allow-listed command-line tool on the input and returns its output as
a sealed artifact — the building block for content-gated, sandboxed
detection-as-code (cold one-shot detonation of an arbitrary tool, with provenance).
"""
from blastbox.engines.detonate import DetonateEngine

__all__ = ["DetonateEngine"]
