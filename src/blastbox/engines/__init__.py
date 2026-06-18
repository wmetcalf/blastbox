"""Reference example engines — NOT domain engines.

blastbox is a framework: real domain engines (ClippyShot, RedTusk, …) live in their
own repos and plug in via ``BLASTBOX_ENGINE=module:Class``. This package holds two
runnable *examples* that exercise the framework seams:

* :class:`~blastbox.engines.detonate.DetonateEngine` — runs an allow-listed command-line
  tool on the input and seals its output: the building block for content-gated, sandboxed
  detection-as-code (cold one-shot detonation of an arbitrary tool, with provenance).
* :mod:`blastbox.engines.urlgrab` (``UrlGrabEngine``) — the reference example for the
  network overlay: fetch one URL, seal the response (see the module docstring). Loaded by
  env like any engine; intentionally not re-exported here (it is a demo, not public API).
"""
from blastbox.engines.detonate import DetonateEngine

__all__ = ["DetonateEngine"]
