"""Detect CRaC "warp" CPU-feature mismatches from a guest serial console.

A CRaC checkpoint records the CPU feature set of the host it was *created* on.
When that checkpoint is *restored* inside a Firecracker microVM (which exposes a
reduced feature set — a CPU template and/or what the guest kernel surfaces), the
warp engine aborts the restore if the checkpoint requires features the guest
lacks.  The JVM then dies with the generic ``Could not create the Java Virtual
Machine`` and, from the orchestrator's point of view, the warm slot simply never
signals READY — surfacing only as an opaque warmup timeout.

The warp engine, however, prints the *compatible* value on the guest console:

    [crac] Restore failed due to incompatible or missing CPU features,
           try using -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint.

So detection is a parse, not a guess.  :func:`parse_cpu_mismatch` extracts that
value; a consumer (e.g. a Firecracker warm pool, on warmup timeout) reads the
slot's captured console and, if a mismatch is found, raises
:class:`blastbox.errors.FcCpuFeatureMismatch` with an actionable remediation
instead of the opaque timeout.

This is the single source of truth for the warp error format — the one place to
update if the warp wording ever changes.  It is pure and has no FC/runtime
dependencies, so it imports cleanly on any host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The warp/CRaC restore error names the compatible value, e.g.
#   "... incompatible or missing CPU features, try using
#    -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint."
# DOTALL so a console with the message wrapped across lines still matches; the
# value charset is restricted to what -XX:CPUFeatures accepts (hex words +
# comma separators) so we stop at the first whitespace/end-of-token.
_MISMATCH_RE = re.compile(
    r"incompatible or missing CPU features.*?-XX:CPUFeatures=([0-9a-fx,]+)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class CpuFeatureMismatch:
    """A detected CRaC CPU-feature mismatch parsed from a guest console.

    ``needed`` is the value to pin on the checkpoint, e.g.
    ``"0x102100055bbd7,0x1c8"``.  ``raw_line`` is the matched text, for logs.
    Distinct from :class:`blastbox.errors.FcCpuFeatureMismatch`, which is the
    *raisable* error a consumer constructs from this finding.
    """

    needed: str
    raw_line: str


def parse_cpu_mismatch(console_text: str | None) -> CpuFeatureMismatch | None:
    """Scan a guest serial console for the warp CRaC CPU-feature-mismatch
    signature.

    Returns a :class:`CpuFeatureMismatch` carrying the compatible
    ``-XX:CPUFeatures`` value the warp engine reported, or ``None`` if the
    console shows no such mismatch — so callers fall back to their generic
    failure path with no behavior change on the happy path.
    """
    if not console_text:
        return None
    m = _MISMATCH_RE.search(console_text)
    if not m:
        return None
    return CpuFeatureMismatch(needed=m.group(1), raw_line=m.group(0).strip())
