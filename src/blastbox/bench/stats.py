"""Pure statistics for benchmark samples — no I/O, fully unit-testable."""
from __future__ import annotations

import statistics
from dataclasses import dataclass


@dataclass(frozen=True)
class Stats:
    """Summary of one set of timing samples (seconds)."""

    n: int
    p50: float
    p90: float
    p99: float
    mean: float
    min: float
    max: float
    stdev: float


def _percentile(sorted_xs: list[float], p: float) -> float:
    """Linear-interpolated percentile of an already-sorted list (0 <= p <= 100)."""
    if not sorted_xs:
        raise ValueError("no samples")
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    k = (len(sorted_xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_xs) - 1)
    return sorted_xs[f] + (sorted_xs[c] - sorted_xs[f]) * (k - f)


def summarize(samples: list[float]) -> Stats:
    """Summarize timing samples. Raises ``ValueError`` on an empty list."""
    if not samples:
        raise ValueError("no samples to summarize")
    xs = sorted(samples)
    return Stats(
        n=len(xs),
        p50=_percentile(xs, 50),
        p90=_percentile(xs, 90),
        p99=_percentile(xs, 99),
        mean=statistics.fmean(xs),
        min=xs[0],
        max=xs[-1],
        stdev=statistics.pstdev(xs) if len(xs) > 1 else 0.0,
    )
