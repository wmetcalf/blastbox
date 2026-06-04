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


@dataclass(frozen=True)
class Comparison:
    """A vs B on p50. ``speedup`` > 1 means the candidate is faster than the baseline."""

    baseline: str
    candidate: str
    speedup: float
    overhead_pct: float


def compare(
    baseline: Stats,
    candidate: Stats,
    *,
    baseline_label: str = "baseline",
    candidate_label: str = "candidate",
) -> Comparison:
    """Compare two Stats on p50."""
    speedup = baseline.p50 / candidate.p50 if candidate.p50 else float("inf")
    overhead_pct = (
        (candidate.p50 / baseline.p50 - 1.0) * 100.0 if baseline.p50 else 0.0
    )
    return Comparison(
        baseline=baseline_label,
        candidate=candidate_label,
        speedup=speedup,
        overhead_pct=overhead_pct,
    )
