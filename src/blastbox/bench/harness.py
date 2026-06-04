"""Sampling harness + Report accumulator for benchmarks."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from blastbox.bench.stats import Comparison, Stats, compare, summarize

_log = logging.getLogger("blastbox.bench")


def measure(
    op: Callable[[], object],
    *,
    runs: int,
    warmup: int = 0,
    clock: Callable[[], float] = time.monotonic,
) -> list[float]:
    """Call ``op`` ``warmup + runs`` times; return the post-warmup durations.

    The clock is injectable for deterministic tests. An ``op`` that raises is
    logged and contributes no sample (the run still counts toward the loop)."""
    samples: list[float] = []
    for i in range(warmup + runs):
        start = clock()
        try:
            op()
        except Exception as exc:  # noqa: BLE001 — one bad sample must not abort the run
            _log.debug("bench.measure op raised on iter %d: %s", i, exc)
            continue
        elapsed = clock() - start
        if i >= warmup:
            samples.append(elapsed)
    return samples


@dataclass
class Report:
    """Accumulates named sample-sets for one scenario, with summaries + A/B."""

    scenario: str
    _samples: dict[str, list[float]] = field(default_factory=dict)

    def add(self, label: str, samples: list[float]) -> None:
        self._samples[label] = list(samples)

    def labels(self) -> list[str]:
        return list(self._samples)

    def samples(self, label: str) -> list[float]:
        return list(self._samples[label])

    def summary(self, label: str) -> Stats:
        return summarize(self._samples[label])

    def compare(self, baseline_label: str, candidate_label: str) -> Comparison:
        return compare(
            self.summary(baseline_label),
            self.summary(candidate_label),
            baseline_label=baseline_label,
            candidate_label=candidate_label,
        )

    def to_table(self, baseline: str | None = None) -> str:
        from blastbox.bench.report import to_table  # type: ignore[import-not-found]

        return to_table(self, baseline=baseline)

    def to_json(self) -> dict[str, Any]:
        from blastbox.bench.report import to_json  # type: ignore[import-not-found]

        return to_json(self)
