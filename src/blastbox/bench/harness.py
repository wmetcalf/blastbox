"""Sampling harness + Report accumulator for benchmarks."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable

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
