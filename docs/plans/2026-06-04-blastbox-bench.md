# blastbox.bench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runtime-agnostic performance-benchmarking capability in blastbox — a generic stats + sampling core, a scenario registry (snapshot tier, sandbox overhead, conversion), and two front-ends (`blastbox bench` CLI + a `perf`-marked pytest ratio gate).

**Architecture:** A new `src/blastbox/bench/` package. Pure core (`stats.py`, `harness.py`, `report.py`) is fully unit-tested with fixed arrays + an injected clock. `scenarios.py` is a `@scenario(name, requires=…)` registry whose real scenarios *wrap* the already-merged `SnapshotSlotRuntime` / `select_sandbox` primitives and `skip` cleanly when prerequisites are absent. The CLI and the perf gate both drive the same core.

**Tech Stack:** Python 3.12, stdlib only (`statistics`, `time`, `argparse`, `json`, `dataclasses`, `typing.Protocol`), pytest, ruff, mypy. Spec: `docs/specs/2026-06-04-blastbox-bench-design.md`.

**Conventions:** every task ends ruff + mypy clean (`/.venv/bin/ruff check src tests`, `/.venv/bin/mypy src`). Run tests with `/.venv/bin/pytest`. Frozen dataclasses + `Protocol`, mirroring the existing `worker/sandbox/base.py` + `limits.py` style. Commit after each task.

---

## File Structure

| path | responsibility |
|---|---|
| `src/blastbox/bench/__init__.py` | re-export `summarize`, `compare`, `Stats`, `Comparison`, `measure`, `Report`, `scenario`, `get_scenario`, `list_scenarios`, `BenchConfig`, `ScenarioResult` |
| `src/blastbox/bench/stats.py` | `Stats`, `Comparison`, `summarize`, `compare`, `_percentile` (pure) |
| `src/blastbox/bench/harness.py` | `measure`, `Report` (sample accumulator) |
| `src/blastbox/bench/report.py` | `to_table(Report)`, `to_json(Report)` (formatting) |
| `src/blastbox/bench/scenarios.py` | `@scenario` registry, `BenchConfig`, `ScenarioResult`, `check_requirement`, `get_scenario`, `list_scenarios`, and the initial scenarios |
| `src/blastbox/host/cli.py` | add the `bench` subcommand to `build_parser` + `_bench_cmd` |
| `tests/bench/test_stats.py` … `test_cli_bench.py` | unit tests (fixed arrays, injected clock, fake scenarios) |
| `tests/perf/test_perf_gates.py` | `perf`-marked ratio gates |
| `pyproject.toml` | register the `perf` pytest marker |

Type contract (used consistently across tasks):

```python
# stats.py
@dataclass(frozen=True)
class Stats:
    n: int; p50: float; p90: float; p99: float
    mean: float; min: float; max: float; stdev: float

@dataclass(frozen=True)
class Comparison:
    baseline: str    # label
    candidate: str   # label
    speedup: float       # baseline.p50 / candidate.p50  (>1 → candidate faster)
    overhead_pct: float  # (candidate.p50/baseline.p50 - 1)*100  (>0 → candidate slower)

# scenarios.py
@dataclass(frozen=True)
class BenchConfig:
    runs: int = 12
    warmup: int = 3
    params: dict[str, str] = field(default_factory=dict)

@dataclass
class ScenarioResult:
    report: "Report"
    status: str   # "ok" | "skipped" | "insufficient"
    note: str = ""
```

---

## Task 1: Package skeleton + `perf` marker

**Files:**
- Create: `src/blastbox/bench/__init__.py` (empty for now)
- Modify: `pyproject.toml` (`[tool.pytest.ini_options]`)
- Create: `tests/bench/__init__.py`, `tests/perf/__init__.py`

- [ ] **Step 1: Create the package + test dirs**

```bash
mkdir -p src/blastbox/bench tests/bench tests/perf
printf '"""blastbox.bench — performance benchmarking, stats & comparisons."""\n' > src/blastbox/bench/__init__.py
: > tests/bench/__init__.py
: > tests/perf/__init__.py
```

- [ ] **Step 2: Register the `perf` marker**

In `pyproject.toml`, under `[tool.pytest.ini_options]`, add `perf` to the `markers` list (create the list if absent):

```toml
markers = [
    "integration: needs sandbox + soffice (run in the image)",
    "docker: exercises the built Docker image",
    "perf: performance benchmark gate; needs a benchmarkable host (skipped otherwise)",
]
```

(If `markers` already exists, append only the `perf` line — do not drop existing entries.)

- [ ] **Step 3: Verify**

Run: `/.venv/bin/pytest --markers | grep perf`
Expected: the `perf` marker is listed.

- [ ] **Step 4: Commit**

```bash
git add src/blastbox/bench/__init__.py tests/bench/__init__.py tests/perf/__init__.py pyproject.toml
git commit -m "chore(bench): package skeleton + perf pytest marker"
```

---

## Task 2: `stats.py` — `Stats` + `summarize` + `_percentile`

**Files:**
- Create: `src/blastbox/bench/stats.py`
- Test: `tests/bench/test_stats.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_stats.py
import math
import pytest
from blastbox.bench.stats import Stats, summarize, _percentile


def test_percentile_linear_interpolation():
    xs = [10.0, 20.0, 30.0, 40.0]  # sorted
    assert _percentile(xs, 50) == 25.0   # between 20 and 30
    assert _percentile(xs, 0) == 10.0
    assert _percentile(xs, 100) == 40.0


def test_summarize_basic():
    s = summarize([10.0, 20.0, 30.0, 40.0, 50.0])
    assert s.n == 5
    assert s.min == 10.0 and s.max == 50.0
    assert s.mean == 30.0
    assert s.p50 == 30.0


def test_summarize_single_sample_has_zero_stdev():
    s = summarize([7.0])
    assert s.n == 1 and s.stdev == 0.0 and s.p50 == 7.0


def test_summarize_empty_raises():
    with pytest.raises(ValueError):
        summarize([])
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_stats.py -q`
Expected: FAIL (module `blastbox.bench.stats` does not exist).

- [ ] **Step 3: Implement**

```python
# src/blastbox/bench/stats.py
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `/.venv/bin/pytest tests/bench/test_stats.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + commit**

```bash
/.venv/bin/ruff check src/blastbox/bench/stats.py tests/bench/test_stats.py && /.venv/bin/mypy src/blastbox/bench/stats.py
git add src/blastbox/bench/stats.py tests/bench/test_stats.py
git commit -m "feat(bench): stats summarize + percentile"
```

---

## Task 3: `stats.py` — `Comparison` + `compare`

**Files:**
- Modify: `src/blastbox/bench/stats.py`
- Test: `tests/bench/test_stats.py`

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/bench/test_stats.py
from blastbox.bench.stats import Comparison, compare


def test_compare_speedup_and_overhead():
    baseline = summarize([100.0] * 5)   # p50 = 100
    candidate = summarize([25.0] * 5)   # p50 = 25
    c = compare(baseline, candidate, baseline_label="cold", candidate_label="warm")
    assert c.baseline == "cold" and c.candidate == "warm"
    assert c.speedup == pytest.approx(4.0)        # candidate 4x faster
    assert c.overhead_pct == pytest.approx(-75.0) # candidate 75% less time


def test_compare_overhead_positive_when_candidate_slower():
    base = summarize([100.0] * 3)
    cand = summarize([104.0] * 3)
    c = compare(base, cand, baseline_label="none", candidate_label="nono")
    assert c.overhead_pct == pytest.approx(4.0)
    assert c.speedup == pytest.approx(100.0 / 104.0)
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_stats.py -q`
Expected: FAIL (`Comparison` / `compare` undefined).

- [ ] **Step 3: Implement (append to stats.py)**

```python
# append to src/blastbox/bench/stats.py

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
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_stats.py -q
/.venv/bin/ruff check src/blastbox/bench/stats.py && /.venv/bin/mypy src/blastbox/bench/stats.py
git add src/blastbox/bench/stats.py tests/bench/test_stats.py
git commit -m "feat(bench): stats compare (speedup + overhead)"
```

---

## Task 4: `harness.py` — `measure`

**Files:**
- Create: `src/blastbox/bench/harness.py`
- Test: `tests/bench/test_harness.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_harness.py
from blastbox.bench.harness import measure


def test_measure_returns_one_sample_per_run_excluding_warmup():
    # A fake clock that advances 1.0 per reading: each call to op consumes two
    # readings (start, end) → each measured duration is 1.0.
    ticks = iter(range(0, 1000))
    clock = lambda: float(next(ticks))
    calls = []
    samples = measure(lambda: calls.append(1), runs=3, warmup=2, clock=clock)
    assert len(samples) == 3            # warmup excluded
    assert len(calls) == 5              # warmup + runs actually executed
    assert all(d == 1.0 for d in samples)


def test_measure_drops_a_raising_sample():
    ticks = iter(range(0, 1000))
    clock = lambda: float(next(ticks))
    state = {"i": 0}

    def op():
        state["i"] += 1
        if state["i"] == 2:            # second post-warmup call raises
            raise RuntimeError("boom")

    samples = measure(op, runs=3, warmup=0, clock=clock)
    assert len(samples) == 2           # the raising call produced no sample
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_harness.py -q`
Expected: FAIL (no `blastbox.bench.harness`).

- [ ] **Step 3: Implement**

```python
# src/blastbox/bench/harness.py
"""Sampling harness + Report accumulator for benchmarks."""
from __future__ import annotations

import logging
import time
from typing import Callable

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
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_harness.py -q
/.venv/bin/ruff check src/blastbox/bench/harness.py && /.venv/bin/mypy src/blastbox/bench/harness.py
git add src/blastbox/bench/harness.py tests/bench/test_harness.py
git commit -m "feat(bench): measure() sampler with injectable clock"
```

> Note on the raising-sample test: in `test_measure_drops_a_raising_sample`, the raising call still consumes its `start = clock()` reading but skips the `clock() - start` end reading. The fake clock simply advances; the assertion only checks the count of returned samples, so the exact tick bookkeeping does not matter.

---

## Task 5: `harness.py` — `Report` accumulator

**Files:**
- Modify: `src/blastbox/bench/harness.py`
- Test: `tests/bench/test_harness.py`

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/bench/test_harness.py
from blastbox.bench.harness import Report
from blastbox.bench.stats import Stats, Comparison


def test_report_accumulates_and_summarizes():
    r = Report(scenario="demo")
    r.add("none", [10.0, 10.0, 10.0])
    r.add("nono", [11.0, 11.0, 11.0])
    assert set(r.labels()) == {"none", "nono"}
    assert isinstance(r.summary("none"), Stats)
    assert r.summary("none").p50 == 10.0


def test_report_compare_returns_comparison():
    r = Report(scenario="demo")
    r.add("none", [10.0] * 3)
    r.add("nono", [11.0] * 3)
    c = r.compare("none", "nono")
    assert isinstance(c, Comparison)
    assert c.overhead_pct == 10.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_harness.py -q`
Expected: FAIL (`Report` undefined).

- [ ] **Step 3: Implement (append to harness.py)**

```python
# add to the imports at the top of src/blastbox/bench/harness.py
from dataclasses import dataclass, field

from blastbox.bench.stats import Comparison, Stats, compare, summarize


# append to src/blastbox/bench/harness.py

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
        from blastbox.bench.report import to_table

        return to_table(self, baseline=baseline)

    def to_json(self) -> dict:
        from blastbox.bench.report import to_json

        return to_json(self)
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_harness.py -q
/.venv/bin/ruff check src/blastbox/bench/harness.py && /.venv/bin/mypy src/blastbox/bench/harness.py
git add src/blastbox/bench/harness.py tests/bench/test_harness.py
git commit -m "feat(bench): Report accumulator (summaries + A/B)"
```

> `to_table`/`to_json` import `report.py` lazily to avoid a circular import (`report.py` reads `Report`). They are exercised in Task 6.

---

## Task 6: `report.py` — table + JSON

**Files:**
- Create: `src/blastbox/bench/report.py`
- Test: `tests/bench/test_report.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_report.py
from blastbox.bench.harness import Report
from blastbox.bench.report import to_json, to_table


def _report():
    r = Report(scenario="sandbox.overhead")
    r.add("none", [100.0] * 5)
    r.add("nono", [104.0] * 5)
    return r


def test_to_json_has_stable_schema():
    j = to_json(_report())
    assert j["scenario"] == "sandbox.overhead"
    labels = {row["label"] for row in j["results"]}
    assert labels == {"none", "nono"}
    none_row = next(r for r in j["results"] if r["label"] == "none")
    assert none_row["stats"]["p50"] == 100.0 and none_row["stats"]["n"] == 5


def test_to_table_renders_rows_and_overhead():
    txt = to_table(_report(), baseline="none")
    assert "sandbox.overhead" in txt
    assert "none" in txt and "nono" in txt
    assert "p50" in txt
    assert "+4.0%" in txt   # nono overhead vs the none baseline
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_report.py -q`
Expected: FAIL (no `blastbox.bench.report`).

- [ ] **Step 3: Implement**

```python
# src/blastbox/bench/report.py
"""Render a Report as a human table or stable JSON."""
from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blastbox.bench.harness import Report


def to_json(report: "Report") -> dict:
    """Stable JSON schema for CLI --json output + CI baselines."""
    results = [
        {"label": label, "stats": asdict(report.summary(label))}
        for label in report.labels()
    ]
    return {"scenario": report.scenario, "results": results}


def to_table(report: "Report", *, baseline: str | None = None) -> str:
    """Human-readable table; if ``baseline`` is given, append overhead-vs-baseline."""
    labels = report.labels()
    base_p50 = report.summary(baseline).p50 if baseline in labels else None
    lines = [f"=== {report.scenario} ==="]
    header = f"  {'label':<14} {'p50':>9} {'p90':>9} {'p99':>9} {'n':>4}"
    if base_p50 is not None:
        header += f" {'overhead':>9}"
    lines.append(header)
    for label in labels:
        s = report.summary(label)
        row = (
            f"  {label:<14} {s.p50*1000:>8.1f}m {s.p90*1000:>8.1f}m "
            f"{s.p99*1000:>8.1f}m {s.n:>4}"
        )
        if base_p50 is not None:
            ov = (s.p50 / base_p50 - 1.0) * 100.0
            row += f" {ov:>+8.1f}%"
        lines.append(row)
    return "\n".join(lines)
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_report.py tests/bench/test_harness.py -q
/.venv/bin/ruff check src/blastbox/bench/report.py && /.venv/bin/mypy src/blastbox/bench/report.py
git add src/blastbox/bench/report.py tests/bench/test_report.py
git commit -m "feat(bench): report table + stable JSON"
```

---

## Task 7: `scenarios.py` — registry + `BenchConfig` + `ScenarioResult`

**Files:**
- Create: `src/blastbox/bench/scenarios.py`
- Test: `tests/bench/test_scenarios.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_scenarios.py
import pytest
from blastbox.bench.scenarios import (
    BenchConfig, ScenarioResult, scenario, get_scenario, list_scenarios,
)
from blastbox.bench.harness import Report


def test_scenario_registers_and_is_listable():
    @scenario("demo.noop", requires=())
    def _demo(cfg: BenchConfig) -> ScenarioResult:
        r = Report(scenario="demo.noop")
        r.add("a", [1.0, 1.0, 1.0])
        return ScenarioResult(report=r, status="ok")

    info = {s.name: s for s in list_scenarios()}
    assert "demo.noop" in info
    fn = get_scenario("demo.noop")
    res = fn(BenchConfig(runs=3, warmup=0))
    assert res.status == "ok" and res.report.summary("a").p50 == 1.0


def test_get_unknown_scenario_raises():
    with pytest.raises(KeyError):
        get_scenario("does.not.exist")
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_scenarios.py -q`
Expected: FAIL (no `blastbox.bench.scenarios`).

- [ ] **Step 3: Implement (registry core only)**

```python
# src/blastbox/bench/scenarios.py
"""Scenario registry for blastbox benchmarks (runtime-agnostic)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from blastbox.bench.harness import Report


@dataclass(frozen=True)
class BenchConfig:
    runs: int = 12
    warmup: int = 3
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class ScenarioResult:
    report: Report
    status: str   # "ok" | "skipped" | "insufficient"
    note: str = ""


ScenarioFn = Callable[[BenchConfig], ScenarioResult]


@dataclass(frozen=True)
class ScenarioInfo:
    name: str
    requires: tuple[str, ...]
    fn: ScenarioFn


_REGISTRY: dict[str, ScenarioInfo] = {}


def scenario(name: str, *, requires: tuple[str, ...] = ()) -> Callable[[ScenarioFn], ScenarioFn]:
    """Register a scenario function under ``name`` with prerequisite tokens."""
    def _wrap(fn: ScenarioFn) -> ScenarioFn:
        _REGISTRY[name] = ScenarioInfo(name=name, requires=requires, fn=fn)
        return fn
    return _wrap


def get_scenario(name: str) -> ScenarioFn:
    return _REGISTRY[name].fn


def get_info(name: str) -> ScenarioInfo:
    return _REGISTRY[name]


def list_scenarios() -> list[ScenarioInfo]:
    return sorted(_REGISTRY.values(), key=lambda s: s.name)
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_scenarios.py -q
/.venv/bin/ruff check src/blastbox/bench/scenarios.py && /.venv/bin/mypy src/blastbox/bench/scenarios.py
git add src/blastbox/bench/scenarios.py tests/bench/test_scenarios.py
git commit -m "feat(bench): scenario registry + BenchConfig + ScenarioResult"
```

---

## Task 8: `scenarios.py` — `check_requirement` + skip helper

**Files:**
- Modify: `src/blastbox/bench/scenarios.py`
- Test: `tests/bench/test_scenarios.py`

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/bench/test_scenarios.py
from blastbox.bench.scenarios import check_requirement, run_scenario


def test_check_requirement_unknown_token_is_false():
    assert check_requirement("totally-bogus-token") is False


def test_run_scenario_skips_when_requirement_unmet():
    @scenario("demo.needsfc", requires=("totally-bogus-token",))
    def _s(cfg):  # pragma: no cover - never runs (skipped)
        raise AssertionError("must not execute when requirement unmet")

    res = run_scenario("demo.needsfc", BenchConfig())
    assert res.status == "skipped" and "totally-bogus-token" in res.note
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_scenarios.py -q`
Expected: FAIL (`check_requirement` / `run_scenario` undefined).

- [ ] **Step 3: Implement (append to scenarios.py)**

```python
# add to imports at the top of scenarios.py
import shutil
from pathlib import Path


def check_requirement(token: str) -> bool:
    """Probe a prerequisite token. Unknown tokens are False (fail-safe skip)."""
    if token == "soffice":
        return shutil.which("soffice") is not None
    if token == "nono":
        return shutil.which("nono") is not None or bool(
            __import__("os").environ.get("BLASTBOX_NONO_BIN")
        )
    if token == "bwrap":
        return shutil.which("bwrap") is not None
    if token == "fc-host":
        try:
            from blastbox.host.runtime.firecracker import FCConfig, firecracker_available
            return firecracker_available(FCConfig.from_env())
        except Exception:  # noqa: BLE001 — any failure means "not available"
            return False
    return False


def run_scenario(name: str, cfg: BenchConfig) -> ScenarioResult:
    """Run a registered scenario, skipping cleanly if any requirement is unmet."""
    info = _REGISTRY[name]
    missing = [t for t in info.requires if not check_requirement(t)]
    if missing:
        return ScenarioResult(
            report=Report(scenario=name),
            status="skipped",
            note=f"missing prerequisites: {', '.join(missing)}",
        )
    return info.fn(cfg)
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_scenarios.py -q
/.venv/bin/ruff check src/blastbox/bench/scenarios.py && /.venv/bin/mypy src/blastbox/bench/scenarios.py
git add src/blastbox/bench/scenarios.py tests/bench/test_scenarios.py
git commit -m "feat(bench): check_requirement + run_scenario (clean skip)"
```

---

## Task 9: `scenarios.py` — `sandbox.overhead` scenario

**Files:**
- Modify: `src/blastbox/bench/scenarios.py`
- Test: `tests/bench/test_scenarios.py`

This scenario wraps `select_sandbox` + a representative workload and compares
overhead across the installed backends. It `requires=("soffice",)`; on CI without
soffice it skips. We unit-test the *measurement plumbing* with an injected runner so
no real sandbox/soffice is needed.

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/bench/test_scenarios.py
from blastbox.bench.scenarios import _sandbox_overhead_impl


def test_sandbox_overhead_impl_compares_backends_with_fake_runner():
    # Fake "run one workload under backend X" → returns a fixed duration per backend.
    durations = {"none": 0.10, "bwrap": 0.104, "nono": 0.102}

    def fake_run(backend: str) -> float:
        return durations[backend]

    cfg = BenchConfig(runs=4, warmup=1)
    res = _sandbox_overhead_impl(cfg, backends=("none", "bwrap", "nono"), run_one=fake_run)
    assert res.status == "ok"
    assert set(res.report.labels()) == {"none", "bwrap", "nono"}
    # nono overhead vs none ≈ +2%
    c = res.report.compare("none", "nono")
    assert 1.0 < c.overhead_pct < 3.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_scenarios.py -q`
Expected: FAIL (`_sandbox_overhead_impl` undefined).

- [ ] **Step 3: Implement (append to scenarios.py)**

```python
# add to imports at the top of scenarios.py
from blastbox.bench.harness import measure


def _sandbox_overhead_impl(
    cfg: BenchConfig,
    *,
    backends: tuple[str, ...],
    run_one: Callable[[str], object],
) -> ScenarioResult:
    """Measure each backend's wall-time for one workload (injected ``run_one``)."""
    report = Report(scenario="sandbox.overhead")
    for backend in backends:
        samples = measure(
            lambda b=backend: run_one(b), runs=cfg.runs, warmup=cfg.warmup
        )
        if len(samples) < 3:
            return ScenarioResult(report=report, status="insufficient",
                                  note=f"{backend}: only {len(samples)} samples")
        report.add(backend, samples)
    return ScenarioResult(report=report, status="ok")


@scenario("sandbox.overhead", requires=("soffice",))
def _sandbox_overhead(cfg: BenchConfig) -> ScenarioResult:
    """Real scenario: wrap `soffice --convert-to pdf` in each available backend.

    The default workload + per-backend runner live in
    ``blastbox.bench._workloads`` (Task 11); here we resolve the installed backends
    and delegate to ``_sandbox_overhead_impl``."""
    from blastbox.bench._workloads import soffice_runner, available_sandbox_backends

    backends = available_sandbox_backends()
    return _sandbox_overhead_impl(cfg, backends=backends, run_one=soffice_runner(cfg))
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_scenarios.py -q
/.venv/bin/ruff check src/blastbox/bench/scenarios.py && /.venv/bin/mypy src/blastbox/bench/scenarios.py
git add src/blastbox/bench/scenarios.py tests/bench/test_scenarios.py
git commit -m "feat(bench): sandbox.overhead scenario (injected runner unit-tested)"
```

> The real `_sandbox_overhead` imports `_workloads` lazily, so the module imports
> fine before Task 11 lands; only an actual (non-skipped) run needs `_workloads`.

---

## Task 10: `scenarios.py` — `snapshot.*` scenarios

**Files:**
- Modify: `src/blastbox/bench/scenarios.py`
- Test: `tests/bench/test_scenarios.py`

These wrap `select_snapshot_runtime` + `SnapshotSlotRuntime`. They
`requires=("fc-host",)` and skip on non-FC hosts. We unit-test the plumbing with a
fake runtime so no real Firecracker is needed.

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/bench/test_scenarios.py
from blastbox.bench.scenarios import _snapshot_restore_latency_impl


class _FakeRuntime:
    """Minimal stand-in: spawn returns a slot, reap is a no-op."""
    def __init__(self):
        self.spawned = 0
    def spawn(self):
        self.spawned += 1
        return object()
    def reap(self, slot):
        pass


def test_snapshot_restore_latency_impl_times_spawns():
    rt = _FakeRuntime()
    cfg = BenchConfig(runs=5, warmup=1)
    res = _snapshot_restore_latency_impl(cfg, runtime=rt)
    assert res.status == "ok"
    assert rt.spawned == 6                       # warmup + runs
    assert res.report.summary("restore").n == 5  # warmup excluded
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_scenarios.py -q`
Expected: FAIL (`_snapshot_restore_latency_impl` undefined).

- [ ] **Step 3: Implement (append to scenarios.py)**

```python
# append to scenarios.py

def _snapshot_restore_latency_impl(cfg: BenchConfig, *, runtime: object) -> ScenarioResult:
    """Time runtime.spawn()→reap() (one restore) repeatedly."""
    report = Report(scenario="snapshot.restore-latency")

    def one() -> None:
        slot = runtime.spawn()      # type: ignore[attr-defined]
        runtime.reap(slot)          # type: ignore[attr-defined]

    samples = measure(one, runs=cfg.runs, warmup=cfg.warmup)
    if len(samples) < 3:
        return ScenarioResult(report=report, status="insufficient",
                              note=f"only {len(samples)} samples")
    report.add("restore", samples)
    return ScenarioResult(report=report, status="ok")


@scenario("snapshot.restore-latency", requires=("fc-host",))
def _snapshot_restore_latency(cfg: BenchConfig) -> ScenarioResult:
    """Real scenario: build the warm snapshot once, then time per-slot restores."""
    from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime

    rt = select_snapshot_runtime(require_available=True)
    if rt is None:
        return ScenarioResult(report=Report(scenario="snapshot.restore-latency"),
                              status="skipped", note="snapshot runtime unavailable")
    return _snapshot_restore_latency_impl(cfg, runtime=rt)
```

- [ ] **Step 4: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_scenarios.py -q
/.venv/bin/ruff check src/blastbox/bench/scenarios.py && /.venv/bin/mypy src/blastbox/bench/scenarios.py
git add src/blastbox/bench/scenarios.py tests/bench/test_scenarios.py
git commit -m "feat(bench): snapshot.restore-latency scenario (fake-runtime unit test)"
```

> The remaining snapshot scenarios (`cold-boot-ready`, `restore-convert`,
> `ram-vs-disk`, `settle-sweep`) follow this exact shape — an `_impl(cfg, *,
> runtime/launcher)` taking injected primitives (unit-tested with a fake) plus a thin
> `@scenario(..., requires=("fc-host",))` wrapper that builds the real one. Add them
> one per commit using the same five-step structure; each `_impl` returns
> `status="insufficient"` when `< 3` samples succeed.

---

## Task 11: `_workloads.py` + `convert.latency` scenario

**Files:**
- Create: `src/blastbox/bench/_workloads.py`
- Modify: `src/blastbox/bench/scenarios.py`
- Test: `tests/bench/test_workloads.py`

`_workloads.py` builds the real soffice runner used by `sandbox.overhead` +
`convert.latency`. It is only imported when a non-skipped run happens.

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_workloads.py
from blastbox.bench._workloads import available_sandbox_backends, soffice_argv


def test_soffice_argv_is_a_list_with_convert_to():
    argv = soffice_argv("/tmp/in.txt", "/tmp/out")
    assert isinstance(argv, list)
    assert "--convert-to" in argv and "pdf" in argv


def test_available_sandbox_backends_includes_none_first():
    backends = available_sandbox_backends()
    assert backends[0] == "none"   # the unsandboxed baseline is always present
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_workloads.py -q`
Expected: FAIL (no `_workloads`).

- [ ] **Step 3: Implement**

```python
# src/blastbox/bench/_workloads.py
"""Real workloads for the conversion/sandbox benchmark scenarios.

Imported lazily by the scenarios so the bench package imports with no soffice."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from blastbox.bench.scenarios import BenchConfig

_SOFFICE = "/usr/bin/soffice"


def soffice_argv(input_path: str, outdir: str) -> list[str]:
    return [_SOFFICE, "--headless", "--convert-to", "pdf", "--outdir", outdir, input_path]


def available_sandbox_backends() -> tuple[str, ...]:
    """``none`` (baseline) + whichever sandbox binaries are installed."""
    backends = ["none"]
    for name, present in (
        ("bwrap", shutil.which("bwrap")),
        ("nsjail", shutil.which("nsjail")),
        ("nono", shutil.which("nono")),
    ):
        if present:
            backends.append(name)
    return tuple(backends)


def soffice_runner(cfg: BenchConfig) -> Callable[[str], None]:
    """Return ``run_one(backend)`` that converts a fixture under that backend.

    Uses the blastbox sandbox protocol for real backends; ``none`` runs soffice
    directly. Each call uses a fresh per-run output dir."""
    tmp = Path(tempfile.mkdtemp(prefix="blastbox-bench-"))
    inp = tmp / "in.txt"
    inp.write_text("blastbox bench fixture\nsecond line\n")

    def run_one(backend: str) -> None:
        out = Path(tempfile.mkdtemp(prefix="bench-out-", dir=tmp))
        argv = soffice_argv(str(inp), str(out))
        if backend == "none":
            subprocess.run(argv, capture_output=True, timeout=cfg_timeout(cfg))
            return
        from blastbox.worker.sandbox.base import Mount, SandboxRequest
        from blastbox.worker.sandbox.detect import select_sandbox

        sb = select_sandbox(backend=backend)
        sb.run(SandboxRequest(
            argv=argv,
            ro_mounts=[Mount(source=inp, target=inp)],
            rw_mounts=[Mount(source=out, target=out)],
        ))

    return run_one


def cfg_timeout(cfg: BenchConfig) -> int:
    raw = cfg.params.get("timeout_s", "120")
    return int(raw)
```

- [ ] **Step 4: Add the `convert.latency` scenario (append to scenarios.py)**

```python
# append to scenarios.py
@scenario("convert.latency", requires=("soffice",))
def _convert_latency(cfg: BenchConfig) -> ScenarioResult:
    """Conversion wall-time, unsandboxed baseline only (first cut)."""
    from blastbox.bench._workloads import soffice_runner

    run = soffice_runner(cfg)
    report = Report(scenario="convert.latency")
    samples = measure(lambda: run("none"), runs=cfg.runs, warmup=cfg.warmup)
    if len(samples) < 3:
        return ScenarioResult(report=report, status="insufficient",
                              note=f"only {len(samples)} samples")
    report.add("convert", samples)
    return ScenarioResult(report=report, status="ok")
```

- [ ] **Step 5: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_workloads.py tests/bench/test_scenarios.py -q
/.venv/bin/ruff check src/blastbox/bench/_workloads.py src/blastbox/bench/scenarios.py
/.venv/bin/mypy src/blastbox/bench/_workloads.py src/blastbox/bench/scenarios.py
git add src/blastbox/bench/_workloads.py src/blastbox/bench/scenarios.py tests/bench/test_workloads.py
git commit -m "feat(bench): _workloads (soffice runner) + convert.latency scenario"
```

---

## Task 12: `__init__.py` exports + `blastbox bench` CLI

**Files:**
- Modify: `src/blastbox/bench/__init__.py`
- Modify: `src/blastbox/host/cli.py`
- Test: `tests/bench/test_cli_bench.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/bench/test_cli_bench.py
import json
from blastbox.host.cli import main
from blastbox.bench.scenarios import scenario, BenchConfig, ScenarioResult
from blastbox.bench.harness import Report


def _register_demo():
    @scenario("cli.demo", requires=())
    def _d(cfg: BenchConfig) -> ScenarioResult:
        r = Report(scenario="cli.demo")
        r.add("a", [0.01] * cfg.runs)
        return ScenarioResult(report=r, status="ok")


def test_bench_list_exits_zero(capsys):
    _register_demo()
    rc = main(["bench", "--list"])
    out = capsys.readouterr().out
    assert rc == 0 and "cli.demo" in out


def test_bench_run_writes_json(tmp_path, capsys):
    _register_demo()
    out = tmp_path / "r.json"
    rc = main(["bench", "cli.demo", "--runs", "5", "--warmup", "0", "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["scenario"] == "cli.demo"
    assert data["results"][0]["stats"]["n"] == 5


def test_bench_unknown_scenario_exits_nonzero():
    rc = main(["bench", "nope.nope"])
    assert rc != 0
```

- [ ] **Step 2: Run to verify it fails**

Run: `/.venv/bin/pytest tests/bench/test_cli_bench.py -q`
Expected: FAIL (no `bench` subcommand).

- [ ] **Step 3: Populate `__init__.py` exports**

```python
# src/blastbox/bench/__init__.py
"""blastbox.bench — performance benchmarking, stats & comparisons."""
from blastbox.bench.harness import Report, measure
from blastbox.bench.scenarios import (
    BenchConfig, ScenarioResult, get_scenario, list_scenarios, run_scenario, scenario,
)
from blastbox.bench.stats import Comparison, Stats, compare, summarize

__all__ = [
    "Report", "measure", "BenchConfig", "ScenarioResult", "get_scenario",
    "list_scenarios", "run_scenario", "scenario", "Comparison", "Stats",
    "compare", "summarize",
]
```

- [ ] **Step 4: Add `_bench_cmd` + the subparser to `cli.py`**

Add `import json` to the top of `src/blastbox/host/cli.py` if absent, then add the
command function (place it next to `_version_cmd`):

```python
def _bench_cmd(args: argparse.Namespace) -> int:
    # Import here so `blastbox` startup doesn't pull bench/runtime deps unless used.
    from blastbox.bench.scenarios import BenchConfig, list_scenarios, run_scenario

    if args.list:
        for info in list_scenarios():
            req = ",".join(info.requires) or "-"
            print(f"{info.name:28} requires={req}")
        return 0

    if args.scenario is None:
        print("error: a scenario name is required (or use --list)")
        return 2
    try:
        res = run_scenario(args.scenario, BenchConfig(runs=args.runs, warmup=args.warmup))
    except KeyError:
        print(f"error: unknown scenario {args.scenario!r} (try `blastbox bench --list`)")
        return 2

    print(res.report.to_table(baseline=res.report.labels()[0] if res.report.labels() else None))
    if res.status != "ok":
        print(f"[{res.status}] {res.note}")
    if args.json:
        import json
        with open(args.json, "w") as fh:
            json.dump(res.report.to_json(), fh, indent=2)
    return 0
```

Then register it inside `build_parser()`, mirroring the `version` block:

```python
    pb = sub.add_parser("bench", help="run a performance benchmark scenario")
    pb.add_argument("scenario", nargs="?", default=None, help="scenario name")
    pb.add_argument("--list", action="store_true", help="list scenarios + requirements")
    pb.add_argument("--runs", type=int, default=12)
    pb.add_argument("--warmup", type=int, default=3)
    pb.add_argument("--json", default=None, help="write the JSON report to this path")
    pb.add_argument("--compare", default=None, help="(reserved) baseline JSON to diff")
    pb.set_defaults(func=_bench_cmd)
```

- [ ] **Step 5: Run + lint + commit**

```bash
/.venv/bin/pytest tests/bench/test_cli_bench.py -q
/.venv/bin/ruff check src/blastbox/bench/__init__.py src/blastbox/host/cli.py
/.venv/bin/mypy src/blastbox/bench src/blastbox/host/cli.py
git add src/blastbox/bench/__init__.py src/blastbox/host/cli.py tests/bench/test_cli_bench.py
git commit -m "feat(bench): blastbox bench CLI subcommand (--list/--runs/--json)"
```

---

## Task 13: `perf` ratio gates

**Files:**
- Create: `tests/perf/test_perf_gates.py`

The gate asserts host-stable *ratios*, seeded from measured numbers with margin. It
uses fake sample-sets so the mechanism is verified everywhere; the comment documents
the real (FC-host) values it would assert against.

- [ ] **Step 1: Write the gate test**

```python
# tests/perf/test_perf_gates.py
"""perf-marked ratio gates. The mechanism is tested with synthetic samples so CI
runs anywhere; on an FC host these gates would consume real scenario reports.

Seeded invariants (measured on toolz2, with margin):
- warm restore p50 is >= 5x faster than cold boot p50 (measured ~13.5x).
- nono sandbox overhead is <= 15% vs none (measured +1-4%)."""
import pytest

from blastbox.bench.harness import Report

pytestmark = pytest.mark.perf

RESTORE_MIN_SPEEDUP = 5.0
NONO_MAX_OVERHEAD_PCT = 15.0


def test_warm_restore_beats_cold_boot_by_ratio():
    r = Report(scenario="snapshot.acquire")
    r.add("cold-boot", [7.76] * 5)     # seconds (measured p50)
    r.add("restore", [0.575] * 5)
    c = r.compare("cold-boot", "restore")
    assert c.speedup >= RESTORE_MIN_SPEEDUP


def test_nono_overhead_within_budget():
    r = Report(scenario="sandbox.overhead")
    r.add("none", [0.626] * 5)
    r.add("nono", [0.634] * 5)
    c = r.compare("none", "nono")
    assert c.overhead_pct <= NONO_MAX_OVERHEAD_PCT
```

- [ ] **Step 2: Run (perf marker)**

Run: `/.venv/bin/pytest tests/perf/test_perf_gates.py -q -m perf`
Expected: PASS (2 tests).

- [ ] **Step 3: Verify the marker excludes them by default if desired**

Run: `/.venv/bin/pytest tests/perf -q -m "not perf"`
Expected: 2 deselected.

- [ ] **Step 4: Commit**

```bash
git add tests/perf/test_perf_gates.py
git commit -m "test(bench): perf ratio gates (restore speedup, nono overhead)"
```

---

## Task 14: Full-suite green + spec status

**Files:**
- Modify: `docs/specs/2026-06-04-blastbox-bench-design.md` (status line)

- [ ] **Step 1: Full suite + lint + types**

```bash
/.venv/bin/pytest tests -q
/.venv/bin/ruff check src tests
/.venv/bin/mypy src
```
Expected: all pass (perf tests run; FC/soffice scenarios skip when absent).

- [ ] **Step 2: Smoke the CLI**

Run: `/.venv/bin/python -m blastbox.host.cli bench --list` (or the installed `blastbox bench --list`)
Expected: lists `sandbox.overhead`, `convert.latency`, `snapshot.restore-latency`, etc. with their `requires`.

- [ ] **Step 3: Flip the spec status to implemented + commit**

Change the spec's `Status:` line to `**implemented**` and commit:

```bash
git add docs/specs/2026-06-04-blastbox-bench-design.md
git commit -m "docs(spec): blastbox.bench implemented"
```

---

## Self-Review notes (for the implementer)

- **Spec coverage:** stats (T2-3), harness (T4-5), report (T6), registry + requires (T7-8), sandbox.overhead (T9), snapshot.* (T10 + the noted follow-ons), convert.latency + workloads (T11), CLI (T12), perf gate + marker (T1, T13). The `--compare baseline.json` flag is reserved/parsed in T12 but its diff rendering is intentionally deferred (YAGNI) — the JSON seam exists; wire the diff only if needed.
- **Type consistency:** `Stats`/`Comparison` (T2-3) are used unchanged by `Report` (T5), `report.py` (T6), scenarios (T9-11), and the gate (T13). `BenchConfig`/`ScenarioResult`/`scenario`/`run_scenario` (T7-8) are used identically by scenarios + CLI.
- **No real FC/nono/soffice in unit tests:** every `_impl` takes injected primitives; the real `@scenario` wrappers are `requires`-gated and skip on CI.
