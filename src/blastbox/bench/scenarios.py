"""Scenario registry for blastbox benchmarks (runtime-agnostic)."""
from __future__ import annotations

import logging
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from blastbox.bench.harness import Report, measure

_log = logging.getLogger("blastbox.bench")


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


def scenario(
    name: str, *, requires: tuple[str, ...] = ()
) -> Callable[[ScenarioFn], ScenarioFn]:
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


def check_requirement(token: str) -> bool:
    """Probe a prerequisite token. Unknown tokens are False (fail-safe skip)."""
    if token == "soffice":
        return shutil.which("soffice") is not None
    if token == "nono":
        return shutil.which("nono") is not None or bool(
            os.environ.get("BLASTBOX_NONO_BIN")
        )
    if token == "bwrap":
        return shutil.which("bwrap") is not None
    if token == "fc-host":
        try:
            from blastbox.host.runtime.firecracker import (
                FCConfig,
                firecracker_available,
            )
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


def _measure_runner(
    run_one: Callable[[str], object], backend: str, cfg: BenchConfig
) -> list[float]:
    """Sample one backend: if ``run_one`` returns a number, treat it as the
    duration (deterministic for injected fakes); otherwise time wall-clock."""
    samples: list[float] = []
    for i in range(cfg.warmup + cfg.runs):
        start = time.monotonic()
        try:
            result = run_one(backend)
        except Exception as exc:  # noqa: BLE001 — one bad sample must not abort the run
            _log.debug("sandbox.overhead %s raised on iter %d: %s", backend, i, exc)
            continue
        elapsed = (
            float(result)
            if isinstance(result, (int, float)) and not isinstance(result, bool)
            else time.monotonic() - start
        )
        if i >= cfg.warmup:
            samples.append(elapsed)
    return samples


def _sandbox_overhead_impl(
    cfg: BenchConfig,
    *,
    backends: tuple[str, ...],
    run_one: Callable[[str], object],
) -> ScenarioResult:
    """Measure each backend's wall-time for one workload (injected ``run_one``)."""
    report = Report(scenario="sandbox.overhead")
    for backend in backends:
        samples = _measure_runner(run_one, backend, cfg)
        if len(samples) < 3:
            return ScenarioResult(
                report=report,
                status="insufficient",
                note=f"{backend}: only {len(samples)} samples",
            )
        report.add(backend, samples)
    return ScenarioResult(report=report, status="ok")


@scenario("sandbox.overhead", requires=("soffice",))
def _sandbox_overhead(cfg: BenchConfig) -> ScenarioResult:
    """Real scenario: wrap `soffice --convert-to pdf` in each available backend.

    The default workload + per-backend runner live in
    ``blastbox.bench._workloads`` (Task 11); here we resolve the installed backends
    and delegate to ``_sandbox_overhead_impl``."""
    from blastbox.bench._workloads import (  # type: ignore[import-not-found]
        available_sandbox_backends,
        soffice_runner,
    )

    backends = available_sandbox_backends()
    with soffice_runner(cfg) as run:
        return _sandbox_overhead_impl(cfg, backends=backends, run_one=run)


def _snapshot_restore_latency_impl(
    cfg: BenchConfig, *, runtime: object
) -> ScenarioResult:
    """Time runtime.spawn()→reap() (one restore) repeatedly."""
    report = Report(scenario="snapshot.restore-latency")

    def one() -> None:
        slot = runtime.spawn()      # type: ignore[attr-defined]
        runtime.reap(slot)          # type: ignore[attr-defined]

    samples = measure(one, runs=cfg.runs, warmup=cfg.warmup)
    if len(samples) < 3:
        return ScenarioResult(
            report=report,
            status="insufficient",
            note=f"only {len(samples)} samples",
        )
    report.add("restore", samples)
    return ScenarioResult(report=report, status="ok")


@scenario("snapshot.restore-latency", requires=("fc-host",))
def _snapshot_restore_latency(cfg: BenchConfig) -> ScenarioResult:
    """Real scenario: build the warm snapshot once, then time per-slot restores."""
    from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime

    rt = select_snapshot_runtime(require_available=True)
    if rt is None:
        return ScenarioResult(
            report=Report(scenario="snapshot.restore-latency"),
            status="skipped",
            note="snapshot runtime unavailable",
        )
    return _snapshot_restore_latency_impl(cfg, runtime=rt)


@scenario("convert.latency", requires=("soffice",))
def _convert_latency(cfg: BenchConfig) -> ScenarioResult:
    """Conversion wall-time, unsandboxed baseline only (first cut)."""
    from blastbox.bench._workloads import soffice_runner

    report = Report(scenario="convert.latency")
    with soffice_runner(cfg) as run:
        samples = measure(lambda: run("none"), runs=cfg.runs, warmup=cfg.warmup)
    if len(samples) < 3:
        return ScenarioResult(
            report=report,
            status="insufficient",
            note=f"only {len(samples)} samples",
        )
    report.add("convert", samples)
    return ScenarioResult(report=report, status="ok")
