"""Scenario registry for blastbox benchmarks (runtime-agnostic)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

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
