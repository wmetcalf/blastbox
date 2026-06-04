"""Scenario registry for blastbox benchmarks (runtime-agnostic)."""
from __future__ import annotations

import os
import shutil
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
