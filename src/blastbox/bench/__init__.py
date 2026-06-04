"""blastbox.bench — performance benchmarking, stats & comparisons."""
from blastbox.bench.harness import Report, measure
from blastbox.bench.scenarios import (
    BenchConfig,
    ScenarioResult,
    get_scenario,
    list_scenarios,
    run_scenario,
    scenario,
)
from blastbox.bench.stats import Comparison, Stats, compare, summarize

__all__ = [
    "Report",
    "measure",
    "BenchConfig",
    "ScenarioResult",
    "get_scenario",
    "list_scenarios",
    "run_scenario",
    "scenario",
    "Comparison",
    "Stats",
    "compare",
    "summarize",
]
