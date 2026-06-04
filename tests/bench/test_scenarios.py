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
