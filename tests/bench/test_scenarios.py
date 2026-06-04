# tests/bench/test_scenarios.py
import pytest
from blastbox.bench.scenarios import (
    BenchConfig, ScenarioResult, check_requirement, get_scenario, list_scenarios,
    run_scenario, scenario,
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


# --- Task 8 ---
def test_check_requirement_unknown_token_is_false():
    assert check_requirement("totally-bogus-token") is False


def test_run_scenario_skips_when_requirement_unmet():
    @scenario("demo.needsfc", requires=("totally-bogus-token",))
    def _s(cfg):  # pragma: no cover - never runs (skipped)
        raise AssertionError("must not execute when requirement unmet")

    res = run_scenario("demo.needsfc", BenchConfig())
    assert res.status == "skipped" and "totally-bogus-token" in res.note
