# tests/bench/test_scenarios.py
import pytest
from blastbox.bench.scenarios import (
    BenchConfig, ScenarioResult, check_requirement, get_scenario, list_scenarios,
    run_scenario, scenario, _sandbox_overhead_impl, _snapshot_restore_latency_impl,
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


# --- Task 9 ---
def test_sandbox_overhead_impl_compares_backends_with_fake_runner():
    # Fake "run one workload under backend X" → returns a fixed duration per backend.
    durations = {"none": 0.10, "bwrap": 0.104, "nono": 0.102}

    def fake_run(backend: str) -> float:
        return durations[backend]

    cfg = BenchConfig(runs=4, warmup=1)
    res = _sandbox_overhead_impl(
        cfg, backends=("none", "bwrap", "nono"), run_one=fake_run
    )
    assert res.status == "ok"
    assert set(res.report.labels()) == {"none", "bwrap", "nono"}
    # nono overhead vs none ≈ +2%
    c = res.report.compare("none", "nono")
    assert 1.0 < c.overhead_pct < 3.0


# --- Task 10 ---
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
