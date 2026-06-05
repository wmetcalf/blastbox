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
