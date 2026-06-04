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
    assert "+4.0%" in txt  # nono overhead vs the none baseline
