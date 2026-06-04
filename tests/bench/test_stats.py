import pytest

from blastbox.bench.stats import _percentile, compare, summarize


def test_percentile_linear_interpolation():
    xs = [10.0, 20.0, 30.0, 40.0]  # sorted
    assert _percentile(xs, 50) == 25.0  # between 20 and 30
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


def test_compare_speedup_and_overhead():
    baseline = summarize([100.0] * 5)  # p50 = 100
    candidate = summarize([25.0] * 5)  # p50 = 25
    c = compare(baseline, candidate, baseline_label="cold", candidate_label="warm")
    assert c.baseline == "cold" and c.candidate == "warm"
    assert c.speedup == pytest.approx(4.0)  # candidate 4x faster
    assert c.overhead_pct == pytest.approx(-75.0)  # candidate 75% less time


def test_compare_overhead_positive_when_candidate_slower():
    base = summarize([100.0] * 3)
    cand = summarize([104.0] * 3)
    c = compare(base, cand, baseline_label="none", candidate_label="nono")
    assert c.overhead_pct == pytest.approx(4.0)
    assert c.speedup == pytest.approx(100.0 / 104.0)
