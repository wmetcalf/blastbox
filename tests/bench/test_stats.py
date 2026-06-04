import pytest

from blastbox.bench.stats import _percentile, summarize


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
