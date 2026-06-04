from blastbox.bench.harness import measure


def test_measure_returns_one_sample_per_run_excluding_warmup():
    # A fake clock that advances 1.0 per reading: each call to op consumes two
    # readings (start, end) → each measured duration is 1.0.
    ticks = iter(range(0, 1000))

    def clock() -> float:
        return float(next(ticks))

    calls: list[int] = []
    samples = measure(lambda: calls.append(1), runs=3, warmup=2, clock=clock)
    assert len(samples) == 3  # warmup excluded
    assert len(calls) == 5  # warmup + runs actually executed
    assert all(d == 1.0 for d in samples)


def test_measure_drops_a_raising_sample():
    ticks = iter(range(0, 1000))

    def clock() -> float:
        return float(next(ticks))

    state = {"i": 0}

    def op() -> None:
        state["i"] += 1
        if state["i"] == 2:  # second post-warmup call raises
            raise RuntimeError("boom")

    samples = measure(op, runs=3, warmup=0, clock=clock)
    assert len(samples) == 2  # the raising call produced no sample
