"""Host-side per-phase timing for a warm dispatch.

Why this exists: throughput on a disposable-slot tier is `slots / slot_cycle_time`, NOT
`1 / engine_time`. Measured on toolz2, 24 slots sustain ~2.6 jobs/s -- a ~9s slot cycle --
while a single job against an IDLE tier finishes in well under a second. Nearly the whole
cycle is therefore something OTHER than extraction, and until now nothing could say which
part: the guest's log lines carry no correlation id, so pairing the k-th "job received" with
the k-th "returned" under concurrency compares DIFFERENT JOBS (that method reported 0.67s and
5.48s for the same tier minutes apart, which is how you can tell it measures nothing).

Timing on the HOST sidesteps the whole problem. `_dispatch_claimed_job` owns one job start to
finish on one thread, so the phases are already sequential and already ours -- no correlation
id needed, and no guest change (hence no rootfs rebuild) to deploy it.

These tests pin the three properties that make the numbers worth reading:
  * every phase of a clean run is present, and the line is per-job;
  * a phase measures ITS OWN work (a mark on the wrong side of a call silently attributes
    the guest's time to whatever follows it);
  * an early exit is self-localizing -- the last phase present is where dispatch left.
"""
from __future__ import annotations

import logging
import re
import time


from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

from tests.host.test_dispatch_warm import (
    _INPUT_SHA,
    FakeWarmPool,
    _FakeVsockRuntime,
    _make_dispatcher_with_pool,
    _make_job,
    _make_slot,
    _setup_job_dirs,
)


def _phase_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "warm_phases" in r.getMessage()]


def _pairs(line: str) -> list[tuple[str, float]]:
    """The phase=seconds pairs IN ORDER, duplicates preserved. Non-numeric fields are skipped.

    The value must run to whitespace or end-of-line. `\b` only required a word boundary, which a
    hyphen satisfies -- so `job_id=24388167-a7e2-...` captured `24388167` and job_id arrived as a
    2.4e7-second "phase" that dominated `max(others)`. It looked like it skipped non-numeric
    fields only because a uuid4 rarely has eight leading digits: measured 2.33%, about one run in
    43, which is exactly the rate at which this suite failed for no attributable reason.
    """
    out: list[tuple[str, float]] = []
    for k, v in re.findall(r"(\w+)=([\d.]+)(?=\s|$)", line):
        try:
            out.append((k, float(v)))
        except ValueError:
            pass
    return out


def _parse(line: str) -> dict[str, float]:
    """As a dict -- and reject duplicate phase names rather than letting the last one win.

    An earlier version of this helper silently collapsed duplicates, which made a mark left on
    BOTH sides of a call (the exact defect the next test hunts) read as perfectly correct.
    """
    pairs = _pairs(line)
    names = [k for k, _ in pairs]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"phase(s) {dupes} appear more than once, so the line double-counts: {line}"
    return dict(pairs)


def _run_warm_job(tmp_path, *, runtime=None):
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job)
    slot = _make_slot(tmp_path)
    runtime = runtime if runtime is not None else _FakeVsockRuntime()
    pool = FakeWarmPool(slot, runtime=runtime)
    d = _make_dispatcher_with_pool(
        store, job_root=tmp_path / "jobs", pool=pool, worker_timeout_s=10
    )
    assert d.dispatch_once() is True
    return store, job, pool


def test_a_clean_warm_run_emits_one_phase_line_covering_every_phase(tmp_path, caplog):
    """MUTATION: delete any single `phases.mark(...)` call in _dispatch_warm and the
    corresponding key disappears from the line, failing this test by name."""
    caplog.set_level(logging.INFO, logger="blastbox.host.dispatch")
    store, job, _pool = _run_warm_job(tmp_path)
    assert store.get(job.job_id).status == JobStatus.DONE

    lines = _phase_lines(caplog)
    assert len(lines) == 1, f"expected exactly one warm_phases line per job, got {lines}"
    line = lines[0]
    assert f"job_id={job.job_id}" in line, f"the line must be attributable to a job: {line}"
    assert "outcome=done" in line

    phases = _parse(line)
    # Every step of the slot cycle a HOST can see. `guest` is the only one that is extraction;
    # if the others sum to more than it does, tuning the engine is the wrong lever -- which is
    # the entire question this instrumentation exists to answer.
    for name in ("slot_claim", "fetch", "stage", "go", "guest", "rdump",
                 "validate", "seal", "commit", "release", "purge"):
        assert name in phases, f"phase {name!r} missing from: {line}"
    assert phases["total"] > 0.0


def test_the_guest_phase_measures_the_wait_and_not_its_neighbours(tmp_path, caplog):
    """A mark on the wrong side of `wait_for_done` still produces a plausible-looking line --
    it just credits the guest's time to the next phase. Force a slow guest and check the
    seconds land where they were spent.

    MUTATION: move `phases.mark("guest")` above the wait_for_done call -> guest reads ~0 and
    `rdump` absorbs the 0.30s, failing both assertions.
    """
    caplog.set_level(logging.INFO, logger="blastbox.host.dispatch")

    slow = _FakeVsockRuntime()
    _orig = slow.host_warm_control

    def _slow_control(slot):
        ctl = _orig(slot)
        real_wait = ctl.wait_for_done

        def _wait(*, timeout_s):
            time.sleep(0.30)
            return real_wait(timeout_s=timeout_s)

        ctl.wait_for_done = _wait
        return ctl

    slow.host_warm_control = _slow_control  # type: ignore[assignment]

    store, job, _pool = _run_warm_job(tmp_path, runtime=slow)
    assert store.get(job.job_id).status == JobStatus.DONE

    phases = _parse(_phase_lines(caplog)[0])
    assert phases["guest"] >= 0.25, (
        f"the 0.30s spent inside wait_for_done must be charged to `guest`, got {phases}"
    )
    others = {k: v for k, v in phases.items() if k not in ("guest", "total")}
    slowest = max(others, key=others.get)
    assert others[slowest] < 0.25, (
        f"no phase other than `guest` did 0.30s of work, but {slowest}={others[slowest]:.3f}s "
        f"— a mark is on the wrong side of a call: {phases}"
    )


def test_an_early_exit_localizes_itself_to_the_phase_it_died_in(tmp_path, caplog):
    """The last phase present IS the diagnostic. A run that dies in rdump must show `guest`
    (it got that far) and must NOT show `validate`/`commit` (it never did).

    MUTATION: emit the full phase list unconditionally (e.g. pre-seed every name at 0.0) and
    the line stops localizing anything -- this test fails on the `validate` assertion.
    """
    caplog.set_level(logging.INFO, logger="blastbox.host.dispatch")

    runtime = _FakeVsockRuntime()

    def _boom(_slot):
        raise RuntimeError("rdump exploded")

    runtime.materialize_warm_output = _boom  # type: ignore[assignment]

    store, job, _pool = _run_warm_job(tmp_path, runtime=runtime)
    assert store.get(job.job_id).status == JobStatus.FAILED

    line = _phase_lines(caplog)[0]
    phases = _parse(line)
    assert "outcome=failed" in line, line
    assert "guest" in phases, f"the dispatch DID reach the guest: {line}"
    assert "validate" not in phases, f"it never validated anything: {line}"
    assert "commit" not in phases, f"it never committed: {line}"
    # ...but the slot still came back, and that cost is still counted.
    assert "release" in phases, f"the release always runs and is always billed: {line}"


def test_timing_never_breaks_a_dispatch(tmp_path, caplog):
    """Instrumentation is not allowed to fail a job. Break the logger itself and the job must
    still reach DONE.

    MUTATION: remove the try/except around the emit body -> the raising handler propagates out
    of the outer `finally` and the dispatch dies after the work was already done.
    """
    caplog.set_level(logging.INFO, logger="blastbox.host.dispatch")

    class _Exploding(logging.Handler):
        def emit(self, record):
            if "warm_phases" in record.getMessage():
                raise RuntimeError("logging backend is down")

    log = logging.getLogger("blastbox.host.dispatch")
    handler = _Exploding()
    log.addHandler(handler)
    try:
        store, job, _pool = _run_warm_job(tmp_path)
    finally:
        log.removeHandler(handler)

    assert store.get(job.job_id).status == JobStatus.DONE


def test_a_job_id_of_all_digits_is_not_read_as_a_phase():
    """Regression: this suite failed ~1 run in 43 with `job_id` as the slowest "phase".

    uuid4 gives eight leading digits 2.33% of the time; a value pattern ending in a word
    boundary then captured the first
    segment. Any test that maxes over the parsed phases inherited the bug, and the failure named
    a phase that does not exist, so it read as a real timing regression rather than a parse bug.
    """
    line = ("warm_phases job_id=24388167-a7e2-4f1a-8074-d1b913fbd57c outcome=done "
            "total=0.304 slot_claim=0.000 guest=0.300 rdump=0.000 purge=0.001")
    phases = _parse(line)
    assert "job_id" not in phases, phases
    assert phases["guest"] == 0.300
    assert phases["total"] == 0.304
    others = {k: v for k, v in phases.items() if k not in ("guest", "total")}
    assert max(others, key=others.get) != "job_id"
