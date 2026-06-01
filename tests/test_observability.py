"""Tests for blastbox.observability.

Checks configure_logging emits to stderr (JSON by default), and that
metrics increment correctly and render to prometheus text format.
"""
from __future__ import annotations

import json


class TestConfigureLogging:
    def test_json_format_outputs_to_stderr(self, capsys):
        from blastbox.observability.logging import configure_logging, get_logger

        configure_logging(format_="json", level="DEBUG")
        log = get_logger("test.observability")
        log.info("test_event", key="value")

        captured = capsys.readouterr()
        # Must be on stderr, not stdout
        assert captured.out == "" or "test_event" not in captured.out
        stderr = captured.err
        # Should contain valid JSON line with our event
        found = False
        for line in stderr.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event") == "test_event" or "test_event" in str(obj):
                found = True
                break
        assert found, f"JSON log event 'test_event' not found in stderr: {stderr!r}"

    def test_text_format_outputs_to_stderr(self, capsys):
        from blastbox.observability.logging import configure_logging, get_logger

        configure_logging(format_="text", level="DEBUG")
        log = get_logger("test.observability.text")
        log.info("text_event", key="val")

        captured = capsys.readouterr()
        assert "text_event" in captured.err


class TestMetrics:
    def test_jobs_submitted_counter_increments(self):
        from blastbox.observability.metrics import (
            JOBS_SUBMITTED_TOTAL,
            record_job_submitted,
        )

        before = JOBS_SUBMITTED_TOTAL.labels(engine="test-engine")._value.get()
        record_job_submitted("test-engine", 1024)
        after = JOBS_SUBMITTED_TOTAL.labels(engine="test-engine")._value.get()
        assert after == before + 1.0

    def test_rejections_counter_increments(self):
        from blastbox.observability.metrics import REJECTIONS_TOTAL, record_rejection

        before = REJECTIONS_TOTAL.labels(reason="test_reason")._value.get()
        record_rejection("test_reason")
        after = REJECTIONS_TOTAL.labels(reason="test_reason")._value.get()
        assert after == before + 1.0

    def test_generate_latest_renders_prometheus(self):
        from blastbox.observability.metrics import generate_latest, record_job_submitted

        record_job_submitted("render-test-engine", 512)
        output = generate_latest()
        assert isinstance(output, bytes)
        assert b"blastbox_jobs_submitted_total" in output

    def test_input_bytes_histogram_observed(self):
        from blastbox.observability.metrics import INPUT_BYTES, record_job_submitted

        before_count = INPUT_BYTES._sum.get()
        record_job_submitted("hist-engine", 8192)
        after_count = INPUT_BYTES._sum.get()
        assert after_count >= before_count + 8192

    def test_jobs_in_flight_gauge(self):
        from blastbox.observability.metrics import JOBS_IN_FLIGHT

        before = JOBS_IN_FLIGHT._value.get()
        JOBS_IN_FLIGHT.inc()
        assert JOBS_IN_FLIGHT._value.get() == before + 1
        JOBS_IN_FLIGHT.dec()
        assert JOBS_IN_FLIGHT._value.get() == before


class TestPoolMetrics:
    def test_slot_spawn_reap_counters(self):
        from blastbox.observability import metrics as m

        bs = m.POOL_SPAWNS_TOTAL._value.get()
        br = m.POOL_REAPS_TOTAL._value.get()
        m.record_slot_spawned()
        m.record_slot_reaped()
        assert m.POOL_SPAWNS_TOTAL._value.get() == bs + 1
        assert m.POOL_REAPS_TOTAL._value.get() == br + 1

    def test_pool_state_gauges(self):
        from blastbox.observability import metrics as m

        m.record_pool_state(
            spawning=1, warming=2, idle=3, assigned=1, draining=0,
            warm_target=6, burst_active=True,
        )
        assert m.POOL_SLOTS.labels(state="idle")._value.get() == 3
        assert m.POOL_SLOTS.labels(state="warming")._value.get() == 2
        assert m.POOL_SLOTS.labels(state="assigned")._value.get() == 1
        assert m.POOL_WARM_TARGET._value.get() == 6
        assert m.POOL_BURST_ACTIVE._value.get() == 1
        m.record_pool_state(
            spawning=0, warming=0, idle=0, assigned=0, draining=0,
            warm_target=2, burst_active=False,
        )
        assert m.POOL_BURST_ACTIVE._value.get() == 0


class TestDispatchMetrics:
    def test_warm_claim_hit_miss(self):
        from blastbox.observability import metrics as m

        bh = m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get()
        bm = m.WARM_CLAIMS_TOTAL.labels(result="miss")._value.get()
        m.record_warm_claim(hit=True)
        m.record_warm_claim(hit=False)
        assert m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get() == bh + 1
        assert m.WARM_CLAIMS_TOTAL.labels(result="miss")._value.get() == bm + 1

    def test_job_dispatched_by_path_outcome(self):
        from blastbox.observability import metrics as m

        b = m.JOBS_DISPATCHED_TOTAL.labels(path="warm", outcome="done")._value.get()
        m.record_job_dispatched(path="warm", outcome="done")
        assert m.JOBS_DISPATCHED_TOTAL.labels(path="warm", outcome="done")._value.get() == b + 1

    def test_job_duration_histogram(self):
        from blastbox.observability import metrics as m

        before = m.JOB_DURATION_SECONDS.labels(path="cold")._sum.get()
        m.observe_job_duration(path="cold", seconds=1.5)
        assert m.JOB_DURATION_SECONDS.labels(path="cold")._sum.get() == before + 1.5


class TestPoolEmitsMetricsOnTick:
    def test_tick_emits_spawn_count_and_state(self):
        """A WarmPool.tick() spawns to deficit and publishes its state — the
        spawn counter increments and the idle/warming gauges reflect reality."""
        from pathlib import Path

        from blastbox.host.pool import Slot, SlotState, WarmPool
        from blastbox.observability import metrics as m

        class _FakeRuntime:
            def __init__(self):
                self.n = 0

            def spawn(self) -> Slot:
                self.n += 1
                return Slot(
                    slot_id=f"s{self.n}",
                    control_dir=Path("/tmp"),
                    input_dir=Path("/tmp"),
                    output_dir=Path("/tmp"),
                    state=SlotState.WARMING,
                )

            def is_ready(self, slot):
                return True

            def is_alive(self, slot):
                return True

            def reap(self, slot):
                pass

        pool = WarmPool(runtime=_FakeRuntime(), warm_size=2, spawn_rate_limit=1000.0)
        before_spawns = m.POOL_SPAWNS_TOTAL._value.get()
        pool.tick()  # spawn 2 WARMING
        pool.tick()  # promote WARMING -> IDLE (is_ready True) + re-sample state
        assert m.POOL_SPAWNS_TOTAL._value.get() == before_spawns + 2
        assert m.POOL_SLOTS.labels(state="idle")._value.get() == 2
        assert pool.idle_count == 2
