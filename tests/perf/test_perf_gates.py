"""perf-marked ratio gates. The mechanism is tested with synthetic samples so CI
runs anywhere; on an FC host these gates would consume real scenario reports.

Seeded invariants (measured on toolz2, with margin):
- warm restore p50 is >= 5x faster than cold boot p50 (measured ~13.5x).
- nono sandbox overhead is <= 15% vs none (measured +1-4%)."""
import pytest

from blastbox.bench.harness import Report

pytestmark = pytest.mark.perf

RESTORE_MIN_SPEEDUP = 5.0
NONO_MAX_OVERHEAD_PCT = 15.0


def test_warm_restore_beats_cold_boot_by_ratio():
    r = Report(scenario="snapshot.acquire")
    r.add("cold-boot", [7.76] * 5)     # seconds (measured p50)
    r.add("restore", [0.575] * 5)
    c = r.compare("cold-boot", "restore")
    assert c.speedup >= RESTORE_MIN_SPEEDUP


def test_nono_overhead_within_budget():
    r = Report(scenario="sandbox.overhead")
    r.add("none", [0.626] * 5)
    r.add("nono", [0.634] * 5)
    c = r.compare("none", "nono")
    assert c.overhead_pct <= NONO_MAX_OVERHEAD_PCT
