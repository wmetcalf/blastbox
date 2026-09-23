"""A warm tier must not rot while idle.

Measured on toolz2 2026-09-23: a Firecracker base checkpointed minutes earlier served 12/12,
the same engine's base from five days before hung every job at the 300s worker timeout, and two
slots restored five days earlier and never claimed hung the first job sent to them. Every other
repair path in the pool is reactive -- it needs failures, each costing the full timeout -- and an
idle tier produces none until a real job pays. These tests pin the proactive path.
"""

from __future__ import annotations

import itertools
import math
import time

import pytest

from blastbox.host.runtime.env_knobs import max_age_env
from blastbox.host.runtime.fc_snapshot import (
    DEFAULT_SNAPSHOT_MAX_AGE_S,
    SnapshotManager,
    idle_slot_usable,
)
from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

from .test_fc_snapshot import FakeBackend, _wait_until


class DistinctBackend(FakeBackend):
    """Each base boot yields a NEW artifact, so a rebuild is observable."""

    def __init__(self) -> None:
        super().__init__()
        self._n = itertools.count()

    def boot_base(self):
        self.artifact = f"artifact-{next(self._n)}"
        return super().boot_base()


def _built(tmp_path, **kw) -> tuple[SnapshotManager, DistinctBackend]:
    backend = DistinctBackend()
    mgr = SnapshotManager(tmp_path, backend, **kw)
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    return mgr, backend


# --- the knob --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "want"),
    [("", 42.0), ("0", 0.0), ("3600", 3600.0), ("1.5", 1.5),
     ("nan", 42.0), ("inf", 42.0), ("-1", 42.0), ("soon", 42.0)],
)
def test_max_age_env(raw: str, want: float) -> None:
    """0 DISABLES (unlike a timeout); nan would silently disable while looking set."""
    got = max_age_env({"K": raw}, "K", 42.0)
    assert got == want and math.isfinite(got)


def test_default_is_on_and_well_inside_the_measured_failure() -> None:
    assert 0 < DEFAULT_SNAPSHOT_MAX_AGE_S < 24 * 3600


# --- the base --------------------------------------------------------------------------------


def test_base_age_is_none_until_built(tmp_path) -> None:
    assert SnapshotManager(tmp_path, DistinctBackend()).base_age_s() is None


def test_a_young_base_is_left_alone(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=3600.0)
    for _ in range(5):
        mgr.ensure_build_started()
    time.sleep(0.05)
    assert len(backend.boots) == 1
    assert 0.0 <= mgr.base_age_s() < 60


def test_an_aged_base_is_rebuilt_before_any_job_restores_it(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    first = mgr.artifact
    mgr._published_at -= 61.0          # age it past the limit
    mgr.ensure_build_started()         # the pool tick
    assert _wait_until(lambda: mgr.is_built() and mgr.artifact != first)
    assert len(backend.boots) == 2
    assert mgr.base_age_s() < 60


def test_zero_disables_the_age_limit(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=0.0)
    mgr._published_at -= 10 * 24 * 3600.0
    mgr.ensure_build_started()
    time.sleep(0.05)
    assert len(backend.boots) == 1


def test_a_restored_slot_keeps_the_old_generation_through_the_rebuild(tmp_path) -> None:
    """Invalidation RETIRES a pinned artifact rather than pulling it from a live microVM."""
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    mgr.restore("slot-1")
    old = mgr.artifact
    mgr._published_at -= 61.0
    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.is_built() and mgr.artifact != old)
    assert backend.restores[0].artifact == old          # the live slot's mapping is untouched
    assert id(old) in mgr._retired                      # collected on release, not now


# --- idle slots ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("restored_at", "now", "max_age", "usable"),
    [(100.0, 150.0, 60.0, True),      # young
     (100.0, 160.0, 60.0, False),     # exactly at the limit
     (100.0, 10_000.0, 60.0, False),  # long idle
     (100.0, 10_000.0, 0.0, True),    # disabled
     (None, 10_000.0, 60.0, True)],   # unknown restore time never convicts
)
def test_idle_slot_usable(restored_at, now, max_age, usable) -> None:
    assert idle_slot_usable("s", restored_at, now, max_age) is usable


class _Mgr:
    def __init__(self, max_age_s: float) -> None:
        self.max_age_s = max_age_s


class _Slot:
    def __init__(self, slot_id: str) -> None:
        self.slot_id = slot_id


def test_runtime_retires_an_idle_slot_that_sat_too_long() -> None:
    clock = [1000.0]
    rt = GvisorSnapshotSlotRuntime(_Mgr(60.0), clock=lambda: clock[0])
    rt._restored_at["old"] = 900.0
    rt._restored_at["new"] = 990.0
    assert rt.maintain_idle(_Slot("old")) is False
    assert rt.maintain_idle(_Slot("new")) is True


def test_runtime_does_not_convict_a_slot_it_has_no_record_of() -> None:
    rt = GvisorSnapshotSlotRuntime(_Mgr(60.0), clock=lambda: 10_000.0)
    assert rt.maintain_idle(_Slot("never-seen")) is True


def test_runtime_hook_accepts_the_pools_budget_keyword() -> None:
    """The pool calls hook(slot, budget_s=...) when the hook takes it."""
    rt = GvisorSnapshotSlotRuntime(_Mgr(60.0), clock=lambda: 0.0)
    assert rt.maintain_idle(_Slot("x"), budget_s=2.0) is True
