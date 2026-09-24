"""A warm tier must not rot while idle -- and refreshing it must not cost the tier.

Measured on toolz2 2026-09-23: a Firecracker base checkpointed minutes earlier served 12/12,
the same engine's base from five days before hung every job at the 300s worker timeout, and two
slots restored five days earlier and never claimed hung the first job sent to them. Every repair
path in the pool is reactive -- it needs failures, each costing the full timeout -- and an idle
tier produces none until a real job pays.

The refresh is BUILD-THEN-SWAP. Review of the first version (invalidate-then-build) found that
it dropped the working base before the replacement existed, so a failed rebuild left zero warm
capacity; that two concurrent age checks could invalidate twice and reject the replacement; and
that the pool was never told, so failures from old-generation slots were charged to the new
base. These tests pin each of those.
"""

from __future__ import annotations

import itertools
import math
import threading
import time

import pytest

from blastbox.host.runtime.env_knobs import max_age_env
from blastbox.host.runtime.fc_snapshot import (
    DEFAULT_SNAPSHOT_MAX_AGE_S,
    SnapshotManager,
)
from blastbox.worker.warm import AckCapability

from .test_fc_snapshot import FakeBackend, _wait_until


class DistinctBackend(FakeBackend):
    """Each base boot yields a NEW artifact, so a swap is observable. Optionally fails or blocks."""

    def __init__(self) -> None:
        super().__init__()
        self._n = itertools.count()
        self.fail_next = False
        self.gate: threading.Event | None = None
        # The manager binds its epoch source here when this is None (see SnapshotManager).
        self._epoch_sampler = None
        self.ack: AckCapability | None = None

    def boot_base(self):
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("transient boot failure")
        if self.ack is not None and self._epoch_sampler is not None:
            self.ack.observe(self._epoch_sampler())    # this build advertises the protocol
        self.artifact = f"artifact-{next(self._n)}"
        return super().boot_base()


def _built(tmp_path, **kw) -> tuple[SnapshotManager, DistinctBackend]:
    backend = kw.pop("backend", None) or DistinctBackend()
    mgr = SnapshotManager(tmp_path, backend, **kw)
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    return mgr, backend


def _age(mgr: SnapshotManager, seconds: float) -> None:
    """Let ``seconds`` pass: the base AND every slot's recorded checkpoint get older."""
    mgr._published_at -= seconds
    for sid in mgr._pin_born:
        mgr._pin_born[sid] -= seconds


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


def test_from_env_is_where_both_factories_read_the_knobs(tmp_path) -> None:
    """One constructor reads BLASTBOX_SNAPSHOT_MAX_AGE_S for the FC and gVisor factories alike.

    Each factory used to build its own kwargs; a knob added to one and not the other is the drift
    this closes. Both select_* functions construct via from_env (asserted structurally below).
    """
    env = {"BLASTBOX_SNAPSHOT_MAX_AGE_S": "123", "BLASTBOX_SNAPSHOT_READY_S": "45"}
    mgr = SnapshotManager.from_env(tmp_path, DistinctBackend(), env=env)
    assert mgr.max_age_s == 123.0
    assert mgr._ready_timeout_s == 45.0
    assert SnapshotManager.from_env(tmp_path, DistinctBackend(), env={}).max_age_s == (
        DEFAULT_SNAPSHOT_MAX_AGE_S
    )


def test_both_factories_construct_through_from_env() -> None:
    import inspect

    from blastbox.host.runtime import fc_snapshot_runtime, gvisor_snapshot_runtime

    for mod in (fc_snapshot_runtime, gvisor_snapshot_runtime):
        src = inspect.getsource(mod)
        assert "SnapshotManager.from_env(" in src, mod.__name__
        assert "SnapshotManager(" not in src.replace("SnapshotManager.from_env(", ""), mod.__name__


# --- the base: build-then-swap ---------------------------------------------------------------


def test_base_age_is_none_until_built(tmp_path) -> None:
    assert SnapshotManager(tmp_path, DistinctBackend()).base_age_s() is None


def test_a_young_base_is_left_alone(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=3600.0)
    for _ in range(5):
        mgr.ensure_build_started()
    time.sleep(0.05)
    assert len(backend.boots) == 1
    assert 0.0 <= mgr.base_age_s() < 60


def test_an_aged_base_keeps_serving_while_its_replacement_builds(tmp_path) -> None:
    """The old artifact is never dropped before the new one exists."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    old = mgr.artifact
    backend.gate = threading.Event()              # hold the replacement build
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert mgr.is_built() and mgr.artifact == old  # still serving, mid-refresh
    mgr.restore("during-refresh")                  # and still restorable
    backend.gate.set()
    assert _wait_until(lambda: mgr.artifact != old)
    assert mgr.base_age_s() < 60


def test_a_failed_refresh_leaves_the_old_base_serving(tmp_path) -> None:
    """Previously: built=False and every restore refused until a rebuild succeeded."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    old = mgr.artifact
    backend.fail_next = True
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: backend.boots and len(backend.boots) >= 1)
    time.sleep(0.2)
    assert mgr.is_built() and mgr.artifact == old
    mgr.restore("after-failed-refresh")           # no "snapshot not built"


def test_the_age_path_never_invalidates(tmp_path, monkeypatch) -> None:
    """invalidate() on the age path is what let two ticks cancel each other's replacement."""
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    calls: list[int] = []
    monkeypatch.setattr(mgr, "invalidate", lambda: calls.append(1) or True)
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.base_age_s() is not None and mgr.base_age_s() < 60)
    assert calls == []


def test_concurrent_age_checks_start_exactly_one_refresh(tmp_path) -> None:
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    old = mgr.artifact
    backend.gate = threading.Event()
    _age(mgr, 61.0)
    threads = [threading.Thread(target=mgr.ensure_build_started) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    backend.gate.set()
    assert _wait_until(lambda: mgr.artifact != old)
    time.sleep(0.1)
    assert len(backend.boots) == 2                # the original build + ONE refresh
    assert mgr.is_built()


def test_an_invalidate_during_a_refresh_wins(tmp_path) -> None:
    """A pool repair landing mid-refresh must not be overwritten by the stale replacement."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)    # artifact-0
    backend.gate = threading.Event()
    _age(mgr, 61.0)
    mgr.ensure_build_started()                   # refresh boots artifact-1, held at the gate
    assert _wait_until(lambda: len(backend.boots) == 2 or backend.gate is not None)
    mgr.invalidate()                              # the pool convicts the base meanwhile
    backend.gate.set()
    time.sleep(0.2)
    assert mgr.artifact != "artifact-1"          # the staged build was NOT published
    backend.gate = None
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    assert mgr.artifact not in ("artifact-0", "artifact-1")


def test_a_swap_is_reported_to_the_pool_exactly_once(tmp_path) -> None:
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    assert mgr.take_repaired() is False           # the first build is not a repair
    old = mgr.artifact
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.artifact != old)
    assert mgr.take_repaired() is True
    assert mgr.take_repaired() is False


def test_a_swap_gives_the_new_base_its_own_epoch_and_ack(tmp_path) -> None:
    ack = AckCapability(artifact_scoped=True)
    backend = DistinctBackend()
    backend.ack = ack
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend, ack_capable=ack)
    old_epoch = mgr.build_epoch
    mgr.restore("old-slot")
    assert mgr._pin_epoch["old-slot"] == old_epoch
    assert ack.capable_for(old_epoch)
    old = mgr.artifact
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.artifact != old)
    new_epoch = mgr.build_epoch
    assert new_epoch != old_epoch
    assert ack.capable_for(new_epoch)             # the replacement's own advertisement
    assert not ack.capable_for(old_epoch)         # old slots read UNKNOWN, which convicts nothing
    assert mgr._pin_epoch["old-slot"] == old_epoch


def test_the_superseded_generation_is_retired_not_pulled_from_a_live_slot(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    mgr.restore("slot-1")
    old = mgr.artifact
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: mgr.artifact != old)
    assert backend.restores[0].artifact == old
    assert id(old) in mgr._retired


# --- idle slots ------------------------------------------------------------------------------


def test_slots_retire_only_once_a_newer_base_exists_and_their_checkpoint_is_old(tmp_path) -> None:
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    mgr.restore("old")
    _age(mgr, 61.0)
    # Aged, but no replacement yet: keep serving rather than retire into a void.
    backend.gate = threading.Event()
    mgr.ensure_build_started()
    assert mgr.slot_should_retire("old") is False
    old = mgr.artifact
    backend.gate.set()
    assert _wait_until(lambda: mgr.artifact != old)
    mgr.restore("new")
    assert mgr.slot_should_retire("old") is True    # superseded AND its checkpoint is old
    assert mgr.slot_should_retire("new") is False
    assert mgr.slot_should_retire("never-seen") is False


def test_a_young_superseded_slot_is_not_retired_by_age(tmp_path) -> None:
    """A pool repair supersedes a young base; that is the pool's business, not the age limit's."""
    mgr, _ = _built(tmp_path, max_age_s=3600.0)
    mgr.restore("young")
    mgr.invalidate()
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    assert mgr.slot_should_retire("young") is False


def test_zero_disables_everything(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=0.0)
    mgr.restore("s")
    _age(mgr, 10 * 24 * 3600.0)
    mgr.ensure_build_started()
    time.sleep(0.05)
    assert len(backend.boots) == 1
    assert mgr.slot_should_retire("s") is False


# --- the runtimes and the pool ---------------------------------------------------------------


class _Slot:
    def __init__(self, slot_id: str) -> None:
        self.slot_id = slot_id


class _Mgr:
    """Just the surface the runtimes consult."""

    def __init__(self) -> None:
        self.retire: set[str] = set()
        self.repaired = False
        self.max_age_s = 60.0

    def slot_should_retire(self, slot_id: str) -> bool:
        return slot_id in self.retire

    def take_repaired(self) -> bool:
        out, self.repaired = self.repaired, False
        return out


def _runtimes(mgr):
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    return [SnapshotSlotRuntime(object(), mgr), GvisorSnapshotSlotRuntime(mgr)]


@pytest.mark.parametrize("which", [0, 1], ids=["firecracker", "gvisor"])
def test_runtime_maintain_idle_follows_the_manager(which) -> None:
    mgr = _Mgr()
    rt = _runtimes(mgr)[which]
    mgr.retire.add("stale")
    assert rt.maintain_idle(_Slot("stale")) is False
    assert rt.maintain_idle(_Slot("fresh"), budget_s=2.0) is True


@pytest.mark.parametrize("which", [0, 1], ids=["firecracker", "gvisor"])
def test_runtime_reports_a_swap_as_a_repair_of_its_base(which) -> None:
    mgr = _Mgr()
    rt = _runtimes(mgr)[which]
    assert rt.take_repaired_tiers() == []
    mgr.repaired = True
    assert rt.take_repaired_tiers() == [""]
    assert rt.take_repaired_tiers() == []


def test_the_pool_advances_the_generation_on_a_swap() -> None:
    """End to end through the pool's own drain: old-generation failures stop counting."""
    from blastbox.host.pool import WarmPool

    mgr = _Mgr()
    rt = _runtimes(mgr)[0]
    pool = WarmPool(runtime=rt, warm_size=0, concurrent_ceiling=1)
    before = pool._base_generation.get("", 0)
    mgr.repaired = True
    pool._drain_runtime_repairs()
    assert pool._base_generation.get("", 0) == before + 1


def test_a_cascade_forwards_its_tiers_own_repairs() -> None:
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    mgr = _Mgr()
    inner = _runtimes(mgr)[0]
    casc = CascadingRuntime([Tier("firecracker", inner, 1)])
    assert casc.take_repaired_tiers() == []
    mgr.repaired = True
    reported = casc.take_repaired_tiers()
    assert reported == [casc._tier_identity(0)]
    assert casc.take_repaired_tiers() == []
