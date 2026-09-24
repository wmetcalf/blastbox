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
        self.fail_always = False
        self.attempts = 0
        #: set the moment a boot begins -- AFTER the manager sampled its epoch
        self.entered = threading.Event()
        self.gate: threading.Event | None = None
        # The manager binds its epoch source here when this is None (see SnapshotManager).
        self._epoch_sampler = None
        self.ack: AckCapability | None = None

    def boot_base(self):
        self.attempts += 1
        self.entered.set()
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail_always:
            raise RuntimeError("persistent boot failure")
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


def _stage(mgr: SnapshotManager) -> None:
    """Wait for the refresh to finish building its replacement (staged, not yet visible)."""
    assert _wait_until(lambda: mgr._staged is not None)


def _swap(mgr: SnapshotManager) -> None:
    """Stage, then acknowledge the way the pool's drain does -- which is what makes it visible."""
    _stage(mgr)
    assert mgr.take_repaired() is True


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
    _swap(mgr)
    assert mgr.artifact != old
    assert mgr.base_age_s() < 60


def test_a_staged_replacement_is_invisible_until_the_pool_takes_it(tmp_path) -> None:
    """The pool stamps a slot's generation BEFORE spawn() restores it, and drains repairs on the
    same thread before spawning. A swap made visible by the refresh thread at an arbitrary moment
    let a slot restored from the NEW base carry the OLD stamp -- and once the drain advanced the
    generation, that slot's failures were discarded as retired-generation evidence."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    old = mgr.artifact
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _stage(mgr)
    mgr.restore("between-stage-and-drain")
    assert backend.restores[-1].artifact == old
    assert mgr.artifact == old
    assert mgr.take_repaired() is True
    mgr.restore("after-drain")
    assert backend.restores[-1].artifact != old


def test_a_failed_refresh_leaves_the_old_base_serving_and_backs_off(tmp_path) -> None:
    """Previously: built=False and every restore refused until a rebuild succeeded."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend, build_retry_backoff_s=3600.0)
    old = mgr.artifact
    backend.fail_always = True
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: backend.attempts == 2)          # the refresh WAS attempted
    assert _wait_until(lambda: mgr._build_thread is None or not mgr._build_thread.is_alive())
    assert mgr.is_built() and mgr.artifact == old
    mgr.restore("after-failed-refresh")           # no "snapshot not built"
    for _ in range(5):                            # and no hot loop of full base boots
        mgr.ensure_build_started()
    time.sleep(0.1)
    assert backend.attempts == 2
    assert mgr.take_repaired() is False


def test_the_age_path_never_invalidates_below_the_ceiling(tmp_path, monkeypatch) -> None:
    """invalidate() on the age path is what let two ticks cancel each other's replacement."""
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    calls: list[int] = []
    monkeypatch.setattr(mgr, "invalidate", lambda: calls.append(1) or True)
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _swap(mgr)
    assert mgr.base_age_s() < 60
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
    _swap(mgr)
    time.sleep(0.1)
    assert mgr.artifact != old
    assert backend.attempts == 2                  # the original build + ONE refresh
    assert mgr.is_built()


def _mid_refresh(tmp_path, **kw):
    """A refresh that has sampled its epoch and is blocked inside boot_base()."""
    backend = kw.pop("backend", None) or DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend, **kw)    # artifact-0
    backend.entered.clear()
    backend.gate = threading.Event()
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert backend.entered.wait(5)
    return mgr, backend


def test_an_invalidate_mid_refresh_adopts_the_refresh_as_its_repair(tmp_path) -> None:
    """The refresh is a FRESH boot, exactly what the repair would build. Rejecting it left the
    tier cold for the rest of the refresh (the repair build could not start behind it) and then
    for a whole second build."""
    ack = AckCapability(artifact_scoped=True)
    backend = DistinctBackend()
    backend.ack = ack
    mgr, _ = _mid_refresh(tmp_path, backend=backend, ack_capable=ack)
    epoch0 = mgr.build_epoch
    assert mgr.invalidate() is True               # the pool convicts the base meanwhile
    assert not mgr.is_built()
    backend.gate.set()
    _stage(mgr)                                   # staged like any refresh: the pool may still
    assert not mgr.is_built()                     # be inside drop(), its generation unmoved
    mgr.ensure_build_started()
    time.sleep(0.05)
    assert backend.attempts == 2                  # and nothing builds over it meanwhile
    assert mgr.take_repaired() is True
    assert mgr.artifact == "artifact-1"
    assert backend.attempts == 2                  # no second build
    assert mgr.build_epoch == epoch0 + 1
    assert ack.capable_for(mgr.build_epoch)       # observed under the epoch it now carries


def test_a_second_invalidate_mid_refresh_rejects_it(tmp_path) -> None:
    mgr, backend = _mid_refresh(tmp_path)
    mgr.invalidate()
    mgr.invalidate()                              # the base convicted AGAIN: refresh is stale
    backend.gate.set()
    assert _wait_until(lambda: not mgr._build_thread.is_alive())
    assert not mgr.is_built()
    backend.gate = None
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    assert mgr.artifact == "artifact-2"


def test_an_invalidate_of_a_staged_refresh_adopts_it(tmp_path) -> None:
    """A finished refresh is a fresh checkpoint -- what the repair would build. The drain cannot
    swap it in while the pool's drop() holds _invalidation_lock, so adopting it is safe; throwing
    it away cost a full cold rebuild whenever a failure beat the tick to it."""
    ack = AckCapability(artifact_scoped=True)
    backend = DistinctBackend()
    backend.ack = ack
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend, ack_capable=ack)
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _stage(mgr)
    mgr.invalidate()
    assert not mgr.is_built()                     # nothing appears inside the pool's drop()
    assert mgr.take_repaired() is True
    assert mgr.artifact == "artifact-1"
    assert backend.attempts == 2
    assert ack.capable_for(mgr.build_epoch)


def test_a_second_invalidate_discards_a_staged_refresh(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _stage(mgr)
    mgr.invalidate()
    mgr.invalidate()
    assert mgr._staged is None
    assert mgr.take_repaired() is False
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)
    assert mgr.artifact == "artifact-2"


def test_build_waits_for_a_live_refresh_instead_of_racing_it(tmp_path) -> None:
    """A second _build overlapping the adopted refresh shares its epoch: begin_build() of one
    erased the other's ACK observation, and a stale observation could certify the other base."""
    mgr, backend = _mid_refresh(tmp_path)
    mgr.invalidate()
    got: list[object] = []
    t = threading.Thread(target=lambda: got.append(mgr.build()))
    t.start()
    time.sleep(0.1)
    backend.gate.set()
    t.join(5)
    assert got == ["artifact-1"]
    assert backend.attempts == 2


def test_a_refresh_retries_undead_bases_first(tmp_path, monkeypatch) -> None:
    """A full, idle pool never calls acquire_built(), so a refresh is the only build path that
    runs -- and each failed one could park another live base sandbox."""
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    retried: list[str] = []
    real = mgr._retry_undead_bases
    monkeypatch.setattr(mgr, "_retry_undead_bases",
                        lambda: retried.append(threading.current_thread().name) or real())
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _stage(mgr)
    assert "warm-snapshot-refresh" in retried


def test_a_swap_is_reported_to_the_pool_exactly_once(tmp_path) -> None:
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    assert mgr.take_repaired() is False           # the first build is not a repair
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _swap(mgr)
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
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _stage(mgr)
    assert ack.capable_for(old_epoch)             # staged is not published: old stays current
    assert mgr.take_repaired() is True
    new_epoch = mgr.build_epoch
    assert new_epoch == old_epoch + 1
    assert ack.capable_for(new_epoch)             # the replacement's own advertisement
    assert not ack.capable_for(old_epoch)         # old slots read UNKNOWN, which convicts nothing
    assert mgr._pin_epoch["old-slot"] == old_epoch


def test_the_superseded_generation_is_retired_not_pulled_from_a_live_slot(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    mgr.restore("slot-1")
    old = mgr.artifact
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _swap(mgr)
    assert backend.restores[0].artifact == old
    assert id(old) in mgr._retired


# --- the ceiling -----------------------------------------------------------------------------


def test_past_the_ceiling_a_base_whose_refresh_keeps_failing_is_invalidated(tmp_path) -> None:
    """Keeping a base alive is right below the ceiling; past it, restores hang every job at the
    worker timeout, which is worse than the pool's cold fallback."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    backend.fail_always = True
    _age(mgr, 119.0)
    mgr.ensure_build_started()
    assert _wait_until(lambda: backend.attempts == 2)
    assert _wait_until(lambda: not mgr._build_thread.is_alive())
    assert mgr.is_built()                         # below the ceiling: keep serving
    _age(mgr, 2.0)                                # 121s > 2 x 60s
    mgr.ensure_build_started()
    assert not mgr.is_built()
    assert mgr.take_repaired() is True            # the pool retires the old generation's slots
    backend.fail_always = False
    mgr._retry_not_before = 0.0
    mgr.ensure_build_started()
    assert _wait_until(mgr.is_built)


def test_a_refresh_still_running_at_the_ceiling_becomes_the_repair(tmp_path) -> None:
    mgr, backend = _mid_refresh(tmp_path)
    _age(mgr, 60.0)                               # 121s: the refresh is still booting
    mgr.ensure_build_started()
    assert not mgr.is_built()
    backend.gate.set()
    _swap(mgr)
    assert mgr.artifact == "artifact-1"
    assert backend.attempts == 2


# --- idle slots ------------------------------------------------------------------------------


def test_slots_retire_by_checkpoint_age_not_restore_age(tmp_path) -> None:
    """A slot restored late in its base's life is as old as the CHECKPOINT, not its restore."""
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    _age(mgr, 50.0)
    mgr.restore("late")                           # restored now, from a 50s-old checkpoint
    _age(mgr, 69.0)
    assert mgr.slot_should_retire("late") is False    # checkpoint 119s old
    _age(mgr, 2.0)
    assert mgr.slot_should_retire("late") is True     # 121s: past 2 x max-age, restored 71s ago
    assert mgr.slot_should_retire("never-seen") is False


def test_a_swap_does_not_mass_retire_idle_slots_below_the_ceiling(tmp_path) -> None:
    """Retiring every idle slot at the swap emptied the claimable pool at once for slots that
    were still well inside the safe window; they turn over on use."""
    mgr, _ = _built(tmp_path, max_age_s=60.0)
    mgr.restore("old")
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    _swap(mgr)
    mgr.restore("new")
    assert mgr.slot_should_retire("old") is False
    assert mgr.slot_should_retire("new") is False


def test_zero_disables_everything(tmp_path) -> None:
    mgr, backend = _built(tmp_path, max_age_s=0.0)
    mgr.restore("s")
    _age(mgr, 10 * 24 * 3600.0)
    mgr.ensure_build_started()
    time.sleep(0.05)
    assert backend.attempts == 1
    assert mgr.is_built()
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


def test_the_pool_drain_retires_the_old_bases_evidence_with_its_generation() -> None:
    """Advancing the generation only filters failures reported AFTER the drain. Evidence the aged
    base had already accumulated survived into its replacement, so two old-slot pre-guest hangs
    plus ONE from the fresh base convicted the base the refresh had just built."""
    from blastbox.host.pool import WarmPool

    mgr = _Mgr()
    rt = _runtimes(mgr)[0]
    pool = WarmPool(runtime=rt, warm_size=0, concurrent_ceiling=1)
    before = pool._base_generation.get("", 0)
    pool._pool_consecutive_failures[""] = 2
    pool._pool_pre_guest_failures[""] = {"old-a", "old-b"}
    mgr.repaired = True
    pool._drain_runtime_repairs()
    assert pool._base_generation.get("", 0) == before + 1
    assert "" not in pool._pool_consecutive_failures
    assert "" not in pool._pool_pre_guest_failures


def test_a_cascade_forwards_its_tiers_own_repairs_and_clears_their_streak() -> None:
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    mgr = _Mgr()
    inner = _runtimes(mgr)[0]
    casc = CascadingRuntime([Tier("firecracker", inner, 1)])
    assert casc.take_repaired_tiers() == []
    casc._tier_failures[0] = 2
    casc._job_guilty.add(0)
    mgr.repaired = True
    reported = casc.take_repaired_tiers()
    assert reported == [casc._tier_identity(0)]
    assert casc._tier_failures[0] == 0            # the swapped-out base's streak goes with it
    # ...but NOT the episode's guilt: a swap does not end a job-failure episode, and empty
    # guilt makes a pending cascade repair fall back to rebuilding EVERY tier.
    assert 0 in casc._job_guilty
    assert casc.take_repaired_tiers() == []


# --- round 3: the refresh's epoch is fixed when it STARTS -------------------------------------


def _refresh_blocked_before_boot(tmp_path):
    """A refresh whose thread is running but has not reached boot_base() -- held in the
    pre-boot housekeeping (undead-base retry, sweeps), which can take a runsc timeout."""
    backend = DistinctBackend()
    mgr, _ = _built(tmp_path, max_age_s=60.0, backend=backend)
    hold, inside = threading.Event(), threading.Event()
    real = mgr._sweep_retired

    def slow_sweep() -> None:
        inside.set()
        hold.wait(5)
        real()

    mgr._sweep_retired = slow_sweep            # type: ignore[method-assign]
    _age(mgr, 61.0)
    mgr.ensure_build_started()
    assert inside.wait(5)
    return mgr, backend, hold


def test_an_invalidate_before_the_refresh_boots_still_adopts_it(tmp_path) -> None:
    mgr, backend, hold = _refresh_blocked_before_boot(tmp_path)
    mgr.invalidate()
    hold.set()
    _swap(mgr)
    assert mgr.artifact == "artifact-1"
    assert backend.attempts == 2                  # no second full build


def test_a_second_invalidate_rejects_the_refresh_whenever_the_first_landed(tmp_path) -> None:
    mgr, backend, hold = _refresh_blocked_before_boot(tmp_path)
    mgr.invalidate()                              # before the boot
    backend.entered.clear()
    backend.gate = threading.Event()
    hold.set()
    assert backend.entered.wait(5)
    mgr.invalidate()                              # during it: this build is convicted too
    backend.gate.set()
    assert _wait_until(lambda: not mgr._build_thread.is_alive())
    assert not mgr.is_built()


def test_the_ceiling_leaves_a_staged_refresh_for_the_drain(tmp_path) -> None:
    """tick() judges the ceiling (prepare) BEFORE it drains (the swap), so a refresh that staged
    just as the base crossed the ceiling was thrown away for a whole new build. Swapping it in
    from prepare() instead is no better: a cascade calls prepare() per spawn, mid-batch."""
    mgr, backend = _built(tmp_path, max_age_s=60.0)
    _age(mgr, 119.0)
    mgr.ensure_build_started()
    _stage(mgr)
    _age(mgr, 2.0)
    mgr.ensure_build_started()
    assert mgr.is_built() and mgr.artifact == "artifact-0"   # at most one tick more
    assert mgr._staged is not None
    assert mgr.take_repaired() is True
    assert mgr.artifact == "artifact-1"
    assert backend.attempts == 2
    assert mgr.take_repaired() is False           # reported once


def test_the_drain_waits_out_a_pool_rebuild_in_flight() -> None:
    """The pool advances the generation only after drop() returns. A swap drained inside that
    window would let the tick stamp new-base slots with the generation about to be retired."""
    from blastbox.host.pool import WarmPool

    mgr = _Mgr()
    pool = WarmPool(runtime=_runtimes(mgr)[0], warm_size=0, concurrent_ceiling=1)
    mgr.repaired = True
    with pool._invalidation_lock:
        pool._drain_runtime_repairs()
    assert mgr.repaired is True                   # not taken while the rebuild is in flight
    pool._drain_runtime_repairs()
    assert mgr.repaired is False


def test_the_drain_swaps_and_advances_under_one_pool_lock() -> None:
    """A failure report landing between the swap and the generation bump still matched the old
    generation and could convict the base that had just been swapped in."""
    from blastbox.host.pool import WarmPool

    mgr = _Mgr()
    pool = WarmPool(runtime=_runtimes(mgr)[0], warm_size=0, concurrent_ceiling=1)
    held: list[bool] = []
    real = mgr.take_repaired

    def take() -> bool:
        held.append(pool._lock.locked())
        return real()

    mgr.take_repaired = take                      # type: ignore[method-assign]
    mgr.repaired = True
    pool._drain_runtime_repairs()
    assert held == [True]


def test_a_retired_generation_slot_does_not_blame_its_tier() -> None:
    """Old slots stay claimable after a swap; their failures must not rebuild the tier's
    evidence against the base that replaced them."""
    from blastbox.host.pool import WarmPool

    mgr = _Mgr()
    rt = _runtimes(mgr)[0]
    blamed: list[str] = []
    rt.blame_tier_for_slot = blamed.append        # type: ignore[attr-defined]
    pool = WarmPool(runtime=rt, warm_size=0, concurrent_ceiling=1)
    pool._base_generation["fc#0"] = 1
    pool._slot_base["old"] = ("fc#0", 0)
    pool._slot_base["new"] = ("fc#0", 1)
    pool._blame_tiers(["old", "new", "unstamped"])
    assert blamed == ["new", "unstamped"]
