"""A warm base that wedges must not cost 48 real jobs before it repairs itself.

Observed in production (toolz2, 2026-08-24): both warm tiers wedged after ~4 days idle. Every job
was handed to a slot whose guest never executed --

    warm_phases outcome=failed total=300.622 go=0.004 release=300.372     # no `guest=` phase
    pool.health pool_consecutive_failures=5 base_rebuilds=0

-- and burned the full 300s worker timeout. The pool was behaving as configured: the base-rebuild
threshold is 2 x warm_size (48 at warm_size=24), sized so a run of malformed samples cannot
destroy a healthy base. But a slot that never reached its guest did not fail ON a sample; it
failed to become able to run one, and that ambiguity is absent. Waiting for 48 of those means the
tier silently degrades to cold-only for hours, which is most of what a warm tier is for.
"""

import threading
from pathlib import Path
from uuid import uuid4

from blastbox.host.pool import Slot, SlotState, WarmPool, release_kwargs


class _Wedged:
    """Alive, recyclable, never able to execute — the production shape."""

    kind = "test"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.base_invalidations = 0

    def spawn(self) -> Slot:
        sid = str(uuid4())
        return Slot(
            slot_id=sid,
            control_dir=Path(f"/fake/c/{sid}"),
            input_dir=Path(f"/fake/i/{sid}"),
            output_dir=Path(f"/fake/o/{sid}"),
            state=SlotState.WARMING,
            spawned_at=0.0,
        )

    def is_ready(self, slot):
        return True

    def is_alive(self, slot):
        return True

    def recycle(self, slot):
        return None

    def reap(self, slot):
        return None

    def invalidate_base(self) -> None:
        with self._lock:
            self.base_invalidations += 1


def _pool(rt, **kw):
    """PROD-LIKE sizing on purpose. warm_size=24 puts the ordinary threshold at 2 x 24 = 48, far
    above the pre-guest bar, so a test that trips can only have tripped the fast path. At
    warm_size=2 the ordinary threshold is 4 and the two are indistinguishable -- which is exactly
    how the first version of this test passed for the wrong reason."""
    return WarmPool(
        runtime=rt, warm_size=24, concurrent_ceiling=32, spawn_rate_limit=1000.0, **kw
    )


def _claim_distinct(pool, n):
    """n slots claimed BEFORE any is released -- otherwise the pool re-hands the same one, and
    'three failures' quietly becomes 'one slot three times', which proves nothing about the base."""
    for _ in range(10):
        pool.tick()
    slots = [pool.claim(timeout_s=0) for _ in range(n)]
    assert all(s is not None for s in slots), "expected IDLE slots to claim"
    assert len({s.slot_id for s in slots}) == n, "expected DISTINCT slots"
    return slots


def _fail(pool, slot, *, stage):
    pool.release(slot, dirty=True, fault="worker", fault_stage=stage)


def test_three_slots_that_never_reach_their_guest_convict_the_base():
    """The fix. Three DISTINCT slots, none able to execute anything, is the base -- not 48 jobs
    later, which at a 300s worker timeout is hours of a warm tier serving nothing."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations >= 1
    assert max(pool._pool_consecutive_failures.values(), default=0) < 48, (
        "must have tripped the pre-guest path, not the ordinary threshold"
    )


def test_the_same_slot_failing_repeatedly_does_not_convict_the_base():
    """One wedged worker is not a wedged base -- the evidence has to be DISTINCT slots.

    max_consecutive_failures is raised so one slot CAN fail past the pre-guest threshold; at the
    default of 2 it burns out first and the test would pass without exercising the rule at all.
    """
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3, max_consecutive_failures=0)
    slot = _claim_distinct(pool, 1)[0]
    for _ in range(6):
        _fail(pool, slot, stage="pre_guest")
    assert len(pool._pool_pre_guest_failures.get("", set())) <= 1, (
        "one slot must contribute at most one piece of evidence"
    )
    assert rt.base_invalidations == 0


def test_failures_inside_the_guest_still_need_the_full_threshold():
    """A run of malformed samples must not destroy a healthy base. That ambiguity is why the
    ordinary threshold is 2 x warm_size, and this fix must not lower it."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 6):
        _fail(pool, slot, stage=None)  # failed IN the guest: could be the document
    assert rt.base_invalidations == 0


def test_a_served_job_clears_the_pre_guest_evidence():
    """One success proves the base CAN execute, which is what the evidence claims it cannot."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    a, b, c, d = _claim_distinct(pool, 4)
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    pool.release(c, dirty=False)  # a clean, served job
    _fail(pool, d, stage="pre_guest")
    assert rt.base_invalidations == 0, "the streak must restart after a served job"


def test_the_threshold_is_configurable():
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=2)
    for slot in _claim_distinct(pool, 2):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations >= 1


def test_the_kwarg_is_only_passed_to_pools_that_accept_it():
    """A pool predating the attribution must behave exactly as before, not raise TypeError -- the
    ladder this seam replaced swallowed that as a 'fallback' and released a slot twice."""

    def old_release(slot, *, dirty=False, fault=None): ...
    def new_release(slot, *, dirty=False, fault=None, fault_stage=None): ...

    assert release_kwargs(
        old_release, dirty=True, fault="worker", fault_stage="pre_guest"
    ) == {"dirty": True, "fault": "worker"}
    assert release_kwargs(
        new_release, dirty=True, fault="worker", fault_stage="pre_guest"
    ) == {"dirty": True, "fault": "worker", "fault_stage": "pre_guest"}


# --- the dispatch-side half: deciding WHEN a failure is pre-guest ----------------------------
def test_warm_fault_stage_reports_pre_guest_only_when_the_guest_never_ran():
    """The pool half is useless if the dispatcher never reports the stage. This is the exact
    production shape: signal_go succeeded, wait_for_done timed out, `guest` was never marked."""
    from blastbox.host.dispatch import _PhaseTimer, warm_fault_stage

    class _Ctl:
        guest_started = False  # the guest PROVED it never started

    wedged = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go"):
        wedged.mark(ph)  # ...then wait_for_done times out; no `guest`
    assert warm_fault_stage(False, "worker", wedged, _Ctl()) == "pre_guest"

    # THE GUEST PHASE DOES NOT RESCUE IT. That mark means only that wait_for_done RETURNED --
    # some `done` file appeared -- and the dispatcher discards the status string. A worker whose
    # wait_for_go() expired writes done="idle_timeout" WITHOUT ever writing `started`, so the
    # phase is marked for a job the guest never took. Letting that override the ack made three
    # slots that never accepted their jobs wait for the ordinary threshold instead of the fast
    # repair built for exactly that shape.
    ran = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go", "guest"):
        ran.mark(ph)
    assert warm_fault_stage(False, "worker", ran, _Ctl()) == "pre_guest", (
        "a worker-written completion status is not proof that detonation executed"
    )

    # ...whereas an ack that DID arrive is proof it ran, phase mark or not.
    class _Started:
        guest_started = True

    assert warm_fault_stage(False, "worker", ran, _Started()) is None, (
        "a failure after the guest executed could be the document"
    )
    assert warm_fault_stage(False, "worker", wedged, _Started()) is None

    # ...and UNKNOWN still convicts nothing, in either shape.
    class _Unknown:
        guest_started = None

    assert warm_fault_stage(False, "worker", ran, _Unknown()) is None
    assert warm_fault_stage(False, "worker", wedged, _Unknown()) is None

    # a clean run, and a job-attributed fault, are never base evidence
    assert warm_fault_stage(True, None, wedged, _Ctl()) is None
    assert warm_fault_stage(False, "job", wedged, _Ctl()) is None
    assert warm_fault_stage(False, None, wedged, _Ctl()) is None


def test_phase_timer_reports_which_phases_ran():
    from blastbox.host.dispatch import _PhaseTimer

    t = _PhaseTimer("j")
    t.mark("go")
    assert t.reached("go") and not t.reached("guest")


# --- review round 1 on #90 -------------------------------------------------------------------
def test_the_fast_path_is_on_by_default():
    """Safe to default on now that the guest itself reports the start (see
    tests/host/runtime/test_warm_start_ack.py): a document that hangs a healthy slot acks first
    and is never attributed to the base, and a worker too old to ack leaves the answer UNKNOWN,
    which also never convicts."""
    from blastbox.host.pool_config import PoolConfig

    assert PoolConfig.pre_guest_rebuild_after == 3
    pool = WarmPool(
        runtime=_Wedged(), warm_size=24, concurrent_ceiling=32, spawn_rate_limit=1000.0
    )
    assert pool._pre_guest_rebuild_after == 3


def test_zero_still_disables_it_entirely():
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=0)
    for slot in _claim_distinct(pool, 6):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 0, "disabled means disabled"


def test_a_threshold_of_one_is_floored_to_two():
    """A threshold of 1 would rebuild the base on a single hung document."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=1)
    assert pool._pre_guest_rebuild_after == 2


def test_the_escape_hatch_does_not_leak_evidence():
    """With BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER=0, _maybe_rebuild_base returns before anything
    consumes the set -- so a continuously wedged tier producing no successes added one slot id
    per failed job, for the life of the process. The integer counter it replaced could not grow."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3, snapshot_rebuild_after=0)
    for slot in _claim_distinct(pool, 8):
        _fail(pool, slot, stage="pre_guest")
    total = sum(len(v) for v in pool._pool_pre_guest_failures.values())
    assert total == 0, (
        f"evidence accumulated with repair disabled: {total} slot ids retained"
    )


def test_a_failed_repair_hands_the_evidence_back():
    """The crossing count (3) is far below the ordinary threshold (48), so restoring only the
    integer streak made the fast path a one-shot: the same unrepaired base had to accumulate
    three fresh distinct slots again before it would even retry."""

    class _RepairFails(_Wedged):
        def invalidate_base(self):
            raise OSError("could not drop the base artifact")

    rt = _RepairFails()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    retained = len(pool._pool_pre_guest_failures.get("", set()))
    assert retained >= 3, (
        f"a failed repair must not discard the evidence that justified it (kept {retained})"
    )


def test_a_success_from_a_retired_generation_does_not_clear_current_evidence():
    """The failure side is generation-guarded; this side was not. A long-running job from an
    already-invalidated generation completing later wiped evidence the REPLACEMENT base had
    accumulated under the same identity."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    stale, a, b = _claim_distinct(pool, 3)
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    # retire the generation `stale` was restored from, then let it succeed late
    ident, gen = pool._slot_base.get(stale.slot_id, ("", 0))
    pool._base_generation[ident] = gen + 1
    pool.release(stale, dirty=False)
    assert len(pool._pool_pre_guest_failures.get("", set())) == 2, (
        "a success from a retired base must not clear the current base's evidence"
    )


def test_the_stage_is_only_reported_when_the_guest_PROVED_it_never_started():
    """The pool half is only sound if the dispatcher refuses to guess. Full matrix in
    tests/host/runtime/test_warm_start_ack.py; this pins the decision itself."""
    from blastbox.host.dispatch import _PhaseTimer, warm_fault_stage

    class _Ctl:
        def __init__(self, started):
            self.guest_started = started

    wedged = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go"):
        wedged.mark(ph)  # ...then a timeout; `guest` never marked

    assert warm_fault_stage(False, "worker", wedged, _Ctl(False)) == "pre_guest"
    assert warm_fault_stage(False, "worker", wedged, _Ctl(True)) is None, (
        "it acked, so it ran -- the document is the suspect, not the base"
    )
    assert warm_fault_stage(False, "worker", wedged, _Ctl(None)) is None, (
        "UNKNOWN (older worker image) must never convict"
    )
    assert warm_fault_stage(False, "worker", wedged, None) is None, (
        "a seam with no ack at all must never convict"
    )


# --- review round 2 on #90 --------------------------------------------------------------------
class _TieredWedge(_Wedged):
    """A cascade-shaped runtime: slots carry a tier identity, repairs are recorded per tier."""

    def __init__(self):
        super().__init__()
        self.invalidated: list = []
        self._ident = {}

    def base_identity(self, slot):
        return self._ident.setdefault(slot.slot_id, "tierB")

    def invalidate_base(self, *, reason=None, only=None):
        self.invalidated.append(only)
        self.base_invalidations += 1
        return [only] if only else ["tierA", "tierB"]


def test_the_fast_path_names_the_tier_it_convicted():
    """A cascade otherwise rebuilds every tier in the episode-wide guilt set, so one unrelated
    fault on healthy tier A plus three pre-guest failures on B destroys A's base too -- removing
    the fallback capacity that is the whole point of a cascade."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.invalidated == ["tierB"], (
        f"expected only the convicted tier, got {rt.invalidated}"
    )


def test_a_success_on_another_base_does_not_abandon_this_ones_repair():
    """The stale-decision token was pool-wide, so a job completing on healthy tier A while tier
    B's repair was being judged abandoned B's decision -- about a base that produced nothing of
    the kind -- and B then had to sacrifice three more distinct jobs."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    a, b, c, other = _claim_distinct(pool, 4)
    rt._ident[other.slot_id] = "tierA"  # a DIFFERENT base
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    pool.release(other, dirty=False)  # healthy tier A serves a job
    _fail(pool, c, stage="pre_guest")
    assert rt.base_invalidations >= 1, (
        "a success on another base must not abandon this base's repair"
    )


def test_a_committed_generation_does_not_inherit_retired_evidence():
    """Releases landing WHILE drop() ran rebuilt a set after the episode consumed the old one,
    charging the retired base's failures to its replacement."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 1
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "the freshly installed generation must start with no inherited evidence"
    )


def test_evidence_accumulating_DURING_the_repair_is_not_charged_to_the_replacement():
    """Slots still assigned when drop() starts release while it runs, building a NEW set after
    the episode consumed the old one. Without clearing on commit, the retired base's failures are
    charged to its replacement: two such stragglers plus one genuine failure convict a fresh base,
    and with the cooldown disabled that is a back-to-back rebuild."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=0)
    a, b, c, s1, s2 = _claim_distinct(pool, 5)

    def _drop(*, reason=None, only=None):
        # two stragglers from the RETIRED generation land mid-repair
        _fail(pool, s1, stage="pre_guest")
        _fail(pool, s2, stage="pre_guest")
        rt.invalidated.append(only)
        rt.base_invalidations += 1
        return [only] if only else ["tierB"]

    rt.invalidate_base = _drop
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    _fail(pool, c, stage="pre_guest")  # crosses -> drop() runs, stragglers land inside
    assert rt.base_invalidations == 1
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "the committed generation inherited the retired base's stragglers: "
        f"{pool._pool_pre_guest_failures}"
    )


def test_the_loser_of_the_repair_race_keeps_its_evidence():
    """Two cascade bases can cross concurrently: both threads consume their evidence before
    contending for the invalidation lock, and the loser lands on the cooldown skip. Its tier was
    never repaired -- the winner repaired a DIFFERENT one -- so dropping the evidence makes the
    still-poisoned tier earn a whole fresh threshold-sized batch before it is even reconsidered,
    which is the cost this fast path exists to avoid."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    # a repair just completed (the winner), so the loser hits the serialized skip
    pool._last_base_rebuild_at = pool._clock()
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 0, "the cooldown must suppress the second repair"
    kept = len(pool._pool_pre_guest_failures.get("tierB", set()))
    assert kept >= 3, (
        f"the loser must keep the evidence that justified its decision (kept {kept})"
    )


def test_a_cooldown_from_THIS_base_still_discards_its_evidence():
    """The original reasoning, unchanged where it holds: if this very base was just rebuilt and is
    still failing, the cause is not the base, and hammering it again helps nobody."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierB"}  # ...and it was THIS one
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 0
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "a base that a rebuild did not fix must not keep accumulating toward another"
    )


def test_a_real_rebuild_records_which_base_it_repaired():
    """End-to-end rather than hand-set: an actual repair must record its target, or the cooldown
    cannot tell "this base was just rebuilt and still fails" (drop the evidence) from "a DIFFERENT
    base was rebuilt" (keep it)."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)

    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 1, "the first crossing must actually repair"
    assert pool._last_base_rebuild_idents == {"tierB"}, (
        "the repair must record its target"
    )

    # ...and now the SAME base keeps failing inside the cooldown: evidence must be discarded,
    # which only works if the identity above was recorded.
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 1, "the cooldown must suppress the second repair"
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "a base a rebuild did not fix must not keep accumulating toward another"
    )


def test_the_repaired_identity_comes_from_what_was_actually_repaired():
    """Recorded before the lock, a second thread crossing concurrently overwrote it while the
    first held the lock: the first repaired A and started the cooldown, but the record said B --
    so B's next failure took the "just rebuilt and still failing" branch and discarded evidence
    for a tier nothing had touched."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)

    # drop() reports repairing a DIFFERENT tier than the one that crossed
    def _drop(*, reason=None, only=None):
        rt.base_invalidations += 1
        return ["tierA"]

    rt.invalidate_base = _drop

    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 1
    assert "tierB" not in pool._last_base_rebuild_idents, (
        "tierB was never repaired, so the cooldown must not treat it as just-rebuilt"
    )


def test_an_ordinary_repair_also_names_its_tier():
    """`only` was supplied for the pre-guest fast path alone. An ordinary streak is per-identity
    too, and a cascade whose _job_guilty was cleared by an unrelated success on tier A would fall
    back to rebuilding EVERY tier -- destroying A's base because B failed."""
    rt = _TieredWedge()
    # ordinary threshold is small here so plain worker faults cross it
    pool = _pool(rt, pre_guest_rebuild_after=0, snapshot_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage=None)  # ordinary worker faults, no pre-guest evidence
    assert rt.invalidated == ["tierB"], (
        f"an ordinary repair must name the tier that crossed, got {rt.invalidated}"
    )


def test_every_tier_a_repair_committed_is_recorded():
    """One invalidation can repair several tiers. Recording only the trigger left the others'
    streaks in place, so a later failure read them as unrepaired, restored evidence predating
    their rebuild, and invalidated a tier that had just been rebuilt."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)

    def _drop(*, reason=None, only=None):
        rt.base_invalidations += 1
        return ["tierA", "tierB"]  # the repair covered BOTH

    rt.invalidate_base = _drop

    a, b, c, sib1, sib2 = _claim_distinct(pool, 5)
    # tierA accumulates a real ordinary streak of its own...
    rt._ident[sib1.slot_id] = "tierA"
    rt._ident[sib2.slot_id] = "tierA"
    _fail(pool, sib1, stage=None)
    _fail(pool, sib2, stage=None)
    assert pool._pool_consecutive_failures.get("tierA") == 2, (
        "precondition: tierA has a streak"
    )

    # ...and tierB's crossing triggers a repair that covers BOTH tiers.
    for slot in (a, b, c):
        _fail(pool, slot, stage="pre_guest")
    assert pool._last_base_rebuild_idents == {"tierA", "tierB"}
    assert not pool._pool_consecutive_failures.get("tierA"), (
        "tierA was rebuilt by this repair, so its pre-rebuild streak must not survive it"
    )


def test_a_retired_generations_success_does_not_bump_the_per_base_token():
    """The per-base token arbitrates whether a decision went stale. A long-running slot from an
    already-retired generation succeeding late still bumped it, which marks the CURRENT base's
    decision stale and abandons its repair -- after the evidence justifying it was consumed.

    Asserted on the token itself: the staleness window (a success landing between a decision's
    capture and its check) is not drivable from a test, and an end-to-end version passed for an
    unrelated reason.
    """
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    current, stale = _claim_distinct(pool, 2)

    pool.release(current, dirty=False)
    assert pool._clean_release_by_base.get("tierB") == 1, (
        "a current-generation success counts"
    )

    ident, gen = pool._slot_base.get(stale.slot_id, ("tierB", 0))
    pool._slot_base[stale.slot_id] = (ident, gen - 1)  # retired generation
    pool.release(stale, dirty=False)
    assert pool._clean_release_by_base.get("tierB") == 1, (
        "a success from a base that has already been replaced says nothing about the current one"
    )


def test_the_loser_discards_evidence_when_the_winner_repaired_THIS_base():
    """Two crossings for the SAME base race: six assigned slots can fail while a slow
    invalidation runs. The loser's evidence is then all from the generation just replaced, and
    restoring it into the fresh base lets one later failure rebuild something never given a
    chance to work.

    The winner is simulated by a lock that completes the repair as the loser acquires it -- which
    is exactly the window, and the only way to reach the serialized skip rather than the outer
    cooldown check.
    """
    import threading

    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)

    real = pool._invalidation_lock

    class _WinnerFinishesFirst:
        def __enter__(self):
            real.acquire()
            pool._last_base_rebuild_at = pool._clock()  # the winner just committed...
            pool._last_base_rebuild_idents = {"tierB"}  # ...on THIS base
            return self

        def __exit__(self, *exc):
            real.release()
            return False

    pool._invalidation_lock = _WinnerFinishesFirst()
    _ = threading
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 0, "the winner's cooldown must suppress the loser"
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "evidence from the generation the winner replaced must not survive into the new one"
    )


def test_a_partial_repair_clears_the_evidence_of_the_tiers_it_did_replace():
    """A spawn-driven cascade invalidation can repair tier A and fail tier B. The exception path
    advances A's generation -- so A HAS been replaced -- but the success-path cleanup never runs,
    leaving below-threshold evidence against the old artifact to convict the new one."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)

    class _PartialFail(Exception):
        repaired = ["tierA"]

    def _drop(*, reason=None, only=None):
        raise _PartialFail("tierB could not be dropped")

    rt.invalidate_base = _drop

    sib, a, b, c = _claim_distinct(pool, 4)
    rt._ident[sib.slot_id] = "tierA"
    _fail(pool, sib, stage="pre_guest")  # evidence against the OLD tierA
    assert pool._pool_pre_guest_failures.get("tierA")
    for slot in (a, b, c):
        _fail(
            pool, slot, stage="pre_guest"
        )  # tierB crosses; the repair partially fails
    assert not pool._pool_pre_guest_failures.get("tierA"), (
        "tierA's generation advanced, so evidence against its retired artifact must go with it"
    )


def test_a_crossed_pre_guest_episode_outranks_an_ordinary_streak():
    """A tier whose slots are PROVEN unable to execute must not wait behind one that merely
    accumulated failures.

    tierA's streak has to still be AT the ordinary threshold when tierB crosses -- otherwise the
    selection never has to choose and the test passes for the wrong reason. So tierA's repair
    FAILS, which restores its streak, exactly the case the review named ("its previous
    invalidation failed"). tierB's own ordinary streak stays far below the threshold, so the
    pre-guest path is the only way it can ever be repaired.
    """
    rt = _TieredWedge()
    pool = _pool(
        rt,
        pre_guest_rebuild_after=3,
        snapshot_rebuild_after=10,
        base_rebuild_cooldown_s=0,
    )

    def _drop(*, reason=None, only=None):
        if only == "tierA":
            raise OSError("tierA could not be dropped")  # streak is restored
        rt.invalidated.append(only)
        rt.base_invalidations += 1
        return [only]

    rt.invalidate_base = _drop

    slots = _claim_distinct(pool, 13)
    for s_ in slots[:10]:
        rt._ident[s_.slot_id] = "tierA"
        _fail(pool, s_, stage=None)
    assert pool._pool_consecutive_failures.get("tierA", 0) >= 10, (
        "precondition: tierA's streak survived its failed repair"
    )

    for s_ in slots[10:]:
        _fail(pool, s_, stage="pre_guest")
    assert "tierB" in rt.invalidated, (
        f"the proven-poisoned tier must be selected over a mere streak, got {rt.invalidated}"
    )


def test_a_success_during_the_lock_wait_discards_the_losing_episode():
    """A slot from THIS base completing while we waited behind another tier's invalidation is
    conclusive. Restoring the pre-recovery evidence would let a later failure invalidate a base
    that has since demonstrated it works."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    real = pool._invalidation_lock

    class _WinnerRepairsAnotherTier:
        def __enter__(self):
            real.acquire()
            pool._last_base_rebuild_at = pool._clock()
            pool._last_base_rebuild_idents = {"tierA"}  # a DIFFERENT tier
            # ...and meanwhile a tierB slot completed cleanly
            pool._clean_release_by_base["tierB"] = (
                pool._clean_release_by_base.get("tierB", 0) + 1
            )
            return self

        def __exit__(self, *exc):
            real.release()
            return False

    pool._invalidation_lock = _WinnerRepairsAnotherTier()
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 0
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "a base that succeeded during the wait must not keep its pre-recovery evidence"
    )


def test_a_spawn_episode_uses_the_pool_wide_success_token():
    """Spawn episodes are unattributed (episode_ident == ""), and a cascade records clean
    releases under a TIER name -- never under "" -- so a per-base token could never move for
    them and the stale-decision guard was dead on that path."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    pool._clean_release_count = 7
    # an unattributed episode compares against the pool-wide counter...
    assert pool._base_succeeded_since("", 7) is False
    assert pool._base_succeeded_since("", 6) is True
    # ...while an attributed one uses its own ledger
    pool._clean_release_by_base["tierB"] = 2
    assert pool._base_succeeded_since("tierB", 2) is False
    assert pool._base_succeeded_since("tierB", 1) is True


def test_the_success_check_does_not_deadlock_when_called_under_no_lock():
    """_base_succeeded_since takes self._lock, which is a plain Lock, not an RLock. Calling it
    from inside an existing `with self._lock:` hung the dispatcher outright -- caught only
    because the suite stopped finishing."""
    import threading

    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    done = threading.Event()

    def _run():
        pool._base_succeeded_since("tierB", 0)
        done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert done.wait(2.0), "the success check deadlocked"


def test_a_success_during_the_cooldown_discards_the_episode_too():
    """The lock-wait branch got this recheck; the COOLDOWN branch did not. A slot from this base
    completing between the decision and the restore is conclusive either way -- restoring failures
    from before it lets one later failure rebuild a base that has since proved healthy.

    Driven through the success predicate rather than by racing a real release: the window is
    between the episode being consumed and the restore, and a release BEFORE that clears the
    evidence outright, so the crossing never happens and the branch is never reached.

    Stubbed at _succeeded_since_locked, which is where the decision is actually taken: the check
    and the restore now share ONE lock acquisition, so there is no longer a moment between them
    at which a caller could consult the public predicate. Asserted on the EVIDENCE rather than on
    whether the restore was called, because "called and declined" is now the correct behaviour.
    """
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierA"}  # a DIFFERENT tier is cooling
    pool._succeeded_since_locked = lambda ident, token, scope=(): ident == "tierB"

    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")

    assert rt.base_invalidations == 0, "the cooldown must suppress the repair"
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "a base that succeeded since the decision must not have its evidence restored"
    )
    assert not pool._pool_consecutive_failures.get("tierB"), (
        "...nor its ordinary streak"
    )


def test_a_base_that_did_NOT_succeed_still_gets_its_evidence_back():
    """The other half: without an intervening success the episode must still be handed back, or a
    tier cooling behind another one loses a whole threshold of evidence for nothing."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierA"}
    pool._base_succeeded_since = lambda ident, token, scope=(): False

    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")

    assert rt.base_invalidations == 0
    assert len(pool._pool_pre_guest_failures.get("tierB", set())) >= 3, (
        "no success means the evidence is still valid and must be handed back"
    )


class _ScopedWedge(_TieredWedge):
    """A cascade that can say which tiers a SPAWN repair would target -- as the real one can."""

    def __init__(self, guilty=("tierB",)):
        super().__init__()
        self.guilty = list(guilty)

    def spawn_guilty_identities(self):
        return list(self.guilty)


def _release_during_the_decision(pool, ident):
    """Land a clean release on `ident` strictly between the token capture and the staleness check.

    _maybe_rebuild_base captures the token, then calls self._clock() once, then judges staleness --
    so the clock is the one seam that sits inside that window.
    """
    real, fired = pool._clock, []

    def _clock():
        if not fired:
            fired.append(1)
            with pool._lock:
                pool._clean_release_count += 1
                pool._clean_release_by_base[ident] = (
                    pool._clean_release_by_base.get(ident, 0) + 1
                )
        return real()

    pool._clock = _clock
    return fired


def test_a_sibling_tiers_success_does_not_cancel_the_guilty_tiers_spawn_repair():
    """The spawn streak is ONE pool-wide integer, but the repair it triggers is narrowed by the
    cascade to the guilty tiers. Judging it against the pool-wide clean-release counter therefore
    asked the wrong question: a healthy sibling absorbing the load -- which is exactly what a
    cascade does when a tier is poisoned -- looked like the guilty tier recovering, and cancelled
    its repair."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)
    fired = _release_during_the_decision(pool, "tierA")  # a DIFFERENT tier succeeds

    assert pool._maybe_rebuild_base(5, reason="spawn") is True, (
        "tierA's success cancelled tierB's repair; tierB produced no successful slot at all"
    )
    assert fired, "the injected sibling release never landed — the test proves nothing"
    assert rt.base_invalidations == 1


def test_the_guilty_tiers_own_success_still_cancels_its_spawn_repair():
    """Fail-closed control: the guard must keep working for the tier it is actually about."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)
    fired = _release_during_the_decision(pool, "tierB")  # the GUILTY tier succeeds

    assert pool._maybe_rebuild_base(5, reason="spawn") is False, (
        "a base that produced a valid result while being judged must not be rebuilt"
    )
    assert fired
    assert rt.base_invalidations == 0


def test_a_runtime_without_the_seam_keeps_the_pool_wide_token():
    """One base means pool-wide IS the right scope; a runtime that cannot attribute must not
    silently lose the guard that the pool-wide counter provides."""
    rt = _TieredWedge()  # no spawn_guilty_identities
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)
    assert pool._spawn_success_scope() == ()
    fired = _release_during_the_decision(pool, "tierA")

    assert pool._maybe_rebuild_base(5, reason="spawn") is False, (
        "with no attribution the pool-wide counter is all there is, and it moved"
    )
    assert fired


def test_a_broken_attribution_seam_does_not_stop_a_repair_decision():
    """The seam is an optimisation. A runtime that raises must degrade to pool-wide, not crash
    the maintenance tick that is trying to repair a wedged tier."""

    class _Broken(_TieredWedge):
        def spawn_guilty_identities(self):
            raise RuntimeError("cascade lock timed out")

    pool = _pool(_Broken(), snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)
    assert pool._spawn_success_scope() == ()
    assert pool._maybe_rebuild_base(5, reason="spawn") is True


def test_a_recovery_during_the_lock_wait_is_caught_even_when_the_winner_failed():
    """The staleness verdict is taken BEFORE queueing on _invalidation_lock, and only the cooldown
    branch re-examines it -- but that branch is driven by _last_base_rebuild_at, which a holder
    whose repair FAILED never sets. So a base that completed a job while we queued was rebuilt
    anyway, with nothing on the path left to notice."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=300.0)
    real = pool._invalidation_lock

    class _HolderFailedButThisBaseRecovered:
        def __enter__(self):
            real.acquire()
            # The holder's repair raised: no _last_base_rebuild_at, no _last_base_rebuild_idents.
            # Meanwhile a current-generation tierB slot completed cleanly.
            pool._clean_release_by_base["tierB"] = (
                pool._clean_release_by_base.get("tierB", 0) + 1
            )
            return self

        def __exit__(self, *exc):
            real.release()
            return False

    pool._invalidation_lock = _HolderFailedButThisBaseRecovered()
    assert pool._last_base_rebuild_at is None, "precondition: no repair has committed"
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")

    assert rt.base_invalidations == 0, (
        "tierB produced a valid result while this decision queued; rebuilding it now is an "
        "outage taken against a base that just proved it works"
    )


def test_a_failed_repair_does_not_restore_evidence_the_base_has_since_disproved():
    """The consumed pre-guest set is threshold-crossed by construction, so restoring it re-arms
    the fast path at once: one later worker fault then rebuilds a base that has since executed a
    job end to end."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3, base_rebuild_cooldown_s=0)

    def _drop(*, reason=None, only=None):
        # A slow repair that ultimately fails -- and while it ran, a tierB slot completed.
        pool._clean_release_by_base["tierB"] = (
            pool._clean_release_by_base.get("tierB", 0) + 1
        )
        raise OSError("tierB could not be dropped")

    rt.invalidate_base = _drop
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")

    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "pre-recovery pre-guest evidence was handed back to a base that has since produced a "
        "valid result"
    )


def test_a_sibling_tiers_cooldown_does_not_discard_this_tiers_spawn_streak():
    """The cooldown is global but the justification for discarding is about ONE base: 'if the base
    were the problem, the previous rebuild would have fixed it'. Tier B crossing while tier A's
    repair cools had its evidence thrown away on the strength of a repair that never touched it."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierA"}  # a DIFFERENT tier was repaired
    pool._spawn_consecutive_failures = 5

    assert pool._maybe_rebuild_base(5, reason="spawn") is False  # cooling, correctly
    assert pool._spawn_consecutive_failures == 5, (
        "tierB's spawn evidence was discarded because tierA had just been repaired; tierB must "
        "not sacrifice another threshold-sized batch of spawns for that"
    )


def test_a_cooldown_from_this_tiers_own_repair_still_discards_the_streak():
    """Control: the original reasoning holds when the repair DID touch this tier."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierB"}  # THIS tier was just repaired
    pool._spawn_consecutive_failures = 5

    assert pool._maybe_rebuild_base(5, reason="spawn") is False
    assert pool._spawn_consecutive_failures == 0, (
        "this tier was just rebuilt and still fails, so the cause is elsewhere -- drop it"
    )


def test_an_unattributed_spawn_cooldown_still_discards_the_streak():
    """No attribution -> the old pool-wide behaviour, unchanged."""
    rt = _TieredWedge()  # no spawn_guilty_identities seam
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=300.0)
    pool._last_base_rebuild_at = pool._clock()
    pool._last_base_rebuild_idents = {"tierA"}
    pool._spawn_consecutive_failures = 5

    assert pool._maybe_rebuild_base(5, reason="spawn") is False
    assert pool._spawn_consecutive_failures == 0


def test_a_spawn_repair_hands_the_cascade_the_scope_it_judged():
    """The pool judges a spawn repair against success_scope, so the repair must ACT on that same
    set. Leaving the cascade to recompute its targets at drop() time let a tier that became guilty
    after the decision be swept into a repair that never weighed it -- and, being absent from
    success_scope, its clean release could not be seen by the staleness checks either."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)

    assert pool._maybe_rebuild_base(5, reason="spawn") is True
    assert rt.invalidated == [("tierB",)], (
        f"the repair must be handed the judged scope, got {rt.invalidated}"
    )


def test_an_unattributed_spawn_repair_still_names_no_target():
    """No scope -> nothing to freeze, and the cascade's own fallback is correct. Passing only=()
    would match no tier and silently repair nothing."""
    rt = _TieredWedge()  # no spawn_guilty_identities seam
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)

    assert pool._maybe_rebuild_base(5, reason="spawn") is True
    assert rt.invalidated == [None], (
        f"an unattributed spawn repair must leave targeting to the cascade, got {rt.invalidated}"
    )


def test_the_recovery_check_lives_inside_the_restore():
    """A guard in a different critical section from the thing it guards is not a guard.

    Callers used to ask _base_succeeded_since (one lock acquisition) and then restore (another). A
    clean release landing between the two cleared the live evidence and advanced the token, and
    the restore resurrected the pre-recovery failures anyway -- so one later fault could rebuild a
    base that had just proved it works. Pinned by making the PUBLIC predicate lie: if the decision
    still consulted it, the stale 'not recovered' verdict would get the evidence restored."""
    pool = _pool(_TieredWedge(), pre_guest_rebuild_after=3)
    pool._base_succeeded_since = lambda *a, **k: False  # the stale pre-lock verdict
    pool._clean_release_by_base["tierB"] = 9  # ...but tierB has since recovered

    assert (
        pool._restore_episode("tierB", 3, frozenset({"x"}), "job", token=8) is False
    ), "the restore trusted a verdict taken in an earlier critical section"
    assert not pool._pool_pre_guest_failures.get("tierB")
    assert not pool._pool_consecutive_failures.get("tierB")


def test_the_restore_still_hands_evidence_back_when_nothing_recovered():
    """Control: the guard must not swallow the restore it is protecting."""
    pool = _pool(_TieredWedge(), pre_guest_rebuild_after=3)
    pool._clean_release_by_base["tierB"] = 8

    assert pool._restore_episode("tierB", 3, frozenset({"x"}), "job", token=8) is True
    assert pool._pool_pre_guest_failures.get("tierB") == {"x"}
    assert pool._pool_consecutive_failures.get("tierB") == 3


def test_a_spawn_episode_is_still_retained_by_its_own_caller():
    pool = _pool(_TieredWedge(), pre_guest_rebuild_after=3)
    assert pool._restore_episode("", 3, frozenset({"x"}), "spawn", token=0) is False
    assert not pool._pool_consecutive_failures.get("")


def test_a_release_during_the_runtime_query_is_not_swallowed_by_the_token():
    """_spawn_success_scope() calls out to the cascade, which takes its own lock and can block.
    Sampling the token AFTER that call folded any clean release landing during it into the token
    itself: every later staleness check then compares equal, and the frozen tier is invalidated
    despite having proved itself healthy inside the decision window -- with the successful worker
    already released, so nothing downstream can see it either."""
    rt = _ScopedWedge(guilty=("tierB",))
    pool = _pool(rt, snapshot_rebuild_after=2, base_rebuild_cooldown_s=0)

    # tierB completes a job WHILE the pool is asking the cascade which tiers to target.
    def _guilty_and_meanwhile_a_success():
        with pool._lock:
            pool._clean_release_by_base["tierB"] = (
                pool._clean_release_by_base.get("tierB", 0) + 1
            )
        return ["tierB"]

    rt.spawn_guilty_identities = _guilty_and_meanwhile_a_success

    assert pool._maybe_rebuild_base(5, reason="spawn") is False, (
        "tierB produced a valid result inside the decision window; the token must have been "
        "captured before the query, so that release is still visible as a change"
    )
    assert rt.base_invalidations == 0


def test_a_retired_generation_success_does_not_move_the_pool_wide_token():
    """_clean_release_by_base was generation-guarded; _clean_release_count was not -- and the
    pool-wide counter IS the fallback token for a single-base runtime and for an unattributed
    spawn episode. An old assigned slot finishing late therefore cancelled the repair of a
    replacement base that had produced no usable worker at all."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    slot = _claim_distinct(pool, 1)[0]

    # Stamp the slot to a RETIRED generation of its base, then let it succeed.
    with pool._lock:
        pool._slot_base[slot.slot_id] = ("tierB", 0)
        pool._base_generation["tierB"] = 1  # the base has since been rebuilt
        before = pool._clean_release_count

    pool.release(slot, dirty=False)

    assert pool._clean_release_count == before, (
        "a slot from a retired generation moved the pool-wide recovery token"
    )


def test_a_current_generation_success_still_moves_the_pool_wide_token():
    """Control: the guard must not deafen the counter to real recoveries."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    slot = _claim_distinct(pool, 1)[0]
    with pool._lock:
        pool._slot_base[slot.slot_id] = ("tierB", 1)
        pool._base_generation["tierB"] = 1  # SAME generation
        before = pool._clean_release_count

    pool.release(slot, dirty=False)

    assert pool._clean_release_count == before + 1
