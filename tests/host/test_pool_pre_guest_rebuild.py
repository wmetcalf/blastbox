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
        return Slot(slot_id=sid, control_dir=Path(f"/fake/c/{sid}"),
                    input_dir=Path(f"/fake/i/{sid}"), output_dir=Path(f"/fake/o/{sid}"),
                    state=SlotState.WARMING, spawned_at=0.0)

    def is_ready(self, slot): return True
    def is_alive(self, slot): return True
    def recycle(self, slot): return None
    def reap(self, slot): return None

    def invalidate_base(self) -> None:
        with self._lock:
            self.base_invalidations += 1


def _pool(rt, **kw):
    """PROD-LIKE sizing on purpose. warm_size=24 puts the ordinary threshold at 2 x 24 = 48, far
    above the pre-guest bar, so a test that trips can only have tripped the fast path. At
    warm_size=2 the ordinary threshold is 4 and the two are indistinguishable -- which is exactly
    how the first version of this test passed for the wrong reason."""
    return WarmPool(runtime=rt, warm_size=24, concurrent_ceiling=32, spawn_rate_limit=1000.0, **kw)


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
        "must have tripped the pre-guest path, not the ordinary threshold")


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
        "one slot must contribute at most one piece of evidence")
    assert rt.base_invalidations == 0


def test_failures_inside_the_guest_still_need_the_full_threshold():
    """A run of malformed samples must not destroy a healthy base. That ambiguity is why the
    ordinary threshold is 2 x warm_size, and this fix must not lower it."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 6):
        _fail(pool, slot, stage=None)      # failed IN the guest: could be the document
    assert rt.base_invalidations == 0


def test_a_served_job_clears_the_pre_guest_evidence():
    """One success proves the base CAN execute, which is what the evidence claims it cannot."""
    rt = _Wedged()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    a, b, c, d = _claim_distinct(pool, 4)
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    pool.release(c, dirty=False)                    # a clean, served job
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
    assert release_kwargs(old_release, dirty=True, fault="worker", fault_stage="pre_guest") == {
        "dirty": True, "fault": "worker"}
    assert release_kwargs(new_release, dirty=True, fault="worker", fault_stage="pre_guest") == {
        "dirty": True, "fault": "worker", "fault_stage": "pre_guest"}


# --- the dispatch-side half: deciding WHEN a failure is pre-guest ----------------------------
def test_warm_fault_stage_reports_pre_guest_only_when_the_guest_never_ran():
    """The pool half is useless if the dispatcher never reports the stage. This is the exact
    production shape: signal_go succeeded, wait_for_done timed out, `guest` was never marked."""
    from blastbox.host.dispatch import _PhaseTimer, warm_fault_stage

    class _Ctl:
        guest_started = False                 # the guest PROVED it never started

    wedged = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go"):
        wedged.mark(ph)                       # ...then wait_for_done times out; no `guest`
    assert warm_fault_stage(False, "worker", wedged, _Ctl()) == "pre_guest"

    ran = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go", "guest"):
        ran.mark(ph)
    assert warm_fault_stage(False, "worker", ran, _Ctl()) is None, (
        "a failure AFTER the guest executed could be the document")

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
    pool = WarmPool(runtime=_Wedged(), warm_size=24, concurrent_ceiling=32,
                    spawn_rate_limit=1000.0)
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
    assert total == 0, f"evidence accumulated with repair disabled: {total} slot ids retained"


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
        f"a failed repair must not discard the evidence that justified it (kept {retained})")


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
        "a success from a retired base must not clear the current base's evidence")


def test_the_stage_is_only_reported_when_the_guest_PROVED_it_never_started():
    """The pool half is only sound if the dispatcher refuses to guess. Full matrix in
    tests/host/runtime/test_warm_start_ack.py; this pins the decision itself."""
    from blastbox.host.dispatch import _PhaseTimer, warm_fault_stage

    class _Ctl:
        def __init__(self, started): self.guest_started = started

    wedged = _PhaseTimer("j")
    for ph in ("slot_claim", "fetch", "stage", "go"):
        wedged.mark(ph)                      # ...then a timeout; `guest` never marked

    assert warm_fault_stage(False, "worker", wedged, _Ctl(False)) == "pre_guest"
    assert warm_fault_stage(False, "worker", wedged, _Ctl(True)) is None, \
        "it acked, so it ran -- the document is the suspect, not the base"
    assert warm_fault_stage(False, "worker", wedged, _Ctl(None)) is None, \
        "UNKNOWN (older worker image) must never convict"
    assert warm_fault_stage(False, "worker", wedged, None) is None, \
        "a seam with no ack at all must never convict"


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
    assert rt.invalidated == ["tierB"], f"expected only the convicted tier, got {rt.invalidated}"


def test_a_success_on_another_base_does_not_abandon_this_ones_repair():
    """The stale-decision token was pool-wide, so a job completing on healthy tier A while tier
    B's repair was being judged abandoned B's decision -- about a base that produced nothing of
    the kind -- and B then had to sacrifice three more distinct jobs."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    a, b, c, other = _claim_distinct(pool, 4)
    rt._ident[other.slot_id] = "tierA"          # a DIFFERENT base
    _fail(pool, a, stage="pre_guest")
    _fail(pool, b, stage="pre_guest")
    pool.release(other, dirty=False)            # healthy tier A serves a job
    _fail(pool, c, stage="pre_guest")
    assert rt.base_invalidations >= 1, (
        "a success on another base must not abandon this base's repair")


def test_a_committed_generation_does_not_inherit_retired_evidence():
    """Releases landing WHILE drop() ran rebuilt a set after the episode consumed the old one,
    charging the retired base's failures to its replacement."""
    rt = _TieredWedge()
    pool = _pool(rt, pre_guest_rebuild_after=3)
    for slot in _claim_distinct(pool, 3):
        _fail(pool, slot, stage="pre_guest")
    assert rt.base_invalidations == 1
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "the freshly installed generation must start with no inherited evidence")


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
    _fail(pool, c, stage="pre_guest")          # crosses -> drop() runs, stragglers land inside
    assert rt.base_invalidations == 1
    assert not pool._pool_pre_guest_failures.get("tierB"), (
        "the committed generation inherited the retired base's stragglers: "
        f"{pool._pool_pre_guest_failures}")
