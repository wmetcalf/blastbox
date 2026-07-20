"""Per-tier claim routing (target_tier) across the in-memory + SQLite stores.

A job with target_tier set is claimable ONLY by a dispatcher whose tier matches; an
untargeted job (the default) by anyone. This is the store-level mechanism behind
operator/test tier routing — the API gate (BLASTBOX_ALLOW_TIER_ROUTING) controls whether
target_tier can be SET at submit; here we verify it's HONORED at claim, the same way on
both backends, and stays a no-op for ordinary (untargeted) jobs.
"""
from __future__ import annotations

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


@pytest.fixture(params=["memory", "sqlite", "redis"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryJobStore()
    if request.param == "redis":
        import fakeredis

        from blastbox.host.jobs.redis_store import RedisJobStore
        return RedisJobStore(fakeredis.FakeRedis(), ttl_seconds=3600)
    return SqlJobStore(f"sqlite:///{tmp_path / 'jobs.db'}")


def _queued(filename: str = "f.docx", target_tier: str | None = None) -> Job:
    j = Job.new(engine="test", filename=filename)
    j.target_tier = target_tier
    return j


def test_untargeted_job_claimable_by_any_tier(store):
    store.create(_queued(target_tier=None))
    claimed = store.claim_next(claimant_tier="gvisor")  # any tier claims an untargeted job
    assert claimed is not None
    assert claimed.status == JobStatus.RUNNING


def test_untargeted_job_claimable_by_untiered_caller(store):
    # Backward compat: a caller that passes no tier still claims ordinary jobs.
    store.create(_queued(target_tier=None))
    assert store.claim_next() is not None


def test_targeted_job_only_claimed_by_matching_tier(store):
    store.create(_queued(target_tier="gvisor"))
    # Non-matching claimants must NOT claim it — it stays queued.
    assert store.claim_next(claimant_tier="firecracker") is None
    assert store.claim_next(claimant_tier="cold") is None
    assert store.claim_next(claimant_tier=None) is None
    # The matching tier does.
    claimed = store.claim_next(claimant_tier="gvisor")
    assert claimed is not None
    assert claimed.target_tier == "gvisor"
    assert claimed.status == JobStatus.RUNNING


def test_targeted_job_does_not_block_an_untargeted_one(store):
    # An fc-targeted job (created first/oldest) must not starve a cold claimant of the
    # untargeted job behind it — the claim skips what it can't take.
    store.create(_queued(filename="targeted.docx", target_tier="firecracker"))
    store.create(_queued(filename="open.docx", target_tier=None))
    claimed = store.claim_next(claimant_tier="cold")
    assert claimed is not None
    assert claimed.filename == "open.docx"


def test_worker_tier_and_target_tier_round_trip(store):
    j = _queued(target_tier="gvisor")
    j.worker_tier = "gvisor"
    store.create(j)
    got = store.get(j.job_id)
    assert got is not None
    assert got.target_tier == "gvisor"
    assert got.worker_tier == "gvisor"


# --- claimable_after (capacity-deferral eligibility) --------------------------------------

def test_deferred_job_not_claimed_until_window_passes(store):
    # PR #60: a job with claimable_after in the FUTURE is temporarily ineligible (a dispatcher
    # deferred it for lack of node-budget headroom), so claim_next skips it — on all backends.
    import time

    j = _queued(filename="deferred.docx")
    j.claimable_after = time.time() + 100.0        # not claimable yet
    store.create(j)
    assert store.claim_next(claimant_tier="cold") is None      # skipped

    # once eligible (claimable_after in the past), it's claimable.
    j2 = _queued(filename="eligible.docx")
    j2.claimable_after = time.time() - 1.0
    store.create(j2)
    claimed = store.claim_next(claimant_tier="cold")
    assert claimed is not None and claimed.filename == "eligible.docx"


def test_deferred_job_does_not_block_claimable_work(store):
    # The whole point: a DEFERRED (capacity-blocked) job that is OLDER must not starve a newer
    # claimable job — claim_next takes the oldest ELIGIBLE job, skipping the deferred one.
    import time

    old_deferred = _queued(filename="old_deferred.docx")
    old_deferred.created_at = 100.0                # oldest
    old_deferred.claimable_after = time.time() + 100.0
    store.create(old_deferred)
    newer = _queued(filename="newer.docx")
    newer.created_at = 200.0
    store.create(newer)

    claimed = store.claim_next(claimant_tier="cold")
    assert claimed is not None and claimed.filename == "newer.docx"   # skipped the older deferred one


def test_claimable_after_round_trips(store):
    j = _queued()
    j.claimable_after = 1234.5
    store.create(j)
    got = store.get(j.job_id)
    assert got is not None and got.claimable_after == 1234.5
