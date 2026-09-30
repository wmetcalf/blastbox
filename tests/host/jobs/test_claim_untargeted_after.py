"""`claim_next(untargeted_min_age_s=...)`: a claimant may decline UNTARGETED jobs until they age.

WHY. One engine runs a warm Firecracker dispatcher and a cold dispatcher against one store. An
untargeted job (``target_tier`` NULL, the default) is claimable by every tier, so whichever
dispatcher polls first wins -- measured on a production host, the cold dispatcher took 2-8 of 16
untargeted jobs while warm slots sat free. Setting a small delay on the COLD dispatcher lets a warm
dispatcher with a free slot take the job first; anything still unclaimed after the delay is fair
game for the cold one (overflow / break-glass).

The delay applies ONLY to untargeted jobs: a job pinned to the claimant's own tier is claimed at
once, and one pinned to another tier stays unclaimable exactly as before. It composes with
``claimable_after`` (both must hold) and with ``engine=`` scoping.

Age is measured the same way every store already measures ``claimable_after``: stored epoch
seconds (``created_at``) against the claimant's ``time.time()``. Never host-monotonic time.
"""
from __future__ import annotations

import math
import time
import uuid

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

DELAY = 30.0


def _stores(tmp_path):
    import os

    from blastbox.host.jobs.sql_store import SqlJobStore

    yield "memory", InMemoryJobStore()
    yield "sqlite", SqlJobStore(f"sqlite:///{tmp_path / 'q.db'}")
    # Postgres is the store the production fleet shares, and its claim is a separate CTE with its
    # own bind order -- it gets its own case rather than being assumed from sqlite.
    dsn = os.environ.get("BLASTBOX_TEST_PG_DSN")
    if dsn:
        yield "postgres", SqlJobStore(dsn)
    try:
        import fakeredis

        from blastbox.host.jobs.redis_store import RedisJobStore

        yield "redis", RedisJobStore(client=fakeredis.FakeRedis())
    except Exception:                       # noqa: BLE001 - redis backend optional here
        pass


_CREATED: "list[tuple[object, str]]" = []


@pytest.fixture(params=["memory", "sqlite", "redis", "postgres"])
def store(request, tmp_path):
    """Cleans up what it created: the postgres case runs against a SHARED database."""
    for name, s in _stores(tmp_path):
        if name == request.param:
            yield s
            while _CREATED:
                st, jid = _CREATED.pop()
                try:
                    st.delete(jid)
                except Exception:           # noqa: BLE001 - best-effort teardown
                    pass
            return
    pytest.skip(f"{request.param} backend unavailable (postgres needs BLASTBOX_TEST_PG_DSN)")


@pytest.fixture
def engine():
    """An engine name unique to the test, so on a shared postgres claim_next sees only our rows."""
    return f"eng-{uuid.uuid4().hex[:10]}"


def _put(store, engine, *, age_s: float, target_tier: str | None = None,
         claimable_after: float | None = None, name: str = "") -> str:
    jid = f"{name or 'job'}-{uuid.uuid4().hex[:10]}"
    store.create(Job(job_id=jid, engine=engine, filename=f"{name or 'f'}.bin",
                     status=JobStatus.QUEUED, created_at=time.time() - age_s,
                     target_tier=target_tier, claimable_after=claimable_after))
    _CREATED.append((store, jid))
    return jid


def test_young_untargeted_job_is_not_claimed_by_a_delayed_claimant(store, engine):
    jid = _put(store, engine, age_s=1.0)
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=DELAY) is None
    assert store.get(jid).status == JobStatus.QUEUED          # left for the warm dispatcher


def test_untargeted_job_is_claimed_once_old_enough(store, engine):
    jid = _put(store, engine, age_s=DELAY + 5)
    got = store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=DELAY)
    assert got is not None and got.job_id == jid and got.status == JobStatus.RUNNING


def test_the_same_job_becomes_claimable_as_it_ages(store, engine):
    # Short real delay so the transition is exercised in the store's own clock, not a fixture.
    jid = _put(store, engine, age_s=0.0)
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=0.4) is None
    time.sleep(0.5)
    got = store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=0.4)
    assert got is not None and got.job_id == jid


def test_a_warm_claimant_without_the_delay_takes_the_young_job(store, engine):
    jid = _put(store, engine, age_s=0.0)
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=DELAY) is None
    got = store.claim_next(claimant_tier="firecracker", engine=engine)
    assert got is not None and got.job_id == jid


def test_job_targeted_at_my_tier_is_claimed_immediately_despite_the_delay(store, engine):
    jid = _put(store, engine, age_s=0.0, target_tier="cold")
    got = store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=DELAY)
    assert got is not None and got.job_id == jid


def test_young_untargeted_job_does_not_block_a_job_targeted_at_me_behind_it(store, engine):
    _put(store, engine, age_s=2.0, name="untargeted")                    # older, but too young
    mine = _put(store, engine, age_s=1.0, target_tier="cold", name="mine")
    got = store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=DELAY)
    assert got is not None and got.job_id == mine


def test_job_targeted_at_another_tier_stays_unclaimable(store, engine):
    jid = _put(store, engine, age_s=DELAY + 60, target_tier="firecracker")
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=DELAY) is None
    assert store.get(jid).status == JobStatus.QUEUED


@pytest.mark.parametrize("kwargs", [{}, {"untargeted_min_age_s": 0.0}, {"untargeted_min_age_s": 0}])
def test_zero_or_absent_delay_is_the_old_behaviour(store, engine, kwargs):
    jid = _put(store, engine, age_s=0.0)
    got = store.claim_next(claimant_tier="cold", engine=engine, **kwargs)
    assert got is not None and got.job_id == jid


def test_claimable_after_is_still_respected(store, engine):
    # Old enough for the delay, but DEFERRED: both conditions must hold.
    jid = _put(store, engine, age_s=DELAY + 60, claimable_after=time.time() + 100.0)
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=DELAY) is None
    assert store.get(jid).status == JobStatus.QUEUED


def test_old_enough_and_past_claimable_after_is_claimed(store, engine):
    jid = _put(store, engine, age_s=DELAY + 60, claimable_after=time.time() - 1.0)
    got = store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=DELAY)
    assert got is not None and got.job_id == jid


def test_engine_scoping_still_applies(store, engine):
    other = f"{engine}-other"
    jid = _put(store, other, age_s=DELAY + 60)
    assert store.claim_next(claimant_tier="cold", engine=engine,
                            untargeted_min_age_s=DELAY) is None
    assert store.get(jid).status == JobStatus.QUEUED


def test_untiered_claimant_is_delayed_too(store, engine):
    # claimant_tier=None only ever takes untargeted jobs, so the delay governs all of them.
    jid = _put(store, engine, age_s=1.0)
    assert store.claim_next(engine=engine, untargeted_min_age_s=DELAY) is None
    got = store.claim_next(engine=engine)
    assert got is not None and got.job_id == jid


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0])
def test_nonsense_delay_is_refused_loudly(store, engine, bad):
    # nan compares false against every age -- it would silently stop this claimant from ever
    # taking an untargeted job. inf does the same on purpose-looking terms. Refuse both.
    _put(store, engine, age_s=DELAY + 60)
    with pytest.raises(ValueError, match="untargeted_min_age_s"):
        store.claim_next(claimant_tier="cold", engine=engine, untargeted_min_age_s=bad)
