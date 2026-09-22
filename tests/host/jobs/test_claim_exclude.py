"""`claim_next(exclude=...)`: a claimant may name jobs it must not be handed (#178, round seven).

WHY THE STORE HAS TO DO THIS. The control plane remembers which jobs a node has already been
refused, and used to step over them AFTER the store handed them out -- a claim, a prefix stamp
and a release per remembered job, capped at `_MAX_CLAIM_SKIPS`. `claim_next` is strictly
oldest-first, so a wall of refused jobs deeper than the cap was the SAME prefix on every poll:
the walk stopped before reaching anything behind it, forever. Round six lowered the cap to cut
the write cost and made the starvation reachable at 16. Asking the store not to offer them at
all removes both: no churn for a job already judged, and nothing blocks the walk.
"""
from __future__ import annotations

import time
import uuid

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


def _stores(tmp_path):
    import os

    from blastbox.host.jobs.sql_store import SqlJobStore

    yield "memory", InMemoryJobStore()
    yield "sqlite", SqlJobStore(f"sqlite:///{tmp_path / 'q.db'}")
    # POSTGRES IS THE STORE A FEDERATED FLEET ACTUALLY SHARES, and its claim is a separate CTE
    # with its own bind order -- so it gets its own case rather than being assumed from sqlite.
    # CI's pg job sets the DSN; locally it skips unless one is provided.
    dsn = os.environ.get("BLASTBOX_TEST_PG_DSN")
    if dsn:
        yield "postgres", SqlJobStore(dsn)
    try:
        import fakeredis

        from blastbox.host.jobs.redis_store import RedisJobStore

        yield "redis", RedisJobStore(client=fakeredis.FakeRedis())
    except Exception:                       # noqa: BLE001 - redis backend optional here
        pass


def _seed(store, n):
    """n QUEUED jobs under an engine name unique to this test, oldest first; returns their ids.

    Unique engine and ids because on a SHARED postgres other tests' rows are present: claiming
    by a per-test engine means claim_next can only ever see this test's jobs.
    """
    tag = uuid.uuid4().hex[:10]
    engine = f"eng-{tag}"
    now = time.time()
    ids = [f"{tag}-{i:03d}" for i in range(n)]
    for i, jid in enumerate(ids):
        store.create(Job(job_id=jid, engine=engine, filename="f",
                         status=JobStatus.QUEUED, created_at=now - 1000 + i))
    return engine, ids


@pytest.fixture(params=["memory", "sqlite", "redis", "postgres"])
def store(request, tmp_path):
    for name, s in _stores(tmp_path):
        if name == request.param:
            return s
    pytest.skip(f"{request.param} backend unavailable (postgres needs BLASTBOX_TEST_PG_DSN)")


def test_without_exclude_the_oldest_is_claimed(store):
    engine, ids = _seed(store, 3)
    assert store.claim_next(engine=engine).job_id == ids[0]


def test_excluded_jobs_are_not_offered(store):
    engine, ids = _seed(store, 3)
    job = store.claim_next(engine=engine, exclude={ids[0], ids[1]})
    assert job is not None and job.job_id == ids[2], (
        "the store handed over a job the claimant said it must not be given")
    for jid in ids[:2]:
        assert store.get(jid).status is JobStatus.QUEUED, f"{jid} was claimed despite exclude"


def test_excluding_everything_is_simply_no_work(store):
    engine, ids = _seed(store, 2)
    assert store.claim_next(engine=engine, exclude=set(ids)) is None


def test_a_large_exclusion_binds(store):
    """The whole refusal memo can be passed (8192 ids). On postgres and modern sqlite that is
    well inside the bound-parameter limit; the query must still return the one job not excluded."""
    engine, ids = _seed(store, 2)
    noise = {f"absent-{i}" for i in range(8192)}
    job = store.claim_next(engine=engine, exclude=noise | {ids[0]})
    assert job is not None and job.job_id == ids[1]
