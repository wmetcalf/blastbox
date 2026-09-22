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

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


def _stores(tmp_path):
    from blastbox.host.jobs.sql_store import SqlJobStore

    yield "memory", InMemoryJobStore()
    yield "sqlite", SqlJobStore(f"sqlite:///{tmp_path / 'q.db'}")
    try:
        import fakeredis

        from blastbox.host.jobs.redis_store import RedisJobStore

        yield "redis", RedisJobStore(client=fakeredis.FakeRedis())
    except Exception:                       # noqa: BLE001 - redis backend optional here
        pass


def _seed(store, n):
    now = time.time()
    for i in range(n):
        store.create(Job(job_id=f"j{i:03d}", engine="boxjs", filename="f",
                         status=JobStatus.QUEUED, created_at=now - 1000 + i))


@pytest.fixture(params=["memory", "sqlite", "redis"])
def store(request, tmp_path):
    for name, s in _stores(tmp_path):
        if name == request.param:
            return s
    pytest.skip(f"{request.param} backend unavailable")


def test_without_exclude_the_oldest_is_claimed(store):
    _seed(store, 3)
    assert store.claim_next(engine="boxjs").job_id == "j000"


def test_excluded_jobs_are_not_offered(store):
    _seed(store, 3)
    job = store.claim_next(engine="boxjs", exclude={"j000", "j001"})
    assert job is not None and job.job_id == "j002", (
        "the store handed over a job the claimant said it must not be given")
    for jid in ("j000", "j001"):
        assert store.get(jid).status is JobStatus.QUEUED, f"{jid} was claimed despite exclude"


def test_excluding_everything_is_simply_no_work(store):
    _seed(store, 2)
    assert store.claim_next(engine="boxjs", exclude={"j000", "j001"}) is None
