from __future__ import annotations

import pytest

from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.node_liveness import (
    InMemoryLivenessStore, RedisLivenessStore, SqlLivenessStore, build_liveness_store,
    safe_record_claim, safe_record_heartbeat)


@pytest.fixture(params=["mem", "sql"])
def store(request, tmp_path):
    if request.param == "mem":
        return InMemoryLivenessStore()
    from blastbox.host.jobs.sql_store import SqlJobStore
    return SqlLivenessStore(SqlJobStore(f"sqlite:///{tmp_path}/t.db"))


def test_round_trip_and_columns_are_independent(store):
    store.record_claim("a", "clamav", 10.0)
    snap = store.snapshot()["a"]
    assert snap.last_claim_at == 10.0 and snap.last_heartbeat_at is None and snap.body is None
    store.record_heartbeat("a", {"agent_version": "1"}, 20.0)
    snap = store.snapshot()["a"]
    assert (snap.last_heartbeat_at, snap.last_claim_at) == (20.0, 10.0)
    assert snap.body == {"agent_version": "1"}
    store.record_claim("a", None, 30.0)
    snap = store.snapshot()["a"]
    assert (snap.last_heartbeat_at, snap.last_claim_at) == (20.0, 30.0)
    assert snap.body == {"agent_version": "1"}


def test_sql_upserts_one_row(tmp_path):
    from blastbox.host.jobs.sql_store import SqlJobStore
    js = SqlJobStore(f"sqlite:///{tmp_path}/t.db")
    s = build_liveness_store(js)
    assert isinstance(s, SqlLivenessStore)
    for i in range(3):
        s.record_heartbeat("a", {"i": i}, float(i))
    with js.connection() as c:
        assert c.execute("SELECT COUNT(*) FROM node_liveness").fetchone()[0] == 1
    assert s.snapshot()["a"].body == {"i": 2}


def test_build_falls_back_to_memory():
    assert isinstance(build_liveness_store(InMemoryJobStore()), InMemoryLivenessStore)


class FakeRedis:
    def __init__(self):
        self.h = {}

    def hset(self, k, mapping):
        self.h.setdefault(k, {}).update({a.encode(): b.encode() for a, b in mapping.items()})

    def scan_iter(self, match, count):
        return [k for k in self.h if k.startswith(match[:-1])]

    def hgetall(self, k):
        return self.h[k]


def test_redis_round_trip():
    s = RedisLivenessStore(FakeRedis())
    s.record_heartbeat("n1", {"x": 1}, 5.0)
    s.record_claim("n1", "boxjs", 6.0)
    r = s.snapshot()["n1"]
    assert (r.last_heartbeat_at, r.last_claim_at, r.last_claim_engine, r.body) == (
        5.0, 6.0, "boxjs", {"x": 1})


def test_writes_are_best_effort():
    class Boom:
        def record_heartbeat(self, *a): raise RuntimeError("down")
        def record_claim(self, *a): raise RuntimeError("down")
        def snapshot(self): return {}

    assert safe_record_heartbeat(Boom(), "a", {}, 1.0) is False
    assert safe_record_claim(Boom(), "a", None, 1.0) is False


def test_redis_claim_with_no_engine_clears_the_engine():
    s = RedisLivenessStore(FakeRedis())
    s.record_claim("n1", "boxjs", 6.0)
    s.record_claim("n1", None, 7.0)
    r = s.snapshot()["n1"]
    assert (r.last_claim_at, r.last_claim_engine) == (7.0, None)


def test_memory_fallback_warns(caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="blastbox.node_liveness"):
        build_liveness_store(InMemoryJobStore())
    assert any("in memory only" in r.getMessage() for r in caplog.records)
