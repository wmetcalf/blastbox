"""`net_policy_effective` and `executor_node`: host-recorded facts every job store must keep.

`net_policy` is the REQUEST (set at ingress). `net_policy_effective` is the personality the
dispatcher RESOLVED and enforced, stamped at dispatch -- the attestation signs it, so it must
survive every backend's round trip exactly like `worker_tier`. `executor_node` is the node id the
control plane handed a job to; the host records it at hand-over so an attestation can name the
node without trusting anything the node says.
"""
from __future__ import annotations

import fakeredis
import pytest

from blastbox.host.jobs.base import Job
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.redis_store import RedisJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


def _stores(tmp_path):
    return {
        "memory": InMemoryJobStore(),
        "sqlite": SqlJobStore(f"sqlite:///{tmp_path / 'j.db'}"),
        "redis": RedisJobStore(fakeredis.FakeRedis(), ttl_seconds=3600),
    }


@pytest.mark.parametrize("backend", ["memory", "sqlite", "redis"])
def test_host_recorded_fields_round_trip_every_store(tmp_path, backend):
    store = _stores(tmp_path)[backend]
    job = Job.new(engine="redtusk", filename="x.doc")
    job.net_policy = "requested"
    store.create(job)
    assert store.get(job.job_id).net_policy_effective is None
    assert store.get(job.job_id).executor_node is None

    store.update(job.job_id, net_policy_effective="none", executor_node="node-7")
    got = store.get(job.job_id)
    assert got.net_policy == "requested"          # the request is untouched
    assert got.net_policy_effective == "none"
    assert got.executor_node == "node-7"


def test_dict_round_trip_and_public_view():
    job = Job.new(engine="e", filename="f")
    job.net_policy_effective = "fakenet"
    job.executor_node = "node-7"
    d = job.to_dict()
    assert d["net_policy_effective"] == "fakenet"
    back = Job.from_dict(d)
    assert back.net_policy_effective == "fakenet"
    assert back.executor_node == "node-7"
    pub = job.to_public_dict()
    assert pub["net_policy_effective"] == "fakenet"   # observability, like worker_tier
    assert "executor_node" not in pub                   # internal fleet identity, like claim_id


def test_sqlite_migrates_a_table_that_predates_the_columns(tmp_path):
    """An existing jobs table (created before these columns existed) gains them on open."""
    import sqlite3

    db = tmp_path / "old.db"
    SqlJobStore(f"sqlite:///{db}")          # create the current schema...
    con = sqlite3.connect(db)
    con.execute("ALTER TABLE jobs DROP COLUMN net_policy_effective")   # ...then age it
    con.execute("ALTER TABLE jobs DROP COLUMN executor_node")
    con.commit()
    con.close()

    store = SqlJobStore(f"sqlite:///{db}")
    job = Job.new(engine="e", filename="f")
    store.create(job)
    store.update(job.job_id, net_policy_effective="none", executor_node="n1")
    assert store.get(job.job_id).net_policy_effective == "none"
    assert store.get(job.job_id).executor_node == "n1"
