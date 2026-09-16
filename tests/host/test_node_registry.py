"""The federated node view.

Every test here exists because a registered node is UNTRUSTED. The registry's job is to
be useful without ever letting a node's own assertions become authority, and to survive
one node publishing rubbish without losing the view for everyone else.
"""
from __future__ import annotations

import json
import time

import pytest

from blastbox.host.node_registry import (
    STALE_AFTER_S,
    InMemoryNodeRegistry,
    NodeClaims,
    NodeRecord,
    fresh_node_ids,
    valid_record,
)


def rec(node_id="toolz3", *, age=0.0, **claims):
    return NodeRecord(node_id=node_id, ts=time.time() - age, claims=NodeClaims(**claims))


# ----------------------------------------------------------------------- round trip

def test_a_record_round_trips_through_json():
    r = rec(engines=("boxjs", "clamav"), slots=8, free_ram_mib=4096, backlog=3,
            egress_healthy=True, egress_reason="all present")
    back = NodeRecord.from_json(r.to_json())
    assert back == r


def test_a_poisoned_record_is_skipped_not_raised():
    """One node publishing rubbish must not take out the whole view — that is the
    difference between one node misbehaving and the fleet losing placement."""
    for junk in ("", "not json", "[]", '{"claims": 7}', '{"node_id": {"a": 1}}',
                 '{"ts": "yesterday"}'):
        assert NodeRecord.from_json(junk) is None or not valid_record(
            NodeRecord.from_json(junk))


def test_the_registry_drops_a_poisoned_row_and_keeps_the_rest():
    reg = InMemoryNodeRegistry()
    reg.publish(rec("good", slots=4))
    reg._rows["bad"] = "{{{ not json"
    assert fresh_node_ids(reg.read_all()) == ("good",)


# ------------------------------------------------------------------------ freshness

def test_a_stale_record_drops_out_on_its_own():
    """Self-healing: a node that DIED rather than exited leaves no deregistration step
    for anyone to miss."""
    reg = InMemoryNodeRegistry()
    reg.publish(rec("gone", age=STALE_AFTER_S + 1))
    reg.publish(rec("here", age=1))
    assert fresh_node_ids(reg.read_all()) == ("here",)


def test_a_record_from_the_future_is_rejected():
    """A node with a badly wrong clock — or one trying to stay permanently fresh — would
    otherwise have a negative age that reads as fresh forever."""
    assert not valid_record(rec(age=-(STALE_AFTER_S + 10)))
    assert valid_record(rec(age=-1))          # small skew is tolerated


def test_an_enormous_timestamp_does_not_raise():
    """math.isfinite OVERFLOWS on a huge int decoded from JSON; raising here would take
    down a reader instead of skipping one record."""
    raw = json.dumps({"node_id": "x", "ts": 10 ** 400, "claims": {}})
    assert not valid_record(NodeRecord.from_json(raw))


# ------------------------------------------------------- claims are bounded, not trusted

@pytest.mark.parametrize("claims", [
    {"slots": -1}, {"slots": 10 ** 9},
    {"free_ram_mib": -5}, {"free_ram_mib": 10 ** 15},
    {"backlog": -1}, {"backlog": 10 ** 12},
])
def test_an_absurd_claim_is_rejected_not_clamped(claims):
    """A node is untrusted, so a malformed value must be REJECTED. Clamping would let it
    silently skew every peer's view of the fleet instead."""
    assert not valid_record(rec(**claims))


def test_an_unsafe_engine_name_is_rejected():
    assert not valid_record(rec(engines=("../etc/passwd",)))
    assert not valid_record(rec(engines=("UPPER",)))
    assert not valid_record(rec(engines=tuple(f"e{i}" for i in range(65))))


def test_an_unsafe_node_id_cannot_be_published():
    reg = InMemoryNodeRegistry()
    for bad in ("", "UPPER", "has space", "../../etc", "x" * 64):
        with pytest.raises(ValueError, match="invalid node id"):
            reg.publish(NodeRecord(node_id=bad, ts=time.time()))


def test_valid_record_authenticates_nothing():
    """A reader treating True from valid_record as "this node is who it says" has
    misread it — so assert the BEHAVIOUR, not the docstring: a record with no cert
    fingerprint at all, or one claiming to be another node, is still "valid". Shape and
    freshness are all this can know from a stored blob; authority is the certificate's
    job, resolved by the reader.
    """
    assert valid_record(NodeRecord(node_id="toolz3", ts=time.time()))            # no cert at all
    assert valid_record(NodeRecord(node_id="toolz3", ts=time.time(),
                                   cert_fingerprint="0" * 64))                   # unverified
    assert valid_record(NodeRecord(node_id="toolz3", ts=time.time(),
                                   cert_fingerprint="obviously not a hash"))     # unparsed


def test_the_registry_records_self_reported_health_without_acting_on_it():
    """A hostile node reports whatever it likes in `egress_healthy`. The registry's job
    is to RECORD that, never to believe it — the spec's answer is that containment is
    verified from the EXIT HOST, which can observe a peer's traffic.

    So the behaviour to pin is that the field changes nothing: a node claiming perfect
    health and a node claiming none are treated identically by both validation and the
    view. The moment a reader starts filtering on it, an observability field has quietly
    become an authority one.
    """
    reg = InMemoryNodeRegistry()
    reg.publish(rec("liar", egress_healthy=True, egress_reason="honestly fine"))
    reg.publish(rec("honest", egress_healthy=False, egress_reason="enforcement MISSING"))
    reg.publish(rec("silent"))                                   # says nothing at all

    assert fresh_node_ids(reg.read_all()) == ("honest", "liar", "silent")
    assert all(valid_record(r) for r in reg.read_all())
    # ...and the claim survives for a human to look at.
    by_id = {r.node_id: r for r in reg.read_all()}
    assert by_id["liar"].claims.egress_healthy is True
    assert by_id["honest"].claims.egress_healthy is False
    assert by_id["silent"].claims.egress_healthy is None


# ---------------------------------------------------------------------- registry ops

def test_publish_is_an_upsert_keyed_on_node_id():
    reg = InMemoryNodeRegistry()
    reg.publish(rec("toolz3", slots=2))
    reg.publish(rec("toolz3", slots=9))
    view = reg.read_all()
    assert len(view) == 1 and view[0].claims.slots == 9


def test_forget_removes_a_node_for_a_graceful_stop():
    reg = InMemoryNodeRegistry()
    reg.publish(rec("toolz3"))
    reg.forget("toolz3")
    assert reg.read_all() == []
    reg.forget("never-existed")               # idempotent


def test_the_view_is_deterministically_ordered():
    """Every dispatcher runs the same placement over the same view, so the view must not
    depend on iteration order or they will not converge."""
    reg = InMemoryNodeRegistry()
    for n in ("zeta", "alpha", "mid"):
        reg.publish(rec(n))
    assert [r.node_id for r in reg.read_all()] == ["alpha", "mid", "zeta"]


# ------------------------------------------------- the SQL backend: actually federated

@pytest.fixture()
def sql_registry(tmp_path):
    from blastbox.host.jobs.sql_store import SqlJobStore
    from blastbox.host.node_registry import SqlNodeRegistry

    return SqlNodeRegistry(SqlJobStore(f"sqlite:///{tmp_path}/t.db"))


def test_the_sql_registry_behaves_like_the_in_memory_one(sql_registry):
    sql_registry.publish(rec("toolz3", engines=("boxjs",), slots=4))
    sql_registry.publish(rec("toolz2", slots=8))
    sql_registry.publish(rec("dead", age=STALE_AFTER_S + 60))
    assert fresh_node_ids(sql_registry.read_all()) == ("toolz2", "toolz3")


def test_the_sql_registry_upserts_rather_than_duplicating(sql_registry):
    """A heartbeat must never leave a window where a live node is absent from the view
    and gets placed against as if it were gone — so it is an UPSERT, not delete+insert."""
    for slots in (1, 2, 99):
        sql_registry.publish(rec("toolz3", slots=slots))
    view = sql_registry.read_all()
    assert len(view) == 1 and view[0].claims.slots == 99


def test_the_sql_registry_survives_a_poisoned_row(sql_registry):
    """A row written by an older version, or a node with a bug, must not blind the view."""
    sql_registry.publish(rec("good"))
    with sql_registry._store.connection() as conn:
        conn.execute("INSERT INTO nodes (node_id, record, ts) VALUES (?, ?, ?)",
                     ("bad", "{{{not json", time.time()))
    assert fresh_node_ids(sql_registry.read_all()) == ("good",)


def test_a_future_dated_row_is_rejected_even_though_sql_let_it_through(sql_registry):
    """The SQL predicate only trims obviously-old rows; the authoritative check —
    including the future-dated case a node could use to stay permanently fresh — is
    valid_record, in Python, where it is tested."""
    sql_registry.publish(rec("liar", age=-(STALE_AFTER_S + 600)))
    assert sql_registry.read_all() == []


def test_the_registry_reuses_the_job_stores_pool(tmp_path):
    """Opening a second pool would silently double this process's share of postgres'
    max_connections — the job store's pool is sized as the node's concurrency ceiling."""
    from blastbox.host.jobs.sql_store import SqlJobStore
    from blastbox.host.node_registry import SqlNodeRegistry, build_node_registry

    store = SqlJobStore(f"sqlite:///{tmp_path}/t.db")
    reg = build_node_registry(store)
    assert isinstance(reg, SqlNodeRegistry)
    assert reg._store is store


def test_build_falls_back_to_in_memory_for_a_store_without_the_seam():
    from blastbox.host.jobs.memory import InMemoryJobStore
    from blastbox.host.node_registry import build_node_registry

    assert isinstance(build_node_registry(InMemoryJobStore()), InMemoryNodeRegistry)


# ----------------------------------------------------------------- the Redis backend

class _FakeRedis:
    """Enough Redis to exercise the registry: set/get/delete/scan_iter with TTLs."""

    def __init__(self):
        self.data: dict[str, tuple[str, float | None]] = {}
        self.scan_calls = 0

    def set(self, key, value, ex=None):
        self.data[key] = (value, ex)

    def get(self, key):
        row = self.data.get(key)
        return None if row is None else row[0].encode()

    def delete(self, key):
        self.data.pop(key, None)

    def scan_iter(self, match=None, count=None):
        self.scan_calls += 1
        pre = (match or "").rstrip("*")
        yield from [k for k in list(self.data) if k.startswith(pre)]


def test_the_redis_registry_behaves_like_the_others():
    from blastbox.host.node_registry import RedisNodeRegistry

    reg = RedisNodeRegistry(_FakeRedis())
    reg.publish(rec("toolz3", slots=4))
    reg.publish(rec("toolz2", slots=8))
    reg.publish(rec("dead", age=STALE_AFTER_S + 60))
    assert fresh_node_ids(reg.read_all()) == ("toolz2", "toolz3")
    reg.forget("toolz2")
    assert fresh_node_ids(reg.read_all()) == ("toolz3",)


def test_the_redis_registry_uses_scan_not_keys():
    """This runs on a schedule against a Redis that is ALSO serving the job store, and
    KEYS blocks the server for the whole keyspace."""
    from blastbox.host.node_registry import RedisNodeRegistry

    client = _FakeRedis()
    assert not hasattr(client, "keys")           # the fake offers no KEYS to fall back on
    RedisNodeRegistry(client).read_all()
    assert client.scan_calls == 1


def test_the_redis_ttl_outlives_the_staleness_window():
    """Expiry must never race a reader into dropping a node that is merely a heartbeat
    behind — the record's own ts is what decides freshness. The TTL only stops dead keys
    accumulating in a shared Redis."""
    from blastbox.host.node_registry import RedisNodeRegistry

    client = _FakeRedis()
    RedisNodeRegistry(client).publish(rec("toolz3"))
    (_value, ttl) = client.data["blastbox:node:toolz3"]
    assert ttl > STALE_AFTER_S


def test_a_key_that_expires_between_scan_and_get_is_skipped():
    from blastbox.host.node_registry import RedisNodeRegistry

    client = _FakeRedis()
    reg = RedisNodeRegistry(client)
    reg.publish(rec("vanishing"))
    original_get = client.get
    client.get = lambda key: None if "vanishing" in key else original_get(key)
    assert reg.read_all() == []


def test_build_selects_the_redis_backend_from_a_redis_job_store():
    from blastbox.host.node_registry import RedisNodeRegistry, build_node_registry

    class FakeJobStore:
        _r = _FakeRedis()

    assert isinstance(build_node_registry(FakeJobStore()), RedisNodeRegistry)
