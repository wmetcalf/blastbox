from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

from . import test_node_claim as _tnc
from .test_node_claim import _claim, auth, token_for

pki_dir = _tnc.pki_dir          # reuse the real-PKI fixture

GOOD = {"agent_version": "1.2.3", "binary_sha256": "ab" * 32, "goos": "linux",
        "goarch": "amd64", "started_at": "2026-11-27T00:00:00Z",
        "engines": [{"name": "clamav", "sandbox": "gvisor", "floor": 1, "slots": 4,
                     "busy": 0, "selftest_ok": True, "selftest_at": "2026-11-27T00:00:01Z"}],
        "in_flight": [{"job_id": "j", "claim_id": "c", "started_at": "2026-11-27T00:00:02Z",
                       "deadline_at": "2026-11-27T00:10:02Z"}],
        "cert_not_after": "2027-01-01T00:00:00Z", "future_field": 1}


@pytest.fixture
def rig(pki_dir):
    store = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir) is True
    return store, TestClient(app)


def _liveness(c):
    return c.app.state.node_liveness


def test_requires_a_session(rig):
    _, c = rig
    assert c.post("/v1/nodes/heartbeat", json=GOOD).status_code == 401
    assert c.post("/v1/nodes/heartbeat", json=GOOD, headers=auth("junk")).status_code == 401


def test_requires_a_held_grant(rig, pki_dir):
    store, c = rig
    tok = token_for(c, pki_dir, "alpha")
    for f in pki_dir.glob("node-alpha.*"):
        f.unlink()
    r = c.post("/v1/nodes/heartbeat", json=GOOD, headers=auth(tok))
    assert r.status_code == 403
    assert "alpha" not in _liveness(c).snapshot()


def test_ok_response_and_stored(rig, pki_dir, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NODE_MIN_AGENT_VERSION", "1.0.0")
    monkeypatch.setenv("BLASTBOX_NODE_HEARTBEAT_S", "5")
    _, c = rig
    r = c.post("/v1/nodes/heartbeat", json=GOOD,
               headers=auth(token_for(c, pki_dir, "alpha")))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["min_agent_version"] == "1.0.0" and j["heartbeat_s"] == 10   # clamped up
    assert abs(j["server_time"] - time.time()) < 5
    row = _liveness(c).snapshot()["alpha"]
    assert row.last_heartbeat_at and row.body["agent_version"] == "1.2.3"
    assert "future_field" not in row.body


def test_defaults(rig, pki_dir, monkeypatch):
    monkeypatch.delenv("BLASTBOX_NODE_MIN_AGENT_VERSION", raising=False)
    monkeypatch.delenv("BLASTBOX_NODE_HEARTBEAT_S", raising=False)
    _, c = rig
    j = c.post("/v1/nodes/heartbeat", json={},
               headers=auth(token_for(c, pki_dir, "alpha"))).json()
    assert (j["min_agent_version"], j["heartbeat_s"]) == ("0.0.0", 30)


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(agent_version="x" * 129),
    lambda b: b.update(started_at="x" * 65),
    lambda b: b.update(engines=[GOOD["engines"][0]] * 65),
    lambda b: b.update(in_flight=[GOOD["in_flight"][0]] * 65),
    lambda b: b["engines"][0].update(name="y" * 129),
    lambda b: b["engines"][0].update(slots=-1),
])
def test_over_bounds_is_422(rig, pki_dir, mutate):
    import copy
    _, c = rig
    body = copy.deepcopy(GOOD)
    mutate(body)
    r = c.post("/v1/nodes/heartbeat", json=body, headers=auth(token_for(c, pki_dir, "alpha")))
    assert r.status_code == 422


def test_claim_records_last_claim_at_even_on_204(rig, pki_dir):
    _, c = rig
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 204
    row = _liveness(c).snapshot()["alpha"]
    assert row.last_claim_at and row.last_claim_engine == "clamav"
    assert row.last_heartbeat_at is None


def test_claim_401_records_nothing(rig):
    _, c = rig
    assert c.post("/v1/nodes/claim", json={}).status_code == 401
    assert _liveness(c).snapshot() == {}


def test_a_failing_liveness_store_never_fails_claim_or_heartbeat(rig, pki_dir):
    store, c = rig
    live = _liveness(c)

    def boom(*a, **k):
        raise RuntimeError("down")
    live.record_claim = boom
    live.record_heartbeat = boom
    tok = token_for(c, pki_dir, "alpha")
    assert c.post("/v1/nodes/heartbeat", json=GOOD, headers=auth(tok)).status_code == 200
    assert _claim(c, pki_dir, "alpha", engine="clamav", token=tok).status_code == 204


def test_heartbeat_listing_extra_engines_changes_no_grant(rig, pki_dir):
    """beta is granted boxjs only. Telling the control plane it runs clamav must not let it
    claim a clamav job."""
    store, c = rig
    store.create(Job(job_id="job-1", engine="clamav", filename="s.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    tok = token_for(c, pki_dir, "beta")
    body = {"engines": [{"name": "clamav", "slots": 99, "selftest_ok": True}]}
    assert c.post("/v1/nodes/heartbeat", json=body, headers=auth(tok)).status_code == 200
    assert _claim(c, pki_dir, "beta", engine="clamav", token=tok).status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED
    r = _claim(c, pki_dir, "beta", token=tok)          # unscoped: only boxjs, so nothing
    assert r.status_code == 204


def test_in_flight_claim_ids_are_not_persisted(rig, pki_dir):
    _, c = rig
    r = c.post("/v1/nodes/heartbeat", json=GOOD, headers=auth(token_for(c, pki_dir, "alpha")))
    assert r.status_code == 200
    body = _liveness(c).snapshot()["alpha"].body
    assert [e["job_id"] for e in body["in_flight"]] == ["j"]
    assert "claim_id" not in body["in_flight"][0] and body["in_flight"][0]["started_at"]


def test_claim_writes_are_throttled(rig, pki_dir):
    _, c = rig
    tok = token_for(c, pki_dir, "alpha")
    _claim(c, pki_dir, "alpha", token=tok)
    first = _liveness(c).snapshot()["alpha"].last_claim_at
    _claim(c, pki_dir, "alpha", token=tok)
    assert _liveness(c).snapshot()["alpha"].last_claim_at == first


@pytest.mark.parametrize("floor,stored", [("seatbelt", "seatbelt"), (1, "1")])
def test_floor_is_a_sandbox_name_and_an_int_is_tolerated(rig, pki_dir, floor, stored):
    _, c = rig
    body = dict(GOOD, engines=[dict(GOOD["engines"][0], floor=floor)])
    r = c.post("/v1/nodes/heartbeat", json=body, headers=auth(token_for(c, pki_dir, "alpha")))
    assert r.status_code == 200
    assert _liveness(c).snapshot()["alpha"].body["engines"][0]["floor"] == stored


def test_floor_longer_than_32_chars_is_refused(rig, pki_dir):
    _, c = rig
    body = dict(GOOD, engines=[dict(GOOD["engines"][0], floor="x" * 33)])
    r = c.post("/v1/nodes/heartbeat", json=body, headers=auth(token_for(c, pki_dir, "alpha")))
    assert r.status_code == 422


def test_claim_from_a_node_whose_cert_is_gone_records_nothing(rig, pki_dir):
    _, c = rig
    tok = token_for(c, pki_dir, "alpha")
    for f in pki_dir.glob("node-alpha.*"):
        f.unlink()
    assert _claim(c, pki_dir, "alpha", token=tok).status_code == 403
    assert "alpha" not in _liveness(c).snapshot()


def test_a_claim_refused_for_an_ungranted_engine_is_not_serving_evidence(rig, pki_dir):
    _, c = rig
    assert _claim(c, pki_dir, "beta", engine="clamav").status_code == 403   # beta: boxjs only
    assert "beta" not in _liveness(c).snapshot()


def test_claims_are_recorded_per_engine(rig, pki_dir):
    _, c = rig
    tok = token_for(c, pki_dir, "alpha")
    _claim(c, pki_dir, "alpha", engine="clamav", token=tok)
    _claim(c, pki_dir, "alpha", token=tok)                         # unscoped: not throttled away
    assert set(_liveness(c).snapshot()["alpha"].claims) == {"clamav", ""}
