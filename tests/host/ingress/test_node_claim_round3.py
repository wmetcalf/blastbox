"""Regressions for the third review round on #178: each was found upstream and reproduced."""
from __future__ import annotations

import base64
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def rig(tmp_path, monkeypatch):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), tiers=("socks",), credentials=True)).write(d, "node-n")
    monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    store = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d)
    c = TestClient(app)
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
    tok = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig}
    ).json()["token"]
    return c, store, {SESSION_HEADER: tok}


def test_many_refusable_jobs_at_the_head_do_not_block_entitled_work(rig):
    """NINE jobs this node may not run, older than one it may. The first version memoised
    refusals but each memoised row still consumed one of eight probes, so job 9 and beyond were
    never reached. Refused jobs are now DEFERRED on release, so `claim_next` itself skips them."""
    c, store, h = rig
    now = time.time()
    for i in range(9):
        store.create(Job(job_id=f"wg{i}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=now - 1000 + i))
    store.create(Job(job_id="ok", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=now))
    seen = []
    for _ in range(3):
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        if r.status_code == 200:
            seen.append(r.json()["job"]["job_id"])
    assert "ok" in seen, "the entitled job was never reached"
    for i in range(9):
        j = store.get(f"wg{i}")
        assert j.status == JobStatus.QUEUED and j.claim_id is None
        assert j.claimable_after is not None and j.claimable_after > now, (
            "a refused job was put back without a deferral, so it would be re-selected at once")


def test_a_deferred_refusal_comes_back_for_an_entitled_peer(rig):
    """The deferral is short and global: after it lapses the job is claimable again."""
    from blastbox.host.ingress import node_claim as nc

    c, store, h = rig
    store.create(Job(job_id="wg", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
    j = store.get("wg")
    assert j.claimable_after <= time.time() + nc._REFUSAL_DEFER_S + 1
    assert j.claimable_after > time.time()


@pytest.mark.parametrize("bad", ["NaN", "nan", "inf", "-inf", "Infinity"])
def test_a_non_finite_deferral_is_refused(rig, bad):
    """NaN passes float() and fails every comparison, so it slid under the one-hour ceiling and
    then sat in the store as a value `claim_next` would never consider due -- the permanent bury
    through a different door."""
    c, store, h = rig
    store.create(Job(job_id="b", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    assert r.status_code == 200, r.text
    job, rcpt = r.json()["job"], r.json()["receipt"]
    w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
               json={"claim_id": job["claim_id"], "receipt": rcpt,
                     "fields": {"status": "queued", "claimable_after": bad}})
    assert w.status_code == 400, w.text
    assert store.get("b").status == JobStatus.RUNNING


def test_the_stored_deferral_is_the_normalised_float(rig):
    c, store, h = rig
    store.create(Job(job_id="b", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    job, rcpt = r.json()["job"], r.json()["receipt"]
    soon = time.time() + 30
    w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
               json={"claim_id": job["claim_id"], "receipt": rcpt,
                     "fields": {"status": "queued", "claimable_after": str(soon)}})
    assert w.status_code == 200, w.text
    stored = store.get("b").claimable_after
    assert isinstance(stored, float) and abs(stored - soon) < 1


def test_an_undeclared_per_job_override_is_unknown_not_ungoverned(tmp_path, monkeypatch):
    """Override allowed, job selects a personality THIS host has not got, engine default none.
    `resolve_net_policy` falls through to none, so it looked ungoverned here while a node whose
    registry holds that name resolves it to a real exit driver. Strict mode must refuse."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("boxjs",))).write(
        d, "node-n")
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    monkeypatch.setenv("BLASTBOX_NODE_CLAIM_STRICT_TIERS", "1")
    monkeypatch.delenv("BLASTBOX_NETPOLICY_UNDECLARED", raising=False)
    store = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d)
    c = TestClient(app)
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
    tok = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig}
    ).json()["token"]
    store.create(Job(job_id="ov", engine="boxjs", filename="f", net_policy="undeclared",
                     status=JobStatus.QUEUED, created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers={SESSION_HEADER: tok})
    assert r.status_code == 204, r.text
    assert store.get("ov").status == JobStatus.QUEUED


def test_registration_warns_when_the_reclaim_sweep_is_off(tmp_path, caplog, monkeypatch):
    """A node claiming here cannot run the dispatcher's orphan sweep. Without the control-plane
    sweep, every lost claim stays RUNNING forever -- said at startup, where it can be acted on."""
    monkeypatch.delenv("BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S", raising=False)
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    with caplog.at_level("WARNING"):
        assert register_node_claim_routes(FastAPI(), job_store=InMemoryJobStore(), pki_dir=d)
    assert any("RECLAIM_AFTER" in r.message for r in caplog.records), caplog.text


def test_the_maintenance_thread_does_not_depend_on_scratch_reaping():
    """BLASTBOX_SCRATCH_MAX_AGE_S=0 is the documented way to disable scratch reclamation only. It
    used to disable the thread entirely, taking the stale-claim sweep -- the only reclaim path on
    a credential-less fleet -- down with it."""
    import inspect

    from blastbox.host.ingress import app

    src = inspect.getsource(app)
    gate = src[src.index("_scratch_max_age_s > 0 or _reclaim_after_s() > 0"):][:200]
    assert "_reclaim_after_s() > 0" in gate and "_retention_wanted" in gate, gate
