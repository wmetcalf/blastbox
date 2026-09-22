"""Round-five regressions on the node hand-over (#178).

Each of these is a control that was PRESENT and not in force: an arm computed and then
discarded, a bound that starves the thing it protects, and a field a node may write that the
sweep protecting the fleet reads.
"""
from __future__ import annotations

import base64
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_reclaim
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


def _rig(tmp_path, monkeypatch, *, grants, env):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=grants).write(d, "node-n")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    store = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d)
    c = TestClient(app)
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
    tok = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig},
    ).json()["token"]
    return c, store, {SESSION_HEADER: tok}


class TestStrictTiersAndAnUnresolvableOverride:
    """`_job_requirements` computed `can_tell=False` for a job selecting a personality this host
    has not got -- and then returned the literal `True` on the governed path, discarding it. So
    the strict-mode arm added for exactly this hole only ever fired when the fallback driver was
    itself ungoverned, which is the case that needed it least."""

    ENV = {
        # A personality this host HAS, so the engine default resolves and looks checkable.
        "BLASTBOX_NETPOLICY_PROX": "exit=socks",
        "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox",
        "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE": "1",
        "BLASTBOX_NODE_CLAIM_STRICT_TIERS": "1",
    }

    @pytest.fixture
    def rig(self, tmp_path, monkeypatch):
        # The node holds everything the FALLBACK personality needs, so nothing but the
        # unresolvable override can refuse this job.
        return _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
            engines=("clamav",), tiers=("socks",), credentials=True), env=self.ENV)

    def test_a_job_selecting_a_personality_this_host_cannot_see_is_refused(self, rig):
        c, store, h = rig
        store.create(Job(job_id="j1", engine="clamav", filename="f", status=JobStatus.QUEUED,
                         created_at=time.time(), net_policy="mystery"))
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        assert r.status_code == 204, (
            "strict mode handed over a job whose personality this host cannot resolve; the "
            f"node's tier and credentials grants went unchecked ({r.text})")
        assert store.get("j1").status is JobStatus.QUEUED

    def test_a_resolvable_governed_job_is_still_handed_over(self, rig):
        """The other direction, so the fix cannot be 'refuse everything governed'."""
        c, store, h = rig
        store.create(Job(job_id="j2", engine="clamav", filename="f", status=JobStatus.QUEUED,
                         created_at=time.time(), net_policy="prox"))
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        assert r.status_code == 200, r.text


def test_jobs_past_their_deferral_limit_do_not_starve_entitled_work(tmp_path, monkeypatch):
    """A refused job is deferred at most `_MAX_REFUSAL_DEFERRALS` times, after which it is
    released immediately claimable so an entitled peer can take it. On an all-federated fleet
    there IS no entitled peer, so those jobs sit at the head of the queue permanently and each
    one consumed one of eight probes -- every later poll burned the budget on the same wall and
    returned 204, with the eligible job never reached."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), tiers=("wireguard",), credentials=False), env={
            "BLASTBOX_NETPOLICY_PROX": "exit=socks",
            "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox",   # socks: needs credentials, node has none
            "BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})
    now = time.time()
    for i in range(8):
        store.create(Job(job_id=f"no{i}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=now - 1000 + i))
    # Exhaust every deferral: after this the wall is permanently claimable and permanently
    # refusable, which is the state an all-federated fleet settles into.
    for _ in range(4):
        assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
        for i in range(8):
            store.update(f"no{i}", claimable_after=None)
    store.create(Job(job_id="ok", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=now))
    got = []
    for _ in range(3):
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        if r.status_code == 200:
            got.append(r.json()["job"]["job_id"])
        for i in range(8):
            store.update(f"no{i}", claimable_after=None)
    assert "ok" in got, (
        "a wall of permanently-refused jobs consumed the whole probe budget, so work this node "
        "IS entitled to was never handed over")


class TestANodeCannotMakeItsOwnClaimUnreclaimable:
    """`reclaim_stale_claims` judges a claim's age on `started_at` and SKIPS a row where it is
    None -- and `started_at` is in NODE_WRITABLE_FIELDS, because dispatch's requeue clears it.
    A node could therefore write `started_at: null` while staying RUNNING and hold the job, and
    its staged sample on the control plane's disk, forever."""

    @pytest.fixture
    def rig(self, tmp_path, monkeypatch):
        return _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                    env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})

    def _claim(self, c, store, h):
        store.create(Job(job_id="j", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                         created_at=time.time() - 10_000))
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        return body["job"]["claim_id"], body["receipt"]

    def test_clearing_started_at_without_releasing_the_job_is_refused(self, rig):
        c, store, h = rig
        claim_id, receipt = self._claim(c, store, h)
        r = c.post("/v1/nodes/jobs/j", headers=h, json={
            "claim_id": claim_id, "receipt": receipt, "fields": {"started_at": None}})
        assert r.status_code == 400, (
            "a node cleared the only clock the reclaim sweep reads while keeping the job "
            f"RUNNING ({r.status_code}: {r.text})")
        assert store.get("j").started_at is not None

    def test_releasing_the_job_may_still_clear_it(self, rig):
        """dispatch.py's own requeue writes status=QUEUED together with started_at=None, so the
        refusal above must not break the legitimate write."""
        c, store, h = rig
        claim_id, receipt = self._claim(c, store, h)
        r = c.post("/v1/nodes/jobs/j", headers=h, json={
            "claim_id": claim_id, "receipt": receipt,
            "fields": {"status": "queued", "claim_id": None, "started_at": None}})
        assert r.status_code == 200, r.text

    def test_the_sweep_reclaims_a_running_claim_that_has_no_start_time(self, tmp_path):
        """Belt and braces: whatever the route allows, the sweep must not be steerable by a
        missing value. A RUNNING row with no `started_at` is anomalous by construction --
        `claim_next` stamps it -- so it is judged on `created_at` rather than skipped."""
        store = InMemoryJobStore()
        store.create(Job(job_id="stuck", engine="boxjs", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000))
        job = store.claim_next(engine=frozenset({"boxjs"}))
        assert job is not None
        store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                               claim_id="node:" + (job.claim_id or ""))
        store.update("stuck", started_at=None)
        n = node_reclaim.reclaim_stale_claims(store, after_s=900.0)
        assert n == 1, "a RUNNING claim with no start time was skipped by the sweep forever"
        assert store.get("stuck").status is JobStatus.FAILED


def test_non_ascii_credentials_are_refused_rather_than_a_500(tmp_path, monkeypatch):
    """`hmac.compare_digest` raises TypeError on a non-ASCII str, so an unauthenticated caller
    could turn every refusal path into a 500 and a traceback per request."""
    c, _store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                        env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})
    d = tmp_path / "pki"
    r = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": "1000.0:é",
        "signature": "AAAA"})
    assert r.status_code in (400, 403), f"non-ASCII challenge gave {r.status_code}: {r.text}"
    # BYTES, because httpx refuses a non-ASCII str header -- but the wire carries bytes and
    # Starlette decodes a header as latin-1, so this is exactly what a raw client can send and
    # what the session verifier then compares.
    r = c.post("/v1/nodes/claim", json={},
               headers={SESSION_HEADER.encode(): "n:1000.0:é".encode("latin-1")})
    assert r.status_code in (400, 401, 403), f"non-ASCII token gave {r.status_code}: {r.text}"


def test_a_stale_queued_job_failed_by_ingress_gets_a_retention_deadline(tmp_path, monkeypatch):
    """`fail_stale_queued` writes `expires_at` precisely so `expire_due` can collect the row it
    creates -- and the ingress call site did not pass `retention_s`, so every row it failed was
    immortal. Its sibling call one line above passes it."""
    from blastbox.host.ingress.app import build_app

    monkeypatch.setenv("BLASTBOX_MAINTENANCE_INTERVAL_S", "0.05")
    monkeypatch.setenv("BLASTBOX_MAX_QUEUED_AGE_S", "60")
    monkeypatch.setenv("BLASTBOX_JOB_RETENTION_SECONDS", "3600")
    monkeypatch.setenv("BLASTBOX_SCRATCH_MAX_AGE_S", "0")
    store = InMemoryJobStore()
    store.create(Job(job_id="old", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time() - 10_000, target_tier="nobody"))
    app = build_app(job_store=store, job_root=tmp_path / "jobs")
    with TestClient(app):
        deadline = time.time() + 5
        while store.get("old").status is JobStatus.QUEUED and time.time() < deadline:
            time.sleep(0.05)
    row = store.get("old")
    assert row.status is JobStatus.FAILED, "the stale-QUEUED sweep never ran"
    assert row.expires_at is not None, (
        "the row was failed with no retention deadline, so `expire_due` will skip it forever "
        "-- the leak this sweep's docstring says it must not trade for")
