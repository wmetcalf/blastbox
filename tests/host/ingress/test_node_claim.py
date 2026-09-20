"""Grants enforced AT the hand-over, over HTTP (#178).

The property every test here circles: a node that is not granted an engine must not be
able to move a job out of QUEUED. Refusing after the fetch is a different, weaker thing --
it is what the node-side gate already does, and what this issue exists because of.
"""
from __future__ import annotations

import base64
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def pki_dir(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), tiers=("socks",))).write(d, "node-alpha")
    ca.issue_node("beta", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("boxjs",))).write(d, "node-beta")
    # gamma is granted the SAME engine as alpha, deliberately: it is the only way to test
    # the claim-OWNERSHIP check on its own. Against beta (granted boxjs only) the write is
    # already refused by the grants re-check, so an ownership test using beta passes for the
    # wrong reason -- measured: deleting the ownership check left it green.
    ca.issue_node("gamma", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), tiers=("socks",))).write(d, "node-gamma")
    return d


@pytest.fixture
def store():
    return InMemoryJobStore()


def queued(store, job_id="job-1", engine="clamav"):
    store.create(Job(job_id=job_id, engine=engine, filename="sample.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    return job_id


def client(store, pki_dir):
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir) is True
    return TestClient(app)


def open_session(c, pki_dir, who, *, sign_as=None, cert_of=None, challenge=None,
                 signature=None):
    """Do the real handshake and return the response, so tests exercise the live flow."""
    ch = challenge if challenge is not None else c.get(
        "/v1/nodes/challenge").json()["challenge"]
    if signature is None:
        key = (pki_dir / f"node-{sign_as or who}.key").read_bytes()
        signature = base64.b64encode(node_auth.sign_claim(
            key, ch, node_auth.SCOPE_CLAIM_NEXT, who)).decode()
    cert = (pki_dir / f"node-{cert_of or who}.crt").read_text()
    return c.post("/v1/nodes/session",
                  json={"cert_pem": cert, "challenge": ch, "signature": signature})


def token_for(c, pki_dir, who, **kw):
    r = open_session(c, pki_dir, who, **kw)
    assert r.status_code == 200, f"handshake failed for {who}: {r.text}"
    return r.json()["token"]


def auth(token):
    return {"Authorization": f"Node {token}"}


def _claim(c, pki_dir, who, *, engine, tier=None, token=None, **session_kw):
    """Claim as *who*. The handshake is REAL unless a token is supplied: otherwise a test
    that means to check the grants gate would be satisfied by a missing token instead, and
    pass for the wrong reason (this happened -- the refusal tests kept passing after the
    grants check moved, because no token was being sent at all)."""
    tok = token if token is not None else token_for(c, pki_dir, who, **session_kw)
    body: dict = {"engine": engine}
    if tier is not None:
        body["tier"] = tier
    return c.post("/v1/nodes/claim", json=body, headers=auth(tok))


def test_a_granted_node_gets_the_job(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 200, r.text
    assert r.json()["job"]["job_id"] == "job-1"
    assert r.json()["node_id"] == "alpha"
    assert store.get("job-1").status == JobStatus.RUNNING


def test_an_ungranted_node_does_not_move_the_job_out_of_queued(store, pki_dir):
    """THE HEADLINE. beta is granted boxjs only. A clamav job must still be QUEUED after
    beta asks for it -- not claimed-then-refused, not RUNNING, not FAILED."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    r = _claim(c, pki_dir, "beta", engine="clamav")
    assert r.status_code == 403, r.text
    assert store.get("job-1").status == JobStatus.QUEUED, "the job was handed over anyway"
    assert store.get("job-1").claim_id is None, "a refused claim still stamped ownership"


def test_a_node_presenting_a_peers_certificate_gets_no_session(store, pki_dir):
    """Node certs sit side by side in the pki dir, so reading a peer's .crt is trivial.
    Without the key it proves nothing -- and the refusal lands at the HANDSHAKE, so there is
    never a token with which to try a claim."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    r = open_session(c, pki_dir, "alpha", sign_as="beta")
    assert r.status_code == 403, r.text
    assert store.get("job-1").status == JobStatus.QUEUED


def test_the_refusal_does_not_say_why(store, pki_dir):
    """A caller must not be able to map the fleet's grants by probing. An UNGRANTED ENGINE
    and an UNHELD KEY are the two most different causes there are -- one is authorisation,
    one is authentication, and they are refused at different endpoints -- and they must be
    byte-identical on the wire."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    ungranted = _claim(c, pki_dir, "beta", engine="clamav")
    unheld_key = open_session(c, pki_dir, "alpha", sign_as="beta")
    assert ungranted.status_code == unheld_key.status_code == 403
    assert ungranted.json()["detail"] == unheld_key.json()["detail"]
    for r in (ungranted, unheld_key):
        body = r.text.lower()
        for leak in ("clamav", "boxjs", "grant", "signature", "certificate", "expired"):
            assert leak not in body, f"the refusal leaked {leak!r}: {r.text}"


def test_no_work_is_204_not_404(store, pki_dir):
    """404 would be indistinguishable from the routes not being mounted, which is exactly
    when a node should fall back to claiming from the store directly."""
    c = client(store, pki_dir)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 204, r.text


def test_an_expired_challenge_gets_no_session(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    stale = node_auth.challenge_for(
        node_auth.SCOPE_CLAIM_NEXT, secret=node_auth.challenge_secret(pki_dir),
        now=time.time() - node_auth.CHALLENGE_TTL_S - 5)
    assert open_session(c, pki_dir, "alpha", challenge=stale).status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_forged_challenge_gets_no_session(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    forged = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=b"someone else's")
    assert open_session(c, pki_dir, "alpha", challenge=forged).status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_foreign_cas_node_is_refused(store, pki_dir, tmp_path):
    c = client(store, pki_dir)
    queued(store)
    rogue_dir = tmp_path / "rogue"
    rogue = pki.ensure_ca(rogue_dir)
    rogue.issue_node("alpha", wg_pubkey=WG,
                     grants=pki.NodeGrants(engines=("clamav", "boxjs"))).write(
        rogue_dir, "node-alpha")
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (rogue_dir / "node-alpha.key").read_bytes(), ch,
        node_auth.SCOPE_CLAIM_NEXT, "alpha")).decode()
    r = c.post("/v1/nodes/session", json={
        "cert_pem": (rogue_dir / "node-alpha.crt").read_text(), "challenge": ch,
        "signature": sig})
    assert r.status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_signature_that_is_not_base64_is_refused_not_a_500(store, pki_dir):
    """OVER-DETERMINED, deliberately recorded as such: removing the strict base64 decode
    fails no test, because garbage decodes to bytes that then fail the signature check.
    What this pins is that malformed input is a 403 and never a 500 -- the decode guard
    exists for a log line that points at the real problem, not as a separate boundary."""
    c = client(store, pki_dir)
    queued(store)
    r = open_session(c, pki_dir, "alpha", signature="!!! not base64 !!!")
    assert r.status_code == 403, r.text
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_tier_grant_is_enforced(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    assert _claim(c, pki_dir, "alpha", engine="clamav", tier="wireguard").status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED
    assert _claim(c, pki_dir, "alpha", engine="clamav", tier="socks").status_code == 200


class TestWithoutAPkiNothingChanges:
    """The routes must not exist at all. A route that waves everyone through is
    indistinguishable from this feature working, which is the failure mode #178 is about."""

    def test_no_ca_means_the_routes_are_not_mounted(self, store, tmp_path):
        app = FastAPI()
        assert register_node_claim_routes(
            app, job_store=store, pki_dir=tmp_path / "nothing-here") is False
        c = TestClient(app)
        assert c.get("/v1/nodes/challenge").status_code == 404
        assert c.post("/v1/nodes/claim", json={}).status_code == 404

    def test_an_empty_directory_is_not_a_pki(self, store, tmp_path):
        """A host that merely has the package installed has the directory. Arming on its
        existence would register routes that can verify nobody, refusing every node on a
        deployment that never opted in."""
        empty = tmp_path / "pki"
        empty.mkdir()
        app = FastAPI()
        assert register_node_claim_routes(app, job_store=store, pki_dir=empty) is False


class TestItIsActuallyWiredIntoTheApp:
    """A module nothing calls enforces nothing. `fix-79` recorded exactly this shape: a
    #80 hook that CascadingRuntime never forwarded, so the feature was inert in production
    while its own unit tests passed."""

    def test_build_app_mounts_the_routes_when_a_pki_exists(self, tmp_path, monkeypatch):
        from blastbox.host.ingress.app import build_app

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
        c = TestClient(build_app(job_store=InMemoryJobStore(), job_root=tmp_path / "jobs"))
        r = c.get("/v1/nodes/challenge")
        assert r.status_code == 200, r.text
        assert r.json()["scope"] == node_auth.SCOPE_CLAIM_NEXT

    def test_build_app_mounts_nothing_without_a_pki(self, tmp_path, monkeypatch):
        from blastbox.host.ingress.app import build_app

        monkeypatch.setenv("BLASTBOX_PKI_DIR", str(tmp_path / "absent"))
        c = TestClient(build_app(job_store=InMemoryJobStore(), job_root=tmp_path / "jobs"))
        assert c.get("/v1/nodes/challenge").status_code == 404


def test_the_module_does_not_overstate_what_it_enforces():
    """The docstring must keep saying that a node holding store credentials can walk around
    this. `dispatch` requires BLASTBOX_DATABASE_URL and calls claim_next() directly, so for
    such a node these routes are defence in depth, not a gate.

    This repo already has this test shape (`test_the_modules_say_accurately_which_half_is_
    wired`) because a banner nobody re-reads is how a partial control gets described as a
    complete one -- the exact defect class this area keeps producing. So the accuracy of
    the claim is asserted, not trusted."""
    import inspect

    from blastbox.host.ingress import node_claim

    doc = inspect.getdoc(node_claim) or ""
    assert "NOT PREVENTION FOR A NODE THAT HOLDS STORE CREDENTIALS" in doc, (
        "the limit was softened; if it has genuinely been closed, this test should be "
        "deleted in the same commit that closes it")
    assert "DEFENCE IN DEPTH" in doc
    # And the reason it is still true: nothing has removed the store from the claim path.
    import blastbox.host.dispatch as dispatch

    assert "claim_next" in inspect.getsource(dispatch), (
        "dispatch no longer claims from the store directly -- if nodes now claim only over "
        "HTTP, the limit above is closed and this test plus that docstring should change")


class TestTheSessionTokenIsNotACapability:
    """A token names a node. It must never carry what that node may do, or it becomes a
    capability that outlives the certificate it came from -- and revocation here IS
    "stop renewing the certificate"."""

    def test_no_token_is_refused(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        r = c.post("/v1/nodes/claim", json={"engine": "clamav"})
        assert r.status_code == 403
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_a_token_from_another_deployment_is_refused(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        forged = node_auth.issue_session("alpha", secret=b"another server's secret key!!!")
        r = _claim(c, pki_dir, "alpha", engine="clamav", token=forged)
        assert r.status_code == 403
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_a_token_naming_a_node_it_did_not_authenticate_is_refused(self, store, pki_dir):
        """Hand-editing the node id out of a valid token must not re-scope it."""
        c = client(store, pki_dir)
        queued(store, engine="boxjs")
        alpha_token = token_for(c, pki_dir, "alpha")
        _name, _, rest = alpha_token.partition(":")
        r = _claim(c, pki_dir, "beta", engine="boxjs", token="beta:" + rest)
        assert r.status_code == 403
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_an_expired_token_is_refused(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        stale = node_auth.issue_session(
            "alpha", secret=node_auth.challenge_secret(pki_dir),
            now=time.time() - node_auth.SESSION_TTL_S - 5)
        assert _claim(c, pki_dir, "alpha", engine="clamav",
                      token=stale).status_code == 403
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_revoking_the_certificate_takes_effect_WITHIN_the_session(self, store, pki_dir):
        """THE REASON THE TOKEN CARRIES NO GRANTS. The node holds a valid, unexpired token.
        Its certificate is then removed -- which is what revocation looks like here. The
        very next claim must be refused, not honoured until the token expires."""
        c = client(store, pki_dir)
        queued(store, engine="clamav")
        tok = token_for(c, pki_dir, "alpha")
        assert _claim(c, pki_dir, "alpha", engine="clamav", token=tok).status_code == 200

        queued(store, job_id="job-2", engine="clamav")
        (pki_dir / "node-alpha.crt").unlink()
        r = _claim(c, pki_dir, "alpha", engine="clamav", token=tok)
        assert r.status_code == 403, "a removed certificate still authorised work"
        assert store.get("job-2").status == JobStatus.QUEUED

    def test_narrowing_the_certificate_takes_effect_within_the_session(self, store, pki_dir):
        """Same property, the subtler half: the certificate is REPLACED with one granting
        less. The token is untouched and must not preserve the old grants."""
        c = client(store, pki_dir)
        tok = token_for(c, pki_dir, "alpha")
        queued(store, engine="clamav")
        assert _claim(c, pki_dir, "alpha", engine="clamav", token=tok).status_code == 200

        ca = pki.load_ca(pki_dir)
        ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
            engines=("boxjs",))).write(pki_dir, "node-alpha")
        queued(store, job_id="job-2", engine="clamav")
        r = _claim(c, pki_dir, "alpha", engine="clamav", token=tok)
        assert r.status_code == 403, "the token preserved grants the certificate withdrew"
        assert store.get("job-2").status == JobStatus.QUEUED


class TestANodeCanOnlyTouchTheJobItHolds:
    """The claim token is the ownership proof. Without this, a node with a valid session
    could write to any job in the queue -- including one another node is running."""

    def _claimed(self, c, pki_dir, store, engine="clamav", job_id="job-1"):
        queued(store, job_id=job_id, engine=engine)
        who = "alpha" if engine == "clamav" else "beta"
        r = _claim(c, pki_dir, who, engine=engine)
        assert r.status_code == 200, r.text
        body = r.json()
        return body["job"], body["receipt"], token_for(c, pki_dir, who)

    def test_the_holder_can_read_and_write_it(self, store, pki_dir):
        c = client(store, pki_dir)
        job, rcpt, tok = self._claimed(c, pki_dir, store)
        got = c.get(f"/v1/nodes/jobs/{job['job_id']}",
                    params={"claim_id": job["claim_id"], "receipt": rcpt},
                    headers=auth(tok))
        assert got.status_code == 200, got.text
        wrote = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                       json={"claim_id": job["claim_id"], "receipt": rcpt,
                             "fields": {"worker_runtime": "runc"}})
        assert wrote.status_code == 200, wrote.text
        assert store.get(job["job_id"]).worker_runtime == "runc"

    def test_a_wrong_claim_id_cannot_write(self, store, pki_dir):
        c = client(store, pki_dir)
        job, rcpt, tok = self._claimed(c, pki_dir, store)
        r = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                   json={"claim_id": "not-the-token", "receipt": rcpt,
                         "fields": {"error": "hijacked"}})
        assert r.status_code == 403
        assert store.get(job["job_id"]).error is None

    def test_a_node_granted_the_same_engine_still_cannot_write_to_it(self, store, pki_dir):
        """THE OWNERSHIP TEST, and it needs gamma rather than beta to mean anything.

        gamma is granted clamav exactly as alpha is, and holds a valid session -- so the
        grants re-check passes and the ONLY thing that can refuse this write is not holding
        the claim. Using beta (granted boxjs) instead made this test pass with the ownership
        check deleted, which is measured, not hypothetical."""
        c = client(store, pki_dir)
        job, rcpt, _tok = self._claimed(c, pki_dir, store)
        gamma = token_for(c, pki_dir, "gamma")
        r = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(gamma),
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "fields": {"error": "hijacked"}})
        assert r.status_code == 403, "a node wrote to a job it does not hold"
        assert store.get(job["job_id"]).error is None

    def test_a_node_granted_the_same_engine_cannot_read_it_either(self, store, pki_dir):
        c = client(store, pki_dir)
        job, rcpt, _tok = self._claimed(c, pki_dir, store)
        gamma = token_for(c, pki_dir, "gamma")
        r = c.get(f"/v1/nodes/jobs/{job['job_id']}",
                  params={"claim_id": job["claim_id"], "receipt": rcpt},
                  headers=auth(gamma))
        assert r.status_code == 403

    def test_a_job_it_does_not_own_reads_as_403_not_404(self, store, pki_dir):
        """404 would let a node enumerate the queue by probing ids."""
        c = client(store, pki_dir)
        _job, rcpt, tok = self._claimed(c, pki_dir, store)
        r = c.get("/v1/nodes/jobs/no-such-job",
                  params={"claim_id": "x", "receipt": "y"}, headers=auth(tok))
        assert r.status_code == 403

    def test_losing_the_cas_is_a_409_not_a_silent_success(self, store, pki_dir):
        c = client(store, pki_dir)
        job, rcpt, tok = self._claimed(c, pki_dir, store)
        r = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "expect_status": "queued", "fields": {"error": "stale"}})
        assert r.status_code == 409, r.text
        assert store.get(job["job_id"]).error is None

    def test_the_cas_applies_when_the_status_matches(self, store, pki_dir):
        c = client(store, pki_dir)
        job, rcpt, tok = self._claimed(c, pki_dir, store)
        r = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "expect_status": "running", "fields": {"worker_tier": "gvisor"}})
        assert r.status_code == 200, r.text
        assert store.get(job["job_id"]).worker_tier == "gvisor"

    def test_losing_the_grant_mid_run_stops_further_writes(self, store, pki_dir):
        """A certificate can lapse while a job is in flight. The grant must hold for the
        whole run, not only at the instant of the hand-over."""
        c = client(store, pki_dir)
        job, rcpt, tok = self._claimed(c, pki_dir, store)
        (pki_dir / "node-alpha.crt").unlink()
        r = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "fields": {"worker_runtime": "runc"}})
        assert r.status_code == 403
        assert store.get(job["job_id"]).worker_runtime is None
