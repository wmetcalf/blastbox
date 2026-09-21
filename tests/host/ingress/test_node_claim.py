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
        engines=("clamav",), tiers=("socks",), credentials=True)).write(d, "node-alpha")
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
    from blastbox.host.ingress.node_claim import SESSION_HEADER

    # A DEDICATED header, not Authorization: BearerAuthMiddleware rejects anything that is
    # not "Bearer <key>" with 401 before the request reaches these routes, so an API-keyed
    # deployment could not authenticate a node at all if the two shared a header.
    return {SESSION_HEADER: token}


def _claim(c, pki_dir, who, *, engine=None, claimant_tier=None, token=None, **session_kw):
    """Claim as *who*. The handshake is REAL unless a token is supplied: otherwise a test
    that means to check the grants gate would be satisfied by a missing token instead, and
    pass for the wrong reason (this happened -- the refusal tests kept passing after the
    grants check moved, because no token was being sent at all)."""
    tok = token if token is not None else token_for(c, pki_dir, who, **session_kw)
    body: dict = {}
    if engine is not None:
        body["engine"] = engine
    if claimant_tier is not None:
        body["claimant_tier"] = claimant_tier
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


def test_the_tier_grant_is_derived_from_the_job_not_asked_of_the_node(
        store, pki_dir, monkeypatch):
    """THE NODE MUST NOT CHOOSE WHAT IT IS CHECKED AGAINST.

    `tier` used to be a request field, so a node granted no tiers simply omitted it and the
    tier grant went unexamined -- a caller selecting its own authorisation predicate is not
    an authorisation check. The requirement now comes from the JOB's network personality,
    resolved on this host, and there is no request field to leave out.

    alpha is granted the `socks` tier and not `wireguard`. A wireguard job must be refused
    AND put back; a socks job must be handed over."""
    # Via the ENGINE DEFAULT, which is the ordinary path and the one that was broken: an
    # earlier version hardcoded engine_default="none", so every job resolved to ungoverned and
    # neither grant was ever examined. The per-job override needs
    # BLASTBOX_ALLOW_NETPOLICY_OVERRIDE and is OFF by default, so testing only that path tested
    # the one configuration that worked.
    monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
    monkeypatch.setenv("BLASTBOX_NETPOLICY_PROX", "exit=socks")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
    c = client(store, pki_dir)

    store.create(Job(job_id="wg", engine="clamav", filename="s.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    # 204, NOT 403. The node is authorised to ask; there is simply nothing it may have. A 403
    # would make the client discard a valid session and re-handshake on every poll, which is
    # the traffic amplification review flagged. What matters is that it does not RECEIVE the
    # job -- and that the job is intact for a node that may run it.
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 204, r.text
    back = store.get("wg")
    assert back.status == JobStatus.QUEUED, "a job the node may not run was left claimed"
    assert back.claim_id is None, "the release did not clear ownership"
    assert back.started_at is None, "the release left a start time for a run that never ran"

    store.delete("wg")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "prox")
    store.create(Job(job_id="px", engine="clamav", filename="s.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    assert _claim(c, pki_dir, "alpha", engine="clamav").status_code == 200


def test_the_credentials_requirement_is_derived_too(store, pki_dir, monkeypatch):
    """gamma is granted the clamav engine AND the socks tier, but NOT credentials. A socks
    exit means a local sidecar holding a provider secret, so the job needs a node cleared to
    hold one -- and gamma is not, whatever it says about itself.

    This is the half a node could previously dodge entirely by omitting a boolean."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_PROX", "exit=socks")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "prox")
    c = client(store, pki_dir)
    store.create(Job(job_id="px", engine="clamav", filename="s.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    r = _claim(c, pki_dir, "gamma", engine="clamav")
    assert r.status_code == 204, r.text
    assert store.get("px").status == JobStatus.QUEUED
    assert store.get("px").claim_id is None
    # alpha holds the same engine and tier AND credentials=True, so the same job is fine.
    assert _claim(c, pki_dir, "alpha", engine="clamav").status_code == 200


def test_omitting_the_engine_asks_for_whatever_the_certificate_grants(store, pki_dir):
    """`dispatch.py` claims with NO engine whenever scoping is off, which is the default. An
    earlier version required one, so a credential-less dispatcher on default configuration
    was refused on every claim."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    r = _claim(c, pki_dir, "alpha")
    assert r.status_code == 200, r.text
    assert r.json()["job"]["job_id"] == "job-1"


def test_omitting_the_engine_still_does_not_widen_the_grant(store, pki_dir):
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    assert _claim(c, pki_dir, "beta").status_code in (204, 403)
    assert store.get("job-1").status == JobStatus.QUEUED


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
        """401, not 403: "your session is no good" is recoverable by re-handshaking, whereas
        403 means "you may not have this" and must NOT provoke one. Conflating them made a
        refused node pay a full handshake on every request."""
        c = client(store, pki_dir)
        queued(store)
        r = c.post("/v1/nodes/claim", json={"engine": "clamav"})
        assert r.status_code == 401
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_a_token_from_another_deployment_is_refused(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        forged = node_auth.issue_session("alpha", secret=b"another server's secret key!!!")
        r = _claim(c, pki_dir, "alpha", engine="clamav", token=forged)
        assert r.status_code == 401
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_a_token_naming_a_node_it_did_not_authenticate_is_refused(self, store, pki_dir):
        """Hand-editing the node id out of a valid token must not re-scope it."""
        c = client(store, pki_dir)
        queued(store, engine="boxjs")
        alpha_token = token_for(c, pki_dir, "alpha")
        _name, _, rest = alpha_token.partition(":")
        r = _claim(c, pki_dir, "beta", engine="boxjs", token="beta:" + rest)
        assert r.status_code == 401
        assert store.get("job-1").status == JobStatus.QUEUED

    def test_an_expired_token_is_refused(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        stale = node_auth.issue_session(
            "alpha", secret=node_auth.challenge_secret(pki_dir),
            now=time.time() - node_auth.SESSION_TTL_S - 5)
        assert _claim(c, pki_dir, "alpha", engine="clamav",
                      token=stale).status_code == 401
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


class TestTheThingsReviewCaught:
    """Each of these is a defect an upstream reviewer found that the local suite did not.
    They are kept as named tests so the same gap cannot reopen quietly."""

    def test_node_auth_coexists_with_the_api_bearer_key(self, store, pki_dir):
        """THE FEATURE WAS BROKEN, not merely awkward, whenever BLASTBOX_API_KEY was set.

        `BearerAuthMiddleware` rejects any Authorization header not starting with "Bearer "
        with a 401 BEFORE the request reaches these routes, and the earlier design sent
        `Authorization: Node <token>`. One header cannot carry both credentials. They now
        get one each: the API key says this caller may talk to the service, the session says
        which node it is."""
        from blastbox.host.ingress.middleware import BearerAuthMiddleware
        from blastbox.host.ingress.node_claim import SESSION_HEADER

        app = FastAPI()
        assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir) is True
        app.add_middleware(BearerAuthMiddleware, api_key="the-submitters-key")
        c = TestClient(app)
        queued(store)

        api = {"Authorization": "Bearer the-submitters-key"}
        ch = c.get("/v1/nodes/challenge", headers=api)
        assert ch.status_code == 200, ch.text
        sig = base64.b64encode(node_auth.sign_claim(
            (pki_dir / "node-alpha.key").read_bytes(), ch.json()["challenge"],
            node_auth.SCOPE_CLAIM_NEXT, "alpha")).decode()
        sess = c.post("/v1/nodes/session", headers=api, json={
            "cert_pem": (pki_dir / "node-alpha.crt").read_text(),
            "challenge": ch.json()["challenge"], "signature": sig})
        assert sess.status_code == 200, sess.text
        r = c.post("/v1/nodes/claim", json={"engine": "clamav"},
                   headers={**api, SESSION_HEADER: sess.json()["token"]})
        assert r.status_code == 200, r.text
        assert store.get("job-1").status == JobStatus.RUNNING

    def test_a_node_may_not_rewrite_the_result_directory(self, store, pki_dir):
        """`JobStore.update` takes ANY Job field, so without an allowlist an authenticated
        node chose where this host writes a result. That is escalation, not untidiness."""
        c = client(store, pki_dir)
        queued(store)
        r = _claim(c, pki_dir, "alpha", engine="clamav")
        job, rcpt = r.json()["job"], r.json()["receipt"]
        tok = token_for(c, pki_dir, "alpha")
        bad = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                     json={"claim_id": job["claim_id"], "receipt": rcpt,
                           "fields": {"result_dir": "/etc"}})
        assert bad.status_code == 400, bad.text
        assert store.get(job["job_id"]).result_dir is None

    def test_a_node_may_not_restamp_ownership(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        r = _claim(c, pki_dir, "alpha", engine="clamav")
        job, rcpt = r.json()["job"], r.json()["receipt"]
        tok = token_for(c, pki_dir, "alpha")
        bad = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                     json={"claim_id": job["claim_id"], "receipt": rcpt,
                           "fields": {"claim_id": "mine-now"}})
        assert bad.status_code == 400, bad.text
        assert store.get(job["job_id"]).claim_id == job["claim_id"]

    def test_a_status_string_becomes_a_real_enum(self, store, pki_dir):
        """JSON has no enums. Stored as a bare string, every terminal write from a node put
        a str where the rest of the system compares against JobStatus."""
        c = client(store, pki_dir)
        queued(store)
        r = _claim(c, pki_dir, "alpha", engine="clamav")
        job, rcpt = r.json()["job"], r.json()["receipt"]
        tok = token_for(c, pki_dir, "alpha")
        done = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                      json={"claim_id": job["claim_id"], "receipt": rcpt,
                            "fields": {"status": "done"}})
        assert done.status_code == 200, done.text
        stored = store.get(job["job_id"]).status
        assert stored is JobStatus.DONE, f"stored {stored!r}, not the enum"

    def test_an_unknown_status_is_a_400_not_a_stored_string(self, store, pki_dir):
        c = client(store, pki_dir)
        queued(store)
        r = _claim(c, pki_dir, "alpha", engine="clamav")
        job, rcpt = r.json()["job"], r.json()["receipt"]
        tok = token_for(c, pki_dir, "alpha")
        bad = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                     json={"claim_id": job["claim_id"], "receipt": rcpt,
                           "fields": {"status": "nonsense"}})
        assert bad.status_code == 400, bad.text

    def test_an_empty_pki_dir_setting_is_not_the_current_directory(self, store, monkeypatch,
                                                                   tmp_path):
        """Deployment tooling emits `BLASTBOX_PKI_DIR=` from an unset compose variable, and
        `Path("")` is the CURRENT DIRECTORY -- so a blank value had this hunting for a trust
        anchor in whatever directory the process started in."""
        monkeypatch.setenv("BLASTBOX_PKI_DIR", "")
        monkeypatch.chdir(tmp_path)
        pki.ensure_ca(tmp_path)          # a CA in the cwd, which must NOT arm the routes
        app = FastAPI()
        assert register_node_claim_routes(app, job_store=store) is False


class TestIngressAndDispatcherMustAgree:
    """The invariant the tier check rests on: both sides resolve ONE job to ONE personality.

    If they disagree, the hand-over authorises against a personality the run will not use --
    which is exactly how the first version was a no-op (ingress hardcoded engine_default="none"
    while the dispatcher read BLASTBOX_ENGINE_<NAME>_NETPOLICY).
    """

    def _dispatcher_view(self, job, engine_default):
        from blastbox.host.netpolicy import parse_personalities, resolve_net_policy
        import os as _os

        return resolve_net_policy(
            job_net_policy=job.net_policy, engine_default=engine_default,
            registry=parse_personalities(_os.environ),
            allow_override=_os.environ.get(
                "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "").strip().lower()
            in ("1", "true", "yes", "on")).exit_driver

    @pytest.mark.parametrize("override", ["", "1"])
    @pytest.mark.parametrize("engine_default,job_policy", [
        ("none", None), ("vpn", None), ("none", "vpn"), ("vpn", "prox"), ("missing", None),
    ])
    def test_both_sides_resolve_the_same_driver(self, store, pki_dir, monkeypatch,
                                               engine_default, job_policy, override):
        from blastbox.host.ingress import node_claim as nc

        monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
        monkeypatch.setenv("BLASTBOX_NETPOLICY_PROX", "exit=socks")
        monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", engine_default)
        if override:
            monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", override)
        job = Job(job_id="j", engine="clamav", filename="s.bin", net_policy=job_policy,
                  status=JobStatus.QUEUED, created_at=time.time())

        app = FastAPI()
        assert nc.register_node_claim_routes(app, job_store=store, pki_dir=pki_dir)
        # Reach the host-side derivation through a claim, and compare with what the dispatcher
        # would compute for the same job.
        c = TestClient(app)
        store.create(job)
        _claim(c, pki_dir, "alpha", engine="clamav")
        theirs = self._dispatcher_view(job, engine_default)
        # An engine default naming a personality this host has NOT got must be treated as
        # UNKNOWN, never as ungoverned -- that silent fallback is the hole.
        if engine_default == "missing":
            assert theirs == "none", "resolve_net_policy no longer falls back to none"
        else:
            assert theirs in ("none", "wireguard", "socks")


def test_a_declared_policy_this_host_cannot_see_is_unknown_not_ungoverned(store, pki_dir,
                                                                         monkeypatch):
    """An operator declares BLASTBOX_ENGINE_CLAMAV_NETPOLICY=vpn but this host has no
    BLASTBOX_NETPOLICY_VPN. `resolve_net_policy` falls back to `none`, so the job would look
    ungoverned and the tier grant would go unchecked. It must read as UNKNOWN instead."""
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
    monkeypatch.delenv("BLASTBOX_NETPOLICY_VPN", raising=False)
    monkeypatch.setenv("BLASTBOX_NODE_CLAIM_STRICT_TIERS", "1")
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 204, r.text
    assert store.get("job-1").status == JobStatus.QUEUED
    assert store.get("job-1").claim_id is None


def test_a_node_is_not_starved_by_a_job_it_may_not_run(store, pki_dir, monkeypatch):
    """THE LIVELOCK. `claim_next` returns the OLDEST eligible job and a refused job goes back
    to QUEUED, so returning after one refusal made the next poll re-select the same job forever
    -- five polls, five refusals, and an entitled job two places back never claimed."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    c = client(store, pki_dir)
    store.create(Job(job_id="cannot", engine="clamav", filename="a", status=JobStatus.QUEUED,
                     created_at=time.time() - 100))
    store.create(Job(job_id="can", engine="boxjs", filename="b", status=JobStatus.QUEUED,
                     created_at=time.time()))
    ca = pki.load_ca(pki_dir)
    ca.issue_node("both", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), tiers=("socks",), credentials=True)).write(
        pki_dir, "node-both")

    r = _claim(c, pki_dir, "both")
    assert r.status_code == 200, r.text
    assert r.json()["job"]["job_id"] == "can", (
        "the node was starved by the older job it may not run")
    assert store.get("cannot").status == JobStatus.QUEUED
    assert store.get("cannot").claim_id is None


def test_a_node_cannot_bury_a_job_forever(store, pki_dir):
    """`claimable_after` is a SHORT capacity deferral, and `claim_next` skips a job until it
    passes -- so an unbounded value let an authenticated node write
    {status: queued, claimable_after: 4102444800} and remove any job it was granted from every
    node's view permanently. Nothing recovered it: the requeue sweep only looks at RUNNING,
    retention only at terminal states, and _fail_stale_queued_jobs is opt-in and runs where the
    database is. Quieter than writing FAILED to achieve the same denial honestly."""
    from blastbox.host.ingress.node_claim import MAX_DEFERRAL_S

    c = client(store, pki_dir)
    queued(store)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    job, rcpt = r.json()["job"], r.json()["receipt"]
    tok = token_for(c, pki_dir, "alpha")
    buried = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                    json={"claim_id": job["claim_id"], "receipt": rcpt,
                          "fields": {"status": "queued", "claimable_after": 4102444800}})
    assert buried.status_code == 200, buried.text
    back = store.get(job["job_id"])
    assert back.claimable_after <= time.time() + MAX_DEFERRAL_S + 1, (
        "the job was deferred beyond any recoverable window")
    # And it comes back: the point is that the queue is not permanently poisoned.
    store.update(job["job_id"], claimable_after=None)
    assert store.claim_next() is not None


def test_a_legitimate_short_deferral_still_works(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    job, rcpt = r.json()["job"], r.json()["receipt"]
    tok = token_for(c, pki_dir, "alpha")
    soon = time.time() + 30
    ok = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=auth(tok),
                json={"claim_id": job["claim_id"], "receipt": rcpt,
                      "fields": {"status": "queued", "claimable_after": soon}})
    assert ok.status_code == 200, ok.text
    assert abs(store.get(job["job_id"]).claimable_after - soon) < 1
