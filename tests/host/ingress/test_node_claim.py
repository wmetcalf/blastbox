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


def _claim(c, pki_dir, who, *, engine, tier=None, challenge=None, sign_as=None,
           cert_of=None, signature=None):
    ch = challenge if challenge is not None else c.get("/v1/nodes/challenge").json()["challenge"]
    if signature is None:
        key = (pki_dir / f"node-{sign_as or who}.key").read_bytes()
        signature = base64.b64encode(node_auth.sign_claim(
            key, ch, node_auth.SCOPE_CLAIM_NEXT, who)).decode()
    cert = (pki_dir / f"node-{cert_of or who}.crt").read_bytes().decode()
    body = {"cert_pem": cert, "challenge": ch, "signature": signature, "engine": engine}
    if tier is not None:
        body["tier"] = tier
    return c.post("/v1/nodes/claim", json=body)


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


def test_a_node_presenting_a_peers_certificate_is_refused_and_the_job_stays_queued(
        store, pki_dir):
    """Node certs sit side by side in the pki dir, so reading a peer's .crt is trivial.
    Without the key it proves nothing."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    r = _claim(c, pki_dir, "alpha", engine="clamav", sign_as="beta")
    assert r.status_code == 403, r.text
    assert store.get("job-1").status == JobStatus.QUEUED


def test_the_refusal_does_not_say_why(store, pki_dir):
    """A caller must not be able to map the fleet's grants by probing. Every cause gives
    the same message; the reason goes to the server log."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    ungranted = _claim(c, pki_dir, "beta", engine="clamav")
    unheld_key = _claim(c, pki_dir, "alpha", engine="clamav", sign_as="beta")
    assert ungranted.json()["detail"] == unheld_key.json()["detail"]
    body = ungranted.text.lower()
    for leak in ("clamav", "boxjs", "grant", "signature", "certificate", "expired"):
        assert leak not in body, f"the refusal leaked {leak!r}: {ungranted.text}"


def test_no_work_is_204_not_404(store, pki_dir):
    """404 would be indistinguishable from the routes not being mounted, which is exactly
    when a node should fall back to claiming from the store directly."""
    c = client(store, pki_dir)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 204, r.text


def test_an_expired_challenge_is_refused(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    stale = node_auth.challenge_for(
        node_auth.SCOPE_CLAIM_NEXT, secret=node_auth.challenge_secret(pki_dir),
        now=time.time() - node_auth.CHALLENGE_TTL_S - 5)
    r = _claim(c, pki_dir, "alpha", engine="clamav", challenge=stale)
    assert r.status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_forged_challenge_is_refused(store, pki_dir):
    c = client(store, pki_dir)
    queued(store)
    forged = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=b"someone else's")
    r = _claim(c, pki_dir, "alpha", engine="clamav", challenge=forged)
    assert r.status_code == 403
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
    r = c.post("/v1/nodes/claim", json={
        "cert_pem": (rogue_dir / "node-alpha.crt").read_text(), "challenge": ch,
        "signature": sig, "engine": "clamav"})
    assert r.status_code == 403
    assert store.get("job-1").status == JobStatus.QUEUED


def test_a_signature_that_is_not_base64_is_refused_not_a_500(store, pki_dir):
    """OVER-DETERMINED, deliberately recorded as such: removing the strict base64 decode
    fails no test, because garbage decodes to bytes that then fail the signature check.
    What this pins is that malformed input is a 403 and never a 500 -- the decode guard
    exists for a log line that points at the real problem, not as a separate boundary."""
    c = client(store, pki_dir)
    queued(store)
    r = _claim(c, pki_dir, "alpha", engine="clamav", signature="!!! not base64 !!!")
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
