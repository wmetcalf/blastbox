"""Regressions for the external panel's findings on #178 head 0985e2d, each reproduced first."""
from __future__ import annotations

import base64
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.middleware import BearerAuthMiddleware
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.http_store import HttpJobStore
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def keyed(tmp_path, monkeypatch):
    """An API-keyed control plane and a node client that does NOT know the key."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        d, "node-n")
    store = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d)
    app.add_middleware(BearerAuthMiddleware, api_key="submitters-only")
    c = TestClient(app)

    def transport(method, path, *, json=None, params=None, headers=None):
        r = c.request(method, path, json=json, params=params, headers=headers or {})
        return r.status_code, (r.json() if r.content else None)

    return c, store, HttpJobStore("https://cp", cert_path=d / "node-n.crt", transport=transport)


def test_a_node_needs_no_api_key(keyed):
    """The client never sent Authorization, so an API-keyed control plane 401'd every node
    before the routes were reached. The node routes authenticate with a certificate and a
    session -- stronger than the key and orthogonal to it -- and are exempt."""
    c, store, node = keyed
    store.create(Job(job_id="j", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    job = node.claim_next(engine="clamav")
    assert job is not None and job.job_id == "j"


def test_the_submitter_routes_still_require_the_key(keyed):
    """The exemption is a PREFIX, not a disarm: anything outside /v1/nodes/ still needs the key
    (the middleware runs before routing, so an unknown path is 401 before it is 404)."""
    c, _store, _node = keyed
    assert c.get("/v1/jobs").status_code == 401
    assert c.post("/v1/jobs", files={"file": ("a", b"x")}).status_code == 401
    assert c.get("/v1/nodes/challenge").status_code == 200


def _rig(tmp_path, monkeypatch):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        d, "node-n")
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
    store.create(Job(job_id="j", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    from blastbox.host.ingress.node_claim import SESSION_HEADER
    r = c.post("/v1/nodes/claim", json={}, headers={SESSION_HEADER: tok})
    assert r.status_code == 200, r.text
    return c, store, {SESSION_HEADER: tok}, r.json()["job"], r.json()["receipt"]


@pytest.mark.parametrize("fields", [
    {"started_at": "not-a-time"}, {"finished_at": "soon"}, {"expires_at": "inf"},
    {"expires_at": -5}, {"started_at": True},
    {"materialise_attempts": "many"}, {"materialise_attempts": -1},
    {"error": "x" * 9000}, {"worker_runtime": ["runc"]}, {"input_sha256": "nothex"},
    {"result_summary": "a string"}, {"security_warnings": "one"},
    {"security_warnings": [1, 2]},
])
def test_a_value_the_store_would_accept_and_readers_would_choke_on_is_refused(
        tmp_path, monkeypatch, fields):
    """With SQLite, started_at='not-a-time' was STORED, and every later read of that job raised
    converting it back -- the reclaim sweep, the listing, the API. One write from one node made
    a row unreadable to the whole fleet."""
    c, store, h, job, rcpt = _rig(tmp_path, monkeypatch)
    w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
               json={"claim_id": job["claim_id"], "receipt": rcpt, "fields": fields})
    assert w.status_code == 400, (fields, w.text)
    assert store.get("j").status == JobStatus.RUNNING


def test_a_well_typed_terminal_write_still_works(tmp_path, monkeypatch):
    c, store, h, job, rcpt = _rig(tmp_path, monkeypatch)
    now = time.time()
    w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
               json={"claim_id": job["claim_id"], "receipt": rcpt, "expect_status": "running",
                     "fields": {"status": "done", "finished_at": now, "expires_at": now + 60,
                                "result_summary": {"detected": True},
                                "security_warnings": ["x"], "error": None,
                                "input_sha256": "a" * 64, "materialise_attempts": 0}})
    assert w.status_code == 200, w.text
    assert store.get("j").status is JobStatus.DONE


def test_the_receipt_travels_in_headers_not_the_url(tmp_path, monkeypatch):
    c, _store, h, job, rcpt = _rig(tmp_path, monkeypatch)
    ok = c.get(f"/v1/nodes/jobs/{job['job_id']}",
               headers={**h, "x-blastbox-claim-id": job["claim_id"], "x-blastbox-receipt": rcpt})
    assert ok.status_code == 200, ok.text
    leaked = c.get(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
                   params={"claim_id": job["claim_id"], "receipt": rcpt})
    assert leaked.status_code == 403, "the query-string form must not be honoured"


class TestReceiptEvictionKeepsLiveJobs:
    def test_settled_entries_are_evicted_before_running_ones(self, tmp_path):
        from blastbox.host.jobs import http_store as hs

        d = tmp_path / "pki"
        ca = pki.ensure_ca(d)
        ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
            d, "node-n")
        s = HttpJobStore("https://cp", cert_path=d / "node-n.crt",
                         transport=lambda *a, **k: (500, None))
        s._claims["live-old"] = ("c", "r")            # oldest, still RUNNING
        for i in range(hs._MAX_TRACKED_CLAIMS + 5):
            s._claims[f"done-{i}"] = ("c", "r")
            s._settled.add(f"done-{i}")
        s._retire_if_settled("done-0", None)
        assert "live-old" in s._claims, "a live job's receipt was evicted while settled ones stayed"


def test_serve_tls_sans_for_a_wildcard_bind_are_real_names(monkeypatch):
    """--host 0.0.0.0 used to become the SAN -- a name no client connects to -- so every node
    refused the certificate. The machine's own names go in, plus BLASTBOX_TLS_SANS."""
    from blastbox.host.cli import _serve_tls_sans

    monkeypatch.setenv("BLASTBOX_TLS_SANS", "cp.example.internal, lb.example")
    sans = _serve_tls_sans("0.0.0.0")
    assert "0.0.0.0" not in sans
    assert sans[:2] == ["cp.example.internal", "lb.example"]
    assert "localhost" in sans and "127.0.0.1" in sans
    monkeypatch.delenv("BLASTBOX_TLS_SANS")
    assert _serve_tls_sans("10.0.0.5")[0] == "10.0.0.5"


def test_ingress_retention_is_gated_on_retention_and_carries_the_blob_store():
    """Gated on the reclaim variable (unrelated) and built WITHOUT a blob store, the sweep
    stamped EXPIRED and left every durable result object in place -- expiry in name only."""
    import inspect

    from blastbox.host.ingress import app

    src = inspect.getsource(app)
    assert "JobRetentionSweeper(_job_root, blob_store=_blob_store)" in src
    assert 'BLASTBOX_JOB_RETENTION_SECONDS' in src


class TestRoundFour:
    """Round four. Two of these were mine, introduced by round three's own fixes."""

    def test_a_node_can_actually_release_a_job(self, tmp_path, monkeypatch):
        """THREE INDEPENDENT FAMILIES found this, and it broke the feature outright: the
        release check compared the WIRE value -- the string "queued" -- against the JobStatus
        enum, because it ran BEFORE the conversion. It never matched, so every release was a
        400 and a node could never hand work back."""
        c, store, h, job, rcpt = _rig(tmp_path, monkeypatch)
        w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "fields": {"status": "queued", "claim_id": None}})
        assert w.status_code == 200, w.text
        back = store.get("j")
        assert back.status is JobStatus.QUEUED
        assert back.claim_id is None
        assert back.claimable_after is not None, "a release must carry the deferral"

    def test_clearing_the_claim_without_queueing_is_still_refused(self, tmp_path, monkeypatch):
        """The release semantics must survive the reordering: claim_id=None on its own left a
        job RUNNING with no owner -- unclaimable, unwritable and unreclaimable."""
        c, store, h, job, rcpt = _rig(tmp_path, monkeypatch)
        w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
                   json={"claim_id": job["claim_id"], "receipt": rcpt,
                         "fields": {"claim_id": None}})
        assert w.status_code == 400, w.text
        assert store.get("j").claim_id == job["claim_id"]

    def test_the_grants_cache_cannot_outlive_certificate_expiry(self, tmp_path, monkeypatch):
        """MY REGRESSION, from caching fleet_grants to stop a per-request CPU DoS. The cache key
        was (name, mtime, size) of every *.crt -- and a certificate that EXPIRES changes none of
        those, so a lapsed identity kept authorising indefinitely. Removal and replacement do
        change the signature; expiry needs a clock, which is why the TTL is the correctness of
        the cache and not a nicety."""
        from blastbox.host.ingress import node_claim as nc

        assert nc._GRANTS_CACHE_TTL_S > 0
        src = __import__("inspect").getsource(nc)
        assert 'now >= _grants_cache["until"]' in src, (
            "the grants cache no longer has a deadline, so expiry stops being a revocation "
            "mechanism")

    def test_the_claim_map_is_evicted_under_the_lock(self):
        """A dispatcher claims and reports from several threads; scanning _claims for a victim
        unlocked raises "dictionary changed size during iteration" -- inside a terminal write,
        which loses the job's result."""
        import inspect

        from blastbox.host.jobs import http_store as hs

        src = inspect.getsource(hs.HttpJobStore._retire_if_settled)
        assert "with self._lock:" in src
        assert "for k in self._claims" not in src, "still iterating outside the lock"

    def test_the_claim_map_survives_concurrent_claims(self, tmp_path):
        """Exercise it rather than trusting the read: many threads settling while the map is at
        its bound."""
        import threading

        from blastbox.host.jobs import http_store as hs

        d = tmp_path / "pki"
        ca = pki.ensure_ca(d)
        ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
            d, "node-n")
        s = HttpJobStore("https://cp", cert_path=d / "node-n.crt",
                         transport=lambda *a, **k: (500, None))
        for i in range(hs._MAX_TRACKED_CLAIMS + 200):
            s._claims[f"j{i}"] = ("c", "r")
            s._settled.add(f"j{i}")
        errors: list[BaseException] = []

        def churn(base):
            try:
                for i in range(200):
                    s._claims[f"new{base}-{i}"] = ("c", "r")
                    s._retire_if_settled(f"new{base}-{i}", None)
            except BaseException as exc:      # noqa: BLE001 - the failure IS the assertion
                errors.append(exc)

        threads = [threading.Thread(target=churn, args=(b,)) for b in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"concurrent eviction raised: {errors[:1]!r}"
