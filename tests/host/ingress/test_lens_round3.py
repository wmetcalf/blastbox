"""Regressions for the adversarial lenses on #178. Each was reproduced before it was fixed."""
from __future__ import annotations

import base64
import logging
import os
import time
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.http_store import HttpJobStore
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import reap_stale_scratch

WG = "A" * 42 + "B="


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        d, "node-n")
    backing = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=backing, pki_dir=d)
    c = TestClient(app)

    def transport(method, path, *, json=None, params=None, headers=None):
        r = c.request(method, path, json=json, params=params, headers=headers or {})
        return r.status_code, (r.json() if r.content else None)

    node = HttpJobStore("https://cp", cert_path=d / "node-n.crt", transport=transport)
    return d, backing, node


def _aged_tree(root, job_id):
    t = root / job_id
    (t / "input").mkdir(parents=True)
    (t / "input" / "sample.exe").write_text("untrusted")
    old = time.time() - 100_000
    for f in list(t.rglob("*"))[::-1] + [t]:
        os.utime(f, (old, old))
    return t


def test_a_node_can_still_reclaim_its_own_disk_after_a_restart(fleet, tmp_path):
    """THE NODE'S ONLY DISK BOUND. `reap_stale_scratch` walks the node's OWN job_root and asks
    the store whether each tree's job is terminal. When `get()` raised for everything this
    process holds no receipt for — which is EVERY job after a restart — the reaper treated them
    all as unconfirmed and skipped them, so job_root grew without bound with untrusted samples
    still on disk. Issue #84's class, on the topology this branch creates."""
    _d, backing, node = fleet
    root = tmp_path / "scratch"
    root.mkdir()
    done = str(uuid.uuid4())
    backing.create(Job(job_id=done, engine="clamav", filename="s", status=JobStatus.DONE,
                       created_at=time.time() - 100_000))
    _aged_tree(root, done)

    class Durable:
        """The result IS in the blob store, so the local tree is not the last copy. Without
        this the reaper correctly retains it -- my first version of this test passed
        blob_store=None and blamed the code for the sweep's own last-copy protection."""

        def has_output(self, job_id):
            return True

    reap_stale_scratch(root, 60.0, node, logging.getLogger("t"), blob_store=Durable())
    assert not (root / done).exists(), "a terminal job's tree was never reclaimable"


def test_but_a_live_job_is_still_left_alone(fleet, tmp_path):
    _d, backing, node = fleet
    root = tmp_path / "scratch"
    root.mkdir()
    live = str(uuid.uuid4())
    backing.create(Job(job_id=live, engine="clamav", filename="s", status=JobStatus.RUNNING,
                       created_at=time.time() - 100_000, claim_id="node:someone"))
    _aged_tree(root, live)
    reap_stale_scratch(root, 60.0, node, logging.getLogger("t"), blob_store=None)
    assert (root / live).exists(), "reclaimed a tree whose job is still RUNNING"


def test_the_disposition_answer_is_truthful_so_peer_data_is_still_safe(fleet):
    """The original data-destruction bug was `get()` returning None for 'not yours', which
    dispatch reads as 'gone, safe to delete'. The fallback must return the REAL claim_id so the
    ownership gates still see a mismatch — truthful, not absent, and not a blanket raise."""
    _d, backing, node = fleet
    backing.create(Job(job_id="peer", engine="clamav", filename="s", status=JobStatus.RUNNING,
                       created_at=time.time(), claim_id="node:held-by-someone-else"))
    got = node.get("peer")
    assert got is not None, "told the caller the job was gone"
    assert got.claim_id == "node:held-by-someone-else"
    assert got.status is JobStatus.RUNNING


def test_a_genuinely_absent_job_is_none(fleet):
    _d, _backing, node = fleet
    assert node.get(str(uuid.uuid4())) is None


def test_the_disposition_ROUTE_leaks_no_content(fleet, tmp_path):
    """ASSERTS THE HTTP RESPONSE, not the client.

    The first version of this test checked `node.get(...)` for empty engine/filename/result_dir
    -- but `http_store.get` HARDCODES those three when it builds the sparse Job, so the assertion
    held whatever the route returned. Widening the route's body to include engine, filename,
    result_dir and params left the whole suite green (measured). The response is the real
    boundary: a node holds a session token and can call the route directly."""
    d, backing, _node = fleet
    backing.create(Job(job_id="secret", engine="clamav", filename="victim-sample.exe",
                       status=JobStatus.DONE, created_at=time.time(),
                       result_dir="/srv/private/secret", params={"key": "value"}))
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=backing, pki_dir=d)
    c = TestClient(app)
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
    tok = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig}
    ).json()["token"]
    r = c.get("/v1/nodes/jobs/secret/disposition", headers={SESSION_HEADER: tok})
    assert r.status_code == 200, r.text
    body = r.json()["job"]
    assert set(body) == {"job_id", "status", "claim_id", "expires_at"}, (
        f"the disposition route returned more than it promises: {sorted(body)}")
    raw = r.text
    for leak in ("victim-sample.exe", "/srv/private/secret", "clamav", "value"):
        assert leak not in raw, f"the route body leaked {leak!r}"


class TestTheSweepsAreWiredBEHAVIOURALLY:
    """The two tests I wrote for this were `inspect.getsource` string greps. A grep cannot tell
    a live call from one behind a gate nobody sets — which is the exact defect they claim to
    guard, and which the lens demonstrated by disabling both gates with the suite still green.
    These drive the real lifespan and assert the sweeps RAN."""

    def _app(self, tmp_path, monkeypatch, **env):
        from blastbox.host.ingress.app import build_app

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("BLASTBOX_MAINTENANCE_INTERVAL_S", "0.05")
        calls: list[str] = []

        class Watched(InMemoryJobStore):
            def list(self, *a, **k):
                calls.append("list")
                return super().list(*a, **k)

        return build_app(job_store=Watched(), job_root=tmp_path / "jobs"), calls

    def test_the_reclaim_sweep_actually_runs(self, tmp_path, monkeypatch):
        app, calls = self._app(tmp_path, monkeypatch,
                               BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S="900",
                               BLASTBOX_SCRATCH_MAX_AGE_S="0")
        with TestClient(app):
            deadline = time.time() + 5
            while not calls and time.time() < deadline:
                time.sleep(0.05)
        assert calls, "the maintenance thread never swept (scratch reaping was off)"

    def test_retention_actually_runs_on_its_own_variable(self, tmp_path, monkeypatch):
        """Gated on the UNRELATED reclaim variable, BLASTBOX_JOB_RETENTION_SECONDS was a no-op
        again — the very thing moving retention to ingress was meant to fix."""
        monkeypatch.delenv("BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S", raising=False)
        app, calls = self._app(tmp_path, monkeypatch,
                               BLASTBOX_JOB_RETENTION_SECONDS="60",
                               BLASTBOX_SCRATCH_MAX_AGE_S="0")
        with TestClient(app):
            deadline = time.time() + 5
            while not calls and time.time() < deadline:
                time.sleep(0.05)
        assert calls, "retention never ran with only its own variable set"


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
    return c, store, {SESSION_HEADER: tok}, d


def test_an_unconditional_write_is_fenced_on_the_current_claim(tmp_path, monkeypatch):
    """The non-CAS path carries a deliberate fence and NOTHING tested it: swapping it for a
    plain update left the suite green. A stale owner's write must not land on a run the sweep
    already reassigned."""
    c, store, h, _d = _rig(tmp_path, monkeypatch)
    store.create(Job(job_id="j", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    job, rcpt = r.json()["job"], r.json()["receipt"]
    # The sweep reassigns it: same status, NEW claim id.
    store.update("j", claim_id="node:someone-else")
    w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
               json={"claim_id": job["claim_id"], "receipt": rcpt,
                     "fields": {"error": "stale owner"}})
    assert w.status_code == 403, w.text
    assert store.get("j").error is None, "a stale owner wrote to a reassigned run"


def test_a_failure_mid_walk_does_not_strand_claimed_jobs(tmp_path, monkeypatch):
    """The claim-walk's `finally` exists so a job claimed on probe N-1 is released when probe N
    raises. Nothing tested it: replacing `finally` with `else` left the suite green. A store
    blip mid-walk would otherwise leave jobs RUNNING with an owner nobody holds."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
    c, store, h, _d = _rig(tmp_path, monkeypatch)
    for i in range(3):
        store.create(Job(job_id=f"j{i}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time() + i))
    real, calls = store.claim_next, {"n": 0}

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("store blip")
        return real(**kw)

    store.claim_next = flaky
    with pytest.raises(RuntimeError):
        c.post("/v1/nodes/claim", json={}, headers=h)
    store.claim_next = real
    stranded = [j for j in (store.get(f"j{i}") for i in range(3))
                if j.status is JobStatus.RUNNING]
    assert not stranded, f"{len(stranded)} job(s) left RUNNING with no owner after a mid-walk failure"


class TestRoundFourAuthz:
    """Round four's authorisation lens. The first of these was mine, and it failed in exactly
    the way the tests it replaced did: I tested the helper and never the call site."""

    def test_the_sweeps_run_INSIDE_the_held_lock(self):
        """THE ELECTION WAS DECORATIVE. `with sweeper_lock(...) as mine: if not mine: continue`
        closed the context -- releasing the flock -- before any sweep ran, so the exclusion
        window was the few microseconds of open+flock+close and every worker swept anyway. My
        test asserted only that the HELPER excludes a second holder, which it always did."""
        import inspect
        import re

        from blastbox.host.ingress import app

        src = inspect.getsource(app)
        i = src.index("with sweeper_lock(_job_root) as _mine:")
        with_indent = len(re.match(r"\s*", src[src.rindex("\n", 0, i) + 1:]).group(0))
        for call in ("reap_stale_scratch(", "reclaim_stale_claims(", "fail_stale_queued(",
                     "expire_due("):
            j = src.index(call, i)
            ls = src.rindex("\n", 0, j) + 1
            indent = len(re.match(r"\s*", src[ls:]).group(0))
            assert indent > with_indent, (
                f"{call} runs OUTSIDE the held lock, so the election excludes nothing")

    def test_only_one_of_many_concurrent_sweepers_proceeds(self, tmp_path):
        """The call-site property, exercised rather than read: threads arriving while a sweep is
        in progress must be turned away, not merely threads arriving in the same microsecond."""
        import threading

        from blastbox.host.ingress.node_reclaim import sweeper_lock

        peak, live, errors = [0], [0], []
        lock = threading.Lock()

        def worker():
            try:
                with sweeper_lock(tmp_path) as mine:
                    if not mine:
                        return
                    with lock:
                        live[0] += 1
                        peak[0] = max(peak[0], live[0])
                    time.sleep(0.15)        # the sweep
                    with lock:
                        live[0] -= 1
            except BaseException as exc:    # noqa: BLE001
                errors.append(exc)

        threads = []
        for _ in range(4):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
            time.sleep(0.005)               # arrive 5 ms apart, mid-sweep
        for t in threads:
            t.join()
        assert not errors, errors[:1]
        assert peak[0] == 1, f"{peak[0]} workers swept concurrently"

    def test_a_deliberately_deferred_job_is_not_failed_as_abandoned(self):
        """A restricted node could poll until a governed job it cannot run was deferred over and
        over, and once it aged past the policy this sweep marked it FAILED and deleted another
        tenant's sample. Deferred means deliberate, not abandoned."""
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        store = InMemoryJobStore()
        store.create(Job(job_id="deferred", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000,
                         claimable_after=time.time() + 60))
        assert fail_stale_queued(store, max_age_s=3600.0) == 0
        assert store.get("deferred").status is JobStatus.QUEUED

    def test_a_failed_queued_job_is_reapable(self):
        """Without expires_at, `expire_due` skips the row forever -- trading a sample stuck
        QUEUED for a FAILED row and its tree stuck instead."""
        from blastbox.host.ingress.node_reclaim import fail_stale_queued

        store = InMemoryJobStore()
        store.create(Job(job_id="old", engine="clamav", filename="s.bin",
                         status=JobStatus.QUEUED, created_at=time.time() - 10_000))
        assert fail_stale_queued(store, max_age_s=3600.0, retention_s=86400.0) == 1
        assert store.get("old").expires_at is not None, "retention can never see this row"

    def test_the_refusal_deferral_cannot_be_renewed_without_bound(self, tmp_path, monkeypatch):
        """Nothing bounded how OFTEN a node could re-defer one job, so a restricted node could
        hold governed work away from the entitled peers the grants exist to route it to."""
        from blastbox.host.ingress import node_claim as nc

        monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
        monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
        monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "vpn")
        d = tmp_path / "pki"
        ca = pki.ensure_ca(d)
        ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
            d, "node-n")
        store = InMemoryJobStore()
        store.create(Job(job_id="gov", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time()))
        app = FastAPI()
        assert register_node_claim_routes(app, job_store=store, pki_dir=d)
        c = TestClient(app)
        ch = c.get("/v1/nodes/challenge").json()["challenge"]
        sig = base64.b64encode(node_auth.sign_claim(
            (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
        tok = c.post("/v1/nodes/session", json={
            "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig}
        ).json()["token"]
        # Past MAX_TOTAL_DEFERRAL_S from submission, no number of refusals may defer it again --
        # and that bound is on `created_at`, which every ingress worker and host reads the same
        # way. The earlier count-based version was per forked worker and per host, and this test
        # derived its loop count from the constant it was testing, so raising the cap raised the
        # loop with it and the suite stayed green.
        store.update("gov", created_at=time.time() - (nc.MAX_TOTAL_DEFERRAL_S + 1))
        for _ in range(5):
            store.update("gov", claimable_after=None)        # the deferral lapses
            c.post("/v1/nodes/claim", json={}, headers={SESSION_HEADER: tok})
            assert store.get("gov").claimable_after is None, (
                "the node kept renewing the deferral, starving entitled peers")

    def test_a_node_cannot_pin_or_destroy_a_result_with_expires_at(self, tmp_path, monkeypatch):
        """The one node-writable timestamp with no bound: 1e18 pinned a tenant's result beyond
        any policy, and a past value had the next retention tick delete it before the submitter
        could fetch it while the API reported success."""
        from blastbox.host.ingress.node_claim import MAX_RESULT_TTL_S

        c, store, h, _d = _rig(tmp_path, monkeypatch)
        store.create(Job(job_id="j", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time()))
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        assert r.status_code == 200, r.text
        job, rcpt = r.json()["job"], r.json()["receipt"]
        for bad in (1e18, time.time() - 10, 0):
            w = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
                       json={"claim_id": job["claim_id"], "receipt": rcpt,
                             "fields": {"expires_at": bad}})
            assert w.status_code == 400, (bad, w.text)
        ok = c.post(f"/v1/nodes/jobs/{job['job_id']}", headers=h,
                    json={"claim_id": job["claim_id"], "receipt": rcpt,
                          "fields": {"expires_at": time.time() + 3600}})
        assert ok.status_code == 200, ok.text
        assert MAX_RESULT_TTL_S > 86400

    def test_the_disposition_route_authorises_like_every_other(self, tmp_path, monkeypatch):
        """It was the one session-gated route that never called _grants_now, so a certificate
        the operator had just deleted kept answering for the rest of the session TTL."""
        c, store, h, d = _rig(tmp_path, monkeypatch)
        store.create(Job(job_id="j", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time()))
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        assert c.get(f"/v1/nodes/jobs/{job['job_id']}/disposition",
                     headers=h).status_code == 200
        (d / "node-n.crt").unlink()          # revoked mid-session
        time.sleep(0)                        # the grants cache is keyed on the directory too
        r = c.get(f"/v1/nodes/jobs/{job['job_id']}/disposition", headers=h)
        assert r.status_code == 403, r.text


class TestArmsThatHadNoCoverage:
    """Each of these survived a mutation with the whole suite green. A destructive guard with no
    test is the shape this branch has already paid for repeatedly."""

    def test_a_handed_over_job_is_reclaimable_end_to_end(self, fleet, tmp_path):
        """NODE_CLAIM_PREFIX appeared in NO test: deleting the re-stamp left the suite green
        while disabling the entire reclaim path, because the sweep filters on that prefix alone.
        The filter half was tested with hand-written prefixed ids; the stamping half was not, so
        the end-to-end property — hand a job over, let the node vanish, the sweep reclaims it —
        went unasserted in both directions."""
        from blastbox.host.ingress.node_claim import NODE_CLAIM_PREFIX
        from blastbox.host.ingress.node_reclaim import reclaim_stale_claims

        d, backing, node = fleet
        backing.create(Job(job_id="handed", engine="clamav", filename="f",
                           status=JobStatus.QUEUED, created_at=time.time()))
        job = node.claim_next(engine="clamav")
        assert job is not None
        assert (job.claim_id or "").startswith(NODE_CLAIM_PREFIX), (
            "the hand-over did not stamp the prefix, so the sweep will never see this job")
        backing.update("handed", started_at=time.time() - 10_000)      # the node vanishes
        assert reclaim_stale_claims(backing, after_s=900.0) == 1
        assert backing.get("handed").status is JobStatus.FAILED

    def test_a_reclaimed_job_is_reapable_by_retention(self):
        """Neither control-plane sweep stamped expires_at, and `expire_due` requires it. On a
        credential-less fleet this is the NORMAL terminal state for a lost claim, so the rows and
        the durable blob objects of jobs that actually ran outlived the retention policy."""
        from blastbox.host.ingress.node_reclaim import reclaim_stale_claims

        store = InMemoryJobStore()
        store.create(Job(job_id="lost", engine="clamav", filename="f",
                         status=JobStatus.RUNNING, created_at=time.time() - 10_000,
                         started_at=time.time() - 10_000, claim_id="node:gone"))
        assert reclaim_stale_claims(store, after_s=900.0, retention_s=86400.0) == 1
        assert store.get("lost").expires_at is not None, "retention can never collect this"

    def test_the_pepper_actually_changes_the_signing_key(self, tmp_path):
        """The word 'pepper' appeared in no test: replacing `if pepper:` with `if False:` left
        the suite green, so the control added because 'a plaintext signing key on the queue lets
        anyone who can read the queue mint a session for ANY node id' was unverified."""
        from blastbox.host.jobs.memory import InMemoryJobStore as Store

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        store = Store()
        plain = node_auth.resolve_claim_secret(store, d, pepper=None)
        k1 = node_auth.resolve_claim_secret(store, d, pepper=b"api-key-one")
        k2 = node_auth.resolve_claim_secret(store, d, pepper=b"api-key-two")
        assert len({plain, k1, k2}) == 3, "the pepper is not reaching the effective key"
        stored = store.get_signing_key()
        assert stored is not None
        assert bytes.fromhex(stored) == plain, "the stored half should be the unpeppered key"

    def test_a_session_does_not_cross_a_pepper_boundary(self, tmp_path):
        """The operational consequence, asserted: two ingress hosts with DIFFERENT API keys on
        one queue cannot honour each other's sessions. This is why the key must match fleet-wide
        and why claim-key show fingerprints the effective key."""
        from blastbox.host.jobs.memory import InMemoryJobStore as Store

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        store = Store()
        a = node_auth.resolve_claim_secret(store, d, pepper=b"host-a-key")
        b = node_auth.resolve_claim_secret(store, d, pepper=b"host-b-key")
        tok = node_auth.issue_session("n", secret=a)
        assert node_auth.verify_session(tok, secret=a) == "n"
        with pytest.raises(node_auth.ClaimRefused):
            node_auth.verify_session(tok, secret=b)


class TestTheIngressCertificateRenewalWindow:
    """Setting _TLS_RENEW_BEFORE_S to 0 — restoring the whole-fleet simultaneous-expiry defect —
    left the suite green. Three behaviours were unprotected: re-issue inside the window, reuse
    outside it, and the hardened-host fallback that logs rather than refusing to boot."""

    def _args(self, **kw):
        import argparse

        base = {"host": "127.0.0.1", "tls_cert": None, "tls_key": None, "no_tls": False}
        base.update(kw)
        return argparse.Namespace(**base)

    def _place(self, d, days):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        ca = pki.load_ca(d)
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ing")]))
                .issuer_name(x509.load_pem_x509_certificate(ca.cert_pem).subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=30))
                .not_valid_after(now + datetime.timedelta(days=days))
                .sign(serialization.load_pem_private_key(ca.key_pem, password=None),
                      hashes.SHA256()))
        (d / "ingress-server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (d / "ingress-server.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        return (d / "ingress-server.crt").read_bytes()

    def test_a_certificate_near_expiry_is_re_issued(self, tmp_path, monkeypatch):
        from blastbox.host.cli import _serve_tls

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        before = self._place(d, days=2)
        monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
        _serve_tls(self._args())
        assert (d / "ingress-server.crt").read_bytes() != before, (
            "an expiring certificate was reused; the whole fleet fails verification at once")

    def test_a_healthy_certificate_is_reused(self, tmp_path, monkeypatch):
        from blastbox.host.cli import _serve_tls

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        before = self._place(d, days=29)
        monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
        _serve_tls(self._args())
        assert (d / "ingress-server.crt").read_bytes() == before, "re-issued needlessly"

    def test_a_hardened_host_serves_the_expiring_pair_and_says_so(self, tmp_path, monkeypatch,
                                                                 caplog):
        """No CA key here, so it cannot renew. Refusing to boot over it would be worse than
        serving a certificate with days left — but the deadline must be loud."""
        from blastbox.host.cli import _serve_tls

        d = tmp_path / "pki"
        pki.ensure_ca(d)
        self._place(d, days=2)
        (d / "ca.key").unlink()
        monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
        with caplog.at_level("ERROR"):
            out = _serve_tls(self._args())
        assert out["ssl_certfile"] == str(d / "ingress-server.crt")
        assert any("no CA key" in r.message for r in caplog.records), caplog.text
