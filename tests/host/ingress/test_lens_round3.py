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


def test_the_disposition_leaks_no_content(fleet):
    _d, backing, node = fleet
    backing.create(Job(job_id="secret", engine="clamav", filename="victim-sample.exe",
                       status=JobStatus.DONE, created_at=time.time(),
                       result_dir="/srv/private/secret"))
    got = node.get("secret")
    assert got is not None
    assert got.filename == "" and got.engine == "" and got.result_dir is None, (
        "the disposition route leaked job content to a node that does not hold it")


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
