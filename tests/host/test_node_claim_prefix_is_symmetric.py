"""The `node:` claim prefix, from BOTH sides (#178, round five).

The prefix exists so that two reclaim paths on one queue can tell each other's claims apart.
Round five found it enforced on one side only, in both directions:

  * the control plane STAMPED it after judging, so every way its claim walk left a job behind
    produced a RUNNING row no sweep would ever look at again; and
  * a DB-backed dispatcher sharing the queue never READ it, so it requeued (or terminally
    failed) a federated node's live job -- the double-detonation this project refuses.
"""
from __future__ import annotations

import base64
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_reclaim
from blastbox.host.ingress.node_claim import (
    NODE_CLAIM_PREFIX, SESSION_HEADER, register_node_claim_routes,
)
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """A node granted boxjs only, and a queue holding one clamav job it may not run."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    monkeypatch.setenv("BLASTBOX_NETPOLICY_PROX", "exit=socks")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "prox")
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), credentials=False)).write(d, "node-n")
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


def test_a_job_the_walk_could_not_release_is_still_reclaimable(rig, monkeypatch):
    """The release raises (a store blip). The job is left RUNNING -- and it must be left RUNNING
    with a claim id the reclaim sweep recognises as its own, or nothing collects it ever: the
    row is not QUEUED (so `fail_stale_queued` skips it), not terminal (so retention and the
    scratch reaper skip it), and unprefixed (so `reclaim_stale_claims` skips it)."""
    c, store, h = rig
    store.create(Job(job_id="cannot-run", engine="clamav", filename="f",
                     status=JobStatus.QUEUED, created_at=time.time() - 10_000))
    real = store.update_if_status

    def break_the_release(job_id, expect, **fields):
        if fields.get("status") is JobStatus.QUEUED:
            raise RuntimeError("store blip during release")
        return real(job_id, expect, **fields)

    monkeypatch.setattr(store, "update_if_status", break_the_release)
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
    row = store.get("cannot-run")
    assert row.status is JobStatus.RUNNING              # the premise: the release failed
    assert (row.claim_id or "").startswith(NODE_CLAIM_PREFIX), (
        "the walk left a RUNNING row with an unprefixed claim id, which no sweep will ever "
        f"look at again (claim_id={row.claim_id!r})")
    monkeypatch.undo()
    store.update("cannot-run", started_at=time.time() - 10_000)   # the claim goes stale
    assert node_reclaim.reclaim_stale_claims(store, after_s=900.0, retention_s=86_400.0) == 1
    assert store.get("cannot-run").status is JobStatus.FAILED


def test_a_handed_over_job_is_still_prefixed_and_writable(rig):
    """The other direction: stamping earlier must not break the hand-over itself."""
    c, store, h = rig
    store.create(Job(job_id="mine", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job"]["claim_id"].startswith(NODE_CLAIM_PREFIX)
    w = c.post("/v1/nodes/jobs/mine", headers=h, json={
        "claim_id": body["job"]["claim_id"], "receipt": body["receipt"],
        "fields": {"status": "done", "finished_at": time.time()}})
    assert w.status_code == 200, w.text


class TestADispatcherSharingTheQueueLeavesNodeClaimsAlone:
    """`reclaim_stale_claims` refuses to touch a DB dispatcher's claims ("NOT OURS TO JUDGE").
    The dispatcher's own recovery never learned the other half of that deal, so on the shipped
    mixed-fleet shape -- a DB-backed dispatcher on the ingress host plus federated nodes on the
    same queue -- it requeued a node's live job after 60s (two workers detonating one sample) or
    terminally FAILED a warm one after 360s (the node's result then loses its CAS)."""

    def _dispatcher(self, store, tmp_path):
        from blastbox.host.dispatch import Dispatcher

        d = Dispatcher.__new__(Dispatcher)
        d._job_store = store
        d._job_root = tmp_path
        d._requeue_grace_s = 60.0
        d._worker_timeout_s = 300.0
        d._job_retention_seconds = 0
        d._list_active_worker_job_ids = lambda: set()      # nothing of ours is running
        d._delete_input = lambda p: None
        return d

    def _node_claim(self, store, *, warm: bool, age: float):
        store.create(Job(job_id="theirs", engine="pdf", filename="s.pdf",
                         status=JobStatus.QUEUED, created_at=time.time() - age))
        job = store.claim_next(engine=frozenset({"pdf"}))
        assert job is not None
        store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                               claim_id=NODE_CLAIM_PREFIX + (job.claim_id or ""))
        store.update("theirs", started_at=time.time() - age,
                     worker_runtime=("warm" if warm else "runc"))

    def test_the_cold_pass_does_not_requeue_a_node_held_job(self, tmp_path):
        store = InMemoryJobStore()
        self._node_claim(store, warm=False, age=120.0)
        self._dispatcher(store, tmp_path).requeue_orphaned_jobs()
        assert store.get("theirs").status is JobStatus.RUNNING, (
            "a peer dispatcher requeued a federated node's live job: the same untrusted sample "
            "is now detonating in two places")

    def test_the_warm_pass_does_not_fail_a_node_held_job(self, tmp_path):
        store = InMemoryJobStore()
        self._node_claim(store, warm=True, age=400.0)
        self._dispatcher(store, tmp_path).requeue_orphaned_jobs()
        assert store.get("theirs").status is JobStatus.RUNNING, (
            "a peer dispatcher terminally failed a federated node's live job; the node's own "
            "result write will now lose its CAS and be discarded")

    def test_it_still_recovers_its_OWN_orphans(self, tmp_path):
        """The fix must not be 'recover nothing'."""
        store = InMemoryJobStore()
        store.create(Job(job_id="ours", engine="pdf", filename="s.pdf",
                         status=JobStatus.QUEUED, created_at=time.time() - 500))
        job = store.claim_next(engine=frozenset({"pdf"}))
        assert job is not None
        store.update("ours", started_at=time.time() - 120, worker_runtime="runc")
        self._dispatcher(store, tmp_path).requeue_orphaned_jobs()
        assert store.get("ours").status is JobStatus.QUEUED


def test_a_vm_dispatchers_orphan_sweep_leaves_a_node_claim_alone(tmp_path, monkeypatch):
    """`VmJobDispatcher`'s orphan sweep FAILs a stale RUNNING job at `orphan_timeout_s` (600 s by
    default, BELOW the node reclaim floor of 900 s), and with `sole_owner` it deliberately
    reclaims an "unmarked" claim -- which is exactly the shape a federated node's claim has."""
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    store = InMemoryJobStore()
    store.create(Job(job_id="theirs", engine="pdf", filename="s.pdf", status=JobStatus.QUEUED,
                     created_at=time.time() - 5_000))
    job = store.claim_next(engine=frozenset({"pdf"}))
    assert job is not None
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           claim_id=NODE_CLAIM_PREFIX + (job.claim_id or ""))
    store.update("theirs", started_at=time.time() - 5_000, worker_runtime="runc")

    d = VmJobDispatcher.__new__(VmJobDispatcher)
    d._store = store
    d._engine = None
    d._sole_owner = True
    d._orphan_timeout_s = 600.0
    d._worker_tier = "libvirt-vm"
    d._job_retention_seconds = 0
    d._expiry = lambda now: None
    d._input_path = lambda job: tmp_path / "nothing"
    d._job_root = tmp_path
    d._scratch_max_age_s = 0.0
    d._max_queued_age_s = 0.0
    d._retention = None
    d._run_maintenance()
    assert store.get("theirs").status is JobStatus.RUNNING, (
        "a VM dispatcher failed a federated node's live job as an orphan")


def test_a_credential_less_nodes_maintenance_tick_is_quiet(tmp_path, caplog):
    """The sweeps that need the fleet's queue live on the control plane for a federated node --
    and the node's own maintenance still called them, so each tick logged an ERROR and a full
    traceback, forever. Alerting keyed on ERROR from this logger then has to be suppressed,
    which is how the next real failure here goes unseen."""
    import logging

    from blastbox.host.dispatch import Dispatcher
    from blastbox.host.jobs.http_store import NodeStoreUnsupported

    d = Dispatcher.__new__(Dispatcher)

    def refuse(*a, **k):
        raise NodeStoreUnsupported("a node may not enumerate the queue")

    d.requeue_orphaned_jobs = refuse
    d._fail_stale_queued_jobs = refuse
    d._reconcile_cold_orphans = lambda: None
    d._pending_upload_retry = 0
    d._reap_stale_scratch = lambda: None
    d._job_retention_seconds = 0
    with caplog.at_level(logging.INFO):
        d._run_maintenance()
        d._run_maintenance()
        d._run_maintenance()
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, f"a refused-by-design sweep logged {len(errors)} ERROR(s): {errors[:1]}"
    said = [r for r in caplog.records if "does not run on a credential-less node" in r.message]
    assert len(said) == 2, (
        f"expected one INFO per refused sweep, said once in total, got {len(said)}")
