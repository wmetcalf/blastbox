"""Round seven: findings from upstream Codex's review of #183.

The headline one reversed a round-six fix. Lowering `_MAX_CLAIM_SKIPS` to 16 to bound the write
cost made a wall of 16 refused jobs the SAME prefix on every poll -- `claim_next` is strictly
oldest-first -- so work behind it was never reached. The cure was not a different constant: the
store now excludes jobs a node has already been refused, so it never offers them at all.
"""
from __future__ import annotations

import base64
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_claim as nc
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


def _rig(tmp_path, monkeypatch, *, grants, env, store=None):
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=grants).write(d, "node-n")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    store = store or InMemoryJobStore()
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


WALL_ENV = {
    "BLASTBOX_NETPOLICY_PROX": "exit=socks",
    "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox",      # needs socks + credentials: refused
    "BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none",       # runnable
}


def test_a_deep_wall_of_refused_jobs_does_not_starve_work_behind_it(tmp_path, monkeypatch):
    """Codex's scenario exactly: a refusal wall deeper than the skip cap, old enough that its
    jobs are no longer deferred, and runnable work queued behind it."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), tiers=(), credentials=False), env=WALL_ENV)
    now = time.time()
    depth = nc._MAX_CLAIM_SKIPS * 3
    for i in range(depth):
        store.create(Job(job_id=f"wall{i:03d}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED,
                         created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 500 + i))
    store.create(Job(job_id="behind", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=now))
    got = None
    for _ in range(depth // nc._MAX_CLAIM_PROBES + 4):
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        if r.status_code == 200:
            got = r.json()["job"]["job_id"]
            break
    assert got == "behind", (
        f"a {depth}-job refusal wall starved the runnable job behind it: every poll stopped at "
        "the same prefix")


def test_a_remembered_wall_costs_no_writes_once_judged(tmp_path, monkeypatch):
    """The write amplification round six introduced: each step over a remembered job was a claim,
    a stamp and a release. Excluded in the query, a judged job costs nothing."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env=WALL_ENV)
    now = time.time()
    for i in range(24):
        store.create(Job(job_id=f"wall{i:03d}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED,
                         created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 500 + i))
    for _ in range(6):                               # judge the whole wall once
        c.post("/v1/nodes/claim", json={}, headers=h)
    writes = {"n": 0}
    real = store.update_if_status

    def counted(*a, **k):
        writes["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(store, "update_if_status", counted)
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
    assert writes["n"] == 0, (
        f"a poll against an already-judged wall issued {writes['n']} store writes; it should "
        "issue none, because the store no longer offers jobs this node was refused")


def test_an_expired_refusal_is_offered_again(tmp_path, monkeypatch):
    """The exclusion must follow the memo's TTL, or a node whose certificate is re-issued WITH the
    missing grant never sees that work again."""
    memo = nc._RefusalMemo(ttl_s=-1.0)
    memo.remember("n", "j")
    assert memo.remembered_for("n") == frozenset()
    fresh = nc._RefusalMemo(ttl_s=60.0)
    fresh.remember("n", "j")
    fresh.remember("other", "k")
    assert fresh.remembered_for("n") == frozenset({"j"}), "one node's refusals leaked to another"


def test_the_exclusion_list_is_bounded():
    memo = nc._RefusalMemo(ttl_s=60.0)
    for i in range(1000):
        memo.remember("n", f"j{i}")
    assert len(memo.remembered_for("n", limit=256)) == 256


def test_the_backlog_counts_work_a_job_override_makes_runnable(tmp_path, monkeypatch):
    """With overrides allowed, a job can select a policy this node CAN run even though the
    engine's default needs a tier it lacks. /claim hands that job over; the engine-wide backlog
    filter reported zero for it, so the sizer sat at its floor with runnable work queued."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env={
            **WALL_ENV, "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE": "1"})
    store.create(Job(job_id="picks-none", engine="clamav", filename="f",
                     status=JobStatus.QUEUED, created_at=time.time(), net_policy="none"))
    assert c.get("/v1/nodes/backlog", headers=h).json()["queued"] >= 1, (
        "runnable work was hidden from the sizer because the ENGINE default is ungranted")
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    assert r.status_code == 200 and r.json()["job"]["job_id"] == "picks-none"


def test_without_overrides_the_backlog_still_hides_ineligible_engines(tmp_path, monkeypatch):
    """The round-six property the fix must keep: with no per-job overrides, an engine whose only
    policy this node cannot run contributes nothing to its backlog."""
    monkeypatch.delenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", raising=False)
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env=WALL_ENV)
    store.create(Job(job_id="gov", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    assert c.get("/v1/nodes/backlog", headers=h).json()["queued"] == 0
