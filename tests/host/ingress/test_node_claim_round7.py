"""Round seven: findings from upstream Codex's review of #183.

The headline one reversed a round-six fix. Lowering `_MAX_CLAIM_SKIPS` to 16 to bound the write
cost made a wall of 16 refused jobs the SAME prefix on every poll -- `claim_next` is strictly
oldest-first -- so work behind it was never reached. The cure was not a different constant: the
store now excludes jobs a node has already been refused, so it never offers them at all.
"""
from __future__ import annotations

import base64
import time

import pytest
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


def test_a_wall_deeper_than_the_old_exclusion_cap_is_still_crossed(tmp_path, monkeypatch):
    """The exclusion was first capped at 256 ids, with the skip branch (16) as the backstop -- which
    only moved the cliff: measured, a 272-deep wall was crossed, a 300-deep one never was in 199
    polls. The exclusion now covers everything the memo remembers, so the only bound is the memo
    itself. 300 is the depth that failed."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav", "boxjs"), tiers=(), credentials=False), env=WALL_ENV)
    now = time.time()
    depth = 300
    for i in range(depth):
        store.create(Job(job_id=f"wall{i:04d}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED,
                         created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 5000 + i))
    store.create(Job(job_id="behind", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=now))
    got = None
    for _ in range(depth // nc._MAX_CLAIM_PROBES + 20):
        r = c.post("/v1/nodes/claim", json={}, headers=h)
        if r.status_code == 200:
            got = r.json()["job"]["job_id"]
            break
    assert got == "behind", f"a {depth}-deep refusal wall starved the job behind it"


def test_the_exclusion_never_truncates_what_the_memo_remembers():
    memo = nc._RefusalMemo(ttl_s=60.0)
    for i in range(1000):
        memo.remember("n", f"j{i}")
    assert len(memo.remembered_for("n")) == 1000, (
        "the exclusion dropped live refusals; every one it drops is a job the walk must step "
        "over by hand, and past the skip budget that is starvation again")


class _IgnoresExclude(InMemoryJobStore):
    """A store that drops `exclude` -- what the walk sees when the exclusion is truncated (an old
    SQLite's parameter limit) or a refusal was evicted from the memo. The skip branch is then the
    ONLY bound on a poll, so this is the one place it can be exercised at all."""

    def claim_next(self, *, claimant_tier=None, engine=None, exclude=()):
        return super().claim_next(claimant_tier=claimant_tier, engine=engine)


def test_the_skip_backstop_bounds_a_poll_when_the_store_cannot_exclude(tmp_path, monkeypatch):
    """A literal bound, not one derived from the constant under test: the previous cost-cap test
    took both its depth and its bound from _MAX_CLAIM_SKIPS, and after the exclusion landed it
    never reached the skip branch at all -- three mutations of it survived the suite."""
    store = _IgnoresExclude()
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env=WALL_ENV, store=store)
    now = time.time()
    for i in range(400):
        store.create(Job(job_id=f"w{i:04d}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED,
                         created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 5000 + i))
    for _ in range(60):                              # judge the whole wall
        c.post("/v1/nodes/claim", json={}, headers=h)
    calls = {"n": 0}
    real = store.claim_next

    def counted(**k):
        calls["n"] += 1
        return real(**k)

    monkeypatch.setattr(store, "claim_next", counted)
    c.post("/v1/nodes/claim", json={}, headers=h)
    assert calls["n"] <= 40, (
        f"one poll made {calls['n']} claims against a 400-job wall the store would not exclude: "
        "the skip backstop is gone, so each poll pays a claim, a stamp and a release per job")


def test_a_read_back_that_keeps_disagreeing_still_charges_the_budget(tmp_path, monkeypatch):
    """The SECOND 'CHARGED TOO' path: the stamp CAS lands but the re-read shows a different claim
    id (a racing sweeper, or replica lag). The first test only ever lost the CAS, so removing the
    charge on THIS path survived -- and a poll became bounded by queue depth, not eight probes."""
    class ReadBackDisagrees(InMemoryJobStore):
        def get(self, job_id):
            job = super().get(job_id)
            if job is not None and (job.claim_id or "").startswith("node:"):
                job.claim_id = "someone-else"
            return job

    store = ReadBackDisagrees()
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                       env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"}, store=store)
    for i in range(200):
        store.create(Job(job_id=f"j{i:03d}", engine="boxjs", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time() - 1000 + i))
    calls = {"n": 0}
    real = store.claim_next

    def counted(**k):
        calls["n"] += 1
        return real(**k)

    monkeypatch.setattr(store, "claim_next", counted)
    c.post("/v1/nodes/claim", json={}, headers=h)
    assert calls["n"] <= 20, f"one poll made {calls['n']} claims against a 200-job queue"


def test_strict_tiers_backlog_agrees_with_the_claim_route(tmp_path, monkeypatch):
    """With strict tiers on and an engine default this host cannot resolve, /claim refuses every
    such job. /backlog must say zero, or the sizer grows a pool for work that is never handed out.
    The strict branch of _engine_is_claimable could be deleted with the suite green."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("clamav",)),
                       env={"BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "notconfiguredhere",
                            "BLASTBOX_NODE_CLAIM_STRICT_TIERS": "1"})
    store.create(Job(job_id="x", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
    assert c.get("/v1/nodes/backlog", headers=h).json()["queued"] == 0, (
        "/backlog counted work /claim refuses under strict tiers")


@pytest.mark.parametrize("spelling", ["1", "true", "yes", "on", "TRUE"])
def test_the_override_switch_reads_the_same_on_both_routes(tmp_path, monkeypatch, spelling):
    """One parser now, used by both the claim walk and the backlog. Two parsers that agreed only by
    coincidence meant `=true` could hide runnable override work from the sizer."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env={
            **WALL_ENV, "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE": spelling})
    store.create(Job(job_id="picks-none", engine="clamav", filename="f",
                     status=JobStatus.QUEUED, created_at=time.time(), net_policy="none"))
    assert c.get("/v1/nodes/backlog", headers=h).json()["queued"] >= 1
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 200
