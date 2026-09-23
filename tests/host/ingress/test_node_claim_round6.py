"""Round six: seven defects upstream Codex found in round five's own fixes.

The pattern worth naming is that four of these live INSIDE controls this branch added
one commit earlier -- a bound enforced on one side of an `if`, a fence placed after the
destructive step it was meant to fence, a set mutated outside the lock that protects the
structure it feeds.
"""
from __future__ import annotations

import base64
import math
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_claim as nc
from blastbox.host.ingress import node_reclaim
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


def _rig(tmp_path, monkeypatch, *, grants, env, engine="clamav"):
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


def test_an_engine_policy_in_mixed_case_is_still_resolved(tmp_path, monkeypatch):
    """`cli.py` lowercases BLASTBOX_ENGINE_<NAME>_NETPOLICY before resolving it and the
    personality registry keys are lowercase, so ingress reading the raw value saw
    `BLASTBOX_ENGINE_CLAMAV_NETPOLICY=VPN` as a name it has not got. Non-strict mode then
    treats "unknown" as "nothing to check" and hands the job over, while the node resolves
    the same value to a real wireguard exit with no tier or credentials grant checked."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_VPN", "exit=wireguard")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "VPN")     # the operator's case
    job = Job(job_id="j", engine="clamav", filename="f", status=JobStatus.QUEUED,
              created_at=time.time())
    tier, _needs_credentials, could_tell = nc._job_requirements(job)
    assert could_tell is True, "a resolvable policy read as UNKNOWN because of its case"
    assert tier == "wireguard", (
        f"ingress resolved {tier!r} while the dispatcher will run this job under wireguard, "
        "so the hand-over authorised against the wrong personality")


def test_a_node_cannot_queue_a_job_while_keeping_its_claim(tmp_path, monkeypatch):
    """The release rule was enforced in one direction only: clearing claim_id required
    status=queued, but queueing did NOT require clearing claim_id. So a node could write
    status=queued with claimable_after an hour out while KEEPING ownership -- no peer can
    take a deferred row, and the holder stays authorised to renew before each hour expires.
    That bypasses both the deferral ceiling and the total-burial bound."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                       env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})
    store.create(Job(job_id="j", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    w = c.post("/v1/nodes/jobs/j", headers=h, json={
        "claim_id": body["job"]["claim_id"], "receipt": body["receipt"],
        "fields": {"status": "queued", "claimable_after": time.time() + 3600}})
    assert w.status_code == 400, (
        f"a node queued a job while keeping its claim ({w.status_code}: {w.text}) -- it can "
        "now renew that deferral forever and no peer may have the job")
    row = store.get("j")
    assert not (row.status is JobStatus.QUEUED and row.claim_id), (
        "the row is QUEUED but still owned: unclaimable by a peer, and its holder can renew")


def test_a_release_that_does_clear_the_claim_still_works(tmp_path, monkeypatch):
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                       env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})
    store.create(Job(job_id="j", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    body = c.post("/v1/nodes/claim", json={}, headers=h).json()
    w = c.post("/v1/nodes/jobs/j", headers=h, json={
        "claim_id": body["job"]["claim_id"], "receipt": body["receipt"],
        "fields": {"status": "queued", "claim_id": None}})
    assert w.status_code == 200, w.text
    assert store.get("j").claim_id is None


@pytest.mark.parametrize("raw", ["NaN", "nan", "inf", "Infinity", "-inf"])
def test_a_non_finite_reclaim_interval_is_refused(monkeypatch, raw):
    """NaN passes `float()` and every comparison against it is False, so it flowed straight
    through the floor as the cutoff. `started >= cutoff` is then False for EVERY row, so the
    next tick failed every node-held claim regardless of age; inf disables the sweep silently,
    which on a credential-less fleet is the only reclaim path there is."""
    monkeypatch.setenv(node_reclaim.RECLAIM_AFTER_ENV, raw)
    value = node_reclaim.reclaim_after_s()
    assert value == 0.0 or math.isfinite(value), f"{raw!r} produced {value!r}"
    if value:
        assert value >= node_reclaim.MIN_RECLAIM_AFTER_S


def test_a_non_finite_interval_does_not_fail_live_claims(monkeypatch):
    """The consequence, end to end: with a NaN cutoff every RUNNING node claim was FAILED."""
    monkeypatch.setenv(node_reclaim.RECLAIM_AFTER_ENV, "NaN")
    store = InMemoryJobStore()
    store.create(Job(job_id="live", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    job = store.claim_next(engine=frozenset({"boxjs"}))
    assert job is not None
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           claim_id="node:" + (job.claim_id or ""))
    after = node_reclaim.reclaim_after_s()
    if after:
        node_reclaim.reclaim_stale_claims(store, after_s=after)
    assert store.get("live").status is JobStatus.RUNNING, (
        "a job that started seconds ago was failed as stale")


def test_the_backlog_counts_only_work_this_node_is_eligible_to_run(tmp_path, monkeypatch):
    """A node granted the engine but NOT the tier its queued jobs need was counting those
    jobs: /claim refuses each one after `_job_requirements`, but /backlog counted them, and
    that number goes straight to DispatcherSizer. The pool grows to its ceiling for work it
    can never run and takes that share of the node budget from a sibling pool that could."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
        engines=("clamav",), tiers=(), credentials=False), env={
            "BLASTBOX_NETPOLICY_PROX": "exit=socks",
            "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox"})
    for i in range(3):
        store.create(Job(job_id=f"gov{i}", engine="clamav", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time()))
    r = c.get("/v1/nodes/backlog", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["queued"] == 0, (
        f"the backlog reported {r.json()['queued']} jobs this node's grants forbid; its sizer "
        "will provision for work /claim refuses")
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204


def test_expiry_does_not_destroy_a_result_it_is_about_to_lose_the_race_for(tmp_path):
    """The fence was placed AFTER the destructive step. Round five made the status write a CAS,
    which stops the row being clobbered -- but the blob delete still ran first, so the losing
    sequence became: expiry reads FAILED, expiry DELETES the durable bytes, the node's repair
    uploads a fresh copy and wins its CAS to DONE, expiry's CAS then correctly loses. Result: a
    DONE job whose result 404s. The row must be reserved before anything is destroyed."""
    from blastbox.host.jobs.retention import JobRetentionSweeper

    deleted: list[str] = []

    class Blobs:
        local_root = None

        def delete_job(self, job_id):
            deleted.append(job_id)

        def has_output(self, job_id):
            return True

    class StaleView(InMemoryJobStore):
        """`get` answers with the row as the sweep saw it a moment ago, while the row itself has
        already been repaired -- the window between the pre-flight re-read and the delete, which
        the re-read alone cannot close."""

        def get(self, job_id):
            real = super().get(job_id)
            if real is not None and job_id == "r":
                return Job(job_id="r", engine="boxjs", filename="f",
                           status=JobStatus.FAILED, created_at=real.created_at,
                           expires_at=time.time() - 1)
            return real

    store = StaleView()
    store.create(Job(job_id="r", engine="boxjs", filename="f", status=JobStatus.DONE,
                     created_at=time.time() - 100, expires_at=time.time() + 86_400))
    JobRetentionSweeper(tmp_path, blob_store=Blobs())._expire_job(
        store, "r", None, expect_status=JobStatus.FAILED)      # selected as FAILED
    assert deleted == [], (
        "expiry deleted the blobs of a job it then failed to expire: the row is DONE and its "
        "result is gone")
    row = InMemoryJobStore.get(store, "r")
    assert row.status is JobStatus.DONE and row.expires_at is not None


def test_expiry_still_retries_when_the_blob_delete_fails(tmp_path):
    """The reservation must not cost the retry property: a row whose blob delete failed has to
    stay selectable, or its durable bytes are orphaned forever."""
    from blastbox.host.jobs.retention import JobRetentionSweeper

    class FlakyBlobs:
        local_root = None

        def delete_job(self, job_id):
            raise RuntimeError("object store unavailable")

        def has_output(self, job_id):
            return True

    store = InMemoryJobStore()
    store.create(Job(job_id="r", engine="boxjs", filename="f", status=JobStatus.FAILED,
                     created_at=time.time() - 100, expires_at=time.time() - 1))
    sweeper = JobRetentionSweeper(tmp_path, blob_store=FlakyBlobs())
    sweeper._expire_job(store, "r", None, expect_status=JobStatus.FAILED)
    row = store.get("r")
    assert row.expires_at is not None, (
        "the row lost its deadline after a failed blob delete, so nothing will ever retry and "
        "the durable bytes are orphaned")
    assert row.status in (JobStatus.FAILED, JobStatus.EXPIRED)
    assert sweeper.expire_due(store) or row.expires_at is not None


def test_a_settled_marker_cannot_land_on_a_newer_claim(tmp_path):
    """Two dispatcher threads, one job: A releases it and B reclaims it. A's `_settled.add` ran
    OUTSIDE the lock and keyed on the job id alone, so if it landed after B's `_record_claim`
    the NEW live receipt was marked settled -- and settled entries are the first the eviction
    scan discards, so B's terminal write is refused and its job sits RUNNING until timeout."""
    from blastbox.host.jobs.http_store import HttpJobStore

    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        d, "node-n")
    s = HttpJobStore("https://cp", cert_path=d / "node-n.crt",
                     transport=lambda *a, **k: (500, None))
    s._record_claim("j", "claim-A", "receipt-A")
    generation_a = s._claims["j"]
    s._record_claim("j", "claim-B", "receipt-B")        # B reclaimed it first
    s._mark_settled("j", generation_a)                  # ...then A's release settles, late
    assert "j" not in s._settled, (
        "a stale release marked the NEW claim settled; eviction will now throw away a live "
        "receipt and refuse that job's terminal write")
    s._mark_settled("j", s._claims["j"])                # the current generation still may
    assert "j" in s._settled


def test_the_refusal_memo_survives_a_concurrent_expiry_drop():
    """FastAPI runs these sync handlers in a threadpool, so two claims for the same node race
    inside the memo. Both `del` sites were unguarded: two threads that each observe the same
    entry expired both delete it, and the second raises KeyError from inside the claim walk --
    a 500 for a request whose honest answer was "nothing for you".

    Threads alone do not reproduce this reliably (the window is two bytecodes wide), so the
    interleaving is FORCED: the mapping drops the key between our `get` and our delete, which
    is exactly what the peer thread does."""
    class DropsUnderUs(dict):
        tripped = False

        def get(self, key, default=None):
            value = super().get(key, default)
            if not self.tripped:
                self.tripped = True
                super().pop(key, None)      # the peer expired it first
            return value

    memo = nc._RefusalMemo(ttl_s=-1.0)      # already expired
    memo._until = DropsUnderUs()
    memo._until[("n", "j")] = time.time() - 1
    assert memo.remembers("n", "j") is False, "an expired entry must read as not remembered"


def test_the_memo_bound_survives_a_concurrent_eviction():
    """The size bound deletes a precomputed list of keys; a peer evicting at the same moment
    removes some of them first, and the loop then raised on a key that is already gone. Forced
    the same way: the mapping reports a key it no longer holds."""
    class ListsAGhost(dict):
        def __iter__(self):
            # FIRST, so it falls inside the half the bound actually walks.
            return iter([("ghost", "gone"), *super().__iter__()])

    memo = nc._RefusalMemo(limit=2)
    memo._until = ListsAGhost()
    memo.remember("n", "a")
    memo.remember("n", "b")
    memo.remember("n", "c")                 # trips the bound, which walks the ghost key


class TestTheSameFixReachesEverySiteOfItsKind:
    """`node_auth._same()` was added because `hmac.compare_digest` raises TypeError on a str
    holding non-ASCII and every value it is given comes off the wire. Three call sites were
    converted; three MORE of exactly that construct were left alone, and one of them fronts
    every non-node route on the ingress."""

    def test_the_bearer_gate_refuses_rather_than_500s(self):
        from fastapi import FastAPI as _FastAPI

        from blastbox.host.ingress.middleware import BearerAuthMiddleware

        app = _FastAPI()

        @app.get("/v1/jobs")
        def _jobs():                                        # pragma: no cover - never reached
            return {}

        app.add_middleware(BearerAuthMiddleware, api_key="k")
        c = TestClient(app, raise_server_exceptions=False)
        # BYTES: Starlette decodes a header as latin-1, so this is what the wire can carry.
        r = c.get("/v1/jobs", headers={b"Authorization": b"Bearer \xc3\xa9"})
        assert r.status_code == 401, (
            f"one non-ASCII byte in the bearer header gave {r.status_code}: an unauthenticated "
            "caller can turn the ingress's own auth gate into a traceback flood")

    def test_a_correct_bearer_token_still_passes(self):
        from fastapi import FastAPI as _FastAPI

        from blastbox.host.ingress.middleware import BearerAuthMiddleware

        app = _FastAPI()

        @app.get("/v1/jobs")
        def _jobs():
            return {"ok": True}

        app.add_middleware(BearerAuthMiddleware, api_key="k")
        c = TestClient(app)
        assert c.get("/v1/jobs", headers={"Authorization": "Bearer k"}).status_code == 200

    def test_the_worker_agent_token_check_refuses_rather_than_raising(self):
        from blastbox.worker.http_agent import _Handler

        class Req:
            token = "s3cret"

            class headers:
                @staticmethod
                def get(key, default=None):
                    return "é" if key == "X-aws-proxy-auth" else default

        assert _Handler._authed(Req()) is False


def test_a_vm_dispatchers_maintenance_tick_is_quiet_on_a_credential_less_node(tmp_path, caplog):
    """`_sweep_unsupported` was added to the container Dispatcher only, and cli.py hands the SAME
    store to the network-endpoint dispatchers -- so a federated node running an aws/static pool
    logged three WARNINGs with tracebacks per tick, forever, for sweeps it is not meant to run."""
    import logging

    from blastbox.host.jobs.http_store import NodeStoreUnsupported
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    class Refuses(InMemoryJobStore):
        def list(self, *a, **k):
            raise NodeStoreUnsupported("a node may not enumerate the queue")

    class Retention:
        def expire_due(self, store):
            return store.list()

    d = VmJobDispatcher.__new__(VmJobDispatcher)
    d._store = Refuses()
    d._job_root = tmp_path
    d._blobs = None
    d._engine = None
    d._sole_owner = False
    d._orphan_timeout_s = 600.0
    d._worker_tier = "vm"
    d._job_retention_seconds = 0
    d._retention_s = 0
    d._pending_upload_retry = False
    d._scratch_max_age_s = 0
    d._max_queued_age_s = 3600.0
    d._expiry = lambda now: None
    d._input_path = lambda job: tmp_path / "nothing"
    d._retention = Retention()
    with caplog.at_level(logging.INFO):
        d._run_maintenance()
        d._run_maintenance()
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not warnings, f"refused-by-design sweeps logged {len(warnings)} warning(s)"
    said = [r for r in caplog.records if "does not run on a credential-less node" in r.message]
    assert said, "nothing explained why the sweeps are not running"
    assert len(said) == len({r.message for r in said}), "a sweep said it more than once"
