"""Arms of #178 that no test held, found by two mutation campaigns over rounds five and six.

Every test here was written against a specific measured mutation: revert the named arm and this
test goes red. Several of these controls are the ones the commit messages make the most of --
the retention race fence, the stamp write's CAS -- which is exactly the class of gap worth
closing: a control nothing holds is one refactor from being gone.
"""
from __future__ import annotations

import base64
import logging
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress import node_claim as nc
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import JobRetentionSweeper

WG = "A" * 42 + "B="


class TestTheRetentionRaceFenceIsReachedFromTheRealCallSite:
    """`expire_due` is the ONE production caller that supplies `expect_status`, and both existing
    tests call `_expire_job` directly with a value they chose themselves -- so deleting the
    argument at the call site left the whole fence inert with the suite green."""

    class Blobs:
        local_root = None

        def __init__(self):
            self.deleted: list[str] = []

        def delete_job(self, job_id):
            self.deleted.append(job_id)

        def has_output(self, job_id):
            return True

    def _row(self, store, status=JobStatus.FAILED, expires_in=-1.0):
        store.create(Job(job_id="r", engine="boxjs", filename="f", status=status,
                         created_at=time.time() - 100,
                         expires_at=time.time() + expires_in))

    def test_expire_due_passes_the_fence_and_a_repair_survives(self, tmp_path):
        """A repair wins between selection and the destructive step. Driven through `expire_due`,
        not through `_expire_job`, so the argument at the call site is load-bearing."""
        class RepairsMidSweep(InMemoryJobStore):
            def __init__(self):
                super().__init__()
                self._flipped = False

            def list(self, *a, **k):
                rows = super().list(*a, **k)
                if not self._flipped:
                    # Selected as FAILED; the node's repair lands immediately afterwards.
                    self._flipped = True
                    super().update("r", status=JobStatus.DONE,
                                   expires_at=time.time() + 86_400)
                return rows

        store = RepairsMidSweep()
        self._row(store)
        blobs = self.Blobs()
        JobRetentionSweeper(tmp_path, blob_store=blobs).expire_due(store)
        assert blobs.deleted == [], (
            "the sweep destroyed the result of a job that had just been repaired to DONE")
        row = store.get("r")
        assert row.status is JobStatus.DONE and row.expires_at is not None

    def test_a_row_whose_deadline_moved_out_is_left_alone(self, tmp_path):
        """One condition of the fence on its own: `fresh.expires_at > now` means someone re-dated
        the row since selection, so it is no longer due."""
        store = InMemoryJobStore()
        self._row(store)
        blobs = self.Blobs()
        sweeper = JobRetentionSweeper(tmp_path, blob_store=blobs)
        store.update("r", expires_at=time.time() + 86_400)      # re-dated after selection
        sweeper._expire_job(store, "r", None, expect_status=JobStatus.FAILED)
        assert blobs.deleted == [], "a row that is no longer due was expired anyway"
        assert store.get("r").status is JobStatus.FAILED

    def test_a_row_with_no_deadline_at_all_is_left_alone(self, tmp_path):
        """And another: a null `expires_at` is retention's own "never collect this" marker, which
        `retry_pending_uploads`' undo path relies on."""
        store = InMemoryJobStore()
        self._row(store)
        blobs = self.Blobs()
        sweeper = JobRetentionSweeper(tmp_path, blob_store=blobs)
        store.update("r", expires_at=None)
        sweeper._expire_job(store, "r", None, expect_status=JobStatus.FAILED)
        assert blobs.deleted == [], "a row with no retention deadline was expired"

    def test_a_due_row_really_is_expired(self, tmp_path):
        """The fence must not be "never expire anything"."""
        store = InMemoryJobStore()
        self._row(store)
        blobs = self.Blobs()
        JobRetentionSweeper(tmp_path, blob_store=blobs).expire_due(store)
        assert blobs.deleted == ["r"]
        assert store.get("r").status is JobStatus.EXPIRED


def _rig(tmp_path, monkeypatch, *, grants, env):
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


def test_the_prefix_stamp_is_fenced_on_the_claim_it_was_given(tmp_path, monkeypatch):
    """THE double-detonation control, and nothing held it. The stamp write is CAS-fenced on the
    claim id `claim_next` returned; drop the fence and a job a PEER re-claimed in that instant is
    re-stamped and handed over anyway -- the same untrusted sample running in two workers, which
    is the hazard this whole branch is built around."""
    c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(engines=("boxjs",)),
                       env={"BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})

    class PeerTakesItFirst(InMemoryJobStore):
        def claim_next(self, *a, **k):
            job = super().claim_next(*a, **k)
            if job is not None:
                # A peer dispatcher re-claims it between claim_next and the stamp.
                super().update(job.job_id, claim_id="peer-owns-this-now")
            return job

    racing = PeerTakesItFirst()
    racing.create(Job(job_id="j", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                      created_at=time.time()))
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=racing, pki_dir=tmp_path / "pki")
    c2 = TestClient(app)
    ch = c2.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (tmp_path / "pki" / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT,
        "n")).decode()
    tok = c2.post("/v1/nodes/session", json={
        "cert_pem": (tmp_path / "pki" / "node-n.crt").read_text(), "challenge": ch,
        "signature": sig}).json()["token"]
    r = c2.post("/v1/nodes/claim", json={}, headers={SESSION_HEADER: tok})
    assert r.status_code == 204, (
        f"the control plane handed over a job a peer already holds ({r.status_code}) -- two "
        "workers now detonate the same sample")
    assert racing.get("j").claim_id == "peer-owns-this-now", (
        "the peer's claim was overwritten by the stamp")


class TestTheWalksCostCapsAreRealCaps:
    """`_MAX_CLAIM_SKIPS` and the two counters that charge it were the entire bound on how much
    store work one cheap /claim poll can force, and none of them appeared in any test."""

    def _walled_rig(self, tmp_path, monkeypatch, depth):
        c, store, h = _rig(tmp_path, monkeypatch, grants=pki.NodeGrants(
            engines=("clamav", "boxjs"), tiers=(), credentials=False), env={
                "BLASTBOX_NETPOLICY_PROX": "exit=socks",
                "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "prox",
                "BLASTBOX_ENGINE_BOXJS_NETPOLICY": "none"})
        now = time.time()
        for i in range(depth):
            store.create(Job(job_id=f"no{i}", engine="clamav", filename="f",
                             status=JobStatus.QUEUED,
                             created_at=now - nc.MAX_TOTAL_DEFERRAL_S - 100 + i))
        return c, store, h

    def test_one_poll_cannot_walk_an_arbitrarily_deep_wall(self, tmp_path, monkeypatch):
        depth = nc._MAX_CLAIM_SKIPS * 4
        c, store, h = self._walled_rig(tmp_path, monkeypatch, depth)
        claims = {"n": 0}
        real = store.claim_next

        def counted(*a, **k):
            claims["n"] += 1
            return real(*a, **k)

        monkeypatch.setattr(store, "claim_next", counted)
        # WARM THE MEMO OVER THE WHOLE WALL FIRST. Each poll can only judge `_MAX_CLAIM_PROBES`
        # fresh jobs, so one poll memoises eight of them -- and with a partly-cold memo the probe
        # cap does the bounding and the skip counter is never the thing under test.
        for _ in range(depth // nc._MAX_CLAIM_PROBES + 2):
            c.post("/v1/nodes/claim", json={}, headers=h)
        claims["n"] = 0
        c.post("/v1/nodes/claim", json={}, headers=h)
        assert claims["n"] <= nc._MAX_CLAIM_SKIPS + nc._MAX_CLAIM_PROBES + 1, (
            f"one poll made {claims['n']} claim_next calls against a {depth}-job wall: the cost "
            "cap scales with the queue, so a node polling on a timer is a write amplifier")

    def test_the_wall_is_left_claimable_for_an_entitled_peer(self, tmp_path, monkeypatch):
        """The cap must not be bought by stranding the jobs it stepped over."""
        c, store, h = self._walled_rig(tmp_path, monkeypatch, 8)
        c.post("/v1/nodes/claim", json={}, headers=h)
        for i in range(8):
            row = store.get(f"no{i}")
            assert row.status is JobStatus.QUEUED and row.claim_id is None, (
                f"no{i} was left claimed by a walk that refused it")


class TestTheRefusalMemoForgets:
    """`_RefusalMemo`, its TTL and its size bound appeared in no test: the memo could be made
    permanent, or its TTL raised to a day, with the suite green."""

    def test_an_expired_memo_no_longer_blocks_the_job(self):
        memo = nc._RefusalMemo(ttl_s=-1.0)
        memo.remember("n", "j")
        assert memo.remembers("n", "j") is False, (
            "the memo never forgets, so a node whose certificate is re-issued WITH the missing "
            "grant keeps stepping over that work for the life of the ingress process")

    def test_a_fresh_memo_does_block_the_job(self):
        memo = nc._RefusalMemo(ttl_s=60.0)
        memo.remember("n", "j")
        assert memo.remembers("n", "j") is True

    def test_the_ttl_is_a_backstop_not_the_grant_mechanism(self):
        """It used to have to be short (<= 300 s) so a newly-granted node re-judged promptly. That
        is now handled by keying the memo on the node's grants (see test_node_claim_round7), and a
        short TTL was itself a defect: refusals expired before a deep wall was crossed. So the
        TTL must be long enough to outlast walking a wall the size of the memo at eight judgements
        per one-second poll."""
        assert nc._REFUSAL_MEMO_TTL_S >= 8192 / 8, nc._REFUSAL_MEMO_TTL_S

    def test_the_memo_is_bounded(self):
        memo = nc._RefusalMemo(ttl_s=3600.0, limit=64)
        for i in range(1000):
            memo.remember("n", f"job{i}")
        assert len(memo._until) <= 64 + 1, (
            f"the memo holds {len(memo._until)} entries with a limit of 64: unbounded growth in "
            "the one process the whole fleet needs up to claim work")


def test_the_retention_sweep_is_also_quiet_on_a_credential_less_node(tmp_path, caplog):
    """The third `except NodeStoreUnsupported` arm. The earlier version of this test set
    `_job_retention_seconds = 0`, which gates the retention block out entirely, and asserted a
    literal count of 2 -- so the arm was unheld AND the test could not grow to cover it."""
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
    d._job_retention_seconds = 3600          # retention ON, so its sweep actually runs
    d._job_root = tmp_path
    d._job_store = type("S", (InMemoryJobStore,), {"list": refuse})()
    d._blobs = None
    with caplog.at_level(logging.INFO):
        for _ in range(3):
            d._run_maintenance()
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, f"the retention sweep logged {len(errors)} ERROR(s) on a node store"
    said = {r.message for r in caplog.records
            if "does not run on a credential-less node" in r.message}
    assert len(said) == 3, (
        f"expected all three refused sweeps to be named once each, got {len(said)}: {said}")


def test_a_store_that_keeps_losing_the_stamp_cas_cannot_run_the_walk_forever(tmp_path,
                                                                            monkeypatch):
    """Both `continue` paths added by the stamp-first change charged neither counter, so the walk
    was bounded by the QUEUE DEPTH: one request against a 500-job queue issued 501 claims and
    left every one of them RUNNING with an unprefixed claim id -- the immortal-row state stamping
    early exists to prevent."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("boxjs",))).write(d, "node-n")

    class StampAlwaysLoses(InMemoryJobStore):
        def update_if_status(self, job_id, expect, **fields):
            if str(fields.get("claim_id", "")).startswith("node:"):
                return False            # the stamp CAS never lands
            return super().update_if_status(job_id, expect, **fields)

    store = StampAlwaysLoses()
    for i in range(200):
        store.create(Job(job_id=f"j{i}", engine="boxjs", filename="f",
                         status=JobStatus.QUEUED, created_at=time.time() - 1000 + i))
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=d)
    c = TestClient(app)
    ch = c.get("/v1/nodes/challenge").json()["challenge"]
    sig = base64.b64encode(node_auth.sign_claim(
        (d / "node-n.key").read_bytes(), ch, node_auth.SCOPE_CLAIM_NEXT, "n")).decode()
    tok = c.post("/v1/nodes/session", json={
        "cert_pem": (d / "node-n.crt").read_text(), "challenge": ch, "signature": sig},
    ).json()["token"]
    calls = {"n": 0}
    real = store.claim_next

    def counted(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(store, "claim_next", counted)
    c.post("/v1/nodes/claim", json={}, headers={SESSION_HEADER: tok})
    assert calls["n"] <= nc._MAX_CLAIM_PROBES + nc._MAX_CLAIM_SKIPS + 1, (
        f"one request made {calls['n']} claims against a 200-job queue: the paths that lose the "
        "stamp CAS charge no budget, so the walk is bounded only by the queue")


def test_a_reclaimed_job_is_not_the_first_live_receipt_evicted(tmp_path):
    """`_claims[job_id] = …` on an existing key keeps the ORIGINAL insertion position, and the
    live-entry eviction fallback is oldest-first -- so a re-claimed job's fresh receipt sat at
    position 0 and was discarded ahead of hundreds of older claims, refusing its terminal write."""
    from blastbox.host.jobs import http_store as hs
    from blastbox.host.jobs.http_store import HttpJobStore

    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(
        d, "node-n")
    s = HttpJobStore("https://cp", cert_path=d / "node-n.crt",
                     transport=lambda *a, **k: (500, None))
    s._record_claim("recycled", "c0", "r0")
    for i in range(hs._MAX_TRACKED_CLAIMS):
        s._record_claim(f"other{i}", "c", "r")
    s._record_claim("recycled", "c1", "r1")        # re-claimed: a NEW, live generation
    s._record_claim("overflow", "c", "r")          # past the cap
    s._evict_tracked()                             # ...which the next write would do for us
    assert "recycled" in s._claims, (
        "the re-claimed job's live receipt was evicted before claims older than it; its terminal "
        "write will be refused as 'no claim receipt'")


def test_one_sweep_finishes_an_expiry(tmp_path):
    """After the reservation the sweep re-points its expectation at EXPIRED; drop that and the
    final CAS (still expecting FAILED) fails every time, so every expiry needs a second tick, the
    blob delete re-runs, and the row sits EXPIRED with a live deadline in between. Asserting only
    the status could never see it -- the reservation had already set EXPIRED."""
    blobs = TestTheRetentionRaceFenceIsReachedFromTheRealCallSite.Blobs()
    store = InMemoryJobStore()
    store.create(Job(job_id="r", engine="boxjs", filename="f", status=JobStatus.FAILED,
                     created_at=time.time() - 100, expires_at=time.time() - 1))
    JobRetentionSweeper(tmp_path, blob_store=blobs).expire_due(store)
    row = store.get("r")
    assert row.status is JobStatus.EXPIRED
    assert row.expires_at is None, "the expiry was only half-applied in one sweep"
    assert blobs.deleted == ["r"]
