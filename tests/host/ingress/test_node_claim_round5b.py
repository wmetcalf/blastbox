"""Round five, part two: arms a mutation campaign showed nothing was holding.

A reviewer reverted forty-nine individual arms of this branch one at a time and re-ran the
suite. Thirty were caught. These are the ones that were not -- plus the three behavioural
holes the same pass reproduced against the real routes.
"""
from __future__ import annotations

import base64
import errno
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, pki
from blastbox.host.ingress.node_claim import SESSION_HEADER, register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def held(tmp_path, monkeypatch):
    """A node holding one claimed job, with the credentials to write to it."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    monkeypatch.setenv("BLASTBOX_ENGINE_BOXJS_NETPOLICY", "none")
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(engines=("boxjs",))).write(d, "node-n")
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
    h = {SESSION_HEADER: tok}
    store.create(Job(job_id="j", engine="boxjs", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    r = c.post("/v1/nodes/claim", json={}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()

    def write(fields):
        return c.post("/v1/nodes/jobs/j", headers=h, json={
            "claim_id": body["job"]["claim_id"], "receipt": body["receipt"], "fields": fields})

    return c, store, h, write


def test_a_node_may_not_expire_a_job(held):
    """EXPIRED is written in exactly one place -- the retention sweep, where the policy lives.
    A node could write it: the result was then unfetchable (open_output is DONE-gated) AND the
    row was permanently uncollectable, because `expire_due` skips a null `expires_at`, so the
    blob delete never ran for it either."""
    _c, store, _h, write = held
    r = write({"status": "expired"})
    assert r.status_code == 400, f"a node expired a job ({r.status_code}: {r.text})"
    assert store.get("j").status is JobStatus.RUNNING


def test_a_node_may_still_report_the_statuses_it_owns(held):
    _c, store, _h, write = held
    assert write({"status": "done", "finished_at": time.time()}).status_code == 200
    assert store.get("j").status is JobStatus.DONE


@pytest.mark.parametrize("field", ["expires_at", "started_at", "claimable_after"])
def test_an_absurdly_large_integer_is_a_400_not_a_500(held, field):
    """`float(10**400)` raises OverflowError, which is neither TypeError nor ValueError -- so it
    escaped the validator and the contract's 400 became a 500 with a traceback."""
    _c, _store, _h, write = held
    r = write({field: 10 ** 400})
    assert r.status_code == 400, f"{field}: {r.status_code}"


def test_a_non_string_status_is_refused(held):
    """The guard's own comment: `{"status": 7}` was stored, and from then on `get()` and the
    unfiltered `list()` raised "7 is not a valid JobStatus" for that row forever -- GET /v1/jobs
    and the ingress retention sweep both dead fleet-wide, at WARNING. Nothing tested it."""
    _c, store, _h, write = held
    assert write({"status": 7}).status_code == 400
    assert store.get("j").status is JobStatus.RUNNING


def test_a_node_cannot_put_its_start_time_in_the_far_future(held):
    """MAX_FUTURE_SKEW_S, with a LITERAL. `started_at` is the field the reclaim sweep judges by,
    so 9e18 made the claim permanently unreclaimable -- and the ceiling could be raised to 1e30
    with the whole suite green."""
    _c, store, _h, write = held
    assert write({"started_at": 9e18}).status_code == 400
    assert store.get("j").started_at < time.time() + 3600


def test_a_node_cannot_defer_a_job_beyond_an_hour(held):
    """MAX_DEFERRAL_S, with a LITERAL rather than the constant under test: the earlier version
    asserted against `MAX_DEFERRAL_S` itself, so setting it to 1e30 -- fully restoring the
    permanent-bury defect -- left the suite green."""
    _c, store, _h, write = held
    assert write({"status": "queued", "claim_id": None,
                  "claimable_after": 4102444800.0}).status_code == 200
    back = store.get("j")
    assert back.claimable_after is not None
    assert back.claimable_after <= time.time() + 3601, (
        "a node buried a job until the year 2100")


def test_a_refused_job_cannot_be_kept_deferred_for_longer_than_its_window(tmp_path,
                                                                           monkeypatch):
    """The burial bound, on the clock every ingress shares. The old bound was a per-process
    COUNT: per forked worker and per host, so the real allowance was cap x workers x hosts, a
    restart reset it, and its own size bound handed a spent allowance back. The test that
    "covered" it looped `range(_MAX_REFUSAL_DEFERRALS + 2)`, so raising the cap raised the loop
    with it and the suite stayed green."""
    monkeypatch.delenv(node_auth.SECRET_FILE_ENV, raising=False)
    monkeypatch.setenv("BLASTBOX_NETPOLICY_PROX", "exit=socks")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_NETPOLICY", "prox")
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("n", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), credentials=False)).write(d, "node-n")
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
    h = {SESSION_HEADER: tok}
    # A job just submitted: deferring it briefly is the point of the mechanism.
    store.create(Job(job_id="young", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time()))
    assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
    assert store.get("young").claimable_after is not None
    # Past the window it is released claimable, NO MATTER how many times it has been refused, by
    # this worker or any other -- there is no per-process state to reset.
    store.update("young", created_at=time.time() - 121.0, claimable_after=None)
    for _ in range(3):
        assert c.post("/v1/nodes/claim", json={}, headers=h).status_code == 204
        assert store.get("young").claimable_after is None, (
            "a node kept an old job deferred, holding governed work away from an entitled peer")


def test_the_burial_bound_is_not_a_per_process_counter():
    """Stateless on purpose: two ingress workers see the same answer for the same job, which a
    dict in one worker's memory could never give."""
    from blastbox.host.ingress import node_claim as m

    assert not hasattr(m, "_MAX_REFUSAL_DEFERRALS"), (
        "the per-process deferral count is back; it cannot bound anything a forked worker or a "
        "second host can undo")
    assert m.MAX_TOTAL_DEFERRAL_S > m._REFUSAL_DEFER_S


def test_a_claimant_tier_hint_is_refused_not_silently_dropped(held):
    """Measured: a node running a plain cold pool asked for claimant_tier="firecracker" and was
    given the hardware-isolated job. The 400 that closed it had no test, so it could be reverted
    to a silent drop with the suite green -- and a silent drop leaves the node believing it is
    routing."""
    c, _store, h, _write = held
    r = c.post("/v1/nodes/claim", json={"claimant_tier": "firecracker"}, headers=h)
    assert r.status_code == 400, f"claimant_tier was accepted ({r.status_code})"


class TestTheMaintenanceLockTellsContentionFromNoLocksAtAll:
    """Only EAGAIN/EWOULDBLOCK means a peer holds it. ENOLCK (NFS -o nolock, lockd down) and
    EOPNOTSUPP mean nobody holds it and nobody ever will -- and treating those as contention
    made every worker stand down on every tick, silently, so all four sweeps stopped."""

    def _mine(self, tmp_path, monkeypatch, err):
        import fcntl

        from blastbox.host.ingress.node_reclaim import sweeper_lock

        def refuse(fd, op):
            raise OSError(err, "nope")

        monkeypatch.setattr(fcntl, "flock", refuse)
        with sweeper_lock(tmp_path) as mine:
            return mine

    def test_contention_stands_down(self, tmp_path, monkeypatch):
        assert self._mine(tmp_path, monkeypatch, errno.EAGAIN) is False

    @pytest.mark.parametrize("err", [errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOSYS])
    def test_a_filesystem_without_locks_still_sweeps(self, tmp_path, monkeypatch, err, caplog):
        with caplog.at_level("WARNING"):
            assert self._mine(tmp_path, monkeypatch, err) is True
        assert any("cannot be locked" in r.message for r in caplog.records), (
            "the sweeps were disabled (or enabled) with nothing in the log")

    def test_an_exception_in_the_body_is_not_replaced(self, tmp_path):
        """The helper yielded from inside `except`, so an exception in the caller's body was
        thrown back in, swallowed, and answered with a second yield -- which contextlib reports
        as RuntimeError("generator didn't stop after throw()"), losing the real failure."""
        from blastbox.host.ingress.node_reclaim import sweeper_lock

        with pytest.raises(ValueError, match="the sweep blew up"):
            with sweeper_lock(tmp_path) as mine:
                assert mine
                raise ValueError("the sweep blew up")


def test_a_repaired_result_is_not_expired_out_from_under_the_repair(tmp_path):
    """`_expire_job`'s terminal write was the one unfenced write left in this family, and #178
    made it concurrent: a node's `retry_pending_uploads` repairs FAILED->DONE with a CAS while
    every ingress host now runs `expire_due`. Unfenced, the sweep clobbered the repaired row
    back to EXPIRED with a null expires_at -- uncollectable forever, its fresh bytes orphaned."""
    from blastbox.host.jobs.retention import JobRetentionSweeper

    store = InMemoryJobStore()
    store.create(Job(job_id="r", engine="boxjs", filename="f", status=JobStatus.FAILED,
                     created_at=time.time() - 100, expires_at=time.time() - 1))
    sweeper = JobRetentionSweeper(tmp_path, blob_store=None)
    selected = store.get("r")
    # The repair wins between selection and the sweep's write, which is the race.
    store.update("r", status=JobStatus.DONE, expires_at=time.time() + 86_400)
    sweeper._expire_job(store, "r", None, expect_status=selected.status)
    after = store.get("r")
    assert after.status is JobStatus.DONE, "the sweep clobbered a freshly repaired result"
    assert after.expires_at is not None, "the repaired row lost its retention deadline"


def test_the_expiry_write_itself_is_a_cas_not_just_a_re_read(tmp_path):
    """The re-read above is the cheap half: it closes the window from selection to the start of
    the destructive work. The write still has to be a CAS, because the repair can land in the
    remaining window -- between that re-read and the write. Simulated by a store whose `get`
    answers with the row as it was, while the row itself has already moved on."""
    from blastbox.host.jobs.retention import JobRetentionSweeper

    class RepairLandsAfterTheReRead(InMemoryJobStore):
        def get(self, job_id):
            stale = super().get(job_id)
            if stale is not None and job_id == "r":
                # What the sweep saw a moment ago...
                stale = Job(job_id="r", engine="boxjs", filename="f",
                            status=JobStatus.FAILED, created_at=stale.created_at,
                            expires_at=time.time() - 1)
                # ...while the repair has ALREADY won, which only the CAS can now notice.
            return stale

    store = RepairLandsAfterTheReRead()
    store.create(Job(job_id="r", engine="boxjs", filename="f", status=JobStatus.DONE,
                     created_at=time.time() - 100, expires_at=time.time() + 86_400))
    JobRetentionSweeper(tmp_path, blob_store=None)._expire_job(
        store, "r", None, expect_status=JobStatus.FAILED)
    row = InMemoryJobStore.get(store, "r")
    assert row.status is JobStatus.DONE, (
        "the expiry write was unfenced, so a repair that landed after the re-read was clobbered "
        "to EXPIRED -- and with expires_at null the row can never be selected again, orphaning "
        "the bytes the repair had just uploaded")
    assert row.expires_at is not None
