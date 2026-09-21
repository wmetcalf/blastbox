"""A node whose only credential is a certificate (#178).

These tests drive the REAL ingress routes through the real store -- the transport seam is
wired to a FastAPI TestClient rather than mocked -- because the thing worth proving is that
the two halves agree. A mocked control plane would pass while the wire format drifted.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import pki
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.http_store import HttpJobStore, NodeStoreUnsupported
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def fleet(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), tiers=("socks",))).write(d, "node-alpha")
    ca.issue_node("beta", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("boxjs",))).write(d, "node-beta")
    return d


@pytest.fixture
def backing():
    return InMemoryJobStore()


@pytest.fixture
def control_plane(backing, fleet):
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=backing, pki_dir=fleet) is True
    return TestClient(app)


def node_store(control_plane, fleet, who="alpha"):
    """An HttpJobStore whose transport is the live app."""
    def transport(method, path, *, json=None, params=None, headers=None):
        r = control_plane.request(method, path, json=json, params=params,
                                  headers=headers or {})
        try:
            return r.status_code, (r.json() if r.content else None)
        except ValueError:
            return r.status_code, None

    return HttpJobStore("http://control-plane", cert_path=fleet / f"node-{who}.crt",
                        transport=transport)


def queued(backing, job_id="job-1", engine="clamav"):
    backing.create(Job(job_id=job_id, engine=engine, filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time()))
    return job_id


def test_a_granted_node_claims_through_the_control_plane(control_plane, fleet, backing):
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None and job.job_id == "job-1"
    assert job.status == JobStatus.RUNNING
    assert backing.get("job-1").status == JobStatus.RUNNING


def test_an_ungranted_node_gets_nothing_and_the_job_stays_queued(control_plane, fleet,
                                                                 backing):
    """THE POINT OF THE WHOLE EXERCISE. beta holds a valid certificate and a valid session
    and NO database credentials, so this is its only path -- and it leads nowhere."""
    queued(backing, engine="clamav")
    s = node_store(control_plane, fleet, "beta")
    assert s.claim_next(engine="clamav") is None
    assert backing.get("job-1").status == JobStatus.QUEUED
    assert backing.get("job-1").claim_id is None


def test_no_work_returns_none_rather_than_raising(control_plane, fleet):
    s = node_store(control_plane, fleet, "alpha")
    assert s.claim_next(engine="clamav") is None


def test_the_holder_can_update_the_job_it_claimed(control_plane, fleet, backing):
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None
    updated = s.update(job.job_id, worker_runtime="runc")
    assert updated.worker_runtime == "runc"
    assert backing.get(job.job_id).worker_runtime == "runc"


def test_a_conditional_update_reports_the_cas_honestly(control_plane, fleet, backing):
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None
    assert s.update_if_status(job.job_id, JobStatus.RUNNING,
                              expect_claim_id=job.claim_id,
                              worker_tier="gvisor") is True
    assert backing.get(job.job_id).worker_tier == "gvisor"
    # Wrong expectation -> False, and NOTHING written. A True here would let a dispatcher
    # believe it had fenced a transition it had not.
    assert s.update_if_status(job.job_id, JobStatus.QUEUED,
                              expect_claim_id=job.claim_id, error="stale") is False
    assert backing.get(job.job_id).error is None


def test_a_stale_claim_id_loses_the_cas_rather_than_writing(control_plane, fleet, backing):
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None
    assert s.update_if_status(job.job_id, JobStatus.RUNNING,
                              expect_claim_id="somebody-elses-claim",
                              error="hijacked") is False
    assert backing.get(job.job_id).error is None


def test_reading_a_job_this_node_does_not_hold_RAISES_rather_than_returning_none(
        control_plane, fleet, backing):
    """NOT None, and the difference destroyed data before it was fixed.

    In every other store `get() -> None` means the row DOES NOT EXIST, and dispatch deletes on
    that: `_delete_input_if_owned` and `_purge_job_dir_if_owned` both treat None as "nobody
    needs these bytes". Returning None for "not mine" made them delete a peer's staged sample
    and its whole job tree mid-detonation. Dispatch already fails SAFE on an exception, so this
    raises into the contract it already has."""
    from blastbox.host.jobs.http_store import ClaimNotHeld

    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    with pytest.raises(ClaimNotHeld):
        s.get("job-1")
    claimed = s.claim_next(engine="clamav")
    assert claimed is not None
    assert s.get(claimed.job_id) is not None


def test_a_job_it_completed_is_still_readable_afterwards(control_plane, fleet, backing):
    """Dispatch reads the job back from its terminal `finally` THREE times -- the outcome
    metric and both ownership gates. Retiring the receipt on the terminal write made every
    completed job unreadable by the process that had just completed it, so the metric would
    have recorded outcome="failed" for every successful job on a federated node."""
    from blastbox.host.jobs.base import JobStatus

    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None
    assert s.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                              status=JobStatus.DONE) is True
    back = s.get(job.job_id)
    assert back is not None and back.status is JobStatus.DONE, (
        "the node cannot read back the job it just completed")


def test_the_claim_map_is_bounded(control_plane, fleet, backing):
    from blastbox.host.jobs import http_store as hs

    s = node_store(control_plane, fleet, "alpha")
    for i in range(hs._MAX_TRACKED_CLAIMS + 50):
        s._claims[f"job-{i}"] = ("c", "r")
    s._retire_if_settled("job-0", None)
    assert len(s._claims) <= hs._MAX_TRACKED_CLAIMS


def test_writing_without_a_claim_refuses_loudly(control_plane, fleet, backing):
    """Silence here would make a restarted dispatcher look like it was reporting results."""
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    with pytest.raises(PermissionError, match="no claim receipt"):
        s.update("job-1", worker_runtime="runc")


def test_a_restart_abandons_in_flight_claims_rather_than_faking_them(control_plane, fleet,
                                                                     backing):
    """The receipt is process-local by design. A restarted node must not be able to report
    on a job whose worker it has also lost -- the reclaim-on-timeout path owns those."""
    queued(backing)
    first = node_store(control_plane, fleet, "alpha")
    job = first.claim_next(engine="clamav")
    assert job is not None
    restarted = node_store(control_plane, fleet, "alpha")
    with pytest.raises(PermissionError):
        restarted.update(job.job_id, worker_runtime="runc")


class TestTheNodeSurfaceIsDeliberatelySmaller:
    """A node with database credentials can submit and delete jobs today. It has no business
    doing either, and the way to guarantee that is for the capability to be ABSENT."""

    @pytest.mark.parametrize("op", ["create", "delete", "list"])
    def test_it_raises_rather_than_silently_doing_nothing(self, control_plane, fleet, op):
        """`count` is NOT in this list any more, deliberately.

        It used to be, and that was the safe-looking answer that under-served invisibly: the
        sizer catches any store error and falls back to a backlog that starts at 0 and never
        advances, so refusing to count was indistinguishable from an empty queue. It now answers
        exactly the sizer's question -- QUEUED, by granted engine, one integer -- and refuses
        every other shape. See TestTheScopedBacklog.
        """
        s = node_store(control_plane, fleet, "alpha")
        args = {"create": (Job(job_id="x", engine="clamav", filename="f",
                               status=JobStatus.QUEUED, created_at=0.0),),
                "delete": ("x",), "list": ()}[op]
        with pytest.raises(NodeStoreUnsupported):
            getattr(s, op)(*args)


class TestSessionHandling:
    def test_one_handshake_serves_many_calls(self, control_plane, fleet, backing):
        """A handshake per request would triple the cost of the hot path."""
        calls = []

        def counting(method, path, *, json=None, params=None, headers=None):
            calls.append(path)
            r = control_plane.request(method, path, json=json, params=params,
                                      headers=headers or {})
            return r.status_code, (r.json() if r.content else None)

        s = HttpJobStore("http://cp", cert_path=fleet / "node-alpha.crt",
                         transport=counting)
        for i in range(4):
            queued(backing, job_id=f"job-{i}")
            assert s.claim_next(engine="clamav") is not None
        assert calls.count("/v1/nodes/session") == 1, calls

    def test_an_expired_session_is_renewed_and_the_call_succeeds(self, control_plane, fleet,
                                                                 backing):
        queued(backing)
        s = node_store(control_plane, fleet, "alpha")
        assert s.claim_next(engine="clamav") is not None
        # Force the token to look expired, as a real 10-minute gap would.
        s._token_expires_at = 0.0
        queued(backing, job_id="job-2")
        assert s.claim_next(engine="clamav") is not None

    def test_a_refused_node_does_not_re_handshake(self, control_plane, fleet, backing):
        """COUNTS THE HANDSHAKES, which is what the earlier version of this test did not.

        It asserted only that /claim was attempted twice, so it passed while the retry discarded
        a valid session and re-handshaked on EVERY refused request -- measured at 22 requests
        where 5 were correct, i.e. the amplification the retry was written to prevent. The
        control plane now answers 401 for a session problem and 403 for an authorisation one, so
        a refused node keeps its session and simply asks again next poll."""
        attempts = []

        def counting(method, path, *, json=None, params=None, headers=None):
            attempts.append(path)
            r = control_plane.request(method, path, json=json, params=params,
                                      headers=headers or {})
            return r.status_code, (r.json() if r.content else None)

        queued(backing, engine="clamav")
        s = HttpJobStore("http://cp", cert_path=fleet / "node-beta.crt",
                         transport=counting)
        for _ in range(5):
            assert s.claim_next(engine="clamav") is None
        handshakes = attempts.count("/v1/nodes/session")
        assert handshakes == 1, (
            f"a refused node re-handshaked {handshakes} times across 5 polls; a 403 must not "
            "discard a valid session")
        assert attempts.count("/v1/nodes/claim") == 5, attempts


def test_claiming_without_naming_an_engine_asks_for_whatever_is_granted(control_plane,
                                                                        fleet, backing):
    """`dispatch.py` calls claim_next(claimant_tier=...) with NO engine whenever engine
    scoping is off -- which is the DEFAULT. An earlier version of this store raised here, so
    a credential-less dispatcher on default configuration failed on every single claim.

    Omitting the engine now asks the control plane for anything this certificate grants,
    which it can answer because it holds the certificate store."""
    queued(backing, engine="clamav")
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next()
    assert job is not None and job.job_id == "job-1"


def test_omitting_the_engine_does_not_widen_the_grant(control_plane, fleet, backing):
    queued(backing, engine="clamav")
    s = node_store(control_plane, fleet, "beta")
    assert s.claim_next() is None
    assert backing.get("job-1").status == JobStatus.QUEUED


def test_one_refused_engine_does_not_abandon_the_granted_ones(control_plane, fleet,
                                                              backing):
    """A dispatcher passes the SET of engines it handles. alpha is granted clamav and not
    boxjs, so the boxjs ask is refused -- and the clamav work must still be found.

    Measured: with a single engine, "give up on the first 403" and "skip it and keep
    looking" behave identically, so this is the only shape that tells them apart. Getting it
    wrong would idle a correctly-configured node whose engine set happens to be iterated in
    an unlucky order."""
    queued(backing, engine="clamav")
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine={"boxjs", "clamav"})
    assert job is not None, "a refused engine stopped the search for a granted one"
    assert job.engine == "clamav"


def test_every_requested_engine_refused_is_simply_no_work(control_plane, fleet, backing):
    queued(backing, engine="clamav")
    s = node_store(control_plane, fleet, "beta")
    assert s.claim_next(engine={"clamav", "authenticode"}) is None
    assert backing.get("job-1").status == JobStatus.QUEUED


def test_a_control_plane_that_omits_the_receipt_is_refused_not_trusted(control_plane, fleet,
                                                                      backing):
    """An older control plane, or a proxy that rewrote the body. Running the job would mean
    doing the work and then being unable to deliver the result -- so decline it instead, and
    leave it to be reclaimed."""
    def strips_receipt(method, path, *, json=None, params=None, headers=None):
        r = control_plane.request(method, path, json=json, params=params,
                                 headers=headers or {})
        body = r.json() if r.content else None
        if isinstance(body, dict):
            body.pop("receipt", None)
        return r.status_code, body

    queued(backing)
    s = HttpJobStore("http://cp", cert_path=fleet / "node-alpha.crt",
                     transport=strips_receipt)
    with pytest.raises(RuntimeError, match="receipt"):
        s.claim_next(engine="clamav")


class TestTheScopedBacklog:
    """A node's sizer must be able to read a backlog, or it under-serves invisibly.

    `DispatcherSizer` catches any store error and falls back to a last-known value that starts at
    0 and never advances — so a permanent refusal is indistinguishable from an empty queue and the
    pool sits at its floor however deep the queue is. Raising on `count` was necessary and NOT
    sufficient, which is why this route exists.

    A COUNT IS NOT AN ENUMERATION: one integer, scoped server-side to engines the certificate
    already grants. That is the whole reason it is answerable while `list` is not.
    """

    def test_it_counts_the_queue_for_a_granted_engine(self, control_plane, fleet, backing):
        for i in range(3):
            queued(backing, job_id=f"c{i}", engine="clamav")
        assert node_store(control_plane, fleet, "alpha").count(
            JobStatus.QUEUED, engine="clamav") == 3

    def test_it_does_not_count_work_this_node_is_not_granted(self, control_plane, fleet,
                                                             backing):
        queued(backing, job_id="mine", engine="clamav")
        for i in range(5):
            queued(backing, job_id=f"theirs{i}", engine="boxjs")
        s = node_store(control_plane, fleet, "alpha")     # granted clamav only
        assert s.count(JobStatus.QUEUED, engine="clamav") == 1
        # Asking about an engine it does not hold is a zero, not a peek at the real number.
        assert s.count(JobStatus.QUEUED, engine="boxjs") == 0

    def test_omitting_the_engine_counts_everything_granted(self, control_plane, fleet,
                                                           backing):
        queued(backing, job_id="a", engine="clamav")
        queued(backing, job_id="b", engine="boxjs")
        assert node_store(control_plane, fleet, "alpha").count(JobStatus.QUEUED) == 1

    def test_the_sizer_gets_a_real_number_through_its_own_helper(self, control_plane, fleet,
                                                                backing):
        """Through `local_backlog_fn`, which is what the sizer actually calls — not the store
        directly. A route the real caller cannot use is not a fix."""
        from blastbox.host.node_sizer import local_backlog_fn

        for i in range(4):
            queued(backing, job_id=f"c{i}", engine="clamav")
        fn = local_backlog_fn(node_store(control_plane, fleet, "alpha"), ["clamav"])
        assert fn() == 4

    def test_a_question_it_cannot_answer_truthfully_is_refused(self, control_plane, fleet):
        """A number computed from a DIFFERENT question than the caller asked is worse than a
        refusal: a sizer acting on a silently-wrong backlog has no symptom."""
        s = node_store(control_plane, fleet, "alpha")
        with pytest.raises(NodeStoreUnsupported):
            s.count(JobStatus.QUEUED, engine="clamav", q="sample")
        with pytest.raises(NodeStoreUnsupported):
            s.count(JobStatus.RUNNING, engine="clamav")
        # claimant_tier is DROPPED (the sizer always sends it) and untargeted_only is passed
        # through (a subset, never a widening) -- neither is a refusal. See the next test.

    def test_the_sizers_REAL_call_shape_works(self, control_plane, fleet, backing, caplog):
        """cli.py builds local_backlog_fn(store, served, claimant_tier=tier) and a second one
        with untargeted_only=True. My earlier test called it with NEITHER, so it passed while
        the real caller raised on every tick and the sizer sat at its floors. This is the shape
        the sizer actually uses."""
        from blastbox.host.node_sizer import local_backlog_fn

        for i in range(3):
            queued(backing, job_id=f"c{i}", engine="clamav")
        backing.create(Job(job_id="pinned", engine="clamav", filename="f",
                           status=JobStatus.QUEUED, created_at=time.time(),
                           target_tier="firecracker"))
        s = node_store(control_plane, fleet, "alpha")
        with caplog.at_level("INFO"):
            tiered = local_backlog_fn(s, ["clamav"], claimant_tier="cold")()
            unpinned = local_backlog_fn(s, ["clamav"], untargeted_only=True)()
        assert tiered == 4 and unpinned == 3, (tiered, unpinned)
        assert any("claimant_tier" in r.message for r in caplog.records)

    def test_it_still_cannot_enumerate(self, control_plane, fleet, backing):
        """The count must not become a crack in the same wall."""
        queued(backing)
        with pytest.raises(NodeStoreUnsupported):
            node_store(control_plane, fleet, "alpha").list()
