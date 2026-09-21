"""The property #178 asks for, end to end: a node whose ONLY credential is a certificate.

Not "a node that is asked not to take ungranted work" -- a node that CANNOT, because the
authenticated hand-over is the only path it has. Every earlier shape of this fix left a
second path (the database) and checked the first one; these tests assert the second path is
absent, which is the part that actually makes the control a control.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import pki
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.factory import build_job_store_from_env
from blastbox.host.jobs.http_store import HttpJobStore, NodeStoreUnsupported
from blastbox.host.jobs.memory import InMemoryJobStore

WG = "A" * 42 + "B="


@pytest.fixture
def deployment(tmp_path):
    """A control plane holding the database, and two nodes holding only certificates."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("cleared", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",), tiers=("socks",), credentials=True)).write(d, "node-cleared")
    ca.issue_node("restricted", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("boxjs",), credentials=False)).write(d, "node-restricted")

    backing = InMemoryJobStore()
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=backing, pki_dir=d) is True
    client = TestClient(app)

    def as_node(name):
        """Exactly what a federated node's environment holds: a URL and a certificate."""
        store = build_job_store_from_env({
            "BLASTBOX_DATABASE_URL": "https://control-plane.example",
            "BLASTBOX_NODE_CERT": str(d / f"node-{name}.crt"),
        })
        assert isinstance(store, HttpJobStore)
        store._transport = lambda method, path, *, json=None, params=None, headers=None: (
            lambda r: (r.status_code, r.json() if r.content else None))(
                client.request(method, path, json=json, params=params,
                               headers=headers or {}))
        return store

    return d, backing, as_node


def test_the_node_environment_contains_no_database_credential(deployment):
    """The whole point, stated as configuration: there is no DSN anywhere on the node."""
    _d, _backing, as_node = deployment
    store = as_node("cleared")
    # Nothing on this store can reach a database: no engine, no connection, no redis client.
    for forbidden in ("_engine", "_conn", "_connection", "_r", "_redis", "_pool", "_dsn"):
        assert not hasattr(store, forbidden), (
            f"the node's store exposes {forbidden!r} -- if a database handle has been added "
            f"here, the second path this issue is about is back")


def test_a_restricted_node_cannot_obtain_work_it_is_not_granted(deployment):
    _d, backing, as_node = deployment
    backing.create(Job(job_id="sensitive", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time()))
    restricted = as_node("restricted")
    assert restricted.claim_next(engine="clamav") is None
    job = backing.get("sensitive")
    assert job.status == JobStatus.QUEUED, "the input was handed to an ungranted node"
    assert job.claim_id is None


def test_and_it_has_no_other_way_to_take_it(deployment):
    """Having been refused the claim, every remaining route out of this store is closed."""
    _d, backing, as_node = deployment
    backing.create(Job(job_id="sensitive", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time()))
    restricted = as_node("restricted")

    # It cannot read the job it was refused -- and is told so by an exception, never by a
    # None that dispatch's delete gates would read as "nobody needs these bytes".
    from blastbox.host.jobs.http_store import ClaimNotHeld

    with pytest.raises(ClaimNotHeld):
        restricted.get("sensitive")
    # ...cannot write to it...
    with pytest.raises(PermissionError):
        restricted.update("sensitive", status=JobStatus.RUNNING)
    # ...cannot enumerate the queue to find out what else is there...
    with pytest.raises(NodeStoreUnsupported):
        restricted.list()
    with pytest.raises(NodeStoreUnsupported):
        restricted.count()
    # ...cannot manufacture work for itself...
    with pytest.raises(NodeStoreUnsupported):
        restricted.create(Job(job_id="mine", engine="boxjs", filename="f",
                              status=JobStatus.QUEUED, created_at=0.0))
    # ...and cannot destroy the evidence.
    with pytest.raises(NodeStoreUnsupported):
        restricted.delete("sensitive")
    assert backing.get("sensitive").status == JobStatus.QUEUED


def test_a_cleared_node_is_not_impeded(deployment):
    """A control that also stops the legitimate node is not a fix. The granted node claims,
    runs and reports through exactly the same path."""
    _d, backing, as_node = deployment
    backing.create(Job(job_id="ok", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time()))
    cleared = as_node("cleared")
    job = cleared.claim_next(engine="clamav")
    assert job is not None and job.job_id == "ok"
    assert cleared.update_if_status(job.job_id, JobStatus.RUNNING,
                                    expect_claim_id=job.claim_id,
                                    worker_runtime="runc") is True
    assert backing.get("ok").worker_runtime == "runc"


def test_one_node_cannot_interfere_with_anothers_running_job(deployment):
    """Both hold valid certificates and valid sessions. Neither may touch the other's work."""
    _d, backing, as_node = deployment
    backing.create(Job(job_id="ok", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time()))
    cleared, restricted = as_node("cleared"), as_node("restricted")
    job = cleared.claim_next(engine="clamav")
    assert job is not None

    # The restricted node knows the job id (they are not secret) and even the claim id.
    restricted._claims[job.job_id] = (job.claim_id or "", "a-receipt-it-made-up")
    status, _body = restricted._call("POST", f"/v1/nodes/jobs/{job.job_id}",
                                     json={"claim_id": job.claim_id,
                                           "receipt": "a-receipt-it-made-up",
                                           "fields": {"error": "sabotaged"}})
    assert status == 403
    assert backing.get("ok").error is None


def test_a_federated_node_counts_as_a_shared_queue(deployment):
    """The 17,626-job protection must not be disarmed by the topology it most applies to.

    `is_shared_job_store` gates `check_store_coherence` AND the operator's explicit
    BLASTBOX_REQUIRE_SHARED_BLOB_STORE. It enumerated Redis and Postgres and answered False for
    anything else -- so a federated node, whose queue is on ANOTHER HOST by construction, was
    classified single-process and booted clean with a LocalBlobStore. That configuration is the
    incident: results written to a host-local directory, every artifact 404ing on the ingress.
    """
    import pytest as _pytest

    from blastbox.host.blobs.local import LocalBlobStore
    from blastbox.host.canary import check_store_coherence, is_shared_job_store

    d, _backing, as_node = deployment
    store = as_node("cleared")
    assert is_shared_job_store(store) is True

    local = d.parent / "blobs"
    local.mkdir(exist_ok=True)
    with _pytest.raises(Exception) as e:
        check_store_coherence(store, LocalBlobStore(local), local, require_shared=True)
    assert "shared" in str(e.value).lower() or "local" in str(e.value).lower(), e.value


def test_a_node_cannot_assert_its_own_runtime_tier(deployment):
    """`claim_next(claimant_tier=...)` decides which target_tier-PINNED jobs a caller may take,
    and pinning is an operator containment control — dispatch pins work so a pool-runtime drift
    cannot route it onto a worker with a different egress posture. Taken from the request it was
    the very defect `ClaimRequest` says it fixed by deleting `tier`: a caller choosing its own
    authorisation predicate. Measured: a node running a plain cold pool asked for
    claimant_tier="firecracker" and received the hardware-isolated job.

    It cannot be authorised either, because a node's RUNTIME tier is not in its certificate —
    `NodeGrants` carries engines, netpolicy tiers and credentials, and none of them says "this
    node runs firecracker". So it is refused with a reason rather than dropped silently, which
    would leave a dispatcher believing it was routing when it was not."""
    _d, backing, as_node = deployment
    backing.create(Job(job_id="pinned", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time(),
                       target_tier="firecracker"))
    node = as_node("cleared")
    with pytest.raises(NodeStoreUnsupported, match="runtime tier"):
        node.claim_next(engine="clamav", claimant_tier="firecracker")
    assert backing.get("pinned").status == JobStatus.QUEUED


def test_a_pinned_job_is_not_handed_to_a_node_that_asks_plainly_either(deployment):
    """Without an asserted tier, `claim_next` skips target_tier-pinned jobs on its own."""
    _d, backing, as_node = deployment
    backing.create(Job(job_id="pinned", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time(),
                       target_tier="firecracker"))
    assert as_node("cleared").claim_next(engine="clamav") is None
    assert backing.get("pinned").status == JobStatus.QUEUED
