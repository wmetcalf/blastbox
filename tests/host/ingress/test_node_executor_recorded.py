"""The host records WHICH node it handed a job to -- and no node can rewrite that.

A host attestation names the executor (`node:<node_id>`). The job row previously carried only a
`node:` claim prefix, not the node's identity, so without this there was nothing host-recorded to
name. It is stamped by the control plane in the same CAS as the prefix and is not node-writable.
"""
from __future__ import annotations

from blastbox.host.jobs.base import JobStatus
from tests.host.ingress.test_node_claim import (  # noqa: F401 (fixtures)
    _claim,
    auth,
    client,
    pki_dir,
    queued,
    store,
    token_for,
)


def test_hand_over_records_the_node(store, pki_dir):  # noqa: F811
    c = client(store, pki_dir)
    queued(store)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 200, r.text
    job = store.get("job-1")
    assert job.status == JobStatus.RUNNING
    assert job.claim_id.startswith("node:")
    assert job.executor_node == "alpha"


def test_a_node_cannot_write_executor_node(store, pki_dir):  # noqa: F811
    c = client(store, pki_dir)
    queued(store)
    tok = token_for(c, pki_dir, "alpha")
    r = _claim(c, pki_dir, "alpha", engine="clamav", token=tok)
    body = r.json()
    w = c.post("/v1/nodes/jobs/job-1", headers=auth(tok),
               json={"claim_id": body["job"]["claim_id"], "receipt": body["receipt"],
                     "fields": {"executor_node": "someone-else"}})
    assert w.status_code == 400, w.text
    assert store.get("job-1").executor_node == "alpha"


def test_a_refused_job_released_back_does_not_keep_a_node(store, pki_dir):  # noqa: F811
    """beta may not run clamav; the walk stamps then releases. No executor may stick."""
    c = client(store, pki_dir)
    queued(store, engine="clamav")
    _claim(c, pki_dir, "beta", engine="clamav")
    job = store.get("job-1")
    assert job.status == JobStatus.QUEUED
    assert job.executor_node is None
