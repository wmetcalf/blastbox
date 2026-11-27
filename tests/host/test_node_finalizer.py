"""node-finalizer: seals quarantined node results where the attest key lives."""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import tarfile
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import attest, node_results as nr
from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.node_finalizer import NodeFinalizer
from blastbox.limits import Limits

from .ingress.test_node_claim import _claim, auth, pki_dir, token_for  # noqa: F401

SAMPLE = b"sample-bytes"
SHA = hashlib.sha256(SAMPLE).hexdigest()


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_") or k in ("BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BLASTBOX_NODE_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setenv("BLASTBOX_HOST_ID", "fin-host")


def envelope(engine="clamav", sha=SHA):
    return {"engine": engine, "status": "ok", "input_sha256": sha,
            "detected": {"label": "bin", "mime": "application/octet-stream",
                         "confidence": 0.9, "source": "magika"},
            "artifacts": [], "warnings": [],
            "payload": {"_type": "extracted_text", "text": "hi", "char_count": 2}}


def tree_tar(env=None):
    body = json.dumps(env if env is not None else envelope()).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("metadata.json")
        ti.size = len(body)
        tf.addfile(ti, io.BytesIO(body))
    return buf.getvalue()


def build(tmp_path, *, key=True):
    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="s.bin", status=JobStatus.QUEUED,
                     created_at=time.time(), input_sha256=SHA))
    job = store.claim_next()
    assert job is not None
    k = attest.load_or_create_key(tmp_path / "keys" / "a.key") if key else None
    blobs = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    fin = NodeFinalizer(job_store=store, blob_store=blobs, limits=Limits(),
                        job_root=tmp_path / "jobs", attest_key=k)
    return store, job, fin, k


def spool(tmp_path, job, *, env=None, claim=None, node="alpha"):
    d = nr.spool_dir(nr.results_root(tmp_path / "jobs"), job.job_id, claim or job.claim_id)
    (d / "out").mkdir(parents=True)
    body = json.dumps(env if env is not None else envelope()).encode()
    (d / "out" / "metadata.json").write_bytes(body)
    now = attest.now_ms()
    nr.write_marker(d, nr.UploadMarker(
        job_id=job.job_id, claim_id=claim or job.claim_id, node_id=node,
        node_cert_sha256="c" * 64, worker_runtime="nsjail", received_at=time.time(),
        started_at_ms=now - 5, finished_at_ms=now))
    return d


def receipt(tmp_path):
    return json.loads((tmp_path / "blobs" / "results" / "job-1" / attest.RECEIPT_NAME).read_bytes())


def test_finalizer_marks_done_and_signs_receipt_with_node_fields(tmp_path):
    store, job, fin, key = build(tmp_path)
    d = spool(tmp_path, job)
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.DONE
    assert nr.read_outcome(d) == {"status": "done", "reason": None}
    assert not (d / "out").exists()
    body = receipt(tmp_path)
    assert attest.verify_body(key, body)
    doc = body["attestation"]
    assert doc["node_id"] == "alpha" and doc["node_cert_sha256"] == "c" * 64
    assert doc["worker_tier"] == "node-agent" and doc["worker_runtime"] == "nsjail"
    assert not [k for k in doc if k.startswith("net_")]


def test_finalizer_fails_untrusted_tree(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job, env=envelope(sha="0" * 64))
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.FAILED
    out = nr.read_outcome(d)
    assert out and out["status"] == "failed" and "trust" in out["reason"]


def test_finalizer_skips_lost_claim(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.QUEUED, claim_id=None)
    before = store.get("job-1")
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": "claim lost"}
    assert store.get("job-1") == before
    assert not (tmp_path / "blobs" / "results" / "job-1").exists()


def test_finalizer_idempotent_rerun(tmp_path):
    store, job, fin, _ = build(tmp_path)
    spool(tmp_path, job)
    assert fin.run_once() == 1
    after = store.get("job-1")
    assert fin.run_once() == 0
    assert store.get("job-1") == after


def test_held_lock_skips_dir(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    fd = os.open(d / ".finalize.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert fin.run_once() == 0
        assert store.get("job-1").status == JobStatus.RUNNING
    finally:
        os.close(fd)
    assert fin.run_once() == 1


def test_crash_after_cas_writes_outcome_without_rerunning(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.DONE)
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "done", "reason": None}
    assert not (tmp_path / "blobs" / "results" / "job-1").exists()      # nothing re-run


def test_crash_after_failed_cas_reports_job_error(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.FAILED, error="boom")
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": "boom"}


def test_old_outcome_dirs_are_removed(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    fin.run_once()
    old = time.time() - 7200
    os.utime(d / "outcome.json", (old, old))
    fin.run_once()
    assert not d.exists()


def test_receipt_without_node_fields_unchanged():
    obs = attest.RunObservation(job_id="j", engine="e", input_sha256="a" * 64,
                                worker_runtime="runc", worker_tier=None,
                                started_at_ms=1, finished_at_ms=2)
    doc = attest.build_receipt(obs, key_id="k", metadata_sha256="b" * 64,
                               issued_at_ms=3, host="h")
    assert "node_id" not in doc and "node_cert_sha256" not in doc
    assert list(doc) == ["v", "alg", "key_id", "host", "job_id", "engine", "status", "executor",
                         "input_sha256", "metadata_sha256", "worker_runtime", "worker_tier",
                         "started_at_ms", "finished_at_ms", "issued_at_ms"]
    with_node = attest.build_receipt(
        attest.RunObservation(**{**obs.__dict__, "node_id": "n", "node_cert_sha256": "c"}),
        key_id="k", metadata_sha256="b" * 64, issued_at_ms=3, host="h")
    assert with_node["node_id"] == "n" and with_node["node_cert_sha256"] == "c"


def test_cli_refuses_without_key_unless_no_receipts(tmp_path, monkeypatch, capsys):
    from blastbox.host import cli
    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)
    assert cli.main(["node-finalizer", "--once"]) == 1
    assert "attest key" in capsys.readouterr().err


def _run_end_to_end(tmp_path, pki_dir):  # noqa: F811
    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="sample.bin",
                     status=JobStatus.QUEUED, created_at=time.time(), input_sha256=SHA))
    root = tmp_path / "jobs"
    (root / "job-1" / "input").mkdir(parents=True)
    (root / "job-1" / "input" / "sample.bin").write_bytes(SAMPLE)
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir, job_root=root) is True
    c = TestClient(app)
    body = _claim(c, pki_dir, "alpha", engine="clamav").json()
    hdr = {**auth(token_for(c, pki_dir, "alpha")),
           "x-blastbox-claim-id": body["job"]["claim_id"], "x-blastbox-receipt": body["receipt"]}
    assert c.get("/v1/nodes/jobs/job-1/input", headers=hdr).content == SAMPLE
    put = lambda: c.put("/v1/nodes/jobs/job-1/result", headers=hdr, content=tree_tar())  # noqa: E731
    assert put().status_code == 202

    key = attest.load_or_create_key(tmp_path / "keys" / "a.key")
    fin = NodeFinalizer(job_store=store,
                        blob_store=LocalBlobStore(root, blob_root=tmp_path / "blobs"),
                        limits=Limits(), job_root=root, attest_key=key)
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.DONE
    rb = receipt(tmp_path)
    assert attest.verify_body(key, rb)
    from blastbox.host import node_results
    assert rb["attestation"]["node_id"] == "alpha"
    assert rb["attestation"]["node_cert_sha256"] == node_results.node_cert_sha256(pki_dir, "alpha")
    return put


def test_end_to_end_claim_input_result_finalise(tmp_path, pki_dir):  # noqa: F811
    _run_end_to_end(tmp_path, pki_dir)


@pytest.mark.xfail(strict=True, reason=(
    "B3 gap: put_result runs _running_owned BEFORE it consults outcome.json, so once the job "
    "is DONE a replayed PUT is refused 403 instead of answering 200 done"))
def test_replayed_put_after_finalise_returns_200_done(tmp_path, pki_dir):  # noqa: F811
    r = _run_end_to_end(tmp_path, pki_dir)()
    assert r.status_code == 200 and r.json() == {"status": "done"}
