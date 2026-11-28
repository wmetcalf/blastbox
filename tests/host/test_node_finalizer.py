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


def receipt(tmp_path, jid="job-1"):
    return json.loads((tmp_path / "blobs" / "results" / jid / attest.RECEIPT_NAME).read_bytes())


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
    assert d.is_dir()
    fd = os.open(fin._lock_path("job-1"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert fin.run_once() == 0
        assert store.get("job-1").status == JobStatus.RUNNING
    finally:
        os.close(fd)
    assert fin.run_once() == 1


def test_finalizers_exclude_each_other_per_job_not_per_claim(tmp_path):
    """Two claims of one job stage into the SAME job_root/<job>/output: a replica working an
    older claim of the job must keep every other replica off the job, whatever the claim."""
    store, job, fin, _ = build(tmp_path)
    old_claim = job.claim_id
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=old_claim,
                           status=JobStatus.QUEUED, claim_id=None)
    job_b = store.claim_next()
    assert job_b is not None and job_b.claim_id != old_claim
    d_b = spool(tmp_path, job_b)
    lock = fin._lock_path("job-1")
    assert lock.parent == nr.results_root(tmp_path / "jobs") / "job-1"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)    # replica 1, on the OLD claim
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert fin.run_once() == 0
        assert nr.read_outcome(d_b) is None
        assert not (tmp_path / "jobs" / "job-1" / "output").exists()
    finally:
        os.close(fd)
        lock.unlink()
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.DONE


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
    r = _run_end_to_end(tmp_path, pki_dir)()
    assert r.status_code == 200 and r.json() == {"status": "done"}


# ---------------------------------------------------------------- fix round 1

class FailingBlobs(LocalBlobStore):
    fail = True

    def put_output(self, job_id, output_dir):
        if self.fail:
            raise OSError("blob store down")
        return super().put_output(job_id, output_dir)


JID = "11111111-2222-3333-4444-555555555555"


def _build_blobs(tmp_path, cls, jid="job-1"):
    store = InMemoryJobStore()
    store.create(Job(job_id=jid, engine="clamav", filename="s.bin", status=JobStatus.QUEUED,
                     created_at=time.time(), input_sha256=SHA))
    job = store.claim_next()
    key = attest.load_or_create_key(tmp_path / "keys" / "a.key")
    blobs = cls(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    from blastbox.host.dispatch import Dispatcher  # noqa: F401
    fin = NodeFinalizer(job_store=store, blob_store=blobs, limits=Limits(),
                        job_root=tmp_path / "jobs", attest_key=key)
    fin._dispatcher._put_output_max_attempts = 1
    fin._dispatcher._put_output_retry_backoff_s = 0.0
    return store, job, fin, blobs


def test_retained_tree_survives_and_the_retry_sweep_uploads_it(tmp_path):
    store, job, fin, blobs = _build_blobs(tmp_path, FailingBlobs, jid=JID)
    d = spool(tmp_path, job)
    assert fin.run_once() == 1
    out = nr.read_outcome(d)
    assert out and out["status"] == "failed" and "retained" in out["reason"]
    staged = tmp_path / "jobs" / JID / "output"
    assert (staged / "metadata.json").is_file() and not (d / "out").exists()
    assert (tmp_path / "jobs" / JID / ".pending-upload").is_file()
    # age sweep must not destroy it
    old = time.time() - 7200
    os.utime(d / "outcome.json", (old, old))
    fin.run_once()
    assert (staged / "metadata.json").is_file()
    blobs.fail = False
    fin.run_once()
    assert store.get(JID).status == JobStatus.DONE
    assert attest.verify_body(attest.load_existing_key(tmp_path / "keys" / "a.key"),
                              receipt(tmp_path, JID))


def test_lost_claim_before_finalise_leaves_job_root_untouched(tmp_path):
    store, job, fin, _ = _build_blobs(tmp_path, LocalBlobStore)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.QUEUED, claim_id=None)
    fin.run_once()
    assert nr.read_outcome(d) == {"status": "failed", "reason": "claim lost"}
    assert not (tmp_path / "jobs" / "job-1" / "output").exists()


def test_claim_lost_during_finalise_discards_nothing_on_a_live_owner(tmp_path, monkeypatch):
    store, job, fin, _ = _build_blobs(tmp_path, LocalBlobStore)
    d = spool(tmp_path, job)
    real = fin._dispatcher.finalise_output

    def steal(j, out, obs, **kw):
        store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=j.claim_id,
                               status=JobStatus.QUEUED, claim_id=None)
        store.claim_next()
        return real(j, out, obs, **kw)

    monkeypatch.setattr(fin._dispatcher, "finalise_output", steal)
    fin.run_once()
    assert nr.read_outcome(d) == {"status": "failed", "reason": "claim lost"}
    assert store.get("job-1").status == JobStatus.RUNNING        # the new owner's row untouched
    assert (tmp_path / "jobs" / "job-1" / "output").exists()


class _Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def _clock(monkeypatch):
    from blastbox.host import node_finalizer as nf

    c = _Clock()
    monkeypatch.setattr(nf, "_now", c)
    return c


def test_poison_tree_is_failed_after_five_spaced_attempts(tmp_path, monkeypatch):
    clock = _clock(monkeypatch)
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(fin._dispatcher, "finalise_output", boom)
    for _ in range(4):
        assert fin.run_once() == 0
        assert nr.read_outcome(d) is None
        assert store.get("job-1").status == JobStatus.RUNNING
        clock.t += 3600
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": "finalisation failed repeatedly"}
    j = store.get("job-1")
    assert j.status == JobStatus.FAILED and "repeatedly" in (j.error or "")
    # the staged copy under job_root is spent too: nothing is left to leak
    assert not (tmp_path / "jobs" / "job-1" / "output").exists()


def test_a_short_outage_does_not_burn_the_poison_cap(tmp_path, monkeypatch):
    """The sweep runs every second; five failures inside a few seconds (a DB blip) must not
    destroy a quarantined result. Attempts back off, so only spaced failures count."""
    clock = _clock(monkeypatch)
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    real = fin._dispatcher.finalise_output
    down = {"on": True}

    def blip(*a, **k):
        if down["on"]:
            raise RuntimeError("store unavailable")
        return real(*a, **k)

    monkeypatch.setattr(fin._dispatcher, "finalise_output", blip)
    for _ in range(20):
        fin.run_once()
        clock.t += 1.0
    assert nr.read_outcome(d) is None
    assert store.get("job-1").status == JobStatus.RUNNING
    down["on"] = False
    clock.t += 3600
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.DONE


def test_transient_error_under_the_cap_then_succeeds(tmp_path, monkeypatch):
    store, job, fin, _ = build(tmp_path)
    spool(tmp_path, job)
    real = fin._dispatcher.finalise_output
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("transient")
        return real(*a, **k)

    monkeypatch.setattr(fin._dispatcher, "finalise_output", flaky)
    clock = _clock(monkeypatch)
    got = []
    for _ in range(3):
        got.append(fin.run_once())
        clock.t += 3600
    assert got == [0, 0, 1]
    assert store.get("job-1").status == JobStatus.DONE


def test_missing_input_sha_fails_the_job(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           input_sha256="")
    fin.run_once()
    out = nr.read_outcome(d)
    assert out and out["status"] == "failed" and "input hash" in out["reason"]
    assert store.get("job-1").status == JobStatus.FAILED


def test_node_reported_times_are_clamped():
    job = Job(job_id="j", engine="e", filename="f", status=JobStatus.RUNNING,
              created_at=0.0, input_sha256=SHA)
    now = attest.now_ms()
    m = nr.UploadMarker(job_id="j", claim_id="c", node_id="n", node_cert_sha256="x",
                        worker_runtime=None, received_at=0.0,
                        started_at_ms=now + 10**9, finished_at_ms=5)
    o = NodeFinalizer._observation(job, m)
    assert o.finished_at_ms >= o.started_at_ms
    assert o.started_at_ms <= now + 301_000 and o.finished_at_ms <= now + 301_000


def test_stale_dir_without_outcome_is_swept_and_logged(tmp_path, caplog):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    (d / "upload.json").unlink()                     # never becomes pending
    old = time.time() - 30 * 3600
    os.utime(d, (old, old))
    with caplog.at_level("WARNING"):
        fin.run_once()
    assert not d.exists() and "no outcome" in caplog.text


def test_no_receipts_path_marks_done_unsigned(tmp_path, caplog):
    store, job, fin, _ = build(tmp_path, key=False)
    spool(tmp_path, job)
    assert fin.run_once() == 1
    assert store.get("job-1").status == JobStatus.DONE
    p = tmp_path / "blobs" / "results" / "job-1" / attest.RECEIPT_NAME
    assert not p.exists() or "signature" not in json.loads(p.read_bytes()) \
        or json.loads(p.read_bytes()).get("signature") is None


def test_cli_no_receipts_logs_a_loud_warning(tmp_path, monkeypatch, caplog):
    from blastbox.host import cli, node_finalizer
    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)

    class Fake:
        def __init__(self, **kw):
            Fake.key = kw["attest_key"]

        def run_once(self):
            return 0

    monkeypatch.setattr(node_finalizer, "NodeFinalizer", Fake)
    import blastbox.host.jobs.factory as jf
    monkeypatch.setattr(jf, "build_job_store_from_env", lambda *a, **k: InMemoryJobStore())
    with caplog.at_level("WARNING"):
        assert cli.main(["node-finalizer", "--once", "--no-receipts"]) == 0
    assert Fake.key is None and "--no-receipts" in caplog.text


def test_node_results_honour_the_job_retention_period(tmp_path, monkeypatch):
    """A DONE node result gets the same expires_at a dispatcher would stamp, and the
    pending-upload sweep it runs repairs with that retention too."""
    from blastbox.host.jobs import retention

    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="s.bin", status=JobStatus.QUEUED,
                     created_at=time.time(), input_sha256=SHA))
    job = store.claim_next()
    blobs = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    fin = NodeFinalizer(job_store=store, blob_store=blobs, limits=Limits(),
                        job_root=tmp_path / "jobs", attest_key=None, job_retention_seconds=60)
    spool(tmp_path, job)
    seen = {}
    real = retention.retry_pending_uploads

    def spy(*a, **k):
        seen.update(k)
        return real(*a, **k)

    from blastbox.host import node_finalizer as nf
    monkeypatch.setattr(nf, "retry_pending_uploads", spy)
    before = time.time()
    assert fin.run_once() == 1
    j = store.get("job-1")
    assert j.status == JobStatus.DONE
    assert j.expires_at is not None and before + 55 <= j.expires_at <= time.time() + 65
    assert seen.get("retention_seconds") == 60


def test_failed_reason_is_the_sanitised_row_error_never_raw(tmp_path, monkeypatch):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    raw = "unexpected trust validation error: /var/lib/blastbox/jobs/job-1/output/x boom"

    def fail(j, out, obs, **k):
        fin._dispatcher._fail_job(j, raw)
        return f"failed: {raw}"

    monkeypatch.setattr(fin._dispatcher, "finalise_output", fail)
    assert fin.run_once() == 1
    out = nr.read_outcome(d)
    assert out["status"] == "failed"
    assert "/var/lib" not in out["reason"] and out["reason"] == store.get("job-1").error


def test_failed_but_cas_lost_is_recorded_as_claim_lost(tmp_path, monkeypatch):
    """finalise_output says 'failed: ...' even when its _fail_job CAS lost to a peer."""
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)

    def lost(j, out, obs, **k):
        store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=j.claim_id,
                               status=JobStatus.QUEUED, claim_id=None)
        fin._dispatcher._fail_job(j, "output trust validation failed: x")   # loses the CAS
        return "failed: output trust validation failed: x"

    monkeypatch.setattr(fin._dispatcher, "finalise_output", lost)
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": "claim lost"}


def test_sweep_removes_crash_orphaned_partials_and_upload_spools(tmp_path):
    store, job, fin, _ = build(tmp_path)
    root = nr.results_root(tmp_path / "jobs")
    partial = root / "job-1" / "abcd.partial-xyz"
    (partial / "out").mkdir(parents=True)
    (partial / "out" / "f").write_bytes(b"x" * 1000)
    spool_tmp = root / ".upload-123.tar"
    spool_tmp.write_bytes(b"x")
    fresh = root / "job-1" / "ffff.partial-new"
    fresh.mkdir()
    old = time.time() - 2 * 3600
    for p in (partial / "out" / "f", partial / "out", partial, spool_tmp):
        os.utime(p, (old, old))
    fin.run_once()
    assert not partial.exists() and not spool_tmp.exists()
    assert fresh.exists()                    # a live extraction is left alone


def test_sweep_spares_a_partial_whose_extraction_is_still_writing(tmp_path):
    """The partial dir's own mtime does not move while a big file inside grows."""
    store, job, fin, _ = build(tmp_path)
    root = nr.results_root(tmp_path / "jobs")
    partial = root / "job-1" / "abcd.partial-live"
    (partial / "out" / "deep").mkdir(parents=True)
    (partial / "out" / "deep" / "big").write_bytes(b"x")       # written just now
    old = time.time() - 2 * 3600
    for p in (partial, partial / "out", partial / "out" / "deep"):
        os.utime(p, (old, old))
    fin.run_once()
    assert (partial / "out" / "deep" / "big").exists()


def test_sweep_removes_a_crash_left_upload_lock_but_not_a_held_one(tmp_path):
    store, job, fin, _ = build(tmp_path)
    root = nr.results_root(tmp_path / "jobs")
    (root / "job-1").mkdir(parents=True, exist_ok=True)
    left = root / "job-1" / "aaaa.ulock"
    left.write_bytes(b"")
    held = nr.UploadLock(root / "job-1" / "bbbb.ulock")
    assert held.try_acquire()
    old = time.time() - 2 * 3600
    for p in (left, held.path):
        os.utime(p, (old, old))
    fin.run_once()
    assert not left.exists()
    assert held.path.exists()
    held.release()


def test_finalizer_never_resurrects_or_litters_job_root(tmp_path):
    """The per-job lock lives in the results spool, which the finalizer's own sweep owns; it
    must not create job_root/<job> for a claim-lost job nor leave a lock behind there."""
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.QUEUED, claim_id=None)
    assert fin.run_once() == 1
    assert not (tmp_path / "jobs" / "job-1").exists()
    old = time.time() - 7200
    os.utime(d / "outcome.json", (old, old))
    fin.run_once()
    assert not (nr.results_root(tmp_path / "jobs") / "job-1").exists()


def test_sweep_removes_a_finalize_lock_left_by_a_killed_finalizer(tmp_path):
    store, job, fin, _ = build(tmp_path)
    jd = nr.results_root(tmp_path / "jobs") / "job-1"
    jd.mkdir(parents=True)
    left = jd / ".finalize.lock"
    left.write_bytes(b"")                                 # SIGKILLed holder: never unlinked
    old = time.time() - 2 * 3600
    os.utime(left, (old, old))
    fin.run_once()
    assert not jd.exists()


def test_crash_after_retained_fail_keeps_the_retained_outcome(tmp_path):
    """finalise_output marked the row FAILED and the tree retained, then the finalizer died
    before outcome.json: recovery must record RETAINED_REASON (so a later sweep repair to
    DONE reads as done on replay), not the row's error."""
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    (tmp_path / "jobs" / "job-1").mkdir(parents=True, exist_ok=True)
    (tmp_path / "jobs" / "job-1" / ".pending-upload").write_text(job.claim_id)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.FAILED, error="result upload failed")
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": nr.RETAINED_REASON}


def test_crash_after_failed_cas_ignores_another_claims_sentinel(tmp_path):
    store, job, fin, _ = build(tmp_path)
    d = spool(tmp_path, job)
    (tmp_path / "jobs" / "job-1").mkdir(parents=True, exist_ok=True)
    (tmp_path / "jobs" / "job-1" / ".pending-upload").write_text("someone-else")
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=job.claim_id,
                           status=JobStatus.FAILED, error="boom")
    assert fin.run_once() == 1
    assert nr.read_outcome(d) == {"status": "failed", "reason": "boom"}


def test_cli_accepts_a_float_retention_like_the_ingress(tmp_path, monkeypatch):
    """The ingress parses BLASTBOX_JOB_RETENTION_SECONDS as a float; "3600.0" must start us."""
    from blastbox.host import cli, node_finalizer
    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.setenv("BLASTBOX_JOB_RETENTION_SECONDS", "3600.0")
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)

    class Fake:
        def __init__(self, **kw):
            Fake.retention = kw["job_retention_seconds"]

        def run_once(self):
            return 0

    monkeypatch.setattr(node_finalizer, "NodeFinalizer", Fake)
    import blastbox.host.jobs.factory as jf
    monkeypatch.setattr(jf, "build_job_store_from_env", lambda *a, **k: InMemoryJobStore())
    assert cli.main(["node-finalizer", "--once", "--no-receipts"]) == 0
    assert Fake.retention == 3600
