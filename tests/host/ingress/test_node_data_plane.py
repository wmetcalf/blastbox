"""``GET /jobs/{id}/input`` and ``PUT /jobs/{id}/result``: authorisation matrix, quarantine."""
from __future__ import annotations

import hashlib
import io
import os
import tarfile
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host import node_auth, node_results
from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

from .test_node_claim import _claim, auth, pki_dir, token_for  # noqa: F401  (fixture)

DATA = b"sample-bytes"
WG = "A" * 42 + "B="


@pytest.fixture(autouse=True)
def _results_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NODE_RESULTS_DIR", str(tmp_path / "results"))


class Blobs:
    def __init__(self, data=None):
        self.data = data

    def get_sample(self, sha256, dest):
        if self.data is None:
            raise FileNotFoundError(sha256)
        dest.write_bytes(self.data)


def _setup(tmp_path, pki_dir, *, spool=DATA, blobs=None):  # noqa: F811
    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="sample.bin",
                     status=JobStatus.QUEUED, created_at=time.time(),
                     input_sha256=hashlib.sha256(DATA).hexdigest()))
    root = tmp_path / "jobs"
    if spool is not None:
        (root / "job-1" / "input").mkdir(parents=True)
        (root / "job-1" / "input" / "sample.bin").write_bytes(spool)
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir, job_root=root,
                                      blob_store=blobs) is True
    c = TestClient(app)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 200, r.text
    body = r.json()
    hdr = {**auth(token_for(c, pki_dir, "alpha")),
           "x-blastbox-claim-id": body["job"]["claim_id"],
           "x-blastbox-receipt": body["receipt"]}
    return store, c, hdr


def make_tar(members, *, metadata=True):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        if metadata:
            members = [("metadata.json", b"{}")] + list(members)
        for name, content in members:
            if isinstance(content, tarfile.TarInfo):
                tf.addfile(content)
                continue
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


def special(name, typ, link=""):
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = link
    return ti


def spool_dirs(tmp_path):
    root = tmp_path / "results"
    return list(root.glob("job-1/*")) if root.exists() else []


# ---------------------------------------------------------------- input route

def test_input_streams_with_sha(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = c.get("/v1/nodes/jobs/job-1/input", headers=hdr)
    assert r.status_code == 200
    assert r.content == DATA
    assert r.headers["x-blastbox-input-sha256"] == hashlib.sha256(r.content).hexdigest()
    assert r.headers["content-length"] == str(len(DATA))
    assert r.headers["content-type"] == "application/octet-stream"


def test_input_blob_store_fallback(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir, spool=None, blobs=Blobs(DATA))
    r = c.get("/v1/nodes/jobs/job-1/input", headers=hdr)
    assert r.status_code == 200 and r.content == DATA
    assert list((tmp_path / "jobs" / ".node-input-tmp").iterdir()) == []


def test_input_unavailable_503(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir, spool=None)
    r = c.get("/v1/nodes/jobs/job-1/input", headers=hdr)
    assert r.status_code == 503 and r.json() == {"detail": "input unavailable"}
    _, c, hdr = _setup(tmp_path / "b", pki_dir, spool=None, blobs=Blobs(None))
    assert c.get("/v1/nodes/jobs/job-1/input", headers=hdr).status_code == 503


# ---------------------------------------------------------------- authorisation matrix

@pytest.mark.parametrize("method", ["get", "put"])
def test_auth_matrix(tmp_path, pki_dir, method):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    path = f"/v1/nodes/jobs/job-1/{'input' if method == 'get' else 'result'}"
    body = make_tar([]) if method == "put" else None

    def call(h):
        return c.request(method.upper(), path, headers=h, content=body)

    # wrong node's session (gamma is granted the same engine; it does not hold the claim)
    other = {**hdr, **auth(token_for(c, pki_dir, "gamma"))}
    assert call(other).status_code == 403
    # stale claim id
    assert call({**hdr, "x-blastbox-claim-id": "stale"}).status_code == 403
    # expired session
    tok = node_auth.issue_session("alpha", secret=node_auth.resolve_claim_secret(
        store, pki_dir, pepper=None), now=time.time() - node_auth.SESSION_TTL_S - 5)
    assert call({**hdr, **auth(tok)}).status_code == 401
    # no session
    assert call({k: v for k, v in hdr.items() if k.startswith("x-blastbox-c")
                 or k.startswith("x-blastbox-r")}).status_code == 401
    # job no longer RUNNING
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.DONE)
    assert call(hdr).status_code == 403
    assert spool_dirs(tmp_path) == []


@pytest.mark.parametrize("method", ["get", "put"])
def test_queued_job_refused(tmp_path, pki_dir, method):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.QUEUED)
    path = f"/v1/nodes/jobs/job-1/{'input' if method == 'get' else 'result'}"
    assert c.request(method.upper(), path, headers=hdr, content=b"").status_code == 403


@pytest.mark.parametrize("method", ["get", "put"])
def test_revoked_cert_refused(tmp_path, pki_dir, method):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    (pki_dir / "node-alpha.crt").unlink()
    path = f"/v1/nodes/jobs/job-1/{'input' if method == 'get' else 'result'}"
    assert c.request(method.upper(), path, headers=hdr, content=make_tar([])).status_code == 403


# ---------------------------------------------------------------- result route

def put(c, hdr, body, **extra):
    return c.put("/v1/nodes/jobs/job-1/result", headers={**hdr, **extra}, content=body)


def test_result_accepted_and_marker_written(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar([("out/a.txt", b"hi")]), **{
        "x-blastbox-worker-runtime": "nsjail", "x-blastbox-started-at-ms": "5",
        "x-blastbox-finished-at-ms": str(10**18)})
    assert r.status_code == 202 and r.json() == {"status": "accepted"}
    (d,) = spool_dirs(tmp_path)
    assert d.name == node_results.claim_digest(hdr["x-blastbox-claim-id"])
    assert (d / "out" / "out" / "a.txt").read_bytes() == b"hi"
    m = node_results.read_marker(d)
    assert m is not None and m.node_id == "alpha" and m.worker_runtime == "nsjail"
    assert m.started_at_ms == 5 and m.finished_at_ms < 10**16      # clamped
    assert m.node_cert_sha256 == node_results.node_cert_sha256(pki_dir, "alpha")
    assert list(node_results.pending(tmp_path / "results")) == [d]
    assert oct((d / "upload.json").stat().st_mode & 0o777) == "0o600"
    assert oct(d.stat().st_mode & 0o777) == "0o700"


def test_worker_runtime_header_allowlisted(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([]), **{"x-blastbox-worker-runtime": "runc"}).status_code == 400
    assert spool_dirs(tmp_path) == []
    assert put(c, hdr, make_tar([]), **{"x-blastbox-worker-runtime": "seatbelt"}).status_code == 202


def test_result_put_idempotent(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    calls = []
    import blastbox.host.runtime.remote_http as rh
    real = rh._safe_extract_tar
    monkeypatch.setattr(rh, "_safe_extract_tar", lambda *a, **k: calls.append(1) or real(*a, **k))
    assert put(c, hdr, make_tar([])).status_code == 202
    r = put(c, hdr, b"garbage not even a tar")
    assert r.status_code == 202 and r.json() == {"status": "accepted"}
    (d,) = spool_dirs(tmp_path)
    node_results.write_outcome(d, "done", None)
    r = put(c, hdr, b"x")
    assert r.status_code == 200 and r.json() == {"status": "done"}
    node_results.write_outcome(d, "failed", "bad evidence")
    r = put(c, hdr, b"x")
    assert r.status_code == 422 and r.json() == {"status": "failed", "reason": "bad evidence"}
    assert len(calls) == 1


def test_result_put_after_reclaim_refused(tmp_path, pki_dir):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.QUEUED, claim_id=None)
    assert put(c, hdr, make_tar([])).status_code == 403
    assert spool_dirs(tmp_path) == []


@pytest.mark.parametrize("name,members", [
    ("dotdot", [("../evil", b"x")]),
    ("nested-dotdot", [("a/../../evil", b"x")]),
    ("absolute", [("/etc/evil", b"x")]),
    ("symlink", [("l", special("l", tarfile.SYMTYPE, "/etc/passwd"))]),
    ("hardlink", [("h", special("h", tarfile.LNKTYPE, "metadata.json"))]),
    ("chardev", [("d", special("d", tarfile.CHRTYPE))]),
    ("fifo", [("f", special("f", tarfile.FIFOTYPE))]),
    ("duplicate", [("x", b"1"), ("x", b"2")]),
])
def test_adversarial_tars_rejected(tmp_path, pki_dir, name, members):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar(members))
    assert r.status_code == 422, r.text
    assert spool_dirs(tmp_path) == []
    assert not (tmp_path / "evil").exists()
    leftovers = [p for p in (tmp_path / "results").rglob("*") if "partial" in p.name]
    assert leftovers == []


def test_missing_metadata_and_garbage_rejected(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([("a", b"x")], metadata=False)).status_code == 422
    assert put(c, hdr, b"not a tar at all" * 100).status_code == 422
    assert spool_dirs(tmp_path) == []


def test_member_cap(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BLASTBOX_MAX_ARTIFACTS", "1")
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar([(f"f{i}", b"x") for i in range(80)]))
    assert r.status_code == 422 and spool_dirs(tmp_path) == []


def test_byte_cap_extraction(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BLASTBOX_MAX_TOTAL_ARTIFACTS", "100")
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar([("big", b"x" * 200)]))
    assert r.status_code == 422 and spool_dirs(tmp_path) == []


def test_stream_cap_413(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BLASTBOX_MAX_TOTAL_ARTIFACTS", "100")
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "100")
    monkeypatch.setenv("BLASTBOX_MAX_ARTIFACTS", "1")
    _, c, hdr = _setup(tmp_path, pki_dir)
    cap = node_results.stream_cap(max_artifact_total=100, max_metadata=100, max_artifacts=1)
    # chunked (no content-length) body so the cap is enforced as bytes arrive
    r = c.put("/v1/nodes/jobs/job-1/result", headers=hdr,
              content=(b"x" * 65536 for _ in range(cap // 65536 + 2)))
    assert r.status_code == 413
    assert spool_dirs(tmp_path) == []
    assert [p for p in (tmp_path / "results").glob(".upload-*")] == []


def test_node_cert_sha256_picks_latest(tmp_path, pki_dir):  # noqa: F811
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from blastbox.host import pki

    assert node_results.node_cert_sha256(pki_dir, "nobody") is None
    ca = pki.load_ca(pki_dir)
    grants = pki.NodeGrants(engines=("clamav",))
    ca.issue_node("delta", wg_pubkey=WG, grants=grants, days=2).write(pki_dir, "node-delta-old")
    ca.issue_node("delta", wg_pubkey=WG, grants=grants, days=6).write(pki_dir, "node-delta-new")

    def sha(name):
        pem = (pki_dir / f"{name}.crt").read_bytes()
        der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    assert sha("node-delta-old") != sha("node-delta-new")
    assert node_results.node_cert_sha256(pki_dir, "delta") == sha("node-delta-new")
    (pki_dir / "node-delta-new.crt").unlink()
    assert node_results.node_cert_sha256(pki_dir, "delta") == sha("node-delta-old")


def test_replay_returns_stored_outcome_after_job_done(tmp_path, pki_dir):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([])).status_code == 202
    (d,) = spool_dirs(tmp_path)
    node_results.write_outcome(d, "done", None)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.DONE)
    r = put(c, hdr, b"ignored")
    assert r.status_code == 200 and r.json() == {"status": "done"}
    # a stranger still gets nothing, whatever the job state
    other = {**hdr, **auth(token_for(c, pki_dir, "gamma"))}
    assert put(c, other, b"x").status_code == 403


def test_replay_pending_and_failed_in_any_state(tmp_path, pki_dir):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([])).status_code == 202
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.FAILED)
    assert put(c, hdr, b"x").status_code == 202
    (d,) = spool_dirs(tmp_path)
    node_results.write_outcome(d, "failed", "nope")
    r = put(c, hdr, b"x")
    assert r.status_code == 422 and r.json()["reason"] == "nope"


def test_reclaim_mid_upload_refused_no_marker(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    store, c, hdr = _setup(tmp_path, pki_dir)
    import blastbox.host.runtime.remote_http as rh
    real = rh._safe_extract_tar

    def reclaiming(*a, **k):
        out = real(*a, **k)
        store.update_if_status("job-1", JobStatus.RUNNING,
                               expect_claim_id=hdr["x-blastbox-claim-id"],
                               status=JobStatus.QUEUED, claim_id=None)
        return out

    monkeypatch.setattr(rh, "_safe_extract_tar", reclaiming)
    assert put(c, hdr, make_tar([])).status_code == 403
    assert spool_dirs(tmp_path) == []
    assert [p for p in (tmp_path / "results").rglob("*") if "partial" in p.name] == []


@pytest.mark.parametrize("h", ["x-blastbox-started-at-ms", "x-blastbox-finished-at-ms"])
@pytest.mark.parametrize("bad", ["abc", "-5", "1.5"])
def test_bad_timestamp_headers_400(tmp_path, pki_dir, h, bad):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([]), **{h: bad}).status_code == 400
    assert spool_dirs(tmp_path) == []


def test_compressed_tar_refused(tmp_path, pki_dir):  # noqa: F811
    import gzip
    _, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, gzip.compress(make_tar([]))).status_code == 422
    assert spool_dirs(tmp_path) == []


def test_metadata_must_be_a_regular_file(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    d = tarfile.TarInfo("metadata.json")
    d.type = tarfile.DIRTYPE
    assert put(c, hdr, make_tar([("m", d)], metadata=False)).status_code == 422


def test_concurrent_identical_puts_extract_once(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    from concurrent.futures import ThreadPoolExecutor

    _, c, hdr = _setup(tmp_path, pki_dir)
    import blastbox.host.runtime.remote_http as rh
    real = rh._safe_extract_tar
    calls = []

    def slow(*a, **k):
        calls.append(1)
        time.sleep(0.6)
        return real(*a, **k)

    monkeypatch.setattr(rh, "_safe_extract_tar", slow)
    body = make_tar([("a", b"x")])
    with ThreadPoolExecutor(3) as ex:
        rs = list(ex.map(lambda _: put(c, hdr, body), range(3)))
    assert [r.status_code for r in rs] == [202, 202, 202]
    assert len(calls) == 1
    assert len(spool_dirs(tmp_path)) == 1
    assert list((tmp_path / "results" / "job-1").glob("*.ulock")) == []


def test_results_root_tightens_existing_mode(tmp_path):
    root = tmp_path / "results"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    node_results.results_root(tmp_path)
    assert oct(root.stat().st_mode & 0o777) == "0o700"


def test_real_build_app_large_result_not_413(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    from blastbox.host.ingress.app import build_app
    from blastbox.limits import Limits

    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(pki_dir))
    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="sample.bin",
                     status=JobStatus.QUEUED, created_at=time.time()))
    app = build_app(job_store=store, job_root=tmp_path / "jobs",
                    limits=Limits(max_input_bytes=1000), blob_store=Blobs(DATA))
    c = TestClient(app)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 200, r.text
    hdr = {**auth(token_for(c, pki_dir, "alpha")),
           "x-blastbox-claim-id": r.json()["job"]["claim_id"],
           "x-blastbox-receipt": r.json()["receipt"]}
    big = make_tar([("a.bin", b"x" * 50_000)])
    assert len(big) > 1000
    assert put(c, hdr, big).status_code == 202
    # while an ordinary route still honours max_input_bytes
    assert c.post("/v1/jobs", content=b"x" * 5000).status_code == 413


def test_middleware_ceiling_is_per_route():
    from blastbox.host.ingress.middleware import BodySizeLimitMiddleware

    app = FastAPI()

    @app.put("/v1/nodes/jobs/{j}/result")
    async def r(j: str, request: __import__("starlette.requests").requests.Request):
        return {"n": len(await request.body())}

    @app.put("/other")
    async def o(request: __import__("starlette.requests").requests.Request):
        return {"n": len(await request.body())}

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=10,
                       route_ceilings=(("PUT", r"/v1/nodes/jobs/[^/]+/result", 1000),))
    c = TestClient(app)
    assert c.put("/v1/nodes/jobs/x/result", content=b"x" * 500).status_code == 200
    assert c.put("/v1/nodes/jobs/x/result", content=b"x" * 2000).status_code == 413
    assert c.put("/other", content=b"x" * 500).status_code == 413


def test_input_generator_cleans_up_when_closed_early(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    from fastapi.responses import StreamingResponse

    captured = {}
    real_init = StreamingResponse.__init__

    def spy(self, content, *a, **k):
        captured["gen"] = content
        real_init(self, content, *a, **k)

    monkeypatch.setattr(StreamingResponse, "__init__", spy)
    _, c, hdr = _setup(tmp_path, pki_dir, spool=None, blobs=Blobs(b"y" * (3 << 20)))
    c.get("/v1/nodes/jobs/job-1/input", headers=hdr)      # full read; now drive one by hand
    tmp_root = tmp_path / "jobs" / ".node-input-tmp"
    assert list(tmp_root.iterdir()) == []
    # second request, but never iterate it to the end: call the route's generator directly
    gen = captured["gen"]
    gen.close()                                           # already finished: must stay safe
    captured.clear()
    import starlette.responses as sr

    async def fake_call(self, scope, receive, send):      # headers only; the body is never iterated
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    monkeypatch.setattr(sr.StreamingResponse, "__call__", fake_call)
    c.get("/v1/nodes/jobs/job-1/input", headers=hdr)
    gen = captured["gen"]
    assert len(list(tmp_root.iterdir())) == 1             # temp tree exists, nothing iterated
    next(gen)                                             # started reading
    gen.close()                                           # client went away mid-stream
    assert list(tmp_root.iterdir()) == []


def test_lock_loser_with_no_outcome_gets_503_retry_not_202(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir)
    root = tmp_path / "results"
    final = node_results.spool_dir(root, "job-1", hdr["x-blastbox-claim-id"])
    final.parent.mkdir(parents=True, exist_ok=True)
    holder = node_results.UploadLock(final.with_name(final.name + ".ulock"))
    assert holder.try_acquire()                           # a winner that never produced anything
    import threading
    threading.Timer(0.3, holder.release).start()          # ...then died and released the lock
    r = put(c, hdr, make_tar([]))
    assert r.status_code == 503 and r.json() == {"status": "retry"}
    assert r.headers["retry-after"] == "2"
    assert spool_dirs(tmp_path) == []
    assert put(c, hdr, make_tar([])).status_code == 202   # a retry succeeds


# ---------------------------------------------------------------- vet_tar: expansion / header bombs

def _gnu_sparse_tar(realsize: int) -> bytes:
    """An old-GNU sparse member: a 0-byte payload that tarfile expands to ``realsize`` bytes."""
    ti = tarfile.TarInfo("big.bin")
    ti.size = 0
    ti.type = tarfile.GNUTYPE_SPARSE
    b = bytearray(ti.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
    b[482] = 0
    b[483:495] = ("%011o" % realsize).encode() + b"\0"
    b[148:156] = b"        "
    b[148:156] = ("%06o\0 " % sum(b)).encode()
    buf = io.BytesIO()
    buf.write(bytes(b))
    tf = tarfile.TarFile(fileobj=buf, mode="w")
    meta = tarfile.TarInfo("metadata.json")
    meta.size = 2
    tf.addfile(meta, io.BytesIO(b"{}"))
    tf.close()
    return buf.getvalue()


def test_sparse_member_refused_before_expansion(tmp_path, pki_dir):  # noqa: F811
    data = _gnu_sparse_tar(50 << 20)
    assert len(data) < 16384
    with pytest.raises(node_results.TarRejected, match="sparse"):
        node_results.vet_tar(io.BytesIO(data), max_members=100, max_total_bytes=500 << 20)
    _, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, data).status_code == 422
    assert spool_dirs(tmp_path) == []


class _NoBigReads(io.BytesIO):
    """A stream that fails any single read big enough to be an unbounded header record."""

    def read(self, n=-1):
        if n is None or n < 0 or n > (1 << 20):
            raise AssertionError(f"unbounded read of {n} bytes")
        return super().read(n)


def _ustar(name: bytes, size: int, typ: bytes) -> bytes:
    b = bytearray(512)
    b[0:len(name)] = name
    b[100:108] = b"0000644\0"
    b[124:136] = b"%011o\0" % size
    b[156] = typ[0]
    b[257:263] = b"ustar\0"
    b[263:265] = b"00"
    b[148:156] = b"        "
    b[148:156] = b"%06o\0 " % sum(b)
    return bytes(b)


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 512)


def _pax_rec(k: str, v: str) -> bytes:
    body = f" {k}={v}\n".encode()
    n = len(body) + 1
    while len(str(n)) + len(body) != n:
        n = len(str(n)) + len(body)
    return str(n).encode() + body


_META = _ustar(b"metadata.json", 2, b"0") + _pad(b"{}")
_BIG = 8 << 20


@pytest.mark.parametrize("typ", [b"x", b"g", b"L", b"K"])
def test_oversized_extended_header_refused_without_reading_it(typ):
    """tarfile reads a pax/GNU long-name record WHOLE into memory: refuse a big one first."""
    data = _ustar(b"././@Long", _BIG, typ) + b"\0" * _BIG + _META + b"\0" * 1024
    with pytest.raises(node_results.TarRejected, match="extended header|global pax"):
        node_results.vet_tar(_NoBigReads(data), max_members=100, max_total_bytes=500 << 20)


def test_extended_header_bound_holds_behind_a_pax_size_override():
    """A pax size= record moves tarfile's next header; the bound must follow tarfile's walk."""
    p = _pax_rec("size", "1024")
    data = (_ustar(b"pax", len(p), b"x") + _pad(p) + _ustar(b"a", 0, b"0") + b"\0" * 1024
            + _ustar(b"pax2", _BIG, b"x") + b"\0" * _BIG + _META + b"\0" * 1024)
    with pytest.raises(node_results.TarRejected, match="extended header"):
        node_results.vet_tar(_NoBigReads(data), max_members=100, max_total_bytes=500 << 20)


def test_extended_header_bound_holds_behind_a_directory_with_a_size():
    """tarfile ignores a directory's size field; a raw walk that honours it skips the record."""
    big = b"%d x=%s\n" % (0, b"A" * (2 << 20))
    data = (_ustar(b"d/", 1 << 20, b"5") + _ustar(b"PaxHeader", len(big), b"x") + _pad(big)
            + _META + b"\0" * 1024)
    with pytest.raises(node_results.TarRejected, match="extended header"):
        node_results.vet_tar(_NoBigReads(data), max_members=100, max_total_bytes=500 << 20)


@pytest.mark.parametrize("fmt", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_long_names_in_pax_and_gnu_tars_still_accepted(fmt):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, body in (("metadata.json", b"{}"), ("a/" + "b" * 150 + "/" + "c" * 150, b"x")):
            ti = tarfile.TarInfo(name)
            ti.size = len(body)
            tf.addfile(ti, io.BytesIO(body))
    node_results.vet_tar(io.BytesIO(buf.getvalue()), max_members=100, max_total_bytes=1 << 20)


def test_metadata_not_counted_against_the_artifact_total(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    """Matches _safe_extract_tar and the cold trust gate: metadata has its own cap."""
    monkeypatch.setenv("BLASTBOX_MAX_TOTAL_ARTIFACTS", "100")
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "1000")
    meta = b'{"pad": "' + b"p" * 500 + b'"}'
    body = make_tar([("metadata.json", meta), ("a", b"x" * 100)], metadata=False)
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, body)
    assert r.status_code == 202, r.text


def test_metadata_over_its_own_cap_refused_by_vet():
    body = make_tar([("metadata.json", b"x" * 200)], metadata=False)
    with pytest.raises(node_results.TarRejected, match="metadata"):
        node_results.vet_tar(io.BytesIO(body), max_members=10, max_total_bytes=10_000,
                             max_metadata_bytes=100)


@pytest.mark.parametrize("err", ["ENOSPC", "EMFILE"])
def test_host_resource_exhaustion_is_retry_not_rejected(tmp_path, pki_dir, monkeypatch, err):  # noqa: F811
    """Our disk/fds running out is not the node's fault: 503 + Retry-After, never 422."""
    import errno as _errno

    from blastbox.host.runtime import remote_http

    def full(*a, **k):
        raise OSError(getattr(_errno, err), "host resource")

    monkeypatch.setattr(remote_http, "_safe_extract_tar", full)
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar([("a", b"x")]))
    assert r.status_code == 503, r.text
    assert r.headers.get("retry-after")
    assert spool_dirs(tmp_path) == []
    # and the node's retry, once the host recovers, is accepted
    monkeypatch.undo()
    monkeypatch.setenv("BLASTBOX_NODE_RESULTS_DIR", str(tmp_path / "results"))
    assert put(c, hdr, make_tar([("a", b"x")])).status_code == 202


def test_host_disk_full_while_spooling_body_is_retry(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    import errno as _errno
    import tempfile as _tempfile

    real = _tempfile.NamedTemporaryFile

    def full(*a, **k):
        if k.get("prefix") == ".upload-":
            raise OSError(_errno.ENOSPC, "disk full")
        return real(*a, **k)

    _, c, hdr = _setup(tmp_path, pki_dir)
    monkeypatch.setattr(_tempfile, "NamedTemporaryFile", full)
    r = put(c, hdr, make_tar([("a", b"x")]))
    assert r.status_code == 503 and r.headers.get("retry-after"), r.text


def test_replay_of_a_retained_result_later_repaired_is_done(tmp_path, pki_dir):  # noqa: F811
    """The finalizer records 'retained' when the blob upload fails; the pending-upload sweep
    later repairs the row to DONE. The node's replay must then say done, not the stale 422."""
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([])).status_code == 202
    (d,) = spool_dirs(tmp_path)
    node_results.write_outcome(d, "failed", node_results.RETAINED_REASON)
    claim = hdr["x-blastbox-claim-id"]
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=claim,
                           status=JobStatus.FAILED, error=node_results.RETAINED_REASON)
    r = put(c, hdr, b"x")
    assert r.status_code == 422 and r.json()["reason"] == node_results.RETAINED_REASON
    store.update_if_status("job-1", JobStatus.FAILED, expect_claim_id=claim,
                           status=JobStatus.DONE, error=None)
    r = put(c, hdr, b"x")
    assert r.status_code == 200 and r.json() == {"status": "done"}


# ---------------------------------------------------------------- upload lock + durability

def test_upload_lock_is_exclusive_and_needs_no_staleness_guess(tmp_path):
    """An flock dies with its holder: no age threshold, so nothing can 'break' a live lock
    and two waiters can never both end up holding it."""
    lk = tmp_path / "x.ulock"
    a = node_results.UploadLock(lk)
    assert a.try_acquire()
    b, c = node_results.UploadLock(lk), node_results.UploadLock(lk)
    old = time.time() - 10_000
    os.utime(lk, (old, old))                 # however old, a held lock is held
    assert not b.try_acquire() and not c.try_acquire()
    assert b.held_elsewhere()
    a.release()
    assert not lk.exists()
    assert b.try_acquire() and not c.try_acquire()
    b.release()


def test_upload_lock_left_by_a_crashed_holder_is_free(tmp_path):
    lk = tmp_path / "x.ulock"
    a = node_results.UploadLock(lk)
    assert a.try_acquire()
    assert a._fd is not None
    os.close(a._fd)                          # the process died: the kernel drops the flock
    a._fd = None
    assert lk.exists()
    b = node_results.UploadLock(lk)
    assert not b.held_elsewhere() and b.try_acquire()
    b.release()


def test_extracted_tree_is_fsynced_before_accepting(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    """202 promises the result is quarantined: the files, not only the marker, are durable."""
    synced: list[str] = []
    real = os.fsync

    def spy(fd):
        try:
            synced.append(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            pass
        return real(fd)

    _, c, hdr = _setup(tmp_path, pki_dir)
    monkeypatch.setattr(os, "fsync", spy)
    assert put(c, hdr, make_tar([("art.bin", b"payload")])).status_code == 202
    assert any(p.endswith("/out/art.bin") for p in synced), synced
    assert any(p.endswith("/out/metadata.json") for p in synced), synced
    (d,) = spool_dirs(tmp_path)
    assert str(d.parent) in synced, synced          # the rename into place is durable


def test_global_pax_header_refused():
    """tarfile keeps every 'g' key for the rest of the archive and deep-copies the lot into
    each later pax member: a few small records become gigabytes. A node never needs one."""
    g = _pax_rec("k", "v")
    data = _ustar(b"g", len(g), b"g") + _pad(g) + _META + b"\0" * 1024
    with pytest.raises(node_results.TarRejected, match="global"):
        node_results.vet_tar(io.BytesIO(data), max_members=100, max_total_bytes=1 << 20)


def test_a_chain_of_extended_headers_is_refused_not_recursed():
    """tarfile recurses once per consecutive extended header; a long chain must be a clean
    TarRejected, not RecursionError."""
    p = _pax_rec("comment", "x")
    chain = (_ustar(b"pax", len(p), b"x") + _pad(p)) * 400
    data = chain + _META + b"\0" * 1024
    with pytest.raises(node_results.TarRejected, match="extended headers"):
        node_results.vet_tar(io.BytesIO(data), max_members=100, max_total_bytes=1 << 20)


def test_long_name_plus_long_link_plus_pax_still_accepted():
    """The deepest legitimate chain (L + K + x before one member) stays accepted."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        ti = tarfile.TarInfo("metadata.json")
        ti.size = 2
        tf.addfile(ti, io.BytesIO(b"{}"))
        ti = tarfile.TarInfo("d/" + "n" * 200)
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    node_results.vet_tar(io.BytesIO(buf.getvalue()), max_members=100, max_total_bytes=1 << 20)


def test_upload_lock_recreates_a_job_dir_the_sweep_just_removed(tmp_path):
    jd = tmp_path / "job-1"
    lk = node_results.UploadLock(jd / "x.ulock")      # jd does not exist (rmdir'd as empty)
    assert not lk.held_elsewhere()
    assert lk.try_acquire()
    lk.release()


def test_upload_lock_name_never_collides_with_a_legacy_lock_dir(tmp_path, pki_dir):  # noqa: F811
    """An earlier build used <digest>.claim as a DIRECTORY lock; one left on disk must not
    make every PUT for that claim a 500."""
    _, c, hdr = _setup(tmp_path, pki_dir)
    final = node_results.spool_dir(tmp_path / "results", "job-1", hdr["x-blastbox-claim-id"])
    final.parent.mkdir(parents=True, exist_ok=True)
    final.with_name(final.name + ".claim").mkdir()
    assert put(c, hdr, make_tar([])).status_code == 202


@pytest.mark.parametrize("err,code", [("ENOSPC", 503), ("EACCES", 503), ("EPERM", 503),
                                      ("EMLINK", 503)])
def test_a_failed_rename_into_place_is_never_acknowledged(tmp_path, pki_dir, monkeypatch, err, code):  # noqa: F811
    """Only a lost race with an identical upload (the final dir now exists) may answer 202.
    The tree was already vetted and extracted, so a rename failure is always the host's
    fault: retry, never a terminal 422."""
    import errno as _errno

    from blastbox.host.ingress import node_claim as nc

    _, c, hdr = _setup(tmp_path, pki_dir)
    final = node_results.spool_dir(tmp_path / "results", "job-1", hdr["x-blastbox-claim-id"])
    real = os.rename

    def fail(src, dst):
        if os.fspath(dst) == os.fspath(final):
            raise OSError(getattr(_errno, err), "rename failed")
        return real(src, dst)

    monkeypatch.setattr(nc.os, "rename", fail)
    r = put(c, hdr, make_tar([]))
    assert r.status_code == code, r.text
    assert not final.exists()
    assert [p for p in (tmp_path / "results").rglob("*") if "partial" in p.name] == []


def test_input_tmp_left_by_a_dead_stream_is_reaped(tmp_path, pki_dir):  # noqa: F811
    _, c, hdr = _setup(tmp_path, pki_dir, spool=None, blobs=Blobs(DATA))
    tmp_root = tmp_path / "jobs" / ".node-input-tmp"
    dead = tmp_root / "deadbeef"
    dead.mkdir(parents=True)
    (dead / "input").write_bytes(b"x" * 100)
    old = time.time() - 2 * 3600
    os.utime(dead / "input", (old, old))
    os.utime(dead, (old, old))
    assert c.get("/v1/nodes/jobs/job-1/input", headers=hdr).status_code == 200
    assert not dead.exists()


def test_input_tmp_still_being_fetched_is_not_reaped(tmp_path, pki_dir):  # noqa: F811
    """A blob fetch writing into an old dir keeps its FILE's mtime fresh: that copy is live."""
    _, c, hdr = _setup(tmp_path, pki_dir, spool=None, blobs=Blobs(DATA))
    tmp_root = tmp_path / "jobs" / ".node-input-tmp"
    live = tmp_root / "fetching"
    live.mkdir(parents=True)
    (live / "input").write_bytes(b"partial")            # written just now
    old = time.time() - 2 * 3600
    os.utime(live, (old, old))
    assert c.get("/v1/nodes/jobs/job-1/input", headers=hdr).status_code == 200
    assert (live / "input").exists()


def test_implicit_parent_directories_count_against_the_member_cap():
    """Extraction creates every missing parent: a deep path per file must spend the budget."""
    deep = "/".join(f"d{i}" for i in range(20))
    body = make_tar([(f"t{n}/{deep}/f", b"") for n in range(5)])   # 5 files, 105 dirs
    with pytest.raises(node_results.TarRejected, match="members"):
        node_results.vet_tar(io.BytesIO(body), max_members=50, max_total_bytes=1 << 20)


def test_explicit_and_implicit_directories_are_counted_once():
    body = make_tar([("a", special("a", tarfile.DIRTYPE)), ("a/b", b"x"), ("a/c", b"y")])
    # metadata.json + a + a/b + a/c = 4 entries
    node_results.vet_tar(io.BytesIO(body), max_members=4, max_total_bytes=1 << 20)


def test_quarantine_dir_is_fsynced_with_its_marker_before_publish(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    """202 promises the upload survives a crash: the partial dir's entries (upload.json, out)
    must be fsynced while the marker is in it, and the new job dir entry persisted in root."""
    synced: list[tuple[str, bool]] = []
    real = node_results.fsync_dir

    def spy(d):
        synced.append((str(d), (d / node_results.MARKER).is_file()))
        real(d)

    monkeypatch.setattr(node_results, "fsync_dir", spy)
    _, c, hdr = _setup(tmp_path, pki_dir)
    r = put(c, hdr, make_tar([]))
    assert r.status_code == 202, r.text
    assert any(".partial-" in p and has for p, has in synced), synced
    root = node_results.results_root(tmp_path / "jobs")
    assert str(root) in [p for p, _ in synced], synced
