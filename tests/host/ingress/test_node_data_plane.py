"""``GET /jobs/{id}/input`` and ``PUT /jobs/{id}/result``: authorisation matrix, quarantine."""
from __future__ import annotations

import hashlib
import io
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
    assert list((tmp_path / "results" / "job-1").glob("*.claim")) == []


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
    lock = final.with_name(final.name + ".claim")
    lock.mkdir()                                          # a winner that never produced anything
    import threading
    threading.Timer(0.3, lock.rmdir).start()              # ...then died and released the lock
    r = put(c, hdr, make_tar([]))
    assert r.status_code == 503 and r.json() == {"status": "retry"}
    assert r.headers["retry-after"] == "2"
    assert spool_dirs(tmp_path) == []
    assert put(c, hdr, make_tar([])).status_code == 202   # a retry succeeds
