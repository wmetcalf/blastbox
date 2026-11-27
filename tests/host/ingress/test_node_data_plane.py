"""``GET /jobs/{id}/input`` and ``PUT /jobs/{id}/result``: authorisation matrix, quarantine."""
from __future__ import annotations

import hashlib
import io
import json
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
    assert node_results.node_cert_sha256(pki_dir, "nobody") is None
    assert len(node_results.node_cert_sha256(pki_dir, "alpha") or "") == 64
    assert json.dumps({}) == "{}"


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
