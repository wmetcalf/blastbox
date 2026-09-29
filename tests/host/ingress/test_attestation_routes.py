"""GET /v1/jobs/{id}/attestation serves the executing dispatcher's receipt; it signs nothing.

GET /v1/attestation/key returns this process's key only if it has one configured.
"""
from __future__ import annotations

import hashlib
import io
import json

import pytest
from fastapi.testclient import TestClient

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host import attest
from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.limits import Limits
from tests.host.ingress.test_app import _make_client, _make_done_job, _push_to_blob


@pytest.fixture(autouse=True)
def _no_key_env(monkeypatch):
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)
    monkeypatch.delenv("BLASTBOX_PKI_DIR", raising=False)


@pytest.fixture
def key(tmp_path):
    return attest.load_or_create_key(tmp_path / "keys" / "attest.key")


def _done_with_receipt(tmp_path, store, key):
    """A DONE job whose sealed tree was uploaded WITH a dispatcher receipt."""
    job, out = _make_done_job(tmp_path, store)
    body = attest.seal_receipt(out, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, net_policy_effective="none", started_at_ms=1, finished_at_ms=2))
    _push_to_blob(tmp_path, job.job_id, out)
    return job, out, body


def test_serves_the_stored_receipt_bytes_verbatim(tmp_path, key):
    client, store = _make_client(tmp_path)
    job, out, body = _done_with_receipt(tmp_path, store, key)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert r.content == (out / attest.RECEIPT_NAME).read_bytes()
    assert r.json() == body


def test_receipt_matches_served_metadata_until_someone_swaps_it(tmp_path, key):
    client, store = _make_client(tmp_path)
    job, out, _ = _done_with_receipt(tmp_path, store, key)
    served = client.get(f"/v1/jobs/{job.job_id}/metadata").content
    doc = client.get(f"/v1/jobs/{job.job_id}/attestation").json()["attestation"]
    assert doc["metadata_sha256"] == hashlib.sha256(served).hexdigest()

    # A shared-bucket writer swaps metadata.json after DONE. The receipt was fixed at the seal,
    # so a verifier comparing it to what it collected now sees the mismatch.
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["engine"] = "tampered"
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    _push_to_blob(tmp_path, job.job_id, out)
    served2 = client.get(f"/v1/jobs/{job.job_id}/metadata").content
    doc2 = client.get(f"/v1/jobs/{job.job_id}/attestation").json()["attestation"]
    assert doc2 == doc
    assert doc2["metadata_sha256"] != hashlib.sha256(served2).hexdigest()


def test_row_writes_do_not_change_what_is_served(tmp_path, key):
    client, store = _make_client(tmp_path)
    job, _, body = _done_with_receipt(tmp_path, store, key)
    store.update(job.job_id, worker_runtime="none", worker_tier="firecracker",
                 claim_id="node:x", input_sha256="0" * 64, net_policy="direct")
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").json() == body


def test_done_without_a_receipt_is_404(tmp_path):
    client, store = _make_client(tmp_path)
    job, _ = _make_done_job(tmp_path, store)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404
    assert "receipt" in r.json()["detail"].lower()


@pytest.mark.parametrize("status", [JobStatus.QUEUED, JobStatus.RUNNING])
def test_non_terminal_is_409(tmp_path, status):
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = status
    store.create(job)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 409


def test_failed_job_has_no_receipt(tmp_path):
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.FAILED
    store.create(job)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 404


def test_expired_is_410_like_the_other_result_routes(tmp_path):
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.EXPIRED
    store.create(job)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 410


def test_unknown_and_malformed_job_ids_are_404(tmp_path):
    client, _ = _make_client(tmp_path)
    assert client.get("/v1/jobs/00000000-0000-0000-0000-000000000000/attestation"
                      ).status_code == 404
    assert client.get("/v1/jobs/not-a-uuid/attestation").status_code == 404


class _FlakyBlobs(LocalBlobStore):
    """Serves everything except the receipt, which fails like an object-store outage."""

    def __init__(self, *a, mode: str, **kw):
        super().__init__(*a, **kw)
        self._mode = mode

    def open_output(self, job_id, name):
        if name != attest.RECEIPT_NAME:
            return super().open_output(job_id, name)
        if self._mode == "open":
            raise BlobFetchError("result fetch failed") from ConnectionError("s3 down")
        fh = super().open_output(job_id, name)

        class _Broken(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, b):
                fh.close()
                raise OSError("connection reset")
        return _Broken()


@pytest.mark.parametrize("mode", ["open", "read"])
def test_blob_errors_are_503_never_a_synthesized_receipt(tmp_path, key, mode):
    store = InMemoryJobStore()
    job, _, _ = _done_with_receipt(tmp_path, store, key)
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="",
                    blob_store=_FlakyBlobs(tmp_path / "jobs", blob_root=tmp_path / "blobs",
                                           mode=mode))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 503


def test_s3_style_missing_object_is_404_not_503(tmp_path):
    """S3BlobStore wraps a NoSuchKey in BlobFetchError too. A missing receipt is absent, not an
    outage."""

    class _NoSuchKey(Exception):
        response = {"Error": {"Code": "NoSuchKey"}}

    class _S3ishBlobs(LocalBlobStore):
        def open_output(self, job_id, name):
            if name == attest.RECEIPT_NAME:
                raise BlobFetchError("result fetch failed") from _NoSuchKey()
            return super().open_output(job_id, name)

    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="",
                    blob_store=_S3ishBlobs(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 404


# ---------------------------------------------------------------------------
# /v1/attestation/key
# ---------------------------------------------------------------------------


def test_key_route_404_when_not_configured(tmp_path):
    client, _ = _make_client(tmp_path)
    r = client.get("/v1/attestation/key")
    assert r.status_code == 404
    assert "attestation" in r.json()["detail"].lower()


def test_key_route_serves_the_configured_key(tmp_path, key, monkeypatch):
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(tmp_path / "keys" / "attest.key"))
    client, _ = _make_client(tmp_path)
    r = client.get("/v1/attestation/key")
    assert r.status_code == 200
    assert r.json() == {"key_id": key.key_id, "alg": "ES256",
                        "public_key_pem": key.public_key_pem}


def test_key_route_never_mints_a_key(tmp_path, monkeypatch):
    """The ingress is not the signer. Minting a key here would advertise one no dispatcher
    signs with."""
    path = tmp_path / "keys" / "attest.key"
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(path))
    client, _ = _make_client(tmp_path)
    assert client.get("/v1/attestation/key").status_code == 404
    assert not path.exists()


def test_key_route_refuses_an_unsafe_key(tmp_path, key, monkeypatch):
    path = tmp_path / "keys" / "attest.key"
    path.chmod(0o644)
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(path))
    client, _ = _make_client(tmp_path)
    assert client.get("/v1/attestation/key").status_code == 404


def test_routes_require_the_api_key_like_job_status(tmp_path, key, monkeypatch):
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(tmp_path / "keys" / "attest.key"))
    client, store = _make_client(tmp_path, api_key="s3cret")
    job, _, _ = _done_with_receipt(tmp_path, store, key)
    assert client.get(f"/v1/jobs/{job.job_id}").status_code == 401
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 401
    assert client.get("/v1/attestation/key").status_code == 401
    h = {"Authorization": "Bearer s3cret"}
    assert client.get(f"/v1/jobs/{job.job_id}/attestation", headers=h).status_code == 200
    assert client.get("/v1/attestation/key", headers=h).status_code == 200


def test_a_legacy_on_disk_tree_never_supplies_a_receipt(tmp_path):
    """LocalBlobStore falls back to <job_root>/<id>/output for pre-blob-store results. A worker
    could have left attestation.json there; it must not be served as a receipt."""
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = tmp_path / "jobs" / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text("{}")
    (out / attest.RECEIPT_NAME).write_text('{"attestation": {"forged": 1}, "signature": "x"}')
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 404
