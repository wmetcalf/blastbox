"""Ingress must upload the sample BEFORE the job row exists.

Otherwise a worker can claim a job whose blob is not there yet and is pushed down
the release-and-retry path for a sample that was never missing — a self-inflicted
race that looks exactly like object-store flakiness.
"""
from pathlib import Path


from blastbox.host.blobs.base import BlobFetchError


class RecordingBlobStore:
    """Records the ORDER of put_sample vs the job-store create."""

    def __init__(self, log): self.log = log
    def put_sample(self, sha256, src):
        assert Path(src).is_file()
        self.log.append(("put_sample", sha256))
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FailingBlobStore(RecordingBlobStore):
    def put_sample(self, sha256, src):
        raise BlobFetchError("object store down")


def test_put_sample_happens_before_job_create(ingress_client_factory):
    """ingress_client_factory: see tests/host/conftest.py — builds the FastAPI app
    with injected stores and returns (client, log)."""
    client, log = ingress_client_factory(blob_store_cls=RecordingBlobStore)
    resp = client.post(
        "/v1/jobs",
        files={"file": ("invoice.doc", b"payload-bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    assert resp.status_code == 202
    kinds = [k for k, _ in log]
    assert kinds.index("put_sample") < kinds.index("job_create"), log


def test_upload_failure_creates_no_job(ingress_client_factory):
    """If the blob cannot be stored, there must be NO claimable job row — a job
    nobody can ever materialise is worse than a rejected upload."""
    client, log = ingress_client_factory(blob_store_cls=FailingBlobStore)
    resp = client.post(
        "/v1/jobs",
        files={"file": ("invoice.doc", b"payload", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    assert resp.status_code == 503
    assert [k for k, _ in log if k == "job_create"] == []
