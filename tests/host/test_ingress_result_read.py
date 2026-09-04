"""Result routes must read through the BlobStore, not the local filesystem.

After Task 5 the worker purges its job dir, so on a multi-node deployment the API
node has no local copy — reading from disk would 404 every completed job.
"""
import io


class MemoryBlobStore:
    def __init__(self, log=None): self.objects = {}
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name):
        return io.BytesIO(self.objects[(job_id, name)])
    def delete_job(self, job_id): ...


def test_metadata_is_served_from_the_blob_store(ingress_client_factory):
    client, _ = ingress_client_factory(blob_store_cls=MemoryBlobStore)
    store = client.app.state.blob_store
    resp = client.post(
        "/v1/jobs",
        files={"file": ("a.doc", b"bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    job_id = resp.json()["job_id"]
    store.objects[(job_id, "metadata.json")] = b'{"status":"ok"}'

    client.app.state.job_store.update(job_id, status="done")
    got = client.get(f"/v1/jobs/{job_id}/metadata")
    assert got.status_code == 200
    assert got.json()["status"] == "ok"


def test_default_result_access_is_stream_not_redirect(ingress_client_factory):
    """Streaming keeps the object store PRIVATE — clients need no credentials and no
    network path to it, which is the point of the firewalled topology.

    NOTE: unlike the brief's sketch (a bare ``"result.zip"`` key), the real /result
    route builds the ZIP at request time from the dispatcher-sealed
    ``metadata.json`` plus its declared artifacts (see ``get_result`` /
    ``_zip_validated_artifacts``) — nothing in the pipeline ever writes a single
    "result.zip" blob. So this seeds a minimal valid ``metadata.json`` (zero
    declared artifacts) instead, which exercises the real code path while still
    proving the thing this test cares about: the default is a 200 stream, never a
    302 redirect to the object store.
    """
    client, _ = ingress_client_factory(blob_store_cls=MemoryBlobStore)
    store = client.app.state.blob_store
    resp = client.post(
        "/v1/jobs",
        files={"file": ("a.doc", b"bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    job_id = resp.json()["job_id"]
    store.objects[(job_id, "metadata.json")] = (
        b'{"engine": "redtusk", "artifacts": [], "warnings": []}'
    )
    client.app.state.job_store.update(job_id, status="done")

    got = client.get(f"/v1/jobs/{job_id}/result", follow_redirects=False)
    assert got.status_code == 200, "default must stream, never 302 to the object store"
    assert got.headers["content-type"] == "application/zip"


def test_result_route_non_dict_metadata_manifest_is_not_500(ingress_client_factory):
    """Ultrareview bug_003: a metadata.json whose top-level JSON value is not a dict
    (``[]``, ``null``, a scalar) parses fine, so ``meta.get("artifacts", [])`` raises
    AttributeError OUTSIDE both try/excepts -> bare 500. The sibling routes
    (``get_artifact``, ``_declared_artifact_paths_from_meta``) already guard this exact
    case -- ``get_result`` must too: fall back to the zero-declared-artifacts path
    (metadata-only ZIP), never a server error."""
    client, _ = ingress_client_factory(blob_store_cls=MemoryBlobStore)
    store = client.app.state.blob_store
    for bad in (b"[]", b"null", b"5", b'"str"'):
        resp = client.post(
            "/v1/jobs",
            files={"file": ("a.doc", b"bytes", "application/octet-stream")},
            data={"engine": "redtusk"},
        )
        job_id = resp.json()["job_id"]
        store.objects[(job_id, "metadata.json")] = bad
        client.app.state.job_store.update(job_id, status="done")

        got = client.get(f"/v1/jobs/{job_id}/result")
        assert got.status_code == 200, f"manifest {bad!r} must hit the empty-artifacts fallback, not 500"
        assert got.headers["content-type"] == "application/zip"
