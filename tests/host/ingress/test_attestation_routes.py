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
        worker_tier=None, net_policy_effective="none", net_exit="none", started_at_ms=1,
        finished_at_ms=2))
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

    open_result_only = open_output      # the route's no-legacy read path fails the same way


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

        open_result_only = open_output

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


def test_a_tombstone_is_404_never_served(tmp_path):
    client, store = _make_client(tmp_path)
    job, out = _make_done_job(tmp_path, store)
    attest.write_tombstone(out, "no attestation key")
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404
    assert "no attestation key" in r.json()["detail"]


@pytest.mark.parametrize("rel,data", [
    ("attestation.json", b'{"attestation": {"looks": "signed"}, "signature": "x"}'),
    ("attestation.json/page.png", b"accepted artifact"),
])
def test_a_declared_artifact_at_the_receipt_name_is_never_served_as_a_receipt(tmp_path, rel,
                                                                             data):
    """A result accepted before the name was reserved (and recovered as-is by the sweep) can hold
    a DECLARED artifact at attestation.json. Its bytes are the analysis output, not a receipt:
    the route answers "no receipt", in the tombstone's 404 shape, with the reason."""
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = tmp_path / "work" / job.job_id / "output"
    (out / rel).parent.mkdir(parents=True, exist_ok=True)
    (out / rel).write_bytes(data)
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": rel, "sha256": hashlib.sha256(data).hexdigest()}]}))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    detail = r.json()["detail"]
    assert detail.startswith("no execution receipt for this job: ")
    assert "occupied by a declared artifact" in detail


def test_an_envelope_that_cannot_rule_out_an_artifact_at_the_receipt_name_serves_no_receipt(
        tmp_path):
    """A result recovered as-is because its envelope could not be parsed: whatever sits at
    attestation.json cannot be ruled out as analysis output (and no dispatcher ever signs over an
    unparseable envelope), so it is never served as a receipt."""
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = tmp_path / "work" / job.job_id / "output"
    out.mkdir(parents=True)
    (out / attest.RECEIPT_NAME).write_bytes(b'{"attestation": {"looks": "signed"}, '
                                            b'"signature": "x"}')
    (out / "metadata.json").write_text('{"artifacts": [{"id": "a", "pa')
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.json()["detail"].startswith("no execution receipt for this job: ")


def test_legacy_tree_is_never_read_even_when_the_result_is_durable(tmp_path, key):
    """has_output() True (the durable result exists) but the durable copy has NO receipt, while
    the legacy on-disk tree has a planted one. open_output would fall back to it; the route must
    read the receipt only from the blob results prefix."""
    client, store = _make_client(tmp_path)
    job, out = _make_done_job(tmp_path, store)          # durable copy, no receipt
    legacy = tmp_path / "jobs" / job.job_id / "output"
    (legacy / attest.RECEIPT_NAME).write_text('{"attestation": {"forged": 1}, "signature": "x"}')
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404


def test_key_route_without_attest_key_is_quiet(tmp_path, monkeypatch, caplog):
    import logging

    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(tmp_path / "pki"))    # the CA dir: NOT opt-in
    caplog.set_level(logging.INFO)
    client, _ = _make_client(tmp_path)
    caplog.clear()
    assert client.get("/v1/attestation/key").status_code == 404
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING
                and "attest" in r.getMessage().lower()]
    assert not (tmp_path / "pki" / "attest.key").exists()


def test_key_route_with_a_configured_but_absent_key_is_quiet(tmp_path, monkeypatch, caplog):
    import logging

    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(tmp_path / "absent.key"))
    client, _ = _make_client(tmp_path)
    caplog.set_level(logging.INFO)
    caplog.clear()
    assert client.get("/v1/attestation/key").status_code == 404
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("why", ["foreign-owner", "unreadable"])
def test_key_route_on_a_non_signer_is_quiet_when_the_key_is_not_ours(tmp_path, key, monkeypatch,
                                                                    caplog, why):
    """The ingress is not the signer: its euid commonly does not own the dispatcher's key. That is
    a 404 at debug level, not an ERROR on every request."""
    import logging
    import os

    path = tmp_path / "keys" / "attest.key"
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(path))
    if why == "foreign-owner":
        owner = os.stat(path).st_uid
        monkeypatch.setattr(attest.os, "geteuid", lambda: owner + 1)
    else:
        real_open = attest.os.open

        def deny(p, *a, **kw):
            if str(p) == str(path):
                raise PermissionError(13, "Permission denied", str(p))
            return real_open(p, *a, **kw)
        monkeypatch.setattr(attest.os, "open", deny)
    client, _ = _make_client(tmp_path)
    caplog.set_level(logging.INFO)
    caplog.clear()
    assert client.get("/v1/attestation/key").status_code == 404
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_dispatchers_own_load_stays_loud(tmp_path, key, monkeypatch, caplog):
    import os

    path = tmp_path / "keys" / "attest.key"
    owner = os.stat(path).st_uid
    monkeypatch.setattr(attest.os, "geteuid", lambda: owner + 1)
    assert attest.load_attest_key({"BLASTBOX_ATTEST_KEY": str(path)}) is None
    assert "DISABLED" in caplog.text


# ---------------------------------------------------------------------------
# No stored envelope => no receipt (round-2 review F1)
# ---------------------------------------------------------------------------

_LOOKS_SIGNED = b'{"attestation": {"status": "done", "job_id": "x"}, "signature": "AAAA"}'


def test_a_result_with_no_stored_envelope_serves_no_receipt(tmp_path):
    """put_output uploads metadata.json LAST, so a result prefix without it is a partial upload
    (or a seal put_output refused to ship). A genuine receipt always signs metadata_sha256, so
    with no envelope there is nothing it could vouch for -- and nothing rules out that the bytes
    at attestation.json are a DECLARED artifact of a pre-reservation tree. Never serve them."""
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = tmp_path / "work" / job.job_id / "output"
    out.mkdir(parents=True)
    (out / attest.RECEIPT_NAME).write_bytes(_LOOKS_SIGNED)
    _push_to_blob(tmp_path, job.job_id, out)               # no metadata.json in the tree
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.json()["detail"].startswith("no execution receipt for this job: ")


def test_a_partial_legacy_upload_never_serves_a_declared_artifact_as_the_receipt(
        tmp_path, monkeypatch):
    """The reviewer's repro: a legacy tree DECLARES an artifact at attestation.json, so the
    migration uploads it as-is; a blip on a later artifact aborts the upload before the seal
    lands. The results prefix then holds the declared artifact and no envelope to say so."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    client, store = _make_client(tmp_path)
    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    (out / attest.RECEIPT_NAME).write_bytes(_LOOKS_SIGNED)
    (out / "page.png").write_bytes(b"png")
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.RECEIPT_NAME,
         "sha256": hashlib.sha256(_LOOKS_SIGNED).hexdigest()},
        {"id": "b", "path": "page.png"}]}))
    real = LocalBlobStore._atomic_copy

    def flaky(src, dst):
        if src.name == "page.png":
            raise OSError(5, "EIO: object store blip")
        return real(src, dst)

    monkeypatch.setattr(LocalBlobStore, "_atomic_copy", staticmethod(flaky))
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (0, 0, 1)
    with blobs.open_result_only(job.job_id, attest.RECEIPT_NAME) as fh:
        assert fh.read() == _LOOKS_SIGNED                  # the declared artifact did land
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.json()["detail"].startswith("no execution receipt for this job: ")


# ---------------------------------------------------------------------------
# Envelope-read branches of the route, pinned (round-2 review F3)
# ---------------------------------------------------------------------------


class _FlakyEnvelopeBlobs(LocalBlobStore):
    """Serves everything except metadata.json, which fails like an object-store outage."""

    def __init__(self, *a, mode: str, **kw):
        super().__init__(*a, **kw)
        self._mode = mode

    def open_result_only(self, job_id, name):
        if name != "metadata.json":
            return super().open_result_only(job_id, name)
        if self._mode == "open":
            raise BlobFetchError("result fetch failed") from ConnectionError("s3 down")
        fh = super().open_result_only(job_id, name)

        class _Broken(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, b):
                fh.close()
                raise OSError("connection reset")
        return _Broken()


@pytest.mark.parametrize("mode", ["open", "read"])
def test_an_envelope_read_error_is_503_not_a_verdict(tmp_path, key, mode):
    """A transient error reading the envelope is neither "absent" nor "nothing declared": the
    route answers 503 (retry), never a 404 that says no receipt exists, never the receipt."""
    store = InMemoryJobStore()
    job, _, _ = _done_with_receipt(tmp_path, store, key)
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="",
                    blob_store=_FlakyEnvelopeBlobs(tmp_path / "jobs",
                                                   blob_root=tmp_path / "blobs", mode=mode))
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 503


def test_an_envelope_over_the_cap_serves_no_receipt(tmp_path, key, monkeypatch):
    """The route reads at most ENVELOPE_MAX_BYTES + 1 bytes; an envelope past the cap cannot be
    parsed whole, so it cannot rule out a declared artifact at attestation.json: 404, even when
    the bytes read happen to parse."""
    client, store = _make_client(tmp_path)
    job, out, _ = _done_with_receipt(tmp_path, store, key)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 200   # control
    size = len((out / "metadata.json").read_bytes())
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", size - 1)   # read cap+1 = the whole file
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]
