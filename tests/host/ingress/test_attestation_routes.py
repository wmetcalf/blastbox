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


def _cleared_for(out):
    """The cleared marker bound to the metadata.json in ``out``."""
    return attest.canonical(attest.cleared_marker_body(
        hashlib.sha256((out / "metadata.json").read_bytes()).hexdigest()))


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


def _migrate_as_is(tmp_path, store, out_setup):
    """Ship a legacy DONE tree through the REAL uploader (the migration), which uploads it as-is
    with the withheld marker; returns (job, blobs)."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    out_setup(out)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (1, 0, 0)
    return job, blobs


def _stored_marker(blobs, job_id):
    with blobs.open_result_only(job_id, attest.WITHHELD_NAME) as fh:
        return json.loads(fh.read())


@pytest.mark.parametrize("rel,data", [
    ("attestation.json", b'{"attestation": {"looks": "signed"}, "signature": "x"}'),
    ("attestation.json/page.png", b"accepted artifact"),
])
def test_a_declared_artifact_at_the_receipt_name_is_never_served_as_a_receipt(tmp_path, rel,
                                                                             data):
    """A result accepted before the name was reserved can hold a DECLARED artifact at
    attestation.json. The uploader ships it as-is, artifact intact, WITH the withheld marker
    (in the stored result), and the route answers "no receipt" with the uploader's reason. The
    route used to re-derive this from the envelope; the marker now carries it (D1/D2)."""
    client, store = _make_client(tmp_path)

    def setup(out):
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
        (out / "metadata.json").write_text(json.dumps({"artifacts": [
            {"id": "a", "path": rel, "sha256": hashlib.sha256(data).hexdigest()}]}))

    job, blobs = _migrate_as_is(tmp_path, store, setup)
    assert _stored_marker(blobs, job.job_id) == attest.tombstone_body(
        attest.RECEIPT_PATH_DECLARED_REASON)
    with blobs.open_result_only(job.job_id, rel) as fh:
        assert fh.read() == data                             # the artifact shipped intact
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    detail = r.json()["detail"]
    assert detail.startswith("no execution receipt for this job: ")
    assert "occupied by a declared artifact" in detail


def test_an_envelope_that_cannot_rule_out_an_artifact_at_the_receipt_name_serves_no_receipt(
        tmp_path):
    """A result shipped as-is because its envelope could not be parsed: whatever sits at
    attestation.json cannot be ruled out as analysis output, so the uploader stores the marker
    and the route never serves those bytes as a receipt."""
    client, store = _make_client(tmp_path)

    def setup(out):
        (out / attest.RECEIPT_NAME).write_bytes(b'{"attestation": {"looks": "signed"}, '
                                                b'"signature": "x"}')
        (out / "metadata.json").write_text('{"artifacts": [{"id": "a", "pa')

    job, blobs = _migrate_as_is(tmp_path, store, setup)
    assert _stored_marker(blobs, job.job_id) == attest.tombstone_body(
        attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]


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
    """A transient error opening or hashing the stored envelope (to check the cleared marker's
    binding) is not "absent" and not "bound elsewhere": the route answers 503 (retry), never a
    404 that says no receipt exists, never the receipt."""
    store = InMemoryJobStore()
    job, _, _ = _done_with_receipt(tmp_path, store, key)
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="",
                    blob_store=_FlakyEnvelopeBlobs(tmp_path / "jobs",
                                                   blob_root=tmp_path / "blobs", mode=mode))
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 503


def test_a_genuine_receipt_over_this_ingress_cap_still_serves(tmp_path, key, monkeypatch):
    """A peer dispatcher configured with a larger BLASTBOX_MAX_METADATA sealed and signed over
    an envelope past THIS ingress's ceiling. The route used to read the envelope under its own
    cap, judge it undecidable and 404 the genuine receipt (round-3 review D1). The uploader's
    as-is verdict now travels as the withheld marker, so the route reads no envelope: with no
    marker the receipt is served."""
    store = InMemoryJobStore()
    job, out = _make_done_job(tmp_path, store)
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["pad"] = "x" * 4096
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    body = attest.seal_receipt(out, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2))
    _push_to_blob(tmp_path, job.job_id, out)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    r = _route_with_limit(tmp_path, store, 1024).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


def test_an_envelope_within_the_configured_metadata_limit_serves_its_receipt(
        tmp_path, key, monkeypatch):
    """BLASTBOX_MAX_METADATA above the fixed cap: the dispatcher sealed and signed over that
    envelope, so the route must parse it and serve the genuine receipt, not 404 it as
    undecidable. The fixed cap is scaled down to keep the test cheap."""
    store = InMemoryJobStore()
    job, out = _make_done_job(tmp_path, store)
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["pad"] = "x" * 4096
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    body = attest.seal_receipt(out, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2))
    _push_to_blob(tmp_path, job.job_id, out)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(max_metadata_bytes=1 << 20), api_workers=2, zip_password="",
                    blob_store=LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    r = TestClient(app).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


# ---------------------------------------------------------------------------
# The migration and the route judge the envelope against the SAME limit (round-3 review H2)
# ---------------------------------------------------------------------------

_FORGED_RECEIPT = b'{"attestation":{"forged":true},"signature":"AAAA"}'


def _legacy_tree_with_big_envelope(tmp_path, store):
    """A legacy DONE tree: an envelope past the fixed floor that declares nothing, plus a
    worker-written attestation.json. The floor is scaled down to keep the test cheap."""
    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text(json.dumps({"artifacts": [], "pad": "x" * 4096}))
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    return job_root, job


def _route_with_limit(tmp_path, store, max_metadata):
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(max_metadata_bytes=max_metadata), api_workers=2,
                    zip_password="",
                    blob_store=LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    return TestClient(app)


def test_a_migration_without_the_service_limit_never_ships_a_forged_receipt(
        tmp_path, monkeypatch):
    """The reviewer's capdiv repro. The operator's CLI shell lacks the service's
    BLASTBOX_MAX_METADATA, so the migration judged the envelope "cannot rule out" and uploaded
    the worker's attestation.json as-is; the ingress, with the larger limit, parsed the envelope,
    saw nothing declared, and served the forged bytes 200. Without a known limit, an envelope
    past the floor is refused (left in place, counted failed), never shipped as-is."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (0, 0, 1)
    assert not blobs.has_output(job.job_id)
    assert (job_root / job.job_id / "output" / attest.RECEIPT_NAME).read_bytes() \
        == _FORGED_RECEIPT                                    # nothing deleted either
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


def test_a_migration_given_the_service_limit_strips_the_forged_receipt(tmp_path, monkeypatch):
    """With the service's limit the migration parses the envelope exactly as the route will,
    sees nothing declared, and replaces the worker's file with a tombstone before it ships."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t"),
                                  limits=Limits(max_metadata_bytes=1 << 20)) == (1, 0, 0)
    assert attest.is_tombstone(
        (job_root / job.job_id / "output" / attest.RECEIPT_NAME).read_bytes())
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


def test_a_migration_reads_the_limit_from_the_service_env_when_set(tmp_path, monkeypatch):
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.setenv("BLASTBOX_MAX_METADATA", str(1 << 20))
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (1, 0, 0)
    assert attest.is_tombstone(
        (job_root / job.job_id / "output" / attest.RECEIPT_NAME).read_bytes())


def test_migrate_results_cli_threads_max_metadata(tmp_path, monkeypatch):
    """`blastbox migrate-results --max-metadata N` is how an operator hands the migration the
    service's limit when the shell does not carry BLASTBOX_MAX_METADATA."""
    from blastbox.host import cli
    from blastbox.host.jobs import retention

    seen = {}

    def fake(job_root, blobs, store, log, **kw):
        seen.update(kw)
        return (0, 0, 0)

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(retention, "migrate_legacy_results", fake)
    monkeypatch.setattr("blastbox.host.blobs.factory.build_blob_store_from_env",
                        lambda env: object())
    monkeypatch.setattr("blastbox.host.jobs.factory.build_job_store_from_env", lambda: object())
    parser = cli.build_parser()
    args = parser.parse_args(["migrate-results", "--job-root", str(tmp_path),
                              "--max-metadata", str(128 << 20)])
    assert args.func(args) == 0
    assert seen["limits"] == Limits(max_metadata_bytes=128 << 20)
    args = parser.parse_args(["migrate-results", "--job-root", str(tmp_path)])
    assert args.func(args) == 0
    assert seen["limits"] is None


# ---------------------------------------------------------------------------
# The uploader's as-is verdict is DURABLE: the route never re-derives it (round-4 review H1)
# ---------------------------------------------------------------------------


def _retained_tree_with_big_envelope(tmp_path, store):
    """A FAILED, retained tree (pending-upload sentinel, claim-less) whose envelope is past the
    (scaled-down) floor and declares nothing, plus a worker-planted UNDECLARED attestation.json."""
    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL, RESULT_RETAINED_MARKER

    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.FAILED
    job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text(json.dumps({"artifacts": [], "pad": "x" * 4096}))
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    (job_root / job.job_id / PENDING_UPLOAD_SENTINEL).write_text("")
    return job_root, job, out


def test_a_sweep_with_a_smaller_limit_than_the_ingress_never_serves_a_forged_receipt(
        tmp_path, monkeypatch):
    """Codex's scenario. The pending-upload sweep runs with the default ceiling (no
    BLASTBOX_MAX_METADATA), judges an envelope between its ceiling and the ingress's
    "cannot rule out" and uploads the tree as-is with the worker's UNDECLARED attestation.json;
    the ingress, configured larger, parsed the envelope, saw nothing declared and served the
    forged bytes 200. The sweep's verdict must travel with the tree."""
    import logging

    from blastbox.host.jobs.retention import retry_pending_uploads

    # The dispatcher's ceiling (scaled: the 64 MiB floor over the 4 MiB default limit) is BELOW
    # the ingress's configured one (scaled: BLASTBOX_MAX_METADATA=80 MiB there).
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "1024")
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job, out = _retained_tree_with_big_envelope(tmp_path, store)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    assert retry_pending_uploads(job_root, blobs, store, logging.getLogger("t"),
                                 attest_key=key) == 1
    assert store.get(job.job_id).status is JobStatus.DONE
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]
    with blobs.open_result_only(job.job_id, attest.WITHHELD_NAME) as fh:
        marker = json.loads(fh.read())
    assert marker == attest.tombstone_body(attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert (out / attest.RECEIPT_NAME).read_bytes() == _FORGED_RECEIPT   # nothing deleted


def test_a_migration_with_a_smaller_limit_than_the_ingress_never_serves_a_forged_receipt(
        tmp_path, monkeypatch):
    """The migration variant: given a limit LOWER than the service's (a stale --max-metadata),
    the run judges the envelope undecidable and ships the tree as-is; the withheld marker it
    writes keeps the route from serving the planted file."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t"),
                                  limits=Limits(max_metadata_bytes=1024)) == (1, 0, 0)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT
    assert _stored_marker(blobs, job.job_id) == attest.tombstone_body(
        attest.RECEIPT_PATH_UNDECIDABLE_REASON)                 # in the STORED result


def test_a_genuine_receipt_beside_a_large_envelope_still_serves(tmp_path, key, monkeypatch):
    """Control: a fresh seal over an envelope past the floor writes no marker, so the ingress
    (configured to accept it) serves the genuine receipt."""
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job, out = _make_done_job(tmp_path, store)
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["pad"] = "x" * 4096
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    assert attest.seal_fresh_receipt(out, key=key, job_id=job.job_id,
                                     observation=attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2))
    assert (out / attest.WITHHELD_NAME).read_bytes() == _cleared_for(out)
    _push_to_blob(tmp_path, job.job_id, out)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.content == (out / attest.RECEIPT_NAME).read_bytes()


def test_a_stored_withheld_marker_withholds_even_a_parseable_envelope(tmp_path, key):
    """The marker alone decides: a result stored with it answers the no-receipt 404 (with its
    reason) whatever the route's own reading of the envelope would be."""
    client, store = _make_client(tmp_path)
    job, out = _make_done_job(tmp_path, store)
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    (out / attest.WITHHELD_NAME).write_bytes(
        attest.canonical(attest.tombstone_body("some uploader reason")))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert "some uploader reason" in r.json()["detail"]


def test_a_withheld_marker_read_error_is_503_never_the_receipt(tmp_path, key):
    """A marker that cannot be checked is no verdict: 503, never fall through to serving."""
    store = InMemoryJobStore()
    job, out = _make_done_job(tmp_path, store)
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    _push_to_blob(tmp_path, job.job_id, out)

    class _Blobs(LocalBlobStore):
        def open_result_only(self, job_id, name):
            if name == attest.WITHHELD_NAME:
                raise BlobFetchError("boom") from OSError(5, "EIO")
            return super().open_result_only(job_id, name)

    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="",
                    blob_store=_Blobs(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    r = TestClient(app, raise_server_exceptions=False).get(
        f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 503, r.text


def _s3_store(tmp_path, request):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    ctx = moto.mock_aws()
    ctx.start()
    request.addfinalizer(ctx.stop)
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="withheld")
    from blastbox.host.blobs.s3 import S3BlobStore

    return S3BlobStore("s3://withheld", job_root=tmp_path / "jobs", env={})


@pytest.mark.parametrize("backend", ["local", "s3"])
def test_the_withheld_marker_round_trips_through_each_blob_store(
        tmp_path, monkeypatch, request, backend):
    """put_output must actually store the marker, and the route's opener must read it -- and,
    on S3, an ABSENT marker (NoSuchKey) must read as absent, so a genuine receipt still
    serves 200 rather than 503."""
    import logging

    from blastbox.host.jobs.retention import retry_pending_uploads

    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "1024")
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    blobs = (LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
             if backend == "local" else _s3_store(tmp_path, request))
    store = InMemoryJobStore()
    job_root, job, out = _retained_tree_with_big_envelope(tmp_path, store)
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    assert retry_pending_uploads(job_root, blobs, store, logging.getLogger("t"),
                                 attest_key=key) == 1

    genuine = Job.new(engine="clippyshot", filename="b.docx")
    genuine.status = JobStatus.DONE
    store.create(genuine)
    gout = tmp_path / "genuine" / "output"
    gout.mkdir(parents=True)
    (gout / "metadata.json").write_text(json.dumps({"artifacts": []}))
    body = attest.seal_receipt(gout, key=key, observation=attest.RunObservation(
        job_id=genuine.job_id, engine="clippyshot", input_sha256="d" * 64,
        worker_runtime="runsc", worker_tier=None, started_at_ms=1, finished_at_ms=2))
    blobs.put_output(genuine.job_id, gout)

    app = build_app(job_store=store, job_root=job_root, allowed_engines={"clippyshot"},
                    limits=Limits(max_metadata_bytes=1 << 20), api_workers=2, zip_password="",
                    blob_store=blobs)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]
    r = client.get(f"/v1/jobs/{genuine.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


# ---------------------------------------------------------------------------
# A partial delete never leaves a servable receipt unmasked (round-5 review M1)
# ---------------------------------------------------------------------------


def _as_is_result(tmp_path, blobs, store):
    """A DONE result stored AS-IS: a worker-written attestation.json, the withheld marker and the
    envelope -- the state the route answers 404 for only while the marker is stored."""
    job, out = _make_done_job(tmp_path, store)
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    attest.write_withheld_marker(out, attest.RECEIPT_PATH_DECLARED_REASON)
    blobs.put_output(job.job_id, out)
    return job


def _client_on(tmp_path, store, blobs):
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"clippyshot"},
                    limits=Limits(), api_workers=2, zip_password="", blob_store=blobs)
    return TestClient(app, raise_server_exceptions=False)


class _Ordered:
    """os.scandir's result, re-ordered: an rmtree that removes in scandir order then meets the
    marker first."""

    def __init__(self, it, key):
        with it:
            self._entries = sorted(it, key=key)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return iter(self._entries)

    def close(self):
        pass


@pytest.mark.parametrize("fail_name", [attest.RECEIPT_NAME, "metadata.json"])
def test_a_partial_local_delete_never_unmasks_an_as_is_receipt(tmp_path, monkeypatch, fail_name):
    """DELETE removes the stored result before the row; on failure it answers 503 and the row
    stays DONE so the delete can be retried. A removal in scandir order that met the marker first
    and then failed left attestation.json + metadata.json stored without it: the route then
    served the worker's bytes 200. Whatever fails, the marker must outlive every servable name."""
    import os as _os

    store = InMemoryJobStore()
    blobs = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    job = _as_is_result(tmp_path, blobs, store)
    client = _client_on(tmp_path, store, blobs)
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 404

    real_scandir, real_unlink = _os.scandir, _os.unlink

    def scandir(*a, **kw):
        return _Ordered(real_scandir(*a, **kw),
                        key=lambda e: (e.name != attest.WITHHELD_NAME, e.name != fail_name,
                                       e.name))

    def unlink(path, *a, **kw):
        if _os.path.basename(_os.fsdecode(path)) == fail_name:
            raise OSError(5, "Input/output error")
        return real_unlink(path, *a, **kw)

    monkeypatch.setattr(_os, "scandir", scandir)
    monkeypatch.setattr(_os, "unlink", unlink)
    assert client.delete(f"/v1/jobs/{job.job_id}").status_code == 503
    monkeypatch.undo()
    assert store.get(job.job_id).status is JobStatus.DONE
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


def _failing_delete_objects(blobs, fail_names, calls):
    """delete_objects that reports per-key Errors (and deletes nothing) for ``fail_names`` and
    really deletes every other key in the batch -- S3's independent per-key outcome."""
    real = blobs._s3.delete_objects

    def delete_objects(Bucket, Delete):  # noqa: N803 -- boto3's parameter names
        objs = Delete["Objects"]
        calls.append([o["Key"].rsplit("/", 1)[-1] for o in objs])
        bad = [o for o in objs if o["Key"].rsplit("/", 1)[-1] in fail_names]
        good = [o for o in objs if o not in bad]
        resp = real(Bucket=Bucket, Delete={"Objects": good}) if good else {}
        resp["Errors"] = [{"Key": o["Key"], "Code": "InternalError", "Message": "x"}
                          for o in bad]
        return resp

    return delete_objects


@pytest.mark.parametrize("fail_names", [
    {attest.RECEIPT_NAME, "metadata.json"}, {attest.RECEIPT_NAME}, {"metadata.json"}])
def test_a_partial_s3_delete_never_unmasks_an_as_is_receipt(tmp_path, request, fail_names):
    """S3 delete_job was one DeleteObjects batch whose per-key Errors are independent: the
    marker could go while attestation.json and metadata.json stayed, and the route served the
    worker's bytes 200 on a still-DONE job."""
    store = InMemoryJobStore()
    blobs = _s3_store(tmp_path, request)
    job = _as_is_result(tmp_path, blobs, store)
    client = _client_on(tmp_path, store, blobs)
    calls: list[list[str]] = []
    blobs._s3.delete_objects = _failing_delete_objects(blobs, fail_names, calls)
    assert client.delete(f"/v1/jobs/{job.job_id}").status_code == 503
    assert store.get(job.job_id).status is JobStatus.DONE
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT
    with blobs.open_output(job.job_id, attest.WITHHELD_NAME) as fh:   # the marker survives
        assert attest.is_tombstone(fh.read())


def test_s3_delete_removes_the_receipt_first_and_the_marker_last(tmp_path, request):
    """The order every partial failure relies on: attestation.json in a call of its own before
    anything else, the marker in a call of its own after everything else."""
    store = InMemoryJobStore()
    blobs = _s3_store(tmp_path, request)
    job = _as_is_result(tmp_path, blobs, store)
    calls: list[list[str]] = []
    blobs._s3.delete_objects = _failing_delete_objects(blobs, set(), calls)
    blobs.delete_job(job.job_id)
    assert calls[0] == [attest.RECEIPT_NAME]
    assert calls[-1] == [attest.WITHHELD_NAME]
    assert all(attest.RECEIPT_NAME not in c and attest.WITHHELD_NAME not in c
               for c in calls[1:-1])
    with pytest.raises(Exception):
        blobs.open_output(job.job_id, "metadata.json")


def test_local_delete_removes_everything_when_nothing_fails(tmp_path):
    store = InMemoryJobStore()
    blobs = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    job = _as_is_result(tmp_path, blobs, store)
    blobs.delete_job(job.job_id)
    assert not (tmp_path / "blobs" / "results" / job.job_id).exists()


# ---------------------------------------------------------------------------
# A stored withheld marker is OVERWRITTEN, never stranded (round-5 review L2)
# ---------------------------------------------------------------------------


def _retained_tree_with_our_receipt(tmp_path, store, key):
    """A FAILED, retained tree whose receipt THIS host's key signed (the sweep ships it)."""
    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL, RESULT_RETAINED_MARKER

    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.FAILED
    job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    body = attest.seal_receipt(out, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine="clippyshot", input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2))
    (job_root / job.job_id / PENDING_UPLOAD_SENTINEL).write_text("")
    return job_root, job, out, body


@pytest.mark.parametrize("backend", ["local", "s3"])
def test_a_marker_an_earlier_as_is_upload_stored_never_hides_a_later_genuine_receipt(
        tmp_path, request, backend):
    """Reviewer's L2: an earlier sweep tick shipped the tree as-is and its marker landed in the
    store (the store never deletes a single object); a later tick, now able to rule the envelope
    out, ships it WITH this host's receipt. Stripping the marker locally left the stored one in
    place and the route 404'd the genuine receipt forever: the later upload must OVERWRITE it."""
    import logging

    from blastbox.host.jobs.retention import retry_pending_uploads

    blobs = (LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
             if backend == "local" else _s3_store(tmp_path, request))
    store = InMemoryJobStore()
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    job_root, job, out, body = _retained_tree_with_our_receipt(tmp_path, store, key)
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    (earlier / attest.WITHHELD_NAME).write_bytes(
        attest.canonical(attest.tombstone_body(attest.RECEIPT_PATH_UNDECIDABLE_REASON)))
    blobs.put_output(job.job_id, earlier)                 # tick 1's partial as-is upload
    assert retry_pending_uploads(job_root, blobs, store, logging.getLogger("t"),
                                 attest_key=key) == 1
    client = _client_on(tmp_path, store, blobs)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


def _stored_result(tmp_path, store, files: dict[str, bytes]):
    job, out = _make_done_job(tmp_path, store)
    for name, data in files.items():
        (out / name).write_bytes(data)
    _push_to_blob(tmp_path, job.job_id, out)
    return job, out


def test_a_cleared_marker_serves_the_receipt(tmp_path, key):
    client, store = _make_client(tmp_path)
    job, out, body = _done_with_receipt(tmp_path, store, key)
    (out / attest.WITHHELD_NAME).write_bytes(_cleared_for(out))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


def test_a_cleared_marker_still_answers_the_tombstone_404(tmp_path):
    client, store = _make_client(tmp_path)
    job, out = _stored_result(tmp_path, store, {
        attest.RECEIPT_NAME: attest.canonical(attest.tombstone_body("no attestation key"))})
    (out / attest.WITHHELD_NAME).write_bytes(_cleared_for(out))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404
    assert "no attestation key" in r.json()["detail"]


@pytest.mark.parametrize("marker", [
    b"",
    b"not json at all",
    b'{"attestation": "not-withheld", "wit',
    b'{"attestation": "not-withheld", "withheld": 0}',
    b'{"attestation": "not-withheld", "withheld": false, "x": 1}',
    b'{"attestation": "not-withheld"}',
    b'{"withheld": false}',
    b'["attestation", "not-withheld"]',
    b'{"attestation": null, "reason": "not-withheld"}',
    b'{"attestation":"not-withheld","withheld":false}',                # the pre-binding body
    attest.canonical({**attest.cleared_marker_body("0" * 64), "x": 1}),
    attest.canonical(attest.cleared_marker_body("0" * 63)),
    attest.canonical(attest.cleared_marker_body("A" * 64)),
    json.dumps(attest.cleared_marker_body("0" * 64)).encode(),         # not canonical
])
def test_any_marker_but_the_cleared_body_withholds(tmp_path, marker):
    """Only the ONE canonical cleared body unmasks; anything else stored at the marker's name
    -- unparseable, a tombstone, a near-miss -- answers the no-receipt 404."""
    client, store = _make_client(tmp_path)
    job, _ = _stored_result(tmp_path, store, {attest.WITHHELD_NAME: marker,
                                              attest.RECEIPT_NAME: _FORGED_RECEIPT})
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


_LOOKALIKE = attest.canonical(attest.cleared_marker_body("a" * 64))


def _legacy_with_declared_marker_lookalike(out):
    """A tree accepted before the marker's name was reserved, DECLARING an artifact there whose
    (untrusted) bytes equal the cleared body, beside a worker-written attestation.json."""
    lookalike = _LOOKALIKE
    (out / attest.WITHHELD_NAME).write_bytes(lookalike)
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.WITHHELD_NAME,
         "sha256": hashlib.sha256(lookalike).hexdigest()}]}))


def test_a_declared_cleared_body_lookalike_is_never_shipped_as_is_by_the_migration(tmp_path):
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    client, store = _make_client(tmp_path)
    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    _legacy_with_declared_marker_lookalike(out)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (0, 0, 1)
    assert not blobs.has_output(job.job_id)
    assert (out / attest.WITHHELD_NAME).read_bytes() == _LOOKALIKE    # nothing destroyed
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404 and r.content != _FORGED_RECEIPT


def test_a_declared_cleared_body_lookalike_is_never_shipped_as_is_by_the_sweep(tmp_path):
    import logging

    from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL, retry_pending_uploads

    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.FAILED
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    _legacy_with_declared_marker_lookalike(out)
    (job_root / job.job_id / PENDING_UPLOAD_SENTINEL).write_text("")
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    assert retry_pending_uploads(job_root, blobs, store, logging.getLogger("t"),
                                 attest_key=key) == 0
    assert not blobs.has_output(job.job_id)
    assert store.get(job.job_id).status is JobStatus.FAILED            # left retained



# ---------------------------------------------------------------------------
# Unmarked is LEGACY, not safe: the route judges its envelope (round-5 panel P1)
# ---------------------------------------------------------------------------


def _unmarked(tmp_path, store, *, envelope: bytes | None = None, receipt: bytes | None = None,
              key=None):
    """A stored DONE result with NO marker -- what pre-upgrade uploaders left in the store."""
    job, out = _make_done_job(tmp_path, store)
    if envelope is not None:
        (out / "metadata.json").write_bytes(envelope)
    body = None
    if key is not None:
        body = attest.seal_receipt(out, key=key, observation=attest.RunObservation(
            job_id=job.job_id, engine=job.engine, input_sha256="d" * 64,
            worker_runtime="runsc", worker_tier=None, started_at_ms=1, finished_at_ms=2))
    if receipt is not None:
        (out / attest.RECEIPT_NAME).write_bytes(receipt)
    (out / attest.WITHHELD_NAME).unlink(missing_ok=True)
    _push_to_blob(tmp_path, job.job_id, out)
    return job, body


@pytest.mark.parametrize("envelope,reason", [
    (json.dumps({"artifacts": [{"id": "a", "path": attest.RECEIPT_NAME}]}).encode(),
     attest.RECEIPT_PATH_DECLARED_REASON),
    (json.dumps({"artifacts": [{"id": "a", "path": "attestation.json/p.png"}]}).encode(),
     attest.RECEIPT_PATH_DECLARED_REASON),
    (b'{"artifacts": [{"id": "a", "pa', attest.RECEIPT_PATH_UNDECIDABLE_REASON),
])
def test_an_unmarked_legacy_result_whose_envelope_protects_the_receipt_name_is_404(
        tmp_path, envelope, reason):
    """Pre-#188 results (attestation.json never reserved) and as-is uploads by earlier builds
    carry no marker. Their envelope still decides: a declared (or undecidable) artifact at
    attestation.json is never served as the receipt."""
    store = InMemoryJobStore()
    job, _ = _unmarked(tmp_path, store, envelope=envelope, receipt=_FORGED_RECEIPT)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert reason in r.json()["detail"]


def test_an_unmarked_legacy_result_over_this_ingress_cap_is_404(tmp_path, monkeypatch):
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job, _ = _unmarked(tmp_path, store, receipt=_FORGED_RECEIPT,
                       envelope=json.dumps({"artifacts": [], "pad": "x" * 4096}).encode())
    r = _route_with_limit(tmp_path, store, 1024).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]


def test_an_unmarked_legacy_result_with_a_genuine_receipt_still_serves(tmp_path, key):
    store = InMemoryJobStore()
    job, body = _unmarked(tmp_path, store, key=key)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.json() == body


def test_a_fresh_result_over_this_ingress_cap_serves_via_the_cleared_marker(
        tmp_path, key, monkeypatch):
    """The fresh seal's cleared marker is the host vouching for its own envelope: an ingress
    with a SMALLER ceiling than the signer's never re-judges it (deepseek D1 stays fixed)."""
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job, out = _make_done_job(tmp_path, store)
    meta = json.loads((out / "metadata.json").read_bytes())
    meta["pad"] = "x" * 4096
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    assert attest.seal_fresh_receipt(out, key=key, job_id=job.job_id,
                                     observation=attest.RunObservation(
        job_id=job.job_id, engine=job.engine, input_sha256="d" * 64, worker_runtime="runsc",
        worker_tier=None, started_at_ms=1, finished_at_ms=2))
    _push_to_blob(tmp_path, job.job_id, out)
    r = _route_with_limit(tmp_path, store, 1024).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    assert r.content == (out / attest.RECEIPT_NAME).read_bytes()


@pytest.mark.parametrize("marker", [
    lambda c: attest.canonical(attest.tombstone_body("r" * 5000)),  # 5000+ bytes, tombstone
    lambda c: c + b" " * 5000,                                      # cleared, then padding
    lambda c: c + b" ",                                             # one byte past cleared
])
def test_an_oversize_or_padded_marker_withholds(tmp_path, key, marker):
    """A marker is read under a small cap; anything over it (or a near-miss of the cleared
    bytes) is withheld, never truncated into a verdict."""
    client, store = _make_client(tmp_path)
    job, out, _ = _done_with_receipt(tmp_path, store, key)
    (out / attest.WITHHELD_NAME).write_bytes(marker(_cleared_for(out)))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text


def test_the_migration_strip_branch_stores_the_cleared_marker(tmp_path):
    """The migration ships a result whose envelope rules the names out with a TOMBSTONE at
    attestation.json (never nothing there: round-6 K1); the tombstone write vouches with the
    cleared marker, so the route never re-judges it."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    store.create(job)
    out = job_root / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, blobs, store, logging.getLogger("t")) == (1, 0, 0)
    with blobs.open_result_only(job.job_id, attest.WITHHELD_NAME) as fh:
        assert fh.read() == _cleared_for(out)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404 and r.content != _FORGED_RECEIPT


def test_the_sweep_receipt_branch_with_a_declared_marker_artifact_stays_retained(tmp_path, key):
    """P2: a pre-upgrade retained tree carrying OUR receipt but DECLARING an artifact at the
    marker's name: the cleared marker cannot be written without destroying it, so the tree is
    not shipped (the accepted strand) and the artifact is intact."""
    import logging

    from blastbox.host.jobs.retention import retry_pending_uploads

    store = InMemoryJobStore()
    job_root, job, out, _ = _retained_tree_with_our_receipt(tmp_path, store, key)
    (out / attest.WITHHELD_NAME).write_bytes(b"accepted")
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.WITHHELD_NAME}]}))
    blobs = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert retry_pending_uploads(job_root, blobs, store, logging.getLogger("t"),
                                 attest_key=key) == 0
    assert not blobs.has_output(job.job_id)
    assert (out / attest.WITHHELD_NAME).read_bytes() == b"accepted"


# ---------------------------------------------------------------------------
# A cleared marker only ever ships beside an attestation.json this host wrote, and it is bound
# to the envelope it shipped with (round-6 review K1/K2/K3)
# ---------------------------------------------------------------------------


class _DiesBeforeSeal(LocalBlobStore):
    """put_output stores metadata.json LAST; this store fails exactly there, so everything else
    of the tree -- attestation.json and the withheld marker included -- is already stored."""

    def _atomic_copy(self, src, dest):
        if dest.name == "metadata.json":
            raise OSError(28, "No space left on device")
        return super()._atomic_copy(src, dest)


class _StoreDown(LocalBlobStore):
    def _atomic_copy(self, src, dest):
        raise OSError(5, "Input/output error")


def test_a_migration_rerun_never_unmasks_a_worker_receipt_an_earlier_partial_upload_stored(
        tmp_path, monkeypatch):
    """K1 (lens). Run 1 (a stale --max-metadata) ships the tree as-is and dies before the
    envelope lands: the worker's attestation.json is stored. Run 2 (the service's limit) strips
    it LOCALLY and vouched with the cleared marker, shipping nothing at attestation.json -- so the
    stored worker file was served 200 as the receipt. The strip branch must OVERWRITE it."""
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    bad = _DiesBeforeSeal(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, bad, store, logging.getLogger("t"),
                                  limits=Limits(max_metadata_bytes=1024)) == (0, 0, 1)
    with bad.open_result_only(job.job_id, attest.RECEIPT_NAME) as fh:
        assert fh.read() == _FORGED_RECEIPT                   # the partial upload stored it
    good = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert migrate_legacy_results(job_root, good, store, logging.getLogger("t"),
                                  limits=Limits(max_metadata_bytes=1 << 20)) == (1, 0, 0)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


_PRE_BINDING_CLEARED = b'{"attestation":"not-withheld","withheld":false}'


def _legacy_declaring_both_names(tmp_path, store, marker_for):
    """K2 (codex). A result uploaded by OLDER code (no reserved names) whose envelope DECLARES an
    artifact at attestation.json (forged) AND one at attestation.withheld.json, whose bytes are
    ``marker_for(envelope-without-that-artifact)``. Stored as the old uploader did: verbatim."""
    job, out = _make_done_job(tmp_path, store)
    (out / attest.RECEIPT_NAME).write_bytes(_FORGED_RECEIPT)
    base = {"artifacts": [{"id": "r", "path": attest.RECEIPT_NAME,
                           "sha256": hashlib.sha256(_FORGED_RECEIPT).hexdigest()}]}
    marker = marker_for(json.dumps(base).encode())
    base["artifacts"].append({"id": "m", "path": attest.WITHHELD_NAME,
                              "sha256": hashlib.sha256(marker).hexdigest()})
    (out / attest.WITHHELD_NAME).write_bytes(marker)
    (out / "metadata.json").write_text(json.dumps(base))
    _push_to_blob(tmp_path, job.job_id, out)
    return job


@pytest.mark.parametrize("marker_for", [
    # The cleared body as it was before it was bound to the envelope.
    lambda envelope: _PRE_BINDING_CLEARED,
    # The best an attacker can do with the binding: the body for the envelope as it was BEFORE
    # it declared the marker artifact (declaring it changes the envelope's hash).
    lambda envelope: attest.canonical({"attestation": "not-withheld", "withheld": False,
                                       "metadata_sha256": hashlib.sha256(envelope).hexdigest()}),
], ids=["pre-binding-body", "bound-to-the-envelope-before-declaring"])
def test_a_declared_cleared_lookalike_never_unmasks_a_declared_receipt(tmp_path, marker_for):
    store = InMemoryJobStore()
    job = _legacy_declaring_both_names(tmp_path, store, marker_for)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT


def test_the_cleared_marker_binds_the_envelope_it_shipped_with(tmp_path, key):
    """The cleared marker names the sha256 of the metadata.json shipped in the same upload."""
    client, store = _make_client(tmp_path)
    job, out, _ = _done_with_receipt(tmp_path, store, key)
    meta_sha = hashlib.sha256((out / "metadata.json").read_bytes()).hexdigest()
    with LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs").open_result_only(
            job.job_id, attest.WITHHELD_NAME) as fh:
        stored = fh.read()
    assert stored == attest.canonical({"attestation": "not-withheld", "withheld": False,
                                       "metadata_sha256": meta_sha})
    assert attest.bound_cleared_marker_sha256(stored) == meta_sha
    assert attest.is_cleared_marker(stored, meta_sha)
    assert not attest.is_cleared_marker(stored, "0" * 64)


def test_a_swapped_envelope_falls_back_to_the_legacy_judgement(tmp_path, key):
    """After a post-DONE swap of metadata.json the marker no longer matches the stored envelope,
    so it vouches for nothing and the route judges the envelope it actually serves: a swap to an
    envelope that declares attestation.json answers 404 (a benign swap still serves the receipt,
    whose metadata_sha256 then shows the mismatch -- see
    test_receipt_matches_served_metadata_until_someone_swaps_it)."""
    client, store = _make_client(tmp_path)
    job, out, _ = _done_with_receipt(tmp_path, store, key)
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.RECEIPT_NAME}]}))
    _push_to_blob(tmp_path, job.job_id, out)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_DECLARED_REASON in r.json()["detail"]


def test_a_sweep_as_is_upload_that_fails_once_is_not_stranded_by_its_own_marker(
        tmp_path, monkeypatch):
    """K3 (lens/codex/agy). Tick 1 writes the withheld marker into the tree, then the store is
    down: the tree stays retained WITH the host's marker. Tick 2 saw an entry at the marker's
    name, could not parse the envelope to rule it out and refused, every tick, forever."""
    import logging

    from blastbox.host.jobs.retention import retry_pending_uploads

    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "1024")
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job, out = _retained_tree_with_big_envelope(tmp_path, store)
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    down = _StoreDown(job_root, blob_root=tmp_path / "blobs")
    assert retry_pending_uploads(job_root, down, store, logging.getLogger("t"),
                                 attest_key=key) == 0
    assert (out / attest.WITHHELD_NAME).exists()
    assert store.get(job.job_id).status is JobStatus.FAILED
    good = LocalBlobStore(job_root, blob_root=tmp_path / "blobs")
    assert retry_pending_uploads(job_root, good, store, logging.getLogger("t"),
                                 attest_key=key) == 1
    assert store.get(job.job_id).status is JobStatus.DONE
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert attest.RECEIPT_PATH_UNDECIDABLE_REASON in r.json()["detail"]


def test_a_migration_as_is_upload_that_fails_once_is_not_stranded_by_its_own_marker(
        tmp_path, monkeypatch):
    import logging

    from blastbox.host.jobs.retention import migrate_legacy_results

    monkeypatch.delenv("BLASTBOX_MAX_METADATA", raising=False)
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    store = InMemoryJobStore()
    job_root, job = _legacy_tree_with_big_envelope(tmp_path, store)
    lim = Limits(max_metadata_bytes=1024)
    assert migrate_legacy_results(job_root, _StoreDown(job_root, blob_root=tmp_path / "blobs"),
                                  store, logging.getLogger("t"), limits=lim) == (0, 0, 1)
    assert migrate_legacy_results(job_root, LocalBlobStore(job_root, blob_root=tmp_path / "blobs"),
                                  store, logging.getLogger("t"), limits=lim) == (1, 0, 0)
    r = _route_with_limit(tmp_path, store, 1 << 20).get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404, r.text
    assert r.content != _FORGED_RECEIPT
