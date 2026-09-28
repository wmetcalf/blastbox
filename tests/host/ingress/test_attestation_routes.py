"""GET /v1/jobs/{id}/attestation and GET /v1/attestation/key."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import attest
from blastbox.host.jobs.base import Job, JobStatus
from tests.host.ingress.test_app import _make_client, _make_done_job, _push_to_blob


@pytest.fixture
def key_env(tmp_path, monkeypatch):
    path = tmp_path / "attest.key"
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(path))
    monkeypatch.delenv("BLASTBOX_PKI_DIR", raising=False)
    monkeypatch.setenv("BLASTBOX_HOST_ID", "toolz-test")
    return path


def _verify(pem: str, doc: dict, sig: str) -> None:
    pub = serialization.load_pem_public_key(pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.urlsafe_b64decode(sig), attest.canonical(doc), ec.ECDSA(hashes.SHA256()))


def _done(tmp_path, store, **row):
    job, out = _make_done_job(tmp_path, store)
    fields = {"input_sha256": "d" * 64, "started_at": 100.0, "finished_at": 105.0,
              "worker_runtime": "runsc", "claim_id": "local-claim", **row}
    store.update(job.job_id, **fields)
    return store.get(job.job_id), out


def test_key_route_and_signature_verify_end_to_end(tmp_path, key_env):
    client, store = _make_client(tmp_path)
    job, _ = _done(tmp_path, store, net_policy_effective="none")
    k = client.get("/v1/attestation/key")
    assert k.status_code == 200
    kb = k.json()
    assert set(kb) == {"key_id", "alg", "public_key_pem"} and kb["alg"] == "ES256"
    assert key_env.exists()

    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    body = r.json()
    doc, sig = body["attestation"], body["signature"]
    _verify(kb["public_key_pem"], doc, sig)
    assert doc["key_id"] == kb["key_id"]
    assert doc["host"] == "toolz-test"
    assert doc["job_id"] == job.job_id and doc["status"] == "done"
    assert doc["input_sha256"] == "d" * 64
    assert doc["executor"] == "local"
    assert doc["worker_runtime"] == "runsc" and doc["net_policy_effective"] == "none"

    doc["status"] = "failed"
    with pytest.raises(InvalidSignature):
        _verify(kb["public_key_pem"], doc, sig)


def test_metadata_sha256_is_the_hash_of_the_served_bytes(tmp_path, key_env):
    client, store = _make_client(tmp_path)
    job, _ = _done(tmp_path, store)
    served = client.get(f"/v1/jobs/{job.job_id}/metadata")
    assert served.status_code == 200
    doc = client.get(f"/v1/jobs/{job.job_id}/attestation").json()["attestation"]
    assert doc["metadata_sha256"] == hashlib.sha256(served.content).hexdigest()


def test_worker_written_claims_in_metadata_change_nothing(tmp_path, key_env):
    """A hostile worker writes attestation-shaped keys into its own envelope. The doc is built
    from the host's row, so none of them surface -- only the hash of the bytes changes."""
    client, store = _make_client(tmp_path)
    job, out = _done(tmp_path, store, worker_runtime="runsc", worker_tier=None,
                     net_policy_effective="none")
    meta = json.loads((out / "metadata.json").read_bytes())
    meta.update({"net_policy_effective": "direct", "attested": True, "worker_runtime": "none",
                 "worker_tier": "firecracker", "executor": "local", "status": "done",
                 "host": "evil", "input_sha256": "0" * 64})
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())
    _push_to_blob(tmp_path, job.job_id, out)

    doc = client.get(f"/v1/jobs/{job.job_id}/attestation").json()["attestation"]
    assert doc["net_policy_effective"] == "none"
    assert doc["worker_runtime"] == "runsc"
    assert doc["worker_tier"] is None
    assert doc["host"] == "toolz-test"
    assert doc["input_sha256"] == "d" * 64
    assert "attested" not in doc
    served = client.get(f"/v1/jobs/{job.job_id}/metadata").content
    assert doc["metadata_sha256"] == hashlib.sha256(served).hexdigest()


def test_node_executed_job_omits_runtime_tier_policy(tmp_path, key_env):
    client, store = _make_client(tmp_path)
    job, _ = _done(tmp_path, store, claim_id="node:xyz", executor_node="node-7",
                   worker_runtime="warm", worker_tier="firecracker",
                   net_policy_effective="none")
    doc = client.get(f"/v1/jobs/{job.job_id}/attestation").json()["attestation"]
    assert doc["executor"] == "node:node-7"
    for k in ("worker_runtime", "worker_tier", "net_policy_effective"):
        assert k not in doc


@pytest.mark.parametrize("status", [JobStatus.QUEUED, JobStatus.RUNNING])
def test_non_terminal_is_409(tmp_path, key_env, status):
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = status
    store.create(job)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 409


def test_failed_job_is_attested_with_no_metadata(tmp_path, key_env):
    client, store = _make_client(tmp_path)
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.FAILED
    job.input_sha256 = "e" * 64
    job.error = "worker died"
    store.create(job)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 200, r.text
    doc = r.json()["attestation"]
    assert doc["status"] == "failed"
    assert doc["metadata_sha256"] is None     # the metadata route serves nothing for it


def test_unknown_and_malformed_job_ids_are_404(tmp_path, key_env):
    client, _ = _make_client(tmp_path)
    assert client.get("/v1/jobs/00000000-0000-0000-0000-000000000000/attestation"
                      ).status_code == 404
    assert client.get("/v1/jobs/not-a-uuid/attestation").status_code == 404


def test_disabled_when_no_key_is_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_ATTEST_KEY", raising=False)
    monkeypatch.delenv("BLASTBOX_PKI_DIR", raising=False)
    client, store = _make_client(tmp_path)
    job, _ = _done(tmp_path, store)
    r = client.get(f"/v1/jobs/{job.job_id}/attestation")
    assert r.status_code == 404
    assert "attestation" in r.json()["detail"].lower()
    k = client.get("/v1/attestation/key")
    assert k.status_code == 404
    assert "attestation" in k.json()["detail"].lower()


def test_routes_require_the_api_key_like_job_status(tmp_path, key_env):
    client, store = _make_client(tmp_path, api_key="s3cret")
    job, _ = _done(tmp_path, store)
    assert client.get(f"/v1/jobs/{job.job_id}").status_code == 401
    assert client.get(f"/v1/jobs/{job.job_id}/attestation").status_code == 401
    assert client.get("/v1/attestation/key").status_code == 401
    h = {"Authorization": "Bearer s3cret"}
    assert client.get(f"/v1/jobs/{job.job_id}/attestation", headers=h).status_code == 200
    assert client.get("/v1/attestation/key", headers=h).status_code == 200
