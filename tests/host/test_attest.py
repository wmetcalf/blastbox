"""Host attestation: the signing key and the signed statement.

The wire format is a CONTRACT another verifier codes against (see the Loadout spec
`2026-09-28-host-attestation-design.md`), so these tests pin it literally: canonical JSON,
key_id derivation, ES256 over DER, base64url with padding.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import attest
from blastbox.host.jobs.base import Job, JobStatus


def _verify(public_pem: str, doc: dict, sig: str) -> None:
    pub = serialization.load_pem_public_key(public_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.urlsafe_b64decode(sig), attest.canonical(doc), ec.ECDSA(hashes.SHA256()))


def _done_job(**kw) -> Job:
    job = Job.new(engine="clippyshot", filename="a.docx")
    job.status = JobStatus.DONE
    job.input_sha256 = "b" * 64
    job.started_at = 1000.25
    job.finished_at = 1010.5
    job.worker_runtime = "runsc"
    job.claim_id = "local-claim"
    for k, v in kw.items():
        setattr(job, k, v)
    return job


# ---------------------------------------------------------------------------
# Key location, generation, identity
# ---------------------------------------------------------------------------


def test_key_path_prefers_explicit_env_then_pki_dir_else_disabled(tmp_path):
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": str(tmp_path / "k"),
                                   "BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) == tmp_path / "k"
    assert attest.attest_key_path({"BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) == (
        tmp_path / "pki" / "attest.key")
    assert attest.attest_key_path({}) is None
    # set-but-empty is not a path (deployment tooling emits `VAR=`)
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": "", "BLASTBOX_PKI_DIR": " "}) is None


def test_generates_p256_key_0600_and_reloads_the_same_one(tmp_path):
    path = tmp_path / "pki" / "attest.key"
    k1 = attest.load_or_create_key(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)
    assert priv.curve.name == "secp256r1"
    k2 = attest.load_or_create_key(path)
    assert k1.key_id == k2.key_id and k1.public_key_pem == k2.public_key_pem
    assert not [p for p in path.parent.iterdir() if p.name != "attest.key"]  # no temp litter


def test_key_id_is_sha256_of_spki_der_first_16_hex(tmp_path):
    k = attest.load_or_create_key(tmp_path / "attest.key")
    pub = serialization.load_pem_public_key(k.public_key_pem.encode())
    spki = pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    assert k.key_id == hashlib.sha256(spki).hexdigest()[:16]
    assert len(k.key_id) == 16


def test_concurrent_first_use_converges_on_one_key(tmp_path):
    path = tmp_path / "attest.key"
    ids: list[str] = []
    lock = threading.Lock()

    def go():
        kid = attest.load_or_create_key(path).key_id
        with lock:
            ids.append(kid)

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(ids)) == 1
    assert ids[0] == attest.load_or_create_key(path).key_id


def test_refuses_a_key_that_is_not_p256(tmp_path):
    path = tmp_path / "attest.key"
    other = ec.generate_private_key(ec.SECP384R1())
    path.write_bytes(other.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    with pytest.raises(ValueError, match="P-256"):
        attest.load_or_create_key(path)


# ---------------------------------------------------------------------------
# Canonical form and signature
# ---------------------------------------------------------------------------


def test_canonical_is_the_contract_form():
    x = {"b": 1, "a": [1.5, None], "é": "ü"}
    assert attest.canonical(x) == json.dumps(
        x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert attest.canonical(x) == b'{"a":[1.5,null],"b":1,"\\u00e9":"\\u00fc"}'


def test_signature_verifies_and_is_padded_base64url(tmp_path):
    key = attest.load_or_create_key(tmp_path / "attest.key")
    body = attest.sign_attestation(key, attest.build_attestation(
        _done_job(), key_id=key.key_id, metadata_sha256="c" * 64, host="h1"))
    assert set(body) == {"attestation", "signature"}
    sig = body["signature"]
    assert "+" not in sig and "/" not in sig and len(sig) % 4 == 0   # urlsafe, padded
    _verify(key.public_key_pem, body["attestation"], sig)


@pytest.mark.parametrize("field,value", [
    ("job_id", "00000000-0000-0000-0000-000000000000"),
    ("engine", "other"),
    ("status", "failed"),
    ("input_sha256", "0" * 64),
    ("metadata_sha256", "0" * 64),
    ("executor", "node:x"),
    ("worker_runtime", "runc"),
    ("net_policy_effective", "direct"),
    ("finished_at", 1.0),
    ("host", "evil"),
    ("key_id", "0" * 16),
])
def test_tampering_any_field_breaks_verification(tmp_path, field, value):
    key = attest.load_or_create_key(tmp_path / "attest.key")
    body = attest.sign_attestation(key, attest.build_attestation(
        _done_job(net_policy_effective="none"), key_id=key.key_id,
        metadata_sha256="c" * 64, host="h1"))
    doc = dict(body["attestation"])
    assert field in doc
    doc[field] = value
    with pytest.raises(InvalidSignature):
        _verify(key.public_key_pem, doc, body["signature"])


# ---------------------------------------------------------------------------
# The document: host row only
# ---------------------------------------------------------------------------


def test_local_doc_fields(tmp_path):
    job = _done_job(worker_tier=None, net_policy_effective="none", net_policy="direct")
    doc = attest.build_attestation(job, key_id="k" * 16, metadata_sha256="c" * 64,
                                   host="h1", now=2000.0)
    assert doc == {
        "v": 1, "alg": "ES256", "key_id": "k" * 16, "host": "h1",
        "job_id": job.job_id, "engine": "clippyshot", "status": "done",
        "input_sha256": "b" * 64, "metadata_sha256": "c" * 64,
        "executor": "local",
        "worker_runtime": "runsc", "worker_tier": None, "net_policy_effective": "none",
        "started_at": 1000.25, "finished_at": 1010.5, "issued_at": 2000.0,
    }


def test_local_doc_omits_net_policy_effective_when_unrecorded():
    doc = attest.build_attestation(_done_job(), key_id="k" * 16, metadata_sha256=None, host="h")
    assert "net_policy_effective" not in doc
    assert doc["metadata_sha256"] is None


def test_node_executed_doc_omits_runtime_tier_and_policy():
    job = _done_job(claim_id="node:abc123", executor_node="node-7", worker_runtime="warm",
                    worker_tier="firecracker", net_policy_effective="none")
    doc = attest.build_attestation(job, key_id="k" * 16, metadata_sha256=None, host="h")
    assert doc["executor"] == "node:node-7"
    for k in ("worker_runtime", "worker_tier", "net_policy_effective"):
        assert k not in doc


def test_node_claim_without_a_recorded_node_is_still_not_local():
    job = _done_job(claim_id="node:abc123", executor_node=None)
    doc = attest.build_attestation(job, key_id="k" * 16, metadata_sha256=None, host="h")
    assert doc["executor"].startswith("node:") and doc["executor"] != "node:"
    assert "worker_runtime" not in doc


def test_host_id_env_else_hostname(monkeypatch):
    import socket

    assert attest.host_id({"BLASTBOX_HOST_ID": "toolz3"}) == "toolz3"
    assert attest.host_id({"BLASTBOX_HOST_ID": "  "}) == socket.gethostname()
    assert attest.host_id({}) == socket.gethostname()


def test_terminal_statuses():
    assert attest.is_terminal(JobStatus.DONE)
    assert attest.is_terminal(JobStatus.FAILED)
    assert attest.is_terminal(JobStatus.EXPIRED)
    assert not attest.is_terminal(JobStatus.QUEUED)
    assert not attest.is_terminal(JobStatus.RUNNING)
