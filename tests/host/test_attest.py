"""Execution receipts: the signing key, the canonical form, and sealing a receipt into a tree.

A receipt is signed by the DISPATCHER that ran the job, at the moment it seals a DONE result,
from its own in-memory observation of that run. Nothing on the job row feeds it.
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


def _verify(public_pem: str, doc: dict, sig: str) -> None:
    pub = serialization.load_pem_public_key(public_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.urlsafe_b64decode(sig), attest.canonical(doc), ec.ECDSA(hashes.SHA256()))


def _obs(**kw) -> attest.RunObservation:
    base = dict(job_id="11111111-1111-1111-1111-111111111111", engine="clippyshot",
                input_sha256="b" * 64, worker_runtime="runsc", worker_tier=None,
                net_policy_effective="none", started_at_ms=1_000_250, finished_at_ms=1_010_500)
    base.update(kw)
    return attest.RunObservation(**base)


def _tree(tmp_path, meta: bytes = b'{"engine":"clippyshot"}'):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_bytes(meta)
    return out


# ---------------------------------------------------------------------------
# Key location, generation, identity, hardening
# ---------------------------------------------------------------------------


def test_key_path_prefers_explicit_env_then_pki_dir_else_disabled(tmp_path):
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": str(tmp_path / "k"),
                                   "BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) == tmp_path / "k"
    assert attest.attest_key_path({"BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) == (
        tmp_path / "pki" / "attest.key")
    assert attest.attest_key_path({}) is None
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": "", "BLASTBOX_PKI_DIR": " "}) is None


def test_generates_p256_key_0600_and_reloads_the_same_one(tmp_path):
    path = tmp_path / "pki" / "attest.key"
    k1 = attest.load_or_create_key(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey) and priv.curve.name == "secp256r1"
    k2 = attest.load_or_create_key(path)
    assert k1.key_id == k2.key_id and k1.public_key_pem == k2.public_key_pem
    assert [p.name for p in path.parent.iterdir()] == ["attest.key"]   # no temp litter


def test_load_existing_does_not_create(tmp_path):
    with pytest.raises(FileNotFoundError):
        attest.load_existing_key(tmp_path / "attest.key")
    assert not (tmp_path / "attest.key").exists()


def test_key_id_is_sha256_of_spki_der_first_16_hex(tmp_path):
    k = attest.load_or_create_key(tmp_path / "attest.key")
    pub = serialization.load_pem_public_key(k.public_key_pem.encode())
    spki = pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    assert k.key_id == hashlib.sha256(spki).hexdigest()[:16]


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


def test_refuses_a_key_that_is_not_p256(tmp_path):
    path = tmp_path / "attest.key"
    other = ec.generate_private_key(ec.SECP384R1())
    path.write_bytes(other.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    path.chmod(0o600)
    with pytest.raises(attest.AttestKeyRefused, match="P-256"):
        attest.load_or_create_key(path)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o610])
def test_refuses_a_key_with_group_or_other_bits(tmp_path, mode):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    path.chmod(mode)
    with pytest.raises(attest.AttestKeyRefused, match="permission"):
        attest.load_or_create_key(path)


def test_refuses_a_symlinked_key(tmp_path):
    real = tmp_path / "real.key"
    attest.load_or_create_key(real)
    link = tmp_path / "attest.key"
    link.symlink_to(real)
    with pytest.raises(attest.AttestKeyRefused, match="symlink"):
        attest.load_or_create_key(link)
    with pytest.raises(attest.AttestKeyRefused, match="symlink"):
        attest.load_existing_key(link)


def test_refuses_a_key_owned_by_someone_else(tmp_path, monkeypatch):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    monkeypatch.setattr(attest.os, "geteuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(attest.AttestKeyRefused, match="owned"):
        attest.load_or_create_key(path)


def test_refuses_a_key_that_is_not_a_regular_file(tmp_path):
    (tmp_path / "attest.key").mkdir()
    with pytest.raises(attest.AttestKeyRefused):
        attest.load_or_create_key(tmp_path / "attest.key")


def test_load_attest_key_returns_none_and_logs_when_refused(tmp_path, caplog):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    path.chmod(0o644)
    assert attest.load_attest_key({"BLASTBOX_ATTEST_KEY": str(path)}) is None
    assert "refus" in caplog.text.lower()
    assert attest.load_attest_key({}) is None


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def test_canonical_is_the_contract_form():
    x = {"b": 1, "a": [2, None, True], "é": "ü"}
    assert attest.canonical(x) == json.dumps(
        x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert attest.canonical(x) == b'{"a":[2,null,true],"b":1,"\\u00e9":"\\u00fc"}'


@pytest.mark.parametrize("bad", [1.5, {"a": 1.0}, [0, {"t": 2.5}], {"n": float("nan")}])
def test_canonical_refuses_floats(bad):
    """Float rendering is implementation-specific, so a float would make the signed bytes
    depend on the verifier's JSON library. Refuse, so it can never regress."""
    with pytest.raises(TypeError, match="float"):
        attest.canonical(bad)


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


def test_receipt_doc_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_HOST_ID", "toolz3")
    key = attest.load_or_create_key(tmp_path / "k")
    doc = attest.build_receipt(_obs(), key_id=key.key_id, metadata_sha256="c" * 64,
                               issued_at_ms=2_000_000)
    assert doc == {
        "v": 1, "alg": "ES256", "key_id": key.key_id, "host": "toolz3",
        "job_id": "11111111-1111-1111-1111-111111111111", "engine": "clippyshot",
        "status": "done", "executor": "local",
        "input_sha256": "b" * 64, "metadata_sha256": "c" * 64,
        "worker_runtime": "runsc", "worker_tier": None, "net_policy_effective": "none",
        "started_at_ms": 1_000_250, "finished_at_ms": 1_010_500, "issued_at_ms": 2_000_000,
    }


def test_unknown_policy_is_omitted_not_guessed():
    doc = attest.build_receipt(_obs(net_policy_effective=None), key_id="k" * 16,
                               metadata_sha256="c" * 64)
    assert "net_policy_effective" not in doc
    assert isinstance(doc["issued_at_ms"], int)


def test_host_id_env_else_hostname():
    import socket

    assert attest.host_id({"BLASTBOX_HOST_ID": "toolz3"}) == "toolz3"
    assert attest.host_id({"BLASTBOX_HOST_ID": "  "}) == socket.gethostname()
    assert attest.host_id({}) == socket.gethostname()


def test_seal_writes_a_verifiable_receipt_over_the_exact_metadata_bytes(tmp_path):
    meta = b'{"engine": "clippyshot",  "x": 1}\n'
    out = _tree(tmp_path, meta)
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    assert body is not None
    on_disk = json.loads((out / attest.RECEIPT_NAME).read_bytes())
    assert on_disk == body
    doc = on_disk["attestation"]
    assert doc["metadata_sha256"] == hashlib.sha256(meta).hexdigest()
    sig = on_disk["signature"]
    assert "+" not in sig and "/" not in sig and len(sig) % 4 == 0   # urlsafe, padded
    _verify(key.public_key_pem, doc, sig)


@pytest.mark.parametrize("field,value", [
    ("job_id", "00000000-0000-0000-0000-000000000000"), ("engine", "other"),
    ("status", "failed"), ("input_sha256", "0" * 64), ("metadata_sha256", "0" * 64),
    ("executor", "node:x"), ("worker_runtime", "runc"), ("worker_tier", "firecracker"),
    ("net_policy_effective", "direct"), ("finished_at_ms", 1), ("host", "evil"),
    ("key_id", "0" * 16), ("issued_at_ms", 7),
])
def test_tampering_any_field_breaks_verification(tmp_path, field, value):
    out = _tree(tmp_path)
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    doc = dict(body["attestation"])
    assert field in doc
    doc[field] = value
    with pytest.raises(InvalidSignature):
        _verify(key.public_key_pem, doc, body["signature"])


@pytest.mark.parametrize("planted", ["file", "dir", "symlink"])
def test_a_worker_planted_receipt_is_removed_even_without_a_key(tmp_path, planted):
    out = _tree(tmp_path)
    target = out / attest.RECEIPT_NAME
    if planted == "file":
        target.write_text('{"attestation": {"attested": true}, "signature": "x"}')
    elif planted == "dir":
        target.mkdir()
        (target / "inner").write_text("x")
    else:
        (tmp_path / "elsewhere").write_text("keep me")
        target.symlink_to(tmp_path / "elsewhere")
    assert attest.seal_receipt(out, key=None, observation=_obs()) is None
    assert not os.path.lexists(target)
    if planted == "symlink":
        assert (tmp_path / "elsewhere").read_text() == "keep me"   # never followed


def test_a_worker_planted_receipt_is_replaced_by_ours(tmp_path):
    out = _tree(tmp_path)
    (out / attest.RECEIPT_NAME).write_text('{"attestation": {"forged": 1}, "signature": "x"}')
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    assert json.loads((out / attest.RECEIPT_NAME).read_bytes()) == body


def test_no_receipt_when_metadata_is_not_a_regular_file(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (tmp_path / "real.json").write_text("{}")
    (out / "metadata.json").symlink_to(tmp_path / "real.json")
    key = attest.load_or_create_key(tmp_path / "k")
    assert attest.seal_receipt(out, key=key, observation=_obs()) is None
    assert not (out / attest.RECEIPT_NAME).exists()


def test_sha256_file_is_the_sha256_of_the_bytes(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"malware" * 100_000)
    assert attest.sha256_file(p) == hashlib.sha256(b"malware" * 100_000).hexdigest()


def test_no_receipt_when_the_envelope_declares_the_reserved_name(tmp_path):
    """Defence in depth behind the trust gate: never write a receipt over a declared artifact."""
    out = _tree(tmp_path, json.dumps({"artifacts": [
        {"id": "r", "path": "./attestation.json"}]}).encode())
    key = attest.load_or_create_key(tmp_path / "k")
    assert attest.seal_receipt(out, key=key, observation=_obs()) is None
    assert not (out / attest.RECEIPT_NAME).exists()
