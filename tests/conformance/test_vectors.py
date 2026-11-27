"""Gate for the v1 node-protocol conformance vectors (scripts/gen_conformance.py).

The Go pull-worker agent consumes the same JSON files, so these tests pin both that the
committed files are exactly what the Python reference generates and that every committed
verdict still holds when replayed through the reference functions.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance" / "v1"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_conformance", ROOT / "scripts" / "gen_conformance.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_conformance"] = mod
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def test_vectors_match_generator():
    expected = gen.generate()
    assert expected, "generator produced nothing"
    for rel, data in expected.items():
        committed = (VECTORS / rel).read_bytes()
        assert committed == data, f"{rel} drifted from the Python reference"


def test_committed_once_artifacts_verify():
    assert gen.verify_committed_once() == []


def test_sha256sums_cover_every_file():
    sums = {}
    for line in (VECTORS / "SHA256SUMS").read_text().splitlines():
        digest, _, rel = line.partition("  ")
        sums[rel] = digest
    files = {str(p.relative_to(VECTORS)) for p in VECTORS.rglob("*")
             if p.is_file() and p.name != "SHA256SUMS"}
    assert set(sums) == files
    for rel, digest in sums.items():
        assert hashlib.sha256((VECTORS / rel).read_bytes()).hexdigest() == digest, rel


def _verify(pem: str, payload_hex: str, sig_b64: str) -> None:
    pub = serialization.load_pem_public_key(pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.b64decode(sig_b64), bytes.fromhex(payload_hex),
               ec.ECDSA(hashes.SHA256()))


def test_ecdsa_cross_both_directions_verify():
    doc = _load("ecdsa_cross.json")
    assert doc["python_signed"], "python_signed must not be empty"
    negatives = [e for e in doc["python_signed"] if e.get("valid") is False]
    assert negatives, "python_signed needs a tampered-signature negative"
    assert not any(e.get("valid") is False for e in doc["go_signed"])
    for entry in doc["python_signed"] + doc["go_signed"]:
        if entry.get("valid", True):
            _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])
    from cryptography.exceptions import InvalidSignature
    for entry in negatives:
        with pytest.raises(InvalidSignature):
            _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])


def test_ecdsa_cross_rejects_tampered_payload():
    from cryptography.exceptions import InvalidSignature

    entry = next(e for e in _load("ecdsa_cross.json")["python_signed"] if e.get("valid", True))
    with pytest.raises(InvalidSignature):
        _verify(entry["public_key_pem"], entry["payload_hex"] + "00", entry["signature_b64"])


def test_challenge_verdicts_replay():
    from blastbox.host import node_auth

    doc = _load("challenge.json")
    secret = bytes.fromhex(doc["secret_hex"])
    for case in doc["cases"]:
        try:
            node_auth._check_challenge(case["challenge"], case["scope"], secret=secret,
                                       now=case["verify_at"])
            got = "ok"
        except node_auth.ClaimRefused as exc:
            got = gen.classify_refusal(str(exc))
        if got == "foreign_or_wrong_scope":      # the reference cannot tell these apart
            assert case["verdict"] in ("foreign", "wrong_scope"), case
        else:
            assert got == case["verdict"], case


def test_signing_payload_replay():
    from blastbox.host import node_auth

    for case in _load("signing_payload.json")["cases"]:
        got = node_auth.signing_payload(case["challenge"], case["scope"], case["node_id"])
        assert got.hex() == case["payload_hex"]


def test_node_cert_verdicts_replay():
    doc = _load("node_certs/cases.json")
    verdicts = {c["name"]: c["verdict"] for c in doc["cases"]}
    for name in ("v1_with_wg", "v2_without_wg"):
        assert verdicts[name] == "ok"
    for name in ("wrong_eku", "client_auth_eku", "node_plus_client_auth_eku", "cn_mismatch", "expired",
                 "missing_node_info", "garbled_node_info"):
        assert verdicts[name] == "refused", name
    assert any(c["name"] == "rsa_key" and c["admit"]["verdict"] == "refused"
               for c in doc["cases"])
