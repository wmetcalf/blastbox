"""The execution-receipt WIRE CONTRACT, shared by the signer and every verifier.

``blastbox.host.attest`` (the dispatcher that signs) and ``blastbox.client.verify`` (a consumer
that checks a receipt it fetched) both build on exactly these definitions, so the bytes one signs
are the bytes the other verifies. This module depends only on the standard library and
``cryptography``: it must stay importable from a lean install (``pip install
blastbox[verify]``), so it never imports anything under ``blastbox.host``.

    canonical(x) json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                 -- and NO FLOATS anywhere in x (canonical() raises)
    key_id       sha256(SubjectPublicKeyInfo DER).hexdigest()[:16]
    signature    base64url, padded, of DER ECDSA-P256-SHA256 over canonical(doc)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

#: The receipt format version this code signs and verifies.
VERSION = 1
#: The only signature algorithm: ECDSA over P-256 with SHA-256, DER-encoded.
ALG = "ES256"
#: Length of a key_id: the leading hex digits of sha256(SPKI DER).
KEY_ID_HEX_LEN = 16


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def _reject_floats(x: object, path: str = "$") -> None:
    if isinstance(x, float):
        raise TypeError(f"canonical(): float at {path} -- the signed form carries integers only")
    if isinstance(x, dict):
        for k, v in x.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(x, (list, tuple)):
        for i, v in enumerate(x):
            _reject_floats(v, f"{path}[{i}]")


def canonical(x: object) -> bytes:
    """The exact bytes that are signed. Part of the contract -- do not change."""
    _reject_floats(x)
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# ---------------------------------------------------------------------------
# Public key
# ---------------------------------------------------------------------------


def spki_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    """The key_id of ``public_key``: always RECOMPUTED from its SubjectPublicKeyInfo, never taken
    from what a key file or a receipt states."""
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()[:KEY_ID_HEX_LEN]


class VerifyKeyRefused(ValueError):
    """A ``--verify-key`` file is not a usable EC P-256 public key (or states a wrong key_id)."""


class _HasPrivateKey(Protocol):
    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey: ...


@dataclass(frozen=True)
class VerifyKey:
    """The PUBLIC half of an attest key: verifies receipts, cannot sign. What a host that does
    not hold a node's private key (the control plane) checks that node's receipts with."""

    public_key: ec.EllipticCurvePublicKey

    @property
    def key_id(self) -> str:
        return spki_key_id(self.public_key)

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @classmethod
    def from_attest_key(cls, key: _HasPrivateKey) -> VerifyKey:
        return cls(key.private_key.public_key())

    @classmethod
    def parse(cls, data: bytes, source: str = "verify key") -> VerifyKey:
        """A PEM SubjectPublicKeyInfo, or the JSON body ``GET /v1/attestation/key`` serves
        (``{"key_id", "alg", "public_key_pem"}``; a stated key_id/alg must match the PEM)."""
        stated: dict = {}
        text = data.strip()
        if text.startswith(b"{"):
            # Explicit checks, not asserts: they must survive python -O.
            try:
                stated = json.loads(text)
            except Exception as exc:  # noqa: BLE001 -- any parse problem is a refusal
                raise VerifyKeyRefused(
                    f"{source}: not a JSON key body with a public_key_pem") from exc
            pem = stated.get("public_key_pem") if isinstance(stated, dict) else None
            if not isinstance(pem, str):
                raise VerifyKeyRefused(f"{source}: not a JSON key body with a public_key_pem")
            try:
                text = pem.encode()
            except UnicodeEncodeError as exc:
                raise VerifyKeyRefused(f"{source}: public_key_pem is not valid text") from exc
        if text.count(b"-----BEGIN ") != 1:
            # load_pem_public_key reads the first block and silently drops the rest.
            raise VerifyKeyRefused(f"{source}: must hold exactly one PEM public key (one "
                                   "--verify-key per signing host)")
        try:
            pub = serialization.load_pem_public_key(text)
        except (ValueError, TypeError) as exc:
            raise VerifyKeyRefused(f"{source}: not a readable PEM public key") from exc
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
            raise VerifyKeyRefused(f"{source}: not an EC P-256 public key (alg is fixed at {ALG})")
        key = cls(pub)
        if "alg" in stated and stated["alg"] != ALG:
            raise VerifyKeyRefused(f"{source}: alg {stated['alg']!r} is not {ALG}")
        if "key_id" in stated and stated["key_id"] != key.key_id:
            raise VerifyKeyRefused(f"{source}: stated key_id {stated['key_id']!r} does not match "
                                   f"its public key (key_id {key.key_id})")
        return key


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


def signature_valid(public_key: ec.EllipticCurvePublicKey, doc: object, der: bytes) -> bool:
    """Whether ``der`` is a valid ES256 signature by ``public_key`` over ``canonical(doc)``.
    False for anything short of a clean verify -- including a ``doc`` canonical() refuses."""
    try:
        public_key.verify(der, canonical(doc), ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001 - anything short of a clean verify is "no"
        return False
    return True
