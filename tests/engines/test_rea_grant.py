from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from blastbox.engines.rea.grant import (
    Grant,
    GrantRejected,
    load_private_key,
    open_grant,
)

VEC = json.loads((Path(__file__).parent / "fixtures" / "rea_grant_vector.json").read_text())
NOW = 1_800_000_000


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


GW_PRIV = _b64d(VEC["gateway_private_key_b64url"])
GW_PUB = _b64d(VEC["gateway_public_key_b64url"])


def _seal(claims: dict, raw: bool = False) -> str:
    """Test-local sealer following the wire format."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    info = b"rea-model-grant/1"
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = eph.exchange(X25519PublicKey.from_public_bytes(GW_PUB))
    k = HKDF(hashes.SHA256(), 32, epk + GW_PUB, info).derive(shared)
    nonce = os.urandom(12)
    pt = json.dumps(claims, separators=(",", ":")).encode()
    return "g1." + _b64e(epk + nonce + AESGCM(k).encrypt(nonce, pt, info))


def _good() -> dict:
    return dict(VEC["claims"])


def test_opens_loadout_vector():
    g = open_grant(VEC["token"], GW_PRIV, NOW)
    c = VEC["claims"]
    assert (g.job, g.provider, g.model, g.key, g.exp) == (
        c["job"], c["provider"], c["model"], c["key"], c["exp"],
    )


def _flip(tok: str) -> str:
    raw = bytearray(_b64d(tok[3:]))
    raw[-20] ^= 1
    return "g1." + _b64e(bytes(raw))


def _wrong_key_token() -> str:
    return VEC["token"]


def _missing() -> dict:
    c = _good()
    del c["model"]
    return c


def _extra() -> dict:
    return {**_good(), "extra": 1}


CASES = {
    "no_prefix": (lambda: VEC["token"][3:], GW_PRIV),
    "bad_b64": (lambda: "g1.!!!not base64!!!", GW_PRIV),
    "truncated": (lambda: VEC["token"][:60], GW_PRIV),
    "flipped": (lambda: _flip(VEC["token"]), GW_PRIV),
    "wrong_key": (lambda: VEC["token"], bytes(range(1, 33))),
    "oversize": (lambda: "g1." + "A" * 4100, GW_PRIV),
    "bad_version": (lambda: _seal({**_good(), "v": 2}), GW_PRIV),
    "missing_claim": (lambda: _seal(_missing()), GW_PRIV),
    "extra_claim": (lambda: _seal(_extra()), GW_PRIV),
    "bad_provider": (lambda: _seal({**_good(), "provider": "other"}), GW_PRIV),
    "expired": (lambda: _seal({**_good(), "exp": NOW}), GW_PRIV),
    "exp_str": (lambda: _seal({**_good(), "exp": "1893456000"}), GW_PRIV),
    "exp_bool": (lambda: _seal({**_good(), "exp": True}), GW_PRIV),
    "v_bool": (lambda: _seal({**_good(), "v": True}), GW_PRIV),
    "key_not_str": (lambda: _seal({**_good(), "key": 5}), GW_PRIV),
    "not_object": (lambda: _seal([1, 2]), GW_PRIV),  # type: ignore[arg-type]
}


@pytest.mark.parametrize("name", list(CASES))
def test_rejects(name):
    make, priv = CASES[name]
    with pytest.raises(GrantRejected) as ei:
        open_grant(make(), priv, NOW)
    assert str(ei.value) == "grant rejected"


def test_bad_private_key_length_rejected():
    with pytest.raises(GrantRejected):
        open_grant(VEC["token"], b"short", NOW)


def test_repr_hides_key():
    g = open_grant(VEC["token"], GW_PRIV, NOW)
    assert VEC["claims"]["key"] not in repr(g)
    assert "key" not in repr(g)
    assert isinstance(g, Grant)


def test_private_key_file_mode(tmp_path):
    p = tmp_path / "k"
    p.write_text(VEC["gateway_private_key_b64url"] + "\n")
    p.chmod(0o644)
    with pytest.raises(ValueError):
        load_private_key(str(p))
    p.chmod(0o400)
    assert load_private_key(str(p)) == GW_PRIV
