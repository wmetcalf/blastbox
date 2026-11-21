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


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


NOW = VEC["claims"]["exp"] - 3600
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


def _mid_junk() -> str:
    t = VEC["token"]
    return t[:40] + "\n" + t[40:]


def _std_alphabet() -> str:
    # find a token whose body would differ in std alphabet: swap '-'/'_' for '+'/'/'
    body = VEC["token"][3:]
    assert "-" in body or "_" in body
    return "g1." + body.replace("-", "+").replace("_", "/")


@pytest.mark.parametrize(
    "make",
    [_mid_junk, _std_alphabet, lambda: VEC["token"] + "==", lambda: VEC["token"] + " "],
)
def test_rejects_malleable_encodings(make):
    with pytest.raises(GrantRejected):
        open_grant(make(), GW_PRIV, NOW)


def _raw(claims_json: bytes) -> str:
    return _seal_bytes(claims_json)


def _seal_bytes(pt: bytes) -> str:
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
    k = HKDF(hashes.SHA256(), 32, epk + GW_PUB, info).derive(
        eph.exchange(X25519PublicKey.from_public_bytes(GW_PUB))
    )
    nonce = os.urandom(12)
    return "g1." + _b64e(epk + nonce + AESGCM(k).encrypt(nonce, pt, info))


def _dup_keys() -> str:
    c = _good()
    body = json.dumps(c, separators=(",", ":"))
    return _seal_bytes(body[:-1].encode() + b',"model":"other"}')


@pytest.mark.parametrize(
    "make",
    [
        _dup_keys,
        lambda: _seal({**_good(), "exp": NOW + 172801}),
        lambda: _seal({**_good(), "key": ""}),
        lambda: _seal({**_good(), "job": ""}),
        lambda: _seal({**_good(), "model": ""}),
        lambda: _seal({**_good(), "key": "sk\nx"}),
        lambda: _seal({**_good(), "model": "a\x7fb"}),
        lambda: _seal({**_good(), "job": "a\x00b"}),
    ],
)
def test_rejects_claim_hardening(make):
    with pytest.raises(GrantRejected):
        open_grant(make(), GW_PRIV, NOW)


def test_exp_at_two_day_limit_ok():
    assert open_grant(_seal({**_good(), "exp": NOW + 172800}), GW_PRIV, NOW)


def test_grant_rejected_has_no_context():
    with pytest.raises(GrantRejected) as ei:
        open_grant(_seal_bytes(b"{not json"), GW_PRIV, NOW)
    assert ei.value.__context__ is None
    assert ei.value.__cause__ is None


def test_key_file_symlink_refused(tmp_path):
    real = tmp_path / "real"
    real.write_text(VEC["gateway_private_key_b64url"])
    real.chmod(0o400)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        load_private_key(str(link))


def test_key_file_fifo_refused_without_blocking(tmp_path):
    p = tmp_path / "fifo"
    os.mkfifo(p, 0o600)
    with pytest.raises(ValueError):
        load_private_key(str(p))


def _key_file(tmp_path, data: bytes):
    p = tmp_path / f"k{len(list(tmp_path.iterdir()))}"
    p.write_bytes(data)
    p.chmod(0o400)
    return str(p)


def test_key_file_oversize_refused(tmp_path):
    with pytest.raises(ValueError):
        load_private_key(_key_file(tmp_path, b"A" * 500))


def test_key_file_junk_in_base64_refused(tmp_path):
    good = VEC["gateway_private_key_b64url"].encode()
    with pytest.raises(ValueError):
        load_private_key(_key_file(tmp_path, good[:10] + b"!" + good[10:]))
    with pytest.raises(ValueError):
        load_private_key(_key_file(tmp_path, good + b"="))


def test_key_file_raw_binary_refused_without_leak(tmp_path):
    raw = bytes(range(128, 160))
    with pytest.raises(ValueError) as ei:
        load_private_key(_key_file(tmp_path, raw))
    e = ei.value
    assert e.__context__ is None and e.__cause__ is None
    assert not hasattr(e, "object")
    assert raw.decode("latin-1") not in str(e)
