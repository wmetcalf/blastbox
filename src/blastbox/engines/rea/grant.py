"""Open a per-job model grant sealed by Loadout to the gateway's X25519 key.

Wire format (shared with Loadout's sealer):
  token = "g1." + base64url_nopad(epk32 || nonce12 || ciphertext)
  k = HKDF-SHA256(ikm=X25519(gw_priv, epk), salt=epk32 || gw_pub32,
                  info=b"rea-model-grant/1", length=32)
  AES-256-GCM, aad=b"rea-model-grant/1", plaintext = compact JSON
  {v, job, provider, model, key, exp}.

``cryptography`` is a [host] extra and is imported only here.
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
from dataclasses import dataclass, field

GRANT_INFO = b"rea-model-grant/1"
MAX_GRANT_CHARS = 4096
_PROVIDERS = frozenset({"openrouter", "anthropic"})
_MAX_TTL = 172800
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_CLAIMS = frozenset({"v", "job", "provider", "model", "key", "exp"})


@dataclass(frozen=True)
class Grant:
    job: str
    provider: str
    model: str
    key: str = field(repr=False)
    exp: int


class GrantRejected(Exception):
    """Grant could not be opened; the message is fixed whatever the cause."""

    def __init__(self) -> None:
        super().__init__("grant rejected")


def _b64d(s: str) -> bytes:
    """Strict unpadded base64url: canonical encodings only."""
    if not _B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError
    out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(out).rstrip(b"=").decode("ascii") != s:
        raise ValueError
    return out


def _no_dup_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    d: dict[str, object] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError
        d[k] = v
    return d


def _clean(s: object) -> bool:
    return (
        isinstance(s, str)
        and s != ""
        and all(ord(c) >= 32 and ord(c) != 127 for c in s)
    )


def open_grant(token: str, private_key: bytes, now: int) -> Grant:
    grant: Grant | None = None
    try:
        grant = _open(token, private_key, now)
    except Exception:
        pass
    if grant is None:
        # Raised outside the except block so no frame data is chained.
        raise GrantRejected()
    return grant


def _open(token: str, private_key: bytes, now: int) -> Grant:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if not isinstance(token, str) or len(token) > MAX_GRANT_CHARS:
        raise ValueError
    if not token.startswith("g1."):
        raise ValueError
    raw = _b64d(token[3:])
    if len(raw) < 32 + 12 + 16:
        raise ValueError
    epk, nonce, ct = raw[:32], raw[32:44], raw[44:]
    if len(private_key) != 32:
        raise ValueError
    priv = X25519PrivateKey.from_private_bytes(private_key)
    gw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = priv.exchange(X25519PublicKey.from_public_bytes(epk))
    k = HKDF(hashes.SHA256(), 32, epk + gw_pub, GRANT_INFO).derive(shared)
    claims = json.loads(
        AESGCM(k).decrypt(nonce, ct, GRANT_INFO), object_pairs_hook=_no_dup_pairs
    )
    if not isinstance(claims, dict) or set(claims) != _CLAIMS:
        raise ValueError
    v, exp = claims["v"], claims["exp"]
    if type(v) is not int or v != 1 or type(exp) is not int or exp <= now or exp - now > _MAX_TTL:
        raise ValueError
    if claims["provider"] not in _PROVIDERS:
        raise ValueError
    for name in ("job", "provider", "model", "key"):
        if not _clean(claims[name]):
            raise ValueError
    return Grant(
        job=claims["job"],
        provider=claims["provider"],
        model=claims["model"],
        key=claims["key"],
        exp=exp,
    )


def _read_key_file(path: str) -> bytes | None:
    fd = -1
    try:
        fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            return None
        data = os.read(fd, 129)
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > 128 or any(b >= 128 for b in data):
        return None
    try:
        return _b64d(data.strip().decode("ascii"))
    except Exception:
        return None


def load_private_key(path: str) -> bytes:
    """Read base64url of 32 raw bytes from a private regular file."""
    key = _read_key_file(path)
    if key is None or len(key) != 32:
        raise ValueError("invalid private key file")
    return key
