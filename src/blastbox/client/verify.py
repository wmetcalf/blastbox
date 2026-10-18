"""Client-side verification of blastbox execution receipts.

A consumer that submits a file to a blastbox ingress (``POST /v1/jobs``) and acts on the result
(``GET /v1/jobs/{id}/metadata``) uses this module to prove that the result was sealed by a
dispatcher whose key it PINNED, for THIS job, over THESE input bytes, and that the metadata
bytes it is about to act on are exactly the bytes that dispatcher signed.

    keys = load_pinned_keys(Path("dispatcher-a.pem"), Path("dispatcher-b.json"))
    receipt = verify_receipt(attestation_body_bytes, keys=keys, expect_job_id=job_id,
                             expect_input_sha256=hashlib.sha256(submitted).hexdigest(),
                             metadata_bytes=metadata_body_bytes)

or, fetching both over HTTP(S) with nothing but the standard library:

    result = fetch_and_verify("https://ingress.example", job_id, keys=keys,
                              expect_input_sha256=...)
    act_on(result.metadata)        # the exact bytes the receipt's metadata_sha256 signs

Every check fails CLOSED with a typed :class:`ReceiptError` subclass carrying a stable ``code``.
A key is trusted only because the caller pinned it: a receipt naming a key_id that is not pinned
fails (:class:`UnknownSigningKey`); nothing here fetches a key and trusts it. Key ids are always
RECOMPUTED from the public key (sha256 of its SubjectPublicKeyInfo), never taken from a key file,
a JSON body or the receipt.

What a verified receipt proves and does not prove is spelled out in docs/CONFIGURATION.md
("Verifying results (clients)"). In short: the holder of the pinned key observed this run and
sealed these metadata bytes; the detections inside are still the worker's account; and the
network posture is attested ONLY when the receipt carries it (:attr:`VerifiedReceipt.network`
is ``None`` otherwise -- "not attested", never "no network").

This module imports only the standard library, ``cryptography`` and :mod:`blastbox.attest_wire`
(install with ``pip install 'blastbox[verify]'``); it never imports the host stack.
"""
from __future__ import annotations

import base64
import dataclasses
import functools
import hashlib
import http.client
import json
import math
import os
import re
import socket
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn

try:
    from cryptography.hazmat.primitives import serialization
except ImportError as _exc:  # pragma: no cover - exercised only on an install without the extra
    raise ImportError("blastbox.client.verify needs the `cryptography` package: install "
                      "blastbox with the verify extra (pip install 'blastbox[verify]')") from _exc

from blastbox.attest_wire import (
    ALG,
    KEY_ID_HEX_LEN,
    VERSION,
    VerifyKey,
    VerifyKeyRefused,
    canonical,
    is_p256_public_key,
    signature_valid,
)

__all__ = [
    "ALG",
    "VERSION",
    "AttestedNetwork",
    "BadSignature",
    "FetchError",
    "KeyIdCollision",
    "NoReceipt",
    "PinnedKeys",
    "ReceiptError",
    "ReceiptMalformed",
    "ReceiptMismatch",
    "UnknownSigningKey",
    "UnsupportedReceipt",
    "VerifiedReceipt",
    "VerifiedResult",
    "VerifyKey",
    "VerifyKeyRefused",
    "canonical",
    "fetch_and_verify",
    "load_pinned_keys",
    "verify_receipt",
]

#: The most of a receipt body this verifier parses. Matches the ingress's own read cap: a body
#: past it is never one the ingress serves.
RECEIPT_MAX_BYTES = 1 << 20
#: The most of a key file :func:`load_pinned_keys` reads. A PEM public key is ~180 bytes.
KEY_FILE_MAX_BYTES = 64 << 10
#: Default cap on the metadata.json :func:`fetch_and_verify` downloads (the ingress's envelope
#: floor; raise it with ``max_metadata_bytes`` when the deployment's BLASTBOX_MAX_METADATA is
#: higher).
DEFAULT_METADATA_MAX_BYTES = 64 << 20
#: Default per-request budget, in seconds, for :func:`fetch_and_verify`.
DEFAULT_TIMEOUT_S = 30.0
#: How far a receipt's issued_at_ms may lie in the verifier's future when ``max_age`` is checked.
DEFAULT_MAX_CLOCK_SKEW_S = 300.0
#: The most of an HTTP error body read for its ``detail``.
_ERROR_BODY_MAX_BYTES = 4096
#: Integer fields are epoch milliseconds; anything outside this is not one.
_MAX_TIMESTAMP_MS = (1 << 63) - 1

_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(rf"[0-9a-f]{{{KEY_ID_HEX_LEN}}}")
_B64URL_PADDED = re.compile(r"(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?")
# `blastbox attest-key` prints "key_id: <hex>" and "alg: ES256" above the PEM.
_STATED_KEY_ID = re.compile(rb"^\s*key_id:\s*(\S*)\s*$", re.MULTILINE)
_STATED_ALG = re.compile(rb"^\s*alg:\s*(\S*)\s*$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


class ReceiptError(Exception):
    """The result could NOT be verified. Every failure of :func:`verify_receipt` and
    :func:`fetch_and_verify` is one of these subclasses; ``code`` is a stable machine-readable
    string, ``str(exc)`` a human explanation. Any text in it that came from the server (a 404's
    detail, a tombstone's reason) is UNAUTHENTICATED and has been sanitised for display."""

    code = "error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class NoReceipt(ReceiptError):
    """There is no receipt to verify: a 404 from the attestation route (unknown job, keyless
    dispatcher, FAILED job, withheld receipt...; ``code`` "no_receipt"), a tombstone (``code`` "tombstone") or an expired result
    (``code`` "expired", 410). ``reason`` is the server's stated reason, if any --
    unauthenticated, for display only."""

    code = "no_receipt"

    def __init__(self, message: str, *, reason: str | None = None,
                 code: str | None = None) -> None:
        super().__init__(message, code=code)
        self.reason = reason


class FetchError(ReceiptError):
    """:func:`fetch_and_verify` could not fetch what it verifies. ``retryable`` is True for the
    transient cases (409 job not terminal yet, 429/5xx, network errors, timeouts); False for
    the rest (401/403, a redirect, a response over its size cap, another status). Either way
    NOTHING was verified."""

    code = "fetch_failed"

    def __init__(self, message: str, *, code: str | None = None, retryable: bool = False,
                 status: int | None = None) -> None:
        super().__init__(message, code=code)
        self.retryable = retryable
        self.status = status


class ReceiptMalformed(ReceiptError):
    """Not a well-formed v1 receipt body: not strict JSON (duplicate keys, floats, NaN), over
    the size cap, a missing/unknown/mistyped field, or an undecodable signature."""

    code = "malformed"


class UnsupportedReceipt(ReceiptMalformed):
    """A receipt version or algorithm this verifier does not implement."""

    code = "unsupported"


class UnknownSigningKey(ReceiptError):
    """The receipt names a key_id that is not pinned. Never resolved by fetching a key."""

    code = "unknown_key"

    def __init__(self, message: str, *, key_id: str) -> None:
        super().__init__(message)
        self.key_id = key_id


class BadSignature(ReceiptError):
    """The signature does not verify under the pinned key the receipt names: the body was
    altered, or it was signed by a different key claiming that key_id."""

    code = "bad_signature"


class ReceiptMismatch(ReceiptError):
    """A validly signed receipt that does not vouch for what the caller expected. ``code`` names
    the check: ``job_id_mismatch``, ``input_mismatch``, ``metadata_mismatch``,
    ``engine_mismatch``, ``status_not_done``, ``stale``, ``issued_in_future``."""

    code = "mismatch"


class KeyIdCollision(VerifyKeyRefused):
    """Two DIFFERENT public keys share one key_id. A receipt names its signer by key_id, so
    pinning both would leave the choice of key to whoever made the collision."""


# ---------------------------------------------------------------------------
# Pinned keys
# ---------------------------------------------------------------------------


def _spki_der(key: VerifyKey) -> bytes:
    return key.public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class PinnedKeys(Mapping[str, VerifyKey]):
    """An immutable set of trusted verify keys, indexed by their RECOMPUTED key_id.

    The same key given twice is kept once; two different keys under one key_id raise
    :class:`KeyIdCollision`. Build it with :func:`load_pinned_keys`, or directly from
    :class:`VerifyKey` objects."""

    __slots__ = ("_by_id",)

    def __init__(self, keys: Iterable[VerifyKey] = ()) -> None:
        if isinstance(keys, (str, bytes, bytearray, VerifyKey)):
            raise TypeError("PinnedKeys takes an iterable of VerifyKey objects")
        by_id: dict[str, VerifyKey] = {}
        for key in keys:
            if not isinstance(key, VerifyKey):
                raise TypeError(f"PinnedKeys: expected VerifyKey, got {type(key).__name__}")
            if not is_p256_public_key(key.public_key):
                # VerifyKey checks this on construction; re-checked here because a frozen
                # dataclass can still be mutated with object.__setattr__.
                raise VerifyKeyRefused("PinnedKeys: not an EC P-256 public key (alg is fixed "
                                       f"at {ALG})")
            key_id = key.key_id
            prev = by_id.get(key_id)
            if prev is None:
                by_id[key_id] = key
            elif _spki_der(prev) != _spki_der(key):
                raise KeyIdCollision(f"two different public keys share key_id {key_id}; "
                                     "refusing to pin either")
        self._by_id = by_id

    def __getitem__(self, key_id: str) -> VerifyKey:
        return self._by_id[key_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_id)

    def __len__(self) -> int:
        return len(self._by_id)

    def __repr__(self) -> str:
        return f"PinnedKeys({sorted(self._by_id)!r})"


KeySource = VerifyKey | os.PathLike[str] | bytes | str | Mapping[str, object]


def _read_key_file(path: Path) -> bytes:
    """A key file's bytes: a regular file, at most KEY_FILE_MAX_BYTES. O_NONBLOCK so a FIFO
    given by mistake is refused rather than blocking forever."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        raise VerifyKeyRefused(f"{path}: cannot read ({exc.strerror or exc})") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise VerifyKeyRefused(f"{path}: not a regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            if total > KEY_FILE_MAX_BYTES:
                raise VerifyKeyRefused(f"{path}: larger than {KEY_FILE_MAX_BYTES} bytes; not a "
                                       "public key file")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise VerifyKeyRefused(f"{path}: cannot read ({exc.strerror or exc})") from exc
    finally:
        os.close(fd)


def _parse_key_text(data: bytes, source: str) -> VerifyKey:
    key = VerifyKey.parse(data, source)
    if not data.lstrip().startswith(b"{"):
        # The `blastbox attest-key` printout states the key_id/alg above the PEM. When present
        # they must agree with the key -- a mismatch means the file was pasted together wrongly.
        stated_ids = _STATED_KEY_ID.findall(data)
        if any(s.decode("ascii", "replace") != key.key_id for s in stated_ids):
            raise VerifyKeyRefused(f"{source}: a stated key_id does not match its public key "
                                   f"(key_id {key.key_id})")
        if any(s != ALG.encode() for s in _STATED_ALG.findall(data)):
            raise VerifyKeyRefused(f"{source}: a stated alg is not {ALG}")
    return key


def _load_one(source: object, index: int) -> VerifyKey:
    if isinstance(source, VerifyKey):
        return source
    if isinstance(source, os.PathLike):
        path = Path(source)
        return _parse_key_text(_read_key_file(path), str(path))
    label = f"key #{index + 1}"
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _parse_key_text(bytes(source), label)
    if isinstance(source, str):
        stripped = source.strip()
        if "-----BEGIN " not in stripped and not stripped.startswith("{"):
            raise VerifyKeyRefused(f"{label}: a str is key TEXT (PEM, `blastbox attest-key` "
                                   "output, or the /v1/attestation/key JSON body); pass a key "
                                   "file as pathlib.Path")
        try:
            data = source.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VerifyKeyRefused(f"{label}: not valid text") from exc
        return _parse_key_text(data, label)
    if isinstance(source, Mapping):
        try:
            data = json.dumps(dict(source)).encode()
        except (TypeError, ValueError) as exc:
            raise VerifyKeyRefused(f"{label}: not a /v1/attestation/key JSON body") from exc
        return VerifyKey.parse(data, label)
    raise TypeError(f"{label}: unsupported key source type {type(source).__name__} (PEM/JSON "
                    "text as str or bytes, a pathlib.Path, a parsed JSON key body, or a "
                    "VerifyKey)")


def load_pinned_keys(*sources: KeySource) -> PinnedKeys:
    """Build the trusted key set from out-of-band sources, each one of:

    * a :class:`pathlib.Path` (any ``os.PathLike``) to a key file -- a PEM public key, the
      output of ``blastbox attest-key`` saved as-is, or the JSON body of
      ``GET /v1/attestation/key``;
    * that same content as ``str`` or ``bytes`` (a ``str`` is never treated as a path);
    * the parsed JSON body (a mapping with ``public_key_pem``);
    * a :class:`VerifyKey`.

    Every key must be EC P-256. Its key_id is recomputed from the key; a key_id (or alg) a source
    states must match or the source is refused. Raises :class:`VerifyKeyRefused` (or its
    subclass :class:`KeyIdCollision` for two different keys under one key_id); never returns an
    empty set."""
    if not sources:
        raise VerifyKeyRefused("no keys given: pin at least one dispatcher public key")
    return PinnedKeys(_load_one(src, i) for i, src in enumerate(sources))


def _as_pinned(keys: object) -> PinnedKeys:
    if isinstance(keys, PinnedKeys):
        pinned = keys
    elif isinstance(keys, VerifyKey):
        pinned = PinnedKeys([keys])
    elif isinstance(keys, (str, bytes, bytearray, Mapping)) or not isinstance(keys, Iterable):
        raise TypeError("keys must be PinnedKeys (see load_pinned_keys), a VerifyKey, or an "
                        "iterable of VerifyKey")
    else:
        pinned = PinnedKeys(keys)
    if not pinned:
        raise VerifyKeyRefused("no keys pinned: nothing can be verified")
    return pinned


# ---------------------------------------------------------------------------
# The verified receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestedNetwork:
    """The network posture the signing dispatcher ENFORCED (and, for a containment claim,
    verified) for this run. Only present when the receipt carries it."""

    #: The personality name the dispatcher enforced (``net_policy_effective``).
    policy_effective: str
    #: The exit driver actually applied (``net_exit``: "none", "direct", "inetsim", ...). The
    #: name is operator-defined, so interpret it against the signing host's configuration.
    #: ``None`` only if the signer stated no exit.
    exit: str | None
    #: True when the applied network args failed the run CLOSED to --network=none.
    downgraded: bool
    #: True when the run was routed through the TLS-MITM inspect gateway.
    inspect: bool


@dataclass(frozen=True)
class VerifiedReceipt:
    """A receipt whose signature verified under a pinned key and whose bindings held.

    Every field is signed. ``network`` is ``None`` when the receipt carries no network posture:
    that means NOT ATTESTED (the signer did not enforce/verify it -- every remote/VM tier, or a
    containment it could not verify), never "no network"."""

    job_id: str
    engine: str
    status: str
    key_id: str
    host: str
    executor: str
    input_sha256: str
    metadata_sha256: str
    worker_runtime: str | None
    worker_tier: str | None
    started_at_ms: int
    finished_at_ms: int
    issued_at_ms: int
    network: AttestedNetwork | None
    #: Whether input_sha256 was checked against the caller's expected hash.
    input_bound: bool
    #: Whether metadata_sha256 was checked against the caller's metadata bytes.
    metadata_bound: bool
    #: The exact signed document (read-only).
    signed: Mapping[str, object] = field(repr=False, compare=False, hash=False)

    @property
    def network_attested(self) -> bool:
        return self.network is not None

    def as_dict(self) -> dict[str, object]:
        """JSON-friendly view. ``network`` is ``null`` when NOT attested."""
        net = self.network
        return {
            "verified": True,
            "job_id": self.job_id,
            "engine": self.engine,
            "status": self.status,
            "key_id": self.key_id,
            "host": self.host,
            "executor": self.executor,
            "input_sha256": self.input_sha256,
            "input_bound": self.input_bound,
            "metadata_sha256": self.metadata_sha256,
            "metadata_bound": self.metadata_bound,
            "worker_runtime": self.worker_runtime,
            "worker_tier": self.worker_tier,
            "started_at_ms": self.started_at_ms,
            "finished_at_ms": self.finished_at_ms,
            "issued_at_ms": self.issued_at_ms,
            "network_attested": net is not None,
            "network": None if net is None else {
                "policy_effective": net.policy_effective,
                "exit": net.exit,
                "downgraded": net.downgraded,
                "inspect": net.inspect,
            },
        }


@dataclass(frozen=True)
class VerifiedResult:
    """What :func:`fetch_and_verify` returns: the verified receipt and the metadata.json bytes
    whose sha256 it signs. Act on ``metadata`` -- not on a separate fetch."""

    receipt: VerifiedReceipt
    metadata: bytes = field(repr=False)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _shown(value: object, limit: int = 120) -> str:
    """Untrusted text made safe to print: ASCII, no control characters, bounded."""
    text = value if isinstance(value, str) else repr(value)
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    text = "".join(c if " " <= c <= "~" else "?" for c in text)
    return text if len(text) <= limit else text[:limit] + "..."


class _DuplicateKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateKey(f"duplicate key {_shown(k)}")
        out[k] = v
    return out


def _no_float(text: str) -> NoReturn:
    raise ValueError(f"non-integer number {_shown(text)} (the signed form carries integers only)")


def _no_constant(text: str) -> NoReturn:
    raise ValueError(f"{_shown(text)} is not JSON")


def _strict_loads(data: bytes | str) -> object:
    """Strict JSON: UTF-8 only, no duplicate keys, no floats/exponents, no NaN/Infinity."""
    if isinstance(data, bytes):
        if len(data) > RECEIPT_MAX_BYTES:
            raise ReceiptMalformed(f"receipt body is larger than {RECEIPT_MAX_BYTES} bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReceiptMalformed("receipt body is not UTF-8") from exc
    else:
        text = data
        if len(text) > RECEIPT_MAX_BYTES:
            raise ReceiptMalformed(f"receipt body is larger than {RECEIPT_MAX_BYTES} bytes")
    try:
        return json.loads(text, object_pairs_hook=_strict_object, parse_float=_no_float,
                          parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise ReceiptMalformed(f"receipt body is not strict JSON: {_shown(exc)}") from exc


_STR: tuple[type, ...] = (str,)
_OPT_STR: tuple[type, ...] = (str, type(None))
#: Every field a v1 receipt carries (build_receipt), and its type. ``int`` means a real int,
#: never a bool.
_REQUIRED_FIELDS: dict[str, type | tuple[type, ...]] = {
    "v": int, "alg": _STR, "key_id": _STR, "host": _STR, "job_id": _STR, "engine": _STR,
    "status": _STR, "executor": _STR, "input_sha256": _STR, "metadata_sha256": _STR,
    "worker_runtime": _OPT_STR, "worker_tier": _OPT_STR,
    "started_at_ms": int, "finished_at_ms": int, "issued_at_ms": int,
}
#: Present only where the signer enforced the posture, and then together.
_NET_FIELDS = ("net_policy_effective", "net_exit", "net_downgraded", "net_inspect")


def _check_doc(doc: Mapping[str, object]) -> dict[str, object]:
    """Validate a v1 receipt document's shape (after v/alg). Returns a plain dict copy."""
    for k in doc:
        if not isinstance(k, str):
            raise ReceiptMalformed(f"receipt field name {_shown(k)} is not a string")
    unknown = set(doc) - set(_REQUIRED_FIELDS) - set(_NET_FIELDS)
    if unknown:
        raise ReceiptMalformed(
            f"receipt v{VERSION} carries unknown field(s) "
            f"{', '.join(_shown(k, 40) for k in sorted(unknown))}; this verifier knows only the "
            f"v{VERSION} fields and refuses what it cannot interpret")
    for name, kind in _REQUIRED_FIELDS.items():
        if name not in doc:
            raise ReceiptMalformed(f"receipt is missing {name}")
        value = doc[name]
        if kind is int:
            if type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP_MS:
                raise ReceiptMalformed(f"receipt field {name} is not a non-negative integer")
        elif not isinstance(value, kind):
            raise ReceiptMalformed(f"receipt field {name} has the wrong type")
    for name in ("input_sha256", "metadata_sha256"):
        if not _HEX64.fullmatch(str(doc[name])):
            raise ReceiptMalformed(f"receipt field {name} is not 64 lowercase hex digits")
    if "net_policy_effective" in doc:
        if not isinstance(doc["net_policy_effective"], str):
            raise ReceiptMalformed("receipt field net_policy_effective is not a string")
        if "net_exit" not in doc:
            raise ReceiptMalformed("receipt carries net_policy_effective without net_exit")
        if not isinstance(doc["net_exit"], _OPT_STR):
            raise ReceiptMalformed("receipt field net_exit has the wrong type")
        for flag in ("net_downgraded", "net_inspect"):
            # The signer writes these only as `true`, only when they hold.
            if flag in doc and doc[flag] is not True:
                raise ReceiptMalformed(f"receipt field {flag} is present but not true")
    else:
        stray = [n for n in _NET_FIELDS if n in doc]
        if stray:
            raise ReceiptMalformed(f"receipt carries {stray[0]} without net_policy_effective")
    return dict(doc)


def _decode_signature(sig: str) -> bytes:
    # Strict, padded base64url -- exactly what the signer emits. A lenient decoder drops
    # characters outside the alphabet, so two different strings would verify as one.
    # Non-zero trailing bits are refused too (the round trip), so each signature has exactly one
    # accepted spelling.
    if not sig or not _B64URL_PADDED.fullmatch(sig):
        raise ReceiptMalformed("receipt signature is not padded base64url")
    der = base64.urlsafe_b64decode(sig)
    if base64.urlsafe_b64encode(der).decode("ascii") != sig:
        raise ReceiptMalformed("receipt signature is not canonical base64url")
    return der


def _parse_body(attestation_response: object) -> tuple[dict[str, object], str]:
    """The receipt body -> (doc, signature). Tombstones raise NoReceipt."""
    if isinstance(attestation_response, (bytes, bytearray, memoryview)):
        body = _strict_loads(bytes(attestation_response))
    elif isinstance(attestation_response, str):
        body = _strict_loads(attestation_response)
    elif isinstance(attestation_response, Mapping):
        body = attestation_response
    else:
        raise TypeError("attestation_response must be the response body (bytes or str) or its "
                        "parsed JSON object")
    if not isinstance(body, Mapping):
        raise ReceiptMalformed("receipt body is not a JSON object")
    if "attestation" in body and body["attestation"] is None:
        # A TOMBSTONE: the finalizing dispatcher stored no receipt for this result and said why.
        # The reason is unauthenticated (it is not signed).
        reason = body.get("reason")
        shown = _shown(reason) if isinstance(reason, str) else None
        raise NoReceipt("no execution receipt: the result carries a tombstone"
                        + (f" (stated reason, unauthenticated: {shown})" if shown else ""),
                        reason=shown, code="tombstone")
    if set(body) != {"attestation", "signature"}:
        raise ReceiptMalformed("receipt body must hold exactly 'attestation' and 'signature'")
    doc, sig = body["attestation"], body["signature"]
    if not isinstance(doc, Mapping):
        raise ReceiptMalformed("receipt 'attestation' is not a JSON object")
    if not isinstance(sig, str):
        raise ReceiptMalformed("receipt 'signature' is not a string")
    return dict(doc), sig


def _seconds(value: float | int | timedelta, name: str) -> float:
    if isinstance(value, timedelta):
        secs = value.total_seconds()
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        secs = float(value)
    else:
        raise TypeError(f"{name} must be seconds (int/float) or a timedelta")
    if not secs >= 0:  # also rejects NaN
        raise ValueError(f"{name} must be >= 0")
    return secs


def _expected_input(expect_input_sha256: object) -> str | None:
    if expect_input_sha256 is None:
        return None
    if not isinstance(expect_input_sha256, str) or not _HEX64.fullmatch(
            expect_input_sha256.lower()):
        raise ValueError("expect_input_sha256 must be a sha256 hex digest")
    return expect_input_sha256.lower()


def _check_engine(expect_engine: object) -> None:
    if expect_engine is not None and (not isinstance(expect_engine, str) or not expect_engine):
        raise ValueError("expect_engine must be a non-empty engine name")


def _check_age(issued_ms: int, max_age_s: float, skew_s: float, now_ms: int | None) -> None:
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    age_ms = now - issued_ms
    if age_ms > max_age_s * 1000:
        raise ReceiptMismatch(f"receipt was issued {age_ms // 1000}s ago, older than "
                              f"max_age {max_age_s:g}s", code="stale")
    if -age_ms > skew_s * 1000:
        raise ReceiptMismatch(f"receipt issued_at_ms is {-age_ms // 1000}s in the future "
                              f"(beyond the {skew_s:g}s clock-skew allowance)",
                              code="issued_in_future")


def _check_metadata(signed_sha256: str, held_sha256: str) -> None:
    if signed_sha256 != held_sha256:
        raise ReceiptMismatch(f"receipt metadata_sha256 {signed_sha256} is not the sha256 of "
                              f"the metadata bytes held ({held_sha256})",
                              code="metadata_mismatch")


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_receipt(
    attestation_response: bytes | str | Mapping[str, object],
    *,
    keys: PinnedKeys | VerifyKey | Iterable[VerifyKey],
    expect_job_id: str,
    expect_input_sha256: str | None = None,
    metadata_bytes: bytes | None = None,
    expect_engine: str | None = None,
    max_age: float | timedelta | None = None,
    max_clock_skew: float | timedelta = DEFAULT_MAX_CLOCK_SKEW_S,
    now_ms: int | None = None,
) -> VerifiedReceipt:
    """Verify the body of ``GET /v1/jobs/{id}/attestation`` and bind it to what the caller knows.

    ``attestation_response`` should be the raw response BYTES: only then can duplicate keys be
    refused (a parsed mapping has already lost them). In order, it checks:

    1. strict JSON, exactly ``{"attestation": {...}, "signature": "..."}``; a tombstone
       (``{"attestation": null, ...}``) raises :class:`NoReceipt`;
    2. ``v`` == 1 and ``alg`` == "ES256" (:class:`UnsupportedReceipt`);
    3. the receipt's ``key_id`` names a PINNED key (:class:`UnknownSigningKey`);
    4. the exact v1 field set and types (:class:`ReceiptMalformed`);
    5. the ES256 signature over ``canonical(attestation)`` under that pinned key
       (:class:`BadSignature`);
    6. ``status == "done"``, ``job_id == expect_job_id``, and -- when given -- ``engine ==
       expect_engine``, ``input_sha256 == expect_input_sha256`` (the sha256 of the bytes the
       caller SUBMITTED), ``metadata_sha256 == sha256(metadata_bytes)`` (the exact metadata.json
       bytes the caller fetched and will act on), and ``issued_at_ms`` no older than
       ``max_age`` and no more than ``max_clock_skew`` in the future (:class:`ReceiptMismatch`).

    Pass ``metadata_bytes`` whenever you act on the metadata: without it the receipt says
    nothing about the payload you hold (``metadata_bound`` is then False). ``now_ms`` overrides
    the clock (tests). Argument errors raise TypeError/ValueError/VerifyKeyRefused."""
    pinned = _as_pinned(keys)
    if not isinstance(expect_job_id, str) or not expect_job_id:
        raise ValueError("expect_job_id must be the non-empty job id you submitted")
    want_input = _expected_input(expect_input_sha256)
    want_metadata = None
    if metadata_bytes is not None:
        if not isinstance(metadata_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("metadata_bytes must be the raw bytes of metadata.json")
        want_metadata = hashlib.sha256(metadata_bytes).hexdigest()
    _check_engine(expect_engine)
    max_age_s = None if max_age is None else _seconds(max_age, "max_age")
    skew_s = _seconds(max_clock_skew, "max_clock_skew")
    if now_ms is not None and type(now_ms) is not int:
        raise TypeError("now_ms must be an int (epoch milliseconds)")

    doc, sig = _parse_body(attestation_response)

    v, alg = doc.get("v"), doc.get("alg")
    if type(v) is not int or v != VERSION:
        raise UnsupportedReceipt(f"receipt version {_shown(v)} is not supported (this verifier "
                                 f"implements v{VERSION})")
    if alg != ALG:
        raise UnsupportedReceipt(f"receipt alg {_shown(alg)} is not {ALG}")
    key_id = doc.get("key_id")
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise ReceiptMalformed(f"receipt key_id is not {KEY_ID_HEX_LEN} lowercase hex digits")
    key = pinned.get(key_id)
    if key is None:
        raise UnknownSigningKey(f"receipt is signed by key_id {key_id}, which is not pinned "
                                f"(pinned: {', '.join(sorted(pinned))})", key_id=key_id)
    doc = _check_doc(doc)
    der = _decode_signature(sig)
    if not signature_valid(key.public_key, doc, der):
        raise BadSignature(f"receipt signature does not verify under pinned key {key_id}")
    if key.key_id != key_id:  # PinnedKeys indexes by the recomputed id; belt and braces
        raise BadSignature("pinned key index is inconsistent")

    # --- signed; now bind it to what the caller knows -------------------------------------
    if doc["status"] != "done":
        raise ReceiptMismatch(f"receipt status is {_shown(doc['status'])}, not done",
                              code="status_not_done")
    if doc["job_id"] != expect_job_id:
        raise ReceiptMismatch(f"receipt is for job {_shown(doc['job_id'])}, not "
                              f"{_shown(expect_job_id)}", code="job_id_mismatch")
    if expect_engine is not None and doc["engine"] != expect_engine:
        raise ReceiptMismatch(f"receipt engine is {_shown(doc['engine'])}, not "
                              f"{_shown(expect_engine)}", code="engine_mismatch")
    if want_input is not None and doc["input_sha256"] != want_input:
        raise ReceiptMismatch(f"receipt input_sha256 {doc['input_sha256']} is not the sha256 of "
                              f"the submitted input ({want_input})", code="input_mismatch")
    if want_metadata is not None:
        _check_metadata(str(doc["metadata_sha256"]), want_metadata)
    def _int(name: str) -> int:
        value = doc[name]
        if type(value) is not int:  # checked by _check_doc; never an assert (python -O)
            raise ReceiptMalformed(f"receipt field {name} is not an integer")
        return value

    issued = _int("issued_at_ms")
    if max_age_s is not None:
        _check_age(issued, max_age_s, skew_s, now_ms)

    network = None
    if "net_policy_effective" in doc:
        net_exit = doc["net_exit"]
        network = AttestedNetwork(
            policy_effective=str(doc["net_policy_effective"]),
            exit=None if net_exit is None else str(net_exit),
            downgraded=doc.get("net_downgraded") is True,
            inspect=doc.get("net_inspect") is True,
        )

    def _opt(name: str) -> str | None:
        value = doc[name]
        return None if value is None else str(value)

    return VerifiedReceipt(
        job_id=str(doc["job_id"]),
        engine=str(doc["engine"]),
        status=str(doc["status"]),
        key_id=key_id,
        host=str(doc["host"]),
        executor=str(doc["executor"]),
        input_sha256=str(doc["input_sha256"]),
        metadata_sha256=str(doc["metadata_sha256"]),
        worker_runtime=_opt("worker_runtime"),
        worker_tier=_opt("worker_tier"),
        started_at_ms=_int("started_at_ms"),
        finished_at_ms=_int("finished_at_ms"),
        issued_at_ms=_int("issued_at_ms"),
        network=network,
        input_bound=want_input is not None,
        metadata_bound=want_metadata is not None,
        signed=MappingProxyType(doc),
    )


# ---------------------------------------------------------------------------
# Fetch (stdlib only)
# ---------------------------------------------------------------------------


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """The ingress never redirects these routes. Following one could hand the bearer token to
    another origin or downgrade https; returning None makes urllib raise the 3xx as an
    HTTPError, which is then refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _base_url(base_url: str) -> str:
    if not isinstance(base_url, str):
        raise TypeError("base_url must be a str")
    parts = urllib.parse.urlsplit(base_url.strip())
    if parts.scheme not in ("http", "https"):
        raise ValueError("base_url must be an http:// or https:// URL")
    if not parts.hostname:
        raise ValueError("base_url has no host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("base_url must not carry credentials; pass token= instead")
    if parts.query or parts.fragment:
        raise ValueError("base_url must not carry a query or fragment")
    try:
        port = parts.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError as exc:
        raise ValueError("base_url has an invalid port (must be 1-65535)") from exc
    if port == 0:
        raise ValueError("base_url has an invalid port (must be 1-65535)")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def _canonical_job_id(job_id: str) -> str:
    try:
        canon = str(uuid.UUID(job_id)) if isinstance(job_id, str) else None
    except ValueError:
        canon = None
    if canon is None or canon != job_id:
        raise ValueError("job_id must be the job's id as the ingress returned it (a lowercase, "
                         "hyphenated UUID)")
    return job_id


class _Deadline:
    """One request's TOTAL wall-clock budget. Every socket the request opens is registered; when
    the budget runs out a watchdog shuts them down, so a read blocked in recv() -- on headers or
    body, however the server paces its bytes -- returns at the deadline instead of waiting out a
    fresh per-operation socket timeout. ``expired`` then turns whatever error (or early EOF) the
    interrupted read produced into a ``timeout``."""

    def __init__(self, timeout: float) -> None:
        self.end = time.monotonic() + timeout
        self._lock = threading.Lock()
        self._socks: list[socket.socket] = []
        self._fired = False
        self._timer = threading.Timer(timeout, self._fire)
        self._timer.daemon = True

    def remaining(self) -> float:
        return self.end - time.monotonic()

    @property
    def expired(self) -> bool:
        return self._fired or self.remaining() <= 0

    def socket_timeout(self) -> float:
        """The per-operation socket timeout for the next blocking step: what is left."""
        left = self.remaining()
        if left <= 0:
            raise TimeoutError("request deadline exceeded")
        return left

    def register(self, sock: socket.socket | None) -> None:
        if sock is None:
            return
        with self._lock:
            self._socks.append(sock)
            fired = self._fired
        if fired:
            self._shutdown(sock)

    @staticmethod
    def _shutdown(sock: socket.socket) -> None:
        # socket.socket.shutdown, not SSLSocket.shutdown: interrupt the fd without touching the
        # TLS state another thread is reading through.
        try:
            if sock.fileno() != -1:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except OSError:
            pass

    def _fire(self) -> None:
        with self._lock:
            self._fired = True
            socks = list(self._socks)
        for sock in socks:
            self._shutdown(sock)

    def __enter__(self) -> _Deadline:
        self._timer.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._timer.cancel()


class _DeadlineConnection(http.client.HTTPConnection):
    """An HTTPConnection that connects within the remaining budget and registers its socket."""

    def __init__(self, *args: Any, deadline: _Deadline, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._deadline = deadline
        create: Callable[..., socket.socket] = self._create_connection  # type: ignore[has-type]

        def _create(*a: Any, **kw: Any) -> socket.socket:
            sock = create(*a, **kw)
            deadline.register(sock)
            return sock

        self._create_connection = _create

    def connect(self) -> None:
        self.timeout = self._deadline.socket_timeout()
        super().connect()
        self._deadline.register(self.sock)


class _DeadlineHTTPSConnection(_DeadlineConnection, http.client.HTTPSConnection):
    pass


class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, deadline: _Deadline) -> None:
        super().__init__()
        self._deadline = deadline

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(  # type: ignore[arg-type]
            functools.partial(_DeadlineConnection, deadline=self._deadline), req)


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, deadline: _Deadline, context: ssl.SSLContext | None) -> None:
        super().__init__(context=context)
        self._deadline = deadline
        self._ctx = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(  # type: ignore[arg-type]
            functools.partial(_DeadlineHTTPSConnection, deadline=self._deadline), req,
            context=self._ctx)


def _read_capped(resp, cap: int, deadline: _Deadline, what: str) -> bytes:  # noqa: ANN001
    length = resp.headers.get("Content-Length")
    if length is not None and length.strip().isdigit() and int(length) > cap:
        raise FetchError(f"{what} is larger than {cap} bytes", code="too_large")
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline.expired:
            raise _timed_out(what)
        chunk = resp.read1(min(65536, cap + 1 - total))
        if not chunk:
            if deadline.expired:
                # The watchdog's shutdown reads as EOF: a truncated body, never a complete one.
                raise _timed_out(what)
            return b"".join(chunks)
        total += len(chunk)
        if total > cap:
            raise FetchError(f"{what} is larger than {cap} bytes", code="too_large")
        chunks.append(chunk)


def _timed_out(what: str) -> FetchError:
    return FetchError(f"{what}: timed out", code="timeout", retryable=True)


def _is_timeout(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None),
                                                       TimeoutError)


def _error_detail(err: urllib.error.HTTPError) -> str | None:
    try:
        raw = err.read(_ERROR_BODY_MAX_BYTES)
        detail = json.loads(raw).get("detail")
    except Exception:  # noqa: BLE001 - the detail is best-effort display text
        return None
    return _shown(detail) if isinstance(detail, str) else None


def _get(url: str, *, headers: dict[str, str], timeout: float, cap: int, what: str,
         ssl_context: ssl.SSLContext | None) -> tuple[int, bytes, str | None]:
    """GET ``url``: (status, body, None) on 2xx; (status, b"", detail) on an HTTP error status.
    Network failures, caps and the total ``timeout`` raise FetchError."""
    with _Deadline(timeout) as deadline:
        opener = urllib.request.build_opener(
            _RefuseRedirect, _DeadlineHTTPHandler(deadline),
            _DeadlineHTTPSHandler(deadline, ssl_context))
        return _get_within(opener, url, headers=headers, deadline=deadline, cap=cap, what=what)


def _get_within(opener: urllib.request.OpenerDirector, url: str, *, headers: dict[str, str],
                deadline: _Deadline, cap: int, what: str) -> tuple[int, bytes, str | None]:
    req = urllib.request.Request(url, method="GET")
    for name, value in headers.items():
        req.add_unredirected_header(name, value)
    try:
        resp = opener.open(req, timeout=deadline.socket_timeout())
    except urllib.error.HTTPError as err:
        try:
            detail = _error_detail(err)
        finally:
            err.close()
        if deadline.expired:
            # _error_detail swallows the interrupted read; a status whose body stalled past the
            # budget is a (retryable) timeout, not the non-retryable status it began as.
            raise _timed_out(what) from err
        return err.code, b"", detail
    except Exception as exc:  # noqa: BLE001 - also http.client protocol errors, bad headers
        if deadline.expired or _is_timeout(exc):
            raise _timed_out(what) from exc
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLError):
            # A certificate or handshake failure is a configuration problem (wrong CA, wrong
            # name, not TLS at all), never something to retry into success.
            raise FetchError(f"{what}: TLS failed: {_shown(reason)}", code="tls") from exc
        raise FetchError(f"{what}: {_shown(reason)}", code="network", retryable=True) from exc
    try:
        with resp:
            status = resp.status
            try:
                body = _read_capped(resp, cap, deadline, what)
            except FetchError:
                raise
            except Exception as exc:  # noqa: BLE001 - a read that died partway
                if deadline.expired or _is_timeout(exc):
                    raise _timed_out(what) from exc
                raise FetchError(f"{what}: {_shown(exc)}", code="network",
                                 retryable=True) from exc
    except FetchError:
        raise
    except Exception as exc:  # noqa: BLE001 - closing a broken connection
        raise FetchError(f"{what}: {_shown(exc)}", code="network", retryable=True) from exc
    return status, body, None


def _status_failure(status: int, detail: str | None, what: str) -> FetchError:
    suffix = f": {detail}" if detail else ""
    if status == 409:
        return FetchError(f"{what}: the job is not finished yet (409){suffix}", code="not_ready",
                          retryable=True, status=status)
    if status in (401, 403):
        return FetchError(f"{what}: not authorized ({status}){suffix}", code="unauthorized",
                          status=status)
    if 300 <= status < 400:
        return FetchError(f"{what}: refused a redirect ({status})", code="redirect",
                          status=status)
    if status == 429 or 500 <= status < 600:
        return FetchError(f"{what}: server unavailable ({status}){suffix}", code="unavailable",
                          retryable=True, status=status)
    return FetchError(f"{what}: unexpected HTTP status {status}{suffix}", code="http_error",
                      status=status)


def fetch_and_verify(
    base_url: str,
    job_id: str,
    *,
    keys: PinnedKeys | VerifyKey | Iterable[VerifyKey],
    expect_input_sha256: str | None = None,
    expect_engine: str | None = None,
    max_age: float | timedelta | None = None,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    max_metadata_bytes: int = DEFAULT_METADATA_MAX_BYTES,
    ssl_context: ssl.SSLContext | None = None,
) -> VerifiedResult:
    """Fetch ``/v1/jobs/{job_id}/attestation`` and ``/v1/jobs/{job_id}/metadata`` from the
    ingress at ``base_url`` and :func:`verify_receipt` them -- the metadata binding is always
    checked. Returns the receipt and the verified metadata bytes; act on those bytes.

    Standard library only (urllib). Only http/https; redirects are refused; the bearer
    ``token`` (``BLASTBOX_API_KEY`` on the ingress) is sent as ``Authorization: Bearer``. The
    receipt is read up to 1 MiB and the metadata up to ``max_metadata_bytes``; ``timeout``
    is each request's TOTAL wall-clock budget -- connect, TLS, headers and body together (name
    resolution is the system resolver's own); a read still blocked when it runs out is
    interrupted (``FetchError`` code ``timeout``). The receipt is fully verified (signature,
    job, input, engine, age) before the metadata is fetched; the metadata is then bound to it.
    Certificates are verified (pass ``ssl_context`` to pin a private CA).

    Raises :class:`NoReceipt` (404/410/tombstone), :class:`FetchError` (``retryable`` for 409,
    429/5xx, network errors and timeouts), or any failure of :func:`verify_receipt`."""
    pinned = _as_pinned(keys)
    # Every argument is checked BEFORE the first request, so a typo is a TypeError/ValueError
    # up front, never a fetch followed by a late argument error.
    _expected_input(expect_input_sha256)
    _check_engine(expect_engine)
    if max_age is not None:
        _seconds(max_age, "max_age")
    root = _base_url(base_url)
    job_id = _canonical_job_id(job_id)
    timeout_s = _seconds(timeout, "timeout")
    if not 0 < timeout_s < math.inf:
        raise ValueError("timeout must be a finite number of seconds > 0")
    if type(max_metadata_bytes) is not int or max_metadata_bytes <= 0:
        raise ValueError("max_metadata_bytes must be a positive int")
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if token is not None:
        if not isinstance(token, str) or not token.strip() or any(
                c in token for c in "\r\n\x00"):
            raise ValueError("token must be a non-empty single-line string")
        headers["Authorization"] = f"Bearer {token.strip()}"
    job_url = f"{root}/v1/jobs/{urllib.parse.quote(job_id, safe='')}"

    status, receipt_body, detail = _get(f"{job_url}/attestation", headers=headers,
                                        timeout=timeout_s, cap=RECEIPT_MAX_BYTES,
                                        what="attestation", ssl_context=ssl_context)
    if status == 404:
        raise NoReceipt("no execution receipt for this job (404)"
                        + (f": {detail}" if detail else ""), reason=detail)
    if status == 410:
        raise NoReceipt("the result has expired (410)", reason=detail, code="expired")
    if status != 200:
        raise _status_failure(status, detail, "attestation")

    # Everything that does not depend on the metadata -- tombstone, shape, pinned key,
    # signature, job/input/engine/age bindings -- is settled BEFORE the metadata is fetched: an
    # unusable receipt never costs a metadata download, and a tombstone is NoReceipt however
    # the metadata route would have answered.
    receipt = verify_receipt(receipt_body, keys=pinned, expect_job_id=job_id,
                             expect_input_sha256=expect_input_sha256,
                             expect_engine=expect_engine, max_age=max_age)

    status, metadata, detail = _get(f"{job_url}/metadata", headers=headers, timeout=timeout_s,
                                    cap=max_metadata_bytes, what="metadata",
                                    ssl_context=ssl_context)
    if status == 410:
        raise NoReceipt("the result has expired (410)", reason=detail, code="expired")
    if status == 404:
        raise FetchError("metadata: not found (404) although a receipt was served"
                         + (f": {detail}" if detail else ""), code="metadata_missing",
                         status=status)
    if status != 200:
        raise _status_failure(status, detail, "metadata")

    _check_metadata(receipt.metadata_sha256, hashlib.sha256(metadata).hexdigest())
    if max_age is not None:
        # Freshness is a property of the result as RETURNED: a slow metadata download can carry
        # a receipt that was fresh at the first check past the caller's max_age.
        _check_age(receipt.issued_at_ms, _seconds(max_age, "max_age"),
                   DEFAULT_MAX_CLOCK_SKEW_S, None)
    receipt = dataclasses.replace(receipt, metadata_bound=True)
    return VerifiedResult(receipt=receipt, metadata=metadata)
