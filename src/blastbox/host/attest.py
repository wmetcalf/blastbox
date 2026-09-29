"""Execution receipts: signed at the point of observation.

The DISPATCHER that executed a job signs a receipt at the moment it seals a successful (DONE)
result, built ONLY from what that dispatcher itself observed of THAT run -- held in memory for
the run, never read back from the job row, which other parties (nodes, peer dispatchers, anyone
with the DSN) can write:

    input_sha256     sha256 of the input bytes it materialised and handed to the sandbox
    metadata_sha256  sha256 of the exact metadata.json bytes it uploads
    worker_runtime   } as it launched them
    worker_tier      }
    net_policy_effective  the personality it resolved and enforced for this run; OMITTED when the
                          dispatcher does not know (e.g. a VM tier whose egress is undeclared)
    started_at_ms / finished_at_ms / issued_at_ms   integer epoch ms, its own clock

The receipt is written as ``attestation.json`` beside ``metadata.json`` in the sealed output
tree, so it reaches the blob store through the same ``put_output`` as the result it vouches for.
The ingress only SERVES those bytes; nothing in the ingress signs anything.

Wire contract (shared with verifiers, e.g. Loadout):

    body         {"attestation": doc, "signature": sig}
    canonical(x) json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                 -- and NO FLOATS anywhere in x (canonical() raises): float rendering is
                 implementation-specific, so a float would tie the signed bytes to Python.
    key_id       sha256(SubjectPublicKeyInfo DER).hexdigest()[:16]
    signature    base64url, padded, of DER ECDSA-P256-SHA256 over canonical(doc)

A verifier pins the key out of band (``blastbox attest-key``); a key served by a host proves
nothing on its own.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import logging
import os
import posixpath
import shutil
import socket
import stat
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_log = logging.getLogger("blastbox.host.attest")

ATTEST_KEY_ENV = "BLASTBOX_ATTEST_KEY"
PKI_DIR_ENV = "BLASTBOX_PKI_DIR"
HOST_ID_ENV = "BLASTBOX_HOST_ID"
ATTEST_KEY_FILENAME = "attest.key"

#: The receipt's name in the sealed output tree and in the blob store's results prefix.
RECEIPT_NAME = "attestation.json"
_SEAL_NAME = "metadata.json"

VERSION = 1
ALG = "ES256"

#: Sentinel for dispatcher constructors: resolve the key from the environment.
FROM_ENV = object()

_READ_CHUNK = 1024 * 1024


class AttestKeyRefused(ValueError):
    """An existing key file this process will not sign with (unsafe or not P-256)."""


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
# Key
# ---------------------------------------------------------------------------


def _env_value(env: Mapping[str, str], name: str) -> str | None:
    # SET-BUT-EMPTY IS NOT A PATH: deployment tooling emits `VAR=` for unset values.
    value = (env.get(name) or "").strip()
    return value or None


def attest_key_path(env: Mapping[str, str] | None = None) -> Path | None:
    """``BLASTBOX_ATTEST_KEY``, else ``$BLASTBOX_PKI_DIR/attest.key``, else ``None`` (disabled).

    No built-in default: a host that never chose to attest must not start minting a key."""
    env = os.environ if env is None else env
    explicit = _env_value(env, ATTEST_KEY_ENV)
    if explicit:
        return Path(explicit)
    pki = _env_value(env, PKI_DIR_ENV)
    return Path(pki) / ATTEST_KEY_FILENAME if pki else None


def host_id(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get(HOST_ID_ENV) or "").strip() or socket.gethostname()


@dataclass(frozen=True)
class AttestKey:
    """An EC P-256 signing key."""

    private_key: ec.EllipticCurvePrivateKey

    @property
    def public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @property
    def key_id(self) -> str:
        spki = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(spki).hexdigest()[:16]

    def sign(self, doc: Mapping[str, object]) -> str:
        der = self.private_key.sign(canonical(doc), ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(der).decode()


def _read_hardened(path: Path) -> bytes:
    """Read an existing key file, refusing anything another principal could have planted or
    read: a symlink, a non-regular file, a file not owned by this euid, or any group/other bit.
    Opened with O_NOFOLLOW and judged on the OPEN descriptor, so a swap between check and read
    changes nothing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:                       # ELOOP: the final component is a symlink
            raise AttestKeyRefused(f"attestation key {path} is a symlink; refusing it") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AttestKeyRefused(f"attestation key {path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise AttestKeyRefused(
                f"attestation key {path} is owned by uid {st.st_uid}, not this process "
                f"(euid {os.geteuid()}); refusing it")
        if st.st_mode & 0o077:
            raise AttestKeyRefused(
                f"attestation key {path} has group/other permission bits "
                f"({stat.S_IMODE(st.st_mode):o}); it must be 0600 or stricter")
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_key(data: bytes, path: Path) -> AttestKey:
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise AttestKeyRefused(f"attestation key {path} is not a readable PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise AttestKeyRefused(f"attestation key {path} is not an EC P-256 private key "
                               f"(alg is fixed at {ALG})")
    return AttestKey(key)


def load_existing_key(path: Path) -> AttestKey:
    """Load the key at ``path`` WITHOUT creating one. FileNotFoundError if absent."""
    path = Path(path)
    return _parse_key(_read_hardened(path), path)


def load_or_create_key(path: Path) -> AttestKey:
    """Load the key at ``path``, generating it (0600) on first use.

    Generation is ATOMIC and race-safe: the key is written in full to a private temp file beside
    the target, then hard-linked into place. ``link`` fails if the target exists, so processes
    starting together converge on whichever key landed first instead of overwriting a key a
    verifier may already have pinned. Either way the result is re-read through the hardened
    loader, so the file actually used is always the one that passed the checks."""
    path = Path(path)
    try:
        return load_existing_key(path)
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass            # a concurrent starter won; use ITS key
    finally:
        tmp.unlink(missing_ok=True)
    return load_existing_key(path)


def load_attest_key(env: Mapping[str, str] | None = None, *, create: bool = True
                    ) -> AttestKey | None:
    """The configured key, or ``None`` -- attestation disabled, or the key refused/unloadable.

    Never raises: a dispatcher whose key is bad must keep running jobs (without receipts), so a
    failure is logged LOUDLY here instead."""
    path = attest_key_path(env)
    if path is None:
        return None
    try:
        return load_or_create_key(path) if create else load_existing_key(path)
    except FileNotFoundError:
        _log.error("attestation: no key at %s; receipts are DISABLED", path)
    except AttestKeyRefused as exc:
        _log.error("attestation: key refused (%s); receipts are DISABLED", exc)
    except Exception as exc:  # noqa: BLE001 - never take the dispatcher down over a receipt
        _log.error("attestation: key at %s unusable (%s); receipts are DISABLED", path, exc)
    return None


def resolve_key(value: object) -> AttestKey | None:
    """A dispatcher constructor argument: an AttestKey, None (disabled), or FROM_ENV."""
    if value is FROM_ENV:
        return load_attest_key()
    if value is None or isinstance(value, AttestKey):
        return value
    raise TypeError(f"attest_key must be an AttestKey, None or FROM_ENV, not {type(value)!r}")


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


def now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class RunObservation:
    """What ONE dispatcher saw of ONE run, collected in memory as it happened."""

    job_id: str
    engine: str
    input_sha256: str
    worker_runtime: str | None
    worker_tier: str | None
    net_policy_effective: str | None
    started_at_ms: int
    finished_at_ms: int


def sha256_file(path: Path) -> str:
    """sha256 of a regular file's bytes, opened without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        h = hashlib.sha256()
        while chunk := os.read(fd, _READ_CHUNK):
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def build_receipt(obs: RunObservation, *, key_id: str, metadata_sha256: str,
                  issued_at_ms: int | None = None, host: str | None = None) -> dict:
    doc: dict[str, object] = {
        "v": VERSION,
        "alg": ALG,
        "key_id": key_id,
        "host": host_id() if host is None else host,
        "job_id": obs.job_id,
        "engine": obs.engine,
        "status": "done",
        # Kept for wire compatibility. By construction the signer IS the executor.
        "executor": "local",
        "input_sha256": obs.input_sha256,
        "metadata_sha256": metadata_sha256,
        "worker_runtime": obs.worker_runtime,
        "worker_tier": obs.worker_tier,
        "started_at_ms": int(obs.started_at_ms),
        "finished_at_ms": int(obs.finished_at_ms),
        "issued_at_ms": now_ms() if issued_at_ms is None else int(issued_at_ms),
    }
    if obs.net_policy_effective is not None:
        doc["net_policy_effective"] = obs.net_policy_effective
    return doc


def strip_receipt(out_dir: Path) -> None:
    """Remove whatever sits at ``<out_dir>/attestation.json`` -- a worker can write into its
    output tree, and an upload ships the whole tree, so a planted receipt must never ride along.
    Never follows a symlink."""
    target = Path(out_dir) / RECEIPT_NAME
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(target)
    else:
        os.unlink(target)


def _declares_receipt_name(seal: Path) -> bool:
    try:
        env = json.loads(seal.read_bytes())
        paths = [str(a.get("path", "")) for a in env.get("artifacts") or []]
    except Exception:  # noqa: BLE001 - unparseable: cannot rule it out
        return True
    return any(posixpath.normpath(p.strip()) == RECEIPT_NAME for p in paths)


def seal_receipt(out_dir: Path, *, key: AttestKey | None,
                 observation: RunObservation | None) -> dict | None:
    """Strip any planted receipt, then (with a key) sign and write ours. Returns the body written,
    or None when no receipt was written. Call it IMMEDIATELY before uploading ``out_dir``: the
    metadata hash is of the bytes on disk at this moment, which are the bytes put_output ships."""
    out_dir = Path(out_dir)
    strip_receipt(out_dir)
    if key is None or observation is None:
        return None
    try:
        metadata_sha256 = sha256_file(out_dir / _SEAL_NAME)
    except (OSError, ValueError) as exc:
        _log.error("attestation: job %s has no regular metadata.json to vouch for (%s); "
                   "no receipt", observation.job_id, exc)
        return None
    if _declares_receipt_name(out_dir / _SEAL_NAME):
        # The trust gate refuses this; never paper over a declared artifact regardless.
        _log.error("attestation: job %s declares %s as an artifact; no receipt",
                   observation.job_id, RECEIPT_NAME)
        return None
    doc = build_receipt(observation, key_id=key.key_id, metadata_sha256=metadata_sha256)
    body = {"attestation": doc, "signature": key.sign(doc)}
    data = canonical(body)
    tmp = out_dir / f".{RECEIPT_NAME}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out_dir / RECEIPT_NAME)
    finally:
        tmp.unlink(missing_ok=True)
    return body


def public_key_body(key: AttestKey) -> dict:
    return {"key_id": key.key_id, "alg": ALG, "public_key_pem": key.public_key_pem}
