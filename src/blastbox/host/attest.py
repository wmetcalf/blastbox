"""Host-signed job attestation.

A statement, signed by THIS host, of facts this host observed or decided about one job: which
job, which engine, its terminal status, the input it spooled, the exact metadata.json bytes it
serves, who executed it, and -- only when its own dispatcher launched the sandbox -- the runtime,
tier and the network personality it resolved and enforced.

EVERY FIELD COMES FROM THE HOST'S JOB ROW, plus a host-computed hash of the stored metadata
bytes. Nothing is read out of metadata.json: a worker that writes ``attested`` or
``net_policy_effective`` into its own envelope changes nothing here. For a job a federated node
executed the host did not see the sandbox, so runtime/tier/policy are OMITTED, not guessed.

The wire format is a contract with verifiers (Loadout's host-attestation spec):

    canonical(x) = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    key_id       = sha256(SubjectPublicKeyInfo DER).hexdigest()[:16]
    signature    = base64url(DER ECDSA-P256-SHA256 over canonical(doc)), padded

A verifier must pin the key out of band (``blastbox attest-key``); a key served by the host
proves nothing on its own.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host.jobs.base import Job, JobStatus, NODE_CLAIM_PREFIX, is_node_claim

ATTEST_KEY_ENV = "BLASTBOX_ATTEST_KEY"
PKI_DIR_ENV = "BLASTBOX_PKI_DIR"
HOST_ID_ENV = "BLASTBOX_HOST_ID"
ATTEST_KEY_FILENAME = "attest.key"

VERSION = 1
ALG = "ES256"

TERMINAL_STATUSES = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED})


def canonical(x: object) -> bytes:
    """The exact bytes that are signed. Part of the contract -- do not change."""
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def is_terminal(status: JobStatus) -> bool:
    return status in TERMINAL_STATUSES


def _env_path(env: Mapping[str, str], name: str) -> str | None:
    # SET-BUT-EMPTY IS NOT A PATH: deployment tooling emits `VAR=` for unset values.
    value = (env.get(name) or "").strip()
    return value or None


def attest_key_path(env: Mapping[str, str] | None = None) -> Path | None:
    """Where the signing key lives: ``BLASTBOX_ATTEST_KEY``, else ``$BLASTBOX_PKI_DIR/attest.key``.

    ``None`` when neither is set: attestation is DISABLED (routes 404). There is deliberately no
    built-in default path -- a host that never chose to attest must not start minting a key."""
    env = os.environ if env is None else env
    explicit = _env_path(env, ATTEST_KEY_ENV)
    if explicit:
        return Path(explicit)
    pki = _env_path(env, PKI_DIR_ENV)
    if pki:
        return Path(pki) / ATTEST_KEY_FILENAME
    return None


def host_id(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get(HOST_ID_ENV) or "").strip() or socket.gethostname()


@dataclass(frozen=True)
class AttestKey:
    """The host's attestation signing key (EC P-256)."""

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


def _parse_key(data: bytes, path: Path) -> AttestKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError(f"attestation key {path} is not an EC P-256 private key "
                         f"(alg is fixed at {ALG})")
    return AttestKey(key)


def load_or_create_key(path: Path) -> AttestKey:
    """Load the key at ``path``, generating it (0600) on first use.

    Generation is ATOMIC and race-safe: the key is written in full to a private temp file beside
    the target, then hard-linked into place. ``link`` fails if the target already exists, so two
    processes starting together converge on whichever key landed first instead of one silently
    overwriting a key the other already served (a verifier pinned to it would then reject every
    statement)."""
    path = Path(path)
    try:
        return _parse_key(path.read_bytes(), path)
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass            # a concurrent starter won; use ITS key, below
    finally:
        tmp.unlink(missing_ok=True)
    return _parse_key(path.read_bytes(), path)


def load_attest_key(env: Mapping[str, str] | None = None) -> AttestKey | None:
    """The configured key (generated if missing), or ``None`` if attestation is disabled."""
    path = attest_key_path(env)
    return None if path is None else load_or_create_key(path)


def executor_of(job: Job) -> str:
    """``"local"`` unless the ingress control plane handed this job to a federated node.

    Decided by the ``node:`` claim prefix, which the HOST stamps at hand-over and a node cannot
    set (it may only clear its claim, as part of a release, which requeues the job). Terminal
    writes keep the claim id, so a node-run terminal row still carries it. The node's id comes
    from ``executor_node``, also host-stamped at hand-over."""
    if is_node_claim(job.claim_id):
        return NODE_CLAIM_PREFIX + (job.executor_node or "unknown")
    return "local"


def build_attestation(job: Job, *, key_id: str, metadata_sha256: str | None, host: str,
                      now: float | None = None) -> dict:
    """The statement for ``job``. Built from the host's job row ONLY (plus the host-computed
    ``metadata_sha256``) -- never from anything the worker wrote."""
    executor = executor_of(job)
    doc: dict[str, object] = {
        "v": VERSION,
        "alg": ALG,
        "key_id": key_id,
        "host": host,
        "job_id": job.job_id,
        "engine": job.engine,
        "status": job.status.value,
        "input_sha256": job.input_sha256,
        "metadata_sha256": metadata_sha256,
        "executor": executor,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "issued_at": time.time() if now is None else now,
    }
    if executor == "local":
        # The local dispatcher launched the sandbox, so these are this host's own observations.
        doc["worker_runtime"] = job.worker_runtime
        doc["worker_tier"] = job.worker_tier
        if job.net_policy_effective is not None:
            doc["net_policy_effective"] = job.net_policy_effective
    return doc


def sign_attestation(key: AttestKey, doc: dict) -> dict:
    """The route body: ``{"attestation": doc, "signature": sig}``."""
    return {"attestation": doc, "signature": key.sign(doc)}


def public_key_body(key: AttestKey) -> dict:
    return {"key_id": key.key_id, "alg": ALG, "public_key_pem": key.public_key_pem}
