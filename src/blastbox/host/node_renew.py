"""Online node-cert renewal: a queued CSR on the ingress, signed on the CA host.

THE SPLIT IS THE POINT. The ingress holds no CA key, so it can only validate a CSR and put
it in ``<pki>/renew/``. A timer on the CA host (`blastbox pki renew-pending`) signs what is
queued. The node then polls ``GET /v1/nodes/cert``.

WHAT A RENEWAL MAY NOT DO. It never widens anything and never revives anything: the new
cert carries the grants of the node's CURRENT verifying cert, and a node whose cert is gone
or expired has no current cert, so its CSR is refused and deleted. "Stop renewing" stays the
revocation path.

No FastAPI in here, so the CA-host CLI and the ingress share one implementation.
"""
from __future__ import annotations

import fcntl
import os
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blastbox.host.pki import CertAuthority, load_trust_anchor, node_identity

RENEW_DIR = "renew"
MAX_CSR_BYTES = 8 * 1024
#: Hard bound on queued files, so a fleet of valid sessions cannot fill the ingress disk.
MAX_QUEUED = 1024

_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RenewRefused(Exception):
    """The CSR was not queued; the message is safe to show the (authenticated) node."""


def _renew_dir(pki_dir: Path, *, create: bool = False) -> Path:
    d = Path(pki_dir) / RENEW_DIR
    if create:
        d.mkdir(mode=0o700, exist_ok=True)
    return d


def queue_csr(pki_dir: Path, node_id: str, csr_pem: bytes) -> None:
    """Validate ``csr_pem`` for ``node_id`` and queue it, newest-wins, one file per node."""
    if not _NODE_ID.match(node_id):
        raise RenewRefused("invalid node id")
    if len(csr_pem) > MAX_CSR_BYTES:
        raise RenewRefused("CSR too large")
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise RenewRefused("CSR signature is invalid")
        pub = csr.public_key()
    except RenewRefused:
        raise
    except Exception:                                   # noqa: BLE001 - any parse failure
        raise RenewRefused("CSR is not a valid PEM certificate request") from None
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise RenewRefused("CSR key must be EC P-256")
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) != 1 or str(cns[0].value) != node_id:
        raise RenewRefused("CSR common name does not match the session's node")

    d = _renew_dir(pki_dir, create=True)
    target = d / f"{node_id}.csr"
    if not target.exists():
        try:
            n = sum(1 for _ in d.iterdir())
        except OSError:
            n = 0
        if n > MAX_QUEUED:
            raise RenewRefused("renewal queue is full")
    fd, tmp = tempfile.mkstemp(dir=d, prefix=f".{node_id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(csr_pem)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _find_current(pki_dir: Path, node_id: str):
    """(path, pem, identity) of the verifying cert with the latest not_after, or None."""
    d = Path(pki_dir)
    try:
        anchor = load_trust_anchor(d)
    except Exception:                                   # noqa: BLE001 - no CA: verify nothing
        return None
    best = None
    for crt in sorted(d.glob("*.crt")):
        try:
            pem = crt.read_bytes()
            ident = node_identity(anchor, pem)
        except Exception:                               # noqa: BLE001 - one bad file is not fatal
            continue
        if ident.node_id != node_id:
            continue
        if best is None or ident.not_after > best[2].not_after:
            best = (crt, pem, ident)
    return best


def current_cert(pki_dir: Path, node_id: str) -> bytes | None:
    """PEM of the node's verifying cert with the latest ``not_after``, or None."""
    found = _find_current(pki_dir, node_id)
    return found[1] if found else None


def current_cert_info(pki_dir: Path, node_id: str) -> tuple[bytes, str] | None:
    """Like :func:`current_cert`, plus its ``not_after`` as an ISO-8601 string."""
    found = _find_current(pki_dir, node_id)
    return (found[1], found[2].not_after.isoformat()) if found else None


def _replace_file(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def sign_pending(ca: CertAuthority, pki_dir: Path, *, days: int = 7) -> list[tuple[str, str]]:
    """Sign every queued CSR with its node's CURRENT grants. Returns (node_id, outcome)."""
    pki_dir = Path(pki_dir)
    d = _renew_dir(pki_dir)
    if not d.is_dir():
        return []
    results: list[tuple[str, str]] = []
    with open(d / ".lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for csr_path in sorted(d.glob("*.csr")):
            node_id = csr_path.stem
            try:
                csr_pem = csr_path.read_bytes()
            except OSError:
                continue
            found = _find_current(pki_dir, node_id)
            if found is None:
                outcome = "refused: no current certificate"
            else:
                path, _pem, ident = found
                try:
                    new = ca.sign_node_csr(csr_pem, node_id=node_id,
                                           grants=ident.grants, days=days)
                    _replace_file(path, new)
                    outcome = "renewed"
                except (ValueError, OSError) as exc:
                    outcome = f"refused: {exc}"
            # A node may have queued a newer CSR while we signed; leave that one for next run.
            try:
                if csr_path.read_bytes() == csr_pem:
                    csr_path.unlink(missing_ok=True)
            except OSError:
                pass
            results.append((node_id, outcome))
    return results
