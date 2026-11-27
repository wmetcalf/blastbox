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

from blastbox.host.pki import (
    MAX_NODE_CERT_DAYS,
    CertAuthority,
    NodeGrants,
    load_trust_anchor,
    node_identity,
)

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
        os.chmod(d, 0o700)          # an existing dir may predate this mode
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
            n = sum(1 for _ in d.glob("*.csr"))
        except OSError:
            n = 0
        if n >= MAX_QUEUED:
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
    """(path, pem, identity, grants) of the node's current cert, or None.

    The path/pem/identity are those of the verifying cert with the latest ``not_after``;
    ``grants`` is the INTERSECTION over every verifying cert for the node, the same rule
    :func:`blastbox.host.placement.fleet_grants` applies on the ingress, so a renewal can
    never restore a grant a narrower cert beside it is withholding.

    A cert that does not verify is skipped, but an OSError reading the anchor or a cert
    file PROPAGATES: "could not read" is a transient fault, not "has no certificate", and
    the caller must not turn it into a refusal that deletes the node's CSR.
    """
    d = Path(pki_dir)
    try:
        anchor = load_trust_anchor(d)
    except OSError:
        raise
    except Exception:                                   # noqa: BLE001 - garbled CA: verify nothing
        return None
    best = None
    grants: NodeGrants | None = None
    for crt in sorted(d.glob("*.crt")):
        pem = crt.read_bytes()                          # OSError propagates (transient)
        try:
            ident = node_identity(anchor, pem)
        except Exception:                               # noqa: BLE001 - one bad file is not fatal
            continue
        if ident.node_id != node_id:
            continue
        g = ident.grants
        grants = g if grants is None else NodeGrants(
            engines=tuple(sorted(set(grants.engines) & set(g.engines))),
            tiers=tuple(sorted(set(grants.tiers) & set(g.tiers))),
            credentials=grants.credentials and g.credentials)
        if best is None or ident.not_after > best[2].not_after:
            best = (crt, pem, ident)
    if best is None or grants is None:
        return None
    return (*best, grants)


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


def _restore(aside: Path, orig: Path) -> None:
    """Put a set-aside CSR back, unless a newer one landed on ``orig`` meanwhile.

    ``os.link`` fails if ``orig`` exists, so this is a no-clobber move: an exists()
    check followed by ``os.replace`` would overwrite a CSR queued between the two.
    """
    try:
        os.link(aside, orig)
    except FileExistsError:
        pass
    aside.unlink(missing_ok=True)


def sign_pending(ca: CertAuthority, pki_dir: Path, *, days: int = 7) -> list[tuple[str, str]]:
    """Sign every queued CSR with its node's CURRENT grants. Returns (node_id, outcome).

    Raises ValueError for an out-of-range ``days`` BEFORE touching the queue: that is an
    operator error, and treating it per CSR would refuse and delete every queued renewal.
    """
    if not 1 <= days <= MAX_NODE_CERT_DAYS:
        raise ValueError(f"node cert lifetime must be 1..{MAX_NODE_CERT_DAYS} days, got {days}")
    pki_dir = Path(pki_dir)
    d = _renew_dir(pki_dir)
    if not d.is_dir():
        return []
    results: list[tuple[str, str]] = []
    with open(d / ".lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # A crash mid-sign leaves "<id>.csr.signing"; put it back unless a newer CSR landed.
        for aside in d.glob("*.csr.signing"):
            _restore(aside, aside.with_suffix(""))
        for csr_path in sorted(d.glob("*.csr")):
            node_id = csr_path.stem
            # Rename aside under the lock, so a newer CSR can land on the original name
            # while we sign and is never deleted by us.
            aside = csr_path.with_name(csr_path.name + ".signing")
            try:
                os.replace(csr_path, aside)
                csr_pem = aside.read_bytes()
            except OSError:
                continue
            outcome, keep = _sign_one(ca, pki_dir, node_id, csr_pem, days)
            if keep:
                # Transient fault: retry next run, unless the node has queued a newer one.
                _restore(aside, csr_path)
            else:
                aside.unlink(missing_ok=True)
            results.append((node_id, outcome))
    return results


def _sign_one(ca: CertAuthority, pki_dir: Path, node_id: str, csr_pem: bytes,
              days: int) -> tuple[str, bool]:
    """Sign one set-aside CSR. Returns (outcome, keep the CSR for a retry)."""
    try:
        found = _find_current(pki_dir, node_id)
    except OSError as exc:
        return f"deferred: {exc}", True
    if found is None:
        return "refused: no current certificate", False
    path, pem, ident, grants = found
    try:
        new = ca.sign_node_csr(csr_pem, node_id=node_id, grants=grants,
                               days=days, wg_pubkey=ident.wg_pubkey)
        # Re-read just before replacing: an operator who deleted the cert (revocation)
        # while we signed must not have it written back.
        try:
            still = path.read_bytes()
        except FileNotFoundError:
            return "refused: certificate removed while signing", False
        if still != pem:
            return "deferred: certificate changed while signing", True
        _replace_file(path, new)
        return "renewed", False
    except ValueError as exc:
        return f"refused: {exc}", False
    except OSError as exc:
        return f"deferred: {exc}", True
