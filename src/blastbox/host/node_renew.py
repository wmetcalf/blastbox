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

import contextlib
import dataclasses
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
    NodeIdentity,
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


def _intersect(a: NodeGrants | None, b: NodeGrants) -> NodeGrants:
    if a is None:
        return b
    return NodeGrants(engines=tuple(sorted(set(a.engines) & set(b.engines))),
                      tiers=tuple(sorted(set(a.tiers) & set(b.tiers))),
                      credentials=a.credentials and b.credentials)


@dataclasses.dataclass
class _Current:
    """A node's verifying certs in one PKI dir."""

    path: Path                          #: the one with the latest not_after
    pem: bytes
    ident: NodeIdentity
    grants: NodeGrants                  #: INTERSECTION over every verifying cert
    wg_keys: set[str | None]            #: every WireGuard key they carry (None = keyless)
    others: list[tuple[Path, bytes]]    #: the rest, superseded by a renewal


def _find_current(pki_dir: Path, node_id: str) -> _Current | None:
    """The node's verifying certs in ``pki_dir``, or None.

    ``grants`` is the intersection over every verifying cert for the node, the same rule
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
    found: list[tuple[Path, bytes, NodeIdentity]] = []
    for crt in sorted(d.glob("*.crt")):
        pem = crt.read_bytes()                          # OSError propagates (transient)
        try:
            ident = node_identity(anchor, pem)
        except Exception:                               # noqa: BLE001 - one bad file is not fatal
            continue
        if ident.node_id == node_id:
            found.append((crt, pem, ident))
    if not found:
        return None
    best = max(found, key=lambda f: f[2].not_after)
    grants: NodeGrants | None = None
    for f in found:
        grants = _intersect(grants, f[2].grants)
    assert grants is not None
    return _Current(path=best[0], pem=best[1], ident=best[2], grants=grants,
                    wg_keys={f[2].wg_pubkey for f in found},
                    others=[(f[0], f[1]) for f in found if f is not best])


def current_cert(pki_dir: Path, node_id: str) -> bytes | None:
    """PEM of the node's verifying cert with the latest ``not_after``, or None."""
    found = _find_current(pki_dir, node_id)
    return found.pem if found else None


def current_cert_info(pki_dir: Path, node_id: str) -> tuple[bytes, str] | None:
    """Like :func:`current_cert`, plus its ``not_after`` as an ISO-8601 string."""
    found = _find_current(pki_dir, node_id)
    return (found.pem, found.ident.not_after.isoformat()) if found else None


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
    check followed by ``os.replace`` would overwrite a CSR queued between the two. A
    mount without hard links (sshfs, SMB) falls back to that check-then-replace; never
    raise, since one stuck aside must not wedge every later run.
    """
    try:
        os.link(aside, orig)
    except FileExistsError:
        pass
    except OSError:
        try:
            if not orig.exists():
                os.replace(aside, orig)
        except OSError:
            return                      # left as .signing; the next run retries it
    aside.unlink(missing_ok=True)


@contextlib.contextmanager
def _locked(dirs: list[Path]):
    """Hold every node dir's renewal lock (sorted, so two runs never deadlock).

    ALL of them for the whole run: a renewal writes certs into every dir where the node
    verifies, so a second run over an overlapping set must wait rather than interleave.
    An OSError (missing or stale mount) propagates before anything is consumed.
    """
    with contextlib.ExitStack() as stack:
        for d in sorted(set(dirs)):
            # In the PKI dir itself, not renew/: creating renew/ from the CA host could
            # leave the ingress a queue dir it does not own.
            fh = stack.enter_context(open(Path(d) / ".renew.lock", "a+"))
            fcntl.flock(fh, fcntl.LOCK_EX)
        yield


def sign_pending(ca: CertAuthority, pki_dir: Path, *, days: int = 7,
                 node_dirs: list[Path] | None = None) -> list[tuple[str, str]]:
    """Sign every queued CSR with its node's CURRENT grants. Returns (node_id, outcome).

    ``pki_dir`` holds the CA key. ``node_dirs`` are further PKI dirs whose certs authorise
    nodes and whose ``renew/`` queues an ingress writes -- on a split deployment, each
    ingress host's PKI dir made reachable on the CA host (the ingress never gets the CA
    key; the mount runs the other way). ``pki_dir`` is always one of them.

    A node's CURRENT state is taken over EVERY dir where it verifies: the new cert carries
    the intersection of all their grants and their one WireGuard key (dirs that disagree
    about the key are refused), and is written to every one of those dirs, so no ingress
    is ever widened by a renewal queued through another. It must verify in the dir that
    queued it. A dir where it does not verify -- revoked there -- is left alone. If any
    write fails, or a cert changed or vanished meanwhile, the CSR is kept and the next
    run redoes the whole renewal; a partly published one converges then.

    Raises ValueError for an out-of-range ``days``, and OSError when a node dir cannot be
    locked (an unreachable mount), BEFORE touching any queue.
    """
    if not 1 <= days <= MAX_NODE_CERT_DAYS:
        raise ValueError(f"node cert lifetime must be 1..{MAX_NODE_CERT_DAYS} days, got {days}")
    every = list(dict.fromkeys([Path(pki_dir), *(Path(p) for p in node_dirs or [])]))
    results: list[tuple[str, str]] = []
    with _locked(every):
        for qdir in every:
            results += _drain(ca, qdir, days, every)
    return results


def _drain(ca: CertAuthority, qdir: Path, days: int,
           every: list[Path]) -> list[tuple[str, str]]:
    d = _renew_dir(qdir)
    results: list[tuple[str, str]] = []
    if not d.is_dir():
        return results
    # A crash mid-sign leaves "<id>.csr.signing"; put it back unless a newer CSR landed.
    for aside in d.glob("*.csr.signing"):
        _restore(aside, aside.with_suffix(""))
    for csr_path in sorted(d.glob("*.csr")):
        node_id = csr_path.stem
        # Set aside, so a newer CSR can land on the original name while we sign and is
        # never deleted by us.
        aside = csr_path.with_name(csr_path.name + ".signing")
        try:
            os.replace(csr_path, aside)
            csr_pem = aside.read_bytes()
        except OSError:
            continue
        outcome, keep = _renew_one(ca, qdir, every, node_id, csr_pem, days)
        if keep:
            # Transient fault: retry next run, unless the node has queued a newer one.
            _restore(aside, csr_path)
        else:
            aside.unlink(missing_ok=True)
        results.append((node_id, outcome))
    return results


def _swap_if_unchanged(path: Path, expected: bytes, new: bytes) -> str | None:
    """Replace ``path`` with ``new`` if it still holds ``expected``; else say why not."""
    try:
        still = path.read_bytes()
    except FileNotFoundError:
        return "removed"
    if still != expected:
        return "changed"
    _replace_file(path, new)
    return None


def _renew_one(ca: CertAuthority, qdir: Path, every: list[Path], node_id: str,
               csr_pem: bytes, days: int) -> tuple[str, bool]:
    """Renew one set-aside CSR across every node dir. Returns (outcome, keep the CSR)."""
    states: dict[Path, _Current] = {}
    try:
        for d in every:
            cur = _find_current(d, node_id)
            if cur is not None:
                states[d] = cur
    except OSError as exc:
        return f"deferred: {exc}", True
    if qdir not in states:
        return "refused: no current certificate", False
    grants: NodeGrants | None = None
    wg_keys: set[str | None] = set()
    for cur in states.values():
        grants = _intersect(grants, cur.grants)
        wg_keys |= cur.wg_keys
    if len(wg_keys) != 1:
        return "refused: the node's certificates disagree about its WireGuard key", False
    assert grants is not None
    try:
        new = ca.sign_node_csr(csr_pem, node_id=node_id, grants=grants, days=days,
                               wg_pubkey=next(iter(wg_keys)))
    except ValueError as exc:
        return f"refused: {exc}", False
    try:
        for d, cur in states.items():
            # Swap only if the cert is still the one we judged: an operator who deleted it
            # (revocation) while we signed must not have it written back.
            why = _swap_if_unchanged(cur.path, cur.pem, new)
            if why:
                return f"deferred: certificate in {d} {why} while signing", True
            # The renewed cert supersedes the node's other certs here: left in place, a
            # longer-lived one would outlive it and be served, and would bring back its
            # grants when the renewed one lapsed.
            for path, pem in cur.others:
                try:
                    if path.read_bytes() == pem:
                        path.unlink()
                except FileNotFoundError:
                    pass
    except OSError as exc:
        return f"deferred: {exc}", True
    return "renewed", False


def revoke(pki_dir: Path, node_id: str, *, node_dirs: list[Path] | None = None) -> list[Path]:
    """Revoke ``node_id``: delete its certs and queued CSRs in every node dir.

    Under the same locks as :func:`sign_pending`, so a renewal in flight cannot write a
    cert back after it. Returns the cert files removed.
    """
    every = list(dict.fromkeys([Path(pki_dir), *(Path(p) for p in node_dirs or [])]))
    removed: list[Path] = []
    with _locked(every):
        for d in every:
            try:
                anchor = load_trust_anchor(d)
            except Exception:                           # noqa: BLE001 - nothing verifies here
                anchor = None
            for crt in sorted(d.glob("*.crt")):
                if anchor is None:
                    break
                try:
                    if node_identity(anchor, crt.read_bytes(),
                                     allow_expired=True).node_id != node_id:
                        continue
                except ValueError:
                    continue
                crt.unlink()
                removed.append(crt)
            for q in _renew_dir(d).glob(f"{node_id}.csr*"):
                q.unlink(missing_ok=True)
    return removed
