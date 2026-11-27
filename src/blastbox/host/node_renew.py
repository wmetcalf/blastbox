"""Online node-cert renewal: a queued CSR on the ingress, signed on the CA host.

THE SPLIT IS THE POINT. The ingress holds no CA key, so it can only validate a CSR and put
it in ``<pki>/renew/``. A timer on the CA host (`blastbox pki renew-pending`) signs what is
queued. The node then polls ``GET /v1/nodes/cert``.

WHAT A RENEWAL MAY NOT DO. It never widens anything and never revives anything: the new
cert carries the grants of the node's CURRENT verifying cert, and a node whose cert is gone
or expired has no current cert, so its CSR is refused and deleted. "Stop renewing" stays the
revocation path.

PROOF OF POSSESSION. A session token is a bearer credential, so it cannot be what lets a
node put a NEW key into its cert: the request also carries the node's current cert and a
signature by that cert's key over :func:`renew_payload` (the CSR's hash and a timestamp).
The ingress checks it, and the CA host checks it AGAIN against the real CA before signing,
because the ingress -- whose dir the queue lives in -- may be hostile: holding a copy of a
node's cert is not holding its key.

No FastAPI in here, so the CA-host CLI and the ingress share one implementation.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import hashlib
import json
import errno
import fcntl
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blastbox.host.pki import _NODE_ID_RE as _PKI_NODE_ID
from blastbox.host.pki import (
    MAX_NODE_CERT_DAYS,
    CertAuthority,
    NodeGrants,
    NodeIdentity,
    TrustAnchor,
    load_trust_anchor,
    node_identity,
)

RENEW_DIR = "renew"
#: What renewal says about a dir holding a non-regular *.crt entry.
LINKS_REFUSED = ("contains cert entries that are not regular files; links are refused -- "
                 "replace them with regular files")
MAX_CSR_BYTES = 8 * 1024
#: The renewal proof's signed-message prefix (see :func:`renew_payload`).
RENEW_PROOF_DOMAIN = b"blastbox/node-renew/v1"
#: How far the ingress lets a proof's ``issued_at`` be from its clock.
RENEW_PROOF_MAX_SKEW_S = 300
#: How old (or ahead) a queued proof may be when the CA host processes it.
RENEW_PROOF_MAX_AGE_S = 24 * 3600
#: Upper bound on one queue entry (JSON: CSR + cert + proof).
MAX_QUEUE_ENTRY_BYTES = 64 * 1024
#: Hard bound on queued files, so a fleet of valid sessions cannot fill the ingress disk.
MAX_QUEUED = 1024

_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

#: In the CA host's own PKI dir (never a node dir): per node, the keys a renewal that is
#: not yet published everywhere links together (see :func:`_renew_one`).
PUBLISHING_DIR = ".renew-publishing"
#: How long such a record lets the old and new keys stand for each other. A renewal that
#: has not converged by then needs the operator (its proof is too old to retry anyway).
PUBLISHING_TTL_S = RENEW_PROOF_MAX_AGE_S


class RenewRefused(Exception):
    """The CSR was not queued; the message is safe to show the (authenticated) node.

    ``identity`` marks a failure of WHO is asking (the cert or its key's signature), which
    the route answers with its uniform 403 rather than the reason.
    """

    def __init__(self, msg: str, *, identity: bool = False) -> None:
        super().__init__(msg)
        self.identity = identity


def renew_payload(node_id: str, csr_pem: str, issued_at: int) -> bytes:
    """The bytes a node signs with its CURRENT cert's key to renew.

    ``RENEW_PROOF_DOMAIN || 0x00 || node_id || 0x00 || sha256hex(utf8(csr_pem)) || 0x00 ||
    decimal(issued_at)``. The CSR is hashed exactly as sent (no PEM normalisation).
    """
    digest = hashlib.sha256(csr_pem.encode("utf-8")).hexdigest().encode()
    return b"\x00".join([RENEW_PROOF_DOMAIN, node_id.encode("utf-8"), digest,
                          str(int(issued_at)).encode()])


def _spki(pub: object) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER,  # type: ignore[attr-defined]
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_renew_proof(key: ec.EllipticCurvePrivateKey, node_id: str, csr_pem: str,
                     issued_at: int) -> str:
    """Base64 (std) DER ECDSA-P256-SHA256 signature over :func:`renew_payload`."""
    sig = key.sign(renew_payload(node_id, csr_pem, issued_at), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def verify_renew_proof(anchor: CertAuthority | TrustAnchor, node_id: str, csr_pem: str,
                       cert_pem: str, issued_at: object, signature_b64: str, *,
                       now: float, max_skew: float,
                       current_keys: set[bytes] | None = None) -> NodeIdentity:
    """Check that the holder of a CA-signed, unexpired cert for ``node_id`` asked for this
    CSR, at ``issued_at`` within ``max_skew`` of ``now``. Raises :class:`RenewRefused`.

    ``current_keys`` (SubjectPublicKeyInfo DER) are the keys of the node's CURRENT certs:
    the proof cert's key must be one of them. Revocation is deletion, so an older cert
    stays CA-valid until it expires; a revoked-then-re-enrolled node's OLD key must not
    renew it.
    """
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not 0 <= issued_at < 2 ** 63):
        raise RenewRefused("issued_at must be an integer (unix seconds, 0 <= t < 2**63)")
    if abs(now - issued_at) > max_skew:
        raise RenewRefused(f"proof issued_at is more than {max_skew:g}s from now")
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise RenewRefused("signature is not base64") from None
    try:
        ident = node_identity(anchor, cert_pem.encode("utf-8"))
    except Exception:                                   # noqa: BLE001 - any verify failure
        raise RenewRefused("proof certificate does not verify", identity=True) from None
    if ident.node_id != node_id:
        raise RenewRefused("proof certificate is not this node's", identity=True)
    pub = x509.load_pem_x509_certificate(cert_pem.encode("utf-8")).public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise RenewRefused("proof certificate key must be EC P-256", identity=True)
    if current_keys is not None and _spki(pub) not in current_keys:
        raise RenewRefused("proof certificate is not the node's current certificate",
                           identity=True)
    try:
        pub.verify(sig, renew_payload(node_id, csr_pem, issued_at), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise RenewRefused("proof signature does not verify", identity=True) from None
    return ident


def _renew_dir(pki_dir: Path, *, create: bool = False) -> Path:
    d = Path(pki_dir) / RENEW_DIR
    if create:
        d.mkdir(mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)          # an existing dir may predate this mode
    return d


def queue_csr(pki_dir: Path, node_id: str, csr_pem: bytes, *, cert_pem: bytes,
              issued_at: object, signature: str,
              anchor: CertAuthority | TrustAnchor | None = None,
              now: float | None = None) -> None:
    """Validate ``csr_pem`` and its proof for ``node_id``; queue them, newest-wins, one file
    per node, as JSON ``{csr_pem, cert_pem, issued_at, signature}``.

    ``anchor`` defaults to this PKI dir's own ``ca.crt`` (the ingress's trust anchor).
    """
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
    if len(cert_pem) > MAX_CERT_BYTES:
        raise RenewRefused("proof certificate too large")
    try:
        csr_text, cert_text = csr_pem.decode("utf-8"), cert_pem.decode("utf-8")
    except UnicodeDecodeError:
        raise RenewRefused("CSR and certificate must be UTF-8 PEM") from None
    explicit = anchor is not None
    if anchor is None:
        try:
            anchor = load_trust_anchor(Path(pki_dir))
        except OSError:
            raise                                       # the caller's 503
        except Exception:                               # noqa: BLE001 - a garbled ca.crt
            raise OSError(errno.EIO, f"{pki_dir}/ca.crt is not a certificate") from None
    # The node's current certs as THIS ingress holds them (regular files only; a dir with
    # anything else raises NonRegularEntries, the route's 503).
    cur = _find_current(Path(pki_dir), node_id, anchor=anchor if explicit else None)
    verify_renew_proof(anchor, node_id, csr_text, cert_text, issued_at, signature,
                       now=time.time() if now is None else now,
                       max_skew=RENEW_PROOF_MAX_SKEW_S,
                       current_keys=cur.keys if cur else set())
    entry = json.dumps({"csr_pem": csr_text, "cert_pem": cert_text,
                        "issued_at": issued_at, "signature": signature},
                       sort_keys=True).encode()
    if len(entry) > MAX_QUEUE_ENTRY_BYTES:      # the CA host would refuse it unread
        raise RenewRefused("renewal request too large")

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
            fh.write(entry)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        Path(tmp).unlink(missing_ok=True)


#: Upper bound on a cert file the CA host reads from a node dir. Real ones are ~1 KiB,
#: but grants make them grow, so this is generous; revoke REPORTS anything larger.
MAX_CERT_BYTES = 1024 * 1024


class _Unreadable(ValueError):
    """Not a file this code will read: a FIFO, device, link, or oversized."""


class _TooLarge(_Unreadable):
    """A regular file over the read cap: possibly a real cert, so never silently ignored."""



#: Never block on a FIFO, never adopt a tty as controlling terminal, never leak the fd.
_OPEN_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


def _read_capped(path: Path, limit: int, *, dir_fd: int | None = None) -> bytes:
    """Read a small REGULAR file without following a link or blocking on a FIFO.

    A node dir is the ingress's to write, so the CA host checks what it opened (fstat on
    the same descriptor, no check-then-open window) and never reads more than ``limit``.
    ``dir_fd`` resolves a relative ``path`` against a pinned directory.
    """
    try:
        flags = _OPEN_FLAGS | os.O_NOFOLLOW
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _Unreadable(f"{path.name} is a symlink") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Unreadable(f"{path.name} is not a regular file")
        if st.st_size > limit:
            raise _TooLarge(f"{path.name} is over {limit} bytes")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, limit + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise _TooLarge(f"{path.name} is over {limit} bytes")
        return b"".join(chunks)
    finally:
        os.close(fd)


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
    idents: list[NodeIdentity]          #: every verifying cert's identity
    keys: set[bytes]                    #: every verifying cert's public key (SPKI DER)
    others: list[tuple[Path, bytes]]    #: the rest, superseded by a renewal


class NonRegularEntries(OSError):
    """A PKI/node dir holds *.crt entries that are not regular files (links refused)."""

    def __init__(self, d: Path, entries: list[Path]) -> None:
        super().__init__(errno.EINVAL,
                         f"{d} {LINKS_REFUSED}: {', '.join(e.name for e in entries)}")
        self.dir, self.entries = d, entries


def _non_regular(d: Path) -> list[Path]:
    """The *.crt entries of ``d`` that are not regular files (symlinks included, never
    followed). An entry that cannot be lstat'd counts: it cannot be shown to be regular."""
    out: list[Path] = []
    for c in sorted(Path(d).glob("*.crt")):
        try:
            if not stat.S_ISREG(os.lstat(c).st_mode):
                out.append(c)
        except FileNotFoundError:
            continue
        except OSError:
            out.append(c)
    return out


def _find_current(pki_dir: Path, node_id: str,
                  anchor: CertAuthority | TrustAnchor | None = None, *,
                  skip_irregular: bool = False) -> _Current | None:
    """The node's verifying certs in ``pki_dir``, or None.

    ``grants`` is the intersection over every verifying cert for the node, the same rule
    :func:`blastbox.host.placement.fleet_grants` applies on the ingress, so a renewal can
    never restore a grant a narrower cert beside it is withholding.

    ``anchor`` None verifies against the dir's own ``ca.crt`` (the ingress serving its own
    certs). The CA host passes ITS OWN CA instead: a node dir is the ingress's to write,
    so its ``ca.crt`` may not decide what the real CA signs.

    PKI and node dirs must contain REGULAR files: a dir with any other *.crt entry (a
    symlink, FIFO, directory...) raises :class:`NonRegularEntries`, and nothing in it is
    followed or read. ``skip_irregular`` instead ignores those entries (used only to ask
    whether such a dir holds the node in a regular file).

    A cert that does not verify is skipped, but an OSError reading the anchor or a cert
    file PROPAGATES: "could not read" is a transient fault, not "has no certificate", and
    the caller must not turn it into a refusal that deletes the node's CSR.
    """
    d = Path(pki_dir)
    if not skip_irregular:
        bad = _non_regular(d)
        if bad:
            raise NonRegularEntries(d, bad)
    if anchor is None:
        try:
            anchor = load_trust_anchor(d)
        except OSError:
            raise
        except Exception:                               # noqa: BLE001 - garbled CA: verify nothing
            return None
    found: list[tuple[Path, bytes, NodeIdentity]] = []
    for crt in sorted(d.glob("*.crt")):
        try:
            # Bounded, no-follow, FIFO-safe: the dir may be someone else's to write.
            pem = _read_capped(crt, MAX_CERT_BYTES)    # OSError propagates (transient)
        except _TooLarge as exc:
            # May be one of the node's certs: dropping it could widen the intersection.
            raise OSError(errno.EFBIG, f"{crt}: {exc}; cannot judge the node") from None
        except _Unreadable:
            if skip_irregular:
                continue
            # Regular at the check, not at the read (swapped meanwhile): the dir holds a
            # non-regular entry after all -- never "no cert here".
            raise NonRegularEntries(d, [crt]) from None
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
                    idents=[f[2] for f in found],
                    keys={_spki(x509.load_pem_x509_certificate(f[1]).public_key())
                          for f in found},
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


#: How long a run waits for another holder of a node dir's lock before failing.
LOCK_TIMEOUT_S = 120.0


def _dirs(pki_dir: Path, node_dirs: list[Path] | None) -> list[Path]:
    """``pki_dir`` then ``node_dirs``, once each by REAL path: two spellings of one dir
    would otherwise be locked twice, and the second flock waits on the first forever."""
    out: dict[str, Path] = {}
    for p in [Path(pki_dir), *(Path(p) for p in node_dirs or [])]:
        out.setdefault(os.path.realpath(p), p)
    dirs = list(out.values())
    for d in dirs:
        # An unmounted mountpoint is an empty dir. Renewing or revoking "around" it would
        # leave that ingress with a stale or unrevoked cert, so fail the run instead.
        if not (d / "ca.crt").is_file():
            raise OSError(errno.ENOENT, f"{d} is not a PKI dir (no ca.crt) -- unmounted?")
    return dirs


#: How long revoke-node waits for one dir's lock before revoking it without (see revoke).
REVOKE_LOCK_WAIT_S = 5.0


@contextlib.contextmanager
def _locked(dirs: list[Path], timeout: float | None = None):
    """Hold every node dir's renewal lock (sorted, so two runs never deadlock).

    ALL of them for the whole run: a renewal writes certs into every dir where the node
    verifies, so a second run over an overlapping set must wait rather than interleave.
    Bounded by :data:`LOCK_TIMEOUT_S`, because a node dir is the ingress's to write and a
    lock it never releases must fail the run, not hang the timer and ``revoke-node``. The
    lock file is never followed through a symlink. An OSError (missing or stale mount, a
    held lock) propagates before anything is consumed.
    """
    with contextlib.ExitStack() as stack:
        for d in sorted(dirs, key=lambda p: os.path.realpath(p)):
            # In the PKI dir itself, not renew/: creating renew/ from the CA host could
            # leave the ingress a queue dir it does not own.
            fd = os.open(Path(d) / ".renew.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            stack.callback(os.close, fd)
            wait = LOCK_TIMEOUT_S if timeout is None else timeout
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OSError(errno.ETIMEDOUT,
                                      f"{d}: renewal lock held for over {wait:g}s")
                    time.sleep(0.05)
        yield


def sign_pending(ca: CertAuthority, pki_dir: Path, *, days: int = 7,
                 node_dirs: list[Path] | None = None) -> list[tuple[str, str]]:
    """Sign every queued CSR with its node's CURRENT grants. Returns (node_id, outcome).

    ``pki_dir`` holds the CA key. ``node_dirs`` are further PKI dirs whose certs authorise
    nodes and whose ``renew/`` queues an ingress writes -- on a split deployment, each
    ingress host's PKI dir made reachable on the CA host (the ingress never gets the CA
    key; the mount runs the other way). ``pki_dir`` is always one of them.

    A node's CURRENT state is taken over EVERY dir where it verifies: the new cert carries
    the intersection of all their grants and the WireGuard key (or none) of the most
    recently ISSUED of them -- mid-rotation the old-key cert is still valid, and the newest
    is the operator's intent -- and is written to every one of those dirs, so no ingress
    is ever widened by a renewal queued through another. It must verify in the dir that
    queued it, and the proof's key must be current in EVERY dir where it verifies: one
    ingress's copy of a cert is not evidence for the others. A dir where it does not
    verify -- revoked there -- is left alone. If any write fails, or a cert changed or
    vanished meanwhile, the CSR is kept and the next run redoes the whole renewal; a partly
    published one converges then (``pki_dir`` records it, see :data:`PUBLISHING_DIR`).

    Raises ValueError for an out-of-range ``days``, and OSError when a node dir cannot be
    locked (an unreachable mount), BEFORE touching any queue.
    """
    if not 1 <= days <= MAX_NODE_CERT_DAYS:
        raise ValueError(f"node cert lifetime must be 1..{MAX_NODE_CERT_DAYS} days, got {days}")
    every = _dirs(pki_dir, node_dirs)
    results: list[tuple[str, str]] = []
    with _locked(every):
        # PKI and node dirs must contain regular files: a dir with any other *.crt entry is
        # reported (the run exits 2); no cert entry in it is followed and no cert is written
        # there. (Its queue is still drained, so invalid entries are refused as anywhere.)
        bad = frozenset(d for d in every if _non_regular(d))
        for d in sorted(bad, key=str):
            names = ", ".join(e.name for e in _non_regular(d))
            results.append((f"<{d}>", f"deferred: {LINKS_REFUSED} ({names})"))
        for qdir in every:
            try:
                results += _drain(ca, qdir, days, every, bad, ledger=Path(pki_dir))
            except OSError as exc:
                # One queue going bad mid-run (a mount dropping) must not abort the others,
                # nor lose the outcomes already reached; say it, so the run exits 2.
                results.append((f"<{qdir}>", f"deferred: cannot read this queue: {exc}"))
    return results


def _open_queue(qdir: Path) -> int | None:
    """Pin ``qdir``'s ``renew/`` once, never through a link; None if there is no such dir.

    Everything after works relative to this descriptor: the ingress owns ``qdir`` and can
    swap ``renew/`` for a link to anywhere on the CA host at any moment.
    """
    try:
        return os.open(_renew_dir(qdir),
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return None                 # a queue linked out of the node dir is not ours
        raise


def _lstat_at(name: str, dfd: int) -> os.stat_result | None:
    try:
        return os.lstat(name, dir_fd=dfd)
    except FileNotFoundError:
        return None


def _drain(ca: CertAuthority, qdir: Path, days: int, every: list[Path],
           bad: frozenset[Path] = frozenset(), *, ledger: Path | None = None
           ) -> list[tuple[str, str]]:
    """Sign what ``qdir``'s ingress queued.

    A CSR being worked on is ``<id>.csr.signing``, and it is never renamed back: a kept
    one (transient fault, crash) simply stays and is retried next run, and a newer
    ``<id>.csr`` the node queued meanwhile replaces it then. So no step ever writes onto
    a name the ingress may be writing, which needs no hard links and has no window.
    """
    results: list[tuple[str, str]] = []
    dfd = _open_queue(qdir)
    if dfd is None:
        return results
    try:
        names = os.listdir(dfd)
        ids = sorted({n[:-len(".csr")] for n in names if n.endswith(".csr")}
                     | {n[:-len(".csr.signing")] for n in names if n.endswith(".csr.signing")})
        for node_id in ids:
            csr_name, aside = f"{node_id}.csr", f"{node_id}.csr.signing"
            try:
                linked = [n for n in (csr_name, aside)
                          if (st := _lstat_at(n, dfd)) is not None and stat.S_ISLNK(st.st_mode)]
                for name in linked:             # never read or move through a link,
                    os.unlink(name, dir_fd=dfd)  # but a kept retry is not lost to one
                if _lstat_at(csr_name, dfd) is not None:
                    # newest wins over a kept older one
                    os.replace(csr_name, aside, src_dir_fd=dfd, dst_dir_fd=dfd)
                if linked and _lstat_at(aside, dfd) is None:
                    results.append((node_id, f"refused: {linked[0]} is a symlink"))
                    continue
                raw = _read_capped(Path(aside), MAX_QUEUE_ENTRY_BYTES, dir_fd=dfd)
            except _Unreadable as exc:          # FIFO, device, dir, oversized, link: refuse it
                _discard(aside, dfd)
                results.append((node_id, f"refused: {exc}"))
                continue
            except OSError as exc:              # say it, so the run exits 2 and is seen
                results.append((node_id, f"deferred: cannot read the queued CSR: {exc}"))
                continue
            try:
                csr_pem, proof_key = _verified_entry(ca, node_id, raw)
            except RenewRefused as exc:
                _discard(aside, dfd)
                results.append((node_id, f"refused: {exc}"))
                continue
            outcome, keep = _renew_one(ca, qdir, every, node_id, csr_pem, days, proof_key, bad,
                                       ledger=ledger if ledger is not None else every[0])
            if not keep:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(aside, dir_fd=dfd)
            results.append((node_id, outcome))
    finally:
        os.close(dfd)
    return results


def _verified_entry(ca: CertAuthority, node_id: str, raw: bytes) -> tuple[bytes, bytes]:
    """The CSR of a queue entry whose proof verifies against the REAL CA, or refuse.

    Everything is checked again here: the queue lives in the ingress's dir, and the
    ingress may be hostile. A legacy bare-PEM entry (no proof) is refused.
    """
    if raw.lstrip().startswith(b"-----BEGIN"):
        raise RenewRefused("legacy queue entry without a proof of possession")
    try:
        doc = json.loads(raw)
        csr_text, cert_text = doc["csr_pem"], doc["cert_pem"]
        issued_at, sig = doc["issued_at"], doc["signature"]
        if not all(isinstance(v, str) for v in (csr_text, cert_text, sig)):
            raise TypeError
    except (ValueError, KeyError, TypeError, RecursionError):   # deep nesting: RecursionError
        raise RenewRefused("malformed queue entry") from None
    try:
        verify_renew_proof(ca, node_id, csr_text, cert_text, issued_at, sig,
                           now=time.time(), max_skew=RENEW_PROOF_MAX_AGE_S)
        proof_key = _spki(x509.load_pem_x509_certificate(cert_text.encode()).public_key())
    except RenewRefused:
        raise
    except Exception as exc:                            # noqa: BLE001 - hostile input
        raise RenewRefused(f"malformed queue entry ({type(exc).__name__})") from None
    return csr_text.encode("utf-8"), proof_key


def _discard(name: str, dfd: int) -> None:
    """Remove a refused queue entry (in the pinned queue ``dfd``), whatever it is; never
    raise (a planted directory must not crash the run and starve every other queue)."""
    try:
        st = _lstat_at(name, dfd)
        if st is None:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=dfd, ignore_errors=True)
        else:
            os.unlink(name, dir_fd=dfd)
    except OSError:
        pass


def _swap_if_unchanged(path: Path, expected: bytes, new: bytes) -> str | None:
    """Replace ``path`` with ``new`` if it still holds ``expected``; else say why not."""
    try:
        still = _read_capped(path, MAX_CERT_BYTES)
    except FileNotFoundError:
        return "removed"
    except _Unreadable:
        return "changed"
    if still != expected:
        return "changed"
    _replace_file(path, new)
    return None


def _publishing_path(ledger: Path, node_id: str) -> Path:
    return Path(ledger) / PUBLISHING_DIR / f"{node_id}.json"


def _publishing_keys(ledger: Path, node_id: str, now: float) -> tuple[set[bytes], int | None]:
    """The keys an unfinished publication links for ``node_id`` and when it began, or
    (empty, None) if there is none (or it is older than :data:`PUBLISHING_TTL_S`).

    The record is the CA host's own, so damage to it is a fault (OSError), not "none"."""
    path = _publishing_path(ledger, node_id)
    try:
        raw = _read_capped(path, MAX_QUEUE_ENTRY_BYTES)
    except FileNotFoundError:
        return set(), None
    except _Unreadable as exc:
        raise OSError(errno.EINVAL, f"{path}: {exc}") from None
    try:
        doc = json.loads(raw)
        since = doc["since"]
        if not isinstance(since, int) or isinstance(since, bool):
            raise TypeError
        keys = {bytes.fromhex(k) for k in doc["keys"]}
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise OSError(errno.EINVAL, f"{path} is not a publication record") from None
    if not 0 <= now - since <= PUBLISHING_TTL_S:
        return set(), None
    return keys, since


def _record_publishing(ledger: Path, node_id: str, keys: set[bytes], since: int) -> None:
    d = Path(ledger) / PUBLISHING_DIR
    d.mkdir(mode=0o700, exist_ok=True)
    _replace_file(_publishing_path(ledger, node_id),
                  json.dumps({"keys": sorted(k.hex() for k in keys), "since": since}).encode())


def _renew_one(ca: CertAuthority, qdir: Path, every: list[Path], node_id: str,
               csr_pem: bytes, days: int, proof_key: bytes,
               bad: frozenset[Path] = frozenset(), *,
               ledger: Path | None = None) -> tuple[str, bool]:
    """Renew one set-aside CSR across every node dir. Returns (outcome, keep the CSR).

    The proof's key must be current in EVERY dir where the node verifies. Any one dir is
    an ingress's to write, so its copy of a cert proves nothing about the others: a hostile
    ingress could restore a revoked-then-re-enrolled node's old, still unexpired cert and
    have its old key overwrite the honest dirs. The one exception is a renewal published
    to some dirs but not yet all: the CA host records, in its OWN dir (``ledger``, the
    ``pki_dir`` holding the CA key), that the old and new key are the same node's, so the
    retry -- or a renewal by the node's new key -- can finish the job. The record expires
    after :data:`PUBLISHING_TTL_S` and goes once publication completes.
    """
    ledger = Path(ledger) if ledger is not None else Path(every[0])
    now = int(time.time())
    states: dict[Path, _Current] = {}
    linked: set[bytes] = set()
    since: int | None = None
    try:
        for d in every:
            if d in bad:
                # Nothing in a dir with non-regular cert entries is followed or trusted. If
                # it holds the node in a regular file (or queued it), the node's renewal
                # waits for the operator; otherwise it is simply not written.
                if d == qdir or _find_current(d, node_id, anchor=ca,
                                              skip_irregular=True) is not None:
                    return f"deferred: {d} {LINKS_REFUSED}", True
                continue
            cur = _find_current(d, node_id, anchor=ca)
            if cur is not None:
                states[d] = cur
        if qdir in states:
            linked, since = _publishing_keys(ledger, node_id, now)
    except OSError as exc:
        return f"deferred: {exc}", True
    if qdir not in states:
        return "refused: no current certificate", False

    def current(cur: _Current) -> set[bytes]:
        return cur.keys | linked if cur.keys & linked else cur.keys
    lacking = [d for d, cur in states.items() if proof_key not in current(cur)]
    if qdir in lacking:
        # CA-valid but not a key the node holds NOW where it asked: an old key after a
        # revoke-and-re-enrol, or a copy of something no longer current.
        return "refused: proof certificate is not the node's current certificate", False
    if lacking:
        # Current where it was queued but not elsewhere: that ingress disagrees with the
        # rest (an operator who copied a cert to some dirs only, or a restored old one).
        return ("deferred: proof certificate is not the node's current certificate in "
                + ", ".join(str(d) for d in lacking)), True
    grants: NodeGrants | None = None
    for cur in states.values():
        grants = _intersect(grants, cur.grants)
    assert grants is not None
    idents = [i for cur in states.values() for i in cur.idents]
    latest = max(i.not_before for i in idents)
    keys = {i.wg_pubkey for i in idents if i.not_before == latest}
    if len(keys) != 1:
        # Issued in the same second (X.509 has one-second resolution) with different
        # keys: which is newer is unknowable, and guessing could restore the old key.
        return ("deferred: certificates issued in the same second disagree about the "
                "WireGuard key; remove the stale one"), True
    try:
        new = ca.sign_node_csr(csr_pem, node_id=node_id, grants=grants, days=days,
                               wg_pubkey=next(iter(keys)))
    except ValueError as exc:
        return f"refused: {exc}", False
    new_key = _spki(x509.load_pem_x509_certificate(new).public_key())
    try:
        # BEFORE the first write: if publication stops part-way, the next run must know the
        # new key and the proof's are the same node's.
        _record_publishing(ledger, node_id, linked | {proof_key, new_key},
                           since if since is not None else now)
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
                    if _read_capped(path, MAX_CERT_BYTES) == pem:
                        path.unlink()
                except (FileNotFoundError, _Unreadable):
                    pass
        _publishing_path(ledger, node_id).unlink(missing_ok=True)   # published everywhere
    except OSError as exc:
        return f"deferred: {exc}", True
    return "renewed", False


class PartialRevoke(OSError):
    """Revocation did what it could but not everything: see ``unlocked`` / ``failed``."""

    def __init__(self, removed: list[Path], unlocked: list[Path],
                 failed: list[tuple[Path, str]]) -> None:
        bits = [f"{d}: revoked WITHOUT its lock (held by someone else)" for d in unlocked]
        bits += [f"{d}: NOT revoked: {why}" for d, why in failed]
        super().__init__(errno.EIO, "; ".join(bits))
        self.removed, self.unlocked, self.failed = removed, unlocked, failed


def revoke(pki_dir: Path, node_id: str, *, node_dirs: list[Path] | None = None) -> list[Path]:
    """Revoke ``node_id``: delete its certs and queued CSRs in every node dir.

    Revocation must not be blockable, and must not lose to a renewal in flight. So each
    dir is revoked at once -- under its lock if that comes within
    :data:`REVOKE_LOCK_WAIT_S`, else without it -- and every dir revoked without its lock
    is then revoked AGAIN once its lock is had (waiting up to :data:`LOCK_TIMEOUT_S`): if
    the holder was a renewal that wrote the cert back, the second pass removes it. A dir
    whose lock never comes (a hostile ingress can hold its own; it can also rewrite its
    own dir at will) or that cannot be revoked at all is reported by
    :class:`PartialRevoke`; the others are revoked regardless. Certs are matched by verifying them (expired ones too) against ``pki_dir``'s
    CA, never a node dir's own ``ca.crt``. Returns the cert files removed.
    Raises ValueError for a malformed node id, OSError for an unreadable CA.
    """
    if not _PKI_NODE_ID.match(node_id):
        raise ValueError(f"invalid node id {node_id!r}")
    anchor = load_trust_anchor(Path(pki_dir))
    out: dict[str, Path] = {}
    for p in [Path(pki_dir), *(Path(p) for p in node_dirs or [])]:
        out.setdefault(os.path.realpath(p), p)
    removed: list[Path] = []
    unlocked: list[Path] = []
    errors_by_dir: dict[Path, list[str]] = {}
    failed: list[tuple[Path, str]] = []

    def one(d: Path, wait: float) -> bool:
        """Revoke ``d``, under its lock if it comes within ``wait``. One lock at a time,
        released before the next: holding one while waiting for another would break the
        sorted order renew-pending locks in, and the two would wait on each other."""
        try:
            with _locked([d], timeout=wait):
                gone, errs = _revoke_in(anchor, d, node_id)
                got = True
        except OSError:                       # the lock did not come: revoke anyway
            gone, errs = _revoke_in(anchor, d, node_id)
            got = False
        removed.extend(g for g in gone if g not in removed)
        errors_by_dir[d] = errs               # the latest pass is what stands
        return got

    for d in sorted(out.values(), key=lambda p: os.path.realpath(p)):
        if not (d / "ca.crt").is_file():
            failed.append((d, "not a PKI dir (no ca.crt) -- unmounted?"))
            continue
        bad = _non_regular(d)
        if bad:
            # Never follow them -- but still revoke the node's REGULAR certs here (the
            # ingress authorises through those), and report the dir: a link may hold it too.
            failed.append((d, f"{LINKS_REFUSED} ({', '.join(e.name for e in bad)}); "
                              "its regular certs were revoked, the links were not followed"))
        if not one(d, REVOKE_LOCK_WAIT_S):
            unlocked.append(d)
    for d in list(unlocked):                  # second pass, now waiting for the lock
        if one(d, LOCK_TIMEOUT_S):
            unlocked.remove(d)
    failed += [(d, why) for d, errs in errors_by_dir.items() for why in errs]
    try:            # an unfinished publication no longer links anything for this node
        _publishing_path(Path(pki_dir), node_id).unlink(missing_ok=True)
    except OSError as exc:
        failed.append((Path(pki_dir), f"{PUBLISHING_DIR}/: {exc.strerror or exc}"))
    if unlocked or failed:
        raise PartialRevoke(removed, unlocked, failed)
    return removed


def _revoke_in(anchor: TrustAnchor, d: Path, node_id: str) -> tuple[list[Path], list[str]]:
    """Revoke in one dir, file by file: one unreadable file must not shield the rest."""
    removed: list[Path] = []
    errors: list[str] = []
    try:
        certs = sorted(d.glob("*.crt"))
    except OSError as exc:
        return removed, [str(exc)]
    for crt in certs:
        try:
            pem = _read_capped(crt, MAX_CERT_BYTES)      # regular files only, no follow
            if node_identity(anchor, pem, allow_expired=True).node_id != node_id:
                continue
            crt.unlink()
            removed.append(crt)
        except _Unreadable as exc:               # appeared since the check: say so, never skip
            errors.append(f"{exc} (not checked)")
        except (ValueError, FileNotFoundError):  # not a cert / gone meanwhile
            continue
        except OSError as exc:                   # cannot tell: it MAY be the node's
            errors.append(f"{crt.name}: {exc.strerror or exc}")
    try:
        dfd = _open_queue(d)            # pinned: never through a renew/ swapped for a link
        if dfd is not None:
            try:
                for name in (f"{node_id}.csr", f"{node_id}.csr.signing"):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=dfd)
            finally:
                os.close(dfd)
    except OSError as exc:
        errors.append(f"renew/: {exc.strerror or exc}")
    return removed, errors
