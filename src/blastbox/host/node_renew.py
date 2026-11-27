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


#: Upper bound on a cert file the CA host reads from a node dir. Real ones are ~1 KiB,
#: but grants make them grow, so this is generous; revoke REPORTS anything larger.
MAX_CERT_BYTES = 1024 * 1024


class _Unreadable(ValueError):
    """Not a file this code will read: a FIFO, device, link, or oversized."""


class _TooLarge(_Unreadable):
    """A regular file over the read cap: possibly a real cert, so never silently ignored."""



def _read_capped(path: Path, limit: int, *, follow: bool = False) -> bytes:
    """Read a small REGULAR file without following a link or blocking on a FIFO.

    A node dir is the ingress's to write, so the CA host checks what it opened (fstat on
    the same descriptor, no check-then-open window) and never reads more than ``limit``.
    """
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW)
        fd = os.open(path, flags)
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
    others: list[tuple[Path, bytes]]    #: the rest, superseded by a renewal


def _links_out(crt: Path, d: Path) -> bool:
    """True if ``crt`` is a symlink resolving outside ``d`` (or not resolving at all)."""
    if not crt.is_symlink():
        return False
    try:
        return Path(os.path.realpath(crt)).parent != Path(os.path.realpath(d))
    except OSError:
        return True


def _find_current(pki_dir: Path, node_id: str,
                  anchor: CertAuthority | TrustAnchor | None = None) -> _Current | None:
    """The node's verifying certs in ``pki_dir``, or None.

    ``grants`` is the intersection over every verifying cert for the node, the same rule
    :func:`blastbox.host.placement.fleet_grants` applies on the ingress, so a renewal can
    never restore a grant a narrower cert beside it is withholding.

    ``anchor`` None verifies against the dir's own ``ca.crt`` (the ingress serving its own
    certs). The CA host passes ITS OWN CA instead: a node dir is the ingress's to write,
    so its ``ca.crt`` may not decide what the real CA signs.

    A cert that does not verify is skipped, but an OSError reading the anchor or a cert
    file PROPAGATES: "could not read" is a transient fault, not "has no certificate", and
    the caller must not turn it into a refusal that deletes the node's CSR.
    """
    d = Path(pki_dir)
    strict = anchor is not None
    if anchor is None:
        try:
            anchor = load_trust_anchor(d)
        except OSError:
            raise
        except Exception:                               # noqa: BLE001 - garbled CA: verify nothing
            return None
    found: list[tuple[Path, bytes, NodeIdentity]] = []
    for crt in sorted(d.glob("*.crt")):
        if strict and _links_out(crt, d):
            continue
        try:
            # OSError propagates (transient). Strict: the dir is someone else's to write,
            # so bounded and FIFO-safe. A symlinked cert is followed only WITHIN its dir:
            # resolved on the CA host, a link out of it can reach a cert the ingress itself
            # never sees (another ingress's mount), which must not authorise anything here.
            # Writing replaces the link, never its target.
            pem = (_read_capped(crt, MAX_CERT_BYTES, follow=True) if strict
                   else crt.read_bytes())
        except _Unreadable:
            continue                                    # FIFO, device, huge: not a cert
        except FileNotFoundError:
            if strict:
                continue                                # a dangling link is not a cert
            raise
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
    queued it. A dir where it does not verify -- revoked there -- is left alone. If any
    write fails, or a cert changed or vanished meanwhile, the CSR is kept and the next
    run redoes the whole renewal; a partly published one converges then.

    Raises ValueError for an out-of-range ``days``, and OSError when a node dir cannot be
    locked (an unreachable mount), BEFORE touching any queue.
    """
    if not 1 <= days <= MAX_NODE_CERT_DAYS:
        raise ValueError(f"node cert lifetime must be 1..{MAX_NODE_CERT_DAYS} days, got {days}")
    every = _dirs(pki_dir, node_dirs)
    results: list[tuple[str, str]] = []
    with _locked(every):
        for qdir in every:
            results += _drain(ca, qdir, days, every)
    return results


def _drain(ca: CertAuthority, qdir: Path, days: int,
           every: list[Path]) -> list[tuple[str, str]]:
    """Sign what ``qdir``'s ingress queued.

    A CSR being worked on is ``<id>.csr.signing``, and it is never renamed back: a kept
    one (transient fault, crash) simply stays and is retried next run, and a newer
    ``<id>.csr`` the node queued meanwhile replaces it then. So no step ever writes onto
    a name the ingress may be writing, which needs no hard links and has no window.
    """
    d = _renew_dir(qdir)
    results: list[tuple[str, str]] = []
    if d.is_symlink() or not d.is_dir():
        return results                  # a queue linked out of the node dir is not ours
    ids = sorted({p.name[:-len(".csr")] for p in d.glob("*.csr")}
                 | {p.name[:-len(".csr.signing")] for p in d.glob("*.csr.signing")})
    for node_id in ids:
        csr_path, aside = d / f"{node_id}.csr", d / f"{node_id}.csr.signing"
        try:
            linked = [p.name for p in (csr_path, aside) if p.is_symlink()]
            for name in linked:                 # never read or move through a link,
                (d / name).unlink()             # but a kept retry is not lost to one
            if csr_path.exists():
                os.replace(csr_path, aside)     # newest wins over a kept older one
            if linked and not aside.exists():
                results.append((node_id, f"refused: {linked[0]} is a symlink"))
                continue
            csr_pem = _read_capped(aside, MAX_CSR_BYTES)
        except _Unreadable as exc:              # FIFO, device, dir, oversized, link: refuse it
            _discard(aside)
            results.append((node_id, f"refused: {exc}"))
            continue
        except OSError as exc:                  # say it, so the run exits 2 and is seen
            results.append((node_id, f"deferred: cannot read the queued CSR: {exc}"))
            continue
        outcome, keep = _renew_one(ca, qdir, every, node_id, csr_pem, days)
        if not keep:
            aside.unlink(missing_ok=True)
        results.append((node_id, outcome))
    return results


def _discard(path: Path) -> None:
    """Remove a refused queue entry, whatever it is; never raise (a planted directory
    must not crash the run and starve every other queue)."""
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def _swap_if_unchanged(path: Path, expected: bytes, new: bytes) -> str | None:
    """Replace ``path`` with ``new`` if it still holds ``expected``; else say why not."""
    try:
        still = _read_capped(path, MAX_CERT_BYTES, follow=True)   # the link, as judged
    except FileNotFoundError:
        return "removed"
    except _Unreadable:
        return "changed"
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
            cur = _find_current(d, node_id, anchor=ca)
            if cur is not None:
                states[d] = cur
    except OSError as exc:
        return f"deferred: {exc}", True
    if qdir not in states:
        if any(_links_out(c, qdir) for c in qdir.glob("*.crt")):
            # Kept and loud (exit 2), not refused: the ingress may be authorising the node
            # through that link, and the fix -- a file instead of the link -- is the
            # operator's, after which the next run renews.
            return ("deferred: no current certificate here; a cert linked from outside its "
                    "node dir does not count -- replace the link with the file"), True
        return "refused: no current certificate", False
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
                    if _read_capped(path, MAX_CERT_BYTES, follow=True) == pem:
                        path.unlink()
                except (FileNotFoundError, _Unreadable):
                    pass
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
        if not one(d, REVOKE_LOCK_WAIT_S):
            unlocked.append(d)
    for d in list(unlocked):                  # second pass, now waiting for the lock
        if one(d, LOCK_TIMEOUT_S):
            unlocked.remove(d)
    failed += [(d, why) for d, errs in errors_by_dir.items() for why in errs]
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
        # A symlinked cert is FOLLOWED here (the ingress follows it too, so it authorises
        # the node), and only the link is removed, never its target.
        try:
            pem = _read_capped(crt, MAX_CERT_BYTES, follow=True)
            if node_identity(anchor, pem, allow_expired=True).node_id != node_id:
                continue
            crt.unlink()
            removed.append(crt)
        except _TooLarge as exc:                 # may be the node's: say so, never skip
            errors.append(f"{exc} (not checked)")
        except (ValueError, FileNotFoundError):  # not a cert / a dangling link
            continue
        except OSError as exc:                   # cannot tell: it MAY be the node's
            errors.append(f"{crt.name}: {exc.strerror or exc}")
    q = _renew_dir(d)
    try:
        if q.is_dir() and not q.is_symlink():
            for name in (f"{node_id}.csr", f"{node_id}.csr.signing"):
                (q / name).unlink(missing_ok=True)
    except OSError as exc:
        errors.append(f"renew/: {exc.strerror or exc}")
    return removed, errors
