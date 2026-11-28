"""Quarantine spool for a node's uploaded result tar (no FastAPI in here).

The ingress that receives a node's result NEVER holds the attest key and NEVER trust-gates:
it only extracts the tar, safely, into a spool and leaves a marker. A separate
``node-finalizer`` process (different privilege) reads the spool, runs the trust gate and
seals. Keeping the two apart means a bug in tar handling cannot reach the signing key.

Layout, per (job, claim)::

    <root>/<job_id>/<claim_digest>/out/          the extracted tree
    <root>/<job_id>/<claim_digest>/upload.json   marker, written LAST (inside the dir before
                                                 it is renamed into place, so the final dir
                                                 never exists without it)
    <root>/<job_id>/<claim_digest>/outcome.json  written by the finalizer

``claim_digest = sha256(claim_id)[:16]``. Directories are 0700 and files 0600 for the ingress
user; the finalizer runs as the same uid in a different container.
"""
from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
import tarfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

RESULTS_ENV = "BLASTBOX_NODE_RESULTS_DIR"
MARKER = "upload.json"
OUTCOME = "outcome.json"
OUT = "out"
# The finalizer's outcome reason when the blob upload failed and the sealed tree was retained
# for the pending-upload sweep. Not final: that sweep may later repair the job to DONE.
RETAINED_REASON = "result upload failed; tree retained"


class TarRejected(ValueError):
    """The uploaded tar is not an acceptable result tree; nothing was extracted."""


def results_root(job_root: Path | str) -> Path:
    env = os.environ.get(RESULTS_ENV)
    root = Path(env) if env else Path(job_root) / ".node-results"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root.chmod(0o700)           # mkdir leaves a pre-existing root as it was
    except OSError:
        pass
    return root


def claim_digest(claim_id: str) -> str:
    return hashlib.sha256(claim_id.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def spool_dir(root: Path, job_id: str, claim_id: str) -> Path:
    return root / job_id / claim_digest(claim_id)


def stream_cap(*, max_artifact_total: int, max_metadata: int, max_artifacts: int) -> int:
    """Raw tar-stream ceiling: artifacts + metadata + per-member header slack (the push path's)."""
    return int(max_artifact_total * 1.1) + max_metadata + max_artifacts * 1024 + 65536


@dataclass
class UploadMarker:
    job_id: str
    claim_id: str
    node_id: str
    node_cert_sha256: str
    worker_runtime: str | None
    received_at: float
    started_at_ms: int | None
    finished_at_ms: int | None


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}-{time.monotonic_ns()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def fsync_tree(top: Path) -> None:
    """fsync every regular file and directory under ``top`` (and ``top`` itself), so a tree
    the ingress is about to acknowledge survives a crash. Never follows symlinks."""
    for dirpath, _dirs, files in os.walk(top, followlinks=False):
        for name in files:
            fd = os.open(os.path.join(dirpath, name), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        fsync_dir(Path(dirpath))


def fsync_dir(d: Path) -> None:
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# A FILE, flock'd. Not ".claim": an earlier build used <digest>.claim as a lock DIRECTORY,
# and opening one of those as a file would turn every PUT for that claim into a 500.
UPLOAD_LOCK_SUFFIX = ".ulock"


class UploadLock:
    """The one-extraction-per-(job, claim) lock: an ``flock`` on a file next to the spool dir.

    The kernel drops an flock when its holder dies, so there is no age threshold to guess
    and nothing ever "breaks" a live lock: a slow upload is never mistaken for a crashed one,
    and two waiters can never both end up holding it. ``release`` unlinks the file WHILE
    still holding it; ``try_acquire`` then re-checks that the path still names the inode it
    locked, so a waiter that opened the old (now unlinked) inode cannot win a dead lock while
    a newcomer holds the live one.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def try_acquire(self) -> bool:
        for _ in range(3):
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            except FileNotFoundError:
                # the finalizer's sweep rmdirs an EMPTY job dir; put it back and retry
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                return False
            try:
                same = os.stat(self.path, follow_symlinks=False).st_ino == os.fstat(fd).st_ino
            except FileNotFoundError:
                same = False
            if same:
                self._fd = fd
                return True
            os.close(fd)                    # we locked an inode its holder already unlinked
        return False

    def held_elsewhere(self) -> bool:
        if self.try_acquire():
            self.release()
            return False
        return True

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            os.unlink(self.path)
        except OSError:
            pass
        finally:
            os.close(fd)


def write_marker(d: Path, marker: UploadMarker) -> None:
    _atomic_write(d / MARKER, dataclasses.asdict(marker))


def read_marker(d: Path) -> UploadMarker | None:
    try:
        raw = json.loads((d / MARKER).read_text())
        return UploadMarker(**raw)
    except (OSError, ValueError, TypeError):
        return None


def write_outcome(d: Path, status: str, reason: str | None) -> None:
    _atomic_write(d / OUTCOME, {"status": status, "reason": reason})


def read_outcome(d: Path) -> dict[str, Any] | None:
    try:
        v = json.loads((d / OUTCOME).read_text())
    except (OSError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def pending(root: Path) -> Iterator[Path]:
    """Spool dirs that carry a marker and no outcome yet."""
    try:
        jobs = sorted(root.iterdir())
    except OSError:
        return
    for jd in jobs:
        if not jd.is_dir():
            continue
        try:
            claims = sorted(jd.iterdir())
        except OSError:
            continue
        for cd in claims:
            if ".partial" in cd.name or not cd.is_dir():
                continue
            if (cd / MARKER).is_file() and not (cd / OUTCOME).is_file():
                yield cd


# A pax ('x'/'g') or GNU long-name/long-link ('L'/'K') record is read WHOLE into memory by
# tarfile before any member is yielded, so its size must be bounded before tarfile reads it.
MAX_EXTENDED_HEADER = 64 * 1024
MAX_EXTENDED_CHAIN = 4
_EXTENDED_TYPES = frozenset({tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                             tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK})


class _BoundedTarInfo(tarfile.TarInfo):
    """Refuses an oversized extended header record and a GNU sparse member at the moment
    tarfile reaches it in ITS OWN header walk, before it reads the record. A separate raw
    prescan cannot do this: tarfile ignores a directory's size field and applies a pax
    ``size=`` override to the next member, so any independent walk can be steered onto a
    different chain than the one tarfile parses."""

    def _proc_member(self, tarfile_obj: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise TarRejected(f"sparse member refused: {self.name!r}")
        if self.type == tarfile.XGLTYPE:
            # tarfile keeps every global key for the rest of the archive and copies the whole
            # set into each later pax member: small records multiply into gigabytes.
            raise TarRejected("global pax header refused")
        if self.type in _EXTENDED_TYPES:
            if self.size > MAX_EXTENDED_HEADER:
                raise TarRejected(f"extended header record of {self.size} bytes refused")
            # tarfile recurses once per consecutive extended header before the member they
            # describe; a legitimate member needs at most L + K + x.
            depth = getattr(tarfile_obj, "_bb_ext_chain", 0) + 1
            if depth > MAX_EXTENDED_CHAIN:
                raise TarRejected(f"more than {MAX_EXTENDED_CHAIN} chained extended headers")
            tarfile_obj._bb_ext_chain = depth   # type: ignore[attr-defined]
        else:
            tarfile_obj._bb_ext_chain = 0       # type: ignore[attr-defined]
        return super()._proc_member(tarfile_obj)  # type: ignore[misc]  # private, stable 3.8-3.13

    # A PAX sparse member (GNU formats 0.0 / 0.1 / 1.0) has its map decoded inside _proc_pax,
    # while the header is parsed and BEFORE the member is yielded: 1.0 reads the map from the
    # data blocks, so a small archive materialises an unbounded list. tarfile calls these on
    # the extended header's TarInfo (this class), so refusing here runs before any map parse.
    def _proc_gnusparse_00(self, *_a: Any, **_k: Any) -> None:
        raise TarRejected("PAX sparse member refused (GNU sparse 0.0)")

    def _proc_gnusparse_01(self, *_a: Any, **_k: Any) -> None:
        raise TarRejected("PAX sparse member refused (GNU sparse 0.1)")

    def _proc_gnusparse_10(self, *_a: Any, **_k: Any) -> None:
        raise TarRejected("PAX sparse member refused (GNU sparse 1.0)")


def vet_tar(fileobj: Any, *, max_members: int, max_total_bytes: int,
            max_metadata_bytes: int | None = None) -> None:
    """Reject the WHOLE tar on anything that is not a plain file or directory.

    ``_safe_extract_tar`` skips symlinks, devices and traversal members rather than refusing
    them; a result that tries those is hostile, so it is refused up front. Also requires a
    root ``metadata.json``, no duplicate names, no sparse members (a tiny upload that expands
    to the whole byte budget on disk), bounded extended headers, and bounded member count /
    declared bytes. ``metadata.json`` has its own cap and does not count toward the artifact
    total, exactly as ``_safe_extract_tar`` and the cold trust gate count it.
    """
    seen: set[str] = set()
    # every filesystem entry extraction will create: explicit members AND the missing parents
    # _safe_extract_tar makes for them, so deep paths cannot multiply inodes past the cap
    entries: set[str] = set()
    meta_regular = False
    count = 0
    total = 0
    try:
        fileobj.seek(0)
        with tarfile.open(fileobj=fileobj, mode="r:",          # "r:" refuses gz/bz2/xz
                          tarinfo=_BoundedTarInfo) as tf:
            for m in tf:
                count += 1
                if count > max_members:
                    raise TarRejected(f"more than {max_members} members")
                if m.issparse():
                    raise TarRejected(f"sparse member refused: {m.name!r}")
                if m.issym() or m.islnk() or m.isdev() or m.isfifo() or not (m.isfile() or m.isdir()):
                    raise TarRejected(f"disallowed member type: {m.name!r}")
                name = m.name
                if not name or name.startswith("/") or "\\" in name or "\x00" in name:
                    raise TarRejected(f"bad member path: {name!r}")
                parts = PurePosixPath(name).parts
                if ".." in parts:
                    raise TarRejected(f"parent reference in member path: {name!r}")
                norm = "/".join(p for p in parts if p != ".")
                if not norm:
                    continue            # the "./" root entry
                if norm in seen:
                    raise TarRejected(f"duplicate member: {norm!r}")
                seen.add(norm)
                npart = norm.split("/")
                for i in range(1, len(npart) + 1):
                    entries.add("/".join(npart[:i]))
                if len(entries) > max_members:
                    raise TarRejected(f"more than {max_members} members, counting the "
                                      "directories extraction creates")
                if norm == "metadata.json" and m.isfile():
                    meta_regular = True
                    if max_metadata_bytes is not None and m.size > max_metadata_bytes:
                        raise TarRejected("metadata.json exceeds the metadata cap")
                elif m.isfile():
                    total += m.size
                    if total > max_total_bytes:
                        raise TarRejected("declared size exceeds the byte cap")
    except tarfile.TarError as exc:
        raise TarRejected(f"unreadable tar: {exc}") from exc
    if not meta_regular:
        raise TarRejected("metadata.json missing at the root, or not a regular file")
    fileobj.seek(0)


def node_cert_sha256(pki_dir: Path, node_id: str) -> str | None:
    """sha256 (hex) of the DER of the verifying cert for ``node_id`` with the latest not_after."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from blastbox.host.pki import load_trust_anchor, node_identity

    try:
        ca = load_trust_anchor(Path(pki_dir))
    except Exception:                                   # noqa: BLE001 - no CA verifies nothing
        return None
    best: tuple[Any, bytes] | None = None
    for crt in sorted(Path(pki_dir).glob("*.crt")):
        try:
            pem = crt.read_bytes()
            ident = node_identity(ca, pem)
        except Exception:                               # noqa: BLE001
            continue
        if ident.node_id != node_id:
            continue
        if best is None or ident.not_after > best[0]:
            der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
            best = (ident.not_after, der)
    return hashlib.sha256(best[1]).hexdigest() if best else None
