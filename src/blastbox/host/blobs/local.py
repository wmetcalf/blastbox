"""LocalBlobStore — the default backend, a REAL filesystem-backed store.

``job_root`` stays the per-job working set in every mode (Firecracker bind-mounts
need a real path), but it is purely EPHEMERAL scratch: the worker purge
(``vm_dispatch._purge_job_dir``) destroys it wholesale on every terminal path. So
this store's durable copies live under a separate ``blob_root``, mirroring
``S3BlobStore``'s key layout:

  ``<blob_root>/samples/<sha256>``      content-addressed, SHARED between jobs
  ``<blob_root>/results/<job_id>/...``  job-scoped

That is what makes re-materialisation always possible after a purge, which is what
makes the purge unconditional (no "am I colocated with my peers?" branch in the
dispatcher) safe in single-node mode too.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import threading
import uuid
from pathlib import Path
from typing import BinaryIO

from blastbox.host.blobs.base import BlobFetchError, BlobIntegrityError

_CHUNK = 1024 * 1024


class LocalBlobStore:
    def __init__(self, job_root: Path | str, blob_root: Path | str | None = None) -> None:
        self._job_root = Path(job_root)
        # Default: a `blobs` dir sibling to job_root — deliberately OUTSIDE it, so
        # destroying job_root (the purge) never touches durable bytes.
        self._blob_root = Path(blob_root) if blob_root is not None else self._job_root.parent / "blobs"

    def _sample_path(self, sha256: str) -> Path:
        return self._blob_root / "samples" / sha256

    def _results_dir(self, job_id: str) -> Path:
        return self._blob_root / "results" / job_id

    @staticmethod
    def _atomic_copy(src: Path, dest: Path) -> None:
        """Copy *src* -> *dest* via a temp file in the same dir + atomic rename, so a
        crash mid-copy can never leave a truncated blob that a later read would trust.

        The temp name includes a per-call uuid4 (plus the thread id, belt-and-braces)
        rather than just the PID: two threads in the SAME process can race to
        ``put_sample`` byte-identical content (the ingress upload path is threaded via
        an ``api_workers``-wide semaphore), and a PID-only name would let both writers
        share one temp path, interleaving/truncating each other before either
        ``os.replace`` — corrupting the bytes that rename then atomically publishes.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.parent / (
            f".{dest.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.part"
        )
        try:
            shutil.copyfile(src, tmp)
            os.replace(tmp, dest)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    # ── samples ──────────────────────────────────────────────────────────────
    def put_sample(self, sha256: str, src: Path) -> None:
        dest = self._sample_path(sha256)
        if dest.is_file():
            return   # already present: content-addressed => identical, idempotent
        try:
            self._atomic_copy(Path(src), dest)
        except OSError as exc:
            raise BlobFetchError(f"sample store failed: {sha256}") from exc

    def get_sample(self, sha256: str, dest: Path) -> None:
        # Re-hash after copying, mirroring S3BlobStore.get_sample: put_sample skips
        # silently once a key exists, so a blob corrupted once on disk (bug, bit rot)
        # would otherwise be trusted forever. A real store verifies its own content.
        src = self._sample_path(sha256)
        if not src.is_file():
            raise BlobFetchError(f"sample not present: {sha256}")
        dest = Path(dest)
        try:
            self._atomic_copy(src, dest)
        except OSError as exc:
            raise BlobFetchError(f"sample fetch failed: {sha256}") from exc

        h = hashlib.sha256()
        with open(dest, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
        if h.hexdigest() != sha256:
            dest.unlink(missing_ok=True)
            raise BlobIntegrityError(
                f"fetched bytes hash {h.hexdigest()}, expected {sha256}"
            )

    # ── results ──────────────────────────────────────────────────────────────
    def put_output(self, job_id: str, out_dir: Path) -> None:
        out_dir = Path(out_dir)
        dest_dir = self._results_dir(job_id)
        for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
            rel = path.relative_to(out_dir)
            self._atomic_copy(path, dest_dir / rel)

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        path = self._results_dir(job_id) / Path(name).name
        try:
            return open(path, "rb")
        except OSError as exc:
            raise BlobFetchError(f"result fetch failed: {job_id}/{name}") from exc

    def delete_job(self, job_id: str) -> None:
        """Drop this job's RESULTS only.

        Sample blobs are content-addressed and shared between jobs, so they are
        never deleted here — doing so would break every other job referencing the
        same bytes, including a future re-run of the corpus. Mirrors
        ``S3BlobStore.delete_job``.
        """
        shutil.rmtree(self._results_dir(job_id), ignore_errors=True)
