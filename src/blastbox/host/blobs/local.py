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

import errno

import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import BinaryIO

from blastbox.host.blobs.base import (
    _SEAL_NAME,
    _declared_paths,
    BlobFetchError,
    BlobIntegrityError,
    _upload_order,
)
from blastbox.observability import get_logger

_log = get_logger("blastbox.blobs.local")

_CHUNK = 1024 * 1024


class LocalBlobStore:
    def __init__(self, job_root: Path | str, blob_root: Path | str | None = None) -> None:
        self._job_root = Path(job_root)
        # Default: a `blobs` dir sibling to job_root — deliberately OUTSIDE it, so
        # destroying job_root (the purge) never touches durable bytes.
        self._blob_root = Path(blob_root) if blob_root is not None else self._job_root.parent / "blobs"

    def _sample_path(self, sha256: str) -> Path:
        return self._blob_root / "samples" / sha256

    @property
    def local_root(self) -> Path:
        """Where this store keeps its bytes. The scratch reclaim asks so it can refuse to delete
        the blob root, whatever it is named and however it was configured."""
        return self._blob_root

    def _results_dir(self, job_id: str) -> Path:
        return self._blob_root / "results" / job_id

    @staticmethod
    def _atomic_copy(src: Path, dest: Path) -> None:
        """Copy *src* -> *dest* via a temp file in the same dir + atomic rename, so a
        crash mid-copy can never leave a truncated blob that a later read would trust.

        The temp name is a per-call uuid4 and NOTHING ELSE -- specifically not the
        destination's name. A uuid4 alone already gives the uniqueness this needs: two threads in
        the SAME process can race to ``put_sample`` byte-identical content (the ingress upload
        path is threaded via an ``api_workers``-wide semaphore), and a shared temp path would let
        both writers interleave/truncate each other before either ``os.replace`` — corrupting the
        bytes that rename then atomically publishes.

        Including ``dest.name`` inflated the temp basename by ~62 characters, so a DECLARED
        artifact with a ~200-char name -- which the filesystem, the envelope (path allows 4096)
        and S3 all accept -- made this raise ENAMETOOLONG on a destination that is perfectly
        storable. That failure is deterministic, so the pending-upload sweep could never drain
        it: the job stayed FAILED forever, every result route answered 409, and the reclaim held
        the tree as the last copy indefinitely. #84 on demand, from one artifact name (#85
        review). A fixed-length temp keeps "storable destination" and "storable temp" the same
        question.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.parent / f".tmp-{uuid.uuid4().hex}.part"
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
        # The terminal purge deletes the local tree on the strength of THIS call, so a
        # silent no-op here turns "upload succeeded" into a DONE job with no durable copy
        # anywhere. rglob on a missing dir yields nothing and raises nothing, so assert the
        # durability barrier explicitly (#85 review).
        out_dir = Path(out_dir)
        if not out_dir.is_dir():
            raise FileNotFoundError(f"put_output: output dir missing for {job_id}: {out_dir}")
        dest_dir = self._results_dir(job_id)
        declared = _declared_paths(out_dir)
        # TWO-PHASE COMMIT. metadata.json is written LAST, so its presence under
        # results/<job_id> means "every other artifact already landed" -- that is what makes
        # has_output() a real durability answer instead of a guess. Uploading in plain sorted
        # order put it FIRST ('m' < 'r'), so a run that died mid-upload left the seal present with
        # artifacts missing, and the age reclaim would then delete the complete local tree as
        # redundant. It is also the artifact the API fetches to serve a job at all (#85 review).
        for path in _upload_order(out_dir):
            # Skip symlinks BEFORE is_file() -- is_file() follows a symlink to its
            # target, so `p.is_symlink() or not p.is_file()` (checked in that
            # order) never reads or uploads a symlink's target bytes. A worker
            # that plants e.g. output/metadata.json -> /etc/passwd before this
            # runs must not get that file's bytes stored (and later served) as
            # trusted job output. A single hostile entry is skipped + logged,
            # not raised — it must not fail the upload of the rest of a
            # legitimate job's output.
            if path.is_symlink():
                _log.warning(
                    "put_output_skipped_symlink",
                    job_id=job_id,
                    path=str(path.relative_to(out_dir)),
                )
                continue
            if not path.is_file():
                continue
            rel = path.relative_to(out_dir)
            # A name we can NEVER store is not an outage -- retrying it forever is what turns
            # one worker-chosen filename into a permanent leak. The sample writes an undeclared
            # 250-char name into its 0o777 output/, put_output raises ENAMETOOLONG on every
            # attempt, the host marks the tree pending-upload, and the last-copy rule then
            # exempts it from BOTH sweeps for the life of the node -- #84 reproduced on demand
            # (upstream review of #85). Skip it loudly, exactly as a hostile symlink is skipped:
            # undeclared files are not servable anyway (the result routes are manifest-gated), so
            # nothing a consumer can reach is lost. Every other error still propagates, because a
            # real outage MUST fail the upload rather than silently ship a partial result.
            try:
                self._atomic_copy(path, dest_dir / rel)
            except OSError as exc:
                if (exc.errno != errno.ENAMETOOLONG or declared is None
                        or rel.as_posix() in declared):
                    raise      # a DECLARED artifact must never be silently dropped
                _log.warning("put_output_skipped_unstorable_name", job_id=job_id,
                             path=str(rel), error=str(exc))

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        # put_output stores nested rel paths (results/<job_id>/<foo/bar.png>), so open_output must
        # read at the SAME key -- collapsing to the basename would 404 (or silently omit) a nested
        # artifact. Each candidate stays safe on its own: resolve it and refuse anything
        # (``..``, an absolute name, a symlink escape) that lands outside its base dir,
        # mirroring JobRetentionSweeper._safe_rmtree's containment posture.
        primary = self._contained_open(self._results_dir(job_id), name, job_id)
        if primary is not None:
            return primary

        # Upgrade compatibility (Finding C1): a job that completed BEFORE this blob-store
        # feature shipped has its output at the legacy `<job_root>/<id>/output/<name>` and
        # was never put_output'd into the store, so the primary lookup above 404s it. Fall
        # back to that legacy on-disk location. Scoped to the LOCAL backend on purpose --
        # S3BlobStore has no such legacy path -- and self-limiting: jobs run under the
        # current code purge their job dir after uploading, so this only ever finds
        # pre-upgrade results. New/distributed deployments never hit it.
        legacy = self._contained_open(self._job_root / job_id / "output", name, job_id)
        if legacy is not None:
            return legacy

        raise BlobFetchError(f"result fetch failed: {job_id}/{name}")

    def has_output(self, job_id: str) -> bool:
        """Positively observed durable result bytes for *job_id*.

        Deliberately does NOT count the legacy `<job_root>/<id>/output` fallback that
        open_output still serves: that path IS the local tree the reclaim is deciding whether
        to delete, so counting it would make the check answer "yes, a durable copy exists"
        with the tree itself as the evidence -- and destroy the only copy of every pre-blob-store
        result on the node (#85 review).
        """
        try:
            return (self._results_dir(job_id) / _SEAL_NAME).is_file()
        except OSError:
            return False        # unknown is NOT durable

    def _contained_open(self, base_dir: Path, name: str, job_id: str) -> BinaryIO | None:
        """Open ``base_dir/name`` if present and contained under ``base_dir``.

        Returns the open file, or ``None`` when the file is simply absent (so the caller can
        try a fallback location). A containment violation (``..``/absolute/symlink escape) is
        fatal -- it raises rather than returning None -- because it signals a crafted name,
        not a missing file.
        """
        base = base_dir.resolve()
        candidate = (base / name).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise BlobFetchError(
                f"result fetch refused (escapes job dir): {job_id}/{name}"
            ) from exc
        try:
            return open(candidate, "rb")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BlobFetchError(f"result fetch failed: {job_id}/{name}") from exc

    def delete_job(self, job_id: str) -> None:
        """Drop this job's RESULTS only.

        Sample blobs are content-addressed and shared between jobs, so they are
        never deleted here — doing so would break every other job referencing the
        same bytes, including a future re-run of the corpus. Mirrors
        ``S3BlobStore.delete_job``.

        A job with no stored results is a clean no-op (NOT an error: most jobs
        that never reached DONE have nothing here). But a genuine removal failure
        (permission/IO error on an existing tree) MUST propagate rather than be
        swallowed: ``retention._expire_job`` only advances a job to EXPIRED
        (clearing ``expires_at``) when this call does NOT raise, specifically so a
        transient failure is retried by a later sweep. Blanket
        ``ignore_errors=True`` would defeat that guard by making every failure mode
        indistinguishable from success.
        """
        results_dir = self._results_dir(job_id)
        try:
            shutil.rmtree(results_dir)
        except FileNotFoundError:
            pass
