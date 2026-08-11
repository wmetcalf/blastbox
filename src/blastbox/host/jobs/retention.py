"""Retention sweeper for job artifacts.

Security properties:
- ``shutil.rmtree`` is confined to paths that resolve under ``job_root``
  (re-resolved + containment check before every delete).
- Symlinks are NOT followed out of ``job_root``: ``shutil.rmtree`` is called
  with ``dir_fd`` unavailable, but we pass the job-subdirectory path (not the
  symlink target); ``onexc`` logs failures rather than swallowing them with
  ``ignore_errors=True``.
- Only terminal-status jobs (DONE / FAILED / EXPIRED) are expired.
  QUEUED and RUNNING jobs are never touched regardless of ``expires_at``.
- Individual failures are logged and do not abort the sweep.
"""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

from blastbox.host.blobs.base import BlobStore
from blastbox.host.jobs.base import JobStatus, JobStore

_log = logging.getLogger("blastbox.host.jobs.retention")

# Only these statuses are eligible for expiry.
_TERMINAL = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED})


def purge_job_dir(job_root: "Path", job_id: str, log: "logging.Logger") -> None:
    """Remove a job's ENTIRE per-job dir (input AND output) from this worker's disk.

    SECURITY INVARIANT, not housekeeping: a worker is a malware-analysis node, frequently
    spare hardware that is not a hardened sample repository. Nothing may survive a terminal
    state, and there is deliberately no setting that disables this. The durable copy lives in
    the blob store (``results/<job_id>/``), so removing the local tree loses nothing.

    Shared by BOTH dispatchers on purpose. It previously existed only in VmJobDispatcher, so
    the file-handshake path (firecracker/gvisor -- every local warm worker) deleted just the
    input and left output/ forever: 97,681 dirs / 184 GiB across a 3-node fleet, one node's
    root filesystem at 100%, and its warm pool collapsed 16 guests -> 3 (issue #84). Keeping
    one implementation is what stops the two from drifting apart again.

    Best-effort by design -- a purge failure must never mask the job's real outcome -- but it
    is logged loudly, never silently swallowed, so an operator can see a worker failing to
    clean up after itself. Containment: resolve first, then refuse anything that does not land
    strictly under ``job_root`` (guards a job_id carrying traversal components).
    """
    root = (job_root / job_id).resolve()
    jr = job_root.resolve()
    if root == jr:
        # STRICTLY under, not equal. Path.relative_to(itself) returns "." rather than raising,
        # so an empty/"."/None-coerced job_id sailed through the guard below and rmtree'd the
        # ENTIRE job_root -- every peer container's in-flight tree on a shared-mount node, from
        # one bad store row. Not reachable today (job_ids are server-side uuid4 and ingress
        # validates them), but this function's docstring calls itself a security invariant.
        log.error("refusing to purge job_root itself (%s) — empty or traversal job_id %r",
                  jr, job_id)
        return
    try:
        root.relative_to(jr)
    except ValueError:
        log.error("refusing to purge %s (outside job_root %s)", root, job_root)
        return
    if not root.exists():
        return
    try:
        shutil.rmtree(root)
    except OSError as exc:
        log.error("PURGE FAILED for job %s at %s: %s — sample bytes may remain on this "
                  "worker's disk", job_id, root, exc)


class JobRetentionSweeper:
    """Sweeps expired terminal-status jobs and deletes their artifacts.

    ``job_root`` is the base directory under which all per-job artifact
    subdirectories live.  Any ``result_dir`` that does not resolve strictly
    inside ``job_root`` is refused — this prevents a malicious or misconfigured
    ``result_dir`` from deleting arbitrary paths on the host.

    ``blob_store``, if given, is also reaped per expired job (``delete_job``)
    so result bytes uploaded via ``BlobStore.put_output`` don't outlive the
    on-disk copy this sweeper already deletes. Defaults to ``None`` — every
    existing call site (mode 1, no object storage) is unaffected.
    """

    def __init__(
        self,
        job_root: Path | str,
        *,
        clock=None,
        blob_store: BlobStore | None = None,
    ) -> None:
        self._job_root = Path(job_root).resolve()
        self._clock = clock or time.time
        self._blobs = blob_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def expire_due(self, job_store: JobStore) -> list[str]:
        """Expire all terminal jobs whose ``expires_at`` is in the past.

        Returns the list of job IDs that were expired this sweep.
        Each job is processed independently; a failure on one is logged
        and does not prevent others from being expired.
        """
        now = self._clock()
        expired: list[str] = []

        for job in job_store.list():
            if job.status not in _TERMINAL:
                continue
            if job.expires_at is None or job.expires_at > now:
                continue
            try:
                self._expire_job(job_store, job.job_id, job.result_dir)
                expired.append(job.job_id)
            except Exception:
                _log.exception("failed to expire job %s", job.job_id)

        return expired

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _expire_job(
        self,
        job_store: JobStore,
        job_id: str,
        result_dir: str | None,
    ) -> None:
        """Delete artifacts and mark the job EXPIRED in the store."""
        if result_dir is not None:
            self._safe_rmtree(job_id, Path(result_dir))

        blob_delete_ok = True
        if self._blobs is not None:
            # Result blobs only. Sample blobs are content-addressed and shared
            # between jobs, so deleting them here would break every other job
            # referencing the same bytes; they age out on their own policy
            # (BLASTBOX_BLOB_SAMPLE_RETENTION / bucket lifecycle).
            try:
                self._blobs.delete_job(job_id)
            except Exception as exc:
                # A transient blob-store delete failure must NOT advance the job to
                # EXPIRED with expires_at=None: an EXPIRED job with a null expires_at
                # is never re-selected, so the result blob would be orphaned forever.
                # Leave the job in its terminal state with expires_at intact so the
                # NEXT sweep retries the (idempotent) delete. The on-disk rmtree above
                # may already have run; that is fine — both rmtree and delete_job are
                # idempotent.
                _log.warning(
                    "retention: blob delete failed for %s: %s; leaving expires_at "
                    "intact so the next sweep retries", job_id, exc,
                )
                blob_delete_ok = False

        # Only advance to EXPIRED once the blob delete has succeeded (or there is no blob store).
        # Clearing expires_at is safe only then: the durable bytes are gone, so there is nothing
        # left to retry, and the now-EXPIRED job (EXPIRED is in _TERMINAL) is not re-selected +
        # re-swept on every subsequent pass. If the delete failed, do NOT touch the store — the
        # job stays sweepable and a later sweep finishes the expiry.
        if not blob_delete_ok:
            return
        job = job_store.get(job_id)
        if job is not None:
            job_store.update(job_id, status=JobStatus.EXPIRED, result_dir=None, expires_at=None)

    def _safe_rmtree(self, job_id: str, result_dir: Path) -> None:
        """Delete the artifact tree, confined to ``job_root``.

        Security:
        - Resolves ``result_dir`` without following symlinks for the final
          component (we check the path, not what the symlink points to).
        - Uses ``Path.resolve()`` to canonicalise before the containment check
          so ``../`` traversals are detected.
        - Passes the resolved directory path (not any symlink target) to
          ``shutil.rmtree``, with ``onexc`` logging each error rather than
          silently swallowing them via ``ignore_errors=True``.
        - Deletes the *parent* of ``result_dir`` so per-job subdirectories
          are removed cleanly (``result_dir`` may be ``job_root/<id>/result``,
          and we want to remove ``job_root/<id>/``).
        """
        # Determine the directory to remove: the parent of result_dir if it
        # is a direct child subdir, otherwise result_dir itself.  We resolve
        # the parent (which exists on disk) to get a canonical path.
        try:
            parent = result_dir.parent.resolve()
        except OSError:
            parent = result_dir.parent

        # Pick the most specific path that still lies under job_root.
        # If the parent is job_root itself, fall back to result_dir.
        if parent == self._job_root:
            target = result_dir.resolve() if result_dir.exists() else result_dir
        else:
            target = parent

        # Containment check: the target must resolve to a path strictly
        # inside job_root.  This defends against both symlink escapes and
        # absolute paths that happen to be outside the base.
        try:
            target_resolved = target.resolve()
        except OSError:
            _log.warning(
                "job %s: result_dir %r could not be resolved; skipping delete",
                job_id,
                str(result_dir),
            )
            return

        try:
            target_resolved.relative_to(self._job_root)
        except ValueError:
            _log.warning(
                "job %s: result_dir %r resolves to %r which is outside "
                "job_root %r; refusing to delete",
                job_id,
                str(result_dir),
                str(target_resolved),
                str(self._job_root),
            )
            return

        if not target.exists():
            _log.debug("job %s: target %r does not exist; nothing to delete", job_id, str(target))
            return

        errors: list[str] = []

        def _on_exc(func, path, exc):
            errors.append(f"{func.__name__}({path!r}): {exc}")

        shutil.rmtree(target, onexc=_on_exc)

        if errors:
            for err in errors:
                _log.warning("job %s: rmtree error: %s", job_id, err)
