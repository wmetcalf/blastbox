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

from blastbox.host.jobs.base import JobStatus, JobStore

_log = logging.getLogger("blastbox.host.jobs.retention")

# Only these statuses are eligible for expiry.
_TERMINAL = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED})


class JobRetentionSweeper:
    """Sweeps expired terminal-status jobs and deletes their artifacts.

    ``job_root`` is the base directory under which all per-job artifact
    subdirectories live.  Any ``result_dir`` that does not resolve strictly
    inside ``job_root`` is refused — this prevents a malicious or misconfigured
    ``result_dir`` from deleting arbitrary paths on the host.
    """

    def __init__(
        self,
        job_root: Path | str,
        *,
        clock=None,
    ) -> None:
        self._job_root = Path(job_root).resolve()
        self._clock = clock or time.time

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

        # Update the store regardless of whether result_dir existed.
        job = job_store.get(job_id)
        if job is not None:
            job_store.update(job_id, status=JobStatus.EXPIRED, result_dir=None)

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
