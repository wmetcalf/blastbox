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
import re
import shutil
import time
from pathlib import Path

from blastbox.host.blobs.base import BlobStore
from blastbox.host.jobs.base import JobStatus, JobStore

_log = logging.getLogger("blastbox.host.jobs.retention")

# A scratch dir must LOOK like a job dir before it can be considered for deletion.
# Ingress mints uuid4 job ids, so require that shape.
_JOB_ID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

# Only these statuses are eligible for expiry.
_TERMINAL = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED})


def purge_job_dir(job_root: "Path", job_id: str, log: "logging.Logger") -> bool:
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
    # ONE canonical path component, decided BEFORE touching the filesystem. Containment alone
    # is not enough: "victim/child/.." is strictly under job_root yet resolves to a DIFFERENT
    # job's tree, so a malformed store row could rmtree a live peer's working directory. Job IDs
    # are server-side uuid4 and ingress validates them, but Job.from_dict() does not, so an
    # imported or corrupted row reaches here unvalidated (#85 review).
    # A job_id must be ONE path component. Containment alone is not enough: "victim/child/.."
    # is strictly under job_root yet resolves to a DIFFERENT job's tree, so a malformed store
    # row could rmtree a live peer's working directory. (Degenerate ids like "" / "." / ".."
    # are left to the root-equality and containment guards below, which already reject them --
    # a duplicate pre-check here is unreachable and mutation-testing cannot justify it.)
    if not job_id or "/" in job_id or "\\" in job_id:
        log.error("refusing to purge: job_id %r is not a single path component", job_id)
        return False
    # A job dir is NEVER a symlink: both dispatchers create it with mkdir(). Refuse one here,
    # because the dangerous alias is the one that stays INSIDE job_root -- "jobs/<id> ->
    # jobs/<peer>" resolves strictly under job_root, so every containment check below passes
    # and rmtree takes out a LIVE PEER's tree while the named job loses nothing and the call
    # reports success. Containment only catches links that escape. The reclaim already refuses
    # symlinks; this is the same rule on the path both dispatchers take for every terminal job
    # (#85 review, matching an upstream codex comment).
    try:
        if (job_root / job_id).is_symlink():
            log.error("refusing to purge job %s: %s is a symlink, not a job dir — sample bytes "
                      "may remain on this worker's disk", job_id, job_root / job_id)
            return False
    except OSError as exc:
        log.error("PURGE FAILED for job %s: cannot stat under %s: %s — sample bytes may remain "
                  "on this worker's disk", job_id, job_root, exc)
        return False
    # Canonicalisation itself can raise -- a symlink loop makes Path.resolve() raise RuntimeError
    # on 3.12, and other filesystem errors escape too. Both dispatchers call this from terminal
    # cleanup, so an escape here masks the job's outcome and skips its metrics. The docstring
    # promises best-effort; make the boundary cover the whole operation, not just the rmtree.
    try:
        root = (job_root / job_id).resolve()
        jr = job_root.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        # ValueError too: Path.resolve() raises it on an embedded NUL, which the component
        # guard above does not reject, and an escape here masks the job's terminal outcome.
        log.error("PURGE FAILED for job %s: cannot canonicalise under %s: %s — sample bytes may "
                  "remain on this worker's disk", job_id, job_root, exc)
        return False
    if root == jr:
        # STRICTLY under, not equal: Path.relative_to(itself) returns "." rather than raising.
        log.error("refusing to purge job_root itself (%s) — degenerate job_id %r", jr, job_id)
        return False
    try:
        root.relative_to(jr)
    except ValueError:
        log.error("refusing to purge %s (outside job_root %s)", root, job_root)
        return False
    if not root.exists():
        return True
    try:
        shutil.rmtree(root)
        return True
    except FileNotFoundError:
        # A peer reaped the same tree concurrently. Two dispatchers share one job_root, and the
        # age-based reclaim is not claim-fenced, so this is the NORMAL two-node case -- not a
        # failure. Reporting it as one fired the module's loudest operator-facing string ("sample
        # bytes may remain") on every reap cycle that actually succeeded (#85 review).
        return True
    except (OSError, RecursionError) as exc:
        # RecursionError too: shutil.rmtree descends recursively, and the tree is written by an
        # untrusted worker into a 0o777 bind mount. A few thousand nested dirs stay well inside
        # PATH_MAX while blowing Python's stack -- so a sample could make its own tree
        # undeletable AND, without this, escape a terminal `finally` and mask the job's outcome.
        log.error("PURGE FAILED for job %s at %s: %s — sample bytes may remain on this "
                  "worker's disk", job_id, root, exc)
        return False


def reap_stale_scratch(
    job_root: Path,
    max_age_s: float,
    job_store: JobStore,
    log: logging.Logger,
    *,
    skip_job_ids: "frozenset[str] | set[str]" = frozenset(),
    blob_store: BlobStore | None = None,
) -> int:
    """Reclaim per-job scratch dirs older than ``BLASTBOX_SCRATCH_MAX_AGE_S``.

    The terminal purge handles the normal case. This bounds the ones it deliberately
    SKIPS -- a tree whose worker container was never confirmed dead, and a result whose
    upload exhausted its retries (which must be retained, since it is then the only copy).
    Without this they leak forever, because the retention sweeper is gated on
    job_retention_seconds > 0 and that knob also deletes results from the blob store.

    Age-based on purpose: it needs no store lookup, so it cannot be fooled by a corrupt
    row, and mtime rises whenever a live writer touches the tree -- a job still being
    worked on is never old enough to qualify. SCRATCH ONLY: the blob store is untouched.
    """
    if max_age_s <= 0 or not job_root.is_dir():
        return 0
    now = time.time()
    cutoff = now - max_age_s
    n = 0
    # Trees whose worker container THIS PROCESS still believes is alive. The inline purge
    # refuses to rmtree under an unconfirmed-kill orphan for good reasons -- it half-deletes
    # the tree, fires a spurious "PURGE FAILED", and frees nothing because the container's
    # open fds pin the blocks -- and those reasons do not expire just because the tree got
    # old. A wedged container writes nothing, so its mtime stops advancing and it ages into
    # this sweep while _reconcile_cold_orphans, running LATER in this same tick, is still
    # deliberately retaining it. _reconcile_cold_orphans purges it the moment docker ps
    # confirms it is gone; until then it is not ours to delete (#85 review).
    retained = skip_job_ids
    try:
        entries = list(job_root.iterdir())
    except OSError as exc:
        log.warning("scratch reclaim: cannot list %s: %s", job_root, exc)
        return 0
    for d in entries:
        try:
            # Must LOOK like a job dir before it can be considered for deletion. "the store
            # has never heard of it" is not evidence of an orphan -- job_root can legitimately
            # contain a co-located blob store (BLASTBOX_BLOB_LOCAL_ROOT under job_root is a
            # documented mode-2 layout), lost+found when it is its own filesystem, or an
            # operator's scratch. Deleting those would destroy the durable results this whole
            # design depends on. Ingress mints uuid4 job ids, so require that shape.
            if d.is_symlink():
                continue          # resolve() would dereference to a SIBLING's real tree
            if not d.is_dir() or not _JOB_ID_RE.match(d.name):
                continue
        except OSError:
            continue
        # NEWEST mtime anywhere in the tree, not just the top-level dir. A live worker writes
        # INTO output/, and on Linux that does not touch the PARENT's mtime -- so a job that
        # has been running for hours (a cold run with BLASTBOX_WORKER_TIMEOUT_S above this
        # cutoff is supported) looks arbitrarily stale by the parent alone, and this sweep
        # would delete the tree out from under it (#85 review).
        try:
            # A future mtime is NO EVIDENCE, not fresh evidence. The worker owns files under
            # output/ (a 0o777 bind mount) and utime() is unprivileged, so a detonated sample
            # could stamp the far future and make its tree immortal -- defeating the only
            # bound on job_root and reproducing #84 deliberately. Clamping such a stamp to
            # `now` would still read as "just touched", so ignore it outright. The small
            # tolerance keeps ordinary clock skew from discarding honest timestamps.
            horizon = now + 60.0

            def _evidence(st_mtime: float) -> float:
                return -1.0 if st_mtime > horizon else st_mtime

            newest = _evidence(d.lstat().st_mtime)
            live = newest > cutoff
            for child in d.rglob("*"):
                if live:
                    break     # already proven active -- no reason to walk the rest
                try:
                    # lstat, NOT stat: stat() DEREFERENCES, and the worker owns output/
                    # (0o777 bind mount). One `ln -s /tmp output/notes` borrows a busy host
                    # path's continuously-refreshed mtime and pins the tree live forever --
                    # permanently defeating the only bound on job_root and reproducing #84
                    # on demand. The stamp is honest, so the future-mtime guard above cannot
                    # see it. rglob already refuses to descend INTO a symlinked dir, so the
                    # link's own mtime is the only evidence it gets to offer (#85 review).
                    newest = max(newest, _evidence(child.lstat().st_mtime))
                    live = newest > cutoff
                except OSError:
                    continue
        except (OSError, RuntimeError):
            continue
        if live:
            continue
        if d.name in retained:
            continue
        # Belt and braces: age is a heuristic, job state is a fact. Never reclaim a tree whose
        # job is still live. A job unknown to the store is a genuine orphan and IS reclaimable.
        try:
            job = job_store.get(d.name)
        except Exception:  # noqa: BLE001 -- store trouble must not turn into deletion
            log.warning("scratch reclaim: cannot confirm job %s is terminal; leaving it",
                         d.name)
            continue
        if job is not None and job.status not in (JobStatus.DONE, JobStatus.FAILED,
                                                  JobStatus.EXPIRED):
            continue
        # NEVER delete the last copy. This whole sweep rests on "the durable copy lives in the
        # blob store, so removing the local tree loses nothing" -- and there are two states where
        # that is simply false. (1) A job completed BEFORE the blob store shipped was never
        # put_output'd: LocalBlobStore.open_output still serves it from the legacy
        # <job_root>/<id>/output path, which is exactly the tree we are about to rmtree, so the
        # first tick after an upgrade would destroy every pre-migration result the API can still
        # serve. (2) A result whose upload exhausted its retries is host-sealed, trust-gate-passed,
        # and unreproducible (the C2 pcap is MOVED into it, and detonation is not deterministic
        # run-to-run). has_output() may only answer True on positively observed bytes -- an error
        # or an outage answers False -- so the failure mode is a retained tree, which the operator
        # can see and this sweep will collect once the store recovers (#85 review).
        # ...but ONLY for a tree that actually holds a RESULT. A tree stranded by a SIGKILL
        # mid-detonation has no sealed output and never will, so requiring a durable copy of it
        # would retain it forever -- reintroducing the exact leak this sweep exists to bound.
        # metadata.json is the host-written seal (_write_sealed_metadata), so its presence is
        # what distinguishes "a finished result with nowhere else to live" from "scratch".
        if blob_store is not None and (d / "output" / "metadata.json").is_file():
            try:
                durable = blob_store.has_output(d.name)
            except Exception:  # noqa: BLE001 -- unknown is NOT durable
                durable = False
            if not durable:
                log.warning("scratch reclaim: %s holds a sealed result with no durable copy in "
                            "the blob store; retaining it rather than deleting the last copy",
                            d.name)
                continue
        # Count only what was actually removed: purge_job_dir refuses and fails
        # best-effort, and an unconditional increment made the operator-facing
        # "removed N job dir(s)" line report directories still on disk, forever.
        if purge_job_dir(job_root, d.name, log):
            n += 1
    if n:
        log.info("scratch reclaim: removed %d job dir(s) older than %.0fs from %s",
                  n, max_age_s, job_root)
    return n


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
