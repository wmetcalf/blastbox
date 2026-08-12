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

import contextlib
import errno
import itertools
import logging
import os
import re
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from blastbox.host.blobs.base import BlobStore, upload_output_with_retry
from blastbox.host.jobs.base import JobStatus, JobStore

_log = logging.getLogger("blastbox.host.jobs.retention")

# A scratch dir must LOOK like a job dir before it can be considered for deletion.
# Ingress mints uuid4 job ids, so require that shape.
# Where the last capped sweep of each job_root stopped, so the next one starts there instead of
# re-examining the same prefix. Process-local and purely an ordering hint: losing it on restart
# costs one repeated sweep, never correctness.
_sweep_cursor: dict[str, int] = {}
_upload_cursor: dict[str, int] = {}

_JOB_ID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

# Only these statuses are eligible for expiry.
_TERMINAL = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED})

# The one marker that identifies "the analysis finished; only its upload didn't". Both
# dispatchers build their failure message with it and retry_pending_uploads matches on it, so
# there is a SINGLE definition rather than a literal duplicated across three call sites.
RESULT_RETAINED_MARKER = "result retained on this worker (no durable copy)"

# The HOST-ONLY record that a tree holds a sealed result whose upload failed.
#
# It is a file in the JOB DIR, deliberately a sibling of output/ and never inside it. The worker
# owns output/ (a 0o777 bind mount) and nothing else: the job dir itself is host-only, which is
# already why the egress resolv.conf is staged there rather than under output/.
#
# The previous gate -- RESULT_RETAINED_MARKER appearing in job.error -- was NOT host-only, and
# that was a real hole, not a theoretical one. job.error carries verbatim worker text on the
# engine-error path (`f"engine_error: {detail}"`), so a worker could put the marker string in its
# own envelope warning, get it copied into the row, and have this sweep upload its untrusted
# output/ as the job's result and CAS the job to DONE. Demonstrated end-to-end in review of #85.
#
# A file also makes the sweep cheap: one stat per job dir instead of a store round-trip per dir,
# which matters at the 97,681-dir fleet state this PR exists to clean up.
PENDING_UPLOAD_SENTINEL = ".pending-upload"

# The same trick for the other tree a sweep must not touch: one whose worker container was never
# confirmed dead. That knowledge lived in a PROCESS-LOCAL set, which is where the danger is --
# two dispatcher containers share one job_root, VmJobDispatcher has no docker access at all to
# probe with, and a restart empties the set. A file in the host-only job dir is visible to every
# sweeper in every process and survives restarts.
RETAINED_ORPHAN_SENTINEL = ".retained-orphan"


def mark_retained_orphan(job_root: "Path", job_id: str, log: "logging.Logger") -> None:
    """Record that this job's worker container was NOT confirmed dead, so its tree must not be
    rmtree'd out from under a possibly-live 0o777 bind mount. Best-effort."""
    try:
        (job_root / job_id / RETAINED_ORPHAN_SENTINEL).write_text("")
    except OSError as exc:
        log.warning("could not mark %s as a retained orphan (%s)", job_id, exc)


def clear_retained_orphan(job_root: "Path", job_id: str) -> None:
    with contextlib.suppress(OSError):
        (job_root / job_id / RETAINED_ORPHAN_SENTINEL).unlink()


def mark_pending_upload(job_root: "Path", job_id: str, log: "logging.Logger",
                        claim_id: str | None = None) -> None:
    """Record that this job's sealed result is on local disk with no durable copy.

    Written BEFORE the terminal store write, so a crash in between cannot lose it: without the
    marker the tree is ordinary scratch and the reclaim deletes the only copy of a sealed result.
    That ordering needs an ownership fence of its own, hence *claim_id*: the sweep will only act
    on a marker whose claim still matches the row, so a marker left behind by an attempt that
    LOST its terminal CAS can never license publishing that attempt's stale bytes over the peer's
    result (#85 review).
    """
    try:
        (job_root / job_id / PENDING_UPLOAD_SENTINEL).write_text(claim_id or "")
    except OSError as exc:
        # NOT best-effort. This file is the ONLY durable record that the tree holds the last copy
        # of a result: the in-memory carve-out protects just the immediate terminal purge, and
        # once that is consumed the age reclaim sees an ordinary FAILED job and deletes it. So a
        # failure here is a pending DATA LOSS, not a missed optimisation, and it says so (#85).
        log.error("CANNOT MARK %s as pending-upload (%s) — its result is the only copy and the "
                  "scratch reclaim will not recognise it; the result may be lost when the tree "
                  "ages out", job_id, exc)


def clear_pending_upload(job_root: "Path", job_id: str) -> None:
    with contextlib.suppress(OSError):
        (job_root / job_id / PENDING_UPLOAD_SENTINEL).unlink()


# How many directory fds the removal below may hold at once. Bounded because a hostile worker
# controls the depth: holding one fd per level hit EMFILE ("Too many open files") at the default
# 1024 ulimit, which is just RecursionError wearing a different hat -- the tree stayed immortal.
_RM_FD_BUDGET = 64


def _rmtree_iterative(root: "Path") -> None:
    """Remove *root* with bounded resources, whatever shape it has.

    A worker owns output/ (a 0o777 bind mount), so every limit here is one it can aim at:
      * shutil.rmtree's fd walk RECURSES -- RecursionError at ~1000 levels;
      * a path-based walk (os.walk, rglob) silently stops at PATH_MAX;
      * one fd per level -- the obvious iterative rewrite -- hits EMFILE at ~1024.

    So: a post-order walk over openat/unlinkat (no absolute paths, so PATH_MAX never applies)
    holding at most _RM_FD_BUDGET fds, and when the budget runs out, whatever is still below is
    RENAMED up into the root and picked up by a later pass.

    Three properties this needs, each of which an earlier version got wrong:
      * TERMINATION. Every pass must remove something. A directory the host cannot rmdir (the
        worker chmods 0555 a dir it owns; a still-mounted bind mount gives EBUSY) used to be
        swallowed by a bare suppress(), leaving root non-empty forever -- a 100% CPU spin inside
        a dispatch `finally` (measured: 369,871 passes in 8s), which is far worse than the clean
        "PURGE FAILED" shutil.rmtree would have produced. A pass that removes nothing now raises.
      * FRESH HOIST NAMES. Renaming onto a fixed `.rm-0` meant residue from an interrupted purge
        (likely, given the spin above) collided with a NON-EMPTY dir -> ENOTEMPTY on every later
        attempt -> zero progress, forever.
      * WIDTH. Descending only the first child per pass made the cost quadratic in sibling count
        (16k dirs = 24s, and 4x per doubling) inside the single maintenance thread. Iterators are
        kept per frame, so one pass clears everything within the budget depth at any width.
    """
    parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent_fd)
        try:
            counter = itertools.count()
            while True:
                removed, remaining = _rm_one_pass(root_fd, counter)
                if not remaining:
                    break
                if not removed:
                    # Nothing left that we are able to remove. Report it the way shutil.rmtree
                    # would have, instead of looping on it.
                    raise OSError(errno.ENOTEMPTY,
                                  "cannot remove every entry (permissions, or a live mount)",
                                  str(root))
        finally:
            os.close(root_fd)
        os.rmdir(root.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _hoist_name(root_fd: int, counter: "itertools.count") -> str:
    """An unused `.rm-N` in the root, so a hoist never lands on residue from an earlier purge."""
    for _ in range(10_000):
        name = f".rm-{next(counter)}"
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return name
        except OSError:
            continue
    raise OSError(errno.EEXIST, "no free hoist name under job dir")


def _rm_one_pass(root_fd: int, counter: "itertools.count") -> "tuple[bool, bool]":
    """One bounded post-order pass. Returns (removed_anything, root_still_has_entries)."""
    removed = False
    # (parent_fd or None for the root, own name or None, own fd, its scandir iterator)
    stack: list[tuple[int | None, str | None, int, "Any"]] = [
        (None, None, root_fd, os.scandir(root_fd)),
    ]
    try:
        while stack:
            pfd, name, fd, it = stack[-1]
            descended = False
            for entry in it:                      # the iterator LIVES on the frame, so returning
                try:                              # to a parent resumes rather than re-scanning
                    if entry.is_dir(follow_symlinks=False):
                        if len(stack) >= _RM_FD_BUDGET:
                            os.rename(entry.name, _hoist_name(root_fd, counter),
                                      src_dir_fd=fd, dst_dir_fd=root_fd)
                            removed = True        # depth fell by a budget: real progress
                            continue
                        cfd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=fd)
                        stack.append((fd, entry.name, cfd, os.scandir(cfd)))
                        descended = True
                        break
                    os.unlink(entry.name, dir_fd=fd)
                    removed = True
                except FileNotFoundError:
                    continue                      # a peer got there first
            if descended:
                continue
            it.close()
            stack.pop()
            if pfd is not None:
                os.close(fd)
                try:
                    os.rmdir(name, dir_fd=pfd)    # type: ignore[arg-type]
                    removed = True
                except OSError:
                    pass                          # not empty yet, or not ours to remove
    finally:
        for _pfd, _name, fd, it in stack:         # only reached on an exception mid-walk
            with contextlib.suppress(Exception):
                it.close()
            if _pfd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
    with os.scandir(root_fd) as it2:
        return removed, any(True for _ in it2)


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
        try:
            shutil.rmtree(root)
        except (RecursionError, OSError) as exc:
            # DEPTH ATTACK. The worker owns output/ (0o777) and `for i in $(seq 1500); do mkdir a;
            # cd a; done` is unprivileged, instant, and stays well inside PATH_MAX -- so it can
            # make its own tree undeletable and reproduce #84 on demand. shutil.rmtree gives up
            # in whichever way the box runs out first: RecursionError (its fd walk recurses),
            # EMFILE/ENFILE (one held fd per level against the ulimit), or ENAMETOOLONG. Catching
            # the error is not enough -- the tree has to actually go -- so retry with the bounded
            # iterative removal below. Anything else (EACCES, EROFS, EBUSY) is a real failure and
            # is reported (#85 review; the EMFILE case was found in end-to-end testing, where the
            # container's 1024 ulimit was reached long before the recursion limit).
            if not isinstance(exc, RecursionError) and getattr(exc, "errno", None) not in (
                    errno.EMFILE, errno.ENFILE, errno.ENAMETOOLONG):
                raise
            _rmtree_iterative(root)
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


def _blob_local_roots() -> "tuple[Path, ...]":
    """Paths the local blob backend may be rooted at, for protect_paths above.

    BLASTBOX_BLOB_LOCAL_ROOT is operator-set, so it can legitimately live under job_root -- a
    documented layout -- and can be named anything, including a uuid.
    """
    raw = os.environ.get("BLASTBOX_BLOB_LOCAL_ROOT", "").strip()
    return (Path(raw),) if raw else ()


def retry_pending_uploads(
    job_root: Path,
    blob_store: BlobStore | None,
    job_store: JobStore,
    log: logging.Logger,
    *,
    attempts: int = 1,
    on_repaired: "Callable[[str, Path], None] | None" = None,
    retention_seconds: float = 0.0,
    max_per_sweep: int = 2000,
) -> int:
    """Re-attempt ``put_output`` for every local tree holding a sealed result with no durable copy.

    THIS is what makes retaining such a tree legitimate. Without it the two dispatchers were
    forced to choose between two wrong answers on upload exhaustion -- discard a host-sealed,
    trust-gate-passed, unreproducible result (detonation is not deterministic run-to-run, and the
    C2 pcap is MOVED into the tree), or keep it forever as bytes no consumer can reach, since the
    API serves results from the blob store alone. Neither ever gets the result durable.

    A retained tree is a PENDING UPLOAD, not a leak: this sweep drains it, and once the seal lands
    the ordinary age reclaim collects the tree like any other. The inline retry inside a dispatch
    is deliberately bounded (it must not hold a claim open across an outage); this is the
    unbounded-in-time half, and an outage that outlives the process is exactly the case the
    in-memory bookkeeping could never survive -- which is why the durability oracle is the store
    itself (has_output) rather than a set of job ids.

    Best-effort and idempotent: put_output overwrites, and every failure is logged, not raised.
    """
    if blob_store is None or not job_root.is_dir():
        return 0
    n = 0
    try:
        entries = sorted(job_root.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        log.warning("pending-upload sweep: cannot list %s: %s", job_root, exc)
        return 0
    # BOUNDED and ROTATING, like the reclaim. This runs FIRST in the maintenance tick and, at
    # default BLASTBOX_DISPATCH_CONCURRENCY=1, maintenance runs inline between dispatch_once()
    # calls -- so on the fleet state this PR targets (97,681 dirs) an uncapped scan stats every
    # entry on every tick before a single job can be claimed. The sentinel check is one stat, so
    # the scan is cheap per entry, but 97k of them per tick is not free (#85 review).
    if entries and max_per_sweep > 0:
        start = _upload_cursor.get(str(job_root), 0) % len(entries)
        entries = entries[start:] + entries[:start]
        _upload_cursor[str(job_root)] = (start + max_per_sweep) % len(entries)
        entries = entries[:max_per_sweep]
    for d in entries:
        try:
            if d.is_symlink() or not d.is_dir() or not _JOB_ID_RE.match(d.name):
                continue
            out_dir = d / "output"
            # The host-only sentinel FIRST: it is one stat, it is unforgeable by the worker, and
            # it means almost no directory reaches the store round-trip below.
            if not (d / PENDING_UPLOAD_SENTINEL).is_file():
                continue
            if not (out_dir / "metadata.json").is_file():
                continue          # sentinel without a result: nothing to upload
        except OSError:
            continue
        # THE GATE: the JOB ROW must say this tree is a host-sealed result whose upload failed.
        #
        # A root metadata.json does NOT prove that. The WORKER writes output/metadata.json
        # (worker/harness.py) and the host only OVERWRITES it when the trust gate passes, so a
        # tree abandoned before sealing -- gate rejection, worker timeout, a dispatcher killed
        # between worker exit and _write_sealed_metadata -- still has one, full of
        # worker-controlled bytes. Uploading that would publish untrusted output into the
        # results namespace under a job id (upstream review of #85).
        #
        # RESULT_RETAINED_MARKER is written by the dispatcher ONLY after the seal, when the
        # upload exhausted, so it is a host-only fact. It also subsumes the claim fence: a peer
        # that reclaimed and finished the job overwrites the row, marker gone. And a row that is
        # missing or unreadable -- a peer's delete, a Redis key past its 24h TTL, a store outage
        # -- yields no marker and no upload, which is the safe direction.
        try:
            row = job_store.get(d.name)
        except Exception:  # noqa: BLE001 -- store trouble must not turn into a bad upload
            log.warning("pending-upload sweep: cannot confirm %s is ours; skipping", d.name)
            continue
        # The row must still be the FAILED job we retained. Not DONE (a peer won it, and its
        # result is authoritative at the same prefix), not EXPIRED (retention deleted the result
        # on an operator's instruction -- re-uploading would silently undo that, and with
        # expires_at cleared nothing would ever collect it again), and not missing.
        if row is None or row.status is not JobStatus.FAILED:
            continue
        # OWNERSHIP. The marker is written before the terminal CAS (so a crash cannot lose it),
        # which means one can survive an attempt that LOST that CAS. It records the claim it was
        # written under; if the row has moved to a different claim, this tree is a stale attempt
        # and its bytes must never be published over the current owner's result. An empty marker
        # is from a caller that had no claim to record and is accepted as before.
        try:
            marker_claim = (d / PENDING_UPLOAD_SENTINEL).read_text().strip()
        except OSError:
            continue
        if marker_claim and row.claim_id and marker_claim != row.claim_id:
            log.warning("pending-upload sweep: %s was marked under claim %s but the row is now "
                        "%s; leaving it to its owner", d.name, marker_claim[:8], row.claim_id[:8])
            continue
        try:
            durable = blob_store.has_output(d.name)
        except Exception:  # noqa: BLE001 -- unknown is NOT durable, so try the upload
            durable = False
        # Already durable but still FAILED: a previous sweep uploaded the bytes and then could
        # not write the status (store blip), or the dispatcher's own upload landed after it had
        # given up. Skipping here would strand that job FAILED forever with its result sitting
        # in the store -- so fall through to the repair with no upload (upstream review of #85).
        upload_exc = None if durable else upload_output_with_retry(
            blob_store, d.name, out_dir, attempts=attempts)
        if upload_exc is None:
            if not durable:
                n += 1
                log.info("pending-upload sweep: result for %s is now durably stored", d.name)

            # REPAIR THE JOB. Uploading the bytes is only half of it: the job was FAILED because
            # its upload exhausted, and open_output is DONE-gated, so a recovered result stays
            # unreachable -- from a client's view the outcome is identical to having discarded it.
            # The analysis DID finish and its result is now durable, so DONE is the honest status.
            # CAS-fenced on FAILED and gated on OUR marker, so it can only ever repair the failure
            # this sweep just undid -- never a job that failed for any other reason, and never a
            # peer's terminal state (#85, found by end-to-end testing: the sweep reported success
            # while the API still answered 409).
            repaired = False
            try:
                # finished_at/expires_at are re-stamped from NOW. The row still carried the
                # clock _fail_job set at the ORIGINAL failure, so after any outage longer than
                # job_retention_seconds the repaired job was already past its expiry: expire_due
                # would delete the freshly recovered result later in this same tick, before any
                # client could fetch it (it was never servable while FAILED). Recovery has to
                # restart the retention clock, not inherit a dead one (#85 review).
                now_ts = time.time()
                repaired = job_store.update_if_status(
                    d.name, JobStatus.FAILED, status=JobStatus.DONE, error=None,
                    finished_at=now_ts,
                    expires_at=(now_ts + retention_seconds) if retention_seconds > 0 else None,
                )
            except Exception:  # noqa: BLE001 -- the bytes are safe; the status can retry
                log.warning("pending-upload sweep: uploaded %s but could not repair its "
                            "status", d.name, exc_info=True)
            if repaired:
                log.info("pending-upload sweep: job %s repaired to DONE (its result is "
                         "durable now)", d.name)
            # SEPARATE boundary, deliberately outside the store's. Nesting the hook inside the
            # update's try meant a hook failure was reported as "could not repair its status"
            # when the status HAD been repaired -- an operator chasing a store problem that does
            # not exist. Different failure, different message.
            #
            # This is everything the job's own DONE path would have done and never got to:
            # page-hash indexing for similarity search, keyed off the sealed envelope. Without
            # it a recovered job is DONE and servable but permanently invisible to /similar,
            # because nothing re-walks DONE jobs (upstream review of #85). Best-effort -- an
            # indexing problem must never undo a good repair.
            # Only NOW is the tree redundant. Clearing the sentinel on upload alone meant a
            # failed status CAS left no marker for the next sweep to find, so the job stayed
            # FAILED forever with its result durable and every result route answering 409 -- the
            # fall-through repair exists precisely for that case and could never run (#85 review).
            if repaired and on_repaired is not None:
                try:
                    on_repaired(d.name, out_dir)
                except Exception:  # noqa: BLE001
                    # ACCEPTED RESIDUAL, stated plainly rather than papered over. Keeping the
                    # sentinel here would NOT buy a retry: this sweep only looks at FAILED rows,
                    # and the row is DONE now, so no later tick would act on the marker -- it
                    # would just hold a stat forever and read like a mechanism that does not
                    # exist. The result itself is durable and servable; what is lost is the
                    # /similar index entry and the artifact/warning counts, which are cosmetic
                    # and separately rebuildable. Logged at WARNING so it is visible (#85 review).
                    log.warning("pending-upload sweep: %s was repaired and its result is durable, "
                                "but post-repair indexing failed; the job is servable with a null "
                                "summary and no /similar entry", d.name, exc_info=True)
            # LAST: after the CAS and after the hook, so a crash mid-recovery leaves the marker
            # (and therefore the tree, and therefore another attempt) rather than a half-done job.
            if repaired:
                clear_pending_upload(job_root, d.name)
        else:
            log.warning("pending-upload sweep: %s still has no durable copy (%s); retaining "
                        "the local tree", d.name, upload_exc)
    if n:
        log.info("pending-upload sweep: uploaded %d retained result(s)", n)
    return n


def reap_stale_scratch(
    job_root: Path,
    max_age_s: float,
    job_store: JobStore,
    log: logging.Logger,
    *,
    skip_job_ids: "frozenset[str] | set[str]" = frozenset(),
    blob_store: BlobStore | None = None,
    protect_paths: "tuple[Path, ...]" = (),
    max_per_sweep: int = 2000,
    live_job_ids: "Callable[[], set[str] | None] | None" = None,
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
    retained = set(skip_job_ids)
    # skip_job_ids is a PROCESS-LOCAL memory of failed kills, which is not where the danger lives:
    # two dispatcher containers share one job_root, VmJobDispatcher keeps no such set, and a
    # restart empties it -- so the other sweeper deletes exactly the trees this guard exists to
    # spare, under a live 0o777 bind mount. `docker ps` is node-wide and survives restarts, so ask
    # it too. Unreadable (None) changes nothing: we keep whatever we already knew.
    if live_job_ids is not None:
        try:
            in_flight = live_job_ids()
        except Exception:  # noqa: BLE001 -- never turn a probe failure into a deletion
            in_flight = None
        if in_flight:
            retained |= in_flight
    try:
        entries = sorted(job_root.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        log.warning("scratch reclaim: cannot list %s: %s", job_root, exc)
        return 0
    # ROTATE the starting point. iterdir order is stable, so a capped sweep examined the same
    # prefix every tick -- and a prefix of permanently-held trees (a legacy result with no durable
    # copy, a retained orphan) would consume the whole cap forever and starve every candidate
    # behind it, which is exactly the unbounded growth the cap was added to prevent. Deterministic
    # (no clock, no randomness): advance by the cap each sweep so successive ticks cover the whole
    # directory (#85 review).
    if entries and max_per_sweep > 0:
        start = _sweep_cursor.get(str(job_root), 0) % len(entries)
        entries = entries[start:] + entries[:start]
        _sweep_cursor[str(job_root)] = (start + max_per_sweep) % len(entries)
    # Canonical paths this sweep must never delete whatever they are named. The uuid4 shape
    # check protects a conventionally-named blob root ("blobs"), but BLASTBOX_BLOB_LOCAL_ROOT is
    # operator-set and may itself be a uuid-shaped directory directly beneath job_root -- in which
    # case the shape check waves it through and the sweep deletes every durable result on the node
    # (upstream review of #85). Compare canonically so a symlinked or ..-laden setting still
    # matches.
    protected: set[Path] = set()
    for p in protect_paths:
        try:
            protected.add(Path(p).resolve())
        except (OSError, RuntimeError, ValueError):
            continue
    # ...and whatever the blob store ITSELF says it is rooted at. Reading only the environment
    # meant a store constructed in code (`Dispatcher(blob_store=LocalBlobStore(..., blob_root=X))`
    # -- a public kwarg) or a process with drifted env was protected by nothing at all, and the
    # uuid-shape check does not save a uuid-named blob root (#85 review).
    local_root = getattr(blob_store, "local_root", None)
    if local_root is not None:
        try:
            protected.add(Path(local_root).resolve())
        except (OSError, RuntimeError, ValueError):
            pass
    retained_last_copy: list[str] = []
    unreachable_last_copy: list[str] = []
    unconfirmed: list[str] = []
    clock_suspect: list[str] = []
    # Counts WORK, not deletions. Capping on removals alone never bounded anything in the state
    # this was written for: a retained or undeletable tree still costs a full rglob walk, a store
    # round-trip and a has_output() call, none of which advanced the counter -- so the sweep
    # re-walked all 97,681 candidates every tick and the cap message never fired (#85 review).
    examined = 0
    for i, d in enumerate(entries):
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
            # A container this node never confirmed dead may still hold output/ bind-mounted
            # 0o777; rmtree'ing under it half-deletes the tree, frees nothing (its fds pin the
            # blocks) and fires the spurious "PURGE FAILED". Honoured across processes and
            # restarts -- but NOT forever: past twice the reclaim age, a container that still has
            # not died is an operator problem, and the disk bound has to win (#85 review).
            try:
                orphan_marked = (d / RETAINED_ORPHAN_SENTINEL).lstat().st_mtime
            except OSError:
                orphan_marked = None
            if orphan_marked is not None and orphan_marked > now - (max_age_s * 2):
                continue
            # CONTAINMENT, not equality: a blob root NESTED under a candidate
            # (<job_root>/<uuid>/blobs) is destroyed by deleting the candidate, so equality
            # protected it not at all.
            if protected:
                rd = d.resolve()
                # Only paths deleting THIS candidate would destroy: the candidate itself, or a
                # protected root nested inside it. NOT the reverse -- a protected path that is an
                # ANCESTOR of job_root (e.g. blob_root=<job_root>/.., the parent that holds both
                # `jobs/` and `blobs/`) made every job dir "protected" and silently disabled the
                # entire reclaim, which is the leak this exists to stop (#85 review).
                if any(rd == p or p.is_relative_to(rd) for p in protected):
                    continue
        except (OSError, RuntimeError, ValueError):
            continue
        # BOUNDED per tick, checked HERE. Everything above is a couple of cheap stats;
        # everything below is the expensive half -- a full recursive walk, a store round-trip and
        # a has_output() call per candidate. The state this exists to clean up is 97,681 dirs /
        # 184 GiB, and doing it in one pass runs all of that ahead of every other maintenance
        # task, including the cold-permit reclaim and crash recovery. Placing the check after the
        # work (and counting only REMOVALS) bounded nothing: a retained or undeletable tree costs
        # the same work, never advanced the counter, and `continue`d straight past the check. The
        # sweep is idempotent and runs every tick, so the backlog still drains -- just without one
        # tick owning the process. Announced, never silent: a cap you cannot see reads as "fully
        # cleaned" (#85 review).
        if examined >= max_per_sweep:
            log.info("scratch reclaim: hit the %d-candidate cap this sweep (%d removed); %d not "
                     "examined, continuing next tick", max_per_sweep, n, len(entries) - i)
            break
        examined += 1
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
            # CTIME, not mtime, and no future-clamp. The worker owns output/ (a 0o777 bind
            # mount) and utime() is unprivileged, so it can stamp mtime anywhere it likes --
            # which is why an earlier version discarded a future mtime as "no evidence". That
            # traded one bug for a worse one: after a backward clock step (an ordinary NTP
            # correction) EVERY honest timestamp looks like the future, so a node's live trees
            # read as ancient and were deleted seconds after being created -- reproduced with a
            # 1h rollback.
            #
            # ctime has no setter. No syscall backdates or forward-dates it, and any metadata
            # change bumps it to now, so a sample cannot forge it at all -- the anti-evasion
            # property comes for free instead of from a clamp. A ctime in the FUTURE therefore
            # means the CLOCK is wrong, not that we are under attack, and the safe reading of
            # "I cannot tell how old this is" is to leave it alone and say so once, not to
            # delete it (#85 review, from an untriaged round-6 codex finding).
            horizon = now + 60.0

            def _evidence(st: "os.stat_result") -> float:
                if st.st_mtime <= horizon:
                    return st.st_mtime          # an ordinary, plausible stamp
                # A future mtime is either an evasion attempt or a clock that moved. ctime tells
                # them apart, because nothing can set it: if ctime is sane, the mtime was forged
                # and ctime is the honest age; if ctime is ALSO in the future, the clock is wrong
                # and this tree's age is simply unknowable.
                return st.st_ctime if st.st_ctime <= horizon else float("inf")

            newest = _evidence(d.lstat())
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
                    newest = max(newest, _evidence(child.lstat()))
                    live = newest > cutoff
                except OSError:
                    continue
        except (OSError, RuntimeError):
            continue
        if newest == float("inf"):
            clock_suspect.append(d.name)
        if live:
            continue
        if d.name in retained:
            continue
        # Belt and braces: age is a heuristic, job state is a fact. Never reclaim a tree whose
        # job is still live. A job unknown to the store is a genuine orphan and IS reclaimable.
        try:
            job = job_store.get(d.name)
        except Exception:  # noqa: BLE001 -- store trouble must not turn into deletion
            unconfirmed.append(d.name)      # aggregated: see below
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
        # ...but ONLY for a tree the HOST vouches for. output/metadata.json cannot be that
        # evidence: the WORKER writes it (worker/harness.py) and the host merely OVERWRITES it
        # once the trust gate passes, so keying on its presence retained every crash-orphaned
        # tree forever -- has_output() is False, no sweep drains it, and #84's unbounded
        # accumulation comes straight back with the malware input still on disk. Two host-only
        # facts qualify instead:
        #   * the pending-upload sentinel -- the host sealed a result and its upload failed; or
        #   * a DONE row with nothing durable -- a pre-blob-store job whose only copy is the
        #     legacy <job_root>/<id>/output path LocalBlobStore.open_output still falls back to.
        # Anything else is scratch, and reclaiming it on age is the entire point (#85 review).
        # A pending-upload hold is only meaningful while the job is FAILED and awaiting its
        # retry. If retention EXPIRED it (the operator's schedule deliberately dropped that
        # result, and expire_due clears expires_at so it is never selected again) or the row is
        # gone entirely (DELETE /v1/jobs), nothing will ever upload the tree -- retry_pending_
        # uploads requires a FAILED row -- so holding it is an immortal leak, not protection.
        marked = (d / PENDING_UPLOAD_SENTINEL).is_file()
        # The hold only means anything while the retry is genuinely outstanding: the sweep needs a
        # FAILED row, so once the row is EXPIRED (retention dropped it) or gone (deleted, or a
        # Redis key past its TTL) nothing will ever upload this tree and holding it is an
        # immortal leak. But deleting the only copy of a sealed result is not routine hygiene
        # either -- it is data loss, and it says so, once, at ERROR (#85 review).
        pending = marked and job is not None and job.status is JobStatus.FAILED
        if marked and not pending:
            unreachable_last_copy.append(d.name)
        if pending or (job is not None and job.status is JobStatus.DONE):
            # NOT gated on having a blob store. Without one there is no durable copy to check --
            # which means we cannot prove this tree is redundant, so it is the LAST copy by
            # definition and deleting it is unconditional data loss. Gating the whole protection
            # on `blob_store is not None` meant the DEFAULT argument silently disabled it: every
            # production caller passes a store, so this never bit, but any new caller inherited a
            # sweep that deletes sealed results (#85 review, full-PR sweep).
            try:
                durable = blob_store.has_output(d.name) if blob_store is not None else False
            except Exception:  # noqa: BLE001 -- unknown is NOT durable
                durable = False
            # AGGREGATED, not per-tree: a fleet mid-migration can hold thousands of these, and one
            # WARNING each per tick buries every other line. One count per sweep says it.
            if not durable:
                retained_last_copy.append(d.name)
                continue
            # Durable, but the job is still not DONE: the status repair has not landed (a store
            # blip mid-sweep). Deleting now strands the job FAILED forever with bytes it can
            # never serve, because the repair's fall-through needs this tree next tick.
            if pending and (job is None or job.status is not JobStatus.DONE):
                retained_last_copy.append(d.name)
                continue
        # Count only what was actually removed: purge_job_dir refuses and fails
        # best-effort, and an unconditional increment made the operator-facing
        # "removed N job dir(s)" line report directories still on disk, forever.
        if purge_job_dir(job_root, d.name, log):
            n += 1
    if clock_suspect:
        log.warning("scratch reclaim: %d tree(s) carry timestamps in the future — the clock has "
                    "moved backwards, so their age cannot be judged and they were left alone "
                    "(e.g. %s)", len(clock_suspect), ", ".join(sorted(clock_suspect)[:3]))
    if unconfirmed:
        # ONE line, not up to max_per_sweep of them. A store outage on a node holding the #84
        # backlog emitted 2000 identical warnings per tick, burying the store error itself --
        # the same reason the last-copy warning below is aggregated.
        log.warning("scratch reclaim: could not confirm %d job(s) are terminal (store error); "
                    "leaving them (e.g. %s)", len(unconfirmed), ", ".join(sorted(unconfirmed)[:3]))
    if unreachable_last_copy:
        log.error("scratch reclaim: DELETING %d tree(s) whose result was never durably stored and "
                  "whose job row is gone or expired — nothing can upload them and nothing can "
                  "serve them, so this is data loss, not hygiene (e.g. %s)",
                  len(unreachable_last_copy), ", ".join(sorted(unreachable_last_copy)[:3]))
    if retained_last_copy:
        log.warning("scratch reclaim: retained %d tree(s) holding a sealed result with no durable "
                    "copy in the blob store — deleting them would destroy the last copy (e.g. %s)",
                    len(retained_last_copy), ", ".join(sorted(retained_last_copy)[:3]))
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
        # NEVER delete a pending-upload tree. The reclaim two blocks earlier in this same
        # maintenance tick deliberately spares it as the only copy of a host-sealed result, and
        # this sweeper would then rmtree it a few lines later -- with the operator's own
        # BLASTBOX_JOB_RETENTION_SECONDS as the trigger, and with the docs promising the exact
        # opposite. Expiry is a RESULT lifecycle policy; it has no business destroying bytes that
        # were never durably stored in the first place (#85 review). The blob delete below still
        # runs (it is a no-op when nothing landed) and the row still advances, so a later sweep
        # after the upload finally succeeds collects the tree normally.
        pending = (self._job_root / job_id / PENDING_UPLOAD_SENTINEL).is_file()
        if pending:
            _log.warning("retention: %s has a sealed result with no durable copy; expiring the "
                         "row but KEEPING the local tree (it is the only copy)", job_id)
        if result_dir is not None and not pending:
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
