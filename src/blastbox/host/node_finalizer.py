"""``blastbox node-finalizer``: seal what pull nodes uploaded, where the attest key lives.

The ingress only extracts a node's result tar into a quarantine spool (``node_results``); it
never holds the attest key and never trust-gates. This control-plane service holds the DB, the
blob store and the attest key, and NEVER claims work. For each quarantined tree it runs the
exact cold-path code (``Dispatcher.finalise_output``: size cap, trust gate, host re-seal,
signed receipt, upload, claim-fenced CAS to DONE), then records the verdict in ``outcome.json``
for the node's (idempotent) PUT replay to read.
"""
from __future__ import annotations

import fcntl
import logging
import os
import shutil
import threading
import time
from pathlib import Path

from blastbox.limits import Limits
from blastbox.host import attest as _attest
from blastbox.host import node_results as nr
from blastbox.host.dispatch import Dispatcher
from blastbox.host.ingress.node_claim import MAX_FUTURE_SKEW_S
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.retention import PENDING_UPLOAD_SENTINEL, retry_pending_uploads

_log = logging.getLogger(__name__)

LOCK_NAME = ".finalize.lock"
RETAIN_ENV = "BLASTBOX_NODE_RESULTS_RETAIN_S"
DEFAULT_RETAIN_S = 3600.0
NODE_TIER = "node-agent"
POISON_REASON = "finalisation failed repeatedly"
RETAINED_REASON = "result upload failed; tree retained"
ATTEMPTS_NAME = ".attempts"
MAX_ATTEMPTS = 5
STALE_NO_OUTCOME_S = 24 * 3600.0


def retain_seconds(env: "dict[str, str] | None" = None) -> float:
    raw = ((env if env is not None else os.environ).get(RETAIN_ENV, "") or "").strip()
    if not raw:
        return DEFAULT_RETAIN_S
    try:
        v = float(raw)
    except ValueError:
        _log.error("%s=%r is not a number; using %ss", RETAIN_ENV, raw, DEFAULT_RETAIN_S)
        return DEFAULT_RETAIN_S
    if v != v or v < 0:
        _log.error("%s=%r is not a non-negative number; using %ss", RETAIN_ENV, raw,
                   DEFAULT_RETAIN_S)
        return DEFAULT_RETAIN_S
    return v


class NodeFinalizer:
    def __init__(self, *, job_store, blob_store, limits: Limits, job_root: Path,
                 attest_key: object = _attest.FROM_ENV, results_dir: Path | None = None,
                 retain_s: float | None = None) -> None:
        self._store = job_store
        self._job_root = Path(job_root)
        self._blobs = blob_store
        self._root = Path(results_dir) if results_dir is not None else nr.results_root(job_root)
        self._retain_s = retain_seconds() if retain_s is None else retain_s
        self._dispatcher = Dispatcher(
            job_store=job_store, engines={}, limits=limits, job_root=Path(job_root),
            blob_store=blob_store, attest_key=attest_key,
        )
        self._attest_key = self._dispatcher._attest_key

    # ------------------------------------------------------------------ public

    def run_once(self) -> int:
        """Finalise every pending spool dir; return how many were finalised by THIS call."""
        n = 0
        for d in list(nr.pending(self._root)):
            try:
                if self._finalise_dir(d):
                    n += 1
            except Exception:  # noqa: BLE001 - one bad tree must not wedge the sweep
                _log.exception("node-finalizer: unexpected error on %s; will retry", d)
        # No dispatcher runs in the cut-over topology, so the finalizer owns the pending-upload
        # sweep: a retained result lives under job_root/<job>/output and this drains it.
        try:
            retry_pending_uploads(self._job_root, self._blobs, self._store, _log,
                                  on_repaired=self._dispatcher._index_repaired_result,
                                  attest_key=self._attest_key)
        except Exception:  # noqa: BLE001
            _log.exception("node-finalizer: pending-upload sweep failed")
        self._sweep_old()
        return n

    def run_forever(self, stop: threading.Event, interval: float = 1.0) -> None:
        while not stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                _log.exception("node-finalizer: sweep failed")
            stop.wait(interval)

    # ------------------------------------------------------------------ internals

    def _finalise_dir(self, d: Path) -> bool:
        try:
            fd = os.open(d / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False                    # another replica holds it
            if nr.read_outcome(d) is not None:  # finished while we waited
                return False
            marker = nr.read_marker(d)
            if marker is None:
                return False
            try:
                status, reason = self._decide(d, marker)
            except Exception:  # noqa: BLE001
                n = self._bump_attempts(d)
                if n < MAX_ATTEMPTS:
                    _log.exception("node-finalizer: attempt %d/%d failed for job %s; will retry",
                                   n, MAX_ATTEMPTS, marker.job_id)
                    return False
                _log.exception("node-finalizer: job %s failed %d times; giving up",
                               marker.job_id, n)
                status, reason = "failed", POISON_REASON
                job = self._store.get(marker.job_id)
                if job is not None and job.claim_id == marker.claim_id:
                    self._dispatcher._fail_job(job, POISON_REASON)
                shutil.rmtree(d / nr.OUT, ignore_errors=True)
            nr.write_outcome(d, status, reason)
            _log.info("node-finalizer: job %s claim %s -> %s%s", marker.job_id,
                      nr.claim_digest(marker.claim_id), status, f" ({reason})" if reason else "")
            return True
        finally:
            os.close(fd)                        # releases the flock

    @staticmethod
    def _bump_attempts(d: Path) -> int:
        f = d / ATTEMPTS_NAME
        try:
            n = int(f.read_text().strip() or "0")
        except (OSError, ValueError):
            n = 0
        n += 1
        try:
            f.write_text(str(n))
        except OSError:
            _log.warning("node-finalizer: cannot persist the attempt counter in %s", d)
        return n

    def _output_dir(self, job_id: str) -> Path:
        return self._job_root / job_id / "output"

    def _stage(self, d: Path, job: Job) -> Path | None:
        """Move the quarantined tree into the cold dispatcher's output layout, so a retained
        result is owned by the existing pending-upload machinery. None when nothing to run."""
        out = d / nr.OUT
        dest = self._output_dir(job.job_id)
        if not out.is_dir():
            return dest if dest.is_dir() else None     # moved by an earlier, crashed attempt
        jd = dest.parent
        jd.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            if (jd / PENDING_UPLOAD_SENTINEL).exists():
                raise RuntimeError(f"{dest} already holds a retained result")
            shutil.rmtree(dest)
        os.rename(out, dest)                           # same volume (job_root/results share it)
        return dest

    def _decide(self, d: Path, marker: nr.UploadMarker) -> tuple[str, str | None]:
        job = self._store.get(marker.job_id)
        if job is None or job.claim_id != marker.claim_id:
            return "failed", "claim lost"
        if job.status == JobStatus.DONE:        # crashed between the CAS and the outcome write
            return "done", None
        if job.status == JobStatus.FAILED:
            return "failed", job.error or "job failed"
        if job.status != JobStatus.RUNNING:
            return "failed", "claim lost"
        if not job.input_sha256:
            self._dispatcher._fail_job(job, "input hash missing; refusing to seal")
            return "failed", "input hash missing; refusing to seal"
        out = self._stage(d, job)
        if out is None:
            self._dispatcher._fail_job(job, "result tree missing")
            return "failed", "result tree missing"
        res = self._dispatcher.finalise_output(job, out, self._observation(job, marker))
        if res == "retained":
            return "failed", RETAINED_REASON    # the tree stays under job_root for the sweep
        self._discard_staged(job, out)
        if res == "done":
            return "done", None
        if res == "lost":
            return "failed", "claim lost"
        return "failed", res[len("failed: "):] if res.startswith("failed: ") else res

    def _discard_staged(self, job: Job, out: Path) -> None:
        """The staged tree is spent (sealed + uploaded, or failed). Never remove it while a row
        could still be RUNNING under someone else's claim, or while a sentinel names it."""
        jd = out.parent
        if (jd / PENDING_UPLOAD_SENTINEL).exists():
            return
        try:
            cur = self._store.get(job.job_id)
        except Exception:  # noqa: BLE001
            return
        if cur is not None and cur.status == JobStatus.RUNNING and cur.claim_id != job.claim_id:
            return
        shutil.rmtree(out, ignore_errors=True)

    @staticmethod
    def _observation(job: Job, marker: nr.UploadMarker) -> _attest.RunObservation:
        now = _attest.now_ms()
        cap = now + int(MAX_FUTURE_SKEW_S * 1000)
        started = min(int(marker.started_at_ms if marker.started_at_ms is not None else now), cap)
        finished = min(max(int(marker.finished_at_ms if marker.finished_at_ms is not None
                               else now), started), cap)
        return _attest.RunObservation(
            job_id=job.job_id, engine=job.engine, input_sha256=job.input_sha256 or "",
            worker_runtime=marker.worker_runtime, worker_tier=NODE_TIER,
            started_at_ms=started, finished_at_ms=finished,
            node_id=marker.node_id, node_cert_sha256=marker.node_cert_sha256,
        )

    def _sweep_old(self) -> None:
        cutoff = time.time() - self._retain_s
        try:
            jobs = list(self._root.iterdir())
        except OSError:
            return
        for jd in jobs:
            if not jd.is_dir():
                continue
            try:
                claims = list(jd.iterdir())
            except OSError:
                continue
            for cd in claims:
                try:
                    if (cd / nr.OUTCOME).is_file():
                        if (cd / nr.OUTCOME).stat().st_mtime < cutoff:
                            shutil.rmtree(cd, ignore_errors=True)
                    elif ".partial" not in cd.name and cd.is_dir() \
                            and cd.stat().st_mtime < time.time() - STALE_NO_OUTCOME_S:
                        _log.warning("node-finalizer: removing %s: no outcome after %.0fh",
                                     cd, STALE_NO_OUTCOME_S / 3600)
                        shutil.rmtree(cd, ignore_errors=True)
                except OSError:
                    continue
            try:
                jd.rmdir()                      # only succeeds when empty
            except OSError:
                pass
