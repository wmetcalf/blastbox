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
from blastbox.host.jobs.base import Job, JobStatus

_log = logging.getLogger(__name__)

LOCK_NAME = ".finalize.lock"
RETAIN_ENV = "BLASTBOX_NODE_RESULTS_RETAIN_S"
DEFAULT_RETAIN_S = 3600.0
NODE_TIER = "node-agent"
RETAINED_REASON = "result upload failed; tree retained"


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
        self._root = Path(results_dir) if results_dir is not None else nr.results_root(job_root)
        self._retain_s = retain_seconds() if retain_s is None else retain_s
        self._dispatcher = Dispatcher(
            job_store=job_store, engines={}, limits=limits, job_root=Path(job_root),
            blob_store=blob_store, attest_key=attest_key,
        )

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
            status, reason, ran = self._decide(d, marker)
            nr.write_outcome(d, status, reason)
            # The extracted tree is spent once sealed -- except a failed upload, whose tree is
            # the only copy of a host-sealed result (the age sweep reclaims it with the dir).
            if ran and reason != RETAINED_REASON:
                shutil.rmtree(d / nr.OUT, ignore_errors=True)
            _log.info("node-finalizer: job %s claim %s -> %s%s", marker.job_id,
                      nr.claim_digest(marker.claim_id), status, f" ({reason})" if reason else "")
            return True
        finally:
            os.close(fd)                        # releases the flock

    def _decide(self, d: Path, marker: nr.UploadMarker) -> tuple[str, str | None, bool]:
        """(status, reason, whether the tree was actually run through finalise_output)."""
        job = self._store.get(marker.job_id)
        if job is None or job.claim_id != marker.claim_id:
            return "failed", "claim lost", False
        if job.status == JobStatus.DONE:        # crashed between the CAS and the outcome write
            return "done", None, False
        if job.status == JobStatus.FAILED:
            return "failed", job.error or "job failed", False
        if job.status != JobStatus.RUNNING:
            return "failed", "claim lost", False
        res = self._dispatcher.finalise_output(
            job, d / nr.OUT, self._observation(job, marker))
        if res == "done":
            return "done", None, True
        if res == "lost":
            return "failed", "claim lost", True
        if res == "retained":
            return "failed", RETAINED_REASON, True
        reason = res[len("failed: "):] if res.startswith("failed: ") else res
        return "failed", reason, True

    @staticmethod
    def _observation(job: Job, marker: nr.UploadMarker) -> _attest.RunObservation:
        now = _attest.now_ms()
        started = marker.started_at_ms if marker.started_at_ms is not None else now
        finished = marker.finished_at_ms if marker.finished_at_ms is not None else now
        return _attest.RunObservation(
            job_id=job.job_id, engine=job.engine, input_sha256=job.input_sha256 or "",
            worker_runtime=marker.worker_runtime, worker_tier=NODE_TIER,
            started_at_ms=int(started), finished_at_ms=int(finished),
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
                    if (cd / nr.OUTCOME).stat().st_mtime < cutoff:
                        shutil.rmtree(cd, ignore_errors=True)
                except OSError:
                    continue
            try:
                jd.rmdir()                      # only succeeds when empty
            except OSError:
                pass
