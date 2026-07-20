"""Thread-safe in-memory JobStore."""

from __future__ import annotations

from collections.abc import Collection

import copy
import dataclasses
import threading
import time
import uuid

from blastbox.host.jobs.base import Job, JobStatus, filter_sort_window, normalize_engine_filter

# Allowlist of Job fields that update() may set — mirrors RedisJobStore._JOB_FIELDS and
# SqlJobStore._COLUMNS so all three backends fail closed identically on an unknown field
# name (a typo'd/invalid key that prod SQL/Redis reject must not silently succeed here).
_JOB_FIELDS = frozenset(f.name for f in dataclasses.fields(Job))


def _snapshot(job: Job | None) -> Job | None:
    """Return a deep copy so callers get a stable SNAPSHOT, never the live store object.

    The multi-dispatcher safety model rests on ``update_if_status(expect_claim_id=...)``: it
    compares the caller's expected claim_id against the LIVE store value. The SQL/Redis backends
    return freshly-deserialized objects, so the caller's expectation is a fixed snapshot. If THIS
    store handed back the live object, a concurrent requeue+reclaim (RUNNING->QUEUED[None]->
    RUNNING[NEW]) would mutate that shared object — so both sides of the CAS would read NEW and the
    guard would wrongly pass, defeating the exact ABA fence claim_id exists to close (and aliasing
    _delete_input_if_owned the same way). Deep-copy on the way out closes it; match SQL/Redis."""
    return copy.deepcopy(job) if job is not None else None


class InMemoryJobStore:
    """Non-persistent, thread-safe job store backed by a plain dict.

    Suitable for single-process dev/test use.  Concurrent ``claim_next``
    calls are serialised by a reentrant lock so no job is ever double-claimed.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def create(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return _snapshot(self._jobs.get(job_id))

    def update(self, job_id: str, **fields) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            for k, v in fields.items():
                if k not in _JOB_FIELDS:
                    raise ValueError(f"unknown Job field in update(): {k!r}")
                setattr(job, k, v)
            # job is non-None here (KeyError raised above), so return a Job (not Job|None).
            return copy.deepcopy(job)

    def update_if_status(
        self,
        job_id: str,
        expect_status: JobStatus,
        *,
        expect_claim_id: str | None = None,
        **fields,
    ) -> bool:
        # Validate field names BEFORE the status guard so an unknown field fails fast (ValueError)
        # uniformly across all backends — not silently no-op on a status mismatch here while the
        # SQL backend raises. (An unknown field is a programming error, never client/worker input.)
        for k in fields:
            if k not in _JOB_FIELDS:
                raise ValueError(f"unknown Job field in update_if_status(): {k!r}")
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != expect_status:
                return False
            if expect_claim_id is not None and job.claim_id != expect_claim_id:
                return False
            for k, v in fields.items():
                setattr(job, k, v)
            return True

    def list(
        self,
        status: JobStatus | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
        newest_first: bool = False,
        q: str | None = None,
        sort: str | None = None,
        order: str = "desc",
    ) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        jobs = filter_sort_window(
            jobs, q=q, sort=sort, order=order, newest_first=newest_first,
            offset=offset, limit=limit,
        )
        return [copy.deepcopy(j) for j in jobs]

    def count(self, status: JobStatus | None = None, *, q: str | None = None,
              engine: "str | Collection[str] | None" = None,
              claimant_tier: str | None = None) -> int:
        with self._lock:
            jobs = list(self._jobs.values())
        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        engines = normalize_engine_filter(engine)
        if engines is not None:
            jobs = [j for j in jobs if j.engine in engines]
        if claimant_tier is not None:      # same routing as claim_next: untargeted OR mine
            jobs = [j for j in jobs
                    if j.target_tier is None or j.target_tier == claimant_tier]
        if q:
            ql = q.lower()
            jobs = [j for j in jobs if ql in (j.filename or "").lower()]
        return len(jobs)

    def claim_next(self, *, claimant_tier: str | None = None,
                   engine: "str | Collection[str] | None" = None) -> Job | None:
        """Atomically claim the oldest QUEUED job and flip it to RUNNING.

        ``claimant_tier`` routes: a job with ``target_tier`` set is claimable only by a
        claimant whose tier matches; an untargeted job (the default) by anyone. ``engine`` (a name
        or the set of engines this claimant handles) restricts the claim (shared multi-engine stores).
        """
        engines = normalize_engine_filter(engine)
        now = time.time()
        with self._lock:
            queued = [
                job for job in self._jobs.values()
                if job.status == JobStatus.QUEUED
                and (job.target_tier is None or job.target_tier == claimant_tier)
                and (engines is None or job.engine in engines)
                # skip DEFERRED jobs (claimable_after in the future) so a capacity-blocked cold job
                # isn't reclaimed ahead of claimable work
                and (job.claimable_after is None or job.claimable_after <= now)
            ]
            if not queued:
                return None
            job = min(queued, key=lambda j: (j.created_at, j.job_id))
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            job.claim_id = uuid.uuid4().hex  # fresh ownership token per claim
            return _snapshot(job)

    def delete(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)
