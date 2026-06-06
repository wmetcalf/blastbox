"""Thread-safe in-memory JobStore."""

from __future__ import annotations

import dataclasses
import threading
import time

from blastbox.host.jobs.base import Job, JobStatus

# Allowlist of Job fields that update() may set — mirrors RedisJobStore._JOB_FIELDS and
# SqlJobStore._COLUMNS so all three backends fail closed identically on an unknown field
# name (a typo'd/invalid key that prod SQL/Redis reject must not silently succeed here).
_JOB_FIELDS = frozenset(f.name for f in dataclasses.fields(Job))


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
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            for k, v in fields.items():
                if k not in _JOB_FIELDS:
                    raise ValueError(f"unknown Job field in update(): {k!r}")
                setattr(job, k, v)
            return job

    def list(
        self,
        status: JobStatus | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        if newest_first:
            jobs.sort(key=lambda j: (j.created_at, j.job_id), reverse=True)
        if offset:
            jobs = jobs[offset:]
        if limit is not None:
            jobs = jobs[:limit]
        return jobs

    def count(self, status: JobStatus | None = None) -> int:
        with self._lock:
            if status is None:
                return len(self._jobs)
            return sum(1 for j in self._jobs.values() if j.status == status)

    def claim_next(self) -> Job | None:
        """Atomically claim the oldest QUEUED job and flip it to RUNNING."""
        with self._lock:
            queued = [
                job for job in self._jobs.values()
                if job.status == JobStatus.QUEUED
            ]
            if not queued:
                return None
            job = min(queued, key=lambda j: (j.created_at, j.job_id))
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            return job

    def delete(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)
