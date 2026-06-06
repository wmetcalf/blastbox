"""Redis-backed JobStore.

Serializes jobs as JSON (not pickle).  Uses ``scan_iter`` (not KEYS) so it
works on large key spaces without blocking.  Every ``set`` includes a TTL.
``claim_next`` is atomic via WATCH/MULTI/EXEC with WatchError retry.
"""

from __future__ import annotations

import dataclasses
import json
import time

from redis.exceptions import WatchError

from blastbox.host.jobs.base import Job, JobStatus

# Allowlist of Job fields that update() may set — mirrors SqlJobStore's _COLUMNS guard so a
# future caller forwarding client-controlled field names can't setattr an arbitrary attribute.
_JOB_FIELDS = frozenset(f.name for f in dataclasses.fields(Job))


_PREFIX = "blastbox:job:"
_TTL_SECONDS = 60 * 60 * 24  # 24 hours default


class RedisJobStore:
    """Redis-backed job store.

    Security / correctness properties:
    - JSON serialization (NOT pickle) — safe across language boundaries, no
      arbitrary code execution on deserialization.
    - ``scan_iter`` (NOT KEYS) — safe on large production key spaces.
    - TTL on every ``set`` — keys expire automatically; pass ``ttl_seconds=0``
      to disable (no-expiry).
    - Atomic claim via WATCH/MULTI/EXEC with WatchError retry — two concurrent
      claimers racing on the same job result in exactly one claim.
    """

    def __init__(self, client, *, ttl_seconds: int = _TTL_SECONDS) -> None:
        self._r = client
        self._ttl_seconds = ttl_seconds

    def _key(self, job_id: str) -> str:
        return _PREFIX + job_id

    def _expiry_arg(self) -> int | None:
        return self._ttl_seconds if self._ttl_seconds > 0 else None

    def create(self, job: Job) -> None:
        self._r.set(
            self._key(job.job_id),
            json.dumps(job.to_dict()),
            ex=self._expiry_arg(),
        )

    def get(self, job_id: str) -> Job | None:
        raw = self._r.get(self._key(job_id))
        if raw is None:
            return None
        return Job.from_dict(json.loads(raw))

    def update(self, job_id: str, **fields) -> Job:
        """Atomic read-modify-write via WATCH/MULTI/EXEC."""
        key = self._key(job_id)
        with self._r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    if raw is None:
                        raise KeyError(job_id)
                    job = Job.from_dict(json.loads(raw))
                    for k, v in fields.items():
                        if k not in _JOB_FIELDS:
                            raise ValueError(f"unknown Job field in update(): {k!r}")
                        setattr(job, k, v)
                    pipe.multi()
                    pipe.set(key, json.dumps(job.to_dict()), ex=self._expiry_arg())
                    pipe.execute()
                    return job
                except WatchError:
                    continue  # retry on concurrent modification

    def list(self, status: JobStatus | None = None) -> list[Job]:
        jobs: list[Job] = []
        for k in self._r.scan_iter(match=_PREFIX + "*", count=200):
            raw = self._r.get(k)
            if raw is None:
                continue
            job = Job.from_dict(json.loads(raw))
            if status is None or job.status == status:
                jobs.append(job)
        return jobs

    def claim_next(self) -> Job | None:
        """Atomically claim the oldest QUEUED job.

        Scans all keys with the store prefix, picks the oldest QUEUED job,
        then atomically updates it via WATCH/MULTI/EXEC.  If another claimer
        races and modifies the key (WatchError), retries from scratch.
        """
        while True:
            candidates: list[tuple[float, str, str]] = []
            for k in self._r.scan_iter(match=_PREFIX + "*", count=200):
                raw = self._r.get(k)
                if raw is None:
                    continue
                job = Job.from_dict(json.loads(raw))
                if job.status == JobStatus.QUEUED:
                    # Decode key to str for comparison; fakeredis may return bytes
                    k_str = k.decode() if isinstance(k, bytes) else k
                    candidates.append((job.created_at, job.job_id, k_str))
            if not candidates:
                return None

            _, _, key = min(candidates, key=lambda item: (item[0], item[1]))
            try:
                with self._r.pipeline() as pipe:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    if raw is None:
                        continue
                    job = Job.from_dict(json.loads(raw))
                    if job.status != JobStatus.QUEUED:
                        # Another claimer won the race; retry from the scan.
                        continue
                    job.status = JobStatus.RUNNING
                    job.started_at = time.time()
                    pipe.multi()
                    pipe.set(key, json.dumps(job.to_dict()), ex=self._expiry_arg())
                    pipe.execute()
                    return job
            except WatchError:
                continue  # retry on concurrent modification

    def delete(self, job_id: str) -> None:
        self._r.delete(self._key(job_id))
