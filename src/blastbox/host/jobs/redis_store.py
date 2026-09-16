"""Redis-backed JobStore.

Serializes jobs as JSON (not pickle).  Uses ``scan_iter`` (not KEYS) so it
works on large key spaces without blocking.  Every ``set`` includes a TTL.
``claim_next`` is atomic via WATCH/MULTI/EXEC with WatchError retry.
"""

from __future__ import annotations

from collections.abc import Collection

import dataclasses
import json
import logging
import time
import uuid

from redis.exceptions import WatchError

from blastbox.host.jobs.base import Job, JobStatus, filter_sort_window, normalize_engine_filter

_log = logging.getLogger("blastbox.host.jobs.redis_store")


def _decode_job(raw: object) -> Job | None:
    """Decode a stored value into a Job, or None (logged) if it isn't valid job JSON — so a
    malformed key sharing the blastbox:job:* prefix (shared/operator-mutable Redis) can't crash
    list()/claim_next()."""
    try:
        return Job.from_dict(json.loads(raw))  # type: ignore[arg-type]
    except (ValueError, TypeError, KeyError) as exc:
        _log.warning("redis_store: skipping malformed job key payload: %s", exc)
        return None

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

    Scaling caveat: ``list()``/``count()`` and ``claim_next()`` ``scan_iter`` +
    ``GET`` + JSON-decode EVERY key (there is no server-side ORDER BY/LIMIT over a
    Redis key space), so listing and claim are **O(N) in the live job count**.  The
    24h TTL bounds N, but for LARGE or high-throughput job histories use the SQL
    (Postgres) backend, which pushes the window + ``COUNT`` down into the query.  A
    ZSET created_at/status index could make these O(log N + page) but is deferred
    (it must also cover ``claim_next`` to move the bottleneck, and stay byte-identical
    to the scan path under the backend-uniform pagination tests).
    """

    def __init__(self, client, *, ttl_seconds: int = _TTL_SECONDS) -> None:
        self._r = client
        self._ttl_seconds = ttl_seconds

    # -- BlobTargetRegistry -------------------------------------------------------------
    _BLOB_TARGET_KEY = "blastbox:blob_target"

    def claim_blob_target(self, fingerprint: str) -> "str | None":
        """SET NX then GET -- atomic on the server, so a boot storm has one winner.

        No TTL: this outlives every job and must survive an idle queue, or two processes that
        started days apart would never be compared. Cleared explicitly (`blastbox blob-target`).
        """
        self._r.set(self._BLOB_TARGET_KEY, fingerprint, nx=True)
        cur = self._r.get(self._BLOB_TARGET_KEY)
        if cur is None:
            # SET NX and GET are each atomic; the PAIR is not. A DEL landing between them -- the
            # documented `blastbox blob-target reset`, run while a mismatched process crash-loops --
            # leaves this nil. Returning our own fingerprint here reported AGREEMENT to the caller
            # and booted the losing side on the wrong target. An `allkeys-*` eviction reaches the
            # same window with no operator involved, since this key carries no TTL.
            return None
        return cur.decode() if isinstance(cur, (bytes, bytearray)) else str(cur)

    def get_blob_target(self) -> "str | None":
        cur = self._r.get(self._BLOB_TARGET_KEY)
        if cur is None:
            return None
        return cur.decode() if isinstance(cur, (bytes, bytearray)) else str(cur)

    def clear_blob_target(self) -> None:
        self._r.delete(self._BLOB_TARGET_KEY)

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
        return _decode_job(raw)  # None on malformed payload -> treated as not found

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
                    job = _decode_job(raw)
                    if job is None:
                        raise KeyError(job_id)  # malformed payload -> fail closed, don't crash
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

    def update_if_status(
        self,
        job_id: str,
        expect_status: JobStatus,
        *,
        expect_claim_id: str | None = None,
        **fields,
    ) -> bool:
        """Compare-and-set via WATCH/MULTI/EXEC: apply ``fields`` only while status is still
        ``expect_status`` (and claim_id matches when ``expect_claim_id`` is given — closes the
        ABA hole). Returns False (no write) on missing/malformed/mismatched status or claim."""
        # Fail fast on an unknown field name BEFORE any Redis round-trip — uniform with the SQL
        # backend (which validates before the UPDATE) so the cross-backend contract holds.
        for k in fields:
            if k not in _JOB_FIELDS:
                raise ValueError(f"unknown Job field in update_if_status(): {k!r}")
        key = self._key(job_id)
        with self._r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    job = _decode_job(raw) if raw is not None else None
                    if job is None or job.status != expect_status or (
                        expect_claim_id is not None and job.claim_id != expect_claim_id
                    ):
                        pipe.unwatch()
                        return False
                    for k, v in fields.items():
                        setattr(job, k, v)
                    pipe.multi()
                    pipe.set(key, json.dumps(job.to_dict()), ex=self._expiry_arg())
                    pipe.execute()
                    return True
                except WatchError:
                    continue  # status changed under us -> retry, re-check the guard

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
        # Redis has no server-side ORDER BY/LIMIT over a scanned key space, so we
        # still collect matching jobs, then apply the same q-filter/sort/window the
        # SQL backend pushes down — keeping the protocol uniform for the endpoint.
        jobs: list[Job] = []
        for k in self._r.scan_iter(match=_PREFIX + "*", count=200):
            raw = self._r.get(k)
            if raw is None:
                continue
            job = _decode_job(raw)
            if job is None:
                continue
            if status is None or job.status == status:
                jobs.append(job)
        return filter_sort_window(
            jobs, q=q, sort=sort, order=order, newest_first=newest_first,
            offset=offset, limit=limit,
        )

    def count(self, status: JobStatus | None = None, *, q: str | None = None,
              engine: "str | Collection[str] | None" = None,
              claimant_tier: str | None = None, untargeted_only: bool = False) -> int:
        n = 0
        ql = q.lower() if q else None
        engines = normalize_engine_filter(engine)   # count ALL requested engines in ONE scan
        for k in self._r.scan_iter(match=_PREFIX + "*", count=200):
            raw = self._r.get(k)
            if raw is None:
                continue
            job = _decode_job(raw)
            if job is None:
                continue
            if status is not None and job.status != status:
                continue
            if engines is not None and job.engine not in engines:
                continue
            if untargeted_only:                      # target_tier IS NULL only
                if job.target_tier is not None:
                    continue
            elif claimant_tier is not None and not (  # mirror claim_next's tier routing
                    job.target_tier is None or job.target_tier == claimant_tier):
                continue
            if ql and ql not in (job.filename or "").lower():
                continue
            n += 1
        return n

    def claim_next(self, *, claimant_tier: str | None = None,
                   engine: "str | Collection[str] | None" = None) -> Job | None:
        """Atomically claim the oldest QUEUED job.

        Scans all keys with the store prefix, picks the oldest QUEUED job,
        then atomically updates it via WATCH/MULTI/EXEC.  If another claimer
        races and modifies the key (WatchError), retries from scratch.

        ``claimant_tier`` routes: a job with ``target_tier`` set is claimable only by a
        claimant whose tier matches; the scan already decodes every job, so the filter is
        free here (the claim stays O(N)-scan as before). ``engine`` (a name or the set of engines
        this claimant handles) restricts the claim (shared multi-engine stores).
        """
        engines = normalize_engine_filter(engine)
        while True:
            now = time.time()
            candidates: list[tuple[float, str, str]] = []
            for k in self._r.scan_iter(match=_PREFIX + "*", count=200):
                raw = self._r.get(k)
                if raw is None:
                    continue
                job = _decode_job(raw)
                if job is None:
                    continue
                if job.target_tier is not None and job.target_tier != claimant_tier:
                    continue
                if engines is not None and job.engine not in engines:
                    continue
                # skip DEFERRED jobs (claimable_after in the future) — a capacity-blocked cold job
                # must not be reclaimed ahead of claimable work
                if job.claimable_after is not None and job.claimable_after > now:
                    continue
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
                    job = _decode_job(raw)
                    if job is None:
                        continue
                    if job.status != JobStatus.QUEUED:
                        # Another claimer won the race; retry from the scan.
                        continue
                    # Re-check the tier AND engine predicates inside the WATCH too: the watched re-read
                    # must re-validate every predicate the scan advertised, else a job mutated under the
                    # same key between scan-select and here (e.g. engine reassigned) could be claimed by
                    # an engine-scoped dispatcher it no longer matches. WATCH aborts the EXEC on any such
                    # write, but re-checking keeps the guard correct even when the value is re-read here.
                    if job.target_tier is not None and job.target_tier != claimant_tier:
                        continue
                    if job.claimable_after is not None and job.claimable_after > now:
                        continue
                    if engines is not None and job.engine not in engines:
                        continue
                    job.status = JobStatus.RUNNING
                    job.started_at = time.time()
                    job.claim_id = uuid.uuid4().hex  # fresh ownership token per claim
                    pipe.multi()
                    pipe.set(key, json.dumps(job.to_dict()), ex=self._expiry_arg())
                    pipe.execute()
                    return job
            except WatchError:
                continue  # retry on concurrent modification

    def delete(self, job_id: str) -> None:
        self._r.delete(self._key(job_id))
