"""Generic Job model and JobStore protocol for the blastbox framework."""

from __future__ import annotations

import enum
import time
import uuid
from builtins import list as _list  # explicit ref: JobStore.list shadows the builtin
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from blastbox.errors import sanitize_public_error

if TYPE_CHECKING:
    from blastbox.contract import Envelope


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class Job:
    """Engine-agnostic job record.

    ``params`` carries per-job engine options (analogous to ClippyShot's
    ``scan_options``).  ``result_summary`` carries a small engine-provided
    summary for listing endpoints (analogous to ClippyShot's ``pages_*`` /
    ``detected`` fields).  Neither leaks engine-specific concepts into the
    generic layer.
    """

    job_id: str
    engine: str                         # which engine handles this job
    filename: str                        # sanitized input basename
    status: JobStatus
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    expires_at: float | None = None
    input_sha256: str | None = None
    result_dir: str | None = None       # server-set; stripped from public dict
    worker_runtime: str | None = None
    error: str | None = None
    # Per-claim ownership token: claim_next() stamps a fresh value on each QUEUED->RUNNING
    # transition; requeue clears it. Terminal/recovery writes CAS on (status, claim_id) so a
    # stale owner can't clobber a RECLAIMED job (status alone has an ABA hole across
    # RUNNING->QUEUED->RUNNING under multiple dispatchers).
    claim_id: str | None = None
    security_warnings: list[str] = field(default_factory=list)
    params: dict[str, str] = field(default_factory=dict)       # engine per-job options
    result_summary: dict | None = None  # small engine result summary for listing

    @classmethod
    def new(cls, *, engine: str, filename: str) -> "Job":
        return cls(
            job_id=str(uuid.uuid4()),
            engine=engine,
            filename=filename,
            status=JobStatus.QUEUED,
            created_at=time.time(),
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    def to_public_dict(self) -> dict:
        """Return a dict safe to expose publicly.

        Strips ``result_dir`` (internal server path), ``params`` (may contain
        sensitive engine options), and ``claim_id`` (an internal ownership token),
        and sanitizes the ``error`` field to remove internal filesystem paths.
        """
        d = self.to_dict()
        d.pop("result_dir", None)
        d.pop("params", None)
        d.pop("claim_id", None)
        if isinstance(d.get("error"), str):
            d["error"] = sanitize_public_error(d["error"])
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        return cls(
            job_id=d["job_id"],
            engine=d["engine"],
            filename=d["filename"],
            status=JobStatus(d["status"]),
            created_at=float(d["created_at"]),
            started_at=float(d["started_at"]) if d.get("started_at") else None,
            finished_at=float(d["finished_at"]) if d.get("finished_at") else None,
            expires_at=float(d["expires_at"]) if d.get("expires_at") else None,
            input_sha256=d.get("input_sha256"),
            result_dir=d.get("result_dir"),
            worker_runtime=d.get("worker_runtime"),
            error=d.get("error"),
            claim_id=d.get("claim_id"),
            security_warnings=(
                list(d.get("security_warnings", []))
                if d.get("security_warnings") is not None
                else []
            ),
            params=dict(d.get("params") or {}),
            result_summary=d.get("result_summary"),
        )


# Whitelist of fields ``list(sort=...)`` accepts. A whitelist (not a free column
# name) keeps the SQL backend injection-safe and the in-memory/Redis backends
# uniform. Anything else falls back to newest-first.
LISTABLE_SORT_FIELDS = ("created_at", "filename", "status", "finished_at")


def _job_sort_key(field: str):
    if field == "filename":
        return lambda j: ((j.filename or "").lower(), j.job_id)
    if field == "status":
        return lambda j: (str(j.status.value), j.job_id)
    if field == "finished_at":
        return lambda j: (j.finished_at or 0.0, j.job_id)
    return lambda j: (j.created_at or 0.0, j.job_id)  # created_at / default


def filter_sort_window(
    jobs: _list[Job],
    *,
    q: str | None = None,
    sort: str | None = None,
    order: str = "desc",
    newest_first: bool = False,
    offset: int = 0,
    limit: int | None = None,
) -> _list[Job]:
    """In-process q-filter (filename substring, case-insensitive) + whitelist sort
    + page window. Shared by the in-memory and Redis backends (the SQL backend
    pushes the same semantics into the query)."""
    if q:
        ql = q.lower()
        jobs = [j for j in jobs if ql in (j.filename or "").lower()]
    if sort in LISTABLE_SORT_FIELDS:
        jobs = sorted(jobs, key=_job_sort_key(sort), reverse=(order or "desc").lower() != "asc")
    elif newest_first:
        jobs = sorted(jobs, key=lambda j: (j.created_at or 0.0, j.job_id), reverse=True)
    if offset:
        jobs = jobs[offset:]
    if limit is not None:
        jobs = jobs[:limit]
    return jobs


@runtime_checkable
class JobStore(Protocol):
    def create(self, job: Job) -> None: ...
    def get(self, job_id: str) -> Job | None: ...
    def update(self, job_id: str, **fields) -> Job: ...
    def update_if_status(
        self,
        job_id: str,
        expect_status: JobStatus,
        *,
        expect_claim_id: str | None = None,
        **fields,
    ) -> bool:
        """Atomically apply ``fields`` ONLY if the job's current status is ``expect_status`` (and,
        when ``expect_claim_id`` is given, its ``claim_id`` still matches); return whether it
        applied (a compare-and-set, like ``claim_next``'s QUEUED guard).

        Used to fence a transition against a concurrent writer. ``expect_claim_id`` closes the ABA
        hole: a terminal/recovery write keyed on (status, claim_id) can't clobber a job that was
        RECLAIMED (RUNNING->QUEUED->RUNNING with a new claim) — status alone can't tell. Missing
        job, status mismatch, or claim_id mismatch returns ``False`` without modifying anything.
        """
        ...
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
        """Return jobs, optionally filtered by ``status`` and a filename substring
        ``q`` (case-insensitive), ordered by ``sort`` (one of LISTABLE_SORT_FIELDS;
        else newest-first) ``order`` asc/desc.

        ``limit``/``offset`` page the result and ``newest_first`` orders by
        ``created_at`` descending.  SQL backends push these down into the query
        (``ORDER BY ... LIMIT ... OFFSET``) so a listing endpoint never loads
        the whole table.  The in-memory backend windows after a cheap in-process
        scan.  The Redis backend has NO server-side ordering/limit over a scanned
        key space, so it still fetches+decodes every key and windows in-process —
        i.e. **O(N) per call**, so it is unsuitable for very large job histories
        (prefer Postgres there; see ``factory`` / README).  Callers that iterate
        every job (dispatcher, retention) omit all three and get the full set,
        unordered.
        """
        ...

    def count(self, status: JobStatus | None = None, *, q: str | None = None) -> int:
        """Total number of jobs (optionally filtered by ``status`` + filename ``q``).

        Paired with ``list(..., limit=, offset=)`` so the listing endpoint can
        report ``total`` without materializing every row.
        """
        ...

    def claim_next(self) -> Job | None: ...
    def delete(self, job_id: str) -> None: ...


@runtime_checkable
class PageHashSearch(Protocol):
    """OPTIONAL per-page perceptual-hash index + similarity search surface.

    This is deliberately a SEPARATE Protocol that ``JobStore`` does NOT inherit:
    only SQL-backed stores implement it (Hamming / L1 search needs a queryable
    index the in-memory and Redis backends can't provide), so folding it into
    ``JobStore`` would make those backends fail the structural contract.

    Search is **Postgres + pg_bktree only** — the SP-GiST BK-tree index is the
    single supported phash backend.  Structural presence is therefore necessary
    but NOT sufficient: a SQL store opened on SQLite (or on Postgres without the
    extension) still satisfies this Protocol's shape, but its capability methods
    raise.  Consumers MUST gate on the runtime ``supports_hash_search()`` flag,
    not merely ``isinstance(store, PageHashSearch)`` / ``hasattr`` — the
    dispatcher's on-DONE indexer and the ``/v1/similar`` route both do.
    """

    def supports_hash_search(self) -> bool:
        """Whether this store can actually serve search right now (PG + pg_bktree).

        ``False`` for SQLite and for Postgres without the extension; the other
        methods on this Protocol raise when this is ``False``."""
        ...

    def index_page_hashes(self, job_id: str, envelope: "Envelope") -> int:
        """Extract per-page hashes from a sealed ``envelope`` and persist them
        for similarity search; return the number of rows written."""
        ...

    def find_similar_phash(
        self, target_int8: int, max_distance: int, limit: int = 50
    ) -> _list[dict]:
        """Pages within Hamming distance ``max_distance`` of the signed-int64
        query phash."""
        ...

    def find_similar_colorhash(
        self,
        target: str,
        *,
        total_max: int | None = None,
        frac_max: int | None = None,
        faint_max: int | None = None,
        bright_max: int | None = None,
        limit: int = 50,
    ) -> _list[dict]:
        """Pages within the given per-bin L1 colorhash distances."""
        ...

    def find_by_colorhash(self, colorhash: str, limit: int = 50) -> _list[dict]:
        """Pages whose colorhash matches exactly."""
        ...

    def find_by_page_sha256(self, sha256: str, limit: int = 50) -> _list[dict]:
        """Pages whose rendered-image sha256 matches exactly."""
        ...
