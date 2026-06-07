"""Generic Job model and JobStore protocol for the blastbox framework."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Protocol, runtime_checkable

from blastbox.errors import sanitize_public_error


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

        Strips ``result_dir`` (internal server path) and ``params``
        (may contain sensitive engine options), and sanitizes the ``error``
        field to remove internal filesystem paths.
        """
        d = self.to_dict()
        d.pop("result_dir", None)
        d.pop("params", None)
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
            security_warnings=(
                list(d.get("security_warnings", []))
                if d.get("security_warnings") is not None
                else []
            ),
            params=dict(d.get("params") or {}),
            result_summary=d.get("result_summary"),
        )


@runtime_checkable
class JobStore(Protocol):
    def create(self, job: Job) -> None: ...
    def get(self, job_id: str) -> Job | None: ...
    def update(self, job_id: str, **fields) -> Job: ...
    def update_if_status(
        self, job_id: str, expect_status: JobStatus, **fields
    ) -> bool:
        """Atomically apply ``fields`` ONLY if the job's current status is ``expect_status``;
        return whether it applied (a compare-and-set, like ``claim_next``'s QUEUED guard).

        Used to fence a transition against a concurrent writer — e.g. an orphan-recovery sweep
        flips a stale RUNNING job to FAILED only while it is still RUNNING, so it can never
        clobber a terminal status the owning dispatcher wrote in the meantime. Missing job or a
        status mismatch returns ``False`` without modifying anything.
        """
        ...
    def list(
        self,
        status: JobStatus | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Job]:
        """Return jobs, optionally filtered by ``status``.

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

    def count(self, status: JobStatus | None = None) -> int:
        """Total number of jobs (optionally filtered by ``status``).

        Paired with ``list(..., limit=, offset=)`` so the listing endpoint can
        report ``total`` without materializing every row.
        """
        ...

    def claim_next(self) -> Job | None: ...
    def delete(self, job_id: str) -> None: ...
