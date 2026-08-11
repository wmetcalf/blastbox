"""BlobStore protocol — the seam between a job's bytes and where they live.

The local job dir stays the working set in EVERY backend: Firecracker bind-mounts
need a real path. A remote backend does not replace ``job_root``, it feeds it.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable


class BlobFetchError(Exception):
    """A sample could not be materialised locally.

    Callers MUST treat this as transient and release the claim back to ``queued``
    rather than failing the job: an unreachable object store is a property of THIS
    worker's connectivity, not of the sample. Failing would permanently discard
    work because one node's link was down.
    """


class BlobIntegrityError(BlobFetchError):
    """Fetched bytes did not hash to the requested key (corrupt or substituted)."""


@runtime_checkable
class BlobStore(Protocol):
    def put_sample(self, sha256: str, src: Path) -> None:
        """Store *src* under the content key *sha256*. Idempotent."""

    def get_sample(self, sha256: str, dest: Path) -> None:
        """Materialise the sample at *dest* (the ORIGINAL filename, not the key)."""

    def put_output(self, job_id: str, out_dir: Path) -> None:
        """Persist the sealed output dir for *job_id*."""

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        """Open one artifact from *job_id*'s output for reading."""

    def delete_job(self, job_id: str) -> None:
        """Drop *job_id*'s outputs. MUST NOT touch shared ``samples/`` blobs."""

    def has_output(self, job_id: str) -> bool:
        """True iff a DURABLE result exists for *job_id* in this store.

        The age reclaim deletes local trees on the strength of this answer, so an
        implementation MUST NOT return True on an error or an unknown -- it may only say
        True when it has positively observed the bytes.
        """


def upload_output_with_retry(
    store: "BlobStore",
    job_id: str,
    out_dir: Path,
    *,
    attempts: int = 3,
    backoff_s: float = 1.0,
) -> Exception | None:
    """Call ``store.put_output`` up to *attempts* times with a short sleep between
    tries, and return the last exception (or ``None`` on success).

    This is the shared upload-failure policy for BOTH dispatchers (Finding D1): the
    detonation already finished and its result is sitting in ``out_dir`` right now,
    while this worker still holds the job's claim — so a transient failure (a
    momentary object-store blip) deserves a real, bounded, in-line chance to
    succeed before the caller gives up on the result. It is deliberately NOT
    unbounded and does NOT leave the job in a non-terminal state for some other
    process to retry later: callers that exhaust every attempt must treat the
    upload as failed, fail the job, and let their normal terminal-path cleanup run
    — there is no consumer that would ever pick a "preserved for retry" job back
    up (see the finding).
    """
    last_exc: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            store.put_output(job_id, out_dir)
            return None
        except Exception as exc:  # noqa: BLE001 — any backend failure is retryable here;
            # the caller decides what to do once every attempt is exhausted.
            last_exc = exc
            if attempt < attempts:
                time.sleep(max(0.0, backoff_s))
    return last_exc
