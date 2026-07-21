"""BlobStore protocol — the seam between a job's bytes and where they live.

The local job dir stays the working set in EVERY backend: Firecracker bind-mounts
need a real path. A remote backend does not replace ``job_root``, it feeds it.
"""
from __future__ import annotations

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
