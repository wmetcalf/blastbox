"""LocalBlobStore — the default, and deliberately almost nothing.

Ingress already spools the input to ``<job_root>/<id>/input/<filename>`` and the
dispatcher already reads it from there, so in single-node mode there is no second
copy to move: put/get VERIFY, they do not transfer. This is what keeps mode 1
byte-identical to pre-BlobStore behaviour with no new dependency.
"""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from blastbox.host.blobs.base import BlobFetchError


class LocalBlobStore:
    def __init__(self, job_root: Path | str) -> None:
        self._job_root = Path(job_root)

    def put_sample(self, sha256: str, src: Path) -> None:
        if not Path(src).is_file():
            raise BlobFetchError(f"sample not present locally: {src}")

    def get_sample(self, sha256: str, dest: Path) -> None:
        # No remote copy exists in local mode. Raise the transient error type anyway
        # so the caller's release-vs-fail policy stays uniform across backends.
        if not Path(dest).is_file():
            raise BlobFetchError(f"sample not present locally: {dest}")

    def put_output(self, job_id: str, out_dir: Path) -> None:
        return None      # already on the filesystem the API serves from

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        return open(self._job_root / job_id / "output" / Path(name).name, "rb")

    def delete_job(self, job_id: str) -> None:
        # Retention owns the on-disk job dir in local mode (jobs/retention.py has the
        # containment checks); duplicating deletion here would race it.
        return None
