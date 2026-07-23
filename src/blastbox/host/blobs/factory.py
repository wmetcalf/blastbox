"""BlobStore factory — select the backend from ``BLASTBOX_BLOB_URL``.

Mirrors ``blastbox.host.jobs.factory.build_job_store_from_env`` so the two storage
knobs are configured the same way. Unset = local filesystem = today's behaviour,
with no S3 dependency imported or required.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from blastbox.host.blobs.base import BlobStore
from blastbox.host.blobs.local import LocalBlobStore


def build_blob_store_from_env(env: dict[str, str] | None = None) -> BlobStore:
    """Return the BlobStore selected by ``BLASTBOX_BLOB_URL``.

    - unset / empty -> ``LocalBlobStore`` (single-node default; no new deps)
    - ``s3://bucket/prefix`` -> ``S3BlobStore`` (MinIO or AWS S3)
    """
    e = os.environ if env is None else env
    job_root = Path(e.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs"))
    url = e.get("BLASTBOX_BLOB_URL", "").strip()
    if not url:
        # Durable bytes live OUTSIDE job_root (a sibling `blobs` dir by default) so the
        # worker purge — which destroys job_root wholesale on every terminal path — can
        # never take the local store's only copy with it. See local.py.
        local_root = e.get("BLASTBOX_BLOB_LOCAL_ROOT", "").strip()
        blob_root = Path(local_root) if local_root else job_root.parent / "blobs"
        return LocalBlobStore(job_root, blob_root=blob_root)

    scheme = urlparse(url).scheme.lower()
    if scheme == "s3":
        # Imported HERE, not at module scope, so `blastbox[host]` needs no boto3 —
        # same pattern as SqlJobStore importing psycopg_pool inside its postgres branch.
        from blastbox.host.blobs.s3 import S3BlobStore

        return S3BlobStore(url, job_root=job_root, env=e)

    raise ValueError(f"unsupported blob url scheme: {scheme!r} (use s3:// or leave unset)")
