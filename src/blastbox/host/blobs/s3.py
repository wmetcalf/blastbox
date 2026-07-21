"""S3BlobStore — sample and result bytes in MinIO or AWS S3.

Reached only when ``BLASTBOX_BLOB_URL=s3://...``; ``blastbox.host.blobs.factory``
imports this module lazily so ``blastbox[host]`` never requires boto3.

Key layout:
  ``<prefix>/samples/<input_sha256>``   content-addressed, SHARED between jobs
  ``<prefix>/results/<job_id>/<name>``  job-scoped, written once
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse

from blastbox.host.blobs.base import BlobFetchError, BlobIntegrityError

_CHUNK = 1024 * 1024


class S3BlobStore:
    def __init__(
        self, url: str, *, job_root: Path, env: Mapping[str, str] | None = None
    ) -> None:
        import boto3  # type: ignore[import-untyped]  # noqa: PLC0415 — optional dep, see module docstring

        e = os.environ if env is None else env
        parsed = urlparse(url)
        self._bucket = parsed.netloc
        self._prefix = parsed.path.strip("/")
        self._job_root = Path(job_root)
        self._compress = e.get("BLASTBOX_BLOB_COMPRESS", "1").strip().lower() not in (
            "0", "false", "no",
        )
        endpoint = e.get("BLASTBOX_BLOB_ENDPOINT_URL", "").strip() or None
        self._s3 = boto3.client("s3", endpoint_url=endpoint)

    def _key(self, *parts: str) -> str:
        return "/".join(p for p in (self._prefix, *parts) if p)

    # ── samples ──────────────────────────────────────────────────────────────
    def put_sample(self, sha256: str, src: Path) -> None:
        key = self._key("samples", sha256)
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return                      # already present: content-addressed => identical
        except Exception as exc:
            # Let non-404 errors propagate; only swallow object-not-found
            import botocore.exceptions  # type: ignore[import-untyped]  # noqa: PLC0415 — optional dep
            if isinstance(exc, botocore.exceptions.ClientError):
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("404", "NoSuchKey"):
                    pass  # object doesn't exist; fall through to upload
                else:
                    raise  # re-raise: real error (permissions, throttling, etc.)
            else:
                raise  # re-raise: not a ClientError
        try:
            self._s3.upload_file(str(src), self._bucket, key)
        except Exception as exc:
            raise BlobFetchError(f"sample upload failed: {sha256}") from exc

    def get_sample(self, sha256: str, dest: Path) -> None:
        key = self._key("samples", sha256)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        try:
            self._s3.download_file(self._bucket, key, str(tmp))
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise BlobFetchError(f"sample fetch failed: {sha256}") from exc

        h = hashlib.sha256()
        with open(tmp, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
        if h.hexdigest() != sha256:
            tmp.unlink(missing_ok=True)
            raise BlobIntegrityError(
                f"fetched bytes hash {h.hexdigest()}, expected {sha256}"
            )
        tmp.replace(dest)

    # ── results ──────────────────────────────────────────────────────────────
    def put_output(self, job_id: str, out_dir: Path) -> None:
        out_dir = Path(out_dir)
        for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
            rel = path.relative_to(out_dir).as_posix()
            body = path.read_bytes()
            extra: dict[str, str] = {}
            if self._compress:
                body = gzip.compress(body)
                extra["ContentEncoding"] = "gzip"
            self._s3.put_object(
                Bucket=self._bucket,
                Key=self._key("results", job_id, rel),
                Body=body,
                **extra,
            )

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        key = self._key("results", job_id, Path(name).name)
        try:
            obj = self._s3.get_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            raise BlobFetchError(f"result fetch failed: {job_id}/{name}") from exc
        data = obj["Body"].read()
        if obj.get("ContentEncoding") == "gzip":
            data = gzip.decompress(data)
        return io.BytesIO(data)

    def delete_job(self, job_id: str) -> None:
        """Drop this job's RESULTS only.

        Sample blobs are content-addressed and shared between jobs, so they are
        never deleted here — doing so would break every other job referencing the
        same bytes, including a future re-run of the corpus.
        """
        prefix = self._key("results", job_id) + "/"
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                self._s3.delete_objects(Bucket=self._bucket, Delete={"Objects": keys})
