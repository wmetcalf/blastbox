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
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlparse

from blastbox.host.blobs.base import (
    _SEAL_NAME,
    BlobFetchError,
    BlobIntegrityError,
    _upload_order,
)
from blastbox.observability import get_logger

_log = get_logger("blastbox.blobs.s3")

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
        # The terminal purge deletes the local tree on the strength of THIS call, so a
        # silent no-op here turns "upload succeeded" into a DONE job with no durable copy
        # anywhere. rglob on a missing dir yields nothing and raises nothing, so assert the
        # durability barrier explicitly (#85 review).
        out_dir = Path(out_dir)
        if not out_dir.is_dir():
            raise FileNotFoundError(f"put_output: output dir missing for {job_id}: {out_dir}")
        # TWO-PHASE COMMIT. metadata.json is written LAST, so its presence under
        # results/<job_id> means "every other artifact already landed" -- that is what makes
        # has_output() a real durability answer instead of a guess. Uploading in plain sorted
        # order put it FIRST ('m' < 'r'), so a run that died mid-upload left the seal present with
        # artifacts missing, and the age reclaim would then delete the complete local tree as
        # redundant. It is also the artifact the API fetches to serve a job at all (#85 review).
        for path in _upload_order(out_dir):
            # Skip symlinks BEFORE is_file() -- is_file() follows a symlink to its
            # target, so `p.is_symlink() or not p.is_file()` (checked in that
            # order) never reads or uploads a symlink's target bytes. A worker
            # that plants e.g. output/metadata.json -> /etc/passwd before this
            # runs must not get that file's bytes stored (and later served) as
            # trusted job output. A single hostile entry is skipped + logged,
            # not raised — it must not fail the upload of the rest of a
            # legitimate job's output.
            if path.is_symlink():
                _log.warning(
                    "put_output_skipped_symlink",
                    job_id=job_id,
                    path=str(path.relative_to(out_dir)),
                )
                continue
            if not path.is_file():
                continue
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

    @staticmethod
    def _safe_rel(name: str) -> str:
        """Normalise *name* to a relative POSIX sub-path under ``results/<job_id>/``, rejecting an
        absolute name or any ``..`` traversal BEFORE it is built into a key -- so open_output can
        never read outside this job's results prefix. Mirrors put_output's ``rel.as_posix()`` key."""
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise BlobFetchError(f"result fetch refused (unsafe name): {name}")
        rel = p.as_posix()
        if rel in ("", "."):
            raise BlobFetchError(f"result fetch refused (empty name): {name}")
        return rel

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        # Mirror put_output's nested key (results/<job_id>/<rel>) instead of collapsing to the
        # basename, but normalise + reject a traversal/absolute name first (see _safe_rel).
        key = self._key("results", job_id, self._safe_rel(name))
        try:
            obj = self._s3.get_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            raise BlobFetchError(f"result fetch failed: {job_id}/{name}") from exc
        data = obj["Body"].read()
        if obj.get("ContentEncoding") == "gzip":
            data = gzip.decompress(data)
        return io.BytesIO(data)

    def has_output(self, job_id: str) -> bool:
        """Positively observed durable result bytes for *job_id*. Any error -> False: the age
        reclaim deletes the local tree on the strength of this answer, so a transient object-store
        outage must never be read as "the durable copy is there"."""
        try:
            self._s3.head_object(Bucket=self._bucket, Key=self._key("results", job_id, _SEAL_NAME))
        except Exception:  # noqa: BLE001 -- a miss AND any error are both "not durable"
            return False
        return True

    def delete_job(self, job_id: str) -> None:
        """Drop this job's RESULTS only.

        Sample blobs are content-addressed and shared between jobs, so they are
        never deleted here — doing so would break every other job referencing the
        same bytes, including a future re-run of the corpus.

        Finding C4: ``delete_objects`` returns HTTP 200 even when SOME objects
        failed to delete (an IAM condition, object lock, etc.) — the failures are
        reported only in ``response["Errors"]``, which the caller must inspect;
        boto3 does not raise for them. Silently ignoring that field would report a
        partial delete as a full success, so the retention sweeper's guard (only
        clear ``expires_at`` when ``delete_job`` does NOT raise) would clear it
        anyway and the undeleted result object would leak forever with nothing left
        to retry it. Raise here so the caller's error-handling (retention's guard,
        or the ingress DELETE route) leaves the job retryable instead.
        """
        prefix = self._key("results", job_id) + "/"
        paginator = self._s3.get_paginator("list_objects_v2")
        errors: list[dict] = []
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if not keys:
                continue
            response = self._s3.delete_objects(Bucket=self._bucket, Delete={"Objects": keys})
            errors.extend(response.get("Errors") or [])
        if errors:
            first = errors[0]
            raise BlobFetchError(
                f"delete_job partially failed for {job_id}: {len(errors)} object(s) "
                f"undeleted (first: key={first.get('Key')!r} code={first.get('Code')!r})"
            )
