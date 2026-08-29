"""S3BlobStore — sample and result bytes in MinIO or AWS S3.

Reached only when ``BLASTBOX_BLOB_URL=s3://...``; ``blastbox.host.blobs.factory``
imports this module lazily so ``blastbox[host]`` never requires boto3.

Key layout:
  ``<prefix>/samples/<input_sha256>``   content-addressed, SHARED between jobs
  ``<prefix>/results/<job_id>/<name>``  job-scoped, written once
"""
from __future__ import annotations

import errno

import gzip
import hashlib
import io
import os
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlparse

from blastbox.host.blobs.base import (
    _SEAL_NAME,
    _assert_declared_landed,
    _declared_paths,
    _is_seal,
    BlobFetchError,
    BlobIntegrityError,
    _upload_order,
)
from blastbox.observability import get_logger

_log = get_logger("blastbox.blobs.s3")

_CHUNK = 1024 * 1024

# put_output costs one round-trip PER OBJECT, and a result tree is often hundreds of them.
# Measured on the fleet (200 corpus documents, FC tier, 24 slots): the upload was 39.7% of all
# job-seconds -- more than extraction itself (38.0%) -- and its duration tracked artifact COUNT,
# not bytes (821 artifacts -> 63.3s; 1 artifact -> 0.35s). Fanning the artifacts out is the
# largest throughput lever left on the tier.
#
# This is a PER-DISPATCHER budget, not a per-job one. The dispatcher builds ONE S3BlobStore and
# shares its boto3 client -- and therefore one connection pool -- across every concurrent job.
# A per-call executor looks the same in a unit test and is badly wrong in production: 24 slots x
# 8 workers = 192 threads queueing on a 10-connection pool, so the fan-out is fake past the tenth
# and the other 182 threads are pure contention. Measured cost of getting this wrong: upload's
# share halved as intended, while purge, commit, rdump and fetch -- none of which touch this code
# -- all got 3-4x SLOWER and per-job p50 rose from 12.8s to 19.6s.
#
# So: one shared bounded pool, and a connection pool sized to it. Jobs queue against a budget
# instead of thrashing. 16 is comfortable for a local MinIO across a 24-slot tier; if uploads
# become the limit again, raise this AND look at the object store, in that order.
_DEFAULT_UPLOAD_CONCURRENCY = 16


def _upload_concurrency(raw: object) -> int:
    """Parse BLASTBOX_BLOB_UPLOAD_CONCURRENCY, falling back rather than raising.

    This runs AFTER the detonation, holding a result that exists nowhere else yet, so an operator
    typo in a deployment env must not be able to take the upload path down for every job. 1 is a
    real setting -- the escape hatch back to the exact serial behaviour this replaced; anything
    unparseable or below 1 is a typo, not a request, and gets the default.
    """
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return _DEFAULT_UPLOAD_CONCURRENCY
    return n if n >= 1 else _DEFAULT_UPLOAD_CONCURRENCY


class S3BlobStore:
    def __init__(
        self, url: str, *, job_root: Path, env: Mapping[str, str] | None = None
    ) -> None:
        import boto3  # type: ignore[import-untyped]  # noqa: PLC0415 — optional dep, see module docstring

        e = os.environ if env is None else env
        parsed = urlparse(url)
        # REJECT user-info rather than quietly carrying it. `urlparse` puts everything before the
        # `@` into netloc, so `s3://key:secret@bucket/prefix` yields a BUCKET of
        # "key:secret@bucket" -- which is not a bucket. Every request then goes to an invalid name
        # and fails at read time, while the canary's identity comparison (which redacts for display
        # and for the persisted fingerprint) sees the same "bucket" on both sides and reports
        # agreement. Redacting the display was necessary -- that string is written into the job
        # queue -- but it is not sufficient: it made a broken configuration look healthy. Credentials
        # belong in AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, not in the URL.
        if "@" in parsed.netloc:
            raise ValueError(
                "BLASTBOX_BLOB_URL must not carry credentials: "
                f"{parsed.scheme}://***@{parsed.netloc.rsplit('@', 1)[-1]}{parsed.path} — the text "
                "before '@' becomes part of the bucket name and every request fails against it. "
                "Put credentials in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (or the instance "
                "role) and give this variable the bucket alone.")
        self._bucket = parsed.netloc
        self._prefix = parsed.path.strip("/")
        self._job_root = Path(job_root)
        self._compress = e.get("BLASTBOX_BLOB_COMPRESS", "1").strip().lower() not in (
            "0", "false", "no",
        )
        endpoint = e.get("BLASTBOX_BLOB_ENDPOINT_URL", "").strip() or None
        self._upload_concurrency = _upload_concurrency(
            e.get("BLASTBOX_BLOB_UPLOAD_CONCURRENCY", _DEFAULT_UPLOAD_CONCURRENCY)
        )
        self._upload_pool: ThreadPoolExecutor | None = None
        self._upload_pool_lock = threading.Lock()
        # botocore's connection pool defaults to 10. Left alone, a fan-out wider than that
        # silently BLOCKS on the pool rather than erroring -- the change would look deployed,
        # measure as no faster, and give no clue why. Size it to the SHARED upload budget, which
        # is the real ceiling on in-flight requests now that the executor is shared.
        import botocore.config  # type: ignore[import-untyped]  # noqa: PLC0415 -- optional dep

        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            config=botocore.config.Config(
                max_pool_connections=max(10, self._upload_concurrency),
            ),
        )

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
        declared = _declared_paths(out_dir)
        stored: set[str] = set()

        paths = _upload_order(out_dir)          # seal LAST, by construction
        seals = [p for p in paths if _is_seal(p, out_dir)]
        rest = [p for p in paths if not _is_seal(p, out_dir)]

        # PHASE 1 — every artifact, fanned out. The seal is deliberately NOT in this set: its
        # whole meaning is "everything else already landed", so it cannot share a barrier with
        # the things it vouches for.
        results: list[tuple[str | None, Exception | None]] = []
        if self._upload_concurrency <= 1:
            for path in rest:
                results.append((self._put_one(job_id, path, out_dir, declared), None))
        else:
            pool = self._pool_for_uploads()
            futures = [pool.submit(self._put_one, job_id, p, out_dir, declared) for p in rest]
            # Drained in SUBMISSION order, so the exception that surfaces is deterministic: the
            # same tree must fail the same way every time, or the bounded retry wrapped around
            # this call is chasing a moving target. EVERY future is drained even after one fails
            # -- the pool is shared and long-lived, so abandoning futures would leave another
            # job's uploads racing ours, and a half-read result set is how `stored` silently
            # loses entries that really did land.
            for fut in futures:
                try:
                    results.append((fut.result(), None))
                except Exception as exc:  # noqa: BLE001 -- re-raised in order below
                    results.append((None, exc))

        for rel, err in results:
            if err is not None:
                # A real outage MUST fail the upload rather than ship a partial result: the
                # caller fails the job and retains the local tree instead of purging it.
                raise err
            if rel is not None:
                stored.add(rel)

        # PHASE 2 — the commit. Only now, with every artifact confirmed stored, may the seal
        # exist: its presence under results/<job_id> is what has_output() reports as durable, and
        # what the age reclaim deletes the complete LOCAL tree on the strength of.
        for path in seals:
            def _precondition() -> None:
                _assert_declared_landed(job_id, out_dir, stored)

            if self._upload_concurrency <= 1:
                self._put_one(job_id, path, out_dir, declared, before_put=_precondition)
            else:
                # Through the SAME pool, so a sealing job counts against the shared budget like
                # any other request -- otherwise the real in-flight ceiling is
                # concurrency + (jobs currently sealing), which on a 24-slot tier is 24 requests
                # nobody budgeted for, against a connection pool sized for the budget alone.
                # Ordering is unaffected: the barrier above has already completed, and .result()
                # both waits for the seal and re-raises whatever it hit. Nothing in the pool ever
                # waits on the pool, so a saturated pool always drains.
                self._pool_for_uploads().submit(
                    self._put_one, job_id, path, out_dir, declared, before_put=_precondition,
                ).result()

    def _pool_for_uploads(self) -> ThreadPoolExecutor:
        """The dispatcher-wide upload pool, created on first use.

        SHARED on purpose: see _DEFAULT_UPLOAD_CONCURRENCY. It is never shut down -- the store
        lives for the process, and ThreadPoolExecutor's own atexit hook joins the workers.
        """
        with self._upload_pool_lock:
            if self._upload_pool is None:
                self._upload_pool = ThreadPoolExecutor(
                    max_workers=self._upload_concurrency,
                    thread_name_prefix="bb-put",
                )
            return self._upload_pool

    def _put_one(
        self,
        job_id: str,
        path: Path,
        out_dir: Path,
        declared: "set[str] | None",
        *,
        before_put: Callable[[], None] | None = None,
    ) -> str | None:
        """Store ONE file. Returns its relative key, or None if it was legitimately skipped.

        Runs on a pool thread, so it touches no shared state: the caller collects the returned
        rels and builds `stored` itself. Raises for anything that must fail the whole upload.
        """
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
            return None
        if not path.is_file():
            return None
        rel = path.relative_to(out_dir).as_posix()
        body = path.read_bytes()
        extra: dict[str, str] = {}
        if self._compress:
            body = gzip.compress(body)
            extra["ContentEncoding"] = "gzip"
        # A name we can NEVER store is not an outage -- retrying it forever is what turns
        # one worker-chosen filename into a permanent leak. The sample writes an undeclared
        # 250-char name into its 0o777 output/, the key exceeds 1024 bytes on every
        # attempt, the host marks the tree pending-upload, and the last-copy rule then
        # exempts it from BOTH sweeps for the life of the node -- #84 reproduced on demand
        # (upstream review of #85). Skip it loudly, exactly as a hostile symlink is skipped:
        # undeclared files are not servable anyway (the result routes are manifest-gated), so
        # nothing a consumer can reach is lost. Every other error still propagates, because a
        # real outage MUST fail the upload rather than silently ship a partial result.
        key = self._key("results", job_id, rel)
        if len(key.encode("utf-8")) > 1024:      # hard S3 limit; no retry will fix it
            if declared is None or rel in declared:
                raise OSError(  # a DECLARED artifact must never be silently dropped
                    errno.ENAMETOOLONG,
                    f"declared artifact {rel!r} exceeds the 1024-byte key limit", key)
            _log.warning("put_output_skipped_unstorable_key", job_id=job_id, path=str(rel))
            return None
        if before_put is not None:
            # The seal's pre-condition, injected by the caller: everything the manifest promises
            # must already be stored. Passed in rather than checked here because `stored` is the
            # CALLER's accumulator, and a pool thread has no business reading it.
            before_put()
        self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body,
            **extra,
        )
        return rel

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
