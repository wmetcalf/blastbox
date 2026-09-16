"""Startup self-test: prove THIS dispatcher can do the job, on THIS host, before it claims one.

Every deployment failure this exists to catch had the same shape -- configuration that is correct
on the node it was written for and silently wrong everywhere else, discovered only when a real job
ran, and usually disguised as a different problem:

  * ``BLASTBOX_BLOB_URL`` set on the API but not on the dispatchers. The dispatchers sealed results
    into a LocalBlobStore the API never read; 17,626 jobs reached DONE and every artifact 404'd.
    Found days later, at collection time, and it cost a full re-run of the corpus.
  * The same variable set correctly, but the dispatchers on a docker network with no route to the
    store. Works on the node where MinIO is a local container, fails everywhere else -- the job
    runs fine and only the upload fails, so it reads as a storage outage rather than a topology bug.
  * Credentials that were rotated in one deployment's env file and not another's. The stack that
    missed the rotation looks healthy until something asks it to write.

None of those are subtle once you look; all of them were invisible because nothing ever asked the
question at startup. A round-trip through the REAL store answers all three in about a second, and
answers them on the machine that will actually do the work rather than the one it was configured
on.

Deliberately NOT a mock or a shape-check: it PUTs a real sealed envelope through the same
``BlobStore`` instance the dispatcher will use for real results, reads the bytes back, compares
them, and deletes them. A store that cannot do that cannot serve a job, whatever the config says.
"""

from __future__ import annotations

import hashlib
import json
import os
import logging
import re
import socket
import time
import uuid
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_log = logging.getLogger("blastbox.canary")

# A sealed envelope that declares NO artifacts. `_declared_paths` returns an empty set for this,
# meaning "nothing was promised", so the upload has nothing it could silently drop. Keeping the
# canary's own payload trivial keeps a canary failure attributable to the STORE rather than to the
# envelope -- the point is to test the deployment, not the seal logic.
_SEAL = {"status": "ok", "engine": "__canary__", "artifacts": [], "canary": True}


def _seal_bytes(nonce: str) -> bytes:
    """The sealed envelope for ONE probe, carrying a nonce unique to it.

    A constant payload plus a stable key silently defeated the check it exists to make: once a
    cleanup denial leaves the object behind, a later put that no-ops or is acknowledged without
    landing is invisible -- has_output finds the OLD object and its bytes match the constant, so
    the probe reports success without ever proving THIS write worked. That is precisely the
    accepted-but-not-landed failure mode the canary was built for.

    The nonce was originally omitted because a shared key would then produce spurious mismatches.
    That reasoning no longer applies: the key carries host+tier+engine+job_root, and a mismatch on
    the shared-key attempt is treated as a race and retried on a unique key.
    """
    return json.dumps({**_SEAL, "nonce": nonce}, sort_keys=True).encode()


class CanaryFailure(RuntimeError):
    """A self-test failed.

    Carries the operator-facing remedy, not just the exception: the whole reason this class exists
    is that the underlying errors (a 403, a connection timeout, a silently-local store) do not say
    which piece of configuration produced them.
    """

    def __init__(self, what: str, remedy: str, cause: BaseException | None = None) -> None:
        msg = f"{what}\n  fix: {remedy}"
        if cause is not None:
            # REDACTED. Redacting the endpoint in the description was not enough: botocore's
            # connection and request errors quote the full URL they tried, so an endpoint carrying
            # user-info or a query token reappeared verbatim here -- and, through exception
            # chaining, in every startup traceback too. Same secret, one layer down.
            msg += f"\n  cause: {type(cause).__name__}: {redact_secrets(str(cause))}"
        super().__init__(msg)
        self.what = what
        self.remedy = remedy


_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"\'<>]+")


def redact_secrets(text: str) -> str:
    """Rewrite every URL in ``text`` through :func:`_safe_endpoint`.

    Used on any message that reaches a log or a traceback. The exception a store raises is written
    by botocore, not by us, so the only safe assumption is that it echoes whatever URL it was
    handed -- credentials included.
    """
    try:
        return _URL_RE.sub(lambda m: _safe_endpoint(m.group(0)), text)
    except Exception:  # noqa: BLE001 - never let redaction raise
        return "<redaction failed>"


def _safe_bucket(bucket: Any) -> str:
    """A bucket with any embedded URI user-info removed.

    `S3BlobStore` takes `_bucket` from `urlsplit(BLASTBOX_BLOB_URL).netloc`, which keeps user-info
    verbatim: `s3://KEY:SECRET@bucket/prefix` yields a `_bucket` of `KEY:SECRET@bucket`. That value
    is not merely logged -- it becomes the target FINGERPRINT, which this feature persists into the
    job queue, so a mistyped URL would write a live credential into Postgres or Redis and leave it
    there. `_safe_endpoint` covers the endpoint only; this is the separate value it never saw.
    """
    text = str(bucket or "")
    return text.rsplit("@", 1)[-1] if "@" in text else text


def _safe_endpoint(url: Any) -> str:
    """An endpoint with any embedded secret removed, for logging.

    `client.meta.endpoint_url` echoes whatever was configured, and both the ingress and every
    dispatcher log it unconditionally at startup. A `BLASTBOX_BLOB_ENDPOINT_URL` carrying URI
    user-info (`http://key:secret@host:9000`) or a query token would therefore be copied into
    every log sink that collects boot output -- a credential disclosure produced by the code whose
    job is to make misconfiguration visible.
    """
    text = str(url or "")
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        redacted = "***@" if (parts.username or parts.password) else ""
        # query and fragment dropped entirely: neither identifies the endpoint, and either can
        # carry a token.
        return urlunsplit((parts.scheme, f"{redacted}{host}", parts.path, "", ""))
    except Exception:  # noqa: BLE001 - never let a log line raise
        return "<unparseable endpoint>"


def describe_blob_store(store: Any) -> str:
    """One line naming the backend AND its target, for the startup log.

    Printed unconditionally, including for the local backend. The 17k incident was a LocalBlobStore
    nobody meant to be using: the config looked right, the dispatchers just never saw the variable.
    A log line that says which store is in use turns that from a silent default into something you
    can notice while reading a boot log.
    """
    name = type(store).__name__
    bucket = getattr(store, "_bucket", None) or getattr(store, "bucket", None)
    if bucket:
        # Prefix and endpoint BOTH matter and neither is on the object as a plain attribute: the
        # prefix separates two stacks sharing a bucket, and the endpoint is the thing you actually
        # check when a write cannot connect. Without them the line said `S3BlobStore(blastbox)`,
        # which does not distinguish a working deployment from one pointed at the wrong host.
        prefix = getattr(store, "_prefix", "") or ""
        bucket = _safe_bucket(bucket)
        endpoint = None
        client = getattr(store, "_s3", None)
        try:
            endpoint = _safe_endpoint(client.meta.endpoint_url) if client is not None else None
        except Exception:  # noqa: BLE001
            endpoint = None
        target = f"{bucket}/{prefix}" if prefix else str(bucket)
        return f"{name}({target}{' via ' + str(endpoint) if endpoint else ''})"
    # `local_root` is a PROPERTY on LocalBlobStore, so a callable() test skips it and the line
    # degrades to the bare class name -- which defeats the point: the whole reason to log the local
    # backend is to show WHICH directory it silently fell back to. Handle both shapes.
    root = getattr(store, "local_root", None)
    if root is not None:
        try:
            return f"{name}(local_root={root() if callable(root) else root})"
        except Exception:  # noqa: BLE001
            pass
    return name


def canary_job_id(key_hint: str = "") -> str:
    """A STABLE per-dispatcher key, not a fresh random one each probe.

    A random id per probe is fine only if deletes work. A store that permits PUT and GET but
    denies DELETE reaches the cleanup handler on every successful probe -- and the probe still
    returns success, correctly, because being unable to tidy up does not stop it serving jobs.
    With the periodic pass on by default that left one permanent object PER INTERVAL PER
    DISPATCHER, growing forever, rather than the single leftover the cleanup warning describes.

    A stable key bounds it at one object per dispatcher no matter how long it runs.

    Two processes sharing a key is NOT harmless, and the earlier reasoning here -- "the payload is
    identical so the comparison still succeeds" -- was wrong about which operation collides. It is
    the DELETE: one process's cleanup can land between another's ``has_output`` and
    ``open_output``, so the second reads a miss and, at startup, refuses to serve against a
    perfectly healthy store. ``key_hint`` therefore has to carry enough identity to separate
    co-located dispatchers (host + tier + engine + job_root), and :func:`blob_roundtrip` retries
    once on a unique key when a read-back misses, so the residual race cannot fail a boot.
    """
    # NOT the hostname alone. In Docker/Kubernetes the default container or pod hostname is
    # ephemeral, so recreating the SAME logical dispatcher produced a different key -- and under
    # the explicitly supported PUT/GET-but-no-DELETE policy that means one more permanent object
    # per rollout or crash-loop restart, which is precisely the unbounded growth the stable key was
    # introduced to end. An operator-declared identity is preferred when present; the hostname
    # remains the fallback for deployments that set nothing, and the unique-key retry already
    # handles genuine collisions between concurrent processes.
    stable = (os.environ.get("BLASTBOX_DISPATCHER_ID") or "").strip() or socket.gethostname()
    ident = f"{stable}|{key_hint}".encode()
    return f"__canary__{hashlib.sha256(ident).hexdigest()[:16]}"


def blob_roundtrip(store: Any, *, keep_failed: bool = False, key_hint: str = "",
                   scratch_dir: Any = None) -> str:
    """PUT a sealed envelope through ``store``, read it back, verify the bytes, delete it.

    Returns a one-line description of what was proven. Raises :class:`CanaryFailure` naming the
    configuration to fix -- each stage is caught separately because they fail for different
    reasons and have different remedies. A store that passes this has been shown to be reachable,
    authorised, writable AND readable from this process.
    """
    try:
        return _roundtrip_once(store, canary_job_id(key_hint), keep_failed, scratch_dir,
                               racey=True)
    except _RaceySuspicion as exc:
        # A miss on a key another process may share is ambiguous: a broken store and a concurrent
        # canary cleanup look identical from here. Retry ONCE on a key nobody else can hold --
        # a genuinely broken store fails that too, while the race cannot fail a boot. The unique
        # key is used only on this rare path, so leftovers stay bounded in the normal case.
        _log.info("canary.retry_unique_key %s", exc)
        return _roundtrip_once(store, f"{canary_job_id(key_hint)}-{uuid.uuid4().hex[:8]}",
                               keep_failed, scratch_dir, racey=False)


class _RaceySuspicion(RuntimeError):
    """A read-back miss that a concurrent canary on a shared key could also explain."""


def _roundtrip_once(store: Any, job_id: str, keep_failed: bool, scratch_dir: Any, *,
                    racey: bool) -> str:
    """One probe. ``racey`` marks the shared-key attempt, whose read-back misses are ambiguous.

    On the retry (``racey=False``) the key is unique to this process, so a miss can only mean the
    store is broken and must surface as a CanaryFailure -- otherwise a genuinely unreadable store
    would escape as an internal exception type nobody handles.
    """
    started = time.monotonic()
    payload = _seal_bytes(uuid.uuid4().hex)

    # Stage under the dispatcher's OWN scratch when we know it. Requiring a writable system /tmp
    # made the gate reject a hardened deployment whose job_root and blob store are both fine --
    # failing it for a prerequisite real dispatch never needed, before the store was even touched.
    # The probe should test what the job path tests, not more.
    parent = None
    if scratch_dir is not None:
        try:
            parent = Path(scratch_dir)
            parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:  # noqa: BLE001
            # NO FALLBACK when a root was explicitly supplied. Quietly staging in the system temp
            # dir instead let the probe pass -- and the dispatcher start claiming -- while real
            # dispatch would fail later creating its input/output dirs under that same unusable
            # root (a volume that did not mount, a read-only parent). The gate exists to catch
            # exactly that, so an unusable job_root has to fail it. The system temp dir is only
            # for callers that supplied no scratch at all.
            raise CanaryFailure(
                f"the configured job root is unusable ({scratch_dir})",
                "the dispatcher stages every job under this path, so it cannot serve while it is "
                "unwritable -- check the volume actually mounted and that the container's uid can "
                "write to it (BLASTBOX_JOB_ROOT)",
                exc,
            ) from None
    with TemporaryDirectory(prefix="blastbox-canary-", dir=parent) as tmp:
        out_dir = Path(tmp) / "output"
        out_dir.mkdir(parents=True)
        (out_dir / "metadata.json").write_bytes(payload)

        try:
            store.put_output(job_id, out_dir)
        except Exception as exc:  # noqa: BLE001
            # A raise here does NOT mean nothing landed: an S3-compatible store can commit the
            # object and then lose the response or time out. Every other failure path cleans up;
            # this one skipping it meant a crash-looping dispatcher -- the exact behaviour a
            # fail-closed gate produces -- left one orphaned object per restart, forever, since
            # each attempt uses a fresh random id.
            _cleanup(store, job_id)
            raise CanaryFailure(
                f"blob store WRITE failed ({describe_blob_store(store)})",
                "check BLASTBOX_BLOB_URL, BLASTBOX_BLOB_ENDPOINT_URL and the AWS_* credentials on "
                "THIS container, and that this container has a network route to the endpoint "
                "(dispatchers on an `internal: true` docker network cannot reach an off-box store)",
                exc,
            ) from None

        try:
            present = store.has_output(job_id)
        except Exception as exc:  # noqa: BLE001
            _cleanup(store, job_id)
            raise CanaryFailure(
                f"blob store EXISTS-check failed ({describe_blob_store(store)})",
                "the write succeeded but the store could not be queried; check read permissions "
                "for the same credentials",
                exc,
            ) from None
        if not present:
            if not keep_failed:
                _cleanup(store, job_id)
            if racey:
                raise _RaceySuspicion(
                    f"wrote {job_id}, has_output() then reported it absent")
            raise CanaryFailure(
                f"blob store accepted a write that then did not exist ({describe_blob_store(store)})",
                "the write path and the read path are not the same store -- check that every "
                "dispatcher AND the API share one BLASTBOX_BLOB_URL (a dispatcher falling back to "
                "LocalBlobStore produces exactly this: jobs reach DONE and their results 404)",
            )

        try:
            with store.open_output(job_id, "metadata.json") as fh:
                got = fh.read()
        except Exception as exc:  # noqa: BLE001
            _cleanup(store, job_id)
            if racey:
                # The delete is what collides, and this is exactly where it lands: another
                # process's cleanup between our has_output and our open_output.
                # Redacted too: this message is logged on the retry path.
                raise _RaceySuspicion(
                    f"read-back of {job_id} failed: {redact_secrets(str(exc))}") from None
            raise CanaryFailure(
                f"blob store READ-BACK failed ({describe_blob_store(store)})",
                "results are being written but cannot be served; check read permissions and that "
                "the API resolves the same bucket/prefix",
                exc,
            ) from None

        if got != payload:
            _cleanup(store, job_id)
            if racey:
                # Another process holding the same key overwrote it between our put and our read.
                # Retrying on a unique key tells the two apart: a store that really returns the
                # wrong bytes fails that attempt too.
                raise _RaceySuspicion(f"read-back of {job_id} returned another probe's bytes")
            raise CanaryFailure(
                f"blob store returned different bytes than were written "
                f"({len(got)}B back vs {len(payload)}B written, {describe_blob_store(store)})",
                "the store is not durable or two deployments share one prefix; give each stack its "
                "own BLASTBOX_BLOB_URL prefix",
            )

    _cleanup(store, job_id)
    return (f"{describe_blob_store(store)} write+read+delete OK "
            f"in {1000 * (time.monotonic() - started):.0f}ms")


def _purge_versions(store: Any, job_id: str) -> None:
    """Drop the canary key's NONCURRENT versions and delete markers. Best-effort, S3 only.

    A stable key bounds the number of live objects to one, but it does not bound STORAGE on a
    versioned bucket: every periodic ``put_output`` writes a new version, and ``delete_job`` lists
    only current keys and calls ``delete_objects`` without a ``VersionId`` -- which adds a delete
    marker rather than removing anything. So each interval leaves one noncurrent version plus one
    marker, per dispatcher, forever, and the probe that exists to prove the store is healthy
    quietly accretes metadata in it.

    Scoped to the canary's own prefix on purpose. ``delete_job`` is shared with retention and the
    ingress DELETE route, where "remove every version" is a different decision with a different
    blast radius; this only touches the key this module wrote.

    Silent on failure, including the permission case: ``s3:ListBucketVersions`` and
    ``s3:DeleteObjectVersion`` are not implied by the write access the canary needs, and a
    deployment that withholds them is expected -- the documented remedy there is a lifecycle rule
    on noncurrent versions. Never raises; the caller is already best-effort.
    """
    s3 = getattr(store, "_s3", None)
    bucket = getattr(store, "_bucket", None)
    keyfn = getattr(store, "_key", None)
    if s3 is None or not bucket or not callable(keyfn):
        return                                   # not an S3-shaped store: nothing to version
    try:
        prefix = keyfn("results", job_id) + "/"
        paginator = s3.get_paginator("list_object_versions")
        # Collect the whole listing BEFORE deleting. Deleting inside the pagination loop
        # walks a listing being mutated underneath it: the continuation token names an
        # object the previous batch removed and the remainder is skipped. That is reachable
        # here -- this key gains a version every probe interval (~96/day per dispatcher at
        # the 900s default), so the purge would silently stop cleaning past the first page.
        stale = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                 for page in paginator.paginate(Bucket=bucket, Prefix=prefix)
                 for k in ("Versions", "DeleteMarkers")
                 for v in (page.get(k) or [])
                 if v.get("VersionId") and v["VersionId"] != "null"]
        for i in range(0, len(stale), 1000):     # DeleteObjects caps at 1000 keys
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": stale[i:i + 1000], "Quiet": True}
            )
    except Exception as exc:  # noqa: BLE001 -- unversioned bucket, or no version permissions
        _log.debug("canary.version_purge_skipped job_id=%s: %s: %s",
                   job_id, type(exc).__name__, redact_secrets(str(exc)))


def _cleanup(store: Any, job_id: str) -> None:
    """Best-effort removal of the canary object.

    Never raises: a store that cannot delete is worth a warning, but failing the self-test over it
    would take a dispatcher down for something that does not stop it serving jobs. Because the key
    is STABLE per dispatcher (see :func:`canary_job_id`), a store that always denies deletes leaves
    exactly one object rather than one per probe -- the earlier random-id version grew without
    bound under precisely that IAM policy.
    """
    try:
        store.delete_job(job_id)
        _purge_versions(store, job_id)
    except Exception as exc:  # noqa: BLE001
        # Redacted like every other message: this is a separate exception path, reached after
        # both successful probes and ambiguous writes, and botocore echoes the URL it was handed.
        _log.warning("canary.cleanup_failed job_id=%s: %s: %s — leftover object left in the store",
                     job_id, type(exc).__name__, redact_secrets(str(exc)))


def is_shared_job_store(job_store: Any) -> bool:
    """Does this dispatcher claim from a queue OTHER processes also use?

    Postgres and Redis are shared by construction -- something else is serving the results. SQLite
    and in-memory are single-process. Deliberately conservative: an unrecognised store answers
    False, so a store we cannot classify never triggers the coherence failure below.
    """
    name = type(job_store).__name__
    if name == "RedisJobStore":
        return True
    driver = getattr(job_store, "_driver", None)
    if driver is not None:
        return str(driver).lower() in ("postgres", "postgresql", "mysql")
    return False


def is_local_blob_store(store: Any) -> bool:
    """True for LocalBlobStore AND its subclasses.

    An exact type-name test let a subclass through -- and `Dispatcher(blob_store=...)` is a
    supported injection seam, so wrapping LocalBlobStore to add instrumentation is a thing callers
    legitimately do. Such a wrapper was classified NON-local, which skipped the fail-closed
    shared-store refusal and let two hosts with identical private paths register and agree. A
    capability gate that a subclass silently bypasses is not a gate.
    """
    try:
        from blastbox.host.blobs.local import LocalBlobStore
    except Exception:  # noqa: BLE001 - optional import; fall back to the name test
        return type(store).__name__ == "LocalBlobStore"
    return isinstance(store, LocalBlobStore)


def check_store_coherence(job_store: Any, blob_store: Any, job_root: Any = None, *,
                          require_shared: bool = False) -> None:
    """A shared queue needs a blob store the OTHER processes can also read.

    Catches what the round-trip provably cannot: a LocalBlobStore round-trips perfectly -- it
    writes and reads its own directory -- so a dispatcher that silently fell back to one passes
    every liveness test while sealing results the API cannot read. Jobs reach DONE and every
    artifact 404s. That is what happened to 17,626 jobs, invisibly, for days.

    WARNS by default; only ``require_shared`` makes it refuse. Two earlier attempts to infer
    "is this store reachable by the other processes?" from the deployment both refused DOCUMENTED
    configurations (docs/specs/2026-07-21-distributed-blob-storage-design.md):

      * Mode 2, multi-node on a LAN: shared postgres, ``BLASTBOX_BLOB_URL`` unset,
        ``BLASTBOX_BLOB_LOCAL_ROOT`` on an NFS export. Rejected for being "local".
      * Mode 1, single node: two processes on one box sharing a **local postgres** and the local
        filesystem. Rejected for being "postgres with the default blob root".

    Path equality cannot separate those from the accident, because the property that actually
    matters -- can the process serving results read what this one writes -- is a fact about the
    filesystem and the deployment topology, not about the string. Guessing it wrong is expensive
    in a way guessing it right is not: a check that refuses a working deployment, by default and
    fail-closed, is worse than the bug it hunts. So the operator declares it.
    ``BLASTBOX_REQUIRE_SHARED_BLOB_STORE=1`` says "this is a fleet, results must be shared", and
    then it refuses. Otherwise it says so loudly and lets the deployment boot.

    The real fix supersedes this entirely: have the dispatcher and the ingress agree on a blob
    target through the job store they already share (issue #88). That needs no inference at all.
    """
    if not (is_shared_job_store(job_store) and is_local_blob_store(blob_store)):
        return
    what = (f"this dispatcher claims from a SHARED queue ({type(job_store).__name__}) but stores "
            f"results in a LOCAL blob store ({describe_blob_store(blob_store)})")
    remedy = (
        "if other machines run this queue, set BLASTBOX_BLOB_URL (plus BLASTBOX_BLOB_ENDPOINT_URL "
        "and AWS_* credentials) on THIS container -- it is almost certainly set on the API and "
        "missing here, and results written to a store only this container can read make jobs "
        "reach DONE with artifacts that 404. If the API and this dispatcher genuinely share a "
        "filesystem (a single node, or BLASTBOX_BLOB_LOCAL_ROOT on a shared mount) this is "
        "correct and you can ignore it; set BLASTBOX_REQUIRE_SHARED_BLOB_STORE=1 to make it a "
        "hard failure on fleets where it never is"
    )
    if require_shared:
        raise CanaryFailure(what, remedy)
    _log.warning("canary.local_blob_store_with_shared_queue %s — %s", what, remedy)


#: What a LOCAL store registers instead of its path. Not an s3:// target, so it conflicts with one
#: in EITHER boot order, while every local store registers the same value so the NFS shape agrees.
_LOCAL_SENTINEL = "local:"


def _missing_not_denied(exc: BaseException) -> bool:
    """True when this error means "the object is not there", not "you may not look".

    Walks the CAUSE CHAIN, because the shipped S3 store does not surface the original error:
    `get_sample` re-raises everything as `BlobFetchError("sample fetch failed: <sha>")` and keeps
    the botocore detail only in `__cause__`. Matching on `str(exc)` alone therefore saw the same
    generic text for a missing key and for AccessDenied -- so a probe built on it flagged every
    healthy S3 dispatcher while still not detecting a denied prefix.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        text = str(cur).lower()
        code = ""
        resp = getattr(cur, "response", None)
        if isinstance(resp, dict):
            code = str(resp.get("Error", {}).get("Code", "")).lower()
        # "sample not present" / "not present" is LocalBlobStore's phrasing, raised with NO cause
        # at all -- so the S3-shaped markers alone flagged every healthy local dispatcher. Same
        # blindness as the S3 wrapper, on the other backend, which is the sibling this fix missed
        # the first time.
        if code in ("404", "nosuchkey", "notfound", "no_such_key") or \
                any(m in text for m in ("404", "not found", "nosuchkey", "no such file",
                                        "not present", "no such key")):
            return True
        if code in ("403", "accessdenied", "invalidaccesskeyid", "signaturedoesnotmatch") or \
                any(m in text for m in ("403", "access denied", "accessdenied", "forbidden")):
            return False
        cur = cur.__cause__ or cur.__context__
    return False


def check_sample_read_access(store: Any, *, role: str, scratch_dir: Any = None) -> None:
    """Prove this dispatcher can read the SAMPLES prefix, not just write results.

    `blob_roundtrip` exercises put_output / has_output / open_output -- all under `results/`. A
    role-separated IAM policy that grants those and denies GetObject on `samples/*` therefore
    passes the startup gate cleanly, and then every claimed job fails in `get_sample`: the input is
    not on this node, the claim is released, and after the bounded materialisation attempts the job
    is terminally failed. A gate that clears a dispatcher which cannot fetch a single input is
    checking the wrong half of its own job.

    Probes a sha that cannot exist. NotFound proves the read was permitted and answered; a denial
    or a connection error proves it was not, and those look different at the API level.

    ADVISORY: a samples-prefix outage is recoverable and the dispatcher may still have useful work
    queued behind it, so this reports rather than refuses -- same posture as the read probe.
    """
    getter = getattr(store, "get_sample", None)
    if not callable(getter):
        return
    import tempfile
    from pathlib import Path as _Path

    probe_sha = "0" * 64          # a valid sha256 shape that no real sample can have
    # Only stage under the configured root if it EXISTS. This probe is advisory, so it must not be
    # able to raise out of startup -- and an absent job root made TemporaryDirectory throw
    # FileNotFoundError straight past the handler below, turning a diagnostic into an outage. The
    # round-trip's refusal to fall back to /tmp is deliberate and stays; it WRITES the artefact
    # under test, whereas this only needs somewhere to drop a throwaway destination file.
    _dir = None
    try:
        if scratch_dir is not None and _Path(str(scratch_dir)).is_dir():
            _dir = str(scratch_dir)
    except Exception:  # noqa: BLE001
        _dir = None
    with tempfile.TemporaryDirectory(prefix="blastbox-canary-sample-", dir=_dir) as tmp:
        dest = _Path(tmp) / "probe.bin"
        try:
            getter(probe_sha, dest)
        except Exception as exc:  # noqa: BLE001
            text = redact_secrets(str(exc))
            # A MISSING object is the expected answer and proves the read was allowed. A denial or
            # a transport failure is the finding. Decided from the CAUSE CHAIN, not from this
            # exception's text: the shipped store hides the botocore error behind a generic
            # BlobFetchError, so the string alone cannot tell the two apart.
            if _missing_not_denied(exc):
                _log.info("canary.sample_read_ok %s can read the samples prefix of %s",
                          role, describe_blob_store(store))
                return
            _log.warning(
                "canary.sample_read_unverified %s could not read the samples prefix of %s: %s: %s "
                "-- results are writable but INPUTS may not be fetchable, in which case every "
                "claimed job fails in get_sample and is terminally failed after its retries. "
                "Check this container's read permission on the samples/ prefix.",
                role, describe_blob_store(store), type(exc).__name__, text)
            return
    _log.info("canary.sample_read_ok %s can read the samples prefix of %s",
              role, describe_blob_store(store))


def check_read_access(store: Any, *, role: str) -> None:
    """Prove this process can actually READ from the target it is about to serve.

    Target agreement compares identities; it does not prove this process can reach the store. An
    ingress with stale credentials or an unreachable endpoint has the same bucket and prefix as its
    dispatchers, so agreement succeeds, `build_app` starts, and every result route then fails --
    all artifacts unreadable, which is the exact failure this whole seam exists to end, arrived at
    through the check meant to prevent it.

    The active round-trip runs in DISPATCHER processes only, and it must stay that way: it WRITES,
    and an API that writes to the results prefix is a different security posture. So this is a read
    probe, not a round-trip -- `has_output` against a key that does not exist. A store that answers
    "no" has proven it can be reached and is permitted to answer; one that raises has not.

    ADVISORY, deliberately. A store that is briefly unreachable at boot is a brownout, and taking
    the API down for it would turn a recoverable outage into an outage plus a restart loop -- the
    same reasoning that keeps the periodic canary advisory once serving. The startup GATE is for
    misconfiguration, which agreement already covers; this reports reachability.
    """
    # NOT `has_output`. The shipped S3 implementation catches EVERY exception and returns False --
    # deliberately, because the age reclaim deletes local trees on the strength of its answer and a
    # transient outage must never read as "the durable copy is there". Correct for that caller, and
    # fatal for this one: a probe built on it never sees AccessDenied, invalid credentials or a
    # connection failure, so an unreachable ingress logged `canary.read_ok` and reported health it
    # had not verified. Worse than no probe, which at least does not claim anything.
    #
    # So go under it when the store exposes a client, and only fall back to the collapsing helper
    # for backends that have no other read surface.
    client = getattr(store, "_s3", None)
    bucket = getattr(store, "_bucket", None)
    keyfn = getattr(store, "_key", None)
    if client is not None and bucket and callable(keyfn):
        try:
            client.head_object(Bucket=bucket,
                               Key=keyfn("results", "blastbox-canary-read-probe", "seal.json"))
        except Exception as exc:  # noqa: BLE001 - advisory
            if _missing_not_denied(exc):
                _log.info("canary.read_ok %s can read from %s", role, describe_blob_store(store))
                return
            _log.warning(
                "canary.read_unverified %s could not read from %s: %s: %s -- results may not be "
                "servable from this process. Check its credentials, endpoint and network route; "
                "the target itself matches what the dispatchers registered.",
                role, describe_blob_store(store), type(exc).__name__, redact_secrets(str(exc)))
            return
        _log.info("canary.read_ok %s can read from %s", role, describe_blob_store(store))
        return

    # LOCAL stores collapse errors too. `LocalBlobStore.has_output` returns False for an OSError
    # -- correct for the reclaim, which must not read "unknown" as "durable" -- so an ingress whose
    # blob root is unreadable by its UID reported read_ok exactly like the S3 case. Bypassing the
    # helper for S3 and leaving local on it fixed one of two identical backends.
    root = getattr(store, "local_root", None)
    if root is not None:
        try:
            from pathlib import Path as _P
            probe_dir = _P(root() if callable(root) else root)
            probe_dir.mkdir(parents=True, exist_ok=True)
            next(probe_dir.iterdir(), None)          # LIST: distinguishes absent from unreadable
        except Exception as exc:  # noqa: BLE001 - advisory
            _log.warning(
                "canary.read_unverified %s could not read from %s: %s: %s -- results may not be "
                "servable from this process. Check the blob root's ownership and permissions for "
                "this container's UID.",
                role, describe_blob_store(store), type(exc).__name__, redact_secrets(str(exc)))
            return
        _log.info("canary.read_ok %s can read from %s", role, describe_blob_store(store))
        return

    probe = getattr(store, "has_output", None)
    if not callable(probe):
        return
    try:
        probe("blastbox-canary-read-probe-nonexistent")
    except Exception as exc:  # noqa: BLE001 - advisory: a brownout must not stop the API booting
        _log.warning(
            "canary.read_unverified %s could not read from %s: %s: %s -- results may not be "
            "servable from this process. Check its credentials, endpoint and network route; the "
            "target itself matches what the dispatchers registered.",
            role, describe_blob_store(store), type(exc).__name__, redact_secrets(str(exc)))
        return
    _log.info("canary.read_ok %s can read from %s", role, describe_blob_store(store))


def check_blob_target_agreement(job_store: Any, blob_store: Any, *, role: str) -> str | None:
    """Prove every process on this queue writes results to the SAME blob target.

    The gap `blob_target_fingerprint` could only make visible: `blob_roundtrip` proves a process
    can write and read ITS OWN store, and `check_store_coherence` catches a private local store
    behind a shared queue -- but dispatch on `s3://results/stack-b` and serve on
    `s3://results/stack-a` both pass those and every finished job 404s. That is the original
    17,626-job incident with a different cause, and it stayed hidden for days because nothing
    compared the two.

    The queue is the carrier, because it is the only thing the two processes are GUARANTEED to
    share: if they do not share it, they are not the same deployment and there is nothing to
    compare. Registration is a compare-and-swap (see :class:`BlobTargetRegistry`) so a boot storm
    has exactly one winner rather than every process recording its own answer and no one noticing.

    REFUSES on mismatch, both sides, naming both targets and who holds which. A mismatch is not a
    brownout that heals: every job the fleet finishes in this state is unreadable, and the sooner
    it stops the fewer there are. Returns the agreed fingerprint, or None when the store predates
    the registry (a third-party JobStore) -- absence of the seam is not evidence of disagreement,
    so it warns rather than refusing.
    """
    from blastbox.host.jobs.base import BlobTargetRegistry

    if not isinstance(job_store, BlobTargetRegistry):
        _log.warning("canary.blob_target_unverified %s cannot record a blob target; "
                     "dispatcher/ingress agreement is NOT being checked",
                     type(job_store).__name__)
        return None

    # LOCAL STORES DO NOT REGISTER, but they are still CHECKED. A LocalBlobStore fingerprint is a
    # host-local PATH, so comparing two of them proves nothing -- the documented multi-node NFS
    # deployment mounts one export at different mount points per host, and an earlier version of
    # this check refused it for that. But skipping the local case ENTIRELY was too much: local
    # versus s3:// needs no path comparison at all, because a host-local directory can never be
    # the bucket another process registered. That is the original incident with one side over --
    # BLASTBOX_BLOB_URL set on the dispatchers and missing on the API -- and it was passing.
    #
    # It matters most here: check_store_coherence has three call sites and every one is
    # dispatcher-side, so an ingress that fell back to a local store gets no coverage from it. The
    # log line that said otherwise was wrong.
    if is_local_blob_store(blob_store):
        # REGISTER A SENTINEL, do not just look. Returning without claiming made enforcement
        # ORDER-DEPENDENT: a local process booting FIRST recorded nothing, so the S3 peer then
        # claimed an empty registry and both started -- the mismatch undetected because the wrong
        # side happened to boot first. The sentinel carries no path (paths across hosts are
        # meaningless, which is why the NFS shape must keep working) but it is not an S3 target, so
        # it conflicts with one in either order.
        recorded = job_store.claim_blob_target(_LOCAL_SENTINEL)
        if recorded is None:
            # Same contract as the non-local path below: an unreadable read-back is UNKNOWN, not
            # success. Logging "registered the sentinel" here was false -- a remote process can
            # then claim the empty registry and start on S3 while this local one is already
            # serving, and the operator was told the opposite.
            _log.warning("canary.blob_target_unverified %s could not read the registry back after "
                         "registering the local sentinel (a concurrent reset, or an evicted key); "
                         "agreement is NOT confirmed this boot", role)
            return None
        if not recorded.startswith(_LOCAL_SENTINEL):
            raise CanaryFailure(
                f"this {role} reads and writes results in a LOCAL directory "
                f"({describe_blob_store(blob_store)}), but another process on the SAME job queue "
                f"registered {recorded}",
                "a host-local directory is not that target and never will be -- results written to "
                "one are unreadable from the other, so every finished job 404s. Usually this means "
                "BLASTBOX_BLOB_URL is set on one side and missing on this one. Set it here, or, if "
                "you are DELIBERATELY migrating, clear the recorded target with "
                "`blastbox blob-target reset` and restart both sides.",
                None,
            )
        _log.info("canary.blob_target %s uses a local store; registered the path-independent "
                  "sentinel (the shared-queue hazard is check_store_coherence's job)", role)
        return None

    mine = blob_target_fingerprint(blob_store)
    if not mine:
        _log.warning("canary.blob_target_unverified %s uses %s, which exposes no comparable target "
                     "identity; agreement is NOT being checked", role, type(blob_store).__name__)
        return None
    agreed = job_store.claim_blob_target(mine)
    if agreed is None:
        # UNKNOWN, not agreement. See BlobTargetRegistry.claim_blob_target.
        _log.warning("canary.blob_target_unverified %s could not read the registry back after "
                     "registering %s (a concurrent reset, or an evicted key); agreement is NOT "
                     "confirmed this boot", role, mine)
        return None
    if agreed == mine:
        _log.info("canary.blob_target %s agrees with the queue (%s)", role, mine)
        return agreed
    raise CanaryFailure(
        f"this {role} writes results to {mine} (reached via {describe_blob_store(blob_store)}), "
        f"but another process on the SAME job queue registered {agreed}",
        "every job finished in this state is unreadable by the other side -- it reaches DONE and "
        "then 404s. Point both at the same bucket/prefix/endpoint, or, if you are DELIBERATELY "
        "migrating, clear the recorded target with `blastbox blob-target reset` and restart both "
        "sides. Check BLASTBOX_BLOB_URL, BLASTBOX_BLOB_ENDPOINT_URL and BLASTBOX_BLOB_LOCAL_ROOT "
        "on THIS process against the other one.",
        None,
    )


def blob_target_fingerprint(store: Any) -> str:
    """A stable identity for WHERE this process reads and writes results.

    WHERE THE BYTES LAND, not how this process gets there. Bucket and prefix only: the ENDPOINT is
    per-process routing and legitimately differs between processes sharing one object store. The
    shipped compose does exactly that on purpose -- the api reaches MinIO on the host IP while the
    dispatcher uses the `minio` alias, because the backend network is `internal: true` -- so an
    equality key that included the endpoint refused a documented, working stack outright, with no
    off switch and no reset that could help (clearing just re-records whichever side boots next).
    That was the THIRD time on this branch that a check aimed at one thing rejected a working
    deployment by over-reading an incidental detail.

    The endpoint is still LOGGED, by `describe_blob_store`, on both sides and in the mismatch
    message -- it is exactly what an operator needs to see. It just is not part of the identity.

    Known limitation, stated rather than hidden: two DIFFERENT object stores that happen to use the
    same bucket and prefix compare equal here. That is a much rarer misconfiguration than
    split-endpoint routing, and the alternative is refusing the common documented case to catch the
    rare one.
    """
    bucket = getattr(store, "_bucket", None) or getattr(store, "bucket", None)
    if bucket:
        prefix = getattr(store, "_prefix", "") or ""
        # Stripped BEFORE it becomes an identity: this string is written to the job queue and
        # outlives every process, so a credential that lands here is a credential at rest.
        bucket = _safe_bucket(bucket)
        return f"s3://{bucket}/{prefix}" if prefix else f"s3://{bucket}"
    # An UNRECOGNISED shape has no identity we can compare. Returning the class name equated every
    # instance of it -- two dispatchers on different endpoints of a custom BlobStore would agree
    # because they share a type, which is worse than not checking. The empty string means "no
    # identity", and the caller declines to register rather than inventing one.
    return ""
