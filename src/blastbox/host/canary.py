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
import logging
import socket
import time
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_log = logging.getLogger("blastbox.canary")

# A sealed envelope that declares NO artifacts. `_declared_paths` returns an empty set for this,
# meaning "nothing was promised", so the upload has nothing it could silently drop. Keeping the
# canary's own payload trivial keeps a canary failure attributable to the STORE rather than to the
# envelope -- the point is to test the deployment, not the seal logic.
_SEAL = {"status": "ok", "engine": "__canary__", "artifacts": [], "canary": True}


class CanaryFailure(RuntimeError):
    """A self-test failed.

    Carries the operator-facing remedy, not just the exception: the whole reason this class exists
    is that the underlying errors (a 403, a connection timeout, a silently-local store) do not say
    which piece of configuration produced them.
    """

    def __init__(self, what: str, remedy: str, cause: BaseException | None = None) -> None:
        msg = f"{what}\n  fix: {remedy}"
        if cause is not None:
            msg += f"\n  cause: {type(cause).__name__}: {cause}"
        super().__init__(msg)
        self.what = what
        self.remedy = remedy


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
        endpoint = None
        client = getattr(store, "_s3", None)
        try:
            endpoint = client.meta.endpoint_url if client is not None else None
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
    ident = f"{socket.gethostname()}|{key_hint}".encode()
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
    payload = json.dumps(_SEAL, sort_keys=True).encode()

    # Stage under the dispatcher's OWN scratch when we know it. Requiring a writable system /tmp
    # made the gate reject a hardened deployment whose job_root and blob store are both fine --
    # failing it for a prerequisite real dispatch never needed, before the store was even touched.
    # The probe should test what the job path tests, not more.
    parent = None
    if scratch_dir is not None:
        try:
            parent = Path(scratch_dir)
            parent.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa: BLE001 - fall back to the system temp dir
            parent = None
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
            ) from exc

        try:
            present = store.has_output(job_id)
        except Exception as exc:  # noqa: BLE001
            _cleanup(store, job_id)
            raise CanaryFailure(
                f"blob store EXISTS-check failed ({describe_blob_store(store)})",
                "the write succeeded but the store could not be queried; check read permissions "
                "for the same credentials",
                exc,
            ) from exc
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
                raise _RaceySuspicion(f"read-back of {job_id} failed: {exc}") from exc
            raise CanaryFailure(
                f"blob store READ-BACK failed ({describe_blob_store(store)})",
                "results are being written but cannot be served; check read permissions and that "
                "the API resolves the same bucket/prefix",
                exc,
            ) from exc

        if got != payload:
            _cleanup(store, job_id)
            raise CanaryFailure(
                f"blob store returned different bytes than were written "
                f"({len(got)}B back vs {len(payload)}B written, {describe_blob_store(store)})",
                "the store is not durable or two deployments share one prefix; give each stack its "
                "own BLASTBOX_BLOB_URL prefix",
            )

    _cleanup(store, job_id)
    return (f"{describe_blob_store(store)} write+read+delete OK "
            f"in {1000 * (time.monotonic() - started):.0f}ms")


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
    except Exception as exc:  # noqa: BLE001
        _log.warning("canary.cleanup_failed job_id=%s: %s: %s — leftover object left in the store",
                     job_id, type(exc).__name__, exc)


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
    return type(store).__name__ == "LocalBlobStore"


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


def blob_target_fingerprint(store: Any) -> str:
    """A stable identity for WHERE this process reads and writes results.

    Logged by both `serve` and `dispatch` so a target mismatch between them is greppable across a
    fleet. It does not PROVE agreement -- the dispatcher's round-trip only ever touches its own
    store, so `s3://results/stack-b` on dispatch and `s3://results/stack-a` on serve both pass
    while every real job still 404s. Proving it needs an identity the two processes exchange
    through something they already share, which today means a seam the JobStore protocol does not
    have; see the follow-up issue. Until then this at least makes the drift visible instead of
    silent, which is how the original incident stayed hidden for days.
    """
    return describe_blob_store(store)
