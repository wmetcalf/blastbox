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

import json
import logging
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


def blob_roundtrip(store: Any, *, keep_failed: bool = False) -> str:
    """PUT a sealed envelope through ``store``, read it back, verify the bytes, delete it.

    Returns a one-line description of what was proven. Raises :class:`CanaryFailure` naming the
    configuration to fix -- each stage is caught separately because they fail for different
    reasons and have different remedies. A store that passes this has been shown to be reachable,
    authorised, writable AND readable from this process.
    """
    job_id = f"__canary__{uuid.uuid4().hex[:16]}"
    started = time.monotonic()
    payload = json.dumps(_SEAL, sort_keys=True).encode()

    with TemporaryDirectory(prefix="blastbox-canary-") as tmp:
        out_dir = Path(tmp) / "output"
        out_dir.mkdir(parents=True)
        (out_dir / "metadata.json").write_bytes(payload)

        try:
            store.put_output(job_id, out_dir)
        except Exception as exc:  # noqa: BLE001
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
    would take a dispatcher down for something that does not stop it serving jobs. The leftover is
    one tiny object under a `__canary__` prefix, which is greppable precisely so an operator can
    find them if deletes are silently failing.
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


def default_local_blob_root(job_root: Any) -> Any:
    """Where the factory puts a LocalBlobStore when nothing points it anywhere.

    Mirrors ``blobs/factory.py``: unset ``BLASTBOX_BLOB_LOCAL_ROOT`` means a ``blobs`` sibling of
    job_root. Kept here so the coherence check can distinguish "nobody configured this" from
    "an operator deliberately pointed it at a shared mount".
    """
    return Path(job_root).parent / "blobs"


def check_store_coherence(job_store: Any, blob_store: Any, job_root: Any = None) -> None:
    """A shared queue needs a blob store the OTHER processes can also read. Raise when it cannot.

    This catches what the round-trip provably cannot. A LocalBlobStore round-trips perfectly -- it
    writes and reads its own directory -- so a dispatcher that silently fell back to one passes
    every liveness test while sealing results the API cannot read: jobs reach DONE and every
    artifact 404s. That is what happened to 17,626 jobs, invisibly, for days.

    The discriminator is NOT "local store with a shared queue". Mode 2 in
    ``docs/specs/2026-07-21-distributed-blob-storage-design.md`` is explicitly a supported
    deployment: several nodes on one postgres with ``BLASTBOX_BLOB_URL`` unset and
    ``BLASTBOX_BLOB_LOCAL_ROOT`` pointed at an NFS export common to every node. Refusing that would
    break a documented configuration by default, fail-closed -- a check that invents a reason to
    reject a valid deployment is worse than the bug it hunts.

    So the tell is a local store that nobody pointed anywhere: still sitting on the factory's
    private default beside this node's job_root, which no other process can read. That separates
    the accident (the variable is simply absent) from the deliberate choice (the operator named a
    shared mount). Without ``job_root`` we cannot tell the two apart, and the safe answer to "we
    cannot tell" is to say nothing.
    """
    if not (is_shared_job_store(job_store) and is_local_blob_store(blob_store)):
        return
    if job_root is None:
        # Without job_root the private-vs-shared distinction cannot be made, and guessing would
        # refuse the documented NFS deployment. Say so rather than staying silent: a check that
        # quietly did not run looks exactly like a check that passed, which is the reporting
        # failure underneath this whole class of bug.
        _log.warning("canary.coherence_skipped shared queue (%s) with a local blob store, but no "
                     "job_root was supplied — cannot tell a private default from a shared mount",
                     type(job_store).__name__)
        return
    root = getattr(blob_store, "local_root", None)
    if root is None:
        return
    try:
        if Path(str(root)).resolve() != default_local_blob_root(job_root).resolve():
            # Deliberately pointed somewhere -- an NFS export or another shared mount. The
            # operator made a choice; this check does not get to second-guess it.
            _log.info("canary.shared_local_blob_root %s — assuming it is shared, as documented "
                      "for multi-node LAN deployments", root)
            return
    except Exception:  # noqa: BLE001
        return

    raise CanaryFailure(
        f"this dispatcher claims from a SHARED queue ({type(job_store).__name__}) but stores "
        f"results in a PRIVATE local blob store ({describe_blob_store(blob_store)}), which is the "
        f"factory default beside this node's job_root -- nothing else can read it",
        "set BLASTBOX_BLOB_URL (and BLASTBOX_BLOB_ENDPOINT_URL + AWS_* credentials) on THIS "
        "container -- it is almost certainly set on the API and missing here. Results written to a "
        "private local store are unreadable by whatever serves them: jobs reach DONE and their "
        "artifacts 404. If this really is a multi-node deployment sharing a filesystem, point "
        "BLASTBOX_BLOB_LOCAL_ROOT at the shared mount and this check will accept it",
    )


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
