"""BlobStore protocol — the seam between a job's bytes and where they live.

The local job dir stays the working set in EVERY backend: Firecracker bind-mounts
need a real path. A remote backend does not replace ``job_root``, it feeds it.
"""
from __future__ import annotations

import time
from pathlib import Path, PurePosixPath
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


# The host-written seal. It is both the artifact the API needs to serve a job at all and,
# because put_output uploads it LAST, the commit marker that makes has_output() meaningful.
_SEAL_NAME = "metadata.json"


def _is_seal(path: Path, out_dir: Path) -> bool:
    """True only for ``<out_dir>/metadata.json`` -- the seal, not any file sharing its name.

    Matching on the BASENAME was wrong against real output: RedTusk writes
    ``rmeta/metadata.json`` per embedded document, so a basename test classified those as seals
    too and shipped them to the end of the upload alongside the real one -- where sorted order
    put the top-level seal FIRST again, silently undoing the two-phase commit. Caught by
    end-to-end testing against MinIO (#85); the unit fixture had no nested metadata.json.
    """
    try:
        return path.relative_to(out_dir).as_posix() == _SEAL_NAME
    except ValueError:
        return False


def _declared_paths(out_dir: Path) -> "set[str] | None":
    """Relative paths the sealed envelope DECLARES as artifacts.

    Skipping a file we cannot store is only safe for an UNDECLARED one: those are not servable
    (the result routes are manifest-gated), so nothing a consumer can reach is lost. A declared
    artifact is the opposite -- dropping it and then writing the seal anyway produces a DONE job
    whose manifest promises bytes the store does not have, and marks the complete local copy
    redundant so the reclaim deletes it. That must fail the upload instead (#85 review).

    Returns None when the envelope is missing or unparseable -- NOT an empty set. Those are
    different: an empty set means "nothing was promised, so a skip is safe", while None means "we
    cannot tell", and the only safe response to that is to skip nothing at all.
    """
    try:
        import json

        env = json.loads((out_dir / _SEAL_NAME).read_text())
    except Exception:  # noqa: BLE001
        return None
    try:
        # NORMALIZED on both sides. Manifest paths are stored verbatim, so a perfectly valid
        # declaration of "./nested/x" or "nested//x" would not match the walker's
        # relative_to(out_dir).as_posix() ("nested/x") -- the artifact would look UNDECLARED, and
        # an unstorable one would then be skipped while the seal was still committed, which is
        # the exact data loss the declared-path check exists to prevent (#85 review).
        return {
            PurePosixPath(str(a.get("path"))).as_posix()
            for a in env.get("artifacts") or [] if a.get("path")
        }
    except Exception:  # noqa: BLE001
        return None


def _assert_declared_landed(job_id: str, out_dir: Path, stored: "set[str]") -> None:
    """Refuse to commit the seal unless every DECLARED artifact was actually stored.

    The per-file checks only ever saw paths the walker ENUMERATED. A worker controls the tree, so
    it can declare a path the walker never returns -- one inside a symlinked directory (rglob does
    not descend those), or past the point where a path-based walk stops -- and that artifact is
    then neither uploaded nor skipped, it is simply absent, while the seal is committed anyway.
    The result: a DONE job whose manifest promises bytes the store does not have, has_output()
    reporting it durable, and the reclaim deleting the complete local copy as redundant.

    Checking the manifest against what we actually stored closes the whole class, whatever the
    walker missed and why (#85 review).
    """
    declared = _declared_paths(out_dir)
    if not declared:
        return
    missing = []
    for rel in sorted(declared - stored):
        # Only a declared path that EXISTS as a real file under out_dir and was still not stored
        # is this function's problem -- that is the walker having missed something it should have
        # returned. A declared path with no file behind it is a manifest that lies, which is the
        # trust gate's business, not the uploader's: failing here would make an upload that can
        # never succeed, and a deterministic upload failure is precisely the immortal-tree class
        # this PR keeps having to close. lstat, so a symlink is not followed into being "real".
        try:
            # CONTAINMENT FIRST. `out_dir / "/etc/passwd"` is /etc/passwd -- an absolute or
            # ..-laden declaration escapes the tree entirely, and such a path is by definition not
            # an artifact we would ever store. That is a manifest lying about where its bytes are,
            # which the trust gate and the serve-time confinement handle; treating it as "missing"
            # here would fail an upload that can never succeed.
            p = out_dir / rel
            if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:
                continue
            if p.is_symlink() or not p.is_file():
                continue
        except OSError:
            continue
        missing.append(rel)
    if missing:
        raise BlobIntegrityError(
            f"put_output({job_id}): {len(missing)} declared artifact(s) exist on disk but were "
            f"not stored, so the seal was not committed: {missing[:3]}")


def _upload_order(out_dir: Path) -> list[Path]:
    """Every artifact under *out_dir*, with the seal LAST.

    Plain sorted order puts metadata.json first ('m' < 'r'), so an upload that died partway
    left the marker present with artifacts missing -- and the age reclaim would then read that
    as "durable copy exists" and delete the complete local tree.
    """
    paths = sorted(out_dir.rglob("*"))
    return ([p for p in paths if not _is_seal(p, out_dir)]
            + [p for p in paths if _is_seal(p, out_dir)])


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
