"""Tests for retention sweeper."""
from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import shutil
import time
from pathlib import Path

import pytest


from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import (
    PENDING_UPLOAD_SENTINEL,
    migrate_legacy_results,
    reap_stale_scratch,
    RESULT_RETAINED_MARKER,
    JobRetentionSweeper,
    purge_job_dir,
    retry_pending_uploads,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_job(
    status: JobStatus = JobStatus.DONE,
    expires_at: float | None = None,
    result_dir: str | None = None,
    engine: str = "test",
    filename: str = "file.docx",
) -> Job:
    job = Job.new(engine=engine, filename=filename)
    job.status = status
    job.expires_at = expires_at
    job.result_dir = result_dir
    return job


def _past(delta: float = 10.0) -> float:
    return time.time() - delta


def _future(delta: float = 3600.0) -> float:
    return time.time() + delta


# ---------------------------------------------------------------------------
# Basic expiry of terminal-status jobs
# ---------------------------------------------------------------------------

def test_expires_done_job_past_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired
    # result_dir's parent (job1/) should be deleted
    assert not (tmp_path / "job1").exists()
    # Job should be marked EXPIRED in store
    final = store.get(job.job_id)
    assert final is not None
    assert final.status == JobStatus.EXPIRED


def test_expires_failed_job_past_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job2" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.FAILED,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired


def test_does_not_expire_future_expiry(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "job3" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_future(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "job3").exists()


def test_does_not_expire_no_expires_at(tmp_path):
    store = InMemoryJobStore()
    job = _make_job(status=JobStatus.DONE, expires_at=None)
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired


# ---------------------------------------------------------------------------
# Non-terminal jobs must NOT be expired
# ---------------------------------------------------------------------------

def test_does_not_expire_queued_job(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "q1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.QUEUED,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "q1").exists()


def test_does_not_expire_running_job(tmp_path):
    store = InMemoryJobStore()
    result_dir = tmp_path / "r1" / "result"
    result_dir.mkdir(parents=True)
    job = _make_job(
        status=JobStatus.RUNNING,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=tmp_path)
    expired = sweeper.expire_due(store)

    assert job.job_id not in expired
    assert (tmp_path / "r1").exists()


# ---------------------------------------------------------------------------
# rmtree confinement — result_dir outside job_root must be refused
# ---------------------------------------------------------------------------

def test_rmtree_refused_outside_job_root(tmp_path):
    """A result_dir pointing outside job_root must not be deleted."""
    store = InMemoryJobStore()
    # Create a directory *outside* tmp_path that we want to protect
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("do not delete")

    # result_dir points to a path outside tmp_path
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(outside),
    )
    store.create(job)

    # Use a sub-directory as the job_root
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    sweeper = JobRetentionSweeper(job_root=job_root)
    sweeper.expire_due(store)

    # The sweep either skips this job or marks it expired without deletion
    # The outside directory must still exist
    assert outside.exists(), "directory outside job_root must not be deleted"
    assert sentinel.exists(), "files outside job_root must not be deleted"


def test_rmtree_confined_to_job_root(tmp_path):
    """A result_dir inside job_root is safe to delete."""
    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    result_dir = job_root / "job1" / "result"
    result_dir.mkdir(parents=True)
    (result_dir / "output.png").write_bytes(b"data")

    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=job_root)
    expired = sweeper.expire_due(store)

    assert job.job_id in expired
    # The job subdirectory (or at least result_dir) should be gone
    assert not result_dir.exists()


# ---------------------------------------------------------------------------
# Symlink escape — a symlink inside result_dir pointing outside must not be
# followed during deletion
# ---------------------------------------------------------------------------

def test_symlink_escape_not_followed(tmp_path):
    """A symlink inside the result dir pointing outside the base is not followed."""
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    # Victim directory outside job_root
    victim = tmp_path / "victim"
    victim.mkdir()
    victim_file = victim / "important.txt"
    victim_file.write_text("do not delete")

    # Set up result_dir inside job_root with a symlink pointing outside
    result_dir = job_root / "job1" / "result"
    result_dir.mkdir(parents=True)
    symlink = result_dir / "escape"
    symlink.symlink_to(victim)

    store = InMemoryJobStore()
    job = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result_dir),
    )
    store.create(job)

    sweeper = JobRetentionSweeper(job_root=job_root)
    sweeper.expire_due(store)

    # The victim directory must still exist — the symlink target must not
    # have been recursively deleted.
    assert victim.exists(), "victim dir outside job_root must survive"
    assert victim_file.exists(), "victim file must not be deleted via symlink"


# ---------------------------------------------------------------------------
# Failure logging (not crashing the sweeper)
# ---------------------------------------------------------------------------

def test_failure_on_one_job_does_not_block_others(tmp_path, caplog):
    """A failure expiring one job must not prevent others from being expired."""
    import logging

    store = InMemoryJobStore()
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    # job1: result_dir points to a non-existent path (simulates partial cleanup)
    job1 = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(job_root / "missing" / "result"),
    )
    store.create(job1)

    # job2: has a real result_dir that should be deleted
    result2 = job_root / "job2" / "result"
    result2.mkdir(parents=True)
    job2 = _make_job(
        status=JobStatus.DONE,
        expires_at=_past(),
        result_dir=str(result2),
    )
    store.create(job2)

    sweeper = JobRetentionSweeper(job_root=job_root)
    with caplog.at_level(logging.WARNING):
        expired = sweeper.expire_due(store)

    # job2 must be expired even if job1 had issues
    assert job2.job_id in expired
    assert not result2.exists()


# ---------------------------------------------------------------------------
# purge_job_dir — the shared helper both dispatchers call (#84)
# ---------------------------------------------------------------------------

class TestPurgeJobDir:
    """The helper is the ONLY thing standing between a terminal job and sample bytes
    left on spare hardware, so its refusals and its successes must both be exact:
    a refusal that fires wrongly leaks bytes, and a success reported wrongly
    (or a success reported as a failure) makes the operator alarm useless.
    """

    def test_returns_true_and_removes_the_tree(self, tmp_path, caplog):
        root = tmp_path / "jobs"
        (root / "abc").mkdir(parents=True)
        (root / "abc" / "sample.bin").write_bytes(b"MALWARE")

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert not (root / "abc").exists()
        assert "PURGE FAILED" not in caplog.text

    def test_already_gone_is_success_not_failure(self, tmp_path):
        root = tmp_path / "jobs"
        root.mkdir()
        # Nothing to do is the correct outcome, not an error: both dispatchers call
        # this from terminal cleanup and may race each other to the same job.
        assert purge_job_dir(root, "never-existed", logging.getLogger("t")) is True

    def test_a_peer_reaping_concurrently_is_not_reported_as_a_failure(
        self, tmp_path, monkeypatch, caplog,
    ):
        """rmtree losing the race to a peer is the NORMAL two-dispatcher case.

        Both dispatchers share one job_root and the age-based reclaim is not
        claim-fenced, so the tree can vanish between exists() and rmtree(). Treating
        that as failure fired the module's loudest operator-facing string ("sample
        bytes may remain") on cycles that had in fact succeeded — training the
        operator to ignore the one message that means bytes really did survive.
        """
        root = tmp_path / "jobs"
        (root / "abc").mkdir(parents=True)
        (root / "abc" / "sample.bin").write_bytes(b"MALWARE")

        real_rmtree = shutil.rmtree

        def racing_rmtree(path, *a, **kw):
            real_rmtree(path, *a, **kw)      # the peer's delete, landing first
            raise FileNotFoundError(2, "No such file or directory", str(path))

        monkeypatch.setattr("blastbox.host.jobs.retention.shutil.rmtree", racing_rmtree)

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert not (root / "abc").exists()
        assert "PURGE FAILED" not in caplog.text
        assert "sample bytes may remain" not in caplog.text

    def test_a_real_rmtree_failure_is_still_reported(self, tmp_path, monkeypatch, caplog):
        """The counterpart: a genuine OSError must keep the loud alarm and return False,
        so the concurrent-reap exemption above cannot be read as 'purge never fails'."""
        root = tmp_path / "jobs"
        (root / "abc").mkdir(parents=True)

        def failing_rmtree(path, *a, **kw):
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr("blastbox.host.jobs.retention.shutil.rmtree", failing_rmtree)

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "abc", logging.getLogger("t")) is False
        assert "PURGE FAILED" in caplog.text
        assert (root / "abc").exists()

    @pytest.mark.parametrize("job_id", ["", ".", "..", "a/b", "..\\b", "../victim"])
    def test_refuses_anything_that_is_not_one_path_component(self, tmp_path, job_id, caplog):
        """'victim/child/..' is strictly UNDER job_root yet resolves to a different job's
        tree, so containment alone cannot protect a peer. Job IDs are server-side uuid4
        and ingress validates them, but Job.from_dict() does not — an imported or
        corrupted store row reaches here unvalidated."""
        root = tmp_path / "jobs"
        (root / "victim").mkdir(parents=True)
        (root / "victim" / "keep.bin").write_bytes(b"LIVE PEER")

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, job_id, logging.getLogger("t")) is False
        assert (root / "victim" / "keep.bin").exists()
        assert root.exists()

    def test_refuses_to_purge_job_root_itself(self, tmp_path, caplog):
        """Path.relative_to(itself) returns '.' rather than raising, so containment
        alone would let a degenerate id take out every job on the worker."""
        root = tmp_path / "jobs"
        (root / "other").mkdir(parents=True)

        # A component that canonicalises back to job_root.
        (root / "self").symlink_to(root, target_is_directory=True)
        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "self", logging.getLogger("t")) is False
        assert (root / "other").exists()

    def test_refuses_a_symlink_alias_pointing_at_a_LIVE_PEER(self, tmp_path, caplog):
        """The dangerous symlink is the one that stays INSIDE job_root.

        An escaping link is caught by containment, but `jobs/<id> -> jobs/<peer>` resolves
        to a path that is strictly under job_root, so every containment check passes and
        rmtree takes out a peer's tree — while the job whose id was passed still has no
        bytes removed, and the call reports success. Job dirs are created with mkdir() and
        are never symlinks, so any link here is anomalous by construction.
        """
        root = tmp_path / "jobs"
        (root / "victim").mkdir(parents=True)
        (root / "victim" / "live.bin").write_bytes(b"PEER STILL RUNNING")
        (root / "alias").symlink_to(root / "victim", target_is_directory=True)

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "alias", logging.getLogger("t")) is False
        assert (root / "victim" / "live.bin").exists(), "purged a live peer's tree"

    def test_refuses_a_symlink_that_escapes_job_root(self, tmp_path, caplog):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "precious.bin").write_bytes(b"NOT OURS")
        root = tmp_path / "jobs"
        root.mkdir()
        (root / "escape").symlink_to(outside, target_is_directory=True)

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "escape", logging.getLogger("t")) is False
        assert (outside / "precious.bin").exists()

    def test_a_canonicalisation_error_is_contained_not_raised(
        self, tmp_path, monkeypatch, caplog,
    ):
        """A symlink loop makes Path.resolve() raise RuntimeError. Both dispatchers call
        this from terminal cleanup, so an escape here would mask the job's real outcome
        and skip its metrics — the docstring promises best-effort."""
        root = tmp_path / "jobs"
        root.mkdir()

        def exploding_resolve(self, *a, **kw):
            raise RuntimeError("symlink loop")

        monkeypatch.setattr(Path, "resolve", exploding_resolve)

        with caplog.at_level(logging.ERROR):
            assert purge_job_dir(root, "abc", logging.getLogger("t")) is False
        assert "PURGE FAILED" in caplog.text


# ---------------------------------------------------------------------------
# retry_pending_uploads — what makes retaining a result legitimate (#85)
# ---------------------------------------------------------------------------

class _FakeBlobs:
    """Minimal BlobStore: put_output can be made to fail, has_output reflects what landed."""

    def __init__(self, fail_put: bool = False) -> None:
        self.fail_put = fail_put
        self.stored: dict[str, list[str]] = {}
        self.put_calls = 0

    def put_output(self, job_id: str, out_dir) -> None:
        self.put_calls += 1
        if self.fail_put:
            raise OSError("object store unavailable")
        self.stored[job_id] = sorted(p.name for p in Path(out_dir).rglob("*") if p.is_file())

    def has_output(self, job_id: str) -> bool:
        return "metadata.json" in self.stored.get(job_id, [])


def _sealed_tree(root: Path, job_id: str, *, pending: bool = True) -> Path:
    """A host-sealed result on local disk. `pending` writes the HOST-ONLY sentinel that says its
    upload failed — the job dir is a sibling of output/ and the worker cannot write here."""
    d = root / job_id
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"sealed": true}')
    (d / "output" / "rmeta.json").write_text("[]")
    if pending:
        (d / PENDING_UPLOAD_SENTINEL).write_text("")
    return d


_JID = "44444444-4444-4444-8444-444444444444"


class TestRetryPendingUploads:

    def test_drains_a_retained_result_once_the_store_recovers(self, tmp_path):
        """The whole reason a tree may be retained. Without this sweep the two dispatchers had to
        choose between destroying a host-sealed, unreproducible result and keeping it forever as
        bytes no consumer can reach — neither of which ever gets the result durable."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED           # our own exhaustion path FAILs the job
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()

        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 1
        assert blobs.has_output(_JID)

    def test_is_a_noop_once_the_result_is_already_durable(self, tmp_path):
        """Idempotent and cheap: a tree whose bytes already landed is the age reclaim's business,
        not this sweep's — re-uploading every tick would hammer the store for nothing."""
        store = InMemoryJobStore()
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()
        blobs.stored[_JID] = ["metadata.json"]

        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0

    def test_never_overwrites_a_peers_authoritative_result(self, tmp_path):
        """THE claim fence. If a peer reclaimed the job and finished it, its result is
        authoritative and sits at the same results/<job_id> prefix. Uploading our stale attempt
        over it would serve the wrong bytes for a DONE job with nothing to repair it. DONE is the
        tell: our own exhaustion path always FAILs the job, so a DONE row means somebody else won.
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.DONE             # the peer won
        store.create(job)
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()

        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "uploaded a stale attempt over the peer's result"

    def test_leaves_the_tree_when_the_store_cannot_be_read(self, tmp_path):
        """Fails safe in the same direction as everything else here: unable to prove the tree is
        ours, we neither upload it nor lose it."""
        class Broken(InMemoryJobStore):
            def get(self, job_id):
                raise RuntimeError("store down")

        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, Broken(), logging.getLogger("t")) == 0
        assert blobs.put_calls == 0

    def test_ignores_ordinary_scratch_with_no_sealed_result(self, tmp_path):
        """A tree stranded mid-detonation has no seal and nothing worth uploading; this sweep must
        not manufacture a half-result from it. The age reclaim is what bounds those."""
        store = InMemoryJobStore()
        d = tmp_path / _JID
        (d / "output").mkdir(parents=True)
        (d / "input.bin").write_bytes(b"MALWARE")
        blobs = _FakeBlobs()

        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0

    def test_a_still_failing_upload_keeps_the_tree(self, tmp_path):
        """An outage that outlives the process is exactly the case in-memory bookkeeping could
        never survive — which is why the durability oracle is the store itself, not a set of ids."""
        store = InMemoryJobStore()
        d = _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs(fail_put=True)

        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert (d / "output" / "metadata.json").exists()

    def test_repairs_the_job_to_done_so_the_recovered_result_is_actually_servable(self, tmp_path):
        """Uploading the bytes is only HALF the recovery.

        The job was FAILED because its upload exhausted, and open_output is DONE-gated — so a
        recovered result stayed unreachable and the API answered 409 forever. From a client's
        view that is identical to having discarded it, which is the very outcome this whole
        mechanism exists to avoid. Found by end-to-end testing against a real dispatcher: the
        sweep logged "now durably stored" while /v1/jobs/<id>/result still returned
        "job not done (status=failed)".
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        assert retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t")) == 1
        repaired = store.get(_JID)
        assert repaired.status is JobStatus.DONE
        assert repaired.error is None

    def test_ignores_a_job_that_failed_for_any_other_reason(self, tmp_path):
        """Gated on OUR marker, which the dispatcher writes ONLY after the host seal, when the
        upload exhausted. A job that failed in the trust gate or the worker is neither uploaded
        nor promoted to DONE, even with a metadata.json lying next to it — that file is written by
        the WORKER (worker/harness.py) and only overwritten by the host once the gate passes."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = "worker exited non-zero"
        store.create(job)
        _sealed_tree(tmp_path, _JID, pending=False)   # no sentinel: the host never retained it

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "published a tree the host never sealed"
        assert store.get(_JID).status is JobStatus.FAILED, "promoted an unrelated failure to DONE"


    def test_never_publishes_a_tree_the_host_never_sealed(self, tmp_path):
        """A root metadata.json is NOT proof of a host seal.

        The WORKER writes output/metadata.json (worker/harness.py); the host only OVERWRITES it
        once the trust gate passes. So a tree abandoned before sealing — gate rejection, worker
        timeout, a dispatcher killed between worker exit and _write_sealed_metadata — still has
        one, full of worker-controlled bytes. Uploading it would publish untrusted output into
        the results namespace under a real job id.
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = "output rejected by the trust gate"      # never sealed
        store.create(job)
        d = tmp_path / _JID
        (d / "output").mkdir(parents=True)
        (d / "output" / "metadata.json").write_text('{"forged": "by the worker"}')
        assert not (d / PENDING_UPLOAD_SENTINEL).exists()    # the host vouched for nothing

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "published worker-controlled bytes as a job result"

    def test_repairs_a_job_whose_bytes_are_already_durable(self, tmp_path):
        """A previous sweep may have uploaded the bytes and then failed to write the status (store
        blip), or the dispatcher's own upload landed after it gave up. Skipping on "already
        durable" stranded that job FAILED forever with its result sitting in the store."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()
        blobs.stored[_JID] = ["metadata.json"]               # already there

        retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t"))
        assert blobs.put_calls == 0, "re-uploaded bytes that were already durable"
        assert store.get(_JID).status is JobStatus.DONE, "left a job FAILED with a durable result"

    def test_a_row_lost_to_a_ttl_is_not_uploaded(self, tmp_path):
        """Redis rows expire (24h default). A missing row yields no marker, so the sweep does
        nothing — the safe direction: the age reclaim still bounds the tree."""
        store = InMemoryJobStore()                            # no row for _JID at all
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0

    def test_a_repaired_job_gets_its_post_done_work_done(self, tmp_path):
        """A recovered job is DONE and servable but was permanently invisible to /similar: its own
        DONE path never ran, so page hashes were never indexed, and nothing re-walks DONE jobs.
        The hook is where a dispatcher does what its DONE path would have."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID)

        seen: list[tuple[str, Path, str]] = []
        retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"),
                              on_repaired=lambda jid, out, seal: seen.append((jid, out, seal)))
        assert [(s[0], s[1]) for s in seen] == [(_JID, d / "output")]
        # The hook is handed the SEAL BYTES, read while the tree was still held — so it does not
        # matter whether a peer reclaims the tree the moment the row goes DONE.
        assert seen[0][2].strip() == '{"sealed": true}' 

    def test_a_failing_post_repair_hook_never_undoes_the_repair(self, tmp_path):
        """Best-effort: the bytes are durable and the status is correct. An indexing problem must
        not drag the job back to FAILED or crash the maintenance tick."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        def boom(jid, out, seal):
            raise RuntimeError("indexer down")

        retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"),
                              on_repaired=boom)
        assert store.get(_JID).status is JobStatus.DONE

    def test_the_post_repair_hook_does_not_run_when_the_repair_did_not_happen(self, tmp_path):
        """The hook means "this job just became DONE". Running it on a CAS that lost — a peer
        moved the row out of FAILED between our read and our write — would index a result for a
        job whose terminal state somebody else owns, off an envelope from our stale attempt."""
        class LosesTheCas(InMemoryJobStore):
            def update_if_status(self, job_id, expect_status, **kw):
                return False               # somebody else moved it first

        store = LosesTheCas()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        seen: list[str] = []
        retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"),
                              on_repaired=lambda jid, out, seal: seen.append(jid))
        assert seen == [], "indexed a job this sweep did not repair"


    def test_a_worker_cannot_forge_its_way_into_the_results_namespace(self, tmp_path):
        """The gate must be a HOST fact, and job.error is not one.

        On the engine-error path the dispatcher stores the worker's own text verbatim
        (f"engine_error: {detail}"), so gating on RESULT_RETAINED_MARKER appearing in job.error
        let a worker put that string in its envelope warning and have this sweep upload its
        untrusted output/ as the job's result and CAS the job to DONE — serving worker-controlled
        bytes from a trusted route. Demonstrated end-to-end in review of #85.

        The sentinel is a file in the JOB DIR, a sibling of output/. The worker owns output/ (a
        0o777 bind mount) and nothing else, so it cannot put one there.
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"engine_error: {RESULT_RETAINED_MARKER}"      # forged by the worker
        store.create(job)
        _sealed_tree(tmp_path, _JID, pending=False)                # host vouched for nothing

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "a worker forged its way into the results namespace"
        assert store.get(_JID).status is JobStatus.FAILED

    def test_an_expired_job_is_never_resurrected(self, tmp_path):
        """Retention deleted this job's result on an operator's instruction and cleared
        expires_at. Re-uploading would silently undo that AND orphan the bytes forever, since the
        sweeper only selects rows whose expires_at is set."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.EXPIRED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "resurrected an expired job's result"


class TestDeepTreeRemoval:
    """A worker owns output/ (a 0o777 bind mount) and can nest directories arbitrarily.

    `for i in $(seq 1500); do mkdir a; cd a; done` is unprivileged, takes milliseconds and stays
    well inside PATH_MAX — but shutil.rmtree's fd walk RECURSES, so it raised RecursionError on
    every attempt forever. Catching it (which the code did) only stopped the exception escaping;
    the tree, and the malware input beside it, stayed on disk permanently, reproducing #84 on
    demand and giving any sample a way to fill the node's root filesystem.
    """

    @pytest.fixture(autouse=True)
    def _no_stranded_trees(self, tmp_path):
        """These tests build trees deliberately too deep for shutil.rmtree, so a FAILING one would
        strand something pytest's own cleanup cannot remove — it renames the dir to garbage-* and
        the next run inherits it. Remove it with the very function under test."""
        yield
        from blastbox.host.jobs.retention import _rmtree_iterative
        for child in list(tmp_path.iterdir()):
            if child.is_dir() and not child.is_symlink():
                with contextlib.suppress(OSError):
                    _rmtree_iterative(child)

    @staticmethod
    def _nest(base: Path, levels: int, leaf=None) -> None:
        """Build *levels* of nesting under *base*, one chdir at a time.

        Deliberately NOT `(base / "a" / "a" / ...).mkdir(parents=True)`: the absolute path passes
        PATH_MAX long before 1500 levels and mkdir fails with ENAMETOOLONG. A worker nests exactly
        this way (`for i in $(seq 1500); do mkdir a; cd a; done`), and it is the same reason the
        removal has to be fd-relative rather than path-based.
        """
        cwd = os.getcwd()
        try:
            os.chdir(base)
            for _ in range(levels):
                os.mkdir("a")
                os.chdir("a")
            if leaf is not None:
                leaf()
        finally:
            os.chdir(cwd)

    def test_a_deep_tree_is_removed_under_a_LOW_fd_limit(self, tmp_path):
        """The fd limit is the one a worker actually reaches first.

        The obvious iterative rewrite of rmtree holds one directory fd per level, so at the
        default 1024 ulimit it dies with EMFILE — RecursionError wearing a different hat, and the
        tree stays just as immortal. shutil.rmtree hits EMFILE first too, which is why the
        fallback cannot trigger on RecursionError alone. Found in end-to-end testing against a
        real dispatcher, where the container's limit was reached long before the recursion limit;
        the unit tests had missed it because pytest runs with a far higher limit.
        """
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        try:
            root = tmp_path / "jobs"
            d = root / "abc"
            (d / "output").mkdir(parents=True)
            (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
            self._nest(d / "output", 2000, leaf=lambda: pathlib.Path("payload").write_text("x"))

            assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
            assert not d.exists(), "a deep tree survived because the removal ran out of fds"
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    def test_a_deeply_nested_tree_is_actually_removed(self, tmp_path):
        root = tmp_path / "jobs"
        d = root / "abc"
        (d / "output").mkdir(parents=True)
        (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
        self._nest(d / "output", 1500, leaf=lambda: pathlib.Path("payload").write_text("x"))

        assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert not d.exists(), "a nested tree made itself permanently undeletable"

    def test_a_symlink_inside_a_deep_tree_is_unlinked_not_followed(self, tmp_path):
        """The iterative walk opens every directory O_NOFOLLOW, so a symlink is removed as an
        entry and never descended — otherwise a link planted deep in the tree would take the
        removal out of job_root entirely."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "precious.bin").write_bytes(b"NOT OURS")

        root = tmp_path / "jobs"
        d = root / "abc"
        (d / "output").mkdir(parents=True)
        self._nest(d / "output", 1200, leaf=lambda: os.symlink(str(outside), "escape"))

        assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert not d.exists()
        assert (outside / "precious.bin").exists(), "the removal followed a symlink out"


class TestRemovalRobustness:
    """Properties the removal must hold against a worker that chooses the tree's shape."""

    def test_an_unremovable_directory_fails_cleanly_instead_of_spinning(self, tmp_path):
        """A dir the host cannot rmdir — the worker chmods 0555 a dir it owns, or a bind mount is
        still live (EBUSY) — used to make the pass loop return "more to do" forever: a 100% CPU
        spin inside a dispatch `finally` (measured 369,871 passes in 8s), which is far worse than
        the clean failure shutil.rmtree would have produced. A pass that removes nothing raises.
        """
        if os.geteuid() == 0:
            pytest.skip("root ignores the permission bits this relies on")
        from blastbox.host.jobs.retention import _rmtree_iterative

        # Exercised DIRECTLY, not through purge_job_dir: shutil.rmtree hits the EACCES first and
        # re-raises it, so going through the front door never reaches the fallback and the test
        # would pass without testing anything.
        d = tmp_path / "abc"
        (d / "output").mkdir(parents=True)
        pinned = d / "output" / "pin"
        (pinned / "child").mkdir(parents=True)
        os.chmod(pinned, 0o555)
        try:
            t0 = time.monotonic()
            with pytest.raises(OSError):
                _rmtree_iterative(d)
            assert time.monotonic() - t0 < 30, "spun instead of giving up"
        finally:
            os.chmod(pinned, 0o755)

    def test_purge_reports_a_permission_failure_rather_than_spinning(self, tmp_path):
        """...and the front door still returns a clean False for it, exactly as shutil.rmtree
        alone would have. The fallback must never convert a bounded failure into a hang."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the permission bits this relies on")
        root = tmp_path / "jobs"
        d = root / "abc"
        (d / "output").mkdir(parents=True)
        pinned = d / "output" / "pin"
        (pinned / "child").mkdir(parents=True)
        self._nest_deep(d / "output")
        os.chmod(pinned, 0o555)
        try:
            t0 = time.monotonic()
            assert purge_job_dir(root, "abc", logging.getLogger("t")) is False
            assert time.monotonic() - t0 < 30, "purge spun instead of failing"
        finally:
            os.chmod(pinned, 0o755)

    def test_residue_from_an_interrupted_purge_does_not_poison_the_next_one(self, tmp_path):
        """The hoist used a fixed `.rm-0`, so residue from a killed purge (likely, given the spin
        above) made every later attempt rename onto a NON-EMPTY dir — ENOTEMPTY, zero progress,
        forever. Hoist names are now probed for freshness."""
        root = tmp_path / "jobs"
        d = root / "abc"
        (d / "output").mkdir(parents=True)
        residue = d / ".rm-0"
        (residue / "leftover").mkdir(parents=True)
        (residue / "leftover" / "f").write_text("x")
        self._nest_deep(d / "output")

        assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert not d.exists()

    def test_a_wide_tree_does_not_cost_a_pass_per_directory(self, tmp_path):
        """Descending only the first child per pass made the cost quadratic in sibling count
        (16k dirs = 24s, 4x per doubling) — inside the single maintenance thread, on a shape the
        worker picks for free. Iterators live on the stack, so one pass clears any width."""
        root = tmp_path / "jobs"
        d = root / "abc"
        (d / "output").mkdir(parents=True)
        for i in range(4000):
            (d / "output" / f"w{i}").mkdir()
        self._nest_deep(d / "output")

        t0 = time.monotonic()
        assert purge_job_dir(root, "abc", logging.getLogger("t")) is True
        assert time.monotonic() - t0 < 20, "wide tree cost is superlinear again"
        assert not d.exists()

    @staticmethod
    def _nest_deep(base: Path, levels: int = 1200) -> None:
        cwd = os.getcwd()
        try:
            os.chdir(base)
            os.mkdir("deep")
            os.chdir("deep")
            for _ in range(levels):
                os.mkdir("a")
                os.chdir("a")
        finally:
            os.chdir(cwd)

    @pytest.fixture(autouse=True)
    def _no_stranded_trees(self, tmp_path):
        yield
        from blastbox.host.jobs.retention import _rmtree_iterative
        for child in list(tmp_path.iterdir()):
            if child.is_dir() and not child.is_symlink():
                with contextlib.suppress(OSError):
                    _rmtree_iterative(child)

    def test_the_sentinel_survives_a_failed_status_repair(self, tmp_path):
        """Clearing the marker on upload alone stranded the job forever.

        The recovery is two steps: upload the bytes, then CAS FAILED->DONE. If the CAS fails (a
        store blip), the next sweep must still find the tree — but the marker was already gone, so
        it saw ordinary scratch, the fall-through repair could never run, and the job stayed
        FAILED with a durable result and every result route answering 409.
        """
        class CasFails(InMemoryJobStore):
            def update_if_status(self, job_id, expect_status, **kw):
                return False

        store = CasFails()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"result upload failed after 3 attempts; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID)

        retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"))
        assert (d / PENDING_UPLOAD_SENTINEL).is_file(), (
            "the marker was dropped before the repair landed — nothing can retry it now"
        )

    def test_a_sentinel_that_cannot_be_written_is_an_error_not_a_shrug(self, tmp_path, caplog):
        """It is the ONLY durable record that a tree holds the last copy: the in-memory carve-out
        covers just the immediate purge, and once consumed the reclaim treats the tree as ordinary
        scratch. A failure here is pending data loss and has to read like one."""
        from blastbox.host.jobs.retention import mark_pending_upload

        with caplog.at_level(logging.WARNING):
            mark_pending_upload(tmp_path, "no-such-job", logging.getLogger("t"))
        assert any(r.levelno >= logging.ERROR for r in caplog.records), (
            "a failed sentinel write was logged below ERROR"
        )

    def test_a_repaired_job_gets_a_FRESH_retention_clock(self, tmp_path):
        """Recovery must restart the retention clock, not inherit a dead one.

        The row still carried the expires_at that _fail_job computed at the ORIGINAL failure, so
        after any outage longer than job_retention_seconds the repaired job was already past its
        expiry — expire_due would delete the freshly recovered result later in the SAME
        maintenance tick, before any client could fetch it (it was never servable while FAILED).
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"upload failed; {RESULT_RETAINED_MARKER}"
        job.expires_at = time.time() - 10_000          # long past, from the original failure
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"),
                              retention_seconds=3600)
        row = store.get(_JID)
        assert row.status is JobStatus.DONE
        assert row.expires_at > time.time(), "repaired job kept an already-expired retention clock"

    def test_a_failing_post_repair_hook_leaves_a_servable_job_and_says_so(self, tmp_path, caplog):
        """The recovery itself must stand, and the shortfall must be visible.

        Keeping the sentinel here would NOT buy a retry — this sweep only looks at FAILED rows and
        the row is DONE by then — so the honest behaviour is: the result is durable and servable,
        the /similar index and the counts are missing, and that is logged rather than pretended
        away. The clear happens after the hook so a CRASH mid-recovery (as opposed to a handled
        error) still leaves the marker, the tree, and another attempt.
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"upload failed; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID)

        def boom(jid, out, seal):
            raise RuntimeError("indexer down")

        with caplog.at_level(logging.WARNING):
            retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t"),
                                  on_repaired=boom)
        assert store.get(_JID).status is JobStatus.DONE, "the repair itself must stand"
        assert not (d / PENDING_UPLOAD_SENTINEL).exists(), (
            "kept a marker no later tick can act on — a mechanism that does not exist"
        )
        assert any("post-repair indexing failed" in r.message for r in caplog.records), (
            "the shortfall was not reported"
        )

    def test_expiry_never_deletes_a_pending_upload_tree(self, tmp_path):
        """The reclaim spares this tree as the only copy, and the retention sweeper would rmtree
        it a few lines later in the SAME tick — with the operator's own
        BLASTBOX_JOB_RETENTION_SECONDS as the trigger, and the docs promising the opposite.
        Expiry is a RESULT lifecycle policy; it has no business destroying bytes that were never
        durably stored."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"upload failed; {RESULT_RETAINED_MARKER}"
        job.expires_at = time.time() - 10
        job.result_dir = str(tmp_path / _JID / "output")
        store.create(job)
        d = _sealed_tree(tmp_path, _JID)

        JobRetentionSweeper(job_root=tmp_path).expire_due(store)

        assert (d / "output" / "metadata.json").exists(), (
            "retention destroyed the only copy of a host-sealed result"
        )


class TestMarkerOwnership:
    """The marker is written BEFORE the terminal CAS so a crash cannot lose it — which means one
    can outlive an attempt that LOST that CAS. It records the claim it was written under."""

    def test_a_marker_from_a_superseded_attempt_never_publishes_its_bytes(self, tmp_path):
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.claim_id = "the-peer"                      # the row moved on
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID, pending=False)
        (d / PENDING_UPLOAD_SENTINEL).write_text("our-stale-claim")

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "published a superseded attempt's bytes over the owner's"
        assert store.get(_JID).status is JobStatus.FAILED

    def test_a_marker_matching_the_current_claim_is_acted_on(self, tmp_path):
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.claim_id = "ours"
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID, pending=False)
        (d / PENDING_UPLOAD_SENTINEL).write_text("ours")

        assert retry_pending_uploads(tmp_path, _FakeBlobs(), store, logging.getLogger("t")) == 1
        assert store.get(_JID).status is JobStatus.DONE

    def test_a_declared_path_written_with_dot_or_double_slash_still_counts_as_declared(self):
        """Manifest paths are stored verbatim, so './nested/x' or 'nested//x' would not match the
        walker's normalized 'nested/x' — the artifact would look UNDECLARED and an unstorable one
        would be skipped while the seal was still committed."""
        import json as _json
        import tempfile

        from blastbox.host.blobs.base import _declared_paths

        d = Path(tempfile.mkdtemp())
        (d / "metadata.json").write_text(_json.dumps({"artifacts": [
            {"path": "./nested/x.png"}, {"path": "nested//y.png"}, {"path": "plain.png"}]}))
        assert _declared_paths(d) == {"nested/x.png", "nested/y.png", "plain.png"}

    def test_the_last_copy_rule_does_not_depend_on_being_handed_a_blob_store(self, tmp_path):
        """Without a store there is no durable copy to check — which means the tree cannot be
        PROVEN redundant, so it is the last copy by definition.

        The whole protection used to sit inside `if blob_store is not None`, so the DEFAULT
        argument silently disabled it. Every production caller passes a store, so it never bit;
        any new caller would have inherited a sweep that deletes sealed results (found by the
        full-PR sweep).
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID)
        old = time.time() - 99_999
        for pth in sorted(d.rglob("*"), reverse=True) + [d]:
            os.utime(pth, (old, old))

        removed = reap_stale_scratch(tmp_path, 60.0, store, logging.getLogger("t"))  # no store
        assert removed == 0, "deleted a sealed result because no blob store was passed"
        assert (d / "output" / "metadata.json").exists()

    def test_ordinary_scratch_is_still_reclaimed_without_a_blob_store(self, tmp_path):
        """The counterpart: 'cannot prove it is redundant' must not become 'never delete
        anything', or the bound this PR exists to add disappears."""
        store = InMemoryJobStore()
        d = tmp_path / _JID
        (d / "output").mkdir(parents=True)
        (d / "input.bin").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
        old = time.time() - 99_999
        for pth in sorted(d.rglob("*"), reverse=True) + [d]:
            os.utime(pth, (old, old))

        assert reap_stale_scratch(tmp_path, 60.0, store, logging.getLogger("t")) == 1
        assert not d.exists()

    def test_a_claimless_row_does_not_satisfy_a_claim_bound_marker(self, tmp_path):
        """`row.claim_id is None` is not a wildcard — it is a REQUEUED row.

        Our attempt marks under claim A and loses; _requeue_claimed clears the claim; the job
        later fails for an unrelated reason. Accepting the marker then published our superseded
        bytes over that job. Only a marker with no claim recorded at all is matchless-by-design.
        """
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.claim_id = None                                  # requeued since we marked it
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        d = _sealed_tree(tmp_path, _JID, pending=False)
        (d / PENDING_UPLOAD_SENTINEL).write_text("our-stale-claim")

        blobs = _FakeBlobs()
        assert retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t")) == 0
        assert blobs.put_calls == 0, "published a superseded attempt's bytes onto a requeued job"

    def test_a_losing_attempt_cannot_withdraw_the_winners_marker(self, tmp_path):
        """The marker is ONE shared pathname under a job_root two dispatchers share.

        An attempt that lost its CAS used to clear unconditionally, deleting the WINNER's marker —
        leaving the winner's tree unprotected by the last-copy rule and its result invisible to
        the recovery sweep.
        """
        from blastbox.host.jobs.retention import clear_pending_upload, mark_pending_upload

        d = tmp_path / _JID
        d.mkdir()
        mark_pending_upload(tmp_path, _JID, logging.getLogger("t"), "the-winner")

        clear_pending_upload(tmp_path, _JID, "the-loser")     # a superseded attempt withdrawing
        assert (d / PENDING_UPLOAD_SENTINEL).is_file(), "a loser deleted the winner's marker"
        assert (d / PENDING_UPLOAD_SENTINEL).read_text() == "the-winner"

        clear_pending_upload(tmp_path, _JID, "the-winner")    # the owner withdrawing its own
        assert not (d / PENDING_UPLOAD_SENTINEL).exists()

    def test_a_result_uploaded_into_an_expiring_job_is_not_left_orphaned(self, tmp_path):
        """Recovery and retention run in different processes over one store.

        If the row EXPIRES while we are uploading, our seal lands after retention's delete_job and
        the repair CAS then no-ops — leaving a complete result in the store under a row whose
        expires_at was cleared, so nothing will ever select it for deletion and nothing can serve
        it (open_output is DONE-gated). Undo our own write rather than orphan the bytes.
        """
        class ExpiresMidUpload(InMemoryJobStore):
            """FAILED when the sweep looks, EXPIRED by the time the repair CAS runs."""

            expired = False

            def update_if_status(self, job_id, expect_status, **kw):
                type(self).expired = True         # retention won the race
                return False

            def get(self, job_id):
                r = super().get(job_id)
                if r is not None and type(self).expired:
                    r.status = JobStatus.EXPIRED
                return r

        store = ExpiresMidUpload()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED             # ...until retention expires it mid-upload
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)

        class Blobs(_FakeBlobs):
            deleted: list = []

            def delete_job(self, job_id):
                type(self).deleted.append(job_id)
                self.stored.pop(job_id, None)

        blobs = Blobs()
        retry_pending_uploads(tmp_path, blobs, store, logging.getLogger("t"))

        assert _JID in Blobs.deleted, (
            "left a complete result in the store under an expired row that nothing can serve, "
            "select for deletion, or ever revisit"
        )


class TestLegacyMigration:
    """The ending where the disk actually recovers.

    The last-copy rule refuses to delete a DONE job whose result is not in the store — correct,
    since those pre-blob-store jobs have no other copy — but nothing ever uploads them, so on an
    upgraded node they accumulate as trees the sweep can only retain. Measured: ~82k on one fleet
    node, every sweep retaining rather than removing.
    """

    def test_a_legacy_result_becomes_durable_and_then_reclaimable(self, tmp_path):
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.DONE
        store.create(job)
        d = _sealed_tree(tmp_path, _JID, pending=False)
        blobs = _FakeBlobs()

        assert not blobs.has_output(_JID)
        # Before: the reclaim can only retain it.
        old = time.time() - 99_999
        for pth in sorted(d.rglob("*"), reverse=True) + [d]:
            os.utime(pth, (old, old))
        assert reap_stale_scratch(tmp_path, 60.0, store, logging.getLogger("t"),
                                  blob_store=blobs) == 0

        migrated, skipped, failed = migrate_legacy_results(
            tmp_path, blobs, store, logging.getLogger("t"))
        assert (migrated, failed) == (1, 0)
        assert blobs.has_output(_JID), "the legacy result is durable now"

        # After: it is redundant, so the sweep collects it — the disk finally comes back.
        assert reap_stale_scratch(tmp_path, 60.0, store, logging.getLogger("t"),
                                  blob_store=blobs) == 1
        assert not d.exists()

    def test_it_leaves_FAILED_jobs_to_the_recovery_sweep(self, tmp_path):
        """A FAILED job's tree belongs to retry_pending_uploads, which owns the marker and the
        claim fence. Uploading it from here would bypass both."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.FAILED
        job.error = f"x; {RESULT_RETAINED_MARKER}"
        store.create(job)
        _sealed_tree(tmp_path, _JID)
        blobs = _FakeBlobs()

        assert migrate_legacy_results(tmp_path, blobs, store, logging.getLogger("t")) == (0, 0, 0)
        assert blobs.put_calls == 0

    def test_dry_run_touches_nothing(self, tmp_path):
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.DONE
        store.create(job)
        _sealed_tree(tmp_path, _JID, pending=False)
        blobs = _FakeBlobs()

        migrated, _, failed = migrate_legacy_results(
            tmp_path, blobs, store, logging.getLogger("t"), dry_run=True)
        assert (migrated, failed) == (1, 0)
        assert blobs.put_calls == 0, "a dry run wrote to the blob store"
        assert not blobs.has_output(_JID)

    def test_it_does_not_re_upload_what_is_already_durable(self, tmp_path):
        """Re-uploading is not free: this runs over tens of thousands of trees against an object
        store, so a result already in the store must cost one has_output and nothing more —
        otherwise a second run rewrites the entire corpus."""
        store = InMemoryJobStore()
        job = Job.new(engine="redtusk", filename="a.doc")
        job.job_id = _JID
        job.status = JobStatus.DONE
        store.create(job)
        _sealed_tree(tmp_path, _JID, pending=False)
        blobs = _FakeBlobs()
        blobs.stored[_JID] = ["metadata.json"]          # a previous run already migrated it

        migrated, skipped, failed = migrate_legacy_results(
            tmp_path, blobs, store, logging.getLogger("t"))
        assert (migrated, skipped, failed) == (0, 1, 0)
        assert blobs.put_calls == 0, "re-uploaded a result that was already durable"


# --- the age evidence that decides whether a scratch tree may be reaped -------
#
# `reap_stale_scratch` treats a tree as live if any entry's mtime is newer than the
# cutoff, so "how old is this" is the whole decision. Two guards protect it, both
# added from #84/#85 review with the rationale in the source, and neither had a
# test: mutating them (lstat -> stat, and trusting a future mtime) left the entire
# tests/host/jobs suite green.


def _aged_job_tree(root: Path, job_id: str, age_s: float = 99_999.0,
                   *, symlink_to: Path | None = None) -> Path:
    d = root / job_id
    (d / "output").mkdir(parents=True)
    (d / "input.bin").write_bytes(b"x")
    # BEFORE the ageing loop, deliberately: creating an entry updates its parent
    # directory's mtime, so a link added afterwards leaves output/ looking fresh
    # and the tree is held live for a reason that has nothing to do with the link.
    if symlink_to is not None:
        (d / "output" / "link").symlink_to(symlink_to)
    old = time.time() - age_s
    for p in sorted(d.rglob("*"), reverse=True) + [d]:
        with contextlib.suppress(OSError, NotImplementedError):
            os.utime(p, (old, old), follow_symlinks=False)
    return d


def test_a_symlink_to_a_busy_path_cannot_pin_the_tree_alive(tmp_path):
    """The worker owns output/, so it can drop a symlink at a continuously-touched
    path. Dereferencing it borrows that path's fresh mtime and the tree is never
    reclaimed -- #84, on demand, from inside the sandbox.

    `lstat` is what stops it: the link's OWN stamp is the only evidence it gets to
    offer. Measured with the guard reverted to `stat`: reaped=0, tree survives.
    """
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "f").write_text("x")            # freshly created => fresh mtime

    root = tmp_path / "jobs"
    root.mkdir()
    d = _aged_job_tree(root, "11111111-1111-1111-8111-111111111111", symlink_to=busy)

    removed = reap_stale_scratch(root, 60.0, InMemoryJobStore(), logging.getLogger("t"))
    assert removed == 1, "the symlink's target pinned the tree alive"
    assert not d.exists()


def test_an_ordinary_fresh_file_still_keeps_the_tree(tmp_path):
    """The positive control: a genuinely fresh entry must still count as live, or
    the test above would pass with the age check removed altogether."""
    root = tmp_path / "jobs"
    root.mkdir()
    d = _aged_job_tree(root, "22222222-2222-2222-8222-222222222222")
    (d / "output" / "recent.bin").write_bytes(b"y")   # now

    removed = reap_stale_scratch(root, 60.0, InMemoryJobStore(), logging.getLogger("t"))
    assert removed == 0
    assert d.exists()


def test_a_forged_future_mtime_falls_back_to_ctime(tmp_path, monkeypatch):
    """A future mtime must not be taken at face value.

    An mtime years ahead makes a tree look live forever. The guard falls back to
    ctime, which nothing can set: if ctime is sane the mtime was forged, and ctime
    is the honest age.

    The state is crafted rather than written to disk because it cannot be produced
    there -- `os.utime` updates ctime as a side effect, so a file with a FUTURE
    mtime always has a FRESH ctime. Only a stat_result can hold "future mtime, old
    ctime" together, which is exactly the combination the guard is about.
    """
    root = tmp_path / "jobs"
    root.mkdir()
    d = _aged_job_tree(root, "33333333-3333-3333-8333-333333333333")
    forged = d / "input.bin"

    old = time.time() - 99_999
    future = time.time() + 10_000_000
    real_lstat = pathlib.Path.lstat

    def fake_lstat(self, *a, **kw):
        st = real_lstat(self, *a, **kw)
        if self == forged:
            fields = list(st)
            fields[8] = future     # st_mtime: forged
            fields[9] = old        # st_ctime: the honest, old age
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(pathlib.Path, "lstat", fake_lstat)
    removed = reap_stale_scratch(root, 60.0, InMemoryJobStore(), logging.getLogger("t"))
    assert removed == 1, "a forged future mtime pinned the tree alive"
    assert not d.exists()


def test_a_future_mtime_with_a_future_ctime_is_left_alone_and_reported(tmp_path, monkeypatch,
                                                                        caplog):
    """When ctime is ALSO ahead the clock moved, and the tree's age is unknowable.

    Two halves, and the second is the one a mutation caught: the safe answer is to
    leave the tree (deleting on a guess is unrecoverable) AND to say so once. The
    `float("inf")` sentinel is how it gets reported -- returning the future ctime
    instead keeps the tree just the same, so only the missing warning distinguishes
    them, and nothing asserted the warning.
    """
    root = tmp_path / "jobs"
    root.mkdir()
    d = _aged_job_tree(root, "44444444-4444-4444-8444-444444444445")
    odd = d / "input.bin"

    future = time.time() + 10_000_000
    real_lstat = pathlib.Path.lstat

    def fake_lstat(self, *a, **kw):
        st = real_lstat(self, *a, **kw)
        if self == odd:
            fields = list(st)
            fields[8] = fields[9] = future
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(pathlib.Path, "lstat", fake_lstat)
    with caplog.at_level(logging.WARNING, logger="t"):
        removed = reap_stale_scratch(root, 60.0, InMemoryJobStore(), logging.getLogger("t"))
    assert removed == 0, "deleted a tree whose age cannot be established"
    assert d.exists()
    text = " ".join(r.getMessage() for r in caplog.records)
    assert d.name in text and "clock" in text.lower(), text


def test_a_tree_named_in_skip_job_ids_is_spared(tmp_path):
    """`skip_job_ids` is the dispatcher's memory of kills that FAILED: the container
    may still be writing under a live 0o777 bind mount, so the tree is not ours to
    delete yet.

    dispatch.py passes it on every sweep and nothing tested it -- replacing
    `retained = set(skip_job_ids)` with `set()` left the suite green, so the
    parameter could have been dropped in a refactor without a single failure.

    Both directions are asserted, because sparing everything would satisfy half of
    it: the same tree, not named, is still reclaimed.
    """
    root = tmp_path / "jobs"
    root.mkdir()
    spared_id = "55555555-5555-5555-8555-555555555555"
    reaped_id = "66666666-6666-6666-8666-666666666666"
    spared = _aged_job_tree(root, spared_id)
    reaped = _aged_job_tree(root, reaped_id)

    removed = reap_stale_scratch(
        root, 60.0, InMemoryJobStore(), logging.getLogger("t"),
        skip_job_ids=frozenset({spared_id}),
    )

    assert removed == 1, "expected exactly the unnamed tree to go"
    assert spared.exists(), "deleted a tree the dispatcher asked to keep"
    assert not reaped.exists()
