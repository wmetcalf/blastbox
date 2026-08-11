"""Tests for retention sweeper."""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

import pytest


from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import (
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


def _sealed_tree(root: Path, job_id: str) -> Path:
    d = root / job_id
    (d / "output").mkdir(parents=True)
    (d / "output" / "metadata.json").write_text('{"sealed": true}')
    (d / "output" / "rmeta.json").write_text("[]")
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
