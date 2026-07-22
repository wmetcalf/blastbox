"""Results are uploaded BEFORE the purge, and a failed upload gets a bounded
inline retry — then the job FAILS and cleans up like every other terminal path.

Finding D1: an earlier version of this file asserted the OPPOSITE contract — that
a put_output failure should leave the job RUNNING "for the sweeper", preserving
its job dir "for a retry". That was the bug: nothing ever re-runs a RUNNING job
(there is no consumer for a "preserved" result), and the orphan-recovery path
that eventually FAILs an abandoned RUNNING job unlinks only the INPUT file, not
the output dir — with the default job_retention_s=0 the resulting FAILED job's
expires_at is None, which retention.expire_due skips forever. So the "preserved"
directory was never cleaned up AND the "preserved" result was never used: pure
loss on both sides of the trade the old contract claimed to make. The fix is a
bounded inline retry (a transient blip gets a real chance to succeed while this
worker still holds the claim and the output dir exists), and on exhaustion an
unconditional FAIL + purge — the same shape as every other terminal path.
"""
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class Blobs:
    def __init__(self, fail_put=False, fail_times=None):
        # fail_put=True: every attempt fails. fail_times=N: the first N attempts
        # fail, then it succeeds (models a transient blip that clears up).
        self.fail_put = fail_put
        self.fail_times = fail_times
        self.put_output_calls = 0
        self.uploaded: list[str] = []
        self.saw_metadata = False
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"x")
    def put_output(self, job_id, out_dir):
        self.put_output_calls += 1
        if self.fail_put or (self.fail_times is not None and self.put_output_calls <= self.fail_times):
            raise OSError(f"object store down (attempt {self.put_output_calls})")
        self.saw_metadata = (out_dir / "metadata.json").is_file()
        self.uploaded.append(job_id)
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_output_uploaded_before_purge(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "a" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = Blobs()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp._process(claimed)

    assert blobs.uploaded == [job.job_id]
    assert blobs.saw_metadata, "output must still exist when put_output runs"
    assert not (tmp_path / job.job_id).exists(), "purge must follow the upload"
    assert store.get(job.job_id).status is JobStatus.DONE


def test_upload_retries_inline_and_recovers_from_a_transient_failure(vm_dispatcher_factory, tmp_path):
    """A blip that clears up within the retry budget must still produce a normal
    DONE — the retry is supposed to be invisible to the job's outcome."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = Blobs(fail_times=2)  # fails twice, then succeeds -- within a 3-attempt budget
    disp = vm_dispatcher_factory(
        store=store, blob_store=blobs, validate_ok=True, put_output_max_attempts=3,
    )
    disp._process(claimed)

    assert blobs.put_output_calls == 3
    assert blobs.uploaded == [job.job_id]
    assert store.get(job.job_id).status is JobStatus.DONE
    assert not (tmp_path / job.job_id).exists(), "purge must still run on the recovered success path"


def test_upload_failure_after_exhausting_retries_fails_the_job_and_purges(vm_dispatcher_factory, tmp_path):
    """Finding D1's replacement contract: once every inline attempt fails, the
    upload is treated as failed -- FAIL the job (never leave it RUNNING) and let
    the unconditional purge run (never leave a leftover output dir "for later").
    """
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = Blobs(fail_put=True)
    disp = vm_dispatcher_factory(
        store=store, blob_store=blobs, validate_ok=True, put_output_max_attempts=3,
    )
    disp._process(claimed)

    assert blobs.put_output_calls == 3, "must exhaust the bounded retry budget, not give up early"
    final = store.get(job.job_id)
    assert final.status is JobStatus.FAILED, "must not be left RUNNING -- there is no consumer for that"
    assert "upload failed" in (final.error or "").lower()
    # the cleanup invariant holds on every terminal path -- no leftover output dir survives.
    assert not (tmp_path / job.job_id).exists(), "job dir (input AND output) must be purged, not preserved"


def test_reclaimed_claim_skips_upload_instead_of_clobbering_peer_result(vm_dispatcher_factory, tmp_path):
    """Regression for the TOCTOU in the finding: put_output writes to a deterministic per-job key
    that is a per-file overwrite/union, not a claim-fenced atomic swap. If our claim is reclaimed
    (sweeper) DURING the window between the last ownership check and the upload -- here simulated
    by a peer's CAS landing right after `_ensure_metadata` runs, before this worker's put_output --
    a peer could already have re-detonated, uploaded ITS result, and CAS-committed DONE. This
    worker must NOT then upload its own (possibly divergent -- detonation isn't deterministic
    run-to-run) bytes over the peer's already-correct result. Assert the fence actually gates the
    call: put_output must never be invoked once ownership is lost.
    """
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "c" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = Blobs()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)

    # Simulate a peer reclaiming the job in the gap right after `_ensure_metadata` writes
    # output/metadata.json but before the dispatcher re-checks ownership for the upload: flip
    # claim_id in the store out from under this worker's in-hand `claimed` snapshot, exactly as
    # a peer's `claim_next()` (after the sweeper requeued it) would.
    real_ensure_metadata = disp._ensure_metadata

    def _ensure_metadata_then_peer_reclaims(job_arg, summary):
        ok = real_ensure_metadata(job_arg, summary)
        store.update(job_arg.job_id, claim_id="peer-claim-id-not-ours")
        return ok

    disp._ensure_metadata = _ensure_metadata_then_peer_reclaims  # type: ignore[method-assign]

    disp._process(claimed)

    # The fence must have gated the write: put_output was never called with the stale bytes.
    assert blobs.uploaded == []
    # This worker did not win any terminal CAS (claim_id no longer matches) -- the job is left
    # exactly as the peer's own claim/state has it (still RUNNING, under the peer's claim_id),
    # not clobbered by our stale terminal write.
    stored = store.get(job.job_id)
    assert stored.status is JobStatus.RUNNING
    assert stored.claim_id == "peer-claim-id-not-ours"
    # Our local copy must be purged -- nothing may survive on this worker's disk once we're no
    # longer the owner (same invariant as the other lost-claim paths in this method).
    assert not (tmp_path / job.job_id).exists()
