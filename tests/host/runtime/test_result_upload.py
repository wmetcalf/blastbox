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
        self.deleted: list[str] = []
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
    def delete_job(self, job_id):
        self.deleted.append(job_id)


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


def test_upload_failure_after_exhausting_retries_fails_the_job_and_retains_the_result(
    vm_dispatcher_factory, tmp_path,
):
    """Finding D1's contract, half revised (#85).

    STILL TRUE: once every inline attempt fails the job is FAILED, never left RUNNING -- nothing
    re-runs a RUNNING job, so that was only ever a leak.

    CHANGED: D1 also DISCARDED the result, and that was correct at the time -- a retained tree had
    no consumer. It was unreachable bytes (the API serves results from the blob store alone) that
    nothing would ever upload, so keeping it bought nothing and violated the no-bytes-survive
    invariant for free. retry_pending_uploads is that consumer now, so the tree is a PENDING
    UPLOAD: retained, drained by maintenance, then collected by the age reclaim once the durable
    copy lands. Purging here would destroy a host-sealed, trust-gate-passed result that cannot be
    reproduced by re-running -- detonation is not deterministic, and the C2 pcap is MOVED into the
    tree -- turning a transient object-store outage into permanent evidence loss.

    It also ends a split brain: the container Dispatcher already retained, so before this the same
    outage lost the result or not depending purely on which dispatcher claimed the job.
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
    # The result is RETAINED as the only copy -- and it is the sealed output that must survive,
    # not merely the directory.
    assert (tmp_path / job.job_id / "output" / "metadata.json").exists(), (
        "the only copy of a host-sealed result was destroyed by a transient upload failure"
    )
    # Finding S1: the exhaustion path must reap any partial result blob -- else, with the
    # default job_retention_s=0 (expires_at=None), the retention sweeper skips this FAILED
    # job forever and the partial results/<job_id> blob leaks unbounded.
    assert blobs.deleted == [job.job_id]


def test_upload_exhaustion_with_lost_claim_does_not_reap_peer_result(vm_dispatcher_factory, tmp_path):
    """Ultrareview bug_001 (VM path): the exhaustion reap (Finding S1) must be claim-fenced.
    The pre-upload `_claim_is_still_ours` check runs once, BEFORE the retry loop; if a peer
    requeues + re-runs + CAS-commits DONE during the backoff window, its result sits at the
    same results/<job_id> prefix -- an unconditional delete_job on exhaustion would wipe the
    peer's authoritative result while the job store says DONE (every result route then 404s,
    and nothing ever repairs it). On a lost claim, skip the reap: the prefix isn't ours."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "d" * 64
    store.create(job)
    claimed = store.claim_next()

    class PeerWinsDuringRetryBlobs(Blobs):
        """Every put_output attempt fails; the first failure simulates the peer's full
        requeue -> re-run -> upload -> DONE-CAS landing during our retry window."""
        def put_output(self, job_id, out_dir):
            first = self.put_output_calls == 0
            try:
                super().put_output(job_id, out_dir)
            finally:
                if first:
                    store.update(job_id, status=JobStatus.DONE, claim_id="peer-claim-id-not-ours")

    blobs = PeerWinsDuringRetryBlobs(fail_put=True)
    disp = vm_dispatcher_factory(
        store=store, blob_store=blobs, validate_ok=True, put_output_max_attempts=3,
    )
    disp._process(claimed)

    assert blobs.put_output_calls == 3
    assert blobs.deleted == [], "must not reap the peer's authoritative result blob"
    stored = store.get(job.job_id)
    assert stored.status is JobStatus.DONE, "the peer's terminal DONE must survive untouched"
    assert stored.claim_id == "peer-claim-id-not-ours"


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
