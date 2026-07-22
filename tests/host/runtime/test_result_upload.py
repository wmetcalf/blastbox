"""Results are uploaded BEFORE the purge, and a failed upload never discards work.

put_output failure is the mirror image of get_sample failure: the work is already
done and expensive, so retry and leave it for the sweeper — do not throw it away.
"""
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class Blobs:
    def __init__(self, fail_put=False):
        self.fail_put = fail_put
        self.uploaded: list[str] = []
        self.saw_metadata = False
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"x")
    def put_output(self, job_id, out_dir):
        if self.fail_put:
            raise OSError("object store down")
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


def test_upload_failure_leaves_the_job_running_for_the_sweeper(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(fail_put=True), validate_ok=True)
    disp._process(claimed)

    assert store.get(job.job_id).status is JobStatus.RUNNING
    # the job dir (including output/) must NOT have been purged -- the result is un-uploaded,
    # not discarded, and the reclaim sweeper needs it to still be there for a retry.
    assert (tmp_path / job.job_id / "output" / "metadata.json").is_file()


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
