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
