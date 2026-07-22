import time

import pytest

from blastbox.host.jobs.base import Job, JobStatus


@pytest.fixture
def expired_job_factory():
    def _factory(store, sha256="a" * 64):
        job = Job.new(engine="redtusk", filename="a.doc")
        job.input_sha256 = sha256
        job.status = JobStatus.DONE
        job.finished_at = time.time() - 3600
        job.expires_at = time.time() - 60
        store.create(job)
        return job

    return _factory
