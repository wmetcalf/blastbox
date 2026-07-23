import pytest


@pytest.fixture
def ingress_client_factory(tmp_path):
    """Build the ingress app with an injected BlobStore and an ordering log."""
    from fastapi.testclient import TestClient

    from blastbox.host.ingress.app import build_app
    from blastbox.host.jobs.memory import InMemoryJobStore

    def _factory(blob_store_cls):
        log: list[tuple[str, str]] = []

        class LoggingJobStore(InMemoryJobStore):
            def create(self, job):
                log.append(("job_create", job.job_id))
                return super().create(job)

        app = build_app(
            job_store=LoggingJobStore(),
            job_root=tmp_path,
            blob_store=blob_store_cls(log),
        )
        return TestClient(app), log

    return _factory
