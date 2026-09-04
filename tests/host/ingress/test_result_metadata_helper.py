"""TDD for the app.state.load_result_metadata helper.

Not everything a product needs to serve is an ARTIFACT. `serve_artifact_file`
requires the path to be a DECLARED artifact -- correctly, since undeclared bytes
were never re-hashed by the trust gate -- so a product that embeds a document in
the ENVELOPE had no way to read it back.

Measured cost of that gap: RedTusk moved its rmeta document into the envelope
and stopped declaring the artifact, but its `/v1/jobs/{id}/rmeta` route still
asked for the file. Every completed job 404'd on the documented retrieval route
while the data sat in the envelope, intact.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.ingress.test_app import _make_done_job


def _router():
    r = APIRouter()

    @r.get("/v1/jobs/{job_id}/envelope")
    def handler(job_id: str, request: Request):
        return request.app.state.load_result_metadata(job_id)

    return r


def _app(tmp_path, store):
    return build_app(
        job_store=store,
        job_root=tmp_path / "jobs",
        allowed_engines={"probe"},
        extension=IngressExtension(routers=(_router(),)),
    )


def test_the_sealed_envelope_is_readable_by_a_product_route(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store))
    r = c.get(f"/v1/jobs/{job.job_id}/envelope")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "artifacts" in body or "payload" in body, body


def test_an_unknown_job_is_404(tmp_path):
    store = InMemoryJobStore()
    _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store))
    assert (
        c.get("/v1/jobs/00000000-0000-4000-8000-000000000000/envelope").status_code
        == 404
    )


def test_a_malformed_job_id_does_not_reach_the_store(tmp_path):
    """The same id validation the artifact routes apply.

    Asserting on the STATUS proves nothing here: an unknown job is 404 from the
    store lookup too, so the code is identical whether the id was validated or
    not. The property that matters is the one the guard exists for -- nothing
    malformed reaches the store or the filesystem -- so that is what is checked.
    """
    store = InMemoryJobStore()
    _make_done_job(tmp_path, store)
    seen: list[str] = []
    real_get = store.get

    def recording_get(job_id):
        seen.append(job_id)
        return real_get(job_id)

    store.get = recording_get  # type: ignore[method-assign]
    c = TestClient(_app(tmp_path, store))
    assert c.get("/v1/jobs/not-a-uuid/envelope").status_code == 404
    assert seen == [], f"a malformed id reached the store: {seen}"


def test_a_job_that_is_not_done_is_not_served(tmp_path):
    """The envelope is only sealed once the job is DONE.

    Serving it earlier would hand out a manifest the trust gate has not
    finished with -- the same reason the artifact routes are DONE-gated.
    """
    from blastbox.host.jobs.base import JobStatus

    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    store.update(job.job_id, status=JobStatus.RUNNING)
    c = TestClient(_app(tmp_path, store))
    assert c.get(f"/v1/jobs/{job.job_id}/envelope").status_code == 409
