"""TDD for the app.state.serve_artifact_file helper.

Product ingress extensions (e.g. ClippyShot's typed artifact routes /pdf,
/pages/{idx}.png) serve FIXED relative paths from a job's output dir. The core
exposes a confined serve helper on app.state so product routers reuse the same
DONE-gate + resolve()+relative_to() + no-symlink-follow protections.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.ingress.test_app import _make_done_job


def _router(route: str, rel: str, **kw):
    r = APIRouter()

    @r.get(route)
    def handler(job_id: str, request: Request):
        return request.app.state.serve_artifact_file(job_id, rel, **kw)

    return r


def _app(tmp_path, store, router):
    # _make_done_job writes output under tmp_path/"jobs"/<id>/output
    return build_app(
        job_store=store, job_root=tmp_path / "jobs", allowed_engines={"probe"},
        extension=IngressExtension(routers=(router,)),
    )


def test_serves_fixed_artifact_from_done_job(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png")))
    r = c.get(f"/v1/jobs/{job.job_id}/png")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")


def test_missing_artifact_is_404(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/x", "does-not-exist.pdf")))
    assert c.get(f"/v1/jobs/{job.job_id}/x").status_code == 404


def test_traversal_is_confined(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/evil", "../../../../etc/passwd")))
    assert c.get(f"/v1/jobs/{job.job_id}/evil").status_code == 404
