"""TDD for the app.state.serve_artifact_file helper.

Product ingress extensions (e.g. ClippyShot's typed artifact routes /pdf,
/pages/{idx}.png) serve FIXED relative paths from a job's output dir. The core
exposes a confined serve helper on app.state so product routers reuse the same
DONE-gate + resolve()+relative_to() + no-symlink-follow protections.
"""
from __future__ import annotations

import json

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


def test_undeclared_file_on_disk_is_404_trust_gate(tmp_path):
    """H-1 regression: a compromised worker that declares a benign manifest yet ALSO drops
    an undeclared file on disk must NOT have it served — only DECLARED (re-hashed) artifacts
    are trustworthy. Without the manifest check this 200s and serves un-re-hashed bytes."""
    store = InMemoryJobStore()
    job, output_dir = _make_done_job(tmp_path, store)  # declares page-001.png only
    # Worker-planted undeclared file (NOT in metadata.json artifacts[]) — exists on disk.
    (output_dir / "document.pdf").write_bytes(b"%PDF-1.4 attacker-controlled un-re-hashed bytes")
    c = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/pdf", "document.pdf", media_type="application/pdf")))
    assert c.get(f"/v1/jobs/{job.job_id}/pdf").status_code == 404
    # sanity: the DECLARED artifact still serves
    c2 = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png")))
    assert c2.get(f"/v1/jobs/{job.job_id}/png").status_code == 200


def test_non_list_artifacts_manifest_is_404_not_500(tmp_path):
    """Gemini #18: a manifest whose ``artifacts`` is not a list ("artifacts": null / 5 / {})
    must NOT crash the serve route — `for a in meta.get("artifacts", [])` would raise a
    TypeError OUTSIDE the json try/except → 500. _declared_artifact_paths fails closed to the
    empty set so the fixed-filename route 404s on the malformed manifest."""
    store = InMemoryJobStore()
    job, output_dir = _make_done_job(tmp_path, store)
    c = TestClient(_app(tmp_path, store, _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png")))
    for bad in (None, 5, {"path": "x"}):
        (output_dir / "metadata.json").write_text(json.dumps({"artifacts": bad}))
        assert c.get(f"/v1/jobs/{job.job_id}/png").status_code == 404
