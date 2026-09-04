"""TDD for the app.state.serve_artifact_file helper.

Product ingress extensions (e.g. ClippyShot's typed artifact routes /pdf,
/pages/{idx}.png) serve FIXED relative paths from a job's output, read through the
BlobStore. The core exposes a confined serve helper on app.state so product routers
reuse the same DONE-gate + declared-artifact + traversal/absolute-path containment
protections (Task 7 gap 2: no local disk access at all — the job dir may already be
purged by the time this runs on a real multi-node deployment).
"""

from __future__ import annotations

import json
import shutil

from fastapi import APIRouter, Request
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.ingress.test_app import _make_done_job, _push_to_blob


def _router(route: str, rel: str, **kw):
    r = APIRouter()

    @r.get(route)
    def handler(job_id: str, request: Request):
        return request.app.state.serve_artifact_file(job_id, rel, **kw)

    return r


def _app(tmp_path, store, router):
    # _make_done_job writes output under tmp_path/"jobs"/<id>/output
    return build_app(
        job_store=store,
        job_root=tmp_path / "jobs",
        allowed_engines={"probe"},
        extension=IngressExtension(routers=(router,)),
    )


def test_serves_fixed_artifact_from_done_job(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(
        _app(
            tmp_path,
            store,
            _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png"),
        )
    )
    r = c.get(f"/v1/jobs/{job.job_id}/png")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")


def test_missing_artifact_is_404(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(
        _app(tmp_path, store, _router("/v1/jobs/{job_id}/x", "does-not-exist.pdf"))
    )
    assert c.get(f"/v1/jobs/{job.job_id}/x").status_code == 404


def test_traversal_is_confined(tmp_path):
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store)
    c = TestClient(
        _app(
            tmp_path, store, _router("/v1/jobs/{job_id}/evil", "../../../../etc/passwd")
        )
    )
    assert c.get(f"/v1/jobs/{job.job_id}/evil").status_code == 404


def test_undeclared_file_on_disk_is_404_trust_gate(tmp_path):
    """H-1 regression: a compromised worker that declares a benign manifest yet ALSO drops
    an undeclared file on disk must NOT have it served — only DECLARED (re-hashed) artifacts
    are trustworthy. Without the manifest check this 200s and serves un-re-hashed bytes."""
    store = InMemoryJobStore()
    job, output_dir = _make_done_job(tmp_path, store)  # declares page-001.png only
    # Worker-planted undeclared file (NOT in metadata.json artifacts[]) — exists on disk.
    (output_dir / "document.pdf").write_bytes(
        b"%PDF-1.4 attacker-controlled un-re-hashed bytes"
    )
    c = TestClient(
        _app(
            tmp_path,
            store,
            _router(
                "/v1/jobs/{job_id}/pdf", "document.pdf", media_type="application/pdf"
            ),
        )
    )
    assert c.get(f"/v1/jobs/{job.job_id}/pdf").status_code == 404
    # sanity: the DECLARED artifact still serves
    c2 = TestClient(
        _app(
            tmp_path,
            store,
            _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png"),
        )
    )
    assert c2.get(f"/v1/jobs/{job.job_id}/png").status_code == 200


def test_serves_fixed_artifact_when_job_dir_purged(tmp_path):
    """Task 7 gap 2: after the worker purge, job_root/<id>/ no longer exists on this
    node at all -- serve_artifact_file must still serve a declared artifact by
    reading exclusively through the BlobStore (never FileResponse from disk)."""
    store = InMemoryJobStore()
    job, _ = _make_done_job(tmp_path, store, artifact_data=b"PURGED-PNG-BYTES")
    shutil.rmtree(
        tmp_path / "jobs" / job.job_id
    )  # simulate the worker's post-upload purge
    c = TestClient(
        _app(
            tmp_path,
            store,
            _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png"),
        )
    )
    r = c.get(f"/v1/jobs/{job.job_id}/png")
    assert r.status_code == 200
    assert r.content == b"PURGED-PNG-BYTES"
    assert r.headers["content-type"].startswith("image/png")


def test_non_list_artifacts_manifest_is_404_not_500(tmp_path):
    """Gemini #18: a manifest whose ``artifacts`` is not a list ("artifacts": null / 5 / {})
    must NOT crash the serve route — `for a in meta.get("artifacts", [])` would raise a
    TypeError OUTSIDE the json try/except → 500. _declared_artifact_paths_from_meta fails
    closed to the empty set so the fixed-filename route 404s on the malformed manifest.

    Task 7 gap 2: _serve_artifact_file reads metadata.json through the BlobStore, not
    disk, so each tampered manifest must be re-pushed (``_push_to_blob``) for the route
    to actually see it — an on-disk-only edit is otherwise inert, mirroring
    tests/host/ingress/test_app.py::test_get_artifact_post_seal_disk_tamper_is_inert.
    """
    store = InMemoryJobStore()
    job, output_dir = _make_done_job(tmp_path, store)
    c = TestClient(
        _app(
            tmp_path,
            store,
            _router("/v1/jobs/{job_id}/png", "page-001.png", media_type="image/png"),
        )
    )
    for bad in (None, 5, {"path": "x"}):
        (output_dir / "metadata.json").write_text(json.dumps({"artifacts": bad}))
        _push_to_blob(tmp_path, job.job_id, output_dir)
        assert c.get(f"/v1/jobs/{job.job_id}/png").status_code == 404
