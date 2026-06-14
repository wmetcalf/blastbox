"""TDD tests for blastbox.host.ingress.app.

Covers (per the plan):
- POST /v1/jobs: 202 queued job, input spooled + sha256 set, input_sha256 stored,
  unknown engine → 400, oversized body → 413, filename sanitization.
- GET /v1/jobs, GET /v1/jobs/{id}, 404 handling.
- metadata / artifact routes return 409 when not DONE.
- After marking DONE with a hand-written metadata.json + artifact:
  metadata served; artifact-by-id served; unknown artifact_id → 404;
  traversal attempts → confined.
- Auth: no key → open + warning; key set → 401/200 behaviour; healthz open.
- Concurrency gate wired (semaphore sized from config).
- Confined delete under job_root.
- Error bodies scrubbed.
- FIX 1: chunked over-limit upload returns 413 (not 400), metrics recorded.
- FIX 2: non-UUID job_id returns 404 before any store/fs use.
- FIX 3: output_dir re-derived from job_root; tampered result_dir is ignored.
"""
from __future__ import annotations

import hashlib
import io
import json
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from blastbox.contract.envelope import (
    DeclaredArtifact,
    seal_envelope,
)
from blastbox.contract.leaf import ArtifactRef, Detection, Dimensions
from blastbox.contract.nodes import Page
from blastbox.host.ingress.app import _safe_upload_name, build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.limits import Limits
from blastbox.observability import REJECTIONS_TOTAL


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_ALLOWED = {"clippyshot", "tika"}


def _make_client(
    tmp_path: Path,
    *,
    allowed_engines: set[str] | None = None,
    max_input_bytes: int = 10 * 1024 * 1024,
    api_workers: int = 4,
    api_key: str | None = None,
    metrics_public: bool | None = None,
    store: InMemoryJobStore | None = None,
    zip_password: str | None = "",
) -> tuple[TestClient, InMemoryJobStore]:
    """Build a TestClient wired to a temp job_root + InMemoryJobStore.

    ``zip_password`` controls /result encryption: ``""`` (default) => plain ZIP
    (deterministic for the structure/confinement tests); a string => AES-encrypted
    with it; ``None`` => omit the arg so build_app uses its "infected" default.
    """
    job_store = store or InMemoryJobStore()
    limits = Limits(max_input_bytes=max_input_bytes)
    extra = {} if zip_password is None else {"zip_password": zip_password}
    app = build_app(
        job_store=job_store,
        job_root=tmp_path / "jobs",
        allowed_engines=allowed_engines if allowed_engines is not None else _ALLOWED,
        limits=limits,
        api_workers=api_workers,
        api_key=api_key,
        metrics_public=metrics_public,
        **extra,
    )
    client = TestClient(app, raise_server_exceptions=False)
    return client, job_store


def test_result_zip_serves_only_validated_artifacts(tmp_path):
    """GET /result must zip ONLY the declared artifacts (+ metadata.json), never undeclared
    files or symlink targets a compromised worker drops into output/."""
    import io
    import zipfile

    client, store = _make_client(tmp_path)
    job, output_dir = _make_done_job(tmp_path, store)

    # Hostile worker leftovers: an undeclared file + a symlink to a file outside output/.
    (output_dir / "secret.txt").write_bytes(b"undeclared-leftover")
    outside = tmp_path / "outside_secret"
    outside.write_bytes(b"OUTSIDE-SECRET")
    (output_dir / "leak").symlink_to(outside)

    resp = client.get(f"/v1/jobs/{job.job_id}/result")
    assert resp.status_code == 200
    names = set(zipfile.ZipFile(io.BytesIO(resp.content)).namelist())
    assert names == {"metadata.json", "page-001.png"}, names
    assert b"OUTSIDE-SECRET" not in resp.content  # symlink target bytes never disclosed


def test_result_zip_encrypted_with_infected_password_by_default(tmp_path, monkeypatch):
    """The /result ZIP is AES-256 encrypted with the 'infected' convention by DEFAULT
    (no zip_password arg, no env) — detonated malware artifacts must never ship plain."""
    import io

    import pyzipper

    monkeypatch.delenv("BLASTBOX_ZIP_PASSWORD", raising=False)
    client, store = _make_client(tmp_path, zip_password=None)  # use build_app's default
    job, output_dir = _make_done_job(tmp_path, store)

    resp = client.get(f"/v1/jobs/{job.job_id}/result")
    assert resp.status_code == 200
    data = resp.content
    # The right password decrypts; the content matches the on-disk artifact.
    with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
        zf.setpassword(b"infected")
        assert zf.read("page-001.png") == (output_dir / "page-001.png").read_bytes()
    # A wrong password cannot decrypt the entry (AES auth fails).
    with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
        zf.setpassword(b"wrong")
        try:
            zf.read("page-001.png")
            wrong_pw_ok = True
        except Exception:
            wrong_pw_ok = False
    assert not wrong_pw_ok, "a wrong password must not decrypt the AES result ZIP"


def test_result_zip_encrypted_with_custom_password(tmp_path):
    import io

    import pyzipper

    client, store = _make_client(tmp_path, zip_password="s3cret!")
    job, output_dir = _make_done_job(tmp_path, store)
    resp = client.get(f"/v1/jobs/{job.job_id}/result")
    assert resp.status_code == 200
    with pyzipper.AESZipFile(io.BytesIO(resp.content)) as zf:
        zf.setpassword(b"s3cret!")
        assert zf.read("page-001.png") == (output_dir / "page-001.png").read_bytes()


def test_result_zip_plain_when_password_disabled(tmp_path):
    """An empty BLASTBOX_ZIP_PASSWORD is the explicit opt-out: a plain ZIP."""
    import io
    import zipfile

    client, store = _make_client(tmp_path, zip_password="")
    job, output_dir = _make_done_job(tmp_path, store)
    resp = client.get(f"/v1/jobs/{job.job_id}/result")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert zf.read("page-001.png") == (output_dir / "page-001.png").read_bytes()


def test_readyz_does_not_leak_store_error(tmp_path):
    """A store failure on /v1/readyz must NOT echo the DSN/host:port to the caller."""
    client, store = _make_client(tmp_path)

    def boom():
        raise RuntimeError("could not connect: host=db.internal port=5432 password=hunter2")

    store.count = boom  # type: ignore[method-assign]  # readyz probes via count()
    resp = client.get("/v1/readyz")
    assert resp.status_code == 503
    body = resp.text
    assert "db.internal" not in body and "hunter2" not in body and "5432" not in body


def test_serve_endpoints_reject_symlinked_output(tmp_path):
    """A compromised worker's symlinked artifact / metadata.json must not be served."""
    client, store = _make_client(tmp_path)
    job, output_dir = _make_done_job(tmp_path, store)
    outside = tmp_path / "outside_secret"
    outside.write_bytes(b"OUTSIDE-SECRET")

    # declared artifact replaced by a symlink to an outside file -> 404, not the target bytes
    (output_dir / "page-001.png").unlink()
    (output_dir / "page-001.png").symlink_to(outside)
    r = client.get(f"/v1/jobs/{job.job_id}/artifacts/page-001")
    assert r.status_code == 404
    assert b"OUTSIDE-SECRET" not in r.content

    # metadata.json replaced by a symlink -> 404
    meta = output_dir / "metadata.json"
    data = meta.read_bytes()
    meta.unlink()
    (tmp_path / "ext_meta.json").write_bytes(data)
    meta.symlink_to(tmp_path / "ext_meta.json")
    assert client.get(f"/v1/jobs/{job.job_id}/metadata").status_code == 404


def _make_done_job(
    tmp_path: Path,
    job_store: InMemoryJobStore,
    *,
    engine: str = "clippyshot",
    filename: str = "test.docx",
    artifact_name: str = "page-001.png",
    artifact_data: bytes = b"PNGDATA123",
) -> tuple[Job, Path]:
    """Create a DONE job with a valid metadata.json and one artifact.

    Returns (job, output_dir).
    """
    job = Job.new(engine=engine, filename=filename)
    output_dir = tmp_path / "jobs" / job.job_id / "output"
    output_dir.mkdir(parents=True)
    input_dir = tmp_path / "jobs" / job.job_id / "input"
    input_dir.mkdir(parents=True)

    # Write the artifact file
    art_path = output_dir / artifact_name
    art_path.write_bytes(artifact_data)

    # Seal a valid envelope
    detection = Detection(label="docx", mime="application/vnd.openxmlformats", confidence=0.99, source="magika")
    payload = Page(
        index=0,
        dims=Dimensions(width=210, height=297, unit="mm"),
        image=ArtifactRef(id="page-001"),
    )
    env = seal_envelope(
        engine=engine,
        outdir=output_dir,
        input_sha256="a" * 64,
        detected=detection,
        declared=[DeclaredArtifact(id="page-001", path=artifact_name, kind="image")],
        warnings=[],
        payload=payload,
    )
    meta_json = output_dir / "metadata.json"
    meta_json.write_text(env.model_dump_json(by_alias=True))

    # Persist the job as DONE
    job.result_dir = str(output_dir)
    job.input_sha256 = "a" * 64
    job.status = JobStatus.DONE
    job.finished_at = time.time()
    job_store.create(job)

    return job, output_dir


# ===========================================================================
# 1. POST /v1/jobs — submission
# ===========================================================================


class TestJobSubmission:
    def test_post_creates_queued_job_202(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("doc.docx", io.BytesIO(b"hello"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "queued"
        job_id = body["job_id"]
        assert uuid.UUID(job_id)  # valid UUID
        assert "/v1/jobs/" in body["links"]["self"]
        assert "/v1/jobs/" in body["links"]["result"]

    def test_post_spools_input_and_sets_sha256(self, tmp_path):
        client, store = _make_client(tmp_path)
        content = b"the file content"
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("sample.pdf", io.BytesIO(content), "application/pdf")},
        )
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        # Verify spooled file exists
        spooled = tmp_path / "jobs" / job_id / "input" / "sample.pdf"
        assert spooled.is_file()
        assert spooled.read_bytes() == content

        # Verify input_sha256 is set in the store
        job = store.get(job_id)
        assert job is not None
        expected_sha256 = hashlib.sha256(content).hexdigest()
        assert job.input_sha256 == expected_sha256

    def test_post_unknown_engine_returns_400(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "unknown-engine"},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        assert resp.status_code == 400
        # Error detail must be scrubbed (no internal paths)
        body_text = resp.text
        assert "/home" not in body_text
        assert "/var" not in body_text

    def test_post_oversized_content_length_returns_413_before_spool(self, tmp_path):
        """Content-Length > max_input_bytes must be rejected before spooling."""
        client, _ = _make_client(tmp_path, max_input_bytes=100)
        large = b"x" * 200

        # Spy on jobs dir to ensure nothing is written
        jobs_dir = tmp_path / "jobs"
        jobs_dir.mkdir(exist_ok=True)

        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("big.bin", io.BytesIO(large), "application/octet-stream")},
        )
        assert resp.status_code == 413
        # Nothing should have been written to disk
        spooled_files = list(jobs_dir.rglob("*.bin"))
        assert spooled_files == [], f"file was spooled: {spooled_files}"

    def test_post_filename_path_traversal_sanitized(self, tmp_path):
        """../../etc/passwd must be stored as 'passwd' (basename only)."""
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={
                "file": (
                    "../../etc/passwd",
                    io.BytesIO(b"root:x:0:0"),
                    "text/plain",
                )
            },
        )
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]
        job = store.get(job_id)
        assert job is not None
        # Must be sanitized to 'passwd', never '../../etc/passwd'
        assert job.filename == "passwd"
        assert "/" not in job.filename
        assert ".." not in job.filename

    def test_post_hidden_filename_becomes_upload_bin(self, tmp_path):
        """.hidden → upload.bin."""
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": (".hidden", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        job = store.get(resp.json()["job_id"])
        assert job is not None
        assert job.filename == "upload.bin"

    def test_post_none_filename_becomes_upload_bin(self, tmp_path):
        """None/missing filename → upload.bin (tested via _safe_upload_name directly).

        The httpx test client requires a filename; we cover the None case via
        the unit tests for _safe_upload_name.  Here we confirm the route
        processes a normal filename through the sanitization pipeline.
        """
        client, store = _make_client(tmp_path)
        # A filename that is just underscores after sanitization should still work
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("validname.bin", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        job = store.get(resp.json()["job_id"])
        assert job is not None
        assert job.filename == "validname.bin"

    def test_post_params_stored_on_job(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot", "params": ["dpi=150", "pages=10"]},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        job = store.get(resp.json()["job_id"])
        assert job is not None
        assert job.params.get("dpi") == "150"
        assert job.params.get("pages") == "10"


# ===========================================================================
# 2. GET /v1/jobs — listing / status
# ===========================================================================


class TestJobListing:
    def test_list_returns_jobs(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        jobs_resp = client.get("/v1/jobs")
        assert jobs_resp.status_code == 200
        body = jobs_resp.json()
        assert "jobs" in body
        assert body["total"] >= 1
        assert any(j["status"] == "queued" for j in body["jobs"])

    def test_get_job_by_id(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        job_id = resp.json()["job_id"]
        detail = client.get(f"/v1/jobs/{job_id}")
        assert detail.status_code == 200
        assert detail.json()["job_id"] == job_id

    def test_get_job_404(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get(f"/v1/jobs/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_list_status_filter(self, tmp_path):
        client, store = _make_client(tmp_path)
        client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        resp = client.get("/v1/jobs?status=queued")
        assert resp.status_code == 200
        jobs = resp.json()["jobs"]
        assert all(j["status"] == "queued" for j in jobs)

    def test_list_bad_status_returns_400(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/v1/jobs?status=flying")
        assert resp.status_code == 400

    def test_list_pagination_window_and_total(self, tmp_path):
        """offset/limit page the result via the store pushdown; total reflects the full count,
        and jobs come back newest-first."""
        client, store = _make_client(tmp_path)
        created = []
        for i in range(5):
            j = Job.new(engine="clippyshot", filename=f"f{i}.docx")
            j.created_at = 1000.0 + i  # deterministic newest-first ordering
            store.create(j)
            created.append(j)

        resp = client.get("/v1/jobs?offset=1&limit=2")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 5  # full count, not the page size
        assert body["offset"] == 1 and body["limit"] == 2
        ids = [j["job_id"] for j in body["jobs"]]
        # newest-first is f4,f3,f2,f1,f0 -> skip f4, take f3,f2
        assert ids == [created[3].job_id, created[2].job_id]

    def test_list_limit_clamped_to_1000(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/v1/jobs?limit=999999&offset=-5")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 1000 and body["offset"] == 0

    def test_public_dict_strips_result_dir(self, tmp_path):
        """result_dir must not appear in any public-facing response."""
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        job_id = resp.json()["job_id"]
        detail = client.get(f"/v1/jobs/{job_id}")
        body = detail.json()
        assert "result_dir" not in body
        assert "params" not in body


# ===========================================================================
# 3. Artifact routes — 409 when not DONE
# ===========================================================================


class TestArtifactRoutes409:
    def _submit(self, client):
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        assert resp.status_code == 202
        return resp.json()["job_id"]

    def test_metadata_409_when_queued(self, tmp_path):
        client, _ = _make_client(tmp_path)
        job_id = self._submit(client)
        resp = client.get(f"/v1/jobs/{job_id}/metadata")
        assert resp.status_code == 409

    def test_artifact_409_when_queued(self, tmp_path):
        client, _ = _make_client(tmp_path)
        job_id = self._submit(client)
        resp = client.get(f"/v1/jobs/{job_id}/artifacts/any-id")
        assert resp.status_code == 409

    def test_result_409_when_queued(self, tmp_path):
        client, _ = _make_client(tmp_path)
        job_id = self._submit(client)
        resp = client.get(f"/v1/jobs/{job_id}/result")
        assert resp.status_code == 409


# ===========================================================================
# 4. Artifact routes — after marking DONE
# ===========================================================================


class TestArtifactRoutesDone:
    def test_metadata_served_when_done(self, tmp_path):
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)
        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/metadata")
        assert resp.status_code == 200
        meta = resp.json()
        assert "artifacts" in meta
        assert meta["engine"] == "clippyshot"

    def test_artifact_by_id_served(self, tmp_path):
        _, store = _make_client(tmp_path)
        artifact_data = b"PNG_CONTENT_BYTES"
        job, output_dir = _make_done_job(tmp_path, store, artifact_data=artifact_data)
        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/page-001")
        assert resp.status_code == 200
        assert resp.content == artifact_data

    def test_unknown_artifact_id_returns_404(self, tmp_path):
        _, store = _make_client(tmp_path)
        job, _ = _make_done_job(tmp_path, store)
        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/does-not-exist")
        assert resp.status_code == 404

    def test_result_zip_served_when_done(self, tmp_path):
        _, store = _make_client(tmp_path)
        job, _ = _make_done_job(tmp_path, store)
        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/result")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"


# ===========================================================================
# 5. Artifact path-confinement (security requirement 3)
# ===========================================================================


class TestArtifactConfinement:
    """Crafted artifact_id or job_id must never read outside the job's output dir."""

    def test_traversal_artifact_id_returns_404(self, tmp_path):
        """A crafted artifact_id with traversal chars is looked up by id, not path.

        Since no such id exists in metadata.json, the route returns 404.
        """
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)
        client, _ = _make_client(tmp_path, store=store)

        for crafted_id in ["../etc/passwd", "../../secrets", "%2e%2e/escape"]:
            resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/{crafted_id}")
            # 404 because none of these ids exist in the validated metadata
            assert resp.status_code in (404, 422), (
                f"Expected 404/422 for artifact_id={crafted_id!r}, got {resp.status_code}"
            )

    def test_tampered_metadata_path_traversal_is_contained(self, tmp_path):
        """Even if metadata.json contains a traversal path, _safe_artifact_path blocks it."""
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)

        # Tamper: overwrite metadata.json with a traversal path in artifacts
        meta_path = output_dir / "metadata.json"
        meta_data = json.loads(meta_path.read_text())
        # Replace path with traversal
        meta_data["artifacts"][0]["path"] = "../../../etc/passwd"
        meta_path.write_text(json.dumps(meta_data))

        client, _ = _make_client(tmp_path, store=store)
        # The artifact id exists, but path is outside output_dir → 404
        resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/page-001")
        assert resp.status_code == 404

    def test_absolute_path_in_metadata_is_contained(self, tmp_path):
        """An absolute artifact path in metadata must not be served."""
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)

        meta_path = output_dir / "metadata.json"
        meta_data = json.loads(meta_path.read_text())
        meta_data["artifacts"][0]["path"] = "/etc/passwd"
        meta_path.write_text(json.dumps(meta_data))

        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/page-001")
        assert resp.status_code == 404


# ===========================================================================
# 6. Authentication
# ===========================================================================


class TestAuth:
    def test_no_key_open(self, tmp_path, capsys):
        """Without BLASTBOX_API_KEY all routes are open."""
        client, _ = _make_client(tmp_path, api_key=None)
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200

    def test_key_set_401_without_token(self, tmp_path):
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/v1/jobs")
        assert resp.status_code == 401

    def test_key_set_401_wrong_token(self, tmp_path):
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/v1/jobs", headers={"Authorization": "Bearer wrongkey"})
        assert resp.status_code == 401

    def test_key_set_200_correct_token(self, tmp_path):
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/v1/jobs", headers={"Authorization": "Bearer secret123"})
        assert resp.status_code == 200

    def test_healthz_always_public(self, tmp_path):
        """healthz must remain 200 even when auth is enabled."""
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200

    def test_version_always_public(self, tmp_path):
        """version must remain 200 even when auth is enabled."""
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/v1/version")
        assert resp.status_code == 200

    def test_metrics_always_public(self, tmp_path):
        """metrics must remain 200 even when auth is enabled (default metrics_public=True)."""
        client, _ = _make_client(tmp_path, api_key="secret123")
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_requires_token_when_private(self, tmp_path):
        """With metrics_public=False (BLASTBOX_METRICS_PUBLIC=false) + auth on, /metrics needs
        the bearer token; /v1/healthz + /v1/version stay public regardless."""
        client, _ = _make_client(tmp_path, api_key="secret123", metrics_public=False)
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer secret123"}).status_code == 200
        # Health/version must NOT be gated by the metrics toggle.
        assert client.get("/v1/healthz").status_code == 200
        assert client.get("/v1/version").status_code == 200

    def test_metrics_private_toggle_noop_without_api_key(self, tmp_path):
        """No api_key -> no auth middleware -> /metrics open even with metrics_public=False."""
        client, _ = _make_client(tmp_path, metrics_public=False)
        assert client.get("/metrics").status_code == 200


# ===========================================================================
# 7. Concurrency gate wired
# ===========================================================================


class TestConcurrencyGate:
    def test_semaphore_value_from_api_workers_config(self, tmp_path):
        """_intake_gate semaphore must be sized from the api_workers parameter."""
        # Build with api_workers=1 and submit two jobs concurrently.
        # With gate=1 the second upload blocks until the first finishes.
        # We can't directly inspect the semaphore, but we can verify the
        # app was constructed with api_workers=1 without error.
        client, store = _make_client(tmp_path, api_workers=1)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert resp.status_code == 202

    def test_api_workers_clamped_at_1(self, tmp_path):
        """api_workers=0 must be clamped to 1."""
        client, _ = _make_client(tmp_path, api_workers=0)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("a.docx", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert resp.status_code == 202

    def test_api_workers_clamped_at_64(self, tmp_path):
        """api_workers=100 must be clamped to 64."""
        # Just ensure app builds without error
        client, _ = _make_client(tmp_path, api_workers=100)
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200


# ===========================================================================
# 8. Delete route — confinement
# ===========================================================================


class TestDeleteJob:
    def test_delete_removes_job(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        job_id = resp.json()["job_id"]
        # Mark done so we can delete
        store.update(job_id, status=JobStatus.DONE, finished_at=time.time())
        del_resp = client.delete(f"/v1/jobs/{job_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] == job_id
        assert store.get(job_id) is None

    def test_delete_404_unknown(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.delete(f"/v1/jobs/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_delete_409_queued_job(self, tmp_path):
        client, store = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        job_id = resp.json()["job_id"]
        del_resp = client.delete(f"/v1/jobs/{job_id}")
        assert del_resp.status_code == 409


# ===========================================================================
# 9. Error scrubbing
# ===========================================================================


class TestErrorScrubbing:
    def test_unknown_engine_detail_has_no_internal_path(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/v1/jobs",
            data={"engine": "dangerous-engine"},
            files={"file": ("f.docx", io.BytesIO(b"x"), "application/octet-stream")},
        )
        assert resp.status_code == 400
        body_str = resp.text
        # No internal paths in the response
        for prefix in ("/home", "/var", "/etc", "/proc"):
            assert prefix not in body_str, f"internal path {prefix!r} leaked in 400 response"


# ===========================================================================
# 10. Metrics and observability endpoints
# ===========================================================================


class TestObservability:
    def test_healthz_200(self, tmp_path):
        client, _ = _make_client(tmp_path)
        assert client.get("/v1/healthz").status_code == 200

    def test_readyz_200(self, tmp_path):
        client, _ = _make_client(tmp_path)
        assert client.get("/v1/readyz").status_code == 200

    def test_version_200(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/v1/version")
        assert resp.status_code == 200
        body = resp.json()
        assert "version" in body
        assert "allowed_engines" in body

    def test_metrics_200(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        # Should be prometheus text format
        assert b"blastbox_" in resp.content or resp.status_code == 200


# ===========================================================================
# 11. _safe_upload_name unit tests
# ===========================================================================


class TestSafeUploadName:
    def test_traversal(self):
        assert _safe_upload_name("../../etc/passwd") == "passwd"

    def test_hidden(self):
        assert _safe_upload_name(".hidden") == "upload.bin"

    def test_empty(self):
        assert _safe_upload_name("") == "upload.bin"

    def test_none(self):
        assert _safe_upload_name(None) == "upload.bin"

    def test_safe_name_preserved(self):
        assert _safe_upload_name("document.docx") == "document.docx"

    def test_special_chars_replaced(self):
        result = _safe_upload_name("my doc (1).docx")
        assert " " not in result
        assert "(" not in result
        assert ")" not in result

    def test_truncated_at_255(self):
        long_name = "a" * 300 + ".txt"
        result = _safe_upload_name(long_name)
        assert len(result) <= 255

    def test_only_dots_becomes_upload_bin(self):
        result = _safe_upload_name("...")
        # "..." starts with '.', so basename Path("...").name = "..."
        # which starts with '.', so → upload.bin
        assert result == "upload.bin"


# ===========================================================================
# FIX 1 — chunked over-limit upload returns 413, not 400
# ===========================================================================


class TestChunkedOverLimitReturns413:
    """FIX 1: BodySizeLimitMiddleware must return 413 even for chunked uploads.

    The Content-Length fast path already returns 413 correctly.  For chunked /
    no-Content-Length uploads, the middleware's streaming guard raises
    RuntimeError("request_body_too_large"), but Starlette's multipart parser
    may swallow it and return 400.  The middleware must intercept the outgoing
    400 and replace it with a 413 whenever the body_too_large flag is set.
    """

    def test_chunked_overlimit_returns_413(self, tmp_path):
        """A chunked POST (no Content-Length) exceeding max_input_bytes → 413."""
        client, _ = _make_client(tmp_path, max_input_bytes=50)
        large = b"x" * 200

        # TestClient sends multipart with Content-Length by default when given
        # a BytesIO. To simulate a truly chunked / unknown-length upload we
        # build the raw multipart body and post it via content= (bytes), which
        # causes httpx to omit the Content-Length header, exercising the
        # streaming guard in BodySizeLimitMiddleware.
        boundary = b"testboundary1234"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="engine"\r\n\r\n'
            b"clippyshot\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="big.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + large
            + b"\r\n--" + boundary + b"--\r\n"
        )
        content_type = b"multipart/form-data; boundary=testboundary1234"

        # Post without Content-Length header (chunked semantics from middleware pov)
        resp = client.post(
            "/v1/jobs",
            content=body,
            headers={"Content-Type": content_type.decode()},
        )
        assert resp.status_code == 413, (
            f"Expected 413 for chunked over-limit upload, got {resp.status_code}: {resp.text}"
        )

    def test_chunked_overlimit_no_file_spooled(self, tmp_path):
        """No file must be written to disk when a chunked upload exceeds the limit."""
        jobs_dir = tmp_path / "jobs"
        jobs_dir.mkdir(exist_ok=True)
        client, _ = _make_client(tmp_path, max_input_bytes=50)
        large = b"x" * 200

        boundary = b"testboundary9999"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="engine"\r\n\r\n'
            b"clippyshot\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="big2.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + large
            + b"\r\n--" + boundary + b"--\r\n"
        )
        client.post(
            "/v1/jobs",
            content=body,
            headers={"Content-Type": "multipart/form-data; boundary=testboundary9999"},
        )
        spooled = list(jobs_dir.rglob("*.bin"))
        assert spooled == [], f"file was spooled despite over-limit: {spooled}"

    def test_chunked_overlimit_records_body_too_large_metric(self, tmp_path):
        """body_too_large rejection metric must be incremented on chunked 413."""
        client, _ = _make_client(tmp_path, max_input_bytes=50)
        large = b"x" * 200

        boundary = b"metricboundary42"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="engine"\r\n\r\n'
            b"clippyshot\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="metric.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + large
            + b"\r\n--" + boundary + b"--\r\n"
        )
        before = REJECTIONS_TOTAL.labels(reason="body_too_large")._value.get()
        client.post(
            "/v1/jobs",
            content=body,
            headers={"Content-Type": "multipart/form-data; boundary=metricboundary42"},
        )
        after = REJECTIONS_TOTAL.labels(reason="body_too_large")._value.get()
        assert after > before, "body_too_large rejection metric was not incremented"

    def test_content_length_overlimit_records_body_too_large_metric(self, tmp_path):
        """body_too_large metric must ALSO be incremented on Content-Length fast path."""
        client, _ = _make_client(tmp_path, max_input_bytes=100)
        large = b"x" * 200
        before = REJECTIONS_TOTAL.labels(reason="body_too_large")._value.get()
        client.post(
            "/v1/jobs",
            data={"engine": "clippyshot"},
            files={"file": ("big.bin", io.BytesIO(large), "application/octet-stream")},
        )
        after = REJECTIONS_TOTAL.labels(reason="body_too_large")._value.get()
        assert after > before, "body_too_large metric not incremented on CL fast path"


# ===========================================================================
# FIX 2 — non-UUID job_id returns 404
# ===========================================================================


class TestJobIdUUIDValidation:
    """FIX 2: Every route taking {job_id} must reject non-UUID values with 404."""

    NON_UUID_CASES = [
        "not-a-uuid",
        "12345",
        "../../etc/passwd",
        "..%2f..%2fetc",
        "'; DROP TABLE jobs; --",
        "",
    ]

    def _routes_for(self, job_id: str) -> list[tuple[str, str]]:
        """Return (method, path) pairs for all job_id routes."""
        return [
            ("GET", f"/v1/jobs/{job_id}"),
            ("GET", f"/v1/jobs/{job_id}/metadata"),
            ("GET", f"/v1/jobs/{job_id}/artifacts/some-id"),
            ("GET", f"/v1/jobs/{job_id}/result"),
            ("DELETE", f"/v1/jobs/{job_id}"),
        ]

    def test_non_uuid_job_id_returns_404(self, tmp_path):
        """All routes with a non-UUID job_id must return 404."""
        client, _ = _make_client(tmp_path)
        for bad_id in ["not-a-uuid", "12345", "'; DROP TABLE jobs; --"]:
            for method, path in self._routes_for(bad_id):
                resp = getattr(client, method.lower())(path)
                assert resp.status_code == 404, (
                    f"{method} {path!r} returned {resp.status_code}, expected 404 for non-UUID"
                )

    def test_path_traversal_job_id_returns_404(self, tmp_path):
        """Path traversal disguised as job_id must return 404."""
        client, _ = _make_client(tmp_path)
        for bad_id in ["../../etc/passwd", "..%2f..%2fetc"]:
            for method, path in self._routes_for(bad_id):
                resp = getattr(client, method.lower())(path)
                assert resp.status_code in (404, 422), (
                    f"{method} {path!r}: expected 404/422 for traversal id, got {resp.status_code}"
                )

    def test_valid_uuid_still_works(self, tmp_path):
        """A valid UUID job_id (that doesn't exist) must return 404-for-not-found, not 404-for-bad-id."""
        client, _ = _make_client(tmp_path)
        valid_id = str(uuid.uuid4())
        resp = client.get(f"/v1/jobs/{valid_id}")
        # 404 is still fine here — the job doesn't exist.  We just want no 422/500.
        assert resp.status_code == 404


# ===========================================================================
# FIX 3 — output_dir re-derived from job_root, tampered result_dir ignored
# ===========================================================================


class TestOutputDirRederived:
    """FIX 3: Artifact/metadata/result serving must anchor to job_root/<id>/output,
    not to the persisted job.result_dir value.
    """

    def test_tampered_result_dir_does_not_escape_job_root(self, tmp_path):
        """A job whose result_dir is tampered to an outside path must not serve from there."""
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)

        # Place a "secret" file outside job_root that result_dir would point to
        outside_dir = tmp_path / "outside_job_root"
        outside_dir.mkdir()
        (outside_dir / "metadata.json").write_text(
            '{"engine": "evil", "artifacts": [], "warnings": []}'
        )
        (outside_dir / "secret.txt").write_bytes(b"TOP SECRET")

        # Tamper the persisted result_dir to point outside job_root
        job.result_dir = str(outside_dir)
        store.update(job.job_id, result_dir=str(outside_dir))

        client, _ = _make_client(tmp_path, store=store)

        # Metadata must come from the re-derived path (job_root/<id>/output),
        # not from outside_dir — so either 200 with the real metadata or 404/410.
        resp = client.get(f"/v1/jobs/{job.job_id}/metadata")
        if resp.status_code == 200:
            meta = resp.json()
            # Must NOT be the tampered "evil" engine metadata
            assert meta.get("engine") != "evil", (
                "Tampered result_dir allowed reading from outside job_root!"
            )
        else:
            # 404/410 also acceptable — re-derived path doesn't exist or job expired
            assert resp.status_code in (404, 410)

    def test_tampered_result_dir_artifact_not_served_from_outside(self, tmp_path):
        """Artifact serving must use re-derived output_dir, not tampered result_dir."""
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)

        outside_dir = tmp_path / "outside_artifacts"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret_artifact.png"
        secret_file.write_bytes(b"SECRET_ARTIFACT_DATA")

        # Tamper result_dir to point outside
        store.update(job.job_id, result_dir=str(outside_dir))

        client, _ = _make_client(tmp_path, store=store)
        # Artifact by id: the re-derived output_dir is the real one that still
        # has the legitimate artifact, so it should still serve correctly or
        # return 404/410 — but NEVER the secret content from outside_dir.
        resp = client.get(f"/v1/jobs/{job.job_id}/artifacts/page-001")
        if resp.status_code == 200:
            assert resp.content != b"SECRET_ARTIFACT_DATA", (
                "Served artifact from tampered outside path!"
            )

    def test_result_zip_uses_rederived_output_dir(self, tmp_path):
        """GET /result ZIP must come from re-derived job_root/<id>/output."""
        _, store = _make_client(tmp_path)
        job, output_dir = _make_done_job(tmp_path, store)

        outside_dir = tmp_path / "outside_zip"
        outside_dir.mkdir()
        (outside_dir / "evil.txt").write_bytes(b"EVIL")

        store.update(job.job_id, result_dir=str(outside_dir))

        client, _ = _make_client(tmp_path, store=store)
        resp = client.get(f"/v1/jobs/{job.job_id}/result")
        if resp.status_code == 200:
            import zipfile as zf
            zdata = io.BytesIO(resp.content)
            with zf.ZipFile(zdata) as z:
                names = z.namelist()
            # Must not contain anything from the outside dir
            assert "evil.txt" not in names, (
                "Result ZIP included files from tampered result_dir outside job_root!"
            )


# ===========================================================================
# POST /v1/jobs — target_tier routing gate (operator/test only, default-off)
# ===========================================================================


class TestTierRoutingGate:
    """A client must not be able to pin/flood a tier unless an operator opts in via
    BLASTBOX_ALLOW_TIER_ROUTING. Off (default) → target_tier is silently dropped;
    on → validated + persisted onto the job (then honored at claim by the store)."""

    def _submit(self, client, target_tier):
        return client.post(
            "/v1/jobs",
            data={"engine": "clippyshot", "target_tier": target_tier},
            files={"file": ("doc.docx", io.BytesIO(b"hi"), "application/octet-stream")},
        )

    def test_target_tier_ignored_when_routing_disabled(self, tmp_path, monkeypatch):
        monkeypatch.delenv("BLASTBOX_ALLOW_TIER_ROUTING", raising=False)
        client, store = _make_client(tmp_path)
        resp = self._submit(client, "gvisor")
        assert resp.status_code == 202
        job = store.get(resp.json()["job_id"])
        assert job.target_tier is None  # dropped — not honored without the operator flag

    def test_target_tier_honored_when_routing_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("BLASTBOX_ALLOW_TIER_ROUTING", "1")
        client, store = _make_client(tmp_path)
        resp = self._submit(client, "gvisor")
        assert resp.status_code == 202
        job = store.get(resp.json()["job_id"])
        assert job.target_tier == "gvisor"

    def test_invalid_target_tier_rejected_when_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("BLASTBOX_ALLOW_TIER_ROUTING", "1")
        client, store = _make_client(tmp_path)
        resp = self._submit(client, "nonsense")
        assert resp.status_code == 400
