"""Finding P1, end-to-end: the classic (file dispatch-style) Dispatcher is what
`cli.py` builds for EVERY local runtime (cold, docker, firecracker, gvisor) --
the standard local deployment. With BLASTBOX_BLOB_URL unset (LocalBlobStore,
the default), a job the Dispatcher finishes must be servable through the same
API routes that ALL result reads now go through exclusively
(ingress/app.py: get_metadata / get_result read only via BlobStore.open_output).

Before the fix, the Dispatcher never called put_output, so a finished job's
bytes sat at job_root/<id>/output while the API looked for
<blob_root>/results/<id>/metadata.json -- which was never written. Every result
route 404'd (open_output raises -> caught -> 404) in the default local mode.
This test drives the REAL Dispatcher.dispatch_once() to a DONE completion with
a real LocalBlobStore (no mocked blob store), then hits the FastAPI routes
through TestClient and asserts they serve the result.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.docker import RuntimeSelection
from blastbox.limits import Limits

_ENGINE_NAME = "test-engine"
_ENGINE_IMAGE = "registry.example.com/test-worker:latest"
_INPUT_SHA = "a" * 64


def _fake_runtime() -> RuntimeSelection:
    return RuntimeSelection(runtime="runc", secure=False, warnings=["no runsc"])


def _write_valid_output_dir(
    output_dir: Path, *, artifact_content: bytes = b"PNG_DATA"
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "page-001.png"
    artifact_path.write_bytes(artifact_content)
    real_sha = hashlib.sha256(artifact_content).hexdigest()
    envelope = {
        "engine": _ENGINE_NAME,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {
            "label": "docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "confidence": 0.99,
            "source": "magika",
        },
        "artifacts": [
            {
                "id": "page-001",
                "path": "page-001.png",
                "kind": "image",
                "sha256": real_sha,
                "bytes": len(artifact_content),
            }
        ],
        "warnings": [],
        "payload": {"_type": "extracted_text", "text": "hello world", "char_count": 11},
    }
    (output_dir / "metadata.json").write_bytes(json.dumps(envelope).encode())


def test_classic_dispatcher_result_is_served_by_the_api_through_the_blob_store(
    tmp_path,
):
    job_root = tmp_path / "jobs"
    job_root.mkdir()

    # The SAME store, job_root, and blob store the Dispatcher and the ingress API
    # would share in a real single-node deployment (mode 1: two processes, one
    # sqlite/shared store, BLASTBOX_BLOB_URL unset -> LocalBlobStore).
    store = InMemoryJobStore()
    blob_store = LocalBlobStore(job_root)  # default blob_root: a `blobs` sibling dir

    job = Job.new(engine=_ENGINE_NAME, filename="malware.docx")
    job.input_sha256 = _INPUT_SHA
    store.create(job)

    # Spool the job dir the way ingress would.
    input_dir = job_root / job.job_id / "input"
    output_dir = job_root / job.job_id / "output"
    input_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    (input_dir / "malware.docx").write_bytes(b"malware-bytes")

    def fake_runner(argv, **kw):
        _write_valid_output_dir(output_dir)
        return subprocess.CompletedProcess(argv, 0, "", "")

    dispatcher = Dispatcher(
        job_store=store,
        engines={
            _ENGINE_NAME: EngineSpec(
                name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"]
            )
        },
        limits=Limits(),
        job_root=job_root,
        runtime_selector=_fake_runtime,
        subprocess_runner=fake_runner,
        blob_store=blob_store,
    )
    assert dispatcher.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE

    # put_output must have actually populated the blob store's results dir --
    # the concrete symptom in the finding.
    results_metadata = blob_store._blob_root / "results" / job.job_id / "metadata.json"
    assert results_metadata.is_file(), (
        "put_output must have written the result under blob_root"
    )

    # Disable the default "infected" ZIP password (BLASTBOX_ZIP_PASSWORD) -- this test is
    # about the blob-store wiring (Finding P1), not the malware-safe-transport encryption.
    app = build_app(
        job_store=store, job_root=job_root, blob_store=blob_store, zip_password=""
    )
    client = TestClient(app)

    meta_resp = client.get(f"/v1/jobs/{job.job_id}/metadata")
    assert meta_resp.status_code == 200, meta_resp.text
    assert meta_resp.json()["status"] == "ok"

    result_resp = client.get(f"/v1/jobs/{job.job_id}/result")
    assert result_resp.status_code == 200, result_resp.text
    assert result_resp.headers["content-type"] == "application/zip"

    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(result_resp.content)) as zf:
        names = set(zf.namelist())
        assert "metadata.json" in names
        assert "page-001.png" in names
        assert zf.read("page-001.png") == b"PNG_DATA"
