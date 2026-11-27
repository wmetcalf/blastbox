"""The server-authored ``run`` block on the claim, and ``result_dir`` staying on the host."""
from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

from .test_node_claim import _claim, pki_dir  # noqa: F401  (fixture)


def _setup(tmp_path, pki_dir, *, params=None, spool=b"hello"):  # noqa: F811
    store = InMemoryJobStore()
    store.create(Job(job_id="job-1", engine="clamav", filename="sample.bin",
                     status=JobStatus.QUEUED, created_at=time.time(),
                     input_sha256="ab" * 32, result_dir="/srv/internal/out",
                     params=params or {}))
    root = tmp_path / "jobs"
    if spool is not None:
        (root / "job-1" / "input").mkdir(parents=True)
        (root / "job-1" / "input" / "sample.bin").write_bytes(spool)
    app = FastAPI()
    assert register_node_claim_routes(app, job_store=store, pki_dir=pki_dir,
                                      job_root=root) is True
    return store, app, TestClient(app)


def test_claim_has_run_block(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BLASTBOX_NODE_RUN_DEADLINE_S_CLAMAV", "5")
    _, _, c = _setup(tmp_path, pki_dir)
    r = _claim(c, pki_dir, "alpha", engine="clamav")
    assert r.status_code == 200, r.text
    run = r.json()["run"]
    assert run["deadline_s"] == 10          # clamped up from 5
    assert set(run["limits"]) == {"max_input", "max_metadata", "max_artifact",
                                  "max_total_artifacts", "max_artifacts"}
    assert run["network"] == "none"
    assert run["input"] == {"sha256": "ab" * 32, "bytes": 5, "filename": "sample.bin"}


def test_run_input_bytes_none_when_not_local(tmp_path, pki_dir):  # noqa: F811
    _, _, c = _setup(tmp_path, pki_dir, spool=None)
    run = _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]
    assert run["input"]["bytes"] is None
    assert run["deadline_s"] == 300


def test_run_params_strip_blastbox_keys(tmp_path, pki_dir):  # noqa: F811
    _, _, c = _setup(tmp_path, pki_dir, params={"BLASTBOX_X": "1", "blastbox_y": "2", "ok": "v"})
    run = _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]
    assert run["params"] == {"ok": "v"}


def test_claim_job_has_no_result_dir(tmp_path, pki_dir):  # noqa: F811
    _, _, c = _setup(tmp_path, pki_dir)
    body = _claim(c, pki_dir, "alpha", engine="clamav").json()
    assert "result_dir" not in body["job"]
    assert "/srv/internal" not in str(body)


def test_http_store_still_parses_claim(tmp_path, pki_dir):  # noqa: F811
    _, _, c = _setup(tmp_path, pki_dir)
    job = Job.from_dict(_claim(c, pki_dir, "alpha", engine="clamav").json()["job"])
    assert job.job_id == "job-1" and job.result_dir is None
