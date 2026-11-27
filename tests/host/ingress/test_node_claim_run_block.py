"""The server-authored ``run`` block on the claim, and ``result_dir`` staying on the host."""
from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from blastbox.host.ingress.node_claim import register_node_claim_routes
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

from .test_node_claim import _claim, pki_dir  # noqa: F401  (fixture)


def _setup(tmp_path, pki_dir, *, params=None, spool=b"hello", limits=None):  # noqa: F811
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
                                      job_root=root, limits=limits) is True
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
    _, _, c = _setup(tmp_path, pki_dir, params={"BLASTBOX_X": "1", "blastbox_y": "2", "OK": "v"})
    run = _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]
    assert run["params"] == {"OK": "v"}


def test_run_params_go_through_the_engine_param_gate(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    """run.params is what the cold path would hand the worker: shape, the reserved floor
    (LD_*/PATH/PYTHON*), the engine's reserved keys, its allowlist and its defaults."""
    params = {"LD_PRELOAD": "/x.so", "PATH": "/evil", "lower": "1", "SCAN": "fast",
              "DEPTH": "3", "SECRET_MODE": "on"}
    _, _, c = _setup(tmp_path, pki_dir, params=params)
    assert _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]["params"] == {
        "SCAN": "fast", "DEPTH": "3", "SECRET_MODE": "on"}

    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_PARAM_KEYS", "scan,secret_mode,LEVEL")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_RESERVED_KEYS", "SECRET_MODE")
    monkeypatch.setenv("BLASTBOX_ENGINE_CLAMAV_DEFAULT_PARAMS", "LEVEL=2")
    _, _, c = _setup(tmp_path / "b", pki_dir, params=params)
    assert _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]["params"] == {
        "SCAN": "fast", "LEVEL": "2"}


def test_run_limits_are_the_enforced_limits(tmp_path, pki_dir):  # noqa: F811
    from blastbox.limits import Limits

    lim = Limits(max_input_bytes=1000, max_metadata_bytes=100)
    _, _, c = _setup(tmp_path, pki_dir, limits=lim)
    got = _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]["limits"]
    assert got["max_input"] == 1000 and got["max_metadata"] == 100


def test_claim_job_has_no_result_dir(tmp_path, pki_dir):  # noqa: F811
    _, _, c = _setup(tmp_path, pki_dir)
    body = _claim(c, pki_dir, "alpha", engine="clamav").json()
    assert "result_dir" not in body["job"]
    assert "/srv/internal" not in str(body)


def test_http_store_still_parses_claim(tmp_path, pki_dir):  # noqa: F811
    """Drive the Python credential-less node's real claim path against the app."""
    from blastbox.host.jobs.factory import build_job_store_from_env
    from blastbox.host.jobs.http_store import HttpJobStore

    _, _, c = _setup(tmp_path, pki_dir)
    store = build_job_store_from_env({
        "BLASTBOX_DATABASE_URL": "https://control-plane.example",
        "BLASTBOX_NODE_CERT": str(pki_dir / "node-alpha.crt"),
    })
    assert isinstance(store, HttpJobStore)
    store._transport = lambda method, path, *, json=None, params=None, headers=None: (
        lambda r: (r.status_code, r.json() if r.content else None))(
            c.request(method, path, json=json, params=params, headers=headers or {}))
    job = store.claim_next(engine="clamav")
    assert job is not None and job.job_id == "job-1"
    assert job.result_dir is None


def test_run_network_carries_resolved_tier(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    from blastbox.host.ingress import node_claim

    monkeypatch.setattr(node_claim, "_job_requirements",
                        lambda job: ("socks", False, True))
    _, _, c = _setup(tmp_path, pki_dir)
    run = _claim(c, pki_dir, "alpha", engine="clamav").json()["run"]
    assert run["network"] == "socks"
