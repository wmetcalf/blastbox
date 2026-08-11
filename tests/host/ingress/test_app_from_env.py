"""Tests for the multi-worker serve factory (``blastbox serve --workers N``).

``uvicorn.run(..., workers>1)`` forks worker processes that each re-import and build
their own app, so it needs an import-string factory rather than a prebuilt object.
``app_from_env`` reconstructs the app from ``BLASTBOX_*`` env so every forked worker
is identical to the single-process app."""
import os
import time
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI

from blastbox.host.ingress.app import app_from_env


def test_app_from_env_builds_app_from_allowed_engines(monkeypatch):
    monkeypatch.setenv("BLASTBOX_ALLOWED_ENGINES", "redtusk,clippyshot")
    monkeypatch.delenv("BLASTBOX_INGRESS_EXTENSION", raising=False)
    app = app_from_env()
    assert isinstance(app, FastAPI)


def test_app_from_env_handles_empty_allowed_engines(monkeypatch):
    # unset/empty -> allowed=None (accept any engine); must still build an app
    monkeypatch.delenv("BLASTBOX_ALLOWED_ENGINES", raising=False)
    monkeypatch.delenv("BLASTBOX_INGRESS_EXTENSION", raising=False)
    app = app_from_env()
    assert isinstance(app, FastAPI)


def test_serve_parses_workers_flag():
    # the CLI must accept --workers so multi-worker serving is reachable
    from blastbox.host.cli import build_parser  # type: ignore[attr-defined]
    p = build_parser() if "build_parser" in dir(__import__("blastbox.host.cli", fromlist=["x"])) else None
    if p is None:
        pytest.skip("no exported parser builder; covered indirectly by _serve_cmd")
    ns = p.parse_args(["serve", "--workers", "8"])
    assert ns.workers == 8


def test_serve_reaps_its_own_job_root(tmp_path, monkeypatch):
    """A serve-only node is where the untrusted bytes land FIRST, and it was the one place with no
    reaper at all.

    Ingress spools every upload to <job_root>/<id>/input/<sample> and deletes it only on the
    put_sample/create failure paths, while both new sweeps live in DISPATCHER maintenance — so in
    the documented role-separated topology (serve xN + dispatch xM, which deliberately rejects a
    shared filesystem) a serve node accumulates raw malware inputs forever. Same reclaim, same
    rules, so on a single-node deployment it is a harmless duplicate of the dispatcher's sweep.
    """
    from fastapi.testclient import TestClient

    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.setenv("BLASTBOX_BLOB_LOCAL_ROOT", str(tmp_path / "blobs"))
    monkeypatch.setenv("BLASTBOX_SCRATCH_MAX_AGE_S", "60")
    monkeypatch.setenv("BLASTBOX_MAINTENANCE_INTERVAL_S", "1")

    (tmp_path / "jobs").mkdir()
    stale = tmp_path / "jobs" / "abcdef12-3456-4789-8abc-def012345678"
    (stale / "input").mkdir(parents=True)
    (stale / "input" / "sample.doc").write_bytes(b"MALWARE-BYTES-MUST-NOT-PERSIST")
    old = time.time() - 99_999
    for pth in (stale / "input" / "sample.doc", stale / "input", stale):
        os.utime(pth, (old, old))

    from blastbox.host.ingress.app import build_app

    with TestClient(build_app()):                 # lifespan starts the reaper thread
        for _ in range(40):
            if not stale.exists():
                break
            time.sleep(0.25)

    assert not stale.exists(), "a serve node kept an abandoned malware input forever"
