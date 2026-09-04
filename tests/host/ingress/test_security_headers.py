"""Security posture restored from the engines' bespoke hosts (lost in the migration):
hardening response headers on every response + API docs withheld by default.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.memory import InMemoryJobStore


def _client(tmp_path):
    app = build_app(
        job_store=InMemoryJobStore(),
        job_root=tmp_path / "jobs",
        allowed_engines={"e"},
    )
    return TestClient(app, raise_server_exceptions=False)


def test_hardening_headers_on_every_response(tmp_path):
    r = _client(tmp_path).get("/v1/healthz")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_csp_overridable(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_CSP", "default-src 'none'")
    r = _client(tmp_path).get("/v1/healthz")
    assert r.headers["Content-Security-Policy"] == "default-src 'none'"
    # the other three hardening headers are unconditional
    assert r.headers["X-Frame-Options"] == "DENY"


def test_csp_can_be_disabled_but_other_headers_stay(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_CSP", "")
    r = _client(tmp_path).get("/v1/healthz")
    assert "Content-Security-Policy" not in r.headers
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_docs_withheld_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTBOX_EXPOSE_DOCS", raising=False)
    c = _client(tmp_path)
    assert c.get("/docs").status_code == 404
    assert c.get("/redoc").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_docs_exposed_on_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_EXPOSE_DOCS", "1")
    c = _client(tmp_path)
    assert c.get("/openapi.json").status_code == 200
    assert c.get("/docs").status_code == 200
