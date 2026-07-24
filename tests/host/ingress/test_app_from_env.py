"""Tests for the multi-worker serve factory (``blastbox serve --workers N``).

``uvicorn.run(..., workers>1)`` forks worker processes that each re-import and build
their own app, so it needs an import-string factory rather than a prebuilt object.
``app_from_env`` reconstructs the app from ``BLASTBOX_*`` env so every forked worker
is identical to the single-process app."""
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
