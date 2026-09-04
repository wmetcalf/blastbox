"""Per-engine web UI mounted through the IngressExtension seam.

An engine ships a ``StaticUI`` (its packaged ``static/`` dir); ``build_app`` serves
``index.html`` at ``GET /`` and mounts an optional ``assets/`` subdir at ``/assets``.
The UI is mounted LAST so it never shadows ``/v1/*`` or product routes.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi import APIRouter
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension, StaticUI
from blastbox.host.jobs.memory import InMemoryJobStore


def _ui_dir(tmp_path, *, with_assets: bool = False):
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>engine ui</title>")
    if with_assets:
        (ui / "assets").mkdir()
        (ui / "assets" / "logo.svg").write_text("<svg/>")
    return ui


def _client(tmp_path, *, static_ui=None, routers=()):
    app = build_app(
        job_store=InMemoryJobStore(),
        job_root=tmp_path / "jobs",
        allowed_engines={"e"},
        extension=IngressExtension(routers=tuple(routers), static_ui=static_ui),
    )
    return TestClient(app, raise_server_exceptions=False)


def test_index_served_at_root(tmp_path):
    ui = _ui_dir(tmp_path)
    client = _client(tmp_path, static_ui=StaticUI(directory=str(ui)))
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "engine ui" in resp.text


def test_no_static_ui_means_no_root_route(tmp_path):
    client = _client(tmp_path)  # extension with no static_ui
    assert client.get("/").status_code == 404


def test_assets_served_when_present(tmp_path):
    ui = _ui_dir(tmp_path, with_assets=True)
    client = _client(tmp_path, static_ui=StaticUI(directory=str(ui)))
    resp = client.get("/assets/logo.svg")
    assert resp.status_code == 200
    assert resp.text == "<svg/>"
    # a missing asset is a 404, and traversal out of /assets is blocked by StaticFiles
    assert client.get("/assets/missing.png").status_code == 404
    assert client.get("/assets/../index.html").status_code in (404, 400)


def test_no_assets_dir_means_no_assets_mount(tmp_path):
    ui = _ui_dir(tmp_path, with_assets=False)
    client = _client(tmp_path, static_ui=StaticUI(directory=str(ui)))
    assert client.get("/assets/anything.png").status_code == 404


def test_ui_does_not_shadow_api_or_product_routes(tmp_path):
    ui = _ui_dir(tmp_path)
    router = APIRouter()

    @router.get("/v1/custom")
    def _custom():
        return {"ok": True}

    client = _client(tmp_path, static_ui=StaticUI(directory=str(ui)), routers=[router])
    # core API still reachable
    assert client.get("/v1/healthz").status_code == 200
    # product route still reachable
    assert client.get("/v1/custom").json() == {"ok": True}
    # and the UI root works alongside them
    assert client.get("/").status_code == 200


def test_index_path_confined(tmp_path):
    ui = _ui_dir(tmp_path)
    # a traversal in `index` must not escape the UI directory
    with pytest.raises(ValueError):
        StaticUI(directory=str(ui), index="../secret.html").index_path()
