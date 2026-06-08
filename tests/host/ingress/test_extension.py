"""TDD tests for the blastbox ingress extension seam (host/ingress/extension.py).

A product mounts its own FastAPI routers on the shared ingress core via
IngressExtension, and `blastbox serve` resolves one from BLASTBOX_INGRESS_EXTENSION.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension


def _dummy_router() -> APIRouter:
    r = APIRouter()

    @r.get("/v1/ext/ping")
    def ping():
        return {"pong": True}

    return r


def _app(**kw):
    return build_app(allowed_engines={"probe"}, **kw)


def test_extension_router_is_mounted():
    c = TestClient(_app(extension=IngressExtension(routers=(_dummy_router(),))))
    assert c.get("/v1/ext/ping").json() == {"pong": True}


def test_core_routes_still_work_with_extension():
    c = TestClient(_app(extension=IngressExtension(routers=(_dummy_router(),))))
    assert c.get("/v1/healthz").status_code == 200


def test_no_extension_is_noop():
    c = TestClient(_app())  # extension defaults to None
    assert c.get("/v1/ext/ping").status_code == 404


def test_extension_route_inherits_bearer_auth():
    # product routes are NOT public — the core middleware gates them
    c = TestClient(
        _app(api_key="secret", extension=IngressExtension(routers=(_dummy_router(),)))
    )
    assert c.get("/v1/ext/ping").status_code == 401
    ok = c.get("/v1/ext/ping", headers={"Authorization": "Bearer secret"})
    assert ok.json() == {"pong": True}
