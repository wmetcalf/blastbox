"""TDD tests for the blastbox ingress extension seam (host/ingress/extension.py).

A product mounts its own FastAPI routers on the shared ingress core via
IngressExtension, and `blastbox serve` resolves one from BLASTBOX_INGRESS_EXTENSION.
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from blastbox.host.ingress.app import build_app
from blastbox.host.ingress.extension import IngressExtension, load_ingress_extension


def _dummy_router() -> APIRouter:
    r = APIRouter()

    @r.get("/v1/ext/ping")
    def ping():
        return {"pong": True}

    return r


def _factory() -> IngressExtension:
    """Module-level factory resolved by BLASTBOX_INGRESS_EXTENSION in tests."""
    return IngressExtension(routers=(_dummy_router(),))


def _app(**kw):
    return build_app(allowed_engines={"probe"}, **kw)


# --- Task 1: the seam -------------------------------------------------------


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


# --- Task 2: the env loader -------------------------------------------------


def test_load_ingress_extension_resolves_factory():
    ext = load_ingress_extension("tests.host.ingress.test_extension:_factory")
    assert isinstance(ext, IngressExtension)
    assert len(ext.routers) == 1


def test_load_ingress_extension_empty_is_none():
    assert load_ingress_extension(None) is None
    assert load_ingress_extension("") is None


def test_load_ingress_extension_bad_spec_raises():
    with pytest.raises(ValueError):
        load_ingress_extension("no_colon_here")


def test_load_ingress_extension_whitespace_is_none():
    # operator-provided whitespace-only config is treated as empty, not a ValueError
    assert load_ingress_extension("   ") is None
    assert load_ingress_extension("\t\n") is None
