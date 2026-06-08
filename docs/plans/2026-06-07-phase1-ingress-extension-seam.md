# Phase 1 — Ingress Extension Seam (Implementation Plan)

> Sub-skill: subagent-driven or inline execution, TDD, commit per task. Steps use `- [ ]`.

**Goal:** Let a product mount its own FastAPI routers on the shared blastbox ingress without forking `build_app` — the prerequisite that lets ClippyShot's Tika/PNG routes and redtusk's infected-zip survive the migration.

**Architecture:** A new `IngressExtension(routers=…)` is passed to `build_app(..., extension=…)`, which `include_router`s each product router after the core routes (so product routes inherit the app's bearer-auth + limits middleware). `blastbox serve` resolves an extension from `BLASTBOX_INGRESS_EXTENSION="module:factory"` — operator-configured, mirroring the `BLASTBOX_FC_ENGINE` engine seam. Never derived from job data.

**Gate:** new unit tests pass; the existing `tests/host/ingress/` suite stays green; ruff + mypy clean. No product/corpus impact (framework-only).

**Repo conventions:** `/home/coz/Downloads/blastbox`, `.venv/bin/{pytest,ruff,mypy}`. Branch: `feat/ingress-extension-seam`.

---

### Task 1: `IngressExtension` + `build_app(extension=…)`

**Files:**
- Create: `src/blastbox/host/ingress/extension.py`
- Modify: `src/blastbox/host/ingress/app.py` (signature ~`:149`; include before `return app` at `:648`)
- Test: `tests/host/ingress/test_extension.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/host/ingress/test_extension.py
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
    c = TestClient(_app(api_key="secret", extension=IngressExtension(routers=(_dummy_router(),))))
    assert c.get("/v1/ext/ping").status_code == 401
    ok = c.get("/v1/ext/ping", headers={"Authorization": "Bearer secret"})
    assert ok.json() == {"pong": True}
```

- [ ] **Step 2: Run it — expect failure**

Run: `.venv/bin/pytest tests/host/ingress/test_extension.py -q`
Expected: `ModuleNotFoundError: blastbox.host.ingress.extension` (or `build_app() got an unexpected keyword 'extension'`).

- [ ] **Step 3: Implement `extension.py`**

```python
# src/blastbox/host/ingress/extension.py
"""Product-route extension seam for the shared blastbox ingress.

A product (clippyshot, redtusk, …) mounts its own FastAPI routers on top of the
shared core (submit/status/artifacts/auth/health/metrics) without forking
build_app. The core owns auth, limits, and the traversal-safe artifact path;
product routers inherit the app's middleware — do NOT re-implement auth in them.
"""
from __future__ import annotations
from dataclasses import dataclass
from fastapi import APIRouter


@dataclass(frozen=True)
class IngressExtension:
    """Operator-provided product routes mounted on the shared ingress."""
    routers: tuple[APIRouter, ...] = ()
```

- [ ] **Step 4: Wire `extension` into `build_app`**

In `src/blastbox/host/ingress/app.py`: add to the signature (after `metrics_public`):
```python
    extension: "IngressExtension | None" = None,
```
Import at top: `from blastbox.host.ingress.extension import IngressExtension`.
Just before `return app` (line ~648):
```python
    # Product routes mounted on the shared core. They inherit the app's
    # middleware (bearer auth, limits); the core owns auth + path-confinement.
    if extension is not None:
        for router in extension.routers:
            app.include_router(router)

    return app
```

- [ ] **Step 5: Run tests — expect pass**

Run: `.venv/bin/pytest tests/host/ingress/test_extension.py -q`
Expected: 4 passed. If `test_extension_route_inherits_bearer_auth` fails, inspect `host/ingress/middleware.py` `BearerAuthMiddleware` public-path set — confirm `/v1/ext/*` is NOT in the public allowlist (it must be gated). Adjust the test only if the middleware's public logic is path-prefix-based in a way that needs documenting; do NOT make product routes public.

- [ ] **Step 6: Regression — existing ingress suite + lint/types**

Run: `.venv/bin/pytest tests/host/ingress -q && .venv/bin/ruff check src/blastbox/host/ingress && .venv/bin/mypy src/blastbox/host/ingress`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/blastbox/host/ingress/extension.py src/blastbox/host/ingress/app.py tests/host/ingress/test_extension.py
git commit -m "feat(ingress): IngressExtension seam — mount product routers on the shared core"
```

---

### Task 2: `BLASTBOX_INGRESS_EXTENSION` loader + `serve` wiring

**Files:**
- Modify: `src/blastbox/host/ingress/extension.py` (add `load_ingress_extension`)
- Modify: `src/blastbox/host/cli.py` (`_serve_cmd` ~`:22`)
- Test: `tests/host/ingress/test_extension.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
def _factory() -> IngressExtension:
    return IngressExtension(routers=(_dummy_router(),))

def test_load_ingress_extension_resolves_factory():
    from blastbox.host.ingress.extension import load_ingress_extension
    ext = load_ingress_extension("tests.host.ingress.test_extension:_factory")
    assert isinstance(ext, IngressExtension)
    assert len(ext.routers) == 1

def test_load_ingress_extension_empty_is_none():
    from blastbox.host.ingress.extension import load_ingress_extension
    assert load_ingress_extension(None) is None
    assert load_ingress_extension("") is None

def test_load_ingress_extension_bad_spec_raises():
    import pytest
    from blastbox.host.ingress.extension import load_ingress_extension
    with pytest.raises(ValueError):
        load_ingress_extension("no_colon_here")
```

- [ ] **Step 2: Run — expect failure** (`ImportError: load_ingress_extension`).

- [ ] **Step 3: Implement the loader (append to `extension.py`)**

```python
def load_ingress_extension(spec: str | None) -> "IngressExtension | None":
    """Resolve ``BLASTBOX_INGRESS_EXTENSION='module:factory'`` to an
    IngressExtension. The factory is a zero-arg callable returning an
    IngressExtension. Operator-configured; never derived from job data.
    Mirrors the ``BLASTBOX_FC_ENGINE`` engine seam. Returns None if empty.
    """
    if not spec:
        return None
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise ValueError(
            f"BLASTBOX_INGRESS_EXTENSION must be 'module:factory', got {spec!r}"
        )
    import importlib
    ext = getattr(importlib.import_module(mod), attr)()
    if not isinstance(ext, IngressExtension):
        raise TypeError(f"{spec!r} factory did not return an IngressExtension")
    return ext
```

- [ ] **Step 4: Wire into `_serve_cmd` (`cli.py`)**

```python
    import os
    from blastbox.host.ingress.app import build_app
    from blastbox.host.ingress.extension import load_ingress_extension
    ...
    extension = load_ingress_extension(os.environ.get("BLASTBOX_INGRESS_EXTENSION"))
    app = build_app(allowed_engines=allowed or None, extension=extension)
```
(Keep `uvicorn.run(app, …)` unchanged.)

- [ ] **Step 5: Run tests — expect pass**

Run: `.venv/bin/pytest tests/host/ingress/test_extension.py -q`
Expected: 7 passed.

- [ ] **Step 6: Regression + lint/types**

Run: `.venv/bin/pytest tests/host -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all green (full host suite unaffected).

- [ ] **Step 7: Commit**

```bash
git add src/blastbox/host/ingress/extension.py src/blastbox/host/cli.py tests/host/ingress/test_extension.py
git commit -m "feat(ingress): BLASTBOX_INGRESS_EXTENSION loader + serve wiring"
```

---

## Done-when

- `build_app(extension=IngressExtension(routers=…))` mounts product routes that inherit auth.
- `blastbox serve` loads an extension from `BLASTBOX_INGRESS_EXTENSION`.
- Full `tests/host` suite + ruff + mypy green.
- Seam documented; ready for ClippyShot (Phase 2) to register its Tika/PNG router.
