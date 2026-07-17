"""Opt-in node coordinator: config toggles + inventory, flag-honouring tick, and the
/v1/pool/* control surface (status read + fail-closed resize)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from blastbox.host import pool_registry
from blastbox.host.node_config import EngineNode, NodeConfig
from blastbox.host.node_coord import NodeCoordinator
from blastbox.host.pool_config import RUNTIME_FIRECRACKER


# --- config: optionality + inventory ---------------------------------------

def test_config_off_by_default():
    cfg = NodeConfig(engines=(EngineNode("a", "http://x"),))
    assert cfg.resource_management is False and cfg.balancing is False
    assert cfg.active is False                      # nothing on → coordinator no-ops


def test_config_active_only_when_a_switch_is_on():
    e = (EngineNode("a", "http://x"),)
    assert NodeConfig(engines=e, resource_management=True).active is True
    assert NodeConfig(engines=e, balancing=True).active is True
    assert NodeConfig(engines=(), balancing=True).active is False   # no engines → nothing to size


def test_add_remove_engine_inventory():
    cfg = NodeConfig()
    cfg = cfg.add_engine(EngineNode("clip", "http://1")).add_engine(EngineNode("red", "http://2"))
    assert {e.name for e in cfg.engines} == {"clip", "red"}
    cfg = cfg.add_engine(EngineNode("clip", "http://1b"))   # replace by name
    assert sum(1 for e in cfg.engines if e.name == "clip") == 1
    cfg = cfg.remove_engine("red")
    assert {e.name for e in cfg.engines} == {"clip"}


def test_from_env_parses_inventory_and_flags(monkeypatch):
    monkeypatch.setenv("BLASTBOX_NODE_ENGINES", "clip=http://127.0.0.1:8001,red=http://127.0.0.1:8003")
    monkeypatch.setenv("BLASTBOX_NODE_ENGINE_CLIP_RAM_MIB", "7000")
    monkeypatch.setenv("BLASTBOX_NODE_BALANCING", "1")
    cfg = NodeConfig.from_env()
    assert {e.name for e in cfg.engines} == {"clip", "red"}
    assert next(e for e in cfg.engines if e.name == "clip").slot_ram_mib == 7000
    assert cfg.balancing is True
    assert cfg.resource_management is True          # balancing implies resource_management


# --- coordinator: flag behaviour -------------------------------------------

def _stub_transports():
    pushed: dict[str, tuple[int, int]] = {}

    def push(url, warm_size, concurrent_ceiling):
        pushed[url] = (warm_size, concurrent_ceiling)

    return pushed, push


def test_coordinator_noop_when_inactive():
    pushed, push = _stub_transports()
    cfg = NodeConfig(engines=(EngineNode("a", "http://a"),))    # both switches off
    coord = NodeCoordinator(cfg, fetch_status=lambda u: {"runtime": RUNTIME_FIRECRACKER},
                            push_resize=push)
    assert coord.tick() == {}                       # no plan, no pushes
    assert pushed == {}


def test_coordinator_balancing_follows_backlog():
    pushed, push = _stub_transports()
    status = {
        "http://a": {"runtime": RUNTIME_FIRECRACKER, "assigned": 0, "backlog": 30},
        "http://b": {"runtime": RUNTIME_FIRECRACKER, "assigned": 0, "backlog": 2},
    }
    cfg = NodeConfig(
        engines=(EngineNode("a", "http://a", slot_ram_mib=1024, max_ceiling=64),
                 EngineNode("b", "http://b", slot_ram_mib=1024, max_ceiling=64)),
        balancing=True, ram_headroom_frac=1.0, vcpu_oversubscription=999)
    coord = NodeCoordinator(cfg, fetch_status=lambda u: status[u], push_resize=push)
    plan = coord.tick()
    # a has the deep queue → bigger ceiling; both engines got a resize pushed
    assert plan["a"]["concurrent_ceiling"] > plan["b"]["concurrent_ceiling"]
    assert set(pushed) == {"http://a", "http://b"}


def test_coordinator_static_shares_when_balancing_off():
    pushed, push = _stub_transports()
    # resource_management ON, balancing OFF → shares track configured weight, not backlog
    status = {"http://a": {"runtime": RUNTIME_FIRECRACKER, "assigned": 0, "backlog": 99},
              "http://b": {"runtime": RUNTIME_FIRECRACKER, "assigned": 0, "backlog": 0}}
    cfg = NodeConfig(
        engines=(EngineNode("a", "http://a", slot_ram_mib=1024, max_ceiling=64, weight=1),
                 EngineNode("b", "http://b", slot_ram_mib=1024, max_ceiling=64, weight=3)),
        resource_management=True, balancing=False, ram_headroom_frac=1.0, vcpu_oversubscription=999)
    coord = NodeCoordinator(cfg, fetch_status=lambda u: status[u], push_resize=push)
    plan = coord.tick()
    # b's weight is higher → bigger share, DESPITE a's huge backlog (backlog ignored)
    assert plan["b"]["concurrent_ceiling"] > plan["a"]["concurrent_ceiling"]


# --- /v1/pool/* control surface --------------------------------------------

class _Pool:
    runtime = RUNTIME_FIRECRACKER
    assigned_count = 3
    burst_active = True
    warm_size = 4
    concurrent_ceiling = 8
    slot_count = 6

    def resize(self, *, warm_size, concurrent_ceiling):
        if concurrent_ceiling is not None and concurrent_ceiling < 1:
            raise ValueError("concurrent_ceiling must be >= 1")
        if warm_size is not None:
            type(self).warm_size = warm_size
        if concurrent_ceiling is not None:
            type(self).concurrent_ceiling = concurrent_ceiling


class _Store:
    def count(self, status=None, *, q=None):
        return 5


def _app():
    from blastbox.host.ingress.pool_routes import build_pool_router
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(build_pool_router())
    return app


def test_status_endpoint_reports_backlog_and_state():
    pool_registry.register(_Pool(), _Store())
    c = TestClient(_app())
    s = c.get("/v1/pool/status").json()
    assert s["assigned"] == 3 and s["burst_active"] is True and s["backlog"] == 5
    pool_registry.register(None, None)


def test_resize_fail_closed_without_admin_token(monkeypatch):
    monkeypatch.delenv("BLASTBOX_ADMIN_TOKEN", raising=False)
    pool_registry.register(_Pool(), _Store())
    c = TestClient(_app())
    r = c.post("/v1/pool/resize", json={"warm_size": 2, "concurrent_ceiling": 5})
    assert r.status_code == 503                     # feature off → nothing to attack
    pool_registry.register(None, None)


def test_resize_requires_matching_token_then_applies(monkeypatch):
    monkeypatch.setenv("BLASTBOX_ADMIN_TOKEN", "s3cret")
    pool_registry.register(_Pool(), _Store())
    c = TestClient(_app())
    assert c.post("/v1/pool/resize", json={"warm_size": 2, "concurrent_ceiling": 5}).status_code == 401
    assert c.post("/v1/pool/resize", json={"warm_size": 2, "concurrent_ceiling": 5},
                  headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = c.post("/v1/pool/resize", json={"warm_size": 2, "concurrent_ceiling": 5},
                headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200 and ok.json()["concurrent_ceiling"] == 5
    pool_registry.register(None, None)
