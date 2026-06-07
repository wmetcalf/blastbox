"""Tests for the warm-pool config + factory (host/pool_config.py)."""
from __future__ import annotations

import pytest

from blastbox.host.pool import Slot, WarmPool
from blastbox.host.pool_config import (
    RUNTIME_FIRECRACKER,
    RUNTIME_NONE,
    PoolConfig,
    build_warm_pool,
)
from blastbox.host.runtime.firecracker import firecracker_available

# True on a FC-capable host (e.g. toolz2 with BLASTBOX_FC_* set).
_HAS_FC = firecracker_available()


class _FakeRuntime:
    """Minimal SlotRuntime double — never actually spawns."""

    def spawn(self) -> Slot:  # pragma: no cover - not exercised here
        raise NotImplementedError

    def is_ready(self, slot: Slot) -> bool:
        return False

    def is_alive(self, slot: Slot) -> bool:
        return False

    def reap(self, slot: Slot) -> None:
        pass


def test_from_env_defaults(monkeypatch):
    for k in (
        "BLASTBOX_POOL_RUNTIME",
        "BLASTBOX_POOL_WARM_SIZE",
        "BLASTBOX_POOL_CEILING",
        "BLASTBOX_POOL_SPAWN_RATE",
        "BLASTBOX_POOL_BURST_SIZE",
    ):
        monkeypatch.delenv(k, raising=False)
    cfg = PoolConfig.from_env()
    assert cfg.runtime == RUNTIME_NONE
    assert cfg.warm_size == 4
    assert cfg.concurrent_ceiling == 16


def test_from_env_reads_overrides(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "Firecracker")  # case-insensitive
    monkeypatch.setenv("BLASTBOX_POOL_WARM_SIZE", "8")
    monkeypatch.setenv("BLASTBOX_POOL_CEILING", "32")
    monkeypatch.setenv("BLASTBOX_POOL_SPAWN_RATE", "2.5")
    monkeypatch.setenv("BLASTBOX_POOL_BURST_SIZE", "6")
    cfg = PoolConfig.from_env()
    assert cfg.runtime == RUNTIME_FIRECRACKER
    assert cfg.warm_size == 8
    assert cfg.concurrent_ceiling == 32
    assert cfg.spawn_rate_limit == 2.5
    assert cfg.burst_size == 6


def test_from_env_rejects_bad_int(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_WARM_SIZE", "not-a-number")
    with pytest.raises(ValueError):
        PoolConfig.from_env()


def test_from_env_rejects_invalid_sizes(monkeypatch):
    monkeypatch.delenv("BLASTBOX_POOL_RUNTIME", raising=False)
    with pytest.raises(ValueError):
        PoolConfig.from_env(concurrent_ceiling=0)


def test_build_pool_none_when_disabled():
    cfg = PoolConfig(runtime=RUNTIME_NONE)
    assert build_warm_pool(cfg) is None


def test_build_pool_with_injected_runtime():
    cfg = PoolConfig(runtime=RUNTIME_FIRECRACKER, warm_size=3, concurrent_ceiling=9)
    pool = build_warm_pool(cfg, runtime=_FakeRuntime())
    assert isinstance(pool, WarmPool)
    assert pool.runtime.__class__ is _FakeRuntime
    # Config flowed into the pool.
    assert pool.effective_target == 3


def test_build_pool_unknown_runtime_raises():
    cfg = PoolConfig(runtime="qemu")
    with pytest.raises(ValueError, match="unknown pool runtime"):
        build_warm_pool(cfg)


# --- warm-snapshot gate ----------------------------------------------------


def test_from_env_warm_snapshot_default_off(monkeypatch):
    monkeypatch.delenv("BLASTBOX_POOL_WARM_SNAPSHOT", raising=False)
    assert PoolConfig.from_env().warm_snapshot is False


def test_from_env_warm_snapshot_reads_truthy(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_WARM_SNAPSHOT", "1")
    assert PoolConfig.from_env().warm_snapshot is True
    for falsey in ("0", "false", "no"):
        monkeypatch.setenv("BLASTBOX_POOL_WARM_SNAPSHOT", falsey)
        assert PoolConfig.from_env().warm_snapshot is False


def test_build_pool_warm_snapshot_routes_to_snapshot_selector(monkeypatch):
    """When warm_snapshot is set, the firecracker tier resolves via
    select_snapshot_runtime (NOT the cold select_fc_runtime)."""
    import blastbox.host.runtime.fc_snapshot_runtime as snap_mod

    sentinel = _FakeRuntime()
    called = {}

    def fake_select(*, require_available=False):
        called["require_available"] = require_available
        return sentinel

    monkeypatch.setattr(snap_mod, "select_snapshot_runtime", fake_select)
    cfg = PoolConfig(runtime=RUNTIME_FIRECRACKER, warm_snapshot=True)
    pool = build_warm_pool(cfg)
    assert pool is not None
    assert pool.runtime is sentinel
    assert called["require_available"] is True  # operator opted in → fail loud


def test_build_pool_cold_path_unaffected_when_snapshot_off(monkeypatch):
    """warm_snapshot=False must NOT touch the snapshot selector."""
    import blastbox.host.runtime.firecracker as fc_mod

    sentinel = _FakeRuntime()
    monkeypatch.setattr(
        fc_mod, "select_fc_runtime", lambda *, require_available=False: sentinel
    )
    cfg = PoolConfig(runtime=RUNTIME_FIRECRACKER, warm_snapshot=False)
    pool = build_warm_pool(cfg)
    assert pool is not None and pool.runtime is sentinel


def test_gvisor_runtime_routes_to_gvisor_snapshot(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "gvisor")
    sentinel = _FakeRuntime()
    calls = {}

    def _capture(**kwargs):
        calls.update(kwargs)
        return sentinel

    import blastbox.host.runtime.gvisor_snapshot_runtime as g
    monkeypatch.setattr(g, "select_gvisor_snapshot_runtime", _capture)
    from blastbox.host.pool_config import build_warm_pool, PoolConfig
    pool = build_warm_pool(PoolConfig.from_env())
    # The pool must wrap the runtime the gvisor selector returned...
    assert pool is not None and pool.runtime is sentinel
    # ...and it must be selected fail-loud (require_available=True), like the FC tier.
    assert calls.get("require_available") is True


@pytest.mark.skipif(
    _HAS_FC,
    reason="this host HAS the FC tier; the unavailable-path only holds without it",
)
def test_build_pool_firecracker_unavailable_raises(monkeypatch):
    # No FC env on this host → select_fc_runtime(require_available=True) raises.
    from blastbox.host.runtime.firecracker import FCUnavailable

    cfg = PoolConfig(runtime=RUNTIME_FIRECRACKER)
    with pytest.raises(FCUnavailable):
        build_warm_pool(cfg)
