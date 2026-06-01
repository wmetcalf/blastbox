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
