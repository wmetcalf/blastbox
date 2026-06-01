"""Warm-pool configuration + factory.

Turns ``BLASTBOX_POOL_*`` env vars into a ``WarmPool`` backed by the configured
slot runtime. The pool is OPT-IN: ``BLASTBOX_POOL_RUNTIME`` defaults to ``none``
(cold path only), so existing cold-only deployments are unaffected. Set it to
``firecracker`` to maintain a warm pool of disposable Firecracker microVMs.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from blastbox.host.pool import SlotRuntime, WarmPool

_log = logging.getLogger("blastbox.host.pool_config")

# Pool runtime identifiers.
RUNTIME_NONE = "none"
RUNTIME_FIRECRACKER = "firecracker"


@dataclass(frozen=True)
class PoolConfig:
    """Warm-pool tunables, all from ``BLASTBOX_POOL_*`` (mirrors WarmPool args)."""

    runtime: str = RUNTIME_NONE
    warm_size: int = 4
    concurrent_ceiling: int = 16
    spawn_rate_limit: float = 4.0
    burst_size: int = 4

    @classmethod
    def from_env(cls, **overrides: object) -> "PoolConfig":
        def _int(key: str, default: int) -> int:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid integer for {key}={raw!r}: {exc}") from exc

        def _float(key: str, default: float) -> float:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                return float(raw)
            except ValueError as exc:
                raise ValueError(f"invalid float for {key}={raw!r}: {exc}") from exc

        values: dict[str, object] = {
            "runtime": os.environ.get("BLASTBOX_POOL_RUNTIME", cls.runtime).strip().lower(),
            "warm_size": _int("BLASTBOX_POOL_WARM_SIZE", cls.warm_size),
            "concurrent_ceiling": _int("BLASTBOX_POOL_CEILING", cls.concurrent_ceiling),
            "spawn_rate_limit": _float("BLASTBOX_POOL_SPAWN_RATE", cls.spawn_rate_limit),
            "burst_size": _int("BLASTBOX_POOL_BURST_SIZE", cls.burst_size),
        }
        values.update(overrides)
        cfg = cls(**values)  # type: ignore[arg-type]
        if cfg.warm_size < 0 or cfg.concurrent_ceiling < 1:
            raise ValueError("warm_size must be >= 0 and concurrent_ceiling >= 1")
        return cfg


def build_warm_pool(
    cfg: PoolConfig | None = None,
    *,
    runtime: SlotRuntime | None = None,
) -> WarmPool | None:
    """Build a WarmPool from config, or ``None`` when pooling is disabled.

    ``runtime`` may be injected (tests / custom runtimes); otherwise it is
    resolved from ``cfg.runtime``. For ``firecracker`` the FC tier MUST be
    available (binary + /dev/kvm + kernel + rootfs) or ``select_fc_runtime``
    raises ``FCUnavailable`` — fail loudly rather than silently fall back to cold.
    """
    cfg = cfg or PoolConfig.from_env()

    if runtime is None:
        if cfg.runtime == RUNTIME_NONE:
            return None
        if cfg.runtime == RUNTIME_FIRECRACKER:
            from blastbox.host.runtime.firecracker import select_fc_runtime

            runtime = select_fc_runtime(require_available=True)
        else:
            raise ValueError(f"unknown pool runtime: {cfg.runtime!r}")

    assert runtime is not None  # narrowed: every branch above returned/raised/assigned
    pool = WarmPool(
        runtime=runtime,
        warm_size=cfg.warm_size,
        concurrent_ceiling=cfg.concurrent_ceiling,
        spawn_rate_limit=cfg.spawn_rate_limit,
        burst_size=cfg.burst_size,
    )
    _log.info(
        "warm_pool_built runtime=%s warm_size=%d ceiling=%d",
        cfg.runtime,
        cfg.warm_size,
        cfg.concurrent_ceiling,
    )
    return pool
