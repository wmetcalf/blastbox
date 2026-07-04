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
RUNTIME_GVISOR = "gvisor"
RUNTIME_AWS_LAMBDA_MICROVM = "aws-lambda-microvm"
RUNTIME_AWS_EC2 = "aws-ec2"
RUNTIME_STATIC = "static"


@dataclass(frozen=True)
class PoolConfig:
    """Warm-pool tunables, all from ``BLASTBOX_POOL_*`` (mirrors WarmPool args)."""

    runtime: str = RUNTIME_NONE
    warm_size: int = 4
    concurrent_ceiling: int = 16
    spawn_rate_limit: float = 4.0
    burst_size: int = 4
    # Warm-snapshot tier (firecracker only): spawn = restore-from-warm-snapshot
    # instead of cold-boot. Opt-in; default OFF (cold FC boot per slot).
    warm_snapshot: bool = False

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

        def _bool(key: str, default: bool) -> bool:
            raw = os.environ.get(key, "").strip().lower()
            if not raw:
                return default
            return raw not in ("0", "false", "no")

        values: dict[str, object] = {
            "runtime": os.environ.get("BLASTBOX_POOL_RUNTIME", cls.runtime).strip().lower(),
            "warm_size": _int("BLASTBOX_POOL_WARM_SIZE", cls.warm_size),
            "concurrent_ceiling": _int("BLASTBOX_POOL_CEILING", cls.concurrent_ceiling),
            "spawn_rate_limit": _float("BLASTBOX_POOL_SPAWN_RATE", cls.spawn_rate_limit),
            "burst_size": _int("BLASTBOX_POOL_BURST_SIZE", cls.burst_size),
            "warm_snapshot": _bool("BLASTBOX_POOL_WARM_SNAPSHOT", cls.warm_snapshot),
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
    available (binary + /dev/kvm + kernel + rootfs) or the selector raises
    ``FCUnavailable`` — fail loudly rather than silently fall back to cold. When
    ``cfg.warm_snapshot`` is set, the firecracker tier's spawn op becomes
    restore-from-warm-snapshot (``select_snapshot_runtime``, which builds the
    ``SnapshotManager`` via ``from_env`` so the RAM-preload toggle is honored).
    """
    cfg = cfg or PoolConfig.from_env()

    if runtime is None:
        if cfg.runtime == RUNTIME_NONE:
            return None
        if cfg.runtime == RUNTIME_FIRECRACKER:
            if cfg.warm_snapshot:
                from blastbox.host.runtime.fc_snapshot_runtime import (
                    select_snapshot_runtime,
                )

                runtime = select_snapshot_runtime(require_available=True)
            else:
                from blastbox.host.runtime.firecracker import select_fc_runtime

                runtime = select_fc_runtime(require_available=True)
        elif cfg.runtime == RUNTIME_GVISOR:
            from blastbox.host.runtime.gvisor_snapshot_runtime import (
                select_gvisor_snapshot_runtime,
            )

            runtime = select_gvisor_snapshot_runtime(require_available=True)
        elif cfg.runtime == RUNTIME_AWS_LAMBDA_MICROVM:
            from blastbox.host.runtime.aws_worker import select_lambda_microvm_runtime

            # network-endpoint slot (AwsWorkerSlot) diverges from the SlotRuntime Protocol's Slot,
            # like libvirt's VmSlot -- WarmPool drives it fine (touches only the common fields).
            runtime = select_lambda_microvm_runtime(require_available=True)  # type: ignore[assignment]
        elif cfg.runtime == RUNTIME_AWS_EC2:
            from blastbox.host.runtime.aws_worker import select_disposable_ec2_runtime

            runtime = select_disposable_ec2_runtime(require_available=True)  # type: ignore[assignment]
        elif cfg.runtime == RUNTIME_STATIC:
            from blastbox.host.runtime.static_pool import select_static_pool_runtime

            runtime = select_static_pool_runtime(require_available=True)  # type: ignore[assignment]
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
        "warm_pool_built runtime=%s warm_size=%d ceiling=%d warm_snapshot=%s",
        cfg.runtime,
        cfg.warm_size,
        cfg.concurrent_ceiling,
        cfg.warm_snapshot,
    )
    return pool
