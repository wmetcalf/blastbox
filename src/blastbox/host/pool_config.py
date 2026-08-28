"""Warm-pool configuration + factory.

Turns ``BLASTBOX_POOL_*`` env vars into a ``WarmPool`` backed by the configured
slot runtime. The pool is OPT-IN: ``BLASTBOX_POOL_RUNTIME`` defaults to ``none``
(cold path only), so existing cold-only deployments are unaffected. Set it to
``firecracker`` to maintain a warm pool of disposable Firecracker microVMs.
"""
from __future__ import annotations

import logging
import math
import os
from typing import Any
from dataclasses import dataclass, field as dc_field

from blastbox.host.pool import SlotRuntime, WarmPool

_log = logging.getLogger("blastbox.host.pool_config")

# Pool runtime identifiers.
RUNTIME_NONE = "none"
RUNTIME_FIRECRACKER = "firecracker"
RUNTIME_GVISOR = "gvisor"
RUNTIME_AWS_LAMBDA_MICROVM = "aws-lambda-microvm"
RUNTIME_AWS_LAMBDA_SNAPSTART = "aws-lambda-snapstart"
RUNTIME_AWS_EC2 = "aws-ec2"
RUNTIME_AWS_EC2_HIBERNATE = "aws-ec2-hibernate"
RUNTIME_STATIC = "static"
RUNTIME_CASCADE = "cascade"


@dataclass(frozen=True)
class PoolConfig:
    """Warm-pool tunables, all from ``BLASTBOX_POOL_*`` (mirrors WarmPool args)."""

    runtime: str = RUNTIME_NONE
    warm_size: int = 4
    concurrent_ceiling: int = 16
    spawn_rate_limit: float = 4.0
    # How many runtime.spawn() calls may be IN FLIGHT at once. The pool's maintenance thread
    # issues spawns one at a time, so a tier whose spawn takes ~0.6s (an FC snapshot restore)
    # caps the WHOLE pool at ~1.7 slots/s -- and with a disposable slot per job that is also the
    # job throughput ceiling, no matter how many warm slots or cores the node has. Measured on
    # toolz2: spawn gap p50=0.57s, ceiling 1.74/s, observed throughput 1.4-1.56/s while the host
    # sat at load 8 of 32 cores with 94G free.
    #
    # DEFAULT 1 = exactly the previous serial behaviour. Raise it only for tiers whose spawn is
    # latency-bound rather than CPU-bound (snapshot restore, cloud API calls).
    spawn_concurrency: int = 1
    burst_size: int = 4
    # Max seconds a slot may sit WARMING before it's evicted. The 120s default is fine for FC/gVisor;
    # raise it for cloud tiers (aws-ec2 first-boot can take minutes) so healthy-but-slow slots aren't
    # churned -- matches the AWS ready_timeout budget.
    warming_timeout_s: float = 120.0
    # Warm-snapshot tier (firecracker only): spawn = restore-from-warm-snapshot
    # instead of cold-boot. Opt-in; default OFF (cold FC boot per slot).
    warm_snapshot: bool = False
    # --- safety controls -------------------------------------------------------------------
    # These decide when the pool evicts a slot or destroys and rebuilds a snapshot base. They
    # were reachable only from the constructor, so an env-configured deployment (which is every
    # production one) could not tune them -- and could not use the documented
    # snapshot_rebuild_after=0 escape hatch to disable automatic base invalidation at all.
    # None everywhere means "not configured — let WarmPool's own default stand". Copying the
    # literals here is what created the last bug: this field said 3 while WarmPool said 2, so
    # every env-configured deployment silently sent a third job to a repeatedly failing slot
    # while the comment claimed the defaults matched. A sentinel cannot drift.
    max_consecutive_failures: int | None = None
    # 0 disables automatic base invalidation entirely; None derives 2*warm_size.
    snapshot_rebuild_after: int | None = None
    # Distinct slots that must fail before their guest ever executes before the base is judged
    # poisoned. Separate from snapshot_rebuild_after, which is sized to tolerate a run of bad
    # DOCUMENTS. Default ON, because the signal is PROOF rather than inference: the guest sends a
    # START frame the moment it has the job, so a document that hangs a healthy slot reports
    # guest_started=True and is never attributed to the base, and a worker image too old to send
    # one leaves the answer UNKNOWN, which also never convicts. 0 disables the fast path.
    pre_guest_rebuild_after: int = 3
    # None derives max(2, warm_size).
    max_evictions_per_window: int | None = None
    # How long a slot may stay CONTINUOUSLY unknown before it can be replaced; 0 disables.
    unknown_grace_s: float | None = None
    #: Tick-thread bounds for the idle-maintenance seam. Both were hardcoded in WarmPool and
    #: unreachable from the environment, so the two knobs that bound this pool's control-plane
    #: CALL RATE and its per-pass tick-thread HOLD were the only ones an operator could not turn
    #: down during an incident -- while every comparable knob on the same page is tunable.
    # KEYWORD-ONLY, because they were inserted into the MIDDLE of a positional dataclass. A caller
    # passing this config positionally -- the dataclass permits it and nothing here forbade it --
    # had its 14th argument silently rebound from capacity_starved_after_s to maintain_interval_s:
    # no error, the capacity-starvation alert quietly back at its default, and maintenance
    # scheduled on a number that was never meant for it. Declaring them kw_only keeps every
    # existing positional call binding exactly what it always did, and is the same guard the AWS
    # config states for its own late additions ("DECLARED LAST so adding it can't silently rebind
    # a positional caller's later fields").
    maintain_interval_s: float | None = dc_field(default=None, kw_only=True)
    maintain_budget_s: float | None = dc_field(default=None, kw_only=True)
    # How long the pool may be unable to spawn for capacity reasons before that is an outage
    # rather than backpressure; 0 disables the alert.
    capacity_starved_after_s: float | None = None

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

        #: Knobs where 0 is NOT a meaningful setting. For a rate limit "disabled" would mean the
        #: UNBOUNDED rate -- `now - last >= 0` is true on every tick, so an ec2-hibernate pool
        #: issues an uncached describe per idle slot at ~10Hz and manufactures the throttling the
        #: knob exists to prevent. That is the opposite of what an operator typing 0 intends, and
        #: they reach for it exactly when it hurts most: mid-incident. The internal default stands
        #: in instead. (Constructing WarmPool directly with 0 still means "no cooldown" -- the
        #: tests use it deliberately; this guards the ENV surface, which is what humans type.)
        _ZERO_IS_NOT_OFF = {"BLASTBOX_POOL_MAINTAIN_INTERVAL_S"}

        def _float(key: str, default: float) -> float:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                v = float(raw)
            except ValueError as exc:
                raise ValueError(f"invalid float for {key}={raw!r}: {exc}") from exc
            if not math.isfinite(v) or v < 0:
                # WARN AND FALL BACK -- the house convention, already documented for
                # BLASTBOX_CANARY_INTERVAL_S ("non-finite (nan, inf) and negative values fall back
                # to 900 with a warning"). Raising here instead was inconsistent twice over: with
                # that knob, and with this branch's own Ec2HibernateConfig.__post_init__, which
                # warns. It also turned a bad value in a LIVE deployment into a process that will
                # not start, which is a worse failure than the one being prevented.
                #
                # The value still cannot be honoured. Both directions misbehave silently: a
                # NEGATIVE interval makes `now - last >= interval` always true (an ec2-hibernate
                # pool then describes every tick and manufactures the throttling the limit exists
                # to avoid), and NaN makes every comparison against it False, which disables
                # whatever the knob gates. BLASTBOX_POOL_UNKNOWN_GRACE_S=nan did both at once: no
                # brownout exemption for WARMING slots, and idle unknowns that never aged out.
                # `0` is the documented "disabled" value.
                _log.warning(
                    "pool config: ignoring %s=%r (must be finite and >= 0); using %r. "
                    "Use 0 to disable.", key, raw, default)
                return default
            if v == 0 and key in _ZERO_IS_NOT_OFF:
                _log.warning(
                    "pool config: %s=0 would remove the rate limit rather than disable the seam "
                    "(every tick, ~10Hz); using %r. Raise it to slow the pool down.", key, default)
                return default
            return v

        def _bool(key: str, default: bool) -> bool:
            raw = os.environ.get(key, "").strip().lower()
            if not raw:
                return default
            return raw not in ("0", "false", "no", "off")

        def _opt_int(key: str, default: int | None) -> int | None:
            """None means "derive from warm_size"; an explicit 0 must survive as 0, so this
            cannot use the falsy-means-default shortcut."""
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid integer for {key}={raw!r}: {exc}") from exc

        def _opt_float(key: str, default: float | None) -> float | None:
            raw = os.environ.get(key, "").strip()
            if not raw:
                return default
            try:
                v = float(raw)
            except ValueError as exc:
                raise ValueError(f"invalid float for {key}={raw!r}: {exc}") from exc
            if not math.isfinite(v) or v < 0:
                # WARN AND FALL BACK -- the house convention, already documented for
                # BLASTBOX_CANARY_INTERVAL_S ("non-finite (nan, inf) and negative values fall back
                # to 900 with a warning"). Raising here instead was inconsistent twice over: with
                # that knob, and with this branch's own Ec2HibernateConfig.__post_init__, which
                # warns. It also turned a bad value in a LIVE deployment into a process that will
                # not start, which is a worse failure than the one being prevented.
                #
                # The value still cannot be honoured. Both directions misbehave silently: a
                # NEGATIVE interval makes `now - last >= interval` always true (an ec2-hibernate
                # pool then describes every tick and manufactures the throttling the limit exists
                # to avoid), and NaN makes every comparison against it False, which disables
                # whatever the knob gates. BLASTBOX_POOL_UNKNOWN_GRACE_S=nan did both at once: no
                # brownout exemption for WARMING slots, and idle unknowns that never aged out.
                # `0` is the documented "disabled" value.
                _log.warning(
                    "pool config: ignoring %s=%r (must be finite and >= 0); using %r. "
                    "Use 0 to disable.", key, raw, default)
                return default
            if v == 0 and key in _ZERO_IS_NOT_OFF:
                _log.warning(
                    "pool config: %s=0 would remove the rate limit rather than disable the seam "
                    "(every tick, ~10Hz); using %r. Raise it to slow the pool down.", key, default)
                return default
            return v

        values: dict[str, object] = {
            "max_consecutive_failures": _opt_int(
                "BLASTBOX_POOL_MAX_CONSECUTIVE_FAILURES", cls.max_consecutive_failures),
            "snapshot_rebuild_after": _opt_int(
                "BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", cls.snapshot_rebuild_after),
            "pre_guest_rebuild_after": _opt_int(
                "BLASTBOX_POOL_PRE_GUEST_REBUILD_AFTER", cls.pre_guest_rebuild_after),
            "max_evictions_per_window": _opt_int(
                "BLASTBOX_POOL_MAX_EVICTIONS_PER_WINDOW", cls.max_evictions_per_window),
            "unknown_grace_s": _opt_float(
                "BLASTBOX_POOL_UNKNOWN_GRACE_S", cls.unknown_grace_s),
            "maintain_interval_s": _opt_float(
                "BLASTBOX_POOL_MAINTAIN_INTERVAL_S", cls.maintain_interval_s),
            "maintain_budget_s": _opt_float(
                "BLASTBOX_POOL_MAINTAIN_BUDGET_S", cls.maintain_budget_s),
            "capacity_starved_after_s": _opt_float(
                "BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S", cls.capacity_starved_after_s),
            "runtime": os.environ.get("BLASTBOX_POOL_RUNTIME", cls.runtime).strip().lower(),
            "warm_size": _int("BLASTBOX_POOL_WARM_SIZE", cls.warm_size),
            "concurrent_ceiling": _int("BLASTBOX_POOL_CEILING", cls.concurrent_ceiling),
            "spawn_rate_limit": _float("BLASTBOX_POOL_SPAWN_RATE", cls.spawn_rate_limit),
            "spawn_concurrency": max(1, _int("BLASTBOX_POOL_SPAWN_CONCURRENCY", cls.spawn_concurrency)),
            "burst_size": _int("BLASTBOX_POOL_BURST_SIZE", cls.burst_size),
            "warming_timeout_s": _float("BLASTBOX_POOL_WARMING_TIMEOUT_S", cls.warming_timeout_s),
            "warm_snapshot": _bool("BLASTBOX_POOL_WARM_SNAPSHOT", cls.warm_snapshot),
        }
        values.update(overrides)
        cfg = cls(**values)  # type: ignore[arg-type]
        if cfg.warm_size < 0 or cfg.concurrent_ceiling < 1:
            raise ValueError("warm_size must be >= 0 and concurrent_ceiling >= 1")
        return cfg


def select_runtime_by_name(
    name: str, *, warm_snapshot: bool = False, require_available: bool = True
) -> Any:
    """Build one SlotRuntime for a backend name. Shared by ``build_warm_pool`` and the cascade tier
    builder. Network-endpoint tiers (aws/static) return slots that structurally diverge from the
    ``SlotRuntime`` Protocol's ``Slot`` -- WarmPool drives them fine (it touches only common fields),
    so this returns ``Any`` rather than sprinkling per-call ``type: ignore``."""
    if name == RUNTIME_FIRECRACKER:
        if warm_snapshot:
            from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime

            return select_snapshot_runtime(require_available=require_available)
        from blastbox.host.runtime.firecracker import select_fc_runtime

        return select_fc_runtime(require_available=require_available)
    if name == RUNTIME_GVISOR:
        from blastbox.host.runtime.gvisor_snapshot_runtime import select_gvisor_snapshot_runtime

        return select_gvisor_snapshot_runtime(require_available=require_available)
    if name == RUNTIME_AWS_LAMBDA_MICROVM:
        from blastbox.host.runtime.aws_worker import select_lambda_microvm_runtime

        return select_lambda_microvm_runtime(require_available=require_available)
    if name == RUNTIME_AWS_LAMBDA_SNAPSTART:
        from blastbox.host.runtime.aws_worker import select_lambda_snapstart_runtime

        return select_lambda_snapstart_runtime(require_available=require_available)
    if name == RUNTIME_AWS_EC2:
        from blastbox.host.runtime.aws_worker import select_disposable_ec2_runtime

        return select_disposable_ec2_runtime(require_available=require_available)
    if name == RUNTIME_AWS_EC2_HIBERNATE:
        from blastbox.host.runtime.aws_worker import select_ec2_hibernate_runtime

        return select_ec2_hibernate_runtime(require_available=require_available)
    if name == RUNTIME_STATIC:
        from blastbox.host.runtime.static_pool import select_static_pool_runtime

        return select_static_pool_runtime(require_available=require_available)
    raise ValueError(f"unknown pool runtime: {name!r}")


def _resolved_rebuild_after(cfg: PoolConfig) -> int:
    """The rebuild threshold BOTH the pool and its cascade must use.

    None means "derive from the feasible warm size" -- the same formula WarmPool applies -- not
    "let each consumer pick its own default".
    """
    if cfg.snapshot_rebuild_after is not None:
        return max(0, int(cfg.snapshot_rebuild_after))
    feasible = min(cfg.warm_size, cfg.concurrent_ceiling)
    return max(4, 2 * max(1, feasible))


def _configured_only(cfg: PoolConfig) -> dict[str, Any]:
    """Only the knobs the operator actually set.

    An unset knob must not be forwarded at all: copying WarmPool's default into this config is
    exactly how the two drifted once already (config said 3, the pool said 2, and every
    env-configured deployment silently changed behaviour while a comment claimed they matched).
    """
    candidates: dict[str, Any] = {
        "max_consecutive_failures": cfg.max_consecutive_failures,
        "unknown_grace_s": cfg.unknown_grace_s,
        "capacity_starved_after_s": cfg.capacity_starved_after_s,
        "maintain_interval_s": cfg.maintain_interval_s,
        "maintain_budget_s": cfg.maintain_budget_s,
    }
    return {k: v for k, v in candidates.items() if v is not None}


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
        if cfg.runtime == RUNTIME_CASCADE:
            from blastbox.host.runtime.cascade import build_cascade_runtime

            # Pass the RESOLVED value, not "let it re-read the environment". A caller using
            # PoolConfig.from_env(snapshot_rebuild_after=0) — the supported override — or
            # constructing a PoolConfig directly would otherwise have the outer pool honour 0
            # while per-tier repair silently fell back to its own default and kept invalidating
            # bases (upstream, PR #82).
            runtime = build_cascade_runtime(
                warm_snapshot=cfg.warm_snapshot,
                # DERIVE it here rather than forwarding None. build_cascade_runtime
                # substitutes a fixed 4, while WarmPool derives max(4, 2*warm_size) -- so on the
                # documented default (nothing configured) a cascade with warm_size > 2
                # invalidated tier bases far earlier than the pool-wide policy it is supposed to
                # follow. One resolved value, both paths (upstream, PR #82).
                tier_rebuild_after=_resolved_rebuild_after(cfg),
                # ...and say whether that number was DERIVED. Resolving it to an int made the
                # cascade record it as explicit, so _retune_runtime_thresholds refused to update
                # it: an autosized cascade resizing 4 -> 16 moved the pool to 32 while per-tier
                # repair stayed pinned at 8, invalidating healthy tier bases far earlier than the
                # documented live-size policy. Two of my own fixes cancelling out (PR #82).
                tier_rebuild_after_explicit=cfg.snapshot_rebuild_after is not None,
            )
        else:
            runtime = select_runtime_by_name(cfg.runtime, warm_snapshot=cfg.warm_snapshot)

    assert runtime is not None  # narrowed: every branch above returned/raised/assigned
    # The per-tier repair threshold is a property of the RUNTIME, not of how it was obtained, so
    # apply the config to an INJECTED one too. The block above only reaches a cascade this
    # function built; a caller using the supported runtime= injection with a CascadingRuntime kept
    # the cascade's own default of 4. That is not merely drift: an explicit cfg value makes
    # WarmPool record its own threshold as explicit, and _retune_runtime_thresholds then declines
    # to push anything down -- so PoolConfig(snapshot_rebuild_after=0), the documented incident
    # escape hatch, disabled pool-wide invalidation while the injected cascade went on
    # invalidating tier bases every four spawn failures. The hatch has to close EVERY rebuild
    # path (upstream, PR #82).
    if hasattr(runtime, "tier_rebuild_after"):
        _explicit = cfg.snapshot_rebuild_after is not None
        # An operator's value always wins. With nothing configured the number is DERIVED, and a
        # runtime the caller deliberately pinned keeps its own -- the same precedence the pool
        # applies to itself, rather than stomping an injected object's configuration.
        if _explicit or not getattr(runtime, "tier_rebuild_after_explicit", False):
            try:
                # setattr, not attribute syntax: this is an OPTIONAL runtime seam (only a cascade
                # carries it today), so the SlotRuntime protocol deliberately does not declare it.
                setattr(runtime, "tier_rebuild_after", _resolved_rebuild_after(cfg))  # noqa: B010
                setattr(runtime, "tier_rebuild_after_explicit", _explicit)            # noqa: B010
            except Exception as exc:  # noqa: BLE001 -- a read-only knob must not fail pool build
                _log.warning("pool_config.tier_rebuild_after_not_applied: %s", exc)
    # A slow-booting runtime (aws-ec2 first boot commonly >120s) declares its own readiness budget.
    # If the operator DIDN'T explicitly set the pool warming timeout, raise it to that budget so a
    # healthy-but-slow cloud slot isn't evicted + churned. An explicit env value always wins.
    warming_timeout_s = cfg.warming_timeout_s
    if os.environ.get("BLASTBOX_POOL_WARMING_TIMEOUT_S") is None:
        warming_timeout_s = max(warming_timeout_s, float(getattr(runtime, "readiness_timeout_s", 0.0)))
    pool = WarmPool(
        runtime=runtime,
        warm_size=cfg.warm_size,
        warming_timeout_s=warming_timeout_s,
        concurrent_ceiling=cfg.concurrent_ceiling,
        spawn_rate_limit=cfg.spawn_rate_limit,
        spawn_concurrency=cfg.spawn_concurrency,
        burst_size=cfg.burst_size,
        # snapshot_rebuild_after / max_evictions_per_window take None natively (it means
        # "derive from warm_size"), so they always forward. The rest use None as "unset", and an
        # unset knob must not be forwarded at all -- passing a copied literal is exactly how this
        # config drifted from the pool's own default once already.
        snapshot_rebuild_after=cfg.snapshot_rebuild_after,
        pre_guest_rebuild_after=cfg.pre_guest_rebuild_after,
        max_evictions_per_window=cfg.max_evictions_per_window,
        **_configured_only(cfg),
    )
    _log.info(
        "warm_pool_built runtime=%s warm_size=%d ceiling=%d warm_snapshot=%s",
        cfg.runtime,
        cfg.warm_size,
        cfg.concurrent_ceiling,
        cfg.warm_snapshot,
    )
    return pool
