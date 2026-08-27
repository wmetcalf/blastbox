"""Tests for the warm-pool config + factory (host/pool_config.py)."""
from __future__ import annotations

import os

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


def test_build_pool_bumps_warming_timeout_from_runtime_readiness(monkeypatch):
    """A slow-booting runtime (e.g. aws-ec2, readiness 300s) raises the pool warming timeout when the
    operator didn't set BLASTBOX_POOL_WARMING_TIMEOUT_S, so a healthy-but-slow slot isn't churned."""
    monkeypatch.delenv("BLASTBOX_POOL_WARMING_TIMEOUT_S", raising=False)

    class _SlowRuntime(_FakeRuntime):
        readiness_timeout_s = 300.0

    cfg = PoolConfig(runtime=RUNTIME_FIRECRACKER, warm_size=1, concurrent_ceiling=1)  # default warming 120
    pool = build_warm_pool(cfg, runtime=_SlowRuntime())
    assert pool._warming_timeout_s == 300.0


def test_build_pool_explicit_warming_timeout_wins(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_WARMING_TIMEOUT_S", "90")

    class _SlowRuntime(_FakeRuntime):
        readiness_timeout_s = 300.0

    cfg = PoolConfig.from_env(runtime=RUNTIME_FIRECRACKER, warm_size=1, concurrent_ceiling=1)
    pool = build_warm_pool(cfg, runtime=_SlowRuntime())
    assert pool._warming_timeout_s == 90.0   # operator override is NOT overridden by the runtime budget


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


def test_the_safety_controls_are_reachable_from_the_environment(monkeypatch):
    """Production pools are built by build_warm_pool() from PoolConfig.from_env().

    These knobs decide when the pool evicts a slot or destroys and rebuilds a snapshot base.
    Reachable only from the constructor, they were untunable in every real deployment.
    """
    monkeypatch.setenv("BLASTBOX_POOL_MAX_CONSECUTIVE_FAILURES", "7")
    monkeypatch.setenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", "9")
    monkeypatch.setenv("BLASTBOX_POOL_MAX_EVICTIONS_PER_WINDOW", "5")
    monkeypatch.setenv("BLASTBOX_POOL_UNKNOWN_GRACE_S", "42.5")
    monkeypatch.setenv("BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S", "77.5")

    cfg = PoolConfig.from_env()
    assert cfg.max_consecutive_failures == 7
    assert cfg.snapshot_rebuild_after == 9
    assert cfg.max_evictions_per_window == 5
    assert cfg.unknown_grace_s == 42.5
    assert cfg.capacity_starved_after_s == 77.5


def test_the_rebuild_escape_hatch_survives_env_parsing(monkeypatch):
    """`snapshot_rebuild_after=0` disables automatic base invalidation — documented, and the
    thing an operator reaches for during an incident. It must not be swallowed as "unset": 0 is
    falsy, so the usual "empty means default" shortcut silently re-enables the behaviour the
    operator just turned off."""
    monkeypatch.setenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", "0")
    assert PoolConfig.from_env().snapshot_rebuild_after == 0

    # and unset still means "derive from warm_size", not 0
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)
    assert PoolConfig.from_env().snapshot_rebuild_after is None


def test_build_warm_pool_forwards_the_safety_controls(monkeypatch):
    """Declaring the fields is only half of it — the factory must actually pass them.

    A config field that is parsed but never forwarded looks correct in every config test while
    the running pool quietly keeps its defaults.
    """
    monkeypatch.setenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", "9")
    monkeypatch.setenv("BLASTBOX_POOL_MAX_EVICTIONS_PER_WINDOW", "5")
    monkeypatch.setenv("BLASTBOX_POOL_MAX_CONSECUTIVE_FAILURES", "7")
    monkeypatch.setenv("BLASTBOX_POOL_UNKNOWN_GRACE_S", "42.5")
    monkeypatch.setenv("BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S", "77.5")

    class _Rt:
        def spawn(self): raise RuntimeError("not used")
        def is_ready(self, slot): return True
        def is_alive(self, slot): return True
        def reap(self, slot): return None

    pool = build_warm_pool(PoolConfig.from_env(runtime="none"), runtime=_Rt())
    assert pool is not None
    assert pool._snapshot_rebuild_after == 9
    assert pool._max_evictions_per_window == 5
    assert pool._max_consecutive_failures == 7
    assert pool._unknown_grace_s == 42.5
    assert pool._capacity_starved_after_s == 77.5


def test_unset_knobs_do_not_override_the_pools_own_defaults(monkeypatch):
    """A config default that COPIES the pool's default is a drift bug waiting to happen.

    It already happened: this config said max_consecutive_failures=3 while WarmPool said 2, so
    every env-configured deployment silently sent a third job to a repeatedly failing slot —
    with an adjacent comment asserting the two matched. Compare against the constructor itself,
    so the test fails if either side moves rather than encoding a third copy of the number.
    """
    import inspect

    for var in ("BLASTBOX_POOL_MAX_CONSECUTIVE_FAILURES",
                "BLASTBOX_POOL_UNKNOWN_GRACE_S",
                "BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S"):
        monkeypatch.delenv(var, raising=False)

    class _Rt:
        def spawn(self): raise RuntimeError("not used")
        def is_ready(self, slot): return True
        def is_alive(self, slot): return True
        def reap(self, slot): return None

    pool = build_warm_pool(PoolConfig.from_env(runtime="none"), runtime=_Rt())
    assert pool is not None

    params = inspect.signature(WarmPool.__init__).parameters
    for attr, arg in (("_max_consecutive_failures", "max_consecutive_failures"),
                      ("_unknown_grace_s", "unknown_grace_s"),
                      ("_capacity_starved_after_s", "capacity_starved_after_s")):
        assert getattr(pool, attr) == params[arg].default, (
            f"{arg}: an unconfigured knob must leave WarmPool's own default "
            f"({params[arg].default}) alone, got {getattr(pool, attr)}"
        )


def test_the_rebuild_escape_hatch_also_disables_cascade_tier_repair(monkeypatch):
    """The escape hatch must disable EVERY path that can invalidate a base.

    Per-tier cascade repair is a second, independently-triggered invalidation route. An operator
    who set BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER=0 during an incident would still have had tier
    bases destroyed under them, because build_cascade_runtime() hard-coded its own threshold.
    """
    from blastbox.host.runtime.cascade import build_cascade_runtime

    # Resolve any tier name to a stub: this test is about the CONFIG reaching the cascade, not
    # about which runtimes happen to be installed on the test host.
    monkeypatch.setattr(
        "blastbox.host.pool_config.select_runtime_by_name",
        lambda name, **kw: object(),
    )
    env = {"BLASTBOX_POOL_TIERS": "stub:1"}
    getter = lambda k: env.get(k) or os.environ.get(k)  # noqa: E731

    monkeypatch.setenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", "0")
    assert build_cascade_runtime(getter).tier_rebuild_after == 0, (
        "0 must disable per-tier repair too"
    )

    monkeypatch.setenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", "9")
    assert build_cascade_runtime(getter).tier_rebuild_after == 9, (
        "an explicit threshold must reach the cascade"
    )

    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)
    assert build_cascade_runtime(getter).tier_rebuild_after == 4, "unset keeps the default"


def test_a_resolved_config_override_reaches_cascade_tier_repair(monkeypatch):
    """The factory must pass the RESOLVED value, not let the cascade re-read the environment.

    PoolConfig.from_env(snapshot_rebuild_after=0) is the supported override, and a PoolConfig can
    be constructed directly — in both cases the outer pool honoured 0 while per-tier repair fell
    back to its own default and kept invalidating bases.
    """
    captured: dict[str, object] = {}

    def _fake_cascade(get=None, *, warm_snapshot=False, tier_rebuild_after=None,
                      tier_rebuild_after_explicit=None):
        captured["tier_rebuild_after"] = tier_rebuild_after
        return type("R", (), {"spawn": lambda s: None, "is_ready": lambda s, x: True,
                              "is_alive": lambda s, x: True, "reap": lambda s, x: None})()

    monkeypatch.setattr("blastbox.host.runtime.cascade.build_cascade_runtime", _fake_cascade)
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)

    # Explicit override, NOT via the environment — this is the case that used to be lost.
    cfg = PoolConfig.from_env(runtime="cascade", snapshot_rebuild_after=0)
    build_warm_pool(cfg)
    assert captured["tier_rebuild_after"] == 0, (
        "a resolved 0 must disable per-tier repair, not fall back to the env/default"
    )


def test_the_cascade_threshold_is_derived_the_same_way_as_the_pools(monkeypatch):
    """One policy, two consumers.

    With nothing configured — the documented default — cfg.snapshot_rebuild_after is None.
    Forwarding that None made build_cascade_runtime substitute a fixed 4 while WarmPool derived
    max(4, 2*warm_size), so a cascade with warm_size > 2 invalidated tier bases far earlier than
    the pool-wide policy it is meant to follow.
    """
    captured: dict[str, object] = {}

    def _fake_cascade(get=None, *, warm_snapshot=False, tier_rebuild_after=None,
                      tier_rebuild_after_explicit=None):
        captured["tier_rebuild_after"] = tier_rebuild_after
        return type("R", (), {"spawn": lambda s: None, "is_ready": lambda s, x: True,
                              "is_alive": lambda s, x: True, "reap": lambda s, x: None})()

    monkeypatch.setattr("blastbox.host.runtime.cascade.build_cascade_runtime", _fake_cascade)
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)

    cfg = PoolConfig.from_env(runtime="cascade", warm_size=8, concurrent_ceiling=16)
    pool = build_warm_pool(cfg)
    assert pool is not None
    assert captured["tier_rebuild_after"] == pool._snapshot_rebuild_after == 16, (
        f"cascade got {captured['tier_rebuild_after']}, pool derived "
        f"{pool._snapshot_rebuild_after} — they must be one policy"
    )


def test_resize_retunes_the_cascade_threshold(monkeypatch):
    """One policy, both consumers — at resize as well as construction.

    The autosizer moves warm_size in production. The cascade keeps its OWN per-tier copy, so
    after a 4->16 resize per-tier repair still fired at 8 while the pool-wide policy had moved to
    32 (and downsizing gave the reverse delay).
    """
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _Rt:
        def prepare(self): return True
        def spawn(self): raise RuntimeError("unused")
        def is_ready(self, slot): return True
        def is_alive(self, slot): return True
        def reap(self, slot): return None

    casc = CascadingRuntime(tiers=[Tier(name="a", runtime=_Rt(), capacity=4)])
    assert casc.tier_rebuild_after == 4, "derived default"

    pool = WarmPool(runtime=casc, warm_size=4, concurrent_ceiling=32)
    assert casc.tier_rebuild_after == pool._snapshot_rebuild_after

    pool.resize(warm_size=16)
    assert casc.tier_rebuild_after == pool._snapshot_rebuild_after == 32, (
        f"cascade kept {casc.tier_rebuild_after} while the pool moved to "
        f"{pool._snapshot_rebuild_after}"
    )

    pool.resize(warm_size=1)
    assert casc.tier_rebuild_after == pool._snapshot_rebuild_after == 4


def test_an_explicit_cascade_threshold_is_never_retuned():
    """An explicitly pinned value is the caller's decision, exactly as for the pool's own."""
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _Rt:
        def prepare(self): return True
        def spawn(self): raise RuntimeError("unused")
        def is_ready(self, slot): return True
        def is_alive(self, slot): return True
        def reap(self, slot): return None

    casc = CascadingRuntime(tiers=[Tier(name="a", runtime=_Rt(), capacity=4)],
                            tier_rebuild_after=7)
    pool = WarmPool(runtime=casc, warm_size=4, concurrent_ceiling=32)
    pool.resize(warm_size=16)
    assert casc.tier_rebuild_after == 7, "a pinned threshold must survive every resize"


def test_a_derived_cascade_threshold_is_still_retunable(monkeypatch):
    """Resolving the derived default to an int made the cascade call it EXPLICIT.

    _retune_runtime_thresholds then refused to update it, so an autosized cascade resizing 4 -> 16
    moved the pool-wide threshold to 32 while per-tier repair stayed pinned at 8 — two fixes of
    mine cancelling each other out. The factory has to say where its number CAME FROM, not just
    what it is.
    """
    captured: dict[str, object] = {}

    def _fake_cascade(get=None, *, warm_snapshot=False, tier_rebuild_after=None,
                      tier_rebuild_after_explicit=None):
        captured["after"] = tier_rebuild_after
        captured["explicit"] = tier_rebuild_after_explicit
        return type("R", (), {"spawn": lambda s: None, "is_ready": lambda s, x: True,
                              "is_alive": lambda s, x: True, "reap": lambda s, x: None})()

    monkeypatch.setattr("blastbox.host.runtime.cascade.build_cascade_runtime", _fake_cascade)
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)

    # Nothing configured: the 16 below is DERIVED from warm_size and must stay retunable.
    cfg = PoolConfig.from_env(runtime="cascade", warm_size=8, concurrent_ceiling=16)
    build_warm_pool(cfg)
    assert captured["after"] == 16
    assert captured["explicit"] is False, (
        "a value derived from warm_size must not be recorded as an operator's choice — "
        "_retune_runtime_thresholds skips explicit values, so the autosizer could never move it"
    )

    # An operator's number stays pinned.
    cfg = PoolConfig.from_env(runtime="cascade", warm_size=8, concurrent_ceiling=16,
                              snapshot_rebuild_after=7)
    build_warm_pool(cfg)
    assert captured["after"] == 7
    assert captured["explicit"] is True


def test_build_cascade_runtime_honours_the_explicit_flag(monkeypatch):
    """The other half of the fix: the factory must actually forward what it was told."""
    from blastbox.host.runtime.cascade import build_cascade_runtime

    # build_cascade_runtime imports this lazily from pool_config, so patch it there.
    monkeypatch.setattr("blastbox.host.pool_config.select_runtime_by_name",
                        lambda name, **kw: type("R", (), {"spawn": lambda s: None})())
    env = {"BLASTBOX_POOL_TIERS": "stub:2"}
    getter = lambda k: env.get(k) or os.environ.get(k)  # noqa: E731

    derived = build_cascade_runtime(getter, tier_rebuild_after=8,
                                    tier_rebuild_after_explicit=False)
    assert derived.tier_rebuild_after_explicit is False
    pinned = build_cascade_runtime(getter, tier_rebuild_after=7,
                                   tier_rebuild_after_explicit=True)
    assert pinned.tier_rebuild_after_explicit is True


def test_an_injected_cascade_gets_the_configured_rebuild_threshold(monkeypatch):
    """The escape hatch has to close EVERY rebuild path.

    The threshold plumbing lived inside the `runtime is None` branch, so a caller using the
    supported runtime= injection with a CascadingRuntime kept the cascade's own default of 4.
    An explicit cfg value also makes WarmPool record its threshold as explicit, and
    _retune_runtime_thresholds then declines to push anything down — so
    PoolConfig(snapshot_rebuild_after=0) disabled pool-wide invalidation while the injected
    cascade went on invalidating tier bases every four spawn failures.
    """
    class _InjectedCascade:
        tier_rebuild_after = 4                     # the cascade's own default
        tier_rebuild_after_explicit = False

        def spawn(self): return None
        def is_ready(self, s): return True
        def is_alive(self, s): return True
        def reap(self, s): return None

    rt = _InjectedCascade()
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)
    cfg = PoolConfig.from_env(snapshot_rebuild_after=0)
    pool = build_warm_pool(cfg, runtime=rt)
    assert pool is not None
    assert pool._snapshot_rebuild_after == 0       # the hatch closed the pool-wide path...
    assert rt.tier_rebuild_after == 0, (
        "...but the injected cascade kept invalidating tier bases every 4 spawn failures"
    )
    assert rt.tier_rebuild_after_explicit is True


def test_an_injected_cascade_the_caller_pinned_is_not_stomped(monkeypatch):
    """With nothing configured the number is DERIVED — it must not overwrite a caller's own."""
    class _PinnedCascade:
        tier_rebuild_after = 7
        tier_rebuild_after_explicit = True

        def spawn(self): return None
        def is_ready(self, s): return True
        def is_alive(self, s): return True
        def reap(self, s): return None

    rt = _PinnedCascade()
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)
    build_warm_pool(PoolConfig.from_env(warm_size=8, concurrent_ceiling=16), runtime=rt)
    assert rt.tier_rebuild_after == 7


def test_an_unpinned_injected_cascade_follows_the_derived_policy(monkeypatch):
    """One policy, both consumers — the injected path included."""
    class _UnpinnedCascade:
        tier_rebuild_after = 4
        tier_rebuild_after_explicit = False

        def spawn(self): return None
        def is_ready(self, s): return True
        def is_alive(self, s): return True
        def reap(self, s): return None

    rt = _UnpinnedCascade()
    monkeypatch.delenv("BLASTBOX_POOL_SNAPSHOT_REBUILD_AFTER", raising=False)
    pool = build_warm_pool(PoolConfig.from_env(warm_size=8, concurrent_ceiling=16), runtime=rt)
    assert pool is not None
    assert rt.tier_rebuild_after == pool._snapshot_rebuild_after == 16


def test_a_config_float_that_parses_but_cannot_mean_anything_is_rejected(monkeypatch):
    """Every numeric knob, not just the two that had a caller-side clamp.

    A float knob has exactly two ways to parse and still be meaningless, and each breaks a
    DIFFERENT direction of the comparison it feeds:
      * NEGATIVE interval/grace -> `now - last >= interval` is ALWAYS true, so the thing the knob
        rate-limits runs every tick. On an ec2-hibernate pool that means an uncached describe per
        tick, i.e. the pool manufactures the throttling the limit exists to prevent.
      * NaN -> every comparison against it is False, so whatever the knob gates silently never
        happens. BLASTBOX_POOL_UNKNOWN_GRACE_S=nan did BOTH at once: WARMING slots got no brownout
        exemption, and idle UNKNOWN slots never aged out.

    Only maintain_interval_s and maintain_budget_s were clamped, and only because they were added
    with a clamp; the four older knobs (spawn_rate, warming_timeout_s, unknown_grace_s,
    capacity_starved_after_s) took anything float() accepted. Validating at each CONSUMER is what
    produced that gap, so the check lives in the env readers -- which already raise on an
    unparseable value, making this the same contract, not a new one.

    Warn-and-fall-back rather than raise, matching the house convention already documented for
    BLASTBOX_CANARY_INTERVAL_S ("non-finite (nan, inf) and negative values fall back to 900 with a
    warning") and this branch's own Ec2HibernateConfig. Raising would turn a bad value in a LIVE
    deployment into a process that will not start -- a worse failure than the one being prevented.

    MUTATION: delete the isfinite/`< 0` guard in _float/_opt_float and every case here is honoured.
    """
    attrs = {"BLASTBOX_POOL_SPAWN_RATE": "spawn_rate_limit",
             "BLASTBOX_POOL_WARMING_TIMEOUT_S": "warming_timeout_s",
             "BLASTBOX_POOL_UNKNOWN_GRACE_S": "unknown_grace_s",
             "BLASTBOX_POOL_CAPACITY_STARVED_AFTER_S": "capacity_starved_after_s",
             "BLASTBOX_POOL_MAINTAIN_INTERVAL_S": "maintain_interval_s",
             "BLASTBOX_POOL_MAINTAIN_BUDGET_S": "maintain_budget_s"}
    defaults = {k: getattr(PoolConfig.from_env(), a) for k, a in attrs.items()}

    for key, attr in attrs.items():
        for bad in ("nan", "inf", "-inf", "-1"):
            monkeypatch.setenv(key, bad)
            got = getattr(PoolConfig.from_env(), attr)
            assert got == defaults[key] or (got is None and defaults[key] is None), (
                f"{key}={bad!r} was honoured as {got!r} instead of falling back to "
                f"{defaults[key]!r}")
            monkeypatch.delenv(key)

    # 0 stays legal -- it is the documented "disabled" -- EXCEPT for the one knob where
    # "disabled" would mean the UNBOUNDED rate. `now - last >= 0` is true on every tick, so
    # BLASTBOX_POOL_MAINTAIN_INTERVAL_S=0 removes the rate limit instead of the seam: an uncached
    # describe per idle slot at ~10Hz, manufacturing the throttling the knob exists to prevent,
    # for an operator who typed 0 meaning "off" -- mid-incident, which is when they reach for it.
    zero_is_not_off = {"BLASTBOX_POOL_MAINTAIN_INTERVAL_S"}
    for key, attr in attrs.items():
        monkeypatch.setenv(key, "0")
        got = getattr(PoolConfig.from_env(), attr)
        if key in zero_is_not_off:
            assert got != 0.0, (
                f"{key}=0 was honoured as a zero cooldown, i.e. maintenance on EVERY tick")
        else:
            assert got == 0.0
        monkeypatch.delenv(key)

    for key, attr in attrs.items():   # ...and a real value is still honoured
        monkeypatch.setenv(key, "12.5")
        assert getattr(PoolConfig.from_env(), attr) == 12.5
        monkeypatch.delenv(key)
