"""Unit tests for the cascading (tiered) runtime -- local-then-overflow scaling."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from blastbox.host.pool import SlotRuntime
from blastbox.host.runtime.cascade import (
    CascadeExhausted,
    CascadeMisconfigured,
    CascadingRuntime,
    Tier,
    _parse_tiers,
    build_cascade_runtime,
)


@dataclass
class FakeSlot:
    slot_id: str


class FakeRuntime:
    """Minimal SlotRuntime: unlimited spawns (the cascade enforces capacity), tracks calls."""

    def __init__(self, name: str, fail_spawn: bool = False) -> None:
        self.name = name
        self.fail_spawn = fail_spawn
        self.spawned: list[FakeSlot] = []
        self.reaped: list[str] = []
        self._n = 0

    def spawn(self) -> FakeSlot:
        if self.fail_spawn:
            raise RuntimeError(f"{self.name} down")
        self._n += 1
        s = FakeSlot(f"{self.name}-{self._n}")
        self.spawned.append(s)
        return s

    def is_ready(self, slot: FakeSlot) -> bool:
        return True

    def is_alive(self, slot: FakeSlot) -> bool:
        return True

    def reap(self, slot: FakeSlot) -> None:
        self.reaped.append(slot.slot_id)


class WarmFileRuntime(FakeRuntime):
    """A file-handshake warm runtime that also implements the warm-transport hooks (like gvisor/fc)."""

    def host_warm_control(self, slot):
        return f"control:{slot.slot_id}"

    def stage_warm_input(self, slot, path):
        return f"staged:{path}"

    def materialize_warm_output(self, slot):
        self.materialized = slot.slot_id


class _PrepRuntime(FakeRuntime):
    def __init__(self, name, ready):
        super().__init__(name)
        self._ready, self.prepped = ready, 0

    def prepare(self):
        self.prepped += 1
        return self._ready


def test_cascade_prepare_ready_if_any_tier_ready():
    # a slow overflow snapshot build must NOT starve a ready primary -> prepare() is True if ANY tier is
    # ready, but EVERY tier's build is still kicked.
    a, b = _PrepRuntime("a", True), _PrepRuntime("b", False)
    rt = CascadingRuntime([Tier("a", a, 1), Tier("b", b, 1)])
    assert rt.prepare() is True                # a ready -> cascade can spawn (on a)
    assert a.prepped == 1 and b.prepped == 1   # BOTH kicked (all async builds start)


def test_cascade_prepare_false_when_no_tier_ready():
    a, b = _PrepRuntime("a", False), _PrepRuntime("b", False)
    rt = CascadingRuntime([Tier("a", a, 1), Tier("b", b, 1)])
    assert rt.prepare() is False


def test_cascade_prepare_true_without_prepare_tiers():
    rt = CascadingRuntime([Tier("a", FakeRuntime("a"), 1)])   # no prepare() -> always ready
    assert rt.prepare() is True


def test_cascade_spawn_skips_still_building_tier():
    # spawn must skip a tier whose prepare() is still False (building) and fill a ready tier instead of
    # blocking on the inner spawn().build().
    building, ready = _PrepRuntime("fc", False), _PrepRuntime("static", True)
    rt = CascadingRuntime([Tier("fc", building, 4), Tier("static", ready, 4)])
    slot = rt.spawn()
    assert slot.slot_id.startswith("static")   # routed to the ready tier, not the building primary
    assert building.spawned == []              # the building tier's spawn was never called
    building._ready = True
    # once fc is built it becomes spawnable (primary preference resumes on the next spawn)
    assert rt.spawn().slot_id.startswith("fc")


def test_cascade_resume_delegates_to_owning_tier():
    # a resume-based tier (aws-ec2-hibernate / snapstart) in a cascade must be woken on claim via the
    # owning tier's resume(); a tier without resume() is a no-op.
    class ResumeRuntime(FakeRuntime):
        def __init__(self, name):
            super().__init__(name)
            self.resumed = []

        def resume(self, slot):
            self.resumed.append(slot.slot_id)

    r, plain = ResumeRuntime("hib"), FakeRuntime("fc")
    rt = CascadingRuntime([Tier("hib", r, 1), Tier("fc", plain, 1)])
    s_r = rt.spawn()      # owned by the resume tier
    s_p = rt.spawn()      # owned by the plain tier
    rt.resume(s_r)
    assert r.resumed == [s_r.slot_id]        # delegated to the owning tier's resume
    rt.resume(s_p)                            # plain tier has no resume() -> no-op (must not raise)


def test_cascade_resume_propagates_owner_failure():
    class BoomResume(FakeRuntime):
        def resume(self, slot):
            raise RuntimeError("cannot wake")

    rt = CascadingRuntime([Tier("hib", BoomResume("hib"), 1)])
    slot = rt.spawn()
    with pytest.raises(RuntimeError, match="cannot wake"):
        rt.resume(slot)   # so _resume_on_claim retires the slot dirty


def test_cascade_is_alive_for_claim_delegates_fresh_hook():
    # a cascade wrapping an AWS tier must route the claim-time FRESH liveness to the owning tier's
    # is_alive_for_claim (cache-bypassing) -- else the pool falls back to the cascade's CACHED is_alive and
    # can hand out a slot AWS terminated between the health tick and the claim.
    class _FreshTier(FakeRuntime):
        def __init__(self, name):
            super().__init__(name)
            self.claim_checks = 0

        def is_alive(self, slot):        # cached / background-tick view: still alive
            return True

        def is_alive_for_claim(self, slot):
            self.claim_checks += 1
            return False                 # fresh view: terminated since the last tick

    aws = _FreshTier("aws")
    rt = CascadingRuntime([Tier("aws", aws, 1)])
    slot = rt.spawn()
    assert rt.is_alive(slot) is True             # cached delegate
    assert rt.is_alive_for_claim(slot) is False  # FRESH delegate reached the tier's hook
    assert aws.claim_checks == 1
    # a tier WITHOUT the hook (file/libvirt) falls back to its is_alive (already fresh)
    rt2 = CascadingRuntime([Tier("fc", FakeRuntime("fc"), 1)])
    assert rt2.is_alive_for_claim(rt2.spawn()) is True


def test_cascade_cli_timeout_s_aggregates_max_across_tiers():
    # I1: a cascade has no single cfg; it exposes the MAX per-CLI-call timeout across wrapped tiers so the
    # dispatcher factory can budget the post-job terminate for cascaded AWS tiers (mirrors resume_timeout_s).
    class _Cfg:
        def __init__(self, v):
            self.cli_timeout_s = v

    class CfgRuntime(FakeRuntime):
        def __init__(self, name, v):
            super().__init__(name)
            self.cfg = _Cfg(v)

    class AttrRuntime(FakeRuntime):
        cli_timeout_s = 90.0

    plain = FakeRuntime("fc")
    assert CascadingRuntime([Tier("fc", plain, 1)]).cli_timeout_s is None   # no AWS tier -> None
    rt = CascadingRuntime([
        Tier("ec2", CfgRuntime("ec2", 120.0), 1),
        Tier("snap", AttrRuntime("snap"), 1),
        Tier("fc", plain, 1),
    ])
    assert rt.cli_timeout_s == 120.0   # max(120 via cfg, 90 via attr)


def test_cascade_resume_timeout_s_aggregates_max_across_tiers():
    # a cascade has no single cfg; it exposes the MAX in-claim resume budget so the dispatcher factory
    # can still warn when a wrapped tier's resume budget outlasts the per-job budget. Reads cfg.* AND a
    # plain resume_timeout_s attr; None when no tier resumes on claim.
    class _Cfg:
        def __init__(self, v):
            self.resume_timeout_s = v

    class CfgRuntime(FakeRuntime):
        def __init__(self, name, v):
            super().__init__(name)
            self.cfg = _Cfg(v)

    class AttrRuntime(FakeRuntime):
        resume_timeout_s = 45.0

    plain = FakeRuntime("fc")
    assert CascadingRuntime([Tier("fc", plain, 1)]).resume_timeout_s is None   # no resume tier
    rt = CascadingRuntime([
        Tier("hib", CfgRuntime("hib", 120.0), 1),
        Tier("snap", AttrRuntime("snap"), 1),
        Tier("fc", plain, 1),
    ])
    assert rt.resume_timeout_s == 120.0   # max(120 via cfg, 45 via attr)


def test_cascade_delegates_warm_hooks_to_owning_tier():
    # an all-file cascade must route host_warm_control/stage_warm_input/materialize_warm_output to the
    # tier that owns the slot -- else gVisor/FC jobs get the wrong input/output transport.
    a, b = WarmFileRuntime("gvisor"), WarmFileRuntime("fc")
    rt = CascadingRuntime([Tier("gvisor", a, 1), Tier("fc", b, 1)])
    s_a = rt.spawn()   # owned by tier gvisor
    s_b = rt.spawn()   # owned by tier fc
    assert rt.host_warm_control(s_a) == f"control:{s_a.slot_id}"
    assert rt.stage_warm_input(s_b, "/in/x") == "staged:/in/x"
    rt.materialize_warm_output(s_b)
    assert b.materialized == s_b.slot_id


def test_cascade_warm_hook_missing_on_tier_raises():
    # a file cascade whose tier can't do the warm handshake fails fast rather than silently mis-routing.
    plain = FakeRuntime("plain")   # no host_warm_control
    rt = CascadingRuntime([Tier("plain", plain, 1)])
    slot = rt.spawn()
    with pytest.raises(CascadeMisconfigured):
        rt.host_warm_control(slot)


# --------------------------------------------------------------- routing

def test_spawn_fills_primary_then_overflows():
    a, b = FakeRuntime("a"), FakeRuntime("b")
    rt = CascadingRuntime([Tier("a", a, 2), Tier("b", b, 3)])
    slots = [rt.spawn() for _ in range(4)]
    assert [s.slot_id for s in slots[:2]] == ["a-1", "a-2"]      # primary filled first
    assert all(s.slot_id.startswith("b") for s in slots[2:])     # then overflow
    assert len(a.spawned) == 2 and len(b.spawned) == 2


def test_exhausted_when_all_tiers_full():
    a = FakeRuntime("a")
    rt = CascadingRuntime([Tier("a", a, 1)])
    rt.spawn()
    with pytest.raises(CascadeExhausted):
        rt.spawn()


def test_reap_frees_capacity_on_owning_tier():
    a = FakeRuntime("a")
    rt = CascadingRuntime([Tier("a", a, 1)])
    s = rt.spawn()
    with pytest.raises(CascadeExhausted):
        rt.spawn()
    rt.reap(s)
    rt.spawn()                      # freed slot reclaimed
    assert a.reaped == ["a-1"] and len(a.spawned) == 2


def test_spawn_falls_through_on_tier_failure():
    a, b = FakeRuntime("a", fail_spawn=True), FakeRuntime("b")
    rt = CascadingRuntime([Tier("a", a, 2), Tier("b", b, 2)])
    s = rt.spawn()
    assert s.slot_id.startswith("b")            # tier a raised -> routed to b
    assert rt._counts[0] == 0 and rt._counts[1] == 1   # a's reservation released


def test_delegates_ready_alive_reap_to_owner():
    a, b = FakeRuntime("a"), FakeRuntime("b")
    rt = CascadingRuntime([Tier("a", a, 1), Tier("b", b, 1)])
    sa, sb = rt.spawn(), rt.spawn()
    assert rt.is_ready(sa) and rt.is_alive(sb)
    rt.reap(sb)
    assert b.reaped == ["b-1"] and a.reaped == []   # only the owning tier reaped


def test_reap_unknown_slot_is_noop():
    a = FakeRuntime("a")
    rt = CascadingRuntime([Tier("a", a, 1)])
    rt.reap(FakeSlot("ghost"))
    assert a.reaped == []


def test_satisfies_slotruntime_protocol():
    rt = CascadingRuntime([Tier("a", FakeRuntime("a"), 1)])
    assert isinstance(rt, SlotRuntime)


def test_cascade_dispatch_style_homogeneous():
    a, b = FakeRuntime("a"), FakeRuntime("b")
    a.dispatch_style = b.dispatch_style = "network"        # type: ignore[attr-defined]
    assert CascadingRuntime([Tier("a", a, 1), Tier("b", b, 1)]).dispatch_style == "network"


def test_cascade_dispatch_style_defaults_file():
    # a runtime without dispatch_style (fc/gvisor) is "file"
    assert CascadingRuntime([Tier("a", FakeRuntime("a"), 1)]).dispatch_style == "file"


def test_cascade_dispatch_style_mixed_raises():
    net = FakeRuntime("net")
    net.dispatch_style = "network"                         # type: ignore[attr-defined]
    rt = CascadingRuntime([Tier("net", net, 1), Tier("file", FakeRuntime("file"), 1)])
    with pytest.raises(CascadeMisconfigured):
        _ = rt.dispatch_style   # can't mix transports in one job


def test_cascade_exposes_inner_ssl_context():
    a = FakeRuntime("a")
    a.dispatch_style = "network"                           # type: ignore[attr-defined]
    a.ssl_context = "CTX"                                  # type: ignore[attr-defined]
    assert CascadingRuntime([Tier("a", a, 1)]).ssl_context == "CTX"


def test_cascade_ssl_context_none_when_absent():
    assert CascadingRuntime([Tier("a", FakeRuntime("a"), 1)]).ssl_context is None


def test_cascade_ssl_context_mixed_mtls_and_public_tls_raises():
    # a worker-mTLS tier (private CA context) + a public-TLS Lambda tier (no context) can't share
    # one transport context -- fail fast rather than silently verifying one and not the other.
    mtls = FakeRuntime("static")
    mtls.dispatch_style = "network"                        # type: ignore[attr-defined]
    mtls.ssl_context = "CTX"                               # type: ignore[attr-defined]
    lam = FakeRuntime("lambda")
    lam.dispatch_style = "network"                         # type: ignore[attr-defined]
    lam.ssl_context = None                                 # type: ignore[attr-defined]
    with pytest.raises(CascadeMisconfigured):
        _ = CascadingRuntime([Tier("static", mtls, 1), Tier("lambda", lam, 1)]).ssl_context


def test_empty_tiers_rejected():
    with pytest.raises(CascadeMisconfigured):
        CascadingRuntime([])


# --------------------------------------------------------------- spec parsing

def test_parse_tiers_ok():
    assert _parse_tiers("gvisor:4, aws-ec2:16 ") == [("gvisor", 4), ("aws-ec2", 16)]


@pytest.mark.parametrize("bad", ["gvisor", "gvisor:x", "gvisor:0", "gvisor:-1", ":4"])
def test_parse_tiers_bad(bad):
    with pytest.raises(CascadeMisconfigured):
        _parse_tiers(bad)


# --------------------------------------------------------------- build_cascade_runtime

def test_build_primary_unavailable_raises(monkeypatch):
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        raise RuntimeError(f"{name} unavailable")

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    with pytest.raises(CascadeMisconfigured):
        build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)


def test_build_overflow_unavailable_is_skipped(monkeypatch):
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            raise RuntimeError("no aws creds")
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [t.name for t in rt.tiers] == ["gvisor"]      # local came up; cloud overflow skipped


def test_build_empty_spec_raises():
    with pytest.raises(CascadeMisconfigured):
        build_cascade_runtime({"BLASTBOX_POOL_TIERS": ""}.get)


def test_pool_config_registers_cascade(monkeypatch):
    """build_warm_pool must reach the cascade branch (CascadeMisconfigured), not 'unknown pool runtime'."""
    from blastbox.host import pool_config

    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "cascade")
    monkeypatch.setenv("BLASTBOX_POOL_TIERS", "")   # empty -> CascadeMisconfigured proves it's wired
    cfg = pool_config.PoolConfig.from_env()
    with pytest.raises(CascadeMisconfigured):
        pool_config.build_warm_pool(cfg=cfg)
