"""Unit tests for the cascading (tiered) runtime -- local-then-overflow scaling."""

from __future__ import annotations

from types import SimpleNamespace

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


def test_cascade_forwards_unknown_liveness_unchanged():
    # issue #77: cascade is the wrapper the AWS tiers actually run under, so it is the real path
    # the UNKNOWN tri-state travels. It must forward None unchanged — collapsing it to a bool would
    # turn "the control plane didn't answer" into "destroy this healthy worker".
    class _UnknownTier:
        kind = "aws-lambda-microvm"

        def __init__(self):
            self.n = 0

        def spawn(self):
            self.n += 1
            return FakeSlot(f"unknown-{self.n}")

        def is_ready(self, slot):
            return True

        def is_alive(self, slot):
            return True                      # the CACHED view still says alive

        def is_alive_for_claim(self, slot):
            return None                      # the FRESH view couldn't answer

        def reap(self, slot):
            pass

    tier_rt = _UnknownTier()
    rt = CascadingRuntime([Tier("aws-lambda-microvm", tier_rt, 1)])
    slot = rt.spawn()                        # cascade records tier ownership on spawn
    assert rt.is_alive_for_claim(slot) is None, "cascade collapsed UNKNOWN into a bool"


def test_cascade_forwards_the_resume_budget():
    """The claim window's remaining time must reach the owning tier, or a slow resume still burns
    the whole window in the production (cascaded) shape."""
    class BudgetResume(FakeRuntime):
        def __init__(self, name):
            super().__init__(name)
            self.budgets = []

        def resume(self, slot, *, budget_s=None):
            self.budgets.append(budget_s)

    r = BudgetResume("hib")
    rt = CascadingRuntime([Tier("hib", r, 1)])
    slot = rt.spawn()
    rt.resume(slot, budget_s=1.25)
    assert r.budgets == [1.25], f"claim budget did not reach the tier: {r.budgets}"


def test_cascade_does_not_retry_resume_when_the_tier_itself_raises():
    """The try guarding inspect.signature used to wrap the CALL too, so a TypeError raised INSIDE
    resume() was mistaken for an introspection failure and resume -- which issues resume-microvm /
    start-instances and clears auth_token -- ran a SECOND time, unbudgeted."""
    calls = []

    class BoomBudgetResume(FakeRuntime):
        def resume(self, slot, *, budget_s=None):
            calls.append(budget_s)
            raise TypeError("bug while parsing the resume response")

    rt = CascadingRuntime([Tier("hib", BoomBudgetResume("hib"), 1)])
    slot = rt.spawn()
    with pytest.raises(TypeError):
        rt.resume(slot, budget_s=0.5)
    assert calls == [0.5], f"a side-effecting resume was retried unbudgeted: {calls}"


def test_spawn_raises_a_FAULT_when_attempted_tiers_fail_and_CAPACITY_when_merely_full():
    """The type itself is the contract, independent of any downstream repair.

    CascadingRuntime.spawn() raises one exception for two opposite conditions unless it is
    careful: "every tier is full" (routine backpressure) and "every tier tried and threw" (a
    corrupt base restores nowhere). Making both a capacity type once disabled base repair for
    every cascaded deployment. Per-tier repair now also covers that case, so this asserts the
    type DIRECTLY — otherwise the second safety net silently hides the loss of the first.
    """
    from blastbox.host.pool import RuntimeAtCapacity
    from blastbox.host.runtime.cascade import (
        CascadeExhausted,
        CascadeSpawnFailed,
        CascadingRuntime,
        Tier,
    )

    class _Broken:
        def prepare(self): return True
        def spawn(self): raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    class _Fine:
        def __init__(self): self.n = 0
        def prepare(self): return True
        def spawn(self):
            self.n += 1
            return SimpleNamespace(slot_id=f"s{self.n}")

    # every ATTEMPTED tier threw -> a fault, and explicitly NOT a capacity type
    broken = CascadingRuntime(tiers=[Tier(name="fc", runtime=_Broken(), capacity=4)],
                              tier_rebuild_after=0)   # isolate from per-tier repair
    with pytest.raises(CascadeSpawnFailed) as ei:
        broken.spawn()
    assert not isinstance(ei.value, RuntimeAtCapacity), (
        "a total spawn failure must never read as capacity — that is what stops the pool "
        "from ever repairing a poisoned base"
    )
    assert isinstance(ei.value.__cause__, RuntimeError), "the tier's cause must survive"

    # nothing attempted, everything full -> routine capacity
    fine = _Fine()
    full = CascadingRuntime(tiers=[Tier(name="fc", runtime=fine, capacity=1)],
                            tier_rebuild_after=0)
    full.spawn()                       # fills the only tier
    with pytest.raises(CascadeExhausted) as ei2:
        full.spawn()
    assert isinstance(ei2.value, RuntimeAtCapacity), (
        "a merely-full cascade is backpressure and must not advance any failure streak"
    )


def test_a_failed_tier_invalidation_is_reported_not_swallowed():
    """A rebuild the pool believes happened, but didn't, is worse than a loud failure.

    Swallowing a tier's invalidate_base() error made CascadingRuntime.invalidate_base() return
    normally, so WarmPool recorded a successful rebuild and started its cooldown while the
    poisoned tier was untouched — delaying the next repair attempt for the whole cooldown while
    that tier kept failing. Every tier is still attempted; the failure is raised at the end.
    """
    from blastbox.host.runtime.cascade import (
        CascadeInvalidateFailed,
        CascadingRuntime,
        Tier,
    )

    invalidated: list[str] = []

    class _Ok:
        def __init__(self, name): self.name = name
        def invalidate_base(self): invalidated.append(self.name)

    class _Broken:
        def invalidate_base(self): raise RuntimeError("snapshot cleanup failed")

    casc = CascadingRuntime(tiers=[
        Tier(name="a", runtime=_Ok("a"), capacity=1),
        Tier(name="broken", runtime=_Broken(), capacity=1),
        Tier(name="c", runtime=_Ok("c"), capacity=1),
    ])

    with pytest.raises(CascadeInvalidateFailed):
        casc.invalidate_base()

    assert invalidated == ["a", "c"], (
        f"one failing tier must not stop the others being repaired (got {invalidated})"
    )


# ------------------------------------------------- deferred admission (issue #79)

# Stand-ins for the AWS runtime's types, matched by TYPE NAME so cascade keeps no import
# dependency on the optional cloud runtime.
AwsUnknownState = type("AwsUnknownState", (RuntimeError,), {})
AwsThrottled = type("AwsThrottled", (AwsUnknownState,), {})
AwsProbeTimeout = type("AwsProbeTimeout", (AwsUnknownState,), {})


def test_an_undecided_overflow_tier_is_deferred_not_dropped(monkeypatch):
    """issue #79: availability is probed ONCE at construction. A throttled sts get-caller-identity
    was indistinguishable from absent credentials, so seconds of throttling at dispatcher start
    removed the AWS burst tier for the whole process lifetime -- pool reporting green throughout.
    """
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            raise AwsProbeTimeout("Throttling: Rate exceeded")
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [t.name for t in rt.tiers] == ["gvisor"]
    assert [d.name for d in rt._deferred] == ["aws-ec2"], (
        "an undecided tier must be kept for re-probing, not dropped like a confirmed-unusable one"
    )


def test_a_confirmed_unusable_overflow_tier_is_still_dropped(monkeypatch):
    """The distinction must stay narrow: missing credentials is a VERDICT, and retrying it forever
    would just log noise every spawn."""
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            raise RuntimeError("no aws creds")
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert rt._deferred == []


def test_a_deferred_tier_that_turns_out_definitively_broken_is_dropped(monkeypatch):
    """The startup rule -- "missing credentials is a VERDICT" -- must survive deferral.

    _admit_deferred caught bare `Exception` and re-queued the tier on ANY failure, so a tier that
    was throttled at startup (undecided, correctly deferred) and whose credentials were later
    revoked (definitive) was re-probed every _admit_retry_s for the life of the process. That
    directly contradicts test_a_confirmed_unusable_overflow_tier_is_still_dropped above, which
    pins the same rule for the startup path.

    MUTATION: widen the handler back to `except Exception` -> the tier stays deferred forever and
    this fails.
    """
    from blastbox.host import pool_config

    state = {"mode": "throttled"}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if state["mode"] == "throttled":
                raise AwsProbeTimeout("sts: timed out")        # UNDECIDED -> defer
            raise RuntimeError("no aws creds (AccessDenied)")  # VERDICT   -> drop
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"], "a throttled probe must defer, not drop"

    state["mode"] = "definitive"
    rt._last_admit_attempt = None
    rt._admit_deferred()

    assert rt._deferred == [], (
        "a deferred tier whose retry returned a DEFINITIVE failure is still queued; it will be "
        "re-probed every admit interval for the life of the process"
    )


def test_the_cascade_forwards_maintain_idle_to_the_slots_owning_tier(monkeypatch):
    """issue #80's reconciliation hook is resolved off the runtime the POOL holds -- and in every
    documented deployment that is the CASCADE, not the tier.

    CascadingRuntime delegates every other optional per-slot seam explicitly (resume,
    is_alive_for_claim, host_warm_control...) because it has no __getattr__ passthrough.
    maintain_idle got neither, so the entire feature was inert behind a cascade: a half-succeeded
    resume left an instance RUNNING and billing with the pool believing it parked.

    MUTATION: delete CascadingRuntime.maintain_idle -> pool._maintain_idle's getattr finds
    nothing, the hook never runs, and this fails.
    """
    seen: list = []

    class _MaintainingTier(FakeRuntime):
        def maintain_idle(self, slot):
            seen.append(slot)
            return False        # and the verdict must come back intact

    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        return _MaintainingTier(name) if name == "aws-ec2-hibernate" else FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2-hibernate:16"}.get)

    assert callable(getattr(rt, "maintain_idle", None)), (
        "CascadingRuntime has no maintain_idle, so pool._maintain_idle's getattr returns None "
        "and the whole #80 reconciliation never runs in production"
    )
    # gvisor has capacity 4, so the 5th spawn lands on the hibernate tier.
    slots = [rt.spawn() for _ in range(5)]
    slot = next(s for s in slots if s.slot_id.startswith("aws-ec2-hibernate"))
    assert rt.maintain_idle(slot) is False, "the tier's UNUSABLE verdict was not forwarded back"
    assert seen, "the owning tier's maintain_idle was never called"


def test_a_deferred_tier_is_still_covered_by_the_allowed_runtimes_gate(monkeypatch):
    """The fail-closed tier gate must not be escapable by being undecided at startup.

    ``enforce_allowed_runtimes`` runs once, at dispatcher construction, against
    ``reachable_tiers`` -- which read only ``cascade.tiers``. A tier deferred by a transient probe
    failure is not in that list yet, so the gate passed; ``_admit_deferred`` then appended it a
    minute later and jobs for an engine pinned to ``static`` routed onto public AWS. Had the tier
    been available at startup the dispatcher would have REFUSED TO START.

    A deferred tier is a tier the operator configured and that we intend to admit, so it belongs
    in the gate's input from the beginning -- only its AVAILABILITY was ever undecided, never its
    identity.

    MUTATION: drop `_deferred` from reachable_tiers -> the gate passes and this fails.
    """
    from blastbox.host import pool_config
    from blastbox.host.dispatch import reachable_tiers

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            raise AwsProbeTimeout("sts: timed out")     # UNDECIDED -> deferred, not dropped
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"]

    pool = SimpleNamespace(runtime=rt)
    reachable = reachable_tiers(pool, "warm", warm_only=True)
    assert "aws-ec2" in reachable, (
        f"a deferred tier is invisible to the allowed_runtimes gate ({sorted(reachable)}); it "
        f"joins the cascade ~60s later and silently bypasses a fail-closed policy check"
    )


def test_a_deferred_tiers_declared_budgets_are_in_the_cascade_totals(monkeypatch):
    """Budgets are sized ONCE, from the tiers admitted at build. A tier that arrives late must
    therefore already be counted, or every budget it needs is wrong for the life of the process.

    warming_timeout_s, _thaw_budget, _cleanup_budget and the watchdog allowance are all derived
    from these cascade properties by consumers that read them exactly once. So a hibernate tier
    deferred by an STS brownout was admitted a minute later and then had its slots evicted at the
    primary tier's 120s WARMING limit though it declares 600s, and its 180s thaws truncated to
    whatever remained of a 60s claim window -- issues #79 and #81 reintroduced for precisely the
    tier the deferral was built to rescue.

    A deferred tier's IDENTITY and DECLARED budgets were never undecided -- only whether it was
    reachable. Availability needs a probe; `ready_timeout_s` does not.

    MUTATION: drop the deferred entries from readiness_timeout_s -> back to 120.0 and this fails.
    """
    from blastbox.host import pool_config

    class _SlowTier(FakeRuntime):
        readiness_timeout_s = 600.0
        resume_timeout_s = 180.0

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2-hibernate":
            if require_available:
                raise AwsProbeTimeout("sts: timed out")   # the PROBE is what fails
            return _SlowTier(name)                        # construction alone is fine
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2-hibernate:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2-hibernate"]

    assert rt.readiness_timeout_s == 600.0, (
        f"cascade reports readiness_timeout_s={rt.readiness_timeout_s}, so the pool sizes its "
        f"WARMING eviction budget without the deferred tier and reaps its instances mid-boot"
    )
    assert rt.resume_timeout_s == 180.0, (
        f"cascade reports resume_timeout_s={rt.resume_timeout_s}, so the dispatcher builds "
        f"_thaw_budget=None and truncates the thaw to the claim remainder (issue #81)"
    )


def test_a_slow_admit_probe_does_not_become_eligible_again_immediately(monkeypatch):
    """`_last_admit_attempt` was stamped BEFORE the probe ran, so the interval measured from the
    probe's START.

    The probe is `select_runtime_by_name(..., require_available=True)` -- two aws-cli calls, each
    able to burn the full cli_timeout_s (120s) during exactly the persistent timeout that caused
    the deferral. A probe lasting longer than `_admit_retry_s` is therefore already eligible when
    it returns, so the next tick runs another one immediately: `spawn()` is on the pool's sole
    maintenance thread, and promotion, health checks and local spawning stall continuously for the
    duration of the outage. Rate-limiting a call by when it STARTED does not limit anything once
    the call outruns its own window.

    MUTATION: stamp _last_admit_attempt before the probe again -> 5 ticks give 5 probes and this
    fails.
    """
    from blastbox.host import pool_config

    now = [1000.0]
    probes: list = []

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if require_available:
                probes.append(now[0])
                now[0] += 240.0            # two cli calls at their full timeout
                raise AwsProbeTimeout("sts: timed out")
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    rt._clock = lambda: now[0]
    rt._admit_retry_s = 60.0
    rt._last_admit_attempt = None
    probes.clear()

    for _ in range(5):
        rt._admit_deferred()

    assert len(probes) == 1, (
        f"{len(probes)} probes across 5 back-to-back ticks ({sum(1 for _ in probes)*240:.0f}s of "
        f"tick-thread blockage): a probe that outruns _admit_retry_s is eligible the moment it "
        f"returns, so the rate limit throttles nothing"
    )


def test_a_deferred_tier_with_a_foreign_transport_is_refused_at_admission(monkeypatch):
    """The startup path REFUSES a cascade that mixes dispatch styles.

    dispatch_style and ssl_context are read ONCE -- cli.py picks the file vs network dispatcher and
    vm_dispatch captures the context -- so a tier that joins 60s later cannot change either. It is
    simply handed jobs over a transport it does not speak: a network tier in a file cascade fails
    per job in _delegate, and a public-TLS tier behind a private-CA context fails verification.
    Fixing reachable_tiers closed the allowed_runtimes POLICY hole; this is the transport one.

    MUTATION: delete _transport_conflict's use -> the network tier is admitted and this fails.
    """
    from blastbox.host import pool_config

    class _NetworkTier(FakeRuntime):
        dispatch_style = "network"

    state = {"up": False}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            return _NetworkTier(name)
        return FakeRuntime(name)          # dispatch_style defaults to "file"

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    # A tier whose DECLARED transport is readable is now refused at STARTUP, not 60s later: the
    # mismatch is a configuration fact, available without a control-plane answer, and the docs
    # promise fail-fast. Deferring it meant the dispatcher booted on a config documented to be
    # refused and then silently lost the operator's declared burst capacity at the late door.
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"]
    assert rt._deferred[0].dispatch_style == "network", (
        "the declared transport is a config fact and must be recorded without a probe")

    # The invariant is a PROPERTY, and cli.py reads it at startup to choose the file vs network
    # dispatcher. Reading it must now refuse, rather than answering "file" and letting the process
    # boot on a cascade whose declared members cannot share one transport.
    with pytest.raises(CascadeMisconfigured, match="dispatch styles"):
        _ = rt.dispatch_style


def test_a_deferred_tier_of_UNKNOWN_transport_is_still_refused_at_admission(monkeypatch):
    """The late door still matters, for the case startup genuinely cannot see.

    _declared_budgets is best-effort: a tier whose config is broken enough that even a probe-FREE
    build fails contributes no transport at all. Counting that as "file" would invent a mismatch
    and refuse a VALID cascade at startup, so unknown is left uncounted -- which means such a tier
    IS deferred, and _transport_conflict has to catch it when it finally answers.
    """
    from blastbox.host import pool_config

    class _NetworkTier(FakeRuntime):
        dispatch_style = "network"

    state = {"up": False}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            if not require_available:
                raise RuntimeError("config too broken to build probe-free")   # transport UNKNOWN
            return _NetworkTier(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"]
    assert rt._deferred[0].dispatch_style is None, "unknown must not be recorded as 'file'"
    assert rt.dispatch_style == "file", "an unknown transport must not change the cascade's style"

    state["up"] = True
    rt._last_admit_attempt = None
    rt._admit_deferred()

    assert [t.name for t in rt.tiers] == ["gvisor"], (
        "a network tier was admitted into a file cascade the file Dispatcher is already driving")
    assert rt.dispatch_style == "file", "the cascade's transport changed under a live dispatcher"
    assert not rt._deferred, "an incompatible tier must be dropped, not re-probed forever"


def test_two_deferred_entries_of_the_same_backend_are_both_admitted(monkeypatch):
    """BLASTBOX_POOL_TIERS entries are positional, not a set of names.

    "aws-ec2:4,aws-ec2:16" is a legitimate config -- the codebase already says so: _tier_identity
    is f"{name}#{idx}", "a UNIQUE identity per tier position, not per backend name". The deferred
    list deduped by NAME, so admitting one entry silently discarded its sibling and the operator
    lost the capacity they asked for, with no error anywhere.

    MUTATION: key the admit re-check on name again -> only one entry is admitted and this fails.
    """
    from blastbox.host import pool_config

    state = {"up": False}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2", "aws-ec2"], "both entries must defer"
    assert sorted(d.pos for d in rt._deferred) == [1, 2], "each carries its declared position"

    state["up"] = True
    rt._last_admit_attempt = None
    rt._admit_deferred()

    caps = sorted(t.capacity for t in rt.tiers if t.name == "aws-ec2")
    assert caps == [4, 16], (
        f"only {caps} admitted -- the second declared aws-ec2 entry was discarded as a duplicate "
        f"name, silently losing the capacity the operator configured"
    )
    assert not rt._deferred, "both entries were admitted, so nothing should remain deferred"


def test_a_slow_deferred_probe_does_not_delay_a_spawn_the_primary_can_serve(monkeypatch):
    """_admit_deferred used to run FIRST, on every spawn.

    It is rate-limited, but the probe itself is a synchronous availability check that can burn full
    cloud CLI timeouts -- and spawn() runs on the pool's sole maintenance thread. So a deferred AWS
    tier that stays unreachable delayed every spawn from perfectly healthy LOCAL tiers, for the
    duration of the outage. Paying for the overflow before trying the primary inverts the cascade's
    entire ordering.

    MUTATION: call _admit_deferred() at the top of spawn() again -> the probe runs and this fails.
    """
    from blastbox.host import pool_config

    probes: list = []

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if require_available:
                probes.append(1)
                raise AwsProbeTimeout("sts: timed out")     # a SLOW, unreachable overflow tier
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    rt._admit_retry_s = 0.0                       # no rate limit hiding the behaviour
    assert [d.name for d in rt._deferred] == ["aws-ec2"]
    probes.clear()

    import time

    t0 = time.monotonic()
    for _ in range(4):                            # every one of these the PRIMARY can serve
        rt.spawn()
    elapsed = time.monotonic() - t0
    _await_admission(rt)

    # The property is that the SPAWN is not delayed -- not that no probe ran. The probe used to be
    # withheld until the primary was exhausted precisely because it was a synchronous cloud call on
    # the pool's only maintenance thread; it runs off-thread now, so withholding it bought nothing
    # and cost everything the deferred tier was waiting for (its ~60s re-probe cadence, and the
    # post-admission orphan sweep, never ran at all while the primary kept up).
    assert elapsed < 0.5, (
        f"four spawns the primary could serve took {elapsed:.2f}s; a deferred availability probe "
        f"is delaying the spawn path"
    )


def _await_admission(rt, timeout: float = 5.0) -> None:
    """Admission probes run OFF the caller's thread now, so spawn() no longer admits inline.

    The CONTRACT is unchanged -- a recovered tier is admitted, and probes stay rate-limited -- but
    the pool observes it one tick later instead of paying for a synchronous cloud call on its sole
    tick thread. Tests that used to read rt.tiers straight after a spawn wait here instead.
    """
    t = getattr(rt, "_admit_thread", None)
    if t is not None:
        t.join(timeout=timeout)


def test_a_recovered_tier_is_admitted_on_a_later_spawn(monkeypatch):
    """The re-probe is the actual fix: without it the tier stays gone until the process restarts."""
    from blastbox.host import pool_config
    throttling = {"on": True}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            if throttling["on"]:
                raise AwsProbeTimeout("Throttling: Rate exceeded")
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    rt._admit_retry_s = 0.0
    assert [t.name for t in rt.tiers] == ["gvisor"]

    throttling["on"] = False          # STS recovers
    # Fill the primary FIRST. Admission is now lazy: spawn() tries the admitted tiers before it
    # pays for a deferred availability probe, because that probe is a synchronous cloud call on the
    # pool's sole maintenance thread and a deferred OVERFLOW tier must never delay a spawn a
    # healthy PRIMARY can serve. So the recovered tier joins when it is actually needed -- at
    # exhaustion -- rather than on the next spawn regardless.
    for _ in range(4):                # gvisor:4
        rt.spawn()
    _await_admission(rt)
    # The probe is off-thread and rate-limited now, so it runs on every spawn rather than waiting
    # for exhaustion -- withholding it meant a pool whose primary keeps up never probed at all.
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"], (
        "the recovered tier should be admitted as soon as a probe answers, not only once the "
        "primary is exhausted"
    )

    # ...and it is immediately usable: the primary is full at 4, so this spawn lands on the tier
    # that just joined.
    assert rt.spawn() is not None, "the recovered tier was admitted but cannot take a spawn"
    assert rt._deferred == []
    # Per-tier bookkeeping must grow with the tier list, or the next spawn indexes off the end.
    assert len(rt._counts) == len(rt.tiers)
    assert len(rt._tier_failures) == len(rt.tiers)


def test_admission_is_rate_limited(monkeypatch):
    """The probe is an STS round trip and spawn() runs on the pool's tick thread (~10Hz)."""
    from blastbox.host import pool_config
    attempts = {"n": 0}

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            attempts["n"] += 1
            raise AwsProbeTimeout("Throttling: Rate exceeded")
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    t = {"now": 1000.0}
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    rt._clock = lambda: t["now"]
    rt._admit_retry_s = 60.0
    rt._last_admit_attempt = None
    attempts["n"] = 0

    def _spawn():
        # The local tier fills at capacity 4; CascadeExhausted is irrelevant here -- the admission
        # probe is what we are counting. It runs on its OWN thread now, so join before counting:
        # the rate limit is unchanged, only the thread it runs on is.
        try:
            rt.spawn()
        except CascadeExhausted:
            pass
        _await_admission(rt)

    for _ in range(5):
        _spawn()
    assert attempts["n"] == 1, "five spawns inside the window must cost ONE probe"

    t["now"] += 61.0
    _spawn()
    assert attempts["n"] == 2, "past the window the tier is probed again"


def test_an_undecided_primary_fails_closed_but_says_it_is_retryable(monkeypatch):
    """Admitting a primary tier we could not verify is the worse trade -- every spawn would route
    to a tier that may not exist. But the operator must be told it is transient, not a config bug.
    """
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        raise AwsProbeTimeout("Throttling: Rate exceeded")

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    with pytest.raises(CascadeMisconfigured, match="could not determine availability"):
        build_cascade_runtime({"BLASTBOX_POOL_TIERS": "aws-ec2:16"}.get)


def test_an_undecided_cause_is_seen_through_a_wrapper(monkeypatch):
    """The factory layers wrap errors on the way out, so the verdict is often not the OUTER type.
    Judging only the outer exception reads a wrapped brownout as a config verdict and drops the
    tier permanently -- the bug, one wrapper deeper.
    """
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            try:
                raise AwsProbeTimeout("Throttling: Rate exceeded")
            except AwsProbeTimeout as inner:
                raise RuntimeError("aws-ec2 unavailable") from inner
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"], (
        "a brownout wrapped in a generic error is still a brownout"
    )


def test_an_auth_verdict_is_not_retried_forever(monkeypatch):
    """The mirror-image bug. AccessDenied says nothing about whether a WORKER died -- so the
    liveness path calls it UNKNOWN -- but it is a definitive answer about whether we may USE the
    tier. Deferring it would re-probe a misconfigured tier every 60s for the process lifetime.
    """
    from blastbox.host import pool_config

    def fake_select(name, *, warm_snapshot=False, require_available=True):
        if name == "aws-ec2":
            raise AwsUnknownState("AccessDenied: not authorized")
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert rt._deferred == [], "an auth verdict must be dropped, not deferred"

def test_the_cascade_names_the_tier_a_spawn_repair_would_target():
    """The pool's spawn streak is one pool-wide integer with no tier attribution, but the repair
    it triggers IS narrowed here. The pool therefore has to ask the cascade which tiers a spawn
    repair would hit, or it judges "should I repair tier B?" against "did ANY tier succeed?" --
    and a healthy overflow tier absorbing the load, which is precisely what a cascade does when a
    tier is poisoned, cancels the poisoned tier's repair."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _Poisoned:
        def prepare(self): return True
        def spawn(self): raise RuntimeError("snapshot restore failed: corrupt warm.mem")

    class _Healthy:
        def __init__(self): self.n = 0
        def prepare(self): return True
        def spawn(self):
            self.n += 1
            return SimpleNamespace(slot_id=f"ok{self.n}")

    rt = CascadingRuntime(tiers=[Tier(name="fc", runtime=_Poisoned(), capacity=4),
                                 Tier(name="gv", runtime=_Healthy(), capacity=4)])

    assert rt.spawn_guilty_identities() == [], "no evidence yet -> caller must fall back"

    slot = rt.spawn()          # fc raises, gv absorbs it -- the pool sees a SUCCESS
    assert slot.slot_id == "ok1"

    assert rt.spawn_guilty_identities() == ["fc#0"], (
        "the poisoned tier must stay named even though the spawn as a whole succeeded -- that is "
        "the entire failure mode: the pool cannot see the tier that failed")


def test_the_named_tier_is_positional_not_just_the_backend_name():
    """BLASTBOX_POOL_TIERS accepts a repeated backend with SEPARATE bases, so the scope the pool
    compares against must distinguish them -- otherwise a clean release on one is read as
    recovery of the other."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _Poisoned:
        def prepare(self): return True
        def spawn(self): raise RuntimeError("corrupt warm.mem")

    class _Healthy:
        def prepare(self): return True
        def spawn(self): return SimpleNamespace(slot_id="ok")

    rt = CascadingRuntime(tiers=[Tier(name="fc", runtime=_Poisoned(), capacity=4),
                                 Tier(name="fc", runtime=_Healthy(), capacity=4)])
    rt.spawn()
    assert rt.spawn_guilty_identities() == ["fc#0"], (
        "identity must carry the tier POSITION; keyed on the name alone both sibling bases "
        "collapse to one entry")


def test_a_tier_whose_streak_a_repair_cleared_stays_named():
    """_recently_guilty is the half of the guilty set that outlives the streak.

    A cascade-side repair zeroes _tier_failures to give the rebuild a full window before trying
    again. If the scope were read from the streak alone, the tier would vanish from it in exactly
    that window -- the pool would fall back to its pool-wide counter, a healthy sibling's release
    would look like recovery, and the repair the pool was about to make would be cancelled."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _T:
        def prepare(self): return True
        def spawn(self): return SimpleNamespace(slot_id="s1")

    rt = CascadingRuntime(tiers=[Tier(name="fc", runtime=_T(), capacity=4),
                                 Tier(name="gv", runtime=_T(), capacity=4)])
    slot = rt.spawn()
    assert rt.blame_tier_for_slot(slot.slot_id) is True
    assert rt.spawn_guilty_identities() == ["fc#0"]

    with rt._lock:
        rt._tier_failures[0] = 0      # a repair gave tier 0 a fresh window

    assert rt.spawn_guilty_identities() == ["fc#0"], (
        "a tier whose streak was cleared by a REPAIR, not by a success, must stay attributable")


def test_a_spawn_repair_hits_only_the_tiers_it_was_handed():
    """The pool judges a spawn repair against the tiers guilty AT THAT MOMENT (success_scope), but
    invalidate_base used to recompute its targets from the LIVE guilty set. A tier that became
    guilty in between was therefore swept into a repair that never weighed it -- and since it was
    absent from success_scope, the pool's staleness checks could not see that it had meanwhile
    produced a clean release. A healthy sibling's base is destroyed by another tier's episode,
    which is the fallback capacity a cascade exists to preserve."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    dropped = []

    def _mk(name):
        class _T:
            def prepare(self): return True
            def spawn(self): return SimpleNamespace(slot_id=f"{name}-1")
            def invalidate_base(self, **kw):
                dropped.append(name)
                return True
        return _T()

    rt = CascadingRuntime(tiers=[Tier(name="fc", runtime=_mk("fc"), capacity=4),
                                 Tier(name="gv", runtime=_mk("gv"), capacity=4)])
    slot = rt.spawn()
    rt.blame_tier_for_slot(slot.slot_id)          # tier 0 is guilty -> the decision's scope
    frozen = rt.spawn_guilty_identities()
    assert frozen == ["fc#0"]

    # ...and now tier 1 becomes guilty too, AFTER the decision was taken.
    with rt._lock:
        rt._recently_guilty.add(1)

    rt.invalidate_base(reason="spawn", only=frozen)
    assert dropped == ["fc"], (
        f"the repair was handed one tier and hit {dropped}; a tier that became guilty after the "
        f"decision must not be swept into it")


def test_a_single_named_target_still_works():
    """`only` was a plain string before it could carry a set; both must keep working."""
    from types import SimpleNamespace

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    dropped = []

    def _mk(name):
        class _T:
            def prepare(self): return True
            def spawn(self): return SimpleNamespace(slot_id=f"{name}-1")
            def invalidate_base(self, **kw):
                dropped.append(name)
                return True
        return _T()

    rt = CascadingRuntime(tiers=[Tier(name="fc", runtime=_mk("fc"), capacity=4),
                                 Tier(name="gv", runtime=_mk("gv"), capacity=4)])
    rt.invalidate_base(reason="job", only="gv#1")
    assert dropped == ["gv"]


def test_a_probe_that_outruns_its_own_window_still_excludes_a_second_one(monkeypatch):
    """The rate limit is a time gate, and a time gate only bounds when a probe may START.

    The completion re-stamp in _admit_deferred exists precisely because the probe -- two aws-cli
    calls, each able to burn the full cli_timeout_s -- routinely outruns _admit_retry_s. Once it
    does, the window reopens while the first caller is still inside d.build(), so a second probe
    starts against the same deferred snapshot: duplicate round trips on the pool's sole
    maintenance thread, and the loser's freshly built runtime dropped by the _admitted_deferred
    re-check with nothing to close it. Only an in-flight flag actually excludes it.

    MUTATION: delete the `if self._admit_inflight: return 0` guard -> the re-entrant probe runs,
    admits the tier itself and returns 1, and this fails.
    """
    from blastbox.host import pool_config

    state = {"up": False}
    holder: dict = {}
    reentered: list[int] = []
    now = [1000.0]

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            rt = holder.get("rt")
            if rt is not None and not holder.get("reentered_once"):
                holder["reentered_once"] = True
                # This probe outruns its own rate-limit window, so the TIME gate would let a
                # second caller straight through. Only the in-flight flag can refuse it.
                now[0] += 10 * (rt._admit_retry_s or 1.0)
                reentered.append(rt._admit_deferred())
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:4"}.get)
    holder["rt"] = rt
    rt._clock = lambda: now[0]        # type: ignore[method-assign]
    assert [d.name for d in rt._deferred] == ["aws-ec2"]

    state["up"] = True
    rt._last_admit_attempt = None
    admitted = rt._admit_deferred()

    assert reentered == [0], (
        f"a second admission probe ran while the first was still inside build() and admitted "
        f"{reentered} tier(s) of its own -- the time gate cannot exclude a concurrent caller"
    )
    assert admitted == 1
    assert len([t for t in rt.tiers if t.name == "aws-ec2"]) == 1


def test_the_cascade_forwards_the_startup_orphan_sweep_to_its_tiers(monkeypatch):
    """The CLI resolves the sweep with getattr(pool.runtime, "sweep_orphans", None). Whenever
    BLASTBOX_POOL_TIERS is set -- the shape the configuration guide's own examples use -- that
    runtime is the CASCADE, which had neither the attribute nor a __getattr__. So an operator who
    enabled BLASTBOX_EC2_ORPHAN_MAX_AGE_S got the documented reclamation only on a single-runtime
    deployment: in a cascade the getattr returned None and the sweep silently never ran, while a
    crashed predecessor's parked instances kept accruing EBS cost with the setting apparently on.
    """
    from blastbox.host import pool_config

    swept: list = []

    class _Sweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            swept.append(self.name)
            return ["i-orphan"]

    class _Raiser(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            raise RuntimeError("describe-instances: throttled")

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            return _Sweeper(name)
        if name == "aws-lambda":
            return _Raiser(name)
        return FakeRuntime(name)          # gvisor has no sweep at all

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-lambda:2,aws-ec2:4"}.get)

    killed = rt.sweep_orphans()

    assert swept == ["aws-ec2"], f"the sweep did not reach the tier that provides one: {swept}"
    assert killed == ["i-orphan"], "the cascade dropped what the tier reclaimed"


def test_a_tier_admitted_after_a_brownout_gets_its_orphan_sweep(monkeypatch):
    """The CLI's sweep is ONE-SHOT at dispatcher start and runs before a deferred tier exists in
    self.tiers, so forwarding to the admitted tiers reclaims nothing for a tier that was undecided
    at startup and admitted afterwards. It would stay unreclaimed for the life of the process --
    exactly the recovered-brownout path the deferral machine exists to serve. Admission is the
    first moment the tier exists, so it is the startup sweep's equivalent for it."""
    from blastbox.host import pool_config

    swept: list = []
    state = {"up": False}

    class _Sweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            swept.append(self.name)
            return ["i-predecessor"]

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            return _Sweeper(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:4"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"], "the tier must start out deferred"

    rt.sweep_orphans()                    # the CLI's startup sweep: the tier does not exist yet
    assert swept == [], "a deferred tier cannot be swept before it is admitted"

    state["up"] = True
    rt._last_admit_attempt = None
    assert rt._admit_deferred() == 1

    assert swept == ["aws-ec2"], (
        "the tier was admitted without ever being swept, so a predecessor's leaked parked "
        "instances accrue EBS cost until the next process restart"
    )


def test_a_failing_sweep_does_not_unwind_the_admission_that_earned_it(monkeypatch):
    """The tier is already in self.tiers by the time the sweep runs, and the sweep is opportunistic
    housekeeping -- a throttled describe on a recovering control plane is the NORMAL case here,
    since the tier was deferred by a brownout in the first place. Letting that propagate would turn
    the recovery this whole machine exists for into a failed admission."""
    from blastbox.host import pool_config

    state = {"up": False}

    class _BadSweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            raise RuntimeError("describe-instances: Throttling")

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            return _BadSweeper(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:4"}.get)
    state["up"] = True
    rt._last_admit_attempt = None

    assert rt._admit_deferred() == 1, "a failing sweep unwound an admission that had succeeded"
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"]
    assert not rt._deferred, "the tier must not be left deferred after a successful admission"


def test_a_TypeError_from_inside_a_tier_reap_is_not_mistaken_for_an_old_signature(monkeypatch):
    """`except TypeError: reap(slot)` was meant to detect a tier whose reap predates the `dirty`
    kwarg. It cannot tell that apart from a TypeError raised by the BODY of a reap that accepted
    the kwarg and had ALREADY issued its terminate -- so the disposal ran a second time against the
    same cloud resource, which is the one thing every reap path here promises not to do.

    pool.py resolves the same question by introspection, and _invalidate_now states the rule: "a
    TypeError from inside drop() must never be mistaken for an older signature".
    """
    from blastbox.host import pool_config

    calls: list = []

    class _RaisesInside(FakeRuntime):
        def reap(self, slot, dirty: bool = False):   # noqa: ANN001 -- accepts the kwarg
            calls.append(dirty)
            raise TypeError("boto3: unhashable type raised from inside the terminate call")

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: _RaisesInside(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:2"}.get)
    slot = rt.spawn()

    with pytest.raises(TypeError):
        rt.reap(slot, dirty=True)

    assert calls == [True], (
        f"the tier's reap ran {len(calls)} times for one cascade.reap() -- the retry re-terminated "
        f"a resource whose disposal had already been issued"
    )


def test_a_tier_whose_reap_predates_the_dirty_kwarg_is_still_supported(monkeypatch):
    """The compatibility the old except-TypeError was there for, kept."""
    from blastbox.host import pool_config

    seen: list = []

    class _OldSignature(FakeRuntime):
        def reap(self, slot):    # noqa: ANN001 -- no `dirty`
            seen.append(slot.slot_id)

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: _OldSignature(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:2"}.get)
    slot = rt.spawn()
    rt.reap(slot, dirty=True)
    assert len(seen) == 1


def test_admission_probes_do_not_run_on_the_callers_thread(monkeypatch):
    """d.build() is an STS round trip plus a service probe, each able to burn cli_timeout_s, and
    spawn() reaches admission from the pool's SINGLE tick thread -- the one that also drives
    promotion, health checks, reaping and replacement spawning. Probing there froze all of them for
    as long as the control plane took to answer, repeatedly, during exactly the overflow brownout
    the deferral machine exists to survive."""
    import time

    from blastbox.host import pool_config

    state = {"up": False}

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            time.sleep(1.5)               # a slow availability probe on a recovering control plane
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:1,aws-ec2:4"}.get)
    rt._admit_retry_s = 0.0
    rt.spawn()                            # fill the primary (capacity 1)
    state["up"] = True

    t0 = time.monotonic()
    with pytest.raises(CascadeExhausted):
        rt.spawn()                        # triggers admission
    blocked = time.monotonic() - t0

    assert blocked < 0.5, (
        f"spawn() blocked {blocked:.2f}s on an availability probe; on the pool's tick thread that "
        f"stalls promotion, health checks, reaping and replacement spawning together"
    )
    _await_admission(rt)
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"]


def test_close_joins_an_admission_probe_and_refuses_to_start_new_ones(monkeypatch):
    """The lifecycle half. Without a join the probe is a daemon issuing control-plane calls while
    the process tears down -- precisely the shape that made the pool's reaper threads a recurring
    bug on this branch (seven instances)."""
    from blastbox.host import pool_config

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)
    from blastbox.host.runtime.cascade import DeferredTier

    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="undecided",
                                 build=lambda: FakeRuntime("aws-ec2"), pos=1)]
    rt._admit_retry_s = 0.0

    rt.close()
    rt._admit_deferred_async()
    assert rt._admit_thread is None, "a probe was started after close()"


def test_reopen_lets_a_restarted_pool_admit_deferred_tiers_again(monkeypatch):
    """close() latches the cascade so no new admission probe begins during shutdown. Without a way
    back the latch is PERMANENT, and WarmPool.start() fully supports restarting a stopped pool --
    it only clears its own stop event -- so the configured overflow tiers could never be admitted
    again until the whole runtime object was reconstructed."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)
    rt._admit_retry_s = 0.0
    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="undecided",
                                 build=lambda: FakeRuntime("aws-ec2"), pos=1)]

    rt.close()
    rt._admit_deferred_async()
    assert rt._admit_thread is None, "a probe started while closed"

    rt.reopen()
    rt._admit_deferred_async()
    _await_admission(rt)
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"], (
        "the cascade stayed latched shut after reopen(), so a restarted pool can never recover "
        "its overflow tiers"
    )


def test_a_thread_that_cannot_start_does_not_lock_admission_out_forever(monkeypatch):
    """The flags are only cleared in the worker's finally, which never runs if the worker never
    started -- so a host that briefly cannot give us a thread (RuntimeError: can't start new
    thread) left every later call returning at the in-flight guard, and the overflow tier could
    never recover even once host resources came back."""
    import threading

    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)
    rt._admit_retry_s = 0.0
    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="undecided",
                                 build=lambda: FakeRuntime("aws-ec2"), pos=1)]

    real_start = threading.Thread.start

    def _no_threads(self):    # noqa: ANN001
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", _no_threads)
    rt._admit_deferred_async()
    assert rt._admit_inflight is False, "the in-flight flag was left set by a failed start"
    assert rt._admit_thread is None

    monkeypatch.setattr(threading.Thread, "start", real_start)
    rt._admit_deferred_async()                 # host recovered -- admission must be possible again
    _await_admission(rt)
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"]


def test_a_probe_that_finishes_after_close_does_not_publish_its_tier(monkeypatch):
    """stop() can exhaust its shared deadline while d.build() is still blocked, so close() latches
    and RETURNS without the probe. Publishing then mutates a cascade the pool has finished with,
    and the post-admission orphan sweep would issue describe/terminate calls during teardown."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    swept: list = []

    class _Sweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            swept.append(self.name)
            return []

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    def _build_after_close():
        rt.close()                        # shutdown lands while we are still building
        return _Sweeper("aws-ec2")

    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="undecided",
                                 build=_build_after_close, pos=1)]
    rt._admit_probe(list(rt._deferred))

    assert [t.name for t in rt.tiers] == ["gvisor"], "a tier was published into a closed cascade"
    assert swept == [], "the orphan sweep ran during teardown"


def test_a_tier_discarded_during_shutdown_stays_deferred(monkeypatch):
    """`continue` dropped the entry from `still`, and the assignment at the end of the probe
    rebuilds _deferred from `still` alone -- so a tier whose build finished after close() was
    permanently DELETED. reopen() cannot recover an entry that no longer exists, so a restarted
    pool silently lost its configured overflow capacity."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    built: list = []

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    def _build_after_close():
        rt.close()
        built.append("a")
        return FakeRuntime("aws-ec2")

    def _second_build():
        built.append("b")
        return FakeRuntime("aws-lambda")

    pending = [DeferredTier(name="aws-ec2", capacity=4, reason="x", build=_build_after_close, pos=1),
               DeferredTier(name="aws-lambda", capacity=2, reason="x", build=_second_build, pos=2)]
    rt._deferred = list(pending)
    rt._admit_probe(pending)

    assert [d.name for d in rt._deferred] == ["aws-ec2", "aws-lambda"], (
        f"tiers were dropped instead of staying deferred: {[d.name for d in rt._deferred]}"
    )
    assert built == ["a"], (
        "the pass kept building tiers after shutdown was already known -- control-plane calls we "
        "knew we would discard"
    )


def test_the_post_admission_sweep_is_skipped_when_shutdown_lands_mid_publish(monkeypatch):
    """The closing check happens under the lock BEFORE the append; the sweep runs after it and
    outside the lock. Shutdown landing in that window still let a probe issue describe/terminate
    calls after stop() had exhausted its deadline and proceeded. A latch has to be read at the
    point of use, not only at the point of decision."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    swept: list = []

    class _Sweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            swept.append(self.name)
            return []

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    class _ClosesOnAppend(list):
        """Shutdown lands in the window BETWEEN the publish and the out-of-lock sweep."""

        def append(self, item):    # noqa: ANN001, ANN201
            super().append(item)
            # Set the latch the way close() does, but WITHOUT re-entering _lock: this runs
            # while _admit_probe still HOLDS it and the lock is not reentrant, so calling
            # close() here deadlocks. In production close() lands from another thread.
            rt._admit_closing = True

    rt.tiers = _ClosesOnAppend(rt.tiers)    # type: ignore[assignment]
    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="x",
                                 build=lambda: _Sweeper("aws-ec2"), pos=1)]
    rt._admit_probe(list(rt._deferred))

    assert swept == [], "the orphan sweep ran after shutdown had already been latched"


def test_a_sweep_skipped_at_shutdown_is_owed_and_run_after_reopen(monkeypatch):
    """The skip was permanent. The tier stays appended and leaves _deferred, so reopen() has
    neither an entry to retry nor any record that the sweep is still owed -- and the CLI's one-shot
    startup sweep already ran before that tier existed. With BLASTBOX_EC2_ORPHAN_MAX_AGE_S on, a
    predecessor's parked instances would accrue cost indefinitely across the stop/start lifecycle
    this runtime now supports."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    swept: list = []

    class _Sweeper(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            swept.append(self.name)
            return []

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)
    rt._admit_retry_s = 0.0

    class _ClosesOnAppend(list):
        def append(self, item):    # noqa: ANN001, ANN201
            super().append(item)
            rt._admit_closing = True      # shutdown lands between publish and sweep

    rt.tiers = _ClosesOnAppend(rt.tiers)    # type: ignore[assignment]
    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="x",
                                 build=lambda: _Sweeper("aws-ec2"), pos=1)]
    rt._admit_probe(list(rt._deferred))

    assert swept == [], "the sweep ran during teardown"
    assert rt._sweep_owed, "the skipped sweep was forgotten rather than recorded as owed"

    rt.reopen()
    rt.poll()
    _await_admission(rt)          # the sweep runs on the background worker, not the tick thread
    assert swept == ["aws-ec2"], (
        "the owed sweep never ran after restart, so a predecessor's parked instances keep "
        "accruing cost with the setting apparently enabled"
    )


def test_poll_probes_without_any_spawn(monkeypatch):
    """A cadence needs a clock, not a demand signal."""
    from blastbox.host import pool_config

    state = {"up": False}

    def fake_select(name, *, warm_snapshot=False, require_available=True):  # noqa: ANN001
        if name == "aws-ec2":
            if require_available and not state["up"]:
                raise AwsProbeTimeout("sts: timed out")
            return FakeRuntime(name)
        return FakeRuntime(name)

    monkeypatch.setattr(pool_config, "select_runtime_by_name", fake_select)
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:4"}.get)
    rt._admit_retry_s = 0.0
    state["up"] = True

    rt.poll()                      # no spawn() anywhere -- the pool is idle and healthy
    _await_admission(rt)
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"]


def test_a_failed_post_admission_sweep_stays_owed(monkeypatch):
    """The tier has already left _deferred by the time the sweep runs, so nothing else remembers
    the sweep is owed -- and both sweep callers are one-shot, so logging the failure alone forfeits
    reclamation until the next process restart. The blank-inventory AwsNoVerdict added a fresh way
    to reach this handler, which made the gap reachable rather than theoretical."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    attempts: list = []

    class _FailsThenWorks(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("describe-instances: empty response (rc=0)")
            return ["i-predecessor"]

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)
    rt._admit_retry_s = 0.0
    rt._deferred = [DeferredTier(name="aws-ec2", capacity=4, reason="x",
                                 build=lambda: _FailsThenWorks("aws-ec2"), pos=1)]
    rt._admit_probe(list(rt._deferred))

    assert attempts == [1], "the sweep should have been attempted once"
    assert rt._sweep_owed, "a failed sweep was logged and forgotten"

    rt._run_owed_sweeps()
    assert len(attempts) == 2, "the owed sweep was never retried"
    assert not rt._sweep_owed, "a successful retry must clear the debt"


def test_a_failed_retry_is_still_owed(monkeypatch):
    """The ledger must not be a one-shot either -- that is the problem it exists to solve."""
    from blastbox.host import pool_config

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    class _AlwaysFails(FakeRuntime):
        def sweep_orphans(self, **kw):    # noqa: ANN001, ANN003
            raise RuntimeError("still throttled")

    rt._sweep_owed = [_AlwaysFails("aws-ec2")]
    rt._run_owed_sweeps()
    assert rt._sweep_owed, "a retry that failed dropped the debt"


def test_no_build_starts_once_shutdown_is_latched(monkeypatch):
    """The owed sweeps run before the probe on the same worker, and they are control-plane calls
    that can outlast close()'s join deadline -- so the thread can resume after stop() has returned.
    _admit_probe's closing check happened only AFTER d.build(), which cannot stop a probe already
    in flight, and each pending entry is a fresh STS + service round trip."""
    from blastbox.host import pool_config
    from blastbox.host.runtime.cascade import DeferredTier

    builds: list = []

    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    def _mk(name):
        def _build():
            builds.append(name)
            return FakeRuntime(name)
        return _build

    pending = [DeferredTier(name="aws-ec2", capacity=4, reason="x", build=_mk("aws-ec2"), pos=1),
               DeferredTier(name="aws-lambda", capacity=2, reason="x", build=_mk("aws-lambda"), pos=2)]
    rt._deferred = list(pending)
    rt.close()                       # shutdown latched BEFORE the probe starts
    rt._admit_probe(pending)

    assert builds == [], f"builds ran during teardown: {builds}"
    assert [d.name for d in rt._deferred] == ["aws-ec2", "aws-lambda"], (
        "tiers were dropped rather than kept deferred for a restart"
    )


def test_a_close_landing_mid_drain_leaves_the_unswept_runtimes_still_owed(monkeypatch):
    """The owed-sweep ledger drained ALL entries, then checked the latch never again.

    `_run_owed_sweeps` took the whole ledger under the lock, emptied it, and iterated. Each entry is
    an uncached describe plus potentially several serial terminates, each able to burn the full CLI
    timeout -- so a drain can easily outlive a close() that arrives mid-loop. Two things then go
    wrong at once: the sweeps keep firing after shutdown (the latch is supposed to stop them), and
    because the ledger was already emptied, every entry not yet reached is silently FORGOTTEN rather
    than settled on the next reopen(). The ledger exists precisely because a sweep skipped at
    shutdown must not be a one-shot, so dropping the remainder re-creates the bug it was built for.

    MUTATION: hoist the recheck back out of the loop (or drop the `_sweep_owed.extend(owed[i:])`)
    and the second runtime is swept during shutdown / vanishes from the ledger.
    """
    swept: list[str] = []

    class _Sweeper:
        def __init__(self, name: str, on_sweep=None) -> None:
            self.name, self._on_sweep = name, on_sweep

        def sweep_orphans(self, **kw) -> None:
            swept.append(self.name)
            if self._on_sweep is not None:
                self._on_sweep()

    from blastbox.host import pool_config
    monkeypatch.setattr(pool_config, "select_runtime_by_name",
                        lambda name, **kw: FakeRuntime(name))
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4"}.get)

    def _close_lands_now() -> None:
        with rt._lock:
            rt._admit_closing = True

    first, second = _Sweeper("first", _close_lands_now), _Sweeper("second")
    with rt._lock:
        rt._sweep_owed = [first, second]
        rt._admit_closing = False

    rt._run_owed_sweeps()

    assert swept == ["first"], (
        f"swept={swept}; the drain kept sweeping after close() latched -- each of these is an "
        f"uncached describe plus serial terminates issued against a shutting-down runtime")
    assert [s.name for s in rt._sweep_owed] == ["second"], (
        f"still owed={[getattr(s, 'name', s) for s in rt._sweep_owed]}; the un-run sweep was "
        f"dropped by the drain that emptied the ledger, so reopen() will never settle it and the "
        f"orphaned instances it would have found keep billing")
