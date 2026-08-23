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
    rt = build_cascade_runtime({"BLASTBOX_POOL_TIERS": "gvisor:4,aws-ec2:16"}.get)
    assert [d.name for d in rt._deferred] == ["aws-ec2"]
    assert rt.dispatch_style == "file"

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

    for _ in range(4):                            # every one of these the PRIMARY can serve
        rt.spawn()

    assert probes == [], (
        f"{len(probes)} deferred availability probes ran while the primary tier still had "
        f"capacity; each is a synchronous cloud call on the pool's only maintenance thread"
    )


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
    assert [t.name for t in rt.tiers] == ["gvisor"], "no probe while the primary can still serve"

    rt.spawn()                        # primary exhausted -> now the probe is worth paying for
    assert [t.name for t in rt.tiers] == ["gvisor", "aws-ec2"], "the recovered tier must be admitted"
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
        # probe runs BEFORE the tier loop, and that is what we are counting.
        try:
            rt.spawn()
        except CascadeExhausted:
            pass

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
