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
    a.ssl_context = "CTX"                                  # type: ignore[attr-defined]
    assert CascadingRuntime([Tier("a", a, 1)]).ssl_context == "CTX"


def test_cascade_ssl_context_none_when_absent():
    assert CascadingRuntime([Tier("a", FakeRuntime("a"), 1)]).ssl_context is None


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
