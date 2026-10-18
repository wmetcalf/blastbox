"""Placement by advertised egress: a static pool serving an egress-granting policy only claims
workers whose /healthz says ``"egress": true``, and a tier that could never place such a job
refuses to start. The agent's own 422 refusal is the backstop for runtimes that do not place
(tested in tests/worker/test_agent_egress_capability.py)."""
from __future__ import annotations

import pytest

from blastbox.host.runtime.static_pool import (
    StaticPoolConfig,
    StaticPoolExhausted,
    StaticPoolNoEgress,
    StaticPoolRuntime,
    StaticWorker,
)


def _rt(adverts: dict[str, object], *, healthy=None) -> StaticPoolRuntime:
    """adverts: host -> the /healthz body's "egress" value (missing key = legacy agent),
    or None = could not ask."""
    workers = tuple(StaticWorker.parse(h, default_port=8765, default_token=None) for h in adverts)

    def caps(url, headers, timeout):
        host = url.split("//")[1].split(":")[0]
        v = adverts[host]
        if v is None:
            return None
        return {} if v == "legacy" else {"ok": True, "egress": v}

    return StaticPoolRuntime(StaticPoolConfig(workers=workers),
                             http_probe=lambda u, h, t: True if healthy is None else healthy(u),
                             capability_probe=caps)


def test_without_an_egress_policy_capability_is_never_asked():
    asked = []
    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="mac1"),)),
                           http_probe=lambda u, h, t: True,
                           capability_probe=lambda *a: asked.append(a) or {"egress": False})
    assert rt.spawn().ip == "mac1" and asked == []


def test_an_egress_tier_skips_workers_that_cannot_provide_it():
    rt = _rt({"mac1": False, "legacy": "legacy", "linux1": True})
    rt.require_egress()
    assert rt.spawn().ip == "linux1"


def test_a_legacy_agent_that_advertises_nothing_is_not_trusted_with_egress():
    rt = _rt({"old": "legacy"})
    rt.require_egress()
    with pytest.raises(StaticPoolNoEgress):
        rt.spawn()


def test_only_incapable_workers_is_a_loud_configuration_fault():
    rt = _rt({"mac1": False, "mac2": False})
    rt.require_egress()
    with pytest.raises(StaticPoolNoEgress, match="advertises egress"):
        rt.spawn()


def test_an_unanswered_capability_question_is_not_a_verdict():
    rt = _rt({"mac1": None})
    rt.require_egress()
    with pytest.raises(StaticPoolExhausted):       # backpressure, not a fault
        rt.spawn()


def test_the_census_separates_yes_no_and_unknown():
    rt = _rt({"a": True, "b": False, "c": "legacy", "d": None})
    assert rt.egress_census() == (1, 2, 1)


def test_the_dispatcher_refuses_to_start_a_tier_that_can_never_place_egress():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    rt = _rt({"mac1": False, "mac2": False})
    with pytest.raises(ValueError, match="none of its 2 static worker"):
        _place_egress(rt, "static")


def test_a_partly_capable_fleet_starts_and_places_only_on_the_capable():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    rt = _rt({"mac1": False, "linux1": True})
    _place_egress(rt, "static")
    assert rt.spawn().ip == "linux1"


def test_an_unreachable_fleet_does_not_block_startup():
    from blastbox.host.runtime.vm_dispatch import _place_egress

    _place_egress(_rt({"mac1": None}), "static")


def test_other_runtimes_rely_on_the_agents_refusal():
    from types import SimpleNamespace

    from blastbox.host.runtime.vm_dispatch import _place_egress

    _place_egress(SimpleNamespace(), "aws")          # no attributes touched, no raise


def test_a_fleet_that_is_merely_down_at_startup_is_unknown_not_incapable(monkeypatch):
    """The default capability probe must not read "unreachable" as "advertises no egress":
    that made a fleet that was down at dispatcher start look permanently unable to serve the
    policy, and the dispatcher refused to start."""
    import urllib.error

    from blastbox.host.runtime import remote_http
    from blastbox.host.runtime.static_pool import make_capability_probe

    def refused(req, timeout, context=None):
        raise urllib.error.URLError(ConnectionRefusedError(61, "refused"))

    monkeypatch.setattr(remote_http, "_default_open", refused)
    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="mac1"),)),
                           http_probe=lambda u, h, t: False,
                           capability_probe=make_capability_probe(None))
    assert rt.egress_census() == (0, 0, 1)


def test_a_busy_capable_worker_is_backpressure_not_a_fault():
    """REGRESSION (review): with the only capable worker CLAIMED, the free set is all Macs --
    that is the fleet being busy, and the next release frees it."""
    rt = _rt({"mac1": False, "linux1": True})
    rt.require_egress()
    assert rt.spawn().ip == "linux1"
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


def test_an_unanswered_capable_worker_is_not_a_fault_either():
    rt = _rt({"mac1": False, "linux1": None})
    rt.require_egress()
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


def test_an_odd_responder_does_not_crash_the_census():
    import http.client

    def boom(url, headers, timeout):
        raise http.client.BadStatusLine("garbage")

    rt = StaticPoolRuntime(StaticPoolConfig(workers=(StaticWorker(host="x"),)),
                           http_probe=lambda u, h, t: True, capability_probe=boom)
    assert rt.egress_census() == (0, 0, 1)
