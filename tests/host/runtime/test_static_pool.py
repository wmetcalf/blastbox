"""Unit tests for the static worker-pool runtime (no network)."""

from __future__ import annotations

import pytest

from blastbox.host.pool import SlotRuntime
from blastbox.host.runtime.remote_http import slot_base_url
from blastbox.host.runtime.static_pool import (
    StaticPoolConfig,
    StaticPoolExhausted,
    StaticPoolUnhealthy,
    StaticPoolRuntime,
    StaticPoolUnavailable,
    StaticWorker,
    StaticWorkerSlot,
    select_static_pool_runtime,
)


class FakeProbe:
    """Injectable http_probe: healthy iff the URL contains one of ``healthy`` substrings."""

    def __init__(self, healthy: set[str] | None = None, all_ok: bool = False) -> None:
        self.healthy = healthy or set()
        self.all_ok = all_ok
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, headers: dict, timeout: float) -> bool:
        self.calls.append((url, headers))
        return self.all_ok or any(h in url for h in self.healthy)


def _cfg(*specs: str, **kw) -> StaticPoolConfig:
    workers = tuple(StaticWorker.parse(s, default_port=8765, default_token=kw.pop("token", None)) for s in specs)
    return StaticPoolConfig(workers=workers, **kw)


# --------------------------------------------------------------- parsing / config

def test_worker_parse_host_port():
    w = StaticWorker.parse("10.0.0.5:9000", default_port=8765, default_token=None)
    assert (w.host, w.port, w.url) == ("10.0.0.5", 9000, None)


def test_worker_parse_host_only_uses_default_port():
    w = StaticWorker.parse("box1", default_port=8765, default_token="tok")
    assert (w.host, w.port, w.token) == ("box1", 8765, "tok")


def test_worker_parse_url():
    w = StaticWorker.parse("https://w.internal:8443/", default_port=8765, default_token=None)
    assert w.url == "https://w.internal:8443" and w.host is None


def test_from_env_parses_and_strips_list(monkeypatch):
    env = {
        "BLASTBOX_STATIC_WORKERS": " 10.0.0.1:8765, 10.0.0.2:8765 ,https://w3 ",
        "BLASTBOX_STATIC_WORKER_TOKEN": "shared",
        "BLASTBOX_STATIC_AGENT_PORT": "9999",
    }
    cfg = StaticPoolConfig.from_env(env.get)
    assert len(cfg.workers) == 3
    assert cfg.workers[0].host == "10.0.0.1" and cfg.workers[0].token == "shared"
    # host-only default port would be 9999 here; explicit ports win
    assert cfg.workers[1].port == 8765
    assert cfg.workers[2].url == "https://w3"


def test_from_env_empty_is_no_workers():
    assert StaticPoolConfig.from_env({}.get).workers == ()


# --------------------------------------------------------------- availability (fail-closed)

def test_available_false_when_no_workers():
    rt = StaticPoolRuntime(_cfg(), http_probe=FakeProbe(all_ok=True))
    assert rt.available() is False


def test_available_true_when_one_box_healthy():
    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765", "10.0.0.2:8765"), http_probe=FakeProbe(healthy={"10.0.0.2"}))
    assert rt.available() is True


def test_available_false_when_all_unreachable():
    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765"), http_probe=FakeProbe(healthy=set()))
    assert rt.available() is False


# --------------------------------------------------------------- lifecycle

def test_spawn_claims_free_box_and_sets_endpoint():
    rt = StaticPoolRuntime(_cfg("10.0.0.7:9001"), http_probe=FakeProbe(all_ok=True))
    slot = rt.spawn()
    assert slot.ip == "10.0.0.7" and slot.agent_port == 9001
    assert slot.endpoint == ("10.0.0.7", 9001)
    assert rt.is_ready(slot) is True and rt.is_alive(slot) is True


def test_spawn_exhausts_then_reap_frees():
    rt = StaticPoolRuntime(_cfg("a:8765", "b:8765"), http_probe=FakeProbe(all_ok=True))
    s1, s2 = rt.spawn(), rt.spawn()
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()
    rt.reap(s1)
    s3 = rt.spawn()  # reclaims the freed box
    assert s3.worker_index == s1.worker_index
    assert {s2.worker_index, s3.worker_index} == {0, 1}


def test_spawn_skips_unhealthy_worker():
    # box "dead" fails /healthz -> the claim must skip it and hand out "live"
    rt = StaticPoolRuntime(_cfg("dead:8765", "live:8765"), http_probe=FakeProbe(healthy={"live"}))
    slot = rt.spawn()
    assert slot.ip == "live"


def test_spawn_raises_when_no_free_worker_healthy():
    rt = StaticPoolRuntime(_cfg("a:8765", "b:8765"), http_probe=FakeProbe(healthy=set()))
    with pytest.raises(StaticPoolUnhealthy):
        rt.spawn()


def test_spawn_distributes_across_distinct_boxes():
    rt = StaticPoolRuntime(_cfg("a:8765", "b:8765", "c:8765"), http_probe=FakeProbe(all_ok=True))
    idxs = {rt.spawn().worker_index for _ in range(3)}
    assert idxs == {0, 1, 2}  # each claim a distinct box


def test_dirty_reap_quarantines_box_until_cooldown():
    # a DIRTY release (timeout/trust-fail) must NOT be re-offered until the cooldown expires, so a
    # stale request still running in the long-lived agent has time to drain.
    now = [1000.0]
    cfg = _cfg("a:8765", dirty_cooldown_s=30.0)
    rt = StaticPoolRuntime(cfg, http_probe=FakeProbe(all_ok=True), clock=lambda: now[0])
    s1 = rt.spawn()
    rt.reap(s1, dirty=True)                       # box goes into cooldown
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()                                # still cooling -> not claimable
    now[0] += 31.0                                # cooldown expires
    s2 = rt.spawn()
    assert s2.worker_index == s1.worker_index     # reclaimed after cooldown


def test_clean_reap_has_no_cooldown():
    now = [1000.0]
    cfg = _cfg("a:8765", dirty_cooldown_s=30.0)
    rt = StaticPoolRuntime(cfg, http_probe=FakeProbe(all_ok=True), clock=lambda: now[0])
    s1 = rt.spawn()
    rt.reap(s1, dirty=False)                       # clean -> immediately reusable
    assert rt.spawn().worker_index == s1.worker_index


def test_reap_is_idempotent():
    rt = StaticPoolRuntime(_cfg("a:8765"), http_probe=FakeProbe(all_ok=True))
    slot = rt.spawn()
    rt.reap(slot)
    rt.reap(slot)  # double-reap must not double-free
    rt.spawn()
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


# --------------------------------------------------------------- transport compatibility + protocol

def test_slot_works_with_remote_http_transport():
    rt = StaticPoolRuntime(_cfg("10.0.1.9:8765"), http_probe=FakeProbe(all_ok=True))
    assert slot_base_url(rt.spawn()) == "http://10.0.1.9:8765"


def test_url_worker_slot_base_url():
    rt = StaticPoolRuntime(_cfg("https://w.internal:8443"), http_probe=FakeProbe(all_ok=True))
    assert slot_base_url(rt.spawn()) == "https://w.internal:8443"


def test_satisfies_slotruntime_protocol():
    rt = StaticPoolRuntime(_cfg("a:8765"), http_probe=FakeProbe(all_ok=True))
    assert isinstance(rt, SlotRuntime)


def test_static_dispatch_style_is_network():
    rt = StaticPoolRuntime(_cfg("a:8765"), http_probe=FakeProbe(all_ok=True))
    assert rt.dispatch_style == "network"   # capability-based routing -> VmJobDispatcher


def test_tls_mode_uses_https_scheme(tmp_path):
    from blastbox.host.pki import ensure_ca
    from blastbox.tls import client_ssl_context
    ensure_ca(tmp_path)  # writes ca.crt
    ctx = client_ssl_context(str(tmp_path / "ca.crt"))
    rt = StaticPoolRuntime(_cfg("10.0.0.9:8765"), http_probe=FakeProbe(all_ok=True), ssl_context=ctx)
    assert rt.ssl_context is ctx
    assert slot_base_url(rt.spawn()) == "https://10.0.0.9:8765"   # host:port -> https in TLS mode


def test_tls_forces_https_on_plaintext_url_worker(tmp_path):
    from blastbox.host.pki import ensure_ca
    from blastbox.tls import client_ssl_context
    ensure_ca(tmp_path)
    ctx = client_ssl_context(str(tmp_path / "ca.crt"))
    rt = StaticPoolRuntime(_cfg("http://w.internal:8443"), http_probe=FakeProbe(all_ok=True), ssl_context=ctx)
    assert slot_base_url(rt.spawn()) == "https://w.internal:8443"   # never plaintext under mTLS


def test_select_builds_ssl_context_from_dispatch_tls_env(tmp_path):
    from blastbox.host.pki import ensure_ca
    ensure_ca(tmp_path)
    env = {"BLASTBOX_STATIC_WORKERS": "10.0.0.1:8765",
           "BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt")}
    rt = select_static_pool_runtime(env.get, require_available=False)
    assert rt.ssl_context is not None


def test_token_forwarded_as_auth_header():
    probe = FakeProbe(all_ok=True)
    rt = StaticPoolRuntime(_cfg("a:8765", token="jwe.tok"), http_probe=probe)
    slot = rt.spawn()
    assert slot.auth_token == "jwe.tok"
    rt.is_ready(slot)
    assert probe.calls[-1][1].get("X-aws-proxy-auth") == "jwe.tok"


# --------------------------------------------------------------- selection

def test_select_requires_available_raises_when_empty():
    with pytest.raises(StaticPoolUnavailable):
        select_static_pool_runtime({}.get, require_available=True, http_probe=FakeProbe(all_ok=True))


def test_select_requires_available_raises_when_unreachable():
    env = {"BLASTBOX_STATIC_WORKERS": "10.0.0.1:8765"}
    with pytest.raises(StaticPoolUnavailable):
        select_static_pool_runtime(env.get, require_available=True, http_probe=FakeProbe(healthy=set()))


def test_select_returns_runtime_when_reachable():
    env = {"BLASTBOX_STATIC_WORKERS": "10.0.0.1:8765,10.0.0.2:8765"}
    rt = select_static_pool_runtime(env.get, require_available=True, http_probe=FakeProbe(all_ok=True))
    assert isinstance(rt, StaticPoolRuntime) and len(rt.cfg.workers) == 2


def test_pool_config_registers_static_runtime(monkeypatch):
    """build_warm_pool must reach the static branch (StaticPoolUnavailable), not 'unknown pool runtime'."""
    from blastbox.host import pool_config

    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME", "static")
    monkeypatch.setenv("BLASTBOX_STATIC_WORKERS", "")  # empty -> require_available raises
    cfg = pool_config.PoolConfig.from_env()
    with pytest.raises(StaticPoolUnavailable):
        pool_config.build_warm_pool(cfg=cfg)


def test_unslotted_worker_endpoint_is_none_for_url():
    slot = StaticWorkerSlot(slot_id="x", worker_index=0, url="https://w", ip=None)
    assert slot.endpoint is None


def test_static_local_probe_failure_is_unknown_not_fleet_wide_death():
    """A LOCAL failure to even attempt the probe (OSError: EMFILE, ENOMEM, host networking being
    reconfigured) says nothing about the box -- and it hits every worker on the same tick, so a
    plain False marked the entire tier dead at once. That is the exact fault `_aws` was hardened
    against, left in place on this tier (issue #77 marla-loop 2)."""
    def _boom(*a, **k):
        raise OSError("[Errno 24] Too many open files")

    # spawn() probes too, so claim the box while the fleet is healthy, THEN break the local probe
    # exactly as an exhausted fd table would mid-run.
    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765"), http_probe=FakeProbe(all_ok=True))
    slot = rt.spawn()
    rt._probe = _boom                       # type: ignore[assignment]
    assert rt.is_alive(slot) is None, "a host-side probe failure must be UNKNOWN, not a verdict"

    # ...while a box that ANSWERS unhealthy is still a real verdict.
    rt2 = StaticPoolRuntime(_cfg("10.0.0.1:8765"), http_probe=FakeProbe(all_ok=True))
    slot2 = rt2.spawn()
    rt2._probe = FakeProbe(healthy=set())   # type: ignore[assignment]
    assert rt2.is_alive(slot2) is False


def test_local_exhaustion_reaches_is_alive_through_the_REAL_probe(monkeypatch):
    """The earlier test for this monkeypatched rt._probe with a raiser, so it never exercised the
    production probe -- which caught OSError and returned False before _health_ok could see it.
    The tri-state was therefore unreachable in production and one health tick evicted the whole
    fleet. Drive the REAL _default_http_probe and assert the verdict reaches is_alive."""
    import errno as _errno

    import blastbox.host.runtime.aws_worker as awsmod
    from blastbox.host.runtime.aws_worker import _default_http_probe

    def _exhausted(req, timeout):  # noqa: ANN001
        raise OSError(_errno.EMFILE, "Too many open files")

    monkeypatch.setattr(awsmod, "_default_open", lambda *a, **k: _exhausted(*a, **k), raising=False)
    monkeypatch.setattr("blastbox.host.runtime.remote_http._default_open",
                        lambda *a, **k: _exhausted(*a, **k), raising=False)
    assert _default_http_probe("http://10.0.0.1:8765/healthz", {}, 1.0) is None, (
        "local fd exhaustion must not be reported as a worker verdict"
    )

    # ...while a refusal IS a real answer about the box.
    def _refused(req, timeout):  # noqa: ANN001
        raise ConnectionRefusedError(_errno.ECONNREFUSED, "Connection refused")

    monkeypatch.setattr("blastbox.host.runtime.remote_http._default_open",
                        lambda *a, **k: _refused(*a, **k), raising=False)
    assert _default_http_probe("http://10.0.0.1:8765/healthz", {}, 1.0) is False


def test_real_fd_exhaustion_does_not_reap_the_fleet(monkeypatch):
    """END TO END against real objects, because every previous guard for this passed against a fake
    that behaved differently from the production opener. Under real fd exhaustion the probe must
    report UNKNOWN and the pool must KEEP both boxes -- previously one _health_check tick evicted
    the entire fleet."""
    import errno as _errno
    import urllib.error

    from blastbox.host.pool import SlotState, WarmPool

    exhausted = {"v": False}

    def _opener(req, timeout):  # noqa: ANN001
        if exhausted["v"]:
            # EXACTLY what urllib.request.AbstractHTTPHandler.do_open raises on a socket failure.
            raise urllib.error.URLError(OSError(_errno.EMFILE, "Too many open files"))
        class _R:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _R()

    monkeypatch.setattr("blastbox.host.runtime.remote_http._default_open", _opener, raising=False)

    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765", "10.0.0.2:8765"))   # REAL probe, not a fake
    pool = WarmPool(runtime=rt, warm_size=2)
    for _ in range(2):
        s = rt.spawn()
        s.state = SlotState.IDLE
        pool._slots[s.slot_id] = s
    assert len(pool._slots) == 2

    exhausted["v"] = True
    pool._health_check()
    alive = [rt.is_alive(s) for s in pool._slots.values()]
    assert all(a is None for a in alive), f"local fd exhaustion read as a verdict: {alive}"
    assert len(pool._slots) == 2, "the entire fleet was reaped by one health tick"

    exhausted["v"] = False                       # pressure clears
    assert all(rt.is_alive(s) is True for s in pool._slots.values())


def test_the_mTLS_probe_reports_unknown_on_local_exhaustion(monkeypatch):
    """make_tls_probe is the DEFAULT probe whenever BLASTBOX_DISPATCH_TLS_CA is set, so leaving it
    bool-only kept the fleet-wide eviction live even with the plain-HTTP path fixed. Three separate
    seals guarded the same failure; any one left open re-opens it."""
    import errno as _errno
    import urllib.error

    from blastbox.host.runtime.remote_http import make_tls_probe

    probe = make_tls_probe(None)

    def _boom(req, timeout, context=None):  # noqa: ANN001
        raise urllib.error.URLError(OSError(_errno.ENOMEM, "Cannot allocate memory"))

    monkeypatch.setattr("blastbox.host.runtime.remote_http._default_open", _boom, raising=False)
    assert probe("https://10.0.0.1:8765/healthz", {}, 1.0) is None, (
        "the mTLS probe convicted a worker on local resource exhaustion")

    def _refused(req, timeout, context=None):  # noqa: ANN001
        raise urllib.error.URLError(ConnectionRefusedError(_errno.ECONNREFUSED, "refused"))

    monkeypatch.setattr("blastbox.host.runtime.remote_http._default_open", _refused, raising=False)
    assert probe("https://10.0.0.1:8765/healthz", {}, 1.0) is False, (
        "a refusal is a real answer about the box and must stay False")


def test_env_probe_timeout_below_the_floor_cannot_brick_the_tier():
    """BLASTBOX_STATIC_PROBE_TIMEOUT_S is operator-settable and this is the ONLY tier where the
    probe timeout is -- a 0 there put the socket in NON-BLOCKING mode, so connect raised
    EINPROGRESS and the whole fleet was convicted in one health tick. Every AWS config clamps its
    probe budgets in __post_init__; this one had none at all (issue #77 marla-loop 4)."""
    from blastbox.host.runtime.aws_worker import _MIN_PROBE_S

    assert _cfg(probe_timeout_s=0.0).probe_timeout_s >= _MIN_PROBE_S
    assert _cfg(probe_timeout_s=0.01).probe_timeout_s >= _MIN_PROBE_S
    assert _cfg(probe_timeout_s=7.5).probe_timeout_s == 7.5      # a sane value is untouched


def test_static_hand_out_probe_honours_the_claim_deadline():
    """Without a claim hook the pool falls back to is_alive(), which always grants the full
    configured probe_timeout_s -- so a claim(timeout_s=0.1) could block five seconds while holding
    the dispatcher's warm-gate reservation, even though AWS and libvirt already honour the
    remaining-budget contract (upstream P2)."""
    seen: list[float] = []

    def _probe(url, headers, timeout):  # noqa: ANN001
        seen.append(timeout)
        return True

    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765"), http_probe=FakeProbe(all_ok=True))
    slot = rt.spawn()
    rt._probe = _probe                       # type: ignore[assignment]
    assert rt.is_alive_for_claim(slot, budget_s=0.4) is True
    assert seen and seen[-1] <= 0.4, f"probe ignored the 0.4s claim budget: {seen}"

    # no window left to ask meaningfully -> UNKNOWN, never a verdict
    assert rt.is_alive_for_claim(slot, budget_s=0.0) is None


def test_cooldown_only_misses_are_capacity_not_a_broken_fleet():
    """A cooling worker is HEALTHY — it just is not claimable this instant.

    One raise site served both "every free worker failed its probe" (the fleet is broken) and
    "every free worker is inside dirty_cooldown_s" (routine, self-clearing). Reporting the
    latter as a fault advances the pool's spawn-failure streak every tick and, behind a cascade,
    can invalidate an unrelated healthy snapshot base.
    """
    cfg = _cfg("a:8765", "b:8765", dirty_cooldown_s=30.0)
    rt = StaticPoolRuntime(cfg, http_probe=FakeProbe(all_ok=True))   # both answer /healthz
    a = rt.spawn()
    b = rt.spawn()
    rt.reap(a, dirty=True)      # both quarantined, neither unhealthy
    rt.reap(b, dirty=True)

    with pytest.raises(StaticPoolExhausted) as ei:
        rt.spawn()
    assert not isinstance(ei.value, StaticPoolUnhealthy), (
        "a cooling fleet is at capacity, not broken"
    )


def test_an_unknown_health_probe_is_capacity_not_a_broken_fleet():
    """`None` from _health_ok means the probe could not be ATTEMPTED, not that the worker failed.

    EMFILE, ENOMEM or a local networking reconfiguration all produce None — a dispatcher-side
    outage. Counting it as unhealthy turns our own resource exhaustion into a tier spawn FAULT
    that advances rebuild streaks and can invalidate snapshot bases in a cascade: the same
    "a slow or erroring control plane must never read as dead" invariant as issue #77.
    """
    cfg = _cfg("a:8765", "b:8765")
    rt = StaticPoolRuntime(cfg, http_probe=lambda *a, **kw: None)   # UNKNOWN, not False

    with pytest.raises(StaticPoolExhausted) as ei:
        rt.spawn()
    assert not isinstance(ei.value, StaticPoolUnhealthy), (
        "an unknown probe is not a verdict on the fleet"
    )


def test_a_genuinely_failing_probe_is_still_unhealthy():
    """The carve-out must stay narrow: False is a real verdict and must keep reporting a fault."""
    cfg = _cfg("a:8765", "b:8765")
    rt = StaticPoolRuntime(cfg, http_probe=FakeProbe(healthy=set()))   # explicit False

    with pytest.raises(StaticPoolUnhealthy):
        rt.spawn()


def test_a_static_workers_failures_survive_its_slot():
    """Per-slot bookkeeping cannot burn out a REUSED box.

    Every spawn() hands a fresh slot_id to the same registered worker and reap() just returns it
    to the free list, so the counter reached one, the slot was removed, _forget_slot_health()
    erased the history, and the next request to the same endpoint started from zero — the default
    threshold of two was unreachable however many correctly-attributed transport failures that
    box produced. A static tier has no snapshot base to invalidate either, so burnout is its only
    protection.
    """
    from blastbox.host.pool import WarmPool

    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765", "10.0.0.2:8765"),
                           http_probe=FakeProbe(all_ok=True))
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=2,
                    max_consecutive_failures=2, eviction_window_s=10_000.0,
                    max_evictions_per_window=10)

    slot1 = rt.spawn()
    pool._slots[slot1.slot_id] = slot1
    key1 = pool._health_key(slot1)
    assert key1 == f"static:{slot1.worker_index}", "the physical box must be the identity"

    pool.release(slot1, dirty=True, fault="worker")
    assert pool._slot_failures.get(key1) == 1

    # The slot goes away; the BOX does not.
    pool._slots.pop(slot1.slot_id, None)
    pool._forget_slot_health(slot1.slot_id)
    assert pool._slot_failures.get(key1) == 1, (
        "the box's failure history was erased with its slot, so a static worker could never "
        "reach the burnout threshold"
    )

    # A second failure on the SAME box, through a brand-new slot, now reaches the threshold.
    slot2 = rt.spawn()
    slot2.worker_index = slot1.worker_index
    pool._slots[slot2.slot_id] = slot2
    pool.release(slot2, dirty=True, fault="worker")
    assert pool._slot_failures.get(pool._health_key(slot2)) == 2


def test_a_disposable_runtimes_history_is_still_dropped_with_its_slot():
    """The carve-out stays narrow: without a stable identity the slot IS the worker, and keeping
    its record would grow unboundedly over a long-lived dispatcher."""
    from blastbox.host.pool import Slot, SlotState, WarmPool

    from uuid import uuid4

    class _Disposable:
        def spawn(self):
            return Slot(slot_id=str(uuid4()), control_dir="/c", input_dir="/i",
                        output_dir="/o", state=SlotState.IDLE)
        def is_ready(self, s): return True
        def is_alive(self, s): return True
        def reap(self, s): pass

    pool = WarmPool(runtime=_Disposable(), warm_size=1, concurrent_ceiling=2)
    slot = pool._runtime.spawn()
    pool._slots[slot.slot_id] = slot
    assert pool._health_key(slot) == slot.slot_id, (
        "with no stable identity the slot IS the worker"
    )

    # A disposable runtime has no recycle(), so a dirty release reaps the slot outright and its
    # record goes with it. Nothing may be retained under a dead slot_id: those ids are per-spawn
    # UUIDs, so keeping them grows without bound over a long-lived dispatcher.
    pool.release(slot, dirty=True, fault="worker")
    pool._forget_slot_health(slot.slot_id)
    assert slot.slot_id not in pool._slot_failures
    assert slot.slot_id not in pool._slot_last_success
    assert slot.slot_id not in pool._health_key_by_slot


def test_a_static_tier_under_a_cascade_keeps_its_worker_identity():
    """The identity hook existed only on StaticPoolRuntime and the cascade did not forward it.

    In the supported static-tier-under-CascadingRuntime configuration the pool asked the OUTER
    cascade, which has no hook, so each reusable box was keyed by its fresh per-spawn slot_id
    again — reap deleted the one recorded failure and max_consecutive_failures > 1 stayed
    unreachable, exactly the bug the hook was added to fix.
    """
    from blastbox.host.pool import WarmPool
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    inner = StaticPoolRuntime(_cfg("10.0.0.1:8765", "10.0.0.2:8765"),
                              http_probe=FakeProbe(all_ok=True))
    # Tier name deliberately DIFFERENT from the inner identity prefix, or a qualified key and a
    # bare one look identical and the assertion proves nothing.
    casc = CascadingRuntime(tiers=[Tier(name="boxes", runtime=inner, capacity=2)],
                            tier_rebuild_after=99)
    pool = WarmPool(runtime=casc, warm_size=1, concurrent_ceiling=2)

    slot = casc.spawn()
    key = pool._health_key(slot)
    assert key is not None and key != slot.slot_id, (
        "the cascade did not forward the tier's worker identity, so the box is keyed by a "
        "per-spawn slot_id again"
    )
    assert key.startswith("boxes#0:"), (
        f"the key must be TIER-QUALIFIED and POSITION-unique — two tiers can share a backend "
        f"name and each report 'static:0' for different boxes (got {key})"
    )
    assert f"static:{slot.worker_index}" in key


def test_a_cascade_over_a_disposable_tier_reports_no_identity():
    """The carve-out stays narrow: without a reusing tier the slot IS the worker."""
    from blastbox.host.pool import Slot, SlotState
    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    class _Disposable:
        def spawn(self):
            return Slot(slot_id="d1", control_dir="/c", input_dir="/i", output_dir="/o",
                        state=SlotState.IDLE)
        def is_ready(self, s): return True
        def is_alive(self, s): return True
        def reap(self, s): pass

    casc = CascadingRuntime(tiers=[Tier(name="d", runtime=_Disposable(), capacity=2)],
                            tier_rebuild_after=99)
    slot = casc.spawn()
    assert casc.worker_identity(slot) is None


def test_a_job_fault_clears_the_boxs_failures_not_the_slots():
    """A valid engine_error proves the box responsive, so its failure record must reset.

    The clear popped slot.slot_id while the record is filed under the physical worker, so the
    box's prior failure survived and the lookup right below — correctly keyed — read it straight
    back. A failure / valid engine_error / failure sequence then counted as CONSECUTIVE and could
    burn out a healthy box or spend eviction budget on it.
    """
    from blastbox.host.pool import WarmPool

    rt = StaticPoolRuntime(_cfg("10.0.0.1:8765", "10.0.0.2:8765"),
                           http_probe=FakeProbe(all_ok=True))
    pool = WarmPool(runtime=rt, warm_size=1, concurrent_ceiling=2,
                    max_consecutive_failures=2, eviction_window_s=10_000.0,
                    max_evictions_per_window=10)

    slot = rt.spawn()
    pool._slots[slot.slot_id] = slot
    key = pool._health_key(slot)

    pool.release(slot, dirty=True, fault="worker")
    assert pool._slot_failures.get(key) == 1

    # A valid engine_error on the SAME physical box, through a FRESH slot -- the production
    # shape, since a static runtime reaps the slot and mints a new id for the next assignment.
    again = rt.spawn()
    again.worker_index = slot.worker_index
    pool._slots[again.slot_id] = again
    assert pool._health_key(again) == key, "sanity: same box, same health key"

    pool.release(again, dirty=True, fault="job")
    assert pool._slot_failures.get(key, 0) == 0, (
        "the box's failure record survived a valid engine response, so two unrelated failures "
        "an hour apart count as consecutive"
    )
