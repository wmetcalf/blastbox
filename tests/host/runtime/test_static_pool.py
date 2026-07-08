"""Unit tests for the static worker-pool runtime (no network)."""

from __future__ import annotations

import pytest

from blastbox.host.pool import SlotRuntime
from blastbox.host.runtime.remote_http import slot_base_url
from blastbox.host.runtime.static_pool import (
    StaticPoolConfig,
    StaticPoolExhausted,
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
    with pytest.raises(StaticPoolExhausted):
        rt.spawn()


def test_spawn_distributes_across_distinct_boxes():
    rt = StaticPoolRuntime(_cfg("a:8765", "b:8765", "c:8765"), http_probe=FakeProbe(all_ok=True))
    idxs = {rt.spawn().worker_index for _ in range(3)}
    assert idxs == {0, 1, 2}  # each claim a distinct box


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
