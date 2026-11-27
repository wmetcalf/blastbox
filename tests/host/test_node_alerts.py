"""Liveness alerts (C2): evaluation on a simulated clock, the view, the gauges, the key gate."""
from __future__ import annotations

import datetime as dt
import logging
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from blastbox.host import pki
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.node_liveness import (
    LivenessConfig, LivenessMonitor, InMemoryLivenessStore, NodeLiveness, enrolled_nodes,
    evaluate, oldest_queued)

WG = "A" * 42 + "B="
T0 = 1_800_000_000.0
CFG = LivenessConfig()


def ident(engines=("clamav",), not_after=T0 + 10 * 86400):
    return SimpleNamespace(
        grants=SimpleNamespace(engines=tuple(engines)),
        not_after=dt.datetime.fromtimestamp(not_after, dt.timezone.utc),
        not_before=dt.datetime.fromtimestamp(T0 - 86400, dt.timezone.utc))


def lv(hb, engines=(("clamav", True),), claim=None):
    body = {"agent_version": "1.0",
            "engines": [{"name": n, "selftest_ok": ok} for n, ok in engines]}
    return NodeLiveness("n", hb, claim, None, body, {"": claim} if claim is not None else {})


def kinds(alerts):
    return sorted((a.kind, a.subject) for a in alerts)


def run(now, enrolled, live, queued=None, cfg=CFG):
    return evaluate(now=now, enrolled=enrolled, live=live, oldest_queued=queued or {}, cfg=cfg)


def test_silent_fires_at_91_not_89():
    enrolled = {"n": ident()}
    assert run(T0 + 89, enrolled, {"n": lv(T0)}) == []
    assert kinds(run(T0 + 91, enrolled, {"n": lv(T0)})) == [("node_silent", "n")]


def test_never_heartbeated_enrolled_node_is_silent():
    assert kinds(run(T0, {"n": ident()}, {})) == [("node_silent", "n")]


def test_unhealthy_on_failed_selftest_and_on_no_engines():
    e = {"n": ident()}
    got = run(T0 + 10, e, {"n": lv(T0, engines=(("clamav", False),))})
    assert kinds(got) == [("node_unhealthy", "n")] and "clamav" in got[0].detail
    assert kinds(run(T0 + 10, e, {"n": lv(T0, engines=())})) == [("node_unhealthy", "n")]


def test_silent_node_is_not_also_unhealthy():
    got = run(T0 + 500, {"n": ident()}, {"n": lv(T0, engines=(("clamav", False),))})
    assert kinds(got) == [("node_silent", "n")]


def test_cert_expiring_at_47h_not_49h():
    live = {"n": lv(T0)}
    soon = run(T0, {"n": ident(not_after=T0 + 47 * 3600)}, live)
    assert kinds(soon) == [("cert_expiring", "n")]
    assert run(T0, {"n": ident(not_after=T0 + 49 * 3600)}, live) == []


def test_orphaned_fires_with_no_live_node_and_clears_on_heartbeat():
    e = {"n": ident()}
    q = {"clamav": T0 - 301}
    got = run(T0, e, {}, q)
    assert ("engine_orphaned", "clamav") in kinds(got)
    assert run(T0, e, {"n": lv(T0, claim=T0)}, q) == []
    young = run(T0, e, {}, {"clamav": T0 - 299})          # queued work not yet 300 s old
    assert kinds(young) == [("node_silent", "n")]


def test_orphaned_needs_selftest_ok_on_that_engine():
    e = {"n": ident(("clamav", "boxjs"))}
    live = {"n": lv(T0, engines=(("clamav", False), ("boxjs", True)))}
    got = run(T0, e, live, {"clamav": T0 - 400})
    assert ("engine_orphaned", "clamav") in kinds(got)


def test_engine_with_no_enrolled_grant_is_unwatched_by_default_but_watchable():
    e = {"n": ident(("clamav",))}
    live = {"n": lv(T0)}
    assert run(T0, e, live, {"boxjs": T0 - 999}) == []         # pure push engine: no alarm
    cfg = LivenessConfig(orphaned_engines=("boxjs",))
    assert kinds(run(T0, e, live, {"boxjs": T0 - 999}, cfg)) == [("engine_orphaned", "boxjs")]
    assert cfg.as_json()["orphaned_engines"] == ["boxjs"]


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("BLASTBOX_NODE_SILENT_AFTER_S", "30")
    monkeypatch.setenv("BLASTBOX_ENGINE_ORPHANED_AFTER_S", "60")
    monkeypatch.setenv("BLASTBOX_NODE_CERT_EXPIRING_S", "100")
    monkeypatch.setenv("BLASTBOX_ENGINE_ORPHANED_ENGINES", "b, a,,a")
    cfg = LivenessConfig.from_env()
    assert (cfg.silent_after_s, cfg.orphaned_after_s, cfg.cert_expiring_s) == (30, 60, 100)
    assert cfg.orphaned_engines == ("a", "b")


def test_defaults():
    c = LivenessConfig.from_env()
    assert (c.silent_after_s, c.orphaned_after_s, c.cert_expiring_s) == (90, 300, 172800)


def test_oldest_queued_sql_group_by_and_fallback(tmp_path):
    from blastbox.host.jobs.sql_store import SqlJobStore
    for store in (SqlJobStore(f"sqlite:///{tmp_path}/q.db"), InMemoryJobStore()):
        for i, (eng, ts, st) in enumerate([("a", 5.0, JobStatus.QUEUED),
                                           ("a", 3.0, JobStatus.QUEUED),
                                           ("b", 9.0, JobStatus.QUEUED),
                                           ("b", 1.0, JobStatus.DONE)]):
            store.create(Job(job_id=f"j{i}", engine=eng, filename="f", status=st,
                             created_at=ts))
        assert oldest_queued(store) == {"a": 3.0, "b": 9.0}


# --- the monitor, the route, the key gate ---------------------------------------------------

@pytest.fixture
def rig(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",))).write(d, "node-alpha")
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    store = InMemoryJobStore()
    app = build_app(job_store=store, job_root=tmp_path / "jobs",
                    allowed_engines={"clamav"}, api_key="k", metrics_public=True)
    return app, store, TestClient(app, raise_server_exceptions=False)


def test_route_requires_the_api_key(rig):
    _, _, c = rig
    assert c.get("/v1/fleet/liveness").status_code == 401
    assert c.get("/v1/fleet/liveness", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/v1/fleet/liveness", headers={"Authorization": "Bearer k"}).status_code == 200


def test_view_shape_and_cert_not_after_from_enrolled_cert(rig):
    app, _, c = rig
    app.state.node_liveness.record_heartbeat(
        "alpha", {"agent_version": "9.9", "cert_not_after": "bogus",
                  "engines": [{"name": "clamav", "selftest_ok": True}]}, time.time())
    j = c.get("/v1/fleet/liveness", headers={"Authorization": "Bearer k"}).json()
    assert set(j) == {"config", "nodes", "alerts", "generated_at"}
    assert {"silent_after_s", "orphaned_after_s", "cert_expiring_s"} <= set(j["config"])
    (n,) = j["nodes"]
    assert set(n) == {"node_id", "last_heartbeat_at", "last_claim_at", "agent_version",
                      "engines", "cert_not_after"}
    assert n["agent_version"] == "9.9" and isinstance(n["cert_not_after"], float)
    assert j["alerts"] == []


def test_metrics_export_gauges_and_alert(rig):
    app, store, c = rig
    store.create(Job(job_id="x", engine="clamav", filename="f", status=JobStatus.QUEUED,
                     created_at=time.time() - 1000))
    text = c.get("/metrics").text
    assert 'blastbox_node_alert{kind="node_silent",subject="alpha"} 1.0' in text
    assert 'blastbox_node_alert{kind="engine_orphaned",subject="clamav"} 1.0' in text
    assert 'blastbox_engine_oldest_queued_seconds{engine="clamav"}' in text
    assert 'blastbox_node_cert_expiry_seconds{node="alpha"}' in text


def test_no_pki_means_no_route(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(tmp_path / "absent"))
    app = build_app(job_store=InMemoryJobStore(), job_root=tmp_path / "jobs",
                    allowed_engines={"clamav"}, api_key=None)
    assert TestClient(app).get("/v1/fleet/liveness").status_code == 404


def test_transition_logged_once_on_raise_and_once_on_clear(tmp_path, caplog):
    d = tmp_path / "pki"
    pki.ensure_ca(d).issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",))).write(d, "node-alpha")
    lvs = InMemoryLivenessStore()
    now = [time.time()]
    lvs.record_heartbeat("alpha", {"engines": [{"name": "clamav", "selftest_ok": True}]}, now[0])
    m = LivenessMonitor(liveness=lvs, job_store=InMemoryJobStore(), pki_dir=d,
                        clock=lambda: now[0])
    caplog.set_level(logging.INFO, logger="blastbox.node_liveness")
    m.view()
    now[0] += 120
    for _ in range(3):
        m.view()
    errs = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errs) == 1 and "node_silent" in errs[0].getMessage()
    first_since = m.as_json()["alerts"][0]["since"]
    lvs.record_heartbeat("alpha", {"engines": [{"name": "clamav", "selftest_ok": True}]}, now[0])
    m.view()
    m.view()
    infos = [r for r in caplog.records if r.levelno == logging.INFO]
    assert len(infos) == 1 and "CLEARED" in infos[0].getMessage()
    assert first_since < now[0]


def test_since_is_pinned_to_first_seen_while_the_alert_stays_active(tmp_path):
    d = tmp_path / "pki"
    pki.ensure_ca(d).issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(
        engines=("clamav",)), days=1).write(d, "node-alpha")      # < 48 h: cert_expiring
    lvs = InMemoryLivenessStore()
    now = [time.time()]
    lvs.record_heartbeat("alpha", {"engines": [{"name": "clamav", "selftest_ok": True}]}, now[0])
    m = LivenessMonitor(liveness=lvs, job_store=InMemoryJobStore(), pki_dir=d,
                        clock=lambda: now[0])
    t_first = now[0]
    (a,) = m.as_json()["alerts"]
    assert a["kind"] == "cert_expiring" and a["since"] <= t_first        # the onset
    t_first = a["since"]
    now[0] += 5
    lvs.record_heartbeat("alpha", {"engines": [{"name": "clamav", "selftest_ok": True}]}, now[0])
    (a,) = m.as_json()["alerts"]
    assert a["since"] == t_first                                   # not advanced to now


def test_evaluate_with_real_node_identities_and_cert_expired(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",)),
                  days=7).write(d, "node-alpha")
    t = time.time()
    enrolled = enrolled_nodes(d, now=t)
    assert isinstance(enrolled["alpha"], pki.NodeIdentity)
    live = {"alpha": NodeLiveness("alpha", t, None, None, {
        "engines": [{"name": "clamav", "selftest_ok": True}]})}
    assert evaluate(now=t, enrolled=enrolled, live=live, oldest_queued={}, cfg=CFG) == []
    # 8 days on: expired 1 day-ish ago is inside the window only if < 24 h; use +7d+1h.
    later = t + 7 * 86400 + 3600
    enrolled = enrolled_nodes(d, now=later)
    got = evaluate(now=later, enrolled=enrolled, live={}, oldest_queued={"clamav": later - 999},
                   cfg=CFG)
    # Not silent. The engine it alone served IS orphaned: the lapse is the incident.
    assert kinds(got) == [("cert_expired", "alpha"), ("engine_orphaned", "clamav")]
    # past the 24 h grace the node is simply gone
    assert enrolled_nodes(d, now=t + 7 * 86400 + 2 * 86400) == {}


def test_enrolled_scan_is_cached_for_10s_and_invalidated_by_a_new_cert(tmp_path, monkeypatch):
    from blastbox.host import node_liveness as nl
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("a", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(d, "node-a")
    calls = []
    real = nl.enrolled_nodes
    monkeypatch.setattr(nl, "enrolled_nodes", lambda *a, **k: calls.append(1) or real(*a, **k))
    now = [1000.0]
    m = LivenessMonitor(liveness=InMemoryLivenessStore(), job_store=InMemoryJobStore(),
                        pki_dir=d, clock=lambda: now[0])
    m.view()
    m.view()
    now[0] += 9
    m.view()
    assert len(calls) == 1
    now[0] += 2
    m.view()
    assert len(calls) == 2                                          # TTL elapsed
    ca.issue_node("b", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",))).write(d, "node-b")
    m.view()
    assert len(calls) == 3                                          # signature changed


def test_claim_writes_are_throttled_per_node():
    from blastbox.host.node_liveness import ClaimThrottle
    t = ClaimThrottle(5.0)
    assert t.allow("a", 100.0) and not t.allow("a", 102.0) and not t.allow("a", 104.9)
    assert t.allow("a", 105.0) and t.allow("b", 102.0)


# --- review round 1 -------------------------------------------------------------------------

def test_silent_default_follows_the_heartbeat_interval_handed_to_agents(monkeypatch):
    """§10: silent after 3 x heartbeat_s. An operator who raises the interval must not turn
    every healthy node silent."""
    monkeypatch.delenv("BLASTBOX_NODE_SILENT_AFTER_S", raising=False)
    monkeypatch.setenv("BLASTBOX_NODE_HEARTBEAT_S", "120")
    assert LivenessConfig.from_env().silent_after_s == 360
    monkeypatch.setenv("BLASTBOX_NODE_SILENT_AFTER_S", "200")     # explicit override wins
    assert LivenessConfig.from_env().silent_after_s == 200


def test_engine_whose_only_node_lapsed_is_still_watched_for_orphaned_work():
    e = {"n": ident(not_after=T0 - 100)}
    got = run(T0, e, {}, {"clamav": T0 - 5000})
    assert kinds(got) == [("cert_expired", "n"), ("engine_orphaned", "clamav")]


def test_shadow_node_heartbeating_but_never_claiming_does_not_serve():
    """A claim=false (shadow) agent heartbeats a passing selftest and never claims."""
    e = {"n": ident()}
    q = {"clamav": T0 - 400}
    assert ("engine_orphaned", "clamav") in kinds(run(T0, e, {"n": lv(T0)}, q))
    assert run(T0, e, {"n": lv(T0, claim=T0 - 3)}, q) == []          # polling: serves
    busy = NodeLiveness("n", T0, None, None, {"engines": [
        {"name": "clamav", "selftest_ok": True, "busy": 2}]})
    assert run(T0, e, {"n": busy}, q) == []                           # all slots busy: serves


def test_a_heartbeat_far_in_the_future_is_not_fresh():
    """A backward clock step leaves a dead node's last heartbeat ahead of now."""
    assert kinds(run(T0, {"n": ident()}, {"n": lv(T0 + 3600)})) == [("node_silent", "n")]
    assert run(T0, {"n": ident()}, {"n": lv(T0 + 5)}) == []           # small skew tolerated


def test_cert_alert_since_is_the_onset_not_the_evaluation_time():
    na = T0 + 47 * 3600
    (a,) = run(T0, {"n": ident(not_after=na)}, {"n": lv(T0)})
    assert a.kind == "cert_expiring" and a.since == na - CFG.cert_expiring_s
    (a,) = run(T0, {"n": ident(not_after=T0 - 100)}, {})
    assert a.kind == "cert_expired" and a.since == T0 - 100


def test_an_expired_cert_does_not_narrow_its_valid_replacements_grants(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("old",)),
                  days=1).write(d, "node-alpha-old")
    ca.issue_node("alpha", wg_pubkey=WG, grants=pki.NodeGrants(engines=("clamav",)),
                  days=30).write(d, "node-alpha-new")
    later = time.time() + 86400 + 3600                   # old lapsed 1 h ago, new valid
    got = enrolled_nodes(d, now=later)["alpha"]
    assert got.grants.engines == ("clamav",)


def test_duplicate_engine_names_never_emit_duplicate_series(rig):
    """Prometheus rejects a whole scrape that carries one series twice."""
    app, _, c = rig
    app.state.node_liveness.record_heartbeat("alpha", {"engines": [
        {"name": "clamav", "selftest_ok": True}, {"name": "clamav", "selftest_ok": False}]},
        time.time())
    lines = [ln for ln in c.get("/metrics").text.splitlines()
             if ln.startswith("blastbox_node_selftest_ok{")]
    assert len(lines) == 1 and lines[0].endswith(" 0.0")


def test_gauges_drop_a_node_whose_certificate_is_gone(rig, tmp_path):
    app, _, c = rig
    app.state.node_liveness.record_heartbeat(
        "ghost", {"engines": [{"name": "clamav", "selftest_ok": True}]}, time.time())
    text = c.get("/metrics").text
    assert 'node="ghost"' not in text


def test_queue_ages_are_cached_between_scrapes(tmp_path):
    calls = []

    class Jobs:
        def oldest_queued_by_engine(self):
            calls.append(1)
            return {}
    now = [1000.0]
    m = LivenessMonitor(liveness=InMemoryLivenessStore(), job_store=Jobs(),
                        pki_dir=tmp_path, clock=lambda: now[0])
    m.view()
    m.view()
    assert len(calls) == 1
    now[0] += 11
    m.view()
    assert len(calls) == 2


# --- review round 2 -------------------------------------------------------------------------

def _claimed(hb, claims, engines=(("clamav", True), ("boxjs", True))):
    body = {"engines": [{"name": n, "selftest_ok": ok} for n, ok in engines]}
    last = max(claims.values()) if claims else None
    return NodeLiveness("n", hb, last, None, body, claims)


def test_a_claim_for_one_engine_does_not_serve_another():
    e = {"n": ident(("clamav", "boxjs"))}
    q = {"clamav": T0 - 400}
    got = run(T0, e, {"n": _claimed(T0, {"boxjs": T0 - 2})}, q)
    assert ("engine_orphaned", "clamav") in kinds(got)
    assert run(T0, e, {"n": _claimed(T0, {"clamav": T0 - 2})}, q) == []
    assert run(T0, e, {"n": _claimed(T0, {"": T0 - 2})}, q) == []     # unscoped: every grant


def test_a_node_that_claims_but_never_heartbeats_is_still_silent():
    """§10: node_silent is "no heartbeat". Claims never stand in for one: a node whose
    heartbeats are blocked (a proxy allowlist) or that has no heartbeat client must surface,
    and a busy claim-only node goes quiet on /claim for a whole job anyway."""
    e = {"n": ident(("clamav",))}
    claim_only = NodeLiveness("n", None, T0 - 2, None, None, {"": T0 - 2})
    assert kinds(run(T0, e, {"n": claim_only})) == [("node_silent", "n")]


def test_the_claim_window_does_not_stretch_with_a_long_heartbeat_interval():
    """Agents poll /claim every ~2 s whatever heartbeat_s is: a node that stopped claiming
    10 minutes ago does not serve just because silence is judged over 15 minutes."""
    cfg = LivenessConfig(silent_after_s=900.0)
    e = {"n": ident(("clamav",))}
    q = {"clamav": T0 - 400}
    stopped = _claimed(T0 - 100, {"clamav": T0 - 600}, engines=(("clamav", True),))
    assert kinds(run(T0, e, {"n": stopped}, q, cfg)) == [("engine_orphaned", "clamav")]
    polling = _claimed(T0 - 100, {"clamav": T0 - 3}, engines=(("clamav", True),))
    assert run(T0, e, {"n": polling}, q, cfg) == []


def test_queue_fallback_sees_every_engine_not_a_10k_prefix():
    class Jobs:
        def list(self, status=None, *, limit=None, **_kw):
            jobs = [SimpleNamespace(engine="a", created_at=float(i)) for i in range(10_001)]
            jobs.append(SimpleNamespace(engine="b", created_at=20_000.0))
            return jobs[:limit] if limit else jobs
    assert oldest_queued(Jobs()) == {"a": 0.0, "b": 20_000.0}


def test_evaluation_and_memo_update_are_one_critical_section(tmp_path, monkeypatch):
    from blastbox.host import node_liveness as nl
    m = LivenessMonitor(liveness=InMemoryLivenessStore(), job_store=InMemoryJobStore(),
                        pki_dir=tmp_path, clock=lambda: T0)
    held = []
    real = nl.evaluate
    monkeypatch.setattr(nl, "evaluate", lambda **kw: held.append(m._lock.locked()) or real(**kw))
    m.view()
    assert held == [True]
