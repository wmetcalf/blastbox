"""Liveness alerts (C2): evaluation on a simulated clock, the view, the gauges, the key gate."""
from __future__ import annotations

import datetime as dt
import logging
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from blastbox.host import pki
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.node_liveness import (
    LivenessConfig, LivenessMonitor, InMemoryLivenessStore, NodeLiveness, evaluate,
    oldest_queued)

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
    return NodeLiveness("n", hb, claim, None, body)


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
    assert run(T0, e, {"n": lv(T0)}, q) == []
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
                  "engines": [{"name": "clamav", "selftest_ok": True}]}, __import__("time").time())
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
                     created_at=__import__("time").time() - 1000))
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
    now = [__import__("time").time()]
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
