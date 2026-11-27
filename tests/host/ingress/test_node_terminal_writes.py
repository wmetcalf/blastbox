"""BLASTBOX_NODE_TERMINAL_WRITES: whether a node may write DONE itself, or only the finalizer."""
from __future__ import annotations

import logging

import pytest

from blastbox.host.ingress import node_claim
from blastbox.host.jobs.base import JobStatus

from .test_node_claim import pki_dir  # noqa: F401  (fixture)
from .test_node_data_plane import _results_dir, _setup  # noqa: F401  (fixtures)

ENV = node_claim.TERMINAL_WRITES_ENV


def _post(c, hdr, fields, *, expect=None):
    body = {"claim_id": hdr["x-blastbox-claim-id"], "receipt": hdr["x-blastbox-receipt"],
            "fields": fields}
    if expect is not None:
        body["expect_status"] = expect
    return c.post("/v1/nodes/jobs/job-1", headers=hdr, json=body)


@pytest.mark.parametrize("expect", [None, "running"])
def test_direct_mode_keeps_todays_behaviour(tmp_path, pki_dir, monkeypatch, expect):  # noqa: F811
    monkeypatch.delenv(ENV, raising=False)                 # default = direct
    store, c, hdr = _setup(tmp_path, pki_dir)
    r = _post(c, hdr, {"status": "done", "result_summary": {"ok": True}}, expect=expect)
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.DONE


@pytest.mark.parametrize("expect", [None, "running"])
def test_finalizer_only_refuses_a_node_done_write(tmp_path, pki_dir, monkeypatch, caplog,  # noqa: F811
                                                  expect):
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    with caplog.at_level(logging.WARNING, logger="blastbox.ingress.node_claim"):
        r = _post(c, hdr, {"status": "done"}, expect=expect)
    assert r.status_code == 403 and r.json() == {"detail": node_claim._REFUSED}
    assert store.get("job-1").status == JobStatus.RUNNING
    assert any(rec.levelno == logging.WARNING and "done" in rec.getMessage()
               for rec in caplog.records)


@pytest.mark.parametrize("status", ["running"])
def test_finalizer_only_refuses_any_status_but_release_or_fail(tmp_path, pki_dir, monkeypatch,  # noqa: F811
                                                               status):
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert _post(c, hdr, {"status": status}).status_code == 403
    assert store.get("job-1").status == JobStatus.RUNNING


def test_finalizer_only_allows_fail(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    r = _post(c, hdr, {"status": "failed", "error": "sandbox would not start"}, expect="running")
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.FAILED


def test_finalizer_only_allows_release(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    r = _post(c, hdr, {"status": "queued", "claim_id": None}, expect="running")
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.QUEUED


def test_finalizer_only_allows_a_write_without_status(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert _post(c, hdr, {"security_warnings": []}).status_code == 200
    assert store.get("job-1").status == JobStatus.RUNNING


def test_an_unknown_mode_fails_closed(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer_only")              # a typo must not open DONE writes
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert _post(c, hdr, {"status": "done"}).status_code == 403
    assert store.get("job-1").status == JobStatus.RUNNING


@pytest.mark.parametrize("mode,warned", [(None, True), ("direct", True),
                                         ("finalizer-only", False)])
def test_ingress_warns_at_startup_unless_finalizer_only(tmp_path, pki_dir, monkeypatch, caplog,  # noqa: F811
                                                        mode, warned):
    if mode is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, mode)
    with caplog.at_level(logging.WARNING, logger="blastbox.ingress.node_claim"):
        _setup(tmp_path, pki_dir)
    hits = [r for r in caplog.records if ENV in r.getMessage()]
    assert bool(hits) is warned
    assert all(r.levelno == logging.WARNING for r in hits)


@pytest.mark.parametrize("mode,errored", [(None, True), ("finalizer-only", False)])
def test_finalizer_errors_at_startup_when_a_pki_is_present_and_not_finalizer_only(
        tmp_path, pki_dir, monkeypatch, caplog, mode, errored):  # noqa: F811
    from blastbox.host import cli, node_finalizer
    from blastbox.host.jobs.memory import InMemoryJobStore

    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.setenv(node_claim.PKI_ENV, str(pki_dir))
    if mode is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, mode)

    class Fake:
        def __init__(self, **kw):
            pass

        def run_once(self):
            return 0

    monkeypatch.setattr(node_finalizer, "NodeFinalizer", Fake)
    import blastbox.host.jobs.factory as jf
    monkeypatch.setattr(jf, "build_job_store_from_env", lambda *a, **k: InMemoryJobStore())
    with caplog.at_level(logging.WARNING):
        assert cli.main(["node-finalizer", "--once", "--no-receipts"]) == 0
    hits = [r for r in caplog.records if ENV in r.getMessage()]
    assert bool(hits) is errored
    assert all(r.levelno == logging.ERROR for r in hits)


def test_finalizer_is_quiet_without_a_pki(tmp_path, monkeypatch, caplog):
    from blastbox.host import cli, node_finalizer
    from blastbox.host.jobs.memory import InMemoryJobStore

    monkeypatch.setenv("BLASTBOX_JOB_ROOT", str(tmp_path / "jobs"))
    monkeypatch.setenv(node_claim.PKI_ENV, str(tmp_path / "no-pki"))
    monkeypatch.delenv(ENV, raising=False)

    class Fake:
        def __init__(self, **kw):
            pass

        def run_once(self):
            return 0

    monkeypatch.setattr(node_finalizer, "NodeFinalizer", Fake)
    import blastbox.host.jobs.factory as jf
    monkeypatch.setattr(jf, "build_job_store_from_env", lambda *a, **k: InMemoryJobStore())
    with caplog.at_level(logging.WARNING):
        assert cli.main(["node-finalizer", "--once", "--no-receipts"]) == 0
    assert not [r for r in caplog.records if ENV in r.getMessage()]
