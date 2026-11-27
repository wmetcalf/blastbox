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
    import time as _t

    now = _t.time()
    r = _post(c, hdr, {"status": "failed", "error": "sandbox would not start", "finished_at": now},
              expect="running")
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.FAILED


def test_finalizer_only_allows_release(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    r = _post(c, hdr, {"status": "queued", "claim_id": None}, expect="running")
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.QUEUED


@pytest.mark.parametrize("fields", [
    {"security_warnings": []},
    {"input_sha256": "ab" * 32},
    {"status": "failed", "input_sha256": "ab" * 32},
    {"status": "failed", "worker_tier": "firecracker"},
    {"status": "failed", "worker_runtime": "nsjail"},
    {"status": "failed", "started_at": 1.0},
    {"status": "failed", "security_warnings": []},
])
def test_finalizer_only_accepts_only_the_agents_two_write_shapes(tmp_path, pki_dir, monkeypatch,  # noqa: F811
                                                                 fields):
    """Release {status: queued, claim_id: null} and fail {status: failed, error, finished_at,
    expires_at is server-set} (spec 6.5), nothing else: input_sha256 is what the finalizer gates on and
    signs, and the rest describe a run the node does not get to narrate onto the row."""
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    before = store.get("job-1")
    assert _post(c, hdr, fields, expect="running").status_code == 403
    assert store.get("job-1") == before


def test_finalizer_only_fail_shape_with_all_its_fields(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    import time as _t

    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    now = _t.time()
    r = _post(c, hdr, {"status": "failed", "error": "killed at deadline", "finished_at": now},
              expect="running")
    assert r.status_code == 200, r.text
    assert store.get("job-1").status == JobStatus.FAILED


@pytest.mark.parametrize("expect", [None, "done"])
def test_finalizer_only_the_cas_is_always_on_running(tmp_path, pki_dir, monkeypatch, expect):  # noqa: F811
    """The RUNNING check reads a snapshot; the finalizer can make the job DONE before the
    write lands. The write's CAS must therefore expect RUNNING, never the caller's choice."""
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    claim = hdr["x-blastbox-claim-id"]
    orig_get = store.get
    armed = {"on": True}

    def racing_get(job_id):
        j = orig_get(job_id)
        if armed["on"] and j is not None and j.status == JobStatus.RUNNING:
            armed["on"] = False      # the finalizer seals right after the node's snapshot
            store.update_if_status(job_id, JobStatus.RUNNING, expect_claim_id=claim,
                                   status=JobStatus.DONE)
        return j

    monkeypatch.setattr(store, "get", racing_get)
    r = _post(c, hdr, {"status": "queued", "claim_id": None}, expect=expect)
    assert not armed["on"], "the race was not exercised"
    assert r.status_code in (403, 409), r.text
    assert orig_get("job-1").status == JobStatus.DONE


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


@pytest.mark.parametrize("fields", [{"status": "queued", "claim_id": None},
                                    {"status": "failed", "error": "x"},
                                    {"result_summary": {"forged": 1}},
                                    {"security_warnings": ["x"]}])
def test_finalizer_only_a_finalized_job_is_closed_to_its_node(tmp_path, pki_dir, monkeypatch,  # noqa: F811
                                                              fields):
    """DONE keeps the claim id, so the node's receipt still authenticates: without this a node
    could release a finished job to be detonated again, or flip or forge its sealed result."""
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    store.update_if_status("job-1", JobStatus.RUNNING, expect_claim_id=hdr["x-blastbox-claim-id"],
                           status=JobStatus.DONE, result_summary={"sealed": 1})
    before = store.get("job-1")
    assert _post(c, hdr, fields).status_code == 403
    assert _post(c, hdr, fields, expect="done").status_code == 403
    assert store.get("job-1") == before


def test_finalizer_only_result_summary_is_the_finalizers(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert _post(c, hdr, {"result_summary": {"forged": 1}}).status_code == 403
    assert store.get("job-1").result_summary in (None, {})


@pytest.mark.parametrize("fields", [
    {"status": "queued", "claim_id": None, "error": "x"},
    {"status": "queued", "claim_id": None, "finished_at": 1.0},
    {"status": "failed"},                                     # no finished_at
    {"status": "failed", "error": "x"},
    {"status": "failed", "error": "x", "finished_at": None},  # null clock
])
def test_finalizer_only_each_shape_is_checked_on_its_own(tmp_path, pki_dir, monkeypatch,  # noqa: F811
                                                         fields):
    import time as _t

    # "<soon>" is resolved HERE, not at collection: a long suite would otherwise make it past
    fields = {k: (_t.time() + 600 if v == "<soon>" else v) for k, v in fields.items()}
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    before = store.get("job-1")
    assert _post(c, hdr, fields, expect="running").status_code == 403
    assert store.get("job-1") == before


def test_finalizer_only_fail_error_is_sanitised_and_finish_not_before_start(tmp_path, pki_dir,  # noqa: F811
                                                                            monkeypatch):
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    started = store.get("job-1").started_at
    r = _post(c, hdr, {"status": "failed", "error": "boom /var/lib/blastbox/jobs/x postgres://u:pw@h/db",
                       "finished_at": 1.0}, expect="running")
    assert r.status_code == 200, r.text
    j = store.get("job-1")
    assert "/var/lib" not in j.error and "pw@" not in j.error
    assert j.finished_at is not None and started is not None and j.finished_at >= started


@pytest.mark.parametrize("fields", [
    {"status": "failed", "error": "x", "finished_at": "<now>", "expires_at": "<soon>"},
    {"status": "failed", "finished_at": "<now>", "expires_at": None},
    {"status": "queued", "claim_id": None, "expires_at": "<soon>"},
])
def test_finalizer_only_a_node_supplied_expiry_is_400(tmp_path, pki_dir, monkeypatch, fields):  # noqa: F811
    """Retention is the operator's policy, not the node's."""
    import time as _t

    sub = {"<now>": _t.time(), "<soon>": _t.time() + 600}
    fields = {k: sub.get(v, v) if isinstance(v, str) else v for k, v in fields.items()}
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    before = store.get("job-1")
    assert _post(c, hdr, fields, expect="running").status_code == 400
    assert store.get("job-1") == before


@pytest.mark.parametrize("retention,expect_expiry", [("60", True), ("0", False), (None, False)])
def test_finalizer_only_fail_expiry_is_the_operators_retention(tmp_path, pki_dir, monkeypatch,  # noqa: F811
                                                               retention, expect_expiry):
    """The same expires_at the dispatcher's _fail_job stamps: now + retention, or None (keep)
    when BLASTBOX_JOB_RETENTION_SECONDS is 0/unset."""
    import time as _t

    monkeypatch.setenv(ENV, "finalizer-only")
    if retention is None:
        monkeypatch.delenv("BLASTBOX_JOB_RETENTION_SECONDS", raising=False)
    else:
        monkeypatch.setenv("BLASTBOX_JOB_RETENTION_SECONDS", retention)
    store, c, hdr = _setup(tmp_path, pki_dir)
    t0 = _t.time()
    r = _post(c, hdr, {"status": "failed", "error": "x", "finished_at": t0}, expect="running")
    assert r.status_code == 200, r.text
    exp = store.get("job-1").expires_at
    if expect_expiry:
        assert exp is not None and t0 + 55 <= exp <= _t.time() + 65
    else:
        assert exp is None


def test_direct_mode_still_takes_the_nodes_expiry(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    import time as _t

    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.setenv("BLASTBOX_JOB_RETENTION_SECONDS", "60")
    store, c, hdr = _setup(tmp_path, pki_dir)
    want = _t.time() + 3000
    r = _post(c, hdr, {"status": "failed", "finished_at": _t.time(), "expires_at": want},
              expect="running")
    assert r.status_code == 200, r.text
    assert abs(store.get("job-1").expires_at - want) < 1


@pytest.mark.parametrize("fields", [{"status": "queued", "claim_id": None},
                                    {"status": "failed", "error": "x", "finished_at": "<now>"}])
def test_finalizer_only_no_release_or_fail_once_a_result_is_quarantined(tmp_path, pki_dir,  # noqa: F811
                                                                         monkeypatch, fields):
    """After a 202 the sample has run and its result waits for the finalizer: a release would
    discard it and hand the sample to another node, a fail would throw away a good result."""
    import time as _t

    from .test_node_data_plane import make_tar, put

    fields = {k: (_t.time() if v == "<now>" else v) for k, v in fields.items()}
    monkeypatch.setenv(ENV, "finalizer-only")
    store, c, hdr = _setup(tmp_path, pki_dir)
    assert put(c, hdr, make_tar([])).status_code == 202
    assert _post(c, hdr, fields, expect="running").status_code == 403
    assert store.get("job-1").status == JobStatus.RUNNING


def test_finalizer_only_retention_parses_like_the_ingress_sweeper(tmp_path, pki_dir, monkeypatch):  # noqa: F811
    """The ingress retention sweeper reads BLASTBOX_JOB_RETENTION_SECONDS as a float; a value
    such as '3600.0' must not silently leave node-failed rows without an expiry."""
    import time as _t

    monkeypatch.setenv(ENV, "finalizer-only")
    monkeypatch.setenv("BLASTBOX_JOB_RETENTION_SECONDS", "60.0")
    store, c, hdr = _setup(tmp_path, pki_dir)
    t0 = _t.time()
    assert _post(c, hdr, {"status": "failed", "finished_at": t0}, expect="running").status_code == 200
    exp = store.get("job-1").expires_at
    assert exp is not None and t0 + 55 <= exp <= _t.time() + 65
