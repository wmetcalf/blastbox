"""The dispatcher records the personality it RESOLVED, at dispatch, on every local path.

`job.net_policy` is what the client asked for. What ran is what `resolve_net_policy` decided
(fail-closed, engine default, override rules) -- and that is what a host attestation signs, so it
is stamped when the sandbox is launched, not recomputed later against a registry that may have
changed. Every path that hands a job back to the queue clears it, or a later attempt that fails
before launching would carry the previous attempt's policy into a signed statement.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import os
import subprocess
import time

import pytest

from blastbox.host.dispatch import EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.test_dispatch import (
    _ENGINE_IMAGE,
    _ENGINE_NAME,
    _INPUT_SHA,
    _make_dispatcher,
    _make_job,
    _make_valid_output_dir,
    _setup_job_dirs,
)


@pytest.fixture(autouse=True)
def _clean_netpolicy_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_") or k == "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE":
            monkeypatch.delenv(k, raising=False)


def _run_cold(tmp_path, *, engine_policy: str, request: str | None) -> Job:
    store = InMemoryJobStore()
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    job.net_policy = request
    store.create(job)
    _setup_job_dirs(tmp_path, job)
    out = tmp_path / job.job_id / "output"

    def runner(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")

    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy=engine_policy)
    d = _make_dispatcher(store, job_root=tmp_path, engines={_ENGINE_NAME: eng},
                         subprocess_runner=runner)
    assert d.dispatch_once() is True
    final = store.get(job.job_id)
    assert final is not None
    return final


def test_cold_records_the_honoured_override(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    final = _run_cold(tmp_path, engine_policy="none", request="direct")
    assert final.status == JobStatus.DONE
    assert final.net_policy_effective == "direct"


def test_cold_override_disallowed_records_the_engine_default_not_the_request(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")   # declared, but not allowed
    final = _run_cold(tmp_path, engine_policy="none", request="direct")
    assert final.status == JobStatus.DONE
    assert final.net_policy == "direct"            # the request, untouched
    assert final.net_policy_effective == "none"    # what actually ran


def test_cold_unknown_request_falls_back_to_the_engine_default(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    final = _run_cold(tmp_path, engine_policy="direct", request="no-such-policy")
    assert final.net_policy == "no-such-policy"
    assert final.net_policy_effective == "direct"


def test_cold_undeclared_engine_default_fails_closed_to_none(tmp_path):
    final = _run_cold(tmp_path, engine_policy="undeclared", request=None)
    assert final.net_policy_effective == "none"


def test_warm_records_the_resolved_policy(tmp_path):
    from tests.host.test_dispatch_warm import (
        FakeWarmPool,
        _make_dispatcher_with_pool,
        _make_slot,
        _start_fake_worker,
    )
    from tests.host.test_dispatch_warm import _make_job as _warm_job
    from tests.host.test_dispatch_warm import _make_valid_output_dir as _warm_out
    from tests.host.test_dispatch_warm import _setup_job_dirs as _warm_dirs

    store = InMemoryJobStore()
    job = _warm_job()
    job.input_sha256 = _INPUT_SHA
    job.net_policy = "something-undeclared"
    store.create(job)
    _warm_dirs(tmp_path / "jobs", job)
    slot = _make_slot(tmp_path)
    _start_fake_worker(slot, output_fn=lambda o: _warm_out(o, input_sha256=_INPUT_SHA))
    d = _make_dispatcher_with_pool(store, job_root=tmp_path / "jobs", pool=FakeWarmPool(slot),
                                   worker_timeout_s=10, tier="gvisor")
    assert d.dispatch_once() is True
    final = store.get(job.job_id)
    assert final.status == JobStatus.DONE and final.worker_tier == "gvisor"
    assert final.net_policy_effective == "none"


def test_requeue_orphaned_clears_net_policy_effective(tmp_path):
    store = InMemoryJobStore()
    orphan = Job.new(engine=_ENGINE_NAME, filename="a.docx")
    orphan.status = JobStatus.RUNNING
    orphan.started_at = time.time() - 120
    orphan.claim_id = "c1"
    orphan.worker_runtime = "runc"
    orphan.net_policy_effective = "direct"
    store.create(orphan)

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "", "")

    d = _make_dispatcher(store, job_root=tmp_path, subprocess_runner=runner)
    assert d.requeue_orphaned_jobs() == 1
    after = store.get(orphan.job_id)
    assert after.status == JobStatus.QUEUED
    assert after.net_policy_effective is None


# ---------------------------------------------------------------------------
# Every release clears it. Derived from the source, so a new release path can't forget.
# ---------------------------------------------------------------------------

_RELEASING_MODULES = (
    "blastbox.host.dispatch",
    "blastbox.host.runtime.vm_dispatch",
    "blastbox.host.ingress.node_claim",
)


def _kw_is_none(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is None
               for kw in call.keywords)


@pytest.mark.parametrize("modname", _RELEASING_MODULES)
def test_every_release_clears_net_policy_effective(modname):
    """A call that releases a claim (claim_id=None) or resets the runtime (worker_runtime=None)
    must also clear net_policy_effective in the same write."""
    tree = ast.parse(inspect.getsource(importlib.import_module(modname)))
    offenders = []
    releases = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _kw_is_none(node, "claim_id") or _kw_is_none(node, "worker_runtime"):
            releases += 1
            if not _kw_is_none(node, "net_policy_effective"):
                offenders.append(node.lineno)
    assert releases, f"found no release writes in {modname} -- the scraper has drifted"
    assert not offenders, f"{modname}: releases without net_policy_effective=None at {offenders}"


# ---------------------------------------------------------------------------
# VM tier: its egress is fixed at spawn, so it records the DECLARED pool egress or nothing.
# ---------------------------------------------------------------------------


def test_vm_tier_records_the_declared_pool_egress(tmp_path):
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher
    from tests.host.test_vm_dispatch import _queue_job

    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "fakenet"
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), fixed_net_policy="fakenet")
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.net_policy_effective == "fakenet"


def test_vm_tier_with_undeclared_egress_records_nothing(tmp_path):
    """Undeclared pool egress: the host does not know what network the VM is on. Record nothing
    rather than echo the request."""
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher
    from tests.host.test_vm_dispatch import _queue_job

    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "tor"
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.net_policy_effective is None
