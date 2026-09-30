"""The dispatcher that ran a job signs its receipt, at the seal, from what IT observed.

The job row is writable by parties the host never observed (nodes, peer dispatchers, anyone with
the DSN), so nothing on it may reach a receipt. These tests write to the row mid-run and after
DONE and require the receipt to be unmoved.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import attest
from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.dispatch import Dispatcher, EngineSpec
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from tests.host.test_dispatch import (
    _ENGINE_IMAGE,
    _ENGINE_NAME,
    _INPUT_SHA,
    _fake_runtime,
    _limits,
    _make_job,
    _make_valid_output_dir,
    _setup_job_dirs,
)

_INPUT_BYTES = b"malware"   # what _setup_job_dirs writes; deliberately NOT _INPUT_SHA's preimage


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("BLASTBOX_NETPOLICY_") or k in (
                "BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BLASTBOX_HOST_ID", "dispatch-host")


@pytest.fixture
def key(tmp_path):
    return attest.load_or_create_key(tmp_path / "keys" / "attest.key")


def _verify(key: attest.AttestKey, body: dict) -> dict:
    pub = serialization.load_pem_public_key(key.public_key_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.urlsafe_b64decode(body["signature"]),
               attest.canonical(body["attestation"]), ec.ECDSA(hashes.SHA256()))
    return body["attestation"]


def _blobs(tmp_path) -> LocalBlobStore:
    return LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")


def _tombstone_reason(tmp_path, job) -> str:
    body = json.loads(_receipt_path(tmp_path, job).read_bytes())
    assert body["attestation"] is None, body
    return body["reason"]


def _receipt_path(tmp_path, job) -> "os.PathLike[str]":
    return tmp_path / "blobs" / "results" / job.job_id / attest.RECEIPT_NAME


def _dispatcher(tmp_path, store, *, attest_key, runner, engine_policy="none",
                runtime_selector=_fake_runtime):
    eng = EngineSpec(name=_ENGINE_NAME, image=_ENGINE_IMAGE, worker_argv=["worker", "run"],
                     net_policy=engine_policy)
    return Dispatcher(
        job_store=store, engines={_ENGINE_NAME: eng}, limits=_limits(),
        job_root=tmp_path / "jobs", runtime_selector=runtime_selector,
        subprocess_runner=runner, worker_timeout_s=30, blob_store=_blobs(tmp_path),
        put_output_max_attempts=1, put_output_retry_backoff_s=0.0, attest_key=attest_key,
    )


def _queue(tmp_path, store, **kw) -> Job:
    job = _make_job()
    job.input_sha256 = _INPUT_SHA
    for k, v in kw.items():
        setattr(job, k, v)
    store.create(job)
    _setup_job_dirs(tmp_path / "jobs", job, input_content=_INPUT_BYTES)
    return job


def _runner(tmp_path, job, *, during=None, plant=None):
    out = tmp_path / "jobs" / job.job_id / "output"

    def run(argv, **kw):
        if argv[:2] == ["docker", "run"]:
            if during:
                during()
            _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
            if plant is not None:
                (out / attest.RECEIPT_NAME).write_bytes(plant)
        return subprocess.CompletedProcess(argv, 0, "", "")
    return run


# ---------------------------------------------------------------------------
# Cold path
# ---------------------------------------------------------------------------


def test_cold_done_job_gets_a_verifiable_receipt_of_what_ran(tmp_path, key, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    monkeypatch.setenv("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "1")
    store = InMemoryJobStore()
    job = _queue(tmp_path, store, net_policy="direct")
    before = attest.now_ms()
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE

    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    meta = (tmp_path / "blobs" / "results" / job.job_id / "metadata.json").read_bytes()
    assert doc["job_id"] == job.job_id and doc["engine"] == _ENGINE_NAME
    assert doc["status"] == "done" and doc["executor"] == "local"
    assert doc["host"] == "dispatch-host" and doc["key_id"] == key.key_id
    assert doc["metadata_sha256"] == hashlib.sha256(meta).hexdigest()
    assert doc["worker_runtime"] == "runc" and doc["worker_tier"] is None
    assert doc["net_policy_effective"] == "direct" and doc["net_exit"] == "direct"
    assert before <= doc["started_at_ms"] <= doc["finished_at_ms"] <= doc["issued_at_ms"]


def test_input_sha256_is_the_hash_of_the_bytes_handed_to_the_sandbox(tmp_path, key):
    """The row says _INPUT_SHA; the file on disk is b"malware". The receipt reports the bytes."""
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert doc["input_sha256"] == hashlib.sha256(_INPUT_BYTES).hexdigest()
    assert doc["input_sha256"] != store.get(job.job_id).input_sha256


def test_effective_policy_is_the_resolved_one_not_the_request(tmp_path, key, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")   # declared, override OFF
    store = InMemoryJobStore()
    job = _queue(tmp_path, store, net_policy="direct")
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert doc["net_policy_effective"] == "none"


def test_row_writes_during_the_run_cannot_change_the_receipt(tmp_path, key):
    """A node/peer/DSN holder rewrites the row while the sandbox runs. The receipt is built from
    the dispatcher's memory of the run, so none of it lands."""
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)

    def scribble():
        store.update(job.job_id, worker_runtime="none", worker_tier="firecracker",
                     net_policy="direct", input_sha256="0" * 64, engine=_ENGINE_NAME,
                     started_at=1.0, security_warnings=["attested"])

    d = _dispatcher(tmp_path, store, attest_key=key,
                    runner=_runner(tmp_path, job, during=scribble))
    assert d.dispatch_once() is True
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert doc["worker_runtime"] == "runc" and doc["worker_tier"] is None
    assert doc["net_policy_effective"] == "none"
    assert doc["input_sha256"] == hashlib.sha256(_INPUT_BYTES).hexdigest()
    assert doc["started_at_ms"] > 10_000


def test_row_writes_after_done_cannot_change_the_receipt(tmp_path, key):
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    before = _receipt_path(tmp_path, job).read_bytes()
    store.update(job.job_id, worker_runtime="none", status=JobStatus.DONE, claim_id="node:x",
                 finished_at=1.0, input_sha256="0" * 64)
    assert _receipt_path(tmp_path, job).read_bytes() == before


def test_requeued_then_rerun_receipt_reflects_the_final_run_only(tmp_path, key, monkeypatch):
    """Attempt 1 left a receipt in the store and a stale row. Attempt 2 runs under a different
    runtime and policy; the served receipt must describe attempt 2 alone."""
    monkeypatch.setenv("BLASTBOX_NETPOLICY_DIRECT", "exit=direct")
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    (stale_dir / "metadata.json").write_bytes(b"{}")
    attest.seal_receipt(stale_dir, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine=_ENGINE_NAME, input_sha256="1" * 64, worker_runtime="runsc",
        worker_tier="gvisor", net_policy_effective="direct", net_exit="direct", started_at_ms=1,
        finished_at_ms=2))
    _blobs(tmp_path).put_output(job.job_id, stale_dir)
    store.update(job.job_id, status=JobStatus.RUNNING, claim_id="c1", worker_runtime="runsc",
                 worker_tier="gvisor", started_at=time.time() - 600)

    def ps_runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "", "")

    requeuer = _dispatcher(tmp_path, store, attest_key=key, runner=ps_runner)
    assert requeuer.requeue_orphaned_jobs() == 1
    assert store.get(job.job_id).status == JobStatus.QUEUED

    start = attest.now_ms()
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job),
                    engine_policy="direct")
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert doc["worker_runtime"] == "runc" and doc["worker_tier"] is None
    assert doc["net_policy_effective"] == "direct"
    assert doc["input_sha256"] == hashlib.sha256(_INPUT_BYTES).hexdigest()
    assert doc["started_at_ms"] >= start


def test_no_key_means_a_tombstone_and_the_job_still_completes(tmp_path):
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=None, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    assert _tombstone_reason(tmp_path, job) == "no attestation key"


def test_a_keyless_rerun_overwrites_a_superseded_receipt(tmp_path, key):
    """The store never deletes one object, so a superseded attempt's receipt would outlive a
    rerun that does not sign. The rerun's tombstone overwrites it."""
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    (stale_dir / "metadata.json").write_bytes(b"{}")
    attest.seal_receipt(stale_dir, key=key, observation=attest.RunObservation(
        job_id=job.job_id, engine=_ENGINE_NAME, input_sha256="1" * 64, worker_runtime="runsc",
        worker_tier=None, net_policy_effective="none", net_exit="none", started_at_ms=1,
        finished_at_ms=2))
    _blobs(tmp_path).put_output(job.job_id, stale_dir)
    d = _dispatcher(tmp_path, store, attest_key=None, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    assert _tombstone_reason(tmp_path, job) == "no attestation key"


def test_env_key_that_is_refused_disables_receipts_but_not_jobs(tmp_path, monkeypatch, caplog):
    bad = tmp_path / "bad.key"
    attest.load_or_create_key(bad)
    bad.chmod(0o644)
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(bad))
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=attest.FROM_ENV, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    assert _tombstone_reason(tmp_path, job) == "no attestation key"
    assert "DISABLED" in caplog.text


def test_env_key_is_generated_and_used(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_ATTEST_KEY", str(tmp_path / "pki" / "attest.key"))
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=attest.FROM_ENV, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    k = attest.load_existing_key(tmp_path / "pki" / "attest.key")
    _verify(k, json.loads(_receipt_path(tmp_path, job).read_bytes()))


def test_a_signing_failure_does_not_fail_the_job(tmp_path, key, monkeypatch, caplog):
    def boom(*a, **kw):
        raise RuntimeError("hsm on fire")

    monkeypatch.setattr(attest.AttestKey, "sign", boom)
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=key, runner=_runner(tmp_path, job))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    assert _tombstone_reason(tmp_path, job) == "signing failed"
    assert "receipt" in caplog.text.lower()


@pytest.mark.parametrize("with_key", [True, False])
def test_a_worker_planted_receipt_never_reaches_the_store(tmp_path, key, with_key):
    forged = b'{"attestation": {"attested": true, "worker_runtime": "none"}, "signature": "x"}'
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=key if with_key else None,
                    runner=_runner(tmp_path, job, plant=forged))
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    path = _receipt_path(tmp_path, job)
    if with_key:
        _verify(key, json.loads(path.read_bytes()))
        assert path.read_bytes() != forged
    else:
        assert _tombstone_reason(tmp_path, job) == "no attestation key"


def test_failed_job_gets_no_receipt(tmp_path, key):
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "boom")   # no output -> FAILED

    d = _dispatcher(tmp_path, store, attest_key=key, runner=runner)
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.FAILED
    assert not _receipt_path(tmp_path, job).exists()


# ---------------------------------------------------------------------------
# Warm path
# ---------------------------------------------------------------------------


def test_warm_receipt(tmp_path, key):
    from tests.host.test_dispatch_warm import (
        FakeWarmPool,
        _make_slot,
        _start_fake_worker,
    )
    from tests.host.test_dispatch_warm import _engine_spec as _warm_engine
    from tests.host.test_dispatch_warm import _fake_runtime as _warm_runtime
    from tests.host.test_dispatch_warm import _make_valid_output_dir as _warm_out

    store = InMemoryJobStore()
    job = _queue(tmp_path, store, net_policy="undeclared")
    slot = _make_slot(tmp_path)
    _start_fake_worker(slot, output_fn=lambda o: _warm_out(o, input_sha256=_INPUT_SHA))
    d = Dispatcher(
        job_store=store, engines={_ENGINE_NAME: _warm_engine()}, limits=_limits(),
        job_root=tmp_path / "jobs", runtime_selector=_warm_runtime,
        subprocess_runner=lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
        worker_timeout_s=10, pool=FakeWarmPool(slot), tier="gvisor",
        warm_claim_timeout_s=0.5, warm_requeue_backoff_s=0.0, blob_store=_blobs(tmp_path),
        attest_key=key,
    )
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    meta = (tmp_path / "blobs" / "results" / job.job_id / "metadata.json").read_bytes()
    assert doc["worker_runtime"] == "warm" and doc["worker_tier"] == "gvisor"
    assert doc["net_policy_effective"] == "none" and doc["net_exit"] == "none"
    assert doc["input_sha256"] == hashlib.sha256(_INPUT_BYTES).hexdigest()
    assert doc["metadata_sha256"] == hashlib.sha256(meta).hexdigest()


# ---------------------------------------------------------------------------
# VM tier: egress fixed at spawn -- the declared pool egress, or nothing
# ---------------------------------------------------------------------------


def _vm_run(tmp_path, key, *, fixed=None, net_policy=None, scribble=False):
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher
    from tests.host.test_vm_dispatch import _queue_job

    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path / "jobs", body=b"MZ-real-bytes")
    job.net_policy = net_policy

    def validate(path):
        if scribble:
            store.update(job.job_id, worker_runtime="none", worker_tier="firecracker",
                         input_sha256="0" * 64)
        return ({"verdict": "ok"}, True)

    d = VmJobDispatcher(store, str(tmp_path / "jobs"), validate, worker_tier="libvirt-vm",
                        fixed_net_policy=fixed, blob_store=_blobs(tmp_path), attest_key=key)
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE
    return job


def test_vm_tier_never_signs_a_policy_it_did_not_enforce(tmp_path, key):
    """A VM/remote tier's "fixed" egress is the ENGINE's declared personality; enforcement is at
    best an env var in the untrusted remote worker (Lambda with default egress, a static endpoint
    on an open network, a permissive EC2 SG all run with internet). The dispatcher did not
    enforce it, so the receipt must not sign it -- even when declared."""
    job = _vm_run(tmp_path, key, fixed="fakenet", net_policy="fakenet", scribble=True)
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    meta = (tmp_path / "blobs" / "results" / job.job_id / "metadata.json").read_bytes()
    assert doc["worker_runtime"] == "warm" and doc["worker_tier"] == "libvirt-vm"
    assert "net_policy_effective" not in doc and "net_exit" not in doc
    assert doc["input_sha256"] == hashlib.sha256(b"MZ-real-bytes").hexdigest()
    assert doc["metadata_sha256"] == hashlib.sha256(meta).hexdigest()


def test_vm_tier_with_undeclared_egress_omits_the_policy(tmp_path, key):
    job = _vm_run(tmp_path, key, net_policy="tor")
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert "net_policy_effective" not in doc


def test_vm_tier_without_a_key_writes_a_tombstone(tmp_path):
    job = _vm_run(tmp_path, None)
    assert _tombstone_reason(tmp_path, job) == "no attestation key"


def test_network_endpoint_tiers_sign_no_policy(tmp_path, key):
    """The review's repro: build_remote_vm_dispatcher for a static endpoint sets
    fixed_net_policy from the engine spec. The receipt must still omit the policy."""
    import types

    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    from blastbox.limits import Limits
    from tests.host.test_vm_dispatch import _queue_job

    rt = types.SimpleNamespace(dispatch_style="network",
                               cfg=types.SimpleNamespace(resume_timeout_s=None))
    pool = types.SimpleNamespace(runtime=rt, claim=lambda **k: None,
                                 release=lambda *a, **k: None)
    spec = types.SimpleNamespace(net_policy="none", allowed_param_keys=(),
                                 reserved_param_keys=(), default_params=None)
    store = InMemoryJobStore()
    vm = build_remote_vm_dispatcher(store, str(tmp_path / "jobs"), pool, tier="static",
                                    engine="authenticode", engine_spec=spec, limits=Limits())
    assert vm._fixed_net_policy == "none"            # the engine's DECLARATION, not enforcement
    vm._blobs = _blobs(tmp_path)
    vm._attest_key = key
    vm._validate = lambda p, **kw: ({"verdict": "ok"}, True)
    vm._output_validator = None
    vm._trust_output_metadata = False
    job = _queue_job(store, tmp_path / "jobs", body=b"MZ")
    vm._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert "net_policy_effective" not in doc and "net_exit" not in doc


# ---------------------------------------------------------------------------
# Cold path: a containment claim is signed only when verified for THIS run
# ---------------------------------------------------------------------------


def _posture_runner(tmp_path, job, *, internal: "dict[str, str | None]", calls=None):
    """docker run -> valid output; docker network inspect <net> -> internal[net] (None = error)."""
    out = tmp_path / "jobs" / job.job_id / "output"

    def run(argv, **kw):
        if argv[:3] == ["docker", "network", "inspect"]:
            net = argv[-1]
            if calls is not None:
                calls.append(net)
            val = internal.get(net)
            if val is None:
                return subprocess.CompletedProcess(argv, 1, "", "Error: No such network")
            return subprocess.CompletedProcess(argv, 0, val + "\n", "")
        if argv[:2] == ["docker", "run"]:
            _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
        return subprocess.CompletedProcess(argv, 0, "", "")
    return run


def _cold_doc(tmp_path, key, monkeypatch, *, decl, internal, calls=None, health=None):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_P", decl)
    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    d = _dispatcher(tmp_path, store, attest_key=key, engine_policy="p",
                    runner=_posture_runner(tmp_path, job, internal=internal, calls=calls))
    if health is not None:
        monkeypatch.setattr(d, "_node_egress_health", lambda: health)
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE, store.get(job.job_id).error
    return _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))


def test_bridge_exit_signed_when_the_bridge_is_verified_internal(tmp_path, key, monkeypatch):
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=inetsim",
                    internal={"bb-fakenet": "true"})
    assert doc["net_policy_effective"] == "p" and doc["net_exit"] == "inetsim"
    assert "net_downgraded" not in doc and "net_inspect" not in doc


@pytest.mark.parametrize("state", ["false", None, "garbage"])
def test_bridge_exit_omitted_when_the_bridge_is_not_verified(tmp_path, key, monkeypatch,
                                                            caplog, state):
    """A hand-made/recreated non-internal bb-fakenet gives the sample real internet. Unless this
    dispatcher verified the bridge is --internal, it must not sign 'inetsim'."""
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=inetsim",
                    internal={"bb-fakenet": state})
    assert "net_policy_effective" not in doc and "net_exit" not in doc
    assert "bb-fakenet" in caplog.text


def test_bridge_verification_is_cached_briefly(tmp_path, key, monkeypatch):
    monkeypatch.setenv("BLASTBOX_NETPOLICY_P", "exit=inetsim")
    store = InMemoryJobStore()
    calls: list[str] = []
    jobs = [_queue(tmp_path, store) for _ in range(2)]
    outs = {j.job_id: tmp_path / "jobs" / j.job_id / "output" for j in jobs}

    def run(argv, **kw):
        if argv[:3] == ["docker", "network", "inspect"]:
            calls.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "true\n", "")
        if argv[:2] == ["docker", "run"]:
            name = next(a for a in argv if a.startswith("--name")) if any(
                a.startswith("--name") for a in argv) else ""
            for jid, out in outs.items():
                if jid in " ".join(argv):
                    _make_valid_output_dir(out, input_sha256=_INPUT_SHA)
            del name
        return subprocess.CompletedProcess(argv, 0, "", "")

    d = _dispatcher(tmp_path, store, attest_key=key, engine_policy="p", runner=run)
    assert d.dispatch_once() is True and d.dispatch_once() is True
    assert calls == ["bb-fakenet"]


def test_direct_makes_no_containment_claim_and_needs_no_check(tmp_path, key, monkeypatch):
    calls: list[str] = []
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=direct", internal={}, calls=calls)
    assert doc["net_exit"] == "direct" and calls == []


def test_none_is_always_verified(tmp_path, key, monkeypatch):
    calls: list[str] = []
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=drop", internal={}, calls=calls)
    assert doc["net_exit"] == "drop" and calls == []
    assert "net_downgraded" not in doc


def test_a_downgrade_signs_what_was_applied(tmp_path, key, monkeypatch):
    """exit=httpproxy,inspect=1 cannot be route-inspected, so the args fail closed to
    --network=none. The receipt signs the APPLIED posture, flagged as a downgrade."""
    calls: list[str] = []
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=httpproxy,inspect=1,proxy=http://x:1",
                    internal={}, calls=calls)
    assert doc["net_policy_effective"] == "p"
    assert doc["net_exit"] == "none" and doc["net_downgraded"] is True
    assert "net_inspect" not in doc and calls == []


def test_an_inspected_run_is_flagged_and_needs_bb_inspect_verified(tmp_path, key, monkeypatch):
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=direct,inspect=1,gateway=172.30.9.1",
                    internal={"bb-inspect": "true"})
    assert doc["net_exit"] == "direct" and doc["net_inspect"] is True


def test_an_inspected_run_on_an_unverified_bb_inspect_is_omitted(tmp_path, key, monkeypatch):
    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=direct,inspect=1,gateway=172.30.9.1",
                    internal={"bb-inspect": "false"})
    assert "net_policy_effective" not in doc and "net_inspect" not in doc


def test_vpn_exit_needs_a_positive_gateway_health_verdict(tmp_path, key, monkeypatch):
    from blastbox.host.egress import Health

    doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=wireguard,gateway=172.30.9.1",
                    internal={"bb-vpn": "true"}, health=Health(True, "ok"))
    assert doc["net_exit"] == "wireguard"


@pytest.mark.parametrize("health", ["gate-off", "bridge-open"])
def test_vpn_exit_omitted_without_verification(tmp_path, key, monkeypatch, health):
    from blastbox.host.egress import Health

    if health == "gate-off":       # the health gate is not armed: nothing verified the gateway
        doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=wireguard,gateway=172.30.9.1",
                        internal={"bb-vpn": "true"})
    else:
        doc = _cold_doc(tmp_path, key, monkeypatch, decl="exit=wireguard,gateway=172.30.9.1",
                        internal={"bb-vpn": "false"}, health=Health(True, "ok"))
    assert "net_policy_effective" not in doc and "net_exit" not in doc


# ---------------------------------------------------------------------------
# Warm path on a local cascade: sign the member tier that owned the slot
# ---------------------------------------------------------------------------


def test_warm_cascade_signs_the_member_tier_that_ran_the_slot(tmp_path, key):
    from tests.host.test_dispatch_warm import (
        FakeWarmPool,
        _make_slot,
        _start_fake_worker,
    )
    from tests.host.test_dispatch_warm import _engine_spec as _warm_engine
    from tests.host.test_dispatch_warm import _fake_runtime as _warm_runtime
    from tests.host.test_dispatch_warm import _make_valid_output_dir as _warm_out

    class _CascadeLike:
        def slot_tier(self, slot):
            return "firecracker"

    store = InMemoryJobStore()
    job = _queue(tmp_path, store)
    slot = _make_slot(tmp_path)
    _start_fake_worker(slot, output_fn=lambda o: _warm_out(o, input_sha256=_INPUT_SHA))
    d = Dispatcher(
        job_store=store, engines={_ENGINE_NAME: _warm_engine()}, limits=_limits(),
        job_root=tmp_path / "jobs", runtime_selector=_warm_runtime,
        subprocess_runner=lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
        worker_timeout_s=10, pool=FakeWarmPool(slot, runtime=_CascadeLike()), tier="cascade",
        warm_claim_timeout_s=0.5, warm_requeue_backoff_s=0.0, blob_store=_blobs(tmp_path),
        attest_key=key,
    )
    assert d.dispatch_once() is True
    assert store.get(job.job_id).status == JobStatus.DONE
    doc = _verify(key, json.loads(_receipt_path(tmp_path, job).read_bytes()))
    assert doc["worker_tier"] == "firecracker"


def test_cascade_runtime_reports_the_owning_tier():
    import threading
    import types

    from blastbox.host.runtime.cascade import CascadingRuntime, Tier

    rt = object.__new__(CascadingRuntime)
    rt._lock = threading.RLock()
    rt.tiers = [Tier(name="gvisor", runtime=object(), capacity=1),
                Tier(name="firecracker", runtime=object(), capacity=1)]
    rt._owner = {"s0": 0, "s1": 1}
    assert rt.slot_tier(types.SimpleNamespace(slot_id="s1")) == "firecracker"
    assert rt.slot_tier(types.SimpleNamespace(slot_id="s0")) == "gvisor"
    assert rt.slot_tier(types.SimpleNamespace(slot_id="gone")) is None
