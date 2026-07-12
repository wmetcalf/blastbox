"""Unit tests for the libvirt pool job dispatcher (in-memory store; validate stubbed)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

# the trust-gated remote factory requires limits (uses getattr(...,None) for caps); an empty ns suffices
# for construction tests that never actually run the trust gate.
_FAKE_LIMITS = SimpleNamespace(max_total_artifact_bytes=None, max_artifacts=None, max_metadata_bytes=None)


def _queue_job(store, tmp_path, filename="evil.dll", body=b"MZ"):
    job = Job.new(engine="authenticode", filename=filename)
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / filename).write_bytes(body)
    job.result_dir = str(root)
    store.create(job)
    return job


def test_dispatch_marks_done_with_summary_and_unlinks_input(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    seen = {}

    def validate(path):
        seen["path"] = path
        return ({"verdict": {"status": "Revoked"}}, True)

    d = VmJobDispatcher(store, str(tmp_path), validate, worker_tier="libvirt-vm")
    d._process(store.claim_next())                       # claim_next -> RUNNING + claim_id
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary["verdict"]["status"] == "Revoked"
    assert seen["path"].name == "evil.dll"
    assert not (tmp_path / job.job_id / "input" / "evil.dll").exists()   # input consumed
    # marked as a warm worker so a peer's crash-recovery sweep won't treat it as a dead cold job.
    assert got.worker_runtime == "warm"
    assert got.worker_tier == "libvirt-vm"


def test_fail_stale_queued_jobs(tmp_path):
    import time
    store = InMemoryJobStore()
    old = _queue_job(store, tmp_path, filename="stale.dll")
    old.created_at = time.time() - 10_000        # far past the TTL
    fresh = _queue_job(store, tmp_path, filename="fresh.dll")

    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        engine="authenticode", max_queued_age_s=1.0)
    d._fail_stale_queued_jobs()

    assert store.get(old.job_id).status is JobStatus.FAILED
    assert "max queued age" in (store.get(old.job_id).error or "")
    assert not (tmp_path / old.job_id / "input" / "stale.dll").exists()   # untrusted input deleted
    assert store.get(fresh.job_id).status is JobStatus.QUEUED             # fresh job untouched


def test_fail_stale_queued_sweeps_other_engines_when_sole_owner(tmp_path):
    import time
    store = InMemoryJobStore()
    other = _queue_job(store, tmp_path, filename="orphan.bin")
    other.engine = "some-unserved-engine"       # an engine THIS dispatcher doesn't serve
    other.created_at = time.time() - 10_000
    # sole_owner => no peer dispatcher, so a job for an engine nobody serves must still be swept.
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        engine="authenticode", max_queued_age_s=1.0, sole_owner=True)
    d._fail_stale_queued_jobs()
    assert store.get(other.job_id).status is JobStatus.FAILED


def test_fail_stale_queued_scopes_to_engine_when_not_sole_owner(tmp_path):
    import time
    store = InMemoryJobStore()
    other = _queue_job(store, tmp_path, filename="orphan.bin")
    other.engine = "some-other-engine"
    other.created_at = time.time() - 10_000
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        engine="authenticode", max_queued_age_s=1.0)  # sole_owner False (default)
    d._fail_stale_queued_jobs()
    assert store.get(other.job_id).status is JobStatus.QUEUED   # a peer owns that engine -> left alone


def test_fail_stale_queued_disabled_by_default(tmp_path):
    import time
    store = InMemoryJobStore()
    old = _queue_job(store, tmp_path, filename="stale.dll")
    old.created_at = time.time() - 10_000
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), engine="authenticode")  # TTL 0 = off
    d._fail_stale_queued_jobs()
    assert store.get(old.job_id).status is JobStatus.QUEUED   # no TTL configured -> no-op


def test_dispatch_writes_metadata_json_on_done(tmp_path):
    # ingress /metadata, /artifacts, /result require <output>/metadata.json once a job is DONE; the
    # dispatcher materializes it from the summary so those routes don't 404 on a VM job.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"verdict": {"status": "Valid"}}, True))
    d._process(store.claim_next())
    meta = tmp_path / job.job_id / "output" / "metadata.json"
    assert meta.is_file()
    import json
    assert json.loads(meta.read_text())["verdict"]["status"] == "Valid"


def test_dispatch_metadata_overwrites_stale_and_neuters_artifacts(tmp_path):
    # metadata.json is overwritten (not skip-if-exists) so a reclaim race resolves to OUR validation,
    # and the guest-supplied artifacts list is neutered to [] (never served as trusted output).
    import json
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_text('{"stale": true, "artifacts": [{"id": "x", "path": "../etc"}]}')
    d = VmJobDispatcher(store, str(tmp_path),
                        lambda p: ({"verdict": "ok", "artifacts": [{"id": "y", "path": "z"}]}, True))
    d._process(store.claim_next())
    meta = json.loads((out / "metadata.json").read_text())
    assert meta.get("verdict") == "ok" and "stale" not in meta   # overwritten with our result
    assert meta["artifacts"] == []                               # guest artifacts neutered (security)


def test_dispatch_trust_output_metadata_preserves_sealed_artifacts(tmp_path):
    # remote_http path: the transport already sealed output/metadata.json (with the real, host-extracted
    # artifact list) -> preserve it instead of clobbering to artifacts:[].
    import json
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True)
    sealed = {"status": "ok", "artifacts": [{"id": "p1", "path": "page.png", "sha256": "ab", "bytes": 3}]}
    (out / "metadata.json").write_text(json.dumps(sealed))
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (sealed, True), trust_output_metadata=True)
    d._process(store.claim_next())
    meta = json.loads((out / "metadata.json").read_text())
    assert meta["status"] == "ok"
    assert meta["artifacts"][0]["id"] == "p1"   # preserved, NOT neutered


def test_dispatch_forwards_sanitized_params_to_validate(tmp_path):
    # per-job params reach a params-aware validate() (the remote_http seam), gated by the sanitize hook
    store = InMemoryJobStore()
    job = Job.new(engine="clippyshot", filename="f.docx")
    job.params = {"CLIPPYSHOT_OCR": "1", "bad key": "x"}
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / "f.docx").write_bytes(b"z")
    job.result_dir = str(root)
    store.create(job)
    seen = {}

    def validate(path, *, params=None):
        seen["params"] = params
        return ({"status": "ok"}, True)

    d = VmJobDispatcher(store, str(tmp_path), validate,
                        sanitize_params=lambda p: {k: v for k, v in p.items() if k == "CLIPPYSHOT_OCR"})
    d._process(store.claim_next())
    assert seen["params"] == {"CLIPPYSHOT_OCR": "1"}   # allowlisted key forwarded; "bad key" dropped


def test_dispatch_legacy_validate_without_params_kwarg(tmp_path):
    # a validate() that doesn't accept params (the libvirt-vm seam) must still work unchanged
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"verdict": "ok"}, True),
                        sanitize_params=lambda p: p)
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE


def test_output_validator_failure_fails_job(tmp_path):
    # the remote trust gate: a validator that raises (engine/input-sha/hash mismatch) FAILs the job
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def boom(job, out_dir):  # noqa: ANN001
        raise RuntimeError("hash mismatch")

    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"status": "ok"}, True), output_validator=boom)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert "trust validation failed" in (got.error or "")


def test_output_validator_success_marks_done(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    called = {}
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"status": "ok"}, True),
                        output_validator=lambda j, o: called.setdefault("ok", True))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE and called["ok"]


def test_vm_dispatch_indexes_page_hashes_when_store_supports_it(tmp_path):
    from blastbox.contract import ArtifactRef, Detection, Dimensions, Page
    from blastbox.contract.envelope import Envelope

    calls = []

    class HashStore(InMemoryJobStore):
        def supports_hash_search(self):
            return True

        def index_page_hashes(self, jid, env):
            calls.append((jid, type(env).__name__))
            return 1

    store = HashStore()
    job = _queue_job(store, tmp_path)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    env = Envelope(engine="authenticode", input_sha256="ab" * 32,
                   detected=Detection(label="dll", mime="application/octet-stream", confidence=1.0, source="t"),
                   payload=Page(index=0, dims=Dimensions(width=1.0, height=1.0, unit="px"),
                                image=ArtifactRef(id="a0")))
    (out / "metadata.json").write_text(env.model_dump_json(by_alias=True))

    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"status": "ok"}, True), engine="authenticode")
    env_parsed = d._sealed_envelope(job)                 # parses the sealed metadata.json -> Envelope
    assert type(env_parsed).__name__ == "Envelope"
    d._index_page_hashes(job, env_parsed)
    assert calls == [(job.job_id, "Envelope")]   # sealed metadata.json fed through the indexer


def test_remote_done_stores_compact_summary(tmp_path):
    # trust_output_metadata (remote path): result_summary must be the COMPACT derivative (like cold),
    # NOT the full sealed metadata dict -- the full envelope stays in metadata.json for /metadata.
    from blastbox.contract import ArtifactRef, Detection, Dimensions, Page
    from blastbox.contract.envelope import Envelope
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    out = tmp_path / job.job_id / "output"
    out.mkdir(parents=True, exist_ok=True)
    env = Envelope(engine="authenticode", input_sha256="ab" * 32,
                   detected=Detection(label="dll", mime="application/octet-stream", confidence=1.0, source="t"),
                   payload=Page(index=0, dims=Dimensions(width=1.0, height=1.0, unit="px"),
                                image=ArtifactRef(id="a0")))
    (out / "metadata.json").write_text(env.model_dump_json(by_alias=True))
    fat = {"status": "ok", "payload": {"blob": "y" * 5000}, "artifacts": [1, 2, 3]}   # what the transport returns
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (fat, True), engine="authenticode",
                        trust_output_metadata=True)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary.get("detected") == "dll" and "artifact_count" in got.result_summary
    assert "payload" not in got.result_summary   # the fat payload was NOT persisted on the job


def test_remote_no_slot_requeues_not_fails(tmp_path):
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def validate(path):
        raise NoWarmSlot("no warm slot available within claim timeout")

    d = VmJobDispatcher(store, str(tmp_path), validate, engine="authenticode")
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.QUEUED and got.claim_id is None   # requeued (never ran), NOT failed
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists()   # input preserved for the retry


def test_dispatch_records_terminal_metrics(tmp_path):
    # parity with the cold dispatcher: a terminal job bumps dispatched(path,outcome) + a warm-claim HIT.
    import blastbox.observability.metrics as m
    store = InMemoryJobStore()
    _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"status": "ok"}, True),
                        worker_tier="aws-ec2-hibernate")
    bd = m.JOBS_DISPATCHED_TOTAL.labels(path="aws-ec2-hibernate", outcome="done")._value.get()
    bh = m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get()
    bc = m.JOB_DURATION_SECONDS.labels(path="aws-ec2-hibernate")._sum.get()
    d._process(store.claim_next())
    assert m.JOBS_DISPATCHED_TOTAL.labels(path="aws-ec2-hibernate", outcome="done")._value.get() == bd + 1
    assert m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get() == bh + 1
    assert m.JOB_DURATION_SECONDS.labels(path="aws-ec2-hibernate")._sum.get() >= bc   # duration observed


def test_requeue_records_warm_claim_miss(tmp_path):
    # a NoWarmSlot requeue is a warm-pool MISS, and must NOT count as a dispatched/hit (the job never ran).
    import blastbox.observability.metrics as m
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot
    store = InMemoryJobStore()
    _queue_job(store, tmp_path)

    def validate(path):
        raise NoWarmSlot("no warm slot available within claim timeout")

    d = VmJobDispatcher(store, str(tmp_path), validate, engine="authenticode", worker_tier="aws-ec2")
    bmiss = m.WARM_CLAIMS_TOTAL.labels(result="miss")._value.get()
    bhit = m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get()
    d._process(store.claim_next())
    assert m.WARM_CLAIMS_TOTAL.labels(result="miss")._value.get() == bmiss + 1
    assert m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get() == bhit       # no false hit for a requeue


def test_requeue_ignores_peer_finish_for_metrics(tmp_path, monkeypatch):
    # F4 race: after THIS attempt requeues on NoWarmSlot (owned=False), a PEER can claim + finish the job
    # so the store reports DONE by the time our finally runs. The terminal metric must gate on this
    # attempt's own winning CAS, NOT the store's current state -- else a tier that only recorded a
    # warm-claim MISS would also record a hit + 'done' it never earned (double-count / wrong attribution).
    from types import SimpleNamespace
    import blastbox.observability.metrics as m
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot
    store = InMemoryJobStore()
    _queue_job(store, tmp_path)

    def validate(path):
        raise NoWarmSlot("no warm slot available within claim timeout")

    d = VmJobDispatcher(store, str(tmp_path), validate, engine="authenticode", worker_tier="aws-ec2")
    j = store.claim_next()
    monkeypatch.setattr(store, "get", lambda jid: SimpleNamespace(status=JobStatus.DONE))  # peer "finished" it
    bhit = m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get()
    bdone = m.JOBS_DISPATCHED_TOTAL.labels(path="aws-ec2", outcome="done")._value.get()
    d._process(j)
    assert m.WARM_CLAIMS_TOTAL.labels(result="hit")._value.get() == bhit             # no false hit
    assert m.JOBS_DISPATCHED_TOTAL.labels(path="aws-ec2", outcome="done")._value.get() == bdone  # no false 'done'


def test_vm_dispatch_skips_indexing_when_unsupported(tmp_path):
    # a store without hash-search support (memory/redis) -> no-op, never raises
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"status": "ok"}, True))
    d._index_page_hashes(job, None)   # must not raise


def test_resume_on_claim_calls_runtime_resume():
    from types import SimpleNamespace

    from blastbox.host.runtime.vm_dispatch import _resume_on_claim
    seen = {}
    slot = SimpleNamespace(slot_id="s1")
    pool = SimpleNamespace(
        runtime=SimpleNamespace(resume=lambda s: seen.setdefault("resumed", s)),
        release=lambda s, dirty=False: seen.setdefault("released", dirty),
    )
    _resume_on_claim(pool, slot)
    assert seen["resumed"] is slot and "released" not in seen   # resumed, not released


def test_resume_on_claim_releases_dirty_on_failure():
    from types import SimpleNamespace

    from blastbox.host.runtime.vm_dispatch import _resume_on_claim
    seen = {}

    def boom(_s):
        raise RuntimeError("resume failed")

    slot = SimpleNamespace(slot_id="s1")
    pool = SimpleNamespace(
        runtime=SimpleNamespace(resume=boom),
        release=lambda s, dirty=False: seen.setdefault("released_dirty", dirty),
    )
    with pytest.raises(RuntimeError, match="resume failed"):
        _resume_on_claim(pool, slot)
    assert seen["released_dirty"] is True   # un-resumable slot retired dirty, not leaked


def test_resume_on_claim_noop_without_resume():
    from types import SimpleNamespace

    from blastbox.host.runtime.vm_dispatch import _resume_on_claim
    # a runtime without a resume() method (disposable ec2/static/etc.) is a no-op
    pool = SimpleNamespace(runtime=SimpleNamespace(), release=lambda *a, **k: None)
    _resume_on_claim(pool, SimpleNamespace(slot_id="s1"))   # must not raise


def test_build_remote_vm_dispatcher_constructs(tmp_path):
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher

    class _FakePool:
        runtime = type("R", (), {"ssl_context": None})()

        def claim(self, *, timeout_s):  # noqa: ANN001, ANN202
            return None

        def release(self, slot, *, dirty=False):  # noqa: ANN001
            pass

    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", limits=_FAKE_LIMITS)
    assert isinstance(vm, VmJobDispatcher)
    assert vm._trust_output_metadata is True        # the remote path preserves the sealed metadata
    assert vm._validate_takes_params is True         # the remote_http validate accepts params
    assert vm._validate_takes_owns is True           # ...and the ownership predicate (metadata fence)


def test_remote_claim_budget_is_bounded_and_reserves_detonation_time(tmp_path):
    # F3: the claim WAIT and the detonation must not share one budget. The claim is bounded by
    # warm_claim_timeout_s (NOT worker_timeout_s), and the heartbeat watchdog covers claim + detonate so
    # a slot claimed late still gets the full worker_timeout_s to run instead of being watchdog-killed.
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot, build_remote_vm_dispatcher
    seen = {}

    class _NeverYieldsPool:
        runtime = type("R", (), {"ssl_context": None})()

        def claim(self, *, timeout_s):  # noqa: ANN001, ANN202
            seen["claim_timeout"] = timeout_s
            return None

        def release(self, slot, *, dirty=False):  # noqa: ANN001
            pass

    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _NeverYieldsPool(),
                                    tier="aws-ec2", engine="clippyshot", limits=_FAKE_LIMITS,
                                    worker_timeout_s=300.0, warm_claim_timeout_s=0.05)
    assert vm._validate_timeout_s == pytest.approx(300.05)   # watchdog = claim budget + detonate budget
    with pytest.raises(NoWarmSlot):
        vm._validate(tmp_path / "in.bin")                    # no slot within the claim budget -> requeue
    assert seen["claim_timeout"] <= 0.05                     # bounded by warm_claim_timeout_s, not 300s


def test_remote_watchdog_includes_resume_budget(tmp_path):
    # G5: for a resume-based tier the in-claim wake (resume_timeout_s) runs BEFORE detonation, so the
    # watchdog must cover claim + resume + detonate -- else a late+slow resume eats the detonation budget
    # and the job is killed mid-run. Here resume_timeout_s=180 (EC2-hibernate default).
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    pool = SimpleNamespace(
        runtime=SimpleNamespace(ssl_context=None, cfg=SimpleNamespace(resume_timeout_s=180.0)),
        claim=lambda *, timeout_s: None, release=lambda s, dirty=False: None,
    )
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                    tier="aws-ec2-hibernate", engine="clippyshot", limits=_FAKE_LIMITS,
                                    worker_timeout_s=300.0, warm_claim_timeout_s=60.0)
    assert vm._validate_timeout_s == pytest.approx(540.0)   # 60 claim + 180 resume + 300 detonate


def test_remote_all_stale_resume_slots_requeues_not_fails(tmp_path):
    # F3: if every slot in the claim window is un-resumable (AWS auto-terminated parked slots in a batch),
    # _claim must raise NoWarmSlot (-> the job REQUEUES, input preserved), NOT the resume exception (which
    # _process would treat as a job failure and delete the input, though the job never ran).
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot, build_remote_vm_dispatcher
    slot = SimpleNamespace(slot_id="s1", url="http://x", auth_token=None, agent_port=8765)
    calls = {"n": 0}

    def claim(*, timeout_s):
        calls["n"] += 1
        return slot if calls["n"] == 1 else None   # one stale slot, then the window is empty

    def resume(s):
        raise RuntimeError("snapstart slot 's1' is 'terminated'; cannot resume")

    pool = SimpleNamespace(runtime=SimpleNamespace(ssl_context=None, resume=resume),
                           claim=claim, release=lambda s, dirty=False: None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                    tier="aws-lambda-snapstart", engine="clippyshot", limits=_FAKE_LIMITS,
                                    warm_claim_timeout_s=5.0)
    with pytest.raises(NoWarmSlot):
        vm._validate(tmp_path / "in.bin")          # resume-failure window -> requeue, not fail


def test_run_sets_stop_on_interrupt_so_executor_can_join(tmp_path):
    # H2: a KeyboardInterrupt out of run()'s _stop.wait() must set _stop in a finally BEFORE the
    # ThreadPoolExecutor joins the worker loops -- else the loops (which spin on _stop) never exit and the
    # join deadlocks, so the CLI's vm.stop()/pool.stop() never reap live cloud slots. Assert _stop ends up
    # set and run() returns (doesn't hang).
    store = InMemoryJobStore()
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), engine="authenticode", concurrency=1)
    orig_wait = d._stop.wait

    def fake_wait(timeout=None):
        if timeout is None:            # the run() main-thread block == the interrupt point
            raise KeyboardInterrupt
        return orig_wait(timeout)      # worker/maintenance loop backoffs

    d._stop.wait = fake_wait           # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        d.run()
    assert d._stop.is_set()            # set in the finally -> loops exit, executor joins, no deadlock


def test_remote_watchdog_includes_cleanup_budget(tmp_path):
    # H3: the watchdog must also cover the SYNCHRONOUS post-job terminate (disposable tiers release() in
    # make_remote_validate's finally, bounded by cli_timeout_s), else a job that used most of
    # worker_timeout_s is watchdog-killed while terminating -- after its output was received + trusted.
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    pool = SimpleNamespace(
        runtime=SimpleNamespace(ssl_context=None,
                                cfg=SimpleNamespace(resume_timeout_s=180.0, cli_timeout_s=120.0)),
        claim=lambda *, timeout_s: None, release=lambda s, dirty=False: None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                    tier="aws-lambda-snapstart", engine="clippyshot", limits=_FAKE_LIMITS,
                                    worker_timeout_s=300.0, warm_claim_timeout_s=60.0)
    # 60 claim + 180 resume + 300 detonate + 120 cleanup
    assert vm._validate_timeout_s == pytest.approx(660.0)


def test_remote_watchdog_cleanup_budget_from_cascade_attr(tmp_path):
    # I1: a cascade has no cfg, so the cleanup budget must come from its aggregated cli_timeout_s ATTR
    # (same fallback the resume budget uses) -- else a cascaded AWS job is watchdog-killed during terminate.
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    pool = SimpleNamespace(
        runtime=SimpleNamespace(ssl_context=None, resume_timeout_s=180.0, cli_timeout_s=120.0),  # no cfg
        claim=lambda *, timeout_s: None, release=lambda s, dirty=False: None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                    tier="cascade", engine="clippyshot", limits=_FAKE_LIMITS,
                                    worker_timeout_s=300.0, warm_claim_timeout_s=60.0)
    assert vm._validate_timeout_s == pytest.approx(660.0)   # 60 + 180 resume + 300 + 120 cleanup (attr)


def test_remote_factory_threads_engine_net_policy(tmp_path, monkeypatch):
    # I2: a programmatic caller with engine_spec.net_policy but no BLASTBOX_ENGINE_<NAME>_NETPOLICY export
    # must source the job DEFAULT from the same spec as the fixed policy -- else every untargeted job is
    # rejected ('none' default != 'inspect' fixed).
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    monkeypatch.setenv("BLASTBOX_NETPOLICY_INSPECT", "exit=direct")
    monkeypatch.delenv("BLASTBOX_ENGINE_CLIPPYSHOT_NETPOLICY", raising=False)
    spec = SimpleNamespace(net_policy="inspect", allowed_param_keys=frozenset(),
                           reserved_param_keys=frozenset(), default_params=None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    assert vm._engine_net_policy == "inspect"   # job default now sourced from the spec, matching fixed
    assert vm._fixed_net_policy == "inspect"


def test_remote_factory_forwards_output_caps_to_worker(tmp_path):
    # I3: the host-owned metadata/artifact/file caps must reach the worker (which enforces its OWN
    # Limits.from_env caps + HTTP 500s an over-cap result BEFORE returning the tar), so a dispatcher-raised
    # cap doesn't fail at the agent. They ride the dispatcher-owned _net_env (merged last).
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    spec = SimpleNamespace(net_policy="none", allowed_param_keys=frozenset(),
                           reserved_param_keys=frozenset(), default_params=None)
    limits = SimpleNamespace(max_metadata_bytes=104857600, max_total_artifact_bytes=500_000_000,
                             max_artifacts=2000, max_artifact_bytes=209715200)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=limits)
    out = vm._sanitize({})
    assert out["BLASTBOX_MAX_METADATA"] == "104857600"
    assert out["BLASTBOX_MAX_TOTAL_ARTIFACTS"] == "500000000"
    assert out["BLASTBOX_MAX_ARTIFACTS"] == "2000"
    assert out["BLASTBOX_MAX_ARTIFACT"] == "209715200"   # per-artifact cap too (engines read it)


def test_remote_factory_fixed_policy_is_resolved_not_raw(tmp_path, monkeypatch):
    # L2: a malformed/missing BLASTBOX_NETPOLICY_* resolves fail-closed to 'none' (worker sealed). The
    # fixed policy must be that RESOLVED name, not the raw spec -- else a job matching the raw name runs on
    # a sealed worker instead of being rejected.
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    monkeypatch.delenv("BLASTBOX_NETPOLICY_INSPECT", raising=False)   # personality NOT declared
    spec = SimpleNamespace(net_policy="inspect", allowed_param_keys=frozenset(),
                           reserved_param_keys=frozenset(), default_params=None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    assert vm._fixed_net_policy == "none"        # RESOLVED (fail-closed), NOT the raw "inspect"
    assert vm._engine_net_policy == "none"       # job DEFAULT also resolved -> untargeted jobs run SEALED
    #                                              (effective "none" == fixed "none"), not rejected
    monkeypatch.setenv("BLASTBOX_NETPOLICY_INSPECT", "exit=direct")   # now properly declared
    vm2 = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                     tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    assert vm2._fixed_net_policy == "inspect"    # declared -> resolves to its own name (normal case unchanged)
    assert vm2._engine_net_policy == "inspect"


def test_remote_factory_forwards_httpproxy_env(tmp_path, monkeypatch):
    # K2: an httpproxy personality must inject the validated HTTP_PROXY/HTTPS_PROXY into the worker env
    # (like the cold dispatcher) -- else the inner sandbox opens for egress but proxy-aware clients go direct.
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    monkeypatch.setenv("BLASTBOX_NETPOLICY_PROXYTEST", "exit=httpproxy,proxy=http://p.example:3128")
    spec = SimpleNamespace(net_policy="proxytest", allowed_param_keys=frozenset(),
                           reserved_param_keys=frozenset(), default_params=None)
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    out = vm._sanitize({})
    assert out["BLASTBOX_NET_EGRESS"] == "1"
    assert out["HTTP_PROXY"] == "http://p.example:3128"
    assert out["HTTPS_PROXY"] == "http://p.example:3128"


def test_remote_factory_requires_limits_and_engine(tmp_path):
    # G1/G2: the trust-gated remote path PRESERVES worker metadata, so it must fail closed without the
    # host trust gate's inputs -- limits (caps/hashes) and an exact engine to match the envelope against.
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    pool = SimpleNamespace(runtime=SimpleNamespace(ssl_context=None),
                           claim=lambda *, timeout_s: None, release=lambda s, dirty=False: None)
    with pytest.raises(ValueError, match="requires limits"):
        build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                   tier="static", engine="clippyshot", limits=None)
    with pytest.raises(ValueError, match="requires engine"):
        build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), pool,
                                   tier="static", engine=None, limits=_FAKE_LIMITS)


class _FakePool:
    runtime = type("R", (), {"ssl_context": None})()

    def claim(self, *, timeout_s):  # noqa: ANN001, ANN202
        return None

    def release(self, slot, *, dirty=False):  # noqa: ANN001
        pass


def test_remote_injects_net_egress_sealed_by_default(tmp_path):
    # a no-egress ('none') engine personality -> the remote worker is told BLASTBOX_NET_EGRESS=0
    from blastbox.host.dispatch import EngineSpec
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    spec = EngineSpec(name="clippyshot", image="img", worker_argv=[], net_policy="none")
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    assert vm._sanitize({})["BLASTBOX_NET_EGRESS"] == "0"


def test_remote_injects_net_egress_open_for_egress_personality(tmp_path, monkeypatch):
    # an egress personality (exit != none/drop) -> BLASTBOX_NET_EGRESS=1 reaches the remote worker
    monkeypatch.setenv("BLASTBOX_NETPOLICY_INSPECT", "exit=direct")
    from blastbox.host.dispatch import EngineSpec
    from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher
    spec = EngineSpec(name="clippyshot", image="img", worker_argv=[], net_policy="inspect")
    vm = build_remote_vm_dispatcher(InMemoryJobStore(), str(tmp_path), _FakePool(),
                                    tier="static", engine="clippyshot", engine_spec=spec, limits=_FAKE_LIMITS)
    assert vm._sanitize({})["BLASTBOX_NET_EGRESS"] == "1"   # dispatcher-owned, merged last
    # a hostile job param cannot flip it back
    assert vm._sanitize({"BLASTBOX_NET_EGRESS": "0"})["BLASTBOX_NET_EGRESS"] == "1"


def test_dispatch_bounds_oversized_summary(tmp_path):
    # a compromised VM agent's huge summary must not be stored verbatim (balloons DB + every response)
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    big = {"blob": "A" * (300 * 1024)}
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (big, True), max_summary_bytes=256 * 1024)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE
    assert got.result_summary["error"] == "summary_too_large"


def test_dispatch_times_out_a_hung_validate(tmp_path):
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: _t.sleep(5),
                        validate_timeout_s=0.3, heartbeat_s=0.1)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "TimeoutError"   # claim thread freed


def test_dispatch_fails_job_when_metadata_unwritable(tmp_path):
    # metadata is a precondition for DONE: if it can't be written, the job FAILs (never DONE with a
    # 404'ing /metadata).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"v": 1}, True))
    d._ensure_metadata = lambda *a, **k: False   # simulate a write failure  # type: ignore[method-assign]
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "metadata_write_failed"


def test_dispatch_does_not_write_metadata_on_failure(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"err": 1}, False))
    d._process(store.claim_next())
    assert not (tmp_path / job.job_id / "output" / "metadata.json").exists()   # only on success


def test_heartbeat_refreshes_started_at_during_validate(tmp_path):
    # a long validate() must not look abandoned to a peer recovery sweep: the heartbeat refreshes
    # started_at while it runs.
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    claimed = store.claim_next()
    t0 = store.get(job.job_id).started_at

    def slow_validate(p):
        deadline = _t.time() + 3.0
        while _t.time() < deadline:           # wait until the heartbeat bumps started_at
            if (store.get(job.job_id).started_at or 0) > t0:
                return ({}, True)
            _t.sleep(0.02)
        return ({}, False)                    # heartbeat never fired → fail the assertion below

    d = VmJobDispatcher(store, str(tmp_path), slow_validate, heartbeat_s=0.05)
    d._process(claimed)
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE       # heartbeat fired (validate returned ok=True)
    assert got.started_at > t0                # started_at was refreshed past claim time


def test_heartbeat_survives_transient_store_error(tmp_path):
    # a transient store error in the heartbeat must NOT kill the heartbeat thread: if started_at
    # stopped refreshing, the orphan sweep would FAIL this still-running job and delete its input.
    # The pump swallows+logs the error and keeps beating; the job still completes.
    import time as _t

    class _FlakyHeartbeatStore(InMemoryJobStore):
        heartbeat_raises = 0

        def update_if_status(self, job_id, expect_status, *, expect_claim_id=None, **fields):
            # The heartbeat is the ONLY caller that refreshes started_at with no status change; the
            # terminal CAS sets status= and the warm-mark sets worker_runtime/worker_tier.
            if "started_at" in fields and "status" not in fields and self.heartbeat_raises > 0:
                self.heartbeat_raises -= 1
                raise RuntimeError("transient store blip")
            return super().update_if_status(job_id, expect_status,
                                            expect_claim_id=expect_claim_id, **fields)

    store = _FlakyHeartbeatStore()
    store.heartbeat_raises = 2          # first two heartbeats blow up, then recover
    job = _queue_job(store, tmp_path)
    claimed = store.claim_next()
    t0 = store.get(job.job_id).started_at

    def slow_validate(p):
        # the heartbeat interval floors at 1s; 2 injected failures push the first SURVIVING beat to
        # ~3s, so give it generous headroom (this asserts recovery, not latency).
        deadline = _t.time() + 8.0
        while _t.time() < deadline:     # wait until a heartbeat survives the blips and bumps started_at
            if (store.get(job.job_id).started_at or 0) > t0:
                return ({}, True)
            _t.sleep(0.02)
        return ({}, False)

    d = VmJobDispatcher(store, str(tmp_path), slow_validate, heartbeat_s=0.05)
    d._process(claimed)
    got = store.get(job.job_id)
    assert got.status is JobStatus.DONE        # heartbeat recovered + job completed despite the blips
    assert got.started_at > t0                 # started_at was still refreshed (sweep won't orphan it)
    assert store.heartbeat_raises == 0         # both injected errors were actually exercised


def test_dispatch_sets_retention_expiry(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), job_retention_s=100)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.finished_at is not None and got.expires_at is not None
    assert got.expires_at == pytest.approx(got.finished_at + 100)   # retention sweeper can reclaim it


def test_dispatch_keeps_input_when_job_was_reclaimed(tmp_path):
    # if validation outran a recovery requeue and another dispatcher reclaimed the job, our terminal
    # CAS fails (stale claim_id) and we must NOT unlink the shared input out from under the new owner.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    stale = store.claim_next()                                       # claim A
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=stale.claim_id,
                           status=JobStatus.QUEUED, claim_id=None, started_at=None)  # requeue
    store.claim_next()                                              # reclaim B (now RUNNING under B)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"v": 1}, True))
    d._process(stale)                                              # process with the STALE claim A
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists()  # preserved for the new owner
    assert store.get(job.job_id).status is JobStatus.RUNNING        # stale owner couldn't terminate it


def test_claim_is_ours_requeues_foreign_engine(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)                  # engine="authenticode"
    ran = []
    d = VmJobDispatcher(store, str(tmp_path), lambda p: (ran.append(p), ({}, True))[1], engine="other")
    assert d._claim_is_ours(store.claim_next()) is False
    got = store.get(job.job_id)
    assert got.status is JobStatus.QUEUED and got.claim_id is None  # requeued for the right dispatcher
    assert ran == []                                               # foreign job never validated


def test_claim_is_ours_accepts_matching_and_unscoped(tmp_path):
    store = InMemoryJobStore()
    _queue_job(store, tmp_path)
    claimed = store.claim_next()
    assert VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))._claim_is_ours(claimed) is True
    assert VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                           engine="authenticode")._claim_is_ours(claimed) is True


def test_claim_next_engine_set_keeps_vm_jobs_off_cold_dispatcher():
    # a cold dispatcher claiming with the SET of engines it handles must leave a VM-only engine's job
    # for the VM dispatcher, not grab it first and fail it "unknown engine".
    store = InMemoryJobStore()
    for eng in ("clippyshot", "authenticode", "redtusk"):
        store.create(Job.new(engine=eng, filename="f"))
    cold_engines = {"clippyshot", "redtusk"}
    seen = set()
    while (j := store.claim_next(engine=cold_engines)) is not None:
        seen.add(j.engine)
    assert seen == cold_engines                                   # never claimed authenticode
    vm = store.claim_next(engine="authenticode")                  # left for the VM dispatcher
    assert vm is not None and vm.engine == "authenticode"


def _claim_as_vm(store, job, *, started_at, worker_runtime="warm", worker_tier="libvirt-vm"):
    claimed = store.claim_next()
    store.update_if_status(job.job_id, JobStatus.RUNNING, expect_claim_id=claimed.claim_id,
                           started_at=started_at, worker_runtime=worker_runtime, worker_tier=worker_tier)


def test_maintenance_recovers_orphaned_running_job(tmp_path):
    # a VM-owned RUNNING job whose heartbeat went stale (claiming dispatcher crashed) is FAILED by
    # maintenance and its input dropped — not left RUNNING forever.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0)             # ancient started_at, marked warm/our-tier
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0)
    d._run_maintenance()
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and got.error == "orphaned"
    assert not (tmp_path / job.job_id / "input" / "evil.dll").exists()


def test_maintenance_leaves_fresh_running_job_alone(tmp_path):
    import time as _t
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=_t.time())        # freshly heartbeated
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=600.0)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.RUNNING   # still alive, untouched


def test_maintenance_sole_owner_recovers_unmarked_claim(tmp_path):
    # a claim that crashed BEFORE the warm stamp (worker_runtime unset) is stuck forever in a VM-only
    # deployment; sole_owner=True lets maintenance reclaim it (no cold dispatcher to mistake it for).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0, worker_runtime=None, worker_tier=None)  # unmarked, stale
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0,
                        sole_owner=True)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.FAILED       # reclaimed
    # without sole_owner an unmarked claim is left alone (could be a cold job)
    store2 = InMemoryJobStore()
    job2 = _queue_job(store2, tmp_path / "b")
    _claim_as_vm(store2, job2, started_at=1.0, worker_runtime=None, worker_tier=None)
    VmJobDispatcher(store2, str(tmp_path / "b"), lambda p: ({}, True),
                    orphan_timeout_s=10.0)._run_maintenance()
    assert store2.get(job2.job_id).status is JobStatus.RUNNING


def test_maintenance_does_not_recover_a_cold_job(tmp_path):
    # a stale-but-not-ours job (a cold/container job, worker_runtime != "warm") must NOT be failed —
    # its Docker worker may still be running; failing + deleting input would be a cross-tier clobber.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    _claim_as_vm(store, job, started_at=1.0, worker_runtime="runc", worker_tier=None)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), orphan_timeout_s=10.0)
    d._run_maintenance()
    assert store.get(job.job_id).status is JobStatus.RUNNING        # left for the cold dispatcher
    assert (tmp_path / job.job_id / "input" / "evil.dll").exists()  # input NOT deleted


def test_maintenance_expires_terminal_job_dir(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.result_dir = str(tmp_path / job.job_id / "output")
    (tmp_path / job.job_id / "output").mkdir(parents=True)
    store.update(job.job_id, status=JobStatus.DONE, result_dir=job.result_dir, expires_at=1.0)  # past
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._run_maintenance()
    assert not (tmp_path / job.job_id).exists()           # retention reclaimed the whole job dir
    assert store.get(job.job_id).status is JobStatus.EXPIRED


def test_libvirt_vm_is_a_routable_tier():
    # operators must be able to target_tier=libvirt-vm so VM-only jobs aren't claimed+failed by the
    # cold dispatcher in a shared store (ingress validates target_tier against VALID_TIERS).
    from blastbox.host.jobs.base import VALID_TIERS
    assert "libvirt-vm" in VALID_TIERS


def test_engine_scoped_claim_skips_older_foreign_head(tmp_path):
    # the store-side fix: an engine-scoped claim must reach OUR job even when an older foreign job is
    # at the queue head (no head-of-line block, no claim+requeue churn).
    store = InMemoryJobStore()
    other = Job.new(engine="other-engine", filename="b.dll")
    store.create(other)                       # older, head of queue
    mine = Job.new(engine="authenticode", filename="a.dll")
    store.create(mine)
    claimed = store.claim_next(engine="authenticode")
    assert claimed is not None and claimed.job_id == mine.job_id   # skipped the foreign head
    assert store.get(other.job_id).status is JobStatus.QUEUED      # foreign job left untouched


def test_dispatch_marks_failed_when_engine_reports_not_ok(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({"envelope_status": "engine_error"}, False))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.FAILED


def test_dispatch_marks_failed_on_raise(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def boom(p):
        raise RuntimeError("worker died")

    d = VmJobDispatcher(store, str(tmp_path), boom)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert got.error == "RuntimeError"


def test_rejects_job_with_unhonored_net_policy(tmp_path):
    # a warm VM has fixed egress; a per-job net_policy it can't honor must FAIL before detonation,
    # never run under the pool's (different) policy while the record claims another. Enforcement is
    # opt-in: the pool here is DECLARED no-network ("none"), so a "tor" override is rejected.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "tor"   # InMemoryJobStore holds the job by reference; claim_next snapshots it
    detonated = {"ran": False}

    def validate(p):
        detonated["ran"] = True
        return ({}, True)

    d = VmJobDispatcher(store, str(tmp_path), validate, fixed_net_policy="none")  # declared no-network
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert "net_policy" in (got.error or "") and "tor" in got.error
    assert detonated["ran"] is False                          # rejected BEFORE validate
    assert not (tmp_path / job.job_id / "input" / job.filename).exists()  # input dropped


def test_net_policy_enforcement_opt_in_skips_when_undeclared(tmp_path):
    # fixed_net_policy unset → enforcement OFF. We must NOT assume the pool is no-network ("none") —
    # a libvirt VM with egress_policy=None is on the (unrestricted) libvirt net, not --network=none —
    # so a job with a policy still runs (operator owns routing when they don't declare the pool egress).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "tor"
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))  # fixed_net_policy=None → opt-out
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE


def test_accepts_job_whose_net_policy_matches_fixed(tmp_path):
    # when the pool IS provisioned for the requested policy, the job runs normally.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "fakenet"
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), fixed_net_policy="fakenet")
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE


def test_rejects_job_when_engine_default_policy_mismatches_fixed(tmp_path):
    # no per-job override (job.net_policy=None), but the ENGINE default is "tor" while the pool is
    # provisioned "fakenet": the cold path would apply tor, so the VM tier must reject rather than
    # detonate under the wrong fixed egress.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)                         # job.net_policy is None
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        fixed_net_policy="fakenet", engine_net_policy="tor")
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert "tor" in (got.error or "") and "engine-default" in got.error


def test_accepts_job_when_engine_default_matches_fixed(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        fixed_net_policy="fakenet", engine_net_policy="fakenet")
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE


def test_per_job_override_takes_precedence_over_engine_default(tmp_path):
    # an explicit override wins over the engine default for the effective-policy comparison.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    job.net_policy = "fakenet"                                # override matches the pool
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        fixed_net_policy="fakenet", engine_net_policy="tor")
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE     # override (fakenet) honored, not the default


def test_engine_net_policy_derived_from_env_when_not_passed(tmp_path, monkeypatch):
    # if the dispatcher isn't given engine_net_policy, derive it from the same env var the cold path
    # reads, so a routed engine default isn't silently skipped just because a caller didn't thread it.
    monkeypatch.setenv("BLASTBOX_ENGINE_AUTHENTICODE_NETPOLICY", "tor")
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)                         # no per-job override
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        engine="authenticode", fixed_net_policy="fakenet")  # engine_net_policy NOT passed
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and "tor" in (got.error or "")


def test_none_policy_job_rejected_on_networked_pool(tmp_path, monkeypatch):
    # "none"/"drop" mean --network=none (NO egress, the fail-closed default). A job whose effective
    # policy is "none" must NOT run on a pool that HAS network (fakenet/tor/direct) — that's a LEAK,
    # not benign over-containment. Reject the mismatch.
    monkeypatch.setenv("BLASTBOX_ENGINE_AUTHENTICODE_NETPOLICY", "none")
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True),
                        engine="authenticode", fixed_net_policy="fakenet")
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED and "none" in (got.error or "")


def test_no_policy_anywhere_runs_on_unconfigured_pool(tmp_path):
    # the common case: no per-job override, no engine default (env unset), pool egress undeclared.
    # effective="none" == fixed="none" → run normally (the equality model doesn't break the default).
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True), engine="authenticode")
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.DONE


def test_does_not_write_metadata_when_claim_lost_during_validate(tmp_path):
    # if a long validate outlives its claim and a peer reclaims the job, the stale owner must NOT
    # write output/metadata.json (a filesystem op the terminal CAS can't fence) — that would clobber
    # the new owner's metadata for the now-DONE job.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    claimed = store.claim_next()

    def validate(p):
        # simulate a peer reclaiming the job mid-validate: rotate the stored claim_id out from under us
        store._jobs[job.job_id].claim_id = "peer-now-owns-it"
        return ({"ok": 1}, True)

    d = VmJobDispatcher(store, str(tmp_path), validate)
    d._process(claimed)
    # we bailed before publishing: no metadata.json written, and we did NOT CAS the job to DONE
    assert not (tmp_path / job.job_id / "output" / "metadata.json").exists()
    got = store.get(job.job_id)
    assert got.status is JobStatus.RUNNING and got.claim_id == "peer-now-owns-it"  # peer still owns it
    # and the shared input is left for the new owner (we didn't unlink it)
    assert (tmp_path / job.job_id / "input" / job.filename).exists()


def test_dispatch_marks_failed_when_validate_raises_baseexception(tmp_path):
    # a validate() that raises a non-Exception BaseException (e.g. a sample-triggered sys.exit) must
    # still FAIL the job, not slip past _process's `except Exception` and leave it RUNNING forever.
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)

    def sys_exit(p):
        raise SystemExit(2)

    d = VmJobDispatcher(store, str(tmp_path), sys_exit)
    d._process(store.claim_next())
    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED              # normalized to a failure, not a stuck RUNNING
    assert got.error == "RuntimeError"                 # wrapped (SystemExit → RuntimeError)


def test_dispatch_missing_input_is_failed(tmp_path):
    store = InMemoryJobStore()
    job = _queue_job(store, tmp_path)
    (tmp_path / job.job_id / "input" / "evil.dll").unlink()   # spooled input vanished
    d = VmJobDispatcher(store, str(tmp_path), lambda p: ({}, True))
    d._process(store.claim_next())
    assert store.get(job.job_id).status is JobStatus.FAILED
