"""Security invariant: a worker leaves no sample bytes behind — on ANY path.

Workers are frequently spare hardware (a laptop, an old desktop), not hardened
sample repositories. The failure paths matter most: they are where a purge is
easiest to omit, and ~1.6% of a real corpus hits the timeout path.
"""

import logging
import shutil
import time

import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

SECRET = b"MALWARE-BYTES-MUST-NOT-PERSIST"


class Blobs:
    def __init__(self, fail_fetch=False):
        self.fail_fetch = fail_fetch

    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        if self.fail_fetch:
            raise BlobFetchError("down")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(SECRET)

    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def _residue(root):
    return [p for p in root.rglob("*") if p.is_file() and SECRET in p.read_bytes()]


@pytest.mark.parametrize(
    "validate_ok", [True, False], ids=["success", "engine-failure"]
)
def test_no_sample_residue_after_terminal_state(
    vm_dispatcher_factory, tmp_path, validate_ok
):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "a" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(
        store=store, blob_store=Blobs(), validate_ok=validate_ok
    )
    disp._process(claimed)

    assert _residue(tmp_path) == [], "sample bytes survived a terminal state"
    # The stub validate() writes no SECRET into output/, so the residue check alone can't catch a
    # dir-level leak (e.g. output/metadata.json, or an empty-but-present input/ dir) — assert the
    # whole per-job directory is gone, which is the actual invariant ("nothing survives").
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must not survive a terminal state"
    )


def test_no_sample_residue_after_validator_raises(vm_dispatcher_factory, tmp_path):
    """The timeout/crash path — the one most likely to skip cleanup."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    def _boom(in_path):
        raise TimeoutError("engine timed out after 120.0s")

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=True)
    disp._validate = _boom
    disp._process(claimed)

    assert _residue(tmp_path) == []
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must not survive a crashed validate()"
    )


def test_no_residue_after_release_back_to_queued(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "c" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(fail_fetch=True))
    disp._process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED
    assert _residue(tmp_path) == []


def test_purge_after_peer_reclaims_right_before_terminal_cas(
    vm_dispatcher_factory, tmp_path
):
    """The terminal-CAS-loss seam: a peer reclaims in the window AFTER the pre-upload ownership
    recheck but BEFORE the DONE CAS, so the CAS loses (owned=False). The job dir (input AND output)
    must still be purged -- the sample is re-materialisable and no peer on another host could ever
    read bytes left on THIS worker's disk. Before the fix the `if owned:` gate left them behind."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "d" * 64
    store.create(job)
    claimed = store.claim_next()

    class ReclaimingBlobs(Blobs):
        # put_output runs after the last ownership recheck and before the terminal DONE CAS -- flip
        # the claim out from under this worker there, exactly as a peer's claim_next() would.
        def put_output(self, job_id, out_dir):
            store.update(job_id, claim_id="peer-claim-not-ours")

    disp = vm_dispatcher_factory(
        store=store, blob_store=ReclaimingBlobs(), validate_ok=True
    )
    disp._process(claimed)

    # Our terminal CAS lost (claim_id no longer ours): the job is left under the peer's claim, NOT
    # marked DONE by this stale attempt.
    assert store.get(job.job_id).claim_id == "peer-claim-not-ours"
    assert store.get(job.job_id).status is JobStatus.RUNNING
    # ...but the security invariant holds regardless: nothing survives on THIS worker's disk.
    assert _residue(tmp_path) == [], "sample bytes survived a lost terminal CAS"
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must be purged even when the terminal CAS lost"
    )


def test_purge_after_reclaim_during_a_raising_validate(vm_dispatcher_factory, tmp_path):
    """The generic-except terminal-CAS-loss seam (the wider window): validate raises AND a peer
    reclaimed mid-validate, so the FAILED CAS loses (owned=False). The job dir must still be purged."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "e" * 64
    store.create(job)
    claimed = store.claim_next()

    def _boom_and_reclaim(in_path):
        store.update(
            job.job_id, claim_id="peer-claim-not-ours"
        )  # peer reclaims mid-validate
        raise RuntimeError("engine blew up")

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=True)
    disp._validate = _boom_and_reclaim
    disp._process(claimed)

    assert (
        store.get(job.job_id).claim_id == "peer-claim-not-ours"
    )  # our FAILED CAS lost
    assert _residue(tmp_path) == [], "sample bytes survived a lost FAILED CAS"
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must be purged even when the FAILED CAS lost"
    )


def test_purge_refuses_path_outside_job_root(tmp_path, caplog):
    """The containment refusal: _purge_job_dir must never rmtree anything that doesn't
    resolve strictly under job_root -- it must refuse and log an error instead."""
    job_root = tmp_path / "job_root"
    job_root.mkdir()
    outside = tmp_path / "outside-target"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(SECRET)

    disp = VmJobDispatcher(
        store=InMemoryJobStore(), job_root=str(job_root), validate=lambda p: ({}, True)
    )
    job = Job.new(engine="redtusk", filename="a.doc")
    job.job_id = "../outside-target"  # job_root / job_id resolves OUTSIDE job_root

    with caplog.at_level(logging.ERROR, logger="blastbox.host.runtime.vm_dispatch"):
        disp._purge_job_dir(job)

    assert outside.exists() and (outside / "secret.bin").exists(), (
        "refused purge must leave the dir intact"
    )
    assert any("refus" in r.message.lower() for r in caplog.records), (
        "containment refusal must be logged"
    )


def test_purge_logs_error_and_does_not_raise_on_rmtree_failure(
    tmp_path, monkeypatch, caplog
):
    """The OSError branch: an rmtree failure must be logged loudly at ERROR and must NOT
    raise -- it must never mask the job's real (already-written) terminal outcome."""
    job_root = tmp_path / "job_root"
    job = Job.new(engine="redtusk", filename="a.doc")
    job_dir = job_root / job.job_id
    (job_dir / "input").mkdir(parents=True)
    (job_dir / "input" / "a.doc").write_bytes(SECRET)

    disp = VmJobDispatcher(
        store=InMemoryJobStore(), job_root=str(job_root), validate=lambda p: ({}, True)
    )

    def _boom(path):
        raise OSError("device or resource busy")

    monkeypatch.setattr(shutil, "rmtree", _boom)

    with caplog.at_level(logging.ERROR, logger="blastbox.host.runtime.vm_dispatch"):
        disp._purge_job_dir(job)  # must not raise

    assert any("PURGE FAILED" in r.message for r in caplog.records), (
        "rmtree failure must be logged at ERROR"
    )


def test_no_residue_after_net_policy_rejection(tmp_path):
    """The net_policy-rejection path is a terminal (FAILED) write and must go through the
    same unconditional purge invariant as every other terminal path -- not a bare input
    unlink that leaves the (now-empty) job dir behind."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.net_policy = "tor"
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / "a.doc").write_bytes(SECRET)
    job.result_dir = str(root)
    store.create(job)
    claimed = store.claim_next()

    def _validate(in_path):
        raise AssertionError(
            "validate() must not run -- job is rejected before detonation"
        )

    disp = VmJobDispatcher(
        store=store, job_root=str(tmp_path), validate=_validate, fixed_net_policy="none"
    )  # pool declared no-network; job wants "tor"
    disp._process(claimed)

    got = store.get(job.job_id)
    assert got.status is JobStatus.FAILED
    assert _residue(tmp_path) == [], (
        "sample bytes survived a net_policy-rejected terminal state"
    )
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must not survive a net_policy-rejected job"
    )


def test_no_residue_after_net_policy_rejection_when_failed_cas_loses(tmp_path):
    """The terminal-CAS-loss seam for the net_policy-rejection path: a peer reclaims the job in
    the window between this worker's claim_next() and the FAILED CAS here, so the CAS loses
    (before the fix, the purge was gated INSIDE that `if`, so a lost CAS skipped it entirely --
    leaving the spooled malware sample on this worker's disk). The purge must run regardless.
    Mirrors test_purge_after_peer_reclaims_right_before_terminal_cas for the DONE/FAILED path."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.net_policy = "tor"
    root = tmp_path / job.job_id
    (root / "input").mkdir(parents=True)
    (root / "input" / "a.doc").write_bytes(SECRET)
    job.result_dir = str(root)
    store.create(job)
    claimed = store.claim_next()

    # Simulate a peer reclaiming the job right after our claim_next(): flip the LIVE claim_id
    # directly (bypassing the CAS) so the net_policy rejection's expect_claim_id=claimed.claim_id
    # no longer matches -- its FAILED CAS below returns False even though this worker is still
    # the one running `_process(claimed)`.
    store.update(job.job_id, claim_id="peer-claim-not-ours")

    def _validate(in_path):
        raise AssertionError(
            "validate() must not run -- job is rejected before detonation"
        )

    disp = VmJobDispatcher(
        store=store, job_root=str(tmp_path), validate=_validate, fixed_net_policy="none"
    )  # pool declared no-network; job wants "tor"
    disp._process(claimed)

    got = store.get(job.job_id)
    # Our FAILED CAS lost: the job is left under the peer's claim, still RUNNING -- NOT the
    # FAILED status this (stale) attempt tried to write.
    assert got.claim_id == "peer-claim-not-ours"
    assert got.status is JobStatus.RUNNING
    assert _residue(tmp_path) == [], (
        "sample bytes survived a net_policy-rejected job whose FAILED CAS lost"
    )
    assert not (tmp_path / job.job_id).exists(), (
        "job dir must be purged even when the net_policy FAILED CAS lost"
    )


def test_vm_dispatcher_reclaims_stale_scratch_too(tmp_path, monkeypatch):
    """BLASTBOX_SCRATCH_MAX_AGE_S is documented as a global bound on job_root, so the network-tier
    dispatcher must honour it — and it is the one that MOST needs it.

    _process's finally-purge covers every terminal path this dispatcher can reach, but a
    SIGKILL / OOM-kill / redeploy mid-detonation reaches none of them and strands the sample and
    its output forever. On a remote-only (static/AWS) node there is no container Dispatcher to
    sweep up behind it, and JobRetentionSweeper is gated on job_retention_seconds > 0 — the same
    docs tell operators to leave that at 0. That is #84's accumulation class, unbounded, on the
    tier the reclaim originally skipped.
    """
    import os as _os

    monkeypatch.setenv("BLASTBOX_SCRATCH_MAX_AGE_S", "60")
    job_root = tmp_path / "job_root"
    job_root.mkdir()
    disp = VmJobDispatcher(
        store=InMemoryJobStore(), job_root=str(job_root), validate=lambda p: ({}, True)
    )

    stranded = job_root / "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    (stranded / "output").mkdir(parents=True)
    (stranded / "input.bin").write_bytes(SECRET)
    old = time.time() - 99_999
    for pth in (stranded / "input.bin", stranded / "output", stranded):
        _os.utime(pth, (old, old))

    disp._run_maintenance()

    assert not stranded.exists(), (
        "a SIGKILL-stranded tree is unbounded on the network tier"
    )
