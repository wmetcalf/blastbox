"""Round-five regressions in the credential-less node's store (#178).

Three separate reviewers arrived at the same place from different directions: the
``_settled`` set that exists to keep a LIVE job's receipt out of the eviction scan was
being set for jobs that are not settled at all, so the protection it names in its own
comment was inverted -- the live receipt became the PREFERRED victim.
"""
from __future__ import annotations

import time


from blastbox.host.jobs import http_store as hs
from blastbox.host.jobs.base import Job, JobStatus
from tests.host.jobs.test_http_store import (  # noqa: F401 -- fixtures
    backing, control_plane, fleet, node_store, queued,
)


def test_an_intermediate_update_does_not_mark_a_running_job_settled(
        control_plane, fleet, backing):  # noqa: F811
    """`_retire_if_settled(job_id, job)` was reached with a non-None job on EVERY successful
    update, and its guard read `if job is not None or ...` -- so a heartbeat write on a RUNNING
    job flagged it settled. Eviction then picks it first, discards the receipt of a job that is
    still running, and its terminal write is refused as "no claim receipt"."""
    queued(backing)
    s = node_store(control_plane, fleet, "alpha")
    job = s.claim_next(engine="clamav")
    assert job is not None
    s.update(job.job_id, worker_runtime="runc")
    assert job.job_id not in s._settled, (
        "a RUNNING job with an intermediate update was flagged settled, making its receipt "
        "the first thing eviction throws away")


def test_a_live_receipt_survives_eviction_pressure_after_a_heartbeat(
        control_plane, fleet, backing):  # noqa: F811
    """The consequence, end to end: the live job's terminal write still lands."""
    queued(backing, "long-runner")
    s = node_store(control_plane, fleet, "alpha")
    live = s.claim_next(engine="clamav")
    assert live is not None
    s.update(live.job_id, worker_runtime="runc")        # an ordinary progress write
    for i in range(hs._MAX_TRACKED_CLAIMS + 8):         # a warm pool churning short jobs
        queued(backing, f"short-{i}")
        short = s.claim_next(engine="clamav")
        assert short is not None
        s.update(short.job_id, status=JobStatus.DONE)
    s.update(live.job_id, status=JobStatus.DONE)        # must not raise PermissionError
    assert backing.get("long-runner").status is JobStatus.DONE


def test_reclaiming_a_job_clears_the_settled_flag_from_its_last_life(
        control_plane, fleet, backing):  # noqa: F811
    """A released-then-reclaimed job carried its old `_settled` membership into the new claim,
    so the fresh, live receipt was again the first eviction victim."""
    queued(backing, "recycled")
    s = node_store(control_plane, fleet, "alpha")
    first = s.claim_next(engine="clamav")
    assert first is not None
    s.update("recycled", status=JobStatus.QUEUED, claim_id=None, started_at=None)
    assert "recycled" in s._settled                     # released: settled as far as we know
    backing.update("recycled", claimable_after=None)    # the release deferral expires
    again = s.claim_next(engine="clamav")
    assert again is not None and again.job_id == "recycled"
    assert "recycled" not in s._settled, (
        "the re-claimed job kept the settled flag from its previous life")


def test_the_backlog_count_is_always_of_work_this_node_could_actually_claim(
        control_plane, fleet, backing):  # noqa: F811
    """`claim_next` over this path sends NO tier, so the control plane never hands over a
    target_tier-pinned job -- but `count` only narrowed to unpinned work when the caller
    happened to ask. `DispatcherSizer` has two backlog callables and only one passes the flag,
    so the pool's demand signal counted work it can never be given."""
    backing.create(Job(job_id="pinned", engine="clamav", filename="s.bin",
                       status=JobStatus.QUEUED, created_at=time.time(),
                       target_tier="firecracker"))
    s = node_store(control_plane, fleet, "alpha")
    assert s.count(JobStatus.QUEUED, engine=["clamav"]) == 0, (
        "the backlog counted a pinned job this node can never be handed")
    assert s.claim_next(engine="clamav") is None         # the claim path agrees
