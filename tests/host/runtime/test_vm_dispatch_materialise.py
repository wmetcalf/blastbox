"""A worker that cannot fetch a sample must RELEASE the claim, not fail the job.

An unreachable object store is a property of THIS worker's connectivity, not of the
sample. Failing would permanently discard work because one node's link blipped.
"""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class UnreachableBlobStore:
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        raise BlobFetchError("object store unreachable")
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FetchingBlobStore:
    def __init__(self, data=b"materialised"): self.data = data; self.calls = 0
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        self.calls += 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.data)
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FlakyBlobStore:
    """Fails ``fail_times`` calls with BlobFetchError, then materialises normally --
    a fetch that was transiently broken and later recovers (unlike UnreachableBlobStore,
    which never succeeds)."""
    def __init__(self, fail_times, data=b"materialised"):
        self.fail_times = fail_times
        self.data = data
        self.calls = 0

    def put_sample(self, sha256, src): ...

    def get_sample(self, sha256, dest):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise BlobFetchError("object store unreachable (still recovering)")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.data)

    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_fetch_failure_returns_the_job_to_queued(vm_dispatcher_factory):
    """vm_dispatcher_factory: see tests/host/runtime/conftest.py."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "d" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp._process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED, "must be reclaimable"


def test_missing_input_is_fetched_then_processed(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "e" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp._process(claimed)

    assert blobs.calls == 1
    assert store.get(job.job_id).status is JobStatus.DONE


def test_present_input_is_not_refetched(vm_dispatcher_factory, tmp_path):
    """Local mode must not pay a fetch for a file that is already there."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "f" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    p = disp._input_path(claimed)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"already here")

    disp._process(claimed)
    assert blobs.calls == 0


def test_release_clears_claim_id_and_backs_the_job_off(vm_dispatcher_factory):
    """Guards the flapping-worker livelock: without claimable_after, the worker that
    just failed to fetch immediately re-claims the same job and spins on it."""
    import time

    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "g" * 64
    store.create(job)
    claimed = store.claim_next()
    assert claimed.claim_id is not None

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp._process(claimed)

    released = store.get(job.job_id)
    assert released.status is JobStatus.QUEUED
    assert released.claim_id is None, "a released job must not keep its claim token"
    assert released.claimable_after > time.time(), "must back off, not be instantly re-claimable"
    assert released.created_at == job.created_at, "submission time must not be rewritten"


# --- bounded materialise retries (Task 4/5 fix: give up instead of looping forever) -------

def test_permanently_missing_sample_eventually_fails_the_job(vm_dispatcher_factory):
    """A sample that can NEVER be materialised (deleted/never-written blob) must not loop
    release -> reclaim -> release forever. Drive the real increment path by re-claiming and
    re-processing in a loop (not by hand-setting the counter): each attempt short of the max
    is released back to QUEUED, and the attempt that reaches MAX_MATERIALISE_ATTEMPTS is
    marked terminally FAILED with a clear error."""
    from blastbox.host.runtime.vm_dispatch import MAX_MATERIALISE_ATTEMPTS

    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "h" * 64
    store.create(job)

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())

    for attempt in range(1, MAX_MATERIALISE_ATTEMPTS + 1):
        claimed = store.claim_next()
        assert claimed is not None, f"job must still be claimable before attempt {attempt}"
        disp._process(claimed)
        current = store.get(job.job_id)
        assert current.materialise_attempts == attempt

        if attempt < MAX_MATERIALISE_ATTEMPTS:
            assert current.status is JobStatus.QUEUED, f"attempt {attempt} should release, not fail"
            assert current.error is None
            # Bypass the backoff window (claimable_after) so the loop can re-claim the job on
            # the next iteration without waiting out blob_retry_backoff_s -- the backoff itself
            # is already covered by test_release_clears_claim_id_and_backs_the_job_off above.
            store.update(job.job_id, claimable_after=None)
        else:
            assert current.status is JobStatus.FAILED, "must give up once the bound is reached"
            assert current.error, "a terminal give-up must carry a non-empty, explanatory error"
            assert str(MAX_MATERIALISE_ATTEMPTS) in current.error or "attempts" in current.error


def test_successful_materialisation_after_a_prior_failure_does_not_misfire(vm_dispatcher_factory):
    """A successful fetch must not leave the retry counter in a state that prematurely fails a
    later, unrelated attempt. Here the sample fails to materialise once (counter -> 1, released)
    and then materialises successfully on the very next attempt, well under
    MAX_MATERIALISE_ATTEMPTS -- the job must complete normally (DONE), not be failed, and the
    counter must RESET to 0 (Finding E3: the bound is on CONSECUTIVE failures, not lifetime --
    a successful fetch must not leave a stale failure count around to prematurely fail some
    later, unrelated attempt)."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "j" * 64
    store.create(job)

    blobs = FlakyBlobStore(fail_times=1)
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)

    # Attempt 1: fetch fails -> released, counter bumped to 1.
    claimed = store.claim_next()
    disp._process(claimed)
    released = store.get(job.job_id)
    assert released.status is JobStatus.QUEUED
    assert released.materialise_attempts == 1
    store.update(job.job_id, claimable_after=None)  # bypass backoff for the retry

    # Attempt 2: fetch now succeeds -> job runs through to DONE, counter reset to 0.
    reclaimed = store.claim_next()
    disp._process(reclaimed)
    done = store.get(job.job_id)
    assert done.status is JobStatus.DONE
    assert done.materialise_attempts == 0, "a successful fetch must reset the counter (Finding E3)"


def test_counter_is_consecutive_not_lifetime_across_a_reset(tmp_path):
    """Finding E3: materialise_attempts bounds CONSECUTIVE fetch failures, not a lifetime total.

    The SAME job fails to materialise twice (counter -> 2, released each time), then
    materialises successfully (counter resets to 0) -- but a NoWarmSlot requeue right after
    (capacity pressure, not a job failure) purges the job dir without a terminal write, exactly
    the scenario the finding describes: "the job dir is purged on every attempt including
    NoWarmSlot/WorkerBusy requeues". The NEXT reclaim must re-fetch (the local copy is gone) and
    fails again -- that failure must land at attempt 1 (the post-reset baseline), not attempt 3
    (which would be the case if a successful fetch never reset the counter)."""
    from blastbox.host.runtime.vm_dispatch import NoWarmSlot, VmJobDispatcher

    class ScriptedBlobStore:
        """Fails on specific 1-indexed call numbers; materialises otherwise."""
        def __init__(self, fail_on, data=b"materialised"):
            self.fail_on = set(fail_on)
            self.data = data
            self.calls = 0
        def put_sample(self, sha256, src): ...
        def get_sample(self, sha256, dest):
            self.calls += 1
            if self.calls in self.fail_on:
                raise BlobFetchError("scripted failure")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.data)
        def put_output(self, job_id, out_dir): ...
        def open_output(self, job_id, name): ...
        def delete_job(self, job_id): ...

    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "m" * 64
    store.create(job)

    # Calls 1 & 2 (the fetch) fail, call 3 succeeds, call 4 (after the requeue purges the
    # re-fetched copy) fails again.
    blobs = ScriptedBlobStore(fail_on={1, 2, 4})
    validate_calls = {"n": 0}

    def _validate(in_path):
        validate_calls["n"] += 1
        if validate_calls["n"] == 1:
            # Capacity pressure, not a job failure: requeues WITHOUT a terminal write, and
            # _process's `finally` purges the job dir unconditionally either way -- so the
            # sample this attempt just fetched is gone again on the next reclaim.
            raise NoWarmSlot("no warm slot free")
        out = in_path.parent.parent / "output"
        out.mkdir(parents=True, exist_ok=True)
        (out / "metadata.json").write_bytes(b'{"status":"ok"}')
        return ({"detected": "test"}, True)

    disp = VmJobDispatcher(
        store=store, job_root=tmp_path, validate=_validate, blob_store=blobs,
        put_output_retry_backoff_s=0.0,
    )

    # Attempts 1 & 2: fetch fails -> released, counter climbs to 1 then 2.
    for expected_attempt in (1, 2):
        claimed = store.claim_next()
        disp._process(claimed)
        current = store.get(job.job_id)
        assert current.status is JobStatus.QUEUED, f"attempt {expected_attempt} should release"
        assert current.materialise_attempts == expected_attempt
        store.update(job.job_id, claimable_after=None)

    # Attempt 3: fetch succeeds (counter resets to 0), then NoWarmSlot requeues it (not a
    # terminal write) -- the purge still runs, so the freshly-fetched sample is gone again.
    claimed = store.claim_next()
    disp._process(claimed)
    requeued = store.get(job.job_id)
    assert requeued.status is JobStatus.QUEUED, "NoWarmSlot must requeue, not fail, the job"
    assert requeued.materialise_attempts == 0, "the successful fetch must have reset the counter"

    # Attempt 4: fetch fails again -- this must land at attempt 1 (the post-reset baseline),
    # NOT attempt 3 (2 old failures + this one), which is exactly the lifetime-vs-consecutive
    # bug Finding E3 fixes.
    reclaimed = store.claim_next()
    disp._process(reclaimed)
    final = store.get(job.job_id)
    assert final.status is JobStatus.QUEUED
    assert final.materialise_attempts == 1, (
        "a fetch failure after a reset must count as attempt 1 (consecutive), not accumulate "
        "the two earlier, already-resolved failures toward the cap (lifetime)"
    )


def test_successful_first_fetch_leaves_the_counter_at_zero(vm_dispatcher_factory):
    """A job whose sample materialises on the first try must never touch the retry counter."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "k" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp._process(claimed)

    done = store.get(job.job_id)
    assert done.status is JobStatus.DONE
    assert done.materialise_attempts == 0
