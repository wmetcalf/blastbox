"""Issue #88: prove the dispatcher and the ingress point at the SAME blob target.

`blob_roundtrip` proves a process can write and read ITS OWN store; `check_store_coherence`
catches a private local store behind a shared queue. Neither can see dispatch on
`s3://results/stack-b` and serve on `s3://results/stack-a`: both pass, and every finished job
404s. That is the original 17,626-job incident with a different cause, and it stayed hidden for
days because nothing compared the two sides.
"""
from __future__ import annotations

import tempfile
import threading

import pytest

from blastbox.host.canary import CanaryFailure, check_blob_target_agreement
from blastbox.host.jobs.base import BlobTargetRegistry
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


class _Store:
    """A NON-LOCAL (S3-shaped) blob store whose fingerprint is whatever we say it is."""

    def __init__(self, bucket: str) -> None:
        self._bucket = bucket
        self._prefix = ""
        self._s3 = None


class LocalBlobStore:                      # noqa: D101 - name IS the contract (is_local_blob_store)
    def __init__(self, root: str) -> None:
        self.local_root = root


def _sql() -> SqlJobStore:
    return SqlJobStore(f"sqlite:///{tempfile.mkdtemp()}/j.db")


ALL_BACKENDS = [pytest.param(InMemoryJobStore, id="memory"), pytest.param(_sql, id="sql")]


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_every_shipped_backend_implements_the_registry(backend):
    """Acceptance: InMemoryJobStore, SqlJobStore and RedisJobStore all implement the seam."""
    assert isinstance(backend(), BlobTargetRegistry)


def test_redis_backend_implements_the_registry():
    """Checked structurally: a live Redis is not available here, and the point is the CONTRACT."""
    from blastbox.host.jobs.redis_store import RedisJobStore

    for name in ("claim_blob_target", "get_blob_target", "clear_blob_target"):
        assert callable(getattr(RedisJobStore, name, None)), f"RedisJobStore is missing {name}"


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_mismatched_targets_cannot_both_start(backend):
    """Acceptance: two processes with mismatched targets cannot both start, and the message names
    both targets and which side holds which."""
    q = backend()
    agreed = check_blob_target_agreement(q, _Store("results/stack-a"), role="dispatcher")
    assert agreed and "stack-a" in agreed

    with pytest.raises(CanaryFailure) as ei:
        check_blob_target_agreement(q, _Store("results/stack-b"), role="ingress")
    msg = str(ei.value)
    assert "stack-a" in msg and "stack-b" in msg, f"both targets must be named: {msg}"
    assert "ingress" in msg, f"the message must say which process holds which: {msg}"
    assert "blastbox blob-target reset" in msg, "the message must name the migration escape hatch"


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_matching_deployments_are_unaffected(backend):
    """Acceptance: single-node and matching multi-node deployments are unaffected.

    This must fail CLOSED on a mismatch, not fail ALWAYS -- the two earlier attempts on this PR to
    infer topology both refused documented, working deployments.
    """
    q = backend()
    for role in ("dispatcher", "ingress", "dispatcher"):
        assert check_blob_target_agreement(q, _Store("results/shared"), role=role) is not None


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_a_boot_storm_has_exactly_one_winner(backend):
    """The registration is a COMPARE-AND-SWAP, not a read followed by a write.

    Get-then-put would let every process starting at once read an empty registry, write its own
    answer, and see no mismatch -- defeating the check on precisely the simultaneous-boot case a
    fleet actually does. Verified by racing eight claimants through one barrier.
    """
    q = backend()
    seen: list[str] = []
    bar = threading.Barrier(8)

    def _claim(i: int) -> None:
        bar.wait()
        seen.append(q.claim_blob_target(f"s3://results/stack-{i}"))

    threads = [threading.Thread(target=_claim, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(seen) == 8
    assert len(set(seen)) == 1, (
        f"eight simultaneous claimants recorded {len(set(seen))} different targets ({set(seen)}); "
        f"a get-then-put registry lets every process register its own and report agreement")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_show_must_not_register_anything(backend):
    """A diagnostic that writes is not a diagnostic.

    `blastbox blob-target show` reaching for `claim_blob_target` would register its own argument on
    an empty queue, after which every real process mismatches it -- bricking the fleet with the
    command meant to inspect it. Hence the separate read-only accessor.
    """
    q = backend()
    assert q.get_blob_target() is None
    assert q.get_blob_target() is None, "reading the registry registered something"
    assert check_blob_target_agreement(q, _Store("results/real"), role="dispatcher")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_reset_lets_a_deliberate_migration_through(backend):
    """Acceptance: a deployment deliberately migrating targets clears the key."""
    q = backend()
    check_blob_target_agreement(q, _Store("results/old"), role="dispatcher")
    with pytest.raises(CanaryFailure):
        check_blob_target_agreement(q, _Store("results/new"), role="dispatcher")
    q.clear_blob_target()
    assert check_blob_target_agreement(q, _Store("results/new"), role="dispatcher")


def test_a_store_without_the_seam_warns_rather_than_refusing(caplog):
    """Absence of the capability is not evidence of disagreement.

    A third-party JobStore satisfying the base protocol must not be refused for lacking an OPTIONAL
    capability -- that is exactly why this is a separate Protocol rather than a widening of
    JobStore. It warns that agreement is unverified, and starts.
    """
    import logging

    class _NoSeam:
        pass

    with caplog.at_level(logging.WARNING, logger="blastbox.host.canary"):
        assert check_blob_target_agreement(_NoSeam(), _Store("results/x"), role="ingress") is None
    assert any("blob_target_unverified" in r.getMessage() for r in caplog.records), (
        "a store without the seam must say so rather than silently skipping the check")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_local_stores_are_not_compared_by_path(backend):
    """A LocalBlobStore fingerprint is a host-local PATH; comparing paths proves nothing.

    The documented multi-node NFS deployment mounts one export at different mount points per host,
    so path comparison would refuse it — the third time this PR would have refused a working
    deployment by over-reading the local case. CI proved it empirically: every ingress test sharing
    one Postgres with its own tmp_path store was refused after the first.

    The real local hazard (a PRIVATE local store behind a shared queue) is check_store_coherence's
    job and is unaffected. This check covers what coherence structurally cannot see: two non-local
    stores that both look fine and point at different buckets.

    MUTATION: drop the is_local_blob_store guard -> two different local paths refuse each other.
    """
    q = backend()
    assert check_blob_target_agreement(q, LocalBlobStore("/mnt/a/blobs"), role="dispatcher") is None
    assert check_blob_target_agreement(q, LocalBlobStore("/mnt/b/blobs"), role="ingress") is None
    assert q.get_blob_target() is None, "a local store must not register a target at all"
