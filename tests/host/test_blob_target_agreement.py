"""Issue #88: prove the dispatcher and the ingress point at the SAME blob target.

`blob_roundtrip` proves a process can write and read ITS OWN store; `check_store_coherence`
catches a private local store behind a shared queue. Neither can see dispatch on
`s3://results/stack-b` and serve on `s3://results/stack-a`: both pass, and every finished job
404s. That is the original 17,626-job incident with a different cause, and it stayed hidden for
days because nothing compared the two sides.
"""
from __future__ import annotations

import tempfile

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


# The REAL LocalBlobStore, not a look-alike: `is_local_blob_store` is inheritance-aware now, so a
# stand-in that merely shares the name would be classified non-local and these tests would assert
# the opposite of production behaviour.
from blastbox.host.blobs.local import LocalBlobStore  # noqa: E402


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


def test_separate_store_instances_on_one_database_still_see_one_winner(tmp_path):
    """SEPARATE store objects on ONE database -- the multi-PROCESS shape, which is the only shape
    that matters here.

    The first version of this test raced eight threads through one store object. That cannot fail:
    both backends guard `claim_blob_target` with a per-instance lock, so the threads serialise on
    the lock and never reach the database concurrently. A reviewer replaced the CAS with plain
    get-then-put and ran that test 30 times per backend -- it detected the mutant 0/30. It was
    asserting the lock works, not that the registration is a compare-and-swap.

    Two store instances sharing one SQLite file have no lock in common, exactly as two processes
    have none, so the atomicity has to come from the database. Which is the actual claim.

    MUTATION: replace the INSERT/SELECT with `if get_blob_target() is None: insert` -> the second
    instance registers its own value and both report winning.
    """
    db = f"sqlite:///{tmp_path}/shared.db"
    first, second = SqlJobStore(db), SqlJobStore(db)

    won = first.claim_blob_target("s3://results/stack-a")
    lost = second.claim_blob_target("s3://results/stack-b")

    assert won == "s3://results/stack-a"
    assert lost == "s3://results/stack-a", (
        f"a second store instance on the SAME database registered its own target ({lost}); with "
        f"two real processes both would boot and report agreement on different buckets")
    assert first.get_blob_target() == second.get_blob_target() == "s3://results/stack-a"


def test_an_unreadable_registry_is_unknown_not_agreement(caplog):
    """A read-back that comes up empty must NOT be reported as winning.

    Both backends returned the caller's own fingerprint there -- indistinguishable from actually
    winning. It is reachable: `clear_blob_target()` is the documented migration remedy, and an
    operator runs it precisely while a mismatched process is crash-looping, so the DELETE lands
    between that process's losing write and its read; on Redis an `allkeys-*` eviction reaches the
    same window with nobody involved. The losing side then logged agreement and booted on the wrong
    target -- the silent split this seam exists to prevent, produced by the seam.

    Asserted at the CANARY, because that is where the consequence lives: a registry answering
    UNKNOWN must produce "unverified", never "agrees". Testing it per-backend does not work --
    after a genuine reset a claim legitimately DOES win, so the honest signal is the contract, not
    the storage.

    MUTATION: return `fingerprint` instead of None on an empty read-back -> the caller reports
    agreement and boots.
    """
    import logging

    class _UnreadableRegistry:
        """Claims succeed; the read-back never sees them (a reset or eviction landed between)."""

        def claim_blob_target(self, fingerprint):  # noqa: ANN001, ANN201
            return None

        def get_blob_target(self):  # noqa: ANN201
            return None

        def clear_blob_target(self) -> None:
            pass

    with caplog.at_level(logging.WARNING, logger="blastbox.canary"):
        out = check_blob_target_agreement(_UnreadableRegistry(), _Store("results/x"),
                                          role="ingress")

    assert out is None, f"an unreadable registry was reported as an agreed target ({out})"
    msgs = [r.getMessage() for r in caplog.records]
    assert any("blob_target_unverified" in m for m in msgs), (
        f"an unreadable registry must say agreement is UNVERIFIED, not stay silent: {msgs}")
    assert not any("agrees with the queue" in m for m in msgs), (
        f"an unreadable registry was reported as agreement: {msgs}")


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

    with caplog.at_level(logging.WARNING, logger="blastbox.canary"):
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
    assert check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="dispatcher") is None
    assert check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="ingress") is None
    recorded = q.get_blob_target()
    assert recorded == "local:", (
        f"a local store registered {recorded!r}; it must record the path-INDEPENDENT sentinel -- "
        f"a host-local path is meaningless to compare, but recording nothing made enforcement "
        f"depend on which side booted first")


def test_every_protocol_used_with_isinstance_stays_runtime_checkable():
    """A guard that runs WITHOUT Postgres, because the one that caught this does not.

    `PageHashSearch` lost its `@runtime_checkable` when this feature was added: the new Protocol
    was inserted between that decorator and the class it decorated, so the decorator silently
    transferred to the new class and `isinstance(store, PageHashSearch)` began raising TypeError
    at runtime. Nothing local failed -- the existing regression test for it is Postgres-gated and
    skips on SQLite -- so it took a CI job with a real database to surface a one-line edit.

    Consumers gate on isinstance for all three of these (the dispatcher's on-DONE indexer, the
    /v1/similar route, and now the blob-target check), so losing the decorator is a runtime break,
    not a typing nicety. Asserted directly rather than by inspecting decorators, since the thing
    that matters is that the call does not raise.
    """
    from blastbox.host.jobs import base

    store = InMemoryJobStore()
    for name in ("JobStore", "PageHashSearch", "BlobTargetRegistry"):
        proto = getattr(base, name)
        try:
            isinstance(store, proto)
        except TypeError as exc:  # pragma: no cover - the failure this exists to prevent
            pytest.fail(f"isinstance() against {name} raises: {exc}. It lost @runtime_checkable, "
                        f"and every consumer that gates on it breaks at runtime.")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_a_local_store_facing_an_s3_registered_queue_is_refused(backend):
    """Local-vs-LOCAL is ambiguous; local-vs-S3 is not, and skipping both was too much.

    A host-local directory can never be the bucket another process registered, so this needs no
    path comparison at all. It is the original 17,626-job incident with one side over --
    BLASTBOX_BLOB_URL set on the dispatchers, missing on the API -- and the first scoping fix let
    it pass. It matters most on the ingress: check_store_coherence has three call sites and every
    one is dispatcher-side, so an API that fell back to a local store had no other check at all.

    MUTATION: return None for every local store before consulting the registry -> the local ingress
    boots against an S3-registered queue.
    """
    q = backend()
    check_blob_target_agreement(q, _Store("results/stack-a"), role="dispatcher")

    with pytest.raises(CanaryFailure) as ei:
        check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="ingress")
    msg = str(ei.value)
    assert "results/stack-a" in msg, f"the message must name what the queue holds: {msg}"
    assert "BLASTBOX_BLOB_URL" in msg, f"the message must name the usual cause: {msg}"


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_two_local_stores_still_agree_across_different_mount_points(backend):
    """...and the NFS shape must still boot: one export, different mount points per host.

    This is the case that got the first version rewritten; the fix for the S3 asymmetry must not
    resurrect it.
    """
    q = backend()
    assert check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="dispatcher") is None
    assert check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="ingress") is None
    assert q.get_blob_target() == "local:", "a local store must record the sentinel, not a path"


def test_the_redis_registry_behaves_like_the_others():
    """Redis is the only shipped backend that is genuinely shared across machines -- so it is the
    one where this check ever does real work -- and it had only an attribute-existence assertion.

    The stated reason ("a live Redis is not available here") was wrong: fakeredis is already a test
    dependency used by four other suites in this repo.

    MUTATION: drop `nx=True` -> last-writer-wins, the loser overwrites and reports agreement.
    """
    fakeredis = pytest.importorskip("fakeredis")

    from blastbox.host.jobs.redis_store import RedisJobStore

    q = RedisJobStore(fakeredis.FakeRedis())
    assert q.get_blob_target() is None
    assert q.claim_blob_target("s3://results/stack-a") == "s3://results/stack-a"
    assert q.claim_blob_target("s3://results/stack-b") == "s3://results/stack-a", (
        "the second claimant overwrote the registry instead of losing to it")
    assert q.get_blob_target() == "s3://results/stack-a"

    with pytest.raises(CanaryFailure):
        check_blob_target_agreement(q, _Store("results/stack-b"), role="ingress")

    q.clear_blob_target()
    assert q.get_blob_target() is None
    assert check_blob_target_agreement(q, _Store("results/stack-b"), role="ingress")


def _s3_with_endpoint(bucket: str, prefix: str, endpoint: str):  # noqa: ANN202
    """An S3-shaped store whose endpoint is visible to describe_blob_store."""
    from types import SimpleNamespace

    store = _Store(bucket)
    store._prefix = prefix
    store._s3 = SimpleNamespace(meta=SimpleNamespace(endpoint_url=endpoint))
    return store


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_split_endpoint_routing_to_one_bucket_still_agrees(backend):
    """The endpoint is per-process ROUTING, not where the bytes land.

    The shipped compose does this deliberately: the api reaches MinIO on the host IP while the
    dispatcher uses the `minio` alias, because the backend network is `internal: true`. One MinIO,
    one bucket, one prefix, two routes. An identity that included the endpoint refused that stack
    outright -- both orders, no off switch, and `blob-target reset` could not help because clearing
    just re-records whichever side boots next. It would have been the fourth time on this branch
    that a check rejected a working deployment by over-reading an incidental detail.

    MUTATION: make the fingerprint `describe_blob_store(store)` again -> the compose stack refuses
    to boot.
    """
    q = backend()
    api = _s3_with_endpoint("blastbox", "redtusk", "http://10.1.0.5:9000")
    dispatcher = _s3_with_endpoint("blastbox", "redtusk", "http://minio:9000")

    assert check_blob_target_agreement(q, api, role="ingress")
    assert check_blob_target_agreement(q, dispatcher, role="dispatcher"), (
        "a dispatcher reaching the SAME bucket by a different endpoint was refused; that is the "
        "shipped compose topology and it has no off switch")

    # ...and a genuine bucket difference is still caught, endpoint notwithstanding.
    with pytest.raises(CanaryFailure):
        check_blob_target_agreement(q, _s3_with_endpoint("other", "redtusk", "http://minio:9000"),
                                    role="dispatcher")


def test_sql_reports_unknown_when_the_row_vanishes_between_write_and_read(tmp_path):
    """The SQL-specific half of the empty-read-back hazard.

    A losing `INSERT ... ON CONFLICT DO NOTHING` takes no row lock, so under READ COMMITTED a
    concurrent `clear_blob_target()` can commit before this SELECT's snapshot. Returning the
    caller's own fingerprint there reads as agreement. Driven deterministically by clearing the row
    between the two statements rather than by racing, since the point is the RETURN VALUE, not the
    timing.

    MUTATION: `return str(row[0]) if row else fingerprint` -> the loser reports winning.
    """
    store = SqlJobStore(f"sqlite:///{tmp_path}/j.db")
    store.claim_blob_target("s3://results/stack-a")

    real_connect = store._connect
    cleared = {"done": False}

    class _ClearOnce:
        """Drops the row after the INSERT, before the SELECT reads it."""

        def __init__(self, conn) -> None:  # noqa: ANN001
            self._conn = conn

        def execute(self, sql, *a):  # noqa: ANN001, ANN201
            out = self._conn.execute(sql, *a)
            if "INSERT INTO blob_target" in sql and not cleared["done"]:
                cleared["done"] = True
                self._conn.execute("DELETE FROM blob_target WHERE id = 1")
            return out

        def __getattr__(self, name):  # noqa: ANN001, ANN204
            return getattr(self._conn, name)

    import contextlib

    @contextlib.contextmanager
    def _wrapped():
        with real_connect() as conn:
            yield _ClearOnce(conn)

    store._connect = _wrapped  # type: ignore[method-assign]
    try:
        out = store.claim_blob_target("s3://results/stack-b")
    finally:
        store._connect = real_connect  # type: ignore[method-assign]

    assert out is None, (
        f"the registry read back empty after our write and we returned {out!r} -- our own value, "
        f"which the caller cannot tell from winning. That boots the losing side on the wrong "
        f"target with the gate reporting agreement")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_a_local_store_booting_first_still_conflicts_with_an_s3_peer(backend):
    """Enforcement must not depend on WHICH SIDE BOOTS FIRST.

    The previous version returned without claiming anything for a local store, so a local process
    booting first recorded nothing and the S3 peer then claimed an empty registry -- both started,
    mismatch undetected, purely because the wrong side won the race to boot. Half-built, in fact:
    the code already tested `recorded.startswith("local:")` while nothing ever wrote that sentinel.

    A local store now registers a path-INDEPENDENT sentinel. Not a path, because paths across hosts
    are meaningless (the NFS shape must keep working); not an S3 target, so it conflicts in either
    order.

    MUTATION: return without claiming for local stores -> the local-first ordering boots both.
    """
    q = backend()
    assert check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()),
                                       role="dispatcher") is None
    with pytest.raises(CanaryFailure):
        check_blob_target_agreement(q, _Store("results/stack-a"), role="ingress")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_a_localblobstore_subclass_is_still_local(backend):
    """`Dispatcher(blob_store=...)` is a supported injection seam, so wrapping LocalBlobStore to add
    instrumentation is something callers legitimately do.

    An exact type-NAME test classified such a wrapper as non-local, which skipped the fail-closed
    shared-store refusal and let two hosts with identical private paths register and agree. A gate a
    subclass silently bypasses is not a gate.

    MUTATION: `type(store).__name__ == "LocalBlobStore"` -> the subclass registers an s3-shaped
    identity and the local-first conflict disappears.
    """
    from blastbox.host.blobs.local import LocalBlobStore as RealLocal
    from blastbox.host.canary import is_local_blob_store

    class Instrumented(RealLocal):
        pass

    store = Instrumented(tempfile.mkdtemp())
    assert is_local_blob_store(store) is True
    q = backend()
    assert check_blob_target_agreement(q, store, role="dispatcher") is None
    with pytest.raises(CanaryFailure):
        check_blob_target_agreement(q, _Store("results/stack-a"), role="ingress")


def test_a_credentialed_blob_url_never_reaches_the_log_or_the_registry():
    """`S3BlobStore._bucket` is `urlsplit(BLASTBOX_BLOB_URL).netloc`, user-info and all.

    `s3://KEY:SECRET@bucket/prefix` therefore yields a `_bucket` of `KEY:SECRET@bucket`. That is
    not just a log leak: the same string becomes the target FINGERPRINT, which this feature
    PERSISTS into the job queue -- so a mistyped URL writes a live credential into Postgres or
    Redis and leaves it there for every later process to read. `_safe_endpoint` covered the
    endpoint only and never saw this value.

    MUTATION: drop `_safe_bucket` from either the formatter or the fingerprint -> the secret
    appears in the startup log, or at rest in the queue.
    """
    from blastbox.host.canary import blob_target_fingerprint, describe_blob_store

    leaky = _Store("AKIAKEY:s3cr3t@bucket")
    leaky._prefix = "prefix"

    described = describe_blob_store(leaky)
    fingerprint = blob_target_fingerprint(leaky)

    for label, value in (("startup log", described), ("persisted fingerprint", fingerprint)):
        assert "s3cr3t" not in value and "AKIAKEY" not in value, (
            f"the {label} carries the credential from BLASTBOX_BLOB_URL: {value}")
    assert "bucket" in fingerprint, f"the bucket itself must survive redaction: {fingerprint}"


def test_an_unknown_store_shape_is_unverified_rather_than_equated_by_class():
    """Two instances of the same custom BlobStore are not the same target.

    An unrecognised shape has no identity we can compare, and returning `ClassName()` equated every
    instance of it -- an ingress and a dispatcher on two different endpoints of one custom store
    would "agree" because they share a type. That is worse than not checking, because it reports a
    guarantee it never established.

    MUTATION: return `f"{type(store).__name__}()"` -> two unrelated instances agree.
    """
    import logging

    from blastbox.host.canary import blob_target_fingerprint
    from blastbox.host.jobs.memory import InMemoryJobStore

    class CustomStore:
        """Neither local nor S3-shaped."""

    assert blob_target_fingerprint(CustomStore()) == "", (
        "an unrecognised store was given a comparable identity it does not have")

    q = InMemoryJobStore()
    logging.disable(logging.NOTSET)
    assert check_blob_target_agreement(q, CustomStore(), role="dispatcher") is None
    assert q.get_blob_target() is None, (
        "an unidentifiable store registered a target; the next process would have to match a value "
        "that means nothing")


@pytest.mark.parametrize("backend", ALL_BACKENDS)
def test_a_local_claim_that_cannot_be_read_back_is_unverified(backend):
    """The local path must answer UNKNOWN exactly like the non-local one.

    When the registry read-back comes up empty after the sentinel claim -- a concurrent reset, or a
    Redis eviction -- the old code treated it as success and logged that the sentinel WAS
    registered. A remote process could then claim the empty registry and start on S3 while this
    local process was already serving, recreating the split without even the unverified warning the
    non-local path emits.

    MUTATION: drop the `recorded is None` branch -> a failed read-back is logged as registered.
    """
    q = backend()
    q.claim_blob_target = lambda fp: None  # type: ignore[method-assign]

    with caplog_at_warning() as records:
        out = check_blob_target_agreement(q, LocalBlobStore(tempfile.mkdtemp()), role="ingress")

    assert out is None
    msgs = [r.getMessage() for r in records]
    assert any("blob_target_unverified" in m for m in msgs), (
        f"a failed read-back on the local path was not reported as unverified: {msgs}")
    assert not any("registered the local sentinel" in m for m in msgs), (
        f"the log claimed the sentinel was registered when it was not: {msgs}")


import contextlib  # noqa: E402


@contextlib.contextmanager
def caplog_at_warning():
    """Collect WARNING records from the canary logger regardless of global logging state."""
    import logging

    records: list = []

    class _Grab(logging.Handler):
        def emit(self, record):  # noqa: ANN001
            records.append(record)

    log = logging.getLogger("blastbox.canary")
    handler = _Grab()
    prev_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    log.addHandler(handler)
    prev_level, log.level = log.level, logging.WARNING
    try:
        yield records
    finally:
        log.removeHandler(handler)
        log.level = prev_level
        logging.disable(prev_disable)
