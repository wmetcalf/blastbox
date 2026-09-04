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


def test_a_credentialed_blob_url_is_rejected_at_construction():
    """Redacting the DISPLAY was necessary but not sufficient.

    `urlparse` puts everything before the `@` into netloc, so `s3://key:secret@bucket/prefix` gives
    a bucket of `key:secret@bucket` -- not a bucket. Every request fails against it, while the
    canary (which redacts for display and for the persisted fingerprint) saw the same "bucket" on
    both sides and reported agreement. A broken configuration made to look healthy by the check
    meant to catch it.

    MUTATION: drop the `@` guard in S3BlobStore.__init__ -> the invalid bucket is accepted.
    """
    from pathlib import Path

    from blastbox.host.blobs.s3 import S3BlobStore

    env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y", "AWS_DEFAULT_REGION": "us-east-1"}
    with pytest.raises(ValueError) as ei:
        S3BlobStore("s3://AKIAEXAMPLE:hunter2swordfish@bucket/prefix",
                    job_root=Path("/tmp"), env=env)
    msg = str(ei.value)
    # A distinctive literal, because "SECRET" also appears in AWS_SECRET_ACCESS_KEY in the remedy.
    assert "hunter2swordfish" not in msg and "AKIAEXAMPLE" not in msg, (
        f"the rejection echoed the credential it is rejecting: {msg}")
    assert "AWS_ACCESS_KEY_ID" in msg, "the message must say where credentials actually belong"

    S3BlobStore("s3://bucket/prefix", job_root=Path("/tmp"), env=env)   # still fine


def test_the_vm_dispatcher_gates_itself_rather_than_trusting_the_cli():
    """`build_remote_vm_dispatcher(...)` is a supported factory, so the gate cannot live in the CLI.

    An embedder calling `run()` got no coherence enforcement, no target agreement and no
    round-trip: it claimed its first job immediately and failed it, against a documented guarantee
    that every dispatcher variant gates before its first claim.

    MUTATION: delete the `self._startup_gate()` call from run() -> the gate never runs.
    """
    import inspect

    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    assert hasattr(VmJobDispatcher, "_startup_gate"), "the dispatcher owns no startup gate"
    src = inspect.getsource(VmJobDispatcher.run)
    assert "_startup_gate()" in src, (
        "VmJobDispatcher.run() does not invoke its own startup gate, so a programmatic caller "
        "claims jobs without proving it can store a result")

    gate = inspect.getsource(VmJobDispatcher._startup_gate)
    for step in ("check_store_coherence", "check_blob_target_agreement", "blob_roundtrip"):
        assert step in gate, f"the dispatcher's gate omits {step}, which the CLI path performs"
    assert gate.index("check_blob_target_agreement") > gate.index("blob_roundtrip"), (
        "the dispatcher registers its target before probing it; a target that never proved it "
        "works must not become the one every other process has to match")


def test_a_read_probe_reports_an_unreachable_store_without_refusing_the_boot():
    """Agreement compares identities; it does not prove this process can reach the store.

    An ingress with stale credentials matches its dispatchers exactly, boots, and 404s every
    artifact. The probe is advisory on purpose -- a brownout at boot must not turn a recoverable
    outage into an outage plus a restart loop.

    MUTATION: make check_read_access raise instead of warning -> the API stops booting on a
    transient store failure.
    """
    from blastbox.host.canary import check_read_access

    class _Unreachable:
        _bucket = "results"
        _prefix = ""
        _s3 = None

        def has_output(self, job_id):  # noqa: ANN001, ANN201
            raise OSError("connection refused")

    with caplog_at_warning() as records:
        check_read_access(_Unreachable(), role="ingress")     # must not raise

    assert any("read_unverified" in r.getMessage() for r in records), (
        "an unreachable store was not reported at all")


def test_a_denied_samples_prefix_is_reported_but_a_missing_object_is_not():
    """The round-trip only exercises results/. Inputs are a different prefix and often a different
    grant, and a dispatcher that cannot fetch inputs fails every job it claims.

    NotFound is the EXPECTED answer and proves the read was permitted; a denial is the finding.

    MUTATION: treat every exception as success -> a denied samples prefix passes silently.
    """
    from blastbox.host.canary import check_sample_read_access

    class _Store:
        _bucket = "results"
        _prefix = ""
        _s3 = None

        def __init__(self, exc) -> None:  # noqa: ANN001
            self._exc = exc

        def get_sample(self, sha, dest):  # noqa: ANN001, ANN201
            raise self._exc

    with caplog_at_warning() as denied:
        check_sample_read_access(_Store(PermissionError("AccessDenied on samples/")),
                                 role="dispatcher")
    assert any("sample_read_unverified" in r.getMessage() for r in denied), (
        "a denied samples prefix was not reported; every claimed job would fail in get_sample")

    with caplog_at_warning() as missing:
        check_sample_read_access(_Store(FileNotFoundError("404 Not Found")), role="dispatcher")
    assert not [r for r in missing if "sample_read_unverified" in r.getMessage()], (
        "a MISSING probe object was reported as a permission problem; not-found proves the read "
        "was allowed and answered")


def test_reset_refuses_without_an_explicit_quiescence_affirmation():
    """Agreement is checked at STARTUP only, so a live fleet never notices a reset.

    Clearing under running processes lets a restarted one adopt a new target while the others keep
    the old, and a rolling restart then writes to one store and serves from the other -- the
    failure this command exists to help escape, caused by the command.

    MUTATION: clear unconditionally -> the registry is gone before the operator is warned.
    """
    import argparse

    from blastbox.host import cli

    cleared = {"n": 0}

    class _Store:
        def claim_blob_target(self, fp):  # noqa: ANN001, ANN201
            return "s3://results/old"

        def get_blob_target(self):  # noqa: ANN201
            return "s3://results/old"

        def clear_blob_target(self) -> None:
            cleared["n"] += 1

    import blastbox.host.jobs.factory as factory
    real = factory.build_job_store_from_env
    factory.build_job_store_from_env = lambda *a, **k: _Store()   # type: ignore[assignment]
    try:
        rc = cli._blob_target_cmd(argparse.Namespace(blob_target_cmd="reset", yes=False))
        assert rc != 0, "reset without --yes returned success"
        assert cleared["n"] == 0, "the registry was cleared despite refusing"

        rc = cli._blob_target_cmd(argparse.Namespace(blob_target_cmd="reset", yes=True))
        assert rc == 0 and cleared["n"] == 1, "reset with --yes did not clear"
    finally:
        factory.build_job_store_from_env = real   # type: ignore[assignment]


class _WrapsEverything:
    """The shipped S3 shape: a client, and helpers that hide the real error.

    `has_output` returns False for ANY failure (correct for the age reclaim, fatal for a probe),
    and `get_sample` re-raises everything as a generic BlobFetchError with the detail in __cause__.
    """

    _bucket = "results"
    _prefix = ""

    def __init__(self, exc) -> None:  # noqa: ANN001
        self._exc = exc

        class _Client:
            def head_object(_self, **kw):  # noqa: ANN001, ANN003, ANN202, N805
                raise exc

        self._s3 = _Client()

    def _key(self, *parts: str) -> str:
        return "/".join(parts)

    def has_output(self, job_id: str) -> bool:
        return False                       # swallows everything, exactly like the real one

    def get_sample(self, sha256, dest):  # noqa: ANN001, ANN201
        from blastbox.host.blobs.s3 import BlobFetchError
        raise BlobFetchError(f"sample fetch failed: {sha256}") from self._exc


class _Denied(Exception):
    response = {"Error": {"Code": "AccessDenied"}}


def test_the_read_probe_sees_past_has_output_swallowing_every_error():
    """`S3BlobStore.has_output` returns False for AccessDenied, bad credentials and connection
    failures alike -- deliberately, because the age reclaim deletes local trees on its answer.

    A probe built on it therefore never entered the warning path: an unreachable ingress logged
    `canary.read_ok` and reported read access it had never verified, which is worse than having no
    probe at all because it makes a claim.

    MUTATION: probe through `has_output` again -> a denied store reports read_ok.
    """
    from blastbox.host.canary import check_read_access

    with caplog_at_warning() as records:
        check_read_access(_WrapsEverything(_Denied()), role="ingress")
    assert any("read_unverified" in r.getMessage() for r in records), (
        "a store that denies reads was reported as readable")

    with caplog_at_warning() as ok:
        check_read_access(_WrapsEverything(FileNotFoundError("404 Not Found")), role="ingress")
    assert not [r for r in ok if "read_unverified" in r.getMessage()], (
        "a MISSING probe key was reported as a read failure; not-found proves the read was "
        "permitted and answered")


def test_the_sample_probe_reads_the_wrapped_cause_not_the_generic_message():
    """`get_sample` re-raises everything as BlobFetchError("sample fetch failed: <sha>").

    Matching on that string classified every healthy S3 dispatcher as `sample_read_unverified` --
    permanently noisy, and still unable to spot an actually-denied prefix, which is both failure
    modes at once.

    MUTATION: match on `str(exc)` instead of walking __cause__ -> healthy dispatchers are flagged.
    """
    from blastbox.host.canary import check_sample_read_access

    with caplog_at_warning() as healthy:
        check_sample_read_access(_WrapsEverything(FileNotFoundError("404 NoSuchKey")),
                                 role="dispatcher")
    assert not [r for r in healthy if "sample_read_unverified" in r.getMessage()], (
        "a healthy dispatcher whose probe key is simply absent was flagged as unable to read")

    with caplog_at_warning() as denied:
        check_sample_read_access(_WrapsEverything(_Denied()), role="dispatcher")
    assert any("sample_read_unverified" in r.getMessage() for r in denied), (
        "a denied samples prefix went unreported; every claimed job would fail in get_sample")


def test_a_programmatic_dispatcher_gets_the_periodic_canary_too():
    """The CLI used to install the callback by reaching in and setting private fields.

    A programmatic dispatcher therefore performed the startup probe and then never re-checked,
    against a documented cadence -- the same shape as the startup gate living in one caller.

    MUTATION: drop the `_canary_cb` wiring from _startup_gate -> programmatic dispatchers never
    re-probe.
    """
    import inspect

    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    gate = inspect.getsource(VmJobDispatcher._startup_gate)
    assert "_canary_cb" in gate and "_canary_interval_s" in gate, (
        "the dispatcher's own gate never installs the periodic canary, so only the CLI path "
        "re-checks the store after startup")
    assert "getattr(self, \"_canary_cb\", None) is None" in gate, (
        "the gate must not clobber a callback the CLI already installed")


def test_a_healthy_local_dispatcher_is_not_flagged_for_a_missing_sample(tmp_path):
    """`LocalBlobStore.get_sample` raises BlobFetchError("sample not present: …") with NO cause.

    The S3-shaped markers did not match that wording, so every healthy LOCAL dispatcher emitted
    `sample_read_unverified` -- telling operators their inputs may be unfetchable when nothing is
    wrong. The same blindness as the S3 wrapper, on the other backend: the fix covered one of two
    identical cases.

    MUTATION: drop "not present" from the missing-object markers -> healthy local dispatchers are
    flagged again.
    """
    from blastbox.host.blobs.local import LocalBlobStore
    from blastbox.host.canary import check_sample_read_access

    store = LocalBlobStore(str(tmp_path))
    with caplog_at_warning() as records:
        check_sample_read_access(store, role="dispatcher", scratch_dir=tmp_path)
    assert not [r for r in records if "sample_read_unverified" in r.getMessage()], (
        "a healthy local dispatcher was told its samples prefix may be unreadable")


def test_an_unreadable_local_blob_root_is_reported_not_declared_ok(tmp_path):
    """`LocalBlobStore.has_output` collapses OSError to False, exactly as the S3 one does.

    So an ingress whose blob root is unreadable by its UID reported `canary.read_ok` -- the same
    false all-clear the S3 fix removed, still live on the other backend because the fallback path
    was left alone.

    MUTATION: probe local stores through `has_output` again -> an unreadable root reports ok.
    """
    import os
    import stat

    from blastbox.host.blobs.local import LocalBlobStore
    from blastbox.host.canary import check_read_access

    root = tmp_path / "blobs"
    root.mkdir()
    store = LocalBlobStore(str(root))
    os.chmod(root, 0)                       # unreadable by this UID
    try:
        if os.access(root, os.R_OK):        # running as root: the probe cannot fail
            pytest.skip("cannot make a directory unreadable as this user")
        with caplog_at_warning() as records:
            check_read_access(store, role="ingress")
        assert any("read_unverified" in r.getMessage() for r in records), (
            "an unreadable blob root was declared readable; every result open would then fail")
    finally:
        os.chmod(root, stat.S_IRWXU)


def test_the_canary_key_survives_a_container_replacement(monkeypatch):
    """Ephemeral container hostnames broke the one-object bound the stable key exists for.

    Recreating the same logical dispatcher changes `socket.gethostname()`, so under the supported
    PUT/GET-but-no-DELETE policy each rollout left another permanent canary object -- the unbounded
    growth the stable key was introduced to end.

    MUTATION: derive the key from the hostname alone -> the key changes across replacements.
    """
    import socket

    from blastbox.host.canary import canary_job_id

    monkeypatch.setenv("BLASTBOX_DISPATCHER_ID", "redtusk-dispatch-a")
    monkeypatch.setattr(socket, "gethostname", lambda: "container-aaaa")
    first = canary_job_id("aws-ec2|clippyshot|/var/lib/blastbox")
    monkeypatch.setattr(socket, "gethostname", lambda: "container-bbbb")
    second = canary_job_id("aws-ec2|clippyshot|/var/lib/blastbox")
    assert first == second, (
        "the canary key changed when the container was replaced; under a DELETE-denied policy "
        "that leaves one more permanent object per rollout")

    # ...and without a declared identity the hostname still distinguishes genuine hosts.
    monkeypatch.delenv("BLASTBOX_DISPATCHER_ID")
    monkeypatch.setattr(socket, "gethostname", lambda: "host-1")
    a = canary_job_id("t|e|/root")
    monkeypatch.setattr(socket, "gethostname", lambda: "host-2")
    assert a != canary_job_id("t|e|/root"), "two real hosts must not share one canary key"
