"""The canary exists to catch deployment bugs that previously surfaced as DONE jobs whose results
404'd, days later. These pin the specific shapes that actually happened -- a store that cannot be
written, one whose write does not land, one that reads back different bytes -- plus the gate
semantics, because "fails closed at boot, advisory once serving" is the whole design and a silent
inversion of it would restore the original failure exactly.
"""
import json
from pathlib import Path

import pytest

from blastbox.host.blobs.local import LocalBlobStore
from blastbox.host.canary import CanaryFailure, blob_roundtrip, describe_blob_store


def _local(tmp_path: Path) -> LocalBlobStore:
    return LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")


def test_a_working_store_round_trips(tmp_path):
    msg = blob_roundtrip(_local(tmp_path))
    assert "OK" in msg and "LocalBlobStore" in msg


def test_the_canary_leaves_nothing_behind(tmp_path):
    store = _local(tmp_path)
    blob_roundtrip(store)
    leftovers = [p for p in (tmp_path / "blobs").rglob("*") if p.is_file()]
    assert leftovers == [], leftovers


class _WriteFails(LocalBlobStore):
    def put_output(self, job_id, out_dir):
        raise OSError("Could not connect to the endpoint URL: http://172.18.101.15:9000")


def test_an_unwritable_store_fails_with_the_remedy(tmp_path):
    """The real one: dispatchers on an `internal: true` network run the job, then cannot upload."""
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_WriteFails(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    msg = str(ei.value)
    assert "WRITE failed" in msg
    # The remedy must name the topology cause, not just the exception -- the connection error on
    # its own reads as a storage outage rather than a container with no route.
    assert "route" in msg and "internal" in msg
    assert "endpoint URL" in msg          # original cause preserved


class _WriteVanishes(LocalBlobStore):
    """Accepts the write and then reports nothing there.

    This is the 17k incident in miniature: the dispatcher sealed into one store and the API read
    another, so every write "succeeded" and nothing was ever readable.
    """

    def has_output(self, job_id):
        return False


def test_a_write_that_does_not_land_is_caught(tmp_path):
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_WriteVanishes(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    msg = str(ei.value)
    assert "did not exist" in msg
    assert "LocalBlobStore" in msg and "404" in msg


class _CorruptsBytes(LocalBlobStore):
    def open_output(self, job_id, name):
        import io
        return io.BytesIO(json.dumps({"status": "ok", "artifacts": [], "tampered": 1}).encode())


def test_bytes_that_come_back_different_are_caught(tmp_path):
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_CorruptsBytes(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    assert "different bytes" in str(ei.value)


class _DeleteFails(LocalBlobStore):
    def delete_job(self, job_id):
        raise OSError("AccessDenied")


def test_a_store_that_cannot_delete_still_passes(tmp_path, caplog):
    """A failed cleanup is a warning, not a failure.

    Taking a dispatcher down because it could not remove a 90-byte canary object would be the
    check causing the outage it exists to prevent.
    """
    msg = blob_roundtrip(_DeleteFails(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    assert "OK" in msg
    assert any("cleanup_failed" in r.message for r in caplog.records)


def test_describe_names_the_backend_so_a_silent_local_fallback_is_visible(tmp_path):
    """The 17k incident was a LocalBlobStore nobody meant to use. Naming it in the boot log is
    what turns that from an invisible default into something readable."""
    d = describe_blob_store(_local(tmp_path))
    assert "LocalBlobStore" in d and str(tmp_path) in d


class _Postgres:
    _driver = "postgres"


class _Sqlite:
    _driver = "sqlite"


class _Redis:
    pass


_Redis.__name__ = "RedisJobStore"


# --- gate semantics -------------------------------------------------------------------------
class _Dispatcher:
    """Minimal stand-in exercising Dispatcher.self_test's real body."""

    def __init__(self, store, job_store=None):
        self._blobs = store
        # Defaults to a SINGLE-NODE queue so these cases exercise the round-trip path; the
        # coherence tests override it. A shared queue here would short-circuit before the
        # round-trip and quietly stop these tests from testing what they name.
        self._job_store = job_store if job_store is not None else _Sqlite()

    self_test = None  # bound below


def _make(store, job_store=None):
    from blastbox.host.dispatch import Dispatcher
    d = _Dispatcher(store, job_store)
    d.self_test = Dispatcher.self_test.__get__(d, _Dispatcher)
    return d


def test_startup_fails_closed(tmp_path):
    """A dispatcher whose store is misconfigured must refuse to serve.

    The alternative is what happened: a healthy-looking stack that claims thousands of jobs and
    marks them DONE with unfetchable results.
    """
    d = _make(_WriteFails(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    with pytest.raises(CanaryFailure):
        d.self_test(gate=True)


def test_the_periodic_pass_does_not_gate(tmp_path):
    """Once serving, a store that goes away is a BROWNOUT, not a config error.

    Killing the dispatcher would destroy warm capacity for something that heals by itself -- the
    exact behaviour issue #79 exists to prevent -- so the periodic pass reports and keeps serving.
    """
    d = _make(_WriteFails(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    assert d.self_test(gate=False) is False


def test_a_healthy_store_passes_both_modes(tmp_path):
    d = _make(_local(tmp_path))
    assert d.self_test(gate=True) is True
    assert d.self_test(gate=False) is True


class _FakeS3:
    """Shape-compatible stand-in for S3BlobStore's identifying attributes."""

    class _Client:
        class meta:  # noqa: N801
            endpoint_url = "http://172.18.101.15:9000"

    def __init__(self):
        self._bucket, self._prefix, self._s3 = "blastbox", "pr83run", self._Client()


def test_describe_names_bucket_prefix_and_endpoint():
    """`S3BlobStore(blastbox)` does not distinguish a working deployment from one pointed at the
    wrong host. The prefix separates two stacks sharing a bucket; the endpoint is the thing you
    check when a write cannot connect."""
    d = describe_blob_store(_FakeS3())
    assert "blastbox/pr83run" in d
    assert "172.18.101.15:9000" in d


# --- the check the round-trip cannot make ----------------------------------------------------
def test_a_shared_queue_with_a_local_blob_store_is_refused(tmp_path):
    """The 17k incident, and the one shape a round-trip provably cannot catch.

    A LocalBlobStore reads back its own directory, so it passes every liveness test while sealing
    results the API cannot read. Only the COMBINATION -- jobs claimed from a queue other processes
    fill, results written where only this container can see them -- reveals it.
    """
    from blastbox.host.canary import check_store_coherence
    with pytest.raises(CanaryFailure) as ei:
        check_store_coherence(_Postgres(), _local(tmp_path))
    msg = str(ei.value)
    assert "SHARED queue" in msg and "LOCAL blob store" in msg
    assert "BLASTBOX_BLOB_URL" in msg and "404" in msg


def test_redis_counts_as_shared(tmp_path):
    from blastbox.host.canary import check_store_coherence
    with pytest.raises(CanaryFailure):
        check_store_coherence(_Redis(), _local(tmp_path))


def test_a_single_node_deployment_is_left_alone(tmp_path):
    """SQLite queue + local blobs is a perfectly good configuration, not a bug."""
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(_Sqlite(), _local(tmp_path))


def test_an_unrecognised_job_store_never_triggers_the_failure(tmp_path):
    """Conservative on purpose: a store we cannot classify must not produce a false refusal that
    stops a valid deployment from booting."""
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(object(), _local(tmp_path))


def test_a_shared_queue_with_a_remote_store_passes():
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(_Postgres(), _FakeS3())


def test_the_dispatcher_gate_refuses_the_incoherent_pair(tmp_path):
    """It must fire through self_test, not just standalone -- and BEFORE the round-trip, which
    would otherwise pass and let the dispatcher serve."""
    d = _make(_local(tmp_path))
    d._job_store = _Postgres()
    with pytest.raises(CanaryFailure) as ei:
        d.self_test(gate=True)
    assert "SHARED queue" in str(ei.value)
