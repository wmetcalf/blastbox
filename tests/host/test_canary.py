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

    def __init__(self, store, job_store=None, job_root=None):
        self._blobs = store
        self._job_root = job_root
        self._require_shared_blob_store = False
        # Defaults to a SINGLE-NODE queue so these cases exercise the round-trip path; the
        # coherence tests override it. A shared queue here would short-circuit before the
        # round-trip and quietly stop these tests from testing what they name.
        self._job_store = job_store if job_store is not None else _Sqlite()

    self_test = None  # bound below


def _make(store, job_store=None, job_root=None):
    from blastbox.host.dispatch import Dispatcher
    d = _Dispatcher(store, job_store, job_root)
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
def test_a_local_store_on_a_shared_queue_warns_by_default(tmp_path, caplog):
    """Default is ADVISORY. Two earlier attempts to infer this from the deployment each refused a
    DOCUMENTED configuration -- Mode 2 (NFS blob root) and Mode 1 (single node on local postgres).
    Refusing a working deployment by default, fail-closed, is worse than the bug being hunted."""
    import logging
    from blastbox.host.canary import check_store_coherence
    with caplog.at_level(logging.WARNING, logger="blastbox.canary"):
        check_store_coherence(_Postgres(), _local(tmp_path), tmp_path / "jobs")
    assert any("local_blob_store_with_shared_queue" in r.message for r in caplog.records)


def test_it_refuses_only_when_the_operator_declares_a_fleet(tmp_path):
    """BLASTBOX_REQUIRE_SHARED_BLOB_STORE=1 is the topology evidence the canary cannot deduce."""
    from blastbox.host.canary import check_store_coherence
    with pytest.raises(CanaryFailure) as ei:
        check_store_coherence(_Postgres(), _local(tmp_path), tmp_path / "jobs",
                              require_shared=True)
    msg = str(ei.value)
    assert "SHARED queue" in msg and "LOCAL blob store" in msg
    assert "BLASTBOX_BLOB_URL" in msg and "404" in msg


def test_documented_mode_1_single_node_on_local_postgres_still_boots(tmp_path):
    """docs/specs/2026-07-21-distributed-blob-storage-design.md: two processes on one box sharing
    "a sqlite (or local postgres) store and the local filesystem", BLASTBOX_BLOB_URL unset. An
    earlier revision refused exactly this."""
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(_Postgres(), _local(tmp_path), tmp_path / "jobs")


def test_documented_mode_2_nfs_blob_root_still_boots(tmp_path):
    """Same doc, Mode 2: several nodes on one postgres with BLASTBOX_BLOB_LOCAL_ROOT on a shared
    export. The revision before this one refused it for being "local"."""
    from blastbox.host.canary import check_store_coherence
    nfs = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "nfs-export")
    check_store_coherence(_Postgres(), nfs, tmp_path / "jobs")


def test_redis_counts_as_shared(tmp_path):
    from blastbox.host.canary import check_store_coherence
    with pytest.raises(CanaryFailure):
        check_store_coherence(_Redis(), _local(tmp_path), tmp_path / "jobs", require_shared=True)


def test_a_single_node_sqlite_deployment_never_even_warns(tmp_path, caplog):
    import logging
    from blastbox.host.canary import check_store_coherence
    with caplog.at_level(logging.WARNING, logger="blastbox.canary"):
        check_store_coherence(_Sqlite(), _local(tmp_path), tmp_path / "jobs", require_shared=True)
    assert not [r for r in caplog.records if "local_blob_store" in r.message]


def test_an_unrecognised_job_store_never_triggers_the_failure(tmp_path):
    """Conservative on purpose: a store we cannot classify must not stop a valid deployment."""
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(object(), _local(tmp_path), tmp_path / "jobs", require_shared=True)


def test_a_shared_queue_with_a_remote_store_passes(tmp_path):
    from blastbox.host.canary import check_store_coherence
    check_store_coherence(_Postgres(), _FakeS3(), tmp_path / "jobs")


def test_the_dispatcher_gate_refuses_the_incoherent_pair(tmp_path):
    """It must fire through self_test, not just standalone -- and BEFORE the round-trip, which
    would otherwise pass and let the dispatcher serve."""
    d = _make(_local(tmp_path), _Postgres(), tmp_path / "jobs")
    d._require_shared_blob_store = True
    with pytest.raises(CanaryFailure) as ei:
        d.self_test(gate=True)
    assert "SHARED queue" in str(ei.value)


class _WriteRaisesAfterLanding(LocalBlobStore):
    """An S3-compatible store that commits the object and then loses the response.

    The write SUCCEEDED; only the acknowledgement did not arrive. Every other failure path cleans
    up, and this one skipping it meant a crash-looping dispatcher -- which is what a fail-closed
    gate produces -- orphaned one canary object per restart, forever, since each attempt uses a
    fresh random id.
    """

    def put_output(self, job_id, out_dir):
        super().put_output(job_id, out_dir)
        raise OSError("Read timeout on endpoint URL")


def test_an_ambiguous_write_failure_still_cleans_up(tmp_path):
    store = _WriteRaisesAfterLanding(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    with pytest.raises(CanaryFailure):
        blob_roundtrip(store)
    leftovers = [p for p in (tmp_path / "blobs").rglob("*") if p.is_file()]
    assert leftovers == [], f"orphaned canary objects: {leftovers}"


@pytest.mark.parametrize("raw,expected", [
    ("60", 60.0), ("900", 900.0), ("0", 0.0),
    # float() accepts both; nan makes every `elapsed >= interval` False and inf makes it never
    # True, so either silently switches the periodic pass OFF -- the same fail-open shape as an
    # affirmative boolean allowlist.
    ("nan", 900.0), ("inf", 900.0), ("-inf", 900.0), ("banana", 900.0),
])
def test_a_malformed_interval_never_silently_disables_the_periodic_pass(raw, expected,
                                                                       monkeypatch):
    from blastbox.host.cli import _canary_settings
    monkeypatch.setenv("BLASTBOX_CANARY_INTERVAL_S", raw)
    _, interval = _canary_settings()
    assert interval == expected


# --- round 4: leftovers, scratch, and two more fail-open knobs --------------------------------
class _NoDelete(LocalBlobStore):
    """PUT and GET allowed, DELETE denied — a perfectly ordinary IAM policy."""

    def delete_job(self, job_id):
        raise OSError("AccessDenied")


def test_an_undeletable_store_leaves_ONE_object_not_one_per_probe(tmp_path):
    """A random id per probe grew without bound under this policy.

    The probe correctly still SUCCEEDS -- being unable to tidy up does not stop a store serving
    jobs -- so with the periodic pass on by default it left one permanent object per interval per
    dispatcher, forever. A stable key bounds it at one.
    """
    store = _NoDelete(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    for _ in range(8):
        assert "OK" in blob_roundtrip(store, key_hint="fc")
    left = {p.relative_to(tmp_path / "blobs").parts[1]
            for p in (tmp_path / "blobs").rglob("*") if p.is_file()}
    assert len(left) == 1, f"expected one leftover key, got {len(left)}: {left}"


def test_different_dispatchers_on_one_host_do_not_share_a_key():
    from blastbox.host.canary import canary_job_id
    assert canary_job_id("firecracker") != canary_job_id("gvisor")
    assert canary_job_id("fc") == canary_job_id("fc"), "must be stable across restarts"


def test_the_probe_uses_the_dispatchers_scratch_not_the_system_tmp(tmp_path, monkeypatch):
    """A hardened dispatcher with a writable job_root and a reachable store but a read-only /tmp
    was rejected by the default-on gate — failing it for a prerequisite real dispatch never had."""
    import tempfile
    # Make the DEFAULT temp location unusable, not mkdtemp itself: `TemporaryDirectory(dir=...)`
    # goes through mkdtemp too, so patching that would break the very path being tested.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "no-such-tmp"))
    scratch = tmp_path / "scratch"
    store = _local(tmp_path)
    with pytest.raises(FileNotFoundError):
        blob_roundtrip(store)                       # would stage in the broken system temp dir
    assert "OK" in blob_roundtrip(store, scratch_dir=scratch)
    assert scratch.exists()


@pytest.mark.parametrize("raw,expected", [
    ("-1", 900.0), ("-0.5", 900.0),   # finite, passes isfinite, then `> 0` silently disables
    ("0", 0.0), ("5", 5.0),
])
def test_a_negative_interval_does_not_silently_disable_the_periodic_pass(raw, expected,
                                                                        monkeypatch):
    from blastbox.host.cli import _canary_settings
    monkeypatch.setenv("BLASTBOX_CANARY_INTERVAL_S", raw)
    assert _canary_settings()[1] == expected


def test_a_typo_in_the_shared_store_declaration_is_reported(monkeypatch, caplog):
    """This repeats, in the variable added to FIX the fail-open boolean, the same shape: a typo
    returning the default silently. It is a deliberate declaration, so say so."""
    import logging
    from blastbox.host.cli import _require_shared_blob_store
    monkeypatch.setenv("BLASTBOX_REQUIRE_SHARED_BLOB_STORE", "treu")
    with caplog.at_level(logging.WARNING, logger="blastbox.host.cli"):
        assert _require_shared_blob_store() is False
    assert any("not a recognised boolean" in r.message for r in caplog.records)


@pytest.mark.parametrize("raw,expected", [("1", True), ("true", True), ("on", True),
                                          ("0", False), ("off", False), ("", False)])
def test_the_shared_store_declaration_parses_the_documented_values(raw, expected, monkeypatch):
    from blastbox.host.cli import _require_shared_blob_store
    monkeypatch.setenv("BLASTBOX_REQUIRE_SHARED_BLOB_STORE", raw)
    assert _require_shared_blob_store() is expected
