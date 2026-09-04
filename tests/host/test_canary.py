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


def test_an_unusable_configured_job_root_fails_the_gate(tmp_path):
    """The inverse trap of the one above: falling back to the system temp dir when an explicit
    root is unusable let the probe PASS while real dispatch would fail later creating its
    input/output dirs under that same root. An unusable job_root must fail the gate."""
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("a file where the job root should be")
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_local(tmp_path), scratch_dir=blocked / "jobs")
    msg = str(ei.value)
    assert "job root is unusable" in msg and "BLASTBOX_JOB_ROOT" in msg


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


# --- round 5: the shared-key race, and a cadence blocked by long jobs -------------------------
class _VanishesOnce(LocalBlobStore):
    """Simulates a CONCURRENT canary's cleanup landing between our has_output and open_output.

    The first probe's read-back misses; a second probe (unique key) is fine. That is exactly what
    a co-located dispatcher sharing the key does, and treating it as a store failure would refuse
    a boot against a perfectly healthy store.
    """

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.misses = 0

    def open_output(self, job_id, name):
        if self.misses == 0:
            self.misses += 1
            raise FileNotFoundError("deleted by a concurrent canary")
        return super().open_output(job_id, name)


def test_a_concurrent_canary_cleanup_does_not_fail_a_boot(tmp_path):
    """The earlier reasoning -- "a shared key is harmless, the payload is identical" -- was wrong
    about which operation collides. It is the DELETE, and it lands right here."""
    store = _VanishesOnce(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    assert "OK" in blob_roundtrip(store, key_hint="cold")
    assert store.misses == 1, "the racey path must actually have been exercised"


class _AlwaysUnreadable(LocalBlobStore):
    def open_output(self, job_id, name):
        raise FileNotFoundError("genuinely gone")


def test_a_genuinely_unreadable_store_still_fails_after_the_retry(tmp_path):
    """The retry must not become a way for a broken store to escape as an internal exception."""
    store = _AlwaysUnreadable(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(store, key_hint="cold")
    assert "READ-BACK failed" in str(ei.value)


def test_the_serial_periodic_canary_is_not_blocked_by_a_long_job(tmp_path, monkeypatch):
    """dispatch_once() is synchronous, so an inline check only ran BETWEEN jobs: one detonation
    up to the worker timeout delayed the interval for the whole job, every job."""
    import threading
    import time as _time
    from blastbox.host.dispatch import Dispatcher

    ticks = []
    released = threading.Event()

    d = _make(_local(tmp_path), _Sqlite(), tmp_path / "jobs")
    d.self_test = lambda gate: ticks.append(_time.monotonic())
    d._run_forever_serial = lambda *a, **k: released.wait(3.0)   # a job that blocks for "ages"

    t = threading.Thread(
        target=lambda: Dispatcher.run_forever(
            d, poll_interval_s=0.01, maintenance_interval_s=0,
            canary=True, canary_interval_s=0.15),
        daemon=True)
    t.start()
    _time.sleep(1.0)
    released.set()
    t.join(timeout=5)
    # Inline, zero ticks would have fired while the "job" ran.
    assert len(ticks) >= 3, f"canary ran {len(ticks)} times while a job was in flight"


def test_co_located_dispatchers_get_distinct_keys():
    """Host+tier alone collides for two engine-scoped dispatchers on one box. A collision only
    costs a retry now, but avoiding it is free."""
    from blastbox.host.canary import canary_job_id
    a = canary_job_id("cold|redtusk|/var/lib/redtusk/jobs")
    b = canary_job_id("cold|clippyshot|/var/lib/clippyshot/jobs")
    c = canary_job_id("cold|redtusk|/var/lib/redtusk/jobs")
    assert a != b
    assert a == c, "must stay stable across restarts"


# --- round 7: credential disclosure, and a loop gated on the wrong timer ----------------------
class _S3WithSecretEndpoint(_FakeS3):
    class _Client:
        class meta:  # noqa: N801
            endpoint_url = "https://AKIAEXAMPLE:s3cr3t-p4ssw0rd@minio.internal:9000/?token=abc123"

    def __init__(self):
        super().__init__()
        self._s3 = self._Client()


def test_the_startup_line_never_carries_credentials():
    """`client.meta.endpoint_url` echoes whatever was configured, and this line is logged
    unconditionally by both the ingress and every dispatcher — so an endpoint carrying URI
    user-info or a query token would be copied into every sink collecting boot output."""
    d = describe_blob_store(_S3WithSecretEndpoint())
    for secret in ("s3cr3t-p4ssw0rd", "AKIAEXAMPLE", "abc123", "token="):
        assert secret not in d, f"{secret!r} leaked into {d!r}"
    # still useful: you can tell WHICH endpoint it is
    assert "minio.internal:9000" in d and "blastbox/pr83run" in d
    assert "***@" in d, "the presence of embedded credentials should still be visible"


@pytest.mark.parametrize("url,expect_in,expect_out", [
    ("http://host:9000", "host:9000", "@"),
    ("http://u:p@host:9000", "***@host:9000", "p@host"),
    ("https://host/path?token=zzz", "host/path", "zzz"),
    ("", "", "x"),
])
def test_endpoint_redaction_keeps_identity_and_drops_secrets(url, expect_in, expect_out):
    from blastbox.host.canary import _safe_endpoint
    got = _safe_endpoint(url)
    assert expect_in in got
    assert expect_out not in got or expect_out == "x" and not got


def test_the_network_canary_ticks_with_maintenance_disabled():
    """The constructor explicitly supports maintenance_interval_s <= 0. The loop previously
    divided its wait on that interval and only ran maintenance, so such a deployment got no
    periodic canary at all — however it was configured."""
    import threading
    import time as _time
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    class _Stub:
        _maintenance_interval_s = 0.0          # maintenance OFF
        _canary_interval_s = 0.05              # canary ON
        def __init__(self):
            self._stop = threading.Event()
            self.ticks = 0
            self._canary_cb = self._tick
        def _tick(self):
            self.ticks += 1
        def _run_maintenance(self):
            raise AssertionError("maintenance is disabled and must not run")

    st = _Stub()
    t = threading.Thread(target=VmJobDispatcher._maintenance_loop.__get__(st, _Stub), daemon=True)
    t.start()
    _time.sleep(0.5)
    st._stop.set()
    t.join(timeout=3)
    assert st.ticks >= 3, f"canary ticked {st.ticks} times with maintenance disabled"


def test_the_network_loop_is_submitted_when_only_the_canary_is_enabled():
    import inspect
    from blastbox.host.runtime import vm_dispatch
    src = inspect.getsource(vm_dispatch.VmJobDispatcher.run)
    assert "_canary_cb is not None and self._canary_interval_s > 0" in src, (
        "run() must submit the loop when the canary alone is enabled")


def test_the_network_loop_sleeps_to_the_canary_deadline_not_the_floor():
    """With maintenance disabled its deadline is permanently in the past, so including it in the
    wait computation pins every iteration to the 0.05s floor: the loop busy-spins for the whole
    interval instead of sleeping to the next canary. Ticking is unaffected, which is exactly why
    this needs its own test."""
    import threading
    import time as _time
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    class _CountingEvent(threading.Event):
        waits = 0
        def wait(self, timeout=None):
            type(self).waits += 1
            return super().wait(timeout)

    class _Stub:
        _maintenance_interval_s = 0.0        # OFF -> its deadline is always overdue
        _canary_interval_s = 5.0             # far away
        def __init__(self):
            self._stop = _CountingEvent()
            self._canary_cb = lambda: None
        def _run_maintenance(self):
            raise AssertionError("maintenance is disabled")

    _CountingEvent.waits = 0
    st = _Stub()
    t = threading.Thread(target=VmJobDispatcher._maintenance_loop.__get__(st, _Stub), daemon=True)
    t.start()
    _time.sleep(0.6)
    st._stop.set()
    t.join(timeout=3)
    # Sleeping to the canary deadline: one wait. Spinning at the floor: ~12 in 0.6s.
    assert _CountingEvent.waits <= 3, f"loop spun {_CountingEvent.waits} times instead of sleeping"


# --- round 8: the secret one layer down, ordering, and a log behind a toggle ------------------
class _EndpointEchoingStore(LocalBlobStore):
    """Botocore quotes the URL it tried. That URL is ours, credentials and all."""

    def put_output(self, job_id, out_dir):
        raise OSError('Could not connect to the endpoint URL: '
                      '"https://AKIAKEY:sup3r-s3cret@minio.internal:9000/b/k?token=zzz"')


def test_a_stores_exception_cannot_leak_the_endpoint_credentials(tmp_path):
    """Redacting describe_blob_store() was not enough: the CAUSE carries the same URL, and it
    reaches both the message and (through chaining) every startup traceback."""
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_EndpointEchoingStore(tmp_path / "jobs", blob_root=tmp_path / "blobs"))
    msg = str(ei.value)
    for secret in ("sup3r-s3cret", "AKIAKEY", "token=zzz"):
        assert secret not in msg, f"{secret!r} leaked into the CanaryFailure message"
    assert "minio.internal:9000" in msg, "the endpoint identity must survive redaction"
    assert ei.value.__cause__ is None, "the raw exception must not be chained into tracebacks"


@pytest.mark.parametrize("text,gone,kept", [
    ('connect to "https://u:p@h:9000/x?t=1"', "p@h", "h:9000"),
    ("no urls here at all", "://", "no urls here"),
    ('two: http://a:b@h1/ and https://c:d@h2/?k=v', "b@h1", "h1"),
])
def test_redaction_scrubs_every_url_in_a_message(text, gone, kept):
    from blastbox.host.canary import redact_secrets
    got = redact_secrets(text)
    assert gone not in got
    assert kept in got


def test_the_blob_target_is_logged_even_with_the_canary_disabled(tmp_path, caplog):
    """BLASTBOX_CANARY=0 skipped self_test entirely — and with it the ONLY line naming the
    backend, bucket, prefix and endpoint. The ingress logs its read target regardless, so the
    side-by-side comparison broke precisely in the deployments that opted out."""
    import logging
    import threading
    from blastbox.host.dispatch import Dispatcher

    d = _make(_local(tmp_path), _Sqlite(), tmp_path / "jobs")
    d._run_forever_serial = lambda *a, **k: None
    d.self_test = lambda gate: pytest.fail("self_test must not run when canary=False")
    with caplog.at_level(logging.INFO, logger="blastbox.host.dispatch"):
        Dispatcher.run_forever(d, poll_interval_s=0.01, maintenance_interval_s=0, canary=False)
    assert any("canary.blob_store" in r.message for r in caplog.records), \
        "the blob target must be logged regardless of the toggle"
    _ = threading


def test_a_slow_maintenance_sweep_cannot_delay_the_canary():
    """Both run on one coordinator thread. _run_maintenance can retry thousands of pending uploads
    through the very store that is down, so with maintenance first an object-store outage could
    postpone by minutes the check whose whole job is reporting that outage."""
    import threading
    import time as _time
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    order = []

    class _Stub:
        _maintenance_interval_s = 0.05
        _canary_interval_s = 0.05
        def __init__(self):
            self._stop = threading.Event()
            self._canary_cb = lambda: order.append("canary")
        def _run_maintenance(self):
            order.append("maintenance")
            _time.sleep(0.4)          # a sweep stuck retrying uploads through a dead store

    st = _Stub()
    t = threading.Thread(target=VmJobDispatcher._maintenance_loop.__get__(st, _Stub), daemon=True)
    t.start()
    _time.sleep(0.35)
    st._stop.set()
    t.join(timeout=3)
    assert order and order[0] == "canary", f"maintenance ran first and blocked the canary: {order}"


# --- round 9: a stale object standing in for this probe's write -------------------------------
class _WriteNoOpsAfterFirst(LocalBlobStore):
    """Accepts later writes and does nothing — the accepted-but-not-landed shape.

    With a stable key and a CONSTANT payload this was undetectable: has_output finds the object
    the FIRST probe left behind, its bytes match the constant, and the probe reports success
    without ever proving the current write worked.
    """

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.writes = 0

    def put_output(self, job_id, out_dir):
        self.writes += 1
        if self.writes == 1:
            super().put_output(job_id, out_dir)     # first one lands
        # later ones silently do nothing

    def delete_job(self, job_id):
        raise OSError("AccessDenied")               # so the first object stays behind


def test_a_stale_object_cannot_stand_in_for_this_probes_write(tmp_path):
    store = _WriteNoOpsAfterFirst(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    assert "OK" in blob_roundtrip(store, key_hint="fc")        # first probe genuinely lands
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(store, key_hint="fc")                   # second must NOT pass on the stale one
    assert "different bytes" in str(ei.value) or "did not exist" in str(ei.value)


def test_each_probe_carries_a_distinct_nonce():
    from blastbox.host.canary import _seal_bytes
    assert _seal_bytes("a") != _seal_bytes("b")
    import json
    assert json.loads(_seal_bytes("a"))["nonce"] == "a"


def test_cleanup_failures_are_redacted_too(tmp_path, caplog):
    """A separate exception path from the CanaryFailure cause, reached after every successful
    probe — and botocore echoes the URL it was handed."""
    import logging

    class _LeakyDelete(LocalBlobStore):
        def delete_job(self, job_id):
            raise OSError('failed: "https://AK:s3cr3t@minio.internal:9000/b?token=zz"')

    store = _LeakyDelete(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    with caplog.at_level(logging.WARNING, logger="blastbox.canary"):
        assert "OK" in blob_roundtrip(store)
    logged = " ".join(r.getMessage() for r in caplog.records)
    for secret in ("s3cr3t", "token=zz"):
        assert secret not in logged, f"{secret!r} leaked into the cleanup warning"
    assert "minio.internal:9000" in logged


class _ForeignBytesOnce(LocalBlobStore):
    """First read-back returns ANOTHER probe's payload — a co-located dispatcher sharing the key
    overwrote ours between our put and our read. Distinct from the vanishing-object race: the
    object is present, the bytes are simply not the ones we wrote."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.swapped = 0

    def open_output(self, job_id, name):
        if self.swapped == 0:
            self.swapped += 1
            import io
            from blastbox.host.canary import _seal_bytes
            return io.BytesIO(_seal_bytes("a-different-process"))
        return super().open_output(job_id, name)


def test_another_probes_bytes_on_a_shared_key_retries_rather_than_failing_a_boot(tmp_path):
    """Adding the per-probe nonce reintroduced a way for a key collision to fail a boot: the
    comparison now legitimately mismatches when another process overwrote our object. It has to
    be treated as a race and retried, exactly like the vanishing-object case."""
    store = _ForeignBytesOnce(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    assert "OK" in blob_roundtrip(store, key_hint="fc")
    assert store.swapped == 1, "the mismatch path must actually have been exercised"


class _AlwaysForeignBytes(LocalBlobStore):
    def open_output(self, job_id, name):
        import io
        from blastbox.host.canary import _seal_bytes
        return io.BytesIO(_seal_bytes("never-ours"))


def test_a_store_that_always_returns_wrong_bytes_still_fails(tmp_path):
    """The retry must not become an escape hatch for a store that genuinely corrupts."""
    with pytest.raises(CanaryFailure) as ei:
        blob_roundtrip(_AlwaysForeignBytes(tmp_path / "jobs", blob_root=tmp_path / "blobs"),
                       key_hint="fc")
    assert "different bytes" in str(ei.value)


class _FakeVersionedS3:
    """An S3-shaped store on a bucket with versioning ENABLED.

    Records what the purge asks for, and models the behaviour that makes the bug invisible without
    it: delete_job removes only the CURRENT key and leaves every prior version in place.
    """

    def __init__(self, *, allow_versions: bool = True) -> None:
        self._bucket = "blastbox"
        self._prefix = ""
        self._s3 = self
        self.versions: list[tuple[str, str]] = []      # (key, version_id) still stored
        self.deleted: list[dict] = []
        self.allow_versions = allow_versions
        self._n = 0

    # -- the bits canary.py introspects -------------------------------------------------
    def _key(self, *parts: str) -> str:
        return "/".join(parts)

    def put_output(self, job_id, out_dir) -> None:  # noqa: ANN001
        self._n += 1
        self.versions.append((self._key("results", job_id) + "/metadata.json", f"v{self._n}"))

    def delete_job(self, job_id) -> None:  # noqa: ANN001
        # A versioned bucket: this adds a delete MARKER; prior versions survive.
        self._n += 1
        self.versions.append((self._key("results", job_id) + "/metadata.json", f"dm{self._n}"))

    # -- the paginator surface ----------------------------------------------------------
    def get_paginator(self, op):  # noqa: ANN001, ANN201
        assert op == "list_object_versions"
        if not self.allow_versions:
            raise RuntimeError("AccessDenied: s3:ListBucketVersions")
        store = self

        class _P:
            def paginate(self, **kw):  # noqa: ANN003, ANN201
                pre = kw["Prefix"]
                yield {"Versions": [{"Key": k, "VersionId": v}
                                    for k, v in store.versions
                                    if k.startswith(pre) and not v.startswith("dm")],
                       "DeleteMarkers": [{"Key": k, "VersionId": v}
                                         for k, v in store.versions
                                         if k.startswith(pre) and v.startswith("dm")]}
        return _P()

    def delete_objects(self, Bucket, Delete):  # noqa: ANN001, ANN201, N803
        if not self.allow_versions:
            raise RuntimeError("AccessDenied: s3:DeleteObjectVersion")
        self.deleted.extend(Delete["Objects"])
        gone = {(o["Key"], o["VersionId"]) for o in Delete["Objects"]}
        self.versions = [kv for kv in self.versions if kv not in gone]
        return {}


def test_the_canary_does_not_accrete_versions_on_a_versioned_bucket():
    """A stable key bounds LIVE objects to one; it does not bound STORAGE.

    On a versioned bucket every periodic put_output writes a new version, and delete_job lists only
    current keys and calls delete_objects without a VersionId -- which adds a delete marker rather
    than removing anything. So each interval left one noncurrent version plus one marker, per
    dispatcher, forever: the probe whose job is proving the store is healthy quietly accreting
    metadata inside it.

    MUTATION: drop the _purge_versions call from _cleanup -> the version count grows per probe.
    """
    from blastbox.host.canary import _cleanup

    store = _FakeVersionedS3()
    for _ in range(5):                       # five periodic probes
        store.put_output("canary-job", None)
        _cleanup(store, "canary-job")

    assert store.versions == [], (
        f"{len(store.versions)} object versions survived five probes ({store.versions}); on a "
        f"versioned bucket that grows unbounded, one noncurrent version plus one delete marker "
        f"per interval per dispatcher")
    assert store.deleted, "the purge never asked for any version to be deleted"
    assert all("VersionId" in d for d in store.deleted), (
        "delete_objects was called without VersionId, which adds another delete marker instead of "
        "removing a version")


def test_denied_version_permissions_do_not_report_a_failed_cleanup(caplog):
    """`s3:ListBucketVersions` / `s3:DeleteObjectVersion` are not implied by the canary's write access.

    A deployment that withholds them is expected, and the documented remedy there is a lifecycle
    rule on noncurrent versions. What must NOT happen is the operator being told cleanup failed:
    `delete_job` succeeded, the live object IS gone, and only the version housekeeping was refused.

    "It must not raise" is too weak a claim to test -- `_cleanup`'s own `except Exception` already
    guarantees that, so a purge with no handler at all passes it (verified: that mutant survived).
    The observable difference is the MESSAGE: without the inner handler the refusal surfaces as
    "leftover object left in the store", which is false and sends the operator looking for an
    object that is not there.

    MUTATION: remove the except in _purge_versions -> the misleading warning is emitted.
    """
    import logging

    from blastbox.host.canary import _cleanup

    store = _FakeVersionedS3(allow_versions=False)
    store.put_output("canary-job", None)
    with caplog.at_level(logging.DEBUG, logger="blastbox.host.canary"):
        _cleanup(store, "canary-job")        # must not raise

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert not any("leftover object left in the store" in m for m in warnings), (
        f"a denied VERSION permission was reported as a failed object cleanup: {warnings}; the "
        f"object was deleted, and the operator is sent looking for something that is not there")


class _PaginatingVersionedS3(_FakeVersionedS3):
    """Models S3's continuation-token paging, which is what makes deleting mid-scan lossy.

    A page is sliced from the CURRENT contents at the moment it is requested, exactly
    like a continuation token resolving against live bucket state. Delete a full page
    and the next slice starts past what remains, so the tail is never visited.
    """

    PAGE = 1000

    def get_paginator(self, op):  # noqa: ANN001, ANN201
        assert op == "list_object_versions"
        store = self

        class _P:
            def paginate(self, **kw):  # noqa: ANN003, ANN201
                pre = kw["Prefix"]
                offset = 0
                while True:
                    live = [(k, v) for k, v in store.versions if k.startswith(pre)]
                    chunk = live[offset : offset + _PaginatingVersionedS3.PAGE]
                    if not chunk:
                        return
                    yield {
                        "Versions": [
                            {"Key": k, "VersionId": v}
                            for k, v in chunk
                            if not v.startswith("dm")
                        ],
                        "DeleteMarkers": [
                            {"Key": k, "VersionId": v}
                            for k, v in chunk
                            if v.startswith("dm")
                        ],
                    }
                    offset += _PaginatingVersionedS3.PAGE

        return _P()


def test_the_version_purge_clears_more_than_one_page(tmp_path):
    """The canary key gains a version every probe, so it outgrows one page in days.

    At the 900s default that is ~96 versions/day per dispatcher: past 1000 the purge
    has to keep working. MUTATION: delete inside the pagination loop instead of after
    it -> the tail past the first page is skipped and this fails.
    """
    from blastbox.host.canary import _purge_versions

    store = _PaginatingVersionedS3()
    for _ in range(2500):
        store.put_output("canary-job", tmp_path)
    assert len(store.versions) == 2500

    _purge_versions(store, "canary-job")

    assert store.versions == [], (
        f"{len(store.versions)} version(s) survived the purge — everything past the "
        "first page was skipped"
    )


def test_the_version_purge_ignores_a_store_that_is_not_s3_shaped(tmp_path):
    """LocalBlobStore has no _s3/_bucket, and must not be probed for versions at all."""
    from blastbox.host.canary import _cleanup

    store = LocalBlobStore(str(tmp_path))
    _cleanup(store, "canary-job")            # must not raise


def test_required_shared_storage_is_enforced_even_with_the_canary_disabled(tmp_path):
    """`BLASTBOX_REQUIRE_SHARED_BLOB_STORE` is a hard requirement, not part of the probe.

    `BLASTBOX_CANARY` turns off the write/read round-trip. Coupling the topology check to that
    toggle meant `CANARY=0` silently dropped the requirement too -- so a Postgres/Redis dispatcher
    on a private LocalBlobStore started happily and produced DONE jobs whose results no other
    machine can read. That is the single worst deployment bug this fleet has had, re-enabled by an
    unrelated opt-out, and it contradicts the guide's "startup fails closed" promise.

    Driven through `run_forever(canary=False)` rather than `self_test()`, because `self_test` is
    exactly the thing the toggle skips -- a test that calls it directly cannot see this bug.

    MUTATION: move check_store_coherence back inside `if canary:` -> the dispatcher starts.
    """
    from blastbox.host.dispatch import Dispatcher, EngineSpec
    from blastbox.limits import Limits

    d = Dispatcher(
        job_store=_Postgres(),                      # SHARED queue...
        engines={"e": EngineSpec(name="e", image="img:t", worker_argv=[])},
        limits=Limits.from_env(),
        job_root=tmp_path,
    )
    d._blobs = _local(tmp_path)                     # ...PRIVATE store: the incoherent pair
    d._require_shared_blob_store = True

    claimed: list[int] = []
    d.dispatch_once = lambda: claimed.append(1) or False  # type: ignore[method-assign]

    with pytest.raises(CanaryFailure) as ei:
        d.run_forever(poll_interval_s=0.001, maintenance_interval_s=0,
                      stop=lambda: True, canary=False)
    assert "SHARED queue" in str(ei.value)
    assert claimed == [], "the dispatcher claimed work before the topology gate refused it"


def test_the_coherent_case_still_starts_with_the_canary_disabled(tmp_path):
    """Enforcement must fail CLOSED on the incoherent pair, not fail ALWAYS.

    A shared queue with a shared store, canary off, must still start -- otherwise this guard just
    breaks every opt-out deployment instead of the misconfigured ones.
    """
    from blastbox.host.dispatch import Dispatcher, EngineSpec
    from blastbox.limits import Limits

    d = Dispatcher(
        job_store=_Postgres(),
        engines={"e": EngineSpec(name="e", image="img:t", worker_argv=[])},
        limits=Limits.from_env(),
        job_root=tmp_path,
    )
    d._blobs = _FakeS3()                            # shared queue + shared store: coherent
    d._require_shared_blob_store = True
    d.run_forever(poll_interval_s=0.001, maintenance_interval_s=0,
                  stop=lambda: True, canary=False)  # must not raise
