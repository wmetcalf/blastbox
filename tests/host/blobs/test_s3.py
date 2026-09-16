"""S3BlobStore against an in-process S3 (moto)."""
import hashlib

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from blastbox.host.blobs.base import BlobFetchError, BlobIntegrityError
from blastbox.host.blobs.s3 import S3BlobStore

BUCKET = "bb-test"


@pytest.fixture
def store(tmp_path):
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        yield S3BlobStore(f"s3://{BUCKET}/pfx", job_root=tmp_path, env={})


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def test_put_then_get_roundtrips_bytes(store, tmp_path):
    data = b"malicious.doc contents"
    digest = hashlib.sha256(data).hexdigest()
    store.put_sample(digest, _write(tmp_path, "in/orig.doc", data))

    dest = tmp_path / "job2" / "input" / "different-name.doc"
    store.get_sample(digest, dest)
    assert dest.read_bytes() == data


def test_get_sample_verifies_the_hash(store, tmp_path):
    """A substituted object must be caught before it reaches an engine."""
    data = b"real"
    digest = hashlib.sha256(data).hexdigest()
    store.put_sample(digest, _write(tmp_path, "in/a.doc", data))
    # corrupt the stored object behind the store's back
    boto3.client("s3", region_name="us-east-1").put_object(
        Bucket=BUCKET, Key=f"pfx/samples/{digest}", Body=b"tampered"
    )
    with pytest.raises(BlobIntegrityError):
        store.get_sample(digest, tmp_path / "job3" / "input" / "a.doc")


def test_missing_object_raises_fetch_error(store, tmp_path):
    with pytest.raises(BlobFetchError):
        store.get_sample("b" * 64, tmp_path / "job4" / "input" / "a.doc")


def test_put_sample_is_idempotent_and_dedupes(store, tmp_path):
    """Same bytes under two different filenames -> ONE object."""
    data = b"same bytes"
    digest = hashlib.sha256(data).hexdigest()
    store.put_sample(digest, _write(tmp_path, "in/invoice.doc", data))
    store.put_sample(digest, _write(tmp_path, "in/PO_08312020.xls", data))
    listing = boto3.client("s3", region_name="us-east-1").list_objects_v2(
        Bucket=BUCKET, Prefix="pfx/samples/"
    )
    assert listing["KeyCount"] == 1


def test_put_output_compresses_by_default(store, tmp_path):
    out = tmp_path / "j9" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"a":1}' * 500)
    store.put_output("j9", out)
    with store.open_output("j9", "metadata.json") as fh:
        assert fh.read() == b'{"a":1}' * 500        # transparent on read


def test_put_output_skips_a_symlink_to_a_file_outside_the_output_dir(store, tmp_path):
    """Security regression (mirrors the LocalBlobStore test): a compromised worker
    can plant e.g. output/metadata.json -> /etc/passwd before put_output runs.
    rglob("*") + is_file() FOLLOWS a symlink and would previously read + upload the
    TARGET's bytes, later served as trusted job output. put_output must skip a
    symlinked entry (never store/serve it) while still uploading legitimate
    sibling files."""
    out = tmp_path / "j10" / "output"
    out.mkdir(parents=True)
    (out / "legit.txt").write_bytes(b"legit-bytes")

    secret = tmp_path / "outside_secret.txt"
    secret.write_bytes(b"TOP-SECRET-OUTSIDE-BYTES")
    (out / "metadata.json").symlink_to(secret)

    store.put_output("j10", out)

    with pytest.raises(BlobFetchError):
        store.open_output("j10", "metadata.json")
    s3 = boto3.client("s3", region_name="us-east-1")
    assert s3.list_objects_v2(
        Bucket=BUCKET, Prefix="pfx/results/j10/metadata.json"
    )["KeyCount"] == 0

    with store.open_output("j10", "legit.txt") as fh:
        assert fh.read() == b"legit-bytes"


def test_open_output_reads_a_nested_artifact_path(store, tmp_path):
    """put_output writes a nested key (results/<id>/foo/bar.png via rel.as_posix()); open_output must
    read the SAME key rather than collapsing to the basename."""
    out = tmp_path / "j11" / "output"
    (out / "foo").mkdir(parents=True)
    (out / "foo" / "bar.png").write_bytes(b"PNGDATA")
    store.put_output("j11", out)
    with store.open_output("j11", "foo/bar.png") as fh:
        assert fh.read() == b"PNGDATA"


@pytest.mark.parametrize("evil", ["../secret", "/etc/passwd", "a/../../b"])
def test_open_output_refuses_traversal_and_absolute_names(store, evil):
    """open_output must normalise + reject a traversal/absolute name on its OWN before building a
    key, so it can never read outside this job's results prefix."""
    with pytest.raises(BlobFetchError):
        store.open_output("j11", evil)


def test_delete_job_removes_outputs_but_not_samples(store, tmp_path):
    data = b"shared sample"
    digest = hashlib.sha256(data).hexdigest()
    store.put_sample(digest, _write(tmp_path, "in/x.doc", data))
    out = tmp_path / "j5" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j5", out)

    store.delete_job("j5")

    s3 = boto3.client("s3", region_name="us-east-1")
    assert s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/results/j5/")["KeyCount"] == 0
    assert s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/samples/")["KeyCount"] == 1


@pytest.fixture
def versioned_store(tmp_path):
    """A bucket with versioning ENABLED — the configuration issue #89 is about."""
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(
            Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )
        yield S3BlobStore(f"s3://{BUCKET}/pfx", job_root=tmp_path, env={})


def _surviving_versions(prefix):
    """Every version and delete marker still stored under ``prefix``.

    Paginates: list_object_versions caps a page at 1000 entries, so a single call
    silently under-reports exactly the >1000 case worth testing.
    """
    s3 = boto3.client("s3", region_name="us-east-1")
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(
        Bucket=BUCKET, Prefix=prefix
    ):
        versions.extend(page.get("Versions", []))
        markers.extend(page.get("DeleteMarkers", []))
    return versions, markers


def test_delete_job_really_removes_bytes_on_a_versioned_bucket(versioned_store, tmp_path):
    """A keyless delete on a versioned bucket is not a delete.

    ``list_objects_v2`` reports current versions only, and ``delete_objects``
    without a ``VersionId`` merely ADDS a delete marker — every prior version
    stays and keeps costing storage. Retention (``expire_due`` -> ``delete_job``)
    and the ingress DELETE route both promise the bytes are gone, so this must
    leave nothing behind.
    """
    out = tmp_path / "j8" / "output"
    out.mkdir(parents=True)
    # Overwrite the same key so the bucket holds several noncurrent versions,
    # which is what a re-run of a job produces.
    for body in (b"first", b"second", b"third"):
        (out / "metadata.json").write_bytes(body)
        versioned_store.put_output("j8", out)

    versions, _ = _surviving_versions("pfx/results/j8/")
    assert len(versions) == 3, "fixture should have produced three versions"

    versioned_store.delete_job("j8")

    versions, markers = _surviving_versions("pfx/results/j8/")
    assert versions == [], (
        f"{len(versions)} noncurrent version(s) survived delete_job — the bytes are "
        "still stored and billed, so retention never reclaims"
    )
    assert markers == [], (
        f"{len(markers)} delete marker(s) left behind — a delete marker is not a deletion"
    )


def test_delete_job_still_works_on_an_unversioned_bucket(store, tmp_path):
    """The versioned path must not regress the ordinary bucket."""
    out = tmp_path / "j9" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j9", out)

    store.delete_job("j9")

    s3 = boto3.client("s3", region_name="us-east-1")
    assert s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/results/j9/")["KeyCount"] == 0


@pytest.mark.parametrize(
    "status,expected",
    [("Enabled", True), ("Suspended", True), (None, False)],
)
def test_bucket_is_versioned_counts_suspended_as_versioned(tmp_path, status, expected):
    """Suspending stops NEW versions; every version made while enabled survives.

    Tested against the decision directly rather than end-to-end: moto deletes
    everything on a keyless delete against a Suspended bucket, where real S3
    writes a null-version delete marker and keeps the noncurrent versions. An
    end-to-end assertion would therefore pass no matter which branch was taken.
    """
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        if status is not None:
            s3.put_bucket_versioning(
                Bucket=BUCKET, VersioningConfiguration={"Status": status}
            )
        st = S3BlobStore(f"s3://{BUCKET}/pfx", job_root=tmp_path, env={})
        assert st._bucket_is_versioned() is expected


def test_delete_job_clears_the_residue_an_old_keyless_delete_left(versioned_store, tmp_path):
    """A job "deleted" by the previous implementation must actually clean up.

    The old code issued a keyless delete, which on a versioned bucket adds a
    delete marker and keeps every prior version. Those buckets exist in the
    field, so delete_job has to clear markers as well as versions.
    """
    out = tmp_path / "jr" / "output"
    out.mkdir(parents=True)
    for body in (b"one", b"two"):
        (out / "metadata.json").write_bytes(body)
        versioned_store.put_output("jr", out)

    # exactly what the pre-fix delete_job did
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.delete_objects(
        Bucket=BUCKET, Delete={"Objects": [{"Key": "pfx/results/jr/metadata.json"}]}
    )
    versions, markers = _surviving_versions("pfx/results/jr/")
    assert len(versions) == 2 and len(markers) == 1, "fixture must reproduce the residue"

    versioned_store.delete_job("jr")

    versions, markers = _surviving_versions("pfx/results/jr/")
    assert versions == [], f"{len(versions)} version(s) survived"
    assert markers == [], f"{len(markers)} delete marker(s) survived"


def test_delete_job_assumes_versioned_when_status_cannot_be_read(versioned_store, tmp_path):
    """Unable to read the status -> take the safe path, not the lossy one.

    Guessing "unversioned" would silently retain data an operator asked to delete.
    """
    from unittest.mock import patch

    import botocore.exceptions

    out = tmp_path / "jd" / "output"
    out.mkdir(parents=True)
    for body in (b"a", b"b"):
        (out / "metadata.json").write_bytes(body)
        versioned_store.put_output("jd", out)

    denied = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetBucketVersioning"
    )
    with patch.object(versioned_store._s3, "get_bucket_versioning", side_effect=denied):
        versioned_store.delete_job("jd")

    versions, markers = _surviving_versions("pfx/results/jd/")
    assert versions == [] and markers == []


def test_delete_job_batches_past_the_1000_key_api_limit(versioned_store, tmp_path):
    """DeleteObjects caps at 1000 keys; versions + markers can exceed one page."""
    out = tmp_path / "jb" / "output"
    out.mkdir(parents=True)
    for i in range(1100):
        (out / f"f{i}.json").write_bytes(b"x")
    versioned_store.put_output("jb", out)

    versions, _ = _surviving_versions("pfx/results/jb/")
    assert len(versions) > 1000, "fixture must exceed one DeleteObjects call"

    versioned_store.delete_job("jb")

    versions, markers = _surviving_versions("pfx/results/jb/")
    assert versions == [] and markers == []


def test_versioning_status_is_rechecked_after_the_ttl(versioned_store, tmp_path):
    """A store outlives a bucket's configuration.

    Caching the answer forever meant versioning enabled after the first delete kept
    taking the keyless path until the process restarted.
    """
    from blastbox.host.blobs import s3 as s3mod

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.put_bucket_versioning(
        Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"}
    )
    # Prime the cache while it reads as versioned (Suspended still counts).
    assert versioned_store._bucket_is_versioned() is True

    # A bucket cannot be un-versioned once enabled, so drive the recheck through
    # the API instead: a changed reply must be picked up once the TTL lapses.
    calls = []
    real = versioned_store._s3.get_bucket_versioning

    def counting(**kw):
        calls.append(1)
        return real(**kw)

    versioned_store._s3.get_bucket_versioning = counting
    versioned_store._bucket_is_versioned()
    assert calls == [], "inside the TTL the cached answer must be reused"

    versioned_store._versioned_at -= s3mod._VERSIONING_TTL_S + 1
    versioned_store._bucket_is_versioned()
    assert len(calls) == 1, "past the TTL the status must be re-read"


def test_an_unreadable_status_is_never_cached(versioned_store):
    """A transient failure must not pin the store into the versioned path.

    Cached, a single throttle or DNS blip would keep every later delete on the
    version-aware path (and failing, where the permissions are absent) until the
    process restarted.
    """
    from unittest.mock import patch

    import botocore.exceptions

    boom = botocore.exceptions.ClientError(
        {"Error": {"Code": "Throttling", "Message": "slow down"}}, "GetBucketVersioning"
    )
    with patch.object(versioned_store._s3, "get_bucket_versioning", side_effect=boom):
        assert versioned_store._bucket_is_versioned() is True
    assert versioned_store._versioned is None, "the failure must not have been cached"

    # Once the API recovers, the real answer is used.
    assert versioned_store._bucket_is_versioned() is True
    assert versioned_store._versioned is True


def test_noncurrent_versions_are_deleted_before_the_current_one(versioned_store, tmp_path):
    """Partial failure must not leave the object invisible but still stored.

    Deleting the current version first makes the key vanish from an ordinary
    listing while older bytes remain -- the state that looks deleted and is not.
    """
    out = tmp_path / "jo" / "output"
    out.mkdir(parents=True)
    for body in (b"v1", b"v2", b"v3"):
        (out / "metadata.json").write_bytes(body)
        versioned_store.put_output("jo", out)

    latest = {
        v["VersionId"]
        for v in _surviving_versions("pfx/results/jo/")[0]
        if v.get("IsLatest")
    }
    assert len(latest) == 1

    seen: list[str] = []
    real = versioned_store._s3.delete_objects

    def spy(Bucket, Delete):  # noqa: N803 — boto3's parameter names
        seen.extend(o["VersionId"] for o in Delete["Objects"])
        return real(Bucket=Bucket, Delete=Delete)

    versioned_store._s3.delete_objects = spy
    versioned_store.delete_job("jo")

    assert seen, "nothing was deleted"
    assert seen[-1] in latest, (
        "the current version must be deleted LAST; order was " + repr(seen)
    )


def test_delete_lists_one_page_at_a_time_rather_than_the_whole_history(
    versioned_store, tmp_path
):
    """Version history is the unbounded thing here; the working set must not be.

    Asserted through the request: a bounded MaxKeys is what keeps a pathological
    history from being materialised in one go.
    """
    out = tmp_path / "jp" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"x")
    versioned_store.put_output("jp", out)

    seen_maxkeys: list[int] = []
    real = versioned_store._s3.list_object_versions

    def spy(**kw):
        seen_maxkeys.append(kw.get("MaxKeys"))
        return real(**kw)

    versioned_store._s3.list_object_versions = spy
    versioned_store.delete_job("jp")

    assert seen_maxkeys, "the versioned path did not list"
    assert all(m is not None and m <= 1000 for m in seen_maxkeys), seen_maxkeys


def test_unversioned_bucket_without_versioning_permissions_still_deletes(store, tmp_path):
    """The regression this fix must not cause.

    An UNVERSIONED bucket whose policy grants neither GetBucketVersioning nor
    ListBucketVersions worked fine before version-aware deletes existed. The
    status read fails -> assume versioned -> list_object_versions ALSO fails, and
    a hard raise there would break a deployment that was previously fine. Fall
    back to the keyless delete, which is correct on an unversioned bucket.
    """
    from unittest.mock import patch

    import botocore.exceptions

    out = tmp_path / "jn" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("jn", out)

    denied = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "op"
    )
    with patch.object(store._s3, "get_bucket_versioning", side_effect=denied), \
         patch.object(store._s3, "list_object_versions", side_effect=denied):
        store.delete_job("jn")

    s3 = boto3.client("s3", region_name="us-east-1")
    assert s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/results/jn/")["KeyCount"] == 0


def test_a_confirmed_versioned_bucket_still_refuses_when_versions_cannot_be_listed(
    versioned_store, tmp_path
):
    """The fallback must NOT extend to a bucket we know is versioned.

    There, a keyless delete writes a marker over bytes we were asked to remove --
    a false reclaim, which is the whole defect. Refuse instead.
    """
    from unittest.mock import patch

    import botocore.exceptions

    out = tmp_path / "jv" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    versioned_store.put_output("jv", out)
    assert versioned_store._bucket_is_versioned() is True  # confirmed, not assumed

    denied = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListBucketVersions"
    )
    with patch.object(versioned_store._s3, "list_object_versions", side_effect=denied):
        with pytest.raises(botocore.exceptions.ClientError):
            versioned_store.delete_job("jv")


@pytest.mark.parametrize(
    "code,transient",
    [("Throttling", True), ("RequestTimeout", True), ("InternalError", True),
     ("AccessDenied", False), ("NotImplemented", False)],
)
def test_only_a_PERMANENT_denial_may_fall_back_to_a_keyless_delete(
    store, tmp_path, code, transient
):
    """A throttle says nothing about whether the bucket is versioned.

    Treating a transient failure as "unversioned" would issue a keyless delete on
    a bucket that may well be versioned, silently retaining every version — the
    exact defect this module exists to fix. Only a settled refusal (no permission,
    or an endpoint without the versioning APIs) justifies the fallback.
    """
    from unittest.mock import patch

    import botocore.exceptions

    out = tmp_path / f"jt{code}" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output(f"jt{code}", out)

    err = botocore.exceptions.ClientError({"Error": {"Code": code, "Message": "x"}}, "op")
    with patch.object(store._s3, "get_bucket_versioning", side_effect=err), \
         patch.object(store._s3, "list_object_versions", side_effect=err):
        if transient:
            with pytest.raises(botocore.exceptions.ClientError):
                store.delete_job(f"jt{code}")
        else:
            store.delete_job(f"jt{code}")  # falls back, must not raise


def test_put_sample_propagates_non_404_errors(store, tmp_path):
    """Non-404 errors in head_object (e.g., AccessDenied) must raise, not be swallowed."""
    from unittest.mock import patch
    import botocore.exceptions

    data = b"sample data"
    digest = hashlib.sha256(data).hexdigest()
    src = _write(tmp_path, "in/test.doc", data)

    # Simulate a permissions error on head_object
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
    client_error = botocore.exceptions.ClientError(error_response, "HeadObject")

    with patch.object(store._s3, "head_object", side_effect=client_error):
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            store.put_sample(digest, src)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


def test_delete_job_raises_when_delete_objects_reports_partial_errors(store, tmp_path):
    """Finding C4: delete_objects returns HTTP 200 even when some keys failed to delete --
    the failures are reported ONLY in response["Errors"], which delete_job must inspect
    and raise on, not ignore. Otherwise a partial delete looks like a full success to the
    retention sweeper's guard, which would then clear expires_at and orphan the undeleted
    object forever."""
    from unittest.mock import patch

    out = tmp_path / "j6" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j6", out)

    real_delete_objects = store._s3.delete_objects

    def _partial_failure(**kwargs):
        response = real_delete_objects(**kwargs)
        response["Errors"] = [
            {"Key": "pfx/results/j6/metadata.json", "Code": "AccessDenied",
             "Message": "insufficient permissions"}
        ]
        return response

    with patch.object(store._s3, "delete_objects", side_effect=_partial_failure):
        with pytest.raises(BlobFetchError):
            store.delete_job("j6")


def test_delete_job_all_success_path_does_not_raise(store, tmp_path):
    """The normal (no Errors) path must not raise -- a regression guard alongside the
    partial-failure test above."""
    out = tmp_path / "j7" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j7", out)

    store.delete_job("j7")  # must not raise

    s3 = boto3.client("s3", region_name="us-east-1")
    assert s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/results/j7/")["KeyCount"] == 0
