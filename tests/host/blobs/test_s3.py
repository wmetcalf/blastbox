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
