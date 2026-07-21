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
