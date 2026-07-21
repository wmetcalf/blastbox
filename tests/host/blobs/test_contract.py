"""One contract, both backends — behaviour that must not diverge."""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.blobs.local import LocalBlobStore


def _local(tmp_path, request):
    return LocalBlobStore(tmp_path)


def _s3(tmp_path, request):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    ctx = moto.mock_aws()
    ctx.start()
    # Stop the mock at the end of THIS test, not at process exit — an unstopped
    # context leaks moto's global backend state into every test that runs after
    # it in the same session (including test_s3.py's own per-test mock_aws(),
    # which then fails to reset between tests and accumulates keys).
    request.addfinalizer(ctx.stop)
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="contract")
    from blastbox.host.blobs.s3 import S3BlobStore

    return S3BlobStore("s3://contract", job_root=tmp_path, env={})


@pytest.mark.parametrize("make_store", [_local, _s3], ids=["local", "s3"])
def test_get_sample_raises_blob_fetch_error_when_absent(make_store, tmp_path, request):
    """Both backends signal 'cannot materialise' with the SAME exception type, so
    the dispatcher's release-don't-fail policy is backend-independent."""
    store = make_store(tmp_path, request)
    with pytest.raises(BlobFetchError):
        store.get_sample("c" * 64, tmp_path / "j" / "input" / "missing.doc")


@pytest.mark.parametrize("make_store", [_local, _s3], ids=["local", "s3"])
def test_open_output_returns_the_written_bytes(make_store, tmp_path, request):
    store = make_store(tmp_path, request)
    out = tmp_path / "jc" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"status":"ok"}')
    store.put_output("jc", out)
    with store.open_output("jc", "metadata.json") as fh:
        assert fh.read() == b'{"status":"ok"}'
