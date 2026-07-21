"""LocalBlobStore — the default backend. It is a near-no-op over the existing
job-root layout: ingress already spooled the input and the dispatcher already
reads it there, so put/get only VERIFY rather than move bytes."""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.blobs.local import LocalBlobStore


def _mk_job(tmp_path, job_id="j1", name="sample.doc", data=b"hello"):
    d = tmp_path / job_id / "input"
    d.mkdir(parents=True)
    p = d / name
    p.write_bytes(data)
    return p


def test_put_sample_accepts_an_existing_file(tmp_path):
    src = _mk_job(tmp_path)
    LocalBlobStore(tmp_path).put_sample("a" * 64, src)  # must not raise


def test_put_sample_rejects_a_missing_file(tmp_path):
    with pytest.raises(BlobFetchError):
        LocalBlobStore(tmp_path).put_sample("a" * 64, tmp_path / "nope.doc")


def test_get_sample_is_a_noop_when_the_file_is_already_there(tmp_path):
    src = _mk_job(tmp_path, data=b"payload")
    LocalBlobStore(tmp_path).get_sample("a" * 64, src)
    assert src.read_bytes() == b"payload"   # untouched


def test_get_sample_raises_when_the_file_is_absent(tmp_path):
    """Local mode has no second copy to fetch from, so an absent input is fatal
    for this backend — but it raises BlobFetchError so the CALLER can still choose
    to release the claim rather than fail the job."""
    with pytest.raises(BlobFetchError):
        LocalBlobStore(tmp_path).get_sample("a" * 64, tmp_path / "gone" / "x.doc")


def test_open_output_reads_the_local_file(tmp_path):
    out = tmp_path / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"ok":true}')
    with LocalBlobStore(tmp_path).open_output("j1", "metadata.json") as fh:
        assert fh.read() == b'{"ok":true}'


def test_put_output_and_delete_job_are_noops(tmp_path):
    out = tmp_path / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store = LocalBlobStore(tmp_path)
    store.put_output("j1", out)
    store.delete_job("j1")
    # retention owns the on-disk dir in local mode; delete_job must not remove it
    assert (out / "metadata.json").exists()
