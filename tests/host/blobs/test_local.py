"""LocalBlobStore — the default backend. It is a REAL filesystem-backed store,
rooted OUTSIDE job_root (see tests/host/blobs/test_local_roundtrip.py for the
property this exists to guarantee: bytes surviving job-dir destruction). These
tests cover the per-method contract in isolation."""
import hashlib

import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.blobs.local import LocalBlobStore


def _mk_job(tmp_path, job_id="j1", name="sample.doc", data=b"hello"):
    d = tmp_path / job_id / "input"
    d.mkdir(parents=True)
    p = d / name
    p.write_bytes(data)
    return p


def _store(tmp_path):
    return LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")


def test_put_sample_copies_bytes_into_the_blob_root(tmp_path):
    src = _mk_job(tmp_path / "jobs")
    _store(tmp_path).put_sample("a" * 64, src)
    assert (tmp_path / "blobs" / "samples" / ("a" * 64)).read_bytes() == b"hello"


def test_put_sample_rejects_a_missing_file(tmp_path):
    with pytest.raises(BlobFetchError):
        _store(tmp_path).put_sample("a" * 64, tmp_path / "nope.doc")


def test_get_sample_materialises_a_copy_from_the_blob_root(tmp_path):
    # put_sample stores it once; get_sample must be able to write it to a BRAND NEW
    # destination, not merely verify a file that's already there (the old no-op
    # contract this replaces — see test_local_roundtrip.py for why that broke).
    data = b"payload"
    digest = hashlib.sha256(data).hexdigest()
    store = _store(tmp_path)
    store.put_sample(digest, _mk_job(tmp_path / "jobs", data=data))
    dest = tmp_path / "jobs" / "j2" / "input" / "renamed.doc"
    store.get_sample(digest, dest)
    assert dest.read_bytes() == b"payload"


def test_get_sample_raises_when_the_blob_is_absent(tmp_path):
    """Nothing was ever put under this key, so there is no second copy to fetch —
    but it raises BlobFetchError so the CALLER can still choose to release the
    claim rather than fail the job."""
    with pytest.raises(BlobFetchError):
        _store(tmp_path).get_sample("a" * 64, tmp_path / "jobs" / "gone" / "x.doc")


def test_put_output_then_open_output_reads_the_stored_copy(tmp_path):
    # open_output must read from the blob root, not the job dir directly — the old
    # no-op contract read job_root/output straight through, which can't survive a
    # purge of job_root.
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"ok":true}')
    store = _store(tmp_path)
    store.put_output("j1", out)
    assert (tmp_path / "blobs" / "results" / "j1" / "metadata.json").read_bytes() == b'{"ok":true}'
    with store.open_output("j1", "metadata.json") as fh:
        assert fh.read() == b'{"ok":true}'


def test_open_output_raises_when_absent(tmp_path):
    with pytest.raises(BlobFetchError):
        _store(tmp_path).open_output("nope", "metadata.json")


def test_delete_job_removes_the_stored_results_but_not_samples(tmp_path):
    # delete_job is no longer a no-op (retention owned the on-disk job dir under the
    # old design; now the blob store owns its OWN durable results copy and must
    # reclaim it itself). Samples are content-addressed and shared, so they must
    # survive regardless of which job's delete_job call is made.
    store = _store(tmp_path)
    store.put_sample("a" * 64, _mk_job(tmp_path / "jobs", data=b"shared"))
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j1", out)

    store.delete_job("j1")

    assert not (tmp_path / "blobs" / "results" / "j1").exists()
    assert (tmp_path / "blobs" / "samples" / ("a" * 64)).exists()


def test_delete_job_on_a_job_with_no_stored_results_is_a_noop(tmp_path):
    _store(tmp_path).delete_job("never-existed")  # must not raise
