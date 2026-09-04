"""LocalBlobStore is a REAL store: bytes survive the job dir being destroyed.

This is the property the worker purge invariant depends on. A store whose only copy
is the job dir cannot serve anything once the worker purges.
"""
import hashlib
import shutil

import pytest

from blastbox.host.blobs.base import BlobFetchError, BlobIntegrityError
from blastbox.host.blobs.local import LocalBlobStore


def _store(tmp_path):
    return LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")


def _spool(tmp_path, job_id, name, data):
    p = tmp_path / "jobs" / job_id / "input" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def test_sample_survives_job_dir_destruction(tmp_path):
    data = b"malware bytes"
    digest = hashlib.sha256(data).hexdigest()
    store = _store(tmp_path)
    store.put_sample(digest, _spool(tmp_path, "j1", "invoice.doc", data))

    shutil.rmtree(tmp_path / "jobs" / "j1")          # the worker purge

    dest = tmp_path / "jobs" / "j2" / "input" / "other-name.doc"
    store.get_sample(digest, dest)
    assert dest.read_bytes() == data


def test_identical_bytes_under_two_names_store_once(tmp_path):
    data = b"same bytes"
    digest = hashlib.sha256(data).hexdigest()
    store = _store(tmp_path)
    store.put_sample(digest, _spool(tmp_path, "j1", "a.doc", data))
    store.put_sample(digest, _spool(tmp_path, "j2", "PO_08312020.xls", data))
    assert len(list((tmp_path / "blobs" / "samples").iterdir())) == 1


def test_missing_sample_raises_blob_fetch_error(tmp_path):
    with pytest.raises(BlobFetchError):
        _store(tmp_path).get_sample("f" * 64, tmp_path / "jobs" / "j" / "input" / "x.doc")


def test_output_survives_job_dir_destruction(tmp_path):
    store = _store(tmp_path)
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"status":"ok"}')
    store.put_output("j1", out)

    shutil.rmtree(tmp_path / "jobs" / "j1")          # the worker purge

    with store.open_output("j1", "metadata.json") as fh:
        assert fh.read() == b'{"status":"ok"}'


def test_get_sample_raises_blob_integrity_error_on_corrupt_stored_blob(tmp_path):
    """A blob corrupted on disk (bug, bit rot) after put_sample must not be trusted
    forever just because the key already existed — get_sample re-hashes and rejects
    it, mirroring S3BlobStore, and must not leave a corrupt copy at dest."""
    data = b"trustworthy bytes"
    digest = hashlib.sha256(data).hexdigest()
    store = _store(tmp_path)
    store.put_sample(digest, _spool(tmp_path, "j1", "invoice.doc", data))

    (tmp_path / "blobs" / "samples" / digest).write_bytes(b"corrupted!!")

    dest = tmp_path / "jobs" / "j2" / "input" / "invoice.doc"
    with pytest.raises(BlobIntegrityError):
        store.get_sample(digest, dest)
    assert not dest.exists(), "a corrupt fetch must not leave bytes at dest"


def test_delete_job_removes_results_but_not_samples(tmp_path):
    data = b"shared"
    digest = hashlib.sha256(data).hexdigest()
    store = _store(tmp_path)
    store.put_sample(digest, _spool(tmp_path, "j1", "a.doc", data))
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j1", out)

    store.delete_job("j1")

    assert not (tmp_path / "blobs" / "results" / "j1").exists()
    assert (tmp_path / "blobs" / "samples" / digest).exists(), "shared sample must survive"


def test_open_output_falls_back_to_legacy_job_root_output(tmp_path):
    """C1 upgrade-compat: a pre-blob-store DONE job has its output only at the legacy
    <job_root>/<id>/output/ location (never put_output'd). open_output must serve it."""
    store = _store(tmp_path)
    # No results/<id> blob at all — simulate a job that completed under the old code.
    legacy_out = tmp_path / "jobs" / "legacy-job" / "output"
    legacy_out.mkdir(parents=True)
    (legacy_out / "metadata.json").write_bytes(b'{"status":"ok","legacy":true}')

    with store.open_output("legacy-job", "metadata.json") as fh:
        assert fh.read() == b'{"status":"ok","legacy":true}'


def test_open_output_prefers_the_blob_store_over_legacy(tmp_path):
    """When both exist, the current blob-store copy wins (legacy is only a fallback)."""
    store = _store(tmp_path)
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"NEW-BLOB-STORE-BYTES")
    store.put_output("j1", out)
    # A stale legacy copy with different bytes must NOT shadow the store copy.
    legacy = tmp_path / "jobs" / "j1" / "output"
    (legacy / "metadata.json").write_bytes(b"STALE-LEGACY-BYTES")
    # store already has the NEW bytes; the legacy on-disk write above is at the same path
    # as put_output read from, so re-stage to be unambiguous:
    (out / "metadata.json").write_bytes(b"NEW-BLOB-STORE-BYTES")
    store.put_output("j1", out)
    (legacy / "metadata.json").write_bytes(b"STALE-LEGACY-BYTES")
    with store.open_output("j1", "metadata.json") as fh:
        assert fh.read() == b"NEW-BLOB-STORE-BYTES"


def test_legacy_fallback_still_enforces_containment(tmp_path):
    """The legacy fallback must reject a traversal name just like the primary path."""
    store = _store(tmp_path)
    with pytest.raises(BlobFetchError):
        store.open_output("j1", "../../../etc/passwd")
