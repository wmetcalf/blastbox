"""LocalBlobStore — the default backend. It is a REAL filesystem-backed store,
rooted OUTSIDE job_root (see tests/host/blobs/test_local_roundtrip.py for the
property this exists to guarantee: bytes surviving job-dir destruction). These
tests cover the per-method contract in isolation."""
import hashlib
from pathlib import Path

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


def test_put_output_skips_a_symlink_to_a_file_outside_the_output_dir(tmp_path):
    """Security regression: a compromised worker can plant e.g.
    output/metadata.json -> /etc/passwd (or any host path) in the output dir before
    put_output runs. rglob("*") + is_file() FOLLOWS a symlink and would previously
    copy the TARGET's bytes into the blob store, where they'd later be served as
    trusted job output through a route with no check (the old check lived at
    serve time and was removed when /metadata + /result switched to open_output).

    put_output must skip (not follow) a symlinked entry, log a warning, and
    continue uploading the rest of the legitimate output untouched.
    """
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "legit.txt").write_bytes(b"legit-bytes")

    secret = tmp_path / "outside_secret.txt"
    secret.write_bytes(b"TOP-SECRET-OUTSIDE-BYTES")
    (out / "metadata.json").symlink_to(secret)

    store = _store(tmp_path)
    store.put_output("j1", out)

    # The symlink's target bytes were never stored/uploaded: the key is absent.
    with pytest.raises(BlobFetchError):
        store.open_output("j1", "metadata.json")
    assert not (tmp_path / "blobs" / "results" / "j1" / "metadata.json").exists()

    # The legitimate sibling file WAS stored.
    with store.open_output("j1", "legit.txt") as fh:
        assert fh.read() == b"legit-bytes"


def test_open_output_reads_a_nested_artifact_path(tmp_path):
    """put_output stores nested rel paths (results/<id>/foo/bar.png); open_output must read them at
    the SAME key, not collapse to the basename -- collapsing 404s / silently omits nested artifacts
    (a Mode-1 regression vs the old FileResponse on output/foo/bar.png)."""
    out = tmp_path / "jobs" / "j1" / "output"
    (out / "foo").mkdir(parents=True)
    (out / "foo" / "bar.png").write_bytes(b"PNGDATA")
    store = _store(tmp_path)
    store.put_output("j1", out)
    assert (tmp_path / "blobs" / "results" / "j1" / "foo" / "bar.png").read_bytes() == b"PNGDATA"
    with store.open_output("j1", "foo/bar.png") as fh:
        assert fh.read() == b"PNGDATA"


@pytest.mark.parametrize("evil", ["../secret", "/etc/passwd", "a/../../b"])
def test_open_output_refuses_traversal_and_absolute_names(tmp_path, evil):
    """open_output must contain the lookup under results/<job_id>/ on its OWN -- a caller must never
    read outside it even if an upstream validator is bypassed."""
    store = _store(tmp_path)
    (tmp_path / "blobs" / "results" / "j1").mkdir(parents=True)
    (tmp_path / "blobs" / "results" / "secret").write_bytes(b"OUTSIDE")  # a sibling a traversal could reach
    with pytest.raises(BlobFetchError):
        store.open_output("j1", evil)


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


def test_delete_job_propagates_a_real_removal_error(tmp_path, monkeypatch):
    """retention._expire_job only advances a job to EXPIRED (clearing expires_at)
    when delete_job did NOT raise, so a transient failure gets retried by a later
    sweep. LocalBlobStore must therefore let a genuine OSError propagate rather than
    swallowing it via ignore_errors=True -- otherwise a partial/failed local delete
    is indistinguishable from success and the leftover bytes are never retried."""
    import shutil as shutil_mod

    store = _store(tmp_path)
    out = tmp_path / "jobs" / "j1" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b"{}")
    store.put_output("j1", out)

    def _boom(path, *a, **kw):
        raise OSError("simulated permission error removing results dir")

    monkeypatch.setattr(shutil_mod, "rmtree", _boom)

    with pytest.raises(OSError):
        store.delete_job("j1")


def test_has_output_is_false_when_the_results_dir_cannot_be_read(tmp_path, monkeypatch):
    """The age reclaim deletes a sealed result's local tree on the strength of this answer, so an
    unreadable/errored store must never be reported as "the durable copy is there" — that turns a
    transient storage fault into irreversible loss of the only copy."""
    store = LocalBlobStore(tmp_path / "jobs", blob_root=tmp_path / "blobs")
    out = tmp_path / "out"
    out.mkdir()
    (out / "metadata.json").write_text("{}")
    store.put_output("j-err", out)
    assert store.has_output("j-err") is True

    def boom(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", boom)
    assert store.has_output("j-err") is False
