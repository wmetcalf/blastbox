"""build_blob_store_from_env — the storage-backend selector.

Mirrors tests/host/jobs/test_factory.py: unset MUST give the local backend so a
single-node deployment needs no configuration and no S3 dependency.
"""

import pytest

from blastbox.host.blobs.factory import build_blob_store_from_env
from blastbox.host.blobs.local import LocalBlobStore


def test_unset_url_returns_local_store(tmp_path):
    store = build_blob_store_from_env({"BLASTBOX_JOB_ROOT": str(tmp_path)})
    assert isinstance(store, LocalBlobStore)


def test_empty_url_returns_local_store(tmp_path):
    store = build_blob_store_from_env(
        {"BLASTBOX_JOB_ROOT": str(tmp_path), "BLASTBOX_BLOB_URL": "   "}
    )
    assert isinstance(store, LocalBlobStore)


def test_unknown_scheme_is_rejected_loudly(tmp_path):
    """A typo'd scheme must fail fast, not silently degrade to local — silently
    writing bytes nowhere is the worst possible outcome for a worker."""
    with pytest.raises(ValueError, match="unsupported blob url scheme"):
        build_blob_store_from_env(
            {"BLASTBOX_JOB_ROOT": str(tmp_path), "BLASTBOX_BLOB_URL": "ftp://nope/x"}
        )
