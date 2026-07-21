"""Blob storage backends — where a job's sample and result bytes live.

Selected by ``BLASTBOX_BLOB_URL`` (see :mod:`blastbox.host.blobs.factory`).
Unset means the local filesystem, which is the single-node default.
"""
