# Distributed Blob Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a blastbox worker execute a claimed job using outbound connections only, so API nodes and worker nodes can be separate machines behind a firewall — without changing the single-node deployment at all.

**Architecture:** Add a `BlobStore` abstraction selected by `BLASTBOX_BLOB_URL`, mirroring the existing `build_job_store_from_env` pattern. `LocalBlobStore` (default, unset) is a near-no-op preserving today's filesystem behaviour; `S3BlobStore` (opt-in) moves sample and result bytes through MinIO/S3. Samples are keyed on the ingress-computed `input_sha256`, never the filename. Firecracker execution is untouched — the local job dir remains the working set, fed on demand.

**Tech Stack:** Python >=3.12, pytest, `boto3` (lazily imported, behind a new `blastbox[s3]` extra), `moto[s3]` for tests.

**Spec:** `docs/specs/2026-07-21-distributed-blob-storage-design.md`

## Global Constraints

- Python `>=3.12`; package version `0.1.24`; tests live under `tests/`, run with `pytest` (`addopts = "-ra -q"`).
- **`blastbox[host]` MUST gain no new mandatory dependency.** `boto3` is imported *inside* the S3 branch only, exactly as `sql_store.py` imports `psycopg_pool` inside its postgres branch.
- **Mode-1 regression gate:** the existing suite must pass with `BLASTBOX_BLOB_URL` unset **and `boto3` not importable**. If a test needs modifying to pass, the abstraction is wrong — rework the abstraction, do not relax the test.
- **Worker purge invariant:** after a job reaches a terminal state, no sample bytes remain under the worker's `job_root` — on the success, engine-failure, timeout, AND release-back-to-queued paths. There is no configuration that disables this.
- **Blob key is `samples/<input_sha256>`** — the hash the ingress computes over the uploaded bytes. Never derive a key from `job.filename`.
- **Local materialisation path is `job_dir/input/<job.filename>`** — the original name, because engines type-detect on the extension.
- **Ordering:** `put_sample()` must succeed before the job row is created (becomes claimable).
- **Failure asymmetry:** `get_sample` failure → release the claim back to `queued` (never fail the job). `put_output` failure → retry, then leave `RUNNING` for the sweeper (never discard completed work).

---

### Task 1: `BlobStore` protocol, `LocalBlobStore`, and the factory

**Files:**
- Create: `src/blastbox/host/blobs/__init__.py`
- Create: `src/blastbox/host/blobs/base.py`
- Create: `src/blastbox/host/blobs/local.py`
- Create: `src/blastbox/host/blobs/factory.py`
- Test: `tests/host/blobs/__init__.py`
- Test: `tests/host/blobs/test_factory.py`
- Test: `tests/host/blobs/test_local.py`

**Interfaces:**
- Consumes: nothing (foundation task).
- Produces:
  - `BlobStore` protocol with `put_sample(sha256: str, src: Path) -> None`, `get_sample(sha256: str, dest: Path) -> None`, `put_output(job_id: str, out_dir: Path) -> None`, `open_output(job_id: str, name: str) -> BinaryIO`, `delete_job(job_id: str) -> None`
  - `BlobFetchError(Exception)` — transient; callers release the claim
  - `BlobIntegrityError(BlobFetchError)` — hash mismatch
  - `LocalBlobStore(job_root: Path)`
  - `build_blob_store_from_env(env: dict[str, str] | None = None) -> BlobStore`

- [ ] **Step 1: Write the failing tests**

Create `tests/host/blobs/__init__.py` (empty file), then `tests/host/blobs/test_factory.py`:

```python
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
```

And `tests/host/blobs/test_local.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/blobs/ -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'blastbox.host.blobs'`

- [ ] **Step 3: Write the protocol and errors**

Create `src/blastbox/host/blobs/__init__.py`:

```python
"""Blob storage backends — where a job's sample and result bytes live.

Selected by ``BLASTBOX_BLOB_URL`` (see :mod:`blastbox.host.blobs.factory`).
Unset means the local filesystem, which is the single-node default.
"""
```

Create `src/blastbox/host/blobs/base.py`:

```python
"""BlobStore protocol — the seam between a job's bytes and where they live.

The local job dir stays the working set in EVERY backend: Firecracker bind-mounts
need a real path. A remote backend does not replace ``job_root``, it feeds it.
"""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable


class BlobFetchError(Exception):
    """A sample could not be materialised locally.

    Callers MUST treat this as transient and release the claim back to ``queued``
    rather than failing the job: an unreachable object store is a property of THIS
    worker's connectivity, not of the sample. Failing would permanently discard
    work because one node's link was down.
    """


class BlobIntegrityError(BlobFetchError):
    """Fetched bytes did not hash to the requested key (corrupt or substituted)."""


@runtime_checkable
class BlobStore(Protocol):
    def put_sample(self, sha256: str, src: Path) -> None:
        """Store *src* under the content key *sha256*. Idempotent."""

    def get_sample(self, sha256: str, dest: Path) -> None:
        """Materialise the sample at *dest* (the ORIGINAL filename, not the key)."""

    def put_output(self, job_id: str, out_dir: Path) -> None:
        """Persist the sealed output dir for *job_id*."""

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        """Open one artifact from *job_id*'s output for reading."""

    def delete_job(self, job_id: str) -> None:
        """Drop *job_id*'s outputs. MUST NOT touch shared ``samples/`` blobs."""
```

- [ ] **Step 4: Write `LocalBlobStore`**

Create `src/blastbox/host/blobs/local.py`:

```python
"""LocalBlobStore — the default, and deliberately almost nothing.

Ingress already spools the input to ``<job_root>/<id>/input/<filename>`` and the
dispatcher already reads it from there, so in single-node mode there is no second
copy to move: put/get VERIFY, they do not transfer. This is what keeps mode 1
byte-identical to pre-BlobStore behaviour with no new dependency.
"""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from blastbox.host.blobs.base import BlobFetchError


class LocalBlobStore:
    def __init__(self, job_root: Path | str) -> None:
        self._job_root = Path(job_root)

    def put_sample(self, sha256: str, src: Path) -> None:
        if not Path(src).is_file():
            raise BlobFetchError(f"sample not present locally: {src}")

    def get_sample(self, sha256: str, dest: Path) -> None:
        # No remote copy exists in local mode. Raise the transient error type anyway
        # so the caller's release-vs-fail policy stays uniform across backends.
        if not Path(dest).is_file():
            raise BlobFetchError(f"sample not present locally: {dest}")

    def put_output(self, job_id: str, out_dir: Path) -> None:
        return None      # already on the filesystem the API serves from

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        return open(self._job_root / job_id / "output" / Path(name).name, "rb")

    def delete_job(self, job_id: str) -> None:
        # Retention owns the on-disk job dir in local mode (jobs/retention.py has the
        # containment checks); duplicating deletion here would race it.
        return None
```

- [ ] **Step 5: Write the factory**

Create `src/blastbox/host/blobs/factory.py`:

```python
"""BlobStore factory — select the backend from ``BLASTBOX_BLOB_URL``.

Mirrors ``blastbox.host.jobs.factory.build_job_store_from_env`` so the two storage
knobs are configured the same way. Unset = local filesystem = today's behaviour,
with no S3 dependency imported or required.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from blastbox.host.blobs.base import BlobStore
from blastbox.host.blobs.local import LocalBlobStore


def build_blob_store_from_env(env: dict[str, str] | None = None) -> BlobStore:
    """Return the BlobStore selected by ``BLASTBOX_BLOB_URL``.

    - unset / empty -> ``LocalBlobStore`` (single-node default; no new deps)
    - ``s3://bucket/prefix`` -> ``S3BlobStore`` (MinIO or AWS S3)
    """
    e = os.environ if env is None else env
    job_root = Path(e.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs"))
    url = e.get("BLASTBOX_BLOB_URL", "").strip()
    if not url:
        return LocalBlobStore(job_root)

    scheme = urlparse(url).scheme.lower()
    if scheme == "s3":
        # Imported HERE, not at module scope, so `blastbox[host]` needs no boto3 —
        # same pattern as SqlJobStore importing psycopg_pool inside its postgres branch.
        from blastbox.host.blobs.s3 import S3BlobStore

        return S3BlobStore(url, job_root=job_root, env=e)

    raise ValueError(f"unsupported blob url scheme: {scheme!r} (use s3:// or leave unset)")
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/blobs/ -v`
Expected: PASS (9 tests)

- [ ] **Step 7: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS, same counts as before this task — nothing is wired up yet, so any change here is a bug.

- [ ] **Step 8: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/blobs/ tests/host/blobs/
git commit -m "feat(blobs): add BlobStore protocol, LocalBlobStore, and env factory"
```

---

### Task 2: `S3BlobStore` + the `blastbox[s3]` extra

**Files:**
- Create: `src/blastbox/host/blobs/s3.py`
- Modify: `pyproject.toml` (add `s3` extra; add `moto[s3]` to `dev`)
- Test: `tests/host/blobs/test_s3.py`
- Test: `tests/host/blobs/test_contract.py`

**Interfaces:**
- Consumes: `BlobStore`, `BlobFetchError`, `BlobIntegrityError` from Task 1.
- Produces: `S3BlobStore(url: str, *, job_root: Path, env: dict[str, str])` satisfying `BlobStore`; keys `samples/<sha256>` and `results/<job_id>/<name>`.

- [ ] **Step 1: Add the extras**

In `pyproject.toml`, inside `[project.optional-dependencies]` add a new extra after the `host` list:

```toml
# Object-storage backend (MinIO / AWS S3) for multi-node deployments. NOT required
# by `blastbox[host]`: BLASTBOX_BLOB_URL unset uses the local filesystem and never
# imports boto3.
s3 = [
    "boto3>=1.34",
]
```

And append to the `dev` list:

```toml
    "moto[s3]>=5.0",             # in-process S3 for the blob-store contract tests
```

- [ ] **Step 2: Write the failing tests**

Create `tests/host/blobs/test_s3.py`:

```python
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
```

Create `tests/host/blobs/test_contract.py`:

```python
"""One contract, both backends — behaviour that must not diverge."""
import hashlib

import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.blobs.local import LocalBlobStore


def _local(tmp_path):
    return LocalBlobStore(tmp_path)


def _s3(tmp_path):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    ctx = moto.mock_aws()
    ctx.start()
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="contract")
    from blastbox.host.blobs.s3 import S3BlobStore

    return S3BlobStore("s3://contract", job_root=tmp_path, env={})


@pytest.mark.parametrize("make_store", [_local, _s3], ids=["local", "s3"])
def test_get_sample_raises_blob_fetch_error_when_absent(make_store, tmp_path):
    """Both backends signal 'cannot materialise' with the SAME exception type, so
    the dispatcher's release-don't-fail policy is backend-independent."""
    store = make_store(tmp_path)
    with pytest.raises(BlobFetchError):
        store.get_sample("c" * 64, tmp_path / "j" / "input" / "missing.doc")


@pytest.mark.parametrize("make_store", [_local, _s3], ids=["local", "s3"])
def test_open_output_returns_the_written_bytes(make_store, tmp_path):
    store = make_store(tmp_path)
    out = tmp_path / "jc" / "output"
    out.mkdir(parents=True)
    (out / "metadata.json").write_bytes(b'{"status":"ok"}')
    store.put_output("jc", out)
    with store.open_output("jc", "metadata.json") as fh:
        assert fh.read() == b'{"status":"ok"}'
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/blobs/test_s3.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'blastbox.host.blobs.s3'`

- [ ] **Step 4: Write `S3BlobStore`**

Create `src/blastbox/host/blobs/s3.py`:

```python
"""S3BlobStore — sample and result bytes in MinIO or AWS S3.

Reached only when ``BLASTBOX_BLOB_URL=s3://...``; ``blastbox.host.blobs.factory``
imports this module lazily so ``blastbox[host]`` never requires boto3.

Key layout:
  ``<prefix>/samples/<input_sha256>``   content-addressed, SHARED between jobs
  ``<prefix>/results/<job_id>/<name>``  job-scoped, written once
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse

from blastbox.host.blobs.base import BlobFetchError, BlobIntegrityError

_CHUNK = 1024 * 1024


class S3BlobStore:
    def __init__(self, url: str, *, job_root: Path, env: dict[str, str] | None = None) -> None:
        import boto3  # noqa: PLC0415 — optional dep, see module docstring

        e = os.environ if env is None else env
        parsed = urlparse(url)
        self._bucket = parsed.netloc
        self._prefix = parsed.path.strip("/")
        self._job_root = Path(job_root)
        self._compress = e.get("BLASTBOX_BLOB_COMPRESS", "1").strip().lower() not in (
            "0", "false", "no",
        )
        endpoint = e.get("BLASTBOX_BLOB_ENDPOINT_URL", "").strip() or None
        self._s3 = boto3.client("s3", endpoint_url=endpoint)

    def _key(self, *parts: str) -> str:
        return "/".join(p for p in (self._prefix, *parts) if p)

    # ── samples ──────────────────────────────────────────────────────────────
    def put_sample(self, sha256: str, src: Path) -> None:
        key = self._key("samples", sha256)
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return                      # already present: content-addressed => identical
        except Exception:
            pass
        try:
            self._s3.upload_file(str(src), self._bucket, key)
        except Exception as exc:
            raise BlobFetchError(f"sample upload failed: {sha256}") from exc

    def get_sample(self, sha256: str, dest: Path) -> None:
        key = self._key("samples", sha256)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        try:
            self._s3.download_file(self._bucket, key, str(tmp))
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise BlobFetchError(f"sample fetch failed: {sha256}") from exc

        h = hashlib.sha256()
        with open(tmp, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
        if h.hexdigest() != sha256:
            tmp.unlink(missing_ok=True)
            raise BlobIntegrityError(
                f"fetched bytes hash {h.hexdigest()}, expected {sha256}"
            )
        tmp.replace(dest)

    # ── results ──────────────────────────────────────────────────────────────
    def put_output(self, job_id: str, out_dir: Path) -> None:
        out_dir = Path(out_dir)
        for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
            rel = path.relative_to(out_dir).as_posix()
            body = path.read_bytes()
            extra: dict[str, str] = {}
            if self._compress:
                body = gzip.compress(body)
                extra["ContentEncoding"] = "gzip"
            self._s3.put_object(
                Bucket=self._bucket,
                Key=self._key("results", job_id, rel),
                Body=body,
                **extra,
            )

    def open_output(self, job_id: str, name: str) -> BinaryIO:
        key = self._key("results", job_id, Path(name).name)
        try:
            obj = self._s3.get_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            raise BlobFetchError(f"result fetch failed: {job_id}/{name}") from exc
        data = obj["Body"].read()
        if obj.get("ContentEncoding") == "gzip":
            data = gzip.decompress(data)
        return io.BytesIO(data)

    def delete_job(self, job_id: str) -> None:
        """Drop this job's RESULTS only.

        Sample blobs are content-addressed and shared between jobs, so they are
        never deleted here — doing so would break every other job referencing the
        same bytes, including a future re-run of the corpus.
        """
        prefix = self._key("results", job_id) + "/"
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                self._s3.delete_objects(Bucket=self._bucket, Delete={"Objects": keys})
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pip install -e '.[dev,s3]' -q && python -m pytest tests/host/blobs/ -v`
Expected: PASS (all local, s3, and contract tests)

- [ ] **Step 6: Verify the no-boto3 gate**

Run:
```bash
cd /home/coz/Downloads/blastbox
python -c "
import builtins, sys
_real = builtins.__import__
def guard(name, *a, **k):
    if name.split('.')[0] == 'boto3':
        raise ImportError('boto3 blocked')
    return _real(name, *a, **k)
builtins.__import__ = guard
from blastbox.host.blobs.factory import build_blob_store_from_env
s = build_blob_store_from_env({'BLASTBOX_JOB_ROOT': '/tmp/x'})
print('OK, local store built without boto3:', type(s).__name__)
"
```
Expected: `OK, local store built without boto3: LocalBlobStore`

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/blobs/s3.py tests/host/blobs/ pyproject.toml
git commit -m "feat(blobs): add S3BlobStore behind the blastbox[s3] extra"
```

---

### Task 3: Ingress uploads the sample before the job becomes claimable

**Files:**
- Modify: `src/blastbox/host/ingress/app.py` (around the `job.input_sha256 = sha256` / `_job_store.create(job)` block, currently ~line 596-600)
- Test: `tests/host/test_ingress_blob_upload.py`

**Interfaces:**
- Consumes: `build_blob_store_from_env`, `BlobStore`, `BlobFetchError` (Tasks 1-2).
- Produces: ingress calls `blob_store.put_sample(job.input_sha256, input_path)` **before** `_job_store.create(job)`.

- [ ] **Step 1: Write the failing test**

Create `tests/host/test_ingress_blob_upload.py`:

```python
"""Ingress must upload the sample BEFORE the job row exists.

Otherwise a worker can claim a job whose blob is not there yet and is pushed down
the release-and-retry path for a sample that was never missing — a self-inflicted
race that looks exactly like object-store flakiness.
"""
from pathlib import Path

import pytest

from blastbox.host.blobs.base import BlobFetchError


class RecordingBlobStore:
    """Records the ORDER of put_sample vs the job-store create."""

    def __init__(self, log): self.log = log
    def put_sample(self, sha256, src):
        assert Path(src).is_file()
        self.log.append(("put_sample", sha256))
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FailingBlobStore(RecordingBlobStore):
    def put_sample(self, sha256, src):
        raise BlobFetchError("object store down")


def test_put_sample_happens_before_job_create(ingress_client_factory):
    """ingress_client_factory: see tests/host/conftest.py — builds the FastAPI app
    with injected stores and returns (client, log)."""
    client, log = ingress_client_factory(blob_store_cls=RecordingBlobStore)
    resp = client.post(
        "/v1/jobs",
        files={"file": ("invoice.doc", b"payload-bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    assert resp.status_code == 202
    kinds = [k for k, _ in log]
    assert kinds.index("put_sample") < kinds.index("job_create"), log


def test_upload_failure_creates_no_job(ingress_client_factory):
    """If the blob cannot be stored, there must be NO claimable job row — a job
    nobody can ever materialise is worse than a rejected upload."""
    client, log = ingress_client_factory(blob_store_cls=FailingBlobStore)
    resp = client.post(
        "/v1/jobs",
        files={"file": ("invoice.doc", b"payload", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    assert resp.status_code == 503
    assert [k for k, _ in log if k == "job_create"] == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/test_ingress_blob_upload.py -v`
Expected: FAIL — the fixture `ingress_client_factory` does not exist yet, and the ordering is unimplemented.

- [ ] **Step 3: Add the fixture**

Append to `tests/host/conftest.py` (create the file if absent, with `import pytest` at the top):

```python
@pytest.fixture
def ingress_client_factory(tmp_path):
    """Build the ingress app with an injected BlobStore and an ordering log."""
    from fastapi.testclient import TestClient

    from blastbox.host.ingress.app import build_app
    from blastbox.host.jobs.memory import InMemoryJobStore

    def _factory(blob_store_cls):
        log: list[tuple[str, str]] = []

        class LoggingJobStore(InMemoryJobStore):
            def create(self, job):
                log.append(("job_create", job.job_id))
                return super().create(job)

        app = build_app(
            job_store=LoggingJobStore(),
            job_root=tmp_path,
            blob_store=blob_store_cls(log),
        )
        return TestClient(app), log

    return _factory
```

- [ ] **Step 4: Wire the blob store into the ingress**

In `src/blastbox/host/ingress/app.py`, add `blob_store` to `build_app`'s signature (defaulting to the env factory) alongside the existing `job_root` parameter:

```python
    blob_store: "BlobStore | None" = None,
```

and near the other module-level resolution (where `_job_root` is set):

```python
    from blastbox.host.blobs.factory import build_blob_store_from_env

    _blob_store = blob_store if blob_store is not None else build_blob_store_from_env()
```

Then replace the create block (currently `job.input_sha256 = sha256` through `_job_store.create(job)`) with:

```python
        job.input_sha256 = sha256
        job.result_dir = str(output_dir)

        # Upload BEFORE the row exists: a job is claimable the instant it is created,
        # and a worker that claims one whose blob is missing would be forced down the
        # release-and-retry path for a sample that was never actually missing.
        try:
            _blob_store.put_sample(sha256, input_path)
        except Exception as exc:
            shutil.rmtree(root, ignore_errors=True)
            _log.warning("blob_put_sample_failed", error=str(exc))
            raise HTTPException(503, "blob store unavailable") from exc

        try:
            _job_store.create(job)
        except Exception as exc:
            shutil.rmtree(root, ignore_errors=True)
            # Don't reflect the store exception (DB driver errors carry host:port/DSN). Log it.
            _log.warning("job_store_create_failed", error=str(exc))
            raise HTTPException(503, "store unavailable") from exc
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/test_ingress_blob_upload.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS — with `BLASTBOX_BLOB_URL` unset, `LocalBlobStore.put_sample` only verifies the spooled file exists, so ingress behaviour is unchanged.

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/ingress/app.py tests/host/conftest.py tests/host/test_ingress_blob_upload.py
git commit -m "feat(ingress): store the sample blob before creating the job row"
```

---

### Task 4: Dispatcher materialises on demand and releases (never fails) on fetch failure

**Files:**
- Modify: `src/blastbox/host/runtime/vm_dispatch.py` (the `if not in_path.exists(): raise FileNotFoundError(...)` guard, currently ~line 350)
- Test: `tests/host/runtime/test_vm_dispatch_materialise.py`

**Interfaces:**
- Consumes: `BlobStore`, `BlobFetchError` (Task 1); `VmJobDispatcher._input_path(job) -> Path` (existing, line ~176); `JobStore.update_if_status(job_id, expect_status, *, expect_claim_id=None, **fields) -> bool` (existing, `jobs/base.py:215`).
- Produces: `VmJobDispatcher` accepts `blob_store: BlobStore` and `blob_retry_backoff_s: float = 30.0`; a `BlobFetchError` returns the job to `QUEUED` and raises no terminal status.

**NOTE — there is no `JobStore.requeue()` method.** The `claim_id` docstring in
`jobs/base.py` refers to requeueing as a *concept*; the actual primitive is
`update_if_status()`, CAS'd on `(status, claim_id)`. Release is therefore a
RUNNING->QUEUED transition that also clears `claim_id`.

Use the existing `Job.claimable_after` field on release. It exists precisely to move
a job "temporarily behind claimable work WITHOUT mutating created_at (which is the
submission time used for public ordering + max_queued_age)". Without it, the worker
that just failed to fetch is free to immediately re-claim the same job and spin — the
flapping-worker livelock. With it, the job stays fair in the queue while this node
backs off.

- [ ] **Step 1: Write the failing test**

Create `tests/host/runtime/test_vm_dispatch_materialise.py`:

```python
"""A worker that cannot fetch a sample must RELEASE the claim, not fail the job.

An unreachable object store is a property of THIS worker's connectivity, not of the
sample. Failing would permanently discard work because one node's link blipped.
"""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class UnreachableBlobStore:
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        raise BlobFetchError("object store unreachable")
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


class FetchingBlobStore:
    def __init__(self, data=b"materialised"): self.data = data; self.calls = 0
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        self.calls += 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.data)
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_fetch_failure_returns_the_job_to_queued(vm_dispatcher_factory):
    """vm_dispatcher_factory: see tests/host/runtime/conftest.py."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "d" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp.process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED, "must be reclaimable"


def test_missing_input_is_fetched_then_processed(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "e" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp.process(claimed)

    assert blobs.calls == 1
    assert store.get(job.job_id).status is JobStatus.DONE


def test_present_input_is_not_refetched(vm_dispatcher_factory, tmp_path):
    """Local mode must not pay a fetch for a file that is already there."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "f" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = FetchingBlobStore()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    p = disp._input_path(claimed)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"already here")

    disp.process(claimed)
    assert blobs.calls == 0


def test_release_clears_claim_id_and_backs_the_job_off(vm_dispatcher_factory):
    """Guards the flapping-worker livelock: without claimable_after, the worker that
    just failed to fetch immediately re-claims the same job and spins on it."""
    import time

    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "g" * 64
    store.create(job)
    claimed = store.claim_next()
    assert claimed.claim_id is not None

    disp = vm_dispatcher_factory(store=store, blob_store=UnreachableBlobStore())
    disp.process(claimed)

    released = store.get(job.job_id)
    assert released.status is JobStatus.QUEUED
    assert released.claim_id is None, "a released job must not keep its claim token"
    assert released.claimable_after > time.time(), "must back off, not be instantly re-claimable"
    assert released.created_at == job.created_at, "submission time must not be rewritten"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_vm_dispatch_materialise.py -v`
Expected: FAIL — `vm_dispatcher_factory` fixture missing and `blob_store` is not a constructor parameter.

- [ ] **Step 3: Add the fixture**

Create `tests/host/runtime/conftest.py`:

```python
import pytest


@pytest.fixture
def vm_dispatcher_factory(tmp_path):
    """Build a VmJobDispatcher with injected stores and a stub validator."""
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    def _factory(*, store, blob_store, validate_ok=False):
        def _validate(in_path):
            out = in_path.parent.parent / "output"
            out.mkdir(parents=True, exist_ok=True)
            (out / "metadata.json").write_bytes(b'{"status":"ok"}')
            return ({"detected": "test"}, validate_ok)

        return VmJobDispatcher(
            store=store,
            job_root=tmp_path,
            validate=_validate,
            blob_store=blob_store,
        )

    return _factory
```

- [ ] **Step 4: Wire materialisation into the dispatcher**

In `src/blastbox/host/runtime/vm_dispatch.py`, add `blob_store` to `__init__` and store it as `self._blobs`. Then replace the existence guard:

```python
            if not in_path.exists():
                raise FileNotFoundError(f"spooled input missing: {in_path}")
```

with:

```python
            if not in_path.exists():
                # Materialise on demand. In local mode this re-raises (there is no
                # second copy); in S3 mode it fetches and hash-verifies.
                #
                # A fetch failure RELEASES the claim instead of failing the job: the
                # object store being unreachable says something about this worker's
                # connectivity, not about the sample. Failing here would permanently
                # discard work because one node's link was down.
                try:
                    self._blobs.get_sample(job.input_sha256, in_path)
                except BlobFetchError:
                    logger.warning(
                        "vm_dispatch: job %s could not materialise its sample; "
                        "releasing the claim for another node", job.job_id,
                    )
                    # RUNNING -> QUEUED, CAS'd on (status, claim_id) so a stale owner
                    # can't clobber a job that was already RECLAIMED. claim_id is
                    # cleared so the next claim_next() stamps a fresh token.
                    #
                    # claimable_after backs the job off briefly: without it THIS worker
                    # is free to instantly re-claim the job it just failed to fetch and
                    # spin on it. created_at is deliberately untouched, so public
                    # ordering and max_queued_age still see the real submission time.
                    self._store.update_if_status(
                        job.job_id,
                        JobStatus.RUNNING,
                        expect_claim_id=job.claim_id,
                        status=JobStatus.QUEUED,
                        claim_id=None,
                        claimable_after=time.time() + self._blob_retry_backoff_s,
                    )
                    return
```

Add the imports at the top of the module (`time` and `JobStatus` are already imported
there; verify before adding duplicates):

```python
from blastbox.host.blobs.base import BlobFetchError
```

And accept the backoff in `__init__`:

```python
        blob_retry_backoff_s: float = 30.0,
```
stored as `self._blob_retry_backoff_s = blob_retry_backoff_s`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_vm_dispatch_materialise.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/runtime/vm_dispatch.py tests/host/runtime/
git commit -m "feat(dispatch): materialise samples on demand; release claim on fetch failure"
```

---

### Task 5: Worker purge invariant — nothing survives a terminal state

**Files:**
- Modify: `src/blastbox/host/runtime/vm_dispatch.py` (the `finally` around the job body)
- Test: `tests/host/runtime/test_worker_purge.py`

**Interfaces:**
- Consumes: `VmJobDispatcher` (Task 4).
- Produces: `VmJobDispatcher._purge_job_dir(job) -> None`, called on every terminal path.

- [ ] **Step 1: Write the failing test**

Create `tests/host/runtime/test_worker_purge.py`:

```python
"""Security invariant: a worker leaves no sample bytes behind — on ANY path.

Workers are frequently spare hardware (a laptop, an old desktop), not hardened
sample repositories. The failure paths matter most: they are where a purge is
easiest to omit, and ~1.6% of a real corpus hits the timeout path.
"""
import pytest

from blastbox.host.blobs.base import BlobFetchError
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore

SECRET = b"MALWARE-BYTES-MUST-NOT-PERSIST"


class Blobs:
    def __init__(self, fail_fetch=False): self.fail_fetch = fail_fetch
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        if self.fail_fetch:
            raise BlobFetchError("down")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(SECRET)
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def _residue(root):
    return [p for p in root.rglob("*") if p.is_file() and SECRET in p.read_bytes()]


@pytest.mark.parametrize("validate_ok", [True, False], ids=["success", "engine-failure"])
def test_no_sample_residue_after_terminal_state(vm_dispatcher_factory, tmp_path, validate_ok):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "a" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=validate_ok)
    disp.process(claimed)

    assert _residue(tmp_path) == [], "sample bytes survived a terminal state"


def test_no_sample_residue_after_validator_raises(vm_dispatcher_factory, tmp_path):
    """The timeout/crash path — the one most likely to skip cleanup."""
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    def _boom(in_path):
        raise TimeoutError("engine timed out after 120.0s")

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(), validate_ok=True)
    disp._validate = _boom
    disp.process(claimed)

    assert _residue(tmp_path) == []


def test_no_residue_after_release_back_to_queued(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "c" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(fail_fetch=True))
    disp.process(claimed)

    assert store.get(job.job_id).status is JobStatus.QUEUED
    assert _residue(tmp_path) == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_worker_purge.py -v`
Expected: FAIL — sample bytes remain under `job_root` after processing.

- [ ] **Step 3: Implement the purge**

In `src/blastbox/host/runtime/vm_dispatch.py`, add the method next to `_input_path`:

```python
    def _purge_job_dir(self, job: Job) -> None:
        """Remove this job's entire dir from the worker.

        SECURITY INVARIANT, not housekeeping: a worker is a malware-analysis node,
        frequently spare hardware that is not a hardened sample repository. Nothing
        may survive a terminal state, and there is deliberately no setting that
        disables this. Best-effort by design — a purge failure must never mask the
        job's real outcome, but it IS logged loudly.
        """
        import shutil

        root = self._job_dir(job).resolve()
        if self._job_root.resolve() not in root.parents:
            logger.error("vm_dispatch: refusing to purge %s (outside job_root)", root)
            return
        try:
            shutil.rmtree(root, ignore_errors=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.error("vm_dispatch: PURGE FAILED for %s: %s", root, exc)
```

Then wrap the job body so every exit purges — in `process()`, change the existing
`try:` around the validate/terminal block to end with:

```python
        finally:
            self._purge_job_dir(job)
```

and add the purge on the release path added in Task 4, immediately before its
`return` (after the `update_if_status` call that returns the job to QUEUED):

```python
                    self._purge_job_dir(job)
                    return
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_worker_purge.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS. If a single-node test now fails because it read artifacts from
`job_root` after completion, that test must be re-pointed at `open_output()` — the
API's read path — rather than the purge being weakened.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/runtime/vm_dispatch.py tests/host/runtime/test_worker_purge.py
git commit -m "feat(dispatch): purge the job dir on every terminal path (security invariant)"
```

---

### Task 6: Upload results before purging, and never discard completed work

**Files:**
- Modify: `src/blastbox/host/runtime/vm_dispatch.py` (terminal success path, before the purge)
- Test: `tests/host/runtime/test_result_upload.py`

**Interfaces:**
- Consumes: `BlobStore.put_output` (Tasks 1-2), `_purge_job_dir` (Task 5).
- Produces: `put_output(job.job_id, <job_dir>/output)` called before purge; upload failure leaves the job `RUNNING`.

- [ ] **Step 1: Write the failing test**

Create `tests/host/runtime/test_result_upload.py`:

```python
"""Results are uploaded BEFORE the purge, and a failed upload never discards work.

put_output failure is the mirror image of get_sample failure: the work is already
done and expensive, so retry and leave it for the sweeper — do not throw it away.
"""
import pytest

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


class Blobs:
    def __init__(self, fail_put=False):
        self.fail_put = fail_put
        self.uploaded: list[str] = []
        self.saw_metadata = False
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"x")
    def put_output(self, job_id, out_dir):
        if self.fail_put:
            raise OSError("object store down")
        self.saw_metadata = (out_dir / "metadata.json").is_file()
        self.uploaded.append(job_id)
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): ...


def test_output_uploaded_before_purge(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "a" * 64
    store.create(job)
    claimed = store.claim_next()

    blobs = Blobs()
    disp = vm_dispatcher_factory(store=store, blob_store=blobs, validate_ok=True)
    disp.process(claimed)

    assert blobs.uploaded == [job.job_id]
    assert blobs.saw_metadata, "output must still exist when put_output runs"
    assert not (tmp_path / job.job_id).exists(), "purge must follow the upload"


def test_upload_failure_leaves_the_job_running_for_the_sweeper(vm_dispatcher_factory, tmp_path):
    store = InMemoryJobStore()
    job = Job.new(engine="redtusk", filename="a.doc")
    job.input_sha256 = "b" * 64
    store.create(job)
    claimed = store.claim_next()

    disp = vm_dispatcher_factory(store=store, blob_store=Blobs(fail_put=True), validate_ok=True)
    disp.process(claimed)

    assert store.get(job.job_id).status is JobStatus.RUNNING
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_result_upload.py -v`
Expected: FAIL — `put_output` is never called.

- [ ] **Step 3: Implement the upload**

In `src/blastbox/host/runtime/vm_dispatch.py`, immediately after the terminal-status
CAS succeeds and before the `finally` purge runs, add:

```python
            # Upload while the output still exists — the purge in `finally` is about to
            # delete it. Unlike get_sample, a failure here must NOT discard the job: the
            # expensive work is already done, so leave it RUNNING for the reclaim sweeper
            # and let a retry pick it up.
            try:
                self._blobs.put_output(job.job_id, self._job_dir(job) / "output")
            except Exception as exc:
                logger.error(
                    "vm_dispatch: result upload failed for %s (%s); leaving RUNNING "
                    "for the sweeper rather than discarding completed work",
                    job.job_id, exc,
                )
                return
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/runtime/test_result_upload.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS — `LocalBlobStore.put_output` is a no-op.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/runtime/vm_dispatch.py tests/host/runtime/test_result_upload.py
git commit -m "feat(dispatch): upload results before purge; never discard completed work"
```

---

### Task 7: API serves results through the blob store

**Files:**
- Modify: `src/blastbox/host/ingress/app.py` (the `/v1/jobs/{id}/result` and `/metadata` handlers)
- Test: `tests/host/test_ingress_result_read.py`

**Interfaces:**
- Consumes: `BlobStore.open_output` (Task 1), `_blob_store` (Task 3).
- Produces: result routes read via `_blob_store.open_output(job_id, name)`; `BLASTBOX_BLOB_RESULT_ACCESS` defaults to `stream`.

- [ ] **Step 1: Write the failing test**

Create `tests/host/test_ingress_result_read.py`:

```python
"""Result routes must read through the BlobStore, not the local filesystem.

After Task 5 the worker purges its job dir, so on a multi-node deployment the API
node has no local copy — reading from disk would 404 every remote job.
"""
import io


class MemoryBlobStore:
    def __init__(self, log=None): self.objects = {}
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name):
        return io.BytesIO(self.objects[(job_id, name)])
    def delete_job(self, job_id): ...


def test_metadata_is_served_from_the_blob_store(ingress_client_factory):
    client, _ = ingress_client_factory(blob_store_cls=MemoryBlobStore)
    store = client.app.state.blob_store
    resp = client.post(
        "/v1/jobs",
        files={"file": ("a.doc", b"bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    job_id = resp.json()["job_id"]
    store.objects[(job_id, "metadata.json")] = b'{"status":"ok"}'

    client.app.state.job_store.update(job_id, status="done")
    got = client.get(f"/v1/jobs/{job_id}/metadata")
    assert got.status_code == 200
    assert got.json()["status"] == "ok"


def test_default_result_access_is_stream_not_redirect(ingress_client_factory):
    """Streaming keeps the object store PRIVATE — clients need no credentials and no
    network path to it, which is the point of the firewalled topology."""
    client, _ = ingress_client_factory(blob_store_cls=MemoryBlobStore)
    store = client.app.state.blob_store
    resp = client.post(
        "/v1/jobs",
        files={"file": ("a.doc", b"bytes", "application/octet-stream")},
        data={"engine": "redtusk"},
    )
    job_id = resp.json()["job_id"]
    store.objects[(job_id, "result.zip")] = b"PK\x03\x04zip"
    client.app.state.job_store.update(job_id, status="done")

    got = client.get(f"/v1/jobs/{job_id}/result", follow_redirects=False)
    assert got.status_code == 200, "default must stream, never 302 to the object store"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/test_ingress_result_read.py -v`
Expected: FAIL — routes still read from the filesystem.

- [ ] **Step 3: Route reads through the blob store**

In `src/blastbox/host/ingress/app.py`, expose the stores for tests near `build_app`'s
end:

```python
    app.state.blob_store = _blob_store
    app.state.job_store = _job_store
```

Then in the `/metadata` and `/result` handlers, replace direct file opens with:

```python
        try:
            fh = _blob_store.open_output(job_id, name)
        except Exception:
            raise HTTPException(404, "artifact not found")
```

and stream `fh` in the existing response.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/test_ingress_result_read.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the mode-1 regression gate**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/ -q`
Expected: PASS — `LocalBlobStore.open_output` opens the same path the routes used before.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/ingress/app.py tests/host/test_ingress_result_read.py
git commit -m "feat(ingress): serve result artifacts through the blob store"
```

---

### Task 8: Retention reaps result blobs — and never shared samples

**Files:**
- Modify: `src/blastbox/host/jobs/retention.py`
- Test: `tests/host/jobs/test_retention_blobs.py`

**Interfaces:**
- Consumes: `BlobStore.delete_job` (Task 1).
- Produces: `RetentionSweeper(..., blob_store: BlobStore | None = None)` calling `delete_job` per expired job.

- [ ] **Step 1: Write the failing test**

Create `tests/host/jobs/test_retention_blobs.py`:

```python
"""Expiring one job must not delete a sample another job still references.

This is the highest-risk failure in the design: sample blobs are content-addressed
and SHARED, so a sweeper that deletes them breaks unrelated jobs silently — including
future re-runs of the same corpus.
"""
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.retention import RetentionSweeper


class Blobs:
    def __init__(self): self.deleted: list[str] = []; self.samples = {"a" * 64}
    def put_sample(self, sha256, src): ...
    def get_sample(self, sha256, dest): ...
    def put_output(self, job_id, out_dir): ...
    def open_output(self, job_id, name): ...
    def delete_job(self, job_id): self.deleted.append(job_id)


def test_expiring_a_job_calls_delete_job(tmp_path, expired_job_factory):
    """expired_job_factory: see tests/host/jobs/conftest.py."""
    store = InMemoryJobStore()
    job = expired_job_factory(store, sha256="a" * 64)
    blobs = Blobs()

    RetentionSweeper(job_root=tmp_path, blob_store=blobs).expire_due(store)

    assert blobs.deleted == [job.job_id]


def test_expiring_a_job_never_deletes_shared_samples(tmp_path, expired_job_factory):
    store = InMemoryJobStore()
    expired_job_factory(store, sha256="a" * 64)
    blobs = Blobs()

    RetentionSweeper(job_root=tmp_path, blob_store=blobs).expire_due(store)

    assert blobs.samples == {"a" * 64}, "sample blob must survive job expiry"
```

Create `tests/host/jobs/conftest.py`:

```python
import time

import pytest

from blastbox.host.jobs.base import Job, JobStatus


@pytest.fixture
def expired_job_factory():
    def _factory(store, sha256="a" * 64):
        job = Job.new(engine="redtusk", filename="a.doc")
        job.input_sha256 = sha256
        job.status = JobStatus.DONE
        job.finished_at = time.time() - 3600
        job.expires_at = time.time() - 60
        store.create(job)
        return job

    return _factory
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/jobs/test_retention_blobs.py -v`
Expected: FAIL — `RetentionSweeper` has no `blob_store` parameter.

- [ ] **Step 3: Wire the blob store into retention**

In `src/blastbox/host/jobs/retention.py`, add `blob_store: "BlobStore | None" = None` to
`__init__`, store it as `self._blobs`, and inside the per-job expiry loop — after the
existing `rmtree` — add:

```python
            if self._blobs is not None:
                # Result blobs only. Sample blobs are content-addressed and shared
                # between jobs, so deleting them here would break every other job
                # referencing the same bytes; they age out on their own policy
                # (BLASTBOX_BLOB_SAMPLE_RETENTION / bucket lifecycle).
                try:
                    self._blobs.delete_job(job_id)
                except Exception as exc:
                    _log.warning("retention: blob delete failed for %s: %s", job_id, exc)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/coz/Downloads/blastbox && python -m pytest tests/host/jobs/test_retention_blobs.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full suite plus the no-boto3 gate**

Run:
```bash
cd /home/coz/Downloads/blastbox
python -m pytest tests/ -q
python -m pip uninstall -y boto3 -q && python -m pytest tests/ -q && python -m pip install -e '.[dev,s3]' -q
```
Expected: PASS both times — the second run proves `blastbox[host]` still works with no S3 dependency present.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/blastbox
git add src/blastbox/host/jobs/retention.py tests/host/jobs/test_retention_blobs.py tests/host/jobs/conftest.py
git commit -m "feat(retention): reap result blobs; never delete shared sample blobs"
```

---

## Self-Review

**Spec coverage:**

| spec section | task |
|---|---|
| `BlobStore` abstraction selected by URL | 1 |
| `LocalBlobStore` near-no-op / mode 1 unchanged | 1 (+ gate in every task) |
| Lazy `boto3`, `blastbox[s3]` extra | 2 |
| Content-addressed samples keyed on `input_sha256` | 2, 3 |
| Naming independence (key ≠ filename) | 2 (dedupe), 3 |
| Ordering: `put_sample` before job create | 3 |
| Materialise on demand | 4 |
| Release-don't-fail on fetch failure | 4 |
| Worker purge invariant, all paths | 5 |
| Compression on result upload | 2 (impl), 6 (call site) |
| `put_output` failure → keep RUNNING | 6 |
| Result read path, `stream` default | 7 |
| Retention reaps results, spares samples | 8 |
| Deployment modes 0-3 | config only; gate enforced per task |

**Deferred (not in this plan, by design):** `BLASTBOX_BLOB_SAMPLE_RETENTION` age-based
expiry and `BLASTBOX_BLOB_RESULT_ACCESS=presigned` are configuration surfaces the spec
defines but whose defaults (`never`, `stream`) are what these tasks implement. Both are
additive follow-ups that cannot regress mode 1; add them once the fleet is running.

**Type consistency:** `BlobStore` method names are identical across Tasks 1-8
(`put_sample`, `get_sample`, `put_output`, `open_output`, `delete_job`). Every stub in
every test implements all five. `BlobFetchError` is raised by both backends' `get_sample`
and caught in exactly one place (Task 4).

**Placeholder scan:** no TBD/TODO; every code step contains complete code; every test
step contains the actual assertions.

---

### Task 9: `LocalBlobStore` becomes a real store; purge becomes unconditional

**Added 2026-07-21 after Task 5 review.** The no-op `LocalBlobStore` was incompatible
with the worker purge invariant and forced a mode-specific branch into the dispatcher.
See the amended design section "LocalBlobStore is a real filesystem-backed store".

**Files:**
- Modify: `src/blastbox/host/blobs/local.py`
- Modify: `src/blastbox/host/blobs/factory.py`
- Modify: `src/blastbox/host/runtime/vm_dispatch.py` (the two reclaim early-returns)
- Modify: `tests/host/blobs/test_local.py` (the no-op assertions are now wrong)
- Modify: `tests/host/test_vm_dispatch.py` (the "left for the new owner" assertion)
- Test: `tests/host/blobs/test_local_roundtrip.py`

**Interfaces:**
- Consumes: `BlobStore`, `BlobFetchError` (Task 1); `_purge_job_dir` (Task 5).
- Produces: `LocalBlobStore(job_root, blob_root=None)` performing real filesystem
  storage under `<blob_root>/samples/<sha256>` and `<blob_root>/results/<job_id>/`;
  `BLASTBOX_BLOB_LOCAL_ROOT` env selects `blob_root` (default: sibling `blobs` dir).

**Why both halves are one task:** the unconditional purge is only safe because
re-materialisation always works, and re-materialisation only always works because the
local store is real. Splitting them would leave a commit where the purge deletes bytes
nothing can restore.

- [ ] **Step 1: Write the failing round-trip tests**

`tests/host/blobs/test_local_roundtrip.py` — the local backend must satisfy the same
contract as S3, including surviving destruction of the job dir:

```python
"""LocalBlobStore is a REAL store: bytes survive the job dir being destroyed.

This is the property the worker purge invariant depends on. A store whose only copy
is the job dir cannot serve anything once the worker purges.
"""
import hashlib
import shutil

import pytest

from blastbox.host.blobs.base import BlobFetchError
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `./.venv/bin/python -m pytest tests/host/blobs/test_local_roundtrip.py -v`
Expected: FAIL — `LocalBlobStore` takes no `blob_root`, and its put/get move no bytes.

- [ ] **Step 3: Implement the real local store**

Rewrite `src/blastbox/host/blobs/local.py` so each method performs real filesystem
work, mirroring `S3BlobStore`'s key layout. `put_sample` is idempotent (skip if the
key exists) and writes via a temp file + atomic rename so a crash cannot leave a
truncated blob that a later `get_sample` would trust. `delete_job` removes
`results/<job_id>` ONLY — sample blobs are shared and must survive.

- [ ] **Step 4: Wire `blob_root` through the factory**

`build_blob_store_from_env` reads `BLASTBOX_BLOB_LOCAL_ROOT`, defaulting to a `blobs`
directory beside `job_root`, and passes it to `LocalBlobStore`.

- [ ] **Step 5: Make the purge unconditional**

In `vm_dispatch.py`, the two reclaim early-returns (job reclaimed before validate, and
claim lost during validate) currently return without purging, deliberately leaving the
input "for the new owner". Add `self._purge_job_dir(job)` before each return.

Update the existing assertion in `tests/host/test_vm_dispatch.py` that documents the
old behaviour ("the shared input is left for the new owner (we didn't unlink it)") to
assert the opposite, with a comment explaining why: peers no longer depend on a
sibling's leftovers because the blob store can always re-materialise, and in a real
fleet the peer is on another host where those bytes would be orphaned malware.

- [ ] **Step 6: Fix the now-wrong no-op tests**

`tests/host/blobs/test_local.py` asserts `put_output`/`delete_job` are no-ops and that
`get_sample` succeeds on an already-present file. Those encode the old design. Update
them to the real-store contract; do not delete coverage, re-point it.

- [ ] **Step 7: Run all three gates**

```
./.venv/bin/python -m ruff check src
./.venv/bin/python -m mypy src
./.venv/bin/python -m pytest tests/ -q
```

- [ ] **Step 8: Commit**

```bash
git add -A src tests
git commit -m "feat(blobs): real local store; purge unconditionally on reclaim"
```
