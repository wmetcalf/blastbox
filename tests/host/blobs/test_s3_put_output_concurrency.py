"""put_output uploads artifacts CONCURRENTLY without weakening the two-phase commit.

Measured on the fleet (200 corpus documents, FC tier, 24 slots): the result upload was 39.7% of
all job-seconds -- a larger share than extraction itself (38.0%) -- and its cost tracked artifact
COUNT, not bytes:

    821 artifacts -> 63.3s      66 -> 34.2s       5 -> 3.8s      1 -> 0.35s
    116 artifacts -> 43.4s      60 -> 30.9s       4 -> 3.8s      0 -> 0.65s

i.e. one sequential round-trip per object against a MinIO on the same host. Fanning those out is
the single largest throughput lever left on the tier.

What must NOT change, and is what these tests are really about -- the durability barrier:

    metadata.json (the seal) is written LAST, so its presence under results/<job_id> means every
    other artifact already landed.

That is what makes has_output() a real answer rather than a guess, and the age-reclaim sweep
deletes the complete LOCAL tree on the strength of it. A seal that commits ahead of its artifacts
produces a DONE job whose manifest promises bytes the store does not have, reported as durable,
with the only real copy deleted. Concurrency is exactly the kind of change that breaks an
ordering invariant quietly, so every test here is aimed at the barrier, not at the speed.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from blastbox.host.blobs.s3 import S3BlobStore  # noqa: E402 -- after importorskip

BUCKET = "bb-conc"
SEAL = "metadata.json"


def _out_dir(tmp_path, n_artifacts: int, *, declare: bool = True):
    """An output dir with *n_artifacts* files plus a sealing metadata.json."""
    out = tmp_path / "job" / "output"
    out.mkdir(parents=True)
    arts = []
    for i in range(n_artifacts):
        name = f"page-{i:03d}.png"
        (out / name).write_bytes(f"PNG{i}".encode())
        arts.append(
            {"id": name, "path": name, "kind": "image", "sha256": "0" * 64, "bytes": 4}
        )
    (out / SEAL).write_text(
        json.dumps(
            {
                "engine": "t",
                "status": "ok",
                "input_sha256": "a" * 64,
                "artifacts": arts if declare else [],
            }
        )
    )
    return out


class _RecordingS3:
    """Stands in for the boto3 client. Records the ORDER of put_object calls."""

    def __init__(self, *, delay: float = 0.0, fail_on: str | None = None) -> None:
        self.delay = delay
        self.fail_on = fail_on
        self.calls: list[str] = []
        self.threads: list[str] = []
        self.concurrent = 0
        self.max_concurrent = 0
        self._lock = threading.Lock()

    def put_object(self, *, Bucket, Key, Body, **kw):  # noqa: N803 -- boto3's own kwarg names
        with self._lock:
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.fail_on and Key.endswith(self.fail_on):
                raise RuntimeError(f"object store said no: {Key}")
            with self._lock:
                self.calls.append(Key)
                self.threads.append(threading.current_thread().name)
        finally:
            with self._lock:
                self.concurrent -= 1


def _store(tmp_path, s3, **env):
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        st = S3BlobStore(f"s3://{BUCKET}/pfx", job_root=tmp_path, env=env)
    st._s3 = s3  # swap in the recorder AFTER construction
    st._compress = False  # gzip is orthogonal here and only obscures the bodies
    return st


# ── the durability barrier ──────────────────────────────────────────────────────────────


def test_the_seal_is_written_after_every_artifact(tmp_path):
    """MUTATION: submit the seal into the pool with the rest -> it lands mid-stream and this
    fails. That ordering IS the durability guarantee; nothing else in the system re-checks it."""
    s3 = _RecordingS3()
    _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="8").put_output(
        "j", _out_dir(tmp_path, 40)
    )

    assert len(s3.calls) == 41
    assert s3.calls[-1].endswith(SEAL), (
        f"the seal must be the LAST put; it was at index {s3.calls.index(next(c for c in s3.calls if c.endswith(SEAL)))}"
    )
    assert sum(c.endswith(SEAL) for c in s3.calls) == 1


def test_a_failed_artifact_never_lets_the_seal_commit(tmp_path):
    """The expensive failure: seal present, artifacts missing -> has_output() says durable, the
    reclaim deletes the only complete copy, and the job serves bytes nobody has.

    MUTATION: swallow a worker's exception (or write the seal outside the success path) -> the
    seal lands anyway and this fails on both assertions.
    """
    s3 = _RecordingS3(fail_on="page-017.png")
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="8")

    with pytest.raises(Exception, match="object store said no"):
        store.put_output("j", _out_dir(tmp_path, 40))

    assert not any(c.endswith(SEAL) for c in s3.calls), (
        "the seal was committed even though an artifact upload failed"
    )


def test_every_stored_artifact_is_counted_toward_the_declared_check(tmp_path):
    """`stored` feeds _assert_declared_landed, which refuses the seal unless every DECLARED
    artifact actually landed. Under concurrency that set is built from many threads.

    MUTATION: collect `stored` from only the futures that finished first (or drop the lock and
    lose entries) -> the check sees phantom-missing artifacts and put_output raises, so this
    fails on a perfectly healthy upload.
    """
    s3 = _RecordingS3()
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="16")
    store.put_output("j", _out_dir(tmp_path, 200, declare=True))  # all 200 declared

    assert len(s3.calls) == 201


# ── that it is actually concurrent ──────────────────────────────────────────────────────


def test_uploads_actually_overlap(tmp_path):
    """Without this, the entire change can no-op and every other test still passes.

    MUTATION: revert to the serial `for path in _upload_order(...)` loop -> max_concurrent is 1.
    """
    s3 = _RecordingS3(delay=0.05)
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="8")

    t0 = time.monotonic()
    store.put_output("j", _out_dir(tmp_path, 32))
    elapsed = time.monotonic() - t0

    assert s3.max_concurrent > 1, "uploads never overlapped — still serial"
    # 32 objects x 50ms serial = 1.6s; at 8-way it should be nearer 0.2s + the seal.
    assert elapsed < 0.9, (
        f"32 x 50ms uploads took {elapsed:.2f}s — not meaningfully parallel"
    )


def test_concurrency_of_one_bypasses_the_pool_entirely(tmp_path):
    """The escape hatch. An operator who suspects the fan-out must get the ORIGINAL code path
    back -- uploads on the calling thread, no executor in the stack -- not a one-worker pool that
    merely behaves similarly. `max_concurrent == 1` alone does NOT distinguish those (a
    max_workers=1 pool never overlaps either), which is exactly why an earlier version of this
    test let `if self._upload_concurrency <= 0:` survive untouched.

    MUTATION: route concurrency=1 through the executor -> the puts run on a `bb-put` thread and
    this fails.
    """
    s3 = _RecordingS3(delay=0.01)
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="1")
    store.put_output("j", _out_dir(tmp_path, 12))

    assert s3.max_concurrent == 1, "concurrency=1 still overlapped uploads"
    caller = threading.current_thread().name
    assert set(s3.threads) == {caller}, (
        f"concurrency=1 must upload on the calling thread; it used {sorted(set(s3.threads))}"
    )
    assert s3.calls[-1].endswith(SEAL)


def test_a_bad_concurrency_setting_falls_back_instead_of_crashing(tmp_path):
    """An operator typo in a deployment env must not take the upload path down -- this runs after
    the detonation, holding a result that only exists locally.

    MUTATION: int(raw) with no guard -> ValueError propagates and every job fails to upload.
    """
    for bad in ("", "banana", "0", "-4"):
        s3 = _RecordingS3()
        _store(tmp_path / bad, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY=bad).put_output(
            "j", _out_dir(tmp_path / bad, 3)
        )
        assert s3.calls[-1].endswith(SEAL), (
            f"upload broke for BLASTBOX_BLOB_UPLOAD_CONCURRENCY={bad!r}"
        )


def test_a_declared_artifact_the_walker_missed_still_blocks_the_seal(tmp_path):
    """The check the fan-out must not lose: `stored` is compared against the MANIFEST before the
    seal is allowed to commit.

    A worker controls its own output tree, so it can declare a path the walker never returns --
    rglob does not descend a symlinked directory, so `link/hidden.png` is a real file on disk that
    is neither uploaded nor skipped, it is simply absent. Committing the seal anyway produces a
    DONE job whose manifest promises bytes the store does not have, reported durable by
    has_output(), with the complete local copy then deleted as redundant.

    MUTATION: drop `before_put=` from the seal put (the fan-out makes this a one-word change,
    since the check no longer sits inline in the loop) -> the seal commits over a missing declared
    artifact and this fails.
    """
    out = tmp_path / "job" / "output"
    (out / "real").mkdir(parents=True)
    (out / "real" / "hidden.png").write_bytes(b"PNGX")
    (out / "link").symlink_to(out / "real", target_is_directory=True)
    (out / "page-000.png").write_bytes(b"PNG0")
    (out / SEAL).write_text(
        json.dumps(
            {
                "engine": "t",
                "status": "ok",
                "input_sha256": "a" * 64,
                "artifacts": [
                    {
                        "id": "a",
                        "path": "page-000.png",
                        "kind": "image",
                        "sha256": "0" * 64,
                        "bytes": 4,
                    },
                    # real file, but reachable only THROUGH the symlinked dir the walker will not enter
                    {
                        "id": "b",
                        "path": "link/hidden.png",
                        "kind": "image",
                        "sha256": "0" * 64,
                        "bytes": 4,
                    },
                ],
            }
        )
    )

    # sanity: the scenario is real -- the leaf is a genuine file, not a symlink
    assert (out / "link" / "hidden.png").is_file()
    assert not (out / "link" / "hidden.png").is_symlink()

    s3 = _RecordingS3()
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY="8")

    with pytest.raises(Exception, match="not stored"):
        store.put_output("j", out)

    assert not any(c.endswith(SEAL) for c in s3.calls), (
        "the seal committed while a DECLARED artifact was never stored"
    )


def test_concurrent_jobs_share_one_upload_budget(tmp_path):
    """The fan-out budget is PER DISPATCHER, not per job.

    The dispatcher builds one S3BlobStore and shares its boto3 client -- and therefore one
    connection pool -- across every concurrent job. A per-call executor passes every other test
    in this file and is badly wrong in production: 24 slots x 8 workers is 192 threads queueing
    on a 10-connection pool, so the fan-out is fake past the tenth and the rest is pure
    contention. Measured on the fleet when it was per-call: upload's share halved as intended
    while purge, commit, rdump and fetch -- none of which touch this code -- all got 3-4x
    SLOWER, and per-job p50 rose from 12.8s to 19.6s.

    MUTATION: build a ThreadPoolExecutor inside put_output instead of reusing the shared one ->
    4 concurrent jobs reach ~4x the configured concurrency and this fails.
    """
    limit = 4
    s3 = _RecordingS3(delay=0.02)
    store = _store(tmp_path, s3, BLASTBOX_BLOB_UPLOAD_CONCURRENCY=str(limit))

    dirs = []
    for n in range(4):
        d = tmp_path / f"j{n}" / "output"
        d.mkdir(parents=True)
        for i in range(12):
            (d / f"page-{i:03d}.png").write_bytes(b"PNG")
        (d / SEAL).write_text(
            json.dumps(
                {
                    "engine": "t",
                    "status": "ok",
                    "input_sha256": "a" * 64,
                    "artifacts": [],
                }
            )
        )
        dirs.append((f"j{n}", d))

    threads = [
        threading.Thread(target=store.put_output, args=(jid, d)) for jid, d in dirs
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(s3.calls) == 4 * 13
    assert s3.max_concurrent <= limit, (
        f"4 concurrent jobs reached {s3.max_concurrent} simultaneous uploads against a budget of "
        f"{limit} — the executor is per-job, not per-dispatcher"
    )
    assert s3.max_concurrent > 1, (
        "no overlap at all — the shared pool is not being used"
    )


@pytest.mark.parametrize("configured,expected_min", [("4", 10), ("16", 16), ("64", 64)])
def test_the_connection_pool_is_sized_to_the_upload_budget(
    tmp_path, configured, expected_min
):
    """botocore's connection pool defaults to 10. A fan-out wider than the pool does not error --
    it BLOCKS, so the change looks deployed, measures as no faster, and gives no clue why. No
    behavioural test can see this (a fake client has no pool), so assert the config directly.

    The floor stays at botocore's 10 for small budgets: shrinking the pool below the default
    would be a regression for the sample get/put path, which shares this client.

    MUTATION: pin max_pool_connections to 10 -> a 16- or 64-wide budget queues on ten sockets and
    this fails.
    """
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        store = S3BlobStore(
            f"s3://{BUCKET}/pfx",
            job_root=tmp_path,
            env={"BLASTBOX_BLOB_UPLOAD_CONCURRENCY": configured},
        )

    assert store._upload_concurrency == int(configured)
    assert store._s3.meta.config.max_pool_connections == expected_min, (
        f"budget {configured} against a pool of "
        f"{store._s3.meta.config.max_pool_connections} — the fan-out will block on sockets"
    )
