"""Per-page perceptual-hash index + similarity search (SQLite path).

Exercises the optional ``index_page_hashes`` / ``find_*`` surface on
``SqlJobStore``: a sealed Envelope's ``Page.hashes`` are extracted and persisted,
then the four search methods (phash Hamming, colorhash exact, sha256 exact,
colorhash per-bin L1) are asserted to return the right matches inside and outside
their distance thresholds.

Postgres-only paths (bktree SP-GiST, colorhash_bin_distance) are NOT covered
here — gated by BLASTBOX_TEST_PG_DSN elsewhere; SQLite uses the in-Python
fallbacks, which is the default test backend.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.contract import (
    Dimensions,
    Hash,
    Page,
    int8_to_phash_hex,
    phash_hex_to_int8,
    seal_envelope,
)
from blastbox.contract.leaf import ArtifactRef, Detection
from blastbox.contract.nodes import EmbeddedResource
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.sql_store import SqlJobStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ZERO_SHA = "0" * 64


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    return SqlJobStore(f"sqlite:///{db}")


def _phash_hex(value: int) -> str:
    """Render an unsigned 64-bit int as a 16-char phash hex string."""
    return f"{value & ((1 << 64) - 1):016x}"


def _make_page(
    index: int,
    *,
    phash: str | None = None,
    colorhash: str | None = None,
    sha256: str | None = None,
    artifact_id: str = "img0",
) -> Page:
    hashes: list[Hash] = []
    if phash is not None:
        hashes.append(Hash(algo="phash", value=phash))
    if colorhash is not None:
        hashes.append(Hash(algo="colorhash", value=colorhash))
    if sha256 is not None:
        hashes.append(Hash(algo="sha256", value=sha256))
    return Page(
        index=index,
        dims=Dimensions(width=100.0, height=100.0, unit="px"),
        image=ArtifactRef(id=artifact_id),
        hashes=hashes,
    )


def _seal_with_pages(outdir: Path, pages: list[Page]):
    """Build a real sealed Envelope whose payload root holds the given pages.

    Writes one tiny artifact file per distinct ArtifactRef the pages reference
    so seal_envelope's confinement + ref-resolution checks pass.
    """
    ref_ids = sorted({p.image.id for p in pages})
    declared = []
    from blastbox.contract import DeclaredArtifact

    for rid in ref_ids:
        rel = f"{rid}.png"
        (outdir / rel).write_bytes(b"\x89PNG\r\n\x1a\n" + rid.encode())
        declared.append(DeclaredArtifact(id=rid, path=rel, kind="page-image"))
    root = EmbeddedResource(
        embedded_path="doc",
        content_type="application/octet-stream",
        depth=0,
        children=list(pages),
    )
    return seal_envelope(
        engine="test-engine",
        outdir=outdir,
        input_sha256=ZERO_SHA,
        detected=Detection(label="test", mime="text/plain", confidence=1.0, source="t"),
        declared=declared,
        warnings=[],
        payload=root,
    )


def _done_job(store: SqlJobStore, *, filename: str = "doc.pdf") -> Job:
    job = Job.new(engine="test-engine", filename=filename)
    store.create(job)
    store.update(job.job_id, status=JobStatus.DONE)
    return job


# ---------------------------------------------------------------------------
# Extraction: index_page_hashes walks the typed envelope
# ---------------------------------------------------------------------------

def test_index_page_hashes_extracts_and_persists(store, tmp_path):
    job = _done_job(store)
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, phash="00000000000000ff", colorhash="0011223344556a", sha256="a" * 64),
            _make_page(1, phash="ffffffffffffffff", colorhash="ffeeddccbbaa99", sha256="b" * 64),
        ],
    )
    written = store.index_page_hashes(job.job_id, env)
    assert written == 2
    # sha256 exact lookup confirms both rows landed.
    assert len(store.find_by_page_sha256("a" * 64)) == 1
    assert len(store.find_by_page_sha256("b" * 64)) == 1


def test_index_is_idempotent_upsert(store, tmp_path):
    job = _done_job(store)
    env = _seal_with_pages(tmp_path, [_make_page(0, phash="0" * 16, colorhash="0" * 14, sha256="c" * 64)])
    store.index_page_hashes(job.job_id, env)
    store.index_page_hashes(job.job_id, env)  # second call must not duplicate
    assert len(store.find_by_page_sha256("c" * 64)) == 1


def test_page_with_only_some_hashes_is_indexed(store, tmp_path):
    """A page with colorhash+sha256 but no phash is still stored (phash NULL)."""
    job = _done_job(store)
    env = _seal_with_pages(tmp_path, [_make_page(0, colorhash="1234567890abcd", sha256="d" * 64)])
    assert store.index_page_hashes(job.job_id, env) == 1
    # Exact lookups work; phash search simply won't surface a NULL-phash row.
    assert len(store.find_by_colorhash("1234567890abcd")) == 1
    assert store.find_similar_phash(phash_hex_to_int8("0" * 16), max_distance=64) == []


def test_page_with_no_hashes_is_skipped(store, tmp_path):
    job = _done_job(store)
    env = _seal_with_pages(tmp_path, [_make_page(0)])  # no hashes at all
    assert store.index_page_hashes(job.job_id, env) == 0


# ---------------------------------------------------------------------------
# find_by_page_sha256 / find_by_colorhash — exact match + DONE gating
# ---------------------------------------------------------------------------

def test_exact_lookups_only_return_done_jobs(store, tmp_path):
    done = _done_job(store, filename="done.pdf")
    running = Job.new(engine="test-engine", filename="running.pdf")
    store.create(running)
    store.update(running.job_id, status=JobStatus.RUNNING)

    env_done = _seal_with_pages(tmp_path / "d", _mkdir(tmp_path / "d", [_make_page(0, colorhash="aaaaaaaaaaaaaa", sha256="1" * 64)]))
    env_run = _seal_with_pages(tmp_path / "r", _mkdir(tmp_path / "r", [_make_page(0, colorhash="aaaaaaaaaaaaaa", sha256="2" * 64)]))
    store.index_page_hashes(done.job_id, env_done)
    store.index_page_hashes(running.job_id, env_run)

    hits = store.find_by_colorhash("aaaaaaaaaaaaaa")
    assert len(hits) == 1
    assert hits[0]["job_id"] == done.job_id
    assert hits[0]["filename"] == "done.pdf"


def test_find_by_colorhash_no_match(store, tmp_path):
    job = _done_job(store)
    env = _seal_with_pages(tmp_path, [_make_page(0, colorhash="00000000000000", sha256="e" * 64)])
    store.index_page_hashes(job.job_id, env)
    assert store.find_by_colorhash("ffffffffffffff") == []


# ---------------------------------------------------------------------------
# find_similar_phash — Hamming distance threshold
# ---------------------------------------------------------------------------

def test_find_similar_phash_within_and_outside_threshold(store, tmp_path):
    job = _done_job(store)
    # base = all zeros. near = 3 bits set (Hamming 3). far = 40 bits set.
    base = _phash_hex(0)
    near = _phash_hex(0b111)  # exactly 3 set bits
    far = _phash_hex((1 << 40) - 1)  # 40 set bits
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, phash=base, sha256="0" * 64, artifact_id="i0"),
            _make_page(1, phash=near, sha256="1" * 64, artifact_id="i1"),
            _make_page(2, phash=far, sha256="2" * 64, artifact_id="i2"),
        ],
    )
    store.index_page_hashes(job.job_id, env)

    target = phash_hex_to_int8(base)

    # distance <= 5 -> base (0) and near (3), not far (40)
    hits = store.find_similar_phash(target, max_distance=5)
    dists = {h["page_index"]: h["distance"] for h in hits}
    assert dists == {0: 0, 1: 3}

    # tighten to <= 2 -> only the exact match
    hits = store.find_similar_phash(target, max_distance=2)
    assert {h["page_index"] for h in hits} == {0}

    # widen to <= 64 -> all three
    hits = store.find_similar_phash(target, max_distance=64)
    assert {h["page_index"] for h in hits} == {0, 1, 2}


def test_find_similar_phash_high_bit_roundtrip(store, tmp_path):
    """A phash with the top bit set must round-trip through signed-int8 storage
    and still compute the correct Hamming distance (the sign-reinterpret bug)."""
    job = _done_job(store)
    high = _phash_hex(1 << 63)  # top bit only -> Hamming 1 from zero
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, phash=_phash_hex(0), sha256="0" * 64, artifact_id="i0"),
            _make_page(1, phash=high, sha256="1" * 64, artifact_id="i1"),
        ],
    )
    store.index_page_hashes(job.job_id, env)
    target = phash_hex_to_int8(_phash_hex(0))
    hits = store.find_similar_phash(target, max_distance=1)
    dists = {h["page_index"]: h["distance"] for h in hits}
    assert dists == {0: 0, 1: 1}
    # The stored signed value reinterprets back to the original unsigned hex.
    high_row = next(h for h in hits if h["page_index"] == 1)
    assert int8_to_phash_hex(high_row["phash"]) == high


def test_find_similar_phash_ordering_and_limit(store, tmp_path):
    job = _done_job(store)
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, phash=_phash_hex(0b1111), sha256="0" * 64, artifact_id="i0"),   # d=4
            _make_page(1, phash=_phash_hex(0b1), sha256="1" * 64, artifact_id="i1"),      # d=1
            _make_page(2, phash=_phash_hex(0b11), sha256="2" * 64, artifact_id="i2"),     # d=2
        ],
    )
    store.index_page_hashes(job.job_id, env)
    target = phash_hex_to_int8(_phash_hex(0))
    hits = store.find_similar_phash(target, max_distance=64)
    assert [h["distance"] for h in hits] == [1, 2, 4]  # ascending by distance
    # limit truncates after ordering
    assert [h["distance"] for h in store.find_similar_phash(target, max_distance=64, limit=2)] == [1, 2]


# ---------------------------------------------------------------------------
# find_similar_colorhash — per-bin L1
# ---------------------------------------------------------------------------

def test_find_similar_colorhash_total_cap(store, tmp_path):
    job = _done_job(store)
    # target 0000000000000; near differs by 3 in one bin (L1 3); far by 15.
    target = "0" * 14
    near = "3" + "0" * 13       # total L1 = 3
    far = "f" + "0" * 13        # total L1 = 15
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, colorhash=target, sha256="0" * 64, artifact_id="i0"),
            _make_page(1, colorhash=near, sha256="1" * 64, artifact_id="i1"),
            _make_page(2, colorhash=far, sha256="2" * 64, artifact_id="i2"),
        ],
    )
    store.index_page_hashes(job.job_id, env)

    hits = store.find_similar_colorhash(target, total_max=5)
    got = {h["page_index"]: h["distance"] for h in hits}
    assert got == {0: 0, 1: 3}

    hits = store.find_similar_colorhash(target, total_max=20)
    assert {h["page_index"] for h in hits} == {0, 1, 2}


def test_find_similar_colorhash_skips_non_hex_rows(store):
    """A stored colorhash with non-hex chars (buggy/hostile engine) must not
    crash the L1 search — the corrupt row is skipped, valid matches still surface."""
    job = _done_job(store)
    store.upsert_page_hashes(
        job.job_id,
        [
            {"page_index": 0, "phash": None, "colorhash": "0" * 14, "sha256": "0" * 64},
            {"page_index": 1, "phash": None, "colorhash": "z" * 14, "sha256": "1" * 64},
        ],
    )
    hits = store.find_similar_colorhash("0" * 14, total_max=5)
    assert {h["page_index"] for h in hits} == {0}


def test_find_similar_colorhash_no_caps_delegates_to_exact(store, tmp_path):
    job = _done_job(store)
    target = "1234567890abcd"
    env = _seal_with_pages(
        tmp_path,
        [
            _make_page(0, colorhash=target, sha256="0" * 64, artifact_id="i0"),
            _make_page(1, colorhash="1234567890abce", sha256="1" * 64, artifact_id="i1"),
        ],
    )
    store.index_page_hashes(job.job_id, env)
    hits = store.find_similar_colorhash(target)  # no caps -> exact match only
    assert {h["page_index"] for h in hits} == {0}


def test_find_similar_colorhash_per_group_caps_are_cumulative_and(store, tmp_path):
    job = _done_job(store)
    target = "0" * 14
    # Differs only in a BRIGHT bin (index 8) by 4: passes frac/faint caps,
    # fails a strict bright cap.
    bright = "0" * 8 + "4" + "0" * 5
    env = _seal_with_pages(
        tmp_path,
        [_make_page(0, colorhash=bright, sha256="0" * 64, artifact_id="i0")],
    )
    store.index_page_hashes(job.job_id, env)

    # frac/faint are 0, bright distance is 4 -> all caps satisfied at >=4
    hits = store.find_similar_colorhash(target, frac_max=0, faint_max=0, bright_max=4)
    assert len(hits) == 1
    row = hits[0]
    assert row["frac_distance"] == 0
    assert row["faint_distance"] == 0
    assert row["bright_distance"] == 4

    # tightening the bright cap below 4 drops it (cumulative AND)
    assert store.find_similar_colorhash(target, bright_max=3) == []
    # ...even though a generous total cap alone would keep it
    assert len(store.find_similar_colorhash(target, total_max=10)) == 1
    assert store.find_similar_colorhash(target, total_max=10, bright_max=3) == []


def test_search_methods_are_optional_on_protocol(store):
    """SqlJobStore satisfies the optional PageHashSearch protocol; the in-memory
    store does NOT (consumers feature-detect, never assume)."""
    from blastbox.host.jobs.base import PageHashSearch
    from blastbox.host.jobs.memory import InMemoryJobStore

    mem = InMemoryJobStore()
    assert not isinstance(mem, PageHashSearch)
    assert not hasattr(mem, "index_page_hashes")
    assert not hasattr(mem, "find_similar_phash")

    assert isinstance(store, PageHashSearch)


# ---------------------------------------------------------------------------
# small local helper used by the DONE-gating test
# ---------------------------------------------------------------------------

def _mkdir(path: Path, pages: list[Page]) -> list[Page]:
    path.mkdir(parents=True, exist_ok=True)
    return pages
