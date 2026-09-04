"""HTTP tests for the generic ``GET /v1/similar`` route (capability-gated).

The route is mounted by ``build_app`` only when the store supports perceptual-hash
search — **Postgres + pg_bktree only**.  The capability-gate tests (route absent
for memory + SQLite stores) run anywhere; the match-semantics + validation tests
need a real PG+bktree and are gated on ``BLASTBOX_TEST_PG_DSN`` (CI builds one from
``deploy/docker/postgres``).  They skip when the DSN is unset / the extension is
absent.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from blastbox.contract import phash_hex_to_int8
from blastbox.host.ingress.app import build_app
from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore
from blastbox.host.jobs.sql_store import SqlJobStore


def _phash_hex(value: int) -> str:
    return f"{value & ((1 << 64) - 1):016x}"


def _client(store, tmp_path) -> TestClient:
    app = build_app(job_store=store, job_root=tmp_path / "jobs", allowed_engines={"e"})
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def pg_store():
    dsn = os.environ.get("BLASTBOX_TEST_PG_DSN")
    if not dsn:
        pytest.skip(
            "BLASTBOX_TEST_PG_DSN not set (search is Postgres + pg_bktree only)"
        )
    s = SqlJobStore(dsn)
    if not s.supports_hash_search():
        pytest.skip("pg_bktree extension not available on the test Postgres")
    with s._lock, s._connect() as conn:
        conn.execute("TRUNCATE jobs CASCADE")
    return s


def _done_job_with_pages(store, *, filename: str, rows: list[dict]) -> Job:
    job = Job.new(engine="e", filename=filename)
    store.create(job)
    store.update(job.job_id, status=JobStatus.DONE)
    store.upsert_page_hashes(job.job_id, rows)
    return job


# ---------------------------------------------------------------------------
# Capability gate (no DB needed)
# ---------------------------------------------------------------------------


def test_route_absent_for_memory_store(tmp_path):
    """A store without search support => the route is never mounted => 404."""
    client = _client(InMemoryJobStore(), tmp_path)
    assert client.get("/v1/similar", params={"sha256": "a" * 64}).status_code == 404


def test_route_absent_for_sqlite_store(tmp_path):
    """A SQL store on SQLite HAS the search methods but supports_hash_search() is
    False -> route not mounted -> 404 (never a 500 from a raising handler)."""
    store = SqlJobStore(f"sqlite:///{tmp_path / 'jobs.db'}")
    client = _client(store, tmp_path)
    assert client.get("/v1/similar", params={"sha256": "a" * 64}).status_code == 404


# ---------------------------------------------------------------------------
# PG+bktree: route present + match semantics
# ---------------------------------------------------------------------------


def test_route_present_for_pg_store(pg_store, tmp_path):
    client = _client(pg_store, tmp_path)
    resp = client.get("/v1/similar", params={"sha256": "a" * 64})
    assert resp.status_code == 200
    assert resp.json() == {"results": []}


def test_phash_search_within_hamming(pg_store, tmp_path):
    base, near, far = _phash_hex(0), _phash_hex(0b111), _phash_hex((1 << 40) - 1)
    _done_job_with_pages(
        pg_store,
        filename="doc.pdf",
        rows=[
            {
                "page_index": 0,
                "phash": phash_hex_to_int8(base),
                "colorhash": None,
                "sha256": "0" * 64,
            },
            {
                "page_index": 1,
                "phash": phash_hex_to_int8(near),
                "colorhash": None,
                "sha256": "1" * 64,
            },
            {
                "page_index": 2,
                "phash": phash_hex_to_int8(far),
                "colorhash": None,
                "sha256": "2" * 64,
            },
        ],
    )
    client = _client(pg_store, tmp_path)
    resp = client.get("/v1/similar", params={"phash": base, "max_hamming": 5})
    assert resp.status_code == 200
    results = resp.json()["results"]
    dists = {r["page_index"]: r["distance"] for r in results}
    assert dists == {0: 0, 1: 3}
    assert {r["phash"] for r in results} == {base, near}  # rendered back to hex
    assert all(r["filename"] == "doc.pdf" for r in results)


def test_colorhash_exact_match(pg_store, tmp_path):
    _done_job_with_pages(
        pg_store,
        filename="a.pdf",
        rows=[
            {
                "page_index": 0,
                "phash": None,
                "colorhash": "1234567890abcd",
                "sha256": "0" * 64,
            }
        ],
    )
    client = _client(pg_store, tmp_path)
    resp = client.get("/v1/similar", params={"colorhash": "1234567890abcd"})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert results[0]["colorhash"] == "1234567890abcd"
    assert results[0]["variant"] == "original"


def test_colorhash_fuzzy_total_cap(pg_store, tmp_path):
    target = "0" * 14
    near = "3" + "0" * 13  # total L1 = 3
    far = "f" + "0" * 13  # total L1 = 15
    _done_job_with_pages(
        pg_store,
        filename="a.pdf",
        rows=[
            {"page_index": 0, "phash": None, "colorhash": target, "sha256": "0" * 64},
            {"page_index": 1, "phash": None, "colorhash": near, "sha256": "1" * 64},
            {"page_index": 2, "phash": None, "colorhash": far, "sha256": "2" * 64},
        ],
    )
    client = _client(pg_store, tmp_path)
    resp = client.get(
        "/v1/similar", params={"colorhash": target, "colorhash_distance": 5}
    )
    assert resp.status_code == 200
    got = {r["page_index"]: r["distance"] for r in resp.json()["results"]}
    assert got == {0: 0, 1: 3}


def test_sha256_exact_match(pg_store, tmp_path):
    _done_job_with_pages(
        pg_store,
        filename="a.pdf",
        rows=[{"page_index": 0, "phash": None, "colorhash": None, "sha256": "d" * 64}],
    )
    client = _client(pg_store, tmp_path)
    resp = client.get("/v1/similar", params={"sha256": "d" * 64})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert results[0]["sha256"] == "d" * 64
    assert results[0]["distance"] is None


def test_only_done_jobs_surface(pg_store, tmp_path):
    _done_job_with_pages(
        pg_store,
        filename="done.pdf",
        rows=[
            {
                "page_index": 0,
                "phash": None,
                "colorhash": "aaaaaaaaaaaaaa",
                "sha256": "1" * 64,
            }
        ],
    )
    running = Job.new(engine="e", filename="running.pdf")
    pg_store.create(running)
    pg_store.update(running.job_id, status=JobStatus.RUNNING)
    pg_store.upsert_page_hashes(
        running.job_id,
        [
            {
                "page_index": 0,
                "phash": None,
                "colorhash": "aaaaaaaaaaaaaa",
                "sha256": "2" * 64,
            }
        ],
    )
    client = _client(pg_store, tmp_path)
    results = client.get("/v1/similar", params={"colorhash": "aaaaaaaaaaaaaa"}).json()[
        "results"
    ]
    assert len(results) == 1
    assert results[0]["filename"] == "done.pdf"


# ---------------------------------------------------------------------------
# Validation (route must be mounted -> needs pg_store)
# ---------------------------------------------------------------------------


def test_exactly_one_hash_required(pg_store, tmp_path):
    client = _client(pg_store, tmp_path)
    assert client.get("/v1/similar").status_code == 400  # zero provided
    assert (
        client.get(
            "/v1/similar", params={"phash": "0" * 16, "sha256": "a" * 64}
        ).status_code
        == 400
    )  # two provided


def test_bad_hash_format_rejected(pg_store, tmp_path):
    client = _client(pg_store, tmp_path)
    assert client.get("/v1/similar", params={"phash": "xyz"}).status_code == 400
    assert client.get("/v1/similar", params={"colorhash": "zz"}).status_code == 400
    assert client.get("/v1/similar", params={"sha256": "short"}).status_code == 400


def test_out_of_range_params_rejected(pg_store, tmp_path):
    client = _client(pg_store, tmp_path)
    assert (
        client.get(
            "/v1/similar", params={"phash": "0" * 16, "max_hamming": 99}
        ).status_code
        == 400
    )
    assert (
        client.get(
            "/v1/similar", params={"sha256": "a" * 64, "limit": 9999}
        ).status_code
        == 400
    )
    assert (
        client.get(
            "/v1/similar", params={"colorhash": "0" * 14, "colorhash_frac_max": 999}
        ).status_code
        == 400
    )
