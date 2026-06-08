"""SQL-backed JobStore — SQLite (default) + Postgres (psycopg v3)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from builtins import list as _list  # explicit ref: SqlJobStore.list shadows the builtin
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse

from blastbox.contract import Envelope, Page, find_by_type, phash_hex_to_int8
from blastbox.host.jobs.base import Job, JobStatus


# Allowlist of column names in the ``jobs`` table.  ``update()`` validates
# every caller-supplied field name against this tuple before it appears in
# any SQL string — so no externally-influenced name can ever be interpolated
# into a query.  Table and column names are constants throughout; only
# *values* travel through the driver paramstyle (``?`` / ``%s``).
_COLUMNS = (
    "job_id",
    "engine",
    "filename",
    "status",
    "created_at",
    "started_at",
    "finished_at",
    "expires_at",
    "input_sha256",
    "result_dir",
    "worker_runtime",
    "error",
    "security_warnings",
    "params",
    "result_summary",
    "claim_id",
)

# Fields whose values are JSON-serialised for storage.
_JSON_FIELDS = {"security_warnings", "params", "result_summary"}


class SqlJobStore:
    """Portable job store with SQLite (dev/single-node) and Postgres backends.

    Security properties:
    - Every SQL *value* is bound via the driver paramstyle (``?`` for SQLite,
      ``%s`` for Postgres).  No value is ever f-string-interpolated.
    - ``update()`` validates field names against ``_COLUMNS`` before building
      the SET clause.  Table/column names are compile-time constants only.
    - SQLite ``claim_next`` uses ``BEGIN IMMEDIATE`` + an instance-level lock
      to serialise concurrent claimers, and the UPDATE includes
      ``AND status = 'queued'`` so a concurrent status change (e.g. retention
      marking the row EXPIRED) is never silently overwritten.
    - Postgres ``claim_next`` uses ``FOR UPDATE SKIP LOCKED`` + ``RETURNING``
      for lock-free concurrent dispatch.
    """

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._lock = threading.RLock()
        self._driver, self._param = self._parse_url(database_url)
        self._pool = None
        if self._driver == "postgres":
            from psycopg_pool import ConnectionPool  # type: ignore[import-not-found]

            self._pool = ConnectionPool(
                self._database_url, min_size=1, max_size=8, timeout=10.0
            )
        self._init_db()

    def _parse_url(self, database_url: str) -> tuple[str, str]:
        scheme = urlparse(database_url).scheme.lower()
        if scheme == "sqlite":
            return "sqlite", "?"
        if scheme in {"postgres", "postgresql"}:
            return "postgres", "%s"
        # Report only the scheme — never the full DSN (it carries credentials).
        raise ValueError(f"unsupported database url scheme: {scheme!r} (use sqlite/postgresql)")

    @contextmanager
    def _connect(self):
        if self._driver == "sqlite":
            parsed = urlparse(self._database_url)
            db_path = unquote(parsed.path or "")
            if parsed.netloc and parsed.netloc != "localhost":
                db_path = f"//{parsed.netloc}{db_path}"
            if not db_path:
                raise ValueError("sqlite database url requires a path")
            if not db_path.startswith("/"):
                db_path = str(Path.cwd() / db_path)
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        else:
            with self._pool.connection() as conn:
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def _init_db(self) -> None:
        sql = """
        CREATE TABLE IF NOT EXISTS jobs (
            job_id            TEXT PRIMARY KEY,
            engine            TEXT NOT NULL,
            filename          TEXT NOT NULL,
            status            TEXT NOT NULL,
            created_at        DOUBLE PRECISION NOT NULL,
            started_at        DOUBLE PRECISION,
            finished_at       DOUBLE PRECISION,
            expires_at        DOUBLE PRECISION,
            input_sha256      TEXT,
            result_dir        TEXT,
            worker_runtime    TEXT,
            error             TEXT,
            security_warnings TEXT,
            params            TEXT,
            result_summary    TEXT,
            claim_id          TEXT
        )
        """
        # Per-page perceptual-hash index for generalized similarity search.
        #
        # Grain: one row per (job_id, page_index).  Unlike ClippyShot's monolith
        # (which keys on (job_id, page_index, variant) because its raw
        # metadata.json nests trimmed/focused sub-dicts each with their own
        # hashes), the blastbox ``Page`` contract carries a single flat
        # ``hashes`` list for one image — there is no variant concept on the
        # wire — so the PK drops ``variant`` entirely.
        #
        # phash is stored as a signed int8 (int64) so a Postgres pg_bktree
        # SP-GiST index can range-scan it for Hamming distance; it is NULLABLE
        # because a Page may legitimately omit a phash (only colorhash/sha256
        # present).  colorhash and sha256 are exact-match (btree) lookups.
        # ``BIGINT`` is ``int8`` on Postgres and degrades to ``INTEGER`` on
        # SQLite, so the same DDL runs on both backends; the bktree/L1 SQL
        # paths are Postgres-only and SQLite falls back to in-Python scans.
        page_hashes_sql = """
        CREATE TABLE IF NOT EXISTS page_hashes (
            job_id      TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
            page_index  INTEGER NOT NULL,
            phash       BIGINT,
            colorhash   TEXT,
            sha256      TEXT,
            created_at  DOUBLE PRECISION NOT NULL,
            PRIMARY KEY (job_id, page_index)
        )
        """
        with self._lock, self._connect() as conn:
            conn.execute(sql)
            conn.execute(page_hashes_sql)
            self._ensure_columns(conn)
            self._ensure_page_hash_indexes(conn)

    def _ensure_columns(self, conn) -> None:
        """Add any columns that don't exist yet (forward-compat migrations)."""
        existing = self._existing_columns(conn)
        for col in ("engine", "params", "result_summary", "claim_id"):
            if col not in existing:
                conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} TEXT")

    def _ensure_page_hash_indexes(self, conn) -> None:
        """Create page_hashes indexes the backend supports (all non-fatal).

        - Portable btrees on (colorhash), (sha256), (phash) — created on both
          SQLite and Postgres.
        - Postgres + pg_bktree: an SP-GiST ``bktree_ops`` index on phash for
          fast Hamming range scans, plus an on-the-fly ``colorhash_bin_distance``
          SQL function for the per-bin L1 colorhash path.  Both are skipped
          silently when the extension is absent — Postgres then falls back to a
          ``bit_count`` seq-scan and SQLite to in-Python popcount / nibble L1.

        Every statement is wrapped so a dev install lacking CREATE privileges
        (or a benign index race) never makes store init fatal.
        """
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ph_colorhash ON page_hashes (colorhash)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ph_sha256 ON page_hashes (sha256)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ph_phash ON page_hashes (phash)"
            )
        except Exception:
            pass
        if self._driver != "postgres":
            return
        try:
            row = conn.execute(
                "SELECT 1 FROM pg_extension WHERE extname = 'bktree' LIMIT 1"
            ).fetchone()
        except Exception:
            return
        if not row:
            return
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ph_phash_bktree "
                "ON page_hashes USING spgist (phash bktree_ops)"
            )
        except Exception:
            pass
        # colorhash_bin_distance(a, b, first_bin, last_bin): per-bin L1 over hex
        # nibbles in [first_bin, last_bin).  IMMUTABLE/PARALLEL SAFE; idempotent
        # via CREATE OR REPLACE.  Sentinel 2147483647 if either hash isn't 14
        # nibbles wide.
        try:
            conn.execute(
                "CREATE OR REPLACE FUNCTION colorhash_bin_distance("
                "a text, b text, first_bin int DEFAULT 0, last_bin int DEFAULT 14"
                ") RETURNS int AS $$ "
                "SELECT CASE "
                "WHEN length(a) <> 14 OR length(b) <> 14 THEN 2147483647 "
                "ELSE coalesce(("
                "SELECT sum(abs("
                "('x' || substring(a FROM i+1 FOR 1))::bit(4)::int "
                "- ('x' || substring(b FROM i+1 FOR 1))::bit(4)::int"
                "))::int "
                "FROM generate_series(first_bin, last_bin - 1) AS i"
                "), 0) END "
                "$$ LANGUAGE SQL IMMUTABLE PARALLEL SAFE"
            )
        except Exception:
            pass

    def _bktree_extension_available(self) -> bool:
        if self._driver != "postgres":
            return False
        with self._lock, self._connect() as conn:
            try:
                row = conn.execute(
                    "SELECT 1 FROM pg_extension WHERE extname = 'bktree' LIMIT 1"
                ).fetchone()
            except Exception:
                return False
            return bool(row)

    def _existing_columns(self, conn) -> set[str]:
        if self._driver == "sqlite":
            rows = conn.execute("PRAGMA table_info(jobs)").fetchall()
            return {str(row[1]) for row in rows}
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s",
            ("jobs",),
        ).fetchall()
        return {str(row[0]) for row in rows}

    # ------------------------------------------------------------------
    # Encode / decode helpers
    # ------------------------------------------------------------------

    def _encode_value(self, key: str, value):
        if key in _JSON_FIELDS and value is not None:
            return json.dumps(value)
        return value

    def _row_to_job(self, row) -> Job | None:
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            raw: dict = {k: row[k] for k in row.keys()}
        else:
            raw = dict(zip(_COLUMNS, row, strict=True))
        # Decode JSON-serialised fields back to Python objects.
        for field in _JSON_FIELDS:
            if raw.get(field):
                raw[field] = json.loads(raw[field])
            elif raw.get(field) is None:
                raw[field] = {} if field == "params" else ([] if field == "security_warnings" else None)
        # Ensure params is always a dict, not None
        if raw.get("params") is None:
            raw["params"] = {}
        if raw.get("security_warnings") is None:
            raw["security_warnings"] = []
        return Job.from_dict(raw)

    # ------------------------------------------------------------------
    # JobStore interface
    # ------------------------------------------------------------------

    def create(self, job: Job) -> None:
        values = job.to_dict()
        cols = ", ".join(_COLUMNS)
        params = ", ".join(self._param for _ in _COLUMNS)
        sql = f"INSERT INTO jobs ({cols}) VALUES ({params})"
        with self._lock, self._connect() as conn:
            conn.execute(
                sql,
                tuple(self._encode_value(col, values.get(col)) for col in _COLUMNS),
            )

    def get(self, job_id: str) -> Job | None:
        sql = f"SELECT {', '.join(_COLUMNS)} FROM jobs WHERE job_id = {self._param}"
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, (job_id,)).fetchone()
        return self._row_to_job(row)

    def update(self, job_id: str, **fields) -> Job:
        if not fields:
            job = self.get(job_id)
            if job is None:
                raise KeyError(job_id)
            return job
        # Security: validate every field name against the allowlist before
        # it appears in any SQL string.  Values always travel via paramstyle.
        for key in fields:
            if key not in _COLUMNS:
                raise ValueError(f"invalid column: {key!r}")
        encoded = {key: self._encode_value(key, value) for key, value in fields.items()}
        set_clause = ", ".join(f"{key} = {self._param}" for key in encoded)
        sql = f"UPDATE jobs SET {set_clause} WHERE job_id = {self._param}"
        with self._lock, self._connect() as conn:
            cur = conn.execute(sql, tuple(encoded.values()) + (job_id,))
            if cur.rowcount == 0:
                raise KeyError(job_id)
        job = self.get(job_id)
        if job is None:
            raise KeyError(job_id)
        return job

    def update_if_status(
        self,
        job_id: str,
        expect_status: JobStatus,
        *,
        expect_claim_id: str | None = None,
        **fields,
    ) -> bool:
        """Compare-and-set: ``UPDATE ... WHERE job_id = ? AND status = ?`` (and ``AND claim_id = ?``
        when ``expect_claim_id`` is given) — applies only while the row still matches (rowcount==1),
        like ``claim_next``'s QUEUED guard. The claim_id guard closes the status-only ABA hole."""
        for key in fields:
            if key not in _COLUMNS:
                raise ValueError(f"invalid column: {key!r}")
        guard_sql = f"WHERE job_id = {self._param} AND status = {self._param}"
        guard_params: tuple = (job_id, expect_status.value)
        if expect_claim_id is not None:
            guard_sql += f" AND claim_id = {self._param}"
            guard_params += (expect_claim_id,)
        if not fields:
            sql = f"SELECT 1 FROM jobs {guard_sql}"
            with self._lock, self._connect() as conn:
                return conn.execute(sql, guard_params).fetchone() is not None
        encoded = {key: self._encode_value(key, value) for key, value in fields.items()}
        set_clause = ", ".join(f"{key} = {self._param}" for key in encoded)
        sql = f"UPDATE jobs SET {set_clause} {guard_sql}"
        with self._lock, self._connect() as conn:
            cur = conn.execute(sql, tuple(encoded.values()) + guard_params)
            return cur.rowcount == 1

    def list(
        self,
        status: JobStatus | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Job]:
        sql = f"SELECT {', '.join(_COLUMNS)} FROM jobs"
        params: list = []
        if status is not None:
            sql += f" WHERE status = {self._param}"
            params.append(status.value)
        if newest_first:
            sql += " ORDER BY created_at DESC, job_id DESC"
        # Push the page window into the query so large tables never fully
        # materialize.  SQLite requires a LIMIT clause syntactically before
        # OFFSET, so a bare offset gets the unbounded sentinel ``LIMIT -1``;
        # Postgres accepts OFFSET alone.
        eff_limit = limit
        if offset and eff_limit is None and self._driver == "sqlite":
            eff_limit = -1
        if eff_limit is not None:
            sql += f" LIMIT {self._param}"
            params.append(int(eff_limit))
        if offset:
            sql += f" OFFSET {self._param}"
            params.append(int(offset))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [job for row in rows if (job := self._row_to_job(row)) is not None]

    def count(self, status: JobStatus | None = None) -> int:
        sql = "SELECT COUNT(*) FROM jobs"
        params: tuple = ()
        if status is not None:
            sql += f" WHERE status = {self._param}"
            params = (status.value,)
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return int(row[0]) if row else 0

    def claim_next(self) -> Job | None:
        if self._driver == "sqlite":
            return self._claim_next_sqlite()
        return self._claim_next_postgres()

    def _claim_next_sqlite(self) -> Job | None:
        select_sql = (
            f"SELECT {', '.join(_COLUMNS)} FROM jobs "
            f"WHERE status = {self._param} "
            f"ORDER BY created_at ASC, job_id ASC LIMIT 1"
        )
        # The UPDATE is a compare-and-swap: it only fires if the row is STILL
        # queued (``AND status = 'queued'``).  ``BEGIN IMMEDIATE`` + the
        # instance lock serialize concurrent claimers, but the status guard
        # also defends against any other path (e.g. retention marking the row
        # EXPIRED) flipping it between the SELECT and UPDATE — without it,
        # such a transition would be silently clobbered back to RUNNING.
        update_sql = (
            f"UPDATE jobs SET status = {self._param}, started_at = {self._param}, "
            f"claim_id = {self._param} "
            f"WHERE job_id = {self._param} AND status = {self._param}"
        )
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(select_sql, (JobStatus.QUEUED.value,)).fetchone()
            if row is None:
                return None
            job = self._row_to_job(row)
            if job is None:
                return None
            started_at = time.time()
            claim_id = uuid.uuid4().hex  # fresh ownership token per claim
            cur = conn.execute(
                update_sql,
                (
                    JobStatus.RUNNING.value,
                    started_at,
                    claim_id,
                    job.job_id,
                    JobStatus.QUEUED.value,
                ),
            )
            if cur.rowcount != 1:
                # Lost the race / row changed underneath us: don't claim.
                return None
            job.status = JobStatus.RUNNING
            job.started_at = started_at
            job.claim_id = claim_id
            return job

    def _claim_next_postgres(self) -> Job | None:
        cols_jobs = ", ".join(f"jobs.{col}" for col in _COLUMNS)
        sql = f"""
        WITH next_job AS (
            SELECT job_id
            FROM jobs
            WHERE status = {self._param}
            ORDER BY created_at ASC, job_id ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE jobs
        SET status = {self._param}, started_at = {self._param}, claim_id = {self._param}
        FROM next_job
        WHERE jobs.job_id = next_job.job_id
        RETURNING {cols_jobs}
        """
        params = (
            JobStatus.QUEUED.value,
            JobStatus.RUNNING.value,
            time.time(),
            uuid.uuid4().hex,  # fresh ownership token per claim
        )
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return self._row_to_job(row)

    def delete(self, job_id: str) -> None:
        sql = f"DELETE FROM jobs WHERE job_id = {self._param}"
        with self._lock, self._connect() as conn:
            conn.execute(sql, (job_id,))

    # ------------------------------------------------------------------
    # Per-page perceptual-hash index (optional; not in the JobStore Protocol
    # core — see base.py.  Consumers hasattr-guard these.)
    # ------------------------------------------------------------------

    @staticmethod
    def _page_hash_rows(envelope: Envelope) -> _list[dict]:
        """Extract per-page hash rows from a *validated* sealed Envelope.

        Walks the typed payload tree for ``Page`` nodes and reads each page's
        flat ``hashes`` list (``{algo: value}``), pulling the ``phash`` /
        ``colorhash`` / ``sha256`` hex values.  The phash hex is converted to a
        signed int64 (the index storage form); colorhash/sha256 are kept as hex
        verbatim.  A page contributes a row as long as it has *any* of the three
        hashes — phash is nullable in the table, so a page with only
        colorhash/sha256 is still indexed (just not phash-searchable).
        """
        rows: _list[dict] = []
        for page in find_by_type(envelope.payload, Page):
            by_algo = {h.algo: h.value for h in page.hashes}
            phash_hex = by_algo.get("phash")
            colorhash = by_algo.get("colorhash")
            sha256 = by_algo.get("sha256")
            if phash_hex is None and colorhash is None and sha256 is None:
                continue
            rows.append(
                {
                    "page_index": page.index,
                    "phash": (
                        phash_hex_to_int8(phash_hex) if phash_hex is not None else None
                    ),
                    "colorhash": colorhash,
                    "sha256": sha256,
                }
            )
        return rows

    def index_page_hashes(self, job_id: str, envelope: Envelope) -> int:
        """Extract + persist a completed job's per-page hashes for search.

        Pulls ``Page`` hashes out of the sealed ``envelope`` and upserts one row
        per page into ``page_hashes``.  Returns the number of rows written.
        Best-effort by contract: callers wrap it in try/except and treat a
        missing method (in-memory / redis stores) as a silent no-op, so an
        index failure never fails an otherwise-DONE job.
        """
        rows = self._page_hash_rows(envelope)
        self.upsert_page_hashes(job_id, rows)
        return len(rows)

    def upsert_page_hashes(self, job_id: str, rows: _list[dict]) -> None:
        """Write a batch of per-page hash rows for a job (idempotent upsert).

        Each row is ``{page_index, phash (signed int8 | None), colorhash (hex |
        None), sha256 (hex | None)}``.  SQLite uses ``INSERT OR REPLACE``;
        Postgres uses ``ON CONFLICT (job_id, page_index) DO UPDATE``.  No-ops on
        an empty list.
        """
        if not rows:
            return
        now = time.time()
        if self._driver == "sqlite":
            sql = (
                "INSERT OR REPLACE INTO page_hashes "
                "(job_id, page_index, phash, colorhash, sha256, created_at) "
                f"VALUES ({self._param}, {self._param}, {self._param}, "
                f"{self._param}, {self._param}, {self._param})"
            )
        else:
            sql = (
                "INSERT INTO page_hashes "
                "(job_id, page_index, phash, colorhash, sha256, created_at) "
                f"VALUES ({self._param}, {self._param}, {self._param}, "
                f"{self._param}, {self._param}, {self._param}) "
                "ON CONFLICT (job_id, page_index) DO UPDATE SET "
                "phash = EXCLUDED.phash, "
                "colorhash = EXCLUDED.colorhash, "
                "sha256 = EXCLUDED.sha256, "
                "created_at = EXCLUDED.created_at"
            )
        params = [
            (
                job_id,
                int(r["page_index"]),
                None if r.get("phash") is None else int(r["phash"]),
                None if r.get("colorhash") is None else str(r["colorhash"]),
                None if r.get("sha256") is None else str(r["sha256"]),
                now,
            )
            for r in rows
        ]
        with self._lock, self._connect() as conn:
            conn.executemany(sql, params)

    # The SELECT column set shared by every search method.  All JOIN page_hashes
    # to jobs and filter j.status = 'done' (only completed jobs are searchable).
    _SEARCH_COLS = (
        "ph.job_id, ph.page_index, ph.phash, ph.colorhash, ph.sha256, j.filename"
    )

    def find_similar_phash(
        self, target_int8: int, max_distance: int, limit: int = 50
    ) -> _list[dict]:
        """Pages within Hamming distance ``max_distance`` of ``target_int8``.

        ``target_int8`` is the already-converted signed int64 form of the query
        phash (use :func:`blastbox.contract.phash_hex_to_int8`).  Postgres with
        pg_bktree uses the indexed ``<@ ROW(center, radius)::bktree_area`` range
        scan; plain Postgres a ``bit_count`` XOR seq-scan; SQLite an in-Python
        popcount.  Rows whose phash is NULL are excluded.  Returns rows with an
        added ``distance`` field, ordered ``(distance, job_id, page_index)``.
        """
        if self._driver == "sqlite":
            rows = self._query_all(
                f"SELECT {self._SEARCH_COLS} "
                "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
                f"WHERE j.status = {self._param} AND ph.phash IS NOT NULL",
                (JobStatus.DONE.value,),
            )
            out = []
            for r in rows:
                dist = bin((r["phash"] ^ target_int8) & ((1 << 64) - 1)).count("1")
                if dist <= max_distance:
                    out.append({**r, "distance": dist})
            out.sort(key=lambda x: (x["distance"], x["job_id"], x["page_index"]))
            return out[:limit]
        if self._bktree_extension_available():
            sql = (
                f"SELECT {self._SEARCH_COLS}, "
                f"hamming_distance(ph.phash, {self._param}::int8) AS distance "
                "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
                f"WHERE j.status = {self._param} AND ph.phash IS NOT NULL "
                f"AND ph.phash <@ ROW({self._param}::int8, {self._param}::int8)::bktree_area "
                f"ORDER BY distance, ph.job_id, ph.page_index LIMIT {self._param}"
            )
        else:
            sql = (
                f"SELECT {self._SEARCH_COLS}, "
                f"bit_count((ph.phash # {self._param}::int8)::bit(64)) AS distance "
                "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
                f"WHERE j.status = {self._param} AND ph.phash IS NOT NULL "
                f"AND bit_count((ph.phash # {self._param}::int8)::bit(64)) <= {self._param} "
                f"ORDER BY distance, ph.job_id, ph.page_index LIMIT {self._param}"
            )
        params = (target_int8, JobStatus.DONE.value, target_int8, max_distance, limit)
        return self._query_all(sql, params)

    def find_by_colorhash(self, colorhash: str, limit: int = 50) -> _list[dict]:
        """Pages whose colorhash matches ``colorhash`` exactly."""
        sql = (
            f"SELECT {self._SEARCH_COLS} "
            "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
            f"WHERE j.status = {self._param} AND ph.colorhash = {self._param} "
            f"ORDER BY ph.job_id, ph.page_index LIMIT {self._param}"
        )
        return self._query_all(sql, (JobStatus.DONE.value, colorhash, limit))

    def find_by_page_sha256(self, sha256: str, limit: int = 50) -> _list[dict]:
        """Pages whose rendered-image sha256 matches exactly (identical page)."""
        sql = (
            f"SELECT {self._SEARCH_COLS} "
            "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
            f"WHERE j.status = {self._param} AND ph.sha256 = {self._param} "
            f"ORDER BY ph.job_id, ph.page_index LIMIT {self._param}"
        )
        return self._query_all(sql, (JobStatus.DONE.value, sha256, limit))

    def find_similar_colorhash(
        self,
        target: str,
        *,
        total_max: int | None = None,
        frac_max: int | None = None,
        faint_max: int | None = None,
        bright_max: int | None = None,
        limit: int = 50,
    ) -> _list[dict]:
        """Pages whose colorhash is within the given per-bin L1 distances.

        colorhash encodes 14 hex nibbles (binbits=4, each a 0-15 count):
            bins 0-1:   fraction bins (black, gray)
            bins 2-7:   6 faint-color hue bins
            bins 8-13:  6 bright-color hue bins
        The metric is L1 (sum of absolute nibble differences) over a bin range.
        Caps are cumulative AND — a row must satisfy *every* set cap.  Passing no
        caps delegates to :meth:`find_by_colorhash` (exact match).  Returns rows
        with ``distance``, ``frac_distance``, ``faint_distance``,
        ``bright_distance`` fields, ordered ``(distance, job_id, page_index)``.
        """
        if not any(v is not None for v in (total_max, frac_max, faint_max, bright_max)):
            return self.find_by_colorhash(target, limit=limit)
        groups = [
            (total_max, 0, 14, "distance"),
            (frac_max, 0, 2, "frac_distance"),
            (faint_max, 2, 8, "faint_distance"),
            (bright_max, 8, 14, "bright_distance"),
        ]
        if self._driver == "sqlite":
            rows = self._query_all(
                f"SELECT {self._SEARCH_COLS} "
                "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
                f"WHERE j.status = {self._param} AND ph.colorhash IS NOT NULL",
                (JobStatus.DONE.value,),
            )
            out: _list[dict] = []
            for r in rows:
                ch = r.get("colorhash") or ""
                if len(ch) != 14 or len(target) != 14:
                    continue
                dists = {}
                keep = True
                for cap, first, last, alias in groups:
                    d = sum(
                        abs(int(ch[i], 16) - int(target[i], 16))
                        for i in range(first, last)
                    )
                    dists[alias] = d
                    if cap is not None and d > cap:
                        keep = False
                        break
                if keep:
                    out.append({**r, **dists})
            out.sort(key=lambda x: (x["distance"], x["job_id"], x["page_index"]))
            return out[:limit]
        # Postgres: per-group SQL function (no usable index for L1 -> seq scan).
        # SELECT placeholders must precede WHERE placeholders in the param
        # tuple, so build the two param lists separately and concatenate.
        select_cols: _list[str] = []
        select_params: list = []
        where_clauses: _list[str] = []
        where_params: list = []
        for cap, first, last, alias in groups:
            select_cols.append(
                f"colorhash_bin_distance(ph.colorhash, {self._param}, {first}, {last}) AS {alias}"
            )
            select_params.append(target)
            if cap is not None:
                where_clauses.append(
                    f"colorhash_bin_distance(ph.colorhash, {self._param}, {first}, {last}) "
                    f"<= {self._param}"
                )
                where_params.extend([target, cap])
        sql = (
            f"SELECT {self._SEARCH_COLS}, "
            + ", ".join(select_cols)
            + " FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
            + f"WHERE j.status = {self._param} AND ph.colorhash IS NOT NULL "
            + (f"AND {' AND '.join(where_clauses)} " if where_clauses else "")
            + f"ORDER BY distance, ph.job_id, ph.page_index LIMIT {self._param}"
        )
        params = select_params + [JobStatus.DONE.value] + where_params + [limit]
        return self._query_all(sql, tuple(params))

    def _query_all(self, sql: str, params: tuple = ()) -> _list[dict]:
        """Run a SELECT and return rows as list-of-dicts, portable across drivers."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
            if self._driver == "sqlite":
                return [dict(r) for r in rows]
            cols = [d[0] for d in cur.description] if cur.description else []
            return [dict(zip(cols, r, strict=True)) for r in rows]
