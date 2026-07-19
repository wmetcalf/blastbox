"""SQL-backed JobStore — SQLite (default) + Postgres (psycopg v3)."""

from __future__ import annotations

from collections.abc import Collection

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
from blastbox.host.jobs.base import LISTABLE_SORT_FIELDS, Job, JobStatus, normalize_engine_filter


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
    "worker_tier",
    "target_tier",
    "net_policy",
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
        self._bktree_available = False  # set once in _init_db (static per process)
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
            worker_tier       TEXT,
            target_tier       TEXT,
            net_policy        TEXT,
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
            # page_hashes + its indexes are Postgres-only: perceptual-hash search
            # is Postgres + pg_bktree ONLY, so SQLite gets no page_hashes table
            # and supports_hash_search() stays False.
            if self._driver == "postgres":
                conn.execute(page_hashes_sql)
            self._ensure_columns(conn)
        # Best-effort indexes run AFTER the table-creation transaction commits, each in its
        # OWN transaction. On Postgres a failed statement (a CREATE INDEX lock/permission
        # error) aborts the WHOLE transaction, so creating them inline would risk rolling back
        # the tables. Covering index for the hot claim + autosizer-backlog predicates
        # (status, engine, target_tier) — without it the node sizer's per-tick COUNT(*) is a
        # full-table scan on a large retained history. Runs on both backends.
        self._try_ddl(
            "CREATE INDEX IF NOT EXISTS idx_jobs_status_engine_tier "
            "ON jobs (status, engine, target_tier)")
        if self._driver == "postgres":
            self._ensure_page_hash_indexes()

    def _ensure_columns(self, conn) -> None:
        """Add any columns that don't exist yet (forward-compat migrations)."""
        existing = self._existing_columns(conn)
        for col in ("engine", "params", "result_summary", "claim_id",
                    "worker_tier", "target_tier", "net_policy"):
            if col not in existing:
                conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} TEXT")

    def _try_ddl(self, stmt: str) -> bool:
        """Run one best-effort DDL statement in its OWN transaction.

        Returns True on success.  Each statement is isolated so a failure (a
        missing CREATE privilege, an index lock, a benign IF-NOT-EXISTS race)
        aborts only its own transaction — on Postgres a failure inside a SHARED
        transaction poisons every later statement in it (and rolls the lot back).
        """
        try:
            with self._lock, self._connect() as conn:
                conn.execute(stmt)
            return True
        except Exception:
            return False

    def _ensure_page_hash_indexes(self) -> None:
        """Create the page_hashes indexes/functions (Postgres-only) + cache bktree avail.

        Called only on Postgres (search is Postgres + pg_bktree only).  Creates:

        - btrees on (colorhash), (sha256), (phash) for the exact-match lookups;
        - when pg_bktree is present: an SP-GiST ``bktree_ops`` index on phash for
          fast Hamming range scans, plus the two helper SQL functions the search
          methods call — ``hamming_distance(int8, int8)`` and
          ``colorhash_bin_distance(text, text, int, int)``.  The store creates its
          OWN helpers (CREATE OR REPLACE, idempotent) so it depends only on the
          extension, not on any product's database-init script.

        Every statement is best-effort and individually transaction-isolated (see
        :meth:`_try_ddl`): a dev install lacking CREATE privileges never makes
        store init fatal, and one failure can't roll back the others (or the
        table).  Also caches ``_bktree_available`` once — static per process, so
        re-probing ``pg_extension`` on every search is a wasted round-trip.
        """
        for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_ph_colorhash ON page_hashes (colorhash)",
            "CREATE INDEX IF NOT EXISTS idx_ph_sha256 ON page_hashes (sha256)",
            "CREATE INDEX IF NOT EXISTS idx_ph_phash ON page_hashes (phash)",
        ):
            self._try_ddl(stmt)
        self._bktree_available = self._bktree_extension_available()
        if not self._bktree_available:
            return
        self._try_ddl(
            "CREATE INDEX IF NOT EXISTS idx_ph_phash_bktree "
            "ON page_hashes USING spgist (phash bktree_ops)"
        )
        # hamming_distance(a, b): popcount of the int8 XOR — the displayed/ordered
        # distance for a bktree range scan (the <@ operator filters but doesn't
        # surface the distance).  Portable popcount (bit(64) text, count '1's) so
        # it carries no PostgreSQL-14+ bit_count() dependency.
        self._try_ddl(
            "CREATE OR REPLACE FUNCTION hamming_distance(a int8, b int8) "
            "RETURNS int4 AS $$ "
            "SELECT length(replace((a # b)::bit(64)::text, '0', ''))::int4 "
            "$$ LANGUAGE SQL IMMUTABLE PARALLEL SAFE"
        )
        # colorhash_bin_distance(a, b, first_bin, last_bin): per-bin L1 over hex
        # nibbles in [first_bin, last_bin).  IMMUTABLE/PARALLEL SAFE; idempotent
        # via CREATE OR REPLACE.  Sentinel 2147483647 if either hash isn't 14
        # hex nibbles wide — the regex guard MUST precede the ('x'||nibble)::bit(4)
        # cast (CASE short-circuits) so a stored non-hex colorhash (a buggy/hostile
        # engine) yields the sentinel instead of an "invalid hexadecimal digit" error
        # that would abort the whole search query.
        self._try_ddl(
            "CREATE OR REPLACE FUNCTION colorhash_bin_distance("
            "a text, b text, first_bin int DEFAULT 0, last_bin int DEFAULT 14"
            ") RETURNS int AS $$ "
            "SELECT CASE "
            "WHEN a !~ '^[0-9a-fA-F]{14}$' OR b !~ '^[0-9a-fA-F]{14}$' THEN 2147483647 "
            "ELSE coalesce(("
            "SELECT sum(abs("
            "('x' || substring(a FROM i+1 FOR 1))::bit(4)::int "
            "- ('x' || substring(b FROM i+1 FOR 1))::bit(4)::int"
            "))::int "
            "FROM generate_series(first_bin, last_bin - 1) AS i"
            "), 0) END "
            "$$ LANGUAGE SQL IMMUTABLE PARALLEL SAFE"
        )

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

    def supports_hash_search(self) -> bool:
        """Whether this store can serve perceptual-hash similarity search.

        Search is **Postgres + pg_bktree only**: the SP-GiST BK-tree index is the
        single supported backend — there is no SQLite in-Python scan and no
        plain-Postgres seq-scan fallback.  SQLite stores and Postgres without the
        extension return ``False``; callers (the dispatcher's on-DONE indexer and
        the ``/v1/similar`` route) feature-detect on this and simply skip
        indexing / don't mount the route.
        """
        return self._driver == "postgres" and self._bktree_available

    def _require_search(self) -> None:
        """Guard the page-hash capability methods (defense-in-depth past the gate)."""
        if not self.supports_hash_search():
            raise RuntimeError(
                "perceptual-hash search requires Postgres with the pg_bktree "
                f"extension (driver={self._driver!r}, bktree={self._bktree_available}); "
                "use supports_hash_search() to feature-detect"
            )

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
        q: str | None = None,
        sort: str | None = None,
        order: str = "desc",
    ) -> list[Job]:
        sql = f"SELECT {', '.join(_COLUMNS)} FROM jobs"
        where, params = self._where_status_q(status, q)
        if where:
            sql += " WHERE " + " AND ".join(where)
        # sort is whitelisted (LISTABLE_SORT_FIELDS) so the column can't inject.
        order_dir = "ASC" if (order or "desc").lower() == "asc" else "DESC"
        if sort in LISTABLE_SORT_FIELDS:
            # finished_at is nullable; COALESCE to 0 so NULL ordering matches the
            # in-memory/Redis backends (None→0.0). Without it Postgres sorts NULLs
            # high in DESC and SQLite low — the order would diverge across backends.
            col = "COALESCE(finished_at, 0)" if sort == "finished_at" else sort
            sql += f" ORDER BY {col} {order_dir}, job_id {order_dir}"
        elif newest_first:
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

    def count(self, status: JobStatus | None = None, *, q: str | None = None,
              engine: str | None = None, claimant_tier: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM jobs"
        where, params = self._where_status_q(status, q)
        if engine is not None:
            where.append(f"engine = {self._param}")
            params.append(engine)
        if claimant_tier is not None:      # mirror claim_next's tier predicate
            where.append(f"(target_tier IS NULL OR target_tier = {self._param})")
            params.append(claimant_tier)
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        return int(row[0]) if row else 0

    def _where_status_q(
        self, status: JobStatus | None, q: str | None
    ) -> tuple[_list[str], _list]:
        """Build the shared WHERE clauses + params for status + filename-``q`` search.
        ``q`` is a case-insensitive substring; LIKE metacharacters are escaped so a
        user's ``%``/``_`` is literal."""
        where: _list[str] = []
        params: _list = []
        if status is not None:
            where.append(f"status = {self._param}")
            params.append(status.value)
        if q:
            esc = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append(f"LOWER(filename) LIKE {self._param} ESCAPE '\\'")
            params.append(f"%{esc}%")
        return where, params

    def _engine_clause(self, engines: tuple[str, ...] | None) -> tuple[str, _list[str]]:
        """SQL fragment + params for the engine filter: ``AND engine IN (?,?,..)`` for a set of
        engines this claimant handles, or empty (no filter) when None."""
        if not engines:
            return "", []
        placeholders = ",".join([self._param] * len(engines))
        return f"AND engine IN ({placeholders}) ", list(engines)

    def claim_next(self, *, claimant_tier: str | None = None,
                   engine: "str | Collection[str] | None" = None) -> Job | None:
        engines = normalize_engine_filter(engine)
        if self._driver == "sqlite":
            return self._claim_next_sqlite(claimant_tier, engines)
        return self._claim_next_postgres(claimant_tier, engines)

    def _claim_next_sqlite(self, claimant_tier: str | None = None,
                           engines: tuple[str, ...] | None = None) -> Job | None:
        # target_tier routing: claim a job only if it has no target, or its target matches
        # this claimant's tier. Binding claimant_tier=None makes `target_tier = NULL` (never
        # true in SQL), so the predicate collapses to `target_tier IS NULL` — an untiered
        # claimant takes only untargeted jobs. Existing rows are NULL → unchanged behaviour.
        # `engines`: when set, restrict to `engine IN (...)`; absent = no engine filter.
        eng_clause, eng_params = self._engine_clause(engines)
        select_sql = (
            f"SELECT {', '.join(_COLUMNS)} FROM jobs "
            f"WHERE status = {self._param} "
            f"AND (target_tier IS NULL OR target_tier = {self._param}) "
            f"{eng_clause}"
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
            row = conn.execute(
                select_sql, (JobStatus.QUEUED.value, claimant_tier, *eng_params)
            ).fetchone()
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

    def _claim_next_postgres(self, claimant_tier: str | None = None,
                             engines: tuple[str, ...] | None = None) -> Job | None:
        cols_jobs = ", ".join(f"jobs.{col}" for col in _COLUMNS)
        # target_tier routing (see _claim_next_sqlite): only rows with no target or a target
        # matching this claimant are eligible; claimant_tier=None ⇒ target_tier IS NULL only.
        # `engines`: when set, restrict to `engine IN (...)`; absent = no engine filter.
        eng_clause, eng_params = self._engine_clause(engines)
        sql = f"""
        WITH next_job AS (
            SELECT job_id
            FROM jobs
            WHERE status = {self._param}
            AND (target_tier IS NULL OR target_tier = {self._param})
            {eng_clause}
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
            claimant_tier,
            *eng_params,
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
        Requires the Postgres + pg_bktree backend (see
        :meth:`supports_hash_search`) — the dispatcher gates the on-DONE call on
        that capability, so SQLite / plain-Postgres stores simply never index.
        """
        self._require_search()
        rows = self._page_hash_rows(envelope)
        self.upsert_page_hashes(job_id, rows)
        return len(rows)

    def upsert_page_hashes(self, job_id: str, rows: _list[dict]) -> None:
        """Write a batch of per-page hash rows for a job (idempotent upsert).

        Each row is ``{page_index, phash (signed int8 | None), colorhash (hex |
        None), sha256 (hex | None)}``.  Postgres ``ON CONFLICT (job_id,
        page_index) DO UPDATE``.  No-ops on an empty list.  Requires the
        Postgres + pg_bktree backend (see :meth:`supports_hash_search`).
        """
        self._require_search()
        if not rows:
            return
        now = time.time()
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
            # executemany lives on the cursor in psycopg3 (the connection has no
            # such method); sqlite3 cursors support it too, so go via a cursor.
            conn.cursor().executemany(sql, params)

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
        phash (use :func:`blastbox.contract.phash_hex_to_int8`).  Served by the
        Postgres pg_bktree SP-GiST index via an ``<@ ROW(center, radius)::
        bktree_area`` range scan — the single supported backend (see
        :meth:`supports_hash_search`).  Rows whose phash is NULL are excluded.
        Returns rows with an added ``distance`` field, ordered
        ``(distance, job_id, page_index)``.
        """
        self._require_search()
        sql = (
            f"SELECT {self._SEARCH_COLS}, "
            f"hamming_distance(ph.phash, {self._param}::int8) AS distance "
            "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
            f"WHERE j.status = {self._param} AND ph.phash IS NOT NULL "
            f"AND ph.phash <@ ROW({self._param}::int8, {self._param}::int8)::bktree_area "
            f"ORDER BY distance, ph.job_id, ph.page_index LIMIT {self._param}"
        )
        params = (target_int8, JobStatus.DONE.value, target_int8, max_distance, limit)
        return self._query_all(sql, params)

    def find_by_colorhash(self, colorhash: str, limit: int = 50) -> _list[dict]:
        """Pages whose colorhash matches ``colorhash`` exactly."""
        self._require_search()
        sql = (
            f"SELECT {self._SEARCH_COLS} "
            "FROM page_hashes ph JOIN jobs j ON j.job_id = ph.job_id "
            f"WHERE j.status = {self._param} AND ph.colorhash = {self._param} "
            f"ORDER BY ph.job_id, ph.page_index LIMIT {self._param}"
        )
        return self._query_all(sql, (JobStatus.DONE.value, colorhash, limit))

    def find_by_page_sha256(self, sha256: str, limit: int = 50) -> _list[dict]:
        """Pages whose rendered-image sha256 matches exactly (identical page)."""
        self._require_search()
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
        self._require_search()
        if not any(v is not None for v in (total_max, frac_max, faint_max, bright_max)):
            return self.find_by_colorhash(target, limit=limit)
        groups = [
            (total_max, 0, 14, "distance"),
            (frac_max, 0, 2, "frac_distance"),
            (faint_max, 2, 8, "faint_distance"),
            (bright_max, 8, 14, "bright_distance"),
        ]
        # Per-group colorhash_bin_distance() function (L1 has no usable index ->
        # seq scan). SELECT placeholders precede WHERE placeholders in the param
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
