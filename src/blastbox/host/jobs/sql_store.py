"""SQL-backed JobStore — SQLite (default) + Postgres (psycopg v3)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse

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
            result_summary    TEXT
        )
        """
        with self._lock, self._connect() as conn:
            conn.execute(sql)
            self._ensure_columns(conn)

    def _ensure_columns(self, conn) -> None:
        """Add any columns that don't exist yet (forward-compat migrations)."""
        existing = self._existing_columns(conn)
        for col in ("engine", "params", "result_summary"):
            if col not in existing:
                conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} TEXT")

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
        self, job_id: str, expect_status: JobStatus, **fields
    ) -> bool:
        """Compare-and-set: ``UPDATE ... WHERE job_id = ? AND status = ?`` — applies only while
        the row is still ``expect_status`` (rowcount==1), like ``claim_next``'s QUEUED guard."""
        if not fields:
            job = self.get(job_id)
            return job is not None and job.status == expect_status
        for key in fields:
            if key not in _COLUMNS:
                raise ValueError(f"invalid column: {key!r}")
        encoded = {key: self._encode_value(key, value) for key, value in fields.items()}
        set_clause = ", ".join(f"{key} = {self._param}" for key in encoded)
        sql = (
            f"UPDATE jobs SET {set_clause} "
            f"WHERE job_id = {self._param} AND status = {self._param}"
        )
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                sql, tuple(encoded.values()) + (job_id, expect_status.value)
            )
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
            f"UPDATE jobs SET status = {self._param}, started_at = {self._param} "
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
            cur = conn.execute(
                update_sql,
                (
                    JobStatus.RUNNING.value,
                    started_at,
                    job.job_id,
                    JobStatus.QUEUED.value,
                ),
            )
            if cur.rowcount != 1:
                # Lost the race / row changed underneath us: don't claim.
                return None
            job.status = JobStatus.RUNNING
            job.started_at = started_at
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
        SET status = {self._param}, started_at = {self._param}
        FROM next_job
        WHERE jobs.job_id = next_job.job_id
        RETURNING {cols_jobs}
        """
        params = (JobStatus.QUEUED.value, JobStatus.RUNNING.value, time.time())
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return self._row_to_job(row)

    def delete(self, job_id: str) -> None:
        sql = f"DELETE FROM jobs WHERE job_id = {self._param}"
        with self._lock, self._connect() as conn:
            conn.execute(sql, (job_id,))
