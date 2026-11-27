"""Per-node liveness: when did each node last heartbeat, and when did it last ask for work.

This is a CLAIM, never a fact and never an input to authorisation. The heartbeat body is
whatever an authenticated node chose to say about itself; what a node may run is resolved
from its certificate (see ``ingress.node_claim``) and nothing stored here changes that.
Its one job is to let an operator alert when a node goes quiet.

Writes are best-effort by design: callers go through :func:`safe_record_heartbeat` /
:func:`safe_record_claim`, which log a store error and carry on, so an unhealthy liveness
table can never fail a heartbeat or, worse, a claim.

Backends mirror the node registry's: SQL over the job store's own pool
(postgres and sqlite), a Redis hash per node, and an in-memory fallback.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "NodeLiveness", "LivenessStore", "InMemoryLivenessStore", "SqlLivenessStore",
    "RedisLivenessStore", "build_liveness_store",
    "safe_record_heartbeat", "safe_record_claim",
]

_log = logging.getLogger("blastbox.node_liveness")


@dataclass(frozen=True)
class NodeLiveness:
    node_id: str
    last_heartbeat_at: float | None = None
    last_claim_at: float | None = None
    last_claim_engine: str | None = None   # not persisted by the SQL backend
    body: dict[str, Any] | None = None     # the node's own claim; never trusted


class LivenessStore(Protocol):
    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None: ...
    def record_claim(self, node_id: str, engine: str | None, at: float) -> None: ...
    def snapshot(self) -> dict[str, NodeLiveness]: ...


def safe_record_heartbeat(store: LivenessStore, node_id: str, body: dict, at: float) -> bool:
    try:
        store.record_heartbeat(node_id, body, at)
        return True
    except Exception:  # noqa: BLE001 - liveness must never fail the request
        _log.exception("node_liveness: could not record heartbeat for node=%s", node_id)
        return False


def safe_record_claim(store: LivenessStore, node_id: str, engine: str | None,
                      at: float) -> bool:
    try:
        store.record_claim(node_id, engine, at)
        return True
    except Exception:  # noqa: BLE001 - liveness must never fail a claim
        _log.exception("node_liveness: could not record claim for node=%s", node_id)
        return False


class InMemoryLivenessStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, NodeLiveness] = {}

    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None:
        with self._lock:
            old = self._rows.get(node_id) or NodeLiveness(node_id)
            self._rows[node_id] = NodeLiveness(node_id, at, old.last_claim_at,
                                               old.last_claim_engine, dict(body))

    def record_claim(self, node_id: str, engine: str | None, at: float) -> None:
        with self._lock:
            old = self._rows.get(node_id) or NodeLiveness(node_id)
            self._rows[node_id] = NodeLiveness(node_id, old.last_heartbeat_at, at,
                                               engine, old.body)

    def snapshot(self) -> dict[str, NodeLiveness]:
        with self._lock:
            return dict(self._rows)


class SqlLivenessStore:
    """Borrows the job store's pool (see ``SqlNodeRegistry`` for why). One row per node,
    upserted; the two timestamps are written by different requests so each upsert touches
    only its own columns."""

    def __init__(self, store) -> None:
        self._store = store
        with store.connection() as conn:
            real = "DOUBLE PRECISION" if store.param_style == "%s" else "REAL"
            conn.execute(
                "CREATE TABLE IF NOT EXISTS node_liveness ("
                " node_id TEXT PRIMARY KEY,"
                f" last_heartbeat_at {real},"
                f" last_claim_at {real},"
                " body TEXT)")

    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None:
        p = self._store.param_style
        sql = (f"INSERT INTO node_liveness (node_id, last_heartbeat_at, last_claim_at, body) "
               f"VALUES ({p}, {p}, NULL, {p}) ON CONFLICT (node_id) DO UPDATE SET "
               f"last_heartbeat_at = EXCLUDED.last_heartbeat_at, body = EXCLUDED.body")
        with self._store.connection() as conn:
            conn.execute(sql, (node_id, at, json.dumps(body, separators=(",", ":"))))

    def record_claim(self, node_id: str, engine: str | None, at: float) -> None:
        p = self._store.param_style
        sql = (f"INSERT INTO node_liveness (node_id, last_heartbeat_at, last_claim_at, body) "
               f"VALUES ({p}, NULL, {p}, NULL) ON CONFLICT (node_id) DO UPDATE SET "
               f"last_claim_at = EXCLUDED.last_claim_at")
        with self._store.connection() as conn:
            conn.execute(sql, (node_id, at))

    def snapshot(self) -> dict[str, NodeLiveness]:
        with self._store.connection() as conn:
            rows = conn.execute("SELECT node_id, last_heartbeat_at, last_claim_at, body "
                                "FROM node_liveness").fetchall()
        out: dict[str, NodeLiveness] = {}
        for node_id, hb, cl, raw in rows:
            body = None
            if raw:
                try:
                    parsed = json.loads(raw)
                    body = parsed if isinstance(parsed, dict) else None
                except ValueError:
                    body = None
            out[node_id] = NodeLiveness(node_id, hb, cl, None, body)
        return out


class RedisLivenessStore:
    """A hash per node under ``blastbox:liveness:``. No TTL: a node that has gone quiet is
    exactly the row an alert needs to keep seeing."""

    PREFIX = "blastbox:liveness:"

    def __init__(self, client) -> None:
        self._r = client

    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None:
        self._r.hset(self.PREFIX + node_id, mapping={
            "last_heartbeat_at": repr(float(at)),
            "body": json.dumps(body, separators=(",", ":"))})

    def record_claim(self, node_id: str, engine: str | None, at: float) -> None:
        mapping = {"last_claim_at": repr(float(at))}
        if engine:
            mapping["last_claim_engine"] = engine
        self._r.hset(self.PREFIX + node_id, mapping=mapping)

    def snapshot(self) -> dict[str, NodeLiveness]:
        def s(v):
            return v.decode() if isinstance(v, bytes) else v

        out: dict[str, NodeLiveness] = {}
        for key in self._r.scan_iter(match=f"{self.PREFIX}*", count=200):
            key = s(key)
            h = {s(k): s(v) for k, v in (self._r.hgetall(key) or {}).items()}
            if not h:
                continue
            body = None
            if h.get("body"):
                try:
                    parsed = json.loads(h["body"])
                    body = parsed if isinstance(parsed, dict) else None
                except ValueError:
                    body = None
            node_id = key[len(self.PREFIX):]
            out[node_id] = NodeLiveness(
                node_id,
                float(h["last_heartbeat_at"]) if h.get("last_heartbeat_at") else None,
                float(h["last_claim_at"]) if h.get("last_claim_at") else None,
                h.get("last_claim_engine") or None, body)
        return out


def build_liveness_store(store=None) -> LivenessStore:
    """The liveness store matching this deployment's job store (same shape as
    ``build_node_registry``)."""
    if store is None:
        from blastbox.host.jobs.factory import build_job_store_from_env
        store = build_job_store_from_env()
    if hasattr(store, "connection") and hasattr(store, "param_style"):
        return SqlLivenessStore(store)
    client = getattr(store, "_r", None)
    if client is not None and hasattr(client, "scan_iter"):
        return RedisLivenessStore(client)
    return InMemoryLivenessStore()
