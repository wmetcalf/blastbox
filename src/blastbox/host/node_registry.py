"""Federated node registry: who is out there, what they have, and what they may run.

This is the MEMBERSHIP half of the federation design
(``docs/superpowers/specs/2026-09-15-federated-node-identity-and-placement.md``). It is
deliberately NOT :mod:`blastbox.host.node_share`, which is a bind-mounted directory in a
single trust domain — a ``/var/run`` socket dir by its own description — and does not
reach across another operator's hardware because there is no shared filesystem to
permission.

It lives on the store the fleet already coordinates through
(``BLASTBOX_DATABASE_URL``). That is not laziness: ``claim_next`` is already distributed
mutual exclusion with CAS fencing, in production, and its failure semantics are already
understood by whoever is on call. Making that store highly available is a boring solved
problem; a second consensus system would be a new one to reason about during an incident.

CLAIMS ARE NOT FACTS
--------------------
The shape of this module is set by one requirement: **a registered node is untrusted.**
:mod:`blastbox.host.trust` already treats a worker's output as hostile and re-seals every
artifact hash host-side; federation needs that one level up. So a :class:`NodeRecord`
separates two things that look alike and are not:

``claims``
    What the node said about itself — capacity, backlog, its own egress health. Useful,
    unverifiable, and never load-bearing for a security decision.
``identity`` / ``grants``
    Taken from the node's CA-signed certificate by the *reader*, never from the payload
    the node sent. A node cannot widen its own grants by writing a bigger number.

The registry therefore stores what a node asserts, and resolves authority separately.
Anything that reads this to make a placement decision must use ``grants``; anything that
reads ``claims`` is making a performance guess, and should degrade gracefully when the
guess is wrong.
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, Protocol

__all__ = [
    "RedisNodeRegistry",
    "SqlNodeRegistry",
    "build_node_registry",
    "NodeClaims",
    "NodeRecord",
    "NodeRegistry",
    "InMemoryNodeRegistry",
    "STALE_AFTER_S",
    "valid_record",
]

#: A record older than this is ignored by readers. Matches node_share's self-healing
#: property: a stopped node drops out of the view on its own, with no deregistration
#: step that could be missed by a node that died rather than exited.
STALE_AFTER_S = 90.0

#: Bounds every numeric claim is clamped/validated against. A node is untrusted, so a
#: malformed or absurd value must be REJECTED rather than propagated into a sizing
#: calculation where it would silently skew every peer's view.
_MAX_SLOTS = 4096
_MAX_RAM_MIB = 64 * 1024 * 1024
_MAX_BACKLOG = 10_000_000

_NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def _finite_in(value: object, lo: float, hi: float) -> bool:
    """A number, actually finite, within bounds.

    ``math.isfinite`` alone OVERFLOWS on a huge int decoded from JSON, which would raise
    inside a reader and take down the whole view rather than skip one poisoned record —
    the same trap node_share documents.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        if not math.isfinite(float(value)):
            return False
    except (OverflowError, ValueError):
        return False
    return lo <= float(value) <= hi


@dataclass(frozen=True)
class NodeClaims:
    """What a node ASSERTS about itself. Unverified by construction — see the module docstring."""

    #: Engines this node currently has images for and believes it can run.
    engines: tuple[str, ...] = ()
    #: Slots it believes it can offer, and the RAM it believes it has free.
    slots: int = 0
    free_ram_mib: int = 0
    #: Its own queue backlog — a scheduling signal, not a security input.
    backlog: int = 0
    #: The node's own view of its egress containment, from `blastbox egress health`.
    #: Recorded for OBSERVABILITY ONLY. A hostile node reports whatever it likes here;
    #: the spec's §5 answer is that containment is verified from the exit host, which
    #: can see a peer's traffic, not from the peer's own say-so.
    egress_healthy: bool | None = None
    egress_reason: str = ""


@dataclass(frozen=True)
class NodeRecord:
    """One node's published snapshot.

    ``node_id`` is the key and MUST equal the CN of the certificate the node
    authenticated with; a writer that cannot prove that must not be able to publish
    under it. Enforcing that binding is the transport's job (mTLS at the control plane),
    and this module refuses to paper over its absence: see :func:`valid_record`, which
    validates shape only and says so.
    """

    node_id: str
    claims: NodeClaims = field(default_factory=NodeClaims)
    #: Wall-clock seconds. Compared against the reader's clock, so a node with a badly
    #: wrong clock drops out rather than appearing permanently fresh.
    ts: float = 0.0
    #: SHA-256 of the node's certificate, recorded so a reader can notice the identity
    #: behind a node_id changing without a re-enrolment it expected.
    cert_fingerprint: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        d["claims"]["engines"] = list(self.claims.engines)
        return json.dumps(d, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "NodeRecord | None":
        """Parse, or return None. NEVER raise: one poisoned record must not take out the
        whole view, which is the difference between one node misbehaving and the fleet
        losing its ability to place work."""
        try:
            d = json.loads(raw)
            c = d.get("claims") or {}
            return cls(
                node_id=str(d.get("node_id", "")),
                ts=float(d.get("ts", 0.0)),
                cert_fingerprint=str(d.get("cert_fingerprint", "")),
                claims=NodeClaims(
                    engines=tuple(str(x) for x in (c.get("engines") or ())),
                    slots=int(c.get("slots", 0)),
                    free_ram_mib=int(c.get("free_ram_mib", 0)),
                    backlog=int(c.get("backlog", 0)),
                    egress_healthy=(None if c.get("egress_healthy") is None
                                    else bool(c.get("egress_healthy"))),
                    egress_reason=str(c.get("egress_reason", ""))[:200],
                ),
            )
        except (ValueError, TypeError, OverflowError, AttributeError, RecursionError):
            # RecursionError belongs here: json.loads on deeply nested input raises it,
            # and an uncaught one takes out the whole read — one hostile node blinding
            # the fleet's view, which is precisely what this parser promises not to do.
            return None


def valid_record(rec: NodeRecord | None, *, now: float | None = None,
                 stale_after_s: float = STALE_AFTER_S) -> bool:
    """Is this record well-formed and fresh enough to include in the view?

    SHAPE AND FRESHNESS ONLY. This deliberately does not authenticate anything — it
    cannot, from a stored blob — and naming that here is the point: a reader that treats
    a `True` from this function as "this node is who it says" has misread it. Authority
    comes from the certificate, resolved by the reader.

    Age is bounded in BOTH directions. A record more than one window in the FUTURE (a
    node with a bad clock, or one trying to stay permanently fresh) is rejected, or its
    negative age would read as fresh forever.
    """
    if rec is None or not _NODE_ID_RE.match(rec.node_id):
        return False
    if not _finite_in(rec.ts, 0, 4102444800):        # through ~2100
        return False
    age = (time.time() if now is None else now) - rec.ts
    if age > stale_after_s or age < -stale_after_s:
        return False
    c = rec.claims
    if not _finite_in(c.slots, 0, _MAX_SLOTS):
        return False
    if not _finite_in(c.free_ram_mib, 0, _MAX_RAM_MIB):
        return False
    if not _finite_in(c.backlog, 0, _MAX_BACKLOG):
        return False
    if len(c.engines) > 64 or any(not _NODE_ID_RE.match(e) for e in c.engines):
        return False
    return True


class NodeRegistry(Protocol):
    """The federated view. Deliberately tiny — it is a heartbeat board, not a scheduler."""

    def publish(self, rec: NodeRecord) -> None:
        """Upsert this node's snapshot."""

    def read_all(self, *, stale_after_s: float = STALE_AFTER_S) -> list[NodeRecord]:
        """Every fresh, well-formed record. Stale and malformed ones are dropped."""

    def forget(self, node_id: str) -> None:
        """Remove a node's record (a graceful stop; a crash is handled by staleness)."""


class InMemoryNodeRegistry:
    """Single-process registry — for tests and a one-node deployment.

    Mirrors the job store's in-memory backend, including its caveat: `serve` and
    `dispatch` are separate processes and will not share it.
    """

    def __init__(self) -> None:
        self._rows: dict[str, str] = {}

    def publish(self, rec: NodeRecord) -> None:
        if not _NODE_ID_RE.match(rec.node_id):
            raise ValueError(f"invalid node id {rec.node_id!r}")
        self._rows[rec.node_id] = rec.to_json()

    def read_all(self, *, stale_after_s: float = STALE_AFTER_S) -> list[NodeRecord]:
        out: list[NodeRecord] = []
        for raw in list(self._rows.values()):
            rec = NodeRecord.from_json(raw)
            if valid_record(rec, stale_after_s=stale_after_s):
                assert rec is not None
                out.append(rec)
        return sorted(out, key=lambda r: r.node_id)

    def forget(self, node_id: str) -> None:
        self._rows.pop(node_id, None)


def fresh_node_ids(records: Iterable[NodeRecord]) -> tuple[str, ...]:
    """Convenience for callers that only need membership."""
    return tuple(sorted({r.node_id for r in records}))


class SqlNodeRegistry:
    """Registry over the SAME database the job store already uses.

    It borrows that store's connection pool rather than opening its own: the pool is
    sized as the node's concurrency ceiling, so a second one would silently double this
    process's share of postgres' ``max_connections``.

    The table is deliberately dumb — one row per node, the record as JSON text. There is
    no schema for ``claims`` on purpose: claims are an untrusted node's assertions whose
    shape will change, and validation belongs in :func:`valid_record` where it is
    testable, not in a migration.
    """

    def __init__(self, store) -> None:
        self._store = store
        self._init()

    def _init(self) -> None:
        with self._store.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS nodes ("
                " node_id TEXT PRIMARY KEY,"
                " record  TEXT NOT NULL,"
                " ts      DOUBLE PRECISION NOT NULL"
                ")" if self._store.param_style == "%s" else
                "CREATE TABLE IF NOT EXISTS nodes ("
                " node_id TEXT PRIMARY KEY,"
                " record  TEXT NOT NULL,"
                " ts      REAL NOT NULL"
                ")"
            )

    def publish(self, rec: NodeRecord) -> None:
        if not _NODE_ID_RE.match(rec.node_id):
            raise ValueError(f"invalid node id {rec.node_id!r}")
        p = self._store.param_style
        # UPSERT rather than delete+insert: a heartbeat must never leave a window where
        # a live node is absent from the view and gets placed against as if gone.
        sql = (f"INSERT INTO nodes (node_id, record, ts) VALUES ({p}, {p}, {p}) "
               f"ON CONFLICT (node_id) DO UPDATE SET record = EXCLUDED.record, "
               f"ts = EXCLUDED.ts")
        with self._store.connection() as conn:
            conn.execute(sql, (rec.node_id, rec.to_json(), rec.ts))

    def read_all(self, *, stale_after_s: float = STALE_AFTER_S) -> list[NodeRecord]:
        p = self._store.param_style
        cutoff = time.time() - stale_after_s
        # Filter stale rows in SQL so a long-dead fleet does not stream back every row,
        # then re-validate in Python: the stored ts is a node's own claim, and the
        # authoritative freshness check (including the future-dated case) lives in
        # valid_record where it is tested.
        with self._store.connection() as conn:
            cur = conn.execute(f"SELECT record FROM nodes WHERE ts >= {p}", (cutoff,))
            rows = [r[0] for r in cur.fetchall()]
        out: list[NodeRecord] = []
        for raw in rows:
            rec = NodeRecord.from_json(raw)
            if valid_record(rec, stale_after_s=stale_after_s):
                assert rec is not None
                out.append(rec)
        return sorted(out, key=lambda r: r.node_id)

    def forget(self, node_id: str) -> None:
        p = self._store.param_style
        with self._store.connection() as conn:
            conn.execute(f"DELETE FROM nodes WHERE node_id = {p}", (node_id,))


def build_node_registry(store=None) -> NodeRegistry:
    """The registry matching this deployment's job store.

    Same knob, same failure domain, deliberately: a node's membership and its work come
    from one place, so there is no state where a dispatcher can claim jobs but not see
    its peers. (The spec flags the flip side as an open question — a store outage now
    blinds placement as well as stopping job flow.)
    """
    if store is None:
        from blastbox.host.jobs.factory import build_job_store_from_env
        store = build_job_store_from_env()
    if hasattr(store, "connection") and hasattr(store, "param_style"):
        return SqlNodeRegistry(store)
    client = getattr(store, "_r", None)
    if client is not None and hasattr(client, "scan_iter"):
        return RedisNodeRegistry(client)
    # In-memory matches the job store's own single-process default and carries the same
    # caveat: `serve` and `dispatch` are separate processes and will not share it.
    return InMemoryNodeRegistry()


class RedisNodeRegistry:
    """Registry over the Redis the job store already uses.

    One key per node under ``blastbox:node:``, carrying the record as JSON, with a Redis
    TTL as well as the in-record timestamp. BOTH, deliberately: the TTL keeps a dead
    node's key from accumulating forever in a shared Redis an operator also pokes at,
    while :func:`valid_record` remains the authority on freshness — it is the one that
    also rejects a future-dated record, which a TTL cannot see.

    The TTL is generously longer than the staleness window so expiry never races a
    reader into dropping a node that is merely a heartbeat behind; the record's own ``ts``
    is what actually decides.
    """

    PREFIX = "blastbox:node:"

    def __init__(self, client, *, stale_after_s: float = STALE_AFTER_S) -> None:
        self._r = client
        self._ttl = int(max(60.0, stale_after_s * 10))

    def _key(self, node_id: str) -> str:
        return f"{self.PREFIX}{node_id}"

    def publish(self, rec: NodeRecord) -> None:
        if not _NODE_ID_RE.match(rec.node_id):
            raise ValueError(f"invalid node id {rec.node_id!r}")
        self._r.set(self._key(rec.node_id), rec.to_json(), ex=self._ttl)

    def read_all(self, *, stale_after_s: float = STALE_AFTER_S) -> list[NodeRecord]:
        out: list[NodeRecord] = []
        # SCAN, not KEYS: this runs on a schedule against a Redis that is also serving
        # the job store, and KEYS blocks the server for the whole keyspace.
        for key in self._r.scan_iter(match=f"{self.PREFIX}*", count=200):
            raw = self._r.get(key)
            if raw is None:              # expired between the scan and the get
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            rec = NodeRecord.from_json(raw)
            if valid_record(rec, stale_after_s=stale_after_s):
                assert rec is not None
                out.append(rec)
        return sorted(out, key=lambda r: r.node_id)

    def forget(self, node_id: str) -> None:
        self._r.delete(self._key(node_id))
