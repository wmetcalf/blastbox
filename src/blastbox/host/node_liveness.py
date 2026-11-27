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
import os
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator, Literal, Mapping, Protocol

if TYPE_CHECKING:
    from blastbox.host.pki import NodeIdentity

__all__ = [
    "ClaimThrottle", "CERT_EXPIRED_GRACE_S",
    "NodeLiveness", "LivenessStore", "InMemoryLivenessStore", "SqlLivenessStore",
    "RedisLivenessStore", "build_liveness_store",
    "safe_record_heartbeat", "safe_record_claim",
    "LivenessConfig", "Alert", "evaluate", "enrolled_nodes", "oldest_queued",
    "LivenessMonitor", "LivenessCollector", "heartbeat_interval_s",
]

_log = logging.getLogger("blastbox.node_liveness")


@dataclass(frozen=True)
class NodeLiveness:
    node_id: str
    last_heartbeat_at: float | None = None
    last_claim_at: float | None = None
    last_claim_engine: str | None = None   # not persisted by the SQL backend
    body: dict[str, Any] | None = None     # the node's own claim; never trusted
    #: engine -> last claim attempt for it ("" = an unscoped claim, i.e. every grant). A claim
    #: is evidence of serving THAT engine only: a node polling one engine says nothing about
    #: another whose claim loop is wedged.
    claims: Mapping[str, float] = field(default_factory=dict)


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


class ClaimThrottle:
    """At most one claim write per node per ``min_interval_s``, in process. Agents poll every
    ~2 s per slot, so unthrottled this is a write per poll; ``last_claim_at`` stays accurate to
    within the interval, which is far inside any silence threshold."""

    def __init__(self, min_interval_s: float = 5.0) -> None:
        self._min = min_interval_s
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def allow(self, node_id: str, at: float) -> bool:
        with self._lock:
            prev = self._last.get(node_id)
            if prev is not None and 0 <= at - prev < self._min:
                return False
            self._last[node_id] = at
            return True


class InMemoryLivenessStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, NodeLiveness] = {}

    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None:
        with self._lock:
            old = self._rows.get(node_id) or NodeLiveness(node_id)
            self._rows[node_id] = replace(old, last_heartbeat_at=at, body=dict(body))

    def record_claim(self, node_id: str, engine: str | None, at: float) -> None:
        with self._lock:
            old = self._rows.get(node_id) or NodeLiveness(node_id)
            self._rows[node_id] = replace(old, last_claim_at=at, last_claim_engine=engine,
                                          claims={**old.claims, engine or "": at})

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
            conn.execute(
                "CREATE TABLE IF NOT EXISTS node_liveness_claims ("
                " node_id TEXT NOT NULL,"
                " engine TEXT NOT NULL,"
                f" at {real} NOT NULL,"
                " PRIMARY KEY (node_id, engine))")

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
        per = (f"INSERT INTO node_liveness_claims (node_id, engine, at) VALUES ({p}, {p}, {p}) "
               f"ON CONFLICT (node_id, engine) DO UPDATE SET at = EXCLUDED.at")
        with self._store.connection() as conn:
            conn.execute(sql, (node_id, at))
            conn.execute(per, (node_id, engine or "", at))

    def snapshot(self) -> dict[str, NodeLiveness]:
        with self._store.connection() as conn:
            rows = conn.execute("SELECT node_id, last_heartbeat_at, last_claim_at, body "
                                "FROM node_liveness").fetchall()
            per = conn.execute("SELECT node_id, engine, at FROM node_liveness_claims").fetchall()
        claims: dict[str, dict[str, float]] = {}
        for node_id, eng, at in per:
            claims.setdefault(node_id, {})[eng] = float(at)
        out: dict[str, NodeLiveness] = {}
        for node_id, hb, cl, raw in rows:
            body = None
            if raw:
                try:
                    parsed = json.loads(raw)
                    body = parsed if isinstance(parsed, dict) else None
                except ValueError:
                    body = None
            out[node_id] = NodeLiveness(node_id, hb, cl, None, body, claims.get(node_id, {}))
        return out


class RedisLivenessStore:
    """A hash per node under ``blastbox:liveness:``. No TTL: a node that has gone quiet is
    exactly the row an alert needs to keep seeing."""

    PREFIX = "blastbox:liveness:"
    CLAIM = "claim:"            # per-engine claim field prefix ("claim:" alone = unscoped)

    def __init__(self, client) -> None:
        self._r = client

    def record_heartbeat(self, node_id: str, body: dict, at: float) -> None:
        self._r.hset(self.PREFIX + node_id, mapping={
            "last_heartbeat_at": repr(float(at)),
            "body": json.dumps(body, separators=(",", ":"))})

    def record_claim(self, node_id: str, engine: str | None, at: float) -> None:
        key = self.PREFIX + node_id
        self._r.hset(key, mapping={"last_claim_at": repr(float(at)),
                                   "last_claim_engine": engine or "",
                                   self.CLAIM + (engine or ""): repr(float(at))})
        # "" reads back as None (snapshot's `or None`), i.e. engine=None overwrites the prior
        # engine exactly as the memory store does.

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
                h.get("last_claim_engine") or None, body,
                {k[len(self.CLAIM):]: float(v) for k, v in h.items()
                 if k.startswith(self.CLAIM)})
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
    _log.warning("node_liveness: job store %s has no SQL or Redis backing; liveness is kept "
                 "in memory only, per process, and is lost on restart",
                 type(store).__name__)
    return InMemoryLivenessStore()


# ---------------------------------------------------------------------------------------------
# Alert evaluation (C2)
# ---------------------------------------------------------------------------------------------

AlertKind = Literal["node_silent", "node_unhealthy", "engine_orphaned", "cert_expiring",
                    "cert_expired"]

#: A cert that lapsed within this window stays in the evaluation as ``cert_expired``.
CERT_EXPIRED_GRACE_S = 86400.0


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return v if v > 0 and v != float("inf") else default


def heartbeat_interval_s() -> int:
    """The heartbeat interval ``/v1/nodes/heartbeat`` hands to agents (clamped to 10..300 s).
    The ``node_silent`` default is derived from it, so the two can never disagree."""
    try:
        v = int(os.environ.get("BLASTBOX_NODE_HEARTBEAT_S", "30"))
    except ValueError:
        v = 30
    return max(10, min(300, v))


@dataclass(frozen=True)
class LivenessConfig:
    """Alert thresholds. Every value is shown in the ``/v1/fleet/liveness`` JSON."""

    silent_after_s: float = 90.0
    orphaned_after_s: float = 300.0
    cert_expiring_s: float = 172800.0
    #: Engines watched for ``engine_orphaned``. Empty = every engine granted to at least one
    #: enrolled node, so a pure push-path deployment (dispatchers, no nodes) never alarms.
    orphaned_engines: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "LivenessConfig":
        raw = os.environ.get("BLASTBOX_ENGINE_ORPHANED_ENGINES", "")
        return cls(
            # §10: silent after 3 x heartbeat_s (90 s at the default 30 s interval).
            silent_after_s=_env_float("BLASTBOX_NODE_SILENT_AFTER_S",
                                      3.0 * heartbeat_interval_s()),
            orphaned_after_s=_env_float("BLASTBOX_ENGINE_ORPHANED_AFTER_S", 300.0),
            cert_expiring_s=_env_float("BLASTBOX_NODE_CERT_EXPIRING_S", 172800.0),
            orphaned_engines=tuple(sorted({e.strip() for e in raw.split(",") if e.strip()})),
        )

    def as_json(self) -> dict[str, Any]:
        return {"silent_after_s": self.silent_after_s,
                "orphaned_after_s": self.orphaned_after_s,
                "cert_expiring_s": self.cert_expiring_s,
                "orphaned_engines": list(self.orphaned_engines)}


@dataclass(frozen=True)
class Alert:
    kind: AlertKind
    subject: str          # a node id or an engine name -- bounded label cardinality
    since: float
    detail: str

    def as_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "subject": self.subject, "since": self.since,
                "detail": self.detail}


def _engines_of(live: "NodeLiveness | None") -> list[dict[str, Any]]:
    raw = (live.body or {}).get("engines") if live else None
    return [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []


def _within(ts: float | None, now: float, cfg: LivenessConfig) -> bool:
    """``ts`` is inside the silence window. One further ahead of ``now`` than the window itself
    is NOT: after a backward clock step a live node rewrites its row on its next request, so
    only a dead node keeps a future timestamp -- and it must not read as alive."""
    return ts is not None and abs(now - ts) <= cfg.silent_after_s


def _fresh(live: "NodeLiveness | None", now: float, cfg: LivenessConfig) -> bool:
    return live is not None and _within(live.last_heartbeat_at, now, cfg)


#: How recent a claim attempt must be to count as "polling". Agents poll /claim every ~2 s
#: (30 s at most under back-off) WHATEVER the heartbeat interval is, so this does not stretch
#: with ``silent_after_s``: a node that stopped claiming must not keep serving for 3 x 300 s.
CLAIM_FRESH_S = 90.0


def _claimed(live: NodeLiveness, eng: str, now: float, cfg: LivenessConfig) -> bool:
    w = min(cfg.silent_after_s, CLAIM_FRESH_S)

    def ok(ts: float | None) -> bool:
        return ts is not None and abs(now - ts) <= w
    return ok(live.claims.get(eng)) or ok(live.claims.get(""))


def _serves(live: "NodeLiveness | None", eng: str, now: float, cfg: LivenessConfig) -> bool:
    """A fresh heartbeat with a passing selftest for ``eng``, AND evidence of taking its work: a
    claim attempt FOR IT (or an unscoped one) within :data:`CLAIM_FRESH_S`, or a busy slot on it.
    A shadow agent (claim=false) heartbeats a passing selftest and never claims, so it must not
    hide orphaned work; a node polling one engine says nothing about another. Claims never stand
    in for a heartbeat (§10: a node with no heartbeat is silent, so it serves nothing)."""
    if live is None or not _fresh(live, now, cfg):
        return False
    mine = [e for e in _engines_of(live) if e.get("name") == eng and e.get("selftest_ok")]
    if not mine:
        return False
    busy = any(isinstance(e.get("busy"), int) and e.get("busy", 0) > 0 for e in mine)
    return busy or _claimed(live, eng, now, cfg)


def evaluate(*, now: float, enrolled: "Mapping[str, NodeIdentity]", live: dict[str, NodeLiveness],
             oldest_queued: dict[str, float], cfg: LivenessConfig) -> list[Alert]:
    """Pure alert evaluation. ``enrolled`` maps node id -> ``pki.NodeIdentity`` for the
    verifying certificates that are unexpired or expired within :data:`CERT_EXPIRED_GRACE_S`.
    An unexpired node is expected to be alive; an expired one raises ``cert_expired`` instead of
    vanishing (a dead node whose cert lapsed is still a dead node)."""
    alerts: list[Alert] = []
    for node_id in sorted(enrolled):
        ident = enrolled[node_id]
        lv = live.get(node_id)
        not_after = ident.not_after.timestamp()
        if not_after <= now:
            # `since` is the onset (the instant it lapsed), so it is the same on every process
            # and across restarts rather than whenever this process first looked.
            alerts.append(Alert("cert_expired", node_id, not_after,
                                f"certificate expired {now - not_after:.0f}s ago"))
            continue
        if lv is not None and _fresh(lv, now, cfg):
            engines = _engines_of(lv)
            bad = sorted(str(e.get("name", "")) for e in engines if not e.get("selftest_ok"))
            if not engines:
                alerts.append(Alert("node_unhealthy", node_id, lv.last_heartbeat_at or now,
                                    "heartbeating with no engines"))
            elif bad:
                alerts.append(Alert("node_unhealthy", node_id, lv.last_heartbeat_at or now,
                                    "selftest failing for: " + ", ".join(bad)))
        else:
            hb = lv.last_heartbeat_at if lv else None
            since = hb if hb is not None else ident.not_before.timestamp()
            detail = ("never heartbeated" if hb is None
                      else f"no heartbeat for {now - hb:.0f}s (limit {cfg.silent_after_s:g}s)")
            alerts.append(Alert("node_silent", node_id, since, detail))
        if not_after - now < cfg.cert_expiring_s:
            alerts.append(Alert("cert_expiring", node_id, not_after - cfg.cert_expiring_s,
                                f"certificate expires in {max(0.0, not_after - now):.0f}s"))
    granted: dict[str, set[str]] = {}
    expected: set[str] = set()
    for node_id, ident in enrolled.items():
        # An engine whose only node just lapsed is still EXPECTED to be served -- that is the
        # incident -- so it stays watched; the lapsed node just cannot be one of its servers.
        expected.update(ident.grants.engines)
        if ident.not_after.timestamp() <= now:
            continue                       # an expired cert serves nothing
        for eng in ident.grants.engines:
            granted.setdefault(eng, set()).add(node_id)
    watched = set(cfg.orphaned_engines) if cfg.orphaned_engines else expected
    for eng in sorted(watched):
        oldest = oldest_queued.get(eng)
        if oldest is None or now - oldest <= cfg.orphaned_after_s:
            continue
        servers = [n for n in granted.get(eng, ()) if _serves(live.get(n), eng, now, cfg)]
        if not servers:
            alerts.append(Alert(
                "engine_orphaned", eng, oldest,
                f"queued work {now - oldest:.0f}s old and no enrolled node with a fresh "
                f"heartbeat, a passing selftest and a recent claim serves it "
                f"({len(granted.get(eng, ()))} granted)"))
    return alerts


def enrolled_nodes(pki_dir: "Path | str", *, now: float | None = None) -> "dict[str, NodeIdentity]":
    """Node id -> ``NodeIdentity`` for every verifying, unexpired ``*.crt`` in ``pki_dir``
    (same scan as ``placement.fleet_grants``). Two certs for one id (a re-issue overlap) merge
    to the intersection of grants and the LATER expiry, so an overlap never false-alarms.
    Certs that expired within :data:`CERT_EXPIRED_GRACE_S` are kept (see :func:`evaluate`)."""
    from blastbox.host.pki import load_trust_anchor, node_identity

    d = Path(pki_dir)
    now_ = time.time() if now is None else now
    cutoff = now_ - CERT_EXPIRED_GRACE_S
    out: dict[str, Any] = {}
    try:
        ca = load_trust_anchor(d)
    except Exception:  # noqa: BLE001 - nothing verifies, nothing is expected
        return out
    for crt in sorted(d.glob("*.crt")):
        try:
            ident = node_identity(ca, crt.read_bytes(), allow_expired=True)
        except Exception:  # noqa: BLE001 - one bad file is not a fleet outage
            continue
        if ident.not_after.timestamp() <= cutoff:
            continue                         # long gone: decommissioned, not an incident
        prior = out.get(ident.node_id)
        if prior is not None and (prior.not_after.timestamp() <= now_) != (
                ident.not_after.timestamp() <= now_):
            # One lapsed, one valid: authorisation ignores the lapsed one, so must this --
            # intersecting would drop the grants actually in force (a false engine_orphaned).
            if ident.not_after.timestamp() <= now_:
                continue
            out[ident.node_id] = ident
            continue
        if prior is not None:
            from blastbox.host.pki import NodeGrants
            grants = NodeGrants(
                engines=tuple(sorted(set(prior.grants.engines) & set(ident.grants.engines))),
                tiers=tuple(sorted(set(prior.grants.tiers) & set(ident.grants.tiers))),
                credentials=prior.grants.credentials and ident.grants.credentials)
            ident = replace(ident, grants=grants,
                            not_after=max(prior.not_after, ident.not_after),
                            not_before=min(prior.not_before, ident.not_before))
        out[ident.node_id] = ident
    return out


def oldest_queued(job_store: Any) -> dict[str, float]:
    """Engine -> ``created_at`` of its oldest QUEUED job. One GROUP BY on SQL stores
    (``oldest_queued_by_engine``); a full QUEUED scan otherwise. NOT a bounded prefix: the
    oldest N jobs globally can all belong to one engine and hide every other engine's backlog
    (Redis and memory stores scan every key before any limit anyway). The monitor caches the
    result, so this runs at most once per ``QUEUED_TTL_S``."""
    fast = getattr(job_store, "oldest_queued_by_engine", None)
    try:
        if callable(fast):
            return dict(fast())
        from blastbox.host.jobs.base import JobStatus
        out: dict[str, float] = {}
        for j in job_store.list(JobStatus.QUEUED):
            if j.created_at is not None and (j.engine not in out or j.created_at < out[j.engine]):
                out[j.engine] = j.created_at
        return out
    except Exception:  # noqa: BLE001 - a store that cannot enumerate means "unknown", not alarm
        _log.warning("node_liveness: could not read queue ages", exc_info=True)
        return {}


@dataclass
class _View:
    now: float
    cfg: LivenessConfig
    enrolled: dict[str, Any]
    live: dict[str, NodeLiveness]
    oldest_queued: dict[str, float]
    alerts: list[Alert] = field(default_factory=list)


class LivenessMonitor:
    """Owns the inputs to :func:`evaluate` and the once-per-transition logging memo."""

    def __init__(self, *, liveness: LivenessStore, job_store: Any, pki_dir: "Path | str",
                 cfg: LivenessConfig | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._liveness = liveness
        self._jobs = job_store
        self._pki = pki_dir
        self.cfg = cfg or LivenessConfig.from_env()
        self._clock = clock
        self._lock = threading.Lock()
        self._memo: dict[tuple[str, str], Alert] = {}
        self._enrolled_cache: tuple[Any, float, dict[str, Any]] | None = None
        self._queued_cache: tuple[float, dict[str, float]] | None = None

    def _pki_signature(self) -> tuple:
        try:
            return tuple(sorted((c.name, c.stat().st_mtime_ns, c.stat().st_size)
                                for c in Path(self._pki).glob("*.crt")))
        except OSError:
            return ("unreadable", self._clock())

    def _enrolled(self, now: float) -> dict[str, Any]:
        """The cert scan verifies every certificate (O(certs)); /metrics may be public, so it is
        cached for ENROLLED_TTL_S, keyed on the directory signature."""
        sig = self._pki_signature()
        c = self._enrolled_cache
        if c is not None and c[0] == sig and 0 <= now - c[1] < self.ENROLLED_TTL_S:
            return c[2]
        got = enrolled_nodes(self._pki, now=now)
        self._enrolled_cache = (sig, now, got)
        return got

    ENROLLED_TTL_S = 10.0
    #: Queue ages are cached too: on a store without ``oldest_queued_by_engine`` (Redis) the
    #: fallback scans every job key, and /metrics may be public. 10 s is far inside the 300 s
    #: orphan threshold.
    QUEUED_TTL_S = 10.0

    def _queued(self, now: float) -> dict[str, float]:
        c = self._queued_cache
        if c is not None and 0 <= now - c[0] < self.QUEUED_TTL_S:
            return c[1]
        got = oldest_queued(self._jobs)
        self._queued_cache = (now, got)
        return got

    def view(self) -> _View:
        # ONE critical section from the clock read to the memo update: the 15 s loop, /metrics
        # and /v1/fleet/liveness call this concurrently, and a view evaluated earlier but
        # applied later would re-raise an alert a newer view had cleared (and race the caches).
        with self._lock:
            return self._view_locked()

    def _view_locked(self) -> _View:
        now = self._clock()
        enrolled = self._enrolled(now)
        live = self._liveness.snapshot()
        queued = self._queued(now)
        alerts = evaluate(now=now, enrolled=enrolled, live=live, oldest_queued=queued,
                          cfg=self.cfg)
        seen: set[tuple[str, str]] = {(a.kind, a.subject) for a in alerts}
        stable: list[Alert] = []
        for a in alerts:
            key = (a.kind, a.subject)
            prior = self._memo.get(key)
            if prior is None:
                _log.error("ALERT %s subject=%s: %s", a.kind, a.subject, a.detail)
            else:
                a = replace(a, since=prior.since)   # `since` is when it began, not last seen
            self._memo[key] = a
            stable.append(a)
        for gone_key in [k for k in self._memo if k not in seen]:
            gone = self._memo.pop(gone_key)
            _log.info("CLEARED %s subject=%s (was: %s)", gone_key[0], gone_key[1],
                      gone.detail)
        return _View(now, self.cfg, enrolled, live, queued, stable)

    def as_json(self) -> dict[str, Any]:
        v = self.view()
        nodes = []
        for node_id in sorted(set(v.enrolled) | set(v.live)):
            lv = v.live.get(node_id)
            ident = v.enrolled.get(node_id)
            body = (lv.body or {}) if lv else {}
            nodes.append({
                "node_id": node_id,
                "last_heartbeat_at": lv.last_heartbeat_at if lv else None,
                "last_claim_at": lv.last_claim_at if lv else None,
                "agent_version": body.get("agent_version") or None,
                "engines": _engines_of(lv),
                "cert_not_after": ident.not_after.timestamp() if ident else None,
            })
        return {"config": v.cfg.as_json(), "nodes": nodes,
                "alerts": [a.as_json() for a in v.alerts], "generated_at": v.now}


class LivenessCollector:
    """Prometheus custom collector: re-evaluates on every scrape, so the gauges are fresh and
    a node that vanished stops being exported. Subjects are node ids / engine names only."""

    def __init__(self, monitor: LivenessMonitor) -> None:
        self._m = monitor

    def collect(self) -> Iterator[Any]:
        from prometheus_client.core import GaugeMetricFamily as G

        try:
            v = self._m.view()
        except Exception:  # noqa: BLE001 - a scrape must not fail on liveness
            _log.exception("node_liveness: evaluation failed during scrape")
            return
        hb = G("blastbox_node_last_heartbeat_seconds",
               "Unix time of the node's last heartbeat", labels=["node"])
        cl = G("blastbox_node_last_claim_seconds",
               "Unix time of the node's last claim", labels=["node"])
        st = G("blastbox_node_selftest_ok", "1 if the engine's last selftest passed",
               labels=["node", "engine"])
        ce = G("blastbox_node_cert_expiry_seconds",
               "Unix time the node's enrolled certificate expires", labels=["node"])
        oq = G("blastbox_engine_oldest_queued_seconds",
               "Age in seconds of the oldest QUEUED job for the engine", labels=["engine"])
        al = G("blastbox_node_alert", "1 while the alert is active", labels=["kind", "subject"])
        # Per-node series only for nodes still in the expected set: a node whose certificate
        # is gone stops being exported (its row is kept, but it is no longer anyone's node).
        for node_id, lv in sorted(v.live.items()):
            if node_id not in v.enrolled:
                continue
            if lv.last_heartbeat_at is not None:
                hb.add_metric([node_id], lv.last_heartbeat_at)
            if lv.last_claim_at is not None:
                cl.add_metric([node_id], lv.last_claim_at)
            # One series per (node, engine): a body naming an engine twice would otherwise
            # emit a duplicate sample, and Prometheus rejects the WHOLE scrape for that. Any
            # failing entry wins, so a duplicate cannot mask a failure.
            ok: dict[str, bool] = {}
            for e in _engines_of(lv):
                name = str(e.get("name", ""))
                ok[name] = ok.get(name, True) and bool(e.get("selftest_ok"))
            for name, good in sorted(ok.items()):
                st.add_metric([node_id, name], 1.0 if good else 0.0)
        for node_id, ident in sorted(v.enrolled.items()):
            ce.add_metric([node_id], ident.not_after.timestamp())
        for eng, ts in sorted(v.oldest_queued.items()):
            oq.add_metric([eng], max(0.0, v.now - ts))
        for a in v.alerts:
            al.add_metric([a.kind, a.subject], 1.0)
        yield from (hb, cl, st, ce, oq, al)
