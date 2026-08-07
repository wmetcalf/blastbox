"""Static worker-pool runtime (SlotRuntime) for pre-provisioned, always-on workers.

The AWS/FC/gVisor tiers *create* a worker per slot (spawn -> boot -> terminate). This backend is the
opposite: a **fixed fleet of long-lived boxes** (bare-metal or VMs) that each already run the generic
``blastbox.worker.http_agent``. "Spawning" a slot just **claims a free box** from the registered list;
"reaping" it **returns the box to the pool** -- nothing is booted or torn down. Same network-endpoint
slot shape as :class:`~blastbox.host.runtime.aws_worker.AwsWorkerSlot`, so the ``remote_http`` transport
and ``VmJobDispatcher`` drive it unchanged.

Selected by ``BLASTBOX_POOL_RUNTIME=static``; the fleet is declared in ``BLASTBOX_STATIC_WORKERS`` (a
comma-list of ``host:port`` or ``http://host:port`` endpoints). Because the fleet is finite, size the pool
to it: keep ``BLASTBOX_POOL_CEILING <= len(workers)`` (a spawn beyond the fleet raises ``StaticPoolExhausted``).

Fail-closed: ``available()`` returns False unless at least one configured box answers ``/healthz``.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from blastbox.host.pool import RuntimeAtCapacity, SlotState
from blastbox.host.runtime.aws_worker import _MIN_PROBE_S, HttpProbe, _default_http_probe

_log = logging.getLogger("blastbox.host.runtime.static_pool")


class StaticPoolExhausted(RuntimeAtCapacity):
    """All registered workers are already CLAIMED (pool ceiling exceeds the fleet size).

    Routine backpressure. See StaticPoolUnhealthy for the case where workers are free but none
    of them is healthy -- conflating the two hides a dead fleet behind a "we're busy" counter."""


class StaticPoolUnhealthy(RuntimeError):
    """Free workers exist but NONE passed its health probe -- the fleet is broken, not busy.

    Deliberately NOT a RuntimeAtCapacity: as capacity this is logged at debug and counted on the
    capacity-miss meter, so a fleet-wide agent death would be indistinguishable from saturation
    and the only symptom would be a sagging warm-hit rate."""


class StaticPoolUnavailable(RuntimeError):
    """No worker is configured / reachable -- the tier must not be selected."""


def _env(get: Callable[[str], str | None], key: str, default: str | None = None) -> str | None:
    v = get(key)
    return v if (v is not None and v != "") else default


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StaticWorker:
    """One registered always-on worker. ``url`` (a full base URL) wins over ``host``/``port``."""

    host: str | None = None
    port: int = 8765
    url: str | None = None
    token: str | None = None

    @classmethod
    def parse(cls, spec: str, *, default_port: int, default_token: str | None) -> StaticWorker:
        """Parse one ``BLASTBOX_STATIC_WORKERS`` item: ``http://h:p``, ``h:p``, or ``h``."""
        spec = spec.strip()
        if spec.startswith(("http://", "https://")):
            return cls(url=spec.rstrip("/"), token=default_token)
        host, _, port = spec.partition(":")
        return cls(host=host, port=int(port) if port else default_port, token=default_token)


@dataclass(frozen=True)
class StaticPoolConfig:
    workers: tuple[StaticWorker, ...] = ()
    health_path: str = "/healthz"
    probe_timeout_s: float = 5.0
    # after a DIRTY release (timeout/trust-fail/agent error) a box is held out of the free set this
    # long, so a stale request still executing in the long-lived agent has time to drain before reuse.
    dirty_cooldown_s: float = 60.0
    def __post_init__(self) -> None:
        # BLASTBOX_STATIC_PROBE_TIMEOUT_S is operator-settable, and this is the ONLY tier where it
        # is -- a 0 there put the socket in NON-BLOCKING mode, so connect raised EINPROGRESS and the
        # whole fleet was convicted in one health tick (issue #77 marla-loop 4). Every AWS config
        # clamps its probe budgets in __post_init__; this one had none at all.
        if self.probe_timeout_s < _MIN_PROBE_S:
            object.__setattr__(self, "probe_timeout_s", _MIN_PROBE_S)


    @classmethod
    def from_env(cls, get: Callable[[str], str | None], **overrides: Any) -> StaticPoolConfig:
        default_port = int(_env(get, "BLASTBOX_STATIC_AGENT_PORT", "8765") or "8765")
        token = _env(get, "BLASTBOX_STATIC_WORKER_TOKEN")
        raw = _env(get, "BLASTBOX_STATIC_WORKERS") or ""
        workers = tuple(
            StaticWorker.parse(item, default_port=default_port, default_token=token)
            for item in raw.split(",")
            if item.strip()
        )
        return cls(
            workers=workers,
            health_path=_env(get, "BLASTBOX_STATIC_HEALTH_PATH", "/healthz") or "/healthz",
            probe_timeout_s=float(_env(get, "BLASTBOX_STATIC_PROBE_TIMEOUT_S", "5") or "5"),
            dirty_cooldown_s=float(_env(get, "BLASTBOX_STATIC_DIRTY_COOLDOWN_S", "60") or "60"),
            **overrides,
        )


# ---------------------------------------------------------------------------
# Slot handle (network-endpoint flavored, like AwsWorkerSlot)
# ---------------------------------------------------------------------------

@dataclass
class StaticWorkerSlot:
    slot_id: str
    worker_index: int                    # which registered box this slot holds (reap -> free)
    ip: str | None = None
    url: str | None = None
    auth_token: str | None = None
    agent_port: int = 8765
    state: SlotState = SlotState.SPAWNING
    jobs: int = 0
    spawned_at: float = 0.0
    reserved: bool = False

    @property
    def endpoint(self) -> tuple[str, int] | None:
        if self.ip is not None:
            return (self.ip, self.agent_port)
        return None


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

@dataclass
class _Counter:
    _seq: Any = field(default_factory=lambda: itertools.count(1))

    def next(self) -> int:
        return next(self._seq)


class StaticPoolRuntime:
    """SlotRuntime over a fixed fleet of always-on http_agent workers. ``spawn`` claims a free box
    (skipping any that fail ``/healthz``); ``reap`` returns it (never boots/terminates). No ``recycle``
    -> WarmPool treats each claim as one-job-then-return; that reuse needs no reset because the
    http_agent runs every job in a fresh temp dir and re-seals its own output (stateless per the
    sealed-envelope contract).

    The free-set is **in-process**: a single dispatcher process is assumed to own the pool (as every
    warm tier does -- ``BLASTBOX_DISPATCH_CONCURRENCY`` threads in one process). Running multiple
    dispatcher processes against the same fleet would double-claim boxes; that would need an external
    coordinator (out of scope)."""

    kind = "static"
    dispatch_style = "network"   # driven over http_agent + remote_http (VmJobDispatcher)

    def __init__(
        self,
        cfg: StaticPoolConfig,
        *,
        http_probe: HttpProbe | None = None,
        clock: Callable[[], float] | None = None,
        ssl_context: Any = None,
    ) -> None:
        self.cfg = cfg
        self._probe = http_probe or _default_http_probe
        self._clock = clock or time.monotonic
        # client (m)TLS context for https workers -- the dispatcher hands this to make_remote_validate
        # so the transport verifies the worker + presents its client cert.
        self.ssl_context = ssl_context
        self._tls = bool(ssl_context)
        self._lock = threading.Lock()
        self._free: list[int] = list(range(len(cfg.workers)))
        self._ids = _Counter()
        # worker_index -> monotonic time until which a DIRTY-released box stays quarantined (a stale,
        # possibly-still-running request must be given time to drain before the box is re-offered).
        self._cooldown_until: dict[int, float] = {}
        self._dirty_cooldown_s = cfg.dirty_cooldown_s

    # -- helpers ------------------------------------------------------------
    def _base_url(self, w: StaticWorker) -> str:
        if w.url:
            url = w.url.rstrip("/")
            if self._tls and url.startswith("http://"):
                # never send tokens/samples in the clear when the pool has an mTLS context
                _log.warning("static: forcing https on plaintext worker %s (dispatcher TLS is on)", url)
                url = "https://" + url[len("http://"):]
            return url
        scheme = "https" if self._tls else "http"  # host:port workers follow the pool's TLS mode
        return f"{scheme}://{w.host}:{w.port}"

    def _health_ok(self, w: StaticWorker, timeout: float | None = None) -> "bool | None":
        """Tri-state reachability: True/False are real answers, None = we could not ASK.

        A LOCAL-EXHAUSTION failure (EMFILE/ENFILE/ENOMEM) is our side failing, not the box's
        verdict, and it hits every worker on the same tick. NB a refusal or reset is NOT that: those
        are real answers about the box and still return False -- an earlier version of this
        docstring had that backwards.
        Callers that need a plain bool coerce with ``is True``; only is_alive() forwards the
        UNKNOWN, so the pool can keep the slot and bound how long it stays that way rather than
        marking the whole tier dead at once (issue #77 marla-loop 2)."""
        url = self._base_url(w) + self.cfg.health_path
        headers = {"X-aws-proxy-auth": w.token} if w.token else {}
        try:
            answer = self._probe(
                url, headers,
                max(_MIN_PROBE_S, float(self.cfg.probe_timeout_s) if timeout is None else timeout))
            # NOT bool(): bool(None) is False, which would silently convert the UNKNOWN this method
            # promises to forward into a confirmed "dead" (issue #77 marla-loop 4).
            return None if answer is None else bool(answer)
        except OSError as exc:
            _log.debug("static: health probe %s could not be attempted: %s", url, exc)
            return None

    # -- fail-closed availability ------------------------------------------
    def available(self) -> bool:
        """True iff at least one registered worker answers /healthz (fail-closed)."""
        return any(self._health_ok(w) is True for w in self.cfg.workers)

    # -- SlotRuntime protocol ----------------------------------------------
    def spawn(self) -> StaticWorkerSlot:
        with self._lock:
            candidates = list(self._free)
        if not candidates:
            raise StaticPoolExhausted(
                f"all {len(self.cfg.workers)} static workers claimed "
                "(set BLASTBOX_POOL_CEILING <= fleet size)"
            )
        # claim the first free box that actually answers /healthz -- don't hand out a dead one
        # (probe outside the lock; re-check under it in case another thread claimed it meanwhile).
        now = self._clock()
        for idx in candidates:
            with self._lock:
                cool = self._cooldown_until.get(idx, 0.0)
            if cool > now:
                _log.info("static: worker[%d] cooling down (%.0fs left), skipping for this claim",
                          idx, cool - now)
                continue
            if self._health_ok(self.cfg.workers[idx]) is not True:
                _log.warning("static: worker[%d] unhealthy, skipping for this claim", idx)
                continue
            with self._lock:
                if idx not in self._free:
                    continue
                self._free.remove(idx)
            w = self.cfg.workers[idx]
            slot = StaticWorkerSlot(
                slot_id=f"static-{self._ids.next()}",
                worker_index=idx,
                ip=w.host,
                url=self._base_url(w),   # carries the scheme (https when TLS) for the transport
                auth_token=w.token,
                agent_port=w.port,
                state=SlotState.WARMING,
                spawned_at=self._clock(),
            )
            _log.info("static: claimed worker[%d] %s for slot=%s", idx, self._base_url(w), slot.slot_id)
            return slot
        raise StaticPoolUnhealthy("no free static worker is currently healthy")

    def is_ready(self, slot: StaticWorkerSlot) -> bool:
        return self._health_ok(self.cfg.workers[slot.worker_index]) is True

    def is_alive(self, slot: StaticWorkerSlot) -> "bool | None":
        """always-on boxes: "alive" == reachable. Tri-state (issue #77 marla-loop 2).

        A LOCAL failure to even attempt the probe -- OSError from the socket layer: EMFILE, ENOMEM,
        no route because the host's own networking is being reconfigured -- says nothing about the
        box and hits every worker in the fleet on the same tick. Returning a plain False there
        marked the whole tier dead at once, the exact fault `_aws` was hardened against. An HTTP
        answer (or a clean connection refusal) is still a real verdict."""
        return self._health_ok(self.cfg.workers[slot.worker_index])

    def is_alive_for_claim(self, slot: StaticWorkerSlot, *,
                           budget_s: float | None = None) -> "bool | None":
        """Hand-out liveness, bounded by the CALLER's remaining claim window.

        Without this hook WarmPool._probe_alive falls back to is_alive(), which always grants the
        full configured probe_timeout_s -- so a claim(timeout_s=0.1) could block five seconds (or
        arbitrarily longer) while holding the dispatcher's warm-gate reservation, even though the
        AWS and libvirt tiers already honour the remaining-budget contract (upstream P2)."""
        w = self.cfg.workers[slot.worker_index]
        timeout = float(self.cfg.probe_timeout_s)
        if budget_s is not None:
            timeout = min(timeout, max(0.0, float(budget_s)))
        if timeout < _MIN_PROBE_S:
            return None      # no window left to ask meaningfully -> UNKNOWN, never a verdict
        return self._health_ok(w, timeout=timeout)

    def reap(self, slot: StaticWorkerSlot, dirty: bool = False) -> None:
        """Return the box to the free pool (nothing is torn down). On a DIRTY release (timeout/trust-
        fail/agent error) QUARANTINE it for ``dirty_cooldown_s`` first -- a stale request may still be
        running in the long-lived agent, and re-offering the box immediately would let the next claim
        hit the agent's busy-409 or race the in-flight (untrusted-output) job. The box is still
        appended to free, but spawn() skips it until the cooldown expires."""
        with self._lock:
            if dirty and self._dirty_cooldown_s > 0:
                self._cooldown_until[slot.worker_index] = self._clock() + self._dirty_cooldown_s
            else:
                self._cooldown_until.pop(slot.worker_index, None)   # clean release clears any cooldown
            if slot.worker_index not in self._free:
                self._free.append(slot.worker_index)
        _log.info("static: released worker[%d] from slot=%s (dirty=%s)",
                  slot.worker_index, slot.slot_id, dirty)


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def select_static_pool_runtime(
    get: Callable[[str], str | None] | None = None,
    *,
    require_available: bool = False,
    http_probe: HttpProbe | None = None,
) -> StaticPoolRuntime:
    """Build a StaticPoolRuntime from the environment. With ``require_available``, raise
    ``StaticPoolUnavailable`` unless the fleet is non-empty AND at least one box answers /healthz."""
    import os

    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env, make_tls_probe

    getter = get or os.environ.get
    cfg = StaticPoolConfig.from_env(getter)
    if not cfg.workers:
        if require_available:
            raise StaticPoolUnavailable("BLASTBOX_STATIC_WORKERS is empty")
        _log.warning("static: no BLASTBOX_STATIC_WORKERS configured")
    # if BLASTBOX_DISPATCH_TLS_CA is set, probe workers over https+mTLS and hand the context to the
    # transport via runtime.ssl_context (workers should be https:// or the pool runs in TLS mode).
    ctx = dispatch_ssl_context_from_env(getter)
    probe = http_probe or (make_tls_probe(ctx) if ctx else None)
    rt = StaticPoolRuntime(cfg, http_probe=probe, ssl_context=ctx)
    if require_available and not rt.available():
        raise StaticPoolUnavailable("no configured static worker answered /healthz")
    return rt
