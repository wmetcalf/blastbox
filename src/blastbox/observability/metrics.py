"""Prometheus metrics for blastbox."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest  # noqa: F401

JOBS_SUBMITTED_TOTAL = Counter(
    "blastbox_jobs_submitted_total",
    "Number of jobs submitted by engine",
    ["engine"],
)

JOBS_IN_FLIGHT = Gauge(
    "blastbox_jobs_in_flight",
    "Number of upload spooling operations currently in progress",
)

REJECTIONS_TOTAL = Counter(
    "blastbox_rejections_total",
    "Requests rejected before spooling, by reason",
    ["reason"],
)

INPUT_BYTES = Histogram(
    "blastbox_input_bytes",
    "Size of accepted input documents in bytes",
    buckets=(1024, 8192, 65536, 524288, 4194304, 33554432, 134217728),
)


def record_job_submitted(engine: str, input_bytes: int) -> None:
    """Record a successfully queued job."""
    JOBS_SUBMITTED_TOTAL.labels(engine=engine).inc()
    INPUT_BYTES.observe(input_bytes)


def record_rejection(reason: str) -> None:
    """Record an upload rejection (engine not allowed, body too large, etc.)."""
    REJECTIONS_TOTAL.labels(reason=reason).inc()


# ---------------------------------------------------------------------------
# Warm-pool metrics (slot lifecycle + demand)
# ---------------------------------------------------------------------------

POOL_SLOTS = Gauge(
    "blastbox_pool_slots",
    "Warm-pool slot count by state",
    ["state"],  # spawning | warming | idle | assigned | draining
)

POOL_WARM_TARGET = Gauge(
    "blastbox_pool_warm_target",
    "Effective warm target (warm_size, lifted by burst_size when burst active)",
)

POOL_BURST_ACTIVE = Gauge(
    "blastbox_pool_burst_active",
    "1 when the demand-driven burst target lift is active, else 0",
)

POOL_SPAWNS_TOTAL = Counter(
    "blastbox_pool_spawns_total", "Warm-pool slots spawned"
)

POOL_REAPS_TOTAL = Counter(
    "blastbox_pool_reaps_total", "Warm-pool slots reaped (disposed)"
)


def record_pool_state(
    *,
    spawning: int,
    warming: int,
    idle: int,
    assigned: int,
    draining: int,
    warm_target: int,
    burst_active: bool,
) -> None:
    """Publish a snapshot of the pool's slot-state counts + target."""
    POOL_SLOTS.labels(state="spawning").set(spawning)
    POOL_SLOTS.labels(state="warming").set(warming)
    POOL_SLOTS.labels(state="idle").set(idle)
    POOL_SLOTS.labels(state="assigned").set(assigned)
    POOL_SLOTS.labels(state="draining").set(draining)
    POOL_WARM_TARGET.set(warm_target)
    POOL_BURST_ACTIVE.set(1 if burst_active else 0)


def record_slot_spawned() -> None:
    POOL_SPAWNS_TOTAL.inc()


def record_slot_reaped() -> None:
    POOL_REAPS_TOTAL.inc()


# ---------------------------------------------------------------------------
# Dispatch metrics (job outcomes + warm-pool demand + latency)
# ---------------------------------------------------------------------------

JOBS_DISPATCHED_TOTAL = Counter(
    "blastbox_jobs_dispatched_total",
    "Jobs dispatched, by path and outcome",
    ["path", "outcome"],  # path=warm|cold, outcome=done|failed
)

WARM_CLAIMS_TOTAL = Counter(
    "blastbox_warm_claims_total",
    "Warm-pool claim attempts, by result",
    ["result"],  # hit | miss
)

JOB_DURATION_SECONDS = Histogram(
    "blastbox_job_duration_seconds",
    "Job processing wall-clock duration, by path",
    ["path"],  # warm | cold
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)


def record_warm_claim(*, hit: bool) -> None:
    WARM_CLAIMS_TOTAL.labels(result="hit" if hit else "miss").inc()


def record_job_dispatched(*, path: str, outcome: str) -> None:
    JOBS_DISPATCHED_TOTAL.labels(path=path, outcome=outcome).inc()


def observe_job_duration(*, path: str, seconds: float) -> None:
    JOB_DURATION_SECONDS.labels(path=path).observe(seconds)
