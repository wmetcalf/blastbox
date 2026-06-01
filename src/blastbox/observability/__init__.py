"""Observability helpers: structured logging + Prometheus metrics."""
from .logging import configure_logging, get_logger
from .metrics import (
    generate_latest,
    record_job_submitted,
    record_rejection,
    JOBS_SUBMITTED_TOTAL,
    JOBS_IN_FLIGHT,
    REJECTIONS_TOTAL,
    INPUT_BYTES,
)

__all__ = [
    "configure_logging",
    "get_logger",
    "generate_latest",
    "record_job_submitted",
    "record_rejection",
    "JOBS_SUBMITTED_TOTAL",
    "JOBS_IN_FLIGHT",
    "REJECTIONS_TOTAL",
    "INPUT_BYTES",
]
