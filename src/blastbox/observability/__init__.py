"""Observability helpers: structured logging + Prometheus metrics.

The metrics half is imported LAZILY. Both halves live behind optional dependencies that ship in
the ``host`` extra, but the ``blastbox`` console script is installed by every install and reaches
this package through ``from blastbox.observability import configure_logging`` -- so an eager
``from .metrics import ...`` made prometheus_client a hard requirement of `blastbox version`.
PEP 562 keeps the public API identical (``from blastbox.observability import INPUT_BYTES`` still
works) while charging the import only to callers that actually use metrics.
"""
from typing import Any

from .logging import configure_logging, get_logger

_METRICS_EXPORTS = frozenset({
    "generate_latest",
    "record_job_submitted",
    "record_rejection",
    "JOBS_SUBMITTED_TOTAL",
    "JOBS_IN_FLIGHT",
    "REJECTIONS_TOTAL",
    "INPUT_BYTES",
})

__all__ = ["configure_logging", "get_logger", *sorted(_METRICS_EXPORTS)]


def __getattr__(name: str) -> Any:
    if name in _METRICS_EXPORTS:
        from . import metrics

        return getattr(metrics, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
