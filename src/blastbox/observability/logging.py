"""structlog setup for blastbox — JSON to stderr by default."""
from __future__ import annotations

import logging
import sys
from typing import Literal

import structlog


def configure_logging(format_: Literal["json", "text"] = "json", level: str = "INFO") -> None:
    """Configure structlog to write structured logs to stderr.

    Args:
        format_: ``"json"`` (default, for production/container) or ``"text"``
                 (human-readable dev output).
        level:   Standard logging level string ("DEBUG", "INFO", …).
    """
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s")
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if format_ == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))
    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog bound logger for the given name."""
    return structlog.get_logger(name)
