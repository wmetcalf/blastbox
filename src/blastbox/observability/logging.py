"""structlog setup for blastbox — JSON to stderr by default.

structlog is OPTIONAL here, and that is the point. It ships in the ``host`` extra, but
``[project.scripts]`` installs the ``blastbox`` console script for EVERY install, and this module
sits on that script's import path. So a plain ``pip install blastbox`` -- the exact command the
adopter engines' build wrappers print when they need a newer CLI -- produced a ``blastbox`` that
could not start:

    $ blastbox version
    ModuleNotFoundError: No module named 'structlog'

and, run through a wrapper that quiets stderr, the operator was told

    this blastbox has no usable `version` output; need >= 0.1.39

on a machine with a current blastbox. Following the printed remediation reinstalled the same
thing. The build-time commands (``version``, ``pins``, ``build-images``, ``stamp``, ``doctor``)
are precisely the ones a consumer needs WITHOUT a host stack, so they must not require fastapi,
uvicorn, psycopg and redis to run. Without structlog they log through the standard library.
"""
from __future__ import annotations

import logging
import sys
from typing import Any, Literal

try:
    import structlog
except ImportError:  # `blastbox` installed without the `host` extra.
    structlog = None  # type: ignore[assignment]


def configure_logging(format_: Literal["json", "text"] = "json", level: str = "INFO") -> None:
    """Configure structlog to write structured logs to stderr.

    Args:
        format_: ``"json"`` (default, for production/container) or ``"text"``
                 (human-readable dev output).
        level:   Standard logging level string ("DEBUG", "INFO", …).
    """
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s")
    if structlog is None:
        # basicConfig above IS the configuration. Returning quietly rather than raising is the
        # whole point: a build-time command that only ever emits a couple of lines should not
        # die because the JSON renderer is absent.
        return
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
        # NOT cached: configure_logging() runs on every build_app(), and caching the
        # bound logger on first use pins the sys.stderr captured at that instant —
        # which defeats the per-call reconfigure and, under pytest's per-test stream
        # capture, makes a later log write to an already-closed stream
        # ("I/O operation on closed file"). The per-call logger cost is negligible here.
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> Any:
    """Return a bound logger for the given name; structlog's if it is installed."""
    if structlog is None:
        return _StdlibBoundLogger(logging.getLogger(name))
    return structlog.get_logger(name)


class _StdlibBoundLogger:
    """The part of structlog's bound-logger surface this codebase actually uses.

    Callers written for structlog pass event keywords -- ``log.info("api_auth_enabled",
    scheme="bearer")`` -- which a stdlib logger rejects with a TypeError. Those call sites all
    live in the host stack, which has real structlog, so this shim exists to keep an unexpected
    one from turning a missing OPTIONAL dependency into a crash. It renders the keywords into
    the message instead, and passes ``exc_info``/``extra`` through to the standard library where
    they mean something.
    """

    __slots__ = ("_log",)

    def __init__(self, log: logging.Logger) -> None:
        self._log = log

    def _emit(self, level: int, event: str, *args: Any, **kw: Any) -> None:
        exc_info = kw.pop("exc_info", None)
        extra = kw.pop("extra", None)
        if kw:
            event = f"{event} " + " ".join(f"{k}={v!r}" for k, v in sorted(kw.items()))
        self._log.log(level, event, *args, exc_info=exc_info, extra=extra)

    def debug(self, event: str, *args: Any, **kw: Any) -> None:
        self._emit(logging.DEBUG, event, *args, **kw)

    def info(self, event: str, *args: Any, **kw: Any) -> None:
        self._emit(logging.INFO, event, *args, **kw)

    def warning(self, event: str, *args: Any, **kw: Any) -> None:
        self._emit(logging.WARNING, event, *args, **kw)

    def error(self, event: str, *args: Any, **kw: Any) -> None:
        self._emit(logging.ERROR, event, *args, **kw)

    def critical(self, event: str, *args: Any, **kw: Any) -> None:
        self._emit(logging.CRITICAL, event, *args, **kw)

    def exception(self, event: str, *args: Any, **kw: Any) -> None:
        kw.setdefault("exc_info", True)
        self._emit(logging.ERROR, event, *args, **kw)

    def bind(self, **kw: Any) -> _StdlibBoundLogger:
        """structlog's binding is a no-op here; nothing in this codebase binds."""
        return self
