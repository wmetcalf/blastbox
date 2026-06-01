"""Exception hierarchy for the blastbox framework."""

from __future__ import annotations

import re


# Strip internal filesystem paths from public-facing error messages.
# Root-agnostic: match any absolute POSIX path of two or more segments
# (``/var/lib/blastbox/x``, ``/etc/passwd``, ``/proc/self/mem``) rather
# than denylisting specific roots.  A single ``/`` between words (``and/or``)
# is not a path and is left untouched because it lacks a trailing segment
# separator.
_INTERNAL_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._+-]+/)+[A-Za-z0-9._+-]*")


def sanitize_public_error(msg: str) -> str:
    """Remove internal filesystem paths from an error message."""
    return _INTERNAL_PATH_RE.sub("<path>", msg)


class BlastboxError(Exception):
    """Base for all blastbox errors."""


class DetectionError(BlastboxError):
    """Input was rejected by the detector."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SandboxError(BlastboxError):
    """Sandbox setup or execution failed."""


class SandboxTimeout(SandboxError):
    """Sandboxed process exceeded the wall-clock timeout."""


class SandboxUnavailable(SandboxError):
    """No usable sandbox backend on this host."""


class EngineError(BlastboxError):
    """An engine-specific failure (e.g. LibreOffice, Tika, …)."""


class DetonationError(BlastboxError):
    """Top-level detonation failure, optionally wrapping a cause."""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.cause = cause
        if cause is not None:
            self.__cause__ = cause


# Keep ConversionError as an alias so engines can use the familiar name
# without importing engine-specific terms into the generic layer.
ConversionError = DetonationError


class ValidationError(BlastboxError):
    """Envelope / metadata validation failed."""


class OutputTrustError(BlastboxError):
    """Worker output failed the host-side trust validation."""


class WarmTimeout(BlastboxError):
    """No job arrived within the idle-timeout window for a warm worker slot."""
