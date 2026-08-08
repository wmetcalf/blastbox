"""Exception hierarchy for the blastbox framework."""

from __future__ import annotations

import errno
import re
import socket
import ssl
import urllib.error


# Strip internal filesystem paths from public-facing error messages.
# Root-agnostic: match any absolute POSIX path of two or more segments
# (``/var/lib/blastbox/x``, ``/etc/passwd``, ``/proc/self/mem``) rather
# than denylisting specific roots.  A single ``/`` between words (``and/or``)
# is not a path and is left untouched because it lacks a trailing segment
# separator.
_INTERNAL_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._+-]+/)+[A-Za-z0-9._+-]*")
# Credentials embedded in a URI/DSN: ``scheme://user:pass@host`` -> ``scheme://<redacted>@host``.
_URI_CRED_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]*@")
# psycopg/driver connection-string key=value pairs that carry infra/secret data.
_SENSITIVE_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|host|hostaddr|port|user|dbname|database)=\S+"
)


def sanitize_public_error(msg: str) -> str:
    """Scrub internal filesystem paths AND DSN/connection credentials (URI ``user:pass@`` and
    ``host=/port=/password=`` style kv pairs) from a client-facing error message.

    Defense-in-depth only — infrastructure exceptions (store/driver/connection) should NOT be
    routed through here at all: return a fixed generic message and log the detail server-side.
    """
    msg = _URI_CRED_RE.sub(r"\1<redacted>@", msg)
    msg = _SENSITIVE_KV_RE.sub(r"\1=<redacted>", msg)
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


# Errnos that mean THIS HOST is out of resources, as opposed to the worker having produced
# something we refuse to follow. The distinction decides ATTRIBUTION everywhere it is used: a
# host-resource failure hits every job at once and must never burn out workers, while a path-shape
# error (ELOOP/ENOTDIR from a confinement check on a worker-writable directory) is a concrete
# violation that must. Defined once because four copies had already accumulated in four modules
# under two names -- agreeing today is precisely the state that precedes an unnoticed drift.
HOST_RESOURCE_ERRNOS = frozenset({
    errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.EIO, errno.ENOSPC, errno.EDQUOT, errno.EROFS,
})


def is_transport_error(exc: BaseException) -> bool:
    """Whether an OSError came from the WIRE rather than the local filesystem.

    urllib.error.URLError (and thus HTTPError), socket.timeout and ConnectionError all subclass
    OSError, so separating "the disk is full" from "the worker is unreachable" has to be
    explicit: an `except OSError` written for ENOSPC otherwise captures every connection failure
    too, and silently stops attributing the wedges this exists to catch.

    ssl.SSLError is an OSError but NOT a URLError, socket.timeout or ConnectionError, so an HTTPS
    read that fails on a TLS protocol error or a mid-stream disconnect was landing in the
    local-filesystem branch -- a worker with a broken TLS stack could never be detected, because
    every failure it produced was attributed to this dispatcher's disk.

    Lives HERE, beside HOST_RESOURCE_ERRNOS, because more than one seam decides worker-vs-host
    attribution from an exception: it started private to remote_http, and vm_compose's
    slot-bound validate needed the same rule. A second copy is how a rule drifts -- the errno set
    above was four divergent copies under two names before it was consolidated (PR #82).
    """
    return isinstance(
        exc, (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError)
    )


def is_host_resource_failure(exc: BaseException) -> bool:
    """Whether a spawn failure is THIS HOST running out, rather than the tier being broken.

    Walks the cause chain: the OSError is nearly always wrapped -- a launcher raises
    SnapshotBuildError, a cascade raises CascadeSpawnFailed `from last_exc` -- so the errno is
    rarely on the outermost exception. Same rule as everywhere else: only a host-resource errno
    is ours, anything else belongs to the thing that failed.

    Lives here, beside HOST_RESOURCE_ERRNOS and is_transport_error, because BOTH the cascade's
    per-tier streak and the pool's pool-wide restore streak must exclude these, and a second copy
    is how that rule drifts (upstream, PR #82).
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, OSError) and cur.errno in HOST_RESOURCE_ERRNOS:
            return True
        cur = cur.__cause__ or cur.__context__
    return False


class OutputTrustUnknown(OutputTrustError):
    """Validation could not be COMPLETED -- not a verdict that the output is bad.

    The host hit its own limits while reading or hashing (EMFILE, EIO, ENOMEM). Subclasses
    OutputTrustError so every existing ``except OutputTrustError`` still fails the job closed,
    but callers attributing blame can tell "the worker produced invalid output" (evidence about
    the worker) from "we could not check" (evidence about this dispatcher). A host I/O outage
    hits every job at once, so conflating them burns out the whole warm set and rebuilds healthy
    snapshot bases during an incident the workers had no part in (upstream, PR #82).
    """


class EngineErrorEnvelope(OutputTrustError):
    """The worker returned a VALIDATED sealed envelope whose status is ``engine_error`` (structure/hashes/
    input-sha all checked out -- the box is healthy, the SAMPLE failed). The job fails, but the slot may be
    released CLEAN, unlike a malformed/unvalidatable envelope (a plain OutputTrustError -> retire dirty)."""


class WarmTimeout(BlastboxError):
    """No job arrived within the idle-timeout window for a warm worker slot."""


class FcCpuFeatureMismatch(SandboxError):
    """A CRaC warp restore aborted because the checkpoint requires CPU features
    the Firecracker guest does not expose.

    This is the actionable form of an otherwise-opaque warmup timeout: the warp
    engine reports the compatible value itself (see
    :func:`blastbox.host.runtime.cpu_features.parse_cpu_mismatch`).  Rebuild the
    rootfs/checkpoint with ``-XX:CPUFeatures=<needed>`` on both the AOT-create
    and the checkpoint command.
    """

    def __init__(self, needed: str, detail: str = "") -> None:
        msg = (
            "Firecracker guest is missing CPU features the CRaC checkpoint "
            f"requires; rebuild the rootfs/checkpoint with -XX:CPUFeatures={needed}"
        )
        super().__init__(f"{msg} ({detail})" if detail else msg)
        self.needed = needed
