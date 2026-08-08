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


_TRANSIENT_RESOLVER_ERRORS = frozenset(
    getattr(socket, n) for n in ("EAI_AGAIN", "EAI_SYSTEM", "EAI_MEMORY") if hasattr(socket, n)
)


def is_local_resource_error(exc: BaseException) -> bool:
    """True if this failure is OUR side running out of resources, not the peer answering.

    ConnectionRefused/Reset and timeouts are OSErrors too, but they are real answers about the
    worker -- only the local-exhaustion errnos mean we never got to ask."""
    # urllib's do_open does a BARE `raise URLError(err)`, which sets __context__ (not __cause__)
    # and stores the original in .reason. URLError is itself an OSError subclass but never calls
    # OSError.__init__, so its .errno is None -- meaning a __cause__-only lookup made this branch
    # UNREACHABLE through the real opener, and local fd exhaustion reaped whole fleets while the
    # guarding test passed against a bare OSError the opener never produces (issue #77 marla-loop 4).
    inner: BaseException = exc
    for _ in range(4):      # bounded: reason/cause/context chains are short and may self-reference
        if isinstance(inner, urllib.error.URLError) and isinstance(inner.reason, BaseException):
            inner = inner.reason
        elif inner.__cause__ is not None:
            inner = inner.__cause__
        elif inner.__context__ is not None and inner.__context__ is not inner:
            inner = inner.__context__
        else:
            break
        if isinstance(inner, OSError) and inner.errno is not None:
            break
    # A RESOLVER failure is its own namespace: socket.gaierror carries EAI_* codes (typically
    # NEGATIVE) which are not errno values at all, so an errno allowlist silently never matched them.
    # Failing to look a name up says nothing about the worker's health -- and one resolver outage
    # hits every hostname-based worker on the same tick, which is the fleet-wipe shape (upstream P1).
    if isinstance(inner, socket.gaierror):
        # Only TEMPORARY resolver failures are "we could not ask". A definitive NXDOMAIN
        # (EAI_NONAME/EAI_NODATA) says the name does not resolve -- for an existing worker that is a
        # real reachability verdict, and treating it as unknown left the slot IDLE and "healthy"
        # for the whole 300s grace while every claim skipped it, when capacity used to be replaced
        # at once (upstream P2). Blanket-unknown was my over-correction.
        return inner.errno in _TRANSIENT_RESOLVER_ERRORS
    return isinstance(inner, OSError) and inner.errno in (
        errno.EMFILE,    # process fd table full
        errno.ENFILE,    # system-wide fd table full
        errno.ENOMEM,    # cannot allocate for the socket
        errno.ENOBUFS,
        errno.EADDRNOTAVAIL,  # ephemeral ports exhausted -- purely LOCAL, and it hits every worker
                              # on the same tick, which is the fleet-wipe shape exactly
        errno.ENETUNREACH,    # no route from THIS host: our networking, not the worker's health
        errno.EINPROGRESS,    # non-blocking connect in flight -- we never waited for an answer
        errno.EAGAIN,         # (== EWOULDBLOCK) same: no answer was ever collected
    )
    # Deliberately NOT here -- these ARE answers about the worker: ETIMEDOUT (it did not respond in
    # time), ECONNREFUSED / ECONNRESET (nothing is listening / it hung up), EHOSTUNREACH (the host
    # itself is unreachable, which for a warm worker is indistinguishable from being down).


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
    # ...but a URLError wrapping OUR OWN exhaustion is not a wire failure at all. urllib's
    # do_open does a bare `raise URLError(err)`, so an EMFILE/ENFILE/ENOMEM from creating the
    # socket arrives here as a URLError whose .errno is None -- an outer-type check called it
    # transport, the remote handler skipped its host-I/O branch, and a host-wide exhaustion event
    # advanced every affected slot's worker and base streaks at once. That is the fleet-wipe
    # shape. is_local_resource_error already unwraps exactly this (upstream, PR #82).
    if is_local_resource_error(exc):
        return False
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


def is_answered_http_rejection(exc: BaseException) -> bool:
    """A 4xx RESPONSE: the agent answered and rejected what we sent.

    HTTPError subclasses URLError, so every transport check treats a 4xx as a wire failure unless
    told otherwise -- and the agent replies 413 when a sample exceeds its own max_bytes, 401/403
    on token skew, 404 on version skew. All of those are verdicts on the REQUEST and all of them
    fail identically on every box, which is exactly the correlated signal that must never reach
    burnout. 5xx is excluded deliberately: the agent itself breaking IS about that worker.

    Defined here so the HTTP transport and the compose seam cannot disagree -- the latter was
    missed when the former learned this rule (upstream, PR #82).
    """
    return isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500


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
