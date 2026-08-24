"""ClamAV signature scanning — a WARM, PARSE-ONLY engine.

WHY WARM RATHER THAN DISPOSABLE. `clamscan` reloads the entire signature database on
every invocation: roughly a gigabyte parsed from disk to answer one question about one
file. Per job that is seconds of latency and hundreds of megabytes of RSS, and a warm
pool of them would spend most of its life reading definitions. `clamd` holds the database
resident and answers over a socket in milliseconds, which is the same shape as the EMBER
engines — load the expensive thing once, keep it, answer many jobs from it.

WHY SLOT REUSE IS SAFE HERE, in the terms `WarmPool` already sets out: `jobs_per_recycle`
is "an ENGINE-THREAT DECISION, not a generic tuning knob", and this engine NEVER EXECUTES
THE SAMPLE. It parses it — the same class as signature validation, and the opposite of
LibreOffice or a headless browser. The threat is a malformed file against ClamAV's own
parsers, which is real and is why the daemon runs as `clamav` inside the slot rather than
alongside the host; it is not the sample obtaining execution. So a slot may serve many
jobs, which is what makes a resident database worth having.

INSTREAM, NOT A PATH. `SCAN /path` asks the daemon to share a filesystem with its caller
and to have permission to read the sample — two coupling assumptions that break the moment
the daemon is elsewhere, and one that means writing untrusted bytes somewhere another
process can find them. INSTREAM sends the bytes over the socket.

AN UNREACHABLE DAEMON IS `engine_error`, NEVER A CLEAN VERDICT. This is the whole reason
the engine is careful: a scanner that cannot run and reports "nothing found" is
indistinguishable from one that looked and found nothing, so an outage silently becomes a
false negative on every sample for as long as it lasts. The Loadout driver this replaces
had exactly that bug — it caught `FileNotFoundError` and sealed an empty, successful
result.
"""

from __future__ import annotations

import os
from pathlib import Path

# No py.typed marker upstream; the surface used here is three methods.
import clamd  # type: ignore[import-untyped]

from blastbox.contract import Detection, Record, Warning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

_SOCKET_ENV = "BLASTBOX_CLAMD_SOCKET"
_HOST_ENV = "BLASTBOX_CLAMD_HOST"
_PORT_ENV = "BLASTBOX_CLAMD_PORT"

#: Where clamd listens inside the worker guest. The daemon is a PRIVATE DETAIL OF THE
#: SLOT, not a service on a network: a unix socket in the guest cannot be reached from
#: anywhere else, so there is no port to firewall, no cross-tenant reachability question,
#: and nothing to authenticate. The TCP env vars exist only for running the engine
#: against a daemon on a developer's box.
DEFAULT_SOCKET = "/run/clamav/clamd.ctl"


class ClamdUnavailable(RuntimeError):
    """The daemon could not be reached, or refused to answer. NOT a clean scan."""


def _client(timeout: float):
    """The `clamd` library's client, pointed at whichever endpoint is configured.

    THE PROTOCOL FRAMING IS THE LIBRARY'S JOB, NOT OURS. An earlier version of this file
    hand-rolled INSTREAM — the `zCMD\0` terminator, the big-endian chunk-length prefixes,
    the zero-length terminator, the reply scan — and got it wrong in the one way that
    matters: a rejected command left the socket in a state where the scan returned
    nothing, so EICAR sealed CLEAN with `status: ok`. `clamd` (PyPI, 1.0.2) has framed
    this correctly for a decade against far more daemon versions than this file will ever
    see. What is worth writing by hand is the part above the protocol — that an
    unreachable daemon is an error and never a verdict — and that is all this module now
    does.
    """
    if sock := os.environ.get(_SOCKET_ENV):
        return clamd.ClamdUnixSocket(path=sock, timeout=timeout)
    if host := os.environ.get(_HOST_ENV):
        return clamd.ClamdNetworkSocket(
            host=host, port=int(os.environ.get(_PORT_ENV, "3310")), timeout=timeout)
    # In-guest default. Nothing configured means the daemon in this slot.
    return clamd.ClamdUnixSocket(path=DEFAULT_SOCKET, timeout=timeout)


def ping(timeout: float = 2.0) -> bool:
    try:
        return _client(timeout).ping() == "PONG"
    except (clamd.ClamdError, OSError):
        return False


def db_version(timeout: float = 2.0) -> str | None:
    """`ClamAV 1.5.3/28102/Mon Aug 24 2026`, or None if the daemon won't say.

    Sealed with every verdict. A "clean" from a database three months stale is a
    materially different statement from a "clean" from this morning's, and the reader of
    a sealed envelope has no other way to tell them apart.
    """
    try:
        return _client(timeout).version().strip() or None
    except (clamd.ClamdError, OSError):
        return None


def scan_stream(data: bytes, timeout: float = 120.0) -> list[str]:
    """Every signature the daemon reports. Empty means it looked and found none.

    ONE HIT PER STREAM IS ALL THE PROTOCOL OFFERS, and this is a real limitation rather
    than a choice. `INSTREAM` stops at the first signature: a zip holding two infected
    members reports one. All-match is a LIBCLAMAV scan option
    (`CL_SCAN_GENERAL_ALLMATCHES`) and is not exposed over the daemon socket at all —
    `ALLMATCHSCAN` answers `UNKNOWN COMMAND`. Getting every member would mean linking
    libclamav in-process, which puts a gigabyte of signatures AND ClamAV's own
    file-format parsers in the caller's address space, pointed at hostile input. That is
    a real trade and it belongs to whoever deploys, not to this file — so the engine seals
    `first_hit_only: true` and lets the reader know what the number means.

    SIZE REFUSAL IS EXPLICIT. Past clamd's `StreamMaxLength` the daemon closes the
    connection mid-stream, which reads as a transport failure rather than the size
    refusal it is; the library raises `BufferTooLongError`, and it is translated here so
    the envelope says the sample was too large rather than that the scanner broke. Either
    way it is an ERROR, never a clean verdict about bytes nobody looked at.
    """
    import io

    try:
        reply = _client(timeout).instream(io.BytesIO(data))
    except clamd.BufferTooLongError as exc:
        raise ClamdUnavailable(
            f"sample is {len(data)} bytes, past clamd's StreamMaxLength. Refused rather "
            f"than truncated: a partial scan reporting clean is a false statement about "
            f"the whole file ({exc})") from exc
    except (clamd.ClamdError, OSError) as exc:
        raise ClamdUnavailable(f"clamd did not answer: {exc}") from exc

    hits: list[str] = []
    for status, name in reply.values():
        if status == "ERROR":
            raise ClamdUnavailable(f"clamd reported an error: {name}")
        if status == "FOUND" and name:
            hits.append(name)
    return hits


def _detected(hits: list[str]) -> Detection:
    return Detection(
        label=hits[0] if hits else "clean",
        mime="application/octet-stream",
        confidence=1.0,
        source="clamav",
    )


class ClamAVEngine:
    """Scan one sample against a resident ClamAV database."""

    name = "clamav"
    formats = frozenset({"*"})

    def __init__(self, *, scan_fn=None, name: str | None = None) -> None:
        self._scan = scan_fn or scan_stream
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        data = input.read_bytes()
        version = db_version(2.0)
        try:
            hits = self._scan(data, timeout=limits.timeout_s)
        except ClamdUnavailable as exc:
            # `engine_error`, NOT an empty ok. See the module docstring: an engine that
            # could not look must never seal a result that reads as "looked, found
            # nothing" — that is a false negative manufactured by an outage.
            return DetonationResult(
                payload=Record(fields={"scanned": False, "error": str(exc)[:1000],
                                       "db_version": version or "unknown"}),
                artifacts=[],
                detected=_detected([]),
                warnings=[Warning(code="clamd_unavailable", message=str(exc)[:2000])],
                status="engine_error",
            )

        warnings: list[Warning] = []
        if version is None:
            # The scan happened, so the result stands — but a verdict whose signature age
            # is unknown is worth less than one that states it, and silently omitting the
            # field would let a reader assume it was current.
            warnings.append(Warning(
                code="db_version_unknown",
                message="clamd answered the scan but not VERSION, so the signature "
                        "database date behind this verdict is unknown"))
        return DetonationResult(
            payload=Record(fields={
                "scanned": True,
                "infected": bool(hits),
                # EVERY hit, not the first — see `scan_stream`.
                "signatures": ", ".join(hits[:64]),
                "signature_count": len(hits),
                "db_version": version or "unknown",
                # THE PROTOCOL STOPS AT THE FIRST HIT. Sealed so a reader of an archive
                # scan knows `signature_count: 1` means "at least one" and not "exactly
                # one" — see `scan_stream`.
                "first_hit_only": True,
                "bytes_scanned": len(data),
            }),
            artifacts=[],
            detected=_detected(hits),
            warnings=warnings,
            status="ok",
        )
