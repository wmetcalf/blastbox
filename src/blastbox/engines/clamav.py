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

ALL-MATCH BY PATH, WITH INSTREAM AS THE FALLBACK — AND THIS FILE PREVIOUSLY SAID THE
OPPOSITE. It claimed all-match "is not exposed over the daemon socket at all" and cited
`ALLMATCHSCAN` answering `UNKNOWN COMMAND`. That reply was real but the conclusion was
wrong: the probe sent `ALLMATCHSCAN` with NO PATH ARGUMENT as a prelude to `INSTREAM`,
and the daemon rejected a malformed command, not the feature. `ALLMATCHSCAN <path>` works.

Measured on 40 LNK samples: `SCAN` returned 36 signatures, `ALLMATCHSCAN` returned 344,
and 33 of the 40 matched more than one. First-hit-only was discarding roughly nine tenths
of what the database had to say — a sample matching `Sanesecurity.Malware.28759.LnkHeur`
AND four distinct `TwinWave.EvilLNK.*` families is telling you about a toolkit, and one
label is not that.

All-match needs a PATH, which means the daemon must be able to read the sample. That is
an assumption, and it is the one the in-guest deployment makes true by construction:
clamd runs inside the same disposable worker guest as the harness, on a unix socket, so
the input file is already on its filesystem. When the daemon is reached over TCP it is
somewhere else and no such path exists, so that configuration falls back to `INSTREAM` —
which is first-hit-only, and says so in the sealed result rather than quietly returning
less.

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

from typing import Literal

from pydantic import Field

from blastbox.contract import Detection, Record, Warning, register_node_type
from blastbox.contract.nodes import _Node
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


@register_node_type
class SignatureScan(_Node):
    """A NAMED TYPE, NOT A BAG OF FIELDS.

    These went into `Record.fields` first — "a typed bag for engine data not worth a
    named type", which is the wrong home for the two fields a consumer must not miss.
    `first_hit_only` is the difference between `signature_count: 1` meaning "exactly
    one" and "at least one"; `db_version` is the difference between a clean verdict from
    this morning's database and one from three months ago. In a bag, a rename makes both
    read as absent, and absent reads as the more reassuring answer in each case.

    `_Node` sets `extra="forbid"`, so drift is a parse error at the boundary instead of
    a `None` that every reader carries on with.
    """

    type: Literal["signature_scan"] = Field(default="signature_scan", alias="_type")

    infected: bool
    #: EVERY signature reported, as a list — it was a comma-joined string, which asks
    #: each consumer to re-split it and get the escaping right on a name containing a
    #: comma.
    signatures: list[str] = Field(default_factory=list, max_length=64)
    signature_count: int = Field(ge=0)

    #: The database behind the verdict. Required, never defaulted: a scan whose
    #: signature age is unknown must say so explicitly ("unknown"), because a reader
    #: given no value at all will assume it was current.
    db_version: str = Field(min_length=1, max_length=255)

    #: THE PROTOCOL STOPS AT THE FIRST HIT. A zip with two infected members reports one.
    #: Sealed on every result so `signature_count` is never read as exhaustive.
    first_hit_only: bool

    bytes_scanned: int = Field(ge=0)


@register_node_type
class SignatureScanUnavailable(_Node):
    """The failure payload — A DIFFERENT TYPE, not a scan with holes in it.

    There is no `infected` field here to misread. That is the entire point: `infected:
    false` from a scanner that never ran is indistinguishable from a real clean verdict,
    and a consumer discriminating on `_type` cannot make that mistake.
    """

    type: Literal["signature_scan_unavailable"] = Field(
        default="signature_scan_unavailable", alias="_type")
    error: str = Field(max_length=1000)
    db_version: str = Field(min_length=1, max_length=255)


class ClamdUnavailable(RuntimeError):
    """The daemon could not be reached, or refused to answer. NOT a clean scan."""


class ClamdCannotSeePath(ClamdUnavailable):
    """The daemon is answering, but cannot read the path it was given.

    A DIFFERENT PROBLEM FROM AN OUTAGE, and the reason it gets its own type. The scanner
    works; only the assumption that it shares a filesystem with the caller is wrong —
    which happens whenever a unix socket is bind-mounted out of a container, a shape
    `_shares_filesystem()` cannot distinguish from a genuinely local daemon. Treating it
    as an outage would fail every job on a deployment whose scanner is perfectly healthy;
    treating it as a clean scan would be the false negative this engine exists to refuse.
    So it is neither: it downgrades to `INSTREAM` and says it did.
    """


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


def _shares_filesystem() -> bool:
    """Can the daemon read a path this process writes?

    THE RULE IS THE TRANSPORT, not a separate toggle: a unix socket can only be reached
    by a process on the same filesystem namespace, and a TCP endpoint is by definition
    somewhere else. Deriving it removes the configuration in which an operator points at
    a remote daemon, leaves a "use paths" flag set, and gets `No such file or directory`
    for every sample. `BLASTBOX_CLAMD_FORCE_STREAM` opts out for the odd case of a unix
    socket bind-mounted from another container with a different view of the filesystem.
    """
    if os.environ.get("BLASTBOX_CLAMD_FORCE_STREAM"):
        return False
    return not os.environ.get(_HOST_ENV)


def scan_path(path: Path, timeout: float = 300.0) -> list[str]:
    """EVERY signature that matched, via `ALLMATCHSCAN`. Requires a shared filesystem.

    Duplicates are collapsed. The daemon reports a signature once per object it matched
    inside, so an archive can echo the same name a dozen times; that is a statement about
    structure, not about which signatures fired, and the count would read as twelve
    findings. Order is preserved so the first hit — what a first-hit-only scan would have
    returned — stays first.
    """
    lines = _raw_command(f"ALLMATCHSCAN {path}", timeout)
    hits: list[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.endswith("ERROR"):
            low = line.lower()
            if ("file path check failure" in low or "no such file" in low
                    or "can't access file" in low or "lstat() failed" in low):
                raise ClamdCannotSeePath(line)
            raise ClamdUnavailable(f"clamd reported an error: {line}")
        if line.endswith(" FOUND"):
            sig = line.partition(": ")[2][: -len(" FOUND")].strip()
            if sig and sig not in hits:
                hits.append(sig)
    return hits


def _raw_command(command: str, timeout: float) -> list[str]:
    """One newline-delimited command, reading the WHOLE multi-line reply.

    Not `clamd`-the-library: its `_basic_command` reads a single line, which for
    `ALLMATCHSCAN` silently returns the first signature and discards the rest — the exact
    truncation this function exists to avoid. Everything else still goes through the
    library; this is the one command whose reply is a stream of lines.
    """
    import socket

    if host := os.environ.get(_HOST_ENV):
        sock = socket.create_connection(
            (host, int(os.environ.get(_PORT_ENV, "3310"))), timeout=timeout)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(os.environ.get(_SOCKET_ENV, DEFAULT_SOCKET))
    try:
        sock.sendall(b"n" + command.encode() + b"\n")
        buf = b""
        while True:
            got = sock.recv(65536)
            if not got:
                break
            buf += got
    except OSError as exc:
        raise ClamdUnavailable(f"clamd did not answer {command.split()[0]}: {exc}") from exc
    finally:
        sock.close()
    return buf.decode("utf-8", "replace").splitlines()


def scan_stream(data: bytes, timeout: float = 120.0) -> list[str]:
    """The FALLBACK, for a daemon that cannot see the sample's path. FIRST HIT ONLY.

    `INSTREAM` stops at the first signature — measured at roughly a ninth of what
    all-match reports on real samples (see the module docstring). It is still the right
    transport when the daemon is remote, because the alternative is not scanning at all,
    but a result produced this way seals `first_hit_only: true` so nobody reads its
    `signature_count` as the whole story.

    SIZE REFUSAL IS EXPLICIT. Past clamd's `StreamMaxLength` the daemon closes the
    connection mid-stream, which reads as a transport failure rather than the size
    refusal it is; the library raises `BufferTooLongError`, translated here so the
    envelope says the sample was too large rather than that the scanner broke.
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



def _sealed(node) -> Record:
    """Validate strictly, then seal GENERICALLY — and this reverses a choice made
    earlier today for a reason worth recording.

    The typed node (`SignatureScan`) is the right contract: it bounds the fields, forbids
    extras, and turns a rename into a parse error. But `register_node_type` registers
    into the REGISTRY OF THE PROCESS THAT IMPORTS THE ENGINE — and an engine runs in a
    container while the dispatcher validating its envelope does not import it. Observed
    live: the host rejected a perfectly good result with
    `Input tag 'signature_scan' ... does not match any of the expected tags`.

    So the model still does the checking (constructed and validated above), and what
    goes on the wire is `Record` — the generic floor any host can validate. The field
    names and bounds are still enforced; they are enforced where they can be.
    """
    return Record(fields={"schema": node.type, **node.model_dump(exclude={"type"})})


class ClamAVEngine:
    """Scan one sample against a resident ClamAV database."""

    name = "clamav"
    formats = frozenset({"*"})

    def __init__(self, *, scan_fn=None, path_scan_fn=None, name: str | None = None) -> None:
        self._scan = scan_fn or scan_stream
        self._scan_path = path_scan_fn or scan_path
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        data_len = input.stat().st_size
        version = db_version(2.0)
        # ALL-MATCH WHEN THE DAEMON CAN SEE THE FILE, which in the in-guest deployment it
        # always can. Roughly 9x the signatures on real samples; see the module docstring.
        all_match = _shares_filesystem()
        degraded: str | None = None
        try:
            if all_match:
                try:
                    hits = self._scan_path(input, timeout=float(limits.timeout_s))
                except ClamdCannotSeePath as exc:
                    # The daemon is healthy and the filesystem assumption is not. Scan
                    # the bytes instead of failing the job — but record the downgrade,
                    # because the result now carries roughly a ninth of the signatures
                    # and nothing else in the envelope would show why.
                    all_match = False
                    degraded = str(exc)[:300]
                    hits = self._scan(input.read_bytes(), timeout=float(limits.timeout_s))
            else:
                hits = self._scan(input.read_bytes(), timeout=float(limits.timeout_s))
        except ClamdUnavailable as exc:
            # `engine_error`, NOT an empty ok. See the module docstring: an engine that
            # could not look must never seal a result that reads as "looked, found
            # nothing" — that is a false negative manufactured by an outage.
            return DetonationResult(
                payload=_sealed(SignatureScanUnavailable(error=str(exc)[:1000],
                                                         db_version=version or "unknown")),
                artifacts=[],
                detected=_detected([]),
                warnings=[Warning(code="clamd_unavailable", message=str(exc)[:2000])],
                status="engine_error",
            )

        warnings: list[Warning] = []
        if degraded:
            warnings.append(Warning(
                code="all_match_unavailable",
                message=f"the daemon could not read the sample's path, so this scan used "
                        f"INSTREAM and stopped at the first signature — set "
                        f"BLASTBOX_CLAMD_FORCE_STREAM to make that the intended mode and "
                        f"silence this: {degraded}"))
        if version is None:
            # The scan happened, so the result stands — but a verdict whose signature age
            # is unknown is worth less than one that states it, and silently omitting the
            # field would let a reader assume it was current.
            warnings.append(Warning(
                code="db_version_unknown",
                message="clamd answered the scan but not VERSION, so the signature "
                        "database date behind this verdict is unknown"))
        return DetonationResult(
            payload=_sealed(SignatureScan(
                infected=bool(hits),
                signatures=hits[:64],
                signature_count=len(hits),
                db_version=version or "unknown",
                # TRUE ONLY ON THE STREAM FALLBACK NOW, and that is the point of
                # keeping the field: it distinguishes "these are all the signatures that
                # matched" from "this is the first of an unknown number".
                first_hit_only=not all_match,
                bytes_scanned=data_len,
            )),
            artifacts=[],
            detected=_detected(hits),
            warnings=warnings,
            status="ok",
        )
