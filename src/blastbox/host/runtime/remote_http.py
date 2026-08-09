"""Generic host-side transport for the remote HTTP worker agent (`blastbox.worker.http_agent`).

The dispatcher posts one job's input bytes to a remote worker over HTTP and gets back a tar of the
worker's sealed output dir (metadata.json + artifacts), which it extracts into the job's output/ dir --
exactly as if a local sandbox had written there. Engine-agnostic: works for any engine served by the
generic agent, over either an EC2 instance (`ip:port`) or a Lambda MicroVM (`url` + JWE token).

Plugs into `VmJobDispatcher(validate=...)` (or a pool_manager-style claim loop) via `make_remote_validate`.
"""

from __future__ import annotations

import io
import json
import logging
import os
import ssl
import threading
import time
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from blastbox.errors import is_transport_error
from blastbox.host.pool import release_kwargs
from blastbox.errors import (
    HOST_RESOURCE_ERRNOS,
    EngineErrorEnvelope,
    OutputTrustUnknown,
    is_answered_http_rejection,
)


_log = logging.getLogger("blastbox.host.runtime.remote_http")

# Injectable HTTP seam (tests pass a fake returning canned tar bytes; default hits the network).
# ``context`` carries the client SSL/mTLS context for https:// workers (None for http/tests).
HttpOpen = Callable[..., Any]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Worker transports MUST NOT follow a worker-chosen 3xx. urllib's default handler rewrites the
    /detonate POST to a GET and re-sends every header (bar content-*) to the Location -- so a compromised
    worker answering 302 would make the dispatcher leak ``X-aws-proxy-auth`` (the JWE) + ``X-Blastbox-
    Params`` to an attacker URL AND perform an SSRF GET from the host net, defeating the worker's no-egress
    containment. Returning None makes urllib raise HTTPError (fail-closed) instead of following."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _default_open(req: urllib.request.Request, timeout: float, context: ssl.SSLContext | None = None) -> Any:
    # build a fresh opener with redirects DISABLED (+ the caller's mTLS context for https workers) rather
    # than urlopen's default opener, which would auto-follow a worker's redirect and leak the auth headers.
    # Also pin an EMPTY ProxyHandler so worker transport IGNORES ambient HTTP_PROXY/HTTPS_PROXY: workers are
    # private/direct-reach, and routing the /detonate body + X-aws-proxy-auth through an env proxy would
    # leak them in cleartext for http:// workers. (Worker EGRESS proxying is the netpolicy httpproxy driver
    # injected into the WORKER's env -- independent of this dispatcher-side transport opener.)
    handlers: list[Any] = [_NoRedirect(), urllib.request.ProxyHandler({})]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)  # noqa: S310 (url is host-built)


class RemoteOutputTooLarge(RuntimeError):
    """A remote worker returned more output than the configured cap allows (DoS guard)."""


class RemoteOutputMalformed(RuntimeError):
    """The worker's tar is internally inconsistent -- a WORKER verdict, not a host failure.

    Deliberately NOT an OSError. The blanket handler in the validate path splits OSError into
    "this dispatcher's disk" vs "the wire", and a worker-authored archive that cannot be laid out
    (a regular file ``a`` followed by a member ``a/b``, so ``a`` must be both) surfaced there as
    FileExistsError/ENOTDIR and was filed under the dispatcher's disk. A reusable static worker
    could then repeat the violation forever without advancing burnout or repair (upstream, PR #82).
    """


class ClaimLost(RuntimeError):
    """This attempt outlived its claim (a peer reclaimed the job) before a destructive output op -- abort
    so we don't clobber the new owner's result in the shared output dir.

    ``validated`` says whether the WORKER'S OUTPUT had already passed the host trust gate when the
    claim was found lost. It changes the attribution, not the control flow: after validation the
    run is positive proof this worker and its base are responsive, so the streaks must RESET --
    leaving it unattributed preserves them, and worker-failure / validated-run-then-claim-loss /
    worker-failure then counts as consecutive and can evict the slot or rebuild its base. Before
    validation nothing has been demonstrated, so it stays unattributed. Carried on the exception
    because only the raise site knows which side of the gate it is on (upstream, PR #82).
    """

    def __init__(self, *args: object, validated: bool = False) -> None:
        super().__init__(*args)
        self.validated = validated


class WorkerBusy(RuntimeError):
    """The worker agent answered /detonate with 409 (its single-flight job lock is held). Capacity
    pressure, NOT a job failure -- the dispatcher requeues (like NoWarmSlot) instead of FAILing the job."""


class ParamsTooLargeForRemote(RuntimeError):
    """The forwarded per-job params serialize to a header larger than the stdlib HTTP line limit, so the
    worker would reject the request before parsing them. Fail fast with an actionable error."""


class RemoteReadTimeout(RuntimeError):
    """Reading the worker's response tar exceeded the total wall-clock deadline (a trickling/broken worker
    kept the stream open). Abort so the validate finally can release the slot instead of pinning it."""


def _sanitized_failure(exc: Exception) -> str:
    """Map a transport/trust exception to a COARSE, non-sensitive reason for the job's error field
    (never the raw message -- it can carry hosts/paths/tokens)."""
    import ssl as _ssl
    import urllib.error as _ue
    if isinstance(exc, RemoteOutputTooLarge):
        return "remote output exceeded configured limits"
    if type(exc).__name__ == "OutputTrustError":
        return "remote output failed host trust validation"
    if isinstance(exc, (_ssl.SSLError,)):
        return "remote worker TLS error"
    if isinstance(exc, (_ue.URLError, TimeoutError, ConnectionError, OSError)):
        return "remote worker transport error"
    return "remote job failed"


def _check_params_header_size(params: dict[str, str] | None) -> None:
    """Raise ParamsTooLargeForRemote if the forwarded params serialize past the stdlib HTTP header-line
    limit (http.client._MAXLINE = 65536). The worker's HTTP parser would reject the request BEFORE
    _parse_params runs -- an opaque failure the cold/file paths (env-passed params) don't have."""
    if not params:
        return
    line = len(b"X-Blastbox-Params: ") + len(json.dumps(params).encode("utf-8", "surrogatepass")) + 2
    if line > 65536:
        raise ParamsTooLargeForRemote(
            f"forwarded params serialize to {line} header bytes (> 65536); reduce the allowlisted "
            "per-job params for the remote tier")


def _open_bounded(opener: Any, req: Any, timeout: float, context: Any, deadline: float) -> Any:
    """Run ``opener()`` (connect + send the request body + read the response status/headers) under a TOTAL
    wall-clock ``deadline``, not just urllib's PER-OP socket timeout. A worker that slowly reads our request
    or trickles response headers would otherwise keep opener() blocked past the job budget while the daemon
    validate thread pins the claimed slot (the watchdog can fail the job but can't retire the slot). On
    timeout raise RemoteReadTimeout so the caller's finally frees the slot promptly. The stuck opener runs
    in a DAEMON thread so it never blocks process exit (a non-daemon executor thread with wait=False would)
    and reaps on its own per-op socket timeout. HTTPError from opener (e.g. 409) is re-raised so the caller's
    existing handling still fires."""
    box: dict[str, Any] = {}

    def _run() -> None:
        try:
            box["resp"] = opener(req, timeout, context=context)
        except BaseException as exc:   # noqa: BLE001 -- surfaced to the caller below
            box["exc"] = exc

    t = threading.Thread(target=_run, name="bb-open", daemon=True)
    t.start()
    t.join(timeout=max(0.0, deadline - time.monotonic()))
    if t.is_alive():
        raise RemoteReadTimeout("remote opener (connect/send/headers) exceeded the wall-clock deadline")
    if "exc" in box:
        raise box["exc"]
    return box["resp"]


def _cap_read_timeout(src: Any, remaining: float) -> None:
    """Best-effort: shrink the NEXT socket read's timeout to the REMAINING wall-clock budget, so a worker
    that sends a chunk just before the deadline and then STALLS can't block for the full original urllib
    socket timeout (another ~worker_timeout_s) past the budget. No-op when the socket isn't reachable (a
    custom opener / test double) -- the per-chunk deadline check still bounds a steady trickle."""
    try:
        src.fp.raw._sock.settimeout(max(0.001, remaining))
    except (AttributeError, OSError):
        pass


def _bounded_copy(src: Any, dst: Any, limit: int | None, deadline: float | None = None) -> int:
    """copyfileobj that aborts once ``limit`` bytes have been read (None = unbounded). When ``deadline``
    (a ``time.monotonic()`` value) is given, also aborts if the TOTAL wall-clock read exceeds it -- the
    urllib socket timeout only bounds idle gaps, so a worker trickling (or chunk-then-stalling) could
    otherwise read past the job budget while the abandoned validate thread pins the pool slot. Reads via
    ``read1`` (one recv per call) when available AND caps each read to the remaining budget, so the deadline
    is enforced both between AND during a blocking read."""
    total = 0
    read = getattr(src, "read1", None) or src.read
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RemoteReadTimeout(f"remote output read exceeded the {deadline:.0f}s wall-clock deadline")
            _cap_read_timeout(src, remaining)   # bound THIS read to the remaining budget
        try:
            chunk = read(1024 * 1024)
        except (TimeoutError, OSError) as exc:   # incl. socket.timeout from the capped read
            if deadline is not None and time.monotonic() >= deadline:
                raise RemoteReadTimeout("remote output read exceeded the wall-clock deadline") from exc
            raise
        if not chunk:
            break
        total += len(chunk)
        if limit is not None and total > limit:
            raise RemoteOutputTooLarge(f"remote output exceeded {limit} bytes")
        dst.write(chunk)
    return total


def dispatch_ssl_context_from_env(get: Callable[[str], str | None] = os.environ.get) -> ssl.SSLContext | None:
    """Build the dispatcher's client (m)TLS context from env, or None if no CA is configured:
    ``BLASTBOX_DISPATCH_TLS_CA`` (verify workers) + optional ``_CERT``/``_KEY`` (present the client cert
    for mTLS). ``BLASTBOX_DISPATCH_TLS_VERIFY_HOSTNAME=0`` trusts any cert the CA signed regardless of
    the address it answered on (see below). Pass the result as ``ssl_context`` to
    ``make_remote_validate`` / ``detonate_remote``."""
    ca = get("BLASTBOX_DISPATCH_TLS_CA")
    cert = get("BLASTBOX_DISPATCH_TLS_CERT") or None
    key = get("BLASTBOX_DISPATCH_TLS_KEY") or None
    # fail closed on a partial config -- don't silently fall back to plaintext (would send the bearer
    # token + sample bytes in the clear).
    if not ca:
        if cert or key:
            raise RuntimeError("partial dispatcher TLS: BLASTBOX_DISPATCH_TLS_CERT/KEY set but _CA missing")
        return None
    if bool(cert) != bool(key):
        raise RuntimeError("BLASTBOX_DISPATCH_TLS_CERT and _TLS_KEY must be set together")
    # BLASTBOX_DISPATCH_TLS_VERIFY_HOSTNAME=0 trusts any unexpired serverAuth cert our private CA
    # signed regardless of the address it answered on -- required for dynamically-addressed worker
    # pools (a disposable-EC2 slot gets a fresh IP, so one baked server cert can't name it). Chain
    # signature/expiry/EKU stay enforced; safety rests on the CA being private + per-worker keys
    # (see blastbox.tls.client_ssl_context).
    verify_host = (get("BLASTBOX_DISPATCH_TLS_VERIFY_HOSTNAME") or "1").strip().lower() not in (
        "0", "false", "no", "off",
    )
    from blastbox.tls import client_ssl_context
    return client_ssl_context(ca, cert_file=cert, key_file=key, verify_hostname=verify_host)


def make_tls_probe(ssl_context: ssl.SSLContext | None) -> "Callable[[str, dict, float], bool | None]":
    """A health-probe (``(url, headers, timeout) -> bool | None``; None = could not ask) that carries the client (m)TLS context, so a
    pool's ``/healthz`` check works against ``https://`` workers. Matches the ``HttpProbe`` seam shape."""
    def probe(url: str, headers: dict, timeout: float) -> "bool | None":
        req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 (host-built url)
        try:
            # no-redirect opener: a worker answering /healthz with a 3xx must NOT be followed (it would
            # re-send X-aws-proxy-auth to the Location -- and on a downgrade to http:// the mTLS context
            # wouldn't apply, so the token would go out in the clear). A 3xx -> HTTPError -> False below.
            with _default_open(req, timeout, context=ssl_context) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # Same tri-state as _default_http_probe: None = we could not even ASK (local resource
            # exhaustion), False = the box answered and the answer was no. This probe is the DEFAULT
            # whenever BLASTBOX_DISPATCH_TLS_CA is set, so leaving it bool-only kept the fleet-wide
            # eviction live even with the plain-HTTP path fixed (issue #77 marla-loop 4).
            from blastbox.host.runtime.aws_worker import _is_local_resource_error
            if _is_local_resource_error(exc):
                return None
            return False
    return probe


class _Slot(Protocol):
    """The subset of a runtime slot this transport needs (AwsWorkerSlot / VmSlot both satisfy it)."""
    ip: str | None
    url: str | None
    auth_token: str | None
    agent_port: int


def slot_base_url(slot: _Slot, *, tls: bool = False) -> str:
    """Resolve the worker's base URL: a Lambda-MicroVM `url`, else `http(s)://<ip>:<port>` (EC2/VM).
    ``tls`` selects the scheme for ip-based slots (https under mTLS)."""
    if getattr(slot, "url", None):
        return str(slot.url).rstrip("/")
    ip = getattr(slot, "ip", None)
    if ip:
        scheme = "https" if tls else "http"
        return f"{scheme}://{ip}:{getattr(slot, 'agent_port', 8765)}"
    raise ValueError("slot has no reachable endpoint (no url and no ip)")


def _make_traversable(dir_path: Path, root: Path) -> None:
    """mkdir ``dir_path`` (parents) and chmod every component from ``root`` down to 0755, so the API
    process in a serve+dispatch UID split can traverse into nested artifact dirs (e.g. ``pages/``).
    mkdir honors the dispatcher umask (a restrictive 077 would leave 0700), so chmod explicitly. These
    are untrusted-output artifact dirs, not sensitive, so world-traversable is fine."""
    dir_path.mkdir(parents=True, exist_ok=True)
    p = dir_path
    while True:
        try:
            p.chmod(0o755)
        except OSError:
            pass
        if p == root or root not in p.parents:
            break
        p = p.parent


def _empty_dir(d: Path) -> None:
    """Remove everything under ``d`` (files, symlinks-as-links, subtrees) without following symlinks
    out of it, leaving ``d`` itself. Used to drop a prior/requeued attempt's output before extracting
    a fresh one, so the host trust gate re-seals ONLY this attempt's artifacts."""
    import shutil
    for child in d.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            try:
                child.unlink()   # removes a file OR a symlink (never the symlink's target)
            except OSError:
                pass




def _safe_extract_tar(tar_source: bytes | Any, dest: Path, *, max_total_bytes: int | None = None,
                      max_members: int | None = None, max_metadata_bytes: int | None = None) -> list[str]:
    """Extract regular files from a tar (bytes or a seekable fileobj) into ``dest``, rejecting path
    traversal and capping the total extracted bytes AND the regular-file member count (an inode-
    exhaustion guard: a buggy/compromised agent could pack hundreds of thousands of tiny files that
    stay under the byte budget). Writes never follow symlinks (``O_NOFOLLOW``) so a stale worker-
    controlled symlink left in ``dest`` from a prior attempt can't redirect a write out of the tree.
    Returns the relative paths written."""
    dest = dest.resolve()
    fileobj = io.BytesIO(tar_source) if isinstance(tar_source, (bytes, bytearray)) else tar_source
    written: list[str] = []
    total = 0
    files = 0
    with tarfile.open(fileobj=fileobj, mode="r") as tf:
        # iterate LAZILY (not getmembers(), which reads every header into a list first) so the member
        # cap short-circuits before a tar of hundreds of thousands of tiny entries materializes all
        # their TarInfo objects in memory.
        for m in tf:
            # count EVERY header against the cap, BEFORE the non-regular skip: a tar dominated by
            # directories/symlinks/other non-file headers would otherwise never trip max_members and could
            # burn CPU parsing up to the raw stream cap. (max_members = max_artifacts + slack, so a few
            # legit dirs are absorbed.)
            files += 1
            if max_members is not None and files > max_members:
                raise RemoteOutputTooLarge(f"remote output exceeded {max_members} members")
            if not m.isfile():
                continue
            raw = dest / m.name
            # bounds check on the FULLY-RESOLVED path (catches leaf + intermediate-dir symlink escapes).
            # resolve() and the parent mkdir happen BEFORE the guarded open below, and they are
            # just as worker-controlled: with a regular file `a` and a later member `a/b`, `a`
            # must be both a file and a directory, so this raises FileExistsError/ENOTDIR and
            # escapes the loop into the caller's OSError branch -- which reads it as this
            # dispatcher's disk. Split it here, where we still know the member that caused it.
            try:
                resolved = raw.resolve()
                if resolved != dest and not str(resolved).startswith(str(dest) + os.sep):
                    _log.warning("remote_http: dropping traversal member %r", m.name)
                    continue
                _make_traversable(raw.parent, dest)   # 0755 so a different API UID can read
            except OSError as exc:
                if exc.errno in HOST_RESOURCE_ERRNOS:
                    raise                              # ours: stays unattributed upstream
                raise RemoteOutputMalformed(
                    f"remote output member {m.name!r} cannot be laid out ({exc})"
                ) from exc
            src = tf.extractfile(m)
            if src is None:
                continue
            # open the UNRESOLVED leaf with O_NOFOLLOW: if that leaf is a symlink (left over from a
            # prior/requeued attempt, or swapped in after the bounds check), the open fails ELOOP and we
            # skip the member rather than writing THROUGH the symlink. Opening the resolved path instead
            # would silently follow it.
            try:
                # 0644: the API process in a serve+dispatch split may run as a different UID and must
                # be able to read the artifacts + the host-sealed metadata.json (matches the re-seal mode).
                fd = os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            except OSError as exc:
                src.close()
                _log.warning("remote_http: refusing to write member %r (%s)", m.name, exc)
                # A member skipped because THIS HOST ran out of fds/space/inodes is a dispatcher
                # failure, but the caller only sees "no metadata" and blames the worker. Surface
                # it instead of silently returning an empty extraction: during an EMFILE/ENOSPC
                # incident every job would otherwise advance burnout and base-rebuild streaks
                # (PR #82). EACCES/ELOOP stay a skip -- those ARE the worker's doing.
                if exc.errno in HOST_RESOURCE_ERRNOS:
                    raise
                continue
            rel = str(resolved.relative_to(dest))
            with src, os.fdopen(fd, "wb") as out:
                # force the exact 0644 regardless of the process umask (a restrictive umask like 077 would
                # otherwise land 0600, unreadable to the API process in a serve+dispatch UID split) --
                # matches the dir chmod above and the host-sealed metadata writer.
                os.fchmod(fd, 0o644)
                # metadata.json is a CONTROL file, not a declared artifact -- bound it by its OWN cap and
                # DON'T count it toward the artifact byte total, so the remote tier matches the cold trust
                # gate (which caps metadata separately). Otherwise a job whose artifacts fit the budget but
                # whose metadata tips the sum over would be failed only on the remote path. Key the cap on
                # the RESOLVED relative path, not the raw member name: a worker sending "./metadata.json"
                # (or "foo/../metadata.json") still lands at output/metadata.json and must get the metadata
                # cap, not the (larger) artifact budget.
                if rel == "metadata.json":
                    _bounded_copy(src, out, max_metadata_bytes)
                else:
                    remaining = None if max_total_bytes is None else max_total_bytes - total
                    total += _bounded_copy(src, out, remaining)
            written.append(rel)
    return written


def detonate_remote(
    base_url: str,
    input_path: Path,
    output_dir: Path,
    *,
    token: str | None = None,
    agent_port: int = 8765,
    timeout: float = 600.0,
    http_open: HttpOpen | None = None,
    params: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    max_output_bytes: int | None = None,
    max_members: int | None = None,
    max_metadata_bytes: int | None = None,
    owns: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """POST ``input_path`` to the remote agent's ``/detonate``; extract the returned sealed output tar
    into ``output_dir``; return the parsed ``metadata.json`` (empty dict if the worker produced none).
    ``params`` is a dict of already-host-allowlisted per-job env overrides (OCR/QR toggles, etc.)
    forwarded so remote workers honor per-job params the same as local ones. ``ssl_context`` verifies
    the worker's server cert + presents the dispatcher's client cert (mTLS) for ``https://`` workers."""
    opener = http_open or _default_open
    url = base_url.rstrip("/") + "/detonate?name=" + quote(input_path.name)
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["X-aws-proxy-auth"] = token
        headers["X-aws-proxy-port"] = str(agent_port)
    if params:
        _check_params_header_size(params)   # belt-and-suspenders for direct callers (make_remote_validate
        headers["X-Blastbox-Params"] = json.dumps(params)   # already checks BEFORE claiming a slot)
    # STREAM the input as the request body (open file handle + explicit Content-Length) instead of
    # read_bytes() -- otherwise the dispatcher holds the whole sample in RAM per concurrent claim
    # thread, so a burst of large-but-valid uploads (raised BLASTBOX_MAX_INPUT) can OOM it before any
    # worker-side limit runs. urllib streams a file-like `data` when Content-Length is set.
    headers["Content-Length"] = str(input_path.stat().st_size)
    output_dir.mkdir(parents=True, exist_ok=True)
    # FENCE the DESTRUCTIVE ops by claim ownership: if this (possibly long) attempt outlived its claim and
    # a peer reclaimed+completed the job, emptying/extracting into the SHARED output dir would clobber the
    # new owner's sealed result. Check before the wipe (peer-already-done ordering) AND again after the
    # network round-trip before extracting (reclaim landed mid-flight). The final metadata write is fenced
    # separately in output_trust; this protects the earlier filesystem mutations it can't.
    if owns is not None and not owns():
        raise ClaimLost("claim lost before output clear (peer recovered the job)")
    _empty_dir(output_dir)   # drop any stale files from a prior/requeued attempt before extracting
    # stream the response tar to a spooled temp file (spills to disk past 64MB) rather than holding the
    # whole thing in memory -- artifact tars can be large. CAP the stream + the extracted total so a
    # buggy/compromised worker can't fill the dispatcher's disk.
    # The tar stream is larger than the ARTIFACT files: it also carries metadata.json (capped SEPARATELY
    # by max_metadata_bytes during extraction, NOT counted in the artifact budget) plus per-member tar
    # headers/padding. Size the stream cap to cover all three (artifact budget + metadata budget + 10%
    # header/padding headroom) -- else a valid output whose artifacts fit the budget but whose metadata
    # (or many tiny members' headers) push the raw stream over is rejected before extraction can apply
    # the real per-cap budgets.
    # header/padding headroom must track the MEMBER count, not just bytes: many tiny files (each a
    # 512B tar header + padding, all within the byte budget) can make the raw stream exceed a byte-only
    # headroom. Add ~1KiB per allowed member so a valid max-member tar isn't rejected pre-extraction.
    stream_cap = None if max_output_bytes is None else (
        int(max_output_bytes * 1.1) + (max_metadata_bytes or 0) + (max_members or 0) * 1024 + 65536)
    read_deadline = time.monotonic() + timeout   # TOTAL wall-clock budget for the response read
    with input_path.open("rb") as body:
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            resp_cm = _open_bounded(opener, req, timeout, ssl_context, read_deadline)
        except urllib.error.HTTPError as exc:
            # 409 = the worker's single-flight job lock is held (a stale detonation still running on a
            # re-offered static box). Capacity pressure, NOT a job failure -> requeue like NoWarmSlot.
            # Other 4xx/5xx are real failures and propagate.
            if exc.code == 409:
                raise WorkerBusy(f"worker busy (409) at {url}") from exc
            raise
        with resp_cm as resp, tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as spool:
            _bounded_copy(resp, spool, stream_cap, deadline=read_deadline)
            spool.seek(0)
            if owns is not None and not owns():   # a peer may have reclaimed during the round-trip
                raise ClaimLost("claim lost before output extract (peer recovered the job)")
            _safe_extract_tar(spool, output_dir, max_total_bytes=max_output_bytes,
                              max_members=max_members, max_metadata_bytes=max_metadata_bytes)
    meta = output_dir / "metadata.json"
    if meta.exists():
        # bound the metadata BEFORE parsing -- a worker can put an under-artifact-budget-but-huge
        # metadata.json in the tar; parsing a multi-hundred-MB JSON here (before the host trust gate
        # enforces max_metadata_bytes) is a CPU/memory DoS.
        if max_metadata_bytes is not None and meta.stat().st_size > max_metadata_bytes:
            raise RemoteOutputTooLarge(
                f"remote metadata.json is {meta.stat().st_size} bytes (> {max_metadata_bytes})")
        return json.loads(meta.read_text())
    return {}


# Re-exported from blastbox.errors so this module's callers keep the local name while the RULE
# has exactly one definition (vm_compose classifies the same way).
_is_transport_error = is_transport_error


def make_remote_validate(
    claim: Callable[[], _Slot],
    release: Callable[..., None],
    output_dir_for: Callable[[Path], Path],
    *,
    token: str | None = None,
    timeout: float = 600.0,
    http_open: HttpOpen | None = None,
    params_for: Callable[[Path], dict[str, str]] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    max_output_bytes: int | None = None,
    max_members: int | None = None,
    max_metadata_bytes: int | None = None,
    output_trust: Callable[..., None] | None = None,
) -> Callable[..., tuple[dict[str, Any] | None, bool]]:
    """Build a ``validate(input_path) -> (metadata, ok)`` for a network-endpoint dispatcher.

    ``claim``/``release`` manage a warm slot from the pool (AWS or VM); ``output_dir_for(input_path)``
    gives the job's output dir the sealed artifacts land in. ``params_for(input_path)`` resolves the
    job's allowlisted per-job params (OCR/QR toggles, etc.) forwarded to the remote worker. The worker's
    own JWE (``slot.auth_token``) is preferred over the static ``token``. A transport/agent failure
    returns ``(None, False)`` so the dispatcher fails the job rather than emitting a bogus verdict.
    """

    def validate(input_path: Path, *, params: dict[str, str] | None = None,
                 input_sha256: str | None = None,
                 owns: Callable[[], bool] | None = None) -> tuple[dict[str, Any] | None, bool]:
        # Derive + size-check the params BEFORE claiming a slot: a raising params_for hook OR an oversized
        # params set (many allowlisted 4KiB keys) must NOT claim+dirty a worker -- that would quarantine a
        # static box for its cooldown / burn a disposable AWS slot without ever running a job (a cheap DoS).
        try:
            job_params = params if params is not None else (params_for(input_path) if params_for else None)
            _check_params_header_size(job_params)
        except Exception as exc:  # noqa: BLE001 -- local validation failure, no slot claimed yet
            _log.warning("remote_http: params rejected before claim: %s", exc)
            return {"error": _sanitized_failure(exc)}, False
        slot = claim()
        dirty = True  # only a clean, successful round-trip releases the slot as reusable
        # WHOSE failure was it? "unknown" is the safe default: an unattributed dirty release still
        # force-resets the slot but never advances it toward eviction (see WarmPool.release).
        fault = "unknown"
        try:
            base = slot_base_url(slot, tls=ssl_context is not None)
            out_dir = output_dir_for(input_path)
            meta = detonate_remote(
                base, input_path, out_dir,
                token=getattr(slot, "auth_token", None) or token,
                agent_port=getattr(slot, "agent_port", 8765),
                timeout=timeout, http_open=http_open,
                params=job_params,
                ssl_context=ssl_context,
                max_output_bytes=max_output_bytes,
                max_members=max_members,
                max_metadata_bytes=max_metadata_bytes,
                owns=owns,   # fence the destructive clear/extract by claim ownership (reclaim race)
            )
            # No metadata at all is abnormal worker output -> fail the job AND retire the slot (dirty).
            if not meta:
                # Attribute HERE, not in the chain below: an earlier version added an
                # `elif not meta` after this return, which could never execute -- so malformed
                # worker output still never advanced burnout or base rebuilding. EMPTY metadata
                # is abnormal worker output: the engine reported nothing at all, so a
                # recycle-capable worker could otherwise be reset and re-offered forever.
                fault = "worker"
                _log.warning("remote_http: remote worker returned no metadata")
                return {"error": "remote worker returned no metadata"}, False
            # HOST TRUST GATE -- runs BEFORE the slot is released clean, so a worker whose output fails
            # host validation (re-sealed hashes / engine / input_sha / caps) stays dirty and is retired
            # rather than re-offered. It re-writes the host-sealed metadata.json in out_dir; re-read it.
            if output_trust is not None:
                # pass the authoritative ingress SHA (if the dispatcher supplied one) so trust compares
                # against it, not a recompute of the staged file, plus the ownership predicate so the
                # host metadata write is fenced by claim ownership. Raises on failure -> dirty stays True.
                try:
                    output_trust(input_path, out_dir, input_sha256, owns)
                except EngineErrorEnvelope:
                    # a VALIDATED engine_error (structure/hashes/input-sha checked out): the box is HEALTHY,
                    # the SAMPLE failed -> fail the job but release the slot CLEAN, so a client feeding
                    # malformed samples can't quarantine the static fleet. A FAKE/malformed engine_error
                    # would have raised a plain OutputTrustError above -> falls to the generic except (dirty).
                    dirty = False
                    return {"error": "remote engine error"}, False
                sealed = out_dir / "metadata.json"
                if sealed.exists():
                    meta = json.loads(sealed.read_text())
            elif meta.get("status") == "engine_error":
                fault = "job"        # the engine RAN and reported on this input; not the worker
                # no trust gate to validate the envelope (direct callers / tests) -> can't tell a genuine
                # engine_error from a faked one, so fail CONSERVATIVELY (dirty).
                return {"error": "remote engine error"}, False
            dirty = False
            return meta, True
        except WorkerBusy:
            # 409 means the worker ANSWERED and its single-flight lock is held: capacity pressure,
            # and the job is REQUEUED rather than failed, so it is not failure evidence at all.
            # Recording it advanced the pool-wide rebuild streak on nothing but load, and a
            # job-driven repair carries no guilty-tier attribution, so in a cascade it could
            # invalidate unrelated healthy snapshot tiers (upstream, PR #82).
            fault = "unknown"
            # Propagate so the dispatcher requeues the job (like NoWarmSlot); the finally still
            # releases this slot DIRTY, quarantining the box so it is not immediately re-offered.
            raise
        except ClaimLost as exc:
            # A PEER already reclaimed or finished this job -- our claim simply outlived itself.
            # The worker did nothing wrong, so attributing it as a wedge let two stale attempts
            # burn out a healthy slot and feed base invalidation (upstream, PR #82).
            #
            # ...and when the loss was found AFTER the trust gate accepted this worker's output,
            # "did nothing wrong" understates it: the run PROVED the worker and its base
            # responsive, and unknown preserves the streaks rather than clearing them.
            fault = "job" if getattr(exc, "validated", False) else "unknown"
            raise
        except OutputTrustUnknown as exc:
            # The host could not COMPLETE validation (EMFILE/EIO/ENOMEM). validate_worker_output
            # wraps the OSError, so this is no longer an OSError and the generic branch below
            # would convict -- defeating the whole point of the type on this path.
            fault = "unknown"
            _log.warning("remote_http: could not complete output validation: %s", exc)
            return {"error": _sanitized_failure(exc)}, False
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, OSError) and not _is_transport_error(exc):
                # LOCAL HOST I/O: input_path.stat(), output_dir.mkdir(), _empty_dir(), tar
                # extraction. These fail on ENOSPC/EROFS/EMFILE with the request never sent, so
                # they are evidence about THIS DISPATCHER, not the worker -- and a dispatcher
                # disk outage hits every job at once, which would burn out every healthy slot
                # and invalidate healthy bases (upstream, PR #82).
                #
                # Decided INSIDE this handler deliberately. A separate `except OSError:` fails
                # twice over: urllib's URLError/HTTPError and socket.timeout are all OSError
                # SUBCLASSES, so it would swallow every transport failure as host I/O; and
                # re-raising from one handler does not fall through to a sibling handler, it
                # escapes the try entirely.
                fault = "unknown"
                _log.warning("remote_http: local preparation failed: %s", exc)
                return {"error": _sanitized_failure(exc)}, False
            if is_answered_http_rejection(exc):
                # The agent ANSWERED and rejected what we SENT. A 4xx is a verdict on the request,
                # not evidence the box is sick: the agent replies 413 when a sample exceeds its
                # own max_bytes, so raising BLASTBOX_MAX_INPUT on the dispatcher while a
                # static/remote worker keeps the default turns every oversized-but-valid job into
                # a worker conviction and burns down healthy boxes one after another. 401/403
                # (token skew) and 404 (version skew) fail the same way, and identically on EVERY
                # box -- exactly the correlated signal that must never reach burnout. 5xx falls
                # through: the agent itself broke, which IS evidence about this worker. 409 never
                # arrives here; it is WorkerBusy (capacity) further up (upstream, PR #82).
                # "job", not "unknown". The agent ANSWERED, which proves it and the base it
                # restored from are responsive -- and unknown merely stops the rejection itself
                # from incrementing the streak, it does not CLEAR the failure before it. A
                # transport failure, then a 413, then another transport failure still counted as
                # consecutive (upstream, PR #82).
                fault = "job"
                _log.warning("remote_http: worker rejected the request (HTTP %s): %s",
                             getattr(exc, "code", "?"), exc)
                return {"error": _sanitized_failure(exc)}, False
            fault = "worker"         # transport failed -> evidence about this worker, not the input
            # transport error after the request may have reached the worker -> the box could still be
            # busy; keep dirty=True so the pool retires/recycles it instead of re-offering immediately.
            _log.warning("remote_http: validate failed: %s", exc)
            # surface a COARSE, sanitized reason (exception CLASS, not its message) so a failed remote
            # job carries an actionable error the API can show -- without leaking hosts/paths/internals.
            return {"error": _sanitized_failure(exc)}, False
        finally:
            # Introspect ONCE rather than laddering down `except TypeError` around the CALL.
            # The ladder could not tell an old seam from a real TypeError inside release, so one
            # genuine bug released the SAME slot three times -- and its last rung dropped `dirty`,
            # returning a worker that had just failed a detonation straight to IDLE with no forced
            # recycle. Never invent an attribution a caller cannot carry: an unattributed dirty
            # release still force-resets the slot, it just does not advance it toward eviction.
            release(slot, **release_kwargs(release, dirty=dirty, fault=fault))

    return validate
