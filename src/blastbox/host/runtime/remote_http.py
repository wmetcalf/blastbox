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
import time
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

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


class ClaimLost(RuntimeError):
    """This attempt outlived its claim (a peer reclaimed the job) before a destructive output op -- abort
    so we don't clobber the new owner's result in the shared output dir."""


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
    for mTLS). Pass the result as ``ssl_context`` to ``make_remote_validate`` / ``detonate_remote``."""
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
    from blastbox.tls import client_ssl_context
    return client_ssl_context(ca, cert_file=cert, key_file=key)


def make_tls_probe(ssl_context: ssl.SSLContext | None) -> Callable[[str, dict, float], bool]:
    """A health-probe (``(url, headers, timeout) -> bool``) that carries the client (m)TLS context, so a
    pool's ``/healthz`` check works against ``https://`` workers. Matches the ``HttpProbe`` seam shape."""
    def probe(url: str, headers: dict, timeout: float) -> bool:
        req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 (host-built url)
        try:
            # no-redirect opener: a worker answering /healthz with a 3xx must NOT be followed (it would
            # re-send X-aws-proxy-auth to the Location -- and on a downgrade to http:// the mTLS context
            # wouldn't apply, so the token would go out in the clear). A 3xx -> HTTPError -> False below.
            with _default_open(req, timeout, context=ssl_context) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
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
            if not m.isfile():
                continue
            files += 1
            if max_members is not None and files > max_members:
                raise RemoteOutputTooLarge(f"remote output exceeded {max_members} files")
            raw = dest / m.name
            # bounds check on the FULLY-RESOLVED path (catches leaf + intermediate-dir symlink escapes).
            resolved = raw.resolve()
            if resolved != dest and not str(resolved).startswith(str(dest) + os.sep):
                _log.warning("remote_http: dropping traversal member %r", m.name)
                continue
            _make_traversable(raw.parent, dest)   # 0755 intermediates so a different API UID can read
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
            resp_cm = opener(req, timeout, context=ssl_context)
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
            # a sealed envelope whose engine failed is NOT a successful job -- gate like the local
            # dispatcher paths do (missing/invalid metadata or engine_error => fail).
            if not meta or meta.get("status") == "engine_error":
                _log.warning("remote_http: remote job not ok (status=%s)", (meta or {}).get("status"))
                reason = "remote engine error" if meta else "remote worker returned no metadata"
                return {"error": reason}, False
            # HOST TRUST GATE -- runs BEFORE the slot is released clean, so a worker whose output fails
            # host validation (re-sealed hashes / engine / input_sha / caps) stays dirty and is retired
            # rather than re-offered. It re-writes the host-sealed metadata.json in out_dir; re-read it.
            if output_trust is not None:
                # pass the authoritative ingress SHA (if the dispatcher supplied one) so trust compares
                # against it, not a recompute of the staged file, plus the ownership predicate so the
                # host metadata write is fenced by claim ownership. Raises on failure -> dirty stays True.
                output_trust(input_path, out_dir, input_sha256, owns)
                sealed = out_dir / "metadata.json"
                if sealed.exists():
                    meta = json.loads(sealed.read_text())
            dirty = False
            return meta, True
        except WorkerBusy:
            # NOT a job failure -- the worker's lock is held by a stale detonation. Propagate so the
            # dispatcher requeues the job (like NoWarmSlot); the finally releases this slot dirty (cooldown).
            raise
        except Exception as exc:  # noqa: BLE001
            # transport error after the request may have reached the worker -> the box could still be
            # busy; keep dirty=True so the pool retires/recycles it instead of re-offering immediately.
            _log.warning("remote_http: validate failed: %s", exc)
            # surface a COARSE, sanitized reason (exception CLASS, not its message) so a failed remote
            # job carries an actionable error the API can show -- without leaking hosts/paths/internals.
            return {"error": _sanitized_failure(exc)}, False
        finally:
            try:
                release(slot, dirty=dirty)
            except TypeError:            # release seam that doesn't accept dirty (legacy callers/tests)
                release(slot)

    return validate
