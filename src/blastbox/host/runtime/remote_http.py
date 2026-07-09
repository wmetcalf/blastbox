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


def _default_open(req: urllib.request.Request, timeout: float, context: ssl.SSLContext | None = None) -> Any:
    return urllib.request.urlopen(req, timeout=timeout, context=context)  # noqa: S310 (url is host-built)


class RemoteOutputTooLarge(RuntimeError):
    """A remote worker returned more output than the configured cap allows (DoS guard)."""


def _bounded_copy(src: Any, dst: Any, limit: int | None) -> int:
    """copyfileobj that aborts once ``limit`` bytes have been read (None = unbounded)."""
    total = 0
    while True:
        chunk = src.read(1024 * 1024)
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
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:  # noqa: S310
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


def _safe_extract_tar(tar_source: bytes | Any, dest: Path, *, max_total_bytes: int | None = None) -> list[str]:
    """Extract regular files from a tar (bytes or a seekable fileobj) into ``dest``, rejecting path
    traversal and capping the total extracted bytes. Returns the relative paths written."""
    dest = dest.resolve()
    fileobj = io.BytesIO(tar_source) if isinstance(tar_source, (bytes, bytearray)) else tar_source
    written: list[str] = []
    total = 0
    with tarfile.open(fileobj=fileobj, mode="r") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            target = (dest / m.name).resolve()
            if target != dest and not str(target).startswith(str(dest) + os.sep):
                _log.warning("remote_http: dropping traversal member %r", m.name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, target.open("wb") as out:
                remaining = None if max_total_bytes is None else max_total_bytes - total
                total += _bounded_copy(src, out, remaining)
            written.append(str(target.relative_to(dest)))
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
        headers["X-Blastbox-Params"] = json.dumps(params)
    req = urllib.request.Request(url, data=input_path.read_bytes(), method="POST", headers=headers)
    output_dir.mkdir(parents=True, exist_ok=True)
    # stream the response tar to a spooled temp file (spills to disk past 64MB) rather than holding the
    # whole thing in memory -- artifact tars can be large. CAP the stream + the extracted total so a
    # buggy/compromised worker can't fill the dispatcher's disk.
    # The tar stream is larger than the files (headers/padding/metadata.json), so cap the STREAM with
    # headroom and enforce the real artifact budget during EXTRACTION -- else a valid output near the
    # budget is rejected purely on archive overhead.
    stream_cap = None if max_output_bytes is None else int(max_output_bytes * 1.1) + 65536
    with opener(req, timeout, context=ssl_context) as resp, \
            tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as spool:
        _bounded_copy(resp, spool, stream_cap)
        spool.seek(0)
        _safe_extract_tar(spool, output_dir, max_total_bytes=max_output_bytes)
    meta = output_dir / "metadata.json"
    if meta.exists():
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
    output_trust: Callable[[Path, Path], None] | None = None,
) -> Callable[[Path], tuple[dict[str, Any] | None, bool]]:
    """Build a ``validate(input_path) -> (metadata, ok)`` for a network-endpoint dispatcher.

    ``claim``/``release`` manage a warm slot from the pool (AWS or VM); ``output_dir_for(input_path)``
    gives the job's output dir the sealed artifacts land in. ``params_for(input_path)`` resolves the
    job's allowlisted per-job params (OCR/QR toggles, etc.) forwarded to the remote worker. The worker's
    own JWE (``slot.auth_token``) is preferred over the static ``token``. A transport/agent failure
    returns ``(None, False)`` so the dispatcher fails the job rather than emitting a bogus verdict.
    """

    def validate(input_path: Path, *, params: dict[str, str] | None = None) -> tuple[dict[str, Any] | None, bool]:
        slot = claim()
        dirty = True  # only a clean, successful round-trip releases the slot as reusable
        # per-job params from the dispatcher (already allowlist-gated) win; else the params_for hook.
        job_params = params if params is not None else (params_for(input_path) if params_for else None)
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
            )
            # a sealed envelope whose engine failed is NOT a successful job -- gate like the local
            # dispatcher paths do (missing/invalid metadata or engine_error => fail).
            if not meta or meta.get("status") == "engine_error":
                _log.warning("remote_http: remote job not ok (status=%s)", (meta or {}).get("status"))
                return meta or None, False
            # HOST TRUST GATE -- runs BEFORE the slot is released clean, so a worker whose output fails
            # host validation (re-sealed hashes / engine / input_sha / caps) stays dirty and is retired
            # rather than re-offered. It re-writes the host-sealed metadata.json in out_dir; re-read it.
            if output_trust is not None:
                output_trust(input_path, out_dir)   # raises on trust failure -> caught below, dirty stays True
                sealed = out_dir / "metadata.json"
                if sealed.exists():
                    meta = json.loads(sealed.read_text())
            dirty = False
            return meta, True
        except Exception as exc:  # noqa: BLE001
            # transport error after the request may have reached the worker -> the box could still be
            # busy; keep dirty=True so the pool retires/recycles it instead of re-offering immediately.
            _log.warning("remote_http: validate failed: %s", exc)
            return None, False
        finally:
            try:
                release(slot, dirty=dirty)
            except TypeError:            # release seam that doesn't accept dirty (legacy callers/tests)
                release(slot)

    return validate
