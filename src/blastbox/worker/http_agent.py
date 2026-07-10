"""Generic HTTP worker agent: serve ANY blastbox Engine over HTTP for REMOTE workers.

The container / Firecracker / gVisor worker tiers deliver a job through a shared or mounted filesystem
(`/in`, `/out`). A **remote** worker -- an AWS EC2 instance, a Lambda MicroVM, or any host that can't
share a filesystem with the dispatcher -- can't do that. This agent is the network-endpoint sibling of
`blastbox.worker.cold`: same engine loading + the SAME `run_detonation` core (so sealing happens on the
worker, where the artifact bytes physically are), but the job arrives as an HTTP POST body and the
sealed output directory is returned as a tar in the response.

**Engine-agnostic.** Nothing here is specific to any engine -- bake
`python -m blastbox.worker.http_agent` + any engine (`BLASTBOX_ENGINE=module:Class`) + its runtime deps
into the worker image (EC2 AMI / Lambda MicroVM image), listening on port 8765.

Contract (deliberately mirrors the win-validator myatg agent so one host transport talks to both):

    GET  /healthz                -> 200 {"ok": true}
    POST /detonate?name=<fn>     body = raw input bytes
                                 -> 200 application/x-tar  (the sealed output dir: metadata.json + every
                                    declared artifact). The host extracts it into the job's output/ dir,
                                    exactly as if a local sandbox had written there.

Optional bearer auth: set `BLASTBOX_WORKER_AGENT_TOKEN`; the agent then requires it in
`Authorization: Bearer <t>` OR `X-aws-proxy-auth: <t>` (the header the Lambda-MicroVM runtime sends).
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import json
import logging
import os
import tarfile
import tempfile
import threading
from collections.abc import Iterator
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from blastbox.limits import Limits
from blastbox.worker.engine import Engine
from blastbox.worker.harness import run_detonation
from blastbox.worker.load import load_engine

_log = logging.getLogger("blastbox.worker.http_agent")

_DEFAULT_MAX_BYTES = 512 * 1024 * 1024

# Per-job env (forwarded params) is applied to os.environ around run_detonation, which the threaded
# server would race on -- serialize detonations behind this lock. A warm slot handles one job at a
# time anyway (the pool assigns one box per job), so this costs nothing in the intended topology.
_JOB_LOCK = threading.Lock()


def _parse_params(raw: str | None) -> dict[str, str]:
    """Parse the ``X-Blastbox-Params`` header (a JSON object of already-allowlisted env overrides)."""
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return {str(k): str(v) for k, v in obj.items()} if isinstance(obj, dict) else {}


@contextlib.contextmanager
def _job_env(params: dict[str, str]) -> Iterator[None]:
    """Apply ``params`` to os.environ for the duration of one detonation, then restore. The caller
    holds ``_JOB_LOCK`` (do_POST acquires it non-blocking, one job at a time), so concurrent requests
    can't observe each other's env."""
    saved = {k: os.environ.get(k) for k in params}
    os.environ.update(params)
    try:
        yield
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _safe_name(raw: str | None) -> str:
    """Basename only, sanitized -- never trust the client's ?name= for a path."""
    base = os.path.basename(raw or "input.bin").strip() or "input.bin"
    keep = "".join(c for c in base if c.isalnum() or c in "._-")
    return keep or "input.bin"


class _TruncatedBody(Exception):
    """The client sent fewer bytes than Content-Length declared."""


class _Handler(BaseHTTPRequestHandler):
    engine: Engine = None  # type: ignore[assignment]  # set on the server
    token: str | None = None
    max_bytes: int = _DEFAULT_MAX_BYTES
    allow_nets: list = []  # peer-IP allowlist (empty = allow any; mTLS is the stronger gate)

    # quieter logging (per-request lines go to our logger at debug)
    def log_message(self, fmt: str, *args: object) -> None:
        _log.debug("http_agent: " + fmt, *args)

    def _caller_allowed(self) -> bool:
        """True if the peer IP is in the configured allowlist (or no allowlist is set)."""
        if not self.allow_nets:
            return True
        try:
            peer = ipaddress.ip_address(self.client_address[0])
        except (ValueError, IndexError):
            return False
        return any(peer in net for net in self.allow_nets)

    def _json(self, status: HTTPStatus, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        if not self.token:
            return True
        got = self.headers.get("X-aws-proxy-auth") or ""
        if not got:
            auth = self.headers.get("Authorization", "")
            got = auth[7:] if auth.startswith("Bearer ") else ""
        return hmac.compare_digest(got, self.token)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/healthz":
            # gate readiness with the SAME controls as /detonate -- else a caller outside the CIDR
            # allowlist or with a wrong token is marked "ready" and only fails later on every job.
            if not self._caller_allowed():
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            if not self._authed():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            self._json(HTTPStatus.OK, {"ok": True, "engine": self.engine.name})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/detonate":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if not self._caller_allowed():
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        if not self._authed():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "bad_content_length"})
            return
        if length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "bad_content_length"})
            return
        # length == 0 is allowed: a zero-byte sample is a valid input the local harness also runs.
        if length > self.max_bytes:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "too_large", "max_bytes": self.max_bytes})
            return
        name = _safe_name(parse_qs(parsed.query).get("name", [None])[0])
        params = _parse_params(self.headers.get("X-Blastbox-Params"))
        # Single-flight: a warm box serves ONE job at a time (the pool assigns one box per job). Acquire
        # NON-BLOCKING so a request that lands on a box still finishing a prior (e.g. host-timed-out) job
        # gets a fast 409 -- the dispatcher fails that job + retires the slot dirty -- instead of queueing
        # behind the stale job and cascading into more timeouts / overlapping detonations.
        if not _JOB_LOCK.acquire(blocking=False):
            self._json(HTTPStatus.CONFLICT, {"error": "busy"})
            return
        try:
            tar = self._run_job(name, length, params)
        except _TruncatedBody:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "truncated_body"})
            return
        except Exception as exc:  # noqa: BLE001 -- a job crash must not kill the agent
            _log.warning("http_agent: detonate failed: %s", exc)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "engine_error"})
            return
        finally:
            _JOB_LOCK.release()
        try:
            import shutil
            size = tar.seek(0, os.SEEK_END)
            tar.seek(0)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/x-tar")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            shutil.copyfileobj(tar, self.wfile)   # stream from the spool, don't hold it all in memory
        finally:
            tar.close()

    def _run_job(self, name: str, length: int, params: dict[str, str]) -> tempfile.SpooledTemporaryFile:
        with tempfile.TemporaryDirectory(prefix="bbagent-") as tmp:
            tmp_p = Path(tmp)
            in_dir = tmp_p / "in"
            in_dir.mkdir()
            in_path = in_dir / name           # own subdir: a client name of "out" can't collide with out_dir
            out_dir = tmp_p / "out"
            # stream the body to disk (bounded)
            remaining = length
            with in_path.open("wb") as fh:
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    fh.write(chunk)
                    remaining -= len(chunk)
            if remaining > 0:
                raise _TruncatedBody
            # SAME core the cold/FC/gVisor workers use: runs the engine + seals metadata.json in out_dir.
            # Per-job params (already host-allowlisted) are applied to env just for this detonation.
            with _job_env(params):
                # build Limits INSIDE the params env so dispatcher-owned overrides (BLASTBOX_NET_EGRESS,
                # render tunables, ...) forwarded via X-Blastbox-Params actually take effect -- reading
                # them before _job_env would pin Limits to the worker-image defaults (sealed egress).
                limits = Limits.from_env()
                rc = run_detonation(self.engine, input_path=in_path, output_dir=out_dir,
                                    limits=limits)
            if rc != 0:
                # harness could not seal metadata.json -- surface as a job failure, not a silent 200
                raise RuntimeError(f"harness failed (rc={rc}); metadata.json not sealed")
            # tar the sealed output dir (metadata.json + artifacts) into a SPOOLED file (spills to disk
            # past 64MB) rather than a full in-memory BytesIO, and CAP the total so a buggy engine that
            # leaves huge undeclared files in out_dir can't OOM the agent. The host re-enforces its own
            # caps on extraction; this is the worker's self-protection.
            cap = getattr(limits, "max_total_artifact_bytes", None)
            # member cap too: zero-byte/tiny files never advance the byte cap, so an engine that leaves
            # hundreds of thousands of them could still emit a huge tar header stream + burn CPU/inodes.
            max_files = getattr(limits, "max_artifacts", None)
            file_cap = (max_files + 16) if max_files is not None else None
            spool: tempfile.SpooledTemporaryFile = tempfile.SpooledTemporaryFile(
                max_size=64 * 1024 * 1024, prefix="bbagent-tar-")
            total = 0
            files = 0
            with tarfile.open(fileobj=spool, mode="w") as tf:
                for f in sorted(out_dir.rglob("*")):
                    if not f.is_file():
                        continue
                    files += 1
                    if file_cap is not None and files > file_cap:
                        spool.close()
                        raise RuntimeError(f"output exceeds {file_cap} files")
                    # metadata.json is a control file, not a declared artifact -- don't count it toward
                    # the artifact byte budget (matches the cold trust gate + the host extractor).
                    if f.name != "metadata.json" or f.parent != out_dir:
                        total += f.stat().st_size
                        if cap is not None and total > cap:
                            spool.close()
                            raise RuntimeError(f"output exceeds {cap} bytes")
                    tf.add(f, arcname=str(f.relative_to(out_dir)))
            spool.seek(0)
            return spool


def _tls_env(get) -> tuple[str | None, str | None, str | None]:
    """Read the agent TLS/mTLS env, failing closed on a partial config (never downgrade to plaintext)."""
    cert = get("BLASTBOX_WORKER_AGENT_TLS_CERT") or None
    key = get("BLASTBOX_WORKER_AGENT_TLS_KEY") or None
    ca = get("BLASTBOX_WORKER_AGENT_CLIENT_CA") or None
    if bool(cert) != bool(key):
        raise SystemExit("BLASTBOX_WORKER_AGENT_TLS_CERT and _TLS_KEY must be set together")
    if ca and not cert:
        raise SystemExit("BLASTBOX_WORKER_AGENT_CLIENT_CA (mTLS) requires _TLS_CERT/_TLS_KEY")
    return cert, key, ca


def _parse_cidrs(raw: str | None) -> list:
    nets = []
    for c in (raw or "").split(","):
        c = c.strip()
        if c:
            nets.append(ipaddress.ip_network(c, strict=False))
    return nets


def serve(engine: Engine, *, bind: str = "0.0.0.0", port: int = 8765,
          token: str | None = None, max_bytes: int = _DEFAULT_MAX_BYTES,
          tls_cert: str | None = None, tls_key: str | None = None,
          client_ca: str | None = None, allow_cidrs: str | None = None) -> ThreadingHTTPServer:
    """Serve the engine. ``tls_cert``/``tls_key`` enable HTTPS; adding ``client_ca`` requires a
    CA-signed **client** cert (mTLS). ``allow_cidrs`` restricts which peer IPs may POST /detonate."""
    handler = type("_BoundHandler", (_Handler,),
                   {"engine": engine, "token": token, "max_bytes": max_bytes,
                    "allow_nets": _parse_cidrs(allow_cidrs)})
    httpd = ThreadingHTTPServer((bind, port), handler)
    if tls_cert and tls_key:
        from blastbox.tls import server_ssl_context
        ctx = server_ssl_context(tls_cert, tls_key, client_ca_file=client_ca)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    _log.info("http_agent: serving engine=%s on %s:%d (tls=%s mtls=%s allowlist=%s)",
              engine.name, bind, port, bool(tls_cert), bool(client_ca), bool(allow_cidrs))
    return httpd


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    spec = os.environ.get("BLASTBOX_ENGINE")
    if not spec:
        raise SystemExit("BLASTBOX_ENGINE=module:Class is required")
    engine = load_engine(spec)
    if hasattr(engine, "warmup"):
        try:
            engine.warmup()
        except Exception as exc:  # noqa: BLE001 -- warmup is best-effort (fail-open to cold)
            _log.warning("http_agent: warmup failed (continuing cold): %s", exc)
    port = int(os.environ.get("BLASTBOX_WORKER_AGENT_PORT", "8765"))
    bind = os.environ.get("BLASTBOX_WORKER_AGENT_BIND", "0.0.0.0")
    token = os.environ.get("BLASTBOX_WORKER_AGENT_TOKEN") or None
    max_bytes = int(os.environ.get("BLASTBOX_WORKER_AGENT_MAX_BYTES", str(_DEFAULT_MAX_BYTES)))
    tls_cert, tls_key, client_ca = _tls_env(os.environ.get)
    allow_cidrs = os.environ.get("BLASTBOX_WORKER_AGENT_ALLOW_CIDRS") or None
    # fail-loud when exposed with no controls: a non-loopback bind with no mTLS, no token, no allowlist
    if bind not in ("127.0.0.1", "localhost", "::1") and not (client_ca or token or allow_cidrs):
        _log.warning("http_agent: bound to %s with NO mTLS / token / IP allowlist -- anyone who can "
                     "reach :%d can submit jobs. Set BLASTBOX_WORKER_AGENT_CLIENT_CA (mTLS) or "
                     "_ALLOW_CIDRS / _TOKEN.", bind, port)
    httpd = serve(engine, bind=bind, port=port, token=token, max_bytes=max_bytes,
                  tls_cert=tls_cert, tls_key=tls_key, client_ca=client_ca, allow_cidrs=allow_cidrs)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
