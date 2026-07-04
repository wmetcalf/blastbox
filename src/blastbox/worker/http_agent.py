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

import hmac
import io
import json
import logging
import os
import tarfile
import tempfile
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

    # quieter logging (per-request lines go to our logger at debug)
    def log_message(self, fmt: str, *args: object) -> None:
        _log.debug("http_agent: " + fmt, *args)

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
            self._json(HTTPStatus.OK, {"ok": True, "engine": self.engine.name})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/detonate":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if not self._authed():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "bad_content_length"})
            return
        if length <= 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "empty_body"})
            return
        if length > self.max_bytes:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "too_large", "max_bytes": self.max_bytes})
            return
        name = _safe_name(parse_qs(parsed.query).get("name", [None])[0])
        try:
            tar_bytes = self._run_job(name, length)
        except _TruncatedBody:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "truncated_body"})
            return
        except Exception as exc:  # noqa: BLE001 -- a job crash must not kill the agent
            _log.warning("http_agent: detonate failed: %s", exc)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "engine_error"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-tar")
        self.send_header("Content-Length", str(len(tar_bytes)))
        self.end_headers()
        self.wfile.write(tar_bytes)

    def _run_job(self, name: str, length: int) -> bytes:
        with tempfile.TemporaryDirectory(prefix="bbagent-") as tmp:
            tmp_p = Path(tmp)
            in_path = tmp_p / name
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
            # SAME core the cold/FC/gVisor workers use: runs the engine + seals metadata.json in out_dir
            run_detonation(self.engine, input_path=in_path, output_dir=out_dir, limits=Limits.from_env())
            # tar the sealed output dir (metadata.json + artifacts) for the host to extract
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                for f in sorted(out_dir.rglob("*")):
                    if f.is_file():
                        tf.add(f, arcname=str(f.relative_to(out_dir)))
            return buf.getvalue()


def serve(engine: Engine, *, bind: str = "0.0.0.0", port: int = 8765,
          token: str | None = None, max_bytes: int = _DEFAULT_MAX_BYTES) -> ThreadingHTTPServer:
    handler = type("_BoundHandler", (_Handler,),
                   {"engine": engine, "token": token, "max_bytes": max_bytes})
    httpd = ThreadingHTTPServer((bind, port), handler)
    _log.info("http_agent: serving engine=%s on %s:%d", engine.name, bind, port)
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
    token = os.environ.get("BLASTBOX_WORKER_AGENT_TOKEN") or None
    max_bytes = int(os.environ.get("BLASTBOX_WORKER_AGENT_MAX_BYTES", str(_DEFAULT_MAX_BYTES)))
    httpd = serve(engine, port=port, token=token, max_bytes=max_bytes)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
