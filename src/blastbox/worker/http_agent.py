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
import time
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


class _SlowBody(Exception):
    """The client trickled the request body past the total wall-clock budget while holding the single-
    flight job lock -- one slow uploader must not take the worker out of service (every other job 409s)."""


_HARD_EXIT = os._exit   # injectable seam: tests override this to avoid killing the test runner


def _hard_deadline_s(limits: Limits) -> float:
    """Hard wall-clock ceiling for ONE detonation, strictly > the engine's own ``timeout_s`` so a normal
    job never trips it. An explicit ``BLASTBOX_WORKER_AGENT_HARD_TIMEOUT_S`` wins (0/negative disables the
    watchdog); else 2x the per-job timeout + 30s slack."""
    override = os.environ.get("BLASTBOX_WORKER_AGENT_HARD_TIMEOUT_S")
    if override is not None:
        return max(0.0, float(override))
    return float(limits.timeout_s) * 2.0 + 30.0


def _on_hard_deadline(hard_s: float) -> None:
    # A hung engine (in-process infinite loop / a child ignoring its own timeout) holds _JOB_LOCK forever:
    # /healthz stays 200 but every /detonate 409s -- a black hole on a reused static/warm box. A Python
    # thread can't be killed and a per-job subprocess would forfeit engine warmth, so RETIRE the whole
    # worker; the supervisor / warm pool replaces the box (its /healthz stops answering -> fail-closed).
    _log.critical("http_agent: detonation exceeded the %.0fs hard deadline -- retiring the worker (a hung "
                  "engine can't be killed in-thread); the supervisor/pool will replace it", hard_s)
    with contextlib.suppress(Exception):
        import faulthandler
        faulthandler.dump_traceback()
    _HARD_EXIT(75)


class _Handler(BaseHTTPRequestHandler):
    engine: Engine = None  # type: ignore[assignment]  # set on the server
    token: str | None = None
    max_bytes: int = _DEFAULT_MAX_BYTES
    allow_nets: list = []  # peer-IP allowlist (empty = allow any; mTLS is the stronger gate)
    # Socket read timeout (StreamRequestHandler.setup() applies it): a stalled/slowloris request body
    # would otherwise hold the single-flight _JOB_LOCK forever and wedge the whole worker. Overridable
    # via BLASTBOX_WORKER_AGENT_TIMEOUT_S; must exceed the largest legitimate upload's transfer time.
    timeout = 300.0   # ClassVar (matches StreamRequestHandler.timeout); no annotation -> no override clash

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
        except _SlowBody:
            self._json(HTTPStatus.REQUEST_TIMEOUT, {"error": "slow_body"})
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
            # stream the body to disk (bounded by size AND a TOTAL wall-clock deadline). The socket timeout
            # only caps idle GAPS, so a client trickling the body (a byte before each timeout) would hold
            # _JOB_LOCK far past the budget and 409 every real job. Cap each recv to the remaining budget so
            # the deadline is enforced during a blocking read too (a single read() can buffer + block).
            remaining = length
            deadline = time.monotonic() + self.timeout
            read = getattr(self.rfile, "read1", self.rfile.read)
            try:
                with in_path.open("wb") as fh:
                    while remaining > 0:
                        budget = deadline - time.monotonic()
                        if budget <= 0:
                            raise _SlowBody
                        with contextlib.suppress(OSError):
                            self.connection.settimeout(budget)
                        try:
                            chunk = read(min(remaining, 1024 * 1024))
                        except (TimeoutError, OSError) as exc:
                            if time.monotonic() >= deadline:
                                raise _SlowBody from exc
                            raise
                        if not chunk:
                            break
                        fh.write(chunk)
                        remaining -= len(chunk)
            finally:
                # restore the per-recv timeout so the shrunk read budget doesn't leak into the response write
                with contextlib.suppress(OSError):
                    self.connection.settimeout(self.timeout)
            if remaining > 0:
                raise _TruncatedBody
            # SAME core the cold/FC/gVisor workers use: runs the engine + seals metadata.json in out_dir.
            # Per-job params (already host-allowlisted) are applied to env just for this detonation.
            with _job_env(params):
                # build Limits INSIDE the params env so dispatcher-owned overrides (BLASTBOX_NET_EGRESS,
                # render tunables, ...) forwarded via X-Blastbox-Params actually take effect -- reading
                # them before _job_env would pin Limits to the worker-image defaults (sealed egress).
                limits = Limits.from_env()
                # AGENT-side hard-deadline backstop, armed ONLY around the detonation (the body is already
                # read, so a slow uploader -- handled by _SlowBody -- can't trip it): a hung engine would
                # otherwise pin _JOB_LOCK forever. The deadline is strictly > the engine's own timeout, so
                # a normal job cancels the timer well before it fires and _HARD_EXIT is never called.
                _hard_s = _hard_deadline_s(limits)
                _wd = threading.Timer(_hard_s, _on_hard_deadline, args=(_hard_s,)) if _hard_s > 0 else None
                if _wd is not None:
                    _wd.daemon = True
                    _wd.start()
                try:
                    rc = run_detonation(self.engine, input_path=in_path, output_dir=out_dir, limits=limits)
                finally:
                    if _wd is not None:
                        _wd.cancel()
            if rc != 0:
                # harness could not seal metadata.json -- surface as a job failure, not a silent 200
                raise RuntimeError(f"harness failed (rc={rc}); metadata.json not sealed")
            # tar the sealed output dir (metadata.json + artifacts) into a SPOOLED file (spills to disk
            # past 64MB) rather than a full in-memory BytesIO, and CAP the total so a buggy engine that
            # leaves huge undeclared files in out_dir can't OOM the agent. The host re-enforces its own
            # caps on extraction; this is the worker's self-protection.
            cap = getattr(limits, "max_total_artifact_bytes", None)
            meta_cap = getattr(limits, "max_metadata_bytes", None)
            # member cap too: zero-byte/tiny files never advance the byte cap, so an engine that leaves
            # hundreds of thousands of them could still emit a huge tar header stream + burn CPU/inodes.
            max_files = getattr(limits, "max_artifacts", None)
            file_cap = (max_files + 16) if max_files is not None else None
            spool: tempfile.SpooledTemporaryFile = tempfile.SpooledTemporaryFile(
                max_size=64 * 1024 * 1024, prefix="bbagent-tar-")
            total = 0
            with tarfile.open(fileobj=spool, mode="w") as tf:
                # Enforce the member cap DURING a LAZY walk, BEFORE sorting: sorted(out_dir.rglob("*"))
                # materializes + sorts the ENTIRE tree, so a job leaving hundreds of thousands of entries
                # burns worker memory/CPU before file_cap could fire. Collect regular files lazily, stop at
                # the cap, then sort the bounded set for a deterministic tar layout.
                candidates: list = []
                entries = 0
                for f in out_dir.rglob("*"):
                    # count EVERY entry (dirs/symlinks/non-files too) BEFORE the non-file skip, so a
                    # directory-bomb out_dir (many empty dirs, few files) can't walk the whole tree under
                    # _JOB_LOCK without tripping the cap -- mirrors the extraction-side header count. file_cap
                    # = max_artifacts + 16, so a handful of legit subdirs are absorbed by the slack.
                    entries += 1
                    if file_cap is not None and entries > file_cap:
                        spool.close()
                        raise RuntimeError(f"output exceeds {file_cap} entries")
                    if not f.is_file():
                        continue
                    candidates.append(f)
                for f in sorted(candidates):
                    # metadata.json is a control file, not a declared artifact -- don't count it toward
                    # the artifact byte budget (matches the cold trust gate + the host extractor), but DO
                    # cap it by its OWN budget BEFORE archiving so a buggy engine's huge metadata can't
                    # fill the worker disk (a second copy lands in the spooled tar) before the host rejects it.
                    if f.name == "metadata.json" and f.parent == out_dir:
                        if meta_cap is not None and f.stat().st_size > meta_cap:
                            spool.close()
                            raise RuntimeError(f"metadata.json is {f.stat().st_size} bytes (> {meta_cap})")
                    else:
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


_LOOPBACK_BINDS = ("127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1")


def _guard_exposure(bind: str, port: int, *, token, client_ca, allow_cidrs, allow_insecure: bool) -> None:
    """FAIL CLOSED when the agent would listen on a non-loopback address with NO request gate
    (mTLS / bearer token / IP allowlist): anyone who can reach the port could submit arbitrary jobs and
    consume the worker's egress + sandbox boundary. A gated deployment (AWS microVM JWE proxy, a security
    group, a private worker network) can opt back in with BLASTBOX_WORKER_AGENT_ALLOW_INSECURE=1."""
    # Parse the CIDR list the SAME way serve()/_caller_allowed does. Two ways it is NOT actually a gate,
    # both of which _caller_allowed treats as allow-ANY: (1) a whitespace/comma-only value (e.g. a typo
    # `" , "`) parses to an EMPTY list; (2) a catch-all network (`0.0.0.0/0` / `::/0`, prefixlen 0) matches
    # every peer. Count the allowlist as a gate ONLY if it is non-empty AND has no catch-all entry.
    _cidrs = _parse_cidrs(allow_cidrs)
    has_cidr_gate = bool(_cidrs) and not any(n.prefixlen == 0 for n in _cidrs)
    exposed = bind not in _LOOPBACK_BINDS
    if not exposed or client_ca or token or has_cidr_gate:
        return
    where = f"{bind}:{port}"
    if not allow_insecure:
        raise SystemExit(
            f"http_agent: refusing to serve on {where} with NO mTLS / token / IP allowlist -- anyone who "
            "can reach it could submit arbitrary jobs. Set BLASTBOX_WORKER_AGENT_CLIENT_CA (mTLS), "
            "_TOKEN or _ALLOW_CIDRS; bind BLASTBOX_WORKER_AGENT_BIND to loopback; or, if an external gate "
            "(AWS microVM proxy / security group / private network) already fences the port, set "
            "BLASTBOX_WORKER_AGENT_ALLOW_INSECURE=1 to accept the risk explicitly.")
    _log.warning("http_agent: serving on %s with NO mTLS / token / IP allowlist -- relying on an EXTERNAL "
                 "gate (BLASTBOX_WORKER_AGENT_ALLOW_INSECURE=1). Anyone who can reach it can submit jobs.",
                 where)


def serve(engine: Engine, *, bind: str = "0.0.0.0", port: int = 8765,
          token: str | None = None, max_bytes: int = _DEFAULT_MAX_BYTES,
          tls_cert: str | None = None, tls_key: str | None = None,
          client_ca: str | None = None, allow_cidrs: str | None = None,
          timeout_s: float = 300.0) -> ThreadingHTTPServer:
    """Serve the engine. ``tls_cert``/``tls_key`` enable HTTPS; adding ``client_ca`` requires a
    CA-signed **client** cert (mTLS). ``allow_cidrs`` restricts which peer IPs may POST /detonate.
    ``timeout_s`` bounds a request's socket reads so a slowloris body can't hold the job lock forever."""
    # Reject a PARTIAL TLS config here too (not just via main()'s _tls_env), so a direct serve() embedder
    # can't pass client_ca WITHOUT a server cert/key: the ssl wrap below (`if tls_cert and tls_key`) would
    # then be skipped and the agent would listen PLAINTEXT -- but _guard_exposure counts client_ca as an
    # mTLS gate and would wave it through wide open. After this, a truthy client_ca implies real mTLS.
    if bool(tls_cert) != bool(tls_key):
        raise SystemExit("serve(): BLASTBOX_WORKER_AGENT_TLS_CERT and _TLS_KEY must be set together")
    if client_ca and not tls_cert:
        raise SystemExit("serve(): client_ca (mTLS) requires TLS_CERT/_TLS_KEY -- refusing to serve plaintext")
    # fail CLOSED here (not just in main()) so a programmatic embedder that calls serve() directly can't
    # listen wide open on the 0.0.0.0 default with no token/mTLS/allowlist. Idempotent with main()'s check.
    allow_insecure = (os.environ.get("BLASTBOX_WORKER_AGENT_ALLOW_INSECURE") or "").strip().lower() in (
        "1", "true", "yes", "on")
    _guard_exposure(bind, port, token=token, client_ca=client_ca, allow_cidrs=allow_cidrs,
                    allow_insecure=allow_insecure)
    handler = type("_BoundHandler", (_Handler,),
                   {"engine": engine, "token": token, "max_bytes": max_bytes,
                    "allow_nets": _parse_cidrs(allow_cidrs), "timeout": timeout_s})
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
    # request-body cap: honor an explicit override, else derive from the operator input cap so a raised
    # BLASTBOX_MAX_INPUT actually lifts the agent's Content-Length gate on the network tiers (per-job param
    # forwarding can't -- the gate runs before params apply). max() keeps the historic 512 MiB floor so an
    # agent box without BLASTBOX_MAX_INPUT never regresses below today's default.
    _explicit_max = os.environ.get("BLASTBOX_WORKER_AGENT_MAX_BYTES")
    max_bytes = int(_explicit_max) if _explicit_max else max(_DEFAULT_MAX_BYTES, Limits.from_env().max_input_bytes)
    tls_cert, tls_key, client_ca = _tls_env(os.environ.get)
    allow_cidrs = os.environ.get("BLASTBOX_WORKER_AGENT_ALLOW_CIDRS") or None
    timeout_s = float(os.environ.get("BLASTBOX_WORKER_AGENT_TIMEOUT_S") or "300")
    httpd = serve(engine, bind=bind, port=port, token=token, max_bytes=max_bytes,
                  tls_cert=tls_cert, tls_key=tls_key, client_ca=client_ca, allow_cidrs=allow_cidrs,
                  timeout_s=timeout_s)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
