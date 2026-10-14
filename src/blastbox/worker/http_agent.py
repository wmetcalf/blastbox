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
from blastbox.worker.sandbox.base import confined_runs, host_platform

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
    # macOS (no outer isolation boundary): an `ok` result must come from a sandboxed run.
    require_confined: bool = False
    # Set when warmup (an engine's known-positive self-test) failed and health is gated on it.
    warmup_error: str | None = None
    max_bytes: int = _DEFAULT_MAX_BYTES

    def _pre_detect(self) -> bool:
        """Whether to call the engine's optional ``detect()`` in this process. Not on macOS:
        nothing contains this agent there, and ``sandboxed_parsing`` covers ``detonate()``, not a
        detector that may parse the hostile file itself -- unless the engine declares
        ``sandboxed_detect = True`` (its detect() also goes through the sandbox, or reads no
        input bytes)."""
        if host_platform() != "darwin":
            return True
        return bool(getattr(self.engine, "sandboxed_detect", False))

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
        return hmac.compare_digest(got.encode("utf-8", "surrogatepass"),
                               self.token.encode("utf-8", "surrogatepass"))

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
            if self.warmup_error is not None:
                # Not ready: a static pool skips this box instead of feeding it jobs whose
                # results can't be trusted (e.g. a sandbox that silently lost a grant).
                self._json(HTTPStatus.SERVICE_UNAVAILABLE,
                           {"ok": False, "engine": self.engine.name, "warmup": "failed"})
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
                confined_before = confined_runs()
                try:
                    rc = run_detonation(self.engine, input_path=in_path, output_dir=out_dir, limits=limits,
                                        pre_detect=self._pre_detect())
                finally:
                    if _wd is not None:
                        _wd.cancel()
            if rc != 0:
                # harness could not seal metadata.json -- surface as a job failure, not a silent 200
                raise RuntimeError(f"harness failed (rc={rc}); metadata.json not sealed")
            if self.require_confined and confined_runs() == confined_before:
                # No outer boundary on this host: an `ok` result produced without a single
                # sandboxed run means the engine parsed the input in this (unconfined) process.
                try:
                    status = json.loads((out_dir / "metadata.json").read_bytes()).get("status")
                except (OSError, ValueError):
                    status = None
                if status == "ok":
                    raise RuntimeError("engine returned ok without a confined run; refusing the result")
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
                # Two SEPARATE caps: file_cap bounds the ARTIFACT count (files only, = max_artifacts + 16);
                # a more generous entry_cap bounds the TOTAL walk (dirs/symlinks included) so a directory
                # bomb can't enumerate an unbounded tree under _JOB_LOCK -- WITHOUT rejecting a valid nested
                # layout (one subdir per artifact ~ 2x entries; allow generous nesting), which charging dirs
                # to file_cap wrongly did.
                entry_cap = None if file_cap is None else (4 * file_cap + 64)
                candidates: list = []
                entries = 0
                for f in out_dir.rglob("*"):
                    entries += 1
                    if entry_cap is not None and entries > entry_cap:
                        spool.close()
                        raise RuntimeError(f"output exceeds {entry_cap} entries (directory bomb?)")
                    if not f.is_file():
                        continue
                    candidates.append(f)
                    if file_cap is not None and len(candidates) > file_cap:
                        spool.close()
                        raise RuntimeError(f"output exceeds {file_cap} files")
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


_TRUE_WORDS = ("1", "true", "yes")
_FALSE_WORDS = ("0", "false", "no")


def _env_flag(name: str, default: bool) -> bool:
    """A security switch from the environment: 0/1/true/false/yes/no (any case); unset or empty
    keeps ``default``. Anything else stops startup -- a typo must not silently pick a side."""
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE_WORDS:
        return True
    if raw in _FALSE_WORDS:
        return False
    raise SystemExit(f"http_agent: {name}={os.environ.get(name)!r} is not one of "
                     "0/1/true/false/yes/no; refusing to start")


def _guard_unsandboxed_engine(engine: Engine) -> bool:
    """On macOS, refuse an engine that doesn't sandbox its parsing; return whether each job must
    prove a confined run.

    A Linux agent sits inside a runsc/Firecracker boundary, so an engine that parses in-process is
    still contained. A Mac has no outer boundary: ``BLASTBOX_SANDBOX`` only selects the backend an
    engine *may* use through ``select_sandbox()``, it confines nothing by itself. So an engine must
    declare ``sandboxed_parsing = True`` (it runs every untrusted parse through ``select_sandbox()``)
    and each ``ok`` result must coincide with a confined run.
    ``BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE=1`` is the explicit, logged escape hatch.
    """
    if host_platform() != "darwin":
        return False
    if _env_flag("BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE", False):
        _log.warning("http_agent: macOS with BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE=1 -- engine "
                     "%s may parse untrusted input in this unconfined process", engine.name)
        return False
    if not getattr(engine, "sandboxed_parsing", False):
        raise SystemExit(
            f"http_agent: refusing engine {engine.name!r} on macOS: it does not declare "
            "sandboxed_parsing = True. There is no outer isolation boundary here, so an engine that "
            "parses in-process would run hostile input in this long-lived agent. Run every parse "
            "through select_sandbox() and declare it, or set "
            "BLASTBOX_WORKER_AGENT_ALLOW_UNSANDBOXED_ENGINE=1 to accept the risk.")
    return True


def _warmup(engine: Engine, require_warmup: bool, require_confined: bool = False) -> str | None:
    """Run the engine's warmup; the error that keeps /healthz at 503, or None when ready.

    With ``require_confined`` (macOS, sandboxed engine) a required warmup also has to complete a
    confined run: a self-test that passed by parsing in-process proves nothing about the
    sandbox's grants, so the agent stays unready until one runs through the sandbox."""
    if not hasattr(engine, "warmup"):
        if require_warmup:
            # The gate is "a known-positive self-test passed": an engine without one isn't ready.
            _log.error("http_agent: engine has no warmup self-test; /healthz reports NOT ready")
            return "engine has no warmup self-test"
        return None
    confined_before = confined_runs()
    try:
        engine.warmup()
    except Exception as exc:  # noqa: BLE001 -- warmup is best-effort (fail-open to cold)
        if require_warmup:
            _log.error("http_agent: warmup failed; /healthz reports NOT ready: %s", exc)
            return str(exc)[:500]
        _log.warning("http_agent: warmup failed (continuing cold): %s", exc)
        return None
    if require_warmup and require_confined and confined_runs() == confined_before:
        _log.error("http_agent: warmup passed without a confined run; /healthz reports NOT ready")
        return "warmup self-test did not complete a confined (sandboxed) run"
    return None


WARMUP_RETRY_FIRST_S = 30.0
WARMUP_RETRY_MAX_S = 300.0


def retry_warmup(engine: Engine, handler: type[_Handler], *,
                 first_s: float = WARMUP_RETRY_FIRST_S, max_s: float = WARMUP_RETRY_MAX_S,
                 stop: threading.Event | None = None) -> threading.Thread:
    """While ``handler.warmup_error`` is set, rerun the required warmup with backoff
    (``first_s`` doubling to ``max_s``); success clears it and /healthz turns 200. Runs under the
    job lock, so a retry never overlaps a detonation."""
    stop = stop or threading.Event()

    def loop() -> None:
        delay = first_s
        while handler.warmup_error is not None and not stop.wait(delay):
            with _JOB_LOCK:
                err = _warmup(engine, require_warmup=True,
                              require_confined=handler.require_confined)
            handler.warmup_error = err
            if err is None:
                _log.info("http_agent: warmup passed on retry; /healthz reports ready")
                return
            delay = min(max_s, delay * 2)

    t = threading.Thread(target=loop, name="bb-warmup-retry", daemon=True)
    t.start()
    return t


def serve(engine: Engine, *, bind: str = "0.0.0.0", port: int = 8765,
          token: str | None = None, max_bytes: int = _DEFAULT_MAX_BYTES,
          tls_cert: str | None = None, tls_key: str | None = None,
          client_ca: str | None = None, allow_cidrs: str | None = None,
          timeout_s: float = 300.0, warmup_error: str | None = None) -> ThreadingHTTPServer:
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
    require_confined = _guard_unsandboxed_engine(engine)
    handler = type("_BoundHandler", (_Handler,),
                   {"engine": engine, "token": token, "max_bytes": max_bytes,
                    "allow_nets": _parse_cidrs(allow_cidrs), "timeout": timeout_s,
                    "require_confined": require_confined, "warmup_error": warmup_error})
    httpd = ThreadingHTTPServer((bind, port), handler)
    if tls_cert and tls_key:
        from blastbox.tls import server_ssl_context
        try:
            # OSError covers a missing/unreadable file (PermissionError, FileNotFoundError) AND a
            # malformed cert/key (ssl.SSLError subclasses OSError). Turn the raw traceback into an
            # actionable message -- the common trap is a 0600 key owned by root that the agent's
            # non-root image USER can't read over a read-only mount, which otherwise crash-loops
            # the container with an opaque error.
            ctx = server_ssl_context(tls_cert, tls_key, client_ca_file=client_ca)
        except OSError as exc:
            httpd.socket.close()
            raise SystemExit(
                f"http_agent: cannot load TLS material (cert={tls_cert!r} key={tls_key!r} "
                f"client_ca={client_ca!r}): {exc}. The files must exist and be READABLE by the agent "
                f"uid ({os.getuid()}) -- a 0600 key owned by root is unreadable when the image runs as "
                f"a non-root USER; chown the key to the agent uid or loosen its mode.") from exc
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
    # On macOS warmup is where an engine runs its known-positive self-test, and a failed one means
    # results can't be trusted, so it gates /healthz there by default
    # (BLASTBOX_WORKER_AGENT_REQUIRE_WARMUP=0/1 overrides on any platform).
    require_warmup = _env_flag("BLASTBOX_WORKER_AGENT_REQUIRE_WARMUP", host_platform() == "darwin")
    # Refuse an unsandboxed engine before its warmup parses anything; serve() re-checks.
    require_confined = _guard_unsandboxed_engine(engine)
    warmup_error = _warmup(engine, require_warmup, require_confined)
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
                  timeout_s=timeout_s, warmup_error=warmup_error)
    if warmup_error is not None and hasattr(engine, "warmup"):
        # launchd/KeepAlive won't restart a live process, so a transient failure (a busy ANE, a
        # slow first compile) would otherwise keep this Mac out of the pool until someone notices.
        retry_warmup(engine, httpd.RequestHandlerClass)  # type: ignore[arg-type]  # serve() binds a _Handler subclass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
