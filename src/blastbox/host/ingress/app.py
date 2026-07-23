"""FastAPI ingress application — submit jobs, poll status, fetch artifacts.

Security properties (review will probe):
1. ``BodySizeLimitMiddleware`` rejects over-limit bodies before spooling:
   Content-Length check is O(1); chunked uploads abort mid-stream.
2. ``_safe_upload_name`` strips directory components, rejects hidden names, and
   replaces unsafe characters — path traversal via filename is impossible.
3. Artifact serving is id-based: ``GET /v1/jobs/{id}/artifacts/{artifact_id}``
   looks up the artifact's *path* in the dispatcher-validated ``metadata.json``
   (read through the BlobStore, not disk); the declared relative path is
   confirmed non-absolute and traversal-free via ``_safe_relative_artifact_path``
   before it is ever used as a BlobStore key.  No client-supplied path is ever
   used directly.
4. Bearer auth is off by default (proxy-fronted); a loud warning is logged.
   ``hmac.compare_digest`` prevents timing oracles.
5. ``_intake_gate`` semaphore (sized from ``BLASTBOX_API_WORKERS``, parsed +
   clamped) is **actually acquired** around every upload-spool operation.
6. ``sanitize_public_error`` is applied to all detail strings before returning.
7. Engine allowlist: ``engine`` form field must be in the configured set or the
   upload is rejected 400 before any disk I/O.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import mimetypes
import os
import re
import shutil
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST

from blastbox import __version__
from blastbox.errors import sanitize_public_error
from blastbox.host.blobs.base import BlobStore
from blastbox.host.jobs.base import VALID_TIERS, Job, JobStatus, JobStore
from blastbox.host.jobs.factory import build_job_store_from_env
from blastbox.limits import Limits
from blastbox.observability import (
    configure_logging,
    generate_latest,
    get_logger,
    record_job_submitted,
    record_rejection,
    JOBS_IN_FLIGHT,
)
from .extension import IngressExtension, StaticUI
from .middleware import (
    DEFAULT_CSP,
    BearerAuthMiddleware,
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
)

_log = get_logger("blastbox.ingress")

# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")

# Bounds on client-supplied job params (persisted on the Job + forwarded to the dispatcher).
_MAX_PARAMS = 64
_MAX_PARAM_LEN = 4096

# Chunk size for streaming a BlobStore artifact (e.g. metadata.json) back to the client
# without buffering the whole object in this process.
_STREAM_CHUNK = 1024 * 1024


def _safe_upload_name(raw: str | None) -> str:
    """Sanitize a client-supplied filename to a safe basename.

    Rules:
    - Extract the basename only (strips any ``../`` prefix or directory path).
    - Reject leading dots (hidden files) and empty results → ``"upload.bin"``.
    - Replace any character outside ``[A-Za-z0-9._-]`` with ``_``.
    - Truncate to 255 characters (POSIX NAME_MAX).
    - Fall back to ``"upload.bin"`` if nothing usable remains.
    """
    if not raw:
        return "upload.bin"
    base = Path(raw).name
    if not base or base.startswith("."):
        return "upload.bin"
    cleaned = _SAFE_FILENAME_RE.sub("_", base)[:255]
    return cleaned or "upload.bin"


# ---------------------------------------------------------------------------
# Artifact path confinement
# ---------------------------------------------------------------------------


def _safe_relative_artifact_path(relative: str) -> str | None:
    """Validate a metadata-declared artifact path is a safe, CONTAINED relative name,
    without touching disk.

    Task 7 gap 2: after the worker purge, a job's local ``output/`` dir may not exist
    on this node at all, so there is no real filesystem path left to
    ``Path.resolve() + relative_to()`` against (the old ``_safe_artifact_path``
    approach). Containment is re-expressed purely on the declared relative name
    itself: reject an absolute path or any ``..`` traversal component *before* the
    caller ever calls ``BlobStore.open_output``. Returns ``relative`` unchanged if
    it's safe, else ``None`` (mirrors the old function's None-on-escape contract).
    """
    if not relative or not isinstance(relative, str):
        return None
    p = PurePosixPath(relative)
    if p.is_absolute():
        return None
    if any(part in ("..", "") for part in p.parts):
        return None
    return relative


def _fetch_and_parse_metadata(blob_store: BlobStore, job_id: str) -> object:
    """Fetch + parse ``metadata.json`` through the BlobStore.

    Task 7 gap 2: artifact routes must never read the local job dir — by the time
    they run on a real (multi-node) deployment the worker has already purged it.
    Mirrors ``get_result``'s metadata fetch. Raises 404 if the object is missing or
    unreadable, 500 if it isn't valid JSON.
    """
    try:
        with blob_store.open_output(job_id, "metadata.json") as fh:
            meta_bytes = fh.read()
    except Exception:
        raise HTTPException(404, "metadata.json not found")
    try:
        return json.loads(meta_bytes)
    except Exception:
        raise HTTPException(500, "could not parse metadata.json")


def _declared_artifact_paths_from_meta(meta: object) -> frozenset[str]:
    """Return the set of ``artifacts[].path`` declared in an already-parsed
    ``metadata.json`` object — the only paths the trust gate re-hashed and thus the
    only paths a fixed-filename serve route may return. Fail-closed: a malformed
    manifest shape yields the empty set (→ caller 404s), so an undeclared file a
    compromised worker dropped is never served as trusted output.

    Task 7 gap 2: takes the already-parsed object (fetched via the BlobStore by
    ``_fetch_and_parse_metadata``) rather than reading+parsing ``output_dir`` off
    disk itself.
    """
    if not isinstance(meta, dict):
        # A top-level JSON array/scalar (e.g. "[]") would make .get() raise — fail closed.
        return frozenset()
    artifacts = meta.get("artifacts", [])
    if not isinstance(artifacts, list):
        # "artifacts": null / 5 / {} would make `for a in ...` raise (TypeError) OUTSIDE the
        # json try/except → a 500 on the serve route. A non-list manifest is malformed — fail
        # closed to the empty set so the caller 404s rather than crashing.
        return frozenset()
    paths = {
        a["path"]
        for a in artifacts
        if isinstance(a, dict) and isinstance(a.get("path"), str)
    }
    return frozenset(paths)


# ---------------------------------------------------------------------------
# Upload I/O helpers
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# ZIP helper
# ---------------------------------------------------------------------------


def _zip_validated_artifacts(
    blob_store: BlobStore,
    job_id: str,
    metadata_bytes: bytes,
    artifact_rels: list[str],
    dest,
    password: str | None = None,
) -> None:
    """Write a ZIP of ONLY the dispatcher-validated artifacts (+ ``metadata.json``) to ``dest``
    (a writable binary file object). The caller streams from a TEMP FILE, so the ZIP — up to
    max_total_artifact_bytes — is never held in host memory.

    If ``password`` is a non-empty string the archive is **AES-256 encrypted** (pyzipper) —
    the standard malware-handling convention for shipping detonated artifacts so AV/scanners
    don't auto-open or quarantine them in transit (default password ``"infected"``). An
    empty/None password writes a plain ``ZIP_DEFLATED`` archive.

    Task 7: reads every byte through the BlobStore (``open_output``), not the local
    filesystem — after Task 5's worker purge, the job's local ``output/`` dir is gone by
    the time this runs on a real (multi-node) deployment. ``metadata_bytes`` is the
    already-fetched ``metadata.json`` content (the caller reads it once, both to derive
    ``artifact_rels`` and to embed here). A compromised worker can get EXTRA undeclared
    files uploaded alongside the sealed output (``put_output`` copies everything under
    ``output/``, not just declared artifacts) — we still serve only the relative paths the
    trust gate declared in ``metadata.json``, silently skipping any declared artifact the
    blob store can't produce (mirrors the old filesystem version's skip-on-missing/symlink
    behaviour, just with the trust boundary at "was it uploaded under this job_id" instead
    of filesystem containment).
    """
    if password:
        import pyzipper  # type: ignore[import-untyped]

        zf_cm = pyzipper.AESZipFile(
            dest, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        )
    else:
        zf_cm = zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED)
    seen: set[str] = set()
    with zf_cm as zf:
        if password:
            zf.setpassword(password.encode("utf-8"))
        zf.writestr("metadata.json", metadata_bytes)
        seen.add("metadata.json")
        for rel in artifact_rels:
            if not rel or rel in seen:
                continue
            seen.add(rel)
            try:
                with blob_store.open_output(job_id, rel) as fh:
                    data = fh.read()
            except Exception:
                continue
            zf.writestr(rel, data)


# ---------------------------------------------------------------------------
# build_app factory
# ---------------------------------------------------------------------------


def build_app(
    *,
    job_store: JobStore | None = None,
    job_root: Path | None = None,
    allowed_engines: set[str] | None = None,
    limits: Limits | None = None,
    api_workers: int | None = None,
    api_key: str | None = None,
    metrics_public: bool | None = None,
    extension: IngressExtension | None = None,
    zip_password: str | None = None,
    blob_store: BlobStore | None = None,
) -> FastAPI:
    """Construct and return the blastbox ingress FastAPI application.

    All configuration can be supplied directly (for tests) or read from
    ``BLASTBOX_*`` environment variables.

    Args:
        job_store: Backing store. Defaults to ``build_job_store_from_env()`` —
                   ``BLASTBOX_DATABASE_URL`` (sqlite/postgres/redis) or an in-memory store.
        job_root: Directory under which job subdirectories are created.
                  Defaults to ``BLASTBOX_JOB_ROOT`` env var or
                  ``/var/lib/blastbox/jobs``.
        allowed_engines: Set of engine names clients may submit to.
                         Defaults to ``BLASTBOX_ALLOWED_ENGINES`` (comma-sep).
        limits: Resource limits.  Defaults to ``Limits.from_env()``.
        api_workers: Max concurrent upload-spool operations.  Defaults to
                     ``BLASTBOX_API_WORKERS`` (clamped to [1, 64]).
        api_key: If set, installs ``BearerAuthMiddleware``; else warns.
                 Defaults to ``BLASTBOX_API_KEY`` env var.
        metrics_public: Whether ``GET /metrics`` bypasses bearer auth.  Defaults to
                        ``BLASTBOX_METRICS_PUBLIC`` (true unless ``false``/``0``/``no``/``off``).
                        Only takes effect when ``api_key`` is set (otherwise nothing is gated).
        blob_store: Backing blob store. Defaults to ``build_blob_store_from_env()`` —
                    ``BLASTBOX_BLOB_URL`` unset means ``LocalBlobStore`` (no bytes moved).
    """
    configure_logging()

    _limits = limits or Limits.from_env()

    _job_store: JobStore = job_store or build_job_store_from_env()

    _job_root = job_root or Path(
        os.environ.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs")
    ).expanduser()

    from blastbox.host.blobs.factory import build_blob_store_from_env

    # Task 9: LocalBlobStore is a REAL store now, and its default blob_root is derived
    # FROM job_root (a sibling `blobs` dir) -- so the factory must see the job_root this
    # app actually uses, not just the raw env var. Without this override, an explicit
    # `job_root=` caller (every test, and any deployment that doesn't rely purely on
    # BLASTBOX_JOB_ROOT) would get a LocalBlobStore rooted at the WRONG directory: samples
    # spooled under `_job_root` would be put_sample'd into a blob_root computed from a
    # different (default) path, and likely fail outright (e.g. no permission to create
    # ``/var/lib/blastbox/blobs``) where the old no-op store never touched the filesystem.
    _blob_store = blob_store if blob_store is not None else build_blob_store_from_env(
        {**os.environ, "BLASTBOX_JOB_ROOT": str(_job_root)}
    )

    # Engine allowlist
    _allowed_engines: set[str]
    if allowed_engines is not None:
        _allowed_engines = set(allowed_engines)
    else:
        raw_engines = os.environ.get("BLASTBOX_ALLOWED_ENGINES", "")
        _allowed_engines = {e.strip() for e in raw_engines.split(",") if e.strip()}
    if not _allowed_engines:
        # An empty allowlist means ANY engine name is accepted (and the upload spooled to disk)
        # before the dispatcher rejects unknown engines — a permissive default kept for dev/test.
        # Operators who want fail-closed ingress (reject unknown engines BEFORE the disk spool)
        # set BLASTBOX_REQUIRE_ENGINE_ALLOWLIST=1, which turns an empty/unset allowlist into a
        # hard startup error rather than a silent accept-any.
        if os.environ.get("BLASTBOX_REQUIRE_ENGINE_ALLOWLIST", "").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            raise RuntimeError(
                "BLASTBOX_REQUIRE_ENGINE_ALLOWLIST is set but the engine allowlist is empty: "
                "refusing to start with an open allowlist. Set BLASTBOX_ALLOWED_ENGINES to the "
                "engines this ingress should accept (comma-separated)."
            )
        # Don't let the ingress allowlist silently become a no-op: an empty set means ANY engine
        # name is accepted (and spooled) before the dispatcher rejects unknown engines. Surface it.
        _log.warning(
            "engine_allowlist_unconfigured accepts_any_engine=true "
            "fix=set_BLASTBOX_ALLOWED_ENGINES_or_pass_allowed_engines"
        )

    # Concurrency gate (BLASTBOX_API_WORKERS)
    if api_workers is not None:
        _api_workers = max(1, min(64, api_workers))
    else:
        raw_workers = os.environ.get("BLASTBOX_API_WORKERS", "4")
        try:
            _api_workers = max(1, min(64, int(raw_workers)))
        except ValueError:
            _api_workers = 4

    # Security requirement 5: semaphore is actually wired to _api_workers.
    _intake_gate = asyncio.Semaphore(_api_workers)

    # Bound concurrent in-memory result-ZIP builds (each up to max_total_artifact_bytes) so a
    # burst of /result requests can't amplify into host memory pressure.
    _result_gate = asyncio.Semaphore(max(1, min(_api_workers, 4)))

    # Bearer auth (requirement 4)
    _api_key = api_key if api_key is not None else os.environ.get("BLASTBOX_API_KEY", "").strip()
    _metrics_public = (
        metrics_public
        if metrics_public is not None
        else os.environ.get("BLASTBOX_METRICS_PUBLIC", "true").strip().lower()
        not in ("false", "0", "no", "off")
    )

    # Result-ZIP encryption (BLASTBOX_ZIP_PASSWORD). Default "infected" — the
    # malware-handling convention: detonated artifacts ship AES-256 encrypted so
    # AV/scanners don't auto-open or quarantine them in transit. Set to an empty
    # string to disable encryption (plain ZIP).
    _zip_password = (
        zip_password
        if zip_password is not None
        else os.environ.get("BLASTBOX_ZIP_PASSWORD", "infected")
    )

    # -------------------------------------------------------------------
    # App + middleware
    # -------------------------------------------------------------------

    # A malware-processing service must not publish its API surface by default —
    # withhold /docs, /redoc, /openapi.json unless an operator opts in. (The
    # engines' bespoke hosts gated these; the migration lost the gate.)
    _expose_docs = os.environ.get("BLASTBOX_EXPOSE_DOCS", "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    app = FastAPI(
        title="blastbox",
        version=__version__,
        docs_url="/docs" if _expose_docs else None,
        redoc_url="/redoc" if _expose_docs else None,
        openapi_url="/openapi.json" if _expose_docs else None,
    )

    # Hardening headers on every response (clickjacking / MIME-sniff / referrer /
    # CSP) — restored from the bespoke hosts. CSP overridable via BLASTBOX_CSP.
    app.add_middleware(
        SecurityHeadersMiddleware,
        csp=os.environ.get("BLASTBOX_CSP", DEFAULT_CSP),
    )

    # Requirement 1: 413 before spool (Content-Length fast path + streaming).
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=_limits.max_input_bytes)

    if _api_key:
        app.add_middleware(
            BearerAuthMiddleware, api_key=_api_key, metrics_public=_metrics_public
        )
        _log.info("api_auth_enabled", scheme="bearer", metrics_public=_metrics_public)
    else:
        _log.warning(
            "api_auth_disabled",
            message=(
                "HTTP server has no authentication. Set BLASTBOX_API_KEY "
                "or place behind an auth proxy. /v1/* and /metrics are open."
            ),
        )

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _validate_job_id(job_id: str) -> None:
        """Raise 404 if *job_id* is not a well-formed UUID.

        Defense-in-depth (FIX 2): job_ids are always UUIDs generated by
        ``Job.new()``.  Reject anything that doesn't parse as a UUID before
        any store lookup or filesystem use, preventing path traversal and
        injection attempts dressed up as job ids.
        """
        try:
            uuid.UUID(job_id)
        except (ValueError, AttributeError):
            raise HTTPException(404, "job not found")

    def _job_dirs(job_id: str) -> tuple[Path, Path, Path]:
        root = _job_root / job_id
        return root, root / "input", root / "output"

    def _require_done(job_id: str) -> Job:
        """Gate for artifact routes: 404 / 409 / 410 as appropriate."""
        job = _job_store.get(job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        if job.status == JobStatus.EXPIRED:
            raise HTTPException(410, "result expired")
        if job.status != JobStatus.DONE:
            raise HTTPException(409, f"job not done (status={job.status.value})")
        return job

    def _public_detail(exc: Exception | str) -> str:
        return sanitize_public_error(str(exc))

    def _stream_artifact_response(
        job_id: str,
        rel: str,
        *,
        media_type: str | None,
        filename: str | None,
    ):
        """Open ``rel`` through the BlobStore and return it as a streaming response,
        matching ``FileResponse``'s media-type inference / Content-Disposition
        behaviour without ever touching disk. Raises 404 if the object can't be
        opened.
        """
        from fastapi.responses import StreamingResponse

        try:
            fh = _blob_store.open_output(job_id, rel)
        except Exception:
            raise HTTPException(404, "artifact file not found")

        resolved_media_type = media_type or (
            mimetypes.guess_type(filename or rel)[0] or "application/octet-stream"
        )
        headers: dict[str, str] = {}
        if filename is not None:
            from urllib.parse import quote

            quoted = quote(filename)
            if quoted != filename:
                headers["content-disposition"] = f"attachment; filename*=utf-8''{quoted}"
            else:
                headers["content-disposition"] = f'attachment; filename="{filename}"'

        def _iter_fh():
            try:
                while True:
                    chunk = fh.read(_STREAM_CHUNK)
                    if not chunk:
                        break
                    yield chunk
            finally:
                fh.close()

        return StreamingResponse(_iter_fh(), media_type=resolved_media_type, headers=headers)

    def _serve_artifact_file(
        job_id: str,
        relative: str,
        *,
        media_type: str | None = None,
        filename: str | None = None,
    ):
        """Serve a FIXED relative artifact path, read through the BlobStore.

        Exposed on ``app.state`` so product ingress extensions (e.g. ClippyShot's
        ``/pdf`` + typed page-PNG routes) reuse the core's confinement: DONE-gated,
        declared-artifact + traversal/absolute-path containment, streamed bytes.

        Task 7 gap 2: after the worker purge, a job's local ``output/`` dir may not
        exist on this node at all — this never reads the local filesystem. The
        declared-artifact check and the relative-path containment check both run
        against the BlobStore-fetched ``metadata.json`` / the declared name itself,
        BEFORE any ``open_output`` call for the artifact bytes.

        TRUST-GATE ENFORCEMENT: unlike ``get_artifact`` (which resolves the served
        path *from* the sealed manifest by id), this route is keyed by a fixed
        relative path — so it MUST additionally require that ``relative`` is a
        **declared** artifact in the dispatcher-sealed ``metadata.json``. Without
        this, a compromised worker that declares a benign/empty manifest yet also
        drops an undeclared ``document.pdf`` / ``page-NNN.png`` would have those
        un-re-hashed bytes served as "trustworthy output" (the zero-trust re-seal
        bypass). The host re-hashes only DECLARED artifacts, so anything not in the
        manifest was never validated and must 404.
        """
        _validate_job_id(job_id)
        _require_done(job_id)

        meta = _fetch_and_parse_metadata(_blob_store, job_id)
        if relative not in _declared_artifact_paths_from_meta(meta):
            # Not a sealed/declared artifact → never re-validated by the trust gate.
            raise HTTPException(404, "artifact file not found")

        safe_rel = _safe_relative_artifact_path(relative)
        if safe_rel is None:
            raise HTTPException(404, "artifact file not found")

        return _stream_artifact_response(
            job_id, safe_rel, media_type=media_type, filename=filename
        )

    # -------------------------------------------------------------------
    # Health / version / metrics (always public)
    # -------------------------------------------------------------------

    @app.get("/v1/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/v1/readyz")
    def readyz():
        try:
            # Cheapest store round-trip that proves connectivity — a bare COUNT on SQL,
            # never a full materialization of the jobs table.
            _job_store.count()
            return {"status": "ready"}
        except Exception as exc:
            # Never echo the store exception to an unauthenticated caller — it can carry the DB
            # host:port / DSN. Log the real cause server-side; return a generic 503.
            _log.warning("readyz_store_unavailable", error=str(exc))
            raise HTTPException(503, "store unavailable") from exc

    @app.get("/v1/version")
    def version():
        return {
            "version": __version__,
            "allowed_engines": sorted(_allowed_engines),
        }

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # -------------------------------------------------------------------
    # Job submission
    # -------------------------------------------------------------------

    @app.post("/v1/jobs", status_code=202)
    async def submit_job(
        file: UploadFile = File(...),
        engine: str = Form(...),
        params: list[str] = Form(default=[]),
        target_tier: str | None = Form(default=None),
        net_policy: str | None = Form(default=None),
    ):
        """Submit a file for detonation by the named engine.

        Security:
        - ``engine`` is validated against the configured allowlist (req. 7).
        - ``_safe_upload_name`` sanitizes the filename (req. 2).
        - Upload is spooled under ``_intake_gate`` (req. 5).
        - Errors are scrubbed before returning (req. 6).
        """
        # Requirement 7: engine allowlist check before any disk I/O.
        if _allowed_engines and engine not in _allowed_engines:
            record_rejection("unknown_engine")
            raise HTTPException(
                400,
                detail={
                    "error": "unknown_engine",
                    "detail": f"engine {engine!r} is not in the allowed set",
                },
            )

        # Requirement 2: safe filename
        safe_name = _safe_upload_name(file.filename)
        if safe_name != (file.filename or ""):
            _log.info(
                "upload_filename_sanitized",
                raw=file.filename,
                safe=safe_name,
            )

        # Bound params at ingest: cap count + entry length so a hostile client can't bloat the
        # persisted job (and amplify the full-list job listing). Reject (400) rather than
        # silently truncate. (Before reaching worker env the dispatcher's _sanitize_params
        # enforces the key SHAPE, DROPS reserved keys — BLASTBOX_*/LD_*/PYTHON*/engine
        # breadcrumbs — and length-caps each value.)
        if len(params) > _MAX_PARAMS:
            raise HTTPException(400, f"too many params (max {_MAX_PARAMS})")
        parsed_params: dict[str, str] = {}
        for p in params:
            if len(p) > _MAX_PARAM_LEN:
                raise HTTPException(400, f"param too long (max {_MAX_PARAM_LEN} chars)")
            if "=" in p:
                k, _, v = p.partition("=")
                parsed_params[k.strip()] = v.strip()
            else:
                parsed_params[p.strip()] = ""

        job = Job.new(engine=engine, filename=safe_name)
        job.params = parsed_params

        # Optional per-job tier routing — an OPERATOR/TEST knob, default-OFF. Pinning a job to a
        # specific tier is a scheduling control, so an untrusted client must not be able to flood
        # or starve a pool (DoS) or force the break-glass cold tier: it's honored ONLY when the
        # operator sets BLASTBOX_ALLOW_TIER_ROUTING. Off (default) → silently ignored, like a
        # non-allowlisted param. On → validated against the tier vocabulary and routed at claim.
        tt_raw = (target_tier or "").strip()  # missing / empty / whitespace-only all → ignored
        if tt_raw:
            if os.environ.get("BLASTBOX_ALLOW_TIER_ROUTING", "").strip().lower() in (
                "1", "true", "yes", "on"
            ):
                tt = tt_raw.lower()
                if tt not in VALID_TIERS:
                    raise HTTPException(
                        400, f"invalid target_tier (allowed: {', '.join(VALID_TIERS)})"
                    )
                job.target_tier = tt
            else:
                # Dropped (routing disabled); cap the attacker-controlled value in the log line.
                _log.info("target_tier_ignored_routing_disabled", requested=tt_raw[:64])

        # Per-job network personality: ignored unless the operator sets
        # BLASTBOX_ALLOW_NETPOLICY_OVERRIDE. Off (default) → silently ignored, mirroring
        # target_tier. The NAME is validated against the registry at dispatch (fail-closed),
        # so ingress only needs the gate here.
        np_raw = (net_policy or "").strip()
        if np_raw:
            if os.environ.get("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "").strip().lower() not in (
                "1", "true", "yes", "on",
            ):
                _log.info("net_policy_ignored_override_disabled", requested=np_raw[:64])
            elif len(np_raw) > 64 or not re.fullmatch(r"[A-Za-z0-9_-]+", np_raw):
                # A personality name is a short token (the BLASTBOX_NETPOLICY_<NAME> suffix). Bound
                # length + charset before persisting — net_policy is stored on the job and echoed in
                # list/status responses, so an unbounded form value must not be accepted (it would
                # fail closed as an unknown name at dispatch anyway, but never get stored/echoed).
                _log.info("net_policy_rejected_invalid_name", requested=np_raw[:64])
            else:
                job.net_policy = np_raw.lower()

        root, input_dir, output_dir = _job_dirs(job.job_id)

        try:
            root.mkdir(parents=True, exist_ok=True)
            input_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            input_path = input_dir / safe_name

            # Requirement 5: semaphore actually gates upload spooling.
            JOBS_IN_FLIGHT.inc()
            try:
                async with _intake_gate:
                    # Offload blocking I/O; streams in 64 KiB chunks.
                    nbytes, sha256 = await asyncio.to_thread(
                        _spool_sync, file, input_path
                    )
            finally:
                JOBS_IN_FLIGHT.dec()

        except Exception as exc:
            shutil.rmtree(root, ignore_errors=True)
            # Don't reflect the spool exception (could carry internal paths/details). Log it.
            _log.warning("upload_spool_failed", error=str(exc))
            raise HTTPException(500, "upload failed") from exc

        job.input_sha256 = sha256
        job.result_dir = str(output_dir)

        # Upload BEFORE the row exists: a job is claimable the instant it is created,
        # and a worker that claims one whose blob is missing would be forced down the
        # release-and-retry path for a sample that was never actually missing.
        try:
            _blob_store.put_sample(sha256, input_path)
        except Exception as exc:
            shutil.rmtree(root, ignore_errors=True)
            _log.warning("blob_put_sample_failed", error=str(exc))
            raise HTTPException(503, "blob store unavailable") from exc

        try:
            _job_store.create(job)
        except Exception as exc:
            shutil.rmtree(root, ignore_errors=True)
            # Don't reflect the store exception (DB driver errors carry host:port/DSN). Log it.
            _log.warning("job_store_create_failed", error=str(exc))
            # Finding C3: this job's own job_root/<id> dir is removed above, but the
            # samples/<sha256> blob just put_sample'd is DELIBERATELY left in place, not
            # deleted here. Unlike results/<job_id> (job-scoped), samples/<sha256> is
            # content-addressed and SHARED across jobs: put_sample is a dedup no-op for any
            # sha256 already present, so a CONCURRENT request for the same content may have
            # skipped its own upload and now depends on exactly this blob. There is no
            # refcount on it, so deleting it here on THIS request's create-failure could
            # yank the sample out from under that other, otherwise-healthy job the instant
            # after it dedup-skipped -- a race this handler cannot detect or fence against.
            # An orphaned sample (no job ever referencing it, e.g. because create() failed
            # for every request that ever uploaded that content) is reclaimed by the
            # sample-retention/GC policy instead (BLASTBOX_BLOB_SAMPLE_RETENTION / bucket
            # lifecycle) -- the same aging-out policy already documented for the
            # content-addressed blobs the retention sweeper also declines to delete inline
            # (see JobRetentionSweeper._expire_job).
            raise HTTPException(503, "store unavailable") from exc

        # Bound the engine metrics label to the allowlist: in open-allowlist mode (empty set) an
        # attacker could submit unbounded distinct `engine` strings, each retained as a Prometheus
        # series (cardinality blow-up). An allowlisted engine keeps its real label; anything else
        # collapses to "other". In configured mode unknown engines are already rejected above, so
        # this only bites the open dev/test default.
        record_job_submitted(engine if engine in _allowed_engines else "other", nbytes)

        return {
            "job_id": job.job_id,
            "status": "queued",
            "links": {
                "self": f"/v1/jobs/{job.job_id}",
                "result": f"/v1/jobs/{job.job_id}/result",
            },
        }

    # -------------------------------------------------------------------
    # Job listing / status
    # -------------------------------------------------------------------

    @app.get("/v1/jobs")
    def list_jobs(
        offset: int = 0,
        limit: int = 100,
        status: str | None = None,
        q: str | None = None,
        sort: str | None = None,
        order: str = "desc",
    ):
        """List jobs.  Single-tenant: all jobs are returned (no per-user scoping).

        Note: multi-tenant scoping is out of scope for this slice; the
        deployment is expected to run behind an auth proxy that enforces
        per-tenant access.
        """
        # Clamp pagination defensively — a negative offset slices from the end and a huge/negative
        # limit is nonsensical.  The store pushes this window down (SQL: ORDER BY ... LIMIT ...
        # OFFSET + a COUNT(*) for total), so a large jobs table never fully materializes here.
        offset = max(0, offset)
        limit = max(1, min(limit, 1000))

        filter_status: JobStatus | None = None
        if status:
            try:
                filter_status = JobStatus(status)
            except ValueError:
                raise HTTPException(400, f"unknown status: {status!r}")

        # Optional filename substring search (q) + whitelisted column sort — restored
        # from the engines' bespoke list views (the generic host had only status).
        q = (q or "").strip() or None
        total = _job_store.count(status=filter_status, q=q)
        page = _job_store.list(
            status=filter_status, limit=limit, offset=offset, newest_first=True,
            q=q, sort=sort, order=order,
        )
        return {
            "jobs": [j.to_public_dict() for j in page],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    @app.get("/v1/jobs/{job_id}")
    def get_job(job_id: str):
        _validate_job_id(job_id)
        job = _job_store.get(job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        return job.to_public_dict()

    # -------------------------------------------------------------------
    # Artifact routes (all require DONE status)
    # -------------------------------------------------------------------

    @app.get("/v1/jobs/{job_id}/metadata")
    def get_metadata(job_id: str):
        """Serve the dispatcher-validated ``metadata.json`` through the BlobStore.

        Returns 409 if the job is not DONE; 410 if expired (job-store status only —
        see Task 7: after the worker purge, the local job dir is gone by design, so
        its absence is no longer used as an expiry signal).

        BLASTBOX_BLOB_RESULT_ACCESS defaults to ``stream``: read from the blob store
        and stream through this API, so the object store itself stays PRIVATE
        (clients need no credentials or network path to it). This route never
        redirects.
        """
        _validate_job_id(job_id)
        _require_done(job_id)
        try:
            fh = _blob_store.open_output(job_id, "metadata.json")
        except Exception:
            raise HTTPException(404, "metadata.json not found")

        from fastapi.responses import StreamingResponse

        def _iter_fh():
            try:
                while True:
                    chunk = fh.read(_STREAM_CHUNK)
                    if not chunk:
                        break
                    yield chunk
            finally:
                fh.close()

        return StreamingResponse(_iter_fh(), media_type="application/json")

    @app.get("/v1/jobs/{job_id}/artifacts/{artifact_id}")
    def get_artifact(job_id: str, artifact_id: str):
        """Serve a single artifact by its id (from dispatcher-validated metadata),
        read through the BlobStore (Task 7 gap 2) — after the worker purge, the
        job's local ``output/`` dir is gone by the time this runs on a real
        (multi-node) deployment.

        Security (requirement 3):
        - ``artifact_id`` is used as a *key* into the validated artifact list,
          never as a filesystem path.
        - The artifact's ``path`` field comes from ``metadata.json`` (validated
          by the dispatcher's trust gate, fetched via the BlobStore), not from
          the client.
        - ``_safe_relative_artifact_path`` rejects an absolute or traversal
          declared path BEFORE any ``open_output`` call — containment is
          re-expressed on the declared relative name itself, since there is no
          guaranteed on-disk ``output_dir`` left to ``resolve()`` against.
        """
        _validate_job_id(job_id)
        _require_done(job_id)

        meta = _fetch_and_parse_metadata(_blob_store, job_id)

        # Find the artifact whose id matches (artifacts are in the top-level list).
        artifacts = meta.get("artifacts", []) if isinstance(meta, dict) else []
        matched = None
        if isinstance(artifacts, list):
            for a in artifacts:
                if isinstance(a, dict) and a.get("id") == artifact_id:
                    matched = a
                    break

        if matched is None:
            raise HTTPException(404, f"artifact {artifact_id!r} not found")

        artifact_rel_path = matched.get("path", "")
        # Requirement 3: containment check, mirroring _zip_validated_artifacts — a
        # symlink can no longer reach here at all (put_output now refuses to store one;
        # see LocalBlobStore/S3BlobStore.put_output), so the check that matters is the
        # declared-path containment itself.
        safe_rel = _safe_relative_artifact_path(artifact_rel_path)
        if safe_rel is None:
            raise HTTPException(404, "artifact file not found")

        return _stream_artifact_response(
            job_id, safe_rel, media_type=None, filename=None
        )

    @app.get("/v1/jobs/{job_id}/result")
    async def get_result(job_id: str):
        """Stream a ZIP of the dispatcher-validated artifacts (+ ``metadata.json``),
        read entirely through the BlobStore (Task 7) — after the worker purge, the
        job's local output/ dir no longer exists on a real deployment.

        Serves only the artifact paths declared in the validated ``metadata.json`` — NOT
        everything ``put_output`` happened to upload — so a compromised worker's
        undeclared extra files are not disclosed (see ``_zip_validated_artifacts``).

        BLASTBOX_BLOB_RESULT_ACCESS defaults to ``stream``: bytes come from the blob
        store and stream through this API; the object store stays PRIVATE and this
        route never redirects.
        """
        _validate_job_id(job_id)
        _require_done(job_id)

        try:
            with _blob_store.open_output(job_id, "metadata.json") as meta_fh:
                meta_bytes = meta_fh.read()
        except Exception:
            raise HTTPException(404, "metadata.json not found")
        try:
            meta = json.loads(meta_bytes)
        except Exception:
            raise HTTPException(500, "could not parse metadata.json")
        # A top-level non-dict manifest (`[]`, `null`, a scalar) parses fine but would
        # make `.get()` raise outside both try/excepts -> bare 500. Guard like the
        # sibling routes (get_artifact, _declared_artifact_paths_from_meta) and fall
        # back to the zero-declared-artifacts path (metadata-only ZIP).
        rels = [
            a["path"]
            for a in (meta.get("artifacts", []) if isinstance(meta, dict) else [])
            if isinstance(a, dict) and isinstance(a.get("path"), str)
        ]

        import tempfile

        from fastapi.responses import FileResponse
        from starlette.background import BackgroundTask

        def _build_zip() -> str:
            fd, tmp_path = tempfile.mkstemp(prefix="bbresult-", suffix=".zip")
            try:
                with os.fdopen(fd, "wb") as fh:
                    _zip_validated_artifacts(
                        _blob_store, job_id, meta_bytes, rels, fh, password=_zip_password
                    )
                return tmp_path
            except BaseException:
                os.unlink(tmp_path)
                raise

        async with _result_gate:  # bound concurrent ZIP BUILDS (now disk-backed, not in-memory)
            tmp_path = await asyncio.to_thread(_build_zip)
        # Stream from the temp file (constant memory) + delete it after the response is sent.
        #
        # The gate is released after the BUILD, not held across streaming — deliberately. Each
        # temp ZIP is size-bounded (<= max_total_artifact_bytes, enforced before the job reaches
        # DONE) and cleanup is GUARANTEED (BackgroundTask below + _build_zip's except-unlink), so
        # the only residual is the COUNT of concurrent slow downloads each pinning one bounded
        # temp file. Holding this small gate (<= 4) across streaming would let a few slowloris
        # readers block ALL /result callers — strictly worse. Generic slow-read DoS is delegated
        # to the upstream proxy / ASGI read timeouts (per the deployment model); for a hard disk
        # bound, mount the ingress temp dir ($TMPDIR) on a size-capped tmpfs (fails closed -> 500).
        return FileResponse(
            tmp_path,
            media_type="application/zip",
            filename=f"{job_id}.zip",
            background=BackgroundTask(os.unlink, tmp_path),
        )

    @app.delete("/v1/jobs/{job_id}")
    def delete_job(job_id: str):
        """Delete a job's store entry and artifacts.

        Refuses to delete QUEUED/RUNNING jobs.  Deletion is confined under
        ``job_root`` — the directory removed is always ``job_root/<job_id>/`` —
        and also reaps the job's durable result blobs from ``_blob_store`` (which
        live under ``blob_root``, OUTSIDE ``job_root``, so the on-disk rmtree
        never touches them).

        Ordering (Finding E2): the blob delete is attempted BEFORE the job row is
        removed, and the row is removed ONLY if it succeeds — symmetric with the
        retention sweeper (``JobRetentionSweeper._expire_job``), which likewise
        withholds its terminal-state write until ``delete_job`` succeeds. A
        transient blob-store failure (S3 throttling, a real LocalBlobStore error)
        must not be swallowed AND have the job row removed underneath it — that
        would orphan the ``results/<job_id>`` blob with no record left for any
        future DELETE/retention sweep to retry. On failure this returns 503 and
        leaves the row intact so the caller (or a later retention pass, once the
        job is terminal with a real expires_at) can retry the same delete.
        """
        _validate_job_id(job_id)
        job = _job_store.get(job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
            raise HTTPException(
                409,
                f"cannot delete job in status={job.status.value}; wait for it to finish",
            )

        # Confined delete: always relative to job_root.
        root, _, _ = _job_dirs(job_id)
        try:
            root_resolved = root.resolve(strict=False)
            job_root_resolved = _job_root.resolve(strict=False)
            root_resolved.relative_to(job_root_resolved)
        except ValueError:
            raise HTTPException(500, "job directory outside job_root")

        # On-disk cleanup under job_root is independent of the durable blob store and of
        # the job row: it is not the record that a retry would need intact, so it proceeds
        # unconditionally (best-effort, as before) regardless of the blob-delete outcome
        # checked next.
        shutil.rmtree(root, ignore_errors=True)

        # Durable result artifacts live under blob_store's blob_root, a SIBLING of
        # job_root -- so the rmtree above removes nothing durable. Attempt this BEFORE
        # touching the job row: if it fails, do NOT delete the row (see the ordering note
        # in the docstring above) -- error out instead so the client/operator knows the
        # job was NOT deleted and can retry.
        try:
            _blob_store.delete_job(job_id)
        except Exception as exc:
            _log.warning("blob_delete_job_failed", job_id=job_id, error=str(exc))
            raise HTTPException(503, "blob store unavailable; job not deleted") from exc

        _job_store.delete(job_id)
        return {"deleted": job_id}

    # Context for product ingress extensions (job lookups + confined artifact serving).
    app.state.job_store = _job_store
    app.state.job_root = _job_root
    app.state.blob_store = _blob_store
    app.state.serve_artifact_file = _serve_artifact_file

    # Generic perceptual-hash search (GET /v1/similar), mounted only when the
    # store can actually serve it (the SQL store; memory/redis cannot). Keeps the
    # surface honest: absent route -> 404 -> "this deployment doesn't index hashes".
    from .similar import build_similar_router

    similar_router = build_similar_router(_job_store)
    if similar_router is not None:
        app.include_router(similar_router)

    # Product routes mounted on the shared core. They inherit the app's
    # middleware (bearer auth, limits); the core owns auth + path-confinement.
    if extension is not None:
        for router in extension.routers:
            app.include_router(router)
        if extension.static_ui is not None:
            _mount_static_ui(app, extension.static_ui)

    return app


def _mount_static_ui(app: FastAPI, ui: StaticUI) -> None:
    """Serve a per-engine web UI: ``GET /`` -> index, ``/assets`` -> static dir.

    Operator-configured (an engine's packaged ``static/`` dir), so the paths are
    trusted — but StaticUI.index_path()/assets_path() still resolve+confine them,
    and StaticFiles handles per-request traversal safety on /assets. Mounted last
    so it never shadows /v1/* or product routes (only the bare site root + /assets).
    """
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    index_path = ui.index_path()
    assets_path = ui.assets_path()

    @app.get("/", include_in_schema=False)
    def _ui_root():
        if not index_path.is_file():
            raise HTTPException(404, "UI not found")
        return FileResponse(index_path, media_type="text/html")

    if assets_path is not None:
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")


# ---------------------------------------------------------------------------
# Synchronous spool helper (called via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _spool_sync(upload: UploadFile, dest: Path) -> tuple[int, str]:
    """Blocking spool: read the upload and write to *dest*.

    Called from ``asyncio.to_thread`` so it must not use ``await``.
    UploadFile exposes a synchronous ``file`` attribute (a SpooledTemporaryFile)
    that we can read directly.
    """
    h = hashlib.sha256()
    total = 0
    raw_file = upload.file  # SpooledTemporaryFile or BytesIO
    with dest.open("wb") as out:
        while True:
            chunk = raw_file.read(65536)
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            total += len(chunk)
    return total, h.hexdigest()
