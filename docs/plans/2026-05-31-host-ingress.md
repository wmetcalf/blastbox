# Host Orchestrator — Ingress (HTTP API + CLI) + Observability Slice

**Goal:** `blastbox.host.ingress` (FastAPI job API) + `blastbox.host.cli` (`serve`/`dispatch`/`version`)
+ `blastbox.observability` (structlog + prometheus). Completes the host orchestrator: a client can
submit an untrusted document for an engine, poll status, and fetch the validated artifacts. Async-only
— upload enqueues a `Job`; the (separately-running) `Dispatcher` does the work.

**Architecture:** `build_app(...)` returns a FastAPI app wired to a `JobStore`, a `job_root`, an engine
allowlist, and `Limits`. Uploads spool to `job_root/<id>/input/<safe_name>`, create a `Job`, return
202. Artifacts are served **by id from the dispatcher-validated `metadata.json`**, path-confined —
never by client-supplied path. No inline conversion (that's the dispatcher). Optional bearer auth is
**off by default** (proxy-fronted — see project memory) with a startup warning.

**Tech Stack:** Python 3.12+, FastAPI, uvicorn, python-multipart, structlog, prometheus-client, pytest + httpx (dev).

**Reference (port + generalize the just-hardened code):**
- `/home/coz/Downloads/ClippyShot/src/clippyshot/api.py` — the async `/v1/jobs` path, the
  `BodySizeLimitMiddleware` (413 before spool), `BearerAuthMiddleware`, `_safe_upload_name`,
  `_safe_artifact_path`, the `_convert_gate` concurrency semaphore, error scrubbing. Drop the
  engine-specific bits (the sync `/v1/convert`, scanner params, the converter) — ingress only enqueues.
- `/home/coz/Downloads/ClippyShot/src/clippyshot/cli.py` and `observability/{logging,metrics}.py`.

## File structure
- `src/blastbox/host/ingress/__init__.py`, `app.py` (build_app + routes), `middleware.py` (body-size + bearer)
- `src/blastbox/host/cli.py`
- `src/blastbox/observability/__init__.py`, `logging.py`, `metrics.py`
- `tests/host/ingress/test_app.py`, `tests/host/test_cli.py`, `tests/test_observability.py`

Add `fastapi>=0.110`, `uvicorn[standard]>=0.27`, `python-multipart>=0.0.9`, `structlog>=24.1`,
`prometheus-client>=0.20` to deps; `httpx>=0.27` to the dev extra.

## Routes (all under the optional bearer gate except healthz/version)
- `POST /v1/jobs` (multipart: `file`, form `engine`, optional form `params` as `k=v` pairs or json):
  reject `engine` not in the configured allowlist (400); `_safe_upload_name(file.filename)`; spool to
  `input/<safe>` under an `await asyncio.to_thread`-offloaded write, bounded by `_intake_gate`
  (semaphore sized `BLASTBOX_API_WORKERS`); compute `input_sha256` while streaming; `Job.new(engine=,
  filename=)` + `input_sha256` + filtered `params`; `result_dir = output/`; `job_store.create`;
  return **202** `{job_id, status:"queued", links:{self, result}}`.
- `GET /v1/jobs` (offset/limit/status filter) → `{jobs:[to_public_dict...], ...}` scoped per the
  deployment (single-tenant behind the proxy — no per-tenant scoping in this slice; document it).
- `GET /v1/jobs/{id}` → `to_public_dict` or 404.
- `GET /v1/jobs/{id}/metadata` → the validated `output/metadata.json` when status DONE (regular-file
  gated); 409 if not done, 410 if expired.
- `GET /v1/jobs/{id}/artifacts/{artifact_id}` → read `output/metadata.json`, find the artifact whose
  `id == artifact_id`, serve `output/<artifact.path>` via a containment-checked `_safe_artifact_path`
  (resolve + `relative_to(output_dir)`); 404 if id unknown; never serve a client-supplied path.
- `GET /v1/jobs/{id}/result` → zip of `output/` artifacts, built via `await asyncio.to_thread`, streamed.
- `DELETE /v1/jobs/{id}` → safe-delete the job dir (confined under job_root) + store delete.
- `GET /v1/healthz` (200), `GET /v1/readyz` (store reachable), `GET /metrics` (prometheus), `GET /v1/version`.

## Security requirements (review WILL probe)
1. **413 before spooling** — `BodySizeLimitMiddleware` rejects on Content-Length over `max_input_bytes`
   AND mid-stream for chunked uploads, before the body hits disk.
2. **Filename sanitization** — `_safe_upload_name` → `[A-Za-z0-9._-]+`, basename only, empty/hidden →
   `upload.bin`; path traversal via filename impossible.
3. **Artifact serving is path-confined and id-based** — `{artifact_id}` indexes the validated
   metadata; the served path is `output/<artifact.path>` resolved and confirmed under `output_dir`.
   A crafted `artifact_id` / `job_id` (`../`, absolute, urlencoded) cannot read outside the job's output.
   `job_id` is only ever a dict key / path component validated as a uuid.
4. **Optional auth, off by default** — bearer middleware installed only if `BLASTBOX_API_KEY` set;
   else a loud `api_auth_disabled` warning (proxy-fronted by design). `compare_digest`.
5. **Concurrency gate** — `BLASTBOX_API_WORKERS` (parsed, clamped, and ACTUALLY WIRED) bounds
   concurrent upload spooling.
6. **Error scrubbing** — `sanitize_public_error` on any detail returned to clients; no stack traces.
7. **Engine allowlist** — `engine` must be in the configured set; can't enqueue for an unknown engine.

## CLI (`blastbox <cmd>`)
- `serve [--host --port]` → uvicorn the app (build_app from env). `dispatch [--poll-interval]` → run a
  `Dispatcher.run_forever` (engines from config/env). `version`. argparse; map errors to exit codes.

## Observability
- `logging.py`: `configure_logging(format_="json"|"text")` (structlog → stderr; JSON default).
- `metrics.py`: counters/gauges — `blastbox_jobs_submitted_total{engine}`, `blastbox_jobs_in_flight`,
  `blastbox_rejections_total{reason}`, `blastbox_input_bytes` histogram. `generate_latest()` for /metrics.

## Tests (TDD, FastAPI TestClient + InMemoryJobStore + a temp job_root)
- POST creates a queued job (202, job_id), spools input, sets input_sha256; unknown engine → 400;
  oversized body → 413 (no file written); filename `../../etc/passwd` → stored basename only.
- GET status/list/404; metadata/artifacts 409 when not done; after manually marking a job DONE with a
  hand-written valid `output/metadata.json` + artifact files: metadata served; artifact-by-id served;
  unknown artifact_id → 404; `artifact_id`/`job_id` traversal → confined (no escape).
- auth: no key → open + warning; key set → 401 without/with bad token, 200 with good token; healthz open.
- concurrency gate wired (semaphore value from env); delete confined to job_root; error bodies scrubbed.
- CLI: `version` prints; `serve`/`dispatch` argparse wiring (don't actually bind a port in the test —
  test the arg parsing + that the right object is constructed via a seam).
- observability: configure_logging emits JSON to stderr; metrics increment + render.

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. contract/jobs/trust/runtime/dispatch), mypy + ruff clean. Don't push.
