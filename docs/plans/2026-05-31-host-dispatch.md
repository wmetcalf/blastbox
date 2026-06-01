# Host Orchestrator — Dispatcher Slice (the integration loop)

**Goal:** `blastbox.host.dispatch` — claim a queued job, launch one disposable worker container for
it, validate the worker's output through the trust gate, record the result, and delete the malicious
input. The piece that ties `jobs` + `trust` + `runtime` together.

**Architecture:** A `Dispatcher` constructed with a `JobStore`, an engine registry, `Limits`, and a
job-root path, plus *injectable* `runtime_selector` and `subprocess_runner` so the whole loop is
unit-testable with no Docker daemon. One job → one fresh container → validate → terminal status →
input deleted. No warm pool (later slice); cold per-job only.

**Tech Stack:** Python 3.12+, stdlib `subprocess`, the merged `blastbox.host.{jobs,trust,runtime}`,
`blastbox.limits`/`errors`, pytest.

**Reference (port + generalize):** `/home/coz/Downloads/ClippyShot/src/clippyshot/dispatcher.py`
(claim/launch/timeout/cleanup/orphan-reap loop) — but integrate the *framework's* `trust.validate_worker_output`,
`runtime.select_worker_runtime`/`build_worker_docker_run_argv`, and the generic `Job`. RedTusk's
`dispatcher.py` is a secondary reference for the orphan-reap + result handling.

## File structure
- `src/blastbox/host/dispatch.py`
- `tests/host/test_dispatch.py`

## Public API
```python
@dataclass(frozen=True)
class EngineSpec:
    name: str
    image: str                 # worker container image for this engine (operator-configured)
    worker_argv: list[str]     # command run inside the container (the worker SDK entrypoint)

class Dispatcher:
    def __init__(self, *, job_store: JobStore, engines: Mapping[str, EngineSpec], limits: Limits,
                 job_root: Path, runtime_selector=select_worker_runtime,
                 subprocess_runner=subprocess.run, worker_timeout_s: int = 300,
                 job_retention_seconds: int = 0): ...
    def dispatch_once(self) -> bool:           # claim+dispatch one job; False if none queued
    def run_forever(self, *, poll_interval_s: float = 1.0, stop: Callable[[], bool] | None = None): ...
    def requeue_orphaned_jobs(self) -> int: ...
```

## `_dispatch_claimed_job(job)` flow (each failure path is terminal + deletes input)
1. Resolve dirs: `root = job_root/<job_id>`, `input_dir = root/input`, `output_dir = root/output`,
   `input_path = input_dir/<job.filename>`. (ingress created these + placed the input; the dispatcher
   does not create the input.)
2. **Engine lookup:** `engine = engines.get(job.engine)`; unknown → fail job ("unknown engine"),
   delete input, return. The image comes from `engine.image` — **never from any job field.**
3. **Runtime:** `runtime = runtime_selector()`; on `InsecureRuntimeRefused`/any exc → fail job, delete
   input, return. Update job: status RUNNING, `worker_runtime`, merge `security_warnings` from runtime.
4. **Build + launch:** `argv = build_worker_docker_run_argv(image=engine.image, input_path,
   input_mount_path, output_dir, output_mount_path, worker_argv=engine.worker_argv, runtime,
   container_name=<derived from job_id>, labels={"blastbox.role":"worker","blastbox.job_id":job_id},
   extra_env=<scan/engine params from job.params, validated keys only>)`. Run via `subprocess_runner`
   with `timeout=worker_timeout_s`. On `TimeoutExpired` → `docker kill <container_name>` (best-effort),
   fail job ("worker timed out"), delete input, return. On other exc → fail job, delete input, return.
5. **Validate output (trust):** `env = validate_worker_output(output_dir=output_dir,
   input_sha256=job.input_sha256, engine=job.engine, limits=limits)`. On `OutputTrustError` → fail job
   (scrubbed message), delete input, return. On non-zero worker exit *and* no valid output → fail.
6. **Success:** update job DONE, `finished_at`, `expires_at` (if retention>0), and a small
   `result_summary` derived from the validated envelope (e.g. `{"status": env.status,
   "artifact_count": len(env.artifacts), "warning_count": len(env.warnings)}` — NOT the whole tree).
   Delete input.

**Input deletion is unconditional on every terminal path** (success, failure, timeout, launch error,
unknown engine, insecure runtime). Use a `finally`-style guarantee. Delete only the input file +
its `input/` dir; never touch `output/`.

## `requeue_orphaned_jobs()`
List RUNNING jobs; for any whose worker container is not currently alive (via an injected
`list_active_worker_job_ids()` backed by `docker ps --filter label=blastbox.role=worker`), set back to
QUEUED with a warning. On `docker ps` failure, no-op (don't requeue live jobs). Exclude jobs claimed
in-process this tick (pass an `exclude` set).

## Security requirements (review WILL probe)
- The worker **image and runtime are never derived from job data** — image from `engine.image`,
  runtime from `runtime_selector`. A malicious `job.engine`/`job.filename`/`job.params` cannot select
  an arbitrary image or add a docker flag (argv is the runtime builder's list).
- Output is **validated through `trust.validate_worker_output` before the job is marked DONE** — a
  worker that writes a traversal/oversized/tampered metadata.json yields FAILED, not DONE.
- **Input deleted on every terminal path.**
- `job.params` → `extra_env` only for a **validated key allowlist** (keys matching
  `[A-Z][A-Z0-9_]*`, values length-capped); never raw.
- All error strings stored on the job pass through `sanitize_public_error`.

## Tests (TDD; inject a fake `subprocess_runner` that writes a valid/invalid output dir + returns a fake CompletedProcess, and a fake `runtime_selector`)
1. `dispatch_once` with empty store → False.
2. Happy path: queued job + fake runner writes a valid output dir (real artifacts + matching
   metadata.json built via the contract) + exit 0 → job DONE, `result_summary` set, input file gone.
3. Worker non-zero exit (no valid output) → job FAILED, input gone.
4. Worker `TimeoutExpired` → a `docker kill` invocation happened (assert via the injected runner), job
   FAILED ("timed out"), input gone.
5. Output fails trust (fake runner writes metadata with a traversal artifact path) → job FAILED, input gone.
6. Unknown `job.engine` → job FAILED, input gone, no subprocess launched.
7. `runtime_selector` raises `InsecureRuntimeRefused` → job FAILED, input gone.
8. Image used in the launched argv equals `engine.image`, NOT any job field (set `job.filename` to a
   bogus image-like string and assert it's not the `--`... image position).
9. `requeue_orphaned_jobs`: a RUNNING job not in the active set → back to QUEUED + warning; a RUNNING
   job still active → untouched; `docker ps` failure → no requeue.
10. `job.params` with a bad key (`"x; --privileged"`) is dropped from `extra_env`; a good key passes.
11. Error strings on FAILED jobs are scrubbed of filesystem paths.

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. contract/jobs/trust/runtime), mypy + ruff clean. Don't push.
