# Host Orchestrator — Dispatcher Warm-Mode Integration Slice

**Goal:** wire the `WarmPool` + the warm protocol into the `Dispatcher` so a claimed job is handed to
a pre-warmed slot (stage input → signal go → wait done → validate → release) instead of cold-launching
a fresh container. Completes the warm path end-to-end. Cold path stays the default/fallback.

**Architecture:** add an optional `pool: WarmPool` to the `Dispatcher`. When present, `_dispatch_claimed_job`
takes the WARM path; when absent (or no slot is available within a short grace), it falls back to the
existing COLD path. A host-side warm control (`HostWarmControl`) is the counterpart to the worker's
`FileWarmControl`: it writes `go.json` and waits for `done`. The trust model is unchanged — the warm
slot's output flows through `validate_worker_output` exactly like cold. Input is deleted on every
terminal path, identically.

**Tech Stack:** Python 3.12+, stdlib, the merged `host.{dispatch,pool,trust}` + `worker.warm`, pytest.

## File structure
- `src/blastbox/worker/warm.py` — ADD `HostWarmControl` (host side: `signal_go`, `wait_for_done`).
- `src/blastbox/host/dispatch.py` — ADD the warm path + the optional `pool` param.
- `tests/host/test_dispatch_warm.py`

## HostWarmControl (host side of the handshake)
```python
class HostWarmControl:
    def __init__(self, control_dir: Path): ...
    def signal_go(self, spec: WarmJobSpec) -> None:   # atomically write control_dir/go.json
    def wait_for_done(self, *, timeout_s: float) -> str:  # poll control_dir/done; return status; raise WarmTimeout
```
Atomic writes (temp+rename); `wait_for_done` polls ~50ms. Symmetric with the worker's `FileWarmControl`.

## Dispatcher changes
`Dispatcher.__init__` gains `pool: WarmPool | None = None` and `warm_claim_timeout_s: float = 2.0`.
`_dispatch_claimed_job(job)`:
- If `self._pool is not None`: try `slot = self._pool.claim(timeout_s=warm_claim_timeout_s)`.
  - **slot obtained → WARM path** (below).
  - **no slot (None) → fall back to the existing COLD path** (don't fail the job; log a warm_pool_miss).
- Else → COLD path (unchanged).

### WARM path
1. Resolve dirs as today; the slot already has `input_dir`/`output_dir`/`control_dir` (pool-managed).
   Stage the job's input INTO `slot.input_dir` (copy/hardlink the staged input file → `slot.input_dir/<filename>`).
2. Update job RUNNING + `worker_runtime="warm"`.
3. `HostWarmControl(slot.control_dir).signal_go(WarmJobSpec(input_path=<staged>, output_dir=slot.output_dir,
   params=<sanitized job.params>))`.
4. `status = control.wait_for_done(timeout_s=self._worker_timeout_s)`. On `WarmTimeout` → fail job
   ("warm worker timed out"), and STILL `pool.release(slot)` + delete input + return.
5. `env = validate_worker_output(output_dir=slot.output_dir, input_sha256=job.input_sha256,
   engine=job.engine, limits=limits)`. On `OutputTrustError` → fail job. On success → DONE + result_summary.
6. **finally**: `pool.release(slot)` (reap+replace — the slot is one-job-then-destroyed) AND delete the
   job's input (both the staged copy and the slot copy). Input deletion + slot release happen on EVERY
   terminal path (success, timeout, trust failure, unexpected error).

The existing security guarantees are preserved: image/runtime are the pool's (engine-configured),
NEVER job-derived; output validated before DONE; input deleted on every path; `job.params` allowlisted;
errors scrubbed. The slot is released-and-reaped after exactly one job (warm ≠ reuse).

## Tests (TDD; fake `WarmPool` returning a fake `Slot`, and a fake "worker" thread/inline that, on
seeing `go.json`, writes a valid output dir + `done` — mirror the cold-path dispatcher test fixtures)
1. warm happy path: pool returns a slot; the fake worker writes valid output + done → job DONE,
   result_summary set, `pool.release(slot)` called once, input gone (staged + slot copies).
2. warm output fails trust (worker writes a traversal artifact) → job FAILED, slot released, input gone.
3. warm worker never signals done within timeout → `WarmTimeout` → job FAILED ("timed out"), slot
   released, input gone.
4. **fallback**: `pool.claim` returns None → the COLD path runs (assert a cold container launch
   happened via the injected subprocess_runner), job processed, NOT failed.
5. slot released on EVERY path (happy, trust-fail, timeout) — assert `release` called exactly once each.
6. image/runtime never job-derived in warm mode (the pool owns the slot's container); a malicious
   `job.engine`/`filename` doesn't change which slot/engine runs.
7. `HostWarmControl` round-trip with the worker `FileWarmControl`: host `signal_go` → worker
   `wait_for_go` returns the spec; worker `signal_done("ok")` → host `wait_for_done` returns "ok";
   host `wait_for_done` with no `done` + tiny timeout → `WarmTimeout`.

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. all prior — no regression), mypy + ruff clean. Don't push.
