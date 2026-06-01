# Worker SDK — Service Lifecycle (Warm Protocol) Slice

**Goal:** `blastbox.worker.warm` — let a worker run in **warm mode**: boot, call `engine.warmup()` in
a pristine (no-input) context, signal READY, block until the host hands it one job, process that single
job through the same harness/trust path, signal DONE, and exit. This is the "pre-pay startup, still
one-untrusted-doc-per-disposable-slot" capability the warm pool (later) and warm-engine modes
(e.g. soffice UNO listener) build on. **Warm ≠ reuse** — a warm slot processes exactly one job then dies.

**Architecture:** A `WarmControl` abstraction (the host↔warm-worker handshake) — injectable so the
whole loop is unit-testable with no real container — plus `serve_warm(engine, ...)`. A file-based
`FileWarmControl` is the concrete container-friendly impl (ready/go/done files + a `job.json`). The
warm worker's output is validated by the host trust gate identically to the cold path (the round-trip
already proven for `run_detonation` applies unchanged).

**Tech Stack:** Python 3.12+, stdlib, the merged `blastbox.worker.harness`/`contract`/`limits`, pytest.

## File structure
- `src/blastbox/worker/warm.py` — `WarmControl` protocol, `WarmJobSpec`, `FileWarmControl`, `serve_warm`
- `tests/worker/test_warm.py`

## Public API
```python
@dataclass(frozen=True)
class WarmJobSpec:
    input_path: Path
    output_dir: Path
    params: dict[str, str] = field(default_factory=dict)

class WarmControl(Protocol):
    def signal_ready(self) -> None: ...
    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec: ...   # raises WarmTimeout if no job arrives
    def signal_done(self, *, status: str) -> None: ...

class WarmTimeout(BlastboxError): ...   # from blastbox.errors

class FileWarmControl:                   # container-friendly file handshake
    def __init__(self, control_dir: Path): ...
    # signal_ready -> writes control_dir/ready
    # wait_for_go  -> polls control_dir/go.json (input/output/params) until present or timeout
    # signal_done  -> writes control_dir/done with the status

def serve_warm(engine: Engine, *, control: WarmControl, limits: Limits,
               idle_timeout_s: float = 600.0) -> int:
    """Warm worker lifecycle: warmup() → READY → wait one job → run_detonation → DONE → exit."""
```

## `serve_warm` flow
1. If `engine` has `warmup`, call it. This runs **before any input exists** — whatever it produces
   (a booted soffice UNO listener, a loaded JVM) is safe to capture/keep. On warmup failure → signal
   DONE(status="warmup_error") and exit non-zero (the slot is unusable; the pool reaps it).
2. `control.signal_ready()` — the host now knows this slot can take a job.
3. `spec = control.wait_for_go(timeout_s=idle_timeout_s)`. On `WarmTimeout` (no job arrived within the
   idle window) → signal DONE(status="idle_timeout") and exit 0 (the slot self-retires; the pool
   replaces it). The idle self-timeout prevents a stuck slot lingering forever.
4. `rc = run_detonation(engine, input_path=spec.input_path, output_dir=spec.output_dir, limits=limits)`
   — the EXACT cold-path harness call, so the output is host-trust-validatable identically.
   (Wrap in try/except: any harness-internal failure → still signal DONE so the host isn't left waiting.)
5. `control.signal_done(status="ok")` and return `rc`. **Exit after one job — never loop for a second.**

## FileWarmControl protocol (the concrete handshake)
- `signal_ready()` → atomically write `control_dir/ready` (e.g. write a temp + rename).
- `wait_for_go(timeout_s)` → poll for `control_dir/go.json` every ~50ms up to `timeout_s`; when present,
  parse it (`{"input_path","output_dir","params"}`), validate `input_path`/`output_dir` are absolute and
  exist, and return the `WarmJobSpec`. Raise `WarmTimeout` past the deadline. (Path validation here is a
  light sanity check; the host controls these paths — it staged the input into the slot.)
- `signal_done(status)` → atomically write `control_dir/done` containing the status.

## Security / correctness notes (review will check)
- **One job only**: `serve_warm` must process exactly one `wait_for_go` result then exit. No loop.
  A test asserts a second job is NOT picked up (the function returns after the first).
- **warmup is pre-input**: `warmup()` is called before `signal_ready`/`wait_for_go`, so no untrusted
  input is present when the warm state is captured (no contamination of the captured state).
- The job's output still flows through `run_detonation` → host `validate_worker_output` unchanged
  (re-seal from disk, input-SHA, caps) — warm mode changes *when startup is paid*, not the trust model.
- `FileWarmControl` writes are atomic (temp+rename) so the host never reads a half-written signal.

## Tests (TDD)
Use a `_FakeControl` recording calls + returning a preset `WarmJobSpec`, and the `_NoopEngine`/a
`_WarmEngine` double (records `warmup()` called).
1. happy: `serve_warm(warm_engine, control=fake_with_go, ...)` → `warmup()` called BEFORE `signal_ready`;
   `signal_ready` then `wait_for_go` then `signal_done(status="ok")`; output dir has a metadata.json;
   feed it to `host.trust.validate_worker_output` → accepted; returns 0.
2. **one-job-only**: the fake control's `wait_for_go` would return a second spec if called twice; assert
   `serve_warm` calls it exactly once (processes one job then exits).
3. warmup failure: a `warmup` that raises → `signal_done(status="warmup_error")`, non-zero return, no job processed.
4. idle timeout: a control whose `wait_for_go` raises `WarmTimeout` → `signal_done(status="idle_timeout")`, returns 0.
5. `FileWarmControl` round-trip: in a tmp control_dir — `signal_ready` creates `ready`; a writer drops
   `go.json` (with a real staged input + output dir) → `wait_for_go` returns the spec; `signal_done`
   writes `done`. Also: `wait_for_go` with no `go.json` and a tiny timeout → `WarmTimeout`. Atomic-write
   check: `ready`/`done` never observed half-written (write via temp+rename).

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. host + worker harness/sandbox + contract), mypy + ruff clean. Don't push.
