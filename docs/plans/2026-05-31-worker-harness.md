# Worker SDK — Engine Seam + Harness Slice

**Goal:** `blastbox.worker` — the `Engine` protocol (the single function each project implements) and
the harness that runs *inside* the disposable worker: read the input, call `engine.detonate()`, seal
the result into the contract `Envelope`, and write the `metadata.json` the host re-validates. The
keystone of Layer 2.

**Architecture:** The engine returns an ergonomic `DetonationResult` (a typed payload + *declared*
artifacts it wrote, plus detection/warnings/status). The harness computes `input_sha256`, calls the
engine, **seals the result via the contract** (recomputing hashes/sizes from disk, confining paths,
resolving refs — the same `seal_envelope` the host uses), and writes `metadata.json`. The loop closes:
a harness-written `metadata.json` is accepted verbatim by `host.trust.validate_worker_output`. No
sandbox here (that's the next slice — the sandbox is what the *engine* uses internally).

**Tech Stack:** Python 3.12+, the merged `blastbox.contract`, `blastbox.limits`, pytest.

## File structure
- `src/blastbox/worker/__init__.py` — exports
- `src/blastbox/worker/engine.py` — `Engine` protocol, `DetonationResult`
- `src/blastbox/worker/harness.py` — `run_detonation`, `main`
- `tests/worker/test_harness.py`, `tests/worker/test_roundtrip.py`

## Public API

```python
# engine.py
@dataclass
class DetonationResult:
    payload: Node                          # contract payload tree (Page/EmbeddedResource/Record/...)
    artifacts: list[DeclaredArtifact]      # id/path/kind of files the engine wrote under outdir
    detected: Detection
    warnings: list[Warning] = field(default_factory=list)
    status: str = "ok"                     # "ok" | "rejected" | "engine_error"

class Engine(Protocol):
    name: str
    formats: frozenset[str]
    def detect(self, input: Path) -> Detection: ...           # optional (hasattr-guarded)
    def warmup(self) -> None: ...                             # optional (warm-pool slice; may be absent)
    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult: ...

# harness.py
def run_detonation(engine: Engine, *, input_path: Path, output_dir: Path, limits: Limits) -> int:
    """Run one detonation, write output_dir/metadata.json (a sealed Envelope), return exit code."""

def main(engine: Engine, argv: list[str] | None = None) -> int:
    """Worker entrypoint: resolve input/output dirs + limits (args/env), call run_detonation."""
```

## `run_detonation` flow
1. `input_sha256 = sha256(input_path.read_bytes())` (stream in chunks; bounded by limits.max_input_bytes — if the input is larger, that's the dispatcher's concern, but read defensively).
2. If the engine has `detect`, call it; if it returns a `Detection` the engine rejects (engine decides — out of scope here, keep simple: detect just feeds `detected`).
3. Call `result = engine.detonate(input_path, output_dir, limits)` inside a try/except:
   - **success** → `env = seal_envelope(engine=engine.name, outdir=output_dir, input_sha256=input_sha256,
     detected=result.detected, declared=result.artifacts, warnings=result.warnings,
     payload=result.payload, status=result.status)`.
   - **engine raises** → build a minimal **engine_error** envelope: `status="engine_error"`,
     `payload=Record(fields={"error": <scrubbed str>})`, no declared artifacts, a `Warning(code=
     "engine_error", message=<scrubbed>)`, and a best-effort `detected` (or a synthetic
     `Detection(label="unknown", mime="application/octet-stream", confidence=0.0, source="harness")`).
     Seal it (no artifacts to confine). This is a *clean* terminal outcome — common for malformed/exploit input.
   - If `seal_envelope` itself raises (engine declared an artifact it didn't write, or a bad path) →
     also fall back to an engine_error envelope describing the seal failure.
4. Write `output_dir/metadata.json` = `env.model_dump_json(by_alias=True)` (create output_dir if needed).
5. Return 0 (the envelope's `status` carries ok/engine_error/rejected; a non-zero exit is reserved for
   harness-internal failure — e.g. can't write metadata at all).

`main(engine, argv)`: argparse `--input-dir`/`--output-dir` (or env `BLASTBOX_INPUT_DIR`/`BLASTBOX_OUTPUT_DIR`,
defaulting to `/in`/`/out`); find the single regular file in input-dir (error if 0 or >1); `limits =
Limits.from_env()`; call `run_detonation`. Used as `if __name__ == "__main__": sys.exit(main(MyEngine()))`
in an engine's image.

## Tests (TDD)
Define a `_NoopEngine` test double: `detonate` writes a real `page-001.png` to outdir and returns a
`DetonationResult(payload=Page(index=0, dims=..., image=ArtifactRef(id="a0")),
artifacts=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")], detected=Detection(...))`.

1. **happy path**: `run_detonation(noop, ...)` writes `output_dir/metadata.json`; parse it back as an
   Envelope; `artifacts[0].sha256` equals the REAL file hash; `input_sha256` stamped; returns 0.
2. **ROUND-TRIP (the keystone test)**: take the harness-written `output_dir` and pass it straight to
   `blastbox.host.trust.validate_worker_output(output_dir=..., input_sha256=<same>, engine=noop.name,
   limits=...)` → it returns a valid Envelope (no `OutputTrustError`). Proves worker output is exactly
   what the host accepts. Also assert a wrong `input_sha256` → host raises (the round-trip is integrity-checked).
3. **engine raises**: an engine whose `detonate` raises `RuntimeError("boom /secret/path")` → metadata
   written with `status="engine_error"`, the path **scrubbed** from the warning, host trust still
   accepts it (status=engine_error), returns 0.
4. **engine declares a missing artifact**: returns a `DeclaredArtifact` for a file it didn't write →
   seal fails → falls back to engine_error envelope (no crash), host accepts it.
5. **engine declares a traversal path** (`path="../escape"`) → seal rejects → engine_error envelope.
6. **`main`**: a temp input-dir with one file + an output-dir → exit 0 + metadata.json written; 0 files
   in input-dir → non-zero/error; >1 file → error. (env-var path + arg path both.)

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. host + contract), mypy + ruff clean. Don't push.
